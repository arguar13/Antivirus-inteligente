//! Reglas Sigma sobre la telemetria del agente (FASE 4 del MP-16, paso 5).
//!
//! Adaptador del contrato unico: traduce cada evento del kernel a una
//! categoria de Sigma para Linux y evalua las reglas de esa categoria con el
//! evaluador de [`aegis_sigma`], el mismo que usa la fabrica de contenido.
//!
//! | Evento | Categoria | Campos |
//! |---|---|---|
//! | `Exec` | `process_creation` | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessId` |
//! | `FileWrite` | `file_event` | `TargetFilename`, `Image`, `ProcessId` |
//! | `FileRename` | `file_event` | `TargetFilename` (destino), `SourceFilename`, `Image`, `ProcessId` |
//! | `NetConnect` | `network_connection` | `DestinationIp`, `DestinationPort`, `DestinationIsIpv6`, `Initiated`, `Image`, `ProcessId` |
//!
//! `ParentImage`, `ParentCommandLine` y el `Image` de los eventos de fichero y
//! de red salen del contexto que el motor guarda de cada `Exec` que ve, acotado
//! a [`MAX_PROCESOS`] y olvidado en cada `Exit`. Un proceso que el agente no
//! vio ejecutar (arrancado antes que el, o creado por `fork` sin `exec`) no
//! tiene contexto: el campo falta, la condicion que lo pide no se cumple, y se
//! CUENTA (`sin_padre`, `sin_imagen`). Los filtros (`and not`) fallan hacia
//! detectar, nunca hacia callar.
//!
//! # Coste
//!
//! Camino caliente, sin retroceso: el peor caso de cada categoria esta acotado
//! al cargar ([`aegis_sigma::compacta::COSTE_MAX_CATEGORIA`]). Por evento no se
//! reserva memoria salvo cuando una regla dispara (la señal). El plazo del
//! arbitro se consulta cada [`CADA_REGLAS`] reglas; si se agota, las reglas que
//! ya dispararon se entregan y, si ninguna disparo, el dictamen es `SinDatos`
//! con la causa: nunca un limpio que no se comprobo.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala, siempre como `Sospechoso` y firmado por el plano conductual: ve
//! la misma telemetria que el triaje, asi que no corrobora a nadie de forma
//! independiente. Una señal por regla y proceso (no se repite hasta que el
//! proceso ejecuta otra imagen). Pasar a imponer exige los numeros de la
//! FASE 4: presupuesto de falsos positivos de cada regla medido en la carga.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use aegis_entidad::{Confianza, Juicio, Motor as Firma, Senal, Severidad};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};
use aegis_sigma::compacta::{Campo, Categoria, Juego, Registro, ReglaCompacta};
use aegis_sigma::regla::{Nivel, Topes};

use crate::graph::ProcKey;
use crate::motores::EventoAgente;
use crate::triage::TelemetryEvent;

/// Procesos cuyo contexto se guarda a la vez.
pub const MAX_PROCESOS: usize = 16_384;
/// Bytes que se cuentan por proceso ademas de sus cadenas. Las cadenas son
/// `Arc` compartidos con el evento y con el grafo, pero se cuentan enteras: si
/// el grafo las suelta, las retiene este motor.
const BYTES_POR_PROCESO: usize = 96;
/// Tope de cadena que se cuenta por proceso: la sonda corta la ruta a 256 y la
/// linea de comandos a 128.
const BYTES_CADENAS: usize = 256 + 128;
/// Señales por evento como mucho.
const MAX_SENALES_EVENTO: usize = 8;
/// Cada cuantas reglas se consulta el plazo.
pub const CADA_REGLAS: usize = 8;
/// `AF_INET`.
const AF_INET: u16 = 2;

struct Proceso {
    imagen: Arc<str>,
    linea: Arc<str>,
    /// Reglas que ya dispararon para esta imagen, como mapa de bits.
    disparadas: Vec<u64>,
}

/// Lo que el motor cuenta, para el informe del agente y las medidas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos evaluados contra alguna regla.
    pub evaluados: u64,
    /// Señales emitidas.
    pub disparos: u64,
    /// Disparos que no se repitieron (misma regla, mismo proceso e imagen).
    pub repetidos: u64,
    /// `Exec` cuyo padre no vio nacer el agente: sin `ParentImage`.
    pub sin_padre: u64,
    /// Eventos de fichero o red de un proceso sin contexto: sin `Image`.
    pub sin_imagen: u64,
    /// Procesos que no cupieron en el contexto.
    pub procesos_descartados: u64,
    /// Señales que no cupieron en un evento.
    pub senales_recortadas: u64,
    /// Evaluaciones cortadas por el plazo.
    pub plazos_agotados: u64,
    /// Campos que hubo que cortar a `MAX_CAMPO`.
    pub campos_cortados: u64,
}

/// Las reglas Sigma del agente.
pub struct MotorSigma {
    juego: Juego,
    /// Primer indice global de cada categoria, para el mapa de bits.
    base: [usize; 3],
    procesos: HashMap<ProcKey, Proceso>,
    bytes_procesos: usize,
    contadores: Contadores,
}

struct Casadas {
    indices: Vec<usize>,
    completas: bool,
    gastado: Duration,
    tope: Duration,
}

/// Una cadena corta en la pila, para formatear numeros y direcciones sin
/// reservar memoria por evento.
struct Pila<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Pila<N> {
    fn nueva() -> Pila<N> {
        Pila {
            buf: [0; N],
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> fmt::Write for Pila<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        let fin = self.len + b.len();
        if fin > N {
            return Err(fmt::Error);
        }
        self.buf[self.len..fin].copy_from_slice(b);
        self.len = fin;
        Ok(())
    }
}

/// Escribe la direccion de destino como la escribe Sigma.
fn direccion(d: &[u8; 16], familia: u16, salida: &mut Pila<48>) {
    let _ = if familia == AF_INET {
        write!(salida, "{}.{}.{}.{}", d[0], d[1], d[2], d[3])
    } else {
        write!(salida, "{}", Ipv6Addr::from(*d))
    };
}

fn severidad_y_confianza(n: Nivel) -> (Severidad, u8) {
    // Una regla de terceros no ha medido su precision en ESTA flota: la
    // confianza se queda por debajo de «fundada» hasta que el banco de la
    // FASE 4 diga otra cosa. Critical no pasa de Alta: la regla no sabe si lo
    // que ve es irreversible.
    match n {
        Nivel::Informational => (Severidad::Info, 10),
        Nivel::Low => (Severidad::Baja, 20),
        Nivel::Medium => (Severidad::Media, 30),
        Nivel::High => (Severidad::Alta, 40),
        Nivel::Critical => (Severidad::Alta, 44),
    }
}

/// La señal de una regla que disparo.
fn senal(r: &ReglaCompacta, ev: &EventoAgente) -> Senal {
    let (sev, conf) = severidad_y_confianza(r.nivel());
    let tecnicas: Vec<&str> = r
        .etiquetas()
        .iter()
        .map(String::as_str)
        .filter(|e| e.starts_with("attack.t"))
        .collect();
    let mut porque = format!(
        "sigma {} «{}» nivel {} ({})",
        r.id(),
        r.titulo(),
        r.nivel().nombre(),
        r.categoria().nombre()
    );
    if !tecnicas.is_empty() {
        let _ = write!(porque, " [{}]", tecnicas.join(", "));
    }
    Senal::nueva(
        Firma::Conductual,
        ev.entidad.clone(),
        Juicio::Sospechoso,
        sev,
        Confianza::nueva(conf),
        porque,
        ev.evento.ts_ns(),
    )
}

impl MotorSigma {
    /// Sobre un juego de reglas ya cargado.
    pub fn con_juego(juego: Juego) -> MotorSigma {
        let n0 = juego.reglas(Categoria::CreacionProceso).len();
        let n1 = juego.reglas(Categoria::EventoFichero).len();
        MotorSigma {
            juego,
            base: [0, n0, n0 + n1],
            procesos: HashMap::new(),
            bytes_procesos: 0,
            contadores: Contadores::default(),
        }
    }

    /// Con las reglas que viajan en el binario ([`aegis_sigma::incluidas`]).
    ///
    /// Una regla que no entra se dice aqui, con su motivo: la puerta de
    /// contenido garantiza que no pase, y si pasa se ve al arrancar. Sin
    /// reglas incluidas tambien se dice: el motor se registra y no evalua nada.
    pub fn incluidas() -> MotorSigma {
        let juego = Juego::cargar(aegis_sigma::incluidas::LINUX, &Topes::default());
        for r in juego.rechazos() {
            eprintln!(
                "aegis-agent: sigma: regla {} rechazada [{}]: {}",
                r.fichero, r.codigo, r.detalle
            );
        }
        if juego.is_empty() {
            // Vacio no es limpio: se dice, para que nadie lea «motor sigma
            // registrado» como cobertura.
            eprintln!("aegis-agent: sigma: 0 reglas, SIN CONTENIDO: no evalua nada");
        } else {
            eprintln!(
                "aegis-agent: sigma: {} regla(s) cargada(s), solo-auditoria",
                juego.len()
            );
        }
        MotorSigma::con_juego(juego)
    }

    /// Las reglas cargadas.
    pub fn juego(&self) -> &Juego {
        &self.juego
    }

    /// Lo contado hasta ahora.
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Procesos con contexto.
    pub fn procesos(&self) -> usize {
        self.procesos.len()
    }

    fn casar(&self, categoria: Categoria, r: &Registro<'_>, plazo: &Plazo) -> Casadas {
        let mut c = Casadas {
            indices: Vec::new(),
            completas: true,
            gastado: Duration::ZERO,
            tope: plazo.tope(),
        };
        for (i, regla) in self.juego.reglas(categoria).iter().enumerate() {
            if i > 0 && i % CADA_REGLAS == 0 && !plazo.sigue() {
                c.completas = false;
                c.gastado = plazo.gastado();
                break;
            }
            if regla.casa(r) {
                c.indices.push(i);
            }
        }
        c
    }

    fn recordar(&mut self, actor: ProcKey, imagen: &Arc<str>, linea: &Arc<str>) {
        let nuevo = imagen.len().min(BYTES_CADENAS) + linea.len().min(BYTES_CADENAS);
        if let Some(p) = self.procesos.get_mut(&actor) {
            let viejo = p.imagen.len().min(BYTES_CADENAS)
                + p.linea.len().min(BYTES_CADENAS)
                + p.disparadas.len() * 8;
            if p.imagen != *imagen {
                // Otra imagen, otro programa: sus reglas pueden volver a
                // disparar. La misma imagen otra vez no repite la señal.
                p.disparadas = Vec::new();
            }
            p.imagen = Arc::clone(imagen);
            p.linea = Arc::clone(linea);
            let ahora = nuevo + p.disparadas.len() * 8;
            self.bytes_procesos = self.bytes_procesos.saturating_sub(viejo) + ahora;
            return;
        }
        if self.procesos.len() >= MAX_PROCESOS {
            self.contadores.procesos_descartados += 1;
            return;
        }
        self.procesos.insert(
            actor,
            Proceso {
                imagen: Arc::clone(imagen),
                linea: Arc::clone(linea),
                disparadas: Vec::new(),
            },
        );
        self.bytes_procesos += BYTES_POR_PROCESO + nuevo;
    }

    fn olvidar(&mut self, actor: ProcKey) {
        if let Some(p) = self.procesos.remove(&actor) {
            let bytes = BYTES_POR_PROCESO
                + p.imagen.len().min(BYTES_CADENAS)
                + p.linea.len().min(BYTES_CADENAS)
                + p.disparadas.len() * 8;
            self.bytes_procesos = self.bytes_procesos.saturating_sub(bytes);
        }
    }

    /// Si la regla ya disparo para este proceso; si no, la marca.
    fn repetida(&mut self, actor: ProcKey, global: usize) -> bool {
        let Some(p) = self.procesos.get_mut(&actor) else {
            return false;
        };
        let (palabra, bit) = (global / 64, 1u64 << (global % 64));
        if p.disparadas.len() <= palabra {
            let crece = palabra + 1 - p.disparadas.len();
            p.disparadas.resize(palabra + 1, 0);
            self.bytes_procesos += crece * 8;
        }
        if p.disparadas[palabra] & bit != 0 {
            return true;
        }
        p.disparadas[palabra] |= bit;
        false
    }

    fn dictamen(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        categoria: Categoria,
        casadas: Casadas,
    ) -> Dictamen {
        self.contadores.evaluados += 1;
        if !casadas.completas {
            self.contadores.plazos_agotados += 1;
        }
        let base = self.base[match categoria {
            Categoria::CreacionProceso => 0,
            Categoria::EventoFichero => 1,
            Categoria::ConexionRed => 2,
        }];
        let mut senales = Vec::new();
        for i in casadas.indices {
            if self.repetida(actor, base + i) {
                self.contadores.repetidos += 1;
                continue;
            }
            if senales.len() == MAX_SENALES_EVENTO {
                self.contadores.senales_recortadas += 1;
                continue;
            }
            senales.push(senal(&self.juego.reglas(categoria)[i], ev));
        }
        self.contadores.disparos += senales.len() as u64;
        if !senales.is_empty() {
            return Dictamen::Senales(senales);
        }
        if casadas.completas {
            Dictamen::NoAplica
        } else {
            Dictamen::SinDatos(Causa::PlazoAgotado {
                gastado: casadas.gastado,
                tope: casadas.tope,
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn exec(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        pid: u32,
        padre: ProcKey,
        imagen: &Arc<str>,
        linea: &Arc<str>,
        plazo: &Plazo,
    ) -> Dictamen {
        let categoria = Categoria::CreacionProceso;
        if self.juego.reglas(categoria).is_empty() {
            self.recordar(actor, imagen, linea);
            return Dictamen::NoAplica;
        }
        let mut npid = Pila::<12>::nueva();
        let _ = write!(npid, "{pid}");
        let mut r = Registro::nuevo();
        let mut cortados = 0u64;
        cortados += u64::from(r.poner(Campo::Imagen, imagen.as_bytes()));
        cortados += u64::from(r.poner(Campo::LineaComandos, linea.as_bytes()));
        let _ = r.poner(Campo::Pid, npid.bytes());
        let sin_padre = match self.procesos.get(&padre) {
            Some(p) => {
                cortados += u64::from(r.poner(Campo::ImagenPadre, p.imagen.as_bytes()));
                cortados += u64::from(r.poner(Campo::LineaComandosPadre, p.linea.as_bytes()));
                false
            }
            None => true,
        };
        let casadas = self.casar(categoria, &r, plazo);
        self.contadores.campos_cortados += cortados;
        self.contadores.sin_padre += u64::from(sin_padre);
        // Primero el contexto nuevo (otra imagen: las marcas se reinician) y
        // despues las marcas de lo que acaba de disparar.
        self.recordar(actor, imagen, linea);
        self.dictamen(ev, actor, categoria, casadas)
    }

    fn fichero(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        pid: u32,
        destino: &str,
        origen: Option<&str>,
        plazo: &Plazo,
    ) -> Dictamen {
        let categoria = Categoria::EventoFichero;
        if self.juego.reglas(categoria).is_empty() {
            return Dictamen::NoAplica;
        }
        let mut npid = Pila::<12>::nueva();
        let _ = write!(npid, "{pid}");
        let mut r = Registro::nuevo();
        let mut cortados = u64::from(r.poner(Campo::FicheroDestino, destino.as_bytes()));
        if let Some(o) = origen {
            cortados += u64::from(r.poner(Campo::FicheroOrigen, o.as_bytes()));
        }
        let _ = r.poner(Campo::Pid, npid.bytes());
        let sin_imagen = match self.procesos.get(&actor) {
            Some(p) => {
                cortados += u64::from(r.poner(Campo::Imagen, p.imagen.as_bytes()));
                false
            }
            None => true,
        };
        let casadas = self.casar(categoria, &r, plazo);
        self.contadores.campos_cortados += cortados;
        self.contadores.sin_imagen += u64::from(sin_imagen);
        self.dictamen(ev, actor, categoria, casadas)
    }

    #[allow(clippy::too_many_arguments)]
    fn red(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        pid: u32,
        daddr: &[u8; 16],
        dport: u16,
        familia: u16,
        plazo: &Plazo,
    ) -> Dictamen {
        let categoria = Categoria::ConexionRed;
        if self.juego.reglas(categoria).is_empty() {
            return Dictamen::NoAplica;
        }
        let mut npid = Pila::<12>::nueva();
        let _ = write!(npid, "{pid}");
        let mut ip = Pila::<48>::nueva();
        direccion(daddr, familia, &mut ip);
        let mut puerto = Pila::<8>::nueva();
        let _ = write!(puerto, "{dport}");
        let mut r = Registro::nuevo();
        let _ = r.poner(Campo::IpDestino, ip.bytes());
        let _ = r.poner(Campo::PuertoDestino, puerto.bytes());
        let v6: &[u8] = if familia == AF_INET {
            b"false"
        } else {
            b"true"
        };
        let _ = r.poner(Campo::DestinoIpv6, v6);
        let _ = r.poner(Campo::Iniciada, b"true");
        let _ = r.poner(Campo::Pid, npid.bytes());
        let mut cortados = 0u64;
        let sin_imagen = match self.procesos.get(&actor) {
            Some(p) => {
                cortados += u64::from(r.poner(Campo::Imagen, p.imagen.as_bytes()));
                false
            }
            None => true,
        };
        let casadas = self.casar(categoria, &r, plazo);
        self.contadores.campos_cortados += cortados;
        self.contadores.sin_imagen += u64::from(sin_imagen);
        self.dictamen(ev, actor, categoria, casadas)
    }
}

impl Motor<EventoAgente> for MotorSigma {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "sigma",
            firma: Firma::Conductual,
            camino: Camino::Caliente,
            // El peor caso de una categoria son 2^20 pasos de comparacion
            // (COSTE_MAX_CATEGORIA); el tipico, unos pocos miles, porque cada
            // regla cae en su primera seleccion. 300 us cubre el tipico con
            // margen y deja que el arbitro sancione un juego que se degrade.
            presupuesto: Presupuesto::caliente(
                300,
                MAX_PROCESOS * (BYTES_POR_PROCESO + 2 * BYTES_CADENAS + 64) + self.juego.memoria(),
            ),
            requisitos: &[Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, plazo: &Plazo) -> Dictamen {
        match &ev.evento {
            TelemetryEvent::Exec {
                actor,
                pid,
                parent,
                image,
                cmdline,
                ..
            } => self.exec(ev, *actor, *pid, *parent, image, cmdline, plazo),
            TelemetryEvent::FileWrite {
                actor, pid, path, ..
            } => self.fichero(ev, *actor, *pid, path, None, plazo),
            TelemetryEvent::FileRename {
                actor,
                pid,
                from,
                to,
                ..
            } => self.fichero(ev, *actor, *pid, to, Some(&**from), plazo),
            TelemetryEvent::NetConnect {
                actor,
                pid,
                daddr,
                dport,
                family,
                ..
            } => self.red(ev, *actor, *pid, daddr, *dport, *family, plazo),
            TelemetryEvent::Exit { actor, .. } => {
                self.olvidar(*actor);
                Dictamen::NoAplica
            }
            _ => Dictamen::NoAplica,
        }
    }

    fn memoria(&self) -> usize {
        self.bytes_procesos + self.juego.memoria()
    }

    fn aligerar(&mut self) {
        // Sin el contexto se pierden ParentImage e Image hasta el proximo exec
        // de cada proceso; las reglas siguen evaluandose con lo que trae el
        // evento. Peor que no olvidar, mejor que quedarse ciego.
        self.procesos.clear();
        self.bytes_procesos = 0;
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn las_direcciones_se_escriben_como_en_sigma() {
        let mut v4 = [0u8; 16];
        v4[..4].copy_from_slice(&[192, 0, 2, 10]);
        let mut p = Pila::<48>::nueva();
        direccion(&v4, AF_INET, &mut p);
        assert_eq!(p.bytes(), b"192.0.2.10");
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let mut p = Pila::<48>::nueva();
        direccion(&v6, 10, &mut p);
        assert_eq!(p.bytes(), b"2001:db8::1");
    }

    #[test]
    fn la_pila_no_se_desborda() {
        let mut p = Pila::<4>::nueva();
        assert!(fmt::Write::write_str(&mut p, "12345").is_err());
        assert!(p.bytes().len() <= 4);
    }

    #[test]
    fn un_motor_sin_reglas_no_retiene_mas_que_su_contexto() {
        let m = MotorSigma::con_juego(Juego::default());
        assert_eq!(m.procesos(), 0);
        assert!(m.ficha().presupuesto.memoria >= MAX_PROCESOS * BYTES_POR_PROCESO);
    }
}
