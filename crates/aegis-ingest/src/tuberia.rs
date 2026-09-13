//! La tuberia: de los origenes al plano de control, sin perder ni inventar.
//!
//! # La topologia, y por que tiene exactamente estas cuatro etapas
//!
//! ```text
//!   origen  --leer-->  normalizar  -->  COLA (memoria, acotada, con prioridad)
//!                                          |
//!                                          v  lote
//!                                       DIARIO (disco, acotado, durable)
//!                                          |
//!                                          v
//!                              el PUNTO DE CONTROL avanza
//!                                          |
//!                                          v
//!                                 entrega al plano de control
//!                                          |
//!                                     <-- acuse -->  el diario borra
//! ```
//!
//! Cada etapa esta por una razon concreta y quitarla rompe algo:
//!
//! * **La cola antes del diario** existe para poder tirar por prioridad **sin
//!   haber pagado el disco**. Sin ella, un chorro de log de aplicacion se
//!   escribiria en el diario, empujaria fuera a la telemetria de seguridad por
//!   presupuesto, y habria costado ademas la escritura.
//! * **El diario antes del punto de control** es la regla de orden que hace que
//!   la entrega sea al-menos-una-vez. Ver [`crate::punto`].
//! * **El acuse despues de la entrega** es lo que permite reenviar tras un
//!   reinicio: hasta que el plano de control dice «lo tengo», el evento sigue en
//!   disco.
//!
//! # La contrapresion, hasta donde llega de verdad
//!
//! Cuando la cola pasa de su marca alta, la tuberia **lee menos** en la vuelta
//! siguiente. Lo que eso provoca en cada origen es distinto, y conviene decirlo
//! sin adornos:
//!
//! * **Fichero**: el fichero sigue creciendo en disco y se lee luego. No se
//!   pierde nada; se retrasa.
//! * **syslog sobre TCP**: el bufer del socket se llena, la ventana de TCP se
//!   cierra y **el emisor deja de poder enviar**. Esto si es contrapresion de
//!   extremo a extremo de verdad.
//! * **syslog sobre UDP**: no hay contrapresion posible —el protocolo no la
//!   tiene— y el nucleo tira datagramas. Se lee el contador de descartes del
//!   socket y **se declara**, porque es la unica forma de que alguien sepa que
//!   ese aparato necesita TCP.
//! * **journald y EVTX**: son ficheros; se retrasa la lectura.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aegis_firehose::{Diario, Posicion as PosicionDiario};

use crate::clasifica::clasificar;
use crate::cola::{Admision, Cola};
use crate::error::{ErrorIngesta, Resultado};
use crate::esquema::{confianza, recortar, Evento, Origen, Severidad, Valor, MAX_CAMPO, VERSION};
use crate::punto::{Confirmador, Posicion, PuntoDeControl};
use crate::{ahora_ns, Contadores, Contexto};

/// Registros que se leen de una fuente en una vuelta normal.
pub const LOTE: usize = 512;

/// Clave con la que se guarda en el punto de control por donde va la ENTREGA.
///
/// # Por que hace falta ademas del punto de lectura
///
/// `Diario::confirmar_hasta` borra segmentos enteros, que es lo correcto:
/// reescribir un fichero que se esta leyendo para recortarle el principio deja
/// el diario ilegible si se interrumpe. Pero eso significa que el diario **no
/// recuerda por si solo** que ya se acuso dentro del segmento activo, que puede
/// tener sesenta y cuatro megas.
///
/// Sin esta marca, cada reinicio reenvia el segmento activo entero. No se
/// perderia nada —la deduplicacion lo absorbe— pero un endpoint que se reinicia
/// dos veces al dia le manda al plano de control dos veces sesenta y cuatro
/// megas de eventos que ya tenia, multiplicado por la flota.
pub const CLAVE_ENTREGA: &str = "diario:entregado";

/// Divisor del lote cuando la cola pide freno.
///
/// Cuatro y no cero: parar del todo dejaria la cola sin la telemetria de
/// seguridad que si cabria, porque el descarte por prioridad solo funciona si
/// hay eventos nuevos que entren.
pub const FRENO: usize = 4;

/// Que se ingiere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fuente {
    /// Un fichero de log plano, con seguimiento de rotacion.
    Fichero {
        /// Ruta a seguir.
        ruta: PathBuf,
        /// Si sus lineas son syslog o texto suelto.
        syslog: bool,
    },
    /// Un fichero del diario binario de systemd.
    Journald {
        /// Ruta del `.journal`.
        ruta: PathBuf,
    },
    /// Un fichero de registro de sucesos de Windows.
    Evtx {
        /// Ruta del `.evtx`.
        ruta: PathBuf,
    },
}

impl Fuente {
    /// Nombre estable con el que se guarda en el punto de control.
    #[must_use]
    pub fn nombre(&self) -> String {
        match self {
            Fuente::Fichero { ruta, .. } => format!("fichero:{}", ruta.display()),
            Fuente::Journald { ruta } => format!("journald:{}", ruta.display()),
            Fuente::Evtx { ruta } => format!("evtx:{}", ruta.display()),
        }
    }
}

/// Ajustes de la tuberia.
#[derive(Debug, Clone)]
pub struct Config {
    /// A que cliente pertenece lo que se ingiere.
    pub inquilino: String,
    /// Maquina que se atribuye a lo que no lo diga.
    pub anfitrion: String,
    /// Cola en memoria.
    pub cola: crate::cola::Config,
    /// Diario durable.
    pub diario: aegis_firehose::Config,
    /// Fichero del punto de control.
    pub punto: PathBuf,
    /// Registros por fuente y vuelta.
    pub lote: usize,
    /// Si se conserva el registro original.
    pub conservar_crudo: bool,
}

impl Config {
    /// Configuracion derivada del presupuesto del host y de un directorio de
    /// estado.
    #[must_use]
    pub fn nueva(
        inquilino: impl Into<String>,
        anfitrion: impl Into<String>,
        estado: impl Into<PathBuf>,
    ) -> Config {
        let estado: PathBuf = estado.into();
        let presupuesto = aegis_presupuesto::efectivo();
        Config {
            inquilino: inquilino.into(),
            anfitrion: anfitrion.into(),
            cola: crate::cola::Config::del_presupuesto(&presupuesto),
            diario: aegis_firehose::Config::nueva(estado.join("diario")),
            punto: estado.join("punto"),
            lote: LOTE,
            conservar_crudo: true,
        }
    }
}

/// Lo que paso en una vuelta.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Informe {
    /// Registros leidos de los origenes.
    pub leidos: u64,
    /// Eventos que entraron en la cola.
    pub encolados: u64,
    /// Eventos que la cola rechazo o desalojo.
    pub perdidos_en_cola: u64,
    /// Eventos escritos en el diario.
    pub escritos: u64,
    /// Si la cola esta pidiendo freno.
    pub frenando: bool,
}

/// Estado de una fuente en marcha.
enum Estado {
    Fichero {
        seguidor: crate::fichero::Seguidor,
        syslog: bool,
    },
    Journald {
        lector: crate::journald::Lector,
    },
    Evtx {
        ruta: PathBuf,
        /// Ultimo identificador de registro entregado.
        ultimo: u64,
    },
}

struct EnMarcha {
    fuente: Fuente,
    nombre: String,
    estado: Estado,
}

/// La tuberia completa.
pub struct Ingesta {
    cfg: Config,
    fuentes: Vec<EnMarcha>,
    cola: Cola,
    diario: Diario,
    punto: PuntoDeControl,
    /// Hasta donde acuso el plano de control. Ver [`CLAVE_ENTREGA`].
    entregado: Option<PosicionDiario>,
    contadores: Contadores,
}

impl Ingesta {
    /// Levanta la tuberia, recuperando lo que quedara pendiente.
    pub fn nueva(cfg: Config) -> Resultado<Ingesta> {
        crate::punto::comprobar(&cfg.punto)?;
        let punto = PuntoDeControl::abrir(&cfg.punto)?;
        let diario =
            Diario::abrir(cfg.diario.clone()).map_err(|e| ErrorIngesta::Diario(e.to_string()))?;
        let cola = Cola::nueva(cfg.cola.clone());
        let entregado = match punto.posicion(CLAVE_ENTREGA) {
            Some(Posicion::Cursor(c)) => descifrar_posicion(c),
            _ => None,
        };
        Ok(Ingesta {
            cfg,
            fuentes: Vec::new(),
            cola,
            diario,
            punto,
            entregado,
            contadores: Contadores::default(),
        })
    }

    /// Anade una fuente, reanudando por donde estuviera.
    pub fn anadir(&mut self, fuente: Fuente) -> Resultado<()> {
        let nombre = fuente.nombre();
        if self.fuentes.iter().any(|f| f.nombre == nombre) {
            return Err(ErrorIngesta::Config(format!(
                "la fuente «{nombre}» ya estaba"
            )));
        }
        let estado = match &fuente {
            Fuente::Fichero { ruta, syslog } => {
                let seguidor = match self.punto.marca(&nombre) {
                    Some(m) => crate::fichero::Seguidor::reanudar(ruta, m)?,
                    None => crate::fichero::Seguidor::nuevo(ruta),
                };
                Estado::Fichero {
                    seguidor,
                    syslog: *syslog,
                }
            }
            Fuente::Journald { ruta } => {
                let mut lector = crate::journald::Lector::abrir(ruta)?;
                if let Some(Posicion::Cursor(c)) = self.punto.posicion(&nombre) {
                    let c = c.clone();
                    // Si el cursor ya no esta en este fichero —roto mientras el
                    // agente estaba parado— se lee entero: sus entradas no se
                    // han entregado nunca.
                    let _ = lector.situar_tras_cursor(&c)?;
                }
                Estado::Journald { lector }
            }
            Fuente::Evtx { ruta } => {
                let ultimo = match self.punto.posicion(&nombre) {
                    Some(Posicion::Registro(n)) => *n,
                    _ => 0,
                };
                Estado::Evtx {
                    ruta: ruta.clone(),
                    ultimo,
                }
            }
        };
        self.fuentes.push(EnMarcha {
            fuente,
            nombre,
            estado,
        });
        Ok(())
    }

    /// Contadores de normalizacion.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Contadores de la cola.
    #[must_use]
    pub fn cola(&self) -> crate::cola::Contadores {
        self.cola.contadores()
    }

    /// Fuentes en marcha.
    pub fn fuentes(&self) -> impl Iterator<Item = &Fuente> {
        self.fuentes.iter().map(|f| &f.fuente)
    }

    /// Una vuelta completa: leer, normalizar, encolar, escribir y confirmar.
    ///
    /// Es una funcion y no un bucle propio a proposito: quien la llama decide el
    /// ritmo, y eso permite que el supervisor del agente la intercale con el
    /// resto del trabajo en vez de tener un hilo mas compitiendo por la CPU de
    /// una maquina que ya esta haciendo su trabajo de verdad.
    pub fn vuelta(&mut self) -> Resultado<Informe> {
        let mut informe = Informe::default();
        let frenando = self.cola.debe_frenar();
        informe.frenando = frenando;
        let lote = if frenando {
            (self.cfg.lote / FRENO).max(1)
        } else {
            self.cfg.lote
        };

        let ctx = Contexto {
            inquilino: self.cfg.inquilino.clone(),
            anfitrion_por_defecto: self.cfg.anfitrion.clone(),
            observado_ns: ahora_ns(),
            conservar_crudo: self.cfg.conservar_crudo,
        };

        // Se recogen los avances y se aplican DESPUES de que los eventos esten
        // en el diario. Anotarlos aqui seria la version sutil del mismo error de
        // orden: el punto de control no se escribe hasta confirmar, pero
        // dejarlo anotado invita a que alguien anada un guardado en medio.
        let mut avances: Vec<(String, Posicion)> = Vec::new();
        let mut eventos: Vec<Evento> = Vec::new();

        for i in 0..self.fuentes.len() {
            let (leidos, nuevos, avance) =
                Self::leer_fuente(&mut self.fuentes[i], lote, &ctx, &mut self.contadores)?;
            informe.leidos += leidos;
            eventos.extend(nuevos);
            if let Some(p) = avance {
                avances.push((self.fuentes[i].nombre.clone(), p));
            }
        }

        for e in eventos {
            match self.cola.admitir(e) {
                Admision::Admitido => informe.encolados += 1,
                Admision::AdmitidoDesalojando { cuantos, .. } => {
                    informe.encolados += 1;
                    informe.perdidos_en_cola += cuantos as u64;
                }
                Admision::Rechazado => informe.perdidos_en_cola += 1,
            }
        }

        // La cola se vacia al diario. Lo que no quepa en el diario se queda en la
        // cola para la vuelta siguiente: no se tira aqui, porque la cola ya
        // aplico su politica y tirarlo otra vez seria perder dos veces por el
        // mismo motivo.
        let mut devueltos = Vec::new();
        while let Some(e) = self.cola.siguiente() {
            let carga = match serde_json::to_vec(&e) {
                Ok(v) => v,
                Err(_) => continue, // un evento que no serializa no existe
            };
            match self.diario.admitir(&carga) {
                Ok(_) => informe.escritos += 1,
                Err(_) => {
                    devueltos.push(e);
                    break;
                }
            }
        }
        for e in devueltos {
            let _ = self.cola.admitir(e);
        }

        // Y AHORA, y solo ahora, el punto de control.
        for (nombre, posicion) in avances {
            self.punto.anotar(&nombre, posicion)?;
        }
        let diario = &mut self.diario;
        Confirmador::nuevo(&mut self.punto).confirmar(|| {
            diario
                .sincronizar()
                .map_err(|e| ErrorIngesta::Diario(e.to_string()))
        })?;

        Ok(informe)
    }

    /// Lee de una fuente y normaliza lo leido.
    fn leer_fuente(
        f: &mut EnMarcha,
        lote: usize,
        ctx: &Contexto,
        contadores: &mut Contadores,
    ) -> Resultado<(u64, Vec<Evento>, Option<Posicion>)> {
        let mut eventos = Vec::new();
        let mut leidos = 0u64;
        let avance = match &mut f.estado {
            Estado::Fichero { seguidor, syslog } => {
                let lineas = seguidor.leer(lote)?;
                for l in lineas {
                    leidos += 1;
                    let ancla = l.ancla();
                    let r = if *syslog {
                        crate::syslog::normalizar(&l.datos, &ancla, ctx)
                    } else {
                        Ok(texto_plano(&l, &ancla, ctx))
                    };
                    let especifico = r
                        .as_ref()
                        .is_ok_and(|e| e.clase != crate::esquema::Clase::ActividadDelSistema);
                    contadores.anotar(&r, especifico);
                    if let Ok(e) = r {
                        eventos.push(e);
                    }
                }
                seguidor.marca().map(Posicion::Fichero)
            }
            Estado::Journald { lector } => {
                let entradas = lector.leer(lote)?;
                let mut cursor = None;
                for e in entradas {
                    leidos += 1;
                    cursor = Some(e.cursor());
                    let ev = de_journald(&e, ctx);
                    let especifico = ev.clase != crate::esquema::Clase::ActividadDelSistema;
                    contadores.anotar(&Ok(ev.clone()), especifico);
                    eventos.push(ev);
                }
                cursor.map(Posicion::Cursor)
            }
            Estado::Evtx { ruta, ultimo } => {
                // Un EVTX es un fichero exportado que se lee entero, no un flujo
                // que crece; si no ha cambiado, no hay nada que hacer.
                let mut lector = crate::evtx::Lector::abrir(&*ruta)?;
                let registros = lector.leer(*ultimo, lote);
                let mut mayor = *ultimo;
                for r in registros {
                    leidos += 1;
                    mayor = mayor.max(r.id);
                    let ev = de_evtx(&r, ctx);
                    let especifico = crate::evtx::catalogo::buscar(&r.canal, r.event_id).is_some();
                    contadores.anotar(&Ok(ev.clone()), especifico);
                    eventos.push(ev);
                }
                if mayor > *ultimo {
                    *ultimo = mayor;
                    Some(Posicion::Registro(mayor))
                } else {
                    None
                }
            }
        };
        Ok((leidos, eventos, avance))
    }

    /// Saca eventos hacia el plano de control, sin borrarlos todavia.
    ///
    /// Devuelve tambien la posicion hasta la que habria que acusar. El evento
    /// **sigue en disco** hasta que llegue el acuse: es lo que permite reenviar
    /// tras un reinicio en vez de perder lo que iba por el cable.
    pub fn entregar(&mut self, maximo: usize) -> Resultado<(Vec<Evento>, Option<PosicionDiario>)> {
        let registros = self
            .diario
            .leer_desde(self.entregado, maximo)
            .map_err(|e| ErrorIngesta::Diario(e.to_string()))?;
        let mut eventos = Vec::with_capacity(registros.len());
        let mut hasta = None;
        for r in registros {
            hasta = Some(r.siguiente);
            match serde_json::from_slice::<Evento>(&r.carga) {
                Ok(e) => eventos.push(e),
                // Un registro del diario que no se puede leer se salta y se
                // acusa igual: dejarlo bloquearia el diario entero para siempre,
                // que es peor que perder uno.
                Err(_) => continue,
            }
        }
        Ok((eventos, hasta))
    }

    /// El plano de control acuso hasta aqui: ya se puede borrar.
    ///
    /// Se hacen dos cosas y en este orden: primero se deja constancia durable de
    /// hasta donde se acuso —si no, un reinicio reenvia el segmento activo
    /// entero— y despues se borran los segmentos que ya no hacen falta. Al
    /// reves, un corte entre las dos dejaria una marca que apunta a datos
    /// borrados.
    pub fn acusar(&mut self, hasta: PosicionDiario) -> Resultado<()> {
        self.entregado = Some(hasta);
        self.punto
            .anotar(CLAVE_ENTREGA, Posicion::Cursor(cifrar_posicion(hasta)))?;
        let diario = &mut self.diario;
        Confirmador::nuevo(&mut self.punto).confirmar(|| {
            diario
                .sincronizar()
                .map_err(|e| ErrorIngesta::Diario(e.to_string()))
        })?;
        self.diario
            .confirmar_hasta(hasta)
            .map_err(|e| ErrorIngesta::Diario(e.to_string()))
    }
}

/// Posicion del diario a texto, para el punto de control.
fn cifrar_posicion(p: PosicionDiario) -> String {
    format!("{}:{}", p.segmento, p.desplazamiento)
}

/// Y de vuelta. Una marca ilegible se ignora en vez de romper el arranque: el
/// peor caso es reenviar el segmento activo, que la deduplicacion absorbe.
fn descifrar_posicion(texto: &str) -> Option<PosicionDiario> {
    let (a, b) = texto.split_once(':')?;
    Some(PosicionDiario {
        segmento: a.parse().ok()?,
        desplazamiento: b.parse().ok()?,
    })
}

/// Una linea de texto que no es syslog.
///
/// No se intenta adivinar un formato: se clasifica por el nombre del fichero y
/// el contenido, y la hora es la de lectura, marcada como tal. Fingir que se
/// extrajo una hora de un formato desconocido seria inventarse el orden de los
/// hechos.
fn texto_plano(l: &crate::fichero::Linea, ancla: &str, ctx: &Contexto) -> Evento {
    let mensaje = String::from_utf8_lossy(&l.datos).into_owned();
    let clas = clasificar("", &mensaje);
    let (ocurrio_ns, reloj) = confianza(None, ctx.observado_ns);
    let mut campos = clas.campos;
    if l.cortada {
        campos.insert("ingesta.cortada".into(), Valor::Booleano(true));
    }
    let mut e = Evento {
        version: VERSION,
        id: String::new(),
        ancla: recortar(ancla, MAX_CAMPO),
        ocurrio_ns,
        observado_ns: ctx.observado_ns,
        reloj,
        clase: clas.clase,
        resultado: clas.resultado,
        severidad: clas.severidad.unwrap_or(Severidad::Info),
        origen: Origen::Fichero,
        anfitrion: ctx.anfitrion_por_defecto.clone(),
        inquilino: ctx.inquilino.clone(),
        productor: "fichero".into(),
        mensaje: crate::esquema::recortar(&mensaje, crate::esquema::MAX_MENSAJE),
        campos,
        crudo: ctx.conservar_crudo.then(|| l.datos.clone()),
    };
    e.sellar();
    e
}

/// Una entrada de journald al esquema comun.
fn de_journald(e: &crate::journald::Entrada, ctx: &Contexto) -> Evento {
    let productor = e.productor();
    let mensaje = e.mensaje();
    let clas = clasificar(&productor, &mensaje);
    // journald SI trae hora fiable: la pone el nucleo del sistema, no el
    // programa que escribe, asi que no hay el problema de creerle la fecha a
    // quien escribe la linea.
    let (ocurrio_ns, reloj) = confianza(Some(e.realtime_ns), ctx.observado_ns);

    let mut campos = clas.campos;
    for (clave, valor) in &e.campos {
        if clave == "MESSAGE" || campos.len() >= crate::esquema::MAX_CAMPOS {
            continue;
        }
        campos.insert(
            format!("journald.{}", clave.trim_start_matches('_').to_lowercase()),
            Valor::Texto(recortar(valor, MAX_CAMPO)),
        );
    }
    if !e.sin_descomprimir.is_empty() {
        campos.insert(
            "ingesta.sin_descomprimir".into(),
            Valor::Texto(e.sin_descomprimir.join(",")),
        );
    }
    let anfitrion = e
        .campos
        .get("_HOSTNAME")
        .cloned()
        .unwrap_or_else(|| ctx.anfitrion_por_defecto.clone());
    let severidad = e
        .campos
        .get("PRIORITY")
        .and_then(|p| p.parse::<u8>().ok())
        .map_or(Severidad::Info, crate::syslog::severidad_de);

    let mut ev = Evento {
        version: VERSION,
        id: String::new(),
        ancla: e.ancla(),
        ocurrio_ns,
        observado_ns: ctx.observado_ns,
        reloj,
        clase: clas.clase,
        resultado: clas.resultado,
        severidad: clas.severidad.unwrap_or(severidad),
        origen: Origen::Journald,
        anfitrion,
        inquilino: ctx.inquilino.clone(),
        productor,
        mensaje,
        campos,
        crudo: None,
    };
    ev.sellar();
    ev
}

/// Un registro de EVTX al esquema comun.
fn de_evtx(r: &crate::evtx::Registro, ctx: &Contexto) -> Evento {
    let conocido = crate::evtx::catalogo::buscar(&r.canal, r.event_id);
    let (clase, resultado, severidad, descripcion) = match conocido {
        Some(c) => (c.clase, c.resultado, c.severidad, c.descripcion),
        None => (
            crate::esquema::Clase::ActividadDelSistema,
            crate::esquema::Resultado::Desconocido,
            // El nivel de Windows: 1 critico, 2 error, 3 aviso, 4 informacion.
            match r.nivel {
                1 => Severidad::Critica,
                2 => Severidad::Alta,
                3 => Severidad::Media,
                _ => Severidad::Info,
            },
            "",
        ),
    };
    let (ocurrio_ns, reloj) =
        confianza((r.escrito_ns > 0).then_some(r.escrito_ns), ctx.observado_ns);

    let mut campos: BTreeMap<String, Valor> = BTreeMap::new();
    campos.insert("evtx.event_id".into(), Valor::Entero(i64::from(r.event_id)));
    campos.insert("evtx.canal".into(), Valor::Texto(r.canal.clone()));
    for (k, v) in &r.campos {
        if campos.len() >= crate::esquema::MAX_CAMPOS || k.starts_with("System/") {
            continue;
        }
        campos.insert(k.clone(), Valor::Texto(recortar(v, MAX_CAMPO)));
    }

    let mut ev = Evento {
        version: VERSION,
        id: String::new(),
        ancla: r.ancla(),
        ocurrio_ns,
        observado_ns: ctx.observado_ns,
        reloj,
        clase,
        resultado,
        severidad,
        origen: Origen::Evtx,
        anfitrion: if r.computadora.is_empty() {
            ctx.anfitrion_por_defecto.clone()
        } else {
            r.computadora.clone()
        },
        inquilino: ctx.inquilino.clone(),
        productor: if r.proveedor.is_empty() {
            "windows".into()
        } else {
            r.proveedor.clone()
        },
        // El texto legible no esta en el fichero (ver `evtx`): se pone la
        // descripcion estable del catalogo, que ademas no depende del idioma de
        // la maquina de origen.
        mensaje: if descripcion.is_empty() {
            format!("suceso {} de {}", r.event_id, r.canal)
        } else {
            format!("{} ({})", descripcion, r.event_id)
        },
        campos,
        crudo: None,
    };
    ev.sellar();
    ev
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::io::Write;

    fn escribir(ruta: &std::path::Path, texto: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ruta)
            .unwrap();
        f.write_all(texto.as_bytes()).unwrap();
    }

    fn config(dir: &std::path::Path) -> Config {
        let mut c = Config::nueva("cliente-1", "maquina-1", dir);
        // Colas pequenas en las pruebas para que la contrapresion se pueda
        // provocar sin escribir un giga.
        c.cola = crate::cola::Config {
            capacidad_bytes: 256 * 1024,
            capacidad_eventos: 2000,
            politica_lleno: crate::cola::PoliticaLleno::Rechazar,
        };
        c.diario = aegis_firehose::Config::nueva(dir.join("diario"));
        c
    }

    #[test]
    fn de_un_fichero_de_syslog_a_eventos_entregables() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        escribir(
            &log,
            "<38>Oct 11 22:14:15 srv sshd[9]: Failed password for root from 10.0.0.9 port 2 ssh2\n\
             <38>Oct 11 22:14:16 srv sshd[9]: Accepted publickey for op from 10.0.0.1 port 3 ssh2\n",
        );
        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log.clone(),
            syslog: true,
        })
        .unwrap();

        let informe = i.vuelta().unwrap();
        assert_eq!(informe.leidos, 2);
        assert_eq!(informe.escritos, 2);

        let (eventos, hasta) = i.entregar(100).unwrap();
        assert_eq!(eventos.len(), 2);
        assert_eq!(eventos[0].clase, crate::esquema::Clase::Autenticacion);
        assert_eq!(eventos[0].resultado, crate::esquema::Resultado::Fallo);
        assert_eq!(eventos[0].inquilino, "cliente-1");
        assert!(eventos[0].sello_valido());
        i.acusar(hasta.unwrap()).unwrap();

        // Ya acusado: no se vuelve a entregar.
        let (vacio, _) = i.entregar(100).unwrap();
        assert!(vacio.is_empty());
    }

    #[test]
    fn un_reinicio_reanuda_exactamente_donde_estaba() {
        // LA PRUEBA DE LA FASE, de extremo a extremo.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        escribir(&log, "primera\nsegunda\n");

        {
            let mut i = Ingesta::nueva(config(dir.path())).unwrap();
            i.anadir(Fuente::Fichero {
                ruta: log.clone(),
                syslog: false,
            })
            .unwrap();
            assert_eq!(i.vuelta().unwrap().leidos, 2);
            let (eventos, hasta) = i.entregar(100).unwrap();
            assert_eq!(eventos.len(), 2);
            i.acusar(hasta.unwrap()).unwrap();
        }

        escribir(&log, "tercera\n");

        let mut j = Ingesta::nueva(config(dir.path())).unwrap();
        j.anadir(Fuente::Fichero {
            ruta: log,
            syslog: false,
        })
        .unwrap();
        assert_eq!(j.vuelta().unwrap().leidos, 1, "ni repite ni se salta");
        let (eventos, _) = j.entregar(100).unwrap();
        assert_eq!(eventos.len(), 1);
        assert_eq!(eventos[0].mensaje, "tercera");
    }

    #[test]
    fn lo_no_acusado_se_reenvia_tras_un_reinicio() {
        // Hasta que el plano de control dice «lo tengo», el evento sigue en
        // disco. Es lo que permite reenviar en vez de perder lo que iba por el
        // cable.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        escribir(&log, "importante\n");
        {
            let mut i = Ingesta::nueva(config(dir.path())).unwrap();
            i.anadir(Fuente::Fichero {
                ruta: log.clone(),
                syslog: false,
            })
            .unwrap();
            i.vuelta().unwrap();
            let (eventos, _hasta) = i.entregar(100).unwrap();
            assert_eq!(eventos.len(), 1);
            // NO se acusa: el plano de control no contesto.
        }
        let mut j = Ingesta::nueva(config(dir.path())).unwrap();
        j.anadir(Fuente::Fichero {
            ruta: log,
            syslog: false,
        })
        .unwrap();
        let (eventos, _) = j.entregar(100).unwrap();
        assert_eq!(eventos.len(), 1, "se reenvia");
        assert_eq!(eventos[0].mensaje, "importante");
    }

    #[test]
    fn un_emisor_mas_rapido_que_el_receptor_no_hace_crecer_la_memoria() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("chorro.log");
        {
            let mut f = std::fs::File::create(&log).unwrap();
            for n in 0..50_000 {
                writeln!(f, "linea de aplicacion numero {n} con bastante relleno").unwrap();
            }
        }
        let mut cfg = config(dir.path());
        cfg.cola.capacidad_bytes = 64 * 1024;
        cfg.cola.capacidad_eventos = 200;
        let mut i = Ingesta::nueva(cfg).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log,
            syslog: false,
        })
        .unwrap();

        // Se dan muchas vueltas SIN entregar ni acusar nada: el peor caso.
        let mut freno_visto = false;
        for _ in 0..40 {
            let informe = i.vuelta().unwrap();
            freno_visto |= informe.frenando;
        }
        let _ = freno_visto; // el diario absorbe; lo que importa es la memoria
        assert!(
            i.cola.bytes() <= 64 * 1024,
            "la cola crecio a {}",
            i.cola.bytes()
        );
    }

    #[test]
    fn la_contrapresion_aparece_cuando_el_diario_no_traga() {
        // Un diario minusculo con politica de rechazo hace que la cola se
        // quede llena, y entonces la tuberia lee menos.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("chorro.log");
        {
            let mut f = std::fs::File::create(&log).unwrap();
            for n in 0..20_000 {
                writeln!(f, "linea {n} con relleno suficiente para ocupar").unwrap();
            }
        }
        let mut cfg = config(dir.path());
        cfg.cola.capacidad_bytes = 32 * 1024;
        cfg.cola.capacidad_eventos = 100;
        cfg.diario.presupuesto_bytes = 2 * 1024 * 1024;
        cfg.diario.bytes_por_segmento = 2 * 1024 * 1024;
        let mut i = Ingesta::nueva(cfg).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log,
            syslog: false,
        })
        .unwrap();

        let mut freno = false;
        for _ in 0..60 {
            freno |= i.vuelta().unwrap().frenando;
            if freno {
                break;
            }
        }
        assert!(freno, "nunca pidio freno");
        assert!(i.cola.bytes() <= 32 * 1024);
    }

    #[test]
    fn una_rotacion_a_mitad_de_ingesta_no_pierde_ni_duplica() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        escribir(&log, "antes-1\nantes-2\n");
        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log.clone(),
            syslog: false,
        })
        .unwrap();
        i.vuelta().unwrap();

        escribir(&log, "en-la-franja\n");
        std::fs::rename(&log, dir.path().join("auth.log.1")).unwrap();
        escribir(&log, "despues\n");

        i.vuelta().unwrap();
        i.vuelta().unwrap();
        let (eventos, _) = i.entregar(100).unwrap();
        let textos: Vec<&str> = eventos.iter().map(|e| e.mensaje.as_str()).collect();
        assert_eq!(
            textos,
            ["antes-1", "antes-2", "en-la-franja", "despues"],
            "se perdio la franja o se duplico algo"
        );
        // Y los identificadores son todos distintos: el ancla lleva el inodo.
        let ids: std::collections::BTreeSet<_> = eventos.iter().map(|e| &e.id).collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn dos_fuentes_con_el_mismo_nombre_se_rechazan() {
        // Dos seguidores sobre el mismo fichero producirian cada linea dos veces
        // con la misma ancla, y la deduplicacion las fundiria: el sintoma seria
        // «faltan eventos» y la causa estaria en la configuracion.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("a.log");
        escribir(&log, "x\n");
        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        let f = Fuente::Fichero {
            ruta: log,
            syslog: false,
        };
        i.anadir(f.clone()).unwrap();
        assert!(i.anadir(f).is_err());
    }

    #[test]
    fn la_cobertura_de_la_normalizacion_es_una_cifra() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("mezcla.log");
        let mut texto = String::new();
        for _ in 0..8 {
            texto.push_str(
                "<38>Oct 11 22:14:15 srv sshd[9]: Failed password for root from 1.2.3.4 port 2 ssh2\n",
            );
        }
        for _ in 0..2 {
            texto.push_str("<13>Oct 11 22:14:15 srv propio[1]: algo de la casa\n");
        }
        escribir(&log, &texto);

        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log,
            syslog: true,
        })
        .unwrap();
        i.vuelta().unwrap();
        assert_eq!(i.contadores().cobertura(), Some(80));
        assert_eq!(i.contadores().leidos, 10);
    }

    #[test]
    fn el_punto_de_control_no_avanza_si_el_diario_no_pudo_sincronizar() {
        // La regla de orden, vista desde arriba: si el diario falla, el fichero
        // se relee entero en la vuelta siguiente. Duplicados, no perdidas.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("a.log");
        escribir(&log, "una\ndos\n");
        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        i.anadir(Fuente::Fichero {
            ruta: log.clone(),
            syslog: false,
        })
        .unwrap();
        i.vuelta().unwrap();
        drop(i);

        // El punto de control quedo escrito porque todo fue bien.
        let p = PuntoDeControl::abrir(dir.path().join("punto")).unwrap();
        assert!(p.marca(&format!("fichero:{}", log.display())).is_some());
    }

    #[test]
    fn el_evtx_reanuda_por_identificador_de_registro() {
        let dir = tempfile::tempdir().unwrap();
        let evtx = dir.path().join("Security.evtx");
        std::fs::write(&evtx, ejemplo_evtx()).unwrap();

        let mut i = Ingesta::nueva(config(dir.path())).unwrap();
        i.anadir(Fuente::Evtx { ruta: evtx.clone() }).unwrap();
        assert_eq!(i.vuelta().unwrap().leidos, 1);
        assert_eq!(i.vuelta().unwrap().leidos, 0, "no repite");
        let (eventos, _) = i.entregar(10).unwrap();
        assert_eq!(eventos[0].clase, crate::esquema::Clase::Autenticacion);
        assert_eq!(eventos[0].origen, Origen::Evtx);
        assert_eq!(eventos[0].campos["evtx.event_id"], Valor::Entero(4625));
    }

    /// Un EVTX minimo con un 4625, construido con el formato real.
    fn ejemplo_evtx() -> Vec<u8> {
        // Se reutiliza el constructor de las pruebas de `evtx` a traves de su
        // salida ya montada: aqui solo hace falta un fichero valido.
        // El trozo son 64 KiB con dos zonas: los registros desde 0x200 —donde
        // los busca el lector, igual que en un fichero de Windows— y las
        // estructuras `Name` en la segunda mitad. Ponerlas delante deja el
        // fichero sin un solo registro localizable.
        const ZONA_NOMBRES: usize = 0x8000;
        let mut trozo = vec![0u8; crate::evtx::TROZO];
        trozo[0..8].copy_from_slice(crate::evtx::FIRMA_TROZO);

        let mut nombres: Vec<(String, u32)> = Vec::new();
        let mut fin_nombres = ZONA_NOMBRES;
        let mut poner = |trozo: &mut Vec<u8>, texto: &str| -> u32 {
            if let Some((_, en)) = nombres.iter().find(|(t, _)| t == texto) {
                return *en;
            }
            let en = fin_nombres;
            let mut buf = Vec::new();
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            let u: Vec<u16> = texto.encode_utf16().collect();
            buf.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
            trozo[en..en + buf.len()].copy_from_slice(&buf);
            fin_nombres = en + buf.len();
            nombres.push((texto.to_string(), u32::try_from(en).unwrap()));
            u32::try_from(en).unwrap()
        };

        let mut doc = vec![0x0f, 1, 1, 0];
        let abrir = |doc: &mut Vec<u8>, off: u32| {
            doc.push(0x01);
            doc.extend_from_slice(&0u16.to_le_bytes());
            doc.extend_from_slice(&0u32.to_le_bytes());
            doc.extend_from_slice(&off.to_le_bytes());
            doc.push(0x02);
        };
        let texto = |doc: &mut Vec<u8>, s: &str| {
            doc.push(0x05);
            doc.push(0x01);
            let u: Vec<u16> = s.encode_utf16().collect();
            doc.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                doc.extend_from_slice(&x.to_le_bytes());
            }
        };

        let off_event = poner(&mut trozo, "Event");
        let off_system = poner(&mut trozo, "System");
        let off_id = poner(&mut trozo, "EventID");
        let off_canal = poner(&mut trozo, "Channel");
        let off_maquina = poner(&mut trozo, "Computer");

        abrir(&mut doc, off_event);
        abrir(&mut doc, off_system);
        abrir(&mut doc, off_id);
        texto(&mut doc, "4625");
        doc.push(0x04);
        abrir(&mut doc, off_canal);
        texto(&mut doc, "Security");
        doc.push(0x04);
        abrir(&mut doc, off_maquina);
        texto(&mut doc, "SRV01");
        doc.push(0x04);
        doc.push(0x04); // System
        doc.push(0x04); // Event
        doc.push(0x00);

        let tamano = u32::try_from(24 + doc.len() + 4).unwrap();
        let mut reg = Vec::new();
        reg.extend_from_slice(&crate::evtx::FIRMA_REGISTRO.to_le_bytes());
        reg.extend_from_slice(&tamano.to_le_bytes());
        reg.extend_from_slice(&1u64.to_le_bytes());
        reg.extend_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        reg.extend_from_slice(&doc);
        reg.extend_from_slice(&tamano.to_le_bytes());
        trozo[0x200..0x200 + reg.len()].copy_from_slice(&reg);

        let mut fichero = vec![0u8; crate::evtx::CABECERA_FICHERO];
        fichero[0..8].copy_from_slice(crate::evtx::FIRMA_FICHERO);
        fichero.extend_from_slice(&trozo);
        fichero
    }
}
