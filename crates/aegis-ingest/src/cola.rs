//! La cola acotada: contrapresion y descarte contado.
//!
//! # La invariante que sostiene todo lo demas
//!
//! **Ninguna cola crece sin limite.** Un plano de control que se cae por un pico
//! de registros deja ciega a la flota entera, y lo mismo vale para el endpoint:
//! si la ingesta se come la memoria, se lleva por delante a la deteccion, que es
//! la razon de que el agente este ahi.
//!
//! Asi que la capacidad es un numero, sale del presupuesto del host —no de una
//! constante inventada aqui— y cuando se llena pasa algo explicito.
//!
//! # Que pasa cuando se llena, y por que NO es «tirar lo mas viejo»
//!
//! Lo intuitivo es descartar lo mas antiguo y seguir aceptando. Aplicado sin
//! matices es un agujero de seguridad con nombre propio: **quien pueda generar
//! volumen puede expulsar evidencia**. Un atacante que acaba de entrar solo
//! tiene que provocar unos miles de lineas para que la linea que lo delata salga
//! de la cola antes de subir.
//!
//! La politica de aqui tiene dos escalones y el orden importa:
//!
//! 1. **Entre prioridades distintas, se tira lo que menos cuesta perder.** Un
//!    evento de seguridad entra desalojando log de aplicacion. Esto no se puede
//!    usar para expulsar evidencia: el log de aplicacion es justamente lo que un
//!    atacante no necesita conservar.
//! 2. **Dentro de la misma prioridad, se RECHAZA lo nuevo** ([`PoliticaLleno`]).
//!    Rechazar falla ruidosamente hacia quien produce —que puede reducir el
//!    ritmo, o dejarlo en disco— mientras que descartar lo viejo falla en
//!    silencio y borra lo que ya estaba a salvo.
//!
//! Y todo lo que se descarta o se rechaza **se cuenta por prioridad**. Un
//! sistema que pierde eventos en silencio es peor que uno que se niega a
//! aceptarlos.
//!
//! # Por que el vaciado es ponderado y no estrictamente por prioridad
//!
//! Vaciar siempre primero lo mas importante es el error clasico de las colas con
//! prioridad: con un chorro sostenido de eventos de seguridad, el log de
//! aplicacion **no sale nunca**, envejece en la cola y acaba descartado aunque
//! hubiera sitio de sobra en el enlace. La respuesta no es renunciar a la
//! prioridad, sino garantizar un minimo a cada clase: cada vuelta reparte siete
//! huecos, cuatro para seguridad, dos para sistema y uno para aplicacion. Ver
//! [`CUOTAS`].

use std::collections::VecDeque;

use aegis_presupuesto::{Componente, Presupuesto};

use crate::esquema::{Evento, Prioridad};

/// Huecos por vuelta de cada prioridad, de mayor a menor.
///
/// Cuatro, dos y uno: la telemetria de seguridad se lleva mas de la mitad de
/// cada vuelta, pero el log de aplicacion tiene garantizado su hueco y por tanto
/// no envejece indefinidamente detras de un chorro que no para.
pub const CUOTAS: [u8; 3] = [4, 2, 1];

/// Ocupacion, en centesimas, a la que se empieza a pedir freno.
pub const MARCA_ALTA: u32 = 75;

/// Ocupacion, en centesimas, a la que se deja de pedir freno.
///
/// Muy por debajo de [`MARCA_ALTA`] a proposito. Con un solo umbral, una cola
/// que oscila alrededor de el manda «frena / no frenes» varias veces por
/// segundo, y el emisor pasa mas tiempo cambiando de ritmo que enviando.
pub const MARCA_BAJA: u32 = 50;

/// Que hacer cuando no cabe y no queda nada de menor prioridad que tirar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoliticaLleno {
    /// Rechazar lo nuevo. Quien produce se entera.
    ///
    /// Es el valor por defecto porque es el unico que no se puede usar para
    /// expulsar evidencia: ver el encabezado del modulo.
    #[default]
    Rechazar,
    /// Descartar lo mas antiguo de la misma prioridad.
    ///
    /// Existe porque hay despliegues donde la telemetria reciente vale mas que
    /// la historica —un panel operativo, no una investigacion— y ahi es la
    /// eleccion correcta. Se declara; no se hereda sin querer.
    DescartarMasAntiguos,
}

/// Ajustes de la cola.
#[derive(Debug, Clone)]
pub struct Config {
    /// Techo de memoria de la cola, en bytes.
    pub capacidad_bytes: usize,
    /// Techo de eventos.
    ///
    /// Hace falta ademas del de bytes: un millon de eventos de cien bytes cabe
    /// de sobra en memoria y aun asi hunde a cualquier consumidor que trabaje
    /// por evento.
    pub capacidad_eventos: usize,
    /// Que hacer cuando no cabe y no hay nada menor que tirar.
    pub politica_lleno: PoliticaLleno,
}

impl Config {
    /// Capacidad tomada del presupuesto del host.
    ///
    /// La cuota de la ingesta sale de [`Componente::Ingesta`], que a su vez sale
    /// de la memoria del anfitrion. En una pasarela de 1 GiB son unos 2 MiB de
    /// cola; en un servidor de 768 GiB, decenas. Es lo que hace que el mismo
    /// binario sea razonable en los dos sitios sin que nadie toque un fichero de
    /// configuracion.
    #[must_use]
    pub fn del_presupuesto(p: &Presupuesto) -> Config {
        let bytes = usize::try_from(p.cuota(Componente::Ingesta)).unwrap_or(usize::MAX);
        Config {
            capacidad_bytes: bytes,
            // Un evento normalizado tipico ronda el medio kilobyte. El techo de
            // eventos se deriva de ahi para que las dos cotas se alcancen mas o
            // menos a la vez y ninguna sea decorativa.
            capacidad_eventos: (bytes / 512).max(64),
            politica_lleno: PoliticaLleno::Rechazar,
        }
    }
}

/// Lo que paso al intentar meter un evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admision {
    /// Entro sin desalojar nada.
    Admitido,
    /// Entro desalojando eventos de menor valor.
    ///
    /// No es un exito silencioso: quien llama lo publica, porque significa que
    /// la maquina esta perdiendo telemetria de forma sostenida.
    AdmitidoDesalojando {
        /// Cuantos se tiraron.
        cuantos: usize,
        /// De que prioridad era el mas alto que se tiro.
        prioridad: Prioridad,
    },
    /// No entro. El productor tiene que reducir el ritmo o guardarlo en disco.
    Rechazado,
}

/// Todo lo que se pierde, contado y por prioridad.
///
/// Sin esto la politica de descarte seria una promesa. Con esto es una cifra que
/// sale en el panel: «esta maquina lleva cuatro horas tirando log de aplicacion»
/// es una frase que alguien puede accionar.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos admitidos.
    pub admitidos: u64,
    /// Eventos rechazados por no caber.
    pub rechazados: u64,
    /// Descartados de prioridad de aplicacion.
    pub descartados_aplicacion: u64,
    /// Descartados de prioridad de sistema.
    pub descartados_sistema: u64,
    /// Descartados de prioridad de seguridad.
    ///
    /// Que este contador deje de ser cero es un incidente operativo: significa
    /// que la maquina esta tirando telemetria de seguridad.
    pub descartados_seguridad: u64,
    /// Veces que se entro en contrapresion.
    pub frenadas: u64,
}

impl Contadores {
    /// Total perdido, se tirara o se rechazara.
    #[must_use]
    pub fn perdidos(&self) -> u64 {
        self.rechazados
            + self.descartados_aplicacion
            + self.descartados_sistema
            + self.descartados_seguridad
    }
}

/// Cola acotada con prioridad, contrapresion y descarte contado.
#[derive(Debug)]
pub struct Cola {
    cfg: Config,
    /// Un carril por prioridad, de mayor a menor: seguridad, sistema,
    /// aplicacion.
    carriles: [VecDeque<Evento>; 3],
    bytes: usize,
    eventos: usize,
    credito: [u8; 3],
    frenando: bool,
    contadores: Contadores,
}

/// Indice del carril de una prioridad. Cero es la mas valiosa.
fn carril_de(p: Prioridad) -> usize {
    match p {
        Prioridad::Seguridad => 0,
        Prioridad::Sistema => 1,
        Prioridad::Aplicacion => 2,
    }
}

fn prioridad_de(carril: usize) -> Prioridad {
    match carril {
        0 => Prioridad::Seguridad,
        1 => Prioridad::Sistema,
        _ => Prioridad::Aplicacion,
    }
}

impl Cola {
    /// Crea la cola.
    #[must_use]
    pub fn nueva(cfg: Config) -> Cola {
        Cola {
            cfg,
            carriles: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            bytes: 0,
            eventos: 0,
            credito: CUOTAS,
            frenando: false,
            contadores: Contadores::default(),
        }
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Eventos en cola.
    #[must_use]
    pub fn largo(&self) -> usize {
        self.eventos
    }

    /// Bytes en cola.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Si no queda nada.
    #[must_use]
    pub fn vacia(&self) -> bool {
        self.eventos == 0
    }

    /// Ocupacion en centesimas, la mayor de las dos cotas.
    ///
    /// Se toma la mayor porque cualquiera de las dos que se alcance deja la cola
    /// llena de verdad; mirar solo los bytes dejaria pasar el caso del millon de
    /// eventos diminutos.
    #[must_use]
    pub fn ocupacion(&self) -> u32 {
        let por_bytes = if self.cfg.capacidad_bytes == 0 {
            100
        } else {
            u32::try_from(self.bytes * 100 / self.cfg.capacidad_bytes).unwrap_or(100)
        };
        let por_eventos = if self.cfg.capacidad_eventos == 0 {
            100
        } else {
            u32::try_from(self.eventos * 100 / self.cfg.capacidad_eventos).unwrap_or(100)
        };
        por_bytes.max(por_eventos).min(100)
    }

    /// Si hay que pedir al emisor que reduzca el ritmo.
    ///
    /// Con histeresis: se entra en [`MARCA_ALTA`] y no se sale hasta
    /// [`MARCA_BAJA`]. Ver por que en la documentacion de esa constante.
    pub fn debe_frenar(&mut self) -> bool {
        let o = self.ocupacion();
        if self.frenando {
            if o <= MARCA_BAJA {
                self.frenando = false;
            }
        } else if o >= MARCA_ALTA {
            self.frenando = true;
            self.contadores.frenadas += 1;
        }
        self.frenando
    }

    /// Mete un evento, aplicando la politica si no cabe.
    pub fn admitir(&mut self, evento: Evento) -> Admision {
        let tamano = evento.bytes();
        // Un evento que ni siquiera cabe en la cola vacia no puede entrar nunca,
        // y hay que decirlo aqui: sin esta salida, el bucle de desalojo vaciaria
        // la cola entera intentando hacer sitio para algo que no cabe, y el
        // resultado seria perderlo todo por un solo evento monstruoso.
        if tamano > self.cfg.capacidad_bytes || self.cfg.capacidad_eventos == 0 {
            self.contadores.rechazados += 1;
            return Admision::Rechazado;
        }

        let prioridad = evento.prioridad();
        let mio = carril_de(prioridad);
        let mut desalojados = 0usize;
        let mut peor: Option<Prioridad> = None;

        // Primer escalon: desalojar de los carriles ESTRICTAMENTE menos
        // valiosos, del menos valioso hacia arriba.
        while !self.cabe(tamano) {
            let Some(victima) = (mio + 1..3).rev().find(|c| !self.carriles[*c].is_empty()) else {
                break;
            };
            self.sacar_del_frente(victima);
            self.contar_descarte(prioridad_de(victima));
            desalojados += 1;
            peor = Some(match peor {
                Some(p) => p.max(prioridad_de(victima)),
                None => prioridad_de(victima),
            });
        }

        // Segundo escalon: dentro de la misma prioridad.
        if !self.cabe(tamano) {
            match self.cfg.politica_lleno {
                PoliticaLleno::Rechazar => {
                    self.contadores.rechazados += 1;
                    return if desalojados > 0 {
                        // Se tiro algo y aun asi no cupo: hay que contarlo, o el
                        // panel diria que no se perdio nada.
                        Admision::Rechazado
                    } else {
                        Admision::Rechazado
                    };
                }
                PoliticaLleno::DescartarMasAntiguos => {
                    while !self.cabe(tamano) && !self.carriles[mio].is_empty() {
                        self.sacar_del_frente(mio);
                        self.contar_descarte(prioridad);
                        desalojados += 1;
                        peor = Some(match peor {
                            Some(p) => p.max(prioridad),
                            None => prioridad,
                        });
                    }
                    if !self.cabe(tamano) {
                        self.contadores.rechazados += 1;
                        return Admision::Rechazado;
                    }
                }
            }
        }

        self.bytes += tamano;
        self.eventos += 1;
        self.carriles[mio].push_back(evento);
        self.contadores.admitidos += 1;
        match peor {
            Some(p) => Admision::AdmitidoDesalojando {
                cuantos: desalojados,
                prioridad: p,
            },
            None => Admision::Admitido,
        }
    }

    /// Saca el siguiente evento a entregar, con reparto ponderado.
    ///
    /// Ver el encabezado del modulo para por que no es estrictamente por
    /// prioridad.
    pub fn siguiente(&mut self) -> Option<Evento> {
        if self.vacia() {
            return None;
        }
        // Dos vueltas como mucho: una con el credito que quede y otra despues de
        // recargarlo. Si en las dos no hay nada, es que la cola estaba vacia, y
        // eso ya se descarto arriba.
        for _ in 0..2 {
            for c in 0..3 {
                if self.credito[c] > 0 && !self.carriles[c].is_empty() {
                    self.credito[c] -= 1;
                    return self.sacar_del_frente(c);
                }
            }
            self.credito = CUOTAS;
        }
        None
    }

    /// Saca hasta `maximo` eventos de una vez.
    pub fn lote(&mut self, maximo: usize) -> Vec<Evento> {
        let mut v = Vec::new();
        while v.len() < maximo {
            match self.siguiente() {
                Some(e) => v.push(e),
                None => break,
            }
        }
        v
    }

    fn cabe(&self, tamano: usize) -> bool {
        self.bytes + tamano <= self.cfg.capacidad_bytes && self.eventos < self.cfg.capacidad_eventos
    }

    fn sacar_del_frente(&mut self, carril: usize) -> Option<Evento> {
        let e = self.carriles[carril].pop_front()?;
        self.bytes = self.bytes.saturating_sub(e.bytes());
        self.eventos = self.eventos.saturating_sub(1);
        Some(e)
    }

    fn contar_descarte(&mut self, p: Prioridad) {
        match p {
            Prioridad::Aplicacion => self.contadores.descartados_aplicacion += 1,
            Prioridad::Sistema => self.contadores.descartados_sistema += 1,
            Prioridad::Seguridad => self.contadores.descartados_seguridad += 1,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::esquema::{Clase, ConfianzaReloj, Origen, Resultado, Severidad, VERSION};
    use std::collections::BTreeMap;

    fn evento(prioridad: Prioridad, relleno: usize, n: u64) -> Evento {
        let (clase, origen, severidad) = match prioridad {
            Prioridad::Seguridad => (Clase::HallazgoDeSeguridad, Origen::Agente, Severidad::Alta),
            Prioridad::Sistema => (
                Clase::ActividadDelSistema,
                Origen::Journald,
                Severidad::Info,
            ),
            Prioridad::Aplicacion => (Clase::ActividadDelSistema, Origen::Fichero, Severidad::Info),
        };
        let mut e = Evento {
            version: VERSION,
            id: String::new(),
            ancla: format!("prueba#{n}"),
            ocurrio_ns: 1_700_000_000_000_000_000 + n,
            observado_ns: 1_700_000_000_000_000_000 + n,
            reloj: ConfianzaReloj::DelOrigen,
            clase,
            resultado: Resultado::Desconocido,
            severidad,
            origen,
            anfitrion: "h".into(),
            inquilino: "t".into(),
            productor: "p".into(),
            mensaje: "x".repeat(relleno),
            campos: BTreeMap::new(),
            crudo: None,
        };
        e.sellar();
        assert_eq!(e.prioridad(), prioridad);
        e
    }

    fn cola(bytes: usize, eventos: usize) -> Cola {
        Cola::nueva(Config {
            capacidad_bytes: bytes,
            capacidad_eventos: eventos,
            politica_lleno: PoliticaLleno::Rechazar,
        })
    }

    // --- La invariante: la memoria no crece ---------------------------------

    #[test]
    fn un_emisor_mas_rapido_que_el_receptor_no_hace_crecer_la_memoria() {
        // LA PRUEBA DE LA FASE. Cien mil eventos contra una cola de 64 KiB.
        let mut c = cola(64 * 1024, 10_000);
        for n in 0..100_000u64 {
            let _ = c.admitir(evento(Prioridad::Sistema, 200, n));
            assert!(c.bytes() <= 64 * 1024, "en el evento {n}: {}", c.bytes());
            assert!(c.largo() <= 10_000);
        }
        // Y lo que se perdio esta contado, no desaparecido.
        let k = c.contadores();
        assert!(k.perdidos() > 0);
        assert_eq!(k.admitidos + k.rechazados, 100_000 + k.descartados_sistema);
    }

    #[test]
    fn el_tope_de_eventos_tambien_manda() {
        // Un millon de eventos diminutos cabe de sobra en memoria y aun asi
        // hunde a cualquier consumidor que trabaje por evento.
        let mut c = cola(usize::MAX / 2, 10);
        for n in 0..1_000u64 {
            let _ = c.admitir(evento(Prioridad::Sistema, 0, n));
        }
        assert_eq!(c.largo(), 10);
    }

    // --- La politica de descarte --------------------------------------------

    #[test]
    fn un_evento_de_seguridad_entra_desalojando_log_de_aplicacion() {
        let mut c = cola(4096, 100);
        let mut metidos = 0;
        while c.ocupacion() < 100 {
            if matches!(
                c.admitir(evento(Prioridad::Aplicacion, 100, metidos)),
                Admision::Rechazado
            ) {
                break;
            }
            metidos += 1;
        }
        let antes = c.contadores().descartados_aplicacion;
        let r = c.admitir(evento(Prioridad::Seguridad, 100, 9999));
        assert!(matches!(r, Admision::AdmitidoDesalojando { .. }), "{r:?}");
        assert!(c.contadores().descartados_aplicacion > antes, "y se cuenta");
        assert_eq!(c.contadores().descartados_seguridad, 0);
    }

    #[test]
    fn el_log_de_aplicacion_no_desaloja_a_la_telemetria_de_seguridad() {
        let mut c = cola(4096, 100);
        let mut n = 0u64;
        while !matches!(
            c.admitir(evento(Prioridad::Seguridad, 100, n)),
            Admision::Rechazado
        ) {
            n += 1;
        }
        let seguridad_en_cola = c.largo();
        let r = c.admitir(evento(Prioridad::Aplicacion, 100, 9999));
        assert_eq!(r, Admision::Rechazado);
        assert_eq!(c.largo(), seguridad_en_cola, "no se toco nada");
        assert_eq!(c.contadores().descartados_seguridad, 0);
    }

    #[test]
    fn nadie_puede_expulsar_evidencia_llenando_la_cola() {
        // EL AGUJERO QUE LA POLITICA POR DEFECTO CIERRA. Un atacante que acaba de
        // entrar solo tendria que provocar volumen para que la linea que lo
        // delata saliera de la cola antes de subir.
        let mut c = cola(4096, 100);
        let delator = evento(Prioridad::Seguridad, 100, 1);
        assert_eq!(c.admitir(delator.clone()), Admision::Admitido);

        // El atacante genera todo el ruido que quiera, de la prioridad que
        // quiera.
        for n in 0..10_000u64 {
            let _ = c.admitir(evento(Prioridad::Aplicacion, 100, 1000 + n));
            let _ = c.admitir(evento(Prioridad::Sistema, 100, 50_000 + n));
            let _ = c.admitir(evento(Prioridad::Seguridad, 100, 90_000 + n));
        }

        // Y el delator sigue ahi.
        let todos = c.lote(usize::MAX);
        assert!(
            todos.iter().any(|e| e.id == delator.id),
            "la evidencia se expulso: {} eventos en cola",
            todos.len()
        );
        assert_eq!(c.contadores().descartados_seguridad, 0);
    }

    #[test]
    fn la_politica_de_descartar_lo_viejo_existe_pero_hay_que_pedirla() {
        let mut c = Cola::nueva(Config {
            capacidad_bytes: 2048,
            capacidad_eventos: 100,
            politica_lleno: PoliticaLleno::DescartarMasAntiguos,
        });
        let primero = evento(Prioridad::Seguridad, 100, 1);
        let _ = c.admitir(primero.clone());
        for n in 0..1_000u64 {
            let _ = c.admitir(evento(Prioridad::Seguridad, 100, 100 + n));
        }
        let todos = c.lote(usize::MAX);
        assert!(!todos.iter().any(|e| e.id == primero.id), "aqui SI se tira");
        assert!(c.contadores().descartados_seguridad > 0, "y se cuenta");
    }

    #[test]
    fn un_evento_que_no_cabe_ni_en_la_cola_vacia_no_la_vacia_entera() {
        // Sin la salida temprana, el bucle de desalojo tiraria todo intentando
        // hacer sitio para algo que no cabe, y se perderia todo por un solo
        // evento monstruoso.
        let mut c = cola(2048, 100);
        for n in 0..5u64 {
            assert_eq!(
                c.admitir(evento(Prioridad::Sistema, 100, n)),
                Admision::Admitido
            );
        }
        let antes = c.largo();
        assert_eq!(
            c.admitir(evento(Prioridad::Seguridad, 100_000, 999)),
            Admision::Rechazado
        );
        assert_eq!(c.largo(), antes, "no se toco la cola");
    }

    // --- La contrapresion ---------------------------------------------------

    #[test]
    fn la_contrapresion_tiene_histeresis() {
        // Con un solo umbral, una cola que oscila alrededor de el manda
        // «frena / no frenes» varias veces por segundo.
        let mut c = cola(10_000, 100);
        for n in 0..80u64 {
            let _ = c.admitir(evento(Prioridad::Sistema, 0, n));
        }
        assert!(c.ocupacion() >= MARCA_ALTA);
        assert!(c.debe_frenar());

        // Baja por debajo del umbral alto pero por encima del bajo: sigue
        // frenando.
        while c.ocupacion() > MARCA_BAJA + 5 {
            c.siguiente();
        }
        assert!(c.debe_frenar(), "en {} sigue frenando", c.ocupacion());

        while c.ocupacion() > MARCA_BAJA {
            c.siguiente();
        }
        assert!(!c.debe_frenar());
        assert_eq!(c.contadores().frenadas, 1, "una sola entrada, no un tren");
    }

    #[test]
    fn la_ocupacion_mira_la_mayor_de_las_dos_cotas() {
        let mut c = cola(1_000_000, 10);
        for n in 0..8u64 {
            let _ = c.admitir(evento(Prioridad::Sistema, 0, n));
        }
        assert_eq!(c.ocupacion(), 80, "por eventos, no por bytes");
    }

    // --- El reparto del vaciado ---------------------------------------------

    #[test]
    fn un_chorro_de_seguridad_no_deja_el_log_de_aplicacion_parado_para_siempre() {
        // EL ERROR CLASICO DE LAS COLAS CON PRIORIDAD. Con vaciado estrictamente
        // por prioridad, el log de aplicacion no sale nunca, envejece y acaba
        // descartado aunque hubiera sitio de sobra en el enlace.
        let mut c = cola(10_000_000, 10_000);
        for n in 0..700u64 {
            let _ = c.admitir(evento(Prioridad::Seguridad, 0, n));
            let _ = c.admitir(evento(Prioridad::Sistema, 0, 10_000 + n));
            let _ = c.admitir(evento(Prioridad::Aplicacion, 0, 20_000 + n));
        }
        let lote = c.lote(700);
        let mut cuenta = [0usize; 3];
        for e in &lote {
            cuenta[carril_de(e.prioridad())] += 1;
        }
        // Cuatro, dos y uno de cada siete.
        assert_eq!(cuenta[0], 400, "seguridad");
        assert_eq!(cuenta[1], 200, "sistema");
        assert_eq!(cuenta[2], 100, "aplicacion");
    }

    #[test]
    fn si_no_hay_de_una_prioridad_su_hueco_no_se_desperdicia() {
        let mut c = cola(10_000_000, 10_000);
        for n in 0..100u64 {
            let _ = c.admitir(evento(Prioridad::Aplicacion, 0, n));
        }
        let lote = c.lote(100);
        assert_eq!(
            lote.len(),
            100,
            "no se queda esperando a los carriles vacios"
        );
    }

    #[test]
    fn dentro_de_un_carril_se_conserva_el_orden_de_llegada() {
        let mut c = cola(10_000_000, 10_000);
        for n in 0..50u64 {
            let _ = c.admitir(evento(Prioridad::Seguridad, 0, n));
        }
        let lote = c.lote(50);
        for (i, e) in lote.iter().enumerate() {
            assert_eq!(e.ancla, format!("prueba#{i}"));
        }
    }

    #[test]
    fn una_cola_vacia_no_devuelve_nada_ni_se_cuelga() {
        let mut c = cola(1024, 10);
        assert!(c.siguiente().is_none());
        assert!(c.lote(100).is_empty());
        assert!(c.vacia());
    }

    // --- El presupuesto -----------------------------------------------------

    #[test]
    fn la_capacidad_sale_del_presupuesto_del_host_y_no_de_una_constante() {
        // El mismo binario tiene que ser razonable en una pasarela de 1 GiB y en
        // un servidor de 768 GiB sin que nadie toque un fichero.
        let pasarela = Config::del_presupuesto(&Presupuesto::para(1024 * 1024 * 1024));
        let servidor = Config::del_presupuesto(&Presupuesto::para(768 * 1024 * 1024 * 1024));
        assert!(servidor.capacidad_bytes > pasarela.capacidad_bytes * 4);
        assert!(pasarela.capacidad_bytes > 0);
        assert!(pasarela.capacidad_eventos >= 64, "siempre queda un minimo");
    }

    #[test]
    fn una_cola_de_capacidad_cero_rechaza_en_vez_de_dividir_por_cero() {
        let mut c = cola(0, 0);
        assert_eq!(
            c.admitir(evento(Prioridad::Seguridad, 0, 1)),
            Admision::Rechazado
        );
        assert_eq!(c.ocupacion(), 100);
    }

    #[test]
    fn todo_lo_que_se_pierde_esta_contado() {
        // Un sistema que pierde eventos en silencio es peor que uno que se niega
        // a aceptarlos.
        let mut c = cola(2048, 20);
        let mut intentos = 0u64;
        for n in 0..5_000u64 {
            let _ = c.admitir(evento(Prioridad::Aplicacion, 50, n));
            intentos += 1;
        }
        let k = c.contadores();
        assert_eq!(k.admitidos + k.rechazados, intentos);
        assert_eq!(
            u64::try_from(c.largo()).unwrap() + k.descartados_aplicacion,
            k.admitidos
        );
    }
}
