//! El contrato: que recibe un motor, que devuelve y cuanto puede gastar.

use std::fmt;
use std::time::{Duration, Instant};

use aegis_entidad::{Eid, Senal};

/// Lo que el arbitro necesita saber de un evento para repartirlo.
///
/// El contrato es generico en el evento: el agente usa el suyo (telemetria del
/// kernel ya decodificada), y las pruebas usan uno de juguete. Lo unico que el
/// arbitro exige es poder nombrar la entidad a la que se refiere, para atribuirle
/// las señales y el «no pude mirar».
pub trait Evento {
    /// La entidad sobre la que trata el evento.
    fn entidad(&self) -> Eid;
    /// Cuando ocurrio, en nanosegundos del reloj del evento.
    fn cuando_ns(&self) -> u64;
}

/// Si el motor decide en linea o despues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Camino {
    /// En el bucle de eventos, por evento, con un presupuesto de microsegundos.
    ///
    /// Es lo que marca la latencia del agente: su p99 se publica por kernel.
    Caliente,
    /// Fuera de linea. El motor solo encola en `evaluar` y entrega sus señales
    /// despues por [`crate::Arbitro::aportar`]; su trabajo pesado corre en otro
    /// hilo o en el trabajador confinado.
    Frio,
}

impl Camino {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Camino::Caliente => "caliente",
            Camino::Frio => "frio",
        }
    }
}

/// Cuanto puede gastar un motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presupuesto {
    /// Tiempo maximo por evento.
    pub tiempo: Duration,
    /// Memoria maxima que el motor puede retener en su estado, en bytes.
    ///
    /// Es un techo DECLARADO que el arbitro comprueba con [`Motor::memoria`]:
    /// dentro de un proceso no se puede medir la memoria de un modulo. Donde hace
    /// falta un techo que el propio codigo no pueda saltarse, el motor corre en
    /// el trabajador confinado, con su cgroup.
    pub memoria: usize,
    /// Excesos SEGUIDOS que se toleran antes de suspender al motor.
    ///
    /// Uno aislado es ruido del planificador; varios seguidos son un motor que
    /// no cabe, y seguir llamandolo es cargar su coste a todos los demas.
    pub tolerancia: u32,
    /// Cuanto dura la suspension.
    pub suspension: Duration,
}

impl Presupuesto {
    /// Un presupuesto de camino caliente: `micros` por evento y `memoria` bytes.
    #[must_use]
    pub fn caliente(micros: u64, memoria: usize) -> Presupuesto {
        Presupuesto {
            tiempo: Duration::from_micros(micros),
            memoria,
            tolerancia: 8,
            suspension: Duration::from_secs(30),
        }
    }
}

/// Lo que un motor necesita del host para poder correr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Requisito {
    /// Telemetria del kernel por eBPF (tracefs y ring buffer).
    TelemetriaKernel,
    /// BPF LSM activo en la lista `lsm=` del kernel.
    BpfLsm,
    /// El trabajador confinado arrancado.
    TrabajadorConfinado,
    /// Virtualizacion (`/dev/kvm`).
    Kvm,
}

impl Requisito {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Requisito::TelemetriaKernel => "telemetria-kernel",
            Requisito::BpfLsm => "bpf-lsm",
            Requisito::TrabajadorConfinado => "trabajador-confinado",
            Requisito::Kvm => "kvm",
        }
    }
}

/// Quien sabe que ofrece este host.
///
/// El agente lo implementa con su deteccion de capacidades; las pruebas, con lo
/// que les convenga. `Err` lleva el motivo, que se publica tal cual.
pub trait Host {
    /// Si el host ofrece el requisito, o por que no.
    fn ofrece(&self, requisito: Requisito) -> Result<(), String>;
}

/// La tarjeta de presentacion de un motor.
#[derive(Debug, Clone)]
pub struct Ficha {
    /// Nombre estable y unico entre los motores del agente.
    pub nombre: &'static str,
    /// En nombre de quien firma sus señales, que fija su plano y su tope de
    /// confianza en el arbitro.
    pub firma: aegis_entidad::Motor,
    /// En linea o despues.
    pub camino: Camino,
    /// Cuanto puede gastar.
    pub presupuesto: Presupuesto,
    /// Que necesita del host.
    pub requisitos: &'static [Requisito],
}

/// El limite de tiempo de una evaluacion.
///
/// Cooperativo: un motor con bucles lo consulta y, si se agota, deja de trabajar
/// y devuelve [`Dictamen::SinDatos`] con [`Causa::PlazoAgotado`]. El arbitro
/// mide igualmente el tiempo real y sanciona al que no lo respete.
#[derive(Debug, Clone, Copy)]
pub struct Plazo {
    inicio: Instant,
    tope: Duration,
}

impl Plazo {
    /// Un plazo que empieza ahora.
    #[must_use]
    pub fn desde_ahora(tope: Duration) -> Plazo {
        Plazo {
            inicio: Instant::now(),
            tope,
        }
    }

    /// Si todavia queda tiempo.
    #[must_use]
    pub fn sigue(&self) -> bool {
        self.inicio.elapsed() < self.tope
    }

    /// El tope de este plazo.
    #[must_use]
    pub fn tope(&self) -> Duration {
        self.tope
    }

    /// Lo gastado hasta ahora.
    #[must_use]
    pub fn gastado(&self) -> Duration {
        self.inicio.elapsed()
    }
}

/// Por que un motor no pudo mirar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Causa {
    /// Se le acabo el tiempo de este evento.
    PlazoAgotado {
        /// Lo que gasto.
        gastado: Duration,
        /// Lo que tenia.
        tope: Duration,
    },
    /// Su estado paso del techo de memoria declarado.
    MemoriaAgotada {
        /// Lo que retiene.
        usada: usize,
        /// Su techo.
        tope: usize,
    },
    /// Esta suspendido por exceder su presupuesto de forma repetida.
    Suspendido,
    /// El trabajador confinado que hace su trabajo murio o no responde.
    TrabajadorCaido(String),
    /// Otro motivo, dicho por el motor.
    Otra(String),
}

impl fmt::Display for Causa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Causa::PlazoAgotado { gastado, tope } => write!(
                f,
                "plazo agotado: {} us de {} us",
                gastado.as_micros(),
                tope.as_micros()
            ),
            Causa::MemoriaAgotada { usada, tope } => {
                write!(f, "memoria agotada: {usada} bytes de {tope}")
            }
            Causa::Suspendido => f.write_str("suspendido por exceder su presupuesto"),
            Causa::TrabajadorCaido(m) => write!(f, "trabajador confinado caido: {m}"),
            Causa::Otra(m) => f.write_str(m),
        }
    }
}

impl Causa {
    /// Clave corta y estable, para contar por causa.
    #[must_use]
    pub fn clave(&self) -> &'static str {
        match self {
            Causa::PlazoAgotado { .. } => "plazo",
            Causa::MemoriaAgotada { .. } => "memoria",
            Causa::Suspendido => "suspendido",
            Causa::TrabajadorCaido(_) => "trabajador",
            Causa::Otra(_) => "otra",
        }
    }
}

/// Lo que devuelve un motor por evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dictamen {
    /// El evento no es de su incumbencia. No cuenta como «no pude mirar».
    NoAplica,
    /// Lo que opina, con su evidencia en cada [`Senal::porque`].
    Senales(Vec<Senal>),
    /// Le tocaba mirar y no pudo. **No es limpio.**
    SinDatos(Causa),
}

/// Un motor de deteccion.
///
/// Todos los motores del agente lo implementan, y solo [`crate::Arbitro`] lo
/// llama: un motor no ve a los demas ni decide nada por su cuenta.
pub trait Motor<E>: Send {
    /// Quien es, que necesita y cuanto puede gastar.
    fn ficha(&self) -> Ficha;

    /// Evalua un evento dentro de `plazo`.
    fn evaluar(&mut self, evento: &E, plazo: &Plazo) -> Dictamen;

    /// Bytes que retiene su estado ahora mismo.
    ///
    /// Lo consulta el arbitro despues de cada evaluacion para comprobar el techo
    /// de [`Presupuesto::memoria`]. Un motor sin estado devuelve 0.
    fn memoria(&self) -> usize {
        0
    }

    /// Suelta estado para volver bajo su techo de memoria.
    ///
    /// Lo llama el arbitro cuando [`Motor::memoria`] se pasa del techo, antes de
    /// suspenderlo. Un motor con estado tiene que implementarlo: olvidar lo mas
    /// viejo es peor que no olvidar, pero mejor que quedarse ciego entero.
    fn aligerar(&mut self) {}

    /// Mantenimiento periodico, fuera del camino caliente.
    fn mantener(&mut self, _ahora_ns: u64) {}
}
