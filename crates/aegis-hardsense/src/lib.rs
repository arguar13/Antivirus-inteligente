//! # `aegis-hardsense` — AegisHPC: la PMU como sensor de defensa (FASE 61)
//!
//! ## Escuchar al procesador
//!
//! Hay ataques que no dejan rastro en las syscalls ni en los ficheros, pero SI
//! en como el procesador se comporta. Un ataque de **canal lateral por cache**
//! (Flush+Reload, Prime+Probe, Spectre) desaloja y recarga lineas de cache miles
//! de veces para robar secretos midiendo tiempos: eso dispara los **fallos de la
//! ultima cache (LLC)**. Una cadena **ROP/JOP** salta por gadgets que el
//! predictor de saltos no aprendio: eso dispara los **fallos de prediccion de
//! saltos** y hunde el IPC. La Performance Monitoring Unit (PMU) del procesador
//! cuenta esos eventos en hardware, casi gratis; AegisHPC la usa como un sensor
//! mas de la defensa.
//!
//! ## Las dos piezas
//!
//! - **La decision** ([`heuristica`], [`AnalizadorHpc`]): aprende la linea base
//!   de cada proceso (por EWMA de media y varianza) y marca un pico que se
//!   dispara muchas sigmas sobre esa base Y sobre un piso absoluto. Es la parte
//!   que puede estar mal de forma peligrosa, y es Rust puro, probada entera con
//!   series de datos reales y cero mocks. Un ataque marcado no entrena la base:
//!   no se le puede ensenar al detector a ignorarlo.
//! - **La captura** ([`contadores`], [`ContadoresHpc`]): abre los contadores de
//!   la PMU por `perf_event_open` y produce las muestras. Reutiliza un espejo
//!   minimo de `perf_event_attr` propio del crate —como `aegis-syscallguard` y
//!   `aegis-ptguard`—, para no arrastrar la maquinaria de otros.
//!
//! ## Honestidad sobre el hardware
//!
//! Leer la PMU necesita que el hardware la exponga. Muchas maquinas virtuales
//! —el runner del CI, entre ellas— no lo hacen: `perf_event_open` devuelve
//! `ENOENT`. Eso se reporta como [`SoporteHpc::NoDisponible`], nunca se finge. La
//! DECISION no depende de la PMU: opera sobre numeros y se prueba en cada
//! `make ci`; la captura en vivo es el muro, declarado en
//! `tools/verificar-hardsense.sh`.
//!
//! ## Defensivo, no ofensivo
//!
//! La misma PMU podria usarse para construir un canal lateral; aqui se usa solo
//! para DETECTAR uno. AegisHPC lee sus propios contadores para delatar a quien
//! ataca, jamas para atacar.

pub mod contadores;
pub mod heuristica;
pub mod perf;

pub use contadores::{sondear_hpc, ContadoresHpc, SoporteHpc};
pub use heuristica::{AnalizadorHpc, ClaseAnomalia, EventoHpc, MuestraPmu, Severidad};

/// AegisHPC: compone la captura de la PMU y el analizador de anomalias en un solo
/// sensor. Donde hay PMU, [`AegisHpc::muestrear`] lee una ventana y decide; donde
/// no la hay, [`AegisHpc::iniciar`] devuelve el `errno` para que el llamante lo
/// reporte con honestidad.
///
/// El analizador ([`AnalizadorHpc`]) tambien se puede usar suelto, alimentado por
/// cualquier fuente de [`MuestraPmu`]: es lo que hace que la decision sea probable
/// sin PMU.
pub struct AegisHpc {
    contadores: ContadoresHpc,
    analizador: AnalizadorHpc,
}

impl AegisHpc {
    /// Arranca el sensor: abre los contadores de la PMU sobre el hilo actual y
    /// los pone en marcha.
    ///
    /// # Errores
    /// El `errno` de `perf_event_open`/`ioctl` (p. ej. `ENOENT` sin PMU). Ver
    /// [`sondear_hpc`] para preguntar antes sin comprometerse.
    pub fn iniciar() -> Result<Self, std::io::Error> {
        let mut contadores = ContadoresHpc::abrir()?;
        contadores.arrancar()?;
        Ok(Self {
            contadores,
            analizador: AnalizadorHpc::nuevo(),
        })
    }

    /// Lee la ventana desde la ultima llamada y decide si hay una anomalia.
    ///
    /// # Errores
    /// El `errno` de `read` si el kernel rechaza la lectura del contador.
    pub fn muestrear(&mut self) -> Result<Option<EventoHpc>, std::io::Error> {
        let muestra = self.contadores.leer_muestra()?;
        Ok(self.analizador.observar(&muestra))
    }

    /// Acceso al analizador (p. ej. para consultar si sigue en calentamiento).
    #[must_use]
    pub fn analizador(&self) -> &AnalizadorHpc {
        &self.analizador
    }
}
