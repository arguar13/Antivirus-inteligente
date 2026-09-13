//! # aegis-presupuesto
//!
//! Cuanta memoria puede gastar el agente, quien le obliga a cumplirlo y que pasa
//! cuando se pasa.
//!
//! ## Por que no es un numero
//!
//! Durante mucho tiempo el presupuesto de AegisCore fue «45 MB». Esa cifra tenia
//! tres problemas, y solo uno era el tamano:
//!
//! 1. **Un numero para tres regimenes.** Un agente que gasta lo mismo vigilando
//!    que escaneando el disco entero no es eficiente: es un agente que no esta
//!    escaneando. Hacen falta tres cifras —reposo, pico y techo— porque son tres
//!    preguntas distintas: que ve el administrador en `top`, que necesita el
//!    agente para trabajar, y a partir de donde el agente es un peligro para la
//!    maquina que vino a proteger.
//! 2. **Un numero para todos los hosts.** Una pasarela industrial de 1 GiB y un
//!    host de base de datos de 768 GiB no pueden compartir presupuesto. Al
//!    segundo le sale mas barato tener el corpus residente que ir al disco en
//!    cada escaneo, y negarselo no es prudencia, es hacerle competir contra su
//!    propia carga. Aqui se fija una **fraccion de la RAM del host, con suelo y
//!    con techo** (ver [`perfil`]).
//! 3. **Una promesa de un comentario.** Se median cuatro segundos al arrancar en
//!    CI y nada mas. Una fuga lenta hasta 2 GiB a las tres de la manana pasaba
//!    entera, y el watchdog —que vigilaba latido, no memoria— la daba por buena.
//!    Lo que lo cierra es [`unidad`]: `MemoryHigh` y `MemoryMax` de cgroup v2,
//!    impuestos por el kernel, que no depende de que el agente se porte bien.
//!
//! ## Donde queda frente al sector
//!
//! Con perfil de estacion en una maquina de 16 GiB salen ~82 MiB en reposo,
//! ~328 MiB en pico y ~492 MiB de techo duro. Para comparar con lo que de verdad
//! se despliega en flotas: `wdavdaemon` de Microsoft Defender for Endpoint ronda
//! los 300-600 MiB, el sensor de CrowdStrike Falcon 100-250 MiB, SentinelOne
//! 200-400 MiB y Elastic Defend alrededor de 500 MiB. El reposo de AegisCore
//! queda por debajo de todos ellos; el techo, en su mismo orden de magnitud, que
//! es donde tiene que estar un EDR que haga el trabajo completo.
//!
//! El patron de obligacion es el de osquery, que no se fia de su propio proceso:
//! su watchdog tiene `--watchdog_memory_limit` y **mata y reinicia** al obrero
//! que se pasa. Aqui lo hacen dos capas, el cgroup y [`regimen::Vigilante`].
//!
//! ## Las tres capas
//!
//! | Capa | Quien la aplica | Que hace |
//! |---|---|---|
//! | Reparto | El propio componente, via [`perfil::Presupuesto::cuota`] | Pide lo que le toca en vez de llevar una constante inventada |
//! | Contencion | El agente sobre si mismo, via [`regimen::Vigilante`] | Suelta lo elastico y rechaza trabajo pesado antes de llegar al techo |
//! | Obligacion | El kernel, via [`unidad::dropin`] | OOM dentro del cgroup y reinicio, sin tocar al host |
//!
//! La primera capa reparte, la segunda evita llegar al limite y la tercera
//! existe porque las dos primeras las ejecuta un proceso que puede estar
//! comprometido o sencillamente tener un bug.
//!
//! ## Ejemplo
//!
//! ```
//! use aegis_presupuesto::{Componente, Presupuesto, Regimen, Vigilante};
//!
//! // 16 GiB de host: perfil de estacion.
//! let presupuesto = Presupuesto::para(16 * 1024 * 1024 * 1024);
//! assert!(presupuesto.es_viable());
//!
//! let mut vigilante = Vigilante::nuevo(presupuesto);
//! vigilante.observar_bytes(presupuesto.reposo / 2);
//! assert_eq!(vigilante.regimen(), Regimen::Holgado);
//!
//! // El indice del corpus pregunta cuanto puede retener ahora mismo.
//! let residencia = vigilante.permitido(Componente::Corpus);
//! assert!(residencia > 0);
//!
//! // Bajo contencion sostenida lo elastico encoge; el nucleo no.
//! vigilante.observar_bytes(presupuesto.pico + 1);
//! assert_eq!(vigilante.regimen(), Regimen::Contencion);
//! assert!(vigilante.permitido(Componente::Corpus) < residencia);
//! assert!(vigilante.permitido(Componente::Nucleo) > 0);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod medida;
pub mod perfil;
pub mod regimen;
pub mod reparto;
pub mod unidad;

pub use medida::{memoria_total, uso_de, uso_propio, Origen, Uso};
pub use perfil::{Perfil, Presupuesto, MINIMO_VIABLE};
pub use regimen::{Regimen, Veredicto, Vigilante, MUESTRAS_PARA_REINICIO};
pub use reparto::{Componente, FIJO_MODELO, FIJO_NUCLEO, FIJO_TOTAL};
pub use unidad::{dropin, humano, resumen};

/// Variable de entorno que fuerza el perfil, por encima de la deteccion.
///
/// El administrador manda: hay hosts de 64 GiB donde el agente no debe crecer
/// porque la RAM ya esta vendida a una JVM, y hosts pequenos donde se quiere
/// maxima deteccion a sabiendas del coste.
pub const VAR_PERFIL: &str = "AEGIS_PERFIL";

/// Presupuesto efectivo de este host, respetando [`VAR_PERFIL`].
///
/// Un valor invalido en la variable **no** se ignora en silencio: se devuelve la
/// deteccion automatica, pero quien llama puede detectar la discrepancia
/// comparando con [`Presupuesto::del_host`] si necesita avisar.
#[must_use]
pub fn efectivo() -> Presupuesto {
    let automatico = Presupuesto::del_host();
    match std::env::var(VAR_PERFIL)
        .ok()
        .as_deref()
        .and_then(Perfil::desde_nombre)
    {
        Some(p) => Presupuesto::forzando(p, automatico.memoria_host),
        None => automatico,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_presupuesto_efectivo_es_coherente_en_este_host() {
        let p = efectivo();
        assert!(p.reposo <= p.pico);
        assert!(p.pico <= p.techo);
        assert!(p.memoria_host > 0);
    }

    #[test]
    fn el_perfil_del_host_de_ci_es_razonable() {
        // No se fija el perfil concreto (la CI puede correr en cualquier sitio),
        // pero si que el resultado tiene sentido: un host que ejecuta la suite
        // tiene RAM de sobra para que el agente sea viable.
        let p = Presupuesto::del_host();
        assert!(p.es_viable(), "host de CI no viable: {}", resumen(&p));
    }
}
