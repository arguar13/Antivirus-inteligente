//! La decision: de una serie de muestras de la PMU a un evento de anomalia.
//!
//! Es la parte que puede estar MAL de forma peligrosa —de menos, un ataque de
//! canal lateral pasa desapercibido; de mas, un proceso legitimo se marca como
//! atacante—, asi que es Rust puro y se prueba entera con series de datos reales,
//! cero mocks. Leer los contadores del hardware ([`crate::contadores`]) es la
//! parte con muro (necesita PMU); ESTO no lo necesita: opera sobre numeros.
//!
//! # Que se detecta, y por que en estos contadores
//!
//! - **Canal lateral por cache** (Flush+Reload, Prime+Probe, Spectre): el
//!   atacante desaloja y recarga lineas de cache miles de veces para medir
//!   tiempos, lo que dispara los **fallos de la ultima cache (LLC)** muy por
//!   encima de lo que hace el codigo normal. Un pico sostenido de fallos de cache
//!   por instruccion es su firma.
//! - **ROP/JOP**: una cadena de gadgets salta a direcciones que el predictor de
//!   saltos no aprendio, asi que la **tasa de fallos de prediccion de saltos** se
//!   dispara. El codigo compilado normal predice bien; una cadena de retornos, no.
//!
//! # Como se decide sin falsos positivos a la primera de cambio
//!
//! No hay un umbral fijo y magico: cada proceso tiene su propia linea base. El
//! analizador aprende, por media movil exponencial (EWMA), la media y la varianza
//! de cada tasa, y solo marca una muestra que se dispara **muchas sigmas** por
//! encima de SU propia base Y ademas supera un piso absoluto (para no marcar el
//! ruido de una base minuscula). Una muestra ya marcada como anomala NO entrena
//! la base: un ataque no puede, poco a poco, ensenarle al detector a ignorarlo.

/// Peso de la media movil exponencial: cuanto pesa la muestra nueva frente a la
/// historia. 0.1 => memoria efectiva de ~10 muestras.
const ALPHA: f64 = 0.1;
/// Muestras de calentamiento antes de juzgar: primero se aprende la base.
const MIN_MUESTRAS: u64 = 8;
/// Cuantas sigmas por encima de la base cuenta como pico.
const K_SIGMA: f64 = 5.0;
/// Piso absoluto de fallos de cache por kilo-instruccion. El codigo normal ronda
/// 1-2; un ataque de cache lo lleva a decenas o cientos.
const PISO_MPKI: f64 = 5.0;
/// Piso absoluto de tasa de fallos de prediccion de saltos. Lo normal es < 2%;
/// una cadena ROP la dispara muy por encima.
const PISO_ERROR_RAMAS: f64 = 0.05;
/// Suelo de sigma para que la puntuacion z sea finita cuando la base es plana.
const EPS: f64 = 1e-9;

/// Una muestra de la PMU: los contadores acumulados durante una ventana de
/// observacion (diferencias respecto a la lectura anterior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuestraPmu {
    /// Ciclos de reloj del nucleo.
    pub ciclos: u64,
    /// Instrucciones retiradas.
    pub instrucciones: u64,
    /// Fallos de la ultima cache (LLC).
    pub fallos_cache: u64,
    /// Saltos ejecutados.
    pub ramas: u64,
    /// Saltos mal predichos.
    pub fallos_rama: u64,
}

impl MuestraPmu {
    /// Instrucciones por ciclo (IPC). Una cadena ROP suele hundir el IPC.
    #[must_use]
    pub fn ipc(&self) -> f64 {
        if self.ciclos == 0 {
            0.0
        } else {
            self.instrucciones as f64 / self.ciclos as f64
        }
    }

    /// Fallos de cache por cada 1000 instrucciones (MPKI): la tasa normalizada
    /// que no depende de cuanto tiempo duro la ventana.
    #[must_use]
    pub fn fallos_cache_por_kinstr(&self) -> f64 {
        if self.instrucciones == 0 {
            0.0
        } else {
            self.fallos_cache as f64 * 1000.0 / self.instrucciones as f64
        }
    }

    /// Fraccion de saltos mal predichos (0.0 a 1.0).
    #[must_use]
    pub fn tasa_error_ramas(&self) -> f64 {
        if self.ramas == 0 {
            0.0
        } else {
            self.fallos_rama as f64 / self.ramas as f64
        }
    }
}

/// La clase de anomalia que delata la telemetria de hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseAnomalia {
    /// Pico de fallos de cache: ataque de canal lateral (Flush+Reload,
    /// Prime+Probe, Spectre).
    CanalLateral,
    /// Pico de fallos de prediccion de saltos: cadena ROP/JOP.
    RopJop,
}

/// La severidad del evento, por cuan lejos de la base esta el pico.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severidad {
    /// Anomalia moderada: vigilar.
    Media,
    /// Anomalia clara: alta.
    Alta,
    /// Anomalia extrema.
    Critica,
}

impl Severidad {
    /// Traduce la puntuacion z (sigmas por encima de la base) a severidad.
    #[must_use]
    fn desde_z(z: f64) -> Self {
        if z >= 20.0 {
            Severidad::Critica
        } else if z >= 10.0 {
            Severidad::Alta
        } else {
            Severidad::Media
        }
    }
}

/// El evento que emite el analizador cuando una muestra es anomala.
#[derive(Debug, Clone, Copy)]
pub struct EventoHpc {
    /// Que clase de ataque delata.
    pub clase: ClaseAnomalia,
    /// Cuan grave, por la magnitud del pico.
    pub severidad: Severidad,
    /// Sigmas por encima de la linea base del propio proceso.
    pub z: f64,
    /// El valor de la tasa que se disparo (MPKI o tasa de error de saltos).
    pub valor: f64,
}

/// Linea base por EWMA de una tasa: su media y su varianza, que se aprenden solas.
#[derive(Debug, Clone, Copy)]
struct LineaBase {
    media: f64,
    var: f64,
    inicial: bool,
}

impl LineaBase {
    fn nueva() -> Self {
        Self {
            media: 0.0,
            var: 0.0,
            inicial: true,
        }
    }

    fn sigma(&self) -> f64 {
        self.var.max(0.0).sqrt().max(EPS)
    }

    /// Sigmas de `x` por encima de la media. 0 mientras no haya base.
    fn z(&self, x: f64) -> f64 {
        if self.inicial {
            0.0
        } else {
            (x - self.media) / self.sigma()
        }
    }

    /// Integra `x` en la base (EWMA de la media y de la varianza).
    fn actualizar(&mut self, x: f64) {
        if self.inicial {
            self.media = x;
            self.var = 0.0;
            self.inicial = false;
            return;
        }
        let d = x - self.media;
        self.media += ALPHA * d;
        // EWMA incremental de la varianza (forma de West).
        self.var = (1.0 - ALPHA) * (self.var + ALPHA * d * d);
    }
}

/// El analizador de telemetria de hardware: mantiene la linea base de cada tasa
/// y decide, muestra a muestra, si hay una anomalia de canal lateral o de ROP/JOP.
#[derive(Debug, Clone)]
pub struct AnalizadorHpc {
    cache: LineaBase,
    ramas: LineaBase,
    vistas: u64,
}

impl Default for AnalizadorHpc {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl AnalizadorHpc {
    /// Un analizador nuevo, sin linea base aun (empieza por el calentamiento).
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            cache: LineaBase::nueva(),
            ramas: LineaBase::nueva(),
            vistas: 0,
        }
    }

    /// `true` mientras el analizador aun esta aprendiendo la base y no juzga.
    #[must_use]
    pub fn en_calentamiento(&self) -> bool {
        self.vistas < MIN_MUESTRAS
    }

    /// Observa una muestra de la PMU y decide si es anomala.
    ///
    /// Durante el calentamiento solo aprende. Despues, marca un pico de fallos de
    /// cache (canal lateral) o de fallos de prediccion de saltos (ROP/JOP) que se
    /// dispare muchas sigmas sobre la base del proceso y supere el piso absoluto.
    /// Una muestra anomala no entrena la base.
    pub fn observar(&mut self, m: &MuestraPmu) -> Option<EventoHpc> {
        let mpki = m.fallos_cache_por_kinstr();
        let err_ramas = m.tasa_error_ramas();
        self.vistas += 1;

        // Calentamiento: aprende, no juzga.
        if self.vistas <= MIN_MUESTRAS {
            self.cache.actualizar(mpki);
            self.ramas.actualizar(err_ramas);
            return None;
        }

        // Canal lateral: pico de fallos de cache sobre la base Y sobre el piso.
        let z_cache = self.cache.z(mpki);
        if mpki > PISO_MPKI && z_cache > K_SIGMA {
            // No se entrena la base con una muestra anomala: un ataque no puede
            // ensenarle al detector a aceptarlo poco a poco.
            return Some(EventoHpc {
                clase: ClaseAnomalia::CanalLateral,
                severidad: Severidad::desde_z(z_cache),
                z: z_cache,
                valor: mpki,
            });
        }

        // ROP/JOP: pico de fallos de prediccion de saltos.
        let z_ramas = self.ramas.z(err_ramas);
        if err_ramas > PISO_ERROR_RAMAS && z_ramas > K_SIGMA {
            return Some(EventoHpc {
                clase: ClaseAnomalia::RopJop,
                severidad: Severidad::desde_z(z_ramas),
                z: z_ramas,
                valor: err_ramas,
            });
        }

        // Muestra normal: refuerza la base.
        self.cache.actualizar(mpki);
        self.ramas.actualizar(err_ramas);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una muestra "normal": mucho computo, poquisimos fallos de cache y de
    /// prediccion. `jitter` mueve un poco los fallos de cache para dar varianza.
    fn muestra_normal(jitter: u64) -> MuestraPmu {
        MuestraPmu {
            ciclos: 1_000_000,
            instrucciones: 2_000_000,     // IPC 2.0, sano
            fallos_cache: 2_000 + jitter, // ~1 MPKI
            ramas: 400_000,
            fallos_rama: 4_000, // 1% de error, sano
        }
    }

    fn analizador_calentado() -> AnalizadorHpc {
        let mut a = AnalizadorHpc::nuevo();
        // Suficientes muestras normales (con jitter) para fijar la base y su
        // varianza.
        for i in 0..30 {
            let ev = a.observar(&muestra_normal(i % 5 * 100));
            assert!(ev.is_none(), "una muestra normal no debe marcar nada");
        }
        assert!(!a.en_calentamiento());
        a
    }

    #[test]
    fn el_trafico_normal_no_dispara_nada() {
        let mut a = analizador_calentado();
        for i in 0..50 {
            assert!(a.observar(&muestra_normal(i % 7 * 120)).is_none());
        }
    }

    #[test]
    fn un_pico_de_fallos_de_cache_es_canal_lateral_de_alta_severidad() {
        let mut a = analizador_calentado();
        // Ataque de canal lateral: los fallos de cache se disparan (~40 MPKI:
        // 80.000 fallos sobre 2M instrucciones), muy por encima de ~1 MPKI.
        let ataque = MuestraPmu {
            ciclos: 1_000_000,
            instrucciones: 2_000_000,
            fallos_cache: 80_000,
            ramas: 400_000,
            fallos_rama: 4_000,
        };
        let ev = a
            .observar(&ataque)
            .expect("un pico de cache tiene que marcarse");
        assert_eq!(ev.clase, ClaseAnomalia::CanalLateral);
        assert!(
            matches!(ev.severidad, Severidad::Alta | Severidad::Critica),
            "un pico de canal lateral es de severidad alta (era {:?})",
            ev.severidad
        );
        assert!(ev.valor > PISO_MPKI);
    }

    #[test]
    fn un_pico_de_fallos_de_prediccion_es_ropjop() {
        let mut a = analizador_calentado();
        // ROP: la tasa de fallos de prediccion se dispara al 35% (140k sobre
        // 400k saltos), con el IPC hundido.
        let ataque = MuestraPmu {
            ciclos: 2_000_000,
            instrucciones: 800_000, // IPC 0.4, deprimido
            fallos_cache: 2_500,
            ramas: 400_000,
            fallos_rama: 140_000,
        };
        let ev = a
            .observar(&ataque)
            .expect("un pico de saltos tiene que marcarse");
        assert_eq!(ev.clase, ClaseAnomalia::RopJop);
        assert!(ev.valor > PISO_ERROR_RAMAS);
    }

    #[test]
    fn durante_el_calentamiento_no_se_juzga() {
        let mut a = AnalizadorHpc::nuevo();
        // Incluso un pico enorme durante el calentamiento solo entrena la base.
        let pico = MuestraPmu {
            ciclos: 1_000_000,
            instrucciones: 2_000_000,
            fallos_cache: 200_000,
            ramas: 400_000,
            fallos_rama: 4_000,
        };
        assert!(a.observar(&pico).is_none());
        assert!(a.en_calentamiento());
    }

    #[test]
    fn un_ataque_no_puede_envenenar_la_base_poco_a_poco() {
        // Tras un pico marcado, la base sigue como estaba: el siguiente pico
        // igual se vuelve a marcar (no se "acostumbro").
        let mut a = analizador_calentado();
        let ataque = MuestraPmu {
            ciclos: 1_000_000,
            instrucciones: 2_000_000,
            fallos_cache: 80_000,
            ramas: 400_000,
            fallos_rama: 4_000,
        };
        for _ in 0..10 {
            let ev = a.observar(&ataque).expect("cada pico se marca");
            assert_eq!(ev.clase, ClaseAnomalia::CanalLateral);
        }
    }

    #[test]
    fn las_tasas_derivadas_no_dividen_por_cero() {
        let vacia = MuestraPmu {
            ciclos: 0,
            instrucciones: 0,
            fallos_cache: 0,
            ramas: 0,
            fallos_rama: 0,
        };
        assert_eq!(vacia.ipc(), 0.0);
        assert_eq!(vacia.fallos_cache_por_kinstr(), 0.0);
        assert_eq!(vacia.tasa_error_ramas(), 0.0);
    }
}
