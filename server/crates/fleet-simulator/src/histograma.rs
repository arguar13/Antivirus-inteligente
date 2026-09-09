//! Histograma de latencias con cubos logaritmicos.
//!
//! # Por que no se guardan las muestras
//!
//! Diez mil agentes latiendo durante un minuto generan cientos de miles de
//! muestras. Guardarlas todas para ordenarlas al final gastaria memoria del
//! propio generador de carga —memoria que compite con las conexiones que se
//! quieren medir— y falsearia el resultado: un medidor que altera lo que mide
//! no sirve.
//!
//! Los cubos logaritmicos dan percentiles con un error acotado y coste
//! constante: una suma atomica por muestra, sin reservar nada.
//!
//! # Por que hay sub-cubos
//!
//! Con cubos de potencia de dos a secas, el error relativo llega al 100 %: un
//! cubo que va de 32 a 65 ms no permite afirmar si se cumple un objetivo de 50.
//! Eso paso de verdad al medir este sistema, y el problema estaba en el
//! instrumento, no en lo medido. Dividiendo cada potencia en 32 tramos lineales
//! el error baja a ~3 %, suficiente para juzgar un umbral sin guardar muestras.

use std::sync::atomic::{AtomicU64, Ordering};

/// Sub-cubos lineales dentro de cada potencia de dos: acotan el error a ~3 %.
const SUB: usize = 32;
/// Bits del indice de sub-cubo.
const BITS_SUB: u32 = 5; // 2^5 = 32
/// Potencias de dos cubiertas: de 1 microsegundo a mas de un minuto.
const POTENCIAS: usize = 40;
/// Numero total de cubos.
const CUBOS: usize = POTENCIAS * SUB;

/// Histograma de latencias en microsegundos.
pub struct Histograma {
    /// Cubo `i` cuenta las latencias en [2^i, 2^(i+1)) microsegundos.
    cubos: [AtomicU64; CUBOS],
    total: AtomicU64,
    suma_us: AtomicU64,
    maximo_us: AtomicU64,
}

impl Default for Histograma {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl Histograma {
    /// Crea un histograma vacio.
    pub fn nuevo() -> Histograma {
        Histograma {
            cubos: std::array::from_fn(|_| AtomicU64::new(0)),
            total: AtomicU64::new(0),
            suma_us: AtomicU64::new(0),
            maximo_us: AtomicU64::new(0),
        }
    }

    /// Indice del cubo de una latencia, y el limite superior de ese cubo.
    fn indice(us: u64) -> (usize, u64) {
        let v = us.max(1);
        let exponente = 63 - v.leading_zeros() as usize;
        if exponente < BITS_SUB as usize {
            // Valores pequenos: cada microsegundo es su propio cubo.
            return ((v as usize).min(CUBOS - 1), v + 1);
        }
        let desplazamiento = exponente as u32 - BITS_SUB;
        let sub = ((v >> desplazamiento) & (SUB as u64 - 1)) as usize;
        let indice = (exponente * SUB + sub).min(CUBOS - 1);
        // Limite superior del tramo: el siguiente sub-cubo.
        let superior = (((v >> desplazamiento) + 1) << desplazamiento).max(v + 1);
        (indice, superior)
    }

    /// Registra una latencia.
    pub fn registrar(&self, us: u64) {
        let (cubo, _) = Self::indice(us);
        self.cubos[cubo].fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
        self.suma_us.fetch_add(us, Ordering::Relaxed);
        self.maximo_us.fetch_max(us, Ordering::Relaxed);
    }

    /// Numero de muestras.
    pub fn muestras(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Latencia media en milisegundos.
    pub fn media_ms(&self) -> f64 {
        let n = self.muestras();
        if n == 0 {
            return 0.0;
        }
        self.suma_us.load(Ordering::Relaxed) as f64 / n as f64 / 1000.0
    }

    /// Latencia maxima observada en milisegundos.
    pub fn maximo_ms(&self) -> f64 {
        self.maximo_us.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Percentil en milisegundos.
    ///
    /// Devuelve el limite SUPERIOR del cubo donde cae el percentil: es una cota
    /// pesimista, que es la que interesa cuando se comprueba un objetivo de
    /// latencia. Decir "el p99 esta por debajo de X" con una cota optimista
    /// seria enganarse.
    pub fn percentil_ms(&self, p: f64) -> f64 {
        let n = self.muestras();
        if n == 0 {
            return 0.0;
        }
        let objetivo = (n as f64 * p / 100.0).ceil() as u64;
        let mut acumulado = 0u64;
        for (i, c) in self.cubos.iter().enumerate() {
            acumulado += c.load(Ordering::Relaxed);
            if acumulado >= objetivo {
                return Self::limite_superior(i) as f64 / 1000.0;
            }
        }
        self.maximo_ms()
    }

    /// Limite superior en microsegundos del cubo dado.
    fn limite_superior(indice: usize) -> u64 {
        if indice < SUB {
            return indice as u64 + 1;
        }
        let exponente = indice / SUB;
        let sub = indice % SUB;
        let desplazamiento = exponente as u32 - BITS_SUB;
        // El cubo cubre [(SUB+sub) << d, (SUB+sub+1) << d): su limite superior
        // es el principio del siguiente.
        ((SUB + sub) as u64 + 1) << desplazamiento
    }

    /// Resumen en una linea.
    pub fn resumen(&self) -> String {
        format!(
            "n={} media={:.2}ms p50<{:.2}ms p95<{:.2}ms p99<{:.2}ms max={:.2}ms",
            self.muestras(),
            self.media_ms(),
            self.percentil_ms(50.0),
            self.percentil_ms(95.0),
            self.percentil_ms(99.0),
            self.maximo_ms()
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_histograma_acota_los_percentiles_por_arriba() {
        let h = Histograma::nuevo();
        // Cien muestras de 1 ms y una de 100 ms.
        for _ in 0..100 {
            h.registrar(1_000);
        }
        h.registrar(100_000);

        assert_eq!(h.muestras(), 101);
        // El p50 debe quedar en el entorno del milisegundo.
        assert!(
            h.percentil_ms(50.0) <= 2.0,
            "p50 = {}",
            h.percentil_ms(50.0)
        );
        // El maximo es exacto, no aproximado.
        assert!((h.maximo_ms() - 100.0).abs() < 0.001);
    }

    #[test]
    fn un_histograma_vacio_no_divide_entre_cero() {
        let h = Histograma::nuevo();
        assert_eq!(h.muestras(), 0);
        assert_eq!(h.media_ms(), 0.0);
        assert_eq!(h.percentil_ms(99.0), 0.0);
    }

    #[test]
    fn el_percentil_es_una_cota_superior_nunca_optimista() {
        let h = Histograma::nuevo();
        // Todas las muestras en 3 ms exactos.
        for _ in 0..1000 {
            h.registrar(3_000);
        }
        // La cota debe estar por encima del valor real, jamas por debajo:
        // afirmar que se cumple un objetivo con una cota optimista seria
        // enganarse a uno mismo.
        assert!(h.percentil_ms(99.0) >= 3.0);
    }
}

#[cfg(test)]
mod precision {
    use super::*;

    #[test]
    fn el_error_del_percentil_se_mantiene_bajo() {
        // El instrumento tiene que ser lo bastante fino para juzgar un objetivo
        // de 50 ms. Con cubos de potencia de dos a secas el error llegaba al
        // 100 % y el veredicto dependia de en que lado del cubo cayera.
        for real_us in [1_000u64, 4_000, 10_000, 42_000, 49_000, 51_000, 120_000] {
            let h = Histograma::nuevo();
            for _ in 0..1000 {
                h.registrar(real_us);
            }
            let medido = h.percentil_ms(99.0) * 1000.0;
            let error = (medido - real_us as f64) / real_us as f64;
            assert!(
                (0.0..=0.05).contains(&error),
                "para {real_us} us el instrumento dijo {medido} us (error {:.1} %)",
                error * 100.0
            );
        }
    }

    #[test]
    fn distingue_por_encima_y_por_debajo_del_objetivo() {
        // La prueba que de verdad importa: que el instrumento no confunda
        // 42 ms (cumple) con 51 ms (no cumple).
        let bajo = Histograma::nuevo();
        for _ in 0..1000 {
            bajo.registrar(42_000);
        }
        assert!(
            bajo.percentil_ms(99.0) <= 50.0,
            "42 ms debe leerse como cumplido"
        );

        let alto = Histograma::nuevo();
        for _ in 0..1000 {
            alto.registrar(51_000);
        }
        assert!(
            alto.percentil_ms(99.0) > 50.0,
            "51 ms debe leerse como incumplido"
        );
    }
}
