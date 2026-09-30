//! Histograma de latencias de tamaño fijo, para percentiles sin guardar muestras.
//!
//! # Por que no una media, ni una lista de muestras
//!
//! La media de la latencia esconde justo lo que importa: la cola. Y guardar las
//! muestras para ordenarlas crece con el trafico, que es lo que un agente con un
//! techo de memoria no se puede permitir. Esto es un histograma log-lineal: ocho
//! cubos por cada potencia de dos, asi que cualquier percentil sale con un error
//! relativo de como mucho un 12,5 % y el tamaño es fijo (312 contadores) haga el
//! trafico que haga.
//!
//! El percentil se da por el limite SUPERIOR de su cubo: publicar un p99
//! optimista es peor que publicarlo un poco pesimista.

/// Cubos por potencia de dos.
const SUB: u32 = 8;
/// Bits de los cubos exactos (valores `0..SUB`).
const BITS_SUB: u32 = 3;
/// Potencia de dos mas alta que se distingue (2^40 ns, unos 18 minutos).
const OCTAVA_MAX: u32 = 40;
/// Numero total de cubos.
const CUBOS: usize = (SUB + (OCTAVA_MAX - BITS_SUB + 1) * SUB) as usize;

/// Histograma de valores en nanosegundos.
#[derive(Clone)]
pub struct Histograma {
    cubos: [u64; CUBOS],
    cuenta: u64,
    suma: u128,
    maximo: u64,
}

impl std::fmt::Debug for Histograma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Histograma")
            .field("cuenta", &self.cuenta)
            .field("p50_ns", &self.percentil(50.0))
            .field("p99_ns", &self.percentil(99.0))
            .field("maximo_ns", &self.maximo)
            .finish()
    }
}

impl Default for Histograma {
    fn default() -> Self {
        Histograma {
            cubos: [0; CUBOS],
            cuenta: 0,
            suma: 0,
            maximo: 0,
        }
    }
}

fn indice(v: u64) -> usize {
    if v < u64::from(SUB) {
        return v as usize;
    }
    let octava = (63 - v.leading_zeros()).min(OCTAVA_MAX);
    let v = if octava == OCTAVA_MAX && v >> OCTAVA_MAX > 1 {
        (1u64 << (OCTAVA_MAX + 1)) - 1
    } else {
        v
    };
    let sub = (v >> (octava - BITS_SUB)) & u64::from(SUB - 1);
    (SUB + (octava - BITS_SUB) * SUB) as usize + sub as usize
}

fn limite_superior(i: usize) -> u64 {
    if i < SUB as usize {
        return i as u64;
    }
    let j = (i - SUB as usize) as u32;
    let octava = j / SUB + BITS_SUB;
    let sub = u64::from(j % SUB);
    let ancho = 1u64 << (octava - BITS_SUB);
    ((u64::from(SUB) + sub) << (octava - BITS_SUB)) + ancho - 1
}

impl Histograma {
    /// Anota un valor en nanosegundos.
    pub fn anotar(&mut self, ns: u64) {
        self.cubos[indice(ns)] += 1;
        self.cuenta += 1;
        self.suma += u128::from(ns);
        self.maximo = self.maximo.max(ns);
    }

    /// Cuantos valores lleva.
    #[must_use]
    pub fn cuenta(&self) -> u64 {
        self.cuenta
    }

    /// El mayor valor visto.
    #[must_use]
    pub fn maximo(&self) -> u64 {
        self.maximo
    }

    /// La media, en nanosegundos.
    #[must_use]
    pub fn media(&self) -> u64 {
        if self.cuenta == 0 {
            0
        } else {
            u64::try_from(self.suma / u128::from(self.cuenta)).unwrap_or(u64::MAX)
        }
    }

    /// El percentil `p` (0-100), por el limite superior de su cubo.
    #[must_use]
    pub fn percentil(&self, p: f64) -> u64 {
        if self.cuenta == 0 {
            return 0;
        }
        let p = p.clamp(0.0, 100.0);
        // Rango del valor buscado, contando desde 1: el p99 de 100 valores es el 99.
        let objetivo = ((p / 100.0) * self.cuenta as f64).ceil().max(1.0) as u64;
        let mut acumulado = 0u64;
        for (i, &c) in self.cubos.iter().enumerate() {
            acumulado += c;
            if acumulado >= objetivo {
                return limite_superior(i).min(self.maximo);
            }
        }
        self.maximo
    }

    /// Suma otro histograma a este.
    pub fn sumar(&mut self, otro: &Histograma) {
        for (a, b) in self.cubos.iter_mut().zip(otro.cubos.iter()) {
            *a += b;
        }
        self.cuenta += otro.cuenta;
        self.suma += otro.suma;
        self.maximo = self.maximo.max(otro.maximo);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn cada_valor_cae_en_un_cubo_cuyo_limite_lo_cubre() {
        let mut v = 0u64;
        while v < (1u64 << 41) {
            let i = indice(v);
            assert!(i < CUBOS, "{v} -> {i}");
            assert!(limite_superior(i) >= v.min((1u64 << 41) - 1), "{v}");
            v = v * 3 / 2 + 1;
        }
    }

    #[test]
    fn el_error_relativo_no_pasa_del_doce_y_medio_por_ciento() {
        for v in [9u64, 100, 1_000, 12_345, 1_000_000, 987_654_321] {
            let tope = limite_superior(indice(v));
            let error = (tope - v) as f64 / v as f64;
            assert!(error <= 0.125, "{v}: {tope} ({error})");
        }
    }

    #[test]
    fn el_percentil_ve_la_cola_que_la_media_esconde() {
        let mut h = Histograma::default();
        for _ in 0..990 {
            h.anotar(1_000);
        }
        for _ in 0..10 {
            h.anotar(5_000_000);
        }
        assert!(h.media() < 60_000);
        assert!(h.percentil(50.0) < 1_200);
        // El 99 % cae en los rapidos; el 99,9 % ya ve la cola.
        assert!(h.percentil(99.0) < 1_200);
        assert!(h.percentil(99.9) >= 5_000_000);
        assert_eq!(h.maximo(), 5_000_000);
    }

    #[test]
    fn vacio_da_cero_y_sumar_es_asociativo() {
        let h = Histograma::default();
        assert_eq!(h.percentil(99.0), 0);
        let mut a = Histograma::default();
        let mut b = Histograma::default();
        a.anotar(10);
        b.anotar(1_000_000);
        a.sumar(&b);
        assert_eq!(a.cuenta(), 2);
        assert_eq!(a.maximo(), 1_000_000);
    }
}
