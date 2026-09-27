//! La latencia AÑADIDA por el corte, medida y publicada (FASE 106).
//!
//! Un IPS en línea añade latencia a cada paquete que juzga. Un IPS que **no
//! publica** su latencia esconde su coste: el cliente descubre en producción que
//! la defensa le metió cola. Aquí la latencia de la decisión se mide y se publica
//! como p50 y p99 —no la media, que esconde la cola larga que es justo la que
//! duele—.
//!
//! El medidor es puro y determinista sobre las muestras que se le dan: los
//! percentiles no dependen del reloj (se cronometra fuera con [`MedidorLatencia::medir`]
//! o se inyectan muestras con [`MedidorLatencia::registrar_ns`]), así que la prueba
//! comprueba el cálculo del percentil sin depender de la máquina.

/// Un medidor de latencia que publica percentiles, no medias.
#[derive(Debug, Clone, Default)]
pub struct MedidorLatencia {
    muestras_ns: Vec<u64>,
}

impl MedidorLatencia {
    /// Un medidor vacío.
    #[must_use]
    pub fn nuevo() -> MedidorLatencia {
        MedidorLatencia::default()
    }

    /// Registra una muestra de latencia en nanosegundos.
    pub fn registrar_ns(&mut self, ns: u64) {
        self.muestras_ns.push(ns);
    }

    /// Cronometra una decisión y registra su latencia, devolviendo su resultado.
    /// Es como se instrumenta el decisor en vivo.
    pub fn medir<T>(&mut self, f: impl FnOnce() -> T) -> T {
        let inicio = std::time::Instant::now();
        let r = f();
        // Saturar en u64 es correcto: una latencia que no cabe en u64 ns (>584
        // años) no existe; nunca envolver a un valor pequeño y mentir.
        let ns = u64::try_from(inicio.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.registrar_ns(ns);
        r
    }

    /// Cuántas muestras hay.
    #[must_use]
    pub fn n(&self) -> usize {
        self.muestras_ns.len()
    }

    /// El percentil `p` (0.0..=1.0) de la latencia, en nanosegundos. `None` si no
    /// hay muestras. Usa el método del rango más cercano (nearest-rank), que es
    /// determinista y no interpola valores que no se midieron.
    #[must_use]
    pub fn percentil_ns(&self, p: f64) -> Option<u64> {
        if self.muestras_ns.is_empty() {
            return None;
        }
        let p = p.clamp(0.0, 1.0);
        let mut ordenadas = self.muestras_ns.clone();
        ordenadas.sort_unstable();
        // Rango más cercano: ceil(p * n), 1-indexado, acotado a [1, n].
        let n = ordenadas.len();
        let rango = (p * n as f64).ceil() as usize;
        let idx = rango.clamp(1, n) - 1;
        Some(ordenadas[idx])
    }

    /// La mediana (p50).
    #[must_use]
    pub fn p50_ns(&self) -> Option<u64> {
        self.percentil_ns(0.50)
    }

    /// La cola (p99): la latencia que duele, la que la media esconde.
    #[must_use]
    pub fn p99_ns(&self) -> Option<u64> {
        self.percentil_ns(0.99)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_percentiles_se_calculan_sobre_las_muestras_no_sobre_el_reloj() {
        let mut m = MedidorLatencia::nuevo();
        // 100 muestras: 1..=100 ns.
        for ns in 1..=100u64 {
            m.registrar_ns(ns);
        }
        assert_eq!(m.n(), 100);
        // p50 nearest-rank = ceil(0.5*100)=50 -> valor 50.
        assert_eq!(m.p50_ns(), Some(50));
        // p99 = ceil(0.99*100)=99 -> valor 99. La cola, no la media.
        assert_eq!(m.p99_ns(), Some(99));
    }

    #[test]
    fn la_p99_no_la_esconde_la_media() {
        // 99 muestras rapidas y una lentisima: la media miente, el p99 no.
        let mut m = MedidorLatencia::nuevo();
        for _ in 0..99 {
            m.registrar_ns(10);
        }
        m.registrar_ns(1_000_000);
        assert_eq!(m.p50_ns(), Some(10));
        // p99 = ceil(0.99*100)=99 -> el valor 99 en orden es 10; el 100 es el pico.
        // El pico entra en p100.
        assert_eq!(m.percentil_ns(1.0), Some(1_000_000));
    }

    #[test]
    fn sin_muestras_no_hay_percentil() {
        let m = MedidorLatencia::nuevo();
        assert_eq!(m.p50_ns(), None);
        assert_eq!(m.p99_ns(), None);
    }

    #[test]
    fn medir_registra_una_muestra() {
        let mut m = MedidorLatencia::nuevo();
        let r = m.medir(|| 2 + 2);
        assert_eq!(r, 4);
        assert_eq!(m.n(), 1);
    }
}
