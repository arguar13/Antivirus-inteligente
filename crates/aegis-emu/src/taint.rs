//! Seguimiento de contaminacion (taint) y deteccion de programacion orientada a
//! datos (DOP).
//!
//! # Que ataque se caza
//!
//! La **programacion orientada a datos** (Data-Oriented Programming) es la
//! evolucion del ROP para un mundo con CFI y W^X: en vez de desviar el flujo de
//! control —que las defensas modernas vigilan—, el exploit deja el flujo intacto
//! y **corrompe datos**. Reescribiendo estructuras del sistema (tablas de
//! paginas, descriptores, punteros en datos) con valores que controla, logra la
//! computacion que quiere sin ejecutar una sola instruccion "suya". No hay salto
//! ilegitimo que atrapar; lo que hay es un **rio de datos del atacante** que
//! termina escribiendo, en masa, sobre una estructura que ningun codigo legitimo
//! reescribe a mano.
//!
//! # Como se detecta: taint + escritura masiva a region protegida
//!
//! Se marca (taint) todo lo que entra por una fuente que el atacante controla
//! —la entrada de un `read`— y se propaga esa marca por el flujo de datos: si un
//! registro o una posicion de memoria se calcula a partir de algo contaminado,
//! queda contaminado. Cuando ese dato contaminado se escribe, **en volumen**,
//! sobre una **region protegida** (una estructura del sistema que el emulador
//! marca como intocable por escritura directa), se declara un intento de DOP. La
//! escritura legitima de esas estructuras pasa por una syscall (una API); la del
//! exploit va directa, byte a byte, y es justo lo que se ve.
//!
//! # Honestidad: es un taint LIGERO y conservador
//!
//! La propagacion es conservadora (cualquier fuente contaminada de una
//! instruccion contamina su destino): puede sobre-contaminar —por ejemplo, un
//! `xor eax,eax` deja `eax` a cero pero aqui hereda la marca—, nunca
//! sub-contaminar. Para un detector defensivo eso es lo seguro: no se pierde el
//! ataque; los falsos positivos los acota exigir volumen Y una region protegida.

use std::collections::HashSet;

/// Umbral por defecto de bytes contaminados escritos sobre una region protegida
/// para declarar un DOP. Una escritura puntual no basta; una masiva, si.
pub const UMBRAL_DOP_BYTES: u64 = 64;

/// El estado de contaminacion: que registros y que bytes de memoria estan
/// marcados como derivados de una fuente que controla el atacante.
#[derive(Debug, Clone, Default)]
pub struct EstadoTaint {
    /// Bit `i` a 1 => el registro `i` esta contaminado.
    registros: u16,
    /// Direcciones de byte contaminadas.
    memoria: HashSet<u64>,
}

impl EstadoTaint {
    /// Un estado limpio, sin nada contaminado.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// `true` si el registro `idx` (0..15) esta contaminado.
    #[must_use]
    pub fn reg_contaminado(&self, idx: usize) -> bool {
        (self.registros >> (idx & 0xF)) & 1 == 1
    }

    /// Marca o limpia la contaminacion del registro `idx`.
    pub fn marcar_reg(&mut self, idx: usize, contaminado: bool) {
        let bit = 1u16 << (idx & 0xF);
        if contaminado {
            self.registros |= bit;
        } else {
            self.registros &= !bit;
        }
    }

    /// `true` si ALGUN byte del rango `[dir, dir+tam)` esta contaminado (una
    /// lectura de ese operando arrastra la contaminacion).
    #[must_use]
    pub fn mem_contaminada(&self, dir: u64, tam: u8) -> bool {
        (0..u64::from(tam)).any(|k| self.memoria.contains(&dir.wrapping_add(k)))
    }

    /// Marca o limpia la contaminacion de los `tam` bytes desde `dir`.
    pub fn marcar_mem(&mut self, dir: u64, tam: u8, contaminado: bool) {
        for k in 0..u64::from(tam) {
            let a = dir.wrapping_add(k);
            if contaminado {
                self.memoria.insert(a);
            } else {
                self.memoria.remove(&a);
            }
        }
    }

    /// Marca `n` bytes desde `dir` como contaminados: la entrada de un `read` es
    /// la fuente que controla el atacante.
    pub fn contaminar_entrada(&mut self, dir: u64, n: u64) {
        for k in 0..n {
            self.memoria.insert(dir.wrapping_add(k));
        }
    }

    /// Cuantos bytes de memoria estan contaminados ahora mismo.
    #[must_use]
    pub fn bytes_contaminados(&self) -> usize {
        self.memoria.len()
    }
}

/// Una region que el emulador protege: una estructura del sistema que ningun
/// codigo legitimo reescribe con datos crudos del exterior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionProtegida {
    /// Inicio de la region.
    pub base: u64,
    /// Fin (exclusivo).
    pub fin: u64,
    /// Nombre legible (p. ej. "tabla de paginas").
    pub nombre: &'static str,
}

/// El resultado de la deteccion: sobre que estructura y cuantos bytes
/// contaminados se escribieron.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeteccionDop {
    /// La estructura protegida que se estaba corrompiendo.
    pub region: &'static str,
    /// Bytes contaminados escritos sobre ella cuando salto la deteccion.
    pub bytes: u64,
}

/// El detector de DOP: vigila las escrituras contaminadas sobre las regiones
/// protegidas y declara el ataque cuando el volumen supera el umbral.
#[derive(Debug, Clone)]
pub struct DetectorDop {
    regiones: Vec<RegionProtegida>,
    acumulado: Vec<u64>,
    umbral: u64,
    detectado: Option<DeteccionDop>,
}

impl DetectorDop {
    /// Un detector con el umbral de bytes dado.
    #[must_use]
    pub fn nuevo(umbral: u64) -> Self {
        Self {
            regiones: Vec::new(),
            acumulado: Vec::new(),
            umbral,
            detectado: None,
        }
    }

    /// Protege la region `[base, fin)`, con un nombre para el informe.
    pub fn proteger(&mut self, base: u64, fin: u64, nombre: &'static str) {
        self.regiones.push(RegionProtegida { base, fin, nombre });
        self.acumulado.push(0);
    }

    /// `true` si hay al menos una region protegida (si no, nada que detectar).
    #[must_use]
    pub fn hay_regiones(&self) -> bool {
        !self.regiones.is_empty()
    }

    /// Observa la escritura de `tam` bytes CONTAMINADOS en `dir`. Si cae en una
    /// region protegida, acumula; al superar el umbral, declara el DOP (una vez).
    pub fn observar_escritura_contaminada(&mut self, dir: u64, tam: u8) {
        let Some(idx) = self
            .regiones
            .iter()
            .position(|r| dir >= r.base && dir < r.fin)
        else {
            return;
        };
        self.acumulado[idx] += u64::from(tam);
        if self.detectado.is_none() && self.acumulado[idx] >= self.umbral {
            self.detectado = Some(DeteccionDop {
                region: self.regiones[idx].nombre,
                bytes: self.acumulado[idx],
            });
        }
    }

    /// La deteccion, si se disparo.
    #[must_use]
    pub fn detectado(&self) -> Option<DeteccionDop> {
        self.detectado
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_taint_de_registros_va_por_bit() {
        let mut t = EstadoTaint::nuevo();
        assert!(!t.reg_contaminado(6));
        t.marcar_reg(6, true);
        assert!(t.reg_contaminado(6));
        assert!(!t.reg_contaminado(7));
        t.marcar_reg(6, false);
        assert!(!t.reg_contaminado(6));
    }

    #[test]
    fn el_taint_de_memoria_es_por_byte_y_solapante() {
        let mut t = EstadoTaint::nuevo();
        t.contaminar_entrada(0x1000, 4);
        assert!(t.mem_contaminada(0x1000, 1));
        assert!(t.mem_contaminada(0x1003, 1));
        assert!(!t.mem_contaminada(0x1004, 1));
        // Una lectura de 8 bytes que ROZA la zona contaminada cuenta como
        // contaminada (conservador).
        assert!(t.mem_contaminada(0x0FFE, 8));
        t.marcar_mem(0x1000, 4, false);
        assert!(!t.mem_contaminada(0x1000, 4));
    }

    #[test]
    fn el_detector_dispara_al_superar_el_umbral() {
        let mut d = DetectorDop::nuevo(64);
        d.proteger(0x9000, 0x9100, "tabla de paginas");
        // Escrituras contaminadas de 8 en 8: a los 64 bytes salta.
        for i in 0..7 {
            d.observar_escritura_contaminada(0x9000 + i * 8, 8);
            assert!(d.detectado().is_none(), "aun por debajo del umbral");
        }
        d.observar_escritura_contaminada(0x9038, 8); // total 64
        let det = d.detectado().expect("al llegar a 64 bytes, DOP");
        assert_eq!(det.region, "tabla de paginas");
        assert!(det.bytes >= 64);
    }

    #[test]
    fn una_escritura_fuera_de_region_protegida_no_cuenta() {
        let mut d = DetectorDop::nuevo(8);
        d.proteger(0x9000, 0x9100, "idt");
        for _ in 0..100 {
            d.observar_escritura_contaminada(0x1000, 8); // lejos de la region
        }
        assert!(d.detectado().is_none());
    }
}
