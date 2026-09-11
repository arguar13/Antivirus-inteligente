//! `AegisMemScanner` — escaneo YARA de memoria cruda, particionado y estrangulado
//! (FASE 57).
//!
//! # El problema
//!
//! Llevar el threat hunting a la RAM significa correr reglas YARA sobre gigabytes
//! de memoria, y hacerlo en TODA la flota. Dos peligros:
//!
//! 1. **Congelar el endpoint.** Escanear un volcado de varios GB de una vez se
//!    come la CPU y la E/S de la maquina de un cliente. Por eso el escaner es
//!    **particionado**: lee la memoria en trozos (`chunks`) y avisa a un
//!    **estrangulador** tras cada uno, para que el ritmo lo module un límite de
//!    E/S/CPU (en producción, cgroups en Linux o Job Objects en Windows).
//! 2. **Perder una firma partida.** El peligro sutil de todo escáner por trozos:
//!    una firma que cae **a caballo entre dos chunks** no aparece entera en
//!    ninguno de los dos, y un escáner ingenuo la pierde. `AegisMemScanner`
//!    arrastra un **solapamiento** de bytes entre chunks, de tamaño mayor o igual
//!    que la firma más larga, de modo que toda coincidencia queda entera dentro
//!    de alguna ventana. Es el caso decisivo que separa este escáner de uno roto.
//!
//! # Honestidad de validación
//!
//! El núcleo —partir, solapar, escanear, deduplicar y contabilizar para el
//! estrangulador— se prueba de verdad con reglas YARA reales sobre buffers
//! reales, cero mocks. El **muro** es leer la memoria FÍSICA cruda (necesita el
//! driver/privilegios de las FASES de kernel) y la aplicación real de los límites
//! por cgroups/Job Objects (necesita el SO): eso se aísla tras la abstracción
//! [`FuenteMemoria`] y el [`Estrangulador`], y se declara en el CI.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::yara::{YaraEngine, YaraError};

/// Una región de memoria a escanear: dónde empieza, cuánto mide y una etiqueta
/// legible (p. ej. `pid 1234 [heap]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionMem {
    /// Dirección base.
    pub base: u64,
    /// Longitud en bytes.
    pub len: u64,
    /// Etiqueta para la traza y el informe.
    pub etiqueta: String,
}

/// De dónde sale la memoria a escanear. Abstrae la procedencia —un proceso vivo,
/// un volcado físico crudo leído por el driver, un fichero de volcado— para que
/// el escáner sea el mismo en todos los casos. La implementación de producción
/// que lee memoria FÍSICA es el muro que se declara gated; el escáner que la
/// recorre, no.
pub trait FuenteMemoria {
    /// Las regiones a escanear.
    fn regiones(&self) -> Vec<RegionMem>;

    /// Lee `len` bytes desde `base`.
    ///
    /// # Errores
    /// [`MemScanError::Lectura`] si la memoria no se puede leer (región liberada,
    /// sin privilegios, página no residente).
    fn leer(&self, base: u64, len: usize) -> Result<Vec<u8>, MemScanError>;
}

/// Modula el ritmo del escaneo para no ahogar al endpoint. Se le avisa tras cada
/// chunk con los bytes que se acaban de leer. En producción, aplica un límite de
/// E/S/CPU (cgroups/Job Objects o una pausa); en las pruebas, se registra.
pub trait Estrangulador {
    /// Aviso de que se han leído `bytes` de un chunk.
    fn tras_chunk(&mut self, bytes: u64);
}

/// No estrangula: para el núcleo del escaneo sin ritmo (pruebas, o cuando el
/// límite lo pone el SO por fuera vía cgroups).
#[derive(Debug, Default)]
pub struct SinEstrangular;

impl Estrangulador for SinEstrangular {
    fn tras_chunk(&mut self, _bytes: u64) {}
}

/// Estrangulador por ritmo máximo: pausa lo justo para no superar
/// `limite_bytes_seg`. La pausa se calcula con [`pausa_para_ritmo`] (pura y
/// probada); el `sleep` real es lo único no ejercido en las pruebas.
#[derive(Debug, Clone, Copy)]
pub struct RitmoMaximo {
    /// Límite de bytes por segundo (0 = sin límite).
    pub limite_bytes_seg: u64,
}

impl Estrangulador for RitmoMaximo {
    fn tras_chunk(&mut self, bytes: u64) {
        let pausa = pausa_para_ritmo(bytes, self.limite_bytes_seg);
        if !pausa.is_zero() {
            std::thread::sleep(pausa);
        }
    }
}

/// Cuánto hay que pausar tras leer `bytes` para no superar `limite_bytes_seg`.
/// Con límite 0 no hay pausa.
#[must_use]
pub fn pausa_para_ritmo(bytes: u64, limite_bytes_seg: u64) -> Duration {
    if limite_bytes_seg == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(bytes as f64 / limite_bytes_seg as f64)
}

/// Configuración del escáner particionado.
#[derive(Debug, Clone, Copy)]
pub struct ConfigEscaner {
    /// Tamaño de cada chunk leído y escaneado, en bytes.
    pub tam_chunk: usize,
    /// Solapamiento arrastrado entre chunks. DEBE ser mayor o igual que la firma
    /// más larga del conjunto YARA, o una firma partida en la frontera se
    /// perdería.
    pub solapamiento: usize,
}

impl Default for ConfigEscaner {
    fn default() -> Self {
        // 1 MiB por chunk, 64 KiB de solapamiento: mayor que cualquier firma YARA
        // razonable, y una fracción pequeña del chunk (coste despreciable).
        Self {
            tam_chunk: 1024 * 1024,
            solapamiento: 64 * 1024,
        }
    }
}

/// Una coincidencia YARA en memoria: qué regla, en qué región. La granularidad es
/// regla+región (existencial: "la regla X coincide en esta región"), que es lo
/// que necesita `SELECT pid FROM memory WHERE yara_match = 'X'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoincidenciaMem {
    /// Nombre de la regla que coincidió.
    pub regla: String,
    /// Etiqueta de la región donde coincidió.
    pub etiqueta: String,
    /// Base de la región.
    pub base_region: u64,
}

/// Error del escáner de memoria.
#[derive(Debug, thiserror::Error)]
pub enum MemScanError {
    /// Falló el motor YARA al escanear un chunk.
    #[error("error de YARA al escanear memoria: {0}")]
    Yara(#[from] YaraError),

    /// No se pudo leer un rango de memoria de la fuente.
    #[error("no se pudo leer la memoria en {0:#x}: {1}")]
    Lectura(u64, String),
}

/// El escáner de memoria particionado y estrangulado.
pub struct AegisMemScanner<'a> {
    motor: &'a YaraEngine,
    config: ConfigEscaner,
}

impl<'a> AegisMemScanner<'a> {
    /// Crea un escáner con un motor YARA compilado y una configuración.
    #[must_use]
    pub fn nuevo(motor: &'a YaraEngine, config: ConfigEscaner) -> Self {
        Self { motor, config }
    }

    /// Escanea toda la memoria de `fuente`, chunk a chunk, arrastrando el
    /// solapamiento y avisando a `estr` tras cada lectura. Devuelve una
    /// coincidencia por cada (regla, región), deduplicada.
    ///
    /// # Errores
    /// [`MemScanError`] si falla una lectura o el motor YARA.
    pub fn escanear(
        &self,
        fuente: &impl FuenteMemoria,
        estr: &mut impl Estrangulador,
    ) -> Result<Vec<CoincidenciaMem>, MemScanError> {
        let mut salida = Vec::new();
        let mut vistos: BTreeSet<(String, u64)> = BTreeSet::new();

        for region in fuente.regiones() {
            let mut off = 0u64;
            // Cola arrastrada del chunk anterior (el solapamiento).
            let mut cola: Vec<u8> = Vec::new();

            while off < region.len {
                let pedir = usize::try_from(region.len - off)
                    .unwrap_or(self.config.tam_chunk)
                    .min(self.config.tam_chunk);
                let base = region.base + off;
                let chunk = fuente.leer(base, pedir).map_err(|e| match e {
                    MemScanError::Lectura(_, m) => MemScanError::Lectura(base, m),
                    otro => otro,
                })?;
                // El estrangulador contabiliza los bytes REALES leídos (sin contar
                // el solapamiento, que no se relee de la fuente).
                estr.tras_chunk(chunk.len() as u64);

                // La ventana a escanear es la cola del chunk anterior más este
                // chunk: así una firma partida en la frontera cae entera aquí.
                let mut ventana = Vec::with_capacity(cola.len() + chunk.len());
                ventana.extend_from_slice(&cola);
                ventana.extend_from_slice(&chunk);

                for d in self.motor.scan_bytes(&ventana)? {
                    if vistos.insert((d.rule.clone(), region.base)) {
                        salida.push(CoincidenciaMem {
                            regla: d.rule,
                            etiqueta: region.etiqueta.clone(),
                            base_region: region.base,
                        });
                    }
                }

                // Preparar el solapamiento para el próximo chunk: los últimos
                // `solapamiento` bytes de ESTE chunk.
                let corte = chunk.len().saturating_sub(self.config.solapamiento);
                cola = chunk[corte..].to_vec();
                off += chunk.len() as u64;

                // Guardia contra una fuente que devuelva 0 bytes: evita un bucle
                // infinito (fallo de raíz, no un parche con `sleep`).
                if chunk.is_empty() {
                    break;
                }
            }
        }
        Ok(salida)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una fuente de memoria plana: una sola región de bytes en RAM del test.
    struct MemoriaPlana {
        base: u64,
        datos: Vec<u8>,
        etiqueta: String,
    }

    impl FuenteMemoria for MemoriaPlana {
        fn regiones(&self) -> Vec<RegionMem> {
            vec![RegionMem {
                base: self.base,
                len: self.datos.len() as u64,
                etiqueta: self.etiqueta.clone(),
            }]
        }

        fn leer(&self, base: u64, len: usize) -> Result<Vec<u8>, MemScanError> {
            let off = (base - self.base) as usize;
            let fin = (off + len).min(self.datos.len());
            Ok(self.datos[off..fin].to_vec())
        }
    }

    /// Estrangulador de prueba: registra cuántos bytes y cuántos chunks.
    #[derive(Default)]
    struct Registro {
        bytes: u64,
        chunks: usize,
    }
    impl Estrangulador for Registro {
        fn tras_chunk(&mut self, bytes: u64) {
            self.bytes += bytes;
            self.chunks += 1;
        }
    }

    const MARCADOR: &[u8] = b"MARCADORAPT29XYZ"; // 16 bytes
    const REGLA: &str = "rule APT29_Core { strings: $a = \"MARCADORAPT29XYZ\" condition: $a }";

    fn motor() -> YaraEngine {
        YaraEngine::from_sources(&[REGLA]).expect("la regla compila")
    }

    #[test]
    fn la_pausa_de_ritmo_es_proporcional() {
        assert_eq!(pausa_para_ritmo(1000, 0), Duration::ZERO);
        // 1 MiB a 1 MiB/s = 1 segundo.
        assert_eq!(
            pausa_para_ritmo(1024 * 1024, 1024 * 1024),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn encuentra_una_firma_a_caballo_entre_dos_chunks() {
        // EL CASO DECISIVO. Región de 40 bytes; el marcador de 16 bytes se coloca
        // en 12..28, que cruza la frontera del chunk de 20 bytes.
        let mut datos = vec![0u8; 40];
        datos[12..28].copy_from_slice(MARCADOR);
        let fuente = MemoriaPlana {
            base: 0x1000,
            datos,
            etiqueta: "pid 42 [heap]".into(),
        };
        let m = motor();

        // Con solapamiento suficiente (>= 16): SÍ se encuentra.
        let esc = AegisMemScanner::nuevo(
            &m,
            ConfigEscaner {
                tam_chunk: 20,
                solapamiento: 16,
            },
        );
        let r = esc.escanear(&fuente, &mut SinEstrangular).unwrap();
        assert_eq!(r.len(), 1, "con solapamiento debe encontrarla");
        assert_eq!(r[0].regla, "APT29_Core");
        assert_eq!(r[0].etiqueta, "pid 42 [heap]");

        // Sin solapamiento (escáner ingenuo): la PIERDE. Es justo el bug que el
        // solapamiento evita.
        let esc_ingenuo = AegisMemScanner::nuevo(
            &m,
            ConfigEscaner {
                tam_chunk: 20,
                solapamiento: 0,
            },
        );
        let r0 = esc_ingenuo.escanear(&fuente, &mut SinEstrangular).unwrap();
        assert!(
            r0.is_empty(),
            "sin solapamiento un escáner ingenuo pierde la firma partida"
        );
    }

    #[test]
    fn no_duplica_una_firma_dentro_del_solapamiento() {
        // El marcador cae dentro de la zona que se re-escanea (solapamiento): no
        // debe contarse dos veces.
        let mut datos = vec![0u8; 60];
        datos[18..34].copy_from_slice(MARCADOR);
        let fuente = MemoriaPlana {
            base: 0,
            datos,
            etiqueta: "r".into(),
        };
        let m = motor();
        let esc = AegisMemScanner::nuevo(
            &m,
            ConfigEscaner {
                tam_chunk: 16,
                solapamiento: 16,
            },
        );
        let r = esc.escanear(&fuente, &mut SinEstrangular).unwrap();
        assert_eq!(r.len(), 1, "una sola coincidencia por (regla, región)");
    }

    #[test]
    fn el_estrangulador_contabiliza_todos_los_bytes() {
        let datos = vec![0u8; 100];
        let fuente = MemoriaPlana {
            base: 0,
            datos,
            etiqueta: "r".into(),
        };
        let m = motor();
        let esc = AegisMemScanner::nuevo(
            &m,
            ConfigEscaner {
                tam_chunk: 30,
                solapamiento: 8,
            },
        );
        let mut reg = Registro::default();
        esc.escanear(&fuente, &mut reg).unwrap();
        // 100 bytes en chunks de 30: 30+30+30+10.
        assert_eq!(reg.bytes, 100);
        assert_eq!(reg.chunks, 4);
    }

    #[test]
    fn memoria_limpia_no_coincide() {
        let fuente = MemoriaPlana {
            base: 0,
            datos: vec![0x41u8; 500],
            etiqueta: "r".into(),
        };
        let m = motor();
        let esc = AegisMemScanner::nuevo(&m, ConfigEscaner::default());
        assert!(esc
            .escanear(&fuente, &mut SinEstrangular)
            .unwrap()
            .is_empty());
    }
}
