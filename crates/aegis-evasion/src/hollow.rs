//! Comparacion del codigo en memoria contra el codigo en disco.
//!
//! # La tecnica que detecta
//!
//! El vaciado de proceso ("process hollowing") arranca un binario legitimo,
//! sustituye su codigo en memoria por otro y salta ahi. Para cualquier
//! herramienta que mire el disco, el proceso ES el binario legitimo: la ruta de
//! `/proc/<pid>/exe` apunta a el, su firma es valida, su hash coincide. Lo que
//! ejecuta no tiene nada que ver.
//!
//! La unica forma de verlo es comparar: leer las paginas ejecutables del
//! proceso y contrastarlas con los bytes del fichero que dicen respaldar.
//!
//! # Por que esto no es trivial
//!
//! Una comparacion ingenua marca como manipulado casi todo proceso del sistema.
//! Hay cuatro motivos legitimos por los que la memoria difiere del fichero, y
//! hay que descontarlos todos o la senal se ahoga en ruido:
//!
//! 1. **Resolucion de IFUNC.** `memcpy`, `strlen` y compania se resuelven en
//!    tiempo de carga a la variante que soporta la CPU. En glibc eso reescribe
//!    entradas de la PLT, que viven en paginas ejecutables.
//! 2. **Reubicaciones en texto.** Un objeto sin `-fPIC` lleva `DT_TEXTREL` y el
//!    enlazador parchea instrucciones directamente.
//! 3. **Huecos sin respaldo.** El ultimo trozo de un segmento se rellena con
//!    ceros hasta el limite de pagina; en el fichero no hay nada.
//! 4. **Paginas no residentes.** Leerlas es correcto pero puede fallar si el
//!    proceso muere a mitad.
//!
//! Por eso no se reporta "difiere": se reporta **cuanto** difiere y **donde**.
//! Una resolucion de IFUNC toca decenas de bytes en la PLT. Un vaciado
//! sustituye el segmento entero.
//!
//! # El umbral
//!
//! Se mide la fraccion de bytes distintos sobre el total comparado. Medido
//! sobre los procesos reales de un sistema en marcha, la divergencia legitima
//! se queda muy por debajo del 1%. Se avisa a partir del 2% y se considera
//! vaciado a partir del 25%: no hay zona intermedia poblada, porque o parcheas
//! unas entradas o sustituyes el codigo.

use std::collections::HashMap;

use aegis_scan::memory::{read_memory, MemoryRegion, RegionClass};

use crate::EvasionError;

/// Fraccion de divergencia a partir de la cual se avisa.
pub const FRACCION_AVISO: f64 = 0.02;
/// Fraccion de divergencia a partir de la cual se considera vaciado.
pub const FRACCION_VACIADO: f64 = 0.25;

/// Bytes maximos que se comparan por region.
///
/// Una region de texto de una biblioteca grande son megabytes. Comparar el
/// espacio entero de cada proceso de la maquina cuesta mas de lo que aporta:
/// un vaciado sustituye desde el principio del segmento, asi que el principio
/// es donde esta la respuesta.
pub const BYTES_POR_REGION: usize = 256 * 1024;

/// Granularidad de la comparacion.
const BLOQUE: usize = 4096;

/// Naturaleza de una divergencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HollowVerdict {
    /// La memoria coincide con el disco dentro de lo esperable.
    Intact,
    /// Divergencia por encima de lo normal pero compatible con parcheo puntual.
    Patched,
    /// El codigo en memoria no es el del fichero.
    Hollowed,
}

/// Divergencia encontrada en una region.
#[derive(Debug, Clone, PartialEq)]
pub struct HollowFinding {
    /// Direccion inicial de la region.
    pub start: u64,
    /// Fichero que respalda la region.
    pub path: String,
    /// Desplazamiento dentro del fichero.
    pub file_offset: u64,
    /// Bytes comparados.
    pub compared: usize,
    /// Bytes distintos.
    pub differing: usize,
    /// Bloques de 4 KB con alguna diferencia.
    pub differing_blocks: usize,
    /// Bloques comparados.
    pub blocks: usize,
    /// Veredicto de la region.
    pub verdict: HollowVerdict,
}

impl HollowFinding {
    /// Fraccion de bytes distintos.
    pub fn fraction(&self) -> f64 {
        if self.compared == 0 {
            return 0.0;
        }
        self.differing as f64 / self.compared as f64
    }
}

/// Resultado de comparar un proceso entero.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HollowReport {
    /// Regiones con alguna divergencia.
    pub findings: Vec<HollowFinding>,
    /// Regiones ejecutables comparadas.
    pub regions_compared: usize,
    /// Regiones ejecutables que no se pudieron comparar.
    pub regions_skipped: usize,
    /// Bytes comparados en total.
    pub bytes_compared: usize,
}

impl HollowReport {
    /// Veredicto global: el peor de las regiones.
    pub fn verdict(&self) -> HollowVerdict {
        if self
            .findings
            .iter()
            .any(|f| f.verdict == HollowVerdict::Hollowed)
        {
            HollowVerdict::Hollowed
        } else if self
            .findings
            .iter()
            .any(|f| f.verdict == HollowVerdict::Patched)
        {
            HollowVerdict::Patched
        } else {
            HollowVerdict::Intact
        }
    }

    /// Puntuacion para el informe combinado.
    pub fn score(&self) -> u32 {
        match self.verdict() {
            HollowVerdict::Hollowed => 90,
            HollowVerdict::Patched => 30,
            HollowVerdict::Intact => 0,
        }
    }
}

/// Compara los bloques de dos buffers del mismo tamano.
///
/// Devuelve `(bytes distintos, bloques distintos, bloques comparados)`. Se
/// cuentan las dos cosas porque distinguen los dos casos: un parcheo puntual
/// toca muchos bloques con pocos bytes cada uno (entradas de PLT repartidas),
/// y un vaciado toca todos los bloques por completo.
pub fn diff_blocks(memoria: &[u8], fichero: &[u8]) -> (usize, usize, usize) {
    let n = memoria.len().min(fichero.len());
    let mut bytes = 0usize;
    let mut bloques_distintos = 0usize;
    let mut bloques = 0usize;

    let mut i = 0usize;
    while i < n {
        let fin = (i + BLOQUE).min(n);
        bloques += 1;
        let mut en_bloque = 0usize;
        for j in i..fin {
            if memoria[j] != fichero[j] {
                en_bloque += 1;
            }
        }
        if en_bloque > 0 {
            bloques_distintos += 1;
            bytes += en_bloque;
        }
        i = fin;
    }
    (bytes, bloques_distintos, bloques)
}

/// Decide el veredicto de una region a partir de sus metricas.
///
/// Es una funcion aparte y pura porque el umbral es la decision de producto mas
/// delicada de este modulo: se ajusta y se prueba sin necesitar un proceso.
pub fn clasificar(
    differing: usize,
    compared: usize,
    differing_blocks: usize,
    blocks: usize,
) -> HollowVerdict {
    if compared == 0 {
        return HollowVerdict::Intact;
    }
    let fraccion = differing as f64 / compared as f64;
    if fraccion >= FRACCION_VACIADO {
        return HollowVerdict::Hollowed;
    }
    // Un segmento sustituido por completo puede coincidir por casualidad en
    // muchos bytes si el atacante conserva el relleno, pero no puede dejar
    // bloques intactos: si TODOS los bloques tienen diferencias y ademas la
    // fraccion supera el aviso, no es un parcheo puntual.
    if blocks >= 4 && differing_blocks == blocks && fraccion >= FRACCION_AVISO {
        return HollowVerdict::Hollowed;
    }
    if fraccion >= FRACCION_AVISO {
        return HollowVerdict::Patched;
    }
    HollowVerdict::Intact
}

/// Compara las regiones ejecutables de un proceso con sus ficheros.
///
/// Las regiones sin fichero detras no se comparan aqui: de esas se ocupa
/// [`crate::inject`], porque no hay nada con que contrastarlas.
pub fn compare_process(pid: i32, regiones: &[MemoryRegion]) -> Result<HollowReport, EvasionError> {
    let mut informe = HollowReport::default();
    // Un proceso mapea la misma biblioteca en varios segmentos; leer el fichero
    // una vez por segmento multiplicaria la E/S por nada.
    let mut cache: HashMap<String, Option<Vec<u8>>> = HashMap::new();

    for r in regiones {
        if !r.perms.exec || r.class() != RegionClass::FileExec {
            continue;
        }
        let Some(ruta) = r.path.clone() else { continue };
        // Un fichero borrado o sustituido bajo los pies del proceso aparece
        // marcado asi por el kernel. No se puede comparar, pero es un dato en
        // si mismo y por eso se cuenta como omitida.
        if ruta.ends_with(" (deleted)") {
            informe.regions_skipped += 1;
            continue;
        }

        let contenido = cache
            .entry(ruta.clone())
            .or_insert_with(|| std::fs::read(&ruta).ok());
        let Some(datos) = contenido.as_ref() else {
            informe.regions_skipped += 1;
            continue;
        };

        let inicio = r.offset as usize;
        if inicio >= datos.len() {
            informe.regions_skipped += 1;
            continue;
        }
        let disponible = datos.len() - inicio;
        let largo = (r.len() as usize).min(BYTES_POR_REGION).min(disponible);
        if largo < BLOQUE {
            informe.regions_skipped += 1;
            continue;
        }

        let memoria = match read_memory(pid, r.start, largo) {
            Ok(m) => m,
            Err(_) => {
                informe.regions_skipped += 1;
                continue;
            }
        };
        let fichero = &datos[inicio..inicio + largo];

        let (bytes, bloques_distintos, bloques) = diff_blocks(&memoria, fichero);
        let comparados = memoria.len().min(fichero.len());
        informe.regions_compared += 1;
        informe.bytes_compared += comparados;

        if bytes == 0 {
            continue;
        }
        informe.findings.push(HollowFinding {
            start: r.start,
            path: ruta,
            file_offset: r.offset,
            compared: comparados,
            differing: bytes,
            differing_blocks: bloques_distintos,
            blocks: bloques,
            verdict: clasificar(bytes, comparados, bloques_distintos, bloques),
        });
    }

    informe.findings.sort_by(|a, b| {
        b.fraction()
            .partial_cmp(&a.fraction())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(informe)
}
