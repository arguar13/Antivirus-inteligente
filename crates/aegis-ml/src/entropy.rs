//! Entropia de Shannon.
//!
//! Es la medida que distingue datos estructurados de datos cifrados o
//! comprimidos, y sostiene tres heuristicas distintas del producto: detectar
//! secciones empaquetadas en un binario, reconocer que un proceso ha empezado a
//! cifrar ficheros, y puntuar recursos incrustados.
//!
//! # La definicion
//!
//! Para una distribucion de simbolos con probabilidades `p_i`:
//!
//! ```text
//! H = - SUM p_i * log2(p_i)
//! ```
//!
//! Sobre bytes, el maximo es 8,0 bits/byte: cada byte lleva exactamente 8 bits
//! de informacion, que es lo que ocurre cuando todos los valores son
//! equiprobables. Texto en ingles ronda 4,0-4,7; un ejecutable sin empaquetar
//! 5,5-6,5; datos comprimidos o cifrados 7,9-8,0.
//!
//! # Lo que la entropia NO dice
//!
//! Alta entropia significa "indistinguible de aleatorio", no "malicioso". Un
//! ZIP, un JPEG y un binario firmado y comprimido dan todos por encima de 7,9.
//! Por eso en este producto la entropia nunca es un veredicto por si sola: es
//! una caracteristica mas del vector, y en el detector de ransomware lo que
//! importa es el SALTO de entropia de un fichero concreto, no su valor
//! absoluto.

/// Entropia de Shannon de un buffer, en bits por byte.
///
/// Devuelve 0,0 para un buffer vacio: sin simbolos no hay incertidumbre.
pub fn shannon(datos: &[u8]) -> f64 {
    if datos.is_empty() {
        return 0.0;
    }
    let mut cuenta = [0u32; 256];
    for &b in datos {
        cuenta[b as usize] += 1;
    }
    let total = datos.len() as f64;
    let mut h = 0.0;
    for &c in cuenta.iter() {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / total;
        h -= p * p.log2();
    }
    h
}

/// Entropia en punto fijo Q8.8, la codificacion del ABI.
///
/// `entropia * 256`, de modo que 8,0 bits/byte se codifica como 2048. Se usa
/// en los eventos de kernel, donde no hay coma flotante disponible.
pub fn shannon_q8_8(datos: &[u8]) -> u16 {
    let h = shannon(datos);
    (h * 256.0).round().clamp(0.0, u16::MAX as f64) as u16
}

/// Convierte de Q8.8 a bits por byte.
pub fn from_q8_8(v: u16) -> f64 {
    f64::from(v) / 256.0
}

/// Estadisticas de entropia calculadas por bloques.
///
/// La entropia global de un fichero oculta la estructura interna: un binario
/// con una seccion de codigo normal y una carga util cifrada al final da una
/// media discreta y no llama la atencion. Trocear lo hace visible, y el maximo
/// por bloque es la senal util.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct BlockEntropy {
    /// Media de la entropia de los bloques.
    pub mean: f64,
    /// Maximo. Delata una region empaquetada aunque el resto sea normal.
    pub max: f64,
    /// Minimo. Muy bajo indica relleno o ceros.
    pub min: f64,
    /// Desviacion tipica. Alta significa que el fichero mezcla regiones de
    /// naturaleza muy distinta, que es lo que hace un packer.
    pub stddev: f64,
    /// Numero de bloques medidos.
    pub blocks: usize,
    /// Fraccion de bloques por encima de 7,5 bits/byte.
    pub high_ratio: f64,
}

/// Umbral por encima del cual un bloque se considera indistinguible de
/// aleatorio.
pub const HIGH_ENTROPY: f64 = 7.5;

/// Calcula estadisticas de entropia por bloques de `block_size` bytes.
///
/// El ultimo bloque parcial se incluye solo si tiene al menos un cuarto del
/// tamano: un bloque de 12 bytes da una entropia artificialmente baja (no caben
/// suficientes simbolos distintos) y arrastraria la media hacia abajo sin
/// significar nada.
pub fn block_entropy(datos: &[u8], block_size: usize) -> BlockEntropy {
    if datos.is_empty() || block_size == 0 {
        return BlockEntropy::default();
    }
    let minimo = block_size / 4;
    let mut valores: Vec<f64> = datos
        .chunks(block_size)
        .filter(|c| c.len() >= minimo.max(1))
        .map(shannon)
        .collect();

    if valores.is_empty() {
        // El buffer es mas corto que el minimo: se mide entero como un bloque.
        valores.push(shannon(datos));
    }

    let n = valores.len() as f64;
    let mean = valores.iter().sum::<f64>() / n;
    let max = valores.iter().cloned().fold(f64::MIN, f64::max);
    let min = valores.iter().cloned().fold(f64::MAX, f64::min);
    let var = valores.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let altos = valores.iter().filter(|v| **v > HIGH_ENTROPY).count();

    BlockEntropy {
        mean,
        max,
        min,
        stddev: var.sqrt(),
        blocks: valores.len(),
        high_ratio: altos as f64 / n,
    }
}

/// Histograma normalizado de bytes en `buckets` cubos.
///
/// Se agrupa en cubos y no se usan los 256 valores para que la caracteristica
/// tenga dimension fija y manejable: 16 cubos capturan la forma de la
/// distribucion (texto concentrado en ASCII imprimible, binario repartido)
/// sin explotar el tamano del vector.
pub fn byte_histogram(datos: &[u8], buckets: usize) -> Vec<f32> {
    let b = buckets.clamp(1, 256);
    let mut h = vec![0f32; b];
    if datos.is_empty() {
        return h;
    }
    let ancho = 256usize.div_ceil(b);
    for &byte in datos {
        let i = (byte as usize / ancho).min(b - 1);
        h[i] += 1.0;
    }
    let total = datos.len() as f32;
    for v in h.iter_mut() {
        *v /= total;
    }
    h
}

/// Histograma de la entropia por bloques en `buckets` cubos sobre `[0, 8]`.
///
/// Distingue un fichero uniformemente aleatorio de uno que mezcla codigo normal
/// con una carga util cifrada: el primero concentra todos los bloques en el
/// cubo mas alto, el segundo tiene masa en dos zonas separadas. La media sola
/// no distingue esos dos casos.
pub fn entropy_histogram(datos: &[u8], block_size: usize, buckets: usize) -> Vec<f32> {
    let b = buckets.max(1);
    let mut h = vec![0f32; b];
    if datos.is_empty() || block_size == 0 {
        return h;
    }
    let minimo = (block_size / 4).max(1);
    let mut n = 0f32;
    for trozo in datos.chunks(block_size) {
        if trozo.len() < minimo {
            continue;
        }
        let e = shannon(trozo);
        let i = ((e / 8.0) * b as f64).floor().clamp(0.0, (b - 1) as f64) as usize;
        h[i] += 1.0;
        n += 1.0;
    }
    if n == 0.0 {
        let e = shannon(datos);
        let i = ((e / 8.0) * b as f64).floor().clamp(0.0, (b - 1) as f64) as usize;
        h[i] = 1.0;
        return h;
    }
    for v in h.iter_mut() {
        *v /= n;
    }
    h
}

/// Fraccion de bytes ASCII imprimibles, incluidos los espacios en blanco
/// habituales.
pub fn printable_ratio(datos: &[u8]) -> f64 {
    if datos.is_empty() {
        return 0.0;
    }
    let n = datos
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b) || matches!(**b, b'\n' | b'\r' | b'\t'))
        .count();
    n as f64 / datos.len() as f64
}

/// Fraccion de bytes nulos.
///
/// Un valor muy alto indica relleno, tablas sin inicializar o un fichero
/// disperso; muy bajo, en un ejecutable, sugiere que todo el contenido esta
/// comprimido.
pub fn null_ratio(datos: &[u8]) -> f64 {
    if datos.is_empty() {
        return 0.0;
    }
    datos.iter().filter(|b| **b == 0).count() as f64 / datos.len() as f64
}
