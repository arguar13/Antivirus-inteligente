//! Politica de barrido de la memoria de procesos vivos.
//!
//! El MODELO de una region —permisos, clase, rango— y las primitivas para
//! leerla viven en `aegis-scal`, la capa de abstraccion del sistema: son lo
//! mismo en Linux, Windows y macOS salvo por como se obtienen, y duplicarlas
//! aqui habria atado el motor de deteccion a `procfs`. Lo que queda en este
//! modulo es lo que SI es del escaner: que regiones merece la pena leer, en que
//! orden y en trozos de que tamano.
//!
//! Se reexporta el modelo para que el resto del producto siga entrando por
//! `aegis_scan::memory`, que es donde lo espera.

pub use aegis_scal::memory::{MemoryRegion, Perms, RegionClass};

#[cfg(target_os = "linux")]
pub use aegis_scal::linux::memory::{
    is_kernel_thread, parse_maps, read_memory, regions_of, ReadError,
};

/// Politica de barrido de memoria.
#[derive(Debug, Clone, Copy)]
pub struct MemoryScanPolicy {
    /// Tamano maximo de una region que se acepta escanear.
    ///
    /// Una region de decenas de gigabytes de un proceso de base de datos agota
    /// la memoria del agente sin aportar deteccion.
    pub max_region_bytes: u64,
    /// Presupuesto total por proceso.
    pub max_total_bytes: u64,
    /// Tamano de cada lectura.
    pub chunk_bytes: usize,
    /// Solape entre trozos consecutivos.
    ///
    /// Sin solape, un patron que cruce la frontera de dos trozos no se detecta
    /// nunca. Es el fallo mas facil de cometer en un escaner por trozos y el
    /// mas dificil de notar, porque solo se manifiesta con ciertos tamanos.
    pub overlap_bytes: usize,
    /// Escanear tambien las regiones respaldadas por fichero.
    ///
    /// Desactivado por defecto: son una copia de algo que ya esta en disco, y
    /// activarlo significa releer `libc` una vez por proceso en cada barrido.
    pub include_file_backed: bool,
}

impl Default for MemoryScanPolicy {
    fn default() -> Self {
        Self {
            max_region_bytes: 256 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            chunk_bytes: 8 * 1024 * 1024,
            // 64 KiB cubre con holgura cualquier patron YARA razonable.
            overlap_bytes: 64 * 1024,
            include_file_backed: false,
        }
    }
}

impl MemoryScanPolicy {
    /// Indica si una region entra en el barrido segun esta politica.
    pub fn accepts(&self, r: &MemoryRegion) -> bool {
        if !r.is_readable() || r.is_empty() {
            return false;
        }
        if r.len() > self.max_region_bytes {
            return false;
        }
        match r.class() {
            RegionClass::AnonymousExec | RegionClass::AnonymousData => true,
            RegionClass::FileExec | RegionClass::FileData => self.include_file_backed,
            RegionClass::Kernel | RegionClass::Device => false,
        }
    }
}

/// Ordena las regiones por valor de deteccion, de mayor a menor.
///
/// El barrido tiene un presupuesto: si se agota, es preferible haberlo gastado
/// en la memoria anonima ejecutable, donde vive el codigo sin fichero, que en
/// el monton de un navegador.
pub fn prioritize(regiones: &mut [MemoryRegion]) {
    regiones.sort_by_key(|r| match r.class() {
        RegionClass::AnonymousExec if r.perms.is_rwx() => 0,
        RegionClass::AnonymousExec => 1,
        RegionClass::AnonymousData if r.perms.write => 2,
        RegionClass::AnonymousData => 3,
        RegionClass::FileExec => 4,
        RegionClass::FileData => 5,
        RegionClass::Kernel | RegionClass::Device => 6,
    });
}

/// Calcula los trozos con solape que cubren `[start, end)`.
///
/// Devuelve pares `(direccion, longitud)`. Dos propiedades que el llamante
/// necesita y que se verifican en las pruebas:
///
/// 1. **Cobertura completa**: todo byte del rango aparece en algun trozo.
/// 2. **Solape efectivo**: dos trozos consecutivos comparten `overlap` bytes,
///    de modo que un patron a caballo entre ambos aparece entero en al menos
///    uno.
///
/// La segunda es el fallo mas facil de cometer en un escaner por trozos y el
/// mas dificil de notar: solo se manifiesta con ciertas combinaciones de tamano
/// de patron, tamano de trozo y posicion, y cuando lo hace el escaner
/// simplemente no encuentra algo que estaba ahi.
pub fn chunk_ranges(start: u64, end: u64, chunk: usize, overlap: usize) -> Vec<(u64, usize)> {
    let mut salida = Vec::new();
    if end <= start || chunk == 0 {
        return salida;
    }
    // El solape se acota a la MITAD del trozo, no a `chunk - 1`.
    //
    // Con el limite ingenuo, una politica mal configurada (solape 500 sobre
    // trozos de 100) hace que el cursor avance un solo byte por lectura: el
    // bucle termina, pero un barrido de 100 MB pasaria a ser 100 millones de
    // lecturas y contra un proceso real seria indistinguible de un cuelgue.
    //
    // Acotar a la mitad garantiza que el avance nunca baja de `chunk / 2`, con
    // lo que el numero de trozos queda acotado por `2 * rango / chunk` sea cual
    // sea el solape pedido. Y es lo semanticamente correcto: si hace falta un
    // solape mayor que medio trozo, el trozo es demasiado pequeno para los
    // patrones que se buscan, y la respuesta es no arrastrarse.
    let paso = chunk as u64;
    let solape = (overlap as u64).min(paso / 2).min(paso.saturating_sub(1));

    let mut pos = start;
    loop {
        let restante = end - pos;
        let len = restante.min(paso);
        salida.push((pos, len as usize));
        if len >= restante {
            break;
        }
        pos += len - solape;
    }
    salida
}
