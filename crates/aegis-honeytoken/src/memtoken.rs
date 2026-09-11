//! Planificar donde colocar un honey-token en la memoria de un proceso.
//!
//! Para que un atacante que vuelca la memoria de LSASS (o de un `ssh-agent`) se
//! encuentre el senuelo, hay que colocarlo en una region ESCRIBIBLE y que el
//! atacante mire: el heap, no una region de solo lectura ni el codigo. Esto se
//! decide leyendo `/proc/<pid>/maps` REAL —el mismo formato en cualquier Linux—,
//! asi que la PLANIFICACION se prueba de verdad aqui (contra `/proc/self/maps`),
//! aunque ESCRIBIR en la memoria de otro proceso sea fontaneria gated.

/// Una region de memoria candidata a alojar el senuelo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionEscribible {
    /// Direccion virtual de inicio.
    pub inicio: u64,
    /// Direccion virtual de fin (exclusiva).
    pub fin: u64,
    /// La etiqueta de `/proc/maps` (p.ej. `[heap]`, `[stack]`, o vacio).
    pub etiqueta: String,
}

impl RegionEscribible {
    /// El tamano de la region en bytes.
    pub fn tamano(&self) -> u64 {
        self.fin.saturating_sub(self.inicio)
    }
}

/// Un fallo al planificar.
#[derive(Debug, thiserror::Error)]
pub enum MemtokenError {
    /// No se pudo leer el mapa de memoria del proceso.
    #[error("no se pudo leer /proc/{0}/maps")]
    SinMaps(i32),
}

/// Lee `/proc/<pid>/maps` y devuelve las regiones escribibles y anonimas (heap,
/// stack, mapeos anonimos): donde un atacante buscaria credenciales y donde, por
/// tanto, tiene sentido sembrar el senuelo. Se descartan las regiones de solo
/// lectura y las respaldadas por fichero (bibliotecas, el binario).
pub fn planificar(pid: i32) -> Result<Vec<RegionEscribible>, MemtokenError> {
    let ruta = format!("/proc/{pid}/maps");
    let contenido = std::fs::read_to_string(&ruta).map_err(|_| MemtokenError::SinMaps(pid))?;
    Ok(parsear_maps(&contenido))
}

/// Parsea el texto de un `/proc/<pid>/maps`. Aparte para poder probarlo con una
/// muestra fija ademas de con el mapa real.
pub fn parsear_maps(texto: &str) -> Vec<RegionEscribible> {
    let mut out = Vec::new();
    for linea in texto.lines() {
        // Formato: "inicio-fin perms offset dev inode  ruta"
        let mut campos = linea.split_whitespace();
        let Some(rango) = campos.next() else { continue };
        let Some(perms) = campos.next() else { continue };
        // Escribible y privada (copy-on-write): 'w' y 'p'.
        if !(perms.contains('w') && perms.contains('p')) {
            continue;
        }
        let _offset = campos.next();
        let _dev = campos.next();
        let _inode = campos.next();
        let etiqueta = campos.next().unwrap_or("").to_string();
        // Se descartan las regiones respaldadas por fichero (una ruta absoluta):
        // el senuelo va en memoria anonima o en heap/stack, donde vive el botin.
        if etiqueta.starts_with('/') {
            continue;
        }
        let Some((ini, fin)) = rango.split_once('-') else {
            continue;
        };
        let (Ok(inicio), Ok(fin)) = (u64::from_str_radix(ini, 16), u64::from_str_radix(fin, 16))
        else {
            continue;
        };
        out.push(RegionEscribible {
            inicio,
            fin,
            etiqueta,
        });
    }
    out
}
