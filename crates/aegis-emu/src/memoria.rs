//! El espacio de direcciones virtual del emulador.
//!
//! Es la clave de la seguridad del micro-sandbox: TODA lectura y escritura del
//! binario emulado cae aqui, sobre `Vec<u8>` normales, nunca sobre memoria real
//! del host. Y es la clave de la deteccion de desempaquetado: la memoria
//! **recuerda que direcciones se escribieron** durante la emulacion, de modo que
//! el ejecutor pueda darse cuenta cuando el binario salta a ejecutar codigo que
//! el mismo acaba de escribir —el momento exacto en que un empaquetador despliega
//! su carga real—.

use crate::EmuError;

/// Una region contigua del espacio de direcciones, con sus permisos.
#[derive(Debug, Clone)]
struct Region {
    base: u64,
    bytes: Vec<u8>,
    lectura: bool,
    escritura: bool,
    ejecucion: bool,
}

impl Region {
    fn contiene(&self, dir: u64, n: usize) -> bool {
        let fin_acceso = match dir.checked_add(n as u64) {
            Some(f) => f,
            None => return false,
        };
        let fin_region = self.base + self.bytes.len() as u64;
        dir >= self.base && fin_acceso <= fin_region
    }
}

/// El espacio de direcciones virtual: un conjunto de regiones mapeadas mas el
/// registro de los rangos escritos en tiempo de ejecucion.
#[derive(Debug, Clone, Default)]
pub struct Memoria {
    regiones: Vec<Region>,
    /// Rangos `[inicio, fin)` escritos durante la emulacion, ordenados y
    /// fusionados.
    escritos: Vec<(u64, u64)>,
}

impl Memoria {
    /// Un espacio de direcciones vacio.
    #[must_use]
    pub fn nueva() -> Self {
        Self::default()
    }

    /// Mapea una region con contenido inicial y permisos.
    ///
    /// # Errores
    /// [`EmuError::RegionSolapada`] si pisa una region ya mapeada.
    pub fn mapear(
        &mut self,
        base: u64,
        bytes: Vec<u8>,
        lectura: bool,
        escritura: bool,
        ejecucion: bool,
    ) -> Result<(), EmuError> {
        let fin = base + bytes.len() as u64;
        for r in &self.regiones {
            let rfin = r.base + r.bytes.len() as u64;
            if base < rfin && r.base < fin {
                return Err(EmuError::RegionSolapada(base));
            }
        }
        self.regiones.push(Region {
            base,
            bytes,
            lectura,
            escritura,
            ejecucion,
        });
        Ok(())
    }

    /// Mapea una region de `len` bytes a cero.
    ///
    /// # Errores
    /// [`EmuError::RegionSolapada`] si pisa una region ya mapeada.
    pub fn mapear_vacia(
        &mut self,
        base: u64,
        len: usize,
        lectura: bool,
        escritura: bool,
        ejecucion: bool,
    ) -> Result<(), EmuError> {
        self.mapear(base, vec![0u8; len], lectura, escritura, ejecucion)
    }

    fn region(&self, dir: u64, n: usize) -> Result<&Region, EmuError> {
        self.regiones
            .iter()
            .find(|r| r.contiene(dir, n))
            .ok_or(EmuError::DireccionNoMapeada(dir))
    }

    fn region_mut(&mut self, dir: u64, n: usize) -> Result<&mut Region, EmuError> {
        self.regiones
            .iter_mut()
            .find(|r| r.contiene(dir, n))
            .ok_or(EmuError::DireccionNoMapeada(dir))
    }

    /// Lee `n` bytes (1..=8) como un entero little-endian.
    ///
    /// # Errores
    /// [`EmuError::DireccionNoMapeada`] o [`EmuError::SinPermisoLectura`].
    pub fn leer(&self, dir: u64, n: usize) -> Result<u64, EmuError> {
        let bytes = self.leer_bytes(dir, n)?;
        let mut v = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            v |= u64::from(*b) << (i * 8);
        }
        Ok(v)
    }

    /// Lee `n` bytes crudos.
    ///
    /// # Errores
    /// [`EmuError::DireccionNoMapeada`] o [`EmuError::SinPermisoLectura`].
    pub fn leer_bytes(&self, dir: u64, n: usize) -> Result<Vec<u8>, EmuError> {
        let r = self.region(dir, n)?;
        if !r.lectura {
            return Err(EmuError::SinPermisoLectura(dir));
        }
        let off = (dir - r.base) as usize;
        Ok(r.bytes[off..off + n].to_vec())
    }

    /// Escribe `valor` como `n` bytes (1..=8) little-endian.
    ///
    /// # Errores
    /// [`EmuError::DireccionNoMapeada`] o [`EmuError::SinPermisoEscritura`].
    pub fn escribir(&mut self, dir: u64, valor: u64, n: usize) -> Result<(), EmuError> {
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            *b = ((valor >> (i * 8)) & 0xFF) as u8;
        }
        self.escribir_bytes(dir, &buf[..n])
    }

    /// Escribe bytes crudos y marca el rango como escrito.
    ///
    /// # Errores
    /// [`EmuError::DireccionNoMapeada`] o [`EmuError::SinPermisoEscritura`].
    pub fn escribir_bytes(&mut self, dir: u64, datos: &[u8]) -> Result<(), EmuError> {
        let n = datos.len();
        let r = self.region_mut(dir, n)?;
        if !r.escritura {
            return Err(EmuError::SinPermisoEscritura(dir));
        }
        let off = (dir - r.base) as usize;
        r.bytes[off..off + n].copy_from_slice(datos);
        self.marcar_escrito(dir, n as u64);
        Ok(())
    }

    /// Lee hasta `max` bytes desde `dir` para decodificar una instruccion,
    /// deteniendose al final de la region (una instruccion x86 ocupa como mucho
    /// 15 bytes). Devuelve lo que haya; el decodificador se queja si necesita
    /// mas de lo que hay. Si `dir` no esta mapeada o la region no es legible,
    /// devuelve vacio.
    #[must_use]
    pub fn leer_codigo(&self, dir: u64, max: usize) -> Vec<u8> {
        let Some(r) = self.regiones.iter().find(|r| r.contiene(dir, 1)) else {
            return Vec::new();
        };
        if !r.lectura {
            return Vec::new();
        }
        let off = (dir - r.base) as usize;
        let fin = (off + max).min(r.bytes.len());
        r.bytes[off..fin].to_vec()
    }

    /// `true` si la region que contiene `dir` tiene permiso de ejecucion.
    #[must_use]
    pub fn es_ejecutable(&self, dir: u64) -> bool {
        self.regiones
            .iter()
            .find(|r| r.contiene(dir, 1))
            .is_some_and(|r| r.ejecucion)
    }

    fn marcar_escrito(&mut self, base: u64, len: u64) {
        let Some(fin) = base.checked_add(len) else {
            return;
        };
        self.escritos.push((base, fin));
        self.escritos.sort_unstable();
        // Fusionar solapes y adyacencias.
        let mut fusionado: Vec<(u64, u64)> = Vec::with_capacity(self.escritos.len());
        for (ini, f) in self.escritos.drain(..) {
            if let Some(ultimo) = fusionado.last_mut() {
                if ini <= ultimo.1 {
                    ultimo.1 = ultimo.1.max(f);
                    continue;
                }
            }
            fusionado.push((ini, f));
        }
        self.escritos = fusionado;
    }

    /// `true` si `dir` cae en algun rango que se escribio durante la emulacion.
    #[must_use]
    pub fn fue_escrito(&self, dir: u64) -> bool {
        self.escritos.iter().any(|&(i, f)| dir >= i && dir < f)
    }

    /// El rango escrito `[inicio, fin)` que contiene `dir`, si lo hay. Es la
    /// region desempaquetada que se puede volcar para escanear.
    #[must_use]
    pub fn rango_escrito(&self, dir: u64) -> Option<(u64, u64)> {
        self.escritos
            .iter()
            .find(|&&(i, f)| dir >= i && dir < f)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lectura_y_escritura_little_endian() {
        let mut m = Memoria::nueva();
        m.mapear_vacia(0x1000, 64, true, true, false).unwrap();
        m.escribir(0x1000, 0x1122_3344, 4).unwrap();
        assert_eq!(m.leer(0x1000, 4).unwrap(), 0x1122_3344);
        // Byte a byte confirma el orden little-endian.
        assert_eq!(m.leer(0x1000, 1).unwrap(), 0x44);
        assert_eq!(m.leer(0x1003, 1).unwrap(), 0x11);
    }

    #[test]
    fn respeta_permisos() {
        let mut m = Memoria::nueva();
        m.mapear(0x2000, vec![0xAA; 16], true, false, false)
            .unwrap();
        assert_eq!(m.leer(0x2000, 1).unwrap(), 0xAA);
        assert_eq!(
            m.escribir(0x2000, 1, 1),
            Err(EmuError::SinPermisoEscritura(0x2000))
        );
    }

    #[test]
    fn acceso_fuera_de_region_falla() {
        let m = Memoria::nueva();
        assert_eq!(m.leer(0x9999, 1), Err(EmuError::DireccionNoMapeada(0x9999)));
    }

    #[test]
    fn seguimiento_de_escrituras_para_desempaquetado() {
        let mut m = Memoria::nueva();
        m.mapear_vacia(0x4000, 0x1000, true, true, false).unwrap();
        assert!(!m.fue_escrito(0x4010));
        m.escribir_bytes(0x4010, &[0x90, 0x90, 0x90, 0x90]).unwrap();
        assert!(m.fue_escrito(0x4010));
        assert!(m.fue_escrito(0x4013));
        assert!(!m.fue_escrito(0x4014));
        assert_eq!(m.rango_escrito(0x4012), Some((0x4010, 0x4014)));
    }

    #[test]
    fn los_rangos_escritos_se_fusionan() {
        let mut m = Memoria::nueva();
        m.mapear_vacia(0x5000, 0x100, true, true, false).unwrap();
        m.escribir_bytes(0x5000, &[0; 8]).unwrap();
        m.escribir_bytes(0x5008, &[0; 8]).unwrap(); // adyacente -> fusiona
        assert_eq!(m.rango_escrito(0x5004), Some((0x5000, 0x5010)));
    }
}
