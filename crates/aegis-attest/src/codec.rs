//! Lector y escritor de bytes big-endian con comprobacion de limites.
//!
//! El wire del TPM 2.0 es big-endian de principio a fin (al reves que el event
//! log de UEFI). Se ensambla y se lee a mano —igual que `construir_pcr_read` en
//! `aegis-firmware::tpm`— para no arrastrar `tss-esapi`, que traeria la libreria
//! `libtss2` en C que este entorno no puede instalar.
//!
//! Un lector con comprobacion de limites no es cosmetica: el blob viene firmado
//! por el TPM pero el PARSEO ocurre antes de verificar nada, sobre bytes que en
//! el peor caso controla un atacante. Un `TPM2B` con una longitud que se sale
//! del buffer tiene que ser un error limpio, no un panico ni una lectura fuera
//! de rango.

use thiserror::Error;

/// Un fallo al leer el wire del TPM: se acabaron los bytes, o una longitud
/// declarada no cabe en lo que queda.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    /// Se pidieron mas bytes de los que quedan en el buffer.
    #[error("fin de buffer: se pidieron {pedidos} bytes en la posicion {pos} de {total}")]
    FinDeBuffer {
        /// Bytes solicitados.
        pedidos: usize,
        /// Posicion del cursor.
        pos: usize,
        /// Tamano total del buffer.
        total: usize,
    },
    /// Un campo `TPM2B` declaro una longitud que no cabe en el buffer.
    #[error("longitud TPM2B invalida: {declarada} bytes no caben en los {restantes} que quedan")]
    Tpm2bInvalido {
        /// Longitud declarada en el prefijo de 2 bytes.
        declarada: usize,
        /// Bytes que quedaban.
        restantes: usize,
    },
}

/// Lector big-endian sobre un buffer prestado.
pub struct Lector<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    /// Crea un lector al principio de `buf`.
    pub fn new(buf: &'a [u8]) -> Lector<'a> {
        Lector { buf, pos: 0 }
    }

    /// Cuantos bytes quedan sin leer.
    pub fn restantes(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn tomar(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let fin = self.pos.checked_add(n).ok_or(CodecError::FinDeBuffer {
            pedidos: n,
            pos: self.pos,
            total: self.buf.len(),
        })?;
        let trozo = self.buf.get(self.pos..fin).ok_or(CodecError::FinDeBuffer {
            pedidos: n,
            pos: self.pos,
            total: self.buf.len(),
        })?;
        self.pos = fin;
        Ok(trozo)
    }

    /// Lee un `u8`.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.tomar(1)?[0])
    }

    /// Lee un `u16` big-endian.
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.tomar(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Lee un `u32` big-endian.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.tomar(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Lee un `u64` big-endian.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.tomar(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Lee `n` bytes crudos.
    pub fn bytes(&mut self, n: usize) -> Result<Vec<u8>, CodecError> {
        Ok(self.tomar(n)?.to_vec())
    }

    /// Lee un `TPM2B`: un `u16` de longitud seguido de esa cantidad de bytes.
    /// Es el patron que mas se repite en el wire y el que un parser descuidado
    /// rompe: la longitud la escribe el emisor del blob.
    pub fn tpm2b(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.u16()? as usize;
        if n > self.restantes() {
            return Err(CodecError::Tpm2bInvalido {
                declarada: n,
                restantes: self.restantes(),
            });
        }
        self.bytes(n)
    }
}

/// Escritor big-endian. La contraparte del lector: re-marshalar la estructura
/// parseada y comprobar que da los MISMOS bytes es como se detecta que el
/// parser interpreto algun campo mal.
#[derive(Default)]
pub struct Escritor {
    buf: Vec<u8>,
}

impl Escritor {
    /// Un escritor vacio.
    pub fn new() -> Escritor {
        Escritor { buf: Vec::new() }
    }

    /// Anade un `u8`.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Anade un `u16` big-endian.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Anade un `u32` big-endian.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Anade un `u64` big-endian.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Anade bytes crudos.
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Anade un `TPM2B`: la longitud en `u16` y luego los bytes.
    pub fn tpm2b(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.buf.extend_from_slice(b);
    }

    /// Consume el escritor y devuelve los bytes.
    pub fn finalizar(self) -> Vec<u8> {
        self.buf
    }
}
