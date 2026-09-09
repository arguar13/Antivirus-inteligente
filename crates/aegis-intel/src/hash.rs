//! Huellas SHA-256 y el reparto entre lo que sale del equipo y lo que no.
//!
//! # La frontera
//!
//! Un SHA-256 tiene 64 caracteres hexadecimales. De ellos salen del equipo
//! exactamente **5**. Los otros 59 no se transmiten nunca, ni cifrados ni
//! troceados ni derivados: se quedan en memoria del agente y solo se usan para
//! comparar localmente contra lo que devuelve el servidor.
//!
//! Esa frontera es la propiedad de privacidad entera del modulo, y por eso el
//! prefijo y el sufijo son tipos distintos: hace falta un acto deliberado para
//! poner un sufijo donde va un prefijo, y el compilador rechaza el descuido.

use std::fmt;

use sha2::{Digest, Sha256};

/// Caracteres hexadecimales del prefijo que se envia al servidor.
///
/// Cinco caracteres son 20 bits. Sobre un corpus de mil millones de hashes
/// conocidos (~2^30), el cubo esperado es 2^(30-20) = 1024 candidatos: el
/// servidor sabe que se pregunto por *algo* dentro de un millar y no puede
/// saber cual, ni siquiera correlacionando consultas sucesivas.
///
/// Seis caracteres dejarian el cubo en 64, que con consultas repetidas se
/// correlaciona; cuatro lo subirian a 16.000 y la respuesta a ~180 KB.
pub const PREFIJO_LEN: usize = 5;

/// Caracteres hexadecimales que nunca salen del equipo.
pub const SUFIJO_LEN: usize = 64 - PREFIJO_LEN;

/// Error al analizar una huella.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HashError {
    /// Longitud incorrecta.
    #[error("longitud {found}, se esperaban {expected} caracteres hexadecimales")]
    Length {
        /// Encontrada.
        found: usize,
        /// Esperada.
        expected: usize,
    },
    /// Caracter no hexadecimal.
    #[error("caracter no hexadecimal: {0:?}")]
    NotHex(char),
}

/// Huella SHA-256 completa.
///
/// Se guarda en binario y no en texto: 32 bytes frente a 64, y la comparacion
/// es una sola instruccion en vez de un recorrido de cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest256(pub [u8; 32]);

impl Digest256 {
    /// Calcula la huella de un buffer.
    pub fn of(datos: &[u8]) -> Digest256 {
        let mut h = Sha256::new();
        h.update(datos);
        Digest256(h.finalize().into())
    }

    /// Calcula la huella de un fichero por bloques.
    ///
    /// Por bloques y no leyendo entero: un fichero de 4 GB no cabe en el
    /// presupuesto de 50 MB de memoria del agente.
    pub fn of_file(ruta: &std::path::Path) -> Result<Digest256, std::io::Error> {
        use std::io::Read;
        let mut f = std::fs::File::open(ruta)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(Digest256(h.finalize().into()))
    }

    /// Analiza una huella en hexadecimal.
    pub fn parse(s: &str) -> Result<Digest256, HashError> {
        if s.len() != 64 {
            return Err(HashError::Length {
                found: s.len(),
                expected: 64,
            });
        }
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        for i in 0..32 {
            out[i] = (nibble(b[2 * i] as char)? << 4) | nibble(b[2 * i + 1] as char)?;
        }
        Ok(Digest256(out))
    }

    /// Representacion hexadecimal en minusculas.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Los 5 caracteres que se envian al servidor.
    pub fn prefix(self) -> Prefix {
        let mut p = [0u8; PREFIJO_LEN];
        p[0] = HEX[(self.0[0] >> 4) as usize];
        p[1] = HEX[(self.0[0] & 0x0f) as usize];
        p[2] = HEX[(self.0[1] >> 4) as usize];
        p[3] = HEX[(self.0[1] & 0x0f) as usize];
        p[4] = HEX[(self.0[2] >> 4) as usize];
        Prefix(p)
    }

    /// Los 59 caracteres que no salen del equipo.
    pub fn suffix(self) -> Suffix {
        let hex = self.to_hex();
        let mut s = [0u8; SUFIJO_LEN];
        s.copy_from_slice(&hex.as_bytes()[PREFIJO_LEN..]);
        Suffix(s)
    }
}

impl fmt::Display for Digest256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Prefijo de 5 caracteres hexadecimales. **Es lo unico que sale del equipo.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix([u8; PREFIJO_LEN]);

impl Prefix {
    /// Texto del prefijo.
    pub fn as_str(&self) -> &str {
        // Invariante: solo se construye con digitos hexadecimales de `HEX`.
        std::str::from_utf8(&self.0).unwrap_or("00000")
    }

    /// Analiza un prefijo recibido.
    pub fn parse(s: &str) -> Result<Prefix, HashError> {
        if s.len() != PREFIJO_LEN {
            return Err(HashError::Length {
                found: s.len(),
                expected: PREFIJO_LEN,
            });
        }
        let mut p = [0u8; PREFIJO_LEN];
        for (i, c) in s.chars().enumerate() {
            nibble(c)?;
            p[i] = c.to_ascii_lowercase() as u8;
        }
        Ok(Prefix(p))
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sufijo de 59 caracteres. **Nunca se transmite.**
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Suffix([u8; SUFIJO_LEN]);

impl Suffix {
    /// Texto del sufijo.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    /// Analiza un sufijo devuelto por el servidor.
    pub fn parse(s: &str) -> Result<Suffix, HashError> {
        if s.len() != SUFIJO_LEN {
            return Err(HashError::Length {
                found: s.len(),
                expected: SUFIJO_LEN,
            });
        }
        let mut out = [0u8; SUFIJO_LEN];
        for (i, c) in s.chars().enumerate() {
            nibble(c)?;
            out[i] = c.to_ascii_lowercase() as u8;
        }
        Ok(Suffix(out))
    }
}

/// Se implementa a mano para que el sufijo NO aparezca entero en los registros.
///
/// Un `derive(Debug)` acabaria escribiendo la parte secreta del hash en el
/// primer `error!` que incluya la estructura, y ahi se pierde la propiedad de
/// privacidad que justifica todo el modulo.
impl fmt::Debug for Suffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Suffix(<{} caracteres ocultos>)", SUFIJO_LEN)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn nibble(c: char) -> Result<u8, HashError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(HashError::NotHex(c)),
    }
}
