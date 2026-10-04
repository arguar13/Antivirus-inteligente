//! Codificacion canonica a mano: enteros little-endian de ancho fijo y cadenas
//! con prefijo de longitud.
//!
//! # Por que a mano
//!
//! Lo que se firma son BYTES. Si el mismo paquete admitiera dos codificaciones,
//! la firma dejaria de significar «este paquete» para significar «estos bytes»
//! (la misma razon que en `aegis-ruleforge/corpus.rs`). Por eso el lector es
//! estricto: booleanos solo 0 o 1, etiquetas conocidas, limites por campo y
//! ningun byte sobrante.

/// Error de formato: los bytes no son lo que dicen ser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ErrorFormato(pub String);

/// Escritor de la codificacion canonica.
#[derive(Debug, Default)]
pub(crate) struct Escritor {
    v: Vec<u8>,
}

impl Escritor {
    pub(crate) fn nuevo() -> Escritor {
        Escritor::default()
    }
    pub(crate) fn u8(&mut self, x: u8) {
        self.v.push(x);
    }
    pub(crate) fn u16(&mut self, x: u16) {
        self.v.extend_from_slice(&x.to_le_bytes());
    }
    pub(crate) fn u32(&mut self, x: u32) {
        self.v.extend_from_slice(&x.to_le_bytes());
    }
    pub(crate) fn u64(&mut self, x: u64) {
        self.v.extend_from_slice(&x.to_le_bytes());
    }
    pub(crate) fn fijo(&mut self, b: &[u8]) {
        self.v.extend_from_slice(b);
    }
    /// Cuenta de elementos. Los limites (muy por debajo de `u32::MAX`) los
    /// imponen las comprobaciones de estructura antes de codificar.
    pub(crate) fn cuenta(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.cuenta(b.len());
        self.v.extend_from_slice(b);
    }
    pub(crate) fn texto(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    pub(crate) fn booleano(&mut self, b: bool) {
        self.u8(u8::from(b));
    }
    pub(crate) fn fin(self) -> Vec<u8> {
        self.v
    }
}

/// Lector estricto de la codificacion canonica.
pub(crate) struct Lector<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Lector<'a> {
    pub(crate) fn nuevo(b: &'a [u8]) -> Lector<'a> {
        Lector { b, i: 0 }
    }

    pub(crate) fn fijo(&mut self, n: usize) -> Result<&'a [u8], ErrorFormato> {
        let fin = self
            .i
            .checked_add(n)
            .filter(|&f| f <= self.b.len())
            .ok_or_else(|| ErrorFormato(format!("truncado en el byte {}", self.i)))?;
        let s = &self.b[self.i..fin];
        self.i = fin;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ErrorFormato> {
        Ok(self.fijo(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ErrorFormato> {
        let s = self.fijo(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ErrorFormato> {
        let s = self.fijo(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ErrorFormato> {
        let s = self.fijo(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }

    pub(crate) fn fijo32(&mut self) -> Result<[u8; 32], ErrorFormato> {
        let s = self.fijo(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Una cuenta de elementos, que no puede pasar de `max`.
    pub(crate) fn cuenta(&mut self, max: usize, que: &str) -> Result<usize, ErrorFormato> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(ErrorFormato(format!(
                "{que}: {n} supera el limite de {max}"
            )));
        }
        Ok(n)
    }

    pub(crate) fn bytes(&mut self, max: usize, que: &str) -> Result<&'a [u8], ErrorFormato> {
        let n = self.cuenta(max, que)?;
        self.fijo(n)
    }

    pub(crate) fn texto(&mut self, max: usize, que: &str) -> Result<&'a str, ErrorFormato> {
        std::str::from_utf8(self.bytes(max, que)?)
            .map_err(|_| ErrorFormato(format!("{que}: no es UTF-8")))
    }

    pub(crate) fn booleano(&mut self, que: &str) -> Result<bool, ErrorFormato> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            x => Err(ErrorFormato(format!("{que}: booleano {x} no canonico"))),
        }
    }

    /// Exige que no sobre nada: dos paquetes que solo difieren en una cola
    /// ignorada serian dos codificaciones del mismo paquete.
    pub(crate) fn terminar(&self) -> Result<(), ErrorFormato> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(ErrorFormato(format!(
                "sobran {} bytes al final",
                self.b.len() - self.i
            )))
        }
    }
}

/// Hexadecimal en minusculas.
#[must_use]
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Lee 32 bytes de su hexadecimal.
///
/// # Errores
/// [`ErrorFormato`] si no son 64 digitos hexadecimales.
pub fn de_hex32(s: &str) -> Result<[u8; 32], ErrorFormato> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(ErrorFormato(format!(
            "hash de {} caracteres, no 64",
            b.len()
        )));
    }
    let mut a = [0u8; 32];
    for (i, par) in b.chunks(2).enumerate() {
        let t = std::str::from_utf8(par).map_err(|_| ErrorFormato("hash no ASCII".into()))?;
        a[i] = u8::from_str_radix(t, 16).map_err(|_| ErrorFormato(format!("«{t}» no es hex")))?;
    }
    Ok(a)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ida_y_vuelta_de_cada_tipo() {
        let mut e = Escritor::nuevo();
        e.u8(7);
        e.u16(0xBEEF);
        e.u32(123_456);
        e.u64(u64::MAX - 1);
        e.texto("canal");
        e.booleano(true);
        let v = e.fin();
        let mut l = Lector::nuevo(&v);
        assert_eq!(l.u8().unwrap(), 7);
        assert_eq!(l.u16().unwrap(), 0xBEEF);
        assert_eq!(l.u32().unwrap(), 123_456);
        assert_eq!(l.u64().unwrap(), u64::MAX - 1);
        assert_eq!(l.texto(16, "t").unwrap(), "canal");
        assert!(l.booleano("b").unwrap());
        l.terminar().unwrap();
    }

    #[test]
    fn el_lector_es_estricto() {
        // Truncado.
        assert!(Lector::nuevo(&[1, 2]).u32().is_err());
        // Booleano no canonico.
        assert!(Lector::nuevo(&[2]).booleano("b").is_err());
        // Longitud por encima del limite, sin reservar nada.
        let mut e = Escritor::nuevo();
        e.u32(1 << 30);
        let v = e.fin();
        assert!(Lector::nuevo(&v).bytes(1024, "x").is_err());
        // Bytes sobrantes.
        let mut l = Lector::nuevo(&[1, 2]);
        l.u8().unwrap();
        assert!(l.terminar().is_err());
    }

    #[test]
    fn hex_ida_y_vuelta() {
        let h = [0xabu8; 32];
        assert_eq!(de_hex32(&hex(&h)).unwrap(), h);
        assert!(de_hex32("zz").is_err());
    }
}
