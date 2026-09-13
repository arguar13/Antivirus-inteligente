//! Lector acotado en orden de red: ningun campo se lee sin comprobar que cabe.
//!
//! # Por que existe este tipo y no se lee con indices
//!
//! Un disector son cientos de lecturas de campos, cada una con su comprobacion
//! de limites. Dejar esa comprobacion a la disciplina de quien escribe el
//! disector garantiza que, con veinte protocolos, alguna se olvide — y en Rust
//! eso no es una vulnerabilidad de memoria, pero **si** es un panico, y un
//! panico en la ruta de red es una denegacion de servicio contra el propio
//! agente: el atacante manda un paquete preparado y tumba la defensa.
//!
//! Con este lector, pedir un campo que no cabe devuelve un error **con nombre**,
//! siempre, y no hay forma de saltarselo sin escribir otro lector.
//!
//! # Orden de red, no del anfitrion
//!
//! Todo lo que viaja por la red va en **big-endian** salvo excepciones que se
//! marcan una por una (SMB, DNS sobre ciertos campos, QUIC). Los metodos de
//! aqui son big-endian por defecto y los little-endian llevan sufijo `_le`, para
//! que confundirlos exija escribirlo: un campo leido con el orden equivocado no
//! falla, simplemente da otro numero, y ese es el peor tipo de defecto.

use crate::error::{ErrorDiseccion, Resultado};

/// Cursor sobre un buffer de red que nunca lee fuera de rango.
#[derive(Debug, Clone)]
pub struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    /// Nuevo lector sobre `datos`.
    #[must_use]
    pub fn nuevo(datos: &'a [u8]) -> Lector<'a> {
        Lector { datos, pos: 0 }
    }

    /// Posicion actual.
    #[must_use]
    pub fn posicion(&self) -> usize {
        self.pos
    }

    /// Bytes que quedan.
    #[must_use]
    pub fn restante(&self) -> usize {
        self.datos.len().saturating_sub(self.pos)
    }

    /// Si no queda nada.
    #[must_use]
    pub fn vacio(&self) -> bool {
        self.restante() == 0
    }

    /// Todo el buffer, desde el principio.
    #[must_use]
    pub fn todo(&self) -> &'a [u8] {
        self.datos
    }

    /// Lo que queda sin consumir, sin consumirlo.
    #[must_use]
    pub fn resto(&self) -> &'a [u8] {
        &self.datos[self.pos.min(self.datos.len())..]
    }

    /// Coloca el cursor en una posicion absoluta.
    ///
    /// # Errores
    /// [`ErrorDiseccion::LongitudImposible`] si la posicion cae fuera.
    pub fn ir_a(&mut self, pos: usize, campo: &'static str) -> Resultado<()> {
        if pos > self.datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo,
                declarada: pos,
                disponible: self.datos.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Salta `n` bytes.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan `n`.
    pub fn saltar(&mut self, n: usize, campo: &'static str) -> Resultado<()> {
        self.tomar(n, campo).map(|_| ())
    }

    /// Toma `n` bytes crudos.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan `n`.
    pub fn tomar(&mut self, n: usize, campo: &'static str) -> Resultado<&'a [u8]> {
        let fin = self
            .pos
            .checked_add(n)
            .ok_or(ErrorDiseccion::LongitudImposible {
                campo,
                declarada: n,
                disponible: self.restante(),
            })?;
        if fin > self.datos.len() {
            return Err(ErrorDiseccion::Truncado {
                campo,
                esperados: n,
                habia: self.restante(),
            });
        }
        let s = &self.datos[self.pos..fin];
        self.pos = fin;
        Ok(s)
    }

    /// Un byte.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no queda ninguno.
    pub fn u8(&mut self, campo: &'static str) -> Resultado<u8> {
        Ok(self.tomar(1, campo)?[0])
    }

    /// `u16` en orden de red (big-endian).
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan dos bytes.
    pub fn u16(&mut self, campo: &'static str) -> Resultado<u16> {
        let b = self.tomar(2, campo)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// `u16` little-endian (SMB, DHCP en algunos campos).
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan dos bytes.
    pub fn u16_le(&mut self, campo: &'static str) -> Resultado<u16> {
        let b = self.tomar(2, campo)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Entero de 24 bits en orden de red (TLS lo usa por todas partes).
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan tres bytes.
    pub fn u24(&mut self, campo: &'static str) -> Resultado<u32> {
        let b = self.tomar(3, campo)?;
        Ok(u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]))
    }

    /// `u32` en orden de red.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan cuatro bytes.
    pub fn u32(&mut self, campo: &'static str) -> Resultado<u32> {
        let b = self.tomar(4, campo)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `u32` little-endian.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan cuatro bytes.
    pub fn u32_le(&mut self, campo: &'static str) -> Resultado<u32> {
        let b = self.tomar(4, campo)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `u64` en orden de red.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan ocho bytes.
    pub fn u64(&mut self, campo: &'static str) -> Resultado<u64> {
        let b = self.tomar(8, campo)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// `u64` little-endian.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan ocho bytes.
    pub fn u64_le(&mut self, campo: &'static str) -> Resultado<u64> {
        let b = self.tomar(8, campo)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// Un bloque cuya longitud va por delante como `u8`.
    ///
    /// # Errores
    /// Truncamiento, o una longitud que no cabe en lo que queda.
    pub fn bloque_u8(&mut self, campo: &'static str) -> Resultado<&'a [u8]> {
        let n = self.u8(campo)? as usize;
        self.bloque(n, campo)
    }

    /// Un bloque cuya longitud va por delante como `u16` en orden de red.
    ///
    /// # Errores
    /// Truncamiento, o una longitud que no cabe en lo que queda.
    pub fn bloque_u16(&mut self, campo: &'static str) -> Resultado<&'a [u8]> {
        let n = self.u16(campo)? as usize;
        self.bloque(n, campo)
    }

    /// Un bloque cuya longitud va por delante como entero de 24 bits.
    ///
    /// # Errores
    /// Truncamiento, o una longitud que no cabe en lo que queda.
    pub fn bloque_u24(&mut self, campo: &'static str) -> Resultado<&'a [u8]> {
        let n = self.u24(campo)? as usize;
        self.bloque(n, campo)
    }

    /// Un bloque de longitud `n`, comprobando ANTES que cabe.
    ///
    /// La distincion con [`Lector::tomar`] importa: aqui `n` lo dijo el emisor,
    /// asi que una longitud que no cabe es que **mintio**, y se reporta como tal
    /// en vez de como un truncamiento.
    ///
    /// # Errores
    /// [`ErrorDiseccion::LongitudImposible`] si `n` no cabe en lo que queda.
    pub fn bloque(&mut self, n: usize, campo: &'static str) -> Resultado<&'a [u8]> {
        if n > self.restante() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo,
                declarada: n,
                disponible: self.restante(),
            });
        }
        self.tomar(n, campo)
    }

    /// Una sub-vista acotada de `n` bytes, como lector propio.
    ///
    /// Sirve para que un disector anidado NO pueda leer mas alla de su propio
    /// campo aunque su longitud interna mienta: el limite lo impone el tipo, no
    /// la disciplina del que escribe el disector anidado.
    ///
    /// # Errores
    /// [`ErrorDiseccion::LongitudImposible`] si `n` no cabe.
    pub fn sub(&mut self, n: usize, campo: &'static str) -> Resultado<Lector<'a>> {
        Ok(Lector::nuevo(self.bloque(n, campo)?))
    }

    /// Texto ASCII imprimible de longitud fija, recortado en el primer nulo.
    ///
    /// Los bytes vienen de la red: lo que no sea ASCII imprimible se sustituye
    /// por `.` en vez de descartar la cadena entera. Un nombre con basura
    /// intercalada sigue siendo evidencia, y a veces la basura **es** la senal.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan `n` bytes.
    pub fn texto_ascii(&mut self, n: usize, campo: &'static str) -> Resultado<String> {
        let b = self.bloque(n, campo)?;
        Ok(ascii_legible(b))
    }

    /// Texto UTF-16LE de `n` bytes (SMB, Kerberos en Windows).
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si no quedan `n` bytes.
    pub fn texto_utf16le(&mut self, n: usize, campo: &'static str) -> Resultado<String> {
        let b = self.bloque(n, campo)?;
        let unidades: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&unidades)
            .trim_end_matches('\0')
            .to_string())
    }

    /// Busca la primera aparicion de `aguja` a partir del cursor.
    ///
    /// Devuelve el desplazamiento ABSOLUTO, sin mover el cursor.
    #[must_use]
    pub fn buscar(&self, aguja: &[u8]) -> Option<usize> {
        if aguja.is_empty() || aguja.len() > self.restante() {
            return None;
        }
        let heno = self.resto();
        heno.windows(aguja.len())
            .position(|v| v == aguja)
            .map(|p| self.pos + p)
    }
}

/// Convierte bytes en texto legible, sustituyendo lo no imprimible por `.`.
///
/// Se recorta en el primer nulo porque en la practica todos los protocolos que
/// usan campos de longitud fija rellenan con nulos.
#[must_use]
pub fn ascii_legible(b: &[u8]) -> String {
    let util = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..util]
        .iter()
        .map(|&c| {
            if (0x20..0x7F).contains(&c) {
                c as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_enteros_se_leen_en_orden_de_red_por_defecto() {
        let datos = [0x12, 0x34, 0x56, 0x78];
        let mut l = Lector::nuevo(&datos);
        assert_eq!(l.u16("a").unwrap(), 0x1234);
        assert_eq!(l.u16("b").unwrap(), 0x5678);

        let mut l = Lector::nuevo(&datos);
        assert_eq!(l.u32("c").unwrap(), 0x1234_5678);

        // Y el little-endian exige pedirlo explicitamente.
        let mut l = Lector::nuevo(&datos);
        assert_eq!(l.u32_le("d").unwrap(), 0x7856_3412);
    }

    #[test]
    fn el_entero_de_24_bits_de_tls_se_lee_bien() {
        let datos = [0x00, 0x01, 0x02];
        let mut l = Lector::nuevo(&datos);
        // Agrupado por bytes, que es como se lee un entero de 24 bits de TLS.
        assert_eq!(l.u24("largo").unwrap(), 0x00_01_02);
    }

    /// LA PROPIEDAD QUE JUSTIFICA EL TIPO: ninguna lectura sale de rango, con
    /// cualquier entrada y en cualquier orden.
    #[test]
    fn ninguna_lectura_sale_de_rango_con_entrada_arbitraria() {
        let mut semilla = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..5000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 40) as usize % 64;
            let datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            let mut l = Lector::nuevo(&datos);
            // Una secuencia arbitraria de lecturas: ninguna puede entrar en
            // panico, solo devolver Ok o Err.
            let _ = l.u8("a");
            let _ = l.u16("b");
            let _ = l.u24("c");
            let _ = l.u32("d");
            let _ = l.u64("e");
            let _ = l.bloque_u8("f");
            let _ = l.bloque_u16("g");
            let _ = l.texto_ascii(17, "h");
            let _ = l.texto_utf16le(9, "i");
            let _ = l.saltar(33, "j");
            let _ = l.sub(7, "k");
            let _ = l.ir_a(usize::MAX, "l");
            let _ = l.buscar(b"AAAA");
        }
    }

    /// Una longitud que MIENTE se distingue de un truncamiento. No es
    /// cosmetica: lo primero es sospechoso, lo segundo puede ser una captura
    /// cortada, y el motor reacciona distinto.
    #[test]
    fn una_longitud_mentirosa_se_distingue_de_un_truncamiento() {
        // Declara 200 bytes y solo hay 2.
        let datos = [0x00, 0xC8, 0x01, 0x02];
        let mut l = Lector::nuevo(&datos);
        assert!(matches!(
            l.bloque_u16("carga"),
            Err(ErrorDiseccion::LongitudImposible { declarada: 200, .. })
        ));

        // Aqui simplemente no hay bytes que leer.
        let mut l = Lector::nuevo(&[]);
        assert!(matches!(
            l.u32("cabecera"),
            Err(ErrorDiseccion::Truncado { .. })
        ));
    }

    /// La sub-vista es lo que impide que un disector anidado lea mas alla de su
    /// campo aunque su longitud interna mienta.
    #[test]
    fn una_subvista_acota_al_disector_anidado() {
        let datos = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut l = Lector::nuevo(&datos);
        let mut dentro = l.sub(2, "anidado").unwrap();
        assert_eq!(dentro.restante(), 2);
        assert_eq!(dentro.u16("x").unwrap(), 0xAABB);
        // El anidado NO puede ver lo que hay despues, aunque exista.
        assert!(dentro.u8("fuera").is_err());
        // Y el de fuera sigue en su sitio.
        assert_eq!(l.restante(), 3);
    }

    #[test]
    fn el_desbordamiento_al_calcular_el_fin_no_entra_en_panico() {
        let datos = [1, 2, 3];
        let mut l = Lector::nuevo(&datos);
        l.saltar(2, "x").unwrap();
        assert!(l.tomar(usize::MAX, "enorme").is_err());
    }

    #[test]
    fn el_texto_no_imprimible_se_sustituye_en_vez_de_descartarse() {
        assert_eq!(ascii_legible(b"hola"), "hola");
        assert_eq!(ascii_legible(b"ho\x00la"), "ho");
        assert_eq!(ascii_legible(&[0x01, b'a', 0xFF, b'b']), ".a.b");
    }

    #[test]
    fn el_utf16_de_windows_se_lee_y_se_recorta_en_el_nulo() {
        // "SMB" en UTF-16LE con relleno.
        let datos = [b'S', 0, b'M', 0, b'B', 0, 0, 0];
        let mut l = Lector::nuevo(&datos);
        assert_eq!(l.texto_utf16le(8, "nombre").unwrap(), "SMB");
    }

    #[test]
    fn buscar_devuelve_un_desplazamiento_absoluto_y_no_mueve_el_cursor() {
        let datos = b"....GET /".to_vec();
        let mut l = Lector::nuevo(&datos);
        l.saltar(2, "x").unwrap();
        assert_eq!(l.buscar(b"GET"), Some(4));
        assert_eq!(l.posicion(), 2, "buscar no consume");
        assert_eq!(l.buscar(b"NOEXISTE"), None);
        assert_eq!(l.buscar(b""), None);
    }
}
