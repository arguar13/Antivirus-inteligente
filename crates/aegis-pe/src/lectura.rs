//! Lectura acotada: la unica forma de tocar los bytes de un fichero hostil.
//!
//! # Por que existe este modulo
//!
//! Todo el trabajo de este crate es leer enteros de desplazamientos que vienen
//! DENTRO del propio fichero que se esta leyendo. Es decir: el atacante elige
//! los desplazamientos. En C eso es una lectura fuera de limites; en Rust seria
//! un panico, que en un agente con `panic = "abort"` es el proceso entero
//! muriendose —y un EDR que se puede matar mandandole un fichero es un EDR que
//! se desinstala solo—.
//!
//! Aqui no hay indexacion cruda en ningun sitio. Toda lectura pasa por
//! [`Lector`], que comprueba el limite y devuelve un error **con nombre** en vez
//! de entrar en panico. No es prudencia: es que el fichero que dispara el caso
//! raro llega el martes, sin avisar, y el caso raro es el que el atacante
//! escogio.
//!
//! La aritmetica tambien va acotada. `offset + tamano` con dos valores de 32
//! bits que el fichero declara desborda con facilidad, y un desbordamiento
//! silencioso convierte «apunta 4 GiB mas alla» en «apunta al principio»: la
//! comprobacion de limites pasaria y la lectura seria de otro sitio.

use crate::error::PeError;

/// Una vista de solo lectura sobre los bytes de un fichero, con limites.
#[derive(Debug, Clone, Copy)]
pub struct Lector<'a> {
    bytes: &'a [u8],
}

impl<'a> Lector<'a> {
    /// Envuelve unos bytes.
    pub fn nuevo(bytes: &'a [u8]) -> Lector<'a> {
        Lector { bytes }
    }

    /// Tamano total del fichero.
    pub fn tamano(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Los bytes enteros, para quien necesite recorrerlos de una vez.
    pub fn todos(&self) -> &'a [u8] {
        self.bytes
    }

    /// Un tramo, comprobando el limite.
    pub fn tramo(&self, desde: u64, largo: u64, que: &'static str) -> Result<&'a [u8], PeError> {
        let fin = desde.checked_add(largo).ok_or(PeError::SeAcabaElFichero {
            que,
            desde,
            necesita: largo,
            hay: self.tamano().saturating_sub(desde),
        })?;
        if fin > self.tamano() {
            return Err(PeError::SeAcabaElFichero {
                que,
                desde,
                necesita: largo,
                hay: self.tamano().saturating_sub(desde),
            });
        }
        // Los dos extremos caben en usize porque ya se comprobo que no pasan del
        // tamano del propio slice.
        Ok(&self.bytes[desde as usize..fin as usize])
    }

    /// Un `u8`.
    pub fn u8(&self, desde: u64, que: &'static str) -> Result<u8, PeError> {
        Ok(self.tramo(desde, 1, que)?[0])
    }

    /// Un `u16` en orden de byte nativo de PE, que es little-endian siempre.
    pub fn u16(&self, desde: u64, que: &'static str) -> Result<u16, PeError> {
        let t = self.tramo(desde, 2, que)?;
        Ok(u16::from_le_bytes([t[0], t[1]]))
    }

    /// Un `u32` little-endian.
    pub fn u32(&self, desde: u64, que: &'static str) -> Result<u32, PeError> {
        let t = self.tramo(desde, 4, que)?;
        Ok(u32::from_le_bytes([t[0], t[1], t[2], t[3]]))
    }

    /// Un `u64` little-endian.
    pub fn u64(&self, desde: u64, que: &'static str) -> Result<u64, PeError> {
        let t = self.tramo(desde, 8, que)?;
        Ok(u64::from_le_bytes([
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
        ]))
    }

    /// Indica si `desde + largo` cabe en el fichero, sin leerlo.
    ///
    /// Se usa para validar un campo antes de decidir si vale la pena seguir, y
    /// va por aritmetica acotada: `u32 + u32` desborda, y un desbordamiento
    /// silencioso haria pasar por «dentro del fichero» algo que apunta a 4 GiB
    /// de distancia.
    pub fn cabe(&self, desde: u64, largo: u64) -> bool {
        match desde.checked_add(largo) {
            Some(fin) => fin <= self.tamano(),
            None => false,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn leer_pasado_el_final_da_error_y_no_panico() {
        let l = Lector::nuevo(&[1, 2, 3]);
        let e = l.u32(0, "prueba").unwrap_err();
        assert!(matches!(
            e,
            PeError::SeAcabaElFichero {
                necesita: 4,
                hay: 3,
                ..
            }
        ));
    }

    #[test]
    fn leer_justo_hasta_el_final_funciona() {
        let l = Lector::nuevo(&[1, 2, 3, 4]);
        assert_eq!(l.u32(0, "prueba").unwrap(), 0x0403_0201);
    }

    #[test]
    fn un_desplazamiento_que_desborda_la_suma_no_pasa_por_dentro_del_fichero() {
        // El caso que un `desde + largo` sin acotar convertiria en «cabe»: la
        // suma da la vuelta y el resultado es pequeno.
        let l = Lector::nuevo(&[0u8; 16]);
        assert!(!l.cabe(u64::MAX, 32), "no puede caber: la suma desborda");
        assert!(l.tramo(u64::MAX, 32, "prueba").is_err());
    }

    #[test]
    fn un_desplazamiento_mas_alla_del_final_no_cabe() {
        let l = Lector::nuevo(&[0u8; 16]);
        assert!(!l.cabe(17, 1));
        assert!(l.cabe(16, 0), "longitud cero justo al final si cabe");
        assert!(l.cabe(0, 16));
    }

    #[test]
    fn los_enteros_se_leen_en_little_endian() {
        // PE es little-endian en todas las arquitecturas, tambien en las que
        // fueron big-endian: leerlo en orden nativo es un fallo que no se ve en
        // x86 y aparece al portar.
        let l = Lector::nuevo(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(l.u16(0, "t").unwrap(), 0x0201);
        assert_eq!(l.u32(0, "t").unwrap(), 0x0403_0201);
        assert_eq!(l.u64(0, "t").unwrap(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn un_fichero_vacio_no_deja_leer_nada_pero_tampoco_revienta() {
        let l = Lector::nuevo(&[]);
        assert_eq!(l.tamano(), 0);
        assert!(l.u8(0, "t").is_err());
        assert!(l.tramo(0, 0, "t").is_ok(), "el tramo vacio es valido");
    }
}
