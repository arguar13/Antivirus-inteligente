//! Codificacion canonica: los bytes exactos sobre los que se firma.
//!
//! # Por que no se firma el JSON
//!
//! La tentacion es firmar `serde_json::to_vec(&estructura)` y acabar antes. No
//! funciona, y falla tarde: un ano despues, cuando alguien intenta reverificar
//! la evidencia con otra version del binario y la firma no cuadra.
//!
//! JSON no tiene una forma canonica. El orden de las claves depende del tipo de
//! mapa, el escapado de caracteres no ASCII admite varias formas validas, los
//! flotantes se imprimen distinto segun la biblioteca, y un campo `Option` puede
//! serializarse como ausente o como `null`. Nada de eso cambia el SIGNIFICADO
//! del documento, y todo cambia sus BYTES —que es lo unico que ve una firma—.
//!
//! Aqui los bytes los define este modulo y no una biblioteca de serializacion:
//!
//! - Cada campo va precedido de su longitud en cuatro bytes, big-endian. Sin la
//!   longitud, `("ab", "c")` y `("a", "bc")` producen el mismo flujo de bytes y
//!   por tanto la misma firma: un atacante podria mover el limite entre dos
//!   campos sin invalidarla.
//! - Los enteros van en anchura fija y big-endian, no en decimal.
//! - El orden de los campos lo fija el codigo que codifica, no un mapa.
//! - No hay campos opcionales implicitos: un ausente se codifica como tal.
//!
//! El resultado es que dos compilaciones distintas, en dos maquinas distintas,
//! separadas por anos, producen el mismo byte string para la misma evidencia.
//! Que es exactamente lo que hay que poder afirmar delante de quien discuta la
//! prueba.

use sha2::{Digest, Sha256};

/// Longitud de un resumen SHA-256.
pub const RESUMEN_LEN: usize = 32;

/// Resumen SHA-256 de unos bytes canonicos.
pub type Resumen = [u8; RESUMEN_LEN];

/// Acumulador de bytes canonicos.
///
/// Se usa siempre igual: se crea con la etiqueta del tipo de documento, se le
/// van anadiendo campos EN UN ORDEN FIJO, y se cierra con [`Codificador::fin`]
/// o [`Codificador::resumen`].
///
/// La etiqueta inicial separa dominios: un sello y un eslabon de custodia nunca
/// producen los mismos bytes aunque llevaran los mismos campos, asi que la firma
/// de uno no puede presentarse como la del otro.
#[derive(Debug, Clone)]
pub struct Codificador {
    bytes: Vec<u8>,
}

impl Codificador {
    /// Abre una codificacion para un tipo de documento.
    pub fn nuevo(etiqueta: &str) -> Self {
        let mut c = Codificador { bytes: Vec::new() };
        c.texto(etiqueta);
        c
    }

    /// Anade un campo de bytes, precedido de su longitud.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        // La longitud se acota a u32 a proposito: cuatro bytes bastan para
        // cualquier campo de esta evidencia y dejan la codificacion fija. Un
        // campo mayor que 4 GiB no es un campo, es un fichero, y va por su
        // resumen.
        let n = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&n.to_be_bytes());
        self.bytes.extend_from_slice(&v[..n as usize]);
        self
    }

    /// Anade una cadena de texto.
    pub fn texto(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// Anade un entero de 64 bits.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Anade un entero de 32 bits.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Anade un octeto.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    /// Anade un resumen de 32 bytes, sin prefijo: su longitud es fija.
    pub fn resumen_de(&mut self, v: &Resumen) -> &mut Self {
        self.bytes.extend_from_slice(v);
        self
    }

    /// Anade un campo que puede faltar.
    ///
    /// Presente y ausente se distinguen por un octeto delante, no por la
    /// longitud: sin el, un campo presente y vacio y un campo ausente se
    /// codificarian igual, y son cosas distintas. En evidencia forense esa
    /// diferencia es justo la que importa —«el binario tenia hash vacio» y «el
    /// binario ya no estaba en disco» son dos hechos muy distintos—.
    pub fn texto_opcional(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            Some(s) => {
                self.u8(1);
                self.texto(s)
            }
            None => self.u8(0),
        }
    }

    /// Anade una lista de textos: primero cuantos, luego cada uno.
    pub fn lista(&mut self, v: &[String]) -> &mut Self {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        for s in v {
            self.texto(s);
        }
        self
    }

    /// Cierra y devuelve los bytes.
    pub fn fin(self) -> Vec<u8> {
        self.bytes
    }

    /// Cierra y devuelve el resumen SHA-256 de los bytes.
    pub fn resumen(self) -> Resumen {
        resumir(&self.bytes)
    }
}

/// Resumen SHA-256 de unos bytes cualesquiera.
pub fn resumir(bytes: &[u8]) -> Resumen {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Representacion hexadecimal en minusculas de un resumen.
///
/// Solo para mostrarlo y para cotejarlo a ojo con la salida de `sha256sum`. La
/// verificacion compara los bytes, nunca la cadena.
pub fn hex(r: &Resumen) -> String {
    let mut s = String::with_capacity(RESUMEN_LEN * 2);
    for b in r {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_longitud_delante_impide_mover_el_limite_entre_campos() {
        // Sin prefijo de longitud los dos pares producirian el mismo flujo de
        // bytes, y una firma sobre el primero valdria para el segundo: se podria
        // mover el limite entre dos campos sin invalidar nada.
        let mut a = Codificador::nuevo("t");
        a.texto("ab").texto("c");
        let mut b = Codificador::nuevo("t");
        b.texto("a").texto("bc");
        assert_ne!(a.fin(), b.fin());
    }

    #[test]
    fn la_etiqueta_separa_dominios() {
        let mut a = Codificador::nuevo("sello");
        a.texto("x");
        let mut b = Codificador::nuevo("eslabon");
        b.texto("x");
        assert_ne!(
            a.resumen(),
            b.resumen(),
            "dos documentos de tipo distinto con el mismo contenido no pueden \
             compartir bytes: la firma de uno valdria para el otro"
        );
    }

    #[test]
    fn ausente_y_presente_vacio_no_se_codifican_igual() {
        let mut a = Codificador::nuevo("t");
        a.texto_opcional(None);
        let mut b = Codificador::nuevo("t");
        b.texto_opcional(Some(""));
        assert_ne!(
            a.fin(),
            b.fin(),
            "«no habia binario» y «el binario tenia nombre vacio» son dos \
             hechos distintos y no pueden firmar igual"
        );
    }

    #[test]
    fn la_codificacion_es_estable_entre_llamadas() {
        // La propiedad que sostiene toda la reverificacion: los mismos datos
        // producen los mismos bytes, siempre.
        let construir = || {
            let mut c = Codificador::nuevo("sello");
            c.texto("endpoint-7")
                .u64(1_700_000_000)
                .lista(&["a".into(), "b".into()])
                .texto_opcional(Some("/usr/bin/curl"));
            c.fin()
        };
        assert_eq!(construir(), construir());
    }

    #[test]
    fn el_hexadecimal_coincide_con_sha256sum() {
        // Vector conocido: SHA-256 de la cadena vacia.
        assert_eq!(
            hex(&resumir(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn una_lista_de_otra_longitud_cambia_los_bytes() {
        let mut a = Codificador::nuevo("t");
        a.lista(&["a".into()]);
        let mut b = Codificador::nuevo("t");
        b.lista(&["a".into(), "".into()]);
        assert_ne!(a.fin(), b.fin());
    }
}
