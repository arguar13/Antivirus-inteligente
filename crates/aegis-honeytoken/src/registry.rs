//! Registro de honey-tokens sembrados.
//!
//! Mapea cada marcador a su atribucion, para que cuando un marcador reaparezca
//! —en un volcado de memoria, en una ruta de fichero abierta— se pueda decir de
//! inmediato que senuelo se toco y donde estaba. Tambien permite escanear un
//! bloque de bytes buscando CUALQUIER marcador conocido, que es como se detecta
//! que un atacante ha leido un token de la memoria de un proceso.
//!
//! # El escaneo, y por que no puede ser el bucle obvio
//!
//! La primera version recorria el bloque entero **una vez por token**: con diez
//! mil tokens sembrados y un volcado de cuatro megabytes son cuarenta gigabytes
//! de comparaciones. Y las dos magnitudes las mueve el atacante: siembra el
//! producto tantos tokens como superficies tenga, y el tamano del volcado lo
//! decide quien lee la memoria. Un detector que se hace mas caro cuanto mas grande
//! es lo que hay que mirar es un amplificador — la misma forma de fallo que el
//! redactor de la FASE 90, y se para igual.
//!
//! Aqui se recorre el bloque **una sola vez**, con un prefiltro de dos bytes sobre
//! el principio del hex de cada marcador. El coste deja de depender de cuantos
//! tokens hay sembrados.
//!
//! # Y por que el orden del resultado importa
//!
//! La version anterior iteraba un `HashMap`, asi que los hallazgos salian en
//! orden distinto en cada ejecucion. Dos analistas mirando el mismo volcado veian
//! dos listas distintas, y una alerta que no se puede reproducir no se puede
//! discutir. Aqui salen **en el orden en que aparecen en los datos**, que ademas
//! es el orden en que se escribieron.

use crate::destino::Destino;
use crate::token::{Atribucion, Marcador};
use std::collections::HashMap;

/// Cuantos caracteres ocupa el hex de un marcador.
const LARGO_HEX: usize = 32;

/// El registro de tokens vivos.
///
/// # Por que el destino se consulta aqui y no en una tabla aparte
///
/// Porque dos tablas que dicen lo mismo acaban diciendo cosas distintas. La
/// version anterior llevaba un `HashMap<ruta, Atribucion>` al lado del registro
/// para resolver la apertura de un honey-file, y una ruta que estuviera en una y
/// no en la otra era o una alerta que no salta o una que no se puede atribuir.
/// Con el indice por destino aqui dentro, **el registro es la unica fuente**.
pub struct Registro {
    por_marcador: HashMap<[u8; LARGO_HEX], Atribucion>,
    /// Del sitio donde se sembro al marcador que le corresponde.
    por_destino: HashMap<Vec<u8>, [u8; LARGO_HEX]>,
    /// Que parejas de bytes pueden empezar el hex de un marcador registrado.
    ///
    /// 65536 posibles en 8 KiB. Es lo que hace que una posicion que no puede ser
    /// el principio de ningun marcador se descarte con una consulta a un bit, sin
    /// mirar ni un token.
    parejas: Box<[u64; 1024]>,
}

impl Default for Registro {
    fn default() -> Registro {
        Registro::new()
    }
}

impl Registro {
    /// Un registro vacio.
    #[must_use]
    pub fn new() -> Registro {
        Registro {
            por_marcador: HashMap::new(),
            por_destino: HashMap::new(),
            parejas: Box::new([0u64; 1024]),
        }
    }

    /// Registra un token sembrado.
    pub fn registrar(&mut self, marcador: &Marcador, atrib: Atribucion) {
        let hex = clave(marcador);
        let c = u16::from(hex[0]) << 8 | u16::from(hex[1]);
        self.parejas[c as usize / 64] |= 1u64 << (c % 64);
        self.por_destino.insert(atrib.destino.bytes(), hex);
        self.por_marcador.insert(hex, atrib);
    }

    /// Que token se sembro en un sitio, si se sembro alguno.
    ///
    /// Es lo que convierte «alguien abrio este fichero» en un disparo atribuible
    /// con su marcador de verdad. Antes se fabricaba un marcador de ceros para
    /// rellenar el hueco, que es lo mismo que no tener marcador y ademas colisiona
    /// con cualquier otro relleno.
    #[must_use]
    pub fn en_destino(&self, destino: &Destino) -> Option<(Marcador, &Atribucion)> {
        let hex = self.por_destino.get(&destino.bytes())?;
        let atrib = self.por_marcador.get(hex)?;
        let m = Marcador::desde_hex(std::str::from_utf8(hex).ok()?)?;
        Some((m, atrib))
    }

    /// Cuantos tokens hay sembrados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.por_marcador.len()
    }

    /// `true` si no hay tokens.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.por_marcador.is_empty()
    }

    /// Busca la atribucion de un marcador concreto.
    #[must_use]
    pub fn atribucion(&self, marcador: &Marcador) -> Option<&Atribucion> {
        self.por_marcador.get(&clave(marcador))
    }

    /// Si esta pareja de bytes puede empezar el hex de algun marcador.
    #[inline]
    fn pareja_posible(&self, a: u8, b: u8) -> bool {
        let c = u16::from(a) << 8 | u16::from(b);
        self.parejas[c as usize / 64] & (1u64 << (c % 64)) != 0
    }

    /// Escanea un bloque de bytes buscando el hex de cualquier marcador
    /// registrado.
    ///
    /// Devuelve todos los que aparezcan —un volcado de memoria puede contener
    /// varios—, **en el orden en que aparecen** y sin repetir uno que salga dos
    /// veces. Es como se detecta que el token se filtro.
    ///
    /// El coste es una pasada por `datos`, independiente de cuantos tokens haya
    /// sembrados. Ver la cabecera del modulo.
    #[must_use]
    pub fn buscar_en(&self, datos: &[u8]) -> Vec<(Marcador, Atribucion)> {
        if self.por_marcador.is_empty() || datos.len() < LARGO_HEX {
            return Vec::new();
        }
        let mut encontrados: Vec<(Marcador, Atribucion)> = Vec::new();
        let mut vistos: Vec<[u8; LARGO_HEX]> = Vec::new();
        let tope = datos.len() - LARGO_HEX;
        let mut i = 0usize;
        while i <= tope {
            if !self.pareja_posible(datos[i], datos[i + 1]) {
                i += 1;
                continue;
            }
            let mut hex = [0u8; LARGO_HEX];
            hex.copy_from_slice(&datos[i..i + LARGO_HEX]);
            if let Some(atrib) = self.por_marcador.get(&hex) {
                if !vistos.contains(&hex) {
                    vistos.push(hex);
                    if let Some(m) = Marcador::desde_hex(std::str::from_utf8(&hex).unwrap_or("")) {
                        encontrados.push((m, atrib.clone()));
                    }
                }
                // Un marcador no se solapa consigo mismo: se sigue por detras.
                i += LARGO_HEX;
                continue;
            }
            i += 1;
        }
        encontrados
    }
}

/// El hex del marcador como bytes, que es la forma en la que aparece sembrado.
fn clave(m: &Marcador) -> [u8; LARGO_HEX] {
    let mut k = [0u8; LARGO_HEX];
    k.copy_from_slice(m.hex().as_bytes());
    k
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::token::Acunador;

    fn registro(n: u32) -> (Registro, Acunador) {
        let a = Acunador::new([0x5a; 32]);
        let mut r = Registro::new();
        for i in 0..n {
            let atrib = Atribucion::en_fichero("host", &format!("/etc/s{i}"), i);
            r.registrar(&a.acunar(&atrib), atrib);
        }
        (r, a)
    }

    #[test]
    fn encuentra_lo_sembrado_y_no_lo_que_no_esta() {
        let (r, a) = registro(50);
        let buscado = Atribucion::en_fichero("host", "/etc/s7", 7);
        let m = a.acunar(&buscado);
        let datos = format!("basura previa {} basura posterior", m.hex()).into_bytes();
        let h = r.buscar_en(&datos);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].1, buscado);

        // Un marcador con el secreto de otro no esta registrado y no dispara.
        let otro = Acunador::new([0x01; 32]);
        let falso = otro.acunar(&buscado);
        let datos = falso.hex().into_bytes();
        assert!(r.buscar_en(&datos).is_empty());
    }

    #[test]
    fn el_mismo_marcador_dos_veces_es_un_solo_hallazgo() {
        let (r, a) = registro(10);
        let atrib = Atribucion::en_fichero("host", "/etc/s3", 3);
        let m = a.acunar(&atrib).hex();
        let datos = format!("{m} y otra vez {m}").into_bytes();
        assert_eq!(r.buscar_en(&datos).len(), 1);
    }

    #[test]
    fn los_hallazgos_salen_en_el_orden_en_que_aparecen() {
        // Con un `HashMap` iterado, este orden cambiaba en cada ejecucion y dos
        // analistas veian dos listas distintas del mismo volcado.
        let (r, a) = registro(200);
        let ids = [11u32, 3, 190, 47];
        let mut datos = Vec::new();
        for i in ids {
            let atrib = Atribucion::en_fichero("host", &format!("/etc/s{i}"), i);
            datos.extend_from_slice(a.acunar(&atrib).hex().as_bytes());
            datos.extend_from_slice(b"  relleno  ");
        }
        let h = r.buscar_en(&datos);
        let salida: Vec<u32> = h.iter().map(|(_, at)| at.token_id).collect();
        assert_eq!(salida, ids.to_vec());
    }

    #[test]
    fn un_bloque_mas_corto_que_un_marcador_no_se_sale_de_rango() {
        let (r, _) = registro(5);
        for n in 0..LARGO_HEX {
            assert!(r.buscar_en(&vec![b'a'; n]).is_empty());
        }
    }

    #[test]
    fn el_registro_vacio_no_encuentra_nada() {
        let r = Registro::new();
        assert!(r
            .buscar_en(b"cualquier cosa, incluso 0123456789abcdef")
            .is_empty());
    }
}
