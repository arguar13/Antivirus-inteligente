//! Acunacion de marcadores atribuibles.
//!
//! El marcador es lo que hace util a un honey-token: un identificador que se
//! embebe en la credencial senuelo y que, cuando reaparece, dice EXACTAMENTE que
//! token se toco y donde estaba sembrado. Se deriva con HMAC-SHA256 de un secreto
//! de flota, asi que:
//!
//! - es unico por (host, proceso, id): dos senuelos nunca colisionan;
//! - es INFALSIFICABLE sin el secreto: un atacante no puede sembrar un
//!   honey-token propio que dispare una atribucion falsa y nos mande a perseguir
//!   fantasmas;
//! - no revela nada: es la salida de un HMAC, indistinguible de aleatorio.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::destino::Destino;

type HmacSha256 = Hmac<Sha256>;

/// A quien, a que y **a donde** se ata un honey-token.
///
/// # Por que el destino va dentro y no en una tabla al lado
///
/// Porque una tabla al lado se desincroniza, se pierde con la maquina y se la
/// lleva por delante el atacante que borre registros. Metiendo el destino en el
/// computo del marcador, la credencial sembrada en `/root/.pgpass` y la sembrada
/// en la fila 7 de `clientes` son credenciales **distintas**: cuando una aparece,
/// el sitio del que salio esta dentro de ella y no hace falta consultar nada.
///
/// Es lo que convierte «te han robado una credencial» —que no sirve de mucho— en
/// «te han robado la que estaba en este sitio», que es por donde se empieza a
/// tirar del hilo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atribucion {
    /// El host donde se sembro.
    pub host: String,
    /// **Donde** se coloco. Ver [`Destino`].
    pub destino: Destino,
    /// Identificador del token dentro de ese host y ese destino.
    pub token_id: u32,
}

impl Atribucion {
    /// Un token sembrado en la memoria de un proceso.
    #[must_use]
    pub fn en_memoria(host: &str, proceso: &str, token_id: u32) -> Atribucion {
        Atribucion {
            host: host.to_owned(),
            destino: Destino::Memoria {
                proceso: proceso.to_owned(),
            },
            token_id,
        }
    }

    /// Un token sembrado en un fichero.
    #[must_use]
    pub fn en_fichero(host: &str, ruta: &str, token_id: u32) -> Atribucion {
        Atribucion {
            host: host.to_owned(),
            destino: Destino::Fichero {
                ruta: ruta.to_owned(),
            },
            token_id,
        }
    }

    /// Como se lee en una alerta: de que maquina y de que sitio salio.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "el senuelo {} de {}, sembrado en {}",
            self.token_id,
            self.host,
            self.destino.frase()
        )
    }

    /// Los bytes canonicos sobre los que se computa el HMAC. Los campos van
    /// separados por un byte nulo para que ("a","bc") y ("ab","c") no colisionen,
    /// y el destino aporta los suyos ya etiquetados por clase.
    fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.host.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.destino.bytes());
        v.push(0);
        v.extend_from_slice(&self.token_id.to_be_bytes());
        v
    }
}

/// El marcador embebible: 16 bytes, presentado en hex (32 caracteres). Cabe en el
/// comentario de una clave SSH, en un campo XML, en un usuario de `.pgpass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marcador(pub [u8; 16]);

impl Marcador {
    /// El marcador en hexadecimal, para embeberlo en texto.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parsea un marcador desde su hex. `None` si no son 32 hex validos.
    pub fn desde_hex(s: &str) -> Option<Marcador> {
        if s.len() != 32 {
            return None;
        }
        let mut b = [0u8; 16];
        for (i, par) in s.as_bytes().chunks(2).enumerate() {
            let par = std::str::from_utf8(par).ok()?;
            b[i] = u8::from_str_radix(par, 16).ok()?;
        }
        Some(Marcador(b))
    }
}

/// Acuna y verifica marcadores con el secreto de flota.
pub struct Acunador {
    secreto: [u8; 32],
}

impl Drop for Acunador {
    fn drop(&mut self) {
        self.secreto.zeroize();
    }
}

impl Acunador {
    /// Un acunador con el secreto de flota dado. El secreto se borra de memoria
    /// al soltar el acunador.
    pub fn new(secreto: [u8; 32]) -> Acunador {
        Acunador { secreto }
    }

    /// Deriva el marcador de una atribucion. Determinista: el mismo (secreto,
    /// atribucion) da siempre el mismo marcador.
    pub fn acunar(&self, atrib: &Atribucion) -> Marcador {
        let mut mac =
            HmacSha256::new_from_slice(&self.secreto).expect("HMAC acepta cualquier clave");
        mac.update(&atrib.bytes());
        let full = mac.finalize().into_bytes();
        let mut m = [0u8; 16];
        m.copy_from_slice(&full[..16]);
        Marcador(m)
    }

    /// Verifica que un marcador es el autentico de una atribucion. Comparacion en
    /// tiempo constante via el propio `verify` del HMAC: un atacante no aprende
    /// nada midiendo cuanto tarda.
    pub fn verificar(&self, atrib: &Atribucion, marcador: &Marcador) -> bool {
        let esperado = self.acunar(atrib);
        // Los 16 bytes se comparan sin ramificar por byte.
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= esperado.0[i] ^ marcador.0[i];
        }
        diff == 0
    }
}
