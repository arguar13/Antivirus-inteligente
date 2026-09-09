//! Cifrado autenticado de los mensajes de la malla.
//!
//! # Por que AES-256-GCM con clave compartida
//!
//! La malla protege un secreto de vida corta —que este equipo acaba de ver este
//! hash— entre maquinas de la MISMA red y la MISMA organizacion. Una infraestructura
//! de clave publica por nodo daria autenticacion individual, pero exige
//! distribucion de certificados, revocacion y rotacion: meses de trabajo
//! operativo para un canal cuyo peor caso es que se filtre un indicador.
//!
//! Lo que si es innegociable es que **un tercero no pueda inyectar vacunas**, y
//! eso lo da un AEAD con clave compartida. Lo que NO da es autenticacion
//! individual: cualquier miembro puede hacerse pasar por otro. Por eso una
//! vacuna solo puede anadir indicadores, nunca retirarlos —ver
//! [`crate::vaccine`]—, y por eso la identidad del emisor sirve para trazar, no
//! para autorizar.
//!
//! # La disciplina de nonce
//!
//! Repetir un nonce con la misma clave en GCM no filtra "un poco": permite
//! recuperar la clave de autenticacion y falsificar mensajes a voluntad. Aqui el
//! nonce es `sesion (8 bytes aleatorios del arranque) ‖ contador (4 bytes)`:
//!
//! - Dentro de una sesion, el contador no se repite jamas, y al agotarse se
//!   devuelve un error en vez de dar la vuelta.
//! - Entre arranques, la sesion es nueva y aleatoria, asi que un agente que se
//!   reinicia no reutiliza los nonces que ya gasto. Un contador persistido en
//!   disco habria sido peor: un rollback del fichero repetiria nonces.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::error::MeshError;

/// Sella un mensaje.
///
/// `aad` son los bytes de la cabecera en claro: quedan autenticados sin cifrar,
/// de modo que cambiar el remitente o el tipo de un mensaje valido lo invalida.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plano: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plano, aad })
        .map_err(|_| MeshError::Crypto("el sellado fallo"))
}

/// Abre un mensaje sellado.
///
/// Un fallo aqui es indistinguible entre "clave equivocada", "mensaje
/// manipulado" y "basura": eso es exactamente lo que se quiere, porque
/// distinguirlos daria a un atacante un oraculo con el que afinar.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    sellado: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sellado, aad })
        .map_err(|_| MeshError::Crypto("el mensaje no es autentico"))
}

/// Rellena un buffer con aleatoriedad del sistema.
///
/// Se pide al kernel: una semilla derivada del reloj seria adivinable, y con
/// ella un atacante podria predecir la sesion de un agente que acaba de arrancar
/// y provocar una repeticion de nonce.
pub fn aleatorio(buf: &mut [u8]) {
    // SAFETY: se escribe exactamente en el buffer indicado y con su longitud.
    let n = unsafe {
        libc::getrandom(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0 as libc::c_uint,
        )
    };
    if n == buf.len() as isize {
        return;
    }
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(buf);
    }
}

/// Ventana deslizante contra repeticiones.
///
/// Un atacante que capture un datagrama valido puede reenviarlo mil veces. El
/// AEAD no lo impide —el mensaje ES autentico—, asi que hace falta recordar lo
/// ya visto. Se recuerda con una ventana y no con un conjunto: guardar todos los
/// contadores vistos de todos los pares es memoria sin cota, que es justo lo que
/// un atacante provocaria.
#[derive(Debug, Clone, Copy)]
pub struct ReplayWindow {
    mayor: u32,
    mapa: u64,
    vacia: bool,
}

/// Anchura de la ventana, en mensajes.
pub const ANCHURA: u32 = 64;

impl ReplayWindow {
    /// Crea una ventana vacia.
    pub fn new() -> ReplayWindow {
        ReplayWindow {
            mayor: 0,
            mapa: 0,
            vacia: true,
        }
    }

    /// Acepta un contador y lo marca. Devuelve `false` si es repetido o
    /// demasiado viejo.
    pub fn accept(&mut self, contador: u32) -> bool {
        if self.vacia {
            self.vacia = false;
            self.mayor = contador;
            self.mapa = 1;
            return true;
        }
        if contador > self.mayor {
            let salto = contador - self.mayor;
            self.mapa = if salto >= 64 {
                1
            } else {
                (self.mapa << salto) | 1
            };
            self.mayor = contador;
            return true;
        }
        let atras = self.mayor - contador;
        if atras >= ANCHURA {
            // Demasiado viejo para poder afirmar que no se vio: se rechaza. Es
            // preferible perder un mensaje muy retrasado a aceptar una
            // repeticion.
            return false;
        }
        let bit = 1u64 << atras;
        if self.mapa & bit != 0 {
            return false;
        }
        self.mapa |= bit;
        true
    }

    /// Mayor contador aceptado.
    pub fn highest(&self) -> u32 {
        self.mayor
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow::new()
    }
}
