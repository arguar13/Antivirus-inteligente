//! Desafio, frescura y anti-replay.
//!
//! Sin frescura, la atestacion no vale nada: un atacante graba un quote de un
//! arranque limpio y lo reproduce eternamente sobre una maquina ya comprometida,
//! y el plano de control lo acepta cada vez. El desafio lo impide: el servidor
//! manda un nonce aleatorio nuevo en cada latido, el TPM lo mete en el quote
//! (`extraData`), y el verificador exige que el quote lleve EXACTAMENTE ese
//! nonce y que no se haya visto antes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// El tamano del nonce: 32 bytes de aleatoriedad real. Mas que suficiente para
/// que no haya dos iguales ni se pueda precomputar.
pub const NONCE_LEN: usize = 32;

/// Un desafio: 32 bytes de `getrandom`, no de un PRNG sembrado. Un desafio
/// predecible es un desafio que un atacante precomputa.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Genera un nonce con aleatoriedad del sistema. Devuelve error solo si la
    /// fuente de entropia del sistema falla, en cuyo caso NO se debe emitir un
    /// desafio degradado.
    pub fn nuevo() -> Result<Nonce, getrandom::Error> {
        let mut b = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut b)?;
        Ok(Nonce(b))
    }

    /// El nonce como bytes, para meterlo en `qualifyingData` o compararlo con el
    /// `extraData` de un quote.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Registro de desafios emitidos y aun validos, para exigir frescura y rechazar
/// reproducciones. Acotado en el tiempo: un desafio caduca, y uno ya usado no se
/// vuelve a aceptar.
pub struct RegistroNonces {
    ventana: Duration,
    emitidos: HashMap<Nonce, Instant>,
}

impl RegistroNonces {
    /// Un registro con la ventana de validez dada. Un quote que responde a un
    /// desafio mas viejo que esto se rechaza aunque el nonce sea correcto.
    pub fn new(ventana: Duration) -> RegistroNonces {
        RegistroNonces {
            ventana,
            emitidos: HashMap::new(),
        }
    }

    /// Emite y registra un desafio nuevo.
    pub fn emitir(&mut self) -> Result<Nonce, getrandom::Error> {
        let n = Nonce::nuevo()?;
        self.emitidos.insert(n.clone(), Instant::now());
        Ok(n)
    }

    /// Registra un desafio ya generado (util cuando el nonce viaja por otro
    /// canal). Devuelve el mismo nonce por comodidad.
    pub fn registrar(&mut self, n: Nonce) -> Nonce {
        self.emitidos.insert(n.clone(), Instant::now());
        n
    }

    /// Consume un desafio: solo pasa si se emitio, no ha caducado, y no se habia
    /// usado ya. Un nonce valido se CONSUME —se borra— para que un segundo
    /// quote con el mismo nonce (una reproduccion) se rechace.
    pub fn consumir(&mut self, n: &Nonce) -> ResultadoNonce {
        match self.emitidos.remove(n) {
            None => ResultadoNonce::DesconocidoOReproducido,
            Some(t) => {
                if t.elapsed() > self.ventana {
                    ResultadoNonce::Caducado
                } else {
                    ResultadoNonce::Fresco
                }
            }
        }
    }

    /// Descarta los desafios caducados. Se puede llamar periodicamente para que
    /// el registro no crezca sin limite en una flota grande.
    pub fn purgar(&mut self) {
        let v = self.ventana;
        self.emitidos.retain(|_, t| t.elapsed() <= v);
    }
}

/// El resultado de consumir un desafio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultadoNonce {
    /// Emitido, vigente y no usado: el quote es fresco.
    Fresco,
    /// Se emitio pero ya paso la ventana de validez.
    Caducado,
    /// No se emitio, o ya se consumio: una reproduccion o un nonce inventado.
    DesconocidoOReproducido,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_nonces_generados_no_son_iguales() {
        let a = Nonce::nuevo().unwrap();
        let b = Nonce::nuevo().unwrap();
        assert_ne!(a, b, "getrandom no debe repetir");
    }

    #[test]
    fn un_nonce_fresco_pasa_una_sola_vez() {
        let mut reg = RegistroNonces::new(Duration::from_secs(60));
        let n = reg.emitir().unwrap();
        assert_eq!(reg.consumir(&n), ResultadoNonce::Fresco);
        // La segunda vez es una reproduccion: ya se consumio.
        assert_eq!(reg.consumir(&n), ResultadoNonce::DesconocidoOReproducido);
    }

    #[test]
    fn un_nonce_inventado_no_se_acepta() {
        let mut reg = RegistroNonces::new(Duration::from_secs(60));
        let ajeno = Nonce([0xEE; NONCE_LEN]);
        assert_eq!(
            reg.consumir(&ajeno),
            ResultadoNonce::DesconocidoOReproducido
        );
    }

    #[test]
    fn un_nonce_caducado_se_rechaza() {
        let mut reg = RegistroNonces::new(Duration::from_millis(1));
        let n = reg.emitir().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(reg.consumir(&n), ResultadoNonce::Caducado);
    }
}
