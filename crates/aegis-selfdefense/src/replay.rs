//! Anti-replay: un OTP es de un solo uso.
//!
//! Sin esto, un atacante que capture UN OTP legitimo del dueno (por ejemplo,
//! observando una desinstalacion autorizada) podria reutilizarlo para desarmar
//! el agente cuando quisiera. El registro recuerda los nonces ya vistos y
//! rechaza el segundo uso.
//!
//! No crece sin limite: un nonce solo hay que recordarlo hasta que su OTP
//! caduque —despues, la comprobacion de ventana ya lo rechaza por si sola—, asi
//! que [`RegistroOtp::purgar`] puede olvidar los ya expirados con seguridad.

use crate::TamperError;
use std::collections::HashMap;

/// Registro de nonces de OTP ya consumidos, con su instante de expiracion.
#[derive(Debug, Default)]
pub struct RegistroOtp {
    /// nonce -> instante Unix en que su OTP expira (y se puede olvidar).
    consumidos: HashMap<[u8; 32], u64>,
}

impl RegistroOtp {
    /// Crea un registro vacio.
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            consumidos: HashMap::new(),
        }
    }

    /// Consume `nonce`, cuyo OTP expira en `expira_unix`.
    ///
    /// # Errores
    /// [`TamperError::Replay`] si el nonce ya se habia consumido.
    pub fn consumir(&mut self, nonce: &[u8; 32], expira_unix: u64) -> Result<(), TamperError> {
        if self.consumidos.contains_key(nonce) {
            return Err(TamperError::Replay);
        }
        self.consumidos.insert(*nonce, expira_unix);
        Ok(())
    }

    /// Olvida los nonces cuyos OTP ya expiraron antes de `ahora_unix`.
    ///
    /// Es seguro: un OTP expirado ya lo rechaza la comprobacion de ventana antes
    /// de llegar al anti-replay, asi que olvidar su nonce no reabre nada.
    pub fn purgar(&mut self, ahora_unix: u64) {
        self.consumidos
            .retain(|_, &mut expira| expira >= ahora_unix);
    }

    /// Cuantos nonces se recuerdan ahora mismo.
    #[must_use]
    pub fn len(&self) -> usize {
        self.consumidos.len()
    }

    /// `true` si no se recuerda ninguno.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.consumidos.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_primer_uso_pasa_y_el_segundo_no() {
        let mut reg = RegistroOtp::nuevo();
        let nonce = [7u8; 32];
        assert!(reg.consumir(&nonce, 100).is_ok());
        assert_eq!(reg.consumir(&nonce, 100), Err(TamperError::Replay));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn nonces_distintos_no_colisionan() {
        let mut reg = RegistroOtp::nuevo();
        assert!(reg.consumir(&[1u8; 32], 100).is_ok());
        assert!(reg.consumir(&[2u8; 32], 100).is_ok());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn purgar_olvida_los_expirados() {
        let mut reg = RegistroOtp::nuevo();
        reg.consumir(&[1u8; 32], 100).unwrap(); // expira en 100
        reg.consumir(&[2u8; 32], 500).unwrap(); // expira en 500
        reg.purgar(300); // "ahora" = 300
        assert_eq!(
            reg.len(),
            1,
            "el que expiraba en 100 se olvida; el de 500 no"
        );
        assert!(!reg.is_empty());
    }
}
