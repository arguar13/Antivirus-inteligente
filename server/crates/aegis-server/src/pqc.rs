//! Capa post-cuantica del canal C2 en el plano de control (FASE 59).
//!
//! El plano de control guarda su **par de claves hibrido** de larga duracion
//! (`X25519MLKEM768`), publica su clave publica a la flota (por el canal firmado
//! de actualizaciones, como cualquier otro material de confianza), abre los
//! sobres sellados que suben los agentes y sella los comandos que les devuelve.
//!
//! Va **por encima del mTLS**: es defensa en profundidad contra "Harvest Now,
//! Decrypt Later". El secreto de sesion nunca toca el disco ni la base de datos;
//! solo se deriva en memoria al abrir o sellar.

use aegis_pqc::canal::{self, SobreSellado};
use aegis_pqc::kem_hibrido::{ClavePublicaHibrida, ParHibrido};
use aegis_pqc::PqcError;

/// La clave hibrida del plano de control para el canal C2 post-cuantico.
pub struct ClavePqcPlanoControl {
    par: ParHibrido,
}

impl ClavePqcPlanoControl {
    /// Genera un par hibrido nuevo tomando la entropia del sistema.
    ///
    /// En produccion se genera una vez y se persiste de forma segura (igual que
    /// la clave privada de firma de actualizaciones); aqui la API es la misma.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si el sistema no puede entregar aleatoriedad.
    pub fn generar() -> Result<Self, PqcError> {
        Ok(Self {
            par: ParHibrido::generar_aleatorio()?,
        })
    }

    /// Los bytes de la clave publica hibrida, para publicarlos a la flota.
    #[must_use]
    pub fn clave_publica_bytes(&self) -> Vec<u8> {
        self.par.publica.a_bytes().to_vec()
    }

    /// Abre un sobre sellado que subio un agente.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si el sobre esta truncado;
    /// [`PqcError::AperturaInvalida`] si el AEAD no autentica (manipulado, `aad`
    /// distinto o dirigido a otra clave).
    pub fn abrir(&self, aad: &[u8], sobre_bytes: &[u8]) -> Result<Vec<u8>, PqcError> {
        let sobre = SobreSellado::desde_bytes(sobre_bytes)?;
        canal::abrir(&self.par, aad, &sobre)
    }

    /// Sella un comando hacia un agente, dada su clave publica hibrida (la que
    /// registro al enrolarse).
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si la clave del agente no es valida;
    /// [`PqcError::Entropia`] si no hay entropia segura.
    pub fn sellar_para_agente(
        &self,
        agente_pk_bytes: &[u8],
        aad: &[u8],
        comando: &[u8],
    ) -> Result<Vec<u8>, PqcError> {
        let pk = ClavePublicaHibrida::desde_bytes(agente_pk_bytes)?;
        Ok(canal::sellar(&pk, aad, comando)?.a_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pqc::kem_hibrido::ParHibrido;

    #[test]
    fn abre_lo_que_un_agente_sella_hacia_el() {
        let plano = ClavePqcPlanoControl::generar().expect("entropia");
        // El agente sella contra la clave publica publicada.
        let pk = ClavePublicaHibrida::desde_bytes(&plano.clave_publica_bytes()).expect("pk");
        let aad = b"agente-4820/Latir";
        let payload = b"estado: sano; pid sospechoso: 0";
        let sobre = canal::sellar(&pk, aad, payload).expect("sellar").a_bytes();

        assert_eq!(plano.abrir(aad, &sobre).expect("abrir"), payload);
    }

    #[test]
    fn sella_un_comando_que_solo_el_agente_destino_abre() {
        let plano = ClavePqcPlanoControl::generar().expect("entropia");
        let agente = ParHibrido::generar_aleatorio().expect("entropia");
        let otro_agente = ParHibrido::generar_aleatorio().expect("entropia");

        let aad = b"comando/volcar-memoria";
        let comando = b"pid=1337";
        let sobre = plano
            .sellar_para_agente(&agente.publica.a_bytes(), aad, comando)
            .expect("sellar");
        let sobre_d = SobreSellado::desde_bytes(&sobre).expect("wire");

        // El agente destino lo abre.
        assert_eq!(
            canal::abrir(&agente, aad, &sobre_d).expect("abrir"),
            comando
        );
        // Otro agente NO.
        assert!(canal::abrir(&otro_agente, aad, &sobre_d).is_err());
    }

    #[test]
    fn un_sobre_truncado_o_manipulado_no_abre() {
        let plano = ClavePqcPlanoControl::generar().expect("entropia");
        let pk = ClavePublicaHibrida::desde_bytes(&plano.clave_publica_bytes()).expect("pk");
        let sobre = canal::sellar(&pk, b"aad", b"x").expect("sellar").a_bytes();

        // Truncado.
        assert!(plano.abrir(b"aad", &sobre[..sobre.len() - 1]).is_err());
        // Manipulado.
        let mut m = sobre.clone();
        let n = m.len();
        m[n - 1] ^= 0x01;
        assert!(plano.abrir(b"aad", &m).is_err());
    }
}
