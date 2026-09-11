//! Capa post-cuantica del canal C2 en el agente (FASE 59).
//!
//! Sella la telemetria que sube al plano de control y abre los comandos sellados
//! que este le devuelve, usando el KEM hibrido `X25519MLKEM768` de `aegis-pqc`
//! **por encima del mTLS** que ya negocia la sesion de flota. Es defensa en
//! profundidad: aunque una computadora cuantica rompa el X25519 del tunel TLS,
//! el payload sigue protegido por ML-KEM-768, y el trafico grabado hoy no se
//! descifra manana ("Harvest Now, Decrypt Later").
//!
//! El reparto de confianza es el mismo que el de las actualizaciones: el agente
//! lleva en su configuracion la clave publica hibrida del plano de control
//! ([`PlanoControlPqc`]), y genera su propia identidad hibrida
//! ([`IdentidadPqcAgente`]) cuya clave publica registra al enrolarse, para poder
//! recibir comandos confidenciales.

use crate::error::Resultado;
use aegis_pqc::canal::{self, SobreSellado};
use aegis_pqc::kem_hibrido::{ClavePublicaHibrida, ParHibrido};

/// La clave publica hibrida del plano de control, que el agente usa para sellar
/// lo que le envia. Viaja en la configuracion de confianza del agente.
#[derive(Clone)]
pub struct PlanoControlPqc {
    pk: ClavePublicaHibrida,
}

impl PlanoControlPqc {
    /// Construye desde los bytes publicados por el plano de control.
    ///
    /// # Errores
    /// [`crate::error::FleetError::Pqc`] si los bytes no son una clave publica
    /// hibrida valida.
    pub fn desde_bytes(bytes: &[u8]) -> Resultado<Self> {
        Ok(Self {
            pk: ClavePublicaHibrida::desde_bytes(bytes)?,
        })
    }

    /// Sella `payload` hacia el plano de control, autenticando `aad` (sin
    /// cifrarlo: ahi va el tipo de mensaje, el id de agente, etc.). Devuelve el
    /// [`SobreSellado`] serializado, listo para ir dentro de la trama mTLS.
    ///
    /// # Errores
    /// [`crate::error::FleetError::Pqc`] ante un fallo de entropia o de cifrado.
    pub fn sellar(&self, aad: &[u8], payload: &[u8]) -> Resultado<Vec<u8>> {
        Ok(canal::sellar(&self.pk, aad, payload)?.a_bytes())
    }
}

/// La identidad hibrida del agente, para **recibir** comandos sellados del plano
/// de control. Su clave publica se registra al enrolarse.
pub struct IdentidadPqcAgente {
    par: ParHibrido,
}

impl IdentidadPqcAgente {
    /// Genera una identidad hibrida nueva tomando la entropia del sistema.
    ///
    /// # Errores
    /// [`crate::error::FleetError::Pqc`] si no hay entropia segura.
    pub fn generar() -> Resultado<Self> {
        Ok(Self {
            par: ParHibrido::generar_aleatorio()?,
        })
    }

    /// Los bytes de la clave publica hibrida del agente, para registrarla en el
    /// plano de control durante el enrolamiento.
    #[must_use]
    pub fn clave_publica_bytes(&self) -> Vec<u8> {
        self.par.publica.a_bytes().to_vec()
    }

    /// Abre un sobre sellado que el plano de control dirigio a este agente.
    ///
    /// # Errores
    /// [`crate::error::FleetError::Pqc`] si el sobre esta mal formado o el AEAD
    /// no autentica (manipulado, `aad` distinto o clave equivocada).
    pub fn abrir(&self, aad: &[u8], sobre_bytes: &[u8]) -> Resultado<Vec<u8>> {
        let sobre = SobreSellado::desde_bytes(sobre_bytes)?;
        Ok(canal::abrir(&self.par, aad, &sobre)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pqc::kem_hibrido::ParHibrido;

    #[test]
    fn el_agente_sella_y_el_plano_de_control_abre() {
        // El plano de control tiene su par; publica la clave publica.
        let plano = ParHibrido::generar_aleatorio().expect("entropia");
        let pcp = PlanoControlPqc::desde_bytes(&plano.publica.a_bytes()).expect("pk");

        let aad = b"agente-4820/ReportarEvento";
        let payload = b"{evento: robo de credenciales en LSASS}";
        let sobre = pcp.sellar(aad, payload).expect("sellar");

        // El plano de control abre con aegis-pqc directamente.
        let sobre_d = SobreSellado::desde_bytes(&sobre).expect("wire");
        let abierto = canal::abrir(&plano, aad, &sobre_d).expect("abrir");
        assert_eq!(abierto, payload);
    }

    #[test]
    fn el_plano_de_control_sella_un_comando_y_el_agente_lo_abre() {
        let agente = IdentidadPqcAgente::generar().expect("entropia");
        let pk_agente =
            ClavePublicaHibrida::desde_bytes(&agente.clave_publica_bytes()).expect("pk");

        let aad = b"comando/aislar";
        let comando = b"{accion: cuarentena, host: 4820}";
        let sobre = canal::sellar(&pk_agente, aad, comando)
            .expect("sellar")
            .a_bytes();

        let abierto = agente.abrir(aad, &sobre).expect("abrir");
        assert_eq!(abierto, comando);
    }

    #[test]
    fn un_sobre_manipulado_no_abre() {
        let agente = IdentidadPqcAgente::generar().expect("entropia");
        let pk_agente =
            ClavePublicaHibrida::desde_bytes(&agente.clave_publica_bytes()).expect("pk");
        let mut sobre = canal::sellar(&pk_agente, b"aad", b"comando")
            .expect("sellar")
            .a_bytes();
        let n = sobre.len();
        sobre[n - 1] ^= 0x01;
        assert!(agente.abrir(b"aad", &sobre).is_err());
    }
}
