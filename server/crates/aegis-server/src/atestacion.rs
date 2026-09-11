//! Atestacion TPM 2.0 en el plano de control (FASE 49).
//!
//! El plano de control deja de creerse la palabra del endpoint. Antes de
//! aceptar telemetria de un agente o de emitirle una orden, exige un *quote*
//! fresco del TPM y lo VERIFICA con la clave de atestacion (AK) matriculada. Si
//! el quote no verifica —binario parcheado, arranque manipulado, o una
//! reproduccion de uno viejo— se invoca la Cuarentena de Enjambre de la FASE 44,
//! que ya existe: aqui NO se reescribe, se dispara.
//!
//! # La decision esta separada del wiring, a proposito
//!
//! [`decidir`] es una funcion pura: dado un reporte y la matricula del agente,
//! devuelve [`Decision`]. Es la parte que puede estar mal de forma peligrosa
//! —cuarentenar de mas apaga una maquina sana; de menos acepta telemetria
//! falsa— y se prueba con firmas REALES sin tocar la base de datos. El wiring
//! [`RegistroAtestacion::procesar`] traduce esa decision en una llamada a la
//! cuarentena y solo se ejercita de verdad con un PostgreSQL real (los tests de
//! integracion que se omiten solos si no lo hay).
//!
//! # Un agente sin TPM no se cuarentena
//!
//! Media flota puede ser microVMs sin TPM. Un agente sin matricula de
//! atestacion produce [`Decision::NoAtestado`], que NO cuarentena: es el
//! `NoAplicable` del tri-estado de `aegis-firmware`, no un fallo. Confundirlos
//! cuarentenaria a toda la flota sin TPM por algo que no es un ataque.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

use aegis_attest::identidad::ClavePublicaAk;
use aegis_attest::nonce::{Nonce, RegistroNonces, ResultadoNonce};
use aegis_attest::verificador::{verificar_quote, Entrada, Veredicto};
use aegis_firmware::HashAlg;

use crate::almacen::Almacen;
use crate::error::Resultado;

/// Motivo con el que se cuarentena a un agente que no atesta.
pub const MOTIVO_ATESTACION: &str = "atestacion-fallida";
/// Quien ordena la cuarentena automatica de atestacion.
pub const ORDENADA_POR: &str = "atestacion-automatica";

/// Lo que el plano de control guarda de un agente para poder verificarlo: su
/// clave de atestacion, el Name que la identifica, los valores dorados de PCR y
/// el hash del esquema de firma de la AK.
#[derive(Debug, Clone)]
pub struct Matricula {
    /// La clave publica de la AK del agente.
    pub ak: ClavePublicaAk,
    /// El Name de esa AK (lo que el `qualifiedSigner` del quote debe llevar).
    pub ak_name: Vec<u8>,
    /// Los valores de PCR de un arranque conocido-bueno, contra los que se
    /// contrasta. Deben mantenerse al dia por el pipeline firmado de
    /// `aegis-update`: un dorado obsoleto tras una actualizacion de firmware
    /// cuarentenaria media flota.
    pub dorados: Vec<(u32, Vec<u8>)>,
    /// El hash del esquema de firma de la AK (con el que el TPM computa el
    /// `pcrDigest`).
    pub hash_firma: HashAlg,
}

/// El reporte que el agente sube: el quote firmado, su firma, los valores de PCR
/// que presenta, y el nonce al que responde.
#[derive(Debug, Clone)]
pub struct ReporteAtestacion {
    /// Los bytes exactos del `TPMS_ATTEST` firmado por el TPM.
    pub attest_firmado: Vec<u8>,
    /// La firma sobre ellos.
    pub firma: Vec<u8>,
    /// Los valores de PCR presentados, en orden ascendente de indice.
    pub pcrs_presentados: Vec<(u32, Vec<u8>)>,
    /// El nonce del desafio al que responde este quote.
    pub nonce: Nonce,
}

/// Que hacer con un agente tras mirar su reporte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// El quote es autentico y fresco: se acepta su telemetria.
    Aceptar,
    /// El agente no tiene matricula de atestacion (p.ej. sin TPM). NO es un
    /// fallo: no se cuarentena, pero tampoco se trata como atestado.
    NoAtestado,
    /// El quote no es de fiar: hay que cuarentenar, con este motivo.
    Cuarentenar(String),
}

/// Decide que hacer con un reporte, sin tocar la base de datos ni la red.
///
/// - `matricula`: lo matriculado para este agente, o `None` si no hay TPM.
/// - `nonce_fresco`: el resultado de consumir el nonce del reporte en el
///   registro anti-replay. Se pasa ya resuelto para que esta funcion sea pura.
pub fn decidir(
    matricula: Option<&Matricula>,
    reporte: &ReporteAtestacion,
    nonce_fresco: ResultadoNonce,
) -> Decision {
    let Some(m) = matricula else {
        return Decision::NoAtestado;
    };

    // La frescura se resuelve fuera (contra el registro con estado); aqui solo
    // se actua sobre el resultado. Un nonce que no es fresco es un quote viejo
    // reproducido: se cuarentena.
    match nonce_fresco {
        ResultadoNonce::Fresco => {}
        ResultadoNonce::Caducado => {
            return Decision::Cuarentenar(format!("{MOTIVO_ATESTACION}: desafio caducado"));
        }
        ResultadoNonce::DesconocidoOReproducido => {
            return Decision::Cuarentenar(format!(
                "{MOTIVO_ATESTACION}: nonce desconocido o reproducido"
            ));
        }
    }

    let entrada = Entrada {
        attest_firmado: &reporte.attest_firmado,
        firma: &reporte.firma,
        ak: &m.ak,
        ak_name_esperado: Some(&m.ak_name),
        nonce_esperado: reporte.nonce.bytes(),
        pcrs_presentados: &reporte.pcrs_presentados,
        hash_firma: m.hash_firma,
        dorados: Some(&m.dorados),
    };

    match verificar_quote(&entrada) {
        Ok(Veredicto::Valido) => Decision::Aceptar,
        Ok(Veredicto::Fallo(motivo)) => {
            Decision::Cuarentenar(format!("{MOTIVO_ATESTACION}: {motivo}"))
        }
        // Un quote que ni siquiera parsea es tan sospechoso como uno que falla.
        Err(e) => Decision::Cuarentenar(format!("{MOTIVO_ATESTACION}: {e}")),
    }
}

/// Registro de atestacion del plano de control: la matricula por agente y el
/// registro de nonces para exigir frescura.
pub struct RegistroAtestacion {
    matriculas: RwLock<HashMap<String, Matricula>>,
    nonces: RwLock<RegistroNonces>,
}

impl RegistroAtestacion {
    /// Un registro nuevo con la ventana de validez de nonce dada.
    pub fn new(ventana_nonce: Duration) -> RegistroAtestacion {
        RegistroAtestacion {
            matriculas: RwLock::new(HashMap::new()),
            nonces: RwLock::new(RegistroNonces::new(ventana_nonce)),
        }
    }

    /// Matricula (o rematricula) a un agente.
    pub fn matricular(&self, id_agente: &str, m: Matricula) {
        self.matriculas
            .write()
            .expect("cerrojo de matriculas envenenado")
            .insert(id_agente.to_string(), m);
    }

    /// Emite un desafio nuevo para mandarselo al agente en el AckLatido.
    pub fn emitir_desafio(&self) -> Result<Nonce, getrandom::Error> {
        self.nonces
            .write()
            .expect("cerrojo de nonces envenenado")
            .emitir()
    }

    /// Procesa un reporte: consume su nonce, decide, y si hay que cuarentenar,
    /// invoca la Cuarentena de Enjambre (FASE 44). Devuelve la decision tomada.
    pub async fn procesar(
        &self,
        almacen: &Almacen,
        direccion: IpAddr,
        id_agente: &str,
        reporte: &ReporteAtestacion,
    ) -> Resultado<Decision> {
        // Consumir el nonce (con estado) antes de decidir (puro).
        let fresco = self
            .nonces
            .write()
            .expect("cerrojo de nonces envenenado")
            .consumir(&reporte.nonce);

        let decision = {
            let matriculas = self.matriculas.read().expect("cerrojo envenenado");
            decidir(matriculas.get(id_agente), reporte, fresco)
        };

        if let Decision::Cuarentenar(motivo) = &decision {
            almacen
                .poner_en_cuarentena(direccion, Some(id_agente), motivo, ORDENADA_POR, None)
                .await?;
        }
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_attest::attest::{
        Attest, QuoteInfo, SeleccionPcr, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    fn pcrs() -> Vec<(u32, Vec<u8>)> {
        (0u32..8)
            .map(|i| {
                let mut h = Sha256::new();
                h.update([i as u8; 4]);
                (i, h.finalize().to_vec())
            })
            .collect()
    }

    fn digest(pcrs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut h = Sha256::new();
        for (_, v) in pcrs {
            h.update(v);
        }
        h.finalize().to_vec()
    }

    // Construye una matricula y un reporte autentico firmado con una AK Ed25519.
    fn matricula_y_reporte(nonce: Nonce) -> (Matricula, ReporteAtestacion) {
        let sk = SigningKey::generate(&mut OsRng);
        let ak = ClavePublicaAk::Ed25519(sk.verifying_key().to_bytes());
        let pcrs = pcrs();
        let ak_name = b"ak-agente-1".to_vec();

        let attest = Attest {
            magic: TPM_GENERATED_VALUE,
            tipo: TPM_ST_ATTEST_QUOTE,
            qualified_signer: ak_name.clone(),
            extra_data: nonce.bytes().to_vec(),
            clock: 1,
            reset_count: 0,
            restart_count: 0,
            safe: 1,
            firmware_version: 1,
            quote: QuoteInfo {
                selecciones: vec![SeleccionPcr {
                    alg: HashAlg::Sha256,
                    bitmap: vec![0xFF, 0, 0],
                }],
                pcr_digest: digest(&pcrs),
            },
        };
        let bytes = attest.marshal();
        let firma = sk.sign(&bytes).to_bytes().to_vec();

        let m = Matricula {
            ak,
            ak_name,
            dorados: pcrs.clone(),
            hash_firma: HashAlg::Sha256,
        };
        let r = ReporteAtestacion {
            attest_firmado: bytes,
            firma,
            pcrs_presentados: pcrs,
            nonce,
        };
        (m, r)
    }

    #[test]
    fn un_quote_autentico_y_fresco_se_acepta() {
        let (m, r) = matricula_y_reporte(Nonce([1u8; 32]));
        assert_eq!(
            decidir(Some(&m), &r, ResultadoNonce::Fresco),
            Decision::Aceptar
        );
    }

    #[test]
    fn sin_matricula_no_se_cuarentena() {
        let (_, r) = matricula_y_reporte(Nonce([2u8; 32]));
        assert_eq!(
            decidir(None, &r, ResultadoNonce::Fresco),
            Decision::NoAtestado,
            "un agente sin TPM no es un fallo"
        );
    }

    #[test]
    fn un_nonce_reproducido_cuarentena() {
        let (m, r) = matricula_y_reporte(Nonce([3u8; 32]));
        // El nonce correcto pero ya consumido (reproduccion) -> cuarentena.
        match decidir(Some(&m), &r, ResultadoNonce::DesconocidoOReproducido) {
            Decision::Cuarentenar(_) => {}
            otra => panic!("se esperaba cuarentena, fue {otra:?}"),
        }
    }

    #[test]
    fn un_pcr_alterado_cuarentena() {
        let (m, mut r) = matricula_y_reporte(Nonce([4u8; 32]));
        // El agente presenta un PCR distinto del que firmo el TPM.
        r.pcrs_presentados[2].1[0] ^= 0xFF;
        match decidir(Some(&m), &r, ResultadoNonce::Fresco) {
            Decision::Cuarentenar(_) => {}
            otra => panic!("se esperaba cuarentena, fue {otra:?}"),
        }
    }
}
