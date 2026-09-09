//! Reproduccion de PCRs y comparacion contra el TPM.
//!
//! # La idea que hace util a todo el modulo
//!
//! Un PCR (*Platform Configuration Register*) no se escribe: se EXTIENDE.
//! Extender es `PCR_nuevo = H(PCR_viejo ‖ medida)`, y el TPM no ofrece otra
//! forma de cambiarlo. Como el hash no se puede invertir, un PCR con un valor
//! dado solo se pudo alcanzar por UNA secuencia concreta de medidas.
//!
//! El event log dice cual fue esa secuencia. Reproducirla —empezar en cero,
//! extender cada digest del log en orden— tiene que dar exactamente el valor
//! que el TPM guarda. Si no da:
//!
//!   - o el log fue manipulado (un bootkit reescribio su propia medida para que
//!     pareciera la legitima),
//!   - o hay una medida que el log no registro (algo se ejecuto sin medirse),
//!
//! y las dos cosas son un compromiso del arranque. El TPM es el testigo que no
//! miente porque no tiene la clave para mentir; el log es la version de los
//! hechos que hay que contrastar contra el.

use sha2::{Digest, Sha256};

use crate::eventlog::EventLog;
use crate::tcg::{HashAlg, NUM_PCRS};

/// Extiende un valor de PCR con una medida, en SHA-256.
///
/// `PCR_nuevo = SHA256(PCR_viejo ‖ medida)`. El PCR arranca en 24 bytes... no,
/// en 32 ceros para SHA-256: el tamano del cero es el del banco.
pub fn extend_sha256(pcr: &[u8; 32], medida: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pcr);
    h.update(medida);
    h.finalize().into()
}

/// Valores de PCR de un banco, indexados por numero de PCR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrBank {
    /// Algoritmo del banco.
    pub alg: HashAlg,
    /// Valor de cada PCR (32 bytes en SHA-256).
    pub valores: Vec<Vec<u8>>,
}

impl PcrBank {
    /// Banco recien inicializado a ceros.
    pub fn cero(alg: HashAlg) -> PcrBank {
        PcrBank {
            alg,
            valores: (0..NUM_PCRS).map(|_| vec![0u8; alg.digest_len()]).collect(),
        }
    }

    /// Valor de un PCR concreto.
    pub fn get(&self, pcr: usize) -> Option<&[u8]> {
        self.valores.get(pcr).map(|v| v.as_slice())
    }
}

/// Reproduce los PCRs de un banco SHA-256 a partir del event log.
///
/// Devuelve los 24 PCRs que resultan de extender, en orden, cada digest
/// SHA-256 del log —saltando los eventos que no extienden, como
/// `EV_NO_ACTION`—. Es el valor que el TPM DEBERIA tener si el log es fiel.
pub fn reproducir_sha256(log: &EventLog) -> PcrBank {
    let mut banco = PcrBank::cero(HashAlg::Sha256);
    for ev in &log.events {
        if !ev.event_type.extiende_pcr() {
            continue;
        }
        let Some(digest) = ev.digest(HashAlg::Sha256) else {
            // Un evento sin digest del banco pedido no se puede reproducir en
            // este banco; se salta, y la comparacion contra el TPM lo delatara
            // si de verdad extendio el registro.
            continue;
        };
        let idx = ev.pcr as usize;
        if idx >= NUM_PCRS {
            continue;
        }
        if digest.len() != 32 {
            continue;
        }
        let mut actual = [0u8; 32];
        actual.copy_from_slice(&banco.valores[idx]);
        let nuevo = extend_sha256(&actual, digest);
        banco.valores[idx] = nuevo.to_vec();
    }
    banco
}

/// Resultado de contrastar el log contra los PCRs del TPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrMatch {
    /// PCRs que coinciden entre el log reproducido y el TPM.
    pub coinciden: Vec<u32>,
    /// PCRs que NO coinciden: el arranque no es el que el log dice.
    pub discrepan: Vec<u32>,
    /// PCRs que el TPM reporta pero el log no explica (quedaron a cero en la
    /// reproduccion pese a tener valor en el TPM).
    pub no_explicados: Vec<u32>,
}

impl PcrMatch {
    /// Indica si hay alguna discrepancia, que es evidencia de manipulacion.
    pub fn hay_discrepancia(&self) -> bool {
        !self.discrepan.is_empty() || !self.no_explicados.is_empty()
    }
}

/// Contrasta los PCRs reproducidos del log contra los que reporta el TPM.
///
/// Solo se comparan los PCRs que interesan al arranque medido; pasar el
/// conjunto por parametro permite ceñirse a los criticos (0-9, 14) y no marcar
/// como discrepancia los PCRs de aplicacion que el firmware no toca.
pub fn contrastar(reproducido: &PcrBank, tpm: &PcrBank, pcrs_de_interes: &[u32]) -> PcrMatch {
    let mut coinciden = Vec::new();
    let mut discrepan = Vec::new();
    let mut no_explicados = Vec::new();

    let cero = vec![0u8; reproducido.alg.digest_len()];
    for &pcr in pcrs_de_interes {
        let i = pcr as usize;
        let (Some(r), Some(t)) = (reproducido.valores.get(i), tpm.valores.get(i)) else {
            continue;
        };
        if r == t {
            coinciden.push(pcr);
        } else if *r == cero && *t != cero {
            // El log no extendio este PCR pero el TPM lo tiene con valor: hay
            // una medida que el log no registro.
            no_explicados.push(pcr);
        } else {
            discrepan.push(pcr);
        }
    }
    PcrMatch {
        coinciden,
        discrepan,
        no_explicados,
    }
}

/// PCRs que un bootkit tiene que alterar y que por tanto interesa contrastar.
///
/// - 0-1: firmware y su configuracion.
/// - 2-3: firmware de opcion (ROMs) y su configuracion.
/// - 4-5: el gestor de arranque y la tabla de particiones. **El objetivo
///   directo de un bootkit tipo BlackLotus.**
/// - 7: la politica de Secure Boot (db, dbx, PK, KEK).
pub const PCRS_DE_ARRANQUE: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
