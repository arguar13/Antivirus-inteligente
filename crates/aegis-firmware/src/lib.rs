//! # aegis-firmware
//!
//! Escaner de integridad de firmware: erradica las amenazas que operan por
//! debajo del sistema operativo.
//!
//! Un bootkit tipo **BlackLotus** se ejecuta ANTES que el kernel: cuando el
//! agente arranca, el compromiso ya esta en marcha y el sistema entero, incluido
//! el propio EDR, corre sobre una base manipulada. No se puede detectar
//! preguntandole al sistema, porque el sistema es lo comprometido. Se detecta
//! mirando lo que quedo grabado ANTES de que el bootkit tuviera control: el
//! estado del hardware de arranque.
//!
//! Tres piezas independientes, y cada una tapa el punto ciego de las otras:
//!
//! - **TPM 2.0 y arranque medido** ([`tpm`], [`eventlog`], [`pcr`]). El firmware
//!   mide cada componente antes de ejecutarlo y extiende la medida en un PCR del
//!   TPM. El PCR no se puede falsificar sin la clave del TPM, asi que reproducir
//!   el event log y contrastarlo contra el PCR real delata cualquier alteracion
//!   del gestor de arranque.
//! - **Secure Boot** ([`uefi`]). Comprueba que el firmware IMPONE la validacion
//!   de firmas de verdad —`SecureBoot=1` y `SetupMode=0`, no una sola de las
//!   dos—.
//! - **Revocacion UEFI (DBX)** ([`uefi`]). La lista de gestores de arranque que
//!   se sabe comprometidos. Comprobar si el binario arrancado esta en ella es la
//!   deteccion directa de un bootkit conocido.
//!
//! # La regla que atraviesa todo el crate
//!
//! **Si el hardware no esta, no se inventa.** La mitad de las maquinas no tienen
//! ni TPM ni UEFI, y en ellas la respuesta correcta es un tercer estado —"no
//! aplicable"—, nunca "inseguro" ni, mucho peor, un PCR sintetico. Un valor que
//! parece una atestacion y no viene de un TPM es una atestacion falsa, y la
//! politica de aguas abajo confiaria en ella: es estrictamente peor que decir la
//! verdad. Ver [`report::CheckState`].
//!
//! # Que se prueba, y contra que
//!
//! Esta maquina de integracion es una microVM sin TPM ni UEFI (kernel compilado
//! sin `CONFIG_TCG_TPM` ni `CONFIG_EFI`), asi que las LECTURAS del hardware se
//! ejercitan solo hasta el punto de detectar honestamente la ausencia. Pero la
//! logica que de verdad puede fallar —los ANALIZADORES del event log, del wire
//! del TPM y de la DBX, y el recalculo de PCRs— se prueba con vectores binarios
//! REALES construidos byte a byte segun el estandar TCG y la especificacion
//! UEFI, incluidos los casos que un analisis descuidado rompe: el prefijo de 4
//! bytes de `efivarfs`, las multiples `EFI_SIGNATURE_LIST` concatenadas, el
//! `EV_NO_ACTION` que no extiende, y las endianidades opuestas del TPM y del
//! event log.

#![deny(missing_docs)]

pub mod eventlog;
pub mod guid;
pub mod pcr;
pub mod report;
pub mod tcg;
pub mod tpm;
pub mod uefi;

pub use eventlog::{EventLog, LogError};
pub use guid::Guid;
pub use pcr::{PcrBank, PcrMatch};
pub use report::{Check, CheckState, FirmwareReport};
pub use tcg::{EventType, HashAlg};
pub use uefi::{Dbx, SecureBootState};

/// Lo que esta maquina puede ofrecer al escaner de firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareSupport {
    /// Hay un TPM accesible por sysfs.
    pub tpm: bool,
    /// Version mayor del TPM, si se pudo leer (2 para TPM 2.0).
    pub tpm_version: Option<u32>,
    /// Bancos de PCR activos.
    pub bancos: Vec<HashAlg>,
    /// La maquina arranco por UEFI.
    pub uefi: bool,
    /// `efivarfs` esta montado y las variables son legibles.
    pub efivars: bool,
    /// Hay event log de arranque medido.
    pub event_log: bool,
}

impl FirmwareSupport {
    /// Detecta lo que esta maquina ofrece.
    pub fn detect() -> FirmwareSupport {
        let tpm = tpm::hay_tpm();
        FirmwareSupport {
            tpm,
            tpm_version: if tpm { tpm::version_mayor() } else { None },
            bancos: if tpm {
                tpm::bancos_activos()
            } else {
                Vec::new()
            },
            uefi: uefi::hay_uefi(),
            efivars: uefi::efivars_montado(),
            event_log: std::path::Path::new(eventlog::RUTA_EVENT_LOG).exists(),
        }
    }

    /// Indica si hay algo de firmware que verificar en esta maquina.
    pub fn algo_que_verificar(&self) -> bool {
        self.tpm || self.uefi || self.event_log
    }
}

/// Escanea el firmware de esta maquina y devuelve el veredicto.
///
/// No falla nunca: la ausencia de una capacidad produce una comprobacion "no
/// aplicable", no un error. `authenticode_binario_arrancado` es el hash
/// Authenticode del gestor de arranque en uso, si el llamante lo conoce; sin el,
/// la comprobacion contra la DBX queda indeterminada.
pub fn escanear(authenticode_binario_arrancado: Option<&[u8]>) -> FirmwareReport {
    let soporte = FirmwareSupport::detect();
    let mut r = FirmwareReport::default();

    // --- Secure Boot ---
    if !soporte.uefi {
        r.push(Check::new(
            "secure-boot-imponiendo",
            CheckState::NoAplicable("esta maquina no arranco por UEFI".into()),
        ));
    } else {
        match uefi::estado_secure_boot() {
            Ok(estado) => r.push(report::check_secure_boot(&estado)),
            Err(e) => r.push(Check::new(
                "secure-boot-imponiendo",
                CheckState::Indeterminado(e.to_string()),
            )),
        }
    }

    // --- DBX ---
    if !soporte.uefi || !soporte.efivars {
        r.push(Check::new(
            "binario-arrancado-no-revocado",
            CheckState::NoAplicable("sin UEFI/efivarfs no hay DBX que consultar".into()),
        ));
    } else {
        match uefi::leer_dbx() {
            Ok(dbx) => r.push(report::check_dbx(&dbx, authenticode_binario_arrancado)),
            Err(e) => r.push(Check::new(
                "binario-arrancado-no-revocado",
                CheckState::Indeterminado(e.to_string()),
            )),
        }
    }

    // --- Arranque medido: log vs TPM ---
    if !soporte.tpm || !soporte.event_log {
        r.push(Check::new(
            "arranque-medido-coherente",
            CheckState::NoAplicable(
                "sin TPM y event log de arranque no hay arranque medido que contrastar".into(),
            ),
        ));
    } else if soporte.tpm_version == Some(1) {
        r.push(Check::new(
            "arranque-medido-coherente",
            CheckState::Indeterminado("el TPM es 1.2, no soportado por este escaner".into()),
        ));
    } else {
        match (
            eventlog::leer_del_sistema(),
            tpm::leer_banco_sysfs(HashAlg::Sha256),
        ) {
            (Ok(Some(log)), Ok(tpm)) => {
                let m = report::contrastar_arranque(&log, &tpm);
                r.push(report::check_pcr_log(&m));
            }
            (Ok(None), _) => r.push(Check::new(
                "arranque-medido-coherente",
                CheckState::NoAplicable("el firmware no entrego event log".into()),
            )),
            (Err(e), _) => r.push(Check::new(
                "arranque-medido-coherente",
                CheckState::Indeterminado(format!("no se pudo leer el event log: {e}")),
            )),
            (_, Err(e)) => r.push(Check::new(
                "arranque-medido-coherente",
                CheckState::Indeterminado(format!("no se pudieron leer los PCRs: {e}")),
            )),
        }
    }

    r
}
