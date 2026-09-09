//! Veredicto de integridad de firmware, y el tercer estado que evita falsos
//! positivos en cada maquina sin TPM o sin UEFI.
//!
//! # Por que un tercer estado es obligatorio
//!
//! La mitad de las maquinas del mundo —microVMs, contenedores, equipos con BIOS
//! heredada— no tienen ni TPM ni UEFI. Reportar "Secure Boot desactivado" o
//! "sin arranque medido" en todas ellas es un falso positivo en cada una, y un
//! producto que grita en cada arranque limpio se apaga. Por eso el veredicto
//! distingue tres estados, no dos: seguro, comprometido, y **no aplicable**.

use crate::eventlog::EventLog;
use crate::pcr::{self, PcrBank, PcrMatch};
use crate::uefi::{Dbx, SecureBootState};

/// Estado de una comprobacion de firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckState {
    /// La comprobacion paso.
    Ok,
    /// La comprobacion encontro una anomalia.
    Fallo(String),
    /// La maquina no tiene la capacidad; la comprobacion no aplica.
    ///
    /// NO es un fallo, y confundirlo con uno es el falso positivo que este
    /// enumerado existe para impedir.
    NoAplicable(String),
    /// La capacidad existe pero no se pudo evaluar (permisos, error de lectura).
    Indeterminado(String),
}

impl CheckState {
    /// Indica si la comprobacion representa un compromiso.
    pub fn es_fallo(&self) -> bool {
        matches!(self, CheckState::Fallo(_))
    }
}

/// Una comprobacion concreta con su nombre y su estado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Nombre corto y estable.
    pub nombre: &'static str,
    /// Estado.
    pub estado: CheckState,
}

impl Check {
    /// Crea una comprobacion.
    pub fn new(nombre: &'static str, estado: CheckState) -> Check {
        Check { nombre, estado }
    }
}

/// Veredicto completo de firmware.
#[derive(Debug, Clone, Default)]
pub struct FirmwareReport {
    /// Comprobaciones realizadas, en orden.
    pub checks: Vec<Check>,
}

impl FirmwareReport {
    /// Anade una comprobacion.
    pub fn push(&mut self, c: Check) {
        self.checks.push(c);
    }

    /// Comprobaciones que representan un compromiso.
    pub fn fallos(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.estado.es_fallo()).collect()
    }

    /// Indica si el firmware muestra evidencia de compromiso.
    pub fn comprometido(&self) -> bool {
        self.checks.iter().any(|c| c.estado.es_fallo())
    }

    /// Indica si TODAS las comprobaciones aplicables pasaron.
    ///
    /// Una maquina con todo "no aplicable" NO esta comprometida ni verificada:
    /// esta fuera del alcance de esta defensa, y eso se dice, no se disfraza de
    /// aprobado.
    pub fn todo_aplicable_ok(&self) -> bool {
        !self.comprometido()
            && self
                .checks
                .iter()
                .any(|c| matches!(c.estado, CheckState::Ok))
    }
}

/// Evalua el estado de Secure Boot y lo convierte en una comprobacion.
pub fn check_secure_boot(estado: &SecureBootState) -> Check {
    let estado = if estado.imponiendo() {
        CheckState::Ok
    } else if estado.secure_boot && estado.setup_mode {
        CheckState::Fallo(
            "Secure Boot esta activo pero en MODO CONFIGURACION: cualquier clave \
             se puede matricular sin autenticacion, que es el estado que busca un \
             bootkit"
                .into(),
        )
    } else {
        CheckState::Fallo("Secure Boot no esta imponiendo (SecureBoot=0)".into())
    };
    Check::new("secure-boot-imponiendo", estado)
}

/// Evalua un binario arrancado contra la DBX.
pub fn check_dbx(dbx: &Dbx, authenticode_binario_arrancado: Option<&[u8]>) -> Check {
    match authenticode_binario_arrancado {
        Some(hash) if dbx.revoca_hash(hash) => Check::new(
            "binario-arrancado-no-revocado",
            CheckState::Fallo(
                "el hash Authenticode del binario arrancado esta en la lista de \
                 revocacion (DBX): es un gestor de arranque comprometido conocido"
                    .into(),
            ),
        ),
        Some(_) => Check::new("binario-arrancado-no-revocado", CheckState::Ok),
        None => Check::new(
            "binario-arrancado-no-revocado",
            CheckState::Indeterminado(
                "no se pudo calcular el hash Authenticode del binario arrancado".into(),
            ),
        ),
    }
}

/// Evalua la coherencia entre el event log y los PCRs del TPM.
pub fn check_pcr_log(m: &PcrMatch) -> Check {
    if m.hay_discrepancia() {
        let mut detalle = String::from(
            "el arranque medido no coincide con el registro: el event log no \
             explica los PCRs que el TPM tiene de verdad. ",
        );
        if !m.discrepan.is_empty() {
            detalle.push_str(&format!("PCRs alterados: {:?}. ", m.discrepan));
        }
        if !m.no_explicados.is_empty() {
            detalle.push_str(&format!(
                "PCRs con medidas no registradas: {:?}.",
                m.no_explicados
            ));
        }
        Check::new("arranque-medido-coherente", CheckState::Fallo(detalle))
    } else if m.coinciden.is_empty() {
        Check::new(
            "arranque-medido-coherente",
            CheckState::Indeterminado("no habia PCRs de interes que contrastar".into()),
        )
    } else {
        Check::new("arranque-medido-coherente", CheckState::Ok)
    }
}

/// Construye el contraste PCR log-vs-TPM para el conjunto de arranque.
pub fn contrastar_arranque(log: &EventLog, tpm_sha256: &PcrBank) -> PcrMatch {
    let reproducido = pcr::reproducir_sha256(log);
    pcr::contrastar(&reproducido, tpm_sha256, &pcr::PCRS_DE_ARRANQUE)
}
