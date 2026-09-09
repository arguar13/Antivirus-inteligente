//! Catalogo de tecnicas de MITRE ATT&CK que el motor sabe puntuar.
//!
//! # Por que un catalogo cerrado y con pesos
//!
//! Un motor conductual que sume "una alerta = un punto" es un generador de
//! ruido: un `bash` es una tecnica de ATT&CK (T1059) y en un servidor Linux
//! ocurre cientos de veces al dia de forma legitima. Lo que separa la deteccion
//! de la alarma es que **cada tecnica pesa lo que de verdad discrimina**.
//!
//! Los pesos de este catalogo estan puestos con ese criterio:
//!
//! - Las que casi nunca son legitimas pesan mucho: inyeccion en otro proceso
//!   (T1055), cifrado masivo (T1486), borrado de rastros (T1070).
//! - Las que son ubicuas pesan poco aunque salgan en todos los informes de
//!   incidentes: interprete de comandos (T1059), protocolo de aplicacion
//!   (T1071). Su valor no esta en aparecer, esta en aparecer **en una cadena**,
//!   y de eso se encarga [`crate::chain`].
//!
//! Un peso alto en T1059 haria escalar cada `cron` de la maquina, y un motor que
//! escala todo es un motor que se apaga a la semana de desplegarlo.

use std::fmt;

/// Tactica de ATT&CK a la que pertenece una tecnica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tactic {
    /// Ejecucion de codigo.
    Execution,
    /// Persistencia en el sistema.
    Persistence,
    /// Elevacion de privilegios.
    PrivilegeEscalation,
    /// Evasion de defensas.
    DefenseEvasion,
    /// Descubrimiento del entorno.
    Discovery,
    /// Movimiento lateral.
    LateralMovement,
    /// Mando y control.
    CommandAndControl,
    /// Impacto sobre la disponibilidad o la integridad.
    Impact,
}

impl Tactic {
    /// Nombre de la tactica tal y como lo publica MITRE.
    pub fn as_str(self) -> &'static str {
        match self {
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Impact => "Impact",
        }
    }
}

/// Tecnica de ATT&CK observada sobre un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Technique {
    /// T1055 — Process Injection.
    ProcessInjection,
    /// T1059 — Command and Scripting Interpreter.
    CommandInterpreter,
    /// T1486 — Data Encrypted for Impact.
    DataEncryptedForImpact,
    /// T1105 — Ingress Tool Transfer.
    IngressToolTransfer,
    /// T1222 — File and Directory Permissions Modification.
    PermissionsModification,
    /// T1036 — Masquerading.
    Masquerading,
    /// T1070 — Indicator Removal.
    IndicatorRemoval,
    /// T1071 — Application Layer Protocol.
    ApplicationLayerProtocol,
    /// T1053 — Scheduled Task/Job.
    ScheduledTask,
    /// T1027 — Obfuscated Files or Information.
    ObfuscatedFiles,
    /// T1548 — Abuse Elevation Control Mechanism.
    AbuseElevationControl,
    /// T1203 — Exploitation for Client Execution.
    ExploitationForExecution,
    /// T1057 — Process Discovery.
    ProcessDiscovery,
    /// T1021 — Remote Services.
    RemoteServices,
}

/// Todas las tecnicas del catalogo, en orden estable.
///
/// Existe para que las pruebas puedan recorrer el catalogo entero y comprobar
/// invariantes sobre TODAS —que ninguna tiene peso cero, que ninguna llega sola
/// al umbral de aislamiento—, en vez de sobre las que alguien se acordo de
/// listar.
pub const CATALOGO: [Technique; 14] = [
    Technique::ProcessInjection,
    Technique::CommandInterpreter,
    Technique::DataEncryptedForImpact,
    Technique::IngressToolTransfer,
    Technique::PermissionsModification,
    Technique::Masquerading,
    Technique::IndicatorRemoval,
    Technique::ApplicationLayerProtocol,
    Technique::ScheduledTask,
    Technique::ObfuscatedFiles,
    Technique::AbuseElevationControl,
    Technique::ExploitationForExecution,
    Technique::ProcessDiscovery,
    Technique::RemoteServices,
];

impl Technique {
    /// Identificador de MITRE.
    pub fn id(self) -> &'static str {
        match self {
            Technique::ProcessInjection => "T1055",
            Technique::CommandInterpreter => "T1059",
            Technique::DataEncryptedForImpact => "T1486",
            Technique::IngressToolTransfer => "T1105",
            Technique::PermissionsModification => "T1222",
            Technique::Masquerading => "T1036",
            Technique::IndicatorRemoval => "T1070",
            Technique::ApplicationLayerProtocol => "T1071",
            Technique::ScheduledTask => "T1053",
            Technique::ObfuscatedFiles => "T1027",
            Technique::AbuseElevationControl => "T1548",
            Technique::ExploitationForExecution => "T1203",
            Technique::ProcessDiscovery => "T1057",
            Technique::RemoteServices => "T1021",
        }
    }

    /// Nombre publicado por MITRE.
    pub fn name(self) -> &'static str {
        match self {
            Technique::ProcessInjection => "Process Injection",
            Technique::CommandInterpreter => "Command and Scripting Interpreter",
            Technique::DataEncryptedForImpact => "Data Encrypted for Impact",
            Technique::IngressToolTransfer => "Ingress Tool Transfer",
            Technique::PermissionsModification => "File and Directory Permissions Modification",
            Technique::Masquerading => "Masquerading",
            Technique::IndicatorRemoval => "Indicator Removal",
            Technique::ApplicationLayerProtocol => "Application Layer Protocol",
            Technique::ScheduledTask => "Scheduled Task/Job",
            Technique::ObfuscatedFiles => "Obfuscated Files or Information",
            Technique::AbuseElevationControl => "Abuse Elevation Control Mechanism",
            Technique::ExploitationForExecution => "Exploitation for Client Execution",
            Technique::ProcessDiscovery => "Process Discovery",
            Technique::RemoteServices => "Remote Services",
        }
    }

    /// Tactica a la que pertenece.
    pub fn tactic(self) -> Tactic {
        match self {
            Technique::ProcessInjection => Tactic::DefenseEvasion,
            Technique::CommandInterpreter => Tactic::Execution,
            Technique::DataEncryptedForImpact => Tactic::Impact,
            Technique::IngressToolTransfer => Tactic::CommandAndControl,
            Technique::PermissionsModification => Tactic::DefenseEvasion,
            Technique::Masquerading => Tactic::DefenseEvasion,
            Technique::IndicatorRemoval => Tactic::DefenseEvasion,
            Technique::ApplicationLayerProtocol => Tactic::CommandAndControl,
            Technique::ScheduledTask => Tactic::Persistence,
            Technique::ObfuscatedFiles => Tactic::DefenseEvasion,
            Technique::AbuseElevationControl => Tactic::PrivilegeEscalation,
            Technique::ExploitationForExecution => Tactic::Execution,
            Technique::ProcessDiscovery => Tactic::Discovery,
            Technique::RemoteServices => Tactic::LateralMovement,
        }
    }

    /// Peso base sobre 100.
    ///
    /// Es lo que la tecnica aporta POR SI SOLA. Ninguna llega al umbral de
    /// aislamiento por si misma, y eso es deliberado: la decision de cortar un
    /// proceso no puede depender de una sola observacion, que siempre puede ser
    /// un falso positivo. Lo que la lleva al umbral es la acumulacion y la
    /// cadena.
    pub fn weight(self) -> u8 {
        match self {
            // Casi nunca legitimas.
            Technique::DataEncryptedForImpact => 60,
            Technique::ProcessInjection => 45,
            Technique::ExploitationForExecution => 40,
            Technique::IndicatorRemoval => 35,
            Technique::AbuseElevationControl => 35,
            // Legitimas a veces, sospechosas en contexto.
            Technique::Masquerading => 30,
            Technique::ObfuscatedFiles => 30,
            Technique::IngressToolTransfer => 25,
            Technique::ScheduledTask => 25,
            Technique::RemoteServices => 20,
            // Ubicuas: su valor esta en la cadena, no en aparecer.
            Technique::CommandInterpreter => 15,
            Technique::PermissionsModification => 15,
            Technique::ProcessDiscovery => 10,
            Technique::ApplicationLayerProtocol => 10,
        }
    }
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.id(), self.name())
    }
}
