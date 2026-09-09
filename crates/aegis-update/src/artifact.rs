//! Artefactos de actualizacion y su descripcion.

/// Tipo de artefacto que se puede actualizar.
///
/// Los tres se validan igual —por firma Ed25519— pero se distinguen porque cada
/// uno va a un sitio y el operador quiere saber que se cambio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// El binario del agente de Ring 3.
    AgentBinary,
    /// Un conjunto de reglas YARA.
    YaraRules,
    /// Un modelo ONNX de clasificacion.
    OnnxModel,
    /// El bytecode eBPF del driver.
    BpfBytecode,
}

impl ArtifactKind {
    /// Nombre estable para el manifiesto y los registros.
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::AgentBinary => "agent-binary",
            ArtifactKind::YaraRules => "yara-rules",
            ArtifactKind::OnnxModel => "onnx-model",
            ArtifactKind::BpfBytecode => "bpf-bytecode",
        }
    }

    /// Analiza el nombre.
    pub fn parse(s: &str) -> Option<ArtifactKind> {
        match s {
            "agent-binary" => Some(ArtifactKind::AgentBinary),
            "yara-rules" => Some(ArtifactKind::YaraRules),
            "onnx-model" => Some(ArtifactKind::OnnxModel),
            "bpf-bytecode" => Some(ArtifactKind::BpfBytecode),
            _ => None,
        }
    }
}

/// Un artefacto descargado, pendiente de verificar y aplicar.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Nombre del fichero destino (sin ruta).
    pub name: String,
    /// Tipo.
    pub kind: ArtifactKind,
    /// Version, para el registro y para evitar aplicar hacia atras.
    pub version: String,
    /// Contenido.
    pub bytes: Vec<u8>,
    /// Firma Ed25519 del contenido, 64 bytes.
    pub signature: Vec<u8>,
}

impl Artifact {
    /// Crea un artefacto.
    pub fn new(
        name: impl Into<String>,
        kind: ArtifactKind,
        version: impl Into<String>,
        bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Artifact {
        Artifact {
            name: name.into(),
            kind,
            version: version.into(),
            bytes,
            signature,
        }
    }

    /// SHA-256 del contenido, en hexadecimal, para el registro.
    pub fn sha256_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&self.bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}
