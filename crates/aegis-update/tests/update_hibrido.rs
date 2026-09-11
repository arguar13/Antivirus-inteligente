//! Pruebas del camino de actualizacion HIBRIDO (FASE 59): firma post-cuantica
//! Ed25519 + ML-DSA-65.
//!
//! Se firma con una clave hibrida GENERADA en la prueba y se verifica con su
//! publica: un ciclo de firma real, no un vector fijo. Se comprueba que se
//! aplica de verdad, que manipular el contenido o bajar la suite (downgrade) se
//! rechaza, y que la firma queda atada al TIPO de artefacto.

use std::path::{Path, PathBuf};

use aegis_update::artifact::ArtifactKind;
use aegis_update::updater::ApplyOutcome;
use aegis_update::{Artifact, ClaveFirmaHibrida, SignatureError, UpdateError, Updater};

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-update-hib-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Firma un artefacto con la clave hibrida, atando el contexto al tipo.
fn firmar(
    sk: &ClaveFirmaHibrida,
    nombre: &str,
    kind: ArtifactKind,
    version: &str,
    bytes: &[u8],
) -> Artifact {
    let firma = sk
        .firmar(bytes, kind.as_str().as_bytes())
        .expect("firmar")
        .a_bytes();
    Artifact::new(nombre, kind, version, bytes.to_vec(), firma)
}

#[test]
fn un_artefacto_hibrido_valido_verifica_y_se_aplica() {
    let lab = Lab::nuevo("apply");
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido(lab.path(), sk.clave_verificacion());

    let art = firmar(
        &sk,
        "modelo.onnx",
        ArtifactKind::OnnxModel,
        "1.0",
        b"MODELO V1",
    );
    assert!(up.verify(&art).is_ok());
    assert_eq!(
        up.apply(&art).unwrap(),
        ApplyOutcome::Applied {
            version: "1.0".into()
        }
    );
    assert_eq!(
        std::fs::read(lab.path().join("modelo.onnx")).unwrap(),
        b"MODELO V1"
    );
}

#[test]
fn manipular_el_contenido_invalida_la_firma_hibrida() {
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido("/tmp", sk.clave_verificacion());
    let mut art = firmar(
        &sk,
        "reglas.yar",
        ArtifactKind::YaraRules,
        "1.0",
        b"legitimo",
    );
    art.bytes[0] ^= 0x01;
    assert!(matches!(up.verify(&art), Err(UpdateError::Signature(_))));
}

#[test]
fn una_firma_de_otra_clave_hibrida_no_verifica() {
    let sk_real = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let sk_atacante = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let art = firmar(
        &sk_atacante,
        "reglas.yar",
        ArtifactKind::YaraRules,
        "1.0",
        b"carga del atacante",
    );
    let up = Updater::nuevo_hibrido("/tmp", sk_real.clave_verificacion());
    assert!(up.verify(&art).is_err());
}

#[test]
fn un_downgrade_a_suite_clasica_se_rechaza() {
    // Un verificador hibrido NO debe aceptar una firma que se anuncie como
    // clasica: es justo el ataque de degradacion que la fase evita.
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido("/tmp", sk.clave_verificacion());
    let mut art = firmar(&sk, "x.bin", ArtifactKind::AgentBinary, "1.0", b"datos");
    // Bajar el byte de suite de hibrida (2) a clasica (1).
    art.signature[0] = 1;
    assert!(matches!(
        up.verify(&art),
        Err(UpdateError::Signature(SignatureError::HibridaMalFormada))
    ));
}

#[test]
fn una_firma_corta_no_cuela_como_hibrida() {
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido("/tmp", sk.clave_verificacion());
    let mut art = firmar(&sk, "x.bin", ArtifactKind::AgentBinary, "1.0", b"datos");
    art.signature.truncate(64); // una Ed25519 cruda de 64 bytes
    assert!(matches!(
        up.verify(&art),
        Err(UpdateError::Signature(SignatureError::HibridaMalFormada))
    ));
}

#[test]
fn una_firma_valida_de_otro_tipo_de_artefacto_no_cuela() {
    // La firma ata el contexto al TIPO: una firma hecha para reglas YARA no
    // puede reaprovecharse para el binario del agente con el mismo contenido.
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido("/tmp", sk.clave_verificacion());

    let bytes = b"contenido identico";
    let firma_para_reglas = sk
        .firmar(bytes, ArtifactKind::YaraRules.as_str().as_bytes())
        .expect("firmar")
        .a_bytes();
    // Se presenta como binario del agente.
    let art = Artifact::new(
        "aegis-agent",
        ArtifactKind::AgentBinary,
        "1.0",
        bytes.to_vec(),
        firma_para_reglas,
    );
    assert!(matches!(up.verify(&art), Err(UpdateError::Signature(_))));
}

#[test]
fn el_rollback_sigue_funcionando_con_firma_hibrida() {
    let lab = Lab::nuevo("rollback");
    let sk = ClaveFirmaHibrida::generar_aleatorio().expect("entropia");
    let up = Updater::nuevo_hibrido(lab.path(), sk.clave_verificacion());
    let vivo = lab.path().join("aegis-agent");

    up.apply(&firmar(
        &sk,
        "aegis-agent",
        ArtifactKind::AgentBinary,
        "1.0",
        b"AGENTE ESTABLE",
    ))
    .unwrap();

    let mala = firmar(
        &sk,
        "aegis-agent",
        ArtifactKind::AgentBinary,
        "2.0-rota",
        b"AGENTE QUE PANICA",
    );
    let sana = |p: &Path| {
        std::fs::read(p)
            .map(|d| d != b"AGENTE QUE PANICA")
            .unwrap_or(false)
    };
    let outcome = up.apply_checked(&mala, &sana).unwrap();
    assert_eq!(
        outcome,
        ApplyOutcome::RolledBack {
            rejected: "2.0-rota".into()
        }
    );
    assert_eq!(std::fs::read(&vivo).unwrap(), b"AGENTE ESTABLE");
}
