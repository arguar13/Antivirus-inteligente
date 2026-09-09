//! Pruebas del motor de actualizacion firmada con rollback.
//!
//! Se firma con una clave Ed25519 GENERADA en la prueba y se verifica con su
//! publica: un ciclo de firma real, no un vector fijo. Y el rollback se
//! comprueba dejando en disco ficheros de verdad y mirando cual queda activo.

use std::path::{Path, PathBuf};

use aegis_update::artifact::ArtifactKind;
use aegis_update::updater::ApplyOutcome;
use aegis_update::{Artifact, UpdateError, UpdateKey, Updater};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-update-{n}-{}", std::process::id()));
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

/// Genera un par de claves y firma; devuelve la clave publica del actualizador.
fn firmante() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn clave_publica(sk: &SigningKey) -> UpdateKey {
    UpdateKey::from_bytes(&sk.verifying_key().to_bytes()).unwrap()
}

fn artefacto_firmado(sk: &SigningKey, nombre: &str, version: &str, bytes: &[u8]) -> Artifact {
    let firma = sk.sign(bytes).to_bytes().to_vec();
    Artifact::new(
        nombre,
        ArtifactKind::YaraRules,
        version,
        bytes.to_vec(),
        firma,
    )
}

// ---------------------------------------------------------------------------
// Firma
// ---------------------------------------------------------------------------

#[test]
fn un_artefacto_firmado_con_la_clave_correcta_verifica() {
    let sk = firmante();
    let up = Updater::new("/tmp", clave_publica(&sk));
    let art = artefacto_firmado(&sk, "reglas.yar", "1.0", b"rule x { condition: true }");
    assert!(up.verify(&art).is_ok());
}

#[test]
fn un_artefacto_manipulado_no_verifica() {
    let sk = firmante();
    let up = Updater::new("/tmp", clave_publica(&sk));
    let mut art = artefacto_firmado(&sk, "reglas.yar", "1.0", b"contenido legitimo");
    // El atacante cambia el contenido tras la firma.
    art.bytes[0] ^= 0x01;
    assert!(matches!(up.verify(&art), Err(UpdateError::Signature(_))));
}

#[test]
fn un_artefacto_firmado_con_otra_clave_no_verifica() {
    let sk_real = firmante();
    let sk_atacante = firmante();
    // El atacante firma su carga con SU clave.
    let art = artefacto_firmado(&sk_atacante, "reglas.yar", "1.0", b"carga del atacante");
    // El agente verifica con la clave real: rechaza.
    let up = Updater::new("/tmp", clave_publica(&sk_real));
    assert!(up.verify(&art).is_err());
}

#[test]
fn una_firma_de_longitud_incorrecta_se_rechaza() {
    let sk = firmante();
    let up = Updater::new("/tmp", clave_publica(&sk));
    let mut art = artefacto_firmado(&sk, "x", "1", b"datos");
    art.signature.truncate(10);
    assert!(up.verify(&art).is_err());
}

// ---------------------------------------------------------------------------
// Aplicacion atomica
// ---------------------------------------------------------------------------

#[test]
fn aplicar_deja_la_version_nueva_activa_y_preserva_la_anterior() {
    let lab = Lab::nuevo("apply");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));

    // Version 1.
    let v1 = artefacto_firmado(&sk, "modelo.onnx", "1.0", b"MODELO VERSION 1");
    assert_eq!(
        up.apply(&v1).unwrap(),
        ApplyOutcome::Applied {
            version: "1.0".into()
        }
    );
    let vivo = lab.path().join("modelo.onnx");
    assert_eq!(std::fs::read(&vivo).unwrap(), b"MODELO VERSION 1");
    assert!(!up.has_backup("modelo.onnx"), "sin version previa aun");

    // Version 2: la 1 pasa a respaldo.
    let v2 = artefacto_firmado(&sk, "modelo.onnx", "2.0", b"MODELO VERSION 2 mas grande");
    up.apply(&v2).unwrap();
    assert_eq!(
        std::fs::read(&vivo).unwrap(),
        b"MODELO VERSION 2 mas grande"
    );
    assert!(
        up.has_backup("modelo.onnx"),
        "la 1.0 tiene que quedar de respaldo"
    );
}

#[test]
fn un_artefacto_sin_firma_valida_no_llega_a_escribirse() {
    let lab = Lab::nuevo("nowrite");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));
    let mut art = artefacto_firmado(&sk, "reglas.yar", "1.0", b"contenido");
    art.bytes.extend_from_slice(b" manipulado");

    assert!(up.apply(&art).is_err());
    assert!(
        !lab.path().join("reglas.yar").exists(),
        "un artefacto que no verifica no puede dejar rastro en produccion"
    );
    assert!(!lab.path().join("reglas.yar.staging").exists());
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

#[test]
fn una_version_que_no_pasa_la_salud_se_revierte_sola() {
    let lab = Lab::nuevo("rollback");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));
    let vivo = lab.path().join("aegis-agent");

    // Version buena instalada.
    up.apply(&artefacto_firmado(
        &sk,
        "aegis-agent",
        "1.0",
        b"AGENTE ESTABLE",
    ))
    .unwrap();

    // Version nueva que "se cae al arrancar": la comprobacion de salud la
    // rechaza. Tiene firma valida (el fallo es de comportamiento, no de firma).
    let mala = artefacto_firmado(&sk, "aegis-agent", "2.0-rota", b"AGENTE QUE PANICA");
    let sana = |p: &Path| -> bool {
        // Sana solo si NO es la version rota.
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

    // La version estable tiene que estar de vuelta y activa.
    assert_eq!(
        std::fs::read(&vivo).unwrap(),
        b"AGENTE ESTABLE",
        "tras el fallo de salud tiene que haberse restaurado la version estable"
    );
    // La version rota se aparta para analisis, no se pierde en silencio.
    assert!(lab.path().join("aegis-agent.failed").exists());
}

#[test]
fn una_version_sana_se_queda() {
    let lab = Lab::nuevo("healthy");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));
    up.apply(&artefacto_firmado(&sk, "aegis-agent", "1.0", b"v1"))
        .unwrap();

    let siempre_sana = |_: &Path| true;
    let outcome = up
        .apply_checked(
            &artefacto_firmado(&sk, "aegis-agent", "2.0", b"v2 buena"),
            &siempre_sana,
        )
        .unwrap();
    assert_eq!(
        outcome,
        ApplyOutcome::Applied {
            version: "2.0".into()
        }
    );
    assert_eq!(
        std::fs::read(lab.path().join("aegis-agent")).unwrap(),
        b"v2 buena"
    );
}

#[test]
fn el_rollback_manual_restaura_la_version_previa() {
    let lab = Lab::nuevo("manual");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));
    up.apply(&artefacto_firmado(&sk, "x.bin", "1", b"uno"))
        .unwrap();
    up.apply(&artefacto_firmado(&sk, "x.bin", "2", b"dos"))
        .unwrap();

    up.rollback("x.bin").unwrap();
    assert_eq!(std::fs::read(lab.path().join("x.bin")).unwrap(), b"uno");
}

#[test]
fn el_rollback_sin_respaldo_es_un_error_claro() {
    let lab = Lab::nuevo("norollback");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));
    up.apply(&artefacto_firmado(&sk, "x.bin", "1", b"uno"))
        .unwrap();
    // Nunca hubo una segunda version, asi que no hay .prev.
    assert!(matches!(
        up.rollback("x.bin"),
        Err(UpdateError::NoBackup(_))
    ));
}

// ---------------------------------------------------------------------------
// Permisos ejecutables
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn una_actualizacion_conserva_el_bit_ejecutable_del_binario() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::nuevo("perms");
    let sk = firmante();
    let up = Updater::new(lab.path(), clave_publica(&sk));

    // Version 1 con bit ejecutable.
    let vivo = lab.path().join("aegis-agent");
    up.apply(&artefacto_firmado(
        &sk,
        "aegis-agent",
        "1.0",
        b"#!/bin/true\n",
    ))
    .unwrap();
    std::fs::set_permissions(&vivo, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Version 2: tiene que heredar el 0o755 del vivo.
    up.apply(&artefacto_firmado(
        &sk,
        "aegis-agent",
        "2.0",
        b"#!/bin/true\n# v2\n",
    ))
    .unwrap();
    let modo = std::fs::metadata(&vivo).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        modo, 0o755,
        "una actualizacion no puede dejar el binario sin permiso de ejecucion"
    );
}
