//! Demostracion del mecanismo de deteccion de bootkits, para la Red Team.
//!
//! No hay TPM en esta maquina, asi que no se puede leer un PCR de hardware. Lo
//! que SI es real y se ejecuta aqui es el MECANISMO completo: se construye un
//! event log de arranque byte a byte como lo escribe el firmware, se calculan
//! los PCRs que ese arranque produce (extendiendo con SHA-256 real, igual que
//! el TPM), y se contrastan. El calculo es el mismo que corre contra un TPM de
//! verdad; solo el origen de los PCRs cambia.
//!
//! Se prueban dos arranques:
//!   1. INTACTO: el log reproduce exactamente los PCRs -> sin alarma.
//!   2. CON BOOTKIT: el gestor de arranque real es malicioso y su medida esta
//!      en el PCR del TPM, pero el log fue reescrito para declarar la medida del
//!      gestor legitimo. El PCR reproducido del log NO coincide con el del TPM
//!      -> alarma. Es imposible de evitar para el bootkit: no tiene la clave del
//!      TPM para cambiar el PCR ya extendido.
//!
//! Sale 0 si el arranque intacto pasa Y el manipulado se detecta.

use sha2::{Digest, Sha256};

use aegis_firmware::eventlog;
use aegis_firmware::pcr::{self, PcrBank};
use aegis_firmware::tcg::{EventType, HashAlg};

fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.finalize().into()
}

fn extend(pcr: [u8; 32], medida: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pcr);
    h.update(medida);
    h.finalize().into()
}

/// Construye un event log crypto-agil (SHA-1 + SHA-256) con los eventos dados.
/// Cada evento: (pcr, tipo, contenido, digest_sha256_declarado).
fn construir_log(eventos: &[(u32, u32, &[u8], [u8; 32])]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Primer registro: EV_NO_ACTION + Spec ID Event03 (SHA-1, SHA-256).
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0x0000_0003u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    let mut ev = Vec::new();
    ev.extend_from_slice(b"Spec ID Event03\0");
    ev.extend_from_slice(&0u32.to_le_bytes());
    ev.extend_from_slice(&[0, 2, 0, 2]); // minor, major, errata, uintnSize
    ev.extend_from_slice(&2u32.to_le_bytes()); // numberOfAlgorithms
    ev.extend_from_slice(&0x0004u16.to_le_bytes());
    ev.extend_from_slice(&20u16.to_le_bytes());
    ev.extend_from_slice(&0x000Bu16.to_le_bytes());
    ev.extend_from_slice(&32u16.to_le_bytes());
    ev.push(0);
    buf.extend_from_slice(&(ev.len() as u32).to_le_bytes());
    buf.extend_from_slice(&ev);

    for (pcr, tipo, contenido, d256) in eventos {
        buf.extend_from_slice(&pcr.to_le_bytes());
        buf.extend_from_slice(&tipo.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // 2 digests
        buf.extend_from_slice(&0x0004u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 20]); // SHA-1 no relevante aqui
        buf.extend_from_slice(&0x000Bu16.to_le_bytes());
        buf.extend_from_slice(d256);
        buf.extend_from_slice(&(contenido.len() as u32).to_le_bytes());
        buf.extend_from_slice(contenido);
    }
    buf
}

fn main() -> std::process::ExitCode {
    let app = EventType::EfiBootServicesApplication.as_u32();

    // --- 1. Arranque INTACTO ---
    let grub_legitimo = b"grub-x86_64.efi v2.06 legitimo";
    let d_legitimo = sha256(grub_legitimo);
    let log_intacto = construir_log(&[(4, app, grub_legitimo, d_legitimo)]);
    // El TPM tiene el PCR 4 extendido con la medida REAL del grub legitimo.
    let mut tpm_intacto = PcrBank::cero(HashAlg::Sha256);
    tpm_intacto.valores[4] = extend([0u8; 32], &d_legitimo).to_vec();

    let log = eventlog::parse(&log_intacto).expect("el log intacto se analiza");
    let m = pcr::contrastar(
        &pcr::reproducir_sha256(&log),
        &tpm_intacto,
        &pcr::PCRS_DE_ARRANQUE,
    );
    let intacto_ok = !m.hay_discrepancia();
    println!(
        "arranque INTACTO: {} (PCRs que coinciden: {:?})",
        if intacto_ok {
            "sin alarma"
        } else {
            "FALSA ALARMA"
        },
        m.coinciden
    );

    // --- 2. Arranque CON BOOTKIT ---
    let grub_malicioso = b"grub-x86_64.efi con BlackLotus";
    let d_malicioso = sha256(grub_malicioso);
    // El TPM midio el grub REAL (el malicioso) y lo tiene en el PCR 4.
    let mut tpm_comprometido = PcrBank::cero(HashAlg::Sha256);
    tpm_comprometido.valores[4] = extend([0u8; 32], &d_malicioso).to_vec();
    // Pero el bootkit reescribio el log para declarar la medida del grub
    // legitimo: el log MIENTE.
    let log_manipulado = construir_log(&[(4, app, grub_malicioso, d_legitimo)]);

    let log2 = eventlog::parse(&log_manipulado).expect("el log manipulado se analiza");
    let m2 = pcr::contrastar(
        &pcr::reproducir_sha256(&log2),
        &tpm_comprometido,
        &pcr::PCRS_DE_ARRANQUE,
    );
    let bootkit_detectado = m2.discrepan.contains(&4);
    println!(
        "arranque CON BOOTKIT: {} (PCRs alterados: {:?})",
        if bootkit_detectado {
            "DETECTADO"
        } else {
            "NO DETECTADO"
        },
        m2.discrepan
    );

    if intacto_ok && bootkit_detectado {
        println!(
            "\nel arranque medido delata al bootkit: el log reescrito no puede \
             reproducir el PCR que el TPM ya tiene extendido con la medida real."
        );
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("BRECHA: el mecanismo de arranque medido no funciono como debe");
        std::process::ExitCode::FAILURE
    }
}
