//! Compila el programa eBPF de verificacion cruzada y lo empotra firmado.
//!
//! Mismo criterio que el agente: se invoca el Makefile del subproyecto en vez
//! de replicar los flags de clang —dos copias divergen, y una divergencia en
//! los flags de un programa eBPF se manifiesta como un rechazo del verificador
//! en produccion, no como un error de compilacion— y el objeto se empotra con
//! su HMAC, de modo que un `.o` suelto en disco no pueda sustituirse.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // En ejecucion y no con `env!`: ver `crates/aegis-net/build.rs`. Con `env!`
    // un repositorio movido de carpeta dejaba de compilar.
    let manifiesto = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("cargo define CARGO_MANIFEST_DIR al ejecutar el script");
    let bpf_dir = PathBuf::from(manifiesto)
        .join("../../drivers/linux/aegis-bpf")
        .canonicalize()
        .expect("el subproyecto eBPF debe existir dentro del repositorio");

    println!("cargo:rerun-if-changed={}", bpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        bpf_dir.join("include").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        bpf_dir.join("Makefile").display()
    );

    if std::env::var_os("CARGO_FEATURE_BPF").is_none() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo define OUT_DIR"));

    let salida = Command::new("make")
        .arg("-C")
        .arg(&bpf_dir)
        .arg("build")
        .arg(format!("BUILD={}", out_dir.display()))
        .output()
        .expect("no se pudo invocar make para compilar los programas eBPF");

    if !salida.status.success() {
        panic!(
            "fallo la compilacion de los programas eBPF.\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&salida.stdout),
            String::from_utf8_lossy(&salida.stderr),
        );
    }

    let objeto = out_dir.join("aegis_kintegrity.bpf.o");
    if !objeto.exists() {
        panic!(
            "make termino con exito pero no produjo {}",
            objeto.display()
        );
    }

    let bytes = std::fs::read(&objeto).expect("no se pudo leer el objeto eBPF compilado");
    let clave = match std::env::var("AEGIS_BPF_HMAC_KEY") {
        Ok(h) => descifrar_hex(&h).expect("AEGIS_BPF_HMAC_KEY debe ser hex"),
        Err(_) => aegis_kguard::DEV_BPF_KEY.to_vec(),
    };
    let hmac = aegis_kguard::integrity::hmac_sha256(&clave, &bytes);
    let hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(out_dir.join("aegis_kintegrity.hmac"), hex)
        .expect("no se pudo escribir la firma del bytecode");
    let clave_hex: String = clave.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(out_dir.join("aegis_kintegrity.key"), clave_hex)
        .expect("no se pudo escribir la clave de verificacion");
}

fn descifrar_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}
