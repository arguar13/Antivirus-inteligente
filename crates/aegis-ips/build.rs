//! Compila el programa TC de prevencion y lo empotra en el binario.
//!
//! Misma decision que en `aegis-net`, y por las mismas dos razones:
//!
//! 1. Se invoca el Makefile del subproyecto en vez de replicar aqui los flags de
//!    clang. Duplicarlos garantizaria que las dos copias divergen, y una
//!    divergencia en los flags de un programa eBPF no se manifiesta como un
//!    error de compilacion: se manifiesta como un rechazo del verificador en
//!    produccion.
//! 2. El objeto se empotra con `include_bytes!` para que el agente sea un unico
//!    artefacto. Un `.o` suelto en disco junto al binario es algo que un atacante
//!    con permisos de escritura puede sustituir por su propio clasificador — y
//!    aqui eso significaria decidir que se corta y que no.
//!
//! Compilar en `OUT_DIR`, y no leer `drivers/.../out/`, es lo que hace que un
//! clon limpio compile a la primera: en la secuencia de `make ci` los pasos de
//! Rust van ANTES que la compilacion de los programas eBPF, asi que apuntar al
//! arbol de `drivers/` fallaria en la primera compilacion de una maquina nueva.

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

    if std::env::var_os("CARGO_FEATURE_KERNEL").is_none() {
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

    let objeto = out_dir.join("aegis_ips.bpf.o");
    if !objeto.exists() {
        panic!(
            "make termino con exito pero no produjo {}",
            objeto.display()
        );
    }
}
