//! Compila los programas eBPF y los empotra en el binario del agente.
//!
//! Se invoca el Makefile del subproyecto en vez de replicar aqui los flags de
//! clang: duplicarlos garantizaria que las dos copias divergen, y una
//! divergencia en los flags de un programa eBPF se manifiesta como un rechazo
//! del verificador en produccion, no como un error de compilacion.
//!
//! El objeto se empotra con `include_bytes!` para que el agente sea un unico
//! artefacto: un fichero .o suelto en disco junto al binario es algo que un
//! atacante con permisos de escritura puede sustituir por su propia telemetria.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
    println!("cargo:rerun-if-changed=../../shared/include/aegis_abi.h");

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

    let objeto = out_dir.join("aegis_probes.bpf.o");
    if !objeto.exists() {
        panic!(
            "make termino con exito pero no produjo {}",
            objeto.display()
        );
    }
}
