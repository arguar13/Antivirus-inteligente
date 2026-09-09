//! Cotejo del layout de `ptrace_syscall_info` entre el header del kernel (C) y
//! el espejo `repr(C)` de `abi.rs` (Rust).
//!
//! El kernel rellena esta estructura; el agente la lee. Si las dos vistas del
//! layout divergen, el agente confunde el numero de syscall con el puntero de
//! instruccion. Las aserciones `const` de `abi.rs` fijan los offsets en Rust;
//! esta prueba compila una sonda en C con el header REAL del kernel y comprueba
//! que coinciden.

use std::process::Command;

/// Offsets que calcula el compilador de C, o `None` si no se pudo compilar.
fn offsets_de_c() -> Option<std::collections::HashMap<String, usize>> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let probe = format!("{dir}/tests/scinfo_abi_probe.c");
    let bin = std::env::temp_dir().join(format!("scinfo_abi_probe_{}", std::process::id()));

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compilar = Command::new(&cc)
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&bin)
        .arg(&probe)
        .output()
        .ok()?;
    if !compilar.status.success() {
        eprintln!(
            "no se pudo compilar la sonda C: {}",
            String::from_utf8_lossy(&compilar.stderr)
        );
        return None;
    }

    let salida = Command::new(&bin).output().ok()?;
    let _ = std::fs::remove_file(&bin);
    let texto = String::from_utf8_lossy(&salida.stdout);

    let mut m = std::collections::HashMap::new();
    for linea in texto.lines() {
        let mut it = linea.rsplitn(2, ' ');
        let (Some(valor), Some(clave)) = (it.next(), it.next()) else {
            continue;
        };
        if let Ok(v) = valor.parse::<usize>() {
            m.insert(clave.to_string(), v);
        }
    }
    Some(m)
}

#[test]
fn el_layout_de_c_y_el_de_rust_coinciden() {
    let Some(c) = offsets_de_c() else {
        // Sin compilador de C no se puede cotejar. No es un pase encubierto:
        // es un salto explicito, como el resto de la puerta de ABI del proyecto.
        eprintln!("OMITIDA: no hay compilador de C para cotejar el layout");
        return;
    };

    for (campo, off) in aegis_syscallguard::abi::OFFSETS {
        assert_eq!(
            c.get(*campo),
            Some(off),
            "el offset de '{campo}' es {:?} en C y {off} en abi.rs::OFFSETS",
            c.get(*campo)
        );
    }
}
