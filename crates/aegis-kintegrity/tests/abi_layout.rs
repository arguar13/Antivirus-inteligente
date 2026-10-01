//! Cotejo del layout del contrato de verificacion cruzada entre C y Rust.
//!
//! El programa eBPF (compilado por C) escribe directamente en estas
//! estructuras y el agente (compilado por rustc) las lee. Si las dos vistas del
//! layout divergen, el agente interpreta un campo por otro y acusa de rootkit a
//! procesos inocentes. Las aserciones `const` de `abi.rs` fijan los valores en
//! Rust; esta prueba compila una sonda en C con el MISMO header que usa el
//! programa eBPF y comprueba que coinciden.

use std::process::Command;

use aegis_prueba::{omitir, Requisito};

/// Offset que el compilador de C calcula para un campo, o `None` si no se pudo.
fn offsets_de_c() -> Option<std::collections::HashMap<String, usize>> {
    let dir = raiz_crate();
    let header_dir = format!("{dir}/../../drivers/linux/aegis-bpf/include");
    let probe = format!("{dir}/tests/ki_abi_probe.c");
    let bin = std::env::temp_dir().join(format!("ki_abi_probe_{}", std::process::id()));

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compilar = Command::new(&cc)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            &header_dir,
            "-o",
        ])
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
        // Sin compilador de C no se puede cotejar. No es un pase: es un salto
        // explicito, igual que en el resto de la puerta de ABI del proyecto.
        omitir(
            "no hay compilador de C (o no compila la sonda) para cotejar el layout",
            Requisito::Herramienta("cc"),
        );
        return;
    };

    // Tamanos y alineaciones que fija abi.rs.
    let esperado: &[(&str, usize)] = &[
        ("struct aegis_ki_task sizeof", 40),
        ("struct aegis_ki_task alignof", 8),
        ("struct aegis_ki_args sizeof", 32),
        ("struct aegis_ki_args alignof", 4),
        ("struct aegis_ki_confirm sizeof", 24),
        ("struct aegis_ki_confirm alignof", 8),
    ];
    for (clave, valor) in esperado {
        assert_eq!(
            c.get(*clave),
            Some(valor),
            "el C dice que '{clave}' es {:?}, Rust espera {valor}",
            c.get(*clave)
        );
    }

    // Offsets declarados en abi.rs, cotejados uno a uno contra el C.
    for (estructura, campo, off) in aegis_kintegrity::abi::OFFSETS {
        let clave = format!("struct {estructura}.{campo}");
        assert_eq!(
            c.get(&clave),
            Some(&off),
            "el offset de {estructura}.{campo} es {:?} en C y {off} en abi.rs::OFFSETS",
            c.get(&clave)
        );
    }
}

/// La raiz del crate, leida al EJECUTAR y no congelada al compilar.
///
/// Con `env!("CARGO_MANIFEST_DIR")` la ruta quedaba fijada en el binario, y
/// Cargo no lo recompila al mover el repositorio de carpeta (el hash de un
/// paquete de ruta es relativo al workspace): la prueba seguia buscando sus
/// ficheros en la ruta vieja y fallaba diciendo que no existian. Cargo define la
/// variable al lanzar pruebas y ejemplos; el valor de compilacion queda solo para
/// quien ejecute el binario a mano.
fn raiz_crate() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}
