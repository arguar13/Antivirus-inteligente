//! Puerta: las pruebas llegan a PostgreSQL por UNA sola via,
//! `comun::almacen_real`.
//!
//! Cinco ficheros tenian su propia copia de `conectar(..).ok()?;
//! migrar().ok()?`: una migracion rota se leia como «no hay PostgreSQL» y la
//! tanda decia que faltaba el entorno cuando lo que fallaba era el producto. La
//! via comun separa los dos casos (sin servidor se omite con el error real; una
//! migracion que no aplica hace fallar la prueba). Esta prueba impide que
//! vuelva una copia.

use std::path::Path;

/// Lo que solo puede aparecer en `comun/mod.rs`.
const SOLO_EN_COMUN: &str = "Almacen::conectar(";

/// Formas de tragarse el error de una migracion, en cualquier fichero.
const PROHIBIDO: [&str; 2] = ["migrar().await.ok()", "migrar().await.unwrap_or"];

#[test]
fn las_pruebas_llegan_a_postgresql_solo_por_la_via_comun() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut fallos = Vec::new();
    let mut vistos = 0;
    for entrada in std::fs::read_dir(&dir).expect("el directorio de pruebas") {
        let ruta = entrada.expect("entrada del directorio").path();
        if ruta.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let nombre = ruta.file_name().unwrap().to_string_lossy().into_owned();
        if nombre == "una_via_a_la_base.rs" {
            continue;
        }
        vistos += 1;
        let texto = std::fs::read_to_string(&ruta).expect("fichero de prueba legible");
        if texto.contains(SOLO_EN_COMUN) {
            fallos.push(format!(
                "{nombre}: conecta por su cuenta; usa comun::almacen_real"
            ));
        }
        for p in PROHIBIDO {
            if texto.contains(p) {
                fallos.push(format!("{nombre}: se traga el error de migracion ({p})"));
            }
        }
    }
    let comun = std::fs::read_to_string(dir.join("comun/mod.rs")).expect("tests/comun/mod.rs");
    assert!(
        comun.contains(SOLO_EN_COMUN),
        "la via comun ya no conecta: esta puerta mira lo que no debe"
    );
    assert!(vistos > 0, "no se ha mirado ninguna prueba");
    assert!(fallos.is_empty(), "{}", fallos.join("\n"));
}
