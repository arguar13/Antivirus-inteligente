//! `cargo xtask invariantes`: el documento de las invariantes no se queda atras.
//!
//! `tools/verificar-invariantes.sh` es la fuente: define cada invariante con una
//! cabecera `# ── NN. NOMBRE`. `docs/75-invariantes.md` las explica en una tabla.
//! El documento decia «las quince» cuando el verificador ya tenia dieciseis, y la
//! decimosexta no aparecia (FASE 1 del MP-16): una cifra escrita a mano que
//! envejecio sola. Esta puerta exige una fila `| N |` en el documento por cada
//! invariante del verificador, y ninguna fila de mas.

use std::collections::BTreeSet;

use crate::repo::Repo;
use crate::Resultado;

/// El verificador, fuente de las invariantes.
const VERIFICADOR: &str = "tools/verificar-invariantes.sh";
/// El documento que las explica.
const DOCUMENTO: &str = "docs/75-invariantes.md";

/// Numeros de invariante que define el verificador.
fn del_verificador(texto: &str) -> BTreeSet<u32> {
    texto
        .lines()
        .filter_map(|l| {
            let resto = l.strip_prefix("# ── ")?;
            let (n, _) = resto.split_once('.')?;
            n.trim().parse().ok()
        })
        .collect()
}

/// Numeros de invariante que tienen fila en la tabla del documento.
fn del_documento(texto: &str) -> BTreeSet<u32> {
    texto
        .lines()
        .filter_map(|l| {
            let resto = l.strip_prefix("| ")?;
            let (n, despues) = resto.split_once(" |")?;
            despues.trim_start().starts_with("**").then_some(())?;
            n.trim().parse().ok()
        })
        .collect()
}

/// Comprueba que documento y verificador hablan de las mismas invariantes.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let leer =
        |r: &str| std::fs::read_to_string(repo.raiz.join(r)).map_err(|e| format!("{r}: {e}"));
    let fuente = del_verificador(&leer(VERIFICADOR)?);
    let doc = del_documento(&leer(DOCUMENTO)?);
    if fuente.is_empty() {
        return Err(format!("{VERIFICADOR} no define ninguna invariante («# ── NN. »)").into());
    }
    let faltan: Vec<u32> = fuente.difference(&doc).copied().collect();
    let sobran: Vec<u32> = doc.difference(&fuente).copied().collect();
    if faltan.is_empty() && sobran.is_empty() {
        return Ok(format!(
            "invariantes: {} en el verificador, todas explicadas en {DOCUMENTO}",
            fuente.len()
        ));
    }
    let mut m = String::from("invariantes:");
    if !faltan.is_empty() {
        m.push_str(&format!("\n    sin fila en {DOCUMENTO}: {faltan:?}"));
    }
    if !sobran.is_empty() {
        m.push_str(&format!(
            "\n    filas en {DOCUMENTO} que el verificador no define: {sobran:?}"
        ));
    }
    Err(m.into())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn lee_las_cabeceras_del_verificador_y_las_filas_del_documento() {
        let v = "# ── 01. PRESUPUESTO ──\nx\n# ── 16. RESIDUO (FASE 99) ──\n";
        assert_eq!(del_verificador(v), BTreeSet::from([1, 16]));
        let d = "| # | Invariante |\n|---:|---|\n| 1 | **Presupuesto** | x |\n| 16 | **Residuo** | y |\n| `x` | nada | - |\n";
        assert_eq!(del_documento(d), BTreeSet::from([1, 16]));
    }
}
