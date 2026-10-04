//! La puerta de publicacion sobre el contenido REAL del repositorio.
//!
//! Lo que hay en `contenido/` es lo que se publicaria. Si una regla de ahi no
//! compila, no dispara con sus muestras, dispara con las benignas o se pasa de
//! su presupuesto de coste, esta prueba falla y con ella `make ci`
//! (`tools/verificar-contenido.sh`): un paquete que rompe un motor no puede
//! llegar a publicarse porque no llega ni a fusionarse.
//!
//! `AEGIS_CONTENIDO_FUENTE` apunta a otro arbol: la puerta lo usa para
//! demostrar que muerde con una copia rota a proposito.

use std::path::PathBuf;

use aegis_contenido::fuente::leer_arbol;
use aegis_contenido::publicar::preparar;
use aegis_contenido::{Anillo, Destino, Historial, Validadores};

fn raiz() -> PathBuf {
    match std::env::var_os("AEGIS_CONTENIDO_FUENTE") {
        Some(r) => PathBuf::from(r),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contenido"),
    }
}

#[test]
fn el_contenido_del_repositorio_pasa_la_puerta_de_publicacion() {
    let raiz = raiz();
    let borrador = leer_arbol(&raiz).unwrap_or_else(|e| panic!("arbol fuente: {e}"));
    assert!(
        !borrador.entradas.is_empty(),
        "{} no tiene reglas",
        raiz.display()
    );
    let firmable = preparar(
        borrador,
        Destino {
            epoca: 1,
            generado_ns: 0,
            anillo: Anillo::canario(&["maq:puerta-de-ci"]),
            escalera: Vec::new(),
            revierte_a: 0,
        },
        &Historial::nuevo(),
        &Validadores::por_defecto(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "el contenido de {} NO se puede publicar: {e}",
            raiz.display()
        )
    });

    // Lineas para el registro de make ci, generadas desde lo medido.
    let m = firmable.manifiesto();
    for (e, i) in m.entradas.iter().zip(firmable.informes()) {
        println!(
            "AEGIS-CONTENIDO regla={} tipo={} modo={} activa={} pasos_por_byte={}/{} \
             micros_64k={}/{}",
            e.id,
            e.tipo.nombre(),
            e.modo.nombre(),
            e.activa,
            i.pasos_por_byte,
            e.coste.pasos_por_byte,
            i.micros_por_64k.unwrap_or(0),
            aegis_contenido::validar::tope_efectivo_us(e.coste.micros_por_64k),
        );
    }
    println!(
        "AEGIS-CONTENIDO total reglas={} bytes_cuerpo={}",
        m.entradas.len(),
        firmable.cuerpo().len()
    );
}
