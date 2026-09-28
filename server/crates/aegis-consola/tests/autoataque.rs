//! Autoataque de la consola (FASE 110): la interfaz como via de fuga y de abuso.
//!
//! Una consola es una superficie de ataque nueva: (a) un camino de salida para
//! sacar lo que la politica retiene, (b) una via para que un rol haga lo que no le
//! toca, y (c) una fuga entre inquilinos. Se comprueba que las tres se cierran.

use aegis_consola::{autorizar, exportar, filtrar, DeInquilino, Exportacion, Permiso, Rol, Sesion};
use aegis_share::{Canal, Destino, Marcado, Pap, Tlp};

#[test]
fn la_consola_no_es_un_camino_de_salida_para_lo_retenido() {
    // Un analista intenta exportar un indicador TLP:RED. No sale: pasa por el
    // mismo juez de difusion (FASE 78) que todo lo demas.
    let destino = Destino {
        nombre: "descarga".into(),
        canal: Canal::Exportacion,
        tope_tlp: Tlp::Red,
        es_propia_organizacion: true,
    };
    let rojo = Marcado::nuevo(Tlp::Red, Pap::Red);
    assert_eq!(
        exportar(rojo, false, &destino),
        Exportacion::Retenida {
            motivo: "TLP:RED: no se distribuye por ningun canal, ni siquiera exportando a fichero"
                .into()
        }
    );
}

#[test]
fn un_rol_no_hace_lo_que_no_le_toca() {
    // Un analista intenta aislar la flota (contener). Denegado con motivo.
    assert!(autorizar(Rol::Analista, Permiso::Contener).is_err());
    // Un auditor intenta cualquier cosa que no sea leer. Denegado.
    assert!(autorizar(Rol::Auditor, Permiso::TrabajarCaso).is_err());
    assert!(autorizar(Rol::Auditor, Permiso::Exportar).is_err());
    // Lo que si les toca, pasa.
    assert!(autorizar(Rol::Responsable, Permiso::Contener).is_ok());
    assert!(autorizar(Rol::Auditor, Permiso::Leer).is_ok());
}

struct Caso {
    inquilino: String,
}
impl DeInquilino for Caso {
    fn inquilino(&self) -> &str {
        &self.inquilino
    }
}

#[test]
fn un_inquilino_no_ve_los_casos_de_otro() {
    let sesion = Sesion {
        usuario: "ana".into(),
        inquilino: "cliente-a".into(),
        rol: Rol::Analista,
    };
    let casos = vec![
        Caso {
            inquilino: "cliente-a".into(),
        },
        Caso {
            inquilino: "cliente-b".into(),
        },
        Caso {
            inquilino: "cliente-b".into(),
        },
    ];
    let vistos = filtrar(&sesion, &casos);
    assert_eq!(vistos.len(), 1, "solo el caso de cliente-a");
    assert!(vistos.iter().all(|c| c.inquilino == "cliente-a"));
}
