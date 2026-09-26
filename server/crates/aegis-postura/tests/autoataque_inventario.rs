//! AUTOATAQUE (FASE 94): el escaner como reconocimiento para el atacante.
//!
//! El inventario de componentes de una maquina es el mapa que un atacante
//! querria. Se comprueba que no sale sin pasar por el estrangulamiento: por
//! CADA canal que existe ([`Canal::todos`]), hacia un destino que no es la propia
//! organizacion, se retiene; el enjambre no lo saca ni hacia dentro; y lo que si
//! sale es un documento valido, que no se puede escribir por otro camino (ver
//! las pruebas `compile_fail` de `aegis_postura::salida`).

use aegis_postura::salida::{exportar, Formato, NoSale, MARCADO_INVENTARIO};
use aegis_sbom::componente::{Componente, Distro, Ecosistema, Procedencia};
use aegis_sbom::Sbom;
use aegis_share::{Canal, Destino, Difusor, Retenido, Tlp};

fn inventario() -> Sbom {
    let mut ssl = Componente::nuevo(
        Ecosistema::Deb,
        "libssl3t64",
        "3.0.13-0ubuntu3.4",
        Procedencia::GestorDePaquetes {
            base: "/var/lib/dpkg/status".into(),
        },
    );
    ssl.fuente = Some("openssl".into());
    ssl.arquitectura = Some("amd64".into());
    ssl.distro = Some(Distro {
        id: "ubuntu".into(),
        version: "24.04".into(),
    });
    let crate_ = Componente::nuevo(
        Ecosistema::Cargo,
        "libc",
        "0.2.153",
        Procedencia::MetadatosDeCompilacion {
            binario: "/usr/bin/sudo".into(),
            formato: "cargo-auditable",
        },
    );
    Sbom {
        componentes: vec![ssl, crate_],
        ..Sbom::default()
    }
}

fn destino(nombre: &str, canal: Canal, propia: bool) -> Destino {
    Destino {
        nombre: nombre.into(),
        canal,
        // El tope mas alto que se puede configurar: si el inventario no sale ni
        // asi, no es porque alguien configuro el destino con cuidado.
        tope_tlp: Tlp::Red,
        es_propia_organizacion: propia,
    }
}

#[test]
fn por_ningun_canal_sale_hacia_fuera_de_la_organizacion() {
    let mut d = Difusor::nuevo();
    for c in Canal::todos() {
        d.declarar(destino(&format!("ajeno-{}", c.nombre()), *c, false));
    }
    for c in Canal::todos() {
        for f in [Formato::CycloneDx, Formato::Spdx] {
            let r = exportar(&inventario(), f, &format!("ajeno-{}", c.nombre()), &d, 0);
            match r {
                Err(NoSale::Retenido(Retenido::FueraDeLaOrganizacion))
                | Err(NoSale::Retenido(Retenido::PorTopeDuroDelCanal { .. })) => {}
                otro => panic!(
                    "{}: el inventario salio o se retuvo por otro motivo: {otro:?}",
                    c.nombre()
                ),
            }
        }
    }
    eprintln!(
        "{} canales, hacia fuera de la organizacion: ninguno lo saca",
        Canal::todos().len()
    );
}

#[test]
fn el_enjambre_no_lo_saca_ni_hacia_la_propia_organizacion() {
    let mut d = Difusor::nuevo();
    d.declarar(destino("malla", Canal::Enjambre, true));
    let r = exportar(&inventario(), Formato::CycloneDx, "malla", &d, 0);
    assert!(
        matches!(
            r,
            Err(NoSale::Retenido(Retenido::PorTopeDuroDelCanal { .. }))
        ),
        "el enjambre llega a maquinas que el atacante puede haber comprometido: {r:?}"
    );
}

#[test]
fn un_destino_no_declarado_es_un_error_y_no_un_permiso() {
    let d = Difusor::nuevo();
    let r = exportar(&inventario(), Formato::Spdx, "quien-sea", &d, 0);
    assert_eq!(r, Err(NoSale::DestinoDesconocido("quien-sea".into())));
}

#[test]
fn un_destino_propio_con_tope_bajo_no_lo_recibe() {
    let mut d = Difusor::nuevo();
    let mut x = destino("soc-verde", Canal::Exportacion, true);
    x.tope_tlp = Tlp::Green;
    d.declarar(x);
    let r = exportar(&inventario(), Formato::CycloneDx, "soc-verde", &d, 0);
    assert!(
        matches!(r, Err(NoSale::Retenido(Retenido::PorTlp { .. }))),
        "{r:?}"
    );
}

#[test]
fn hacia_la_propia_organizacion_sale_un_cyclonedx_y_un_spdx_validos() {
    let mut d = Difusor::nuevo();
    d.declarar(destino("soc", Canal::Exportacion, true));
    let cdx = exportar(
        &inventario(),
        Formato::CycloneDx,
        "soc",
        &d,
        1_700_000_000_000_000_000,
    )
    .expect("sale hacia dentro");
    let v: serde_json::Value = serde_json::from_str(&cdx.contenido).unwrap();
    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.5");
    // Dos bibliotecas y el sistema operativo del que depende el paquete deb.
    let comps = v["components"].as_array().unwrap();
    assert_eq!(comps.len(), 3);
    assert!(comps.iter().any(|c| c["type"] == "operating-system"
        && c["name"] == "ubuntu"
        && c["version"] == "24.04"));
    assert_eq!(v["dependencies"][0]["ref"], "os:ubuntu@24.04");
    // El paquete fuente, en la forma que leen los consumidores.
    assert!(cdx.contenido.contains("\"aquasecurity:trivy:SrcName\""));
    assert!(v["components"][0]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["value"] == "openssl"));
    assert_eq!(
        v["dependencies"][0]["dependsOn"].as_array().unwrap().len(),
        1,
        "del sistema depende el paquete deb, no la crate"
    );
    assert_eq!(
        v["components"][0]["purl"],
        "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04&upstream=openssl"
    );
    assert_eq!(v["metadata"]["timestamp"], "2023-11-14T22:13:20Z");
    // El marcado viaja dentro del documento: quien lo reciba sabe como tratarlo.
    assert!(cdx.contenido.contains("TLP:AMBER+STRICT"));

    let spdx = exportar(&inventario(), Formato::Spdx, "soc", &d, 0).unwrap();
    let v: serde_json::Value = serde_json::from_str(&spdx.contenido).unwrap();
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["packages"].as_array().unwrap().len(), 2);
    assert_eq!(v["relationships"].as_array().unwrap().len(), 2);
    assert_eq!(
        v["packages"][1]["externalRefs"][0]["referenceLocator"],
        "pkg:cargo/libc@0.2.153"
    );

    // Reproducible: el mismo inventario, el mismo documento.
    let otra = exportar(
        &inventario(),
        Formato::CycloneDx,
        "soc",
        &d,
        1_700_000_000_000_000_000,
    )
    .unwrap();
    assert_eq!(cdx.contenido, otra.contenido);
}

#[test]
fn el_marcado_del_inventario_es_solo_la_propia_organizacion() {
    assert_eq!(MARCADO_INVENTARIO.tlp, Tlp::AmberStrict);
}
