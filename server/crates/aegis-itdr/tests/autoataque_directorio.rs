//! AUTOATAQUE (FASE 95): el grafo del directorio como mapa para el atacante.
//!
//! El grafo completo del directorio —quien puede sobre quien en toda la
//! organizacion— es exactamente el mapa que un atacante querria antes de elegir
//! por donde escalar. Se comprueba que no sale del plano de control sin pasar por
//! el estrangulamiento unico del producto: por CADA canal que existe, hacia un
//! destino que no es la propia organizacion, se retiene; el enjambre no lo saca ni
//! hacia dentro; y lo que si sale es un documento valido, que no se puede armar
//! por otro camino (ver las pruebas `compile_fail` de
//! `aegis_itdr::directorio::salida`).

use aegis_itdr::directorio::objeto::{ClasePrincipal, Principal, Sid};
use aegis_itdr::directorio::relacion::{Arista, RelacionDirectorio};
use aegis_itdr::directorio::salida::{exportar, NoSale};
use aegis_itdr::directorio::GrafoDirectorio;
use aegis_share::{Canal, Destino, Difusor, Retenido, Tlp};

fn grafo() -> GrafoDirectorio {
    let mut g = GrafoDirectorio::nuevo();
    g.agregar_principal(Principal::nuevo(
        Sid::nuevo("S-1-5-21-1-2-3-1104"),
        ClasePrincipal::Usuario,
        "becario",
    ))
    .unwrap();
    g.agregar_principal(Principal::nuevo(
        Sid::nuevo("S-1-5-21-1-2-3-512"),
        ClasePrincipal::Grupo,
        "Domain Admins",
    ))
    .unwrap();
    g.conectar(Arista::permanente(
        &Sid::nuevo("S-1-5-21-1-2-3-1104"),
        &Sid::nuevo("S-1-5-21-1-2-3-512"),
        RelacionDirectorio::EscrituraDacl,
    ))
    .unwrap();
    g
}

fn destino(nombre: &str, canal: Canal, propia: bool) -> Destino {
    Destino {
        nombre: nombre.into(),
        canal,
        // El tope mas alto que se puede configurar: si el grafo no sale ni asi, no
        // es porque alguien configuro el destino con cuidado.
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
        let r = exportar(&grafo(), &format!("ajeno-{}", c.nombre()), &d);
        match r {
            Err(NoSale::Retenido(Retenido::FueraDeLaOrganizacion))
            | Err(NoSale::Retenido(Retenido::PorTopeDuroDelCanal { .. })) => {}
            otro => panic!(
                "{}: el grafo salio o se retuvo por otro motivo: {otro:?}",
                c.nombre()
            ),
        }
    }
    eprintln!(
        "{} canales, hacia fuera de la organizacion: ninguno saca el grafo del directorio",
        Canal::todos().len()
    );
}

#[test]
fn el_enjambre_no_lo_saca_ni_hacia_dentro() {
    // El canal del enjambre tiene un tope duro de GREEN: ni siquiera hacia la
    // propia organizacion puede llevar un grafo marcado AMBER+STRICT.
    let mut d = Difusor::nuevo();
    d.declarar(destino("par-enjambre", Canal::Enjambre, true));
    match exportar(&grafo(), "par-enjambre", &d) {
        Err(NoSale::Retenido(Retenido::PorTopeDuroDelCanal { .. })) => {}
        otro => panic!("el enjambre no puede transportar el grafo del directorio: {otro:?}"),
    }
}

#[test]
fn a_un_destino_no_declarado_no_sale() {
    let d = Difusor::nuevo();
    assert!(matches!(
        exportar(&grafo(), "fantasma", &d),
        Err(NoSale::DestinoDesconocido(_))
    ));
}
