//! Autoataque de la atestacion (FASE 105): la atestacion como arma.
//!
//! La atestacion protege a la flota, pero tambien puede volverse contra ella:
//!  - Como DENEGACION DE SERVICIO: si el atacante provoca fallos de atestacion,
//!    revocar media flota la derriba. El freno pegajoso (FASE 71) lo corta.
//!  - Como LAVADO DE AUTORIDAD: un nodo comprometido intenta dar ordenes en la
//!    malla; un par no acepta autoridad de quien no esta atestado.
//!  - Como POLITICA DESINCRONIZADA: una politica de PCR contradictoria; el tipo la
//!    rechaza en el sitio, no en produccion.

use aegis_attest::{
    ErrorPolitica, ErrorRevocacion, EstadoNodo, LimitadorRevocacion, Par, PoliticaPcr,
};
use aegis_entidad::Confianza;

#[test]
fn revocar_media_flota_lo_corta_la_degradacion_pegajosa() {
    // Flota de 10 000, tope 20 % = 2000. El atacante fuerza 6000 «fallos».
    let mut lim = LimitadorRevocacion::nuevo(10_000, 2000);
    let mut aplicadas = 0usize;
    let mut cortadas = 0usize;
    for _ in 0..6000 {
        match lim.intentar_revocar() {
            Ok(_) => aplicadas += 1,
            Err(ErrorRevocacion::TopeAlcanzado(_)) => cortadas += 1,
        }
    }
    assert_eq!(
        aplicadas, 2000,
        "solo hasta el tope: no se derriba la flota"
    );
    assert_eq!(cortadas, 4000);
    assert!(
        lim.esta_pegado(),
        "el freno queda pegado hasta el rearme manual"
    );
}

#[test]
fn un_nodo_comprometido_no_lava_su_autoridad_en_la_malla() {
    let par = Par;
    // El nodo fallo la atestacion (revocado): sus pares no le obedecen.
    assert!(!par.acepta_autoridad_de(&EstadoNodo::revocado()));
    // Uno atestado si tiene autoridad.
    assert!(par.acepta_autoridad_de(&EstadoNodo::atestado(Confianza::nueva(75))));
}

#[test]
fn una_politica_de_pcr_no_puede_desincronizarse_en_contradiccion() {
    // Un fichero de politica podria pedir dos valores incompatibles para el mismo
    // PCR y nadie lo notaria hasta produccion. El tipo lo rechaza al construirlo.
    let p = PoliticaPcr::nueva().exigir_igual(7, vec![0x11]).unwrap();
    assert_eq!(
        p.exigir_igual(7, vec![0x22]),
        Err(ErrorPolitica::Contradiccion(7))
    );
}
