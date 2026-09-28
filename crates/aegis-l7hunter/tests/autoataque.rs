//! Autoataque del cazador de TLS en claro (FASE 107).
//!
//! El propio cazador es la mayor fuga potencial de la maquina: ve las contrasenas,
//! los tokens y las cookies en claro. Se comprueba que (a) lo capturado sale SIEMPRE
//! redactado y la difusion no puede exceder el presupuesto (FASE 78); (b) un binario
//! despojado del que no se puede derivar el offset produce NoConcluyente, jamas una
//! lectura a ciegas; y (c) un gancho no verificado no se usa.

use aegis_l7hunter::desplazamiento::Fuente;
use aegis_l7hunter::{
    derivar, verificar_canario, CapturaEnClaro, Desplazamiento, FuenteOffset, PoliticaRedaccion,
    PresupuestoDifusion,
};

#[test]
fn los_uprobes_no_pueden_filtrar_secretos_en_claro() {
    // Trafico con lo mas sensible: contrasena, token y cabecera Authorization.
    let bruto = "POST /login\r\nAuthorization: Bearer eyJ.token.secreto\r\n\r\nuser=alice&password=hunter2&api_key=AK99";
    let c = CapturaEnClaro::capturar(bruto, &PoliticaRedaccion::estricta());
    let t = c.texto_redactado();
    for secreto in ["hunter2", "AK99", "eyJ.token.secreto"] {
        assert!(
            !t.contains(secreto),
            "el secreto «{secreto}» no puede salir: {t}"
        );
    }
    // Y aunque este redactado, la difusion tiene tope: no se puede sacar sin fin.
    let mut p = PresupuestoDifusion::nuevo(c.tam()); // solo cabe una vez
    assert!(p.intentar_difundir(&c));
    assert!(
        !p.intentar_difundir(&c),
        "la segunda excede el presupuesto (FASE 78)"
    );
}

struct SinNada;
impl Fuente for SinNada {
    fn clase(&self) -> FuenteOffset {
        FuenteOffset::AnalisisBinario
    }
    fn derivar(&self, _: &str) -> Option<u64> {
        None // un binario despojado del que ni el analisis saca el offset
    }
}

#[test]
fn un_binario_despojado_da_noconcluyente_no_basura() {
    let d = derivar("crypto/tls.(*Conn).Write", &[&SinNada]);
    assert!(matches!(d, Desplazamiento::NoConcluyente { .. }));
    assert_eq!(d.offset(), None, "jamas un offset a ciegas");
}

#[test]
fn un_gancho_no_verificado_no_se_usa() {
    // El offset era plausible pero el gancho lee basura: la verificacion en
    // caliente lo caza y el gancho no se usa.
    let e = verificar_canario(b"AEGIS-CANARIO", b"otra-cosa");
    assert!(!e.se_puede_usar());
}
