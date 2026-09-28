//! Autoataque de la procedencia (FASE 108): la actualizacion como via de ejecucion.
//!
//! El canal de actualizacion es el sueno de un atacante: si logra que el agente
//! aplique SU binario, ejecuta codigo con privilegios en toda la flota. Se recorren
//! las variantes —artefacto cambiado, firma que no verifica, cadena rota, no
//! reproducible, y un registro de transparencia reescrito— y se comprueba que
//! ninguna abre la puerta.

use aegis_procedencia::transparencia::hash_hoja;
use aegis_procedencia::{
    prueba_consistencia, raiz, verificar_antes_de_aplicar, verificar_consistencia, Atestacion,
    Bitacora, PoliticaAplicacion, Sbom,
};

fn sbom() -> Sbom {
    Sbom {
        huella_esperada: [7u8; 32],
    }
}
fn atest_legitima() -> Atestacion {
    Atestacion {
        huella_artefacto: [7u8; 32],
        reproducible: true,
        firma_valida: true,
        cadena_completa: true,
    }
}

#[test]
fn ninguna_variante_de_actualizacion_maliciosa_se_aplica() {
    let pol = PoliticaAplicacion::estricta();
    let mut b = Bitacora::nueva();

    // 1. El atacante mete SU artefacto (otra huella) con firma «valida».
    let mut cambiado = atest_legitima();
    cambiado.huella_artefacto = [0xEE; 32];
    assert!(!b.evaluar_y_registrar(&cambiado, &sbom(), pol).se_aplica());

    // 2. Firma que no verifica.
    let mut sin_firma = atest_legitima();
    sin_firma.firma_valida = false;
    assert!(!b.evaluar_y_registrar(&sin_firma, &sbom(), pol).se_aplica());

    // 3. Cadena de procedencia rota (falta un eslabon).
    let mut sin_cadena = atest_legitima();
    sin_cadena.cadena_completa = false;
    assert!(!b.evaluar_y_registrar(&sin_cadena, &sbom(), pol).se_aplica());

    // 4. No reproducible: no se puede confirmar que salio de la fuente auditada.
    let mut sin_repro = atest_legitima();
    sin_repro.reproducible = false;
    assert!(!b.evaluar_y_registrar(&sin_repro, &sbom(), pol).se_aplica());

    // Las cuatro se rechazaron y se registraron.
    assert_eq!(
        b.rechazos(),
        4,
        "cada rechazo se registra para investigarlo"
    );

    // Y la legitima si se aplica: la puerta no es un muro que lo bloquea todo.
    assert!(verificar_antes_de_aplicar(&atest_legitima(), &sbom(), pol).se_aplica());
}

#[test]
fn un_registro_de_transparencia_reescrito_se_detecta() {
    // El agente recordaba la raiz al tamano 4. El operador (o un atacante que
    // comprometio el registro) reescribe una atestacion vieja para ocultar una
    // actualizacion maliciosa ya aplicada, y presenta un registro de tamano 6.
    let honesto: Vec<_> = (0..6)
        .map(|i| hash_hoja(format!("v{i}").as_bytes()))
        .collect();
    let raiz_recordada = raiz(&honesto[..4]);

    let mut forjado = honesto.clone();
    forjado[1] = hash_hoja(b"v1-REESCRITA-PARA-OCULTAR");
    let raiz_forjada = raiz(&forjado);
    let prueba = prueba_consistencia(&forjado, 4);

    assert!(
        !verificar_consistencia(4, 6, raiz_recordada, raiz_forjada, &prueba),
        "un registro que reescribio la historia NO es consistente con lo que el agente recordaba"
    );
}
