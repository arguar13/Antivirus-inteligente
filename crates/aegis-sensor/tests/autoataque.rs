//! Autoataque: la inundacion de eventos como ceguera.
//!
//! El atacante genera ruido para llenar el anillo y tapar su accion. Se comprueba
//! que (a) la perdida NO es silenciosa —se cuenta y se dice como `SinDatos`—, y
//! (b) la degradacion por presupuesto PRIORIZA por valor, conservando lo que mas
//! importa. Tapar con ruido no puede convertir «perdi eventos» en «no paso nada».

use aegis_entidad::{arbitrar, entidad, Juicio, Motor, Resultado};
use aegis_sensor::{Familia, Sensor};

#[test]
fn inundar_una_familia_no_la_convierte_en_limpia() {
    // El atacante inunda la familia de red para tapar su baliza. El sensor pierde
    // eventos, los cuenta, y el arbitro ve SinDatos en ese plano, no «limpio».
    let mut s = Sensor::nuevo();
    s.registrar_perdida(Familia::Red, 1_000_000);
    let ent = entidad::contenido("baliza");
    let senales: Vec<_> = s
        .senales_sin_datos(&ent, 1)
        .into_iter()
        .filter(|sig| sig.motor == Motor::Wire)
        .collect();
    assert!(
        !senales.is_empty(),
        "la perdida de red tiene que producir señal"
    );
    assert!(senales
        .iter()
        .all(|sig| sig.juicio == Juicio::NoConcluyente));
    assert!(
        senales[0].porque.contains("hueco de cobertura"),
        "la señal dice que es un hueco, no una ausencia: {}",
        senales[0].porque
    );
    assert_eq!(arbitrar(&ent, &senales, 1).resultado, Resultado::SinDatos);
}

#[test]
fn bajo_presion_extrema_se_conserva_lo_de_mas_valor() {
    // Presupuesto ridiculo: se apagan casi todas, pero la ejecucion de procesos
    // —la de mas valor— se conserva hasta el final.
    let mut s = Sensor::nuevo();
    // Presupuesto = coste de proceso: solo cabe proceso.
    let apagadas = s.degradar(Familia::Proceso.costo());
    assert!(!apagadas.is_empty());
    assert!(
        s.activa(Familia::Proceso),
        "la ejecucion de procesos se conserva bajo presion"
    );
    // Y las apagadas se DICEN como SinDatos.
    let ciegas = s.familias_ciegas();
    assert!(
        ciegas.contains(&Familia::Perf),
        "perf, de bajo valor, se apago"
    );
    assert!(!ciegas.contains(&Familia::Proceso));
}

#[test]
fn la_perdida_se_cuenta_por_familia_no_en_un_solo_numero() {
    // Falco publica un contador global; aqui la cuenta es POR FAMILIA, que es lo
    // que permite decir en que plano hay ceguera.
    let mut s = Sensor::nuevo();
    s.registrar_perdida(Familia::Red, 10);
    s.registrar_perdida(Familia::Memoria, 3);
    assert_eq!(s.estado(Familia::Red).perdidos, 10);
    assert_eq!(s.estado(Familia::Memoria).perdidos, 3);
    assert_eq!(s.estado(Familia::Proceso).perdidos, 0);
    assert_eq!(s.perdida_total(), 13);
}
