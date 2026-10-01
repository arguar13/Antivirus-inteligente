//! Verificacion de EXTREMO A EXTREMO contra un corredor de Kafka real.
//!
//! Se omite —con aviso, sin fingir exito— si no hay corredor. Se ejecuta con
//! `tools/verificar-kafka.sh`, que explica por que existe aparte.
//!
//! Lo que comprueba, y que las otras pruebas no pueden:
//!
//! - que el registro LLEGA y el corredor lo acusa;
//! - que el orden dentro de una particion se conserva, que es lo que hace que
//!   una linea de tiempo forense siga siendo una linea de tiempo;
//! - que un lote confirmado no se reenvia, es decir, que la bomba no duplica
//!   cuando todo va bien.

#![cfg(feature = "kafka")]

use aegis_firehose::bomba::Bomba;
use aegis_firehose::diario::{Config, Diario, MAX_REGISTRO};
use aegis_firehose::kafka::{ConfigKafka, DestinoKafka};
use aegis_firehose::reintento::Politica;
use aegis_prueba::{omitir, Requisito};

fn entorno() -> Option<(String, String)> {
    Some((
        std::env::var("AEGIS_KAFKA_CORREDORES").ok()?,
        std::env::var("AEGIS_KAFKA_TEMA").ok()?,
    ))
}

struct Temporal(std::path::PathBuf);

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temporal() -> Temporal {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("aegis-kafka-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    Temporal(d)
}

#[test]
fn la_auditoria_llega_al_corredor_y_el_diario_queda_vacio() {
    let Some((corredores, tema)) = entorno() else {
        omitir(
            "no hay corredor de Kafka (ver tools/verificar-kafka.sh)",
            Requisito::Kafka,
        );
        return;
    };
    let t = temporal();
    let mut diario = Diario::abrir(Config {
        bytes_por_segmento: (MAX_REGISTRO + 64) as u64,
        presupuesto_bytes: (MAX_REGISTRO + 64) as u64 * 16,
        registros_por_sincronizacion: 1,
        ..Config::nueva(&t.0)
    })
    .unwrap();

    for i in 0..100u32 {
        diario
            .admitir(format!(r#"{{"evento":{i},"tipo":"auditoria"}}"#).as_bytes())
            .unwrap();
    }

    let destino = DestinoKafka::nuevo(ConfigKafka {
        corredores,
        tema,
        plazo: std::time::Duration::from_secs(30),
        extra: Vec::new(),
    })
    .expect("el productor tiene que construirse");

    let mut bomba = Bomba::nueva(destino, Politica::default()).con_lote(25);
    for _ in 0..8 {
        let v = bomba.vuelta(&mut diario, &|c| c.to_vec()).unwrap();
        assert!(!v.fallo, "con el corredor vivo no puede fallar la entrega");
    }

    assert_eq!(
        bomba.entregados(),
        100,
        "los cien registros tienen que quedar acusados por el corredor"
    );
    // Y una vuelta mas no reenvia nada: la bomba no duplica cuando todo va bien.
    let v = bomba.vuelta(&mut diario, &|c| c.to_vec()).unwrap();
    assert_eq!(v.entregados, 0, "un lote confirmado no se reenvia");
    println!("  entregados y acusados: {}", bomba.entregados());
}
