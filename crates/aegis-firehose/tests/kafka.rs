//! El destino Kafka, y lo que se pudo comprobar de el.
//!
//! # Que se comprueba aqui y que no
//!
//! No hay corredor de Kafka en este entorno: la politica de red bloquea los
//! archivos de Apache y no hay ninguno accesible. La verificacion de extremo a
//! extremo esta escrita y es ejecutable —`tools/verificar-kafka.sh`—, pero no
//! se ha podido ejecutar, y eso se dice en vez de darlo por hecho.
//!
//! Lo que SI se comprueba, contra la biblioteca y el sistema reales, es la
//! propiedad cuya rotura seria catastrofica: **un destino inalcanzable nunca
//! devuelve exito**. Importa mas que cualquier otra porque un exito falso hace
//! que la bomba confirme y BORRE del diario evidencia que no llego a ninguna
//! parte: el sistema entero informaria de que todo va bien mientras la
//! auditoria desaparece. Un fallo al entregar solo cuesta un reintento.

#![cfg(feature = "kafka")]

use aegis_firehose::destino::Destino;
use aegis_firehose::kafka::{ConfigKafka, DestinoKafka};

fn config(corredores: &str) -> ConfigKafka {
    ConfigKafka {
        corredores: corredores.to_string(),
        tema: "aegis-auditoria".to_string(),
        // Corto: la prueba comprueba que FALLA, no cuanto tarda en rendirse.
        plazo: std::time::Duration::from_millis(1500),
        extra: Vec::new(),
    }
}

#[test]
fn un_corredor_inalcanzable_nunca_devuelve_exito() {
    // El puerto 1 con nada escuchando. Si esto devolviera `Ok`, la bomba
    // confirmaria y borraria del diario evidencia que no salio de la maquina.
    let mut d = DestinoKafka::nuevo(config("127.0.0.1:1")).unwrap();
    let carga = b"registro de auditoria".as_slice();
    let r = d.entregar(&[carga]);
    assert!(
        r.is_err(),
        "un corredor inalcanzable NO puede reportar entrega: seria borrar del \
         diario evidencia que nunca salio"
    );
}

#[test]
fn un_extremo_que_acepta_pero_no_habla_kafka_tampoco_devuelve_exito() {
    // Mas dificil que el anterior y mas realista: un balanceador delante de un
    // servicio muerto acepta el TCP y no contesta nada. Un cliente que tomara
    // la conexion establecida por entrega confirmada perderia el lote entero.
    let escucha = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let direccion = escucha.local_addr().unwrap().to_string();
    let _mudo = std::thread::spawn(move || {
        // Se acepta y se mantiene abierto sin decir nada.
        let conexiones: Vec<_> = escucha.incoming().take(8).flatten().collect();
        std::thread::sleep(std::time::Duration::from_secs(20));
        drop(conexiones);
    });

    let mut d = DestinoKafka::nuevo(config(&direccion)).unwrap();
    let carga = b"registro de auditoria".as_slice();
    assert!(
        d.entregar(&[carga]).is_err(),
        "una conexion establecida NO es un acuse de escritura"
    );
}

#[test]
fn una_configuracion_incompleta_se_rechaza_al_construir() {
    // Fallar al arrancar es mejor que arrancar con un destino que nunca
    // entregara nada: lo segundo se descubre cuando alguien busca la evidencia.
    assert!(DestinoKafka::nuevo(config("")).is_err());
    let mut sin_tema = config("127.0.0.1:9092");
    sin_tema.tema = String::new();
    assert!(DestinoKafka::nuevo(sin_tema).is_err());
}

#[test]
fn los_ajustes_de_durabilidad_no_se_pueden_relajar_desde_la_configuracion() {
    // `acks=1` haria que el lider acusara ANTES de replicar: si muere en ese
    // instante, el registro se pierde con el visto bueno del productor y la
    // bomba ya lo habra borrado del diario. Que un despliegue pueda ponerlo
    // "por rendimiento" no es una opcion.
    let mut cfg = config("127.0.0.1:1");
    cfg.extra = vec![
        ("acks".to_string(), "1".to_string()),
        ("enable.idempotence".to_string(), "false".to_string()),
    ];
    // El productor se construye —los ajustes obligatorios se aplican DESPUES de
    // los del despliegue— y sigue sin poder entregar contra un puerto muerto.
    let mut d = DestinoKafka::nuevo(cfg).expect("los ajustes obligatorios pisan a los del cliente");
    assert!(d.entregar(&[b"x".as_slice()]).is_err());
}
