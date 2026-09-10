//! El diario, probado contra el sistema de ficheros REAL.
//!
//! Nada de imitaciones: los ficheros se escriben, se corrompen a mano y se
//! vuelven a abrir. Un diario que solo funciona contra un sistema de ficheros
//! imaginario no sirve para lo unico que tiene que hacer, que es sobrevivir a
//! que la maquina se apague de golpe.

use std::io::{Seek, SeekFrom, Write};

use aegis_firehose::diario::{Config, Diario, PoliticaLleno, MAX_REGISTRO};
use aegis_firehose::ErrorFirehose;

/// Directorio temporal propio, sin dependencias.
struct Temporal(std::path::PathBuf);

impl Temporal {
    fn nuevo(etiqueta: &str) -> Temporal {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("aegis-diario-{etiqueta}-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        Temporal(d)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Config pequena para que las pruebas ejerzan la rotacion de verdad.
fn config(dir: &std::path::Path) -> Config {
    Config {
        bytes_por_segmento: (MAX_REGISTRO + 64) as u64,
        presupuesto_bytes: (MAX_REGISTRO + 64) as u64 * 8,
        registros_por_sincronizacion: 1,
        ..Config::nueva(dir)
    }
}

#[test]
fn lo_admitido_sobrevive_a_que_el_proceso_desaparezca() {
    // El caso que justifica todo el modulo: el plano de control muere con
    // registros sin entregar. Al volver, tienen que seguir ahi.
    let t = Temporal::nuevo("sobrevive");
    {
        let mut d = Diario::abrir(config(&t.0)).unwrap();
        for i in 0..50u32 {
            d.admitir(format!("evento-{i}").as_bytes()).unwrap();
        }
        // Se suelta sin confirmar nada: equivale a un `kill -9`.
    }

    let d = Diario::abrir(config(&t.0)).unwrap();
    let leidos = d.leer_desde(None, 100).unwrap();
    assert_eq!(
        leidos.len(),
        50,
        "no puede perderse ni un registro admitido"
    );
    assert_eq!(leidos[0].carga, b"evento-0");
    assert_eq!(leidos[49].carga, b"evento-49");
}

#[test]
fn una_escritura_a_medias_se_trunca_y_no_se_envia_como_auditoria() {
    // El proceso murio EN MITAD de escribir. Sin el CRC, al reiniciar se leeria
    // una longitud plausible seguida de basura y se enviaria al SIEM un registro
    // de auditoria inventado. Un registro falso es peor que uno perdido: el
    // perdido se nota, el falso no.
    let t = Temporal::nuevo("amedias");
    {
        let mut d = Diario::abrir(config(&t.0)).unwrap();
        d.admitir(b"entero-1").unwrap();
        d.admitir(b"entero-2").unwrap();
    }

    // Se simula la muerte a media escritura anadiendo una cabecera valida y
    // solo parte de su carga.
    let segmento = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "diario"))
        .unwrap();
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&segmento)
            .unwrap();
        f.write_all(&0x4147_5257u32.to_le_bytes()).unwrap(); // magia
        f.write_all(&64u32.to_le_bytes()).unwrap(); // dice 64 bytes
        f.write_all(&0u32.to_le_bytes()).unwrap(); // crc
        f.write_all(b"solo diez ").unwrap(); // ...pero solo hay 10
    }

    let d = Diario::abrir(config(&t.0)).unwrap();
    let leidos = d.leer_desde(None, 100).unwrap();
    assert_eq!(leidos.len(), 2, "lo entero se conserva");
    assert_eq!(d.contadores().truncados, 1, "y la cola rota se contabiliza");
}

#[test]
fn un_registro_alterado_no_se_entrega() {
    // No es un ataque criptografico —para eso el CRC no serviria— sino la otra
    // mitad del mismo problema: un sector que el disco devuelve mal. Enviarlo
    // al SIEM seria firmar como auditoria algo que nadie escribio.
    let t = Temporal::nuevo("alterado");
    {
        let mut d = Diario::abrir(config(&t.0)).unwrap();
        d.admitir(b"primero").unwrap();
        d.admitir(b"segundo").unwrap();
    }
    let segmento = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "diario"))
        .unwrap();
    {
        // Se cambia un byte de la carga del PRIMER registro.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&segmento)
            .unwrap();
        f.seek(SeekFrom::Start(12)).unwrap();
        f.write_all(b"X").unwrap();
    }

    let d = Diario::abrir(config(&t.0)).unwrap();
    assert!(
        d.leer_desde(None, 100).unwrap().is_empty(),
        "un registro con el CRC roto no puede salir hacia el SIEM"
    );
}

#[test]
fn confirmar_libera_el_disco_pero_nunca_lo_no_entregado() {
    let t = Temporal::nuevo("confirmar");
    let mut d = Diario::abrir(config(&t.0)).unwrap();
    let mut posiciones = Vec::new();
    // Cada registro llena casi un segmento entero, asi que esto rota de verdad.
    let relleno = vec![b'x'; MAX_REGISTRO / 2];
    for _ in 0..6 {
        posiciones.push(d.admitir(&relleno).unwrap());
    }
    let ocupado_antes = d.ocupado().unwrap();

    // Se confirma hasta el cuarto: los tres primeros segmentos se pueden ir.
    d.confirmar_hasta(posiciones[4]).unwrap();
    assert!(
        d.ocupado().unwrap() < ocupado_antes,
        "confirmar tiene que liberar disco"
    );

    // Lo NO confirmado sigue entero: es la propiedad de la que depende todo.
    let quedan = d.leer_desde(Some(posiciones[4]), 100).unwrap();
    assert_eq!(quedan.len(), 2, "lo no confirmado no se toca");
}

#[test]
fn con_el_presupuesto_agotado_se_rechaza_ruidosamente_por_defecto() {
    // Un EDR que llenara el disco del cliente para no perder un registro habria
    // cambiado un fallo por otro peor: la maquina entera deja de funcionar,
    // incluido el propio EDR. Y la eleccion por defecto falla RUIDOSAMENTE:
    // quien produce el registro se entera.
    let t = Temporal::nuevo("lleno");
    let mut cfg = config(&t.0);
    cfg.presupuesto_bytes = (MAX_REGISTRO + 64) as u64 * 2;
    let mut d = Diario::abrir(cfg).unwrap();

    let relleno = vec![b'x'; MAX_REGISTRO / 2];
    let mut error = None;
    for _ in 0..20 {
        if let Err(e) = d.admitir(&relleno) {
            error = Some(e);
            break;
        }
    }
    assert!(
        matches!(error, Some(ErrorFirehose::DiarioLleno { .. })),
        "el productor tiene que enterarse de que el diario esta lleno"
    );
    assert!(d.contadores().rechazados > 0, "y el rechazo se cuenta");
}

#[test]
fn la_politica_de_descarte_cuenta_lo_que_tira() {
    // La otra eleccion legitima: seguir aceptando lo reciente a costa de lo
    // viejo. Lo que no puede pasar es que lo tirado desaparezca sin dejar
    // rastro: un registro de auditoria que se pierde en silencio es
    // exactamente lo que un atacante quiere.
    let t = Temporal::nuevo("descarte");
    let mut cfg = config(&t.0);
    cfg.presupuesto_bytes = (MAX_REGISTRO + 64) as u64 * 2;
    cfg.politica_lleno = PoliticaLleno::DescartarMasAntiguos;
    let mut d = Diario::abrir(cfg).unwrap();

    let relleno = vec![b'x'; MAX_REGISTRO / 2];
    for _ in 0..12 {
        d.admitir(&relleno).unwrap();
    }
    assert!(
        d.contadores().descartados > 0,
        "lo descartado tiene que quedar contabilizado"
    );
    assert!(
        d.ocupado().unwrap() <= (MAX_REGISTRO + 64) as u64 * 3,
        "el presupuesto tiene que respetarse de verdad"
    );
}

#[test]
fn un_registro_desmesurado_se_rechaza_antes_de_tocar_el_disco() {
    // Un registro de auditoria es un evento, no un volcado de memoria. Sin
    // techo, un productor equivocado se come el presupuesto de una vez.
    let t = Temporal::nuevo("gigante");
    let mut d = Diario::abrir(config(&t.0)).unwrap();
    let enorme = vec![b'x'; MAX_REGISTRO + 1];
    assert!(matches!(
        d.admitir(&enorme),
        Err(ErrorFirehose::RegistroDesmesurado { .. })
    ));
    assert_eq!(d.ocupado().unwrap(), 0, "no puede haber llegado al disco");
}

#[test]
fn una_configuracion_imposible_se_rechaza_al_abrir() {
    // Un segmento que no admite ni un registro maximo dejaria el diario en un
    // bucle de rotacion infinita la primera vez que llegara uno grande. Mejor
    // no arrancar que arrancar roto.
    let t = Temporal::nuevo("configmala");
    let mut cfg = Config::nueva(&t.0);
    cfg.bytes_por_segmento = 1024;
    assert!(matches!(Diario::abrir(cfg), Err(ErrorFirehose::Config(_))));
}

#[test]
fn leer_no_consume_para_que_un_fallo_de_envio_no_pierda_nada() {
    // Confirmar al leer convertiria "al menos una vez" en "como mucho una vez",
    // que es justo lo contrario de lo que hace falta en auditoria: si el envio
    // falla despues de leer, el registro tiene que seguir ahi.
    let t = Temporal::nuevo("leernoconsume");
    let mut d = Diario::abrir(config(&t.0)).unwrap();
    d.admitir(b"a").unwrap();
    d.admitir(b"b").unwrap();

    let primera = d.leer_desde(None, 10).unwrap();
    let segunda = d.leer_desde(None, 10).unwrap();
    assert_eq!(primera.len(), 2);
    assert_eq!(segunda.len(), 2, "leer no puede consumir");
    assert_eq!(primera[0].posicion, segunda[0].posicion);
}
