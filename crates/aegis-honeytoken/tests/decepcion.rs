//! Decepcion activa de extremo a extremo, con validacion por parsers REALES.
//!
//! Sin mocks: los artefactos senuelo se validan con los mismos parsers que
//! usaria el atacante (ssh-key, roxmltree) —una credencial que no parsea no
//! engana—, el marcador se acuna con HMAC real, y el ciclo sembrar -> tocar ->
//! disparar se ejercita sobre memoria y ficheros de verdad.

use aegis_honeytoken::credformat::{render, Artefacto};
use aegis_honeytoken::memtoken::{parsear_maps, planificar};
use aegis_honeytoken::registry::Registro;
use aegis_honeytoken::respuesta::decidir_respuesta;
use aegis_honeytoken::token::{Acunador, Atribucion, Marcador};
use aegis_honeytoken::trip::{clasificar, ComoDisparo, Evento};
use std::collections::HashMap;

fn atrib() -> Atribucion {
    Atribucion {
        host: "web-07".to_string(),
        proceso: "sshd".to_string(),
        token_id: 42,
    }
}

// --- Marcador atribuible ----------------------------------------------------

#[test]
fn el_marcador_es_determinista_e_infalsificable() {
    let a = Acunador::new([0x11; 32]);
    let m1 = a.acunar(&atrib());
    let m2 = a.acunar(&atrib());
    assert_eq!(m1, m2, "mismo secreto y atribucion -> mismo marcador");
    assert!(a.verificar(&atrib(), &m1), "el marcador autentico verifica");

    // Un atacante con OTRO secreto no puede reproducir el marcador.
    let atacante = Acunador::new([0x22; 32]);
    assert!(
        !atacante.verificar(&atrib(), &m1),
        "sin el secreto de flota no se puede falsificar el marcador"
    );

    // Dos atribuciones distintas no colisionan.
    let otra = Atribucion {
        token_id: 43,
        ..atrib()
    };
    assert_ne!(a.acunar(&otra), m1);
}

#[test]
fn el_marcador_sobrevive_al_ida_y_vuelta_hex() {
    let a = Acunador::new([0x33; 32]);
    let m = a.acunar(&atrib());
    let recuperado = Marcador::desde_hex(&m.hex()).unwrap();
    assert_eq!(m, recuperado);
}

// --- Credenciales creibles: validadas por parsers reales --------------------

#[test]
fn la_clave_ssh_senuelo_parsea_como_openssh_real() {
    let a = Acunador::new([0x44; 32]);
    let m = a.acunar(&atrib());
    let linea = render(Artefacto::ClaveSshAutorizada, &m);
    // El atacante la parsearia con una libreria OpenSSH: tiene que parsear.
    let clave = ssh_key::PublicKey::from_openssh(&linea)
        .expect("la clave senuelo debe parsear como OpenSSH de verdad");
    // Y el marcador viaja en el comentario, que el atacante conserva.
    assert!(
        clave.comment().contains(&m.hex()),
        "el marcador esta en el comentario"
    );
}

#[test]
fn el_credentials_xml_senuelo_parsea_como_xml_real() {
    let a = Acunador::new([0x55; 32]);
    let m = a.acunar(&atrib());
    let xml = render(Artefacto::CredentialsXml, &m);
    let doc = roxmltree::Document::parse(&xml).expect("el XML senuelo debe ser XML valido");
    // El marcador esta en la cuenta.
    let hay = doc
        .descendants()
        .filter(|n| n.has_tag_name("account"))
        .any(|n| n.text().map(|t| t.contains(&m.hex())).unwrap_or(false));
    assert!(hay, "el marcador esta en <account>");
}

#[test]
fn los_artefactos_de_texto_llevan_el_marcador() {
    let a = Acunador::new([0x66; 32]);
    let m = a.acunar(&atrib());
    for art in [Artefacto::PgpassLinea, Artefacto::ShadowLinea] {
        assert!(
            render(art, &m).contains(&m.hex()),
            "el artefacto {art:?} debe llevar el marcador"
        );
    }
}

// --- El ciclo sembrar -> tocar -> disparar ----------------------------------

#[test]
fn leer_el_token_de_la_memoria_dispara_con_atribucion() {
    let a = Acunador::new([0x77; 32]);
    let m = a.acunar(&atrib());
    let mut reg = Registro::new();
    reg.registrar(&m, atrib());

    // Simula un volcado de la memoria de sshd que el atacante se llevo: bytes
    // cualquiera con la credencial senuelo (y su marcador) dentro.
    let mut volcado = vec![0xABu8; 1024];
    volcado.extend_from_slice(render(Artefacto::PgpassLinea, &m).as_bytes());
    volcado.extend_from_slice(&[0xCD; 512]);

    let disparos = clasificar(
        &Evento::LecturaMemoria {
            lector: "mimikatz-like".to_string(),
            contenido: volcado,
        },
        &reg,
        &HashMap::new(),
    );
    assert_eq!(disparos.len(), 1, "el marcador aparece: un disparo");
    assert_eq!(disparos[0].token, atrib(), "atribuido al senuelo correcto");
    assert!(matches!(
        disparos[0].como,
        ComoDisparo::LeidoDeMemoria { .. }
    ));

    // La respuesta a robo de credenciales es la maxima: aislar y volcar.
    let r = decidir_respuesta(&disparos[0]);
    assert!(r.aislar && r.volcar_memoria && r.severidad == 4);
}

#[test]
fn memoria_sin_marcador_no_dispara() {
    let a = Acunador::new([0x88; 32]);
    let m = a.acunar(&atrib());
    let mut reg = Registro::new();
    reg.registrar(&m, atrib());
    // Un volcado que NO contiene el marcador: nada que atribuir, nada que gritar.
    let disparos = clasificar(
        &Evento::LecturaMemoria {
            lector: "proceso-legitimo".to_string(),
            contenido: vec![0x00; 4096],
        },
        &reg,
        &HashMap::new(),
    );
    assert!(
        disparos.is_empty(),
        "sin marcador no hay disparo: evita el falso positivo"
    );
}

#[test]
fn abrir_un_honey_file_dispara_y_se_siembra_de_verdad() {
    use aegis_honeytoken::honeyfile::sembrar;
    let a = Acunador::new([0x99; 32]);
    let m = a.acunar(&atrib());

    let dir = std::env::temp_dir().join(format!("aegis-honey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join(".pgpass");
    let hf = sembrar(&ruta, Artefacto::PgpassLinea, m, atrib()).unwrap();
    // Se escribio de verdad, con el marcador dentro.
    let en_disco = std::fs::read_to_string(&hf.ruta).unwrap();
    assert!(en_disco.contains(&hf.marcador.hex()));

    let mut rutas = HashMap::new();
    rutas.insert(ruta.to_str().unwrap().to_string(), atrib());

    let disparos = clasificar(
        &Evento::AperturaFichero {
            lector: "curioso".to_string(),
            ruta: ruta.to_str().unwrap().to_string(),
        },
        &Registro::new(),
        &rutas,
    );
    assert_eq!(disparos.len(), 1);
    let r = decidir_respuesta(&disparos[0]);
    assert!(r.aislar && !r.volcar_memoria && r.severidad == 3);

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Planificacion sobre /proc/maps real ------------------------------------

#[test]
fn planificar_lee_el_mapa_de_memoria_real_de_este_proceso() {
    // Sobre el propio proceso: /proc/self/maps existe siempre en Linux y tiene
    // al menos una region escribible (la pila).
    let regiones = planificar(std::process::id() as i32).expect("leer /proc/self/maps");
    assert!(
        !regiones.is_empty(),
        "todo proceso tiene alguna region escribible donde sembrar"
    );
    assert!(regiones.iter().all(|r| r.tamano() > 0));
}

#[test]
fn parsear_maps_selecciona_solo_lo_escribible_y_anonimo() {
    // Muestra con el formato real de /proc/maps.
    let muestra = "\
55e0aa000000-55e0aa021000 r-xp 00000000 08:01 100 /usr/bin/app\n\
55e0aa220000-55e0aa221000 rw-p 00021000 08:01 100 /usr/bin/app\n\
7f0000000000-7f0000021000 rw-p 00000000 00:00 0 \n\
7fffffffe000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n\
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]\n";
    let regiones = parsear_maps(muestra);
    // Se quedan: el mapeo anonimo rw y la pila. Se descartan: el codigo r-x, la
    // region rw respaldada por /usr/bin/app, y el vsyscall r-x.
    assert_eq!(regiones.len(), 2);
    assert!(regiones.iter().any(|r| r.etiqueta == "[stack]"));
    assert!(regiones.iter().any(|r| r.etiqueta.is_empty()));
}
