//! El capturador como arma contra su propio dueno.
//!
//! # Las dos formas de volver esto en contra
//!
//! Un capturador es, por diseno, el sitio donde se acumula todo lo que paso por
//! la red. Eso lo convierte en dos cosas a la vez:
//!
//! 1. **Un sitio del que robar.** Si guarda credenciales, quien consiga leer el
//!    almacen se lleva las contrasenas de todos los usuarios de la ultima
//!    semana. No hace falta comprometer el agente: basta con el disco.
//! 2. **Una forma de llenar el disco.** Si guarda todo lo que le echen, quien
//!    genere trafico decide cuando se queda sin espacio la maquina — y una
//!    maquina sin espacio deja de escribir registros, que es apagar la defensa
//!    por la puerta de atras.
//!
//! Las dos se prueban aqui, y las dos se paran con una propiedad **estructural**
//! y no con un limite configurable: la primera porque el anillo solo acepta
//! [`Limpio`], y la segunda porque el anillo no crece y la retencion por defecto
//! no guarda contenido.

use aegis_captura::anillo::Anillo;
use aegis_captura::redaccion::{AmbitoSensible, Donde, Redactor};
use aegis_captura::retencion::{Autorizacion, Decision};
use aegis_captura::{Capturador, Flujo, Limpio, Politica, Suerte};
use aegis_entidad::arbitro::{Resultado, Veredicto};
use aegis_entidad::entidad;
use aegis_entidad::escala::{Confianza, Severidad};

fn veredicto(r: Resultado) -> Veredicto {
    Veredicto {
        entidad: entidad::maquina("m1"),
        resultado: r,
        severidad: Severidad::Alta,
        confianza: Confianza::nueva(90),
        porque: "dos planos independientes lo sostienen".to_owned(),
        planos: Vec::new(),
        senales: Vec::new(),
    }
}

/// Todo lo que un atacante podria querer leer del almacen, en el trafico que
/// pasaria por delante de un capturador en una manana cualquiera.
fn trafico_con_secretos() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "http-basica",
            b"GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic YWRtaW46U3VwM3JTM2NyZXQh\r\n\r\n".to_vec(),
        ),
        (
            "http-portador",
            b"GET /api/v1/nominas HTTP/1.1\r\nHost: rrhh\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.ZWxzZWNyZXRv.firma\r\n\r\n".to_vec(),
        ),
        (
            "formulario",
            b"POST /entrar HTTP/1.1\r\nHost: portal\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusuario=director&password=LaDelDirector2026&recordar=1".to_vec(),
        ),
        (
            "clave-de-api",
            b"POST /v1/pagos HTTP/1.1\r\nHost: pasarela\r\nX-API-Key: sk_live_ESTONOPUEDESALIRNUNCA\r\n\r\n{}".to_vec(),
        ),
        (
            "ftp",
            b"USER contable\r\nPASS LaContrasenaDelContable\r\n".to_vec(),
        ),
        (
            "correo",
            b"AUTH PLAIN AGFkbWluAFN1cDNyUzNjcmV0IQ==\r\n".to_vec(),
        ),
        (
            "oauth",
            b"POST /token HTTP/1.1\r\nHost: idp\r\n\r\ngrant_type=client_credentials&client_id=app&client_secret=ELSECRETODELCLIENTE".to_vec(),
        ),
    ]
}

/// Lo que **nunca** puede aparecer en el almacen, ni con autorizacion.
const NUNCA: &[&str] = &[
    "YWRtaW46U3VwM3JTM2NyZXQh",
    "ZWxzZWNyZXRv",
    "LaDelDirector2026",
    "sk_live_ESTONOPUEDESALIRNUNCA",
    "LaContrasenaDelContable",
    "AGFkbWluAFN1cDNyUzNjcmV0IQ==",
    "ELSECRETODELCLIENTE",
];

/// LA prueba de la primera via: con el flujo acusado y autorizado a guardarse
/// **entero**, que es el caso mas favorable al atacante, ninguna credencial llega
/// al almacen.
#[test]
fn ninguna_credencial_llega_al_almacen_ni_con_autorizacion() {
    let mut c = Capturador::nuevo(Redactor::nuevo(), 4 * 1024 * 1024);
    let a =
        Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).expect("malicioso autoriza");

    for (nombre, bytes) in trafico_con_secretos() {
        let mut f = Flujo::nuevo(entidad::maquina(nombre), Donde::default());
        f.decidir(Decision::autorizada(&a));
        assert!(
            matches!(
                c.capturar(&mut f, 1, &bytes, bytes.len()),
                Suerte::Guardado(_)
            ),
            "{nombre} no se guardo y la prueba no probaria nada"
        );
    }

    let guardado: Vec<u8> = c.vaciar().into_iter().flat_map(|p| p.datos).collect();
    let texto = String::from_utf8_lossy(&guardado);
    for secreto in NUNCA {
        assert!(
            !texto.contains(secreto),
            "«{secreto}» llego al almacen: el capturador es el sitio del que se roba"
        );
    }
    // Y lo que SI tiene que estar, porque sin ello la captura no sirve para
    // investigar: quien hablo, con quien y que pidio.
    for debe_estar in [
        "GET /admin",
        "Host: intranet",
        "usuario=director",
        "POST /v1/pagos",
    ] {
        assert!(texto.contains(debe_estar), "falta «{debe_estar}»: {texto}");
    }
}

/// El ambito declarado por el cliente: el sobre se queda y el contenido no sale
/// de su red. Es lo que permite capturar en una clinica sin llevarse el historial.
#[test]
fn el_contenido_de_un_ambito_declarado_no_sale_y_el_sobre_si() {
    let redactor = Redactor::nuevo().con_ambito(AmbitoSensible {
        nombre: "historia clinica".to_owned(),
        anfitriones: vec!["hce.hospital.es".to_owned()],
        puertos: vec![],
    });
    let mut c = Capturador::nuevo(redactor, 1024 * 1024);
    let a = Autorizacion::del_veredicto(&veredicto(Resultado::EnDisputa)).expect("autoriza");
    let mut f = Flujo::nuevo(entidad::maquina("consulta-3"), Donde::default());
    f.decidir(Decision::autorizada(&a));

    let p = b"POST /episodio/8812 HTTP/1.1\r\nHost: hce.hospital.es\r\n\r\n{\"paciente\":\"Ana Ruiz\",\"diagnostico\":\"privado\"}";
    c.capturar(&mut f, 1, p, p.len());

    let guardado: Vec<u8> = c.vaciar().into_iter().flat_map(|p| p.datos).collect();
    let texto = String::from_utf8_lossy(&guardado);
    assert!(!texto.contains("Ana Ruiz"), "{texto}");
    assert!(!texto.contains("diagnostico"), "{texto}");
    // El sobre si: es lo que hace falta para investigar sin ver el contenido.
    assert!(texto.contains("POST /episodio/8812"), "{texto}");
    assert!(texto.contains("hce.hospital.es"), "{texto}");
}

/// LA prueba de la segunda via: quien genere trafico no puede decidir cuanta
/// memoria usa el agente ni cuando se llena el disco.
#[test]
fn quien_genera_trafico_no_decide_cuanta_memoria_usa_el_agente() {
    const ANILLO: usize = 256 * 1024;
    let mut c = Capturador::nuevo(Redactor::nuevo(), ANILLO);
    let a = Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).expect("autoriza");
    let mut f = Flujo::nuevo(entidad::maquina("el-que-inunda"), Donde::default());
    f.decidir(Decision::autorizada(&a));

    // Doscientos mil paquetes de mil quinientos bytes: trescientos megabytes de
    // trafico contra un anillo de doscientos cincuenta y seis kilobytes, que es
    // mil veces su tamano. El numero esta elegido para que la prueba corra en la
    // puerta de calidad sin compilar en modo optimizado: con mil veces el anillo
    // la propiedad ya se ve, y subirlo a un millon solo alarga el CI.
    let paquete = vec![b'x'; 1500];
    for i in 0..200_000u64 {
        c.capturar(&mut f, i, &paquete, paquete.len());
    }

    // La memoria no crecio: el anillo tiene su tamano y no se toca.
    let dentro = c.vaciar();
    let ocupado: usize = dentro.iter().map(|p| p.datos.len()).sum();
    assert!(
        ocupado <= ANILLO,
        "el anillo guarda {ocupado} bytes con una capacidad de {ANILLO}"
    );
    // Y la perdida esta contada: no se tiro nada en silencio.
    let cont = c.contadores();
    assert!(cont.cuadran_en_la_entrada(), "{cont:?}");
    assert!(cont.perdidos() > 0);
    assert!(
        c.frase().contains("SE PERDIERON"),
        "un capturador que suelta en silencio produce capturas incompletas que parecen \
         completas: {}",
        c.frase()
    );
}

/// Y la misma via por el otro lado: sin veredicto, no hay contenido que guardar,
/// asi que el disco no se llena aunque el trafico no pare.
#[test]
fn sin_veredicto_el_trafico_no_llena_el_disco_por_mucho_que_dure() {
    let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
    let paquete = vec![b'x'; 1500];
    let mut vistos = 0u64;
    for n in 0..200u32 {
        let mut f = Flujo::nuevo(entidad::maquina(&format!("m{n}")), Donde::default());
        for i in 0..500u64 {
            c.capturar(&mut f, i, &paquete, paquete.len());
        }
        vistos += f.vistos();
    }
    assert_eq!(
        c.bytes_de_contenido(),
        0,
        "sin veredicto no se guarda ni un byte de contenido"
    );
    assert!(vistos > 100_000_000, "se vieron {vistos} bytes");
    // Y sin embargo el sobre esta: se sabe quien hablo, sin almacenar la
    // conversacion.
    assert_eq!(c.indice().entidades(), 200);
}

/// La politica que el cliente puso no la levanta un veredicto, y eso se prueba
/// con el veredicto mas fuerte que hay.
#[test]
fn un_veredicto_no_levanta_lo_que_el_cliente_prohibio() {
    let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
    let a = Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).expect("autoriza");
    let mut f = Flujo::nuevo(entidad::maquina("red-vetada"), Donde::default());
    f.decidir(Decision::nada("el cliente no retiene esta red"));
    f.decidir(Decision::autorizada(&a));

    assert_eq!(f.decision.politica, Politica::Nada);
    for i in 0..100u64 {
        assert_eq!(
            c.capturar(&mut f, i, b"lo que sea", 10),
            Suerte::ProhibidoPorElCliente
        );
    }
    assert_eq!(c.bytes_de_contenido(), 0);
    assert_eq!(c.indice().cuantas(), 0);
}

/// El anillo como via de agotamiento, medido aparte del capturador: una entrada
/// que no cabe no puede hacer reservar lo que diga.
#[test]
fn un_paquete_imposible_no_hace_reservar_lo_que_diga() {
    let mut a = Anillo::nuevo(64 * 1024);
    let antes = a.capacidad();
    let enorme = Redactor::nuevo().limpiar(&vec![0u8; 8 * 1024 * 1024], Donde::default());
    for _ in 0..1000 {
        assert!(!a.meter(1, &enorme));
    }
    assert_eq!(a.capacidad(), antes);
    assert_eq!(a.contadores.rechazados, 1000);
    assert!(a.cuadran(), "{:?}", a.contadores);
}

/// La propiedad estructural, dicha en una prueba: el anillo no tiene forma de
/// aceptar bytes que no hayan pasado por la redaccion. Si alguien anadiera un
/// `meter_crudo`, esta prueba seguiria pasando — pero el barrido de la puerta de
/// calidad, que busca la ausencia, no.
#[test]
fn el_anillo_solo_acepta_lo_que_paso_por_la_redaccion() {
    let r = Redactor::nuevo();
    let limpio: Limpio = r.limpiar(b"GET / HTTP/1.1\r\n\r\n", Donde::default());
    let mut a = Anillo::nuevo(64 * 1024);
    assert!(a.meter(1, &limpio));
    // Y el tipo lo dice: `Limpio` no tiene constructor publico ni `From`.
    assert!(limpio.intacto());
    assert_eq!(a.contadores.escritos, 1);
}
