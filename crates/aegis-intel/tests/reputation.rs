//! Pruebas del cliente de reputacion contra un servidor real.
//!
//! # Por que hay un servidor de verdad y no un doble
//!
//! La propiedad que este modulo promete es "el sufijo del hash no sale del
//! equipo". Un doble de transporte que devuelve cadenas no puede demostrar eso:
//! demuestra que el codigo llama a una funcion. Lo que lo demuestra es
//! **mirar los bytes que llegan al otro lado del socket**, y para eso hace
//! falta un socket.
//!
//! El servidor de estas pruebas escucha en `127.0.0.1:0`, habla HTTP/1.1 de
//! verdad y **guarda todas las peticiones recibidas** para poder afirmar sobre
//! ellas.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use aegis_intel::cache::CacheLookup;
use aegis_intel::client::Origin;
use aegis_intel::hash::{Digest256, Prefix, Suffix};
use aegis_intel::protocol::{self, BucketEntry};
use aegis_intel::transport::{HttpTransport, Transport, TransportError};
use aegis_intel::verdict::{Record, Reputation};
use aegis_intel::{ReputationCache, ReputationClient};

// ---------------------------------------------------------------------------
// Servidor de reputacion real
// ---------------------------------------------------------------------------

/// Como responde el servidor a una peticion.
#[derive(Clone)]
enum Respuesta {
    /// Cubo normal.
    Cubo,
    /// Cubo con `n` entradas de relleno sinteticas bajo el prefijo pedido.
    ///
    /// Sirve para probar un cubo grande sin buscar colisiones reales de hash:
    /// el cliente compara sufijos, y un sufijo sintetico que no sea el del
    /// objetivo no casa, que es justo lo que un vecino de cubo hace.
    CuboRelleno(usize),
    /// Codigo de error HTTP.
    Error(u16),
    /// Cuerpo literal, para probar formatos raros.
    Crudo(String),
    /// Respuesta troceada.
    Troceada(String),
    /// Cierra sin responder.
    Corta,
}

struct Servidor {
    addr: String,
    /// Rutas recibidas, en orden.
    peticiones: Arc<Mutex<Vec<String>>>,
    /// Todo lo que llego por el socket, byte a byte.
    crudo: Arc<Mutex<Vec<String>>>,
    _hilo: std::thread::JoinHandle<()>,
}

impl Servidor {
    fn arrancar(corpus: Vec<(Digest256, Record)>, modo: Respuesta) -> Servidor {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let peticiones = Arc::new(Mutex::new(Vec::new()));
        let crudo = Arc::new(Mutex::new(Vec::new()));

        let p = peticiones.clone();
        let c = crudo.clone();
        let hilo = std::thread::spawn(move || {
            for flujo in l.incoming() {
                let Ok(s) = flujo else { break };
                if atender(s, &corpus, &modo, &p, &c).is_err() {
                    continue;
                }
            }
        });

        Servidor {
            addr,
            peticiones,
            crudo,
            _hilo: hilo,
        }
    }

    fn transporte(&self) -> HttpTransport {
        HttpTransport::new(self.addr.clone())
    }

    fn rutas(&self) -> Vec<String> {
        self.peticiones.lock().unwrap().clone()
    }

    fn bytes_recibidos(&self) -> Vec<String> {
        self.crudo.lock().unwrap().clone()
    }
}

fn benigno_comun_srv() -> Record {
    Record {
        reputation: Reputation::Benign,
        confidence: 100,
        first_seen_age_s: 400 * 24 * 3600,
        prevalence: 5_000_000,
    }
}

fn atender(
    mut s: TcpStream,
    corpus: &[(Digest256, Record)],
    modo: &Respuesta,
    peticiones: &Arc<Mutex<Vec<String>>>,
    crudo: &Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let mut r = BufReader::new(s.try_clone()?);
    let mut completo = String::new();
    let mut primera = String::new();
    r.read_line(&mut primera)?;
    completo.push_str(&primera);
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 {
            break;
        }
        completo.push_str(&h);
        if h.trim().is_empty() {
            break;
        }
    }
    crudo.lock().unwrap().push(completo);

    let ruta = primera.split_whitespace().nth(1).unwrap_or("").to_string();
    peticiones.lock().unwrap().push(ruta.clone());

    match modo {
        Respuesta::Corta => return Ok(()),
        Respuesta::Error(c) => {
            let cuerpo = "no";
            write!(
                s,
                "HTTP/1.1 {c} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
                cuerpo.len()
            )?;
            return Ok(());
        }
        Respuesta::Crudo(cuerpo) => {
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
                cuerpo.len()
            )?;
            return Ok(());
        }
        Respuesta::Troceada(cuerpo) => {
            write!(
                s,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )?;
            // Troceado a proposito en pedazos pequenos y desiguales.
            for trozo in cuerpo.as_bytes().chunks(37) {
                write!(s, "{:x}\r\n", trozo.len())?;
                s.write_all(trozo)?;
                write!(s, "\r\n")?;
            }
            write!(s, "0\r\n\r\n")?;
            return Ok(());
        }
        Respuesta::Cubo | Respuesta::CuboRelleno(_) => {}
    }

    // El servidor solo conoce el PREFIJO. Filtra su corpus por el, que es
    // exactamente lo que puede hacer un servidor real: devolver el cubo entero
    // sin saber cual de sus miembros interesa.
    let prefijo = ruta.rsplit('/').next().unwrap_or("");
    let entradas: Vec<BucketEntry> = corpus
        .iter()
        .filter(|(d, _)| d.prefix().as_str() == prefijo)
        .map(|(d, r)| BucketEntry {
            suffix: d.suffix(),
            record: *r,
        })
        .collect();

    let mut entradas = entradas;
    if let Respuesta::CuboRelleno(n) = modo {
        for i in 0..*n {
            // 59 digitos hexadecimales deterministas: un vecino de cubo cuyo
            // sufijo nunca coincide con el del objetivo real.
            let suf = format!("{i:059x}");
            let suf = &suf[suf.len() - 59..];
            if let Ok(suffix) = Suffix::parse(suf) {
                entradas.push(BucketEntry {
                    suffix,
                    record: benigno_comun_srv(),
                });
            }
        }
    }

    let cuerpo = protocol::render_bucket(&entradas);
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        cuerpo.len()
    )?;
    s.write_all(cuerpo.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

fn malicioso() -> Record {
    Record {
        reputation: Reputation::Malicious,
        confidence: 98,
        first_seen_age_s: 3600,
        prevalence: 12,
    }
}

fn benigno_comun() -> Record {
    Record {
        reputation: Reputation::Benign,
        confidence: 100,
        first_seen_age_s: 400 * 24 * 3600,
        prevalence: 5_000_000,
    }
}

fn benigno_raro() -> Record {
    Record {
        reputation: Reputation::Benign,
        confidence: 70,
        first_seen_age_s: 2 * 24 * 3600,
        prevalence: 4,
    }
}

/// Dos huellas distintas que comparten prefijo.
///
/// Se encuentran por paradoja del cumpleanos: sobre un espacio de prefijos de
/// 20 bits, una colision aparece tras ~1.000 candidatos, asi que esto termina
/// en unos milisegundos y sin depender de la suerte, a diferencia de buscar un
/// prefijo concreto (que cuesta ~un millon de intentos).
fn par_con_prefijo_comun() -> (Digest256, Digest256) {
    use std::collections::HashMap;
    let mut visto: HashMap<String, Digest256> = HashMap::new();
    for i in 0..1_000_000u64 {
        let d = Digest256::of(format!("par-fixture-{i}").as_bytes());
        let p = d.prefix().as_str().to_string();
        if let Some(&otro) = visto.get(&p) {
            if otro != d {
                return (otro, d);
            }
        } else {
            visto.insert(p, d);
        }
    }
    panic!("no se encontro un par con prefijo comun");
}

// ---------------------------------------------------------------------------
// 1. La propiedad de privacidad, comprobada sobre el socket
// ---------------------------------------------------------------------------

/// **La prueba central del modulo.** Se miran los bytes que de verdad cruzaron
/// el socket y se exige que el sufijo del hash no este entre ellos.
#[test]
fn el_sufijo_del_hash_no_cruza_el_socket() {
    let d = Digest256::of(b"un binario cualquiera del usuario");
    let srv = Servidor::arrancar(vec![(d, malicioso())], Respuesta::Cubo);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(d, 0);
    assert_eq!(r.record.reputation, Reputation::Malicious);
    assert_eq!(r.origin, Origin::Network);

    let recibido = srv.bytes_recibidos().join("\n");
    let hex = d.to_hex();
    let sufijo = d.suffix().as_str().to_string();

    assert!(
        !recibido.contains(&hex),
        "el hash completo llego al servidor"
    );
    assert!(
        !recibido.contains(&sufijo),
        "el sufijo llego al servidor: es exactamente lo que no puede pasar"
    );
    assert!(
        recibido.contains(d.prefix().as_str()),
        "el prefijo si tiene que llegar, o no hay consulta"
    );

    // Y de forma exacta: la ruta es el prefijo y nada mas.
    assert_eq!(srv.rutas(), vec![format!("/v1/rep/{}", d.prefix())]);
    assert_eq!(d.prefix().as_str().len(), 5);
}

/// Ninguna cabecera distinta de la de otro cliente: una cabecera caracteristica
/// reintroduce por la puerta de atras la correlacion que el k-anonimato quita.
#[test]
fn la_peticion_no_lleva_nada_que_identifique_al_cliente() {
    let d = Digest256::of(b"x");
    let srv = Servidor::arrancar(vec![], Respuesta::Cubo);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());
    c.lookup(d, 0);

    let pet = srv.bytes_recibidos().join("").to_ascii_lowercase();
    for prohibida in ["user-agent", "cookie", "authorization", "x-", "referer"] {
        assert!(
            !pet.contains(prohibida),
            "la peticion lleva {prohibida:?}:\n{pet}"
        );
    }
}

/// Un cubo grande no delata cual interesaba: el servidor ve una consulta y
/// devuelve mil candidatos, y la eleccion ocurre en el cliente.
#[test]
fn el_servidor_devuelve_el_cubo_entero_y_el_cliente_elige() {
    let objetivo = Digest256::of(b"el fichero que de verdad interesa");
    let prefijo = objetivo.prefix().as_str().to_string();

    // El cubo se construye con 1.024 vecinos sinteticos bajo el mismo prefijo,
    // que es el tamano real de un cubo de 20 bits sobre mil millones de hashes.
    // No se buscan colisiones reales: el cliente compara sufijos, y ninguno de
    // los rellenos casa con el del objetivo.
    let srv = Servidor::arrancar(vec![(objetivo, malicioso())], Respuesta::CuboRelleno(1024));
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(objetivo, 0);
    assert_eq!(
        r.record.reputation,
        Reputation::Malicious,
        "el objetivo tiene que encontrarse entre mil candidatos"
    );
    assert!(
        c.stats().bucket_entries >= 1000,
        "deberia haber recibido el cubo entero: {}",
        c.stats().bucket_entries
    );
    // El servidor solo vio el prefijo, cualquiera que fuese el tamano del cubo.
    assert_eq!(srv.rutas(), vec![format!("/v1/rep/{prefijo}")]);
}

// ---------------------------------------------------------------------------
// 2. Cache
// ---------------------------------------------------------------------------

/// La cache es parte del mecanismo de privacidad: cada consulta que evita es
/// informacion que el servidor no recibe.
#[test]
fn la_segunda_consulta_no_sale_a_la_red() {
    let d = Digest256::of(b"binario repetido");
    let srv = Servidor::arrancar(vec![(d, benigno_comun())], Respuesta::Cubo);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    assert_eq!(c.lookup(d, 0).origin, Origin::Network);
    for i in 1..100 {
        assert_eq!(c.lookup(d, i).origin, Origin::Cache);
    }
    assert_eq!(srv.rutas().len(), 1, "solo una consulta en 100 ejecuciones");
    assert_eq!(c.stats().lookups, 100);
    assert_eq!(c.stats().queries, 1);
    assert!(c.stats().local_fraction() > 0.98);
}

/// Cache **negativa**: sin ella, un fichero desconocido que se ejecuta cada
/// minuto genera una consulta por minuto para siempre.
#[test]
fn un_desconocido_tambien_se_cachea() {
    let d = Digest256::of(b"nadie ha visto esto jamas");
    let srv = Servidor::arrancar(vec![], Respuesta::Cubo);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(d, 0);
    assert_eq!(r.record.reputation, Reputation::Unknown);
    assert_eq!(r.origin, Origin::Network);

    for i in 1..60 {
        assert_eq!(c.lookup(d, i * 60).origin, Origin::Cache);
    }
    assert_eq!(srv.rutas().len(), 1);

    // Pero caduca en una hora: merece la pena volver a preguntar pronto.
    assert_eq!(c.lookup(d, 3601).origin, Origin::Network);
    assert_eq!(srv.rutas().len(), 2);
}

/// Cada veredicto caduca segun con que facilidad puede cambiar.
#[test]
fn cada_veredicto_caduca_a_su_ritmo() {
    let dia = 24 * 3600;
    assert_eq!(malicioso().ttl_s(), 7 * dia);
    assert_eq!(benigno_comun().ttl_s(), 30 * dia);
    assert_eq!(
        benigno_raro().ttl_s(),
        dia,
        "un benigno poco extendido pudo haber sido comprometido"
    );
    assert_eq!(Record::unknown().ttl_s(), 3600);

    let d = Digest256::of(b"z");
    let mut cache = ReputationCache::new(16);
    cache.put(d, benigno_comun(), 1000);
    assert!(matches!(
        cache.get(&d, 1000 + 29 * dia),
        CacheLookup::Hit(_)
    ));
    assert_eq!(cache.get(&d, 1000 + 30 * dia), CacheLookup::Expired);
}

/// La cota dura es lo que hace que el presupuesto de 50 MB del agente se cumpla
/// siempre y no casi siempre.
#[test]
fn la_cache_no_crece_por_encima_de_su_capacidad() {
    let mut cache = ReputationCache::new(64);
    for i in 0..10_000u64 {
        cache.put(Digest256::of(&i.to_le_bytes()), benigno_comun(), i);
    }
    assert_eq!(cache.len(), 64);
    assert!(cache.stats().evicted >= 9_936);
}

/// LRU y no FIFO: lo que se usa se queda.
#[test]
fn el_desalojo_respeta_lo_que_se_esta_usando() {
    let mut cache = ReputationCache::new(3);
    let a = Digest256::of(b"a");
    let b = Digest256::of(b"b");
    let c = Digest256::of(b"c");
    let d = Digest256::of(b"d");

    cache.put(a, benigno_comun(), 0);
    cache.put(b, benigno_comun(), 0);
    cache.put(c, benigno_comun(), 0);

    // Se usa `a`, que pasa a ser el mas reciente.
    assert!(matches!(cache.get(&a, 1), CacheLookup::Hit(_)));
    cache.put(d, benigno_comun(), 1);

    assert!(
        matches!(cache.get(&a, 2), CacheLookup::Hit(_)),
        "a se usaba"
    );
    assert_eq!(cache.get(&b, 2), CacheLookup::Miss, "b era el mas antiguo");
    assert!(matches!(cache.get(&d, 2), CacheLookup::Hit(_)));
}

#[test]
fn la_purga_retira_lo_caducado_y_la_invalidacion_lo_puntual() {
    let mut cache = ReputationCache::new(64);
    for i in 0..10u64 {
        cache.put(Digest256::of(&i.to_le_bytes()), Record::unknown(), 0);
    }
    let perenne = Digest256::of(b"perenne");
    cache.put(perenne, benigno_comun(), 0);

    assert_eq!(cache.len(), 11);
    assert_eq!(cache.purge(3601), 10, "los desconocidos caducan a la hora");
    assert_eq!(cache.len(), 1);

    assert!(cache.invalidate(&perenne));
    assert!(!cache.invalidate(&perenne));
    assert!(cache.is_empty());
}

// ---------------------------------------------------------------------------
// 3. La nube nunca esta en la ruta de decision
// ---------------------------------------------------------------------------

/// Un servidor caido no puede ser un error para el llamante: la arquitectura
/// entera esta construida para que la nube sea opcional.
#[test]
fn sin_servidor_se_responde_desconocido_y_no_se_falla() {
    // Puerto cerrado: se reserva y se suelta.
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let mut t = HttpTransport::new(addr);
    t.timeout = std::time::Duration::from_millis(250);

    let mut c = ReputationClient::new(t, ReputationCache::default());
    let d = Digest256::of(b"algo");
    let r = c.lookup(d, 0);

    assert_eq!(r.origin, Origin::Offline);
    assert_eq!(r.record.reputation, Reputation::Unknown);
    assert_eq!(c.stats().failures, 1);

    // Y NO se cachea: la proxima vez hay que volver a intentarlo.
    let r2 = c.lookup(d, 1);
    assert_eq!(r2.origin, Origin::Offline);
    assert_eq!(c.stats().queries, 2);
}

#[test]
fn un_error_del_servidor_se_trata_como_estar_sin_red() {
    let srv = Servidor::arrancar(vec![], Respuesta::Error(503));
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());
    let r = c.lookup(Digest256::of(b"algo"), 0);
    assert_eq!(r.origin, Origin::Offline);
    assert_eq!(c.stats().failures, 1);
}

#[test]
fn un_servidor_que_cuelga_la_conexion_no_cuelga_al_agente() {
    let srv = Servidor::arrancar(vec![], Respuesta::Corta);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());
    assert_eq!(c.lookup(Digest256::of(b"algo"), 0).origin, Origin::Offline);
}

// ---------------------------------------------------------------------------
// 4. Robustez del protocolo
// ---------------------------------------------------------------------------

/// Un servidor mas nuevo que anada campos no puede dejar inservible al cliente:
/// un cliente sin reputacion es un cliente que decide a ciegas.
#[test]
fn las_lineas_con_campos_de_mas_se_siguen_entendiendo() {
    let d = Digest256::of(b"futuro");
    let cuerpo = format!("{}:m:90:100:5:un_campo_nuevo:y_otro\n", d.suffix().as_str());
    let srv = Servidor::arrancar(vec![], Respuesta::Crudo(cuerpo));
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(d, 0);
    assert_eq!(r.record.reputation, Reputation::Malicious);
    assert_eq!(c.stats().discarded_lines, 0);
}

/// Pero una linea a medias se tira entera: aceptarla a medias seria inventarse
/// un veredicto.
#[test]
fn las_lineas_rotas_se_descartan_sin_tumbar_el_resto() {
    let bueno = Digest256::of(b"bueno");
    let cuerpo = format!(
        "# comentario\n\
         basura\n\
         {}:m:90:100:5\n\
         soloesto:m:1:1:1\n\
         {}:x:90:100:5\n\
         {}:m:900:100:5\n\
         \n",
        bueno.suffix().as_str(),
        Digest256::of(b"otro").suffix().as_str(),
        Digest256::of(b"tercero").suffix().as_str(),
    );
    let srv = Servidor::arrancar(vec![], Respuesta::Crudo(cuerpo));
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(bueno, 0);
    assert_eq!(r.record.reputation, Reputation::Malicious);
    assert_eq!(
        c.stats().discarded_lines,
        4,
        "basura, sufijo corto, veredicto invalido y confianza fuera de rango"
    );
    assert_eq!(c.stats().bucket_entries, 1);
}

/// El transporte tiene que hablar `chunked`: es lo que produce cualquier
/// servidor que comprima al vuelo, que es como se sirve un cubo de 70 KB.
#[test]
fn la_respuesta_troceada_se_reensambla() {
    let d = Digest256::of(b"troceado");
    let mut cuerpo = String::new();
    for i in 0..50 {
        cuerpo.push_str(&format!(
            "{}:b:50:10:7\n",
            Digest256::of(&[i as u8]).suffix().as_str()
        ));
    }
    cuerpo.push_str(&format!("{}:m:99:60:2\n", d.suffix().as_str()));

    let srv = Servidor::arrancar(vec![], Respuesta::Troceada(cuerpo));
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup(d, 0);
    assert_eq!(r.record.reputation, Reputation::Malicious);
    assert_eq!(c.stats().bucket_entries, 51);
}

#[test]
fn una_respuesta_desmesurada_se_rechaza() {
    let grande = "a".repeat(aegis_intel::transport::RESPUESTA_MAX + 1024);
    let srv = Servidor::arrancar(vec![], Respuesta::Crudo(grande));
    let t = srv.transporte();
    match t.fetch("/v1/rep/00000") {
        Err(TransportError::TooLarge { .. }) => {}
        otro => panic!("se esperaba TooLarge, llego {otro:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Huellas
// ---------------------------------------------------------------------------

#[test]
fn el_reparto_entre_prefijo_y_sufijo_es_exacto_y_reversible() {
    let d = Digest256::of(b"contenido");
    let hex = d.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(d.prefix().as_str().len(), 5);
    assert_eq!(d.suffix().as_str().len(), 59);
    assert_eq!(format!("{}{}", d.prefix(), d.suffix().as_str()), hex);
    assert_eq!(Digest256::parse(&hex).unwrap(), d);
}

/// El `Debug` del sufijo no puede revelarlo: un `derive` habria acabado
/// escribiendo la parte secreta del hash en el primer registro de error.
#[test]
fn el_sufijo_no_aparece_en_su_propia_representacion() {
    let d = Digest256::of(b"secreto");
    let s = d.suffix();
    let texto = format!("{s:?}");
    assert!(
        !texto.contains(s.as_str()),
        "el Debug del sufijo lo revela: {texto}"
    );
    assert!(texto.contains("ocultos"), "{texto}");
}

#[test]
fn las_huellas_mal_formadas_se_rechazan_con_su_motivo() {
    use aegis_intel::HashError;
    assert!(matches!(
        Digest256::parse("abc"),
        Err(HashError::Length { found: 3, .. })
    ));
    assert!(matches!(
        Digest256::parse(&"z".repeat(64)),
        Err(HashError::NotHex('z'))
    ));
    assert!(matches!(
        Prefix::parse("abcdef"),
        Err(HashError::Length { found: 6, .. })
    ));
    assert!(Prefix::parse("ABCDE").is_ok(), "se acepta en mayusculas");
    assert!(matches!(
        Suffix::parse("corto"),
        Err(HashError::Length { .. })
    ));
}

/// Sobre un fichero real del disco y por bloques: un fichero de 4 GB no cabe en
/// el presupuesto de memoria del agente.
#[test]
fn la_huella_de_un_fichero_real_coincide_con_la_de_su_contenido() {
    let p = std::env::temp_dir().join(format!("aegis-intel-{}.bin", std::process::id()));
    let mut datos = Vec::new();
    for i in 0..300_000u32 {
        datos.extend_from_slice(&i.to_le_bytes());
    }
    std::fs::write(&p, &datos).unwrap();

    let a = Digest256::of_file(&p).unwrap();
    let b = Digest256::of(&datos);
    let _ = std::fs::remove_file(&p);

    assert_eq!(a, b, "el hasheo por bloques tiene que dar lo mismo");
    assert!(datos.len() > 64 * 1024, "y el fichero cruza varios bloques");
}

// ---------------------------------------------------------------------------
// 6. Consulta agrupada
// ---------------------------------------------------------------------------

/// Agrupar por prefijo no es solo eficiencia: dos ficheros que comparten
/// prefijo se resuelven con UNA consulta, con lo que el servidor ve menos
/// peticiones y con menos estructura temporal que correlacionar.
#[test]
fn varias_huellas_con_el_mismo_prefijo_se_resuelven_en_una_consulta() {
    let (a, b) = par_con_prefijo_comun();
    assert_eq!(a.prefix(), b.prefix());

    // Un tercero con prefijo distinto: cualquier huella lo es con probabilidad
    // abrumadora, pero se comprueba para que la prueba no dependa de ello.
    let mut otro = Digest256::of(b"tercero con otro prefijo");
    let mut n = 0u64;
    while otro.prefix() == a.prefix() {
        n += 1;
        otro = Digest256::of(format!("tercero-{n}").as_bytes());
    }

    let srv = Servidor::arrancar(
        vec![
            (a, malicioso()),
            (b, benigno_comun()),
            (otro, benigno_raro()),
        ],
        Respuesta::Cubo,
    );
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    let r = c.lookup_many(&[a, b, otro], 0);
    assert_eq!(r[0].record.reputation, Reputation::Malicious);
    assert_eq!(r[1].record.reputation, Reputation::Benign);
    assert_eq!(r[2].record.reputation, Reputation::Benign);
    assert_eq!(r[2].record.prevalence, 4);

    assert_eq!(
        srv.rutas().len(),
        2,
        "tres huellas y dos prefijos: dos consultas, no tres. rutas={:?}",
        srv.rutas()
    );
    assert_eq!(c.stats().lookups, 3);
    assert_eq!(c.stats().queries, 2);

    // Y la segunda vez, ninguna.
    let r = c.lookup_many(&[a, b, otro], 1);
    assert!(r.iter().all(|x| x.origin == Origin::Cache));
    assert_eq!(srv.rutas().len(), 2);
}

#[test]
fn la_precarga_evita_la_primera_consulta() {
    let d = Digest256::of(b"binario comun del despliegue");
    let srv = Servidor::arrancar(vec![(d, benigno_comun())], Respuesta::Cubo);
    let mut c = ReputationClient::new(srv.transporte(), ReputationCache::default());

    c.preload(
        d,
        &[BucketEntry {
            suffix: d.suffix(),
            record: benigno_comun(),
        }],
        0,
    );
    let r = c.lookup(d, 0);
    assert_eq!(r.origin, Origin::Cache);
    assert_eq!(r.record.reputation, Reputation::Benign);
    assert!(srv.rutas().is_empty(), "no deberia haber salido a la red");
}
