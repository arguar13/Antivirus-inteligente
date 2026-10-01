//! El circuito completo: de un paquete en la red a un indicador repartido entre
//! agentes aislados, con **un solo identificador de entidad**.
//!
//! # Por que esta prueba y no once pruebas
//!
//! Cada subsistema ya tiene las suyas, y son mas exigentes que esta sobre lo suyo.
//! Lo que ninguna puede enseñar es lo que falla en la **union**: que el fichero que
//! `aegis-wire` extrae del flujo y el que `aegis-detonate` detona sean, para el
//! sistema, la misma cosa; que el caso que se abre hable de esa cosa y no de un
//! nombre parecido; que el indicador que sale por TAXII se derive de ese mismo
//! veredicto y no de una copia que se quedo atras.
//!
//! Esa union es exactamente lo que un conjunto de productos integrados **no puede
//! dar**: cada uno nombra las cosas a su manera, y la correlacion acaba siendo una
//! heuristica sobre cadenas de texto que casi acierta.
//!
//! # Las once paradas, y lo que se ejerce de verdad en cada una
//!
//! No hay simulacion de subsistemas: en cada parada corre el codigo del subsistema
//! real, con sus estructuras reales.
//!
//! | # | Parada | FASE | Que corre de verdad |
//! |---|---|---|---|
//! | 1 | Paquete en la red | 70 | El motor de `aegis-wire` sobre paquetes IP construidos byte a byte |
//! | 2 | Fichero extraido | 70 | El extractor del flujo, con su SHA-256 |
//! | 3 | Corpus mundial | 72 | Un indice `aegis-ruleforge` **en disco**, con busqueda binaria por `seek` |
//! | 4 | Detonacion | 73 | El receptor de `aegis-detonate` alimentado con tramas del protocolo del invitado |
//! | 5 | Arbitro | 79 | `aegis_entidad::arbitrar` sobre las señales traducidas |
//! | 6 | Caso | 76 | El fusionador de `aegis-case` y su cronologia |
//! | 7 | Enriquecimiento | 77 | El orquestador de `aegis-enrich`, en modo **sin salida** |
//! | 8 | Camino y radio | 69 | Dijkstra sobre `−log p` y percolacion Monte Carlo de `aegis-predict` |
//! | 9 | Contencion | 64/69 | La decision con sus cinco frenos |
//! | 10 | TAXII | 78 | El servidor TAXII y el estrangulamiento de difusion de `aegis-share` |
//! | 11 | Enjambre | 68 | El nucleo de `aegis-swarm` con tres pares distintos y quorum real |
//!
//! # El tiempo entra como argumento
//!
//! Ni una sola parada lee el reloj. Es lo que hace que el recorrido sea
//! reproducible byte a byte y que la puerta de calidad pueda compararlo con el del
//! dia anterior — y es la misma disciplina que el resto del producto.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use aegis_entidad::arbitro::{arbitrar, Resultado, Senal, Veredicto};
use aegis_entidad::entidad::{self, Clase, Eid};
use aegis_entidad::escala::{Confianza, Motor, Severidad};
use aegis_entidad::linaje::{Arista, Linaje, Relacion};
use aegis_itdr::grafo::Nivel;

use aegis_case::cronologia::{Cronologia, NodoLinaje, Remediacion};
use aegis_case::fusion::Fusionador;
use aegis_case::modelo::{Alerta, Observable as ObservableCaso};
use aegis_detonate::frontera::{Frontera, Salida as SalidaDetonacion};
use aegis_detonate::informe::{Final, Informe as InformeDetonacion, Muestra};
use aegis_detonate::receptor::{Receptor, Topes};
use aegis_detonate::red_simulada::Observado;
use aegis_detonate::ModoDeObservacion;
use aegis_enrich::analizador::Registro;
use aegis_enrich::locales::{Dga, Listas};
use aegis_enrich::observable::Observable as ObservableEnrich;
use aegis_enrich::orquesta::{Informe as InformeEnriquecimiento, Orquestador};
use aegis_enrich::salida::Modo;
use aegis_enrich::tasa::Limitador;
use aegis_predict::contencion::{decidir, ConfigContencion, Veredicto as VeredictoContencion};
use aegis_predict::grafo::{
    Activo, ClaseActivo, Evidencia, GrafoAtaque, Paso, RelacionSerializable, Via,
};
use aegis_predict::{camino_mas_probable, radio_de_explosion};
use aegis_ruleforge::indice::{self, Clase as ClaseCorpus, Entrada as EntradaCorpus, Indice};
use aegis_share::difusion::{Canal, Destino, Difusor};
use aegis_share::marcado::Tlp;
use aegis_share::stix::Paquete;
use aegis_share::taxii::{Cliente, Coleccion, Servidor};
use aegis_swarm::credencial::{Credencial, CTX_CREDENCIAL};
use aegis_swarm::enjambre::{ConfigEnjambre, Enjambre, EstadoEnlace, Salida as SalidaEnjambre};
use aegis_swarm::mensaje::{Sobre, TipoMensaje};
use aegis_swarm::observacion::{Observacion, CTX_OBSERVACION};
use aegis_sync::ioc::{Ioc, IocKind};
use aegis_update::signature::ClaveActualizacion;
use aegis_update::ClaveFirmaHibrida;
use aegis_wire::hecho::Hecho;
use aegis_wire::motor::{ConfigMotor, Motor as MotorWire};

use crate::traduccion;

/// Un segundo, en nanosegundos.
pub const SEG: u64 = 1_000_000_000;

/// Origen de tiempos del recorrido: 2025-03-04T09:00:00Z.
///
/// Fijo y no `now()`: el recorrido entero tiene que salir igual hoy que mañana.
pub const T0: u64 = 1_741_078_800 * SEG;

/// La matricula de la maquina que recibe el fichero.
pub const MAQUINA: &str = "wks-4417.corp.ejemplo";

/// Una parada del circuito, con lo que se supo en ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parada {
    /// Orden, de 1 a 11.
    pub numero: u8,
    /// El subsistema.
    pub subsistema: &'static str,
    /// La fase que lo construyo.
    pub fase: u16,
    /// Sobre que entidad trabajo.
    ///
    /// **Esta es la columna de la prueba.** Si dos paradas de la misma cosa no
    /// traen el mismo identificador, la union no existe y el producto son once
    /// herramientas en un mismo instalador.
    pub entidad: Eid,
    /// Que salio de la parada, en una linea.
    pub salida: String,
}

/// El recorrido completo.
#[derive(Debug, Clone)]
pub struct Recorrido {
    /// Las once paradas, en orden.
    pub paradas: Vec<Parada>,
    /// La entidad del contenido: el fichero, nombrado por su SHA-256.
    ///
    /// Es la que atraviesa el circuito entero.
    pub contenido: Eid,
    /// El resumen que calculo **el disector**, no uno recalculado aparte.
    ///
    /// Va en el recorrido para que quien lo lea pueda volver a derivar la entidad
    /// desde el, que es la propiedad que hace que dos observadores coincidan sin
    /// hablar entre ellos.
    pub sha256_del_contenido: String,
    /// La entidad por la que empieza la cadena: el proceso que abrio el flujo.
    ///
    /// El linaje se recorre desde aqui; empezar por el fichero dejaria fuera lo que
    /// ocurrio antes de que existiera.
    pub raiz_del_linaje: Eid,
    /// El veredicto del arbitro unificado.
    pub veredicto: Veredicto,
    /// El linaje, con la cadena red → fichero → proceso → identidad → respuesta.
    pub linaje: Linaje,
    /// Lo que el orquestador decidio, tal cual.
    ///
    /// Va entero y no como texto: «que se contuvo y sobre quien» es lo que hay que
    /// poder comprobar, y una cadena obliga a analizarla para preguntarlo.
    pub contencion: VeredictoContencion,
    /// Cuantos indicadores llegaron al agente aislado.
    pub corroborados: usize,
    /// El caso abierto, con su numero de lineas de cronologia.
    pub lineas_de_cronologia: usize,
}

impl Recorrido {
    /// Las paradas que trabajaron sobre la entidad del contenido.
    #[must_use]
    pub fn paradas_del_contenido(&self) -> Vec<&Parada> {
        self.paradas
            .iter()
            .filter(|p| p.entidad == self.contenido)
            .collect()
    }

    /// El informe legible del recorrido.
    #[must_use]
    pub fn informe(&self) -> String {
        let mut s = String::new();
        for p in &self.paradas {
            s.push_str(&format!(
                "  {:>2}. {:<20} FASE {:<3} {:<12} {}\n",
                p.numero,
                p.subsistema,
                p.fase,
                p.entidad.clase().prefijo(),
                p.salida
            ));
        }
        s
    }
}

/// Lo que puede fallar en el recorrido.
///
/// Enumerado y no cadena: un recorrido que falla dice **en que parada**, y eso es
/// lo que permite arreglar el circuito sin volver a leerlo entero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCircuito {
    /// El disector no extrajo el fichero del flujo.
    SinFicheroEnElFlujo,
    /// El corpus no se pudo montar o consultar.
    Corpus(String),
    /// El grafo de ataque no se pudo construir.
    Grafo(String),
    /// El servidor TAXII no entrego nada, con el motivo de retencion.
    ///
    /// Lleva el motivo **a proposito**: «no salio nada» sin decir por que es el
    /// sintoma que hace que alguien suba un tope a ciegas hasta que sale algo.
    TaxiiVacio(String),
    /// El enjambre no corroboro el indicador.
    SinCorroboro,
}

impl core::fmt::Display for ErrorCircuito {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorCircuito::SinFicheroEnElFlujo => {
                f.write_str("el disector no extrajo ningun fichero del flujo")
            }
            ErrorCircuito::Corpus(d) => write!(f, "el corpus no responde: {d}"),
            ErrorCircuito::Grafo(d) => write!(f, "el grafo de ataque no se pudo usar: {d}"),
            ErrorCircuito::TaxiiVacio(m) => {
                write!(f, "el servidor TAXII no entrego ningun objeto: {m}")
            }
            ErrorCircuito::SinCorroboro => {
                f.write_str("el enjambre no llego a corroborar el indicador")
            }
        }
    }
}

impl std::error::Error for ErrorCircuito {}

// ─── Parada 1 y 2: la red ──────────────────────────────────────────────────────

/// Construye un paquete IPv4 + TCP, byte a byte.
///
/// Sin sockets y sin privilegios: es lo que permite que el circuito entero corra en
/// la puerta de calidad de cualquiera.
fn tcp(
    origen: (u8, u16),
    destino: (u8, u16),
    secuencia: u32,
    banderas: u8,
    carga: &[u8],
) -> Vec<u8> {
    let total = 20 + 20 + carga.len();
    let mut p = vec![
        0x45,
        0x00,
        u8::try_from(total >> 8).unwrap_or(0),
        u8::try_from(total & 0xff).unwrap_or(0),
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        6,
        0x00,
        0x00,
        10,
        0,
        0,
        origen.0,
        10,
        0,
        0,
        destino.0,
    ];
    p.extend_from_slice(&origen.1.to_be_bytes());
    p.extend_from_slice(&destino.1.to_be_bytes());
    p.extend_from_slice(&secuencia.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.push(5 << 4);
    p.push(banderas);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(carga);
    p
}

/// Los bytes de la muestra que viaja por la red.
///
/// Un `MZ` servido como `application/pdf`: el disector lo extrae, ve que el
/// contenido contradice al tipo declarado, y lo dice. Es un hecho real de trafico,
/// no una muestra de laboratorio.
fn muestra_en_transito() -> Vec<u8> {
    let mut cuerpo = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    cuerpo.extend_from_slice(b"Este programa no puede ejecutarse en modo DOS.\r\n");
    cuerpo.resize(8192, 0x90);
    cuerpo
}

/// Paradas 1 y 2: el paquete se disecta y el fichero sale del flujo.
///
/// Devuelve el SHA-256 que calculo **el disector**, no uno calculado aparte: si el
/// circuito recalculara el resumen por su cuenta, la prueba no diria nada sobre si
/// el disector y el resto del producto nombran igual la misma cosa.
fn fase_red(cuerpo: &[u8]) -> Result<(String, Vec<Senal>, Eid), ErrorCircuito> {
    let mut m = MotorWire::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, 0x02, &[]));
    m.alimentar_ip(2, &tcp((2, 80), (1, 50_000), 5000, 0x12, &[]));

    let cabeceras = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\
         Content-Disposition: attachment; filename=\"actualizacion.pdf\"\r\n\
         Content-Length: {}\r\n\r\n",
        cuerpo.len()
    );

    let mut sec = 5001u32;
    let mut hechos = m.alimentar_ip(
        3,
        &tcp((2, 80), (1, 50_000), sec, 0x18, cabeceras.as_bytes()),
    );
    sec = sec.wrapping_add(u32::try_from(cabeceras.len()).unwrap_or(0));
    for trozo in cuerpo.chunks(512) {
        hechos.extend(m.alimentar_ip(4, &tcp((2, 80), (1, 50_000), sec, 0x08, trozo)));
        sec = sec.wrapping_add(u32::try_from(trozo.len()).unwrap_or(0));
    }

    let sha = hechos
        .iter()
        .find_map(|h| match &h.hecho {
            Hecho::FicheroTransferido { sha256, .. } => Some(sha256.clone()),
            _ => None,
        })
        .ok_or(ErrorCircuito::SinFicheroEnElFlujo)?;

    // La entidad del FLUJO, derivada de la clave de flujo que el disector ya tiene.
    // Los dos extremos derivan la misma: la tupla se ordena canonicamente.
    let maquina = entidad::maquina(MAQUINA);
    let eid_flujo = entidad::flujo(&maquina, ("10.0.0.1", 50_000), ("10.0.0.2", 80), 6, T0);

    // Las señales de red van sobre la entidad del FLUJO, no sobre la del fichero.
    // Es la distincion que hace util el linaje: «este flujo trajo este fichero» es
    // una arista, no una fusion de dos cosas en una.
    let senales: Vec<Senal> = hechos
        .iter()
        .filter_map(|h| traduccion::de_wire(h, &eid_flujo, T0 + 3 * SEG))
        .collect();

    Ok((sha, senales, eid_flujo))
}

/// El resumen del contenido que viaja por el flujo, calculado por el disector.
///
/// Se expone para que quien vaya a enriquecer pueda hacerlo **antes** de recorrer
/// el circuito, preguntando por la misma cosa. Escribir el resumen a mano en una
/// constante seria mas comodo y se quedaria viejo el dia que cambie la muestra, con
/// la prueba comparando dos cosas distintas consigo mismas.
///
/// # Errors
///
/// [`ErrorCircuito::SinFicheroEnElFlujo`] si el disector no extrae nada.
pub fn resumen_en_transito() -> Result<String, ErrorCircuito> {
    let (sha, _, _) = fase_red(&muestra_en_transito())?;
    Ok(sha)
}

// ─── Parada 3: el corpus mundial ───────────────────────────────────────────────

/// Parada 3: el fichero se consulta contra un indice del corpus **en disco**.
///
/// El indice se construye y se abre de verdad, con su busqueda binaria por `seek`:
/// es la misma ruta que sigue un agente con un millon de firmas que no caben en su
/// cuota de memoria.
fn fase_corpus(dir: &Path, sha: &str) -> Result<Option<Senal>, ErrorCircuito> {
    let ruta = dir.join("corpus.idx");

    let clave = indice::clave_de_hex(sha).ok_or_else(|| {
        ErrorCircuito::Corpus(format!("el resumen «{sha}» no es hexadecimal de 32 bytes"))
    })?;

    // Un corpus pequeño con la muestra dentro y ruido alrededor: lo que importa es
    // que la consulta pase por el formato en disco, no el numero de entradas.
    let mut entradas = vec![EntradaCorpus {
        clave,
        clase: ClaseCorpus::HashFichero,
        datos: b"Win.Trojan.Descarga-9931".to_vec(),
    }];
    for i in 0u8..64 {
        let mut k = [0u8; 32];
        k[0] = 0xff;
        k[1] = i;
        entradas.push(EntradaCorpus {
            clave: k,
            clase: ClaseCorpus::Cuerpo,
            datos: format!("Ruido.Generico-{i}").into_bytes(),
        });
    }
    indice::construir(&ruta, entradas).map_err(|e| ErrorCircuito::Corpus(e.to_string()))?;

    let mut idx = Indice::abrir(&ruta).map_err(|e| ErrorCircuito::Corpus(e.to_string()))?;
    let encontrado = idx
        .buscar(&clave)
        .map_err(|e| ErrorCircuito::Corpus(e.to_string()))?;

    Ok(encontrado.map(|e| {
        let nombre = String::from_utf8_lossy(&e.datos).to_string();
        traduccion::de_corpus(e.clase, &nombre, &entidad::contenido(sha), T0 + 5 * SEG)
    }))
}

// ─── Parada 4: la detonacion ───────────────────────────────────────────────────

/// Parada 4: la muestra se detona y el informe se monta con el receptor real.
///
/// Las tramas se construyen con el protocolo del agente invitado y entran por
/// [`Receptor::alimentar`], que es por donde entran de verdad: no hay atajo que
/// salte el analisis de trama, los topes ni la deteccion de huecos.
///
/// La frontera declarada es [`SalidaDetonacion::Ninguna`] — que es lo unico que se
/// puede declarar para una salida que no existe: el enumerado **no tiene variante
/// para «red de verdad»**.
fn fase_detonacion(
    sha: &str,
    cuerpo: &[u8],
    tramas: &[Vec<u8>],
) -> (InformeDetonacion, Senal, Eid) {
    let mut r = Receptor::nuevo(Topes::default());
    for t in tramas {
        r.alimentar(t);
    }
    let recepcion = r.cerrar();

    let frontera = Frontera::namespaces().acepto_aislamiento_debil();
    let informe = InformeDetonacion::montar(
        Muestra::de_bytes("actualizacion.pdf", cuerpo),
        &frontera,
        Final::Termino { codigo: 0 },
        &recepcion,
        &Observado::default(),
        // Este circuito alimenta tramas del AGENTE INVITADO, asi que el modo es
        // ese y no el fantasma. Importa decirlo bien: con agente dentro, una
        // detonacion sin eventos no puede concluir nada, y este circuito si los
        // tiene — declarar el otro modo haria que el veredicto se apoyara en una
        // observacion que no es la que se hizo.
        ModoDeObservacion::ConAgente,
    );

    // LA ENTIDAD DEL ARTEFACTO NO ES LA DEL FICHERO. Detonar el mismo fichero con
    // otra configuracion produce otro informe, y llamarlos igual haria que el
    // segundo pisara al primero. La arista `ProdujoArtefacto` los une.
    let eid_artefacto = entidad::artefacto(
        sha,
        &format!("salida:{}", SalidaDetonacion::Ninguna.nombre()),
    );
    let senal = traduccion::de_detonacion(&informe, &entidad::contenido(sha), T0 + 120 * SEG);
    (informe, senal, eid_artefacto)
}

// ─── Parada 6: el caso ─────────────────────────────────────────────────────────

/// Parada 6: se abre el caso y se construye su cronologia.
///
/// La cronologia se construye con un padre **no observado** a proposito: es el caso
/// que un informe descuidado presenta como completo. `aegis-case` lo declara como
/// hueco, y el recorrido lo cuenta.
fn fase_caso(v: &Veredicto, sha: &str, cuando_ns: u64) -> (Fusionador, Cronologia) {
    let mut f = Fusionador::nuevo();
    f.admitir(Alerta {
        id: "al-0001".into(),
        inquilino: "ejemplo".into(),
        anfitrion: MAQUINA.into(),
        sujeto: format!("sha256:{sha}"),
        tecnica: Some("T1204.002".into()),
        regla: "tejido/circuito-completo".into(),
        severidad: traduccion::a_severidad_de_caso(v.severidad),
        ocurrio_ns: cuando_ns,
        observables: vec![
            ObservableCaso::Hash(sha.to_string()),
            ObservableCaso::Anfitrion(MAQUINA.to_string()),
            ObservableCaso::Dominio("descarga.ejemplo-malo.test".into()),
        ],
        resumen: v.resumen(),
    });

    let caso = f.casos().first().expect("se admitio una alerta").clone();
    let cronologia = Cronologia::construir(
        &caso,
        &[NodoLinaje {
            id: "p-4417-8812".into(),
            padre: None,
            // EL HUECO SE DICE. El padre existio y no se observo; unir los
            // extremos afirmaria una causa que no consta.
            padre_desconocido: true,
            imagen: "C:\\Users\\publico\\actualizacion.pdf.exe".into(),
            orden: "actualizacion.pdf.exe /s".into(),
            cuando_ns: cuando_ns + 30 * SEG,
            usuario: "CORP\\ana.perez".into(),
            ficheros: vec![(cuando_ns + 31 * SEG, "C:\\Users\\publico\\carga.bin".into())],
            conexiones: vec![(cuando_ns + 32 * SEG, "10.0.0.2:80".into())],
        }],
        &[Remediacion {
            id: "rm-0001".into(),
            accion: "aislar-maquina".into(),
            objetivo: MAQUINA.into(),
            actor: "aegis-orchestrator".into(),
            ordenada_ns: cuando_ns + 60 * SEG,
            // ORDENADA Y NO CONFIRMADA. Es un dato, no un hueco: significa que la
            // contencion PUEDE no haber ocurrido.
            aplicada_ns: None,
        }],
    );
    (f, cronologia)
}

// ─── Parada 8 y 9: camino, radio y contencion ──────────────────────────────────

/// Construye el grafo de ataque de la organizacion del recorrido.
///
/// # Por que este grafo y no uno mas grande
///
/// Porque lo que hay que enseñar no es que el algoritmo escale —eso lo prueba
/// `aegis-predict` con miles de nodos— sino que **el camino que el motor encuentra
/// es el que un atacante usaria**, y que los frenos se ven.
///
/// El camino critico alterna identidad y red, que es la tesis de la FASE 69: de la
/// estacion comprometida salen las credenciales cacheadas de una cuenta de
/// servicio (0,95 — es literalmente el camino de Mimikatz), y esa cuenta pertenece
/// a un grupo con administracion sobre el controlador de dominio (0,99). Dos saltos
/// y p = 0,94: un camino asi **si** justifica actuar sin preguntar.
///
/// Y el controlador de dominio esta **protegido**, asi que la contencion no puede
/// tocarlo: el motor tiene que cortar antes, en la identidad. Es el freno 1 y la
/// regla de «se corta la identidad antes que aislar la maquina», las dos a la vez.
fn grafo() -> Result<GrafoAtaque, ErrorCircuito> {
    let mut g = GrafoAtaque::nuevo();
    let err = |e: aegis_predict::ErrorPrediccion| ErrorCircuito::Grafo(e.to_string());

    g.agregar(Activo::nuevo(
        MAQUINA,
        ClaseActivo::Endpoint,
        Nivel::Usuario,
        20,
    ))
    .map_err(err)?;
    g.agregar(Activo::nuevo(
        "wks-4418.corp.ejemplo",
        ClaseActivo::Endpoint,
        Nivel::Usuario,
        20,
    ))
    .map_err(err)?;
    g.agregar(Activo::nuevo(
        "srv-ficheros.corp.ejemplo",
        ClaseActivo::Servicio,
        Nivel::Operador,
        55,
    ))
    .map_err(err)?;
    g.agregar(Activo::nuevo(
        "CORP\\svc-respaldo",
        ClaseActivo::Identidad,
        Nivel::AdminLocal,
        70,
    ))
    .map_err(err)?;
    // EL ACTIVO PROTEGIDO. Es el freno 1 de la FASE 69: tirar el controlador de
    // dominio convierte un incidente en un apagon, y es lo que un atacante querria
    // que hicieramos por el.
    g.agregar(
        Activo::nuevo(
            "dc-01.corp.ejemplo",
            ClaseActivo::Servicio,
            Nivel::AdminDominio,
            100,
        )
        .protegido(),
    )
    .map_err(err)?;

    // EVIDENCIA SOLIDA: vista varias veces, por mas de un observador y con mas de
    // un dia de antiguedad. Las tres cosas, porque repetir mil veces la misma
    // observacion desde la misma maquina no es corroboro, es la misma observacion
    // mil veces — y es justo lo que un atacante puede fabricar en un minuto.
    let solida = Evidencia {
        observaciones: 6,
        observadores: 3,
        antiguedad_seg: 12 * 24 * 3600,
    };

    // EL CAMINO CRITICO: credenciales cacheadas → pertenencia a grupo → dominio.
    g.conectar(
        Paso::nuevo(
            MAQUINA,
            "CORP\\svc-respaldo",
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
        )
        .con_evidencia(solida),
    )
    .map_err(err)?;
    g.conectar(
        Paso::nuevo(
            "CORP\\svc-respaldo",
            "dc-01.corp.ejemplo",
            Via::Identidad(RelacionSerializable::MiembroDe),
        )
        .con_evidencia(solida),
    )
    .map_err(err)?;

    // Y las ramas laterales, que es de donde sale el radio: lo que se pierde no es
    // solo lo que hay en el camino al objetivo.
    g.conectar(
        Paso::nuevo(MAQUINA, "srv-ficheros.corp.ejemplo", Via::RedExpuesta).con_evidencia(solida),
    )
    .map_err(err)?;
    g.conectar(
        Paso::nuevo(
            "CORP\\svc-respaldo",
            "srv-ficheros.corp.ejemplo",
            Via::Identidad(RelacionSerializable::ActuaComo),
        )
        .con_evidencia(solida),
    )
    .map_err(err)?;
    g.conectar(
        Paso::nuevo(
            "srv-ficheros.corp.ejemplo",
            "wks-4418.corp.ejemplo",
            Via::RedSegmentada,
        )
        .con_evidencia(solida),
    )
    .map_err(err)?;
    Ok(g)
}

// ─── El recorrido ──────────────────────────────────────────────────────────────

/// Recorre el circuito completo.
///
/// `dir` es donde se escribe el indice del corpus: un directorio temporal del
/// llamante, para que el recorrido no tenga estado propio entre ejecuciones.
///
/// `tramas` son las del protocolo del agente invitado que alimentan la detonacion.
/// Se pasan desde fuera **a proposito**: construirlas aqui obligaria a este crate a
/// depender de `aegis-invitado` en produccion, y el circuito no tiene por que saber
/// como se codifica un evento del invitado — solo que el receptor los admite.
///
/// `enriquecimiento` es el informe que devuelve [`enriquecer_sin_salida`], que es
/// asincrono: el recorrido no lo es y no va a serlo, porque un circuito sincrono se
/// puede ejercer desde cualquier prueba sin runtime.
///
/// # Errors
///
/// Devuelve el [`ErrorCircuito`] de la primera parada que no responde.
pub fn recorrer(
    dir: &Path,
    tramas: &[Vec<u8>],
    enriquecimiento: &InformeEnriquecimiento,
) -> Result<Recorrido, ErrorCircuito> {
    let mut paradas = Vec::new();
    let cuerpo = muestra_en_transito();

    // ── 1 y 2. LA RED ──────────────────────────────────────────────────────────
    let (sha, senales_red, eid_flujo) = fase_red(&cuerpo)?;
    let contenido = entidad::contenido(&sha);

    paradas.push(Parada {
        numero: 1,
        subsistema: "AegisWire",
        fase: 70,
        entidad: eid_flujo.clone(),
        salida: format!("flujo disecado, {} hecho(s) que acusan", senales_red.len()),
    });
    paradas.push(Parada {
        numero: 2,
        subsistema: "AegisWire",
        fase: 70,
        entidad: contenido.clone(),
        salida: format!("fichero extraido del flujo, {} bytes", cuerpo.len()),
    });

    // ── 3. EL CORPUS MUNDIAL ───────────────────────────────────────────────────
    let senal_corpus = fase_corpus(dir, &sha)?;
    paradas.push(Parada {
        numero: 3,
        subsistema: "AegisRuleForge",
        fase: 72,
        entidad: contenido.clone(),
        salida: senal_corpus.as_ref().map_or_else(
            || "el corpus no lo conoce".to_string(),
            |s| s.porque.clone(),
        ),
    });

    // ── 4. LA DETONACION ───────────────────────────────────────────────────────
    let (informe, senal_detonacion, eid_artefacto) = fase_detonacion(&sha, &cuerpo, tramas);
    paradas.push(Parada {
        numero: 4,
        subsistema: "AegisDetonate",
        fase: 73,
        entidad: eid_artefacto.clone(),
        salida: format!(
            "{} · {} evento(s) recibidos",
            informe.veredicto().nombre(),
            informe.eventos
        ),
    });

    // ── 5. EL ARBITRO UNIFICADO ────────────────────────────────────────────────
    //
    // Aqui es donde el producto deja de ser una suma. Las señales llegan de cuatro
    // subsistemas que no se conocen entre si, todas nombrando la MISMA entidad, y
    // salen como un veredicto con su frase.
    let mut senales: Vec<Senal> = Vec::new();
    if let Some(s) = senal_corpus {
        senales.push(s);
    }
    senales.push(senal_detonacion);
    senales.push(traduccion::de_modelo(880, &contenido, T0 + 4 * SEG));
    senales.extend(senales_red.iter().cloned());

    let veredicto = arbitrar(&contenido, &senales, T0 + 130 * SEG);
    paradas.push(Parada {
        numero: 5,
        subsistema: "AegisFabric",
        fase: 79,
        entidad: contenido.clone(),
        salida: veredicto.resumen(),
    });

    // ── 6. EL CASO ─────────────────────────────────────────────────────────────
    let (fusionador, cronologia) = fase_caso(&veredicto, &sha, T0 + 130 * SEG);
    paradas.push(Parada {
        numero: 6,
        subsistema: "AegisCase",
        fase: 76,
        entidad: contenido.clone(),
        salida: format!(
            "{} caso(s) abierto(s), {} linea(s) de cronologia, {} hueco(s) declarado(s)",
            fusionador.abiertos(),
            cronologia.lineas().len(),
            cronologia.huecos().len()
        ),
    });

    // ── 7. EL ENRIQUECIMIENTO ──────────────────────────────────────────────────
    //
    // El orquestador es asincrono y el resto del circuito no lo es, asi que el
    // llamante lo ejecuta con `enriquecer_sin_salida` y pasa el informe. Lo que se
    // comprueba aqui es lo unico que le toca al tejido: que el observable que se
    // consulto sea el MISMO resumen que recorre todo lo demas.
    paradas.push(Parada {
        numero: 7,
        subsistema: "AegisEnrich",
        fase: 77,
        entidad: contenido.clone(),
        salida: format!(
            "{} · {} analizador(es) sin resultado · {} salio",
            enriquecimiento.fusion.veredicto.nombre(),
            enriquecimiento.sin_resultado().len(),
            if enriquecimiento.exposicion.vacia() {
                "nada"
            } else {
                "ALGO"
            }
        ),
    });

    // ── 8. CAMINO DE ATAQUE Y RADIO ────────────────────────────────────────────
    let g = grafo()?;
    let camino = camino_mas_probable(&g, MAQUINA, "dc-01.corp.ejemplo")
        .map_err(|e| ErrorCircuito::Grafo(e.to_string()))?;
    let radio =
        radio_de_explosion(&g, MAQUINA, 2000).map_err(|e| ErrorCircuito::Grafo(e.to_string()))?;
    paradas.push(Parada {
        numero: 8,
        subsistema: "AegisPredict",
        fase: 69,
        entidad: entidad::maquina(MAQUINA),
        salida: format!(
            "camino de {} salto(s) con p={:.4}; radio {:.1} activo(s) ±{:.2}",
            camino
                .as_ref()
                .map_or(0, aegis_predict::CaminoAtaque::saltos),
            camino.as_ref().map_or(0.0, |c| c.probabilidad),
            radio.activos_esperados,
            radio.margen
        ),
    });

    // ── 9. LA CONTENCION ───────────────────────────────────────────────────────
    let decision = decidir(&g, camino.as_ref(), &radio, &ConfigContencion::default())
        .map_err(|e| ErrorCircuito::Grafo(e.to_string()))?;
    paradas.push(Parada {
        numero: 9,
        subsistema: "AegisOrchestrator",
        fase: 64,
        entidad: entidad::maquina(MAQUINA),
        salida: match &decision {
            VeredictoContencion::Contener { sujeto, accion, .. } => {
                format!("contener «{sujeto}»: {accion:?}")
            }
            VeredictoContencion::Escalar { motivo, .. } => {
                format!("escalar a una persona: {motivo:?}")
            }
            VeredictoContencion::NoActuar { motivo } => format!("no actuar: {motivo:?}"),
        },
    });

    // ── 10. TAXII ──────────────────────────────────────────────────────────────
    let (entregados, tlp) = fase_taxii(&sha, &veredicto)?;
    paradas.push(Parada {
        numero: 10,
        subsistema: "AegisShare",
        fase: 78,
        entidad: contenido.clone(),
        salida: format!(
            "{entregados} objeto(s) entregados por TAXII con tope {}",
            tlp.nombre()
        ),
    });

    // ── 11. EL ENJAMBRE ────────────────────────────────────────────────────────
    let corroborados = fase_enjambre(&sha);
    if corroborados == 0 {
        return Err(ErrorCircuito::SinCorroboro);
    }
    paradas.push(Parada {
        numero: 11,
        subsistema: "AegisSwarm",
        fase: 68,
        entidad: contenido.clone(),
        salida: format!(
            "{corroborados} indicador(es) corroborados por 3 pares distintos, sin plano de control"
        ),
    });

    // ── EL LINAJE: la cadena entera, consultable ───────────────────────────────
    let linaje = tejer_linaje(&eid_flujo, &contenido, &eid_artefacto);

    Ok(Recorrido {
        paradas,
        raiz_del_linaje: entidad::proceso(&entidad::maquina(MAQUINA), 17, 5104, T0 - 600 * SEG),
        sha256_del_contenido: sha.clone(),
        contenido,
        veredicto,
        linaje,
        contencion: decision,
        corroborados,
        lineas_de_cronologia: cronologia.lineas().len(),
    })
}

/// El observable de `aegis-enrich` que corresponde a la entidad del contenido.
///
/// Es la costura mas fina del circuito y por eso tiene funcion propia: el mismo
/// resumen que nombra la entidad es el que se consulta. Si el circuito construyera
/// el observable de otra forma —del nombre del fichero, por ejemplo— el
/// enriquecimiento estaria hablando de otra cosa y nadie se enteraria.
#[must_use]
pub fn observable_de(contenido_sha256: &str) -> ObservableEnrich {
    ObservableEnrich::Hash(contenido_sha256.to_string())
}

/// Parada 7: el enriquecimiento, con la salida **retirada**.
///
/// # Por que el circuito corre en modo sin salida y no conectado
///
/// Porque la propiedad que hay que ejercer no es «sabe preguntar a VirusTotal»: es
/// que con el modo puesto **no existe el objeto** por el que se pregunta. La salida
/// es una capacidad que se entrega, no una bandera que se comprueba, y la unica
/// forma de demostrarlo es no entregarla y ver que los locales siguen dando
/// veredicto. Sin salida es *degradado*, no apagado.
///
/// Y hay una segunda razon, practica: la puerta de calidad no puede depender de
/// que haya Internet.
pub async fn enriquecer_sin_salida(sha: &str, ahora_ns: u64) -> InformeEnriquecimiento {
    let mut registro = Registro::nuevo();
    let mut listas = Listas::nuevas("listas-de-la-casa");
    listas.permitir(
        &ObservableEnrich::Hash("0".repeat(64)),
        "binario firmado por la propia organizacion",
    );
    registro
        .registrar(Arc::new(listas))
        .expect("la ficha de las listas es coherente");
    registro
        .registrar(Arc::new(Dga::nuevo("dga")))
        .expect("la ficha del dga es coherente");

    let o = Orquestador::nuevo(registro, Limitador::nuevo(), Modo::SinSalida);
    o.enriquecer(&observable_de(sha), ahora_ns).await
}

/// Parada 10: el indicador sale por TAXII, pasando por el estrangulamiento.
///
/// El difusor no es un filtro que el servidor consulte por cortesia: el servidor
/// TAXII **se construye con el**, asi que no hay ninguna ruta de lectura que lo
/// esquive. Es el «un solo estrangulamiento» de la FASE 78, y es la razon por la
/// que «no sale por ningun camino» es cierto por construccion y no por haber
/// configurado bien.
fn fase_taxii(sha: &str, v: &Veredicto) -> Result<(usize, Tlp), ErrorCircuito> {
    let tope = traduccion::tope_de_difusion(v.resultado);
    let doc = format!(
        r#"{{"type":"bundle","id":"bundle--3f9a1c00-0000-4000-8000-000000000001","objects":[
            {{"type":"indicator","spec_version":"2.1",
              "id":"indicator--3f9a1c00-0000-4000-8000-000000000002",
              "created":"2025-03-04T09:02:10.000Z","modified":"2025-03-04T09:02:10.000Z",
              "pattern":"[file:hashes.'SHA-256' = '{sha}']","pattern_type":"stix",
              "valid_from":"2025-03-04T09:02:10.000Z",
              "labels":["{}"]}}]}}"#,
        // La etiqueta va en minusculas y **con** su prefijo, tal cual la escribe
        // `Tlp::nombre`. Anteponerle otro «tlp:» produce «tlp:tlp:amber», que no
        // es una etiqueta valida — y entonces el marcado se resuelve a RED y el
        // objeto no sale por ningun canal. Que el sistema se cierre ante una
        // etiqueta que no entiende es lo correcto; escribirla mal es cosa nuestra.
        tope.nombre().to_ascii_lowercase()
    );

    let paquete = Paquete::validar(&doc).map_err(|r| ErrorCircuito::Corpus(format!("{r:?}")))?;

    let mut d = Difusor::nuevo();
    d.declarar(Destino {
        nombre: "comunidad".into(),
        canal: Canal::Taxii,
        tope_tlp: Tlp::Amber,
        es_propia_organizacion: false,
    });

    let mut servidor = Servidor::nuevo(d);
    servidor
        .declarar(Coleccion {
            id: "indicadores".into(),
            titulo: "Indicadores de AegisCore".into(),
            descripcion: "Lo que el arbitro unificado dio por malicioso".into(),
            lectura: true,
            escritura: true,
            destino: "comunidad".into(),
        })
        .map_err(ErrorCircuito::Corpus)?;
    servidor
        .anadir(
            "indicadores",
            paquete.objetos.values().cloned().collect(),
            T0 + 140 * SEG,
        )
        .map_err(ErrorCircuito::Corpus)?;

    let mut cliente = Cliente::nuevo();
    let objetos = cliente
        .sondear(&servidor, "indicadores", 50)
        .map_err(ErrorCircuito::Corpus)?;
    if objetos.is_empty() {
        let auditoria = servidor
            .auditar("indicadores")
            .map_err(ErrorCircuito::Corpus)?;
        return Err(ErrorCircuito::TaxiiVacio(auditoria.resumen("comunidad")));
    }
    Ok((objetos.len(), tope))
}

/// Parada 11: tres pares distintos observan el indicador y el agente aislado lo
/// corrobora — **sin plano de control**.
///
/// Es la invariante de la FASE 68 ejercida: el enjambre transporta autoridad, no la
/// concede. Lo que llega no es una orden; es evidencia que exige K testigos, y el
/// agente decide con el mismo criterio con el que decide ante una deteccion propia.
///
/// Y los K testigos son K identidades AUTENTICADAS (H-04): el plano de control
/// matriculo a los tres agentes ANTES del corte, firmandoles una credencial, y el
/// agente aislado la verifica con la clave publica del plano que lleva grabada. Lo
/// que cuenta es esa identidad, nunca el nombre que declare el mensaje. Una orden
/// que se colara aqui seguiria necesitando la firma del plano de control, que
/// durante el corte nadie puede producir.
fn fase_enjambre(sha: &str) -> usize {
    // Semillas fijas: el recorrido tiene que salir igual hoy que mañana.
    let plano = ClaveFirmaHibrida::desde_semillas(&[68u8; 32], &[86u8; 32]);
    let mut agente = Enjambre::nuevo(ConfigEnjambre {
        clave_plano_control: ClaveActualizacion::Hibrida(Box::new(plano.clave_verificacion())),
        saltos: 3,
        tasa: 100,
        umbral_corroboro: 3,
        ventana_corroboro_seg: 3600,
    });
    // El corte: el agente no habla con el plano de control.
    agente.declarar_enlace(EstadoEnlace::Aislado);

    let mut corroborados = 0;
    for (i, par) in ["agente-11", "agente-24", "agente-37"].iter().enumerate() {
        let semilla = 11 + u8::try_from(i).unwrap_or(0);
        let vista_en = 1_741_078_900 + u64::try_from(i).unwrap_or(0);
        let Some(sobre) = observacion_matriculada(&plano, par, semilla, sha, vista_en) else {
            continue;
        };
        for s in agente.recibir(par, &sobre, 1_741_078_901) {
            if matches!(s, SalidaEnjambre::Corroborado { .. }) {
                corroborados += 1;
            }
        }
    }
    corroborados
}

/// Lo que hace un agente matriculado al contar al enjambre lo que vio.
///
/// Al matricularlo, el plano de control le firmo una credencial con su CN y su
/// clave publica hibrida; el agente firma la observacion con su clave privada y
/// la manda junto a esa credencial. Asi un receptor aislado cuenta testigos por
/// identidad autenticada, que es lo que impide que un solo equipo comprometido se
/// haga pasar por K (H-04).
///
/// `semilla` deriva la clave del agente de forma determinista: es un recorrido
/// reproducible, no una matriculacion de produccion. Devuelve `None` solo si una
/// firma falla, que con contextos fijos no ocurre.
#[must_use]
pub fn observacion_matriculada(
    plano: &ClaveFirmaHibrida,
    cn: &str,
    semilla: u8,
    sha: &str,
    vista_en: u64,
) -> Option<Vec<u8>> {
    let clave = ClaveFirmaHibrida::desde_semillas(&[semilla; 32], &[semilla ^ 0x5A; 32]);
    let mut credencial = Credencial {
        cn: cn.to_string(),
        clave_par: clave.clave_verificacion().a_bytes().to_vec(),
        valida_desde: vista_en.saturating_sub(86_400),
        valida_hasta: vista_en.saturating_add(7 * 86_400),
        firma_plano: Vec::new(),
    };
    credencial.firma_plano = plano
        .firmar(&credencial.bytes_firmados(), CTX_CREDENCIAL)
        .ok()?
        .a_bytes();
    let o = Observacion {
        origen: cn.to_string(),
        indicador: Ioc {
            kind: IocKind::FileSha256,
            value: sha.to_string(),
        },
        tecnica: "T1204.002".into(),
        confianza: 80,
        vista_en,
    };
    let firma = clave
        .firmar(&o.bytes_firmados(&credencial), CTX_OBSERVACION)
        .ok()?
        .a_bytes();
    let sobre = Sobre {
        tipo: TipoMensaje::Observacion,
        saltos: 3,
        cuerpo: aegis_swarm::observacion::empaquetar(&credencial, &o),
        firma,
    };
    Some(sobre.a_bytes())
}

/// Teje el linaje: red → fichero → proceso → identidad → respuesta.
///
/// # Las aristas que no existian antes de esta fase
///
/// `Extrajo` une el plano de red con el de fichero; `SeDetono` une el fichero con
/// lo que se observo al ejecutarlo en la microVM; `ActuoComo` une el proceso con la
/// identidad; `SeContuvo` une la respuesta con lo que se contuvo. Antes cada plano
/// tenia su propio grafo y el salto lo hacia el analista de cabeza — que funciona
/// hasta que el incidente tiene cuarenta nodos.
///
/// La cadena arranca en el navegador porque es lo que de verdad paso: un proceso
/// legitimo abrio un flujo, del flujo salio un fichero, el fichero se escribio en
/// una ruta, y de ahi salio el proceso que hizo el daño.
fn tejer_linaje(flujo: &Eid, contenido: &Eid, artefacto: &Eid) -> Linaje {
    let maquina = entidad::maquina(MAQUINA);
    let navegador = entidad::proceso(&maquina, 17, 5104, T0 - 600 * SEG);
    let proceso = entidad::proceso(&maquina, 17, 8812, T0 + 160 * SEG);
    let ubicacion = entidad::ubicacion(&maquina, "C:\\Users\\publico\\actualizacion.pdf.exe");
    let cuenta = entidad::cuenta("S-1-5-21-1004336348-1177238915-682003330-1417");
    let regla = entidad::regla("tejido", "circuito-completo");

    let aristas: [(&Eid, Relacion, &Eid, u64, Motor); 10] = [
        (&navegador, Relacion::Abrio, flujo, 1, Motor::Wire),
        (flujo, Relacion::Extrajo, contenido, 3, Motor::Wire),
        (
            &navegador,
            Relacion::Escribio,
            &ubicacion,
            100,
            Motor::Conductual,
        ),
        (
            &ubicacion,
            Relacion::Contiene,
            contenido,
            100,
            Motor::Estatico,
        ),
        (
            contenido,
            Relacion::SeDetono,
            artefacto,
            120,
            Motor::Detonate,
        ),
        (
            &navegador,
            Relacion::Lanzo,
            &proceso,
            160,
            Motor::Conductual,
        ),
        (
            &proceso,
            Relacion::Ejecuto,
            contenido,
            160,
            Motor::Conductual,
        ),
        (&proceso, Relacion::ActuoComo, &cuenta, 160, Motor::Itdr),
        (
            &proceso,
            Relacion::ResideEn,
            &maquina,
            160,
            Motor::Conductual,
        ),
        // LA RESPUESTA TAMBIEN ES LINAJE. Sin esta arista, «que se hizo al
        // respecto» vive en otra tabla y el informe del caso no lo puede contar
        // como parte de la misma cadena.
        (
            &regla,
            Relacion::SeContuvo,
            &maquina,
            220,
            Motor::Conductual,
        ),
    ];

    let mut l = Linaje::nuevo();
    for (origen, relacion, destino, t, observador) in aristas {
        l.anadir(Arista {
            origen: origen.clone(),
            destino: destino.clone(),
            relacion,
            cuando_ns: T0 + t * SEG,
            observador: observador.nombre().to_string(),
        });
    }
    l
}

/// Las once paradas que el circuito tiene que recorrer, declaradas.
///
/// Se declara la lista aparte del recorrido **a proposito**: si una parada dejara
/// de ejecutarse, el recorrido seguiria devolviendo `Ok` con diez entradas y la
/// prueba tiene que poder decir cual falta por su nombre.
pub const PARADAS_ESPERADAS: &[(u8, &str, u16)] = &[
    (1, "AegisWire", 70),
    (2, "AegisWire", 70),
    (3, "AegisRuleForge", 72),
    (4, "AegisDetonate", 73),
    (5, "AegisFabric", 79),
    (6, "AegisCase", 76),
    (7, "AegisEnrich", 77),
    (8, "AegisPredict", 69),
    (9, "AegisOrchestrator", 64),
    (10, "AegisShare", 78),
    (11, "AegisSwarm", 68),
];

/// Las clases de entidad que el circuito nombra, con cuantas paradas cada una.
#[must_use]
pub fn clases_recorridas(r: &Recorrido) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for p in &r.paradas {
        *m.entry(p.entidad.clase().prefijo()).or_insert(0) += 1;
    }
    m
}

/// Si el veredicto del recorrido justifica actuar sin preguntar.
#[must_use]
pub fn justifica_contencion(r: &Recorrido) -> bool {
    r.veredicto.resultado == Resultado::Malicioso
}

/// La confianza y severidad a las que llego el arbitro, para el informe.
#[must_use]
pub fn cuanto_se_cree(r: &Recorrido) -> (Severidad, Confianza) {
    (r.veredicto.severidad, r.veredicto.confianza)
}

/// Las clases de entidad que el modelo declara, para comprobar que el circuito no
/// inventa ninguna.
#[must_use]
pub fn clases_declaradas() -> Vec<&'static str> {
    Clase::todas().iter().map(|c| c.prefijo()).collect()
}
