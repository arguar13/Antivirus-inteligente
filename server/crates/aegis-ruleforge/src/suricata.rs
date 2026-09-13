//! Compilador de reglas de red en sintaxis Suricata / Snort.
//!
//! # Que entra y que sale
//!
//! Entra el corpus publico —Emerging Threats y companeras, decenas de miles de
//! reglas— y sale [`aegis_ips::Regla`], que es lo que el motor de la FASE 71
//! evalua de verdad. No una representacion intermedia que espera a que alguien
//! la conecte: reglas ejecutables.
//!
//! # La decision que define el modulo: SE ANALIZA TODO, SE COMPILA LO QUE SE SABE
//!
//! Hay dos formas de escribir esto y solo una sirve.
//!
//! La facil es buscar las opciones que se entienden e ignorar el resto. Compila
//! muchisimas reglas, y **todas mal**: una regla `content:"x"; content:"y";
//! distance:0;` a la que se le ignora el `distance` casa con cosas que no
//! deberia. El operador cree tener 40.000 reglas y tiene 40.000 aproximaciones.
//!
//! La correcta es analizar la sintaxis **entera** —aunque la opcion no se vaya a
//! usar— para poder decir con precision cual no se soporta, rechazar esa regla
//! CON NOMBRE, y contarla. Cuesta mas y da un numero mas bajo de reglas
//! compiladas. Ese numero mas bajo es el verdadero.
//!
//! > Una regla compilada a medias es peor que una regla rechazada: la rechazada
//! > se ve en el informe, la compilada a medias se ve cuando no detecta.
//!
//! # Como se escriben hoy las reglas, y por que eso nos favorece
//!
//! El contenido publico moderno ya casi no busca bytes en la carga cruda: busca
//! en el campo semantico concreto (`http.uri`, `tls.sni`, `http.user_agent`,
//! `dns.query`). Eso es **exactamente** lo que produce [`aegis_wire`] tras
//! reensamblar y normalizar, asi que la traduccion es directa — y ademas hereda
//! gratis la resistencia a evasion de la FASE 70: una regla que busca en
//! `http.uri` no se puede evadir partiendo la cadena entre dos segmentos TCP,
//! porque el disector ya reensamblo.
//!
//! # Lo que NO se compila, y se dice
//!
//! Las opciones que operan sobre bytes crudos con aritmetica de desplazamientos
//! —`byte_test`, `byte_jump`, `byte_extract`, `isdataat`— describen una maquina
//! de bytes que el motor de hechos no tiene. Se ANALIZAN para reconocerlas y se
//! rechaza la regla nombrando la opcion concreta, en vez de compilarla sin esa
//! condicion y que case de mas.

use std::collections::BTreeMap;

use aegis_ips::confianza::Confianza;
use aegis_ips::regla::{Criterio, Regla};

use crate::informe::{Informe, Rechazo};
use crate::presupuesto::Presupuesto;
use crate::regex_segura;

/// Accion declarada por la regla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accion {
    /// Solo alerta.
    Alert,
    /// Descarta el paquete.
    Drop,
    /// Descarta y responde.
    Reject,
    /// Deja pasar explicitamente.
    Pass,
    /// Solo registra.
    Log,
}

impl Accion {
    fn desde(s: &str) -> Option<Accion> {
        match s {
            "alert" => Some(Accion::Alert),
            "drop" => Some(Accion::Drop),
            "reject" | "rejectsrc" | "rejectdst" | "rejectboth" => Some(Accion::Reject),
            "pass" => Some(Accion::Pass),
            "log" => Some(Accion::Log),
            _ => None,
        }
    }
}

/// Sentido del flujo en la cabecera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sentido {
    /// `->`, solo de origen a destino.
    HaciaDestino,
    /// `<>`, en los dos sentidos.
    Ambos,
}

/// Un extremo de la cabecera: direcciones o puertos.
///
/// Se conserva el TEXTO ademas de la interpretacion. Una regla que se rechaza
/// tiene que poder citarse tal y como venia, o quien lea el informe no la
/// encuentra en el fichero original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extremo {
    /// Tal y como venia escrito.
    pub texto: String,
    /// Si va negado con `!`.
    pub negado: bool,
    /// Si es `any`.
    pub cualquiera: bool,
}

impl Extremo {
    fn analizar(texto: &str) -> Extremo {
        let t = texto.trim();
        let negado = t.starts_with('!');
        let limpio = t.trim_start_matches('!').trim();
        Extremo {
            texto: t.to_string(),
            negado,
            cualquiera: limpio.eq_ignore_ascii_case("any"),
        }
    }
}

/// La cabecera de una regla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cabecera {
    /// Que hace la regla.
    pub accion: Accion,
    /// Protocolo declarado (`tcp`, `http`, `tls`, `dns`...).
    pub protocolo: String,
    /// Direcciones de origen.
    pub origen: Extremo,
    /// Puertos de origen.
    pub puerto_origen: Extremo,
    /// Sentido.
    pub sentido: Sentido,
    /// Direcciones de destino.
    pub destino: Extremo,
    /// Puertos de destino.
    pub puerto_destino: Extremo,
}

/// Una opcion de la regla, ya separada en clave y valor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opcion {
    /// Nombre de la opcion.
    pub clave: String,
    /// Valor, sin comillas. Vacio en las opciones sin valor.
    pub valor: String,
    /// Si el valor venia entrecomillado.
    pub entrecomillado: bool,
}

/// Una regla ya analizada, antes de traducirse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglaSuricata {
    /// La cabecera.
    pub cabecera: Cabecera,
    /// Las opciones, en orden de aparicion.
    ///
    /// El ORDEN importa y no es un detalle: en Suricata los modificadores
    /// (`nocase`, `http_uri`, `distance`) se aplican al `content` que los
    /// precede. Guardarlas en un mapa perderia esa relacion y haria imposible
    /// saber a que patron modifica cada cosa.
    pub opciones: Vec<Opcion>,
    /// Texto original, para poder citarla en el informe.
    pub texto: String,
}

impl ReglaSuricata {
    /// Valor de la primera opcion con esa clave.
    #[must_use]
    pub fn opcion(&self, clave: &str) -> Option<&str> {
        self.opciones
            .iter()
            .find(|o| o.clave == clave)
            .map(|o| o.valor.as_str())
    }

    /// Identificador de la regla (`sid`), o un marcador si no lo trae.
    #[must_use]
    pub fn sid(&self) -> String {
        self.opcion("sid")
            .map(str::to_string)
            .unwrap_or_else(|| "sin-sid".to_string())
    }

    /// Mensaje declarado.
    #[must_use]
    pub fn msg(&self) -> String {
        self.opcion("msg").unwrap_or("").to_string()
    }
}

/// Por que una regla no se pudo analizar o traducir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSuricata {
    /// La linea no tiene la forma `cabecera (opciones)`.
    Malformada(String),
    /// La accion no se reconoce.
    AccionDesconocida(String),
    /// El sentido no se reconoce.
    SentidoDesconocido(String),
    /// La regla pasa del tamano permitido.
    DemasiadoGrande {
        /// Bytes que ocupa.
        bytes: usize,
        /// Tope.
        tope: usize,
    },
    /// Usa una opcion que el motor no evalua.
    OpcionNoSoportada(String),
    /// Su expresion regular es patologica o demasiado compleja.
    RegexRechazada(String),
    /// Tiene mas patrones de los permitidos.
    DemasiadosPatrones {
        /// Cuantos trae.
        patrones: usize,
        /// Tope.
        tope: usize,
    },
    /// Se analizo bien pero no quedo ningun criterio evaluable.
    ///
    /// Es distinto de «opcion no soportada»: aqui todas las opciones se
    /// entienden, pero ninguna dice nada que el motor de hechos pueda mirar (por
    /// ejemplo, una regla que solo declara `flow` y `sid`). Compilarla daria una
    /// regla que casa con TODO, que es el peor resultado posible.
    SinCriterioEvaluable,
}

impl ErrorSuricata {
    /// Codigo estable para el informe.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            ErrorSuricata::Malformada(_) => "suricata-malformada",
            ErrorSuricata::AccionDesconocida(_) => "suricata-accion-desconocida",
            ErrorSuricata::SentidoDesconocido(_) => "suricata-sentido-desconocido",
            ErrorSuricata::DemasiadoGrande { .. } => "suricata-demasiado-grande",
            ErrorSuricata::OpcionNoSoportada(_) => "suricata-opcion-no-soportada",
            ErrorSuricata::RegexRechazada(_) => "regex-patologica",
            ErrorSuricata::DemasiadosPatrones { .. } => "suricata-demasiados-patrones",
            ErrorSuricata::SinCriterioEvaluable => "suricata-sin-criterio-evaluable",
        }
    }

    /// Detalle legible, con el nombre concreto de lo que fallo.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorSuricata::Malformada(d) => d.clone(),
            ErrorSuricata::AccionDesconocida(a) => format!("accion «{a}»"),
            ErrorSuricata::SentidoDesconocido(s) => format!("sentido «{s}»"),
            ErrorSuricata::DemasiadoGrande { bytes, tope } => {
                format!("{bytes} bytes, por encima del tope de {tope}")
            }
            ErrorSuricata::OpcionNoSoportada(o) => format!("opcion «{o}»"),
            ErrorSuricata::RegexRechazada(d) => d.clone(),
            ErrorSuricata::DemasiadosPatrones { patrones, tope } => {
                format!("{patrones} patrones, por encima del tope de {tope}")
            }
            ErrorSuricata::SinCriterioEvaluable => {
                "se analizo entera, pero ninguna de sus opciones dice nada que el motor de \
                 hechos pueda mirar; compilarla daria una regla que casa con todo"
                    .to_string()
            }
        }
    }
}

/// Opciones que solo aportan metadatos: no condicionan la deteccion.
///
/// Se reconocen a proposito, para NO rechazar una regla por traerlas. Una regla
/// con `reference:cve,2021-1234` no es menos compilable por eso.
const METADATOS: &[&str] = &[
    "msg",
    "sid",
    "rev",
    "gid",
    "classtype",
    "reference",
    "priority",
    "metadata",
    "target",
    "noalert",
];

/// Opciones que acotan el flujo y que el motor ya cubre por otra via.
///
/// `flow:established,to_server` describe una condicion que la tabla de flujos de
/// la FASE 70 ya conoce. No se traduce a un criterio porque no hace falta: el
/// hecho solo existe si el flujo existia.
const DE_FLUJO: &[&str] = &["flow", "flowint", "stream_size"];

/// Opciones que operan sobre BYTES CRUDOS con aritmetica de desplazamientos.
///
/// Describen una maquina de bytes que el motor de hechos no tiene. Se reconocen
/// para poder rechazar la regla NOMBRANDO la opcion, en vez de compilarla sin
/// esa condicion —que casaria de mas— o de ignorarla en silencio.
const DE_BYTES: &[&str] = &[
    "byte_test",
    "byte_jump",
    "byte_extract",
    "byte_math",
    "isdataat",
    "base64_decode",
    "base64_data",
    "detection_filter",
    "threshold",
    "flowbits",
    "xbits",
    "hostbits",
    "luajit",
    "lua",
    "datarep",
    "dataset",
];

/// Modificadores que se aplican al `content` anterior.
const MODIFICADORES: &[&str] = &[
    "nocase",
    "depth",
    "offset",
    "distance",
    "within",
    "fast_pattern",
    "startswith",
    "endswith",
    "bsize",
    "rawbytes",
    "http_uri",
    "http_raw_uri",
    "http_method",
    "http_header",
    "http_raw_header",
    "http_cookie",
    "http_user_agent",
    "http_host",
    "http_client_body",
    "http_server_body",
    "http_stat_code",
    "http_stat_msg",
    "tls_sni",
    "tls_cert_subject",
    "dns_query",
];

/// Analiza el texto de una regla.
///
/// # Errores
/// [`ErrorSuricata`] con el motivo concreto: nunca se devuelve un «no se pudo»
/// sin nombre, porque el informe agrupa por motivo y un motivo generico no se
/// puede convertir en una lista de trabajo.
pub fn analizar(texto: &str, presupuesto: &Presupuesto) -> Result<ReglaSuricata, ErrorSuricata> {
    let texto = texto.trim();
    if texto.len() > presupuesto.max_bytes_regla {
        return Err(ErrorSuricata::DemasiadoGrande {
            bytes: texto.len(),
            tope: presupuesto.max_bytes_regla,
        });
    }

    let Some(abre) = texto.find('(') else {
        return Err(ErrorSuricata::Malformada(
            "no tiene parentesis de opciones".to_string(),
        ));
    };
    if !texto.ends_with(')') {
        return Err(ErrorSuricata::Malformada(
            "no acaba en parentesis de cierre".to_string(),
        ));
    }

    let cabecera = analizar_cabecera(&texto[..abre])?;
    let opciones = analizar_opciones(&texto[abre + 1..texto.len() - 1])?;

    Ok(ReglaSuricata {
        cabecera,
        opciones,
        texto: texto.to_string(),
    })
}

/// Analiza la cabecera `accion proto origen puerto sentido destino puerto`.
fn analizar_cabecera(texto: &str) -> Result<Cabecera, ErrorSuricata> {
    // Las listas van entre corchetes y pueden llevar espacios dentro:
    // `[1.2.3.4, 5.6.7.8]`. Partir por espacios a secas rompe ahi, asi que se
    // parte respetando el anidamiento.
    let campos = partir_respetando_corchetes(texto);
    if campos.len() != 7 {
        return Err(ErrorSuricata::Malformada(format!(
            "la cabecera tiene {} campos y hacen falta 7 («{}»)",
            campos.len(),
            texto.trim()
        )));
    }

    let accion = Accion::desde(&campos[0].to_ascii_lowercase())
        .ok_or_else(|| ErrorSuricata::AccionDesconocida(campos[0].clone()))?;
    let sentido = match campos[4].as_str() {
        "->" => Sentido::HaciaDestino,
        "<>" => Sentido::Ambos,
        // `<-` no existe en Suricata: la regla se escribe al reves. Rechazarla
        // con nombre es mejor que invertirla por nuestra cuenta y que detecte
        // en el sentido contrario al que su autor queria.
        otro => return Err(ErrorSuricata::SentidoDesconocido(otro.to_string())),
    };

    Ok(Cabecera {
        accion,
        protocolo: campos[1].to_ascii_lowercase(),
        origen: Extremo::analizar(&campos[2]),
        puerto_origen: Extremo::analizar(&campos[3]),
        sentido,
        destino: Extremo::analizar(&campos[5]),
        puerto_destino: Extremo::analizar(&campos[6]),
    })
}

/// Parte por espacios sin romper dentro de `[...]`.
fn partir_respetando_corchetes(texto: &str) -> Vec<String> {
    let mut campos = Vec::new();
    let mut actual = String::new();
    let mut nivel = 0usize;
    for c in texto.chars() {
        match c {
            '[' => {
                nivel += 1;
                actual.push(c);
            }
            ']' => {
                nivel = nivel.saturating_sub(1);
                actual.push(c);
            }
            c if c.is_whitespace() && nivel == 0 => {
                if !actual.is_empty() {
                    campos.push(std::mem::take(&mut actual));
                }
            }
            c => actual.push(c),
        }
    }
    if !actual.is_empty() {
        campos.push(actual);
    }
    campos
}

/// Analiza el cuerpo de opciones.
///
/// El punto delicado: el `;` separa opciones, **salvo dentro de comillas**.
/// `content:"a;b";` es UN patron que contiene un punto y coma, no dos opciones.
/// Partir por `;` a secas parte ese patron por la mitad y compila una regla que
/// busca otra cosa — sin error visible.
fn analizar_opciones(cuerpo: &str) -> Result<Vec<Opcion>, ErrorSuricata> {
    let mut opciones = Vec::new();
    let bytes = cuerpo.as_bytes();
    let mut inicio = 0usize;
    let mut en_comillas = false;
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' if en_comillas => {
                // Dentro de comillas, la barra invertida escapa al siguiente
                // byte: `content:"a\";b"` sigue siendo un solo patron.
                i += 2;
                continue;
            }
            b'"' => {
                en_comillas = !en_comillas;
                i += 1;
            }
            b';' if !en_comillas => {
                let trozo = cuerpo[inicio..i].trim();
                if !trozo.is_empty() {
                    opciones.push(analizar_opcion(trozo));
                }
                inicio = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    if en_comillas {
        return Err(ErrorSuricata::Malformada(
            "quedan comillas sin cerrar en las opciones".to_string(),
        ));
    }
    let cola = cuerpo[inicio..].trim();
    if !cola.is_empty() {
        opciones.push(analizar_opcion(cola));
    }
    Ok(opciones)
}

/// Separa una opcion en clave y valor.
fn analizar_opcion(trozo: &str) -> Opcion {
    match trozo.split_once(':') {
        Some((k, v)) => {
            let v = v.trim();
            let entrecomillado = v.len() >= 2 && v.starts_with('"') && v.ends_with('"');
            let valor = if entrecomillado {
                desescapar(&v[1..v.len() - 1])
            } else {
                v.to_string()
            };
            Opcion {
                clave: k.trim().to_ascii_lowercase(),
                valor,
                entrecomillado,
            }
        }
        None => Opcion {
            clave: trozo.trim().to_ascii_lowercase(),
            valor: String::new(),
            entrecomillado: false,
        },
    }
}

/// Quita los escapes de un valor entrecomillado.
fn desescapar(s: &str) -> String {
    let mut salida = String::with_capacity(s.len());
    let mut cs = s.chars();
    while let Some(c) = cs.next() {
        if c == '\\' {
            match cs.next() {
                Some(sig) => salida.push(sig),
                None => salida.push('\\'),
            }
        } else {
            salida.push(c);
        }
    }
    salida
}

/// Traduce el contenido de un `content:` a bytes.
///
/// Suricata permite mezclar texto y bytes en hexadecimal entre barras
/// verticales: `content:"GET |20 2f|admin"`. Interpretar eso mal cambia el
/// patron, asi que se hace aqui y no se da por hecho que todo es texto.
fn contenido_a_texto(valor: &str) -> String {
    let mut salida = String::new();
    let mut en_hex = false;
    let mut hex = String::new();
    for c in valor.chars() {
        if c == '|' {
            if en_hex {
                // Cierre: se vuelca lo acumulado.
                for par in hex.split_whitespace() {
                    if let Ok(b) = u8::from_str_radix(par, 16) {
                        salida.push(b as char);
                    }
                }
                hex.clear();
            }
            en_hex = !en_hex;
            continue;
        }
        if en_hex {
            hex.push(c);
        } else {
            salida.push(c);
        }
    }
    salida
}

/// El campo semantico al que apunta un `content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Campo {
    /// Ningun sticky buffer: carga cruda.
    Cruda,
    UriHttp,
    MetodoHttp,
    HostHttp,
    AgenteHttp,
    CabeceraHttp,
    SniTls,
    SujetoCertificado,
    ConsultaDns,
    Ja3,
    Ja3s,
}

impl Campo {
    /// Traduce el nombre de un sticky buffer moderno o un modificador clasico.
    fn desde(nombre: &str) -> Option<Campo> {
        match nombre {
            "http.uri" | "http.uri.raw" | "http_uri" | "http_raw_uri" => Some(Campo::UriHttp),
            "http.method" | "http_method" => Some(Campo::MetodoHttp),
            "http.host" | "http.host.raw" | "http_host" => Some(Campo::HostHttp),
            "http.user_agent" | "http_user_agent" => Some(Campo::AgenteHttp),
            "http.header" | "http.header.raw" | "http_header" | "http_raw_header"
            | "http.cookie" | "http_cookie" => Some(Campo::CabeceraHttp),
            "tls.sni" | "tls_sni" | "tls.server_name" => Some(Campo::SniTls),
            "tls.cert_subject" | "tls_cert_subject" => Some(Campo::SujetoCertificado),
            "dns.query" | "dns_query" | "dns.query.name" => Some(Campo::ConsultaDns),
            "ja3.hash" | "ja3_hash" => Some(Campo::Ja3),
            "ja3s.hash" | "ja3s_hash" => Some(Campo::Ja3s),
            _ => None,
        }
    }
}

/// Traduce una regla ya analizada a la regla que evalua el motor.
///
/// # Errores
/// [`ErrorSuricata`] nombrando la opcion concreta que impide traducirla.
pub fn traducir(r: &ReglaSuricata, presupuesto: &Presupuesto) -> Result<Vec<Regla>, ErrorSuricata> {
    let sid = r.sid();
    let nombre = if r.msg().is_empty() {
        format!("suricata:{sid}")
    } else {
        r.msg()
    };
    let id: u64 = sid.parse().unwrap_or_else(|_| hash_id(&sid));

    // PASADA PREVIA: a que campo apunta cada patron.
    //
    // Hace falta porque Suricata admite las dos sintaxis y el campo puede llegar
    // ANTES o DESPUES del patron:
    //
    //   moderna:  http.uri; content:"/admin";
    //   clasica:  content:"/admin"; http_uri;
    //
    // Resolver esto sobre la marcha obligaria a decidir sin haber leido todavia
    // el modificador que viene detras —que es justo lo que hacia fallar la
    // sintaxis clasica, con la que esta escrito medio catalogo historico—. Con
    // una pasada previa, las dos formas dan el mismo resultado por construccion.
    let campos = resolver_campos(&r.opciones);

    let mut criterios: Vec<Criterio> = Vec::new();
    let mut patrones = 0usize;

    for (indice, op) in r.opciones.iter().enumerate() {
        let clave = op.clave.as_str();

        // 1. Sticky buffer o modificador de campo: ya se resolvio en la pasada
        //    previa, aqui no aporta nada mas.
        if op.valor.is_empty() && Campo::desde(clave).is_some() {
            continue;
        }

        // 2. Metadatos y flujo: no condicionan lo que el motor mira.
        if METADATOS.contains(&clave) || DE_FLUJO.contains(&clave) {
            continue;
        }

        // 3. Aritmetica de bytes: se RECHAZA la regla entera, con nombre.
        if DE_BYTES.contains(&clave) {
            return Err(ErrorSuricata::OpcionNoSoportada(clave.to_string()));
        }

        match clave {
            "content" => {
                patrones += 1;
                if patrones > presupuesto.max_patrones_por_regla {
                    return Err(ErrorSuricata::DemasiadosPatrones {
                        patrones,
                        tope: presupuesto.max_patrones_por_regla,
                    });
                }
                let texto = contenido_a_texto(&op.valor);
                if texto.is_empty() {
                    continue;
                }
                let campo = campos.get(&indice).copied().unwrap_or(Campo::Cruda);
                let sensible = !modificador_tras(&r.opciones, indice, "nocase");
                match criterio_de_contenido(campo, &texto, sensible) {
                    Some(c) => criterios.push(c),
                    // Contenido sobre carga cruda: el motor de hechos no lo
                    // evalua. Se rechaza NOMBRANDOLO en vez de omitirlo, que
                    // daria una regla que casa de mas.
                    None => {
                        return Err(ErrorSuricata::OpcionNoSoportada(
                            "content sobre carga cruda (sin sticky buffer)".to_string(),
                        ))
                    }
                }
            }
            "pcre" => {
                patrones += 1;
                if patrones > presupuesto.max_patrones_por_regla {
                    return Err(ErrorSuricata::DemasiadosPatrones {
                        patrones,
                        tope: presupuesto.max_patrones_por_regla,
                    });
                }
                let (patron, banderas) = partir_pcre(&op.valor);
                // LA EXPRESION SE ANALIZA ANTES DE DISTRIBUIRLA. Una regex
                // patologica en una regla de red es una denegacion de servicio
                // contra nuestro propio IPS, firmada por nosotros.
                if let Err(pat) = regex_segura::analizar(&patron, presupuesto) {
                    return Err(ErrorSuricata::RegexRechazada(format!(
                        "{}: {}",
                        pat.codigo(),
                        pat.explicacion()
                    )));
                }
                let campo = campo_de_banderas_pcre(&banderas)
                    .or_else(|| campos.get(&indice).copied())
                    .unwrap_or(Campo::Cruda);
                // El motor compara subcadenas, no expresiones: una pcre solo se
                // traduce si es literalmente texto. Si no, se rechaza, en vez de
                // convertirse en una subcadena que casaria de otra forma.
                match literal_de_regex(&patron) {
                    Some(lit) if !lit.is_empty() => {
                        let sensible = !banderas.contains('i');
                        match criterio_de_contenido(campo, &lit, sensible) {
                            Some(c) => criterios.push(c),
                            None => {
                                return Err(ErrorSuricata::OpcionNoSoportada(
                                    "pcre sobre carga cruda".to_string(),
                                ))
                            }
                        }
                    }
                    _ => {
                        return Err(ErrorSuricata::OpcionNoSoportada(
                            "pcre con expresion no literal".to_string(),
                        ))
                    }
                }
            }
            "filemd5" | "filesha1" | "filesha256" => {
                return Err(ErrorSuricata::OpcionNoSoportada(format!(
                    "{clave} (la lista de hashes vive en otro fichero)"
                )));
            }
            "dsize" | "urilen" | "ttl" | "ipopts" | "fragbits" | "flags" | "itype" | "icode"
            | "id" | "seq" | "ack" | "window" | "ip_proto" | "tos" => {
                // Condiciones sobre campos del paquete que el motor de hechos no
                // expone. Se nombran una a una en vez de agruparlas, para que el
                // informe diga cual falta y se pueda priorizar.
                return Err(ErrorSuricata::OpcionNoSoportada(clave.to_string()));
            }
            // Condiciones de POSICION dentro del campo. El motor compara el
            // campo entero, asi que ignorar un `depth` casaria de mas.
            "depth" | "offset" | "distance" | "within" | "bsize" | "startswith" | "endswith" => {
                return Err(ErrorSuricata::OpcionNoSoportada(format!(
                    "{clave} (condicion de posicion dentro del campo)"
                )));
            }
            // Modificadores que no cambian ni el campo ni la posicion.
            _ if MODIFICADORES.contains(&clave) => {}
            otra => {
                // Cualquier cosa que no se reconozca. Se rechaza con su nombre
                // exacto: es lo que convierte «han fallado 1.200 reglas» en una
                // lista de trabajo concreta.
                return Err(ErrorSuricata::OpcionNoSoportada(otra.to_string()));
            }
        }
    }

    if criterios.is_empty() {
        return Err(ErrorSuricata::SinCriterioEvaluable);
    }

    // La confianza sale de la ACCION que pedia la regla y de la precision de su
    // criterio. Una regla que su autor escribio como `alert` no se convierte en
    // un corte por pasar por aqui: eso seria endurecer la politica de otro sin
    // que nadie lo haya decidido.
    let confianza = confianza_de(r, &criterios);

    Ok(criterios
        .into_iter()
        .enumerate()
        .map(|(n, criterio)| Regla {
            // Varias condiciones de la misma regla comparten identificador base
            // y se distinguen por el orden, para poder rastrear cada una hasta
            // su sid original.
            id: id.wrapping_mul(1000).wrapping_add(n as u64),
            nombre: nombre.clone(),
            confianza,
            criterio,
        })
        .collect())
}

/// A que campo apunta cada patron de la regla.
///
/// Resuelve las DOS sintaxis de Suricata en una sola pasada:
///
/// - **Moderna**: un sticky buffer (`http.uri;`) fija el campo para los patrones
///   que vienen detras, hasta el siguiente sticky buffer.
/// - **Clasica**: un modificador (`http_uri;`) detras de un patron fija el campo
///   de ESE patron.
///
/// Devuelve, para cada indice de opcion que sea `content` o `pcre`, su campo.
fn resolver_campos(opciones: &[Opcion]) -> BTreeMap<usize, Campo> {
    let mut campos = BTreeMap::new();
    let mut activo = Campo::Cruda;
    // Indices de los patrones que aun no tienen campo por modificador posterior.
    let mut pendientes: Vec<usize> = Vec::new();

    for (i, op) in opciones.iter().enumerate() {
        let clave = op.clave.as_str();
        let es_patron = clave == "content" || clave == "pcre";

        if es_patron {
            campos.insert(i, activo);
            pendientes.push(i);
            continue;
        }

        // LA DISTINCION ES SINTACTICA, y es la que usa Suricata:
        //
        //   - Con PUNTO (`http.uri`) es un sticky buffer MODERNO: fija el campo
        //     de los patrones que vienen DETRAS.
        //   - Con GUION BAJO (`http_uri`) es un modificador CLASICO: se aplica
        //     al patron que lo PRECEDE.
        //
        // Sin esta distincion, `http.method; content:"POST"; http.uri;` haria
        // que el `http.uri` reasignara el campo del «POST» que ya estaba
        // resuelto, y los campos saldrian todos desplazados una posicion: el
        // metodo buscado en la URI, la URI en el user-agent. La regla compilaria
        // sin error y no detectaria nada.
        if op.valor.is_empty() {
            if let Some(c) = Campo::desde(clave) {
                if clave.contains('.') {
                    // Sticky buffer moderno: mira hacia delante.
                    pendientes.clear();
                    activo = c;
                } else {
                    // Modificador clasico: mira hacia atras.
                    for idx in pendientes.drain(..) {
                        campos.insert(idx, c);
                    }
                }
                continue;
            }
        }

        // Cualquier otra opcion cierra el grupo de patrones pendientes: un
        // modificador que venga despues ya no es de ellos.
        if !MODIFICADORES.contains(&clave) {
            pendientes.clear();
        }
    }
    campos
}

/// Si tras el patron en `indice` aparece el modificador `nombre` antes del
/// siguiente patron.
///
/// En Suricata los modificadores se aplican al patron que los PRECEDE, asi que
/// para saber si un `content` lleva `nocase` hay que mirar hacia delante.
fn modificador_tras(opciones: &[Opcion], indice: usize, nombre: &str) -> bool {
    for sig in opciones.iter().skip(indice + 1) {
        if sig.clave == "content" || sig.clave == "pcre" {
            return false;
        }
        if sig.clave == nombre {
            return true;
        }
    }
    false
}

/// Construye el criterio para un contenido sobre un campo.
fn criterio_de_contenido(campo: Campo, texto: &str, sensible: bool) -> Option<Criterio> {
    match campo {
        Campo::Cruda => None,
        Campo::UriHttp => Some(Criterio::ContenidoUriHttp {
            aguja: texto.to_string(),
            distingue_mayusculas: sensible,
        }),
        Campo::MetodoHttp => Some(Criterio::MetodoHttp(texto.to_string())),
        Campo::HostHttp => Some(Criterio::HostHttp(texto.to_string())),
        Campo::AgenteHttp => Some(Criterio::AgenteHttp(texto.to_string())),
        Campo::CabeceraHttp => {
            // `http.header` busca en el bloque de cabeceras. Si el patron trae
            // `nombre: valor`, se parte; si no, se busca en cualquiera.
            match texto.split_once(':') {
                Some((n, v)) if !n.trim().is_empty() && !v.trim().is_empty() => {
                    Some(Criterio::CabeceraHttp {
                        nombre: n.trim().to_string(),
                        contiene: v.trim().to_string(),
                    })
                }
                _ => Some(Criterio::CabeceraHttp {
                    nombre: texto.trim_end_matches(':').trim().to_string(),
                    contiene: String::new(),
                }),
            }
        }
        Campo::SniTls => Some(Criterio::Sni(texto.to_string())),
        Campo::SujetoCertificado => Some(Criterio::SujetoCertificado(texto.to_string())),
        Campo::ConsultaDns => Some(Criterio::NombreDns(texto.to_string())),
        Campo::Ja3 => Some(Criterio::Ja3(texto.to_string())),
        Campo::Ja3s => Some(Criterio::Ja3s(texto.to_string())),
    }
}

/// Separa una pcre `"/patron/banderas"` en sus dos partes.
fn partir_pcre(valor: &str) -> (String, String) {
    let v = valor.trim();
    let Some(primera) = v.find('/') else {
        return (v.to_string(), String::new());
    };
    // El delimitador de cierre es la ULTIMA barra no escapada.
    let bytes = v.as_bytes();
    let mut ultima = None;
    let mut i = primera + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'/' {
            ultima = Some(i);
        }
        i += 1;
    }
    match ultima {
        Some(fin) if fin > primera => (v[primera + 1..fin].to_string(), v[fin + 1..].to_string()),
        _ => (v[primera + 1..].to_string(), String::new()),
    }
}

/// El campo al que apunta una pcre segun sus banderas.
///
/// Suricata usa letras finales para el buffer: `U` es la URI, `H` la cabecera,
/// `M` el metodo, `V` el user-agent. Ignorarlas haria que la expresion se
/// buscara en el sitio equivocado.
fn campo_de_banderas_pcre(banderas: &str) -> Option<Campo> {
    for c in banderas.chars() {
        let campo = match c {
            'U' | 'I' => Some(Campo::UriHttp),
            'H' | 'D' => Some(Campo::CabeceraHttp),
            'M' => Some(Campo::MetodoHttp),
            'V' => Some(Campo::AgenteHttp),
            'W' => Some(Campo::HostHttp),
            _ => None,
        };
        if campo.is_some() {
            return campo;
        }
    }
    None
}

/// Si la expresion es una cadena literal, la devuelve.
///
/// El motor compara subcadenas, no expresiones. Una pcre que sea literalmente
/// texto se puede traducir sin perder nada; una con metacaracteres, no — y se
/// rechaza en vez de convertirse en una subcadena que casaria de otra forma.
fn literal_de_regex(patron: &str) -> Option<String> {
    let mut salida = String::with_capacity(patron.len());
    let mut cs = patron.chars().peekable();
    while let Some(c) = cs.next() {
        match c {
            // Un anclaje al principio o al final no cambia el texto buscado.
            '^' if salida.is_empty() => continue,
            '$' if cs.peek().is_none() => continue,
            '\\' => match cs.next() {
                // Escape de un metacaracter: es el caracter literal.
                Some(sig) if !sig.is_ascii_alphanumeric() => salida.push(sig),
                // `\d`, `\w`, `\s`... no son literales.
                _ => return None,
            },
            c if "[](){}|*+?.".contains(c) => return None,
            c => salida.push(c),
        }
    }
    Some(salida)
}

/// Confianza que se le da a la regla traducida.
///
/// # Por que NO se hereda la accion tal cual
///
/// Una regla publica escrita como `drop` la escribio otro equipo para otra red.
/// Convertirla automaticamente en un corte aqui seria aplicar la politica de un
/// tercero sobre la red de nuestro cliente sin que nadie lo haya decidido.
///
/// La accion pesa —una regla que su autor marco `alert` no puede acabar
/// cortando— pero el techo lo pone la PRECISION del criterio: una igualdad
/// exacta contra una huella o un nombre admite confianza alta; una subcadena
/// dentro de un user-agent, no.
fn confianza_de(r: &ReglaSuricata, criterios: &[Criterio]) -> Confianza {
    // Una regla que su autor no queria que cortara, no corta.
    if !matches!(r.cabecera.accion, Accion::Drop | Accion::Reject) {
        return Confianza::Media;
    }
    let exacta = criterios.iter().all(|c| {
        matches!(
            c,
            Criterio::Ja3(_)
                | Criterio::Ja3s(_)
                | Criterio::Ja4(_)
                | Criterio::HashFichero(_)
                | Criterio::HuellaCertificado(_)
                | Criterio::NombreDns(_)
                | Criterio::SufijoDns(_)
                | Criterio::Sni(_)
                | Criterio::HostHttp(_)
        )
    });
    if exacta {
        Confianza::Alta
    } else {
        Confianza::Media
    }
}

/// Identificador estable para una regla sin `sid` numerico.
///
/// FNV-1a y no el `DefaultHasher` de la biblioteca estandar: el de la estandar
/// no garantiza estabilidad entre versiones de Rust, y un identificador de regla
/// que cambia al recompilar rompe la trazabilidad entre corpus.
fn hash_id(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Compila un fichero de reglas entero.
///
/// Devuelve las reglas traducidas y el informe con cuantas de cuantas y por que
/// las demas no.
#[must_use]
pub fn compilar(fuente: &str, presupuesto: &Presupuesto) -> (Vec<Regla>, Informe) {
    let mut salida = Vec::new();
    let mut informe = Informe::default();
    // Deduplicacion por sid: los feeds se solapan, y la misma regla en dos
    // ficheros no es dos reglas.
    let mut vistos: BTreeMap<String, ()> = BTreeMap::new();

    if fuente.len() > presupuesto.max_bytes_entrada {
        informe.rechazada(Rechazo::nuevo(
            "(fichero)",
            "entrada-demasiado-grande",
            format!(
                "{} bytes, por encima del tope de {}",
                fuente.len(),
                presupuesto.max_bytes_entrada
            ),
        ));
        return (salida, informe);
    }

    for linea in fuente.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if informe.vistas >= presupuesto.max_reglas {
            informe.rechazada(Rechazo::nuevo(
                "(resto del fichero)",
                "demasiadas-reglas",
                format!("se paso el tope de {} reglas", presupuesto.max_reglas),
            ));
            break;
        }

        match analizar(l, presupuesto) {
            Ok(r) => {
                let sid = r.sid();
                if sid != "sin-sid" && vistos.insert(sid.clone(), ()).is_some() {
                    informe.duplicada();
                    continue;
                }
                match traducir(&r, presupuesto) {
                    Ok(reglas) => {
                        salida.extend(reglas);
                        informe.compilada();
                    }
                    Err(e) => informe.rechazada(Rechazo::nuevo(sid, e.codigo(), e.detalle())),
                }
            }
            Err(e) => informe.rechazada(Rechazo::nuevo(
                recorte_para_informe(l),
                e.codigo(),
                e.detalle(),
            )),
        }
    }
    (salida, informe)
}

/// Recorta una linea para citarla en el informe sin volcarla entera.
fn recorte_para_informe(l: &str) -> String {
    const TOPE: usize = 80;
    if l.len() <= TOPE {
        return l.to_string();
    }
    let mut fin = TOPE;
    while fin < l.len() && !l.is_char_boundary(fin) {
        fin += 1;
    }
    format!("{}…", &l[..fin])
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    /// UNA REGLA REAL, de las que trae Emerging Threats, escrita entera.
    const REGLA_REAL: &str = r#"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Win32/Agent CnC Checkin"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/gate.php"; nocase; http.user_agent; content:"Mozilla/4.0"; reference:md5,0123456789abcdef; classtype:trojan-activity; sid:2018316; rev:5; metadata:created_at 2014_04_01;)"#;

    #[test]
    fn una_regla_real_se_analiza_entera() {
        let r = analizar(REGLA_REAL, &p()).expect("la regla es valida");
        assert_eq!(r.cabecera.accion, Accion::Alert);
        assert_eq!(r.cabecera.protocolo, "http");
        assert_eq!(r.cabecera.sentido, Sentido::HaciaDestino);
        assert_eq!(r.cabecera.origen.texto, "$HOME_NET");
        assert!(r.cabecera.puerto_destino.cualquiera);
        assert_eq!(r.sid(), "2018316");
        assert_eq!(r.msg(), "ET TROJAN Win32/Agent CnC Checkin");
    }

    /// Y SE TRADUCE a criterios que el motor evalua de verdad, cada uno sobre su
    /// campo: el metodo al metodo, la URI a la URI y el agente al agente.
    #[test]
    fn una_regla_real_se_traduce_a_criterios_sobre_su_campo() {
        let r = analizar(REGLA_REAL, &p()).unwrap();
        let reglas = traducir(&r, &p()).expect("traducible");

        let criterios: Vec<&Criterio> = reglas.iter().map(|x| &x.criterio).collect();
        assert!(
            criterios
                .iter()
                .any(|c| matches!(c, Criterio::MetodoHttp(m) if m == "POST")),
            "{criterios:?}"
        );
        assert!(
            criterios.iter().any(|c| matches!(
                c,
                Criterio::ContenidoUriHttp { aguja, distingue_mayusculas: false } if aguja == "/gate.php"
            )),
            "el `nocase` que sigue al content tiene que aplicarse: {criterios:?}"
        );
        assert!(
            criterios
                .iter()
                .any(|c| matches!(c, Criterio::AgenteHttp(a) if a == "Mozilla/4.0")),
            "{criterios:?}"
        );
        // Todas conservan el nombre y el sid de origen.
        assert!(reglas.iter().all(|x| x.nombre.contains("ET TROJAN")));
    }

    /// EL PUNTO Y COMA DENTRO DE COMILLAS NO SEPARA OPCIONES. Partir por `;` a
    /// secas parte el patron por la mitad y compila una regla que busca otra
    /// cosa, sin ningun error visible.
    #[test]
    fn un_punto_y_coma_dentro_del_patron_no_parte_la_opcion() {
        let regla = r#"alert http any any -> any any (msg:"x"; http.uri; content:"a;b;c"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let content = r
            .opciones
            .iter()
            .find(|o| o.clave == "content")
            .expect("hay content");
        assert_eq!(content.valor, "a;b;c");
    }

    /// Y una comilla escapada dentro del patron tampoco cierra el entrecomillado.
    #[test]
    fn una_comilla_escapada_no_cierra_el_patron() {
        let regla =
            r#"alert http any any -> any any (msg:"x"; http.uri; content:"di \"hola\""; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let content = r.opciones.iter().find(|o| o.clave == "content").unwrap();
        assert_eq!(content.valor, "di \"hola\"");
    }

    /// Los bytes en hexadecimal entre barras se interpretan: `|20|` es un
    /// espacio, no el texto «|20|».
    #[test]
    fn el_contenido_en_hexadecimal_se_interpreta() {
        assert_eq!(contenido_a_texto("GET|20|/admin"), "GET /admin");
        assert_eq!(contenido_a_texto("|48 54 54 50|"), "HTTP");
        assert_eq!(contenido_a_texto("sin hex"), "sin hex");
    }

    /// Una lista de direcciones con espacios dentro NO parte la cabecera.
    #[test]
    fn una_lista_de_direcciones_con_espacios_no_rompe_la_cabecera() {
        let regla = r#"alert tcp [10.0.0.0/8, 192.168.0.0/16] any -> $EXTERNAL_NET [80, 443] (msg:"x"; tls.sni; content:"malo.com"; sid:1;)"#;
        let r = analizar(regla, &p()).expect("la cabecera se parte respetando corchetes");
        // El texto se conserva TAL Y COMO VENIA —espacios incluidos— porque es
        // lo que permite citar la regla en el informe y encontrarla en el
        // fichero original. Lo que importa aqui es que no se PARTIO.
        assert_eq!(r.cabecera.origen.texto, "[10.0.0.0/8, 192.168.0.0/16]");
        assert_eq!(r.cabecera.puerto_destino.texto, "[80, 443]");
        assert!(!r.cabecera.origen.cualquiera);
    }

    /// LA DECISION CENTRAL DEL MODULO: una opcion que el motor no evalua hace
    /// que la regla se RECHACE CON NOMBRE. Compilarla sin esa condicion daria
    /// una regla que casa de mas, y eso no se ve hasta que detecta de mas.
    #[test]
    fn una_opcion_de_aritmetica_de_bytes_rechaza_la_regla_con_su_nombre() {
        let regla = r#"alert tcp any any -> any any (msg:"x"; http.uri; content:"a"; byte_test:4,>,1000,0; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let e = traducir(&r, &p()).unwrap_err();
        assert_eq!(e.codigo(), "suricata-opcion-no-soportada");
        assert!(e.detalle().contains("byte_test"), "{}", e.detalle());
    }

    /// Las condiciones de POSICION dentro del campo tambien se rechazan: el
    /// motor compara el campo entero, asi que ignorar un `depth` casaria de mas.
    #[test]
    fn una_condicion_de_posicion_rechaza_la_regla() {
        for opcion in ["depth:10", "offset:4", "distance:0", "within:20"] {
            let regla = format!(
                r#"alert http any any -> any any (msg:"x"; http.uri; content:"a"; {opcion}; sid:1;)"#
            );
            let r = analizar(&regla, &p()).unwrap();
            let e = traducir(&r, &p()).unwrap_err();
            assert_eq!(e.codigo(), "suricata-opcion-no-soportada", "con {opcion}");
        }
    }

    /// UNA REGLA QUE NO DEJA NINGUN CRITERIO NO SE COMPILA. Si se compilara,
    /// seria una regla que casa con TODO: el peor resultado posible.
    #[test]
    fn una_regla_sin_criterio_evaluable_no_se_compila() {
        let regla = r#"alert tcp any any -> any any (msg:"solo metadatos"; flow:established; sid:1; rev:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let e = traducir(&r, &p()).unwrap_err();
        assert_eq!(e.codigo(), "suricata-sin-criterio-evaluable");
    }

    /// UNA REGLA CON EXPRESION PATOLOGICA NO SE DISTRIBUYE. Es una denegacion de
    /// servicio contra nuestro propio IPS, firmada por nosotros.
    #[test]
    fn una_regla_con_expresion_patologica_se_rechaza() {
        let regla = r#"alert http any any -> any any (msg:"x"; pcre:"/(a+)+$/U"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let e = traducir(&r, &p()).unwrap_err();
        assert_eq!(e.codigo(), "regex-patologica");
        assert!(e.detalle().contains("cuantificador"), "{}", e.detalle());
    }

    /// Una pcre literal SI se traduce, y a su campo correcto segun la bandera.
    #[test]
    fn una_pcre_literal_se_traduce_al_campo_de_su_bandera() {
        let regla = r#"alert http any any -> any any (msg:"x"; pcre:"/\/wp-admin\//U"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let reglas = traducir(&r, &p()).expect("traducible");
        assert!(
            matches!(
                &reglas[0].criterio,
                Criterio::ContenidoUriHttp { aguja, .. } if aguja == "/wp-admin/"
            ),
            "{:?}",
            reglas[0].criterio
        );
    }

    /// La bandera `i` de una pcre apaga la distincion de mayusculas.
    #[test]
    fn la_bandera_i_de_una_pcre_apaga_la_distincion_de_mayusculas() {
        let regla = r#"alert http any any -> any any (msg:"x"; pcre:"/admin/Ui"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let reglas = traducir(&r, &p()).unwrap();
        assert!(matches!(
            &reglas[0].criterio,
            Criterio::ContenidoUriHttp {
                distingue_mayusculas: false,
                ..
            }
        ));
    }

    /// LA POLITICA DE OTRO NO SE APLICA SOBRE LA RED DEL CLIENTE. Una regla que
    /// su autor escribio como `alert` no puede acabar cortando por pasar por
    /// aqui.
    #[test]
    fn una_regla_de_alerta_nunca_sube_a_confianza_de_corte() {
        let regla =
            r#"alert tls any any -> any any (msg:"x"; tls.sni; content:"malo.com"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let reglas = traducir(&r, &p()).unwrap();
        assert_eq!(reglas[0].confianza, Confianza::Media);
        assert!(!reglas[0].confianza.puede_cortar());
    }

    /// Y una que su autor SI escribio como `drop`, con un criterio exacto, llega
    /// a confianza alta.
    #[test]
    fn una_regla_de_corte_con_criterio_exacto_llega_a_confianza_alta() {
        let regla = r#"drop tls any any -> any any (msg:"x"; tls.sni; content:"malo.com"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let reglas = traducir(&r, &p()).unwrap();
        assert_eq!(reglas[0].confianza, Confianza::Alta);
    }

    /// Pero un `drop` con criterio IMPRECISO no llega a alta: una subcadena
    /// dentro de un user-agent no admite cortar la red de nadie.
    #[test]
    fn un_corte_con_criterio_impreciso_no_llega_a_confianza_alta() {
        let regla =
            r#"drop http any any -> any any (msg:"x"; http.user_agent; content:"Mozilla"; sid:1;)"#;
        let r = analizar(regla, &p()).unwrap();
        let reglas = traducir(&r, &p()).unwrap();
        assert_eq!(reglas[0].confianza, Confianza::Media);
    }

    /// El informe dice CUANTAS DE CUANTAS y por que las demas no.
    #[test]
    fn el_informe_dice_cuantas_de_cuantas_y_por_que() {
        let fuente = format!(
            "# comentario\n\
             {REGLA_REAL}\n\
             alert tcp any any -> any any (msg:\"bytes\"; http.uri; content:\"a\"; byte_test:4,>,1,0; sid:2;)\n\
             alert http any any -> any any (msg:\"pat\"; pcre:\"/(x+)+$/U\"; sid:3;)\n\
             esto no es una regla\n"
        );
        let (reglas, informe) = compilar(&fuente, &p());

        assert!(!reglas.is_empty(), "la regla real tiene que compilar");
        assert_eq!(informe.vistas, 4);
        assert_eq!(informe.compiladas, 1);
        assert_eq!(informe.rechazadas(), 3);

        let motivos: Vec<&str> = informe.por_motivo().iter().map(|(m, _)| *m).collect();
        assert!(
            motivos.contains(&"suricata-opcion-no-soportada"),
            "{motivos:?}"
        );
        assert!(motivos.contains(&"regex-patologica"), "{motivos:?}");
        assert!(motivos.contains(&"suricata-malformada"), "{motivos:?}");

        let resumen = informe.resumen();
        assert!(resumen.contains("1 de 4"), "{resumen}");
    }

    /// Las reglas duplicadas por `sid` no se cuentan dos veces: los feeds se
    /// solapan, y la misma regla en dos ficheros no es dos reglas.
    #[test]
    fn las_reglas_duplicadas_por_sid_se_descartan() {
        let fuente = format!("{REGLA_REAL}\n{REGLA_REAL}\n");
        let (_, informe) = compilar(&fuente, &p());
        assert_eq!(informe.compiladas, 1);
        assert_eq!(informe.duplicadas, 1);
    }

    /// El presupuesto acota un feed hostil: sin esto, un fichero generado tumba
    /// la fabrica, y con ella el plano de control de la flota entera.
    #[test]
    fn un_feed_desmesurado_se_corta_por_presupuesto() {
        let estrecho = Presupuesto::estrecho();
        let mut fuente = String::new();
        for n in 0..50 {
            fuente.push_str(&format!(
                "alert tls any any -> any any (msg:\"x\"; tls.sni; content:\"m{n}.com\"; sid:{n};)\n"
            ));
        }
        let (_, informe) = compilar(&fuente, &estrecho);
        assert!(informe.vistas <= estrecho.max_reglas + 1);
        assert!(
            informe
                .por_motivo()
                .iter()
                .any(|(m, _)| *m == "demasiadas-reglas"),
            "y se DICE que se corto: {:?}",
            informe.por_motivo()
        );
    }

    /// Una regla mas grande que el tope no se analiza siquiera.
    #[test]
    fn una_regla_gigante_se_rechaza_por_tamano() {
        let estrecho = Presupuesto::estrecho();
        let regla = format!(
            "alert http any any -> any any (msg:\"{}\"; http.uri; content:\"a\"; sid:1;)",
            "x".repeat(500)
        );
        let e = analizar(&regla, &estrecho).unwrap_err();
        assert_eq!(e.codigo(), "suricata-demasiado-grande");
    }

    /// El sentido `<-` no existe en Suricata. Invertirlo por nuestra cuenta
    /// haria que la regla detectara en el sentido contrario al que queria su
    /// autor, asi que se rechaza con nombre.
    #[test]
    fn un_sentido_invalido_se_rechaza_en_vez_de_adivinarse() {
        let regla = r#"alert tcp any any <- any any (msg:"x"; sid:1;)"#;
        let e = analizar(regla, &p()).unwrap_err();
        assert_eq!(e.codigo(), "suricata-sentido-desconocido");
    }

    /// La sintaxis CLASICA —modificador despues del content— tiene que dar el
    /// mismo resultado que la moderna. Si no, medio catalogo se compilaria mal.
    #[test]
    fn la_sintaxis_clasica_y_la_moderna_dan_el_mismo_criterio() {
        let moderna =
            r#"alert http any any -> any any (msg:"x"; http.uri; content:"/admin"; sid:1;)"#;
        let clasica =
            r#"alert http any any -> any any (msg:"x"; content:"/admin"; http_uri; sid:2;)"#;

        let a = traducir(&analizar(moderna, &p()).unwrap(), &p()).unwrap();
        let b = traducir(&analizar(clasica, &p()).unwrap(), &p()).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].criterio, b[0].criterio);
    }

    /// EL FALLO QUE COMPILA SIN ERROR Y NO DETECTA NADA: si un sticky buffer
    /// moderno se confundiera con un modificador clasico, los campos saldrian
    /// desplazados una posicion —el metodo buscado en la URI, la URI en el
    /// user-agent— y la regla compilaria perfectamente sin detectar nunca.
    ///
    /// La distincion es sintactica y es la que usa Suricata: punto para el
    /// sticky buffer moderno, guion bajo para el modificador clasico.
    #[test]
    fn los_campos_no_se_desplazan_al_encadenar_varios_sticky_buffers() {
        let regla = r#"alert http any any -> any any (msg:"x"; http.method; content:"POST"; http.uri; content:"/gate.php"; http.user_agent; content:"Mozilla/4.0"; sid:1;)"#;
        let reglas = traducir(&analizar(regla, &p()).unwrap(), &p()).unwrap();
        let cs: Vec<&Criterio> = reglas.iter().map(|r| &r.criterio).collect();

        assert_eq!(cs.len(), 3, "{cs:?}");
        assert!(
            matches!(cs[0], Criterio::MetodoHttp(m) if m == "POST"),
            "el metodo al metodo: {cs:?}"
        );
        assert!(
            matches!(cs[1], Criterio::ContenidoUriHttp { aguja, .. } if aguja == "/gate.php"),
            "la URI a la URI: {cs:?}"
        );
        assert!(
            matches!(cs[2], Criterio::AgenteHttp(a) if a == "Mozilla/4.0"),
            "el agente al agente: {cs:?}"
        );
    }

    /// Y encadenar modificadores CLASICOS tampoco desplaza nada.
    #[test]
    fn los_campos_tampoco_se_desplazan_con_la_sintaxis_clasica() {
        let regla = r#"alert http any any -> any any (msg:"x"; content:"POST"; http_method; content:"/gate.php"; http_uri; sid:1;)"#;
        let reglas = traducir(&analizar(regla, &p()).unwrap(), &p()).unwrap();
        let cs: Vec<&Criterio> = reglas.iter().map(|r| &r.criterio).collect();
        assert!(
            matches!(cs[0], Criterio::MetodoHttp(m) if m == "POST"),
            "{cs:?}"
        );
        assert!(
            matches!(cs[1], Criterio::ContenidoUriHttp { aguja, .. } if aguja == "/gate.php"),
            "{cs:?}"
        );
    }

    /// El identificador de una regla sin sid numerico es ESTABLE entre
    /// ejecuciones: si cambiara, se perderia la trazabilidad entre corpus.
    #[test]
    fn el_identificador_derivado_es_estable() {
        assert_eq!(hash_id("regla-sin-sid"), hash_id("regla-sin-sid"));
        assert_ne!(hash_id("a"), hash_id("b"));
    }

    /// Ninguna entrada arbitraria puede tumbar el analizador: lo que analiza son
    /// ficheros de feeds que pueden estar comprometidos.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "alert",
            "tcp",
            "any",
            "->",
            "(",
            ")",
            ";",
            ":",
            "\"",
            "content",
            "pcre",
            "|",
            "[",
            "]",
            "!",
            "$HOME_NET",
            "\\",
            "sid",
            "1",
        ];
        let mut semilla = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..3_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 25) as usize;
            let linea: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect::<Vec<&str>>()
                .join(" ");
            if let Ok(r) = analizar(&linea, &p()) {
                let _ = traducir(&r, &p());
            }
        }
    }
}
