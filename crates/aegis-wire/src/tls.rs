//! Disector de TLS: SNI, ALPN, certificados y las huellas JA3, JA3S y JA4.
//!
//! # Por que la huella es la senal mas util de todo el trafico cifrado
//!
//! El contenido va cifrado, pero **el saludo del cliente va en claro**, y en el
//! va la forma exacta en que la pila TLS del que llama se presenta: que suites
//! ofrece, en que orden, que extensiones manda y en que orden. Eso es una huella
//! de la **biblioteca y su configuracion**, no del sitio al que se conecta.
//!
//! Por eso funciona: una familia de malware compilada contra una version
//! concreta de una biblioteca TLS produce siempre la misma huella, vaya al
//! dominio que vaya. Cambiarla exige recompilar con otra pila, que es mucho mas
//! caro que cambiar de dominio o de certificado.
//!
//! # Los valores GREASE, y por que filtrarlos no es opcional
//!
//! Los navegadores modernos meten valores **aleatorios** en la lista de suites y
//! de extensiones —el mecanismo GREASE— justamente para que nadie asuma que la
//! lista es fija. Si el disector no los quita, la huella de Chrome **cambia en
//! cada conexion**, y toda la tecnica deja de servir sin que nadie se entere:
//! no falla, simplemente no casa con nada nunca.
//!
//! Es el tipo de defecto que pasa todas las pruebas escritas con un unico
//! saludo capturado. Aqui hay una prueba dedicada a ello.
//!
//! # Que variante de JA4 se implementa
//!
//! JA4 tiene tres partes: una legible (`a`), el resumen de suites (`b`) y el de
//! extensiones mas algoritmos de firma (`c`). Se implementa la del documento
//! original de FoxIO: transporte, version negociada —tomada de
//! `supported_versions` si viene, que es lo correcto en TLS 1.3—, presencia de
//! SNI, cuentas de suites y extensiones acotadas a 99, y las dos primeras letras
//! del primer ALPN. Los resumenes son los primeros doce caracteres del SHA-256
//! de las listas **ordenadas**. Se documenta aqui porque una implementacion que
//! difiera en un detalle produce huellas que no casan con las bases publicas, y
//! ese fallo tambien es silencioso.

use sha2::{Digest, Sha256};

use crate::der;
use crate::error::{ErrorDiseccion, Resultado};
use crate::hecho::{Hecho, ProtocoloApp};
use crate::lector::Lector;

/// Tipo de registro: handshake.
pub const REGISTRO_HANDSHAKE: u8 = 22;

/// Tipo de registro mas bajo que existe (cambio de cifrado).
pub const REGISTRO_MINIMO: u8 = 20;
/// Tipo de registro mas alto que existe (datos de aplicacion).
pub const REGISTRO_MAXIMO: u8 = 23;

/// Bytes de la cabecera de un registro TLS: tipo, version y longitud.
pub const CABECERA_REGISTRO: usize = 5;

/// Tope de la carga de un registro TLS.
///
/// La norma fija 2^14 de texto en claro y permite hasta 2048 bytes mas de
/// expansion por el cifrado. Un registro que declare mas no es TLS: es alguien
/// pidiendo que se reserve memoria por un numero inventado.
pub const MAX_CARGA_REGISTRO: usize = 16384 + 2048;

/// Handshake: saludo del cliente.
pub const HS_CLIENTE: u8 = 1;
/// Handshake: saludo del servidor.
pub const HS_SERVIDOR: u8 = 2;
/// Handshake: certificado.
pub const HS_CERTIFICADO: u8 = 11;

/// Extension: nombre del servidor.
pub const EXT_SNI: u16 = 0;
/// Extension: grupos soportados (curvas).
pub const EXT_GRUPOS: u16 = 10;
/// Extension: formatos de punto.
pub const EXT_FORMATOS: u16 = 11;
/// Extension: algoritmos de firma.
pub const EXT_FIRMAS: u16 = 13;
/// Extension: ALPN.
pub const EXT_ALPN: u16 = 16;
/// Extension: versiones soportadas.
pub const EXT_VERSIONES: u16 = 43;

/// Tope de suites, extensiones o grupos que se leen de un saludo.
pub const MAX_LISTA: usize = 512;

/// Tope de certificados de una cadena.
pub const MAX_CERTIFICADOS: usize = 16;

/// Si un valor es GREASE.
///
/// El patron es `0x?A?A` con los dos bytes iguales: `0x0A0A`, `0x1A1A`, ...,
/// `0xFAFA`. **No filtrarlos hace que la huella de Chrome cambie en cada
/// conexion** y la tecnica entera deje de servir en silencio.
#[must_use]
pub fn es_grease(v: u16) -> bool {
    let alto = (v >> 8) as u8;
    let bajo = (v & 0xFF) as u8;
    alto == bajo && (alto & 0x0F) == 0x0A
}

/// Nombre legible de una version del protocolo.
#[must_use]
pub fn nombre_version(v: u16) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",
        _ => "desconocida",
    }
}

/// Codigo de dos cifras que JA4 usa para la version.
fn version_ja4(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// Lo que se extrae de un saludo del cliente.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SaludoCliente {
    /// Version anunciada en el campo clasico.
    pub version_clasica: u16,
    /// Version real negociada (de `supported_versions` si viene).
    pub version_efectiva: u16,
    /// Suites ofrecidas, ya sin GREASE.
    pub suites: Vec<u16>,
    /// Extensiones presentes, en orden y sin GREASE.
    pub extensiones: Vec<u16>,
    /// Grupos (curvas) ofrecidos, sin GREASE.
    pub grupos: Vec<u16>,
    /// Formatos de punto ofrecidos.
    pub formatos: Vec<u8>,
    /// Algoritmos de firma ofrecidos.
    pub firmas: Vec<u16>,
    /// Nombre del servidor solicitado.
    pub sni: String,
    /// Protocolos ofrecidos por ALPN.
    pub alpn: Vec<String>,
}

impl SaludoCliente {
    /// La huella JA3: `MD5(version,suites,extensiones,grupos,formatos)`.
    #[must_use]
    pub fn ja3(&self) -> String {
        let unir = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join("-");
        let cadena = format!(
            "{},{},{},{},{}",
            self.version_clasica,
            unir(&self.suites),
            unir(&self.extensiones),
            unir(&self.grupos),
            self.formatos
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("-")
        );
        crate::md5::hex(cadena.as_bytes())
    }

    /// La huella JA4.
    #[must_use]
    pub fn ja4(&self) -> String {
        let sni = if self.sni.is_empty() { 'i' } else { 'd' };
        let n_suites = self.suites.len().min(99);
        let n_ext = self.extensiones.len().min(99);
        let alpn = match self.alpn.first() {
            Some(a) if a.len() >= 2 => {
                let b = a.as_bytes();
                format!("{}{}", b[0] as char, b[b.len() - 1] as char)
            }
            Some(a) if a.len() == 1 => format!("{}{}", a, a),
            _ => "00".to_string(),
        };
        let a = format!(
            "t{}{}{:02}{:02}{}",
            version_ja4(self.version_efectiva),
            sni,
            n_suites,
            n_ext,
            alpn
        );

        let mut suites = self.suites.clone();
        suites.sort_unstable();
        let b = resumen12(
            &suites
                .iter()
                .map(|s| format!("{s:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );

        // JA4 excluye SNI y ALPN de la lista de extensiones: son contenido, no
        // forma de la pila, y meterlos haria que la huella cambiara con el
        // destino en vez de con el cliente.
        let mut ext: Vec<u16> = self
            .extensiones
            .iter()
            .copied()
            .filter(|e| *e != EXT_SNI && *e != EXT_ALPN)
            .collect();
        ext.sort_unstable();
        let c = resumen12(&format!(
            "{}_{}",
            ext.iter()
                .map(|e| format!("{e:04x}"))
                .collect::<Vec<_>>()
                .join(","),
            self.firmas
                .iter()
                .map(|f| format!("{f:04x}"))
                .collect::<Vec<_>>()
                .join(",")
        ));

        format!("{a}_{b}_{c}")
    }
}

/// Los doce primeros caracteres del SHA-256 en hexadecimal.
fn resumen12(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .chars()
        .take(12)
        .collect()
}

/// Lo que se extrae de un saludo del servidor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SaludoServidor {
    /// Version del campo clasico.
    pub version_clasica: u16,
    /// Version efectiva.
    pub version_efectiva: u16,
    /// Suite elegida.
    pub suite: u16,
    /// Extensiones devueltas.
    pub extensiones: Vec<u16>,
}

impl SaludoServidor {
    /// La huella JA3S: `MD5(version,suite,extensiones)`.
    #[must_use]
    pub fn ja3s(&self) -> String {
        let cadena = format!(
            "{},{},{}",
            self.version_clasica,
            self.suite,
            self.extensiones
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("-")
        );
        crate::md5::hex(cadena.as_bytes())
    }
}

/// Analiza un saludo del cliente a partir del cuerpo del handshake.
///
/// # Errores
/// Truncamiento o longitudes que no cuadran.
pub fn analizar_saludo_cliente(cuerpo: &[u8]) -> Resultado<SaludoCliente> {
    let mut l = Lector::nuevo(cuerpo);
    let mut s = SaludoCliente {
        version_clasica: l.u16("tls.version")?,
        ..Default::default()
    };
    s.version_efectiva = s.version_clasica;
    l.saltar(32, "tls.aleatorio")?;
    let _sesion = l.bloque_u8("tls.sesion")?;

    let suites = l.bloque_u16("tls.suites")?;
    let mut sl = Lector::nuevo(suites);
    while !sl.vacio() && s.suites.len() < MAX_LISTA {
        let v = sl.u16("tls.suite")?;
        if !es_grease(v) {
            s.suites.push(v);
        }
    }

    let _compresion = l.bloque_u8("tls.compresion")?;

    // Las extensiones pueden no venir (TLS muy antiguo): no es un error.
    let Ok(ext) = l.bloque_u16("tls.extensiones") else {
        return Ok(s);
    };
    let mut el = Lector::nuevo(ext);
    while el.restante() >= 4 && s.extensiones.len() < MAX_LISTA {
        let tipo = el.u16("tls.ext.tipo")?;
        let datos = el.bloque_u16("tls.ext.datos")?;
        if es_grease(tipo) {
            continue;
        }
        s.extensiones.push(tipo);

        match tipo {
            EXT_SNI => {
                let mut sl = Lector::nuevo(datos);
                if let Ok(lista) = sl.bloque_u16("tls.sni.lista") {
                    let mut nl = Lector::nuevo(lista);
                    // Tipo 0 = nombre de anfitrion. Es el unico definido.
                    if nl.u8("tls.sni.tipo").is_ok() {
                        if let Ok(n) = nl.bloque_u16("tls.sni.nombre") {
                            s.sni = crate::lector::ascii_legible(n);
                        }
                    }
                }
            }
            EXT_GRUPOS => {
                let mut gl = Lector::nuevo(datos);
                if let Ok(lista) = gl.bloque_u16("tls.grupos.lista") {
                    let mut ll = Lector::nuevo(lista);
                    while !ll.vacio() && s.grupos.len() < MAX_LISTA {
                        let Ok(g) = ll.u16("tls.grupo") else { break };
                        if !es_grease(g) {
                            s.grupos.push(g);
                        }
                    }
                }
            }
            EXT_FORMATOS => {
                let mut fl = Lector::nuevo(datos);
                if let Ok(lista) = fl.bloque_u8("tls.formatos.lista") {
                    s.formatos = lista.to_vec();
                }
            }
            EXT_FIRMAS => {
                let mut fl = Lector::nuevo(datos);
                if let Ok(lista) = fl.bloque_u16("tls.firmas.lista") {
                    let mut ll = Lector::nuevo(lista);
                    while !ll.vacio() && s.firmas.len() < MAX_LISTA {
                        let Ok(f) = ll.u16("tls.firma") else { break };
                        if !es_grease(f) {
                            s.firmas.push(f);
                        }
                    }
                }
            }
            EXT_ALPN => {
                let mut al = Lector::nuevo(datos);
                if let Ok(lista) = al.bloque_u16("tls.alpn.lista") {
                    let mut ll = Lector::nuevo(lista);
                    while !ll.vacio() && s.alpn.len() < 16 {
                        let Ok(p) = ll.bloque_u8("tls.alpn.proto") else {
                            break;
                        };
                        s.alpn.push(crate::lector::ascii_legible(p));
                    }
                }
            }
            EXT_VERSIONES => {
                // En TLS 1.3 la version REAL va aqui; el campo clasico dice 1.2
                // por compatibilidad. Tomar el campo clasico daria siempre
                // "TLS1.2" para todo el trafico moderno.
                let mut vl = Lector::nuevo(datos);
                if let Ok(lista) = vl.bloque_u8("tls.versiones.lista") {
                    let mut ll = Lector::nuevo(lista);
                    let mut mejor = 0u16;
                    while !ll.vacio() {
                        let Ok(v) = ll.u16("tls.version-ofrecida") else {
                            break;
                        };
                        if !es_grease(v) && v > mejor {
                            mejor = v;
                        }
                    }
                    if mejor != 0 {
                        s.version_efectiva = mejor;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(s)
}

/// Analiza un saludo del servidor.
///
/// # Errores
/// Truncamiento o longitudes que no cuadran.
pub fn analizar_saludo_servidor(cuerpo: &[u8]) -> Resultado<SaludoServidor> {
    let mut l = Lector::nuevo(cuerpo);
    let mut s = SaludoServidor {
        version_clasica: l.u16("tls.version")?,
        ..Default::default()
    };
    s.version_efectiva = s.version_clasica;
    l.saltar(32, "tls.aleatorio")?;
    let _sesion = l.bloque_u8("tls.sesion")?;
    s.suite = l.u16("tls.suite")?;
    let _compresion = l.u8("tls.compresion")?;

    let Ok(ext) = l.bloque_u16("tls.extensiones") else {
        return Ok(s);
    };
    let mut el = Lector::nuevo(ext);
    while el.restante() >= 4 && s.extensiones.len() < MAX_LISTA {
        let tipo = el.u16("tls.ext.tipo")?;
        let datos = el.bloque_u16("tls.ext.datos")?;
        if es_grease(tipo) {
            continue;
        }
        s.extensiones.push(tipo);
        if tipo == EXT_VERSIONES && datos.len() >= 2 {
            s.version_efectiva = u16::from_be_bytes([datos[0], datos[1]]);
        }
    }
    Ok(s)
}

/// Analiza una cadena de certificados y emite un hecho por cada uno.
#[must_use]
pub fn analizar_certificados(cuerpo: &[u8]) -> Vec<Hecho> {
    let mut l = Lector::nuevo(cuerpo);
    let Ok(cadena) = l.bloque_u24("tls.cadena") else {
        return Vec::new();
    };
    let mut cl = Lector::nuevo(cadena);
    let mut salida = Vec::new();
    while !cl.vacio() && salida.len() < MAX_CERTIFICADOS {
        let Ok(cert) = cl.bloque_u24("tls.certificado") else {
            break;
        };
        salida.push(hecho_de_certificado(cert));
    }
    salida
}

/// Extrae de un certificado lo que un analista va a leer.
///
/// No se implementa el modelo completo de nombres X.500 —es enorme y no cambia
/// ningun veredicto—: se sacan los textos del `tbsCertificate` en orden, que es
/// donde estan el emisor y el sujeto.
fn hecho_de_certificado(der_bytes: &[u8]) -> Hecho {
    let huella: String = Sha256::digest(der_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Estructura: Certificate ::= SEQUENCE { tbsCertificate, ... }
    // tbsCertificate ::= SEQUENCE { [0] version, serial, firma, issuer, validez,
    //                               subject, ... }
    // Los dos primeros bloques de texto son, en ese orden, emisor y sujeto.
    let textos = der::textos(der_bytes, 64);
    // Los algoritmos vienen como OID, no como texto, asi que los textos que
    // salen son ya los nombres. El primer grupo es el emisor y el segundo el
    // sujeto; sin el modelo X.500 completo se separan por posicion, que es lo
    // que da un resultado legible sin pretender exactitud que no se tiene.
    let mitad = textos.len().div_ceil(2);
    let emisor = textos[..mitad.min(textos.len())].join(", ");
    let sujeto = textos[mitad.min(textos.len())..].join(", ");

    Hecho::CertificadoTls {
        autofirmado: !emisor.is_empty() && emisor == sujeto,
        sujeto,
        emisor,
        huella,
    }
}

/// Analiza los registros TLS de un lado de un flujo y emite sus hechos.
///
/// `del_cliente` dice si estos bytes los mando quien abrio la conexion: el mismo
/// byte de handshake significa cosas distintas en cada sentido.
#[must_use]
pub fn analizar(datos: &[u8], del_cliente: bool) -> Vec<Hecho> {
    let mut l = Lector::nuevo(datos);
    let mut hechos = Vec::new();
    let mut registros = 0usize;

    while l.restante() >= 5 && registros < 64 {
        registros += 1;
        let Ok(tipo) = l.u8("tls.registro.tipo") else {
            break;
        };
        let Ok(_version) = l.u16("tls.registro.version") else {
            break;
        };
        let Ok(cuerpo) = l.bloque_u16("tls.registro.cuerpo") else {
            break;
        };
        if tipo != REGISTRO_HANDSHAKE {
            continue;
        }

        let mut hl = Lector::nuevo(cuerpo);
        let mut mensajes = 0usize;
        while hl.restante() >= 4 && mensajes < 16 {
            mensajes += 1;
            let Ok(hs) = hl.u8("tls.hs.tipo") else { break };
            let Ok(mensaje) = hl.bloque_u24("tls.hs.cuerpo") else {
                break;
            };
            match (hs, del_cliente) {
                (HS_CLIENTE, true) => match analizar_saludo_cliente(mensaje) {
                    Ok(s) => {
                        hechos.push(Hecho::ProtocoloIdentificado(ProtocoloApp::Tls));
                        hechos.push(Hecho::SaludoClienteTls {
                            version: nombre_version(s.version_efectiva).to_string(),
                            sni: s.sni.clone(),
                            alpn: s.alpn.clone(),
                            ja3: s.ja3(),
                            ja4: s.ja4(),
                        });
                    }
                    Err(e) => hechos.push(Hecho::no_analizable(ProtocoloApp::Tls, &e)),
                },
                (HS_SERVIDOR, false) => match analizar_saludo_servidor(mensaje) {
                    Ok(s) => {
                        hechos.push(Hecho::ProtocoloIdentificado(ProtocoloApp::Tls));
                        hechos.push(Hecho::SaludoServidorTls {
                            version: nombre_version(s.version_efectiva).to_string(),
                            suite: s.suite,
                            ja3s: s.ja3s(),
                        });
                    }
                    Err(e) => hechos.push(Hecho::no_analizable(ProtocoloApp::Tls, &e)),
                },
                (HS_CERTIFICADO, false) => hechos.extend(analizar_certificados(mensaje)),
                _ => {}
            }
        }
    }
    hechos
}

/// Si unos bytes parecen el inicio de un registro TLS de handshake.
#[must_use]
pub fn parece_tls(datos: &[u8]) -> bool {
    datos.len() >= 3 && datos[0] == REGISTRO_HANDSHAKE && datos[1] == 0x03 && datos[2] <= 0x04
}

/// Error tipico al no encontrar un saludo.
#[must_use]
pub fn sin_saludo() -> ErrorDiseccion {
    ErrorDiseccion::NoEsEsteProtocolo("tls")
}

/// Longitud TOTAL de un registro TLS completo al principio de `datos`.
///
/// Devuelve `None` si no parece un registro o si todavia no llego entero.
///
/// # Para que sirve enmarcar lo que no se puede leer
///
/// Un registro de datos de aplicacion esta cifrado: no hay nada que sacar de el.
/// Pero saber DONDE ACABA si importa, y mucho. Sin eso, el motor guarda cada
/// byte cifrado de cada sesion TLS esperando entenderlo algun dia —y las
/// sesiones TLS son la mayoria del trafico—, asi que la memoria se va en
/// justamente lo unico que nunca va a poder interpretar.
///
/// Fijarse solo en el tipo 22 (handshake), que es lo que mira [`parece_tls`], no
/// vale aqui: precisamente los tipos que NO se pueden leer son los que hay que
/// poder apartar.
#[must_use]
pub fn largo_registro(datos: &[u8]) -> Option<usize> {
    if datos.len() < CABECERA_REGISTRO {
        return None;
    }
    if !(REGISTRO_MINIMO..=REGISTRO_MAXIMO).contains(&datos[0]) {
        return None;
    }
    // La version del registro es siempre 0x03xx, incluso en TLS 1.3, donde el
    // campo miente a proposito por compatibilidad con intermediarios antiguos.
    if datos[1] != 0x03 || datos[2] > 0x04 {
        return None;
    }
    let carga = usize::from(u16::from_be_bytes([datos[3], datos[4]]));
    if carga > MAX_CARGA_REGISTRO {
        return None;
    }
    let total = CABECERA_REGISTRO + carga;
    if datos.len() < total {
        return None;
    }
    Some(total)
}

/// Si un registro es de handshake, que es el unico que se puede disecar.
#[must_use]
pub fn es_handshake(datos: &[u8]) -> bool {
    datos.first() == Some(&REGISTRO_HANDSHAKE)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un ClientHello REAL, byte a byte.
    fn saludo_cliente(suites: &[u16], extensiones: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&0x0303u16.to_be_bytes());
        c.extend_from_slice(&[0x11; 32]);
        c.push(0); // sin sesion
        let mut s = Vec::new();
        for x in suites {
            s.extend_from_slice(&x.to_be_bytes());
        }
        c.extend_from_slice(&(s.len() as u16).to_be_bytes());
        c.extend_from_slice(&s);
        c.extend_from_slice(&[1, 0]); // compresion: null
        let mut e = Vec::new();
        for (t, d) in extensiones {
            e.extend_from_slice(&t.to_be_bytes());
            e.extend_from_slice(&(d.len() as u16).to_be_bytes());
            e.extend_from_slice(d);
        }
        c.extend_from_slice(&(e.len() as u16).to_be_bytes());
        c.extend_from_slice(&e);
        c
    }

    fn envolver(hs: u8, cuerpo: &[u8]) -> Vec<u8> {
        let mut m = vec![hs];
        let l = cuerpo.len();
        m.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        m.extend_from_slice(cuerpo);

        let mut r = vec![REGISTRO_HANDSHAKE, 0x03, 0x01];
        r.extend_from_slice(&(m.len() as u16).to_be_bytes());
        r.extend_from_slice(&m);
        r
    }

    fn ext_sni(nombre: &str) -> (u16, Vec<u8>) {
        let mut d = Vec::new();
        let n = nombre.as_bytes();
        let interior_len = 3 + n.len();
        d.extend_from_slice(&(interior_len as u16).to_be_bytes());
        d.push(0);
        d.extend_from_slice(&(n.len() as u16).to_be_bytes());
        d.extend_from_slice(n);
        (EXT_SNI, d)
    }

    fn ext_alpn(protos: &[&str]) -> (u16, Vec<u8>) {
        let mut lista = Vec::new();
        for p in protos {
            lista.push(p.len() as u8);
            lista.extend_from_slice(p.as_bytes());
        }
        let mut d = (lista.len() as u16).to_be_bytes().to_vec();
        d.extend_from_slice(&lista);
        (EXT_ALPN, d)
    }

    #[test]
    fn un_saludo_de_cliente_se_lee_con_sni_y_alpn() {
        let c = saludo_cliente(
            &[0x1301, 0x1302, 0xC02F],
            &[ext_sni("ejemplo.com"), ext_alpn(&["h2", "http/1.1"])],
        );
        let s = analizar_saludo_cliente(&c).expect("saludo valido");
        assert_eq!(s.sni, "ejemplo.com");
        assert_eq!(s.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(s.suites, vec![0x1301, 0x1302, 0xC02F]);
    }

    /// EL DEFECTO SILENCIOSO: sin filtrar GREASE, la huella de un navegador
    /// moderno cambia en CADA conexion y la tecnica entera deja de servir sin
    /// que nadie se entere. Esta prueba existe para que eso no pueda pasar.
    #[test]
    fn los_valores_grease_no_cambian_la_huella() {
        let limpio = saludo_cliente(&[0x1301, 0x1302], &[ext_sni("a.com")]);
        // El mismo saludo, con GREASE distinto cada vez, como hace Chrome.
        let con_grease_1 = saludo_cliente(
            &[0x0A0A, 0x1301, 0x1302],
            &[(0x1A1A, vec![]), ext_sni("a.com")],
        );
        let con_grease_2 = saludo_cliente(
            &[0x7A7A, 0x1301, 0x1302],
            &[(0xFAFA, vec![]), ext_sni("a.com")],
        );

        let j0 = analizar_saludo_cliente(&limpio).unwrap().ja3();
        let j1 = analizar_saludo_cliente(&con_grease_1).unwrap().ja3();
        let j2 = analizar_saludo_cliente(&con_grease_2).unwrap().ja3();

        assert_eq!(j0, j1, "GREASE no puede cambiar la huella");
        assert_eq!(j1, j2, "ni entre dos conexiones del mismo cliente");
    }

    #[test]
    fn el_detector_de_grease_reconoce_el_patron_y_solo_ese() {
        for g in [0x0A0Au16, 0x1A1A, 0x2A2A, 0x7A7A, 0xAAAA, 0xFAFA] {
            assert!(es_grease(g), "{g:#06x} es GREASE");
        }
        for n in [0x1301u16, 0x1302, 0xC02F, 0x0A0B, 0x0B0A, 0x0000] {
            assert!(!es_grease(n), "{n:#06x} NO es GREASE");
        }
    }

    /// En TLS 1.3 la version real va en `supported_versions`; el campo clasico
    /// dice 1.2 por compatibilidad. Leer el clasico daria "TLS1.2" para TODO el
    /// trafico moderno.
    #[test]
    fn la_version_de_tls_1_3_se_toma_de_la_extension_y_no_del_campo_clasico() {
        let mut d = vec![2u8]; // longitud de la lista
        d.extend_from_slice(&0x0304u16.to_be_bytes());
        let c = saludo_cliente(&[0x1301], &[(EXT_VERSIONES, d)]);
        let s = analizar_saludo_cliente(&c).unwrap();
        assert_eq!(s.version_clasica, 0x0303, "el campo clasico dice 1.2");
        assert_eq!(s.version_efectiva, 0x0304, "pero la real es 1.3");
        assert_eq!(nombre_version(s.version_efectiva), "TLS1.3");
    }

    /// La huella es de la PILA, no del destino: dos conexiones del mismo cliente
    /// a sitios distintos tienen que dar la misma JA3.
    #[test]
    fn la_huella_identifica_al_cliente_y_no_al_destino() {
        let a = saludo_cliente(&[0x1301, 0xC02F], &[ext_sni("banco.com")]);
        let b = saludo_cliente(&[0x1301, 0xC02F], &[ext_sni("malware-c2.example")]);
        let ja = analizar_saludo_cliente(&a).unwrap().ja3();
        let jb = analizar_saludo_cliente(&b).unwrap().ja3();
        assert_eq!(ja, jb, "el destino no cambia la huella de la pila");

        // Pero otra pila (otras suites) SI da otra huella.
        let c = saludo_cliente(&[0x1302, 0x1303], &[ext_sni("banco.com")]);
        assert_ne!(ja, analizar_saludo_cliente(&c).unwrap().ja3());
    }

    #[test]
    fn la_huella_ja4_tiene_la_forma_documentada() {
        let c = saludo_cliente(
            &[0x1301, 0x1302, 0x1303],
            &[ext_sni("ejemplo.com"), ext_alpn(&["h2"])],
        );
        let ja4 = analizar_saludo_cliente(&c).unwrap().ja4();
        let partes: Vec<&str> = ja4.split('_').collect();
        assert_eq!(partes.len(), 3, "JA4 son tres partes: {ja4}");

        // La parte legible tiene posiciones FIJAS, y por eso se comprueban una a
        // una: un desplazamiento de un caracter produce una huella con la forma
        // correcta que no casa con ninguna base publica, y ese fallo no se ve.
        //
        //   t  12  d  03  02  h2
        //   0  1-2 3  4-5 6-7 8-9
        let a = partes[0];
        assert_eq!(a.len(), 10, "parte legible: {a}");
        assert_eq!(&a[0..1], "t", "transporte TCP");
        assert_eq!(
            &a[1..3],
            "12",
            "version, del campo clasico al no haber extension"
        );
        assert_eq!(&a[3..4], "d", "hay SNI");
        assert_eq!(&a[4..6], "03", "tres suites");
        assert_eq!(&a[6..8], "02", "dos extensiones: SNI y ALPN");
        assert_eq!(&a[8..10], "h2", "primera y ultima letra del primer ALPN");

        assert_eq!(partes[1].len(), 12, "resumen de suites");
        assert_eq!(partes[2].len(), 12, "resumen de extensiones y firmas");

        // Sin SNI la marca cambia a 'i'.
        let sin = saludo_cliente(&[0x1301], &[]);
        let ja4_sin = analizar_saludo_cliente(&sin).unwrap().ja4();
        assert!(ja4_sin.split('_').next().unwrap().contains('i'));
    }

    /// El ORDEN de las suites es parte de la huella: dos clientes que ofrecen
    /// las mismas en distinto orden son pilas distintas, y JA3 tiene que
    /// distinguirlos.
    #[test]
    fn el_orden_de_las_suites_cambia_ja3_pero_no_el_resumen_ordenado_de_ja4() {
        let a = saludo_cliente(&[0x1301, 0x1302], &[]);
        let b = saludo_cliente(&[0x1302, 0x1301], &[]);
        let sa = analizar_saludo_cliente(&a).unwrap();
        let sb = analizar_saludo_cliente(&b).unwrap();
        assert_ne!(sa.ja3(), sb.ja3(), "JA3 conserva el orden");
        // JA4 ordena a proposito, para ser estable ante reordenacion.
        assert_eq!(
            sa.ja4().split('_').nth(1),
            sb.ja4().split('_').nth(1),
            "el resumen de suites de JA4 va ordenado"
        );
    }

    #[test]
    fn el_flujo_completo_emite_los_hechos_del_cliente() {
        let c = saludo_cliente(&[0x1301], &[ext_sni("ejemplo.com")]);
        let registro = envolver(HS_CLIENTE, &c);
        let hechos = analizar(&registro, true);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Tls)));
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::SaludoClienteTls { sni, ja3, ja4, .. }
                if sni == "ejemplo.com" && ja3.len() == 32 && ja4.contains('_')
        )));
    }

    /// Un saludo del cliente en el sentido del SERVIDOR no se interpreta: el
    /// mismo byte significa cosas distintas segun quien hable.
    #[test]
    fn el_sentido_importa_y_no_se_confunden_los_saludos() {
        let c = saludo_cliente(&[0x1301], &[]);
        let registro = envolver(HS_CLIENTE, &c);
        assert!(analizar(&registro, false).is_empty());
    }

    #[test]
    fn parece_tls_reconoce_el_registro_y_no_otra_cosa() {
        assert!(parece_tls(&[0x16, 0x03, 0x01]));
        assert!(parece_tls(&[0x16, 0x03, 0x04]));
        assert!(!parece_tls(b"GET /"));
        assert!(!parece_tls(&[0x16, 0x02, 0x01]));
        assert!(!parece_tls(&[0x16]));
    }

    #[test]
    fn una_lista_de_suites_desmesurada_no_hace_crecer_la_memoria() {
        let suites: Vec<u16> = (0..30_000u16).collect();
        let c = saludo_cliente(&suites, &[]);
        let s = analizar_saludo_cliente(&c).unwrap();
        assert!(s.suites.len() <= MAX_LISTA, "suites = {}", s.suites.len());
    }

    #[test]
    fn ningun_saludo_arbitrario_provoca_panico() {
        let mut semilla = 0xCAFE_D00D_1234_5678u64;
        for _ in 0..8000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 400;
            let mut datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            // La mitad con cabecera de registro valida, para llegar mas adentro.
            if largo > 5 && largo % 2 == 0 {
                datos[0] = REGISTRO_HANDSHAKE;
                datos[1] = 0x03;
                datos[2] = 0x01;
            }
            let _ = analizar(&datos, true);
            let _ = analizar(&datos, false);
            let _ = analizar_saludo_cliente(&datos);
            let _ = analizar_saludo_servidor(&datos);
            let _ = analizar_certificados(&datos);
        }
    }
}
