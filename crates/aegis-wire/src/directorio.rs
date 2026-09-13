//! Kerberos y LDAP: los dos protocolos del directorio, los dos sobre ASN.1.
//!
//! # Por que van juntos
//!
//! Son las dos caras del mismo servicio —autenticacion y consulta del
//! directorio—, viajan a los mismos servidores y comparten el mismo lector DER
//! acotado ([`crate::der`]). Un atacante que se mueve por identidad los usa los
//! dos en la misma secuencia: consulta LDAP para encontrar cuentas de servicio,
//! y pide tickets Kerberos para ellas.
//!
//! # La senal que justifica el modulo: el cifrado degradado
//!
//! **Kerberoasting** funciona asi: el atacante pide un ticket de servicio para
//! una cuenta de servicio y lo descifra sin conexion, a fuerza bruta, para sacar
//! su contrasena. Un ticket cifrado con AES es inviable de romper; uno con
//! **RC4-HMAC** (tipo 23) es mucho mas barato.
//!
//! Por eso la peticion pide RC4 explicitamente cuando puede, aunque el dominio
//! soporte AES. Ese **degradado** es la senal, y se ve en claro en la peticion:
//! no hace falta descifrar nada.
//!
//! Aqui se observa y se reporta con su tipo de cifrado. Quien decide si es
//! Kerberoasting es el motor ITDR de la FASE 58, que ve la secuencia entera de
//! peticiones de una cuenta; el disector solo aporta el hecho.
//!
//! # Kerberos sobre TCP lleva longitud por delante
//!
//! Cuatro bytes en orden de red antes del DER. Quien no los quite intenta leer
//! ASN.1 desde una longitud y no reconoce nada. Sobre UDP no los lleva, asi que
//! hay que admitir las dos formas.

use crate::der::{self, Clase};
use crate::hecho::{Hecho, ProtocoloApp};

/// Etiquetas de aplicacion de los mensajes Kerberos que importan.
pub mod mensaje {
    /// Peticion de ticket inicial.
    pub const AS_REQ: u32 = 10;
    /// Respuesta a la peticion inicial.
    pub const AS_REP: u32 = 11;
    /// Peticion de ticket de servicio.
    pub const TGS_REQ: u32 = 12;
    /// Respuesta con ticket de servicio.
    pub const TGS_REP: u32 = 13;
    /// Presentacion de un ticket.
    pub const AP_REQ: u32 = 14;
    /// Error.
    pub const ERROR: u32 = 30;
}

/// Nombre de un tipo de cifrado de Kerberos.
///
/// Los nombres son los del registro de IANA. El que importa es el 23.
#[must_use]
pub fn nombre_cifrado(t: i64) -> &'static str {
    match t {
        1 => "DES-CBC-CRC",
        3 => "DES-CBC-MD5",
        17 => "AES128-CTS-HMAC-SHA1",
        18 => "AES256-CTS-HMAC-SHA1",
        19 => "AES128-CTS-HMAC-SHA256",
        20 => "AES256-CTS-HMAC-SHA384",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        _ => "otro",
    }
}

/// Si un tipo de cifrado es debil para resistir fuerza bruta sin conexion.
///
/// RC4 y DES lo son; AES no. Es la condicion que hace viable el Kerberoasting.
#[must_use]
pub fn cifrado_debil(t: i64) -> bool {
    matches!(t, 1 | 3 | 23 | 24)
}

/// Nombre de un tipo de mensaje.
#[must_use]
pub fn nombre_mensaje(e: u32) -> &'static str {
    match e {
        mensaje::AS_REQ => "AS-REQ",
        mensaje::AS_REP => "AS-REP",
        mensaje::TGS_REQ => "TGS-REQ",
        mensaje::TGS_REP => "TGS-REP",
        mensaje::AP_REQ => "AP-REQ",
        mensaje::ERROR => "KRB-ERROR",
        _ => "otro",
    }
}

/// El hijo con una etiqueta de contexto concreta (`[0]`, `[1]`, ...).
///
/// Es la pieza que permite navegar ASN.1 **por posicion declarada** en vez de
/// por parecido. La diferencia importa: buscar por parecido confunde campos
/// distintos que casualmente tienen la misma forma, y en un protocolo de
/// identidad eso significa delatar ataques que no existen.
#[must_use]
pub fn contexto(datos: &[u8], etiqueta: u32) -> Option<der::Elemento<'_>> {
    der::hijos(datos)
        .ok()?
        .into_iter()
        .find(|e| e.clase == Clase::Contexto && e.etiqueta == etiqueta)
}

/// Une los textos ASN.1 que haya dentro de un elemento.
fn textos_unidos(datos: &[u8], separador: &str) -> String {
    der::textos(datos, 8).join(separador)
}

/// El primer `OCTET STRING` que haya entre los hijos, como texto.
///
/// LDAP codifica sus nombres distinguidos como `LDAPString ::= OCTET STRING`, no
/// como una de las cadenas con tipo de ASN.1. Un extractor generico de textos no
/// los ve, y el disector se quedaria sin el dato que mas interesa: quien se
/// autentica y sobre que rama busca.
#[must_use]
pub fn cadena_octetos(datos: &[u8], indice: usize) -> String {
    der::hijos(datos)
        .ok()
        .and_then(|h| {
            h.into_iter()
                .filter(|e| {
                    e.clase == Clase::Universal && e.etiqueta == der::etiqueta::CADENA_OCTETOS
                })
                .nth(indice)
        })
        .map(|e| crate::lector::ascii_legible(e.contenido))
        .unwrap_or_default()
}

/// Quita la longitud de cuatro bytes que Kerberos lleva sobre TCP.
///
/// Sobre UDP no la lleva, asi que hay que admitir las dos formas: quien asuma
/// una sola deja de ver la mitad del trafico Kerberos de la red.
#[must_use]
pub fn quitar_longitud_tcp(datos: &[u8]) -> &[u8] {
    if datos.len() < 5 {
        return datos;
    }
    // El DER de un mensaje Kerberos empieza siempre con una etiqueta de
    // aplicacion construida: 0x6A (AS-REQ), 0x6C (TGS-REQ), etc.
    if datos[0] & 0xE0 == 0x60 {
        return datos;
    }
    let declarada = u32::from_be_bytes([datos[0], datos[1], datos[2], datos[3]]) as usize;
    if declarada > 0 && declarada <= datos.len() - 4 && datos[4] & 0xE0 == 0x60 {
        &datos[4..4 + declarada]
    } else {
        datos
    }
}

/// Analiza un mensaje Kerberos.
#[must_use]
pub fn analizar_kerberos(datos: &[u8]) -> Vec<Hecho> {
    let cuerpo = quitar_longitud_tcp(datos);
    let Ok(raiz) = der::leer(cuerpo) else {
        return Vec::new();
    };
    if raiz.clase != Clase::Aplicacion || !raiz.construido {
        return Vec::new();
    }
    let tipo = nombre_mensaje(raiz.etiqueta);
    if tipo == "otro" {
        return Vec::new();
    }

    // NAVEGACION EXPLICITA POR ETIQUETA DE CONTEXTO, no busqueda ciega.
    //
    // La tentacion es buscar «el primer entero pequeno que parezca un tipo de
    // cifrado» por todo el mensaje. No vale, y el motivo es concreto: un
    // `PrincipalName` lleva un campo `name-type` cuyo valor habitual es 1 o 2, y
    // el tipo de cifrado 1 es DES-CBC-CRC. Una busqueda ciega confunde el tipo
    // de nombre de un principal con un cifrado debil y delata Kerberoasting en
    // CADA peticion del dominio. El ruido enterraria la senal de verdad.
    //
    // KDC-REQ ::= SEQUENCE { [1] pvno, [2] msg-type, [3] padata, [4] req-body }
    // KDC-REQ-BODY ::= SEQUENCE { [0] opciones, [1] cname, [2] realm,
    //                             [3] sname, ..., [8] etype }
    let cuerpo_req = der::hijos(raiz.contenido)
        .ok()
        .and_then(|h| h.into_iter().next())
        .and_then(|seq| contexto(seq.contenido, 4))
        .or_else(|| contexto(raiz.contenido, 4));

    let campos = cuerpo_req.as_ref().map_or(raiz.contenido, |e| e.contenido);
    // El cuerpo viene envuelto en una SEQUENCE dentro del [4].
    let campos = der::hijos(campos)
        .ok()
        .and_then(|h| {
            h.into_iter()
                .find(|e| e.etiqueta == der::etiqueta::SECUENCIA)
        })
        .map_or(campos, |s| s.contenido);

    let cliente = contexto(campos, 1)
        .map(|e| textos_unidos(e.contenido, "/"))
        .unwrap_or_default();
    let realm = contexto(campos, 2)
        .map(|e| textos_unidos(e.contenido, ""))
        .unwrap_or_default();
    let servicio = contexto(campos, 3)
        .map(|e| textos_unidos(e.contenido, "/"))
        .unwrap_or_default();
    let servicio = if realm.is_empty() || servicio.is_empty() {
        servicio
    } else {
        format!("{servicio}@{realm}")
    };

    // El tipo de cifrado esta en [8], y SOLO ahi.
    let mut cifrado = String::new();
    let mut debil = false;
    if let Some(etype) = contexto(campos, 8) {
        let mut tipos: Vec<i64> = Vec::new();
        if let Ok(lista) = der::hijos(etype.contenido) {
            for e in lista {
                let dentro = if e.etiqueta == der::etiqueta::SECUENCIA {
                    der::hijos(e.contenido).unwrap_or_default()
                } else {
                    vec![e]
                };
                for i in dentro {
                    if i.etiqueta == der::etiqueta::ENTERO && i.clase == Clase::Universal {
                        if let Some(&b) = i.contenido.first() {
                            tipos.push(i64::from(b));
                        }
                    }
                }
            }
        }
        // Si se ofrece CUALQUIER cifrado rompible, esa es la senal: al atacante
        // le basta con que la KDC acepte el debil.
        if let Some(&t) = tipos.iter().find(|t| cifrado_debil(**t)) {
            cifrado = nombre_cifrado(t).to_string();
            debil = true;
        } else if let Some(&t) = tipos.first() {
            cifrado = nombre_cifrado(t).to_string();
        }
    }

    let mut hechos = vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Kerberos),
        Hecho::MensajeKerberos {
            tipo: tipo.to_string(),
            cliente,
            servicio,
            cifrado: cifrado.clone(),
        },
    ];

    // EL DEGRADADO. Se anota como anomalia aparte para que el motor ITDR de la
    // FASE 58 pueda contarlo por cuenta: una peticion suelta con RC4 puede ser
    // un sistema antiguo; cincuenta en un minuto es Kerberoasting.
    if debil {
        hechos.push(Hecho::AnomaliaDeFlujo {
            codigo: "kerberos-cifrado-debil",
            detalle: format!(
                "peticion con cifrado {cifrado}: un ticket asi se puede romper sin \
                 conexion, que es la condicion del Kerberoasting"
            ),
        });
    }
    hechos
}

/// Si unos bytes parecen Kerberos.
#[must_use]
pub fn parece_kerberos(datos: &[u8]) -> bool {
    let c = quitar_longitud_tcp(datos);
    c.first().is_some_and(|b| b & 0xE0 == 0x60)
        && der::leer(c)
            .is_ok_and(|e| e.clase == Clase::Aplicacion && nombre_mensaje(e.etiqueta) != "otro")
}

// ---------------------------------------------------------------------------
// LDAP
// ---------------------------------------------------------------------------

/// Operaciones LDAP, por su etiqueta de aplicacion.
#[must_use]
pub fn nombre_operacion_ldap(e: u32) -> &'static str {
    match e {
        0 => "bind",
        1 => "bindResponse",
        2 => "unbind",
        3 => "search",
        4 => "searchEntry",
        5 => "searchDone",
        6 => "modify",
        8 => "add",
        10 => "delete",
        12 => "modifyDN",
        14 => "compare",
        23 => "extended",
        _ => "otra",
    }
}

/// Analiza un mensaje LDAP.
#[must_use]
pub fn analizar_ldap(datos: &[u8]) -> Vec<Hecho> {
    let Ok(raiz) = der::leer(datos) else {
        return Vec::new();
    };
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE {...} }
    if raiz.clase != Clase::Universal || raiz.etiqueta != der::etiqueta::SECUENCIA {
        return Vec::new();
    }
    let Ok(hijos) = der::hijos(raiz.contenido) else {
        return Vec::new();
    };
    // El primero tiene que ser el identificador de mensaje.
    if hijos.first().map(|e| e.etiqueta) != Some(der::etiqueta::ENTERO) {
        return Vec::new();
    }
    let Some(op) = hijos.get(1) else {
        return Vec::new();
    };
    if op.clase != Clase::Aplicacion {
        return Vec::new();
    }
    let operacion = nombre_operacion_ldap(op.etiqueta);
    if operacion == "otra" {
        return Vec::new();
    }

    // El nombre distinguido se lee de SU POSICION en cada operacion, no
    // buscandolo. Y es un `OCTET STRING`, no una cadena con tipo de ASN.1: un
    // extractor generico de textos no lo ve.
    //
    //   bindRequest   ::= SEQUENCE { version INTEGER, name LDAPDN, auth CHOICE }
    //   searchRequest ::= SEQUENCE { baseObject LDAPDN, scope, ... }
    //
    // En las dos, el nombre es el PRIMER octet string del cuerpo: en el bind la
    // version va delante pero es un entero, no una cadena, asi que el indice
    // cero acierta en ambos casos sin necesidad de distinguirlos.
    let dn = cadena_octetos(op.contenido, 0);

    let mut hechos = vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Ldap),
        Hecho::OperacionLdap {
            operacion: operacion.to_string(),
            dn: dn.clone(),
        },
    ];

    // Un bind SIN cifrar lleva la contrasena en claro por la red. Se delata el
    // hecho, y la contrasena NO se registra: un EDR que la copie en su propia
    // telemetria crea la brecha que dice prevenir.
    if operacion == "bind" && !dn.is_empty() {
        hechos.push(Hecho::AnomaliaDeFlujo {
            codigo: "ldap-bind-sin-cifrar",
            detalle: format!(
                "autenticacion LDAP en claro para '{dn}': las credenciales viajan sin \
                 cifrar por la red"
            ),
        });
    }
    hechos
}

/// Si unos bytes parecen LDAP.
#[must_use]
pub fn parece_ldap(datos: &[u8]) -> bool {
    der::leer(datos).is_ok_and(|e| {
        e.etiqueta == der::etiqueta::SECUENCIA
            && e.clase == Clase::Universal
            && der::hijos(e.contenido).is_ok_and(|h| {
                h.first().map(|x| x.etiqueta) == Some(der::etiqueta::ENTERO)
                    && h.get(1).is_some_and(|x| x.clase == Clase::Aplicacion)
            })
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un elemento DER.
    fn der_e(etiqueta: u8, contenido: &[u8]) -> Vec<u8> {
        let mut v = vec![etiqueta];
        if contenido.len() < 0x80 {
            v.push(contenido.len() as u8);
        } else {
            let b = (contenido.len() as u16).to_be_bytes();
            v.push(0x82);
            v.extend_from_slice(&b);
        }
        v.extend_from_slice(contenido);
        v
    }

    /// Un PrincipalName con sus cadenas.
    fn principal(partes: &[&str]) -> Vec<u8> {
        let cadenas: Vec<u8> = partes
            .iter()
            .flat_map(|p| der_e(0x1B, p.as_bytes()))
            .collect();
        let seq = der_e(0x30, &cadenas);
        let ctx1 = der_e(0xA1, &seq);
        let tipo = der_e(0xA0, &der_e(0x02, &[1]));
        der_e(0x30, &[tipo, ctx1].concat())
    }

    /// Un TGS-REQ con el tipo de cifrado indicado.
    fn tgs_req(cliente: &str, servicio: &str, etype: u8) -> Vec<u8> {
        let cuerpo = [
            principal(&[cliente]),
            principal(&[servicio]),
            // etype: SEQUENCE OF INTEGER
            der_e(0xA8, &der_e(0x30, &der_e(0x02, &[etype]))),
        ]
        .concat();
        let seq = der_e(0x30, &cuerpo);
        der_e(0x6C, &seq) // [APPLICATION 12]
    }

    /// LA SENAL DEL KERBEROASTING: la peticion pide RC4 aunque el dominio
    /// soporte AES, porque un ticket RC4 se rompe sin conexion.
    #[test]
    fn una_peticion_con_rc4_se_delata_como_cifrado_debil() {
        let m = tgs_req("alice", "MSSQLSvc", 23);
        let hechos = analizar_kerberos(&m);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Kerberos)));
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::MensajeKerberos { .. }))
        {
            Some(Hecho::MensajeKerberos { tipo, cifrado, .. }) => {
                assert_eq!(tipo, "TGS-REQ");
                assert_eq!(cifrado, "RC4-HMAC");
            }
            otro => panic!("se esperaba un mensaje: {otro:?}"),
        }
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "kerberos-cifrado-debil"
            )),
            "el degradado ES la senal: {hechos:?}"
        );
    }

    /// Y con AES NO se delata: si lo hiciera, todo el trafico Kerberos legitimo
    /// del dominio saltaria y la senal quedaria enterrada.
    #[test]
    fn una_peticion_con_aes_no_se_delata() {
        let m = tgs_req("alice", "HTTP", 18);
        let hechos = analizar_kerberos(&m);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::MensajeKerberos { cifrado, .. } if cifrado == "AES256-CTS-HMAC-SHA1"
        )));
        assert!(
            !hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "kerberos-cifrado-debil"
            )),
            "AES no puede disparar la senal, o se enterraria la de verdad"
        );
    }

    #[test]
    fn la_clasificacion_de_cifrados_distingue_lo_rompible_de_lo_que_no() {
        for debil in [1, 3, 23, 24] {
            assert!(cifrado_debil(debil), "{debil} es rompible sin conexion");
        }
        for fuerte in [17, 18, 19, 20] {
            assert!(!cifrado_debil(fuerte), "{fuerte} no lo es");
        }
        assert_eq!(nombre_cifrado(23), "RC4-HMAC");
        assert_eq!(nombre_cifrado(18), "AES256-CTS-HMAC-SHA1");
    }

    /// KERBEROS SOBRE TCP lleva longitud por delante; sobre UDP no. Quien asuma
    /// una sola forma deja de ver la mitad del trafico Kerberos de la red.
    #[test]
    fn kerberos_se_reconoce_con_y_sin_la_longitud_de_tcp() {
        let sin = tgs_req("bob", "CIFS", 23);
        let mut con = (sin.len() as u32).to_be_bytes().to_vec();
        con.extend_from_slice(&sin);

        assert!(!analizar_kerberos(&sin).is_empty(), "forma UDP");
        assert!(!analizar_kerberos(&con).is_empty(), "forma TCP");
        assert_eq!(quitar_longitud_tcp(&con), &sin[..]);
        assert_eq!(quitar_longitud_tcp(&sin), &sin[..]);
    }

    #[test]
    fn los_tipos_de_mensaje_se_nombran_bien() {
        assert_eq!(nombre_mensaje(mensaje::AS_REQ), "AS-REQ");
        assert_eq!(nombre_mensaje(mensaje::TGS_REP), "TGS-REP");
        assert_eq!(nombre_mensaje(99), "otro");
    }

    /// Un bind LDAP sin cifrar lleva la contrasena en claro. Se delata el hecho,
    /// y la contrasena NO se copia a la telemetria.
    #[test]
    fn un_bind_ldap_en_claro_se_delata_sin_copiar_la_contrasena() {
        let dn = "cn=admin,dc=empresa,dc=local";
        let clave = "ContrasenaSuperSecreta";
        let cuerpo = [
            der_e(0x02, &[3]),             // version
            der_e(0x04, dn.as_bytes()),    // nombre
            der_e(0x80, clave.as_bytes()), // contrasena simple
        ]
        .concat();
        let op = der_e(0x60, &cuerpo); // [APPLICATION 0] bindRequest
        let m = der_e(0x30, &[der_e(0x02, &[1]), op].concat());

        let hechos = analizar_ldap(&m);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Ldap)));
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::OperacionLdap { operacion, dn: d } if operacion == "bind" && d == dn
        )));
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "ldap-bind-sin-cifrar"
        )));

        let todo = format!("{hechos:?}");
        assert!(
            !todo.contains(clave),
            "la contrasena se ha colado en la telemetria: {todo}"
        );
    }

    #[test]
    fn una_busqueda_ldap_se_lee_con_su_base() {
        let base = "dc=empresa,dc=local";
        let cuerpo = der_e(0x04, base.as_bytes());
        let op = der_e(0x63, &cuerpo); // [APPLICATION 3] searchRequest
        let m = der_e(0x30, &[der_e(0x02, &[2]), op].concat());

        let hechos = analizar_ldap(&m);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::OperacionLdap { operacion, dn } if operacion == "search" && dn == base
        )));
    }

    #[test]
    fn lo_que_no_es_del_directorio_no_produce_hechos_del_directorio() {
        assert!(analizar_kerberos(b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(analizar_ldap(b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(analizar_kerberos(&[0u8; 50]).is_empty());
        assert!(!parece_kerberos(b"cualquier cosa"));
        assert!(!parece_ldap(b"cualquier cosa"));
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let mut semilla = 0x4B52_4235_4C44_4150u64;
        for _ in 0..10_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 300;
            let mut datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            // La mitad con una etiqueta de aplicacion valida.
            if !datos.is_empty() && largo % 2 == 0 {
                datos[0] = 0x6C;
            }
            let _ = analizar_kerberos(&datos);
            let _ = analizar_ldap(&datos);
        }
    }
}
