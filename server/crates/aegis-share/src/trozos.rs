//! Trocea un paquete STIX en objetos sin analizarlo entero.
//!
//! Es un analizador LEXICO, no sintactico: sigue comillas, escapes y
//! corchetes, y con eso sabe donde empieza y acaba cada valor. No construye
//! nada ni interpreta numeros: cada trozo lo analiza despues `serde_json` por
//! separado, con los topes de un objeto. Lo que este modulo garantiza es que un
//! documento malformado se rechaza —comillas sin cerrar, corchetes que no
//! casan, basura detras— y que ningun trozo pasa de su tope.

use std::ops::Range;

use crate::stix::Rechazo;

/// Los trozos de un paquete.
#[derive(Debug, Default)]
pub(crate) struct Trozos {
    /// El `id` del paquete, si lo trae.
    pub id: Option<String>,
    /// Donde esta cada objeto de `objects`.
    pub objetos: Vec<Range<usize>>,
}

fn malformado(detalle: impl Into<String>) -> Rechazo {
    Rechazo::NoEsJson {
        detalle: detalle.into(),
    }
}

fn blancos(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// Fin (exclusivo) de la cadena que empieza en `b[i] == '"'`.
fn fin_de_cadena(b: &[u8], i: usize) -> Result<usize, Rechazo> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Ok(j + 1),
            _ => j += 1,
        }
    }
    Err(malformado("una cadena sin cerrar"))
}

/// Fin (exclusivo) del valor que empieza en `b[i]`.
fn fin_de_valor(b: &[u8], i: usize) -> Result<usize, Rechazo> {
    match b.get(i) {
        Some(b'"') => fin_de_cadena(b, i),
        Some(b'{' | b'[') => {
            // Una pila de cierres esperados: `{]` no casa aunque la profundidad
            // cuadre.
            let mut pila: Vec<u8> = Vec::new();
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = fin_de_cadena(b, j)?;
                        continue;
                    }
                    b'{' => pila.push(b'}'),
                    b'[' => pila.push(b']'),
                    c @ (b'}' | b']') => {
                        if pila.pop() != Some(c) {
                            return Err(malformado("llaves o corchetes que no casan"));
                        }
                        if pila.is_empty() {
                            return Ok(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            Err(malformado("un objeto o una lista sin cerrar"))
        }
        Some(_) => {
            // Un literal: numero, true, false o null. Acaba en un separador.
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            if j == i {
                return Err(malformado("se esperaba un valor"));
            }
            Ok(j)
        }
        None => Err(malformado(
            "el documento se acaba donde se esperaba un valor",
        )),
    }
}

/// Trocea `texto`: un paquete `{"type":"bundle","id":…,"objects":[…]}`.
pub(crate) fn trocear(
    texto: &str,
    max_objeto: usize,
    max_objetos: usize,
) -> Result<Trozos, Rechazo> {
    let b = texto.as_bytes();
    let mut i = blancos(b, 0);
    if b.get(i) != Some(&b'{') {
        return Err(malformado("la raiz no es un objeto"));
    }
    i += 1;
    let mut t = Trozos::default();
    let mut con_objetos = false;
    loop {
        i = blancos(b, i);
        match b.get(i) {
            Some(b'}') => {
                i += 1;
                break;
            }
            Some(b'"') => {}
            _ => return Err(malformado("se esperaba una clave en la raiz")),
        }
        let fin_clave = fin_de_cadena(b, i)?;
        let clave = &texto[i + 1..fin_clave - 1];
        i = blancos(b, fin_clave);
        if b.get(i) != Some(&b':') {
            return Err(malformado("se esperaban dos puntos tras una clave"));
        }
        i = blancos(b, i + 1);
        let fin = fin_de_valor(b, i)?;
        match clave {
            "objects" => {
                if b.get(i) != Some(&b'[') {
                    return Err(malformado("«objects» no es una lista"));
                }
                con_objetos = true;
                let mut j = blancos(b, i + 1);
                if b.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < fin {
                    let f = fin_de_valor(b, j)?;
                    if f - j > max_objeto {
                        return Err(Rechazo::Desmesurado {
                            que: "bytes de un objeto",
                            visto: f - j,
                            tope: max_objeto,
                        });
                    }
                    t.objetos.push(j..f);
                    if t.objetos.len() > max_objetos {
                        return Err(Rechazo::Desmesurado {
                            que: "objetos del recorrido",
                            visto: t.objetos.len(),
                            tope: max_objetos,
                        });
                    }
                    j = blancos(b, f);
                    match b.get(j) {
                        Some(b',') => j = blancos(b, j + 1),
                        Some(b']') => j += 1,
                        _ => {
                            return Err(malformado("se esperaba una coma o el cierre de «objects»"))
                        }
                    }
                }
            }
            "id" => {
                if let Ok(serde_json::Value::String(s)) = serde_json::from_str(&texto[i..fin]) {
                    t.id = Some(s);
                }
            }
            _ => {}
        }
        i = blancos(b, fin);
        match b.get(i) {
            Some(b',') => i += 1,
            Some(b'}') => {
                i += 1;
                break;
            }
            _ => return Err(malformado("se esperaba una coma o el cierre de la raiz")),
        }
    }
    if blancos(b, i) != b.len() {
        return Err(malformado("basura detras del paquete"));
    }
    if !con_objetos {
        return Err(malformado("el paquete no trae «objects»"));
    }
    Ok(t)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn cuantos(s: &str) -> Result<usize, Rechazo> {
        trocear(s, 1024, 100).map(|t| t.objetos.len())
    }

    #[test]
    fn trocea_respetando_cadenas_y_escapes() {
        let s = r#"{"type":"bundle","objects":[{"a":"} ] { [ \" x"},{"b":[1,{"c":"]"}]}],"id":"bundle--1"}"#;
        let t = trocear(s, 1024, 100).unwrap();
        assert_eq!(t.objetos.len(), 2);
        assert_eq!(&s[t.objetos[0].clone()], r#"{"a":"} ] { [ \" x"}"#);
        assert_eq!(t.id.as_deref(), Some("bundle--1"));
        assert_eq!(cuantos(r#"{"objects":[]}"#).unwrap(), 0);
    }

    #[test]
    fn rechaza_lo_malformado_y_lo_desmesurado() {
        for malo in [
            r#"{"objects":[{"a":1}"#,
            r#"{"objects":[{"a":"sin cerrar}]}"#,
            r#"{"objects":[{"a":1]]}"#,
            r#"{"objects":[{"a":1}] } basura"#,
            r#"{"objects":{"a":1}}"#,
            r#"{"type":"bundle"}"#,
            r#"["objects"]"#,
            r#"{"objects":[{"a":1} {"b":2}]}"#,
        ] {
            assert!(cuantos(malo).is_err(), "deberia rechazar {malo}");
        }
        let grande = format!(r#"{{"objects":[{{"a":"{}"}}]}}"#, "x".repeat(2000));
        assert!(matches!(cuantos(&grande), Err(Rechazo::Desmesurado { .. })));
        let muchos = format!(r#"{{"objects":[{}]}}"#, vec!["{}"; 101].join(","));
        assert!(matches!(cuantos(&muchos), Err(Rechazo::Desmesurado { .. })));
    }
}
