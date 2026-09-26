//! Lectura de documentos de politica de AWS: ¿concede todo?, ¿es publica?
//!
//! # Que se lee y que no, dicho antes de leer
//!
//! El evaluador de politicas de IAM es un lenguaje entero: comodines en medio
//! de una accion, `NotAction`, `NotResource`, condiciones con veinte operadores,
//! limites de permisos, SCP. Reimplementarlo aqui seria reimplementarlo mal. Lo
//! que se contesta son dos preguntas estrechas cuya respuesta no depende de
//! nada de eso:
//!
//! - **¿Concede todo?** Una declaracion `Allow` con `Action` `*` (o `*:*`) sobre
//!   `Resource` `*`. Es la forma exacta de `AdministratorAccess` y la que busca
//!   cualquier auditor. `NotAction` con `Allow` es casi lo mismo y NO se cuenta:
//!   se declara en la tabla de honestidad en vez de fingir que se evalua.
//! - **¿Es publica?** Una declaracion `Allow` con `Principal` `*` (o
//!   `{"AWS":"*"}`) y **sin** `Condition`. Con condicion (`aws:SourceIp`,
//!   `aws:PrincipalOrgID`...) puede estar acotada y afirmar que es publica seria
//!   un falso positivo. Se cuenta como no publica y el extracto lo dice.
//!
//! Todo con tope: el documento pasa antes por
//! [`MAX_CUERPO`](crate::entrada::MAX_CUERPO), y las listas se recorren hasta
//! [`MAX_ELEMENTOS`](crate::entrada::MAX_ELEMENTOS). Si alguna lista es mas
//! larga y no se encontro nada en lo recorrido, la respuesta es
//! [`Lectura::Ilegible`], no [`Lectura::No`]: lo que no se vio no se afirma.

use serde_json::Value;

use crate::entrada::{ci, json_anidado, lista_con_tope, texto};

/// Lo que se pudo leer de un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lectura {
    /// La pregunta se contesta que si, con la declaracion que lo hace.
    Si(String),
    /// La pregunta se contesta que no. Lleva una nota si la hay (p.ej.
    /// «principal * con condicion»).
    No(Option<String>),
    /// El documento no se pudo leer entero, y por que.
    Ilegible(String),
}

/// ¿Concede este documento todas las acciones sobre todos los recursos?
#[must_use]
pub fn concede_todo(doc: &Value) -> Lectura {
    let doc = match json_anidado(doc) {
        Ok(d) => d,
        Err(e) => return Lectura::Ilegible(e),
    };
    let Some(decl) = ci(&doc, "Statement") else {
        return Lectura::Ilegible("el documento no tiene Statement".into());
    };
    let (declaraciones, mut cortada) = lista_con_tope(decl);
    for (i, d) in declaraciones.into_iter().enumerate() {
        if !permite(d) {
            continue;
        }
        let (accion_total, c1) = contiene(ci(d, "Action"), |a| a == "*" || a == "*:*");
        let (recurso_total, c2) = contiene(ci(d, "Resource"), |r| r == "*");
        cortada |= c1 || c2;
        if accion_total && recurso_total {
            return Lectura::Si(format!(
                "declaracion {} ({}) concede Action * sobre Resource *",
                i + 1,
                sid(d)
            ));
        }
    }
    if cortada {
        return Lectura::Ilegible(listas_cortadas());
    }
    Lectura::No(None)
}

/// ¿Permite este documento el acceso a cualquiera?
#[must_use]
pub fn es_publica(doc: &Value) -> Lectura {
    let doc = match json_anidado(doc) {
        Ok(d) => d,
        Err(e) => return Lectura::Ilegible(e),
    };
    let Some(decl) = ci(&doc, "Statement") else {
        return Lectura::Ilegible("el documento no tiene Statement".into());
    };
    let mut nota = None;
    let (declaraciones, mut cortada) = lista_con_tope(decl);
    for (i, d) in declaraciones.into_iter().enumerate() {
        if !permite(d) {
            continue;
        }
        let (publico, c) = principal_publico(d);
        cortada |= c;
        if !publico {
            continue;
        }
        let condicionada = ci(d, "Condition")
            .is_some_and(|c| !c.is_null() && c.as_object().is_none_or(|m| !m.is_empty()));
        if condicionada {
            nota = Some(format!(
                "declaracion {} ({}) tiene Principal * pero con Condition: no se afirma que \
                 sea publica",
                i + 1,
                sid(d)
            ));
            continue;
        }
        return Lectura::Si(format!(
            "declaracion {} ({}) permite a Principal * sin condicion",
            i + 1,
            sid(d)
        ));
    }
    if cortada {
        return Lectura::Ilegible(listas_cortadas());
    }
    Lectura::No(nota)
}

fn permite(d: &Value) -> bool {
    ci(d, "Effect")
        .and_then(texto)
        .is_some_and(|e| e.eq_ignore_ascii_case("allow"))
}

fn principal_publico(d: &Value) -> (bool, bool) {
    let Some(p) = ci(d, "Principal") else {
        return (false, false);
    };
    match p {
        Value::String(s) => (s == "*", false),
        Value::Object(_) => contiene(ci(p, "AWS"), |x| x == "*"),
        _ => (false, false),
    }
}

/// Si alguno de los valores (escalar o lista) cumple `pred`, y si la lista se
/// corto antes de verla entera.
fn contiene(v: Option<&Value>, pred: impl Fn(&str) -> bool) -> (bool, bool) {
    let Some(v) = v else {
        return (false, false);
    };
    let (l, cortada) = lista_con_tope(v);
    (l.into_iter().filter_map(texto).any(|x| pred(&x)), cortada)
}

fn listas_cortadas() -> String {
    format!(
        "el documento tiene listas de mas de {} elementos y no se recorrio entero: no se \
         afirma nada de lo que no se vio",
        crate::entrada::MAX_ELEMENTOS
    )
}

fn sid(d: &Value) -> String {
    ci(d, "Sid").and_then(texto).map_or_else(
        || "sin Sid".into(),
        |s| aegis_ingest::esquema::recortar(&s, 64),
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use serde_json::json;

    #[test]
    fn administrator_access_en_linea_concede_todo() {
        let d = json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"*","Resource":"*"}]});
        assert!(matches!(concede_todo(&d), Lectura::Si(_)));
    }

    #[test]
    fn el_documento_como_texto_y_como_url_tambien() {
        let plano = Value::String(
            r#"{"Statement":{"Effect":"Allow","Action":["s3:*","*"],"Resource":["*"]}}"#.into(),
        );
        assert!(matches!(concede_todo(&plano), Lectura::Si(_)));
        let url = Value::String(
            "%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%7D"
                .into(),
        );
        assert!(matches!(concede_todo(&url), Lectura::Si(_)));
    }

    #[test]
    fn una_politica_acotada_no_concede_todo() {
        let d = json!({"Statement":[
            {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
            {"Effect":"Deny","Action":"*","Resource":"*"}]});
        assert_eq!(concede_todo(&d), Lectura::No(None));
    }

    #[test]
    fn principal_asterisco_sin_condicion_es_publica_y_con_condicion_no_se_afirma() {
        let publica = json!({"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]});
        assert!(matches!(es_publica(&publica), Lectura::Si(_)));
        let condicionada = json!({"Statement":[{"Effect":"Allow","Principal":"*",
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*",
            "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]});
        match es_publica(&condicionada) {
            Lectura::No(Some(n)) => assert!(n.contains("Condition")),
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn un_documento_ilegible_se_dice_ilegible_y_no_no() {
        // «No se pudo leer» no es «no concede»: lo segundo pintaria de verde
        // una politica que no se miro.
        let roto = Value::String("{no es json".into());
        assert!(matches!(concede_todo(&roto), Lectura::Ilegible(_)));
        let gordo = Value::String(format!(
            r#"{{"Statement":[],"x":"{}"}}"#,
            "a".repeat(1024 * 1024)
        ));
        assert!(matches!(concede_todo(&gordo), Lectura::Ilegible(_)));
        let mut hondo = String::from(r#"{"Statement":"#);
        for _ in 0..1000 {
            hondo.push('[');
        }
        for _ in 0..1000 {
            hondo.push(']');
        }
        hondo.push('}');
        assert!(matches!(
            es_publica(&Value::String(hondo)),
            Lectura::Ilegible(_)
        ));
    }

    #[test]
    fn miles_de_declaraciones_se_recorren_con_tope_y_lo_no_visto_no_se_afirma() {
        // La declaracion que concede todo esta DETRAS del tope: no se ve, y por
        // eso la respuesta no puede ser «no concede».
        let mut muchas: Vec<Value> = (0..100_000)
            .map(|_| json!({"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}))
            .collect();
        muchas.push(json!({"Effect":"Allow","Action":"*","Resource":"*"}));
        let d = json!({ "Statement": muchas });
        assert!(matches!(concede_todo(&d), Lectura::Ilegible(_)));
        let d = json!({ "Statement": [{"Effect":"Allow","Principal":{"AWS": vec!["x"; 5000]},
            "Action":"s3:*","Resource":"*"}] });
        assert!(matches!(es_publica(&d), Lectura::Ilegible(_)));
    }
}
