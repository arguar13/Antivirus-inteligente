//! Heuristicas globales: deteccion de APT distribuida (FASE 45).
//!
//! # El hecho que no existe en ningun endpoint
//!
//! Un operador de APT competente no dispara ninguna alerta en ninguna maquina.
//! Ejecuta `nltest /dclist` en una, `whoami /groups` en otra, monta un recurso
//! compartido en una tercera. Cada endpoint ve una accion administrativa
//! normal —de hecho lo es, tomada de una en una— y ninguno tiene motivo para
//! avisar.
//!
//! Lo que delata la campana esta en el CONJUNTO: cincuenta maquinas enumerando
//! el dominio bajo la misma cuenta en cuarenta y ocho horas no es
//! administracion, es reconocimiento. Ese hecho solo existe en el plano de
//! control, porque es el unico que ve las cincuenta.
//!
//! # Por que la regla tiene forma fija
//!
//! Ya hay un lenguaje de consulta en el producto (AegisQL, FASE 43) y sirve
//! para otra cosa: preguntar al endpoint. Una correlacion de flota tiene una
//! forma fija —que buscar, por que agrupar, en cuanto tiempo, cuantos
//! endpoints— y con campos la valida el esquema. Un analizador de texto libre
//! seria codigo que puede equivocarse sobre algo que decide si se lanza una
//! respuesta automatica contra la flota de un cliente.

use std::collections::BTreeMap;

use crate::error::{ErrorServidor, Resultado};

/// Longitud maxima del nombre de una regla o de un patron.
const MAX_TEXTO: usize = 200;
/// Elementos maximos en `tecnicas`, `categorias` o `claves_excluidas`.
const MAX_ELEMENTOS: usize = 256;
/// Longitud maxima de cada elemento de esas listas y de la clave de agrupacion.
const MAX_ELEMENTO: usize = 128;
/// Ventana maxima: treinta dias.
///
/// Mas alla, la ventana deja de ser una ventana: casi cualquier cuenta de
/// servicio de una flota grande toca cincuenta maquinas en dos meses, y la
/// regla dispara siempre. Ademas, el coste de la consulta crece con la ventana
/// y esto lo evalua un temporizador, no una persona.
pub const VENTANA_MAXIMA_HORAS: i32 = 720;

// ---------------------------------------------------------------------------
// Atributos estructurados de una alerta
// ---------------------------------------------------------------------------

/// Tamano maximo del objeto de detalles que un agente puede adjuntar.
///
/// Es por alerta y las alertas son millones: sin techo, un agente comprometido
/// convierte el historico de seguridad en su almacenamiento gratuito, y el
/// disco se llena justo cuando hace falta registrar el incidente.
pub const MAX_DETALLES: usize = 4096;
/// Numero maximo de atributos.
pub const MAX_ATRIBUTOS: usize = 32;
/// Longitud maxima de un nombre de atributo.
pub const MAX_NOMBRE_ATRIBUTO: usize = 64;
/// Longitud maxima del valor de un atributo, ya convertido a texto.
pub const MAX_VALOR_ATRIBUTO: usize = 512;

/// Normaliza los atributos que declara un agente, o explica por que no valen.
///
/// POR QUE SOLO SE ACEPTAN ESCALARES
/// ---------------------------------
/// El motor agrupa por `detalles ->> 'cuenta'`. Si el valor fuera un objeto o
/// una lista, ese operador devolveria su texto JSON y la correlacion agruparia
/// por un bloque de JSON: dos endpoints que informan del mismo atributo con las
/// claves en distinto orden caerian en grupos distintos, y la campana que los
/// une no se veria. Un escalar tiene una representacion y solo una.
///
/// Ademas acota el coste: sin esta comprobacion, un objeto anidado de un mega
/// pasaria el limite de tamano por los pelos y costaria un arbol entero de
/// JSONB por alerta.
///
/// Entrada vacia es valida y significa "este detector no aporta atributos".
pub fn normalizar_detalles(json: &str) -> Resultado<serde_json::Value> {
    let recorte = json.trim();
    if recorte.is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    if recorte.len() > MAX_DETALLES {
        return Err(ErrorServidor::Config(format!(
            "los detalles ocupan {} bytes y el maximo es {MAX_DETALLES}",
            recorte.len()
        )));
    }
    let valor: serde_json::Value = serde_json::from_str(recorte)
        .map_err(|e| ErrorServidor::Config(format!("los detalles no son JSON valido: {e}")))?;
    let serde_json::Value::Object(objeto) = valor else {
        return Err(ErrorServidor::Config(
            "los detalles tienen que ser un objeto JSON".to_string(),
        ));
    };
    if objeto.len() > MAX_ATRIBUTOS {
        return Err(ErrorServidor::Config(format!(
            "los detalles traen {} atributos y el maximo es {MAX_ATRIBUTOS}",
            objeto.len()
        )));
    }

    // BTreeMap y no el orden de llegada: el objeto se guarda como JSONB, que ya
    // normaliza el orden, pero construirlo ordenado hace que dos agentes que
    // informen lo mismo produzcan literalmente el mismo texto. Eso importa para
    // poder comparar en las pruebas sin depender del orden de serializacion.
    let mut limpio: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (nombre, valor) in objeto {
        if nombre.is_empty() || nombre.len() > MAX_NOMBRE_ATRIBUTO {
            return Err(ErrorServidor::Config(format!(
                "el nombre de atributo '{}' no esta entre 1 y {MAX_NOMBRE_ATRIBUTO} bytes",
                nombre.chars().take(32).collect::<String>()
            )));
        }
        let escalar = match valor {
            serde_json::Value::String(s) => {
                if s.len() > MAX_VALOR_ATRIBUTO {
                    return Err(ErrorServidor::Config(format!(
                        "el atributo '{nombre}' mide {} bytes y el maximo es {MAX_VALOR_ATRIBUTO}",
                        s.len()
                    )));
                }
                serde_json::Value::String(s)
            }
            v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_)) => v,
            // Un nulo es lo mismo que no informar del atributo, y dejarlo
            // pasar crearia un grupo "sin valor" que reune todo lo que no se
            // pudo ver. Ese grupo dispararia siempre.
            serde_json::Value::Null => continue,
            _ => {
                return Err(ErrorServidor::Config(format!(
                    "el atributo '{nombre}' tiene que ser texto, numero o booleano"
                )))
            }
        };
        limpio.insert(nombre, escalar);
    }
    Ok(serde_json::Value::Object(limpio.into_iter().collect()))
}

// ---------------------------------------------------------------------------
// Las reglas
// ---------------------------------------------------------------------------

/// Una regla de correlacion, tal como la escribe un analista.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NuevaHeuristica {
    /// Nombre unico.
    pub nombre: String,
    /// Que se le dice al analista cuando dispara.
    pub patron: String,
    /// Tecnicas ATT&CK que cuentan para esta regla.
    #[serde(default)]
    pub tecnicas: Vec<String>,
    /// Categorias de alerta que cuentan para esta regla.
    #[serde(default)]
    pub categorias: Vec<String>,
    /// Atributo de `detalles` por el que se agrupa.
    pub clave_detalle: String,
    /// Ventana deslizante, en horas.
    pub ventana_horas: i32,
    /// Endpoints DISTINTOS necesarios para disparar.
    pub minimo_endpoints: i32,
    /// Severidad de la correlacion resultante.
    #[serde(default = "severidad_por_defecto")]
    pub severidad: i16,
    /// Tecnica ATT&CK que se le asigna a la correlacion.
    #[serde(default)]
    pub tecnica_mitre: Option<String>,
    /// Tactica ATT&CK que se le asigna a la correlacion.
    #[serde(default)]
    pub tactica_mitre: Option<String>,
}

fn severidad_por_defecto() -> i16 {
    4
}

/// Una regla ya validada. Solo se construye por [`NuevaHeuristica::validar`].
#[derive(Debug, Clone)]
pub struct Heuristica {
    /// Nombre unico.
    pub nombre: String,
    /// Patron legible.
    pub patron: String,
    /// Tecnicas ATT&CK aceptadas.
    pub tecnicas: Vec<String>,
    /// Categorias aceptadas.
    pub categorias: Vec<String>,
    /// Atributo de agrupacion.
    pub clave_detalle: String,
    /// Ventana en horas.
    pub ventana_horas: i32,
    /// Endpoints distintos necesarios.
    pub minimo_endpoints: i32,
    /// Severidad de la correlacion.
    pub severidad: i16,
    /// Tecnica ATT&CK de la correlacion.
    pub tecnica_mitre: Option<String>,
    /// Tactica ATT&CK de la correlacion.
    pub tactica_mitre: Option<String>,
}

impl NuevaHeuristica {
    /// Comprueba la regla ANTES de que llegue a la base de datos.
    ///
    /// El esquema tiene sus propias restricciones y son la ultima palabra; esto
    /// existe para que el analista reciba un motivo en castellano en vez de un
    /// error de violacion de restriccion, y para las comprobaciones que el
    /// esquema no puede hacer.
    pub fn validar(self) -> Resultado<Heuristica> {
        let nombre = texto_acotado("nombre", &self.nombre)?;
        let patron = texto_acotado("patron", &self.patron)?;
        let clave_detalle = elemento_valido("clave_detalle", &self.clave_detalle)?;

        let tecnicas = lista_valida("tecnicas", &self.tecnicas)?;
        let categorias = lista_valida("categorias", &self.categorias)?;
        // Una regla que no busca nada casa con TODA alerta de la flota: no es
        // una heuristica, es un contador de alertas disfrazado de deteccion.
        if tecnicas.is_empty() && categorias.is_empty() {
            return Err(ErrorServidor::Config(
                "la regla tiene que declarar al menos una tecnica o una categoria".to_string(),
            ));
        }

        if !(1..=VENTANA_MAXIMA_HORAS).contains(&self.ventana_horas) {
            return Err(ErrorServidor::Config(format!(
                "la ventana es de {} horas y tiene que estar entre 1 y {VENTANA_MAXIMA_HORAS}",
                self.ventana_horas
            )));
        }
        // Uno solo no es una correlacion distribuida: es una alerta con otro
        // nombre, y ademas la produciria un unico endpoint —posiblemente el
        // comprometido— sin que nadie mas la corrobore.
        if self.minimo_endpoints < 2 {
            return Err(ErrorServidor::Config(
                "una correlacion distribuida necesita al menos 2 endpoints".to_string(),
            ));
        }
        if !(0..=4).contains(&self.severidad) {
            return Err(ErrorServidor::Config(
                "la severidad tiene que estar entre 0 y 4".to_string(),
            ));
        }

        Ok(Heuristica {
            nombre,
            patron,
            tecnicas,
            categorias,
            clave_detalle,
            ventana_horas: self.ventana_horas,
            minimo_endpoints: self.minimo_endpoints,
            severidad: self.severidad,
            tecnica_mitre: self
                .tecnica_mitre
                .map(|t| elemento_valido("tecnica_mitre", &t))
                .transpose()?,
            tactica_mitre: self
                .tactica_mitre
                .map(|t| texto_acotado("tactica_mitre", &t))
                .transpose()?,
        })
    }
}

fn texto_acotado(campo: &str, v: &str) -> Resultado<String> {
    let t = v.trim();
    if t.is_empty() || t.len() > MAX_TEXTO {
        return Err(ErrorServidor::Config(format!(
            "'{campo}' tiene que medir entre 1 y {MAX_TEXTO} bytes"
        )));
    }
    Ok(t.to_string())
}

/// Valida un elemento que se compara CONTRA DATOS (una tecnica, una categoria,
/// un nombre de atributo).
///
/// El juego de caracteres se restringe a proposito. No es por inyeccion —todo
/// viaja como parametro— sino porque un elemento con espacios o mayusculas
/// inesperadas NO CASA CON NADA y la regla queda muda: el analista cree tener
/// una deteccion activa y no tiene ninguna. Un fallo ruidoso al crearla es
/// infinitamente mejor que una regla que nunca dispara.
fn elemento_valido(campo: &str, v: &str) -> Resultado<String> {
    let t = v.trim();
    if t.is_empty() || t.len() > MAX_ELEMENTO {
        return Err(ErrorServidor::Config(format!(
            "'{campo}' tiene que medir entre 1 y {MAX_ELEMENTO} bytes"
        )));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        return Err(ErrorServidor::Config(format!(
            "'{campo}' solo admite letras, digitos y . _ - :  (recibido: '{}')",
            t.chars().take(32).collect::<String>()
        )));
    }
    Ok(t.to_string())
}

fn lista_valida(campo: &str, v: &[String]) -> Resultado<Vec<String>> {
    if v.len() > MAX_ELEMENTOS {
        return Err(ErrorServidor::Config(format!(
            "'{campo}' trae {} elementos y el maximo es {MAX_ELEMENTOS}",
            v.len()
        )));
    }
    let mut salida = Vec::with_capacity(v.len());
    for e in v {
        let e = elemento_valido(campo, e)?;
        if !salida.contains(&e) {
            salida.push(e);
        }
    }
    Ok(salida)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn regla() -> NuevaHeuristica {
        NuevaHeuristica {
            nombre: "reconocimiento-distribuido".to_string(),
            patron: "Movimiento Lateral Distribuido".to_string(),
            tecnicas: vec!["T1087".to_string()],
            categorias: vec![],
            clave_detalle: "cuenta".to_string(),
            ventana_horas: 48,
            minimo_endpoints: 50,
            severidad: 4,
            tecnica_mitre: Some("T1087".to_string()),
            tactica_mitre: Some("Descubrimiento".to_string()),
        }
    }

    #[test]
    fn una_regla_del_ejemplo_canonico_se_acepta() {
        let h = regla().validar().unwrap();
        assert_eq!(h.minimo_endpoints, 50);
        assert_eq!(h.ventana_horas, 48);
    }

    #[test]
    fn una_regla_que_no_busca_nada_se_rechaza() {
        // Casaria con toda alerta de la flota: no es una deteccion, es un
        // contador de alertas con nombre de deteccion.
        let mut r = regla();
        r.tecnicas.clear();
        r.categorias.clear();
        assert!(r.validar().is_err());
    }

    #[test]
    fn una_correlacion_de_un_solo_endpoint_se_rechaza() {
        // Con un endpoint no hay nada que corroborar: la produciria el propio
        // endpoint comprometido sin que ninguna otra maquina la respalde.
        let mut r = regla();
        r.minimo_endpoints = 1;
        assert!(r.validar().is_err());
    }

    #[test]
    fn una_ventana_desmesurada_se_rechaza() {
        // En dos meses, casi cualquier cuenta de servicio de una flota grande
        // toca cincuenta maquinas: la regla dispararia siempre.
        let mut r = regla();
        r.ventana_horas = VENTANA_MAXIMA_HORAS + 1;
        assert!(r.clone().validar().is_err());
        r.ventana_horas = 0;
        assert!(r.validar().is_err());
    }

    #[test]
    fn una_tecnica_con_espacios_se_rechaza_en_vez_de_quedar_muda() {
        // "T1087 " no casa con nada. Aceptarla dejaria al analista con una
        // deteccion que cree activa y que no dispara nunca.
        let mut r = regla();
        r.tecnicas = vec!["T1087 lateral".to_string()];
        assert!(r.validar().is_err());
    }

    #[test]
    fn las_tecnicas_repetidas_se_colapsan() {
        let mut r = regla();
        r.tecnicas = vec![
            "T1087".to_string(),
            "T1087".to_string(),
            "T1018".to_string(),
        ];
        assert_eq!(r.validar().unwrap().tecnicas, vec!["T1087", "T1018"]);
    }

    // --- atributos de alerta ---

    #[test]
    fn unos_detalles_vacios_son_un_objeto_vacio_y_no_un_error() {
        // "este detector no aporta atributos" es una respuesta legitima.
        assert_eq!(normalizar_detalles("").unwrap(), serde_json::json!({}));
        assert_eq!(normalizar_detalles("   ").unwrap(), serde_json::json!({}));
    }

    #[test]
    fn un_valor_anidado_se_rechaza_porque_no_sirve_para_agrupar() {
        // `detalles ->> 'x'` sobre un objeto devuelve su texto JSON: dos agentes
        // que informen lo mismo con las claves en otro orden caerian en grupos
        // distintos y la campana que los une no se veria.
        assert!(normalizar_detalles(r#"{"cuenta":{"nombre":"admin"}}"#).is_err());
        assert!(normalizar_detalles(r#"{"cuenta":["admin"]}"#).is_err());
    }

    #[test]
    fn un_nulo_se_descarta_en_vez_de_crear_un_grupo_de_lo_desconocido() {
        let v = normalizar_detalles(r#"{"cuenta":null,"pid":42}"#).unwrap();
        assert_eq!(v, serde_json::json!({"pid": 42}));
    }

    #[test]
    fn unos_detalles_que_no_son_un_objeto_se_rechazan() {
        assert!(normalizar_detalles("[1,2,3]").is_err());
        assert!(normalizar_detalles("\"admin\"").is_err());
        assert!(normalizar_detalles("42").is_err());
        assert!(normalizar_detalles("{no es json}").is_err());
    }

    #[test]
    fn unos_detalles_desmesurados_se_rechazan_antes_de_analizarse() {
        // Son millones de alertas: sin techo, un agente comprometido convierte
        // el historico de seguridad en su almacenamiento gratuito.
        let enorme = format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_DETALLES));
        assert!(normalizar_detalles(&enorme).is_err());
    }

    #[test]
    fn demasiados_atributos_se_rechazan() {
        let campos: Vec<String> = (0..=MAX_ATRIBUTOS)
            .map(|i| format!(r#""c{i}":1"#))
            .collect();
        let j = format!("{{{}}}", campos.join(","));
        assert!(normalizar_detalles(&j).is_err());
    }

    #[test]
    fn los_escalares_utiles_sobreviven_intactos() {
        let v =
            normalizar_detalles(r#"{"cuenta":"CORP\\admin","pid":1234,"elevado":true}"#).unwrap();
        assert_eq!(v["cuenta"], "CORP\\admin");
        assert_eq!(v["pid"], 1234);
        assert_eq!(v["elevado"], true);
    }
}
