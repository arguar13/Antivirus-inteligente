//! De un [`Evento`] normalizado a lo que una comprobacion necesita leer de el.
//!
//! # Lo que el aplanado de `aegis-pipeline` conserva, y lo que no
//!
//! Esta es la decision de la que depende todo el crate, asi que se escribe con
//! la evidencia delante. `aegis_pipeline::nube` convierte el registro del
//! proveedor en un [`Evento`] y, para AWS, **aplana** `requestParameters` en
//! `evento.campos` con claves `nube.parametros.<ruta>`. Leido el codigo de
//! `aplanar`:
//!
//! | Que | Que hace el aplanado | Consecuencia aqui |
//! |---|---|---|
//! | Objetos | `prefijo.clave`, recursivo | Se reconstruyen sin perdida |
//! | Arrays | `prefijo.0`, `prefijo.1`... **solo los 32 primeros** (`take(32)`) | El elemento 33 de `ipRanges` se pierde **sin rastro**: un atacante que pone 32 rangos inocentes y `0.0.0.0/0` el 33 no se veria |
//! | Profundidad | se corta a `MAX_PROFUNDIDAD` = 8 | Lo que leen estas comprobaciones esta a 7 niveles como mucho; el corte no les afecta, pero no se puede detectar desde fuera |
//! | Numero de campos | se corta a `MAX_CAMPOS` = 128 **en todo el evento** | Un `requestParameters` grande pierde su cola |
//! | Textos | se recortan a `MAX_CAMPO` = 4096 bytes | Un `policyDocument` de 5 KiB llega truncado y **no es JSON** |
//! | `responseElements` de AWS | **no se aplana** | El `accessKeyId` de `CreateAccessKey` y los `securityGroupRuleId` solo estan en el crudo |
//! | `properties` de Azure | **no se aplana** | El cuerpo de `roleAssignments/write` y de `securityRules/write` solo esta en el crudo |
//! | `protoPayload.request` / `serviceData` de GCP | **no se aplanan** | Los `bindingDeltas` de `SetIamPolicy` y las `sourceRanges` de un cortafuegos solo estan en el crudo |
//!
//! Los arrays, por tanto, **no se descartan**: se conservan indexados y con un
//! tope de 32 que no deja marca. Eso no se esquiva en silencio, y tampoco se
//! arregla tocando `aplanar`: cambiar lo que entra en `evento.campos` cambia el
//! [`Evento::id`] —que se deriva de los campos— de todos los eventos de nube, y
//! el mismo registro reentregado tras la actualizacion ya no se desduplicaria
//! contra el almacenado antes. Es una migracion, no un arreglo.
//!
//! La solucion de raiz es otra y ya existe: el evento puede llevar el registro
//! **crudo** (`Contexto::conservar_crudo`), que es el documento del proveedor
//! entero, sin aplanar y sin recortar mas que por `MAX_DOCUMENTO`. Este modulo:
//!
//! 1. Lee **el crudo** cuando esta. Es la fuente completa.
//! 2. Sin crudo, y solo en AWS, **reconstruye** `requestParameters` desde los
//!    campos aplanados y marca la lectura como [`Detalle::CamposTruncados`]
//!    cuando hay cualquier señal de que el aplanado corto algo (32 elementos,
//!    128 campos, un texto al tope). Una comprobacion que lea asi puede afirmar
//!    que algo ESTA abierto, pero no que NO lo esta.
//! 3. Sin crudo en Azure o GCP, no hay cuerpo que leer: [`Detalle::Ninguno`], y
//!    la comprobacion dice `SinDatos` con ese motivo — nunca `Cumple`.
//!
//! La consecuencia operativa se escribe en el fragmento de documentacion: para
//! que la postura de Azure y GCP diga algo, el conector de nube tiene que correr
//! con `conservar_crudo`.

use std::borrow::Cow;
use std::collections::BTreeMap;

use aegis_ingest::esquema::{
    recortar, Evento, Origen, Resultado as ResultadoEvento, Valor, MAX_CAMPO, MAX_CAMPOS,
};
use aegis_pipeline::nube::{Proveedor, MAX_DOCUMENTO, MAX_PROFUNDIDAD};
use serde_json::{Map, Value};

use crate::modelo::Referencia;

/// Bytes maximos de un documento anidado como texto dentro del evento: una
/// politica IAM, un cuerpo de peticion de Azure.
///
/// Las politicas de AWS miden como mucho 10 240 caracteres (en linea) y 20 KiB
/// (de cubo); 64 KiB es holgado y sigue siendo un tope. Lo que lo supera no se
/// analiza y se dice.
pub const MAX_CUERPO: usize = 64 * 1024;

/// Elementos maximos que se recorren de una lista (reglas, rangos, miembros,
/// declaraciones).
///
/// El documento ya esta acotado por `MAX_DOCUMENTO` y [`MAX_CUERPO`], asi que
/// este tope no protege la memoria —eso ya esta hecho— sino el tiempo: el
/// recorrido es lineal y 4096 elementos por lista es mas de lo que cualquier
/// configuracion real tiene (un grupo de seguridad admite 60 reglas por
/// defecto; una politica de IAM, 10 KiB). Lo que lo supera se DICE: ver
/// [`lista_con_tope`].
pub const MAX_ELEMENTOS: usize = 4096;

/// Elementos de un array que conserva el aplanado de `aegis-pipeline`.
///
/// Es el `take(32)` de `aegis_pipeline::nube::aplanar`, repetido aqui porque ese
/// modulo no lo exporta. Si cambia alli, la prueba
/// `el_tope_de_arrays_del_aplanado_es_el_que_se_cree` lo detecta.
pub const ARRAY_APLANADO: usize = 32;

/// De donde salio el detalle de la peticion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detalle {
    /// Del registro crudo del proveedor: completo.
    Crudo,
    /// Reconstruido de los campos aplanados, sin señal de recorte.
    Campos,
    /// Reconstruido de los campos aplanados, y el aplanado pudo cortar algo.
    CamposTruncados,
    /// No hay detalle que leer.
    Ninguno,
}

impl Detalle {
    /// Si se puede afirmar que algo NO esta en la peticion.
    #[must_use]
    pub fn completo(self) -> bool {
        matches!(self, Detalle::Crudo | Detalle::Campos)
    }
}

/// Si una llamada configuro algo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desenlace {
    /// La llamada tuvo exito: cambia el estado.
    Aplicada,
    /// Azure: la operacion empezo (`Start`, `Accept`) y su final no ha llegado.
    /// No cambia el estado; su cuerpo se guarda por si llega el final.
    Pendiente,
    /// Fallo, se rechazo o no se sabe como acabo: **no configuro nada**.
    NoAplicada,
}

/// Una llamada al plano de control, lista para leer.
#[derive(Debug)]
pub struct Llamada<'a> {
    /// El evento del que sale.
    pub evento: &'a Evento,
    /// De que nube.
    pub proveedor: Proveedor,
    /// `eventName`, `operationName` o `methodName`.
    pub accion: String,
    /// Cuenta, suscripcion o proyecto, si se sabe.
    pub cuenta: String,
    /// Region, si se sabe.
    pub region: String,
    /// Quien llamo, legible.
    pub usuario: String,
    /// El recurso que nombra el evento, si lo nombra.
    pub recurso: String,
    /// De donde sale el detalle.
    pub detalle: Detalle,
    crudo: Option<Value>,
    reconstruida: Option<Value>,
}

impl<'a> Llamada<'a> {
    /// Prepara la lectura de un evento. `None` si no es de nube.
    #[must_use]
    pub fn de(evento: &'a Evento) -> Option<Llamada<'a>> {
        if evento.origen != Origen::Nube {
            return None;
        }
        let proveedor = match campo(evento, "nube.proveedor").as_str() {
            "aws" => Proveedor::Aws,
            "azure" => Proveedor::Azure,
            "gcp" => Proveedor::Gcp,
            _ => return None,
        };
        // El crudo lo escribio el atacante en parte: se lee con el mismo tope
        // que la ingesta, y si no es JSON legible se trata como ausente.
        let crudo = evento
            .crudo
            .as_ref()
            .filter(|c| c.len() <= MAX_DOCUMENTO)
            .and_then(|c| serde_json::from_slice::<Value>(c).ok())
            .filter(Value::is_object);
        let (reconstruida, truncada) = if crudo.is_none() && proveedor == Proveedor::Aws {
            reconstruir(&evento.campos, "nube.parametros")
        } else {
            (None, false)
        };
        let detalle = match (&crudo, &reconstruida) {
            (Some(_), _) => Detalle::Crudo,
            (None, Some(_)) if truncada => Detalle::CamposTruncados,
            (None, Some(_)) => Detalle::Campos,
            (None, None) => Detalle::Ninguno,
        };
        Some(Llamada {
            evento,
            proveedor,
            accion: campo(evento, "nube.accion"),
            cuenta: campo(evento, "nube.cuenta"),
            region: campo(evento, "nube.region"),
            usuario: campo(evento, "usuario"),
            recurso: campo(evento, "nube.recurso"),
            detalle,
            crudo,
            reconstruida,
        })
    }

    /// El registro crudo, si se conservo y es legible.
    #[must_use]
    pub fn crudo(&self) -> Option<&Value> {
        self.crudo.as_ref()
    }

    /// Los parametros de la peticion.
    ///
    /// AWS: `requestParameters` (del crudo o reconstruido). Azure: el
    /// `requestbody` de `properties`, que llega como TEXTO JSON. GCP:
    /// `protoPayload.request`.
    #[must_use]
    pub fn peticion(&self) -> Option<Cow<'_, Value>> {
        match self.proveedor {
            Proveedor::Aws => match &self.crudo {
                Some(c) => ci(c, "requestParameters")
                    .filter(|v| !v.is_null())
                    .map(Cow::Borrowed),
                None => self.reconstruida.as_ref().map(Cow::Borrowed),
            },
            Proveedor::Azure => {
                let p = ci(self.crudo.as_ref()?, "properties")?;
                ci(p, "requestbody").and_then(|v| json_anidado(v).ok())
            }
            Proveedor::Gcp => {
                ruta(self.crudo.as_ref()?, &["protoPayload", "request"]).map(Cow::Borrowed)
            }
        }
    }

    /// La respuesta del proveedor, si la hay. Solo existe en el crudo.
    #[must_use]
    pub fn respuesta(&self) -> Option<Cow<'_, Value>> {
        let c = self.crudo.as_ref()?;
        match self.proveedor {
            Proveedor::Aws => ci(c, "responseElements")
                .filter(|v| !v.is_null())
                .map(Cow::Borrowed),
            Proveedor::Azure => {
                let p = ci(c, "properties")?;
                ci(p, "responseBody").and_then(|v| json_anidado(v).ok())
            }
            Proveedor::Gcp => ruta(c, &["protoPayload", "response"]).map(Cow::Borrowed),
        }
    }

    /// GCP: el `policyDelta` de la llamada, que viene en `serviceData` (API v1)
    /// o en `metadata` (servicios mas nuevos).
    #[must_use]
    pub fn delta_de_politica(&self) -> Option<&Value> {
        let c = self.crudo.as_ref()?;
        ruta(c, &["protoPayload", "serviceData", "policyDelta"])
            .or_else(|| ruta(c, &["protoPayload", "metadata", "policyDelta"]))
            .or_else(|| {
                ruta(
                    c,
                    &["protoPayload", "metadata", "datasetChange", "policyDelta"],
                )
            })
    }

    /// GCP: la operacion larga a la que pertenece el evento, si la hay.
    #[must_use]
    pub fn operacion(&self) -> Option<(String, bool)> {
        let op = ci(self.crudo.as_ref()?, "operation")?;
        let id = ci(op, "id").and_then(texto)?;
        let ultima = ci(op, "last").and_then(booleano).unwrap_or(false);
        Some((id, ultima))
    }

    /// Como acabo la llamada.
    ///
    /// # Azure se lee distinto, y a proposito
    ///
    /// En Azure una operacion produce VARIOS registros con el mismo
    /// `correlationId`: `Start` (que es el que lleva el cuerpo de la peticion) y
    /// luego `Success` o `Failure`. `aegis-pipeline` clasifica `Start` como
    /// fallo —no es exito—, y leerlo asi aqui tiraria el unico registro que dice
    /// QUE se configuro. Tampoco se puede aplicar al ver `Start`: la operacion
    /// puede fallar despues. Asi que `Start`/`Accept` quedan pendientes y solo el
    /// final con exito aplica.
    #[must_use]
    pub fn desenlace(&self) -> Desenlace {
        if self.proveedor == Proveedor::Azure {
            return match campo(self.evento, "nube.resultado")
                .to_ascii_lowercase()
                .as_str()
            {
                "success" | "succeeded" => Desenlace::Aplicada,
                "start" | "started" | "accept" | "accepted" => Desenlace::Pendiente,
                _ => Desenlace::NoAplicada,
            };
        }
        if self.evento.resultado == ResultadoEvento::Exito {
            Desenlace::Aplicada
        } else {
            Desenlace::NoAplicada
        }
    }

    /// El identificador de correlacion de Azure.
    #[must_use]
    pub fn correlacion(&self) -> String {
        campo(self.evento, "nube.correlacion")
    }

    /// El identificador estable de quien llamo, para derivar su entidad.
    ///
    /// AWS: el ARN de `userIdentity` (el crudo lo tiene; los campos solo el
    /// nombre). Azure: el `objectidentifier` de las reclamaciones, que es el
    /// mismo `PrincipalId` que aparece en una asignacion de rol: asi quien
    /// concede y quien recibe caen en la misma entidad. GCP: el correo.
    #[must_use]
    pub fn actor(&self) -> String {
        match self.proveedor {
            Proveedor::Aws => {
                if let Some(arn) = self
                    .crudo
                    .as_ref()
                    .and_then(|c| ruta(c, &["userIdentity", "arn"]))
                    .and_then(texto)
                    .filter(|s| !s.is_empty())
                {
                    return arn;
                }
                if self.usuario.starts_with("arn:") {
                    return self.usuario.clone();
                }
                if campo(self.evento, "nube.identidad_tipo") == "IAMUser"
                    && !self.cuenta.is_empty()
                    && !self.usuario.is_empty()
                {
                    return arn_iam(&self.cuenta, "user", &self.usuario);
                }
                format!("aws:{}:{}", self.cuenta, self.usuario)
            }
            Proveedor::Azure => self
                .crudo
                .as_ref()
                .and_then(|c| ruta(c, &["identity", "claims"]))
                .and_then(|cl| {
                    ci(
                        cl,
                        "http://schemas.microsoft.com/identity/claims/objectidentifier",
                    )
                    .or_else(|| ci(cl, "oid"))
                })
                .and_then(texto)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| self.usuario.clone()),
            Proveedor::Gcp => self.usuario.clone(),
        }
    }

    /// La referencia de evidencia de esta llamada.
    #[must_use]
    pub fn referencia(&self) -> Referencia {
        Referencia::Evento {
            id: self.evento.id.clone(),
            ocurrio_ns: self.evento.ocurrio_ns,
            accion: recortar(&self.accion, 128),
        }
    }
}

/// El ARN de una identidad de IAM.
#[must_use]
pub fn arn_iam(cuenta: &str, tipo: &str, nombre: &str) -> String {
    let cuenta = if cuenta.is_empty() {
        "desconocida"
    } else {
        cuenta
    };
    format!("arn:aws:iam::{cuenta}:{tipo}/{nombre}")
}

/// Un campo de texto del evento, o vacio.
#[must_use]
pub fn campo(e: &Evento, clave: &str) -> String {
    e.campos.get(clave).map(Valor::texto).unwrap_or_default()
}

/// `v[clave]`, probando primero la clave exacta y luego sin distinguir
/// mayusculas.
///
/// Azure escribe `Properties.RoleDefinitionId` en la peticion y
/// `properties.roleDefinitionId` en la respuesta; IAM acepta `Statement` y
/// `statement`. Leer solo una grafia seria perder el hallazgo por una
/// mayuscula.
#[must_use]
pub fn ci<'v>(v: &'v Value, clave: &str) -> Option<&'v Value> {
    let m = v.as_object()?;
    if let Some(x) = m.get(clave) {
        return Some(x);
    }
    m.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(clave))
        .map(|(_, x)| x)
}

/// Sigue una ruta de claves (sin distinguir mayusculas).
#[must_use]
pub fn ruta<'v>(v: &'v Value, claves: &[&str]) -> Option<&'v Value> {
    let mut x = v;
    for k in claves {
        x = ci(x, k)?;
    }
    Some(x)
}

/// Los elementos de algo que deberia ser una lista, venga como venga.
///
/// Tres formas reales: un array JSON; el `{"items":[...]}` con que CloudTrail
/// envuelve las listas de EC2; y el objeto de claves `"0"`, `"1"`... que sale al
/// reconstruir un array aplanado. Un escalar es una lista de uno (IAM acepta
/// `"Action":"*"` y `"Action":["*"]`). Con tope.
#[must_use]
pub fn lista(v: &Value) -> Vec<&Value> {
    lista_con_tope(v).0
}

/// Como [`lista`], y ademas dice si la lista tenia mas de [`MAX_ELEMENTOS`] y
/// se corto.
///
/// # Por que importa saberlo
///
/// Es el mismo defecto que se le señala al aplanado: una lista cortada en
/// silencio convierte «no lo encontre en los primeros N» en «no esta». Quien
/// concluye que algo NO esta en una lista tiene que preguntar si la vio
/// entera; si no la vio, la respuesta honrada es `SinDatos`.
#[must_use]
pub fn lista_con_tope(v: &Value) -> (Vec<&Value>, bool) {
    match v {
        Value::Null => (Vec::new(), false),
        Value::Array(a) => (
            a.iter().take(MAX_ELEMENTOS).collect(),
            a.len() > MAX_ELEMENTOS,
        ),
        Value::Object(m) => {
            if let Some(items) = ci(v, "items") {
                return lista_con_tope(items);
            }
            if !m.is_empty() && m.keys().all(|k| k.parse::<usize>().is_ok()) {
                let mut pares: Vec<(usize, &Value)> = m
                    .iter()
                    .filter_map(|(k, x)| k.parse::<usize>().ok().map(|i| (i, x)))
                    .collect();
                pares.sort_by_key(|(i, _)| *i);
                let cortada = pares.len() > MAX_ELEMENTOS;
                return (
                    pares
                        .into_iter()
                        .take(MAX_ELEMENTOS)
                        .map(|(_, x)| x)
                        .collect(),
                    cortada,
                );
            }
            (vec![v], false)
        }
        _ => (vec![v], false),
    }
}

/// Un valor escalar como texto, con tope.
#[must_use]
pub fn texto(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(recortar(s, MAX_CAMPO)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Un valor como entero (numero o texto numerico).
#[must_use]
pub fn entero(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Un valor como booleano (booleano o texto `true`/`false`).
#[must_use]
pub fn booleano(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// Un documento JSON que puede venir como objeto o como TEXTO JSON (plano o
/// codificado como URL, que es como CloudTrail entrega los `policyDocument` de
/// algunas llamadas de IAM).
///
/// # Errors
///
/// Devuelve el motivo si el texto supera [`MAX_CUERPO`], no es JSON legible o
/// anida mas de lo que `serde_json` admite (128 niveles, su limite de
/// recursion, que es lo que impide que un documento de mil niveles agote la
/// pila).
pub fn json_anidado(v: &Value) -> Result<Cow<'_, Value>, String> {
    match v {
        Value::Object(_) | Value::Array(_) => Ok(Cow::Borrowed(v)),
        Value::String(s) => texto_json(s).map(Cow::Owned),
        _ => Err("no es un documento".into()),
    }
}

/// Interpreta un texto JSON, plano o codificado como URL, con tope.
///
/// # Errors
///
/// Igual que [`json_anidado`].
pub fn texto_json(s: &str) -> Result<Value, String> {
    if s.len() > MAX_CUERPO {
        return Err(format!(
            "documento de {} bytes, mayor que el tope de {MAX_CUERPO}: no se analiza",
            s.len()
        ));
    }
    match serde_json::from_str::<Value>(s) {
        Ok(v) => Ok(v),
        Err(e) if s.contains('%') => {
            let d = desescapar_url(s).ok_or("codificacion URL invalida")?;
            serde_json::from_str::<Value>(&d)
                .map_err(|e2| format!("no es JSON legible ({e}; decodificado: {e2})"))
        }
        Err(e) => Err(format!("no es JSON legible ({e})")),
    }
}

/// Decodifica `%XX` y `+`. `None` si una secuencia esta rota o el resultado no
/// es UTF-8. La salida nunca es mas larga que la entrada.
#[must_use]
pub fn desescapar_url(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let alto = hex(*b.get(i + 1)?)?;
                let bajo = hex(*b.get(i + 2)?)?;
                out.push(alto << 4 | bajo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            x => {
                out.push(x);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Reconstruye un objeto desde los campos aplanados bajo `prefijo`.
///
/// Devuelve el objeto (si habia algo) y si hay señal de que el aplanado corto:
/// el evento lleno sus 128 campos, algun array llego a su elemento 32, alguna
/// clave toco la profundidad maxima o algun texto llego al tope.
#[must_use]
pub fn reconstruir(campos: &BTreeMap<String, Valor>, prefijo: &str) -> (Option<Value>, bool) {
    let pref = format!("{prefijo}.");
    let mut raiz = Map::new();
    let mut truncado = campos.len() >= MAX_CAMPOS;
    let ultimo_indice = (ARRAY_APLANADO - 1).to_string();
    for (k, v) in campos.range(pref.clone()..) {
        let Some(resto) = k.strip_prefix(&pref) else {
            break;
        };
        let partes: Vec<&str> = resto.split('.').collect();
        if partes.len() >= MAX_PROFUNDIDAD || partes.iter().any(|p| *p == ultimo_indice) {
            truncado = true;
        }
        let hoja = match v {
            Valor::Texto(s) => {
                if s.len() + 4 >= MAX_CAMPO {
                    truncado = true;
                }
                Value::String(s.clone())
            }
            Valor::Entero(n) => Value::from(*n),
            Valor::Booleano(b) => Value::Bool(*b),
        };
        insertar(&mut raiz, &partes, hoja);
    }
    if raiz.is_empty() {
        (None, truncado)
    } else {
        (Some(Value::Object(raiz)), truncado)
    }
}

fn insertar(m: &mut Map<String, Value>, partes: &[&str], hoja: Value) {
    let Some((primera, resto)) = partes.split_first() else {
        return;
    };
    if resto.is_empty() {
        m.entry((*primera).to_string()).or_insert(hoja);
        return;
    }
    let hijo = m
        .entry((*primera).to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    // Una clave que es hoja y a la vez tiene hijos no sale de un aplanado
    // correcto; si aparece, se conserva lo primero y se ignora lo demas.
    if let Value::Object(h) = hijo {
        insertar(h, resto, hoja);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_pipeline::nube::{analizar_lote, Contexto};

    fn ctx(crudo: bool) -> Contexto {
        Contexto {
            inquilino: "t".into(),
            observado_ns: 1_780_000_000_000_000_000,
            conservar_crudo: crudo,
        }
    }

    fn sg_con_rangos(n: usize) -> String {
        let mut rangos = String::new();
        for i in 0..n {
            if i > 0 {
                rangos.push(',');
            }
            rangos.push_str(&format!(r#"{{"cidrIp":"10.0.{i}.0/24"}}"#));
        }
        format!(
            r#"{{"eventVersion":"1.08","eventSource":"ec2.amazonaws.com",
            "eventName":"AuthorizeSecurityGroupIngress","eventID":"e1",
            "eventTime":"2026-09-01T00:00:00Z",
            "requestParameters":{{"groupId":"sg-1","ipPermissions":{{"items":[
              {{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{{"items":[{rangos}]}}}}]}}}}}}"#
        )
    }

    #[test]
    fn el_tope_de_arrays_del_aplanado_es_el_que_se_cree() {
        // Si `aplanar` cambia su `take(32)`, esta prueba lo dice y la deteccion
        // de truncado se revisa: no se descubre en produccion.
        let e = analizar_lote(sg_con_rangos(40).as_bytes(), &ctx(false)).remove(0);
        let n = e.campos.keys().filter(|k| k.ends_with(".cidrIp")).count();
        assert_eq!(n, ARRAY_APLANADO);
    }

    #[test]
    fn sin_crudo_la_peticion_de_aws_se_reconstruye_con_sus_listas() {
        let e = analizar_lote(sg_con_rangos(2).as_bytes(), &ctx(false)).remove(0);
        let l = Llamada::de(&e).unwrap();
        assert_eq!(l.detalle, Detalle::Campos);
        let p = l.peticion().unwrap();
        let perms = lista(ci(&p, "ipPermissions").unwrap());
        assert_eq!(perms.len(), 1);
        let rangos = lista(ruta(perms[0], &["ipRanges"]).unwrap());
        assert_eq!(rangos.len(), 2);
        assert_eq!(entero(ci(perms[0], "fromPort").unwrap()), Some(22));
    }

    #[test]
    fn un_array_cortado_por_el_aplanado_se_marca_como_truncado() {
        let e = analizar_lote(sg_con_rangos(40).as_bytes(), &ctx(false)).remove(0);
        let l = Llamada::de(&e).unwrap();
        assert_eq!(l.detalle, Detalle::CamposTruncados);
        assert!(!l.detalle.completo());
    }

    #[test]
    fn con_crudo_se_lee_el_documento_entero() {
        let e = analizar_lote(sg_con_rangos(40).as_bytes(), &ctx(true)).remove(0);
        let l = Llamada::de(&e).unwrap();
        assert_eq!(l.detalle, Detalle::Crudo);
        let p = l.peticion().unwrap();
        let perms = lista(ci(&p, "ipPermissions").unwrap());
        assert_eq!(lista(ci(perms[0], "ipRanges").unwrap()).len(), 40);
    }

    #[test]
    fn una_politica_codificada_como_url_se_decodifica() {
        let v = texto_json("%7B%22Statement%22%3A%5B%5D%7D").unwrap();
        assert!(v.get("Statement").is_some());
    }

    #[test]
    fn un_documento_de_un_mega_no_se_analiza_y_se_dice() {
        let grande = format!(r#"{{"a":"{}"}}"#, "x".repeat(1024 * 1024));
        let err = texto_json(&grande).unwrap_err();
        assert!(err.contains("tope"), "{err}");
    }

    #[test]
    fn un_documento_de_mil_niveles_no_revienta_nada() {
        let mut s = String::new();
        for _ in 0..1000 {
            s.push('[');
        }
        for _ in 0..1000 {
            s.push(']');
        }
        assert!(texto_json(&s).is_err());
        let codificado = s.replace('[', "%5B").replace(']', "%5D");
        assert!(texto_json(&codificado).is_err());
    }

    #[test]
    fn una_codificacion_url_rota_no_se_inventa() {
        assert!(desescapar_url("%4").is_none());
        assert!(desescapar_url("%zz").is_none());
        assert_eq!(desescapar_url("a+b%21").as_deref(), Some("a b!"));
    }

    #[test]
    fn la_lista_acepta_las_tres_formas_reales() {
        let a: Value = serde_json::json!(["x", "y"]);
        let items: Value = serde_json::json!({"items": ["x", "y"]});
        let indices: Value = serde_json::json!({"1": "y", "0": "x"});
        for v in [&a, &items, &indices] {
            let l = lista(v);
            assert_eq!(l.len(), 2);
            assert_eq!(l[0], "x");
        }
        assert_eq!(lista(&serde_json::json!("*")).len(), 1);
    }
}
