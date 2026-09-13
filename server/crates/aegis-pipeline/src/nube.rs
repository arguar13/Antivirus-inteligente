//! Registros de nube: CloudTrail, Azure Activity y GCP Audit.
//!
//! # Por que esto vive en el plano de control y no en el agente
//!
//! Un registro de nube no lo produce ninguna maquina del cliente: lo produce el
//! proveedor y lo deja en un cubo de S3, en un Event Hub o en un tema de
//! Pub/Sub. No hay endpoint del que leerlo. Ponerlo en el agente obligaria a
//! elegir un endpoint arbitrario para hacerlo, y ese endpoint tendria
//! credenciales de la nube entera: exactamente el activo que un atacante busca
//! en un endpoint.
//!
//! # Lo que estos registros tienen y la telemetria de endpoint no
//!
//! **El plano de control de la nube es el sitio donde se pierde una empresa
//! entera sin tocar un solo servidor.** Robar una clave, crearse un usuario,
//! darle permisos y apagar la auditoria son cuatro llamadas a una API; ninguna
//! deja rastro en ningun endpoint. Por eso el catalogo de aqui no es decorativo:
//! `StopLogging` y `DeleteTrail` son el equivalente exacto de borrar el registro
//! de sucesos de Windows, y se clasifican igual de alto.
//!
//! # Entrada hostil, tambien aqui
//!
//! El cuerpo de un registro de nube incluye campos que **el atacante controla**:
//! el nombre del recurso que creo, el agente de usuario con el que llamo, los
//! parametros de la peticion. Todo lo que entra lleva tope, y ningun campo se
//! usa para reservar memoria.

use std::collections::BTreeMap;

use aegis_ingest::esquema::{
    confianza, recortar, Clase, Evento, Origen, Resultado as ResultadoEvento, Severidad, Valor,
    MAX_CAMPO, MAX_CAMPOS, MAX_MENSAJE, VERSION,
};
use aegis_ingest::tiempo::desde_rfc3339;
use serde_json::Value;

/// Bytes maximos de un documento de nube.
///
/// Un registro de CloudTrail con `requestParameters` grandes llega a decenas de
/// kilobytes; medio mega es holgado y sigue siendo un tope.
pub const MAX_DOCUMENTO: usize = 512 * 1024;

/// Registros maximos en un lote.
pub const MAX_LOTE: usize = 10_000;

/// Profundidad maxima al aplanar un objeto anidado.
///
/// El JSON de un proveedor de nube anida poco, pero lo escribe en parte quien
/// llama a la API. Sin tope, un objeto de mil niveles agota la pila.
pub const MAX_PROFUNDIDAD: usize = 8;

/// De que nube viene.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proveedor {
    /// AWS CloudTrail.
    Aws,
    /// Azure Activity Log.
    Azure,
    /// Google Cloud Audit Logs.
    Gcp,
}

impl Proveedor {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Proveedor::Aws => "aws",
            Proveedor::Azure => "azure",
            Proveedor::Gcp => "gcp",
        }
    }
}

/// Contexto de la ingesta de nube.
#[derive(Debug, Clone)]
pub struct Contexto {
    /// Inquilino al que pertenece.
    pub inquilino: String,
    /// Cuando se leyo, en nanosegundos Unix.
    pub observado_ns: u64,
    /// Si se conserva el documento original.
    pub conservar_crudo: bool,
}

/// Descubre el proveedor mirando el documento.
///
/// Se mira la **forma** y no un campo de configuracion: un cliente que encamine
/// mal un cubo de S3 hacia el conector de Azure produciria eventos vacios sin un
/// solo error, y nadie lo notaria hasta la primera investigacion.
#[must_use]
pub fn proveedor_de(v: &Value) -> Option<Proveedor> {
    if v.get("eventVersion").is_some() || v.get("eventSource").is_some() {
        return Some(Proveedor::Aws);
    }
    if v.get("protoPayload").is_some() {
        return Some(Proveedor::Gcp);
    }
    if v.get("operationName").is_some() && v.get("category").is_some() {
        return Some(Proveedor::Azure);
    }
    None
}

/// Analiza un documento que puede contener uno o varios registros.
///
/// CloudTrail entrega `{"Records":[...]}`; Azure y GCP entregan un registro por
/// linea o un vector. Los tres casos se admiten porque los tres se dan.
pub fn analizar_lote(bytes: &[u8], ctx: &Contexto) -> Vec<Evento> {
    if bytes.len() > MAX_DOCUMENTO {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        // Podria ser JSON delimitado por lineas, que es como llegan los de GCP
        // y Azure por Event Hub.
        return analizar_lineas(bytes, ctx);
    };
    let mut salida = Vec::new();
    if let Some(records) = v.get("Records").and_then(Value::as_array) {
        for r in records.iter().take(MAX_LOTE) {
            if let Some(e) = analizar(r, ctx) {
                salida.push(e);
            }
        }
        return salida;
    }
    if let Some(records) = v.get("records").and_then(Value::as_array) {
        for r in records.iter().take(MAX_LOTE) {
            if let Some(e) = analizar(r, ctx) {
                salida.push(e);
            }
        }
        return salida;
    }
    if let Some(vec) = v.as_array() {
        for r in vec.iter().take(MAX_LOTE) {
            if let Some(e) = analizar(r, ctx) {
                salida.push(e);
            }
        }
        return salida;
    }
    if let Some(e) = analizar(&v, ctx) {
        salida.push(e);
    }
    salida
}

fn analizar_lineas(bytes: &[u8], ctx: &Contexto) -> Vec<Evento> {
    let mut salida = Vec::new();
    for linea in bytes.split(|b| *b == b'\n').take(MAX_LOTE) {
        if linea.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(linea) {
            if let Some(e) = analizar(&v, ctx) {
                salida.push(e);
            }
        }
    }
    salida
}

/// Analiza un registro suelto.
#[must_use]
pub fn analizar(v: &Value, ctx: &Contexto) -> Option<Evento> {
    match proveedor_de(v)? {
        Proveedor::Aws => Some(cloudtrail(v, ctx)),
        Proveedor::Azure => Some(azure(v, ctx)),
        Proveedor::Gcp => Some(gcp(v, ctx)),
    }
}

// --- AWS CloudTrail ---------------------------------------------------------

fn cloudtrail(v: &Value, ctx: &Contexto) -> Evento {
    let accion = texto(v, "eventName");
    let servicio = texto(v, "eventSource");
    let error = texto(v, "errorCode");
    let resultado = if error.is_empty() {
        ResultadoEvento::Exito
    } else {
        ResultadoEvento::Fallo
    };

    let mut campos = BTreeMap::new();
    poner(&mut campos, "nube.proveedor", "aws");
    poner(&mut campos, "nube.servicio", &servicio);
    poner(&mut campos, "nube.accion", &accion);
    poner(&mut campos, "nube.region", &texto(v, "awsRegion"));
    poner(&mut campos, "ip_origen", &texto(v, "sourceIPAddress"));
    poner(&mut campos, "agente", &texto(v, "userAgent"));
    poner(&mut campos, "nube.error", &error);
    poner(&mut campos, "nube.mensaje_error", &texto(v, "errorMessage"));
    poner(&mut campos, "nube.evento_id", &texto(v, "eventID"));

    let identidad = v.get("userIdentity");
    let usuario = identidad
        .map(|i| {
            let n = texto(i, "userName");
            if n.is_empty() {
                texto(i, "arn")
            } else {
                n
            }
        })
        .unwrap_or_default();
    poner(&mut campos, "usuario", &usuario);
    if let Some(i) = identidad {
        poner(&mut campos, "nube.identidad_tipo", &texto(i, "type"));
        poner(&mut campos, "nube.cuenta", &texto(i, "accountId"));
        // La clave de acceso usada importa: si aparece una que nadie reconoce,
        // eso es la clave robada.
        poner(&mut campos, "nube.clave_acceso", &texto(i, "accessKeyId"));
        if let Some(s) = i.get("sessionContext").and_then(|s| s.get("sessionIssuer")) {
            poner(&mut campos, "nube.rol", &texto(s, "userName"));
        }
    }
    // Los parametros los escribe quien llama: entran aplanados y con tope.
    if let Some(p) = v.get("requestParameters") {
        aplanar(p, "nube.parametros", &mut campos, 0);
    }

    let conocido = catalogo::aws(&accion);
    let (clase, severidad) = clase_y_gravedad(conocido, resultado, &accion);
    montar(
        ctx,
        v,
        desde_rfc3339(&texto(v, "eventTime")),
        clase,
        resultado,
        severidad,
        &servicio,
        &format!("{accion} en {servicio}"),
        campos,
    )
}

// --- Azure Activity ---------------------------------------------------------

fn azure(v: &Value, ctx: &Contexto) -> Evento {
    let accion = texto(v, "operationName");
    let estado = texto(v, "resultType");
    let resultado = match estado.to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "accepted" => ResultadoEvento::Exito,
        "" => ResultadoEvento::Desconocido,
        _ => ResultadoEvento::Fallo,
    };

    let mut campos = BTreeMap::new();
    poner(&mut campos, "nube.proveedor", "azure");
    poner(&mut campos, "nube.accion", &accion);
    poner(&mut campos, "nube.categoria", &texto(v, "category"));
    poner(&mut campos, "nube.recurso", &texto(v, "resourceId"));
    poner(&mut campos, "ip_origen", &texto(v, "callerIpAddress"));
    poner(&mut campos, "nube.correlacion", &texto(v, "correlationId"));
    poner(&mut campos, "nube.resultado", &estado);

    let usuario = v
        .get("identity")
        .and_then(|i| i.get("claims"))
        .map(|c| {
            for clave in [
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                "name",
                "upn",
                "appid",
            ] {
                let t = texto(c, clave);
                if !t.is_empty() {
                    return t;
                }
            }
            String::new()
        })
        .unwrap_or_default();
    poner(&mut campos, "usuario", &usuario);

    let conocido = catalogo::azure(&accion);
    let (clase, severidad) = clase_y_gravedad(conocido, resultado, &accion);
    let servicio = accion.split('/').next().unwrap_or("azure").to_string();
    montar(
        ctx,
        v,
        desde_rfc3339(&texto(v, "time")),
        clase,
        resultado,
        severidad,
        &servicio,
        &format!("{accion} ({estado})"),
        campos,
    )
}

// --- GCP Audit --------------------------------------------------------------

fn gcp(v: &Value, ctx: &Contexto) -> Evento {
    let carga = v.get("protoPayload").unwrap_or(&Value::Null);
    let accion = texto(carga, "methodName");
    let servicio = texto(carga, "serviceName");
    // GCP pone `status` vacio cuando fue bien y con `code` cuando no.
    let codigo = carga
        .get("status")
        .and_then(|s| s.get("code"))
        .and_then(Value::as_i64);
    let resultado = match codigo {
        None | Some(0) => ResultadoEvento::Exito,
        Some(_) => ResultadoEvento::Fallo,
    };

    let mut campos = BTreeMap::new();
    poner(&mut campos, "nube.proveedor", "gcp");
    poner(&mut campos, "nube.servicio", &servicio);
    poner(&mut campos, "nube.accion", &accion);
    poner(&mut campos, "nube.recurso", &texto(carga, "resourceName"));
    poner(&mut campos, "nube.evento_id", &texto(v, "insertId"));
    if let Some(a) = carga.get("authenticationInfo") {
        poner(&mut campos, "usuario", &texto(a, "principalEmail"));
    }
    if let Some(m) = carga.get("requestMetadata") {
        poner(&mut campos, "ip_origen", &texto(m, "callerIp"));
        poner(&mut campos, "agente", &texto(m, "callerSuppliedUserAgent"));
    }
    if let Some(s) = carga.get("status") {
        poner(&mut campos, "nube.mensaje_error", &texto(s, "message"));
    }
    if let Some(n) = codigo {
        campos.insert("nube.codigo".into(), Valor::Entero(n));
    }

    let conocido = catalogo::gcp(&accion);
    let (clase, severidad) = clase_y_gravedad(conocido, resultado, &accion);
    montar(
        ctx,
        v,
        desde_rfc3339(&texto(v, "timestamp")),
        clase,
        resultado,
        severidad,
        &servicio,
        &format!("{accion} en {servicio}"),
        campos,
    )
}

// --- Comun ------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn montar(
    ctx: &Contexto,
    v: &Value,
    hora: Option<u64>,
    clase: Clase,
    resultado: ResultadoEvento,
    severidad: Severidad,
    productor: &str,
    mensaje: &str,
    campos: BTreeMap<String, Valor>,
) -> Evento {
    let (ocurrio_ns, reloj) = confianza(hora, ctx.observado_ns);
    // EL ANCLA DE UN REGISTRO DE NUBE. Los tres proveedores dan un
    // identificador unico por evento —`eventID`, `correlationId`, `insertId`— y
    // es exactamente lo que hace falta: los tres reentregan, y sin ancla propia
    // un reintento del conector duplicaria el evento en el panel.
    let ancla = ["eventID", "insertId", "correlationId", "id"]
        .iter()
        .map(|k| texto(v, k))
        .find(|t| !t.is_empty())
        .map_or_else(
            || format!("nube:{}:{}", productor, ocurrio_ns),
            |id| format!("nube:{id}"),
        );

    let mut e = Evento {
        version: VERSION,
        id: String::new(),
        ancla: recortar(&ancla, MAX_CAMPO),
        ocurrio_ns,
        observado_ns: ctx.observado_ns,
        reloj,
        clase,
        resultado,
        severidad,
        origen: Origen::Nube,
        // La «maquina» de un registro de nube es el servicio: no hay anfitrion.
        // Poner el del recolector seria atribuir a una maquina del cliente algo
        // que no paso en ella.
        anfitrion: recortar(productor, 255),
        inquilino: ctx.inquilino.clone(),
        productor: recortar(productor, 255),
        mensaje: recortar(mensaje, MAX_MENSAJE),
        campos,
        crudo: ctx
            .conservar_crudo
            .then(|| serde_json::to_vec(v).unwrap_or_default()),
    };
    e.sellar();
    e
}

/// Decide clase y gravedad con el catalogo y, si no lo conoce, con heuristicas
/// que se declaran.
fn clase_y_gravedad(
    conocido: Option<catalogo::Conocido>,
    resultado: ResultadoEvento,
    accion: &str,
) -> (Clase, Severidad) {
    if let Some(c) = conocido {
        // Un fallo en una accion de riesgo sube: alguien lo intento y no pudo,
        // que es tan interesante como que lo consiguiera.
        let s = if resultado == ResultadoEvento::Fallo && c.severidad >= Severidad::Alta {
            Severidad::Alta
        } else {
            c.severidad
        };
        return (c.clase, s);
    }
    // Sin catalogo: todo lo que no sea de lectura merece al menos verse. Los
    // nombres de accion de los tres proveedores empiezan por el verbo, asi que
    // esta heuristica es fiable y barata, y se declara como heuristica.
    let bajo = accion.to_ascii_lowercase();
    let solo_lectura = ["get", "list", "describe", "read", "head"]
        .iter()
        .any(|p| bajo.contains(p));
    (
        Clase::ApiDeNube,
        if solo_lectura {
            Severidad::Info
        } else {
            Severidad::Baja
        },
    )
}

fn texto(v: &Value, clave: &str) -> String {
    match v.get(clave) {
        Some(Value::String(s)) => recortar(s, MAX_CAMPO),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn poner(campos: &mut BTreeMap<String, Valor>, clave: &str, valor: &str) {
    if valor.is_empty() || campos.len() >= MAX_CAMPOS {
        return;
    }
    campos.insert(clave.to_string(), Valor::Texto(recortar(valor, MAX_CAMPO)));
}

/// Aplana un objeto anidado a `prefijo.clave`, con tope de profundidad.
fn aplanar(v: &Value, prefijo: &str, campos: &mut BTreeMap<String, Valor>, profundidad: usize) {
    if profundidad > MAX_PROFUNDIDAD || campos.len() >= MAX_CAMPOS {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if campos.len() >= MAX_CAMPOS {
                    return;
                }
                aplanar(x, &format!("{prefijo}.{k}"), campos, profundidad + 1);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(32) {
                aplanar(x, &format!("{prefijo}.{i}"), campos, profundidad + 1);
            }
        }
        Value::String(s) => poner(campos, prefijo, s),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                campos.insert(recortar(prefijo, MAX_CAMPO), Valor::Entero(i));
            }
        }
        Value::Bool(b) => {
            campos.insert(recortar(prefijo, MAX_CAMPO), Valor::Booleano(*b));
        }
        Value::Null => {}
    }
}

/// Las acciones de nube que importan.
pub mod catalogo {
    use super::{Clase, Severidad};

    /// Lo que se sabe de una accion.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Conocido {
        /// Clase del esquema.
        pub clase: Clase,
        /// Gravedad.
        pub severidad: Severidad,
    }

    const fn c(clase: Clase, severidad: Severidad) -> Conocido {
        Conocido { clase, severidad }
    }

    /// Acciones de AWS.
    #[must_use]
    pub fn aws(accion: &str) -> Option<Conocido> {
        use Clase::*;
        use Severidad::*;
        Some(match accion {
            // Apagar la auditoria es el equivalente exacto de borrar el registro
            // de sucesos de Windows. Es lo primero que hace quien sabe lo que
            // hace, y por eso va en critica.
            "StopLogging" | "DeleteTrail" | "PutEventSelectors" => c(HallazgoDeSeguridad, Critica),
            "DeleteFlowLogs" | "DeleteConfigRule" | "StopConfigurationRecorder" => {
                c(HallazgoDeSeguridad, Critica)
            }
            "ConsoleLogin" => c(Autenticacion, Media),
            "AssumeRole" | "AssumeRoleWithSAML" | "AssumeRoleWithWebIdentity" => {
                c(Autenticacion, Media)
            }
            "GetSessionToken" | "GetFederationToken" => c(Autenticacion, Media),
            "CreateUser" | "CreateRole" | "CreateLoginProfile" => c(GestionDeCuentas, Alta),
            "DeleteUser" | "DeleteRole" => c(GestionDeCuentas, Alta),
            "CreateAccessKey" | "UpdateAccessKey" => c(GestionDeCuentas, Critica),
            "AttachUserPolicy"
            | "AttachRolePolicy"
            | "PutUserPolicy"
            | "PutRolePolicy"
            | "AttachGroupPolicy"
            | "CreatePolicyVersion" => c(GestionDeCuentas, Critica),
            "AddUserToGroup" => c(GestionDeCuentas, Alta),
            "DeactivateMFADevice" | "DeleteVirtualMFADevice" => c(GestionDeCuentas, Critica),
            "PutBucketPolicy" | "PutBucketAcl" | "DeleteBucketPolicy" => {
                c(ActividadDeConfiguracion, Alta)
            }
            "PutBucketPublicAccessBlock" | "DeletePublicAccessBlock" => {
                c(ActividadDeConfiguracion, Critica)
            }
            "AuthorizeSecurityGroupIngress" | "ModifyInstanceAttribute" => {
                c(ActividadDeConfiguracion, Alta)
            }
            "RunInstances" | "TerminateInstances" => c(ActividadDeProceso, Media),
            "CreateFunction" | "UpdateFunctionCode" | "InvokeFunction" => {
                c(ActividadDeProceso, Media)
            }
            "GetSecretValue" | "Decrypt" | "GetParameter" => c(ActividadDeConfiguracion, Media),
            "ScheduleKeyDeletion" | "DisableKey" => c(HallazgoDeSeguridad, Critica),
            _ => return None,
        })
    }

    /// Operaciones de Azure.
    #[must_use]
    pub fn azure(accion: &str) -> Option<Conocido> {
        use Clase::*;
        use Severidad::*;
        let a = accion.to_ascii_uppercase();
        Some(match a.as_str() {
            x if x.contains("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE") => {
                c(GestionDeCuentas, Critica)
            }
            x if x.contains("MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE") => {
                c(GestionDeCuentas, Critica)
            }
            x if x.contains("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE") => {
                c(HallazgoDeSeguridad, Critica)
            }
            x if x.contains("MICROSOFT.KEYVAULT/VAULTS/SECRETS") => {
                c(ActividadDeConfiguracion, Alta)
            }
            x if x.contains("MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES") => {
                c(GestionDeCuentas, Critica)
            }
            x if x.contains("MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND") => {
                c(ActividadDeProceso, Critica)
            }
            x if x.contains("MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE") => {
                c(ActividadDeProceso, Alta)
            }
            x if x.contains("MICROSOFT.NETWORK/NETWORKSECURITYGROUPS") && x.ends_with("/WRITE") => {
                c(ActividadDeConfiguracion, Alta)
            }
            x if x.contains("MICROSOFT.AAD") || x.contains("SIGNIN") => c(Autenticacion, Media),
            x if x.ends_with("/DELETE") => c(ActividadDeConfiguracion, Media),
            x if x.ends_with("/WRITE") => c(ActividadDeConfiguracion, Baja),
            _ => return None,
        })
    }

    /// Metodos de GCP.
    #[must_use]
    pub fn gcp(accion: &str) -> Option<Conocido> {
        use Clase::*;
        use Severidad::*;
        Some(match accion {
            x if x.contains("SetIamPolicy") => c(GestionDeCuentas, Critica),
            x if x.contains("serviceAccounts.keys.create") => c(GestionDeCuentas, Critica),
            x if x.contains("serviceAccounts.create") => c(GestionDeCuentas, Alta),
            x if x.contains("logging.sinks.delete") || x.contains("logging.buckets.delete") => {
                c(HallazgoDeSeguridad, Critica)
            }
            x if x.contains("cryptoKeyVersions.destroy") => c(HallazgoDeSeguridad, Critica),
            x if x.contains("instances.insert") || x.contains("instances.delete") => {
                c(ActividadDeProceso, Media)
            }
            x if x.contains("firewalls.insert") || x.contains("firewalls.patch") => {
                c(ActividadDeConfiguracion, Alta)
            }
            x if x.contains("buckets.setIamPolicy") => c(ActividadDeConfiguracion, Critica),
            x if x.contains("secrets.versions.access") => c(ActividadDeConfiguracion, Media),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto {
            inquilino: "cliente-1".into(),
            observado_ns: 1_700_000_000_000_000_000,
            conservar_crudo: true,
        }
    }

    // Los documentos de estas pruebas estan copiados de la forma real que
    // publican los tres proveedores.

    const CLOUDTRAIL: &str = r#"{
      "Records": [{
        "eventVersion": "1.08",
        "userIdentity": {
          "type": "IAMUser",
          "principalId": "AIDAEXAMPLE",
          "arn": "arn:aws:iam::123456789012:user/atacante",
          "accountId": "123456789012",
          "accessKeyId": "AKIAEXAMPLE",
          "userName": "atacante"
        },
        "eventTime": "2023-10-11T22:14:15Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "203.0.113.9",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {"name": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/principal"},
        "eventID": "abcd-1234-efgh-5678"
      }]
    }"#;

    #[test]
    fn apagar_cloudtrail_es_critico_y_sale_con_quien_lo_hizo() {
        // Es el equivalente exacto de borrar el registro de sucesos de Windows,
        // y es lo primero que hace quien sabe lo que hace.
        let eventos = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx());
        assert_eq!(eventos.len(), 1);
        let e = &eventos[0];
        assert_eq!(e.clase, Clase::HallazgoDeSeguridad);
        assert_eq!(e.severidad, Severidad::Critica);
        assert_eq!(e.resultado, ResultadoEvento::Exito);
        assert_eq!(e.campos["usuario"], Valor::Texto("atacante".into()));
        assert_eq!(e.campos["ip_origen"], Valor::Texto("203.0.113.9".into()));
        assert_eq!(
            e.campos["nube.clave_acceso"],
            Valor::Texto("AKIAEXAMPLE".into())
        );
        assert_eq!(e.origen, Origen::Nube);
        assert!(e.sello_valido());
    }

    #[test]
    fn el_ancla_de_nube_sale_del_identificador_del_proveedor() {
        // Los tres reentregan; sin ancla propia, un reintento del conector
        // duplicaria el evento en el panel.
        let a = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        let b = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        assert_eq!(a.ancla, "nube:abcd-1234-efgh-5678");
        assert_eq!(a.id, b.id, "el mismo registro reentregado se desduplica");
    }

    #[test]
    fn un_fallo_de_una_accion_de_riesgo_sigue_pesando() {
        // Alguien lo intento y no pudo, que es tan interesante como que lo
        // consiguiera.
        let doc = r#"{"eventVersion":"1.08","eventName":"CreateAccessKey",
            "eventSource":"iam.amazonaws.com","eventTime":"2023-10-11T22:14:15Z",
            "errorCode":"AccessDenied","errorMessage":"no puedes",
            "sourceIPAddress":"1.2.3.4","eventID":"x1"}"#;
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.resultado, ResultadoEvento::Fallo);
        assert!(e.severidad >= Severidad::Alta);
        assert_eq!(e.campos["nube.error"], Valor::Texto("AccessDenied".into()));
    }

    #[test]
    fn una_accion_de_solo_lectura_no_hace_ruido() {
        let doc = r#"{"eventVersion":"1.08","eventName":"DescribeInstances",
            "eventSource":"ec2.amazonaws.com","eventTime":"2023-10-11T22:14:15Z","eventID":"x2"}"#;
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.severidad, Severidad::Info);
        assert_eq!(e.clase, Clase::ApiDeNube);
    }

    #[test]
    fn azure_se_reconoce_por_su_forma_y_no_por_la_configuracion() {
        // Un cliente que encamine mal un cubo de S3 hacia el conector de Azure
        // produciria eventos vacios sin un solo error.
        let doc = r#"{"time":"2023-10-11T22:14:15.1234567Z","category":"Administrative",
            "operationName":"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
            "resultType":"Success","callerIpAddress":"198.51.100.4",
            "correlationId":"c-1","resourceId":"/subscriptions/s1/resourceGroups/rg",
            "identity":{"claims":{"name":"admin@corp.com"}}}"#;
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.clase, Clase::GestionDeCuentas);
        assert_eq!(e.severidad, Severidad::Critica);
        assert_eq!(e.campos["usuario"], Valor::Texto("admin@corp.com".into()));
        assert_eq!(e.ancla, "nube:c-1");
    }

    #[test]
    fn gcp_se_analiza_desde_protopayload() {
        let doc = r#"{"insertId":"i-1","timestamp":"2023-10-11T22:14:15Z",
            "protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog",
              "serviceName":"iam.googleapis.com","methodName":"google.iam.admin.v1.SetIamPolicy",
              "resourceName":"projects/p1",
              "authenticationInfo":{"principalEmail":"malo@corp.com"},
              "requestMetadata":{"callerIp":"203.0.113.7","callerSuppliedUserAgent":"gcloud"},
              "status":{"code":7,"message":"PERMISSION_DENIED"}}}"#;
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.clase, Clase::GestionDeCuentas);
        assert_eq!(e.resultado, ResultadoEvento::Fallo);
        assert_eq!(e.campos["usuario"], Valor::Texto("malo@corp.com".into()));
        assert_eq!(e.campos["nube.codigo"], Valor::Entero(7));
    }

    #[test]
    fn el_json_delimitado_por_lineas_tambien_se_lee() {
        // Es como llegan los de GCP y Azure por Event Hub y Pub/Sub.
        let doc = "{\"insertId\":\"a\",\"timestamp\":\"2023-10-11T22:14:15Z\",\
                   \"protoPayload\":{\"methodName\":\"x\",\"serviceName\":\"s\"}}\n\
                   {\"insertId\":\"b\",\"timestamp\":\"2023-10-11T22:14:16Z\",\
                   \"protoPayload\":{\"methodName\":\"y\",\"serviceName\":\"s\"}}\n";
        let eventos = analizar_lote(doc.as_bytes(), &ctx());
        assert_eq!(eventos.len(), 2);
        assert_ne!(eventos[0].id, eventos[1].id);
    }

    #[test]
    fn el_anfitrion_de_un_evento_de_nube_no_es_una_maquina_del_cliente() {
        // Poner el del recolector seria atribuir a una maquina del cliente algo
        // que no paso en ella.
        let e = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.anfitrion, "cloudtrail.amazonaws.com");
    }

    #[test]
    fn la_hora_del_proveedor_manda_y_se_marca_su_confianza() {
        let e = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        assert_eq!(e.ocurrio_ns, desde_rfc3339("2023-10-11T22:14:15Z").unwrap());
        assert!(e.reloj.sirve_para_ordenar());
    }

    // --- Entrada hostil ------------------------------------------------------

    #[test]
    fn un_documento_mas_grande_que_el_tope_no_se_analiza() {
        let gordo = vec![b'x'; MAX_DOCUMENTO + 1];
        assert!(analizar_lote(&gordo, &ctx()).is_empty());
    }

    #[test]
    fn un_objeto_de_mil_niveles_no_agota_la_pila() {
        // Los parametros de la peticion los escribe quien llama a la API.
        let mut doc = String::from(
            r#"{"eventVersion":"1.08","eventName":"X","eventSource":"s","eventID":"1","requestParameters":"#,
        );
        for _ in 0..1000 {
            doc.push_str(r#"{"a":"#);
        }
        doc.push('1');
        for _ in 0..1000 {
            doc.push('}');
        }
        doc.push('}');
        // serde_json ya se niega a anidar tanto; si lo aceptara, el tope de
        // profundidad del aplanado lo para igual.
        let _ = analizar_lote(doc.as_bytes(), &ctx());
    }

    #[test]
    fn un_campo_gigante_se_recorta() {
        let largo = "a".repeat(100_000);
        let doc = format!(
            r#"{{"eventVersion":"1.08","eventName":"X","eventSource":"s","eventID":"1","userAgent":"{largo}"}}"#
        );
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert!(e.campos["agente"].texto().len() <= MAX_CAMPO);
    }

    #[test]
    fn un_documento_que_no_es_de_ninguna_nube_no_produce_eventos_vacios() {
        assert!(analizar_lote(br#"{"hola":"mundo"}"#, &ctx()).is_empty());
        assert!(analizar_lote(b"esto no es json", &ctx()).is_empty());
        assert!(analizar_lote(b"", &ctx()).is_empty());
    }

    #[test]
    fn un_lote_enorme_esta_acotado() {
        let mut doc = String::from(r#"{"Records":["#);
        for i in 0..(MAX_LOTE + 100) {
            if i > 0 {
                doc.push(',');
            }
            doc.push_str(&format!(
                r#"{{"eventVersion":"1.08","eventName":"X","eventSource":"s","eventID":"{i}"}}"#
            ));
        }
        doc.push_str("]}");
        if doc.len() <= MAX_DOCUMENTO {
            let eventos = analizar_lote(doc.as_bytes(), &ctx());
            assert!(eventos.len() <= MAX_LOTE);
        }
    }

    #[test]
    fn el_numero_de_campos_esta_acotado_aunque_los_parametros_sean_enormes() {
        let mut params = String::from("{");
        for i in 0..1000 {
            if i > 0 {
                params.push(',');
            }
            params.push_str(&format!(r#""k{i}":"v""#));
        }
        params.push('}');
        let doc = format!(
            r#"{{"eventVersion":"1.08","eventName":"X","eventSource":"s","eventID":"1","requestParameters":{params}}}"#
        );
        let e = analizar_lote(doc.as_bytes(), &ctx()).remove(0);
        assert!(e.campos.len() <= MAX_CAMPOS, "{}", e.campos.len());
    }

    #[test]
    fn la_normalizacion_de_nube_es_determinista() {
        let a = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        let b = analizar_lote(CLOUDTRAIL.as_bytes(), &ctx()).remove(0);
        assert_eq!(a, b);
    }
}
