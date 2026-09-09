//! Custodia del informe en el registro de auditoria cifrado.
//!
//! # Por que no un fichero suelto
//!
//! Un informe forense en un `.json` del disco es exactamente lo que el atacante
//! borra cuando descubre que lo han detectado, y ademas contiene lo mas sensible
//! de la maquina: rutas, lineas de comandos —que a veces llevan credenciales— y
//! con quien hablaba el proceso. El registro de auditoria de AegisCore lo guarda
//! **cifrado con AES-256-GCM**, con el identificador de fila ligado al cifrado,
//! de modo que ni se puede leer sin la clave ni se pueden reordenar o sustituir
//! filas sin que se note.
//!
//! # El informe se recorta si no cabe
//!
//! Un incidente con un arbol enorme produce un bundle de megabytes. Guardarlo
//! entero desplazaria del registro, por rotacion, a los eventos anteriores —que
//! son justo el contexto del incidente—. Cuando el bundle pasa del limite se
//! guarda una version reducida, y el hecho de haberla reducido **queda escrito
//! en el propio evento**: un informe recortado en silencio se lee como un
//! incidente pequeno.

use aegis_audit::{AuditError, AuditEvent, AuditLogger, Severity};

use crate::artifacts::IncidentArtifacts;
use crate::stix;

/// Clase de evento con la que se registra un informe forense.
pub const KIND: &str = "forensics.incident";

/// Clase de evento de un informe que hubo que recortar.
pub const KIND_TRUNCADO: &str = "forensics.incident.truncated";

/// Tamano maximo del bundle que se guarda entero.
///
/// 256 KB entran de sobra para el arbol de un incidente real y dejan sitio en
/// el segmento activo para el resto de la telemetria.
pub const MAX_BUNDLE: usize = 256 * 1024;

/// Guarda el informe en el registro y devuelve el identificador de fila.
///
/// La gravedad es siempre la maxima: se recoge un informe forense porque algo
/// ya se ha decidido que es un incidente, y degradar su gravedad en el registro
/// haria que una consulta por gravedad se lo saltara.
pub fn store(
    logger: &mut AuditLogger,
    a: &IncidentArtifacts,
    ts_ns: u64,
) -> Result<i64, AuditError> {
    let bundle = stix::to_bundle(a);
    guardar(logger, a, ts_ns, bundle)
}

/// Igual que [`store`], con el bundle ya serializado.
///
/// Sirve para guardar exactamente el mismo documento que se envio a otra
/// plataforma, sin volver a generarlo —los UUID de los objetos de dominio son
/// aleatorios y una segunda serializacion daria otros—.
pub fn store_bundle(
    logger: &mut AuditLogger,
    a: &IncidentArtifacts,
    ts_ns: u64,
    bundle: String,
) -> Result<i64, AuditError> {
    guardar(logger, a, ts_ns, bundle)
}

fn guardar(
    logger: &mut AuditLogger,
    a: &IncidentArtifacts,
    ts_ns: u64,
    bundle: String,
) -> Result<i64, AuditError> {
    let (kind, detalle) = if bundle.len() <= MAX_BUNDLE {
        (KIND, bundle)
    } else {
        (KIND_TRUNCADO, resumen(a, bundle.len()))
    };

    let ev = AuditEvent::new(ts_ns, Severity::Critical, kind)
        .with_actor(a.root_pid as u64)
        .with_detail(detalle);
    logger.log(&ev)
}

/// Version reducida para cuando el bundle no cabe.
///
/// Conserva lo que permite seguir investigando —identificador, disparador,
/// hashes y extremos remotos— y dice explicitamente cuanto se perdio.
fn resumen(a: &IncidentArtifacts, tamano_original: usize) -> String {
    use crate::json::Obj;

    let hashes: Vec<String> = a
        .processes
        .iter()
        .filter_map(|p| p.sha256.clone())
        .collect();
    let remotos: Vec<String> = a
        .connected_sockets()
        .map(|s| s.remote.to_string())
        .collect();

    let mut o = Obj::new();
    o.str("type", "x-aegis-incident-summary")
        .str("id", &a.id)
        .str("collected_at", &a.collected_at)
        .num("root_pid", a.root_pid as u64)
        .str("trigger_source", &a.trigger.source)
        .str("trigger_reason", &a.trigger.reason)
        .num("processes", a.processes.len() as u64)
        .num("sockets", a.sockets.len() as u64)
        .str_array("sha256", &hashes)
        .str_array("remote_endpoints", &remotos)
        .str_array("techniques", &a.trigger.techniques)
        .num("original_bundle_bytes", tamano_original as u64)
        .bool("truncated", true);
    o.finish()
}
