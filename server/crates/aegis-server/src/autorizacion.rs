//! Autorizacion de la API: RBAC por ruta y aislamiento por inquilino (H-03,
//! FASE 6.2 del MP-16).
//!
//! # Que habia
//!
//! `aegis-consola` tenia la tabla de roles (`rbac::puede`) y la sesion ligada a
//! un inquilino (`inquilino::Sesion`), y el servidor no enlazaba ninguna de las
//! dos: cualquier sesion valida aislaba la flota, publicaba politica o leia los
//! casos de cualquier cliente, y el inquilino era un parametro de consulta que
//! elegia el propio cliente (`?inquilino=`).
//!
//! # Que hay
//!
//! Una sola tabla, [`REGLAS`], clasifica CADA par metodo-ruta que declara
//! `api::declarar()` con:
//!
//! - el **permiso** de `aegis_consola::rbac` que exige, y
//! - su **alcance** ([`Alcance`]): de quien son los datos que toca.
//!
//! La capa de sesion de la API (`api::exigir_sesion`) llama a [`autorizar`]
//! DESPUES de validar la sesion y ANTES del manejador. Una ruta sin fila en la
//! tabla se deniega (falla cerrada), y la prueba `tests/rbac_matriz.rs` exige
//! que la tabla y la declaracion de rutas sean el mismo conjunto: una ruta nueva
//! sin clasificar hace fallar `make ci`.
//!
//! # El inquilino
//!
//! El inquilino de un agente es una funcion pura de su CN autenticado por mTLS
//! ([`inquilino_de_cn`]), la misma que guarda el enrolamiento en
//! `agentes.id_flota`. El de un operador lo fija el alta (`operadores.inquilino`)
//! y viaja en la sesion: el cliente no lo elige.
//!
//! Hay un inquilino reservado, [`INQUILINO_PLATAFORMA`], para quien gestiona el
//! contenido GLOBAL del producto (reglas, heuristicas, politica, reputacion,
//! cuarentena de enjambre): lo que una sesion de cliente cambiara ahi afectaria
//! a los agentes de los demas clientes. Una sesion de plataforma no ve los datos
//! de ningun cliente: no hay inquilino comodin (doctrina de
//! `aegis_consola::inquilino`).
//!
//! Las rutas cuyo listado todavia no se filtra por inquilino (STIX, grafos,
//! correlaciones, remediaciones, cuarentena) son de alcance
//! [`Alcance::Plataforma`]: cerradas a los clientes hasta que existan sus
//! versiones por inquilino. Es la opcion que no fuga: un 403 honesto en vez de
//! una lista con datos ajenos.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sqlx::PgPool;

pub use aegis_consola::rbac::{puede, Permiso, Rol};

use crate::error::Resultado;

/// Inquilino reservado para la gestion del contenido global del producto.
///
/// No puede coincidir con el de ningun agente: esos empiezan por `flota-`
/// ([`inquilino_de_cn`]).
pub const INQUILINO_PLATAFORMA: &str = "plataforma";

/// Bytes maximos del texto de una caza. El analizador acota la profundidad y
/// las listas, no la longitud: sin esto, el limite seria el del cuerpo HTTP
/// (1 MiB) por cada caza persistida y difundida.
pub const MAX_CONSULTA_BYTES: usize = 4096;

/// Cazas abiertas a la vez por inquilino. Cada una se difunde a todos los
/// agentes del inquilino: mil cazas simultaneas son mil ejecuciones por
/// endpoint.
pub const MAX_CAZAS_ABIERTAS: i64 = 16;

/// Inquilino de un agente a partir de su CN autenticado.
///
/// Es la regla del enrolamiento (`ServicioFlota::enrolar` la usa para
/// `agentes.id_flota`): el ultimo tramo del CN separado por puntos.
pub fn inquilino_de_cn(cn: &str) -> String {
    format!("flota-{}", cn.split('.').next_back().unwrap_or("principal"))
}

/// Rol a partir de su nombre estable.
pub fn rol_de_nombre(nombre: &str) -> Option<Rol> {
    Rol::todos().into_iter().find(|r| r.nombre() == nombre)
}

/// La sesion de un operador: quien es, de que inquilino y con que rol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SesionOperador {
    /// Usuario.
    pub usuario: String,
    /// Rol (`aegis_consola::rbac`).
    pub rol: Rol,
    /// Inquilino. Todo lo que la sesion ve y toca se acota a este.
    pub inquilino: String,
}

impl SesionOperador {
    /// La sesion como objeto JSON, para guardarla en Redis.
    pub fn json(&self) -> String {
        serde_json::json!({
            "usuario": self.usuario,
            "rol": self.rol.nombre(),
            "inquilino": self.inquilino,
        })
        .to_string()
    }

    /// Lee una sesion guardada. Un valor que no sea una sesion completa (las
    /// de antes de esta fase guardaban solo el usuario) no es una sesion.
    pub fn desde_json(texto: &str) -> Option<SesionOperador> {
        let v: serde_json::Value = serde_json::from_str(texto).ok()?;
        Some(SesionOperador {
            usuario: v.get("usuario")?.as_str()?.to_string(),
            rol: rol_de_nombre(v.get("rol")?.as_str()?)?,
            inquilino: v.get("inquilino")?.as_str()?.to_string(),
        })
    }

    /// Si es una sesion de la plataforma.
    pub fn es_plataforma(&self) -> bool {
        self.inquilino == INQUILINO_PLATAFORMA
    }

    /// Si puede ver lo de un agente.
    pub fn ve_cn(&self, cn: &str) -> bool {
        inquilino_de_cn(cn) == self.inquilino
    }
}

/// De quien son los datos que toca una ruta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alcance {
    /// Sin sesion (`RUTAS_PUBLICAS` de la API).
    Publica,
    /// Solo exige sesion (cerrar la propia).
    Sesion,
    /// Contenido global de solo lectura, sin datos de ningun cliente.
    Global,
    /// Datos del inquilino de la sesion: el manejador filtra por el.
    Inquilino,
    /// Contenido global que se ESCRIBE, o listados aun sin filtrar por
    /// inquilino: solo sesiones de [`INQUILINO_PLATAFORMA`].
    Plataforma,
    /// Un agente concreto (`{cn}`): solo si es del inquilino de la sesion.
    Agente,
    /// Un caso concreto (`{id}`): solo si `casos.inquilino` es el de la sesion.
    Caso,
    /// Una caza concreta (`{id}`): solo si `cacerias.inquilino` es el de la
    /// sesion.
    Caza,
}

impl Alcance {
    /// Nombre estable, para la matriz.
    pub fn nombre(self) -> &'static str {
        match self {
            Alcance::Publica => "publica",
            Alcance::Sesion => "sesion",
            Alcance::Global => "global",
            Alcance::Inquilino => "inquilino",
            Alcance::Plataforma => "plataforma",
            Alcance::Agente => "agente-del-inquilino",
            Alcance::Caso => "caso-del-inquilino",
            Alcance::Caza => "caza-del-inquilino",
        }
    }
}

/// La clasificacion de un par metodo-ruta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regla {
    /// Metodo HTTP, en mayusculas.
    pub metodo: &'static str,
    /// Patron tal y como lo casa axum.
    pub patron: &'static str,
    /// Permiso que exige; `None` en las publicas y en cerrar la propia sesion.
    pub permiso: Option<Permiso>,
    /// De quien son los datos.
    pub alcance: Alcance,
}

const fn r(
    metodo: &'static str,
    patron: &'static str,
    permiso: Option<Permiso>,
    alcance: Alcance,
) -> Regla {
    Regla {
        metodo,
        patron,
        permiso,
        alcance,
    }
}

use Alcance as A;
use Permiso as P;

/// LA tabla. Un par metodo-ruta por fila, el mismo conjunto que declara
/// `api::declarar()` (lo exige `tests/rbac_matriz.rs`).
///
/// Notas de clasificacion que no son obvias:
///
/// - `GET /api/agentes/{cn}/comando` CONSUME el comando pendiente: es una
///   escritura con verbo de lectura, y exige `Contener`.
/// - `GET /api/cuarentena` acepta `?levantar=<ip>`, que LEVANTA una cuarentena:
///   otra escritura con verbo de lectura, y exige `Contener` (hallazgo H-41 de
///   esta fase; el arreglo de raiz es moverlo a un POST).
/// - La ingesta ITDR dispara playbooks de contencion: exige `Contener`.
/// - La cuarentena de enjambre corta una IP en TODA la flota, de todos los
///   clientes: es de plataforma aunque la ruta lleve el CN de un agente.
pub const REGLAS: &[Regla] = &[
    r("GET", "/salud", None, A::Publica),
    r("POST", "/api/sesion", None, A::Publica),
    r("DELETE", "/api/sesion", None, A::Sesion),
    // Inventario y alertas
    r("GET", "/api/resumen", Some(P::Leer), A::Inquilino),
    r("GET", "/api/agentes", Some(P::Leer), A::Inquilino),
    r("GET", "/api/agentes/{cn}", Some(P::Leer), A::Agente),
    r(
        "GET",
        "/api/agentes/{cn}/comando",
        Some(P::Contener),
        A::Agente,
    ),
    r("GET", "/api/alertas", Some(P::Leer), A::Inquilino),
    r("GET", "/api/agentes/{cn}/alertas", Some(P::Leer), A::Agente),
    // Respuesta de un clic
    r(
        "POST",
        "/api/agentes/{cn}/aislar",
        Some(P::Contener),
        A::Agente,
    ),
    r(
        "POST",
        "/api/agentes/{cn}/liberar",
        Some(P::Contener),
        A::Agente,
    ),
    // Politica global y motor de reglas
    r(
        "POST",
        "/api/politicas",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    r("GET", "/api/reglas", Some(P::Leer), A::Global),
    r(
        "POST",
        "/api/reglas",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    r(
        "DELETE",
        "/api/reglas/{id}",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    r(
        "POST",
        "/api/reglas/{id}/activa",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    // Inteligencia y linaje (aun sin filtrar por inquilino)
    r("GET", "/api/stix/objetos", Some(P::Leer), A::Plataforma),
    r("GET", "/api/grafos", Some(P::Leer), A::Plataforma),
    r("GET", "/api/grafos/{id}", Some(P::Leer), A::Plataforma),
    // Casos
    r("GET", "/api/casos", Some(P::Leer), A::Inquilino),
    r("GET", "/api/casos/{id}", Some(P::Leer), A::Caso),
    r(
        "POST",
        "/api/casos/{id}/estado",
        Some(P::TrabajarCaso),
        A::Caso,
    ),
    r(
        "POST",
        "/api/casos/{id}/cerrar",
        Some(P::TrabajarCaso),
        A::Caso,
    ),
    r(
        "POST",
        "/api/casos/{id}/tareas",
        Some(P::TrabajarCaso),
        A::Caso,
    ),
    r(
        "POST",
        "/api/casos/{id}/tareas/{tarea}/cerrar",
        Some(P::TrabajarCaso),
        A::Caso,
    ),
    r("GET", "/api/casos/{id}/auditoria", Some(P::Leer), A::Caso),
    r(
        "GET",
        "/api/casos/{id}/auditoria/verificar",
        Some(P::Leer),
        A::Caso,
    ),
    r(
        "POST",
        "/api/casos/{id}/auditoria/anclar",
        Some(P::TrabajarCaso),
        A::Caso,
    ),
    r("GET", "/api/soc/metricas", Some(P::Leer), A::Inquilino),
    // Caceria AegisQL
    r("GET", "/api/cacerias", Some(P::Leer), A::Inquilino),
    r("POST", "/api/cacerias", Some(P::LanzarCaza), A::Inquilino),
    r("GET", "/api/cacerias/{id}", Some(P::Leer), A::Caza),
    r(
        "POST",
        "/api/cacerias/{id}/cerrar",
        Some(P::LanzarCaza),
        A::Caza,
    ),
    r("GET", "/api/aegisql/esquema", Some(P::Leer), A::Global),
    // Cuarentena de enjambre: corta una IP en toda la flota
    r("GET", "/api/cuarentena", Some(P::Contener), A::Plataforma),
    r("POST", "/api/cuarentena", Some(P::Contener), A::Plataforma),
    r(
        "POST",
        "/api/agentes/{cn}/cuarentena",
        Some(P::Contener),
        A::Plataforma,
    ),
    r(
        "GET",
        "/api/cuarentena/difusion",
        Some(P::Leer),
        A::Plataforma,
    ),
    // Respuesta automatica
    r(
        "POST",
        "/api/agentes/{cn}/itdr/telemetria",
        Some(P::Contener),
        A::Agente,
    ),
    r("GET", "/api/remediaciones", Some(P::Leer), A::Plataforma),
    // Heuristicas y correlaciones
    r("GET", "/api/heuristicas", Some(P::Leer), A::Global),
    r(
        "POST",
        "/api/heuristicas",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    r(
        "POST",
        "/api/heuristicas/{id}/activa",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
    r("GET", "/api/correlaciones", Some(P::Leer), A::Plataforma),
    r(
        "GET",
        "/api/correlaciones/{id}",
        Some(P::Leer),
        A::Plataforma,
    ),
    r(
        "POST",
        "/api/correlaciones/{id}/cerrar",
        Some(P::TrabajarCaso),
        A::Plataforma,
    ),
    // Tiempo real (filtrado por inquilino en el manejador)
    r("GET", "/api/ws", Some(P::Leer), A::Inquilino),
    // Reputacion k-anonima
    r("GET", "/api/reputacion/{prefijo}", Some(P::Leer), A::Global),
    r(
        "POST",
        "/api/reputacion",
        Some(P::GestionarDeteccion),
        A::Plataforma,
    ),
];

/// La regla de un par metodo-ruta, si esta clasificado.
pub fn regla_de(metodo: &str, patron: &str) -> Option<&'static Regla> {
    REGLAS
        .iter()
        .find(|r| r.metodo == metodo && r.patron == patron)
}

/// Por que se deniega.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denegacion {
    /// 403: la ruta no esta clasificada (falla cerrada).
    SinClasificar,
    /// 403: el rol no tiene el permiso.
    Rol(Rol, Permiso),
    /// 403: contenido de plataforma pedido por una sesion de cliente.
    SoloPlataforma,
    /// 404: el recurso no es del inquilino de la sesion. Se responde como si
    /// no existiera, para no confirmar que existe en otro cliente.
    Ajeno,
}

impl Denegacion {
    /// La respuesta HTTP.
    pub fn respuesta(&self) -> axum::response::Response {
        let (codigo, motivo) = match self {
            Denegacion::SinClasificar => (
                StatusCode::FORBIDDEN,
                "ruta sin clasificar en la tabla de autorizacion".to_string(),
            ),
            Denegacion::Rol(rol, permiso) => (
                StatusCode::FORBIDDEN,
                aegis_consola::rbac::Denegado {
                    rol: *rol,
                    permiso: *permiso,
                }
                .motivo(),
            ),
            Denegacion::SoloPlataforma => (
                StatusCode::FORBIDDEN,
                "contenido de la plataforma: solo para sesiones del inquilino de plataforma"
                    .to_string(),
            ),
            Denegacion::Ajeno => (StatusCode::NOT_FOUND, "no existe".to_string()),
        };
        (codigo, Json(serde_json::json!({ "error": motivo }))).into_response()
    }
}

/// La parte PURA de la decision: rol y plataforma. No mira recursos.
///
/// Es la que recorre la matriz: `permitido_por_rol(rol, regla)` es la celda.
pub fn decidir(sesion: &SesionOperador, regla: &Regla) -> Result<(), Denegacion> {
    if let Some(p) = regla.permiso {
        if !puede(sesion.rol, p) {
            return Err(Denegacion::Rol(sesion.rol, p));
        }
    }
    if regla.alcance == Alcance::Plataforma && !sesion.es_plataforma() {
        return Err(Denegacion::SoloPlataforma);
    }
    Ok(())
}

/// Si el RBAC deja a `rol` usar la ruta (sin mirar el inquilino).
pub fn permitido_por_rol(rol: Rol, regla: &Regla) -> bool {
    regla.permiso.is_none_or(|p| puede(rol, p))
}

/// Autoriza una peticion con sesion valida. `parametros` son los de la ruta,
/// ya decodificados (`RawPathParams`).
///
/// Orden: clasificacion, rol, plataforma y, solo si todo eso pasa, propiedad
/// del recurso. Asi un rol sin permiso recibe 403 aunque el recurso sea ajeno,
/// y la matriz RBAC no depende de que los recursos existan.
///
/// # Errors
///
/// [`Denegacion`] con su respuesta; un fallo de la base de datos al comprobar
/// la propiedad se trata como recurso ajeno (falla cerrada) y se registra.
pub async fn autorizar(
    pool: &PgPool,
    sesion: &SesionOperador,
    metodo: &str,
    patron: &str,
    parametros: &[(String, String)],
) -> Result<(), Denegacion> {
    let Some(regla) = regla_de(metodo, patron) else {
        tracing::error!(metodo, patron, "ruta sin clasificar: se deniega");
        return Err(Denegacion::SinClasificar);
    };
    decidir(sesion, regla)?;
    let parametro = |nombre: &str| {
        parametros
            .iter()
            .find(|(k, _)| k == nombre)
            .map(|(_, v)| v.as_str())
    };
    match regla.alcance {
        Alcance::Agente => match parametro("cn") {
            Some(cn) if sesion.ve_cn(cn) => Ok(()),
            _ => Err(Denegacion::Ajeno),
        },
        Alcance::Caso => {
            let Some(id) = parametro("id") else {
                return Err(Denegacion::Ajeno);
            };
            propio(crate::inquilino::propietario_caso(pool, id).await, sesion)
        }
        Alcance::Caza => {
            let Some(id) = parametro("id").and_then(|i| uuid::Uuid::parse_str(i).ok()) else {
                return Err(Denegacion::Ajeno);
            };
            propio(crate::inquilino::propietario_caza(pool, id).await, sesion)
        }
        Alcance::Publica
        | Alcance::Sesion
        | Alcance::Global
        | Alcance::Inquilino
        | Alcance::Plataforma => Ok(()),
    }
}

fn propio(dueno: Resultado<Option<String>>, sesion: &SesionOperador) -> Result<(), Denegacion> {
    match dueno {
        Ok(Some(i)) if i == sesion.inquilino => Ok(()),
        Ok(_) => Err(Denegacion::Ajeno),
        Err(e) => {
            tracing::error!(error = %e, "no se pudo comprobar el dueno del recurso: se deniega");
            Err(Denegacion::Ajeno)
        }
    }
}

/// Si un evento del bus del panel puede salir por el tiempo real de `sesion`.
///
/// El bus es UNO para todo el plano de control. Un evento que lleva el CN de un
/// agente sale solo hacia las consolas de su inquilino; uno sin CN (politica
/// publicada, caza lanzada, correlacion) es contenido de flota y sale solo
/// hacia las de plataforma: el texto de una caza ajena tambien es un dato del
/// otro cliente.
pub fn evento_visible(sesion: &SesionOperador, evento: &crate::eventos::EventoPanel) -> bool {
    let valor = serde_json::to_value(evento).ok();
    match valor
        .as_ref()
        .and_then(|v| v.get("cn"))
        .and_then(|c| c.as_str())
    {
        Some(cn) => sesion.ve_cn(cn),
        None => sesion.es_plataforma(),
    }
}

// ---------------------------------------------------------------------------
// La matriz, generada desde la tabla
// ---------------------------------------------------------------------------

/// Una celda de la matriz rol x ruta x metodo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Celda {
    /// Rol.
    pub rol: Rol,
    /// La regla de la ruta.
    pub regla: Regla,
    /// Si el RBAC lo permite (antes de mirar inquilino y plataforma).
    pub permitido: bool,
}

/// La matriz entera, en el orden de [`REGLAS`] y de `Rol::todos()`.
pub fn matriz() -> Vec<Celda> {
    let mut v = Vec::with_capacity(REGLAS.len() * 4);
    for regla in REGLAS {
        for rol in Rol::todos() {
            v.push(Celda {
                rol,
                regla: *regla,
                permitido: permitido_por_rol(rol, regla),
            });
        }
    }
    v
}

/// La matriz en Markdown: `docs/generado/matriz-rbac.md`.
///
/// La genera el codigo y la compara `tests/rbac_matriz.rs`; con
/// `AEGIS_REGENERAR=1` la prueba la reescribe.
pub fn matriz_markdown() -> String {
    let mut s = String::new();
    s.push_str("# Matriz RBAC de la API del plano de control\n\n");
    s.push_str(
        "> GENERADO por `aegis_server::autorizacion::matriz_markdown` (no editar a mano).\n\
         > Lo comprueba `server/crates/aegis-server/tests/rbac_matriz.rs`, que ademas RECORRE\n\
         > cada celda contra el servidor real. Regenerar: `AEGIS_REGENERAR=1 cargo test -p\n\
         > aegis-server --test rbac_matriz`.\n\n",
    );
    s.push_str(
        "`si` = el rol tiene el permiso. Las rutas de alcance `plataforma` exigen ademas una\n\
         sesion del inquilino `plataforma`; las de alcance `*-del-inquilino` responden 404 si el\n\
         recurso es de otro inquilino.\n\n",
    );
    let roles = Rol::todos();
    s.push_str("| Metodo | Ruta | Permiso | Alcance |");
    for rol in roles {
        s.push_str(&format!(" {} |", rol.nombre()));
    }
    s.push('\n');
    s.push_str("|---|---|---|---|");
    for _ in roles {
        s.push_str("---|");
    }
    s.push('\n');
    for regla in REGLAS {
        s.push_str(&format!(
            "| {} | `{}` | {} | {} |",
            regla.metodo,
            regla.patron,
            regla.permiso.map_or("-", |p| p.nombre()),
            regla.alcance.nombre()
        ));
        for rol in roles {
            s.push_str(if permitido_por_rol(rol, regla) {
                " si |"
            } else {
                " no |"
            });
        }
        s.push('\n');
    }
    let permitidas = matriz().iter().filter(|c| c.permitido).count();
    s.push_str(&format!(
        "\n{} rutas x {} roles = {} celdas; {} permitidas por rol.\n",
        REGLAS.len(),
        roles.len(),
        REGLAS.len() * roles.len(),
        permitidas
    ));
    s
}

// ---------------------------------------------------------------------------
// Operadores: rol e inquilino
// ---------------------------------------------------------------------------

/// Rol e inquilino de un operador activo.
///
/// # Errors
///
/// Fallo de la base de datos. Un rol desconocido en la tabla (no deberia: hay
/// un CHECK) se trata como operador sin rol.
pub async fn operador(pool: &PgPool, usuario: &str) -> Resultado<Option<(Rol, String)>> {
    let fila: Option<(String, String)> =
        sqlx::query_as("SELECT rol, inquilino FROM operadores WHERE usuario = $1 AND activo")
            .bind(usuario)
            .fetch_optional(pool)
            .await?;
    Ok(fila.and_then(|(rol, inq)| rol_de_nombre(&rol).map(|r| (r, inq))))
}

/// Asigna rol e inquilino a un operador existente. Devuelve si existia.
///
/// # Errors
///
/// Fallo de la base de datos, o inquilino vacio.
pub async fn asignar_rol(
    pool: &PgPool,
    usuario: &str,
    rol: Rol,
    inquilino: &str,
) -> Resultado<bool> {
    if inquilino.trim().is_empty() || inquilino.len() > 128 {
        return Err(crate::error::ErrorServidor::Config(
            "el inquilino no puede estar vacio ni pasar de 128 bytes".to_string(),
        ));
    }
    let r = sqlx::query("UPDATE operadores SET rol = $2, inquilino = $3 WHERE usuario = $1")
        .bind(usuario)
        .bind(rol.nombre())
        .bind(inquilino.trim())
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Coste maximo de una caza que puede lanzar un rol (H-25).
///
/// `Peligroso` no se lanza nunca desde el plano de control: su coste no esta
/// acotado por el tamano de la tabla. El analista llega a `Medio`; quien
/// responde del turno, a `Caro`.
pub fn coste_maximo_de(rol: Rol) -> aegis_parser::esquema::Coste {
    use aegis_parser::esquema::Coste;
    match rol {
        Rol::Responsable | Rol::Administrador => Coste::Caro,
        Rol::Analista | Rol::Auditor => Coste::Medio,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn sesion(rol: Rol, inq: &str) -> SesionOperador {
        SesionOperador {
            usuario: "ana".into(),
            rol,
            inquilino: inq.into(),
        }
    }

    #[test]
    fn el_inquilino_del_cn_es_el_del_enrolamiento() {
        assert_eq!(inquilino_de_cn("pc-1.cliente-a"), "flota-cliente-a");
        assert_eq!(inquilino_de_cn("sin-punto"), "flota-sin-punto");
        assert_ne!(inquilino_de_cn("x.plataforma"), INQUILINO_PLATAFORMA);
    }

    #[test]
    fn la_sesion_va_y_vuelve_y_un_valor_viejo_no_es_sesion() {
        let s = sesion(Rol::Responsable, "flota-a");
        assert_eq!(SesionOperador::desde_json(&s.json()), Some(s));
        assert_eq!(SesionOperador::desde_json("operador@empresa"), None);
        assert_eq!(
            SesionOperador::desde_json(r#"{"usuario":"a","rol":"dios","inquilino":"x"}"#),
            None
        );
    }

    #[test]
    fn la_tabla_no_repite_ninguna_ruta() {
        let mut vistas = std::collections::HashSet::new();
        for r in REGLAS {
            assert!(
                vistas.insert((r.metodo, r.patron)),
                "{} {} repetida",
                r.metodo,
                r.patron
            );
        }
    }

    #[test]
    fn el_rol_se_mira_antes_que_la_plataforma() {
        let regla = regla_de("POST", "/api/reglas").unwrap();
        assert_eq!(
            decidir(&sesion(Rol::Auditor, INQUILINO_PLATAFORMA), regla),
            Err(Denegacion::Rol(Rol::Auditor, Permiso::GestionarDeteccion))
        );
        assert_eq!(
            decidir(&sesion(Rol::Administrador, "flota-a"), regla),
            Err(Denegacion::SoloPlataforma)
        );
        assert!(decidir(&sesion(Rol::Administrador, INQUILINO_PLATAFORMA), regla).is_ok());
    }

    #[test]
    fn la_matriz_tiene_una_celda_por_rol_y_ruta() {
        assert_eq!(matriz().len(), REGLAS.len() * Rol::todos().len());
        let md = matriz_markdown();
        assert_eq!(md.matches("\n| ").count(), REGLAS.len() + 1);
    }
}
