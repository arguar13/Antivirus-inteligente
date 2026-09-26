//! AegisStore (FASE 96): el almacen de telemetria historica del plano de
//! control, indexado por entidad y consultado con el mismo AegisQL que el
//! endpoint.
//!
//! # La pregunta
//!
//! Elastic, OpenSearch y Graylog indexan DOCUMENTOS y buscan por TEXTO. Para
//! saber todo lo que paso con un proceso hay que adivinar como se escribio su
//! nombre en cada fuente y unir por cadenas, que es la heuristica que casi
//! acierta. Aqui el indice primario es la ENTIDAD del modelo unico (FASE 79):
//! buscar `proc:…` devuelve sus filas de todas las tablas —proceso, conexiones,
//! ficheros, veredictos, casos— sin una sola union por texto.
//!
//! Y el lenguaje es AegisQL, el MISMO que el analista usa contra el endpoint:
//! la misma consulta se escribe una vez y corre contra el vivo y contra el
//! historico (ver `aegis_parser::historico`).
//!
//! # Arquitectura
//!
//! - **Particion por dia** con `PARTITION BY RANGE` de PostgreSQL, y la purga es
//!   `DROP TABLE` de la particion ([`sql`]).
//! - **Segmentos columnares**: hasta [`SEGMENTO_FILAS`] filas de una tabla; cada
//!   columna se codifica por su tipo y se comprime aparte ([`codec`]), y se
//!   guarda en su propia fila, de modo que una consulta lee SOLO las columnas
//!   que usa.
//! - **Indice primario (entidad, tiempo)** y **secundarios declarados**: un
//!   indice por un campo que nadie consulta es disco tirado, asi que no hay
//!   ninguno automatico ([`Almacen::declarar_indice`]).
//! - **Coste declarado y plan rechazado** ([`plan`]): antes de leer una sola
//!   columna, el planificador cuenta particiones y segmentos, y una consulta que
//!   barreria mas de [`MAX_PARTICIONES_SIN_FILTRO`] dias sin filtro de tiempo
//!   ni de entidad NO se ejecuta, y el error dice como arreglarla.
//! - **Retencion por niveles** con su coste declarado ([`retencion`]): caliente,
//!   tibio y frio.

#![forbid(unsafe_code)]

pub mod codec;
pub mod ejecucion;
pub mod ingesta;
pub mod plan;
pub mod retencion;
pub mod sql;

use std::path::PathBuf;

use aegis_entidad::Eid;
use aegis_parser::esquema::{historico as cat, Columna, Tabla};
use aegis_parser::valor::Valor;
use sqlx::PgPool;

pub use ejecucion::Respuesta;
pub use plan::{Coste, Rechazo, Via};
pub use retencion::{InformeRetencion, Nivel, Retencion};

/// Filas de un segmento.
///
/// Ocho mil filas por columna son bastante para que el diccionario y el delta
/// rindan, y poco para que un segmento que casa con una entidad no obligue a
/// descomprimir medio dia.
pub const SEGMENTO_FILAS: usize = 8_192;

/// Particiones (dias) que una consulta puede barrer SIN filtro de tiempo ni de
/// entidad antes de rechazarse.
pub const MAX_PARTICIONES_SIN_FILTRO: usize = 7;

/// Segmentos maximos que lee una consulta, con filtro o sin el.
pub const MAX_SEGMENTOS_CONSULTA: u64 = 20_000;

/// Error del almacen.
#[derive(Debug, thiserror::Error)]
pub enum ErrorAlmacen {
    /// PostgreSQL.
    #[error("postgresql: {0}")]
    Pg(#[from] sqlx::Error),
    /// Una columna corrupta.
    #[error(transparent)]
    Codec(#[from] codec::ErrorCodec),
    /// La consulta no se entiende; lleva el error del analizador dibujado.
    #[error("{0}")]
    Consulta(String),
    /// La consulta se entiende y NO se ejecuta por su coste.
    #[error("{0}")]
    Rechazada(Box<Rechazo>),
    /// Filas que no cuadran con el esquema de su tabla.
    #[error("filas no validas para '{tabla}': {motivo}")]
    Filas {
        /// Tabla.
        tabla: String,
        /// Por que.
        motivo: String,
    },
    /// Configuracion no valida.
    #[error("configuracion: {0}")]
    Configuracion(String),
    /// Entrada y salida del nivel frio.
    #[error("nivel frio: {0}")]
    Io(#[from] std::io::Error),
}

/// Una fila que entra al almacen.
#[derive(Debug, Clone, PartialEq)]
pub struct FilaEntrada {
    /// Cuando se observo, en nanosegundos Unix.
    pub ts_ns: u64,
    /// La entidad a la que pertenece, si la tiene.
    pub entidad: Option<Eid>,
    /// Los valores, en el orden de [`columnas_guardadas`] de su tabla.
    pub valores: Vec<Valor>,
}

/// Las columnas que el almacen guarda de una tabla, en orden.
///
/// Todas las del esquema salvo las CUALIFICADAS (`network.port`,
/// `memory.entropy`): en el endpoint son cuantificadores sobre una coleccion
/// asociada que el ejecutor calcula en vivo, no un valor de la fila, y no hay
/// nada que guardar. Una consulta historica que las use se rechaza con ese
/// motivo, no se contesta vacia.
#[must_use]
pub fn columnas_guardadas(t: &Tabla) -> Vec<&'static Columna> {
    t.columnas
        .iter()
        .filter(|c| !c.nombre.contains('.'))
        .collect()
}

/// Nombre de la columna del instante y de la entidad dentro de un segmento.
pub(crate) fn columnas_de_segmento(t: &Tabla) -> Vec<(&'static str, aegis_parser::esquema::Tipo)> {
    let mut v: Vec<(&'static str, aegis_parser::esquema::Tipo)> = vec![
        (cat::TS.nombre, cat::TS.tipo),
        (cat::ENTITY.nombre, cat::ENTITY.tipo),
    ];
    v.extend(
        columnas_guardadas(t)
            .into_iter()
            .map(|c| (c.nombre, c.tipo)),
    );
    v
}

/// El almacen.
#[derive(Clone)]
pub struct Almacen {
    pub(crate) pool: PgPool,
    pub(crate) esquema: String,
    pub(crate) retencion: Retencion,
    pub(crate) dir_frio: PathBuf,
}

impl Almacen {
    /// Abre el almacen sobre un esquema de PostgreSQL, creandolo si falta.
    ///
    /// # Errors
    ///
    /// Si el esquema o la retencion no son validos, o PostgreSQL falla.
    pub async fn abrir(
        pool: PgPool,
        esquema: &str,
        retencion: Retencion,
        dir_frio: PathBuf,
    ) -> Result<Almacen, ErrorAlmacen> {
        sql::validar_esquema(esquema)?;
        retencion.validar()?;
        sql::crear(&pool, esquema).await?;
        std::fs::create_dir_all(&dir_frio)?;
        Ok(Almacen {
            pool,
            esquema: esquema.to_string(),
            retencion,
            dir_frio,
        })
    }

    /// El conjunto de conexiones.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Declara un indice secundario sobre una columna de una tabla.
    ///
    /// Solo afecta a lo que se ingiera desde ahora: un indice no se construye
    /// hacia atras en silencio, porque eso es reescribir particiones enteras sin
    /// que nadie lo haya pedido.
    ///
    /// # Errors
    ///
    /// Si la tabla o la columna no existen, o PostgreSQL falla.
    pub async fn declarar_indice(&self, tabla: &str, columna: &str) -> Result<(), ErrorAlmacen> {
        let t = cat::tabla(tabla)
            .ok_or_else(|| ErrorAlmacen::Configuracion(format!("no existe la tabla '{tabla}'")))?;
        if !columnas_guardadas(t).iter().any(|c| c.nombre == columna) {
            return Err(ErrorAlmacen::Configuracion(format!(
                "'{tabla}' no guarda la columna '{columna}'"
            )));
        }
        let s = &self.esquema;
        sqlx::query(&format!(
            "INSERT INTO {s}.declarados (tabla, columna) VALUES ($1, $2) ON CONFLICT DO NOTHING"
        ))
        .bind(tabla)
        .bind(columna)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Los indices secundarios declarados de una tabla.
    ///
    /// # Errors
    ///
    /// Si PostgreSQL falla.
    pub async fn indices_de(&self, tabla: &str) -> Result<Vec<String>, ErrorAlmacen> {
        let s = &self.esquema;
        let v: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT columna FROM {s}.declarados WHERE tabla = $1 ORDER BY columna"
        ))
        .bind(tabla)
        .fetch_all(&self.pool)
        .await?;
        Ok(v)
    }
}
