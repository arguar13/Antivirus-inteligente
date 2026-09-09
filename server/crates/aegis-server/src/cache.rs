//! Cache en Redis: sesiones del panel y reputacion k-anonima.
//!
//! # Por que la reputacion es k-anonima
//!
//! Consultar la reputacion de un fichero es, sin cuidado, una fuga de
//! privacidad: si el agente envia el hash completo de cada binario que ve, el
//! plano de control acaba con el inventario exacto del software —y de los
//! documentos— de cada endpoint del cliente. Un EDR no deberia saber eso.
//!
//! Aqui el agente envia solo un PREFIJO del hash y el servidor devuelve TODOS
//! los veredictos conocidos de ese cubo; el agente busca el suyo en local. El
//! servidor sabe que alguien pregunto por un cubo de miles de hashes posibles,
//! no por cual. Es el mismo principio del "k-anonymity" de las bases de
//! contrasenas filtradas.

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::error::Resultado;

/// Longitud del prefijo de hash que forma un cubo k-anonimo.
///
/// Cinco caracteres hexadecimales son 20 bits: mas de un millon de cubos. Con
/// un corpus grande cada cubo agrupa suficientes hashes para que la consulta no
/// identifique un fichero, y sigue siendo lo bastante estrecho para que la
/// respuesta quepa en un mensaje pequeno.
pub const LONGITUD_PREFIJO: usize = 5;

/// Tiempo de vida de una entrada de reputacion.
const TTL_REPUTACION_SEG: u64 = 3600;

/// Tiempo de vida de una sesion del panel.
const TTL_SESION_SEG: u64 = 8 * 3600;

/// Cliente de cache.
#[derive(Clone)]
pub struct Cache {
    conexion: ConnectionManager,
}

/// Veredicto de reputacion de un artefacto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Veredicto {
    /// Conocido y benigno.
    Limpio,
    /// Conocido y malicioso.
    Malicioso,
    /// Visto, sin veredicto firme.
    Sospechoso,
}

impl Veredicto {
    /// Representacion corta para la cache.
    fn como_str(self) -> &'static str {
        match self {
            Veredicto::Limpio => "limpio",
            Veredicto::Malicioso => "malicioso",
            Veredicto::Sospechoso => "sospechoso",
        }
    }

    /// Veredicto a partir de su representacion corta.
    fn de_str(s: &str) -> Option<Veredicto> {
        match s {
            "limpio" => Some(Veredicto::Limpio),
            "malicioso" => Some(Veredicto::Malicioso),
            "sospechoso" => Some(Veredicto::Sospechoso),
            _ => None,
        }
    }
}

impl Cache {
    /// Conecta a Redis con un gestor que reconecta solo.
    ///
    /// `ConnectionManager` reintenta y restablece la conexion por su cuenta: si
    /// Redis se reinicia, el plano de control no se queda sin cache hasta que
    /// alguien lo reinicie a mano.
    pub async fn conectar(url: &str) -> Resultado<Cache> {
        let cliente = redis::Client::open(url)?;
        let conexion = ConnectionManager::new(cliente).await?;
        Ok(Cache { conexion })
    }

    /// Comprueba que la cache responde.
    pub async fn ping(&self) -> Resultado<()> {
        let mut c = self.conexion.clone();
        let _: String = redis::cmd("PING").query_async(&mut c).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reputacion k-anonima
    // -----------------------------------------------------------------------

    /// Clave del cubo de un prefijo.
    fn clave_cubo(prefijo: &str) -> String {
        format!("rep:{prefijo}")
    }

    /// Registra el veredicto de un hash completo en su cubo.
    ///
    /// Se guarda el SUFIJO como campo del hash de Redis: junto al prefijo de la
    /// clave reconstruye el hash completo, sin almacenarlo entero en ningun
    /// sitio donde una consulta pueda enumerarlo.
    pub async fn registrar_reputacion(&self, hash_hex: &str, v: Veredicto) -> Resultado<()> {
        if hash_hex.len() <= LONGITUD_PREFIJO {
            return Ok(());
        }
        let (prefijo, sufijo) = hash_hex.split_at(LONGITUD_PREFIJO);
        let clave = Self::clave_cubo(prefijo);
        let mut c = self.conexion.clone();
        let _: () = c.hset(&clave, sufijo, v.como_str()).await?;
        let _: () = c.expire(&clave, TTL_REPUTACION_SEG as i64).await?;
        Ok(())
    }

    /// Devuelve todos los veredictos del cubo de un prefijo.
    ///
    /// El agente recibe el cubo entero y busca su hash en local: el servidor
    /// nunca llega a saber cual de los miles de hashes posibles le interesaba.
    pub async fn consultar_cubo(&self, prefijo: &str) -> Resultado<Vec<(String, Veredicto)>> {
        let mut c = self.conexion.clone();
        let mapa: std::collections::HashMap<String, String> =
            c.hgetall(Self::clave_cubo(prefijo)).await?;
        Ok(mapa
            .into_iter()
            .filter_map(|(sufijo, v)| Veredicto::de_str(&v).map(|v| (sufijo, v)))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Sesiones del panel
    // -----------------------------------------------------------------------

    /// Clave de una sesion.
    fn clave_sesion(token: &str) -> String {
        format!("sesion:{token}")
    }

    /// Abre una sesion para un administrador y devuelve su token.
    pub async fn abrir_sesion(&self, usuario: &str) -> Resultado<String> {
        // El token es aleatorio de 256 bits: no deriva del usuario ni del
        // tiempo, asi que no se puede adivinar a partir de otra sesion.
        let token =
            uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
        let mut c = self.conexion.clone();
        let _: () = c
            .set_ex(Self::clave_sesion(&token), usuario, TTL_SESION_SEG)
            .await?;
        Ok(token)
    }

    /// Devuelve el usuario de una sesion viva, si lo hay.
    pub async fn usuario_de_sesion(&self, token: &str) -> Resultado<Option<String>> {
        let mut c = self.conexion.clone();
        let usuario: Option<String> = c.get(Self::clave_sesion(token)).await?;
        Ok(usuario)
    }

    /// Cierra una sesion.
    pub async fn cerrar_sesion(&self, token: &str) -> Resultado<bool> {
        let mut c = self.conexion.clone();
        let borradas: i64 = c.del(Self::clave_sesion(token)).await?;
        Ok(borradas > 0)
    }
}
