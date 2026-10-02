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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use redis::aio::{ConnectionLike, ConnectionManager};
use redis::{AsyncCommands, Cmd, Pipeline, RedisFuture, Value};

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

/// Ventana, deslizante, de la cuenta de inicios de sesion fallidos.
const VENTANA_FALLOS_SEG: u64 = 15 * 60;

/// Inicios de sesion fallidos por usuario dentro de la ventana antes de frenar.
pub const MAX_FALLOS_ACCESO: u64 = 10;

/// Cada cuanto, como mucho, se intenta rehacer una conexion caida.
const REINTENTO_RECONEXION: Duration = Duration::from_secs(1);

/// Plazo de un intento de reconexion: el que pide no espera mas que esto.
const PLAZO_RECONEXION: Duration = Duration::from_secs(2);

/// Cliente de cache.
///
/// Guarda el cliente y no solo el gestor de conexion: `ConnectionManager`
/// reintenta con un presupuesto finito y, agotado con Redis aun caido, no
/// vuelve a intentarlo. Aqui un fallo de conexion marca la cache como caida y
/// el siguiente uso rehace el gestor.
#[derive(Clone)]
pub struct Cache {
    cliente: redis::Client,
    gestor: Arc<RwLock<ConnectionManager>>,
    caida: Arc<AtomicBool>,
    ultimo_intento: Arc<Mutex<Option<Instant>>>,
}

/// La conexion que usan las operaciones: delega en el gestor y, si un comando
/// falla por la conexion, lo anota para que la cache la rehaga.
struct Vigilada {
    gestor: ConnectionManager,
    caida: Arc<AtomicBool>,
}

fn es_de_conexion(e: &redis::RedisError) -> bool {
    e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() || e.is_timeout()
}

impl ConnectionLike for Vigilada {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        Box::pin(async move {
            let r = self.gestor.req_packed_command(cmd).await;
            if let Err(e) = &r {
                if es_de_conexion(e) {
                    self.caida.store(true, Ordering::Relaxed);
                }
            }
            r
        })
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        Box::pin(async move {
            let r = self.gestor.req_packed_commands(cmd, offset, count).await;
            if let Err(e) = &r {
                if es_de_conexion(e) {
                    self.caida.store(true, Ordering::Relaxed);
                }
            }
            r
        })
    }

    fn get_db(&self) -> i64 {
        self.gestor.get_db()
    }
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
        let gestor = ConnectionManager::new(cliente.clone()).await?;
        Ok(Cache {
            cliente,
            gestor: Arc::new(RwLock::new(gestor)),
            caida: Arc::new(AtomicBool::new(false)),
            ultimo_intento: Arc::new(Mutex::new(None)),
        })
    }

    /// La conexion para una operacion; si la ultima fallo por la conexion,
    /// antes intenta rehacer el gestor (como mucho cada
    /// [`REINTENTO_RECONEXION`], y nunca mas de [`PLAZO_RECONEXION`]).
    async fn conexion(&self) -> Vigilada {
        if self.caida.load(Ordering::Relaxed) && self.toca_reintentar() {
            if let Ok(Ok(nuevo)) = tokio::time::timeout(
                PLAZO_RECONEXION,
                ConnectionManager::new(self.cliente.clone()),
            )
            .await
            {
                if let Ok(mut g) = self.gestor.write() {
                    *g = nuevo;
                }
                self.caida.store(false, Ordering::Relaxed);
                tracing::info!("cache: conexion con Redis rehecha");
            }
        }
        let gestor = self
            .gestor
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        Vigilada {
            gestor,
            caida: Arc::clone(&self.caida),
        }
    }

    /// Si ha pasado bastante desde el ultimo intento de reconexion (y lo anota).
    fn toca_reintentar(&self) -> bool {
        let Ok(mut u) = self.ultimo_intento.lock() else {
            return true;
        };
        let ahora = Instant::now();
        match *u {
            Some(t) if ahora.duration_since(t) < REINTENTO_RECONEXION => false,
            _ => {
                *u = Some(ahora);
                true
            }
        }
    }

    /// Comprueba que la cache responde.
    pub async fn ping(&self) -> Resultado<()> {
        let mut c = self.conexion().await;
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
        let mut c = self.conexion().await;
        let _: () = c.hset(&clave, sufijo, v.como_str()).await?;
        let _: () = c.expire(&clave, TTL_REPUTACION_SEG as i64).await?;
        Ok(())
    }

    /// Devuelve todos los veredictos del cubo de un prefijo.
    ///
    /// El agente recibe el cubo entero y busca su hash en local: el servidor
    /// nunca llega a saber cual de los miles de hashes posibles le interesaba.
    pub async fn consultar_cubo(&self, prefijo: &str) -> Resultado<Vec<(String, Veredicto)>> {
        let mut c = self.conexion().await;
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
        let mut c = self.conexion().await;
        let _: () = c
            .set_ex(Self::clave_sesion(&token), usuario, TTL_SESION_SEG)
            .await?;
        Ok(token)
    }

    /// Devuelve el usuario de una sesion viva, si lo hay.
    ///
    /// Desde la FASE 6.2 la sesion guarda rol e inquilino
    /// ([`crate::autorizacion::SesionOperador`]); las abiertas con
    /// [`Cache::abrir_sesion`] guardan solo el usuario. Las dos dan el usuario.
    pub async fn usuario_de_sesion(&self, token: &str) -> Resultado<Option<String>> {
        let mut c = self.conexion().await;
        let valor: Option<String> = c.get(Self::clave_sesion(token)).await?;
        Ok(valor.map(
            |v| match crate::autorizacion::SesionOperador::desde_json(&v) {
                Some(s) => s.usuario,
                None => v,
            },
        ))
    }

    /// Abre una sesion con rol e inquilino y devuelve su token (FASE 6.2).
    pub async fn abrir_sesion_operador(
        &self,
        sesion: &crate::autorizacion::SesionOperador,
    ) -> Resultado<String> {
        let token =
            uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
        let mut c = self.conexion().await;
        let _: () = c
            .set_ex(Self::clave_sesion(&token), sesion.json(), TTL_SESION_SEG)
            .await?;
        Ok(token)
    }

    /// La sesion completa, si esta viva y tiene rol e inquilino. Una sesion
    /// de solo usuario no autoriza nada en la API: hay que volver a entrar.
    pub async fn sesion_operador(
        &self,
        token: &str,
    ) -> Resultado<Option<crate::autorizacion::SesionOperador>> {
        let mut c = self.conexion().await;
        let valor: Option<String> = c.get(Self::clave_sesion(token)).await?;
        Ok(valor
            .as_deref()
            .and_then(crate::autorizacion::SesionOperador::desde_json))
    }

    /// Cierra una sesion.
    pub async fn cerrar_sesion(&self, token: &str) -> Resultado<bool> {
        let mut c = self.conexion().await;
        let borradas: i64 = c.del(Self::clave_sesion(token)).await?;
        Ok(borradas > 0)
    }

    // -----------------------------------------------------------------------
    // Freno a los inicios de sesion fallidos (H-02)
    // -----------------------------------------------------------------------

    /// Clave de la cuenta de fallos de un usuario.
    fn clave_fallos(usuario: &str) -> String {
        format!("acceso_fallos:{}", usuario.to_lowercase())
    }

    /// Fallos de inicio de sesion de `usuario` en la ventana vigente.
    pub async fn fallos_acceso(&self, usuario: &str) -> Resultado<u64> {
        let mut c = self.conexion().await;
        let n: Option<u64> = c.get(Self::clave_fallos(usuario)).await?;
        Ok(n.unwrap_or(0))
    }

    /// Cuenta un fallo y renueva la ventana, atomicamente.
    ///
    /// INCR y EXPIRE van en la misma transaccion: por separado, una caida entre
    /// los dos dejaria una cuenta sin caducidad, es decir, un bloqueo eterno.
    pub async fn contar_fallo_acceso(&self, usuario: &str) -> Resultado<u64> {
        let mut c = self.conexion().await;
        let clave = Self::clave_fallos(usuario);
        let (n, _): (u64, i64) = redis::pipe()
            .atomic()
            .incr(&clave, 1u64)
            .expire(&clave, VENTANA_FALLOS_SEG as i64)
            .query_async(&mut c)
            .await?;
        Ok(n)
    }

    /// Borra la cuenta de fallos tras un inicio de sesion correcto.
    pub async fn limpiar_fallos_acceso(&self, usuario: &str) -> Resultado<()> {
        let mut c = self.conexion().await;
        let _: i64 = c.del(Self::clave_fallos(usuario)).await?;
        Ok(())
    }
}
