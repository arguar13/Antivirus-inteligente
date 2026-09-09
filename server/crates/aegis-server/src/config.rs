//! Configuracion del plano de control, tomada del entorno.
//!
//! Nada de credenciales en ficheros del repositorio: la cadena de conexion a la
//! base de datos y las direcciones de escucha vienen del entorno, que es lo que
//! un despliegue real (systemd, Kubernetes, Terraform) sabe inyectar sin dejar
//! secretos en disco.

use std::net::SocketAddr;
use std::time::Duration;

/// Configuracion completa del servidor.
#[derive(Debug, Clone)]
pub struct Config {
    /// Cadena de conexion de PostgreSQL.
    pub pg_url: String,
    /// Cadena de conexion de Redis.
    pub redis_url: String,
    /// Direccion de la API REST del panel.
    pub api_addr: SocketAddr,
    /// Direccion de la superficie gRPC estandar (HTTP/2).
    pub grpc_addr: SocketAddr,
    /// Direccion del transporte nativo de la flota (mTLS crudo).
    pub flota_addr: String,
    /// Intervalo de latido que se entrega a los agentes al enrolarse.
    pub intervalo_latido: Duration,
    /// Margen tras el cual un agente sin latidos se considera caido.
    pub margen_desconexion: Duration,
    /// Tamano maximo del pool de PostgreSQL.
    pub pg_max_conexiones: u32,
    /// Directorio donde vive el material de la CA de la flota.
    pub ca_dir: std::path::PathBuf,
}

/// Lee una variable de entorno o devuelve el valor por defecto.
fn var(clave: &str, defecto: &str) -> String {
    std::env::var(clave).unwrap_or_else(|_| defecto.to_string())
}

impl Config {
    /// Construye la configuracion desde el entorno.
    ///
    /// Los valores por defecto apuntan a una instalacion local de desarrollo;
    /// en produccion los inyecta el despliegue.
    pub fn desde_entorno() -> Result<Config, crate::error::ErrorServidor> {
        let api_addr = var("AEGIS_API_ADDR", "127.0.0.1:8080");
        let grpc_addr = var("AEGIS_GRPC_ADDR", "127.0.0.1:50051");

        Ok(Config {
            pg_url: var(
                "AEGIS_PG_URL",
                "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis",
            ),
            redis_url: var("AEGIS_REDIS_URL", "redis://127.0.0.1:6379"),
            api_addr: api_addr.parse().map_err(|_| {
                crate::error::ErrorServidor::Config(format!("AEGIS_API_ADDR invalida: {api_addr}"))
            })?,
            grpc_addr: grpc_addr.parse().map_err(|_| {
                crate::error::ErrorServidor::Config(format!(
                    "AEGIS_GRPC_ADDR invalida: {grpc_addr}"
                ))
            })?,
            flota_addr: var("AEGIS_FLEET_ADDR", "127.0.0.1:8443"),
            intervalo_latido: Duration::from_secs(
                var("AEGIS_INTERVALO_LATIDO_SEG", "30")
                    .parse()
                    .unwrap_or(30),
            ),
            // Tres latidos perdidos antes de dar por caido a un endpoint: uno
            // solo seria demasiado sensible a una perdida de paquetes.
            margen_desconexion: Duration::from_secs(
                var("AEGIS_MARGEN_DESCONEXION_SEG", "90")
                    .parse()
                    .unwrap_or(90),
            ),
            pg_max_conexiones: var("AEGIS_PG_MAX_CONEXIONES", "32").parse().unwrap_or(32),
            // La CA de la flota se persiste: si se regenerase en cada arranque,
            // todos los certificados emitidos dejarian de validar y la flota
            // entera quedaria fuera al primer reinicio del servicio.
            ca_dir: std::path::PathBuf::from(var("AEGIS_CA_DIR", "/var/lib/aegis/ca")),
        })
    }
}
