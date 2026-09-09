//! Servidor de control sobre un socket Unix.
//!
//! El agente escucha en un socket Unix y responde a las peticiones de
//! `aegisctl`. El socket se crea con permisos **0600**: el canal de control de
//! un EDR es una via para escanear, aislar la red y consultar la cuarentena, y
//! esa via no puede quedar abierta a cualquier usuario del sistema. Es el mismo
//! criterio que con los mapas eBPF: lo que controla el EDR lo controla root.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::protocol::{Request, Response};

/// Quien atiende las peticiones de control.
///
/// Es un rasgo para que el servidor se pruebe con un manejador de prueba, sin
/// levantar el agente entero, y para que el manejador real viva junto a los
/// subsistemas que usa (escaneo, respuesta) sin que el servidor dependa de
/// ellos.
pub trait ControlHandler: Send + Sync {
    /// Atiende una peticion y produce una respuesta.
    fn handle(&self, req: Request) -> Response;
}

/// Error del servidor de control.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Error de E/S al crear o usar el socket.
    #[error("error de E/S en el socket de control: {0}")]
    Io(#[from] std::io::Error),
}

/// Servidor de control ligado a una ruta de socket.
pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlServer {
    /// Crea el socket en `path`, sustituyendo uno anterior si existe.
    ///
    /// Un socket huerfano de una ejecucion anterior impediria el `bind`; se
    /// borra primero. El fichero queda en 0600 en cuanto se crea.
    pub fn bind(path: impl AsRef<Path>) -> Result<ControlServer, ServerError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Un socket previo bloquea el bind aunque no lo escuche nadie.
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path)?;
        // 0600: solo el propietario (root, el agente) puede conectarse. Se pone
        // DESPUES del bind, que es cuando el fichero existe.
        set_socket_perms(&path)?;
        Ok(ControlServer { listener, path })
    }

    /// Ruta del socket.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Acepta y atiende peticiones hasta que `parar` se activa.
    ///
    /// Cada conexion es una peticion y una respuesta. El bucle no lanza hilos:
    /// el volumen es de una peticion humana ocasional, y un manejador secuencial
    /// no puede sufrir contencion ni condiciones de carrera. Un cliente lento no
    /// bloquea al agente porque el socket tiene plazo de lectura.
    pub fn serve<H: ControlHandler>(&self, handler: &H, parar: &Arc<AtomicBool>) {
        // El accept no bloquea indefinidamente: se pone en no bloqueante y se
        // sondea la bandera de parada, para que el hilo de control termine
        // limpio cuando el agente se apaga.
        let _ = self.listener.set_nonblocking(true);
        while !parar.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((flujo, _)) => {
                    let _ = atender(flujo, handler);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }

    /// Atiende UNA sola peticion (bloqueante). Util para pruebas.
    pub fn serve_one<H: ControlHandler>(&self, handler: &H) -> Result<(), ServerError> {
        let _ = self.listener.set_nonblocking(false);
        let (flujo, _) = self.listener.accept()?;
        atender(flujo, handler)?;
        Ok(())
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // El socket es un fichero: se retira al cerrar para no dejar huerfanos.
        let _ = std::fs::remove_file(&self.path);
    }
}

fn atender<H: ControlHandler>(mut flujo: UnixStream, handler: &H) -> Result<(), ServerError> {
    flujo.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    flujo.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    // La peticion es una sola linea; se lee hasta el primer salto de linea sin
    // tragar cantidades arbitrarias de datos de un cliente hostil.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match flujo.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
                // Una ruta larguisima es un abuso; se acota la peticion.
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let linea = String::from_utf8_lossy(&buf);
    let respuesta = match Request::parse(&linea) {
        Ok(req) => handler.handle(req),
        Err(e) => Response::Error(e.to_string()),
    };
    let _ = flujo.write_all(respuesta.encode().as_bytes());
    let _ = flujo.flush();
    Ok(())
}

fn set_socket_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Cliente de control.
pub struct ControlClient;

impl ControlClient {
    /// Envia una peticion y devuelve la respuesta.
    ///
    /// Abre una conexion nueva por peticion, que es lo que espera el servidor.
    /// El plazo evita que un agente colgado deje a `aegisctl` esperando para
    /// siempre.
    pub fn request(path: impl AsRef<Path>, req: &Request) -> Result<Response, ServerError> {
        let mut flujo = UnixStream::connect(path.as_ref())?;
        flujo.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        flujo.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

        let mut linea = req.encode();
        linea.push('\n');
        flujo.write_all(linea.as_bytes())?;
        flujo.flush()?;
        // El servidor cierra al terminar; se lee hasta el fin de flujo.
        let mut respuesta = String::new();
        flujo.read_to_string(&mut respuesta)?;
        Response::parse(&respuesta).map_err(|_| {
            ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "respuesta de control ininteligible",
            ))
        })
    }
}
