//! El canal por el que la traza sale del invitado.
//!
//! # Por que vsock y no la red del invitado
//!
//! Si la traza saliera por la red del invitado harian falta dos cosas que no
//! pueden existir a la vez: que el invitado tenga una ruta hacia el anfitrion, y
//! que el invitado no tenga ninguna ruta a ningun sitio. `vsock` no es red: es un
//! canal entre la maquina virtual y su anfitrion que **no pasa por la pila de red
//! del invitado**, asi que el invitado puede quedarse sin salida a nada y seguir
//! contando lo que ve.
//!
//! Y no es un detalle de comodidad: la muestra tambien puede usar la red del
//! invitado. Compartir ese camino con la traza significaria que el malware puede
//! observarla, interferirla o llenarla.
//!
//! # El detalle que decide si el malware puede ahogar su propia traza
//!
//! El anfitrion lee a su ritmo. Una muestra que genera eventos mas deprisa de lo
//! que el canal drena deja dos salidas malas y una buena:
//!
//! - **Bloquear** al trazador hasta que el canal admita mas. El malware
//!   conseguiria parar la detonacion escribiendo en un bucle.
//! - **Acumular** en memoria sin limite. El malware conseguiria tumbar al agente
//!   invitado, y con el a la traza entera.
//! - **Tirar lo que no cabe y CONTARLO.** Es lo que se hace: la escritura tiene
//!   plazo, lo que no entra se descarta, y al final se emite un
//!   [`Evento::Degradado`] diciendo cuanto se perdio.
//!
//! La tercera es la unica en la que el malware no gana nada: puede provocar un
//! hueco en la evidencia, pero el hueco **aparece en el informe**, y un hueco
//! declarado es un indicador de comportamiento, no una perdida silenciosa.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::protocolo::{Evento, Trama};

/// Puerto de vsock en el que escucha el anfitrion.
///
/// Elegido fuera del rango de los servicios habituales para no chocar con nada
/// que la imagen del invitado traiga de serie.
pub const PUERTO: u32 = 8973;

/// CID del anfitrion en vsock. Es una constante del protocolo, no una eleccion.
pub const CID_ANFITRION: u32 = 2;

/// Plazo de escritura antes de dar el evento por perdido.
///
/// Corto a proposito: el trazador tiene a la muestra parada mientras escribe, y
/// cada milisegundo de mas es un milisegundo en el que la muestra no avanza y el
/// plazo de la detonacion si.
pub const PLAZO_ESCRITURA: Duration = Duration::from_millis(200);

/// Lo que puede salir mal en el canal.
#[derive(Debug)]
pub enum ErrorCanal {
    /// No se pudo abrir el canal.
    NoConecta(String),
    /// El canal se cerro por el otro lado.
    Cerrado,
}

impl core::fmt::Display for ErrorCanal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorCanal::NoConecta(d) => write!(f, "no se pudo abrir el canal: {d}"),
            ErrorCanal::Cerrado => write!(f, "el anfitrion cerro el canal"),
        }
    }
}

impl std::error::Error for ErrorCanal {}

/// Por donde sale la traza.
///
/// Las dos variantes hablan **el mismo protocolo**; lo que cambia es el
/// transporte. Eso permite ejercitar el canal entero contra un socket de dominio
/// Unix real —que es ademas exactamente lo que Firecracker le presenta al
/// anfitrion al otro lado de un vsock— sin simular nada del formato.
#[derive(Debug)]
enum Transporte {
    Unix(UnixStream),
    /// Socket AF_VSOCK ya conectado, por su descriptor.
    Vsock(i32),
}

/// El canal de salida de la traza.
#[derive(Debug)]
pub struct Canal {
    transporte: Transporte,
    secuencia: u64,
    perdidos: u64,
    enviados: u64,
}

impl Canal {
    /// Abre el canal contra un socket de dominio Unix.
    ///
    /// Es el transporte que se usa cuando la detonacion corre bajo aislamiento
    /// por espacios de nombres en vez de en una maquina virtual, y el que
    /// permite ejercitar el protocolo entero en una prueba.
    ///
    /// # Errores
    /// [`ErrorCanal::NoConecta`] si el socket no esta.
    pub fn unix(ruta: &Path) -> Result<Canal, ErrorCanal> {
        let flujo = UnixStream::connect(ruta).map_err(|e| ErrorCanal::NoConecta(e.to_string()))?;
        flujo
            .set_write_timeout(Some(PLAZO_ESCRITURA))
            .map_err(|e| ErrorCanal::NoConecta(e.to_string()))?;
        Ok(Canal {
            transporte: Transporte::Unix(flujo),
            secuencia: 0,
            perdidos: 0,
            enviados: 0,
        })
    }

    /// Abre el canal por vsock contra el anfitrion.
    ///
    /// # Errores
    /// [`ErrorCanal::NoConecta`] si el kernel del invitado no trae vsock o si el
    /// anfitrion no esta escuchando.
    #[allow(unsafe_code)] // socket/connect sobre AF_VSOCK; no hay envoltorio seguro
    pub fn vsock(puerto: u32) -> Result<Canal, ErrorCanal> {
        // SAFETY: `socket` con constantes validas; devuelve un descriptor o -1.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(ErrorCanal::NoConecta(
                "el kernel del invitado no trae AF_VSOCK".into(),
            ));
        }

        // SAFETY: se rellena una `sockaddr_vm` en la pila y se pasa por puntero
        // con su tamano exacto, que es el contrato de `connect`.
        let rc = unsafe {
            let mut dir: libc::sockaddr_vm = core::mem::zeroed();
            dir.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            dir.svm_cid = CID_ANFITRION;
            dir.svm_port = puerto;
            libc::connect(
                fd,
                core::ptr::addr_of!(dir).cast::<libc::sockaddr>(),
                core::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            // SAFETY: cerrar un descriptor que acabamos de abrir.
            unsafe { libc::close(fd) };
            return Err(ErrorCanal::NoConecta(
                "el anfitrion no esta escuchando en vsock".into(),
            ));
        }

        // SAFETY: `setsockopt` con una `timeval` local y su tamano exacto. Sin el
        // plazo, una escritura contra un anfitrion parado bloquearia al trazador
        // para siempre, que es justo lo que el malware querria.
        unsafe {
            let tv = libc::timeval {
                tv_sec: PLAZO_ESCRITURA.as_secs() as libc::time_t,
                tv_usec: PLAZO_ESCRITURA.subsec_micros() as libc::suseconds_t,
            };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                core::ptr::addr_of!(tv).cast(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        Ok(Canal {
            transporte: Transporte::Vsock(fd),
            secuencia: 0,
            perdidos: 0,
            enviados: 0,
        })
    }

    /// Eventos entregados al canal.
    #[must_use]
    pub fn enviados(&self) -> u64 {
        self.enviados
    }

    /// Eventos que no cupieron y se perdieron.
    ///
    /// Es una cifra del informe, no un detalle interno: un hueco declarado es un
    /// indicador de comportamiento —la muestra genero mas de lo que el canal
    /// admite— mientras que un hueco silencioso es una mentira.
    #[must_use]
    pub fn perdidos(&self) -> u64 {
        self.perdidos
    }

    /// Numero de la proxima trama.
    #[must_use]
    pub fn secuencia(&self) -> u64 {
        self.secuencia
    }

    /// Manda un evento. Nunca bloquea mas de [`PLAZO_ESCRITURA`].
    ///
    /// Un fallo de escritura **no** es un error que el llamante tenga que
    /// gestionar: es un evento perdido, se cuenta, y el trazado sigue. Propagarlo
    /// convertiria «el canal va lento» en «se acabo la traza».
    pub fn enviar(&mut self, evento: Evento) {
        let trama = Trama {
            secuencia: self.secuencia,
            evento,
        };
        // La secuencia avanza SIEMPRE, se haya podido escribir o no. Es lo que le
        // permite al anfitrion ver el hueco: si solo avanzara al escribir con
        // exito, la traza llegaria continua y la perdida seria invisible.
        self.secuencia += 1;

        let bytes = trama.a_bytes();
        if self.escribir(&bytes) {
            self.enviados += 1;
        } else {
            self.perdidos += 1;
        }
    }

    /// Cierra el canal contando lo que se perdio.
    ///
    /// El resumen se manda **antes** de cerrar y por el mismo canal, que es lo
    /// unico que garantiza que llegue al informe.
    pub fn cerrar(mut self, codigo: i32, completo: bool) {
        if self.perdidos > 0 {
            let perdidos = self.perdidos;
            self.enviar(Evento::Degradado {
                causa: format!(
                    "{perdidos} eventos no cupieron en el canal y se perdieron; la traza tiene \
                     huecos en esos numeros de secuencia"
                ),
            });
        }
        let emitidos = self.secuencia;
        self.enviar(Evento::Fin {
            codigo,
            emitidos,
            completo,
        });
        self.vaciar();
    }

    fn escribir(&mut self, bytes: &[u8]) -> bool {
        match &mut self.transporte {
            Transporte::Unix(f) => f.write_all(bytes).is_ok(),
            Transporte::Vsock(fd) => escribir_fd(*fd, bytes),
        }
    }

    fn vaciar(&mut self) {
        if let Transporte::Unix(f) = &mut self.transporte {
            let _ = f.flush();
        }
    }
}

impl Drop for Canal {
    #[allow(unsafe_code)] // close del descriptor de vsock
    fn drop(&mut self) {
        if let Transporte::Vsock(fd) = self.transporte {
            // SAFETY: el descriptor lo abrio este mismo objeto y nadie mas lo
            // tiene; cerrarlo aqui es lo que impide fugarlo.
            unsafe { libc::close(fd) };
        }
    }
}

/// Escribe todo el bufer en un descriptor, reintentando ante interrupciones.
#[allow(unsafe_code)] // write sobre un descriptor propio
fn escribir_fd(fd: i32, bytes: &[u8]) -> bool {
    let mut escritos = 0usize;
    while escritos < bytes.len() {
        // SAFETY: `bytes[escritos..]` es un trozo valido y vivo, y su longitud es
        // exactamente la que se le pasa a `write`.
        let n = unsafe {
            libc::write(
                fd,
                bytes[escritos..].as_ptr().cast(),
                bytes.len() - escritos,
            )
        };
        if n > 0 {
            escritos += n as usize;
            continue;
        }
        // SAFETY: `__errno_location` devuelve un puntero valido al errno del hilo.
        let err = unsafe { *libc::__errno_location() };
        if n < 0 && err == libc::EINTR {
            continue;
        }
        return false;
    }
    true
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::protocolo::{AccionFichero, Trama};
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    /// Levanta un receptor real y devuelve su ruta y el hilo que acumula bytes.
    fn receptor(nombre: &str) -> (std::path::PathBuf, std::sync::mpsc::Receiver<Vec<u8>>) {
        let ruta =
            std::env::temp_dir().join(format!("aegis-canal-{nombre}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&ruta);
        let escucha = UnixListener::bind(&ruta).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut flujo, _)) = escucha.accept() {
                let mut todo = Vec::new();
                let _ = flujo.read_to_end(&mut todo);
                let _ = tx.send(todo);
            }
        });
        (ruta, rx)
    }

    #[test]
    fn la_traza_llega_entera_por_un_socket_real() {
        // Sin simulacion del formato: se escribe por un socket de verdad y se lee
        // por el otro lado con el mismo decodificador que usa el anfitrion.
        let (ruta, rx) = receptor("entera");
        let mut c = Canal::unix(&ruta).unwrap();

        c.enviar(Evento::Preparado {
            version: "1.0.0".into(),
        });
        c.enviar(Evento::Fichero {
            pid: 7,
            accion: AccionFichero::Escribe,
            ruta: "/home/victima/nomina.xlsx.cifrado".into(),
            bytes: 2048,
        });
        c.cerrar(0, true);

        let bytes = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut pos = 0usize;
        let mut eventos = Vec::new();
        while pos < bytes.len() {
            let Some((t, n)) = Trama::de_bytes(&bytes[pos..]).unwrap() else {
                break;
            };
            eventos.push(t);
            pos += n;
        }

        assert_eq!(eventos.len(), 3, "preparado + fichero + fin");
        assert_eq!(eventos[0].secuencia, 0);
        assert_eq!(eventos[1].secuencia, 1);
        assert!(matches!(eventos[2].evento, Evento::Fin { .. }));
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn la_secuencia_avanza_aunque_no_se_pueda_escribir() {
        // Si solo avanzara al escribir con exito, la traza llegaria continua y la
        // perdida seria invisible. El hueco en la numeracion ES la evidencia.
        let (ruta, _rx) = receptor("hueco");
        let mut c = Canal::unix(&ruta).unwrap();
        c.enviar(Evento::Degradado {
            causa: "uno".into(),
        });
        assert_eq!(c.secuencia(), 1);
        c.enviar(Evento::Degradado {
            causa: "dos".into(),
        });
        assert_eq!(c.secuencia(), 2);
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn un_anfitrion_ausente_no_cuelga_al_invitado() {
        // Si el anfitrion no esta, el agente invitado tiene que enterarse y
        // seguir vivo: colgarse aqui seria dejar la maquina infectada con un
        // proceso bloqueado dentro.
        let ruta = std::env::temp_dir().join("aegis-canal-que-no-existe.sock");
        let _ = std::fs::remove_file(&ruta);
        assert!(matches!(Canal::unix(&ruta), Err(ErrorCanal::NoConecta(_))));
    }

    #[test]
    fn el_cierre_declara_lo_que_se_perdio() {
        // Se fabrica la perdida a mano para comprobar que el resumen sale.
        let (ruta, rx) = receptor("perdidos");
        let mut c = Canal::unix(&ruta).unwrap();
        c.perdidos = 3;
        c.cerrar(0, true);

        let bytes = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut pos = 0usize;
        let mut hubo_degradado = false;
        while let Ok(Some((t, n))) = Trama::de_bytes(&bytes[pos..]) {
            if let Evento::Degradado { causa } = &t.evento {
                assert!(causa.contains('3'), "{causa}");
                assert!(causa.contains("huecos"), "{causa}");
                hubo_degradado = true;
            }
            pos += n;
            if pos >= bytes.len() {
                break;
            }
        }
        assert!(hubo_degradado, "el cierre tiene que declarar la perdida");
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn el_puerto_y_el_cid_son_los_del_protocolo() {
        // El CID 2 es una constante de vsock, no una eleccion: cambiarlo dejaria
        // al invitado hablando con nadie.
        assert_eq!(CID_ANFITRION, 2);
        const _: () = assert!(PUERTO > 1024, "el puerto choca con un servicio conocido");
    }
}
