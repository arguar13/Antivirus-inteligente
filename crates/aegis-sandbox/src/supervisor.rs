//! Supervision de un proceso por notificacion de usuario de seccomp.
//!
//! # Para que (FASE 93)
//!
//! Confinar un proceso con un perfil exige saber que hace de verdad. Hay tres
//! maneras de verlo desde fuera, y solo una sirve para esto:
//!
//! - **`ptrace`** para el proceso en cada llamada y le da al observador control
//!   total sobre el: mas de lo que hace falta, y el proceso lo nota.
//! - **`SECCOMP_RET_LOG`** deja la traza en el log de auditoria del kernel, que
//!   esta limitado en ritmo: un aprendizaje que pierde llamadas produce un
//!   perfil que rompe el programa en cuanto se aplica.
//! - **`SECCOMP_RET_USER_NOTIF`** suspende la llamada y se la entrega a un
//!   supervisor con su numero y sus argumentos; el supervisor decide que siga
//!   (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) o que falle con un errno. No se pierde
//!   ninguna, no se da mas control del necesario, y el mismo mecanismo sirve
//!   para aprender (se deja seguir todo) y para el modo permisivo (se deja
//!   seguir lo que el perfil no tiene y se anota que se habria bloqueado).
//!
//! # El detalle que hace funcionar el arranque
//!
//! La escucha nace en el HIJO al instalar el filtro, y el padre la necesita. Pasarla
//! por un socket exige un `sendmsg` que, con el filtro ya puesto, quedaria
//! suspendido esperando a un supervisor que todavia no tiene la escucha. Por eso:
//!
//! 1. el hijo instala el filtro y hace `dup3` de la escucha a un descriptor fijo
//!    ([`crate::seccomp::FD_ESCUCHA`]), y el filtro deja pasar exactamente ese
//!    `dup3` y ningun otro;
//! 2. el hijo llama a `execve`, que el filtro notifica, asi que queda suspendido
//!    ANTES de que `O_CLOEXEC` cierre la escucha;
//! 3. el padre la recoge con `pidfd_getfd` del descriptor fijo y empieza a
//!    atender, empezando por ese `execve`.
//!
//! Para que el paso 2 se cumpla, `execve` no puede estar nunca en la lista
//! blanca de un hijo supervisado: si pasara sin notificarse, cerraria la escucha
//! antes de que el padre la tuviera.
//!
//! # Lo que el supervisor NO es
//!
//! No es una frontera de seguridad. Leer un argumento que es un puntero (una ruta)
//! desde fuera tiene carrera: otro hilo del proceso puede cambiarlo entre la
//! lectura y el uso. Aqui da igual, porque el supervisor solo APRENDE y ANOTA; lo
//! que impone —en modo obligatorio— lo imponen el filtro de seccomp y Landlock
//! dentro del kernel, sobre el objeto ya resuelto.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::SandboxError;
use crate::seccomp::{self, SockFilter, FD_ESCUCHA};

/// `struct seccomp_data`, espejo exacto (64 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct DatosSeccomp {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

/// `struct seccomp_notif` (80 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NotifSeccomp {
    id: u64,
    pid: u32,
    flags: u32,
    data: DatosSeccomp,
}

/// `struct seccomp_notif_resp` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct RespSeccomp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// El kernel rechaza un `ioctl` cuyo tamano no casa con el suyo: se fija en
// compilacion, y la prueba de ABI lo coteja ademas con `SECCOMP_GET_NOTIF_SIZES`.
const _: () = assert!(std::mem::size_of::<DatosSeccomp>() == 64);
const _: () = assert!(std::mem::size_of::<NotifSeccomp>() == 80);
const _: () = assert!(std::mem::size_of::<RespSeccomp>() == 24);

// El tipo de la peticion de `ioctl` no es el mismo en todas las libc: `c_ulong`
// en glibc, `c_int` en musl. `libc::Ioctl` es el de la que se enlaza, y el valor
// se reinterpreta bit a bit (el kernel lo lee como `unsigned int`). Con
// `c_ulong` escrito a mano, este crate no compilaba contra musl, y no se supo
// hasta que el agente hermetico lo enlazo por primera vez (FASE 1 del MP-16).
/// `SECCOMP_IOCTL_NOTIF_RECV` = `_IOWR('!', 0, struct seccomp_notif)`.
const IOCTL_RECV: libc::Ioctl = 0xc050_2100_u32 as libc::Ioctl;
/// `SECCOMP_IOCTL_NOTIF_SEND` = `_IOWR('!', 1, struct seccomp_notif_resp)`.
const IOCTL_SEND: libc::Ioctl = 0xc018_2101_u32 as libc::Ioctl;
/// `SECCOMP_IOCTL_NOTIF_ID_VALID` = `_IOW('!', 2, __u64)`.
const IOCTL_ID_VALID: libc::Ioctl = 0x4008_2102_u32 as libc::Ioctl;
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
const FLAG_CONTINUE: u32 = 1;
/// `SECCOMP_GET_NOTIF_SIZES`.
const SECCOMP_GET_NOTIF_SIZES: libc::c_ulong = 3;

// Numeros comunes a todas las arquitecturas desde la tabla unificada (5.1+).
const NR_PIDFD_OPEN: libc::c_long = 434;
const NR_PIDFD_GETFD: libc::c_long = 438;
#[cfg(target_arch = "x86_64")]
const NR_SECCOMP: libc::c_long = 317;
#[cfg(target_arch = "aarch64")]
const NR_SECCOMP: libc::c_long = 277;

/// Tope de lo que se guarda de la salida del hijo.
pub const TOPE_SALIDA: usize = 4 * 1024 * 1024;

/// Una llamada suspendida, tal y como la entrega el kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notificacion {
    /// Identificador para responderla.
    pub id: u64,
    /// Hilo que la hizo (en el espacio de PID del supervisor).
    pub pid: u32,
    /// Numero de llamada.
    pub nr: u32,
    /// Arquitectura (`AUDIT_ARCH_*`).
    pub arch: u32,
    /// Argumentos crudos.
    pub args: [u64; 6],
}

/// Que paso al esperar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evento {
    /// Una llamada que atender.
    Llamada(Notificacion),
    /// Nada dentro del plazo.
    SinNovedad,
    /// El proceso principal termino.
    Terminado,
}

/// Como se responde a una llamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Respuesta {
    /// Que se ejecute tal cual.
    Continuar,
    /// Que falle con este errno sin ejecutarse.
    Errno(i32),
}

/// Como termino el proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fin {
    /// Salio con este codigo.
    Codigo(i32),
    /// Lo mato esta senal.
    Senal(i32),
}

impl Fin {
    /// Si termino bien.
    #[must_use]
    pub const fn limpio(self) -> bool {
        matches!(self, Fin::Codigo(0))
    }

    fn de_estado(estado: i32) -> Fin {
        if libc::WIFSIGNALED(estado) {
            Fin::Senal(libc::WTERMSIG(estado))
        } else {
            Fin::Codigo(libc::WEXITSTATUS(estado))
        }
    }
}

/// Un proceso lanzado bajo supervision.
#[derive(Debug)]
pub struct Supervisado {
    pid: libc::pid_t,
    escucha: OwnedFd,
    pidfd: OwnedFd,
    lector: Option<std::thread::JoinHandle<Vec<u8>>>,
    esperado: bool,
}

fn error_os(op: &'static str) -> SandboxError {
    SandboxError::Supervision {
        op,
        source: std::io::Error::last_os_error(),
    }
}

fn cadena(s: &[u8]) -> Result<CString, SandboxError> {
    CString::new(s).map_err(|_| SandboxError::Argumento(String::from_utf8_lossy(s).into_owned()))
}

/// Los tamanos de las estructuras de notificacion segun el kernel.
///
/// # Errores
/// El `errno` si el kernel no admite la consulta (anterior a 5.0).
pub fn tamanos_del_kernel() -> Result<(u16, u16, u16), SandboxError> {
    let mut t = [0u16; 3];
    // SAFETY: el kernel escribe tres u16 en `t`, que mide exactamente eso.
    let r = unsafe { libc::syscall(NR_SECCOMP, SECCOMP_GET_NOTIF_SIZES, 0, t.as_mut_ptr()) };
    if r != 0 {
        return Err(error_os("SECCOMP_GET_NOTIF_SIZES"));
    }
    Ok((t[0], t[1], t[2]))
}

impl Supervisado {
    /// Lanza `programa` con `argumentos` bajo el filtro `filtro`, que tiene que
    /// devolver `SECCOMP_RET_USER_NOTIF` para lo que se quiera ver y dejar pasar
    /// el `dup3` de la escucha (ver
    /// [`crate::seccomp::ListaBlanca::pasaje_de_escucha`]).
    ///
    /// La salida estandar y la de errores del hijo se recogen y se devuelven en
    /// [`Supervisado::esperar`].
    ///
    /// # Errores
    /// Si el programa no se puede preparar, el `fork` falla, o el hijo muere
    /// antes de entregar su escucha.
    pub fn lanzar(
        programa: &Path,
        argumentos: &[String],
        filtro: &[SockFilter],
    ) -> Result<Supervisado, SandboxError> {
        // TODO lo que reserva memoria se hace ANTES del fork: en el hijo solo
        // quedan llamadas al sistema.
        let ruta = cadena(programa.as_os_str().as_bytes())?;
        let mut argv_c = vec![ruta.clone()];
        for a in argumentos {
            argv_c.push(cadena(a.as_bytes())?);
        }
        let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        argv.push(std::ptr::null());
        let envp_c: Vec<CString> = std::env::vars_os()
            .filter_map(|(k, v)| {
                let mut b = k.as_bytes().to_vec();
                b.push(b'=');
                b.extend_from_slice(v.as_bytes());
                CString::new(b).ok()
            })
            .collect();
        let mut envp: Vec<*const libc::c_char> = envp_c.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());
        if filtro.is_empty() {
            return Err(SandboxError::EmptyFilter);
        }

        let mut tubo = [0 as RawFd; 2];
        // SAFETY: `pipe2` escribe dos descriptores en `tubo`.
        if unsafe { libc::pipe2(tubo.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(error_os("pipe2"));
        }

        // SAFETY: tras el fork, el hijo solo ejecuta llamadas al sistema sobre
        // memoria preparada antes (argv, envp, el filtro) y termina con `execve`
        // o `_exit`; no reserva memoria ni toma bloqueos.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(error_os("fork"));
        }
        if pid == 0 {
            // ── HIJO ──
            // SAFETY: llamadas al sistema sobre descriptores y punteros validos.
            unsafe {
                libc::dup2(tubo[1], 1);
                libc::dup2(tubo[1], 2);
                let escucha = match seccomp::install_con_escucha(filtro) {
                    Ok(fd) => fd,
                    Err(_) => libc::_exit(125),
                };
                if libc::dup3(escucha, FD_ESCUCHA as RawFd, libc::O_CLOEXEC) < 0 {
                    libc::_exit(124);
                }
                libc::execve(ruta.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }

        // ── PADRE ──
        // SAFETY: `tubo[1]` es nuestro y ya no lo necesitamos; `tubo[0]` pasa a
        // ser propiedad de un `OwnedFd`.
        unsafe { libc::close(tubo[1]) };
        let lectura = unsafe { OwnedFd::from_raw_fd(tubo[0]) };
        let lector = std::thread::spawn(move || {
            let mut f = std::fs::File::from(lectura);
            let mut v = Vec::new();
            let mut trozo = [0u8; 8192];
            loop {
                match f.read(&mut trozo) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if v.len() < TOPE_SALIDA {
                            v.extend_from_slice(&trozo[..n.min(TOPE_SALIDA - v.len())]);
                        }
                    }
                }
            }
            v
        });

        // SAFETY: `pidfd_open` sobre el pid del hijo recien creado.
        let pidfd = unsafe { libc::syscall(NR_PIDFD_OPEN, pid, 0) };
        if pidfd < 0 {
            let e = error_os("pidfd_open");
            matar_y_recoger(pid);
            return Err(e);
        }
        // SAFETY: descriptor recien devuelto por el kernel, sin otro dueno.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

        // Se reintenta hasta que el hijo haya hecho su `dup3`. Mientras tanto
        // puede estar instalando el filtro; despues queda suspendido en `execve`
        // hasta que se le responda, asi que la escucha no desaparece.
        let limite = Instant::now() + Duration::from_secs(10);
        let escucha = loop {
            // SAFETY: consulta sobre un pidfd propio.
            let r = unsafe { libc::syscall(NR_PIDFD_GETFD, pidfd.as_raw_fd(), FD_ESCUCHA, 0) };
            if r >= 0 {
                // SAFETY: descriptor nuevo del kernel, sin otro dueno.
                break unsafe { OwnedFd::from_raw_fd(r as RawFd) };
            }
            let mut estado = 0;
            // SAFETY: consulta no bloqueante sobre nuestro hijo.
            if unsafe { libc::waitpid(pid, &mut estado, libc::WNOHANG) } == pid {
                return Err(SandboxError::HijoSinEscucha(estado));
            }
            if Instant::now() > limite {
                let e = error_os("pidfd_getfd");
                matar_y_recoger(pid);
                return Err(e);
            }
            std::thread::sleep(Duration::from_micros(200));
        };

        Ok(Supervisado {
            pid,
            escucha,
            pidfd,
            lector: Some(lector),
            esperado: false,
        })
    }

    /// El pid del proceso principal.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Espera la siguiente llamada, como mucho `plazo`.
    ///
    /// # Errores
    /// Si `poll` o el `ioctl` fallan por algo que no sea que el hilo ya murio.
    pub fn recibir(&self, plazo: Duration) -> Result<Evento, SandboxError> {
        let mut fds = [
            libc::pollfd {
                fd: self.escucha.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ms = i32::try_from(plazo.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `fds` es un array valido de dos `pollfd`.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                return Ok(Evento::SinNovedad);
            }
            return Err(error_os("poll"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let mut n = NotifSeccomp::default();
            // SAFETY: `n` esta a cero (el kernel lo exige) y mide lo que espera.
            let r = unsafe { libc::ioctl(self.escucha.as_raw_fd(), IOCTL_RECV, &mut n) };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                // ENOENT: el hilo que la hizo murio entre el aviso y la lectura.
                if e.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(Evento::SinNovedad);
                }
                return Err(SandboxError::Supervision {
                    op: "SECCOMP_IOCTL_NOTIF_RECV",
                    source: e,
                });
            }
            return Ok(Evento::Llamada(Notificacion {
                id: n.id,
                pid: n.pid,
                nr: n.data.nr as u32,
                arch: n.data.arch,
                args: n.data.args,
            }));
        }
        if fds[1].revents & libc::POLLIN != 0 || fds[0].revents & libc::POLLHUP != 0 {
            return Ok(Evento::Terminado);
        }
        Ok(Evento::SinNovedad)
    }

    /// Responde a una llamada.
    ///
    /// # Errores
    /// Si el `ioctl` falla por algo que no sea que el hilo ya murio.
    pub fn responder(&self, id: u64, r: Respuesta) -> Result<(), SandboxError> {
        let resp = match r {
            Respuesta::Continuar => RespSeccomp {
                id,
                val: 0,
                error: 0,
                flags: FLAG_CONTINUE,
            },
            Respuesta::Errno(e) => RespSeccomp {
                id,
                val: 0,
                error: -e.abs(),
                flags: 0,
            },
        };
        // SAFETY: `resp` es la estructura que el kernel espera.
        let r = unsafe { libc::ioctl(self.escucha.as_raw_fd(), IOCTL_SEND, &resp) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(SandboxError::Supervision {
                op: "SECCOMP_IOCTL_NOTIF_SEND",
                source: e,
            });
        }
        Ok(())
    }

    /// Si una notificacion sigue viva: el hilo no ha muerto ni ha recibido una
    /// senal que la anule. Se comprueba DESPUES de leer argumentos de su memoria,
    /// para no anotar como dato lo que leyo otro proceso que reutilizo el pid.
    #[must_use]
    pub fn sigue_valida(&self, id: u64) -> bool {
        // SAFETY: `id` es un u64 que el kernel solo lee.
        unsafe { libc::ioctl(self.escucha.as_raw_fd(), IOCTL_ID_VALID, &id) == 0 }
    }

    /// Lee `n` bytes de la memoria de un hilo supervisado, **solo lectura**.
    ///
    /// # Errores
    /// Si la direccion no esta mapeada o el hilo ya no existe.
    pub fn leer(&self, hilo: u32, direccion: u64, n: usize) -> Result<Vec<u8>, SandboxError> {
        let mut buf = vec![0u8; n];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: n,
        };
        let remota = libc::iovec {
            iov_base: direccion as *mut libc::c_void,
            iov_len: n,
        };
        // SAFETY: `local` apunta a `buf`, que mide `n`; la memoria remota la
        // valida el kernel y un fallo devuelve -1, no un acceso invalido aqui.
        let r = unsafe { libc::process_vm_readv(hilo as libc::pid_t, &local, 1, &remota, 1, 0) };
        if r < 0 {
            return Err(error_os("process_vm_readv"));
        }
        buf.truncate(r as usize);
        Ok(buf)
    }

    /// Lee una cadena terminada en cero, como mucho `tope` bytes.
    ///
    /// Se lee por trozos que no cruzan un limite de pagina: una ruta al final de
    /// una pagina mapeada seguida de una sin mapear se tiene que poder leer igual.
    #[must_use]
    pub fn leer_cadena(&self, hilo: u32, direccion: u64, tope: usize) -> Option<Vec<u8>> {
        if direccion == 0 {
            return None;
        }
        let mut v = Vec::new();
        let mut dir = direccion;
        while v.len() < tope {
            let hasta_pagina = (4096 - (dir % 4096)) as usize;
            let n = hasta_pagina.min(tope - v.len()).min(256);
            let trozo = self.leer(hilo, dir, n).ok()?;
            if trozo.is_empty() {
                return None;
            }
            if let Some(i) = trozo.iter().position(|b| *b == 0) {
                v.extend_from_slice(&trozo[..i]);
                return Some(v);
            }
            dir += trozo.len() as u64;
            v.extend_from_slice(&trozo);
        }
        Some(v)
    }

    /// Espera a que el proceso termine y devuelve como, con su salida.
    ///
    /// Antes de esperar se atienden las notificaciones que queden dejandolas
    /// seguir: un hijo suspendido en una llamada no termina nunca.
    ///
    /// # Errores
    /// Si `waitpid` falla.
    pub fn esperar(mut self) -> Result<(Fin, Vec<u8>), SandboxError> {
        let mut estado = 0;
        loop {
            // SAFETY: consulta no bloqueante sobre nuestro hijo.
            let r = unsafe { libc::waitpid(self.pid, &mut estado, libc::WNOHANG) };
            if r == self.pid {
                break;
            }
            if r < 0 {
                return Err(error_os("waitpid"));
            }
            if let Evento::Llamada(n) = self.recibir(Duration::from_millis(20))? {
                self.responder(n.id, Respuesta::Continuar)?;
            }
        }
        self.esperado = true;
        let salida = self
            .lector
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        Ok((Fin::de_estado(estado), salida))
    }
}

fn matar_y_recoger(pid: libc::pid_t) {
    let mut estado = 0;
    // SAFETY: senal y espera sobre nuestro propio hijo.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut estado, 0);
    }
}

impl Drop for Supervisado {
    fn drop(&mut self) {
        if !self.esperado {
            matar_y_recoger(self.pid);
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::seccomp::{compile_lista_blanca, ListaBlanca, Resto};

    fn filtro_aprendizaje() -> Vec<SockFilter> {
        compile_lista_blanca(&ListaBlanca {
            permitidas: &[],
            dominios_socket: None,
            resto: Resto::Notificar,
            pasaje_de_escucha: true,
        })
    }

    /// Las estructuras miden lo que el kernel de ESTA maquina dice que miden.
    #[test]
    fn los_tamanos_casan_con_los_del_kernel() {
        match tamanos_del_kernel() {
            Ok((n, r, d)) => {
                assert_eq!(n as usize, std::mem::size_of::<NotifSeccomp>());
                assert_eq!(r as usize, std::mem::size_of::<RespSeccomp>());
                assert_eq!(d as usize, std::mem::size_of::<DatosSeccomp>());
            }
            Err(e) => eprintln!("NO APLICABLE: {e}"),
        }
    }

    /// UN PROCESO REAL, supervisado de principio a fin: cada llamada llega, se
    /// deja seguir, y el programa hace exactamente lo mismo que sin supervision.
    #[test]
    fn un_proceso_real_se_supervisa_entero_sin_cambiar_lo_que_hace() {
        let sh = Path::new("/bin/sh");
        let args = vec!["-c".to_string(), "echo hola-supervisado".to_string()];
        let s = match Supervisado::lanzar(sh, &args, &filtro_aprendizaje()) {
            Ok(s) => s,
            Err(e) => panic!("no se pudo supervisar /bin/sh: {e}"),
        };
        let mut vistas = std::collections::BTreeSet::new();
        let mut total = 0usize;
        loop {
            match s.recibir(Duration::from_secs(5)).expect("recibir") {
                Evento::Llamada(n) => {
                    vistas.insert(n.nr);
                    total += 1;
                    s.responder(n.id, Respuesta::Continuar).expect("responder");
                }
                Evento::Terminado => break,
                Evento::SinNovedad => {}
            }
        }
        let (fin, salida) = s.esperar().expect("esperar");
        assert!(fin.limpio(), "{fin:?}");
        assert_eq!(String::from_utf8_lossy(&salida).trim(), "hola-supervisado");
        let execve = crate::syscalls::numero("execve").expect("execve");
        let write = crate::syscalls::numero("write").expect("write");
        assert!(vistas.contains(&execve), "el primer execve tiene que verse");
        assert!(vistas.contains(&write));
        eprintln!("llamadas vistas: {total} ({} distintas)", vistas.len());
    }

    /// Responder con un errno hace fallar la llamada sin ejecutarla.
    #[test]
    fn responder_con_un_errno_hace_fallar_la_llamada() {
        let sh = Path::new("/bin/sh");
        let args = vec!["-c".to_string(), "echo x > /dev/null".to_string()];
        let s = Supervisado::lanzar(sh, &args, &filtro_aprendizaje()).expect("lanzar");
        let openat = crate::syscalls::numero("openat").expect("openat");
        let mut rutas = Vec::new();
        loop {
            match s.recibir(Duration::from_secs(5)).expect("recibir") {
                Evento::Llamada(n) => {
                    let r = if n.nr == openat {
                        let ruta = s.leer_cadena(n.pid, n.args[1], 4096).unwrap_or_default();
                        let es = ruta == b"/dev/null";
                        rutas.push(String::from_utf8_lossy(&ruta).into_owned());
                        if es {
                            Respuesta::Errno(libc::EACCES)
                        } else {
                            Respuesta::Continuar
                        }
                    } else {
                        Respuesta::Continuar
                    };
                    s.responder(n.id, r).expect("responder");
                }
                Evento::Terminado => break,
                Evento::SinNovedad => {}
            }
        }
        let (fin, _) = s.esperar().expect("esperar");
        assert!(rutas.iter().any(|r| r == "/dev/null"), "{rutas:?}");
        assert!(
            !fin.limpio(),
            "la redireccion fallida hace fallar a sh: {fin:?}"
        );
    }

    #[test]
    fn un_programa_que_no_existe_no_deja_el_padre_colgado() {
        let r = Supervisado::lanzar(Path::new("/no/existe/jamas"), &[], &filtro_aprendizaje());
        match r {
            Ok(s) => {
                // El execve se notifica, se deja seguir, falla, y el hijo sale 127.
                loop {
                    match s.recibir(Duration::from_secs(5)).expect("recibir") {
                        Evento::Llamada(n) => s.responder(n.id, Respuesta::Continuar).expect("r"),
                        Evento::Terminado => break,
                        Evento::SinNovedad => {}
                    }
                }
                let (fin, _) = s.esperar().expect("esperar");
                assert_eq!(fin, Fin::Codigo(127));
            }
            Err(e) => panic!("{e}"),
        }
    }
}
