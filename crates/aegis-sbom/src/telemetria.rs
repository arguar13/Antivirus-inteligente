//! La telemetria que ya tiene el agente, en la forma que necesita la
//! alcanzabilidad: que ficheros tiene proyectados cada proceso y en que puertos
//! escucha.
//!
//! # Lo que no se pudo leer se cuenta
//!
//! Sin privilegios, los mapas de memoria y los descriptores de los procesos de
//! otros usuarios no se pueden leer. Eso no es un error que haya que esconder: es
//! la diferencia entre «ningun proceso carga esta biblioteca» y «ninguno de los
//! que pude mirar la carga». Cada proceso que no se pudo leer se cuenta, y la
//! alcanzabilidad lo usa para no afirmar un «No» que no ha comprobado.
//!
//! # La red de cada proceso, desde el propio proceso
//!
//! `/proc/net/tcp` solo muestra el espacio de nombres de red de quien lo lee: los
//! servicios de un contenedor no aparecen ahi. Por eso las escuchas de un proceso
//! se leen de `/proc/<pid>/net/*` —su vista de la red— cruzadas con SUS
//! descriptores.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Un fichero proyectado en la memoria de un proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapeado {
    /// La ruta, sin el sufijo ` (deleted)`.
    pub ruta: PathBuf,
    /// El inodo del fichero proyectado.
    pub inodo: u64,
    /// Si el fichero se borro del disco despues de proyectarse: el proceso
    /// sigue ejecutando una version que ya no esta instalada.
    pub borrado: bool,
}

/// Un proceso vivo y lo que tiene proyectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcesoVivo {
    /// Pid.
    pub pid: u32,
    /// Su ejecutable.
    pub exe: Option<PathBuf>,
    /// Sus ficheros proyectados, sin repetir.
    pub mapas: Vec<Mapeado>,
}

/// Un puerto en escucha.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escucha {
    /// `tcp` o `udp`.
    pub protocolo: &'static str,
    /// Direccion local.
    pub ip: IpAddr,
    /// Puerto.
    pub puerto: u16,
}

impl Escucha {
    /// Si se puede alcanzar desde fuera de la maquina: cualquier direccion que no
    /// sea de bucle local.
    #[must_use]
    pub fn es_externa(&self) -> bool {
        !self.ip.is_loopback()
    }
}

/// Lo que se leyo de los procesos.
#[derive(Debug, Clone, Default)]
pub struct Procesos {
    /// Los que se pudieron leer.
    pub leidos: Vec<ProcesoVivo>,
    /// Los que no, con el motivo.
    pub no_leidos: Vec<(u32, String)>,
}

/// De donde sale la telemetria. Un rasgo para poder probar la alcanzabilidad con
/// procesos simulados y ejecutarla con los reales.
pub trait Telemetria {
    /// Los procesos vivos y sus mapas.
    fn procesos(&self) -> Procesos;
    /// Los puertos en los que escucha un proceso.
    ///
    /// # Errors
    ///
    /// Con el motivo, si no se pudo saber.
    fn escuchas_de(&self, pid: u32) -> Result<Vec<Escucha>, String>;
}

/// Quita el sufijo ` (deleted)` que el nucleo anade a un fichero borrado.
#[must_use]
pub fn sin_borrado(ruta: &str) -> (PathBuf, bool) {
    match ruta.strip_suffix(" (deleted)") {
        Some(r) => (PathBuf::from(r), true),
        None => (PathBuf::from(ruta), false),
    }
}

/// La telemetria del propio sistema.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct DelSistema;

#[cfg(target_os = "linux")]
impl Telemetria for DelSistema {
    fn procesos(&self) -> Procesos {
        let mut p = Procesos::default();
        let Ok(it) = std::fs::read_dir("/proc") else {
            return p;
        };
        let mut pids: Vec<u32> = it
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
            .collect();
        pids.sort_unstable();
        for pid in pids {
            let regiones = match aegis_scal::linux::memory::regions_of(pid as i32) {
                Ok(r) => r,
                Err(e) => {
                    // Un proceso que termino entre el listado y la lectura no es
                    // un proceso que no se pudo leer: no esta.
                    if e.kind() != std::io::ErrorKind::NotFound {
                        p.no_leidos.push((pid, e.to_string()));
                    }
                    continue;
                }
            };
            // Los hilos del nucleo no tienen mapas: no cargan bibliotecas.
            if regiones.is_empty() {
                continue;
            }
            let mut mapas: Vec<Mapeado> = Vec::new();
            for r in regiones {
                let Some(ruta) = r.path.as_deref() else {
                    continue;
                };
                if r.inode == 0 || !ruta.starts_with('/') {
                    continue;
                }
                let (ruta, borrado) = sin_borrado(ruta);
                if !mapas.iter().any(|m| m.ruta == ruta && m.inodo == r.inode) {
                    mapas.push(Mapeado {
                        ruta,
                        inodo: r.inode,
                        borrado,
                    });
                }
            }
            p.leidos.push(ProcesoVivo {
                pid,
                exe: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
                mapas,
            });
        }
        p
    }

    fn escuchas_de(&self, pid: u32) -> Result<Vec<Escucha>, String> {
        use aegis_scal::linux::net::{analizar_tabla, inodo_de_enlace, EstadoSocket};
        let fds = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(f) => f,
            // Termino entre la instantanea y esta lectura: un proceso que ya no
            // existe no escucha en nada. No es «ilegible», y contarlo asi dejaba
            // sin respuesta la exposicion de todo lo que el cargaba.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("descriptores del proceso {pid}: {e}")),
        };
        let mut propios = std::collections::BTreeSet::new();
        for fd in fds.flatten() {
            if let Some(i) = std::fs::read_link(fd.path())
                .ok()
                .and_then(|d| d.to_str().and_then(inodo_de_enlace))
            {
                propios.insert(i);
            }
        }
        let mut out = Vec::new();
        for (f, proto, v6) in [
            ("tcp", "tcp", false),
            ("tcp6", "tcp", true),
            ("udp", "udp", false),
            ("udp6", "udp", true),
        ] {
            let Ok(t) = std::fs::read_to_string(format!("/proc/{pid}/net/{f}")) else {
                continue;
            };
            for s in analizar_tabla(&t, proto, v6) {
                // TCP en LISTEN; UDP ligado sin extremo remoto (estado 07).
                let escucha = match proto {
                    "tcp" => s.estado == EstadoSocket::Escuchando,
                    _ => s.estado == EstadoSocket::Cerrado && s.puerto_remoto == 0,
                };
                if escucha && propios.contains(&s.inodo) {
                    out.push(Escucha {
                        protocolo: proto,
                        ip: s.ip_local,
                        puerto: s.puerto_local,
                    });
                }
            }
        }
        out.sort_by(|a, b| (a.puerto, a.protocolo).cmp(&(b.puerto, b.protocolo)));
        out.dedup();
        Ok(out)
    }
}

/// Telemetria fija, para las pruebas.
#[derive(Debug, Clone, Default)]
pub struct Simulada {
    /// Los procesos.
    pub procesos: Procesos,
    /// Escuchas por pid; un pid ausente es «no se pudo leer».
    pub escuchas: std::collections::BTreeMap<u32, Vec<Escucha>>,
}

impl Telemetria for Simulada {
    fn procesos(&self) -> Procesos {
        self.procesos.clone()
    }
    fn escuchas_de(&self, pid: u32) -> Result<Vec<Escucha>, String> {
        self.escuchas
            .get(&pid)
            .cloned()
            .ok_or_else(|| format!("descriptores del proceso {pid}: permiso denegado"))
    }
}

/// El inodo de un fichero, si existe.
#[must_use]
pub fn inodo_de(ruta: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(ruta).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = ruta;
        None
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_sufijo_de_borrado_se_quita_y_se_anota() {
        assert_eq!(
            sin_borrado("/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)"),
            (PathBuf::from("/usr/lib/x86_64-linux-gnu/libssl.so.3"), true)
        );
        assert_eq!(
            sin_borrado("/usr/bin/sshd"),
            (PathBuf::from("/usr/bin/sshd"), false)
        );
    }

    #[test]
    fn una_escucha_en_bucle_local_no_es_externa() {
        let e = |ip: &str| Escucha {
            protocolo: "tcp",
            ip: ip.parse().unwrap(),
            puerto: 5432,
        };
        assert!(!e("127.0.0.1").es_externa());
        assert!(!e("::1").es_externa());
        assert!(e("0.0.0.0").es_externa());
        assert!(e("::").es_externa());
        assert!(e("192.168.1.10").es_externa());
    }
}
