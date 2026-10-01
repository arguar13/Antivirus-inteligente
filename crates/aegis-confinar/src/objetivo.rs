//! A quien se puede confinar, y a quien no, decidido al construir el tipo.
//!
//! # El confinamiento como arma contra el propio producto
//!
//! Un motor que confina procesos es tambien un motor que puede dejar sin
//! capacidades, sin red o sin ficheros a cualquier proceso. Vuelto contra el
//! propio agente, es la forma mas limpia de cegarlo: un perfil «aprendido» en un
//! momento en que el agente no usaba la red lo dejaria mudo para siempre. Vuelto
//! contra `init` o contra `sshd`, deja al cliente sin maquina o sin forma de
//! entrar a arreglarla.
//!
//! Por eso la comprobacion no esta en el codigo que aplica —que alguien puede
//! saltarse o reescribir—: esta en el constructor de [`ObjetivoConfinable`]. Sin
//! un `ObjetivoConfinable` no se puede aprender, ni ensayar, ni imponer, y no
//! hay forma de construir uno para lo que esta protegido.

use std::path::{Path, PathBuf};

/// Por que un ejecutable no se puede confinar.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rechazo {
    /// Es el propio agente, o uno de sus binarios.
    #[error("{0} es el propio agente: confinarlo es una forma de cegarlo")]
    AgentePropio(PathBuf),
    /// Es el proceso 1 de la maquina.
    #[error("{0} es init: confinarlo es dejar al cliente sin maquina")]
    Init(PathBuf),
    /// Esta en la lista de activos protegidos.
    #[error("{0} es un activo protegido ({1}): nunca se confina automaticamente")]
    ActivoProtegido(PathBuf, String),
    /// No existe o no es un fichero ejecutable.
    #[error("{0} no es un ejecutable: {1}")]
    NoEjecutable(PathBuf, String),
}

/// Los activos que no se confinan nunca, ni con confirmacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivosProtegidos {
    /// Ejecutables concretos, con el motivo.
    pub ejecutables: Vec<(PathBuf, String)>,
    /// Directorios cuyo contenido entero esta protegido (la instalacion del
    /// agente, por ejemplo).
    pub directorios: Vec<(PathBuf, String)>,
}

impl Default for ActivosProtegidos {
    /// Los de cualquier maquina Linux: el arranque, el acceso remoto y el propio
    /// agente.
    fn default() -> Self {
        let e = |p: &str, m: &str| (PathBuf::from(p), m.to_string());
        ActivosProtegidos {
            ejecutables: vec![
                e("/sbin/init", "arranque del sistema"),
                e("/lib/systemd/systemd", "arranque del sistema"),
                e("/usr/lib/systemd/systemd", "arranque del sistema"),
                e(
                    "/usr/sbin/sshd",
                    "acceso remoto: sin el no se puede entrar a arreglar nada",
                ),
                e("/usr/sbin/sshd-session", "acceso remoto"),
            ],
            directorios: vec![
                e("/opt/aegis", "instalacion del agente"),
                e("/usr/lib/aegis", "instalacion del agente"),
            ],
        }
    }
}

/// Un ejecutable que SI se puede confinar.
///
/// No tiene constructor publico salvo [`ObjetivoConfinable::nuevo`], que hace
/// todas las comprobaciones: tener uno es la prueba de que se pasaron.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjetivoConfinable {
    ejecutable: PathBuf,
}

/// La ruta real, resolviendo enlaces: `/bin/sshd` y `/usr/sbin/sshd` pueden ser
/// el mismo fichero, y la lista protegida no puede depender de por donde se
/// nombre.
fn real(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

impl ObjetivoConfinable {
    /// Comprueba que un ejecutable se puede confinar.
    ///
    /// # Errores
    /// [`Rechazo`] con el motivo concreto.
    pub fn nuevo(ejecutable: &Path, protegidos: &ActivosProtegidos) -> Result<Self, Rechazo> {
        let ruta = real(ejecutable);
        let meta = std::fs::metadata(&ruta)
            .map_err(|e| Rechazo::NoEjecutable(ejecutable.to_path_buf(), e.to_string()))?;
        if !meta.is_file() {
            return Err(Rechazo::NoEjecutable(
                ejecutable.to_path_buf(),
                "no es un fichero regular".into(),
            ));
        }

        // 1. El propio agente: el binario que esta corriendo AHORA, venga de
        //    donde venga, y cualquier binario del producto por su nombre.
        if let Ok(yo) = std::env::current_exe() {
            if real(&yo) == ruta {
                return Err(Rechazo::AgentePropio(ruta));
            }
        }
        let nombre = ruta
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if nombre.starts_with("aegis-") || nombre == "aegisd" || nombre == "aegisctl" {
            return Err(Rechazo::AgentePropio(ruta));
        }

        // 2. init: lo que este corriendo como proceso 1 en ESTA maquina, que no
        //    siempre es la ruta de la lista.
        if let Ok(uno) = std::fs::read_link("/proc/1/exe") {
            if real(&uno) == ruta {
                return Err(Rechazo::Init(ruta));
            }
        }

        // 3. La lista protegida.
        for (p, motivo) in &protegidos.ejecutables {
            if real(p) == ruta {
                return Err(Rechazo::ActivoProtegido(ruta, motivo.clone()));
            }
        }
        for (d, motivo) in &protegidos.directorios {
            if ruta.starts_with(real(d)) {
                return Err(Rechazo::ActivoProtegido(ruta, motivo.clone()));
            }
        }
        Ok(ObjetivoConfinable { ejecutable: ruta })
    }

    /// El ejecutable, con la ruta real.
    #[must_use]
    pub fn ejecutable(&self) -> &Path {
        &self.ejecutable
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    /// AUTOATAQUE: el motor de confinamiento contra el propio agente. El
    /// binario que esta corriendo ahora mismo —el de las pruebas— hace de agente.
    #[test]
    fn el_propio_agente_no_se_puede_confinar() {
        let yo = std::env::current_exe().expect("current_exe");
        assert!(matches!(
            ObjetivoConfinable::nuevo(&yo, &ActivosProtegidos::default()),
            Err(Rechazo::AgentePropio(_))
        ));
    }

    /// Y contra init, sea cual sea en esta maquina.
    #[test]
    fn init_no_se_puede_confinar() {
        let Ok(uno) = std::fs::read_link("/proc/1/exe") else {
            omitir("/proc/1/exe no se puede leer aqui", Requisito::Root);
            return;
        };
        let r = ObjetivoConfinable::nuevo(&uno, &ActivosProtegidos::default());
        assert!(
            matches!(r, Err(Rechazo::Init(_) | Rechazo::ActivoProtegido(..))),
            "{r:?}"
        );
    }

    #[test]
    fn un_activo_protegido_no_se_confina_ni_nombrandolo_por_un_enlace() {
        let dir = std::env::temp_dir().join(format!("aegis-objetivo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let real = dir.join("servicio-critico");
        std::fs::copy("/bin/true", &real).expect("copiar");
        let enlace = dir.join("otro-nombre");
        std::os::unix::fs::symlink(&real, &enlace).expect("enlace");
        let protegidos = ActivosProtegidos {
            ejecutables: vec![(real.clone(), "prueba".into())],
            directorios: vec![],
        };
        assert!(matches!(
            ObjetivoConfinable::nuevo(&enlace, &protegidos),
            Err(Rechazo::ActivoProtegido(..))
        ));
        let dentro = ActivosProtegidos {
            ejecutables: vec![],
            directorios: vec![(dir.clone(), "instalacion".into())],
        };
        assert!(matches!(
            ObjetivoConfinable::nuevo(&real, &dentro),
            Err(Rechazo::ActivoProtegido(..))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_binario_cualquiera_si_se_puede_confinar() {
        let o = ObjetivoConfinable::nuevo(Path::new("/bin/true"), &ActivosProtegidos::default())
            .expect("confinable");
        assert!(o.ejecutable().is_absolute());
        assert!(matches!(
            ObjetivoConfinable::nuevo(Path::new("/no/existe"), &ActivosProtegidos::default()),
            Err(Rechazo::NoEjecutable(..))
        ));
        assert!(matches!(
            ObjetivoConfinable::nuevo(Path::new("/tmp"), &ActivosProtegidos::default()),
            Err(Rechazo::NoEjecutable(..))
        ));
    }
}
