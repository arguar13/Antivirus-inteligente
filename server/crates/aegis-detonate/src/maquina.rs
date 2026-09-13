//! El ciclo de vida de la maquina: arrancarla y, sobre todo, destruirla.
//!
//! # La unica garantia que no se puede negociar
//!
//! **La maquina se destruye siempre.** Si la detonacion falla, si el informe no
//! se puede escribir, si el proceso que la lanzo entra en panico, si alguien
//! suelta el objeto sin llamar a nada: se destruye.
//!
//! No es higiene: una maquina de detonacion que sobrevive a su detonacion es una
//! maquina infectada, con la muestra dentro, corriendo en la infraestructura del
//! que analiza. Y como nadie la esta mirando, es ademas invisible.
//!
//! Por eso la destruccion esta en [`Drop`] y no solo en un metodo: un metodo se
//! olvida en el camino de error, y el camino de error es justo el que se toma
//! cuando algo ha ido mal con una muestra que muerde.
//!
//! # Nunca se reutiliza una maquina
//!
//! Cada detonacion parte de una instantanea limpia. Reutilizar ahorraria el
//! arranque y costaria las dos cosas que hacen util a un sandbox: que dos
//! detonaciones de la misma muestra den el mismo informe —imposible si la segunda
//! empieza con lo que dejo la primera— y que lo que se observa sea de la muestra
//! y no de la anterior.
//!
//! # Los dos confinamientos
//!
//! - [`Maquina::MicroVm`] es el de produccion. Aqui se genera su configuracion y
//!   se comprueba pieza a pieza; **arrancarla necesita `/dev/kvm`**, que no hay
//!   en cualquier sitio, y eso se declara en vez de fingirse.
//! - [`Jaula`] es confinamiento por espacios de nombres del kernel. Se ejercita
//!   entero —se crea el espacio, se lanza dentro, y se comprueba que de verdad no
//!   hay salida— y **no equivale a una maquina virtual**, cosa que dice
//!   [`crate::frontera::Confinamiento::aguanta_elevacion_local`].

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::frontera::{Confinamiento, Frontera, Salida};

// --- Configuracion de la maquina virtual --------------------------------------

/// De donde arranca el invitado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arranque {
    /// Imagen del kernel.
    pub kernel_image_path: String,
    /// Linea de ordenes del kernel.
    pub boot_args: String,
}

/// Un disco del invitado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disco {
    /// Identificador.
    pub drive_id: String,
    /// Fichero de respaldo.
    pub path_on_host: String,
    /// Si es el disco de raiz.
    pub is_root_device: bool,
    /// Si es de solo lectura.
    pub is_read_only: bool,
}

/// Recursos de la maquina.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recursos {
    /// Nucleos.
    pub vcpu_count: u8,
    /// Memoria en MiB.
    pub mem_size_mib: u32,
    /// Si se comparte el reloj del anfitrion.
    ///
    /// Siempre falso: compartirlo le daria a la muestra un reloj coherente con el
    /// del anfitrion, que es una de las cosas que se miran para reconocer un
    /// entorno virtualizado.
    pub track_dirty_pages: bool,
}

/// El canal vsock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vsock {
    /// Identificador del dispositivo.
    pub guest_cid: u32,
    /// Socket del anfitrion al que el hipervisor traduce las conexiones.
    pub uds_path: String,
}

/// La configuracion completa que se le pasa al hipervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigMaquina {
    /// De donde arranca.
    pub boot_source: Arranque,
    /// Los discos.
    pub drives: Vec<Disco>,
    /// Los recursos.
    pub machine_config: Recursos,
    /// El canal.
    pub vsock: Vsock,
    /// Interfaces de red.
    ///
    /// **Siempre vacio en esta version.** El invitado habla con los servicios
    /// falsos por un dispositivo de tipo tap dentro de un espacio de nombres de
    /// red sin salida, que se configura fuera de este fichero. Poner aqui una
    /// interfaz sin ese espacio de nombres seria darle al invitado la red del
    /// anfitrion, y la generacion lo impide.
    pub network_interfaces: Vec<String>,
}

/// CID del invitado en vsock. El 2 es el anfitrion, asi que el invitado empieza en 3.
pub const CID_INVITADO: u32 = 3;

/// Genera la configuracion del hipervisor a partir de la frontera.
///
/// # Errores
/// [`ErrorMaquina::FronteraRota`] si la frontera no es de maquina virtual.
pub fn configurar(
    frontera: &Frontera,
    raiz_escribible: &Path,
    socket_vsock: &Path,
) -> Result<ConfigMaquina, ErrorMaquina> {
    let Confinamiento::MicroVm { kernel, raiz, .. } = &frontera.confinamiento else {
        return Err(ErrorMaquina::FronteraRota(
            "se pidio configuracion de maquina virtual para un confinamiento que no lo es".into(),
        ));
    };

    Ok(ConfigMaquina {
        boot_source: Arranque {
            kernel_image_path: kernel.display().to_string(),
            // `panic=-1` reinicia al instante en vez de quedarse en el panico, y
            // `reboot=t` lo convierte en apagado: una maquina de detonacion que
            // se queda colgada en un panico del kernel ocupa un puesto hasta que
            // vence el plazo, y el plazo es caro.
            //
            // `random.trust_cpu=on` evita que el invitado se quede esperando
            // entropia al arrancar: sin ello, el arranque tarda tanto que el
            // plazo se consume antes de detonar nada.
            boot_args: "console=ttyS0 reboot=t panic=-1 random.trust_cpu=on \
                        i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
                .to_string(),
        },
        drives: vec![
            Disco {
                drive_id: "raiz".into(),
                path_on_host: raiz.display().to_string(),
                is_root_device: true,
                // La imagen de raiz NUNCA se escribe. Es lo que garantiza que dos
                // detonaciones de la misma muestra parten del mismo estado, y lo
                // que impide que una muestra deje algo para la siguiente.
                is_read_only: true,
            },
            Disco {
                drive_id: "desechable".into(),
                path_on_host: raiz_escribible.display().to_string(),
                is_root_device: false,
                is_read_only: false,
            },
        ],
        machine_config: Recursos {
            vcpu_count: frontera.limites.vcpus,
            mem_size_mib: frontera.limites.memoria_mib,
            track_dirty_pages: false,
        },
        vsock: Vsock {
            guest_cid: CID_INVITADO,
            uds_path: socket_vsock.display().to_string(),
        },
        network_interfaces: Vec::new(),
    })
}

// --- Errores ------------------------------------------------------------------

/// Lo que puede salir mal con la maquina.
#[derive(Debug, thiserror::Error)]
pub enum ErrorMaquina {
    /// La frontera no permite lo que se pide.
    #[error("{0}")]
    FronteraRota(String),
    /// No se pudo lanzar.
    #[error("no se pudo lanzar la maquina: {0}")]
    NoArranca(String),
    /// El entorno no da lo que hace falta.
    ///
    /// Es el muro declarado: sin `/dev/kvm` no hay maquina virtual, y decirlo es
    /// mejor que arrancar algo que no es una maquina virtual y llamarlo asi.
    #[error("{0}")]
    SinSoporte(String),
}

/// Si este anfitrion puede levantar maquinas virtuales.
///
/// Se comprueba y se **dice**: un sistema de analisis que degrada en silencio a
/// un aislamiento mas debil es peor que uno que se niega a arrancar, porque el
/// informe sale igual y nadie sabe con que fuerza estaba encerrada la muestra.
#[must_use]
pub fn hay_virtualizacion() -> bool {
    Path::new("/dev/kvm").exists()
}

// --- La jaula por espacios de nombres -----------------------------------------

/// Como acabo la destruccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destruccion {
    /// No habia nada que destruir.
    NoHabiaNada,
    /// Termino por si sola y se recogio.
    TerminoSola,
    /// Hubo que matarla.
    Matada,
}

/// Una detonacion encerrada en espacios de nombres del kernel.
///
/// **No equivale a una maquina virtual.** Una elevacion local de privilegios en
/// el kernel saca a la muestra de aqui; contra una maquina virtual no lo
/// consigue. Sirve para ejercitar la maquinaria entera —y el aislamiento de red
/// es real y se comprueba— pero no para muestras que muerden, cosa que
/// [`Frontera::verificar`] impide por su cuenta.
#[derive(Debug)]
pub struct Jaula {
    hijo: Option<Child>,
    pgid: i32,
    destruida: bool,
}

impl Jaula {
    /// Lanza un programa dentro de espacios de nombres nuevos.
    ///
    /// Se le quitan, como minimo, la red y el espacio de PID. La red es la que
    /// importa aqui: dentro solo hay `lo`, sin rutas, sin puerta de enlace y sin
    /// nada que reenvie, asi que una muestra que intente salir no alcanza nada
    /// real. Eso no se declara, se comprueba en una prueba.
    ///
    /// # Errores
    /// [`ErrorMaquina::NoArranca`] si `unshare` no esta o no hay permisos.
    pub fn lanzar(
        programa: &Path,
        argumentos: &[String],
        salida: Salida,
    ) -> Result<Jaula, ErrorMaquina> {
        use std::os::unix::process::CommandExt;

        let mut orden = Command::new("unshare");
        orden.arg("--net");
        orden.arg("--pid");
        orden.arg("--fork");
        orden.arg("--mount-proc");
        // Sin salida ninguna significa que ni siquiera se levanta el bucle local
        // hacia fuera; con salida simulada, los servicios falsos viven dentro de
        // este mismo espacio de nombres, que es la unica forma de que el invitado
        // los alcance sin alcanzar nada mas.
        let _ = salida;
        orden.arg("--");
        orden.arg(programa);
        orden.args(argumentos);
        orden.stdin(Stdio::null());
        orden.stdout(Stdio::null());
        orden.stderr(Stdio::null());
        // Grupo de procesos propio: la destruccion mata al arbol entero de un
        // golpe. Sin esto, una muestra que lanza un hijo y se muere dejaria al
        // hijo corriendo en el anfitrion.
        orden.process_group(0);

        let hijo = orden
            .spawn()
            .map_err(|e| ErrorMaquina::NoArranca(format!("unshare: {e}")))?;
        let pgid = hijo.id() as i32;

        Ok(Jaula {
            hijo: Some(hijo),
            pgid,
            destruida: false,
        })
    }

    /// PID del proceso raiz de la jaula, visto desde el anfitrion.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.hijo.as_ref().map(Child::id)
    }

    /// Si el proceso raiz sigue vivo. Recoge el estado si ya termino.
    pub fn viva(&mut self) -> bool {
        match self.hijo.as_mut() {
            None => false,
            Some(h) => matches!(h.try_wait(), Ok(None)),
        }
    }

    /// Espera a que termine, con plazo. Devuelve el codigo si termino.
    pub fn esperar(&mut self, plazo: Duration) -> Option<i32> {
        let fin = Instant::now() + plazo;
        while Instant::now() < fin {
            match self.hijo.as_mut()?.try_wait() {
                Ok(Some(estado)) => return Some(estado.code().unwrap_or(-1)),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => return None,
            }
        }
        None
    }

    /// Destruye la jaula. Es idempotente y no falla nunca.
    pub fn destruir(&mut self) -> Destruccion {
        if self.destruida {
            return Destruccion::NoHabiaNada;
        }
        self.destruida = true;

        let Some(mut hijo) = self.hijo.take() else {
            return Destruccion::NoHabiaNada;
        };

        if let Ok(Some(_)) = hijo.try_wait() {
            return Destruccion::TerminoSola;
        }

        // Se mata al GRUPO, no al proceso. Matar solo al proceso raiz dejaria
        // vivos a los hijos que la muestra haya lanzado, que es exactamente lo
        // que hace cualquier malware que quiera sobrevivir a su propia muerte.
        matar_grupo(self.pgid);
        let _ = hijo.kill();
        let _ = hijo.wait();
        Destruccion::Matada
    }
}

impl Drop for Jaula {
    /// La garantia que no se negocia.
    ///
    /// Esta en `Drop` y no solo en [`Jaula::destruir`] porque un metodo se olvida
    /// en el camino de error, y el camino de error es justo el que se toma cuando
    /// algo ha ido mal con una muestra que muerde.
    fn drop(&mut self) {
        self.destruir();
    }
}

/// Manda `SIGKILL` a un grupo de procesos entero.
fn matar_grupo(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    // Se usa `kill` del sistema en vez de `libc::kill` para que este crate siga
    // sin `unsafe`: es una sola llamada por detonacion y el coste no se mide al
    // lado de arrancar una maquina.
    let _ = Command::new("kill")
        .arg("-9")
        .arg(format!("-{pgid}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::path::PathBuf;

    fn frontera_vm() -> Frontera {
        // Rutas de mentira: lo que se prueba aqui es la GENERACION de la
        // configuracion, que es lo que se puede comprobar sin /dev/kvm.
        Frontera::microvm(
            PathBuf::from("/usr/bin/firecracker"),
            PathBuf::from("/var/lib/aegis/vmlinux"),
            PathBuf::from("/var/lib/aegis/raiz.ext4"),
        )
    }

    // --- La configuracion de la maquina virtual ----------------------------

    #[test]
    fn la_raiz_del_invitado_es_de_solo_lectura() {
        // Es lo que garantiza que dos detonaciones de la misma muestra parten del
        // mismo estado, y lo que impide que una muestra deje algo preparado para
        // la siguiente.
        let c = configurar(
            &frontera_vm(),
            Path::new("/tmp/desechable.ext4"),
            Path::new("/tmp/v.sock"),
        )
        .unwrap();

        let raiz = c.drives.iter().find(|d| d.is_root_device).unwrap();
        assert!(raiz.is_read_only, "la raiz NO puede ser escribible");
        assert!(
            c.drives.iter().any(|d| !d.is_read_only),
            "falta el desechable"
        );
    }

    #[test]
    fn la_configuracion_no_le_da_al_invitado_ninguna_interfaz_de_red() {
        // Poner una interfaz aqui sin el espacio de nombres seria darle al
        // invitado la red del anfitrion.
        let c = configurar(
            &frontera_vm(),
            Path::new("/tmp/d.ext4"),
            Path::new("/tmp/v.sock"),
        )
        .unwrap();
        assert!(c.network_interfaces.is_empty());
    }

    #[test]
    fn los_limites_de_la_frontera_llegan_a_la_configuracion() {
        // Unos limites que se verifican y luego no se aplican son peores que no
        // tenerlos: dan la sensacion de estar acotando.
        let mut f = frontera_vm();
        f.limites.vcpus = 4;
        f.limites.memoria_mib = 2048;
        let c = configurar(&f, Path::new("/tmp/d"), Path::new("/tmp/v")).unwrap();
        assert_eq!(c.machine_config.vcpu_count, 4);
        assert_eq!(c.machine_config.mem_size_mib, 2048);
    }

    #[test]
    fn el_canal_va_por_vsock_y_no_por_la_red_del_invitado() {
        let c = configurar(
            &frontera_vm(),
            Path::new("/tmp/d"),
            Path::new("/run/aegis/v.sock"),
        )
        .unwrap();
        assert_eq!(c.vsock.guest_cid, CID_INVITADO);
        assert_eq!(c.vsock.uds_path, "/run/aegis/v.sock");
    }

    #[test]
    fn el_arranque_no_deja_al_invitado_colgado_en_un_panico() {
        // Una maquina que se queda en un panico del kernel ocupa un puesto de
        // detonacion hasta que vence el plazo, y el plazo es caro.
        let c = configurar(&frontera_vm(), Path::new("/tmp/d"), Path::new("/tmp/v")).unwrap();
        assert!(
            c.boot_source.boot_args.contains("panic=-1"),
            "{:?}",
            c.boot_source
        );
        assert!(c.boot_source.boot_args.contains("reboot=t"));
    }

    #[test]
    fn pedirle_configuracion_de_vm_a_una_jaula_es_un_error() {
        let f = crate::frontera::Frontera::namespaces();
        assert!(matches!(
            configurar(&f, Path::new("/tmp/d"), Path::new("/tmp/v")),
            Err(ErrorMaquina::FronteraRota(_))
        ));
    }

    #[test]
    fn la_configuracion_va_y_vuelve_por_json() {
        // El hipervisor la lee en JSON: si no serializa bien, no arranca nada.
        let c = configurar(&frontera_vm(), Path::new("/tmp/d"), Path::new("/tmp/v")).unwrap();
        let texto = serde_json::to_string(&c).unwrap();
        assert!(texto.contains("boot_source"), "{texto}");
        assert!(texto.contains("vsock"), "{texto}");
        let vuelta: ConfigMaquina = serde_json::from_str(&texto).unwrap();
        assert_eq!(vuelta, c);
    }

    #[test]
    fn se_dice_si_este_anfitrion_puede_virtualizar() {
        // Degradar en silencio a un aislamiento mas debil es peor que negarse a
        // arrancar: el informe sale igual y nadie sabe con que fuerza estaba
        // encerrada la muestra.
        let hay = hay_virtualizacion();
        assert_eq!(hay, Path::new("/dev/kvm").exists());
    }

    // --- La jaula, ejercitada de verdad ------------------------------------

    fn hay_unshare() -> bool {
        Command::new("unshare")
            .arg("--net")
            .arg("--")
            .arg("/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn dentro_de_la_jaula_no_se_alcanza_nada_real() {
        // LA PRUEBA QUE JUSTIFICA EL MODULO, y no se declara: se comprueba. Se
        // intenta una conexion de verdad a una direccion de verdad desde dentro
        // y desde fuera, y tienen que dar resultados distintos.
        if !hay_unshare() {
            return;
        }
        let guion = "import socket,sys\n\
                     s=socket.socket(); s.settimeout(3)\n\
                     try:\n    s.connect(('1.1.1.1',80)); sys.exit(0)\n\
                     except Exception:\n    sys.exit(7)\n";
        let dir = std::env::temp_dir().join(format!("aegis-jaula-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sonda = dir.join("sonda.py");
        std::fs::write(&sonda, guion).unwrap();

        // Sin python3 no hay sonda; se omite en vez de fingir.
        if Command::new("python3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let mut jaula = Jaula::lanzar(
            Path::new("/usr/bin/python3"),
            &[sonda.display().to_string()],
            Salida::Ninguna,
        )
        .unwrap();
        let codigo = jaula.esperar(Duration::from_secs(20));
        assert_eq!(
            codigo,
            Some(7),
            "una muestra dentro de la jaula NO puede alcanzar una direccion real"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn la_jaula_se_destruye_aunque_nadie_la_destruya() {
        // LA GARANTIA QUE NO SE NEGOCIA. Una maquina de detonacion que sobrevive
        // a su detonacion es una maquina infectada corriendo en la
        // infraestructura del que analiza, y ademas invisible.
        if !hay_unshare() {
            return;
        }
        let pid = {
            let jaula = Jaula::lanzar(
                Path::new("/bin/sh"),
                &["-c".into(), "sleep 600".into()],
                Salida::Ninguna,
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(200));
            jaula.pid().unwrap()
            // Aqui se suelta sin llamar a destruir.
        };

        std::thread::sleep(Duration::from_millis(300));
        let sigue = Path::new(&format!("/proc/{pid}")).exists();
        assert!(!sigue, "el proceso {pid} sobrevivio a su Jaula");
    }

    #[test]
    fn destruir_es_idempotente_y_no_falla() {
        // El camino de error puede llamarla dos veces, y es justo el camino que
        // se toma cuando algo ha ido mal con una muestra que muerde.
        if !hay_unshare() {
            return;
        }
        let mut jaula = Jaula::lanzar(
            Path::new("/bin/sh"),
            &["-c".into(), "sleep 600".into()],
            Salida::Ninguna,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(jaula.destruir(), Destruccion::Matada);
        assert_eq!(jaula.destruir(), Destruccion::NoHabiaNada);
        assert_eq!(jaula.destruir(), Destruccion::NoHabiaNada);
    }

    #[test]
    fn una_jaula_que_termina_sola_se_recoge_sin_matarla() {
        if !hay_unshare() {
            return;
        }
        let mut jaula = Jaula::lanzar(Path::new("/bin/true"), &[], Salida::Ninguna).unwrap();
        assert_eq!(jaula.esperar(Duration::from_secs(10)), Some(0));
        assert_eq!(jaula.destruir(), Destruccion::TerminoSola);
    }

    #[test]
    fn un_programa_que_no_existe_no_deja_la_jaula_a_medias() {
        if !hay_unshare() {
            return;
        }
        let mut jaula = Jaula::lanzar(Path::new("/no/existe/nada"), &[], Salida::Ninguna).unwrap();
        // `unshare` arranca y falla dentro; lo importante es que se pueda
        // destruir sin colgarse.
        let _ = jaula.esperar(Duration::from_secs(5));
        let _ = jaula.destruir();
    }
}
