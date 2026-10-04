//! Emulaciones REALES, benignas y reversibles, de tecnicas ATT&CK, hechas con
//! `std` y utilidades del sistema.
//!
//! # La diferencia con el catalogo de marcadores
//!
//! [`crate::catalogo`] materializa un fichero marcador: sirve para medir la
//! cobertura que PERMITEN los motores, sin ataque. Esto, en cambio, ejecuta el
//! gesto de verdad —exec, cron, persistencia, cifrado, baliza, ocultacion— para
//! que el agente publicado tenga algo REAL que ver. Solo corre dentro del binario
//! del rango, en la microVM, contra el agente en marcha.
//!
//! # Sigue siendo benigno y reversible, por contrato
//!
//! Cada emulacion implementa [`Tecnica`], asi que [`Tecnica::revertir`] no tiene
//! cuerpo por defecto: una que no sepa deshacerse no compila. Lo que se toca fuera
//! de la jaula (cron del usuario, `sshd_config`) se copia antes y se restaura
//! despues; los procesos que se lanzan son propios y de vida corta (`/bin/true`,
//! `sleep`); el cifrado es un XOR reversible sobre ficheros creados por la propia
//! emulacion en la jaula. Nada persiste tras [`revertir`].

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use aegis_entidad::{entidad, Eid, Motor};

use crate::rango::{ErrorRango, Plataforma, PruebaDeRango, Rango};
use crate::tecnica::{Tactica, Tecnica};

const SOLO_LINUX: &[Plataforma] = &[Plataforma::Linux];

/// Una emulacion lista para la prueba en vivo: la tecnica, cuanto hay que esperar
/// a que el agente reaccione, y el patron que delata su señal en el journal.
pub struct Emulacion {
    /// La tecnica que se ejecuta.
    pub tecnica: Box<dyn Tecnica>,
    /// Segundos que la prueba espera una señal del agente tras ejecutar.
    pub ventana_s: u64,
    /// Subcadena que tiene que aparecer en el `porque` de la señal del motor
    /// esperado para contarla como detectada. Vacia = basta con que firme el motor.
    pub patron: String,
}

impl Emulacion {
    fn nueva(tecnica: Box<dyn Tecnica>, ventana_s: u64, patron: impl Into<String>) -> Emulacion {
        Emulacion {
            tecnica,
            ventana_s,
            patron: patron.into(),
        }
    }
}

/// Las emulaciones reales: ninguna necesita llamadas al sistema crudas.
///
/// `destino_baliza` es la direccion (no loopback) de la VM a la que baliza la
/// emulacion de mando y control: la calcula el binario segun la IP de la microVM.
#[must_use]
pub fn catalogo_seguro(destino_baliza: &str) -> Vec<Emulacion> {
    vec![
        Emulacion::nueva(Box::new(Cron::nueva()), 30, "ScheduledTask"),
        Emulacion::nueva(Box::new(PersistenciaSsh::nueva()), 45, "PermitRootLogin"),
        Emulacion::nueva(Box::new(CifradoMasivo::nuevo()), 30, "secuestro de datos"),
        Emulacion::nueva(
            Box::new(BalizaTcp::nueva(destino_baliza)),
            30,
            destino_baliza.to_string(),
        ),
        Emulacion::nueva(Box::new(OcultacionBind::nueva()), 90, "oculto-en-userland"),
    ]
}

// ── utilidades comunes ────────────────────────────────────────────────────────

/// Ejecuta una orden y falla ruidosamente si no sale con exito.
fn correr(programa: &str, args: &[&str]) -> Result<(), ErrorRango> {
    let salida = Command::new(programa)
        .args(args)
        .output()
        .map_err(|e| ErrorRango::Es(io::Error::new(e.kind(), format!("{programa}: {e}"))))?;
    if salida.status.success() {
        Ok(())
    } else {
        Err(ErrorRango::Es(io::Error::other(format!(
            "{programa} salio con {}: {}",
            salida.status,
            String::from_utf8_lossy(&salida.stderr).trim()
        ))))
    }
}

/// La entidad estable de una tecnica real, separada de la del marcador.
fn entidad_de(id: &str) -> Eid {
    entidad::contenido(&format!("rango-real:{id}"))
}

/// Un subdirectorio propio de la tecnica dentro de la jaula, recien creado.
fn dir_tecnica(rango: &Rango, id: &str) -> Result<PathBuf, ErrorRango> {
    let seguro: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let d = rango.raiz().join(format!("real_{seguro}"));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

// ── T1053.003 — cron ────────────────────────────────────────────────────────

/// Persistencia por tarea programada: instala un `crontab` benigno para el
/// usuario actual y lo restaura. Lo que el agente ve es el `exec` de `crontab`
/// (tecnica conductual `ScheduledTask`).
struct Cron;

impl Cron {
    fn nueva() -> Cron {
        Cron
    }

    /// El crontab guardado antes de tocar nada.
    fn respaldo(rango: &Rango) -> PathBuf {
        rango.raiz().join("real_T1053_003").join("crontab.orig")
    }

    fn marca() -> &'static str {
        "# aegis-rango T1053.003"
    }
}

impl Tecnica for Cron {
    fn id(&self) -> &str {
        "T1053.003"
    }
    fn nombre(&self) -> &str {
        "cron"
    }
    fn tactica(&self) -> Tactica {
        Tactica::Persistencia
    }
    fn plataformas(&self) -> &[Plataforma] {
        SOLO_LINUX
    }
    fn deteccion_esperada(&self) -> Motor {
        Motor::Conductual
    }
    fn entidad_afectada(&self, _r: &Rango) -> Eid {
        entidad_de(self.id())
    }

    fn ejecutar(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let dir = dir_tecnica(rango, self.id())?;
        // El crontab anterior (puede no haber ninguno: entonces el respaldo queda
        // vacio y la reversion lo interpreta como «no habia»).
        let actual = Command::new("crontab").arg("-l").output();
        let contenido = actual
            .ok()
            .filter(|o| o.status.success())
            .map(|o| o.stdout)
            .unwrap_or_default();
        std::fs::write(Cron::respaldo(rango), &contenido)?;
        // El nuevo crontab: lo de antes mas una linea benigna marcada.
        let nuevo = dir.join("crontab.nuevo");
        let mut texto = String::from_utf8_lossy(&contenido).into_owned();
        if !texto.is_empty() && !texto.ends_with('\n') {
            texto.push('\n');
        }
        texto.push_str(&format!("* * * * * /bin/true {}\n", Cron::marca()));
        std::fs::write(&nuevo, texto)?;
        correr("crontab", &[nuevo.to_str().unwrap_or_default()])
    }

    fn revertir(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let respaldo = Cron::respaldo(rango);
        let previo = std::fs::read(&respaldo).unwrap_or_default();
        if previo.is_empty() {
            // No habia crontab: se borra el que pusimos. `crontab -r` sin crontab
            // devuelve error en algunas distros; se tolera.
            let _ = Command::new("crontab").arg("-r").output();
            Ok(())
        } else {
            correr("crontab", &[respaldo.to_str().unwrap_or_default()])
        }
    }

    fn exito(&self, _rango: &Rango) -> bool {
        Command::new("crontab")
            .arg("-l")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains(Cron::marca()))
    }
}

// ── T1098.004 — persistencia SSH (authorized_keys / sshd_config) ────────────

/// Puerta trasera en la configuracion de SSH: añade `PermitRootLogin yes` a
/// `sshd_config` (con copia y restauracion) y una clave marcada en un
/// `authorized_keys` de prueba dentro de la jaula. Lo ve la integridad de ficheros
/// de configuracion (firma conductual).
struct PersistenciaSsh;

impl PersistenciaSsh {
    fn nueva() -> PersistenciaSsh {
        PersistenciaSsh
    }
    fn cfg() -> &'static Path {
        Path::new("/etc/ssh/sshd_config")
    }
    fn marca() -> &'static str {
        "PermitRootLogin yes # aegis-rango T1098.004"
    }
    fn respaldo(rango: &Rango) -> PathBuf {
        rango.raiz().join("real_T1098_004").join("sshd_config.orig")
    }
}

impl Tecnica for PersistenciaSsh {
    fn id(&self) -> &str {
        "T1098.004"
    }
    fn nombre(&self) -> &str {
        "persistencia ssh (authorized_keys/sshd_config)"
    }
    fn tactica(&self) -> Tactica {
        Tactica::Persistencia
    }
    fn plataformas(&self) -> &[Plataforma] {
        SOLO_LINUX
    }
    fn deteccion_esperada(&self) -> Motor {
        Motor::Conductual
    }
    fn entidad_afectada(&self, _r: &Rango) -> Eid {
        entidad_de(self.id())
    }

    fn ejecutar(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let dir = dir_tecnica(rango, self.id())?;
        // authorized_keys de prueba, dentro de la jaula (benigno, reversible al
        // borrar el directorio de la tecnica).
        let ssh = dir.join(".ssh");
        std::fs::create_dir_all(&ssh)?;
        std::fs::write(
            ssh.join("authorized_keys"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEGISRANGObenignotestkeyNOUSARENPRODUCCION aegis-rango\n",
        )?;
        // sshd_config: copia y directiva marcada. Si la imagen no trae sshd, no
        // hay nada que respaldar y la tecnica no aplica en esta imagen.
        if PersistenciaSsh::cfg().is_file() {
            std::fs::copy(PersistenciaSsh::cfg(), PersistenciaSsh::respaldo(rango))?;
            let mut txt = std::fs::read_to_string(PersistenciaSsh::cfg())?;
            if !txt.ends_with('\n') {
                txt.push('\n');
            }
            txt.push_str(PersistenciaSsh::marca());
            txt.push('\n');
            std::fs::write(PersistenciaSsh::cfg(), txt)?;
        }
        Ok(())
    }

    fn revertir(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let respaldo = PersistenciaSsh::respaldo(rango);
        if respaldo.is_file() {
            std::fs::copy(&respaldo, PersistenciaSsh::cfg())?;
        }
        let _ = std::fs::remove_dir_all(rango.raiz().join("real_T1098_004").join(".ssh"));
        Ok(())
    }

    fn exito(&self, rango: &Rango) -> bool {
        let clave = rango
            .raiz()
            .join("real_T1098_004")
            .join(".ssh")
            .join("authorized_keys")
            .is_file();
        let cfg = std::fs::read_to_string(PersistenciaSsh::cfg())
            .map(|t| t.contains("aegis-rango T1098.004"))
            .unwrap_or(false);
        clave || cfg
    }
}

// ── T1486 — cifrado masivo (ransomware), en la jaula ────────────────────────

/// Cifrado masivo dentro de la jaula: crea ficheros, los reescribe con un XOR de
/// alta entropia y los renombra con extension de rescate, rapido. Es lo que el
/// motor de secuestro cruza (velocidad + entropia + renombrados). Reversible: el
/// XOR es su propia inversa y se deshace con la misma clave.
struct CifradoMasivo;

impl CifradoMasivo {
    fn nuevo() -> CifradoMasivo {
        CifradoMasivo
    }
    const FICHEROS: usize = 64;
    const EXT: &'static str = ".aegiscrypt";

    /// Flujo de clave determinista (xorshift): la reversion usa el mismo.
    fn keystream(semilla: u64, n: usize) -> Vec<u8> {
        let mut e = semilla | 1;
        (0..n)
            .map(|_| {
                e ^= e << 13;
                e ^= e >> 7;
                e ^= e << 17;
                (e & 0xff) as u8
            })
            .collect()
    }

    fn cifrar(dir: &Path, deshacer: bool) -> Result<usize, ErrorRango> {
        let mut tocados = 0;
        for i in 0..CifradoMasivo::FICHEROS {
            let claro = dir.join(format!("documento_{i:03}.txt"));
            let cifrado = dir.join(format!("documento_{i:03}.txt{}", CifradoMasivo::EXT));
            let (origen, destino) = if deshacer {
                (&cifrado, &claro)
            } else {
                (&claro, &cifrado)
            };
            if !origen.is_file() {
                continue;
            }
            let datos = std::fs::read(origen)?;
            let ks = CifradoMasivo::keystream(0x5ee_d000 + i as u64, datos.len());
            let transformado: Vec<u8> = datos.iter().zip(ks).map(|(b, k)| b ^ k).collect();
            std::fs::write(destino, &transformado)?;
            std::fs::remove_file(origen)?;
            tocados += 1;
        }
        Ok(tocados)
    }
}

impl Tecnica for CifradoMasivo {
    fn id(&self) -> &str {
        "T1486"
    }
    fn nombre(&self) -> &str {
        "cifrado masivo de datos (ransomware) en la jaula"
    }
    fn tactica(&self) -> Tactica {
        Tactica::Impacto
    }
    fn plataformas(&self) -> &[Plataforma] {
        SOLO_LINUX
    }
    fn deteccion_esperada(&self) -> Motor {
        Motor::Conductual
    }
    fn entidad_afectada(&self, _r: &Rango) -> Eid {
        entidad_de(self.id())
    }

    fn ejecutar(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let dir = dir_tecnica(rango, self.id())?;
        // Datos «de la victima»: texto normal, entropia baja.
        for i in 0..CifradoMasivo::FICHEROS {
            let contenido = format!(
                "documento de prueba numero {i}\nlinea de texto ordinario, entropia baja\n"
            )
            .repeat(16);
            std::fs::write(dir.join(format!("documento_{i:03}.txt")), contenido)?;
        }
        let n = CifradoMasivo::cifrar(&dir, false)?;
        if n == 0 {
            return Err(ErrorRango::Inconsistente {
                tecnica: self.id().to_string(),
                que: "no cifro ningun fichero",
            });
        }
        Ok(())
    }

    fn revertir(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let dir = dir_tecnica(rango, self.id())?;
        // Se descifra lo que quede y se borra el directorio entero: no debe quedar
        // ni un fichero de rescate.
        let _ = CifradoMasivo::cifrar(&dir, true);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    fn exito(&self, rango: &Rango) -> bool {
        let dir = rango.raiz().join("real_T1486");
        std::fs::read_dir(&dir).ok().is_some_and(|it| {
            it.filter_map(Result::ok).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with(CifradoMasivo::EXT)
            })
        })
    }
}

// ── T1071.001 — baliza TCP con jitter ───────────────────────────────────────

/// Baliza de mando y control: un servidor TCP propio en la VM y conexiones
/// periodicas con jitter hacia el (por la IP no-loopback de la VM, que es lo que
/// baliza mira: el loopback lo ignora). El motor l7hunter lo delata por el ritmo.
struct BalizaTcp {
    destino: String,
}

impl BalizaTcp {
    fn nueva(destino: &str) -> BalizaTcp {
        BalizaTcp {
            destino: destino.to_string(),
        }
    }
    /// Conexiones que se hacen: bastante por encima del minimo de intervalos que
    /// el detector exige para pronunciarse.
    const CONEXIONES: usize = 16;
    /// Intervalo base entre conexiones, en milisegundos.
    const BASE_MS: u64 = 5_000;
}

impl Tecnica for BalizaTcp {
    fn id(&self) -> &str {
        "T1071.001"
    }
    fn nombre(&self) -> &str {
        "baliza de protocolo de aplicacion con jitter"
    }
    fn tactica(&self) -> Tactica {
        Tactica::MandoYControl
    }
    fn plataformas(&self) -> &[Plataforma] {
        SOLO_LINUX
    }
    fn deteccion_esperada(&self) -> Motor {
        Motor::L7Hunter
    }
    fn entidad_afectada(&self, _r: &Rango) -> Eid {
        entidad_de(self.id())
    }

    fn ejecutar(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        use std::io::Write as _;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let dir = dir_tecnica(rango, self.id())?;
        std::fs::write(dir.join("activa"), b"1")?;

        // Servidor propio: acepta y descarta. Se cierra cuando el listener se
        // suelta al terminar `ejecutar`.
        let puerto: u16 = self
            .destino
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8443);
        let escucha = TcpListener::bind(("0.0.0.0", puerto))?;
        escucha.set_nonblocking(true)?;

        let mut e: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut jitter = || {
            e ^= e << 13;
            e ^= e >> 7;
            e ^= e << 17;
            (e % 10_000) as f64 / 10_000.0
        };

        for _ in 0..BalizaTcp::CONEXIONES {
            // Un intento de conexion a la IP no-loopback de la VM: eso es lo que
            // ven las sondas como `connect` con destino privado.
            if let Ok(mut s) = TcpStream::connect(&self.destino) {
                let _ = s.write_all(b"aegis-rango baliza\n");
            }
            // Se drena lo que haya entrado, sin bloquear.
            while escucha.accept().is_ok() {}
            // U[BASE*(1-J), BASE] con J = 0,3.
            let espera = (BalizaTcp::BASE_MS as f64 * (1.0 - 0.3 * jitter())) as u64;
            std::thread::sleep(Duration::from_millis(espera.max(1)));
        }
        Ok(())
    }

    fn revertir(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        // La baliza no deja artefacto: el servidor y el bucle terminaron con
        // `ejecutar`. Solo se borra la marca.
        let _ = std::fs::remove_dir_all(rango.raiz().join("real_T1071_001"));
        Ok(())
    }

    fn exito(&self, rango: &Rango) -> bool {
        rango.raiz().join("real_T1071_001").join("activa").is_file()
    }
}

// ── T1564 — ocultacion por bind-mount sobre /proc/<pid> ─────────────────────

/// Ocultacion en espacio de usuario: se lanza un `sleep` propio y se monta un
/// directorio vacio encima de su `/proc/<pid>`, que lo esconde de cualquiera que
/// lea `/proc` sin tocar el kernel. El motor nucleo lo caza como
/// `oculto-en-userland`. Reversible: `umount` y matar al proceso.
struct OcultacionBind;

impl OcultacionBind {
    fn nueva() -> OcultacionBind {
        OcultacionBind
    }
    fn fichero_pid(rango: &Rango) -> PathBuf {
        rango.raiz().join("real_T1564").join("pid")
    }
}

impl Tecnica for OcultacionBind {
    fn id(&self) -> &str {
        "T1564"
    }
    fn nombre(&self) -> &str {
        "ocultacion por bind-mount sobre /proc"
    }
    fn tactica(&self) -> Tactica {
        Tactica::EvasionDefensiva
    }
    fn plataformas(&self) -> &[Plataforma] {
        SOLO_LINUX
    }
    fn deteccion_esperada(&self) -> Motor {
        // Requiere que se aplique parche_nucleo.py (FASE 2): Motor::Nucleo.
        Motor::Nucleo
    }
    fn entidad_afectada(&self, _r: &Rango) -> Eid {
        entidad_de(self.id())
    }

    fn ejecutar(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let dir = dir_tecnica(rango, self.id())?;
        let vacio = dir.join("vacio");
        std::fs::create_dir_all(&vacio)?;
        // Proceso propio de vida larga, que se matara en la reversion.
        let hijo = Command::new("sleep").arg("600").spawn()?;
        let pid = hijo.id();
        std::fs::write(OcultacionBind::fichero_pid(rango), pid.to_string())?;
        // Se le da un instante a /proc/<pid> para existir.
        std::thread::sleep(std::time::Duration::from_millis(200));
        correr(
            "mount",
            &[
                "--bind",
                vacio.to_str().unwrap_or_default(),
                &format!("/proc/{pid}"),
            ],
        )
    }

    fn revertir(&self, _p: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        if let Ok(txt) = std::fs::read_to_string(OcultacionBind::fichero_pid(rango)) {
            if let Ok(pid) = txt.trim().parse::<u32>() {
                let _ = Command::new("umount").arg(format!("/proc/{pid}")).output();
                let _ = Command::new("kill").arg(pid.to_string()).output();
            }
        }
        let _ = std::fs::remove_dir_all(rango.raiz().join("real_T1564"));
        Ok(())
    }

    fn exito(&self, rango: &Rango) -> bool {
        // El proceso oculto sigue vivo mientras la emulacion este activa; tras
        // revertir, el fichero de pid ya no esta y esto es falso.
        std::fs::read_to_string(OcultacionBind::fichero_pid(rango))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            .is_some_and(|pid| Path::new(&format!("/proc/{pid}/stat")).exists())
    }
}
