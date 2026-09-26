//! Compilacion y aplicacion del sandbox.

use std::process::Command;
use std::sync::Arc;

use crate::error::SandboxError;
use crate::landlock::{self, Ruleset};
use crate::policy::SandboxPolicy;
use crate::seccomp::{self, SockFilter};

/// Lo que se acabo aplicando de verdad.
///
/// Se devuelve siempre, tambien cuando falta algo: quien despliega tiene que
/// poder saber que la maquina no puede ofrecer parte de la politica, en vez de
/// creer que esta protegido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Numero de llamadas al sistema bloqueadas por el filtro.
    pub blocked_syscalls: usize,
    /// Version de ABI de Landlock aplicada, si se aplico.
    pub landlock_abi: Option<u32>,
    /// Numero de rutas que recibieron una regla de verdad.
    pub allowed_paths: usize,
    /// Rutas de la politica que no admitian ni uno de los derechos pedidos.
    ///
    /// Ocurre cuando la politica pide derechos de directorio sobre algo que no
    /// lo es. La ruta queda PROHIBIDA, que es la direccion segura, pero quien
    /// despliega tiene que poder ver la diferencia entre lo que escribio y lo
    /// que el kernel acepto: contarla como permitida seria la mentira de
    /// siempre, que la politica y la realidad digan cosas distintas.
    pub skipped_paths: usize,
    /// Cierto si la restriccion de red de Landlock no cupo por ABI antigua.
    ///
    /// No es fatal: seccomp ya bloquea la red entera, y esta bandera solo dice
    /// que la capa redundante no esta.
    pub landlock_net_skipped: bool,
    /// Capacidades que se quitan del conjunto limite antes del `exec` (FASE 93).
    pub capacidades_quitadas: u32,
    /// Cierto si el perfil pedia quitar capacidades y este proceso no puede
    /// (le falta `CAP_SETPCAP`).
    ///
    /// No deja un hueco: sin privilegio, el hijo tampoco tiene capacidades que
    /// usar, y `no_new_privs` —que el filtro de seccomp pone siempre— impide que
    /// un binario `setuid` o con capacidades de fichero se las devuelva.
    pub capacidades_sin_privilegio: bool,
}

/// La ultima capacidad que conoce este kernel.
#[must_use]
pub fn ultima_capacidad() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(40)
}

/// Si el proceso actual puede quitar capacidades del conjunto limite: hace
/// falta `CAP_SETPCAP` (la 8) en el conjunto efectivo.
#[must_use]
pub fn puede_quitar_capacidades() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|c| c & (1 << 8) != 0)
}

/// Sandbox ya compilado, listo para aplicarse.
///
/// # Por que se compila aparte
///
/// Aplicar un sandbox al hijo de un `fork` obliga a hacerlo entre `fork` y
/// `exec`, donde solo se pueden usar funciones seguras en contexto de senal.
/// Reservar memoria ahi puede bloquearse para siempre: si otro hilo tenia el
/// bloqueo del asignador en el instante del `fork`, en el hijo ese bloqueo esta
/// tomado por un hilo que ya no existe.
///
/// Por eso todo lo que reserva memoria o abre ficheros —compilar el programa
/// BPF, abrir los directorios de las reglas, crear el conjunto de Landlock—
/// ocurre AQUI, antes de bifurcar. El descriptor del conjunto sobrevive al
/// `fork`, asi que en el hijo solo quedan tres llamadas al sistema.
#[derive(Debug)]
pub struct CompiledSandbox {
    programa: Vec<SockFilter>,
    ruleset: Option<Ruleset>,
    rutas: usize,
    rutas_sin_regla: usize,
    net_omitida: bool,
    bloqueadas: usize,
    quitar_capacidades: u64,
    capacidades_sin_privilegio: bool,
}

impl CompiledSandbox {
    /// Compila una politica.
    ///
    /// Falla si el kernel no admite seccomp: sin el no queda ninguna capa de
    /// aislamiento real, y devolver un sandbox vacio seria mentir. La ausencia
    /// de Landlock, en cambio, se tolera y se refleja en [`Applied`], porque
    /// seccomp por si solo ya recorta la superficie de forma sustancial.
    pub fn compile(p: &SandboxPolicy) -> Result<CompiledSandbox, SandboxError> {
        if !seccomp::available() {
            return Err(SandboxError::SeccompUnsupported);
        }
        let denegadas = p.denied_syscalls();
        let programa = seccomp::compile(&denegadas, p.denied_action);

        let mut rutas = 0usize;
        let mut rutas_sin_regla = 0usize;

        let abi = landlock::Abi::detect();
        // La red solo se puede gobernar con Landlock desde ABI 4. Por debajo, la
        // sigue cubriendo seccomp, que deniega `socket`, `connect`, `bind`,
        // `listen` y `accept`: la restriccion se aplica igual, lo que se pierde es
        // la segunda capa. Se declara en `Applied` en vez de callarlo.
        let net_gobernable = p.handled_net() != 0 && abi.is_some_and(landlock::Abi::supports_net);
        let net_omitida = p.handled_net() != 0 && !net_gobernable;

        // Solo se crea el conjunto de reglas si hay algo que gobernar CON ESTA
        // ABI. Antes bastaba con que la politica pidiera red, aunque la ABI no
        // pudiera darla: entonces `handled_access_fs` y `handled_access_net`
        // quedaban los dos a cero y el kernel rechazaba el conjunto vacio con
        // ENOMSG ("No message of desired type"), haciendo fallar la compilacion
        // entera de una politica que seccomp podia aplicar perfectamente.
        //
        // Le pasaba a cualquier politica sin rutas que prohibiera la red —como
        // `agent_helper`— en un kernel con Landlock ABI 3, que es lo que trae WSL2
        // y cualquier kernel anterior a 6.7.
        let ruleset = match abi {
            Some(abi) if !p.fs.is_empty() || net_gobernable => {
                let rs = Ruleset::new(abi, p.handled_fs(abi), p.handled_net())?;
                let mut anotar = |aplicada: bool| {
                    if aplicada {
                        rutas += 1;
                    } else {
                        rutas_sin_regla += 1;
                    }
                };
                for ruta in &p.fs.read_only {
                    anotar(rs.allow_path(ruta, landlock::LECTURA)?);
                }
                for ruta in &p.fs.read_write {
                    anotar(rs.allow_path(ruta, landlock::LECTURA | landlock::ESCRITURA)?);
                }
                Some(rs)
            }
            _ => None,
        };

        Ok(CompiledSandbox {
            bloqueadas: denegadas.len(),
            programa,
            ruleset,
            rutas,
            rutas_sin_regla,
            net_omitida,
            quitar_capacidades: 0,
            capacidades_sin_privilegio: false,
        })
    }

    /// Compila un sandbox a partir de las piezas de un perfil APRENDIDO (FASE
    /// 93): un programa de seccomp ya hecho —una lista blanca—, las rutas que el
    /// proceso uso, y las capacidades que necesita conservar.
    ///
    /// `capacidades_retenidas` en `None` no toca las capacidades; en
    /// `Some(mascara)` quita del conjunto limite todas las que no esten en la
    /// mascara, que es lo que hace que un servicio de root arranque sin las
    /// capacidades que nunca uso.
    ///
    /// # Errores
    /// Si el kernel no admite seccomp, o una regla de Landlock falla.
    pub fn desde_perfil(
        programa: Vec<SockFilter>,
        fs: &crate::policy::FsPolicy,
        capacidades_retenidas: Option<u64>,
    ) -> Result<CompiledSandbox, SandboxError> {
        if !seccomp::available() {
            return Err(SandboxError::SeccompUnsupported);
        }
        let mut rutas = 0usize;
        let mut rutas_sin_regla = 0usize;
        let ruleset = match landlock::Abi::detect() {
            Some(abi) if !fs.is_empty() => {
                let rs = Ruleset::new(abi, abi.supported_fs(), 0)?;
                for (lista, derechos) in [
                    (&fs.read_only, landlock::LECTURA),
                    (&fs.read_write, landlock::LECTURA | landlock::ESCRITURA),
                ] {
                    for ruta in lista {
                        if rs.allow_path(ruta, derechos)? {
                            rutas += 1;
                        } else {
                            rutas_sin_regla += 1;
                        }
                    }
                }
                Some(rs)
            }
            _ => None,
        };
        let (quitar_capacidades, capacidades_sin_privilegio) = match capacidades_retenidas {
            None => (0, false),
            Some(retenidas) => {
                let ultima = ultima_capacidad().min(63);
                let todas = if ultima == 63 {
                    u64::MAX
                } else {
                    (1u64 << (ultima + 1)) - 1
                };
                let quitar = todas & !retenidas;
                if quitar != 0 && !puede_quitar_capacidades() {
                    (0, true)
                } else {
                    (quitar, false)
                }
            }
        };
        Ok(CompiledSandbox {
            bloqueadas: 0,
            programa,
            ruleset,
            rutas,
            rutas_sin_regla,
            net_omitida: false,
            quitar_capacidades,
            capacidades_sin_privilegio,
        })
    }

    /// Programa BPF compilado, para poder auditarlo y probarlo.
    pub fn program(&self) -> &[SockFilter] {
        &self.programa
    }

    /// Resumen de lo que aplicaria.
    pub fn summary(&self) -> Applied {
        Applied {
            blocked_syscalls: self.bloqueadas,
            landlock_abi: self.ruleset.as_ref().map(|r| r.abi().0),
            allowed_paths: self.rutas,
            skipped_paths: self.rutas_sin_regla,
            landlock_net_skipped: self.net_omitida,
            capacidades_quitadas: self.quitar_capacidades.count_ones(),
            capacidades_sin_privilegio: self.capacidades_sin_privilegio,
        }
    }

    /// Aplica el sandbox al proceso ACTUAL. **Irreversible.**
    ///
    /// No hay forma de deshacerlo: es la propiedad que lo hace util, porque un
    /// sandbox reversible no confina a quien se propone salir de el.
    ///
    /// # Seguridad en contexto de senal
    ///
    /// No reserva memoria ni abre ficheros: solo llamadas al sistema sobre
    /// estructuras ya construidas. Se puede llamar entre `fork` y `exec`.
    ///
    /// # Orden
    ///
    /// Landlock va ANTES que seccomp. Al reves no funcionaria: la politica
    /// prohibe `landlock_add_rule`... no, prohibe cosas peores —el filtro se
    /// aplica a `landlock_restrict_self` igual que a cualquier otra llamada—, y
    /// mas importante, una vez instalado el filtro ya no se pueden abrir los
    /// descriptores que Landlock necesitaria.
    pub fn apply(&self) -> Result<Applied, SandboxError> {
        if let Some(rs) = &self.ruleset {
            landlock::restrict_self(rs.raw_fd())?;
        }
        // Las capacidades van ANTES que seccomp: un perfil aprendido no contiene
        // `prctl` si el programa no lo usaba, y el filtro lo bloquearia.
        for cap in 0..64u64 {
            if self.quitar_capacidades & (1 << cap) != 0 {
                // SAFETY: `prctl(PR_CAPBSET_DROP)` no toca memoria del proceso.
                let r =
                    unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
                if r != 0 {
                    return Err(SandboxError::Supervision {
                        op: "prctl(PR_CAPBSET_DROP)",
                        source: std::io::Error::last_os_error(),
                    });
                }
            }
        }
        seccomp::install(&self.programa)?;
        Ok(self.summary())
    }

    /// Prepara un comando para que se ejecute dentro del sandbox.
    ///
    /// El sandbox se aplica en el hijo, despues del `fork` y antes del `exec`,
    /// de modo que el binario nace ya confinado y no existe ni un instante en el
    /// que corra sin restringir.
    pub fn confine<'c>(self: &Arc<Self>, cmd: &'c mut Command) -> &'c mut Command {
        let yo = Arc::clone(self);
        // SAFETY: el cierre solo ejecuta llamadas al sistema sobre estructuras
        // ya construidas —el programa BPF y el descriptor del conjunto de
        // reglas—, sin reservar memoria ni tomar bloqueos, que es lo que exige
        // el contrato de `pre_exec`.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(cmd, move || {
                yo.apply()
                    .map(|_| ())
                    .map_err(|e| std::io::Error::other(e.to_string()))
            })
        }
    }
}
