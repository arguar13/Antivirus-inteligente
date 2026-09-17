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
        let mut net_omitida = false;
        let ruleset = match landlock::Abi::detect() {
            Some(abi) if !p.fs.is_empty() || p.handled_net() != 0 => {
                if p.handled_net() != 0 && !abi.supports_net() {
                    net_omitida = true;
                }
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
