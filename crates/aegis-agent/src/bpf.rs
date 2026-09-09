//! Carga de los programas eBPF y consumo del ring buffer.
//!
//! Es la unica parte del agente que necesita privilegios, BTF y un kernel real.
//! Se mantiene deliberadamente delgada: aqui no hay logica de deteccion, solo
//! el transporte. Todo lo que decide vive en [`crate::triage`] y
//! [`crate::graph`], que se prueban sin kernel.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use libbpf_rs::{Link, MapCore, MapFlags, ObjectBuilder, RingBufferBuilder};

use crate::error::TelemetryError;

/// Objeto eBPF empotrado en el binario en tiempo de compilacion.
///
/// Va empotrado y no como fichero suelto en disco: un `.o` junto al binario es
/// algo que un atacante con permisos de escritura puede sustituir por su propia
/// telemetria, y el agente lo cargaria sin saberlo.
const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_probes.bpf.o"));

/// Ruta del BTF del kernel. Sin el, CO-RE no puede reubicar los accesos.
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Punto de montaje de tracefs. libbpf resuelve ahi el identificador de perf de
/// cada tracepoint antes de poder engancharlo.
const TRACEFS: &str = "/sys/kernel/tracing";

/// Tracepoints que las sondas necesitan, en la forma `categoria/evento`.
///
/// La lista se comprueba ANTES de intentar el enganche. Sin esta comprobacion,
/// un kernel sin `CONFIG_FTRACE_SYSCALLS` o un contenedor sin tracefs montado
/// producen un `-ENOENT` de libbpf que no dice que falta ni como arreglarlo.
const TRACEPOINTS_REQUERIDOS: [&str; 9] = [
    "syscalls/sys_enter_execve",
    "syscalls/sys_enter_openat",
    "syscalls/sys_exit_openat",
    "syscalls/sys_enter_ptrace",
    "syscalls/sys_enter_write",
    "syscalls/sys_enter_rename",
    "syscalls/sys_enter_renameat2",
    "sched/sched_process_exit",
    "sock/inet_sock_set_state",
];

/// Verifica que el entorno puede sostener las sondas.
///
/// Se ejecuta antes de cargar nada. Diagnosticar aqui, con el remedio concreto
/// en el mensaje, evita que un despliegue falle en produccion con un errno.
pub fn preflight() -> Result<(), TelemetryError> {
    let btf = Path::new(KERNEL_BTF);
    if !btf.exists() {
        return Err(TelemetryError::NoKernelBtf(PathBuf::from(KERNEL_BTF)));
    }

    let tracefs = Path::new(TRACEFS);
    if !tracefs.join("events").is_dir() {
        return Err(TelemetryError::TracefsUnavailable(PathBuf::from(TRACEFS)));
    }

    for tp in TRACEPOINTS_REQUERIDOS {
        // libbpf lee este fichero para obtener el id de perf del tracepoint.
        if !tracefs.join("events").join(tp).join("id").is_file() {
            return Err(TelemetryError::TracepointMissing { name: tp });
        }
    }

    Ok(())
}

/// Espejo de `struct aegis_bpf_config` de `aegis_bpf_common.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct BpfConfigRaw {
    agent_pid: u32,
    flags: u32,
    min_write_bytes: u32,
    write_distinct_threshold: u32,
}

/// Banderas de configuracion, espejo de `AEGIS_CFG_*`.
pub mod cfg_flags {
    /// Habilita la emision de eventos.
    pub const ENABLED: u32 = 0x0000_0001;
    /// Habilita la sonda de ficheros.
    pub const TRACE_FILES: u32 = 0x0000_0002;
    /// Habilita la sonda de red.
    pub const TRACE_NET: u32 = 0x0000_0004;
    /// Habilita la sonda de ptrace.
    pub const TRACE_PTRACE: u32 = 0x0000_0008;
    /// Habilita la sonda de escrituras, base de la deteccion de ransomware.
    pub const TRACE_WRITES: u32 = 0x0000_0010;
    /// Habilita la sonda de renombrados.
    pub const TRACE_RENAME: u32 = 0x0000_0020;
}

/// Indices del mapa de estadisticas, espejo de `enum aegis_stat`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BpfStat {
    /// Eventos emitidos al ring.
    Emitted = 0,
    /// Eventos perdidos por ring lleno. Cualquier valor distinto de cero es un
    /// punto ciego de deteccion, no una metrica de rendimiento.
    DroppedFull = 1,
    /// Eventos descartados por politica dentro del kernel.
    Filtered = 2,
    /// Cadenas truncadas por longitud.
    Truncated = 3,
}

/// Configuracion del origen de telemetria.
#[derive(Debug, Clone)]
pub struct SourceConfig {
    /// PID del propio agente, que se excluye de la telemetria.
    pub agent_pid: u32,
    /// Sondas activas.
    pub flags: u32,
    /// Tiempo maximo de espera en cada sondeo del ring buffer.
    pub poll_timeout: Duration,
    /// Tamano minimo de escritura que se emite, salvo alta entropia.
    ///
    /// Sin este filtro, cada linea que un proceso escribe en su registro genera
    /// un evento y el ruido de un servidor normal ahoga el ring.
    pub min_write_bytes: u32,
    /// Valores de byte distintos, sobre la muestra de 512 bytes, a partir de
    /// los cuales el kernel considera el buffer candidato a cifrado.
    ///
    /// Texto plano da 60-90 valores distintos; datos cifrados, 230-256. El
    /// umbral separa ambos con holgura sin necesitar logaritmos, que en eBPF no
    /// existen: la entropia exacta se calcula despues en Ring 3.
    pub write_distinct_threshold: u32,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            agent_pid: std::process::id(),
            flags: cfg_flags::ENABLED
                | cfg_flags::TRACE_FILES
                | cfg_flags::TRACE_NET
                | cfg_flags::TRACE_PTRACE
                | cfg_flags::TRACE_WRITES
                | cfg_flags::TRACE_RENAME,
            // 200 ms acota lo que tarda el agente en atender un apagado o la
            // rotacion de reglas cuando no hay trafico, sin gastar CPU en
            // espera activa.
            poll_timeout: Duration::from_millis(200),
            min_write_bytes: 4096,
            write_distinct_threshold: 200,
        }
    }
}

/// Contadores leidos del kernel tras una sesion de consumo.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelStats {
    /// Eventos emitidos.
    pub emitted: u64,
    /// Eventos perdidos por ring lleno.
    pub dropped_full: u64,
    /// Eventos filtrados por politica en el kernel.
    pub filtered: u64,
    /// Cadenas truncadas.
    pub truncated: u64,
}

fn map_err(e: libbpf_rs::Error) -> TelemetryError {
    TelemetryError::BpfLoad(e.to_string())
}

/// Suma un contador `PERCPU_ARRAY` a lo largo de todas las CPU.
fn read_percpu_sum(map: &dyn MapCore, index: u32) -> u64 {
    let key = index.to_ne_bytes();
    match map.lookup_percpu(&key, MapFlags::ANY) {
        Ok(Some(valores)) => valores
            .iter()
            .map(|v| {
                let mut buf = [0u8; 8];
                let n = v.len().min(8);
                buf[..n].copy_from_slice(&v[..n]);
                u64::from_ne_bytes(buf)
            })
            .sum(),
        _ => 0,
    }
}

/// Carga las sondas, las engancha y consume el ring buffer hasta que `stop`
/// se ponga a cierto.
///
/// `on_record` recibe cada registro crudo del ABI. No se decodifica aqui a
/// proposito: el callback del ring buffer corre en el camino caliente y su
/// unica responsabilidad debe ser entregar los bytes.
///
/// Devuelve los contadores del kernel al terminar. Que `dropped_full` sea mayor
/// que cero significa que el agente no drenaba lo bastante rapido y hubo
/// eventos que nunca se vieron.
pub fn run<F>(
    config: &SourceConfig,
    stop: &AtomicBool,
    mut on_record: F,
) -> Result<KernelStats, TelemetryError>
where
    F: FnMut(&[u8]),
{
    preflight()?;

    let mut builder_obj = ObjectBuilder::default();
    let open = builder_obj.open_memory(BPF_OBJECT).map_err(map_err)?;
    let obj = open.load().map_err(|e| {
        // EPERM al cargar casi siempre es falta de capacidades, no un programa
        // invalido: el verificador ya paso en tiempo de compilacion.
        if e.kind() == libbpf_rs::ErrorKind::PermissionDenied {
            TelemetryError::InsufficientPrivileges
        } else {
            map_err(e)
        }
    })?;

    // --- Configuracion: se escribe ANTES de enganchar las sondas ---------
    // Si se enganchara primero, existiria una ventana en la que los programas
    // corren con agent_pid = 0 y el agente se observa a si mismo, que es
    // exactamente la realimentacion positiva que la configuracion evita.
    let cfg_map = obj
        .maps()
        .find(|m| m.name() == OsStr::new("aegis_config"))
        .ok_or_else(|| TelemetryError::BpfLoad("falta el mapa aegis_config".into()))?;

    let raw = BpfConfigRaw {
        agent_pid: config.agent_pid,
        flags: config.flags,
        min_write_bytes: config.min_write_bytes,
        write_distinct_threshold: config.write_distinct_threshold,
    };
    // SAFETY: `BpfConfigRaw` es `#[repr(C)]` y solo contiene enteros sin signo,
    // asi que su representacion en memoria es exactamente los bytes que espera
    // el mapa del kernel.
    let raw_bytes = unsafe {
        std::slice::from_raw_parts(
            &raw as *const BpfConfigRaw as *const u8,
            std::mem::size_of::<BpfConfigRaw>(),
        )
    };
    cfg_map
        .update(&0u32.to_ne_bytes(), raw_bytes, MapFlags::ANY)
        .map_err(map_err)?;

    // --- Enganche de las sondas -----------------------------------------
    // Los enlaces tienen que seguir vivos mientras se consume: al soltarlos,
    // libbpf desengancha el programa y la telemetria se apaga en silencio.
    let mut links: Vec<Link> = Vec::new();
    // progs_mut y no progs: attach() solo existe sobre la vista mutable del
    // programa, porque enganchar modifica el estado del objeto BPF.
    for prog in obj.progs_mut() {
        let nombre = prog.name().to_string_lossy().into_owned();
        let link = prog
            .attach()
            .map_err(|e: libbpf_rs::Error| TelemetryError::ProbeAttach {
                probe: nombre,
                detail: e.to_string(),
            })?;
        links.push(link);
    }

    // --- Consumo ---------------------------------------------------------
    let events_map = obj
        .maps()
        .find(|m| m.name() == OsStr::new("aegis_events"))
        .ok_or_else(|| TelemetryError::BpfLoad("falta el mapa aegis_events".into()))?;

    let stats_map = obj
        .maps()
        .find(|m| m.name() == OsStr::new("aegis_stats"))
        .ok_or_else(|| TelemetryError::BpfLoad("falta el mapa aegis_stats".into()))?;

    {
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&events_map, |data: &[u8]| {
                on_record(data);
                0
            })
            .map_err(map_err)?;
        let rb = rb_builder.build().map_err(map_err)?;

        while !stop.load(Ordering::Relaxed) {
            match rb.poll(config.poll_timeout) {
                Ok(()) => {}
                Err(e) => {
                    // EINTR es normal: llega una senal durante el sondeo. Solo
                    // se aborta ante un error real del canal.
                    if e.kind() == libbpf_rs::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(map_err(e));
                }
            }
        }
    }

    Ok(KernelStats {
        emitted: read_percpu_sum(&stats_map, BpfStat::Emitted as u32),
        dropped_full: read_percpu_sum(&stats_map, BpfStat::DroppedFull as u32),
        filtered: read_percpu_sum(&stats_map, BpfStat::Filtered as u32),
        truncated: read_percpu_sum(&stats_map, BpfStat::Truncated as u32),
    })
}
