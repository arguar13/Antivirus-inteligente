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

use crate::capacidades::{self, Capacidades, SondeoBpf, Tri};
pub use crate::capacidades::{planificar, PlanSondas, SondaOmitida};
use crate::error::TelemetryError;

/// Objeto eBPF empotrado en el binario en tiempo de compilacion.
///
/// Va empotrado y no como fichero suelto en disco: un `.o` junto al binario es
/// algo que un atacante con permisos de escritura puede sustituir por su propia
/// telemetria, y el agente lo cargaria sin saberlo.
const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_probes.bpf.o"));

/// Firma HMAC-SHA256 del bytecode empotrado, calculada en la compilacion por
/// `build.rs` (FASE 14). El cargador la recalcula sobre [`BPF_OBJECT`] y la
/// compara antes de entregar el programa al kernel: si la region del `.o` dentro
/// del binario del agente fue parcheada, la firma no coincide y la carga se
/// rechaza.
const BPF_OBJECT_HMAC: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_probes.hmac"));

/// Clave con la que se firmo el bytecode (la de desarrollo, o la de produccion
/// pasada por entorno en la compilacion). Se emite junto a la firma para que la
/// verificacion use exactamente la misma.
const BPF_OBJECT_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_probes.key"));

/// Verifica la integridad del bytecode empotrado antes de cargarlo.
///
/// Es el primer paso de `run`, antes incluso del preflight: cargar en el kernel
/// un programa cuya firma no cuadra es exactamente lo que hay que impedir, y no
/// tiene sentido comprobar el entorno para un binario en el que ya no se confia.
fn verificar_integridad_bytecode() -> Result<(), TelemetryError> {
    let clave = descifrar_hex(BPF_OBJECT_KEY.trim()).ok_or(TelemetryError::BytecodeTampered)?;
    let esperado = descifrar_hex(BPF_OBJECT_HMAC.trim()).ok_or(TelemetryError::BytecodeTampered)?;
    let calculado = aegis_kguard::integrity::hmac_sha256(&clave, BPF_OBJECT);
    if aegis_kguard::integrity::constant_time_eq(&calculado, &esperado) {
        Ok(())
    } else {
        Err(TelemetryError::BytecodeTampered)
    }
}

fn descifrar_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Ruta del BTF del kernel. Sin el, CO-RE no puede reubicar los accesos.
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Pregunta directamente al kernel, por `bpf()`, que tipos de mapa y de programa
/// admite. Necesita privilegios; sin ellos cada respuesta es `Desconocido` con el
/// errno, que es la verdad: no se pudo preguntar.
pub fn sondear() -> SondeoBpf {
    fn tri(r: libbpf_rs::Result<bool>) -> Tri {
        match r {
            Ok(true) => Tri::Si,
            Ok(false) => Tri::No,
            Err(e) => Tri::Desconocido(e.to_string()),
        }
    }
    SondeoBpf {
        ringbuf: tri(libbpf_rs::MapType::RingBuf.is_supported()),
        tracepoint: tri(libbpf_rs::ProgramType::Tracepoint.is_supported()),
        xdp: tri(libbpf_rs::ProgramType::Xdp.is_supported()),
        lsm: tri(libbpf_rs::ProgramType::Lsm.is_supported()),
    }
}

/// Las capacidades del kernel en el que corre el agente: lectura de `/sys` y
/// `/proc` mas el sondeo directo por `bpf()`.
pub fn capacidades() -> Capacidades {
    capacidades::detectar_en(Path::new("/"), sondear())
}

/// Verifica que el entorno puede sostener la telemetria de kernel.
///
/// Solo falla ante lo que la BLOQUEA entera (sin BTF, sin tracefs, sin
/// ringbuf); lo que solo quita una familia no es un fallo, es una degradacion,
/// y la resuelve [`planificar`] sonda a sonda. Devuelve las capacidades para que
/// quien llama las declare.
pub fn preflight() -> Result<Capacidades, TelemetryError> {
    let caps = capacidades();
    if !caps.btf {
        return Err(TelemetryError::NoKernelBtf(PathBuf::from(KERNEL_BTF)));
    }
    if caps.tracefs.is_none() {
        return Err(TelemetryError::TracefsUnavailable(PathBuf::from(
            "/sys/kernel/tracing",
        )));
    }
    if caps.sondeo.ringbuf == Tri::No {
        return Err(TelemetryError::NoRingbuf);
    }
    Ok(caps)
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

/// Contadores leidos del kernel tras una sesion de consumo, y el plan de sondas
/// con el que se consumio.
#[derive(Debug, Default, Clone)]
pub struct KernelStats {
    /// Eventos emitidos.
    pub emitted: u64,
    /// Eventos perdidos por ring lleno.
    pub dropped_full: u64,
    /// Eventos filtrados por politica en el kernel.
    pub filtered: u64,
    /// Cadenas truncadas.
    pub truncated: u64,
    /// Que sondas estuvieron vivas y que familias quedaron sin datos.
    pub plan: PlanSondas,
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
    // Integridad ANTES que nada: no se carga un bytecode en el que no se confia,
    // y no tiene sentido comprobar el entorno para un binario ya sospechoso.
    verificar_integridad_bytecode()?;

    let caps = preflight()?;
    let tracefs = caps
        .tracefs
        .clone()
        .ok_or_else(|| TelemetryError::TracefsUnavailable(PathBuf::from("/sys/kernel/tracing")))?;

    let mut builder_obj = ObjectBuilder::default();
    let mut open = builder_obj.open_memory(BPF_OBJECT).map_err(map_err)?;

    // El plan sale de las secciones ELF del objeto REAL: si manana se anade una
    // sonda, entra en el plan sin tocar ninguna lista.
    let secciones: Vec<(String, String)> = open
        .progs()
        .map(|p| {
            (
                p.name().to_string_lossy().into_owned(),
                p.section().to_string_lossy().into_owned(),
            )
        })
        .collect();
    let mut plan = planificar(
        secciones.iter().map(|(n, s)| (n.as_str(), s.as_str())),
        // libbpf lee este fichero para obtener el id de perf del tracepoint.
        |tp| tracefs.join("events").join(tp).join("id").is_file(),
    );
    if plan.activos.is_empty() {
        return Err(TelemetryError::NoProbes);
    }
    // Nunca en silencio: cada sonda que no se engancha y cada familia que se
    // queda ciega se dicen ANTES de empezar a consumir, no al terminar.
    for o in &plan.omitidos {
        eprintln!(
            "aegis-agent: DEGRADADO sonda={} tracepoint={}: {}",
            o.programa, o.tracepoint, o.motivo
        );
    }
    for f in &plan.familias_sin_datos {
        eprintln!(
            "aegis-agent: DEGRADADO familia={} sin sondas vivas: su telemetria es SinDatos",
            f.nombre()
        );
    }
    for mut prog in open.progs_mut() {
        let vivo = plan.activos.iter().any(|a| OsStr::new(a) == prog.name());
        if !vivo {
            prog.set_autoload(false);
        }
    }

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
    let mut enganchadas: Vec<String> = Vec::new();
    let mut primer_fallo: Option<TelemetryError> = None;
    // progs_mut y no progs: attach() solo existe sobre la vista mutable del
    // programa, porque enganchar modifica el estado del objeto BPF.
    for prog in obj.progs_mut() {
        let nombre = prog.name().to_string_lossy().into_owned();
        if !plan.activos.contains(&nombre) {
            continue;
        }
        match prog.attach() {
            Ok(link) => {
                links.push(link);
                enganchadas.push(nombre);
            }
            // Una sonda que el kernel o la politica (SELinux, lockdown) no dejan
            // enganchar se omite y se DECLARA, igual que la que no tiene
            // tracepoint: la doctrina es degradar por familia, no abortar. Antes
            // el primer -EACCES tumbaba el agente entero (visto en Rocky 9 con
            // SELinux en enforcing, FASE 0 del MP-15).
            Err(e) => {
                eprintln!("aegis-agent: DEGRADADO sonda={nombre} no se pudo enganchar: {e}");
                let tracepoint = secciones
                    .iter()
                    .find(|(n, _)| *n == nombre)
                    .map(|(_, s)| s.trim_start_matches("tracepoint/").to_string())
                    .unwrap_or_default();
                plan.omitidos.push(SondaOmitida {
                    familia: capacidades::familia_de_programa(&nombre),
                    programa: nombre.clone(),
                    tracepoint,
                    motivo: format!("el enganche fallo: {e}"),
                });
                primer_fallo.get_or_insert(TelemetryError::ProbeAttach {
                    probe: nombre,
                    detail: e.to_string(),
                });
            }
        }
    }
    // Sin ninguna sonda viva no hay agente: eso SI es un error, el del primer
    // enganche que fallo.
    if links.is_empty() {
        return Err(primer_fallo.unwrap_or(TelemetryError::NoProbes));
    }
    let antes = plan.familias_sin_datos.clone();
    plan.activos = enganchadas;
    plan.recalcular_familias();
    for f in plan
        .familias_sin_datos
        .iter()
        .filter(|f| !antes.contains(f))
    {
        eprintln!(
            "aegis-agent: DEGRADADO familia={} sin sondas vivas: su telemetria es SinDatos",
            f.nombre()
        );
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
        plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La puerta que impide que una sonda nueva se degrade en silencio: se abre el
    /// objeto REAL empotrado (abrir no carga nada, no hace falta kernel ni
    /// privilegios) y todo programa tiene que tener familia. Si no la tuviera, al
    /// faltar su tracepoint no habria familia que declarar como `SinDatos`.
    #[test]
    fn todo_programa_del_objeto_real_tiene_familia_y_es_tracepoint() {
        let mut b = ObjectBuilder::default();
        let open = b
            .open_memory(BPF_OBJECT)
            .expect("el objeto empotrado se abre sin kernel");
        let mut n = 0;
        for p in open.progs() {
            n += 1;
            let nombre = p.name().to_string_lossy().into_owned();
            assert!(
                capacidades::familia_de_programa(&nombre).is_some(),
                "la sonda {nombre} no tiene familia: su degradacion no podria declararse"
            );
            assert!(
                p.section().to_string_lossy().starts_with("tracepoint/"),
                "{nombre}: el plan solo sabe comprobar tracepoints"
            );
        }
        assert!(n > 0, "el objeto empotrado no tiene programas");
    }
}
