//! Carga y control del filtro XDP.
//!
//! Este modulo es el plano de CONTROL: carga el programa, escribe su
//! configuracion y gestiona la lista de bloqueo. El plano de DATOS esta
//! integramente en el kernel, porque un paquete que tiene que subir a userland
//! para decidirse ya ha pagado el coste que XDP existe para evitar.
//!
//! Las busquedas de mapa por nombre se repiten en cada operacion en vez de
//! cachearse. Es deliberado: cachear un `Map` obligaria a una estructura
//! autorreferencial sobre el `Object`, y estas operaciones son de control (un
//! puñado por segundo como mucho), no de datos.

use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::time::Duration;

use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder};

use crate::error::NetError;

/// Objeto XDP compilado y empotrado en el binario.
const XDP_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_xdp.bpf.o"));

/// Accion que devuelve el programa XDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    /// Descartar el paquete antes del stack TCP/IP.
    Drop,
    /// Dejarlo continuar.
    Pass,
    /// Devolverlo por la misma interfaz.
    Tx,
    /// Abortar (error del programa).
    Aborted,
    /// Codigo no reconocido.
    Other(u32),
}

impl XdpAction {
    /// Convierte el valor de retorno del programa.
    pub fn from_code(code: u32) -> XdpAction {
        match code {
            0 => XdpAction::Aborted,
            1 => XdpAction::Drop,
            2 => XdpAction::Pass,
            3 => XdpAction::Tx,
            otro => XdpAction::Other(otro),
        }
    }
}

/// Motivo por el que una direccion esta bloqueada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Bloqueo introducido por un operador.
    Manual = 1,
    /// Barrido de puertos.
    PortScan = 2,
    /// Trafico de mando y control.
    CommandAndControl = 3,
    /// Exfiltracion de datos.
    Exfiltration = 4,
}

impl BlockReason {
    fn from_code(c: u32) -> BlockReason {
        match c {
            2 => BlockReason::PortScan,
            3 => BlockReason::CommandAndControl,
            4 => BlockReason::Exfiltration,
            _ => BlockReason::Manual,
        }
    }
}

/// Configuracion del filtro.
#[derive(Debug, Clone, Copy)]
pub struct XdpConfig {
    /// Filtro activo.
    pub enabled: bool,
    /// Bloquear automaticamente al detectar un barrido.
    ///
    /// **Desactivado por defecto y debe seguir estandolo salvo decision
    /// explicita.** La IP origen de un SYN se falsifica trivialmente, asi que
    /// el bloqueo automatico es el mecanismo con el que un atacante consigue
    /// que bloqueemos a un tercero: basta con enviar un barrido con la IP de
    /// origen del servidor DNS o de la puerta de enlace.
    pub autoblock: bool,
    /// Ventana del detector de barridos en el kernel.
    pub scan_window: Duration,
    /// Puertos distintos (cota inferior) que definen un barrido.
    pub scan_port_threshold: u32,
    /// SYN minimos en la ventana.
    pub scan_syn_threshold: u32,
    /// Duracion del bloqueo automatico.
    pub autoblock_duration: Duration,
    /// Uno de cada cuantos SYN se envia a userland. 0 = ninguno.
    pub syn_sample_rate: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            autoblock: false,
            scan_window: Duration::from_secs(1),
            scan_port_threshold: 15,
            scan_syn_threshold: 15,
            autoblock_duration: Duration::from_secs(300),
            syn_sample_rate: 8,
        }
    }
}

/// Espejo de `struct aegis_xdp_config`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct XdpConfigRaw {
    flags: u32,
    scan_window_ns: u64,
    scan_port_threshold: u32,
    scan_syn_threshold: u32,
    autoblock_ns: u64,
    syn_sample_rate: u32,
    reserved: u32,
}

const CFG_ENABLED: u32 = 0x0000_0001;
const CFG_AUTOBLOCK: u32 = 0x0000_0002;

// El kernel lee esta estructura por cada paquete. Una divergencia de layout no
// produce un error: produce un filtro que lee umbrales en los campos
// equivocados y deja de detectar.
const _: () = assert!(std::mem::size_of::<XdpConfigRaw>() == 40);

/// Espejo de `struct aegis_block_entry`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct BlockEntryRaw {
    until_ns: u64,
    hits: u64,
    reason: u32,
    pad: u32,
}

const _: () = assert!(std::mem::size_of::<BlockEntryRaw>() == 24);

/// Entrada de la lista de bloqueo.
#[derive(Debug, Clone, Copy)]
pub struct BlockEntry {
    /// Direccion bloqueada.
    pub address: Ipv4Addr,
    /// Motivo.
    pub reason: BlockReason,
    /// Paquetes descartados por esta entrada.
    pub hits: u64,
    /// Nanosegundos de vida restantes, o `None` si el bloqueo es permanente.
    pub remaining_ns: Option<u64>,
}

/// Contadores del filtro.
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    /// Paquetes inspeccionados.
    pub packets: u64,
    /// SYN observados.
    pub syn: u64,
    /// Paquetes descartados.
    pub dropped: u64,
    /// Barridos detectados.
    pub scans: u64,
    /// Eventos emitidos a userland.
    pub events: u64,
    /// Eventos perdidos por ring lleno.
    pub events_dropped: u64,
    /// Paquetes IPv6 que pasaron sin inspeccionar.
    ///
    /// No es cero por descuido: el filtro solo analiza IPv4. Se cuenta para que
    /// el punto ciego sea visible; uno que nadie mide es uno que nadie arregla.
    pub ipv6_uninspected: u64,
}

/// Nanosegundos desde el arranque, en la misma base que `bpf_ktime_get_boot_ns`.
///
/// Usar `SystemTime` aqui seria un error silencioso: el kernel marca los plazos
/// con el reloj monotono de arranque, y compararlos contra la hora de pared
/// haria que un ajuste de NTP caducara o eternizara los bloqueos.
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` solo escribe en la estructura que se le pasa, que
    // esta correctamente inicializada y viva durante toda la llamada.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if r != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Filtro XDP cargado.
pub struct XdpFilter {
    obj: Object,
}

impl std::fmt::Debug for XdpFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpFilter").finish_non_exhaustive()
    }
}

fn map_err(e: libbpf_rs::Error) -> NetError {
    NetError::Bpf(e.to_string())
}

impl XdpFilter {
    /// Carga el programa XDP y aplica la configuracion.
    ///
    /// No lo engancha a ninguna interfaz: cargar y enganchar son operaciones
    /// distintas a proposito, porque cargar es seguro y enganchar afecta al
    /// trafico de una interfaz real.
    pub fn load(config: &XdpConfig) -> Result<XdpFilter, NetError> {
        let mut builder = ObjectBuilder::default();
        let open = builder.open_memory(XDP_OBJECT).map_err(map_err)?;
        let obj = open.load().map_err(|e| {
            if e.kind() == libbpf_rs::ErrorKind::PermissionDenied {
                NetError::InsufficientPrivileges
            } else {
                map_err(e)
            }
        })?;

        let filtro = XdpFilter { obj };
        filtro.configure(config)?;
        Ok(filtro)
    }

    fn map(&self, nombre: &str) -> Result<libbpf_rs::Map<'_>, NetError> {
        self.obj
            .maps()
            .find(|m| m.name() == OsStr::new(nombre))
            .ok_or_else(|| NetError::MissingMap(nombre.to_string()))
    }

    /// Escribe la configuracion en el mapa que lee el programa.
    pub fn configure(&self, config: &XdpConfig) -> Result<(), NetError> {
        let mut flags = 0;
        if config.enabled {
            flags |= CFG_ENABLED;
        }
        if config.autoblock {
            flags |= CFG_AUTOBLOCK;
        }
        let raw = XdpConfigRaw {
            flags,
            scan_window_ns: config.scan_window.as_nanos() as u64,
            scan_port_threshold: config.scan_port_threshold,
            scan_syn_threshold: config.scan_syn_threshold,
            autoblock_ns: config.autoblock_duration.as_nanos() as u64,
            syn_sample_rate: config.syn_sample_rate,
            reserved: 0,
        };
        // SAFETY: `XdpConfigRaw` es `#[repr(C)]` y solo contiene enteros sin
        // signo, asi que su representacion en memoria son exactamente los bytes
        // que espera el mapa.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const XdpConfigRaw as *const u8,
                std::mem::size_of::<XdpConfigRaw>(),
            )
        };
        self.map("aegis_xdp_config")?
            .update(&0u32.to_ne_bytes(), bytes, MapFlags::ANY)
            .map_err(map_err)
    }

    /// Engancha el filtro a una interfaz por nombre.
    ///
    /// Devuelve el enlace, que hay que mantener vivo: al soltarlo el filtro se
    /// desengancha y el trafico deja de inspeccionarse.
    pub fn attach(&mut self, ifname: &str) -> Result<libbpf_rs::Link, NetError> {
        let ifindex = if_nametoindex(ifname)?;
        let prog = self
            .obj
            .progs_mut()
            .find(|p| p.name() == OsStr::new("aegis_xdp_filter"))
            .ok_or_else(|| NetError::MissingProgram("aegis_xdp_filter".into()))?;
        prog.attach_xdp(ifindex as i32).map_err(map_err)
    }

    /// Ejecuta el programa contra una trama sintetica, sin engancharlo a
    /// ninguna interfaz.
    ///
    /// Es la forma correcta de probar un filtro XDP: generar trafico real
    /// depende del entorno y arriesga la conectividad de la maquina, mientras
    /// que esto ejercita el mismo codigo de kernel de forma determinista.
    pub fn test_packet(&mut self, frame: &[u8]) -> Result<XdpAction, NetError> {
        // XDP exige espacio de cabecera y de cola en el buffer: el kernel
        // reserva sitio para metadatos y para el skb_shared_info.
        let mut buffer = vec![0u8; frame.len().max(64) + 256];
        buffer[..frame.len()].copy_from_slice(frame);

        let prog = self
            .obj
            .progs_mut()
            .find(|p| p.name() == OsStr::new("aegis_xdp_filter"))
            .ok_or_else(|| NetError::MissingProgram("aegis_xdp_filter".into()))?;

        let mut salida = vec![0u8; buffer.len()];
        let entrada = libbpf_rs::ProgramInput {
            data_in: Some(&buffer[..frame.len()]),
            data_out: Some(&mut salida),
            ..Default::default()
        };
        let out = prog.test_run(entrada).map_err(map_err)?;
        Ok(XdpAction::from_code(out.return_value))
    }

    /// Bloquea una direccion.
    ///
    /// `ttl` a `None` significa bloqueo permanente hasta que se retire.
    pub fn block(
        &self,
        addr: Ipv4Addr,
        ttl: Option<Duration>,
        reason: BlockReason,
    ) -> Result<(), NetError> {
        let entrada = BlockEntryRaw {
            until_ns: match ttl {
                Some(d) => boottime_ns() + d.as_nanos() as u64,
                None => 0,
            },
            hits: 0,
            reason: reason as u32,
            pad: 0,
        };
        // SAFETY: POD `#[repr(C)]` de enteros sin signo.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &entrada as *const BlockEntryRaw as *const u8,
                std::mem::size_of::<BlockEntryRaw>(),
            )
        };
        // La clave es la direccion en orden de RED, que es como la ve el
        // programa XDP al leerla del paquete.
        self.map("aegis_blocklist")?
            .update(&u32::from(addr).to_be_bytes(), bytes, MapFlags::ANY)
            .map_err(map_err)
    }

    /// Retira una direccion de la lista de bloqueo.
    pub fn unblock(&self, addr: Ipv4Addr) -> Result<(), NetError> {
        self.map("aegis_blocklist")?
            .delete(&u32::from(addr).to_be_bytes())
            .map_err(map_err)
    }

    /// Indica si una direccion esta bloqueada y con cuantos aciertos.
    pub fn block_entry(&self, addr: Ipv4Addr) -> Result<Option<BlockEntry>, NetError> {
        let m = self.map("aegis_blocklist")?;
        let Some(bytes) = m
            .lookup(&u32::from(addr).to_be_bytes(), MapFlags::ANY)
            .map_err(map_err)?
        else {
            return Ok(None);
        };
        Ok(Some(decode_block_entry(addr, &bytes)))
    }

    /// Devuelve la lista de bloqueo completa.
    pub fn blocklist(&self) -> Result<Vec<BlockEntry>, NetError> {
        let m = self.map("aegis_blocklist")?;
        let mut salida = Vec::new();
        for clave in m.keys() {
            if clave.len() != 4 {
                continue;
            }
            let Some(bytes) = m.lookup(&clave, MapFlags::ANY).map_err(map_err)? else {
                continue;
            };
            let addr = Ipv4Addr::from([clave[0], clave[1], clave[2], clave[3]]);
            salida.push(decode_block_entry(addr, &bytes));
        }
        salida.sort_by_key(|e| e.address);
        Ok(salida)
    }

    /// Lee los contadores del filtro.
    pub fn stats(&self) -> Result<XdpStats, NetError> {
        let m = self.map("aegis_xdp_stats")?;
        let leer = |i: u32| -> u64 {
            match m.lookup_percpu(&i.to_ne_bytes(), MapFlags::ANY) {
                Ok(Some(v)) => v
                    .iter()
                    .map(|b| {
                        let mut buf = [0u8; 8];
                        let n = b.len().min(8);
                        buf[..n].copy_from_slice(&b[..n]);
                        u64::from_ne_bytes(buf)
                    })
                    .sum(),
                _ => 0,
            }
        };
        Ok(XdpStats {
            packets: leer(0),
            syn: leer(1),
            dropped: leer(2),
            scans: leer(3),
            events: leer(4),
            events_dropped: leer(5),
            ipv6_uninspected: leer(6),
        })
    }

    /// Nombre del mapa de eventos, para construir el consumidor del ring.
    pub fn events_map_name() -> &'static str {
        "aegis_net_events"
    }

    /// Acceso al objeto cargado, para consumir el ring buffer.
    pub fn object(&self) -> &Object {
        &self.obj
    }
}

fn decode_block_entry(addr: Ipv4Addr, bytes: &[u8]) -> BlockEntry {
    let mut raw = BlockEntryRaw::default();
    let n = bytes.len().min(std::mem::size_of::<BlockEntryRaw>());
    // SAFETY: se copian como mucho `size_of::<BlockEntryRaw>()` bytes sobre una
    // estructura POD ya inicializada; todo patron de bits es valido para ella.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), &mut raw as *mut BlockEntryRaw as *mut u8, n);
    }
    let ahora = boottime_ns();
    BlockEntry {
        address: addr,
        reason: BlockReason::from_code(raw.reason),
        hits: raw.hits,
        remaining_ns: if raw.until_ns == 0 {
            None
        } else {
            Some(raw.until_ns.saturating_sub(ahora))
        },
    }
}

/// Resuelve el indice de una interfaz por su nombre.
fn if_nametoindex(nombre: &str) -> Result<u32, NetError> {
    let c = std::ffi::CString::new(nombre)
        .map_err(|_| NetError::UnknownInterface(nombre.to_string()))?;
    // SAFETY: `c` es una cadena C valida y viva durante la llamada.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(NetError::UnknownInterface(nombre.to_string()));
    }
    Ok(idx)
}
