//! Espejo en Rust de `shared/include/aegis_abi.h`.
//!
//! Cada `struct` de este modulo tiene que coincidir **byte a byte** con su
//! equivalente en C: es la misma memoria, escrita por el driver y leida por el
//! agente. Las aserciones `const _` de este fichero verifican tamanos y offsets
//! en tiempo de compilacion, y `tools/abi-check.sh` compara ademas el layout
//! real que produce el compilador de C con el que produce rustc, de forma que
//! una divergencia rompe la build en vez de corromper telemetria en produccion.

#![allow(non_camel_case_types)]

use core::mem::{offset_of, size_of};

/// Version del ABI. Se incrementa si cambia o se reordena cualquier campo.
pub const AEGIS_ABI_VERSION: u16 = 1;
/// Magic del bloque de control del ring (`"AGIS"` en little-endian).
pub const AEGIS_RING_MAGIC: u32 = 0x5349_4741;
/// Magic de cada cabecera de evento (`"AEVT"` en little-endian).
pub const AEGIS_EVT_MAGIC: u32 = 0x5456_4541;

/// Tipos de evento que cruzan la frontera de privilegio.
pub mod evt {
    /// Relleno hasta el final del buffer: garantiza que ningun registro se parte.
    pub const PADDING: u16 = 0xFFFF;
    /// Creacion de proceso.
    pub const PROCESS_CREATE: u16 = 0x0001;
    /// Terminacion de proceso.
    pub const PROCESS_EXIT: u16 = 0x0002;
    /// Creacion de hilo.
    pub const THREAD_CREATE: u16 = 0x0003;
    /// Carga de imagen (EXE/DLL/.so).
    pub const IMAGE_LOAD: u16 = 0x0004;
    /// Pre-operacion de apertura/creacion de fichero (puede bloquear).
    pub const FILE_PRE_CREATE: u16 = 0x0010;
    /// Escritura de fichero.
    pub const FILE_WRITE: u16 = 0x0011;
    /// Renombrado de fichero.
    pub const FILE_RENAME: u16 = 0x0012;
    /// Borrado de fichero.
    pub const FILE_DELETE: u16 = 0x0013;
    /// Escritura de valor de registro.
    pub const REGISTRY_SET: u16 = 0x0020;
    /// Borrado de clave/valor de registro.
    pub const REGISTRY_DELETE: u16 = 0x0021;
    /// Reserva de memoria en otro proceso.
    pub const REMOTE_ALLOC: u16 = 0x0030;
    /// Escritura de memoria en otro proceso.
    pub const REMOTE_WRITE: u16 = 0x0031;
    /// Cambio de proteccion de memoria en otro proceso.
    pub const REMOTE_PROTECT: u16 = 0x0032;
    /// Creacion de hilo remoto o encolado de APC.
    pub const REMOTE_THREAD: u16 = 0x0033;
    /// Solicitud de handle sobre proceso/hilo (`ObRegisterCallbacks`).
    pub const HANDLE_REQUEST: u16 = 0x0034;
    /// Conexion de red saliente.
    pub const NET_CONNECT: u16 = 0x0040;
    /// Syscall ejecutado desde una region anomala.
    pub const SYSCALL_ANOMALY: u16 = 0x0050;
    /// Intento de manipulacion contra el propio EDR.
    pub const TAMPER_ATTEMPT: u16 = 0x0060;
}

/// Flags de la cabecera de evento.
pub mod flags {
    /// El productor esta bloqueado esperando un veredicto.
    pub const NEEDS_VERDICT: u32 = 0x0000_0001;
    /// El payload se recorto por limite de tamano.
    pub const TRUNCATED: u32 = 0x0000_0002;
    /// El actor es codigo de kernel, no un proceso de usuario.
    pub const KERNEL_ACTOR: u32 = 0x0000_0004;
    /// Las cadenas del evento estan en UTF-16LE (Windows).
    pub const UTF16: u32 = 0x0000_0008;
}

/// Acciones que el agente puede devolver en un veredicto.
pub mod action {
    /// Permitir la operacion.
    pub const ALLOW: u32 = 0;
    /// Denegar la operacion (`STATUS_VIRUS_INFECTED` / `-EPERM`).
    pub const BLOCK: u32 = 1;
    /// Denegar y poner el fichero en cuarentena.
    pub const QUARANTINE: u32 = 2;
    /// Congelar el proceso para triaje.
    pub const SUSPEND: u32 = 3;
    /// Terminar el proceso.
    pub const KILL: u32 = 4;
}

/// Nivel de integridad del token (Windows) o contexto de credenciales (Linux).
pub mod integrity {
    /// Untrusted.
    pub const UNTRUSTED: u16 = 0;
    /// Low (procesos en sandbox, navegadores).
    pub const LOW: u16 = 1;
    /// Medium: el nivel de un usuario interactivo normal.
    pub const MEDIUM: u16 = 2;
    /// High: elevado.
    pub const HIGH: u16 = 3;
    /// System.
    pub const SYSTEM: u16 = 4;
}

/// Flags de [`AegisImageLoad`].
pub mod img_flags {
    /// La imagen no esta respaldada por un fichero en disco.
    pub const UNBACKED: u32 = 0x0000_0001;
    /// Se mapeo en una base distinta de la preferida.
    pub const RELOCATED: u32 = 0x0000_0002;
    /// Proviene de `\KnownDlls`.
    pub const KNOWNDLL: u32 = 0x0000_0004;
    /// Se cargo desde una ruta de red.
    pub const REMOTE: u32 = 0x0000_0008;
}

/// Flags de [`AegisRemoteMem`].
pub mod mem_flags {
    /// Region con permisos de lectura, escritura y ejecucion simultaneos.
    pub const RWX: u32 = 0x0000_0001;
    /// Memoria privada ejecutable, sin fichero que la respalde.
    pub const UNBACKED: u32 = 0x0000_0002;
    /// La operacion cruza sesiones de terminal.
    pub const CROSS_SESSION: u32 = 0x0000_0004;
    /// Transicion RW -> RX: el patron clasico de escribir shellcode y luego
    /// hacerlo ejecutable para no dejar nunca una region RWX visible.
    pub const RX_TRANSITION: u32 = 0x0000_0008;
}

/// Flags de [`AegisSyscallAnomaly`].
pub mod sys_flags {
    /// La direccion de retorno cae en memoria privada.
    pub const UNBACKED_CALLER: u32 = 0x0000_0001;
    /// La direccion de retorno esta fuera de ntdll.
    pub const NOT_NTDLL: u32 = 0x0000_0002;
    /// Se reutilizo un gadget `syscall` de ntdll (syscall indirecto).
    pub const INDIRECT: u32 = 0x0000_0004;
    /// El `.text` de ntdll difiere de la copia limpia: unhooking.
    pub const HOOK_REMOVED: u32 = 0x0000_0008;
}

/// Referencia a una cadena dentro del evento: `(offset, len)` desde el inicio
/// de la cabecera. Nunca hay terminador NUL y nunca hay punteros.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AegisStr {
    /// Offset en bytes desde el inicio de la cabecera del evento.
    pub off: u16,
    /// Longitud en bytes.
    pub len: u16,
}

/// Cabecera de evento: exactamente una linea de cache.
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug)]
pub struct AegisEvtHdr {
    /// [`AEGIS_EVT_MAGIC`].
    pub magic: u32,
    /// [`AEGIS_ABI_VERSION`] con la que se produjo el evento.
    pub abi_version: u16,
    /// Uno de los valores de [`evt`].
    pub ty: u16,
    /// Cabecera + payload + cadenas, multiplo de 8.
    pub total_len: u32,
    /// Combinacion de [`flags`].
    pub flags: u32,
    /// Secuencia monotona por CPU: permite detectar perdida de eventos.
    pub seq: u64,
    /// Marca de tiempo en nanosegundos desde el arranque.
    pub ts_ns: u64,
    /// Clave estable del proceso que ejecuta la accion.
    pub actor_key: u64,
    /// Clave estable del objetivo, o 0 si no aplica.
    pub target_key: u64,
    /// CPU productora, necesaria para reordenar por `seq`.
    pub cpu: u32,
    /// Identificador de veredicto si [`flags::NEEDS_VERDICT`] esta activo.
    pub verdict_id: u32,
    /// Reservado, debe ser 0 en ABI v1.
    pub reserved: u64,
}

/// Payload de creacion de proceso.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisProcCreate {
    /// Padre reportado por el sistema operativo.
    pub parent_key: u64,
    /// Proceso que realmente invoco la creacion. Si difiere de `parent_key`,
    /// hay suplantacion de proceso padre (PPID spoofing).
    pub creator_key: u64,
    /// FNV-1a del path canonico de la imagen.
    pub image_id: u64,
    /// Instante de creacion, en unidades de 100 ns del sistema operativo.
    pub create_time: u64,
    /// PID del proceso creado.
    pub pid: u32,
    /// PID del padre reportado.
    pub parent_pid: u32,
    /// Sesion de terminal.
    pub session_id: u32,
    /// Flags del token: elevado, restringido, AppContainer, etc.
    pub token_flags: u32,
    /// Nivel de integridad del token.
    pub integrity_level: u16,
    /// Nivel de firma de la imagen (`SE_SIGNING_LEVEL_*`).
    pub signature_level: u16,
    /// Ruta de la imagen.
    pub image_path: AegisStr,
    /// Linea de comandos.
    pub cmdline: AegisStr,
    /// SID (Windows) o `uid:gid` (Linux) del usuario.
    pub user_sid: AegisStr,
}

/// Payload de carga de imagen.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisImageLoad {
    /// Direccion base donde se mapeo la imagen.
    pub image_base: u64,
    /// Tamano mapeado.
    pub image_size: u64,
    /// FNV-1a del path canonico.
    pub image_id: u64,
    /// PID que carga la imagen.
    pub pid: u32,
    /// Flags `AEGIS_IMG_F_*`.
    pub flags: u32,
    /// Nivel de firma.
    pub signature_level: u16,
    /// Tipo de firma (catalogo, embebida, ...).
    pub signature_type: u16,
    /// Ruta de la imagen.
    pub image_path: AegisStr,
    /// Reservado.
    pub reserved: u64,
}

/// Payload de operacion de fichero.
///
/// `entropy_before` y `entropy_after` usan punto fijo Q8.8 (entropia * 256):
/// 8.0 bits/byte se codifica como 2048.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisFileOp {
    /// `FILE_ID_128` (parte baja) en Windows, inode en Linux.
    pub file_id: u64,
    /// Identificador de volumen.
    pub volume_id: u64,
    /// Bytes escritos en esta operacion.
    pub bytes_written: u64,
    /// PID que opera.
    pub pid: u32,
    /// Acceso solicitado.
    pub desired_access: u32,
    /// Opciones de creacion.
    pub create_options: u32,
    /// Flags informativos de la operacion.
    pub info_flags: u32,
    /// Entropia previa en Q8.8.
    pub entropy_before: u16,
    /// Entropia posterior en Q8.8.
    pub entropy_after: u16,
    /// Ruta del fichero.
    pub path: AegisStr,
    /// Ruta destino en un renombrado.
    pub new_path: AegisStr,
    /// Reservado.
    pub reserved0: u32,
    /// Reservado.
    pub reserved1: u64,
}

/// Payload de manipulacion de memoria en un proceso remoto.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisRemoteMem {
    /// Clave estable del proceso objetivo.
    pub target_key: u64,
    /// Direccion afectada.
    pub address: u64,
    /// Tamano de la region.
    pub region_size: u64,
    /// PID que origina la operacion.
    pub source_pid: u32,
    /// PID objetivo.
    pub target_pid: u32,
    /// `MEM_COMMIT | MEM_RESERVE`.
    pub alloc_type: u32,
    /// Proteccion solicitada.
    pub protect: u32,
    /// Proteccion previa (en cambios de proteccion).
    pub prev_protect: u32,
    /// Flags `AEGIS_MEM_F_*`.
    pub flags: u32,
}

/// Payload de anomalia de syscall.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisSyscallAnomaly {
    /// Direccion de retorno desde la que se ejecuto el syscall.
    pub return_address: u64,
    /// Base de la region que contiene esa direccion.
    pub region_base: u64,
    /// Tamano de esa region.
    pub region_size: u64,
    /// PID.
    pub pid: u32,
    /// TID.
    pub tid: u32,
    /// System Service Number invocado.
    pub ssn: u32,
    /// Proteccion de la region.
    pub region_protect: u32,
    /// `MEM_IMAGE`, `MEM_PRIVATE` o `MEM_MAPPED`.
    pub region_type: u32,
    /// Flags `AEGIS_SYS_F_*`.
    pub flags: u32,
}

/// Respuesta del agente a una operacion pendiente de veredicto.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AegisVerdict {
    /// Identificador de la peticion, copiado de la cabecera.
    pub verdict_id: u64,
    /// Deteccion que lo motiva, 0 si ninguna.
    pub detection_id: u64,
    /// Una de las constantes de [`action`].
    pub action: u32,
    /// Codigo de motivo para telemetria y UI.
    pub reason: u32,
}

/// Bloque de control del ring buffer SPSC en memoria compartida.
///
/// Las tres lineas de cache son disjuntas a proposito: productor y consumidor
/// escriben en lineas distintas, de modo que publicar un evento no invalida la
/// linea que el otro lado esta leyendo.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct AegisRingCtrl {
    /// [`AEGIS_RING_MAGIC`].
    pub magic: u32,
    /// Version del ABI del ring.
    pub abi_version: u32,
    /// Bytes de la zona de datos. Siempre potencia de dos.
    pub capacity: u64,
    /// Offset de la zona de datos desde el inicio de esta estructura.
    pub data_offset: u64,
    /// Flags del ring.
    pub flags: u32,
    pub(crate) pad0: u32,
    pub(crate) rsv0: [u8; 32],

    /// Cursor de escritura. Solo lo modifica Ring 0.
    pub producer_head: u64,
    /// Eventos descartados por ring lleno.
    pub dropped_events: u64,
    /// Bytes descartados por ring lleno.
    pub dropped_bytes: u64,
    pub(crate) rsv1: [u8; 40],

    /// Cursor de lectura. Solo lo modifica Ring 3.
    pub consumer_tail: u64,
    /// Heartbeat del agente. Si deja de latir, el driver degrada a modo minimo.
    pub consumer_alive: u32,
    pub(crate) pad1: u32,
    pub(crate) rsv2: [u8; 48],
}

// --------------------------------------------------------------------------
// Verificacion del layout en tiempo de compilacion.
// --------------------------------------------------------------------------

const _: () = {
    assert!(size_of::<AegisStr>() == 4);

    assert!(size_of::<AegisEvtHdr>() == 64);
    assert!(offset_of!(AegisEvtHdr, magic) == 0);
    assert!(offset_of!(AegisEvtHdr, abi_version) == 4);
    assert!(offset_of!(AegisEvtHdr, ty) == 6);
    assert!(offset_of!(AegisEvtHdr, total_len) == 8);
    assert!(offset_of!(AegisEvtHdr, flags) == 12);
    assert!(offset_of!(AegisEvtHdr, seq) == 16);
    assert!(offset_of!(AegisEvtHdr, ts_ns) == 24);
    assert!(offset_of!(AegisEvtHdr, actor_key) == 32);
    assert!(offset_of!(AegisEvtHdr, target_key) == 40);
    assert!(offset_of!(AegisEvtHdr, cpu) == 48);
    assert!(offset_of!(AegisEvtHdr, verdict_id) == 52);
    assert!(offset_of!(AegisEvtHdr, reserved) == 56);

    assert!(size_of::<AegisProcCreate>() == 64);
    assert!(offset_of!(AegisProcCreate, image_path) == 52);
    assert!(offset_of!(AegisProcCreate, cmdline) == 56);
    assert!(offset_of!(AegisProcCreate, user_sid) == 60);

    assert!(size_of::<AegisImageLoad>() == 48);
    assert!(size_of::<AegisFileOp>() == 64);
    assert!(offset_of!(AegisFileOp, entropy_before) == 40);
    assert!(offset_of!(AegisFileOp, path) == 44);
    assert!(offset_of!(AegisFileOp, new_path) == 48);

    assert!(size_of::<AegisRemoteMem>() == 48);
    assert!(size_of::<AegisSyscallAnomaly>() == 48);
    assert!(size_of::<AegisVerdict>() == 24);

    assert!(size_of::<AegisRingCtrl>() == 192);
    assert!(offset_of!(AegisRingCtrl, producer_head) == 64);
    assert!(offset_of!(AegisRingCtrl, consumer_tail) == 128);
};
