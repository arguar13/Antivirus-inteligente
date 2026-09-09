/*
 * AegisCore - Contrato ABI compartido Ring 0 <-> Ring 3
 *
 * Este header es la UNICA fuente de verdad del formato binario que cruza la
 * frontera de privilegio. Lo consumen:
 *   - aegis-drv   (Windows, minifilter + kernel callbacks, C, WDK)
 *   - aegis-bpf   (Linux, eBPF CO-RE + LSM, C, libbpf)
 *   - aegis-ipc   (Rust, espejo #[repr(C)] verificado en tools/abi-check.sh)
 *
 * Reglas invariantes del ABI:
 *   1. NUNCA hay punteros en la memoria compartida. Las cadenas se referencian
 *      con (offset, len) relativos al inicio de la cabecera del evento.
 *   2. Todo registro del ring empieza en una frontera de 64 bytes y su
 *      total_len es multiplo de 64. Asi la cabecera nunca cruza dos lineas de
 *      cache ni queda desalineada, y el consumidor puede leerla directamente
 *      en vez de copiarla byte a byte.
 *   3. Los campos solo se ANIADEN en el espacio reservado. Cambiar o reordenar
 *      un campo existente obliga a incrementar AEGIS_ABI_VERSION.
 *   4. El consumidor SIEMPRE valida total_len contra el espacio disponible
 *      antes de leer el payload. El kernel es confiable, pero un driver con un
 *      bug no debe poder provocar un OOB read en el agente.
 */
#ifndef AEGIS_ABI_H
#define AEGIS_ABI_H

#include <stdint.h>

#define AEGIS_ABI_VERSION   1u
#define AEGIS_RING_MAGIC    0x53494741u  /* "AGIS" en little-endian */
#define AEGIS_EVT_MAGIC     0x54564541u  /* "AEVT" en little-endian */

/* --------------------------------------------------------------------------
 * Portabilidad: WDK (MSVC, modo kernel), GCC/Clang (Linux) y userland MSVC.
 * -------------------------------------------------------------------------- */
#if defined(_MSC_VER)
#  define AEGIS_ALIGNED_STRUCT(n) __declspec(align(n)) struct
#else
#  define AEGIS_ALIGNED_STRUCT(n) struct __attribute__((aligned(n)))
#endif

#if defined(C_ASSERT)
   /* ntdef.h del WDK ya define C_ASSERT; en modo kernel es lo idiomatico. */
#  define AEGIS_STATIC_ASSERT(cond, msg) C_ASSERT(cond)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define AEGIS_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#  define AEGIS_STATIC_ASSERT(cond, msg) /* sin verificacion en C89/C99 */
#endif

/* --------------------------------------------------------------------------
 * Tipos de evento
 * -------------------------------------------------------------------------- */
typedef uint16_t aegis_evt_type_t;

#define AEGIS_EVT_PADDING          0xFFFFu /* relleno hasta fin de buffer */
#define AEGIS_EVT_PROCESS_CREATE   0x0001u
#define AEGIS_EVT_PROCESS_EXIT     0x0002u
#define AEGIS_EVT_THREAD_CREATE    0x0003u
#define AEGIS_EVT_IMAGE_LOAD       0x0004u
#define AEGIS_EVT_FILE_PRE_CREATE  0x0010u
#define AEGIS_EVT_FILE_WRITE       0x0011u
#define AEGIS_EVT_FILE_RENAME      0x0012u
#define AEGIS_EVT_FILE_DELETE      0x0013u
#define AEGIS_EVT_REGISTRY_SET     0x0020u
#define AEGIS_EVT_REGISTRY_DELETE  0x0021u
#define AEGIS_EVT_REMOTE_ALLOC     0x0030u /* VirtualAllocEx cross-process   */
#define AEGIS_EVT_REMOTE_WRITE     0x0031u /* WriteProcessMemory cross-proc  */
#define AEGIS_EVT_REMOTE_PROTECT   0x0032u /* VirtualProtectEx -> RX/RWX     */
#define AEGIS_EVT_REMOTE_THREAD    0x0033u /* CreateRemoteThread / APC       */
#define AEGIS_EVT_HANDLE_REQUEST   0x0034u /* ObRegisterCallbacks pre-op     */
#define AEGIS_EVT_NET_CONNECT      0x0040u
#define AEGIS_EVT_NET_SCAN         0x0041u /* barrido de puertos detectado  */
#define AEGIS_EVT_NET_BLOCKED      0x0042u /* paquete descartado en XDP     */
#define AEGIS_EVT_SYSCALL_ANOMALY  0x0050u /* syscall directo/indirecto      */
#define AEGIS_EVT_TAMPER_ATTEMPT   0x0060u /* intento contra el propio EDR   */

/* Flags de la cabecera */
#define AEGIS_F_NEEDS_VERDICT      0x00000001u /* el productor esta bloqueado */
#define AEGIS_F_TRUNCATED          0x00000002u /* payload recortado por tamano */
#define AEGIS_F_KERNEL_ACTOR       0x00000004u /* el actor es codigo de kernel */
#define AEGIS_F_UTF16              0x00000008u /* cadenas en UTF-16LE (Windows) */

/* --------------------------------------------------------------------------
 * Referencia a cadena: (offset, len) desde el inicio de la cabecera.
 * len == 0 significa ausente. Nunca hay terminador NUL.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t off;
    uint16_t len;
} aegis_str_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_str_t) == 4, "aegis_str_t debe ocupar 4 bytes");

/* --------------------------------------------------------------------------
 * Cabecera de evento: exactamente una linea de cache (64 B).
 *
 * actor_key / target_key NO son PIDs. Un PID se recicla y eso rompe cualquier
 * correlacion de linaje: son claves estables de 64 bits derivadas de
 * (pid, create_time) en el kernel, donde create_time es monotono.
 * -------------------------------------------------------------------------- */
typedef AEGIS_ALIGNED_STRUCT(64) {
    uint32_t magic;        /* AEGIS_EVT_MAGIC                                */
    uint16_t abi_version;  /* AEGIS_ABI_VERSION                              */
    uint16_t type;         /* aegis_evt_type_t                               */
    uint32_t total_len;    /* cabecera + payload + cadenas + relleno.        */
                           /* Multiplo de 64: es el paso del registro en el   */
                           /* ring, no solo el contenido util.                */
    uint32_t flags;        /* AEGIS_F_*                                      */
    uint64_t seq;          /* monotono por CPU: detecta perdida de eventos   */
    uint64_t ts_ns;        /* KeQueryPerformanceCounter / ktime_get_boot_ns  */
    uint64_t actor_key;    /* quien ejecuta la accion                        */
    uint64_t target_key;   /* sobre quien se ejecuta (0 si no aplica)        */
    uint32_t cpu;          /* CPU productora, para reordenar por seq         */
    uint32_t verdict_id;   /* != 0 si AEGIS_F_NEEDS_VERDICT                  */
    uint64_t reserved;     /* debe ser 0 en ABI v1                           */
} aegis_evt_hdr_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_evt_hdr_t) == 64, "la cabecera debe ser una linea de cache");

/* --------------------------------------------------------------------------
 * Payloads. Todos empiezan justo despues de la cabecera (offset 64). Las
 * cadenas de longitud variable van detras del payload y se referencian con
 * aegis_str_t; el resto del registro hasta total_len es relleno a cero.
 * -------------------------------------------------------------------------- */

/* Nivel de integridad (Windows) / contexto de credenciales (Linux) */
#define AEGIS_IL_UNTRUSTED  0u
#define AEGIS_IL_LOW        1u
#define AEGIS_IL_MEDIUM     2u
#define AEGIS_IL_HIGH       3u
#define AEGIS_IL_SYSTEM     4u

typedef struct {
    uint64_t    parent_key;   /* padre reportado por el SO                   */
    uint64_t    creator_key;  /* quien llamo a NtCreateUserProcess.          */
                              /* creator_key != parent_key => PPID spoofing  */
    uint64_t    image_id;     /* FNV-1a del path canonico: clave de cache    */
    uint64_t    create_time;  /* 100ns desde epoch del SO                    */
    uint32_t    pid;
    uint32_t    parent_pid;
    uint32_t    session_id;
    uint32_t    token_flags;  /* elevado, restringido, AppContainer, ...     */
    uint16_t    integrity_level;
    uint16_t    signature_level; /* SE_SIGNING_LEVEL_*                       */
    aegis_str_t image_path;
    aegis_str_t cmdline;
    aegis_str_t user_sid;
} aegis_proc_create_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_proc_create_t) == 64, "aegis_proc_create_t == 64");

/* Flags de carga de imagen */
#define AEGIS_IMG_F_UNBACKED   0x00000001u /* no respaldada por fichero      */
#define AEGIS_IMG_F_RELOCATED  0x00000002u /* base != ImageBase preferida    */
#define AEGIS_IMG_F_KNOWNDLL   0x00000004u /* proviene de \KnownDlls         */
#define AEGIS_IMG_F_REMOTE     0x00000008u /* cargada desde ruta UNC         */

typedef struct {
    uint64_t    image_base;
    uint64_t    image_size;
    uint64_t    image_id;
    uint32_t    pid;
    uint32_t    flags;           /* AEGIS_IMG_F_*                            */
    uint16_t    signature_level;
    uint16_t    signature_type;
    aegis_str_t image_path;
    uint64_t    reserved;
} aegis_image_load_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_image_load_t) == 48, "aegis_image_load_t == 48");

/*
 * Operacion de fichero. entropy_* usa punto fijo Q8.8 (entropia * 256), de modo
 * que 8.0 bits/byte -> 2048. Calcular la entropia en el kernel sobre el buffer
 * que ya esta en memoria evita una segunda lectura de disco y es lo que
 * alimenta el detector de ransomware con latencia de milisegundos.
 */
typedef struct {
    uint64_t    file_id;        /* FILE_ID_128 (low) en Windows / inode      */
    uint64_t    volume_id;
    uint64_t    bytes_written;
    uint32_t    pid;
    uint32_t    desired_access;
    uint32_t    create_options;
    uint32_t    info_flags;
    uint16_t    entropy_before; /* Q8.8 */
    uint16_t    entropy_after;  /* Q8.8 */
    aegis_str_t path;
    aegis_str_t new_path;       /* destino del rename */
    uint32_t    reserved0;
    uint64_t    reserved1;
} aegis_file_op_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_file_op_t) == 64, "aegis_file_op_t == 64");

/* Flags de memoria remota */
#define AEGIS_MEM_F_RWX           0x00000001u /* PAGE_EXECUTE_READWRITE      */
#define AEGIS_MEM_F_UNBACKED      0x00000002u /* MEM_PRIVATE ejecutable      */
#define AEGIS_MEM_F_CROSS_SESSION 0x00000004u
#define AEGIS_MEM_F_RX_TRANSITION 0x00000008u /* RW -> RX: patron de shellcode */

typedef struct {
    uint64_t target_key;
    uint64_t address;
    uint64_t region_size;
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t alloc_type;    /* MEM_COMMIT | MEM_RESERVE                      */
    uint32_t protect;       /* proteccion solicitada                         */
    uint32_t prev_protect;  /* proteccion previa (VirtualProtectEx)          */
    uint32_t flags;         /* AEGIS_MEM_F_*                                 */
} aegis_remote_mem_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_remote_mem_t) == 48, "aegis_remote_mem_t == 48");

/*
 * Anomalia de syscall. Es la senal central contra evasion de hooks: un syscall
 * legitimo se ejecuta SIEMPRE desde el .text de ntdll.dll o win32u.dll. Si la
 * direccion de retorno cae en memoria privada (shellcode, syscall directo) o en
 * una imagen que no es ntdll (syscall indirecto / stub robado), es anomalo.
 */
#define AEGIS_SYS_F_UNBACKED_CALLER 0x00000001u /* retorno en MEM_PRIVATE    */
#define AEGIS_SYS_F_NOT_NTDLL       0x00000002u /* retorno fuera de ntdll    */
#define AEGIS_SYS_F_INDIRECT        0x00000004u /* gadget syscall reutilizado */
#define AEGIS_SYS_F_HOOK_REMOVED    0x00000008u /* .text de ntdll modificado */

typedef struct {
    uint64_t return_address;
    uint64_t region_base;
    uint64_t region_size;
    uint32_t pid;
    uint32_t tid;
    uint32_t ssn;             /* System Service Number invocado              */
    uint32_t region_protect;
    uint32_t region_type;     /* MEM_IMAGE | MEM_PRIVATE | MEM_MAPPED        */
    uint32_t flags;           /* AEGIS_SYS_F_*                               */
} aegis_syscall_anomaly_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_syscall_anomaly_t) == 48, "aegis_syscall_anomaly_t == 48");

/*
 * Conexion de red. En Linux lo alimenta el tracepoint sock/inet_sock_set_state,
 * que es estable entre versiones de kernel; en Windows, la capa ALE de WFP.
 *
 * Las direcciones viajan siempre en 16 bytes: IPv4 ocupa los cuatro primeros y
 * el resto queda a cero. Un solo formato evita ramificar todo el correlador de
 * Ring 3 por familia de direcciones.
 */
#define AEGIS_NET_F_OUTBOUND   0x00000001u
#define AEGIS_NET_F_INBOUND    0x00000002u
#define AEGIS_NET_F_LOOPBACK   0x00000004u
#define AEGIS_NET_F_PRIVATE_DST 0x00000008u /* destino en rango RFC1918        */
#define AEGIS_NET_F_SYN         0x00000010u /* TCP SYN sin ACK                 */
#define AEGIS_NET_F_DROPPED     0x00000020u /* descartado antes del stack TCP/IP */
#define AEGIS_NET_F_SCAN_SYN    0x00000040u /* atribuido a un barrido SYN      */
#define AEGIS_NET_F_XDP         0x00000080u /* observado en XDP, no en socket  */

typedef struct {
    uint8_t  saddr[16];     /* 0  */
    uint8_t  daddr[16];     /* 16 */
    uint32_t pid;           /* 32 */
    uint16_t sport;         /* 36 */
    uint16_t dport;         /* 38 */
    uint16_t family;        /* 40  AF_INET=2, AF_INET6=10                      */
    uint16_t protocol;      /* 42  IPPROTO_TCP=6, IPPROTO_UDP=17               */
    uint16_t old_state;     /* 44 */
    uint16_t new_state;     /* 46 */
    uint32_t flags;         /* 48  AEGIS_NET_F_*                               */
    uint32_t reserved0;     /* 52 */
    uint64_t reserved1;     /* 56 */
} aegis_net_conn_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_net_conn_t) == 64, "aegis_net_conn_t == 64");

/* --------------------------------------------------------------------------
 * Canal de veredicto (sincrono, bloqueante y acotado en tiempo).
 * -------------------------------------------------------------------------- */
#define AEGIS_ACTION_ALLOW      0u
#define AEGIS_ACTION_BLOCK      1u /* STATUS_VIRUS_INFECTED / -EPERM         */
#define AEGIS_ACTION_QUARANTINE 2u
#define AEGIS_ACTION_SUSPEND    3u /* congelar el proceso para triaje        */
#define AEGIS_ACTION_KILL       4u

typedef struct {
    uint64_t verdict_id;
    uint64_t detection_id;  /* id de la deteccion que lo motivo (0 = ninguna) */
    uint32_t action;        /* AEGIS_ACTION_*                                 */
    uint32_t reason;        /* codigo de motivo para telemetria y UI          */
} aegis_verdict_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_verdict_t) == 24, "aegis_verdict_t == 24");

/* --------------------------------------------------------------------------
 * Bloque de control del ring buffer SPSC en memoria compartida.
 *
 * Tres lineas de cache disjuntas. producer_* solo lo escribe Ring 0 y
 * consumer_* solo lo escribe Ring 3: sin esa separacion, cada publicacion de
 * evento invalidaria la linea que el otro lado esta leyendo (false sharing) y
 * el coste por evento se multiplicaria.
 * -------------------------------------------------------------------------- */
typedef AEGIS_ALIGNED_STRUCT(64) {
    /* --- linea 0: inmutable tras la inicializacion --- */
    uint32_t magic;        /* AEGIS_RING_MAGIC                               */
    uint32_t abi_version;
    uint64_t capacity;     /* bytes de la zona de datos, potencia de 2       */
    uint64_t data_offset;  /* offset de la zona de datos desde esta cabecera */
    uint32_t flags;
    uint32_t pad0;
    uint8_t  rsv0[32];

    /* --- linea 1: escribe solo el productor (Ring 0) --- */
    uint64_t producer_head;  /* release-store tras escribir el registro      */
    uint64_t dropped_events; /* eventos perdidos por ring lleno              */
    uint64_t dropped_bytes;
    uint8_t  rsv1[40];

    /* --- linea 2: escribe solo el consumidor (Ring 3) --- */
    uint64_t consumer_tail;  /* release-store tras consumir                  */
    uint32_t consumer_alive; /* heartbeat: el driver degrada a modo minimo   */
                             /* si el agente deja de latir                   */
    uint32_t pad1;
    uint8_t  rsv2[48];
} aegis_ring_ctrl_t;
AEGIS_STATIC_ASSERT(sizeof(aegis_ring_ctrl_t) == 192, "aegis_ring_ctrl_t == 3 lineas de cache");

#endif /* AEGIS_ABI_H */
