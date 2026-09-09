/*
 * AegisCore - definiciones compartidas de los programas eBPF.
 *
 * NO se usa vmlinux.h. En su lugar se declaran solo los campos de kernel que
 * los programas realmente leen, marcados con preserve_access_index para que
 * libbpf los reubique via CO-RE contra el BTF del kernel de destino.
 *
 * Es una tecnica soportada y aqui es la correcta por tres razones:
 *   1. Elimina bpftool del pipeline de compilacion (un vmlinux.h generado son
 *      ~100.000 lineas que hay que regenerar por cada kernel de referencia).
 *   2. Hace explicito y auditable EXACTAMENTE que toca el codigo de kernel:
 *      la superficie completa cabe en esta pantalla.
 *   3. Sigue siendo CO-RE: un unico binario funciona en kernels distintos.
 */
#ifndef AEGIS_BPF_COMMON_H
#define AEGIS_BPF_COMMON_H

/*
 * Esta cabecera es AUTOCONTENIDA: los programas eBPF la incluyen antes que
 * aegis_abi.h, asi que no puede depender de macros definidas alli.
 */
#ifndef AEGIS_BPF_STATIC_ASSERT
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#    define AEGIS_BPF_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#  else
#    define AEGIS_BPF_STATIC_ASSERT(cond, msg)
#  endif
#endif

/* ------------------------------------------------------------------------
 * Estructuras de kernel. Solo los campos que se leen.
 * ------------------------------------------------------------------------ */

struct task_struct {
    int pid;                            /* TID en terminologia de kernel     */
    int tgid;                           /* PID en terminologia de userland   */
    struct task_struct *real_parent;
    struct task_struct *group_leader;
    unsigned long long start_boottime;  /* ns desde el arranque, monotono    */
} __attribute__((preserve_access_index));

/* Contexto comun de los tracepoints de syscall. */
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long int id;
    unsigned long args[6];
} __attribute__((preserve_access_index));

/* Contexto de sched:sched_process_exit. */
struct trace_event_raw_sched_process_template {
    unsigned long long unused;
    char comm[16];
    int pid;
    int prio;
} __attribute__((preserve_access_index));

/* Contexto de sock:inet_sock_set_state. */
struct trace_event_raw_inet_sock_set_state {
    unsigned long long unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
} __attribute__((preserve_access_index));

/* ------------------------------------------------------------------------
 * Constantes UAPI que se necesitan sin arrastrar cabeceras de libc.
 * ------------------------------------------------------------------------ */
#define AEGIS_O_WRONLY   00000001
#define AEGIS_O_RDWR     00000002
#define AEGIS_O_CREAT    00000100
#define AEGIS_O_TRUNC    00001000
#define AEGIS_O_APPEND   00002000
/* Intencion de modificar el fichero: es el unico caso que se emite. */
#define AEGIS_O_WRITE_INTENT \
    (AEGIS_O_WRONLY | AEGIS_O_RDWR | AEGIS_O_CREAT | AEGIS_O_TRUNC | AEGIS_O_APPEND)

#define AEGIS_PTRACE_TRACEME    0
#define AEGIS_PTRACE_PEEKTEXT   1
#define AEGIS_PTRACE_PEEKDATA   2
#define AEGIS_PTRACE_POKETEXT   4
#define AEGIS_PTRACE_POKEDATA   5
#define AEGIS_PTRACE_ATTACH    16
#define AEGIS_PTRACE_DETACH    17
#define AEGIS_PTRACE_SEIZE  0x4206

#define AEGIS_TCP_ESTABLISHED   1
#define AEGIS_TCP_SYN_SENT      2
#define AEGIS_TCP_SYN_RECV      3
#define AEGIS_TCP_CLOSE         7
#define AEGIS_TCP_LISTEN       10

#define AEGIS_AF_INET           2
#define AEGIS_AF_INET6         10

/* ------------------------------------------------------------------------
 * Disposicion de los registros que se escriben en el ring buffer.
 *
 * Dos tamanos fijos y nada mas. bpf_ringbuf_reserve() exige un tamano
 * constante para el verificador, y usar offsets constantes para cada campo es
 * lo que permite que el verificador acepte las escrituras sin comprobaciones
 * dinamicas en la ruta caliente.
 *
 *   REGISTRO GRANDE (512 B)          REGISTRO PEQUENO (128 B)
 *     0..64    cabecera                0..64    cabecera
 *    64..128   payload                64..128   payload
 *   128..384   cadena 1 (ruta)
 *   384..512   cadena 2 (cmdline)
 * ------------------------------------------------------------------------ */
#define AEGIS_BPF_EVT_LARGE  512u
#define AEGIS_BPF_EVT_SMALL  128u
#define AEGIS_BPF_EVT_TINY    64u   /* solo cabecera */

/* Registro de escritura con muestra del buffer adjunta.
 *
 *     0..64    cabecera
 *    64..128   aegis_file_write_t
 *   128..640   muestra del buffer
 *
 * La muestra son 512 bytes y no menos porque la entropia de Shannon sobre n
 * simbolos esta acotada por log2(n): con 128 bytes el maximo alcanzable seria
 * 7,0 bits/byte y el umbral de 7,9 que define "cifrado" nunca se cruzaria.
 * Con 512 el techo es 8,0 y el umbral es alcanzable. */
#define AEGIS_BPF_EVT_WSAMPLE 640u
#define AEGIS_BPF_WSAMPLE_OFF 128u
#define AEGIS_BPF_WSAMPLE_MAX 512u

#define AEGIS_BPF_PAYLOAD_OFF 64u
#define AEGIS_BPF_STR1_OFF   128u
#define AEGIS_BPF_STR1_MAX   256u
#define AEGIS_BPF_STR2_OFF   384u
#define AEGIS_BPF_STR2_MAX   128u

/* ------------------------------------------------------------------------
 * Estado compartido con el espacio de usuario.
 * ------------------------------------------------------------------------ */

#define AEGIS_CFG_ENABLED        0x00000001u
#define AEGIS_CFG_TRACE_FILES    0x00000002u
#define AEGIS_CFG_TRACE_NET      0x00000004u
#define AEGIS_CFG_TRACE_PTRACE   0x00000008u
#define AEGIS_CFG_TRACE_WRITES   0x00000010u
#define AEGIS_CFG_TRACE_RENAME   0x00000020u

struct aegis_bpf_config {
    /* PID del agente. Sus propios eventos no se emiten: si el agente escribe
     * un fichero y eso genera un evento que el agente consume y registra en
     * otro fichero, el sistema entra en realimentacion positiva y se ahoga. */
    __u32 agent_pid;
    __u32 flags;
    /* Ruido de fondo: por debajo de este umbral de bytes no se emiten
     * escrituras, salvo que la muestra parezca cifrada. 0 = emitir todas.
     *
     * Sin este filtro, cada linea que un proceso escribe en su registro genera
     * un evento, y el ruido de un servidor normal ahoga el ring. */
    __u32 min_write_bytes;
    /* Valores de byte distintos, sobre la muestra, a partir de los cuales el
     * buffer se considera candidato a cifrado.
     *
     * Sobre 512 bytes, texto plano da 60-90 valores distintos y datos cifrados
     * 230-256. Un umbral de 200 separa ambos con holgura sin necesitar
     * logaritmos, que en eBPF no existen. */
    __u32 write_distinct_threshold;
};

enum aegis_stat {
    AEGIS_STAT_EMITTED = 0,
    AEGIS_STAT_DROPPED_FULL = 1,   /* ring lleno: punto ciego de deteccion   */
    AEGIS_STAT_FILTERED = 2,       /* descartado por politica, no es perdida */
    AEGIS_STAT_TRUNCATED = 3,
    AEGIS_STAT__MAX = 4,
};

/* Buffer temporal por CPU para construir la linea de comandos.
 *
 * No se construye directamente en el registro del ring: concatenar argumentos
 * exige escribir en offsets variables, y el verificador solo lo acepta si el
 * destino tiene holgura demostrable por encima del maximo. Este buffer la
 * tiene; el registro del ring recibe despues una copia de tamano constante.
 */
#define AEGIS_SCRATCH_LEN 512u
#define AEGIS_ARGV_MAX      8u   /* argumentos que se recorren como maximo    */
#define AEGIS_ARG_LEN      64u   /* bytes por argumento como maximo           */

struct aegis_scratch {
    char buf[AEGIS_SCRATCH_LEN];
};

/* Buffer por CPU para muestrear escrituras.
 *
 * Separado del scratch de la linea de comandos a proposito: aunque dos
 * tracepoints no se solapan en la misma CPU en la practica, compartir el buffer
 * crearia una dependencia invisible entre dos sondas que no tienen nada que ver
 * la una con la otra. */
struct aegis_wsample {
    char buf[AEGIS_BPF_WSAMPLE_MAX];
    /* Mapa de bits de 256 posiciones: un bit por valor de byte visto. */
    __u64 seen[4];
};

/* ------------------------------------------------------------------------
 * Filtro XDP
 * ------------------------------------------------------------------------ */

#define AEGIS_XDP_CFG_ENABLED   0x00000001u
/* Bloqueo automatico al detectar un barrido. DESACTIVADO por defecto: la IP
 * origen de un SYN se falsifica trivialmente, asi que bloquear en automatico es
 * el mecanismo con el que un atacante consigue que bloqueemos a un tercero. */
#define AEGIS_XDP_CFG_AUTOBLOCK 0x00000002u

/* Entrada de la lista de bloqueo. La escribe userland, la lee el programa XDP
 * por cada paquete cuya IP origen aparezca en el mapa. */
struct aegis_block_entry {
    /* Instante de caducidad en la base de bpf_ktime_get_boot_ns.
     * 0 = bloqueo permanente hasta que userland lo retire. */
    __u64 until_ns;
    /* Paquetes descartados por esta entrada. Lo lleva el kernel para que
     * userland pueda medir el efecto de un bloqueo sin recibir un evento por
     * cada paquete descartado. */
    __u64 hits;
    __u32 reason;
    __u32 pad;
};

struct aegis_xdp_config {
    __u32 flags;
    /* Ventana de observacion del detector de barridos. */
    __u64 scan_window_ns;
    /* Puertos distintos (cota inferior) que definen un barrido. */
    __u32 scan_port_threshold;
    /* SYN minimos en la ventana. Exigir ambos umbrales evita clasificar como
     * barrido a un cliente que abre unas pocas conexiones a puertos dispersos. */
    __u32 scan_syn_threshold;
    /* Duracion del bloqueo automatico, si esta habilitado. */
    __u64 autoblock_ns;
    /* Uno de cada cuantos SYN se envia a userland. 0 = ninguno. */
    __u32 syn_sample_rate;
    __u32 reserved;
};
/* El espejo en Rust tiene que coincidir byte a byte: el mapa lo escribe
 * userland y lo lee el kernel por cada paquete. */
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_xdp_config) == 40, "aegis_xdp_config == 40");
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_block_entry) == 24, "aegis_block_entry == 24");

/* Motivos de bloqueo. */
#define AEGIS_BLOCK_REASON_MANUAL     1u
#define AEGIS_BLOCK_REASON_PORT_SCAN  2u
#define AEGIS_BLOCK_REASON_C2         3u
#define AEGIS_BLOCK_REASON_EXFIL      4u

enum aegis_xdp_stat {
    AEGIS_XDP_STAT_PACKETS = 0,
    AEGIS_XDP_STAT_SYN = 1,
    AEGIS_XDP_STAT_DROPPED = 2,
    AEGIS_XDP_STAT_SCANS = 3,
    AEGIS_XDP_STAT_EVENTS = 4,
    AEGIS_XDP_STAT_EVENT_DROPPED = 5,
    AEGIS_XDP_STAT_IPV6_UNINSPECTED = 6,
    AEGIS_XDP_STAT__MAX = 7,
};

#endif /* AEGIS_BPF_COMMON_H */
