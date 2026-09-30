/*
 * AegisCore - definiciones compartidas de los programas eBPF.
 *
 * Aqui NO hay tipos de kernel. Los aporta `vmlinux.h`, generado del BTF del
 * kernel (ver el Makefile): asi los anchos y los signos de cada campo son los
 * autenticos, y libbpf reubica los accesos via CO-RE contra el kernel de
 * destino. Este fichero contiene solo lo que es de AegisCore —la disposicion
 * de los registros del ring, la configuracion compartida con Ring 3 y las
 * constantes UAPI que se usan— y por eso se incluye DESPUES de vmlinux.h.
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
 * Relocalizacion de tipos: el instante de arranque de una tarea
 *
 * `task_struct` guarda el instante en que arranco la tarea en la base
 * monotona del arranque. Ese campo se llamo `real_start_time` hasta Linux 5.4
 * y `start_boottime` desde 5.5. AegisCore lo necesita porque es la mitad de la
 * IDENTIDAD estable de un proceso: el PID se recicla, el par (pid, instante de
 * arranque) no. Sin el, dos procesos distintos que reutilizan un PID se
 * confunden en el grafo de linaje, y ahi es donde se esconde un atacante.
 *
 * Esto es exactamente el problema para el que existe CO-RE, y se resuelve con
 * sus dos mecanismos:
 *
 *   - `bpf_core_field_exists` pregunta al BTF del kernel de DESTINO si el campo
 *     nuevo esta. La respuesta se resuelve al cargar, no al compilar.
 *   - un "sabor" de tipo (`___pre55`) declara el campo viejo. libbpf ignora
 *     todo lo que sigue a `___` al buscar el tipo en el kernel, asi que este
 *     sabor casa con `struct task_struct` y permite pedir un campo que el
 *     vmlinux.h con el que compilamos ya no tiene.
 *
 * La rama que no corresponda al kernel de destino queda como codigo muerto y el
 * verificador la poda. Resultado: UN solo bytecode que lee el campo correcto
 * tanto en un RHEL 8 como en un kernel 6.x.
 * ------------------------------------------------------------------------ */

/* Solo tiene sentido dentro de una unidad de traduccion de eBPF, que es donde
 * existen `task_struct` y las macros de CO-RE. El guardia lo pone vmlinux.h. */
#ifdef __VMLINUX_H__
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct task_struct___pre55 {
    __u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline __u64 aegis_inicio_de_tarea(struct task_struct *tarea)
{
    if (bpf_core_field_exists(tarea->start_boottime))
        return BPF_CORE_READ(tarea, start_boottime);

    struct task_struct___pre55 *antigua = (void *)tarea;
    return BPF_CORE_READ(antigua, real_start_time);
}
#endif /* __VMLINUX_H__ */

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

/* EtherType. Son valores asignados por la IANA y viven en macros de
 * <linux/if_ether.h>, no en tipos: por eso NO viajan en el BTF del kernel y
 * vmlinux.h no puede aportarlos. Definirlos aqui es correcto —son numeros de
 * protocolo, no disposicion de memoria— y evita reintroducir las cabeceras UAPI
 * del sistema, que si chocarian con vmlinux.h. */
#define AEGIS_ETH_P_IP     0x0800u
#define AEGIS_ETH_P_IPV6   0x86DDu

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

/* Tamano del ring buffer de eventos. Las prioridades se miden contra el. */
#define AEGIS_RING_BYTES (8u * 1024u * 1024u)

enum aegis_stat {
    AEGIS_STAT_EMITTED = 0,
    AEGIS_STAT_DROPPED_FULL = 1,   /* ring lleno: punto ciego de deteccion   */
    AEGIS_STAT_FILTERED = 2,       /* descartado por politica, no es perdida */
    AEGIS_STAT_TRUNCATED = 3,
    AEGIS_STAT_DROPPED_PRIORIDAD = 4, /* cedido a un evento de mas prioridad  */
    AEGIS_STAT__MAX = 5,
};

/*
 * Familias de telemetria, en el MISMO orden que `Familia::todas()` del agente
 * (crates/aegis-agent/src/capacidades.rs). Indexan el mapa de perdidas por
 * familia; la prueba del objeto real comprueba que el mapa tiene una entrada
 * por familia.
 */
enum aegis_familia {
    AEGIS_FAM_EJECUCION = 0,
    AEGIS_FAM_SALIDA = 1,
    AEGIS_FAM_FICHEROS = 2,
    AEGIS_FAM_ESCRITURAS = 3,
    AEGIS_FAM_RENOMBRADOS = 4,
    AEGIS_FAM_PTRACE = 5,
    AEGIS_FAM_RED = 6,
    AEGIS_FAM__MAX = 7,
};

/*
 * PERDER CON PRIORIDAD (FASE 1 del MP-16).
 *
 * Con el ring lleno se perdia lo que llegara, y en una tormenta de escrituras
 * —justo lo que hace un cifrador— lo que llega son escrituras: el `exec` del
 * cifrador y el `ptrace` de quien inyecta podian perderse detras de miles de
 * aperturas de fichero. Ahora cada familia tiene prioridad, y las de prioridad
 * menor CEDEN el ring antes de que se llene:
 *
 *   alta   ejecucion, salida de proceso, ptrace   solo se pierden con el ring LLENO
 *   media  red, renombrados                       ceden por encima del 90 %
 *   baja   ficheros, escrituras                   ceden por encima del 75 %
 *
 * El ultimo cuarto del ring queda asi para lo que no se puede perder. Lo cedido
 * se cuenta, por familia, y el agente lo publica: una perdida que no se ve es
 * un punto ciego que nadie sabe que tiene.
 */
enum aegis_prioridad {
    AEGIS_PRIO_ALTA = 0,
    AEGIS_PRIO_MEDIA = 1,
    AEGIS_PRIO_BAJA = 2,
};

static __always_inline enum aegis_prioridad aegis_prioridad_de(__u32 familia)
{
    switch (familia) {
    case AEGIS_FAM_EJECUCION:
    case AEGIS_FAM_SALIDA:
    case AEGIS_FAM_PTRACE:
        return AEGIS_PRIO_ALTA;
    case AEGIS_FAM_RED:
    case AEGIS_FAM_RENOMBRADOS:
        return AEGIS_PRIO_MEDIA;
    default:
        return AEGIS_PRIO_BAJA;
    }
}

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

/* ------------------------------------------------------------------------
 * Prevencion en linea (AegisIPS, FASE 71)
 * ------------------------------------------------------------------------ */

/* MODOS. El kernel los aplica, no solo los transporta.
 *
 * Que el modo se compruebe AQUI y no en userland no es un detalle de
 * implementacion: es lo que hace que «modo aprendizaje» sea una promesa que se
 * puede sostener. Si la decision de cortar viviera arriba, un fallo de logica
 * en userland cortaria trafico de un cliente que habia pedido expresamente que
 * no se cortara nada. Con la comprobacion aqui, para que eso pase hace falta
 * cambiar el modo a proposito. */
#define AEGIS_IPS_MODO_SOLO_DETECCION 0u
#define AEGIS_IPS_MODO_BLOQUEO        1u
#define AEGIS_IPS_MODO_APRENDIZAJE    2u

#define AEGIS_IPS_CFG_ENABLED 0x00000001u

/* Veredictos que userland puede escribir para un flujo. */
#define AEGIS_IPS_VEREDICTO_PERMITIR 0u
#define AEGIS_IPS_VEREDICTO_CORTAR   1u

/* Clave de flujo NORMALIZADA: los dos sentidos de una conversacion dan la
 * misma clave. Userland la normaliza antes de escribir; el kernel la normaliza
 * antes de buscar. Si no coincidieran, un veredicto escrito viendo el sentido
 * cliente->servidor no cortaria el sentido de vuelta, que es justo por donde
 * llega lo que interesa cortar. */
struct aegis_ips_flujo {
    __u32 ip_a;     /* la menor de las dos, en orden de red */
    __u32 ip_b;
    __u16 puerto_a; /* el de ip_a, en orden de host */
    __u16 puerto_b;
    __u8 protocolo;
    __u8 pad[3];
};

/* Veredicto cacheado en el kernel para un flujo.
 *
 * ESTO ES LO QUE HACE QUE BLOQUEAR NO CUESTE RENDIMIENTO: el primer paquete de
 * un flujo sospechoso sube a userland, se juzga una vez, y el veredicto baja al
 * kernel. A partir de ahi el resto del flujo se corta con una busqueda de mapa,
 * sin volver a subir. Un IPS que consulte a userland por cada paquete paga el
 * coste que existe para evitar. */
struct aegis_ips_veredicto {
    /* Caducidad en la base de bpf_ktime_get_boot_ns. 0 = sin caducidad. */
    __u64 until_ns;
    /* Paquetes afectados por este veredicto. Lo lleva el kernel para que
     * userland mida el efecto sin recibir un evento por paquete. */
    __u64 hits;
    /* AEGIS_IPS_VEREDICTO_*. */
    __u32 veredicto;
    /* AEGIS_BLOCK_REASON_*, para poder explicar el corte. */
    __u32 motivo;
    /* Identificador de la regla que lo decidio, para poder auditarlo. */
    __u64 regla;
};

/* Entrada de la lista de NUNCA BLOQUEAR.
 *
 * Se consulta ANTES que el veredicto, a proposito. Un falso positivo en un IPS
 * no es una alerta molesta: es una interrupcion de servicio. El plano de
 * control, los controladores de dominio y el DNS de la organizacion son
 * justamente las maquinas cuyo corte convierte un incidente en un apagon, y
 * son las que un atacante querria que bloquearamos por el. */
struct aegis_ips_protegido {
    /* Veces que esta entrada ha evitado un corte. Es la medida de cuantas
     * veces la salvaguarda ha hecho falta de verdad. */
    __u64 salvadas;
    __u32 motivo;
    __u32 pad;
};

struct aegis_ips_config {
    __u32 flags;
    /* AEGIS_IPS_MODO_*. Por defecto SOLO_DETECCION: un IPS que llega
     * bloqueando por defecto tira la produccion del cliente el primer dia. */
    __u32 modo;
    __u64 reservado;
};
/* El espejo en Rust tiene que coincidir byte a byte: estos mapas los escribe
 * userland y los lee el kernel por cada paquete. */
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_ips_flujo) == 16, "aegis_ips_flujo == 16");
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_ips_veredicto) == 32, "aegis_ips_veredicto == 32");
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_ips_protegido) == 16, "aegis_ips_protegido == 16");
AEGIS_BPF_STATIC_ASSERT(sizeof(struct aegis_ips_config) == 16, "aegis_ips_config == 16");

enum aegis_ips_stat {
    AEGIS_IPS_STAT_PAQUETES = 0,
    /* Paquetes CORTADOS de verdad. */
    AEGIS_IPS_STAT_CORTADOS = 1,
    /* Paquetes que se HABRIAN cortado y no se cortaron, por el modo.
     * Es la cifra que un cliente mira antes de atreverse a activar el bloqueo. */
    AEGIS_IPS_STAT_HABRIA_CORTADO = 2,
    /* Veces que la lista de protegidos evito un corte. Si esto sube, el motor
     * de decision se esta equivocando en algo grave y hay que mirarlo. */
    AEGIS_IPS_STAT_PROTEGIDOS = 3,
    /* Aciertos y fallos de la cache de veredictos, para poder demostrar que el
     * bloqueo no cuesta subir a userland por paquete. */
    AEGIS_IPS_STAT_CACHE_ACIERTO = 4,
    AEGIS_IPS_STAT_CACHE_FALLO = 5,
    /* Paquetes que no se pudieron clasificar hasta tener clave de flujo. */
    AEGIS_IPS_STAT_NO_CLASIFICADOS = 6,
    /* Veredictos encontrados pero ya caducados. */
    AEGIS_IPS_STAT_CADUCADOS = 7,
    AEGIS_IPS_STAT__MAX = 8,
};

#endif /* AEGIS_BPF_COMMON_H */
