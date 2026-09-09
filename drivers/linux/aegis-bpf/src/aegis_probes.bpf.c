// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * AegisCore - sondas de telemetria eBPF (Linux Ring 0).
 *
 * Emiten eventos en el formato definido por shared/include/aegis_abi.h, el
 * mismo contrato que usa el driver de Windows. El transporte aqui es
 * BPF_MAP_TYPE_RINGBUF en lugar del ring SPSC propio, pero el CONTENIDO de
 * cada registro es identico, de modo que el correlador de Ring 3 es el mismo
 * codigo en las dos plataformas.
 *
 * Licencia dual: los helpers bpf_probe_read_user_str() y bpf_get_current_task()
 * estan marcados como GPL-only por el kernel, asi que la cadena de licencia
 * tiene que ser compatible con GPL para que el programa cargue. El resto del
 * proyecto es Apache-2.0; solo estos programas de kernel son duales.
 *
 * Principios que se respetan en todo el fichero:
 *   - Cero asignaciones dinamicas. Todo sale del ring o del scratch por CPU.
 *   - Cero bucles no acotados. El verificador rechazaria el programa.
 *   - Ante un ring lleno se descarta y se cuenta; jamas se aplica contrapresion.
 *   - Se filtra DENTRO del kernel. Emitir todo y filtrar arriba desperdicia el
 *     ancho de banda del ring, que es el recurso escaso.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "aegis_bpf_common.h"
#include "aegis_abi.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ------------------------------------------------------------------------
 * Mapas
 * ------------------------------------------------------------------------ */

/* 8 MiB. Dimensionado para absorber una rafaga de compilacion (el pico de
 * carga real mas duro) sin descartar, dando al agente ~2 s de margen para
 * drenar antes de perder eventos. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} aegis_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_bpf_config);
} aegis_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AEGIS_STAT__MAX);
    __type(key, __u32);
    __type(value, __u64);
} aegis_stats SEC(".maps");

/* Secuencia monotona por CPU. El consumidor detecta perdida comparando saltos
 * en `seq` por CPU, sin necesidad de un contador global que serializaria todas
 * las CPU en la misma linea de cache. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} aegis_seq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_scratch);
} aegis_scratch_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Utilidades
 * ------------------------------------------------------------------------ */

static __always_inline void aegis_stat_inc(enum aegis_stat which)
{
    __u32 key = (__u32)which;
    __u64 *slot = bpf_map_lookup_elem(&aegis_stats, &key);
    if (slot)
        (*slot)++;
}

static __always_inline const struct aegis_bpf_config *aegis_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&aegis_config, &key);
}

static __always_inline __u64 aegis_next_seq(void)
{
    __u32 key = 0;
    __u64 *slot = bpf_map_lookup_elem(&aegis_seq, &key);
    if (!slot)
        return 0;
    return ++(*slot);
}

/*
 * Clave estable de proceso.
 *
 * El PID se recicla, asi que por si solo no sirve como identidad: un ataque que
 * espere al reciclado consigue que la telemetria atribuya sus acciones a un
 * proceso inocente ya terminado. Se mezcla con start_boottime, que es monotono,
 * de modo que el par nunca se repite en la vida del sistema.
 *
 * FNV-1a de 64 bits, identico al que usa el driver de Windows, para que las
 * claves sean comparables entre plataformas en un despliegue mixto.
 */
static __always_inline __u64 aegis_key_from(__u32 tgid, __u64 start_boottime)
{
    __u64 h = 0xcbf29ce484222325ULL;
    h = (h ^ (start_boottime & 0xFFFFFFFFULL)) * 0x100000001b3ULL;
    h = (h ^ (start_boottime >> 32)) * 0x100000001b3ULL;
    h = (h ^ (__u64)tgid) * 0x100000001b3ULL;
    return h | 1ULL; /* 0 queda reservado para "sin actor" */
}

static __always_inline __u64 aegis_task_key(struct task_struct *task)
{
    if (!task)
        return 0;
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u64 start = BPF_CORE_READ(task, start_boottime);
    return aegis_key_from(tgid, start);
}

/*
 * Reserva un registro y rellena la cabecera comun.
 *
 * `total_len` tiene que ser constante en cada punto de llamada: el verificador
 * exige un tamano conocido para bpf_ringbuf_reserve, y ademas el ABI obliga a
 * que sea multiplo de 64.
 */
static __always_inline void *aegis_evt_begin(__u16 type, __u32 total_len,
                                             __u64 actor_key, __u64 target_key,
                                             __u32 flags)
{
    void *rec = bpf_ringbuf_reserve(&aegis_events, total_len, 0);
    if (!rec) {
        /* Ring lleno. Se descarta y se cuenta: el agente ve crecer el contador
         * y sabe que tiene un punto ciego. Bloquear aqui seria peor: estamos en
         * el contexto del proceso que hizo la syscall. */
        aegis_stat_inc(AEGIS_STAT_DROPPED_FULL);
        return 0;
    }

    aegis_evt_hdr_t *hdr = (aegis_evt_hdr_t *)rec;
    hdr->magic = AEGIS_EVT_MAGIC;
    hdr->abi_version = AEGIS_ABI_VERSION;
    hdr->type = type;
    hdr->total_len = total_len;
    hdr->flags = flags;
    hdr->seq = aegis_next_seq();
    hdr->ts_ns = bpf_ktime_get_boot_ns();
    hdr->actor_key = actor_key;
    hdr->target_key = target_key;
    hdr->cpu = bpf_get_smp_processor_id();
    hdr->verdict_id = 0;
    hdr->reserved = 0;
    return rec;
}

static __always_inline void aegis_evt_commit(void *rec)
{
    aegis_stat_inc(AEGIS_STAT_EMITTED);
    bpf_ringbuf_submit(rec, 0);
}

/*
 * Copia una cadena de espacio de usuario a una ranura de offset FIJO dentro del
 * registro y devuelve la referencia (offset, longitud) del ABI.
 *
 * El offset fijo no es una simplificacion: es lo que permite al verificador
 * aceptar la escritura sin comprobaciones dinamicas, y mantiene el coste del
 * evento constante e independiente de la longitud de la ruta.
 */
static __always_inline aegis_str_t aegis_put_str(void *rec, __u32 off, __u32 max,
                                                 const void *user_ptr)
{
    aegis_str_t s = { 0, 0 };
    if (!user_ptr)
        return s;

    char *dst = (char *)rec + off;
    long n = bpf_probe_read_user_str(dst, max, user_ptr);
    if (n <= 1)          /* error, o cadena vacia (solo el NUL) */
        return s;

    if ((__u32)n >= max) {
        n = max;
        aegis_stat_inc(AEGIS_STAT_TRUNCATED);
    }
    s.off = (__u16)off;
    s.len = (__u16)(n - 1);   /* el ABI no almacena el terminador NUL */
    return s;
}

/*
 * Decide si el actor actual debe generar telemetria.
 *
 * Devuelve el PID/TGID actual en `out_tgid` cuando procede emitir.
 */
static __always_inline int aegis_should_emit(__u32 trace_flag, __u32 *out_tgid)
{
    const struct aegis_bpf_config *cfg = aegis_cfg();
    if (!cfg)
        return 0;
    if (!(cfg->flags & AEGIS_CFG_ENABLED))
        return 0;
    if (trace_flag && !(cfg->flags & trace_flag))
        return 0;

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /* El agente no se observa a si mismo: si lo hiciera, cada evento que
     * consume y registra generaria eventos nuevos, en realimentacion positiva. */
    if (cfg->agent_pid && tgid == cfg->agent_pid) {
        aegis_stat_inc(AEGIS_STAT_FILTERED);
        return 0;
    }

    *out_tgid = tgid;
    return 1;
}

/* ------------------------------------------------------------------------
 * Sonda: ejecucion de proceso
 *
 * Se engancha en sys_enter_execve, que da la INTENCION junto con argv. El
 * evento describe por tanto un intento de ejecucion, no una ejecucion
 * consumada: una execve que falle (fichero inexistente, permisos, ENOEXEC)
 * tambien lo genera. Es deliberado, porque el intento fallido es en si mismo
 * telemetria util, y el correlador de Ring 3 confirma el exito por la
 * actividad posterior del proceso.
 * ------------------------------------------------------------------------ */
SEC("tracepoint/syscalls/sys_enter_execve")
int aegis_tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = 0;
    if (!aegis_should_emit(0, &tgid))
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 start = BPF_CORE_READ(task, start_boottime);
    __u64 actor = aegis_key_from(tgid, start);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    __u64 parent_key = aegis_task_key(parent);
    __u32 ppid = BPF_CORE_READ(parent, tgid);

    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];

    /* La linea de comandos se construye primero en el scratch por CPU: unir
     * argumentos exige escribir en offsets variables, y el verificador solo lo
     * acepta con holgura demostrable por encima del maximo. Despues se copia al
     * registro con un tamano constante. */
    __u32 zero = 0;
    struct aegis_scratch *scratch = bpf_map_lookup_elem(&aegis_scratch_map, &zero);
    if (!scratch)
        return 0;

    __u32 off = 0;
    __u32 written = 0;
#pragma unroll
    for (__u32 i = 0; i < AEGIS_ARGV_MAX; i++) {
        const char *argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0)
            break;
        if (!argp)
            break;
        if (off >= AEGIS_BPF_STR2_MAX)
            break;

        /* La mascara le prueba al verificador que el offset esta acotado; el
         * buffer tiene AEGIS_ARG_LEN bytes de holgura por encima del maximo
         * enmascarado, asi que la escritura nunca se sale. */
        __u32 pos = off & (AEGIS_BPF_STR2_MAX - 1);
        long n = bpf_probe_read_user_str(&scratch->buf[pos], AEGIS_ARG_LEN, argp);
        if (n <= 1)
            break;

        off = pos + (__u32)(n - 1);
        written = off;
        if (off < AEGIS_SCRATCH_LEN - 1) {
            scratch->buf[off] = ' ';   /* separador entre argumentos */
            off++;
        }
    }
    if (written > AEGIS_BPF_STR2_MAX)
        written = AEGIS_BPF_STR2_MAX;

    void *rec = aegis_evt_begin(AEGIS_EVT_PROCESS_CREATE, AEGIS_BPF_EVT_LARGE,
                                actor, 0, 0);
    if (!rec)
        return 0;

    aegis_proc_create_t *p = (aegis_proc_create_t *)((char *)rec + AEGIS_BPF_PAYLOAD_OFF);
    p->parent_key = parent_key;
    /* En Linux el creador y el padre coinciden en execve: no existe el
     * equivalente de PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. El campo se rellena
     * igualmente para que el correlador sea el mismo codigo en ambas
     * plataformas; una divergencia solo puede venir de Windows. */
    p->creator_key = parent_key;
    p->image_id = 0;
    p->create_time = start;
    p->pid = tgid;
    p->parent_pid = ppid;
    p->session_id = 0;
    p->token_flags = 0;
    p->integrity_level = AEGIS_IL_MEDIUM;
    p->signature_level = 0;
    p->user_sid.off = 0;
    p->user_sid.len = 0;
    p->cmdline.off = 0;
    p->cmdline.len = 0;

    p->image_path = aegis_put_str(rec, AEGIS_BPF_STR1_OFF, AEGIS_BPF_STR1_MAX, filename);

    if (written > 0) {
        char *dst = (char *)rec + AEGIS_BPF_STR2_OFF;
        /* Copia de tamano constante: el verificador la acepta sin analisis de
         * rango, y el coste del evento no depende de la longitud real. */
        __builtin_memcpy(dst, scratch->buf, AEGIS_BPF_STR2_MAX);
        p->cmdline.off = (__u16)AEGIS_BPF_STR2_OFF;
        p->cmdline.len = (__u16)written;
    }

    aegis_evt_commit(rec);
    return 0;
}

/* ------------------------------------------------------------------------
 * Sonda: apertura de fichero
 *
 * openat es de las syscalls mas frecuentes del sistema: emitir todas saturaria
 * el ring sin aportar nada. Solo se emiten las aperturas con INTENCION DE
 * ESCRITURA, que son las que importan para ransomware, persistencia y
 * manipulacion de binarios. Las lecturas se cubren, cuando hace falta, por otra
 * via en Ring 3.
 * ------------------------------------------------------------------------ */
SEC("tracepoint/syscalls/sys_enter_openat")
int aegis_tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = 0;
    if (!aegis_should_emit(AEGIS_CFG_TRACE_FILES, &tgid))
        return 0;

    __u32 flags = (__u32)ctx->args[2];
    if (!(flags & AEGIS_O_WRITE_INTENT)) {
        aegis_stat_inc(AEGIS_STAT_FILTERED);
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 actor = aegis_task_key(task);

    void *rec = aegis_evt_begin(AEGIS_EVT_FILE_PRE_CREATE, AEGIS_BPF_EVT_LARGE,
                                actor, 0, 0);
    if (!rec)
        return 0;

    aegis_file_op_t *f = (aegis_file_op_t *)((char *)rec + AEGIS_BPF_PAYLOAD_OFF);
    f->file_id = 0;          /* el inode se resuelve en Ring 3 si escala */
    f->volume_id = 0;
    f->bytes_written = 0;
    f->pid = tgid;
    f->desired_access = flags;
    f->create_options = (__u32)ctx->args[3];   /* modo */
    f->info_flags = 0;
    f->entropy_before = 0;   /* la entropia se calcula sobre escrituras, no aqui */
    f->entropy_after = 0;
    f->new_path.off = 0;
    f->new_path.len = 0;
    f->reserved0 = 0;
    f->reserved1 = 0;

    f->path = aegis_put_str(rec, AEGIS_BPF_STR1_OFF, AEGIS_BPF_STR1_MAX,
                            (const void *)ctx->args[1]);

    aegis_evt_commit(rec);
    return 0;
}

/* ------------------------------------------------------------------------
 * Sonda: ptrace
 *
 * En Linux, ptrace es el equivalente exacto de abrir un handle a otro proceso
 * con permiso de lectura o escritura de memoria en Windows: es la via para
 * inyectar codigo, robar credenciales de memoria o depurar un proceso ajeno.
 * Se emite SIEMPRE, sin filtrar por peticion: el volumen es despreciable y
 * cualquier uso merece contexto.
 * ------------------------------------------------------------------------ */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int aegis_tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = 0;
    if (!aegis_should_emit(AEGIS_CFG_TRACE_PTRACE, &tgid))
        return 0;

    __u32 request = (__u32)ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];

    /* PTRACE_TRACEME es un proceso pidiendo ser trazado por su propio padre:
     * es el patron de los depuradores y de los tests, y no cruza fronteras de
     * proceso hacia una victima. */
    if (request == AEGIS_PTRACE_TRACEME) {
        aegis_stat_inc(AEGIS_STAT_FILTERED);
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 actor = aegis_task_key(task);

    void *rec = aegis_evt_begin(AEGIS_EVT_HANDLE_REQUEST, AEGIS_BPF_EVT_SMALL,
                                actor, 0, 0);
    if (!rec)
        return 0;

    /* Se reutiliza aegis_remote_mem_t sin forzar la semantica: describe
     * exactamente "un proceso operando sobre la memoria de otro". */
    aegis_remote_mem_t *m = (aegis_remote_mem_t *)((char *)rec + AEGIS_BPF_PAYLOAD_OFF);
    m->target_key = 0;       /* Ring 3 lo resuelve desde su grafo de procesos */
    m->address = (__u64)ctx->args[2];
    m->region_size = (__u64)ctx->args[3];
    m->source_pid = tgid;
    m->target_pid = target_pid;
    m->alloc_type = request;
    m->protect = 0;
    m->prev_protect = 0;
    m->flags = 0;

    /* POKETEXT y POKEDATA escriben en la memoria del objetivo: es inyeccion,
     * no observacion. Se marca para que el motor de reglas no tenga que
     * reinterpretar el numero de peticion. */
    if (request == AEGIS_PTRACE_POKETEXT || request == AEGIS_PTRACE_POKEDATA)
        m->flags |= AEGIS_MEM_F_RWX;

    aegis_evt_commit(rec);
    return 0;
}

/* ------------------------------------------------------------------------
 * Sonda: salida de proceso
 *
 * Registro minimo de 64 bytes: solo cabecera. La clave del actor es todo lo
 * que Ring 3 necesita para cerrar el nodo en el grafo de linaje.
 * ------------------------------------------------------------------------ */
SEC("tracepoint/sched/sched_process_exit")
int aegis_tp_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 tgid = 0;
    if (!aegis_should_emit(0, &tgid))
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    /* Solo interesa la muerte del proceso, no la de cada hilo: sched_process_exit
     * dispara por hilo, y un proceso con 200 hilos generaria 200 eventos de
     * salida para un unico final. El lider del grupo es el proceso. */
    __u32 pid = BPF_CORE_READ(task, pid);
    if (pid != tgid)
        return 0;

    __u64 actor = aegis_task_key(task);

    void *rec = aegis_evt_begin(AEGIS_EVT_PROCESS_EXIT, AEGIS_BPF_EVT_TINY,
                                actor, 0, 0);
    if (!rec)
        return 0;

    aegis_evt_commit(rec);
    return 0;
}

/* ------------------------------------------------------------------------
 * Sonda: cambios de estado de socket TCP
 *
 * inet_sock_set_state es un tracepoint estable, a diferencia de un kprobe sobre
 * tcp_connect, que se rompe entre versiones de kernel. Da conexiones salientes
 * (SYN_SENT) y entrantes aceptadas (SYN_RECV) sin tocar el camino de datos.
 * ------------------------------------------------------------------------ */
SEC("tracepoint/sock/inet_sock_set_state")
int aegis_tp_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    __u32 tgid = 0;
    if (!aegis_should_emit(AEGIS_CFG_TRACE_NET, &tgid))
        return 0;

    int newstate = ctx->newstate;
    /* Solo el establecimiento importa. Los cierres y estados intermedios
     * multiplicarian el volumen sin aportar deteccion. */
    if (newstate != AEGIS_TCP_SYN_SENT && newstate != AEGIS_TCP_SYN_RECV)
        return 0;

    __u16 family = ctx->family;
    if (family != AEGIS_AF_INET && family != AEGIS_AF_INET6)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 actor = aegis_task_key(task);

    void *rec = aegis_evt_begin(AEGIS_EVT_NET_CONNECT, AEGIS_BPF_EVT_SMALL,
                                actor, 0, 0);
    if (!rec)
        return 0;

    aegis_net_conn_t *n = (aegis_net_conn_t *)((char *)rec + AEGIS_BPF_PAYLOAD_OFF);
    __builtin_memset(n, 0, sizeof(*n));

    /*
     * Las direcciones se leen a pila con bpf_core_read y desde ahi se copian al
     * registro. Ni memcpy directo desde ctx ni indexado elemento a elemento
     * valen: preserve_access_index hace que el compilador materialice un
     * puntero base sobre ctx para el array, y el verificador rechaza
     * dereferenciar un puntero de contexto modificado
     * ("dereference of modified ctx ptr"). Con bpf_core_read la reubicacion
     * CO-RE se mantiene, la lectura pasa por el helper de probe read, y la
     * copia final va de pila a ring buffer, que si es un patron aceptado.
     */
    __u8 tmp_src[16];
    __u8 tmp_dst[16];
    __builtin_memset(tmp_src, 0, sizeof(tmp_src));
    __builtin_memset(tmp_dst, 0, sizeof(tmp_dst));

    if (family == AEGIS_AF_INET) {
        /* IPv4 en los cuatro primeros bytes; el resto queda a cero, para que
         * Ring 3 no ramifique por familia en cada evento. */
        bpf_core_read(tmp_src, 4, ctx->saddr);
        bpf_core_read(tmp_dst, 4, ctx->daddr);
    } else {
        bpf_core_read(tmp_src, 16, ctx->saddr_v6);
        bpf_core_read(tmp_dst, 16, ctx->daddr_v6);
    }
    __builtin_memcpy(n->saddr, tmp_src, 16);
    __builtin_memcpy(n->daddr, tmp_dst, 16);

    n->pid = tgid;
    n->sport = ctx->sport;
    n->dport = ctx->dport;
    n->family = family;
    n->protocol = ctx->protocol;
    n->old_state = (__u16)ctx->oldstate;
    n->new_state = (__u16)newstate;
    n->flags = (newstate == AEGIS_TCP_SYN_SENT) ? AEGIS_NET_F_OUTBOUND
                                                : AEGIS_NET_F_INBOUND;

    /* Clasificacion barata del destino, hecha aqui para que el correlador no
     * tenga que repetirla por evento. */
    if (family == AEGIS_AF_INET) {
        __u8 a = n->daddr[0], b = n->daddr[1];
        if (a == 127)
            n->flags |= AEGIS_NET_F_LOOPBACK;
        else if (a == 10 ||
                 (a == 192 && b == 168) ||
                 (a == 172 && (b & 0xF0) == 16))
            n->flags |= AEGIS_NET_F_PRIVATE_DST;
    }

    aegis_evt_commit(rec);
    return 0;
}
