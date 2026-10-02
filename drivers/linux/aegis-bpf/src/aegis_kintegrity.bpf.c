// SPDX-License-Identifier: GPL-2.0
/*
 * AegisCore - verificacion cruzada de la integridad del kernel (Ring 0).
 *
 * # Que problema resuelve
 *
 * Un rootkit de kernel que hace DKOM (Direct Kernel Object Manipulation)
 * desenlaza el `task_struct` de su proceso de la lista global de tareas. A
 * partir de ese momento el proceso es invisible para todo lo que recorra esa
 * lista —`/proc`, `ps`, `top` y cualquier EDR que pregunte al sistema— pero
 * SIGUE EJECUTANDOSE, porque el planificador no usa esa lista: usa las colas de
 * ejecucion, y el proceso sigue estando en el arbol de PID.
 *
 * Esa asimetria es la firma. No se detecta preguntando mejor: se detecta
 * preguntando por DOS CAMINOS distintos y comparando.
 *
 * # Las dos vistas de kernel
 *
 *   Vista B - la LISTA DE TAREAS, recorrida con el iterador abierto
 *             `bpf_iter_task_*`. Es la estructura que el rootkit desenlaza.
 *   Vista C - el ESPACIO DE PID, sondeado con `bpf_task_from_pid()`. Va contra
 *             el `idr` del espacio de nombres de PID, una estructura DISTINTA
 *             que el rootkit tiene que dejar intacta si quiere que su proceso
 *             siga siendo planificable y pueda recibir senales.
 *
 * Una tarea en C pero no en B es DKOM. Una tarea en las dos pero ausente de
 * `/proc` (vista A, en Ring 3) es ocultacion en espacio de usuario.
 *
 * # Por tramos
 *
 * Cada invocacion trabaja sobre UN TRAMO `[primero, ultimo]` del espacio de PID
 * de como mucho AEGIS_KI_MAX_BARRIDO (65536) numeros: C sondea el tramo y B
 * guarda solo las tareas cuyo PID cae en el. `pid_max` llega a 4194304 (el
 * valor que fija systemd en 64 bits: Ubuntu, Fedora), asi que el espacio entero
 * son hasta 64 tramos, y el espacio de usuario los pide en lecturas sucesivas
 * del iterador (crates/aegis-kintegrity/src/tramos.rs decide cuales). Asi:
 *
 *   - B y C de un mismo PID siguen tomandose en la MISMA invocacion;
 *   - ninguna invocacion pasa de 65536 sondeos, y entre una y otra el hilo
 *     vuelve a espacio de usuario, donde el planificador puede expropiarlo;
 *   - una peticion de mas de 65536 PID se RECHAZA con AEGIS_KI_ERR_ARGS. La
 *     version anterior la recortaba en silencio: con `pid_max` = 4194304 toda
 *     tarea por encima del PID 65536 quedaba en B y fuera de C sin que el
 *     informe lo dijera, y un DKOM ahi no se veia.
 *
 * # Por que las dos vistas van en el MISMO programa
 *
 * Entre una vista y la siguiente, los procesos nacen y mueren. Tomarlas en dos
 * llamadas al sistema distintas deja una ventana de milisegundos que produce
 * discrepancias falsas en cada barrido. Aqui las dos ocurren en una unica
 * invocacion, separadas por microsegundos, y ademas existe
 * `aegis_ki_confirmar`, que vuelve a mirar UN solo TID por los dos caminos para
 * descartar la carrera antes de acusar a nadie.
 *
 * # Por que son iteradores `iter.s/task` y no programas `syscall`
 *
 * El kernel no permite un kfunc a todo programa: lo registra POR TIPO DE
 * PROGRAMA (`kfunc_init`, kernel/bpf/helpers.c). Medido en el codigo:
 *
 *   kfunc                                   TRACING          SYSCALL
 *   bpf_task_from_pid, bpf_task_release     desde 6.2        desde 6.10
 *   bpf_iter_task_*, bpf_rcu_read_*         todos los tipos (conjunto comun)
 *
 * La version anterior eran programas `SEC("syscall")` ejecutados con
 * BPF_PROG_RUN: cargaban en 6.10+ y Ubuntu 24.04 (6.8) los rechazaba con
 * «calling kernel function bpf_task_from_pid is not allowed», aunque el kfunc
 * existe desde 6.2. Un programa iterador es de tipo TRACING, y para TRACING
 * todos los kfuncs de aqui estan permitidos desde que existen: el minimo pasa a
 * ser el de `bpf_iter_task_new`, Linux 6.7.
 *
 * Lo que NO cambia es la propiedad de arriba. El enlace del iterador se crea
 * con `link_info.task.tid` = el PID de este proceso (el lider del grupo, que
 * vive tanto como el proceso), asi que el iterador visita UNA sola tarea y el
 * programa corre UNA vez por lectura. Esa unica invocacion toma las dos vistas
 * seguidas, igual que antes. La tarea que visita es solo el ancla que dispara
 * el programa: no es una vista ni se compara con nada.
 *
 * Transporte:
 *   peticion   el espacio de usuario escribe `struct aegis_ki_args` (o
 *              `aegis_ki_confirm`) en la entrada 0 de un mapa ARRAY;
 *   ejecucion  `read()` sobre el fd de `bpf_iter_create(enlace)`;
 *   respuesta  el programa la devuelve con `bpf_seq_write` en esa misma
 *              lectura: la misma estructura, ya rellena.
 * La disposicion de las estructuras no cambia (ver aegis_kintegrity.h).
 *
 * `iter.s` y no `iter`: durmiente, como lo era `SEC("syscall")` para libbpf.
 * El kernel lo ejecuta bajo `rcu_read_lock_trace` con la migracion desactivada
 * y SIN desactivar la expropiacion, que importa en un tramo de 65536 PID; y
 * el verificador razona el RCU exactamente igual que con la version anterior.
 * El objetivo `task` admite programas durmientes (BPF_ITER_RESCHED).
 *
 * # Notas del verificador que costaron sangre
 *
 *   - `bpf_iter_task_new` EXIGE seccion critica RCU. Sin ella el verificador
 *     rechaza el programa, y hace bien: recorrer la lista de tareas sin RCU es
 *     un uso despues de liberar dentro del kernel.
 *   - El iterador queda creado AUNQUE `new` devuelva error, asi que
 *     `bpf_iter_task_destroy` tiene que llamarse en todos los caminos o el
 *     verificador lo rechaza por fuga de referencia.
 *   - El barrido de PID va con `bpf_loop` y no con un bucle desenrollado: 32768
 *     iteraciones desenrolladas superan el limite de complejidad de saltos del
 *     verificador ("the sequence of N jumps is too complex").
 *   - Los contadores viven en el valor del mapa de peticion y no en la pila.
 *     Un contador en la pila cambia en cada vuelta del iterador abierto o del
 *     callback de `bpf_loop`, y la convergencia de esos bucles se razona
 *     comparando estados; los verificadores de 6.7/6.8 son los menos
 *     indulgentes con eso. Un incremento a traves de un puntero a mapa es una
 *     escritura en memoria y no hace distintos dos estados.
 */

/* vmlinux.h en lugar de <linux/bpf.h>: ademas de los tipos de kernel, es quien
 * aporta `struct task_struct` DEFINIDA, `struct bpf_iter_task` y el contexto
 * `struct bpf_iter__task` tal y como las conoce el kernel de destino, que es
 * justo lo que exigen las kfuncs y el objetivo de iterador de abajo. */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "aegis_bpf_common.h"
#include "aegis_kintegrity.h"

/*
 * GPL a secas y no dual: `bpf_task_from_pid`, `bpf_iter_task_*`,
 * `bpf_rcu_read_lock` y `bpf_seq_write` estan marcadas GPL-only por el kernel.
 * Es el unico fichero del proyecto con esta licencia y esta aislado por ese
 * motivo.
 */
char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------------
 * kfuncs del kernel
 *
 * Los prototipos tienen que coincidir EXACTAMENTE con el BTF del kernel o
 * libbpf rechaza la carga con "func_proto incompatible". Dos trampas concretas:
 *   - `struct task_struct` tiene que estar DEFINIDA, no declarada hacia
 *     delante: una declaracion adelantada es BTF_KIND_FWD y no casa con el
 *     BTF_KIND_STRUCT del kernel.
 *   - El PID es `s32` en el BTF del kernel, no `int`.
 *
 * Las dos las resuelve vmlinux.h por construccion.
 *
 * Esta lista es la que comprueba la sonda del agente (`KFUNCS_TAREAS` en
 * crates/aegis-agent/src/motores/mod.rs), y una prueba de alli la coteja con
 * este fichero: anadir un kfunc aqui sin anadirlo alli rompe esa prueba.
 * ------------------------------------------------------------------------ */

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern int bpf_iter_task_new(struct bpf_iter_task *it, struct task_struct *task,
                             unsigned int flags) __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* ------------------------------------------------------------------------
 * Mapas
 * ------------------------------------------------------------------------ */

/* Vista B: lo que aparece recorriendo la lista de tareas. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AEGIS_KI_MAX_TAREAS);
    __type(key, __u32);
    __type(value, struct aegis_ki_task);
} aegis_ki_lista SEC(".maps");

/* Vista C: lo que aparece sondeando el espacio de PID. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AEGIS_KI_MAX_TAREAS);
    __type(key, __u32);
    __type(value, struct aegis_ki_task);
} aegis_ki_pidmap SEC(".maps");

/* Peticion del barrido: la entrada 0 la escribe el espacio de usuario antes de
 * leer el iterador. Los nombres caben en los 15 caracteres del kernel. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_ki_args);
} aegis_ki_arg SEC(".maps");

/* Peticion de la confirmacion. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_ki_confirm);
} aegis_ki_cnf SEC(".maps");

/* ------------------------------------------------------------------------
 * Utilidades
 * ------------------------------------------------------------------------ */

/*
 * Copia el retrato de una tarea.
 *
 * `start_boottime` es lo que convierte el TID en una identidad: dos procesos
 * distintos que reutilicen el mismo numero tienen instantes de arranque
 * distintos, y sin ese campo un PID reciclado entre la deteccion y la
 * confirmacion pareceria el mismo proceso.
 */
static __always_inline void aegis_ki_retratar(struct task_struct *t,
                                              struct aegis_ki_task *out,
                                              uint32_t gen)
{
    out->tgid = BPF_CORE_READ(t, tgid);
    out->start_boottime = aegis_inicio_de_tarea(t);
    out->gen = gen;
    out->flags = 0;
    out->_pad = 0;
    __builtin_memset(out->comm, 0, sizeof(out->comm));
    /* `comm` es un ARRAY dentro de task_struct, no un puntero: leerlo con
     * BPF_CORE_READ daria el primer byte. La macro _STR_INTO reubica el
     * desplazamiento por CO-RE y copia la cadena entera. */
    BPF_CORE_READ_STR_INTO(&out->comm, t, comm);
}

/*
 * Si esta invocacion es la que tiene que trabajar.
 *
 * El enlace esta anclado a una sola tarea, asi que el programa corre una vez
 * con esa tarea y otra al terminar con `task == NULL` (la llamada de cierre del
 * seq_file). Se trabaja solo en la primera. Exigir ademas `seq_num == 0` hace
 * que, aunque el ancla se perdiera y el iterador recorriera todas las tareas,
 * el barrido se hiciera una vez y no una por tarea.
 */
static __always_inline int aegis_ki_es_la_primera(struct bpf_iter__task *ctx)
{
    return ctx->task != (void *)0 && ctx->meta->seq_num == 0;
}

/* Contexto del barrido de PID que recibe el callback de `bpf_loop`. Solo lleva
 * datos que no cambian durante el bucle: ver la ultima nota de cabecera. */
struct aegis_ki_ctx_pid {
    int32_t primero;
    int32_t ultimo;
    uint32_t gen;
    uint32_t _pad;
};

/*
 * Un PID del barrido.
 *
 * Devolver 1 corta el bucle; se usa solo al pasarse del rango, nunca ante un
 * PID que no existe, porque los huecos en el espacio de PID son lo normal.
 */
static int aegis_ki_sonda_pid(uint32_t i, void *ctx)
{
    struct aegis_ki_ctx_pid *c = ctx;
    int32_t pid = c->primero + (int32_t)i;
    if (pid > c->ultimo)
        return 1;

    struct task_struct *t = bpf_task_from_pid(pid);
    if (!t)
        return 0;

    struct aegis_ki_task v;
    aegis_ki_retratar(t, &v, c->gen);
    bpf_task_release(t);

    uint32_t clave = (uint32_t)pid;
    long rc = bpf_map_update_elem(&aegis_ki_pidmap, &clave, &v, BPF_ANY);

    uint32_t cero = 0;
    struct aegis_ki_args *a = bpf_map_lookup_elem(&aegis_ki_arg, &cero);
    if (a) {
        if (rc == 0)
            a->en_pidmap++;
        else
            a->desbordes++;
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Barrido: las dos vistas de UN tramo en una sola invocacion
 * ------------------------------------------------------------------------ */

SEC("iter.s/task")
int aegis_ki_barrido(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    if (!aegis_ki_es_la_primera(ctx))
        return 0;

    uint32_t cero = 0;
    struct aegis_ki_args *a = bpf_map_lookup_elem(&aegis_ki_arg, &cero);
    if (!a)
        return 0; /* sin respuesta: el espacio de usuario lo trata como error */

    /* El tramo se copia a la pila: no cambia durante los bucles, asi que no
     * hace distintos los estados que compara el verificador (ver la ultima
     * nota de cabecera; lo que cambia son los contadores, y esos van en el
     * mapa). */
    uint32_t gen = a->gen;
    int32_t primero = a->primero;
    int32_t ultimo = a->ultimo;
    a->en_lista = 0;
    a->en_pidmap = 0;
    a->desbordes = 0;
    a->error = 0;
    a->_pad = 0;

    /* Un tramo valido: no vacio, sin negativos y de AEGIS_KI_MAX_BARRIDO PID
     * como mucho. Lo que no cumpla se rechaza ANTES de tomar ninguna vista:
     * recortarlo dejaria PID sin sondear y un informe que no lo dice. */
    if (primero < 0 || ultimo < primero ||
        (int64_t)ultimo - (int64_t)primero + 1 > (int64_t)AEGIS_KI_MAX_BARRIDO) {
        a->error = AEGIS_KI_ERR_ARGS;
        bpf_seq_write(seq, a, sizeof(*a));
        return 0;
    }

    /* --- Vista B: recorrido de la lista de tareas, quedandose con el tramo --- */
    struct bpf_iter_task it;
    struct task_struct *t;

    bpf_rcu_read_lock();
    int err = bpf_iter_task_new(&it, (struct task_struct *)0,
                                AEGIS_KI_ITER_TODOS_LOS_HILOS);
    if (!err) {
        while ((t = bpf_iter_task_next(&it))) {
            int32_t pid = BPF_CORE_READ(t, pid);
            /* Fuera del tramo no se guarda: lo trae la invocacion de SU tramo,
             * junto con su vista C. */
            if (pid < primero || pid > ultimo)
                continue;
            struct aegis_ki_task v;
            aegis_ki_retratar(t, &v, gen);
            uint32_t clave = (uint32_t)pid;
            if (bpf_map_update_elem(&aegis_ki_lista, &clave, &v, BPF_ANY) == 0)
                a->en_lista++;
            else
                a->desbordes++;
        }
    }
    /* Obligatorio en todos los caminos: ver la nota de cabecera. */
    bpf_iter_task_destroy(&it);
    bpf_rcu_read_unlock();

    if (err) {
        a->error = AEGIS_KI_ERR_ITERADOR;
        bpf_seq_write(seq, a, sizeof(*a));
        return 0;
    }

    /* --- Vista C: sondeo del tramo del espacio de PID --- */
    struct aegis_ki_ctx_pid c = {
        .primero = primero,
        .ultimo = ultimo,
        .gen = gen,
        ._pad = 0,
    };
    /* Validado arriba: entre 1 y AEGIS_KI_MAX_BARRIDO, muy por debajo del
     * BPF_MAX_LOOPS (2^23) de `bpf_loop`. El tramo entero, sin recorte. */
    uint32_t cuantos = (uint32_t)(ultimo - primero) + 1;
    bpf_loop(cuantos, aegis_ki_sonda_pid, &c, 0);

    /* La respuesta sale por la misma lectura que disparo el barrido. */
    bpf_seq_write(seq, a, sizeof(*a));
    return 0;
}

/* ------------------------------------------------------------------------
 * Confirmacion: un solo TID, por los dos caminos, en el mismo instante
 * ------------------------------------------------------------------------ */

/*
 * Confirma o descarta una discrepancia.
 *
 * Es la pieza que hace utilizable el detector. Entre el barrido y el veredicto
 * pasan milisegundos, y en ese tiempo un proceso puede haber muerto: el barrido
 * lo veria en una vista y no en la otra, y acusaria de rootkit a un `ls` que
 * termino. Aqui se vuelve a mirar el MISMO TID por los dos caminos con
 * microsegundos de diferencia, de modo que un proceso que murio desaparece de
 * las dos y uno oculto conserva la asimetria.
 *
 * La respuesta devuelve el mismo `tid` que se pidio; un `tid` NEGATIVO en la
 * respuesta es un AEGIS_KI_ERR_* (los TID reales son positivos).
 */
SEC("iter.s/task")
int aegis_ki_confirmar(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    if (!aegis_ki_es_la_primera(ctx))
        return 0;

    uint32_t cero = 0;
    struct aegis_ki_confirm *c = bpf_map_lookup_elem(&aegis_ki_cnf, &cero);
    if (!c)
        return 0;

    int32_t tid = c->tid;
    c->en_lista = 0;
    c->en_pidmap = 0;
    c->start_boottime = 0;
    c->tgid = 0;

    /* Camino 1: espacio de PID. */
    struct task_struct *t = bpf_task_from_pid(tid);
    if (t) {
        c->en_pidmap = 1;
        c->start_boottime = aegis_inicio_de_tarea(t);
        c->tgid = BPF_CORE_READ(t, tgid);
        bpf_task_release(t);
    }

    /* Camino 2: lista de tareas. */
    struct bpf_iter_task it;
    struct task_struct *p;
    bpf_rcu_read_lock();
    int err = bpf_iter_task_new(&it, (struct task_struct *)0,
                                AEGIS_KI_ITER_TODOS_LOS_HILOS);
    if (!err) {
        while ((p = bpf_iter_task_next(&it))) {
            if (BPF_CORE_READ(p, pid) != tid)
                continue;
            c->en_lista = 1;
            /* El retrato del espacio de PID manda; el de la lista solo se
             * usa si el PID no resolvio. */
            if (!c->en_pidmap) {
                c->start_boottime = aegis_inicio_de_tarea(p);
                c->tgid = BPF_CORE_READ(p, tgid);
            }
            /* No se corta el bucle: el iterador tiene que agotarse o
             * quedarse en un estado que el verificador no acepta al
             * destruirlo a medias en algunos kernels. Recorrer lo que
             * queda cuesta microsegundos. */
        }
    }
    bpf_iter_task_destroy(&it);
    bpf_rcu_read_unlock();

    if (err)
        c->tid = AEGIS_KI_ERR_ITERADOR;

    bpf_seq_write(seq, c, sizeof(*c));
    return 0;
}
