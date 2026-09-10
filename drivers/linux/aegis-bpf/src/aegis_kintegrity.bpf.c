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
 * # Por que las dos vistas van en el MISMO programa
 *
 * Entre una vista y la siguiente, los procesos nacen y mueren. Tomarlas en dos
 * llamadas al sistema distintas deja una ventana de milisegundos que produce
 * discrepancias falsas en cada barrido. Aqui las dos ocurren en una unica
 * invocacion, separadas por microsegundos, y ademas existe
 * `aegis_ki_confirmar`, que vuelve a mirar UN solo TID por los dos caminos para
 * descartar la carrera antes de acusar a nadie.
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
 */

/* vmlinux.h en lugar de <linux/bpf.h>: ademas de los tipos de kernel, es quien
 * aporta `struct task_struct` DEFINIDA y `struct bpf_iter_task` tal y como las
 * conoce el kernel de destino, que es justo lo que exigen las kfuncs de abajo. */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "aegis_bpf_common.h"
#include "aegis_kintegrity.h"

/*
 * GPL a secas y no dual: `bpf_task_from_pid`, `bpf_iter_task_*` y
 * `bpf_rcu_read_lock` estan marcadas GPL-only por el kernel. Es el unico
 * fichero del proyecto con esta licencia y esta aislado por ese motivo.
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
 * Las dos las resuelve vmlinux.h por construccion, y por eso ya no hay aqui ni
 * un `typedef int s32` ni una `struct bpf_iter_task` opaca escritos a mano:
 * eran precisamente el tipo de declaracion que acierta hoy y miente manana.
 * Ahora `s32` y `bpf_iter_task` son las del BTF del kernel.
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

/* Contexto del barrido de PID que recibe el callback de `bpf_loop`. */
struct aegis_ki_ctx_pid {
    int32_t primero;
    int32_t ultimo;
    uint32_t gen;
    uint32_t hallados;
    uint32_t desbordes;
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
    if (bpf_map_update_elem(&aegis_ki_pidmap, &clave, &v, BPF_ANY) == 0)
        c->hallados++;
    else
        c->desbordes++;
    return 0;
}

/* ------------------------------------------------------------------------
 * Barrido: las dos vistas en una sola invocacion
 * ------------------------------------------------------------------------ */

SEC("syscall")
int aegis_ki_barrido(struct aegis_ki_args *a)
{
    if (!a)
        return AEGIS_KI_ERR_ARGS;

    uint32_t gen = a->gen;
    uint32_t en_lista = 0;
    uint32_t desbordes = 0;

    /* --- Vista B: recorrido de la lista de tareas --- */
    struct bpf_iter_task it;
    struct task_struct *t;

    bpf_rcu_read_lock();
    int err = bpf_iter_task_new(&it, (struct task_struct *)0,
                                AEGIS_KI_ITER_TODOS_LOS_HILOS);
    if (!err) {
        while ((t = bpf_iter_task_next(&it))) {
            struct aegis_ki_task v;
            aegis_ki_retratar(t, &v, gen);
            uint32_t clave = (uint32_t)BPF_CORE_READ(t, pid);
            if (bpf_map_update_elem(&aegis_ki_lista, &clave, &v, BPF_ANY) == 0)
                en_lista++;
            else
                desbordes++;
        }
    }
    /* Obligatorio en todos los caminos: ver la nota de cabecera. */
    bpf_iter_task_destroy(&it);
    bpf_rcu_read_unlock();

    if (err) {
        a->error = AEGIS_KI_ERR_ITERADOR;
        return AEGIS_KI_ERR_ITERADOR;
    }

    /* --- Vista C: sondeo del espacio de PID --- */
    struct aegis_ki_ctx_pid c = {
        .primero = a->primero,
        .ultimo = a->ultimo,
        .gen = gen,
        .hallados = 0,
        .desbordes = 0,
    };
    uint32_t cuantos = 0;
    if (a->ultimo >= a->primero) {
        int64_t rango = (int64_t)a->ultimo - (int64_t)a->primero + 1;
        cuantos = rango > AEGIS_KI_MAX_BARRIDO ? AEGIS_KI_MAX_BARRIDO
                                               : (uint32_t)rango;
    }
    bpf_loop(cuantos, aegis_ki_sonda_pid, &c, 0);

    a->en_lista = en_lista;
    a->en_pidmap = c.hallados;
    a->desbordes = desbordes + c.desbordes;
    a->error = 0;
    return 0;
}

/* ------------------------------------------------------------------------
 * Confirmacion: un solo TID, por los dos caminos, en el mismo instante
 * ------------------------------------------------------------------------ */

/* Contexto de la busqueda de un TID concreto en la lista. */
struct aegis_ki_ctx_busca {
    int32_t tid;
    uint32_t hallado;
    uint64_t start_boottime;
    uint32_t tgid;
};

/*
 * Confirma o descarta una discrepancia.
 *
 * Es la pieza que hace utilizable el detector. Entre el barrido y el veredicto
 * pasan milisegundos, y en ese tiempo un proceso puede haber muerto: el barrido
 * lo veria en una vista y no en la otra, y acusaria de rootkit a un `ls` que
 * termino. Aqui se vuelve a mirar el MISMO TID por los dos caminos con
 * microsegundos de diferencia, de modo que un proceso que murio desaparece de
 * las dos y uno oculto conserva la asimetria.
 */
SEC("syscall")
int aegis_ki_confirmar(struct aegis_ki_confirm *c)
{
    if (!c)
        return AEGIS_KI_ERR_ARGS;

    c->en_lista = 0;
    c->en_pidmap = 0;
    c->start_boottime = 0;
    c->tgid = 0;

    /* Camino 1: espacio de PID. */
    struct task_struct *t = bpf_task_from_pid(c->tid);
    if (t) {
        c->en_pidmap = 1;
        c->start_boottime = aegis_inicio_de_tarea(t);
        c->tgid = BPF_CORE_READ(t, tgid);
        bpf_task_release(t);
    }

    /* Camino 2: lista de tareas. */
    struct aegis_ki_ctx_busca b = {
        .tid = c->tid,
        .hallado = 0,
        .start_boottime = 0,
        .tgid = 0,
    };
    struct bpf_iter_task it;
    struct task_struct *p;
    bpf_rcu_read_lock();
    int err = bpf_iter_task_new(&it, (struct task_struct *)0,
                                AEGIS_KI_ITER_TODOS_LOS_HILOS);
    if (!err) {
        while ((p = bpf_iter_task_next(&it))) {
            if (BPF_CORE_READ(p, pid) == b.tid) {
                b.hallado = 1;
                b.start_boottime = aegis_inicio_de_tarea(p);
                b.tgid = BPF_CORE_READ(p, tgid);
                /* No se corta el bucle: el iterador tiene que agotarse o
                 * quedarse en un estado que el verificador no acepta al
                 * destruirlo a medias en algunos kernels. Recorrer lo que
                 * queda cuesta microsegundos. */
            }
        }
    }
    bpf_iter_task_destroy(&it);
    bpf_rcu_read_unlock();

    if (err)
        return AEGIS_KI_ERR_ITERADOR;

    c->en_lista = b.hallado;
    if (!c->en_pidmap && b.hallado) {
        c->start_boottime = b.start_boottime;
        c->tgid = b.tgid;
    }
    return 0;
}
