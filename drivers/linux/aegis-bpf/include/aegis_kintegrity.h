/*
 * AegisCore - contrato de la verificacion cruzada del kernel.
 *
 * Estas estructuras cruzan la frontera entre el programa eBPF y el agente de
 * Ring 3, y tambien entre C y Rust. Su disposicion en memoria es parte del
 * contrato: `tools/abi-check.sh` compara los tamanos y desplazamientos que ve
 * el compilador de C con los que declara el espejo de Rust, porque un campo
 * desalineado aqui no da un error de compilacion, da veredictos de rootkit
 * sobre procesos inocentes.
 *
 * Todos los campos son de anchura fija y estan ordenados de mayor a menor
 * alineacion, con relleno explicito. Nada queda al criterio del compilador.
 */
#ifndef AEGIS_KINTEGRITY_H
#define AEGIS_KINTEGRITY_H

/*
 * Se usan los tipos de `<stdint.h>` y no los `__u32` del kernel, igual que
 * `aegis_abi.h`: los programas eBPF ya incluyen `linux/bpf.h`, que define los
 * `__u*` de kernel, y redefinirlos aqui choca. Con `stdint.h` la cabecera vale
 * tal cual para el compilador de BPF, para el comprobador de ABI y para el
 * espejo de Rust.
 */
#include <stdint.h>

/* Capacidad de los mapas de vista. 65536 cubre `pid_max` por defecto (32768)
 * con holgura para un sistema que lo haya subido. Al desbordarse se CUENTA, no
 * se descarta en silencio: un barrido incompleto no puede pasar por limpio. */
#define AEGIS_KI_MAX_TAREAS   65536u

/* Iteraciones maximas del barrido de PID en una invocacion. */
#define AEGIS_KI_MAX_BARRIDO  65536u

/* Banderas de `bpf_iter_task_new`. */
#define AEGIS_KI_ITER_SOLO_PROCESOS      0u  /* solo lideres de grupo de hilos */
#define AEGIS_KI_ITER_TODOS_LOS_HILOS    1u  /* todas las tareas              */

/* Errores devueltos por los programas. */
#define AEGIS_KI_ERR_ARGS      (-1)
#define AEGIS_KI_ERR_ITERADOR  (-2)

/* Longitud de `comm` en el kernel, incluido el terminador. */
#define AEGIS_KI_COMM_LEN 16

/*
 * Retrato de una tarea vista por el kernel.
 *
 * `start_boottime` no es informativo: es lo que convierte el TID en una
 * IDENTIDAD. Dos procesos que reutilicen el mismo numero tienen instantes de
 * arranque distintos, y sin ese campo un PID reciclado entre el barrido y la
 * confirmacion pareceria el mismo proceso.
 */
struct aegis_ki_task {
    uint64_t start_boottime;              /*  0: ns monotonos desde el arranque  */
    uint32_t tgid;                        /*  8: PID en terminologia de userland */
    uint32_t gen;                         /* 12: generacion del barrido          */
    uint32_t flags;                       /* 16: reservado                       */
    uint8_t  comm[AEGIS_KI_COMM_LEN];     /* 20: nombre corto                    */
    uint32_t _pad;                        /* 36: relleno explicito               */
};                                     /* 40 bytes                            */

/*
 * Argumentos y resultados del barrido.
 *
 * El programa escribe DIRECTAMENTE en esta estructura del espacio de usuario:
 * los programas `SEC("syscall")` reciben su contexto como un puntero real y
 * `bpf_prog_test_run` no debe llevar `ctx_out`, o el kernel devuelve EINVAL.
 */
struct aegis_ki_args {
    int32_t primero;    /*  0: primer PID del barrido                           */
    int32_t ultimo;     /*  4: ultimo PID del barrido, inclusive                */
    uint32_t gen;        /*  8: generacion; descarta entradas de barridos previos */
    uint32_t en_lista;   /* 12: tareas vistas en la lista de tareas              */
    uint32_t en_pidmap;  /* 16: tareas halladas en el espacio de PID             */
    uint32_t desbordes;  /* 20: entradas que no cupieron en los mapas            */
    int32_t error;      /* 24: 0 o un AEGIS_KI_ERR_*                            */
    uint32_t _pad;       /* 28: relleno explicito                                */
};                    /* 32 bytes                                             */

/*
 * Confirmacion de UN solo TID por los dos caminos.
 *
 * Es la pieza que hace utilizable el detector: entre el barrido y el veredicto
 * pasan milisegundos y un proceso puede haber muerto, lo que produciria una
 * discrepancia falsa. Aqui las dos consultas se hacen con microsegundos de
 * diferencia sobre el mismo TID.
 */
struct aegis_ki_confirm {
    int32_t tid;               /*  0: TID a confirmar                           */
    uint32_t en_lista;          /*  4: 1 si aparece en la lista de tareas        */
    uint32_t en_pidmap;         /*  8: 1 si aparece en el espacio de PID         */
    uint32_t tgid;              /* 12: grupo de hilos, si se pudo leer           */
    uint64_t start_boottime;    /* 16: instante de arranque, si se pudo leer     */
};                           /* 24 bytes                                      */

#endif /* AEGIS_KINTEGRITY_H */
