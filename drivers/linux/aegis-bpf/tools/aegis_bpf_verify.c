/*
 * Somete los programas eBPF de AegisCore al verificador del kernel.
 *
 * Compilar un programa eBPF no demuestra que sea cargable: el verificador
 * rechaza codigo que compila sin un solo warning (accesos que no puede probar
 * acotados, bucles cuyo fin no puede demostrar, punteros sin comprobar contra
 * NULL). Esta herramienta abre el objeto, lo carga de verdad y reporta, de modo
 * que un fallo del verificador rompa la build igual que un error de compilacion.
 *
 * PRUEBA CRUZADA DE CO-RE (FASE 42)
 * ---------------------------------
 * Con `--btf <fichero>` se le dice a libbpf que resuelva las reubicaciones
 * CO-RE contra el BTF de OTRO kernel en vez de contra el que esta corriendo.
 * Eso convierte la promesa "compile once, run everywhere" en algo comprobable
 * aqui y ahora: si un campo que el codigo lee no existiera o hubiera cambiado
 * en ese kernel, libbpf lo diria al reubicar, y no meses despues en el endpoint
 * de un cliente.
 *
 * KFUNCS EXIGIDAS (FASE 0 del MP-15)
 * ----------------------------------
 * Con `--requiere-kfunc <nombre>` (repetible) se comprueba ANTES de cargar que
 * el BTF del kernel EN EJECUCION exponga esas kfunc. Si falta alguna, el objeto
 * no aplica a este kernel: se dice cual falta y se sale con 77, el codigo
 * convencional de «omitido». Es la forma de distinguir, en la matriz de kernels,
 * «este kernel no tiene la capacidad» de «el bytecode esta mal», y de hacerlo
 * dentro de la maquina que se prueba y no en la que compila.
 *
 * Salida 0 si todos los programas cargan; 1 en caso contrario; 77 si el kernel
 * no tiene una kfunc exigida.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <sys/utsname.h>

/* Se pone a 1 si libbpf informa de que no pudo REUBICAR un acceso CO-RE.
 *
 * Distinguirlo importa. Al probar contra el BTF de otro kernel hay dos fallos
 * que no se parecen en nada:
 *
 *   - "failed to resolve CO-RE relocation": el codigo lee un campo que en ese
 *     kernel no existe o cambio de nombre. Es un defecto REAL de portabilidad y
 *     tiene que romper la construccion.
 *
 *   - el verificador rechaza el programa DESPUES de reubicar bien: el bytecode
 *     quedo ajustado a la disposicion del kernel objetivo, y se esta intentando
 *     cargar en el kernel de ESTA maquina, que es otro. Es una limitacion del
 *     metodo de prueba, no del producto.
 *
 * Sin esta distincion, el segundo caso se leeria como el primero y el equipo
 * acabaria persiguiendo un defecto que no existe —o, peor, silenciando la
 * comprobacion entera para quitarse el ruido de encima—.
 */
static int core_sin_resolver;

/* Las kfunc exigidas (--requiere-kfunc) y, si el verificador rechazo alguna por
 * no estar PERMITIDA en el tipo de programa, cual.
 *
 * Que una kfunc exista en el BTF no basta: el kernel la registra para ciertos
 * tipos de programa y no para otros. En Ubuntu 24.04 (6.8) `bpf_task_from_pid`
 * existe pero no se permite en programas `syscall`, y la matriz de kernels lo
 * vio como un FALLO del objeto cuando es una capacidad que ESE kernel no tiene.
 * Se reconoce solo para las kfunc declaradas como exigidas: cualquier otro
 * rechazo sigue siendo un fallo. */
static const char *kfuncs[8];
static int n_kfuncs;
static char kfunc_no_permitida[64];

static int silenciar_libbpf(enum libbpf_print_level nivel, const char *fmt, va_list args)
{
    /* Los avisos y errores si interesan: son el diagnostico del verificador. */
    if (nivel == LIBBPF_DEBUG)
        return 0;
    if (strstr(fmt, "failed to resolve CO-RE relocation"))
        core_sin_resolver = 1;

    /* El log del verificador llega como argumento %s: hay que formatearlo para
     * buscar en el. */
    va_list copia;
    va_copy(copia, args);
    int n = vsnprintf(NULL, 0, fmt, copia);
    va_end(copia);
    char *texto = n > 0 ? malloc((size_t)n + 1) : NULL;
    if (!texto)
        return vfprintf(stderr, fmt, args);
    vsnprintf(texto, (size_t)n + 1, fmt, args);
    for (int k = 0; k < n_kfuncs; k++) {
        char aguja[128];
        snprintf(aguja, sizeof(aguja), "calling kernel function %s is not allowed", kfuncs[k]);
        if (strstr(texto, aguja))
            snprintf(kfunc_no_permitida, sizeof(kfunc_no_permitida), "%s", kfuncs[k]);
    }
    fputs(texto, stderr);
    free(texto);
    return n;
}

int main(int argc, char **argv)
{
    const char *btf_ajeno = NULL;
    const char *ruta = NULL;
    int solo_core = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--btf") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--btf necesita la ruta de un BTF\n");
                return 2;
            }
            btf_ajeno = argv[++i];
        } else if (strcmp(argv[i], "--solo-core") == 0) {
            solo_core = 1;
        } else if (strcmp(argv[i], "--requiere-kfunc") == 0) {
            if (i + 1 >= argc || n_kfuncs == (int)(sizeof(kfuncs) / sizeof(kfuncs[0]))) {
                fprintf(stderr, "--requiere-kfunc necesita un nombre (maximo 8)\n");
                return 2;
            }
            kfuncs[n_kfuncs++] = argv[++i];
        } else if (ruta == NULL) {
            ruta = argv[i];
        } else {
            fprintf(stderr, "argumento inesperado: %s\n", argv[i]);
            return 2;
        }
    }
    if (ruta == NULL) {
        fprintf(stderr,
                "uso: %s [--btf <vmlinux.btf>] [--solo-core]\n"
                "          [--requiere-kfunc <nombre>]... <objeto.bpf.o>\n"
                "  --btf             reubica CO-RE contra el BTF de OTRO kernel\n"
                "  --solo-core       exige que las reubicaciones RESUELVAN, sin exigir\n"
                "                    que el programa cargue en el kernel de esta maquina\n"
                "  --requiere-kfunc  si el kernel en ejecucion no la expone, sale con 77\n",
                argv[0]);
        return 2;
    }

    libbpf_set_print(silenciar_libbpf);

    if (n_kfuncs > 0) {
        struct btf *vmlinux = btf__load_vmlinux_btf();
        if (libbpf_get_error(vmlinux)) {
            fprintf(stderr, "FALLO: no se pudo leer el BTF del kernel en ejecucion\n");
            return 1;
        }
        struct utsname u;
        uname(&u);
        for (int k = 0; k < n_kfuncs; k++) {
            if (btf__find_by_name_kind(vmlinux, kfuncs[k], BTF_KIND_FUNC) < 0) {
                printf("NO-APLICA: %s exige la kfunc %s y el kernel %s no la expone\n",
                       ruta, kfuncs[k], u.release);
                btf__free(vmlinux);
                return 77;
            }
        }
        btf__free(vmlinux);
    }

    LIBBPF_OPTS(bpf_object_open_opts, opciones);
    if (btf_ajeno)
        opciones.btf_custom_path = btf_ajeno;

    struct bpf_object *obj = bpf_object__open_file(ruta, &opciones);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "FALLO: no se pudo abrir %s: %s\n", ruta, strerror((int)-err));
        return 1;
    }

    int n_progs = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
        n_progs++;

    if (btf_ajeno)
        printf("==> %s: %d programas  [CO-RE contra %s]\n", ruta, n_progs, btf_ajeno);
    else
        printf("==> %s: %d programas\n", ruta, n_progs);

    if (bpf_object__load(obj) != 0) {
        if (kfunc_no_permitida[0]) {
            struct utsname u;
            uname(&u);
            printf("NO-APLICA: %s exige la kfunc %s y el kernel %s la tiene pero no la "
                   "permite en este tipo de programa\n",
                   ruta, kfunc_no_permitida, u.release);
            bpf_object__close(obj);
            return 77;
        }
        if (core_sin_resolver) {
            fprintf(stderr,
                    "FALLO: hay accesos que NO se pueden reubicar contra ese kernel.\n"
                    "       El bytecode no es portable a el; el detalle esta arriba.\n");
            bpf_object__close(obj);
            return 1;
        }
        if (solo_core) {
            printf("    CO-RE OK: todas las reubicaciones resolvieron.\n");
            printf("    (la carga no aplica: el objeto quedo ajustado a OTRO kernel,\n");
            printf("     y el que corre en esta maquina tiene otra disposicion)\n");
            bpf_object__close(obj);
            return 0;
        }
        fprintf(stderr,
                "FALLO: el verificador del kernel rechazo el objeto (errno %d: %s)\n"
                "       El log del verificador aparece arriba.\n",
                errno, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        printf("    OK  %-24s seccion=%-44s fd=%d\n",
               bpf_program__name(prog),
               bpf_program__section_name(prog),
               bpf_program__fd(prog));
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        printf("    MAP %-24s tipo=%-2d max_entries=%u\n",
               bpf_map__name(map), bpf_map__type(map), bpf_map__max_entries(map));
    }

    printf("==> Todos los programas pasan el verificador del kernel.\n");
    bpf_object__close(obj);
    return 0;
}
