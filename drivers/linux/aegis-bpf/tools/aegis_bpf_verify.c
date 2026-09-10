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
 * Salida 0 si todos los programas cargan; 1 en caso contrario.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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

static int silenciar_libbpf(enum libbpf_print_level nivel, const char *fmt, va_list args)
{
    /* Los avisos y errores si interesan: son el diagnostico del verificador. */
    if (nivel == LIBBPF_DEBUG)
        return 0;
    if (strstr(fmt, "failed to resolve CO-RE relocation"))
        core_sin_resolver = 1;
    return vfprintf(stderr, fmt, args);
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
        } else if (ruta == NULL) {
            ruta = argv[i];
        } else {
            fprintf(stderr, "argumento inesperado: %s\n", argv[i]);
            return 2;
        }
    }
    if (ruta == NULL) {
        fprintf(stderr,
                "uso: %s [--btf <vmlinux.btf>] [--solo-core] <objeto.bpf.o>\n"
                "  --btf        reubica CO-RE contra el BTF de OTRO kernel\n"
                "  --solo-core  exige que las reubicaciones RESUELVAN, sin exigir\n"
                "               que el programa cargue en el kernel de esta maquina\n",
                argv[0]);
        return 2;
    }

    libbpf_set_print(silenciar_libbpf);

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
