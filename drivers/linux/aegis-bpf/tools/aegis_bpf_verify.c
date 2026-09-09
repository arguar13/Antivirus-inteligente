/*
 * Somete los programas eBPF de AegisCore al verificador del kernel.
 *
 * Compilar un programa eBPF no demuestra que sea cargable: el verificador
 * rechaza codigo que compila sin un solo warning (accesos que no puede probar
 * acotados, bucles cuyo fin no puede demostrar, punteros sin comprobar contra
 * NULL). Esta herramienta abre el objeto, lo carga de verdad y reporta, de modo
 * que un fallo del verificador rompa la build igual que un error de compilacion.
 *
 * Salida 0 si todos los programas cargan; 1 en caso contrario.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int silenciar_libbpf(enum libbpf_print_level nivel, const char *fmt, va_list args)
{
    /* Los avisos y errores si interesan: son el diagnostico del verificador. */
    if (nivel == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "uso: %s <objeto.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(silenciar_libbpf);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "FALLO: no se pudo abrir %s: %s\n", argv[1], strerror((int)-err));
        return 1;
    }

    int n_progs = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
        n_progs++;

    printf("==> %s: %d programas\n", argv[1], n_progs);

    if (bpf_object__load(obj) != 0) {
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
