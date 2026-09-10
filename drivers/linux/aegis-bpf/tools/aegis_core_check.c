// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * AegisCore - comprobacion de conformidad CO-RE del bytecode eBPF (FASE 42).
 *
 * POR QUE EXISTE
 * --------------
 * "Compilar con vmlinux.h" no demuestra nada por si solo. Un programa eBPF
 * puede compilar perfectamente y llevar dentro los desplazamientos del kernel
 * de la maquina de construccion grabados a fuego: cargara sin protestar en ese
 * kernel y leera campos equivocados en cualquier otro. El fallo es SILENCIOSO
 * —no hay error, hay telemetria mal interpretada—, que es la peor clase de
 * fallo en un producto de deteccion.
 *
 * Lo que hace que el bytecode sea universal son las REUBICACIONES CO-RE: una
 * tabla en la seccion .BTF.ext que dice, por cada acceso a una estructura del
 * kernel, que tipo y que campo se pretendia leer. libbpf la recorre al cargar y
 * reescribe cada desplazamiento contra el BTF del kernel de destino.
 *
 * Este programa abre el objeto compilado y comprueba, sobre los bytes reales:
 *   1. que lleva .BTF (los tipos) y .BTF.ext (las reubicaciones),
 *   2. que la cabecera de .BTF.ext es de una version que incluye CO-RE,
 *   3. que hay reubicaciones y ninguna esta malformada,
 *   4. y a que tipos del kernel apuntan, para poder auditar la superficie.
 *
 * Un objeto con CERO reubicaciones se rechaza: significa que no toca ninguna
 * estructura del kernel de forma reubicable, y en este proyecto eso solo puede
 * ser un error de compilacion.
 *
 * Uso:  aegis_core_check <objeto.bpf.o> [...]
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

#include <bpf/btf.h>

/* ------------------------------------------------------------------------
 * Formato de .BTF.ext. Esta documentado en include/uapi/linux/btf.h del kernel
 * y en libbpf; se declara aqui porque libbpf no expone acceso publico a la
 * tabla de reubicaciones CO-RE.
 * ------------------------------------------------------------------------ */
#define BTF_MAGIC_ESPERADO 0xeB9F

struct cab_btf_ext {
    uint16_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint32_t hdr_len;
    /* Desplazamientos relativos al FINAL de la cabecera. */
    uint32_t func_info_off;
    uint32_t func_info_len;
    uint32_t line_info_off;
    uint32_t line_info_len;
    /* Parte opcional: solo si hdr_len la cubre. */
    uint32_t core_relo_off;
    uint32_t core_relo_len;
};

/* Cabecera de cada subseccion: a que seccion del ELF pertenece y cuantos
 * registros trae. */
struct cab_sec_info {
    uint32_t sec_name_off;
    uint32_t num_info;
};

/* Un registro de reubicacion CO-RE. */
struct relo_core {
    uint32_t insn_off;       /* instruccion a reescribir (en bytes)          */
    uint32_t type_id;        /* tipo del BTF LOCAL que se pretendia acceder  */
    uint32_t access_str_off; /* cadena de acceso: "0:3" = campo 3 del tipo   */
    uint32_t kind;           /* que se reubica: desplazamiento, existencia...*/
};

static const char *nombre_kind(uint32_t k)
{
    switch (k) {
    case 0:  return "byte-offset";
    case 1:  return "byte-size";
    case 2:  return "field-exists";
    case 3:  return "signedness";
    case 4:  return "lshift-u64";
    case 5:  return "rshift-u64";
    case 6:  return "local-type-id";
    case 7:  return "target-type-id";
    case 8:  return "type-exists";
    case 9:  return "type-size";
    case 10: return "enumval-exists";
    case 11: return "enumval-value";
    case 12: return "type-matches";
    default: return "desconocido";
    }
}

/* Lee entera una seccion del ELF por nombre. Devuelve 0 si no existe. */
static int leer_seccion(Elf *elf, const char *nombre, const void **datos, size_t *tam)
{
    size_t idx_str;
    if (elf_getshdrstrndx(elf, &idx_str) != 0)
        return -1;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr sh;
        if (gelf_getshdr(scn, &sh) != &sh)
            return -1;
        const char *n = elf_strptr(elf, idx_str, sh.sh_name);
        if (!n || strcmp(n, nombre) != 0)
            continue;
        Elf_Data *d = elf_getdata(scn, NULL);
        if (!d || !d->d_buf)
            return -1;
        *datos = d->d_buf;
        *tam = d->d_size;
        return 1;
    }
    return 0;
}

struct resumen {
    unsigned long relocaciones;
    unsigned long por_kind[16];
    unsigned secciones;
};

/* Recorre la tabla de reubicaciones CO-RE de .BTF.ext. */
static int recorrer_core(const void *ext, size_t tam_ext, const struct btf *btf,
                         struct resumen *res, int detallado)
{
    if (tam_ext < sizeof(struct cab_btf_ext)) {
        fprintf(stderr, "  .BTF.ext mide %zu bytes: no cabe ni la cabecera\n", tam_ext);
        return -1;
    }
    struct cab_btf_ext cab;
    memcpy(&cab, ext, sizeof(cab));

    if (cab.magic != BTF_MAGIC_ESPERADO) {
        fprintf(stderr, "  magic de .BTF.ext = 0x%04x, se esperaba 0x%04x\n",
                cab.magic, BTF_MAGIC_ESPERADO);
        return -1;
    }
    /* La parte de CO-RE es opcional en el formato: si hdr_len no llega hasta
     * ella, el compilador no emitio reubicaciones y el objeto NO es portable. */
    if (cab.hdr_len < sizeof(struct cab_btf_ext)) {
        fprintf(stderr, "  cabecera de .BTF.ext de %u bytes: sin campos CO-RE\n",
                cab.hdr_len);
        fprintf(stderr, "  | el bytecode lleva los desplazamientos del kernel de compilacion\n");
        return -1;
    }
    if (cab.core_relo_len == 0) {
        fprintf(stderr, "  la tabla de reubicaciones CO-RE esta VACIA\n");
        return -1;
    }

    const uint8_t *base = (const uint8_t *)ext + cab.hdr_len;
    size_t tam_datos = tam_ext - cab.hdr_len;
    if ((size_t)cab.core_relo_off + cab.core_relo_len > tam_datos) {
        fprintf(stderr, "  la tabla CO-RE se sale de la seccion\n");
        return -1;
    }

    const uint8_t *p = base + cab.core_relo_off;
    const uint8_t *fin = p + cab.core_relo_len;

    if ((size_t)(fin - p) < sizeof(uint32_t)) {
        fprintf(stderr, "  tabla CO-RE truncada: falta el tamano de registro\n");
        return -1;
    }
    uint32_t rec_size;
    memcpy(&rec_size, p, sizeof(rec_size));
    p += sizeof(rec_size);

    if (rec_size < sizeof(struct relo_core)) {
        fprintf(stderr, "  registro CO-RE de %u bytes: menor que los %zu del formato\n",
                rec_size, sizeof(struct relo_core));
        return -1;
    }

    while (p < fin) {
        if ((size_t)(fin - p) < sizeof(struct cab_sec_info)) {
            fprintf(stderr, "  subseccion CO-RE truncada\n");
            return -1;
        }
        struct cab_sec_info sec;
        memcpy(&sec, p, sizeof(sec));
        p += sizeof(sec);

        const char *nombre_sec = btf__str_by_offset(btf, sec.sec_name_off);
        size_t necesarios = (size_t)sec.num_info * rec_size;
        if ((size_t)(fin - p) < necesarios) {
            fprintf(stderr, "  la subseccion '%s' declara %u registros que no caben\n",
                    nombre_sec ? nombre_sec : "?", sec.num_info);
            return -1;
        }

        res->secciones++;
        if (detallado)
            printf("    %-46s %4u reubicaciones\n",
                   nombre_sec ? nombre_sec : "(sin nombre)", sec.num_info);

        for (uint32_t i = 0; i < sec.num_info; i++) {
            struct relo_core r;
            memcpy(&r, p + (size_t)i * rec_size, sizeof(r));

            /* Un registro tiene que apuntar a un tipo real del BTF local y a
             * una cadena de acceso valida; si no, libbpf no sabria que
             * reubicar y la portabilidad seria ficticia. */
            if (btf__type_by_id(btf, r.type_id) == NULL) {
                fprintf(stderr, "  reubicacion con type_id %u inexistente en .BTF\n",
                        r.type_id);
                return -1;
            }
            const char *acceso = btf__str_by_offset(btf, r.access_str_off);
            if (acceso == NULL || acceso[0] == '\0') {
                fprintf(stderr, "  reubicacion sin cadena de acceso (type_id %u)\n",
                        r.type_id);
                return -1;
            }

            res->relocaciones++;
            res->por_kind[r.kind < 16 ? r.kind : 15]++;
        }
        p += necesarios;
    }
    return 0;
}

static int comprobar(const char *ruta, int detallado)
{
    printf("==> %s\n", ruta);

    int fd = open(ruta, O_RDONLY);
    if (fd < 0) {
        perror("  open");
        return -1;
    }
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "  no es un ELF valido: %s\n", elf_errmsg(-1));
        close(fd);
        return -1;
    }

    int rc = -1;
    const void *btf_datos = NULL, *ext_datos = NULL;
    size_t btf_tam = 0, ext_tam = 0;
    struct btf *btf = NULL;

    if (leer_seccion(elf, ".BTF", &btf_datos, &btf_tam) != 1) {
        fprintf(stderr, "  FALTA la seccion .BTF: el objeto no lleva tipos\n");
        fprintf(stderr, "  | falta -g al compilar con clang\n");
        goto salir;
    }
    if (leer_seccion(elf, ".BTF.ext", &ext_datos, &ext_tam) != 1) {
        fprintf(stderr, "  FALTA la seccion .BTF.ext: no hay reubicaciones CO-RE\n");
        goto salir;
    }

    btf = btf__new(btf_datos, (uint32_t)btf_tam);
    if (!btf) {
        fprintf(stderr, "  .BTF ilegible\n");
        goto salir;
    }

    struct resumen res;
    memset(&res, 0, sizeof(res));
    if (recorrer_core(ext_datos, ext_tam, btf, &res, detallado) != 0)
        goto salir;

    if (res.relocaciones == 0) {
        fprintf(stderr, "  CERO reubicaciones CO-RE\n");
        goto salir;
    }

    printf("    .BTF %zu B, .BTF.ext %zu B, %u seccion(es), %lu reubicacion(es)\n",
           btf_tam, ext_tam, res.secciones, res.relocaciones);
    printf("    tipos:");
    for (uint32_t k = 0; k < 16; k++)
        if (res.por_kind[k])
            printf(" %s=%lu", nombre_kind(k), res.por_kind[k]);
    printf("\n");
    rc = 0;

salir:
    if (btf)
        btf__free(btf);
    elf_end(elf);
    close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "uso: %s <objeto.bpf.o> [...]\n", argv[0]);
        return 2;
    }
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf desactualizada: %s\n", elf_errmsg(-1));
        return 2;
    }

    int detallado = getenv("AEGIS_CORE_DETALLE") != NULL;
    int fallos = 0;
    for (int i = 1; i < argc; i++)
        if (comprobar(argv[i], detallado) != 0)
            fallos++;

    if (fallos) {
        fprintf(stderr, "\n%d objeto(s) NO son reubicables via CO-RE.\n", fallos);
        return 1;
    }
    printf("\nTodos los objetos llevan reubicaciones CO-RE bien formadas.\n");
    return 0;
}
