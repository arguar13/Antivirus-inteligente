/*
 * Sonda de layout del evento L7, lado C (FASE 66).
 *
 * Imprime el tamano y el desplazamiento de cada campo tal y como los calcula el
 * compilador de C, que es el que compila el programa eBPF. tools/abi-check-l7.sh
 * compara esta salida con la de la sonda equivalente en Rust.
 *
 * Las aserciones `_Static_assert` de la cabecera ya fijan lo que ve C, y las
 * `const` de abi.rs fijan lo que ve Rust. Lo que ninguna puede ver es a la otra:
 * eso lo cierra el diff de las dos sondas.
 */
#include <stdio.h>
#include <stddef.h>

/* El programa eBPF usa los tipos __u* del kernel; fuera de una unidad de
 * traduccion de BPF no existen, asi que se aportan con los mismos anchos. Si
 * estos alias no coincidieran con los del kernel, el layout saldria distinto y
 * el diff contra Rust lo delataria, que es justo para lo que sirve esta sonda. */
typedef unsigned char      __u8;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

#include "aegis_sslsniff.h"

#define P_SIZE(t)      printf("%s sizeof %zu\n", #t, sizeof(t))
#define P_ALIGN(t)     printf("%s alignof %zu\n", #t, _Alignof(t))
#define P_OFF(t, f)    printf("%s.%s %zu\n", #t, #f, offsetof(t, f))

int main(void)
{
    P_SIZE(struct aegis_l7_evento);
    P_ALIGN(struct aegis_l7_evento);
    P_OFF(struct aegis_l7_evento, tiempo_ns);
    P_OFF(struct aegis_l7_evento, inicio_tarea_ns);
    P_OFF(struct aegis_l7_evento, longitud_total);
    P_OFF(struct aegis_l7_evento, pid);
    P_OFF(struct aegis_l7_evento, tid);
    P_OFF(struct aegis_l7_evento, direccion);
    P_OFF(struct aegis_l7_evento, carga_len);
    P_OFF(struct aegis_l7_evento, comm);
    P_OFF(struct aegis_l7_evento, carga);
    printf("AEGIS_L7_CARGA_MAX %u\n", (unsigned)AEGIS_L7_CARGA_MAX);
    printf("AEGIS_L7_COMM_MAX %u\n", (unsigned)AEGIS_L7_COMM_MAX);
    printf("AEGIS_L7_SALIENTE %d\n", (int)AEGIS_L7_SALIENTE);
    printf("AEGIS_L7_ENTRANTE %d\n", (int)AEGIS_L7_ENTRANTE);
    return 0;
}
