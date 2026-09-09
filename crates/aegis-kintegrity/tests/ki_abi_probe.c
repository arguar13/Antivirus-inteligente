/*
 * Sonda de layout del contrato de verificacion cruzada, lado C.
 *
 * Imprime tamano, alineacion y offset de cada campo de aegis_kintegrity.h tal
 * y como los calcula el compilador de C (el mismo que compila el programa
 * eBPF). La prueba `abi_layout` en Rust compara esta salida con lo que declara
 * el espejo de `abi.rs`: un campo desplazado aqui no da un error de
 * compilacion, da veredictos de rootkit sobre procesos inocentes.
 */
#include <stdio.h>
#include <stddef.h>
#include "aegis_kintegrity.h"

#define P_SIZE(t)   printf("%s sizeof %zu\n", #t, sizeof(t))
#define P_ALIGN(t)  printf("%s alignof %zu\n", #t, _Alignof(t))
#define P_OFF(t, f) printf("%s.%s %zu\n", #t, #f, offsetof(t, f))

int main(void)
{
    P_SIZE(struct aegis_ki_task);
    P_ALIGN(struct aegis_ki_task);
    P_OFF(struct aegis_ki_task, start_boottime);
    P_OFF(struct aegis_ki_task, tgid);
    P_OFF(struct aegis_ki_task, gen);
    P_OFF(struct aegis_ki_task, flags);
    P_OFF(struct aegis_ki_task, comm);

    P_SIZE(struct aegis_ki_args);
    P_ALIGN(struct aegis_ki_args);
    P_OFF(struct aegis_ki_args, primero);
    P_OFF(struct aegis_ki_args, ultimo);
    P_OFF(struct aegis_ki_args, gen);
    P_OFF(struct aegis_ki_args, en_lista);

    P_SIZE(struct aegis_ki_confirm);
    P_ALIGN(struct aegis_ki_confirm);
    P_OFF(struct aegis_ki_confirm, tid);
    P_OFF(struct aegis_ki_confirm, tgid);
    P_OFF(struct aegis_ki_confirm, start_boottime);
    return 0;
}
