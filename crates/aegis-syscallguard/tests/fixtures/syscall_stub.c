/*
 * Vector de prueba real para el guardia de syscalls.
 *
 * Hace, a proposito, DOS clases de syscall que el guardia debe distinguir:
 *
 *   1. Una syscall LEGITIMA a traves de libc: write(2) por su envoltorio de
 *      glibc. El puntero de instruccion cae en el .text de libc.
 *
 *   2. Una syscall DIRECTA: copia un pequeno trozo de codigo maquina en una
 *      pagina ANONIMA con permiso de ejecucion y salta a el. Ese codigo tiene
 *      su propia instruccion `syscall` (0F 05 en x86-64, `svc #0` en aarch64)
 *      y entra al kernel sin pasar por libc. Es exactamente lo que hace el
 *      malware que evade los enganches de userland. El puntero de instruccion
 *      cae en memoria anonima: la firma que el guardia busca.
 *
 * No es una simulacion: es la tecnica de evasion, ejecutada de verdad contra el
 * kernel real. El guardia lo traza y tiene que ver una —y solo una— syscall de
 * origen anonimo.
 */
#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#if defined(__x86_64__)
/* mov eax, 39 (getpid); syscall; ret */
static const unsigned char SHELL[] = {
    0xB8, 0x27, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3
};
#elif defined(__aarch64__)
/* mov x8, #172 (getpid); svc #0; ret */
static const unsigned char SHELL[] = {
    0x88, 0x15, 0x80, 0xD2, 0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6
};
#else
#error "arquitectura no soportada por el vector de prueba"
#endif

int main(void)
{
    /* (1) syscall legitima a traves de libc */
    const char marca[] = "AEGIS_SYSCALLGUARD_STUB\n";
    ssize_t _ = write(1, marca, sizeof(marca) - 1);
    (void)_;

    /* (2) syscall directa desde memoria anonima ejecutable */
    void *pagina = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pagina == MAP_FAILED)
        return 2;
    memcpy(pagina, SHELL, sizeof(SHELL));

    /* barrera de cache de instrucciones (imprescindible en aarch64) */
    __builtin___clear_cache((char *)pagina, (char *)pagina + sizeof(SHELL));

    void (*directa)(void) = (void (*)(void))pagina;
    directa();

    return 0;
}
