/*
 * Empaquetador de prueba REAL, reducido a lo esencial.
 *
 * En disco, el "codigo real" (un payload) esta CIFRADO con XOR: la firma que
 * contiene, "AEGIS_UNPACKED_OK_7F3A", no aparece en el fichero. En tiempo de
 * ejecucion, el stub reserva una region mmap(RWX), descifra el payload dentro,
 * y salta a el. El payload deja la firma en claro en esa region y despues hace
 * una syscall (exit), que es cuando el tracer detecta el OEP.
 *
 * Es exactamente lo que hace un empaquetador real: codigo comprimido/cifrado en
 * disco, desplegado en memoria en tiempo de ejecucion. Aqui el "cifrado" es un
 * XOR de un byte para que el fixture sea reproducible sin dependencias.
 */
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

/* Clave XOR de un byte. */
#define K 0x5A

/*
 * El payload YA CIFRADO. Se genera con la herramienta de al lado y se pega
 * aqui. Contiene: la firma en claro tras descifrar, y un stub que hace exit(0).
 *
 * El payload en claro es codigo x86-64 posicion-independiente:
 *   - unos bytes de datos con la firma (nunca ejecutados como codigo: se salta)
 *   - jmp corto por encima de los datos, y luego el exit.
 * Para simplificar y que sea robusto, el payload en claro es:
 *     EB 16                  jmp +0x16 (por encima de la firma de 22 bytes)
 *     "AEGIS_UNPACKED_OK_7F3A" (22 bytes de firma)
 *     48 31 FF               xor rdi, rdi        ; codigo de salida 0
 *     48 C7 C0 3C 00 00 00   mov rax, 60         ; SYS_exit
 *     0F 05                  syscall
 */
static const unsigned char PAYLOAD_CIFRADO[] = {
    /* se rellena en tiempo de compilacion desde el array en claro, ver abajo */
    0
};

/* El payload en CLARO, para cifrarlo en tiempo de compilacion no es trivial en
 * C; en su lugar lo llevamos en claro en un array `const` y lo ciframos al
 * vuelo antes de escribirlo... pero eso dejaria la firma en claro en el .rodata.
 * Para que la firma NO este en el binario, la ciframos aqui a mano byte a byte:
 * el array de abajo ya esta XOR'd con K. */
static unsigned char payload[] = {
    0xEB ^ K, 0x16 ^ K,
    /* "AEGIS_UNPACKED_OK_7F3A" xor K */
    'A' ^ K, 'E' ^ K, 'G' ^ K, 'I' ^ K, 'S' ^ K, '_' ^ K,
    'U' ^ K, 'N' ^ K, 'P' ^ K, 'A' ^ K, 'C' ^ K, 'K' ^ K, 'E' ^ K, 'D' ^ K, '_' ^ K,
    'O' ^ K, 'K' ^ K, '_' ^ K, '7' ^ K, 'F' ^ K, '3' ^ K, 'A' ^ K,
    0x48 ^ K, 0x31 ^ K, 0xFF ^ K,
    0x48 ^ K, 0xC7 ^ K, 0xC0 ^ K, 0x3C ^ K, 0x00 ^ K, 0x00 ^ K, 0x00 ^ K,
    0x0F ^ K, 0x05 ^ K
};

int main(void)
{
    (void)PAYLOAD_CIFRADO;
    unsigned long n = sizeof(payload);
    /* Region ejecutable NUEVA: aqui va el codigo real. */
    unsigned char *m = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 1;
    /* Descifrar el payload dentro de la region. */
    for (unsigned long i = 0; i < n; i++)
        m[i] = payload[i] ^ K;
    /* Saltar al OEP: la primera instruccion del codigo desempaquetado. */
    void (*oep)(void) = (void (*)(void))m;
    oep();
    return 0;
}
