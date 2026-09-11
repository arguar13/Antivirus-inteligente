/* Ejercita la politica del minifilter de rollback (FASE 50).
 *
 * El minifilter solo compila con el WDK, en Windows. Pero la DECISION —que
 * escritura merece copia-sombra— es C portable y se prueba aqui con gcc y clang,
 * porque es la parte que puede estar mal de forma cara: interceptar de mas llena
 * el disco del cliente; de menos deja ficheros sin poder revertir.
 */
#include <stdio.h>
#include <string.h>
#include "../kernel/windows/aegis/include/aegis_rollback_politica.h"

static int fallos = 0, total = 0;
static void afirmar(int c, const char *q) {
    total++;
    if (!c) { fallos++; printf("  FALLO: %s\n", q); }
}

static aegis_rb_contexto base(void) {
    aegis_rb_contexto c;
    memset(&c, 0, sizeof(c));
    return c;
}

int main(void) {
    /* El propio EDR nunca se intercepta, ni siquiera en incidente. */
    {
        aegis_rb_contexto c = base();
        c.solicitante_confiable = 1;
        c.incidente_activo = 1;
        c.transicion_a_cifrado = 1;
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_IGNORAR,
                "al EDR de confianza no se le copia (evita bucle y disco lleno)");
    }
    /* Dedup gana sobre incidente: no pisar la copia buena. */
    {
        aegis_rb_contexto c = base();
        c.ya_copiado = 1;
        c.incidente_activo = 1;
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_IGNORAR,
                "un fichero ya copiado no se vuelve a copiar");
    }
    /* Ruido del sistema no se copia. */
    {
        aegis_rb_contexto c = base();
        c.ruta_sistema = 1;
        c.transicion_a_cifrado = 1;
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_IGNORAR,
                "el ruido del sistema no se copia aunque parezca cifrado");
    }
    /* Con incidente confirmado se copia todo lo que el proceso toque. */
    {
        aegis_rb_contexto c = base();
        c.incidente_activo = 1;
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_COPIAR,
                "en incidente se preserva todo lo que el proceso malicioso toque");
    }
    /* Sin incidente, la transicion a cifrado dispara la copia. */
    {
        aegis_rb_contexto c = base();
        c.transicion_a_cifrado = 1;
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_COPIAR,
                "la firma cruda del cifrado salva a las primeras victimas");
    }
    /* Una escritura normal sin nada de lo anterior no se copia. */
    {
        aegis_rb_contexto c = base();
        afirmar(aegis_rb_decidir(&c) == AEGIS_RB_IGNORAR,
                "una escritura normal no dispara copia");
    }
    /* Un puntero nulo no concede copia. */
    afirmar(aegis_rb_decidir(NULL) == AEGIS_RB_IGNORAR, "NULL no copia");

    if (fallos == 0) { printf("OK: %d afirmaciones de la politica de rollback se cumplen.\n", total); return 0; }
    printf("FALLO: %d de %d afirmaciones fallan.\n", fallos, total);
    return 1;
}
