/* Implementacion de la politica de tamper protection. Portable: ni una linea
 * del WDK.
 *
 * Ver `include/aegis_tamper.h` para por que esta separada del minifilter.
 *
 * El orden de las reglas ES la decision de seguridad, y termina en la linea
 * etica: la autorizacion del dueno (el OTP) siempre gana sobre la autodefensa.
 */

#include "include/aegis_tamper.h"

aegis_veredicto_tamper_t aegis_decidir_tamper(const aegis_contexto_tamper *ctx)
{
    /* 0. Contexto nulo: es un fallo del driver, no una peticion legitima. Se
     *    falla CERRADO (denegar): ante una peticion malformada, mejor bloquear
     *    que dejar pasar un sabotaje. El camino del dueno siempre trae un
     *    contexto valido con `orden_autorizada`, asi que esto no lo bloquea. */
    if (ctx == NULL)
        return AEGIS_TAMPER_DENEGAR;

    /* 1. Nunca pelear contra el sistema operativo ni contra nosotros mismos.
     *    El kernel abre y cierra handles contra todo constantemente; estorbarle
     *    rompe el sistema operativo del dueno de formas que se manifiestan como
     *    pantallazos azules. El propio agente y los componentes de AegisCore
     *    —el watchdog, que tiene que poder pararse y reiniciarse para la
     *    auto-recuperacion— tambien pasan. */
    if (ctx->es_kernel || ctx->es_mismo_agente || ctx->es_componente_aegis)
        return AEGIS_TAMPER_PERMITIR;

    /* 2. Solo defendemos lo nuestro. Sobre un recurso ajeno no nos metemos: un
     *    EDR no puede ser la razon por la que las aplicaciones del cliente
     *    dejan de poder borrar sus propios ficheros. */
    if (!ctx->recurso_protegido)
        return AEGIS_TAMPER_PERMITIR;

    /* 3. LA LINEA ETICA. Un recurso protegido, pero con una orden autorizada del
     *    Control Plane: es el DUENO de la flota ejerciendo su derecho a
     *    desinstalar, parar o quitar AegisCore. SIEMPRE se permite. Es
     *    exactamente lo que separa a un EDR de un rootkit: un rootkit no le da a
     *    nadie la llave para quitarlo. */
    if (ctx->orden_autorizada)
        return AEGIS_TAMPER_PERMITIR;

    /* 4. Recurso protegido, sin autorizacion del dueno: es un intento de
     *    sabotaje (tipicamente un atacante con privilegios que quiere cegar al
     *    EDR antes de actuar). Se deniega. */
    return AEGIS_TAMPER_DENEGAR;
}
