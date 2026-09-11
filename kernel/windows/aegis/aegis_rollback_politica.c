/* Implementacion de la politica de rollback. Portable: ni una linea del WDK.
 *
 * Ver include/aegis_rollback_politica.h para por que esta separado del driver.
 */

#include "include/aegis_rollback_politica.h"

aegis_rb_decision aegis_rb_decidir(const aegis_rb_contexto *ctx)
{
    if (ctx == NULL)
        return AEGIS_RB_IGNORAR;

    /* 1. El propio EDR: sus escrituras (las copias-sombra, el diario) no se
     *    interceptan. Hacerlo seria un bucle —copiar la copia— y el camino
     *    seguro para llenar el disco del cliente. */
    if (ctx->solicitante_confiable)
        return AEGIS_RB_IGNORAR;

    /* 2. Dedup: una ruta ya copiada en este incidente no se vuelve a copiar. La
     *    segunda escritura del ransomware sobre el mismo fichero ya trae
     *    contenido cifrado; copiarlo pisaria la version buena y el rollback
     *    restauraria basura. */
    if (ctx->ya_copiado)
        return AEGIS_RB_IGNORAR;

    /* 3. Ruido del sistema: temporales, cache, ficheros del SO. No es dato de
     *    usuario que haya que poder revertir, y copiarlo es puro coste. */
    if (ctx->ruta_sistema)
        return AEGIS_RB_IGNORAR;

    /* 4. Con incidente confirmado, el proceso es malicioso: cualquier cosa que
     *    toque hay que poder deshacerla, aunque no parezca cifrado todavia. */
    if (ctx->incidente_activo)
        return AEGIS_RB_COPIAR;

    /* 5. Sin veredicto aun, la senal cruda: una escritura que convierte un
     *    documento de baja entropia en algo de alta entropia. Es lo que permite
     *    salvar a las primeras victimas, antes de que el detector global
     *    acumule bastante para confirmar. */
    if (ctx->transicion_a_cifrado)
        return AEGIS_RB_COPIAR;

    return AEGIS_RB_IGNORAR;
}
