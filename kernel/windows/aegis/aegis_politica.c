/* Implementacion de la politica. Portable: ni una linea del WDK.
 *
 * Ver `include/aegis_politica.h` para por que esta separado del driver.
 */

#include "include/aegis_politica.h"

aegis_mascara_t aegis_filtrar_acceso_proceso(const aegis_contexto_acceso *ctx)
{
    if (ctx == NULL)
        return 0u;

    /* 1. El kernel abre handles contra todo constantemente: el gestor de
     *    memoria, el planificador, el propio subsistema de objetos. Recortarle
     *    un bit al kernel no protege de nada —un atacante que ya esta en el
     *    kernel no necesita un handle— y rompe el sistema operativo de formas
     *    que se manifiestan como pantallazos azules aleatorios. */
    if (ctx->es_kernel)
        return ctx->solicitada;

    /* 2. Solo nos defendemos a nosotros. Filtrar handles contra procesos
     *    ajenos convertiria el EDR en la razon por la que las aplicaciones del
     *    cliente dejan de funcionar. */
    if (!ctx->objetivo_protegido)
        return ctx->solicitada;

    /* 3. Un proceso tiene que poder abrirse a si mismo. Sus propios hilos, su
     *    propio manejo de excepciones y su propia recoleccion de basura lo
     *    hacen. Recortarselo es romperse a uno mismo. */
    if (ctx->es_mismo_proceso)
        return ctx->solicitada;

    /* 4. Los demas componentes de AegisCore, verificados por firma. El
     *    watchdog tiene que poder supervisar al agente y reiniciarlo; sin esta
     *    excepcion, la auto-defensa impediria la auto-recuperacion. */
    if (ctx->solicitante_confiable)
        return ctx->solicitada;

    /* 5. Se RECORTA, no se deniega. Ver el header. */
    aegis_mascara_t concedida = ctx->solicitada & ~AEGIS_ACCESO_PELIGROSO_PROCESO;

    /* 6. Y se devuelve lo que el sistema necesita para poder describir el
     *    proceso, aunque el paso anterior lo hubiera quitado. */
    concedida |= (ctx->solicitada & AEGIS_ACCESO_SIEMPRE_PERMITIDO_PROCESO);

    return concedida;
}

aegis_mascara_t aegis_filtrar_acceso_hilo(const aegis_contexto_acceso *ctx)
{
    if (ctx == NULL)
        return 0u;

    if (ctx->es_kernel)
        return ctx->solicitada;
    if (!ctx->objetivo_protegido)
        return ctx->solicitada;
    if (ctx->es_mismo_proceso)
        return ctx->solicitada;
    if (ctx->solicitante_confiable)
        return ctx->solicitada;

    aegis_mascara_t concedida = ctx->solicitada & ~AEGIS_ACCESO_PELIGROSO_HILO;
    concedida |= (ctx->solicitada & AEGIS_ACCESO_SIEMPRE_PERMITIDO_HILO);
    return concedida;
}

aegis_severidad aegis_clasificar_etwti(const aegis_etwti_evento *ev)
{
    if (ev == NULL)
        return AEGIS_SEV_INFORMATIVA;

    /* La operacion sobre UNO MISMO no es inyeccion. Un compilador JIT reserva y
     * hace ejecutable su propia memoria constantemente; avisar de eso enterraria
     * al analista en ruido hasta que dejara de mirar. */
    const int remoto = (ev->pid_origen != ev->pid_destino);
    if (!remoto)
        return AEGIS_SEV_INFORMATIVA;

    /* Un origen declarado como depurador tiene permiso para hacer justo esto.
     * Se rebaja a informativa y NO se descarta: si alguien secuestra la
     * autorizacion, la evidencia sigue estando. */
    if (ev->origen_autorizado)
        return AEGIS_SEV_INFORMATIVA;

    switch (ev->tipo) {
    case AEGIS_ETWTI_ALLOCVM:
        /* Reservar memoria EJECUTABLE en otro proceso es el primer paso del
         * cargador de shellcode clasico. Reservar memoria de datos en otro
         * proceso tambien es raro, pero lo hacen depuradores e inyectores de
         * DLL legitimos: se registra con menos severidad en vez de callarse. */
        return AEGIS_PAGE_ES_EJECUTABLE(ev->proteccion) ? AEGIS_SEV_CRITICA
                                                        : AEGIS_SEV_MEDIA;

    case AEGIS_ETWTI_PROTECTVM:
        /* El paso que delata al cargador que EVITA reservar RWX para no
         * llamar la atencion: reserva RW, escribe, y despues pasa a ejecutable.
         * Esa transicion en un proceso AJENO casi no tiene uso legitimo. */
        if (AEGIS_PAGE_ES_EJECUTABLE(ev->proteccion) &&
            !AEGIS_PAGE_ES_EJECUTABLE(ev->proteccion_anterior))
            return AEGIS_SEV_CRITICA;
        return AEGIS_SEV_BAJA;

    case AEGIS_ETWTI_MAPVIEW:
        /* Mapear una seccion ejecutable en otro proceso es la variante que
         * evita WriteProcessMemory por completo: se escribe en la seccion desde
         * el propio proceso y se mapea ya lista. */
        return AEGIS_PAGE_ES_EJECUTABLE(ev->proteccion) ? AEGIS_SEV_ALTA
                                                        : AEGIS_SEV_BAJA;

    case AEGIS_ETWTI_QUEUEAPC:
        /* Encolar una APC de usuario en un hilo de otro proceso es la primitiva
         * de ejecucion de la inyeccion por APC —y de la variante «early bird»,
         * que la encola antes de que el proceso victima empiece a ejecutar—.
         * En el propio proceso es E/S alertable normal, y eso ya se descarto
         * arriba por no ser remoto. */
        return AEGIS_SEV_CRITICA;

    case AEGIS_ETWTI_SETTHREADCONTEXT:
        /* Secuestro de hilo: se le cambia el puntero de instruccion a un hilo
         * ajeno. Lo hacen los depuradores, y por eso la autorizacion de arriba
         * existe; sin ella, no hay uso legitimo comun. */
        return AEGIS_SEV_CRITICA;
    }

    return AEGIS_SEV_INFORMATIVA;
}
