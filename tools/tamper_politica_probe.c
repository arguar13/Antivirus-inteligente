/* Sonda de la politica de tamper protection (FASE 55').
 *
 * Ejercita la DECISION que el minifilter del WDK no puede ejecutar aqui, con
 * gcc Y con clang, en cada `make ci`. La afirmacion central es la linea etica:
 * un recurso protegido se puede eliminar SI, y solo si, viene con la orden
 * autorizada del dueno; sin ella, se deniega el sabotaje.
 */

#include "../kernel/windows/aegis/include/aegis_tamper.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static aegis_contexto_tamper base(void)
{
    aegis_contexto_tamper c;
    memset(&c, 0, sizeof c);
    c.operacion = AEGIS_OP_BORRAR_BINARIO;
    return c;
}

int main(void)
{
    /* Sabotaje: un administrador cualquiera intenta borrar el binario del EDR
     * sin OTP -> DENEGAR. Es el ataque que toda la fase caza. */
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 1;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_DENEGAR);
    }

    /* LA LINEA ETICA: el dueno, con un OTP valido del Control Plane, SI puede
     * eliminar -> PERMITIR. Sin esto, AegisCore seria malware. */
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 1;
        c.orden_autorizada = 1;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_PERMITIR);
    }

    /* Sobre un recurso ajeno no nos metemos -> PERMITIR. */
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 0;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_PERMITIR);
    }

    /* Al kernel, a uno mismo y a los componentes de AegisCore no se les pelea,
     * aunque sea un recurso protegido y sin OTP -> PERMITIR. */
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 1;
        c.es_kernel = 1;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_PERMITIR);
    }
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 1;
        c.es_mismo_agente = 1;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_PERMITIR);
    }
    {
        aegis_contexto_tamper c = base();
        c.recurso_protegido = 1;
        c.es_componente_aegis = 1;
        assert(aegis_decidir_tamper(&c) == AEGIS_TAMPER_PERMITIR);
    }

    /* Contexto nulo -> DENEGAR (fail-closed ante un fallo del driver). */
    assert(aegis_decidir_tamper(NULL) == AEGIS_TAMPER_DENEGAR);

    /* Tabla de verdad completa: la unica combinacion que DENIEGA es
     * recurso protegido, sin OTP, y el solicitante NO es kernel/self/componente.
     * Es la misma tabla que verifica el espejo en Rust (tamper::decidir). */
    for (int rec = 0; rec < 2; rec++)
        for (int otp = 0; otp < 2; otp++)
            for (int k = 0; k < 2; k++)
                for (int s = 0; s < 2; s++)
                    for (int comp = 0; comp < 2; comp++) {
                        aegis_contexto_tamper c = base();
                        c.recurso_protegido = rec;
                        c.orden_autorizada = otp;
                        c.es_kernel = k;
                        c.es_mismo_agente = s;
                        c.es_componente_aegis = comp;
                        int debe_denegar = rec && !otp && !k && !s && !comp;
                        aegis_veredicto_tamper_t v = aegis_decidir_tamper(&c);
                        assert((v == AEGIS_TAMPER_DENEGAR) == debe_denegar);
                    }

    printf("politica de tamper: OK (linea etica y tabla de verdad verificadas)\n");
    return 0;
}
