/* Politica de tamper protection (autodefensa) de AegisCore. Portable: ni una
 * linea del WDK.
 *
 * POR QUE ESTE FICHERO NO INCLUYE NADA DEL WDK
 * --------------------------------------------
 * Aqui vive LA DECISION: cuando se permite y cuando se deniega una operacion
 * destructiva —borrar el binario, parar el servicio, matar el proceso, borrar
 * una clave de registro— sobre un recurso de AegisCore. El resto (el minifilter
 * de FltRegisterFilter, los callbacks de registro de CmRegisterCallbackEx, el
 * ObRegisterCallbacks de proceso) es fontaneria del WDK que solo compila en
 * Windows. El minifilter incluira ESTE header, asi que no hay dos definiciones
 * que puedan divergir.
 *
 * Separarlas no es estetica. La decision es la parte que puede estar MAL de
 * forma peligrosa: denegar de MENOS deja que un atacante con privilegios de
 * administrador borre el EDR; denegar de MAS impide que el DUENO lo desinstale,
 * y un EDR que su dueno no puede quitar es malware. Y es la unica parte que se
 * puede compilar y probar en cualquier maquina, con gcc Y con clang, en cada
 * `make ci` (ver tools/tamper_politica_probe.c y tools/verificar-windows.sh).
 *
 * La CRIPTOGRAFIA del OTP no vive aqui: verificar una firma hibrida
 * (Ed25519 + ML-DSA-65) en C de kernel seria fragil. La hace el crate Rust
 * `aegis-selfdefense` (o el servicio en modo usuario protegido por PPL), y a
 * esta politica solo le llega el booleano `orden_autorizada` ya verificado.
 */
#ifndef AEGIS_TAMPER_H
#define AEGIS_TAMPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Operaciones protegidas. Espejo de `OperacionProtegida` en el crate Rust: los
 * numeros TIENEN que coincidir, porque el OTP se firma con este byte. */
#define AEGIS_OP_DESINSTALAR         1u
#define AEGIS_OP_DETENER_SERVICIO    2u
#define AEGIS_OP_BORRAR_BINARIO      3u
#define AEGIS_OP_BORRAR_CLAVE_REG    4u
#define AEGIS_OP_DESPROTEGER_PROCESO 5u

/* El veredicto de la politica. */
typedef enum aegis_veredicto_tamper {
    AEGIS_TAMPER_PERMITIR = 0,
    AEGIS_TAMPER_DENEGAR = 1
} aegis_veredicto_tamper_t;

/* Contexto de una operacion potencialmente destructiva. Los enteros son 0/1
 * (booleanos de C) para que el ABI sea trivial y estable entre el driver y las
 * pruebas. */
typedef struct aegis_contexto_tamper {
    /* El objetivo es un recurso protegido de AegisCore (su binario, su
     * servicio, su clave de registro, su proceso). */
    int recurso_protegido;
    /* Que se intenta hacer (uno de AEGIS_OP_*). Informativo para la auditoria;
     * la decision no cambia segun la operacion, solo segun la autorizacion. */
    uint8_t operacion;
    /* El propio kernel: nunca se le pelea. */
    int es_kernel;
    /* El propio proceso del agente sobre sus propios recursos. */
    int es_mismo_agente;
    /* Otro componente de AegisCore verificado por firma (el watchdog, que tiene
     * que poder pararse y reiniciarse para la auto-recuperacion). */
    int es_componente_aegis;
    /* Viene con un OTP del Control Plane que YA se verifico (la criptografia la
     * hace Rust; aqui llega el booleano). Es la llave del dueno. */
    int orden_autorizada;
} aegis_contexto_tamper;

/* Decide si una operacion sobre un recurso de AegisCore se permite o se deniega.
 * Ver el .c para el orden de las reglas y la linea etica. */
aegis_veredicto_tamper_t aegis_decidir_tamper(const aegis_contexto_tamper *ctx);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_TAMPER_H */
