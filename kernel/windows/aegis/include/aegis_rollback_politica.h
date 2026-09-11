/* Politica del minifilter de rollback de ransomware (FASE 50).
 *
 * POR QUE ESTE FICHERO NO INCLUYE NADA DEL WDK
 * --------------------------------------------
 * Igual que la politica de auto-defensa de la FASE 47, aqui vive LA DECISION:
 * ante una escritura, decidir si hay que guardar una copia-sombra del contenido
 * original antes de dejarla pasar. El resto del minifilter —registrar el filtro,
 * traducir el IRP, leer el fichero previo— es fontaneria del WDK que solo
 * compila en Windows.
 *
 * La decision es la parte que puede estar mal de forma peligrosa y cara:
 *   - interceptar de MAS convierte el EDR en la razon por la que el disco del
 *     cliente se llena y el sistema se arrastra (una copia por cada escritura de
 *     cada proceso);
 *   - interceptar de MENOS deja ficheros sin copia-sombra, y esos no se pueden
 *     revertir cuando el ransomware los cifra.
 *
 * Y es la unica parte que se puede compilar y probar sin un Windows delante: se
 * ejercita en cada `make ci` con gcc y con clang, igual que la de la FASE 47.
 */
#ifndef AEGIS_ROLLBACK_POLITICA_H
#define AEGIS_ROLLBACK_POLITICA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Que hacer ante una operacion de escritura observada. */
typedef enum {
    /* Dejar pasar sin copiar: no es candidata. */
    AEGIS_RB_IGNORAR = 0,
    /* Guardar una copia-sombra del contenido previo antes de dejar escribir. */
    AEGIS_RB_COPIAR = 1
} aegis_rb_decision;

/* Contexto de una escritura, ya normalizado desde el IRP (Windows) o el evento
 * fanotify (Linux). */
typedef struct {
    /* El proceso que escribe es un componente de AegisCore, verificado por
     * firma. Sus escrituras NO se interceptan: ni las copias-sombra que el
     * propio rollback escribe, ni el diario, para no morderse la cola. */
    int solicitante_confiable;
    /* La ruta es del sistema operativo o de un area volatil (temporales,
     * cache, el registro): ruido que no es dato de usuario que revertir. */
    int ruta_sistema;
    /* La ruta ya tiene copia-sombra en este incidente (dedup): no volver a
     * copiarla, o se pisaria la version buena con la ya cifrada. */
    int ya_copiado;
    /* El detector (aegis-ransom) ya confirmo un incidente: a partir de aqui se
     * preserva la primera version de CADA fichero que el proceso toque. */
    int incidente_activo;
    /* La escritura sube la entropia de "documento" a "cifrado": la firma cruda
     * del ransomware, util ANTES de que el veredicto global llegue. La calcula
     * el nucleo Rust (aegis_ml::entropy) y llega aqui ya resuelta como 0/1. */
    int transicion_a_cifrado;
} aegis_rb_contexto;

/* Decide si una escritura merece copia-sombra.
 *
 * El orden de las reglas es la decision de seguridad:
 *   1. jamas interceptar al propio EDR (bucle infinito, disco lleno);
 *   2. jamas re-copiar lo ya copiado (pisaria la version buena);
 *   3. nunca copiar ruido del sistema;
 *   4. con incidente confirmado, copiar todo lo que el proceso toque;
 *   5. sin incidente, copiar solo ante la firma cruda del cifrado.
 */
aegis_rb_decision aegis_rb_decidir(const aegis_rb_contexto *ctx);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_ROLLBACK_POLITICA_H */
