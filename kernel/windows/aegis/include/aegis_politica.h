/* Politica de auto-defensa y de clasificacion de inyeccion en Windows.
 *
 * POR QUE ESTE FICHERO NO INCLUYE NADA DEL WDK
 * --------------------------------------------
 * Aqui vive LA DECISION: que bits de acceso sobreviven cuando alguien abre un
 * handle contra el agente, y cuando un evento de ETW-Ti es una inyeccion. El
 * resto del driver es fontaneria del sistema operativo —registrar callbacks,
 * traducir estructuras— y solo se puede compilar con el WDK, en Windows.
 *
 * Separarlas no es estetica. La decision es la parte que puede estar MAL de
 * forma peligrosa: quitar un bit de mas deja al usuario sin poder ver su propio
 * gestor de tareas; quitar uno de menos deja al atacante matar el EDR. Y es
 * tambien la unica parte que se puede compilar y probar en cualquier maquina.
 * Con esta separacion, la logica que decide si el producto se defiende o no se
 * ejercita en CADA `make ci`, con gcc y con clang, en vez de comprobarse a mano
 * en un Windows cuando alguien se acuerda.
 *
 * Los valores de las mascaras se definen aqui, con los del SDK de Windows, para
 * que el fichero compile en cualquier sitio. El driver incluye ESTE header, asi
 * que no hay dos definiciones que puedan divergir.
 */
#ifndef AEGIS_POLITICA_H
#define AEGIS_POLITICA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t aegis_mascara_t;

/* --- Derechos de acceso a PROCESO (winnt.h) ----------------------------- */
#define AEGIS_PROCESS_TERMINATE                 0x0001u
#define AEGIS_PROCESS_CREATE_THREAD             0x0002u
#define AEGIS_PROCESS_SET_SESSIONID             0x0004u
#define AEGIS_PROCESS_VM_OPERATION              0x0008u
#define AEGIS_PROCESS_VM_READ                   0x0010u
#define AEGIS_PROCESS_VM_WRITE                  0x0020u
#define AEGIS_PROCESS_DUP_HANDLE                0x0040u
#define AEGIS_PROCESS_CREATE_PROCESS            0x0080u
#define AEGIS_PROCESS_SET_QUOTA                 0x0100u
#define AEGIS_PROCESS_SET_INFORMATION           0x0200u
#define AEGIS_PROCESS_QUERY_INFORMATION         0x0400u
#define AEGIS_PROCESS_SUSPEND_RESUME            0x0800u
#define AEGIS_PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define AEGIS_PROCESS_SET_LIMITED_INFORMATION   0x2000u
#define AEGIS_SYNCHRONIZE                       0x00100000u

/* --- Derechos de acceso a HILO (winnt.h) -------------------------------- */
#define AEGIS_THREAD_TERMINATE                 0x0001u
#define AEGIS_THREAD_SUSPEND_RESUME            0x0002u
#define AEGIS_THREAD_GET_CONTEXT               0x0008u
#define AEGIS_THREAD_SET_CONTEXT               0x0010u
#define AEGIS_THREAD_SET_INFORMATION           0x0020u
#define AEGIS_THREAD_QUERY_INFORMATION         0x0040u
#define AEGIS_THREAD_SET_THREAD_TOKEN          0x0080u
#define AEGIS_THREAD_IMPERSONATE               0x0100u
#define AEGIS_THREAD_DIRECT_IMPERSONATION      0x0200u
#define AEGIS_THREAD_QUERY_LIMITED_INFORMATION 0x0800u

/* Lo que se le quita a un handle ajeno contra un proceso protegido.
 *
 * Es la lista de lo que permite MATAR o MODIFICAR el proceso. Cada bit esta
 * aqui por un ataque concreto:
 *
 *   TERMINATE        matar el EDR, que es el primer paso de casi todo
 *   VM_WRITE/VM_OP   escribir en su memoria: parchear una comprobacion, meter
 *                    un hook, o desactivar la deteccion sin matar el proceso
 *   VM_READ          leer su memoria: la clave privada de la flota vive ahi y
 *                    NUNCA toca el disco (ver el rotador de certificados)
 *   CREATE_THREAD    ejecutar codigo DENTRO del EDR, con su identidad
 *   SUSPEND_RESUME   congelarlo: no muere, pero deja de detectar, y el panel
 *                    lo sigue viendo "vivo"
 *   SET_INFORMATION  cambiar su prioridad, sus limites o su mitigacion
 *   DUP_HANDLE       obtener por la puerta de atras un handle que aqui se
 *                    acaba de recortar
 */
#define AEGIS_ACCESO_PELIGROSO_PROCESO                                   \
    (AEGIS_PROCESS_TERMINATE | AEGIS_PROCESS_CREATE_THREAD |             \
     AEGIS_PROCESS_VM_OPERATION | AEGIS_PROCESS_VM_READ |                \
     AEGIS_PROCESS_VM_WRITE | AEGIS_PROCESS_DUP_HANDLE |                 \
     AEGIS_PROCESS_SET_INFORMATION | AEGIS_PROCESS_SUSPEND_RESUME |      \
     AEGIS_PROCESS_SET_QUOTA)

/* Lo que NUNCA se quita, aunque estuviera en la lista de arriba.
 *
 * POR QUE ESTA EXCEPCION EXISTE
 * -----------------------------
 * El gestor de tareas, WMI, el gestor de servicios y cualquier herramienta de
 * inventario abren los procesos con QUERY_LIMITED_INFORMATION y SYNCHRONIZE.
 * Un EDR que se los quite convierte su propio proceso en algo que el sistema no
 * puede describir: el usuario ve una entrada rara que no responde, el
 * administrador cree que la maquina esta rota, y la reaccion normal es
 * desinstalar el EDR. La auto-defensa que hace que te desinstalen no defiende
 * nada.
 */
#define AEGIS_ACCESO_SIEMPRE_PERMITIDO_PROCESO \
    (AEGIS_PROCESS_QUERY_LIMITED_INFORMATION | AEGIS_SYNCHRONIZE)

/* Lo que se le quita a un handle ajeno contra un HILO del proceso protegido.
 *
 * Un atacante que no puede tocar el proceso puede intentar el hilo: SET_CONTEXT
 * es secuestro de hilo —se le cambia el puntero de instruccion— y TERMINATE
 * mata los hilos uno a uno hasta que el EDR deja de funcionar sin haber muerto.
 */
#define AEGIS_ACCESO_PELIGROSO_HILO                                     \
    (AEGIS_THREAD_TERMINATE | AEGIS_THREAD_SUSPEND_RESUME |             \
     AEGIS_THREAD_SET_CONTEXT | AEGIS_THREAD_SET_INFORMATION |          \
     AEGIS_THREAD_SET_THREAD_TOKEN | AEGIS_THREAD_IMPERSONATE |         \
     AEGIS_THREAD_DIRECT_IMPERSONATION)

#define AEGIS_ACCESO_SIEMPRE_PERMITIDO_HILO \
    (AEGIS_THREAD_QUERY_LIMITED_INFORMATION | AEGIS_SYNCHRONIZE)

/* Quien pide, contra quien, y con que. */
typedef struct {
    /* El handle lo pide el propio kernel (`OB_PRE_OPERATION_INFORMATION.
     * KernelHandle`). */
    int es_kernel;
    /* El solicitante ES el objetivo. */
    int es_mismo_proceso;
    /* El objetivo es un proceso de AegisCore que hay que proteger. */
    int objetivo_protegido;
    /* El solicitante es otro componente de AegisCore, verificado por firma. */
    int solicitante_confiable;
    /* Mascara que se ha pedido. */
    aegis_mascara_t solicitada;
} aegis_contexto_acceso;

/* Devuelve la mascara que debe CONCEDERSE.
 *
 * Recorta, no deniega. Devolver STATUS_ACCESS_DENIED rompe a quien pide
 * MAXIMUM_ALLOWED —que es lo que hacen muchas APIs de Windows por dentro— y
 * convierte una proteccion en una averia. Recortando, el llamante recibe un
 * handle valido con menos derechos, que es exactamente lo que Windows espera.
 */
aegis_mascara_t aegis_filtrar_acceso_proceso(const aegis_contexto_acceso *ctx);

/* Lo mismo para un hilo del proceso protegido. */
aegis_mascara_t aegis_filtrar_acceso_hilo(const aegis_contexto_acceso *ctx);

/* --- Clasificacion de eventos de ETW Threat Intelligence ----------------- */

/* Tipo de evento de ETW-Ti que se observa. */
typedef enum {
    /* Reserva de memoria (VirtualAllocEx). */
    AEGIS_ETWTI_ALLOCVM = 1,
    /* Cambio de proteccion de memoria (VirtualProtectEx). */
    AEGIS_ETWTI_PROTECTVM = 2,
    /* Mapeo de una seccion (NtMapViewOfSection). */
    AEGIS_ETWTI_MAPVIEW = 3,
    /* APC en modo usuario encolada a un hilo (QueueUserAPC / NtQueueApcThread). */
    AEGIS_ETWTI_QUEUEAPC = 4,
    /* Cambio del contexto de un hilo (SetThreadContext). */
    AEGIS_ETWTI_SETTHREADCONTEXT = 5
} aegis_etwti_tipo;

/* Proteccion de pagina (winnt.h), solo lo que se usa. */
#define AEGIS_PAGE_NOACCESS          0x01u
#define AEGIS_PAGE_READONLY          0x02u
#define AEGIS_PAGE_READWRITE         0x04u
#define AEGIS_PAGE_WRITECOPY         0x08u
#define AEGIS_PAGE_EXECUTE           0x10u
#define AEGIS_PAGE_EXECUTE_READ      0x20u
#define AEGIS_PAGE_EXECUTE_READWRITE 0x40u
#define AEGIS_PAGE_EXECUTE_WRITECOPY 0x80u

#define AEGIS_PAGE_ES_EJECUTABLE(p)                                  \
    (((p) & (AEGIS_PAGE_EXECUTE | AEGIS_PAGE_EXECUTE_READ |          \
             AEGIS_PAGE_EXECUTE_READWRITE |                          \
             AEGIS_PAGE_EXECUTE_WRITECOPY)) != 0u)

/* Un evento de ETW-Ti, ya normalizado. */
typedef struct {
    aegis_etwti_tipo tipo;
    /* PID que realiza la operacion. */
    uint32_t pid_origen;
    /* PID sobre el que se realiza. */
    uint32_t pid_destino;
    /* Proteccion resultante (ALLOCVM, PROTECTVM, MAPVIEW). */
    uint32_t proteccion;
    /* Proteccion anterior (PROTECTVM). Cero si no aplica. */
    uint32_t proteccion_anterior;
    /* Bytes implicados. */
    uint64_t tamano;
    /* El origen esta autorizado a inyectar (depurador declarado, etc.). */
    int origen_autorizado;
} aegis_etwti_evento;

/* Severidad de AegisCore: 0 informativa .. 4 critica. */
typedef enum {
    AEGIS_SEV_INFORMATIVA = 0,
    AEGIS_SEV_BAJA = 1,
    AEGIS_SEV_MEDIA = 2,
    AEGIS_SEV_ALTA = 3,
    AEGIS_SEV_CRITICA = 4
} aegis_severidad;

/* Clasifica un evento de ETW-Ti.
 *
 * Devuelve la severidad. La regla de oro es que la operacion sobre UNO MISMO no
 * es inyeccion: un compilador JIT reserva y hace ejecutable su propia memoria
 * constantemente, y un EDR que avisara de eso enterraria al analista en ruido
 * hasta que dejara de mirar. Lo que delata la inyeccion es que el destino sea
 * OTRO proceso.
 */
aegis_severidad aegis_clasificar_etwti(const aegis_etwti_evento *ev);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_POLITICA_H */
