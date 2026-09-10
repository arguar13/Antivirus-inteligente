/* Auto-defensa por `ObRegisterCallbacks` (FASE 47).
 *
 * # Que hace y por que en el kernel
 *
 * Windows decide si un proceso puede abrir a otro consultando el descriptor de
 * seguridad. Contra un atacante con `SeDebugPrivilege` —que es lo que tiene
 * cualquier cosa que corra como SYSTEM, incluida casi toda la administracion
 * remota— ese descriptor no sirve: el privilegio se lo salta.
 *
 * `ObRegisterCallbacks` es el gancho del propio gestor de objetos: se ejecuta
 * DESPUES de que Windows haya concedido el acceso, y permite recortar la
 * mascara antes de que el handle llegue a manos del solicitante. Es la unica
 * forma soportada de que un proceso de usuario sobreviva a SYSTEM.
 *
 * # Lo que este fichero NO hace
 *
 * No decide. La decision vive en `aegis_politica.c`, que es C portable y se
 * ejercita con gcc y con clang en cada `make ci`. Aqui solo se traduce la
 * estructura del WDK a esa decision y de vuelta. Ver el header de la politica
 * para por que se separan.
 *
 * # Requisitos que no se pueden saltar
 *
 * - El driver tiene que estar firmado con el EKU de proteccion antimalware
 *   (1.3.6.1.4.1.311.61.4.1). Sin el, `ObRegisterCallbacks` devuelve
 *   STATUS_ACCESS_DENIED y no hay auto-defensa, por muy bien escrito que este
 *   este fichero.
 * - La altitud tiene que estar registrada con Microsoft. Es lo que fija el
 *   orden respecto a otros productos de seguridad instalados en la misma
 *   maquina.
 */

#include <ntddk.h>

#include "include/aegis_politica.h"

/* Altitud del rango FSFilter Anti-Virus asignado por Microsoft (320000-329999).
 *
 * No es cosmetica: determina el orden respecto a los filtros de cifrado y de
 * virtualizacion. Ver el modulo 01 de la documentacion. */
#define AEGIS_ALTITUD L"321410"

/* Registro devuelto por `ObRegisterCallbacks`; hace falta para desregistrar. */
static PVOID g_RegistroCallbacks = NULL;

/* Procesos protegidos. La rellena el resto del driver segun se crean los
 * componentes de AegisCore; aqui solo se consulta.
 *
 * Se guarda el PID Y la hora de creacion: un PID se reutiliza, y proteger «el
 * PID 4820» despues de que muera el proceso significa proteger a lo que sea que
 * el sistema ponga ahi despues. Es un fallo clasico y silencioso. */
typedef struct {
    HANDLE Pid;
    LARGE_INTEGER Creacion;
    BOOLEAN Confiable;
} AEGIS_PROCESO_PROTEGIDO;

#define AEGIS_MAX_PROTEGIDOS 8

static AEGIS_PROCESO_PROTEGIDO g_Protegidos[AEGIS_MAX_PROTEGIDOS];
static ULONG g_NumProtegidos = 0;
/* Cerrojo de lector/escritor: la lista se lee en CADA apertura de handle de
 * toda la maquina y se escribe muy de vez en cuando. Un `FAST_MUTEX` aqui
 * serializaria el sistema entero. */
static EX_SPIN_LOCK g_CerrojoProtegidos;

/* Registra un proceso de AegisCore como protegido. */
NTSTATUS AegisProtegerProceso(_In_ HANDLE Pid, _In_ LARGE_INTEGER Creacion,
                              _In_ BOOLEAN Confiable)
{
    KIRQL irql = ExAcquireSpinLockExclusive(&g_CerrojoProtegidos);
    NTSTATUS estado = STATUS_INSUFFICIENT_RESOURCES;
    if (g_NumProtegidos < AEGIS_MAX_PROTEGIDOS) {
        g_Protegidos[g_NumProtegidos].Pid = Pid;
        g_Protegidos[g_NumProtegidos].Creacion = Creacion;
        g_Protegidos[g_NumProtegidos].Confiable = Confiable;
        g_NumProtegidos++;
        estado = STATUS_SUCCESS;
    }
    ExReleaseSpinLockExclusive(&g_CerrojoProtegidos, irql);
    return estado;
}

/* Busca un proceso en la lista. Devuelve TRUE si esta. */
static BOOLEAN AegisBuscarProtegido(_In_ PEPROCESS Proceso, _Out_ PBOOLEAN Confiable)
{
    HANDLE pid = PsGetProcessId(Proceso);
    LARGE_INTEGER creacion = { 0 };
    /* La hora de creacion distingue al proceso del PID reciclado. */
    creacion.QuadPart = (LONGLONG)PsGetProcessCreateTimeQuadPart(Proceso);

    BOOLEAN encontrado = FALSE;
    *Confiable = FALSE;

    KIRQL irql = ExAcquireSpinLockShared(&g_CerrojoProtegidos);
    for (ULONG i = 0; i < g_NumProtegidos; i++) {
        if (g_Protegidos[i].Pid == pid &&
            g_Protegidos[i].Creacion.QuadPart == creacion.QuadPart) {
            encontrado = TRUE;
            *Confiable = g_Protegidos[i].Confiable;
            break;
        }
    }
    ExReleaseSpinLockShared(&g_CerrojoProtegidos, irql);
    return encontrado;
}

/* Construye el contexto que la politica necesita. */
static void AegisRellenarContexto(_In_ POB_PRE_OPERATION_INFORMATION Info,
                                  _In_ PEPROCESS Objetivo,
                                  _In_ ACCESS_MASK Solicitada,
                                  _Out_ aegis_contexto_acceso *Ctx)
{
    RtlZeroMemory(Ctx, sizeof(*Ctx));
    Ctx->solicitada = (aegis_mascara_t)Solicitada;

    /* Un handle del kernel: el gestor de memoria, el planificador, el propio
     * subsistema de objetos. Recortarle un bit no protege de nada y rompe el
     * sistema operativo. */
    Ctx->es_kernel = Info->KernelHandle ? 1 : 0;

    BOOLEAN confiable = FALSE;
    Ctx->objetivo_protegido = AegisBuscarProtegido(Objetivo, &confiable) ? 1 : 0;

    PEPROCESS solicitante = PsGetCurrentProcess();
    Ctx->es_mismo_proceso = (solicitante == Objetivo) ? 1 : 0;

    /* El solicitante es confiable si el TAMBIEN esta en la lista marcado como
     * tal: el watchdog tiene que poder supervisar al agente y reiniciarlo. */
    BOOLEAN confiable_solicitante = FALSE;
    if (AegisBuscarProtegido(solicitante, &confiable_solicitante))
        Ctx->solicitante_confiable = confiable_solicitante ? 1 : 0;
}

/* Pre-operacion: se ejecuta antes de entregar el handle. */
static OB_PREOP_CALLBACK_STATUS AegisPreOperacion(_In_ PVOID Contexto,
                                                  _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(Contexto);

    /* Un handle que el propio kernel se concede: no se toca. */
    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    aegis_contexto_acceso ctx;

    if (Info->ObjectType == *PsProcessType) {
        PEPROCESS objetivo = (PEPROCESS)Info->Object;

        /* CREATE y DUPLICATE llevan la mascara en campos distintos de la union,
         * y hay que recortar los DOS: si solo se recortara CREATE, bastaria con
         * duplicar un handle ya abierto para recuperar todos los derechos. */
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            AegisRellenarContexto(Info, objetivo,
                                  Info->Parameters->CreateHandleInformation.DesiredAccess,
                                  &ctx);
            Info->Parameters->CreateHandleInformation.DesiredAccess =
                (ACCESS_MASK)aegis_filtrar_acceso_proceso(&ctx);
        } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            AegisRellenarContexto(Info, objetivo,
                                  Info->Parameters->DuplicateHandleInformation.DesiredAccess,
                                  &ctx);
            Info->Parameters->DuplicateHandleInformation.DesiredAccess =
                (ACCESS_MASK)aegis_filtrar_acceso_proceso(&ctx);
        }
    } else if (Info->ObjectType == *PsThreadType) {
        /* El proceso dueno del hilo es el que decide: un atacante que no puede
         * tocar el proceso intenta el hilo. */
        PEPROCESS objetivo = IoThreadToProcess((PETHREAD)Info->Object);

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            AegisRellenarContexto(Info, objetivo,
                                  Info->Parameters->CreateHandleInformation.DesiredAccess,
                                  &ctx);
            Info->Parameters->CreateHandleInformation.DesiredAccess =
                (ACCESS_MASK)aegis_filtrar_acceso_hilo(&ctx);
        } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            AegisRellenarContexto(Info, objetivo,
                                  Info->Parameters->DuplicateHandleInformation.DesiredAccess,
                                  &ctx);
            Info->Parameters->DuplicateHandleInformation.DesiredAccess =
                (ACCESS_MASK)aegis_filtrar_acceso_hilo(&ctx);
        }
    }

    return OB_PREOP_SUCCESS;
}

/* Registra los callbacks de proceso y de hilo. */
NTSTATUS AegisRegistrarObCallbacks(void)
{
    if (g_RegistroCallbacks != NULL)
        return STATUS_SUCCESS;

    OB_OPERATION_REGISTRATION operaciones[2];
    RtlZeroMemory(operaciones, sizeof(operaciones));

    operaciones[0].ObjectType = PsProcessType;
    operaciones[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operaciones[0].PreOperation = AegisPreOperacion;

    operaciones[1].ObjectType = PsThreadType;
    operaciones[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operaciones[1].PreOperation = AegisPreOperacion;

    UNICODE_STRING altitud;
    RtlInitUnicodeString(&altitud, AEGIS_ALTITUD);

    OB_CALLBACK_REGISTRATION registro;
    RtlZeroMemory(&registro, sizeof(registro));
    registro.Version = OB_FLT_REGISTRATION_VERSION;
    registro.OperationRegistrationCount = 2;
    registro.Altitude = altitud;
    registro.RegistrationContext = NULL;
    registro.OperationRegistration = operaciones;

    NTSTATUS estado = ObRegisterCallbacks(&registro, &g_RegistroCallbacks);
    if (!NT_SUCCESS(estado)) {
        /* El motivo casi siempre es la firma: sin el EKU de proteccion
         * antimalware, esto devuelve STATUS_ACCESS_DENIED. Se deja constancia
         * con el codigo para que no haya que adivinarlo. */
        g_RegistroCallbacks = NULL;
        DbgPrint("AegisCore: ObRegisterCallbacks fallo (0x%08X). "
                 "SIN AUTO-DEFENSA: comprueba la firma con el EKU 1.3.6.1.4.1.311.61.4.1 "
                 "y la altitud registrada.\n",
                 estado);
    }
    return estado;
}

/* Quita los callbacks. Obligatorio antes de descargar el driver: dejarlos
 * puestos con el codigo descargado es un pantallazo azul garantizado en la
 * siguiente apertura de handle de la maquina. */
void AegisDesregistrarObCallbacks(void)
{
    if (g_RegistroCallbacks != NULL) {
        ObUnRegisterCallbacks(g_RegistroCallbacks);
        g_RegistroCallbacks = NULL;
    }
}
