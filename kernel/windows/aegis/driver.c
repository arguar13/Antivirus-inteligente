/* Punto de entrada del driver de auto-defensa (FASE 47).
 *
 * # Que hay aqui y que no
 *
 * Registro y ciclo de vida. La decision de que acceso se recorta vive en
 * `aegis_politica.c`, que es C portable y se ejercita en cada `make ci` con gcc
 * y con clang; ver el header de la politica para por que.
 *
 * # El requisito encadenado que se suele pasar por alto
 *
 * Para que `ObRegisterCallbacks` funcione, el driver tiene que estar firmado
 * con el EKU de proteccion antimalware (1.3.6.1.4.1.311.61.4.1). Y para que el
 * SERVICIO de usuario opte a PPL-Antimalware —sin el cual no hay acceso a
 * ETW-Ti— hace falta ademas un driver ELAM con un recurso `MSElamCertInfoID`.
 * Son tres cosas encadenadas: sin ELAM no hay PPL, sin PPL no hay ETW-Ti, y sin
 * el EKU no hay auto-defensa. Ver el modulo 01 de la documentacion.
 */

#include <ntddk.h>

NTSTATUS AegisRegistrarObCallbacks(void);
void AegisDesregistrarObCallbacks(void);

static void AegisDescargar(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    /* Desregistrar ANTES de que el codigo se descargue. Dejar los callbacks
     * puestos apuntando a memoria liberada es un pantallazo azul en la
     * siguiente apertura de handle de toda la maquina, que ocurre en
     * microsegundos. */
    AegisDesregistrarObCallbacks();
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = AegisDescargar;

    NTSTATUS estado = AegisRegistrarObCallbacks();
    if (!NT_SUCCESS(estado)) {
        /* SE ARRANCA IGUAL, y esta es una decision deliberada.
         *
         * Si el registro falla —tipicamente por la firma— el driver podria
         * negarse a cargar. No lo hace: el resto de la proteccion (el
         * minifiltro, la telemetria) sigue siendo util, y un endpoint sin
         * ninguna proteccion es peor que uno sin auto-defensa. Lo que NO se
         * hace es callarlo: queda en el registro de eventos con el codigo, y el
         * agente lo reporta al plano de control como degradacion.
         *
         * La alternativa —fallar al cargar— convierte un problema de firma en
         * una flota entera sin EDR, que es exactamente lo que un atacante
         * conseguiria manipulando el almacen de certificados. */
        DbgPrint("AegisCore: se arranca SIN auto-defensa (0x%08X).\n", estado);
    }
    return STATUS_SUCCESS;
}
