# Módulo 1 — Motor de kernel (Ring 0)

> Componentes: `drivers/windows/aegis-drv` (C, WDK) y `drivers/linux/aegis-bpf`
> (C, libbpf CO-RE).

El kernel es el único punto de observación que el atacante no puede falsear sin
haberlo comprometido antes. Todo lo que el agente de Ring 3 sabe, lo sabe porque
se lo contó este módulo.

## Regla que gobierna todo el módulo

**El código de kernel nunca espera a userland sin un plazo, y nunca asigna
memoria en la ruta caliente.**

No es una preferencia de estilo. Un callback de creación de proceso corre en el
contexto del hilo que llamó a `NtCreateUserProcess`, a menudo con locks del
gestor de procesos tomados. Si ahí se espera indefinidamente a que un proceso de
usuario responda, y ese proceso de usuario necesita crear un hilo para
responder, el sistema se ha bloqueado a sí mismo. Todos los EDR que han
provocado caídas masivas de flota lo han hecho por violar alguna variante de
esta regla.

Consecuencias concretas, que aparecen en cada decisión de abajo:

- Toda espera de veredicto tiene *timeout* y una política de vencimiento explícita.
- Toda memoria de la ruta caliente sale de *lookaside lists* preasignadas.
- El ring de telemetría descarta cuando se llena; jamás aplica contrapresión.
- Nada que pueda tocar disco se ejecuta por encima de `PASSIVE_LEVEL`.

---

## 1.1 Filtro de ficheros

### Windows: minifilter

Se registra en el rango de altitud **320000–329999** (`FSFilter Anti-Virus`),
asignado por Microsoft. La altitud no es cosmética: determina el orden respecto
a los filtros de cifrado y de virtualización. Por debajo del filtro de cifrado
veríamos texto cifrado; el rango antivirus está deliberadamente por encima.

| Callback | Momento | Para qué |
|---|---|---|
| `IRP_MJ_CREATE` | pre | Cachear la intención (¿ejecución? ¿escritura?) y aplicar la lista de bloqueo. Barato y sin E/S |
| `IRP_MJ_CREATE` | post | Resolver el nombre normalizado y el `FILE_ID_128`; consultar la caché de veredictos |
| `IRP_MJ_WRITE` | pre | Marcar el fichero como sucio y muestrear entropía para el detector de ransomware |
| `IRP_MJ_SET_INFORMATION` | pre | Renombrado y borrado: señal fuerte de ransomware y de borrado de evidencia |
| `IRP_MJ_CLEANUP` | pre | **Aquí se escanea.** El último handle de un fichero sucio se está cerrando: el contenido ya está completo |
| `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` | pre | Alguien mapea el fichero como sección ejecutable. Es la vía real de ejecución, y no pasa por `IRP_MJ_READ` |

**Por qué se escanea en `CLEANUP` y no en `WRITE`:** un fichero que se está
escribiendo está incompleto. Escanearlo en cada `IRP_MJ_WRITE` significa escanear
la misma muestra decenas de veces, siempre parcial, y multiplicar por diez el
coste de cualquier copia de ficheros. En `CLEANUP` el contenido ya está y se
escanea una vez.

**Ejecución sí se intercepta antes**, en `CREATE` con
`FILE_EXECUTE`/`SECTION_SYNCHRONIZATION`: ahí sí hay que decidir antes de dejar
que ocurra.

#### Evitar la reentrada

El escáner lee ficheros; esas lecturas vuelven a entrar por nuestro propio
filtro. Sin defensa, es recursión infinita y agotamiento de pila del kernel.
Tres barreras, en orden de coste:

```c
static BOOLEAN AegisShouldIgnore(_In_ PFLT_CALLBACK_DATA Data)
{
    /* 1. E/S originada por nuestro propio agente o por el kernel. */
    if (FltGetRequestorProcess(Data) == g_AegisAgentProcess)
        return TRUE;

    /* 2. E/S emitida por nosotros mismos desde el driver: FltMgr la marca. */
    if (Data->Iopb->OperationFlags & SL_OPEN_PAGING_FILE)
        return TRUE;
    if (IoGetTopLevelIrp() != NULL)
        return TRUE;   /* estamos anidados dentro de otra operacion */

    /* 3. Rutas propias: cuarentena y almacen de rollback. */
    return AegisIsOwnPath(Data);
}
```

#### Caché de veredictos

Escanear el mismo `notepad.exe` en cada arranque es el mayor derroche posible.
La caché se indexa por `(volume_id, FILE_ID_128, usn)`:

- `FILE_ID_128` en lugar de la ruta: la ruta es reescribible por el atacante
  (*hardlinks*, uniones de directorio, rutas UNC); el ID de fichero no.
- El **USN** del *change journal* invalida la entrada en cuanto el contenido
  cambia, sin necesidad de rehashear.

Entrada de caché en 32 bytes, en una tabla hash de tamaño fijo con expulsión LRU
y presupuesto de memoria cerrado: la caché nunca crece sin límite en pool no
paginado.

### Linux: eBPF + LSM

En Linux no hay minifilter. La estructura equivalente son programas **BPF LSM**
adjuntos a los *hooks* del Linux Security Module, que sí pueden **denegar**
(devolviendo `-EPERM`), a diferencia de los *tracepoints*, que solo observan.

| Hook LSM | Equivalente Windows | Puede denegar |
|---|---|---|
| `bprm_check_security` | `IRP_MJ_CREATE` con `FILE_EXECUTE` | Sí |
| `file_open` | `IRP_MJ_CREATE` | Sí |
| `file_mprotect` | Cambio a `PAGE_EXECUTE_*` | Sí |
| `mmap_file` | `ACQUIRE_FOR_SECTION_SYNCHRONIZATION` | Sí |
| `task_kill` | `ObRegisterCallbacks` sobre `PsProcessType` | Sí |
| `ptrace_access_check` | Acceso a memoria entre procesos | Sí |

Todo se compila **CO-RE** (*Compile Once, Run Everywhere*) con BTF, de modo que
un único binario funciona en kernels distintos sin recompilar contra sus
cabeceras. Sin CO-RE habría que distribuir un artefacto por versión de kernel,
que es exactamente el tipo de fragilidad operativa que hunde un EDR en flota
heterogénea.

Requisito mínimo: kernel 5.7+ para BPF LSM (`CONFIG_BPF_LSM=y`, `lsm=bpf` en la
línea de arranque). Para kernels anteriores existe una degradación documentada:
`fanotify` con `FAN_OPEN_EXEC_PERM` para el control de ejecución y
*tracepoints* para telemetría, perdiendo el control de `mprotect`.

---

## 1.2 Callbacks de proceso, hilo, imagen y registro

### Registro

```c
NTSTATUS AegisRegisterCallbacks(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    /* Ex2 permite DENEGAR la creacion escribiendo en CreateInfo->CreationStatus. */
    status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems,
                                                (PVOID)AegisProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) return status;

    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem,
                                              (PVOID)AegisThreadNotify);
    if (!NT_SUCCESS(status)) goto unwind_process;

    /* Ex informa ademas del nivel de firma de la imagen. */
    status = PsSetLoadImageNotifyRoutineEx(AegisImageNotify,
                                           PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);
    if (!NT_SUCCESS(status)) goto unwind_thread;

    status = CmRegisterCallbackEx(AegisRegistryNotify, &g_Altitude,
                                  DriverObject, NULL, &g_CmCookie, NULL);
    if (!NT_SUCCESS(status)) goto unwind_image;

    return AegisRegisterObCallbacks();   /* autodefensa, seccion 1.3 */
    ...
}
```

### La clave estable de proceso

El PID es inservible como identidad: se recicla. Un ataque que espere al
reciclado puede hacer que la telemetría atribuya sus acciones a un proceso
inocente ya terminado. Todo el sistema usa una clave de 64 bits derivada de
`(pid, create_time)`:

```c
static UINT64 AegisProcessKey(_In_ PEPROCESS Process)
{
    /* create_time es monotono y unico por PID: el par nunca se repite. */
    UINT64 createTime = (UINT64)PsGetProcessCreateTimeQuadPart(Process);
    UINT64 pid        = (UINT64)(ULONG_PTR)PsGetProcessId(Process);

    UINT64 h = 0xcbf29ce484222325ULL;          /* FNV-1a de 64 bits */
    h = (h ^ (createTime & 0xFFFFFFFFULL)) * 0x100000001b3ULL;
    h = (h ^ (createTime >> 32))           * 0x100000001b3ULL;
    h = (h ^ pid)                          * 0x100000001b3ULL;
    return h | 1;                               /* 0 se reserva para "sin actor" */
}
```

### Detección de suplantación de proceso padre (*PPID spoofing*)

`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` permite a cualquier proceso declarar otro
padre. Es la técnica estándar para que un `powershell.exe` malicioso aparezca
colgando de `explorer.exe` y no del documento de Office que lo lanzó.

`PS_CREATE_NOTIFY_INFO` da los dos datos por separado, y esa es toda la
detección:

```c
VOID AegisProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                        _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo == NULL) { AegisOnProcessExit(ProcessId); return; }

    /* ParentProcessId  = el padre DECLARADO.
     * CreatingThreadId = quien REALMENTE llamo a NtCreateUserProcess. */
    UINT64 parentKey  = AegisKeyFromPid(CreateInfo->ParentProcessId);
    UINT64 creatorKey = AegisKeyFromPid(CreateInfo->CreatingThreadId.UniqueProcess);

    /* Si difieren, hay suplantacion. No se bloquea por si solo: hay software
     * legitimo que lo usa. Se emite como senal para el correlador de Ring 3,
     * que la pondera junto al resto del contexto. */
    ...
}
```

Bloquear solo por esta señal generaría falsos positivos (algunos instaladores y
lanzadores legítimos la usan). Se emite como señal ponderada, no como veredicto.

### Registro (Windows)

`CmRegisterCallbackEx` cubre la persistencia. Filtrar en el callback es
obligatorio: hay decenas de miles de operaciones de registro por segundo en un
sistema en reposo, y emitir todas saturaría el ring. Solo se emiten las claves
que importan:

- `...\CurrentVersion\Run`, `RunOnce`, `Winlogon\Shell`, `Userinit`
- `Image File Execution Options` (secuestro por *debugger*)
- `Services` con `Start=0` o `Start=1` (drivers de arranque)
- `LSA\Notification Packages`, proveedores de seguridad
- Nuestras propias claves (autodefensa)

Un `switch` sobre un hash precalculado del prefijo de la clave, sin asignar
memoria, resuelve el filtro en decenas de nanosegundos.

---

## 1.3 Autodefensa

Un EDR que se puede matar con `taskkill /f` no es un EDR. Cuatro capas
independientes; ninguna basta por sí sola.

### Capa 1 — `ObRegisterCallbacks`: recortar derechos de handle

No se deniega la apertura del handle (romper `OpenProcess` provoca fallos
extraños en software legítimo). Se **quitan los derechos peligrosos** del handle
concedido:

```c
OB_PREOP_CALLBACK_STATUS AegisPreOperationCallback(
    _In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;   /* el kernel es confiable */
    if (!AegisIsProtectedProcess((PEPROCESS)Info->Object)) return OB_PREOP_SUCCESS;
    if (AegisIsTrustedRequestor()) return OB_PREOP_SUCCESS;

    ACCESS_MASK deny = PROCESS_TERMINATE | PROCESS_VM_WRITE |
                       PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME |
                       PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~deny;
    else
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~deny;

    AegisEmitTamperEvent(...);   /* el intento en si es telemetria valiosa */
    return OB_PREOP_SUCCESS;
}
```

El intento fallido se emite como `AEGIS_EVT_TAMPER_ATTEMPT`. Que alguien intente
matar al EDR es una de las señales de mayor valor que existen: casi nada
legítimo lo hace.

`ObRegisterCallbacks` exige que el driver esté firmado con el atributo
`/INTEGRITYCHECK` y un certificado con EKU de firma de kernel.

### Capa 2 — PPL (Protected Process Light)

El servicio del agente se registra como
`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`. A partir de ahí, ni un proceso
SYSTEM con `SeDebugPrivilege` puede abrir el agente con `PROCESS_VM_WRITE`: la
protección la impone el propio gestor de objetos del kernel, por encima de
cualquier privilegio de usuario.

**Requisito encadenado, y es el detalle que se suele pasar por alto:** para
optar a PPL-Antimalware hay que publicar un driver ELAM cuya sección de recursos
contenga un recurso `MSElamCertInfoID` con el hash del certificado que firma el
binario del servicio. Sin ELAM no hay PPL. Por eso la sección 1.4 no es opcional.

PPL trae además el permiso para suscribirse al proveedor ETW
**Microsoft-Windows-Threat-Intelligence** (`ETW-Ti`), que es la única fuente
soportada de eventos de `VirtualAllocEx`, `WriteProcessMemory` y
`SetThreadContext` entre procesos. Sin PPL, esa telemetría es inalcanzable sin
recurrir a parcheado no soportado del kernel, que rompe PatchGuard.

### Capa 3 — Anti-descarga y protección de artefactos

```c
NTSTATUS AegisFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    /* Descarga obligatoria del sistema: hay que obedecer. */
    if (FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY))
        return STATUS_SUCCESS;

    /* Con proteccion antimanipulacion activa, no nos desprendemos.
     * El desinstalador legitimo desactiva antes la proteccion por el canal
     * autenticado, y solo entonces `fltmc unload` funciona. */
    if (g_TamperProtectionEnabled)
        return STATUS_FLT_DO_NOT_DETACH;

    return STATUS_SUCCESS;
}
```

Complementos:

- **Ficheros propios**: el minifilter deniega en `IRP_MJ_CREATE` cualquier
  apertura con intención de escritura o borrado sobre binarios, cuarentena y
  almacén de rollback, venga de donde venga.
- **Claves propias**: `CmRegisterCallbackEx` deniega escritura sobre
  `Services\AegisDrv` y la configuración. Sin esto, poner `Start=4` en el
  servicio y reiniciar desactiva el EDR sin tocar un solo proceso.
- **Servicio**: DACL que impide `SERVICE_STOP` y `DELETE` incluso a
  administradores; los cambios legítimos pasan por el canal autenticado.

### Capa 4 — Vigilancia mutua

El driver observa el ciclo de vida del agente por `PsSetCreateProcessNotifyRoutineEx`:

- Salida **no autorizada** del agente (sin apagado ordenado por el canal de
  control) → se registra el evento, se pasa a modo mínimo (solo bloqueo por
  lista, sin análisis) y se pide al SCM el reinicio del servicio encolando un
  work item a `PASSIVE_LEVEL`. El driver **no** crea procesos por su cuenta: eso
  es frágil y peligroso; usa el gestor de servicios, que es quien sabe hacerlo.
- El agente vigila al driver por el latido `consumer_alive` / `producer_head`
  del ring. Si el driver deja de producir, hay manipulación o fallo y se alerta.

**Modo mínimo** es una decisión deliberada: mientras no hay agente, el driver no
se apaga. Sigue aplicando la lista de bloqueo y sigue protegiéndose. Un EDR que
queda completamente inerte al matar su proceso de usuario ha convertido el
Ring 3 en su punto único de fallo.

---

## 1.4 ELAM — Early Launch Anti-Malware

Un *bootkit* que se cargue antes que nosotros nos gana la partida antes de
empezar. ELAM es el mecanismo de Windows para estar entre los primeros.

Requisitos del driver ELAM: firmado con un certificado ELAM de Microsoft,
`Start = SERVICE_BOOT_START (0)`, grupo `Early-Launch`, y una sección de
recursos con `MSElamCertInfoID`, que además es lo que habilita el PPL del
servicio (sección 1.3).

```c
/* Clasifica cada driver de arranque ANTES de que se ejecute su DriverEntry. */
BDCB_STATUS AegisBootDriverCallback(_In_ PVOID CallbackContext,
                                    _In_ BDCB_CALLBACK_TYPE Classification,
                                    _Inout_ PBDCB_IMAGE_INFORMATION ImageInfo)
{
    if (Classification != BdCbStatusUpdate && ImageInfo != NULL) {
        /* La politica y los hashes vienen de una colmena de registro cargada
         * por el gestor de arranque: en esta fase no hay sistema de ficheros
         * disponible. */
        switch (AegisLookupBootDriverPolicy(ImageInfo)) {
        case AEGIS_BOOT_KNOWN_BAD:
            ImageInfo->Classification = BdCbClassificationKnownBadImage;
            break;   /* Windows no lo carga */
        case AEGIS_BOOT_KNOWN_GOOD:
            ImageInfo->Classification = BdCbClassificationKnownGoodImage;
            break;
        default:
            /* Desconocido != malo. Bloquear lo desconocido en el arranque
             * deja el equipo sin arrancar ante cualquier driver de terceros
             * legitimo. Se carga y se audita despues. */
            ImageInfo->Classification = BdCbClassificationUnknownImage;
        }
    }
    return BdCbStatusMoreData;
}
```

La política se registra en la colmena ELAM: en esa fase del arranque no hay
sistema de ficheros, así que los hashes tienen que estar ya en el registro.

**Equivalente en Linux:** no existe ELAM, pero la cadena es Secure Boot → kernel
firmado → módulo/BTF verificado. Los programas eBPF se cargan desde un initramfs
firmado, y el estado del arranque se atesta contra los PCR del TPM. La propiedad
que se busca es la misma: que nada sin verificar corra antes que nosotros.

---

## 1.5 Presupuesto de rendimiento

| Ruta | Objetivo | Cómo se consigue |
|---|---:|---|
| `IRP_MJ_CREATE` pre (sin escaneo) | < 2 µs | Solo comparaciones y hash; cero asignaciones, cero E/S |
| Acierto en caché de veredicto | < 5 µs | Tabla hash en pool no paginado, indexada por `FILE_ID_128` |
| Emisión de evento al ring | < 500 ns | Reserva, `memcpy`, release-store. Sin locks |
| Callback de creación de proceso | < 10 µs | El escaneo ocurre después, no dentro |
| Veredicto síncrono (ejecución) | < 50 ms p99, timeout 200 ms | Escaneo en Ring 3 con caché caliente |

**Disciplina de IRQL.** `IRP_MJ_CREATE` y `CLEANUP` llegan a `PASSIVE_LEVEL` y
pueden hacer E/S. Los callbacks de proceso, hilo e imagen pueden llegar a
`APC_LEVEL` con locks del gestor de procesos tomados: ahí solo se permite copiar
al ring. Cualquier trabajo real se difiere a un work item.

**Memoria.** Toda asignación de la ruta caliente sale de *lookaside lists*
preasignadas en `DriverEntry`. Si la lista se agota, el evento se descarta y se
incrementa `dropped_events`. Nunca se llama a `ExAllocatePool2` en un callback:
bajo presión de memoria puede fallar, y el camino de error de una asignación
fallida dentro de un callback de kernel es exactamente donde viven los BSOD.

**Verificación.** Driver Verifier con Special Pool, IRQL checking, Low Resources
Simulation y Deadlock Detection es obligatorio en CI antes de cualquier firma.
La simulación de recursos bajos es la que encuentra los caminos de error que
nunca se ejercitan en pruebas normales.

---

## Lo que este módulo NO hace

Delimitarlo es tan importante como lo que hace:

- **No decide.** Emite señales y aplica veredictos. La lógica de detección vive
  en Ring 3, donde un error es una excepción y no un BSOD.
- **No escanea contenido.** Calcula entropía sobre buffers ya residentes y
  extrae metadatos; YARA y el modelo ML corren en userland.
- **No habla con la red.** Un driver que abre sockets es superficie de ataque en
  el anillo más privilegiado.

→ Siguiente: [Módulo 2 — Agente y telemetría (Ring 3)](02-agente-ring3.md)
