# Módulo 2 — Agente y telemetría (Ring 3)

> Componente: `crates/aegis-agent` (Rust). Contrato IPC ya implementado en
> `crates/aegis-ipc`.

El agente es el cerebro. Recibe hechos del kernel, los convierte en contexto y
decide. Corre como servicio protegido (PPL-Antimalware en Windows), y todo su
código de análisis es Rust seguro: parsea entrada hostil (PE de atacante,
memoria de procesos comprometidos) y un desbordamiento aquí sería un
compromiso del propio EDR.

---

## 2.1 Canal IPC entre Ring 0 y Ring 3

Hay **dos canales**, con requisitos opuestos, y mezclarlos es el error de diseño
clásico:

| Canal | Dirección | Volumen | Latencia | Bloquea al kernel |
|---|---|---|---|---|
| **Telemetría** | Ring 0 → Ring 3 | 10³–10⁵ ev/s | Best effort | Nunca |
| **Veredicto** | Ring 0 ↔ Ring 3 | 1–50 /s | Acotada, con timeout | Sí, con plazo |

Si la telemetría bloqueara, cada evento pagaría un cambio de contexto. Si el
veredicto no bloqueara, no habría forma de impedir nada.

### Canal de telemetría: memoria compartida

**Quién asigna la memoria importa.** La asigna el *agente*, no el driver:

```
1. El agente reserva el ring:  VirtualAlloc(NULL, 4 MB, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
2. Se conecta al puerto del filtro y envia (base, tamaño)
3. El driver bloquea esas páginas y obtiene un alias en espacio de kernel:

       PMDL mdl = IoAllocateMdl(userBase, size, FALSE, FALSE, NULL);
       MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);   // dentro de __try/__except
       PVOID kernelVa = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority | MdlMappingNoExecute);

4. Ambos lados escriben la misma memoria física, cada uno con su dirección virtual.
```

La alternativa —que el driver cree la sección con `ZwCreateSection` y se la mapee
al agente— pondría memoria de kernel al alcance de userland. Con el MDL, las
páginas son páginas de usuario desde el principio: un fallo del driver no puede
filtrar memoria de kernel, y `MdlMappingNoExecute` impide que ese alias se use
como región ejecutable.

`MmProbeAndLockPages` va envuelto en `__try/__except`: si el agente pasa un rango
inválido, lanza una excepción que hay que capturar en lugar de un BSOD.

El protocolo del ring (cursores, publicación release/acquire, relleno de fin de
buffer, detección de corrupción) está **implementado y probado** en
[`crates/aegis-ipc/src/ring.rs`](../crates/aegis-ipc/src/ring.rs).

Bucle del colector:

```rust
loop {
    let n = consumer.drain(BUDGET, |ev| dispatch(ev))?;   // BUDGET = 4096
    consumer.heartbeat(tick());

    if consumer.dropped_events() > last_dropped {
        // Perdida de eventos = punto ciego de deteccion. Es un incidente de
        // salud del producto, no una metrica de rendimiento: se escala.
        metrics::telemetry_gap(consumer.dropped_events() - last_dropped);
    }
    if n < BUDGET { park_timeout(Duration::from_micros(200)); }
}
```

El `park` corto en lugar de espera activa mantiene el 0,1 % de CPU en reposo; el
presupuesto por iteración impide que una ráfaga secuestre el hilo e impida
atender la rotación de reglas o el apagado.

### Canal de veredicto: llamada invertida

Patrón documentado de FltMgr. El agente mantiene N peticiones pendientes
(`FilterGetMessage`); el driver completa una cuando necesita decidir; el agente
responde con `FilterReplyMessage`.

```c
/* Lado kernel: esperar con plazo, siempre. */
NTSTATUS AegisRequestVerdict(_In_ PAEGIS_VERDICT_REQ req, _Out_ PUINT32 action)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)AEGIS_VERDICT_TIMEOUT_100NS;  /* 200 ms */

    NTSTATUS status = FltSendMessage(g_Filter, &g_ClientPort, req, sizeof(*req),
                                     &reply, &replyLen, &timeout);
    if (status == STATUS_TIMEOUT || !NT_SUCCESS(status)) {
        /* El agente no respondio. Politica de vencimiento por clase de riesgo. */
        *action = AegisFailurePolicy(req->class);
        InterlockedIncrement64(&g_VerdictTimeouts);
        return STATUS_SUCCESS;   /* la operacion continua segun la politica */
    }
    *action = reply.action;
    return STATUS_SUCCESS;
}
```

**Política de vencimiento.** Al expirar el plazo hay que elegir, y la elección
no es uniforme:

| Clase de operación | Al vencer | Razón |
|---|---|---|
| Ejecución de binario desconocido | **Permitir** y auditar | Bloquear todo ante un fallo del agente deja el equipo inutilizable |
| Escritura en fichero protegido | **Permitir** y auditar | Idem |
| Manipulación de nuestro propio proceso | **Denegar** | Es la única clase en la que fallar cerrado no rompe nada legítimo |
| Ejecución con veredicto malicioso ya en caché | **Denegar** | No hace falta consultar |

Fallar abierto por defecto es deliberado. Un EDR que deja el equipo inservible
cuando su agente se cuelga se desinstala en una semana, y un equipo sin EDR está
peor protegido que uno con un EDR que falló abierto durante 200 ms.

### Linux

La telemetría va por `BPF_MAP_TYPE_RINGBUF`, que ya es un ring SPSC mapeado con
la misma semántica de cursores; `aegis-ipc` se adapta con un *shim* fino.

Para el camino **bloqueante** no se usa eBPF sino **fanotify** con
`FAN_OPEN_EXEC_PERM`: da un evento de permiso con un descriptor de respuesta y
un modelo de bloqueo soportado por el kernel. Bloquear dentro de un programa BPF
LSM esperando a userland tiene el mismo problema de deadlock que en Windows, y
además el verificador limita lo que se puede hacer ahí.

---

## 2.2 Detección de malware sin fichero

El malware moderno no toca el disco. Lo que sigue es lo que hay que ver en
memoria, y por qué cada señal es difícil de falsificar.

### Taxonomía de memoria anómala

| Patrón | Qué se observa | Por qué es raro en software legítimo |
|---|---|---|
| **Código flotante** | `MEM_PRIVATE` con `PAGE_EXECUTE_*` | El código legítimo se ejecuta desde imágenes mapeadas; solo los JIT hacen esto |
| **Process hollowing** | Región `MEM_IMAGE` cuyo contenido difiere del fichero en disco | Una imagen mapeada debería coincidir con su fichero salvo reubicaciones |
| **Module stomping** | DLL legítima cargada cuyo `.text` fue sobrescrito | El `.text` de una DLL firmada no cambia |
| **Phantom DLL / doppelgänging** | `MEM_MAPPED` ejecutable sin nombre de sección | Toda imagen legítima tiene fichero asociado |
| **Hilo inyectado** | Dirección de inicio fuera de todo módulo | `CreateThread` legítimo apunta a código de un módulo |
| **Transición RW → RX** | `VirtualProtect` de `PAGE_READWRITE` a `PAGE_EXECUTE_READ` | Escribir y luego hacer ejecutable evita dejar una región RWX visible; casi solo lo hacen los packers y los JIT |

Los JIT (.NET, JavaScript, Java) generan código flotante de forma legítima y son
la mayor fuente de falsos positivos. Se manejan con un modelo por proceso: si el
proceso ha cargado `clr.dll`/`coreclr.dll`/`jvm.dll`, sus regiones flotantes se
esperan y se ponderan a la baja, sin dejar de escanear su contenido.

### Barrido de memoria

Escanear la memoria de todos los procesos periódicamente cuesta segundos de CPU
y viola el presupuesto. El barrido es **guiado por eventos**:

```rust
enum ScanTrigger {
    /// El kernel vio una asignación remota de memoria ejecutable.
    RemoteExecAlloc { target: ProcKey },
    /// Transición RW -> RX dentro del propio proceso.
    ProtectTransition { target: ProcKey, addr: u64 },
    /// Hilo creado con dirección de inicio fuera de todo módulo.
    UnbackedThreadStart { target: ProcKey },
    /// Puntuación conductual acumulada por encima del umbral.
    BehaviorScore { target: ProcKey, score: u16 },
    /// Barrido de fondo en reposo, con presupuesto y prioridad mínima.
    IdleSweep,
}
```

Cada disparo escanea **un** proceso, no todos. `IdleSweep` corre solo con la
máquina inactiva, con prioridad de E/S baja, y se aborta en cuanto hay actividad
de usuario.

### Detección de *hollowing*

Se compara la imagen en memoria con la imagen en disco, teniendo en cuenta que
diferencias legítimas existen:

```rust
fn detectar_hollowing(proc: &Process, region: &Region) -> Option<Hallazgo> {
    let nombre_seccion = proc.query_section_name(region.base)?;   // MemorySectionName
    let en_disco = mapear_imagen_limpia(&nombre_seccion)?;

    // Diferencias esperadas y por tanto ignoradas:
    //   - .data / .rdata: cambian en ejecución por diseño
    //   - reubicaciones aplicadas si la base difiere de la preferida
    //   - hooks de IAT: legítimos en software de accesibilidad y depuradores
    let dif = comparar_solo_texto_ejecutable(region, &en_disco)?;

    if dif.bytes_distintos > UMBRAL {
        return Some(Hallazgo::TextoModificado {
            imagen: nombre_seccion,
            ratio: dif.ratio(),
            primer_offset: dif.primer_offset,
        });
    }
    None
}
```

Comparar la imagen entera daría falsos positivos constantes: `.data` cambia por
diseño. Solo se comparan las secciones **ejecutables**, y aplicando primero las
reubicaciones.

### Detección de *unhooking* de NTDLL

Un atacante que quiere evitar los hooks de userland restaura el `.text` de
`ntdll.dll` desde una copia limpia. La ironía es que **eso mismo se detecta**:
comparamos el `.text` en memoria contra una copia limpia que obtenemos mapeando
la sección `\KnownDlls\ntdll.dll`.

```rust
enum EstadoNtdll {
    /// Coincide con la copia limpia. Normal.
    Limpio,
    /// Modificado de forma coherente con hooks de otro producto de seguridad.
    ConHooksDeTerceros { producto: Option<String> },
    /// Tenía hooks y ahora no: alguien lo restauró deliberadamente.
    RestauradoDeliberadamente,
    /// Modificado de forma que no corresponde a ningún patrón de hook conocido.
    Anomalo { offset: u64 },
}
```

`RestauradoDeliberadamente` es la señal de alto valor. Que un proceso normal
repare `ntdll` no tiene ninguna explicación benigna.

**AegisCore no instala hooks propios en userland.** Son evadibles con syscalls
directos, se pisan con otros productos de seguridad y añaden superficie de
ataque en cada proceso del sistema. La telemetría viene del kernel, donde el
atacante no puede quitarla.

### Syscalls directos e indirectos

- **Syscall directo**: el malware pone el número de servicio en `eax` y ejecuta
  `syscall` desde su propio código, sin pasar por `ntdll`.
- **Syscall indirecto**: salta a la instrucción `syscall` que ya existe dentro de
  `ntdll` para que la dirección de retorno parezca legítima. Es la evolución
  diseñada precisamente para derrotar a la detección anterior.

Dos niveles de detección:

**Nivel 1 — ETW-Ti (siempre activo, coste cero por proceso).** El proveedor
Threat Intelligence emite eventos con pila de llamadas para las operaciones
sensibles: `ALLOCVM_REMOTE`, `PROTECTVM_REMOTE`, `MAPVIEW_REMOTE`,
`WRITEVM_REMOTE`, `QUEUEUSERAPC_REMOTE`, `SETTHREADCONTEXT_REMOTE`. Si la pila
no atraviesa `ntdll`, hubo syscall directo. Requiere PPL (ver módulo 1).

**Nivel 2 — *instrumentation callback* (selectivo).**
`NtSetInformationProcess(ProcessInstrumentationCallback)` instala un callback que
se ejecuta en **cada** retorno de kernel a usuario, con la dirección de retorno
en `r10`. Validar que esa dirección cae dentro del `.text` de `ntdll` detecta
también el syscall indirecto, porque el gadget reutilizado devuelve a un punto
que no es el que corresponde al stub de esa función.

Tiene coste medible, así que se activa **solo** sobre procesos ya sospechosos
(puntuación conductual por encima del umbral, o hallazgo de código flotante). Es
la escalada, no la línea base.

Detalle relevante: los atacantes usan este mismo mecanismo. Si un proceso instala
su propio *instrumentation callback*, es señal por sí misma, y el nuestro se
protege comprobando periódicamente que sigue instalado.

---

## 2.3 Grafo de linaje de procesos

Una detección aislada casi nunca es concluyente. `powershell.exe` ejecutando
base64 es sospechoso; `winword.exe` → `cmd.exe` → `powershell.exe` con base64 es
un incidente. El grafo es lo que convierte lo primero en lo segundo.

```rust
/// Clave estable: (pid, create_time) mezclados en el kernel. Nunca un PID.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey(pub u64);

pub struct ProcessNode {
    pub key: ProcKey,
    /// Padre declarado por el sistema operativo.
    pub parent: ProcKey,
    /// Quien realmente invocó la creación. Si difiere de `parent`, hubo
    /// suplantación de proceso padre.
    pub creator: ProcKey,
    /// Profundidad desde la raíz. Acota el coste de recorrer ancestros.
    pub depth: u16,

    pub image_id: ImageId,
    pub cmdline: CompactString,
    pub integrity: IntegrityLevel,
    pub signature: SignatureLevel,

    pub started_ns: u64,
    /// `Some` si terminó. Los nodos muertos se retienen un tiempo de gracia:
    /// una detección puede llegar después de que el proceso haya salido.
    pub exited_ns: Option<u64>,

    /// Estado conductual acumulado (módulo 3).
    pub behavior: BehaviorState,
    /// Etiquetas propagadas desde ancestros: `OfficeChild`, `BrowserChild`,
    /// `RemoteShell`, `MarkOfTheWeb`.
    pub taints: TaintSet,
}

pub struct ProcessGraph {
    nodes: HashMap<ProcKey, ProcessNode>,
    children: HashMap<ProcKey, SmallVec<[ProcKey; 4]>>,
    /// Muertos pendientes de expirar, ordenados por instante de salida.
    reaper: VecDeque<(u64, ProcKey)>,
}
```

### Propagación de contaminación (*taint*)

Es la parte que aporta más valor por línea de código. Ciertas propiedades se
heredan por el árbol:

```rust
impl ProcessGraph {
    fn taints_heredados(&self, padre: ProcKey, hijo_img: ImageId) -> TaintSet {
        let mut t = self.nodes.get(&padre).map(|n| n.taints).unwrap_or_default();

        // Origen: descendiente de una aplicación de Office.
        if es_aplicacion_office(padre_img) { t |= Taint::OFFICE_CHILD; }
        // Origen: descendiente de un navegador (posible descarga ejecutada).
        if es_navegador(padre_img)         { t |= Taint::BROWSER_CHILD; }
        // Origen: ejecutado desde un fichero con Mark-of-the-Web.
        if tiene_motw(hijo_img)            { t |= Taint::FROM_INTERNET; }
        // Origen: bajo un servicio de escritorio remoto o WMI.
        if es_ejecucion_remota(padre_img)  { t |= Taint::REMOTE_ORIGIN; }

        t   // se hereda hacia abajo indefinidamente
    }
}
```

`OFFICE_CHILD` sobrevive a la cadena `winword → cmd → powershell → rundll32`.
Cuando `rundll32` intenta una asignación remota de memoria, la regla que dispara
no es «rundll32 asigna memoria» (ocurre legítimamente) sino «un descendiente de
Office asigna memoria ejecutable en otro proceso», que no ocurre casi nunca.

### Cota de memoria

El grafo no puede crecer sin límite en un servidor que crea miles de procesos por
minuto:

- Máximo de nodos vivos: 16 384. Al superarse, se expulsan los muertos más
  antiguos.
- Tiempo de gracia de los muertos: 5 minutos, o hasta que ningún hallazgo
  pendiente los referencie.
- `cmdline` se trunca a 512 bytes en `CompactString`, que guarda las cadenas
  cortas en la pila sin asignar en el montón.
- Presupuesto total: **8 MB**, verificado en pruebas de carga. Al alcanzarse, se
  degrada guardando solo la cadena de ancestros y descartando los hermanos.

---

## 2.4 Colector conductual

El colector convierte eventos individuales en estado por proceso, con ventanas
deslizantes y decaimiento temporal:

```rust
pub struct BehaviorState {
    /// Ficheros escritos con salto de entropía alto, últimos 10 s.
    pub escrituras_alta_entropia: SlidingCounter,
    /// Renombrados a extensiones desconocidas, últimos 10 s.
    pub renombrados_extension_nueva: SlidingCounter,
    /// Directorios distintos tocados, últimos 30 s.
    pub dispersion_directorios: HyperLogLog,
    /// Asignaciones remotas de memoria ejecutable.
    pub asignaciones_remotas_exec: u16,
    /// Ficheros señuelo tocados. Cualquier valor > 0 es concluyente.
    pub senuelos_tocados: u16,
    /// Puntuación agregada con decaimiento exponencial (semivida 60 s).
    pub score: DecayingScore,
}
```

`HyperLogLog` para la dispersión de directorios: contar directorios únicos con un
`HashSet` sería memoria no acotada por proceso. HLL da el cardinal aproximado en
1 KB fijos, y la precisión aproximada sobra para distinguir «este proceso tocó 4
directorios» de «este proceso tocó 900».

El decaimiento exponencial evita que un proceso de larga vida acumule puntuación
para siempre por actividad benigna dispersa en horas.

→ Siguiente: [Módulo 3 — Motor de detección](03-motor-deteccion.md)
