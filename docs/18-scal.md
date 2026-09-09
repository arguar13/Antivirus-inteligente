# Módulo 18 — SCAL: capa de abstracción del núcleo del sistema

> Componente: `crates/aegis-scal` (Rust) + el puente `aegis-agent::scal`.

Hasta esta fase, el producto hablaba de `/proc`, de `inotify` y de `nftables` en
todas partes: el motor de correlación, el de ransomware, el forense y el de
respuesta contenían rutas de `procfs` y nombres de llamadas de Linux. Portar eso
a Windows no habría sido un port: habría sido reescribir el producto.

La **SCAL** (*System Core Abstraction Layer*) define en cuatro rasgos todo lo
que AegisCore necesita del sistema operativo. Debajo hay un backend por
plataforma; encima, la lógica de detección —que es el valor real— se compila
igual en los tres sistemas.

| Rasgo | Qué abstrae |
|---|---|
| `ProcessLifecycleProvider` | Quién nace, quién muere, quién es hijo de quién |
| `FileSystemMonitor` | Qué cambia en el disco |
| `NetworkFilter` | Qué direcciones se cortan |
| `MemoryInspector` | Qué hay dentro de un proceso vivo |

---

## 18.1 Un PID no es una identidad

El tipo transversal de la capa es `ProcessKey`, y lleva **el PID y el instante de
arranque**. No es una precaución teórica: los PID se reciclan, y en una máquina
con mucha rotación se reciclan en segundos. Cualquier estructura indexada por PID
a secas acaba atribuyendo las acciones de un proceso nuevo al historial del que
ocupaba antes ese número, y así se fabrican a la vez los falsos positivos y los
puntos ciegos.

Los tres sistemas exponen la marca de arranque —campo 22 de `/proc/<pid>/stat` en
Linux, `CreateTime` en Windows, `p_starttime` en macOS—, así que la identidad
correcta se puede construir en los tres. La prueba
`la_identidad_distingue_un_pid_reciclado` fija la propiedad: mismo PID y distinto
arranque son procesos **distintos**.

---

## 18.2 La capa declara lo que puede, y lo que no

Una capa de abstracción que finge que todos los sistemas pueden lo mismo es peor
que ninguna: convierte una limitación visible en un punto ciego silencioso. Por
eso `Capabilities` es parte de la interfaz. Cada backend declara, capacidad por
capacidad, uno de tres estados:

- **`Native`** — implementado con la interfaz nativa.
- **`Degraded(motivo)`** — implementado por otra vía, **diciendo cuál es la
  limitación**.
- **`Unavailable(motivo)`** — no implementado, nombrando la interfaz que falta.

En Linux, los eventos de proceso se declaran *degradados* aunque funcionen: el
censo de `/proc` tiene una ventana ciega de 250 ms, y un proceso que nace y muere
dentro de ella no se ve. Un motor que dependa de eventos inmediatos puede
consultarlo y apagarse, en vez de dar falsos negativos convencido de que la
máquina está limpia.

---

## 18.3 El backend de Linux

Todo lo que hay en él funciona **en un kernel sin BTF y dentro de un
contenedor**: eBPF es un acelerador que el agente enchufa cuando puede, no un
requisito para que la capa exista.

- **Procesos** (`procfs`): censo diferencial. El censo inicial se toma en la
  construcción, de modo que la primera llamada no reporte como recién nacidos los
  cientos de procesos que ya existían.
- **Ficheros** (`inotify`): la vigilancia es por **directorio**, no por fichero.
  Vigilar un fichero concreto parece más preciso y es lo contrario: la forma
  habitual de sustituir un binario de sistema es escribir uno nuevo al lado y
  renombrarlo encima, y una vigilancia anclada al inodo viejo no ve nada.
- **Red** (`nftables`): tabla propia `inet aegis_scal` y **conjuntos**, no una
  regla por dirección —mil bloqueos serían mil comparaciones por paquete, y un
  conjunto es una tabla hash en el kernel—. La caducidad la lleva el kernel con
  `flags timeout`: si la llevara el agente, un reinicio dejaría bloqueos
  permanentes que nadie recuerda haber puesto.
- **Memoria** (`process_vm_readv`): sin parar al objetivo. Un `ptrace`-stop es
  observable por el propio proceso —que es como el malware detecta que lo están
  mirando— y además congela algo que puede ser legítimo.

El conjunto de reglas se reinstala con `flush chain`, nunca con `flush table`:
vaciar la tabla borraría los bloqueos vigentes en cada arranque del agente, que
es justo lo que un atacante querría provocar.

---

## 18.4 El puente con eBPF: dos relojes, una identidad

`aegis-agent::scal::EbpfProcessProvider` junta las dos fuentes que hablan de lo
mismo con vocabularios distintos: las sondas de eBPF, que avisan de un `execve`
en microsegundos, y el censo de `/proc`, que responde consultas completas.

Dos decisiones lo hacen correcto:

1. **La identidad la fija siempre `procfs`, nunca el evento de eBPF.** Las dos
   fuentes tienen relojes distintos —tics desde el arranque del sistema frente a
   nanosegundos monótonos—, y construir claves con uno u otro según quién avise
   primero produciría dos identidades para el mismo proceso. Si el proceso ya
   murió antes de poder resolverlo, el evento se cuenta como **perdido** en vez
   de inventar una clave: un contador visible es preferible a una identidad
   falsa.
2. **Lo aprendido por eBPF se reconcilia con el censo.** Sin eso, el censo
   siguiente vería el mismo proceso como nuevo y el motor conductual contaría dos
   veces cada cadena, escalando al doble de velocidad de la calibrada.

Las muertes se resuelven con el mapa `actor → ProcessKey` construido al nacer:
cuando llega la salida, `/proc/<pid>` ya no existe y no hay otra forma de saber
de quién era.

---

## 18.5 Windows y macOS: esqueletos honestos

Los backends de las otras dos plataformas implementan los cuatro rasgos y
devuelven `ScalError::Unsupported` **nombrando la interfaz nativa que falta por
escribir**. No simulan nada: un backend que devolviera listas vacías haría que el
motor de detección creyera que la máquina está limpia, que es peor que no tener
backend.

Se compilan **en todas las plataformas**, no detrás de `#[cfg(target_os)]`. Es
deliberado: como no contienen FFI, el `cargo clippy` y el `cargo test` del CI de
Linux comprueban de verdad que siguen cuadrando con los rasgos. Un esqueleto
escondido tras `cfg` deja de compilar en cuanto alguien cambia una firma, y nadie
se entera hasta el día del port. Lo que sí va bajo `cfg` es la **elección** del
backend anfitrión, en `SystemCore::host()`.

Las interfaces previstas están anotadas en el propio código:

| | Windows | macOS |
|---|---|---|
| Procesos | ETW `Kernel-Process`, `NtQuerySystemInformation` | EndpointSecurity, `sysctl KERN_PROC` |
| Ficheros | Minifiltro, `ReadDirectoryChangesW` | FSEvents, `ES_EVENT_TYPE_AUTH_*` |
| Red | WFP, sublayer propio | Network Extension o ancla de `pf` |
| Memoria | `VirtualQueryEx` / `ReadProcessMemory` | `mach_vm_region_recurse` / `mach_vm_read` |

En macOS queda anotado el condicionante que decide el diseño del port entero:
EndpointSecurity exige un *entitlement* que Apple concede caso por caso y obliga
a responder con veredicto dentro de un plazo, o el sistema mata al cliente.

---

## 18.6 Qué se movió, y por qué no se duplicó nada

La SCAL es la capa **más baja**, así que las primitivas del sistema que vivían
más arriba bajaron a ella en vez de copiarse:

- `aegis-scan::memory` cede el modelo de región y las primitivas de lectura, y
  se queda con lo que sí es del escáner: qué regiones merece la pena leer, en qué
  orden y en trozos de qué tamaño.
- `aegis-fim::watch` cede la implementación de `inotify` y se queda como fachada
  de nombres, de modo que la línea base y el hasheo del FIM no cambian una línea
  y podrán correr sobre `ReadDirectoryChangesW` cuando exista.

Ambos reexportan lo que cedieron, así que el resto del producto entra por donde
entraba.

---

## 18.7 Cómo se prueba

Todo lo que se puede comprobar contra el sistema de verdad se comprueba contra el
sistema de verdad: procesos que se lanzan y se matan, ficheros creados en un
directorio vigilado por `inotify`, memoria propia leída con `process_vm_readv` y
comparada byte a byte, y reglas puestas y quitadas en `nftables` sobre
direcciones de TEST-NET-1 (RFC 5737), que jamás se enrutan.

Dos detalles que, mal resueltos, harían fallar la prueba y no el código:

- Un proceso muerto sin recolectar es un **zombi**, y un zombi conserva su
  `/proc/<pid>/stat`. Sin el `wait`, la detección de muertes no se estaría
  probando.
- El análisis de `/proc/<pid>/stat` busca el **último** `)`, porque el nombre del
  ejecutable puede llevar espacios y paréntesis. Trocear desde el principio da un
  `ppid` aleatorio, y es el defecto clásico de este analizador.
