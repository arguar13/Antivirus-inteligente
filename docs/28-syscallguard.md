# Módulo 28 — Detección de syscalls directas (PMU/DRx)

> Componente: `crates/aegis-syscallguard`.

Todo el resto del producto que vigila el comportamiento asume que las llamadas
al sistema salen de donde siempre: el trampolín de `libc`. Ahí es donde un EDR
—este incluido— coloca sus enganches. El malware moderno lo sabe y lo evita:
incrusta su **propia** instrucción `syscall` (`0F 05` en x86-64, `svc #0` en
aarch64) en su código y salta al kernel sin pasar por `libc`. El enganche nunca
se dispara; la syscall pasa sin ser vista. Es la técnica de la **syscall
directa** (y su prima, la **indirecta**, que salta al `0F 05` de `libc` con la
pila preparada por el atacante).

Este módulo la caza por su **origen**.

---

## 28.1 La idea: verificación cruzada del origen de cada syscall

El kernel, al atender una syscall, sabe la dirección **exacta** desde la que se
le llamó: el hardware la captura en el puntero de instrucción. Esa es una vista.
La otra es el mapa de memoria del proceso (`/proc/<pid>/maps`), que dice qué hay
en cada dirección. Se cruzan:

| Origen del puntero | Veredicto |
|---|---|
| `.text` de `libc`/`ld` | legítima |
| `[vdso]` | legítima (código que mapea el propio kernel) |
| `.text` propio de un fichero | binario estático: legítimo, se informa |
| **memoria anónima ejecutable** | **syscall directa: evasión** |
| dirección imposible (sin región, no ejecutable) | la info del kernel es sospechosa |

La señal fuerte es la **memoria anónima ejecutable**: código sin fichero detrás,
que generó el propio proceso. Nadie compila así. Un binario estáticamente
enlazado (Go, Rust con musl) llama al kernel desde su propio `.text`, que es de
fichero pero no es `libc`; es legítimo y común, así que se distingue como
categoría propia y se informa sin alarmar.

---

## 28.2 Si el kernel miente, se descubre

El puntero lo da el kernel vía `PTRACE_GET_SYSCALL_INFO`. Un rootkit podría
falsear esa información para esconder de dónde vienen sus syscalls. Por eso el
guardia **no se fía**: lee los bytes reales en `ip − tamaño_opcode` de la memoria
del proceso y comprueba que ahí hay de verdad una instrucción `syscall`. Si el
kernel dijo «syscall aquí» pero la memoria dice otra cosa, la propia información
del kernel queda marcada como no confirmada. Es la verificación cruzada aplicada
a la palabra del propio kernel.

---

## 28.3 Tres capas, y honestidad sobre el hardware

La detección se apoya en tres mecanismos, con un estado honesto sobre lo que la
máquina ofrece:

| Capa | Mecanismo | En esta máquina |
|---|---|---|
| Verificación cruzada | `PTRACE_GET_SYSCALL_INFO` + `/proc/<pid>/maps` | **operativa** |
| Registros de depuración (DRx) | punto de ruptura por hardware sobre la puerta sancionada | **disponible** |
| PMU | contador de hardware para cribado barato y continuo | **no aplicable** |

**La PMU** (`perf_event_open` con `PERF_TYPE_HARDWARE`) es la vía escalable: en
producción, sobre una flota, no se puede trazar todo con `ptrace`. La PMU cuenta
eventos en hardware sin parar nada, y con muestreo (PEBS) captura el puntero de
instrucción casi gratis. Pero muchas máquinas virtuales —esta, un microVM de
Firecracker— no exponen PMU al huésped. No se disimula: se reporta «no
aplicable», igual que la ausencia de TPM en el escáner de firmware. **La
detección no depende de la PMU**; el trazador con verificación cruzada la hace
por sí solo.

**Los registros de depuración** (DR0..DR3) sí están en esta máquina. El kernel
los expone vía `perf_event_open` con `PERF_TYPE_BREAKPOINT`. Disparan una
excepción cuando la CPU **ejecuta** una dirección concreta, sin modificar ni un
byte del código vigilado —invisibles para el proceso observado, que no puede
detectarlos leyéndose a sí mismo como haría con un `int3` inyectado—. Un
vigilante sobre el trampolín de syscall de `libc` cuenta, en hardware, cuántas
veces se pasó **realmente** por la puerta sancionada; las syscalls de más que
ve el trazador entraron por otro sitio.

---

## 28.4 Por qué esto es real, y cómo se prueba

Nada está simulado. El puntero que se cruza lo captura la CPU en el instante del
`syscall`; la PMU y los registros de depuración son hardware puro.

- **La ABI del kernel** se fija con un espejo `repr(C)` de `ptrace_syscall_info`
  cuyos offsets se cotejan, en cada `cargo test`, contra una sonda en C compilada
  con el header real del kernel (gcc y clang). Un campo desplazado da un fallo de
  compilación, no veredictos erróneos en producción.
- **Los registros de depuración** se ejercitan de verdad: una prueba arma un
  punto de ruptura de ejecución por hardware sobre una función conocida, la llama
  N veces y comprueba que el silicio cuenta **exactamente** N disparos.
- **La detección de extremo a extremo** se prueba contra un binario real
  (`fixtures/syscall_stub.c`) que hace, a propósito, una syscall vía `libc` y
  otra **directa** desde una página anónima ejecutable —la técnica de evasión,
  ejecutada de verdad contra el kernel real—. El guardia lo traza y tiene que ver
  una, y solo una, syscall de origen anónimo, con el opcode `syscall` confirmado
  en la memoria del proceso. `/bin/true` no dispara ninguna: cero falsos
  positivos.

El escenario 13 de la simulación de Red Team ejecuta ese ciclo de extremo a
extremo. Donde la plataforma no ofrece el trazado de syscalls, el escenario se
omite diciéndolo.
