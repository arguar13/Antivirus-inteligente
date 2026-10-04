# Módulo 109 — La columna vertebral del agente (FASE 1 del MP-16)

> Componentes: `crates/aegis-motor` (contrato y árbitro), `crates/aegis-trabajador`
> (trabajador confinado), `crates/aegis-agent/src/motores/`, `fuzz/`,
> `drivers/linux/aegis-bpf` (pérdida con prioridad). Controles del
> [modelo de amenazas](modelo-de-amenazas.md) que toca: AM-1.2, AM-1.5.

## La causa raíz que cierra

Tres cosas, y se alimentaban entre sí:

1. **Los parsers de entrada hostil vivían en el proceso que decide.** El agente
   compila con `panic = "abort"`: un fichero que hiciera entrar en pánico a
   cualquier parser apagaba el EDR entero en esa máquina.
2. **No había contrato para sumar motores.** Cada uno se cableaba a mano, sin
   presupuesto y sin forma de decir «no pude mirar»; el bucle del agente imprimía
   escalados y no decidía nada. El árbitro existía y nadie lo llamaba.
3. **La pérdida de eventos no tenía orden.** Con el ring lleno se perdía lo que
   llegara, y en una tormenta de escrituras eso incluye el `exec` del cifrador.

## Qué se hizo, y la puerta que lo sostiene

| Entrega | Qué es | Puerta |
|---|---|---|
| Contrato único de motor | `aegis_motor::Motor`: evento tipado → señales (juicio tri-estado + evidencia) o `SinDatos` con causa; presupuesto de tiempo y memoria por motor; registro según las capacidades del host | grupo `motores`: pruebas de combinación, presupuesto, suspensión y firma |
| El árbitro como único punto de entrada | `Arbitro`: reparte, mide, suspende al que se pasa y combina con `aegis_entidad::arbitrar` | grupo `motores`: nadie en el agente llama a un motor ni combina, y los crates de detección solo entran por `src/motores/` (la lista de pendientes solo mengua) |
| Motores del agente por el contrato | triaje, conducta, secuestro de datos, estático y modelo; nacen en solo-auditoría | ídem, y `tests/arbitro.rs` con los motores reales |
| Trabajador confinado | el mismo binario con `--trabajador`: sin red (espacio de nombres propio), uid propio sin capacidades, sin ficheros (Landlock), seccomp en lista blanca, límites de recursos, cgroup con techo de memoria, CPU y un proceso, plazo por petición; protocolo versionado en el que solo se puede firmar como plano estático | grupo `trabajador`: confinamiento real como root (comprobado desde dentro), pánico, bomba de memoria, bucle infinito, relanzamiento y enfriamiento |
| El agente sobrevive a su trabajador | matar al trabajador N veces con ELF malformados no interrumpe la protección ni hace que el watchdog reinicie al agente | matriz de kernels: `trabajador-en-vivo` |
| Fuzzing continuo | un objetivo por parser del trabajador y otro para su protocolo; nightly fijado; semillas versionadas que son también las regresiones; ejecución nocturna en la forja | invariante en `crates/aegis-trabajador/tests/fuzzing.rs`; fuzzing breve en el grupo `trabajador`, que FALLA sin toolchain |
| Pérdida con prioridad | ejecución, salida y ptrace solo se pierden con el ring lleno; red y renombrados ceden por encima del 90 %; ficheros y escrituras, del 75 %; pérdida contada por familia | matriz de kernels: `prioridad-en-vivo` (200 de 200 ejecuciones con el ring saturado) y la prueba que cruza las familias de C y de Rust |
| Latido | el agente late desde su bucle de sondeo, haya eventos o no | matriz de kernels: `trabajador-en-vivo` corre bajo el watchdog real |
| Camino caliente medido por kernel | p99 del árbitro por evento y de cada motor, publicados en cada imagen de la matriz | `agente-en-vivo`: líneas `AEGIS-MEDIDA` que la matriz de capacidades lee |

Las cifras de latencia y de coste por kernel no se copian aquí: las publica cada
tanda de la matriz en `matriz-kernels/resumen.md` y la matriz de capacidades las
recoge como medida de cada crate.

## Hallazgos, cada uno con su arreglo de raíz

| Hallazgo | Causa raíz | Arreglo | Puerta |
|---|---|---|---|
| El grafo de linaje no caducaba nunca a los procesos muertos por tiempo | El agente medía «ahora» desde su propio arranque y los eventos llevan CLOCK_BOOTTIME: `ahora − muerte` saturaba a cero | Un solo reloj, el de los eventos del kernel (`bpf::ahora_boot_ns`) | prueba contra `/proc/uptime` |
| El desensamblador tardaba 21 s y usaba 600 MB con `python3`, con un plazo de 500 ms | El plazo solo lo consultaba la primera fase; una señal recorría todos los bloques por cada arista (cuadrático) y la propagación guardaba tres copias del estado de cada bloque | Un presupuesto para todas las fases, la señal con búsqueda indexada, estados dispersos | `crates/aegis-disasm/tests/presupuesto.rs` (demostrado con 20 000 funciones sintéticas) |
| El trabajador moría por falta de memoria con binarios corrientes | El caso anterior; el confinamiento lo contuvo, que es para lo que está | Ídem, y un tope de trabajo derivado del techo de memoria del trabajador | grupo `trabajador` |
| El modelo empotrado acusaba de sospechosos a `python3` y a `git` | Es una línea base con pesos fijados a mano, sin entrenar, y se publicaba como evidencia | `aegis_ml::puerta`: su puntuación se ve y no acusa salvo que su tarjeta generada corresponda por hash al modelo y al extractor y cumpla el FPR objetivo de `tools/config/modelo.toml` (FASE 4.4) | prueba en `aegis-trabajador` |
| Una muerte del trabajador se repetía en cada ejecución posterior del mismo binario | La caché del análisis guardaba también los fallos del momento | Solo se recuerda lo definitivo | prueba en `motores/estatico.rs` |
| El cgroup del trabajador quedaba huérfano al parar el agente | El proceso salía sin esperar al hilo analista | Parada ordenada y limpieza de los cgroups de agentes muertos al arrancar | ejecución en vivo |
| `aegis-sandbox` no compilaba contra musl | Tipo de petición de `ioctl` escrito como `c_ulong` (en musl es `c_int`); nunca lo había enlazado un instalable | `libc::Ioctl` | grupo `hermetico` |
| El agente ignoraba en silencio las opciones que no conocía | Buscaba las conocidas y descartaba el resto: la unidad del despliegue le pasaba `--config` y arrancaba sin configuración | Argumentos estrictos: una opción desconocida sale con 2 | ejecución en vivo |
| La prueba de captura fallaba con otro proceso compilando al lado | Medía coste algorítmico con el reloj | Trabajo contado, exacto | `aegis-captura`, pruebas de redacción |
| Dos pruebas e2e escondían el error de carga de las sondas | Se descartaba el resultado de `bpf::run` | El error es el diagnóstico | las propias pruebas |
| El fuzzing no se había ejecutado nunca en esta máquina | Sin nightly el script se omitía con código 0 | Nightly fijado, instalado en el runner, y fallo sin él | grupo `trabajador` |
| **En RHEL 9 (Rocky, Alma) todas las sondas de syscalls leían el argumento equivocado**: la ruta de cada ejecución llegaba como basura | El contexto de los tracepoints `syscalls:*` se declaraba con la estructura de `raw_syscalls`; RHEL 9 alarga `trace_entry` y CO-RE reubicó `args` y `ret` a su sitio en la estructura equivocada, ocho bytes más allá | `syscall_trace_enter` / `syscall_trace_exit`, las estructuras reales de esos tracepoints | prueba sobre las fuentes de las sondas; matriz de kernels: `ejecucion-en-vivo` y `ficheros-en-vivo`, que miran el contenido de los eventos |
| **Escribir ficheros con `open`, `creat` u `openat2` no llegaba a la telemetría** | Solo se enganchaba `openat`, que es lo que usa glibc; musl usa `open`, y un programa puede hacer la syscall a mano | Todas las vías de apertura, con un núcleo común en la sonda | matriz de kernels: `ficheros-en-vivo` (una apertura por vía) |
| La parada autorizada del watchdog mataba al agente con SIGKILL | `stop()` era `kill` directo | SIGTERM, plazo, y SIGKILL solo si no sale | `crates/aegis-watchdog/tests/watchdog.rs` |
| El cgroup del trabajador fallaba en las VM de la matriz | Se daba por hecho que la raíz repartía el controlador de CPU | Se activan los controladores necesarios; sin techo de CPU se declara | matriz de kernels: `trabajador-en-vivo` |
| La matriz no arrancaba: el disco de carga no cabía | Tamaño fijo de 256 MiB | Tamaño calculado de lo que se copia, y las pruebas sin información de depuración | la propia matriz |
| El fuzzing marcaba como fuga las tablas de `iced-x86` | Tablas estáticas de un solo uso que LeakSanitizer no ve | Supresión documentada en `fuzz/lsan.supp`; el resto de la detección de fugas sigue activa | grupo `trabajador` |

## Lo que no se hizo, y los muros

- **Prevención con BPF LSM (punto 5) y la política de decisión por clase de
  activo (punto 4, salvo la pérdida con prioridad):** no se entregan en esta
  fase. Siguen abiertas; el agente no deniega nada todavía, y lo dice.
- **Observabilidad en la consola (punto 6):** los histogramas por motor, la
  pérdida por familia y el estado del trabajador se publican en el registro del
  agente en cada informe; la consola web todavía no los muestra.
- **El motor de conducta hace E/S en el camino caliente:** en cada `exec` resuelve
  la imagen por `/proc/<pid>/exe`. En las VM de la matriz su p99 pasó de su
  presupuesto en algún kernel (el árbitro lo cuenta como exceso y lo suspendería
  si fuera seguido). Sacar esa resolución del camino caliente es trabajo de la
  FASE 3, con el banco de sobrecoste delante.
- **Parsers sin productor en el agente:** el motor de patrones, los disectores,
  el desempaquetador y la instrumentación entran al trabajador cuando el agente
  tenga algo que darles (FASE 2, ola C).
- **Despliegue:** las unidades de systemd del despliegue no pueden funcionar tal
  como están (el watchdog vigila hijos, no servicios hermanos, y al agente le
  faltan las capacidades que su trabajador necesita). Es la FASE 3, donde el
  empaquetado se ejerce en toda la matriz.

## Cómo se verifica

```bash
./tools/verificar-motores.sh       # contrato, árbitro y punto de entrada único
./tools/verificar-trabajador.sh    # confinamiento real (root), fuzzing, instalable limpio
cargo xtask kernels ejecutar       # agente, trabajador y prioridad en cada kernel
tools/fuzz.sh 600                  # lo que corre cada noche
```
