# Módulo 56 — AegisHPC: la PMU del procesador como sensor de defensa

> Componentes: `crates/aegis-hardsense/`.

## 56.1 Ataques que solo se ven en el hardware

Hay ataques que no dejan huella en las syscalls ni en los ficheros, pero sí en
cómo se comporta el procesador por dentro:

- Un **canal lateral por caché** (Flush+Reload, Prime+Probe, Spectre) desaloja y
  recarga líneas de caché miles de veces para robar un secreto midiendo tiempos
  de acceso. Eso dispara los **fallos de la última caché (LLC)** muy por encima
  de lo que hace el código normal.
- Una cadena **ROP/JOP** encadena "gadgets" saltando a direcciones que el
  predictor de saltos nunca aprendió. Eso dispara la **tasa de fallos de
  predicción de saltos** y, de paso, hunde el IPC (instrucciones por ciclo).

La **Performance Monitoring Unit** (PMU) del procesador cuenta esos eventos en
hardware, sin frenar nada. AegisHPC la lee y la convierte en un sensor más de la
defensa.

## 56.2 Defensivo, no ofensivo

La misma PMU podría usarse para *construir* un canal lateral. Aquí se usa sólo
para **detectarlo**: AegisHPC lee sus propios contadores para delatar a quien
ataca, jamás para atacar. Es la misma línea que recorre todo AegisCore.

## 56.3 La decisión: una línea base por proceso, no un umbral mágico

No hay un número fijo que separe lo bueno de lo malo —cada proceso tiene su
propio perfil de caché y de saltos—. El analizador aprende, por media móvil
exponencial (EWMA), la **media y la varianza** de cada tasa, y sólo marca una
muestra que se dispara **muchas sigmas** por encima de *su propia* base **y**
además supera un piso absoluto (para no marcar el ruido de una base minúscula).

Dos defensas más, deliberadas:

- **Calentamiento**: durante las primeras muestras el analizador aprende y no
  juzga; no acusa antes de conocer al proceso.
- **La base no se envenena**: una muestra ya marcada como anómala **no** entrena
  la línea base. Un ataque no puede, subiendo poco a poco, enseñarle al detector
  a aceptarlo.

Un pico de fallos de caché se clasifica como **canal lateral**; un pico de fallos
de predicción de saltos, como **ROP/JOP**. La severidad sale de cuán lejos de la
base está el pico.

## 56.4 La captura, reutilizando el patrón de los otros crates de hardware

Leer la PMU se hace por `perf_event_open`. AegisHPC lleva su **propio** espejo
mínimo de `perf_event_attr` (136 bytes, verificado en compilación), igual que
`aegis-syscallguard` y `aegis-ptguard`: cada crate de hardware es autocontenido
para no arrastrar la maquinaria de los otros y mantener pequeño el árbol del
agente. Abre cinco contadores —ciclos, instrucciones, fallos de LLC, saltos y
fallos de predicción— sobre el hilo, y produce muestras de diferencias.

## 56.5 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Detección de canal lateral por pico de fallos de caché | sí, con series reales, cero mocks | — |
| Detección de ROP/JOP por pico de fallos de predicción de saltos | sí | — |
| Ausencia de falsos positivos con tráfico normal (ruidoso) | sí | — |
| Calentamiento (no juzgar sin base) y base a prueba de envenenamiento | sí | — |
| Tasas derivadas (IPC, MPKI, error de saltos) sin división por cero | sí | — |
| ABI de `perf_event_attr` (136 B) | sí, en compilación | — |
| Sondeo honesto de la PMU (`ENOENT` en un microVM) | sí (se declara) | — |
| Leer los contadores de la PMU **en vivo** | — | necesita que el hardware exponga la PMU; en este runner no está (microVM); gated |

El núcleo que puede estar mal de forma peligrosa —aprender la base y decidir— se
prueba de verdad en cada `make ci`. Leer la PMU en vivo es un muro físico: donde
el hardware no la expone, `tools/verificar-hardsense.sh` lo declara en vez de
fingirlo, y la decisión se sigue probando sobre datos reales.
