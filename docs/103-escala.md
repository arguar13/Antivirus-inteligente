# Módulo 103 — AegisReal: la escala, de verdad (FASE 111)

> Componentes: `server/crates/aegis-server/tests/escala_real.rs`,
> `tools/verificar-escala-real.sh`, grupo CI `escala-real`. Apoyado en el benchmark
> en memoria de `fleet-simulator/src/bin/escala.rs` (FASE 75) para lo que no cabe
> en una máquina.

## 103.1 La derrota que cierra: «simulado» no es «medido»

Los cien mil agentes del plano de control estaban **simulados en memoria** —en un
solo proceso, sin tocar la base ni la red (`escala.rs`)—. Es honesto sobre su muro,
pero la afirmación que de verdad importa —**«cero pérdida silenciosa, demostrada
contando en los dos extremos»**— no se puede sostener contando en un solo proceso:
la garantiza la base de datos, o no se garantiza. Frente a Wazuh y Elastic en
producción no se gana declarando; se gana **midiendo lo mismo que ellos, con la
misma base de datos real, y publicando el número**.

## 103.2 Qué se mide, contra PostgreSQL real

`escala_real.rs` ingesta por el **mismo camino de persistencia que producción**
(`Almacen::registrar_alerta` → `INSERT INTO alertas` + `UPDATE agentes` en una
transacción), contra un PostgreSQL real, y mide:

1. **Pérdida cero, contada en los dos extremos.** Se cuenta (a) lo que el simulador
   **envió**, (b) lo que la base **guarda** (`count(*)` de alertas de mis agentes) y
   (c) el **contador propio del servidor** (`sum(eventos)` de agentes). Los tres
   cuadran, o hay pérdida y se ve. Ya no es un conteo en memoria del mismo proceso:
   es la base la que responde.
2. **Latencia de ingesta p50/p95/p99**, publicada.
3. **Aislamiento por inquilino**: el conteo de una flota no incluye a la otra, con
   un `JOIN` real contra la base.
4. **La purga de la FASE 75 es metadato, no un barrido.** Contra PostgreSQL real, en
   un esquema desechable, se cronometra `DETACH PARTITION` + `DROP` frente a un
   `DELETE` equivalente: el `DROP` no toca las filas (por eso no compite con la
   ingesta), el `DELETE` las recorre. Es la propiedad que hace que **la purga no
   bloquee la ingesta**, y no depende del tamaño.

Se **omite con honestidad** —sin fingir éxito— si la máquina no tiene PostgreSQL:
el grupo `escala-real` lo declara, como hacen `orchestrator`, `almacen` y `flujo`.

## 103.3 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Pérdida cero contada en los dos extremos | **sí, real** | envío vs `count(*)` de alertas vs `sum(eventos)` de agentes, contra PG real |
| Latencia de ingesta p50/p95/p99 | **sí, real** | cronometrada por inserción, publicada |
| Aislamiento por inquilino | **sí, real** | `JOIN` alertas↔agentes por `id_flota`; una flota no ve a la otra |
| Purga = metadato (DETACH+DROP, no DELETE) | **sí, real** | cronometrado contra PG en esquema desechable; el DELETE recorre 20 000 filas, el DROP no |
| Reparto de la flota y manada tras caída de nodo | **sí, en memoria** | `escala.rs` (FASE 75) lo mide a escala de 100 000 como lógica pura |
| Cuotas por inquilino (un hostil no desplaza a otro) | **sí, en memoria** | `aegis-pipeline` con sus dos cuotas, ejercido en `escala.rs` |
| Cien mil conexiones mTLS **vivas** | **muro declarado** | no caben en una máquina; el diseño deliberadamente no las mantiene (`aegis-scale::sesion`) |
| EPS sostenidos a escala de producción | **muro declarado** | el simulador y el servidor comparten núcleos; el número extremo-a-extremo incluye el coste del generador |
| Purga sobre una partición realmente llena (144M filas/día) | **muro declarado** | no reproducible aquí; la propiedad (metadato) sí, a escala reducida |
| Cableado de `aegis-scale` al arranque del servidor | **incremento siguiente** | hoy la purga se prueba como SQL puro y aquí como DETACH+DROP real; ejecutarla desde el mantenimiento del servidor es el paso que queda |

El alcance por partes es la decisión honesta: lo que se puede medir de verdad
contra la base —pérdida cero en los dos extremos, latencia, aislamiento, y que la
purga es metadato— se mide contra PostgreSQL real; lo que no cabe en una máquina
—cien mil conexiones vivas, discos de producción— se declara como muro y se apoya en
el benchmark en memoria que ya existe, en vez de fingir una escala que no se
ejerció.

Mensaje de commit:
`test(scale): replace the simulated control plane benchmark with a real PostgreSQL-backed fleet measurement`
