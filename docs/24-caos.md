# Módulo 24 — Ingeniería del caos

> Componente: `crates/aegis-e2e/tests/chaos_harness.rs`, integrado en `make audit`.

Las pruebas normales comprueban que el producto hace lo que debe cuando el
entorno se porta. Éstas comprueban lo contrario: que **no hace nada
catastrófico** cuando el entorno se rompe.

Un EDR que se cuelga, que crece sin límite o que corrompe su propia memoria ante
una entrada rara es peor que no tener EDR, porque el equipo cree estar protegido.

---

## 24.1 El caos es determinista

La corrupción y las pérdidas siguen un patrón reproducible —un generador
congruencial lineal con semillas fijas— en vez de un generador aleatorio. **Una
prueba de caos que falla una vez de cada cien y no se puede reproducir no se
arregla: se desactiva.**

---

## 24.2 Corrupción del buffer de IPC

El ring es memoria compartida con el kernel. Un fallo de hardware, o un atacante
con el mapeo, puede alterarla. Se corrompen dos zonas por separado, porque
fallan de forma distinta:

- **El área de datos**: el consumidor puede interpretar basura como eventos —el
  triaje de arriba ya los descarta por malformados—, pero leer basura no puede
  convertirse en **leer fuera del buffer**. La prueba toca todos los bytes de
  cada carga útil, de modo que un desbordamiento se manifiesta de verdad y no
  pasa por una comprobación superficial de la longitud.
- **La cabecera de control**: los índices del ring alterados son el peor caso, un
  `tail` inventado podría hacer leer fuera del mapeo. Que `attach` rechace el
  mapeo es la respuesta correcta: una cabecera que no cuadra no se interpreta.

Y un ring saturado **suelta en vez de bloquear**: si bloqueara al llenarse, el
hilo que drena eBPF se pararía y el kernel empezaría a descartar eventos, un
punto ciego mucho peor que perder unos cuantos aquí. Lo que sí entró se sigue
leyendo en orden: soltar no corrompe el flujo.

---

## 24.3 Caídas de red

- **Pérdida del 70 %**: un relé que descarta cuatro de cada cinco datagramas de
  forma determinista. La malla no retransmite —es un protocolo de inundación, no
  de entrega fiable—, así que lo que se comprueba es que la **repetición del
  emisor converge**, que es como funciona el rumor en una red local. Las copias
  que llegan después se reconocen como duplicadas.
- **Alteración en tránsito**: un relé que voltea un bit de cada mensaje, que es
  lo que hace un enlace defectuoso y también lo que haría un atacante con acceso
  al medio. Ni una cuela, y la malla sigue viva para el tráfico bueno.
- **Todos los pares caídos**: un agente aislado no puede quedarse esperando —
  seguiría sin detectar mientras espera a hablar—, y el sondeo devuelve el
  control aunque no llegue nada.

---

## 24.4 Saturación de memoria

Todas las estructuras que guardan estado **por origen** son un objetivo: si
crecieran sin cota, el detector se convertiría en el objetivo del ataque. Se
inundan las tres a la vez con 200 000 entradas hostiles:

| Estructura | Ataque | Cota |
|---|---|---|
| Sensor de señuelos | 100 000 direcciones falsificadas | `max_peers` |
| Grafo conductual | 50 000 procesos que nacen y mueren | `max_nodes` + expiración |
| Memoria de vacunas | 50 000 vacunas distintas | `dedup_capacity` |

Además de comprobar cada cota, se mide el **RSS real** del proceso antes y
después y se exige que el crecimiento se quede por debajo de 128 MB. Comprobar
sólo los `len()` no detectaría una fuga en una estructura auxiliar.

---

## 24.5 Cuelgues de hilos

- **Un consumidor colgado no bloquea al productor.** Es la propiedad que sostiene
  todo el pipeline: si el consumidor se cuelga, el hilo que drena el ring de eBPF
  tiene que seguir avanzando y soltar. Si se parara, el kernel empezaría a
  descartar eventos y el agente se quedaría ciego. Se prueba con un hilo real que
  deja de drenar mientras el productor mete 200 000 eventos.
- **El watchdog distingue colgado de muerto.** Un proceso presente pero colgado
  es el fallo más difícil de ver: el PID existe, así que cualquier comprobación
  basada sólo en su presencia dice que todo va bien.
- **Ningún sondeo se queda esperando para siempre.** Todos los bucles del
  producto sondean con plazo; uno que lo ignorara dejaría al agente sin poder
  atender ni siquiera su propia señal de parada.

---

## 24.6 Todo a la vez

La última prueba mezcla las cuatro familias, que es como se presentan en
producción: la red falla mientras la memoria se llena mientras el consumidor se
atasca. Se exige que el conjunto termine en tiempo acotado, que la memoria no
crezca, que las cotas se respeten y que **después de todo eso** el consumidor
drene lo que quedó sin colgarse.

El arnés forma parte de `make audit`, la puerta final antes de una release, en
paralelo con la compilación sin avisos, clippy, la simulación de Red Team y el
estrés de un millón de eventos.
