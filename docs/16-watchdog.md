# Módulo 16 — Watchdog de alta disponibilidad

> Componente: `crates/aegis-watchdog` (Rust) + binario `aegis-watchdog`.

Un EDR que se puede tumbar con un `kill` no protege nada: lo primero que hace un
atacante es apagar la vigilancia. **El agente no puede impedir su propia
terminación** —un `SIGKILL` de root no se puede bloquear desde el proceso
víctima—, así que la resiliencia la aporta un proceso aparte, mínimo, que lo
vuelve a arrancar.

Es minimalista a propósito: su única misión es que el agente siga en marcha, y
cuanto menos haga y menos memoria ocupe, menos superficie tiene quien quiera
tumbarlo a él.

---

## 16.1 Vivo, no solo presente

Un proceso puede estar **presente** (su PID existe) y sin embargo **colgado**: un
interbloqueo, un bucle infinito, un `read` que nunca vuelve. Comprobar solo el
PID no lo detecta. El agente escribe periódicamente un **latido** —un instante
del reloj monótono— en un fichero conocido; el watchdog lo lee y, si deja de
avanzar, sabe que el agente está colgado aunque su proceso siga ahí.

El fichero de latido es diminuto y la escritura es atómica por renombrado, para
que el watchdog nunca lea un valor a medias. Se usa el reloj **monótono** y no la
hora del sistema: un ajuste de reloj (NTP) no debe hacer creer al watchdog que el
agente lleva colgado horas.

---

## 16.2 Muerto, colgado, o parado a propósito

El watchdog distingue tres situaciones y actúa distinto en cada una:

| Estado observado | Decisión |
|---|---|
| El proceso ya no existe | **Reiniciar** (un `SIGKILL` cae aquí) |
| Existe pero el latido dejó de avanzar | **Reiniciar** (colgado) |
| Acaba de arrancar, aún sin latir | Esperar |
| Existe una marca de apagado autorizado | **No reiniciar** |

La **parada autorizada** es la frontera entre "lo mataron" y "lo pararon". Cuando
alguien con permiso le pide al agente que se detenga, este deja una marca de
apagado limpio; el watchdog la ve y no reinicia. Sin esto sería imposible parar
el agente: el watchdog lo resucitaría una y otra vez. La marca manda sobre todo
lo demás, incluso si el proceso murió.

Al reiniciar **no se pierden las políticas de seguridad**: el agente las recarga
de disco al arrancar (la configuración firmada, la línea base del FIM, la
cuarentena), y el watchdog solo lo vuelve a poner en marcha.

---

## 16.3 Cómo se prueba

Con un proceso hijo **real**: se lanza, se le hace `SIGKILL` —que no se puede
bloquear— y se comprueba que el watchdog lo detecta muerto (recolectando el
zombi) y arranca uno nuevo. Es el escenario que la FASE 17 dejó pendiente, y
ahora forma el **escenario 5** de la simulación de Red Team: se levanta el
binario `aegis-watchdog` supervisando un agente de mentira, se mata a ese agente
con `SIGKILL`, y se verifica que aparece un proceso nuevo.

También se prueba el reinicio ante cuelgue (latido rancio) y que una parada
autorizada nunca reinicia.

---

## 16.4 El tercer fallo: el agente desbordado

El watchdog original distinguía dos fallos: **muerto** y **colgado**. Falta un
tercero, y es el que más cuesta reconocer:

> **Desbordado.** El proceso existe, late con normalidad, y se está comiendo la
> máquina.

Una fuga lenta no mata ni cuelga a nadie. Llega a 2 GiB a las tres de la mañana,
y para entonces el problema ya no es el agente: es el host de producción que se
ha llevado por delante. Un watchdog que solo mira el latido da eso por bueno
hasta el final, y **un EDR que tumba al host que protege es peor que un EDR
ausente**, porque el ausente al menos no causa la caída.

Es el patrón de `osquery`, que no se fía de su propio proceso: su watchdog tiene
`--watchdog_memory_limit` y **mata y reinicia** al obrero que se pasa.

### Las dos mitades que lo hacen desplegable

**Una sola muestra sobre el techo no reinicia nada.** Reiniciar el EDR es en sí
mismo un evento de seguridad: abre una ventana sin protección. Si bastara una
lectura alta, un atacante capaz de provocar picos de memoria tendría ahí un
interruptor para apagar la vigilancia a voluntad. Hacen falta
`MUESTRAS_PARA_REINICIO` muestras **seguidas**, una por ciclo de supervisión.

**El contador no sobrevive al reinicio.** Si lo hiciera, el proceso nuevo nacería
condenado y el watchdog lo mataría en su primer ciclo, una y otra vez: una fuga
acotada se convertiría en una máquina sin EDR, que es peor que la fuga.

Dos decisiones más, ambas contra el mismo tipo de error:

- **Se mide el proceso, no su cgroup.** En el despliegue real el watchdog lanza
  al agente como hijo, así que comparten unidad. Preguntarle al cgroup cuánto
  gasta el agente devolvería también lo que gasta el watchdog, y el reinicio —que
  no libera nada de lo que de verdad sobraba— se repetiría sin converger.
- **No poder medir no es una fuga.** Si `/proc` no se deja leer, no se acumula
  nada. Tratarlo como desbordamiento haría que el watchdog reiniciase al agente
  por no poder mirarlo, que es justo lo que un atacante querría provocar.
- **Observar no muestrea.** `MUESTRAS_PARA_REINICIO` cuenta ciclos de
  supervisión. Si cada consulta de estado contase como muestra, cualquiera que
  sondease el watchdog en bucle acortaría a voluntad el plazo antes del reinicio.

---

## 16.5 El presupuesto de memoria

El presupuesto ya no es una cifra fija. Es una **fracción de la RAM del host, con
suelo y con techo**, repartida en tres regímenes y obligada por tres capas. El
detalle completo —por qué «45 MB» estaba mal de tres maneras distintas, el
reparto por clase de host y la comparativa con Defender, CrowdStrike, SentinelOne
y Elastic Defend— está en el [README](../README.md#presupuesto-de-recursos) y en
el crate `aegis-presupuesto`.

Lo que toca a este documento es la tercera capa, la que convierte la promesa en
un invariante: el kernel.

| Directiva | Valor | Por qué |
|---|---|---|
| `MemoryHigh` | el **pico** | Límite **blando**: el kernel reclama y frena, pero el escaneo termina |
| `MemoryMax` | el **techo** | Límite **duro**: OOM dentro del cgroup. Mata al agente, nunca al host |
| `MemorySwapMax` | `0` | Un EDR paginado llega tarde, y sus estructuras no deben acabar escritas en el disco de la víctima |
| `OOMScoreAdjust` | `-500` | Ante presión de memoria **ajena** el agente no es la víctima a sacrificar: su propia fuga ya la corta `MemoryMax`, que es local |
| `Restart` | `always` | El OOM del cgroup no es el final: es un reinicio de un segundo |

Confundir `MemoryHigh` con `MemoryMax` no es un detalle de estilo: intercambiados,
el kernel **mata donde debería frenar**. Hay una prueba que comprueba que el
blando lleva el pico y el duro el techo.

`make ci` mide el arranque real del agente contra **dos puertas**: el presupuesto
del host, que escala, y la línea base de arranque, que no escala con nada y es la
única que caza una regresión en una máquina grande.
