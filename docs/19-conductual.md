# Módulo 19 — Motor conductual: grafo DAG y puntuación MITRE ATT&CK

> Componentes: `crates/aegis-behavior` (motor) + `aegis-agent::behavior` (traducción de telemetría).

La detección por evento aislado se acabó hace años. Ninguna de las acciones de
una intrusión moderna es, por sí sola, distinguible de trabajo legítimo: un
servidor lanza procesos, un intérprete se ejecuta, alguien descarga un fichero,
alguien le da permisos de ejecución. **Lo que delata al ataque es la secuencia**,
y para ver secuencias hace falta memoria estructurada de lo que ha pasado.

---

## 19.1 Por qué un DAG y no un árbol

El linaje de procesos es un árbol: cada proceso tiene un padre. Pero la
causalidad que importa a la detección no es sólo quién lanzó a quién. Cuando un
proceso **inyecta** código en otro, o lo **traza**, la actividad del segundo es
responsabilidad del primero aunque no sea su hijo: esa es precisamente la gracia
de inyectar, romper el linaje para que el analista vea un `gnome-calculator`
conectando a Internet en vez de la macro que lo hizo.

Modelar esas aristas convierte el árbol en un grafo dirigido y obliga a
garantizar que sigue siendo **acíclico**. Dos procesos que se inyectan mutuamente
—técnica de evasión real— cerrarían un ciclo, y el recorrido de ancestros, que es
la operación más usada del motor, dejaría de terminar: una denegación de servicio
contra el propio motor. `BehaviorGraph::link` rechaza y **cuenta** esa arista en
vez de confiar en que no ocurra.

Cada tipo de arista propaga una fracción distinta del riesgo, porque no significan
lo mismo:

| Arista | Propagación | Por qué |
|---|---|---|
| `Injected` | 0.95 | Nadie inyecta código en otro proceso por accidente |
| `Wrote` | 0.80 | Escribió el binario que el otro ejecuta |
| `Traced` | 0.75 | Control total sobre el trazado |
| `Spawned` | 0.60 | Un servidor lanza procesos legítimos todo el día |

---

## 19.2 Los pesos discriminan, no describen

Un motor que sume «una alerta = un punto» es un generador de ruido. `bash` es
T1059 y ocurre cientos de veces al día en cualquier servidor. Lo que separa la
detección de la alarma es que cada técnica pese **lo que de verdad discrimina**:

- Casi nunca legítimas → peso alto: cifrado con impacto (T1486, 60), inyección
  (T1055, 45), explotación (T1203, 40), borrado de rastros (T1070, 35).
- Ubicuas → peso bajo aunque salgan en todos los informes: intérprete de
  comandos (T1059, 15), protocolo de aplicación (T1071, 10).

**Ninguna técnica del catálogo llega sola al umbral de aislamiento**, y hay una
prueba que lo verifica sobre las catorce. Cortar un proceso por una sola
observación es como se saca de producción algo que funcionaba.

La suma propia **decae**: se ordena de mayor a menor y cada sumando siguiente
vale un 60 % del anterior. Sin eso, diez técnicas ubicuas de peso 10 sumarían 100
y aislarían un proceso normal.

---

## 19.3 La cadena vale más que la suma

Un patrón es una secuencia ordenada de pasos que debe aparecer como subsecuencia
del camino causal raíz → nodo. La cadena canónica de una ejecución remota de
código en un servidor web:

```
nginx  →  sh  →  curl  →  chmod  →  /tmp/.update
```

Cada paso por separado es defendible. Juntos y en ese orden son un compromiso, y
el patrón `web-rce` aporta 80 puntos: por sí solo cruza el umbral. Es defendible
porque el patrón es muy específico —cinco pasos, tres nodos distintos y un
servidor expuesto en la raíz—. **La misma secuencia sin el servidor** (un
administrador por SSH que descarga un instalador y lo ejecuta) no cruza el
umbral, y hay una prueba para cada uno de los dos casos.

Dos decisiones del emparejamiento merecen explicación:

- **El último paso se ancla en el nodo puntuado.** Un patrón describe una cadena
  que culmina en ese nodo. Sin anclaje hay una evasión real: basta con que un
  nodo intermedio cumpla por casualidad el paso final —un intérprete copiado a
  `/tmp`— para que lo consuma y la cadena de verdad deje de reconocerse. Un
  atacante puede provocarlo a propósito, y hay una prueba que lo intenta.
- **Los pasos anteriores pueden caer en el mismo nodo**, porque la cadena real se
  reparte entre hermanos: el intérprete no descarga ni cambia permisos, lanza a
  quien lo hace. Para que eso no degenere en «un nodo cumple el patrón entero»,
  cada patrón declara un mínimo de nodos **distintos** que debe abarcar.
- Los pasos que hablan de lo que un nodo *provocó* miran sólo a sus hijos
  **directos**. Mirar el subárbol entero haría que el servidor de la raíz
  cumpliera cualquier paso, porque debajo de él acaba estando todo.

---

## 19.4 La decisión, y cuándo se repite

| Puntuación | Acción |
|---|---|
| < 40 | Observar |
| 40 – 85 | Alertar a un analista |
| > 85 | **Aislar automáticamente** |

El umbral es 85 y no 100 porque exigir certeza absoluta significa no contener
nunca; y no es 50 porque una acción automática sobre un falso positivo saca de
producción algo que funcionaba. La franja intermedia va a un humano.

La deduplicación guarda el **nivel** ya emitido, no la mera presencia. Es la
trampa evidente: un proceso que alerta a 60 se marcaría como «ya decidido», y
cuando después llegara a 92 la escalada a aislamiento se perdería, dejando el
proceso corriendo con una alerta antigua como única constancia.

El modo **no autónomo** (`autonomous: false`) alerta en vez de cortar: es como se
despliega el motor la primera semana en producción, para ver qué *habría* hecho.
La puntuación **no** se rebaja en ese modo: esconderla ocultaría que la máquina
tiene un proceso que merece aislamiento.

---

## 19.5 Qué se traduce a técnica, y qué no

`aegis-agent::behavior` convierte la telemetría del kernel en observaciones de
ATT&CK. Es donde se decide qué cuenta como qué, y una traducción generosa de más
arruina el motor más rápido que un motor mal calibrado, porque le mete ruido con
peso alto.

| Telemetría | Técnica | Criterio |
|---|---|---|
| `exec` de intérprete/descargador/`chmod`/`crontab`/`shred` | T1059 / T1105 / T1222 / T1053 / T1070 | Por la imagen **resuelta**, no la invocada |
| `ptrace` que **escribe** memoria ajena | T1055 + arista `Injected` | Escribirla no admite lectura benigna |
| `ptrace` que sólo **lee** | — | `gdb` y los perfiladores lo hacen |
| Conexión a red pública | T1071 | |
| Conexión a 22/445/3389 en red interna | T1021 | |
| Conexión a *loopback* | — | Cualquier servicio local la genera |
| Renombrado dentro de `/var/log` | T1070 | Mover un registro lo hace desaparecer igual que borrarlo |
| Escritura de alta entropía | — | Ver abajo |

La escritura de alta entropía **no** se traduce a T1486. Es la técnica de más peso
del catálogo, y anotarla desde una señal ambigua convertiría cada copia de
seguridad comprimida en un aislamiento automático. T1486 entra por una única vía:
`on_ransom_confirmed`, que llama el motor de ransomware **después** de cruzar
velocidad, entropía normalizada y señuelos.

La imagen que decide es la que resolvió la capa de abstracción
(`/proc/<pid>/exe`), no la que traía el evento: el evento trae la ruta que el
proceso pasó a `execve`, que el atacante elige y puede ser un enlace a cualquier
sitio. Y es la misma imagen con la que se evalúan los patrones: dos autoridades
distintas para «qué binario es este» acabarían clasificando el mismo proceso de
dos maneras.

El **linaje** lo fija la sonda, no `procfs`: el evento de `exec` trae el padre
capturado en el momento de la ejecución, mientras que `procfs` trae el padre
actual. Cuando un proceso muere, sus hijos se reasignan a `init` y con ellos se
pierde el linaje del incidente — y desligarse así es una técnica deliberada.

---

## 19.6 Independiente del sistema operativo

El motor sólo habla el vocabulario de [`aegis-scal`](18-scal.md): recibe
`ProcessEvent` y observaciones de técnica, venga quien las traiga. No sabe que
existe `/proc`, ni ETW, ni EndpointSecurity. Es lo que permite que la parte del
producto con más valor se compile igual en los tres sistemas.

Los nodos se identifican con `ProcessKey`, que lleva el instante de arranque: un
PID reciclado **no** hereda el historial del anterior, y hay una prueba que lo
comprueba con un proceso que cifró ficheros y otro que reutiliza su número.
