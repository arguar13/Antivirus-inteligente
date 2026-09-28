# Módulo 101 — AegisWork: el trabajo del analista (FASE 109)

> Componentes: ampliación de `server/crates/aegis-case/` (`colaboracion`,
> `informe`) y de `server/crates/aegis-enrich/` (`presupuesto_caso`).

Esta fase va **antes** que la consola a propósito: una consola sobre un flujo de
trabajo incompleto es una interfaz bonita sobre un hueco. El modelo de casos de
AegisCore ya era mejor que el de TheHive —nadie más distingue el hueco de la
ausencia— y el de enriquecimiento mejor que el de Cortex —la exposición declarada
en el tipo—; lo que faltaba era el **trabajo encima**, y un empate es un fracaso.

## 101.1 PARTE A — Casos: colaboración real e informe honesto

**Traspaso con contexto** (`colaboracion`). TheHive reasigna un caso: cambia el
nombre del dueño y ya. Un turno que recibe un caso a las tres de la mañana sin
saber qué miró el anterior y qué dejó abierto empieza de cero, y en un incidente en
curso empezar de cero es tiempo que el atacante usa. Aquí el `Traspaso` **lleva el
contexto**: lo que el que entrega sabe (lo escribe) y lo que deja abierto **se
captura del caso**, no de su memoria —aunque se olvide de mencionar una tarea, el
que recibe la ve—.

**Tiempo por estado medido del rastro** (`tiempo_en_estados`). El tiempo en cada
estado se **mide** de las transiciones, no se declara: una hora en `EnEspera`
—esperando al cliente— no puede contar como una hora de respuesta del equipo, o la
métrica culpa al equipo de algo que no depende de él. (Sobre esto se apoyan las
métricas del SOC de `metricas`, ya existentes: MTTD, MTTC, MTTR por tipo.)

**Informe con cadena de custodia y huecos declarados** (`informe`). Es la tentación
de todo informe: presentar el caso como una historia cerrada y limpia. Pero un
informe que dice «resuelto» con tareas sin hacer, o que no menciona que el rastro
no estaba anclado, es lo que un abogado de la parte contraria usa para tirar el
peritaje entero. Aquí el informe **lista sus huecos** —tareas abiertas, veredicto
no concluyente, rastro manipulado o sin anclar— porque un hueco dicho es una
limitación y un hueco callado es una mentira. La cadena de custodia sale del rastro
inmutable (`auditoria`), no se escribe a mano. Ningún producto abierto declara sus
huecos.

La cronología a escala (`cronologia`), las plantillas de respuesta que arrancan
flujos con frenos (`plantillas`) y las métricas del rastro (`metricas`) ya existían
de la FASE 76; esta fase añade la colaboración y el informe que faltaban encima.

## 101.2 PARTE B — Enriquecimiento: el presupuesto de exposición por caso

`aegis-enrich` ya declaraba la exposición consulta a consulta, ejecutaba lo local
primero (los analizadores que no revelan nada —decompilador, motor de patrones,
emulador, grafo— corren antes que cualquier remoto), y medía las consultas que la
caché evitó. Lo que faltaba: la exposición **acumulada por caso**.

`presupuesto_caso::PresupuestoCaso` cierra ese hueco. Un caso son muchas consultas,
y cada una revela un poco: diez consultas «inofensivas» sobre el mismo incidente
pueden dibujarle a un tercero la mitad de tu red sin que ninguna, por sí sola,
pareciera de más. Aquí la exposición **se acumula** por caso, con un tope; cuando la
siguiente consulta al exterior pasaría del tope, se **para** —no se hace, y se
dice—. Lo local no cuesta (0 puntos) y **nunca se corta**: preguntar dentro no
revela nada fuera, así que no hay motivo para racionarlo. Es «local primero»
expresado como economía: lo gratis va primero y sin límite. El gasto es **visible**
consulta a consulta.

## 101.3 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Traspaso con contexto capturado del caso | **sí** | las tareas abiertas viajan con el traspaso aunque el que entrega no las mencione |
| No se traspasa a uno mismo ni a nadie | **sí** | rechazado con motivo |
| Tiempo por estado del rastro | **sí** | la hora en `EnEspera` se aísla del tiempo de trabajo |
| Informe declara todos los huecos | **sí** | tareas abiertas + veredicto no concluyente + rastro sin anclar → todos listados |
| Rastro manipulado sale como hueco | **sí** | una entrada fuera de secuencia → `RastroManipulado` en el informe |
| Presupuesto de exposición por caso | **sí** | la exposición externa acumula y se para al exceder; una consulta rechazada no gasta |
| Local primero como economía | **sí** | lo local cuesta 0 y nunca se corta, aun con tope cero |
| Gasto visible consulta a consulta | **sí** | `detalle()` lista quién costó cuánto |
| Jurisdicción sin adecuación cuesta el doble | **sí** | el coste refleja el riesgo del destino |
| Más analizadores que Cortex+IntelOwl | **parte declarada** | el marco tipado y la exposición por analizador están; el catálogo se amplía como incremento medido, sin fingir integraciones |
| Colaboración/timeline/métricas base | **ya existían** | FASE 76 (`fusion`, `cronologia`, `metricas`, `plantillas`); esta fase añade lo que faltaba encima |

El alcance por partes es la decisión honesta: sobre el modelo de casos y el de
enriquecimiento —ya superiores en diseño— se añade el trabajo que convertía el
empate en superioridad medida: colaboración con contexto, informe con huecos, y el
presupuesto de exposición por caso. El recuento de analizadores se amplía como
incremento medido, sin fingir integraciones que no existen.

Mensaje de commit:
`feat(soc): complete case collaboration with timeline-scale joins and local-first enrichment under an exposure budget`
