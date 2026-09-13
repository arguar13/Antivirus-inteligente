# 71 · AegisCase — de alerta a caso cerrado

> FASE 76. `server/crates/aegis-case`, `server/crates/aegis-server/src/casos.rs`,
> `server/migrations/0008_casos.sql` y diez rutas nuevas de la API.

## La tesis

**Un producto que detecta y no da un flujo de trabajo produce alertas que nadie
mira.** Y no por dejadez del analista: un humano que recibe cincuenta alertas al
día de las que cuarenta y ocho son ruido **deja de mirarlas**, porque es la
respuesta racional a una señal con esa relación señal-ruido. El día que llega la
que importa, va al mismo sitio que las demás.

De modo que esto no es una capa de gestión encima del producto. Es **lo que
impide que la detección se pierda por el camino**, y son seis problemas
concretos. Todos comparten una propiedad incómoda: fallan **en silencio**.

| Módulo | El problema, y por qué no se nota |
|---|---|
| [`modelo`] | Un caso cerrado sin veredicto, o con tareas abiertas y sin justificar, cuenta igual en la métrica que uno resuelto |
| [`fusion`] | Mil alertas de una campaña esconden el caso distinto que llegó en medio — y fusionar de más pierde un incidente sin dejar constancia de haberlo perdido |
| [`cronologia`] | Quien escribe la cronología a mano copia los hechos que confirman su hipótesis, y cose los huecos en una cadena causal que no existió |
| [`auditoria`] | Un registro que se puede editar después no vale como evidencia, y no hace falta un atacante para romperlo: basta una migración mal hecha |
| [`metricas`] | Sin ruido **por regla** no se pueden apagar las reglas que sólo hacen ruido, que es lo único que de verdad cambia la vida de un SOC |
| [`plantillas`] | «Contener primero» es correcto para un ransomware y catastrófico para una cuenta comprometida |

---

## 1 · El modelo: las dos reglas que parecen burocracia y no lo son

### Un caso no se cierra sin veredicto

`pasar_a(Estado::Cerrado)` **devuelve error**. Cerrar es una operación distinta,
`cerrar(veredicto, …)`, y exige el veredicto como argumento. No es rigidez: un
caso cerrado sin veredicto es indistinguible en el panel de uno resuelto, y
alimenta la métrica de ruido por regla con un dato que no existe.

### Con tareas abiertas, hace falta escribir por qué

`cerrar` con tareas abiertas y sin justificación devuelve `Rechazo`. La razón
cabe en una frase:

> «Se investigó y no era nada» y «nadie llegó a mirarlo» acaban con el caso
> cerrado, producen la misma métrica, y sólo una de las dos es aceptable.

La justificación es lo único que las separa, y tiene que estar en el momento de
cerrar, porque después nadie se acuerda.

### Reabrir limpia el cierre

`pasar_a` desde `Cerrado` borra `cerrado_ns`, `veredicto` y
`justificacion_cierre`. Dejarlos puestos haría que la métrica de tiempo hasta
cierre contase un caso que **volvió a abrirse** — y esa métrica es exactamente la
que se lleva a la reunión de trimestre.

### El estado `Contenido` existe aparte de `Cerrado`

El ataque está parado y la investigación sigue. Es el estado en el que más tiempo
pasa un caso serio, y confundirlo con «cerrado» hace que las métricas digan que
se cierra más rápido de lo que se cierra.

### El estado `EnEspera` también, y por una razón de medida

Si esperar al cliente, al proveedor o a la ventana de mantenimiento contara como
tiempo de trabajo, la métrica de respuesta del equipo saldría mal **por algo que
no depende del equipo**. `espera_de` la calcula de la **historia de estados**, no
de un contador que se va sumando: un contador se olvida de restar en algún
camino, y el síntoma es una métrica que mejora sola.

---

## 2 · La fusión: la decisión más peligrosa del módulo

Fusionar de menos ahoga la cola. Fusionar de más **pierde un incidente**, y lo
pierde sin dejar hueco donde mirar. Las dos son malas; la segunda es peor y la
que no se nota.

Cinco constantes, y cada una responde a una pregunta concreta:

| Constante | Valor | Por qué ése |
|---|---|---|
| `VENTANA_CASO_NS` | 4 h | Lo que dura un incidente en atención activa. Más allá, la misma alerta del mismo sujeto es probablemente **otra cosa** —el atacante volvió, la máquina se reinfectó— y merece su caso, su cronología y su tiempo de respuesta |
| `VENTANA_CAMPANA_NS` | 1 h | Una campaña se reconoce por ser **simultánea**. La misma técnica en máquinas distintas con horas de diferencia es más probablemente la misma herramienta usada por gente distinta |
| `MINIMO_MAQUINAS_CAMPANA` | 3 | Dos máquinas son una coincidencia |
| `SILENCIO_NS` | 30 min | Lo que separa «el incidente sigue» de «el incidente acabó y esto es nuevo». Absorber tras media hora de silencio une dos cosas separadas por media hora, que en un ataque es una eternidad |
| `MAX_ALERTAS_POR_CASO` | 10 000 | **No es una cota de memoria.** Un caso con más alertas ya no se puede revisar, y seguir metiendo dentro sólo hace que el siguiente hecho se pierda ahí |

### El motivo se guarda por alerta, no por caso

Cuando un analista pregunta por qué hay trescientas alertas juntas, la respuesta
útil no es «por campaña»: es «ésta por sujeto, estas doscientas por campaña, y
ésta por técnica». Sin ese detalle, una fusión equivocada **no se puede ni
discutir**.

### Lo que el fusionador no puede hacer, y no intenta

Ésta es la conclusión menos obvia de la fase, y sale de la jornada que corre en
la puerta de calidad.

Una regla ruidosa que salta 180 veces en 90 máquinas en una hora produce **un
solo caso**, igual que una campaña real. Y está bien que así sea: el fusionador
agrupa por **forma**, y la forma de las dos cosas es idéntica. No hay señal en el
tráfico que las separe.

Lo que las separa es el **veredicto**, y el veredicto no existe hasta que alguien
mira. Por eso la herramienta contra el ruido no es el fusionador —que no puede
saberlo— sino la métrica de ruido por regla, que lo sabe después y con base
suficiente. El efecto práctico que sí da el fusionador es el que importa: la cola
del analista recibe **3 casos en vez de 1 061**.

### El sellado

Un caso cerrado deja de absorber. Sin eso, una alerta que llega después del
cierre se cuela en un caso ya archivado y **cambia su contenido** — con el rastro
de auditoría diciendo que nadie lo tocó.

---

## 3 · La cronología: el hueco se dice, no se rellena

`Cronologia::construir` sólo come **datos que el sistema tiene**: alertas,
linaje de procesos y remediaciones registradas. Lo que escribe una persona entra
por `anotar` y queda marcado con `Origen::Analista`, porque «el sistema vio X» y
«el analista cree X» son afirmaciones de distinto valor y en una cronología plana
se leen igual.

Las líneas caen en **tres** clases, no en dos, y la tercera es la que se pierde:

1. **Evidencia** — `Sensor`, `Linaje`, `Remediacion`.
2. **Afirmación** — `Analista`.
3. **Hueco** — `Origen::Hueco`. El sistema **no pudo** observar ese tramo.

Un informe que mezcla las dos primeras atribuye a la evidencia lo que era una
hipótesis. Uno que omite la tercera presenta como completo algo con agujeros.

### Los dos huecos que el módulo sabe declarar

- **Padre no observado.** Un proceso cuyo padre existió pero no se llegó a ver.
  Unir los dos extremos produciría una cadena causal que no existió: el informe
  diría que A llevó a B cuando lo único que consta es que A ocurrió antes que B.
  Eso puede acabar en un juzgado.
- **Remediación ordenada y no confirmada.** `aplicada_ns: None` no es un dato que
  falte: es exactamente lo que hay que ver, porque significa que **la contención
  puede no haber ocurrido**.

### El orden es determinista

Se ordena por tiempo y se desempata por una `clave` estable. Dos ejecuciones
sobre los mismos datos producen la misma cronología, byte a byte — que es lo
mínimo exigible a algo que se adjunta a un informe.

### La cronología descubre observables

`observables_nuevos` devuelve lo que el linaje aportó y las alertas no traían: en
la jornada de la puerta, una ruta de fichero y una dirección. Son los que se
llevan a la búsqueda retroactiva.

---

## 4 · La auditoría: cuatro formas de romper una cadena, cuatro detectadas

Cada entrada lleva el resumen de la anterior. `Entrada::calcular` hace SHA-256
sobre **todos** los campos más `anterior`, de modo que tocar cualquier cosa
cambia el resumen y desengancha el resto.

| Manipulación | Qué devuelve `verificar` |
|---|---|
| Editar el detalle de una entrada | `ContenidoAlterado { secuencia }` |
| Desenganchar un eslabón | `EslabonRoto { secuencia }` |
| **Borrar** una entrada | `Hueco { esperada }` |
| Reescribir la cadena entera | `AnclajeRoto { hasta }` |

Las dos últimas son las que importan.

**Borrar es la manipulación más limpia**: no deja contenido alterado ni eslabón
roto si se reescribe lo que viene detrás. Lo único que la delata es el **número
de secuencia**, y por eso está en la entrada: sin él, una cadena a la que le
faltan tres entradas es indistinguible de una cadena corta.

**Reescribir la cadena entera sobrevive a toda comprobación interna**, porque
internamente **es** válida. La verificación sin anclaje devuelve la lista vacía —
y es correcto que lo haga. Lo único que la detecta es un valor que el sistema ya
no controla: el **anclaje publicado**, el resumen de la cabeza sacado por el canal
de atestación.

De ahí la frase que resume la garantía real, sin exagerarla:

> Todo lo anterior al último anclaje es **inmutable**. Todo lo posterior es
> **detectable**.

### `Consultado` es una acción del rastro

Quién **leyó** el caso también consta. En una investigación interna, quién miró
el caso antes de que pasara algo es un dato; y bajo un régimen de protección de
datos, el acceso a información personal se audita por obligación.

### La lista de acciones es cerrada

Doce variantes, ninguna de texto libre. Un rastro con acciones libres no se puede
consultar —«enséñame quién cerró casos este mes» deja de tener respuesta— y
además invita a meter ahí lo que no cabía en otro sitio.

---

## 5 · Las métricas: las dos decisiones que hacen que el número sirva

`Regla::ruido_centesimas` es `falsos_positivos * 100 / base`, y `base` **excluye
lo no concluyente**:

1. **Lo no concluyente no está en el denominador.** Un caso que nadie pudo
   resolver no dice nada sobre la regla. Meterlo abajo hace que una regla buena
   con casos difíciles parezca ruidosa, y apagarla es exactamente el error que
   deja un hueco de detección.
2. **Lo autorizado no es ruido.** La regla acertó: el hecho ocurrió y estaba
   permitido. Lo que hay que ajustar es la lista de excepciones, no la regla.

Y `MINIMO_PARA_JUZGAR = 20` casos concluyentes: apagar una regla porque sus dos
primeros casos fueron falsos positivos es la forma más rápida de quedarse sin
detección, y pasa.

### Los casos atascados van al lado de los percentiles

Un caso abierto **no está en la muestra**. Los percentiles sólo miden lo que ya
se cerró, así que un caso que lleva tres semanas abierto no aparece en ningún
tiempo hasta que se cierra. Es el sesgo clásico de estas métricas — y la única
corrección honesta es publicar la cuenta de atascados junto a ellas.

---

## 6 · Las plantillas: el orden de respuesta no es el mismo

`Orden` tiene tres valores y cada uno lleva su `motivo()` legible, porque una
plantilla que dice qué hacer sin decir por qué se salta en cuanto alguien tiene
prisa.

| Clase | Orden | El motivo |
|---|---|---|
| Ransomware | `ContenerPrimero` | Cada minuto son ficheros, y los ficheros cifrados no se descifran |
| Cuenta comprometida | `InvestigarPrimero` | Bloquear ahora le dice al atacante que se le ha visto, y cambiará al acceso de reserva que todavía no se ha encontrado |
| Movimiento lateral | `ContenerElOrigen` | Contener todo a la vez deja al atacante sin camino **y al defensor sin saber cuántas máquinas tenía** |

`clasificar` compara las técnicas de ATT&CK **por prefijo**: `T1059.001` y
`T1059` son la misma técnica con distinto grado de detalle, y exigir igualdad
exacta dejaría sin clasificar justo los casos mejor identificados. Con varias
técnicas gana la de más urgencia: un caso que es a la vez persistencia y
ransomware se atiende como ransomware, porque la persistencia se puede investigar
después.

**La plantilla propone, no ejecuta.** No crea ni cierra tareas sola. Una
plantilla que actúa es un automatismo, y un automatismo que contiene una máquina
sin que nadie lo pidiera es exactamente lo que un cliente no perdona.

---

## 7 · La persistencia: una sola transacción, y por qué

`ServicioCasos::anotar_en` escribe la entrada del rastro **en la misma
transacción** que el cambio que la produjo, y toma el caso con `SELECT … FOR
UPDATE`.

No es prudencia:

- **La transacción.** Escribir el rastro aparte crea un camino en el que el
  cambio se guarda y la entrada no. Cualquier fallo entre las dos deja un caso
  modificado sin constancia de quién lo modificó, que es justo lo que el rastro
  existe para impedir.
- **El bloqueo de fila.** La cadena se encadena con la cabeza anterior. Dos
  escrituras concurrentes leerían la misma cabeza y producirían dos entradas con
  el mismo número de secuencia — una cadena rota por concurrencia, no por
  manipulación, e indistinguible de una manipulación.
- **El índice único sobre el resumen** en la migración 0008 es la segunda red,
  por si alguien escribe alguna vez por otro camino.

### Las diez rutas

| Método | Ruta | Qué hace |
|---|---|---|
| `GET` | `/api/casos` | Lista con filtros |
| `GET` | `/api/casos/{id}` | Un caso, y **anota `Consultado`** |
| `POST` | `/api/casos/{id}/estado` | Transición validada; `409` si es inválida |
| `POST` | `/api/casos/{id}/cerrar` | Cierre con veredicto; `409` sin justificación con tareas abiertas |
| `POST` | `/api/casos/{id}/tareas` | Crea tarea |
| `POST` | `/api/casos/{id}/tareas/{tarea}/cerrar` | Cierra tarea |
| `GET` | `/api/casos/{id}/auditoria` | El rastro completo |
| `GET` | `/api/casos/{id}/auditoria/verificar` | Verificación, con las roturas si las hay |
| `POST` | `/api/casos/{id}/auditoria/anclar` | Publica un anclaje |
| `GET` | `/api/soc/metricas` | Percentiles, veredictos, ruido por regla y atascados |

Las transiciones inválidas devuelven **409 Conflict** con el motivo legible que
produjo el modelo, no un 400 genérico: el cliente necesita distinguir «lo que
mandaste está mal escrito» de «lo que mandaste no se puede hacer ahora».

### La migración 0008

Añade `casos`, `caso_alertas`, `caso_observables`, `caso_tareas`,
`caso_auditoria` (con índice único sobre el resumen) y `caso_anclas`. **No altera
ninguna tabla existente.**

Tres restricciones hacen cumplir en la base de datos lo que el modelo ya exige en
Rust, porque una regla que sólo vive en el código deja de valer el día que
alguien escribe un `INSERT` a mano:

- `CHECK (estado <> 'cerrado' OR veredicto IS NOT NULL)` — la fila que rompe
  todas las métricas del SOC no puede existir.
- `CHECK (length(trim(actor)) > 0)` — una entrada sin actor no es auditoría, es un
  registro de sucesos.
- `UNIQUE (resumen)` — dos entradas con el mismo resumen significarían que la
  cadena se bifurcó, y eso sólo pasa si alguien la manipuló.

### Y una decisión sobre el borrado que conviene explicar

`caso_alertas`, `caso_observables` y `caso_tareas` son **contenido** del caso:
`ON DELETE CASCADE`, si el caso se va se van con él.

`caso_auditoria` y `caso_anclas` son **`ON DELETE RESTRICT`**. No son contenido:
son la constancia de quién hizo qué. Con `CASCADE`, un `DELETE FROM casos` se
llevaría por delante —en silencio y como efecto secundario— la prueba de la única
operación que más evidentemente hay que auditar, que es destruir el caso. Y no
hace falta mala fe: basta una purga de retención escrita sin pensar en esto.

Con `RESTRICT`, y dado que todo caso nace con su entrada `creado`, en la práctica
**un caso no se borra: se cierra**. Si algún día hay que purgar de verdad —una
baja de inquilino, un derecho de supresión— hay que borrar el rastro
explícitamente primero, que es exactamente la propiedad que se busca: destruir
una cadena de custodia tiene que ser un **acto deliberado**, nunca la
consecuencia de otra cosa.

---

## Contratos existentes: qué se conserva y qué cambia

**No cambia nada de lo anterior.** `aegis-case` es un crate nuevo de funciones
puras; `aegis-server` lo usa, no al revés.

**Se reutiliza en vez de duplicarse:**

- La escala de **severidad** es la misma del resto del producto. Dos escalas es
  la forma de que un panel diga «alta» donde otro dice «media».
- Los **observables** usan los mismos tipos que la caza retroactiva, de modo que
  un observable de un caso se busca sin traducirlo.
- La **taxonomía de ATT&CK** es la que ya emplean detección y `aegis-predict`.

---

## Por qué ningún módulo de este crate hace entrada/salida

Todos son funciones puras sobre estado explícito: sin reloj, sin red y sin disco
—el tiempo entra siempre como argumento—. Es la misma decisión que en
`aegis-scale`, y da lo mismo: **mil sesenta y una alertas y cuatro
manipulaciones de un rastro se prueban en milisegundos**, que es la única forma de
tener estas propiedades en la puerta de calidad en vez de en un documento que
nadie vuelve a reproducir.

---

## Lo que mide la jornada de la puerta de calidad

`cargo run -p aegis-case --example jornada` recorre un día entero y **falla con
código distinto de cero** si alguna propiedad se rompe. Las cifras son
deterministas y se comprueban, no se imprimen:

| Cifra | Valor | Qué protege |
|---|---|---|
| Alertas admitidas | 1 061 | La cola del analista recibe **3 casos** |
| Alertas de la campaña en un caso | 880 | Fusionar de menos ahoga la cola |
| Caso de movimiento lateral | 1 alerta, caso propio | Fusionar de más **pierde el incidente** |
| Líneas de cronología | 8 evidencia · 1 afirmada · 2 huecos | Ninguna línea sin procedencia |
| Roturas detectadas | 4 de 4 | Incluida la reescritura completa, que sólo el anclaje ve |
| Detección p50 | 9 min | El triaje inyectado, no la cola |
| Respuesta p50 | 25 min sobre 165 min de reloj | La espera externa se descuenta |
| Cierre p50 | 14 min | Toda muestra es un caso cerrado |
| Ruido de la regla ruidosa | 95 % sobre 180 concluyentes | Sale sola, con base suficiente |
| Casos atascados | 1 | El caso vivo no entra en ningún percentil |

---

## El muro, declarado

La puerta de calidad de esta fase **no escribe en PostgreSQL**. La persistencia
real vive en `aegis-server` —migración 0008, `casos.rs`, las diez rutas— y sus
pruebas de integración corren en «Servidor · tests» cuando hay base de datos
(`AEGIS_TEST_PG_URL`).

Y hay una segunda cosa que este módulo **no** hace, y conviene decirla: el
anclaje se publica, pero **sacarlo del sistema es responsabilidad del canal de
atestación**, no de este crate. Un anclaje que se queda en la misma base de datos
que el rastro no protege de nada, porque quien puede reescribir el rastro puede
reescribir el anclaje. La garantía empieza cuando el valor sale a un sitio que el
operador del sistema no controla.

[`modelo`]: ../server/crates/aegis-case/src/modelo.rs
[`fusion`]: ../server/crates/aegis-case/src/fusion.rs
[`cronologia`]: ../server/crates/aegis-case/src/cronologia.rs
[`auditoria`]: ../server/crates/aegis-case/src/auditoria.rs
[`metricas`]: ../server/crates/aegis-case/src/metricas.rs
[`plantillas`]: ../server/crates/aegis-case/src/plantillas.rs
