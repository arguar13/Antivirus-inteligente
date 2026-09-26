# AegisFlow — automatización de respuesta con frenos

**FASE 97.** Crate nuevo `server/crates/aegis-flujo`; migración
`server/migrations/0009_flujos.sql`. Puerta: `tools/verificar-flujo.sh` (grupo
`flujo` de `tools/ci-local.sh`). Invariante nueva: la **15**, «una automatización
sin freno es un arma».

## La pregunta

Shuffle, StackStorm y los SOAR abiertos ejecutan flujos con integraciones: la
salida de un paso es un documento JSON, la entrada del siguiente una plantilla
(`$paso.campo`), y lo que pasa si el flujo falla a medias es que queda a medias.
Un SOAR que puede aislar mil máquinas por un error de plantilla es un arma
apuntando al cliente. La pregunta de esta fase no es «¿cuántas integraciones?»,
sino **qué garantías da un flujo antes, durante y después de tocar la flota**.

## El inventario de partida

| Pieza | Qué había | Qué faltaba |
|---|---|---|
| `aegis-predict` (FASE 69) | los cinco frenos, dentro de `decidir`, sobre un camino del grafo | aplicarlos a un **paso** con sus objetivos, y a cada paso |
| `aegis-orchestrator` + `remediacion.rs` (FASE 64) | un *playbook* fijo de cuatro acciones, con reintento de lo fallido | reversión: **ninguna acción del servidor sabía deshacerse** |
| tabla `comandos` | la cola de órdenes al agente (`aislar`, `liberar`) que usa la consola | nada |
| tabla `cuarentena` (FASE 44) | la cuarentena de red de enjambre, que se levanta marcando | nada |
| `casos` + `caso_auditoria` (FASE 76) | casos con rastro encadenado | nada |
| cuentas de directorio | revocar tickets como orden al agente | **deshabilitar una cuenta no existía**, ni un sitio donde preguntar si ya lo estaba |
| notificaciones | — | todo |

## Las cinco garantías, y dónde está cada una

### 1. El flujo es un grafo acíclico tipado: el mal tipado no compila

`Flujo::nuevo` da el nodo de entrada con su tipo; `Flujo::paso(paso, desde,
permiso)` exige que `desde` sea un `Nodo<P::Entrada>`. Las entidades llevan su
clase en el tipo (`Objetivo<Proceso>`, `Objetivo<Fichero>`, `Objetivo<Cuenta>`…),
y un paso que consume un proceso enganchado a uno que produce un fichero es un
error de compilación:

```
error[E0308]: mismatched types
   |     f.paso(SoloProcesos, fichero, SinFirma);
   |                          ^^^^^^^ expected `Nodo<Ref<Proceso>>`, found `Nodo<Ref<Fichero>>`
```

El grafo es acíclico **por construcción**: `Nodo` no tiene constructor público y
solo lo devuelven `nuevo` y `paso`, así que un paso solo puede engancharse a un
nodo que ya existe. El orden de inserción es, por eso mismo, un orden topológico.

`Objetivo<T>` junta identidad y localización y **deriva** la primera de la
segunda con las funciones del modelo único (FASE 79): no existe un objetivo cuya
identidad diga «el proceso 4242 de srv-1» y cuya localización apunte al 4243 de
srv-2, que es exactamente el error de plantilla que convierte una respuesta en un
incidente. Y un proceso se localiza por máquina, arranque, pid **e instante de
arranque**: «matar el pid 4242» mataría a quien tenga ese pid cuando llegue la
orden.

### 2. Cada paso declara su reversión: sin ella no compila

`Paso::revertir` no tiene cuerpo por defecto (`error[E0046]: not all trait items
implemented, missing: revertir`). Si el flujo falla a medias —un paso falla, un
freno lo detiene o su firma no cubre sus objetivos—, lo hecho se revierte **en
orden inverso**.

Revertir es **volver al estado de antes**, no «hacer lo contrario». Cada paso
guarda en su `Deshacer` cómo estaba lo que toca, leído en la **misma transacción**
que lo cambia y con la fila bloqueada (`FOR UPDATE`):

| paso | reversión |
|---|---|
| aislar | si la máquina ya estaba aislada por otra persona, nada; si no: la orden se **retira** si el agente aún no la recogió (nunca la verá) o se le manda `liberar` si ya la recogió |
| cuarentena de fichero | igual: se retira, o `restaurar_fichero` |
| deshabilitar cuenta | rehabilitar **marcando** quién y cuándo, salvo que ya estuviera deshabilitada |
| bloquear indicador | la fila de la cuarentena de red vuelve a ser **exactamente** la de antes, microsegundos incluidos; si ya estaba vigente por otra orden, no se toca |
| abrir caso | un caso no se borra —su rastro lo impide, a propósito—: se cierra como **no concluyente** diciendo que el flujo que lo abrió se revirtió, con su entrada en el rastro |
| notificar | es una **compensación** y se dice: si no salió, se anula; si ya salió, se envía una rectificación que la referencia |
| matar, revocar tickets | **irreversibles**: el motor no finge deshacerlos. Se cuentan y el flujo termina `RevertidoConFallos` con ellos como pendientes para una persona |

### 3. Idempotencia

Dentro de una ejecución, el mismo paso con la misma clave no se repite: el segundo
nodo toma la salida del primero. Entre reintentos, cada efecto lleva un
identificador **derivado** de la ejecución, el paso y la clave (UUID v8 sobre
SHA-256), y la base de datos rechaza el duplicado: reintentar la misma ejecución
no encola dos veces la orden de aislar, no abre dos casos, no manda dos avisos.
El paso `tomar` (la proyección que ramifica el grafo) usa como clave su etiqueta
**y el SHA-256 de su entrada**, para que dos tomas sobre entradas distintas no se
confundan.

### 4. La aprobación humana es un tipo

Un paso de alto impacto declara `type Permiso = Firma`. `Firma` no tiene campos
públicos ni valor por defecto (`error[E0451]` al fabricarla a mano): solo existe
si `Firma::verificar` comprobó una firma **híbrida** (Ed25519 + ML-DSA, la del
resto del producto) de una persona sobre la **huella de esa ejecución**: el flujo,
el paso y sus objetivos exactos, con contexto de dominio propio. El motor
recalcula la huella con los objetivos reales antes de ejecutar: una firma para
aislar `srv-0005` no aísla `srv-0006`. Y un paso **irreversible** con un permiso
que no es firma no compila:

```
error[E0080]: evaluation panicked: un paso irreversible exige una Firma humana como permiso
```

### 5. Los cinco frenos de la FASE 69, en cada paso que toca la flota

`CincoFrenos` usa **las mismas piezas** que `aegis_predict::decidir`
(`ConfigContencion`, `FLOTA_MINIMA_PARA_FRACCION`, `Evidencia::solida`), en el
mismo orden: probabilidad, radio, protegidos, evidencia, mínimo y reversible. Dos
decisiones de diseño que no estaban en el enunciado y que el autoataque justifica:

- **El radio es el acumulado de la ejecución**, no el del paso. Frenar «por paso»
  no puede significar que mil pasos de radio uno sumen un radio de uno.
- **Los objetivos de un paso son su radio real**. Bloquear una red corta a todas
  las máquinas de la flota que viven dentro; su objetivo no es «la red», son esas
  máquinas, resueltas contra `agentes.direccion_vista`.
- Si un paso toca un activo protegido y su efecto no se puede separar de él
  (bloquear la subred del controlador de dominio), se **detiene** con
  `ProtegidosEnElRadio`; no se ejecuta «sin el protegido», porque no existe esa
  forma de ejecutarlo.

## AUTOATAQUE: la automatización como arma

`tests/autoataque.rs`, contra una flota de **1000 máquinas** más el controlador de
dominio protegido, en el esquema real del plano de control:

| ataque | resultado |
|---|---|
| aislar la flota entera en un paso, **con firma** | `Escalado` · radio 1000, tope 25 — la firma dice que alguien lo aprobó, no que el radio sea razonable |
| la misma intención expandida en 1000 pasos de una máquina, cada uno firmado | `Escalado` en el paso 26 (radio acumulado 26, tope 25); los 25 anteriores **revertidos** |
| bloquear `0.0.0.0/0` donde iba una dirección | `Escalado` · radio 1001 |
| bloquear `10.20.1.248/29`, la red del controlador de dominio (4 máquinas) | `Escalado` · `ProtegidosEnElRadio { preservados: 1 }` |
| **control**: aislar una máquina, firmado | `Completado` |

Después de cada ataque se comprueba **la base de datos**: cero máquinas aisladas,
cero órdenes encoladas, cero redes bloqueadas. La prueba entera tarda unos 13 s,
casi todo en firmar las mil aprobaciones híbridas.

## Contra el estado real

`tests/pg.rs` migra en un esquema propio **las mismas migraciones** que aplica
`aegis-server` al arrancar y ejecuta el flujo de contención de un incidente
(aislar la máquina, deshabilitar la cuenta, bloquear la red, abrir un caso, poner
el fichero en cuarentena, avisar a la guardia):

- **completo, y su reintento**: todo aplicado; el rastro del caso verifica al
  releerlo de disco; el reintento de la misma ejecución no duplica ni una fila.
- **a medias** (la cuarentena, quinto paso con efecto, falla): máquina liberada y
  orden retirada, cuenta rehabilitada con quién y cuándo, la red **exactamente**
  como estaba (una cuarentena levantada por otra persona en marzo, con sus
  microsegundos), caso cerrado «no concluyente» con sus dos entradas de rastro
  intactas.
- **lo ajeno no se toca**: una máquina, una cuenta y una red que otra persona ya
  había contenido siguen contenidas después de revertir.
- **orden ya recogida**: si el agente ya había recogido `aislar`, revertir le
  manda `liberar`.
- **firma de otra máquina**: nada aislado, nada encolado.
- **enriquecer** lee solo lo de dentro (alertas y objetos de inteligencia de la
  instancia) y no acepta un «hash» que sea un patrón `LIKE`.

## Comparativa con Shuffle

**No está medida ejecutándolo**, y se declara: Shuffle se despliega con Docker
(«Shuffle is based on Docker and is started using docker-compose», su guía de
configuración) y esta máquina no tiene Docker. La comparativa es **por
propiedades**, cada una citada de su documentación (`Shuffle/shuffle-docs`,
`docs/workflows.md`, `docs/triggers.md`, `docs/configuration.md`):

| garantía | Shuffle (según su documentación) | AegisFlow |
|---|---|---|
| paso de datos entre acciones | plantillas `$nodo.campo`; «if a node doesn't exist or the key is missing, Shuffle writes the expression as-is» | tipos: un fichero donde iba un proceso **no compila** |
| validación al guardar | no documentada | el compilador |
| reversión si falla a medias | no documentada: las condiciones «skip» ramas; los estados son terminado, fallido o abortado | obligatoria por tipo, en orden inverso, al estado de **antes** |
| lo irreversible | no se distingue | declarado en el tipo; exige firma; se escala, no se finge deshacer |
| reintento | «re-execute with the same argument», «mass-rerun»; deduplicación como patrón manual con el *Datastore* | claves derivadas de la ejecución: el reintento no duplica |
| aprobación humana | *User Input*: un clic en «proceed» o «abort», por enlace | firma híbrida sobre **esa** ejecución (flujo, paso, objetivos) |
| límite de radio | no documentado; solo concurrencia (`SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY`) y tiempo | los cinco frenos, con radio **acumulado**, en cada paso |

Pasos equivalentes: aislar, matar, cuarentena, revocar tickets, deshabilitar
cuenta, bloquear indicador, abrir caso, enriquecer y notificar existen en los dos
lados (en Shuffle, como acciones de sus *apps* de EDR, directorio, cortafuegos y
casos). La diferencia no está en la lista, está en la tabla de arriba.

## El muro, declarado

- La comparativa con Shuffle es por propiedades, no medida (arriba).
- Las órdenes a los agentes (`aislar`, `liberar`, `matar_proceso`,
  `cuarentena_fichero`, `restaurar_fichero`) y al directorio (`deshabilitar`,
  `rehabilitar`, `revocar_tickets`) se **encolan** en las tablas reales; aplicarlas
  es del agente y del conector del directorio. Lo que esta fase garantiza es qué
  se ordena, con qué permiso y cómo se deshace.
- Una notificación que ya salió no se «des-lee»: su reversión es una
  rectificación, y así está escrito en el tipo y en la tabla.
