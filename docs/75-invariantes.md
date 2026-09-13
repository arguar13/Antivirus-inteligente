# 75 · AegisProof — las trece invariantes, demostradas sobre el producto completo

> FASE 80. `tools/verificar-invariantes.sh`, `tools/lineabase-agente.txt`,
> `tools/lineabase-unsafe.txt`, `server/crates/aegis-tejido/tests/autonomia.rs`.

## Por qué esta puerta existe aparte de las otras veintisiete

Cada `tools/verificar-<fase>.sh` comprueba lo suyo, y lo comprueba mejor que ésta.
Lo que **ninguna** puede comprobar es lo que se rompe al **sumar**:

- que el agente siga cabiendo en su presupuesto **con todas las capacidades
  encendidas a la vez** —cada fase midió la suya, ninguna midió el total—,
- que ningún crate de análisis haya ganado un `unsafe` por el camino,
- que el árbol de dependencias del endpoint no haya engordado sin que nadie lo
  justifique por escrito,
- y que el producto **entero** —no sólo el enjambre— siga protegiendo con el plano
  de control caído.

Y tiene **derecho de veto**. Si una invariante se rompió, se arregla *de raíz*
antes de dar el trabajo por terminado, aunque obligue a volver sobre una fase
anterior. Una invariante que se relaja «sólo esta vez» deja de ser una invariante
y pasa a ser una aspiración.

## Las trece

Ocho estructurales, una de autoataque con sus siete pruebas, y cuatro doctrinales
que el producto ya sostenía y que aquí se comprueban mecánicamente en vez de
afirmarse.

| # | Invariante | Cómo se comprueba |
|---:|---|---|
| 1 | **Presupuesto** | El agente arranca de verdad y se mide su RSS contra el reparto de su perfil y contra la línea base; y el kernel lo impone desde fuera (`MemoryHigh` 321 MiB, `MemoryMax` 482 MiB) |
| 2 | **Seguridad de memoria** | Todo crate del agente **o** declara `#![forbid(unsafe_code)]` **o** está en `tools/lineabase-unsafe.txt` con su razón escrita — hoy **32 y 22** |
| 3 | **Árbol de dependencias** | Las **39** dependencias directas del agente están en `tools/lineabase-agente.txt` con su justificación |
| 4 | **Determinismo** | El circuito completo repetido: mismo veredicto, mismo caso, misma propuesta de contención |
| 5 | **Explicabilidad** | Se recorren **todas** las combinaciones del árbitro exigiendo frase no vacía |
| 6 | **Tri-estado** | Los **siete** enumerados de veredicto tienen su variante de duda, y las pruebas que la ejercen pasan |
| 7 | **Autonomía** | `tests/autonomia.rs`: **7** pruebas con el enlace cortado de verdad, y el producto entero sigue dando veredicto |
| 8 | **Los cinco frenos** | Las pruebas de contención de `aegis-predict`, y otra vez sobre el grafo del circuito completo |
| 9 | **Autoataque** | Siete capacidades usadas **contra** el producto, con **205** pruebas |
| 10 | **Doctrina del enjambre** | La carga tiene dos variantes y **ninguna es una orden** |
| 11 | **Un solo estrangulamiento** | Los cuatro canales de salida pasan por el mismo juez |
| 12 | **La ausencia es la frontera** | Tres enumerados **sin** su variante peligrosa |
| 13 | **El identificador único** | Once subsistemas, un identificador (FASE 79) |

## 1 · Presupuesto: por qué no son 46 080 KB

El enunciado de la fase pedía un número fijo: 46 080 KB de RSS del agente. Se
sustituyó a propósito, y conviene decir por qué en voz alta.

Un número fijo para todo host obliga a elegir entre **ahogar** una pasarela de
1 GiB y **desaprovechar** un servidor de 512 GiB, y este producto corre en los
dos. El modelo real está en `aegis-presupuesto`: una fracción de la RAM del host
—0,5 % en reposo, 2 % en pico, 3 % de techo duro— con suelos y techos absolutos,
tres perfiles por clase de máquina y tres regímenes de degradación.

Lo que **no escala**, y por eso sigue siendo una regresión dura, es la huella de
**arranque**: `LINEA_BASE_ARRANQUE = 32 MiB`. Si el agente arranca ocupando más
que eso ha engordado, quepa o no quepa en el host que tenga delante — y esa cifra
está medida, no estimada.

Y las dos capas de dentro las ejecuta un proceso que puede estar comprometido o
sencillamente tener un bug: la tercera la ejecuta **el kernel**, con `MemoryHigh`
y `MemoryMax` de cgroup v2 en el drop-in de systemd.

## 2 · Seguridad de memoria: «cero unsafe» sería mentira

«Ningún crate de análisis ha ganado un `unsafe`» es la invariante. La forma
honesta de comprobarla no es contar bloques, porque **hay código del agente cuyo
trabajo es hablar con el kernel** —`ioctl`, `mmap`, mapas de eBPF, memoria
compartida, memoria ajena— y prohibírselo no haría el producto más seguro: lo
haría imposible.

La invariante útil es ésta, y no admite tercera opción:

> Todo crate del agente **o** declara `#![forbid(unsafe_code)]` —y entonces lo
> impone el compilador— **o** está en `tools/lineabase-unsafe.txt` con su razón
> escrita.

Un lado lo impone el compilador; el otro, la revisión. Un crate que se cuele sin
ninguna de las dos cosas hace fallar la puerta.

Dónde importa de verdad: en lo que **mira entrada que escribe un atacante**
—paquetes, ficheros, reglas de terceros, mensajes del enjambre, registros ajenos—
un `unsafe` no es una decisión de rendimiento. Es poner una vulnerabilidad de
corrupción de memoria en el camino por el que entra lo hostil, en un proceso
privilegiado, en cien mil máquinas.

La línea base también funciona al revés: si un crate declarado deja de necesitar
`unsafe`, la puerta lo dice y pide que se le ponga el `forbid`. Una lista de
excepciones que sólo crece deja de ser una lista de excepciones.

## 3 · Árbol de dependencias: la fila se escribe antes que el código

El árbol del agente **no es una lista de bibliotecas**: es la superficie de ataque
de la cadena de suministro del endpoint. Cada crate que entra es código de un
tercero que acabará ejecutándose con privilegios en cien mil sitios.

De ahí la regla: **un crate nuevo en el agente necesita una justificación
escrita**, y la fila se añade *antes* que la dependencia, no después. Cuando la
puerta falla porque falta una fila, la respuesta correcta casi nunca es escribir
la fila: es preguntarse si ese crate tiene que entrar en el endpoint o puede vivir
en el servidor — como se hizo con **libp2p** en la FASE 68, cuyos 340 crates y
runtime asíncrono viven en un workspace aparte precisamente por esto.

El servidor no lleva línea base equivalente, y es deliberado: allí el criterio es
otro (tokio, axum, sqlx y su árbol completo), y mezclarlos convertiría esta lista
en ruido. Que los dos workspaces estén separados es lo que hace **posible**
auditar éste.

## 7 · Autonomía no es permisividad

Cortar la salida a Internet es lo **primero** que hace un atacante que sabe lo que
tiene delante. El estado «sin plano de control» no es un fallo del que
recuperarse: es el estado en el que hay que detectar.

La FASE 68 ya probaba que el enjambre habla durante el corte. Lo que esta
invariante añade es que el **resto** del producto sigue funcionando: el corpus
local reconoce el fichero, el árbitro decide —es una función pura, no consulta a
nadie—, el enriquecimiento degrada **diciéndolo** (`sin-datos`, nunca «limpio»), y
la flota se corrobora entre pares.

Y la prueba que más dice del fichero es la que cierra la puerta contraria:

> **`autonomia_no_significa_bajar_el_liston`.** Un agente aislado que aceptara
> órdenes sin firma sería peor que uno que no detecta nada, porque el atacante
> **crea** el aislamiento y luego manda. El corte no afloja ni una comprobación:
> una orden con firma inventada se descarta, y las tres que **no viajan nunca**
> —levantar un aislamiento, desactivar una regla, degradar la protección— se
> descartan *por su clase*, porque reproducidas durante el corte apagan la defensa
> con una firma auténtica.

## 9 · Autoataque: cada capacidad, usada contra el producto

Cada capacidad que se añade a un producto de seguridad es una capacidad nueva
**para quien lo comprometa**. El disector que lee todo el tráfico es un
amplificador; el IPS que corta flujos es un botón de denegación de servicio; el
compilador de reglas ejecuta lo que escriben terceros.

La prueba no es que el producto «aguante»: es que el intento **falle donde se
intenta**, y que el intento esté escrito.

| Ataque | Qué se intenta | Dónde falla |
|---|---|---|
| El disector como amplificador | 100 000 flujos × 2 sentidos × 1 MiB = 200 GB contra una cuota de red de 12 MiB | Dos techos **globales**: una cota por flujo no es una cota, porque el atacante elige también el número de flujos |
| El IPS como denegación de servicio | Hacer que el motor corte media red | Tope con degradación automática, **pegajosa** y con ventana deslizante: si el motor bloquea media red, el motor está mal, no la red |
| El compilador de reglas como vía de ejecución | Una regex con retroceso catastrófico que corre en el endpoint por cada paquete | Se rechaza analizando la **estructura**, no cronometrando: el caso malo es una cadena concreta y encontrarla es el problema que se intenta evitar |
| La detonación como fuga del invitado | Conectar a `1.1.1.1` desde dentro de la microVM | La salida **no tiene variante** para red real: no se declara, se comprueba |
| La ingesta como agotamiento de memoria | Un emisor más rápido que el receptor, un objeto de tamaño absurdo, cien mil elementos | Contrapresión con histéresis y **dos cubos de cuota** por inquilino: con uno, el atacante genera ruido en cualquier aplicación del cliente y sus propias huellas dejan de subir |
| El enriquecimiento como fuga de datos | Sacar cuentas, rutas, líneas de órdenes o direcciones internas a un tercero | La salida es una **capacidad que se entrega**, no una bandera que se comprueba; con el modo sin salida el objeto no existe |
| La federación como envenenamiento | Tres semanas de indicadores fabricados por un canal comprometido | La confianza **se calcula, no se guarda**, y dos canales que repiten al mismo son **una** fuente |

## 12 · La ausencia es la frontera

Es la única clase de garantía que **no depende de que el código de comprobación
esté bien**: si la variante no existe, no hay configuración, error ni atacante que
la produzca. Por eso se verifica por lo que **falta**:

- `aegis_detonate::frontera::Salida` no tiene variante para «red de verdad».
- `aegis_share::puente::Carga` no tiene variante `Orden`.
- `aegis_invitado::protocolo::Evento` no tiene ni una variante que sea una orden,
  de modo que el anfitrión no valida nada porque no hay nada que ejecutar.

## La tabla de honestidad consolidada

Lo que se verifica de verdad en cada `make ci`, y lo que queda declarado como
muro. Un muro declarado no es una deuda escondida: es la diferencia entre «esto no
se comprueba aquí, y por esta razón» y el silencio.

| Puerta | Se ejerce de verdad | Muro declarado |
|---|---|---|
| `verificar-wire.sh` | Reensamblado TCP contra evasión por solape, paquetes byte a byte, dos techos globales bajo el ataque que los busca | — |
| `verificar-ips.sh` | Los dos programas eBPF pasan el **verificador real del kernel**; el corte se escribe a mano en el mapa y el kernel no lo aplica | — |
| `verificar-ruleforge.sh` | Los cuatro formatos del corpus mundial, el canario sobre binarios reales de `/bin`, la época monótona | Sin red no se descargan feeds reales |
| `verificar-detonate.sh` | El canal del invitado, los topes, los huecos de secuencia, el catálogo anti-anti-VM | **Sin `/dev/kvm` no se arranca ninguna máquina virtual aquí** |
| `verificar-ingest.sh` | Rotación, `copytruncate`, ancla, deduplicación exacta, dos cubos por inquilino | Este contenedor no tiene diario de systemd ni log en `/var/log` |
| `verificar-scale.sh` | 100 000 agentes, 400 000 eventos, p50 13 µs, cero pérdida silenciosa | **Sin PostgreSQL no se ejercita la escritura a escala** |
| `verificar-case.sh` | La jornada completa del SOC: 1 061 alertas → 3 casos, cuatro tipos de manipulación detectados | **Sin PostgreSQL no se ejercita la persistencia del caso** |
| `verificar-enrich.sh` | El modo sin salida, la cuota reservada, la fusión que no promedia, el analizador colgado | **Sin claves no se habla con ningún proveedor real** |
| `verificar-share.sh` | Servidor **y** cliente TAXII de verdad hablando entre ellos, 3 082 entradas hostiles, la federación completa | **Sin servidor externo no se habla con ninguna comunidad** |
| `verificar-fabric.sh` | El circuito de once subsistemas con el código real de cada uno, el inventario, la ruta caliente | El circuito no arranca hipervisor ni abre sockets: **cada subsistema ya ejerce eso en su propia puerta** |
| `verificar-swarm.sh` | El núcleo *sans-io* completo y **dos nodos libp2p reales** | — |
| `verificar-predict.sh` | Dijkstra sobre `−log p`, percolación Monte Carlo con su margen, los cinco frenos | — |
| `verificar-memhunter.sh` | Las dos técnicas construidas contra el kernel real en cada `make ci` | Los VAD de Windows quedan gated, con su ABI verificada en compilación |
| `verificar-l7hunter.sh` | Los 9 programas eBPF pasan el verificador real; ABI cotejada C↔Rust con dos compiladores | El enganche en un proceso vivo queda gated |
| `verificar-fwaudit.sh` | Las tablas ACPI reales de la máquina; `write`/`pwrite`/`ftruncate` → `EBADF` ejercido contra el kernel | Leer la ROM SPI queda declarado no aplicable donde el kernel no expone la flash |
| `verificar-ptguard.sh` | El núcleo del decodificador de trazas | **Captura en vivo no ejercida: VM sin Intel PT** |
| `verificar-honeytoken.sh` | Los tokens, su atribución y su detección | La inyección en memoria ajena queda gated |
| `verificar-vmi.sh` | El recorrido de EPT, el parser del kernel desde memoria física | Arrancar el hipervisor necesita VT-x/AMD-V |
| `verificar-presupuesto.sh` | El agente arranca de verdad y se mide su RSS; el drop-in impone los dos límites | Se omite si el agente no arranca en este entorno, **diciéndolo** |
| `verificar-invariantes.sh` | Las trece, sobre el producto completo | — |

## Lo que esta fase encontró

Una fase cuyo trabajo es comprobar invariantes sobre el producto entero encuentra
cosas que ninguna fase encuentra sobre lo suyo.

**Diecinueve crates del agente no tenían `unsafe` y tampoco lo prohibían.** Entre
ellos, crates de análisis puro que miran entrada hostil: `aegis-parser`,
`aegis-scan`, `aegis-ml`, `aegis-behavior`, `aegis-l7hunter`, `aegis-evasion`. No
era un fallo con síntoma —no había ningún `unsafe` que quitar—: era un hueco por
el que uno podía entrar en silencio el día que alguien optimizara un bucle. Ahora
lo impone el compilador.

---

← Volver al [README](../README.md)
