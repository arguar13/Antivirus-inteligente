# 77 · AegisArtifact — la evidencia que se puede sostener

> FASE 82. `crates/aegis-custodia/`, `crates/aegis-scal/src/linux/reloj.rs`,
> `tools/verificar-custodia.sh`.

## El problema, dicho sin adornos

`aegis-forensics` ya recoge lo que hay que recoger antes de que desaparezca: el
árbol de procesos, los sockets, los hashes, la memoria. Lo que produce es
correcto, y basta para **investigar**.

No basta para **sostener**. En cuanto alguien discute la prueba —el cliente, su
aseguradora, un regulador, un juez, o el propio analista seis meses después— las
preguntas que llegan no son sobre el contenido:

- ¿Cómo se sabe que estos bytes salieron de **esa** máquina?
- ¿Cómo se sabe que son **los mismos** que salieron, y no los que alguien puso
  después en el almacén?
- ¿**Quién** los ha tenido en las manos desde entonces, y consta lo que hizo?
- ¿La **hora** que dice el informe es la hora en que ocurrió?

Un fichero suelto, por auténtico que sea, no contesta ninguna. Y «confíe en
nuestro producto» es exactamente la respuesta que un forense no puede dar.

## Lo que hay ahora

| | Antes | Ahora |
|---|---|---|
| Procedencia de un artefacto | ninguna | **firmada**: caso, endpoint, agente, versión, motivo, técnicas |
| Integridad | ninguna | resumen **y** longitud, dentro de la firma |
| Quién lo tocó después | no consta | cadena encadenada por resumen, **seis clases de paso** |
| Marca de tiempo | un reloj, movible | **dos relojes**, y la contradicción se delata |
| Firma | — | **híbrida** Ed25519 + ML-DSA-65, las dos tienen que validar |
| Lo que la verificación no prueba | implícito | **cinco límites**, en la estructura de datos |
| Recogida de flota incompleta | «completada» | **no se declara completa**, y lo que falta se nombra |

## Las cuatro decisiones, y por qué cada una

### 1. No se firma JSON

La tentación es firmar `serde_json::to_vec(&estructura)` y acabar antes. No
funciona, y **falla tarde**: años después, cuando alguien intenta reverificar con
otra versión del binario y la firma no cuadra.

JSON no tiene forma canónica. El orden de las claves depende del tipo de mapa, el
escapado de caracteres no ASCII admite varias formas válidas, los flotantes se
imprimen distinto según la biblioteca, y un `Option` puede serializarse como
ausente o como `null`. Nada de eso cambia el *significado*; todo cambia los
*bytes*, que es lo único que ve una firma.

Los bytes los define `canon`, no una biblioteca de serialización:

- Cada campo lleva **su longitud delante**, en cuatro bytes. Sin ella, `("ab",
  "c")` y `("a", "bc")` producen el mismo flujo, y una firma sobre el primero
  vale para el segundo: se podría mover el límite entre dos campos de la
  evidencia sin invalidar nada.
- Los enteros van en anchura fija y *big-endian*; el orden lo fija el código, no
  un mapa; presente-y-vacío se distingue de ausente por un octeto, porque «el
  binario tenía hash vacío» y «el binario ya no estaba en disco» son dos hechos
  muy distintos.

Un **vector dorado** congela el formato en una prueba. Si alguien cambia el orden
de un campo, un prefijo o una etiqueta, toda la evidencia ya sellada dejaría de
verificar —para siempre y sin aviso—; con el vector, ese cambio rompe la
compilación hoy. El resumen del artefacto se coteja además contra `sha256sum`,
que es una implementación de fuera: el vector no se autovalida.

### 2. No se confía en un solo reloj

Una cronología forense se sostiene sobre marcas de tiempo, y la marca obvia —el
reloj de pared— es **la única que un atacante con root puede mover**:
`clock_settime` está a una llamada de distancia. Retrasarlo dos horas coloca la
actividad del atacante antes de la ventana que el analista mira; adelantarlo, la
coloca después. En los dos casos la evidencia sigue siendo auténtica y cuenta una
historia falsa. Firmar la marca no arregla nada: lo que se firma es el número que
el kernel devolvió, y ese número ya venía movido.

Por eso cada marca lleva también `CLOCK_BOOTTIME`, que **no se puede fijar** —no
hay llamada para ello— e incluye el tiempo suspendido. No sabe qué día es, pero
ordena hechos del mismo arranque con independencia del otro reloj. Cuando los dos
órdenes se contradicen, alguien movió el reloj entre los dos hechos: eso no es
una sospecha, es aritmética, y `saltos_de_reloj()` la reporta.

Se usa `BOOTTIME` y no `MONOTONIC` porque el segundo se para mientras la máquina
está suspendida: en un portátil que pasa la noche cerrado, dos hechos separados
por diez horas reales aparecerían separados por segundos y la cronología quedaría
comprimida sin que nada lo indicara.

**La llamada vive en `aegis-scal`**, que es donde el producto concentra el
`unsafe`. Añadir `aegis-custodia` a la línea base habría sido lo cómodo; el
propio fichero de línea base dice que lo correcto es lo contrario. El crate de
custodia declara `#![forbid(unsafe_code)]`.

### 3. La cadena va encadenada por resumen, no es una lista de firmas

Una lista de pasos, cada uno con su firma, **se puede podar**: quitar el eslabón
incómodo deja una lista más corta cuyos eslabones siguen verificando uno a uno.
Lo que hay que impedir no es alterar un eslabón —eso lo para la firma— sino
quitarlo, insertarlo o reordenarlo.

Cada eslabón lleva el resumen del anterior **dentro de lo que firma**. Quitar uno
deja al siguiente apuntando a algo que ya no está; insertar uno rompe el enganche
del que venía detrás; reordenarlos los rompe todos. Y el primero apunta a la
identidad del sello, no a un cero, así que una cadena legítima de otro artefacto
no se puede pegar a este.

**Una cadena vacía no es una cadena intacta.** No dice «nadie tocó esto», dice
«nadie anotó nada», y verificarla devuelve un error y no un aprobado.

### 4. No se devuelve un booleano

«Custodia verificada: SÍ» es una frase peligrosa, porque quien la lee entiende
más de lo que dice: que la evidencia es auténtica, que nadie la tocó, que la
máquina estaba limpia y que la cronología es correcta. La verificación
criptográfica no prueba ninguna de las cuatro enteras.

`Veredicto::no_demuestra` lleva la lista explícita, **en la estructura de datos y
no en una nota al pie**, para que quien redacte el informe tenga que pasar por
ella:

| Límite | Qué queda fuera |
|---|---|
| `ClaveNoEsPersona` | prueba que firmó esa clave, no que la tuviera quien debía |
| `NoCubreLoAnteriorALaRecogida` | si había un rootkit cuando el agente miró, la evidencia será auténtica y falsa |
| `ElFinalSePuedePodar` | un prefijo de una cadena válida también verifica |
| `LaCronologiaNoEsComprobable` | solo se lista cuando de verdad no se pudo contrastar |
| `NoDiceQueSeRecogieraTodo` | lo que el agente no pudo leer está en los huecos, no aquí |

El tercero es una **limitación real del método** que esta implementación no puede
cerrar, y está escrita como prueba —con ese nombre— para que no se olvide y para
que, si algún día deja de ser cierta, falle y alguien lo mire. Lo que sí la
detecta está fuera de la cadena: la copia que conserva la contraparte que firmó
el eslabón podado. Por eso la custodia se lleva por los dos lados.

## La flota: noventa y siete de cien no son cien

Se ordena una recogida en cien endpoints. Contestan noventa y siete. El informe
dice «recogida completada» y lista noventa y siete artefactos intactos, cada uno
con su sello perfecto.

Todo lo que ese informe afirma es cierto, y la conclusión que induce es falsa.
Los tres que faltan son, en un incidente real, el sitio más probable donde está
lo que se busca: una máquina apagada porque el atacante la apagó, una que no
contesta porque está comprometida, una que el agente no alcanzó. Presentar
noventa y siete piezas íntegras como *la evidencia del caso* convierte la
ausencia más informativa del incidente en silencio.

Es la misma regla que el resto del producto aplica a lo que no puede leer: **lo
que falta se declara; no se descuenta del total.**

La cuenta tiene que cuadrar, y se comprueba que cuadre. Cada endpoint acaba **o**
con su pieza **o** con una ausencia que dice por qué —sin respuesta, no
alcanzable, rechazada por política, parcial, o con la pieza rota, que son cinco
historias distintas para quien investiga—. Un endpoint que no esté en ninguna de
las dos listas sale en `sin_contabilizar()`: es un fallo de contabilidad del
propio sistema de recogida, y es la única ausencia sobre la que el informe ni
siquiera sabe que le falta algo.

`esta_completo()` exige cuatro cosas, y la cuarta la encontró la propia prueba al
escribirla: **que se le haya ordenado a alguien**. Con la lista de endpoints
vacía, las otras tres se cumplen por vacuidad y un conjunto que no preguntó a
nadie se declaraba completo.

## Qué se prueba, y contra qué

- **La evidencia de las pruebas no está inventada**: son los bytes reales de
  `/proc/self/maps` y del propio binario de la prueba —megabytes, con bytes no
  imprimibles—. Un artefacto de mentira comprueba la aritmética de la firma; uno
  real comprueba también que el camino aguanta lo que de verdad se recoge.
- **Cada manipulación conocida tiene su prueba**: cambiar un bit, recortar el
  final, reetiquetar para otro caso, adelantar la hora, cambiar la máquina,
  borrar un paso del medio, reordenar dos, insertar uno inventado, pegarle la
  cadena de otra evidencia, firmar con otra clave.
- **El reloj se mide de verdad**: no basta con que avance. Una prueba comprueba
  que mide una espera real de veinte milisegundos y otra que no es el mismo reloj
  que el de pared. Sin eso, cablear los dos al mismo `clockid` pasaría
  desapercibido y toda la defensa contra un atacante que mueve la hora no
  detectaría nada.

Sesenta y siete pruebas, y la puerta número 30 de `make ci`.

## Lo que esta fase NO hace

No recoge evidencia —eso es `aegis-forensics`—, no la transporta —`aegis-fleet`—
y no la almacena —`aegis-audit` y el plano de control—. Solo **responde por
ella**. Mezclarlo con la recogida sería pedirle al mismo código que produzca la
prueba y que la avale.
