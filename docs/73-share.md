# 73 · AegisShare — inteligencia con difusión impuesta en el código

> FASE 78. `server/crates/aegis-share`.

## La asimetría que lo decide todo

**Compartir es irreversible, y los errores se propagan.** De ahí salen los dos
fallos que este crate existe para impedir, y ninguno de los dos es de formato:

1. **Sale algo que no debía.** Un `TLP:RED` en un canal público no se puede
   retirar. Y no hace falta un ataque: basta un filtro que se quedó atrás cuando
   se añadió un camino de salida nuevo.
2. **Entra algo envenenado y no se puede deshacer.** Un canal mete tres semanas
   de indicadores fabricados —la IP del resolutor público que usa media
   industria, el resumen de una biblioteca firmada—, se descubre, y sin
   procedencia no se sabe cuáles eran suyos.

El formato —STIX, TAXII— es la parte fácil. Lo difícil es que **no haya ningún
camino** por el que algo salga sin pasar por la política, y que **siempre** se
pueda deshacer lo que entró.

| Módulo | El problema |
|---|---|
| [`marcado`] | Casi todo el mundo implementa TLP y se olvida de PAP |
| [`stix`] | Un paquete STIX es JSON de un desconocido que procesa el plano de control |
| [`difusion`] | Si cada camino de salida tuviera su filtro, uno se quedaría atrás |
| [`taxii`] | La paginación por desplazamiento **pierde objetos en silencio** |
| [`federacion`] | «Ya he visto ese identificador» corta el bucle y también las correcciones |
| [`procedencia`] | Dos canales que repiten al mismo no son dos fuentes |
| [`taxonomia`] | Una etiqueta de texto libre no es una etiqueta, es una nota |
| [`puente`] | El enjambre llega a máquinas que el atacante puede haber comprometido |

---

## 1 · TLP y PAP son dos ejes, y confundirlos es el fallo clásico

- **TLP** (*Traffic Light Protocol*) responde a **quién puede verlo**.
- **PAP** (*Permissible Actions Protocol*) responde a **qué puedes hacer con ello
  sin que el adversario lo note**.

La combinación que enseña por qué hacen falta los dos es `TLP:GREEN` con
`PAP:RED`:

> El dominio de mando y control se puede compartir con toda la comunidad, **y no
> se puede bloquear**. Porque bloquearlo le dice al atacante que se le ha visto,
> cambia de infraestructura, y se pierde la visibilidad que costó meses
> conseguir.

Un producto que sólo implementa TLP hace exactamente eso: recibe un indicador
compartible, lo empuja al motor de bloqueo, y **quema la operación de quien lo
compartió**. La siguiente vez no se lo mandan.

### El retículo: sólo se puede restringir, nunca aflojar

Es la doctrina de la FASE 23 y del enjambre —sólo se puede añadir protección,
jamás quitarla— aplicada al marcado:

- Al **combinar**, el resultado toma lo más restrictivo **de cada eje por
  separado**. `TLP:CLEAR/PAP:RED` combinado con `TLP:RED/PAP:CLEAR` da
  `TLP:RED/PAP:RED` — tomar «el peor de los dos objetos» como bloque devolvería
  uno de los dos originales y perdería la mitad de la restricción.
- Al **propagarse**, `admite_reemision_como` sólo deja subir. Una instancia que
  recibiera `TLP:AMBER` y lo reemitiera como `TLP:CLEAR` estaría filtrando **con
  un documento perfectamente válido**.

No hay ninguna función que afloje.

### Lo que llega sin marcado es lo más restrictivo

Un objeto sin marcado no es público: es un objeto **cuyo marcado no sabemos**.
Y lo mismo con una etiqueta que no se reconoce — el `TLP:PINK` que aparezca el
año que viene en una comunidad. Leerlo como «no reconozco esto, será público» lo
publica, y no hay vuelta atrás.

El caso que más se da es el PAP: **casi nadie lo marca**. Sin PAP explícito no se
puede actuar. Quien quiera bloquear tiene que decir que puede.

---

## 2 · STIX: la extensibilidad del formato **es** la superficie de ataque

STIX **obliga** a aceptar propiedades desconocidas —es lo que permite que el
formato crezca— y eso significa que un paquete puede traer carga arbitraria en
campos que nadie mira. La respuesta no es prohibirlo, porque entonces se deja de
hablar STIX: es **acotarlo**.

| Tope | Valor | Qué impide |
|---|---|---|
| Bytes del paquete | 8 MiB | Un documento de un gigabyte |
| Objetos | 50 000 | Lo mismo por la vía de la cantidad |
| Propiedades por objeto | 256 | La vía de la extensibilidad |
| Longitud de un texto | 64 KiB | Un campo descriptivo de un gigabyte |
| **Profundidad** | **32** | Un desbordamiento de pila **al analizar** |

La profundidad se mide **antes** de `serde_json::from_str`, recorriendo los bytes.
Un documento con diez mil llaves abiertas desborda la pila al analizarlo, y
entonces no hay validación que valga porque el proceso ya no está.

### Las tres comprobaciones que casi nadie hace

| Comprobación | Sin ella |
|---|---|
| El **prefijo del identificador** coincide con el `type` | Un objeto dice `type: "indicator"` con un `id` de `malware--…`; quien indexe por el prefijo y pinte por el tipo **guarda una cosa y enseña otra** |
| Una **referencia de marcado que no resuelve** restringe más | El objeto apunta a un marcado que no viaja en el paquete, no se encuentra, y se pinta **sin marcar** — es decir, público |
| `modified >= created` | Un objeto «modificado antes de crearse» gana cualquier resolución de conflictos por fecha, **para siempre** |

La segunda es la que más veces se ha visto filtrar en sistemas reales, y es
silenciosa: el documento es válido, el objeto se ve entero, y lo único que falta
es la etiqueta que decía que no se podía enseñar.

### Un tipo desconocido se conserva, no se descarta

Descartarlo perdería información que otra instancia sí entiende, y este nodo
sería **un agujero en la federación**. El documento crudo se guarda entero: la
ida y vuelta no pierde nada, ni siquiera una extensión anidada que este nodo no
interpreta.

### Y una excepción que hace falta explicar

Una `marking-definition` sin marcado propio es **pública**, no desconocida.
Parece contradecir la regla anterior y en realidad es lo que la hace funcionar:
la definición **tiene que viajar** con los objetos que marca, porque si no llega,
su referencia no resuelve y —por nuestra propia regla— esos objetos acaban en
`TLP:RED` en el otro extremo. Una definición que no se puede distribuir hace que
**nada** se pueda distribuir.

Y no abre ningún agujero: una definición no lleva inteligencia, lleva el nombre
de una etiqueta, y los marcados TLP son constantes públicas.

---

## 3 · Un solo estrangulamiento

> Un indicador marcado como no compartible **no sale por ningún camino**.

«Ningún camino» es la parte difícil, y es una decisión de arquitectura antes que
de código. Si la federación tuviera su filtro, el servidor TAXII otro y el puente
del enjambre un tercero, tarde o temprano uno de los tres se queda atrás. Y el
que se queda atrás **no falla ruidosamente: comparte de más**.

Por eso hay un solo `Difusor::repartir`, y `Canal` es un enumerado cerrado que la
puerta de calidad recorre entero: un camino de salida nuevo no puede quedarse sin
cubrir sin que la comprobación de cobertura lo note.

### `TLP:RED` no se distribuye por ningún canal

`TLP:RED` significa, literalmente, «sólo para quien lo recibió en la reunión o la
conversación en que se entregó». No es «sólo dentro de mi organización» —eso es
`AMBER+STRICT`—: es **sólo estas personas**.

De modo que no hay ningún canal de distribución por el que pueda salir, **y eso
incluye una exportación a fichero dentro de casa**: exportar es distribuir, y el
fichero acaba en un correo. Configurar un destino con tope `RED` no lo habilita.

La consecuencia práctica es la que importa: la frase «no sale por ningún camino»
es cierta **por construcción**, no por haber configurado bien los cinco destinos.
En la puerta de calidad se comprueba que el motivo de retención es **el mismo en
los cinco**.

### El enjambre no es un canal confidencial

El enjambre llega a **todos** los agentes de la flota, incluidos los que corren en
máquinas que el atacante puede haber comprometido — que es literalmente el
supuesto de la FASE 68. De ahí dos topes que **no se pueden subir por
configuración**, porque subirlos sería configurar una fuga:

1. **Nada por encima de `TLP:GREEN` viaja por el enjambre.**
2. **Nada que no permita bloqueo propio tampoco**: lo que llega a los agentes
   acaba en el motor de bloqueo, y un `PAP:RED` repartido por la malla quema la
   operación de quien lo compartió **en cien mil máquinas a la vez**.

El destino del puente se declara pidiendo el máximo (`Tlp::Red`) a propósito: que
el tope efectivo salga `Green` enseña que el que manda es el canal y no la
configuración.

---

## 4 · TAXII: la paginación que no pierde nada

La forma evidente de paginar es por desplazamiento. Y **pierde objetos en
silencio** en cuanto alguien escribe entre dos peticiones: si entran diez objetos
antes de la posición 100, los diez que la ocupaban se desplazan y no se ven nunca.

En una lista de productos eso es una molestia. En un canal de indicadores es **un
indicador que no se recibe**, y no hay ningún error: la respuesta es válida y el
cliente sigue sondeando tan tranquilo.

El cursor es `(añadido, identificador)`. Un objeto que entra después tiene un
`añadido` posterior y **no desplaza** lo ya paginado; el identificador desempata
cuando decenas entran en el mismo instante, que con lotes grandes pasa siempre.

### El sondeo va por «cuándo se añadió aquí», no por `modified`

Un objeto creado hace un año que llega hoy por federación tiene que salir en el
sondeo de hoy. Ordenando por `modified` se colaría detrás del cursor del cliente
y **no lo vería nunca**.

### `hay_mas` y `siguiente` son dos preguntas distintas

Juntarlas rompe el sondeo, y fue un bug real de esta fase: si la última página no
trae cursor, el cliente no puede continuar desde ahí la próxima vez y sólo le
quedan dos salidas, repetirlo todo o saltar al final y perderse lo que entre
después. `siguiente` va siempre que se entregue algo; el `next` del sobre TAXII
—que significa «sigue pidiendo»— sólo cuando de verdad hay más.

### El cliente agota las páginas del ciclo

Un cliente que pide una página por ciclo y sondea cada cinco minutos **no alcanza
nunca** a un canal que publica más rápido de lo que él sondea: el retraso crece
sin parar y no hay ningún error que lo diga.

---

## 5 · Federación: el ciclo, y por qué la defensa evidente rompe el sistema

A comparte con B, B con C, y C con A. Es la topología normal de una comunidad
—nadie la diseña, sale sola—.

La solución evidente es recordar los identificadores ya vistos. Y **rompe el
sistema**: un objeto se actualiza, y la versión nueva lleva el mismo
identificador. Con esa defensa, una corrección —«este resumen era un falso
positivo, lo retiro»— **no llega nunca**. Se cambia un bucle por un sistema que no
se puede corregir, que es peor.

Lo que sí funciona es el **vector de camino**, la solución de BGP al mismo
problema: cada objeto lleva por dónde ha pasado, y una instancia rechaza lo que
ya lleva su propio nombre. No mira *qué* es el objeto, mira *por dónde ha venido*.

### Lo que el vector no puede hacer

Una instancia maliciosa **puede mentir sobre el camino**: quitarse a sí misma.
Contra eso hay dos cosas y ninguna sobra:

- Cada salto **añade su identidad**, y quien recibe comprueba que el último salto
  es el par autenticado por el canal. Eso hace **ese** salto infalsificable, y
  sólo ése.
- Los saltos anteriores los puede falsear un par malicioso. Contra eso está el
  **tope de seis saltos**, que no depende de que nadie diga la verdad.

Y se distingue: un ciclo es **topología** y se corta en silencio; un último salto
que no cuadra es **un par mintiendo sobre su identidad**, y eso se reporta.

### Los conflictos no se resuelven por hora de llegada

Resolver por «la última que llegó» hace que el resultado dependa de la latencia:
dos instancias de la misma federación acabarían con contenidos distintos y
ninguna sabría cuál es el bueno. Se resuelve por `(modified, revocado, id)`, que
es igual en todas partes. A igualdad de fecha gana la revocación — misma doctrina
de siempre: la versión que **retira** una protección equivocada se aplica, y la
que la añade se puede volver a mandar.

### El cursor de salida, que faltaba

Otro bug real de esta fase, encontrado al ejecutar la comunidad completa: sin
cursor de salida, cada ciclo manda la base **entera** a cada par. No produce un
bucle —el otro extremo rechaza lo repetido— y aun así hace inviable la
federación: con 400 000 indicadores y veinte pares son **ocho millones de objetos
por la red para no cambiar nada**.

Y lo peor es que *funciona*: nadie se entera hasta que la federación crece lo
suficiente para que el ciclo no termine antes del siguiente. Con el cursor, la
comunidad de tres instancias del ejemplo se estabiliza en **2 vueltas y 2
mensajes**.

---

## 6 · Procedencia: cómo se deshace un canal envenenado

Sin procedencia sólo quedan dos salidas y las dos son malas: vaciar la base
entera —perdiendo lo bueno de tres semanas— o seguir bloqueando el resolutor
público que metió.

### Las dos decisiones que lo hacen reversible

1. **La confianza no se guarda, se calcula.** Si se guardara un escalar, quitar un
   aporte dejaría el número inflado que ese aporte ayudó a subir, y la revocación
   **no se notaría en la cifra que decide si se bloquea**.
2. **Un objeto con varios aportes sobrevive a la revocación de uno.** Lo que
   dijeron los demás sigue siendo cierto. Borrarlo entero castigaría a las fuentes
   buenas por haber coincidido con la mala.

### Y la que casi nadie toma: dos canales que repiten al mismo no son dos

Si el canal A y el canal B se nutren los dos de C, «dos fuentes coinciden» es
**una** fuente contada dos veces. Es la forma más común de que un indicador
parezca corroborado sin estarlo, y es exactamente lo que aprovecha quien envenena:
**envenena C y cobra en A y en B**.

Por eso un aporte lleva su **cadena de origen** y se cuentan raíces distintas, no
aportes. Y revocar se lleva también lo que **pasó por** el canal envenenado: un
aporte que llegó a través de él lo pudo alterar al reemitirlo, y no hay forma de
saber que no lo hizo.

### La revocación es auditable y se puede mirar antes

`aportados_por` lista lo que se va a tirar **antes** de tirarlo: una revocación a
ciegas sobre cuatrocientos mil indicadores no la firma nadie. Y el resultado lleva
el **antes y el después** de cada confianza, porque un informe que sólo dice
«retirados 412» no permite comprobar nada.

`dependencia_unica` responde a la pregunta que un panel no suele hacer: un panel
que enseña «450 000 indicadores» no dice nada; uno que enseña «310 000 dependen de
un solo canal abierto» dice bastante.

---

## 7 · Taxonomías y galaxias

**Una etiqueta de texto libre no es una etiqueta, es una nota.** El valor está en
poder *preguntar* por ella, y con texto libre en seis meses la misma cosa está
escrita de cuatro formas y ninguna consulta las encuentra todas. El etiquetado
deja de servir sin que nadie lo note, porque las etiquetas siguen ahí.

Por eso lo que no valida **se rechaza al entrar**. Guardarlo «por si acaso» es
exactamente como se llega a las cuatro formas. Y el error dice qué taxonomías hay,
porque un rechazo sin alternativa hace que la gente deje de etiquetar.

Las taxonomías estándar **vienen incluidas y no se descargan**: un producto que
necesita Internet para validar una etiqueta no vale en una red aislada, que son
justo las que más cuidado ponen en esto. Entre ellas la **escala del
Almirantazgo**, que separa la fiabilidad de la fuente de la credibilidad de la
información —la distinción que un solo número de «confianza» borra: una fuente
pésima puede traer un dato comprobado.

### Las galaxias

`APT29`, `Cozy Bear`, `Nobelium` y `Midnight Blizzard` son el mismo actor. Una
base que los trate como cuatro **no junta nunca** lo que se sabe de él. Y dos
grupos que comparten un sinónimo **se rechazan** en vez de resolverse: o son el
mismo y hay que fusionarlos, o el sinónimo está mal, y elegir uno automáticamente
esconde las dos posibilidades.

---

## 8 · El puente al enjambre: aquí se cobra la FASE 68

> **El enjambre transporta autoridad; no la concede.**

Un indicador que llega por federación, por muy fiable que sea su fuente, **no se
convierte en una orden**. Lo que cruza la malla es de dos clases y ninguna manda
nada:

| Clase | Qué es | Qué hace falta para actuar |
|---|---|---|
| `Observacion` | Evidencia | K pares distintos corroborando |
| `Artefacto` | Un conjunto de indicadores | Firma del plano de control |

**No hay una tercera variante que sea una orden**, y esa ausencia es deliberada:
es la misma técnica que en `aegis-detonate` —donde `Salida` no tiene variante para
«red de verdad»— y en `orden::Accion::gossipable`. Lo que no se puede expresar no
se puede configurar por error. La puerta de calidad **cuenta las variantes**.

Si un día hiciera falta que un indicador federado provocara una contención, no se
haría aquí: haría falta que el plano de control emitiera una orden firmada, con su
época y su ventana. Este puente no es un atajo a eso.

### Y tres filtros más, cada uno con su coste

- **Sin procedencia no cruza nada**: no se puede revertir lo que no se sabe de
  dónde vino.
- **Fiabilidad mínima «comunidad»**: un canal abierto no reparte nada por la
  flota. Cualquiera puede envenenar uno sin identificarse, y el coste lo pagan
  cien mil endpoints.
- **Confianza mínima 70**: un falso positivo repartido por la malla es una
  interrupción en toda la flota — **con el plano de control caído**, que es cuando
  el enjambre se usa, y por tanto sin nadie a quien pedirle que lo retire.

### El patrón se traduce entero o no se traduce

Un agente no evalúa el lenguaje de patrones de STIX: no tiene sitio para un
intérprete, y metérselo sería meterle un analizador de entrada hostil en el
proceso más privilegiado del endpoint. Se traducen las cuatro comparaciones de
igualdad que cubren la práctica totalidad de lo que se comparte, y **lo demás se
declara no traducible** en vez de traducirse a medias: un patrón traducido a
medias detecta otra cosa que la que su autor escribió, y eso es peor que no
detectarlo.

Y se trocea a 2 000 indicadores: el presupuesto del agente va de 48 a 384 MiB
según la clase de máquina, y un artefacto de un millón de indicadores no es
grande, **es irrecibible para media flota**.

---

## Lo que mide la puerta de calidad

`cargo run -p aegis-share --example comunidad` monta una comunidad entera y falla
con código distinto de cero si alguna propiedad se rompe:

| Propiedad | Cifra |
|---|---|
| Ida y vuelta STIX | Idéntica, incluido un tipo desconocido y una extensión anidada |
| No compartible | **0 salidas** de 5 destinos, y el **mismo motivo** en los cinco |
| Cobertura de canales | Los 4 del enumerado, con destino cada uno |
| Ciclo de federación | **2 vueltas, 2 mensajes**; con la vuelta forzada, cortada por el vector |
| Corrección | Llega hasta el último nodo de la cadena |
| Canal envenenado | 467 aportes tocados · **430 caen** · **37 sobreviven** con confianza recalculada · 237 intactos |
| Revocación idempotente | La segunda no cambia nada |
| Entrada hostil | **3 082 entradas** sin un solo pánico |
| TAXII extremo a extremo | 250 objetos · 150 entregados · 100 retenidos · segundo sondeo vacío |
| Puente al enjambre | 150 cruzan, todos exigiendo firma; 100 retenidos por difusión |

---

## Contratos existentes: qué se conserva y qué cambia

**No cambia nada de lo anterior.** `aegis-share` es un crate nuevo del plano de
control.

**Se conserva intacto:**

- La **doctrina del enjambre** de la FASE 68, comprobada en la puerta de calidad
  contando las variantes de la carga.
- La **disciplina del tri-estado** del resto del producto.
- La técnica de **la ausencia como frontera** de `aegis-detonate`.

**Se reutiliza en vez de duplicarse:**

- Las clases de fuente de `procedencia` siguen el mismo orden de autoridad que las
  de `aegis-enrich`, y por la misma razón.
- El calendario es el de `aegis-ingest::tiempo`, escrito con el mismo algoritmo:
  dos calendarios en el mismo producto es la forma de que un día dos módulos
  ordenen el mismo suceso al revés.
- Los tipos de indicador que cruzan la malla son los de `aegis-sync::IocKind`,
  para que el agente no tenga que traducir nada.

---

## El muro, declarado

La puerta de calidad **no habla con ningún servidor TAXII de Internet ni con
ninguna comunidad real**, y es deliberado: una puerta que depende de un tercero
falla los días que ese tercero tiene un mal día, y **una puerta que falla sin
motivo se acaba ignorando** — que es peor que no tenerla.

Lo que sí corre es el servidor **y** el cliente TAXII de verdad hablando entre
ellos, con el mismo código que hablaría con un tercero.

Y dos cosas más que este crate **no** hace, dichas aquí:

- **No firma.** El puente prepara el contenido y declara que exige firma; quien la
  pone es el plano de control, cuya clave privada no está en este crate.
- **No transporta.** La federación decide qué sale, qué entra y qué se rechaza;
  el canal —mTLS entre instancias— es de `aegis-server`. Por eso la identidad del
  par se recibe como argumento y **no se lee del documento**: leerla del documento
  sería creerse la identidad que dice quien habla.

[`marcado`]: ../server/crates/aegis-share/src/marcado.rs
[`stix`]: ../server/crates/aegis-share/src/stix.rs
[`difusion`]: ../server/crates/aegis-share/src/difusion.rs
[`taxii`]: ../server/crates/aegis-share/src/taxii.rs
[`federacion`]: ../server/crates/aegis-share/src/federacion.rs
[`procedencia`]: ../server/crates/aegis-share/src/procedencia.rs
[`taxonomia`]: ../server/crates/aegis-share/src/taxonomia.rs
[`puente`]: ../server/crates/aegis-share/src/puente.rs
