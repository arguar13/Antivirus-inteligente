# 72 · AegisEnrich — preguntar a muchas fuentes sin contar lo que no toca

> FASE 77. `server/crates/aegis-enrich`.

## La regla que define la fase

**Consultar por un resumen le dice al proveedor que ese fichero está en tu red.**

No es un efecto secundario de la consulta: *es* la consulta. Le das información
que no tenía, gratis, y no se puede retirar.

Casi siempre compensa. Pero «casi siempre» es una decisión, y una decisión que
nadie ve no es una decisión: es un valor por defecto. De modo que el marco obliga
a **declarar** qué sale, y el panel se lo enseña al analista **antes** de ejecutar
el analizador.

| Módulo | El problema, dicho como se nota |
|---|---|
| [`observable`] | Consultar un `10.4.1.7` no puede devolver nada y a cambio dibuja tu direccionamiento interno |
| [`exposicion`] | Una descripción en texto libre se rellena con «consulta reputación» y no dice nada |
| [`salida`] | Una bandera `si sin_salida: no consultes` es opcional, y el analizador que se escriba el mes que viene se la olvida |
| [`dictamen`] | Lo que devuelve un analizador lo escribió un tercero por Internet |
| [`cache`] | Si «no lo conozco» se guarda tanto como «es malicioso», el malware nuevo te sigue pareciendo desconocido durante meses |
| [`tasa`] | Veinte tareas que comprueban «voy por 99 de 100» pasan las veinte |
| [`fusion`] | Promediar dos fuentes seguras y contrarias produce un número que se lee como evidencia débil |
| [`analizador`] | Un analizador que elige su propia clase se declara autoritativo |
| [`locales`] | Un producto cuyo enriquecimiento entero depende de terceros no sirve en una red aislada |
| [`orquesta`] | El orden de las puertas: la de privacidad es la única irreversible |

---

## 1 · Lo que no sale nunca, y por qué es una propiedad del tipo

Hay observables cuya consulta externa **no tiene ningún valor y sí un coste
directo**:

| No sale | Por qué | Qué pasaría |
|---|---|---|
| Cuenta de usuario | Es un dato personal | Sacarlo a un tercero necesita una base legal que un proceso automático no tiene |
| Ruta de fichero | `C:\Users\maria.lopez\Adquisición Norte\plan.xlsx` | Dice el nombre del usuario, el del proyecto y a menudo el del cliente, y no ayuda a decidir nada |
| Línea de órdenes | `mysql -u root -pSecreta123` | Una credencial enviada a un tercero está comprometida aunque el tercero sea de fiar |
| Dirección privada | RFC 1918, enlace local, CGNAT | La respuesta es «desconocido» **siempre**, y a cambio dibujas tu direccionamiento |
| Nombre interno | `dc-01.corp.local`, o cualquier nombre sin punto | Revela tu nomenclatura y tus unidades de negocio |

Podría comprobarse en cada analizador. **No se hace**: se comprueba una vez, en
`Observable::puede_salir`, y esa es la única respuesta. Una regla de privacidad
repartida por veinte analizadores es una regla que el analizador número
veintiuno se salta sin que nadie lo note.

### Los dos errores que costaron una corrección en esta fase

Ambos aparecieron al ejecutar las pruebas, y los dos son silenciosos:

1. **Usar «¿es una IP no enrutable?» como si fuera «¿es una IP?».**
   `ip_no_enrutable` es conservador con lo que no entiende —lo que no parsea se
   queda dentro—, que es correcto para algo que *dice ser* una IP y desastroso
   como prueba de tipo: `evil.example.com` no parsea como IPv4, así que la fallaba
   y **dejaba de consultarse todo dominio público**. El síntoma habría sido un
   enriquecimiento silenciosamente pobre, de los que no se notan nunca.
2. **Un literal IPv6 clasificado como nombre de máquina interno.**
   `nombre_interno` trata «sin punto» como nombre corto, y `[fd00::1]` no tiene
   puntos. Se quedaba dentro —correcto— pero **por el motivo equivocado**, y el
   motivo es lo que lee el analista en el informe.

La corrección es una función, `juzgar_anfitrion`, que decide **primero si es una
dirección** y sólo después pregunta lo que corresponda. Mezclar las dos preguntas
era el fallo.

---

## 2 · La declaración de exposición: un tipo, no un texto

`Exposicion` obliga a enumerar **qué campos** salen, **a dónde**, con **qué
retención** y bajo **qué jurisdicción**, y todos son enumerados cerrados. Lo que
no se puede expresar no se puede declarar mal.

Y es un **campo obligatorio de la ficha del analizador**, no una llamada que se
pueda olvidar: un analizador sin exposición declarada **no compila**.

Cada campo dice qué revela, y eso es lo que ve el analista — no el nombre del
campo, que no informa a nadie:

> `resumen-de-fichero`: revela que ese fichero exacto está en tu red; quien ya
> tenga el fichero puede confirmarlo comparando resúmenes.
>
> `identidad-del-consultante`: revela que eres **tú** quien pregunta, que
> convierte todo lo anterior en atribuible.

### Tres casos exigen que una persona lo autorice

Y los tres por la misma razón: son irreversibles y desproporcionados frente a lo
que aporta una consulta rutinaria.

1. **Sale contenido.** Mandar el fichero entero no es consultar, es entregar.
2. **Se comparte con terceros.** Lo que subes lo ven los demás participantes del
   agregador. Para una muestra de malware es deseable; para un documento interno
   es una fuga con reparto.
3. **Jurisdicción sin adecuación.** No lo prohíbe: obliga a que alguien lo mire.

### Lo que la declaración **no** es

**No es un control de acceso.** Sirve para que la decisión sea visible y
revisable. Quien impide físicamente la salida es [`salida`], que está a propósito
separado. Confundir «declarado» con «impedido» es el error clásico de estos
marcos, y por eso son dos módulos.

---

## 3 · El modo sin salida, cumplido por construcción

Lo obvio sería una bandera: `if sin_salida { return NoAplicable }` al principio de
cada analizador. Y no sirve:

1. Es **opcional**. El analizador que se escriba el mes que viene se la olvida, y
   nadie lo nota hasta que un cliente con la red aislada ve tráfico saliente.
2. Es **una comprobación, no una frontera**. Comprueba la intención declarada, no
   la capacidad real.

Aquí la salida es una **capacidad**: un objeto que el analizador recibe como
argumento y sin el cual no tiene forma de hablar con nadie. Con el modo puesto,
ese objeto **no existe**.

> La diferencia es la que va de «prometió no salir» a «no se le dio por dónde».

Igual que en `aegis-detonate`: `Salida` **no tiene ninguna variante** que
signifique «red sin restricciones». La ausencia es la frontera.

### En modo sin salida no se permite ni lo interno

Una red aislada lo está también para los servicios propios que vivan al otro lado
del aislamiento. Permitir «sólo lo interno» sería justo el matiz que hace que el
modo no valga para lo que existe.

### Y los analizadores locales siguen funcionando

Es lo que separa «modo sin salida» de «apagado». `Listas` —lo que la
organización ya decidió sobre su propia red— y `Dga` —una heurística sobre la
forma del nombre— siguen dando veredicto. En la ejecución de la puerta de calidad,
el veredicto **sale igual**: `malicioso`, decidido por lo que la organización ya
sabía.

Y hay una razón menos evidente para que existan: lo que la organización ya sabe
es **mejor información que cualquier reputación externa**, porque es sobre su
propia red. Consultar fuera antes de mirar dentro es el orden equivocado.

### El muro, dicho aquí y no en un anexo

Esto impide la salida **por la vía que el marco ofrece**. Un analizador que
llamara directamente a `std::net::TcpStream` saldría igual: Rust no puede negarle
el acceso a la biblioteca estándar. Lo que hace que eso no sea un agujero real:

- Los analizadores **viven en el árbol** y pasan por revisión. Esto **no es un
  cargador de complementos**: un marco que carga código de terceros en caliente
  dentro del plano de control es una superficie de ataque distinta y mucho mayor.
- La puerta de calidad **comprueba** que ningún analizador enlaza contra las
  primitivas de red (`tools/verificar-enrich.sh`), mirando código y no
  comentarios — una comprobación que castigara documentar el riesgo empujaría a
  dejar de documentarlo.
- Y el confinamiento de verdad es el del sistema: el proceso del servidor corre
  con su propia política de red.

---

## 4 · Lo que un analizador **no** puede elegir

Un analizador traduce lo que contesta un tercero. Eso lo convierte, desde el
punto de vista del plano de control, en código que trata entrada hostil.

| No decide | Si pudiera |
|---|---|
| Su **clase** | Un canal comunitario se declararía autoritativo y se saltaría la jerarquía entera de la fusión |
| Su **exposición** en ejecución | Declararía «local» y consultaría fuera; la declaración no valdría nada |
| Si **hay red** | Es la capacidad quien se la da o no |
| Su **cuota** | Una fuente que se autoasigna la cuota puede agotar el contrato |
| El **observable** del dictamen | Metería en el informe un veredicto sobre otra cosa |

Las primeras viven en la `Ficha`, que se da **al registrar**. Y el orquestador
sobrescribe clase, fuente y observable del dictamen con los de la ficha antes de
que entren en la fusión — en la puerta de calidad hay un analizador que **lo
intenta a propósito** y no lo consigue.

### Y lo que se sanea de su respuesta

| Se acota | Sin acotar |
|---|---|
| Longitud de cada texto (4 KiB→512 B) | Un motivo de un gigabyte llena la memoria del plano de control |
| Número de etiquetas (32) | Igual, por la vía de la cantidad en vez de la del tamaño |
| Confianza (≤100) | Un `255 %` desequilibra la fusión a favor de quien lo mande |
| Fecha en el futuro | Un dictamen que no caduca **nunca** |

El saneado es **idempotente**: si no lo fuera, sanear dos veces —algo que ocurre
en cuanto hay una caché por medio— cambiaría el dictamen y la fusión dejaría de
ser determinista.

---

## 5 · La caché es también una medida de privacidad

Cada consulta que **no** se hace es una vez menos que le dices al proveedor que
ese fichero está en tu red. La caché no reduce lo que ya se reveló, pero sí la
frecuencia con la que se confirma — y la frecuencia es lo que permite a un
proveedor reconstruir tu cronología.

De ahí que `Procedencia::hubo_exposicion()` sea `false` para un acierto de caché,
y que el informe de exposición cuente **hechos y no intenciones**.

### La caducidad va por tipo, y sale del mundo real

| Observable | Caduca a | Por qué |
|---|---|---|
| Resumen | 180 días | El fichero no cambia; lo que cambia es lo que se sabe de él, y despacio |
| Dominio | 30 días | Se registran, se abandonan, se incautan y se revenden en semanas |
| URL | 7 días | La página cambia sin que cambie el dominio |
| **IP** | **2 días** | Direccionamiento dinámico y nubes: la misma IP es de otro en horas |

La IP es la que más importa acertar: tratarla con la caducidad de un resumen
significa **bloquear a quien ocupa hoy una dirección por lo que hizo quien la
ocupaba la semana pasada**.

### El acierto negativo dura una hora, y no lo mismo que el positivo

Es el error clásico. Si «no lo conozco» se guardara tanto como «es malicioso», un
fichero que el proveedor incorpora hoy **te seguiría pareciendo desconocido
durante meses** — y ése es justo el caso que importa: malware nuevo, que primero
nadie conoce y a las pocas horas conoce todo el mundo.

### Y un dato antiguo no se rejuvenece al guardarlo

La vigencia cuenta desde que la fuente lo **observó**, no desde que lo guardamos.
Sin eso, volver a preguntar a una fuente que repite un dato antiguo lo pone otra
vez a estrenar y no caduca nunca.

### La clave es un resumen, no el valor

Una clave con el valor en claro convierte un volcado de la caché en la lista de
todo lo que se ha mirado, **con rutas de fichero y nombres de cuenta incluidos**.
Cuesta lo mismo guardar el resumen.

---

## 6 · La cuota: se reserva, no se comprueba

Lo evidente es «llevo la cuenta y si paso del límite, espero». Con veinte tareas a
la vez, veinte comprueban «voy por 99 de 100», veinte pasan, y salen ciento
diecinueve consultas. Es la carrera clásica de comprobar-y-actuar, y aquí la paga
el cliente: **pasarse de la cuota corta el servicio, y lo corta justo durante un
incidente**.

Por eso no se comprueba y después se actúa: se **reserva**. Una tarea que obtiene
un `Permiso` ya ha consumido su ficha antes de salir a la red. En la puerta de
calidad, **1.440 peticiones concurrentes contra una ráfaga de 100 conceden
exactamente 100**.

### La reserva se devuelve, y explícitamente

Si la consulta no llega a hacerse, la ficha vuelve. Un consumidor que reserva y no
devuelve va agotando la cuota con consultas que no ocurrieron, y el síntoma es un
límite que parece más bajo de lo contratado.

La devolución **no ocurre en `Drop`**: ahí no se puede distinguir «se soltó porque
la consulta se hizo» de «se soltó porque no se hizo», que es justo la distinción
que importa. Sin decir nada, se asume gastado — asumir devuelto regalaría cuota
que el proveedor sí contabilizó.

### El depósito se rellena por tiempo, no por ventana

Una ventana fija —«cien por minuto, contador a cero cada minuto»— deja pasar
doscientas consultas en dos segundos si caen a caballo del cambio de minuto. El
proveedor lo ve como un pico del doble del límite y corta igual.

---

## 7 · La fusión: por qué no una media

Es la tentación evidente: ponderar y promediar. Y produce el peor resultado
posible, por tres motivos que se suman:

1. **Una media esconde el desacuerdo.** «Malicioso al 95 %» y «limpio al 95 %»
   promedian a un valor intermedio que se lee como evidencia **débil**, cuando lo
   que hay es evidencia **fuerte y en conflicto**. Son dos situaciones opuestas y
   el número las hace iguales.
2. **Una media convierte el desconocimiento en voto.** Cuatro fuentes que no saben
   nada arrastran el promedio y el resultado se lee como «probablemente limpio».
3. **Una media trata a todas las fuentes como comparables.** Nuestra propia
   detonación vio el fichero cifrar ficheros. Un canal comunitario repite algo que
   alguien envió.

### El criterio, en cuatro reglas que se aplican en orden

| # | Regla | Por qué |
|---|---|---|
| 1 | Una observación **propia** decide | Vimos la cosa; los demás repiten lo que alguien dijo |
| 2 | Si nada aporta → **`SinDatos`** | Cuatro «no sé» no son «probablemente limpio» |
| 3 | Desacuerdo dentro de la clase que manda → **`EnDisputa`** | El desacuerdo **es** el hallazgo |
| 4 | Si no, decide esa clase | El que más sabe, manda |

La primera que decide, decide. Eso hace el resultado explicable en una frase, que
es el requisito de verdad: **un veredicto que el analista no puede reconstruir es
un veredicto que no usa**.

El enumerado tiene **cinco** valores y no tres, y los dos de más son los que hacen
que sirva: `SinDatos` y `EnDisputa` son situaciones reales y frecuentes que un
enumerado de tres obliga a disfrazar de otra cosa.

### Dos observaciones propias contrarias no se resuelven por mayoría

Es el único caso en que nuestras propias herramientas discrepan. Decidirlo por
mayoría **escondería un fallo en una de ellas**.

### La antigüedad no pondera: descarta

Un dictamen viejo no es un dictamen débil, es un dictamen **sobre otra cosa**. Un
dominio que era malicioso hace dos años puede llevar dieciocho meses siendo el
blog de alguien. Ponderarlo por la mitad lo mete igual en la decisión; lo correcto
es sacarlo y **decir que se sacó**, porque «no había datos» y «los datos eran de
hace dos años» son cosas distintas.

### `Limpio` y `Desconocido` no son lo mismo

Un fabricante que firma un binario y lo declara suyo es información. No tener el
binario en la base de datos no lo es. Juntarlos convierte «nadie lo ha visto» en
«está limpio», que es exactamente lo que parece un fichero recién compilado por un
atacante.

---

## 8 · La heurística de dominio generado, y lo que no puede decir

`Dga` **nunca devuelve `Malicioso`**. Como mucho `Sospechoso`, y con confianza
entre 25 y 55.

No es prudencia: es que la heurística **no puede** distinguir un dominio de un
algoritmo de generación de un nombre de una red de distribución de contenidos
—`d3kx7p2q9.cloudfront.net`—, de un identificador de despliegue, o de una marca
corta en un alfabeto que no es el latino. Un analizador que pudiera decir
«malicioso» sobre esa base acabaría bloqueando el dominio de un proveedor
legítimo, y el día que eso pase el cliente apaga el producto entero.

Lo que sí hace bien es **ordenar una cola**: entre diez mil dominios vistos hoy,
dice cuáles merecen que alguien los mire primero.

### Mira todas las etiquetas, no sólo la registrable

Un algoritmo de generación registra `xqzvbnmk.com`, y ahí basta la registrable.
Pero un **túnel de DNS** usa un dominio legítimo y mete los datos en el subdominio
—`a7f3b2c1d9e8f4a6.datos.ejemplo.com`—, donde la registrable (`ejemplo`) es
perfectamente normal. Mirar sólo ésa perdería justo el caso que casi nadie señala.

### La entropía se calcula con aritmética entera

Milésimas de bit, sin coma flotante. Dos máquinas distintas tienen que producir el
mismo número, o **el mismo dominio sale sospechoso en un nodo y no en otro** y el
informe deja de ser reproducible.

---

## 9 · El orden de las seis puertas

Cada encargo pasa por seis puertas, y el orden importa porque una puerta cruzada
antes de tiempo cuesta algo que ya no se recupera:

| # | Puerta | Si se hiciera después |
|---|---|---|
| 1 | ¿Sabe mirar este tipo? | Se gastaría cuota en un analizador que iba a decir que no |
| 2 | **¿El observable puede salir?** | **Ya habría salido.** Es la única irreversible |
| 3 | ¿Hay salida en este modo? | Igual: se habría consultado |
| 4 | ¿Está autorizado? | Se habría mandado el fichero antes de que nadie lo aprobara |
| 5 | ¿Está en caché? | Se gastaría cuota y exposición por algo que ya se sabe |
| 6 | ¿Hay cuota? | Se reservaría una ficha para no usarla |

**La puerta 2 manda: es la única que no se puede deshacer.** Una consulta hecha no
se retira.

### El informe lleva a todos los analizadores, también a los que no hicieron nada

Es la propiedad central del módulo. Todas las variantes de `NoAplicable` llevan
motivo, y están **todas** en el informe — incluidas las de los analizadores que ni
siquiera aceptaban el tipo, porque su ausencia silenciosa hace pensar que se
consultó.

> «No se consultó» nunca puede producir el mismo hueco visual que «se consultó y no
> había nada». Si lo hiciera, el analista leería «sin resultados» y entendería
> «limpio».

Y se distingue lo **transitorio** —cuota, plazo— de lo que no lo es: un «vuelve en
30 s» y un «esto nunca va a funcionar para este observable» exigen cosas distintas
del analista, y el panel sólo puede ofrecer «reintentar» en el primero.

---

## Lo que mide la puerta de calidad

`cargo run -p aegis-enrich --example consulta` ejercita las cinco propiedades **a
la vez**, y falla con código distinto de cero si alguna se rompe:

| Propiedad | Cifra |
|---|---|
| El colgado no bloquea a los demás | 203 ms en total, con plazo de 200 ms y un analizador que tarda 2 000 |
| El corte dice **por qué** | `PlazoAgotado` si llegó a trabajar, `NoEjecutado` si el sistema no le dio hueco |
| El que entra en pánico se recoge | El plano de control sigue, y el resto da veredicto |
| La respuesta manipulada se sanea | 20 000 B → 510 B · 1 000 etiquetas → 1 · confianza 255 → 100 · fecha futura → presente |
| Modo sin salida | 0 consultas salieron, y el analizador **lo intentó** |
| Cuota bajo concurrencia | 1 440 peticiones · ráfaga 100 · **concedidas exactamente 100** |
| Relleno continuo | 10 fichas al segundo a 600/min, no una ráfaga entera |
| Fusión determinista | 12 ejecuciones concurrentes, mismo veredicto y misma explicación |
| Tres «no sé» | `SinDatos`, no «limpio» |
| Consulta repetida | Sale de caché, **0 proveedores expuestos** |

---

## Contratos existentes: qué se conserva y qué cambia

**No cambia nada de lo anterior.** `aegis-enrich` es un crate nuevo; nadie
dependía de él.

**Se reutiliza en vez de duplicarse:**

- Los tipos de **observable** son los mismos de `aegis-case`, a propósito: un
  observable de un caso se enriquece sin traducirlo, y dos taxonomías es la forma
  de que un día una ruta sea una cosa en un sitio y otra en otro.
- La doctrina de la **frontera** es la de `aegis-detonate`: la ausencia de variante
  **es** la frontera, no un olvido.
- La disciplina de **tri-estado** es la del resto del producto, y aquí se aplica
  dos veces: `Desconocido` no aporta, y `SinDatos` no es `Limpio`.

---

## El muro, declarado

La puerta de calidad **no habla con ningún proveedor real**, y es deliberado: una
puerta que depende de un tercero por Internet falla los días que ese tercero tiene
un mal día, y **una puerta que falla sin motivo se acaba ignorando** — que es peor
que no tenerla.

Lo que sí queda comprobado, contra código real: el orden de las seis puertas, el
corte por plazo, la recogida de un pánico, el saneado de una respuesta manipulada,
1 440 peticiones concurrentes y doce fusiones idénticas.

Y una segunda cosa que este crate **no** hace: los analizadores de proveedores
concretos —sus formatos, sus claves, sus peculiaridades— no están aquí. Lo que
está es el marco que decide **si** se les pregunta, **qué** se les manda y **qué
se hace** con lo que contestan. Escribir el traductor de un proveedor es trabajo
mecánico; decidir si mandarle el resumen de un documento interno no lo es.

[`observable`]: ../server/crates/aegis-enrich/src/observable.rs
[`exposicion`]: ../server/crates/aegis-enrich/src/exposicion.rs
[`salida`]: ../server/crates/aegis-enrich/src/salida.rs
[`dictamen`]: ../server/crates/aegis-enrich/src/dictamen.rs
[`cache`]: ../server/crates/aegis-enrich/src/cache.rs
[`tasa`]: ../server/crates/aegis-enrich/src/tasa.rs
[`fusion`]: ../server/crates/aegis-enrich/src/fusion.rs
[`analizador`]: ../server/crates/aegis-enrich/src/analizador.rs
[`locales`]: ../server/crates/aegis-enrich/src/locales.rs
[`orquesta`]: ../server/crates/aegis-enrich/src/orquesta.rs
