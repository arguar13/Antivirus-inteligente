# 69 · AegisIngest — canalización de registros a escala

> FASE 74. `crates/aegis-ingest` (endpoint) y `server/crates/aegis-pipeline`
> (plano de control).

## El hueco que cierra

Hasta aquí AegisCore consumía **su propia telemetría**: lo que ven sus sensores.
Eso lo hace un EDR. Una plataforma tiene que tragarse además lo que ya escribe el
resto de la casa —el syslog de los cortafuegos, el diario de los servidores
Linux, el registro de sucesos de los Windows, los ficheros de las aplicaciones,
los planos de control de las nubes— y **correlacionarlo con lo propio**. Sin
esto, el analista tiene dos paneles y ninguna correlación entre ellos.

Y no es un detalle de integración. El movimiento que de verdad importa cruza esos
mundos: una clave robada en AWS, usada desde una IP que aparece en el syslog del
cortafuegos, contra una cuenta cuyo `4625` está en el EVTX del controlador de
dominio. Cada pieza por separado es ruido; juntas son un incidente.

---

## Por qué OCSF y no ECS

Es la decisión más cara de deshacer de toda la fase: cambiar el esquema después
no es una edición, es una migración de todo lo que un cliente tenga almacenado.

**ECS** (Elastic Common Schema) es más maduro, tiene un vocabulario enorme y lo
entiende cualquier SIEM. Su fuerza es la amplitud: hay un campo para casi todo.

**OCSF** (Open Cybersecurity Schema Framework) es más nuevo y más estrecho, y
**esa estrechez es justamente la razón para elegirlo**: su taxonomía está
*enumerada*. Una actividad es un identificador de una lista cerrada, no una
cadena libre. Eso tiene dos consecuencias que a un EDR le importan más que la
amplitud:

1. **La normalización se puede comprobar.** Un registro o encaja en una clase
   conocida o no encaja, y cuando no encaja se cuenta. De ahí sale una **cifra de
   cobertura**: no «normalizamos syslog», sino «el 94 % de las líneas de esta
   máquina encajaron en una clase, y estas cien no». Alguien mira las cien,
   escribe la regla que falta, y la cifra sube. Con un vocabulario abierto esa
   cifra **no existiría**, porque todo «encajaría».
2. **La correlación es determinista.** Un inicio de sesión fallido en syslog y
   otro en EVTX caen en el mismo identificador de actividad y se cuentan juntos,
   sin una tabla de equivalencias que alguien tenga que mantener.

Lo que se pierde es real y se dice: hay campos de ECS que aquí no tienen sitio y
acaban como extensión. No se tiran.

---

## El reloj es el corazón del módulo

Un endpoint que estuvo apagado un día entrega su lote entero al reconectar. Si
los eventos se ordenaran por **llegada**, un ataque repartido en dos días
aparecería como un pico de un segundo, y todas las heurísticas de ritmo —fuerza
bruta, exfiltración lenta, balizas— lo leerían exactamente al revés.

Se ordena por **ocurrencia**. Pero la hora de ocurrencia sale del registro, y el
registro lo escribe cualquiera: un atacante que quiera esconderse sólo tiene que
fechar sus líneas en 2019. Por eso no basta con tener el campo:

| Confianza | Qué significa | Qué se hace |
|---|---|---|
| `DelOrigen` | El registro traía marca y es verosímil | Se ordena por ella |
| `Sospechosa` | Traía marca, pero no cuadra con cuándo se leyó | Se **marca**, se conservan las dos horas, y quien correlaciona lo ve |
| `DeLlegada` | No traía hora | Se usa la de lectura y se dice que no sirve para razonar sobre el orden |

La tentación de descartar una línea fechada hace dos años sería un error: un
endpoint apagado tres días entrega un lote legítimo con horas viejas, y
rechazarlo perdería justo la evidencia del rato en que nadie miraba. La contraria
—creérsela— le regala al atacante la forma más barata de esconderse.

### La marca de agua es monótona, y eso es una defensa

La **marca de agua** es la hora por debajo de la cual ya no va a salir nada más:
lo que permite a la correlación cerrar una ventana y decidir. Es monótona a la
fuerza. Sin monotonía, un atacante que fechara una línea en 2019 haría retroceder
la marca y **reabriría ventanas de correlación ya cerradas**, obligando al plano
de control a recalcular historia indefinidamente.

---

## El caso que casi todo el mundo hace mal: la rotación

Seguir un fichero que crece es trivial. Seguir uno que **rota** es donde fallan
la mayoría de los recolectores, y falla de las dos formas posibles a la vez.
Lo que hace `logrotate` a medianoche:

```text
  mv  auth.log  auth.log.1      <- el inodo NO cambia; el nombre sí
  create auth.log               <- un inodo NUEVO en el nombre de siempre
  kill -HUP rsyslog             <- el demonio reabre por nombre
```

Y los cuatro errores clásicos, los cuatro resueltos y con prueba:

1. **Seguir por nombre.** El recolector reabre `auth.log`, ve un fichero de cero
   bytes y se lleva por delante lo que quedaba sin leer del renombrado.
2. **Detectar la rotación y saltar de inmediato.** El descriptor viejo *todavía
   tenía bytes sin leer*: entre la última lectura y el `mv` se escribieron
   líneas. Hay que **agotar el viejo primero**.
3. **No detectar el truncado.** Con `copytruncate` el inodo no cambia. El
   recolector sigue en el desplazamiento de ayer, que ahora está más allá del
   final, y no lee nada **hasta que el fichero crezca por encima de donde
   estaba**: un día entero de silencio sin un solo error en ningún sitio.
4. **Emitir líneas a medias.** El escritor no es atómico: una lectura puede caer
   entre el mensaje y su salto de línea.

La prueba de la fase escribe en el fichero **después** de la última lectura y
**antes** del `mv`: esas líneas sólo existen en el descriptor viejo, y son justo
las de la franja en que nadie mira.

---

## Entrega al menos una vez: la regla de orden

```text
  1. leer del origen            -> eventos en memoria
  2. admitir en el diario       -> en disco, pendientes
  3. sincronizar el diario      -> en disco DE VERDAD
  4. avanzar el punto de control
```

El orden **no es negociable y es asimétrico a propósito**:

- Si el proceso muere entre 3 y 4, al arrancar se relee desde el punto viejo y se
  reenvían eventos que ya estaban. Son **duplicados**, y el plano de control los
  desduplica.
- Si se avanzara el punto **antes** de sincronizar, un corte entre las dos dejaría
  el origen marcado como leído con los eventos en un búfer que ya no existe.
  Serían **pérdidas**, y una pérdida no se arregla después: nadie sabe siquiera
  que la hubo.

Duplicar es recuperable y perder no lo es. Por eso el `Confirmador` hace los
pasos 3 y 4 juntos y en ese orden, y es la única forma de avanzar el punto.

### Dos durabilidades distintas

- **El diario** (`aegis-firehose::Diario`, FASE 46) guarda los eventos ya
  normalizados y todavía sin acusar. Se **reutiliza**, no se reescribe: dos
  verdades sobre la durabilidad son dos verdades que un día divergen.
- **El punto de control** guarda **por dónde iba cada origen**: el
  desplazamiento en un fichero, el cursor de journald, el número de registro de
  EVTX. Se escribe con sustitución atómica (temporal, `fsync`, `rename`, `fsync`
  del directorio) y lleva resumen SHA-256: un punto de control corrupto leído
  como válido hace saltar o repetir un tramo arbitrario de historia, y nadie lo
  notaría.

---

## Sin ancla, la deduplicación destruye evidencia

El identificador de un evento se deriva de su contenido —tiene que hacerlo, o el
mismo evento reenviado tras un reinicio daría un identificador nuevo—. Pero
derivarlo **sólo** del contenido tiene un fallo con nombre propio:

> Veinte intentos de contraseña fallidos del mismo usuario, en el mismo segundo,
> contra el mismo servicio, producen **veinte líneas idénticas byte a byte** —RFC
> 3164 fecha con resolución de segundo—. Un identificador de sólo contenido las
> fundiría en una, y la detección de fuerza bruta vería un intento aislado donde
> hubo veinte.

Por eso cada evento lleva **ancla**: de dónde salió exactamente dentro de su
origen. El desplazamiento y el inodo en un fichero, el número de secuencia en
journald, el identificador de registro en EVTX, el `eventID` en CloudTrail. Dos
entregas del mismo registro comparten ancla; dos hechos distintos, no.

El ancla de fichero lleva **el inodo, no la ruta**: la línea 500 de `auth.log` de
hoy y la de ayer están en la misma ruta y en el mismo desplazamiento.

---

## Memoria acotada de extremo a extremo

Ninguna cola crece sin límite en ningún punto. La capacidad del endpoint sale del
**presupuesto del host** (`Componente::Ingesta`), no de una constante inventada.

### Qué pasa cuando se llena, y por qué NO es «tirar lo más viejo»

Descartar lo más antiguo, aplicado sin matices, es un agujero con nombre:
**quien pueda generar volumen puede expulsar evidencia**. Un atacante que acaba
de entrar sólo tiene que provocar unos miles de líneas para que la que lo delata
salga de la cola antes de subir.

La política tiene dos escalones, y el orden importa:

1. **Entre prioridades distintas**, se tira lo que menos cuesta perder: un evento
   de seguridad entra desalojando log de aplicación. Esto no sirve para expulsar
   evidencia — el log de aplicación es justo lo que un atacante no necesita
   conservar.
2. **Dentro de la misma prioridad**, se **rechaza lo nuevo**. Rechazar falla
   ruidosamente hacia quien produce; descartar lo viejo falla en silencio y borra
   lo que ya estaba a salvo.

Y el vaciado es **ponderado**, no estrictamente por prioridad: con vaciado
estricto, un chorro sostenido de eventos de seguridad deja el log de aplicación
parado para siempre. Cada vuelta reparte siete huecos: cuatro, dos y uno.

### Hasta dónde llega la contrapresión, sin adornos

| Origen | Qué pasa al frenar |
|---|---|
| Fichero | El fichero sigue creciendo en disco y se lee luego. **No se pierde nada**, se retrasa |
| syslog sobre TCP | El búfer del socket se llena, la ventana de TCP se cierra y **el emisor deja de poder enviar**. Contrapresión de extremo a extremo de verdad |
| syslog sobre UDP | **No hay contrapresión posible** —el protocolo no la tiene— y el núcleo tira datagramas. Se **declara**, porque es la única forma de que alguien sepa que ese aparato necesita TCP |
| journald y EVTX | Son ficheros: se retrasa la lectura |

---

## El plano de control

```text
  entrada --> ADMISION --> DEDUPLICACION --> ORDEN --> correlación
```

**La admisión va primera** porque es la única etapa de coste constante por
evento: ponerla detrás significaría pagar el resumen y la búsqueda de un evento
que se iba a rechazar, que es exactamente lo que un cliente ruidoso necesita.
**La deduplicación va antes que el orden** porque el reordenador tiene cota de
memoria: llenarla con duplicados obligaría a emitir eventos **legítimos**
desordenados.

### Por qué la deduplicación NO es un filtro de Bloom

Es la respuesta habitual a «desduplicar mil millones de identificadores con poca
memoria», y aquí sería un **error de seguridad**.

Un falso positivo de un Bloom significa «ya lo he visto» cuando no es cierto. Y
lo que se hace con un duplicado es **tirarlo**. O sea: un falso positivo **borra
un evento único**, en silencio y sin saber cuál.

La estructura de aquí es **exacta**: un conjunto acotado con ventana temporal. Su
fallo posible es el contrario —un duplicado que llega después de que su
identificador saliera de la ventana pasa— y es inofensivo: el analista ve dos
veces lo mismo, y se cuenta.

> **Falso positivo: se borra evidencia. Falso negativo: se ve dos veces lo
> mismo.** No son intercambiables, y por eso la estructura no es intercambiable.

### Dos cubos por inquilino, no uno

Con un solo cubo de fichas, un cliente que emita millones de líneas de log de
aplicación agota su cuota, y a partir de ahí **su propia telemetría de seguridad
tampoco entra**. El atacante que esté dentro de ese cliente no necesita hacer
nada más: genera ruido en una aplicación cualquiera y sus propias huellas dejan
de subir.

Por eso cada inquilino tiene un cubo **general** y una **reserva** que sólo pueden
usar los eventos de prioridad de seguridad. Y la reserva también está acotada:
inundar con eventos marcados como de seguridad choca con ella, así que la
etiqueta no sirve de llave.

La aritmética de los cubos es **entera**, no en coma flotante: dos nodos del
plano de control decidiendo distinto sobre el mismo evento es un fallo que nadie
reproduce.

---

## Los muros, declarados

**(a) La compresión de journald.** systemd comprime los campos grandes con tres
algoritmos. Aquí se descomprime **LZ4**, implementado en el propio crate
—cuarenta líneas de LZ77, cero dependencias—. **XZ y ZSTD no**: meter un
descompresor de zstd en el proceso más privilegiado de la máquina es añadir miles
de líneas de análisis de formato binario, y eso es una decisión que se toma a
propósito o no se toma. El campo afectado se entrega **marcado** con el algoritmo
que haría falta y se cuenta. Como systemd sólo comprime por encima de 512 bytes,
lo que queda fuera son trazas largas, no las claves con las que se clasifica.

**(b) El texto legible de un suceso de Windows no está en el EVTX.** Lo que el
visor de sucesos muestra como «La cuenta no pudo iniciar sesión» vive en una
tabla de mensajes dentro de la DLL del proveedor, en la máquina de origen y en su
idioma. Se analiza la **estructura entera** —BinXML, plantillas y sustituciones,
cada valor con su nombre— y el significado lo pone un **catálogo** de
identificadores que, además, es más fiable que el texto: un `4625` es un fallo de
autenticación en alemán igual que en castellano; su frase, no.

**(c) Los registros de nube se ingieren en el plano de control.** No salen de
ninguna máquina del cliente. Ponerlos en el agente obligaría a elegir un endpoint
arbitrario que tendría credenciales de la nube entera: exactamente el activo que
un atacante busca en un endpoint.

---

## Qué se comprueba, y contra qué

| Comprobación | Contra qué |
|---|---|
| syslog RFC 5424 y 3164 | Los ejemplos **literales** de los RFC, campo a campo |
| El día de una cifra va rellenado con espacio | `Oct  1` tiene **dos** espacios: quien parta por espacios se desalinea entero |
| El 31 de diciembre leído el 1 de enero | RFC 3164 no lleva año; ponerlo mal saca el incidente de nochevieja de toda ventana |
| El enmarcado de RFC 6587 | Si el receptor adivina, el atacante mete un salto de línea en una trama contada y **parte un registro en dos**, con la segunda mitad leída como trama nueva cuya prioridad elige él |
| journald | Ficheros de diario construidos **byte a byte** con el formato real, incluidos los hostiles |
| Cadena de vectores que se muerde la cola | El recolector giraría para siempre sin leer nada nuevo y **sin fallar** |
| EVTX | Ficheros construidos byte a byte: cabecera, trozos, registros, BinXML, plantillas y sustituciones |
| Documento anidado dos mil veces | Agota la pila del agente con un fichero de 300 bytes |
| Rotación a mitad de lectura | Ficheros reales en disco, con inodos reales y escritura en la franja ciega |
| Reinicio en medio de la ingesta | Ni pierde ni repite: `fsync` y sustitución atómica de verdad |
| Emisor más rápido que el receptor | 100.000 eventos contra una cola de 64 KiB, midiendo la ocupación en **cada** vuelta |
| Expulsión de evidencia | Un delator entra primero; el atacante genera 30.000 eventos de las tres prioridades; el delator sigue ahí |
| Aislamiento entre inquilinos | Un cliente satura su cuota y otro entra sin enterarse |
| Ataque repartido en dos días | La separación que sale por el otro lado sigue siendo de un día, no de un segundo |
| Nube | Documentos reales de CloudTrail, Azure Activity y GCP Audit |

---

## Lo que esta fase **no** hace

- **No resuelve plantillas de mensaje de Windows.** Ver el muro (b).
- **No descomprime XZ ni ZSTD.** Ver el muro (a).
- **No inventa una hora cuando el registro no la trae.** Se marca `DeLlegada` y
  quien correlacione sabe que ahí no puede fiarse del orden.
- **No adivina el formato de un fichero de texto plano.** Se clasifica por
  contenido y la hora es la de lectura, marcada como tal. Fingir que se extrajo
  una hora de un formato desconocido sería inventarse el orden de los hechos.
