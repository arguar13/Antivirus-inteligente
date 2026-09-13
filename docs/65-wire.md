# Módulo 65 — AegisWire: disección semántica de protocolos

> Componentes: `crates/aegis-wire/`, `tools/verificar-wire.sh`.

## 65.1 Qué se veía antes y qué se ve ahora

Hasta esta fase, AegisCore veía la red como **metadatos**: quién habla con quién,
por qué puerto, cuántos bytes, en qué momento. Con eso se detecta un escaneo o
una exfiltración por volumen, y poco más.

El problema es que el tráfico que de verdad importa está diseñado para parecer
normal en metadatos. Un C2 moderno va por HTTPS al 443, con volumen de navegación
y a horas de oficina. En metadatos es un navegador. La diferencia sólo aparece
cuando se mira **dentro**: el SNI que pide, la huella de su implementación TLS,
el certificado que le presentan, los nombres que resuelve antes.

Esta fase convierte bytes crudos en **hechos con significado**:

| Antes (metadatos) | Ahora (hechos) |
|---|---|
| `10.0.0.5 → 8.8.8.8:53, 74 bytes` | consulta DNS de `x3f9a2.tunel.attacker.com`, entropía 4,3 bits/carácter, etiqueta de 52 |
| `10.0.0.5 → 1.2.3.4:443, 2 KB` | `ClientHello` con SNI `cdn.legitimo.com`, ALPN `h2`, **JA3 `a0e9f5…`**, certificado autofirmado |
| `10.0.0.5 → 10.0.0.9:445, 1 MB` | `SMB2 CREATE` de `\\srv\C$\Windows\Temp\a.exe` |
| `10.0.0.5 → 10.0.0.2:88, 400 bytes` | `AS-REQ` de `admin@DOM` para `krbtgt/DOM` con **cifrado RC4** |
| `8.8.8.8 → 10.0.0.5, 4 KB` | fichero `informe.pdf` que **en realidad es un PE**, SHA-256 `9f2c…` |

## 65.2 La decisión que más cambia lo que el sensor ve

**El protocolo se decide por CONTENIDO, no por puerto.**

Identificar por puerto es cómodo y falla exactamente donde importa. El malware
pone su C2 en el 443 *precisamente porque* todo el mundo asume que el 443 es TLS.
Un sensor que confía en el puerto intentará disecar como TLS algo que no lo es,
no reconocerá nada, y **no dirá nada**.

Aquí el orden es:

1. **Contenido.** ¿Empieza por un registro TLS? ¿Por un método HTTP? ¿Por
   `\xFESMB`? ¿Por una cabecera DNS coherente?
2. **Puerto, como pista de desempate.** Sólo si el contenido no dijo nada.
3. **`Desconocido`.** Y eso, en un puerto conocido, **es una señal por sí misma**.

El caso que lo justifica entero: tráfico no-TLS en el 443. Un sensor por puerto
lo da por TLS ilegible y calla. Aquí sale `Desconocido` en un puerto donde
`Desconocido` no debería existir, que es justo el indicio.

## 65.3 La evasión por solape de segmentos TCP

Es el ataque central de la fase, y tiene veintiocho años.

Cuando dos segmentos TCP **se solapan con contenido distinto**, alguien tiene que
decidir cuál se queda:

```
  secuencia 1001, 12 bytes: "GET /publico"    <- el IDS lo ve
  secuencia 1001, 12 bytes: "GET /secreto"    <- misma secuencia, OTRO contenido
```

El sistema operativo del destino aplica **su** política. Si el sensor aplica otra,
reconstruye un flujo que **el endpoint nunca va a ver**, y a partir de ahí todas
sus reglas miran datos que no existieron. No es un fallo de detección: es una
**evasión completa y silenciosa**. La describieron Ptacek y Newsham en 1998 y
sigue funcionando contra productos mal hechos.

### La respuesta: la política es explícita y se declara

No existe «la» política correcta, porque depende del destino. Lo que sí es
incorrecto es tener una política **implícita** —la que salga de cómo se escribió
el bucle— porque entonces nadie sabe cuál es y nadie puede razonar sobre la
evasión.

| `Politica` | A quién imita | Cuándo elegirla |
|---|---|---|
| `PrimeroGana` *(por defecto)* | BSD y Linux moderno para datos confirmados | por defecto, y es la más segura: el atacante no puede reescribir hacia atrás lo que el sensor ya analizó |
| `UltimoGana` | pilas antiguas de Windows | sólo si el destino se comporta así; elegirlo sin saberlo **abre** la evasión en vez de cerrarla |

Hay una prueba que comprueba que las dos políticas reconstruyen de verdad cosas
distintas. Si reconstruyeran lo mismo, la política no existiría.

### La mitad peligrosa: el solape que llega *después*

Un reensamblador que tira los bytes en cuanto los entrega sólo detecta la
contradicción mientras los dos segmentos siguen retenidos. Pero la forma clásica
del ataque es la contraria: el segundo segmento llega **después** de que el
primero se entregara y se analizara.

Sin memoria de lo entregado, ese segundo segmento es **indistinguible de una
retransmisión normal**, y el ataque pasa contado como ruido. Por eso se conserva
una ventana acotada de bytes ya entregados (`MAX_HISTORIA`, 4 KiB por sentido) y
el solape se **compara byte a byte**:

| Resultado de la comparación | Cómo se cuenta | Por qué |
|---|---|---|
| Bytes iguales | `solapes_identicos` | retransmisión de libro; contarla como ataque enterraría la señal en ruido |
| Bytes **distintos** | `solapes_contradictorios` | **la señal.** El tráfico legítimo no hace esto |
| Más atrás de la ventana | `retransmisiones` | no se conserva, así que **no se afirma nada**: es lo único honesto |

Guardar el flujo entero sería exactamente la memoria que el atacante quiere que
se reserve. El límite está puesto y **se declara**, en vez de disimularse.

## 65.4 Cotas: una cota por flujo no es una cota

El número de flujos, la secuencia TCP, la longitud de un campo, la profundidad de
un DER, el tamaño de un fichero: **los elige quien manda los bytes**.

Cada uno tiene su tope. Pero el hallazgo de esta fase es que **los topes por flujo
no acotan nada**, porque el atacante controla también el número de flujos, y lo
que se reserva de verdad es el producto:

```
100.000 flujos × 2 sentidos × 1 MiB retenido = 200 GB
```

en un agente cuyo presupuesto **entero** son 45 MB. Medido en la propia suite:
3.000 flujos reteniendo **un solo** segmento de 1.400 bytes cada uno ya reservan
4,2 MB, que extrapolados al tope de flujos son **133 MB** — con el atacante
haciendo el mínimo esfuerzo posible.

Por eso hay **dos topes globales**, y son los que de verdad sostienen el
presupuesto:

| Tope | Valor | Qué acota |
|---|---|---|
| `flujo::MAX_MEMORIA` | 8 MiB | todo lo retenido por los reensamblados, sumado |
| `motor::MAX_MEMORIA_APP` | 4 MiB | todos los buffers de mensajes a medio construir |

Cuando se llega al techo se expulsa por inactividad —nunca el flujo que se acaba
de tocar— y **se cuenta** en `expulsados_por_memoria`, aparte de
`expulsados_por_sitio`, porque las causas son distintas: llenar la tabla de flujos
vacíos es un ataque de apertura masiva; llenar la memoria con pocos flujos es un
ataque de retención.

Y expulsar un flujo suelta **también** su buffer de aplicación y su transferencia
en curso. Sin eso no sería un peor caso teórico: sería una fuga, una por cada
expulsión.

## 65.5 Enmarcar: un mensaje se cuenta una vez, y se pasa al siguiente

El disector siempre empieza por el principio del buffer. Eso obliga a **apartar
lo ya interpretado**, y no hacerlo tiene dos consecuencias, las dos malas:

1. **Cada paquete nuevo vuelve a emitir los mismos hechos.** Ruido que entierra
   lo que sí es nuevo, y detecciones infladas que el analista tiene que descartar
   a mano.
2. **El segundo mensaje no se llega a ver nunca.** Con reutilización de conexión
   —lo normal desde HTTP/1.1— la primera petición nunca se aparta, así que el
   sensor repite la primera y queda ciego para el resto de la sesión. Es gratis
   de explotar: basta con encadenar la descarga detrás de algo inocente.

Por eso cada tramo se enmarca:

| Protocolo | Cómo se sabe dónde acaba | Si no se puede |
|---|---|---|
| HTTP | cabeceras hasta la línea en blanco + `Content-Length` | sin longitud declarada (`chunked`, cierre de conexión) **no se enmarca**, y está declarado |
| TLS | cabecera de registro: tipo, versión y longitud | un `ClientHello` **partido entre registros** se sigue acumulando, en vez de apartarse a medio leer |
| Los demás | si el disector sacó algo **concluyente**, entendió el tramo | un `NoAnalizable` **no** cuenta como entendido: es justo lo que emite un mensaje que llegó a medias |

El caso de TLS merece decirse aparte: un registro de datos de aplicación está
cifrado y no hay **nada** que sacar de él, pero saber dónde acaba sí importa. Sin
eso, el motor guarda cada byte cifrado de cada sesión esperando entenderlo algún
día —y las sesiones TLS son la mayoría del tráfico—, así que la memoria se va en
justamente lo único que nunca va a poder interpretar. Enmarcar lo ilegible es lo
que permite no pagar por ello.

## 65.6 Huellas TLS: reconocer la implementación sin descifrar nada

De una sesión TLS no se ve el contenido — y esta fase **no finge verlo**. Lo que
sí se ve es cómo el cliente se presenta, y eso identifica la **implementación**,
no el usuario:

- **JA3**: MD5 de `versión,cifrados,extensiones,curvas,formatos` del `ClientHello`.
- **JA3S**: lo mismo para la respuesta del servidor.
- **JA4**: el sucesor, con las suites **ordenadas** —así no cambia si el cliente
  baraja el orden, que es cómo se evade JA3— y la versión real leída de la
  extensión `supported_versions`, no del campo clásico, que en TLS 1.3 miente por
  compatibilidad.

Filtrar **GREASE** es obligatorio y no un detalle: sin ese filtro, la huella de
Chrome cambia en cada conexión y no sirve para reconocer nada.

> El MD5 de `md5.rs` está implementado a mano y documentado como **etiqueta de
> interoperabilidad JA3 y nada más**. JA3 lo exige por definición del estándar.
> Jamás se usa para seguridad.

## 65.7 Extracción de ficheros: por magia, nunca por lo que se declare

Un fichero que llega por la red se puede ver **dos veces**: cuando viaja y cuando
se escribe. Verlo cuando viaja tiene tres ventajas que el disco no da:

1. Llega **antes** de existir en la máquina.
2. Se ve aunque el destino nunca lo escriba —ejecución en memoria, carga
   reflectiva, un descargador que no toca el disco—, que es justo lo que hace el
   malware moderno para no dejar rastro.
3. Se ve el **contexto**: de dónde venía, por qué protocolo, en qué sesión.

El tipo sale **de los bytes**. El nombre y el `Content-Type` los escribe quien
manda el fichero: un `application/pdf` sobre un PE no es un caso raro, **es la
técnica**. Y la contradicción entre lo declarado y lo real se emite como señal
propia (`fichero-tipo-contradictorio`, `fichero-nombre-engañoso`), porque mentir
sobre el tipo es en sí mismo un indicio.

Dos detalles que importan:

- **El hash se calcula al vuelo.** El tamaño lo elige el atacante, así que guardar
  el fichero para hashearlo al final sería dejarle reservar lo que quiera. Un
  cuerpo de 8 MB atraviesa el motor sin que su memoria pase de 256 KB. Y el hash
  de un fichero troceado en 1.400 paquetes es el **mismo** que el del fichero
  entero: si no lo fuera, trocear la descarga evadiría la comparación contra
  indicadores, y eso es gratis para el atacante.
- **La ISO se reconoce en flujo.** Su magia vive 32 KiB dentro del fichero.
  Guardar 32 KiB de cada transferencia para poder mirarla sería justo la memoria
  que el atacante quiere que se reserve; se capturan **cinco bytes al vuelo**
  cuando el flujo cruza ese punto. Las ISO son un vehículo de entrega actual
  —sirven para saltarse la marca de procedencia de Windows—, así que renunciar a
  verlas no era una opción.

## 65.8 Sans-io, y por qué eso hace verificable la fase

`motor::Motor` no abre sockets, no toca la NIC y no tiene reloj propio: el tiempo
entra como parámetro. Se le dan bytes y devuelve hechos.

La consecuencia es la que importa: **cada ataque de esta fase se construye entero
en una prueba**, con paquetes IPv4+TCP escritos byte a byte y metidos por el mismo
sitio por el que entraría el tráfico real. Sin red, sin privilegios y sin
condiciones de carrera.

Y cada prueba de ataque comprueba **las tres cosas juntas**:

1. que reconstruye lo que reconstruiría el destino,
2. que **delata** el intento, y
3. que sigue vivo y acotado después.

Un sensor que resiste un ataque sin contarlo deja al analista sin saber que le
atacaron. Eso no es defensa: es un agujero con buena cara.

## 65.9 Cero dependencias externas nuevas

No es una postura de estilo. Un disector analiza bytes que escribe el atacante,
sin autenticación previa y a velocidad de línea: es la superficie de ataque más
expuesta del producto, y es exactamente donde ClamAV, Suricata y Zeek acumulan su
historial de CVE de desbordamiento.

El árbol entero de terceros de este crate son **15 crates**, que son el cierre
completo de `sha2` —que el agente ya enlazaba, y que JA4 necesita por definición
del estándar— y de `thiserror`. `make ci` lo comprueba con `cargo tree` y la lista
está **enumerada a propósito** en vez de con un patrón laxo: si mañana entra algo,
tiene que doler.

Además, el crate es `#![forbid(unsafe_code)]` y sus pruebas corren bajo
**AddressSanitizer** en `tools/sanitize.sh`. Ahí ASan no busca `unsafe` propio:
busca que ningún índice calculado a partir de bytes hostiles se salga de su
buffer.

## 65.10 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Evasión por solape TCP | **Sí, entera** | se construyen los segmentos contradictorios y se comprueba qué reconstruye y qué delata |
| Solape sobre terreno **ya entregado** | **Sí** | ventana acotada; más atrás se cuenta como retransmisión y **se dice** |
| Que la política cambia el resultado | **Sí** | las dos políticas reconstruyen cosas distintas, o la política no existiría |
| Contrabando HTTP (CL.TE) | **Sí** | se manda el mensaje con las dos cabeceras y se comprueba la anomalía |
| Bucle de punteros DNS | **Sí** | se construye el bucle y se comprueba que corta con progreso estricto |
| DER anidado a propósito | **Sí** | recorrido **iterativo con pila explícita**; un disector recursivo revienta aquí |
| Cadena de extensiones IPv6 | **Sí** | se encadenan hasta pasar el tope y se comprueba que **declara** que no pudo llegar |
| Huellas JA3/JA3S/JA4 | **Sí** | vectores byte a byte, con GREASE dentro |
| Extracción de ficheros | **Sí** | descarga completa por paquetes, hash contrastado contra el del fichero entero |
| Cotas de memoria | **Sí, medidas** | se ejerce el ataque de retención y se comprueba el techo global |
| Ausencia de pánico | **Sí** | miles de paquetes pseudoaleatorios por las dos entradas del motor |
| Captura real desde la NIC | **No aquí** | el motor es *sans-io* a propósito; la captura vive en `aegis-net` ([FASE 39](39-cuarentena.md)) |
| Defragmentación **IP** | **No**, y se declara | el datagrama se marca como fragmentado y los fragmentos posteriores **no** se analizan como transporte — leerlos así interpretaría carga útil como puertos y secuencia, e inyectaría bytes elegidos por el atacante en el reensamblador |
| Cuerpos HTTP `chunked` | **No todavía** | sólo se extrae con longitud declarada; un cuerpo sin `Content-Length` no produce fichero |
| Contenido **cifrado** | **No, y no se finge** | de TLS se ve el saludo y el certificado; lo de dentro lo ve [`aegis-l7hunter`](61-l7hunter.md) con uprobes |

La última fila es la que más importa decir en voz alta: **esta fase no descifra
nada**. Lo que da es el metadato de la sesión cifrada —huella, SNI, certificado—
que es justo lo que sirve para reconocer una familia de C2 sin romper el cifrado
de nadie.

## 65.11 Qué habilita

El registro de conexión (`RegistroConexion`) tiene un formato versionado y de
campos estables, pensado para que lo consuma el plano de control sin acoplarse a
la implementación. Con eso, la caza deja de ser «busca esta IP» y pasa a ser
«busca todas las sesiones TLS con esta huella JA3», «busca quién resolvió nombres
con entropía alta», «busca qué máquinas recibieron un PE anunciado como PDF».

Y es la base directa de la FASE 71 (AegisIPS): no se puede bloquear en línea lo
que no se sabe leer.
