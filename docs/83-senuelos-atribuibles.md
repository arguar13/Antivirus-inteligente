# AegisLure — red de señuelos atribuible

**FASE 91.** Crates `crates/aegis-deception` (señuelos y diálogos) y
`crates/aegis-honeytoken` (tokens y procedencia). Puerta:
`tools/verificar-senuelos.sh` (grupo `senuelos` de `tools/ci-local.sh`).

## La pregunta que un tarro de miel normal no contesta

Un señuelo cuenta visitas. Eso responde «¿me está mirando alguien?», que es útil
el primer día y deja de serlo enseguida, porque en internet la respuesta es
siempre que sí.

La pregunta que importa en un incidente es otra: **¿por dónde entraron, y dónde
ha estado después lo que se llevaron?** Y esa sólo se contesta si lo que el
señuelo entrega es único y está atado al sitio del que salió.

## Cero falsos positivos, por construcción

No es una promesa de calibración. Un detector normal tiene que decidir si un
tráfico legítimo es sospechoso, y por eso siempre se equivoca en algún caso. Un
señuelo invierte el problema: **el servicio no existe**. Nadie tiene motivo para
conectar a un puerto que no publica nada, así que cualquier conexión es no
autorizada por definición. La única fuente real de ruido —los escáneres
autorizados de la propia organización— se conoce por dirección y va en la lista
de exclusión, no en una heurística.

El mismo argumento vale del lado de los tokens: un disparo exige que aparezca un
marcador **registrado**, no «algo que parece una credencial». Y un marcador de
otra flota no dispara, porque va firmado con HMAC sobre el secreto de flota: quien
conozca el formato no puede sembrar marcadores propios y mandarnos a perseguir
fantasmas.

## Alta interacción sin nada que encarcelar

Un señuelo de baja interacción acepta, saluda y cierra. El atacante ve que no
responde a nada, lo descarta y se va; lo que interesa —qué herramienta usa, qué
credenciales prueba, qué hace cuando cree haber entrado— no llega a pasar.

Aquí los 19 señuelos **completan el protocolo** varios turnos. Pero «alta
interacción» **no** significa lo que significa en Cowrie: no hay sistema operativo
detrás, no se ejecuta nada y no se escribe nada. Un diálogo es una **máquina de
estados pura** que transforma bytes en bytes. La jaula no puede fallar porque no
hay jaula: no hay nada dentro de lo que escaparse, y eso se comprueba **por
ausencia** sobre el código de `src/dialogos/` —si `Command` no aparece, no hay
proceso hijo que confinar, lo intente quien lo intente—.

Es la invariante 12 del producto —la ausencia es la frontera— aplicada aquí, y es
la única clase de garantía que no depende de que el código de comprobación esté
bien.

### Hasta dónde llega cada familia, y por qué justo ahí

Cada diálogo avanza hasta el punto en que el paso siguiente exigiría criptografía
de verdad. Y resulta que **lo más valioso de cada protocolo se entrega antes**:

| Familia | Hasta dónde | Lo que se saca |
|---|---|---|
| SSH | versiones y `KEXINIT` | la lista completa de algoritmos del cliente: la huella HASSH, que identifica la herramienta aunque mienta en el banner |
| Telnet, FTP | sesión aceptada | **usuario y contraseña en claro**, y qué hace después de entrar |
| RDP | petición X.224 | la cookie `mstshash`, con el **nombre de usuario** que iba a usar |
| SMB | `SESSION_SETUP` con NTLMSSP | usuario, dominio y el **NTLMv2** contra un reto nuestro fijo |
| VNC | reto de autenticación | la respuesta al reto, que con el reto conocido da la contraseña que probaron |
| HTTPS | `ClientHello` | el **SNI** —qué máquina buscaban— y la huella de suites |
| Web | petición completa | rutas, agente, y las credenciales de `Authorization` y del formulario |
| Bases | saludo y autenticación | usuario, base, aplicación cliente y las primeras consultas |
| Industrial | orden completa | **si venía a leer o a escribir** |

Los retos son **fijos y conocidos a propósito** (VNC, NTLM, la sal de MySQL). No se
autentica a nadie, así que aleatorizarlos no aportaría nada, y en cambio se
perdería poder trabajar después la respuesta que mandó el atacante, sin prisa y
sin él delante.

## Lo que separa al que mira del que toca

En una red de planta no hay tráfico legítimo hacia una dirección que no existe.
Un autómata que nadie ha configurado y que recibe una lectura de registros es, sin
ambigüedad, alguien que no debería estar ahí.

Y ahí se puede distinguir lo que en una oficina no: una lectura es
reconocimiento; una escritura de bobinas, un `parar CPU` de S7, un
`reinicio-en-frío` de DNP3 o un `CONFIG SET dir` de Redis son intentos de actuar.
En una planta esa diferencia **no es un grado de severidad: es otra clase de
incidente**. Por eso `Revelacion::OrdenDeEscritura` es una variante propia y no un
campo booleano dentro de otra cosa.

## Procedencia por destino: el corazón de la fase

`Atribucion` lleva **dónde** se sembró, y el destino entra en el cómputo del
marcador:

```rust
pub struct Atribucion {
    pub host: String,
    pub destino: Destino,   // fichero, memoria, DNS, API, fila de tabla, señuelo
    pub token_id: u32,
}
```

La consecuencia es que la credencial sembrada en `/root/.pgpass` y la sembrada en
la fila 7 de `clientes` **son credenciales distintas**. Cuando una aparece, el
sitio del que salió está dentro de ella y no hay que consultar nada.

Que no haya tabla al lado es el punto. Una tabla se desincroniza, se pierde con la
máquina, y se la lleva por delante quien borre registros. Por lo mismo se
eliminó el `HashMap<ruta, Atribucion>` que había junto al registro: **el registro
es la única fuente**, y una ruta que estuviera en una y no en la otra era o una
alerta que no salta o una que no se puede atribuir.

La **clase va primero** en los bytes del destino. Sin ella, un fichero llamado
`prod` y una base llamada `prod` darían los mismos bytes y el mismo marcador — y
dos destinos con el mismo marcador es exactamente perder la procedencia.

De los seis destinos, **sólo el DNS delata sin que toquen la máquina**: los demás
se disparan con el atacante todavía dentro; ése significa que la credencial ya
salió de la organización. La distinción cambia la respuesta —uno se contiene, el
otro ya hay que notificarlo—, así que se dice en el tipo y no en un comentario.

## El señuelo como arma contra su dueño

Tres formas, y las tres paradas por construcción.

### 1. Como amplificador

Un servicio que contesta más de lo que le preguntan, sobre un transporte donde el
origen puede falsificarse, manda tráfico a una víctima que no pidió nada — con
nuestra dirección en sus registros. No es teórico: es como se han usado NTP, DNS,
memcached y **BACnet**, que es uno de los protocolos que este producto finge. Su
`Who-Is` mide 8 bytes y su `I-Am` bastante más.

La regla depende del transporte, y eso no es un detalle:

- En **UDP** no hay saludo y **la respuesta nunca es mayor que la pregunta**. El
  factor queda acotado por 1, así que falsificar el origen no sirve de nada.
- En **TCP** el saludo de tres vías verifica el origen, así que la reflexión no
  aplica; ahí lo que se acota es el total absoluto.

La cota la aplica el **envoltorio**, no cada diálogo. Si la aplicara cada diálogo,
el que alguien escriba dentro de un año no la aplicaría — y no fallaría
ruidosamente, amplificaría en silencio. Es la misma técnica que el `Limpio` de la
FASE 90: el único camino de los bytes al cable pasa por un sitio.

**Medido, el peor mensaje de cada señuelo** (no la media: una media se hunde sola
mandando basura grande que no se contesta, y taparía justo el mensaje que sí
amplifica, que es el único que el atacante va a repetir):

| Transporte | Peor | |
|---|---|---|
| UDP (bacnet) | **x1.00** | la cota es vinculante y se alcanza |
| TCP (telnet) | infinito | legítimo: el origen lo verifica el saludo de tres vías |

### 2. Como forma de agotar el agente

Techo de turnos (10), techo de estado por diálogo (4 KiB), techo de orígenes
recordados (4096) y cupo global de bytes por segundo.

**El limitador es uno para toda la red, no uno por conexión.** La primera versión
lo tenía dentro de la conversación, y la prueba de autoataque lo enseñó: un cubo
de fichas por conexión no limita nada, porque quien quiera pasarse cuelga y vuelve
a llamar con el cubo lleno. Medido: un origen ruidoso se queda en sus 50 mensajes
por segundo **abriendo conexiones nuevas cada vez**, y el vecino callado sigue
teniendo servicio.

### 3. Como vía de entrada

La que hunde a los tarros de miel de alta interacción clásicos. Aquí no hay jaula
porque no hay nada que encarcelar. Ver arriba.

## Lo que encontró el autoataque

La suite de autoataque no es decorativa: encontró tres defectos reales, todos
corregidos de raíz.

| Defecto | Corrección |
|---|---|
| **Pánico remoto**: `&otra[..otra.len().min(16)]` corta un `String` por índice de byte. Mandar `ññññ…` al señuelo de FTP o de Redis **tumbaba el agente** — apagar la defensa mandando un paquete raro es el mejor resultado posible para el atacante | `primeros()`, que cuenta **caracteres**; no hay borde que caiga en mal sitio |
| El limitador vivía en la conversación, así que colgar y volver a llamar daba cubo nuevo | limitador compartido por la red, pasado por parámetro |
| El barrido de amplificación medía la **media** y todo salía x0.00 | se mide el **peor mensaje**, y el corpus incluye mensajes válidos de cada protocolo — sin ellos sólo se medía el camino de rechazo |

Y en el registro de tokens, dos más, encontrados leyendo el código heredado de la
FASE 52:

| Defecto | Corrección |
|---|---|
| `Registro::buscar_en` recorría el bloque **una vez por token**: 10 000 tokens y un volcado de 4 MB son 40 GB de comparaciones, y las dos magnitudes las mueve el atacante | una sola pasada con prefiltro de dos bytes; el coste deja de depender de cuántos tokens hay. Misma técnica que el redactor de la FASE 90 |
| Los hallazgos salían en orden de `HashMap`: **distinto en cada ejecución** | salen en el orden en que aparecen en los datos. Una alerta que no se puede reproducir no se puede discutir |
| El disparo de un honey-file rellenaba con `Marcador([0u8; 16])`, así que decía «se tocó un señuelo» sin decir cuál — y todos los rellenos de ceros son el mismo marcador | la ruta **es** el destino, y el registro devuelve el marcador auténtico |

## Lo medido

| Medida | Cifra |
|---|---|
| Señuelos que conversan por un socket real | **19 de 19** |
| Entradas hostiles sin pánico | **10 887** contra 19 señuelos |
| Amplificación, peor mensaje en UDP | **x1.00** |
| Ficheros de diálogo sin ejecución, ficheros, sockets ni reloj | **5 de 5** |
| Inundación por socket | 100 conexiones hostiles; la red sigue en pie y sigue contando |
| Coste de atender lo hostil frente a lo normal | no crece por byte: el atacante no multiplica el coste eligiendo el relleno |

## La comparación, medida de un lado y citada del otro

**19 protocolos aquí, 2 en Cowrie** (SSH y Telnet) — y ese recuento **no es la
comparación**, porque se mueve añadiendo diálogos triviales. No se ha ejecutado
Cowrie contra este corpus.

Lo primero que se escribe es **lo que el otro hace mejor**, porque una comparación
que empieza por lo propio es un folleto. En SSH y Telnet, que es donde compiten,
**Cowrie saca más**: da un intérprete de órdenes completo, un sistema de ficheros
falso y persistente, descarga de verdad los binarios que el atacante pide, graba
la sesión entera de forma reproducible, y tiene años de despliegue público
acumulados, que es algo que no se escribe.

Lo de este lado: 19 protocolos con los 5 industriales, un token distinto por
señuelo y por puerto, la cota de amplificación estructural, el limitador
compartido, ninguna ejecución en ningún señuelo, el mismo identificador de entidad
que el resto del producto, y la distinción entre leer y escribir.

**El precio de cada elección**, que es lo que de verdad se compara: se cambia
profundidad en SSH y Telnet por no tener un intérprete que encarcelar. Cowrie saca
lo que el atacante **hace**; éste saca **quién es, con qué viene y por dónde
volverá a aparecer lo que se lleve**. Son dos preguntas distintas.

## El muro, declarado

- **Ningún señuelo completa la criptografía.** SSH para en el `KEXINIT`, TLS en el
  `ClientHello`, OPC-UA en el `ACKNOWLEDGE`. Es donde acaba lo que se puede fingir
  sin construir un riesgo.
- **No se ha ejecutado Cowrie contra este corpus.** Se comparan propiedades.
- **El señuelo de BACnet se prueba por TCP**, porque el oyente de la red es de
  TCP; lo que importa de él —que no amplifique— se mide en el diálogo, que es
  donde vive la cota, y con su mensaje real.
- **Aceptar el acceso a la tercera credencial en Telnet es una decisión**, no un
  descuido: aceptar a la primera levanta sospechas —nadie acierta siempre— y no
  aceptar nunca pierde lo que el atacante hace cuando cree haber entrado.
- **La siembra en memoria ajena sigue tras la feature `inyeccion`.** Aquí se acuña
  y se registra; escribir en la memoria de otro proceso necesita privilegios y un
  objetivo vivo, y el CI declara que no se ejerció.
- **El señuelo no abre canales de datos que le pidan.** Un `PASV` de FTP se
  contesta con un `425`: abrir un puerto porque lo pida quien está al otro lado es
  dejarle elegir recursos del agente.
