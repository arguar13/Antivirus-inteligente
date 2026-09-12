# Módulo 60 — AegisMemHunter: caza en memoria por VAD y tabla de páginas

> Componentes: `crates/aegis-memhunter/`, `tools/verificar-memhunter.sh`.

## 60.1 El disco dejó de ser donde vive el malware

Cobalt Strike, Brute Ratel y cualquier framework de post-explotación moderno no
dejan fichero. Usan una de estas dos técnicas:

- **Carga reflexiva** (*Reflective DLL Injection*): mapean su módulo a mano en
  memoria anónima, resolviendo importaciones y reubicaciones por su cuenta, sin
  pasar por el cargador del sistema. No hay fichero, y el módulo no aparece en
  ningún inventario de módulos cargados.
- ***Module stomping***: mapean una DLL legítima y sobrescriben su sección de
  código **ya en memoria**. Para cualquier herramienta que mire el disco, el
  módulo es real: la ruta existe, el fichero está intacto y **su firma sigue
  siendo válida**. Lo que se ejecuta no tiene nada que ver con él.

Un escaneo de disco no ve ninguna de las dos. Un inventario de módulos cargados
tampoco ve la segunda.

## 60.2 La idea: preguntarle al hardware, no al proceso

Este módulo **no lee la memoria del proceso** para compararla con el disco. Eso
ya lo hace [`aegis-evasion::hollow`](../crates/aegis-evasion/src/hollow.rs),
cuesta cientos de kilobytes por región y responde a otra pregunta: *«¿en qué se
diferencia?»*. Aquí la pregunta es *«¿hay algo que mirar?»*, y se responde con los
**metadatos de la memoria**, que el atacante no controla porque los mantiene el
kernel y, en última instancia, la MMU:

| Sistema | Fuente | Qué da |
|---|---|---|
| Windows | los **VAD** (*Virtual Address Descriptors*) vía `VirtualQueryEx` | tipo de respaldo (`MEM_IMAGE`/`MEM_MAPPED`/`MEM_PRIVATE`) y la protección **inicial** además de la actual |
| Linux | `/proc/<pid>/smaps` | por región: cuánta memoria ha dejado de pertenecer al fichero (`Anonymous:`) |
| Linux | `/proc/<pid>/pagemap` | por **página**: una entrada de 64 bits de la tabla de páginas |

## 60.3 La detección que define esta fase, al bit

En `pagemap`, el **bit 61** de la entrada de una página vale 1 cuando la página
está respaldada por un fichero. La deducción, paso a paso:

1. Una región privada respaldada por fichero —`r-xp /usr/lib/libfoo.so`, la
   sección de código de un módulo— empieza con todas sus páginas apuntando a la
   caché de páginas del fichero: **bit 61 = 1**.
2. Escribir en una de esas páginas obliga al kernel a hacer **copy-on-write**:
   asigna una página nueva, copia el contenido y la sustituye. La nueva ya no
   pertenece al fichero: **bit 61 = 0**.
3. Una página de **código** no se escribe nunca en operación normal.

Luego una página **presente**, con el **bit 61 a 0**, dentro de una región de
código respaldada por fichero, significa que *lo que se ejecuta ahí ya no es lo
que hay en el fichero*. Eso es *module stomping*, delatado **sin leer un solo
byte** de la memoria del proceso y **sin abrir el fichero** de disco para
comparar.

Los tres estados no se deducen del manual: se **verifican contra el kernel de la
máquina** en cada `make ci`, construyendo cada caso de verdad.

| Página | bit 61 |
|---|---|
| anónima privada, escrita | 0 |
| respaldada por fichero, sólo leída | 1 |
| respaldada por fichero, **tras copy-on-write** | **0** |

Si un kernel futuro cambiara esa semántica, la detección se volvería
silenciosamente inútil —dejaría de encontrar nada, que es el peor fallo posible en
un EDR— y nadie se enteraría. Se entera el CI.

## 60.4 Por qué buscar RWX ya no sirve

Buscar páginas `RWX` es la detección de manual y está obsoleta desde hace años: el
cargador reflexivo actual mapea `RW`, escribe la carga útil y llama a
`mprotect`/`VirtualProtect` para dejarla `RX`. Cuando el escáner mira, **no hay ni
una página `RWX`**. Aquí se cubren los dos casos y el que de verdad importa:

| Anomalía | Qué la delata | MITRE |
|---|---|---|
| `RwxSinRespaldo` | escritura y ejecución a la vez, sin fichero (el clásico) | T1055 |
| `EjecutableAnonimo` | ejecutable sin fichero **aunque no sea escribible** (el moderno) | T1620 |
| `ImagenReflexiva` | lo anterior **más una cabecera `MZ`/`ELF`** al principio | T1620 |
| `ModuleStomping` | código de módulo con páginas desligadas del fichero | T1055 |
| `PilaOMontonEjecutable` | `[stack]`/`[heap]` con permiso de ejecución | T1055 |
| `ProteccionMutada` | (Windows) nació `RW`, ahora es `RX` | T1055.002 |
| `ImagenSinFichero` | (Windows) `MEM_IMAGE` sin fichero que la respalde | T1620 |

*El* **module stomping** *no tiene sub-técnica propia en ATT&CK; se mapea a T1055,
que es su familia. Inventar un identificador que no existe haría que el analista
lo cruzara con su inteligencia externa y no encontrara nada.*

## 60.5 Lo difícil no es detectar: es no ahogar al analista

Encontrar memoria ejecutable sin fichero detrás es trivial. El problema es que un
sistema real está **lleno** de ella y casi toda es legítima: cada JVM, cada
proceso de Node, cada runtime de .NET y cada navegador generan código en tiempo de
ejecución. Un detector que reporte eso produce cientos de avisos por máquina, y a
la semana nadie los mira.

Hay tres discriminadores, ordenados de más fuerte a más débil:

1. **Una cabecera de imagen en memoria anónima.** Un JIT emite instrucciones
   sueltas; no tiene ningún motivo para escribir una cabecera `MZ` de PE ni un
   `\x7fELF` al principio de su arena. Un cargador reflexivo mapea un módulo
   entero, y la cabecera viaja con él. Es **objetivo**: no depende de saber quién
   es el proceso.
2. **La forma del copy-on-write.** La resolución de **IFUNC** y las reubicaciones
   en texto (`DT_TEXTREL`) provocan copy-on-write sobre páginas de código en el
   arranque de casi todo proceso de glibc, tocando páginas **dispersas** al
   principio del módulo. Sobrescribir el código de un módulo deja un **bloque
   contiguo**. Por eso no se mide sólo el recuento: se mide **el bloque contiguo
   más largo**.
3. **La lista de runtimes con JIT**, que es el más **débil** y por eso sólo **baja
   la severidad, nunca silencia**, y **no aplica a los dos anteriores**. Un
   atacante que se inyecta en un proceso Java no puede volverse invisible por
   estar donde está: una cabecera de imagen o un código de módulo sobrescrito
   dentro de una JVM siguen siendo críticos. Hay una prueba para cada una de esas
   dos cosas.

## 60.6 Un falso positivo que casi se escapa

La primera versión marcaba el **vDSO** como carga reflexiva crítica. El vDSO es
una imagen ELF auténtica que el kernel mapea en **todo** proceso de Linux, sin
fichero detrás: cumplía los tres criterios. Eso habría sido **una alerta crítica
por proceso en toda la flota** desde el primer día.

La corrección no fue subir un umbral, sino modelar lo que faltaba: distinguir los
mapeos que pone **el kernel** (`[vdso]`, `[vvar]`, `[vsyscall]`) de la memoria del
proceso. Es seguro porque la etiqueta sale de `vm_ops->name` del propio kernel y
un atacante no puede hacer que su mapeo se imprima así en `maps`. Y se hizo por
«lo mapea el kernel», **no** por «lleva corchetes»: `[heap]` y `[stack]` siguen
tratándose como memoria del proceso, porque una **pila ejecutable** es una de las
anomalías más graves que hay y una exclusión por corchetes la habría perdido.

Lo encontró la prueba que caza un proceso **real**. Con datos sintéticos no habría
salido nunca.

## 60.7 Rendimiento: triar primero, bajar al bit después

El requisito es latencia de un dígito en milisegundos. Leer `pagemap` del espacio
de direcciones entero de un navegador serían decenas de megabytes de entradas, y
el 99 % de ese espacio no puede contener ninguna de estas anomalías. Por eso el
análisis es en dos etapas:

| Etapa | Fuente | Coste | Qué decide |
|---|---|---|---|
| **Triación** | `smaps` | un parseo de texto | qué regiones merecen mirarse |
| **Confirmación** | `pagemap` | 8 bytes por página, sólo de las candidatas | qué páginas exactas, y si forman bloque |

Sólo bajan a `pagemap` el código de módulo que `smaps` ya delata (`Anonymous:` >
0) y la memoria anónima ejecutable. El decisor resuelve **2 000 regiones —un
navegador— en menos de 10 ms**, y eso se mide en la prueba, no se promete.

Cuando `pagemap` no está disponible, la evidencia de `smaps` alcanza para avisar
pero **no para afirmar dónde**, y el informe lo dice y baja la severidad: no puede
prometer una precisión que no tiene.

## 60.8 Honestidad de validación

**Esta fase no tiene muro en Linux.** Es la diferencia con las fases de hardware
anteriores, y por eso el script de verificación afirma más que los demás.

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Semántica del bit 61 de `pagemap` | **sí** | los tres estados construidos de verdad contra el kernel de la máquina |
| Parseo de `smaps` | **sí** | contra el `/proc/self/smaps` real, y con casos corruptos |
| Carga reflexiva | **sí** | región RWX anónima con cabecera ELF construida en el proceso, cazada por `/proc` auténtico |
| *Module stomping* | **sí** | 32 páginas contiguas de código sobrescritas sobre un fichero mapeado, **comprobando que el fichero en disco queda intacto** |
| Tasa de falsos positivos | **sí** | se caza un proceso **hijo** limpio (`/bin/sleep`); no puede pedir respuesta |
| Umbrales (IFUNC vs. sustitución) | sí | patrones de página disperso y contiguo |
| Latencia | sí | 2 000 regiones, medidas |
| ABI de `MEMORY_BASIC_INFORMATION` | sí, **en compilación** | `const assert` sobre tamaño y los 7 desplazamientos del SDK |
| **Captura de VAD en Windows** | — | `VirtualQueryEx` sobre un proceso ajeno necesita Windows; **gated** |
| Manipulación del propio vDSO | — | exigiría comparar con la imagen prístina del kernel; **no cubierto**, y se dice |

El caso del *stomping* se prueba cazando un proceso **hijo** y no el propio: las
pruebas de este módulo corren en hilos del **mismo** proceso y dos de ellas
fabrican anomalías a propósito, así que medir la tasa de falsos positivos sobre un
proceso ya contaminado no mediría nada. Cazar un proceso ajeno es además el camino
de **producción**: ejercita `process_vm_readv` y la lectura de
`/proc/<otro>/pagemap` de verdad.

El ABI de Windows se verifica en compilación porque un campo desplazado **no rompe
la compilación**: haría que el clasificador leyera una protección donde hay un
tamaño. El síntoma en producción no sería un fallo, sería **un EDR que no ve
nada**, que es infinitamente peor.
