# 78 · AegisWin — el ejecutable de Windows por dentro

> FASE 83. `crates/aegis-pe/`, `tools/verificar-pe.sh`.

## El problema, dicho sin adornos

El agente sabía mirar un proceso de Windows **por fuera** —quién lo lanzó, con
quién habla, qué hace— y **no sabía abrir su fichero**.

Todo lo que un EDR decide sobre un ejecutable antes de dejarlo correr sale de
dentro: si está firmado y por quién, si le han quitado la firma, si le han pegado
algo detrás, si su punto de entrada está donde debería, si viene empaquetado.

Sin eso, la paridad con Linux era de nombre. Allí el agente lee ELF, `/proc` y
los mapas de memoria; en Windows tenía el esqueleto de la SCAL devolviendo
`Unsupported` con el nombre de la interfaz nativa que falta por escribir. Honesto
—no simulaba nada, que es lo importante— y vacío.

## Lo que hay ahora

| | Antes | Ahora |
|---|---|---|
| Leer un PE | no | **PE32 y PE32+**, encabezados, secciones y 16 directorios |
| Huella Authenticode | no | la que Windows compara, con sus tres saltos |
| Localizar la firma | no | tabla de certificados, entrada a entrada |
| Hechos sobre la forma | no | **9 indicios**, cada uno con su falso positivo escrito |
| Entrada hostil | — | **cero** indexación cruda; truncado y mutado en pruebas |

## Las tres decisiones

### 1. Ninguna indexación cruda, en ningún sitio

Este crate lee enteros de desplazamientos que vienen **dentro del propio fichero
que está leyendo**. Es decir: el atacante elige los desplazamientos.

En C eso es una lectura fuera de límites. En Rust sería un pánico, y con
`panic = "abort"` —que es como se compila el agente— un pánico es el proceso
entero muriéndose. **Un EDR que se puede matar mandándole un fichero se
desinstala solo.**

Toda lectura pasa por `Lector`, que comprueba el límite y devuelve un error con
nombre. La aritmética también va acotada: `offset + tamaño` con dos campos de 32
bits que declara el fichero desborda con facilidad, y un desbordamiento
silencioso convierte «apunta 4 GiB más allá» en «apunta al principio» — la
comprobación de límites pasaría y la lectura sería de otro sitio.

### 2. La huella Authenticode no es el hash del fichero

Es el error que parece una optimización y es un agujero. Un ejecutable firmado
lleva la firma **dentro de sí mismo**, así que el hash del fichero cambiaría al
firmarlo y la firma no podría cubrirse a sí misma. Authenticode se salta tres
tramos, y hay que saltarse exactamente esos tres:

1. El campo `CheckSum`, cuatro bytes. Windows lo recalcula al firmar.
2. La entrada del directorio de seguridad, ocho bytes. Apunta a la firma, que
   todavía no existe cuando se calcula la huella.
3. La tabla de certificados entera. Es la firma.

Y el resto sí se cubre, en un orden concreto: los encabezados, luego cada sección
**por orden creciente de `PointerToRawData`** —no por el de la tabla, que puede
venir desordenada y sigue siendo un fichero válido— y por último el *overlay* que
quede por delante de la tabla de certificados.

Cada error tiene su consecuencia:

| Error | Qué permite |
|---|---|
| Saltarse **de más** | editar el ejecutable sin invalidar la firma |
| Saltarse **de menos** | que nada cuadre nunca, y que alguien apague la comprobación de firma por ruido |
| Ordenar por la tabla | una huella distinta de la de Windows en cuanto alguien desordena la tabla |

### 3. Indicios, no veredictos

Cada hecho de `indicios` tiene falsos positivos conocidos, y los dice **en su
propia frase**. Una sección escribible y ejecutable la produce un empaquetador, y
también un compilador viejo. No llevar firma es lo normal en casi todo el disco.
Un overlay grande lo tiene cualquier instalador.

Por eso este crate **no clasifica**. Devuelve hechos sobre la forma del fichero, y
quien decide es el motor de veredicto con el linaje, el comportamiento y la
reputación delante. Un lector de formato que se pusiera a decir «malicioso» sería
un antivirus de los noventa, con su tasa de falsos positivos.

Hay una prueba que lo impone: cada frase tiene que contener su propio «también» o
«como la mayoría». Un indicio sin su falso positivo escrito acaba tratado como
veredicto por quien lo lea deprisa.

## La trampa del formato que casi todo el mundo se come

Los dieciséis directorios de datos llevan un campo `VirtualAddress`. En el número
4 —la tabla de certificados— **ese campo es un desplazamiento de fichero, no una
dirección virtual**. Es la única excepción del formato.

Traducirlo como RVA, que es lo que hace el código escrito por analogía con los
otros quince, manda a leer a cualquier sitio. Está escrito en el módulo para que
no se vuelva a perder.

## Qué se prueba, y contra qué

**No hay ficheros de prueba en el repositorio.** Un `.exe` guardado en
`tests/datos/` es una foto: se generó una vez, con un enlazador, y prueba que el
lector entiende *ese* fichero.

Esta máquina de integración tiene `clang` y `lld-link` —ya los usa para
cross-compilar el driver de Windows desde Linux—, así que los ejecutables se
**construyen en el momento**: PE32+ reales, con su encabezado DOS, su encabezado
opcional, su tabla de secciones y su punto de entrada. Y el testigo tampoco es
este crate: lo que dice el lector se coteja contra **`llvm-readobj`**, que es otra
implementación del mismo formato, escrita por otra gente.

La huella se prueba por sus dos mitades, y hacen falta las dos:

- Cambiar el `CheckSum` **no** la mueve. Sola, esta prueba la pasaría una
  implementación que no hasheara nada.
- Cambiar un byte de una sección, del talón DOS o del final **sí** la mueve.
  Sola, esta la pasaría una que hasheara el fichero entero.
- Y una tercera las cierra: la huella y el SHA-256 del fichero **no pueden
  coincidir**, porque se saltan tres tramos.

Contra entrada hostil: un PE real truncado por doscientos sitios y con tres mil
bits volteados en sus encabezados. Lo único que se exige es que la respuesta sea
`Ok` o un `Err` con nombre —nunca un pánico—. El generador de mutaciones es
determinista a propósito: una prueba que falla una vez de cada cien y no se puede
reproducir acaba marcada como inestable y desactivada, que es como se pierde la
única prueba que de verdad estaba encontrando algo.

Cuarenta y dos pruebas, y la puerta número 31 de `make ci`. Ninguna de las quince
de integración se omitió: la puerta las cuenta con `--nocapture` precisamente
porque una prueba que se salta en silencio es peor que no tenerla.

## Lo que esta fase NO cierra

- **La validación criptográfica de la firma.** Se localiza la tabla de
  certificados y se calcula la huella que Windows compara. Validar el PKCS#7
  —cadena de confianza, marca de tiempo, revocación— es otro trabajo y otra
  superficie. Por eso el método se llama `lleva_tabla_de_certificados()` y no
  `firmado()`: uno se comprobó y el otro no.
- **El driver completo.** Sigue necesitando el WDK y firma de Microsoft, y eso no
  lo arregla escribir más código. Lo que sí se compila y se prueba en cada
  `make ci` es la **decisión** —qué bits de acceso se recortan, qué evento de
  ETW-Ti es inyección—, que es la parte que puede estar mal de forma peligrosa.
- **Las tablas de estado de Windows.** La FASE 81 dejó cincuenta y dos de Linux;
  las de Windows necesitan las interfaces nativas que la SCAL declara y que solo
  se pueden ejercer sobre un Windows de verdad.
