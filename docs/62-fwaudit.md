# Módulo 62 — AegisFirmwareAudit: auditoría de ROM SPI y tablas ACPI, **sólo lectura**

> Componentes: `crates/aegis-fwaudit/`, `crates/aegis-fwaudit/examples/fwaudit_support.rs`,
> `tools/verificar-fwaudit.sh`.

## 62.1 El sitio donde formatear el disco no sirve de nada

Una APT con recursos no se queda en el disco. Implanta **por debajo del sistema
operativo**: LoJax en el firmware UEFI, MoonBounce en la ROM SPI, CosmicStrand en
el bootkit. Desde ahí sobrevive a formatear el disco, a reinstalar el sistema y a
**cambiar el disco duro**, porque no está en ninguno de los tres. Cuando el
sistema arranca, el implante ya lleva ejecutándose un rato y lo que el EDR ve del
mundo se lo ha contado él.

El módulo 26 ([`aegis-firmware`](26-firmware.md)) audita la cadena de arranque
*medido*: TPM, PCR, event log, DBX. Eso responde a «¿se manipuló el arranque?».
Este módulo responde a la otra mitad: **«¿qué hay realmente escrito ahí abajo?»**,
mirando las dos superficies donde un implante tiene que dejarse ver:

1. **Las tablas ACPI** que el firmware le entrega al kernel. El sistema operativo
   **se las cree**: son la palabra de algo que se ejecuta antes que él y por
   debajo de él. El caso extremo es **WPBT**.
2. **El contenido de la ROM SPI**: el descriptor de flash de Intel delimita la
   región BIOS, dentro viven los volúmenes de firmware y dentro de ellos los
   ficheros FFS que un implante añade o sustituye.

## 62.2 La regla que gobierna el módulo entero: jamás se escribe

Esta fase es distinta de todas las demás en un punto que cambia el diseño
completo: **el riesgo principal no es dejar de detectar, es escribir**.

Una escritura accidental sobre la ROM SPI no es un *bug*: es un **ladrillo**. Deja
la placa base sin arrancar y **no hay recuperación por software** — hace falta un
programador SPI externo con pinzas sobre el chip. Un EDR capaz de hacerle eso a la
flota es infinitamente peor que el implante que estaba buscando.

Así que la garantía no es una convención ni una nota en el código. Es
**estructural, y tiene dos capas independientes**:

| Capa | Quién la impone | Qué impide |
|---|---|---|
| `#![forbid(unsafe_code)]` + el tipo `LecturaSolo`, que **no expone ninguna operación de escritura** | el compilador | que exista, en el crate, una ruta de código que escriba |
| `O_RDONLY \| O_CLOEXEC \| O_NOFOLLOW` en cada apertura | el **kernel** | que una escritura, si la hubiera, llegue al dispositivo |

Ninguna de las dos basta sola: `forbid(unsafe_code)` no impide llamar a
`File::write`, y `O_RDONLY` no impide un fallo lógico en otra parte.

Y la segunda capa **se ejerce**, no se afirma. `tests/solo_lectura.rs` coge el
descriptor que usa el crate e intenta escribir en él de las tres formas posibles:

```
write(fd, ...)              →  EBADF
pwrite(fd, ..., offset)     →  EBADF
ftruncate(fd, 0)            →  EBADF
```

Esas pruebas viven en un crate de integración **aparte** por una razón que no es
cosmética: dentro del crate, con `forbid(unsafe_code)`, no se pueden ni escribir.
Para que `LecturaSolo` pueda entregar su descriptor a esa prueba sin abrir una
puerta de escritura, implementa `AsFd` y nada más.

`O_NOFOLLOW` cierra el último hueco: sin él, un enlace simbólico colocado donde se
espera un nodo MTD redirige la lectura a otro fichero.

## 62.3 WPBT: la persistencia que el fabricante documentó

**WPBT** (*Windows Platform Binary Table*) es una tabla ACPI que dice, literalmente:
*«ejecuta este binario en cada arranque»*. El firmware entrega un PE en memoria y
Windows lo ejecuta antes que nada más. Existe para que un fabricante reinstale su
software de gestión aunque el usuario formatee — y es, exactamente por lo mismo,
**la persistencia más limpia que existe**: no hay fichero que borrar ni clave de
registro que limpiar, porque la fuente está en la flash.

El caso Lenovo Superfish/LSE de 2015 no fue teórico: una WPBT de fábrica
reinyectaba software en cada arranque incluso tras una instalación limpia.

La tabla se analiza entera (cabecera ACPI de 36 bytes, y después `HandoffSize`,
`HandoffAddress`, `Layout`, `ContentType`, `ArgumentsLength` y los argumentos en
UTF-16LE), y se buscan
indicios en la **línea de comandos**: `powershell`, `-enc`, `-nop`, `-w hidden`,
`iex`, `downloadstring`, `certutil`, `bitsadmin`, `mshta`, `rundll32`,
`frombase64string`, rutas UNC `\\`, y URLs.

Tres decisiones que costaron trabajo y que importan:

- **Una WPBT presente no es un fallo.** Sale como `Indeterminado`, con el motivo
  explícito: *el firmware ejecuta un binario en cada arranque, lo cual es un
  mecanismo legítimo de fabricante y también la persistencia más limpia que
  existe; conviene identificar el binario*. Marcarla como compromiso significaría
  una alerta crítica en cada portátil de fabricante el primer día, y una alerta
  que salta siempre es una alerta que nadie mira.
- **El UTF-16 inválido no descarta la evidencia.** Los bytes vienen del firmware,
  no tienen por qué ser válidos. Los pares que no forman carácter se sustituyen
  por `?` en lugar de tirar la cadena entera: un argumento con basura intercalada
  sigue siendo evidencia, y a veces la basura **es** la señal.
- **Una longitud de argumentos mentirosa no lee fuera de rango.** El campo lo
  escribe quien está siendo auditado.

Del resto de tablas ACPI se comprueba el **checksum de 8 bits** (la suma de todos
los bytes, incluido el propio checksum, ha de ser ≡ 0 mod 256), se buscan **PE
embebidos** (`MZ` + `e_lfanew` → `PE\0\0`, comprobado de verdad, no por la firma
`MZ` suelta, que aparece por casualidad en cualquier blob) y se marcan las firmas
desconocidas sin tratarlas como maliciosas.

## 62.4 La ROM: descriptor de Intel, volúmenes UEFI y ficheros FFS

Cuando el kernel **sí** expone la flash, el recorrido es en tres saltos:

1. **Descriptor de flash de Intel** — firma `0x0FF0A55A` en el desplazamiento
   `0x10` (y `0x00` en el formato antiguo). De él salen las regiones: Descriptor,
   BIOS, ME, GbE. Sólo interesa la **región BIOS**.
2. **Volúmenes de firmware** — `EFI_FIRMWARE_VOLUME_HEADER`, reconocidos por la
   firma `_FVH` en el desplazamiento 40 y validados con su **checksum de 16 bits**.
3. **Ficheros FFS** dentro de cada volumen, cada uno con su GUID y su tipo.

Sin el descriptor **se puede seguir**, buscando volúmenes por toda la imagen, pero
**se dice**: la comprobación `spi-descriptor` sale `Indeterminado` con el motivo,
porque buscar `_FVH` por fuerza bruta encuentra coincidencias dentro de la región
ME y dentro de datos comprimidos.

### El hash canónico: qué bytes *no* entran

El hash de un fichero FFS **no puede ser el de sus bytes tal cual**. Tres bytes de
la cabecera los muta el propio firmware durante la vida normal de la máquina —el
byte de `State` (marcado de fichero borrado o en cabeza) y los dos de
`IntegrityCheck`—, así que un hash ingenuo cambiaría tras un arranque cualquiera y
la línea base entera se volvería ruido.

El hash canónico pone esos tres bytes a cero antes de calcular SHA-256. Hay una
prueba dedicada a ello: *el hash canónico no cambia cuando el estado muta en la
flash*.

### El recorrido ante bytes hostiles

Los tamaños de los ficheros FFS los escribe quien está siendo auditado, así que el
recorrido está construido con **progreso estricto**: un tamaño cero, un tamaño que
se sale del volumen o basura pura **terminan** el recorrido en lugar de colgarlo o
de leer fuera de rango. Cada uno tiene su prueba.

## 62.5 Línea base: «desconocido» no es «malicioso»

La línea base es un fichero de texto versionado:

```
version 1
fv    <guid>                 <nombre>
ffs   <guid> <sha256>        <nombre>
revocado    <sha256>         <nombre-del-implante>
```

y produce cinco veredictos, que son cinco cosas distintas y se mantienen
distintas:

| Veredicto | Significa |
|---|---|
| `Conocido` | GUID y hash coinciden con lo catalogado |
| `Alterado` | el GUID está catalogado, **el hash no coincide**: ese módulo fue reescrito |
| `Revocado` | el hash coincide con un **implante conocido** |
| `Desconocido` | el GUID no está en la base — lo que **aún no se ha catalogado**, no un ataque |
| `SinBase` | no hay con qué comparar |

`Revocado` gana sobre `Conocido`: un implante que reutiliza el GUID de un módulo
legítimo no se cuela por el orden de las comprobaciones.

Y una base malformada **se rechaza entera** en vez de cargarse a medias: una línea
base con la mitad de las entradas produce «desconocido» sobre módulos legítimos,
que es ruido, y «conocido» sobre módulos que ya no están, que es peor.

## 62.6 Tri-estado: «no se puede mirar» no es «está bien»

Todas las comprobaciones usan el `CheckState` de
[`aegis_firmware::report`](26-firmware.md) — `Ok` / `Fallo` / `NoAplicable` /
`Indeterminado` — y no un booleano, porque las tres formas de «no es un fallo» son
distintas y confundirlas es el error que mata a un producto de seguridad:

| Comprobación | Cuándo sale qué |
|---|---|
| `acpi-tablas` | `Ok` si nada grave; `Fallo` con el código y el sujeto; `NoAplicable` si la máquina no expone ACPI |
| `acpi-wpbt` | `Ok` si no hay WPBT; `Indeterminado` si la hay sin indicios; `Fallo` si sus argumentos son de ataque |
| `spi-rom` | `Ok` si se leyó; `NoAplicable` **con el motivo** si el kernel no expone la flash; `Indeterminado` si existe pero falló la lectura |
| `spi-descriptor` | `Ok` si delimitó la región BIOS; `Indeterminado` si se recorre la imagen entera |
| `spi-ficheros` | `Ok` contra su base; `Fallo` si hay alterados o revocados; **`Indeterminado` si no hay línea base** |

Esa última fila es la que más importa. **Sin línea base el veredicto no es
«correcto»**: no es lo mismo no encontrar nada que no tener con qué comparar, y un
informe que dijera `Ok` ahí estaría mintiendo sobre lo que sabe.

## 62.7 El muro, declarado

En la mayoría de máquinas —incluida la de desarrollo— **la ROM SPI no se puede
leer**. Hace falta que el kernel exponga la flash como dispositivo MTD
(`/sys/class/mtd`), lo que exige un controlador como `intel-spi` o `spi-nor` que
casi ninguna distribución activa, y además privilegios de root.

Cuando no se puede, el informe **dice por qué**, con el motivo literal:

```
spi-rom   no aplicable (/sys/class/mtd no existe: el kernel no expone la flash
          como MTD (hace falta un controlador como intel-spi o spi-nor, que casi
          ninguna distribucion activa))
```

Por eso `auditar_rom` toma una **imagen en memoria** y no una ruta: la misma
función sirve para la ROM viva de un endpoint que sí la expone y para un volcado
que el analista trae de otro equipo, sin duplicar el decisor ni dejar sin probar
la mitad que importa.

## 62.8 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| **Garantía de sólo lectura** | **sí** | ejercida contra el kernel: `write`, `pwrite` y `ftruncate` → `EBADF` los tres |
| Parseo de tablas ACPI | **sí** | contra las tablas **reales** del firmware de esta máquina |
| Checksum ACPI | **sí** | el de una tabla auténtica tiene que dar cero, y da |
| Veredicto sobre esta máquina | **sí** | la auditoría real sale limpia; si no, o hay compromiso o el decisor está mal calibrado |
| WPBT | sí | vectores construidos byte a byte según la especificación, incluidos los hostiles |
| Descriptor Intel, volúmenes UEFI, FFS | sí | ídem, con tamaños mentirosos, tamaño cero y basura |
| Hash canónico | sí | el estado muta en la flash y el hash **no** cambia |
| Línea base y veredictos | sí | incluido que `Revocado` gane sobre `Conocido` |
| **Leer la ROM SPI** | — | esta máquina no la expone; **no aplicable**, que no es «bien» ni «mal» |

La segunda capa de la garantía de inocuidad es la primera comprobación que corre
`tools/verificar-fwaudit.sh`, antes que ninguna de detección. El orden es
deliberado: si esa falla, lo demás da igual.

Un defecto real que encontró el desarrollo de esta fase: `leer_todo` usaba el
cursor compartido del descriptor, de modo que **dos lecturas del mismo lector
devolvían datos distintos**. Sobre una ROM eso significa auditar la primera mitad
de la imagen y, en el siguiente arranque del análisis, la segunda — sin error y
sin aviso. Está arreglado de raíz leyendo siempre por posición (`read_at`) desde
el desplazamiento 0, y hay una prueba que lo fija.
