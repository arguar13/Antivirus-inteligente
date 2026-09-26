# AegisFirmware+ — auditoría de plataforma de grado CHIPSEC, sin poder escribir

**FASE 92.** Crate `crates/aegis-fwaudit` (ampliado). Puerta:
`tools/verificar-plataforma.sh` (grupo `plataforma` de `tools/ci-local.sh`).

## La pregunta

La FASE 67 miraba dos superficies del firmware —las tablas ACPI y el contenido de
la ROM SPI— y la FASE 26 comprobaba Secure Boot y el arranque medido. Eso
contesta «¿hay un implante conocido en la ROM?». No contesta la pregunta que un
equipo de plataforma necesita antes: **¿puede alguien poner uno?** ¿Es escribible
la flash desde el sistema operativo? ¿Está cerrada SMRAM? ¿Hay IOMMU? ¿El
microcódigo es el último? ¿Qué ejecuta el firmware en el kernel en cada arranque?

CHIPSEC contesta casi todo eso. Pero es una herramienta que un experto ejecuta a
mano, que **puede escribir** en la plataforma, y cuyo informe lee una persona.
Esta fase cubre lo mismo corriendo desatendida en cien mil máquinas, con la
escritura **imposible de expresar**, y con un veredicto que entra en el árbitro.

## El inventario de partida

Escrito en la documentación del módulo antes de ampliar nada, y resumido aquí:
eran **dos superficies y media** (ACPI con WPBT, contenido de la ROM contra línea
base, y Secure Boot/DBX/PCR desde `aegis-firmware`). Las protecciones de la
flash, SMM, los bloqueos del chipset, los MSR, IOMMU, las mitigaciones de CPU, el
microcódigo, las variables UEFI completas, el AML y las option ROM **no se
miraban**.

## Lo que se añade, superficie a superficie

| Superficie | Qué se comprueba | Fuente, siempre de solo lectura |
|---|---|---|
| Protección de la flash | BIOSWE/BLE/SMM_BWP con la tabla de verdad de `bios_wp`, PRx que cubran la BIOS **entera**, FLOCKDN, FRAP, FDOPSS, BILD | configuración PCI y SPIBAR por `/dev/mem` |
| SMM | SMRAMC (D_LCK, D_OPEN), TSEG bloqueado y no vacío, SMRR activo **en todas las CPU** y cubriendo TSEG, SMM sin ejecutar fuera de SMRAM, SMRAM ilegible desde el SO, WSMT | configuración PCI, MSR, `/dev/mem`, tabla WSMT |
| Chipset y CPU | bloqueos del mapa de memoria, SMI_LOCK, modo del ME, SPD por SMBus, IA32_FEATURE_CONTROL, depuración por sonda, LT_LOCK_MEMORY, **Boot Guard** | configuración PCI y MSR |
| IOMMU | DMAR/IVRS declarado, **activo en el kernel**, y protegiendo desde el arranque (`DMA_CTRL_PLATFORM_OPT_IN`) | tablas ACPI y `/sys/class/iommu` |
| Mitigaciones | cada vulnerabilidad en cuatro estados, no en dos | `/sys/devices/system/cpu/vulnerabilities` |
| Microcódigo | la revisión cargada frente a la última **del fabricante**, con los ficheros de Intel y AMD verificados por su suma | `/proc/cpuinfo`, `/lib/firmware/{intel,amd}-ucode` |
| Variables UEFI | todas, con atributos contra la especificación; Secure Boot con **AuditMode**; DBX presente y no vacía; `BootOrder`, `BootNext` y `Boot####` decodificados | `efivarfs` |
| AML | cada método de la DSDT y las SSDT, los que el sistema ejecuta **solo**, y lo que hacen (memoria, puertos, SMI, carga de código) | tablas ACPI |
| Option ROM | cada imagen de expansión PCI contra línea base | imagen de la ROM o volcado, y su medida en el PCR 2 |
| Cadena de arranque | cada medida del registro TCG **explicada**, y los resúmenes autodescriptivos **comprobados** | registro de arranque medido |

## La escritura, imposible por dos capas y comprobada por las dos

La FASE 67 ya tenía la regla: una escritura en la ROM SPI es un ladrillo. Esta
fase lleva el mismo tipo `LecturaSolo` a sitios mucho más peligrosos —la
configuración del chipset, `/dev/mem`, los MSR— y la garantía se comprueba otra
vez, por cada superficie:

**Contra el kernel.** Se abre cada superficie real y se intenta escribir por el
descriptor. En esta máquina se ejercieron seis: configuración PCI, la DSDT,
`/proc/cpuinfo`, las mitigaciones, un fichero de microcódigo del fabricante y
`/dev/mem`. Las escrituras de la prueba son de **cero bytes** y el truncado es al
**tamaño actual**: el kernel mira el modo del descriptor antes que la longitud,
así que el rechazo se demuestra igual, y si la garantía fallara algún día la
prueba no podría dañar ni la memoria física ni el microcódigo del fabricante.

Y se afirma **el errno que da el kernel, no el que pedía el enunciado**. El
enunciado de la fase dice «`write`, `pwrite` y `ftruncate` devuelven `EBADF`».
Medido, no es así:

| Llamada | Fichero regular, `/dev/mem` | `/proc`, sysfs |
|---|---|---|
| `write` | `EBADF` | `EBADF` |
| `pwrite` | `EBADF` | `ESPIPE` — rechaza la escritura posicional antes de mirar el modo |
| `ftruncate` | `EINVAL` | `EINVAL` — el kernel exige fichero regular **y** abierto para escribir, y agrupa los dos fallos en ese código |

Una prueba que exigiera `EBADF` en los tres fallaría en la primera ejecución, y
la tentación sería aflojarla. Se comprueba lo que el kernel hace.

**Contra el compilador.** Cinco pruebas `compile_fail` con el código de error
atado —una errata no las hace pasar—: `LecturaSolo` no tiene método de escritura
(`E0599`), no es `io::Write` (`E0277`), su fichero interno es privado (`E0616`), y
el lector físico no tiene `wrmsr` ni escritura de memoria (`E0599` dos veces). La
invariante 12 del producto lo comprueba además por ausencia en el código fuente.

### Lo que no se lee porque habría que escribir

Tres sitios donde leer exige escribir antes, y en los tres se declara no
aplicable con ese motivo:

- **El controlador SPI oculto por el P2SB.** En los PCH de la serie 100 en
  adelante el firmware suele esconder el dispositivo 00:1f.5. CHIPSEC lo destapa
  **escribiendo en la configuración del P2SB**. Aquí no.
- **El fichero `rom` de sysfs.** Para leer la option ROM de una tarjeta hay que
  escribir `1` en él (el kernel habilita la decodificación) y luego `0`. Aquí las
  option ROM se sacan de la imagen de la ROM, de un volcado, o de su medida en el
  PCR 2.
- **El módulo `msr`.** Si `/dev/cpu` no existe, cargarlo es cambiar el núcleo de
  la máquina del cliente.

## Compromiso frente a exposición

Hasta esta fase todo fallo del crate era un compromiso. Las superficies nuevas
fallan de otra manera: un BLE a cero **no es un implante**, es una puerta que el
fabricante dejó abierta. Juntarlos habría producido los dos errores clásicos a la
vez: el árbitro recibiría «sospechoso» sobre medio parque por configuraciones de
fábrica, y la exposición real —lo que un equipo de plataforma necesita para
priorizar— quedaría enterrada entre alarmas.

Por eso cada comprobación lleva su **naturaleza** en el tipo, y al árbitro sólo
llegan los compromisos. Una prueba lo fija: una placa con veinte exposiciones y
ningún compromiso sale **limpia**, no sospechosa. Y sin nada mirado, la señal es
`NoConcluyente`, nunca «limpia por defecto».

## AML, cotejado contra las dos herramientas de Intel

AML es la ambigüedad clásica: una invocación de método no dice cuántos argumentos
lleva, hay que saberlo del espacio de nombres. Se resuelve en dos pasadas
(registro y análisis), con presupuesto de operaciones, profundidad máxima, y
recuperación por contenedor: un método roto no tapa a los doscientos siguientes.

La DSDT real de esta máquina, cotejada **en la propia puerta** contra `iasl` y
`acpiexec`, sin cifras escritas a mano en ninguna prueba:

| Medida | Aquí | Referencia |
|---|---:|---:|
| Métodos estáticos | **2457** | 2457 según `iasl -d` |
| Métodos incondicionales | **7** | 7 cargados por `acpiexec` |
| Decodificados enteros | 2457 | — |
| Nombres sin resolver | 0 | — |
| Tiempo | ~120 ms | — |

La diferencia entre 2457 y 7 es la DSDT de Hyper-V: casi todo vive dentro de
bloques `If` que el intérprete resuelve al cargar con valores de la máquina viva.
El análisis estático los ve todos y marca cuáles dependen de una condición.

Lo que se inventaría de cada método que el sistema ejecuta solo: si lee o escribe
memoria física, si escribe puertos, **si escribe en el puerto `SMI_CMD` de la
FADT** (dispara código de SMM), si carga una tabla nueva, si crea una región con
dirección calculada. Contra una línea base (`aml <ruta> <sha256>`), un método que
el sistema ejecuta solo con un cuerpo distinto es un compromiso.

## La cadena de arranque, explicada

La FASE 26 reproduce el registro y comprueba que los PCR del TPM salen de él: eso
prueba los **resúmenes**. No prueba el **texto**. Un atacante que reescribe el
texto de un evento dejando su resumen intacto deja la reproducción cuadrando y
enseña a quien lea el registro un arranque limpio.

Para una familia de eventos la especificación obliga a que el resumen sea el hash
del propio texto —separadores, acciones, variables de configuración de Secure
Boot—, y ahí se comprueba. Una prueba construye exactamente ese ataque: el evento
dice `SecureBoot = 1` y lo medido fue `SecureBoot = 0`. Se delata. Los eventos que
miden código llevan el hash del binario y se marcan `NoVerificable` con el motivo,
que no es lo mismo que verificado.

Además: la versión del firmware, Secure Boot tal y como se midió frente a como
está ahora, los cargadores que se ejecutaron, la línea de órdenes del kernel, los
separadores de cada fase, y las option ROM que el firmware ejecutó (PCR 2) contra
la línea base.

## Microcódigo: la referencia es el fabricante

La «última revisión conocida» no es una tabla escrita aquí, que caducaría con la
siguiente publicación: son los ficheros del propio fabricante que la distribución
actualiza. Se leen con el formato de Intel y de AMD y **se verifica la suma de
comprobación** de cada actualización. Medido en esta máquina: **126 ficheros de
Intel, 166 actualizaciones, todas íntegras**.

Para la CPU de esta máquina (familia 6, modelo 0xA5, escalón 2) el fabricante
publica `0x100` (2024-11-14). El hipervisor publica `0xffffffff` en vez de la
revisión real, y el veredicto es **indeterminado** con las dos cifras al lado para
que quien mire el anfitrión sepa contra qué comparar. No es «atrasado» ni «al día».

## Lo que encontró la fase por el camino

| Defecto | Corrección |
|---|---|
| **Los `build.rs` de `aegis-net`, `aegis-agent`, `aegis-ips` y `aegis-kintegrity` leían `CARGO_MANIFEST_DIR` con `env!`**, es decir, congelado al compilar el propio script. Cargo calcula el hash de un paquete de ruta relativo al workspace, así que al **renombrar la carpeta del proyecto** reutilizó los scripts ya compilados, que buscaban el subproyecto eBPF en la ruta vieja: cuatro capacidades de la invariante 9 aparecían rotas sin que su código hubiera cambiado | la variable se lee **en ejecución**, que Cargo también define |
| El mismo `env!` en **nueve ficheros de pruebas y ejemplos** (`aegis-deception`, `aegis-harden`, `aegis-kintegrity`, `aegis-kguard`, `aegis-unpacker`, `aegis-syscallguard`, `aegis-detonate`). El autoataque de los señuelos, que lee su propio código fuente para comprobar que ningún diálogo ejecuta nada, buscaba `src/dialogos` en la carpeta vieja y fallaba diciendo que no existía | `raiz_crate()`: el entorno en ejecución primero, el valor de compilación sólo para quien lance el binario a mano |
| El enunciado afirmaba `EBADF` para `pwrite` y `ftruncate` | se comprueba el errno real, tabla arriba |
| Las dos pruebas de coste de la redacción de `aegis-captura` fallaban **con otro proceso compilando al lado**. Una medía `limpiar`, que devuelve una **copia** del paquete —lineal por necesidad—, así que su cociente medía sobre todo el asignador de memoria y el ancho de banda; la otra comparaba tiempos tomados en momentos distintos. Al medirlo bien apareció la cifra real: un relleno de «w» cuesta 3,5 veces el neutro, estable, con el umbral en 4 | se mide `inspeccionar` (lo que la ventana acota, separado de la copia) y cada paquete **inmediatamente después** de su referencia, tomando la **mediana** de los cocientes. Resultado: la ventana da **1,0** (mirar 4 MB cuesta lo mismo que mirar 16 KiB) y el relleno su 3,5 real; **15 de 15** bajo seis procesos saturando la CPU. Los umbrales no se movieron |
| La prueba de volcado en vivo de `aegis-forensics` fallaba **a veces**: el kernel **funde** mapeos anónimos contiguos con los mismos permisos, y como las demás pruebas del binario reservan memoria en paralelo, la región marcada de la prueba acababa dentro de otra de varios megabytes; el volcado lee cada región hasta el tope de 2 MB que declara su política, y el marcador quedaba más allá. El producto cumplía su política; la prueba suponía un aislamiento que no garantizaba | la región va entre dos páginas de guarda `PROT_NONE`: con vecinos de otros permisos, el kernel no puede fundirla. 30 repeticiones seguidas, 30 bien |
| La prueba del ME usaba `HFSTS1 = 0x9000_0255`, que **tiene** el bit de modo fabricación; el decodificador acertaba y el vector estaba mal | vector corregido (`0x9000_0245`) y el de `0x…255` pasa a ser el caso de fabricación |
| Sin ninguna tabla ACPI legible, IOMMU y WSMT salían como **exposición** («el firmware no declara…») | sin ACPI es **no aplicable**: no poder mirar no es encontrar nada |
| Una línea base que sólo traía AML hacía que cada fichero FFS saliera «desconocido» en vez de «sin base» | `cubre_ffs()`: cada superficie decide con sus propias entradas |

## Lo medido

| Medida | Cifra |
|---|---|
| Superficies de plataforma | **12** (antes, dos y media) |
| Comprobaciones por máquina | **37** (11 de compromiso, 26 de exposición), todas siempre presentes |
| Superficies donde el kernel rechazó la escritura | **6** de 8 (las otras dos no existen aquí) |
| Pruebas `compile_fail` de la no escritura | **5** |
| AML frente a `iasl` / `acpiexec` | **idéntico** / **idéntico** |
| Ficheros de microcódigo del fabricante verificados | **126** (166 actualizaciones) |
| Auditoría completa de esta máquina | ~250 ms, sin compromisos, 1 exposición real (`mmio_stale_data` vulnerable) |
| Pruebas del crate | **161** (antes 67) |

## La comparación con CHIPSEC, medida por módulos

**Lo primero, lo que CHIPSEC hace mejor**, porque una comparación que empieza por
lo propio es un folleto:

- Corre **sobre hardware real con su propio controlador de kernel**, y aquí no se
  ha podido ejecutar: el controlador se compila contra las cabeceras del kernel y
  el de WSL no las publica. La comparación que valdría —los dos sobre la misma
  placa física— **queda pendiente** y se declara.
- Tiene **definiciones de registros por plataforma** (un fichero de configuración
  por generación de chipset) acumuladas durante años. Aquí los desplazamientos son
  los genéricos del PCH de legado y de la serie 100+, verificados contra los
  datasheets pero no contra cada generación.
- En los PCH modernos **lee el controlador SPI oculto**, porque escribe en el P2SB
  para destaparlo. Aquí esas comprobaciones quedan indeterminadas en esas placas.
- **AMD**: sus protecciones de flash y su SMM no se cubren en esta fase.

Con eso dicho, los módulos que CHIPSEC publica en `chipsec/modules/common` y
`chipsec/modules/tools`, uno a uno (la tabla es código en `src/chipsec.rs` y una
prueba exige que cada comprobación que cita exista de verdad):

| Respuesta | Módulos |
|---|---:|
| Cubierto | **21** |
| Parcial (se dice qué falta) | **3** — `bios_smi`, `remap`, `uefi.access_uefispec` |
| No cubierto (derrota, escrita) | **6** — `rtclock`, `bios_kbrd_buffer`, `sgx_check`, `uefi.s3bootscript`, `cpu.ia_untrusted`, `uefi.reputation` |
| Excluido por escribir o atacar | **6** — `smm_ptr`, `rogue_mmio_bar`, `uefivar_fuzz`, `sinkhole`, `secureboot.te`, `vmm.*` |

Los excluidos no cuentan como victoria ni como derrota: confirman un fallo
**explotándolo**, y un escáner que corre desatendido en cien mil máquinas no
explota nada (invariante de la fase: un escáner no es un ataque).

Y **13 comprobaciones sin equivalente en CHIPSEC**: WPBT, el AML que el sistema
ejecuta solo, el texto de cada evento del registro de arranque, Secure Boot
medido frente a actual, la reproducción de los PCR, las option ROM ejecutadas y
las extraídas contra línea base, IOMMU activo y protegiendo desde el arranque,
WSMT, el microcódigo frente al del fabricante, Boot Guard, los arranques de una
sola vez, y la DBX vacía.

Y lo que ninguna tabla de módulos recoge: aquí todo corre **desatendido**, con la
escritura imposible, y el resultado es una **señal al árbitro** sobre la entidad
máquina, no un informe que alguien tiene que leer.

## Tabla de honestidad

| Pieza | Aquí | Cómo |
|---|---|---|
| Inocuidad frente al kernel | **sí** | 6 superficies reales: configuración PCI, DSDT, `/proc/cpuinfo`, mitigaciones, microcódigo, `/dev/mem` |
| Inocuidad frente al compilador | **sí** | 5 `compile_fail` con código de error, y la invariante 12 por ausencia |
| Decisores de registros (flash, SMM, chipset, MSR) | sí | con los valores de los datasheets de Intel, bit a bit |
| **Leer esos registros en hardware** | — | esta máquina es una VM de Hyper-V: sin chipset de Intel visible y sin módulo `msr`. **No aplicable**, con el motivo |
| AML | **sí** | la DSDT real, cotejada con `iasl` y `acpiexec` en cada `make ci` |
| Mitigaciones | **sí** | las de esta CPU, con una exposición real |
| Microcódigo del fabricante | **sí** | 126 ficheros reales, suma verificada |
| Microcódigo cargado | — | el hipervisor lo oculta: indeterminado, dicho así |
| Variables UEFI | sí | `efivarfs` sintético con el formato real; esta máquina no arrancó por UEFI |
| Cadena de arranque | sí | registros TCG crypto-ágiles construidos byte a byte según la especificación; aquí no hay TPM |
| Option ROM | sí | imágenes construidas según la especificación PCI; la lectura por sysfs se descarta por diseño |
| Comparación con CHIPSEC | parcial | por módulos equivalentes; **no** se ha ejecutado CHIPSEC en la misma placa |

## El muro, declarado

- **Esta máquina no tiene chipset visible, UEFI, TPM ni módulo `msr`.** Las
  lecturas de esas superficies salen no aplicables con su motivo; los decisores
  se prueban enteros. La medida en hardware físico es la que falta.
- **CHIPSEC no se ha ejecutado.** Su controlador exige las cabeceras del kernel.
- **AMD no está cubierto** en protecciones de flash ni SMM.
- **El controlador SPI oculto por el P2SB no se lee**, y no se leerá: destaparlo
  es escribir.
- **Sin línea base, el AML y las option ROM se inventarían pero no se juzgan**:
  «no sé si es lo que debería» es indeterminado, no limpio.
