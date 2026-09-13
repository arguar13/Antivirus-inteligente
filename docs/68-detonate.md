# 68. AegisDetonate — detonación en microVM real

> **Crates**: `server/crates/aegis-detonate` (anfitrión) y `crates/aegis-invitado` (agente invitado)
> **Fase**: 73 · **Verificación**: `tools/verificar-detonate.sh`, integrado en `make ci`

Esta fase ejecuta malware **a propósito** para ver qué hace.

Todo lo demás —la traza, el informe, el análisis, los indicadores— vale
exactamente cero si esa ejecución puede tocar algo real. La frontera no es una
capa más del diseño: es la única razón por la que el resto puede existir.

---

## 68.1 Las tres promesas

### 1. La muestra no alcanza nada real

La frontera son dos piezas. La primera es el **confinamiento**; la segunda es la
salida de red, y ahí hay una decisión que se ve mejor por lo que falta:

```rust
pub enum Salida {
    Ninguna,
    Simulada,
}
```

**No hay ninguna variante que dé acceso a una red real.** Igual que en el
protocolo del canal, la ausencia *es* la frontera: nadie puede configurar por
error lo que no se puede expresar. Para conectar una detonación a una red de
verdad habría que añadir una variante, y eso se ve en una revisión.

Y no se declara: **se comprueba**. Hay una prueba que lanza una muestra dentro de
la frontera, intenta una conexión real a `1.1.1.1:80` y verifica que no la
alcanza; la misma sonda fuera de la frontera sí conecta.

### 2. La máquina se destruye siempre

Está en `Drop` y no sólo en un método. La diferencia importa: **un método se
olvida en el camino de error, y el camino de error es justo el que se toma
cuando algo ha ido mal con una muestra que muerde.**

Una máquina de detonación que sobrevive a su detonación es una máquina
infectada, con la muestra dentro, corriendo en la infraestructura del que
analiza. Y como nadie la está mirando, es además invisible.

Se mata al **grupo de procesos**, no al proceso: un malware que lanza un hijo y
se muere dejaría al hijo corriendo suelto. Hay una prueba que hace exactamente
eso —la muestra deja un hijo para sobrevivirse— y comprueba que el hijo tampoco
sobrevive.

### 3. El informe no puede mentir

Hay tres situaciones que un sandbox descuidado escribe **igual** y significan
cosas radicalmente distintas:

| Lo que pasó | Lo que un sandbox descuidado escribe |
|---|---|
| Corrió entera y no hizo nada malo | «sin comportamiento malicioso» |
| **Detectó el entorno y se marchó** | «sin comportamiento malicioso» |
| **Se cortó antes de que empezara** | «sin comportamiento malicioso» |

Sólo la primera es benigna. Las otras dos son «no se sabe», y confundirlas es la
forma más cara de equivocarse: alguien despliega la muestra creyendo que está
limpia.

`Informe::veredicto()` **no tiene ningún camino** que llegue a `SinHallazgos` sin
haber descartado antes las otras dos. No es una convención que alguien pueda
saltarse por descuido: es la estructura del `match`, y para romperla habría que
reordenarlo a propósito.

---

## 68.2 El invitado está infectado a propósito

El agente invitado corre **en la misma máquina y con los mismos permisos que la
muestra**, y en cuanto ella escale los tendrá todos. Todo lo de `aegis-invitado`
parte de que la muestra puede acabar controlándolo.

### El canal transporta hechos, no órdenes

> **El invitado puede contar lo que le pasa. No puede pedir nada.**

Cualquier vía por la que el invitado pudiera ordenar algo al anfitrión —«abre
este fichero», «ejecuta esto»— sería una fuga del sandbox implementada por
nosotros. Eso no se resuelve con una comprobación en el anfitrión: se resuelve
con el **tipo**. `Evento` no tiene ni una variante que sea una orden, así que el
anfitrión no valida nada porque no hay nada que ejecutar.

### Árbol mínimo

`aegis-invitado` enlaza **sólo `libc`**. Cada crate de más es código que el
malware puede intentar subvertir para llegar al anfitrión por el canal.

### Todo lo que sube lo escribe el malware

- **Toda longitud tiene tope.** Un `u32` de longitud sin cota es la forma más
  corta de escribir una denegación de servicio contra el propio analizador.
- **Toda cadena puede no ser UTF-8.** Una ruta de Linux es una secuencia de bytes
  sin codificación y el malware la elige. No se rechaza: se **escapa**. Tirar el
  evento le daría al malware una forma trivial de borrar su rastro del informe —
  basta con elegir un nombre que el informe no sepa escribir.
- **Un error de protocolo cierra el canal y NO se resincroniza.** Buscar la
  siguiente marca y seguir le dejaría al invitado colocar la marca donde quiera y
  **fabricar tramas** dentro de lo que el anfitrión cree que es carga.
- **Un hueco en la secuencia se anota, no aborta.** Abortar le daría al malware
  una forma trivial de destruir su propio informe: generar eventos a toda
  velocidad hasta provocar la pérdida.
- **Lo que el invitado dice haber emitido se contrasta** con lo que de verdad
  llegó. Creérselo sin más sería dejar que el malware decida cuánta evidencia
  parece haber.

---

## 68.3 Anti-anti-VM: lo que se contrarresta y lo que no

Un sandbox que no dice lo que no ve, miente. Por eso el catálogo no es un párrafo
en un documento —nadie lo lee en el momento en el que importa— sino **un campo
dentro de cada informe**.

| Técnica | Contramedida |
|---|---|
| Identificadores de hardware (DMI) | **Aplicada**: cadenas de un fabricante corriente, serie distinta por detonación |
| Prefijo de MAC | **Aplicada**: prefijo de fabricante real, no del hipervisor |
| Herramientas de análisis | **Aplicada**: la imagen no trae depuradores ni capturadores |
| `CPUID` de hipervisor | **Parcial**: no se expone la hoja de fabricante; el bit 31 de ECX lo pone el hardware |
| Disco virtual | **Parcial**: modelo y serie fijados; el controlador sigue siendo virtio |
| Tiempo encendida | **Parcial**: arranque con varias horas simuladas; los tiempos de proceso no cuadran al detalle |
| Actividad de usuario | **Parcial**: documentos e historial sembrados; **no hay nadie moviendo el ratón** |
| Recursos escasos | **Parcial**: 2 vCPU y 1 GiB por omisión; sigue siendo menos que un escritorio |
| **Medición de tiempos** | **Ninguna** |
| **Red creíble** | **Ninguna** |
| **Espera prolongada** | **Ninguna** |

Las tres últimas merecen su explicación, porque la tentación de disimularlas es
grande:

**No se acelera el reloj.** Falsear las esperas haría que una muestra que compara
`RDTSC` con el reloj de pared viera la incoherencia, y eso es **más detectable**
que la espera honesta. El coste es que una muestra que espera media hora agota el
plazo — y el informe lo dice.

**La red es falsa y se nota.** Todos los nombres resuelven, no hay latencia
creíble, y un TLS contra el servicio simulado no valida contra ninguna autoridad.
Engañar eso exigiría una autoridad propia en el almacén del invitado, que es a su
vez un artefacto delator.

### La otra mitad: detectar que la muestra miró

Contrarrestar tiene límite. Lo que no lo tiene es **darse cuenta de que estuvo
mirando**. Si la traza enseña consultas a `/sys/class/dmi`, `/proc/cpuinfo` y
`/proc/uptime`, y justo después la muestra sale sin hacer nada, eso no es
«benigna»: es `Sospecha::ProbableEvasion`, y es **un hallazgo, no la ausencia de
uno**.

La señal es la **coincidencia** de las dos cosas. Por separado no significan
nada: un instalador legítimo lee `/proc/cpuinfo`, y un programa que hace poco
puede simplemente hacer poco.

> **Un detalle que costó una iteración.** `/home` estaba en los rastros de
> «actividad de usuario», así que un ransomware cifrando `/home/víctima/*` salía
> marcado como que había estado comprobando si alguien usa la máquina. Es
> exactamente al revés: no la está comprobando, la está **atacando**. Los rastros
> tienen que ser artefactos de *comprobación* —`/root/.bash_history`,
> `/var/log/wtmp`— y no directorios enteros.

---

## 68.4 La red simulada: dejarle creer que llegó

Lo más contenido sería no dar red ninguna. El problema es que entonces el informe
casi siempre dice lo mismo: la muestra resuelve su dominio, falla, y sale sin
hacer nada. Eso no es «la muestra es inofensiva», es **«no le dejamos
empezar»** — y confundirlas es la forma más común de que un sandbox mienta sin
querer.

Así que se le contesta a todo: DNS que resuelve cualquier nombre a un sumidero, y
HTTP que devuelve 200 a cualquier petición. Con eso la mayoría de las familias
pasan de la fase de contacto a la fase en la que hacen lo que vinieron a hacer.

Y se gana lo más valioso del informe: **el nombre que la muestra pregunta es el
dominio de su C2**. Un sandbox sin DNS falso no lo consigue nunca, porque la
resolución falla antes de llegar al cable.

Dos decisiones pequeñas con motivo:

- **El sumidero es `203.0.113.13`** (TEST-NET-3, RFC 5737). Si un día una
  detonación se escapara de su frontera, esa dirección no es la de nadie.
- **El TTL es de un segundo.** Con un TTL largo, una muestra que resuelve una vez
  y cachea no vuelve a preguntar, y en un algoritmo de generación de dominios esa
  secuencia es el dato entero.

---

## 68.5 Determinismo: se mide, no se afirma

La misma muestra tiene que dar el mismo informe. Pero el malware usa la hora,
números al azar y el PID que le toque, así que hay partes que **no pueden** ser
iguales entre dos detonaciones.

La salida no es normalizarlo todo hasta que parezca determinista —eso esconde
justo el comportamiento que interesa, como un nombre de fichero generado al
azar— sino separar las dos cosas:

- La **huella** se calcula sobre el comportamiento agregado y ordenado. No entran
  ni los PID, ni los tamaños, ni el orden de llegada: nada de eso se repite, y
  meterlo haría que la huella no coincidiera nunca, que es lo mismo que no
  tenerla.
- Lo que **no** encaja se declara en `Informe::indeterminismo`, con su motivo. Un
  informe sin ninguna fuente de indeterminismo está afirmando algo fuerte y tiene
  que poder sostenerlo.

Y `detonar_dos_veces()` **mide** el determinismo en vez de afirmarlo: detona dos
veces desde cero y compara. Lo que diverge sale con nombre.

---

## 68.6 Dos bugs que el diseño no vio a la primera

**El anfitrión deducía el final del código de salida equivocado.** El código que
ve el anfitrión es el del *agente invitado*, y el agente termina limpiamente
tanto si la muestra acabó como si tuvo que matarla por plazo: las dos cosas
llegan como un cero. Una muestra cortada salía como «terminó», y con ella un
veredicto que decía que no hizo nada. El arreglo es un campo explícito en la
trama final —`completo: bool`— y una regla asimétrica: un `false` se cree
siempre (nadie miente para que su informe valga menos), un `true` se **cruza**
con el plazo del anfitrión, con si hubo que matar la máquina y con sus anomalías.

**`waitpid(-1, ...)` sin `__WNOTHREAD` se cuelga.** En Linux el trazador de
`ptrace` es un **hilo** concreto, no el proceso. Las paradas de un trazado sólo
puede atenderlas el hilo que lo enganchó, pero `waitpid(-1, ...)` recoge a los
hijos de *cualquier* hilo del grupo. Con dos detonaciones a la vez —o simplemente
con `cargo test` corriendo en paralelo— un hilo recoge la notificación del
trazado de otro, no puede hacer nada con ella porque no es su trazador, y el que
sí lo era espera para siempre. El trazado se queda en `t` y la detonación no
termina nunca.

---

## 68.7 Honestidad: los muros

| Muro | Qué se hace en su lugar |
|---|---|
| **Arrancar el hipervisor necesita `/dev/kvm`** | Donde no lo hay —una máquina de integración que ya corre dentro de otra máquina virtual— se genera y se comprueba su configuración **campo a campo**, pero no se arranca. `maquina::hay_virtualizacion()` lo dice, y **degradar en silencio a un aislamiento más débil sería peor que negarse a arrancar**: el informe saldría igual y nadie sabría con qué fuerza estaba encerrada la muestra |
| **Muestras de Windows** | Necesitan una licencia y una imagen que no se puede distribuir. La orquestación, la frontera y el análisis son los mismos; lo que cambia es el invitado |
| **Los espacios de nombres NO equivalen a una máquina virtual** | Una elevación local del kernel —de las que salen varias al año— saca a la muestra de ahí y la pone en el anfitrión; contra una VM le haría falta además un escape del hipervisor, que es otra categoría de fallo. Por eso se **niega** a detonar muestras reales salvo reconocimiento explícito, y el informe lleva escrito con qué fuerza estaba encerrada |
| **La jaula no puede ofrecer la red simulada** | Los servicios falsos viven en el anfitrión y el espacio de nombres de red los deja fuera, que es justamente su trabajo. Se **rechaza la combinación** en vez de degradar a «sin salida» en silencio: un informe que dice «no contactó con nadie» cuando lo cierto es «no había con quién» es la misma mentira de siempre con otra ropa |
| **El trazador no ve dentro de una llamada** | Se ven los argumentos a la entrada y el resultado a la salida, no el efecto en el kernel. Una muestra que carga un módulo se ha salido del alcance de `ptrace`; lo que queda es el `finit_module`, y por eso esa llamada está marcada como evasión |

---

## 68.8 Lo que se ejercita de verdad

El único muro es arrancar el hipervisor. **Todo lo demás ocurre**, contra cosas
reales y no contra simulaciones:

- El **trazador** con `ptrace` sobre procesos de verdad: sigue a los hijos,
  distingue escribir un fichero de leerlo, y el plazo lo aplica un hilo aparte
  porque el bucle vive bloqueado en `waitpid`.
- El **aislamiento de red** contra `1.1.1.1`, desde dentro y desde fuera.
- El **canal** sobre un socket de dominio Unix real — que es además exactamente
  lo que Firecracker le presenta al anfitrión al otro lado de un vsock.
- La **destrucción garantizada** contra un proceso real que intenta sobrevivir.
- Los **servicios falsos** con sockets UDP y TCP reales.
- La **detonación entera** de una muestra escrita en la prueba que cifra
  ficheros, borra los originales y deja una nota de rescate: las tres cosas
  aparecen en el informe.
- Una muestra que **no termina** y se corta, con el informe declarándolo.
- Una **traza manipulada** —basura de verdad por el socket— de la que el
  anfitrión sale con un informe, no con un pánico.
- El **determinismo**, detonando dos veces y comparando.
