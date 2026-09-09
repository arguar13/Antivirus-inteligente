# Módulo 27 — Desempaquetado dinámico en memoria

> Componente: `crates/aegis-unpacker`.

El malware moderno casi nunca lleva su código en claro en el disco. Un
**empaquetador** —UPX, Themida, o uno a medida— lo guarda comprimido o cifrado
dentro de una sección, junto a un pequeño descompresor. Al ejecutarse, el
descompresor despliega el código real en memoria y salta a él. Escanear el
fichero con firmas no ve nada: **el código que las firmas buscan no está ahí
todavía, está comprimido**.

Este módulo lo despliega y lo captura.

---

## 27.1 El filtro de entrada: no se desempaqueta todo

Desempaquetar es **ejecutar** el binario bajo control, con todo lo que eso cuesta
y arriesga. El filtro deja pasar solo lo que tiene la firma de un empaquetador:
**secciones ejecutables de entropía casi máxima**.

Un binario normal tiene su código en sus secciones y su entropía es media —las
instrucciones se repiten, hay huecos, hay tablas—. Uno empaquetado lleva su
código real comprimido dentro de una sección, y un flujo comprimido o cifrado es
indistinguible de ruido: entropía al máximo. Es la misma señal que el motor de
ransomware usa para el cifrado, aquí sobre las secciones de un ejecutable.

Se exige que **todas** las secciones ejecutables sean de alta entropía, no solo
una: un binario legítimo puede llevar recursos comprimidos en una sección de
datos, pero si su sección de código está en claro, no es un empaquetador. Hay
una prueba para cada caso.

---

## 27.2 La detección del OEP: observar el efecto, no adivinar el salto

No se puede saber dónde está el OEP (*Original Entry Point*) de antemano, así que
se observa el efecto: el proceso empieza a ejecutar código en una región
ejecutable que **no existía al arrancar**.

El bucle de `ptrace`:

1. Lanza el binario con `PTRACE_TRACEME`, confinado (§27.4), y para en el primer
   `exec`.
2. Toma el mapa de regiones ejecutables de arranque: las de confianza.
3. Avanza de **syscall en syscall** (`PTRACE_SYSCALL`), no instrucción a
   instrucción —recorrer un descompresor paso a paso serían millones de
   paradas—, interceptando los `mmap`/`mprotect` que crean regiones ejecutables.
4. En cada parada comprueba el puntero de instrucción. Cuando cae en una región
   nueva, el código desempaquetado ya se está ejecutando: es el OEP. Se congela
   ahí y se vuelca.

**Por qué «la primera syscall desde el código nuevo» y no el salto exacto:**
atrapar la instrucción exacta del salto exigiría un breakpoint hardware o
ejecutar paso a paso, y ninguno escala a un descompresor real. La primera syscall
que el código desempaquetado ejecuta —y todo *payload* hace alguna: pide memoria,
abre un fichero, se conecta— cae con el puntero ya dentro de la región nueva, a
poca distancia del OEP. Para volcar y escanear, esa distancia es irrelevante: el
código real ya está entero en memoria.

---

## 27.3 El discriminante que evita el falso OEP: memoria anónima

El enlazador dinámico mapea `libc` y las demás bibliotecas con `PROT_EXEC`, pero
**desde fichero**. Si se tomara cualquier región ejecutable nueva como el código
desempaquetado, la primera syscall de `libc` se confundiría con el OEP —y eso es
exactamente lo que ocurría en la primera versión—.

El código desempaquetado vive en memoria **anónima**: no hay fichero del que
venga, lo generó el propio proceso. Así que solo cuentan las regiones ejecutables
anónimas: un `mmap` con `MAP_ANONYMOUS | PROT_EXEC`, o un `mprotect` que promueve
a ejecutable una región anónima (el patrón RW→RX del empaquetador que escribe su
código y luego lo hace ejecutable). El anonimato de la región de `mprotect` se
confirma leyendo `/proc/<pid>/maps` del proceso, que está detenido.

---

## 27.4 Contención: desempaquetar es detonar la muestra

Desempaquetar ejecuta código posiblemente malicioso. Hacerlo sin contención es
detonarlo. Antes del `exec`, en el proceso hijo, se instala un filtro **seccomp**
que le corta la red, el control de otros procesos, la superficie de kernel y los
cambios de privilegio.

Se deja pasar `mmap` y `mprotect` a propósito: son justo las llamadas que el
empaquetador usa para desplegar su código, y el tracer las necesita para detectar
el OEP. Lo que se corta es la capacidad de **hacer daño** desde ese código, no la
de desplegarlo.

En una máquina con Landlock (que la de integración no tiene, §20), el
confinamiento sumaría además la restricción por rutas. Aquí, seccomp por sí solo
recorta la superficie de forma sustancial.

---

## 27.5 El ciclo de vida del proceso

El volcado ocurre con el proceso **detenido en el OEP**, para que la memoria no
cambie bajo los pies del lector, y **solo después** se mata. Si el volcado falla,
el proceso se mata igual: no puede quedar vivo código posiblemente malicioso, y
hay una prueba que verifica que tras desempaquetar no queda ni un proceso vivo.

---

## 27.6 Por qué esto es real, y cómo se prueba

El desempaquetado ejecuta el binario de verdad, sigue sus llamadas al sistema de
verdad, y detecta el OEP observando el efecto real de la descompresión sobre el
mapa de memoria del proceso. Nada está simulado.

La prueba de integración construye un **empaquetador auténtico**: un binario
cuyo código real está cifrado con XOR en el disco —de modo que la firma
`AEGIS_UNPACKED_OK_7F3A` que contiene **no aparece** con `strings` ni la ve
YARA— y que se descifra a sí mismo en una región `mmap(RWX)` en tiempo de
ejecución. Se compila desde su fuente en la propia prueba (el binario no se
versiona), se desempaqueta, y se comprueba con el **motor YARA real** que la
firma que no estaba en el disco **sí está** en el volcado. Es exactamente lo que
hace un empaquetador real, reducido a lo esencial.

El escenario 12 de la simulación de Red Team ejecuta ese ciclo de extremo a
extremo. En una máquina sin seccomp el desempaquetado se desactiva por seguridad
—correría sin confinar— y el escenario se omite diciéndolo.
