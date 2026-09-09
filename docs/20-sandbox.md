# Módulo 20 — Sandbox de confianza cero: Landlock y seccomp-bpf

> Componente: `crates/aegis-sandbox`.

Detectar y responder llega, por definición, **después**. Entre que el binario
sospechoso empieza a correr y que el motor decide cortarlo hay una ventana en la
que el atacante ya ha hecho su trabajo. El aislamiento preventivo cierra esa
ventana quitando de antemano lo que un binario no confiable no debería poder
hacer nunca: hablar por la red, tocar otros procesos, cargar código en el kernel
o escribir donde deja su segunda etapa.

---

## 20.1 Dos mecanismos, porque ninguno basta solo

| | seccomp-bpf | Landlock |
|---|---|---|
| Filtra por | Número de llamada | Objeto del VFS ya resuelto |
| Disponible desde | Linux 3.5 (universal) | Linux 5.13, por versión de ABI |
| Puede decir «no leas `/etc/shadow`» | **No** | Sí |
| Puede decir «nada de `kexec_load`» | Sí | No |

seccomp no puede mirar una ruta: el argumento es un puntero al espacio del
proceso, y aunque el filtro pudiera leerlo, entre comprobarlo y usarlo la ruta
puede cambiar —la carrera clásica de tiempo de comprobación contra tiempo de
uso—. Landlock aplica la restricción en el VFS, sobre el objeto ya resuelto, así
que esa carrera no existe.

Se usan los dos. Cuando falta Landlock, `CompiledSandbox::compile` **no falla**:
aplica seccomp y lo dice en `Applied`. Callárselo sería lo peligroso, porque
quien despliega creería tener una protección que no tiene.

---

## 20.2 Las dos trampas de un filtro de seccomp

**No comprobar la arquitectura.** Los números de llamada dependen de la ABI. En
x86-64 el mismo proceso puede invocar la ABI de 32 bits o la x32, donde los
números son *otros*: el filtro que bloquea `ptrace` (101) en x86-64 deja pasar
`ptrace` (26) en i386. Un filtro que no empieza comprobando `arch` no bloquea
nada que le importe a un atacante. El de AegisCore empieza por ahí y además
rechaza el bit de x32; hay una prueba que fija las seis primeras instrucciones.

**Reservar memoria después del `fork`.** El filtro se instala en el hijo, entre
`fork` y `exec`, donde sólo valen funciones seguras en contexto de señal.
Reservar memoria ahí puede bloquearse para siempre: si otro hilo tenía el bloqueo
del asignador en el instante del `fork`, en el hijo ese bloqueo lo tiene un hilo
que ya no existe. Por eso todo lo que reserva memoria o abre ficheros ocurre en
`CompiledSandbox::compile`, **antes** de bifurcar; el descriptor del conjunto de
Landlock sobrevive al `fork`, y en el hijo sólo quedan tres llamadas al sistema.

---

## 20.3 Lista blanca de rutas, lista negra de llamadas

No es una incoherencia. Una lista blanca de **llamadas** rompe cualquier programa
no escrito para ella —otra versión de `libc` usa otras—, y un sandbox que rompe
el software legítimo se desactiva a la semana de desplegarlo. La lista negra
cubre exactamente las capacidades que la política niega y el resto del
comportamiento normal sigue funcionando; hay una prueba que lo comprueba
ejecutando un programa corriente dentro del sandbox.

Con las **rutas** ocurre lo contrario: enumerar lo prohibido es imposible, y
Landlock está diseñado como lista blanca. Todo derecho gobernado queda prohibido
salvo donde una regla lo permita.

La política gobierna **todos** los derechos que la ABI conozca. Gobernar sólo la
escritura dejaría al binario leer cualquier cosa de la máquina.

---

## 20.4 La política de binario no confiable

Sin red, sin control de otros procesos, sin superficie de kernel, sin cambios de
privilegio ni de espacio de nombres: **35 llamadas bloqueadas**. Acceso de
lectura sólo a lo imprescindible para ejecutarse.

**`/tmp` no está**, y hay una prueba que lo verifica sobre la política: es el
directorio donde acaba todo lo que se descarga, y un binario sospechoso que pueda
escribir ahí puede dejar su segunda etapa.

La acción es **matar**, no devolver `EPERM`: si un binario en el que no se confía
intenta algo que la política prohíbe no hay conversación posible, y la muerte por
`SIGSYS` queda registrada de forma inconfundible. Para los auxiliares del propio
agente la acción es `EPERM`, porque un componente legítimo que recibe `EPERM`
informa y sigue, mientras que matarlo produce un fallo incomprensible.

---

## 20.5 Negociación de la ABI de Landlock

Landlock evoluciona por versiones y cada una añade derechos. Pedir un derecho que
el kernel no conoce devuelve `EINVAL` y **el sandbox no se aplica en absoluto**,
que es el peor resultado posible: el proceso acaba sin restringir creyendo que lo
está. Por eso la máscara se recorta a lo que el kernel admite.

| ABI | Añade |
|---|---|
| 1 | Derechos básicos de fichero |
| 2 | `REFER` (reubicar entre directorios) |
| 3 | `TRUNCATE` |
| 4 | Red: `BIND_TCP`, `CONNECT_TCP` |
| 5 | `IOCTL_DEV` |
| 6 | `scoped` |

El tamaño de `landlock_ruleset_attr` se ajusta a la versión detectada: pasar la
estructura completa a un kernel antiguo devuelve `E2BIG`. Y
`landlock_path_beneath_attr` es **empaquetada**: sin `#[repr(packed)]` el
compilador añade cuatro bytes de relleno y el kernel recibe 16 donde espera 12.

La restricción de red de Landlock **no sustituye** al filtro de seccomp: Landlock
cubre TCP, y seccomp cubre todo lo demás —UDP, sockets de dominio Unix,
`netlink`, paquetes en crudo—.

---

## 20.6 Cómo se prueba, y qué no se puede probar aquí

El aislamiento se prueba **ejerciéndolo**: se bifurca un hijo, se le aplica el
sandbox y se le hace intentar exactamente lo que la política prohíbe. El
resultado se lee del código de salida, porque un hijo con seccomp puesto no puede
reservar memoria ni imprimir con seguridad. Probar un sandbox comprobando que la
función «no devuelve error» no prueba nada: un filtro con los números equivocados
también se instala sin error.

Cada caso lleva su **control sin sandbox**. Las llamadas de fuga usan PID `-1`,
que no existe: sin sandbox fallan con `ESRCH` y con sandbox con `EPERM`, y esa
diferencia es lo que demuestra que el `EPERM` viene del filtro y no del entorno.

El escenario 6 de la simulación de Red Team ejecuta un binario que se confina a
sí mismo y prueba **siete fugas** reales (socket, `ptrace`, leer y escribir
memoria ajena, `bpf`, `setuid`, `unshare`), y después comprueba que la política
de matar mata de verdad con `SIGSYS`.

> **Limitación honesta.** El kernel de la máquina de integración
> (`6.18.44-fc-v24`, un microVM de Firecracker) **no trae Landlock**
> (`CONFIG_SECURITY_LANDLOCK` desactivado). La capa de llamadas al sistema se
> ejerce por completo; la restricción por rutas está implementada y negocia la
> ABI, pero **aquí no se puede ejercer**, y la prueba correspondiente lo dice y
> se omite en vez de fingir que pasó. `make ci` imprime en cada ejecución qué
> capas ofrece la máquina, para que la diferencia entre «probado» y «no se pudo
> probar aquí» esté siempre a la vista.

---

## 20.7 Otras plataformas

`aegis-sandbox` es un error de compilación fuera de Linux, a propósito. El
equivalente en Windows es AppContainer con capacidades, y en macOS el sandbox de
Seatbelt; ninguno de los dos se puede fingir desde aquí, y un módulo que
devolviera «aislado» sin aislar sería peor que su ausencia. Cuando existan,
entrarán por la misma frontera que el resto de lo específico de cada sistema:
[la capa de abstracción](18-scal.md).
