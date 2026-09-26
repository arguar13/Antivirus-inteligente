# AegisConfine — confinamiento que se aprende, se ensaya y se retira solo

**FASE 93.** Crate nuevo `crates/aegis-confinar`; supervisión por notificación de
seccomp y perfiles aprendidos en `crates/aegis-sandbox`. Puerta:
`tools/verificar-confinar.sh` (grupo `confinar` de `tools/ci-local.sh`).

## La pregunta

SELinux, AppArmor, gVisor y Kata saben confinar. Lo que no resuelven es **de dónde
sale la política**: una persona la escribe, o una herramienta la propone y una
persona la acepta regla a regla. Y cuando la política rompe algo, el servicio
falla hasta que alguien intervenga; la salida habitual es apagar el confinamiento
en toda la máquina.

Esta fase construye el ciclo entero sin una persona en cada vuelta: **aprender** lo
que un programa hace de verdad, **ensayarlo** sin romper nada, **imponerlo** sólo con
una confirmación explícita, y **retirarse solo** si rompe la producción.

## El inventario de partida

| Pieza | Qué hacía | Qué le faltaba |
|---|---|---|
| `aegis-sandbox` | seccomp como lista negra por familias y Landlock como lista blanca de rutas | dos políticas escritas a mano, que no saben nada del programa concreto |
| `aegis-enforce` | mide qué se puede imponer en la máquina | mide, no confina |
| jaula de detonación | microVM para muestras | es para analizar muestras, no para correr un servicio |

## Cómo se aprende sin tocar el proceso

Hay tres formas de ver desde fuera lo que hace un proceso, y sólo una sirve:
`ptrace` da control total y el proceso lo nota; `SECCOMP_RET_LOG` escribe en un
log limitado en ritmo, y un aprendizaje que pierde llamadas produce un perfil que
rompe el programa. La **notificación de usuario de seccomp** suspende cada llamada
y se la entrega al supervisor con su número y sus argumentos; el supervisor la
deja seguir. No se pierde ninguna.

El arranque tiene un detalle que lo decide todo: la escucha nace en el hijo al
instalar el filtro, y el padre la necesita. Pasarla por un socket exige un
`sendmsg` que, con el filtro puesto, quedaría suspendido esperando a un supervisor
que todavía no la tiene. La solución: el hijo hace `dup3` de la escucha a un
descriptor fijo (y el filtro deja pasar **sólo** ese `dup3`), llama a `execve`
—que se notifica, así que el hijo queda suspendido antes de que `O_CLOEXEC` cierre
la escucha— y el padre la recoge con `pidfd_getfd`.

Medido sobre `/bin/sh` real: 75 llamadas, 28 distintas, y la salida idéntica a la
de sin supervisión.

## El perfil como tipo, y su traducción comprobada

| Del perfil | A | Aprendiendo | Permisivo | Obligatorio |
|---|---|---|---|---|
| llamadas | seccomp | todo se notifica | lo aprendido pasa; lo demás se notifica y se anota | lo aprendido pasa; lo demás, `EPERM` |
| familias de socket | argumento 0 de `socket` | se notifica | se compara | sólo las aprendidas |
| rutas | Landlock | — | se comprueban en el supervisor | reglas de Landlock |
| capacidades | conjunto límite | — | — | se quitan las no retenidas |

La traducción no es una intención: una prueba recorre **las 385 llamadas de la
tabla** con un intérprete de BPF y exige que cada aprendida pase y cada no
aprendida dé `EPERM`. La tabla de números sale de la cabecera del kernel
(`tools/generar-tabla-llamadas.sh`) y otra prueba la vuelve a cotejar con ella:
un número equivocado confinaría la llamada que no es.

Las rutas se generalizan con reglas escritas: los prefijos del sistema enteros en
lectura (cambian con cada actualización); en los directorios sensibles, **el
fichero y nunca el directorio** —leer `/etc/hostname` no da `/etc/shadow`—; `/proc`
y `/sys` enteros; lo demás, su directorio. Con un tope de 128 reglas que sube de
nivel sin llegar nunca a `/`, y que avisa si ni así cabe.

Las capacidades se deducen de las llamadas (`mount` exige `CAP_SYS_ADMIN`, un
`bind` a un puerto bajo `CAP_NET_BIND_SERVICE`). Las que **no se pueden deducir**
—un root que abre un fichero ajeno usa `CAP_DAC_OVERRIDE` sin que ninguna llamada
lo diga— se conservan en los procesos de root, y se dice por qué.

## Lo que el kernel hizo, medido

Con un programa de C propio de modos conocidos, contra el kernel real:

| Qué | Resultado |
|---|---|
| Aprender el modo normal | 20 llamadas distintas de 385, en ~5 ms |
| Ensayo permisivo con el modo desviado | el socket se abre y `/etc/passwd` se lee **de verdad**; los dos quedan anotados como «habría bloqueado» |
| Imponer, modo normal | funciona: `hostname=ok` |
| Imponer, modo desviado | `socket=Operation not permitted` (**seccomp**) y `passwd=Permission denied` (**Landlock**) |
| Capacidades de un proceso de root | `CapEff` = `0x3e`: sólo las cinco implícitas; `CAP_SYS_ADMIN` y el resto, fuera |
| Perfil deliberadamente roto (sin `openat`) | falla, falla, falla, **se retira solo**; el siguiente arranque, sin perfil, funciona |

Y sobre un programa real del sistema (`ls`, que en esta máquina es el de coreutils
en Rust):

| Medida | Cifra |
|---|---|
| Superficie de llamadas que se cierra | **91,7 %** (32 de 385 permitidas) |
| Aprender | 19 ms |
| Ejecutar libre / confinado / supervisado | 5,4 ms / 9,2 ms / 16,9 ms |
| Ensayo sobre otro directorio | anota la lectura de `/etc` que el perfil no cubre, sin bloquearla |

## Lo que encontró la fase por el camino

| Defecto | Corrección |
|---|---|
| El aprendizaje anotaba los ficheros que el cargador **intentó** abrir y no existían (las rutas de `LD_LIBRARY_PATH` del entorno de pruebas); al imponer, Landlock no puede poner una regla sobre algo que no existe y la compilación fallaba | se omiten al compilar, no en el perfil: abrir algo inexistente da `ENOENT` antes de que Landlock mire, y el modo permisivo sigue comprobando contra todas |
| El perfil retenía `CAP_SYS_RESOURCE` por `prlimit64`, que glibc llama al arrancar **cualquier** programa, pero sólo para leer (tercer argumento nulo) | la capacidad se deduce sólo si se fija un límite nuevo |

## El modo que no rompe al cliente

1. El modo por defecto es **aprender**, que no bloquea nada.
2. Después se **ensaya** en permisivo.
3. El obligatorio no se puede construir sin una `Confirmacion` con autor y motivo:
   sus campos son privados y no tiene valor por defecto (dos `compile_fail` con su
   código de error, y la invariante 12 lo comprueba por ausencia).
4. Además, el despliegue no impone sin un **ensayo permisivo limpio**.
5. Si con el perfil impuesto el proceso falla tres veces —o se reinicia diez— en
   diez minutos, el perfil **se retira solo** y se avisa. La retirada es
   **pegajosa**: estabilizarse sin perfil no demuestra que el perfil fuera bueno,
   así que para volver hace falta aprender de nuevo y confirmar de nuevo.

Lo que no se puede deshacer, dicho: seccomp y Landlock no se quitan de un proceso
vivo. «Retirar» es que el **siguiente** arranque vaya sin perfil.

## El confinamiento como arma contra el propio producto

Un motor que puede dejar sin red, ficheros o capacidades a cualquier proceso,
vuelto contra el propio agente, lo ciega; contra `init` o `sshd`, deja al cliente
sin máquina o sin forma de entrar a arreglarla. La comprobación está en el
**constructor** del objetivo, no en el código que aplica: no se puede construir un
`ObjetivoConfinable` para el binario que está corriendo, para ningún binario
`aegis-*`, para lo que corre como proceso 1 —se mire por la ruta que se mire— ni
para los activos protegidos, también a través de un enlace simbólico.

## Cuando un perfil no basta

Un perfil deja al proceso en el mismo kernel: una vulnerabilidad en una llamada
permitida es un escape. Para el riesgo alto lo que toca es otro kernel, el de una
microVM —lo que hacen gVisor y Kata—, y el producto ya tiene esa jaula. Aquí se
decide cuándo y se prepara la solicitud, con el perfil dentro; si la máquina no
tiene `/dev/kvm`, se dice, no se sustituye por un perfil en silencio. (Esta la
tiene.)

La desviación del perfil llega al árbitro como una señal **conductual débil**:
sola no mueve nada, corroborada por otro plano es lo que el árbitro necesita. Un
ensayo sin desviaciones no se manda como «limpio».

## La comparación

**Lo que los otros hacen mejor**, primero:

- **gVisor y Kata** ponen una frontera mucho más fuerte: otro kernel. Un perfil de
  seccomp y Landlock reduce la superficie del kernel compartido; no la sustituye.
  Aquí esa frontera se delega en la microVM de la jaula, no se reimplementa.
- **SELinux** tiene control de acceso obligatorio por etiquetas sobre todo el
  sistema, incluidas las transiciones entre dominios, que un perfil por proceso no
  expresa. **AppArmor** tiene años de perfiles publicados por las distribuciones.
- **AppArmor ya aprende**: `aa-genprof` y `aa-logprof` proponen reglas desde el
  modo *complain*, y SELinux tiene `audit2allow`. Lo que no hacen es cerrar el
  ciclo solos: una persona acepta cada regla, y si la política rompe el servicio,
  nada la retira.

Lo de este lado: el perfil sale del programa real sin intervención; el ensayo
permisivo es de verdad (el supervisor deja pasar y anota); el obligatorio exige
confirmación en el tipo; la reversión es automática y pegajosa; el motor no puede
volverse contra el agente ni contra los activos protegidos; y todo usa el mismo
modelo de entidad y el mismo árbitro que el resto del producto.

**Lo que no se ha podido medir contra ellos**, declarado: en la máquina de
integración los LSM activos son `capability, landlock, yama, safesetid, selinux`;
SELinux está sin política cargada y AppArmor no está activo (activarlo exige
cambiar la línea de arranque del kernel). gVisor y Kata no están instalados. La
comparación con ellos es por propiedades; lo propio está medido arriba.

## Tabla de honestidad

| Pieza | Aquí | Cómo |
|---|---|---|
| Supervisión por notificación | **sí** | procesos reales (`/bin/sh`, el programa de prueba, `ls`) |
| Tabla de llamadas | **sí** | generada de la cabecera y cotejada con ella en cada `make ci` |
| Lista blanca | sí | intérprete de BPF sobre las 385 llamadas |
| Aprender, ensayar, imponer | **sí** | contra el kernel real, con seccomp y Landlock de verdad |
| Capacidades | **sí** | `CapEff` del proceso confinado, leído de `/proc` |
| Reversión | **sí** | con un perfil roto sobre un proceso real |
| Autoataque | **sí** | el agente, un binario `aegis-*`, `init` y activos protegidos |
| Red por Landlock | — | ABI 3 en este kernel: la red la cubre seccomp; Landlock de red exige ABI 4 |
| MicroVM | parcial | la decisión y la solicitud; la ejecución es de la jaula del plano de control |
| Comparativa medida con SELinux, AppArmor, gVisor, Kata | — | no ejecutables aquí; ver arriba |

## El muro, declarado

- **El aprendizaje es una ejecución dedicada**: el filtro no se puede quitar de un
  proceso vivo, así que al acabar la ventana ese proceso se termina. Se aprende en
  un entorno de ensayo, no espiando la instancia de producción.
- **Leer rutas de la memoria del proceso tiene carrera** y no importa: el
  supervisor aprende y anota; lo que se impone lo impone el kernel sobre el objeto
  ya resuelto.
- **Las capacidades implícitas se conservan en root** porque no se pueden deducir.
  Es la dirección segura del error, y se dice.
