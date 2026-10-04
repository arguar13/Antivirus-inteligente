# 79 · AegisMac y AegisEnforce — macOS, y qué se impone de verdad

> **macOS no es producto.** Hace falta que Apple apruebe el entitlement com.apple.developer.endpoint-security.client, una System Extension firmada con Developer ID y la notarización. Lo que este documento cuenta de macOS es biblioteca o diseño: no protege ninguna máquina macOS. Ver [Plataformas](matriz-capacidades.md#plataformas).

> FASE 84. `crates/aegis-macho/`, `crates/aegis-enforce/`,
> `tools/verificar-mac.sh`.

Son dos cosas en una fase porque cierran la misma pregunta desde dos lados: **qué
puede este agente, aquí, de verdad.**

---

## AegisMac — el fichero que contiene varios programas

### El problema, dicho sin adornos

En macOS un ejecutable puede contener **varios programas a la vez**, uno por
arquitectura, y el sistema elige cuál corre según la máquina.

Eso convierte la práctica habitual de análisis —abrir el fichero, coger la
primera rodaja, analizarla— en un punto ciego con nombre: se está analizando **el
programa que no se va a ejecutar** en la mitad del parque. Un atacante que ponga
código limpio en la rodaja x86_64 y su carga en la arm64 pasa por delante de
cualquier análisis que no mire las dos. Y hoy los Mac son arm64.

### Cómo se cierra

`Binario` **no tiene ninguna función que devuelva «la» rodaja**. No existe tal
cosa: quien consuma esto tiene que decidir explícitamente qué hace con cada una.

Esa ausencia es la parte importante del diseño, y la puerta la comprueba: una API
cómoda que devolviera la primera sería la forma más rápida de reconstruir el
punto ciego **dentro del propio producto** — y sería la que todo el mundo usaría,
porque devuelve un valor en vez de una lista.

Una rodaja que no se puede leer se guarda como `Result`, no se descarta: el
fichero sigue teniéndola y el sistema puede ejecutarla. Lo único que pasa es que
este lector no pudo mirarla, y eso es cobertura que falta, no una rodaja que no
existe.

### Las dos trampas del formato

**Dos órdenes de byte en el mismo fichero.** El encabezado universal es
big-endian siempre, por herencia de NeXT; los Mach-O de dentro son little-endian.
Leer el primero en orden nativo funcionaba en un PowerPC de 2003 y en ningún
ordenador de hoy: da un número de rodajas absurdo, y un lector que se fíe de él
reserva memoria por ese número.

**`0xcafebabe` no es solo de Apple.** Un fichero `.class` de Java empieza
exactamente igual. Se distinguen por lo que sigue: en un `.class` son dos números
de versión, que leídos como «número de rodajas» dan un valor enorme. Aquí un
recuento imposible se rechaza como tal.

### Y el campo que puede colgar al agente

`cmdsize` es el que mueve el cursor del recorrido de comandos de carga. A cero,
el bucle no avanza: **treinta y dos bytes bien puestos cuelgan al agente**. Sin
alinear a ocho, descoloca todos los comandos siguientes. Mayor que lo que queda,
manda a leer fuera. Los tres se comprueban antes de moverse.

---

## AegisEnforce — mirar y bloquear se parecen mucho por fuera

### El problema

Un EDR tiene dos modos, y la diferencia la nota el cliente **el día del
incidente**. Para entonces ya es tarde para descubrir que el mecanismo de bloqueo
nunca llegó a engancharse: el kernel no traía BPF LSM, el driver no estaba firmado
para esa versión de Windows, macOS no concedió el permiso, la interfaz no admitía
XDP.

En todos esos casos el agente **sigue funcionando**: recoge telemetría, correla,
alerta. Y su panel sigue diciendo «protegido».

**Un agente que no puede bloquear no está protegiendo: está mirando.** Son dos
productos distintos al mismo precio.

### Las tres reglas

1. **La postura se mide, no se configura.** Lo que declare un fichero sobre lo
   que el producto «tiene activado» no dice nada de lo que este kernel acepta.
   Cada capacidad se sondea contra el sistema de verdad.

2. **Poder observar no cuenta como poder aplicar.** `Estado::SoloObserva` existe
   para eso. Un mecanismo que ve pasar la operación y no puede negarla es
   telemetría; contarlo como aplicación es lo que produce el informe
   tranquilizador de una máquina desprotegida. En eBPF la distinción es exacta:
   los ganchos de traza —kprobes, tracepoints— ven y no paran; solo BPF LSM
   puede negar. Un producto que diga bloquear con kprobes está alertando.

3. **Lo que exige aplicación falla cerrado.** Una política que dice «esto no se
   ejecuta», desplegada sobre una máquina que no puede impedirlo, se rechaza en
   el despliegue — no se descubre en el incidente.

Y una cuarta que evita que todo esto se vuelva ruido: **lo de otras plataformas
no se cuenta como carencia**. Que en Linux no haya minifiltro no es un defecto de
la máquina. Si lo fuera, cada endpoint reportaría tres carencias por no ser
Windows ni un Mac, y el informe dejaría de leerse — que es la forma habitual de
que un aviso importante se pierda.

### La postura real de esta máquina de integración

> **Corrección (H-28).** La primera versión de esta sección daba seccomp y
> Landlock por impuestos solo porque el kernel los admitía: confundía «el kernel
> lo ofrece» con «el producto lo impone», que es justo la mentira que este crate
> existe para impedir. Desde H-28 son dos estados distintos, `Estado::Aplica`
> solo sale de evidencia medida sobre un proceso concreto, y esta tabla ya no se
> escribe a mano: la imprime `cargo run -p aegis-enforce --example postura` en
> cada `make ci`, y `tools/verificar-mac.sh` falla si algún texto del repo da por
> impuesta una capa que la postura medida no da por aplicada.

| Estado | Qué hace falta para decirlo |
|---|---|
| **aplica** | una evidencia medida sobre un proceso del producto (un *testigo*): un filtro seccomp propio en `/proc/<pid>/status` (`Seccomp: 2`, descontados los filtros heredados del padre), un dominio Landlock que el proceso declara tras `landlock_restrict_self` y que se corrobora desde fuera (vivo, `NoNewPrivs: 1`, ABI existente), o un enlace BPF LSM que el proceso sostiene y se ve en `/proc/<pid>/fdinfo` |
| **disponible** | el kernel lo ofrece y nada medido demuestra que el producto lo use |
| **solo observa** | se ve la operación y no se puede negar (kprobes sin BPF LSM) |
| **ausente** | el kernel no lo ofrece, con su motivo |
| **otra plataforma** | no es de este sistema operativo, y no cuenta como carencia |

Sin testigos —que es como mide la puerta: en el CI no corre ningún agente que
haya confinado nada— seccomp y Landlock salen **disponibles**, y el agente se
describe como «SOLO OBSERVANDO». Es la respuesta correcta: el kernel los ofrece,
y en esa máquina el producto no los está usando sobre ningún proceso.

Que BPF LSM falte o esté apagado se sigue diciendo **con su motivo y
distinguiendo «no trae el framework» de «lo trae y no está habilitado»**, porque
llevan a dos sitios distintos a quien lo lea. Y que esté habilitado ya no basta:
sin un enlace LSM medido, es solo disponible.

**El agente, con su trabajador como testigo.** El proceso del agente que de
verdad está confinado es su trabajador de análisis: se pone un dominio Landlock
sin reglas y un filtro seccomp en lista blanca antes de leer un byte. El agente
mide su postura con `aegis-enforce` pasándolo como testigo —su pid y la ABI de
Landlock que declara en su saludo (`landlock=si (N)`)— y la publica al arrancar,
en cada informe periódico y en `aegisctl status`: una línea por capa
(`aplicacion <capa>: ETIQUETA (evidencia o motivo)`), con la etiqueta y el
texto que da `aegis-enforce`. La mide el hilo que es dueño del trabajador, entre
dos peticiones: mientras no lo recoja, su pid no puede pasar a otro proceso, y
un trabajador muerto y aún sin recoger (zombi) no cuenta, aunque conserve en
`/proc` su filtro y su `NoNewPrivs`. Sin trabajador —no arrancó, murió y no se
ha relanzado, o se enfría tras morir en bucle— no hay testigo y ninguna capa
lleva la etiqueta de aplicado. BPF LSM no puede llevarla por esta vía: el
trabajador no sostiene enlaces BPF; cuando el agente cargue programas LSM, el
testigo de esa capa tendrá que ser el propio agente. Medir no cambia ninguna
decisión del agente: es solo-auditoría.

---

## Qué se prueba, y contra qué

Los Mach-O de las pruebas son **reales**: `clang` compila a Mach-O de 64 bits
para arm64 y para x86_64 sin necesitar un Mac, y los ficheros traen su
`MH_MAGIC_64` de verdad. Ninguna de las siete pruebas de integración se omitió, y
la puerta las cuenta con `--nocapture` para poder afirmarlo.

Lo que **no** hay aquí se declara en vez de disimularse:

- No hay `ld64.lld`, así que se compilan **objetos** y no ejecutables enlazados.
  Un objeto trae encabezado, comandos de carga y segmentos —lo que este lector
  recorre— y no trae `LC_MAIN` ni `LC_LOAD_DYLIB`, que solo aparecen al enlazar.
  Esos caminos se prueban con vistas construidas, y se dice cuál es cuál.
- No hay `llvm-lipo`, así que el contenedor universal lo monta la prueba. **Las
  rodajas son Mach-O reales; el sobre que las envuelve está construido.**

Las pruebas de `aegis-enforce` no usan una postura inventada: sondean **esta**
máquina. Sin testigos exigen que seccomp y Landlock salgan **disponibles** y no
aplicados; con un hijo real que se confina en su hilo (Landlock sin reglas y un
filtro seccomp) exigen que salgan con su evidencia, leída de `/proc/<tid>/status`;
y con el propio proceso de la prueba, que no se confinó, exigen que no la haya.
(Corrección H-28: antes exigían lo contrario solo porque el kernel los ofrecía.)

Treinta y siete pruebas, y la puerta número 32 de `make ci`.

## Lo que esta fase NO cierra

- **La validación de la firma de código de macOS.** Se localiza el
  `LC_CODE_SIGNATURE` y se dice qué bytes ocupa; validar el `SuperBlob`, su
  `CodeDirectory`, los hashes de página y la cadena hasta Apple es otro trabajo.
  Por eso el método se llama `declara_firma()` y no `firmado()`.
- **El camino de negación real de BPF LSM.** Ningún programa BPF LSM de este
  repositorio se carga todavía, así que la postura no puede darlo por aplicado
  en ninguna máquina; lo que no se puede es ejercer aquí el bloqueo.
