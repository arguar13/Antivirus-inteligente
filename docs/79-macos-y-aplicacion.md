# 79 · AegisMac y AegisEnforce — macOS, y qué se impone de verdad

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

| Capacidad | Estado |
|---|---|
| seccomp | **aplica** |
| Landlock | **aplica** |
| BPF LSM | **no está**: este kernel ni siquiera publica `/sys/kernel/security/lsm` |
| XDP | se mide por interfaz al programarlo |
| minifiltro, ObCallbacks, Endpoint Security | otra plataforma |

Que BPF LSM falte no es el resultado interesante. Lo interesante es que **la
postura lo dice, con su motivo y distinguiendo «no trae el framework» de
«lo trae y no está habilitado»**, porque llevan a dos sitios distintos a quien lo
lea. Es exactamente el caso que el crate existe para no dejar pasar.

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
máquina y exigen que seccomp y Landlock salgan aplicando —porque están— y que BPF
LSM salga con su motivo —porque no está—. Si el kernel cambia, la prueba falla y
alguien lo mira, que es lo que tiene que pasar.

Treinta y siete pruebas, y la puerta número 32 de `make ci`.

## Lo que esta fase NO cierra

- **La validación de la firma de código de macOS.** Se localiza el
  `LC_CODE_SIGNATURE` y se dice qué bytes ocupa; validar el `SuperBlob`, su
  `CodeDirectory`, los hashes de página y la cadena hasta Apple es otro trabajo.
  Por eso el método se llama `declara_firma()` y no `firmado()`.
- **El camino de negación real de BPF LSM.** Este kernel no lo trae. La postura
  lo detecta y lo declara, que es lo que se le pedía; lo que no se puede es
  ejercer aquí el bloqueo.
