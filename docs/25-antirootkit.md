# Módulo 25 — Anti-rootkit: verificación cruzada del kernel

> Componentes: `drivers/linux/aegis-bpf/src/aegis_kintegrity.bpf.c` (Ring 0) + `crates/aegis-kintegrity` (Ring 3).

Un rootkit de kernel que hace **DKOM** (*Direct Kernel Object Manipulation*)
desenlaza el `task_struct` de su proceso de la lista global de tareas. Desde ese
momento el proceso es invisible para todo lo que recorra esa lista —`/proc`,
`ps`, `top` y cualquier EDR que le pregunte al sistema— pero **sigue
ejecutándose**, porque el planificador no usa esa lista: usa las colas de
ejecución, y el proceso sigue en el árbol de PID.

Preguntarle mejor al sistema no sirve: el sistema es justo lo que está
comprometido. Lo que sirve es preguntar por **caminos distintos** y comparar.

---

## 25.1 Las tres vistas

Cada vista sale de una estructura **distinta**, y ahí está toda la potencia del
método: un rootkit tiene que manipular las tres de forma coherente para
esconderse, y manipular las tres es mucho más difícil que manipular una.

| Vista | De dónde sale | Qué la manipula |
|---|---|---|
| **A** `procfs` | `/proc/<pid>/task/<tid>`, Ring 3 | hook de `getdents`, `LD_PRELOAD` sobre `readdir`, montaje encima de `/proc` |
| **B** lista de tareas | `bpf_iter_task_*`, Ring 0 | **DKOM**: desenlazar el `task_struct` |
| **C** espacio de PID | `bpf_task_from_pid()`, Ring 0 | borrar la entrada del `idr`, lo que deja al proceso **sin poder recibir señales** |

La asimetría es la firma:

- En **C pero no en B** → DKOM. El rootkit desenlaza de la lista para esconderse,
  pero deja el proceso en el árbol de PID o dejaría de ser planificable, que es
  tanto como matarlo.
- En **B y C pero ausente de A** → ocultación en espacio de usuario.
- En **A pero en ninguna vista de kernel** → entrada de `/proc` falsificada.

---

## 25.2 Las dos vistas de kernel van en una sola invocación

Entre una vista y la siguiente, los procesos nacen y mueren. Tomar B y C en dos
llamadas al sistema distintas deja una ventana de milisegundos que produce
discrepancias falsas **en cada barrido**. El programa eBPF las toma en una única
invocación, separadas por microsegundos: primero recorre la lista de tareas con
el iterador abierto `bpf_iter_task_*`, y acto seguido sondea el espacio de PID
con `bpf_task_from_pid()`.

Notas del verificador que costaron sangre y quedan escritas en el código:

- `bpf_iter_task_new` **exige** sección crítica RCU. Sin ella el verificador
  rechaza el programa, y hace bien: recorrer la lista de tareas sin RCU es un
  uso-después-de-liberar dentro del kernel.
- El iterador queda creado **aunque `new` falle**, así que
  `bpf_iter_task_destroy` tiene que llamarse en **todos** los caminos o el
  verificador lo rechaza por fuga de referencia.
- El barrido de 32768 PIDs va con `bpf_loop`, no desenrollado: desenrollado
  supera el límite de complejidad de saltos del verificador.

---

## 25.3 Las tres trampas que hacen inútil a un detector así

Cualquiera de las tres, mal resuelta, convierte el detector en un generador de
ruido que se desinstala la primera semana.

**1 · La granularidad.** `/proc/<pid>` de primer nivel lista solo líderes de
grupo de hilos; las vistas de kernel traen una entrada por **hilo**. Comparar la
una con las otras reportaría como oculto cada hilo secundario de cada proceso
multihilo: cientos de falsos positivos críticos en el primer barrido. Por eso la
vista A se construye recorriendo `/proc/<pid>/task/<tid>`, y las tres vistas son
de hilos.

**2 · La carrera.** Un `ls` que termina justo entre dos vistas aparece en una y
no en la otra. Por eso la comparación produce **candidatos**, no acusaciones, y
solo una **confirmación** —volver a mirar ese TID por los dos caminos, con
microsegundos de diferencia— los convierte en anomalías. Un proceso que murió
desaparece de las dos vistas; uno oculto conserva la asimetría. Y se exigen
confirmaciones **consecutivas**: una carrera que parpadea nunca suma el umbral.

**3 · Las tareas ociosas.** Tienen PID 0, no salen en `/proc` y
`bpf_task_from_pid(0)` no las resuelve. Sin excluirlas, cada CPU produce una
anomalía en cada barrido.

Una cuarta, más sutil: la **confirmación de la vista A usa el mismo canal que la
vista original** —el listado del directorio, es decir `getdents`—, no el acceso
directo a `/proc/<tid>`. Confirmar por acceso directo consultaría un oráculo que
un rootkit de `getdents` no toca, y descartaría una detección legítima.

---

## 25.4 Qué se prueba, y contra qué

Montar un rootkit DKOM de verdad exige cargar un módulo de kernel, y el kernel de
integración de este proyecto está compilado **sin soporte de módulos**
(`# CONFIG_MODULES is not set`). Fingirlo con datos inventados violaría la regla
de cero simulaciones. La estrategia es la que un ingeniero honesto usa cuando no
puede reproducir la causa pero sí el mecanismo:

- **La lógica que acusa** (`verdict`, `engine`) es pura: recibe vistas ya tomadas
  y se prueba con vistas construidas a mano que reproducen cada clase de
  manipulación —DKOM, ocultación de userland, entrada fantasma, identidad
  incoherente— y cada trampa —hilos, carrera, PID 0, barrido desbordado—.
- **El mecanismo completo** se prueba contra el kernel **real**: se cargan las
  sondas eBPF de verdad y se comprueba que los ~115 hilos reales de la máquina no
  producen **ni un** falso positivo (una prueba tan exigente como detectar un
  rootkit, y mucho más reproducible), y se **detecta de verdad** una ocultación
  de userland inyectada sobre un hilo real: todo lo de kernel es auténtico, solo
  la vista de `/proc` está manipulada —exactamente lo que un rootkit de
  `getdents` manipula—.

El escenario 10 de la simulación de Red Team ejecuta esa detección de extremo a
extremo. En una máquina sin los kfuncs necesarios (`bpf_task_from_pid`, Linux
6.1; `bpf_iter_task_*`, Linux 6.7) el escenario se **omite diciéndolo**, no pasa
en falso.

---

## 25.5 Respuesta

Una anomalía confirmada de clase `DkomUnlinked` (gravedad 100) o `UserlandHidden`
(95) exige mitigación de máxima severidad: no hay lectura benigna de un proceso
que el sistema operativo esconde por su cuenta. Las clases que pueden darse de
forma transitoria durante el desmontaje de una tarea —`PidSpaceDetached`,
`PhantomProcEntry`— pesan menos aunque también se confirmen, y no disparan acción
automática.

El bytecode del verificador va **firmado con HMAC** y empotrado en el binario,
igual que las sondas de telemetría (módulo 14): el cargador recalcula la firma
sobre el objeto empotrado y la compara antes de entregarlo al kernel, de modo que
un `.o` parcheado dentro del binario del agente se rechaza.
