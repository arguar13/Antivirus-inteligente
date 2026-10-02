# Módulo 108 — AegisTruth: verdad, CI remoto y matriz de kernels (FASE 0 del MP-15)

> Componentes: `xtask/` (`cargo xtask`), `tools/config/`, `tools/matriz-kernels/`,
> `crates/aegis-agent/src/capacidades.rs`, `.forgejo/workflows/ci.yml`, `deploy/ci/`,
> [modelo de amenazas](modelo-de-amenazas.md) v1, [matriz de capacidades](matriz-capacidades.md).

## La causa raíz que cierra

El proyecto se había validado en **un solo kernel** (el de WSL2), el **CI remoto no
arrancaba** y la **documentación contaba lo que no se ejecutaba**. Las tres cosas se
alimentaban entre sí: sin una matriz de kernels no se veía que el agente no cargaba
en distribuciones corrientes; sin CI remoto nadie más que el desarrollador ejecutaba
las puertas; y sin una documentación generada desde los binarios, lo escrito en fases
anteriores —«motor conductual», «rollback de ransomware», «TLS en claro»— se leía como
producto cuando era biblioteca.

## Qué se hizo, y la puerta que lo sostiene

| Entrega | Qué es | Puerta |
|---|---|---|
| Matriz de capacidades | Por crate: qué instalable lo **enlaza** (`cargo tree`), cuál lo **invoca** (símbolos y DWARF que sobreviven al LTO en el binario release), qué prueba e2e lo ejerce, qué medida tiene y su estado | `make ci` grupo `documentacion` (`cargo xtask docs --comprobar`) |
| README generado | La prosa en `docs/plantillas/README.md`; cifras, tablas y el diagrama C4 salen del código; sin cifras escritas a mano | mismo grupo; la plantilla con una cantidad a mano no genera |
| Diagrama C4 con evidencia | Cada flecha exige un fichero y un texto del código; desaparecen `aegis-ui` y los servicios en Go | mismo grupo |
| Detección de capacidades | `aegis-agent --capacidades`: BTF, tracefs, ringbuf, BPF LSM, cgroup, SELinux/AppArmor, lockdown; degradación **por familia** y siempre declarada | prueba que abre el objeto real y exige familia para toda sonda |
| Matriz de kernels | Cada distribución real en su microVM (KVM; aarch64 en emulación): capacidades, verificador sobre los cinco objetos eBPF, agente en vivo con medidas | `make ci` grupo `kernels` (obligatorio) |
| CI remoto | Forgejo Actions con runner propio y KVM que ejecuta `make ci` entero | `.forgejo/workflows/ci.yml` |
| Modelo de amenazas | Cinco adversarios, control existente/parcial/ausente/aceptado con evidencia | `make ci` grupo `arquitectura` (`cargo xtask amenazas`); las fases siguientes tienen que citarlo |
| Higiene | cargo-deny, cargo-audit y cargo-vet en los cuatro workspaces; capas sin ciclos; idioma único con renombrado planificado | grupos `cadena` y `arquitectura` |

## La matriz de kernels, al cerrar la fase

Diez imágenes, diez verdes. En cada una: los cinco objetos eBPF pasan el
verificador de ESE kernel (o `kintegrity` se declara *no aplica* con la kfunc que
falta o que no se permite), el agente publicado arranca como servicio de systemd y
consume actividad real sin perder eventos, y una conexión TCP real llega con su IP,
su puerto y su marca de loopback.

| Imagen | Kernel | Degradaciones declaradas |
|---|---|---|
| Debian 11 | 5.10 | BPF LSM inactivo |
| Rocky Linux 9 | 5.14-el9 | SELinux en enforcing |
| Ubuntu 22.04 | 5.15 | BPF LSM inactivo |
| Debian 12 | 6.1 | ninguna |
| Amazon Linux 2023 | 6.1 | ninguna |
| openSUSE Leap 15.6 | 6.4 | ninguna |
| Ubuntu 24.04 | 6.8 | BPF LSM inactivo |
| Fedora 44 | 6.19 | SELinux en enforcing |
| Ubuntu 24.04 (aarch64) | 6.8 | BPF LSM inactivo; `sys_enter_rename` no existe en ARM (la familia sigue viva por `renameat2`) |
| Debian 12 (aarch64) | 6.1 | ninguna |

Las cifras de cada ejecución (eventos emitidos y perdidos, memoria del agente en
vivo) las publica cada tanda en `matriz-kernels/resumen.md`; no se copian aquí a
mano porque cambian con cada imagen vigente.

## Veredicto

`make ci` pasa entero en el runner remoto, en un clon limpio y con la matriz de
diez kernels incluida: ejecución 6 de Forgejo Actions sobre `52c231c`, 38 minutos.
Las cinco ejecuciones anteriores fallaron, y cada fallo está en las tablas de abajo
con su causa raíz y su puerta.

## Hallazgos, cada uno con su arreglo de raíz

| Hallazgo | Causa raíz | Arreglo | Puerta |
|---|---|---|---|
| El agente no arrancaba en aarch64 | `preflight` exigía TODOS los tracepoints; `sys_enter_rename` no existe en ARM | Plan de sondas desde las secciones ELF y degradación por familia | prueba del objeto real |
| **Los eventos de red nunca llevaron su IP** (todos los kernels), y el agente no cargaba en Ubuntu 22.04 | `bpf_core_read(dst, 4, ctx->saddr)`: el array no decae dentro de `__builtin_preserve_access_index`, y se usaba su CONTENIDO como dirección de origen. Se leían bytes arbitrarios del kernel (una conexión a 127.0.0.1 llegaba como 255.64.239.114, sin marca de loopback). Solo el verificador de 5.15 rechazaba el patrón | Origen `&ctx->saddr`, leído directo al registro del ring buffer | `crates/aegis-e2e/tests/red_en_vivo.rs`, en cada kernel de la matriz; demostrado fallando con el código viejo |
| El agente abortaba entero si SELinux denegaba un enganche | El primer error de `attach` era fatal | Degradación por sonda también en el enganche; fatal solo sin ninguna viva | prueba de `recalcular_familias` y matriz (Rocky, Fedora) |
| La prueba del agente corría fuera de su dominio SELinux | Se lanzaba desde cloud-init (confinado) y con salida a un fichero que systemd no podía abrir (209/STDOUT) | Se ejecuta como se instala: `/usr/local/bin`, servicio de systemd, salida al journal | matriz de kernels |
| `sslsniff` no cargaba en Debian 11 (5.10) | Incremento atómico innecesario sobre un mapa por CPU (BPF_ATOMIC, 5.12+) | Incremento normal, como el resto de sondas | matriz de kernels |
| `kintegrity` «fallaba» en Ubuntu 24.04 (6.8) | La kfunc existe pero ese kernel no la permite en programas `syscall`; se tomaba por fallo del objeto | El verificador distingue «no permitida en este tipo» para las kfunc exigidas: *no aplica* con motivo | matriz de kernels |
| El bytecode empotrado era x86 en compilación cruzada | El Makefile tomaba `uname -m`; los `build.rs` no pasaban la arquitectura | Arquitectura desde `CARGO_CFG_TARGET_ARCH`, en un solo sitio para los cuatro `build.rs` | matriz aarch64 |
| El bucle del agente solo usa grafo y triaje | Los motores estaban en el árbol, pero `main` no los llama | Declarado: la matriz lo muestra como «enlaza sin invocar» | grupo `documentacion` |
| El watchdog vigila un latido que el agente no escribe | Dos binarios con un contrato que solo uno cumple | Declarado (AM-1.2) | modelo de amenazas |
| `aegis-fleet` es una demostración autocontenida | Su `main` levanta su propia CA y su propio servidor | Declarado; el diagrama no dibuja esa flecha | evidencia del C4 |
| La API de administración no autentica | `abrir_sesion` emite sesión a cualquier usuario no vacío | Declarado como el control más grave (AM-3.3) | modelo de amenazas |
| La auditoría de dependencias no se había ejecutado nunca | No estaba en `make ci` y se «omitía» si faltaba la herramienta | En `make ci`, falla si falta; vulnerabilidades reales corregidas (rustls, time, hickory, ldap3/rustls-webpki, wasmtime) | grupo `cadena` |
| El trabajo hermético se omitía en silencio | Sin sysroot salía con código 0 | Ahora falla; y respeta `CARGO_TARGET_DIR` | grupo `hermetico` |
| `ci-local.sh` «igual al workflow» no lo era | Dos listas de pasos que divergieron | El CI remoto ejecuta `make ci`: una sola definición | por construcción |
| Una prueba e2e dependía de un `sleep` | Suponía el enganche de las sondas en 700 ms | Espera la señal real (primer evento del kernel) | la propia prueba |
| La matriz perdía resultados en Rocky, Fedora y openSUSE | La consola serie la revoca `agetty` (vhangup) al arrancar el getty | Resultados en un disco de salida, no en la consola | matriz de kernels |
| La imagen ARM no pasaba del firmware en 40 minutos | `-cpu max` emula en software la autenticación de punteros en cada instrucción | CPU Cortex-A72: llega a systemd en minutos | matriz aarch64 |
| La imagen ARM rozaba el plazo de 40 minutos | Sin fuente de entropía, el kernel emulado tardaba más de 3 minutos en iniciar su generador aleatorio y systemd y cloud-init esperaban detrás | `virtio-rng` y 4 vCPU emuladas (QEMU traduce cada una en su hilo): de más de 2400 s a entre 680 y 1070 s | matriz aarch64 |
| Las pruebas e2e con sondas escondían el error de carga | El hilo de telemetría descartaba el resultado de `bpf::run`: un fallo al cargar se leía como «ningún evento en 20 s» | El error de carga es el diagnóstico; el plazo cubre el verificador bajo emulación | `red_en_vivo.rs`, `malware_blocked.rs` |

> **Corrección (MP-16, kintegrity con iteradores).** La fila «`kintegrity`
> «fallaba» en Ubuntu 24.04 (6.8)» y el *no aplica* «con la kfunc que falta o que
> no se permite» del apartado de la matriz describen un arreglo que ya no está en
> vigor. El diagnóstico era correcto —el kernel registra `bpf_task_from_pid` y
> `bpf_task_release` por tipo de programa, y para `syscall` no los admite hasta
> 6.10—, pero declarar *no aplica* en 6.8 tapaba un defecto del objeto, no una
> carencia del kernel. Los programas son ahora iteradores `iter.s/task` (tipo
> tracing), que admiten esas kfunc desde que existen; la matriz las exige desde
> Linux 6.7 (`obligatorio_desde` en `tools/config/kernels.toml`) y por encima un
> *no aplica* es un fallo. La vía «no permitida en este tipo» de
> `aegis_bpf_verify.c` sigue, pero desde 6.7 ya no tapa nada.
>
> En el mismo cambio, la vista C (el espacio de PID) dejó de recortarse en
> silencio a `MAX_BARRIDO` PID por invocación: cubre `pid_max` entero por tramos,
> con presupuesto (`PRESUPUESTO_TRAMOS`) y rotación
> (`crates/aegis-kintegrity/src/tramos.rs`), así que un barrido puede ser
> parcial. Un barrido parcial no es «sin datos» —en Ubuntu y Fedora lo sería cada
> barrido— ni autoriza «limpio»: el motor `nucleo` publica en su línea del
> informe periódico y de `aegisctl status` cuánto sondeó el último barrido y
> cuántas vueltas completas lleva, y cómo acabaron (`cobertura: …`), y solo
> afirma «limpio» de una vuelta completa sin hallazgos. Las cifras de cada
> máquina salen de esa línea; no se copian aquí.

**Lo que destapó el primer runner independiente.** Todo lo de arriba pasaba en la
máquina de desarrollo. La primera ejecución en un clon limpio falló en quince grupos,
y ninguno era un defecto del producto: eran dependencias ocultas del entorno de quien
desarrolla, que habrían roto a cualquiera que clonase el repositorio.

| Hallazgo | Causa raíz | Arreglo | Puerta |
|---|---|---|---|
| «Permission denied» en 21 scripts, 16 de ellos verificadores | Creados desde Windows: NTFS bajo WSL los muestra ejecutables, git los guardó 100644 | Bit de ejecución en el índice de git | grupo `permisos` |
| `aegis-ml`, `aegis-edgeml` y `aegis-l7hunter` no compilaban | Los modelos de referencia que incrustan estaban excluidos por `*.onnx` en `.gitignore` | Versionados, con la excepción explicada (los de producción siguen fuera) | `cargo xtask incrustados` (todo `include_bytes!` en git) |
| Las sondas no compilaban (y con ellas, clippy, pruebas, IPS, hermético, matriz…) | El BTF con el que se generan los tipos era el del kernel en marcha, o uno extraído a mano que solo existía en esta máquina | BTF de construcción fijado y obtenido de forma reproducible de la imagen oficial de Ubuntu 24.04 | `make ci` lo exige antes de empezar |
| El CI moría a mitad en este PC | WSL apaga la distribución sin terminales conectadas, y con ella la forja y el runner | `deploy/ci/ci-en-este-pc.sh` se queda conectado durante la ejecución y apaga los servicios al acabar | ejecución completa |
| Ficheros con CRLF rompían bash | Ediciones hechas con herramientas de Windows | `.gitattributes` con LF y grupo `finales` | `make ci` |
| Con el BTF ya fijado, clippy seguía sin compilar `aegis-net` en el runner | `vmlinux.h` solo dependía de existir: el directorio de salida de Cargo, reutilizado, conservaba el de otro BTF (sin `bpf_iter_task`); y tres de los cuatro `build.rs` no se reejecutaban al cambiar `AEGIS_BTF` | Sello con la ruta y la suma del BTF de origen, del que depende `vmlinux.h`; los cuatro `build.rs` siguen a `AEGIS_BTF` | `make check-btf-sello`, grupo `bpf` (demostrado fallando con la regla vieja) |
| Un verificador abortaba con «HOME: unbound variable» solo en el runner | Una unidad de systemd sin `User=` no define `HOME` | `User=root` en la unidad del runner | `instalar-runner.sh --comprobar`, que el flujo ejecuta antes de `make ci` |

## Controles del modelo de amenazas que toca

- **AM-1.5** pasa de ausente a *parcial*: las capacidades se detectan y la degradación se
  declara al arrancar; falta re-evaluarla en ejecución.
- **AM-3.3**, **AM-4.1**, **AM-1.2** y **AM-5.3** quedan escritos como los huecos más
  graves y son la entrada de las fases de integración y endurecimiento.

## Lo que no se hizo, y los muros

- **Integrar las bibliotecas** en el agente no es de esta fase: esta fase las *cuenta*.
  La matriz lo dice crate a crate.
- **Renombrado al español**: planificado en `tools/config/nombres.toml`, con techo que
  solo puede bajar; no ejecutado.
- **Una máquina dedicada para el CI remoto** es un recurso del propietario, como el
  certificado de Microsoft. Por su decisión, forja y runner viven hoy en el PC de
  desarrollo; el repositorio trae todo para moverlos con una orden
  ([ci-remoto.md](ci-remoto.md)).
- **SLES 15** exige registro: la matriz usa openSUSE Leap 15.6, su base binaria.

## Cómo se verifica

```bash
make ci                                  # todas las puertas, matriz de kernels incluida
cargo xtask docs --comprobar             # README y matriz coinciden con los binarios
cargo xtask kernels ejecutar             # cada distribución en su microVM
cargo xtask arquitectura                 # capas, nombres y modelo de amenazas
```
