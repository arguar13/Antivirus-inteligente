<!--
  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.
  Los datos viven en tools/config/ y en el codigo.
-->

# Matriz de capacidades

El estado **real** de cada crate de AegisCore: qué llega a una máquina, qué se ejecuta de verdad, qué se ha probado sobre un kernel real y qué se ha medido. Se calcula compilando los ejecutables instalables y leyendo sus símbolos; no se declara a mano.

## Criterios

| Estado | Criterio |
|---|---|
| **Producto** | (a) lo **invoca** un ejecutable instalable —sobreviven símbolos suyos en el binario release, tras el LTO—; (b) lo ejerce una **prueba de extremo a extremo** de la matriz de kernels; (c) tiene al menos una **medida** publicada (`AEGIS-MEDIDA`). |
| **Condicional** | lo invoca un instalable, pero depende de hardware o de un certificado; lo detecta en tiempo de ejecución y declara la degradación ([`tools/config/condiciones.toml`](../tools/config/condiciones.toml)). |
| **Biblioteca** | todo lo demás: código probado que hoy no protege ninguna máquina. |
| **Herramienta** | crates de prueba; no se instalan. |

**Enlazar no es invocar.** Un crate puede estar en el árbol de dependencias de un binario y no ejecutarse nunca: el enlazador lo descarta entero. La columna *invocado por* solo cuenta los crates de los que queda código en el binario.

## Resumen

| Espacio de trabajo | Producto | Condicional | Biblioteca | Herramienta |
|---|---:|---:|---:|---:|
| Agente (`crates/`) | 8 | 1 | 65 | 2 |
| Plano de control (`server/crates/`) | 0 | 0 | 19 | 1 |
| Enjambre (`swarm-net/`) | 0 | 0 | 1 | 0 |

**Producto** = lo invoca un ejecutable instalable, lo ejerce una prueba de extremo a extremo en la matriz de kernels y tiene una medida. **Condicional** = lo mismo, pero depende de hardware o de un certificado y lo declara. **Biblioteca** = código probado que hoy no protege ninguna máquina. Detalle crate a crate, con lo que le falta a cada uno: [matriz de capacidades](#por-crate).

## Por ejecutable instalable

### `aegis-agent` (endpoint)

El agente EDR: sondas eBPF de kernel, grafo de linaje y triaje.

- **Invoca** (34): `aegis-agent`, `aegis-behavior`, `aegis-captura`, `aegis-contenido`, `aegis-ctl`, `aegis-disasm`, `aegis-emu`, `aegis-enforce`, `aegis-entidad`, `aegis-fleet`, `aegis-harden`, `aegis-integridad`, `aegis-ipc`, `aegis-kguard`, `aegis-kintegrity`, `aegis-l7hunter`, `aegis-macho`, `aegis-memhunter`, `aegis-ml`, `aegis-motor`, `aegis-patron`, `aegis-pe`, `aegis-pqc`, `aegis-presupuesto`, `aegis-ransom`, `aegis-resp`, `aegis-sandbox`, `aegis-scal`, `aegis-scan`, `aegis-sigma`, `aegis-trabajador`, `aegis-update`, `aegis-vuln`, `aegis-watchdog`
- **Enlaza sin invocar** (6): `aegis-disectores`, `aegis-edgeml`, `aegis-net`, `aegis-procedencia`, `aegis-sensor`, `aegis-wire`

### `aegisctl` (endpoint)

CLI de administración local sobre el socket de control del agente.

- **Invoca** (1): `aegis-ctl`
- **Enlaza sin invocar** (11): `aegis-captura`, `aegis-disectores`, `aegis-entidad`, `aegis-ipc`, `aegis-net`, `aegis-patron`, `aegis-presupuesto`, `aegis-resp`, `aegis-scal`, `aegis-scan`, `aegis-wire`

### `aegis-watchdog` (endpoint)

Supervisor: reinicia el agente ante caída, cuelgue o exceso de memoria.

- **Invoca** (2): `aegis-presupuesto`, `aegis-watchdog`
- **Enlaza sin invocar** (0): —

### `aegis-fleet` (endpoint)

Demostración autocontenida del canal de flota (gRPC sobre mTLS): hoy no se conecta al servidor real.

- **Invoca** (2): `aegis-fleet`, `aegis-pqc`
- **Enlaza sin invocar** (0): —

### `aegis-server` (plano-de-control)

Plano de control: ingesta de la flota, API de administración y consola SOC.

- **Invoca** (9): `aegis-case`, `aegis-consola`, `aegis-firehose`, `aegis-fleet`, `aegis-itdr`, `aegis-orchestrator`, `aegis-parser`, `aegis-pqc`, `aegis-server`
- **Enlaza sin invocar** (6): `aegis-attest`, `aegis-entidad`, `aegis-firmware`, `aegis-predict`, `aegis-selfdefense`, `aegis-share`

## Plataformas

Qué plataformas son producto, generado desde [`tools/config/plataformas.toml`](../tools/config/plataformas.toml). `cargo xtask arquitectura` falla si un documento de una plataforma que no es producto no lo dice en su cabecera, o si un texto del repositorio afirma lo contrario ([detalle](#plataformas)).

| Plataforma | Estado | Qué es hoy | Qué hace falta para que sea producto |
|---|---|---|---|
| Linux | **Producto** | El agente (x86_64 y aarch64) en las distribuciones de la matriz de kernels; producto es solo lo que la tabla de crates marca como tal | — |
| Windows | **No producto** | Un driver que compila (`kernel/windows/`), un instalador MSI y bibliotecas (ELAM, PPL, análisis de PE); nada protege una máquina Windows | Hace falta ser miembro de la Microsoft Virus Initiative (MVI), un driver ELAM y la firma del driver por atestación en el portal de hardware de Microsoft (con certificado EV), y PPL para el servicio; lo decide Microsoft, no este repositorio. |
| macOS | **No producto** | Análisis de binarios Mach-O desde Linux (`aegis-macho`, biblioteca); no existe un agente que corra en macOS | Hace falta que Apple apruebe el entitlement com.apple.developer.endpoint-security.client, una System Extension firmada con Developer ID y la notarización. |

## Matriz de kernels

Cada prueba de extremo a extremo se ejecuta dentro de una microVM con el kernel y el espacio de usuario reales de cada distribución (`cargo xtask kernels`). Configuración: [`tools/config/kernels.toml`](../tools/config/kernels.toml).

| Imagen | Distribución | Arquitectura | Kernel | Nota |
|---|---|---|---|---|
| `debian-11` | Debian 11 (bullseye) | x86_64 | 5.10 | — |
| `rocky-9` | Rocky Linux 9 | x86_64 | 5.14-el9 | Kernel 5.14 con retroportes de RHEL 9: la familia más distinta de la matriz. |
| `ubuntu-22.04` | Ubuntu 22.04 LTS | x86_64 | 5.15 | — |
| `debian-12` | Debian 12 (bookworm) | x86_64 | 6.1 | — |
| `amazon-linux-2023` | Amazon Linux 2023 | x86_64 | 6.1 | — |
| `opensuse-leap-15.6` | openSUSE Leap 15.6 | x86_64 | 6.4 | Sustituto de SLES 15 SP6: mismo kernel y base binaria; la imagen de SLES exige registro en SUSE. |
| `ubuntu-24.04` | Ubuntu 24.04 LTS | x86_64 | 6.8 | — |
| `fedora-44` | Fedora 44 | x86_64 | estable | Sigue al kernel estable más reciente; SELinux en enforcing. |
| `ubuntu-24.04-arm64` | Ubuntu 24.04 LTS | aarch64 | 6.8 | — |
| `debian-12-arm64` | Debian 12 (bookworm) | aarch64 | 6.1 | — |

| Objeto eBPF (pasa el verificador en cada kernel) | Exige kfunc |
|---|---|
| `aegis_probes.bpf.o` | — |
| `aegis_xdp.bpf.o` | — |
| `aegis_kintegrity.bpf.o` | bpf_iter_task_new, bpf_task_from_pid (sin ellas: *no aplica*, no fallo; desde Linux 6.7, obligatorio) |
| `aegis_sslsniff.bpf.o` | — |
| `aegis_ips.bpf.o` | — |

| Prueba e2e | Qué demuestra | Crates que ejerce |
|---|---|---:|
| `agente-en-vivo` | El agente publicado engancha sus sondas, consume actividad real y para limpio sin perder eventos. | 34 |
| `red-en-vivo` | Una conexión TCP real llega del kernel con su dirección, su puerto y la marca de loopback. | 4 |
| `ejecucion-en-vivo` | Una ejecución llega del kernel con su ruta y sus argumentos exactos. | 4 |
| `ficheros-en-vivo` | Cada vía de apertura para escritura (open, creat, openat, openat2) llega del kernel con su ruta. | 4 |
| `prioridad-en-vivo` | Con el ring saturado de aperturas de fichero, ninguna ejecución se pierde: la prioridad baja cede su sitio y la pérdida queda atribuida a su familia. | 4 |
| `trabajador-en-vivo` | El trabajador confinado muere varias veces ejecutando ELF malformados y el agente sigue protegiendo: los eventos siguen llegando y el watchdog no lo reinicia. | 34 |
| `rango-en-vivo` | El rango ejecuta emulaciones ATT&CK reales, benignas y reversibles, contra el agente publicado; se cuenta detectada solo la tecnica con una señal del agente en su ventana. Publica cobertura, tiempo hasta deteccion y motor. | 34 |
| `integridad-en-vivo` | Una puerta trasera en sshd_config (PermitRootLogin yes) con el agente en marcha: el agente dice qué cambió en el fichero y quién lo cambió. | 34 |
| `nucleo-en-vivo` | Con la máquina en reposo el verificador cruzado de tareas no acusa a nadie, y un proceso escondido de /proc con un montaje encima sale como oculto-en-userland; donde el kernel no tiene los kfuncs de tareas, el motor queda degradado con su motivo. | 34 |
| `paquete-en-vivo` | El paquete .deb o .rpm con el gestor nativo: instalar, actualizar, una versión que no late vuelve sola a la anterior y el gestor la marca fallida, reconciliar, y desinstalar solo con autorización y sin residuos (procesos, unidad, drop-in, /run, cgroups, usuario, ficheros, /etc/aegiscore). | 34 |
| `convivencia-en-vivo` | El agente instalado junto a auditd, un segundo consumidor eBPF de los mismos tracepoints y un antivirus ajeno con fanotify que tarda en contestar: nadie ciega a nadie y el camino caliente no espera al analista. | 34 |
| `sobrecoste-en-vivo` | La misma carga (ejecuciones, ficheros, lecturas) sin y con el agente INSTALADO: sobrecoste, CPU del agente y pico de memoria del servicio frente al techo que calcula aegis-presupuesto. Solo se juzga con KVM. | 34 |

## Excepciones de arquitectura

Dependencias que hoy suben de capa ([`tools/config/capas.toml`](../tools/config/capas.toml)). La lista solo puede menguar: una nueva hace fallar `make ci`.

| Desde | Hacia | Causa | Plan |
|---|---|---|---|
| `aegis-postura` | `aegis-ingest` | El modelo de evento normalizado vive en aegis-ingest, que es E/S. | Extraer el modelo de evento a un crate de núcleo y que ingest lo produzca. |
| `aegis-postura` | `aegis-pipeline` | Misma causa: la postura consume el evento ya canalizado del pipeline. | Se resuelve con la misma extracción del modelo de evento. |
| `aegis-detonate` | `aegis-invitado` | El protocolo vsock entre anfitrión e invitado está definido en el binario invitado. | Mover los tipos del protocolo de detonación a un crate de núcleo compartido. |

## Por crate

| Crate | Capa | Estado | Invocado por | Gancho | Prueba e2e | Medidas | Qué le falta |
|---|---|---|---|---|---|---|---|
| `aegis-agent` | E/S | **Producto** | `aegis-agent` | [crates/aegis-agent/src/main.rs:1](../crates/aegis-agent/src/main.rs#L1) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | analista_esperando_a_otro_fanotify (si_no), carga_sin_agente (ms), codigo_del_gestor_ante_version_rota (codigo), convivencia_auditd_ejercida (si_no), convivencia_auditd_registros (de_200), convivencia_ebpf_ejercida (si_no), convivencia_fanotify_ejercida (si_no), convivencia_medidas_repetidas (medidas), convivencia_watchdog_reinicio (si_no), cpu_bajo_carga (ms), denegaciones_lsm_ciclo_de_vida (denegaciones), deriva_de_la_maquina (%), eventos_emitidos (eventos), eventos_perdidos (eventos), p99_triaje (ns), pico_memoria_bajo_carga (KiB), pico_memoria_del_servicio_bajo_carga (KiB), rss_en_vivo (KiB), segundos_de_actualizacion (s), segundos_de_vuelta_atras (s), segundos_hasta_latir_tras_instalar (s), sobrecoste_carga (%) | — |
| `aegis-almacen` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-almacen-pcap` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-attest` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-audit` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-behavior` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/conducta.rs:23](../crates/aegis-agent/src/motores/conducta.rs#L23) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | p99_evaluacion (ns) | — |
| `aegis-captura` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-ctl/src/redaccion.rs:72](../crates/aegis-ctl/src/redaccion.rs#L72) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-case` | núcleo | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/api.rs:2257](../server/crates/aegis-server/src/api.rs#L2257) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-cloudnative` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-confinar` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-conocimiento` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-consola` | E/S | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/autorizacion.rs:51](../server/crates/aegis-server/src/autorizacion.rs#L51) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-contenido` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/contenido.rs:28](../crates/aegis-agent/src/contenido.rs#L28) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-ctl` | E/S | **Biblioteca** | `aegis-agent`, `aegisctl` | [crates/aegis-agent/src/diagnostico.rs:54](../crates/aegis-agent/src/diagnostico.rs#L54) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-custodia` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-deception` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-decompile` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-detonate` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-disasm` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:417](../crates/aegis-trabajador/src/analizadores.rs#L417) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-disectores` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-e2e` | herramienta | **Herramienta** | — | — | — | — | — |
| `aegis-edgeml` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-emu` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:491](../crates/aegis-trabajador/src/analizadores.rs#L491) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-emular` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-enforce` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/aplicacion.rs:38](../crates/aegis-agent/src/aplicacion.rs#L38) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-enrich` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-entidad` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/diagnostico.rs:125](../crates/aegis-agent/src/diagnostico.rs#L125) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-estado` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-evasion` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-firehose` | E/S | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/firehose.rs:46](../server/crates/aegis-server/src/firehose.rs#L46) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-firmware` | plataforma | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-fleet` | E/S | **Biblioteca** | `aegis-agent`, `aegis-fleet`, `aegis-server` | [crates/aegis-agent/src/plano.rs:54](../crates/aegis-agent/src/plano.rs#L54) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-flujo` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-forensics` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-fwaudit` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-harden` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/diagnostico.rs:1031](../crates/aegis-agent/src/diagnostico.rs#L1031) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-hardsense` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-honeytoken` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-hunt` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ingest` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-instrumentar` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-integridad` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/integridad.rs:26](../crates/aegis-agent/src/motores/integridad.rs#L26) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | segundos_hasta_veredicto (s) | — |
| `aegis-intel` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-invitado` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ipc` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/decode.rs:9](../crates/aegis-agent/src/decode.rs#L9) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-ips` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-itdr` | motores | **Biblioteca** | `aegis-server` | [server/crates/aegis-orchestrator/src/lib.rs:45](../server/crates/aegis-orchestrator/src/lib.rs#L45) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-kguard` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/bpf.rs:46](../crates/aegis-agent/src/bpf.rs#L46) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-kintegrity` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/nucleo.rs:62](../crates/aegis-agent/src/motores/nucleo.rs#L62) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | falsos_en_reposo (veredictos) | requiere kernel con los kfuncs de tareas bpf_iter_task_* y bpf_task_from_pid (Linux 6.7+ o backport) (sin ello: sin los kfuncs no hay verificacion cruzada de tareas: un proceso escondido por DKOM o de /proc no se ve) |
| `aegis-l7hunter` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/motores/baliza.rs:30](../crates/aegis-agent/src/motores/baliza.rs#L30) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-macho` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:362](../crates/aegis-trabajador/src/analizadores.rs#L362) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-memhunter` | motores | **Condicional** | `aegis-agent` | [crates/aegis-agent/src/motores/memoria.rs:36](../crates/aegis-agent/src/motores/memoria.rs#L36) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida; requiere CAP_SYS_PTRACE en el agente y Yama ptrace_scope por debajo de 3 (sin ello: sin leer la memoria ajena no hay forense en vivo: codigo sin fichero, carga reflexiva y module stomping quedan sin mirar) |
| `aegis-mesh` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ml` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-ransom/src/engine.rs:286](../crates/aegis-ransom/src/engine.rs#L286) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-motor` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/main.rs:23](../crates/aegis-agent/src/main.rs#L23) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | p99_camino_caliente (ns) | — |
| `aegis-net` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-orchestrator` | motores | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/main.rs:214](../server/crates/aegis-server/src/main.rs#L214) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-parser` | núcleo | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/api.rs:1455](../server/crates/aegis-server/src/api.rs#L1455) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-patron` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-contenido/src/validar.rs:35](../crates/aegis-contenido/src/validar.rs#L35) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-pe` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-macho/src/macho.rs:27](../crates/aegis-macho/src/macho.rs#L27) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-pipeline` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-postura` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-pqc` | núcleo | **Biblioteca** | `aegis-agent`, `aegis-fleet`, `aegis-server` | [crates/aegis-fleet/src/error.rs:61](../crates/aegis-fleet/src/error.rs#L61) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-predict` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-presupuesto` | núcleo | **Biblioteca** | `aegis-agent`, `aegis-watchdog` | [crates/aegis-agent/src/main.rs:739](../crates/aegis-agent/src/main.rs#L739) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-procedencia` | núcleo | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-prueba` | herramienta | **Herramienta** | — | — | `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo` | — | — |
| `aegis-ptguard` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-rango` | motores | **Biblioteca** | — | — | — | cobertura_en_vivo (%), deteccion_${tid} (s), residuos_tras_revertir (tecnicas), tecnicas_detectadas (de_) | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels |
| `aegis-ransom` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/secuestro.rs:20](../crates/aegis-agent/src/motores/secuestro.rs#L20) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | p99_evaluacion (ns) | — |
| `aegis-resp` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-ctl/src/handler.rs:12](../crates/aegis-ctl/src/handler.rs#L12) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-rollback` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ruleforge` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sandbox` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-enforce/src/postura.rs:579](../crates/aegis-enforce/src/postura.rs#L579) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-sbom` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-scal` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/motores/conducta.rs:26](../crates/aegis-agent/src/motores/conducta.rs#L26) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-scale` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-scan` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-ctl/src/handler.rs:13](../crates/aegis-ctl/src/handler.rs#L13) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-selfdefense` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sensor` | plataforma | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-server` | E/S | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/main.rs:1](../server/crates/aegis-server/src/main.rs#L1) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-share` | núcleo | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sigma` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/motores/sigma.rs:47](../crates/aegis-agent/src/motores/sigma.rs#L47) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-swarm` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-swarm-net` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sync` | núcleo | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-syscallguard` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-tejido` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-trabajador` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/estatico.rs:36](../crates/aegis-agent/src/motores/estatico.rs#L36) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | muertes_por_plazo (muertes), muertes_sin_interrupcion (muertes), p99_analisis (ns) | — |
| `aegis-unpacker` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-update` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-contenido/src/almacen.rs:34](../crates/aegis-contenido/src/almacen.rs#L34) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-vmi` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-volcado` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-vuln` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/motores/postura.rs:43](../crates/aegis-agent/src/motores/postura.rs#L43) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | — | sin medida |
| `aegis-watchdog` | E/S | **Producto** | `aegis-agent`, `aegis-watchdog` | [crates/aegis-agent/src/main.rs:421](../crates/aegis-agent/src/main.rs#L421) | `agente-en-vivo`, `trabajador-en-vivo`, `rango-en-vivo`, `integridad-en-vivo`, `nucleo-en-vivo`, `paquete-en-vivo`, `convivencia-en-vivo`, `sobrecoste-en-vivo` | reinicios_del_agente (reinicios) | — |
| `aegis-wire` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `fleet-simulator` | herramienta | **Herramienta** | — | — | — | — | — |
