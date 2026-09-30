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
| Agente (`crates/`) | 6 | 0 | 66 | 1 |
| Plano de control (`server/crates/`) | 0 | 0 | 19 | 1 |
| Enjambre (`swarm-net/`) | 0 | 0 | 1 | 0 |

**Producto** = lo invoca un ejecutable instalable, lo ejerce una prueba de extremo a extremo en la matriz de kernels y tiene una medida. **Condicional** = lo mismo, pero depende de hardware o de un certificado y lo declara. **Biblioteca** = código probado que hoy no protege ninguna máquina. Detalle crate a crate, con lo que le falta a cada uno: [matriz de capacidades](#por-crate).

## Por ejecutable instalable

### `aegis-agent` (endpoint)

El agente EDR: sondas eBPF de kernel, grafo de linaje y triaje.

- **Invoca** (21): `aegis-agent`, `aegis-behavior`, `aegis-ctl`, `aegis-disasm`, `aegis-emu`, `aegis-entidad`, `aegis-harden`, `aegis-ipc`, `aegis-kguard`, `aegis-macho`, `aegis-ml`, `aegis-motor`, `aegis-patron`, `aegis-pe`, `aegis-ransom`, `aegis-resp`, `aegis-sandbox`, `aegis-scal`, `aegis-scan`, `aegis-trabajador`, `aegis-watchdog`
- **Enlaza sin invocar** (2): `aegis-edgeml`, `aegis-presupuesto`

### `aegisctl` (endpoint)

CLI de administración local sobre el socket de control del agente.

- **Invoca** (1): `aegis-ctl`
- **Enlaza sin invocar** (4): `aegis-patron`, `aegis-resp`, `aegis-scal`, `aegis-scan`

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

- **Invoca** (8): `aegis-case`, `aegis-firehose`, `aegis-fleet`, `aegis-itdr`, `aegis-orchestrator`, `aegis-parser`, `aegis-pqc`, `aegis-server`
- **Enlaza sin invocar** (6): `aegis-attest`, `aegis-entidad`, `aegis-firmware`, `aegis-predict`, `aegis-selfdefense`, `aegis-share`

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
| `aegis_kintegrity.bpf.o` | bpf_iter_task_new, bpf_task_from_pid (sin ellas: *no aplica*, no fallo) |
| `aegis_sslsniff.bpf.o` | — |
| `aegis_ips.bpf.o` | — |

| Prueba e2e | Qué demuestra | Crates que ejerce |
|---|---|---:|
| `agente-en-vivo` | El agente publicado engancha sus sondas, consume actividad real y para limpio sin perder eventos. | 21 |
| `red-en-vivo` | Una conexión TCP real llega del kernel con su dirección, su puerto y la marca de loopback. | 3 |
| `ejecucion-en-vivo` | Una ejecución llega del kernel con su ruta y sus argumentos exactos. | 3 |
| `ficheros-en-vivo` | Cada vía de apertura para escritura (open, creat, openat, openat2) llega del kernel con su ruta. | 3 |
| `prioridad-en-vivo` | Con el ring saturado de aperturas de fichero, ninguna ejecución se pierde: la prioridad baja cede su sitio y la pérdida queda atribuida a su familia. | 3 |
| `trabajador-en-vivo` | El trabajador confinado muere varias veces ejecutando ELF malformados y el agente sigue protegiendo: los eventos siguen llegando y el watchdog no lo reinicia. | 22 |

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
| `aegis-agent` | E/S | **Producto** | `aegis-agent` | [crates/aegis-agent/src/main.rs:1](../crates/aegis-agent/src/main.rs#L1) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo` | eventos_emitidos (eventos), eventos_perdidos (eventos), p99_triaje (ns), rss_en_vivo (KiB) | — |
| `aegis-almacen` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-almacen-pcap` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-attest` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-audit` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-behavior` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/conducta.rs:23](../crates/aegis-agent/src/motores/conducta.rs#L23) | `agente-en-vivo`, `trabajador-en-vivo` | p99_evaluacion (ns) | — |
| `aegis-captura` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-case` | núcleo | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/api.rs:1857](../server/crates/aegis-server/src/api.rs#L1857) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-cloudnative` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-confinar` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-conocimiento` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-consola` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ctl` | E/S | **Biblioteca** | `aegis-agent`, `aegisctl` | [crates/aegis-agent/src/main.rs:211](../crates/aegis-agent/src/main.rs#L211) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-custodia` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-deception` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-decompile` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-detonate` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-disasm` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:415](../crates/aegis-trabajador/src/analizadores.rs#L415) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-disectores` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-e2e` | herramienta | **Herramienta** | — | — | — | — | — |
| `aegis-edgeml` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-emu` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:489](../crates/aegis-trabajador/src/analizadores.rs#L489) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-emular` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-enforce` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-enrich` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-entidad` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/main.rs:287](../crates/aegis-agent/src/main.rs#L287) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-estado` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-evasion` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-firehose` | E/S | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/firehose.rs:27](../server/crates/aegis-server/src/firehose.rs#L27) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-firmware` | plataforma | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-fleet` | E/S | **Biblioteca** | `aegis-fleet`, `aegis-server` | [crates/aegis-fleet/src/main.rs:1](../crates/aegis-fleet/src/main.rs#L1) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-flujo` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-forensics` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-fwaudit` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-harden` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/main.rs:240](../crates/aegis-agent/src/main.rs#L240) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-hardsense` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-honeytoken` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-hunt` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ingest` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-instrumentar` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-integridad` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-intel` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-invitado` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ipc` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/decode.rs:9](../crates/aegis-agent/src/decode.rs#L9) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-ips` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-itdr` | motores | **Biblioteca** | `aegis-server` | [server/crates/aegis-orchestrator/src/lib.rs:45](../server/crates/aegis-orchestrator/src/lib.rs#L45) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-kguard` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/bpf.rs:46](../crates/aegis-agent/src/bpf.rs#L46) | `agente-en-vivo`, `red-en-vivo`, `ejecucion-en-vivo`, `ficheros-en-vivo`, `prioridad-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-kintegrity` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-l7hunter` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-macho` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/analizadores.rs:360](../crates/aegis-trabajador/src/analizadores.rs#L360) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-memhunter` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-mesh` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ml` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-ransom/src/engine.rs:286](../crates/aegis-ransom/src/engine.rs#L286) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-motor` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/main.rs:23](../crates/aegis-agent/src/main.rs#L23) | `agente-en-vivo`, `trabajador-en-vivo` | p99_camino_caliente (ns) | — |
| `aegis-net` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-orchestrator` | motores | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/main.rs:156](../server/crates/aegis-server/src/main.rs#L156) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-parser` | núcleo | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/api.rs:1083](../server/crates/aegis-server/src/api.rs#L1083) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-patron` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-scan/src/yara.rs:24](../crates/aegis-scan/src/yara.rs#L24) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-pe` | núcleo | **Biblioteca** | `aegis-agent` | [crates/aegis-macho/src/macho.rs:27](../crates/aegis-macho/src/macho.rs#L27) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-pipeline` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-postura` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-pqc` | núcleo | **Biblioteca** | `aegis-fleet`, `aegis-server` | [crates/aegis-fleet/src/error.rs:61](../crates/aegis-fleet/src/error.rs#L61) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-predict` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-presupuesto` | núcleo | **Biblioteca** | `aegis-watchdog` | [crates/aegis-watchdog/src/bin/aegis-watchdog.rs:79](../crates/aegis-watchdog/src/bin/aegis-watchdog.rs#L79) | `trabajador-en-vivo` | — | sin medida |
| `aegis-procedencia` | núcleo | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ptguard` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-rango` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ransom` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/secuestro.rs:20](../crates/aegis-agent/src/motores/secuestro.rs#L20) | `agente-en-vivo`, `trabajador-en-vivo` | p99_evaluacion (ns) | — |
| `aegis-resp` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-ctl/src/handler.rs:12](../crates/aegis-ctl/src/handler.rs#L12) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-rollback` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-ruleforge` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sandbox` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-trabajador/src/confinamiento.rs:158](../crates/aegis-trabajador/src/confinamiento.rs#L158) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-sbom` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-scal` | plataforma | **Biblioteca** | `aegis-agent` | [crates/aegis-agent/src/motores/conducta.rs:26](../crates/aegis-agent/src/motores/conducta.rs#L26) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-scale` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-scan` | motores | **Biblioteca** | `aegis-agent` | [crates/aegis-ctl/src/handler.rs:13](../crates/aegis-ctl/src/handler.rs#L13) | `agente-en-vivo`, `trabajador-en-vivo` | — | sin medida |
| `aegis-selfdefense` | motores | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sensor` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-server` | E/S | **Biblioteca** | `aegis-server` | [server/crates/aegis-server/src/main.rs:1](../server/crates/aegis-server/src/main.rs#L1) | — | — | sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-share` | núcleo | **Biblioteca** | — | — | — | — | enlazado, pero ningún símbolo sobrevive en el binario; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-swarm` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-swarm-net` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-sync` | núcleo | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-syscallguard` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-tejido` | E/S | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-trabajador` | motores | **Producto** | `aegis-agent` | [crates/aegis-agent/src/motores/estatico.rs:35](../crates/aegis-agent/src/motores/estatico.rs#L35) | `agente-en-vivo`, `trabajador-en-vivo` | muertes_sin_interrupcion (muertes), p99_analisis (ns) | — |
| `aegis-unpacker` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-update` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-vmi` | plataforma | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-volcado` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-vuln` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `aegis-watchdog` | E/S | **Producto** | `aegis-agent`, `aegis-watchdog` | [crates/aegis-agent/src/main.rs:308](../crates/aegis-agent/src/main.rs#L308) | `agente-en-vivo`, `trabajador-en-vivo` | reinicios_del_agente (reinicios) | — |
| `aegis-wire` | motores | **Biblioteca** | — | — | — | — | ningún instalable lo enlaza; sin prueba e2e en la matriz de kernels; sin medida |
| `fleet-simulator` | herramienta | **Herramienta** | — | — | — | — | — |
