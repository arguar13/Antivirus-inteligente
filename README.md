# AegisCore

EDR (Endpoint Detection and Response) de nueva generación para Windows y Linux.
Motor de defensa en Ring 0 + Ring 3, sin bloatware: solo detección, aislamiento
y respuesta.

> **Estado: la línea Linux está implementada y verificada contra un kernel
> real.** Telemetría eBPF, correlación, escáner de postura y CVE, IDS de red con
> XDP, y motor de respuesta (terminación, cuarentena cifrada, aislamiento). La
> línea Windows sigue siendo blueprint. Ver
> [Hoja de ruta](docs/06-stack-y-roadmap.md) y [Estado del CI](docs/07-estado-ci.md).

| Componente | Estado | Verificación |
|---|---|---|
| Contrato ABI Ring 0 ↔ Ring 3 | Implementado | 126 entradas de layout contrastadas entre C y Rust, con gcc y clang |
| Sondas eBPF (proceso, fichero, ptrace, red) | Implementado | 5 programas cargados y aceptados por el verificador de kernel 6.18 |
| Agente: grafo de linaje y triaje | Implementado | 25 pruebas; 4 escalados de 170 eventos reales |
| Escáner de postura y CVE | Implementado | 45 pruebas; 690 paquetes inventariados en el host real |
| IDS de red con XDP | Implementado | 29 pruebas vía `BPF_PROG_TEST_RUN` contra el kernel |
| Respuesta: kill, cuarentena, aislamiento | Implementado | 22 pruebas con procesos y ficheros reales |
| Motor YARA-X sobre fichero y memoria | Implementado | 22 pruebas; firma inyectada en la memoria de un proceso hijo y detectada |
| Atributos estáticos PE/ELF + inferencia ONNX | Implementado | 22 pruebas; binarios ELF y PE construidos byte a byte en tiempo de ejecución |
| Integración de extremo a extremo | Implementado | Malware simulado detectado, terminado y revertido |
| Driver de Windows, ELAM, PPL | Blueprint | Bloqueado por certificación (ver módulo 6) |

---

## Por qué otro antivirus

Las suites comerciales fallan en dos ejes a la vez. Por un lado se han convertido
en plataformas de venta cruzada: VPN, limpiador de registro, gestor de
contraseñas, pop-ups de renovación. Por otro, su detección sigue anclada en
firmas de fichero, justo cuando el malware moderno ha dejado de tocar el disco:
ejecución en memoria, *living off the land*, syscalls directos para saltarse los
hooks de userland, y ransomware que cifra 10.000 ficheros antes de que un escaneo
programado se entere.

AegisCore ataca el problema desde donde el atacante no puede mentir: el kernel.
Un proceso puede desengancharse (*unhook*) de `ntdll.dll`, puede falsificar su
proceso padre y puede ejecutar shellcode que nunca existe como fichero. Lo que no
puede hacer, sin haber comprometido antes el propio kernel, es ocultarle al
kernel que está reservando memoria ejecutable en otro proceso.

## Principios de diseño

| Principio | Compromiso concreto | Cómo se verifica |
|---|---|---|
| **Eficiencia permanente** | Presupuesto por clase de host, impuesto por el kernel | Reparto por componente (abajo); dos puertas en CI; `MemoryMax` de cgroup v2 |
| **Cero bloatware** | Solo defensa, detección, aislamiento y respuesta | Cualquier funcionalidad que no reduzca el riesgo de compromiso se rechaza en revisión |
| **Autodefensa** | Inmune a terminación no autorizada | PPL + ELAM + `ObRegisterCallbacks` (Windows), LSM + eBPF (Linux) |
| **Resiliencia ante evasión** | Detección de syscalls directos e indirectos | Telemetría desde ETW-Ti / eBPF, no desde hooks de userland |

### Presupuesto de recursos

Durante mucho tiempo el presupuesto fue **«45 MB»**. Esa cifra tenía tres
problemas y solo uno era el tamaño:

1. **Un número para tres regímenes.** Un agente que gasta lo mismo vigilando que
   escaneando el disco entero no es eficiente: es un agente que no está
   escaneando.
2. **Un número para todos los hosts.** Una pasarela industrial de 1 GiB y un host
   de base de datos de 768 GiB no pueden compartir presupuesto. Al segundo le
   sale más barato tener el corpus residente que ir al disco en cada escaneo, y
   negárselo no es prudencia: es hacerle competir contra su propia carga.
3. **Era una promesa de un comentario.** Se medían cuatro segundos al arrancar en
   CI y nada más. Una fuga lenta hasta 2 GiB a las tres de la mañana pasaba
   entera, y el watchdog —que vigilaba latido, **no memoria**— la daba por buena
   hasta que se llevaba el host por delante.

Lo que hay ahora es una **fracción de la RAM del host, con suelo y con techo**
(`crates/aegis-presupuesto`). La fracción hace que escale, el suelo mantiene
capaz al host pequeño, y el techo impide que en un host enorme el agente crezca
solo porque puede.

| Clase de host | RAM | Reposo | Pico | Techo duro | % del host |
|---|---:|---:|---:|---:|---:|
| Pasarela IoT | 1 GiB | 48 MiB | 96 MiB | 160 MiB | 15,6 % |
| Portátil | 8 GiB | 48 MiB | 163 MiB | 245 MiB | 2,99 % |
| Estación | 16 GiB | 81 MiB | 327 MiB | 491 MiB | 2,99 % |
| Servidor | 64 GiB | 327 MiB | 1,0 GiB | 1,5 GiB | 2,34 % |
| Host de BBDD | 768 GiB | 384 MiB | 1,0 GiB | 1,5 GiB | 0,19 % |

En una pasarela pequeña el agente es un **15 % del host**, y eso se declara aquí
en vez de disimularlo: quien decide si lo despliega tiene que saberlo.

**Dónde queda frente al sector.** En lo que de verdad se despliega en flotas,
`wdavdaemon` de Microsoft Defender for Endpoint ronda los 300-600 MB, el sensor
de CrowdStrike Falcon 100-250 MB, SentinelOne 200-400 MB y Elastic Defend unos
500 MB. El **reposo** de AegisCore queda por debajo de todos ellos; el **techo**,
en su mismo orden de magnitud, que es donde tiene que estar un EDR que haga el
trabajo completo en vez de uno que solo manda telemetría.

**El reparto por componente**, sobre una estación de 16 GiB. Se distingue lo
fijo de lo elástico porque son cosas distintas: el modelo ONNX pesa lo que pesa
en cualquier máquina, mientras que las caches y las firmas residentes sí deben
escalar con el host —y son justo lo que hay que soltar bajo presión.

| Componente | Cuota en reposo | Naturaleza | Notas |
|---|---:|---|---|
| Núcleo (colector + correlación) | 24 MiB | fijo | Grafo de procesos acotado por LRU |
| Modelo ML (ONNX, int8) | 6 MiB | fijo | Solo se ejecuta ante ficheros desconocidos |
| Reglas YARA compiladas | 15 MiB | elástico | Compartidas entre hilos vía `Arc`, no por hilo |
| Red (reensamblado + flujos) | 12 MiB | elástico | Techo **global**, no cota por flujo |
| Corpus (índice de firmas) | 15 MiB | elástico | Lo que no cabe vive en disco y se pagina |
| Margen sin asignar | 7 MiB | elástico | Absorbe la fragmentación del asignador |
| `aegis-ui` (cerrada) | 0 MiB | — | La UI **no** es un proceso residente |

En un host de base de datos esas mismas cuotas elásticas son 106, 88 y 106 MiB:
el servidor mantiene **siete veces más corpus residente** que la estación, que es
exactamente lo que se quiere — cada firma que no está en RAM es una lectura de
disco que compite con la carga real de la máquina.

**Tres capas lo obligan**, y la tercera existe porque las dos primeras las
ejecuta un proceso que puede estar comprometido o sencillamente tener un bug:

| Capa | Quién la aplica | Qué hace |
|---|---|---|
| Reparto | Cada componente, vía `Presupuesto::cuota` | Pide lo que le toca en vez de llevar una constante inventada |
| Contención | El agente sobre sí mismo | Suelta lo elástico y rechaza trabajo pesado **antes** de llegar al techo |
| Obligación | El **kernel**, vía `MemoryHigh`/`MemoryMax` de cgroup v2 | OOM dentro del cgroup y reinicio, sin tocar al host |

Y el watchdog ya no vigila solo el latido: muestrea la memoria del agente y lo
reinicia si se pasa del techo de forma sostenida (el patrón de `osquery`, cuyo
watchdog **mata y reinicia** al obrero que se pasa de `--watchdog_memory_limit`).
Dos detalles lo hacen desplegable: una sola muestra sobre el techo **no**
reinicia —reiniciar el EDR abre una ventana sin protección, y quien sepa provocar
picos de memoria tendría ahí un interruptor para apagar la vigilancia—, y el
contador **no sobrevive al reinicio**, porque si lo hiciera el proceso nuevo
nacería condenado y una fuga acotada se convertiría en una máquina sin EDR.

**Dos puertas en CI**, y las dos hacen falta. El **presupuesto** del host escala,
así que como única comprobación sería inútil en un servidor grande: un componente
podría decuplicar su huella y seguir pasando. La **línea base de arranque**
(32 MiB) no escala con nada, y es la que caza la regresión. Medida real del
agente de release con el blindaje activo: **~22 MiB**.

La UI cerrada consume cero porque no es un proceso residente: se lanza bajo
demanda y habla con el agente por un canal local con ACL. Es la primera víctima
del principio de cero bloatware.

---

## Diagrama C4 — Nivel 2 (Contenedores)

```
                                    ┌────────────────────────────────────┐
                                    │  Analista / Usuario del endpoint   │
                                    └──────────────────┬─────────────────┘
                                                       │ [1] consulta estado,
                                                       │     revisa cuarentena
═══════════════════════════════════════════════════════╪══════════════════════════
  ENDPOINT  (Windows 10+ / Linux 5.8+)                 │
                                                       ▼
  RING 3 ─────────────────────────────────────────────────────────────────────────
                              ┌─────────────────────────────┐
                              │  aegis-ui                   │
                              │  Tauri v2 (Rust + WebView)  │
                              │  NO residente: se lanza      │
                              │  bajo demanda               │
                              └──────────────┬──────────────┘
                                             │ [2] named pipe con ACL /
                                             │     unix socket 0600, JSON-RPC
                                             ▼
   ┌────────────────────────┐   [3] veredicto  ┌──────────────────────────────────┐
   │  aegis-scan            │◄────────────────►│  aegis-agent                     │
   │  Rust                  │   in-process     │  Rust · servicio PPL-Antimalware │
   │  · YARA-X multihilo    │   (canal mpsc)   │  · consume el ring buffer        │
   │  · ONNX Runtime int8   │                  │  · grafo de linaje de procesos   │
   │  · analizador PE/ELF   │                  │  · motor de reglas conductuales  │
   │  · escáner de memoria  │                  │  · árbitro de veredictos         │
   └────────────────────────┘                  └───┬───────────────┬──────────────┘
   ┌────────────────────────┐                      │               │
   │  aegis-resp            │◄─────────────────────┘ [4] acción    │ [6] async,
   │  Rust                  │                                      │  fuera de la
   │  · aislamiento WFP     │                                      │  ruta caliente
   │  · cuarentena AES-GCM  │                                      │
   │  · rollback CoW        │                                      │
   └────────────────────────┘                                      │
                    ▲                                              │
                    │ [5] ring buffer en memoria compartida        │
  ══════════════════╪═══ frontera de privilegio ═══════════════════╪═════════════
  RING 0            │                                              │
       ┌────────────┴──────────────────────────────┐               │
       │  aegis-drv (Windows)  ·  aegis-bpf (Linux)│               │
       │  C · WDK / libbpf CO-RE                   │               │
       │  · minifilter de ficheros  · LSM hooks    │               │
       │  · callbacks proc/hilo/imagen/registro    │               │
       │  · ObRegisterCallbacks (autodefensa)      │               │
       │  · consumidor ETW-Ti (syscalls anómalos)  │               │
       │  · driver ELAM (arranque)                 │               │
       └───────────────────────────────────────────┘               │
                                                                   │
═══════════════════════════════════════════════════════════════════╪══════════════
  NUBE                                                             ▼
                    ┌──────────────────────────┐   ┌────────────────────────────┐
                    │  aegis-cloud-api         │──►│  aegis-sandbox             │
                    │  Go                      │   │  Go + Firecracker/gVisor   │
                    │  · reputación k-anónima  │   │  · microVM efímera         │
                    │  · ingesta de muestras   │   │  · sin egreso real de red  │
                    └──────────────────────────┘   └────────────────────────────┘
```

### Relaciones

| # | Origen → Destino | Protocolo / tecnología | Propósito |
|---|---|---|---|
| 1 | Usuario → `aegis-ui` | GUI local | Ver estado, revisar y restaurar cuarentena |
| 2 | `aegis-ui` → `aegis-agent` | Named pipe con ACL (Win) / unix socket 0600 (Linux), JSON-RPC | Consultar estado y solicitar acciones. La UI **nunca** decide: propone |
| 3 | `aegis-agent` ↔ `aegis-scan` | Canal `mpsc` en proceso | Solicitar veredicto sobre fichero, memoria o comportamiento |
| 4 | `aegis-agent` → `aegis-resp` | Llamada directa en proceso | Ejecutar bloqueo, aislamiento, cuarentena o rollback |
| 5 | `aegis-drv` ↔ `aegis-agent` | Memoria compartida (ring SPSC) + canal de veredicto síncrono | Telemetría a alta frecuencia hacia arriba; veredictos acotados en tiempo hacia abajo |
| 6 | `aegis-agent` → `aegis-cloud-api` | HTTPS 1.3 + ECH, asíncrono | Reputación por prefijo de hash (k-anonimato) y envío opcional de muestras |

**Lo que el diagrama afirma, y es la decisión de arquitectura central:** la nube
está fuera de la ruta de decisión. El veredicto local es autoritativo y bloquea;
la nube solo refina *a posteriori*. Un endpoint sin red se defiende igual de bien.
Cualquier diseño que exija una consulta remota para decidir si se permite una
ejecución introduce latencia de red en cada `CreateProcess` y deja al usuario sin
protección en cuanto se cae el enlace.

---

## Estructura del repositorio

```
shared/include/aegis_abi.h    Contrato ABI Ring 0 <-> Ring 3 (fuente de verdad)
crates/
  aegis-ipc/                  Espejo Rust del ABI + consumidor del ring   [hecho]
  aegis-agent/                Colector eBPF, grafo de linaje, triaje      [hecho]
  aegis-vuln/                 Escáner de postura y CVE del host           [hecho]
  aegis-net/                  IDS de red, filtro XDP, detección de barridos [hecho]
  aegis-resp/                 Terminación, cuarentena AES-256-GCM, aislamiento [hecho]
  aegis-scan/                 YARA-X sobre ficheros y memoria de procesos    [hecho]
  aegis-ml/                   Atributos estáticos PE/ELF + inferencia ONNX   [hecho]
  aegis-ransom/               Velocidad, transición de entropía, señuelos    [hecho]
  aegis-evasion/              Vaciado de proceso, inyección, hooks           [hecho]
  aegis-intel/                Reputación k-anónima + caché LRU               [hecho]
  aegis-e2e/                  Integración de extremo a extremo + estrés      [hecho]
  aegis-harden/               Cifrado de cadenas + anti-depuración           [hecho]
  aegis-kguard/               Integridad HMAC del eBPF + permisos de mapas   [hecho]
  aegis-audit/                Registro de auditoría cifrado + rotación       [hecho]
  aegis-ctl/                  Canal de control por socket Unix + aegisctl    [hecho]
  aegis-update/               Actualización firmada Ed25519 + rollback       [hecho]
  aegis-forensics/            Volcado de memoria en vivo + exploits          [hecho]
  aegis-sync/                 Sincronización diferencial (Merkle) de IoCs    [hecho]
  aegis-fim/                  Integridad de ficheros (inotify + BLAKE3)      [hecho]
  aegis-watchdog/             Watchdog de alta disponibilidad                [hecho]
  aegis-presupuesto/          Presupuesto de memoria por clase de host       [hecho]
  aegis-ui/                   Tauri v2, no residente
drivers/
  windows/aegis-drv/          Minifilter + callbacks + ELAM (C, WDK)
  linux/aegis-bpf/            Sondas eBPF CO-RE + filtro XDP (C, libbpf)  [hecho]
cloud/
  api/                        Reputación k-anónima (Go)
  sandbox/                    Detonación en microVM (Go)
tools/
  abi-check.sh                Verificación cruzada del layout C <-> Rust
docs/                         Blueprint arquitectónico
```

## Documentación

| Módulo | Documento |
|---|---|
| 1 | [Motor de kernel (Ring 0)](docs/01-kernel-ring0.md) — minifilter, callbacks, autodefensa, ELAM |
| 2 | [Agente y telemetría (Ring 3)](docs/02-agente-ring3.md) — IPC, malware sin fichero, linaje de procesos |
| 3 | [Motor de detección](docs/03-motor-deteccion.md) — YARA-X, ML local, reglas conductuales |
| 4 | [Respuesta y aislamiento](docs/04-respuesta.md) — WFP, cuarentena, rollback |
| 5 | [Nube y threat intelligence](docs/05-cloud.md) — k-anonimato, sandbox |
| 6 | [Stack y hoja de ruta](docs/06-stack-y-roadmap.md) — lenguajes, fases, criterios de salida |
| 8 | [Blindaje del agente](docs/08-blindaje.md) — cifrado de cadenas, anti-depuración, stripping |
| 9 | [Auditoría local cifrada](docs/09-auditoria.md) — SQLite embebida, AES-256-GCM, rotación |
| 10 | [Canal de control](docs/10-control.md) — socket Unix 0600, aegisctl, status/scan/isolate/quarantine |
| 11 | [Red Team defensiva](docs/11-red-team.md) — ataques reales contra las defensas en cada `make ci` |
| 12 | [Actualización segura](docs/12-actualizacion.md) — firmas Ed25519, rollback atómico |
| 13 | [Análisis forense en vivo](docs/13-forense.md) — volcado sin parar el proceso, vtable/pivote/shellcode |
| 14 | [Sincronización diferencial](docs/14-sync.md) — árboles de Merkle, tráfico proporcional al cambio |
| 15 | [Integridad de ficheros](docs/15-fim.md) — inotify, BLAKE3 concurrente, línea base |
| 16 | [Watchdog de alta disponibilidad](docs/16-watchdog.md) — reinicio ante SIGKILL/cuelgue, **tercer fallo**: el agente que late y se come la máquina |
| 17 | [Auditoría final de release](docs/17-auditoria-final.md) — estrés + red team en paralelo, cero advertencias |
| 18 | [SCAL: abstracción multiplataforma](docs/18-scal.md) — cuatro rasgos, backend de Linux, esqueletos de Windows y macOS |
| 19 | [Motor conductual](docs/19-conductual.md) — grafo DAG, técnicas MITRE ATT&CK, cadenas de ataque, aislamiento a partir de 85/100 |
| 20 | [Sandbox de confianza cero](docs/20-sandbox.md) — Landlock y seccomp-bpf, 35 llamadas bloqueadas, 7 fugas probadas |
| 21 | [Decepción de red](docs/21-decepcion.md) — señuelos SSH/SMB/RDP, movimiento lateral, bloqueo con barandilla |
| 22 | [Incidentes y STIX 2.1](docs/22-incidentes.md) — recogida automática de artefactos, exportación estándar, custodia cifrada |
| 23 | [Malla P2P](docs/23-malla.md) — propagación de vacunas por la red local, UDP con AEAD, sólo añade |
| 24 | [Ingeniería del caos](docs/24-caos.md) — corrupción de IPC, caídas de red, saturación de RAM, cuelgues |
| 25 | [Anti-rootkit](docs/25-antirootkit.md) — verificación cruzada del kernel, detección DKOM y de procesos ocultos |
| 26 | [Integridad de firmware](docs/26-firmware.md) — TPM 2.0, arranque medido, Secure Boot y revocación UEFI (DBX) |
| 27 | [Desempaquetado dinámico](docs/27-unpacker.md) — ejecución controlada, detección de OEP, volcado del código real |
| 28 | [Syscalls directas](docs/28-syscallguard.md) — verificación cruzada del origen de cada syscall, breakpoints por hardware (PMU/DRx) |
| 29 | [Gestión de flota](docs/29-fleet.md) — plano de control gRPC/mTLS mutuo, certificados de rotación automática, claves solo en memoria |
| 30 | [Pipeline DevSecOps](docs/30-devsecops.md) — fuzzing continuo (libFuzzer), sanitización de memoria (ASan), auditoría de dependencias (RustSec) |
| 31 | [CI/CD blindado](docs/31-cicd.md) — pipeline de GitHub Actions reconstruido y runner local de respaldo con detección de deriva |
| 32 | [Aegis Control Plane](docs/32-plano-control.md) — backend de flota: mTLS nativo + gRPC (tonic) + REST (axum), PostgreSQL y Redis |
| 33 | [Inteligencia y reglas](docs/33-inteligencia-y-reglas.md) — ingesta STIX 2.1, linaje de procesos y empuje de política global por LISTEN/NOTIFY |
| 34 | [Consola de administración](docs/34-consola.md) — panel en tiempo real por WebSocket: topología, alertas MITRE, árbol de procesos y respuesta de un clic |
| 35 | [Despliegue corporativo](docs/35-despliegue.md) — Terraform en nube, Ansible por tandas en la flota Linux, MSI silencioso y GPO en Windows |
| 36 | [Prueba de carga](docs/36-carga.md) — 10.000 agentes simultáneos: p99 de 6,91 ms, dos defectos de rendimiento y una condición de carrera en la publicación de política, corregidos en el producto |
| 37 | [Construcción hermética](docs/37-hermetico.md) — sysroot musl completo, artefactos sin dependencias del anfitrión y BPF CO-RE probado contra kernels reales |
| 38 | [Caza distribuida](docs/38-caza.md) — AegisQL: lenguaje de consulta de solo lectura y coste acotado, difundido a toda la flota y agregado en tiempo real |
| 39 | [Cuarentena de enjambre](docs/39-cuarentena.md) — micro-segmentación Zero-Trust: XDP en entrada y nftables en salida, difundida a 10.000 endpoints en menos de 200 ms |
| 40 | [Heurísticas globales](docs/40-heuristicas.md) — detección de APT distribuida: lo que no delata a ningún endpoint por separado, correlacionado en ventanas deslizantes sobre toda la flota |
| 41 | [Firehose SIEM/SOAR](docs/41-firehose.md) — entrega de auditoría sin pérdida: diario en disco, Syslog RFC 5424 sobre TLS y Kafka con acuse replicado |
| 42 | [Paridad en Windows](docs/42-windows.md) — auto-defensa por ObRegisterCallbacks y clasificación de inyección desde ETW Threat Intelligence, con la decisión probada en cada build |
| 43 | [Infra de CI real](docs/43-infra-ci-real.md) — cierre de los dos huecos de verificación: un corredor Apache Kafka real (KRaft, sin Docker) y la compilación cruzada del driver de Windows desde Linux |
| 44 | [Atestación TPM 2.0](docs/44-atestacion-tpm.md) — raíz de confianza en hardware: el plano de control verifica un *quote* firmado por el TPM antes de creerse la telemetría, y ante un fallo dispara la Cuarentena de FASE 44 |
| 45 | [Rollback de ransomware](docs/45-rollback-ransomware.md) — copia-sombra cifrada del contenido original antes de cada escritura sospechosa, y restauración byte a byte cuando el veredicto se confirma |
| 46 | [Intel PT contra ROP/JOP](docs/46-intel-pt.md) — trazado de ejecución por hardware: decodifica la traza Intel PT, reconstruye el flujo con desensamblado real y detecta cadenas de gadgets |
| 47 | [Decepción activa](docs/47-decepcion.md) — honey-tokens dinámicos con marcador HMAC atribuible: credenciales señuelo creíbles que, al ser tocadas, delatan e identifican al intruso |
| 48 | [TinyML en el borde](docs/48-tinyml-borde.md) — clasificador de comportamiento embebido en el agente: detecta zero-day por la forma de las syscalls y aísla sin conexión a la nube |
| 49 | [Criptografía post-cuántica](docs/49-pqc.md) — migración híbrida a NIST ML-KEM-768 y ML-DSA-65: capa HPKE sobre el mTLS del C2 y firma Ed25519+ML-DSA en las actualizaciones, contra *Harvest Now, Decrypt Later*, anclada en los KAT oficiales de ACVP |
| 50 | [Autodefensa legítima](docs/50-autodefensa.md) — ELAM, PPL y Tamper Protection con un OTP firmado por el Control Plane: el agente resiste al atacante pero **siempre** obedece la desinstalación autorizada del dueño; la línea que separa un EDR de un rootkit |
| 51 | [Detección de amenazas de identidad (ITDR)](docs/51-itdr.md) — Kerberoasting, Golden/Silver Ticket y escaladas de privilegio sobre el grafo de identidad de la flota (centralidad de Brandes); tickets Kerberos parseados byte a byte y correlación probada de extremo a extremo, con la captura en vivo del Controlador de Dominio declarada gated |
| 52 | [Micro-sandbox de emulación](docs/52-microsandbox.md) — emulador x86-64 propio en Rust puro: despliega binarios desconocidos y empaquetados sin que ninguna instrucción toque el host, detecta el desempaquetado y clasifica el comportamiento por las syscalls interceptadas; sin muro, todo probado contra código máquina real |
| 53 | [Forense de memoria a escala](docs/53-ram-hunting.md) — `AegisMemScanner`: YARA sobre la RAM de la flota, particionado y estrangulado para no congelar el endpoint, con solapamiento entre chunks que no pierde una firma partida; expuesto por AegisQL como `SELECT pid FROM memory WHERE yara_match = '...'`, con la lectura de memoria física declarada gated |
| 54 | [Introspección de Ring -1 (VMI + EPT)](docs/54-ring-1-vmi.md) — hipervisor **defensivo**: marca el código del kernel con EPT para atrapar ejecución oculta y parcheo, y lee `task_struct`/`EPROCESS` desde memoria física (sin las APIs del SO) para delatar procesos ocultos por vista cruzada (DKOM); núcleo y ABI probados, arranque del hipervisor declarado gated (VT-x/AMD-V) |
| 55 | [Resiliencia empresarial (ELAM/PPL + tamper crypto)](docs/55-resiliencia.md) — `AegisResilience`: el agente rechaza cualquier señal de parada (`SIGTERM`, control del SCM, desinstalar) que no venga con un OTP firmado por el Control Plane (Ed25519+ML-DSA-65), y **siempre** obedece la autorización del dueño; contratos de ABI de ELAM (`BDCB_*`) y PPL (`PS_PROTECTION`) con tamaños y códigos reales del WDK verificados en compilación, y la honestidad de declarar que `SIGKILL` sólo lo impone el kernel (PPL) |
| 56 | [AegisHPC: la PMU como sensor](docs/56-hardsense.md) — telemetría de la PMU por `perf_event_open`: aprende la línea base de cada proceso (EWMA de media y varianza) y delata un pico de fallos de caché como canal lateral (Flush+Reload/Spectre) o un pico de fallos de predicción de saltos como cadena ROP/JOP, sin falsos positivos con tráfico normal y sin dejarse envenenar la base; núcleo probado con datos reales, lectura de la PMU en vivo declarada gated (microVM sin PMU) |
| 57 | [AegisCloudNative: escape de contenedor](docs/57-cloudnative.md) — reconoce el salto del contenedor al host (Deepce/Traitor): escritura de `release_agent`/`core_pattern`/`modprobe`, montaje del disco del host, `setns` al namespace del host, `bpf` desde el contenedor y la secuencia `unshare(CLONE_NEWUSER)`+`mount`, sin marcar las mismas syscalls en el host; decisor en Rust puro probado con secuencias reales, enganche eBPF en vivo declarado gated (kernel/BTF/privilegios) |
| 58 | [Mitigación de DOP (taint tracking)](docs/58-dop.md) — extiende el micro-sandbox con seguimiento de contaminación: marca los datos que entran por `read` y, si se escriben en masa sobre una estructura del sistema protegida sin pasar por una API, delata la programación orientada a datos (que evade CFI/W^X sin desviar el flujo); validado con un exploit DOP real y con el caso negativo (la misma copia con datos limpios no dispara), sin muro (todo emulado) |
| 59 | [Orquestador de remediación (AI-RO)](docs/59-orchestrator.md) — `AegisOrchestrator`: ante un Golden Ticket lanza en paralelo el playbook de respuesta (aislar red por XDP, matar procesos, revocar tickets Kerberos, volcado forense), como una máquina de estados transaccional resiliente a fallos parciales e idempotente en el reintento; **conectado en vivo** al motor ITDR, de modo que un veredicto de identidad dispara el playbook sobre el endpoint sin intervención humana, con un cerrojo distribuido en PostgreSQL que impide que dos instancias del plano de control remedien dos veces el mismo incidente y que un ataque de veinte lotes lance veinte playbooks; circuito completo probado contra PostgreSQL real, aplicación de la orden en el endpoint declarada gated |
| 60 | [AegisMemHunter: VAD y tabla de páginas](docs/60-memhunter.md) — caza el código que no deja fichero: **carga reflexiva** (módulo mapeado a mano en memoria anónima, delatado por su cabecera `MZ`/`ELF`) y ***module stomping*** (el código de un módulo legítimo sobrescrito en memoria, con el fichero en disco intacto y su firma válida). Lo detecta en la **tabla de páginas**: una página presente con el bit 61 a 0 dentro de una región de código respaldada por fichero ya no contiene lo que hay en el fichero — sin leer la memoria del proceso ni compararla con disco. Sin muro en Linux: la semántica del bit y las dos técnicas se construyen de verdad contra el kernel en cada `make ci`; sólo los VAD de Windows quedan gated, con su ABI verificada en compilación |
| 61 | [AegisL7Hunter: C2 sobre TLS con uprobes](docs/61-l7hunter.md) — extrae la telemetría L7 **en claro** enganchando `SSL_read`/`SSL_write` con uprobes de eBPF, sin MitM, sin romper el *certificate pinning* y sin ninguna CA de interceptación que robar; cubre OpenSSL, GnuTLS, NSS y el `crypto/tls` de Go enlazado estáticamente, que es lo que usa el malware moderno. Detecta balizas por una **cota demostrada**: con el modelo de jitter uniforme de Cobalt Strike, ninguna baliza supera un CV de 2/√12 ≈ 0,578, duerma lo que duerma. Los 9 programas eBPF pasan el verificador real del kernel y el ABI del evento se coteja C↔Rust con los dos compiladores; el enganche en un proceso vivo queda gated |
| 62 | [AegisFirmwareAudit: ROM SPI y ACPI, sólo lectura](docs/62-fwaudit.md) — mira **por debajo del sistema operativo**, donde un implante (LoJax, MoonBounce, CosmicStrand) sobrevive a formatear el disco y a cambiarlo: parsea las tablas ACPI que el firmware le entrega al kernel —con **WPBT**, que literalmente ordena ejecutar un binario en cada arranque, y sus argumentos de línea de comandos— y recorre la ROM SPI (descriptor de flash de Intel → volúmenes UEFI → ficheros FFS) validando cada módulo contra una línea base por **hash canónico**, que ignora los tres bytes de cabecera que el propio firmware muta. Aquí el riesgo no es dejar de detectar sino **escribir** —una escritura en la ROM deja la placa inservible sin recuperación por software—, así que la inocuidad es estructural y de dos capas: `#![forbid(unsafe_code)]` con un tipo sin operaciones de escritura, y `O_RDONLY`, **ejercido contra el kernel** (`write`, `pwrite` y `ftruncate` → `EBADF`). Las tablas ACPI reales de la máquina se auditan en cada `make ci`; **leer** la ROM queda declarado no aplicable, con su motivo, donde el kernel no expone la flash |
| 63 | [AegisSwarm: el enjambre autónomo](docs/63-swarm.md) — cuando el atacante **corta el habla** (tirar la salida a Internet es lo primero que hace), la flota se reparte entre sí indicadores, reglas YARA y órdenes de contención sin consola. La pregunta que decide el diseño: si un agente pudiera decir «aísla al equipo X», quien comprometa **uno** tendría un botón de denegación de servicio sobre la organización entera, y podría aislar justo las máquinas que lo habrían detectado. La respuesta: **el enjambre transporta autoridad, no la concede** — una orden sólo vale con la firma del plano de control, cuya clave no está en ningún agente; una observación de un par no manda nada, es evidencia que exige **K testigos distintos**; y levantar un aislamiento o desactivar una regla **no viajan ni con la firma perfecta**, porque reproducidas en el corte apagan la defensa con una firma auténtica. El ataque central —reproducir una orden **vieja y auténtica**, que ninguna firma distingue— lo corta la época monótona. libp2p (gossipsub/Noise/Yamux) vive en un workspace **aparte**: sus 340 crates y su runtime async no entran en un agente privilegiado cuyo presupuesto de memoria en una pasarela son 48 MiB en reposo, y `make ci` lo **comprueba** con `cargo tree`. Núcleo *sans-io*: cada ataque se construye entero en una prueba, y el transporte se ejercita con **dos nodos libp2p reales** |
| 64 | [AegisPredict: predecir el ataque y contenerlo antes](docs/64-predict.md) — responde la pregunta de un CISO: *dado cómo está montada mi organización, ¿por dónde van a entrar y hasta dónde llegan?* Une el grafo de identidad (FASE 58) con la topología de red —porque un atacante los **alterna**, y mirarlos por separado deja fuera justo los caminos que usa— y calcula tres cosas exactas: el **camino más probable** con Dijkstra sobre `−log p` (el logaritmo convierte maximizar un producto en minimizar una suma de pesos no negativos, así que es el **óptimo exacto**, y el camino más probable **no** es el más corto); el **radio de explosión** por percolación Monte Carlo, porque la pregunta exacta es #P-completa, con el **margen de error dentro del resultado**; y la **criticidad**, que propaga hacia atrás el valor de las joyas de la corona. Este motor **propone aislar máquinas de producción**, y eso gobierna todo: **nada está entrenado** —los números están a mano, con su razón, para que un analista pueda leerlos y rebatirlos— y todo es **determinista**. Cinco frenos: un activo protegido no se toca jamás, por encima del tope de radio **no actúa, escala a una persona** (a esa escala la contención *es* la interrupción), la evidencia que el atacante acaba de **fabricar** no mueve nada, un camino improbable tampoco, y se corta la identidad antes que aislar la máquina |
| 65 | [AegisWire: disección semántica de protocolos](docs/65-wire.md) — hasta aquí la red se veía como **metadatos**, y el tráfico que importa está diseñado para parecer normal en metadatos: un C2 moderno va por HTTPS al 443 con volumen de navegación, y es indistinguible de un navegador hasta que se mira **dentro**. Esta fase convierte bytes crudos en hechos con significado —consultas DNS con su entropía, huellas **JA3/JA3S/JA4** y certificados, `SMB2 CREATE`, `AS-REQ` con cifrado débil, `bind` LDAP sin cifrar, y **ficheros extraídos con su SHA-256**— decidiendo el protocolo por **contenido y no por puerto**, porque el malware pone su C2 en el 443 *precisamente porque* todo el mundo asume que el 443 es TLS. El ataque central es la **evasión por solape de segmentos** (Ptacek y Newsham, 1998): si el sensor resuelve un solape contradictorio con otra política que el destino, reconstruye un flujo que el endpoint nunca verá y todas sus reglas miran datos que no existieron; aquí la política **se elige** y las dos variantes reconstruyen de verdad cosas distintas. Y su mitad peligrosa —el solape que llega **después** de entregar los bytes, indistinguible de una retransmisión sin memoria de lo entregado— se cierra con una ventana acotada cuyo límite **se declara**. Hallazgo de la fase: una cota por flujo **no es una cota**, porque el atacante elige también el número de flujos — 100.000 × 2 × 1 MiB son 200 GB cuando la cuota de red entera son 12 MiB, así que hay **dos techos globales**, medidos bajo el ataque que los busca. Y cada mensaje se cuenta **una vez**: conservar lo ya interpretado repetiría sus hechos en cada paquete y dejaría sin ver la segunda petición de una conexión reutilizada. Motor *sans-io*: cada ataque se construye entero en una prueba, con paquetes byte a byte, y **15 crates de terceros** en todo el árbol |
| 66 | [AegisIPS: prevención en línea a velocidad de cable](docs/66-ips.md) — el paso de **detectar a cortar**, que no es pequeño: *un falso positivo en un IDS es una alerta que alguien descarta; en un IPS es una interrupción de servicio*. Eso gobierna el diseño entero — las salvaguardas no son un añadido al motor de bloqueo, **son** el diseño. El veredicto de un flujo se **escribe en un mapa eBPF**, así que el primer paquete sospechoso sube, se juzga una vez, y el resto del flujo lo corta el kernel con una búsqueda de mapa (medido: mil paquetes, mil cortes, mil aciertos de caché, sin que userland intervenga). Va por **TC y no XDP** porque *XDP no tiene camino de salida*, y el sentido que más importa cortar en un endpoint es el **saliente**: la baliza al C2, la exfiltración, el movimiento lateral — y convive con el filtro XDP existente sin tocarlo. Cuatro salvaguardas: sólo la confianza **alta** puede cortar (está en el tipo, no en una opción, porque una política que se puede aflojar se afloja); **activos protegidos** que no se cortan jamás, porque tirar el controlador de dominio convierte un incidente en un apagón y es lo que un atacante querría que hiciéramos por él; **modo por defecto Sólo Detección**, con un camino escalonado que pasa por registrar lo que se *habría* cortado; y un **tope con degradación automática** —si el motor bloquea media red, el motor está mal, no la red— que es **pegajosa** y con **ventana deslizante**, porque un contador que se reinicia no ve la ráfaga a caballo del corte. Las dos del medio se comprueban **otra vez en el kernel**: una salvaguarda que depende de que el código de decisión esté bien no protege del caso que importa, y hay una prueba que escribe el corte **a mano** en el mapa y comprueba que el kernel no lo aplica. Los dos programas eBPF pasan el **verificador real**, y el circuito entero —paquete → hecho → decisión → corte— se ejerce contra el kernel de verdad |
| 67 | [AegisRuleForge: la fábrica de contenido](docs/67-ruleforge.md) — un motor de detección sin contenido no detecta nada, y el contenido del mundo —Emerging Threats, el catálogo Sigma, las bases de ClamAV, las colecciones YARA públicas— está escrito en **cuatro formatos por gente que no somos nosotros**. La parte difícil no es leer los formatos: es que **si un feed se compromete, quien escribe lo que entra aquí es el atacante**, y entra en el proceso que compila el contenido de seguridad de la flota entera. De ahí que los analizadores sean **propios** —incluido el de YAML, con progreso estricto— y que lo que no se entiende se rechace **con nombre**, porque de contar los rechazos sale la **cobertura**: un analizador permisivo no puede dar esa cifra y nadie sabe qué se está perdiendo. Dos puertas más, contra dos formas de tumbar al cliente con contenido firmado por nosotros: el **retroceso catastrófico** de una regex, que corre en el endpoint por cada paquete, se rechaza analizando la **estructura** y no cronometrando (el caso malo es una cadena concreta, y encontrarla es el problema que se intenta evitar); y el **canario**, que bloquea la release si alguna firma dispara sobre binarios reales de `/bin` — una firma que casa con `ls` distribuida con el corte activo mata software legítimo en toda la flota a la vez, sin atacante, que es la forma exacta de la caída de CrowdStrike de julio de 2024. Tres cosas bloquean, y la tercera es la que cuesta: dispara, tiene menos de 16 bytes fijos (los comodines no cuentan, y en una alternativa manda la rama más corta), o **no se pudo evaluar** — desconocida no es limpia. El ataque central es el que **ninguna firma detiene**: reponer el corpus de hace seis meses, auténtico y con la firma perfecta; lo corta una **época monótona**, estrictamente mayor. Y una sola firma, no dos: con dos, un atacante se queda el manifiesto de la v5 y el índice de la v4 y **las dos verifican**. Un millón de firmas no caben en la cuota de nadie, así que el **índice vive en disco** con búsqueda binaria por `seek`, y su residencia la fija el presupuesto del host: **medida** con 40.000 firmas consultadas enteras |
| — | [Estado del CI remoto](docs/07-estado-ci.md) — diagnóstico del bloqueo de GitHub Actions |

## Desarrollo

```bash
make ci        # todas las comprobaciones: formato, clippy, tests, ABI, eBPF,
               # docs y presupuesto de memoria
make test      # solo cargo test
make bpf       # compila los programas eBPF
make bpf-verify# los carga y los pasa por el verificador del kernel
make abi       # el layout de C y el de Rust deben coincidir
```

Las partes que tocan el kernel (sondas eBPF, filtro XDP, terminación de
procesos) necesitan `CAP_BPF`, `CAP_PERFMON` y `CAP_NET_ADMIN`, un kernel con
`CONFIG_DEBUG_INFO_BTF=y` y `tracefs` montado. Cuando falta algo, las pruebas
correspondientes **se saltan con un aviso** en lugar de fallar: una prueba que
falla por el entorno enseña al equipo a ignorar el rojo del CI.

> **GitHub Actions esta bloqueado a nivel de repositorio o cuenta en este
> proyecto.** El workflow es correcto y esta verificado, pero no arranca. Ver
> [docs/07-estado-ci.md](docs/07-estado-ci.md) para el diagnostico y los pasos
> exactos que lo resuelven. Mientras tanto `make ci` es la puerta de calidad, y
> corre el mismo conjunto de comprobaciones.

`abi-check.sh` es obligatorio en CI. Las aserciones `const` de Rust fijan los
offsets esperados, pero no pueden ver el header de C: sin la comparación
cruzada, un cambio en `aegis_abi.h` se manifestaría en producción como campos
desplazados, con el agente leyendo un PID donde hay una dirección de memoria.

## Licencia

Apache-2.0.
