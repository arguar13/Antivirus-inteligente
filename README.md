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
| Reglas YARA compiladas | 14 MiB | elástico | Compartidas entre hilos vía `Arc`, no por hilo |
| Red (reensamblado + flujos) | 11 MiB | elástico | Techo **global**, no cota por flujo |
| Corpus (índice de firmas) | 13 MiB | elástico | Lo que no cabe vive en disco y se pagina |
| Ingesta de registros | 6 MiB | elástico | Colas de `AegisIngest`; al llenarse frena y descarta por prioridad **contando** |
| Margen sin asignar | 6 MiB | elástico | Absorbe la fragmentación del asignador |
| `aegis-ui` (cerrada) | 0 MiB | — | La UI **no** es un proceso residente |

En un host de base de datos esas mismas cuotas elásticas son 99, 77, 92, 42 y 42
MiB: el servidor mantiene **siete veces más corpus residente** que la estación,
que es exactamente lo que se quiere — cada firma que no está en RAM es una
lectura de disco que compite con la carga real de la máquina.

La ingesta de registros de terceros tiene cuota **propia y medida** por el mismo
motivo por el que la tiene la red: es el segundo componente cuyo volumen decide
alguien de fuera. Un cliente que encamine el syslog de mil aparatos a un endpoint
tiene que notar contrapresión mucho antes de que el motor de comportamiento
empiece a soltar estado, y con una cuota sin declarar eso no se puede ni ver.

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
crates/                       Workspace del AGENTE: sincrono, sin runtime async, panic=abort
server/crates/                Workspace del PLANO DE CONTROL: tokio, axum, sqlx
swarm-net/                    Transporte libp2p del enjambre, FUERA del agente a proposito
drivers/linux/aegis-bpf/      Sondas eBPF CO-RE + filtro XDP (C, libbpf) — 2.746 lineas
kernel/windows/aegis/         Minifilter + ObCallbacks + politica (C, WDK) — 887 lineas
deploy/terraform/             Aprovisionamiento del plano de control
fuzz/                         Objetivos de libFuzzer sobre los analizadores
tools/                        42 puertas de verificacion + ABI check + CI local
docs/                         Blueprint arquitectonico, una pagina por fase
```

**Lo que NO hay, dicho aqui y no escondido en una nota al pie:** no existe un
directorio `cloud/`. La reputacion k-anonima corre en el cliente
(`crates/aegis-intel`) contra un servicio que no esta en este repositorio, y la
detonacion vive en el plano de control (`server/crates/aegis-detonate`), no en un
servicio en Go aparte. El driver de Windows compila, pero **ELAM necesita un
certificado de Microsoft** que no se tiene, asi que la paridad de Windows esta
declarada como muro en `tools/verificar-windows.sh` y no como capacidad.

Los **dos workspaces están separados a propósito**, y no por gusto: el agente es
síncrono, sin runtime asíncrono, con un presupuesto de memoria acotado por clase
de host y `panic = "abort"`; el servidor es justo lo contrario. Mezclarlos
contaminaría el árbol de dependencias del agente —que en un EDR **es** superficie
de ataque— con cientos de crates que sólo necesita el servidor. Separándolos, la
auditoría de la cadena de suministro del endpoint sigue siendo corta y revisable:
**39 dependencias directas, cada una con su justificación escrita** en
[`tools/lineabase-agente.txt`](tools/lineabase-agente.txt), y `make ci` falla si
alguna no la tiene.

### Componentes, con su estado real

La columna `forbid(unsafe)` no es informativa: es una **invariante comprobada**.
Todo crate del agente o la tiene en «sí» —y entonces lo impone el compilador— o
está en [`tools/lineabase-unsafe.txt`](tools/lineabase-unsafe.txt) con su razón
escrita. No hay tercera opción, y `tools/verificar-invariantes.sh` lo comprueba.

#### Workspace del agente (`crates/`) — corre en cada endpoint, con privilegios

**66 crates · 2993 pruebas**

| Crate | Qué hace | Pruebas | Puerta propia | `forbid(unsafe)` |
|---|---|---:|---|---|
| `aegis-agent` | Agente de deteccion de AegisCore: consumidor de telemetria, grafo de linaje y triaje | 54 | — | — |
| `aegis-attest` | Atestacion remota con raiz de confianza en el TPM 2.0 (FASE 49) | 11 | — | sí |
| `aegis-audit` | Registro local de auditoria cifrado con rotacion automatica | 9 | — | sí |
| `aegis-behavior` | Motor conductual de AegisCore: grafo dirigido de procesos, tecnicas MITRE ATT&CK y puntuacion de riesgo | 22 | — | sí |
| `aegis-captura` | Captura de trafico indexada por entidad con retencion selectiva por veredicto y reproduccion determinista | 88 | `verificar-captura.sh` | sí |
| `aegis-cloudnative` | Deteccion de escape de contenedor (Deepce/Traitor) a partir de setns/unshare/capset/bpf/mount, con el decisor en Rust puro y el enganche eBPF declarado gated | 13 | `verificar-cloudnative.sh` | sí |
| `aegis-confinar` | Confinamiento derivado del comportamiento: aprende lo que un proceso hace de verdad, lo ensaya en modo permisivo, lo impone solo con confirmacion y se retira solo si rompe algo; no puede volverse contra el agente ni contra los activos protegidos | 41 | `verificar-confinar.sh` | sí |
| `aegis-ctl` | Protocolo de control por socket Unix y CLI de administracion aegisctl | 10 | — | sí |
| `aegis-custodia` | Cadena de custodia verificable para la evidencia forense de una flota: sello de procedencia, encadenado por resumen y veredicto que enumera lo que NO prueba | 67 | `verificar-custodia.sh` | sí |
| `aegis-deception` | Servicios senuelo de red y deteccion de reconocimiento sin falsos positivos | 18 | — | — |
| `aegis-disasm` | Desensamblado de x86-64 y A64, grafo de flujo, grafo de llamadas con indirectas resueltas por constantes, y capacidades con la evidencia dentro del tipo | 164 | `verificar-disasm.sh` | sí |
| `aegis-disectores` | Disectores de protocolo del sensor de red: empresariales, industriales y de nube, con cobertura declarada | 195 | `verificar-disectores.sh` | sí |
| `aegis-e2e` | Pruebas de integracion de extremo a extremo de AegisCore | 15 | — | sí |
| `aegis-edgeml` | Inferencia TinyML en el borde: deteccion de zero-day por comportamiento, sin nube (FASE 53) | 6 | — | sí |
| `aegis-emu` | Micro-sandbox de emulacion x86-64 en memoria: desempaqueta binarios desconocidos y observa su comportamiento sin ejecutarlos en el host | 39 | — | sí |
| `aegis-enforce` | Postura de aplicacion: que se impone de verdad en esta maquina y que solo se observa | 9 | `verificar-mac.sh` | sí |
| `aegis-entidad` | Modelo de entidad unico y arbitro de veredictos para todos los subsistemas de deteccion | 61 | `verificar-fabric.sh` | sí |
| `aegis-estado` | El estado del endpoint entero y consultable: 52 tablas tipadas con coste declarado por tabla, empuje de predicados y motivo escrito cuando una tabla no se puede leer | 174 | `verificar-estado.sh` | sí |
| `aegis-evasion` | Deteccion de vaciado de procesos, inyeccion reflectiva y manipulacion de hooks | 22 | — | sí |
| `aegis-fim` | Monitorizacion de integridad de ficheros criticos con inotify y BLAKE3 | 8 | — | sí |
| `aegis-firehose` | Entrega sin perdida de auditoria hacia SIEM y SOAR: WAL en disco, Kafka y Syslog sobre TLS | 32 | — | sí |
| `aegis-firmware` | Escaner de integridad de firmware: TPM 2.0 PCRs, event log TCG, Secure Boot y revocacion UEFI (DBX) | 24 | — | sí |
| `aegis-fleet` | Agente de gestion de flota sobre gRPC/mTLS con certificados de rotacion automatica y claves que nunca tocan el disco | 52 | — | sí |
| `aegis-forensics` | Introspeccion de memoria en vivo y deteccion de exploits de corrupcion | 31 | — | — |
| `aegis-fwaudit` | Auditoria de plataforma estrictamente de solo lectura: ACPI (WPBT), ROM SPI, protecciones de la flash, SMM, chipset y MSR, IOMMU, mitigaciones, microcodigo frente al del fabricante, variables UEFI, AML y cadena de arranque explicada; compromiso y exposicion separados, y la escritura imposible de expresar | 161 | `verificar-fwaudit.sh`, `verificar-plataforma.sh` | sí |
| `aegis-harden` | Blindaje del agente: cifrado de cadenas y anti-depuracion | 12 | — | — |
| `aegis-hardsense` | Telemetria de la PMU (perf_event_open) para detectar ataques de canal lateral y anomalias ROP/JOP por picos de fallos de cache y de prediccion de saltos | 7 | `verificar-hardsense.sh` | — |
| `aegis-honeytoken` | Honey-tokens dinamicos y decepcion activa: credenciales senuelo atribuibles (FASE 52) | 10 | `verificar-honeytoken.sh` | — |
| `aegis-hunt` | Ejecucion de consultas AegisQL contra el estado real del endpoint | 44 | — | sí |
| `aegis-ingest` | Ingesta y normalizacion de registros de cualquier origen, con contrapresion y punto de control durable | 201 | `verificar-ingest.sh` | sí |
| `aegis-instrumentar` | Instrumentacion dirigida por lo que el analisis estatico no resolvio. El tipo que escribe en un proceso no se puede construir sin una prueba medida de estar en la jaula: fuera, no compila | 44 | `verificar-instrumentar.sh` | sí |
| `aegis-intel` | Cliente de reputacion con k-anonimato y cache local | 22 | — | sí |
| `aegis-invitado` | Agente invitado de detonacion: traza el comportamiento de una muestra y lo sube por vsock | 38 | `verificar-detonate.sh` | — |
| `aegis-ipc` | Contrato ABI y consumidor del ring buffer compartido Ring 0 <-> Ring 3 de AegisCore | 17 | `verificar-resiliencia.sh` | — |
| `aegis-ips` | Prevencion en linea: decide que flujos cortar y baja el veredicto al kernel | 76 | `verificar-ips.sh` | sí |
| `aegis-kguard` | Integridad del bytecode eBPF y bloqueo de permisos de mapas | 11 | — | sí |
| `aegis-kintegrity` | Verificacion cruzada de la integridad del kernel: deteccion de rootkits DKOM y procesos ocultos | 24 | — | — |
| `aegis-l7hunter` | Extraccion de telemetria L7 en claro por uprobes de eBPF sobre SSL_read/SSL_write, y caza de balizas C2 sin romper el certificate pinning | 56 | `verificar-l7hunter.sh` | sí |
| `aegis-memhunter` | Analisis de VAD y de la tabla de paginas (PTE) para delatar codigo sin fichero, inyeccion reflexiva y module stomping, sin leer la memoria del proceso | 39 | `verificar-memhunter.sh` | — |
| `aegis-macho` | Lector de binarios de macOS (Mach-O y universales), endurecido contra entrada hostil | 28 | `verificar-mac.sh` | sí |
| `aegis-mesh` | Malla P2P de la red local: propagacion cifrada y autenticada de vacunas entre agentes | 19 | — | — |
| `aegis-ml` | Extraccion de atributos estaticos PE/ELF e inferencia local ONNX para AegisCore | 22 | — | sí |
| `aegis-net` | IDS de red y filtro XDP de AegisCore | 45 | — | — |
| `aegis-parser` | Lexer, parser y validador de AegisQL: el del endpoint y, en un analizador aparte que el endpoint no acepta, el del historico (ventanas, agregaciones, subconsultas acotadas) | 82 | `verificar-almacen.sh` | sí |
| `aegis-pe` | Lector de ejecutables de Windows (PE/COFF) y de la huella Authenticode, endurecido contra entrada hostil | 42 | `verificar-pe.sh` | sí |
| `aegis-pqc` | Criptografia post-cuantica hibrida (ML-KEM-768 + ML-DSA-65) para el canal C2 y el firmado de actualizaciones | 39 | — | sí |
| `aegis-presupuesto` | Presupuesto de memoria del agente: reparto por host, regimenes y obligacion desde el kernel | 50 | `verificar-presupuesto.sh` | sí |
| `aegis-ptguard` | Trazado de ejecucion por hardware (Intel PT) para detectar ROP/JOP (FASE 51) | 12 | `verificar-ptguard.sh` | — |
| `aegis-ransom` | Motor de deteccion y contencion de ransomware en tiempo real | 22 | — | sí |
| `aegis-resp` | Motor de respuesta activa de AegisCore: terminacion, cuarentena y aislamiento | 22 | — | — |
| `aegis-rollback` | Reversion de ransomware: copia-sombra cifrada y restauracion en milisegundos (FASE 50) | 6 | — | — |
| `aegis-sandbox` | Aislamiento preventivo con Landlock y seccomp-bpf, y la supervision por notificacion de seccomp y los perfiles aprendidos (lista blanca, reglas de Landlock y conjunto limite de capacidades) sobre los que se construye el confinamiento | 30 | `verificar-confinar.sh` | — |
| `aegis-sbom` | Inventario de componentes (SBOM) de paquetes, bibliotecas, binarios (`cargo-auditable`, Go), contenedores capa a capa y dependencias de aplicacion; correlacion con OSV y alcanzabilidad en ejecucion tri-estado —cargado, alcanzable por el grafo de llamadas, expuesto en red—; sin serializador: el inventario no sabe salir del agente | 72 | `verificar-postura.sh` | sí |
| `aegis-scal` | Capa de abstraccion del nucleo del sistema (SCAL): telemetria y control independientes del sistema operativo | 52 | — | — |
| `aegis-scan` | Motor de deteccion profunda de AegisCore: YARA sobre ficheros y memoria de procesos | 27 | `verificar-memscanner.sh` | sí |
| `aegis-selfdefense` | Autodefensa legitima: OTP firmado del Control Plane, decision de tamper, clasificacion ELAM y requisitos PPL | 42 | — | sí |
| `aegis-swarm` | Enjambre autonomo: nucleo sans-io del protocolo de reparto de inteligencia y ordenes de contencion entre agentes aislados del plano de control | 75 | `verificar-swarm.sh` | sí |
| `aegis-sync` | Sincronizacion diferencial de indicadores de compromiso con arboles de Merkle | 8 | — | — |
| `aegis-syscallguard` | Deteccion de syscalls directas respaldada por hardware (PMU/DRx) y verificacion cruzada del origen de cada syscall | 15 | — | — |
| `aegis-unpacker` | Desempaquetado dinamico en memoria: detecta el OEP de un binario empaquetado y extrae el codigo real | 7 | — | — |
| `aegis-update` | Actualizacion firmada (hibrida Ed25519+ML-DSA-65) con rollback atomico | 18 | `verificar-resiliencia.sh` | sí |
| `aegis-vmi` | Introspeccion de maquina virtual (VMI) DEFENSIVA: EPT y lectura de estructuras del kernel desde memoria fisica para detectar rootkits por debajo del SO |  29  | `verificar-vmi.sh` | — |
| `aegis-volcado` | Forense de memoria: mapa de regiones, codigo sin respaldo de fichero, capacidades del codigo que solo existe en memoria, y vista cruzada de tres caminos para procesos ocultos. Sin ninguna operacion de escritura | 54 | `verificar-volcado.sh` | sí |
| `aegis-vuln` | Escaner de postura y vulnerabilidades del host para AegisCore, que cruza cada paquete por su nombre binario y por su paquete fuente (FASE 94) | 49 | `verificar-postura.sh` | sí |
| `aegis-watchdog` | Watchdog de alta disponibilidad del agente y el driver | 8 | — | — |
| `aegis-wire` | Diseccion semantica de protocolos: convierte trafico crudo en hechos, con reensamblado TCP resistente a evasion | 191 | `verificar-wire.sh` | sí |

#### Workspace del plano de control (`server/crates/`)

**16 crates · 1075 pruebas**

| Crate | Qué hace | Pruebas | Puerta propia |
|---|---|---:|---|
| `aegis-almacen` | Almacen historico del plano de control: columnar por particion de dia en PostgreSQL, purga por DROP, indice primario por entidad y secundarios declarados, retencion caliente/tibio/frio, y AegisQL de coste declarado —la consulta que no cabe se rechaza antes de leer, y dice como arreglarla— | 21 | `verificar-almacen.sh` |
| `aegis-almacen-pcap` | Almacen de captura de red: una particion es un fichero PCAP, se busca por entidad y se purga con un unlink | 10 | `verificar-captura.sh` |
| `aegis-case` | Ciclo de vida del incidente: de alerta a caso cerrado, con cronologia automatica y rastro inmutable | 79 | `verificar-case.sh` |
| `aegis-detonate` | Detonacion de muestras en microVM con invitado hostil, informe determinista y MODO de observacion declarado: con agente dentro y cero eventos no hay camino a «sin hallazgos» | 99 | `verificar-detonate.sh` |
| `aegis-enrich` | Orquestacion de enriquecimiento con declaracion obligatoria de exposicion de datos y modo sin salida | 125 | `verificar-enrich.sh` |
| `aegis-itdr` | Deteccion y respuesta a amenazas de identidad (ITDR): Kerberoasting, Golden/Silver Ticket, grafo de identidad con centralidad, y el **grafo completo del directorio** (FASE 95) —ACL del `ntSecurityDescriptor` byte a byte, delegacion, GPO, confianzas y plantillas ESC, con caducidad de sesion y alcance por red— que no sale del plano de control | 25 | `verificar-itdr.sh`, `verificar-directorio.sh` |
| `aegis-orchestrator` | Maquina de estados transaccional de remediacion de flota; ante una deteccion critica lanza en paralelo el playbook de respuesta, resiliente a fallos parciales e idempotente en el reintento | 6 | `verificar-orchestrator.sh` |
| `aegis-pipeline` | Canalizacion de registros del plano de control: nubes, deduplicacion, orden por ocurrencia y cuotas por inquilino | 58 | `verificar-ingest.sh` |
| `aegis-postura` | Postura de nube reconstruida de los eventos del plano de control —privilegios excesivos, almacenamiento publico, claves sin rotar, registro apagado, red abierta— con evidencia por evento y entidad; y el unico camino por el que sale un SBOM (CycloneDX, SPDX), detras del juez de difusion | 65 | `verificar-postura.sh` |
| `aegis-predict` | Caminos de ataque mas probables, radio de explosion y contencion preventiva acotada | 53 | `verificar-predict.sh` |
| `aegis-ruleforge` | La fabrica de contenido: compila el corpus mundial de deteccion en artefactos firmados | 181 | `verificar-ruleforge.sh` |
| `aegis-scale` | Plano de control para 100.000 agentes: particionado de flota, conexiones, base de datos y actualizacion progresiva | 62 | `verificar-scale.sh` |
| `aegis-server` | Plano de control de AegisCore: ingesta de flota gRPC/mTLS y API de administracion | 122 | — |
| `aegis-share` | Plataforma STIX/TAXII de inteligencia con difusion controlada, federacion y procedencia reversible | 120 | `verificar-share.sh` |
| `aegis-tejido` | El tejido de AegisFabric: inventario de veredictos, traduccion a la escala unica y el circuito completo de extremo a extremo | 38 | `verificar-fabric.sh` |
| `fleet-simulator` | Generador de carga: simula una flota de miles de agentes contra el plano de control | 11 | — |

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
| 68 | [AegisDetonate: detonación en microVM real](docs/68-detonate.md) — esta fase ejecuta malware **a propósito** para ver qué hace, y todo lo demás —la traza, el informe, los indicadores— vale exactamente cero si esa ejecución puede tocar algo real: la frontera no es una capa más del diseño, es la **única razón por la que el resto puede existir**. Se ve mejor por lo que falta: la salida de red **no tiene variante para «red de verdad»**, así que nadie puede configurar por error lo que no se puede expresar — y no se declara, se **comprueba** con una muestra que intenta conectar a `1.1.1.1` desde dentro y no lo consigue. El agente invitado corre con los mismos permisos que la muestra y en cuanto ella escale los tendrá todos, así que enlaza **sólo `libc`**, y el canal transporta hechos y no órdenes: el enumerado de eventos **no tiene ni una variante que sea una orden**, de modo que el anfitrión no valida nada porque no hay nada que ejecutar. Todo lo que sube lo escribe el malware: topes en cada longitud, rutas no-UTF-8 **escapadas en vez de descartadas** (tirarlas le daría una forma trivial de borrar su rastro), huecos de secuencia **anotados en vez de abortados** (abortar le daría una forma trivial de destruir su propio informe) y un error de protocolo que cierra el canal **sin resincronizar**, porque resincronizar le dejaría colocar la marca donde quiera y fabricar tramas. La máquina se destruye **siempre**, en `Drop` y no en un método —un método se olvida en el camino de error, que es justo el que se toma cuando algo ha ido mal— y se mata al **grupo**, porque un malware que lanza un hijo y se muere dejaría al hijo suelto. Y el informe no puede mentir: «corrió entera y no hizo nada», «detectó el entorno y se marchó» y «se cortó antes de empezar» se escriben **igual** en un sandbox descuidado, y sólo la primera es benigna — el veredicto **no tiene ningún camino** que llegue a «sin hallazgos» sin descartar las otras dos. El catálogo anti-anti-VM va **dentro de cada informe** y declara las tres técnicas que **no** se contrarrestan, incluida la medición de tiempos: acelerar el reloj sería *más* detectable que la espera honesta |
| 69 | [AegisIngest: canalización de registros a escala](docs/69-ingest.md) — hasta aquí AegisCore consumía **su propia telemetría**, que es lo que hace un EDR; una plataforma tiene que tragarse además lo que ya escribe el resto de la casa —syslog, journald, EVTX, ficheros planos y los planos de control de AWS, Azure y GCP— y correlacionarlo con lo propio, porque el movimiento que importa cruza esos mundos: una clave robada en AWS, usada desde una IP que sale en el syslog del cortafuegos, contra una cuenta cuyo `4625` está en el EVTX del controlador de dominio. Se elige **OCSF sobre ECS** y se justifica: su taxonomía está *enumerada*, así que la normalización se puede **comprobar** —de contar lo que no encaja sale una cifra de cobertura que con un vocabulario abierto no existiría—. El corazón es el **reloj**: un endpoint apagado un día entrega su lote al reconectar, y ordenado por llegada un ataque repartido en dos días parecería un pico de un segundo; pero la hora de ocurrencia la escribe quien escribe el registro, así que lo inverosímil se **marca**, no se cree ni se tira. Tres cosas que casi todo el mundo hace mal y aquí tienen prueba: la **rotación** —se escribe en la franja entre la última lectura y el `mv`, que sólo existe en el descriptor viejo—, el **truncado** con `copytruncate` —mismo inodo, un día entero de silencio sin un solo error— y el **ancla**: sin ella, veinte fallos de contraseña idénticos byte a byte en el mismo segundo se funden en uno y la fuerza bruta desaparece. La entrega es al-menos-una-vez con una **regla de orden asimétrica** —sincronizar y después avanzar el punto— porque duplicar es recuperable y perder no. Y dos decisiones de seguridad que parecen de rendimiento: la deduplicación es **exacta y no un filtro de Bloom** (un falso positivo borraría un evento único en silencio), y cada inquilino tiene **dos** cubos de cuota, porque con uno el atacante genera ruido en cualquier aplicación del cliente y sus propias huellas dejan de subir |
| 70 | [AegisScale: plano de control para 100.000 agentes](docs/70-scale.md) — la tesis es que **la diferencia entre diez agentes y cien mil no es un factor de escala, es un diseño distinto**, y que los sistemas que no se diseñaron para ello no se arreglan añadiendo máquinas. Cuatro cosas fallan, y las cuatro igual: funcionan hasta que dejan de hacerlo, y entonces ya es tarde. **Ampliar**: con `hash % nodos`, pasar de cuatro a cinco mueve al 80 % de la flota —cien mil agentes reconectando contra un plano de control que acaba de crecer *porque iba justo*—; con **sorteo** se mueve `1/N`, **medido: 5 %**, y además es una función *pura* de (agente, nodos), así que dos nodos calculan lo mismo **sin hablar entre ellos**, que en una partición de red es la diferencia entre funcionar y necesitar consenso para atender un latido. **Conexiones**: una sesión TLS viva cuesta ~48 KiB, así que cien mil son 4,7 GiB *sólo en estar conectado* — «un proceso con cien mil conexiones» no es una meta, es no haber hecho las cuentas; se resuelve con **arriendos** (10.000 huecos atienden a 100.000 agentes con ciclo del 10 %) y con un **desfase determinista**, que aplana la manada de 601/s a 17/s y, al no ser aleatorio, el servidor puede predecirla y la prueba puede comprobarla. **La base de datos**: 144 millones de filas al día, y lo que mata no es el tamaño sino que el `DELETE` de la purga tarda cada día un poco más *hasta el día en que no acaba*; particionada, la purga es un `DROP` —con `DETACH CONCURRENTLY` antes, porque el `DROP` sobre una partición adjunta bloquea la tabla **padre** y para la ingesta de todas—. Y **la trampa de protobuf**: un nodo de la versión anterior ignora *en silencio* un campo que no conoce, así que un «he puesto esta máquina en cuarentena» se pierde y el panel dice que no pasó nada — de ahí la regla, **en el código y no en un manual**: lo que no se puede ignorar va en un **método** nuevo, que falla ruidosamente, no en un campo. Prueba de carga real en `make ci`: 100.000 agentes, 400.000 eventos de telemetría realista, **p50 13 µs · p95 20 µs · p99 40 µs**, 145.000 eventos/s, y la comprobación que de verdad justifica la prueba — **cero pérdida silenciosa**, porque a esta escala nadie cuenta cuatrocientos mil |
| 71 | [AegisCase: de alerta a caso cerrado](docs/71-case.md) — la tesis incomoda: **un producto que detecta y no da flujo de trabajo produce alertas que nadie mira**, y no por dejadez — un analista que recibe cincuenta al día de las que cuarenta y ocho son ruido deja de mirarlas porque es la respuesta *racional* a una señal con esa relación, y el día que llega la que importa va al mismo sitio que las demás. Seis problemas, y los seis fallan **en silencio**. **Fusionar**: de menos ahoga la cola, de más *pierde un incidente sin dejar constancia de haberlo perdido* — en la jornada de la puerta, 1.061 alertas llegan como **3 casos** y la alerta de movimiento lateral que entra en mitad de una campaña de 880 **no se traga**; el motivo se guarda *por alerta* y no por caso, porque ante trescientas alertas juntas la respuesta útil no es «por campaña» sino «ésta por sujeto, estas doscientas por campaña», y sin eso una fusión equivocada no se puede ni discutir. Y la conclusión que sale de medir y no de opinar: una regla ruidosa que salta en noventa máquinas en una hora tiene la **misma forma** que una campaña real, así que el fusionador **no puede** distinguirlas y no lo intenta — lo que las separa es el *veredicto*, que no existe hasta que alguien mira, y por eso la herramienta contra el ruido es la métrica **por regla** (95 % sobre 180 casos concluyentes, con un mínimo de 20 antes de juzgar: apagar una regla por sus dos primeros falsos positivos es la forma más rápida de quedarse sin detección). **Cronología**: se construye de lo que el sistema tiene, y las líneas caen en **tres** clases y no en dos — evidencia, afirmación de una persona, y **hueco** — porque un informe que mezcla las dos primeras atribuye a la evidencia lo que era una hipótesis, y uno que omite la tercera presenta como completo algo con agujeros; un padre no observado **se declara**, unir los extremos diría que A llevó a B cuando lo único que consta es que A ocurrió antes, y una remediación ordenada y no confirmada es el dato de que **la contención puede no haber ocurrido**. **Auditoría**: cadena encadenada por resumen con cuatro roturas distinguidas, y las dos que importan son *borrar* —la manipulación más limpia, que sólo delata el número de secuencia, porque sin él una cadena a la que faltan tres entradas es indistinguible de una cadena corta— y *reescribir entera*, que **sobrevive a toda comprobación interna porque internamente es válida** y sólo la ve un anclaje publicado: todo lo anterior al último anclaje es **inmutable**, todo lo posterior es **detectable** — y el muro se dice, sacar el anclaje del sistema es del canal de atestación, un anclaje guardado junto al rastro no protege de nada. **Modelo**: cerrar exige veredicto y, con tareas abiertas, **escribir por qué**, porque «se investigó y no era nada» y «nadie llegó a mirarlo» producen la misma métrica y sólo una es aceptable; la espera externa se descuenta de la respuesta (25 min de trabajo real sobre 165 de reloj) y se calcula de la *historia de estados* y no de un contador, que se olvida de restar en algún camino y el síntoma es una métrica que mejora sola. Y el rastro se escribe **en la misma transacción** que el cambio, con `FOR UPDATE`: escribirlo aparte crea un camino en el que el caso cambia y la entrada no, que es exactamente lo que el rastro existe para impedir |
| 72 | [AegisEnrich: preguntar a muchas fuentes sin contar lo que no toca](docs/72-enrich.md) — la regla que define la fase, y que casi ningún producto dice en voz alta: **consultar por un resumen le dice al proveedor que ese fichero está en tu red**; no es un efecto secundario de la consulta, *es* la consulta — le das información que no tenía, gratis, y no se puede retirar. Casi siempre compensa, pero «casi siempre» es una decisión, y una decisión que nadie ve no es una decisión: es un valor por defecto. Así que la exposición se **declara en el tipo** —qué campos salen, a dónde, con qué retención y bajo qué jurisdicción, todo enumerados cerrados, campo obligatorio de la ficha: un analizador sin declararla **no compila**— y el panel enseña *qué revela* cada campo antes de ejecutar, no su nombre: «revela que ese fichero exacto está en tu red» y «revela que eres **tú** quien pregunta, que convierte todo lo anterior en atribuible». Lo que **nunca** sale se decide una sola vez y no en cada analizador —una regla repartida por veinte es una regla que el veintiuno se salta—: cuentas, rutas, líneas de órdenes, direcciones privadas y nombres internos, cada uno con su motivo escrito. El **modo sin salida** se cumple *por construcción*: la salida es una **capacidad** que se entrega, no una bandera que se comprueba, y con el modo puesto ese objeto **no existe** — la diferencia que va de «prometió no salir» a **«no se le dio por dónde»**; en la puerta de calidad el analizador lo intenta y sale con 0 consultas, mientras los locales siguen dando veredicto (sin salida es *degradado*, no apagado). Lo que devuelve un analizador lo escribió un tercero por Internet dentro del proceso más privilegiado del producto, así que se **sanea siempre** —20.000 B → 510, 1.000 etiquetas → 1, confianza 255 → 100, fecha futura → presente— y hay cuatro cosas que **no puede elegir**: su clase (si no, un canal comunitario se declara autoritativo y se salta la jerarquía entera), su exposición, si hay red, y el observable del dictamen. La **caché es también privacidad** —cada consulta que no se hace es una vez menos que lo confirmas, y la frecuencia es lo que permite reconstruir tu cronología—, con caducidad por tipo sacada del mundo real (**IP 2 días** frente a resumen 180: tratarlas igual es bloquear a quien ocupa hoy una dirección por lo que hizo quien la ocupaba la semana pasada) y el acierto **negativo a una hora**, porque guardar «no lo conozco» durante meses es no enterarse justo del malware nuevo. La cuota se **reserva**, no se comprueba: 1.440 peticiones concurrentes contra una ráfaga de 100 conceden **exactamente 100**, porque comprobar-y-actuar deja pasar de más y pasarse de cuota corta el servicio *durante* el incidente. Y la fusión **no promedia**: dos fuentes seguras y contrarias dan **`EnDisputa`** y no un valor intermedio que se leería como evidencia débil cuando lo que hay es evidencia fuerte en las dos direcciones; cuatro «no sé» dan **`SinDatos`** y no «probablemente limpio» —un fichero que nadie conoce es lo que parece un fichero recién compilado—; y una observación propia gana a tres reputaciones porque nosotros **vimos** la cosa y ellas repiten lo que alguien dijo. Un analizador colgado se corta (203 ms con plazo de 200 y uno que tarda 2.000), uno que entra en pánico se recoge, y doce fusiones concurrentes dan el mismo veredicto **y la misma explicación** |
| 73 | [AegisShare: inteligencia con difusión impuesta en el código](docs/73-share.md) — la asimetría que lo decide todo es que **compartir es irreversible y los errores se propagan**, y por eso los dos fallos que importan no son de formato: que salga algo que no debía —y no hace falta un ataque, basta un filtro que se quedó atrás cuando se añadió un camino de salida nuevo—, y que entre algo envenenado y **no se pueda deshacer**. STIX y TAXII son la parte fácil. **TLP y PAP son dos ejes** y casi todo el mundo implementa sólo el primero: `TLP:GREEN`+`PAP:RED` significa «compártelo con toda la comunidad **y no lo bloquees**», porque bloquearlo le dice al atacante que se le ha visto y cambia de infraestructura — quien sólo mira TLP lo empuja al motor de bloqueo y **quema la operación de quien lo compartió**, y la siguiente vez no se lo mandan. El retículo sólo restringe: combinar toma lo peor **de cada eje por separado** (tomar «el peor objeto» perdería la mitad de la restricción), lo que llega sin marcar es lo más restrictivo, y el `TLP:PINK` que aparezca el año que viene se lee como RED y no como público. Un paquete STIX es **JSON de un desconocido que procesa el plano de control**, así que la extensibilidad del formato *es* la superficie de ataque: topes de bytes, objetos, propiedades y textos, y **profundidad medida ANTES de analizar** —10.000 llaves abiertas desbordan la pila antes de que ninguna validación llegue a ejecutarse—; más las tres comprobaciones que casi nadie hace, y la que más ha filtrado en sistemas reales es que **una referencia de marcado que no resuelve restringe MÁS, no menos** (si no, el objeto se pinta sin etiqueta: documento válido, objeto entero, y lo único que falta es lo que decía que no se podía enseñar). «No sale por ningún camino» es arquitectura antes que código: **un solo estrangulamiento** por el que pasan TAXII, federación, enjambre y exportación —si cada uno tuviera su filtro, el que se quedara atrás no fallaría ruidosamente, *compartiría de más*— y `TLP:RED` **no lo distribuye ningún canal**, ni una exportación a fichero, porque exportar es distribuir; en la puerta el motivo de retención es **el mismo en los cinco destinos**, así que la propiedad es cierta por construcción y no por haber configurado bien. El enjambre lleva dos topes que **no se pueden subir**: nada por encima de `TLP:GREEN` y nada que no permita bloqueo propio, porque llega a máquinas que el atacante puede haber comprometido —el supuesto de la FASE 68— y lo que cruza acaba en el motor de bloqueo de cien mil endpoints. La paginación TAXII por **cursor `(añadido, id)`** y no por desplazamiento, que *pierde objetos en silencio* si alguien escribe entre dos peticiones, y el sondeo va por «cuándo se añadió aquí» para que lo que llega viejo por federación se vea hoy. En federación, «ya vi ese identificador» corta el bucle **y también las correcciones** —«esto era un falso positivo, lo retiro» no llegaría nunca—, así que se usa el **vector de camino** de BGP, con el último salto autenticado (lo único infalsificable) y un tope de saltos que **no depende de que nadie diga la verdad**; los conflictos se resuelven por `(modified, revocado, id)` y jamás por hora de llegada, que haría que dos nodos de la misma federación acabaran distintos. Y la procedencia: la confianza **se calcula, no se guarda** (un escalar dejaría el número inflado al revocar), un objeto con varios aportes **sobrevive** a que caiga uno, y —lo que casi nadie hace— **dos canales que repiten al mismo son una fuente**, que es como un indicador parece corroborado sin estarlo y lo que explota quien envenena: envenena el de arriba y cobra en los dos. En la puerta: 467 aportes tocados, **430 caen, 37 sobreviven** con la confianza recalculada y 237 quedan intactos; **3.082 entradas hostiles** sin un solo pánico; y la doctrina de la FASE 68 **se cuenta**, no se afirma — la carga del enjambre tiene dos variantes y ninguna es una orden |
| 74 | [AegisFabric: un solo modelo de entidad, un solo veredicto](docs/74-fabric.md) — la tesis es incómoda y comprobable: **nueve subsistemas de detección, cada uno con su idea de «qué es una cosa», producen nueve sucesos sin relación ante un mismo ataque**. En este árbol había **doce enumerados de veredicto y nueve de severidad**, ninguno mal por separado, y ni una tabla que dijera cuál se traduce a cuál — así que ante el mismo incidente el disector decía `FicheroTransferido{sha256}`, el corpus `Entrada{clave,clase}`, la detonación `ConHallazgos{hechos}` sobre una `Muestra{sha256}`, el caso `Observable::Hash` y el enjambre `Ioc{FileSha256}`: cinco nombres para la misma cosa, y la unión la hacía una persona de cabeza. El identificador **se deriva, no se coordina** (dos observadores con los mismos hechos llegan al mismo nombre sin hablar, que es lo que salva un corte de red), y lo que más decide es **lo que NO se fusiona**: un **pid reciclado** no hereda la historia del anterior —por eso el identificador lleva el arranque, y sin él la cronología mezcla dos procesos ajenos—, el **contenido y la ubicación** son entidades distintas —el mismo fichero en dos rutas no es una cosa, y dos ficheros en la misma ruta tampoco: eso es una actualización, y confundirlos hace que un binario nuevo herede el veredicto del que sustituyó—, y el **mismo flujo desde los dos extremos** sí es uno. Severidad y confianza son **ejes distintos**: un adware con certeza absoluta y un indicio de ransomware dan el mismo «riesgo de 0 a 100» y son la diferencia entre anotarlo y levantar a alguien de la cama. Cada motor lleva su **tope de confianza** con su razón —99 la detonación, que *vio* la muestra correr; 70 el modelo, porque una puntuación alta no es una probabilidad salvo que se haya calibrado— y lo impone el **constructor**, no una convención. Corroborar **cuenta planos, no motores**: el estático y el modelo del endpoint comparten la entrada entera, así que si el fichero está ofuscado **fallan los dos a la vez y por lo mismo**, y contarlos como dos es la falsa confirmación más fácil de fabricar; toda la inteligencia externa es **un** plano, y nunca decide sola. El árbitro es una **función pura** —el tiempo entra como argumento— con seis reglas en orden y **sin medias**: dos motores seguros y contrarios dan `EnDisputa`, no un punto medio que se leería como evidencia débil. La prueba que justifica la fase encadena **once subsistemas sobre un solo identificador** —paquete → disección → fichero extraído → corpus mundial → microVM → árbitro → caso → enriquecimiento → camino de ataque → contención → TAXII → enjambre—, con el código real de cada uno; y dos paradas dicen lo que el producto es: el enriquecimiento responde **`sin-datos`** porque corre sin salida y «nadie lo conoce» no es «está limpio», y la contención **corta la identidad y no el controlador de dominio**, que está protegido. La ruta caliente se mide antes y después (85 ns el criterio viejo, **2,9 µs** el árbitro con su frase, sus planos y sus señales, bajo un techo declarado de 5 µs), y el coste en el endpoint son **cero crates nuevos**, comprobado por subconjunto del árbol del agente y no contando dependencias. Y la fase, al usar el producto desde fuera por primera vez, encontró que los dos marcados AMBER de `aegis-share` **tenían el nombre cambiado**: `Tlp::Amber` valía `TLP:AMBER+STRICT`. El orden era correcto y todo funcionaba, así que ninguna prueba lo veía —la ida y vuelta de etiqueta es estable con los nombres cambiados porque sólo compara el sistema consigo mismo—; lo que rompe es quien escribe `if tlp <= Tlp::Amber { compartir }` y sin saberlo deja pasar «sólo mi organización». **Un identificador que miente sobre su valor es un fallo de seguridad aunque la aritmética esté bien** |
| 75 | [AegisProof: las trece invariantes, demostradas sobre el producto completo](docs/75-invariantes.md) — cada una de las veintiocho puertas de fase comprueba lo suyo y lo comprueba mejor que ésta; lo que **ninguna puede comprobar es lo que se rompe al sumar**: que el agente siga cabiendo en su presupuesto con *todas* las capacidades encendidas a la vez —cada fase midió la suya, ninguna midió el total—, que ningún crate de análisis haya ganado un `unsafe` por el camino, que el árbol del endpoint no haya engordado sin que nadie lo justifique, y que el producto **entero** siga protegiendo con el plano de control caído. Tiene **derecho de veto**: si una invariante se rompió, se arregla *de raíz* antes de dar el trabajo por terminado, aunque obligue a volver sobre una fase anterior — una invariante que se relaja «sólo esta vez» deja de ser una invariante y pasa a ser una aspiración. El **presupuesto** no son 46 080 KB fijos, y se dice por qué: un número fijo obliga a elegir entre ahogar una pasarela de 1 GiB y desaprovechar un servidor de 512 GiB, así que se mide contra el reparto por clase de host, con la huella de arranque —32 MiB medidos— como regresión dura, y con la tercera capa impuesta por **el kernel** (`MemoryHigh` 321 MiB, `MemoryMax` 482 MiB de cgroup v2) porque las dos de dentro las ejecuta un proceso que puede estar comprometido. La **seguridad de memoria** no se afirma como «cero `unsafe`», que sería mentira —hay código cuyo trabajo *es* hablar con el kernel—, sino como algo comprobable y sin tercera opción: todo crate del agente **o** declara `#![forbid(unsafe_code)]`, y lo impone el compilador, **o** está en la línea base con su razón escrita; la fase encontró **19 crates que no usaban `unsafe` y tampoco lo prohibían** —entre ellos `aegis-parser`, `aegis-scan`, `aegis-ml` y `aegis-behavior`, análisis puro que mira entrada hostil— y ahora son 32 con el `forbid` y 22 declarados. La **autonomía** no es permisividad, y ésa es la prueba que más dice: un agente aislado que aceptara órdenes sin firma sería peor que uno que no detecta nada, porque el atacante **crea** el aislamiento y luego manda — así que el corte no afloja ni una comprobación, y las tres acciones que apagarían la defensa (levantar un aislamiento, desactivar una regla, degradar la protección) se descartan *por su clase*, antes de mirar la firma. El **autoataque** usa cada capacidad contra el producto —el disector como amplificador, el IPS como denegación de servicio, el compilador de reglas como vía de ejecución, la detonación como fuga del invitado, la ingesta como agotamiento de memoria, el enriquecimiento como fuga de datos, la federación como envenenamiento— con **205 pruebas**, porque cada capacidad que se añade a un producto de seguridad es una capacidad nueva para quien lo comprometa. Y cuatro invariantes se verifican **por lo que falta**, que es la única garantía que no depende de que el código de comprobación esté bien: la carga del enjambre no tiene variante que sea una orden, la salida de la detonación no tiene variante para «red de verdad», y el evento del invitado no tiene ninguna que se pueda ejecutar |
| 76 | [AegisState: el estado del endpoint, entero y consultable](docs/76-estado.md) — AegisQL era **mejor lenguaje** que el SQL de osquery —no tiene `JOIN`, así que el coste de cualquier consulta es acotable; valida tablas, columnas y tipos *antes* de salir de la consola; y su gramática no puede expresar una escritura, así que no hay nada que filtrar— y corría sobre **cinco tablas**. Un lenguaje excelente sobre una fracción del sistema responde bien a lo que puede responder y **no dice nada de lo demás**, que es la peor manera de fallar: el analista no sabe que no puede preguntar. Ahora son **52 tablas y 328 columnas** en ocho familias, y lo que las separa de osquery no es el número sino **cuatro cosas de clase, no de grado**. La primera: una tabla de osquery que no se puede leer devuelve **filas vacías**, y no es un descuido de su implementación —con `Vec<Row>` como tipo de retorno **no hay dónde poner el motivo**, así que «no hay nada» y «no pude mirar» se escriben igual y en un informe se leen igual: como si la máquina estuviera limpia. Aquí la firma es `Result<Filas, MotivoNoLeible>` con **ocho variantes y ninguna `Otro(String)`**, porque una variante comodín se convierte en el vertedero donde acaban los fallos que nadie miró; y hay un segundo nivel, `Aviso`, para la lectura que **sí** tuvo éxito y declara sus huecos —«enumeré diez mil ficheros y tres no los pude abrir» no es un fallo, pero tampoco es haber visto la máquina entera—. La segunda: **coste declarado por tabla**, con un nivel que no existía: `Peligroso` no significa «muy caro» sino «su coste **no lo acota el tamaño de la tabla sino el disco del cliente**», porque recorrer el árbol de ficheros para encontrar los `suid` no depende de cuántos `suid` haya. Una consulta que toca una de las **seis** peligrosas sin filtro no se ejecuta —el rechazo llega en menos de 50 ms sin tocar el disco— y en Rust **ni siquiera compila**: el rasgo que autoriza a difundirla no tiene implementación para esa combinación, y está **sellado**, así que nadie puede añadirla desde otro crate. De las seis, `process_environment` es peligrosa por lo que **contiene** y no por lo que tarda: difundirla a la flota juntaría los tokens de nube y las contraseñas de toda la empresa en un solo sitio, que es el peor sitio donde podrían estar juntos. La tercera: **empuje de predicados**, medido —`process_arguments` examina **1 proceso** acotada y **75** sin acotar— y con su propiedad de corrección escrita, porque es la única forma de que este mecanismo haga daño: lo que devuelve la consulta acotada tiene que **contener** lo que cumple el filtro, así que solo se empuja **conjunción pura en la raíz**; bajo un `OR`, saber que una rama pide `pid = 42` no autoriza a mirar solo el 42 —la otra acepta más—, y empujarlo **perdería detección en silencio**. La cuarta: cada fila que nombra una cosa lleva su **`Eid`** de la FASE 79, así que el resultado de una consulta se une con el linaje y con el veredicto del árbitro **sin correlacionar por cadenas**. El esquema vive en el **lenguaje** y no junto a los proveedores, y no es un detalle de gusto: el plano de control valida las consultas del analista contra ese mismo esquema *antes* de difundirlas, y si el catálogo viviera junto a los lectores de `/proc` habría que compilar llamadas al sistema de Linux dentro del servidor. Son dos sitios que tienen que decir lo mismo y dos sitios se desincronizan, así que una tabla que el lenguaje declara y nadie sirve, un proveedor que el lenguaje no conoce y una tabla peligrosa que se olvida de exigir filtro **rompen la compilación de las pruebas**. Y lo que la fase encontró **en su propio código** es exactamente el pecado que existe para corregir: **cuatro tablas devolvían cero filas sin poder distinguir «miré y no hay» de «no miré»** —`authorized_keys` contaba ficheros y no cuentas, y `kerberos_tickets`, `boot_images` y las tres de contenedores callaban—; la lista de directorios que no se recorren comparaba **por igualdad**, así que una consulta acotada a `/proc/self/` empezaba *dentro* de `/proc` y lo recorría entero; y `kernel_modules` recorría `/lib/modules` **una vez por módulo**. Medido aquí, no citado: las diez preguntas que un analista hace de verdad durante un incidente, **261 ms** las diez, y **la fila que importa es la sexta** — en esta máquina no hay `/proc/modules`, y la respuesta no es «cero módulos», que haría concluir que no hay ningún rootkit, sino **el motivo** |
| 77 | [AegisArtifact: la evidencia que se puede sostener](docs/77-custodia.md) — `aegis-forensics` recogía lo que hay que recoger antes de que desaparezca, y eso basta para **investigar**; no basta para **sostener** en cuanto alguien discute la prueba. Cada recolección lleva un sello de procedencia —quién la ordenó, cuándo, sobre qué entidad, con qué reloj— encadenado por resumen, y un veredicto de custodia que **enumera lo que NO prueba**: una evidencia sin custodia no se puede construir |
| 78 | [AegisWin: el ejecutable de Windows por dentro](docs/78-windows-pe.md) — el agente sabía mirar un proceso de Windows **por fuera** y no sabía abrir su fichero. Lector PE/COFF endurecido contra entrada hostil, con la huella Authenticode —que excluye a propósito el checksum, la entrada de certificados y su sección— para que casar con la DBX y con las firmas sea posible |
| 79 | [AegisMac y AegisEnforce: macOS, y qué se impone de verdad](docs/79-macos-y-aplicacion.md) — el lector Mach-O y universal que contiene varios programas en un fichero, y la postura de aplicación medida en esta máquina: qué se **impone** de verdad y qué sólo se **observa**, dicho sin redondear |
| 80 | [AegisDisasm: desensamblado, grafos y capacidades con evidencia](docs/80-desensamblado-y-capacidades.md) — una firma dice «esto es Emotet» y no dice por qué; una **capacidad** dice «esto inyecta código» y **enseña las instrucciones que lo hacen**. Desensamblado de x86-64 y A64, grafo de flujo y de llamadas con indirectas resueltas por constantes, y la evidencia dentro del tipo |
| 81 | [AegisDissect: disección de protocolos empresariales, industriales y de nube](docs/81-diseccion-de-protocolos-ampliada.md) — cuando falta una alerta hay dos explicaciones, **no pasó nada** o **pasó algo que no supimos leer**, y ningún sensor distingue las dos. Cada disector declara qué entiende, qué reconoce sin analizar y por qué, y de ahí sale la cifra de cobertura |
| 82 | [AegisCapture: captura de paquetes indexada por entidad](docs/82-captura-indexada-por-entidad.md) — un capturador es un sitio del que robar y una forma de llenar el disco. El anillo sólo acepta bytes redactados, guardar entero exige un veredicto, la retención se decide en el tipo, y el índice es por entidad: buscar una entidad devuelve su tráfico sin correlacionar por texto |
| 83 | [AegisLure: red de señuelos atribuible](docs/83-senuelos-atribuibles.md) — diecinueve señuelos que conversan varios turnos sin nada que encarcelar, cero falsos positivos por construcción, amplificación acotada a x1 en UDP por el envoltorio, y un token distinto por señuelo y por destino: cuando una credencial aparece, el sitio del que salió está dentro de ella |
| 84 | [AegisFirmware+: auditoría de plataforma de grado CHIPSEC, sin poder escribir](docs/84-auditoria-de-plataforma.md) — de dos superficies de firmware a **doce**: protecciones de la flash, SMM, chipset y MSR, IOMMU, mitigaciones, microcódigo frente al publicado por el fabricante, variables UEFI, AML y la cadena de arranque **explicada** medida a medida, con el texto de cada evento comprobado contra su resumen. La escritura es **imposible de expresar** —cinco `compile_fail` con código de error— y se ejerce contra el kernel en seis superficies reales, con el errno que el kernel da de verdad y no el que pedía el enunciado. Compromiso y exposición van separados en el tipo: al árbitro sólo llegan los compromisos. El AML real se coteja en cada `make ci` contra `iasl` (2457 métodos, idéntico) y `acpiexec` (7 cargados, idéntico); frente a CHIPSEC, 21 módulos cubiertos, 3 parciales, 6 no cubiertos —escritos como derrota— y 6 excluidos por escribir o atacar |
| 85 | [AegisConfine: confinamiento que se aprende, se ensaya y se retira solo](docs/85-confinamiento-aprendido.md) — SELinux, AppArmor, gVisor y Kata saben confinar; lo que no resuelven es **de dónde sale la política** ni qué pasa cuando rompe algo. Aquí se **aprende** del programa real con la notificación de usuario de seccomp (sin perder ni una llamada y sin que el proceso lo note), se **ensaya** en permisivo dejando pasar todo y anotando lo que se habría bloqueado, se **impone** sólo con una confirmación con autor y motivo —el tipo no admite otra forma— y un **ensayo limpio**, y si rompe la producción **se retira solo**, de forma pegajosa. Contra el kernel real: lo aprendido funciona, el `socket` no aprendido lo bloquea seccomp y el fichero no aprendido Landlock, un proceso de root arranca sólo con sus cinco capacidades implícitas, y un perfil roto se retira a los tres fallos. Sobre `ls` real, el perfil cierra el **91,7 %** de la superficie de llamadas. El motor no puede ni construir el objetivo para el propio agente, `init` o un activo protegido |
| 86 | [AegisPosture: vulnerabilidades que importan, SBOM y postura de nube](docs/86-postura-y-alcanzabilidad.md) — Trivy, Grype y Syft dicen que **hay** una vulnerabilidad; aquí se dice si **importa**: si el componente está **cargado** en un proceso vivo, si la función vulnerable es **alcanzable** por el grafo de llamadas desde las raíces del programa y si el servicio está **expuesto** en red, cada respuesta tri-estado y sacada de telemetría que el agente ya tenía. Medido en esta máquina: de las 15 899 vulnerabilidades de Trivy, 12 319 están en componentes que ningún proceso carga; el inventario completo cabe en 38 MiB frente a los 0,9–5,5 GB de las otras. El SBOM no sale del agente: se exporta solo desde el plano de control, detrás del juez de difusión, marcado `TLP:AMBER+STRICT`, y Trivy lo lee. Y la postura de nube, reconstruida de los eventos que ya se ingerían, sin credenciales de lectura en la nube del cliente. |
| 87 | [AegisStore: el almacén y el lenguaje sobre el histórico](docs/87-almacen-historico.md) — Elastic, OpenSearch y Graylog indexan documentos y buscan por texto; aquí el índice primario es la **entidad** del modelo único, y el lenguaje es **el mismo AegisQL** del endpoint: 14 consultas de caza devuelven las mismas filas contra el ejecutor real del endpoint y contra el histórico. Las extensiones del histórico —ventanas, agregaciones, subconsultas acotadas— no existen para el endpoint, **por tipo**. Columnar por partición de día en PostgreSQL real (el muro de la FASE 75, derribado), purga por `DROP`, retención caliente/tibio/frío, y **coste declarado**: la consulta que no cabe se rechaza en 1 ms sin leer nada y dice cómo arreglarla. Medido con 4,2 millones de eventos: 284 000 eventos/s de ingesta, 108 MiB en disco, «todo de una entidad en 7 días» en 87 ms. La comparativa con OpenSearch no se hizo, y se declara. |
| 88 | [AegisFlow: automatización de respuesta con frenos](docs/88-automatizacion-con-frenos.md) — Shuffle y los SOAR abiertos pasan datos entre acciones con plantillas de texto y, si el flujo falla a medias, queda a medias. Aquí el flujo es un **grafo tipado**: un fichero donde iba un proceso **no compila**, un paso sin reversión **no compila**, un paso irreversible sin firma humana **no compila** —cuatro `compile_fail`, cada una comprobada por el error exacto del compilador—. Si falla a medias, se revierte en orden inverso **al estado de antes**, comprobado fila a fila contra el esquema real del plano de control; la aprobación es una firma híbrida sobre esa ejecución concreta; y los cinco frenos miran **cada paso** con el radio **acumulado** de la ejecución. Autoataque contra mil máquinas: aislar la flota entera firmado, lo mismo en mil pasos de uno, y bloquear `0.0.0.0/0`, detenidos y escalados sin tocar una fila. La comparativa con Shuffle es por propiedades citadas de su documentación, no medida, y se declara. |
| 89 | [AegisKnowledge: el conocimiento de amenazas, unido a lo observado](docs/89-conocimiento-de-amenazas.md) — OpenCTI y MISP modelan el conocimiento; aquí además se une con lo **observado** en el mismo grafo, así que «qué sé de este actor» y «qué he visto yo de él» son el mismo recorrido. STIX 2.1 completo, con las relaciones embebidas y las personalizadas, y el canon de relaciones sacado **del PDF normativo** y del validador de OASIS, con la procedencia de cada fila. ATT&CK entero (30 894 objetos reales) de ida y vuelta **idéntico** objeto a objeto, por el juez único de salida. La inferencia **propone y no afirma**: cadena explicable, acotada, repartida entre alternativas (ver Cobalt Strike da 36 hipótesis a 1/100) y rebatible, y una hipótesis **no compila** como hecho. Autoataque de envenenamiento: la relación falsa se aísla por su procedencia y se revierte sin tirar lo que sostenían los demás. Frente al esquema de OpenCTI: empate en el canon (137/137); sobre ATT&CK real, 24 818 relaciones conservadas frente al 92,0 % que su esquema admite. |
| 90 | [AegisDirectory: el grafo completo del directorio](docs/90-grafo-de-directorio.md) — BloodHound modela el directorio y encuentra caminos; aquí se modela lo mismo —pertenencia anidada con ciclos, ACL del `ntSecurityDescriptor` **byte a byte**, delegación sin restricciones/restringida/RBCD, derechos de ejecución, GPO, confianzas y plantillas de certificado **ESC**— y se une con dos cosas que BloodHound no tiene: la **caducidad de la sesión** en cada arista (la misma consulta, antes y después de caducar una sesión, da un camino distinto) y el **alcance por red**. Se lee en solo lectura y sale como inventario de exposiciones **con su remediación**; alimenta la predicción de la FASE 69 sin que los cinco frenos se rompan, y el grafo completo **no sale del plano de control** (autoataque canal a canal + `compile_fail`). Núcleo probado sin red con estructuras binarias reales; medido con 10 002 principales sintéticos. Muros de entorno: la captura en vivo por LDAP y la medida a cien mil cuentas necesitan un dominio real —el lector LDAP compila siempre—. |
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
