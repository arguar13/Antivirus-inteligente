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
| **Eficiencia permanente** | < 50 MB RSS y < 0,5 % CPU en reposo | Presupuesto repartido por componente (abajo); prueba de carga en CI |
| **Cero bloatware** | Solo defensa, detección, aislamiento y respuesta | Cualquier funcionalidad que no reduzca el riesgo de compromiso se rechaza en revisión |
| **Autodefensa** | Inmune a terminación no autorizada | PPL + ELAM + `ObRegisterCallbacks` (Windows), LSM + eBPF (Linux) |
| **Resiliencia ante evasión** | Detección de syscalls directos e indirectos | Telemetría desde ETW-Ti / eBPF, no desde hooks de userland |

### Presupuesto de recursos

El límite de 50 MB no es un objetivo vago: se reparte por componente y se mide.
Un componente que se pase de su cuota es un bug, no una molestia.

| Componente | RSS en reposo | CPU en reposo | Notas |
|---|---:|---:|---|
| `aegis-drv` (kernel, non-paged pool) | 8 MB | ~0 % | Ring buffer 4 MB + tablas de procesos |
| `aegis-agent` (colector + correlación) | 18 MB | 0,1 % | Grafo de procesos acotado por LRU |
| Reglas YARA compiladas (residentes) | 12 MB | 0 % | Compartidas entre hilos vía `Arc`, no por hilo |
| Modelo ML (ONNX, cuantizado int8) | 6 MB | 0 % | Solo se ejecuta ante ficheros desconocidos |
| `aegis-ui` (cuando está cerrada) | 0 MB | 0 % | La UI **no** es un proceso residente |
| **Total en reposo** | **44 MB** | **< 0,5 %** | 6 MB de margen |

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
