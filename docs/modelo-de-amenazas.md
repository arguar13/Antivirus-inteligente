# Modelo de amenazas de AegisCore

> **Versión 1** · FASE 0 del MP-15 · 2026-09-29
>
> Documento vivo y versionado. Cada fase posterior lo **cita** por identificador
> (`AM-3.3`) cuando cierra, abre o cambia un control, y sube la versión. La
> estructura la comprueba `cargo xtask amenazas` en cada `make ci`: identificadores
> únicos, estados válidos y evidencias que existen en el repositorio.

## Alcance

Se modela **lo que se instala hoy**, no lo que existe como biblioteca. Los
ejecutables instalables son los de
[`tools/config/instalables.toml`](../tools/config/instalables.toml), y lo que cada
uno ejecuta de verdad está en la [matriz de capacidades](matriz-capacidades.md).
Una capacidad que solo existe como biblioteca **no cuenta como control**: si el
control vive en un crate que ningún instalable invoca, el estado es *ausente*.

### Activos que se protegen

| Activo | Por qué importa |
|---|---|
| El veredicto del endpoint | Si se ciega o se falsea, el cliente cree estar protegido sin estarlo |
| La capacidad de respuesta (matar, aislar, cuarentena) | En manos equivocadas es un arma contra la propia flota |
| Las claves (CA de flota, firma de actualizaciones y de OTP) | Quien las tiene manda sobre todos los agentes |
| Los datos del cliente (telemetría, evidencias, casos) | Confidencialidad y obligaciones legales |
| La disponibilidad del host | Un EDR que tumba la máquina es peor que ninguno |

### Fronteras de confianza

```
  [kernel] ──ring buffer BPF──▶ [aegis-agent] ◀──socket Unix 0600── [aegisctl]
                                      ▲
                          lanza/relanza (sin latido, AM-1.2)
                                      │
                               [aegis-watchdog]

  [navegador SOC] ──HTTP + Bearer (AM-3.3)──▶ [aegis-server] ──▶ PostgreSQL, Redis
  [agente de flota] ──gRPC + mTLS──────────▶ [aegis-server]    (hoy ningún agente real conecta)
```

### Estados

| Estado | Significado |
|---|---|
| **existente** | El control está implementado **y** lo ejecuta un instalable. Lleva evidencia en el código. |
| **parcial** | Existe, pero no cubre toda la amenaza; se dice qué falta. |
| **ausente** | No hay control en lo que se instala (aunque exista como biblioteca). |
| **aceptado** | Riesgo asumido a sabiendas, con el motivo escrito. |
| **no-aplica** | La superficie no existe hoy en lo instalado; se reevalúa al integrarla. |

## AM-1 · Atacante con root en el endpoint

Es el adversario más fuerte. Con root pleno sobre el kernel ningún agente de
espacio de usuario es invulnerable; lo exigible es que **cegarlo se note** desde
fuera y que lo que se pueda impedir, se impida.

| ID | Amenaza | Control | Estado | Evidencia | Plan |
|---|---|---|---|---|---|
| AM-1.1 | Matar o parar el agente | El watchdog lo relanza si muere | **parcial** | `crates/aegis-watchdog/src/bin/aegis-watchdog.rs` | Root mata también al watchdog: falta protección desde el kernel (BPF LSM) y alarma de silencio en el plano de control |
| AM-1.2 | Colgar el agente sin matarlo | Detección por latido | **ausente** | `crates/aegis-watchdog/src/bin/aegis-watchdog.rs` | El watchdog espera un latido que el agente no escribe: conectar el latido en el bucle del agente |
| AM-1.3 | Desenganchar o sustituir sus programas eBPF | Comprobación periódica de que los enlaces siguen vivos | **ausente** | — | Verificar en caliente los enlaces y declarar la ceguera |
| AM-1.4 | Parchear el binario o el bytecode empotrado | HMAC del bytecode antes de cargarlo | **parcial** | `crates/aegis-agent/src/bpf.rs` | La clave va en el mismo binario: detecta corrupción, no a un root. Hace falta firma con clave fuera del endpoint o medida por IMA/TPM |
| AM-1.5 | Cegar familias de telemetría (desmontar tracefs, cambiar `lsm=`) | Capacidades detectadas y degradación declarada | **parcial** | `crates/aegis-agent/src/capacidades.rs` | Solo se evalúa al arrancar: re-evaluar en ejecución y reportarlo al plano de control |
| AM-1.6 | Depurar o leer la memoria del agente | Antidepuración pasiva siempre; activa con `--harden` | **parcial** | `crates/aegis-agent/src/main.rs` | La respuesta activa está apagada por defecto |
| AM-1.7 | Borrar o alterar el registro local | Auditoría cifrada con rotación | **ausente** | — | `aegis-audit` es biblioteca: ningún instalable lo invoca |
| AM-1.8 | Desinstalar sin autorización | OTP firmado por el plano de control | **ausente** | — | El servidor emite el OTP (`aegis-selfdefense`), pero el agente no lo exige |
| AM-1.9 | Ocultar el compromiso del propio kernel | Atestación remota por TPM | **ausente** | — | `aegis-attest` solo lo enlaza el servidor; ningún agente produce el *quote* |

## AM-2 · Fichero o dato hostil a los analizadores

El agente analiza datos que el atacante controla: líneas de órdenes, rutas y
contenido de ficheros. Un fallo aquí es ejecución de código como root.

| ID | Amenaza | Control | Estado | Evidencia | Plan |
|---|---|---|---|---|---|
| AM-2.1 | Registros del ring buffer con contenido del atacante (órdenes, rutas) | Decodificación acotada y contador de malformados | **existente** | `crates/aegis-agent/src/decode.rs` | Añadir objetivo de *fuzzing* sobre `decode` |
| AM-2.2 | Fichero diseñado para colgar el escáner (ReDoS) | Motor de patrones sin retroceso y de coste acotado | **existente** | `crates/aegis-patron/src/lib.rs` | — |
| AM-2.3 | Corrupción de memoria en los analizadores | Rust con `forbid(unsafe_code)` en los analizadores | **existente** | `crates/aegis-patron/src/lib.rs` | Mantener la invariante de `unsafe` |
| AM-2.4 | Entrada que siempre provoca pánico (bucle de reinicios) | `panic = "abort"` y relanzamiento del watchdog | **parcial** | `Cargo.toml` | Falta limitar los reinicios y poner en cuarentena la entrada que los causa |
| AM-2.5 | Analizador sin *fuzzing* en el camino instalado | *Fuzzing* continuo (libFuzzer) | **parcial** | `fuzz/fuzz_targets/aegisql.rs` | Hay objetivos para AegisQL, firmware y flota, no para `decode` ni para el motor de patrones |
| AM-2.6 | PE, Mach-O, disectores de red, desensamblador con entrada hostil | Analizadores endurecidos y con pruebas | **no-aplica** | — | Ningún instalable los invoca hoy; se reevalúa al integrarlos |

## AM-3 · Atacante en la red contra gRPC, la API y la malla

| ID | Amenaza | Control | Estado | Evidencia | Plan |
|---|---|---|---|---|---|
| AM-3.1 | Suplantar a un agente ante el servidor | mTLS mutuo con la CA de flota | **existente** | `server/crates/aegis-server/src/ca.rs` | — |
| AM-3.2 | Suplantar al servidor ante el agente | mTLS en el cliente de flota | **no-aplica** | — | El instalable `aegis-fleet` es una demostración que no se conecta al servidor real |
| AM-3.3 | Entrar en la API de administración | Sesión con token Bearer en Redis | **ausente** | `server/crates/aegis-server/src/api.rs` | **Crítico.** `abrir_sesion` emite sesión a cualquier usuario no vacío, sin credenciales. Solo lo contiene que escuche en `127.0.0.1` por defecto |
| AM-3.4 | Escuchar o alterar la API en tránsito | TLS en la API | **ausente** | `server/crates/aegis-server/src/config.rs` | La API sirve HTTP plano; hace falta TLS propio o terminación declarada |
| AM-3.5 | Cosechar tráfico para descifrarlo en el futuro | Capa post-cuántica híbrida | **parcial** | `server/crates/aegis-server/src/pqc.rs` | El servidor la enlaza; no está ejercida de extremo a extremo con un agente real |
| AM-3.6 | Atacar al agente por la red | El agente no abre puertos; control solo por socket Unix `0600` | **existente** | `crates/aegis-ctl/src/lib.rs` | — |
| AM-3.7 | Inyectar órdenes por la malla o el enjambre | Quórum de K testigos; el enjambre transporta autoridad, no la concede | **no-aplica** | — | Malla y enjambre no se instalan |
| AM-3.8 | Inundar la ingesta del servidor | Cuotas por inquilino | **ausente** | — | `aegis-pipeline` es biblioteca: el servidor no la enlaza |

## AM-4 · Operador del SOC malicioso, o sesión robada

| ID | Amenaza | Control | Estado | Evidencia | Plan |
|---|---|---|---|---|---|
| AM-4.1 | Aislar o matar en masa | RBAC por acción y frenos de automatización | **ausente** | — | `aegis-consola` (RBAC) y `aegis-flujo` (frenos) no están conectados al servidor |
| AM-4.2 | Actuar sin dejar rastro atribuible | Registro de cada acción sobre un endpoint con su usuario | **parcial** | `server/crates/aegis-server/src/api.rs` | Se registra, pero el usuario no está autenticado (AM-3.3): la atribución se puede falsificar |
| AM-4.3 | Ver datos de otro inquilino | Aislamiento por flota en la base de datos | **parcial** | `server/crates/aegis-server/tests/escala_real.rs` | El aislamiento ligado a la sesión (`aegis-consola`) no está conectado |
| AM-4.4 | Sacar datos por una exportación | Un único juez de difusión (TLP/PAP) | **ausente** | — | `aegis-share` no lo enlaza el servidor |
| AM-4.5 | Alterar la historia de un caso | Rastro de caso encadenado | **parcial** | `server/crates/aegis-server/src/casos.rs` | Sin anclaje externo del encadenado en el camino instalado |

## AM-5 · Contenido de detección envenenado

| ID | Amenaza | Control | Estado | Evidencia | Plan |
|---|---|---|---|---|---|
| AM-5.1 | Vaciar o recortar las reglas del agente | Reglas empotradas y recuento comprobado al arrancar | **existente** | `crates/aegis-scan/src/rules.rs` | — |
| AM-5.2 | Regla maliciosa creada desde la consola | Validación en la cara del operador | **parcial** | `server/crates/aegis-server/src/api.rs` | Las reglas no llegan a ningún agente hoy; al conectarlas, exigir firma y procedencia |
| AM-5.3 | Actualización de reglas o binarios falsificada | Firma híbrida y procedencia verificada antes de aplicar | **ausente** | — | `aegis-update` y `aegis-procedencia` no los invoca ningún instalable: hoy no hay canal de actualización |
| AM-5.4 | Modelo de ML envenenado | Modelo empotrado | **no-aplica** | `crates/aegis-agent/src/edge_ml.rs` | El modelo no se invoca en el bucle del agente (ver matriz); al integrarlo, documentar su procedencia de entrenamiento |

## Lo más grave, en orden

1. **AM-3.3** — la API de administración no autentica. Cualquiera que la alcance
   puede aislar equipos.
2. **AM-4.1** — no hay RBAC ni frenos en el camino instalado.
3. **AM-1.2 / AM-1.3** — un root puede colgar o cegar al agente sin que nada lo note.
4. **AM-5.3** — no hay canal de actualización firmado; el agente no se actualiza.

## Historial

| Versión | Fase | Cambio |
|---|---|---|
| 1 | FASE 0 (MP-15) | Primera versión, sobre lo instalado a fecha del commit de la fase. |
