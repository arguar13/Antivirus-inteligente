# Módulo 6 — Stack tecnológico y hoja de ruta

---

## 6.1 Elección de lenguajes

| Subsistema | Lenguaje | Por qué ese, y no otro |
|---|---|---|
| `aegis-drv` (Windows Ring 0) | **C** (WDK) | El WDK es C. C++ en kernel arrastra manejo de excepciones y RTTI que no existen ahí; Rust en kernel de Windows no tiene soporte de producción para minifilters. No hay elección real, y pretender lo contrario sería un riesgo mal calculado |
| `aegis-bpf` (Linux Ring 0) | **C** (libbpf CO-RE) | El verificador eBPF y el ecosistema BTF están construidos alrededor de C. `aya` (Rust) es prometedor pero su cobertura de LSM es incompleta |
| `aegis-agent`, `aegis-scan`, `aegis-resp` | **Rust** | Parsea entrada hostil (PE de atacante, memoria de procesos comprometidos) con privilegios altos. Un desbordamiento aquí compromete el EDR. Sin GC, así que no hay pausas impredecibles en la ruta de veredicto |
| `aegis-ui` | **Rust + Tauri v2** | ~5 MB frente a los ~150 MB de Electron, y sobre todo: comparte tipos con el agente, así que la UI no puede desincronizarse del modelo de datos |
| `cloud/*` | **Go** | Servicio de red con mucha concurrencia y despliegue trivial. La recolección de basura es irrelevante en un servicio HTTP; en el endpoint habría sido descalificante |
| Entrenamiento ML | **Python** | Solo offline. Al endpoint llega un ONNX, nunca un intérprete de Python |
| Ensamblador | **Solo donde no hay alternativa** | Trampolines del *instrumentation callback* y lectura de registros de control. Cada línea documentada y aislada en su propio módulo |

**Sobre `unsafe` en Rust.** Los crates de lógica llevan `#![forbid(unsafe_code)]`.
El `unsafe` se concentra en `aegis-ipc` (memoria compartida) y en los crates de
FFI con el sistema operativo, donde cada bloque tiene su comentario `// SAFETY:`
justificando la invariante. La disciplina es que `unsafe` sea auditable en una
tarde, no que no exista.

### Dependencias

Cada dependencia de terceros es superficie de ataque de cadena de suministro en
un producto de seguridad. Lista corta y justificada:

| Crate | Uso | Por qué se acepta |
|---|---|---|
| `yara-x` | Motor de firmas | Mantenido por VirusTotal, Rust puro |
| `ort` | ONNX Runtime | Envoltorio sobre una biblioteca de Microsoft ampliamente auditada |
| `ring` / `aws-lc-rs` | AES-GCM, HKDF, Ed25519 | Criptografía auditada; implementarla nosotros sería irresponsable |
| `arc-swap` | Recarga de reglas sin lock | Pequeño y sin dependencias |
| `windows-rs` | Enlaces a la API de Windows | Oficial de Microsoft |

Se rechazan: cualquier crate con más de tres niveles de dependencias
transitivas, cualquiera sin publicaciones en 12 meses, y cualquiera que traiga un
runtime asíncrono al agente (el agente usa hilos y canales; `tokio` está solo en
el lado de la nube).

`cargo-deny` y `cargo-audit` en CI, con bloqueo por fallo.

---

## 6.2 Comunicación entre subsistemas

| Enlace | Mecanismo | Formato | Autenticación |
|---|---|---|---|
| Driver → Agente (telemetría) | Memoria compartida SPSC | `aegis_abi.h` binario | Puerto de filtro con descriptor de seguridad; solo el proceso PPL conecta |
| Driver ↔ Agente (veredicto) | `FltSendMessage` (llamada invertida) | `aegis_verdict_t` | Idem |
| Agente ↔ Scan/Resp | Canales `mpsc` en proceso | Tipos Rust | N/A |
| UI → Agente | Named pipe con ACL / socket unix 0600 | JSON-RPC 2.0 | Token del usuario; toda acción pasa por autorización |
| Agente → Nube | HTTPS 1.3 + ECH | JSON comprimido | Sin identidad de cliente, por diseño |
| Actualizaciones → Agente | Descarga + verificación local | Paquete firmado Ed25519 | Firma verificada antes de cargar |

**La UI nunca decide.** Propone acciones al agente, que las autoriza. Si la UI
pudiera ordenar «restaurar de cuarentena» directamente, comprometerla equivaldría
a desactivar el producto, y la UI es el componente con más superficie de ataque
(renderiza contenido, corre en la sesión del usuario).

---

## 6.3 Estructura del repositorio

```
shared/include/aegis_abi.h      Contrato ABI. Fuente de verdad, en C.
crates/
  aegis-ipc/                    Espejo Rust + consumidor del ring        [HECHO]
  aegis-agent/                  Servicio: colector, grafo, árbitro
  aegis-scan/                   YARA-X, ONNX, analizador PE/ELF, memoria
  aegis-resp/                   WFP, cuarentena, rollback
  aegis-sys-win/                FFI de Windows (unsafe aislado aquí)
  aegis-sys-linux/              FFI de Linux  (unsafe aislado aquí)
  aegis-ui/                     Tauri v2
drivers/
  windows/aegis-drv/            Minifilter + callbacks + WFP callout
  windows/aegis-elam/           Driver ELAM
  linux/aegis-bpf/              Programas eBPF CO-RE + cargador
cloud/
  api/                          Reputación k-anónima (Go)
  sandbox/                      Orquestador Firecracker (Go)
ml/
  training/                     Entrenamiento offline (Python)
  features/                     Extractor de referencia, espejo del de Rust
tools/
  abi-check.sh                  Verificación cruzada de layout C <-> Rust
  bench/                        Pruebas de carga y presupuesto de recursos
tests/
  redteam/                      Reproducción de técnicas ofensivas conocidas
docs/                           Este blueprint
```

---

## 6.4 Hoja de ruta

Cada fase tiene **criterios de salida medibles**. Una fase no se cierra por
calendario; se cierra cuando sus números se cumplen.

### Fase 0 — Contrato ABI · **completada**

Formato binario Ring 0 ↔ Ring 3, consumidor del ring y verificación cruzada de
layout entre C y Rust. Se hizo primero porque es lo que ambos lados necesitan
acordar antes de poder desarrollarse en paralelo.

**Estado:** 11 pruebas en verde, 104 entradas de layout verificadas.

---

### Fase 1 — MVP en Linux · ~3 meses

**Linux primero, y la razón no es técnica sino de calendario.** Windows exige un
certificado EV, firma por atestación de Microsoft y un certificado ELAM: entre
seis y doce meses de trámites con Microsoft antes de que un driver cargue en una
máquina que no esté en modo de pruebas. Empezar por Windows significa tres meses
de equipo parado esperando papeles.

En Linux, un programa eBPF se carga en segundos. La lógica de detección —que es
el 70 % del valor del producto— se desarrolla, se prueba y se itera de verdad,
y llega a Windows ya madura.

**Alcance**
- `aegis-bpf`: telemetría de procesos, ficheros e imágenes por eBPF CO-RE.
- Cargador con `libbpf-rs` y adaptador del ring hacia `aegis-ipc`.
- `aegis-agent`: colector, grafo de procesos con *taints*.
- `aegis-scan`: YARA-X con recarga en caliente.
- CLI (aún sin GUI).

**Criterios de salida**
- 10.000 eventos/s sostenidos con < 3 % de CPU en 4 núcleos.
- Cero eventos perdidos durante `kernel build -j8` (la carga de E/S más dura).
- < 25 MB RSS con 500 procesos vivos.
- Detección de las 20 técnicas de `tests/redteam/` que son observables solo con
  telemetría.
- 72 h de ejecución continua sin fugas (RSS estable ±2 %).

**Fuera de alcance a propósito:** ML, GUI, nube, respuesta. Solo telemetría y
firmas.

**En paralelo, desde el día 1:** iniciar la solicitud del certificado EV, la
cuenta de Partner Center y la petición del certificado ELAM. Es el camino
crítico del proyecto entero.

---

### Fase 2 — Detección y respuesta en Linux · ~3 meses

**Alcance**
- Modelo ML: extractor de características, entrenamiento, exportación a ONNX
  int8, inferencia en el agente.
- Motor de reglas conductuales con ventanas deslizantes y decaimiento.
- Mitigación de ransomware: ficheros señuelo, entropía, contención.
- `aegis-resp`: cuarentena AES-256-GCM, rollback copy-on-write, aislamiento de
  red por cgroup.
- GUI mínima en Tauri.

**Criterios de salida**
- FPR ≤ 10⁻⁵ sobre un corpus benigno de 500.000 ficheros, en el umbral de
  bloqueo.
- Detección ≥ 95 % sobre un conjunto de validación de malware ELF reciente.
- Inferencia < 1 ms p99.
- Ransomware simulado detenido con < 20 ficheros cifrados y **100 % de
  restauración** desde el almacén de sombra.
- Restauración desde cuarentena bit a bit idéntica, permisos y `xattr` incluidos.

---

### Fase 3 — Windows Ring 3 y Ring 0 · ~5 meses

**Alcance**
- `aegis-drv`: minifilter, callbacks de proceso/hilo/imagen/registro.
- Memoria compartida por MDL y canal de veredicto por llamada invertida.
- Portado del agente y de los motores (la lógica ya está probada en Linux).
- Escáner de memoria: código flotante, *hollowing*, *module stomping*.
- Callout WFP para aislamiento, incluido el aborto de flujos establecidos.

**Criterios de salida**
- Driver Verifier limpio con Special Pool, IRQL checking, Low Resources
  Simulation y Deadlock Detection, durante 24 h de carga.
- Cero BSOD en 30 días × 50 máquinas de prueba.
- `IRP_MJ_CREATE` con acierto de caché < 5 µs p99.
- Arranque del sistema no se degrada más de 500 ms.
- Detección de las 40 técnicas de `tests/redteam/` en Windows.

**Riesgo principal:** el escáner de memoria de Windows es lo más caro y frágil
del proyecto. Se aísla en su propio crate con superficie estrecha, para poder
desactivarlo en producción sin tocar el resto.

---

### Fase 4 — Autodefensa y arranque protegido · ~3 meses

Depende de los certificados solicitados en la fase 1. Si llegan tarde, esta fase
se desplaza; nada más depende de ella, y por eso está aislada aquí.

**Alcance**
- Driver ELAM con recurso `MSElamCertInfoID` y callback de clasificación.
- Servicio como PPL-Antimalware.
- Consumo de ETW-Ti: inyección entre procesos y syscalls anómalos.
- `ObRegisterCallbacks` con recorte de derechos; anti-descarga; protección de
  ficheros y claves propios.
- *Instrumentation callback* selectivo para syscalls indirectos.
- Firma por atestación / WHQL.

**Criterios de salida**
- El agente sobrevive a `taskkill /f`, `PROCESS_TERMINATE` desde SYSTEM con
  `SeDebugPrivilege`, borrado de servicio y `Start=4` en el registro.
- El driver ELAM clasifica drivers de arranque sin impedir el arranque con
  drivers de terceros legítimos.
- Detección de syscall directo e indirecto en `tests/redteam/`.
- El desinstalador legítimo funciona sin dejar restos.

---

### Fase 5 — Nube, escala y producción · ~4 meses

**Alcance**
- `cloud/api`: reputación k-anónima, con corpus y caché de borde.
- `cloud/sandbox`: orquestación de Firecracker, INetSim, informes.
- Canal de actualización firmado con despliegue por fases y reversión
  automática.
- Telemetría de salud de flota y consola de administración.
- Documentación, instaladores, soporte.

**Criterios de salida**
- Consulta de reputación < 100 ms p95 desde tres regiones.
- Sandbox: 1.000 muestras/hora por nodo.
- Despliegue por fases con reversión automática verificada en simulacro.
- 1.000 endpoints piloto durante 30 días con < 1 falso positivo por cada 100
  endpoints/mes.

---

### Camino crítico

```
Fase 1 ──── Fase 2 ──── Fase 3 ──── Fase 4 ──── Fase 5
  │                                    ▲
  └─ Trámites de certificación ────────┘
     (EV, Partner Center, ELAM: 6-12 meses)
```

Los trámites arrancan el día 1 precisamente porque su duración es comparable a la
de las fases 1 a 3 juntas y no depende de nosotros. Total estimado: **~18 meses**
hasta producción.

---

## 6.5 Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Certificado ELAM denegado o retrasado | Sin PPL ni ETW-Ti: se pierde la detección de inyección | Iniciar el día 1. Plan B: producto sin PPL, documentando la degradación |
| BSOD en producción | Catastrófico, irrecuperable en reputación | Driver Verifier en CI, despliegue por fases, interruptor remoto que desactiva el driver sin desinstalar |
| Falsos positivos masivos por una actualización | Flota inutilizada | Validación contra corpus benigno, despliegue 1 %→10 %→100 %, parada automática a 3σ, reversión sin red |
| Evasión por técnica nueva | Pérdida de detección | Defensa en capas: ningún vector depende de un solo motor |
| Coste de la nube por muestras | Presupuesto | Cuotas por cliente, deduplicación por hash, muestreo |
| Rotura de la API interna de Windows | El driver deja de compilar o funcionar | Solo API documentada. Ninguna estructura no documentada ni desplazamiento fijo en `EPROCESS` |
| Deriva del ABI entre driver y agente | Telemetría corrupta silenciosa | `tools/abi-check.sh` obligatorio en CI, ya implementado |

La fila más importante es la última entrada de la columna de mitigaciones de
BSOD: **el interruptor remoto**. Un EDR que solo se puede desactivar
desinstalándolo obliga a tocar máquina por máquina el día que su driver rompe el
arranque.

---

## 6.6 Integración continua

| Comprobación | Cuándo | Bloquea |
|---|---|---|
| `cargo test` (workspace) | Cada push | Sí |
| `cargo clippy -- -D warnings` | Cada push | Sí |
| `tools/abi-check.sh` | Cada push | Sí |
| `cargo deny` + `cargo audit` | Cada push | Sí |
| Compilación del driver + Driver Verifier | Diario | Sí |
| `tests/redteam/` en VM efímera | Diario | Sí |
| Presupuesto de recursos (`tools/bench/`) | Diario | Sí, si se supera el 110 % de la cuota |
| Corpus benigno de falsos positivos | Antes de cada publicación | Sí, con cero tolerancia |
| 72 h de estabilidad | Antes de cada publicación | Sí |

`tests/redteam/` es el conjunto de pruebas que más valor aporta: reproduce
técnicas ofensivas conocidas (inyección, *hollowing*, syscalls directos,
persistencia, simulación de ransomware) contra el producto real en una VM
efímera. Una técnica que deja de detectarse rompe la build igual que un test
unitario, que es la única forma de que la cobertura de detección no se erosione
en silencio con el tiempo.

---

← Volver al [README](../README.md)
