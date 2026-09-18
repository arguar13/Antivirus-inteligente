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

**Sobre `unsafe` en Rust.** «Cero `unsafe`» sería mentira: hay código del agente
cuyo trabajo *es* hablar con el kernel —`ioctl`, `mmap`, mapas de eBPF, memoria
compartida, memoria ajena— y prohibírselo no haría el producto más seguro, lo
haría imposible. La invariante que sí es cierta, y que `make ci` comprueba, no
admite tercera opción:

> Todo crate del agente **o** declara `#![forbid(unsafe_code)]` —y entonces lo
> impone el compilador— **o** está en
> [`tools/lineabase-unsafe.txt`](../tools/lineabase-unsafe.txt) con su razón
> escrita.

Un lado lo impone el compilador; el otro, la revisión. Un crate que se cuele sin
ninguna de las dos cosas hace fallar `tools/verificar-invariantes.sh`.

El `unsafe` se concentra a propósito: `aegis-ipc` (memoria compartida del anillo
Ring 0 ↔ Ring 3) y `aegis-scal` (la capa de abstracción del núcleo del sistema —
si no estuviera ahí, estaría repartido por veinte crates). Donde de verdad importa
—lo que **mira entrada que escribe un atacante**— no hay ninguno: ahí un `unsafe`
no es una decisión de rendimiento, es una corrupción de memoria en el camino por
el que entra lo hostil, en un proceso privilegiado, en cien mil máquinas.

La línea base funciona también al revés: si un crate declarado deja de necesitar
`unsafe`, la puerta lo dice y pide que se le ponga el `forbid`. Una lista de
excepciones que sólo crece deja de ser una lista de excepciones.

### Dependencias

Cada dependencia de terceros es superficie de ataque de cadena de suministro en
un producto de seguridad. En el agente eso no es una frase: es código de un
tercero que acabará ejecutándose **con privilegios en cada máquina de la flota**.

La lista completa, con una justificación por crate, vive en
[`tools/lineabase-agente.txt`](../tools/lineabase-agente.txt) y la comprueba
`tools/verificar-invariantes.sh`: **una dependencia directa sin justificación
escrita hace fallar `make ci`**, y la fila se añade *antes* que la dependencia.

Hoy son **39 dependencias directas** en el workspace del agente. Las que más
dicen del criterio:

| Crate | Uso | Por qué se acepta |
|---|---|---|
| `yara-x` | Motor de firmas | Rust puro; la alternativa —`libyara` en C— procesaría ficheros hostiles dentro del proceso privilegiado |
| `tract-onnx` | Inferencia ONNX | Rust puro; `onnxruntime` es C++ y arrastraría un árbol que no cabe en el presupuesto del endpoint |
| `rustls` | TLS | Sin OpenSSL: el árbol de una biblioteca en C con esa superficie no cabe en un agente privilegiado |
| `libbpf-rs` / `libbpf-sys` | eBPF CO-RE | El verificador y BTF están construidos alrededor de libbpf; reimplementarla sería el proyecto entero |
| `ml-dsa`, `libcrux-ml-kem` | Post-cuántico | La mitad post-cuántica del par híbrido de firma (ML-DSA-65) y de KEM (ML-KEM-768) |
| `libc` | Llamadas al sistema | Las syscalls **son** el trabajo del agente; escribirlas a mano sería reimplementar la libc con menos revisiones |
| `tokio` | **Sólo en `aegis-firehose`** | Es el proceso de salida a SIEM, **no** el colector privilegiado: el agente de detección sigue siendo síncrono |

Se rechaza lo que no quepa en esa lógica, y el ejemplo que más se cita aquí es
**libp2p**: sus 340 crates y su runtime asíncrono no entran en un agente
privilegiado cuyo presupuesto en reposo en una pasarela son 48 MiB, así que el
transporte del enjambre vive en un workspace **aparte** (`swarm-net/`) y `make ci`
lo comprueba con `cargo tree`. El núcleo del protocolo, que es lo que el endpoint
necesita, es *sans-io* y no depende de nada de eso.

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
shared/include/aegis_abi.h    Contrato ABI Ring 0 <-> Ring 3. Fuente de verdad, en C.
crates/                       Workspace del AGENTE: sincrono, panic=abort, 57 crates
server/crates/                Workspace del PLANO DE CONTROL: tokio/axum/sqlx, 13 crates
swarm-net/                    Transporte libp2p del enjambre, FUERA del agente a proposito
drivers/linux/aegis-bpf/      Sondas eBPF CO-RE + filtro XDP (C, libbpf)
kernel/windows/aegis/         Minifilter + ObCallbacks + politica (C, WDK)
deploy/terraform/             Aprovisionamiento del plano de control
tools/                        31 puertas de verificacion + ABI check + CI local
docs/                         Una pagina por fase
```

La tabla de componentes con el estado real de cada crate —qué hace, cuántas
pruebas tiene, qué puerta lo verifica y si lleva `#![forbid(unsafe_code)]`— vive
en el [README](../README.md#componentes-con-su-estado-real), que es donde la
busca quien llega al repositorio. Aquí se repetiría y se quedaría vieja.

## 6.4 Hoja de ruta

Cada fase tiene **criterios de salida medibles**. Una fase no se cierra por
calendario; se cierra cuando sus números se cumplen.

Las seis que siguen son el **plan original**, y están hechas. El estado real del
proyecto —ochenta y tres fases, con lo que eso cambió— está en
[«Dónde está el proyecto hoy»](#dónde-está-el-proyecto-hoy), al final de esta
sección.

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

### Dónde está el proyecto hoy

Las cinco fases de arriba son el **plan original**, y están hechas. Lo que vino
después no estaba en ese plan: ochenta y una fases numeradas, cada una con sus
criterios de salida medibles y su puerta en `make ci`. El recuento de hoy:

| | |
|---|---|
| Crates propios | **70** (57 en el agente, 13 en el plano de control) |
| Pruebas | **3 126** (2 155 + 971) |
| Puertas de verificación | **31**, todas en `make ci` |
| Dependencias directas del agente | **39**, cada una justificada por escrito |
| Crates del agente con `forbid(unsafe_code)` | **35**; los otros 22, declarados con su razón |

Las tres últimas fases son las que cambian la naturaleza del conjunto:

- **AegisFabric (79)** convierte nueve subsistemas en un producto: un modelo de
  entidad único, una escala única y un árbitro único, con un circuito que
  encadena once subsistemas sobre **un solo identificador**. Es la única ventaja
  de este diseño que no se puede copiar comprando: un conjunto de productos
  integrados no puede darla porque cada uno nombra las cosas a su manera.
- **AegisProof (80)** demuestra que las invariantes siguen en pie sobre el
  producto completo, y tiene derecho de veto sobre el resto.
- **AegisState (81)** le da a AegisQL el estado sobre el que correr: de cinco
  tablas a **52**, con el coste declarado por tabla y —lo que de verdad la
  separa de osquery— un **motivo** cuando una tabla no se puede leer, en vez de
  filas vacías que en un informe se leen como una máquina limpia.

### Lo que falta para producción

Nada de esto depende de escribir más detección:

```
Certificación EV + Partner Center + ELAM ──── 6-12 meses, y no depende de nosotros
Driver de Windows en Driver Verifier ──────── continuo
Piloto de 1.000 endpoints, 30 días ────────── tras la certificación
```

Los trámites arrancan el día 1 precisamente porque su duración no la controlamos
y es comparable a la del desarrollo entero.

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
| `cargo fmt --check` (los **dos** workspaces) | Cada push | Sí |
| `cargo clippy --all-targets -- -D warnings` (los dos) | Cada push | Sí |
| `cargo test` (los dos) | Cada push | Sí |
| `tools/abi-check.sh` (layout C ↔ Rust) | Cada push | Sí |
| Las 28 puertas de fase `tools/verificar-*.sh` | Cada push | Sí |
| **`tools/verificar-invariantes.sh`** (las trece) | Cada push | Sí, **con derecho de veto** |
| `cargo deny` + `cargo audit` | Cada push | Sí |
| Compilación del driver + Driver Verifier | Diario | Sí |
| `tests/redteam/` en VM efímera | Diario | Sí |
| Corpus benigno de falsos positivos | Antes de cada publicación | Sí, con cero tolerancia |
| 72 h de estabilidad | Antes de cada publicación | Sí |

El presupuesto de recursos ya no es una comprobación diaria aparte: entra en cada
push como la **primera** de las trece invariantes, y no contra una cuota fija sino
contra el reparto por clase de host de `aegis-presupuesto`, con la huella de
arranque —32 MiB medidos— como regresión dura.

La fila que define el proyecto es `verificar-invariantes.sh`: no comprueba una
fase, comprueba **el producto completo**, y si demuestra que una invariante se
rompió se arregla *de raíz* antes de dar el trabajo por terminado, aunque obligue
a volver sobre una fase anterior. Una invariante que se relaja «sólo esta vez»
deja de ser una invariante y pasa a ser una aspiración.

`tests/redteam/` es el conjunto de pruebas que más valor aporta: reproduce
técnicas ofensivas conocidas (inyección, *hollowing*, syscalls directos,
persistencia, simulación de ransomware) contra el producto real en una VM
efímera. Una técnica que deja de detectarse rompe la build igual que un test
unitario, que es la única forma de que la cobertura de detección no se erosione
en silencio con el tiempo.

---

← Volver al [README](../README.md)
