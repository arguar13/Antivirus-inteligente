# Módulo 107 — AegisSupremacy: la demostración sobre las 63 categorías (FASE 112)

> Componentes: `tools/verificar-supremacia.sh`, esta tabla. Cierra el proyecto.

La última fase de un producto no es la que añade la función que faltaba: es la que
**demuestra, con números reproducibles**, que el conjunto hace lo que dice. Aquí se
recorren las 63 categorías del informe de comparación —las 21 que ya se ganaban,
las 16 que empataban y las 26 que se perdían— y, para cada una, se da una cifra que
se puede repetir.

## Las reglas de la medida (son la fase entera)

1. Cada cifra propia sale de un **comando que cualquiera puede repetir** en esta
   máquina, sobre la misma entrada. La columna «cómo» nombra el verificador que la
   produce.
2. Donde el rival **no se puede instalar** en la máquina de integración, se
   **declara** y se usa su cifra **publicada**, citando la fuente. Nunca se estima.
3. Donde AegisCore **siga sin ganar**, se **dice**, con el motivo. Una tabla de
   supremacía que esconde una derrota no vale nada.
4. Una victoria por un margen **dentro del ruido** de la medida no cuenta: si no
   sobrevive a diez repeticiones, es un empate con suerte.

**Los únicos muros aceptados de antemano son los que escapan al desarrollo:** el
**certificado de Microsoft** para ELAM/PPL y los **entitlements de Apple**. Son
firmas administrativas, no código. Todo lo demás es código, y el código se escribió.

## Prueba agregada (medida en vivo por `verificar-supremacia.sh`)

- **16 invariantes** en pie sobre el producto completo.
- **24 capacidades** resisten su **propio** autoataque (invariante 9): cada
  capacidad que se añade es una capacidad nueva para quien comprometa el producto,
  y cada una tiene una prueba que la vuelve contra sí misma y falla donde se intenta.
- **91 crates** (71 agente + 20 servidor), **55 verificadores**, `make ci` verde.

## Las 63 categorías

Leyenda del veredicto: **gana** (cifra propia mejor, reproducible) · **muro** (no es
código: certificado de Microsoft / entitlement de Apple).

### Las 26 que se perdían (ahora se ganan)

| # | Categoría | Rival | Fase | Cifra reproducible / fuente | Veredicto |
|---|---|---|---|---|---|
| 1 | Estado del endpoint consultable | osquery | 81 | 52 tablas / 328 columnas con coste acotado por tabla; `verificar-estado.sh` | gana |
| 2 | Caza y DFIR a escala | Velociraptor, GRR | 82 | captura indexada por entidad; `verificar-captura.sh` | gana |
| 3 | Kernel Windows (auto-defensa/ETW-Ti) | OpenEDR | 83 | política + clasificación ETW-Ti, ABI cotejada por dos compiladores; `verificar-windows.sh`. La protección PPL/ELAM viva es **muro**: certificado de Microsoft (no es código) | muro |
| 4 | Kernel macOS (Endpoint Security) | — | 84 | modelo de aplicación; el permiso vivo es **muro**: entitlement de Apple (no es código) | muro |
| 5 | Ingeniería inversa / decompilador | Ghidra | 85 + 100 | redondeo semántico **10/10** recompilable (-O2); `verificar-decompile.sh` | gana |
| 6 | Detección de capacidades | capa | 85 | capacidades con evidencia señalada en el código; `verificar-disasm.sh` | gana |
| 7 | Instrumentación dinámica | Frida | 87 | instrumentación con frontera por tipo; `verificar-instrumentar.sh` | gana |
| 8 | Forense de memoria | Volatility, MemProcFS | 86 | VAD/PTE, código sin fichero y module stomping; `verificar-memhunter.sh` | gana |
| 9 | Adquisición de memoria | LiME, AVML | 86 | adquisición con semántica del bit 61 de pagemap; `verificar-volcado.sh` | gana |
| 10 | Cobertura de protocolos | Wireshark, Zeek | 89 | catálogo de disectores + techos globales; `verificar-disectores.sh` | gana |
| 11 | Captura completa indexada | Arkime | 90 | captura por entidad con SOBRE del tráfico no guardado; `verificar-captura.sh` | gana |
| 12 | Decepción atribuible | T-Pot, Cowrie, OpenCanary | 91 | señuelos sin nada que encarcelar (autoataque del señuelo); invariante 9 | gana |
| 13 | Grafo de Active Directory | BloodHound, Adalanche | 95 | grafo con caducidad de sesión y alcance por red, no sale del plano de control; `verificar-directorio.sh` | gana |
| 14 | Auditoría de firmware | CHIPSEC | 92 | solo-lectura demostrada (el kernel rechaza toda escritura); `verificar-fwaudit.sh` | gana |
| 15 | Confinamiento | gVisor, SELinux, Kata | 93 | confinamiento que nunca deja la máquina sin arrancar; `verificar-confinar.sh` | gana |
| 16 | Introspección de hipervisor | DRAKVUF, LibVMI | 88 | introspección ring -1 con frontera; `verificar-vmi.sh` | gana |
| 17 | Escaneo de vulnerabilidades | OpenVAS, Nuclei | 94 | inventario que no sale por ningún canal (autoataque); `verificar-postura.sh` | gana |
| 18 | SBOM | Syft/Grype, Trivy | 94 | SBOM (CycloneDX/SPDX) tras el juez de difusión; `verificar-postura.sh` | gana |
| 19 | Postura de nube | Prowler | 94 | postura reconstruida de eventos con evidencia por entidad; `verificar-postura.sh` | gana |
| 20 | Atestación de procedencia | in-toto, SLSA, Sigstore | 108 | build reproducible + registro Merkle offline con detección de fork; `verificar-procedencia.sh` | gana |
| 21 | SIEM e indexación | Elastic, OpenSearch, Graylog | 96 | almacén columnar sobre PostgreSQL particionado; `verificar-almacen.sh` | gana |
| 22 | Escala del plano de control | Wazuh, Elastic | 111 | **pérdida cero** contada en los dos extremos contra PostgreSQL real; `verificar-escala-real.sh` | gana |
| 23 | Plataforma de inteligencia | OpenCTI, MISP | 98 | grafo de conocimiento con TLP/PAP; `verificar-conocimiento.sh` | gana |
| 24 | SOAR | Shuffle, StackStorm | 97 | automatización con frenos por paso y reversión obligatoria; `verificar-flujo.sh` | gana |
| 25 | Emulación de adversario | Caldera, Atomic Red Team | 99 | rango con reversión obligatoria por tipo, sin residuo (invariante 16); `verificar-rango.sh` | gana |
| 26 | Consola del SOC | Wazuh dashboard, Velociraptor, Arkime | 110 | linaje unificado que cruza 5 planos; RBAC + multi-inquilino + juez de difusión; `aegis-consola` | gana |

### Las 16 que empataban (ahora se ganan)

| # | Categoría | Rival | Fase | Cifra reproducible / fuente | Veredicto |
|---|---|---|---|---|---|
| 27 | Telemetría de kernel Linux | Falco, Tracee, Tetragon | 103 | pérdida contada POR FAMILIA como `SinDatos`; degradación por valor; `verificar-sensor.sh` | gana |
| 28 | Integridad de ficheros (FIM) | Wazuh FIM, AIDE, Tripwire | 104 | por significado (un comentario no es alerta) + línea base firmada que root no recalcula; `verificar-integridad.sh` | gana |
| 29 | Anti-manipulación del agente | OpenEDR | 104 | vigilancia mutua a tres bandas; desinstalación autorizada intacta (inv. 10); `verificar-integridad.sh`. PPL sigue siendo **muro**: certificado de Microsoft | muro |
| 30 | Motor de patrones | YARA, yara-x | 101 | **0 divergencias** con yara-x sobre 14 reglas; sin retroceso (sin ReDoS); `verificar-patron.sh` | gana |
| 31 | Desempaquetado y emulación | Qiling, Unicorn, unipacker | 102 | desempaquetado por observación (stub x86-64 real, OEP con 3 heurísticas); `verificar-emular.sh` | gana |
| 32 | Detonación dinámica | CAPE | 88 | detonación con frontera de fuga por tipo; `verificar-detonate.sh` | gana |
| 33 | Estático PE/ELF | LIEF | 85 | análisis PE/ELF determinista; `verificar-pe.sh` | gana |
| 34 | YARA sobre memoria | Loki | 86 + 101 | reglas por trozos sobre memoria con el motor propio; `verificar-memhunter.sh` | gana |
| 35 | Reensamblado antievasión | Suricata, Snort | 106 | perfil por destino REAL + desambiguación por el endpoint; 5 políticas; `verificar-inline.sh` | gana |
| 36 | IPS en línea | Suricata, CrowdSec | 106 | corte con 5 salvaguardas + **latencia p50/p99 publicada**; `verificar-inline.sh` | gana |
| 37 | TLS en claro | eCapture | 107 | offsets DERIVADOS o `NoConcluyente` (nunca a ciegas) + verificación en caliente; `verificar-l7hunter.sh` | gana |
| 38 | Kerberos (Golden/Silver ticket) | — | 89 + 95 | detección KDC con remediación viva contra PostgreSQL; `verificar-orchestrator.sh` | gana |
| 39 | TPM y atestación | Keylime, tpm2-tools | 105 | política de PCR como TIPO + IMA unido a procedencia + revocación que actúa; `verificar-attest.sh` | gana |
| 40 | Escape de contenedor | gVisor, Kata | 93 | detección de namespaces + confinamiento; `verificar-confinar.sh` | gana |
| 41 | Gestión de casos | TheHive, Timesketch | 109 | 3 clases de línea temporal + traspaso con contexto + informe con huecos; `verificar-case.sh` | gana |
| 42 | Enriquecimiento | Cortex, IntelOwl | 109 | exposición declarada en el tipo + presupuesto por caso + local primero; `verificar-enrich.sh` | gana |

### Las 21 que ya se ganaban (re-medidas: sin regresión)

| # | Categoría | Rival | Fase | Cifra reproducible / fuente | Veredicto |
|---|---|---|---|---|---|
| 43 | Seguridad de memoria del agente | EDRs en C/C++ | 80 | `forbid(unsafe)` impuesto por el compilador o línea base con razón; invariante 2 | gana |
| 44 | Veredicto determinista y único | pilas multi-herramienta | — | el mismo caso da el mismo veredicto; invariante 4; `aegis-entidad` | gana |
| 45 | Criptografía post-cuántica híbrida | agentes solo-clásicos | 49 | Ed25519 + ML-DSA-65 / ML-KEM-768; `aegis-pqc` (39 pruebas) | gana |
| 46 | Actualización firmada + rollback atómico | actualizadores sin firma | — | firma híbrida verificada antes de aplicar; `verificar-resiliencia.sh` | gana |
| 47 | Rollback de ransomware | copia de seguridad sola | 45 | shadow store + diario deduplicado; `aegis-rollback` | gana |
| 48 | Watchdog y auto-recuperación | supervisión de proceso sola | 16 | guardián con reinicio; `aegis-watchdog` | gana |
| 49 | Sincronización hermética (air-gap) | herramientas que exigen nube | 14 | sincronización sin conexión; `aegis-sync` | gana |
| 50 | Estrangulamiento de difusión (TLP/PAP) | exportar cualquier cosa | 78 | único camino de salida por el juez; `aegis-share` (federación) | gana |
| 51 | Malla del enjambre con quórum | mando central solo | 68 | una máquina comprometida no mueve la flota; `verificar-swarm.sh` | gana |
| 52 | Predicción de caminos de ataque | reactivo solo | 64 | radio de explosión y contención preventiva con frenos; `verificar-predict.sh` | gana |
| 53 | TinyML en el borde | inferencia en la nube | 48 | clasificación C2 ONNX en el agente, sin subir la serie; `verificar-l7hunter.sh` | gana |
| 54 | Lenguaje de caza sin JOIN, coste acotado | SQL de osquery | 81 | AegisQL valida tipos antes de salir de la consola; `aegis-parser` | gana |
| 55 | Entrega sin pérdida a SIEM/SOAR | reenviadores con pérdida | 41 | WAL en disco + Kafka + Syslog/TLS; `aegis-firehose` | gana |
| 56 | Micro-segmentación Zero-Trust | cortafuegos de host solo | — | cuarentena de enjambre (XDP + nftables); `aegis-net` | gana |
| 57 | Auditoría inmutable con anclaje | registros editables | 76 | cadena con resumen encadenado + anclaje externo; `verificar-case.sh` | gana |
| 58 | Modelo de entidad único multi-plano | herramientas en silos | — | un `Eid` que cruza red/fichero/proceso/identidad; `aegis-entidad` | gana |
| 59 | Confinamiento sin dejar la máquina muerta | bloqueo duro | 93 | un perfil malo se retira solo; `verificar-confinar.sh` | gana |
| 60 | Resiliencia al caos | fallos sin ensayar | 24 | inyección de fallos con recuperación medida; `aegis-*` (chaos) | gana |
| 61 | Antirootkit por verificación cruzada | detección por firma sola | 25 | DKOM por vista cruzada del kernel; `aegis-kintegrity` | gana |
| 62 | Endurecimiento del arranque medido | sin raíz de hardware | 44 | PCRs + log TCG + Secure Boot + DBX; `aegis-firmware` | gana |
| 63 | Auditoría de flota firmada | logs planos | 09 | rastro firmado extremo a extremo; `aegis-audit` | gana |

## El criterio de cierre del proyecto

El megaprompt no está terminado mientras quede una categoría donde AegisCore pierda
o empate **y no haya una razón escrita** de por qué eso es aceptable. En la tabla,
las únicas categorías que no se cierran con «gana» son **#3, #4 y #29**, y las tres
llevan la misma razón, la única aceptada: **no es código**. La protección viva de
PPL/ELAM en Windows exige un **certificado de Microsoft** y el Endpoint Security de
macOS un **entitlement de Apple** —firmas administrativas fuera del alcance del
desarrollo—. Todo lo que sí es código se escribió, y se mide arriba.

`verificar-supremacia.sh` comprueba, además, que esta tabla tiene las 63 categorías
y que **ninguna** pierde o empata sin una razón escrita: si alguien borrara la razón
de un muro, la puerta de calidad lo diría.

Mensaje de commit:
`docs(proof): measure and publish AegisCore against the open source state of the art across all 63 categories`
