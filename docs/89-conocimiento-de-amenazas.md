# AegisKnowledge — el conocimiento de amenazas, unido a lo observado

**FASE 98.** Crate nuevo `server/crates/aegis-conocimiento`; `aegis-share` ampliado
(lector por objetos `Paquete::recorrer`, marcado declarado por el operador).
Tablas de relaciones en `server/crates/aegis-conocimiento/datos/`, regeneradas
por `tools/tablas-stix.py`. Puerta: `tools/verificar-conocimiento.sh` (grupo
`conocimiento` de `tools/ci-local.sh`). La invariante **11** («un solo
estrangulamiento») cubre ahora también la salida del conocimiento.

## La pregunta

OpenCTI y MISP modelan el conocimiento y lo relacionan. Pero un actor, en ellos,
es una ficha: lo que se sabe de él. La pregunta de esta fase es otra: **¿qué he
visto yo de este actor?** Aquí las dos preguntas tienen la misma respuesta porque
son el mismo recorrido del mismo grafo: `Grafo::alrededor(actor, saltos)` devuelve
los objetos del conocimiento **y**, en la misma estructura, las entidades de este
despliegue que los sostienen.

## El inventario de partida

| Pieza | Qué había | Qué faltaba |
|---|---|---|
| `aegis-share::stix` | los 19 SDO, las SRO, validación estricta, ida y vuelta por `crudo` | un paquete de más de 8 MiB (ATT&CK son 53 MB) no entraba, y el tope no se debe subir |
| `aegis-share::procedencia` (FASE 78) | ficha por objeto, confianza recalculada, revocación por fuente | nada que propagara la revocación a lo **deducido** |
| `aegis-share::difusion` | el juez único de salida | nada |
| `aegis-entidad` (FASE 79) | `cont:` por SHA-256, `cuenta:` | ningún puente de un observable STIX a una entidad |
| ATT&CK | 14 técnicas en `aegis-behavior` | el conocimiento entero |

## Lo que se construyó

### El grafo

- **Nodos:** todo objeto STIX, incluidos los 18 SCO y cualquier tipo que este nodo
  no conozca (se conserva igual: `x-mitre-*` entra, se recorre y sale intacto).
- **Aristas de dos clases:** las SRO (`relationship`), clasificadas frente al canon
  de la especificación, y **todas las embebidas**: cualquier `*_ref` o `*_refs` de
  cualquier objeto (`created_by_ref`, `object_refs`, `sighting_of_ref`,
  `resolves_to_refs`…). La especificación las llama relaciones (§3.3).
- **Versiones:** manda el `modified` más reciente; una versión anterior no pisa,
  pero su fuente queda en la procedencia.
- **Una relación fuera del vocabulario no se rechaza:** la especificación dice que
  `relationship_type` «SHOULD» ser uno de los definidos «but MAY be any string».
  Se clasifica (`Especificacion`, `Comun`, `Personalizada`) y se recorre igual.

### Las relaciones de STIX 2.1, sacadas de la especificación y no de memoria

`tools/tablas-stix.py` genera `relaciones-stix21.tsv` del **Apéndice B del PDF
normativo** (extraído con `pdftotext`) y del validador oficial de OASIS (commit
`d3ef2a5`), y marca la procedencia de cada fila. Donde discrepan manda lo que la
propia especificación declara autoritativo (las secciones de cada objeto):

- el Apéndice escribe `exfiltrate-to`; §4.11 dice `exfiltrates-to` → errata del
  Apéndice;
- `course-of-action remediates …` no está en el Apéndice pero sí en §4.3 → canon;
- `vulnerability impacts …` solo está en el validador y en ningún lugar del texto
  → **fuera del canon**, registrado.

Canon: **137 relaciones**. La puerta regenera las tablas desde las fuentes
fijadas y exige que salgan idénticas a las del repositorio.

### La unión con lo observado

Un `Observable` (SHA-256, dirección, dominio, URL, cuenta) se saca de un SCO por
su valor o del patrón de un indicador si es una igualdad simple (la misma regla
que el puente del enjambre: un patrón compuesto no se traduce a medias). Donde el
modelo único tiene clase, se nombra con **su `Eid`** —`cont:…` es el mismo
identificador que usan el almacén, el árbitro y los casos—; donde no la tiene
(una dirección no es una entidad del modelo, es un atributo de un flujo), por su
valor, y se dice. Cada avistamiento entra en la procedencia con la máquina que lo
vio como fuente: dos máquinas son dos testigos.

### Inferencia acotada y explicable

Regla única: si el conocimiento dice que un actor usa una capacidad (malware,
herramienta, infraestructura), y aquí se ha visto un observable que el
conocimiento asocia a esa capacidad, se **propone** «ese actor está activo aquí».

- **Acotada:** observado → quien lo declara → lo que indica o lo contiene → quien
  lo usa → como mucho **dos** `attributed-to` más.
- **Confianza:** la del eslabón **más débil**, **repartida entre las
  alternativas** (si veinte actores usan la misma herramienta, verla dice poco de
  cuál es) y rebajada un 20 % por atribución encadenada.
- **Explicable:** cada eslabón lleva su apoyo (objeto, relación u observación),
  su confianza recalculada y sus fuentes; `depende_de()` dice qué fuentes la
  tumbarían **solas**.
- **Rebatible:** `rebatir()` la comprueba contra el grafo de ahora y dice en qué
  eslabón cae y por qué.
- **La diferencia está en el tipo:** `Hipotesis` no es un `Objeto`. No compila
  meterla en el grafo (`E0308`) ni fabricarla (`E0451`). La única salida es
  `confirmar(autor, …)`: sin autor no sale, y lo que sale es un `sighting` de
  **esta** organización con la cadena en su descripción —«vimos esto»—, no una
  relación de atribución anónima —«X es responsable»—.

Con ATT&CK real y un indicador de Cobalt Strike visto en una máquina: 36
hipótesis, una por cada grupo o campaña que lo usa según MITRE, **cada una a
1/100**. Es la respuesta correcta: ver Cobalt Strike no dice quién es.

### Entrada y salida

- `importar` (un paquete), `importar_declarado` (una colección grande, objeto a
  objeto) y `sondear` (TAXII, agotando páginas).
- **El lector por objetos** (`aegis-share::Paquete::recorrer`): un analizador
  léxico trocea el documento siguiendo comillas, escapes y corchetes, y cada
  objeto se valida **por separado** con las mismas funciones que
  `Paquete::validar`. El tope de 8 MiB por paquete de red no se toca. Un
  objeto suelto tampoco puede pasar de 8 MiB, porque el mayor objeto real de
  ATT&CK (la `x-mitre-collection`, que enumera la colección entera) pesa 4,8 MB.
- **El marcado declarado:** ATT&CK es público por licencia pero no lleva TLP. Por
  la regla de lo desconocido se queda en `TLP:RED`, y eso es correcto: nadie ha
  dicho que se pueda compartir. `recorrer_declarado` recibe una `Declaracion`
  **con autor**, que solo rellena lo que cada objeto calla. Lo que el objeto dice
  siempre manda, y una marca que no resuelve sigue siendo RED.
- **Una sola salida:** `exportar` pasa por `Difusor::repartir` antes de construir
  el documento, y es el único sitio del crate que lo construye (comprobado por
  estructura en la puerta y en la invariante 11). Lo observado no son objetos del
  grafo y las hipótesis tampoco: no hay por dónde sacarlos.

## AUTOATAQUE: el conocimiento como vía de envenenamiento

`tests/envenenamiento.rs`:

1. Dos canales legítimos (un ISAC y un proveedor) aportan QakBot, su indicador y
   «FIN7 usa QakBot». Un canal abierto **repite** todo eso para parecer fiable e
   **inyecta** «Operación Nación-X usa QakBot». El hash se ve en tres máquinas.
2. **La procedencia la aísla:** salen las dos hipótesis, cada una con la otra como
   alternativa y ninguna por encima de 50/100. La falsa (10/100) dice «cae si se
   revoca solo: feed-abierto-x»; la legítima (36/100) no depende de él. La base
   informa de que 2 objetos dependen en exclusiva de ese canal.
3. **La revocación la revierte:** se retiran exactamente el actor inventado y la
   relación falsa; la hipótesis falsa cae al rebatirla y deja de proponerse.
4. **Sin tirar lo que sostenían los demás:** QakBot, el indicador, FIN7 y sus
   relaciones siguen en pie (con una fuente independiente menos), lo observado
   sigue, y la hipótesis legítima pasa de 36 a 73: sin la alternativa falsa gana
   la confianza que esta le quitaba.

## Ida y vuelta STIX 2.1, con datos reales

MITRE ATT&CK Enterprise, ICS y Mobile (commit de `attack-stix-data` del día):

| | |
|---|---|
| objetos | 30 894 (30 726 distintos: ICS y Mobile comparten 168 con Enterprise) |
| relaciones | 24 818; 21 377 dentro del canon, 3 411 personalizadas, todas conservadas |
| ida y vuelta por el lector | **idéntica** objeto a objeto en las tres colecciones |
| salida por el juez | salen 30 507; se retienen los 219 revocados por MITRE, con su motivo |
| releído lo exportado | **idéntico** objeto a objeto |
| TAXII | 2 500 objetos en 3 páginas, por el mismo `Difusor` |

## Comparativa medida con OpenCTI

**Medida contra su esquema de relaciones, no contra una instancia:** OpenCTI se
despliega con Docker, Elasticsearch, Redis, RabbitMQ y MinIO, y esta máquina no
tiene Docker. `tools/tablas-stix.py` lee su código fijado (commit `c4ca983`):
el mapeo central de `database/stix.ts` **y** las relaciones que declara cada
módulo (65 módulos las registran por su cuenta; la primera versión de la tabla,
solo con `stix.ts`, atribuía a OpenCTI carencias que no tiene, y se corrigió).
Cada constante se resuelve leyendo el fichero que la define: **545 relaciones**,
cero sin resolver.

| | AegisKnowledge | OpenCTI (esquema) |
|---|---|---|
| canon de STIX 2.1 (137) | 137: las recorre todas | **137**: las admite todas |
| relaciones fuera del canon | todas, clasificadas como personalizadas | 114 propias, cerradas en su esquema |
| relaciones cuyo extremo es otra relación | no (STIX lo prohíbe, §5.1.2) | 6 |
| relaciones reales de ATT&CK (24 818) | **24 818** conservadas y recorridas | **22 836 (92,0 %)** |

Las que el esquema de OpenCTI no admite tal cual: `revoked-by` (222),
`attack-pattern targets x-mitre-asset` (842, ICS) y
`x-mitre-detection-strategy detects attack-pattern` (918, el modelo de detección
de ATT&CK). Su conector de MITRE podría traducir parte de ello, y eso no se ha
medido.

**Conclusión honesta:** en cobertura del vocabulario es un **empate**, y OpenCTI
tiene además 114 extensiones propias. Lo que OpenCTI no tiene es lo de arriba:
la unión con lo observado en el mismo grafo, la ida y vuelta sin perder lo que no
entiende, la revocación por procedencia que se propaga a lo deducido y la
hipótesis como un tipo que no se puede hacer pasar por un hecho.

## El muro, declarado

- OpenCTI no se ha ejecutado: la comparativa es contra su esquema.
- El grafo vive en memoria del plano de control; su persistencia (hoy lo STIX de
  los agentes va a `stix_objetos`) no es parte de esta fase.
- Los patrones STIX compuestos no se unen con lo observado: se traducen solo las
  igualdades simples, por la misma razón que en el puente del enjambre.
