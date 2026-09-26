# AegisStore — el almacén y el lenguaje sobre el histórico

**FASE 96.** Crate nuevo `server/crates/aegis-almacen`; AegisQL del histórico en
`crates/aegis-parser` (`historico`, `esquema::historico`). Puerta:
`tools/verificar-almacen.sh` (grupo `almacen` de `tools/ci-local.sh`). Invariante
nueva: la **14**, «una consulta no tumba el almacén».

## La pregunta

Elastic, OpenSearch y Graylog indexan **documentos** y buscan por **texto**. Para
saber todo lo que pasó con un proceso hay que adivinar cómo se escribió su nombre
en cada fuente y unir por cadenas. Aquí el índice primario es la **entidad** del
modelo único (FASE 79): buscar `proc:…` devuelve sus filas de todas las tablas
—proceso, conexiones, ficheros, veredictos, casos— sin una sola unión por texto.
Y el lenguaje es AegisQL, **el mismo** que el analista usa contra el endpoint.

## El inventario de partida

| Pieza | Qué había | Qué faltaba |
|---|---|---|
| `aegis-parser` | AegisQL del endpoint: `SELECT … WHERE … ORDER BY … LIMIT`, `COUNT(*)` | ventanas, agregaciones, uniones y subconsultas — que el endpoint no debe tener |
| `aegis-estado` | coste declarado y tabla peligrosa rechazada **en el endpoint** | nada equivalente en el servidor |
| `aegis-scale` | el SQL de particiones mensuales, generado | nunca se había ejecutado contra PostgreSQL: el muro de la FASE 75 |
| filas del endpoint | la entidad de cada fila, fuera de banda | un sitio donde guardarla e indexarla |

## El lenguaje: el del endpoint no cambia

AegisQL corre con privilegios en cada máquina del cliente, y su gramática no
tiene `JOIN`, subconsultas ni agregaciones **a propósito**. Por eso las
extensiones son **solo del histórico, garantizado por tipo**:

- `sintaxis::analizar` produce `Consulta`, lo único que acepta el endpoint, y sigue
  rechazando todo lo nuevo.
- `historico::analizar` produce `ConsultaHistorica`. Su árbol de condiciones puede
  contener una subconsulta; el del endpoint **no puede ni representarla**.
- Las palabras nuevas (`DURING`, `GROUP`, `EVERY`, `LAST`, `SUM`…) son
  **contextuales**: no entran en el léxico que comparte el endpoint.
- Los predicados se analizan con **el mismo código** a través de un «ámbito», y
  una prueba exige que toda consulta del endpoint dé **el mismo árbol** por los
  dos caminos.

Lo que se añade: ventanas (`DURING LAST 24 HOURS`, `DURING 'desde' TO 'hasta'`),
agregaciones (`COUNT`, `SUM`, `MIN`, `MAX`, `AVG`) con `GROUP BY` y cubos de tiempo
(`GROUP BY EVERY 1 HOURS`), unión por entidad como subconsulta acotada (`entity IN
(SELECT entity FROM verdicts … LIMIT n)`, con `LIMIT` obligatorio y tope de 1 000),
y dos columnas en toda tabla: `ts` y `entity`. Una subconsulta sin ventana propia
**hereda** la de fuera.

## El almacén

| Pieza | Cómo |
|---|---|
| Partición | un día, con `PARTITION BY RANGE` real de PostgreSQL; la purga es `DROP TABLE` |
| Segmento | hasta 8 192 filas de una tabla; **cada columna en su propia fila** de PostgreSQL, así que una consulta lee solo las columnas que usa |
| Codificación por columna | enteros con delta, zigzag y *varint*; reales con XOR del anterior; texto con diccionario si se repite; booleanos en bits; mapa de presencia para lo **ausente**, que sobrevive al almacén |
| Compresión | deflate en Rust puro (`miniz_oxide`), rápido en caliente y máximo en tibio |
| Orden dentro del día | **por entidad y luego por tiempo** (ver «lo que encontró la fase») |
| Índice primario | (entidad, tiempo) → segmento, en la misma partición diaria |
| Índices secundarios | solo los **declarados**; un índice que nadie consulta es disco tirado |
| Retención | caliente → tibio (recompresión, sin secundarios) → frío (columnas a un fichero por día con CRC; en la base quedan metadatos e índice de entidad) → `DROP` |

**Coste declarado y plan rechazado.** Antes de descomprimir nada, el planificador
cuenta particiones, segmentos, filas y bytes de las columnas necesarias. Sin
filtro de tiempo ni de entidad, más de 7 días se rechazan; con o sin filtro, más
de 20 000 segmentos se rechazan. El rechazo dice cuánto habría leído y cómo
arreglarlo, con la ventana concreta. Y el único camino de lectura pasa por el
planificador: lo comprueba la invariante 14 por estructura.

**La misma semántica que el endpoint.** El filtro se evalúa con las reglas del
ejecutor del endpoint, incluida la lógica de dos valores: lo ausente no casa, y
por eso `NOT LIKE` y `NOT IN` sobre un ausente son ciertos.

## Lo que encontró la fase por el camino

| Defecto | Corrección |
|---|---|
| El analizador citaba un `validar_coste` en `crate::plan` que no existe | la referencia apunta a donde está de verdad el rechazo, `aegis_estado::coste::validar` |
| Segmentos cortados solo por tiempo: con 500 anfitriones cada segmento tenía a casi todos, y «todo de una entidad en 7 días» leía **272 de 273** segmentos por el índice | orden por (entidad, tiempo) dentro del día: **21 segmentos**, de 1 040 ms a **87 ms**, y el disco de 188 a **108 MiB** |
| Una subconsulta sin ventana se rechazaba aunque la de fuera estuviera acotada | hereda la ventana de fuera, resuelto en el árbol para que el coste declarado sea el real |

## Lo medido

Ubuntu 26.04 en WSL2, PostgreSQL 18.6 local, 8 núcleos. Conjunto sintético
determinista: **4 200 000 eventos**, 14 días, 500 anfitriones (autenticación,
procesos, red y hallazgos).

| Medida | Cifra |
|---|---|
| Ingesta | **284 000 eventos/s** (14,8 s) |
| Columnas | 283 MiB sin comprimir → **92 MiB** comprimidas |
| Disco en PostgreSQL (tablas, índices y TOAST) | **108 MiB** |
| Memoria máxima del proceso de ingesta | 214 MiB (incluye el generador y el lote en memoria) |

Las diez consultas de un SOC, mediana de cinco:

| Consulta | Latencia | Segmentos leídos | Vía |
|---|---:|---:|---|
| fallos de autenticación, 24 h | 98 ms | 39 | barrido |
| top anfitriones por fallos, 24 h | 94 ms | 39 | barrido |
| eventos por hora de un anfitrión, 24 h | 66 ms | 39 | barrido |
| **todo de una entidad, 7 días** | **87 ms** | 21 | índice de entidad |
| hallazgos críticos, 7 días | 974 ms | 273 | barrido |
| sesiones de sshd, 3 días | 197 ms | 117 | barrido |
| texto en el mensaje, 24 h | 244 ms | 39 | barrido |
| volumen por origen, 7 días | 739 ms | 273 | barrido |
| último evento por anfitrión, 1 día | 136 ms | 39 | barrido |
| **unión por entidad** (lo de quien tuvo un crítico), 1 día | **81 ms** | 3 | índice de entidad |
| la misma consulta **sin acotar**, 14 días | **1,1 ms** | 0 | **rechazada sin leer** |

Con PostgreSQL real, además, la prueba de paridad: **14 consultas de caza** sobre
la tabla real `users` de esta máquina devuelven **las mismas filas** por el
ejecutor real del endpoint y por el almacén.

## La comparación con OpenSearch

**No se ha hecho en esta fase, y se declara.** OpenSearch 3.8.0 está descargado y
verificado (SHA-512) en la máquina de integración, y el generador produce el
mismo conjunto de datos en formato `_bulk`, pero la medición contra él no se
llegó a ejecutar. Las cifras de arriba son solo de AegisStore; no se afirma
ninguna ventaja frente a OpenSearch que no se haya medido.

Lo que OpenSearch hace mejor, por diseño y sin necesidad de medirlo: búsqueda de
texto completo con análisis lingüístico y relevancia (aquí `LIKE` es subcadena,
no palabras), escalado horizontal en un clúster con réplicas, y un ecosistema de
visualización maduro.

## Tabla de honestidad

| Pieza | Aquí | Cómo |
|---|---|---|
| PostgreSQL real | **sí** | particiones declarativas, `DROP`, índices; el muro de la FASE 75, derribado |
| Mismo lenguaje en vivo e histórico | **sí** | 14 consultas, ejecutor real del endpoint, filas reales |
| Consulta por entidad | **sí** | índice primario; cruza procesos, veredictos y casos |
| Rechazo por coste | **sí** | contra PostgreSQL, antes de leer; invariante 14 |
| Retención por niveles | **sí** | caliente, tibio y frío (fichero con CRC) y purga, en pruebas |
| Volumen | parcial | 4,2 millones de eventos en una máquina; no un clúster |
| Comparativa con OpenSearch | **no** | ver arriba |
| Columnas cualificadas del endpoint (`network.port`, `memory.*`) | no se guardan | son cuantificadores que el ejecutor calcula en vivo; la consulta histórica que las usa se rechaza con ese motivo |

## El muro, declarado

- **Sin comparativa medida con OpenSearch** en esta fase.
- **Una sola máquina.** No hay réplica ni reparto del almacén entre nodos; eso lo
  da PostgreSQL con sus propias herramientas, y aquí no se ha probado.
- **Filas tardías de un día frío se rechazan**: sus columnas ya están en un
  fichero, y el día tendría datos en dos sitios. Un día tibio sí las acepta.
- **El orden por entidad cede el mapa de zona temporal dentro del día**; las
  ventanas de pocas horas leen el día entero de la tabla. Es la elección a favor
  del índice primario, medida arriba.
