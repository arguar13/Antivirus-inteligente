# 67. AegisRuleForge — la fábrica de contenido

> **Crate**: `server/crates/aegis-ruleforge` · **Fase**: 72
> **Verificación**: `tools/verificar-ruleforge.sh`, integrado en `make ci`

Un motor de detección sin contenido no detecta nada. El contenido del mundo
—Emerging Threats, el catálogo Sigma, las bases de ClamAV, las colecciones YARA
públicas— existe, es bueno, y está escrito en cuatro formatos distintos por
gente que no somos nosotros.

Esta fase lo convierte en un artefacto que el agente puede consumir. Y la parte
difícil no es leer los formatos.

---

## 67.1 Las cuatro invariantes

Todo lo de este crate sale de estas cuatro, y ninguna es negociable.

### 1. Lo que entra lo escribe alguien que no somos nosotros

Un feed comprometido no entrega reglas: entrega **lo que el atacante quiera**,
directamente al proceso que compila el contenido de seguridad de toda la flota.

Por eso los analizadores son propios —`suricata`, `sigma`, `clamav`,
`yara_feed`, y un lector de YAML escrito para el subconjunto que Sigma usa de
verdad— y no bibliotecas genéricas. Un analizador de propósito general en ese
camino es **código no auditado procesando entrada hostil con los permisos del
defensor**, que es exactamente el patrón de la mitad de los CVE de los productos
de seguridad.

El árbol de dependencias del crate lo dice entero: `thiserror`, `serde`, `sha2`,
y tres crates propios. Nada más entra en el camino del contenido.

### 2. Lo que no se entiende se rechaza CON NOMBRE

Ningún analizador acepta de todo. Cada regla que no se compila va al `Informe`
con **su código y su explicación**, y de ahí sale la **cobertura**: cuántas
reglas de cuántas se compilaron.

Esto no es cosmético. Un analizador permisivo que «intenta hacer lo que puede»
con una regla que no entiende produce una regla que hace *otra cosa* — y no
puede dar la cifra de cobertura, porque no sabe que ha fallado. Sin esa cifra,
nadie sabe qué parte del corpus mundial se está perdiendo.

```
canario OK: 1200 firmas contra 14 muestras legítimas
cobertura 0,94 · 1200 compiladas · 71 rechazadas · 12 duplicadas
  regex-cuantificador-anidado      31
  suricata-opcion-desconocida      24
  sigma-condicion-no-analizable    16
```

### 3. Lo que se distribuye no puede tumbar al cliente

Dos puertas distintas, contra dos formas de tumbarlo.

**`regex_segura`** rechaza expresiones con retroceso catastrófico. Una expresión
como `(a+)+$` explora del orden de 2^30 caminos contra una cadena de treinta
caracteres que no casa. Ahora piénsese dónde corre eso: **en el endpoint del
cliente, por cada paquete**. Una sola regla así, distribuida a la flota, es una
denegación de servicio contra el propio producto, firmada por nosotros y aplicada
por nosotros.

Se analiza la **estructura**, no el tiempo. Cronometrar falla por dos lados: el
caso malo de una expresión patológica es una cadena concreta, y encontrarla es el
problema que se intenta evitar; y un umbral en milisegundos calibrado en el
servidor de compilación no dice nada del portátil del cliente.

**`canario`** rechaza el corpus entero si alguna firma dispara sobre software
legítimo. Está en §67.3, porque merece su propia sección.

### 4. Lo que llega al agente tiene que caber en el agente

Un corpus de ClamAV son dos millones de firmas. Aunque cada una ocupara solo 48
bytes, eso son **96 MB solo en las claves**. La cuota que el presupuesto del host
le da al corpus residente son 5 MiB en una pasarela, 15 en una estación y 106 en
un host de base de datos (ver [presupuesto](../README.md#presupuesto-de-recursos)).

No cabe en ninguna clase de host, y no es «no cabe cómodo». El `indice` vive en
disco: entradas de tamaño fijo, ordenadas por clave, con búsqueda binaria por
`seek`. Veintiuna lecturas de 48 bytes para dos millones de entradas.

---

## 67.2 Los cuatro compiladores, y lo que cada uno enseñó

| Formato | Lo que cuesta de verdad |
|---|---|
| **Suricata** | Distinguir `http.uri` (búfer pegajoso, mira hacia **adelante**) de `http_uri` (modificador clásico, mira hacia **atrás**, al `content` anterior). Las dos sintaxis conviven en el mismo feed. Confundirlas desplaza todos los campos **uno**, y el resultado son reglas que compilan y miran el sitio equivocado |
| **Sigma** | La condición es una gramática con precedencia (`not` > `and` > `or`) y `1 of`/`all of`. Y las reglas son dinámicas: el motor de cadenas del agente usa `&'static`, así que Sigma necesita su propia representación y su propio evaluador |
| **ClamAV** | Los formatos no son simétricos: en `.mdb` el **tamaño va primero** y en `.hdb` va después. Y los comodines (`??`, `*`, `{n-m}`, `(a\|b)`) hacen que emparejar tenga coste explosivo, lo que obliga a un presupuesto de pasos |
| **YARA** | Las reglas se refieren unas a otras, así que hay que **ordenar por dependencias** antes de compilar. Con detección de ciclos, porque un feed puede traerlos. Y `pe.number_of_sections` no es una dependencia: hay que consumir la cadena de accesos entera para no confundir un campo de módulo con un nombre de regla |

El lector de YAML es propio por la invariante 1, y tiene **progreso estricto**:
todo bucle avanza o para. Un analizador de entrada hostil que puede no consumir
nada en una iteración es un cuelgue esperando a la entrada que lo provoque.

---

## 67.3 El canario: por qué bloquea la release

Un falso positivo en un EDR no es un fallo cosmético.

Una firma que casa con `/bin/ls` y se distribuye con el modo de corte activo
**mata `ls` en toda la flota a la vez**, en el mismo minuto, sin que haya un
atacante. El radio de explosión no es un equipo: es la organización entera, y la
causa no es un exploit sino un fichero de contenido firmado por el fabricante.
Es la forma exacta que tuvo la caída de CrowdStrike de julio de 2024.

Por eso el canario no emite un aviso que alguien pueda ignorar con prisa. Si
bloquea, **no hay artefacto**: `compilar_corpus` ni siquiera escribe el índice.

### Las tres cosas que bloquean

1. **Disparo.** Una firma casa con software legítimo conocido.
2. **Firma demasiado corta.** Una secuencia de `n` bytes concretos aparece por
   azar en un fichero de `L` bytes con probabilidad `L / 256^n`. Con 4 bytes y un
   binario de 100 MB eso es un falso positivo cada diez ficheros grandes. Se
   exigen **16 bytes fijos** (los comodines no cuentan, y en una alternativa manda
   la rama más corta), y se rechaza **sin necesidad de que dispare**.
3. **Firma no evaluable.** Si el emparejador agota su presupuesto de pasos, el
   resultado no es «limpia»: es **desconocida**, y desconocida bloquea igual.

La tercera es la que más cuesta aceptar y la que más importa: declarar limpia una
firma que no se pudo evaluar es firmar a ciegas.

### Las muestras son ficheros reales

Salen del sistema de ficheros del host, no de un generador. Un ELF fabricado en
una prueba no tiene las cadenas, las tablas de secciones ni las secuencias de
instrucciones que hacen que una firma corta dispare; usarlo como canario daría un
verde que no significa nada.

Y un canario **sin muestras nunca aprueba**. Dar el visto bueno porque no había
nada contra lo que probar es el peor fallo posible en una puerta de seguridad.

---

## 67.4 El ataque que ninguna firma detiene

Un corpus se firma para que nadie pueda fabricar uno. Eso deja fuera al atacante
que **inventa** contenido. No deja fuera al que **repite** el nuestro.

> Coger el corpus de hace seis meses —auténtico, firmado por nosotros, con la
> firma perfecta— y reponerlo en la flota.

Ninguna verificación criptográfica lo distingue del bueno, porque no hay nada que
distinguir: es nuestro. Lo que consigue es que el endpoint vuelva a un corpus que
no conoce el ransomware de este mes, y lo consigue **sin romper nada**.

Es el mismo ataque que la [FASE 68](63-swarm.md) encontró en la malla, y lleva la
misma respuesta: una **época monótona**. El agente recuerda la época más alta que
ha visto y rechaza cualquier corpus con una época **igual o menor**, tenga la
firma que tenga.

Estrictamente mayor, no mayor o igual: si se aceptara la igualdad, dos corpus
distintos con la misma época serían intercambiables y el atacante elegiría cuál.

### El orden de las comprobaciones

```
1. La firma       ── si no es nuestro, no se mira nada más
2. La época       ── auténtico y anterior sigue siendo un ataque
3. El índice      ── que el manifiesto firme ESTE índice
4. El canario     ── que acredite haber pasado la puerta
```

El orden importa. Comprobar la época **antes** que la firma le dejaría a
cualquiera mover el estado del agente mandándole basura con una época enorme.

### Por qué una sola firma y no dos

Se firma el **manifiesto**, y el manifiesto se compromete con el **SHA-256 del
índice**. Una sola firma cubre las dos cosas.

La alternativa —firmar manifiesto e índice por separado— es peor, y no es obvio
por qué: con dos firmas independientes, un atacante puede quedarse el manifiesto
de la versión 5 y el índice de la versión 4, y **las dos firmas verifican**. El
resultado es un corpus que nunca existió, montado enteramente con piezas
auténticas.

### Codificación canónica

El manifiesto se serializa a mano, con campos de longitud fija. Si dos
codificaciones del mismo manifiesto dieran bytes distintos, la firma dejaría de
significar «este manifiesto» para significar «estos bytes», y quien controlase la
serialización podría fabricar dos manifiestos con sentidos distintos y una sola
firma.

---

## 67.5 Distribución por diferencias

Con dos millones de firmas y un cambio de veinte, mandar el corpus entero cada
vez sería gastar gigabytes de la red del cliente para entregar unos kilobytes de
novedad.

Se reutiliza el **árbol de Merkle** de la [FASE 23](../README.md): si las raíces
coinciden, la sincronización termina con **una sola comparación de hash** y sin
transferir nada. Si difieren, solo se baja a los subárboles que difieren.

Medido en la propia suite: 2000 indicadores contra 2020, y se transfieren **20**,
moviendo como mucho 20 cubos de 256.

Las revocaciones viajan igual que las altas: una regla revocada que se queda en
el endpoint sigue dando falsos positivos, así que quitar es tan importante como
poner.

---

## 67.6 La tubería

```
  feeds ──▶ analizadores ──▶ informe ──▶ canario ──▶ índice ──▶ manifiesto
           (propios)       (cobertura)  (BLOQUEA)  (en disco)  (firmado)
```

`Fabrica` es esa tubería entera. Cada etapa se puede usar suelta, pero el orden
no es negociable, y por eso hay una fachada: **saltarse el canario no es una
opción de configuración**, es que `corpus::preparar` no construye manifiesto sin
su veredicto.

Un feed que no se puede compilar **no detiene a los demás**. Lo que pasa con él
queda en el informe, con nombre y motivo, y esa es la diferencia entre perder un
feed sabiéndolo y perderlo en silencio.

---

## 67.7 Honestidad: lo que esta fase NO hace

| Muro | Por qué está, y qué se hace en su lugar |
|---|---|
| **No ejecuta reglas** | Compila YARA a texto ordenado por dependencias, no a bytecode. Evaluar Sigma contra eventos y YARA contra ficheros es de los motores, que viven en el agente y ya tienen sus propias fases |
| **No firma** | `corpus::preparar` deja los bytes exactos que hay que firmar; la clave privada vive en el firmador del plano de control y no en una biblioteca |
| **No descarga** | De dónde salen los ficheros del feed es del canal de actualizaciones, que ya tiene su propia autenticación |
| **El canario no evalúa YARA ni Sigma** | Necesitan sus propios motores. Devolver verde fingiendo que se comprueban sería justo la clase de mentira que el módulo existe para evitar. Quien tenga esos motores los aporta con `Canario::evaluar_con` |
| **El canario demuestra ausencia de falsos positivos sobre SU conjunto de muestras**, no en general | Ninguna implementación arregla esto: el conjunto nunca será todo el software del mundo. Por eso existe la comprobación de longitud mínima, que es la única de las tres que dice algo sobre el software que el canario no ha visto |
| **El análisis de expresiones regulares no es un demostrador** | Reconoce las formas conocidas de explosión, no todas las posibles. Se declara así a propósito: un analizador que se vende como completo invita a saltarse las demás defensas |

---

## 67.8 Verificación

`tools/verificar-ruleforge.sh`, integrado en `make ci`. Ejercita, contra
contenido con sintaxis real de los feeds y no con esqueletos fabricados:

- los cuatro compiladores, con las dos sintaxis de Suricata conviviendo;
- el rechazo con nombre y la cifra de cobertura;
- el orden por dependencias de YARA, ingiriendo las fuentes **al revés**;
- el canario bloqueando con una firma de cuatro bytes sacada de un binario real
  del host;
- el circuito completo: compilar, firmar, entregar, verificar;
- **el ataque de reposición**: un corpus anterior con la firma perfecta;
- **la mezcla de versiones**: manifiesto de la 5 con índice de la 4;
- y la **medida** de residencia de un corpus de 40.000 firmas consultado entero,
  contra la cuota que cada clase de host le concede.
