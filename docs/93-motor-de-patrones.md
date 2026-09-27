# Módulo 93 — AegisPattern: el motor de patrones deja de ser prestado (FASE 101)

> Componentes: `crates/aegis-patron/`, `crates/aegis-scan/src/yara.rs`,
> `tools/verificar-patron.sh`.

## 93.1 Por qué un motor propio

El agente usaba `yara-x` —la reescritura en Rust de VirusTotal—. Está bien hecho,
pero un producto **no puede superar a su propia dependencia**: como mucho la iguala,
y siempre con el retraso de la versión que empaqueta. Y hay algo peor: cada fallo de
esa dependencia es un fallo del agente **en el camino que come entrada hostil** —el
que procesa ficheros y memoria que controla un atacante—. La FASE 101 cierra eso con
`aegis-patron`, un motor propio.

## 93.2 Las cinco propiedades que YARA no tiene, cada una por construcción

1. **Coste acotado por tipo.** Cada cadena lleva su cota demostrable. Una regla cuya
   cota no se puede demostrar —un salto de hex sin tope `[10-]`, uno gigante
   `[0-1000000]`— **no compila**, y el error dice qué parte no se acota. YARA acepta
   esas reglas, y viajan en corpus públicos.
2. **Tri-estado.** Escanear 4 MiB de un fichero de 4 GiB no es «limpio»: el resultado
   dice cuántos bytes se miraron y si fue completo.
3. **Determinismo y orden.** El conjunto de coincidencias no depende del orden de
   carga de las reglas ni del número de hilos: el escaneo es una función pura de
   (reglas, entrada), y los resultados salen ordenados.
4. **Sin retroceso.** El motor de expresiones regulares es una simulación tipo Pike
   VM del NFA de Thompson: tiempo **lineal siempre**. El patrón patológico `(a+)+c`
   sobre 100.000 bytes sin la `c` final —que hace explotar a un motor con retroceso—
   aquí termina de inmediato. **Sin retroceso no hay ReDoS**, por construcción.
5. **Seguridad de memoria.** `#![forbid(unsafe_code)]` en el motor que come entrada
   hostil. Es exactamente donde los motores en C han sangrado CVE de corrupción de
   memoria durante veinte años.

## 93.3 Compatibilidad de entrada, no de comportamiento

El frontal lee la sintaxis YARA —cadenas de texto y hex con comodines (`??`, `?X`) y
saltos (`[a-b]`), modificadores (`nocase`, `ascii`, `wide`, `fullword`), condiciones
con `and`/`or`/`not` y `N of (...)` / `any`/`all of them`— porque el corpus existente
está escrito así. Los literales van por un **Aho-Corasick** (el prefiltro que casa
miles de cadenas en una pasada); los patrones con comodines o saltos, por el motor
sin retroceso. La semántica es la nueva. Lo que este incremento aún no implementa
—expresiones regulares `/.../`, módulos, `xor`/`base64`— **se dice al compilar** en
vez de mal-escanear en silencio; ninguna regla del conjunto base del agente lo usa,
y se añade sobre el motor sin retroceso ya presente.

## 93.4 La prueba de que la fase terminó

La invariante 8 del MEGAPROMPT 11 no admite matices: **la fila de `yara-x`
desaparece del árbol del agente**. Se comprueba mecánicamente en
`verificar-patron.sh`: `yara-x` no está en `tools/lineabase-agente.txt` ni en el
árbol de producción de `aegis-scan` (`cargo tree -e no-dev`). Queda únicamente como
**dependencia de prueba** de `aegis-patron`, para el barrido diferencial. La
comparación contra el motor que se sustituye es como se demuestra la paridad sin
someterse a él.

## 93.5 Paridad medida, y honestidad

Sobre `base.yar` —las 14 reglas que el agente lleva residentes—, `aegis-patron` da
**las mismas coincidencias que `yara-x`**: compila con sus 14 reglas, y sobre
entradas dirigidas a cada regla y un barrido generativo de 200 pasadas de bytes
pseudoaleatorios, **cero divergencias**. La sustitución en `aegis-scan` es
transparente: `aegis-hunt`, `aegis-ctl` y el servicio de escaneo no cambian una línea.

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Sin retroceso (sin ReDoS) | **sí** | `(a+)+c` sobre 100k bytes termina en tiempo lineal |
| Coste acotado por tipo | **sí** | salto sin cota / gigante **no compila**, con su motivo |
| Tri-estado | **sí** | escaneo parcial declara bytes mirados y `completo=false` |
| Determinismo | **sí** | mismo (reglas, entrada) da el mismo resultado ordenado |
| Aho-Corasick + regex | **sí** | literales por prefiltro, comodines/saltos por el motor |
| Paridad con yara-x | **sí, medida** | base.yar: 14 reglas, 0 divergencias en entradas dirigidas y barrido |
| Autoataque | **sí** | reglas hostiles rechazadas; entradas hostiles sin pánico |
| yara-x fuera del agente | **sí** | ausente de lineabase y del árbol de producción |
| Regex `/.../`, módulos, xor/base64 | **parte siguiente** | ninguna regla base los usa; se declaran al compilar en vez de mal-escanear |
| Rendimiento MiB/s contra yara-x y clamscan | **muro de entorno** | requiere un banco medido; se declara |

## 93.6 Un solo motor

El mismo código escanea fichero, memoria de proceso, flujo y volcado. Dos motores
serían dos verdades; la tabla `memory` de `aegis-hunt` y el escaneo de ficheros del
servicio comparten exactamente el mismo `Motor`.

Mensaje de commit:
`feat(engine): replace the third-party pattern engine with a bounded-cost, backtracking-free matcher of our own`
