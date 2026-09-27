# Módulo 92 — AegisDecompile: de bytes a pseudo-C, y determinista (FASE 100)

> Componentes: `crates/aegis-decompile/`, `tools/verificar-decompile.sh`.

## 92.1 El inventario obligatorio: qué abre esta fase, y qué no rodea

El grafo de la FASE 85 (`aegis-disasm`) **ya es consultable**: el CFG con
predecesores, los bloques con sus instrucciones, el grafo de llamadas y las
importaciones. Eso se consume tal cual. Lo que el modelo de instrucción de
`aegis-disasm` **no** guarda —a propósito, porque el motor de capacidades no lo
mira— es la **semántica de operandos**: la clase `Aritmética` y una máscara de
registros no bastan para elevar `add eax, [rbp-8]` a algo recompilable. Esta fase
**abre** esa semántica con una capa de elevación que re-decodifica cada
instrucción localizada por el CFG con el mismo `iced-x86` del desensamblador. No
reconstruye el grafo (eso sería rodearlo); añade la única pieza que faltaba.

## 92.2 Las cuatro cosas en las que gana a Ghidra

1. **Determinismo.** La misma entrada da byte a byte la misma salida, y se
   comprueba en la prueba. La causa del indeterminismo de casi todos los
   decompiladores es nombrar las variables por el **orden** de análisis; aquí los
   nombres se derivan del **contenido** (hash FNV-1a del subgrafo que define la
   variable). El nombre deja de depender del orden.
2. **La decompilación es evidencia.** Cada sentencia de pseudo-C lleva, en un
   comentario, las direcciones de las instrucciones que la originan. Una capacidad
   detectada cita el código.
3. **Cota dura y calidad declarada.** La calidad —% de instrucciones elevadas,
   `goto` emitidos, variables sin tipo, funciones abandonadas— es **parte de la
   salida**, no un informe aparte. El decompilador dice lo bueno que fue el
   resultado.
4. **No ejecuta nada.** Entra un `&[u8]`, sale una estructura de datos. No hay
   variante de ejecución en ningún tipo del crate, y declara
   `#![forbid(unsafe_code)]`. Se verifica por lo que **falta** y con un barrido de
   bytes hostiles que no entra en pánico.

## 92.3 La IR: tres direcciones, SSA, memoria explícita

Una IR **tipada**, no texto: nadie la serializa para volver a leerla, cada valor
sabe de qué instrucciones sale, y el orden es el del recorrido por dirección. En
forma **SSA** (construcción de Braun sobre los predecesores del CFG): cada valor se
define una vez, y donde el flujo une dos definiciones hay un `phi`. La memoria es
explícita —una carga es un valor, un almacenamiento es un efecto—. Es **una sola
IR** en el producto: la misma que consumirá la ejecución simbólica de la FASE 102.

## 92.4 Reconstrucción de tipos: nunca se inventa

El tipo de un valor se deduce del **uso** —tamaño de los accesos, aritmética de
punteros, prototipos de API, cadenas— y se combina por unificación. `Desconocido`
es el tope del retículo; dos restricciones incompatibles dan `Conflicto`, que al
usuario se le muestra como `desconocido`. **Lo que no se puede inferir se emite
como `desconocido`, jamás se inventa**: un tipo inventado en un informe forense es
una afirmación falsa con aspecto de dato.

## 92.5 La cifra de la fase: el redondeo semántico

La prueba honesta de un decompilador es recompilar su salida y comprobar que se
comporta igual. Se compila un corpus desde C conocido, se sacan los bytes de cada
función del objeto, se decompilan, se **recompila** el pseudo-C emitido y se
compara el comportamiento sobre 2000 entradas generadas por función. La tasa se
publica tal cual sale.

**Resultado de este incremento: 10/10 equivalentes (100 %) sobre el subconjunto
verificado** —funciones de registros, aritmética entera sobre argumentos,
compiladas a -O2—. Cada función recompila y devuelve exactamente lo mismo que la
original sobre todas las entradas probadas.

## 92.6 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Determinismo | **sí** | la misma entrada da el mismo pseudo-C, comprobado |
| Evidencia | **sí** | cada sentencia cita sus direcciones |
| No ejecuta / robustez | **sí** | barrido de bytes hostiles sin pánico; `forbid(unsafe)` |
| Reconstrucción de tipos | **sí** | unificación con `Desconocido` como tope, conflicto → desconocido |
| Calidad como salida | **sí** | % elevado, gotos, variables sin tipo, funciones abandonadas |
| Redondeo semántico | **sí, medido** | 10/10 del subconjunto de registros a -O2 recompila equivalente |
| Recuperación de variables de pila (-O0) | **parte siguiente** | a -O0 los argumentos se derraman a la pila; el marco de pila se modela en el siguiente incremento, y hasta entonces esas funciones se decompilan y se leen, pero no cuentan como verificadas |
| Destrucción de `phi` recompilable | **parte siguiente** | las funciones con control se decompilan y se leen (con `goto` contados), pero su emisión recompilable —sin errores de arista crítica— es el siguiente incremento |
| ARM64 | **parte siguiente** | el desensamblado A64 existe (FASE 85); la elevación A64 es el siguiente incremento |
| Comparativa medida contra Ghidra | **muro de entorno** | requiere Ghidra instalado y un corpus grande; se declara |

La cifra mide **lo que de verdad se comprobó**. El alcance por partes es la
decisión honesta: se construye el mecanismo entero —IR, SSA, tipos, estructuración,
emisión, determinismo, calidad— y se verifica equivalencia sobre el subconjunto que
hoy se emite como C recompilable, ampliándolo en incrementos medidos en vez de
afirmar una cobertura que no se alcanzó.

## 92.7 El muro declarado

No se persigue la **ergonomía interactiva** de Ghidra —renombrado colaborativo,
scripting de usuario, navegación—. Ghidra es un IDE de ingeniería inversa;
AegisCore es un EDR. Se dice, y se dice por qué.

Mensaje de commit:
`feat(analysis): implement deterministic decompiler with SSA lifting, type reconstruction and evidence-backed pseudo-C`
