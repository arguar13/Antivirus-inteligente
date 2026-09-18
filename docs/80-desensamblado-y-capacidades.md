# AegisDisasm: desensamblado, grafos y capacidades con evidencia

**FASE 85.** El crate `aegis-disasm`.

## El problema

Una firma dice «esto es Emotet» y no dice por qué. Cuando se equivoca —y se
equivoca— no hay forma de saberlo sin repetir el análisis a mano, y el analista
que la recibe tiene dos opciones: creérsela o rehacer el trabajo.

Una **capacidad** dice «esto inyecta código en otro proceso» y **enseña las
instrucciones que lo hacen**. Quien la lea puede comprobarla en treinta segundos,
y quien la escriba no puede esconder que la regla era floja.

Ese es todo el cambio, y tiene una consecuencia de diseño: aquí no hay ninguna
función que devuelva una lista de nombres.

## La evidencia no es una convención, es el tipo

```rust
pub struct Capacidad {
    pub nombre: &'static str,
    pub familia: Familia,
    pub attack: Option<&'static str>,
    evidencias: Vec<Evidencia>,   // privado
}

impl Capacidad {
    pub fn nueva(..., evidencias: Vec<Evidencia>) -> Option<Capacidad> {
        if evidencias.is_empty() { return None; }
        ...
    }
}
```

El campo es privado y el único constructor devuelve `None` sin evidencia. **Una
capacidad sin evidencia no existe como valor.** No es una comprobación que
alguien pueda saltarse un viernes por la tarde.

La puerta `tools/verificar-disasm.sh` comprueba que el campo siga siendo privado:
si alguien lo hace público, el CI falla y hay que explicar por qué.

## Lo que hay dentro

| Módulo | Qué hace |
|---|---|
| `instruccion` | El modelo común: lo que x86 y A64 tienen que producir igual |
| `x86` | Decodificación de x86 y x86-64, sobre `iced-x86` |
| `arm64` | Decodificación de A64, escrita en casa |
| `cfg` | El grafo de flujo por descenso recursivo, con tablas de saltos |
| `llamadas` | El grafo de llamadas, con las indirectas resueltas por constantes |
| `importaciones` | A qué llama, y **cómo** averigua las direcciones |
| `capacidad` | El tipo que no se puede construir sin evidencia |
| `reglas` | El catálogo, como datos, y el motor que lo evalúa |
| `senal` | El puente al árbitro |
| `analisis` | La entrada de una pieza: bytes dentro, capacidades fuera |
| `plazo` | La cota, y la cobertura que se declara al agotarla |

## Dos decodificadores, dos decisiones opuestas, una sola regla

**x86-64 con `iced-x86`.** No es una codificación, es un sedimento: prefijos
heredados, REX, VEX, EVEX, opcodes de uno a tres bytes, ModRM, SIB, longitud
variable. Escribirlo entero en casa son años, y un decodificador incompleto **no
falla ruidosamente**: lee una instrucción de cinco bytes como una de tres y todo
lo que viene detrás queda desplazado, produciendo un desensamblado que parece
correcto. `iced-x86` entra con **cero dependencias transitivas** y ya estaba en
la línea base.

**A64 en casa.** El candidato equivalente, `yaxpeax-arm`, arrastra ocho crates.
Este proyecto rechazó libp2p por su árbol; aceptar ocho más por A64 sería
incoherente. Y el trabajo no es comparable: A64 es **ancho fijo de 32 bits**, con
los campos en posiciones constantes, así que **no existe el fallo por
desalineamiento**. Una instrucción que este módulo no conozca sale como
`Clase::Otra` y el recorrido sigue intacto.

Esa segunda propiedad es la que hace defendible escribirlo.

## El modelo NO guarda el texto de cada instrucción

Es la decisión con más consecuencias del crate. Guardar el mnemónico y la
instrucción formateada son dos asignaciones por instrucción: en un binario de cien
mil instrucciones, doscientas mil asignaciones pequeñas para un texto que **casi
nunca se lee**. Solo se lee el de las que acaban siendo evidencia, que son unas
decenas.

Así que se guarda lo que el análisis necesita y el texto se formatea **a la
carta**. El efecto medible: un análisis acotado en tiempo no se queda sin memoria
antes de quedarse sin tiempo, que es la forma típica de que una cota de tiempo no
sirva de nada.

## Lo que se midió, y las tres correcciones que salieron de medirlo

El catálogo se ejecutó contra `/bin/ls`, `/bin/bash` y la libc de la máquina.
**Disparaba en los tres.** Las tres causas, corregidas de raíz:

### 1. El motor juntaba hechos que no estaban juntos

La regla de RC4 disparaba en `/bin/ls` con un `cmp rax, 0x100` en `0x604a`, un
`rep movsq` en `0x87da` y un `xor eax, eax` en `0x4dd5`: tres instrucciones en
tres sitios distintos de un binario de cien kilobytes, sin ninguna relación entre
ellas.

Y su evidencia parecía impecable: tres direcciones concretas, cada una con su
instrucción. Quien la leyera por encima la daría por buena.

Ahora una regla que mira código lleva `Ambito::MismaFuncion`, y eso exige dos
cosas: la misma función **y** una ventana de 4 KB. Hicieron falta las dos, porque
en un binario sin tabla de símbolos completa «función» delimita poco: en
`/bin/ls` la mayor de las funciones reconstruidas abarca 75 KB de un `.text` de
100.

### 2. El cuerpo de una función no paraba en los saltos de cola

Un `jmp` a la entrada de otra función transfiere el control y no vuelve, así que
lo que hay al otro lado no es parte de esta. Estaba escrito en el comentario y no
en el código, y la diferencia se midió: sin parar ahí, una función de `/bin/bash`
contenía bloques a medio megabyte de distancia, porque cada salto de cola
encadenaba con la función siguiente.

### 3. `fs:[0x30]` no es el bloque de entorno en todas partes

Lo es en Windows de 32 bits. En **Linux de 64**, `fs` es el área de datos locales
del hilo y ese desplazamiento es un campo cualquiera: la libc de esta máquina lo
lee **79 veces**. Sin mirar la anchura, el módulo declaraba 79 veces que la libc
resuelve funciones a escondidas.

**Resultado medido: cero capacidades en los tres binarios**, y las 32 reglas
siguen disparando con las señales que buscan.

## El grafo de flujo también tenía dos defectos, y salieron al usarlo

**Bloques solapados.** Un salto hacia adelante dejaba las mismas instrucciones en
dos bloques a la vez, y eso resolvía un `call rax` **a dos direcciones a la vez**,
cada una cierta por un camino. Ahora se parten — salvo cuando el solape es real:
en x86 dos flujos de instrucciones pueden solaparse de verdad y después
converger, y eso pasa diez veces en 257.523 instrucciones de la libc. Ahí las dos
lecturas son legítimas y partirlas sería inventarse que son la misma.

**Los destinos de llamada directa no se desensamblaban.** Un binario cuyo `main`
solo llama a otras funciones salía como una función de tres instrucciones. Ahora
van como **raíz**, no como sucesor: el control no pasa del que llama al llamado
dentro de una misma función, pero es código y hay que mirarlo.

## Resolver llamadas indirectas sin inventar ninguna

El código que se analiza no llama por nombre: resuelve la dirección en ejecución,
la deja en un registro y salta a él. Un grafo que solo siga las llamadas directas
ve un binario que no llama a nadie.

La propagación de constantes lo resuelve, y el modelo que lo hace posible tiene
tres distinciones que existen **para no inventar destinos**:

- **Escrito frente a definido.** `mov al, 1` no deja `RAX` valiendo 1: deja sus 56
  bits altos como estaban. Un análisis que apuntara `RAX = 1` fabricaría una
  arista hacia una dirección a la que el programa nunca llama.
- **Máscaras y no un registro.** `xchg` escribe dos, `mul` escribe `RAX` y `RDX`
  sin nombrarlos, `cpuid` cuatro, y una llamada deja indefinido todo lo volátil.
  Guardar uno solo dejaría vivo un valor que el programa ya pisó.
- **Encuentro y no unión.** Cuando dos caminos llegan con valores distintos, el
  resultado es desconocido. Quedarse con uno daría una arista cierta a medias,
  que para quien la lea es indistinguible de una falsa.

También se corrigió que `MOVN` daba el inmediato en vez de su complemento —el
ensamblador escribe `movn x1, #0x10` como `mov x1, #-0x11`— y que las exclusivas
de A64 se buscaban en la familia equivocada.

## Lo que esta fase NO cierra

- **Un binario empaquetado.** Estas reglas se evalúan sobre código desensamblado,
  y un empaquetado no enseña el suyo hasta que se ejecuta: sobre él se verá el
  desempaquetador y no la carga. Sale en la cobertura, y es el trabajo de
  `aegis-unpacker` y de la detonación.
- **A qué API se resuelve un hash de nombre.** Haría falta el diccionario de
  exportaciones de la máquina objetivo; adivinarlo produciría nombres inventados
  con aspecto de hechos.
- **Destinos indirectos que vienen de memoria.** Un `call [rip+0x2f10]` lee un
  puntero que el análisis estático no conoce. Se cuentan y se dicen con su
  motivo.

Sobre un binario benigno compilado de la forma normal, el análisis de constantes
resuelve **casi ninguna** llamada indirecta, porque el patrón que resuelve no
aparece ahí: de las 690 sin resolver de la libc, 343 tienen el destino en
memoria, 111 salen de una suma de dos registros —tablas de saltos— y 46 de un
valor devuelto por una función. Los números están en la cabecera de `llamadas.rs`,
y no se disimulan subiendo la regla hasta que salga algo.

## Nada se ejecuta, y se verifica por lo que falta

Es la invariante 8: **el análisis nunca ejecuta en el host**. Un desensamblador
que ejecutara lo que desensambla es un ejecutor de malware con otro nombre.

No hay en todo el crate una llamada que lance un proceso, cargue una biblioteca,
proyecte memoria ejecutable o reinterprete bytes como código, y `unsafe` está
prohibido con `#![forbid(unsafe_code)]`. Entra un `&[u8]` y sale una estructura de
datos. **No es que esté desactivado: es que no está**, y la puerta lo comprueba
buscando esos caminos.

## Cómo se verifica

```
./tools/verificar-disasm.sh        # la puerta entera
./tools/ci-local.sh disasm         # dentro del CI
```

La puerta cotejó **642.967 instrucciones de 3.926 funciones** de `/bin/ls`,
`/bin/bash` y la libc contra `objdump`, con longitudes idénticas. Se compara
contra otra implementación porque un desensamblador que se desplaza un byte
produce un desensamblado que **parece** correcto, y esa es la peor forma de
fallar que puede tener esta pieza.
