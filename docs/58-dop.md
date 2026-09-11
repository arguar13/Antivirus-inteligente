# Módulo 58 — Mitigación de DOP: taint tracking en el micro-sandbox

> Componentes: `crates/aegis-emu/` (módulo `taint`, sobre el emulador de la
> FASE 56).

## 58.1 El ataque que evade el CFI: programación orientada a datos

Las defensas modernas de control de flujo (CFI, W^X, shadow stacks) han encarecido
el ROP clásico: desviar el flujo de control a *gadgets* es cada vez más difícil de
esconder. La **programación orientada a datos** (Data-Oriented Programming, DOP)
es la respuesta del atacante: no desvía el flujo —lo deja intacto, así ninguna
defensa de control de flujo se dispara— y en su lugar **corrompe datos**.
Reescribiendo estructuras del sistema (tablas de páginas, descriptores, punteros
almacenados en datos) con valores que controla, consigue la computación que quiere
sin ejecutar una sola instrucción "suya". No hay salto ilegítimo que atrapar; lo
que hay es un **río de datos del atacante** que termina escribiendo, en masa,
sobre una estructura que ningún código legítimo reescribe a mano.

## 58.2 La idea: seguir la contaminación hasta una estructura protegida

El micro-sandbox de la FASE 56 ya ejecuta el binario desconocido instrucción a
instrucción sobre una CPU y una memoria virtuales. La FASE 63 le añade un
**seguimiento de contaminación** (taint) ligero:

- **La fuente**: todo lo que entra por un `read` —los datos que el atacante
  controla— se marca como contaminado.
- **La propagación**: cuando una instrucción lee un operando contaminado, su
  resultado queda contaminado. Se hace en los **dos únicos puntos** por los que
  toda instrucción lee y escribe operandos, así que no hay que instrumentar el
  emulador entero.
- **La detección**: cuando ese dato contaminado se escribe, **en volumen**, sobre
  una **región protegida** —una estructura del sistema que se declara intocable
  por escritura directa—, se levanta la alarma de DOP. La escritura legítima de
  esas estructuras pasa por una API (una syscall); la del exploit va directa, byte
  a byte, y es justo lo que se ve.

Se valida con un **binario de exploit DOP real** (código máquina x86-64 ensamblado
a mano): un `read` que contamina un buffer y un bucle que copia esos bytes sobre
la región protegida. El sandbox lo detecta. Y el caso decisivo negativo: el
**mismo** bucle de copia, pero sin el `read` —datos limpios— **no** se marca, que
es lo que separa una detección de un estorbo.

## 58.3 Honestidad: un taint ligero y conservador

La propagación es deliberadamente **conservadora**: cualquier fuente contaminada
de una instrucción contamina su destino. Eso puede *sobre*-contaminar —un
`xor eax, eax` deja `eax` a cero pero aquí hereda la marca—, nunca
*sub*-contaminar. Para un detector defensivo es lo seguro: no se pierde el ataque;
los falsos positivos los acota exigir **volumen** (un umbral de bytes) **y** una
**región protegida**, no una escritura suelta. La imprecisión se documenta en vez
de fingir un seguimiento perfecto por byte de cada bit de cada registro.

## 58.4 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Un exploit DOP real (read → copia masiva a la región protegida) se detecta | sí, código máquina real, cero mocks | — |
| El mismo bucle sin `read` (datos limpios) **no** es DOP | sí | — |
| Propagación de taint por registros y memoria (por byte) | sí | — |
| El detector dispara sólo al superar el umbral y dentro de la región | sí | — |
| El taint no crece sin límite (tope del `read`) | sí | — |
| Ejecución del binario emulado | sí | **sin muro**: todo ocurre en la CPU virtual |

Como el análisis es 100% emulado —ninguna instrucción del binario toca el
procesador real— no hay muro físico que declarar: el detector de DOP se prueba de
verdad, entero, contra código máquina real en cada `make ci`, dentro del grupo
"Rust · tests".
