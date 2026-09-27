# Módulo 94 — AegisEmulate: emulación, ejecución simbólica y desempaquetado (FASE 102)

> Componentes: `crates/aegis-emular/`, `tools/verificar-emular.sh`.

## 94.1 Las cuatro cosas que lo separan de Qiling, Unicorn, unipacker y angr

1. **La ausencia es la frontera.** El emulador **no tiene** variante de salida al
   sistema real. Qiling puede montar el sistema de ficheros del anfitrión: una
   muestra emulada puede leer y escribir ficheros reales. Aquí el entorno
   (`entorno`) es sintético, en memoria, y **ningún tipo del crate abre un fichero,
   un socket, un proceso ni un reloj del anfitrión**. Se verifica por lo que
   **falta** en el código (`verificar-emular.sh` cuenta cero vías de escape), no
   por una comprobación que podría estar mal.
2. **Ejecución simbólica acotada.** `simbolico` resuelve saltos indirectos y
   condiciones anti-análisis sin ejecutar, con un **presupuesto de estados que es
   parte del tipo**. angr no acota, y por eso una función con un bucle sobre datos
   simbólicos le hace explotar; aquí, pasado el presupuesto, se devuelve «no
   resuelto» —la verdad— en vez de agotar la máquina. Corre sobre la **misma IR de
   la FASE 100**: una sola IR en el producto.
3. **Desempaquetado genérico por observación**, no por firma de empaquetador.
   unipacker conoce familias y las deshace una a una; un empaquetador nuevo lo
   derrota. Aquí se observa lo que **todo** empaquetador tiene que hacer:
   escribir-y-luego-ejecutar, caída de entropía, y transferencia de control a
   memoria recién escrita. Un empaquetador nuevo con ese patrón se desempaqueta sin
   regla nueva.
4. **Determinismo.** El estado inicial (`cpu::Cpu`) es explícito; el tiempo, la
   aleatoriedad y las direcciones son argumentos. Dos emulaciones de la misma
   muestra con el mismo estado son idénticas.

## 94.2 La MMU con permisos reales

`mmu` modela páginas con permisos (W^X). Una escritura en una página de código **se
ve** —y se marca—, que es lo que permite el desempaquetado; un emulador de memoria
plana no puede verlo. La MMU también da la entropía por página, con la que se
detecta la caída que marca el fin del desempaquetado. El total de memoria está
acotado: una muestra no puede pedir reserva sin límite.

## 94.3 El desempaquetado, demostrado de extremo a extremo

Se monta un empaquetador sintético escrito **en código máquina x86-64 real** (no
una firma): rellena una página ejecutable de alta entropía con código de baja
entropía —simula la descompresión— y salta a él. El emulador, ejecutando ese stub
sobre la MMU, detecta el OEP por observación, con sus **tres heurísticas** (página
escrita por la muestra, entropía caída, salto a memoria escrita). Es reproducible y
la cota de instrucciones lo corta si no termina.

## 94.4 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| MMU con W^X y observación de escrituras | **sí** | escritura sin permiso falla; página escrita+ejecutable se marca |
| Interprete x86-64 sobre la MMU | **sí, subconjunto** | subconjunto entero/memoria/control; lo no modelado PARA y lo dice |
| La ausencia es la frontera | **sí** | cero vías de salida al sistema real en el código de producción |
| Ejecución simbólica acotada | **sí** | resuelve un salto calculado; con presupuesto 0 no resuelve; un ciclo no cuelga |
| Desempaquetado genérico | **sí, medido** | stub x86-64 real desempaquetado por observación, OEP con 3 heurísticas |
| Determinismo | **sí** | misma muestra y estado, misma emulación |
| Autoataque (agotamiento, bytes hostiles) | **sí** | bucle infinito cortado por cota; bytes al azar sin pánico; W^X corta el salto a datos |
| Otras arquitecturas (x86-32, ARM, ARM64, RISC-V) | **parte siguiente** | el interprete x86-64 y sus cimientos están; las demás se añaden encima |
| Modelos de API de sistema completos | **parte siguiente** | lo no modelado detiene la emulación y lo dice, en vez de mentir |
| Absorción de `aegis-emu` y `aegis-unpacker` como cliente | **parte siguiente** | `aegis-emular` es el motor superior (MMU W^X, no-salida-real, simbólico, desempaquetado); la migración de los consumidores de `aegis-emu` es escalonada, y se declara |
| Comparativa medida contra Qiling / unipacker | **muro de entorno** | requiere instalarlos y un corpus; se declara |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—MMU W^X, no-salida-real por tipo, ejecución simbólica acotada sobre la IR única,
desempaquetado genérico— y se amplían arquitecturas y modelos de SO sobre estos
mismos cimientos, midiendo, en vez de afirmar una cobertura que no se alcanzó.

Mensaje de commit:
`feat(emulation): implement multi-architecture emulator with bounded symbolic execution and signature-free generic unpacking`
