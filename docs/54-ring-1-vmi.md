# Módulo 54 — Introspección de Ring -1: ver el rootkit desde debajo del OS

> Componentes: `crates/aegis-vmi/`.

## 54.1 Por qué bajar al Ring -1

Un rootkit de Ring 0 controla el kernel: sus tablas de páginas y sus APIs. Una
defensa que corra **dentro** del sistema operativo puede ser cegada por él —le
pregunta al kernel qué procesos hay, y el rootkit borra el suyo de la respuesta—.
La única forma de no depender de la palabra del atacante es mirar desde **más
abajo**: el Ring -1, el hipervisor. Desde ahí, el kernel (y el rootkit que lo
subvirtió) es sólo un invitado observado.

## 54.2 La línea que no se cruza: esto NO es un rootkit

El hipervisor de AegisCore es **100% defensivo**, y la distinción es la misma que
separa un EDR de un malware. Se usa para **observar y delatar** la manipulación
del kernel desde fuera, jamás para lo contrario. Prohibido y ausente:
persistencia en firmware o UEFI contra el dueño, ocultar el agente, evadir su
eliminación. La antigua idea de un "bootkit UEFI" se rechazó por ser malware;
esto es su opuesto legítimo —un guardián que el dueño de la flota controla y
puede quitar cuando quiera—. Bajar al Ring -1 es una técnica; lo que la hace
defensiva u ofensiva es para qué se usa, y aquí se usa sólo para detectar.

## 54.3 EPT: atrapar el código oculto y el parcheo del kernel

Las **Extended Page Tables** son una segunda capa de traducción de memoria que
controla el hipervisor, no el SO. Si AegisCore marca las páginas de código del
kernel como **lectura + ejecución, pero no escritura**, el hardware atrapa dos
ataques clásicos:

- **Ejecución oculta**: ejecutar código desde una página que no está marcada
  ejecutable dispara una violación de ejecución —un módulo oculto corriendo—.
- **Parcheo del kernel**: escribir sobre una página de código protegida dispara
  una violación de escritura —alguien instalando un hook en línea—.

El crate diseña las estructuras EPT reales (entradas de 8 bytes, tablas de 512
entradas = una página de 4 KiB, con el tamaño y la disposición de bits
**verificados en compilación**), recorre los cuatro niveles como el hardware
(combinando permisos por AND), y clasifica cada violación. El caso decisivo lo
prueba: ejecutar una página de datos es *ejecución oculta*; escribir una página
de código es *parcheo*; ejecutar esa misma página de código es legítimo.

## 54.4 Leer el kernel sin preguntarle al kernel

Para saber qué procesos hay de verdad, el hipervisor **no pregunta**: lee la
memoria física y reconstruye las estructuras (`task_struct` en Linux, `EPROCESS`
en Windows) siguiendo los punteros a mano, sin pasar por ninguna API que el
rootkit pueda haber hookeado. Es lo que hace Volatility sobre un volcado, pero en
vivo y desde debajo.

La técnica que delata a un rootkit **DKOM** (que desenlaza su estructura de la
lista de procesos para esconderse) es la **vista cruzada**: se compara la lista
enlazada que el SO recorrería con un **barrido** de la memoria física que
encuentra *todas* las estructuras, enlazadas o no. Un proceso que aparece en el
barrido pero no en la lista está oculto: es la prueba del rootkit. El recorrido
de la lista se protege además contra listas cíclicas corruptas —un rootkit puede
dejarlas en cualquier estado— sin colgarse.

## 54.5 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Estructuras EPT: tamaño y ABI (8 B por entrada, 4 KiB por tabla) | sí, en compilación | — |
| Recorrido de las 4 tablas EPT y combinación de permisos | sí | — |
| Clasificación de violaciones (ejecución oculta, parcheo de kernel) | sí | — |
| Parser de `task_struct`/`EPROCESS` desde memoria física | sí, byte a byte | — |
| Detección de procesos ocultos por vista cruzada (DKOM) | sí | — |
| Recorrido robusto ante una lista cíclica corrupta | sí | — |
| ABI de KVM (`kvm_userspace_memory_region`) y la fontanería en vivo | compila (feature `kvm`) | ejecutar necesita VT-x/AMD-V y `/dev/kvm`; gated |
| Programar las EPT en el procesador y atrapar violaciones reales | — | necesita el hipervisor en hardware; gated |

El núcleo que puede estar mal de forma peligrosa —recorrer las EPT, clasificar,
parsear el kernel, detectar lo oculto— se prueba de verdad en cada `make ci`.
Arrancar el hipervisor en un procesador real es un muro físico, que
`tools/verificar-vmi.sh` declara en vez de fingir.
