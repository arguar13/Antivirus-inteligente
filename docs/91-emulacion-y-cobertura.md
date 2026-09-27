# Módulo 91 — AegisRange: emulación de adversario y medida de cobertura (FASE 99)

> Componentes: `server/crates/aegis-rango/`, `server/crates/aegis-rango/tests/`,
> `tools/verificar-rango.sh`.

## 91.1 La pregunta que un equipo de detección no puede contestar con una opinión

> ¿Mi EDR **ve** la técnica X?

Hoy esa respuesta la da una persona mirando un panel. MITRE Caldera y Atomic Red
Team ejecutan la técnica y **dejan que tú mires**: el ciclo lo cierra alguien, y lo
que cierra una persona no entra en la puerta de calidad. AegisRange cierra el ciclo
entero y **automático**: ejecuta una emulación benigna y reversible de la técnica en
un rango declarado, pregunta al árbitro (`aegis_entidad::arbitrar`) por la entidad
afectada, y **si no hubo veredicto lo dice como hueco de cobertura con el nombre de
la técnica**. La cobertura de detección deja de ser una opinión y pasa a ser una
cifra que `make ci` publica.

## 91.2 Las tres garantías, todas por tipo

**Solo en el rango.** Una técnica no se ejecuta sin una `PruebaDeRango`, y esa
prueba solo la acuña un `Rango` declarado con su confirmación (autor y motivo, sin
valor por defecto). `PruebaDeRango` no tiene constructor público ni campos públicos:
fabricarla no compila. No hay ninguna ruta de código que emule contra producción —se
verifica por lo que el tipo **no** ofrece—.

**Reversión obligatoria.** El rasgo `Tecnica` exige `revertir` **sin cuerpo por
defecto**: una técnica sin reversión no implementa el rasgo y no compila. La medida
revierte **siempre** —haya ido bien o mal— y comprueba, contra el estado real del
rango, que no queda residuo. Una prueba de cobertura que deja una puerta abierta es
un incidente, no una prueba.

**Emulación benigna.** El gesto de cada técnica es materializar un artefacto marcador
dentro de la jaula del rango —lo mínimo que la detección debería ver— y borrarlo. No
hay payload ni código de ataque: el valor está en **medir** si la detección se
dispara, no en la técnica.

## 91.3 La honestidad del informe: tres estados, y ninguno se infla

Por cada técnica, el informe da uno de tres estados:

- **Detectada** — el árbitro produjo un veredicto acusatorio; se registra qué motor
  y en cuánto tiempo.
- **No detectada** — se ejecutó y el árbitro no acusó: **hueco de cobertura**, con el
  nombre de la técnica.
- **No aplicable** — la técnica no aplica en la plataforma del rango; **no se
  ejecuta** y **nunca** cuenta como detectada.

La cobertura es `detectadas / (detectadas + huecos)`: las no aplicables no entran en
el denominador. Inflar la cifra contando lo que no aplica como cubierto es la mentira
que esta fase existe para impedir. Si no hay nada aplicable, la cobertura es «sin
datos», no cero —que se leería como «lo miré y no detecté nada»—.

## 91.4 Lo que el rango revela hoy, y por qué eso es el punto

El árbitro decide sobre las **señales** que se le pasan. Varios motores detectan pero
todavía no entregan señal al árbitro —el conductual (las 14 técnicas de la FASE 19) y
el forense de memoria, según el inventario—. El rango no lo esconde: esas técnicas
salen como hueco, con su nombre, para que se cierre el cableado. La prueba de
cobertura lo fija: las técnicas de un motor cableado (ITDR, estático, red…) se
detectan; las de uno sin cablear (memhunter, conductual) salen como hueco. Medir la
propia ceguera es exactamente para lo que existe esta fase.

El catálogo cubre **al menos una técnica por cada una de las 14 tácticas de ATT&CK
Enterprise**, incluidas las 14 del motor conductual y las de identidad, red e
impacto. Las tácticas que un EDR no puede ver por su naturaleza —reconocimiento,
desarrollo de recursos, que ocurren en la infraestructura del adversario— están en el
catálogo para que el informe las cuente, y salen como hueco: decirlo es más honrado
que omitirlas.

## 91.5 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Cada técnica se ejecuta, se mide y se revierte | **sí** | contra el estado real del rango (marcadores en la jaula) |
| Una técnica sin reversión no compila | **sí** | `compile_fail` E0046 sobre el rasgo |
| No se ejecuta fuera del rango | **sí** | `PruebaDeRango` no fabricable, `compile_fail` E0451 |
| La medida no deja residuo | **sí** | tras medir el catálogo entero, cero marcadores |
| Tres estados, sin inflar | **sí** | una no aplicable nunca cuenta como detectada |
| La cifra es reproducible | **sí** | dos ejecuciones dan los mismos estados |
| Los huecos se nombran | **sí** | memhunter y conductual salen como hueco por su técnica |
| La detección real de cada motor | **parcial** | el rango mide contra el árbitro con las señales que hoy le llegan; cablear cada motor al árbitro es trabajo de otras fases, y el rango es justo lo que mide cuánto falta |

El límite honesto de la fase es el último: el rango mide la cobertura **tal como está
cableada hoy**. No la maquilla —al revés: la expone—. Cuando un motor que hoy detecta
pero no entrega señal se cablee al árbitro, su técnica pasará de hueco a detectada sin
tocar el rango, y la cifra subirá sola.

Mensaje de commit:
`test(coverage): implement adversary emulation range with mandatory rollback and automatic detection coverage measurement`
