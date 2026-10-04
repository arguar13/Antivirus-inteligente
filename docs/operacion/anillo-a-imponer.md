# Pasar un anillo de solo-auditoría a imponer

> **Hoy este runbook termina en una decisión escrita, no en un cambio.** El
> agente no tiene modo imponer (FASE 1.5 del MP-16) ni existe la herramienta del
> publicador que firmaría un paquete de contenido con reglas en modo imponer
> (FASE 4.5). Hasta que existan, **ningún anillo pasa a imponer**, aunque los
> números lo permitan. Este documento fija ya cómo se decide, para que la
> decisión no se tome a ojo el día que se pueda.

Imponer es que una detección actúe (negar, matar, aislar) sin una persona en
medio. Un falso positivo en imponer tumba un servicio de un cliente; por eso lo
gobiernan números medidos, nunca una impresión del piloto.

## Los umbrales (del código, no de este texto)

Son las constantes del canal de contenido (`crates/aegis-contenido`, FASE 4.5).
La puerta `runbooks` de `make ci` compara cada fila con el código y falla si
alguien cambia uno de los dos sin el otro.

| Umbral | Constante | Valor |
|---|---|---|
| Muestras benignas mínimas para que una regla pueda imponer | `MIN_MUESTRAS_IMPONER` | 100 000 |
| Falsos positivos por millón de muestras benignas, como mucho (1e-5) | `FP_POR_MILLON_MAX` | 10 |
| Equipos sanos mínimos en el canario antes de ampliar | `MIN_SANOS_CANARIO` | 10 |
| Equipos sanos mínimos en el 5 % antes de la flota | `MIN_SANOS_PORCENTAJE` | 100 |
| Tamaño del anillo del 5 %, en puntos básicos | `CINCO_POR_CIENTO` | 500 |

Y los del piloto, que no son constantes del código:

| Criterio | Exigido |
|---|---|
| Tiempo del anillo en solo-auditoría | Dos semanas como mínimo, sin cambiar de versión de agente ni de contenido en medio |
| Fallos en el escalón anterior | Cero: ni un equipo con S1 o S2 atribuible al agente |
| Sobrecoste | Dentro del presupuesto de memoria del host (`memoria` del diagnóstico, sin `oom_kill`) y la latencia del camino caliente medida por la prueba `sobrecoste-en-vivo` |
| Pérdidas de eventos | Ninguna sostenida (`perdidas` del diagnóstico a cero en reposo) |
| Motores | Los mismos registrados en todos los equipos del anillo, o la diferencia declarada |

## Procedimiento

1. **Recoger** cada día, de cada equipo del anillo, el diagnóstico en JSON:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico --json > "diagnostico-$(date +%F).json"
```

2. **Clasificar** cada veredicto de `ultimos_veredictos` (y de la consola, si el
   plano de control recibe): cierto, falso positivo o sin decidir. Un veredicto
   sin decidir cuenta como falso positivo para esta decisión.
3. **Calcular por regla** los falsos positivos por millón con el corpus
   benigno de la FASE 4 (binarios y scripts de cada imagen de la matriz) más lo
   visto en el anillo. Una regla sin `MIN_MUESTRAS_IMPONER` muestras benignas
   no impone, por buenos que sean sus números.
4. **Escribir la decisión** en la incidencia del anillo: reglas que pasan,
   reglas que no y por qué, los valores medidos frente a cada umbral, y quién
   decide. Sin ese registro no hay paso a imponer.
5. **Aplicar** (cuando exista): publicar el paquete de contenido con esas
   reglas en modo imponer, firmado, solo para el anillo; comprobar en cada
   equipo que lo cargó y en qué modo. *Hoy: no existe; el procedimiento se
   detiene en el paso 4.*
6. **Vigilar** el anillo 48 h con guardia S1 reforzada antes de ampliar al
   siguiente (canario, después 5 %, después flota).

## Volver a auditoría

Es la dirección segura y no exige números: una regla que da un falso positivo
en imponer vuelve a auditoría de inmediato. El canal de contenido lo hará con
unos ajustes firmados que **solo restan** (apagar una regla o bajarla a
auditoría; no existe la variante que sube). Mientras no exista, no hay nada en
imponer que bajar.
