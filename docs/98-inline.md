# Módulo 98 — AegisInline: reensamblado y corte que no se pueden evadir (FASE 106)

> Componentes: ampliación de `crates/aegis-net/` (perfil de reensamblado) y de
> `crates/aegis-ips/` (latencia medida), `tools/verificar-inline.sh`.

## 98.1 De dónde parte, y el hueco que cierra

El reensamblador TCP de flujo (huecos, orden, solapes contradictorios ya
entregados) vive en `aegis-wire` (FASE 70), y **no se duplica**. Pero tenía dos
límites que son exactamente el margen de evasión: la política de solape era **una
sola, global** (primero-gana / último-gana), elegida a mano por motor; y la
ambigüedad se resolvía **adivinando** con esa política, nunca preguntando al
destino. Esta fase cierra ese margen con una capa de **reensamblado dirigido por el
destino** (target-based) en `aegis-net`.

## 98.2 La superioridad estructural: el perfil es el del destino REAL

Cuando dos segmentos TCP se solapan con contenido distinto, cada sistema operativo
resuelve el solape a su manera. El evasor lo explota: fabrica un flujo que el IDS
reensambla de una forma y el destino de otra, y lo malo viaja en la interpretación
que el IDS no ve. **Suricata adivina** el sistema del destino, por configuración o
por huella. **AegisCore lo sabe**: el endpoint es suyo y le dice su sistema, su
versión y su pila. El perfil de reensamblado se elige con ese dato.

Se implementan las **cinco políticas** clásicas de solape —`Primero`, `Ultimo`,
`Bsd`, `Linux`, `Solaris`— y se demuestra que **la misma evasión se reensambla
distinto** según el destino: los segmentos `[0..4]="AAAA"` y `[2..6]="BBBB"` dan
`AAAABB` bajo `Primero` y `AABBBB` bajo `Ultimo`. AegisCore, con el perfil del
destino real, ve **lo mismo que el destino**; un IDS que adivinara «primero» se
equivocaría.

## 98.3 La ambigüedad se resuelve preguntando al endpoint

Cuando dos interpretaciones de un flujo son posibles —que es justo lo que explota el
evasor—, no hay que adivinar. `ReensambladorPerfil::es_ambiguo` detecta que dos
políticas discrepan, y `politica_segun_endpoint` toma lo que el destino **entregó
de verdad a la aplicación** y devuelve qué política lo explica —o `None` si ninguna
de las cinco lo hace, que es en sí un hecho a reportar—. Nadie en el mundo abierto
puede hacer esto, porque nadie más tiene los dos lados con el mismo modelo de
entidad.

## 98.4 El corte publica su latencia, y el reensamblado no se agota

**Latencia (aegis-ips):** un IPS en línea añade latencia a cada paquete que juzga, y
uno que no la publica esconde su coste. `MedidorLatencia` publica **p50 y p99** —no
la media, que esconde la cola larga que es justo la que duele—, con el percentil
calculado de forma determinista sobre las muestras (método del rango más cercano),
sin depender del reloj de la máquina.

**Agotamiento (aegis-net):** `ReensambladorPerfil` tiene cotas duras de bytes y de
segmentos por flujo. Un atacante que inunda con millones de segmentos a medio abrir
—o fragmentos que nunca completan— se rechaza pasado el techo: los bytes quedan
acotados, sin OOM, y el flujo desbordado se **dice**.

## 98.5 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Perfil de reensamblado por OS del destino | **sí** | `para_sistema` mapea Windows→Ultimo, Linux→Linux, …; desconocido→Primero (el más seguro) |
| Las cinco políticas de solape | **sí** | la misma evasión se reensambla distinto según la política |
| Ambigüedad resuelta preguntando al endpoint | **sí** | flujo ambiguo → `politica_segun_endpoint` confirma la del destino real |
| Segmentos fuera de orden y huecos | **sí** | reordena por seq; un hueco corta el tramo contiguo, no inventa |
| Latencia p50/p99 (no la media) | **sí** | percentil determinista sobre muestras; el p99 no lo esconde la media |
| Reensamblado no agotable | **sí** | cotas duras; una inundación de segmentos se rechaza, bytes acotados |
| Determinismo | **sí** | mismo flujo y política → mismo resultado (Bsd por seq, no por orden de llegada) |
| Disección semántica (HTTP/DNS/TLS) | **no se duplica** | vive en `aegis-wire` (FASE 70); la capa de perfil es target-based reassembly puro |
| Reensamblado de fragmentos IP, TTL, ventana cero, MSS | **incremento siguiente** | la capa de perfil TCP está; los vectores de capa IP/ventana se añaden encima |
| HTTP/2 · HTTP/3 con tramas partidas, migración QUIC | **incremento siguiente** | hoy HTTP/2/3 y QUIC-Initial se reconocen en aegis-wire; el reensamblado de tramas es trabajo declarado |
| Comparativa con los mismos pcaps por Suricata | **muro de entorno** | requiere desplegar Suricata y un corpus; se declara |
| Corte real a 10 GbE | **no aquí** | se mide en hardware real con carga real, no en un contenedor de CI |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—perfil por destino real, cinco políticas, desambiguación por el endpoint, latencia
publicada, cotas— sobre el reensamblador semántico que ya existía, y los vectores de
capa IP/HTTP2/QUIC y la comparativa medida se declaran en vez de fingirse.

Mensaje de commit:
`feat(network): implement endpoint-informed reassembly profiles with proven evasion coverage and measured inline latency`
