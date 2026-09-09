# Módulo 36 — Prueba de carga: 10.000 agentes contra el plano de control

> Componentes: `server/crates/fleet-simulator/`.

Un plano de control que solo se ha probado con tres agentes no ha demostrado
nada. Este módulo genera una flota de miles de endpoints **reales** contra un
servidor **real** y responde a tres preguntas con números, no con estimaciones.

---

## 36.1 Fidelidad: por qué los agentes virtuales cuentan

Los agentes del simulador usan el **códec auténtico** (`aegis_fleet::proto`), la
**configuración TLS auténtica** (`aegis_fleet::tls::config_cliente`) y
**certificados emitidos por la CA real del servidor**. Los bytes que llegan al
plano de control son indistinguibles de los de un endpoint de producción.

Lo único que cambia es que el transporte es **asíncrono**: un hilo por agente
choca con el límite de hilos mucho antes que con el del protocolo, y el
generador de carga no puede ser el cuello de botella de su propia medida.

---

## 36.2 Dos cargas que parecen una

| | Latidos | Suscripciones |
|---|---|---|
| Forma | conexiones cortas y frecuentes | conexiones **largas**, abiertas |
| 10.000 agentes | ~333 latidos/s, milisegundos cada uno | **10.000 conexiones simultáneas** |
| Concurrencia instantánea | ~2 conexiones | 10.000, y un **hilo por cada una** |
| Qué mide | rendimiento | **escala** |

Esa asimetría es el hallazgo que orientó toda la prueba: con un intervalo de
treinta segundos, diez mil agentes casi no producen concurrencia de latidos. La
escala real la impone el canal de política, que queda abierto.

---

## 36.3 Dos defectos de rendimiento encontrados en el producto

La primera medición dio **55 ms de latencia media por latido** con solo cincuenta
agentes y sin contención. Una latencia alta *y constante* sin carga no es
saturación: es un **coste fijo**. Buscarlo dio dos defectos reales.

### El algoritmo de Nagle: ~40 ms por llamada

Ni el servidor ni el agente desactivaban `TCP_NODELAY`. El protocolo son mensajes
pequeños de petición y respuesta; con Nagle activo, cada extremo retiene su envío
esperando más datos que nunca llegan, y su interacción con el ACK retardado del
otro añade unos 40 ms **a cada llamada**. En una flota de diez mil endpoints, ese
impuesto invisible se paga multiplicado por cada latido.

| | media | p50 | p99 |
|---|---|---|---|
| antes | 55,0 ms | 65,5 ms | 131,1 ms |
| después | **9,4 ms** | 16,4 ms | 32,8 ms |

### El bucle de aceptación sondeaba: hasta 20 ms por conexión

El escuchador era no bloqueante y el bucle **dormía 20 ms** cuando no había nada
que aceptar. Como en este protocolo cada llamada abre una conexión, eso añadía
hasta veinte milisegundos a todas.

Se sustituyó por un `accept` **bloqueante**; la parada ordenada se resuelve
despertándolo con una conexión local que se descarta —el precio de no sondear es
tener que dar exactamente eso, una conexión—.

| | media | p50 |
|---|---|---|
| antes | 9,4 ms | 16,4 ms |
| después | **4,6 ms** | **4,1 ms** |

**Efecto combinado: de 55 ms a 4,6 ms. Doce veces más rápido**, en el producto,
no en el banco de pruebas.

---

## 36.4 Un tercer defecto, esta vez del instrumento

Con los dos arreglos aplicados, el veredicto seguía diciendo *no cumple*: el p99
salía «< 65,54 ms» frente a un objetivo de 50 ms… mientras el **máximo real era
42,17 ms**, por debajo del objetivo.

El problema estaba en el medidor. El histograma usaba cubos de potencia de dos, y
el tramo 32,77–65,54 ms cae justo **encima** del umbral: con esa resolución no se
puede afirmar si se cumple. Se añadieron 32 sub-cubos lineales por potencia, que
bajan el error al 3 %, y una prueba que lo fija: `distingue_por_encima_y_por_debajo_del_objetivo`
comprueba que 42 ms se lee como cumplido y 51 ms como incumplido.

Un instrumento demasiado grueso para juzgar su umbral no es conservador: es
inútil, porque el veredicto depende de en qué lado del cubo caiga la medida.

---

## 36.5 Resultado con 10.000 agentes

```
agentes enrolados   : 10000
canales suscritos   : 10000     (simultáneos)
latidos             : 20000
empujes recibidos   : 20000
fallos de conexion  : 0
fallos de operacion : 0

latido (régimen)    : media=3,04ms  p50<2,82ms  p95<4,86ms  p99<6,91ms  max=20,53ms
```

**p99 de 6,91 ms frente a un objetivo de 50 ms: siete veces mejor.** Sin un solo
fallo.

Coste en el servidor, medido en el pico: **10.006 hilos, 417 MB de RSS y 10.046
descriptores** para diez mil canales abiertos —unos 43 KB por endpoint
conectado—.

### PostgreSQL: sin bloqueos

```
transacciones confirmadas : 90.193
transacciones revertidas  : 0
INTERBLOQUEOS             : 0
sesiones esperando bloqueo: 0
tasa de acierto de cache  : 100,00 %
```

El encargo pedía optimizar el pool de conexiones **si hacía falta**. Con treinta
y dos conexiones no hizo falta, y cambiarlo sin necesidad habría sido tocar por
tocar. La integridad cuadra exactamente: 10.000 agentes y 20.000 latidos en la
base de datos, los mismos que contó el generador.

---

## 36.6 Un cuarto defecto: dos publicaciones de política a la vez

La prueba de carga no lo encontró, y conviene decir por qué: el generador **lee**
política, no la publica. Quien lo encontró fue la suite de integración del plano
de control, que corre sus pruebas en paralelo contra el PostgreSQL real. Una
prueba empezó a fallar de forma intermitente con:

```
duplicate key value violates unique constraint "idx_politica_unica_activa"
```

El mecanismo es el clásico de `READ COMMITTED`, el aislamiento por defecto de
PostgreSQL. Publicar política es un ciclo leer‑modificar‑escribir: desactivar la
vigente, calcular `max(version) + 1`, insertar la nueva. Con dos publicaciones
simultáneas:

1. T1 hace `UPDATE politicas SET activa = FALSE WHERE activa` y bloquea la fila.
2. T2 ejecuta el mismo `UPDATE` y **espera** en esa fila.
3. T1 inserta su política nueva y confirma.
4. T2 se desbloquea y **vuelve a evaluar** la condición sobre la fila ya
   desactivada: no le afecta a ninguna. Y la fila que T1 acaba de insertar no
   entra en la instantánea de esa sentencia, así que tampoco la ve.
5. T2 inserta su propia política activa → choca con el índice único parcial (y
   con la clave primaria de `version`).

El resultado es que **una publicación se pierde** con un error crudo de base de
datos. No es un caso de laboratorio: son dos operadores en la consola, o un
operador publicando mientras la automatización recompila reglas tras ingerir un
bundle STIX — dos caminos distintos del código (`publicar_politica` y
`recompilar_y_publicar`) que escriben la misma tabla y compiten también **entre
sí**.

Primero se reprodujo de forma determinista, con ocho publicaciones concurrentes,
y la prueba falló siempre en la primera vuelta. La corrección es un **cerrojo
consultivo de transacción** al principio de ambos caminos:

```sql
SELECT pg_advisory_xact_lock($1)   -- 0x4145474953504F4C  ("AEGISPOL")
```

Por qué ese y no otro:

| Alternativa | Por qué no |
|---|---|
| Subir a `SERIALIZABLE` | Obliga a lógica de reintento en **todo** el servidor, no solo aquí, y a que cada llamador sepa distinguir un fallo reintentable. |
| `LOCK TABLE ... IN EXCLUSIVE MODE` | Funciona, pero es un cerrojo pesado sobre una tabla que además leen los latidos de toda la flota. |
| Serializar en el proceso (un mutex) | **No sirve**: el plano de control se despliega con varias instancias detrás del balanceador. Un mutex de proceso no las coordina. |

El cerrojo consultivo es del ámbito del *clúster*, así que sigue valiendo con
varias instancias; y al ser `_xact_` se libera solo al confirmar o deshacer la
transacción, sin ninguna ruta de fuga. Con él, las ocho publicaciones
simultáneas se serializan, cada una recibe su propia versión y la flota nunca
queda sin política activa.

La prueba que lo reprodujo se queda en la suite
(`publicaciones_de_politica_simultaneas_se_serializan_sin_perder_ninguna`):
un fallo intermitente que se «arregla» sin dejar una prueba que lo fije vuelve.

---

## 36.7 Lo que la prueba mide aparte, y por qué

El **arranque** se mide en un histograma distinto del **régimen estacionario**:

```
enrolamiento : media=622,51ms  p95<2555,90ms  max=11487,98ms
arranque     : media=155,69ms  p95<1114,11ms  max=11436,36ms
latido       : media=3,04ms    p95<4,86ms     max=20,53ms
```

Diez mil agentes conectándose a la vez es una **avalancha**, y en producción no
ocurre: los endpoints ya están corriendo. Mezclarla con el régimen normal mediría
una cosa distinta de la que se quiere afirmar.

Pero tampoco se esconde, porque **sí ocurre en un caso real**: cuando el plano de
control se reinicia y toda la flota reconecta a la vez. Ese escenario cuesta
segundos de latencia de enrolamiento, y conviene saberlo antes de programar un
mantenimiento.

Un detalle del mismo tipo: los agentes reparten su ciclo sobre el intervalo
**entero**. En una primera versión el desfase cubría solo la mitad y el ritmo
oscilaba entre 88 y 12 latidos por segundo — picos y valles que una flota real no
tiene, inventados por el generador.

---

## 36.8 Uso

```
fleet_simulator --agentes 10000 --duracion 60 --intervalo 30 \
    --calentamiento 35 --modo mixto --rampa 500 \
    --servidor 127.0.0.1:8443 --ca-dir /var/lib/aegis/ca
```

| Opción | Para qué |
|---|---|
| `--modo latidos` | solo rendimiento |
| `--modo suscripciones` | solo escala de canales abiertos |
| `--rampa` | cuántos se enrolan a la vez, para no medir la avalancha |
| `--calentamiento` | segundos iniciales que no deciden el veredicto |
| `--objetivo-ms` | umbral de p99 que se comprueba al final |

Sale con código distinto de cero si el objetivo no se cumple o si hubo fallos:
sirve como puerta automática, no solo como informe para leer.
