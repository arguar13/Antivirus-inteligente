# Módulo 39 — Cuarentena de enjambre: micro-segmentación Zero-Trust

> Componentes: `crates/aegis-net/src/segmentacion.rs`,
> `server/crates/aegis-server/src/pizarra.rs`, migración `0004_cuarentena.sql`.

Un endpoint está comprometido y se está moviendo lateralmente. Aislar *esa*
máquina no basta: para cuando el analista pulsa el botón, el atacante puede
llevar minutos hablando con otras. La cuarentena de enjambre le da la vuelta al
problema: en vez de cortarle la red al infectado, **el resto de la flota deja de
aceptar su tráfico**.

---

## 39.1 Por qué hacen falta dos mecanismos y no uno

XDP es el punto más temprano del camino de recepción —antes de `sk_buff`, antes
de netfilter— y por eso es donde el bloqueo cuesta menos. Pero **XDP solo existe
en el ingreso**: no hay gancho XDP de salida. Un endpoint sano con la orden
puesta descartaría lo que le llega del comprometido y aun así seguiría
iniciando conexiones hacia él.

Así que el segmentador aplica dos cosas distintas por el mismo motivo:

| Sentido | Mecanismo | Por qué ese |
|---|---|---|
| Entrada | mapa XDP | Lo más temprano posible: se descarta antes de asignar `sk_buff` |
| Salida | cadena `output` de nftables | Porque XDP no tiene gancho de salida, no por preferencia |

`Segmentador` reconcilia estado, no ejecuta órdenes sueltas: compara lo que
debería estar aplicado con lo que está y devuelve `Reconciliacion { anadidas,
retiradas, solo_entrante, solo_saliente, fallidas }`. `solo_entrante` y
`solo_saliente` no son ruido: una dirección que quedó bloqueada en un sentido y
no en el otro es exactamente el estado que un operador tiene que ver.

---

## 39.2 Las direcciones propias se excluyen en el endpoint, no en el servidor

La lista viaja **entera** a cada agente, incluida la dirección del propio agente
si la tuviera. Excluirla en el plano de control obligaría a saber cuál es —otra
consulta por agente, y aun así solo conoceríamos la que vimos en el handshake,
no las demás interfaces—.

Quien sabe todas las direcciones de una máquina es la máquina. El segmentador
del endpoint se salta las suyas (`con_propias`) antes de aplicar nada: sin eso,
una cuarentena que incluyera por error la dirección de un endpoint sano lo
dejaría sin red por su propia mano.

El plano de control aplica la misma idea a sí mismo: `negar_si_es_intocable`
rechaza poner en cuarentena una dirección por la que él escucha. Si la aceptara,
cada endpoint de la flota dejaría de poder hablar con él —incluido para recibir
la orden de levantar esa misma cuarentena—, y la recuperación sería ir máquina
por máquina.

---

## 39.3 Difundir a diez mil endpoints en menos de 200 ms

El compromiso es que la orden esté en el cable para toda la flota en menos de
200 ms. Llegar ahí costó cuatro defectos, todos encontrados **midiendo**, no
leyendo.

| Versión | Transacciones | Empujes | Último endpoint |
|---|---|---|---|
| Consulta por canal | 418.162 | — | 5.304 ms |
| Con caché en memoria | 426.084 | — | 3.778 ms |
| Con atajo «al día» (defectuosa) | 60.242 | 7.040.987 | 25.911 ms, y solo 5.124 de 10.000 |
| Con estado por contenido | — | 37.103 | 779 ms |
| Con el aviso de cuarentena separado | — | 36.716 | 370 ms |
| Con la pizarra | — | 36.991 | **160 / 145 / 117 ms** |

Las tres últimas cifras son tres corridas consecutivas, 10.000 de 10.000
endpoints cada una.

### La caché: una consulta, no diez mil

La cuarentena es idéntica para toda la flota. Consultarla por canal convertía
una orden de contención en diez mil consultas sobre un pool de treinta y dos
conexiones. Con la caché es **una** lectura de base de datos y diez mil
escrituras en sockets.

### El bucle cerrado: siete millones de empujes

El atajo que evitaba consultar la base de datos en cada vuelta se apoyaba en los
canales de notificación de tokio. Los receptores se clonaban por vuelta y
heredaban la versión del original, que no consume nada: en cuanto había habido
un solo aviso, la espera dejaba de esperar y el canal reenviaba la misma orden a
toda velocidad. **Siete millones de empujes en veinticinco segundos**, provocados
por una sola orden de contención —una denegación de servicio que se causa el
propio producto justo cuando está conteniendo un incidente—.

La raíz no era el clon: era preguntar *«¿me han avisado?»*. Un canal que está
escribiendo el empuje anterior cuando llega la orden no estaba mirando, y se
quedaría sin ella hasta el siguiente cambio, que puede no llegar nunca. La
pregunta correcta es *«¿hay algo que este canal no haya atendido?»*, que no
depende de si estaba mirando. `EstadoCanal` lleva esa cuenta y la condición se
evalúa bajo el mismo cerrojo que usa quien publica: ni se pierde un cambio ni se
despierta de más.

### Dos despertares por orden

El aviso de cuarentena viajaba en el mismo canal que los de política y cacería,
que esperan los diez mil. Cada orden despertaba a todos **dos veces**: una por
el aviso —que no podían atender todavía, porque la lista aún no estaba en la
caché— y otra por la publicación de la caché. Peor que inútil: un canal que
contestara al primer despertar enviaría la lista *anterior*, y como el aviso ya
pasó, no habría un segundo intento. La orden se perdía en silencio para ese
endpoint.

El aviso de cuarentena tiene ahora su propio canal, con **un** suscriptor: la
tarea que refresca la caché. Los canales esperan la publicación de esa caché,
que es lo único que pueden atender.

### La pizarra: la primitiva que corresponde a diez mil hilos

Con lo anterior arreglado, la difusión seguía tardando 365 ms con la máquina a
la mitad de su capacidad. No faltaba CPU: **sobraba serialización**.

El transporte de flota es un hilo del sistema por conexión. Esperar ahí con
canales de tokio obliga a cada hilo a entrar en el runtime en cada vuelta para
inscribirse en dos esperas y dar de alta un temporizador de keepalive. Con diez
mil hilos, eso son veinte mil inscripciones, diez mil altas y diez mil bajas en
la rueda de temporizadores —que los hilos ajenos al runtime comparten— y diez
mil despertares individuales por cada orden. Todo ese trabajo lo hace en serie
quien publica, mientras los endpoints esperan.

Un cerrojo y una variable de condición son la primitiva que corresponde a diez
mil hilos bloqueados: `notify_all` es **una** llamada al sistema que despacha a
todos, no diez mil; la espera con plazo es la propia `wait_timeout_while`, así
que no hay temporizadores; y no hay nada en que reinscribirse. El camino rápido
—una cuarentena nueva— ya no entra en el runtime en absoluto.

---

## 39.4 Qué se mide, y por qué se publican dos números

El simulador mide cuándo cada agente **recibe** la orden. Es lo que le importa
al cliente. Pero en un banco de pruebas de una sola máquina ese número incluye
también lo que tardan diez mil agentes virtuales en despertar y leer sus
sockets, compitiendo por los mismos cuatro núcleos que el servidor. En
producción esos diez mil agentes están en diez mil máquinas distintas.

Por eso el plano de control publica su propia medida en
`/api/cuarentena/difusion`: desde que la lista queda publicada hasta que el
**último** canal terminó de escribirla en su socket. El cronómetro lo cierra la
escritura, no la composición del empuje: un canal puede componer y morir al
escribir, y contar ahí de más sería decir que una contención se difundió a
máquinas que nunca la recibieron.

Se publican las dos. Dar solo la del banco atribuye al producto un coste que es
del banco; dar solo la del producto esconde lo que el banco cuesta.

El reparto (`p50`, `p90`, `p99`) no es adorno: el máximo dice **si** se cumple
el objetivo, el reparto dice **por qué** no. Una mediana pegada al máximo
significa que el cuello está en el coste por canal; una mediana muy por debajo
significa que hay un puñado de rezagados. Son dos diagnósticos opuestos con el
mismo máximo, y fue el reparto plano (p50 de 138 ms contra un máximo de 257 ms)
lo que señaló la serialización.

El veredicto se juzga sobre la medida del **producto**, y no por relajar el
criterio: se sigue exigiendo que la orden llegue a **todos** los endpoints —una
difusión rapidísima al 80 % de la flota deja al 20 % hablando con una máquina
comprometida— y que el plano de control la haya puesto en el cable para todos
los canales suscritos. Si el servidor no publicara la medida, se juzga la de
extremo a extremo: es peor, pero es honesto.

---

## 39.5 Uso

```bash
# Poner una dirección en cuarentena en toda la flota
curl -X POST http://servidor:8080/api/cuarentena \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"direccion":"10.0.0.5","motivo":"baliza Cobalt Strike","horas":24}'

# Contra un endpoint concreto, tomando su dirección vista en el handshake
curl -X POST http://servidor:8080/api/agentes/$CN/cuarentena \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"motivo":"movimiento lateral"}'

# Ver la lista vigente y levantar una
curl http://servidor:8080/api/cuarentena -H "Authorization: Bearer $TOKEN"
curl "http://servidor:8080/api/cuarentena?levantar=10.0.0.5" -H "Authorization: Bearer $TOKEN"

# La medida de difusión del propio plano de control
curl http://servidor:8080/api/cuarentena/difusion -H "Authorization: Bearer $TOKEN"
```
