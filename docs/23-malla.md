# Módulo 23 — Malla P2P: propagación de vacunas en la red local

> Componente: `crates/aegis-mesh`.

Cuando un agente descubre una amenaza, el resto de la flota queda inmunizado en
milisegundos, sin pasar por la nube.

---

## 23.1 Por qué horizontal y no por la nube

El camino normal —el agente informa a la consola, la consola reparte— tiene dos
problemas justo en el momento en que importa:

1. **Latencia.** Un ataque que se mueve lateralmente va de un equipo al siguiente
   en segundos. Un viaje de ida y vuelta a Internet más el ciclo de sondeo de los
   demás agentes llega tarde.
2. **El atacante ya está dentro.** Si lo primero que hace es cortar la salida a
   Internet, la flota se queda sin actualizaciones precisamente cuando las
   necesita.

La malla no sustituye al canal central: **lo adelanta**. La vacuna llega ya, y
[la sincronización diferencial](14-sync.md) garantiza después la convergencia.

---

## 23.2 Por qué UDP y no QUIC

Un mensaje de esta malla es un hash y cuatro campos: cabe en un datagrama de
menos de 200 bytes. QUIC aporta flujos, control de congestión y establecimiento
de sesión cifrada, y ninguna de las tres cosas sirve para enviar un datagrama
suelto a los vecinos. Lo que sí aportaría es **una pila TLS entera —decenas de
miles de líneas— dentro de un producto de seguridad**, y un apretón de manos por
par antes de poder decir nada.

Se usa UDP con AEAD propio: la misma confidencialidad y autenticidad para este
caso, en un fichero auditable.

Cada mensaje cabe en **un** datagrama de menos de 1200 bytes, sin fragmentar. No
es una limitación, es el diseño: un mensaje fragmentado por IP se pierde entero
si se pierde un fragmento, y reensamblar es una superficie de ataque clásica.

---

## 23.3 La regla que define el diseño: una vacuna sólo puede AÑADIR

La malla se autentica con una clave compartida por todos los agentes de la red
local, así que un atacante que comprometa **un solo** equipo tiene la clave y
puede emitir mensajes válidos.

Si una vacuna pudiera **retirar** un indicador, ese atacante desactivaría la
detección de toda la flota con un único datagrama, desde dentro y con
credenciales legítimas.

Por eso el tipo no tiene variante de revocación, y no es un olvido: quitar un
indicador es una operación privilegiada que viaja por
[el canal de actualización](12-actualizacion.md), firmada con Ed25519 por una
clave que **no está en ningún agente**. La malla es rápida y horizontal; la
revocación es lenta y jerárquica, y eso es lo correcto.

La identidad del emisor sirve para **trazar**, no para **autorizar**: con clave
compartida, cualquier miembro puede hacerse pasar por otro.

---

## 23.4 La disciplina de nonce

Repetir un nonce con la misma clave en AES-GCM no filtra «un poco»: permite
recuperar la clave de autenticación y falsificar mensajes a voluntad.

El nonce es `sesión (8 bytes aleatorios del arranque) ‖ contador (4 bytes)`:

- Dentro de una sesión el contador no se repite jamás, y al agotarse se devuelve
  un error en vez de dar la vuelta.
- Entre arranques la sesión es nueva y aleatoria, así que un agente que se
  reinicia no reutiliza los nonces que ya gastó. **Un contador persistido en
  disco habría sido peor**: un *rollback* del fichero repetiría nonces.

La cabecera va **autenticada pero no cifrada**. Cifrarla obligaría a descifrar
para saber con qué nonce descifrar, que es circular; dejarla fuera del AEAD
permitiría a un atacante cambiar el remitente de un mensaje válido y hacer que la
flota atribuya una vacuna a otro equipo.

---

## 23.5 Las tres cotas que impiden que la malla sea el ataque

| Cota | Qué evita |
|---|---|
| **Saltos** (3 por defecto) | La tormenta de difusión: sin límite, tres agentes que reciben algo nuevo a la vez lo reenvían los tres |
| **Deduplicación** | Los caminos redundantes de la inundación; la identidad de la vacuna **no** incluye los saltos, o la misma vacuna por dos caminos no se reconocería |
| **Tasa por par** | Un par que inunda. La comprobación va **antes** de descifrar, para no regalar un amplificador de CPU |

A eso se suman la **ventana anti-repetición** —el AEAD no impide reenviar un
datagrama auténtico capturado— y el descarte de vacunas **caducadas** o
**fechadas en el futuro**, que es como un atacante haría que una vacuna capturada
no expirase nunca.

Un par caído no impide avisar a los demás: en una red local, «puerto no
alcanzable» es lo normal cuando un equipo se apaga.

---

## 23.6 Cómo se prueba

Con **sockets UDP de verdad** sobre la interfaz local: tres agentes distintos,
cada uno con su clave de sesión y su identidad, que se hablan por la red. Los
ataques —repetición de un datagrama capturado por un espía, clave equivocada,
basura de todos los tamaños, inundación, vacunas viejas— se lanzan desde un
socket externo, como los lanzaría alguien que está en la misma red local.

El **escenario 9** de la simulación de Red Team usa **dos procesos separados**:
la propagación entre hilos del mismo proceso no demostraría que el formato de
red, el cifrado y el descubrimiento funcionan de verdad.
