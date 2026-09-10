# Módulo 40 — Heurísticas globales: detección de APT distribuida

> Componentes: `server/crates/aegis-server/src/heuristicas.rs`,
> `.../correlador.rs`, migración `0005_heuristicas.sql`.

Un operador de APT competente no dispara ninguna alerta en ninguna máquina.
Ejecuta `nltest /dclist` en una, `whoami /groups` en otra, monta un recurso
compartido en una tercera. Cada endpoint ve una acción administrativa normal
—de hecho lo es, tomada de una en una— y ninguno tiene motivo para avisar.

Lo que delata la campaña está en el **conjunto**: cincuenta máquinas enumerando
el dominio bajo la misma cuenta en cuarenta y ocho horas no es administración,
es reconocimiento. Ese hecho no existe en ningún endpoint. Solo existe en el
plano de control, porque es el único que ve las cincuenta.

---

## 40.1 Lo que faltaba: algo con lo que agrupar

Hasta ahora una alerta llevaba una categoría y una descripción. La descripción
es para que la lea una persona; correlacionar necesita algo con lo que
**agrupar**: la cuenta bajo la que se ejecutó, el hash del binario, la dirección
de destino.

Sacar eso de la descripción con expresiones regulares en el plano de control
sería convertir un texto libre —que cada detector escribe a su manera y que
cambia con cada versión del agente— en el eje de una detección. Así que las
alertas llevan ahora atributos estructurados, y el plano de control los
normaliza antes de persistirlos:

| Regla | Qué pasa sin ella |
|---|---|
| Solo escalares (texto, número, booleano) | `detalles ->> 'cuenta'` sobre un objeto devuelve su texto JSON: dos endpoints que informan lo mismo con las claves en otro orden caen en grupos distintos y la campaña que los une no se ve |
| Techo de 4 KiB y 32 atributos | Son millones de alertas: sin techo, un agente comprometido convierte el histórico de seguridad en su almacenamiento gratuito, y el disco se llena justo cuando hace falta registrar el incidente |
| Un nulo se descarta | Dejarlo pasar crearía un grupo «sin valor» que reúne todo lo que no se pudo ver — el grupo más grande de la flota, disparando siempre |
| Vacío es válido | «Este detector no aporta atributos» es una respuesta legítima. Lo que no puede hacer es inventárselos |

---

## 40.2 Por qué la regla tiene forma fija y no es un lenguaje

La tentación es un segundo lenguaje de consulta. Ya hay uno —AegisQL,
[módulo 38](38-caza.md)— y sirve para otra cosa: preguntar al endpoint. Una
correlación de flota tiene una forma fija —qué buscar, por qué agrupar, en
cuánto tiempo, cuántos endpoints— y con campos la valida el esquema. Un
analizador de texto libre sería código que puede equivocarse sobre algo que
decide si se lanza una respuesta automática contra la flota de un cliente.

Lo que el esquema no puede comprobar, lo comprueba la validación:

- **Una regla que no busca nada** casa con toda alerta de la flota. No es una
  detección: es un contador de alertas con nombre de detección.
- **Una técnica con espacios** (`"T1087 lateral"`) no casa con nada. Aceptarla
  dejaría al analista con una detección que cree activa y que no dispara nunca.
  Un fallo ruidoso al crearla es infinitamente mejor que una regla muda.
- **Un solo endpoint** no es una correlación distribuida: la produciría el
  propio endpoint comprometido sin que ninguna otra máquina la corrobore.
- **Una ventana de dos meses** hace que casi cualquier cuenta de servicio de una
  flota grande toque cincuenta máquinas. La regla dispararía siempre.

---

## 40.3 Endpoints distintos, no alertas

Es la diferencia entre una detección y un contador. Un endpoint ruidoso que
ejecuta `whoami` quinientas veces no es movimiento lateral, y contar alertas lo
convertiría en una campaña de APT de quinientas máquinas.

Y es también lo que impide el ataque de inflación: **un endpoint comprometido no
puede fabricar una correlación él solo** para provocar con ella una respuesta
automática contra el resto de la flota. Hay prueba: doscientas alertas del mismo
endpoint no abren nada.

El caso contrario —un agente comprometido que *oculta* o antedata sus propias
alertas para no aparecer en el recuento— no se puede evitar, y no se finge lo
contrario: es cierto de cualquier telemetría de endpoint. Lo que se hace es no
depender de ella para contener: la [cuarentena de enjambre](39-cuarentena.md) la
aplican las máquinas sanas, no la comprometida.

## 40.4 La ventana se recorre por cuándo ocurrió, no por cuándo llegó

Un endpoint que estuvo apagado un día entrega sus alertas al reconectar. Con la
hora de llegada, esas alertas caerían todas en el mismo instante: una campaña
repartida en dos días parecería un pico de un segundo, o al revés, una campaña
real quedaría fuera de la ventana porque su evidencia llegó tarde.

---

## 40.5 Una campaña es una correlación, no cuatro mil

El motor evalúa cada minuto y la evidencia sigue en la ventana de 48 horas. Sin
idempotencia, una campaña que dura tres días produce cuatro mil correlaciones
idénticas: el analista no ve una campaña, ve una tormenta — que es exactamente
el ruido por el que se dejan de mirar las alertas.

Lo garantiza un **índice único parcial** en la base de datos, no el código: el
plano de control corre con varias instancias y dos de ellas pueden evaluar a la
vez. La evaluación siguiente actualiza la que ya existe. `vista_en` solo avanza
si la evidencia **creció**: una campaña que sigue creciendo está en curso; una
que lleva dos días igual es historia, y hay que poder distinguirlas de un
vistazo.

La evidencia se **materializa** en vez de recalcularse. La ventana es
deslizante: dentro de dos días la consulta que encontró la correlación ya no
devolvería las mismas máquinas, y el analista que abre el caso el martes tiene
que ver la evidencia que lo abrió el lunes.

### Cerrar un falso positivo tiene que impedir que vuelva

La cuenta de servicio que inventaría el dominio cada noche es el falso positivo
clásico de esta clase de detección. Cerrar la correlación no basta: la evidencia
sigue en la ventana y el motor la vuelve a encontrar un minuto después,
reabriendo exactamente lo que el analista acaba de descartar. A la tercera vez,
nadie mira las correlaciones.

Por eso cerrar como falso positivo **excluye la clave de la regla en la misma
transacción**. En la misma, y no en dos: si se cerrara y fallara la exclusión,
quedaría cerrada y reabriéndose en bucle. Y excluir una clave no puede dejar la
regla ciega para las demás — hay prueba de las dos cosas.

---

## 40.6 El coste, medido

El motor es un **temporizador**, no un disparo por evento. Una flota de diez mil
endpoints entrega miles de alertas por minuto y cada evaluación es una
agregación sobre la ventana entera: evaluar por alerta multiplicaría ese coste
por el número de alertas para obtener exactamente la misma respuesta —una
correlación sobre cuarenta y ocho horas no cambia por una alerta más—.

Lo que se pierde es latencia, y la cantidad correcta se deduce de lo que se
busca: una campaña que tarda dos días en desplegarse no se escapa por medio
minuto. Lo que no puede pasar es lo contrario: que el motor consuma la base de
datos que necesitan los latidos de diez mil agentes, las cacerías y la difusión
de cuarentena.

Medido con **200.000 alertas de 10.000 endpoints repartidas en 48 horas** y 500
cuentas distintas (veinte alertas por endpoint en dos días: para un EDR que solo
avisa de hallazgos reales es una cifra alta, no media):

| Versión | Una vuelta completa |
|---|---|
| Una consulta de evidencia por grupo (N+1) | agregación 298 ms + evidencia **6.771 ms** |
| Dos consultas: grupos, y evidencia de todos a la vez | 743 ms |
| Una sola consulta | **~1,05 s** |

La primera versión recorría la ventana entera cien veces —una por grupo— para
quedarse cada vez con una clave: veintitrés veces más cara que el trabajo útil,
repetida cada minuto. Ahora el agrupamiento por `(clave, endpoint)` se hace una
vez y de él salen las dos cosas: los totales del grupo y el reparto por
endpoint. Los dos topes —cien grupos por regla, mil endpoints por grupo— se
aplican **dentro** de la consulta: traerse cuarenta mil filas para recortar
después sería mover por la red lo que se va a tirar.

Con el periodo de 60 segundos, eso es un 1,8 % de ciclo de trabajo.

> Sobre el tope de la prueba: el primer valor que puse fue 1.000 ms, elegido
> antes de medir nada. La medida dio 1.030 ms de forma consistente, así que la
> prueba fallaba por treinta milisegundos de ruido de planificación en vez de
> por una regresión. Un tope que falla por ruido no protege: se acaba
> desactivando. El tope es ahora de 3 s —tres veces lo medido— porque lo que hay
> que garantizar no es un número redondo sino que una vuelta quepa holgadamente
> en su periodo.

---

## 40.7 La consola

Una pestaña «Campañas» con las correlaciones abiertas, ordenadas por la que más
recientemente creció. Al abrir una, la evidencia: qué máquinas y cuánto aportó
cada una.

El aviso en vivo se publica **solo cuando la correlación se abre por primera
vez**, no en cada evaluación: una consola que avisa cuatro mil veces de lo mismo
deja de mirarse.

La clave agrupada la escribe, indirectamente, un endpoint potencialmente
comprometido, así que se pinta con `textContent` y nunca con `innerHTML`.
Verificado en navegador real: una clave `<img src=x onerror=…>` llega al DOM
escapada y no ejecuta nada.

---

## 40.8 Uso

```bash
# Crear la regla del ejemplo canonico
curl -X POST http://servidor:8080/api/heuristicas \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"nombre":"reconocimiento-distribuido",
          "patron":"Movimiento Lateral Distribuido",
          "tecnicas":["T1087"],
          "clave_detalle":"cuenta",
          "ventana_horas":48,
          "minimo_endpoints":50,
          "tecnica_mitre":"T1087","tactica_mitre":"Descubrimiento"}'

curl http://servidor:8080/api/correlaciones -H "Authorization: Bearer $TOKEN"
curl http://servidor:8080/api/correlaciones/$ID -H "Authorization: Bearer $TOKEN"

# Descartar: excluye esa clave de la regla, en la misma transaccion
curl -X POST http://servidor:8080/api/correlaciones/$ID/cerrar \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"veredicto":"falso_positivo"}'
```

Y para medir el coste con un histórico realista:

```bash
AEGIS_BENCH_CORRELACION=1 cargo test -p aegis-server \
    --test correlacion_escala -- --nocapture
```
