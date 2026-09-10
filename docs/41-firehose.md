# Módulo 41 — Firehose: la auditoría llega al SIEM o sigue en disco

> Componentes: `crates/aegis-firehose/`,
> `server/crates/aegis-server/src/firehose.rs`.

Un EDR produce evidencia que el cliente tiene que conservar: para responder,
para cumplir, y a veces para un juicio. Esa evidencia sale hacia el SIEM del
cliente, y el SIEM se cae, se satura, se reinicia por mantenimiento un martes
por la noche.

Un productor que envíe y olvide pierde exactamente los registros del rato en que
el SIEM no estaba — que es, con demasiada frecuencia, el rato en que el atacante
contaba con que no estuviera.

---

## 41.1 El diario es la fuente de la verdad, no la cola

Una cola en memoria pierde todo lo que tenga dentro cuando el proceso muere. Da
igual lo bien escrita que esté: un corte de corriente, el OOM killer o un
`kill -9` durante un despliegue se llevan la evidencia. Y el momento en que el
plano de control es más probable que muera es exactamente el momento en que más
evidencia está produciendo.

El orden es **escribir en disco, sincronizar, y solo entonces admitir**. Lo que
se le devuelve al productor es una promesa ya cumplida, no una intención.

### Lo que «sin pérdida» significa exactamente

Un `fsync` por registro limita el caudal a los IOPS del disco: unos cientos por
segundo en un disco giratorio. Con diez mil endpoints eso no da. Se hace
confirmación en grupo, y **la consecuencia se dice en vez de esconderse**: entre
que un registro se escribe y que su lote se sincroniza hay una ventana en la que
un corte de corriente lo perdería. Esa ventana está acotada por dos ajustes y
quien despliega decide su tamaño; con lote de 1 no hay ventana y el caudal es el
del disco. Un producto que dijera «cero pérdida» sin explicar esto estaría
mintiendo.

### El CRC no es contra un disco malicioso

Es contra la **escritura a medias**: el proceso murió mientras escribía. Sin él,
al reiniciar se leería una longitud plausible seguida de basura y se enviaría al
SIEM un registro de auditoría inventado.

**Un registro de auditoría falso es peor que uno perdido: el perdido se nota, el
falso no.** Hay prueba de las dos cosas — la cola a medias se trunca y se
cuenta; un byte alterado en medio impide que ese registro salga.

---

## 41.2 Confirmar es lo último, y por eso nada se pierde

```text
leer del diario  →  entregar  →  esperar el acuse  →  confirmar
```

Cada flecha se puede romper:

- muere después de leer → el registro sigue en disco;
- muere después de entregar pero antes de confirmar → sigue en disco y se
  reenvía; el destino lo ve dos veces;
- muere después de confirmar → ya estaba entregado.

Confirmar **antes** de entregar convertiría «al menos una vez» en «como mucho
una vez»: exactamente lo contrario de lo que hace falta en auditoría, y de una
forma que no se nota hasta que alguien busca la evidencia y no está.

El precio es el duplicado, y se paga a conciencia: cada registro lleva su
identificador de evento y el SIEM desduplica por él. Se documenta porque un
duplicado que el integrador no espera acaba contando dos veces un incidente en
un informe de cumplimiento.

---

## 41.3 Cuando el disco se acaba hay que ceder algo, y la elección es explícita

Un EDR que llenara el disco del cliente para no perder un registro habría
cambiado un fallo por otro peor: la máquina entera deja de funcionar, incluido
el propio EDR.

| Política | Qué cede | Cuándo |
|---|---|---|
| `Rechazar` (por defecto) | Lo nuevo. El productor recibe un error | Cuando la integridad de la auditoría manda |
| `DescartarMasAntiguos` | Lo viejo | Cuando la telemetría reciente vale más que la histórica |

El valor por defecto es el que falla **ruidosamente**: un registro de auditoría
que desaparece sin que nadie se entere es exactamente lo que un atacante quiere.
Y en las dos políticas, lo descartado **se cuenta y se publica**.

---

## 41.4 Un salto de línea en una línea de comandos no puede fabricar un evento

La forma tradicional de meter syslog en TCP es separar mensajes con `\n`. Es una
vulnerabilidad, no una simplificación: los mensajes de un EDR llevan líneas de
comandos de procesos, y una línea de comandos puede contener un salto de línea
**porque la escribe el atacante**.

```text
<134>1 ... proceso ejecutado: cmd.exe /c whoami
<134>1 2026-01-01T00:00:00Z servidor - - - todo correcto
```

El SIEM vería dos eventos, y el segundo lo escribió el atacante: puede
fabricarse acuses de inocencia, enterrar la sospecha de una investigación o
desbordar una regla de correlación, todo desde el nombre de un proceso.

El marcado por conteo de octetos (RFC 6587) lo hace imposible **por
construcción**: el receptor lee exactamente los bytes que se le anuncian y lo
que haya dentro es carga, no sintaxis. No hay nada que escapar y, por tanto,
nada que se pueda olvidar escapar. Verificado de extremo a extremo contra un
colector TLS real: el colector ve **un** evento con el texto inyectado dentro.

Lo que el conteo de octetos no protege es la **cabecera** — un hostname con un
espacio corre los campos siguientes y el SIEM lee la fecha donde debería leer el
programa — así que esos campos sí se sanean. El mensaje no, porque ahí no hace
falta y recortarlo sería perder evidencia.

Dos detalles más que se comprueban: la longitud se cuenta en **bytes** (un
nombre de fichero con eñes desincronizaría la sesión entera si se contaran
caracteres) y la severidad **no se degrada** a informativa, porque de eso
dependen las reglas de enrutado del cliente.

---

## 41.5 La dispersión del reintento no es un adorno

Diez mil productores detectan la caída en el mismo segundo. Con retroceso
exponencial puro reintentan todos en el mismo instante: 1 s, 2 s, 4 s, 8 s,
siempre a la vez. El SIEM vuelve, recibe diez mil conexiones simultáneas, se cae
otra vez. **El mecanismo puesto para tolerar la caída es lo que impide que se
recupere.**

Cada reintento espera un tiempo aleatorio *dentro* de la ventana. Hay techo,
porque sin él una caída larga deja al SIEM disponible diez minutos sin que nadie
le envíe nada; y hay reinicio al primer éxito, porque un destino que se cae y se
recupera cada pocos minutos no puede quedarse con la espera en el techo para
siempre.

---

## 41.6 Los dos destinos no son equivalentes, y se dice

| | Acuse | Qué se puede afirmar al confirmar |
|---|---|---|
| Syslog/TLS | **No existe** en el protocolo | Que los bytes salieron y el otro extremo los reconoció a nivel de TCP |
| Kafka | Escritura replicada (`acks=all`) | Que el registro está en el clúster del cliente |

Syslog sobre TCP no tiene acuse de aplicación. Si el SIEM acepta la conexión y
muere antes de indexar, esos registros se pierden y aquí parecerían entregados.
Se reduce la ventana todo lo que el protocolo permite —escribir el lote entero,
vaciar el buffer, no dar nunca por bueno un lote escrito a medias— y se dice
claramente que es más débil. Presentar los dos destinos como equivalentes sería
ocultar la diferencia que importa.

En Kafka hay tres ajustes que **no** se pueden relajar desde la configuración:

- `acks=all`, porque con `acks=1` el líder acusa antes de replicar y, si muere
  en ese instante, el registro se pierde con el visto bueno del productor — y la
  bomba ya lo habrá borrado del diario;
- `enable.idempotence=true`, porque sin ella un reintento interno duplica y
  además puede **reordenar**: un «proceso terminado» delante de su «proceso
  creado» convierte una línea de tiempo forense en ruido;
- `max.in.flight ≤ 5`, que es el límite que la idempotencia admite manteniendo
  el orden.

Se aplican **después** de los ajustes del despliegue, para que nadie pueda
ponerlos «por rendimiento». Hay prueba.

### Y TLS con verificación, no negociable

Los registros llevan rutas, líneas de comandos y nombres de usuario de la red
del cliente: es un mapa de su infraestructura viajando por ella. Sin autenticar
al servidor, cualquiera que responda en ese puerto recibe la telemetría de
seguridad completa **y puede además dejar de reenviarla**, que es una forma
silenciosa de cegar el SOC. Sin ancla de confianza el destino ni se construye.

---

## 41.7 Qué se verificó y qué no

Se ejecuta de verdad, en cada `make ci`:

- el diario contra el sistema de ficheros real, incluida la muerte a media
  escritura y la corrupción de un byte;
- las dos políticas de presupuesto, con sus contadores;
- la entrega de extremo a extremo contra un **colector Syslog TLS real** — con
  su certificado y su handshake — incluidas la caída del colector, la
  recuperación, el reenvío de lo no confirmado y el rechazo de un colector con
  otra CA;
- el camino completo del producto: una alerta reportada por un endpoint acaba en
  el SIEM, y la evidencia producida con el SIEM caído llega cuando vuelve;
- del destino Kafka, la propiedad cuya rotura sería catastrófica: **que un
  destino inalcanzable nunca devuelve éxito**, contra la librdkafka real. Un
  éxito falso haría que la bomba borrase del diario evidencia que no llegó a
  ninguna parte.

**No se ejecutó:** la verificación de extremo a extremo del destino Kafka contra
un corredor real. Este entorno de desarrollo no tiene salida hacia los archivos
de Apache —tres intentos, dos bloqueados por la política de red y uno agotado
por tiempo— y no hay ningún corredor accesible.

La verificación **está escrita y es ejecutable**: `tools/verificar-kafka.sh`, y
`make ci` la ejecuta e informa de si se pudo o no. La diferencia entre «probado
contra un corredor» y «no había corredor aquí» se ve en la puerta de calidad, no
se queda en un comentario del código.

---

## 41.8 Por qué la exportación no bloquea la ingesta

Cada alerta se escribe en el diario **antes** de que la llamada que la produjo
devuelva. Lo que no se hace es enviarla desde ahí: un endpoint que reporta una
alerta no puede quedarse esperando a que el SIEM del cliente conteste. Si el
SIEM está lento, diez mil agentes se bloquearían detrás de él y el EDR dejaría
de recibir telemetría justo por intentar exportarla.

Y si el diario está lleno, el error **no se propaga al agente**: la alerta ya
está en PostgreSQL, que es la fuente de la verdad del producto, y rechazarla
haría que el endpoint la reintentara y la duplicara allí. Lo que se pierde es la
exportación, y se cuenta.

La exportación corre en un **hilo propio**, no en el runtime: bloquea en E/S de
disco y de red, y hacerlo en un worker de tokio castigaría a los latidos de diez
mil agentes.

---

## 41.9 Uso

```bash
export AEGIS_FIREHOSE_DIR=/var/lib/aegis/auditoria
export AEGIS_SYSLOG_SERVIDOR=siem.cliente.local:6514
export AEGIS_SYSLOG_NOMBRE=siem.cliente.local
export AEGIS_SYSLOG_CA=/etc/aegis/siem-ca.pem
export AEGIS_FIREHOSE_PRESUPUESTO=4294967296   # 4 GiB

# Verificar el destino Kafka contra un corredor real
AEGIS_KAFKA=localhost:9092 ./tools/verificar-kafka.sh
```
