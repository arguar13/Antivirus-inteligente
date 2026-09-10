# Módulo 38 — Caza distribuida: AegisQL

> Componentes: `crates/aegis-parser/`, `crates/aegis-hunt/`, `server/panel/`,
> migración `0003_cacerias.sql`.

Un analista del SOC sospecha que hay una baliza Cobalt Strike en la flota. Sin
esto, su única opción es pedir a alguien que se conecte máquina por máquina. Con
esto, escribe una pregunta y toda la flota responde:

```sql
SELECT pid, path, sha256 FROM processes
 WHERE network.port = 4444 AND memory.entropy > 7.0
 ORDER BY memory.entropy DESC
 LIMIT 50
```

---

## 38.1 Tres invariantes que el lenguaje impone por construcción

El texto lo escribe un operador remoto y se ejecuta con privilegios en decenas de
miles de máquinas ajenas. Las garantías no pueden depender de comprobaciones que
alguien pueda olvidar:

**Es de solo lectura.** No hay `INSERT`, `UPDATE`, `DELETE` ni forma de invocar
código. La gramática *no puede expresar* una modificación, así que no hay lista
negra que mantener ni nada que se escape. Hay una prueba que deja constancia de
que sigue siendo así.

**Su coste es acotable.** No hay `JOIN` ni subconsultas ni bucles. Un `JOIN` sin
restricciones tiene coste cuadrático, y aquí quien lo paga es el portátil o el
servidor de producción del cliente. En su lugar, las tablas exponen columnas
**cualificadas** (`network.port`, `memory.entropy`) que son cuantificadores
existenciales sobre la colección de cada fila. El trabajo máximo es «filas por
tamaño de la colección», y las dos cosas tienen techo.

**Se valida antes de salir de la consola.** Tablas, columnas y tipos se comprueban
al analizar, en el plano de control. Sin eso, una columna mal escrita se
convertiría en diez mil fallos remotos por un error que se veía antes de pulsar
«ejecutar».

```
error: la tabla 'processes' no tiene la columna 'pdi'
  1 | SELECT pdi FROM processes
    |        ^^^
  ayuda: quiza querias decir 'pid'
```

---

## 38.2 Límites contra entrada adversaria

| Límite | Qué pasa sin él |
|---|---|
| Profundidad de anidamiento (32) | `WHERE ((((…))))` con 5.000 paréntesis desborda la pila y **mata el proceso**: una denegación de servicio de una línea contra el plano de control |
| `LIMIT` obligatorio (100 por defecto, 10.000 máximo) | Una consulta sin techo devolviendo los procesos de diez mil máquinas es una denegación de servicio contra el propio plano de control |
| Elementos de `IN` (256) | Cada valor es una comparación más por fila y por endpoint |
| Retroceso acotado en `LIKE` | La implementación recursiva evidente es exponencial ante `%a%a%a%b`. El patrón lo escribe un operador remoto contra la línea de comandos de cada proceso |

El objetivo de fuzzing `aegisql` ejercita el analizador con entrada arbitraria:
**1.286 puntos de cobertura, 37.383 ejecuciones/s, sin un solo pánico**, y
comprueba además las invariantes de salida (ninguna consulta sin techo, ninguna
tabla fuera del esquema, ninguna columna en el plan que no exista).

---

## 38.3 El planificador existe por una razón concreta

```sql
WHERE sha256 = '...' AND uid = 0
```

Evaluada tal cual, hashea el ejecutable de **cada** proceso de la máquina para
después descartar casi todos por el uid. Reordenada, compara primero un entero
que ya está en memoria y hashea solo los pocos que quedan. En un portátil con dos
mil procesos y un disco lento son minutos de E/S contra milisegundos,
multiplicado por cada endpoint de la flota.

Cada columna declara su coste (trivial, barato, medio, caro) y el planificador
reordena las cadenas de `AND` y de `OR` —ambas conmutativas, todos los predicados
puros— de forma **estable**: entre dos predicados del mismo coste se conserva el
orden del analista, que suele reflejar lo que él cree más selectivo. Hay prueba
de que reordenar cambia el orden pero **nunca el conjunto** de predicados.

`SELECT *` deja fuera las columnas caras. Un asterisco que hashee cada ejecutable
y calcule la entropía de cada región de memoria de cada proceso de cada endpoint
es una caída de servicio provocada por el propio EDR.

---

## 38.4 Lo que no se pudo ver no se esconde

Un dato del endpoint puede no estar disponible: el ejecutable de un proceso de
otro usuario, la memoria de un proceso protegido. AegisQL usa **lógica de dos
valores** —lo ausente no casa— y no el `NULL` de SQL. Con tres valores,
`NOT path LIKE '/usr/%'` dejaría de mostrar, sin avisar, los procesos cuya ruta
no se pudo leer, que son justo los que más interesan.

El coste de esa elección se asume y se compensa contando aparte los valores
inaccesibles. **Un analista tiene que poder distinguir «no hay nada» de «no pude
mirar»**: si el agente corre sin privilegios y no puede leer la memoria ajena,
una cacería de inyección que devuelve cero filas *no* significa que la máquina
esté limpia. Por eso el panel destaca dos indicadores junto al resultado: valores
no legibles y endpoints que se quedaron a medias.

Un `sha256` de un fichero mayor de 512 MB queda ausente en vez de devolver un
hash parcial: un hash parcial parece un hash, no coincide con el de nadie, y
haría creer que el fichero es desconocido.

---

## 38.5 Atribución socket → proceso

«Qué proceso tiene una conexión al puerto 4444» era, hasta ahora, una pregunta
que AegisCore no podía responder: veía eventos de conexión por el tracepoint de
eBPF, pero no podía enumerar el estado **actual** de la tabla de sockets. Un
evento se pierde si el agente no estaba escuchando; la tabla está siempre.

El kernel no publica el PID dueño de un socket: publica su **inodo**. Cada
descriptor de `/proc/<pid>/fd/` es un enlace a `socket:[<inodo>]`. La atribución
construye el índice inodo → pid una vez por consulta —con dos mil procesos son
decenas de miles de `readlink`, asumible una vez y ruinoso por fila—.

Una trampa del formato, tratada con prueba: en `/proc/net/tcp` la IPv4 va en
**orden de bytes del anfitrión**. `0100007F` es 127.0.0.1; leerlo al revés da
1.0.0.127, que es una dirección de internet perfectamente válida y llevaría a
bloquear a un tercero.

Los sockets que no se pueden atribuir quedan con `pid = 0`. No se inventa un
dueño.

---

## 38.6 La cacería viaja por el canal que ya existía

Difundir una consulta a diez mil endpoints es exactamente el mismo problema que
empujar una política: llegar en milisegundos sin esperar al siguiente latido. Ese
canal ya está abierto contra cada agente y **su coste está medido**: 10.000
canales simultáneos cuestan 10.006 hilos y 10.046 descriptores
([módulo 36](36-carga.md)). Abrir un segundo canal por agente duplicaría ese
coste a cambio de nada.

El resultado, en cambio, sube por una llamada aparte. Una cacería cara puede
tardar segundos en el endpoint, y devolverla por el canal de suscripción lo
bloquearía: una orden de aislamiento —lo que se envía cuando la máquina está
comprometida— quedaría esperando detrás de una consulta de rutina.

### Tres defectos reales, encontrados al ejecutar

**Bucle cerrado entre el canal y el agente.** Una cacería le corresponde a un
agente hasta que la *contesta*, y contestar tarda. El canal la veía pendiente, la
empujaba, volvía a mirar, la seguía viendo pendiente, y la empujaba otra vez.
Multiplicado por diez mil canales es una denegación de servicio que se provoca el
propio producto al lanzar una consulta de rutina. La raíz era de modelado: el
canal llevaba la cuenta de la política entregada pero no de la cacería.

**`sum()` sobre `BIGINT` devuelve `NUMERIC` en PostgreSQL**, no `BIGINT` —es así
para que la suma de una columna de 64 bits no pueda desbordar—. Leerla como `i64`
reventaba en tiempo de ejecución.

**Reenvío inútil de política.** Desde que las cacerías comparten canal, cualquier
cacería despierta los canales de toda la flota. Cada despertar reenviaba la
política completa: lanzar una consulta costaba diez mil copias de una política
que los agentes ya tenían.

---

## 38.7 Idempotencia y honestidad en la agregación

La clave primaria `(caza_id, cn_agente)` hace **idempotente el reintento**. Sin
ella, un endpoint con mala red que reintenta inflaría el recuento y el analista
vería una amenaza más extendida de lo que está.

El denominador de la cobertura se congela **al lanzar**. Contarlo al leer el
resultado daría un porcentaje que baja solo: un endpoint que se apagó *después*
de responder haría caer la cobertura sin que nadie dejara de contestar.

La agregación la hace PostgreSQL, no el servidor: traerse diez mil respuestas a
memoria para sumarlas sería mover megabytes en cada refresco del panel, cuando lo
que el analista mira son ocho números.

Un endpoint que no puede ejecutar la consulta **lo dice**. Si callara, sería
indistinguible de uno apagado.

---

## 38.8 La consola

El panel recibe un evento por **cada** respuesta, no uno al terminar: una cacería
sobre diez mil máquinas se ve llegar. El esquema de ayuda lo sirve el mismo
binario que valida las consultas, así que no puede quedar desfasado.

Las celdas de resultado se pintan siempre con `textContent`, nunca con
`innerHTML`: contienen líneas de comandos de procesos de endpoints potencialmente
comprometidos, y un nombre de proceso malicioso no puede convertirse en ejecución
de script dentro de la consola del SOC. Verificado en navegador real, no solo en
el DOM.

---

## 38.9 Uso

```bash
# Desde la consola: pestaña "Caza".
# Desde la API:
curl -X POST http://servidor:8080/api/cacerias \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"consulta":"SELECT pid, path FROM processes WHERE memory.rwx"}'

curl http://servidor:8080/api/cacerias/$ID -H "Authorization: Bearer $TOKEN"
curl http://servidor:8080/api/aegisql/esquema -H "Authorization: Bearer $TOKEN"
```
