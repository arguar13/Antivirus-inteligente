# 70 · AegisScale — plano de control para 100.000 agentes

> FASE 75. `server/crates/aegis-scale`, `server/migrations/0007_particionado.sql`
> y el binario `escala` de `fleet-simulator`.

## La tesis

**La diferencia entre diez agentes y cien mil no es un factor de escala: es un
diseño distinto.** Y los sistemas que no se diseñaron para ello no se arreglan
añadiendo máquinas, porque lo que falla no es la capacidad de una máquina.

Cuatro cosas fallan, y las cuatro fallan de la misma forma: funcionan
perfectamente hasta que dejan de hacerlo, y cuando dejan de hacerlo ya es tarde.

| Lo que falla | Cómo se nota | Dónde se arregla |
|---|---|---|
| Ampliar el plano de control rebaraja el 80 % de la flota | Cien mil agentes reconectan a la vez contra un plano que acaba de crecer **porque iba justo** | [`fragmento`] |
| Cien mil conexiones mTLS no caben, y la manada tira al nodo que vuelve | Un nodo se levanta y se cae otra vez, en bucle | [`sesion`] |
| La purga de la base de datos tarda cada día un poco más | El día que no acaba antes de que empiece la siguiente | [`particion`] |
| Una actualización progresiva rompe **en silencio** | La máquina está contenida y el panel dice que no | [`version`] |

---

## 1 · El reparto: por qué sorteo y no módulo ni anillo

Con el reparto ingenuo `hash(agente) % nodos`, pasar de cuatro nodos a cinco
mueve al **80 %** de la flota.

Las dos soluciones clásicas —anillo consistente y sorteo (*rendezvous*, o
*highest random weight*)— mueven sólo `1/N`. La diferencia está en lo demás:

- El **anillo consistente** necesita entre cien y doscientos nodos virtuales por
  nodo real para repartir bien: una tabla que mantener, ordenar y distribuir, y
  un reparto que sigue teniendo varianza.
- El **sorteo** no tiene tabla: para cada agente se calcula un peso con cada nodo
  y gana el mayor.

Y lo que de verdad decide: el sorteo es una **función pura de (agente, lista de
nodos)**. Dos nodos del plano de control con la misma lista calculan la misma
asignación **sin hablar entre ellos**. En una partición de red eso es la
diferencia entre seguir funcionando y necesitar consenso para atender un latido.

### El peso se calcula con un resumen criptográfico, y no por gusto

Una función de mezcla barata **correlaciona** los pesos de nodos con
identificadores parecidos —`nodo-1`, `nodo-2`, `nodo-3`— y entonces el reparto
deja de ser uniforme justo en el caso normal, que es nombrar los nodos con un
contador.

### La estabilidad de la membresía es parte del diseño

Un nodo que parpadea —una pausa del recolector de basura, un reinicio de treinta
segundos— cambiaría la lista y con ella la asignación de `1/N` de la flota. Si la
lista siguiera al estado instantáneo, **cada parpadeo provocaría una migración
completa de ese fragmento y otra de vuelta**. Por eso una baja tarda noventa
segundos en aplicarse, y una retirada **ordenada** —un despliegue— no espera: se
sabe que se va.

### La época del mapa es monótona, y eso es una defensa

El mapa de nodos viaja hasta los agentes. **Ninguna firma distingue un mapa
auténtico de ayer de uno auténtico de hoy**, así que sin época, reproducir el
viejo redirige a una fracción de la flota hacia nodos que ya no existen. Con
época, el agente se queda con la mayor que haya visto.

---

## 2 · Las conexiones: el número que decide el diseño

Una conexión TLS viva cuesta del orden de **48 KiB** entre búferes, estado de
sesión, socket del núcleo y bucle de eventos. Cien mil conexiones son unos
**4,7 GiB sólo en estar conectado**, sin haber procesado un evento. Más los
descriptores: el límite por defecto de un proceso son 1024.

> «Un proceso con cien mil conexiones» no es una meta de ingeniería: es una forma
> de no haber hecho las cuentas.

**Las dos ideas que hacen que quepa:**

**(a) La mayoría de los agentes no necesita estar conectada.** Un agente en
reposo manda un latido cada pocos minutos. Lo que necesita conexión viva es un
agente **con trabajo pendiente**. Por eso la conexión es un **arriendo** y no un
estado permanente. Un nodo con diez mil huecos atiende a cien mil agentes si cada
uno está conectado el diez por ciento del tiempo.

**(b) El desfase tiene que ser determinista, no aleatorio.** Cuando un nodo se
reinicia, sus agentes reconectan; si lo hacen a la vez, el nodo se levanta y se
cae otra vez, y como el reintento suele ser periódico, vuelven a coincidir. No se
arregla con reintentos exponenciales, porque todos crecen igual. Se arregla
repartiendo a los agentes en la ventana, y el reparto se calcula con el
identificador del agente:

1. **El agente y el servidor calculan lo mismo**, así que el servidor puede
   predecir la curva de reconexión de su fragmento.
2. **Es estable entre reinicios**: con azar, un agente desafortunado cae en el
   pico una vez de cada tantas; así, cada agente tiene su hueco.
3. **Se puede probar.** Con un generador aleatorio, la prueba sería sobre el
   generador.

---

## 3 · La base de datos: «una tabla de alertas sin particionar muere al año»

Cien mil agentes con un evento de seguridad al minuto son **144 millones de filas
al día**. El problema no es el tamaño: es la **purga**.

`DELETE FROM alertas WHERE creado_en < ...` en una tabla así:

- escribe en el registro de transacciones **tanto como escribió la inserción
  original**, así que compite con la ingesta por el mismo disco;
- no devuelve el espacio: deja filas muertas que hay que aspirar, y el aspirado
  vuelve a leer la tabla entera;
- mantiene abierta una transacción larga que bloquea la limpieza de todo lo demás;
- y tarda cada día un poco más, **hasta el día en que no acaba antes de que
  empiece la siguiente**. Ese día mata la instalación, y llega sin aviso.

Con particionado declarativo la purga es un `DROP` de la partición entera:
constante, sin registro proporcional a las filas, sin filas muertas y sin
bloquear la ingesta de las particiones vivas.

### `DETACH CONCURRENTLY` antes del `DROP`

`DROP TABLE` sobre una partición adjunta toma un bloqueo de acceso exclusivo
**sobre la tabla padre**, y eso para la ingesta de todas las demás mientras dura.
Es la diferencia entre una purga que nadie nota y una que aparece en el panel
como un pico de latencia todos los días a la misma hora.

### El orden de las dimensiones

**Rango por tiempo primero**, porque es la dimensión por la que se purga.
Particionar primero por inquilino obligaría a borrar *dentro* de cada partición,
que es volver al `DELETE`. **Hash por inquilino dentro**, porque es la dimensión
por la que se consulta.

### Tres meses por adelantado

Sin adelanto, la primera inserción del mes que viene falla porque no existe su
partición, y falla **a las cero horas del día uno**, que es cuando menos gente
está mirando.

---

## 4 · La actualización progresiva: la trampa de protobuf

Protobuf presume de compatibilidad hacia delante: un lector viejo **ignora en
silencio** los campos que no conoce. Para telemetría es exactamente lo que se
quiere. Para un campo con **significado de seguridad, es un agujero**:

> La versión nueva del agente añade un campo «he puesto esta máquina en
> cuarentena». Un nodo de la versión anterior recibe el mensaje, ignora el campo,
> y **cree que no ha pasado nada**. La máquina está contenida y el panel dice que
> no. Nadie ve un error: el mensaje se aceptó, se guardó y se contestó que sí.

**La regla:** un cambio que no se puede ignorar **no va en un campo nuevo: va en
un método nuevo**. Un método que el servidor viejo no conoce falla ruidosamente
—«no implementado»— y el agente se entera. Un campo que no conoce, no.

La política está **en el código** (`version::evaluar`), no en un documento: quien
añade un cambio tiene que elegir una variante del enumerado, y la variante dice
si vale con un campo o hace falta un método.

### El drenaje es la fase que casi siempre falta

Sin drenar, actualizar un nodo corta de golpe sus conexiones y provoca la manada
contra los demás; y como los demás también se van a actualizar, **la manada se
repite una vez por nodo**.

---

## Los números medidos

De la ejecución real de `cargo run --release -p fleet-simulator --bin escala` en
la máquina de integración (16 nodos, 100.000 agentes, 32 inquilinos, 400.000
eventos de telemetría realista):

| Medida | Resultado |
|---|---|
| Reparto entre 16 nodos | ideal 6.250 · mín. 6.120 · máx. 6.465 · **desviación 5 %** |
| Ampliar de 16 a 17 nodos | **se mueve el 5 %** de la flota (con `hash % nodos` sería el 94 %) |
| Conexiones vivas | 10.000 de 100.000 agentes con ciclo del 10 % · capacidad 160.000 · **ninguno sin sitio** |
| Caída de un nodo | 601 conexiones perdidas · **pico de reconexión 17/s** (sin desfase serían 601/s) |
| Latencia de la canalización por lote | **p50 13 µs · p95 20 µs · p99 40 µs** |
| Rendimiento | **145.000 eventos/s** en un solo hilo |
| Profundidad de cola | reordenador 50.000 en vuelo (su cota) · deduplicación 400.000 identificadores |
| Memoria | 8 MiB → 125 MiB |
| Pérdida silenciosa | **cero**: cada evento entrado está contado en la salida, el rechazo o el duplicado |

La comprobación que justifica la prueba **no es la latencia**: es la última fila.
Un sistema que pierde eventos en silencio a esta escala no se nota nunca, porque
nadie cuenta cuatrocientos mil.

El p99 tiene un **objetivo que hace fallar la prueba** si se supera (5.000 µs).
Una prueba de carga que sólo imprime números no protege de nada: la regresión se
ve el día que alguien se molesta en comparar.

---

## Contratos existentes: qué se conserva y qué cambia

**No cambia nada de `aegis-server`.** `aegis-scale` es un crate nuevo de
funciones puras; el servidor lo usará, no al revés.

**Se reutiliza en vez de duplicarse:**

- Las **cuotas por inquilino** y la **señal de contrapresión** hacia los agentes
  son las de `aegis-pipeline` (FASE 74). Reimplementarlas aquí sería tener dos
  políticas de admisión, y el día que difirieran un cliente vería una y otro la
  otra.
- El **calendario** de las particiones es el de `aegis-ingest::tiempo`. Dos
  implementaciones del mismo calendario es la forma de que un día una partición
  cubra un rango que la otra no.

**La migración 0007 añade** `eventos_normalizados` (particionada desde que nace),
`particiones`, `cuotas_inquilino`, `nodos_plano_control` y `epoca_membresia`. No
altera ninguna tabla existente.

---

## Por qué ningún módulo de este crate hace entrada/salida

Todos son funciones puras sobre estado explícito: el reparto es función de
(agente, nodos); el plan de particiones, de (ahora, existentes); la
compatibilidad, de (versión, versión).

Eso permite **probar cien mil agentes y trece meses de particiones en
milisegundos**, que es la única forma de tener estas propiedades en una puerta de
calidad en vez de en un documento.

---

## El muro, declarado

La prueba de carga de la puerta de calidad **no levanta cien mil conexiones mTLS
reales ni escribe en PostgreSQL**.

Y no es una limitación de la máquina de integración: **es que el diseño no
levanta cien mil conexiones** —no caben, y ésa es justamente la conclusión del
módulo de sesiones—. Lo que sí se hace es la cuenta completa de capacidad y la
simulación del reparto, incluida la caída de un nodo y la manada que provoca.

El escenario contra un plano de control real con PostgreSQL real existe y se
lanza con `fleet_simulator` —el otro binario—, que habla el protocolo auténtico
con certificados de la CA real. Lo que corre en la puerta es la parte que
**decide** el resultado a esa escala y que se puede ejecutar en cualquier
máquina, para que la cifra esté en el CI y no en un documento que nadie vuelve a
reproducir.

[`fragmento`]: ../server/crates/aegis-scale/src/fragmento.rs
[`sesion`]: ../server/crates/aegis-scale/src/sesion.rs
[`particion`]: ../server/crates/aegis-scale/src/particion.rs
[`version`]: ../server/crates/aegis-scale/src/version.rs
