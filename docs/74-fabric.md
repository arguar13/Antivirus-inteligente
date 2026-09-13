# 74 · AegisFabric — un solo modelo de entidad, un solo veredicto

> FASE 79. `crates/aegis-entidad` (agente) y `server/crates/aegis-tejido` (plano de control).

## La ventaja estructural, dicha sin adornos

Nueve subsistemas de detección, cada uno con su propia idea de «qué es una cosa»
y su propio enumerado de veredicto, producen **nueve sucesos sin relación** ante
un mismo ataque. Antes de esta fase este árbol tenía **doce enumerados de
veredicto y nueve de severidad** —veintiuno en total, sin contar los que hablan de
otras cosas, como el régimen de memoria o la compatibilidad de protocolo—, y
ninguno estaba mal por separado. Lo que no había era una sola tabla que dijera
cuál se traduce a cuál.

La consecuencia práctica no es estética. Un analista con el mismo incidente
delante veía:

- `aegis-wire` diciendo `Hecho::FicheroTransferido { sha256: "e016…" }`,
- `aegis-ruleforge` diciendo `Entrada { clave: [0xe0, 0x16, …], clase: HashFichero }`,
- `aegis-detonate` diciendo `Veredicto::ConHallazgos { hechos: 5 }` sobre una
  `Muestra { sha256: "e016…" }`,
- `aegis-case` diciendo `Observable::Hash("e016…")`,
- `aegis-swarm` diciendo `Ioc { kind: FileSha256, value: "e016…" }`.

Cinco nombres para la misma cosa, cinco vocabularios, y la unión la hacía una
persona de cabeza — que funciona hasta que el incidente tiene cuarenta nodos.

**Lo que esta fase construye no es una capa más: es el tejido que hace que la
misma cosa se llame igual en los nueve.** Y eso no se consigue integrando
productos de fabricantes distintos: es la única ventaja de este diseño que **no
se puede copiar comprando**.

## El inventario va primero, y va en el código

Unificar sin haber contado es adivinar. El censo de quién produce veredictos hoy
—con qué vocabulario, sobre qué clase de entidad y de qué hechos deriva su
identificador— está en `aegis_tejido::inventario`, y **la puerta de calidad lo
recorre**: un motor nuevo sin fila rompe la compilación de las pruebas.

Está en el código y no en un documento por una razón comprobable: un documento se
queda viejo en silencio.

| Plano | Motores | Vocabulario nativo del que se viene | Entidad que nombra |
|---|---|---|---|
| Estático | `estatico` (F3), `aprendizaje` (F21) | coincidencia de firma; `Veredicto{Benigno,Sospechoso,Malicioso}` + puntuación `f32` | contenido (SHA-256) |
| Conductual | `conductual` (F8), `syscallguard` (F46), `detonate` (F73) | puntuación acumulada; `Severidad` de cinco; `Veredicto{SinHallazgos,ConHallazgos,NoConcluyente}` | proceso; artefacto |
| Red | `wire` (F70), `ips` (F71), `l7hunter` (F66) | `Hecho` de 23 variantes; `Confianza{Baja,Media,Alta}`; `Veredicto{SinMuestra,Irregular,Baliza…}` | flujo |
| Memoria | `memhunter` (F65) | `Severidad` de cinco sobre la región | proceso |
| Identidad | `itdr` (F56) | `Severidad` de cinco + `Nivel` del grafo de identidad | cuenta (SID, no el nombre) |
| Plataforma | `fwaudit` (F67) | `Veredicto` de línea base + `Severidad` de anomalía ACPI | máquina |
| Externo | `intel` (F77), `enjambre` (F68) | `Veredicto` de cinco de la fusión; `Veredicto{Insuficiente,Corroborado,…}` | contenido |

Y tres productores **no** entran en la tabla, a propósito, porque darles voto en
el árbitro sería dárselo a algo que no observó nada:

| Subsistema | Qué produce | Por qué no es una señal |
|---|---|---|
| `aegis-case` | `Veredicto` de cierre | Es el juicio de **una persona**, y llega después: realimentaría la detección con su propio resultado |
| `aegis-predict` | `Veredicto` de contención | Es una **decisión de respuesta**: consume veredictos, no los produce |
| `aegis-share` | `Retenido` | Gobierna la difusión; no dice si la cosa es maliciosa |

## Cuándo dos observaciones son la misma entidad — y cuándo no

Un identificador de entidad **se deriva, no se coordina**: dos observadores con
los mismos hechos llegan al mismo nombre sin hablar entre ellos. Es el reparto por
sorteo de `aegis-scale` aplicado a nombrar cosas, y es lo que hace posible que un
agente aislado y el plano de control coincidan durante un corte de red.

Lo que más decide del diseño, sin embargo, es **lo que NO se fusiona**:

- **Un PID reciclado no hereda la historia del anterior.** Por eso el
  identificador de proceso lleva `(máquina, arranque del sistema, pid, arranque
  del proceso)` y no solo el pid: en un servidor ocupado los pid se reciclan en
  minutos, y sin el arranque la cronología de un incidente mezcla dos procesos
  que no tienen nada que ver.
- **El contenido y la ubicación son entidades distintas.** El mismo fichero en dos
  rutas no es una cosa —una puede estar en cuarentena y la otra ejecutándose—, y
  dos ficheros distintos en la misma ruta tampoco: eso es exactamente lo que hace
  una actualización, y confundirlos hace que un binario nuevo herede el veredicto
  del que sustituyó.
- **El mismo flujo visto desde los dos extremos sí es uno.** La tupla se ordena
  canónicamente antes de derivar, así que el sensor del cliente y el del servidor
  llegan al mismo identificador sin negociarlo.
- **La detonación produce una entidad propia.** Detonar el mismo fichero con otra
  configuración produce otro informe; llamarlos igual haría que el segundo pisara
  al primero.

## Severidad y confianza son ejes distintos

Un adware detectado con certeza absoluta es **confianza alta, severidad baja**. Un
indicio de ransomware es **confianza baja, severidad crítica**. Colapsarlos en un
solo número —un «riesgo» de 0 a 100— hace que las dos situaciones den la misma
cifra, y son la diferencia entre «anótalo» y «levanta a alguien de la cama».

La confianza es **la probabilidad de que la afirmación sea cierta**, no «lo fuerte
que gritó el motor». Y no llega nunca a cien: cien es certeza absoluta, y un
sistema de detección que se declara absolutamente seguro no deja sitio a la duda
que el analista necesita para poder contradecirlo. Lo observado directamente llega
a 99.

Cada motor tiene un **tope de confianza**, y no es un desprecio a nadie: es que un
motor que no puede ver una cosa no puede estar seguro de ella, por bien que haga
lo suyo.

| Motor | Tope | Por qué |
|---|---|---|
| `detonate` | 99 | **Vio** la muestra ejecutarse y hacer lo que hizo |
| `memhunter` | 95 | Vio el código inyectado en la memoria del proceso |
| `conductual`, `syscallguard` | 90 | Vieron la acción; la intención se deduce |
| `ips`, `wire`, `l7hunter`, `itdr`, `fwaudit` | 85 | Vieron el hecho en su plano |
| `estatico` | 80 | Una firma acierta mucho y un empaquetador nuevo la esquiva |
| `intel`, `enjambre` | 75 | **Repiten** lo que otro observó |
| `aprendizaje` | 70 | Una puntuación alta **no es** una probabilidad salvo que se haya calibrado |

El tope lo impone el constructor de la señal, no una convención: `Senal::nueva`
acota, y no hay otro camino. Basta un `confianza: 100` puesto por costumbre en un
motor nuevo para desequilibrar el árbitro entero, y no hace falta mala fe.

## Corroborar cuenta planos, no motores

Es la decisión que más cambia el resultado, y viene de `aegis-share::procedencia`:
**dos canales que repiten al mismo no son dos fuentes**. Aplicada a los motores
propios:

- **El estático y el modelo del endpoint comparten la entrada entera.** El modelo
  se alimenta de características estáticas del fichero: si está ofuscado de una
  forma que ninguno reconoce, **fallan los dos a la vez y por lo mismo**. Ponerlos
  en planos distintos convertiría «el estático y el modelo coinciden» en
  corroboración independiente, que es la falsa confirmación más fácil de fabricar.
- **Toda la inteligencia externa es un plano.** Veinte proveedores de reputación
  que copian al mismo origen no son veinte confirmaciones. Y por eso el plano
  externo **nunca decide solo**: si bastara, quien envenenara el feed de arriba
  cobraría en todos los de abajo.

## El árbitro: seis reglas en orden, y ninguna media

`arbitrar(entidad, señales, ahora_ns)` es una **función pura** —el tiempo entra
como argumento, no se lee del reloj—, así que el criterio entero cabe en la puerta
de calidad en vez de en un documento, y dos ejecuciones sobre los mismos hechos
dan exactamente lo mismo.

**No se promedia.** Es el argumento de `aegis-enrich::fusion`: una media esconde
el desacuerdo y convierte el desconocimiento en voto. Dos motores seguros y
contrarios dan `EnDisputa` —que exige una persona—, no un valor intermedio que se
leería como evidencia débil cuando lo que hay es evidencia fuerte en las dos
direcciones.

Y hay cinco resultados, no tres, por la misma razón que en la fusión de
enriquecimiento: `EnDisputa` y `SinDatos` son situaciones reales y frecuentes que
un enumerado de tres obliga a disfrazar de otra cosa. **`SinDatos` no es
`Limpio`**: un fichero que nadie conoce es lo que parece un fichero recién
compilado por un atacante.

**Todo veredicto sale con una frase**, y la puerta de calidad lo comprueba
recorriendo **todas** las combinaciones en vez de afirmarlo: un veredicto que el
analista no puede reconstruir es un veredicto que no usa.

## El linaje: una cadena, no siete grafos

El camino de un ataque atraviesa red, fichero, proceso, identidad y respuesta. Las
aristas que no existían antes de esta fase son justo las que cruzan:

- `Extrajo` une el plano de red con el de fichero,
- `SeDetono` une el fichero con lo que se observó al ejecutarlo,
- `ActuoComo` une el proceso con la identidad,
- `SeContuvo` une la respuesta con lo que se contuvo.

Dos detalles que parecen menores y no lo son. **`ResideEn` no propaga causa**: que
dos ficheros estén en la misma máquina no relaciona lo que hacen, y si propagara,
preguntar por cualquier cosa devolvería el equipo entero. Y **un recorrido
truncado se dice**: un camino cortado sin avisar se lee como «hasta aquí llegó el
ataque», y esa lectura cierra incidentes que siguen abiertos.

## La costura vive en un módulo

La traducción de cada vocabulario nativo a la escala única está en
`aegis_tejido::traduccion`, y no repartida por los motores. Es la misma decisión
que `aegis-share::difusion` tomó para lo que sale de la organización, y por la
misma razón: **una regla repartida por veinte sitios es una regla que el veintiuno
se salta**.

Tres reglas la gobiernan entera:

1. **Lo que el motor no puede ver no lo puede afirmar** — el constructor acota.
2. **Un hecho no es un juicio.** `aegis-wire` produce veintitrés clases de hecho y
   la mayoría **no son señales**: una consulta DNS no acusa a nadie. Un disector
   que grita «malicioso» en cada paquete es un disector que nadie mira.
3. **No poder mirar nunca se traduce a limpio.** Es la línea que más importa del
   módulo: `SinHallazgos` es el único camino a «no encontramos nada», y en
   `aegis-detonate` no se alcanza si la detonación no fue completa o hubo sospecha
   de evasión. Si esta costura tradujera `NoConcluyente` a `Limpio` «para no
   generar ruido», una muestra que detecta el sandbox y se marcha entraría en la
   flota con el sello de haber sido analizada.

## La prueba que justifica la fase

Once subsistemas encadenados sobre **un solo identificador de entidad**, con el
código real de cada uno:

```
 1. AegisWire        F70  flujo  flujo disecado, 2 hecho(s) que acusan
 2. AegisWire        F70  cont   fichero extraído del flujo, 8192 bytes
 3. AegisRuleForge   F72  cont   el corpus reconoce el fichero exacto: «Win.Trojan.Descarga-9931»
 4. AegisDetonate    F73  arte   con-hallazgos · 9 evento(s) recibidos
 5. AegisFabric      F79  cont   malicioso · severidad alta · confianza 99 % · 2 plano(s)
 6. AegisCase        F76  cont   1 caso, 7 líneas de cronología, 2 huecos declarados
 7. AegisEnrich      F77  cont   sin-datos · 1 analizador sin resultado · nada salió
 8. AegisPredict     F69  maq    camino de 2 saltos con p=0,9405; radio 2,9 activos ±0,02
 9. AegisOrchestrator F64 maq    contener «CORP\svc-respaldo»: RevocarTicketsKerberos
10. AegisShare       F78  cont   1 objeto entregado por TAXII con tope TLP:AMBER
11. AegisSwarm       F68  cont   1 indicador corroborado por 3 pares distintos, sin plano de control
```

Siete de las once paradas nombran la **misma** entidad; las otras cuatro nombran
entidades unidas a ella por una arista del linaje, y la prueba lo comprueba en vez
de suponerlo. Eso es, literalmente, lo que un conjunto de productos integrados no
puede hacer: cada uno nombra las cosas a su manera y la correlación acaba siendo
una heurística sobre cadenas de texto que casi acierta.

Vale la pena mirar dos paradas de cerca:

- **La 7 dice `sin-datos`**, y es lo correcto: el circuito enriquece en **modo sin
  salida**, así que las fuentes externas no responden. «Nadie lo conoce» no es
  «está limpio», y el informe lo dice con esas palabras.
- **La 9 corta la identidad y no la máquina.** El camino más probable termina en el
  controlador de dominio, que está **protegido**: el motor no puede actuar ahí, así
  que corta un salto antes, en la cuenta de servicio, con la acción mínima que
  cierra ese salto. Tirar el controlador de dominio convierte un incidente en un
  apagón, y es lo que un atacante querría que hiciéramos por él.

## La ruta caliente, medida antes y después

Unificar no puede haber costado latencia en el camino que corre en cada endpoint.
Se mide contra la referencia honesta: lo que había antes, que era quedarse con la
severidad peor de las señales que acusan.

| Camino | ns/decisión |
|---|---|
| Antes: peor severidad, sin explicación | ~85 |
| Ahora: árbitro con frase, planos y señales | ~2 900 |

El árbitro hace cosas que el máximo no hacía —cuenta planos, acota por
corroboración, construye la frase y adjunta las señales—, así que no puede costar
lo mismo. Lo que la fase promete es que **sigue siendo despreciable frente al
trabajo que ya había**: la detección que produce esas tres señales cuesta
microsegundos por sí sola. El techo declarado son 5 µs por decisión; a mil
decisiones por segundo —que es una máquina bajo ataque, no una en reposo— son 5 ms
de cada segundo: cinco milésimas del 1 % de una CPU.

## El coste en el endpoint: cero crates

El modelo de entidad y el árbitro corren **en el agente**, no solo en el servidor:
el endpoint tiene que poder derivar el identificador y arbitrar sin preguntarle a
nadie, porque durante un corte de red es lo único que tiene.

`aegis-entidad` tiene **una** dependencia directa, `sha2`, que el agente ya tenía
por `aegis-sync`. La puerta de calidad no cuenta crates —eso invitaría a discutir
si diez son muchos o pocos— sino que comprueba que **el árbol de `aegis-entidad`
es un subconjunto del que el agente ya tenía**: cero crates nuevos. En un producto
que corre con privilegios en cada máquina, ese árbol *es* superficie de ataque.

Y la dirección de la dependencia importa: `aegis-tejido` depende de **todos** los
subsistemas y **ninguno** depende de él. Al revés, el tejido dejaría de poder
cambiar sin tocarlos a todos, y la traducción volvería a repartirse por veinte
sitios — que es de lo que se venía.

## Lo que esta fase encontró al usar el producto desde fuera

Una fase que une subsistemas es también la primera que los usa como los usaría un
tercero, y eso saca defectos que ninguna prueba interna ve.

**Los dos marcados AMBER de `aegis-share` tenían el nombre cambiado.**
`Tlp::Amber` valía `TLP:AMBER+STRICT` y `Tlp::AmberStrict` valía `TLP:AMBER`. El
orden del enumerado era correcto y todas las comprobaciones funcionaban, así que
**ninguna prueba lo veía**: la ida y vuelta de etiqueta es estable con los nombres
cambiados, porque sólo compara el sistema consigo mismo.

Lo que rompe es quien escribe `Tlp::Amber` creyendo que pone AMBER y resulta poner
la restricción de más arriba — o, en la dirección peligrosa, quien escribe
`if tlp <= Tlp::Amber { compartir }` y sin saberlo deja pasar también
`AMBER+STRICT`, que significa «sólo mi organización». **Un identificador que miente
sobre su valor es un fallo de seguridad aunque la aritmética esté bien**, y la
única prueba que lo detecta es la que ata el nombre al texto canónico. Ahora está,
y `tools/verificar-fabric.sh` la comprueba también desde fuera.

## Las cinco propiedades de la puerta

`tools/verificar-fabric.sh` y `cargo run -p aegis-tejido --example circuito`:

1. **El inventario** cubre los trece motores y los siete planos, recorrido y
   comprobado.
2. **El circuito** recorre las once paradas con un identificador.
3. **El linaje** atraviesa las siete clases de entidad sin truncarse, y el
   recorrido de causa es más estrecho que el de alcance.
4. **La ruta caliente** decide por debajo del techo declarado.
5. **El determinismo**: dos recorridos dan el mismo identificador, el mismo
   veredicto y el mismo informe, frase incluida.

Más dos comprobaciones estructurales: el árbol del endpoint no crece ni un crate,
y ningún crate del agente depende del tejido.

## El muro, declarado

El circuito no arranca un hipervisor ni abre sockets, y es deliberado: **cada
subsistema ya ejerce eso en su propia puerta** —`aegis-detonate` arranca microVM de
verdad, `aegis-wire` reconstruye flujos byte a byte contra ataques de evasión,
`aegis-swarm` habla entre dos nodos libp2p reales—. Lo que esta puerta comprueba es
lo que ninguna de esas puede: **la unión**. Y esa sí corre entera, con el código
real de los once subsistemas.
