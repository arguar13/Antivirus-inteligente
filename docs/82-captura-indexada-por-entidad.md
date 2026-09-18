# AegisCapture — captura de paquetes indexada por entidad

**FASE 90.** Crates `crates/aegis-captura` (agente) y
`server/crates/aegis-almacen-pcap` (almacén). Puerta:
`tools/verificar-captura.sh` (grupo `captura` de `tools/ci-local.sh`).

## Las dos cosas que un capturador es, además de un capturador

Un capturador es, por diseño, el sitio donde se acumula todo lo que pasó por la
red. Eso lo convierte en dos armas contra su propio dueño, y las dos se han
usado en incidentes reales contra sensores de este tipo:

- **Un sitio del que robar.** Si guarda credenciales, quien lea el disco se lleva
  las contraseñas de todos los usuarios de la última semana sin necesidad de
  comprometer el agente. La captura completa es una copia de seguridad de los
  secretos de la organización, ordenada y con índice.
- **Una forma de llenar el disco.** Si guarda todo lo que le echen, quien genere
  tráfico decide cuándo se queda sin espacio la máquina — y una máquina sin
  espacio deja de escribir registros, que es apagar la defensa por detrás.

Las dos se paran aquí con propiedades **estructurales**, no con opciones de
configuración. Una opción se cambia; un tipo que no tiene constructor no se puede
construir.

## Las dos invariantes, sostenidas por el sistema de tipos

### 1. No hay camino del cable al disco que se salte la redacción

El anillo no acepta `&[u8]`. Acepta `Limpio`:

```rust
pub fn meter(&mut self, cuando_ns: u64, limpio: &Limpio) -> bool
```

Y `Limpio` tiene los campos privados y **un solo constructor**:
`Redactor::limpiar`. No hay `Limpio::nuevo`, no hay `From<&[u8]> for Limpio`, no
hay `Default`. Quien quiera meter bytes sin redactar tiene que escribir primero
un constructor que no existe, y la puerta de calidad lo comprueba **por
ausencia**: busca el constructor que no debe estar y falla si aparece.

Es el mismo patrón que la jaula de la FASE 87 y que la `Autorizacion` de abajo:
la propiedad no la vigila una revisión, la impide el compilador.

### 2. Sin veredicto no hay contenido

Guardar el contenido de un flujo entero exige una `Autorizacion`, y
`Autorizacion` sólo sale de un veredicto:

```rust
pub fn del_veredicto(v: &Veredicto) -> Option<Autorizacion>
```

`Some` únicamente para `Resultado::Malicioso` y `Resultado::EnDisputa`. Sin
`Default`, sin `From`, sin `nueva()`. El flujo que nadie ha acusado deja **el
sobre** —quién habló con quién, cuándo, cuánto— y no deja el contenido.

`Politica::Nada` es asimétrica a propósito: `Decision::combinar` la respeta
siempre, y ningún veredicto posterior la levanta. Lo que el cliente prohibió
guardar no se guarda aunque luego resulte malicioso; para eso está el sobre, que
sí se conserva.

### 3. Nada de lo que crece con el tráfico crece sin techo

Son **dos** estructuras, no una, y la primera versión sólo acotaba la primera:

- El **anillo** acota el contenido, por bytes, fijado al construirlo.
- El **índice** acota el sobre, por entradas… y no lo hacía.

El sobre se anota de **todo** el tráfico, también del 99 % que no se guarda. Un
índice sin techo convierte «no guardamos casi nada» en una memoria que crece con
el tráfico, y quien genera el tráfico es precisamente de quien hay que
defenderse. Es la invariante 9 en su forma exacta: **una cota por flujo no es una
cota**, porque un millón de flujos pequeños son un problema grande.

El techo sale del presupuesto, no de la intuición. En el host más pequeño que se
soporta, lo elástico son 18 MiB y la red se lleva 22 partes de 100: unos 4 MiB,
que ya tiene pedidos el estado de los disectores. El índice toma un cuarto de
eso, **1 MiB**, y lo comprueba el compilador:

```rust
const _: () = assert!(MAX_MEMORIA_INDICE <= aegis_wire::MAX_MEMORIA_APP / 4);
```

Un mega son **4096 entradas**, que a los 23 000 paquetes por segundo medidos aquí
son menos de dos décimas de segundo de tráfico a tope. No se disimula subiendo el
número: el índice del agente es un sitio de paso hasta que se drena al almacén, y
decirlo pequeño obliga a que el drenaje exista de verdad en vez de suponerlo.

#### El desalojo es por carga, no por antigüedad

Con el índice lleno hay que echar a alguien, y **a quién se echa es una decisión
de seguridad, no de eficiencia**. Echando la entrada más antigua, un atacante que
inunde el sensor le borra el sobre a todas las demás máquinas —incluida la que
está atacando—: el sensor le haría el trabajo de tapar el rastro.

Se desaloja a la **entidad con más entradas**, y dentro de ella la más antigua.
Así el que inunda se desaloja a sí mismo. Medido: una máquina callada mete 10
entradas, otra inunda con 100 veces el techo, y a la callada le quedan **las 10**.

El coste de encontrar a la más cargada es O(log n) —un árbol `(cuántas, entidad)`
al día— porque un techo que cuesta O(entidades) comprobar se convierte él mismo
en el amplificador que viene a impedir.

Y lo que se cae **se cuenta aparte de lo que se purga**: `Pagina::desbordadas`
frente a `Pagina::purgadas`. Una entrada purgada se fue cumpliendo su retención,
que es el producto funcionando; una desbordada se fue porque no había sitio, que
es el agente quedándose corto y hasta que se arregle **falta tráfico en el
informe**. Juntarlas sería el mismo error que dar una sola cifra de «paquetes
perdidos» en el anillo.

## La contabilidad de la pérdida: dos invariantes, no una

El primer anillo que escribí contaba mal, y la forma de contar mal es
instructiva: un paquete escrito y desalojado después aparecía a la vez en
`escritos` y en la cifra de pérdida, con lo que la suma no cuadraba nunca bajo
carga. La tentación es sumar un contador más hasta que cuadre. La corrección de
raíz es reconocer que hay **dos** momentos en los que se pierde algo, y que se
arreglan de forma distinta:

```rust
pub fn cuadran_en_la_entrada(&self) -> bool {
    self.recibidos == self.escritos + self.descartados + self.rechazados
}
pub fn cuadran_en_la_salida(&self, dentro: u64) -> bool {
    self.escritos == self.drenados + self.desalojados + dentro
}
```

| Contador | Qué pasó | Cómo se arregla |
|---|---|---|
| `descartados` | no cupo en el anillo | anillo más grande |
| `rechazados` | la política decía que no | es lo correcto, no es pérdida |
| `desalojados` | entró, y lo echó uno posterior | drenar más rápido |
| `drenados` | salió al almacén | nada que arreglar |

Un capturador que dé una sola cifra de «paquetes perdidos» está juntando tres
problemas con tres soluciones distintas. **El anillo no puede crecer**: no tiene
`reservar` ni `redimensionar`, y la puerta lo comprueba. Quien genere tráfico no
decide cuánta memoria usa el agente.

## La redacción: lo que nunca se almacena

18 patrones (cabeceras `Authorization`, `Cookie`, `X-Api-Key`, `Proxy-Authorization`,
campos de formulario `password`, `token`, `secret`, credenciales de protocolo…),
más los ámbitos que declare el cliente. Lo que se tapa se sustituye por `*`,
**conservando la longitud**, para que la disección posterior siga viendo una
trama bien formada y la fidelidad de la reproducción se pueda declarar.

### El redactor era un vector de denegación de servicio

Medido: **382 µs por paquete**. Un paquete de 1500 bytes lleno de `x` hacía que
el prefiltro de un byte dejara pasar todas las posiciones, porque `x-api-key:`
empieza por `x`. Un atacante que conociera la tabla —y la tabla está en el
código— podía multiplicar por diez el coste de mirar su propio tráfico. Un sensor
que se hace más caro cuanto más hostil es el tráfico es un amplificador, que es
justo lo que la invariante 10 prohíbe.

Tres correcciones de raíz, ninguna un límite configurable:

1. **Una sola pasada.** 18 recorridos independientes del paquete pasaron a un
   recorrido sobre una tabla `PATRONES` ordenada.
2. **El ámbito no se busca si no hay ámbitos.** `ambito_que_cubre` leía la
   cabecera `Host` de todos los paquetes aunque el cliente no hubiera declarado
   ninguno; ahora sale antes, y `cabecera()` ya no reserva una copia en
   minúsculas para comparar.
3. **Prefiltro de dos bytes con índice por pareja.** Un mapa de bits
   `PAREJAS: [u64; 1024]` dice si una pareja de bytes puede empezar algún patrón;
   `INDICE` da el tramo de patrones que empiezan exactamente por esa pareja; y
   `ultimo_cuadra` comprueba el último byte antes de comparar el resto.

**382 µs → 37 µs por paquete**, y la propiedad queda fijada por
`el_relleno_del_paquete_no_multiplica_el_coste_de_mirarlo`, que mide el paquete
hostil contra el normal, no por un comentario.

## El índice: por entidad, no por tiempo

Un capturador clásico indexa por tiempo y deja al analista el trabajo de cruzar.
Aquí la clave primaria es la `Eid`, que es la misma entidad que arbitra el resto
del producto, y la respuesta a «enséñame todo lo de esta máquina» sale de una
sola búsqueda. El `Cursor` es opaco (`texto()` / `de_texto()`) para que la
paginación no dependa de la forma interna del índice.

Las particiones son `{política}-{día}`, y la purga es un `unlink` del fichero de
la partición entera: no hay que reescribir nada, y **lo purgado se cuenta por
entidad**, que es lo que permite decir «de esta máquina había 4 000 entradas y
caducaron 1 200» en vez de devolver una lista corta sin explicación.

Caducidades por política, con tope duro de 730 días: `Completo` 180, `SoloMetadatos`
90, `Cabeceras` 30, `Nada` 0.

## La reproducción, y dónde deja de prometerse

`reproducir()` vuelve a pasar un flujo guardado por el registro de disectores de
la FASE 89. La traducción de hecho a señal es **la misma función** (`senales_de`)
que se usa en vivo: si fueran dos, la reproducción podría dar un veredicto
distinto por una diferencia de código y no por una diferencia de bytes.

La fidelidad se declara en el tipo:

| `Fidelidad` | Qué promete |
|---|---|
| `Exacta` | los mismos bytes, y por tanto el mismo veredicto |
| `ConTapados { bytes }` | los mismos bytes **menos** los redactados |
| `Parcial { guardados, originales }` | se guardó menos de lo que hubo |

Un flujo con bytes tapados **no** promete reproducir el mismo veredicto: si la
señal estaba en la credencial que se tapó, al reproducirlo ya no está. Se dice en
la variante en vez de esconderse detrás de una media, y la igualdad estricta sólo
se exige donde la fidelidad es `Exacta`.

## Lo medido

| Medida | Cifra |
|---|---|
| Disco: 600 MB de tráfico, uno de cada cien flujos acusado | **3 MB** contra 600 MB guardándolo todo — **200×**, 99 % menos |
| Índice: 50 000 entradas de 1 000 entidades | **4,6 µs** por búsqueda de entidad |
| Carga sostenida: 200 000 paquetes, 300 MB, anillo bien dimensionado | **0** perdidos, cuadrando las dos invariantes |
| Anillo pequeño a propósito | 99 % perdidos, **desglosado en los tres tipos** |
| Redacción | 382 µs → **37 µs** por paquete |
| Coste de una entrada de índice, con asignador que cuenta | **156 bytes**, idénticos entre ejecuciones |
| Inundación: 409 600 entradas contra 10 de una máquina callada | a la callada le quedan **las 10**; la ruidosa se desaloja 405 514 veces |

El sobre se conserva entero en los dos modelos: las mismas 1 000 entidades y las
mismas 500 000 entradas de índice. El ahorro no sale de ver menos, sale de
guardar menos contenido de lo que se vio. **Quien conserva ese sobre es el
almacén**: al agente le caben 4096 entradas y las drena, y lo que le pasa si no
drena se mide aparte.

**El porcentaje redondea siempre en contra de la afirmación.** Con división entera
hacia abajo, 3 MB de 600 MB daban «100 % menos», que leído en voz alta es «no se
guardó nada», y se guardó. La parte almacenada se redondea hacia arriba: el único
100 que devuelve `ahorro()` es el de no haber guardado ni un byte.

**Y la medida de memoria se cuenta por hilo.** La primera versión usaba un
contador global y dio 237 bytes por entrada en una ejecución y 185 en la
siguiente, sin tocar el código: `cargo test` corre las pruebas del mismo binario
en paralelo y lo que reservaban las otras caía dentro de la medida. Una cifra que
baila un 30 % entre dos ejecuciones no es una medida, y una constante derivada de
ella tampoco. Es la misma lección que el RSS de la FASE 89, un nivel más abajo.

## El muro, declarado

- **AUSENTE: este crate no abre sockets ni lee interfaces de red.** Es sans-IO, como
  los disectores: recibe paquetes con su marca de tiempo. La captura de verdad la
  hace el plano de datos (XDP, `aegis-net`), que ya existe y tiene sus propias
  garantías. Lo que se prueba aquí es todo lo que pasa **después**, que es donde
  están las dos armas. La puerta lo comprueba: ni `std::net`, ni `TcpStream`, ni
  `SystemTime::now`.
- **AUSENTE: no se ha ejecutado Arkime contra este corpus.** Lo que se compara es
  el **modelo** de almacenamiento —guardarlo todo contra retener por veredicto—
  con el mismo perfil de tráfico para los dos y el perfil escrito en la prueba
  para que se pueda discutir. Presentar una cifra ajena como medida propia es lo
  que este producto existe para no hacer.
- **DECLARADO: un flujo con bytes tapados no promete el mismo veredicto.** Ver
  arriba.
- **El reensamblado sigue siendo del motor.** Este crate guarda y devuelve lo que
  le dan; no junta un mensaje partido en varios paquetes.
- **El drenaje del agente al almacén no está en este crate.** El techo del índice
  del agente presupone que alguien lo vacía; quién y cada cuánto es del plano de
  control. Aquí lo que se garantiza es que, si no lo vacía, el agente **no se come
  la máquina** y dice cuánto sobre perdió.
- **Cero dependencias externas** en los dos crates, y `#![forbid(unsafe_code)]` en
  el del agente.
