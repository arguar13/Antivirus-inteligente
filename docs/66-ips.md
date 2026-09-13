# Módulo 66 — AegisIPS: prevención en línea a velocidad de cable

> Componentes: `crates/aegis-ips/`, `drivers/linux/aegis-bpf/src/aegis_ips.bpf.c`,
> `tools/verificar-ips.sh`.

## 66.1 La frase que gobierna la fase entera

Todo lo anterior del producto **observa**. Esta fase **corta**. Y la diferencia
cabe en una frase:

> Un falso positivo en un IDS es una alerta que alguien descarta.
> Un falso positivo en un IPS es una **interrupción de servicio**.

Eso no es un matiz: cambia el diseño entero. No hay salvaguardas *además* del
motor de bloqueo — las salvaguardas **son** el diseño, y el motor de bloqueo es
la parte fácil.

## 66.2 Dónde corre cada cosa

| | Quién | Dónde | Por qué ahí |
|---|---|---|---|
| **Juzgar** | `decisor::Decisor` | Ring 3 | aplicar reglas con contexto no cabe en un programa que el verificador acota |
| **Aplicar** | `aegis_ips.bpf.c` | kernel | un paquete que sube a userland para decidirse ya pagó el coste que esto existe para evitar |

El veredicto de un flujo se **escribe en un mapa eBPF**. El primer paquete
sospechoso sube, se juzga una vez, y el veredicto baja. A partir de ahí el resto
del flujo se corta con una búsqueda de mapa, sin volver a subir.

Eso está **medido**, no prometido: hay una prueba que manda mil paquetes del
mismo flujo y comprueba que los mil se cortaron y los mil los resolvió la caché
del kernel, sin que userland intervenga entre medias.

## 66.3 Por qué TC y no XDP

XDP es más barato y corre antes, y por eso el filtro de barridos de `aegis-net`
sigue donde estaba. Pero hay un hecho que decide:

> **XDP no tiene camino de salida.** Es un gancho de recepción y nada más.

Y para un EDR el sentido que más importa cortar es el **saliente**:

| Qué sale por ahí | Por qué importa |
|---|---|
| La baliza hacia el C2 | es la señal de que la máquina ya está controlada |
| La exfiltración | es el daño consumado |
| El movimiento lateral | es cómo el incidente pasa de una máquina a la organización |

Un IPS que sólo filtre lo que entra deja pasar precisamente el tráfico que
confirma que ya es tarde. TC con `clsact` tiene los dos ganchos, así que un solo
programa cubre la conversación entera — y **convive** con el filtro XDP en la
misma interfaz, de modo que esta fase no tuvo que quitar ni reescribir nada de lo
que ya funcionaba.

## 66.4 Las cuatro salvaguardas

| # | Salvaguarda | Dónde se comprueba | Qué impide |
|---|---|---|---|
| 1 | Sólo la confianza **alta** corta | Ring 3 | que una heurística tire la red de un cliente |
| 2 | **Activos protegidos** | Ring 3 **y kernel** | que un incidente se convierta en un apagón |
| 3 | **Modo**, por defecto sólo detección | Ring 3 **y kernel** | llegar bloqueando el primer día |
| 4 | **Tope de bloqueos** con degradación | Ring 3 | que un motor que se equivoca siga equivocándose a escala |

### 1. Sólo la confianza alta corta

No todas las detecciones valen lo mismo:

- «El SHA-256 de este fichero está en la lista de indicadores» es una igualdad.
  O coincide o no.
- «El nombre que ha resuelto tiene mucha entropía» es una heurística. Acierta
  mucho y falla con dominios legítimos que generan subdominios — redes de
  distribución de contenido, telemetría, el antivirus de la competencia.

Tratarlas igual obliga a elegir entre no cortar nunca (y entonces el IPS no
previene) o cortar con heurísticas (y entonces tira producción). La confianza es
lo que permite no elegir.

Y no es configurable: está en el tipo, en `Confianza::puede_cortar`, y el motor
no ofrece ninguna vía para saltárselo. **Una política que se puede aflojar se
afloja**, normalmente el día que alguien tiene prisa.

### 2. Los activos protegidos

Cortar un endpoint infectado es contención. Cortar el controlador de dominio es
un apagón: nadie se autentica, nadie entra a su equipo, y el incidente pasa de
«una máquina comprometida» a «la organización parada». Lo mismo con el DNS de la
organización, y con el propio plano de control de AegisCore — cortarlo deja a la
flota sin consola *justo cuando hace falta*, y encima ciega la vista desde la que
se vería que el corte fue un error.

**Y no es sólo un accidente posible: es un objetivo.** Un atacante que sepa que
hay un IPS automático intentará que corte por él. Basta con que el tráfico hacia
el controlador de dominio se parezca a lo que la regla busca. Si lo consigue, ha
logrado una denegación de servicio sobre la infraestructura crítica **usando la
propia defensa como arma**, sin vulnerar nada.

Es la misma doctrina de activos protegidos de la [FASE 69](64-predict.md).

### 3. El modo, y el camino escalonado

1. **Sólo detección** *(por defecto)*. Se ve lo que hay, no se toca nada.
2. **Bloqueo con aprendizaje.** Se registra lo que se HABRÍA cortado, con su
   regla y su flujo, sin cortarlo. El cliente mira esa lista y decide.
3. **Bloqueo.** Sólo cuando esa lista ya no tiene sorpresas.

El paso 2 es lo que hace posible el 3 **sin apostar**. Sin él, activar el bloqueo
es un salto a ciegas sobre la red de otro.

### 4. El tope y la degradación

> Si el motor está bloqueando media red, el motor está mal, **no la red**.

Un IPS que empieza a cortar muchísimo casi nunca está conteniendo una intrusión
masiva: es una regla mal escrita, un indicador envenenado, o un cambio en el
tráfico legítimo del cliente que la regla no contemplaba. En los tres casos,
seguir cortando empeora las cosas a cada segundo. Y en el caso que *no* es un
error, cortar media red por decisión automática tampoco es la respuesta: eso lo
decide una persona, no un umbral.

Al pasar el tope, el motor **se degrada solo** a sólo detección y lo **declara**.

Dos detalles que importan:

- **La degradación es pegajosa.** No se re-arma sola al bajar el ritmo. Si lo
  hiciera, entraría en un ciclo de cortar → pasarse → parar → volver a cortar,
  que desde fuera se ve como una red que va y viene: peor de diagnosticar que una
  cortada del todo. Reactivarla exige una intervención deliberada.
- **La ventana es deslizante de verdad.** Con un contador que se reinicia cada
  minuto, mandar el tope entero justo antes del corte y otro tanto justo después
  pasa desapercibido — el doble del tope en un instante, sin disparar nada. Hay
  una prueba con esa ráfaga exacta.

## 66.5 Por qué dos de las salvaguardas se comprueban dos veces

Los activos protegidos y el modo se comprueban en Ring 3 **y otra vez** en el
programa TC, antes de cortar.

No es redundancia por gusto:

> Una salvaguarda que depende de que el código de decisión esté bien no protege
> del caso que importa, que es justamente que el código de decisión esté mal.

Hay una prueba que lo ejerce sin ambigüedad: se escribe **a mano** un veredicto
de corte para un flujo cuyo destino es un activo protegido —simulando un fallo de
lógica en userland, o una vía que nadie previó— y se comprueba que el kernel
**no lo aplica**. La primera capa puede fallar; la segunda aguanta.

Y con el modo, lo mismo: en sólo detección el programa no corta aunque el mapa de
veredictos diga que sí. Eso es lo que hace que «modo aprendizaje» sea una promesa
sostenible y no una intención de userland.

## 66.6 Las reglas miran hechos, no bytes

Un IPS clásico busca cadenas dentro del paquete. Funciona, y tiene dos problemas
conocidos: se evade partiendo la cadena entre dos segmentos, y no puede decir
nada del tráfico cifrado.

Aquí las reglas miran lo que produce [`aegis-wire`](65-wire.md): un nombre DNS ya
descomprimido, una huella JA3 ya calculada, el SHA-256 de un fichero ya
reensamblado. Eso cierra las dos evasiones de golpe —el disector ya reensambló y
ya normalizó— y permite escribir reglas sobre sesiones cifradas **sin descifrar
nada**, porque la huella y el SNI viajan en claro.

Un detalle que parece menor y no lo es: un criterio de sufijo DNS corta **en el
punto**. Con un `ends_with` pelado, una regla para `evil.com` cortaría también
`noevil.com` — que es de otro, y que es trivial de registrar a propósito para que
cortemos a un tercero.

## 66.7 El circuito entero, y por qué se prueba junto

Las pruebas del decisor comprueban que se decide bien. Las del plano comprueban
que el kernel corta lo que se le marca. Lo que de verdad hace falta probar es
**la unión**:

> Que la clave de flujo que calcula el disector sea la misma que escribe userland
> y la misma que busca el kernel.

Si esas tres no coincidieran, cada pieza pasaría sus pruebas por separado y el
producto **no cortaría nada, sin un solo error visible**. Por eso hay una prueba
que construye un paquete DNS de verdad, lo mete por `aegis-wire`, juzga el hecho
que sale, baja el veredicto al kernel, y comprueba que el siguiente paquete de
esa conversación se corta.

## 66.8 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Un activo protegido no se corta jamás | **Sí, en las dos capas** | con el veredicto de corte **escrito a mano** en el mapa, simulando un fallo de userland |
| Sólo la confianza alta corta | **Sí** | las tres confianzas contra la misma regla y el mismo hecho |
| El modo de aprendizaje registra y no corta | **Sí** | y se comprueba que lo **cuenta**, que es su razón de ser |
| La degradación se dispara y se declara | **Sí** | y llega **hasta el kernel**: con los veredictos ya escritos, deja de cortar |
| Ráfaga a caballo del corte de ventana | **Sí** | un contador que se reinicia no la vería |
| Decisión reproducible | **Sí** | el mismo conjunto de reglas decide igual sea cual sea el orden de carga |
| Los programas eBPF pasan el verificador **real** | **Sí** | `make -C drivers/linux/aegis-bpf verify`, en cada `make ci` |
| El corte, contra el kernel de verdad | **Sí** | `BPF_PROG_RUN`: el kernel ejecuta el programa y devuelve su veredicto |
| El corte en los **dos sentidos** y en **egreso** | **Sí** | la vuelta es por donde responde el C2; el egreso es lo que XDP no puede |
| Que no se pierde ningún paquete | **Medido** | todo lo que entra sale contado en alguna categoría, sin huecos |
| Que el corte no cuesta subir a userland | **Medido** | mil paquetes, mil cortes, mil aciertos de caché |
| Sin `CAP_BPF` | **Se declara omitido** | «no se pudo mirar» y «se miró y estaba bien» no son lo mismo |
| Trama con cabecera IP truncada | **Parcial, y se declara** | `BPF_PROG_RUN` se niega a construir el `skb`; en una NIC real sí llegan, y las cubren las comprobaciones contra `data_end` que el verificador exige |
| Que una NIC real descarte con `TC_ACT_SHOT` | **No aquí** | es comportamiento del kernel, no de este código |
| Cortar a velocidad de 10 GbE | **No aquí** | se mide en hardware con carga real, no en un contenedor de CI |
| IPv6 | **No, y se declara** | el plano de datos juzga IPv4; lo demás pasa y **se cuenta** |

Dos filas merecen decirse en voz alta. La de IPv6, porque un punto ciego que
nadie mide es un punto ciego que nadie arregla — por eso se cuenta en
`NO_CLASIFICADOS` en vez de callarse. Y la de las protecciones IPv6: al
sincronizar la lista al kernel, las direcciones IPv6 se saltan y **se devuelven
contadas**, porque creer que un activo está protegido abajo cuando no lo está es
exactamente la clase de error que esa lista existe para no cometer.
