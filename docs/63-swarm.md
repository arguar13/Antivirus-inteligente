# Módulo 63 — AegisSwarm: el enjambre autónomo

> Componentes: `crates/aegis-swarm/` (núcleo *sans-io*, en el agente),
> `swarm-net/` (transporte libp2p, workspace aparte), `tools/verificar-swarm.sh`.

## 63.1 Cortar el habla es más barato que romper la defensa

Un adversario competente no ataca la flota de frente: **le corta el habla**.
Tirar la salida a Internet o el enlace de una sede es barato, y suele ser lo
primero, porque a partir de ahí cada endpoint está solo y la consola no ve nada.
Un EDR que dependa por completo de su plano de control queda, exactamente en ese
momento, reducido a un antivirus de firmas locales.

Esta fase es lo que la flota hace entonces: los agentes se reparten entre ellos
indicadores, reglas YARA y órdenes de contención, sin consola.

## 63.2 La pregunta que decide el diseño entero

> Si un agente puede decirle al enjambre «aísla al equipo X», ¿qué consigue el
> atacante que comprometa **un** endpoint?

Consigue un botón de denegación de servicio sobre toda la organización. Y algo
peor: puede aislar precisamente las máquinas que lo habrían detectado, o el salto
del SOC desde el que se responde. **Una malla de órdenes mal diseñada no es una
defensa: es movimiento lateral regalado.**

La [FASE 23](23-malla.md) esquivó el problema declarando que una vacuna sólo
puede AÑADIR indicadores, nunca retirarlos. Aquí no se puede esquivar, porque el
requisito es repartir órdenes. La respuesta cabe en una frase:

> **El enjambre transporta autoridad; no la concede.**

Una orden sólo vale con la firma del **plano de control**, cuya clave privada no
está en ningún agente. El enjambre no fabrica órdenes: lleva órdenes que el plano
de control ya emitió, cuando el plano de control no se alcanza. Es un transporte
de último recurso, no un consenso.

## 63.3 Tres clases de mensaje, tres reglas de confianza distintas

| Clase | Quién puede originarla | Qué hace falta para actuar |
|---|---|---|
| **Orden** (aislar, matar, cuarentena, revocar tickets) | sólo el plano de control | firma híbrida válida + época monótona + dentro de su ventana |
| **Artefacto** (reglas YARA, modelos) | sólo el plano de control | firma del descriptor + hash de cada trozo + hash del conjunto |
| **Observación** («vi este hash hacer esto») | cualquier par, con su identidad de matriculación | **K pares distintos** dentro de una ventana |

Una observación **no manda nada**: es evidencia. Lo que la convierte en acción es
el corroboro, y eso transforma «un endpoint comprometido mueve a la flota» en
«hacen falta K endpoints comprometidos».

### La honestidad del límite del quorum

El quorum vale lo que cuesta comprometer K endpoints matriculados. **No defiende**
contra un adversario que ya controla K equipos, y no se debe vender como si lo
hiciera. Lo que sí hace, y es mucho, es que un solo equipo comprometido no pueda
mover nada, que es el caso abrumadoramente más común.

Y descansa entero sobre una propiedad: la identidad del origen es el **CN de
matriculación**, autenticado por el transporte, no un campo que el par rellene. Si
el par pudiera elegir su nombre, fabricaría K identidades desde una máquina y el
quorum no valdría nada.

## 63.4 El ataque central: reproducir una orden auténtica

Éste es el ataque que no se puede parar con criptografía, y por eso es el
interesante.

El atacante graba una orden legítima de la red, provoca el corte, y la vuelve a
soltar. **La firma verifica perfectamente**, porque es auténtica. Reproducir
«aísla al equipo 17» cuando ya no toca, o peor, reproducir órdenes viejas en
cascada, es gratis si sólo se comprueba la firma.

Lo paran dos cosas que no son criptográficas:

- **Época monótona por (acción, sujeto).** Una época ya superada para ese sujeto
  se rechaza. Y es *por sujeto*: aislar al equipo 18 no puede quedar bloqueado
  porque ya se aislara al 17 con una época mayor.
- **Ventana temporal.** Una orden caduca, con holgura de reloj de cinco minutos
  para absorber la deriva normal de una flota sin abrir una ventana útil.

## 63.5 Lo que no viaja, con firma o sin ella

Levantar un aislamiento, desactivar una regla o degradar la protección son justo
los efectos que el atacante busca. Esas órdenes **no se aceptan por el enjambre
aunque su firma sea auténtica**: reproducidas en el instante del corte apagan la
defensa con una firma buena de verdad.

La defensa aquí **no es criptográfica, es de clase**: esas acciones viven en un
rango de discriminante aparte (≥ 200) y el protocolo las rechaza antes de gastar
siquiera una verificación de firma. Retirar protección exige el canal directo con
el plano de control, que el atacante tendría que comprometer aparte.

Es la doctrina de la FASE 23 —sólo se añade protección, jamás se quita— llevada de
los indicadores a las órdenes.

## 63.6 La tentación que no se cae: aislarse no relaja nada

Parece razonable **bajar** el umbral de corroboro cuando el agente está aislado,
«porque no hay a quién preguntar». Es exactamente al revés.

Un adversario competente **provoca** el aislamiento como primer paso, precisamente
para que la flota decida sola. Estar aislado es motivo para ser más cuidadoso, no
menos. El umbral **no baja nunca**; lo único que cambia al aislarse es que el
enjambre pasa de ser un atajo a ser el único camino.

Hay una prueba dedicada a fijar esa decisión, porque es el tipo de cosa que un
cambio bienintencionado deshace.

## 63.7 Las cuatro cotas, y por qué su orden es el diseño

Un mensaje entrante recorre este orden, y no es negociable:

1. **Tasa por par** — antes de nada. Verificar primero y limitar después
   convierte la malla en un **amplificador de CPU**: mandar basura firmada con
   cualquier cosa costaría al receptor una verificación ML-DSA por mensaje, que es
   justo lo que el atacante quiere. Y la cuota es por par: que uno inunde no puede
   silenciar a los vecinos honestos.
2. **Tamaño y formato** — acotado, sin reservar memoria por lo que diga nadie.
3. **Deduplicación** — lo ya visto ni se procesa ni se reenvía. El identificador
   se deriva del contenido e **ignora los saltos**: el mismo mensaje por dos
   caminos trae contadores distintos, y si eso cambiara el identificador la
   inundación no convergería nunca.
4. **Autenticidad** — al final, y según la clase.

Más los topes de memoria, que no son adorno: registro de vistos, indicadores en
seguimiento, testigos por indicador y reensamblados en curso están todos acotados.
Sin ellos, un par que emite observaciones de indicadores siempre nuevos hace crecer
la memoria del receptor sin límite, con mensajes perfectamente válidos.

Un detalle que costó pensarlo: cuando el seguimiento se llena se descarta **lo
nuevo, no lo viejo**. Al revés, inundar con indicadores nuevos borraría corroboros
a punto de cerrarse — justo lo que el atacante querría.

## 63.8 Reglas YARA por trozos

Un mensaje de la FASE 23 cabe en un datagrama de 1200 bytes, y eso es su diseño.
Un paquete de reglas YARA son cientos de kilobytes. Trocear exige reensamblar, que
es una superficie de ataque clásica —los fragmentos IP y sus dos décadas de CVE—,
así que el reensamblado está acotado por todos lados:

- **El tamaño viene de lo firmado.** El receptor reserva memoria según el
  descriptor firmado, jamás según lo que diga un trozo. Si lo pusiera un trozo, uno
  que declarase «desplazamiento 4 GiB» provocaría una reserva de 4 GiB: denegación
  de servicio con un mensaje de 50 bytes.
- **Cada trozo se comprueba al llegar**, contra su hash en el descriptor. Verificar
  sólo al final permitiría envenenar la reconstrucción gratis hasta el último byte.
- **Y al final, además, el hash del conjunto**: los hashes de trozo prueban que
  cada pieza es la que toca; el del conjunto, que están todas y en su sitio.
- **Un trozo suelto no abre nada.** Sólo un descriptor firmado abre una ranura de
  reensamblado; si no, cualquier par agotaría las ranuras gratis.

## 63.9 Dónde está libp2p, y por qué no está en el agente

El backlog pedía integrar una malla *gossip* de libp2p. Está integrada —
gossipsub sobre TCP con Noise y Yamux, más mDNS para descubrir vecinos — y vive en
**`swarm-net/`**, un workspace aparte que consume el núcleo. No está dentro del
agente, y la razón es medida, no opinada:

| | dependencias transitivas | runtime | dónde corre |
|---|---|---|---|
| núcleo `aegis-swarm` | **0 nuevas** | ninguno (síncrono) | dentro del agente, en cada endpoint |
| `swarm-net` con libp2p | **340 crates** | tokio | fuera del agente |

El agente corre con privilegios en cada endpoint, tiene un presupuesto de **45 MB
de RSS** y trata su árbol de dependencias como superficie de ataque. Meterle 340
crates de código **que analiza entrada hostil de la red** es precisamente el riesgo
de cadena de suministro que un fabricante de seguridad no puede asumir. Es la misma
razón por la que la FASE 23 se escribió con UDP y un AEAD auditable en un fichero
en vez de con QUIC.

Esa propiedad no se promete: `tools/verificar-swarm.sh` **comprueba** con
`cargo tree` que el núcleo no arrastra ni libp2p ni tokio al agente, y falla si
algún día alguien los cuela.

Y la separación no es sólo higiene: al ser el núcleo *sans-io*, **cada ataque de
esta fase se construye entero en una prueba**, sin red y sin condiciones de
carrera. Si las decisiones vivieran dentro del transporte, probarlas exigiría
levantar una red y acabarían sin probarse.

## 63.10 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Reglas de confianza de las tres clases | **sí** | claves híbridas Ed25519 + ML-DSA-65 reales, firmando y verificando |
| **Reproducción de una orden antigua y auténtica** | **sí** | se emite de verdad y la corta la época; no se puede fingir con una firma falsa |
| Un endpoint comprometido fabricando órdenes | **sí** | firma con su propia clave y se rechaza |
| Un reenviador cambiando el sujeto en tránsito | **sí** | rompe la firma |
| Una sola máquina gritando mil veces | **sí** | se queda en un testigo |
| Inundación, duplicados, saltos, memoria | **sí** | construidos contra el núcleo |
| Trozo envenenado y trozo que miente el tamaño | **sí** | rechazados al llegar |
| Entrada hostil arbitraria | **sí** | barrido determinista; ninguna entrada provoca pánico |
| **Transporte libp2p** | **sí** | **dos nodos reales** por loopback: Noise, Yamux y gossipsub auténticos |
| Descubrimiento por **mDNS** | — | necesita multicast en la red local; un contenedor de CI no lo tiene. **Declarado** |

La fila del transporte era el sitio natural para declarar un muro y no hizo falta.
`swarm-net/tests/malla_viva.rs` levanta dos `Swarm` completos, los conecta de
verdad y comprueba las **dos mitades** del contrato: que una orden legítima cruza y
se aplica, y que **una orden de un impostor cruza igual y el núcleo la rechaza**.

Esa segunda prueba es la que enseña dónde está la seguridad de esta fase: no en el
transporte, que no juzga nada, sino en el núcleo. Un transporte distinto mañana no
cambia ni una de las garantías.

Y se ejercen también los dos casos que rompen un enjambre mal escrito: **publicar
sin vecinos** —el estado normal de un endpoint recién arrancado en una red rota,
que es el escenario para el que existe la fase— y **la caída de un vecino a
mitad**. Ninguno de los dos puede tumbar al nodo que queda.
