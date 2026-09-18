# AegisDissect — disección de protocolos empresariales, industriales y de nube

**FASE 89.** Crate `crates/aegis-disectores`. Puerta: `tools/verificar-disectores.sh`
(grupo `disectores` de `tools/ci-local.sh`).

## La pregunta que este crate existe para contestar

Cuando falta una alerta, sólo hay dos explicaciones: **no pasó nada**, o **pasó
algo que no supimos leer**. Ningún sensor del sector distingue las dos. Cuando un
analizador de Wireshark o de Zeek no entiende un mensaje, lo salta o lo marca como
malformado, y el analista ve una traza con menos líneas sin saber que faltan.

Esa diferencia es un incidente. Un atacante que use una extensión del protocolo
que el disector no conoce pasa por delante de un sensor que no declara su
cobertura, y el informe dice que no pasó nada.

Aquí cada disección devuelve, además de los hechos, **una cifra de cobertura**:
cuántos mensajes se entendieron, cuántos se reconocieron y no se analizaron, y
cuántos no se reconocieron. `Cobertura::completa()` es lo único que autoriza a
leer una lista de hechos vacía como «este flujo no llevaba nada».

## Por qué un crate aparte

El árbol del motor no puede crecer con cada protocolo. `aegis-wire` corre en la
ruta caliente de cada paquete de cada endpoint: su código se audita entero y su
memoria está presupuestada. Los disectores son piezas independientes que se
añaden, se quitan y **se compilan por perfil**: una pasarela industrial no
necesita el de Kafka y un servidor de aplicaciones no necesita el de Modbus.

| Perfil | Familias | Disectores |
|---|---|---|
| `Completo` | las nueve | 38 |
| `PuestoDeTrabajo` | identidad, ejecución remota, correo, web, túneles, nube | 23 |
| `Servidor` | identidad, ejecución remota, bases, mensajería, web, túneles, nube | 31 |
| `PasarelaIndustrial` | industrial, identidad, ejecución remota, túneles | 22 |

La pasarela lleva identidad y ejecución remota además de lo industrial **a
propósito**: es el sitio por donde un ataque pasa de la red de oficina a la de
planta, y un sensor que sólo mirase Modbus vería la orden que para la CPU sin ver
por dónde entró quien la mandó.

## Lo que se añade, por familia

- **Identidad y directorio**: NTLM (dentro de SMB, HTTP, DCERPC o LDAP — se busca
  la firma `NTLMSSP\0`, que es lo que hace que se vea en los cuatro sitios),
  RADIUS, Diameter, SAML y OAuth/OIDC.
- **Ficheros y ejecución remota**: DCERPC con **catálogo de interfaces**, NFS
  sobre ONC RPC, WebDAV, RDP, VNC y WinRM.
- **Bases de datos**: MySQL, PostgreSQL, TDS, MongoDB, Redis y Elasticsearch.
- **Mensajería**: AMQP, MQTT, Kafka y gRPC.
- **Correo**: IMAP, POP3 y **extracción de adjuntos** nombrados por su SHA-256.
- **Web moderna**: HTTP/2 con la tabla estática de HPACK, HTTP/3 sobre QUIC y
  WebSocket.
- **Industrial y OT**: Modbus/TCP, DNP3, S7comm, BACnet/IP y OPC-UA.
- **Túneles y evasión**: DoH, DoT, WireGuard, IKEv2, SOCKS y los túneles sobre
  HTTP e ICMP medidos por entropía.
- **Nube**: el servicio de metadatos de instancia de seis proveedores.

## Las tres piezas que valen más que el recuento

### 1. `escribe`, en las órdenes industriales

`Hecho::OrdenIndustrial` lleva un campo `escribe`. Leer un registro de un PLC es
telemetría y ocurre miles de veces por minuto; escribirlo mueve algo en el mundo
físico. Contarlos juntos entierra el segundo bajo el primero, que es lo que hace
un sensor que sólo sepa decir «vi Modbus».

De S7comm sale `parar-cpu` (función 0x29) con nombre propio. De DNP3, el par
`seleccionar`/`operar` que arma y dispara una salida. De BACnet,
`controlar-la-comunicacion-del-dispositivo`, que es con lo que se aísla un
controlador antes de manipularlo.

### 2. El UUID de DCERPC **es** la técnica

De un `bind` sale el identificador del interfaz, y ese identificador nombra el
ataque: `drsuapi` es DCSync, `netlogon` es donde vivió Zerologon, `efsrpc` es
PetitPotam, `svcctl` es cómo PsExec crea su servicio, `atsvc` es una tarea
programada a distancia. Un sensor que sólo diga «vi DCERPC al 135» tiene delante
la técnica y no la nombra. El catálogo son 18 interfaces, cada uno con **para qué
se usa de verdad** escrito al lado, porque eso es lo que aparece en la alerta.

### 3. Un solo tipo de hecho para todo

Los cinco de identidad emiten `AutenticacionVista`; los seis de bases,
`OperacionDeBaseDeDatos`; los seis de ejecución remota, `EjecucionRemota`. «Cuántos
intentos fallidos tuvo este usuario» y «quién tocó esta tabla» son consultas, no
proyectos de correlación.

## Las tres invariantes de la fase

### Sans-IO

Ningún disector abre un socket, lee un fichero ni mira el reloj: recibe `&[u8]` y
devuelve hechos. No es purismo — es lo que permite construir cada ataque entero en
una prueba, sin montar un servidor y sin condiciones de carrera. La puerta lo
comprueba **por ausencia**, que es la única forma de comprobar una ausencia.

### Una cota por flujo no es una cota

El atacante elige también el número de flujos. Con sólo el tope por flujo, cien
mil flujos de 64 KiB son seis gigabytes que decide el atacante.

Los dos techos de este crate **son los mismos que los del motor**, derivados de
sus constantes y no copiados:

```rust
pub const MAX_ESTADO_POR_FLUJO: usize = aegis_wire::motor::MAX_BUFER_APP;   // 64 KiB
pub const MAX_ESTADO_GLOBAL:   usize = aegis_wire::MAX_MEMORIA_APP;         //  4 MiB
const _: () = assert!(MAX_ESTADO_GLOBAL <= aegis_wire::MAX_MEMORIA_APP);
```

La comprobación es de **compilación**, no de prueba: una prueba se puede saltar
con `--skip`; esto no. El estado de un disector *es* un mensaje de aplicación a
medio construir, exactamente lo que el motor ya presupuestaba; un crate nuevo que
se declarase su propio techo no estaría cumpliendo la invariante, estaría
esquivándola.

**Medido** (`tests/techo_global.rs`, con un asignador que cuenta lo vivo): cien mil
flujos respetando cada uno su tope dejan 4 194 304 bytes contabilizados y
4 263 688 vivos de verdad, con 99 936 estados soltados **y contados**. Cien mil
disecciones seguidas dejan **0 bytes** vivos al acabar.

### El sensor no puede ser un amplificador

El rasgo `Disector` devuelve hechos, no bytes para enviar: no hay forma de
responder. No se sondea y no se pregunta al dispositivo, que en una red industrial
no es una preferencia de estilo — un PLC de hace veinte años se cae con un escaneo
de puertos, y el sensor que «enriquece» preguntándole provoca la parada de planta
que venía a evitar.

## `Fuerza`: por qué el orden de la lista no decide nada

Los protocolos no se reconocen todos igual de bien. Una trama de WebSocket son dos
bytes de marco; una cabecera de Modbus tiene cuatro campos que se comprueban entre
sí; un mensaje NTLMSSP lleva ocho bytes de firma. Si el registro probara en el
orden de inserción, el más débil se quedaría con el tráfico del más fuerte — y eso
**se midió**: una cabecera de Modbus encajaba como trama de continuación de
WebSocket.

Cada disector declara su `Fuerza` (`Marca`, `Forma`, `Indicio`) y el registro
prueba de más fuerte a más débil. Cuando dos de la misma fuerza reconocen lo
mismo, gana el primero **y se cuenta**: el solape existe y callarlo lo dejaría
escondido tras el orden de inserción.

## Lo que encontró el barrido hostil

`tests/hostil.rs` cruza cada entrada derivada de un vector válido —todos sus
prefijos, sus mutaciones de un byte, sus longitudes al máximo, ruido reproducible—
contra **cada** disector y cada contexto. Encontró diez defectos reales, todos
corregidos de raíz:

| Defecto | Corrección |
|---|---|
| MySQL, Redis, MQTT, TDS, IMAP, POP3: `reconoce` y `disecar` decidían distinto | una sola función de clasificación, usada por los dos |
| Modbus aceptaba una excepción sobre una función inexistente | se declara malformada |
| S7comm, SOCKS, WireGuard, DoT, HTTP/3: `disecar` ignoraba el contexto | la guarda está en los dos sitios |
| TDS reclamaba el 2 % del ruido puro | se exige la cabecera entera: estado, ventana y longitud del paquete |
| IKEv2 reclamaba el 0,15 % | los cinco bits reservados de las banderas y la longitud del datagrama |
| HTTP/3 reclamaba el 0,03 % | los dos enteros de longitud variable de un paquete inicial |

**Medido después**: de 60 000 mensajes de ruido puro, **0** se dan por entendidos.

## El muro, declarado

- **No se descifra nada.** De DoT, WireGuard y HTTP/3 se ve el sobre. Se cuenta
  como `Motivo::Cifrado` y no como «no implementado», porque una se arregla
  escribiendo código y la otra no. La cifra `perdidos_por_falta_de_codigo()`
  separa la deuda del límite.
- **HPACK sin Huffman y sin tabla dinámica.** De HTTP/2 salen las cabeceras de la
  tabla **estática**, que no dependen de haber visto el principio de la conexión.
  Las demás se cuentan como hueco declarado.
- **Protobuf sin definiciones.** De gRPC se ve el marco del mensaje y la ruta; el
  cuerpo no se puede nombrar sin el fichero `.proto`.
- **El reensamblado es del motor.** Un adjunto partido en varios trozos no lo junta
  este crate.
- **No hay captura de una planta real.** Los vectores son de la norma de cada
  protocolo, con documento y sección citados.

## La comparación, medida de un lado y citada del otro

**Una mitad se mide y la otra se cita, y se dice cuál es cuál.** Los 49 protocolos
de este sensor salen de construir el registro y preguntarle. Los 47 analizadores
del de referencia están transcritos de su documentación: no se ha ejecutado Zeek
contra este corpus, y presentar un dato de segunda mano como si se hubiera medido
es exactamente la clase de cifra que este crate existe para no producir.

De la lista citada se quitaron `conn` (el registro de conexiones, no un
analizador), `krb` (otro nombre de `kerberos`) y `ssl_tunnel` (variante del de
TLS): una comparación se hace igual de deshonesta inflando al otro que
inflándose uno.

- **17 sólo aquí**: diameter, saml, oauth, webdav, winrm, mongodb, redis,
  elasticsearch, kafka, grpc, **s7comm**, **opcua**, doh, dot, wireguard, ikev2,
  metadatos-de-nube.
- **17 sólo allí**: x509, irc, sip, snmp, syslog, mount, portmap, gssapi, xmpp,
  finger, ident, telnet, login, ayiya, teredo, gtpv1, vxlan.

El recuento no es la diferencia: se mueve añadiendo disectores triviales. La
diferencia son las **siete propiedades** que el otro no tiene en ningún protocolo,
empezando por decir cuánto no entendió, y siguiendo por separar lo cifrado de lo
no implementado, declarar por adelantado lo que cada disector no analiza, emitir un
solo tipo de hecho, marcar si una orden industrial escribe, tener un techo global
con recuento de lo que se suelta, y traer S7comm y OPC-UA, que son los dos
protocolos con los que se para una planta.

**Cobertura declarada, medida**: 170 clases de mensaje entendidas y **153 huecos
declarados**. Un sensor con cero huecos declarados estaría diciendo que lo
entiende todo, y de estos protocolos no se entiende ninguno entero.
