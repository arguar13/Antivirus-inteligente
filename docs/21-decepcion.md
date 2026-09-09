# Módulo 21 — Decepción: señuelos de red sin falsos positivos

> Componente: `crates/aegis-deception`.

Un detector de intrusiones normal tiene que decidir si un tráfico **legítimo** es
sospechoso, y por eso siempre se equivoca en algún caso. Un señuelo invierte el
problema: **el servicio no existe**. Ningún usuario, ninguna aplicación y ningún
sistema de monitorización tiene motivo para conectar a un puerto que no publica
nada, así que cualquier conexión es no autorizada *por definición*.

La ausencia de falsos positivos no es una promesa de calibración: es una
propiedad de la construcción.

La única fuente real de ruido son los escáneres autorizados de la propia
organización, y esos se conocen **por dirección**: van en la lista de exclusión,
no en una heurística.

---

## 21.1 Qué se finge, y por qué se saluda

Por defecto se levantan señuelos de **SSH (22)**, **SMB (445)** y **RDP (3389)**:
los tres puertos por los que se mueve lateralmente quien ya está dentro. El
catálogo incluye además FTP, Telnet, MySQL, PostgreSQL, VNC y WinRM.

Los protocolos con saludo de texto lo envían:

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
220 (vsFTPd 3.0.5)
```

No es decoración. Un escáner que no recibe nada anota «puerto abierto, servicio
desconocido» y sigue. Uno que recibe un saludo creíble anota **servicio y
versión** y **vuelve** con un exploit concreto. Esa segunda visita es información
de altísimo valor: dice qué herramientas usa el atacante y qué vulnerabilidades
busca. Lo que envíe queda guardado como evidencia, y es lo que distingue un
barrido —conecta y cierra— de un intento de explotación.

Los protocolos binarios (SMB, RDP, VNC) no saludan con texto: se acepta y se
escucha, que es lo que hace el servicio real.

---

## 21.2 Lo que un señuelo nunca hace

**Tapar un servicio de verdad.** Si el puerto 22 lo está usando el `sshd` real,
el señuelo no lo toma: dejaría la máquina sin administración remota, y un
producto de seguridad que corta el acceso legítimo se desinstala el mismo día.
Cuando ocurre se informa en `DecoyNet::skipped()` con el motivo (`InUse`,
`Privileged`), y se sigue. Hay una prueba que ocupa un puerto, comprueba que el
señuelo lo respeta y que el servicio real sigue atendiendo.

---

## 21.3 Qué clase de ataque describe lo observado

La confianza no se calcula: se hereda del señuelo. Lo que el sensor decide no es
*si* alertar, sino *qué* alertar, porque eso cambia la respuesta:

| Clase | Cuándo |
|---|---|
| `Contact` | Una conexión suelta |
| `Probe` | El origen envió datos: no sólo miró, habló |
| `PortSweep` | 3 o más señuelos distintos desde el mismo origen |
| `LateralMovement` | 2 o más servicios de **acceso remoto** (SSH/SMB/RDP/WinRM) |

Un solo servicio de acceso remoto todavía puede ser un inventario mal apuntado;
dos ya no: alguien está buscando por dónde saltar al siguiente equipo.

La alerta se emite **sólo cuando la gravedad sube**. Repetirla por cada paquete
convierte la consola en ruido y entrena al analista a ignorarla.

El bloqueo se pide a partir de la **segunda** interacción, no de la primera: una
sola conexión puede ser un inventario mal configurado de la propia organización,
y bloquear por ella acabaría cortando a un compañero.

---

## 21.4 La barandilla: el módulo más importante del crate

Un motor que bloquea direcciones sólo tiene una forma de fallar
catastróficamente: **bloquear la que no debía**. Bloquear la puerta de enlace
deja la máquina incomunicada; bloquear la red de administración deja al equipo
sin poder entrar a arreglarlo, *incluido el arreglo de quitar el bloqueo*. Es un
fallo del que no se sale por control remoto.

Por eso las exclusiones no son configuración opcional. Nunca se bloquean:

- La propia máquina (*loopback*) y la dirección sin especificar.
- La **puerta de enlace**, detectada sola desde `/proc/net/route`.
- Las direcciones de enlace local — en la nube, `169.254.169.254` es el servicio
  de metadatos: cortarlo deja la instancia sin credenciales ni DNS.
- Difusión y multidifusión.
- La lista de exclusión del despliegue (escáneres autorizados, red de gestión).

El fichero `/proc/net/route` lleva las direcciones en hexadecimal y en el orden
de bytes del **host**. Leerlas como big-endian convierte un `192.0.2.1` en un
`1.2.0.192`, y la barandilla dejaría de proteger la puerta de enlace de verdad;
hay una prueba con el formato exacto que fija ese detalle.

Cuando la barandilla rechaza un bloqueo, **se reporta**. Que el motor haya
querido bloquear la puerta de enlace es información operativa de primer orden,
tanto si significa que un atacante la está suplantando como si significa que la
detección está mal calibrada.

El bloqueo lleva **caducidad** (una hora por defecto), y la expira el kernel: un
bloqueo permanente por un barrido convierte una detección en una interrupción de
servicio permanente.

---

## 21.5 Dónde se aplica el bloqueo

El motor **decide**; la aplicación la hace un `NetworkFilter` de
[la capa de abstracción](18-scal.md):

- Por defecto, **nftables**: tabla propia, conjuntos hash, caducidad en el
  kernel.
- Con la característica `xdp`, el mismo veredicto baja a **XDP**, donde el
  paquete se descarta antes de que el stack TCP/IP lo toque: unos 50 ns en vez de
  microsegundos, y sin poder explotar un fallo del stack, porque nunca llega a
  él. El adaptador rechaza explícitamente las direcciones IPv6, porque el mapa
  del programa XDP es de cuatro bytes; aceptarlas en silencio dejaría al llamante
  creyendo que hay una contención que no existe.

---

## 21.6 Cómo se prueba

Los señuelos se prueban con **sockets de verdad**: se levantan, se conecta a
ellos, se lee el saludo que envían y se comprueba que la interacción queda
registrada con el origen y el puerto correctos. El bloqueo se prueba contra
`nftables` **real**, sobre direcciones de TEST-NET-2 (RFC 5737), que jamás se
enrutan y no son ni la de esta máquina ni la de su puerta de enlace.

Lo que no se puede fabricar con tráfico real —un ataque que venga de la puerta de
enlace— se inyecta como interacción sintética, porque la propiedad que se fija
ahí es la de la barandilla, no la del socket.

El **escenario 7** de la simulación de Red Team levanta la red de señuelos de
verdad, barre sus tres puertos desde fuera del proceso, y comprueba dos cosas:
que el barrido se clasifica como movimiento lateral, y que la barandilla impide
bloquear la dirección de la propia máquina.
