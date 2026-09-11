# Módulo 51 — ITDR: detección de amenazas de identidad

> Componentes: `server/crates/aegis-itdr/`,
> `server/crates/aegis-server/src/itdr.rs`.

## 51.1 La identidad es el nuevo perímetro

El malware moderno muchas veces no **explota** nada: **inicia sesión**. Roba un
ticket, falsifica una credencial, o pide en masa tickets de servicio para
crackearlos offline. En el endpoint todo se ve legítimo —procesos normales
hablando Kerberos— y por eso la detección de identidad tiene que vivir donde el
ataque se ve **entero**: el plano de control, que correlaciona la capa de
autenticación de toda la flota.

El motor ITDR tiene dos mitades. La primera analiza **Kerberos** para detectar
**Kerberoasting**, **Golden Ticket** y **Silver Ticket**. La segunda construye un
**grafo de identidad** de la flota —quién puede actuar como quién— y detecta
**escaladas de privilegio** por alcanzabilidad y por centralidad. La lógica pura
vive en el crate `aegis-itdr`; el módulo `itdr.rs` del servidor la conecta al bus
de alertas del panel, con su técnica MITRE ATT&CK.

## 51.2 Kerberoasting: detectar por la forma, no por el volumen

Kerberoasting abusa de un hecho de diseño: cualquier usuario autenticado puede
pedir un ticket de servicio para cualquier SPN, y ese ticket va cifrado con la
clave de la cuenta de servicio. El atacante pide muchos y los craquea offline.

El caso que separa un buen detector de uno malo **no** es detectar el barrido
—eso lo hace cualquier contador—, es **no disparar con un servicio legítimo de
alto volumen**: una cuenta de monitorización (SCOM, un backup) pide el mismo
puñado de tickets miles de veces con AES. Tiene volumen enorme pero **pocos SPN
distintos** y **cero degradado**. Un detector que cuente solicitudes ahogaría al
analista en falsos positivos —y una alarma que casi siempre miente enseña a
ignorarlas todas—. Por eso aquí se cuentan **SPN distintos** y **degradados a
RC4/DES distintos** dentro de una ventana deslizante, no solicitudes. Dos reglas:
un **barrido** (muchos SPN distintos) o un **degradado amplio** (varios servicios
distintos pedidos en RC4 en un dominio que usa AES, el atacante "lento y
sigiloso" que evita el barrido evidente).

## 51.3 Golden y Silver Ticket: el ticket que la KDC nunca emitió

- **Golden Ticket**: TGT forjado con la clave de `krbtgt`. Como se fabrica
  offline, la KDC nunca lo emitió. Se marca cuando una cuenta tiene actividad de
  servicio (4769) durante **más de una vida de TGT** sin un solo 4768/4770 que la
  respalde, o cuando la vida solicitada supera el tope de renovación del dominio
  (Mimikatz pone 10 años). El riesgo de este detector es al revés que el de
  Kerberoasting: es fácil disparar de más. Un usuario con un TGT viejo pero
  **válido** de esta mañana no es un Golden Ticket, y el detector no lo marca.
- **Silver Ticket**: TGS forjado con la clave de la cuenta de servicio. Es aún
  más sigiloso porque **nunca toca la KDC**. Solo se ve cuando el ticket forjado
  se **usa** en el servicio: se cruza cada uso con lo que la KDC emitió, y un uso
  sin su 4769 (dentro de la ventana, con tolerancia de reloj) es un ticket que la
  KDC nunca emitió.

## 51.4 El grafo de identidad y la centralidad de Brandes

El movimiento lateral es un problema de **grafos**. Ningún evento aislado dice
"escalada"; lo dice el camino: `alice` (usuario) impersona `svc-backup`
(servicio), que tiene credenciales cacheadas de un `Domain Admin`. Las
identidades son nodos con un **nivel** de privilegio; las relaciones observadas
—actúa como, impersona, controla credenciales de, autentica en— son aristas
dirigidas. Una **escalada** es una arista nueva que abre, desde una identidad de
nivel bajo, un camino a otra de nivel **estrictamente mayor** que antes no
existía. La comparación estricta es lo que hace que un administrador haciendo
cosas de administrador **no** sea una escalada.

Sobre ese grafo se calcula la **centralidad de intermediación** con el algoritmo
de **Brandes** (implementado en el proyecto, no importado): identifica las
identidades por las que pasan más caminos de ataque —las joyas de la corona y los
concentradores de movimiento lateral que hay que endurecer primero—. El algoritmo
se prueba contra un valor calculado a mano sobre un grafo conocido: un KAT de
grafos, igual que los KAT de cripto de la FASE 59.

## 51.5 Parsear el ticket byte a byte

Para leer un ticket tal cual viaja por el cable, el módulo `kerberos.rs`
decodifica la estructura `Ticket` de RFC 4120 **byte a byte**, sin librerías
externas de ASN.1: un lector DER estricto que rechaza cualquier tag inesperado,
longitud no mínima, byte sobrante o cadena no UTF-8. Extrae el realm, el SPN y
—lo que importa para detectar el degradado— el `etype` de la parte cifrada. Solo
se parsea el sobre en claro; la parte cifrada con la clave del servicio no se
toca porque no se puede. El ancla de honestidad es un ticket real codificado a
mano y anotado contra el RFC, que se puede verificar leyendo los comentarios.

## 51.6 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Parseo DER de tickets Kerberos (RFC 4120), con negativos | sí, byte a byte, cero mocks | — |
| Kerberoasting (incluye "no disparar con servicio legítimo de alto volumen") | sí | — |
| Golden Ticket (huérfano + vida imposible), con el negativo del TGT viejo válido | sí | — |
| Silver Ticket (cruce uso ↔ 4769) | sí | — |
| Grafo de identidad, escaladas y centralidad de Brandes (KAT de grafos) | sí | — |
| Correlación del plano de control de extremo a extremo (varios ataques a la vez) | sí | — |
| Mapeo a alerta del panel con técnica MITRE ATT&CK | sí | — |
| Captura EN VIVO de eventos 4768/4769/4770 de un Controlador de Dominio | — | necesita un dominio AD real (Windows/ETW-Ti); gated |
| Captura de tickets de la red (RPC/SMB) | — | necesita tráfico de dominio real; gated |

La parte que puede estar mal de forma peligrosa —decidir si un patrón de
identidad es un ataque— se prueba de verdad en cada `make ci`. La captura en vivo,
que necesita un dominio Active Directory y privilegios que el runner no tiene, se
declara en `tools/verificar-itdr.sh` en vez de fingirse.
