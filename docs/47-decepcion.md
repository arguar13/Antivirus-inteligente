# Módulo 47 — Decepción activa: honey-tokens que delatan al intruso

> Componentes: `crates/aegis-honeytoken/`.

## 47.1 Convertir el robo de credenciales en la señal que lo caza

Un honey-token es una credencial **falsa** que ningún proceso legítimo tiene
motivo de tocar. Se siembra donde un atacante mira **después** de entrar —en la
memoria de un proceso crítico, en un `~/.pgpass`, en un `credentials.xml`— y no
da acceso a nada. Su único propósito es que, en el instante en que alguien la lee
o la usa, **delata su presencia**: no hay falsos positivos, porque nadie honrado
toca lo que no sirve para nada.

Es una técnica puramente **defensiva** (deception / canary tokens): convierte el
movimiento lateral del atacante —el paso en que recolecta credenciales— en la
señal que lo descubre.

## 47.2 Atribuible por diseño

Cada token lleva un marcador **HMAC-SHA256** único que ata la credencial a un
host, un proceso sembrado y un identificador. Tres propiedades, cada una por una
razón:

- **Único** por (host, proceso, id): dos señuelos nunca colisionan, así que
  cuando el marcador reaparece se sabe *exactamente* cuál se tocó y dónde estaba.
- **Infalsificable** sin el secreto de flota: un atacante no puede sembrar un
  honey-token propio que dispare una atribución falsa y nos mande a perseguir
  fantasmas.
- **Opaco**: es la salida de un HMAC, indistinguible de aleatorio; no revela que
  es un señuelo.

## 47.3 Credenciales que el atacante se cree

Un honey-token solo funciona si el atacante se lo cree. Una credencial mal formada
la descarta a simple vista —o su herramienta la rechaza al parsearla— y el señuelo
no dispara. Por eso cada artefacto se genera con la forma real de su tipo, y **las
pruebas lo validan con los mismos parsers que usaría el atacante**: la clave
OpenSSH señuelo parsea con `ssh-key`; el `credentials.xml` parsea con `roxmltree`.
Si el artefacto no parsea como lo que dice ser, no engaña a nadie. El marcador se
embebe en un campo que el atacante conservaría al robar la credencial: el
comentario de la clave, el usuario del `.pgpass`, la cuenta del XML.

## 47.4 El clasificador de disparo: la parte peligrosa

`trip.rs` decide si un evento tocó un honey-token. Un disparo de **menos** deja
pasar al atacante que ya está recolectando credenciales —el momento exacto que
toda la fase existe para cazar—. Uno de **más** convierte una lectura legítima en
una alarma, y una decepción que grita por nada se ignora enseguida. Por eso el
disparo exige que aparezca un marcador **registrado**: no *"algo que parece una
credencial"*, sino uno de nuestros señuelos, atribuible. Los tests lo verifican en
ambos sentidos: un volcado de memoria con el marcador dispara con la atribución
correcta; uno sin él, no.

## 47.5 La respuesta, y su gradación

Tocar un honey-token no tiene explicación inocente, así que la respuesta por
defecto es contundente: **aislar** (invocando la Cuarentena de FASE 44) y
**volcar** la memoria del sospechoso para el forense. La severidad distingue
matices: leer credenciales de la memoria de un proceso (LSASS, `ssh-agent`) es el
corazón del robo de credenciales y va a lo más alto; abrir un honey-file es
reconocimiento, un paso antes, y se aísla y observa.

## 47.6 Planificar dónde sembrar, sobre `/proc/maps` real

Para que un atacante que vuelca la memoria de un proceso se encuentre el señuelo,
hay que colocarlo en una región **escribible y anónima** (heap, stack, mapeos
anónimos) —donde vive el botín—, no en código ni en regiones de solo lectura. Eso
se decide leyendo `/proc/<pid>/maps` **real**, el mismo formato en cualquier
Linux, así que la planificación se prueba de verdad aquí (contra
`/proc/self/maps`).

## 47.7 La línea gated

Escribir el token en la memoria de otro proceso (`process_vm_writev` en un
`ssh-agent`; la inyección en LSASS en Windows) necesita privilegios y un proceso
víctima vivo. Vive tras la feature `inyeccion` y el CI declara que no se ejercitó
aquí. El núcleo —acuñar, renderizar, planificar, decidir el disparo— sí se prueba
en cada `make ci`, sin un solo mock.

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Marcador HMAC atribuible | sí, HMAC real + anti-falsificación | — |
| Credenciales creíbles | sí, validadas con ssh-key y roxmltree | — |
| Clasificador de disparo | sí, memoria y ficheros reales | — |
| Planificación en `/proc/maps` | sí, contra `/proc/self/maps` | — |
| Inyección en memoria ajena | — | `process_vm_writev` / LSASS, gated tras `inyeccion` |
