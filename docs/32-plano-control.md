# Módulo 32 — Aegis Control Plane: el backend de la flota

> Componentes: `server/` (workspace propio), `server/crates/aegis-server/`,
> `server/proto/aegis_fleet.proto`, `server/migrations/`.

Un antivirus de una máquina se administra a mano. Una flota de miles necesita un
plano de control: algo que sepa qué endpoints existen, recoja lo que ven,
guarde las alertas y les entregue política. Este módulo es ese servidor.

---

## 32.1 Por qué es un workspace separado

El agente es **síncrono, sin runtime asíncrono, con un presupuesto de memoria
acotado por clase de host —48 MiB en reposo en una pasarela, impuesto por el
kernel con `MemoryMax`— y `panic = "abort"`**. El servidor es exactamente lo contrario:
asíncrono, con `tokio`, `axum`, `tonic` y pools de conexiones.

Mezclarlos en un workspace contaminaría el árbol de dependencias del agente —que
en un EDR **es superficie de ataque**— con cientos de crates que solo necesita el
servidor. Separándolos, la auditoría de la cadena de suministro del endpoint
sigue siendo corta y revisable, que es justo lo que hace falta en el software que
corre con privilegios en la máquina del cliente.

---

## 32.2 El hallazgo que definió la arquitectura

En la [FASE 34](29-fleet.md) el agente se construyó deliberadamente **sin
`tokio`**: habla protobuf con el enmarcado de gRPC —prefijo de cinco bytes—
sobre un canal **mTLS crudo**, no sobre HTTP/2.

La consecuencia es incómoda y hay que decirla claro: **`tonic` no es compatible a
nivel de cable con los agentes reales de AegisCore.** Un servidor que solo
hablara `tonic` no podría atender a su propia flota.

La solución no es rendir el agente al peso de HTTP/2, sino **dos transportes
sobre un solo núcleo**:

| Transporte | Quién lo usa | Formato |
|---|---|---|
| **Nativo de flota** (mTLS) | los agentes **reales** de AegisCore | protobuf con enmarcado de gRPC sobre TLS mutuo crudo |
| **gRPC estándar** (HTTP/2) | integraciones de terceros, conectores de SIEM | gRPC canónico (`tonic`) |
| **REST** (HTTP) | el panel web de administración | JSON (`axum`) |

Los tres desembocan en el mismo `dominio::ServicioFlota`, así que un endpoint
recibe la misma decisión entre por donde entre.

**La compatibilidad no es una promesa, es el mismo código:** el servidor depende
del propio crate del agente (`aegis-fleet`) e implementa su trait
`ManejadorFlota`, de modo que decodifica exactamente con lo que el agente
codifica. Y el `.proto` de la superficie estándar declara **los mismos números de
campo** que el códec escrito a mano, así que los dos transportes intercambian
bytes de mensaje idénticos.

---

## 32.3 Qué guarda, y por qué así

Cuatro tablas (`server/migrations/0001_esquema_inicial.sql`):

- **`agentes`** — el inventario. Su clave primaria es el **CN del certificado**,
  no un identificador que el agente declare: el CN lo valida el handshake mTLS
  contra la CA de la flota, así que es lo único que un agente no puede
  falsificar. El hostname y la versión son *datos*, no identidad.
- **`alertas`** — con su **técnica y táctica de MITRE ATT&CK** materializadas. Se
  guarda el mapeo, y no solo la categoría, porque el mapeo puede cambiar y una
  alerta histórica debe conservar cómo se clasificó *entonces*.
- **`politicas`** — con un **índice único parcial** que garantiza que solo hay una
  activa. Que lo imponga la base de datos y no el código: dos políticas activas
  dejarían la flota en dos configuraciones distintas según a quién preguntara
  cada agente.
- **`comandos`** — la cola de respuesta. Se toman con `FOR UPDATE SKIP LOCKED`,
  que es lo que permite que varias instancias del plano de control atiendan a la
  misma flota sin entregar el mismo comando dos veces.

El agente reporta lo que **observa** ("ransomware", "rootkit"); el analista razona
en **ATT&CK**. `dominio::clasificar_mitre` traduce entre los dos. Una categoría
desconocida se guarda **sin mapeo** antes que con un mapeo falso que engañaría al
analista.

---

## 32.4 Defensas del propio plano de control

Un servidor que recibe datos de miles de endpoints —algunos de los cuales pueden
estar comprometidos— tiene que desconfiar de ellos:

- **La identidad nunca sale del cuerpo del mensaje.** Sale del certificado
  (transporte nativo) o de la cabecera que inyecta el proxy autenticador
  (gRPC). Sin identidad verificada no se escribe nada.
- **La severidad se acota** antes de tocar la base de datos: un agente
  comprometido que declare `9999` no puede reventar la restricción del esquema.
- **El reloj del agente no manda.** Una fecha diez años en el pasado —o en el
  futuro— enterraría la alerta al final del histórico donde nadie la vería: fuera
  de rango se usa la hora de recepción.
- **Los límites son explícitos**: cuerpo de petición acotado, `LIMIT` de las
  consultas del panel acotado, tamaño máximo de trama en el transporte.
- **Un fallo de base de datos no corta la conexión**: se convierte en un rechazo
  *con motivo*, para que el agente reintente y el operador vea por qué.

---

## 32.5 Reputación k-anónima

Consultar la reputación de un fichero es, sin cuidado, una fuga de privacidad: si
el agente enviara el hash completo de cada binario que ve, el plano de control
acabaría con el **inventario exacto del software y los documentos de cada
endpoint del cliente**. Un EDR no debería saber eso.

El agente envía solo un **prefijo** de cinco dígitos hexadecimales y el servidor
devuelve **todos** los veredictos de ese cubo; el agente busca el suyo en local.
El servidor sabe que alguien preguntó por un cubo de miles de hashes posibles, no
por cuál. Un prefijo más largo estrecharía el cubo y rompería la garantía: **se
rechaza con 400** en vez de responder con menos privacidad.

---

## 32.6 Cómo se prueba: cero imitaciones

Las pruebas de integración (`server/crates/aegis-server/tests/integracion.rs`)
hablan con un **PostgreSQL y un Redis reales**, y las dos decisivas levantan el
transporte mTLS de verdad:

- **`el_agente_autentico_habla_con_el_plano_de_control_sobre_mtls_y_queda_en_postgres`**
  — construye el **cliente auténtico del agente** (`aegis_fleet::ClienteFlota`,
  el mismo que corre en el endpoint), lo enrola, late y reporta un evento sobre
  mTLS, y comprueba que todo aterriza en PostgreSQL con su técnica ATT&CK. Si el
  enmarcado o un número de campo divergieran, esta prueba fallaría.
- **`un_impostor_con_otra_ca_no_llega_a_tocar_la_base_de_datos`** — un
  certificado firmado por otra autoridad se rechaza en el handshake y **no deja
  rastro**: ni una consulta llega a ejecutarse.

Donde no hay bases de datos, cada prueba se **omite diciéndolo**, nunca fingiendo
éxito. En CI las aporta el propio workflow con servicios de contenedor.

---

## 32.7 Operación

```
make -C .. ci                      # el pipeline completo incluye el job 'servidor'
tools/ci/servidor.sh               # solo el backend: formato, lints y pruebas
cargo run -p aegis-server          # arranca los tres transportes
```

Configuración por entorno (nada de credenciales en el repositorio):
`AEGIS_PG_URL`, `AEGIS_REDIS_URL`, `AEGIS_API_ADDR`, `AEGIS_GRPC_ADDR`,
`AEGIS_FLEET_ADDR`, `AEGIS_INTERVALO_LATIDO_SEG`, `AEGIS_PG_MAX_CONEXIONES`.

`GET /salud` es una **sonda de disponibilidad real**: comprueba PostgreSQL y
Redis y expone el estado del pool, devolviendo `503` si falta una dependencia.
Un plano de control que no alcanza su base de datos está en pie pero es inútil, y
el orquestador debe sacarlo del balanceo.

---

## 32.8 Custodia de la CA de la flota

El plano de control **es** la autoridad certificadora de la flota: quien firma
los certificados con los que los agentes se autentican. Ese material tiene dos
propiedades incómodas a la vez, y las dos están resueltas en el código, no
delegadas al despliegue:

**1. Tiene que sobrevivir al proceso.** Una CA regenerada en cada arranque
invalidaría los certificados de *toda* la flota en el primer reinicio: miles de
endpoints dejarían de reportar a la vez. Por eso la CA se **persiste** en
`AEGIS_CA_DIR` (por defecto `/var/lib/aegis/ca`) y se recupera al arrancar.

Recuperar una CA con `rcgen` tiene un matiz que importa: la biblioteca no reabre
un certificado, **reconstruye uno equivalente** a partir de sus parámetros. Ese
certificado sirve para firmar —mismo nombre distinguido y misma clave, luego las
hojas encadenan igual— pero sus bytes no tienen por qué coincidir con los
originales. Por eso `AutoridadCertificadora::desde_pem` conserva el **DER
original tal cual llegó**: es el que se distribuye a los endpoints como ancla de
confianza y tiene que ser byte a byte el mismo que ya tengan provisionado.

Lo demuestra
`el_certificado_emitido_por_la_ca_recuperada_lo_acepta_quien_confia_en_la_original`:
simula el reinicio del servidor y comprueba, en un **handshake mTLS real**, que
un agente provisionado *antes* sigue enrolándose sin tocar su configuración.

**2. Es el secreto más valioso del sistema.** Quien tenga la clave de la CA puede
emitir un certificado válido para cualquier identidad: hacerse pasar por el plano
de control ante toda la flota, o por cualquier agente ante el plano de control.
De ahí tres controles:

- El directorio se crea con **0700** y la clave con **0600**, y el modo se pasa
  al `open`, no se corrige después: crearla abierta y ajustarla a continuación
  dejaría una ventana —por breve que sea— en la que la clave es legible por
  cualquiera del sistema.
- Si al arrancar la clave resulta legible por el grupo o por otros, el servicio
  **se niega a arrancar** con un error que dice exactamente qué corregir.
  Arrancar sería peor que no hacerlo: daría la impresión de que todo funciona
  mientras la confianza de la flota entera está comprometida.
- Si falta uno solo de los dos ficheros, **no se genera una CA nueva encima**: es
  un estado corrupto, y sobrescribirlo destruiría en silencio el ancla que la
  flota ya tiene provisionada.

En un despliegue serio esa clave debería vivir en un HSM o un gestor de claves;
el módulo deja el punto de extensión preparado y, mientras tanto, la custodia en
disco es explícita y verificada.
