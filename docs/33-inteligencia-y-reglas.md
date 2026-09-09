# Módulo 33 — Inteligencia STIX 2.1, linaje de procesos y empuje de reglas

> Componentes: `crates/aegis-fleet/src/{proto,rpc,servidor,cliente}.rs` (extensión
> del protocolo), `server/crates/aegis-server/src/{reglas,notificador}.rs`,
> `server/migrations/0002_inteligencia_y_reglas.sql`.

La [FASE 37](32-plano-control.md) dejó el plano de control recogiendo latidos y
alertas. Falta lo que convierte esos datos en **inteligencia** —y en **acción
sobre la flota entera**—: recibir el contexto completo de una detección, y poder
ordenar algo a miles de endpoints sin esperar a que pregunten.

---

## 33.1 Extender el protocolo, no rodearlo

Las tres capacidades nuevas exigían mensajes que el protocolo de flota no tenía.
La tentación es añadirlos en el servidor y que el agente "ya se adaptará"; el
resultado siempre es el mismo, dos definiciones del mismo mensaje divergiendo.

Se extendió **`aegis-fleet`**, que es la única fuente de verdad del formato de
cable, y de ahí lo heredan los dos extremos:

| Método | Código | Qué hace |
|---|---|---|
| `ReportarStix` | 4 | el agente entrega un bundle STIX 2.1 completo |
| `ReportarGrafo` | 5 | el agente entrega el subgrafo de linaje de una detección |
| `SuscribirPolitica` | 6 | el agente abre el canal por el que **recibe** política |

El compilador hizo su parte: al añadir las variantes, el `match` del despacho
dejó de compilar hasta cubrirlas. Un protocolo que se extiende sin que nada
avise es un protocolo que acaba con métodos que nadie atiende.

### El bundle STIX viaja como JSON, a propósito

STIX 2.1 **es** JSON. Reempaquetarlo en campos protobuf obligaría a mantener un
esquema paralelo al estándar y a reconstruirlo en el servidor, con la garantía de
divergir en cuanto el estándar evolucione. Se transporta tal cual lo genera
`aegis-forensics`.

### El linaje, no el proceso culpable

Una detección aislada casi nunca concluye nada: `python` abriendo un socket es
rutina; `libreoffice → sh → python` abriendo un socket es un incidente. Por eso
el agente no envía el proceso, envía su **linaje**.

Las claves de los nodos **no son PID**. Los PID se reciclan, y un ataque que
espere al reciclado consigue que la telemetría atribuya sus acciones a un proceso
inocente ya terminado. La clave deriva de `(pid, start_boottime)`, cuyo par no se
repite en la vida del sistema.

---

## 33.2 Empuje real, no un sondeo disfrazado

"Bloquear el puerto 445 en toda la flota" no puede tardar un ciclo de latido. Un
sondeo cada 30 segundos deja al atacante media hora de margen si la flota es
grande y los latidos están repartidos.

El método `SuscribirPolitica` **rompe el patrón petición/respuesta**: el agente
abre la conexión y ésta queda viva; el hilo que la atiende en el servidor duerme
dentro de `esperar_empuje` y **despierta en el instante en que el operador
publica**. Entonces escribe la política por el canal.

En el sistema de tipos también se nota: `suscribir_politica` **consume** la
sesión y devuelve un `CanalPolitica`. A partir de ahí esa conexión ya no sirve
para llamadas unarias, y el compilador lo impide.

### Latido del canal

Un canal que solo habla cuando hay novedades es indistinguible de un canal
muerto. Cada 30 segundos sin novedad el servidor envía un marco con
`es_keepalive`, y los dos extremos detectan la caída sin esperar al plazo del
sistema operativo.

### Por qué `LISTEN`/`NOTIFY` de PostgreSQL y no un aviso en memoria

El plano de control se despliega con **varias instancias** detrás de un
balanceador. Un agente mantiene su canal contra la instancia A, elegida por el
balanceador; el operador publica la regla contra la B. Con un aviso en memoria,
ese endpoint no se enteraría hasta reconectar: la orden llegaría a una parte de
la flota y a otra no.

La base de datos ya es el punto común de todas las instancias, así que hace de
bus sin añadir una pieza más de infraestructura que mantener y vigilar. El aviso
se emite **después del `commit`**: si fuera dentro y la transacción se deshiciera,
los suscriptores irían a buscar una política que no existe.

Encolar un comando avisa también. Sin eso, aislar un endpoint comprometido
esperaría hasta 30 segundos al latido del canal — y aislar es precisamente lo que
no puede esperar.

---

## 33.3 El motor de reglas

Un operador define una **regla**; el motor la valida, la compila junto a las
demás en un documento de política versionado, y ese documento se empuja.

| Tipo | Parámetros | Validación |
|---|---|---|
| `bloquear_puerto` | `puerto`, `direccion` | rango 1..65535; dirección entrada/salida/ambas |
| `bloquear_hash` | `sha256` | 64 dígitos hexadecimales, normalizado a minúsculas |
| `bloquear_proceso` | `imagen` | **ruta absoluta** obligatoria |
| `bloquear_red` | `cidr` | IP válida y prefijo dentro de rango (IPv4 e IPv6) |
| `aislar_por_puntuacion` | `umbral` | 1..1000 |

**La validación ocurre al definir la regla, en la cara del operador.** Una regla
mal formada que el agente ignorase en silencio es lo peor de los dos mundos: el
operador cree que la flota está protegida y no lo está. Algunos ejemplos reales
de lo que se rechaza y por qué:

- Un `sha256` de longitud incorrecta **jamás casaría con nada**: quedaría en la
  política dando una falsa sensación de protección.
- Una ruta **relativa** depende del directorio de trabajo del proceso: la misma
  regla bloquearía cosas distintas en cada endpoint.
- Un umbral de **0** aislaría la flota entera en cuanto se aplicara la política.
  Es el error de configuración más caro posible, y el mensaje de error lo dice:
  *"un umbral de 0 aislaria toda la flota"*.

Los parámetros se guardan **normalizados**, no como los escribiera el operador,
para que dos reglas equivalentes escritas distinto no acaben conviviendo como si
fueran dos.

Crear, activar, desactivar o borrar una regla **recompila y publica** en la misma
operación. Dar de alta la regla y no publicar dejaría la flota sin ella; borrarla
sin republicar la dejaría aplicándola todavía.

---

## 33.4 Deduplicación: de cien anécdotas a una campaña

STIX define los identificadores para que dos herramientas que observen el **mismo
artefacto** produzcan el **mismo id**. El plano de control lo aprovecha: cien
endpoints que ven el mismo fichero malicioso no generan cien objetos, generan
**uno con cien avistamientos**.

Esa cuenta es la señal que distingue un indicador anecdótico de una campaña en
curso, y por eso el listado del panel ordena por avistamientos: es lo que el
analista tiene que mirar primero.

---

## 33.5 Desconfiar del endpoint

Un servidor que recibe telemetría de miles de máquinas —algunas comprometidas—
tiene que tratarla como entrada hostil:

- **Límite de nodos** por grafo (4096), comprobado **durante** la decodificación:
  un límite que para verificarse necesita materializar antes toda la memoria que
  pretendía acotar no sirve de nada.
- **Textos recortados** (imagen 4 KiB, línea de comandos 8 KiB) sin partir un
  carácter UTF-8 por la mitad: el endpoint controla esos campos.
- **Tamaño máximo de bundle** (2 MiB) antes de analizarlo.
- Un objeto STIX sin `id` o sin `type` **descarta ese objeto, no el bundle
  entero**, para no perder los que sí son válidos.

---

## 33.6 Cómo se prueba

- **Protocolo** (`crates/aegis-fleet/tests/telemetria_y_empuje.rs`): ida y vuelta
  de los mensajes nuevos, rechazo del grafo desmesurado, y las tres pruebas del
  canal — la política llega **al publicarse**, un agente que reconecta atrasado
  se pone al día al instante, y a uno al día no se le reenvía lo que ya tiene.
- **Servidor** (`server/crates/aegis-server/tests/integracion.rs`): ingesta y
  deduplicación contra PostgreSQL real, linaje con sus aristas, recorte de textos
  hostiles, compilación de política, y la prueba de extremo a extremo donde un
  **agente auténtico** se suscribe por mTLS, el operador crea la regla, y la
  política compilada le llega por el canal — pasando de verdad por el
  `NOTIFY` de PostgreSQL.
