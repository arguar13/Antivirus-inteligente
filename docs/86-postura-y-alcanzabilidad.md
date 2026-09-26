# AegisPosture — vulnerabilidades que importan, SBOM y postura de nube

**FASE 94.** Crate nuevo `crates/aegis-sbom` (inventario, correlación y
alcanzabilidad, en el agente), crate nuevo `server/crates/aegis-postura` (postura
de nube y la única salida del SBOM, en el plano de control), y `crates/aegis-vuln`
ampliado. Puerta: `tools/verificar-postura.sh` (grupo `postura` de
`tools/ci-local.sh`).

## La pregunta

OpenVAS, Nuclei, Trivy, Grype, Syft y OSV dicen que **hay** una vulnerabilidad.
Lo que no dicen es si **importa en esta máquina, ahora**:

1. ¿Está **cargado** el componente vulnerable en algún proceso vivo?
2. ¿Es **alcanzable** la función vulnerable desde el programa que lo carga?
3. ¿Está **expuesto** ese programa en la red?

Una lista de miles de CVE sin priorizar es ruido; una docena cargada, alcanzable y
expuesta es trabajo. Las tres respuestas salen de telemetría que el agente **ya
tiene**: los mapas de memoria de cada proceso, los sockets atribuidos a proceso y
el grafo de llamadas de la FASE 85. Cada una es tri-estado: sin datos para
responder se dice `SinDatos` con su motivo, y **nunca se asume alcanzable ni
inalcanzable**.

## El inventario de partida

| Pieza | Qué hacía | Qué le faltaba |
|---|---|---|
| `aegis-vuln` | paquetes de dpkg y apk, comparador de versiones de Debian, un feed propio de CVE | el paquete **fuente**, la segunda arquitectura, y todo lo que no es un paquete del sistema |
| `aegis-scal` | mapas de memoria y sockets con su proceso | nadie los cruzaba con el inventario |
| `aegis-disasm` (FASE 85) | grafo de llamadas de un tramo de código | las raíces de un programa real y la tabla de importaciones de un ELF |
| `aegis-pipeline` | eventos de CloudTrail, Azure Activity y GCP Audit | ninguna comprobación de configuración sobre ellos |
| `aegis-share` | el juez de difusión TLP/PAP, único estrangulamiento | el inventario no pasaba por él: no existía |

## Parte A — el inventario

| Fuente | Cómo se lee | Procedencia |
|---|---|---|
| Paquetes del sistema | dpkg y apk vía `aegis-vuln`, con el paquete fuente y la lista de ficheros de cada paquete | hecho declarado |
| Bibliotecas y ejecutables | de la lista de cada paquete: `.so` por nombre, y ejecutables por **bit de ejecución y cabecera ELF**, estén donde estén | hecho declarado |
| Binarios de Rust y Go | la sección `.dep-v0` de `cargo-auditable` (zlib + JSON) y `.go.buildinfo` (Go ≥ 1.18, formato en línea), leyendo solo la tabla de secciones | hecho de la cadena de compilación |
| Bibliotecas enlazadas estáticamente | firmas de versión, solo las **cotejadas con un binario real** (hoy, OpenSSL) y solo en ficheros que ningún paquete reclama | **inferencia**, marcada como tal |
| Dependencias de aplicación | `Cargo.lock`, `package-lock.json` (v1, v2, v3), `requirements.txt` fijado con `==`, `*.dist-info/METADATA` | manifiesto frente a instalado, distinguidos |
| Contenedores | `docker save`, layout OCI y `overlay2`, **capa a capa**: cada componente con la capa que lo introdujo y los borrados (*whiteouts*, directorios opacos) aplicados | hecho declarado |

Cada componente lleva su purl (especificación Package URL: el `+` de una versión de
Debian se codifica, la época no; calificadores ordenados). El SBOM dice qué fuentes
leyó y cómo (`Leida`, `Parcial`, `Ausente`, `NoSoportada`, `Ilegible`): «5 698
componentes» no significa nada sin «de estas fuentes, leídas así».

La correlación usa **OSV** como formato de entrada, no una base de datos concreta:
el cliente elige de dónde salen sus avisos. Casan el ecosistema y la distribución
(un aviso de Ubuntu 22.04 no dice nada de 24.04; Alpine casa por rama), el nombre en
la forma del aviso (**paquete fuente** en Debian, Ubuntu y Alpine; nombre
normalizado PEP 503 en PyPI) y la versión, con el comparador de **su** ecosistema:
dpkg, apk, SemVer 2.0 (con las pseudoversiones de Go) y PEP 440. El mismo fallo
con varios identificadores (`GHSA-…`, `PYSEC-…`, `USN-…`) cuenta una vez, por su
CVE. Los rangos de commits no se pueden evaluar contra una versión instalada: se
cuentan como no evaluados, no se callan.

## Parte B — las tres preguntas

**Cargado.** Los ficheros del componente se resuelven a su ruta canónica y su
inodo, y se cruzan con los mapas de memoria de todos los procesos. Tres matices que
separan esto de un cruce de nombres:

- un proceso que tiene proyectado un fichero **ya borrado del disco** sigue
  ejecutando la versión anterior a la actualización, y se dice;
- el **código interpretado** (Python, Perl, shell) no aparece en ningún mapa aunque
  se esté ejecutando, así que no se afirma «no cargado» de un paquete que lo trae;
- si algún proceso no se pudo leer (sin privilegios), «ninguno lo carga» no se
  afirma: es `SinDatos`.

Un paquete que **no contiene código** —ni bibliotecas, ni ejecutables, ni código
interpretado— sí se descarta con un «No»: ningún proceso lo puede estar ejecutando.

**Alcanzable.** Es el grafo de llamadas de la FASE 85 sobre el ejecutable de cada
proceso que carga el componente. Lo difícil no es el grafo, son las **raíces**:
`_start` no llama a `main`, le pasa su dirección. Las raíces son toda función cuya
dirección se toma —en el código (`lea`/`mov`), en las secciones de datos, en las
reubicaciones `RELATIVE` y en las entradas `GLOB_DAT`/`JUMP_SLOT` de un símbolo
definido en el propio binario— más, en una biblioteca, lo que exporta. Con esas
raíces, una llamada indirecta no resuelta solo puede ir a una función que ya es
raíz, y el «No» es sano. Para una función importada (una biblioteca dinámica) se
busca una llamada a través de su entrada del GOT dentro de una función alcanzable;
para una interna (una dependencia enlazada dentro) se busca su símbolo.

Lo que no se afirma: si el aviso no dice qué función es vulnerable (los de las
distribuciones casi nunca lo dicen), si la llamada pasaría por **otra** biblioteca
—el grafo entre módulos no se construye—, si el binario no tiene tabla de
símbolos, o si el análisis se cortó por sus topes. En todos esos casos, `SinDatos`
con el motivo.

**Expuesto.** Los sockets de cada proceso que carga el componente se leen de
`/proc/<pid>/net/*` —su propia vista de la red, para que un servicio dentro de un
contenedor cuente— cruzados con **sus** descriptores. Escuchar en una dirección de
bucle local no es estar expuesto.

## El escáner como reconocimiento para el atacante (autoataque)

Un SBOM es exactamente el mapa que un atacante querría antes de elegir por dónde
entrar. Por eso el inventario **no sale sin pasar por el estrangulamiento**, y la
garantía está en el código y no en una configuración:

1. `aegis-sbom` **no sabe escribirse**: sin serializador, sin `serde`, sin
   sockets, sin escribir ficheros. La invariante 12 lo comprueba por ausencia.
2. CycloneDX 1.5 y SPDX 2.3 viven en `aegis-postura::salida`, **privados**. Lo único
   público es `exportar`, que pasa por `Difusor::juzgar_marcado` con el inventario
   marcado `TLP:AMBER+STRICT`/`PAP:AMBER` —solo la propia organización—, y no
   tiene parámetro de marcado. Tres `compile_fail` con su código de error lo fijan
   (E0603 ×2, E0061).
3. Medido canal a canal (`Canal::todos()`): hacia fuera de la organización, por
   ningún canal; por el enjambre, ni hacia dentro (su tope duro es GREEN); a un
   destino no declarado, error. La invariante 9 lo cuenta como la duodécima
   capacidad que resiste su propio ataque.

Para que el documento que sí sale sirva, lleva el sistema operativo como componente
del que dependen sus paquetes y el paquete fuente en la forma que leen los
consumidores. Sin eso, medido: Trivy encontraba **454** vulnerabilidades en el
CycloneDX de esta máquina; con eso, **15 919**, al nivel de su propio análisis.

## Lo que encontró la fase por el camino

| Defecto | Dónde | Corrección |
|---|---|---|
| El escáner cruzaba solo por el nombre instalado: el aviso de OpenSSL (publicado por paquete fuente, `openssl`) no salía en una máquina con `libssl3` y sin la herramienta de línea de órdenes | `aegis-vuln` | cada paquete se cruza por su nombre binario con su versión y por su fuente con la suya; un registro que llega por los dos caminos cuenta una vez |
| Con `libc6:amd64` y `libc6:i386` instalados, la segunda arquitectura pisaba a la primera y el inventario perdía un paquete | `aegis-vuln` | las dos pasan a `nombre:arq`, como las nombra dpkg, y el resultado no depende del orden del fichero |
| Una línea de un byte o que partía un carácter multibyte en la base de datos de apk hacía entrar en pánico al inventario | `aegis-vuln` | lectura con `get`, sin `split_at` |
| El catálogo de GCP buscaba el nombre del permiso (`serviceAccounts.keys.create`) y no el `methodName` que llega (`google.iam.admin.v1.CreateServiceAccountKey`): crear una clave de cuenta de servicio o borrar el sumidero de registros eran «una llamada a la API» | `aegis-pipeline` | las dos formas, con una prueba por nombre real |
| El crudo de los eventos de nube no respetaba el tope del esquema (64 KiB) | `aegis-pipeline` | recortado como el de syslog; quien lo lee lo trata como ausente si deja de ser JSON |
| Una capa gzip con el CRC corrupto pasaba por buena: el tar se acaba antes que el gzip y la cola, donde está el CRC, no se leía | `aegis-sbom` | se consume el flujo hasta el final y se comprueba |
| Leer entero cada binario sin paquete para buscar firmas subió el pico a **414 MB** | `aegis-sbom` | por trozos de 1 MiB con solape, y una versión que llega al borde del trozo no se anota (podría estar cortada) |
| Cargar la exportación de OSV de Ubuntu costaba **3,5 GB**: cada aviso trae las versiones afectadas de todas las distribuciones | `aegis-sbom` | se filtra **al leer**, con las mismas reglas de la correlación: **40 MB** |
| Solo se reconocían ejecutables en `bin`: `/usr/lib/systemd/systemd` (el proceso 1) no contaba, y los módulos de Go de `/usr/lib/snapd` no entraban | `aegis-sbom` | bit de ejecución y cabecera ELF, esté donde esté; la comparación con Syft lo destapó |
| El CycloneDX no llevaba el sistema operativo ni el paquete fuente en la forma que leen los consumidores | `aegis-postura` | medido con Trivy antes y después |

## Lo medido, en esta máquina

Ubuntu 26.04 en WSL2, como root, con los 16 358 avisos OSV de Ubuntu 26.04.

| Medida | Cifra |
|---|---|
| Paquetes deb frente a `dpkg-query` | **668 = 668** |
| Componentes | 5 698 (668 deb, 4 333 crates, 608 módulos de Go, 89 de Python) |
| Metadatos de compilación reales | 21 binarios (`sudo-rs` con `cargo-auditable`, y los de Go de snapd, Trivy, Grype y Syft); `.dep-v0` cotejado con `objcopy` + `zlib` de Python |
| Firma de OpenSSL en la `libcrypto.so.3` real | `3.5.5`, la del paquete |
| Avisos | 6 241 afectan al inventario; 10 117 descartados al leer |
| Hallazgos | 19 266 (4 018 fallos distintos) |
| Cargados | 200 |
| Descartables **con evidencia** (alguna respuesta es un «No» comprobado) | **15 312** |
| Sin datos | 3 954, cada uno con su motivo |
| Tiempo y memoria (inventario + cotejo + alcanzabilidad) | ~20 s, **38 MiB** medidos por el núcleo |

Con procesos reales compilados en la prueba: la función a la que se llega desde
`main` sale **alcanzable**, con el camino; la que solo llama una función muerta sale
**No**, comprobado contra las 17 direcciones de función que el programa toma; la
biblioteca que no carga nadie sale **No** en las tres preguntas; escuchar en
`0.0.0.0` es estar expuesto, en `127.0.0.1` no.

## La comparación, medida

Las cuatro herramientas sobre la misma máquina, con las mismas exclusiones (`/proc`,
`/sys`, `/dev`, `/run`, `/mnt`, `/media`, `/snap`, el almacén de Docker). Trivy
0.74.0, Grype 0.119.0 y Syft 1.52.0, de sus publicaciones oficiales con la suma
SHA-256 verificada.

**Lo que ellas hacen mejor, primero.** Trivy y Grype llevan su base de datos de
vulnerabilidades y la actualizan solos; aquí hay que darle a la herramienta los
avisos OSV. Syft reconoce muchos más ecosistemas (Java, módulos del núcleo,
acciones de GitHub, `binary` por firma de cientos de programas); aquí hay seis.
Las tres escriben SBOM de terceros y leen los de otros; aquí solo se escribe, y
solo hacia la propia organización.

| | Tiempo | Memoria máx. | Resultado |
|---|---:|---:|---|
| **AegisPosture** | **~20 s** | **38 MiB** | 19 266 hallazgos; 15 312 descartables con evidencia |
| Syft | 209 s | 5,0 GB | 38 904 componentes |
| Trivy | 169 s | 0,9 GB | 15 899 vulnerabilidades (3 291 distintas) |
| Grype | 375 s | 5,5 GB | 28 501 coincidencias (3 848 distintas) |

**Componentes frente a Syft** (únicos por ecosistema, nombre y versión):

| Ecosistema | Aquí | Syft | Por qué difieren |
|---|---:|---:|---|
| deb | 668 | 669 | el de más de Syft (`hithere 1.0-1`) es un `.deb` de **prueba** dentro del caché de crates, no un paquete instalado |
| cargo | 4 333 | 4 333 | idénticos |
| Go | 608 | 612 | tres módulos principales con versión `UNKNOWN` (aquí no se inventa una), un `go.mod` de ejemplos de documentación, y la grafía de `stdlib` |
| PyPI | 89 | 90 | la misma lista con la grafía del nombre sin normalizar, y un paquete de prueba de `pkg_resources` |

**Cuántas de sus vulnerabilidades resultan alcanzables.** Las 15 899 de Trivy
pasadas por la alcanzabilidad de aquí: **12 319 (77 %)** están en componentes que
ningún proceso carga —descartables con evidencia—, **92** están cargadas y ninguna
en un servicio expuesto, y **3 100** quedan sin datos con su motivo. Ninguna salió
alcanzable por el grafo: los avisos de Ubuntu no dicen qué función es la
vulnerable, y sin eso no hay ruta que buscar. Es la frontera honesta de esta fase,
no un resultado a presentar como «cero alcanzables».

## Parte C — la postura de nube (`aegis-postura`)

«¿Qué hay mal configurado en el plano de control de mis nubes?» —identidades con
privilegio de administrador, almacenamiento público, claves sin rotar, registro de
auditoría apagado, puertos de administración abiertos a Internet—. Es la pregunta
de un CSPM, y la referencia es Prowler.

La diferencia de partida: este producto **no tiene credenciales de lectura en la
nube del cliente** ni las quiere —son justo el activo que busca un atacante—. Lo
que sí tiene son los registros de auditoría que `aegis-pipeline` ya normaliza. La
postura se reconstruye de ahí.

### Cómo se reconstruye el estado

No hay instantánea: hay una historia, y el estado se obtiene **plegándola**:

1. **Orden de ocurrencia, no de llegada**; a igualdad, por `Evento::id`.
2. **Idempotencia**: un evento repetido se pliega una vez y no duplica evidencia.
3. **Una llamada que falló no configuró nada.** En Azure, el `Start` (que lleva el
   cuerpo) queda pendiente por `correlationId` y solo el final con éxito aplica; la
   evidencia cita los dos.

Lo que se escribe **entero** en un evento (una regla de NSG, un cortafuegos de GCP,
el estado de un trail, la política de un cubo) se afirma entero; lo que se
configura por **deltas** (adjuntar una política, una entrada de un grupo de
seguridad) se afirma **por concesión**, nunca de la identidad entera.

### Las comprobaciones

| Id | Proveedor | Qué | Naturaleza |
|---|---|---|---|
| `AEGIS-NUBE-IAM-001` | AWS, Azure, GCP | `AdministratorAccess` o política con `Action *` sobre `Resource *` (también la que pasa a concederlo todo **después** de adjuntarse); Owner, Contributor, User Access Administrator; `roles/owner`, `roles/editor` | Exposición |
| `AEGIS-NUBE-IAM-002` | GCP | cualquier rol de proyecto a `allUsers`/`allAuthenticatedUsers` | Exposición |
| `AEGIS-NUBE-ALM-001` | AWS, GCP | `Principal *` sin condición, ACL a AllUsers/AuthenticatedUsers, bloqueo de acceso público retirado o a `false`; GCS con `allUsers`. Lo corrige un bloqueo completo | Exposición |
| `AEGIS-NUBE-CLV-001` | AWS, GCP | clave de larga duración con más de 90 días respecto a un `ahora_ns` que se pasa; opcional, el informe de credenciales de IAM (CSV) | Exposición |
| `AEGIS-NUBE-LOG-001` | AWS, Azure, GCP | registro apagado, borrado o sin eventos de gestión; lo corrige volver a encenderlo | Exposición |
| `AEGIS-NUBE-LOG-002` | AWS, Azure, GCP | tras apagar el registro, gestión de cuentas en la misma cuenta | **Compromiso** |
| `AEGIS-NUBE-RED-001` | AWS, Azure, GCP | `0.0.0.0/0`, `::/0`, `*`, `Internet` hacia 22, 3389, 5432, 3306, 6379, 9200, 27017 o todos; lo corrige el revoke (también por identificador de regla) | Exposición |

Cada resultado lleva su estado tri-estado, la lista de `Evento::id` que lo
sostienen, la **entidad** del modelo único (`entidad::cuenta` para una identidad —
la misma que ve ITDR—, `entidad::ubicacion` en el espacio `nube:<proveedor>` para
un recurso) y la remediación.

### Frente a Prowler

**Lo que Prowler hace mejor, primero.** Consulta la API de configuración **en
vivo**, con cientos de comprobaciones y marcos de cumplimiento mapeados, y ve el
estado **aunque no haya ningún evento**: un cubo que se hizo público hace dos
años sale igual que uno de ayer. Aquí eso no se ve. Y cubre servicios que este
crate no mira.

| | Prowler | `aegis-postura` |
|---|---|---|
| Credenciales en la nube del cliente | sí, de lectura, en toda la cuenta | **ninguna** |
| Qué dice un hallazgo | «el cubo es público» | «lo hizo público `admin` a las 10:14 con **este** evento» |
| Sobre qué | un ARN | una entidad del modelo único |
| Lo que no se pudo mirar | error de API o comprobación omitida | `SinDatos` con su motivo; la cobertura por proveedor lo cuenta |
| Exposición frente a compromiso | todo es configuración | «apagó el registro y **luego** creó claves» es un compromiso aparte |

### La lectura de los eventos

`aplanar` conserva los arrays indexados, pero solo los 32 primeros, y no aplana
`responseElements` de AWS, `properties` de Azure ni `protoPayload.request` de GCP.
No se cambia —lo que entra en los campos forma parte del `Evento::id`, y cambiarlo
rompería la desduplicación de lo ya guardado—: la fuente completa es el **crudo**
(`conservar_crudo`). Sin crudo, en AWS se reconstruye de los campos y, si hay señal
de recorte, se puede afirmar que algo *está* abierto pero no que *no* lo está. Para
que la postura de Azure y GCP diga algo, el conector de nube tiene que correr con
`conservar_crudo`.

**Al árbitro no llega nada, y es una decisión.** Las exposiciones no mueven el
juicio (media cuenta mal configurada no es media cuenta comprometida). El
compromiso `LOG-002` podría, pero la lista de motores es cerrada y firmarlo como
`Itdr` mentiría en el censo de `aegis_tejido::inventario`; sale en
`Informe::compromisos()` para respuesta a incidentes y el camino al árbitro queda
pendiente de una decisión de motor.

## Tabla de honestidad

| Pieza | Aquí | Cómo |
|---|---|---|
| Inventario de paquetes | **sí** | cotejado con `dpkg-query` en cada puerta |
| `cargo-auditable` | **sí** | binarios reales, cotejado con una lectura independiente |
| Go buildinfo (≥ 1.18) | **sí** | binarios de Go reales de la máquina; el formato anterior se declara ilegible |
| Firmas | parcial | solo OpenSSL, cotejada; las demás no se suponen |
| Contenedores | parcial | los tres formatos con imágenes construidas en la prueba; **no hay Docker en esta máquina** |
| rpm | — | no hay lector; si hay base de datos de rpm, el SBOM lo dice como fuente no soportada |
| Cargado | **sí** | procesos reales |
| Alcanzable | **sí**, dentro de un binario | procesos reales compilados en la prueba; entre módulos, `SinDatos` |
| Expuesto | **sí** | sockets reales del proceso |
| Autoataque | **sí** | canal a canal y `compile_fail` |
| Interoperabilidad | **sí** | Trivy lee el CycloneDX exportado |
| Postura de nube | **sí**, sobre eventos | documentos de forma real de los tres proveedores; sin cuentas de nube reales conectadas |
| Comparativa | **sí** | Trivy, Grype y Syft en esta máquina; se mide aparte, no en cada puerta (necesita red y minutos) |

## El muro, declarado

- **La ruta vulnerable se busca dentro de un binario.** Si pasaría por otra
  biblioteca cargada, no se construye el grafo entre módulos: `SinDatos`.
- **Los avisos de las distribuciones no dicen qué función es vulnerable.** Para
  ellos, «alcanzable» es `SinDatos` casi siempre; lo que sí se responde —cargado y
  expuesto— es lo que más reduce la lista.
- **Lo que no se vio en la ventana de eventos no se sabe.** Una comprobación de
  nube sin eventos que la toquen dice `SinDatos`, nunca `Cumple`, y apagar el
  registro deja ciego al proveedor desde ese instante.
- **Direcciones calculadas con aritmética y código generado en ejecución** no
  entran en las raíces: un «No» de alcanzabilidad es sano frente a punteros a
  función, no frente a eso.
