# 76 · AegisState — el estado del endpoint, entero y consultable

> FASE 81. `crates/aegis-estado/`, `crates/aegis-parser/src/esquema/`,
> `crates/aegis-hunt/src/estado.rs`, `crates/aegis-scal/src/linux/xattr.rs`,
> `tools/verificar-estado.sh`.

## El problema, dicho sin adornos

AegisQL era **mejor lenguaje** que el SQL de osquery. No tiene `JOIN`, así que el
coste de cualquier consulta es acotable; valida tablas, columnas y tipos **antes**
de salir de la consola, así que un error de tecleo no se convierte en cien mil
fallos remotos; y su gramática no puede expresar una escritura, así que no hay
nada que filtrar.

Lo que no tenía era **estado sobre el que correr**. Cinco tablas —`processes`,
`connections`, `memory_regions`, `graph_edges` y `memory`— frente a las
doscientas y pico que osquery expone en Linux.

Un lenguaje excelente sobre una fracción del sistema responde bien a lo que puede
responder y **no dice nada de lo demás**, que es la peor manera de fallar: el
analista no sabe que no puede preguntar.

## Lo que hay ahora

| | Antes | Ahora |
|---|---|---|
| Tablas | 5 | **52** |
| Columnas | 43 | **328** |
| Familias | 2 | **8** |
| Tablas con cota obligatoria | 0 | **6** |
| Motivo cuando no se puede leer | no existe | **8 variantes, con su frase** |

Las ocho familias: procesos (10), ficheros (7), red (6), identidad (6),
persistencia (8), plataforma (9), contenedores (4), comportamiento (2).

## Las cuatro cosas que osquery no tiene

### 1. El motivo, que es estructural y no un descuido

Una tabla de osquery que no se puede leer devuelve filas vacías. **No es un fallo
de su implementación**: con `Vec<Row>` como tipo de retorno no hay dónde poner el
motivo. «No hay nada» y «no pude mirar» se escriben igual, y en un informe se
leen igual: como si la máquina estuviera limpia.

Aquí la firma es `Result<Filas, MotivoNoLeible>`, y la segunda respuesta tiene
sitio propio:

```rust
pub enum MotivoNoLeible {
    SinPrivilegios { operacion, necesita },      // y dice CUÁL hace falta
    NoExisteEnEsteNucleo { interfaz },
    NoAplicaEnEstaPlataforma { interfaz },
    FuenteAusente { ruta },
    CambioDuranteLaLectura { ruta },
    ErrorDelSistema { operacion, detalle },
    RequiereFiltro { columnas },                 // y dice CÓMO acotar
    PresupuestoAgotado,
}
```

**No hay variante `Otro(String)`.** Cada motivo que el enumerado puede expresar es
uno que alguien pensó, escribió y puede explicar a un analista. Una variante
comodín se convierte en el vertedero donde acaban los fallos que nadie miró.

Hay además un segundo nivel: `Aviso`, para la lectura que **sí** tuvo éxito y
declara sus huecos. «Enumeré diez mil ficheros y tres no los pude abrir» no es un
fallo, pero tampoco es haber visto la máquina entera.

### 2. Coste declarado por tabla, con un nivel que no existía

`Coste::Peligroso` no significa «muy caro». Significa **su coste no lo acota el
tamaño de la tabla sino el disco del cliente**: recorrer el árbol de ficheros
para encontrar los `suid` no depende de cuántos `suid` haya.

Una consulta que toca una tabla peligrosa **sin filtro no se ejecuta**, y el
rechazo llega sin tocar el disco —medido: menos de 50 ms—. En Rust, además, **no
compila**:

```rust
let c: Caceria<Caro, SinAcotar> = Caceria::nueva("SELECT sha256 FROM files");
c.difundir();   // ← no compila: no hay `SePuedeDifundir` para esta combinación
```

El rasgo está **sellado**, así que nadie puede añadir la implementación que falta
desde otro crate. Es la doctrina de «la ausencia es la frontera» aplicada al
coste: lo que no se puede expresar no se puede configurar mal.

De las seis peligrosas, una lo es por lo que **contiene** y no por lo que tarda:
`process_environment`. Difundirla a la flota juntaría los tokens de nube y las
contraseñas de toda la empresa en un solo sitio, que es el peor sitio donde
podrían estar juntos.

### 3. Empuje de predicados, con la propiedad que lo hace seguro

`WHERE pid = N` abre un fichero; sin filtro, la misma tabla abre miles. Medido:
`process_arguments` examina **1 proceso** acotada y **75** sin acotar.

La propiedad de corrección se escribe así: lo que devuelve la consulta acotada
tiene que **contener** lo que cumple el filtro. Devolver de más cuesta tiempo;
devolver de menos **pierde detección en silencio**, que es la única forma de que
este mecanismo haga daño.

De ahí que solo se empujen predicados en **conjunción pura en la raíz**. Bajo un
`OR`, saber que una rama pide `pid = 42` no autoriza a mirar solo el 42, porque
la otra acepta más. Un `pid > 1000` tampoco empuja, y podría: razonar sobre
rangos es donde se cuela el error de signo que deja de ver justo lo que se
buscaba.

### 4. Identidad, no texto

Cada fila que nombra una cosa lleva su `Eid` de la FASE 79, así que el resultado
de una consulta se une con el linaje, con el veredicto del árbitro y con lo que
vio otro subsistema **sin correlacionar por cadenas**.

## Dónde vive cada cosa, y por qué

```
aegis-parser   el lenguaje: esquema, Valor, plan      ← lo usa TAMBIÉN el servidor
     ↑
aegis-estado   los proveedores: el rasgo Tabla        ← lee /proc, /sys, /etc
     ↑
aegis-hunt     el ejecutor: evalúa el filtro
```

El esquema vive en el lenguaje y no junto a los proveedores, y no es un detalle de
gusto: el plano de control valida las consultas del analista contra ese mismo
esquema **antes** de difundirlas. Si el catálogo viviera junto a los lectores de
`/proc`, validar una consulta en la consola obligaría a compilar llamadas al
sistema de Linux dentro del servidor.

Son dos sitios que tienen que decir lo mismo, y dos sitios se desincronizan. Las
pruebas del catálogo lo impiden: una tabla que el lenguaje declara y nadie sirve,
un proveedor que el lenguaje no conoce, un proveedor que apunta al esquema de
otra tabla, una tabla peligrosa que se olvida de exigir filtro y una tabla que
devuelve filas con todos los valores ausentes **rompen la compilación de las
pruebas**.

## La objeción que había que responder

El ejecutor de `aegis-hunt` dejaba escrito en su cabecera que **no** quería una
capa «fuente de datos»: *«un ejecutor que habla con una interfaz se prueba contra
una implementación de mentira, y lo que se demuestra entonces es que el evaluador
funciona contra esa mentira»*.

El argumento es bueno y sigue siendo cierto. El rasgo `Tabla` existe para
**organizar cuarenta y siete proveedores, no para poder sustituirlos**: no hay
—ni habrá— una implementación que invente filas para que una prueba pase. Las
pruebas corren contra el sistema real de la máquina que las ejecuta, y cuando una
tabla no aplica ahí, la prueba comprueba que **declara el motivo**, que es
precisamente la capacidad nueva.

La única frontera que se parametriza es la **raíz del sistema de ficheros**, el
mismo recurso que `aegis-vuln::inventory::collect(root)` usa desde la FASE 20:
sustituye el disco, nunca una decisión.

## Lo que las pruebas encontraron en este mismo código

Cinco defectos reales, y cuatro de ellos eran **el pecado que esta fase existe
para corregir** — una tabla devolviendo cero filas sin poder distinguir «miré y no
hay» de «no miré»:

| Dónde | Qué pasaba |
|---|---|
| `authorized_keys` | contaba ficheros y no cuentas: sin claves, `examinadas = 0` |
| `kerberos_tickets` | callaba cuando no había ninguna caché |
| `boot_images` | callaba cuando `/boot` no tenía imágenes |
| las tres de contenedores | callaban cuando no había contenedores |
| `kernel_modules` | recorría `/lib/modules` **una vez por módulo**: colgaba la consulta |

Y dos más, de los que solo se ven leyendo las cuarenta y siete tablas seguidas:

- La lista de directorios que no se recorren comparaba **por igualdad**, así que
  una consulta acotada a `/proc/self/` empezaba *dentro* de `/proc` y lo
  recorría. `/proc` no es un árbol de ficheros: es una ventana al núcleo con
  enlaces que apuntan a cualquier sitio. Ahora compara por prefijo, y la
  comprobación vive en el único sitio por el que pasan las cuatro tablas
  peligrosas de ficheros.
- Varias tablas iteraban **sin mirar el presupuesto**, lo que rompía la promesa
  de que una lectura no se cuelga.

## Cuatro defectos anteriores a esta fase, que esta fase destapó

Ninguno estaba en código nuevo. Los cuatro estaban esperando a que alguien
mirara, y lo que hizo mirar fue medir el estado real del endpoint de punta a
punta.

**1. `aegis-scal`: las direcciones IPv6 de los sockets, mal decodificadas.** Se
leían con `to_be_bytes()` cuando `/proc` las escribe en orden del anfitrión, de
modo que `::1` salía como `::100:0`. La prueba que lo tapaba comprobaba
`matches!(ip, IpAddr::V6(_))`: el **tipo** del resultado, nunca su **valor**.
Una dirección mal decodificada no devuelve «no encontrado» sino **otra
dirección**, y quien actúa sobre esa columna actúa contra un tercero. Ver el
commit `3f75470`.

Los tres siguientes se destaparon al correr `make ci` contra un kernel moderno
—Linux 6.18, con Landlock ABI 7 y BTF— donde antes el entorno de integración no
tenía ninguna de las dos cosas y las pruebas se **omitían diciéndolo**. Ésa es
justamente la razón de que una puerta declare sus muros en vez de callarlos:
el día que el muro desaparece, lo que había detrás se ve.

**2. `aegis-sandbox`: una regla de Landlock sobre un fichero suelto tumbaba el
sandbox entero.** El kernel rechaza con `EINVAL` una regla `PATH_BENEATH` cuyo
objetivo no es un directorio y cuyos derechos incluyen alguno que sólo tiene
sentido sobre un directorio —listar, crear, borrar, reubicar—. `LECTURA` incluye
«listar un directorio», y la lista de rutas base nombra `/etc/ld.so.cache`, que
es un fichero regular. El resultado no era una regla de menos: era **ninguna
regla**, porque el error se propagaba y la construcción del sandbox fallaba
entera. El binario acababa corriendo **sin confinar**, que es el peor fallo que
este crate puede tener, porque no se nota.

**3. `aegis-sandbox`: una política sin rutas prohibía el sistema de ficheros
entero.** Landlock es una lista blanca: gobernar los derechos de fichero sin
añadir ni una regla que los conceda deja el árbol completo prohibido, y el
proceso ni siquiera llega a ejecutarse —`execve` devuelve `EACCES` antes de su
primera instrucción—. Es la forma exacta de `SandboxPolicy::agent_helper()`, que
prohíbe la red y no dice nada de rutas: **todo proceso auxiliar del agente moría
al arrancar** en cuanto el kernel traía Landlock. La documentación del módulo ya
decía lo correcto —«una política vacía significa que no se aplica Landlock»— y
el código decía lo contrario.

**4. `aegis-kintegrity`: la verificación cruzada acusaba a procesos vivos.** Las
dos vistas de kernel llegan por eBPF y numeran en el espacio de nombres de PID
**inicial**; la vista de `/proc` numera en el del proceso que lee. Cuando no son
el mismo, cada tarea aparece «sólo en `/proc`» y el detector la acusa de tener la
entrada falsificada. En la máquina de integración pasa con los once hilos del
PID 1, y **en un contenedor pasaría con la máquina entera**: un EDR que en su
primer barrido declara rootkit a todo lo que corre se desinstala esa misma
tarde.

La corrección no relaja nada, al contrario: añade un **tercer camino**.
`sched_getscheduler(tid)` resuelve el TID con `find_task_by_vpid()`, es decir en
el **mismo** espacio de nombres en el que `/proc` lo publica. Con él, las dos
situaciones que antes se escribían igual se separan:

| `/proc` | eBPF (ns inicial) | planificador (ns propio) | Veredicto |
|---|---|---|---|
| lo publica | no lo tiene | **sí lo resuelve** | los dos lados numeran distinto: **no comparable** |
| lo publica | no lo tiene | **tampoco** | la entrada de `/proc` está **falsificada** |

Y lo no comparable **se cuenta aparte** —`ScanReport::numeracion_distinta`— en
vez de mezclarse con las carreras: una carrera es ruido normal, y una numeración
distinta significa que la verificación cruzada **no está cubriendo** esas tareas.
Confundirlas escondería la segunda dentro de la primera. La detección de la
entrada fantasma queda **más fuerte** que antes, porque ahora exige que el kernel
la niegue por **tres** caminos independientes en vez de dos.

## La comparativa, medida en esta máquina

```
tablas            52
columnas          328
peligrosas        6 (exigen filtro; no se difunden sin acotar)

consulta                                                  ms  resultado
cuentas con uid 0                                          0  1 fila de 25 examinadas
claves SSH autorizadas                                     0  0 filas de 25 examinadas
sudo sin contraseña                                        0  1 fila de 4 examinadas
servicios que arrancan solos                              40  40 filas de 536 examinadas
tareas que se ejecutan en cada arranque                    0  0 filas de 3 examinadas
módulos del núcleo sin fichero en disco                    0  MOTIVO: /proc/modules no existe aquí
montajes escribibles y ejecutables                         0  19 filas de 26 examinadas
vulnerabilidades de CPU sin mitigar                        0  2 filas de 19 examinadas
sockets locales abstractos                                 0  0 filas de 8 examinadas
binarios setuid fuera del sistema                        221  0 filas de 2866 examinadas

total             261 ms para las diez consultas
con motivo        1 de 10 no se pudo responder Y DIJO POR QUÉ
```

No son consultas de demostración: son diez preguntas que un analista hace durante
un incidente, y cada una toca una familia distinta.

**La fila que importa es la sexta.** En esta máquina no hay `/proc/modules`, y la
respuesta no es «cero módulos» —que haría concluir que no hay ningún rootkit—
sino el motivo. Ésa es la fase entera en una línea.

## Tabla de honestidad

| Se comprueba | Lo que de verdad se ejerce | El muro |
|---|---|---|
| Las 52 tablas | contra el sistema real de la máquina de integración | lo que esta máquina no tiene (TPM, contenedores, SELinux, `/proc/modules`) se ejerce por su **motivo**, que es la mitad de la capacidad |
| Coste y cota | 6 tablas peligrosas rechazan sin filtro en <50 ms, medido | — |
| Rechazo en compilación | 2 doctests `compile_fail` | — |
| Empuje de predicados | contención comprobada contra la lectura sin acotar | solo conjunción pura: es deliberado |
| Autoataque | agotamiento, pánico, fuga y mentira | — |
| Determinismo | dos lecturas seguidas, fila a fila | — |
| Comparativa | las 10 consultas, medidas aquí | **osquery no está instalado**: sus cifras se citan, no se miden |
| Plataformas | Linux | Windows y macOS llegan en las FASES 83 y 84 |
| `forbid(unsafe_code)` | el crate entero | el `unsafe` de los atributos extendidos vive en `aegis-scal` |

## Lo que este crate no puede hacer nunca

- **No modifica nada.** El rasgo recibe `&self` y devuelve filas; no existe un
  `escribir`.
- **No entra en pánico.** Un dato que no se puede leer es un valor ausente; una
  tabla que no se puede leer es un motivo.
- **No se cuelga.** Toda lectura está acotada por el presupuesto y por la cota de
  la tabla.
- **No miente sobre lo que vio.** Ni con filas vacías, ni con ceros, ni con listas
  truncadas en silencio.

---

← Volver al [README](../README.md)
