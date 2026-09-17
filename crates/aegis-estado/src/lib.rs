//! `AegisState`: el estado del endpoint, entero, tipado y consultable.
//!
//! # El hueco que esta fase cierra
//!
//! AegisQL era, como lenguaje, mejor que el SQL de osquery: no tiene `JOIN`
//! —asi que el coste de cualquier consulta es acotable—, valida tablas y
//! columnas ANTES de salir de la consola, y no puede expresar una escritura. Lo
//! que no tenia era ESTADO sobre el que correr. Cinco tablas —`processes`,
//! `connections`, `memory_regions`, `graph_edges` y `memory`— contra las
//! doscientas y pico que osquery expone en Linux.
//!
//! Un lenguaje excelente sobre una fraccion del sistema responde bien a las
//! preguntas que puede responder y no dice nada de las demas, que es la peor
//! manera de fallar: el analista no sabe que no puede preguntar.
//!
//! # El inventario, que es el mapa de la fase
//!
//! El disparador de la FASE 81 exige escribirlo aqui antes que una sola linea
//! de codigo, y la razon es que sin el la ampliacion habria sido una lista de
//! deseos. Estado del endpoint, familia por familia:
//!
//! | Familia | AegisQL antes | osquery (Linux) | AegisState |
//! |---|---|---|---|
//! | Procesos | `processes`, `memory_regions` | `processes`, `process_open_files`, `process_memory_map`, `process_envs`, `process_open_sockets` | 10 tablas |
//! | Ficheros | — | `file`, `extended_attributes`, `suid_bin`, `mounts`, `device_file` | 7 tablas |
//! | Red | `connections` | `listening_ports`, `routes`, `interface_addresses`, `interface_details`, `arp_cache`, `iptables` | 5 tablas |
//! | Identidad | — | `users`, `groups`, `logged_in_users`, `sudoers`, `authorized_keys`, `last` | 6 tablas |
//! | Persistencia | — | `systemd_units`, `crontab`, `kernel_modules`, `startup_items` | 8 tablas |
//! | Paquetes | — | `deb_packages`, `rpm_packages`, `apk_packages`, `portage_packages` | 1 tabla, tres formatos |
//! | Plataforma | — | `system_info`, `cpu_info`, `memory_info`, `pci_devices`, `usb_devices`, `block_devices`, `platform_info`, `secureboot` | 8 tablas |
//! | Contenedores | — | `docker_containers`, `docker_images`, `docker_volumes` (requieren el socket de Docker) | 4 tablas |
//! | Comportamiento | `graph_edges`, `memory` | — (osquery no tiene grafo de linaje ni escaneo YARA de memoria en tabla) | se conservan |
//!
//! No se persigue el NUMERO de tablas de osquery, y conviene decir por que: una
//! parte grande de su catalogo son tablas de introspeccion de osquery mismo
//! (`osquery_flags`, `osquery_registry`, `osquery_schedule`...) y tablas de
//! plataformas que no son esta. Contar eso como visibilidad del endpoint seria
//! inflar la comparativa. Lo que se persigue es cubrir el ESTADO QUE IMPORTA
//! para detectar, y medirlo en `docs/76-estado.md` con la consulta real de un
//! SOC, no con el tamaño del catalogo.
//!
//! # Las cuatro cosas que osquery no tiene y aqui si
//!
//! 1. **`MotivoNoLeible`.** Una tabla de osquery que no puede leerse devuelve
//!    filas vacias. Cero filas y "no pude mirar" se escriben igual, y en un
//!    informe se leen igual: como si la maquina estuviera limpia. Aqui una
//!    tabla que falla devuelve POR QUE fallo —sin privilegios, no existe en
//!    este nucleo, cambio durante la lectura, la fuente no esta— y ese motivo
//!    viaja hasta el analista. Es la invariante 5 del megaprompt y es, de las
//!    cuatro, la que mas incidentes evita.
//! 2. **Coste declarado por tabla, y cota que no se puede saltar.** Cada tabla
//!    declara lo que cuesta leerla. El nivel [`Coste::Peligroso`] no es "muy
//!    caro": es "su coste no lo acota el tamaño de la tabla sino el disco del
//!    cliente", y una consulta que lo toca SIN FILTRO no se ejecuta. En Rust,
//!    ademas, no compila. Ver [`coste`].
//! 3. **Empuje de predicados.** Si la consulta filtra por `pid`, la tabla no
//!    enumera `/proc` entero para descartar despues. Ver [`Filtro`].
//! 4. **Identidad, no texto.** Cada fila que nombra una cosa lleva su
//!    [`aegis_entidad::Eid`], asi que el resultado de una consulta se une con el
//!    linaje, con el veredicto del arbitro y con lo que vio otro subsistema sin
//!    correlacionar por cadenas.
//!
//! # Donde vive cada cosa, y por que esa direccion
//!
//! ```text
//! aegis-parser   el lenguaje: esquema, Valor, plan     <- lo usa TAMBIEN el servidor
//!      ^
//! aegis-estado   los proveedores: el rasgo Tabla       <- lee /proc, /sys, /etc
//!      ^
//! aegis-hunt     el ejecutor: evalua el filtro
//! ```
//!
//! El esquema vive en el lenguaje y no aqui, y no es un detalle de gusto: el
//! plano de control (`server/crates/aegis-server`) valida las consultas del
//! analista contra ese mismo esquema ANTES de difundirlas a la flota. Si el
//! catalogo viviera junto a los lectores de `/proc`, validar una consulta en la
//! consola obligaria a compilar llamadas al sistema de Linux dentro del
//! servidor. Una sola verdad, si; en el sitio donde las dos partes la ven.
//!
//! Cada proveedor APUNTA a su esquema en vez de repetirlo, y hay una prueba
//! —`el_catalogo_y_los_proveedores_declaran_lo_mismo`— que falla si una columna
//! existe en uno y no en el otro. La coherencia no se confia a la disciplina.
//!
//! # La objecion que este crate tiene que responder
//!
//! El ejecutor de `aegis-hunt` dejo escrito, en su cabecera, que NO queria una
//! capa «fuente de datos»: «un ejecutor que habla con una interfaz se prueba
//! contra una implementacion de mentira, y lo que se demuestra entonces es que
//! el evaluador funciona contra esa mentira». El argumento es bueno y sigue
//! siendo cierto, asi que conviene decir exactamente que hace este crate y que
//! no:
//!
//! El rasgo [`Tabla`] existe para ORGANIZAR cincuenta y un proveedores, no para
//! poder sustituirlos. No hay —ni habra— una implementacion de `Tabla` que
//! invente filas para que una prueba pase. Las pruebas de este crate corren
//! contra el sistema real de la maquina que las ejecuta, y cuando una tabla no
//! aplica en esa maquina la prueba lo comprueba DECLARANDO el motivo, que es
//! precisamente la capacidad nueva. La unica frontera que se parametriza es la
//! RAIZ del sistema de ficheros ([`Contexto::raiz`]), que es el mismo recurso
//! que `aegis-vuln::inventory::collect(root)` lleva usando desde la FASE 20:
//! sustituye el DISCO, nunca una decision.
//!
//! # Lo que este crate no puede hacer nunca
//!
//! Corre dentro del agente, con privilegios, en el endpoint de un cliente, y lo
//! dispara texto que escribio alguien en una consola remota:
//!
//!   - **No modifica nada.** No hay una sola ruta de escritura. El rasgo
//!     [`Tabla`] recibe `&self` y devuelve filas; no existe un `escribir`.
//!   - **No entra en panico.** Un dato que no se puede leer es un valor
//!     ausente; una tabla que no se puede leer es un [`MotivoNoLeible`].
//!   - **No se cuelga.** Toda lectura esta acotada por el presupuesto del
//!     [`Contexto`] y por la cota de la tabla.
//!   - **No miente sobre lo que vio.** Ni con filas vacias, ni con ceros, ni
//!     con listas truncadas en silencio.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate lee el estado entero de la maquina y no necesita `unsafe` para
// hacerlo, cosa que merece una frase porque no era obvia: casi todo el estado
// del sistema en Linux es TEXTO en /proc, /sys y /etc, y leer texto no requiere
// punteros crudos. Lo unico que si necesita llamadas al sistema de verdad
// —enumerar procesos, leer memoria ajena, cruzar inodos de socket— ya vive
// detras de `aegis-scal`, que es donde el `unsafe` esta concentrado y revisado.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita.
#![forbid(unsafe_code)]

/// El contexto de una lectura: presupuesto, reloj, raiz y maquina.
pub mod contexto;
/// El coste de una tabla, y el rechazo en compilacion de lo que no se puede difundir.
pub mod coste;
/// Ficheros, atributos extendidos, ACL, montajes y superbloques.
pub mod ficheros;
/// Procesos y todo lo que cuelga de ellos.
pub mod procesos;
/// Sockets locales, rutas, interfaces, vecinos y cortafuegos.
pub mod red;
/// El rasgo `Tabla`, sus filas y el motivo por el que a veces no hay ninguna.
pub mod tabla;

pub use contexto::Contexto;
pub use tabla::{Aviso, Fila, Filas, Filtro, MotivoNoLeible, Tabla};

pub use aegis_parser::esquema::Coste;
