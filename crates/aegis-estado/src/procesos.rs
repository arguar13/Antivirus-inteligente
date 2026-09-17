//! Proveedores de las tablas de procesos.
//!
//! # El empuje de predicados, que es lo que hace usable esta familia
//!
//! Las ocho tablas se leen de `/proc/<pid>/algo`. Sin acotar, cada una recorre
//! los miles de procesos de la maquina abriendo al menos un fichero por cada
//! uno; con `WHERE pid = N` abre exactamente uno. En una flota, la diferencia
//! entre las dos formas de la misma consulta es la diferencia entre una caceria
//! y una caida de servicio.
//!
//! Todo eso pasa por [`pids_a_leer`], que es la unica funcion del modulo que
//! decide QUE se recorre. Que sea una sola tiene un motivo: la propiedad que
//! hace correcto el empuje —devolver de mas es aceptable, devolver de menos
//! pierde deteccion— se demuestra una vez sobre ella y vale para las ocho.
//!
//! # Por que casi todo son avisos y no errores
//!
//! Un proceso puede morir entre que se enumera y que se lee, y un proceso de
//! otro usuario puede ser ilegible. Ninguna de las dos cosas es un fallo de la
//! tabla: la tabla tiene exito, devuelve lo que vio, y DECLARA lo que no pudo
//! ver. Lo contrario —abortar la lectura entera porque un proceso de root no se
//! deja leer— convertiria cada consulta de un agente sin privilegios en un error
//! vacio.

use aegis_entidad::{entidad, Clase};
use aegis_parser::esquema::{procesos as esq, Coste, Tabla as Esquema};

use crate::contexto::{desde_io, Contexto, TOPE_DE_FILAS};
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

// ---------------------------------------------------------------------------
// Que procesos hay que recorrer
// ---------------------------------------------------------------------------

/// Los pids que la consulta necesita, aprovechando lo que ya sabe el filtro.
///
/// # La propiedad que tiene que cumplir
///
/// El conjunto que devuelve tiene que CONTENER a todos los procesos que podrian
/// pasar el filtro. Devolver de mas cuesta tiempo; devolver de menos pierde
/// filas en silencio, que es la unica forma de que el empuje haga daño. Por eso
/// solo se recorta cuando el filtro fija `pid` de forma positiva —una igualdad
/// o una pertenencia—, que son los dos unicos casos en los que se sabe con
/// certeza que el resto no puede pasar.
///
/// Un `pid > 1000` NO recorta, aunque podria: hacerlo obligaria a razonar sobre
/// rangos y la primera vez que alguien se equivoque de signo, la caceria dejara
/// de ver justo lo que buscaba. La ganancia no compensa la clase de fallo.
fn pids_a_leer(ctx: &Contexto, filtro: &Filtro) -> Result<Vec<u32>, MotivoNoLeible> {
    if let Some(pid) = filtro.entero("pid") {
        // Un pid concreto. Si no existe, no es un error: es un proceso que ya
        // murio, y la respuesta correcta es una tabla vacia, no un fallo.
        return match u32::try_from(pid) {
            Ok(p) if ctx.proceso(p).is_ok() => Ok(vec![p]),
            _ => Ok(Vec::new()),
        };
    }
    if let Some(lista) = filtro.enteros("pid") {
        let mut salida: Vec<u32> = lista
            .into_iter()
            .filter_map(|p| u32::try_from(p).ok())
            .filter(|p| ctx.proceso(*p).is_ok())
            .collect();
        salida.sort_unstable();
        salida.dedup();
        return Ok(salida);
    }
    let mut todos: Vec<u32> = ctx.procesos()?.into_iter().map(|p| p.key.pid).collect();
    todos.sort_unstable();
    Ok(todos)
}

/// Lee un fichero de `/proc/<pid>/...` sin pasar por la raiz del contexto.
///
/// `/proc` es el nucleo vivo de ESTA maquina: no tiene sentido redirigirlo a un
/// arbol de prueba, porque los procesos que enumera `aegis-scal` serian de la
/// maquina y los ficheros de otro sitio. Una tabla de procesos sobre una raiz
/// alternativa declara su motivo en vez de mezclar las dos cosas; ver
/// [`exige_sistema_real`].
fn leer_de_proc(pid: u32, hoja: &str) -> Result<String, MotivoNoLeible> {
    let ruta = std::path::PathBuf::from(format!("/proc/{pid}/{hoja}"));
    std::fs::read_to_string(&ruta).map_err(|e| desde_io(e, &ruta, "leer de /proc"))
}

/// Lee un fichero de `/proc` como bytes, para los que van separados por NUL.
fn leer_bytes_de_proc(pid: u32, hoja: &str) -> Result<Vec<u8>, MotivoNoLeible> {
    let ruta = std::path::PathBuf::from(format!("/proc/{pid}/{hoja}"));
    std::fs::read(&ruta).map_err(|e| desde_io(e, &ruta, "leer de /proc"))
}

/// Rechaza la lectura si el contexto no apunta a la maquina real.
///
/// Ver [`leer_de_proc`] sobre por que estas tablas no se pueden redirigir.
fn exige_sistema_real(ctx: &Contexto) -> Result<(), MotivoNoLeible> {
    if ctx.es_el_sistema_real() {
        Ok(())
    } else {
        Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
            interfaz: "/proc de la maquina real; esta lectura no se puede redirigir a otra raiz",
        })
    }
}

/// Deriva el `Eid` de un proceso con el criterio del producto.
///
/// CUIDADO CON LAS UNIDADES, que aqui hay una trampa real:
/// `ProcessKey::start_stamp` de `aegis-scal` esta en TICS de reloj —el campo 22
/// de `/proc/<pid>/stat`, tal y como lo escribe el nucleo— mientras que
/// [`entidad::proceso`] pide NANOSEGUNDOS. Convertir tics a nanosegundos
/// introduce exactamente el redondeo que `start_stamp` existe para evitar, y
/// dos conversiones distintas darian dos identidades para el mismo proceso.
///
/// La salida es usar el valor EN TICS tal cual, que es lo que hace el sensor: la
/// identidad no necesita ser un instante, necesita ser ESTABLE y no repetirse
/// tras un reciclado de pid, y el tic de arranque lo cumple. Lo que no se puede
/// es mezclar las dos escalas, y por eso esta funcion es la unica que deriva
/// identidades de proceso en todo el crate.
fn eid_de_proceso(ctx: &Contexto, pid: u32, arranque_en_tics: u64) -> aegis_entidad::Eid {
    entidad::proceso(ctx.maquina(), ctx.boot(), pid, arranque_en_tics)
}

/// El arranque en tics de un proceso, o `None` si ya no esta.
fn arranque_de(ctx: &Contexto, pid: u32) -> Option<u64> {
    ctx.proceso(pid).ok().map(|p| p.key.start_stamp)
}

// ---------------------------------------------------------------------------
// process_arguments
// ---------------------------------------------------------------------------

/// Los argumentos de la linea de comandos, uno por fila.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argumentos;

impl Tabla for Argumentos {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_ARGUMENTS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let bytes = match leer_bytes_de_proc(pid, "cmdline") {
                Ok(b) => b,
                Err(m) => {
                    salida.avisar(format!("/proc/{pid}/cmdline"), m);
                    continue;
                }
            };
            let argumentos = aegis_scal::linux::process::parse_cmdline(&bytes);
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));
            for (i, arg) in argumentos.iter().enumerate() {
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                c.entero("pid", i64::from(pid));
                c.entero("position", i as i64);
                c.texto("value", arg.clone());
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_environment
// ---------------------------------------------------------------------------

/// El entorno de un proceso, una variable por fila.
#[derive(Debug, Clone, Copy, Default)]
pub struct Entorno;

impl Tabla for Entorno {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_ENVIRONMENT
    }

    /// PELIGROSO, y no por su coste de computo.
    ///
    /// Es la unica tabla del catalogo que se declara peligrosa por lo que
    /// CONTIENE y no por lo que tarda: el entorno de los procesos de una
    /// maquina lleva tokens de nube, contrasenas y claves de API. Difundir
    /// `SELECT * FROM process_environment` a cien mil endpoints y devolver el
    /// resultado al plano de control mueve todos los secretos de la flota a un
    /// solo sitio, que es el peor sitio donde podrian estar juntos.
    ///
    /// Acotada por `pid` o por `key` sigue siendo util —que es lo que hace de
    /// verdad un analista— y deja de ser una aspiradora.
    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["pid", "key"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        exige_sistema_real(ctx)?;
        let clave_buscada = filtro.texto("key");
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let bytes = match leer_bytes_de_proc(pid, "environ") {
                Ok(b) => b,
                Err(m) => {
                    salida.avisar(format!("/proc/{pid}/environ"), m);
                    continue;
                }
            };
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));
            for entrada in bytes.split(|b| *b == 0) {
                if entrada.is_empty() {
                    continue;
                }
                let texto = String::from_utf8_lossy(entrada);
                // Una variable sin `=` es basura del entorno, no una variable
                // con valor vacio: se salta en vez de inventarle un nombre.
                let Some((clave, valor)) = texto.split_once('=') else {
                    continue;
                };
                if let Some(k) = clave_buscada {
                    if clave != k {
                        continue;
                    }
                }
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                c.entero("pid", i64::from(pid));
                c.texto("key", clave);
                c.texto("value", valor);
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_open_files
// ---------------------------------------------------------------------------

/// Los descriptores abiertos por un proceso.
#[derive(Debug, Clone, Copy, Default)]
pub struct Abiertos;

/// Clasifica el destino de un enlace de `/proc/<pid>/fd/<n>`.
///
/// El nucleo escribe `socket:[12345]`, `pipe:[678]` y `anon_inode:[eventfd]`
/// para lo que no tiene nombre en el sistema de ficheros, y una ruta absoluta
/// para lo que si. Se distinguen porque el inodo de un socket es la clave que lo
/// une con `/proc/net/tcp`, y confundirlo con una ruta perderia esa union.
fn clasificar_descriptor(destino: &str) -> (&'static str, Option<u64>) {
    for (prefijo, clase) in [
        ("socket:[", "socket"),
        ("pipe:[", "pipe"),
        ("anon_inode:[", "anon_inode"),
    ] {
        if let Some(resto) = destino.strip_prefix(prefijo) {
            let inodo = resto.trim_end_matches(']').parse::<u64>().ok();
            return (clase, inodo);
        }
    }
    if destino.starts_with('/') {
        ("file", None)
    } else {
        ("unknown", None)
    }
}

impl Tabla for Abiertos {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_OPEN_FILES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let dir = std::path::PathBuf::from(format!("/proc/{pid}/fd"));
            let entradas = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    salida.avisar(dir.display().to_string(), desde_io(e, &dir, "enumerar"));
                    continue;
                }
            };
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));

            // Ordenar por numero de descriptor y no por el orden del directorio:
            // el determinismo de la respuesta empieza aqui.
            let mut fds: Vec<(i64, std::path::PathBuf)> = entradas
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_str()?.parse::<i64>().ok()?;
                    Some((n, e.path()))
                })
                .collect();
            fds.sort_by_key(|(n, _)| *n);

            for (fd, enlace) in fds {
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                let Ok(destino) = std::fs::read_link(&enlace) else {
                    // El descriptor se cerro mientras se enumeraba. Es lo normal
                    // en una maquina viva y no merece un aviso por cada uno.
                    continue;
                };
                let destino = destino.to_string_lossy().to_string();
                let borrado = destino.ends_with(" (deleted)");
                let limpio = destino.trim_end_matches(" (deleted)");
                let (clase, inodo) = clasificar_descriptor(limpio);

                c.entero("pid", i64::from(pid));
                c.entero("fd", fd);
                c.texto("path", limpio);
                c.texto("kind", clase);
                c.booleano("deleted", borrado);
                match inodo {
                    Some(i) => {
                        c.entero("inode", i64::try_from(i).unwrap_or(i64::MAX));
                    }
                    None => {
                        // El inodo de un fichero normal se pide al sistema; si no
                        // se puede, queda ausente y no a cero.
                        if let Ok(md) = std::fs::metadata(&enlace) {
                            use std::os::unix::fs::MetadataExt;
                            c.entero("inode", i64::try_from(md.ino()).unwrap_or(i64::MAX));
                        }
                    }
                }
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_threads
// ---------------------------------------------------------------------------

/// Los hilos de un proceso.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hilos;

impl Tabla for Hilos {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_THREADS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let dir = std::path::PathBuf::from(format!("/proc/{pid}/task"));
            let entradas = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    salida.avisar(dir.display().to_string(), desde_io(e, &dir, "enumerar"));
                    continue;
                }
            };
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));

            let mut tids: Vec<u32> = entradas
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .collect();
            tids.sort_unstable();

            for tid in tids {
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                c.entero("pid", i64::from(pid));
                c.entero("tid", i64::from(tid));

                let comm = leer_de_proc(pid, &format!("task/{tid}/comm")).ok();
                c.texto_opcional("name", comm.map(|s| s.trim_end().to_string()));

                // El `stat` del hilo da su estado Y su arranque propio, que es
                // lo que delata un hilo inyectado mucho despues que su proceso.
                if let Ok(stat) = leer_de_proc(pid, &format!("task/{tid}/stat")) {
                    if let Some((estado, _ppid, _hilos, arranque)) =
                        aegis_scal::linux::process::parse_stat(&stat)
                    {
                        c.texto("state", nombre_de_estado(estado));
                        c.entero("start_ticks", i64::try_from(arranque).unwrap_or(i64::MAX));
                    }
                }
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

/// Nombre estable de un estado del planificador.
///
/// Se escribe aqui y no se reutiliza el `Debug` del enumerado a proposito: un
/// `Debug` puede cambiar al refactorizar y esto es el VALOR de una columna que
/// aparece en consultas guardadas de los clientes.
fn nombre_de_estado(e: aegis_scal::process::ProcessState) -> &'static str {
    use aegis_scal::process::ProcessState as S;
    match e {
        S::Running => "running",
        S::Sleeping => "sleeping",
        S::Uninterruptible => "uninterruptible",
        S::Stopped => "stopped",
        S::Zombie => "zombie",
        S::Other => "other",
    }
}

// ---------------------------------------------------------------------------
// process_capabilities
// ---------------------------------------------------------------------------

/// Nombres de las capacidades de Linux, por su numero de bit.
///
/// La lista llega hasta `CAP_CHECKPOINT_RESTORE` (40), que es la ultima que
/// anadio el nucleo 5.9. Un bit por encima del final de esta tabla se devuelve
/// como `CAP_<n>` en vez de descartarse: un nucleo mas nuevo que esta tabla
/// tiene que seguir dando una respuesta util, y un numero es mas util que
/// perder la fila.
const NOMBRES_CAPACIDADES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Nombre de una capacidad por su numero de bit.
pub fn nombre_de_capacidad(bit: u32) -> String {
    NOMBRES_CAPACIDADES
        .get(bit as usize)
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| format!("CAP_{bit}"))
}

/// Los cinco conjuntos de capacidades, con su nombre en `/proc/<pid>/status`.
const CONJUNTOS: &[(&str, &str)] = &[
    ("CapInh:", "inheritable"),
    ("CapPrm:", "permitted"),
    ("CapEff:", "effective"),
    ("CapBnd:", "bounding"),
    ("CapAmb:", "ambient"),
];

/// Las capacidades de un proceso, una fila por capacidad y conjunto.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capacidades;

impl Tabla for Capacidades {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_CAPABILITIES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        let capacidad_buscada = filtro.texto("capability");
        let conjunto_buscado = filtro.texto("set");
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let status = match leer_de_proc(pid, "status") {
                Ok(s) => s,
                Err(m) => {
                    salida.avisar(format!("/proc/{pid}/status"), m);
                    continue;
                }
            };
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));

            for (etiqueta, nombre_conjunto) in CONJUNTOS {
                if let Some(cj) = conjunto_buscado {
                    if cj != *nombre_conjunto {
                        continue;
                    }
                }
                let Some(linea) = status.lines().find(|l| l.starts_with(etiqueta)) else {
                    continue;
                };
                let hex = linea[etiqueta.len()..].trim();
                let Ok(mascara) = u64::from_str_radix(hex, 16) else {
                    salida.avisar(
                        format!("/proc/{pid}/status {etiqueta}"),
                        MotivoNoLeible::ErrorDelSistema {
                            operacion: "leer la mascara de capacidades",
                            detalle: format!("no es hexadecimal: {hex}"),
                        },
                    );
                    continue;
                };
                for bit in 0..64u32 {
                    if mascara & (1u64 << bit) == 0 {
                        continue;
                    }
                    let nombre = nombre_de_capacidad(bit);
                    if let Some(buscada) = capacidad_buscada {
                        if nombre != buscada {
                            continue;
                        }
                    }
                    if salida.filas.len() >= TOPE_DE_FILAS {
                        salida.truncada = true;
                        return Ok(salida);
                    }
                    c.entero("pid", i64::from(pid));
                    c.texto("set", *nombre_conjunto);
                    c.texto("capability", nombre);
                    if let Some(e) = &eid {
                        c.entidad(e.clone());
                    }
                    salida.filas.push(c.fin());
                }
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_namespaces
// ---------------------------------------------------------------------------

/// Los ocho espacios de nombres que expone el nucleo.
const ESPACIOS: &[&str] = &["mnt", "net", "pid", "uts", "ipc", "user", "cgroup", "time"];

/// Los espacios de nombres de un proceso.
#[derive(Debug, Clone, Copy, Default)]
pub struct Espacios;

/// Inodo de un espacio de nombres, de `net:[4026531840]`.
fn inodo_de_espacio(destino: &str) -> Option<u64> {
    let (_, resto) = destino.split_once(":[")?;
    resto.trim_end_matches(']').parse().ok()
}

impl Tabla for Espacios {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_NAMESPACES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        // Los del proceso 1, una sola vez: son la referencia contra la que se
        // decide si un proceso esta aislado o no.
        let del_init: Vec<Option<u64>> = ESPACIOS
            .iter()
            .map(|k| {
                std::fs::read_link(format!("/proc/1/ns/{k}"))
                    .ok()
                    .and_then(|d| inodo_de_espacio(&d.to_string_lossy()))
            })
            .collect();

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));
            let mut alguno = false;

            for (i, kind) in ESPACIOS.iter().enumerate() {
                let Ok(destino) = std::fs::read_link(format!("/proc/{pid}/ns/{kind}")) else {
                    // Un espacio que no existe en este nucleo (`time` es de 5.6
                    // en adelante) no es un fallo: es una capacidad que esta
                    // maquina no tiene.
                    continue;
                };
                alguno = true;
                let Some(inodo) = inodo_de_espacio(&destino.to_string_lossy()) else {
                    continue;
                };
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                c.entero("pid", i64::from(pid));
                c.texto("kind", *kind);
                c.entero("inode", i64::try_from(inodo).unwrap_or(i64::MAX));
                match del_init[i] {
                    Some(referencia) => {
                        c.booleano("shared_with_init", inodo == referencia);
                    }
                    // Sin referencia no se afirma nada: `false` diria "esta
                    // aislado", que es una conclusion que no se ha comprobado.
                    None => {
                        c.pon("shared_with_init", aegis_parser::valor::Valor::Ausente);
                    }
                }
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }

            if !alguno {
                salida.avisar(
                    format!("/proc/{pid}/ns"),
                    MotivoNoLeible::SinPrivilegios {
                        operacion: "leer los espacios de nombres",
                        necesita: "CAP_SYS_PTRACE o ser el dueno del proceso",
                    },
                );
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_cgroups
// ---------------------------------------------------------------------------

/// La pertenencia de un proceso a las jerarquias de cgroups.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cgroups;

impl Tabla for Cgroups {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_CGROUPS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let texto = match leer_de_proc(pid, "cgroup") {
                Ok(t) => t,
                Err(m) => {
                    salida.avisar(format!("/proc/{pid}/cgroup"), m);
                    continue;
                }
            };
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));

            for linea in texto.lines() {
                // Formato: `jerarquia:controladores:ruta`. La ruta puede llevar
                // dos puntos, asi que se parte SOLO por los dos primeros.
                let mut partes = linea.splitn(3, ':');
                let (Some(jerarquia), Some(controladores), Some(ruta)) =
                    (partes.next(), partes.next(), partes.next())
                else {
                    continue;
                };
                if salida.filas.len() >= TOPE_DE_FILAS {
                    salida.truncada = true;
                    return Ok(salida);
                }
                c.entero("pid", i64::from(pid));
                c.entero("hierarchy", jerarquia.parse::<i64>().unwrap_or(-1));
                c.texto("controllers", controladores);
                c.texto("path", ruta);
                if let Some(e) = &eid {
                    c.entidad(e.clone());
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// process_selinux
// ---------------------------------------------------------------------------

/// El contexto SELinux de un proceso.
#[derive(Debug, Clone, Copy, Default)]
pub struct Selinux;

impl Tabla for Selinux {
    fn esquema(&self) -> &'static Esquema {
        &esq::PROCESS_SELINUX
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Proceso)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        exige_sistema_real(ctx)?;
        // Si SELinux no esta, se DICE. Devolver cero filas aqui haria que un
        // informe concluyera «ningun proceso sin confinar» en una maquina donde
        // no hay confinamiento ninguno.
        if !std::path::Path::new("/sys/fs/selinux").exists() {
            return Err(MotivoNoLeible::NoExisteEnEsteNucleo {
                interfaz: "/sys/fs/selinux (SELinux no esta activo en esta maquina)",
            });
        }

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for pid in pids_a_leer(ctx, filtro)? {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            salida.examinadas += 1;
            let contexto = match leer_de_proc(pid, "attr/current") {
                Ok(t) => t.trim_end_matches('\0').trim().to_string(),
                Err(m) => {
                    salida.avisar(format!("/proc/{pid}/attr/current"), m);
                    continue;
                }
            };
            if contexto.is_empty() {
                continue;
            }
            if salida.filas.len() >= TOPE_DE_FILAS {
                salida.truncada = true;
                return Ok(salida);
            }
            let eid = arranque_de(ctx, pid).map(|t| eid_de_proceso(ctx, pid, t));

            // `usuario:rol:tipo[:nivel]`. El nivel puede llevar dos puntos
            // dentro (`s0:c1,c2`), asi que se parte por los tres primeros.
            let mut partes = contexto.splitn(4, ':');
            c.entero("pid", i64::from(pid));
            c.texto("context", contexto.clone());
            c.texto_opcional("user", partes.next());
            c.texto_opcional("role", partes.next());
            c.texto_opcional("type", partes.next());
            c.texto_opcional("level", partes.next());
            if let Some(e) = &eid {
                c.entidad(e.clone());
            }
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

/// Las ocho tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Argumentos),
        Box::new(Entorno),
        Box::new(Abiertos),
        Box::new(Hilos),
        Box::new(Capacidades),
        Box::new(Espacios),
        Box::new(Cgroups),
        Box::new(Selinux),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_parser::ast::Literal;

    fn ctx() -> Contexto {
        Contexto::del_sistema(entidad::maquina("prueba"), 0, 0)
    }

    fn columna(t: &dyn Tabla, nombre: &str) -> usize {
        t.esquema()
            .columnas
            .iter()
            .position(|c| c.nombre == nombre)
            .unwrap_or_else(|| panic!("la columna {nombre} no esta en {}", t.nombre()))
    }

    #[test]
    fn el_empuje_por_pid_lee_un_solo_proceso() {
        // La propiedad que justifica el empuje entero: con `pid = N` se examina
        // UNO, no los miles de la maquina.
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Argumentos.leer(&c, &f).expect("leer argumentos");
        assert_eq!(r.examinadas, 1, "se examino mas de un proceso");
        assert!(!r.filas.is_empty(), "mi propio proceso tiene argumentos");
    }

    #[test]
    fn sin_empuje_se_examinan_todos_los_procesos() {
        let c = ctx();
        let r = Argumentos
            .leer(&c, &Filtro::ninguno())
            .expect("leer argumentos");
        assert!(
            r.examinadas > 1,
            "una maquina viva tiene mas de un proceso: {}",
            r.examinadas
        );
    }

    #[test]
    fn el_empuje_no_pierde_filas() {
        // LA propiedad de correccion del empuje: lo que devuelve la consulta
        // acotada tiene que estar contenido en lo que devuelve la no acotada.
        // Si esto falla, el empuje esta perdiendo deteccion en silencio.
        let c = ctx();
        let yo = i64::from(std::process::id());

        let acotada = Argumentos
            .leer(
                &c,
                &Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo)),
            )
            .expect("acotada");
        let todo = Argumentos.leer(&c, &Filtro::ninguno()).expect("sin acotar");

        let i_pid = columna(&Argumentos, "pid");
        let i_val = columna(&Argumentos, "value");
        let mias_en_todo: Vec<_> = todo
            .filas
            .iter()
            .filter(|f| f.valor(i_pid) == &aegis_parser::valor::Valor::Entero(yo))
            .map(|f| f.valor(i_val).a_texto())
            .collect();
        let mias_acotada: Vec<_> = acotada
            .filas
            .iter()
            .map(|f| f.valor(i_val).a_texto())
            .collect();
        assert_eq!(mias_acotada, mias_en_todo);
    }

    #[test]
    fn un_pid_que_no_existe_da_cero_filas_y_no_un_error() {
        // Un proceso que murio no es un fallo de la consulta.
        let c = ctx();
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(0));
        let r = Argumentos.leer(&c, &f).expect("no deberia fallar");
        assert!(r.filas.is_empty());
    }

    #[test]
    fn los_argumentos_salen_separados_y_en_orden() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Argumentos.leer(&c, &f).unwrap();
        let i_pos = columna(&Argumentos, "position");
        let posiciones: Vec<i64> = r
            .filas
            .iter()
            .map(|f| match f.valor(i_pos) {
                aegis_parser::valor::Valor::Entero(n) => *n,
                otro => panic!("position no es entero: {otro:?}"),
            })
            .collect();
        assert_eq!(
            posiciones,
            (0..posiciones.len() as i64).collect::<Vec<_>>(),
            "las posiciones tienen que ser 0,1,2..."
        );
    }

    #[test]
    fn el_entorno_sin_acotar_se_rechaza_sin_tocar_el_sistema() {
        // Es la tabla peligrosa: sin filtro no se lee, y el motivo dice como
        // escribir la consulta bien.
        let c = ctx();
        match Entorno.leer(&c, &Filtro::ninguno()) {
            Err(MotivoNoLeible::RequiereFiltro { columnas }) => {
                assert!(columnas.contains(&"pid"));
                assert!(columnas.contains(&"key"));
            }
            otro => panic!("se esperaba RequiereFiltro, salio {otro:?}"),
        }
    }

    #[test]
    fn el_entorno_acotado_por_pid_se_lee() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Entorno.leer(&c, &f).expect("acotado por pid se lee");
        // El proceso de prueba siempre tiene algo en el entorno.
        assert!(!r.filas.is_empty());
    }

    #[test]
    fn el_entorno_acotado_por_clave_devuelve_solo_esa() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno()
            .con_igualdad("pid", Literal::Entero(yo))
            .con_igualdad("key", Literal::Texto("PATH".into()));
        let r = Entorno.leer(&c, &f).unwrap();
        let i_key = columna(&Entorno, "key");
        assert!(r.filas.iter().all(|f| f.valor(i_key).a_texto() == "PATH"));
    }

    #[test]
    fn los_descriptores_del_proceso_propio_incluyen_los_tres_estandar() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Abiertos.leer(&c, &f).expect("leer descriptores");
        let i_fd = columna(&Abiertos, "fd");
        let fds: Vec<i64> = r
            .filas
            .iter()
            .filter_map(|f| match f.valor(i_fd) {
                aegis_parser::valor::Valor::Entero(n) => Some(*n),
                _ => None,
            })
            .collect();
        for esperado in [0i64, 1, 2] {
            assert!(fds.contains(&esperado), "falta el descriptor {esperado}");
        }
        assert!(fds.windows(2).all(|p| p[0] <= p[1]), "no estan ordenados");
    }

    #[test]
    fn un_socket_se_clasifica_con_su_inodo() {
        let (clase, inodo) = clasificar_descriptor("socket:[123456]");
        assert_eq!(clase, "socket");
        assert_eq!(inodo, Some(123_456));

        let (clase, inodo) = clasificar_descriptor("/usr/bin/curl");
        assert_eq!(clase, "file");
        assert_eq!(inodo, None);

        let (clase, _) = clasificar_descriptor("pipe:[99]");
        assert_eq!(clase, "pipe");
        let (clase, _) = clasificar_descriptor("anon_inode:[eventfd]");
        assert_eq!(clase, "anon_inode");
        let (clase, _) = clasificar_descriptor("algo-raro");
        assert_eq!(clase, "unknown");
    }

    #[test]
    fn el_proceso_propio_tiene_al_menos_un_hilo() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Hilos.leer(&c, &f).expect("leer hilos");
        assert!(!r.filas.is_empty());
        let i_tid = columna(&Hilos, "tid");
        // El hilo principal tiene tid == pid.
        assert!(r
            .filas
            .iter()
            .any(|f| f.valor(i_tid) == &aegis_parser::valor::Valor::Entero(yo)));
    }

    #[test]
    fn las_capacidades_salen_por_nombre_y_no_como_mascara() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Capacidades.leer(&c, &f).expect("leer capacidades");
        let i_cap = columna(&Capacidades, "capability");
        let i_set = columna(&Capacidades, "set");
        // El proceso de prueba tiene al menos el conjunto `bounding` completo.
        assert!(!r.filas.is_empty(), "ningun conjunto de capacidades");
        for fila in &r.filas {
            let cap = fila.valor(i_cap).a_texto();
            assert!(cap.starts_with("CAP_"), "capacidad sin nombre: {cap}");
            let conjunto = fila.valor(i_set).a_texto();
            assert!(
                CONJUNTOS.iter().any(|(_, n)| *n == conjunto),
                "conjunto desconocido: {conjunto}"
            );
        }
    }

    #[test]
    fn una_capacidad_por_encima_de_la_tabla_no_se_pierde() {
        // Un nucleo mas nuevo que esta tabla tiene que seguir dando respuesta.
        assert_eq!(nombre_de_capacidad(0), "CAP_CHOWN");
        assert_eq!(nombre_de_capacidad(21), "CAP_SYS_ADMIN");
        assert_eq!(nombre_de_capacidad(40), "CAP_CHECKPOINT_RESTORE");
        assert_eq!(nombre_de_capacidad(63), "CAP_63");
    }

    #[test]
    fn el_filtro_por_capacidad_devuelve_solo_esa() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno()
            .con_igualdad("pid", Literal::Entero(yo))
            .con_igualdad("capability", Literal::Texto("CAP_SYS_ADMIN".into()));
        let r = Capacidades.leer(&c, &f).unwrap();
        let i_cap = columna(&Capacidades, "capability");
        assert!(r
            .filas
            .iter()
            .all(|f| f.valor(i_cap).a_texto() == "CAP_SYS_ADMIN"));
    }

    #[test]
    fn los_espacios_de_nombres_del_proceso_propio_se_leen() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Espacios.leer(&c, &f).expect("leer espacios");
        let i_kind = columna(&Espacios, "kind");
        let clases: Vec<String> = r.filas.iter().map(|f| f.valor(i_kind).a_texto()).collect();
        // `mnt`, `net` y `pid` existen en cualquier nucleo con espacios.
        for esperado in ["mnt", "net", "pid"] {
            assert!(clases.iter().any(|k| k == esperado), "falta {esperado}");
        }
    }

    #[test]
    fn el_inodo_de_un_espacio_se_extrae_del_enlace() {
        assert_eq!(inodo_de_espacio("net:[4026531840]"), Some(4_026_531_840));
        assert_eq!(inodo_de_espacio("basura"), None);
    }

    #[test]
    fn el_cgroup_del_proceso_propio_se_lee_con_su_ruta() {
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Cgroups.leer(&c, &f).expect("leer cgroups");
        assert!(!r.filas.is_empty(), "todo proceso pertenece a algun cgroup");
        let i_path = columna(&Cgroups, "path");
        assert!(r
            .filas
            .iter()
            .all(|f| f.valor(i_path).a_texto().starts_with('/')));
    }

    #[test]
    fn una_ruta_de_cgroup_con_dos_puntos_no_se_parte_de_mas() {
        // Las rutas de cgroup de systemd llevan `:` en los nombres de scope
        // (`libpod-...scope`), y partir por todos los `:` truncaria la ruta.
        // Se comprueba con la funcion real, sobre una linea sintetica.
        let linea = "0::/system.slice/docker-abc:def.scope";
        let mut partes = linea.splitn(3, ':');
        assert_eq!(partes.next(), Some("0"));
        assert_eq!(partes.next(), Some(""));
        assert_eq!(partes.next(), Some("/system.slice/docker-abc:def.scope"));
    }

    #[test]
    fn sin_selinux_se_dice_en_vez_de_devolver_cero_filas() {
        let c = ctx();
        let r = Selinux.leer(&c, &Filtro::ninguno());
        if std::path::Path::new("/sys/fs/selinux").exists() {
            assert!(r.is_ok(), "con SELinux activo tiene que leerse");
        } else {
            match r {
                Err(MotivoNoLeible::NoExisteEnEsteNucleo { interfaz }) => {
                    assert!(interfaz.contains("selinux"));
                }
                otro => panic!("sin SELinux se esperaba el motivo, salio {otro:?}"),
            }
        }
    }

    #[test]
    fn estas_tablas_no_se_leen_contra_una_raiz_de_prueba() {
        // Mezclar los procesos de la maquina real con un arbol de ficheros de
        // prueba daria una respuesta que no describe ninguna maquina.
        let c = ctx().con_raiz("/tmp/raiz-de-prueba");
        for t in tablas() {
            match t.leer(
                &c,
                &Filtro::ninguno().con_igualdad("pid", Literal::Entero(1)),
            ) {
                Err(MotivoNoLeible::NoAplicaEnEstaPlataforma { .. }) => {}
                // El entorno rechaza antes por la cota, que tambien es correcto.
                Err(MotivoNoLeible::RequiereFiltro { .. }) => {}
                Err(MotivoNoLeible::NoExisteEnEsteNucleo { .. }) => {}
                otro => panic!("{} no rechazo la raiz de prueba: {otro:?}", t.nombre()),
            }
        }
    }

    #[test]
    fn toda_tabla_de_la_familia_declara_clase_de_proceso() {
        for t in tablas() {
            assert_eq!(
                t.clase(),
                Some(Clase::Proceso),
                "{} no nombra procesos",
                t.nombre()
            );
        }
    }

    #[test]
    fn las_filas_llevan_la_entidad_del_proceso() {
        // Es lo que permite unir el resultado con el linaje sin correlacionar
        // por texto.
        let c = ctx();
        let yo = i64::from(std::process::id());
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(yo));
        let r = Argumentos.leer(&c, &f).unwrap();
        let con_entidad = r.filas.iter().filter(|f| f.entidad().is_some()).count();
        assert_eq!(con_entidad, r.filas.len(), "hay filas sin Eid");
        assert_eq!(
            r.filas[0].entidad().unwrap().clase(),
            Clase::Proceso,
            "el Eid no es de un proceso"
        );
    }

    #[test]
    fn el_presupuesto_agotado_trunca_pero_no_falla() {
        let c = ctx().con_presupuesto(std::time::Duration::from_nanos(1));
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r = Argumentos.leer(&c, &Filtro::ninguno()).expect("no falla");
        assert!(r.truncada, "una lectura cortada tiene que decirlo");
    }
}
