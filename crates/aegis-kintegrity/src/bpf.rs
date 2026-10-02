//! Carga del verificador y ejecucion de las dos vistas de kernel.
//!
//! Es la unica parte del crate que necesita privilegios, BTF y un kernel
//! reciente. Todo lo que DECIDE vive en [`crate::verdict`] y [`crate::engine`],
//! que se prueban sin kernel; y lo que interpreta las respuestas del kernel,
//! en [`crate::abi`], que tambien.
//!
//! # Como se ejecuta un programa
//!
//! Los programas son iteradores `iter.s/task` (tipo TRACING), no programas
//! `syscall`: el kernel registra `bpf_task_from_pid` para TRACING desde 6.2 y
//! para SYSCALL solo desde 6.10, y con `syscall` Ubuntu 24.04 (6.8) rechazaba
//! el objeto. La cabecera de `aegis_kintegrity.bpf.c` tiene la tabla medida.
//!
//! Cada programa tiene un enlace de iterador creado al cargar y anclado a UNA
//! tarea —este proceso— con `link_info.task.tid`. Pedirle algo es:
//!
//! 1. escribir la peticion en la entrada 0 de su mapa ARRAY;
//! 2. crear un iterador sobre el enlace y leerlo hasta el final;
//! 3. decodificar lo leido, que es la misma estructura ya rellena.
//!
//! Como el iterador visita una sola tarea, el programa corre una sola vez por
//! lectura y toma las dos vistas en esa unica invocacion.
//!
//! Un barrido son tantas lecturas como tramos de [`crate::abi::MAX_BARRIDO`]
//! PID pida el motor ([`crate::tramos`]): cada una toma B y C de su tramo, y
//! entre una y otra el hilo vuelve a espacio de usuario.

use std::ffi::OsStr;
use std::io::Read;
use std::ptr::NonNull;

use libbpf_rs::{AsRawLibbpf, Iter, Link, MapCore, MapFlags, Object, ObjectBuilder};

use crate::abi::{KiArgs, KiConfirm, KiTask};
use crate::engine::KernelViews;
use crate::error::KiError;
use crate::tramos::{self, Tramo};
use crate::views::{self, Vista};

/// Objeto eBPF empotrado en el binario.
const OBJETO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.bpf.o"));
/// Firma HMAC del objeto, calculada en la compilacion.
const OBJETO_HMAC: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.hmac"));
/// Clave con la que se firmo.
const OBJETO_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.key"));

/// Programa que toma las dos vistas.
const PROG_BARRIDO: &str = "aegis_ki_barrido";
/// Programa que confirma un TID.
const PROG_CONFIRMAR: &str = "aegis_ki_confirmar";
/// Mapa de peticion del barrido.
const MAPA_BARRIDO: &str = "aegis_ki_arg";
/// Mapa de peticion de la confirmacion.
const MAPA_CONFIRMAR: &str = "aegis_ki_cnf";

fn descifrar_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Comprueba la firma del bytecode antes de entregarlo al kernel.
///
/// Va primero, antes de cualquier otra comprobacion: cargar en el kernel un
/// programa cuya firma no cuadra es exactamente lo que hay que impedir, y no
/// tiene sentido diagnosticar el entorno para un binario en el que ya no se
/// confia.
fn verificar_integridad() -> Result<(), KiError> {
    let clave = descifrar_hex(OBJETO_KEY.trim()).ok_or(KiError::BytecodeTampered)?;
    let esperado = descifrar_hex(OBJETO_HMAC.trim()).ok_or(KiError::BytecodeTampered)?;
    let calculado = aegis_kguard::integrity::hmac_sha256(&clave, OBJETO);
    if aegis_kguard::integrity::constant_time_eq(&calculado, &esperado) {
        Ok(())
    } else {
        Err(KiError::BytecodeTampered)
    }
}

/// Vistas de kernel respaldadas por eBPF.
pub struct BpfViews {
    // Los enlaces van ANTES que el objeto: los campos se sueltan en el orden en
    // que se declaran, y un enlace se desmonta mejor con su programa vivo.
    /// Enlace de iterador del barrido.
    barrido: Link,
    /// Enlace de iterador de la confirmacion.
    confirmacion: Link,
    obj: Object,
    /// Generacion del barrido en curso.
    ///
    /// Los mapas no se vacian entre barridos: vaciarlos cuesta un borrado por
    /// entrada y deja una ventana en la que el mapa esta a medias. En su lugar
    /// cada entrada lleva la generacion que la escribio, y al leer se descarta
    /// —y se borra— todo lo que no sea de la actual.
    gen: u32,
}

impl std::fmt::Debug for BpfViews {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfViews").field("gen", &self.gen).finish()
    }
}

fn map_err(op: &'static str, e: libbpf_rs::Error) -> KiError {
    if errno_de(&e) == Some(libc::EPERM) {
        return KiError::InsufficientPrivileges;
    }
    KiError::Bpf {
        op,
        detail: e.to_string(),
    }
}

/// El errno de verdad de un error de libbpf.
///
/// `ErrorKind::PermissionDenied` no sirve para decidir: agrupa EPERM (falta
/// CAP_BPF) con EACCES (el verificador rechazo el programa), que piden
/// remedios opuestos. Se busca el `io::Error` con codigo en la cadena de causas.
fn errno_de(e: &libbpf_rs::Error) -> Option<i32> {
    let mut causa: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(c) = causa {
        if let Some(io) = c.downcast_ref::<std::io::Error>() {
            if let Some(n) = io.raw_os_error() {
                return Some(n);
            }
        }
        causa = c.source();
    }
    None
}

/// Las ultimas lineas que libbpf ha escrito, para explicar un rechazo.
///
/// libbpf solo sabe avisar por una funcion global sin estado, asi que el
/// registro es un anillo estatico y acotado. Se instala unicamente mientras se
/// carga este objeto y despues se restaura el anterior.
static REGISTRO: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const LINEAS_REGISTRO: usize = 64;

fn anotar(_nivel: libbpf_rs::PrintLevel, mensaje: String) {
    if let Ok(mut r) = REGISTRO.lock() {
        for l in mensaje.lines() {
            if r.len() == LINEAS_REGISTRO {
                r.remove(0);
            }
            r.push(l.trim_end().to_string());
        }
    }
}

/// Lo que explica el rechazo: la cola del registro del verificador, sin lineas
/// vacias ni los marcadores de comienzo y fin.
fn motivo_del_rechazo() -> String {
    let r = REGISTRO.lock().map(|g| g.clone()).unwrap_or_default();
    let utiles: Vec<&String> = r
        .iter()
        // Las lineas propias de libbpf («failed to load object», «failed to
        // load: -13») resumen el fallo; la causa la dice el verificador.
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.contains("PROG LOAD LOG")
                && !t.starts_with("libbpf:")
                && !t.starts_with("processed ")
        })
        .collect();
    // De la ultima a la primera: el verificador escribe su veredicto al final,
    // y quien lea un motivo acotado tiene que ver eso antes que el contexto.
    utiles
        .iter()
        .rev()
        .take(6)
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Crea el enlace de iterador de un programa, anclado a este proceso.
///
/// El ancla es el PID del proceso —el TID de su lider de grupo—, no el del
/// hilo que llama: el lider vive tanto como el proceso, y el hilo que carga el
/// verificador puede ser cualquiera. El numero se interpreta en el espacio de
/// nombres de PID de quien crea el enlace, que es este mismo proceso.
///
/// libbpf-rs 0.24 solo sabe parametrizar iteradores de mapa, asi que el
/// `link_info` de tarea se construye aqui y se entrega a libbpf directamente.
fn enlazar(obj: &Object, programa: &'static str) -> Result<Link, KiError> {
    let prog = obj
        .progs()
        .find(|p| p.name() == OsStr::new(programa))
        .ok_or_else(|| KiError::Bpf {
            op: "buscar programa",
            detail: format!("no existe {programa} en el objeto"),
        })?;

    let mut info = libbpf_sys::bpf_iter_link_info::default();
    info.task.tid = std::process::id();
    let opciones = libbpf_sys::bpf_iter_attach_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_iter_attach_opts>() as _,
        link_info: std::ptr::addr_of_mut!(info),
        link_info_len: std::mem::size_of::<libbpf_sys::bpf_iter_link_info>() as _,
        ..Default::default()
    };
    // SAFETY: `prog` es un programa cargado del objeto, que sigue vivo mientras
    // dura la llamada; `opciones` e `info` son locales que libbpf solo lee
    // durante la llamada y no retiene.
    let ptr = unsafe {
        libbpf_sys::bpf_program__attach_iter(prog.as_libbpf_object().as_ptr(), &opciones)
    };
    let Some(ptr) = NonNull::new(ptr) else {
        // libbpf 1.x devuelve NULL y deja el error en errno.
        let e = std::io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::EPERM) => KiError::InsufficientPrivileges,
            _ => KiError::Bpf {
                op: "enlazar iterador",
                detail: format!("{programa}: {e}"),
            },
        });
    };
    // SAFETY: el puntero lo acaba de crear libbpf, no es nulo y nadie mas lo
    // posee; el `Link` pasa a ser su unico dueno y lo destruye al soltarse.
    Ok(unsafe { Link::from_ptr(ptr) })
}

impl BpfViews {
    /// Carga el verificador en el kernel y crea sus dos enlaces de iterador.
    ///
    /// # Errores
    ///
    /// Un rechazo del verificador suele significar que faltan los kfuncs
    /// `bpf_task_from_pid` (Linux 6.2) o `bpf_iter_task_*` (Linux 6.7); un
    /// `EPERM`, que falta `CAP_BPF` o `CAP_PERFMON`, que un programa TRACING
    /// exige los dos.
    pub fn cargar() -> Result<BpfViews, KiError> {
        verificar_integridad()?;

        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return Err(KiError::Unsupported(
                "falta /sys/kernel/btf/vmlinux; sin BTF no hay CO-RE ni kfuncs".into(),
            ));
        }

        let mut builder = ObjectBuilder::default();
        let abierto = builder
            .open_memory(OBJETO)
            .map_err(|e| map_err("open_memory", e))?;
        if let Ok(mut r) = REGISTRO.lock() {
            r.clear();
        }
        let previo = libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, anotar)));
        let cargado = abierto.load();
        libbpf_rs::set_print(previo);
        let obj = cargado.map_err(|e| match errno_de(&e) {
            Some(libc::EPERM) => KiError::InsufficientPrivileges,
            n => KiError::Unsupported(format!(
                "el kernel rechazo el verificador (errno {}): {}",
                n.map_or_else(|| "?".to_string(), |n| n.to_string()),
                match motivo_del_rechazo() {
                    m if m.is_empty() => e.to_string(),
                    m => m,
                }
            )),
        })?;

        let barrido = enlazar(&obj, PROG_BARRIDO)?;
        let confirmacion = enlazar(&obj, PROG_CONFIRMAR)?;

        Ok(BpfViews {
            barrido,
            confirmacion,
            obj,
            gen: 0,
        })
    }

    /// Escribe la peticion, ejecuta el programa una vez y devuelve lo que
    /// respondio.
    fn consultar(
        &self,
        mapa: &'static str,
        enlace: &Link,
        peticion: &[u8],
    ) -> Result<Vec<u8>, KiError> {
        let m = self
            .obj
            .maps()
            .find(|m| m.name() == OsStr::new(mapa))
            .ok_or_else(|| KiError::Bpf {
                op: "buscar mapa",
                detail: format!("no existe {mapa}"),
            })?;
        m.update(&0u32.to_ne_bytes(), peticion, MapFlags::ANY)
            .map_err(|e| map_err("escribir la peticion", e))?;

        // Cada iterador es un seq_file nuevo: la lectura empieza siempre por la
        // tarea ancla y el programa trabaja en esa primera visita.
        let mut it = Iter::new(enlace).map_err(|e| map_err("crear el iterador", e))?;
        let mut respuesta = Vec::with_capacity(64);
        it.read_to_end(&mut respuesta).map_err(|e| KiError::Bpf {
            op: "leer el iterador",
            detail: e.to_string(),
        })?;
        Ok(respuesta)
    }

    /// Lee un mapa de vista y borra lo que no sea de la generacion actual.
    fn leer_vista(&self, nombre: &'static str, gen: u32) -> Result<Vista, KiError> {
        let mapa = self
            .obj
            .maps()
            .find(|m| m.name() == OsStr::new(nombre))
            .ok_or_else(|| KiError::Bpf {
                op: "buscar mapa",
                detail: format!("no existe {nombre}"),
            })?;

        let mut vivas: Vec<(u32, KiTask)> = Vec::new();
        let mut caducas: Vec<Vec<u8>> = Vec::new();

        for clave in mapa.keys() {
            let Some(valor) = mapa
                .lookup(&clave, MapFlags::ANY)
                .map_err(|e| map_err("map lookup", e))?
            else {
                // La entrada desaparecio entre enumerar y leer: normal.
                continue;
            };
            if valor.len() != std::mem::size_of::<KiTask>() {
                return Err(KiError::LayoutMismatch {
                    map: nombre,
                    got: valor.len(),
                    want: std::mem::size_of::<KiTask>(),
                });
            }
            if clave.len() != std::mem::size_of::<u32>() {
                return Err(KiError::LayoutMismatch {
                    map: nombre,
                    got: clave.len(),
                    want: std::mem::size_of::<u32>(),
                });
            }
            // SAFETY: el tamano se acaba de comprobar y `KiTask` es `repr(C)`
            // de enteros y bytes, sin invariantes ni punteros: cualquier patron
            // de bits es un valor valido.
            let t: KiTask = unsafe { std::ptr::read_unaligned(valor.as_ptr() as *const KiTask) };
            let tid = u32::from_ne_bytes([clave[0], clave[1], clave[2], clave[3]]);
            if t.gen == gen {
                vivas.push((tid, t));
            } else {
                caducas.push(clave);
            }
        }

        for c in caducas {
            // Un borrado que falla no es fatal: la entrada seguira siendo
            // descartada por generacion en el proximo barrido.
            let _ = mapa.delete(&c);
        }

        Ok(views::desde_mapa(vivas))
    }
}

impl KernelViews for BpfViews {
    fn barrer(&mut self, primero: i32, ultimo: i32) -> Result<(Vista, Vista, u32), KiError> {
        // El rango entero, en tramos: con `pid_max` = 4194304 son 64 lecturas.
        self.barrer_tramos(&tramos::partir(primero, ultimo))
    }

    /// Una lectura del iterador por tramo; los mapas se leen una vez al final.
    ///
    /// Todos los tramos llevan la misma generacion, de modo que lo que escribe
    /// uno no lo descarta el siguiente; y cada lectura toma B y C de su tramo
    /// en una sola invocacion. Leer los mapas por tramo costaria una llamada al
    /// sistema por entrada y por tramo: se leen al final, una vez.
    fn barrer_tramos(&mut self, tramos: &[Tramo]) -> Result<(Vista, Vista, u32), KiError> {
        self.gen = self.gen.wrapping_add(1);
        // La generacion 0 se reserva para "sin escribir": saltarla evita que una
        // entrada nunca tocada pase por reciente al dar la vuelta el contador.
        if self.gen == 0 {
            self.gen = 1;
        }
        let gen = self.gen;

        let mut desbordes = 0u32;
        for t in tramos {
            let peticion = KiArgs {
                primero: t.primero,
                ultimo: t.ultimo,
                gen,
                ..Default::default()
            };
            let bytes = self.consultar(MAPA_BARRIDO, &self.barrido, &peticion.a_bytes())?;
            // Un tramo de mas de MAX_BARRIDO PID vuelve como ERR_ARGS y aborta
            // el barrido: nada se recorta en silencio.
            let r = KiArgs::respuesta(&bytes, gen)?;
            desbordes = desbordes.saturating_add(r.desbordes);
        }

        let lista = self.leer_vista("aegis_ki_lista", gen)?;
        let pidmap = self.leer_vista("aegis_ki_pidmap", gen)?;
        Ok((lista, pidmap, desbordes))
    }

    fn confirmar(&mut self, tid: u32) -> Result<(bool, bool, Option<u64>), KiError> {
        // Un TID que no cabe en el `s32` del kernel no puede existir en ninguna
        // de las dos estructuras; y enviado tal cual volveria negativo, que en
        // la respuesta significa error del programa.
        let Ok(tid) = i32::try_from(tid) else {
            return Ok((false, false, None));
        };
        let peticion = KiConfirm {
            tid,
            ..Default::default()
        };
        let bytes = self.consultar(MAPA_CONFIRMAR, &self.confirmacion, &peticion.a_bytes())?;
        let c = KiConfirm::respuesta(&bytes, tid)?;
        let start = if c.start_boottime != 0 {
            Some(c.start_boottime)
        } else {
            None
        };
        Ok((c.en_lista != 0, c.en_pidmap != 0, start))
    }
}
