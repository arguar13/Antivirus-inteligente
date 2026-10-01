//! Carga del verificador y ejecucion de las dos vistas de kernel.
//!
//! Es la unica parte del crate que necesita privilegios, BTF y un kernel
//! reciente. Todo lo que DECIDE vive en [`crate::verdict`] y [`crate::engine`],
//! que se prueban sin kernel.

use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, ProgramInput};

use crate::abi::{KiArgs, KiConfirm, KiTask};
use crate::error::KiError;
use crate::views::{self, Vista};

/// Objeto eBPF empotrado en el binario.
const OBJETO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.bpf.o"));
/// Firma HMAC del objeto, calculada en la compilacion.
const OBJETO_HMAC: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.hmac"));
/// Clave con la que se firmo.
const OBJETO_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/aegis_kintegrity.key"));

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

impl BpfViews {
    /// Carga el verificador en el kernel.
    ///
    /// # Errores
    ///
    /// Un `EINVAL` al cargar suele significar que faltan los kfuncs
    /// `bpf_task_from_pid` (Linux 6.1) o `bpf_iter_task_*` (Linux 6.7); un
    /// `EPERM`, que falta `CAP_BPF`.
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

        Ok(BpfViews { obj, gen: 0 })
    }

    fn ejecutar<T: Copy>(&mut self, programa: &str, ctx: &mut T) -> Result<i32, KiError> {
        // El contexto se pasa como bytes: el programa `SEC("syscall")` recibe un
        // puntero real al espacio de usuario y escribe en el.
        //
        // `context_out` tiene que quedarse a `None`. El kernel devuelve EINVAL
        // si se le da uno para un programa de tipo syscall, porque ya escribio
        // directamente en `context_in`.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(ctx as *mut T as *mut u8, std::mem::size_of::<T>())
        };
        let prog = self
            .obj
            .progs_mut()
            .find(|p| p.name() == std::ffi::OsStr::new(programa))
            .ok_or_else(|| KiError::Bpf {
                op: "buscar programa",
                detail: format!("no existe {programa} en el objeto"),
            })?;

        let entrada = ProgramInput {
            context_in: Some(bytes),
            ..Default::default()
        };
        let salida = prog
            .test_run(entrada)
            .map_err(|e| map_err("bpf_prog_test_run", e))?;
        Ok(salida.return_value as i32)
    }

    /// Lee un mapa de vista y borra lo que no sea de la generacion actual.
    fn leer_vista(&self, nombre: &'static str, gen: u32) -> Result<Vista, KiError> {
        let mapa = self
            .obj
            .maps()
            .find(|m| m.name() == std::ffi::OsStr::new(nombre))
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

impl crate::engine::KernelViews for BpfViews {
    fn barrer(&mut self, primero: i32, ultimo: i32) -> Result<(Vista, Vista, u32), KiError> {
        self.gen = self.gen.wrapping_add(1);
        // La generacion 0 se reserva para "sin escribir": saltarla evita que una
        // entrada nunca tocada pase por reciente al dar la vuelta el contador.
        if self.gen == 0 {
            self.gen = 1;
        }
        let gen = self.gen;

        let mut args = KiArgs {
            primero,
            ultimo,
            gen,
            ..Default::default()
        };
        let rc = self.ejecutar("aegis_ki_barrido", &mut args)?;
        if rc != 0 || args.error != 0 {
            return Err(KiError::Programa(if rc != 0 { rc } else { args.error }));
        }

        let lista = self.leer_vista("aegis_ki_lista", gen)?;
        let pidmap = self.leer_vista("aegis_ki_pidmap", gen)?;
        Ok((lista, pidmap, args.desbordes))
    }

    fn confirmar(&mut self, tid: u32) -> Result<(bool, bool, Option<u64>), KiError> {
        let mut c = KiConfirm {
            tid: tid as i32,
            ..Default::default()
        };
        let rc = self.ejecutar("aegis_ki_confirmar", &mut c)?;
        if rc != 0 {
            return Err(KiError::Programa(rc));
        }
        let start = if c.start_boottime != 0 {
            Some(c.start_boottime)
        } else {
            None
        };
        Ok((c.en_lista != 0, c.en_pidmap != 0, start))
    }
}
