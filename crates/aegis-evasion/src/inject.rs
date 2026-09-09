//! Deteccion de codigo ejecutable sin fichero detras.
//!
//! # La senal
//!
//! El codigo legitimo se ejecuta desde imagenes mapeadas: el enlazador abre el
//! fichero, lo mapea con `PROT_EXEC` y el mapeo queda respaldado por un inodo.
//! Una region ejecutable **sin fichero detras** es codigo que llego ahi por
//! otro camino, y solo hay dos caminos: un compilador JIT o una inyeccion.
//!
//! # Por que no basta con contarlas
//!
//! Un navegador tiene decenas de regiones anonimas ejecutables y es
//! perfectamente legitimo. Marcar cada una seria inutilizable. Lo que separa
//! una inyeccion de un JIT son los detalles:
//!
//! - **RWX simultaneo.** Un JIT serio escribe y luego cambia a solo ejecucion
//!   (W^X), porque dejar la memoria escribible y ejecutable a la vez es la
//!   primitiva que convierte cualquier desbordamiento en ejecucion de codigo.
//!   Un inyector no se molesta.
//! - **Pila o monton ejecutables.** Ningun runtime hace esto. Es la firma de
//!   un desbordamiento clasico o de un cargador perezoso.
//! - **Tamano.** Una carga util reflectiva ronda decenas o cientos de KB. Las
//!   arenas de un JIT son de megabytes.
//! - **Ausencia de runtime.** Si el proceso no tiene mapeada ninguna biblioteca
//!   de JIT conocida, la explicacion benigna desaparece.

use aegis_scan::memory::{MemoryRegion, RegionClass};

/// Bibliotecas cuya presencia explica de forma benigna la memoria anonima
/// ejecutable de un proceso.
///
/// La lista es deliberadamente corta y se compara por subcadena del nombre del
/// fichero. Ampliarla sin medida convierte la excepcion en la regla.
const RUNTIMES_JIT: &[&str] = &[
    "libjvm",
    "libv8",
    "libmozjs",
    "libjavascriptcore",
    "libnode",
    "libpython",
    "libmono",
    "libcoreclr",
    "libclrjit",
    "libluajit",
    "libjulia",
    "libtorch",
];

/// Ejecutables que llevan el JIT dentro y no mapean ninguna biblioteca que lo
/// delate.
///
/// Node enlaza V8 estaticamente: un proceso de Node no mapea ningun `libv8.so`,
/// asi que buscar solo entre las bibliotecas lo deja sin explicacion benigna.
/// La comparacion es por nombre exacto del fichero y no por subcadena, porque
/// "node" o "java" como subcadena aparecen en demasiadas rutas.
const EJECUTABLES_JIT: &[&str] = &[
    "node", "nodejs", "deno", "bun", "chrome", "chromium", "firefox", "java", "dotnet", "mono",
    "python3", "pypy", "julia", "lua", "luajit", "electron", "code",
];

/// Tamano por encima del cual una region anonima ejecutable se parece mas a la
/// arena de un JIT que a una carga util inyectada.
pub const ARENA_JIT_MIN: u64 = 8 * 1024 * 1024;

/// Tamano por debajo del cual una region ejecutable es sospechosamente justa.
///
/// Una carga util reflectiva se mapea con el tamano que necesita. Un runtime
/// reserva de golpe.
pub const CARGA_UTIL_MAX: u64 = 2 * 1024 * 1024;

/// Naturaleza de un hallazgo de inyeccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionKind {
    /// Region anonima con lectura, escritura y ejecucion a la vez, del tamano
    /// de una carga util.
    ///
    /// Es el hallazgo de mas valor: nada legitimo de este tamano deja una
    /// region asi, porque es la primitiva que convierte un desbordamiento en
    /// ejecucion de codigo.
    AnonymousRwx,
    /// Region anonima RWX del tamano de la arena de un compilador JIT.
    ///
    /// Medido sobre procesos reales: un proceso de Node reserva 64 MB de RWX de
    /// una vez para el espacio de codigo de V8, y la JVM reserva aun mas. Una
    /// carga util reflectiva se mapea con el tamano que necesita, que son
    /// cientos de KB. El tamano manda sobre los permisos aqui: tratar los 64 MB
    /// de V8 como una inyeccion convierte en alerta permanente cualquier
    /// proceso con JIT, y una alerta permanente es una alerta que se ignora.
    ///
    /// No se descarta del todo porque RWX viola W^X a cualquier tamano, y
    /// porque es donde mejor se esconde una carga util: el escaneo de memoria
    /// con YARA la recorre igual.
    AnonymousRwxArena,
    /// Region anonima ejecutable, del tamano de una carga util.
    AnonymousExecPayload,
    /// Region anonima ejecutable grande, compatible con la arena de un JIT.
    AnonymousExecArena,
    /// La pila del proceso es ejecutable.
    ExecutableStack,
    /// El monton del proceso es ejecutable.
    ExecutableHeap,
    /// Una region respaldada por fichero es escribible y ejecutable.
    ///
    /// Un mapeo privado escribible sobre el `.text` de una biblioteca es como
    /// se parchea codigo ajeno sin tocar el disco.
    FileBackedWx,
}

impl InjectionKind {
    /// Peso del hallazgo en la puntuacion del proceso.
    pub fn weight(self) -> u32 {
        match self {
            InjectionKind::AnonymousRwx => 45,
            InjectionKind::AnonymousRwxArena => 10,
            InjectionKind::ExecutableStack => 60,
            InjectionKind::ExecutableHeap => 55,
            InjectionKind::FileBackedWx => 50,
            InjectionKind::AnonymousExecPayload => 25,
            // Se registra pero no puntua: una arena grande es lo normal en
            // cualquier proceso con JIT, y puntuarla dispararia en todos los
            // navegadores de la flota.
            InjectionKind::AnonymousExecArena => 0,
        }
    }
}

/// Un hallazgo concreto sobre una region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionFinding {
    /// Naturaleza.
    pub kind: InjectionKind,
    /// Direccion inicial de la region.
    pub start: u64,
    /// Tamano.
    pub size: u64,
    /// Etiqueta o ruta, si la region la tiene.
    pub label: Option<String>,
}

/// Resultado del analisis de un espacio de direcciones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InjectionReport {
    /// Hallazgos, del mas grave al menos grave.
    pub findings: Vec<InjectionFinding>,
    /// Regiones anonimas ejecutables encontradas en total.
    pub anon_exec_regions: usize,
    /// Bytes anonimos ejecutables en total.
    pub anon_exec_bytes: u64,
    /// Runtimes de JIT reconocidos en el proceso.
    pub jit_runtimes: Vec<String>,
}

impl InjectionReport {
    /// Puntuacion acumulada.
    ///
    /// Si el proceso tiene un runtime de JIT mapeado, los hallazgos que ese
    /// runtime explica valen la mitad. No cero: un JIT es tambien el sitio
    /// favorito donde esconder codigo, precisamente porque su memoria
    /// ejecutable no llama la atencion.
    pub fn score(&self) -> u32 {
        let bruto: u32 = self.findings.iter().map(|f| f.kind.weight()).sum();
        if self.jit_runtimes.is_empty() {
            bruto
        } else {
            bruto / 2
        }
    }
}

/// Analiza las regiones de memoria de un proceso.
///
/// Es una funcion pura sobre el mapa ya leido: asi se prueba con mapas
/// sinteticos y con mapas capturados de procesos reales, sin privilegios.
pub fn scan_injection(regiones: &[MemoryRegion]) -> InjectionReport {
    let mut informe = InjectionReport::default();

    for r in regiones {
        if let Some(p) = &r.path {
            if let Some(nombre) = p.rsplit('/').next() {
                for rt in RUNTIMES_JIT {
                    if nombre.contains(rt) && !informe.jit_runtimes.iter().any(|x| x == rt) {
                        informe.jit_runtimes.push((*rt).to_string());
                    }
                }
                for rt in EJECUTABLES_JIT {
                    if nombre == *rt && !informe.jit_runtimes.iter().any(|x| x == rt) {
                        informe.jit_runtimes.push((*rt).to_string());
                    }
                }
            }
        }
    }

    for r in regiones {
        if !r.perms.exec || r.is_empty() {
            continue;
        }
        let etiqueta = r.path.clone();

        match r.class() {
            RegionClass::AnonymousExec => {
                informe.anon_exec_regions += 1;
                informe.anon_exec_bytes = informe.anon_exec_bytes.saturating_add(r.len());

                let kind = match r.path.as_deref() {
                    Some("[stack]") => InjectionKind::ExecutableStack,
                    Some("[heap]") => InjectionKind::ExecutableHeap,
                    _ if r.perms.write && r.len() >= ARENA_JIT_MIN => {
                        InjectionKind::AnonymousRwxArena
                    }
                    _ if r.perms.write => InjectionKind::AnonymousRwx,
                    _ if r.len() >= ARENA_JIT_MIN => InjectionKind::AnonymousExecArena,
                    _ if r.len() <= CARGA_UTIL_MAX => InjectionKind::AnonymousExecPayload,
                    // Entre la carga util y la arena: se registra como arena,
                    // que es la lectura conservadora.
                    _ => InjectionKind::AnonymousExecArena,
                };
                informe.findings.push(InjectionFinding {
                    kind,
                    start: r.start,
                    size: r.len(),
                    label: etiqueta,
                });
            }
            RegionClass::FileExec if r.perms.write => {
                informe.findings.push(InjectionFinding {
                    kind: InjectionKind::FileBackedWx,
                    start: r.start,
                    size: r.len(),
                    label: etiqueta,
                });
            }
            _ => {}
        }
    }

    informe.findings.sort_by(|a, b| {
        b.kind
            .weight()
            .cmp(&a.kind.weight())
            .then(a.start.cmp(&b.start))
    });
    informe
}
