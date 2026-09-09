//! # aegis-unpacker
//!
//! Desempaquetado dinamico en memoria: extrae el codigo real de un binario
//! empaquetado ejecutandolo bajo control hasta su punto de entrada original.
//!
//! # El problema
//!
//! El malware moderno casi nunca lleva su codigo en claro en el disco. Un
//! empaquetador —UPX, Themida, o uno a medida— lo guarda COMPRIMIDO o CIFRADO
//! dentro de una seccion, junto a un pequeno descompresor. Al ejecutarse, el
//! descompresor despliega el codigo real en memoria y salta a el. Escanear el
//! fichero de disco con firmas no ve nada: el codigo que las firmas buscan no
//! esta ahi todavia, esta comprimido.
//!
//! Este crate lo despliega y lo captura:
//!
//! 1. **Filtro de entrada** ([`gate`]): solo se molesta con binarios cuya senal
//!    es la de un empaquetador —secciones ejecutables de entropia casi maxima—,
//!    porque desempaquetar es caro y arriesgado.
//! 2. **Ejecucion controlada** ([`tracer`]): lanza el binario bajo `ptrace`,
//!    CONFINADO por un sandbox de llamadas al sistema ([`confinamiento`]) que le
//!    corta la red y la capacidad de hacer dano, y lo sigue hasta que empieza a
//!    ejecutar codigo en una region que no existia al arrancar: el OEP.
//! 3. **Volcado** ([`dump`]): con el proceso detenido en el OEP, lee la region
//!    desempaquetada.
//! 4. **Escaneo**: el volcado se entrega al motor YARA, que ahora SI ve el
//!    codigo real.
//!
//! # Por que esto es real y no una simulacion
//!
//! El desempaquetado ejecuta el binario de verdad y sigue sus llamadas al
//! sistema de verdad; el OEP se detecta observando el efecto real de la
//! descompresion sobre el mapa de memoria del proceso. La prueba de integracion
//! construye un empaquetador AUTENTICO —un binario cuyo codigo real esta cifrado
//! con XOR en el disco y que se descifra a si mismo en una region `mmap` en
//! tiempo de ejecucion— y comprueba que una firma que NO aparece en el fichero
//! de disco SI aparece en el volcado. Es exactamente lo que hace un empaquetador
//! real, reducido a lo esencial.

#![deny(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "aegis-unpacker usa ptrace y seccomp, que son de Linux. En Windows el \
     equivalente es la depuracion con la Debug API y los page-guard hooks; en \
     macOS, mach exception ports. Ninguno se puede fingir desde aqui."
);

pub mod confinamiento;
pub mod dump;
pub mod error;
pub mod gate;
pub mod region;
pub mod tracer;

pub use dump::{volcar, DumpDesempaquetado};
pub use error::UnpackError;
pub use gate::{evaluar, GateVerdict, Seccion};
pub use region::Rango;
pub use tracer::{ejecutar_hasta_oep, OepAlcanzado, TraceConfig};

/// Resultado completo de un desempaquetado.
#[derive(Debug, Clone)]
pub struct Unpacked {
    /// Donde se detecto el codigo desempaquetado.
    pub oep: OepAlcanzado,
    /// El codigo real volcado.
    pub dump: DumpDesempaquetado,
}

/// Desempaqueta un binario: lo ejecuta bajo control y vuelca su codigo real.
///
/// Es el punto de entrada de alto nivel. No aplica el filtro de entropia por su
/// cuenta —eso es decision del llamante, que quiza ya lo evaluo al extraer las
/// secciones—, pero SI confina el proceso por defecto.
pub fn desempaquetar(
    programa: &std::path::Path,
    args: &[String],
    config: &TraceConfig,
) -> Result<Unpacked, UnpackError> {
    let oep = tracer::ejecutar_hasta_oep(programa, args, config)?;
    // El proceso esta detenido en el OEP: se vuelca AHORA, con la memoria
    // quieta, y solo despues se mata. Si el volcado falla, el proceso se mata
    // igual: no puede quedar vivo codigo posiblemente malicioso.
    let dump = dump::volcar(oep.pid, oep.region);
    tracer::matar_proceso(oep.pid);
    Ok(Unpacked { oep, dump: dump? })
}

/// Indica si esta maquina admite el desempaquetado dinamico.
pub fn soportado() -> bool {
    confinamiento::seccomp_disponible()
}
