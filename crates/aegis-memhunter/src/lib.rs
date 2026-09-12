//! # `aegis-memhunter` — AegisMemHunter: caza en memoria por VAD y tabla de
//! paginas (FASE 65)
//!
//! ## El problema: el disco ya no es donde vive el malware
//!
//! Cobalt Strike, Brute Ratel y cualquier framework de post-explotacion moderno
//! no dejan fichero. Cargan su modulo **reflexivamente** —lo mapean a mano en
//! memoria anonima, resolviendo importaciones y reubicaciones sin pasar por el
//! cargador del sistema— o hacen **module stomping**: mapean una DLL legitima y
//! sobrescriben su seccion de codigo *ya en memoria*. Un escaneo de disco no ve
//! nada. Un inventario de modulos cargados tampoco: en el *stomping*, el modulo
//! que aparece es real, su fichero en disco esta intacto y su firma es valida.
//!
//! ## La idea: preguntarle al hardware, no al proceso
//!
//! Este modulo no lee la memoria del proceso para compararla con el disco (eso
//! ya lo hace `aegis-evasion::hollow`, y cuesta megabytes por proceso). Pregunta
//! por los **metadatos de la memoria**, que el atacante no controla porque los
//! mantiene el kernel y, en ultima instancia, la MMU:
//!
//! - En Windows, los **VAD** (*Virtual Address Descriptors*): el arbol que
//!   describe cada reserva del espacio de direcciones, con su tipo de respaldo
//!   (`MEM_IMAGE` / `MEM_MAPPED` / `MEM_PRIVATE`) y —esto es lo valioso— la
//!   proteccion **inicial** ademas de la actual.
//! - En Linux, `/proc/<pid>/smaps` (que es `maps` con las metricas por region) y
//!   `/proc/<pid>/pagemap`, que expone **una entrada por pagina de la tabla de
//!   paginas**.
//!
//! ## La deteccion que define esta fase, al bit
//!
//! En `pagemap`, el bit 61 de la entrada de una pagina vale 1 cuando la pagina
//! esta **respaldada por un fichero**. Dentro de una region privada respaldada
//! por fichero —la seccion de codigo de un modulo, `r-xp /usr/lib/libfoo.so`—
//! toda pagina residente deberia tenerlo a 1.
//!
//! Si una pagina de esa region esta presente y tiene el bit 61 a **0**, es que
//! hubo un **copy-on-write**: el kernel sustituyo la pagina del fichero por una
//! copia privada. Y una pagina de CODIGO solo se copia por una razon —alguien la
//! escribio—, asi que **lo que se ejecuta ahi ya no es lo que hay en el fichero**.
//! Eso es *module stomping*, delatado sin leer un solo byte del proceso y sin
//! abrir el fichero de disco para comparar.
//!
//! Los tres estados estan verificados empiricamente contra el kernel, no
//! deducidos de la documentacion (ver `pruebas_vivas` en [`pte`]):
//!
//! | Pagina | bit 61 |
//! |---|---|
//! | anonima privada, escrita | 0 |
//! | respaldada por fichero, solo leida | 1 |
//! | respaldada por fichero, **tras copy-on-write** | **0** |
//!
//! Hay un descuento legitimo que hay que hacer y que esta implementado: la
//! resolucion de **IFUNC** y las reubicaciones en texto (`DT_TEXTREL`) tambien
//! provocan copy-on-write sobre paginas de codigo, en el arranque de casi todo
//! proceso de glibc. Por eso no se reporta "hubo CoW", sino **cuantas** paginas
//! y **que fraccion** de la region: parchear la PLT toca unas pocas; sobrescribir
//! el codigo de un modulo toca la region entera. Ver [`hunter::Politica`].
//!
//! ## Por que no basta con buscar RWX
//!
//! Buscar paginas `RWX` es la deteccion de manual y esta obsoleta desde hace
//! anos: el cargador reflexivo actual mapea `RW`, escribe la carga y llama a
//! `mprotect`/`VirtualProtect` para dejarla `RX`. Cuando el escaner mira, no hay
//! ni una pagina `RWX`. Aqui se cubren los dos casos y el que de verdad importa:
//!
//! - `RWX` sin respaldo en fichero (el clasico).
//! - **Ejecutable y anonimo** aunque no sea escribible (el moderno): codigo que
//!   se ejecuta sin fichero detras. Con una cabecera `MZ`/`ELF` al principio, ya
//!   no es ambiguo: un JIT emite codigo maquina suelto, **no imagenes**.
//! - En Windows, proteccion **inicial** `RW` y actual `RX` sobre memoria
//!   `MEM_PRIVATE`: la firma exacta del cargador reflexivo. Ese dato solo existe
//!   en el VAD; `VirtualQuery` lo devuelve en `AllocationProtect`.
//!
//! ## Honestidad de validacion
//!
//! El **decisor** —clasificar una region, descontar el CoW legitimo, puntuar y
//! no ahogar al analista con los JIT— es logica pura y se prueba entero, con
//! `smaps` y entradas de `pagemap` reales.
//!
//! Y la **captura en vivo** tampoco se finge: en Linux las pruebas construyen las
//! anomalias de verdad **en el propio proceso de prueba** —`mmap` de una region
//! RWX anonima, y un copy-on-write forzado sobre una pagina de codigo respaldada
//! por fichero— y el cazador las encuentra leyendo `/proc/self/smaps` y
//! `/proc/self/pagemap` autenticos. No hay muro en Linux.
//!
//! El muro es **Windows**: `VirtualQueryEx` sobre un proceso ajeno necesita
//! Windows y un manejador con `PROCESS_QUERY_INFORMATION`. Lo que si se verifica
//! aqui, en compilacion, es el **ABI** de `MEMORY_BASIC_INFORMATION` (tamano,
//! desplazamiento de cada campo y valores de las constantes del SDK): un campo
//! desplazado haria que el clasificador leyera una proteccion donde hay un
//! tamano, y eso no se manifiesta como un fallo de compilacion sino como un EDR
//! que no ve nada. Ver [`vad::windows`].

#![deny(missing_docs)]

pub mod hunter;
pub mod pte;
pub mod vad;

pub use hunter::{AegisMemHunter, Anomalia, ClaseAnomalia, Informe, Politica, Severidad};
pub use pte::{EntradaPagina, MapaPaginas};
pub use vad::{Proteccion, RegionVad, Respaldo};

/// Error del cazador de memoria.
#[derive(Debug, thiserror::Error)]
pub enum MemHunterError {
    /// No se pudo leer un fichero de `/proc`.
    #[error("no se pudo leer {ruta}: {causa}")]
    Lectura {
        /// Ruta que se intentaba leer.
        ruta: String,
        /// Causa subyacente.
        #[source]
        causa: std::io::Error,
    },

    /// Una linea de `maps`/`smaps` no tiene el formato esperado.
    ///
    /// Se distingue de un error de E/S a proposito: si el formato de `/proc`
    /// cambiara en un kernel futuro, el cazador tiene que DECIRLO en vez de
    /// devolver cero anomalias, que se leeria como "esta maquina esta limpia".
    #[error("formato inesperado en {fichero}, linea {linea}: {detalle}")]
    Formato {
        /// Fichero de origen.
        fichero: &'static str,
        /// Numero de linea (base 1).
        linea: usize,
        /// Que no encajaba.
        detalle: String,
    },

    /// El proceso ya no existe.
    #[error("el proceso {pid} ya no existe")]
    ProcesoMuerto {
        /// PID consultado.
        pid: i32,
    },
}
