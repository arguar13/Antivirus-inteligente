//! # aegis-procedencia — la procedencia del propio producto (FASE 108)
//!
//! Es la unica fase que audita al proyecto. Frente a in-toto, SLSA y Sigstore,
//! gana en cuatro cosas, probadas como logica pura:
//!
//! 1. **Construccion reproducible bit a bit** ([`reproducible`]): in-toto
//!    atestigua lo que paso; esto demuestra que se puede REPETIR —dos builds del
//!    mismo commit dan el mismo binario, o se declara por que no—.
//! 2. **La atestacion se verifica EN EL ENDPOINT, antes de aplicar**
//!    ([`verificacion`]): el agente no aplica una actualizacion cuya atestacion no
//!    case con su SBOM y su politica. Esta en el camino critico, no en un informe,
//!    y cada rechazo se registra.
//! 3. **Una sola cadena** de linaje fuente → dependencias → compilador → artefacto
//!    → firma → atestacion → despliegue → medida en el TPM ([`cadena`]), con un
//!    `Eid` por eslabon; un hueco es un eslabon roto.
//! 4. **Transparencia sin depender de nadie** ([`transparencia`]): registro de
//!    solo apendice con pruebas de inclusion y de consistencia (RFC 6962) que el
//!    agente verifica SIN CONEXION. Sigstore depende de un servicio publico; una
//!    flota aislada no puede. Un registro bifurcado —historia reescrita— no supera
//!    la prueba de consistencia.
//!
//! # La frontera
//!
//! Las dos construcciones de verdad, en dos maquinas, las hace
//! `tools/construir-reproducible.sh`; aqui esta la DECISION (mismas huellas ⇒
//! reproducible). La firma hibrida del artefacto la verifica `aegis-update`, que
//! ahora consulta esta puerta ANTES de aplicar.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cadena;
pub mod reproducible;
pub mod transparencia;
pub mod verificacion;

pub use cadena::{CadenaProcedencia, Eslabon};
pub use reproducible::{comparar, huella, HuellaConstruccion, Reproducibilidad};
pub use transparencia::{
    hash_hoja, prueba_consistencia, prueba_inclusion, raiz, verificar_consistencia,
    verificar_inclusion, Hash, RegistroTransparencia,
};
pub use verificacion::{
    verificar_antes_de_aplicar, Atestacion, Bitacora, Decision, PoliticaAplicacion, Sbom,
};
