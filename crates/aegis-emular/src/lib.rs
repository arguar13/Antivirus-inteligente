//! # aegis-emular — emulacion multiarquitectura y desempaquetado generico (FASE 102)
//!
//! El motor de emulacion del producto, con cuatro propiedades que lo separan de
//! Qiling, Unicorn, unipacker y angr:
//!
//! 1. **La ausencia es la frontera.** El emulador NO TIENE variante de salida al
//!    sistema real. Qiling puede montar el sistema de ficheros del anfitrion; aqui
//!    el [`entorno`] es sintetico, en memoria, y ningun tipo de este crate abre un
//!    fichero, un socket ni una syscall reales. Se verifica por lo que FALTA.
//! 2. **Ejecucion simbolica ACOTADA.** [`simbolico`] resuelve saltos indirectos y
//!    condiciones anti-analisis sin ejecutar, con un presupuesto de estados que es
//!    parte del tipo. angr no acota y por eso explota; aqui la cota es dura.
//! 3. **Desempaquetado GENERICO por observacion**, no por firma de empaquetador
//!    ([`desempaquetado`]): escritura-y-luego-ejecucion, caida de entropia,
//!    transferencia de control a memoria recien escrita. Un empaquetador NUEVO se
//!    desempaqueta sin regla nueva.
//! 4. **Determinismo.** El tiempo, la aleatoriedad y las direcciones son
//!    ARGUMENTOS del estado inicial ([`cpu::Cpu`]); dos emulaciones de la misma
//!    muestra con el mismo estado son iguales.
//!
//! # La MMU con permisos reales
//!
//! [`mmu`] modela paginas con permisos (W^X): una escritura en una pagina de codigo
//! se VE, que es lo que permite el desempaquetado. Un emulador con memoria plana no
//! puede verlo.
//!
//! # Una sola IR
//!
//! La ejecucion simbolica corre sobre `aegis_decompile::ir`, la MISMA IR de la
//! FASE 100. Una sola IR en el producto; dos es la averia que la invariante 10 del
//! MEGAPROMPT 7 existe para impedir.
//!
//! # Alcance por partes, y honesto
//!
//! Este incremento entrega el interprete de x86-64, la MMU, el entorno sintetico,
//! la ejecucion simbolica sobre la IR y el desempaquetado generico. Las otras
//! arquitecturas (x86 de 32, ARM, ARM64, RISC-V) y los modelos de API de sistema
//! completos se anaden en incrementos siguientes, sobre estos mismos cimientos; lo
//! no modelado PARA la emulacion y lo dice, en vez de correr sobre una mentira.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cpu;
pub mod desempaquetado;
pub mod entorno;
pub mod mmu;
pub mod simbolico;

pub use cpu::{emular, Cpu, Detencion, Emulacion};
pub use desempaquetado::{detectar_oep, Observacion, PuntoEntradaOriginal};
pub use entorno::{Entorno, Respuesta};
pub use mmu::{FalloMemoria, Mmu, Permisos};
pub use simbolico::{Abstracto, Evaluador};

/// El resultado de intentar desempaquetar una muestra por emulacion.
#[derive(Debug, Clone)]
pub struct Desempaquetado {
    /// Por que paro la emulacion.
    pub detencion: Detencion,
    /// El OEP detectado, si lo hubo, con su evidencia.
    pub oep: Option<PuntoEntradaOriginal>,
    /// Instrucciones ejecutadas.
    pub instrucciones: u64,
}

/// Emula una muestra buscando el punto de entrada original (desempaquetado
/// generico). Es la operacion que [`aegis-unpacker`](https://docs.rs) consume como
/// cliente.
///
/// `cpu` es el estado inicial (todo explicito, para determinismo); `mmu` la memoria
/// ya cargada con la muestra y sus permisos; `presupuesto` la cota dura de
/// instrucciones.
#[must_use]
pub fn desempaquetar(
    cpu: Cpu,
    mmu: &mut Mmu,
    entorno: &Entorno,
    presupuesto: u64,
) -> Desempaquetado {
    let emu = emular(cpu, mmu, entorno, presupuesto);
    let oep = detectar_oep(&emu.observaciones);
    Desempaquetado {
        detencion: emu.detencion,
        oep,
        instrucciones: emu.instrucciones,
    }
}
