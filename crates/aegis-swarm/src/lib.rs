//! # `aegis-swarm` — AegisSwarm: el enjambre autónomo (FASE 68)
//!
//! ## Qué pasa cuando el plano de control deja de estar
//!
//! Un adversario competente no ataca la flota de frente: **le corta el habla**.
//! Cortar la salida a Internet, o el enlace de una sede, es barato y es lo
//! primero que hace, porque a partir de ahí cada endpoint está solo y la consola
//! no ve nada. Un EDR que dependa por completo de su plano de control queda,
//! exactamente en ese momento, reducido a un antivirus de firmas locales.
//!
//! Esta fase es lo que la flota hace cuando eso ocurre: los agentes se reparten
//! entre ellos indicadores, reglas YARA y órdenes de contención, sin consola.
//!
//! ## La pregunta que decide el diseño entero
//!
//! > Si un agente puede decirle al enjambre «aisla al equipo X», ¿qué consigue
//! > el atacante que comprometa **un** endpoint?
//!
//! Consigue un botón de denegación de servicio sobre toda la organización. Y
//! algo peor: aislar precisamente las máquinas que lo habrían detectado, o el
//! salto del SOC desde el que se responde. Una malla de órdenes mal diseñada no
//! es una defensa, es **movimiento lateral regalado**.
//!
//! La [FASE 23](../../aegis_mesh/index.html) esquivó el problema declarando que
//! una vacuna sólo puede AÑADIR indicadores. Aquí no se puede esquivar, porque
//! el requisito es repartir órdenes. La respuesta es una sola frase:
//!
//! > **El enjambre transporta autoridad; no la concede.**
//!
//! De ahí salen las tres clases de mensaje, con tres reglas de confianza que no
//! se parecen entre sí:
//!
//! | Clase | Quién puede originarla | Qué hace falta para actuar |
//! |---|---|---|
//! | [`orden::Orden`] | **sólo el plano de control** (ningún agente tiene su clave) | firma híbrida válida + época monótona + dentro de su ventana |
//! | [`artefacto::Descriptor`] (reglas YARA, modelos) | **sólo el plano de control** | firma válida del descriptor + hash de cada trozo + hash del conjunto |
//! | [`observacion::Observacion`] | cualquier par, con su identidad de matriculación | **K pares distintos** viendo lo mismo dentro de una ventana ([`quorum`]) |
//!
//! Una observación **no manda nada**: es evidencia. Lo que convierte evidencia
//! en acción es el corroboro, y eso transforma «un endpoint comprometido mueve a
//! la flota» en «hacen falta K endpoints comprometidos».
//!
//! ## Lo que no viaja, con firma o sin ella
//!
//! Levantar un aislamiento, desactivar una regla o degradar la protección son
//! justo los efectos que el atacante busca. Esas órdenes **no se aceptan por el
//! enjambre aunque su firma sea auténtica**: reproducidas en el instante del
//! corte apagan la defensa con una firma buena de verdad. Retirar protección
//! exige el canal directo con el plano de control. Ver [`orden::Accion::gossipable`].
//!
//! Es la doctrina de la FASE 23 —sólo se puede añadir protección, jamás
//! quitarla— llevada de los indicadores a las órdenes.
//!
//! ## Por qué libp2p no está en este crate
//!
//! El backlog pedía integrar una malla *gossip* de libp2p, y está integrada:
//! vive en **`swarm-net/`**, un workspace aparte, y consume este núcleo. No está
//! aquí, y la razón es medible:
//!
//! | | dependencias transitivas | runtime | dónde corre |
//! |---|---|---|---|
//! | este núcleo | **0 nuevas** | ninguno (síncrono) | dentro del agente, en cada endpoint |
//! | libp2p (gossipsub+noise+yamux+tcp+mdns) | **340 crates** | tokio | `swarm-net/`, fuera del agente |
//!
//! El agente corre con privilegios en cada endpoint, tiene un presupuesto de
//! memoria **acotado por clase de host** —48 MiB en reposo en una pasarela— y
//! trata su árbol de dependencias como superficie de ataque.
//! Meterle 340 crates de código **que analiza entrada hostil de la red** es
//! precisamente el riesgo de cadena de suministro que un fabricante de seguridad
//! no puede asumir: es la misma razón por la que la FASE 23 se escribió con UDP
//! y un AEAD auditable en un fichero en vez de con QUIC.
//!
//! La separación no es un rodeo, es lo que hace que esta fase sea **verificable
//! de verdad**: al ser un núcleo *sans-io*, cada ataque —reproducción,
//! inundación, Sybil, envenenamiento de trozos, agotamiento de memoria— se
//! construye entero en una prueba, en vez de quedarse declarado como muro.
//!
//! ## Honestidad de validación
//!
//! | Pieza | Verificable aquí | Cómo |
//! |---|---|---|
//! | Reglas de confianza de las tres clases | **sí** | con claves reales, incluida la híbrida post-cuántica |
//! | Reproducción de una orden antigua y auténtica | **sí** | se emite de verdad y la época la corta |
//! | Una sola máquina comprometida gritando | **sí** | mil observaciones y no mueve nada |
//! | Inundación, duplicados, saltos, memoria | **sí** | construidos contra el núcleo |
//! | Trozo envenenado y trozo que miente el tamaño | **sí** | rechazados al llegar |
//! | Entrada hostil arbitraria | **sí** | barrido determinista; ninguna entrada provoca pánico |
//! | Transporte libp2p | **sí**, en `swarm-net/` | **dos nodos reales** por loopback: Noise, Yamux y gossipsub auténticos; una orden firmada cruza la malla y se aplica en el otro extremo |
//!
//! Esa última fila merece una nota, porque era el sitio natural para declarar un
//! muro y no hizo falta: el transporte **no** se da por bueno porque compile.
//! `swarm-net/tests/malla_viva.rs` levanta dos `Swarm` completos, los conecta de
//! verdad y comprueba las dos mitades del contrato — que una orden legítima
//! cruza y se aplica, y que **una orden de un impostor cruza igual y el núcleo
//! la rechaza**. Esa segunda prueba es la que enseña dónde está la seguridad: no
//! en el transporte, que no juzga nada, sino en el núcleo.
//!
//! Lo único que no se ejerce es el descubrimiento por **mDNS**, que necesita
//! multicast en la red local y un contenedor de CI no tiene; los vecinos se
//! marcan por dirección explícita. Lo que se prueba —difusión, identidad
//! autenticada por Noise, entrega al núcleo— es lo mismo por los dos caminos.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod artefacto;
pub mod enjambre;
pub mod error;
pub mod mensaje;
pub mod observacion;
pub mod orden;
pub mod quorum;

pub use artefacto::{ClaseArtefacto, Descriptor, Reensamblado, Trozo};
pub use enjambre::{
    ConfigEnjambre, Contadores, Enjambre, EstadoEnlace, MotivoDescarte, Salida, SALTOS_POR_DEFECTO,
};
pub use error::ErrorEnjambre;
pub use mensaje::{Sobre, TipoMensaje};
pub use observacion::Observacion;
pub use orden::{Accion, Orden};
pub use quorum::{Corroboro, Veredicto};
