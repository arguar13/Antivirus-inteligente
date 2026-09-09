//! # aegis-deception
//!
//! Servicios senuelo de red y deteccion de reconocimiento **sin falsos
//! positivos**.
//!
//! # De donde sale esa afirmacion
//!
//! No es una promesa de calibracion: es una propiedad de la construccion. Un
//! detector de intrusiones normal tiene que decidir si un trafico legitimo es
//! sospechoso, y por eso siempre se equivoca en algun caso. Un senuelo invierte
//! el problema: **el servicio no existe**. Ningun usuario, ninguna aplicacion y
//! ningun sistema de monitorizacion tiene motivo para conectar a un puerto que
//! no publica nada, asi que cualquier conexion es no autorizada por definicion.
//!
//! La unica fuente real de ruido son los escaneres autorizados de la propia
//! organizacion, y esos se conocen por direccion: van en la lista de exclusion
//! de [`guard::Guard`], no en una heuristica.
//!
//! # Que se finge y por que se saluda
//!
//! Se levantan senuelos de SSH (22), SMB (445) y RDP (3389) por defecto, que son
//! los tres puertos por los que se mueve lateralmente quien ya esta dentro. Los
//! que tienen saludo de texto lo envian: un escaner que no recibe nada anota
//! "puerto abierto, servicio desconocido" y sigue; uno que recibe un saludo
//! creible anota servicio y version y **vuelve** con un exploit concreto. Esa
//! segunda visita dice que herramientas usa y que vulnerabilidades busca.
//!
//! # Lo que un senuelo nunca hace
//!
//! Tapar un servicio de verdad. Si el 22 lo tiene el `sshd` real, el senuelo no
//! lo toma: dejaria la maquina sin administracion remota. Se informa en
//! [`decoy::DecoyNet::skipped`] y se sigue.
//!
//! # La barandilla
//!
//! El bloqueo automatico solo tiene una forma de fallar catastroficamente:
//! bloquear lo que no debia. La puerta de enlace y las direcciones propias se
//! detectan solas y **no se pueden desactivar**, porque bloquear la puerta de
//! enlace deja la maquina incomunicada, incluido el arreglo de quitar el
//! bloqueo. Ver [`guard`].
//!
//! # Donde se aplica el bloqueo
//!
//! El motor decide, y la aplicacion la hace un [`aegis_scal::NetworkFilter`]. En
//! Linux eso es `nftables` por defecto, y con la caracteristica `xdp` el mismo
//! veredicto baja a XDP, donde el paquete se descarta ANTES de que el stack
//! TCP/IP lo toque: unos 50 ns en vez de microsegundos, y sin poder explotar un
//! fallo del stack, porque nunca llega a el.

#![deny(missing_docs)]

pub mod decoy;
pub mod engine;
pub mod guard;
pub mod sensor;

#[cfg(feature = "xdp")]
pub mod xdp;

pub use decoy::{DecoyConfig, DecoyKind, DecoyNet, Interaction, SkipReason, Skipped, CATALOGO};
pub use engine::{DeceptionConfig, DeceptionEngine, DeceptionStats, Round};
pub use guard::Guard;
pub use sensor::{Alert, AlertKind, ReconSensor, SensorConfig};
