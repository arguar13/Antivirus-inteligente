//! AegisPostura: la postura de la nube, reconstruida de los eventos que el
//! producto ya ingiere.
//!
//! # La pregunta
//!
//! «¿Que hay mal configurado en el plano de control de mis nubes?»: identidades
//! con privilegio de administrador, almacenamiento publico, claves que no se
//! rotan, registro de auditoria apagado, puertos de administracion abiertos a
//! Internet. Es la pregunta de un CSPM, y la herramienta de referencia para
//! contestarla es Prowler.
//!
//! # Lo que se hace distinto, y lo que se pierde
//!
//! Prowler pregunta a la API de configuracion de cada nube, en vivo, con
//! credenciales de lectura y cientos de comprobaciones. Ve el estado AUNQUE no
//! haya ningun evento: un cubo que se hizo publico hace dos años sale igual que
//! uno de ayer. Eso lo hace mejor, y se dice primero.
//!
//! Este crate no tiene credenciales en la nube del cliente ni las quiere —son
//! justo el activo que busca un atacante—. Reconstruye el estado de los
//! registros de auditoria que `aegis-pipeline` **ya** normaliza (CloudTrail,
//! Azure Activity, GCP Audit), y gana tres cosas:
//!
//! 1. **Cada hallazgo cita el evento exacto** que lo sostiene —su
//!    [`Evento::id`](aegis_ingest::esquema::Evento::id)—, con quien, cuando y
//!    desde donde. No «el cubo es publico» sino «lo hizo publico `ana` a las
//!    10:14 con esta llamada».
//! 2. **Cada hallazgo recae sobre una entidad del modelo unico**
//!    ([`aegis_entidad::Eid`]): la identidad a la que se concedio el rol es la
//!    misma `Cuenta` que ve ITDR, y el recurso una `Ubicacion` estable.
//! 3. **Lo que no se observo se dice**: [`Estado::SinDatos`] con su motivo,
//!    nunca un verde por defecto. Ver EL MURO en [`estado`].
//!
//! # Exposicion no es compromiso, y que llega al arbitro
//!
//! Igual que en `aegis-fwaudit`, cada comprobacion lleva su
//! [`Naturaleza`]: un cubo publico es una puerta abierta (exposicion); apagar
//! el registro de auditoria y, con el apagado, crear claves o conceder roles es
//! alguien dentro (compromiso, `AEGIS-NUBE-LOG-002`).
//!
//! **Este crate no produce ninguna [`Senal`](aegis_entidad::Senal) para el
//! arbitro**, y la decision se explica porque es la que un integrador
//! preguntara:
//!
//! - **Las exposiciones no pueden mover el juicio**, por la razon de
//!   `aegis-fwaudit::senal`: media cuenta mal configurada no es media cuenta
//!   comprometida, y un arbitro que lo creyera enseñaria al analista a ignorar
//!   la nube entera. Van al informe de postura. Esto no es una decision de esta
//!   fase: es el criterio de la casa.
//! - **El compromiso si podria**, pero no hay motor que lo firme. La lista de
//!   [`Motor`](aegis_entidad::Motor) es cerrada y hay pruebas que fijan su
//!   cuenta; añadir `postura` no es de esta fase. Firmarlo como `Motor::Itdr`
//!   —el plano correcto, identidad, con tope 85— seria mentir en el censo de
//!   `aegis_tejido::inventario`, cuya fila de `Itdr` dice que ese motor es el
//!   crate `aegis-itdr`: el dia que un analista pregunte «¿que motor lo dijo?»,
//!   la respuesta seria falsa.
//!
//! Asi que el compromiso sale en [`Informe::compromisos`], con su evidencia y
//! su entidad (la cuenta que apago el registro), para que respuesta a
//! incidentes lo consuma; y el camino al arbitro queda escrito como pendiente
//! de una decision de motor, no improvisado.
//!
//! # Los modulos
//!
//! | Modulo | Que resuelve |
//! |---|---|
//! | [`entrada`] | Que se puede leer de un evento, del crudo o del aplanado, y que no |
//! | [`politica`] | Si un documento de politica de AWS concede todo o es publico |
//! | [`estado`] | El pliegue de eventos en estado, y EL MURO |
//! | [`credenciales`] | El informe de credenciales de IAM como fuente de antiguedad de claves |
//! | [`informe`] | Agregado por proveedor y cobertura |
//! | [`modelo`] | Tri-estado, evidencia, naturaleza y catalogo |
//! | [`salida`] | El unico camino por el que un inventario de componentes (SBOM) sale del producto: CycloneDX y SPDX, detras del juez de difusion |

#![forbid(unsafe_code)]

pub mod credenciales;
pub mod entrada;
pub mod estado;
pub mod informe;
pub mod modelo;
pub mod politica;
pub mod salida;

pub use estado::EstadoNube;
pub use informe::{Cobertura, CoberturaProveedor, Comprobacion, Informe};
pub use modelo::{
    Definicion, Estado, Evidencia, Naturaleza, Proveedor, Referencia, Resultado, CATALOGO,
};

use aegis_ingest::esquema::Evento;

/// Evalua la postura de una ventana de eventos de nube.
///
/// Atajo de [`Informe::evaluar`]. `ahora_ns` es la referencia para la
/// antiguedad de las claves y la pone quien llama.
#[must_use]
pub fn evaluar(eventos: &[Evento], ahora_ns: u64) -> Informe {
    Informe::evaluar(eventos, ahora_ns)
}
