//! AegisEnrich: preguntar a muchas fuentes sin contar lo que no toca.
//!
//! # La regla que define la fase
//!
//! **Consultar por un resumen le dice al proveedor que ese fichero esta en tu
//! red.** No es un efecto secundario de la consulta: es la consulta. Le das
//! informacion que no tenia, gratis, y no se puede retirar.
//!
//! Casi siempre compensa. Pero «casi siempre» es una decision, y una decision que
//! nadie ve no es una decision: es un valor por defecto. De modo que el marco
//! obliga a **declarar** que sale, y el panel se lo enseña al analista **antes** de
//! ejecutar el analizador.
//!
//! # Los modulos, y el problema concreto de cada uno
//!
//! | Modulo | El problema |
//! |---|---|
//! | [`observable`] | Consultar un `10.4.1.7` no puede devolver nada y a cambio dibuja tu direccionamiento interno |
//! | [`exposicion`] | Una descripcion en texto libre se rellena con «consulta reputacion» y no dice nada |
//! | [`salida`] | Una bandera `si sin_salida: no consultes` es opcional, y el analizador que se escriba el mes que viene se la olvida |
//! | [`dictamen`] | Lo que devuelve un analizador lo escribio un tercero por Internet |
//! | [`cache`] | Si «no lo conozco» se guarda tanto como «es malicioso», el malware nuevo te sigue pareciendo desconocido durante meses |
//! | [`tasa`] | Veinte tareas que comprueban «voy por 99 de 100» pasan las veinte |
//! | [`fusion`] | Promediar dos fuentes seguras y contrarias produce un numero que se lee como evidencia debil |
//! | [`analizador`] | Un analizador que elige su propia clase se declara autoritativo |
//! | [`orquesta`] | El orden de las puertas: la de privacidad es la unica irreversible |
//!
//! # Las tres propiedades que hay que poder afirmar
//!
//! 1. **El modo sin salida se cumple por construccion, no por comprobacion.** Un
//!    analizador recibe `Option<&dyn Salida>`; con el modo puesto, `None`. No es
//!    que prometa no salir: es que no se le dio por donde.
//! 2. **«No se consulto» nunca se ve igual que «se consulto y no habia nada».**
//!    Todas las variantes de [`analizador::NoAplicable`] llevan motivo, y el
//!    informe las lleva todas — tambien las de los analizadores que ni siquiera
//!    aceptaban el tipo.
//! 3. **La fusion es determinista y explicable.** El mismo conjunto de dictamenes
//!    da siempre el mismo veredicto llegue en el orden que llegue, y el resultado
//!    trae la regla que decidio, en una frase.
//!
//! # Lo que este crate NO es
//!
//! **No es un cargador de complementos.** Los analizadores viven en el arbol y
//! pasan por revision, igual que el resto del servidor. Un marco que carga codigo
//! de terceros en caliente dentro del plano de control es una superficie de ataque
//! distinta y mucho mayor, y este no lo hace.
//!
//! Y **no es un control de acceso**: la declaracion de exposicion sirve para que la
//! decision sea visible y revisable. Quien impide fisicamente la salida es
//! [`salida`], que esta a proposito separado. Confundir «declarado» con «impedido»
//! es el error clasico de estos marcos, y por eso son dos modulos.
//!
//! # Sobre el reloj
//!
//! Salvo el plazo de ejecucion —que necesita un reloj de verdad para cortar a un
//! analizador colgado—, todo recibe `ahora_ns` como argumento. Es lo que permite
//! probar una caducidad de seis meses en un microsegundo y tener el criterio en la
//! puerta de calidad.

#![forbid(unsafe_code)]

pub mod analizador;
pub mod cache;
pub mod dictamen;
pub mod exposicion;
pub mod fusion;
pub mod locales;
pub mod observable;
pub mod orquesta;
pub mod salida;
pub mod tasa;

pub use analizador::{Analizador, Encargo, Ficha, NoAplicable, Registro};
pub use dictamen::{Clase, Dictamen, Juicio};
pub use exposicion::{Campo, Destino, Exposicion, Jurisdiccion, Retencion};
pub use fusion::{fusionar, Fusion, Veredicto};
pub use locales::{Dga, Listas};
pub use observable::{MotivoRetencion, Observable, Tipo};
pub use orquesta::{Informe, Orquestador, Resultado};
pub use salida::{Modo, Peticion, Salida};
pub use tasa::{Cuota, Limitador};
