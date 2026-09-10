//! `AegisQLRunner`: ejecucion de consultas AegisQL contra el estado real del
//! endpoint.
//!
//! El analizador (`aegis-parser`) garantiza que toda consulta que llega aqui es
//! sintacticamente valida, apunta a tablas y columnas que existen, tiene los
//! tipos correctos y lleva un techo de filas. Este crate se ocupa de lo otro:
//! obtener los datos de verdad —de /proc, de la tabla de sockets, del grafo de
//! comportamiento en memoria— y decidir que filas pasan el filtro.
//!
//! # Lo que el ejecutor no puede hacer nunca
//!
//! Corre dentro del agente, con privilegios, en el endpoint de un cliente, y lo
//! dispara texto que escribio alguien en una consola remota:
//!
//!   - **No modifica nada.** Solo lee. La gramatica ya lo impedia; aqui no hay
//!     una sola ruta de escritura que pudiera reintroducirlo.
//!   - **No se cuelga.** Todo recorrido esta acotado por el `LIMIT` de la
//!     consulta y por los limites del propio sistema.
//!   - **No entra en panico.** Un dato que no se puede leer es un valor
//!     ausente, no un fallo.
//!   - **No miente sobre lo que vio.** Si hubo datos inaccesibles, el resultado
//!     lo dice: un analista tiene que poder distinguir "no hay nada" de "no
//!     pude mirar".

/// Valores del endpoint y su comparacion.
pub mod valor;

/// Entropia de Shannon.
pub mod entropia;

/// El ejecutor de consultas.
pub mod ejecutor;
