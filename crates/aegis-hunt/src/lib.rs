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

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. No es una declaracion de
// intenciones: `forbid` no se puede levantar desde dentro ni con un `allow`, asi
// que el dia que alguien optimice un bucle con un puntero crudo, no compila.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita. Un
// crate que se cuele sin ninguna de las dos hace fallar
// `tools/verificar-invariantes.sh`.
#![forbid(unsafe_code)]

/// Valores del endpoint y su comparacion.
///
/// Vive en `aegis-parser` desde la FASE 81. El motivo es de direccion de
/// dependencias: los valores ya no los produce solo este crate, sino los
/// sesenta y cinco proveedores de `aegis-estado`, que son quienes leen el
/// sistema. Si `Valor` se hubiera quedado aqui, el proveedor tendria que
/// depender del ejecutor que lo llama. Se reexporta para que
/// `aegis_hunt::valor::Valor` siga siendo el mismo tipo de siempre.
pub use aegis_parser::valor;

/// Entropia de Shannon.
pub mod entropia;

/// El ejecutor de consultas.
pub mod ejecutor;

/// El lado del endpoint: recibir, ejecutar y responder cacerias.
pub mod agente;
