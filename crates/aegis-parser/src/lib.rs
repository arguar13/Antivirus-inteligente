//! AegisQL: el lenguaje de consulta de telemetria de AegisCore.
//!
//! Permite a un analista del SOC preguntar a toda la flota a la vez cosas como
//! «que procesos tienen una conexion al puerto 4444 y region de memoria con
//! entropia alta», y recibir la respuesta agregada en segundos.
//!
//! ```text
//! SELECT pid, path, sha256 FROM processes
//!  WHERE network.port = 4444 AND memory.entropy > 7.0
//!  ORDER BY memory.entropy DESC
//!  LIMIT 50
//! ```
//!
//! # Tres invariantes que el lenguaje impone POR CONSTRUCCION
//!
//! Una consulta escrita en la consola se difunde a decenas de miles de
//! endpoints de un cliente. Eso convierte al lenguaje en superficie de ataque y
//! en riesgo operativo a la vez, asi que las garantias no pueden depender de
//! comprobaciones en tiempo de ejecucion que alguien pueda olvidar:
//!
//! 1. **Es de solo lectura.** No hay `INSERT`, `UPDATE`, `DELETE` ni forma de
//!    invocar codigo. La gramatica sencillamente no puede expresar una
//!    modificacion, asi que no hay nada que validar ni nada que se escape.
//! 2. **Su coste es acotable.** No hay `JOIN` ni bucles: el trabajo maximo de
//!    cualquier consulta es «filas de la tabla por tamano de la coleccion
//!    asociada», y las dos cosas tienen limite. Ver [`esquema`].
//! 3. **Se valida antes de salir de la consola.** Tablas, columnas y tipos se
//!    comprueban al analizar. Un error de tecleo se ve en la consola, no se
//!    convierte en diez mil fallos remotos.

/// Arbol sintactico.
pub mod ast;
/// Errores con posicion dentro de la consulta.
pub mod error;
/// Descripcion de tablas, columnas, tipos y coste de acceso.
pub mod esquema;
/// Analisis lexico.
pub mod lexico;
/// Planificacion por coste de acceso.
pub mod plan;
/// Analisis sintactico y semantico.
pub mod sintaxis;
