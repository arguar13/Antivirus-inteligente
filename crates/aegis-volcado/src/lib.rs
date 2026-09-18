//! # `aegis-volcado` — AegisMemForensics: analisis forense de memoria (FASE 86)
//!
//! ## El problema: lo que solo existe en memoria
//!
//! Un implante moderno no deja fichero. Se carga reflexivamente, se inyecta en
//! un proceso legitimo o vive en una region que nadie mapeo desde disco. Cuando
//! el incidente ya ha pasado, lo unico que queda es un volcado de memoria, y ahi
//! esta todo: el codigo que corrio, las cadenas que uso, las conexiones que
//! abrio.
//!
//! Este crate analiza ese volcado. **Inerte, y sin ejecutar nada.**
//!
//! ## La invariante que define este crate: no hay operacion de escritura
//!
//! Un adquiridor de memoria forense lee la memoria de procesos ajenos con
//! privilegios. La diferencia entre esa herramienta y una de ataque no esta en
//! la intencion de quien la use: esta en **que operaciones existen**. Un
//! adquiridor que pudiera escribir seria una primitiva de inyeccion con otro
//! nombre, y la tendria cualquiera que se hiciera con el agente.
//!
//! Por eso [`Lectura`] tiene un metodo, devuelve bytes, y **no hay ningun
//! camino de escritura en todo el crate**: ni `process_vm_writev`, ni
//! `ptrace(POKEDATA)`, ni un `OpenOptions` que pida escritura. No es que este
//! desactivado: es que no esta.
//!
//! Eso se comprueba de la unica forma en que se puede comprobar una ausencia: la
//! puerta `tools/verificar-volcado.sh` busca esos caminos y falla si aparecen.
//! Es la invariante 9 del encargo — «se verifica por lo que FALTA».
//!
//! ## Que se busca, y por que eso
//!
//! Lo que distingue el codigo de un implante del codigo del sistema **no es como
//! es, es de donde viene**. El codigo legitimo llega al espacio de direcciones de
//! una sola forma: lo mapea el cargador desde un fichero que sigue en disco y que
//! se puede volver a leer, comparar y comprobar.
//!
//! Codigo ejecutable en memoria anonima significa que alguien lo escribio ahi en
//! ejecucion. Lo hace un compilador al vuelo y lo hace un cargador reflexivo, y
//! por eso lo que sale de aqui son hechos con su evidencia y no veredictos.
//!
//! ## Lo que este crate NO hace
//!
//! - **No adquiere memoria de un proceso vivo.** Eso exige privilegios y
//!   mecanismos que dependen del sistema, y lo hace `aegis-memhunter` con otras
//!   garantias. Aqui entra una memoria ya volcada.
//! - **No reconstruye las estructuras del nucleo.** Listar procesos a partir de
//!   la memoria fisica es un trabajo distinto —y depende de la version exacta del
//!   nucleo—, y hacerlo a medias produce listas de procesos inventadas.
//! - **No decide.** Quien junta esto con el resto es el arbitro.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod adquirir;
pub mod error;
pub mod hallazgos;
pub mod procesos;
pub mod regiones;
pub mod senal;
pub mod vivo;

pub use adquirir::{EnMemoria, Lectura, Volcado};
pub use error::VolcadoError;
pub use hallazgos::{analizar_memoria, Hallazgo, Informe};
pub use procesos::{Camino, Cruce, Perfil, Proceso, Vistas};
pub use regiones::{leer_mapa, Permisos, Region, Respaldo};
