//! # aegis-trabajador
//!
//! El proceso trabajador confinado donde corren TODOS los parsers de bytes no
//! confiables del agente, y el cliente con el que el agente lo usa.
//!
//! # La causa raiz que cierra (FASE 1 del MP-16)
//!
//! Los parsers de entrada hostil —ejecutables PE, ELF y Mach-O, el modelo que
//! extrae rasgos de un fichero, el desensamblador, el emulador— vivian en el
//! mismo proceso que decide. Y el perfil de publicacion compila con
//! `panic = "abort"`: un fichero que hiciera entrar en panico a un parser
//! tumbaba el AGENTE ENTERO, con sus sondas, su triaje y su canal de control.
//! Un atacante que conociera un fallo de lectura en cualquiera de ellos tenia un
//! interruptor para apagar el EDR en esa maquina.
//!
//! # Lo que hay ahora
//!
//! ```text
//!   agente (root, sondas, arbitro)            trabajador (uid propio, sin red,
//!     │                                         sin ficheros, seccomp, cgroup)
//!     │  Peticion{analizador, bytes}  ─────►    Analizadores::analizar
//!     │  ◄─────  Informe{hallazgos} | Fallo
//!     │
//!     └─ plazo por peticion: si no contesta, SIGKILL
//!        si muere: SinDatos con la causa, y se relanza (con freno)
//! ```
//!
//! El trabajador es el mismo binario del agente arrancado con `--trabajador`: un
//! solo artefacto que instalar y firmar. Se confina a si mismo antes de leer un
//! byte ([`confinamiento`]); lo que no se puede quitar a si mismo —el plazo y el
//! techo de su cgroup— se lo pone el agente desde fuera ([`cliente`]).

#![deny(missing_docs)]

pub mod analizadores;
pub mod protocolo;

#[cfg(target_os = "linux")]
pub mod cliente;
#[cfg(target_os = "linux")]
pub mod confinamiento;
#[cfg(target_os = "linux")]
pub mod servidor;

pub use analizadores::{para_ejecutable, Analizador, Analizadores};
#[cfg(target_os = "linux")]
pub use cliente::{ConfigTrabajador, EstadoTrabajador, FalloAnalisis, Trabajador};
pub use protocolo::{Hallazgo, Informe};
