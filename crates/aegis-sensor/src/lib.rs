//! # aegis-sensor — telemetria de kernel sin perdida silenciosa y sin carreras (FASE 103)
//!
//! Contra Falco, Tracee y Tetragon, la telemetria de kernel de AegisCore gana en
//! tres cosas que aqui son la parte que DECIDE, y que se prueban sin depender del
//! kernel:
//!
//! 1. **Un sensor que pierde, LO DICE Y LO CUENTA.** La perdida es una cifra POR
//!    FAMILIA que el sensor publica ([`sensor::Sensor::estado`]). Un anillo lleno
//!    produce un `NoConcluyente` de esa familia —un `SinDatos` con su cuenta— al
//!    arbitro, jamas un hueco silencioso. Falco documenta que pierde; casi nadie
//!    MIDE la perdida en la maquina del cliente y la sube como dato de confianza
//!    del veredicto.
//! 2. **Degradacion por presupuesto, visible.** Si el coste sube, se apagan
//!    familias por VALOR ascendente y se DICE cual ([`sensor::Sensor::degradar`]).
//!    Una familia apagada tambien es `SinDatos`: una degradacion silenciosa es una
//!    ceguera que el cliente no sabe que tiene.
//! 3. **Ninguna decision sobre datos que pudieron cambiar.** El [`evento::Evento`]
//!    lleva sus campos capturados EN EL KERNEL en el instante del hecho, y no hay
//!    ninguna operacion que vuelva a leer `/proc` —se verifica por lo que FALTA del
//!    tipo—. Leer `/proc` despues es una carrera, y una carrera en un sensor de
//!    seguridad es una EVASION documentada, no un defecto de calidad.
//!
//! # La frontera: lo que decide aqui, lo que captura el kernel
//!
//! La captura EN VIVO —los programas eBPF con ganchos LSM y tracepoints por
//! familia— vive en `drivers/linux/aegis-bpf`. Este crate es el lado que DECIDE:
//! el modelo de familias, la contabilidad de perdida, la degradacion y la
//! traduccion a `SinDatos`, todo logica pura y comprobada sin red ni kernel. Sobre
//! este entorno, BPF LSM esta activo, asi que la ampliacion de los programas eBPF a
//! familias completas con ganchos LSM se puede ejercer de verdad; ese es el trabajo
//! del siguiente incremento, sobre este modelo.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod evento;
pub mod familia;
pub mod sensor;

pub use evento::Evento;
pub use familia::Familia;
pub use sensor::{EstadoFamilia, Sensor};
