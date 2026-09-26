//! # `aegis-confinar` — AegisConfine: confinamiento derivado del comportamiento
//! (FASE 93)
//!
//! ## El inventario, antes de escribir nada
//!
//! Lo que el producto sabia confinar al empezar esta fase:
//!
//! | Pieza | Que hace | Que le falta para ser confinamiento de verdad |
//! |---|---|---|
//! | `aegis-sandbox` | seccomp como lista NEGRA por familias y Landlock como lista blanca de rutas, aplicados entre `fork` y `exec` | las politicas son dos y estan escritas a mano (`untrusted_binary`, `agent_helper`): no saben nada del programa concreto |
//! | `aegis-enforce` | mide que se puede imponer en esta maquina | mide, no confina |
//! | la jaula de detonacion | microVM para muestras | es para analizar muestras en el plano de control, no para correr un servicio |
//!
//! Y lo que hay fuera, que es con lo que se compite:
//!
//! | Mecanismo | Como nace la politica | Que pasa si rompe algo |
//! |---|---|---|
//! | SELinux | la escribe una persona (con `audit2allow` como ayuda sobre las denegaciones) | el servicio falla hasta que alguien la corrija; la salida habitual es `setenforce 0` en toda la maquina |
//! | AppArmor | la escribe una persona, o `aa-genprof`/`aa-logprof` la proponen desde el modo *complain* y una persona acepta regla a regla | igual: falla hasta que alguien intervenga |
//! | gVisor | no hay politica por programa: un nucleo en espacio de usuario media todas las llamadas | frontera mucho mas fuerte, a cambio de compatibilidad y rendimiento; confina contenedores, no un proceso cualquiera del endpoint |
//! | Kata | no hay politica: una maquina virtual por contenedor | frontera de hipervisor; mismo ambito que gVisor |
//!
//! Lo que ninguno hace de punta a punta —y es lo que esta fase construye— es el
//! ciclo entero sin una persona en cada vuelta: **aprender** del programa real,
//! **ensayar** sin romper nada, **imponer** solo con una confirmacion explicita, y
//! **retirarse solo** si rompe la produccion.
//!
//! ## Los modulos
//!
//! | Modulo | Que resuelve |
//! |---|---|
//! | [`objetivo`] | a quien se puede confinar y, sobre todo, a quien NO: el propio agente, `init` y los activos protegidos no son confinables por construccion |
//! | [`observacion`] | de una llamada suspendida a un hecho: que fichero, que familia de red, que puerto, que capacidad |
//! | [`perfil`] | el perfil como TIPO: llamadas, familias, rutas generalizadas y capacidades, con su traduccion escrita y comprobada |
//! | [`modo`] | los tres modos, con el mas suave por defecto y el obligatorio imposible de construir sin confirmacion |
//! | [`compilar`] | del perfil y el modo al filtro de seccomp, las reglas de Landlock y la mascara de capacidades |
//! | [`supervision`] | aprender y ensayar sobre un proceso real, con la escucha de seccomp |
//! | [`despliegue`] | el ciclo de vida y la reversion automatica, pegajosa |
//! | [`aislamiento`] | cuando un proceso es de riesgo tal que lo que toca es la microVM, no un perfil |
//! | [`senal`] | la desviacion del perfil aprendido, al arbitro |
//!
//! ## La regla que gobierna el crate: el confinamiento no rompe al cliente
//!
//! Un confinamiento que rompe la produccion del cliente y no se retira es peor
//! que no tenerlo: el cliente lo quita de toda la flota a la semana y se queda
//! sin nada. Por eso, en este orden:
//!
//! 1. El modo por defecto es **aprender**, que no bloquea nada.
//! 2. Despues se **ensaya** en permisivo: se deja pasar todo y se anota lo que se
//!    habria bloqueado.
//! 3. El modo **obligatorio** no se puede construir sin una [`modo::Confirmacion`]
//!    con autor y motivo: el tipo no tiene otra forma de crearlo.
//! 4. Si con el perfil impuesto el proceso falla o se reinicia de mas, el perfil
//!    se **retira solo** y se avisa, y no vuelve sin una confirmacion nueva.
//!
//! Todo el `unsafe` —`fork`, la escucha de seccomp, `pidfd_getfd`, Landlock,
//! `PR_CAPBSET_DROP`— vive en `aegis-sandbox`, que es el crate de FFI declarado.
//! Aqui solo se decide.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aislamiento;
pub mod compilar;
pub mod despliegue;
pub mod modo;
pub mod objetivo;
pub mod observacion;
pub mod perfil;
pub mod senal;
pub mod supervision;

pub use despliegue::{Despliegue, Estado};
pub use modo::{Confirmacion, Modo};
pub use objetivo::{ActivosProtegidos, ObjetivoConfinable, Rechazo};
pub use perfil::Perfil;
