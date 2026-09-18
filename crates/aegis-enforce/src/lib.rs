//! # aegis-enforce
//!
//! Que se **impone** de verdad en esta maquina, y que solo se **observa**.
//!
//! # El problema
//!
//! Un EDR tiene dos modos y se parecen mucho por fuera: mirar y bloquear. Un
//! agente que mira produce alertas; uno que bloquea impide que la cosa ocurra.
//! La diferencia la nota el cliente el dia del incidente, y para entonces ya es
//! tarde para descubrir que el mecanismo de bloqueo nunca llego a engancharse.
//!
//! Eso pasa constantemente y casi siempre en silencio: el kernel no trae BPF
//! LSM compilado, el driver no esta firmado para esta version de Windows, macOS
//! no ha concedido el permiso de *Full Disk Access*, la interfaz de red no
//! admite XDP. En todos esos casos el agente **sigue funcionando**: recoge
//! telemetria, correla, alerta. Y su panel sigue diciendo «protegido».
//!
//! Esa es la mentira que este crate existe para impedir. **Un agente que no
//! puede bloquear no esta protegiendo: esta mirando**, y son dos productos
//! distintos al mismo precio.
//!
//! # Las tres reglas
//!
//! **1. La postura se mide, no se configura.** Lo que declare el fichero de
//! configuracion no dice nada de lo que el kernel de esta maquina acepta. Cada
//! capacidad se sondea aqui, contra el sistema de verdad.
//!
//! **2. Poder observar no cuenta como poder aplicar.** [`Estado::SoloObserva`]
//! existe para eso: un mecanismo que ve pasar la operacion pero no puede negarla
//! es telemetria, y contarlo como aplicacion es lo que produce el informe
//! tranquilizador de una maquina desprotegida.
//!
//! **3. Lo que exige aplicacion falla cerrado.** Ver [`Postura::puede_cumplir`].
//! Una politica que dice «esto no se ejecuta» y se despliega sobre una maquina
//! que no puede impedirlo tiene que rechazarse en el despliegue, no descubrirse
//! en el incidente.
//!
//! # Lo que este crate NO hace
//!
//! No aplica nada: dice **quien puede**. El seccomp y el Landlock los aplica
//! `aegis-sandbox`, el filtro de red `aegis-ips`, y los mecanismos de Windows y
//! macOS sus respectivos backends. Mezclar el que mide con el que aplica es como
//! se acaba teniendo un medidor que informa de lo que deberia pasar.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Las sondas que necesitan llamadas al sistema viven en `aegis-sandbox` y
// `aegis-scal`. Aqui solo hay logica.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod postura;

pub use postura::{Capacidad, Estado, Exigencia, Postura};
