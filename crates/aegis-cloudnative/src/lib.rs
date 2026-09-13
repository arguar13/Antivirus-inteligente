//! # `aegis-cloudnative` — AegisCloudNative: frenar el escape de contenedor (FASE 62)
//!
//! ## El riesgo de lo cloud-native
//!
//! En un mundo de contenedores, el limite que importa es el que separa al
//! contenedor del host. Un atacante que compromete un contenedor casi nunca se
//! conforma con el: su objetivo es **escapar** al anfitrion, donde estan los
//! demas contenedores y los secretos. Herramientas como Deepce o Traitor
//! automatizan ese salto. AegisCloudNative vigila las syscalls con las que se da
//! —`setns`, `unshare`, `capset`, `bpf`, `mount` y la escritura de rutas del
//! kernel— y reconoce el patron de escape antes de que se complete.
//!
//! ## Las dos piezas
//!
//! - **El decisor** ([`deteccion`], [`MonitorEscape`]): Rust puro, probado con
//!   secuencias reales de escape y cero mocks. Reconoce la escritura del
//!   `release_agent`/`core_pattern`/`modprobe`, el montaje del disco del host, el
//!   `setns` a un namespace del host, la carga de eBPF desde un contenedor y la
//!   secuencia `unshare(CLONE_NEWUSER)` + `mount`. Solo actua DENTRO de un
//!   contenedor: las mismas syscalls en el host son orquestacion legitima.
//! - **El contrato con el eBPF** ([`eventos`], [`EventoBpf`]): la estructura de
//!   layout fijo que el programa del kernel emite por el ring buffer, con su
//!   tamano verificado en compilacion.
//!
//! ## Honestidad sobre el kernel (el muro)
//!
//! Enganchar esas syscalls de verdad es un programa **eBPF** que corre en el
//! kernel: necesita un kernel con BTF, privilegios y el bytecode cargado (la via
//! del agente, `aegis-agent`). Eso es el muro, y `tools/verificar-cloudnative.sh`
//! lo declara. La DECISION —lo que puede estar mal de forma peligrosa— no
//! necesita kernel: opera sobre eventos y se prueba en cada `make ci`. Es el mismo
//! patron del resto del producto: el transporte eBPF es fino y tonto; toda la
//! inteligencia vive en Rust probado.
//!
//! ## Defensivo
//!
//! AegisCloudNative observa para DELATAR el escape, jamas para facilitarlo.

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

pub mod deteccion;
pub mod eventos;

pub use deteccion::{DeteccionEscape, MonitorEscape, PatronEscape, Severidad};
pub use eventos::{ContextoProceso, EventoBpf, EventoNucleo, Operacion, RutaSensible};

/// AegisCloudNative: el sensor de escape de contenedor. Compone la traduccion de
/// los eventos crudos del eBPF y el decisor de patrones en un solo objeto.
#[derive(Debug, Default)]
pub struct AegisCloudNative {
    monitor: MonitorEscape,
}

impl AegisCloudNative {
    /// Un sensor nuevo, sin estado.
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            monitor: MonitorEscape::nuevo(),
        }
    }

    /// Procesa un evento crudo del ring buffer del eBPF: lo traduce y lo decide.
    ///
    /// Un evento con una operacion desconocida se descarta (devuelve `None`), no
    /// se adivina.
    pub fn observar_bpf(&mut self, crudo: &EventoBpf) -> Option<DeteccionEscape> {
        let ev = EventoNucleo::desde_bpf(crudo)?;
        self.monitor.analizar(&ev)
    }

    /// Procesa un evento ya normalizado.
    pub fn observar(&mut self, ev: &EventoNucleo) -> Option<DeteccionEscape> {
        self.monitor.analizar(ev)
    }

    /// Olvida el estado de un proceso que termino (su PID puede reciclarse).
    pub fn olvidar(&mut self, pid: u32) {
        self.monitor.olvidar(pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventos::CAP_SYS_ADMIN;

    #[test]
    fn el_sensor_decide_sobre_un_evento_crudo_del_ebpf() {
        let mut s = AegisCloudNative::nuevo();
        // Un evento crudo (como lo emitiria el eBPF): escritura de release_agent
        // desde un contenedor.
        let crudo = EventoBpf {
            operacion: Operacion::Escritura.codigo(),
            en_contenedor: 1,
            pid: 7,
            ruta: RutaSensible::ReleaseAgentCgroup.codigo(),
            capacidades: 1 << CAP_SYS_ADMIN,
            flags: 0,
            banderas: 0,
        };
        let d = s.observar_bpf(&crudo).expect("es un escape");
        assert_eq!(d.patron, PatronEscape::ReleaseAgentCgroup);
        assert_eq!(d.severidad, Severidad::Critica);
        assert_eq!(d.pid, 7);
    }
}
