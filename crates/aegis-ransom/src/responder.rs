//! Ejecutor de contencion sobre el motor de respuesta real.

use aegis_resp::kill::{KillOptions, ProcOutcome};
use aegis_resp::kill_process_tree;

use crate::engine::{ContainmentOutcome, Responder};

/// Contencion mediante terminacion del arbol de procesos.
#[derive(Debug, Clone)]
pub struct KillResponder {
    /// Opciones de terminacion.
    pub options: KillOptions,
}

impl Default for KillResponder {
    fn default() -> Self {
        Self {
            options: KillOptions {
                // SIN periodo de gracia. Ante ransomware activo, cada
                // milisegundo de cortesia son ficheros cifrados, y un cifrador
                // no va a aprovechar SIGTERM para cerrar nada ordenadamente.
                immediate: true,
                ..Default::default()
            },
        }
    }
}

impl Responder for KillResponder {
    fn contain(&self, pid: u32) -> ContainmentOutcome {
        match kill_process_tree(pid as i32, &self.options) {
            Ok(informe) => {
                let terminados = informe.killed();
                if informe.complete() {
                    ContainmentOutcome::Killed {
                        processes: terminados,
                    }
                } else {
                    // Se reporta el fallo parcial en vez de declarar exito: un
                    // superviviente de un arbol de ransomware sigue cifrando.
                    let supervivientes: Vec<String> = informe
                        .outcomes
                        .iter()
                        .filter(|(_, o)| matches!(o, ProcOutcome::Survived { .. }))
                        .map(|(p, o)| format!("{} ({}): {:?}", p.pid, p.comm, o))
                        .collect();
                    ContainmentOutcome::Failed {
                        reason: format!(
                            "{terminados} terminados pero quedan supervivientes: {}",
                            supervivientes.join(", ")
                        ),
                    }
                }
            }
            Err(e) => ContainmentOutcome::Failed {
                reason: e.to_string(),
            },
        }
    }
}
