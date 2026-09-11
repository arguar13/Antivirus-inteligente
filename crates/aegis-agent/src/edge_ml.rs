//! Clasificador de comportamiento en el borde (FASE 53).
//!
//! Puentea la telemetria que el agente ya recoge —secuencias de syscalls, el
//! grafo de procesos— al modelo TinyML embebido de `aegis-edgeml`, para emitir un
//! veredicto de aislamiento SIN preguntarle a la nube. La FASE 45 correlaciona en
//! el plano de control, con su latencia y su dependencia de red; esto decide en
//! los milisegundos en que la nube todavia no sabe nada, y sigue funcionando en un
//! endpoint sin salida a internet.
//!
//! El modelo viaja DENTRO del binario del agente (unos pocos KB), asi que no hay
//! fichero externo que un atacante pueda borrar para cegarlo.

use aegis_edgeml::behavior::Traza;
use aegis_edgeml::modelo::{ModeloComportamiento, ModeloError, Prediccion};

/// El motor de inferencia en el borde, cargado una vez al arrancar el agente.
pub struct MotorEdge {
    modelo: ModeloComportamiento,
}

impl MotorEdge {
    /// Carga el modelo embebido. Se hace una vez: la inferencia posterior es
    /// barata y no vuelve a tocar disco ni red.
    pub fn cargar() -> Result<MotorEdge, ModeloError> {
        Ok(MotorEdge {
            modelo: ModeloComportamiento::embebido()?,
        })
    }

    /// Clasifica una ventana de comportamiento y devuelve el veredicto.
    pub fn clasificar(&self, traza: &Traza) -> Result<Prediccion, ModeloError> {
        self.modelo.analizar(traza)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_edgeml::behavior::{CatSyscall, Dag, EventoSyscall};
    use aegis_edgeml::modelo::Veredicto;

    #[test]
    fn el_agente_lleva_el_modelo_embebido_y_clasifica_sin_red() {
        // Que esto cargue prueba que el modelo viaja DENTRO del binario del
        // agente, no en un fichero aparte.
        let motor = MotorEdge::cargar().expect("el modelo embebido debe cargar en el agente");

        // Una rafaga de leer-cifrar-borrar: ransomware, sin preguntar a nadie.
        let mut eventos = Vec::new();
        for _ in 0..150 {
            eventos.push(EventoSyscall::de(CatSyscall::Open));
            eventos.push(EventoSyscall::de(CatSyscall::Read));
            eventos.push(EventoSyscall {
                cat: CatSyscall::Write,
                entropia: Some(0.97),
            });
            eventos.push(EventoSyscall::de(CatSyscall::Unlink));
        }
        let traza = Traza {
            eventos,
            dag: Dag::default(),
            duracion_seg: 0.3,
            ficheros_distintos: 150,
        };
        let p = motor.clasificar(&traza).unwrap();
        assert_eq!(
            p.veredicto,
            Veredicto::Malicioso,
            "el agente aisla el ransomware en el borde (score {:.3})",
            p.score
        );
    }
}
