//! La bomba: mueve el diario hacia el destino sin perder nada.
//!
//! # El orden importa y es el unico que funciona
//!
//! ```text
//! leer del diario  ->  entregar  ->  esperar el acuse  ->  confirmar
//! ```
//!
//! Cada flecha se puede romper. Lo que hace que ninguna rotura pierda nada es
//! que **confirmar es lo ultimo**:
//!
//! - Si el proceso muere despues de leer, el registro sigue en disco.
//! - Si muere despues de entregar pero antes de confirmar, el registro sigue en
//!   disco y se reenvia. El destino lo vera dos veces.
//! - Si muere despues de confirmar, ya estaba entregado.
//!
//! Confirmar ANTES de entregar convertiria «al menos una vez» en «como mucho
//! una vez»: exactamente lo contrario de lo que hace falta en auditoria, y de
//! una forma que no se nota hasta que alguien busca la evidencia y no esta.
//!
//! # Que se le pide a quien integra
//!
//! Duplicados. Cada registro lleva su identificador de evento; el SIEM
//! desduplica por el. Se dice aqui, en la documentacion, y no se esconde: un
//! duplicado que el integrador no espera acaba contando dos veces un incidente
//! en un informe de cumplimiento.

use crate::destino::Destino;
use crate::diario::{Diario, Posicion};
use crate::error::Resultado;
use crate::reintento::{Politica, Reintento};

/// Cuantos registros se llevan por lote.
///
/// Un lote grande amortiza los viajes de red; uno demasiado grande retiene
/// evidencia en disco mas tiempo del necesario y, cuando falla, obliga a
/// reenviarlo entero.
pub const LOTE_POR_DEFECTO: usize = 256;

/// Resultado de una vuelta de la bomba.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vuelta {
    /// Registros entregados y confirmados.
    pub entregados: usize,
    /// Si el destino fallo en esta vuelta.
    pub fallo: bool,
    /// Cuanto conviene esperar antes de reintentar.
    pub espera: std::time::Duration,
}

/// Mueve registros del diario al destino.
pub struct Bomba<D: Destino> {
    destino: D,
    reintento: Reintento,
    lote: usize,
    /// Donde seguir leyendo. `None` = por el principio.
    ///
    /// Es la posicion del registro SIGUIENTE al ultimo confirmado, no la del
    /// ultimo confirmado: apuntar al confirmado lo reenviaria en cada vuelta.
    reanudar: Option<Posicion>,
    entregados: u64,
    fallos: u64,
}

impl<D: Destino> Bomba<D> {
    /// Crea la bomba con la politica de reintento dada.
    pub fn nueva(destino: D, politica: Politica) -> Bomba<D> {
        Bomba {
            destino,
            reintento: Reintento::nuevo(politica),
            lote: LOTE_POR_DEFECTO,
            reanudar: None,
            entregados: 0,
            fallos: 0,
        }
    }

    /// Cambia el tamano de lote.
    pub fn con_lote(mut self, lote: usize) -> Bomba<D> {
        self.lote = lote.max(1);
        self
    }

    /// Registros entregados y confirmados desde que arranco.
    pub fn entregados(&self) -> u64 {
        self.entregados
    }

    /// Fallos de entrega acumulados.
    pub fn fallos(&self) -> u64 {
        self.fallos
    }

    /// Una vuelta: lee, entrega, y solo entonces confirma.
    ///
    /// `enmarcar` traduce el registro del diario al formato del destino. Va
    /// aparte porque el diario guarda la carga tal cual la produjo el plano de
    /// control: el marcado de syslog o la clave de Kafka son cosa del destino,
    /// y meterlos en disco ataria la evidencia ya escrita al destino que
    /// estuviera configurado ese dia.
    pub fn vuelta(
        &mut self,
        diario: &mut Diario,
        enmarcar: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> Resultado<Vuelta> {
        // El diario borra por segmentos ENTEROS, asi que tras confirmar puede
        // quedar en disco la cola del segmento activo. Se sigue por donde
        // termino el ultimo confirmado, no por el principio del directorio.
        let pendientes = diario.leer_desde(self.reanudar, self.lote)?;
        if pendientes.is_empty() {
            return Ok(Vuelta::default());
        }

        let marcos: Vec<Vec<u8>> = pendientes.iter().map(|r| enmarcar(&r.carga)).collect();
        let refs: Vec<&[u8]> = marcos.iter().map(|m| m.as_slice()).collect();

        match self.destino.entregar(&refs) {
            Ok(()) => {
                self.reintento.exito();
                // CONFIRMAR ES LO ULTIMO. Ver el comentario del modulo.
                let ultimo = &pendientes[pendientes.len() - 1];
                diario.confirmar_hasta(ultimo.posicion)?;
                self.reanudar = Some(ultimo.siguiente);
                self.entregados += pendientes.len() as u64;
                Ok(Vuelta {
                    entregados: pendientes.len(),
                    fallo: false,
                    espera: std::time::Duration::ZERO,
                })
            }
            Err(_) => {
                // Nada se confirma. El lote entero se reintentara: puede
                // producir duplicados en el destino y esa es la eleccion
                // deliberada, porque la alternativa es perder auditoria.
                self.destino.reiniciar();
                self.fallos += 1;
                Ok(Vuelta {
                    entregados: 0,
                    fallo: true,
                    espera: self.reintento.fallo(),
                })
            }
        }
    }

    /// Acceso al destino, para las metricas.
    pub fn destino(&self) -> &D {
        &self.destino
    }
}
