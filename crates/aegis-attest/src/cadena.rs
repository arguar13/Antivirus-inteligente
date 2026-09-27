//! Una sola cadena de linaje: firmware -> arranque -> kernel -> agente -> proceso.
//!
//! Casi todo el mundo tiene esto repartido en varios sistemas que se apuntan entre
//! si: uno mide el firmware, otro el arranque, otro el kernel, y nadie tiene la
//! cadena entera. Aqui es UNA cadena, con un `Eid` del modelo unico por eslabon, y
//! se verifica que es contigua: un hueco —falta el kernel entre el arranque y el
//! agente— es un eslabon roto, y sin la cadena entera no hay confianza que herede
//! el proceso.

use aegis_entidad::Eid;

/// El nivel de un eslabon, de la raiz de confianza al proceso. El orden es el de
/// la cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nivel {
    /// El firmware medido (FASE 92).
    Firmware,
    /// El arranque medido (los PCR del cargador y el kernel).
    ArranqueMedido,
    /// El kernel en ejecucion.
    Kernel,
    /// El agente.
    Agente,
    /// Un proceso vigilado.
    Proceso,
}

impl Nivel {
    /// Los niveles en orden de cadena.
    #[must_use]
    pub fn en_orden() -> [Nivel; 5] {
        [
            Nivel::Firmware,
            Nivel::ArranqueMedido,
            Nivel::Kernel,
            Nivel::Agente,
            Nivel::Proceso,
        ]
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Nivel::Firmware => "firmware",
            Nivel::ArranqueMedido => "arranque-medido",
            Nivel::Kernel => "kernel",
            Nivel::Agente => "agente",
            Nivel::Proceso => "proceso",
        }
    }
}

/// Un eslabon: un nivel y la entidad que lo encarna.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eslabon {
    /// El nivel.
    pub nivel: Nivel,
    /// La entidad, del modelo unico.
    pub eid: Eid,
}

/// La cadena de atestacion.
#[derive(Debug, Clone, Default)]
pub struct CadenaAtestacion {
    eslabones: Vec<Eslabon>,
}

impl CadenaAtestacion {
    /// Una cadena vacia.
    #[must_use]
    pub fn nueva() -> CadenaAtestacion {
        CadenaAtestacion::default()
    }

    /// Anade un eslabon.
    #[must_use]
    pub fn con(mut self, nivel: Nivel, eid: Eid) -> CadenaAtestacion {
        self.eslabones.push(Eslabon { nivel, eid });
        self
    }

    /// Verifica que la cadena es contigua desde `Firmware` hasta el nivel mas alto
    /// presente, sin huecos. Devuelve el primer nivel que FALTA si la cadena esta
    /// rota.
    ///
    /// Un proceso cuyo linaje salta el kernel no hereda una raiz de confianza: hay
    /// un eslabon en el que nadie midio a nadie.
    pub fn verificar(&self) -> Result<(), Nivel> {
        let presentes: std::collections::BTreeSet<Nivel> =
            self.eslabones.iter().map(|e| e.nivel).collect();
        if presentes.is_empty() {
            return Err(Nivel::Firmware);
        }
        // El nivel mas alto presente marca hasta donde tiene que llegar la cadena.
        let mas_alto = *presentes.iter().max().expect("no vacio");
        for nivel in Nivel::en_orden() {
            if nivel > mas_alto {
                break;
            }
            if !presentes.contains(&nivel) {
                return Err(nivel);
            }
        }
        Ok(())
    }

    /// Los eslabones, en el orden en que se anadieron.
    #[must_use]
    pub fn eslabones(&self) -> &[Eslabon] {
        &self.eslabones
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    fn eid(n: u32) -> Eid {
        entidad::contenido(&format!("{n:064x}"))
    }

    #[test]
    fn una_cadena_completa_verifica() {
        let c = CadenaAtestacion::nueva()
            .con(Nivel::Firmware, eid(1))
            .con(Nivel::ArranqueMedido, eid(2))
            .con(Nivel::Kernel, eid(3))
            .con(Nivel::Agente, eid(4))
            .con(Nivel::Proceso, eid(5));
        assert_eq!(c.verificar(), Ok(()));
    }

    #[test]
    fn un_hueco_en_la_cadena_es_un_eslabon_roto() {
        // Falta el kernel entre el arranque y el agente: el proceso no hereda raiz.
        let c = CadenaAtestacion::nueva()
            .con(Nivel::Firmware, eid(1))
            .con(Nivel::ArranqueMedido, eid(2))
            .con(Nivel::Agente, eid(4));
        assert_eq!(c.verificar(), Err(Nivel::Kernel));
    }

    #[test]
    fn una_cadena_que_no_arranca_en_el_firmware_esta_rota() {
        let c = CadenaAtestacion::nueva()
            .con(Nivel::Kernel, eid(3))
            .con(Nivel::Agente, eid(4));
        assert_eq!(c.verificar(), Err(Nivel::Firmware));
    }
}
