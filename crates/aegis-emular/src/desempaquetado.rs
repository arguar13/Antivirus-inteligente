//! Desempaquetado GENERICO por observacion, no por firma de empaquetador.
//!
//! # Por que generico, y por que gana a unipacker
//!
//! unipacker conoce familias de empaquetadores y las deshace una a una: un
//! empaquetador nuevo lo derrota. Aqui no se reconoce el empaquetador: se observa
//! lo que TODO empaquetador tiene que hacer, sea cual sea:
//!
//! 1. **escribir-y-luego-ejecutar**: descomprime el codigo real a una region y
//!    salta a ella;
//! 2. **caida de entropia**: la region empaquetada es de entropia alta (comprimida
//!    o cifrada) y, al desempaquetarse, cae a la del codigo normal;
//! 3. **transferencia de control a memoria recien escrita**: el salto al punto de
//!    entrada original (OEP) va a una pagina que la propia muestra escribio.
//!
//! Un empaquetador NUEVO se desempaqueta sin regla nueva, porque estas tres cosas
//! son la definicion de empaquetar, no una firma. El OEP se declara con su
//! evidencia: las tres senales que lo sostienen.
//!
//! Este modulo razona sobre OBSERVACIONES que el interprete emite; asi se prueba
//! sin ejecutar nada, con observaciones sinteticas.

/// Una observacion que el interprete emite durante la emulacion.
#[derive(Debug, Clone, PartialEq)]
pub enum Observacion {
    /// Se escribio en una pagina ejecutable (o que luego se hara ejecutable).
    Escritura {
        /// Pagina base escrita.
        pagina: u64,
        /// Entropia de la pagina tras la escritura (bits/byte, 0..8).
        entropia: f64,
    },
    /// El control se transfirio a una direccion (un salto/llamada indirectos, o el
    /// salto final al OEP).
    Transferencia {
        /// A donde salto el control.
        destino: u64,
    },
}

/// El OEP detectado, con la evidencia que lo sostiene.
#[derive(Debug, Clone, PartialEq)]
pub struct PuntoEntradaOriginal {
    /// La direccion del OEP.
    pub direccion: u64,
    /// La pagina fue escrita por la muestra antes de saltar a ella.
    pub escrita_por_la_muestra: bool,
    /// La entropia de la pagina destino cayo respecto a la region empaquetada.
    pub entropia_cayo: bool,
    /// El salto fue a memoria recien escrita (no a la seccion de codigo original).
    pub salto_a_memoria_escrita: bool,
}

impl PuntoEntradaOriginal {
    /// Cuantas de las tres heuristicas lo sostienen.
    #[must_use]
    pub fn heuristicas(&self) -> u8 {
        u8::from(self.escrita_por_la_muestra)
            + u8::from(self.entropia_cayo)
            + u8::from(self.salto_a_memoria_escrita)
    }

    /// Una frase de evidencia para el informe.
    #[must_use]
    pub fn evidencia(&self) -> String {
        format!(
            "OEP en {:#x}: escrita por la muestra={}, entropia cayo={}, salto a memoria escrita={} \
             ({} de 3 heuristicas)",
            self.direccion,
            self.escrita_por_la_muestra,
            self.entropia_cayo,
            self.salto_a_memoria_escrita,
            self.heuristicas()
        )
    }
}

/// El umbral de entropia por encima del cual una region se considera empaquetada
/// (comprimida o cifrada). 7,0 bits/byte es el criterio habitual.
pub const ENTROPIA_EMPAQUETADA: f64 = 7.0;

/// La caida minima de entropia que cuenta como desempaquetado.
pub const CAIDA_MINIMA: f64 = 1.0;

/// Analiza una traza de observaciones y detecta el OEP, si lo hay.
///
/// El OEP es la ultima transferencia de control a una pagina que la muestra
/// escribio. La entropia de esa pagina, comparada con la maxima entropia escrita
/// antes, dice si hubo desempaquetado.
#[must_use]
pub fn detectar_oep(traza: &[Observacion]) -> Option<PuntoEntradaOriginal> {
    // Paginas escritas por la muestra y su entropia tras la ultima escritura.
    let mut escritas: std::collections::BTreeMap<u64, f64> = std::collections::BTreeMap::new();
    // La entropia mas alta que se escribio: la region empaquetada.
    let mut entropia_maxima = 0.0f64;

    let mut oep: Option<PuntoEntradaOriginal> = None;
    for obs in traza {
        match obs {
            Observacion::Escritura { pagina, entropia } => {
                escritas.insert(*pagina, *entropia);
                if *entropia > entropia_maxima {
                    entropia_maxima = *entropia;
                }
            }
            Observacion::Transferencia { destino } => {
                let base = destino & !0xfff;
                let escrita = escritas.contains_key(&base);
                if escrita {
                    let ent_destino = escritas.get(&base).copied().unwrap_or(8.0);
                    let cayo = entropia_maxima >= ENTROPIA_EMPAQUETADA
                        && (entropia_maxima - ent_destino) >= CAIDA_MINIMA;
                    // Se queda con la ULTIMA transferencia a memoria escrita: el
                    // salto final al codigo desempaquetado.
                    oep = Some(PuntoEntradaOriginal {
                        direccion: *destino,
                        escrita_por_la_muestra: true,
                        entropia_cayo: cayo,
                        salto_a_memoria_escrita: true,
                    });
                }
            }
        }
    }
    oep
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_salto_a_memoria_escrita_tras_caer_la_entropia_es_el_oep() {
        // El patron de todo empaquetador: escribe una region de alta entropia
        // (empaquetada), luego escribe el codigo desempaquetado (baja entropia) y
        // salta a el.
        let traza = vec![
            Observacion::Escritura {
                pagina: 0x5000,
                entropia: 7.9,
            }, // empaquetada
            Observacion::Escritura {
                pagina: 0x6000,
                entropia: 5.2,
            }, // desempaquetada
            Observacion::Transferencia { destino: 0x6010 }, // salto al OEP
        ];
        let oep = detectar_oep(&traza).expect("hay OEP");
        assert_eq!(oep.direccion, 0x6010);
        assert!(oep.escrita_por_la_muestra);
        assert!(oep.salto_a_memoria_escrita);
        assert!(oep.entropia_cayo, "la entropia cayo de 7.9 a 5.2");
        assert_eq!(oep.heuristicas(), 3, "las tres heuristicas lo sostienen");
    }

    #[test]
    fn un_salto_a_codigo_original_no_es_oep() {
        // Un programa normal no escribe su propio codigo y salta a el.
        let traza = vec![
            Observacion::Transferencia { destino: 0x401000 }, // seccion de codigo original
        ];
        assert!(detectar_oep(&traza).is_none());
    }

    #[test]
    fn sin_caida_de_entropia_se_detecta_el_salto_pero_no_como_desempaquetado() {
        // Codigo automodificante que no es un empaquetador: escribe y salta, pero
        // sin la region de alta entropia previa. Se detecta el salto a memoria
        // escrita (dos heuristicas), pero la entropia no cayo.
        let traza = vec![
            Observacion::Escritura {
                pagina: 0x6000,
                entropia: 5.0,
            },
            Observacion::Transferencia { destino: 0x6000 },
        ];
        let oep = detectar_oep(&traza).unwrap();
        assert!(!oep.entropia_cayo);
        assert_eq!(oep.heuristicas(), 2);
    }

    #[test]
    fn la_evidencia_nombra_las_tres_heuristicas() {
        let traza = vec![
            Observacion::Escritura {
                pagina: 0x5000,
                entropia: 7.8,
            },
            Observacion::Escritura {
                pagina: 0x6000,
                entropia: 4.0,
            },
            Observacion::Transferencia { destino: 0x6000 },
        ];
        let e = detectar_oep(&traza).unwrap().evidencia();
        assert!(e.contains("OEP en 0x6000"));
        assert!(e.contains("3 de 3"));
    }
}
