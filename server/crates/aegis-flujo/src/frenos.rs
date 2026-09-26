//! Los cinco frenos de la FASE 69, aplicados a CADA paso que toca la flota.
//!
//! # Por paso, no por flujo
//!
//! Un flujo que aisla una maquina, luego deshabilita una cuenta y luego bloquea
//! un indicador tiene tres decisiones con tres radios distintos. Frenar el
//! flujo entero una vez —al empezar— dejaria pasar el tercer paso con el
//! permiso del primero. Aqui el motor pregunta a los frenos ANTES de cada paso
//! que toca la flota, con los objetivos reales de ese paso.
//!
//! # Los mismos frenos, no unos parecidos
//!
//! `aegis_predict::decidir` los aplica sobre un camino de un grafo. Aqui no hay
//! camino: hay un paso con sus objetivos. Se aplican en el mismo orden y con las
//! MISMAS piezas —[`ConfigContencion`] y sus constantes, [`Evidencia::solida`]—,
//! de modo que un umbral cambiado en la FASE 69 cambia aqui tambien:
//!
//! 1. **Probabilidad** (el freno 4 de `decidir`): la confianza de la deteccion
//!    que dispara el flujo por debajo de la minima, y no se actua.
//! 2. **Radio**: mas objetivos que el tope, o mas de la fraccion de la flota
//!    cuando la flota es grande, y se escala. El radio es el ACUMULADO de la
//!    ejecucion —las entidades distintas que habra tocado el flujo entero con
//!    este paso—, no el del paso suelto: frenar por paso no puede significar que
//!    mil pasos de radio uno sumen un radio de uno.
//! 3. **Activos protegidos**: se preservan —se quitan de los objetivos—; si no
//!    queda ninguno, no se actua.
//! 4. **Evidencia**: si no es solida, se escala.
//! 5. **Minima y reversible**: un paso irreversible sin firma humana se escala
//!    (el compilador ya impide construirlo; esto lo comprueba otra vez en
//!    ejecucion, por si llega por un camino no tipado).

use std::collections::BTreeSet;

use aegis_entidad::Eid;
use aegis_predict::contencion::FLOTA_MINIMA_PARA_FRACCION;
use aegis_predict::grafo::Evidencia;
use aegis_predict::ConfigContencion;

use crate::paso::Reversibilidad;

/// Por que un freno detuvo un paso.
#[derive(Debug, Clone, PartialEq)]
pub enum Motivo {
    /// Confianza por debajo de la minima.
    ProbabilidadBaja {
        /// La confianza.
        confianza: f64,
        /// La minima.
        minima: f64,
    },
    /// Demasiados objetivos.
    RadioDemasiadoGrande {
        /// Objetivos del paso.
        objetivos: usize,
        /// El tope.
        tope: usize,
    },
    /// Todos los objetivos estan protegidos.
    SoloActivosProtegidos,
    /// Algunos objetivos estan protegidos y el efecto del paso no se puede
    /// dividir (bloquear una red corta a todas las maquinas de dentro): se
    /// preservan deteniendo el paso.
    ProtegidosEnElRadio {
        /// Cuantos protegidos habria tocado.
        preservados: usize,
    },
    /// La evidencia no es solida.
    EvidenciaDebil,
    /// Un paso irreversible sin firma.
    IrreversibleSinFirma,
}

impl Motivo {
    /// Frase para el operador.
    #[must_use]
    pub fn frase(&self) -> String {
        match self {
            Motivo::ProbabilidadBaja { confianza, minima } => format!(
                "la deteccion que dispara el flujo tiene confianza {confianza:.2}, por debajo de {minima:.2}"
            ),
            Motivo::RadioDemasiadoGrande { objetivos, tope } => format!(
                "el paso tocaria {objetivos} objetivos y el tope sin una persona es {tope}"
            ),
            Motivo::SoloActivosProtegidos => "todos los objetivos del paso son activos protegidos".into(),
            Motivo::ProtegidosEnElRadio { preservados } => format!(
                "el paso tocaria {preservados} activos protegidos y su efecto no se puede separar de ellos"
            ),
            Motivo::EvidenciaDebil => {
                "la evidencia no es solida (pocas observaciones, un solo observador o demasiado reciente)".into()
            }
            Motivo::IrreversibleSinFirma => "el paso es irreversible y no lleva firma humana".into(),
        }
    }
}

/// Lo que deciden los frenos sobre un paso.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Adelante, con estos objetivos (los protegidos ya fuera).
    Actuar {
        /// Los objetivos que quedan.
        objetivos: Vec<Eid>,
        /// Los protegidos que se preservaron.
        preservados: Vec<Eid>,
    },
    /// Se para y lo decide una persona.
    Escalar(Motivo),
    /// No se actua.
    NoActuar(Motivo),
}

/// Lo que un paso pide a los frenos.
#[derive(Debug, Clone)]
pub struct Solicitud<'a> {
    /// El paso.
    pub paso: &'static str,
    /// Sus objetivos.
    pub objetivos: &'a [Eid],
    /// Cuantas entidades DISTINTAS habra tocado la ejecucion entera, contando
    /// las de este paso. Es lo que mira el freno de radio: ver [`CincoFrenos`].
    pub radio: usize,
    /// Si es reversible.
    pub reversibilidad: Reversibilidad,
    /// Si lleva firma humana.
    pub firmado: bool,
}

/// Algo que decide si un paso puede actuar.
pub trait Frenos: Send + Sync {
    /// Decide sobre un paso.
    fn evaluar(&self, s: &Solicitud<'_>) -> Decision;
}

/// Los cinco frenos, con la configuracion de la contencion (FASE 69).
#[derive(Debug, Clone)]
pub struct CincoFrenos {
    /// Umbrales: los de la FASE 69.
    pub config: ConfigContencion,
    /// Maquinas en la flota, para el tope fraccional.
    pub flota: usize,
    /// Activos que ningun flujo toca sin una persona.
    pub protegidos: BTreeSet<Eid>,
    /// La evidencia de la deteccion que dispara el flujo.
    pub evidencia: Evidencia,
    /// Su confianza, de 0 a 1.
    pub confianza: f64,
}

impl CincoFrenos {
    /// El radio maximo sin una persona: el tope absoluto y, en una flota
    /// grande, tambien el fraccional; manda el menor.
    ///
    /// Para un radio entero `n`, `n > fraccion * flota` equivale a
    /// `n > floor(fraccion * flota)`: es la misma condicion que aplica
    /// `aegis_predict::decidir`, expresada como un tope que se puede ensenar al
    /// operador.
    #[must_use]
    pub fn tope(&self) -> usize {
        if self.flota >= FLOTA_MINIMA_PARA_FRACCION {
            let fraccional = (self.config.max_fraccion_flota * self.flota as f64).floor();
            // Una fraccion no finita o negativa (una configuracion rota) no
            // abre el tope: se queda en cero, que escala todo.
            let fraccional = if fraccional.is_finite() && fraccional >= 0.0 {
                fraccional as usize
            } else {
                0
            };
            self.config.max_activos.min(fraccional)
        } else {
            self.config.max_activos
        }
    }
}

impl Frenos for CincoFrenos {
    fn evaluar(&self, s: &Solicitud<'_>) -> Decision {
        // 1. Probabilidad. Un NaN (una confianza que no se pudo calcular) no
        // es «suficiente»: no se compara como mayor ni como menor, y no actua.
        if !matches!(
            self.confianza.partial_cmp(&self.config.probabilidad_minima),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ) {
            return Decision::NoActuar(Motivo::ProbabilidadBaja {
                confianza: self.confianza,
                minima: self.config.probabilidad_minima,
            });
        }
        // 2. Radio: el tope absoluto y, en una flota grande, el fraccional.
        // El radio es el ACUMULADO de la ejecucion, no el del paso: una
        // plantilla que expande «aislar» en mil pasos de una maquina cada uno
        // pasaria mil veces un freno de radio uno. Nunca menos que el paso.
        let n = s.radio.max(s.objetivos.len());
        if n > self.tope() {
            return Decision::Escalar(Motivo::RadioDemasiadoGrande {
                objetivos: n,
                tope: self.tope(),
            });
        }
        // 3. Protegidos: se preservan.
        let (preservados, objetivos): (Vec<Eid>, Vec<Eid>) = s
            .objetivos
            .iter()
            .cloned()
            .partition(|e| self.protegidos.contains(e));
        if objetivos.is_empty() && !preservados.is_empty() {
            return Decision::NoActuar(Motivo::SoloActivosProtegidos);
        }
        // 4. Evidencia.
        if !self.evidencia.solida() {
            return Decision::Escalar(Motivo::EvidenciaDebil);
        }
        // 5. Minima y reversible.
        if s.reversibilidad == Reversibilidad::Irreversible && !s.firmado {
            return Decision::Escalar(Motivo::IrreversibleSinFirma);
        }
        Decision::Actuar {
            objetivos,
            preservados,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    fn frenos(flota: usize) -> CincoFrenos {
        CincoFrenos {
            config: ConfigContencion::default(),
            flota,
            protegidos: [entidad::maquina("dc-01")].into_iter().collect(),
            evidencia: Evidencia {
                observaciones: 5,
                observadores: 3,
                antiguedad_seg: 2 * 86_400,
            },
            confianza: 0.9,
        }
    }

    fn maquinas(n: usize) -> Vec<Eid> {
        (0..n)
            .map(|i| entidad::maquina(&format!("srv-{i}")))
            .collect()
    }

    fn pedir<'a>(o: &'a [Eid]) -> Solicitud<'a> {
        Solicitud {
            paso: "aislar",
            objetivos: o,
            radio: o.len(),
            reversibilidad: Reversibilidad::Total,
            firmado: false,
        }
    }

    #[test]
    fn aislar_la_flota_entera_se_escala() {
        let f = frenos(1000);
        let o = maquinas(1000);
        assert!(matches!(
            f.evaluar(&pedir(&o)),
            Decision::Escalar(Motivo::RadioDemasiadoGrande { .. })
        ));
        // Treinta maquinas de una flota de mil: por debajo del 5 %, pero por
        // encima del tope absoluto de 25.
        let o = maquinas(30);
        assert!(matches!(
            f.evaluar(&pedir(&o)),
            Decision::Escalar(Motivo::RadioDemasiadoGrande { .. })
        ));
        let o = maquinas(3);
        assert!(matches!(f.evaluar(&pedir(&o)), Decision::Actuar { .. }));
    }

    #[test]
    fn manda_el_menor_de_los_topes() {
        // 5 % de 1000 son 50: manda el absoluto, 25.
        assert_eq!(frenos(1000).tope(), 25);
        // 5 % de 200 son 10: manda el fraccional.
        assert_eq!(frenos(200).tope(), 10);
        let o = maquinas(11);
        assert_eq!(
            frenos(200).evaluar(&pedir(&o)),
            Decision::Escalar(Motivo::RadioDemasiadoGrande {
                objetivos: 11,
                tope: 10
            })
        );
        // Una flota pequena no tiene tope fraccional.
        assert_eq!(frenos(49).tope(), 25);
        // Una configuracion rota no abre el tope.
        let mut f = frenos(1000);
        f.config.max_fraccion_flota = f64::NAN;
        assert_eq!(f.tope(), 0);
    }

    #[test]
    fn el_radio_es_el_acumulado_de_la_ejecucion() {
        let f = frenos(1000);
        let o = maquinas(1);
        let mut s = pedir(&o);
        s.radio = 25;
        assert!(matches!(f.evaluar(&s), Decision::Actuar { .. }));
        // El paso numero 26 de radio uno lleva la ejecucion a 26.
        s.radio = 26;
        assert!(matches!(
            f.evaluar(&s),
            Decision::Escalar(Motivo::RadioDemasiadoGrande { objetivos: 26, .. })
        ));
    }

    #[test]
    fn los_protegidos_se_preservan_y_solo_protegidos_no_actua() {
        let f = frenos(100);
        let mut o = maquinas(2);
        o.push(entidad::maquina("dc-01"));
        let Decision::Actuar {
            objetivos,
            preservados,
        } = f.evaluar(&pedir(&o))
        else {
            panic!()
        };
        assert_eq!(objetivos.len(), 2);
        assert_eq!(preservados, [entidad::maquina("dc-01")]);
        let solo = [entidad::maquina("dc-01")];
        assert_eq!(
            f.evaluar(&pedir(&solo)),
            Decision::NoActuar(Motivo::SoloActivosProtegidos)
        );
    }

    #[test]
    fn confianza_baja_evidencia_debil_e_irreversible_sin_firma() {
        let o = maquinas(1);
        let mut f = frenos(100);
        f.confianza = 0.3;
        assert!(matches!(
            f.evaluar(&pedir(&o)),
            Decision::NoActuar(Motivo::ProbabilidadBaja { .. })
        ));
        f.confianza = f64::NAN;
        assert!(
            matches!(
                f.evaluar(&pedir(&o)),
                Decision::NoActuar(Motivo::ProbabilidadBaja { .. })
            ),
            "un NaN no pasa"
        );
        let mut f = frenos(100);
        f.evidencia.observadores = 1;
        assert_eq!(
            f.evaluar(&pedir(&o)),
            Decision::Escalar(Motivo::EvidenciaDebil)
        );
        let f = frenos(100);
        let mut s = pedir(&o);
        s.reversibilidad = Reversibilidad::Irreversible;
        assert_eq!(
            f.evaluar(&s),
            Decision::Escalar(Motivo::IrreversibleSinFirma)
        );
        s.firmado = true;
        assert!(matches!(f.evaluar(&s), Decision::Actuar { .. }));
    }
}
