//! El presupuesto de exposicion POR CASO: cuanto se ha entregado ya al exterior,
//! acumulado, visible y con tope (FASE 109).
//!
//! La declaracion de exposicion ([`crate::exposicion`]) dice, consulta a consulta,
//! que revela cada una. Pero un caso son muchas consultas, y cada una revela un
//! poco: diez consultas «inofensivas» sobre el mismo incidente pueden dibujarle a
//! un tercero la mitad de tu red sin que ninguna, por si sola, pareciera de mas.
//!
//! Por eso la exposicion se ACUMULA por caso, con un tope. Cuando la siguiente
//! consulta al exterior pasaria del tope, se PARA: no se hace, y se dice. Lo LOCAL
//! —lo que no sale de la organizacion— no cuesta nada y nunca se corta: preguntar
//! dentro no revela nada fuera, asi que no hay motivo para racionarlo. Es la regla
//! «local primero» expresada como economia: lo gratis va primero y sin limite.

use crate::exposicion::{Campo, Destino, Exposicion, Jurisdiccion};

/// El coste de exposicion de un campo que SALE al exterior, en puntos.
fn costo_campo(c: Campo) -> u32 {
    match c {
        // Mandar el fichero entero es entregar, no consultar: lo mas caro.
        Campo::ContenidoDeFichero => 10,
        // Una URL puede llevar identificadores de sesion.
        Campo::UrlCompleta => 5,
        // Confirman presencia en la red.
        Campo::ResumenDeFichero | Campo::DireccionIp | Campo::Dominio => 3,
        // Metadatos y tiempos: menos, pero situan.
        Campo::MetadatosDeFichero | Campo::MomentoDeObservacion => 2,
        // Que eres tu quien pregunta: hace atribuible lo demas.
        Campo::IdentidadDelConsultante => 1,
    }
}

/// El coste de exposicion de una consulta. `Local` no cuesta —no sale de la
/// organizacion—; `Interno` cuesta lo minimo (cruza una frontera interna); y
/// `Externo` cuesta la suma de sus campos, doblada si la jurisdiccion no tiene
/// adecuacion o el tercero comparte lo que recibe.
#[must_use]
pub fn costo(exp: &Exposicion) -> u32 {
    match &exp.destino {
        Destino::Local => 0,
        Destino::Interno { .. } => 1,
        Destino::Externo {
            jurisdiccion,
            retencion,
            ..
        } => {
            let base: u32 = exp.campos.iter().map(|c| costo_campo(*c)).sum();
            let multiplica =
                *jurisdiccion == Jurisdiccion::SinAdecuacion || retencion.se_comparte();
            let bruto = if multiplica {
                base.saturating_mul(2)
            } else {
                base
            };
            // Una consulta externa cuesta al menos 1: el mero hecho de preguntar
            // ya revela que preguntas.
            bruto.max(1)
        }
    }
}

/// Por que no se pudo gastar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rechazo {
    /// Motivo legible, para el panel.
    pub motivo: String,
}

/// El presupuesto de exposicion de un caso.
#[derive(Debug, Clone)]
pub struct PresupuestoCaso {
    caso: String,
    tope: u32,
    gastado: u32,
    detalle: Vec<(String, u32)>,
}

impl PresupuestoCaso {
    /// Un presupuesto para un caso, con su tope de puntos de exposicion externa.
    #[must_use]
    pub fn nuevo(caso: impl Into<String>, tope: u32) -> PresupuestoCaso {
        PresupuestoCaso {
            caso: caso.into(),
            tope,
            gastado: 0,
            detalle: Vec::new(),
        }
    }

    /// Intenta gastar la exposicion de una consulta de `proveedor`.
    ///
    /// Lo local (coste 0) SIEMPRE pasa: no sale nada, no hay nada que racionar.
    /// Lo que sale acumula; si pasaria del tope, se RECHAZA y no se gasta —la
    /// consulta no se hace—. Devuelve el coste aplicado si se acepto.
    pub fn intentar_gastar(&mut self, proveedor: &str, exp: &Exposicion) -> Result<u32, Rechazo> {
        let c = costo(exp);
        if c == 0 {
            // Local: se registra a coste cero y nunca se corta.
            self.detalle.push((proveedor.to_string(), 0));
            return Ok(0);
        }
        let nuevo = self.gastado.saturating_add(c);
        if nuevo > self.tope {
            return Err(Rechazo {
                motivo: format!(
                    "el caso «{}» ya gasto {} de {} puntos de exposicion externa; esta consulta \
                     de «{proveedor}» costaria {c} y pasaria del tope: se para",
                    self.caso, self.gastado, self.tope
                ),
            });
        }
        self.gastado = nuevo;
        self.detalle.push((proveedor.to_string(), c));
        Ok(c)
    }

    /// Cuanto se ha entregado ya al exterior, acumulado.
    #[must_use]
    pub fn gastado(&self) -> u32 {
        self.gastado
    }

    /// El tope.
    #[must_use]
    pub fn tope(&self) -> u32 {
        self.tope
    }

    /// Cuanto queda antes de parar.
    #[must_use]
    pub fn restante(&self) -> u32 {
        self.tope.saturating_sub(self.gastado)
    }

    /// El detalle, consulta a consulta: quien costo cuanto. Es lo que hace el
    /// gasto VISIBLE en el panel.
    #[must_use]
    pub fn detalle(&self) -> &[(String, u32)] {
        &self.detalle
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::exposicion::Retencion;

    fn externo(campos: Vec<Campo>) -> Exposicion {
        Exposicion {
            destino: Destino::Externo {
                proveedor: "reputacion-x".into(),
                jurisdiccion: Jurisdiccion::ConAdecuacion,
                retencion: Retencion::Ninguna,
            },
            campos,
        }
    }

    #[test]
    fn lo_local_nunca_se_corta_y_no_cuesta() {
        let mut p = PresupuestoCaso::nuevo("C-1", 0); // tope cero
        let local = Exposicion::ninguna();
        // Aun con tope cero, lo local pasa siempre: no sale nada.
        for _ in 0..100 {
            assert!(p.intentar_gastar("decompilador", &local).is_ok());
        }
        assert_eq!(p.gastado(), 0);
    }

    #[test]
    fn la_exposicion_externa_acumula_y_se_para_al_exceder() {
        let mut p = PresupuestoCaso::nuevo("C-1", 10);
        // Una IP externa cuesta 3.
        assert_eq!(
            p.intentar_gastar("a", &externo(vec![Campo::DireccionIp])),
            Ok(3)
        );
        assert_eq!(
            p.intentar_gastar("b", &externo(vec![Campo::DireccionIp])),
            Ok(3)
        );
        assert_eq!(p.gastado(), 6);
        // Mandar el contenido (10) pasaria de 10: se para y no se gasta.
        assert!(p
            .intentar_gastar("c", &externo(vec![Campo::ContenidoDeFichero]))
            .is_err());
        assert_eq!(p.gastado(), 6, "una consulta rechazada no gasta");
        // Pero algo que quepa (3, quedan 4) si.
        assert_eq!(
            p.intentar_gastar("d", &externo(vec![Campo::Dominio])),
            Ok(3)
        );
        assert_eq!(p.gastado(), 9);
        assert_eq!(p.restante(), 1);
    }

    #[test]
    fn el_gasto_es_visible_consulta_a_consulta() {
        let mut p = PresupuestoCaso::nuevo("C-1", 100);
        p.intentar_gastar("virustotal", &externo(vec![Campo::ResumenDeFichero]))
            .unwrap();
        p.intentar_gastar("grafo-local", &Exposicion::ninguna())
            .unwrap();
        let d = p.detalle();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0], ("virustotal".to_string(), 3));
        assert_eq!(
            d[1],
            ("grafo-local".to_string(), 0),
            "lo local, a coste cero y visible"
        );
    }

    #[test]
    fn una_jurisdiccion_sin_adecuacion_cuesta_el_doble() {
        let caro = Exposicion {
            destino: Destino::Externo {
                proveedor: "x".into(),
                jurisdiccion: Jurisdiccion::SinAdecuacion,
                retencion: Retencion::Ninguna,
            },
            campos: vec![Campo::DireccionIp], // 3, doblado a 6
        };
        assert_eq!(costo(&caro), 6);
    }
}
