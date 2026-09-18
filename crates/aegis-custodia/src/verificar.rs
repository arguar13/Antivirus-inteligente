//! El veredicto, con lo que prueba y —sobre todo— lo que no.
//!
//! # Por que un booleano no vale
//!
//! «Custodia verificada: SI» es una frase peligrosa, porque quien la lee
//! entiende mas de lo que dice. Entiende que la evidencia es autentica, que
//! nadie la toco, que la maquina estaba limpia y que la cronologia es correcta.
//! La verificacion criptografica no prueba ninguna de esas cuatro cosas enteras,
//! y una herramienta forense que deje entenderlas esta induciendo a error aunque
//! cada bit de su comprobacion sea correcto.
//!
//! En un informe de incidente eso no es un matiz academico. Es la diferencia
//! entre un analista que sabe que le falta un dato y uno que cree tenerlo.
//!
//! Por eso [`Veredicto`] lleva [`Veredicto::no_demuestra`]: la lista explicita,
//! en la propia estructura de datos y no en una nota al pie de la documentacion,
//! de lo que queda fuera. Quien genere un informe a partir de esto tiene que
//! pasar por ella.

use crate::cadena::{CadenaDeCustodia, Paso, RegistroDeClaves};
use crate::error::CustodiaError;
use crate::sello::Sello;

/// Algo que esta verificacion NO establece.
///
/// No son fallos: son los limites del metodo. Aparecen incluso en un veredicto
/// perfecto, porque un veredicto perfecto tambien los tiene.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiteDeLaPrueba {
    /// La firma prueba que firmo esa clave, no que la tuviera quien debia.
    ///
    /// Una clave robada de un endpoint comprometido firma evidencia perfecta.
    /// Lo que acota este riesgo esta fuera de aqui: claves de vida corta que
    /// nunca tocan el disco (`aegis-fleet`) y revocacion.
    ClaveNoEsPersona,

    /// Que la recogida sea autentica no dice que la maquina fuera de fiar.
    ///
    /// Un rootkit en el endpoint puede haber alterado lo que el agente VIO antes
    /// de que el agente lo sellara. El sello cubre desde la recogida hacia
    /// adelante; lo de antes lo cubre la verificacion cruzada del kernel
    /// (`aegis-kintegrity`), que es otra prueba y puede no haberse hecho.
    NoCubreLoAnteriorALaRecogida,

    /// Podar la cadena por el final no lo detecta el encadenado.
    ///
    /// Un prefijo de una cadena valida es una cadena valida. Ninguna cadena
    /// puede detectarlo por si sola. Lo detecta la copia que conserva la
    /// contraparte que firmo el eslabon podado, que es por lo que la custodia se
    /// lleva por los dos lados.
    ElFinalSePuedePodar,

    /// La cronologia depende de un reloj que se puede mover.
    ///
    /// Solo aparece cuando NO se pudo descartar: si las marcas son comparables y
    /// coherentes, este limite no se lista, y si son comparables e incoherentes
    /// se lista el salto concreto en [`Veredicto::saltos_de_reloj`].
    LaCronologiaNoEsComprobable,

    /// Que lo recogido sea autentico no dice que se recogiera todo.
    ///
    /// Lo que el agente no pudo leer no esta aqui: esta en los huecos que anota
    /// la recogida (`aegis_forensics::collect`). Una evidencia integra de una
    /// recogida incompleta sigue siendo una recogida incompleta.
    NoDiceQueSeRecogieraTodo,
}

impl LimiteDeLaPrueba {
    /// La frase con la que aparece en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            LimiteDeLaPrueba::ClaveNoEsPersona => {
                "prueba que firmo esa clave, no que la tuviera quien debia: una \
                 clave robada firma evidencia valida"
            }
            LimiteDeLaPrueba::NoCubreLoAnteriorALaRecogida => {
                "cubre desde la recogida en adelante: no dice que lo que el \
                 agente vio en la maquina no estuviera ya manipulado"
            }
            LimiteDeLaPrueba::ElFinalSePuedePodar => {
                "un prefijo de una cadena valida tambien verifica: que falte un \
                 paso del final solo lo delata la copia de la contraparte"
            }
            LimiteDeLaPrueba::LaCronologiaNoEsComprobable => {
                "las marcas no se pudieron contrastar entre si, asi que la \
                 cronologia se apoya en un reloj que se puede mover"
            }
            LimiteDeLaPrueba::NoDiceQueSeRecogieraTodo => {
                "dice que lo recogido esta intacto, no que se recogiera todo: lo \
                 que no se pudo leer esta en los huecos de la recogida"
            }
        }
    }
}

/// Un paso de la custodia, tal y como se cuenta en un informe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasoDelInforme {
    /// Que se hizo.
    pub paso: Paso,
    /// Quien lo hizo.
    pub actor: String,
    /// Cuando, en segundos desde la epoca, si el reloj de pared era legible.
    pub cuando: Option<u64>,
}

/// Lo que se puede afirmar de un artefacto, y lo que no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veredicto {
    /// Si el sello, los bytes y la cadena resistieron todas las comprobaciones.
    pub intacta: bool,
    /// Por que no, cuando no.
    pub motivo: Option<CustodiaError>,
    /// El recorrido de la evidencia, para contarlo.
    pub recorrido: Vec<PasoDelInforme>,
    /// Posiciones de la cadena donde dos marcas consecutivas se contradicen.
    ///
    /// No invalidan la evidencia: los bytes siguen siendo los sellados. Invalidan
    /// el razonamiento temporal que se haga con ella, que es un problema
    /// distinto y se cuenta aparte.
    pub saltos_de_reloj: Vec<usize>,
    /// Lo que esta verificacion no establece, aunque salga intacta.
    pub no_demuestra: Vec<LimiteDeLaPrueba>,
}

impl Veredicto {
    /// Verifica un artefacto entero: sus bytes, su sello y su cadena.
    ///
    /// `bytes` es el artefacto. Se pasa aparte porque el sello y la cadena viajan
    /// en el indice del caso y el artefacto —que puede pesar gigabytes— en el
    /// almacen: obligar a tenerlos juntos para verificar haria que nadie
    /// verificara.
    pub fn de(
        bytes: &[u8],
        sello: &Sello,
        cadena: &CadenaDeCustodia,
        registro: &dyn RegistroDeClaves,
    ) -> Veredicto {
        let saltos_de_reloj = cadena.saltos_de_reloj();
        let recorrido = cadena
            .eslabones
            .iter()
            .map(|e| PasoDelInforme {
                paso: e.paso,
                actor: e.actor.clone(),
                cuando: e.cuando.fechable().then_some(e.cuando.pared),
            })
            .collect();

        // Los limites del metodo se listan siempre, salga lo que salga: son del
        // metodo, no del resultado.
        let mut no_demuestra = vec![
            LimiteDeLaPrueba::ClaveNoEsPersona,
            LimiteDeLaPrueba::NoCubreLoAnteriorALaRecogida,
            LimiteDeLaPrueba::ElFinalSePuedePodar,
            LimiteDeLaPrueba::NoDiceQueSeRecogieraTodo,
        ];
        // Este solo se lista cuando de verdad no se pudo descartar. Con menos de
        // dos eslabones no hay dos marcas que contrastar; con marcas de
        // arranques distintos, tampoco.
        if !cronologia_contrastable(cadena) {
            no_demuestra.push(LimiteDeLaPrueba::LaCronologiaNoEsComprobable);
        }

        let motivo = Veredicto::comprobar(bytes, sello, cadena, registro).err();
        Veredicto {
            intacta: motivo.is_none(),
            motivo,
            recorrido,
            saltos_de_reloj,
            no_demuestra,
        }
    }

    /// Las tres comprobaciones, en el orden en que tienen sentido.
    fn comprobar(
        bytes: &[u8],
        sello: &Sello,
        cadena: &CadenaDeCustodia,
        registro: &dyn RegistroDeClaves,
    ) -> Result<(), CustodiaError> {
        // 1. Los bytes son los sellados. Sin esto, verificar la firma del sello
        //    probaria que el sello es autentico sobre OTRA cosa.
        sello.cubre(bytes)?;
        // 2. El sello lo firmo quien dice, con una clave que consta.
        let Some(clave) = registro.clave_de(&sello.procedencia.agente) else {
            return Err(CustodiaError::FirmanteDesconocido {
                firmante: sello.procedencia.agente.clone(),
            });
        };
        sello.firma_valida(clave)?;
        // 3. La cadena ancla en este sello y esta entera.
        cadena.verificar(sello, registro)
    }

    /// Frases de lo que no queda probado, para volcarlas en el informe.
    pub fn advertencias(&self) -> Vec<&'static str> {
        self.no_demuestra.iter().map(|l| l.frase()).collect()
    }
}

/// Si las marcas de la cadena se pudieron contrastar entre si.
///
/// Hacen falta al menos dos eslabones del mismo arranque y con reloj de pared
/// legible. Si no, la coherencia temporal no es que sea buena: es que no se
/// comprobo.
fn cronologia_contrastable(cadena: &CadenaDeCustodia) -> bool {
    cadena.eslabones.windows(2).any(|par| {
        par[0].cuando.arranque != 0
            && par[0].cuando.arranque == par[1].cuando.arranque
            && par[0].cuando.fechable()
            && par[1].cuando.fechable()
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cadena::{CadenaDeCustodia, Claveros, Paso};
    use crate::reloj::Marca;
    use crate::sello::{Clase, Procedencia};
    use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;

    fn montar() -> (Vec<u8>, Sello, CadenaDeCustodia, Claveros) {
        let ka = ClaveFirmaHibrida::generar_aleatorio().unwrap();
        let kb = ClaveFirmaHibrida::generar_aleatorio().unwrap();
        let bytes = b"volcado de la region".to_vec();
        let sello = Sello::sellar(
            &bytes,
            Procedencia {
                caso: "CASO-1".into(),
                endpoint: "endpoint-7".into(),
                agente: "agente-7".into(),
                version_agente: "1.0.0".into(),
                clase: Clase::Memoria,
                motivo: "region anonima ejecutable".into(),
                tecnicas: vec!["T1055".into()],
                recogido: Marca::ahora(),
            },
            &ka,
        )
        .unwrap();
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "agente-7", "disparada por el motor", &ka)
            .unwrap();
        cadena
            .anadir(Paso::Transferencia, "plano-de-control", "por mTLS", &kb)
            .unwrap();
        let registro = Claveros::nuevo()
            .con("agente-7", ka.clave_verificacion())
            .con("plano-de-control", kb.clave_verificacion());
        (bytes, sello, cadena, registro)
    }

    #[test]
    fn una_evidencia_integra_sale_intacta_y_con_su_recorrido() {
        let (bytes, sello, cadena, registro) = montar();
        let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
        assert!(v.intacta, "motivo: {:?}", v.motivo);
        assert_eq!(v.recorrido.len(), 2);
        assert_eq!(v.recorrido[0].paso, Paso::Recogida);
        assert_eq!(v.recorrido[1].actor, "plano-de-control");
        assert!(v.saltos_de_reloj.is_empty());
    }

    #[test]
    fn un_veredicto_intacto_tambien_dice_lo_que_no_prueba() {
        // El punto entero del modulo: salir intacta no autoriza a entender mas
        // de lo que se comprobo.
        let (bytes, sello, cadena, registro) = montar();
        let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
        assert!(v.intacta);
        assert!(
            v.no_demuestra.contains(&LimiteDeLaPrueba::ClaveNoEsPersona),
            "una clave robada firma evidencia valida, y eso se dice"
        );
        assert!(v
            .no_demuestra
            .contains(&LimiteDeLaPrueba::NoCubreLoAnteriorALaRecogida));
        assert!(v
            .no_demuestra
            .contains(&LimiteDeLaPrueba::ElFinalSePuedePodar));
        assert!(v
            .no_demuestra
            .contains(&LimiteDeLaPrueba::NoDiceQueSeRecogieraTodo));
        assert_eq!(v.advertencias().len(), v.no_demuestra.len());
    }

    #[test]
    fn con_dos_eslabones_del_mismo_arranque_la_cronologia_si_es_contrastable() {
        let (bytes, sello, cadena, registro) = montar();
        let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
        assert!(
            !v.no_demuestra
                .contains(&LimiteDeLaPrueba::LaCronologiaNoEsComprobable),
            "los dos eslabones son de este arranque y se contrastaron: ese \
             limite no se lista porque si se pudo descartar"
        );
    }

    #[test]
    fn con_un_solo_eslabon_la_cronologia_no_es_contrastable_y_se_dice() {
        let ka = ClaveFirmaHibrida::generar_aleatorio().unwrap();
        let bytes = b"x".to_vec();
        let sello = Sello::sellar(
            &bytes,
            Procedencia {
                caso: "CASO-1".into(),
                endpoint: "e".into(),
                agente: "a".into(),
                version_agente: "1".into(),
                clase: Clase::Fichero,
                motivo: "m".into(),
                tecnicas: vec![],
                recogido: Marca::ahora(),
            },
            &ka,
        )
        .unwrap();
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena.anadir(Paso::Recogida, "a", "", &ka).unwrap();
        let registro = Claveros::nuevo().con("a", ka.clave_verificacion());

        let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
        assert!(v.intacta);
        assert!(
            v.no_demuestra
                .contains(&LimiteDeLaPrueba::LaCronologiaNoEsComprobable),
            "con una sola marca no hay nada que contrastar, y no comprobado no \
             es lo mismo que correcto"
        );
    }

    #[test]
    fn unos_bytes_cambiados_no_salen_intactos_y_dicen_por_que() {
        let (_, sello, cadena, registro) = montar();
        let v = Veredicto::de(b"volcado de la regioN", &sello, &cadena, &registro);
        assert!(!v.intacta);
        assert!(matches!(v.motivo, Some(CustodiaError::OtrosBytes { .. })));
    }

    #[test]
    fn el_recorrido_se_cuenta_aunque_la_verificacion_falle() {
        // Un informe de una custodia ROTA es donde mas falta hace saber por
        // cuantas manos paso: negarle el recorrido a quien investiga el fallo
        // seria justo lo contrario de lo que hace falta.
        let (_, sello, cadena, registro) = montar();
        let v = Veredicto::de(b"otra cosa", &sello, &cadena, &registro);
        assert!(!v.intacta);
        assert_eq!(v.recorrido.len(), 2, "el recorrido se cuenta igual");
    }

    #[test]
    fn un_agente_que_no_consta_en_la_pki_no_sale_intacto() {
        let (bytes, sello, cadena, _) = montar();
        let v = Veredicto::de(&bytes, &sello, &cadena, &Claveros::nuevo());
        assert!(!v.intacta);
        assert!(matches!(
            v.motivo,
            Some(CustodiaError::FirmanteDesconocido { .. })
        ));
    }

    #[test]
    fn cada_limite_tiene_una_frase_util() {
        for l in [
            LimiteDeLaPrueba::ClaveNoEsPersona,
            LimiteDeLaPrueba::NoCubreLoAnteriorALaRecogida,
            LimiteDeLaPrueba::ElFinalSePuedePodar,
            LimiteDeLaPrueba::LaCronologiaNoEsComprobable,
            LimiteDeLaPrueba::NoDiceQueSeRecogieraTodo,
        ] {
            let f = l.frase();
            assert!(f.len() > 40, "una frase que no explica nada sobra: {f:?}");
            assert!(!f.ends_with('.'), "las frases se componen en el informe");
        }
    }
}
