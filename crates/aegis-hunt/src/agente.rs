//! El lado del ENDPOINT de una caceria: recibir, ejecutar y responder.
//!
//! Traduce entre el protocolo de flota y el ejecutor. Es poco codigo, pero
//! concentra las decisiones que hacen que una caceria distribuida sea util o
//! sea ruido:
//!
//!   - **Un endpoint que no puede contestar, CONTESTA que no puede.** Si
//!     callara, seria indistinguible de uno apagado, y el analista creeria que
//!     su caceria cubrio una flota que en realidad no cubrio. Es la diferencia
//!     entre "ninguna de mis diez mil maquinas tiene esa baliza" y "no lo se".
//!   - **Una consulta invalida no se ejecuta a medias.** Si el analizador la
//!     rechaza aqui —cosa que no deberia pasar, porque el plano de control ya
//!     la valido— se devuelve el motivo, no un resultado vacio que parezca un
//!     "no hay nada".
//!   - **El presupuesto lo pone el endpoint.** El plano de control no sabe si
//!     esta maquina es un servidor de produccion o un portatil con bateria; la
//!     maquina si.

use std::time::Duration;

use aegis_behavior::dag::BehaviorGraph;
use aegis_fleet::proto::{EmpujePolitica, FilaCaza, ReporteCaza};
use aegis_parser::plan::planificar;
use aegis_parser::sintaxis::analizar;

use crate::ejecutor::{Ejecutor, Resultado};

/// Ejecuta la caceria que venga en un empuje del plano de control.
///
/// Devuelve `None` si el empuje no lleva caceria, que es el caso normal: la
/// mayoria de los marcos del canal son politica o latidos.
pub fn atender_empuje(
    empuje: &EmpujePolitica,
    grafo: Option<&BehaviorGraph>,
    presupuesto: Duration,
) -> Option<ReporteCaza> {
    if empuje.caza_id.is_empty() || empuje.caza_ql.is_empty() {
        return None;
    }
    Some(ejecutar_caza(
        &empuje.caza_id,
        &empuje.caza_ql,
        grafo,
        presupuesto,
    ))
}

/// Ejecuta una consulta y arma el informe.
pub fn ejecutar_caza(
    caza_id: &str,
    consulta: &str,
    grafo: Option<&BehaviorGraph>,
    presupuesto: Duration,
) -> ReporteCaza {
    let base = ReporteCaza {
        caza_id: caza_id.to_string(),
        ..Default::default()
    };

    let arbol = match analizar(consulta) {
        Ok(a) => a,
        Err(e) => {
            // No deberia ocurrir: el plano de control valida antes de difundir.
            // Si ocurre, es que el agente y el servidor tienen versiones
            // distintas del esquema, y eso hay que verlo en la consola.
            return ReporteCaza {
                error: format!("no entiendo la consulta: {e}"),
                ..base
            };
        }
    };

    let plan = planificar(arbol);
    let ejecutor = match grafo {
        Some(g) => Ejecutor::con_grafo(g),
        None => Ejecutor::nuevo(),
    }
    .con_presupuesto(presupuesto);

    informe(caza_id, ejecutor.ejecutar(&plan))
}

/// Convierte un resultado local en el informe que viaja por el cable.
fn informe(caza_id: &str, r: Resultado) -> ReporteCaza {
    ReporteCaza {
        caza_id: caza_id.to_string(),
        // El id_agente lo pone el plano de control desde el CERTIFICADO: lo que
        // el agente declare de si mismo no es identidad, es un dato.
        id_agente: String::new(),
        columnas: r.columnas,
        filas: r
            .filas
            .into_iter()
            .map(|celdas| FilaCaza { celdas })
            .collect(),
        coincidencias: r.coincidencias,
        examinadas: r.examinadas,
        inaccesibles: r.inaccesibles,
        incompleto: r.incompleto,
        agotado: r.agotado,
        duracion_ms: r.duracion_ms,
        error: String::new(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn empuje_con(ql: &str) -> EmpujePolitica {
        EmpujePolitica {
            caza_id: "caza-1".to_string(),
            caza_ql: ql.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn un_empuje_sin_caceria_no_dispara_nada() {
        // La mayoria de los marcos del canal son politica o latidos: ejecutar
        // algo en cada uno seria hacer trabajo en el endpoint por nada.
        assert!(atender_empuje(&EmpujePolitica::default(), None, Duration::from_secs(1)).is_none());
        assert!(atender_empuje(
            &EmpujePolitica {
                caza_id: "caza-1".into(),
                ..Default::default()
            },
            None,
            Duration::from_secs(1)
        )
        .is_none());
    }

    #[test]
    fn una_caceria_real_se_ejecuta_contra_este_endpoint() {
        let r = atender_empuje(
            &empuje_con(&format!(
                "SELECT pid FROM processes WHERE pid = {}",
                std::process::id()
            )),
            None,
            Duration::from_secs(5),
        )
        .expect("deberia ejecutarse");

        assert_eq!(r.caza_id, "caza-1");
        assert!(r.error.is_empty());
        assert_eq!(r.filas.len(), 1, "se encuentra a si mismo");
        assert_eq!(r.filas[0].celdas[0], std::process::id().to_string());
        assert_eq!(r.coincidencias, 1);
        assert!(r.examinadas > 0);
    }

    #[test]
    fn una_consulta_invalida_devuelve_el_motivo_y_no_un_vacio_enganoso() {
        // Un resultado vacio y un "no pude" se parecen mucho en una tabla y no
        // significan lo mismo en absoluto.
        let r = atender_empuje(
            &empuje_con("SELECT pdi FROM processes"),
            None,
            Duration::from_secs(1),
        )
        .expect("deberia responder");
        assert!(!r.error.is_empty(), "tiene que decir por que no pudo");
        assert!(r.error.contains("pdi"), "{}", r.error);
        assert!(r.filas.is_empty());
        assert_eq!(r.coincidencias, 0);
    }

    #[test]
    fn el_informe_no_declara_identidad() {
        // La identidad la pone el plano de control desde el certificado. Si el
        // agente la declarara, un agente comprometido podria atribuir sus
        // hallazgos a otro endpoint.
        let r = atender_empuje(
            &empuje_con("SELECT COUNT(*) FROM processes"),
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(r.id_agente.is_empty());
    }

    #[test]
    fn un_presupuesto_imposible_devuelve_lo_que_llevaba_y_lo_dice() {
        let r = atender_empuje(
            &empuje_con("SELECT pid, sha256 FROM processes"),
            None,
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(r.agotado, "tiene que avisar de que se quedo a medias");
        assert!(r.incompleto);
        assert!(r.error.is_empty(), "agotarse no es un error, es un aviso");
    }
}
