//! Colaboracion real sobre el caso: asignacion, turnos y traspaso CON CONTEXTO,
//! con el tiempo en cada estado medido del rastro (FASE 109).
//!
//! # Por que un traspaso sin contexto pierde el caso
//!
//! TheHive reasigna un caso: cambia el nombre del dueno y ya. Pero un turno que
//! recibe un caso a las tres de la manana sin saber QUE miro el anterior y QUE dejo
//! abierto empieza de cero, y en un incidente en curso empezar de cero es perder
//! tiempo que el atacante usa. Aqui el traspaso LLEVA el contexto: lo que el
//! anterior sabia (lo escribe) y lo que dejo abierto (se captura solo del caso, no
//! se confia en que lo recuerde).
//!
//! Y el tiempo en cada estado se MIDE de las transiciones, no se declara: es lo
//! que permite decir «este caso paso seis horas en espera del cliente» sin que esa
//! espera cuente como tiempo de trabajo del equipo.

use std::collections::BTreeMap;

use crate::modelo::{Caso, Estado, Rechazo};

/// El contexto que viaja con un traspaso: lo que el que entrega sabe, y lo que
/// deja abierto. El que recibe lo ve; no tiene que reconstruirlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextoTraspaso {
    /// Lo que el analista que entrega sabe del caso, en sus palabras.
    pub lo_que_se_sabe: String,
    /// Las tareas que quedan abiertas, capturadas del caso (no de la memoria del
    /// que entrega).
    pub tareas_abiertas: Vec<String>,
    /// El estado en el que queda el caso.
    pub estado: Estado,
}

/// Un traspaso de un analista a otro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traspaso {
    /// Quien entrega.
    pub de: String,
    /// Quien recibe.
    pub a: String,
    /// El contexto que viaja con el caso.
    pub contexto: ContextoTraspaso,
    /// Cuando, en nanosegundos Unix.
    pub cuando_ns: u64,
}

/// Traspasa un caso de un analista a otro, capturando el contexto.
///
/// Las tareas abiertas se sacan del CASO, no de lo que el que entrega diga: asi el
/// que recibe ve lo que de verdad queda, aunque el anterior se olvide de
/// mencionarlo. `lo_que_se_sabe` es lo unico que pone el que entrega.
///
/// Se rechaza traspasar a uno mismo (no es un traspaso) o a un destinatario vacio.
pub fn traspasar(
    caso: &Caso,
    de: &str,
    a: &str,
    lo_que_se_sabe: &str,
    cuando_ns: u64,
) -> Result<Traspaso, Rechazo> {
    if a.trim().is_empty() {
        return Err(Rechazo {
            motivo: "un traspaso necesita a quien se entrega".into(),
        });
    }
    if de.trim() == a.trim() {
        return Err(Rechazo {
            motivo: "traspasar un caso a uno mismo no es un traspaso".into(),
        });
    }
    let tareas_abiertas = caso
        .tareas
        .iter()
        .filter(|t| t.abierta())
        .map(|t| t.titulo.clone())
        .collect();
    Ok(Traspaso {
        de: de.to_string(),
        a: a.to_string(),
        contexto: ContextoTraspaso {
            lo_que_se_sabe: lo_que_se_sabe.to_string(),
            tareas_abiertas,
            estado: caso.estado,
        },
        cuando_ns,
    })
}

/// El tiempo que un caso paso en cada estado, en nanosegundos, medido de la
/// secuencia de transiciones `(estado_entrado, cuando_ns)` en orden, cerrando la
/// ultima con `ahora_ns`.
///
/// Es lo que separa el tiempo de TRABAJO del tiempo de ESPERA: una hora en
/// `EnEspera` (esperando al cliente) no puede contar como una hora de respuesta
/// del equipo, o la metrica culpa al equipo de algo que no depende de el.
#[must_use]
pub fn tiempo_en_estados(transiciones: &[(Estado, u64)], ahora_ns: u64) -> BTreeMap<Estado, u64> {
    let mut total: BTreeMap<Estado, u64> = BTreeMap::new();
    for (i, (estado, entrada_ns)) in transiciones.iter().enumerate() {
        let salida_ns = transiciones.get(i + 1).map_or(ahora_ns, |(_, ns)| *ns);
        let dur = salida_ns.saturating_sub(*entrada_ns);
        *total.entry(*estado).or_insert(0) += dur;
    }
    total
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Alerta, Observable, Severidad};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn caso_con_tareas() -> Caso {
        let a = Alerta {
            id: "A-1".into(),
            inquilino: "c1".into(),
            anfitrion: "m-17".into(),
            sujeto: "pid:42".into(),
            tecnica: None,
            regla: "r".into(),
            severidad: Severidad::Alta,
            ocurrio_ns: AHORA,
            observables: vec![Observable::Anfitrion("m-17".into())],
            resumen: "algo".into(),
        };
        let mut c = Caso::abrir("C-1", a);
        c.anadir_tarea("aislar la maquina");
        c.anadir_tarea("mirar el linaje");
        c
    }

    #[test]
    fn el_traspaso_lleva_lo_abierto_capturado_del_caso() {
        let c = caso_con_tareas();
        let t = traspasar(
            &c,
            "ana",
            "beto",
            "el hijo del proceso es sospechoso",
            AHORA + SEG,
        )
        .unwrap();
        assert_eq!(t.de, "ana");
        assert_eq!(t.a, "beto");
        assert_eq!(
            t.contexto.lo_que_se_sabe,
            "el hijo del proceso es sospechoso"
        );
        // Las dos tareas abiertas viajan con el traspaso: beto no empieza de cero.
        assert_eq!(t.contexto.tareas_abiertas.len(), 2);
        assert!(t
            .contexto
            .tareas_abiertas
            .contains(&"aislar la maquina".to_string()));
    }

    #[test]
    fn no_se_traspasa_a_uno_mismo_ni_a_nadie() {
        let c = caso_con_tareas();
        assert!(traspasar(&c, "ana", "ana", "x", AHORA).is_err());
        assert!(traspasar(&c, "ana", "  ", "x", AHORA).is_err());
    }

    #[test]
    fn el_tiempo_en_espera_no_cuenta_como_tiempo_de_trabajo() {
        // Nuevo 1 min, EnCurso 5 min, EnEspera 1 h, EnCurso 2 min, Contenido.
        let trans = vec![
            (Estado::Nuevo, AHORA),
            (Estado::EnCurso, AHORA + 60 * SEG),
            (Estado::EnEspera, AHORA + 360 * SEG),
            (Estado::EnCurso, AHORA + 3960 * SEG),
            (Estado::Contenido, AHORA + 4080 * SEG),
        ];
        let t = tiempo_en_estados(&trans, AHORA + 4080 * SEG);
        assert_eq!(t[&Estado::Nuevo], 60 * SEG);
        assert_eq!(
            t[&Estado::EnEspera],
            3600 * SEG,
            "la hora de espera se aisla"
        );
        assert_eq!(t[&Estado::EnCurso], (300 + 120) * SEG, "el trabajo, aparte");
    }

    #[test]
    fn el_ultimo_estado_se_cierra_con_ahora() {
        let trans = vec![(Estado::Nuevo, AHORA)];
        let t = tiempo_en_estados(&trans, AHORA + 10 * SEG);
        assert_eq!(t[&Estado::Nuevo], 10 * SEG);
    }
}
