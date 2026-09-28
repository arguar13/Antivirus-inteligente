//! El informe del caso: con su cadena de custodia y sus HUECOS DECLARADOS (FASE 109).
//!
//! # Un informe que oculta un hueco es el que hunde un peritaje
//!
//! Es la tentacion de todo informe: presentar el caso como una historia cerrada y
//! limpia. Pero un informe que dice «resuelto» cuando quedaban tareas sin hacer, o
//! que no menciona que el rastro no estaba anclado, es exactamente lo que un
//! abogado de la parte contraria usa para tirar el peritaje entero. Ningun producto
//! abierto declara sus huecos; aqui el informe los LISTA, porque un hueco dicho es
//! una limitacion y un hueco callado es una mentira.
//!
//! La cadena de custodia sale del rastro inmutable ([`crate::auditoria`]): quien
//! vio que, quien cambio que, y cuando. No se escribe a mano.

use crate::auditoria::{Rastro, Rotura};
use crate::modelo::{Caso, Veredicto};

/// Un hueco del caso: algo que el informe DECLARA en vez de esconder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hueco {
    /// Se cerro (o se informa) con tareas todavia abiertas.
    TareasAbiertas {
        /// Cuantas.
        cuantas: usize,
    },
    /// El caso no tiene veredicto.
    SinVeredicto,
    /// El veredicto es `NoConcluyente`: se investigo y no se pudo determinar. No
    /// es un fallo, pero el informe no puede presentarlo como resuelto.
    VeredictoNoConcluyente,
    /// El rastro de auditoria no verifica: hay manipulacion o corrupcion.
    RastroManipulado {
        /// Las roturas encontradas.
        roturas: Vec<Rotura>,
    },
    /// El rastro no esta anclado: es inmutable frente a edicion, pero una
    /// reescritura completa no se detectaria. La frontera se dice.
    RastroSinAnclar,
}

impl Hueco {
    /// Una frase legible del hueco, para el informe.
    #[must_use]
    pub fn describir(&self) -> String {
        match self {
            Hueco::TareasAbiertas { cuantas } => {
                format!("quedan {cuantas} tarea(s) abierta(s) sin resolver")
            }
            Hueco::SinVeredicto => "el caso se informa sin veredicto".to_string(),
            Hueco::VeredictoNoConcluyente => {
                "el veredicto es no concluyente: no se pudo determinar".to_string()
            }
            Hueco::RastroManipulado { roturas } => {
                format!(
                    "el rastro de auditoria NO verifica ({} rotura(s))",
                    roturas.len()
                )
            }
            Hueco::RastroSinAnclar => {
                "el rastro no esta anclado: una reescritura completa no se detectaria".to_string()
            }
        }
    }
}

/// El informe de un caso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Informe {
    /// Identificador del caso.
    pub caso: String,
    /// Titulo.
    pub titulo: String,
    /// Veredicto con el que se cerro, si lo hay.
    pub veredicto: Option<Veredicto>,
    /// La cadena de custodia: las entradas del rastro, en orden, ya renderizadas.
    pub cadena_custodia: Vec<String>,
    /// Los huecos declarados.
    pub huecos: Vec<Hueco>,
}

impl Informe {
    /// `true` si el caso se puede presentar como cerrado y limpio, SIN huecos.
    /// Un informe honesto no lo fuerza: si hay huecos, lo dice.
    #[must_use]
    pub fn sin_huecos(&self) -> bool {
        self.huecos.is_empty()
    }
}

/// Genera el informe de un caso a partir de su estado y su rastro.
///
/// El informe no puede ocultar un hueco: recorre todo lo que podria estar
/// incompleto —tareas abiertas, veredicto ausente o no concluyente, rastro
/// manipulado o sin anclar— y lo LISTA.
#[must_use]
pub fn generar(caso: &Caso, rastro: &Rastro) -> Informe {
    let mut huecos = Vec::new();

    let abiertas = caso.tareas_abiertas();
    if abiertas > 0 {
        huecos.push(Hueco::TareasAbiertas { cuantas: abiertas });
    }
    match caso.veredicto {
        None => huecos.push(Hueco::SinVeredicto),
        Some(Veredicto::NoConcluyente) => huecos.push(Hueco::VeredictoNoConcluyente),
        Some(_) => {}
    }
    let roturas = rastro.verificar();
    if !roturas.is_empty() {
        huecos.push(Hueco::RastroManipulado { roturas });
    }
    if rastro.anclas().is_empty() {
        huecos.push(Hueco::RastroSinAnclar);
    }

    Informe {
        caso: caso.id.clone(),
        titulo: caso.titulo.clone(),
        veredicto: caso.veredicto,
        cadena_custodia: rastro.entradas().iter().map(ToString::to_string).collect(),
        huecos,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::auditoria::Accion;
    use crate::modelo::{Alerta, Observable, Severidad};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn caso() -> Caso {
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
        Caso::abrir("C-1", a)
    }

    fn rastro() -> Rastro {
        let mut r = Rastro::nuevo("C-1");
        r.anotar("sistema", Accion::Creado, "abrio", AHORA).unwrap();
        r.anotar("ana", Accion::Comentario, "mirando", AHORA + SEG)
            .unwrap();
        r
    }

    #[test]
    fn un_caso_cerrado_limpio_y_anclado_no_tiene_huecos() {
        let mut c = caso();
        let t = c.anadir_tarea("mirar");
        c.pasar_a(crate::modelo::Estado::EnCurso, AHORA).unwrap();
        c.cerrar_tarea(t, None).unwrap();
        c.cerrar(Veredicto::Verdadero, None, AHORA + SEG).unwrap();
        let mut r = rastro();
        r.anclar(AHORA + 2 * SEG);
        let inf = generar(&c, &r);
        assert!(inf.sin_huecos(), "{:?}", inf.huecos);
        assert_eq!(inf.cadena_custodia.len(), 2);
    }

    #[test]
    fn el_informe_declara_todos_los_huecos_no_los_esconde() {
        // Caso con tarea abierta, veredicto no concluyente y rastro sin anclar.
        let mut c = caso();
        c.anadir_tarea("sin hacer");
        c.pasar_a(crate::modelo::Estado::EnCurso, AHORA).unwrap();
        c.cerrar(
            Veredicto::NoConcluyente,
            Some("no se pudo determinar".into()),
            AHORA + SEG,
        )
        .unwrap();
        let inf = generar(&c, &rastro());
        assert!(!inf.sin_huecos());
        assert!(inf
            .huecos
            .iter()
            .any(|h| matches!(h, Hueco::TareasAbiertas { .. })));
        assert!(inf.huecos.contains(&Hueco::VeredictoNoConcluyente));
        assert!(inf.huecos.contains(&Hueco::RastroSinAnclar));
    }

    #[test]
    fn un_rastro_manipulado_sale_como_hueco() {
        use crate::auditoria::{Entrada, GENESIS};
        let c = caso();
        // Un rastro con una entrada cargada fuera de secuencia (borrar la primera
        // es la forma mas limpia de manipular): verificar() encuentra un Hueco, y
        // el informe lo DECLARA en vez de esconderlo.
        let mut r = Rastro::nuevo("C-1");
        r.cargar(Entrada::nueva(
            5,
            "C-1",
            "ana",
            Accion::Comentario,
            "entrada con secuencia rota",
            AHORA,
            GENESIS,
        ));
        r.anclar(AHORA + 2 * SEG);
        let inf = generar(&c, &r);
        assert!(inf
            .huecos
            .iter()
            .any(|h| matches!(h, Hueco::RastroManipulado { .. })));
    }
}
