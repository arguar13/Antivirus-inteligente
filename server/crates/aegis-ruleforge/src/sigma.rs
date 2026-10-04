//! Sigma en la fabrica de contenido.
//!
//! El compilador y el evaluador viven en `aegis-sigma` (crates/), compartidos
//! con el agente desde la FASE 4 del MP-16: lo que la fabrica aprueba es
//! exactamente lo que el endpoint evalua, con el mismo codigo. Aqui quedan las
//! dos cosas que son de la fabrica: el analizador de retroceso catastrofico de
//! las expresiones regulares ([`crate::regex_segura`], compartido con
//! Suricata) y el [`Informe`] de un lote.
//!
//! Al moverlo se arreglaron cinco fallos del compilador anterior (listas de
//! mapas leidas como conjuncion, palabras clave que casaban con todo, `''` al
//! reves, el tope de anidamiento sin aplicar a la condicion y un panico con
//! caracteres multibyte), y los comodines `*` pasaron a evaluarse como
//! comodines: ver la documentacion de `aegis_sigma::regla`.

use std::collections::BTreeMap;

pub use aegis_sigma::regla::{
    analizar_condicion, Comparacion, Condicion, ErrorSigma, Expresion, Nivel, ReglaSigma,
    Seleccion, Topes,
};

use crate::informe::{Informe, Rechazo};
use crate::presupuesto::Presupuesto;
use crate::regex_segura;

/// Los topes del compilador que salen del presupuesto de la fabrica.
#[must_use]
pub fn topes(p: &Presupuesto) -> Topes {
    Topes {
        max_anidamiento: p.max_anidamiento,
        max_bytes_regla: p.max_bytes_regla,
        ..Topes::default()
    }
}

/// Compila una regla Sigma, rechazando las expresiones patologicas.
///
/// # Errores
/// [`ErrorSigma`] nombrando lo concreto que falla.
pub fn compilar_regla(fuente: &str, presupuesto: &Presupuesto) -> Result<ReglaSigma, ErrorSigma> {
    let validar = |re: &str| -> Result<(), String> {
        regex_segura::analizar(re, presupuesto)
            .map(|_| ())
            .map_err(|p| format!("{}: {}", p.codigo(), p.explicacion()))
    };
    aegis_sigma::regla::compilar_regla(fuente, &topes(presupuesto), &validar)
}

/// Compila una coleccion de reglas Sigma, una por documento.
#[must_use]
pub fn compilar(documentos: &[&str], presupuesto: &Presupuesto) -> (Vec<ReglaSigma>, Informe) {
    let mut salida = Vec::new();
    let mut informe = Informe::default();
    let mut vistos: BTreeMap<String, ()> = BTreeMap::new();

    for doc in documentos {
        if informe.vistas >= presupuesto.max_reglas {
            informe.rechazada(Rechazo::nuevo(
                "(resto)",
                "demasiadas-reglas",
                format!("se paso el tope de {} reglas", presupuesto.max_reglas),
            ));
            break;
        }
        match compilar_regla(doc, presupuesto) {
            Ok(r) => {
                if vistos.insert(r.id.clone(), ()).is_some() {
                    informe.duplicada();
                    continue;
                }
                salida.push(r);
                informe.compilada();
            }
            Err(e) => {
                informe.rechazada(Rechazo::nuevo(titulo_de(doc), e.codigo(), e.detalle()));
            }
        }
    }
    (salida, informe)
}

/// Saca el titulo de un documento sin analizarlo entero, para poder citarlo.
fn titulo_de(doc: &str) -> String {
    doc.lines()
        .find_map(|l| l.trim().strip_prefix("title:"))
        .map(|t| t.trim().trim_matches(['"', '\'']).to_string())
        .unwrap_or_else(|| "(sin titulo)".to_string())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    /// UNA REGLA SIGMA REAL, del catalogo publico.
    const REAL: &str = r#"
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
    filter:
        CommandLine|contains: 'update.microsoft.com'
    condition: selection and not filter
level: high
tags:
    - attack.execution
    - attack.t1059.001
"#;

    #[test]
    fn la_fabrica_compila_con_el_compilador_compartido() {
        let r = compilar_regla(REAL, &p()).expect("la regla es valida");
        assert_eq!(r.nivel, Nivel::High);
        assert_eq!(r.selecciones.len(), 2);
    }

    /// Una expresion patologica se rechaza en la fabrica: correria en el
    /// endpoint por cada evento.
    #[test]
    fn una_expresion_patologica_en_sigma_se_rechaza() {
        let fuente =
            "title: Patologica\ndetection:\n    sel:\n        CommandLine|re: '(a+)+$'\n    \
                      condition: sel\nlevel: low\n";
        assert_eq!(
            compilar_regla(fuente, &p()).unwrap_err().codigo(),
            "regex-patologica"
        );
    }

    #[test]
    fn el_informe_de_un_lote_dice_cuantas_de_cuantas() {
        let mala = "title: Mala\ndetection:\n  sel:\n    A: 1\n  condition: fantasma\nlevel: low\n";
        let obsoleta =
            "title: Vieja\nstatus: deprecated\ndetection:\n  sel:\n    A: 1\n  condition: sel\nlevel: low\n";
        let (reglas, informe) = compilar(&[REAL, mala, obsoleta], &p());
        assert_eq!(reglas.len(), 1);
        assert_eq!(informe.vistas, 3);
        assert_eq!(informe.compiladas, 1);
        let motivos: Vec<&str> = informe.por_motivo().iter().map(|(m, _)| *m).collect();
        assert!(
            motivos.contains(&"sigma-seleccion-desconocida"),
            "{motivos:?}"
        );
        assert!(motivos.contains(&"sigma-obsoleta"), "{motivos:?}");
    }

    #[test]
    fn las_reglas_duplicadas_por_id_se_descartan() {
        let (_, informe) = compilar(&[REAL, REAL], &p());
        assert_eq!(informe.compiladas, 1);
        assert_eq!(informe.duplicadas, 1);
    }

    #[test]
    fn el_presupuesto_de_la_fabrica_llega_al_compilador() {
        let estrecho = Presupuesto::estrecho();
        assert_eq!(topes(&estrecho).max_anidamiento, estrecho.max_anidamiento);
        let e = compilar_regla(REAL, &estrecho).unwrap_err();
        assert_eq!(e.codigo(), "sigma-regla-desmedida");
    }
}
