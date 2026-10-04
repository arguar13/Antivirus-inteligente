//! La puerta de contenido: cada regla que se distribuye trae un evento que la
//! dispara, uno que no, y un presupuesto de falsos positivos (FASE 4 del MP-16).
//!
//! Los dos eventos NO se escriben a mano: salen de la regla
//! ([`crate::generador`]). El presupuesto si lo fija una persona, en el fichero
//! `PRESUPUESTOS` junto a las reglas, una linea por regla:
//!
//! ```text
//! # id                                    fp_max_por_millon
//! 00000000-0000-0000-0000-000000000000    20
//! ```
//!
//! `fp_max_por_millon` es el techo de disparos por millon de eventos BENIGNOS
//! de su categoria que se acepta al medirla contra la carga de sobrecoste de la
//! FASE 3 y el corpus benigno de la FASE 4. Aqui se exige que exista; la medida
//! la hace el banco, y una regla que se pase no sale de solo-auditoria.

use std::collections::BTreeMap;

use crate::compacta::ReglaCompacta;
use crate::generador::{self, Evento};

/// Lo que la puerta exige de una regla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prueba {
    /// Un evento que la regla TIENE que disparar (generado).
    pub dispara: Evento,
    /// El mismo con un campo obligatorio alterado, que NO dispara (generado).
    pub no_dispara: Evento,
    /// Techo de falsos positivos por millon de eventos benignos.
    pub fp_max_por_millon: u32,
}

/// Por que una regla no pasa la puerta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPrueba {
    /// Codigo estable.
    pub codigo: &'static str,
    /// Detalle legible.
    pub detalle: String,
}

fn falla(codigo: &'static str, detalle: impl Into<String>) -> ErrorPrueba {
    ErrorPrueba {
        codigo,
        detalle: detalle.into(),
    }
}

/// Lee el fichero `PRESUPUESTOS`.
///
/// # Errores
/// La primera linea mal formada o repetida, con su numero.
pub fn leer_presupuestos(texto: &str) -> Result<BTreeMap<String, u32>, ErrorPrueba> {
    let mut salida = BTreeMap::new();
    for (i, linea) in texto.lines().enumerate() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut partes = l.split_whitespace();
        let (Some(id), Some(n), None) = (partes.next(), partes.next(), partes.next()) else {
            return Err(falla(
                "presupuesto-mal-formado",
                format!("linea {}: «{l}» no es «id numero»", i + 1),
            ));
        };
        let n = n.parse::<u32>().map_err(|_| {
            falla(
                "presupuesto-mal-formado",
                format!("linea {}: «{n}» no es un entero", i + 1),
            )
        })?;
        if salida.insert(id.to_string(), n).is_some() {
            return Err(falla(
                "presupuesto-repetido",
                format!("linea {}: el id {id} ya tenia presupuesto", i + 1),
            ));
        }
    }
    Ok(salida)
}

/// Pasa una regla por la puerta.
///
/// # Errores
/// - `prueba-sin-evento-que-dispara`: no se encontro un evento que la
///   dispare. Una regla que nada dispara esta muerta.
/// - `prueba-sin-evento-que-no-dispara`: dispara aunque se le altere o quite
///   cualquier campo. Dispararia sobre casi todo.
/// - `prueba-sin-presupuesto-fp`: su id no esta en `PRESUPUESTOS`.
pub fn prueba_de(
    regla: &ReglaCompacta,
    presupuestos: &BTreeMap<String, u32>,
) -> Result<Prueba, ErrorPrueba> {
    let dispara = generador::dispara(regla).ok_or_else(|| {
        falla(
            "prueba-sin-evento-que-dispara",
            format!("{}: ningun evento la dispara", regla.id()),
        )
    })?;
    let no_dispara = generador::no_dispara(regla, &dispara).ok_or_else(|| {
        falla(
            "prueba-sin-evento-que-no-dispara",
            format!(
                "{}: dispara aunque se altere o quite cualquier campo",
                regla.id()
            ),
        )
    })?;
    let fp_max_por_millon = *presupuestos.get(regla.id()).ok_or_else(|| {
        falla(
            "prueba-sin-presupuesto-fp",
            format!("{}: no esta en PRESUPUESTOS", regla.id()),
        )
    })?;
    Ok(Prueba {
        dispara,
        no_dispara,
        fp_max_por_millon,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::compacta::{Categoria, Juego};
    use crate::generador::registro;
    use crate::regla::Topes;

    /// Una regla SINTETICA de valores inocuos.
    fn sintetica(condicion: &str) -> ReglaCompacta {
        let fuente = format!(
            "title: Sintetica\nid: id-sintetica\nlogsource:\n    product: linux\n    \
             category: process_creation\ndetection:\n    sel:\n        \
             Image|endswith: '/alfa'\n    filtro:\n        CommandLine|contains: 'beta'\n    \
             condition: {condicion}\n"
        );
        let j = Juego::cargar(&[("s.yml", fuente.as_str())], &Topes::default());
        j.reglas(Categoria::CreacionProceso)[0].clone()
    }

    fn presupuestos() -> BTreeMap<String, u32> {
        leer_presupuestos("# comentario\nid-sintetica   20\n").unwrap()
    }

    #[test]
    fn una_regla_viva_pasa_la_puerta_con_sus_dos_eventos() {
        let r = sintetica("sel and not filtro");
        let p = prueba_de(&r, &presupuestos()).unwrap();
        assert!(r.casa(&registro(&p.dispara)));
        assert!(!r.casa(&registro(&p.no_dispara)));
        assert_eq!(p.fp_max_por_millon, 20);
    }

    /// LA PUERTA: sin sus dos eventos, o sin presupuesto, no entra.
    #[test]
    fn una_regla_sin_eventos_o_sin_presupuesto_no_pasa() {
        let muerta = sintetica("sel and not sel");
        assert_eq!(
            prueba_de(&muerta, &presupuestos()).unwrap_err().codigo,
            "prueba-sin-evento-que-dispara"
        );
        let todo = sintetica("not filtro");
        assert_eq!(
            prueba_de(&todo, &presupuestos()).unwrap_err().codigo,
            "prueba-sin-evento-que-no-dispara"
        );
        let viva = sintetica("sel");
        assert_eq!(
            prueba_de(&viva, &BTreeMap::new()).unwrap_err().codigo,
            "prueba-sin-presupuesto-fp"
        );
    }

    #[test]
    fn un_fichero_de_presupuestos_roto_se_dice_con_su_linea() {
        assert_eq!(
            leer_presupuestos("a 1\nb\n").unwrap_err().codigo,
            "presupuesto-mal-formado"
        );
        assert_eq!(
            leer_presupuestos("a x\n").unwrap_err().codigo,
            "presupuesto-mal-formado"
        );
        assert_eq!(
            leer_presupuestos("a 1\na 2\n").unwrap_err().codigo,
            "presupuesto-repetido"
        );
    }
}
