//! El unico camino por el que el grafo del directorio sale del plano de control.
//!
//! # El grafo como mapa para el atacante
//!
//! El grafo completo del directorio —quien puede sobre quien, en toda la
//! organizacion— es exactamente el mapa que un atacante querria antes de elegir
//! por donde escalar. Es la misma clase de dato que el inventario de componentes
//! de la FASE 94, y se protege igual:
//!
//! 1. **El serializador es privado.** [`documento`] no es publico: nadie fuera de
//!    este modulo arma el JSON del grafo.
//! 2. **La unica salida pasa por el juez de difusion.** [`exportar`] marca el
//!    grafo como [`MARCADO_GRAFO`] —`TLP:AMBER+STRICT`, «solo mi organizacion»— y
//!    lo somete al unico estrangulamiento del producto ([`aegis_share::Difusor`]).
//!    El llamante **no elige el marcado**: no hay parametro con el que rebajarlo.
//!
//! Consecuencias, comprobadas canal a canal en la prueba de autoataque: el
//! enjambre no lo saca nunca (su tope duro es GREEN); ningun destino que no sea la
//! propia organizacion lo recibe, por ningun canal; y un destino no declarado es
//! un error, no un permiso.
//!
//! Armar el documento sin pasar por el juez no compila (privado):
//!
//! ```compile_fail,E0603
//! let _ = aegis_itdr::directorio::salida::documento;
//! ```
//!
//! Y el marcado no se elige: `exportar` no tiene parametro de marcado (E0061):
//!
//! ```compile_fail,E0061
//! # use aegis_itdr::directorio::salida::exportar;
//! # use aegis_itdr::directorio::GrafoDirectorio;
//! # let (g, d) = (GrafoDirectorio::nuevo(), aegis_share::Difusor::nuevo());
//! let m = aegis_share::Marcado { tlp: aegis_share::Tlp::Clear, pap: aegis_share::Pap::Clear };
//! let _ = exportar(&g, "x", &d, m);
//! ```

use aegis_share::{Difusor, Marcado, Pap, Retenido, Tlp};
use serde_json::{json, Value};

use super::GrafoDirectorio;

/// El marcado del grafo del directorio.
///
/// `AMBER+STRICT` y no `RED`: el grafo existe para que el equipo de seguridad de
/// la organizacion trabaje con el —si fuera `RED` no podria salir ni hacia el
/// propio equipo—. `PAP:AMBER`: se puede usar para defender dentro de casa, no
/// para publicar.
pub const MARCADO_GRAFO: Marcado = Marcado {
    tlp: Tlp::AmberStrict,
    pap: Pap::Amber,
};

/// Un grafo que ya paso por el juez de difusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrafoExportado {
    /// A que destino se autorizo.
    pub destino: String,
    /// El documento JSON.
    pub contenido: String,
}

/// Por que no sale el grafo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoSale {
    /// El destino no esta declarado: no se reparte a ciegas.
    DestinoDesconocido(String),
    /// El juez lo retiene, con su motivo.
    Retenido(Retenido),
}

impl std::fmt::Display for NoSale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoSale::DestinoDesconocido(d) => {
                write!(
                    f,
                    "destino «{d}» no declarado: el grafo no se exporta a ciegas"
                )
            }
            NoSale::Retenido(r) => write!(f, "el grafo del directorio se retiene: {}", r.texto()),
        }
    }
}

/// Exporta el grafo del directorio hacia un destino declarado, si el juez lo
/// permite. Es el **unico** camino de salida.
///
/// # Errores
/// [`NoSale`] si el destino no existe o el marcado no le deja llegar.
pub fn exportar(
    g: &GrafoDirectorio,
    destino: &str,
    difusor: &Difusor,
) -> Result<GrafoExportado, NoSale> {
    let d = difusor
        .destino(destino)
        .ok_or_else(|| NoSale::DestinoDesconocido(destino.to_string()))?;
    Difusor::juzgar_marcado(MARCADO_GRAFO, false, d).map_err(NoSale::Retenido)?;
    Ok(GrafoExportado {
        destino: destino.to_string(),
        contenido: serde_json::to_string(&documento(g)).unwrap_or_default(),
    })
}

/// Arma el documento JSON del grafo. **Privado**: solo sale por [`exportar`].
fn documento(g: &GrafoDirectorio) -> Value {
    let principales: Vec<Value> = g
        .iter_principales()
        .map(|p| {
            json!({
                "sid": p.sid.texto(),
                "eid": p.eid().texto(),
                "nombre": p.nombre,
                "clase": p.clase.nombre(),
            })
        })
        .collect();
    let aristas: Vec<Value> = g
        .iter_aristas()
        .map(|a| {
            json!({
                "origen": a.origen,
                "destino": a.destino,
                "relacion": a.relacion.describir(),
            })
        })
        .collect();
    json!({
        "aegis:tlp": "TLP:AMBER+STRICT",
        "aegis:pap": "PAP:AMBER",
        "principales": principales,
        "aristas": aristas,
    })
}

#[cfg(test)]
mod pruebas {
    use super::super::objeto::{ClasePrincipal, Principal, Sid};
    use super::super::relacion::{Arista, RelacionDirectorio};
    use super::*;
    use aegis_share::{Canal, Destino};

    fn grafo() -> GrafoDirectorio {
        let mut g = GrafoDirectorio::nuevo();
        g.agregar_principal(Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-1104"),
            ClasePrincipal::Usuario,
            "alice",
        ))
        .unwrap();
        g.agregar_principal(Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-512"),
            ClasePrincipal::Grupo,
            "Domain Admins",
        ))
        .unwrap();
        g.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::EscrituraDacl,
        ))
        .unwrap();
        g
    }

    fn destino(nombre: &str, canal: Canal, propia: bool) -> Destino {
        Destino {
            nombre: nombre.into(),
            canal,
            tope_tlp: Tlp::Red,
            es_propia_organizacion: propia,
        }
    }

    #[test]
    fn hacia_la_propia_organizacion_sale_un_documento_valido() {
        let mut d = Difusor::nuevo();
        d.declarar(destino("soc-interno", Canal::Exportacion, true));
        let doc = exportar(&grafo(), "soc-interno", &d).expect("hacia dentro sale");
        let v: Value = serde_json::from_str(&doc.contenido).unwrap();
        assert_eq!(v["aegis:tlp"], "TLP:AMBER+STRICT");
        assert_eq!(v["principales"].as_array().unwrap().len(), 2);
        assert_eq!(v["aristas"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_un_destino_no_declarado_no_sale() {
        let d = Difusor::nuevo();
        assert!(matches!(
            exportar(&grafo(), "fantasma", &d),
            Err(NoSale::DestinoDesconocido(_))
        ));
    }
}
