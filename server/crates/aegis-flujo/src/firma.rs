//! La aprobacion humana, como tipo y como firma.
//!
//! # Por que una firma y no una casilla
//!
//! Un paso de alto impacto —aislar maquinas, deshabilitar cuentas, matar
//! procesos— no se ejecuta sin que una persona lo apruebe. Una casilla de
//! «aprobado» en una base de datos la marca cualquiera que llegue a esa base.
//! Aqui la aprobacion es una FIRMA hibrida (Ed25519 + ML-DSA, la misma del resto
//! del producto) sobre la huella de la ejecucion concreta: el flujo, el paso y
//! sus objetivos exactos. Tres consecuencias:
//!
//! - [`Firma`] solo se construye verificando una firma: no tiene campos
//!   publicos ni valor por defecto.
//!
//! ```compile_fail,E0451
//! let f = aegis_flujo::firma::Firma { huella: [0; 32], quien: String::new() };
//! ```
//!
//! - Una firma para «aislar srv-1» no cubre «aislar srv-1 y srv-2»: el motor
//!   recalcula la huella con los objetivos reales y la compara.
//! - Quien firma queda en el registro de la ejecucion.

use aegis_entidad::Eid;
use aegis_pqc::firma_hibrida::{ClaveVerificacionHibrida, FirmaHibrida};
use sha2::{Digest, Sha256};

use crate::paso::Permiso;

/// Contexto de dominio de las firmas de aprobacion: una firma de otra cosa del
/// producto no vale como aprobacion de un paso.
pub const DOMINIO: &[u8] = b"AegisCore/flujo/aprobacion/v1";

/// La huella de una ejecucion de un paso: flujo, paso y objetivos ordenados.
#[must_use]
pub fn huella(flujo: &str, paso: &str, objetivos: &[Eid]) -> [u8; 32] {
    let mut o: Vec<String> = objetivos.iter().map(Eid::texto).collect();
    o.sort();
    o.dedup();
    let mut h = Sha256::new();
    for parte in [flujo, paso] {
        h.update(parte.as_bytes());
        h.update([0x1f]);
    }
    for x in o {
        h.update(x.as_bytes());
        h.update([0x1e]);
    }
    h.finalize().into()
}

/// Una aprobacion humana verificada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firma {
    huella: [u8; 32],
    quien: String,
}

/// Una firma que no verifica.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("la firma de aprobacion de {quien} no verifica para esta ejecucion")]
pub struct FirmaNoValida {
    /// Quien decia firmar.
    pub quien: String,
}

impl Firma {
    /// Verifica una firma de aprobacion de `quien` sobre la ejecucion del paso
    /// `paso` del flujo `flujo` con esos `objetivos`.
    ///
    /// # Errors
    ///
    /// [`FirmaNoValida`] si la firma no es de esa clave sobre esa huella.
    pub fn verificar(
        clave: &ClaveVerificacionHibrida,
        quien: &str,
        flujo: &str,
        paso: &str,
        objetivos: &[Eid],
        firma: &FirmaHibrida,
    ) -> Result<Firma, FirmaNoValida> {
        let h = huella(flujo, paso, objetivos);
        if !quien.trim().is_empty() && clave.verificar(&h, DOMINIO, firma) {
            Ok(Firma {
                huella: h,
                quien: quien.to_string(),
            })
        } else {
            Err(FirmaNoValida {
                quien: quien.to_string(),
            })
        }
    }
}

impl Permiso for Firma {
    const FIRMADO: bool = true;
    fn cubre(&self, h: &[u8; 32]) -> bool {
        &self.huella == h
    }
    fn quien(&self) -> Option<&str> {
        Some(&self.quien)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;
    use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;

    #[test]
    fn una_firma_cubre_su_ejecucion_y_ninguna_otra() {
        let clave = ClaveFirmaHibrida::generar_aleatorio().unwrap();
        let a = entidad::maquina("srv-1");
        let b = entidad::maquina("srv-2");
        let h = huella("contencion", "aislar", std::slice::from_ref(&a));
        let firma = clave.firmar(&h, DOMINIO).unwrap();
        let f = Firma::verificar(
            &clave.clave_verificacion(),
            "ana",
            "contencion",
            "aislar",
            std::slice::from_ref(&a),
            &firma,
        )
        .unwrap();
        assert!(f.cubre(&h));
        assert!(!f.cubre(&huella("contencion", "aislar", &[a.clone(), b.clone()])));
        // La misma firma no verifica para otros objetivos ni otro paso.
        assert!(Firma::verificar(
            &clave.clave_verificacion(),
            "ana",
            "contencion",
            "aislar",
            &[b],
            &firma
        )
        .is_err());
        assert!(Firma::verificar(
            &clave.clave_verificacion(),
            "ana",
            "contencion",
            "matar",
            std::slice::from_ref(&a),
            &firma
        )
        .is_err());
        // Ni sin autor.
        assert!(Firma::verificar(
            &clave.clave_verificacion(),
            " ",
            "contencion",
            "aislar",
            &[a],
            &firma
        )
        .is_err());
    }

    #[test]
    fn la_huella_no_depende_del_orden_de_los_objetivos() {
        let a = entidad::maquina("a");
        let b = entidad::maquina("b");
        assert_eq!(
            huella("f", "p", &[a.clone(), b.clone()]),
            huella("f", "p", &[b, a])
        );
    }
}
