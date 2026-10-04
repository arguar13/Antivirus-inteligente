//! Apagado individual y bajada a auditoria, sin republicar el paquete.
//!
//! # Por que un documento aparte
//!
//! Apagar una regla que esta disparando sobre software legitimo en toda la flota
//! no puede esperar a que un paquete nuevo suba la escalera canario -> 5 % ->
//! flota. Los ajustes son un documento pequeño, firmado con SU dominio
//! ([`CTX_AJUSTES`]) y con SU epoca monotona, que se aplica a todo el canal de
//! golpe.
//!
//! # Solo restan
//!
//! Un ajuste puede apagar una regla o bajarla de imponer a auditoria. No existe
//! la variante que sube: esa decision la gobiernan los numeros medidos y viaja
//! en el paquete, que pasa por la puerta de publicacion. Asi el camino rapido no
//! puede convertirse en la forma de saltarse la puerta.

use std::collections::BTreeMap;

use crate::codificacion::{ErrorFormato, Escritor, Lector};
use crate::paquete::{id_valido, MAX_CANAL, MAX_ENTRADAS, MAX_ID};

/// Marca de un documento de ajustes.
pub const MAGIA_AJUSTES: &[u8; 8] = b"AEGISAJU";
/// Version del formato.
pub const VERSION_AJUSTES: u32 = 1;
/// Contexto de dominio de la firma de unos ajustes.
pub const CTX_AJUSTES: &[u8] = b"aegiscore/contenido/ajustes/v1";

/// Lo que un ajuste le hace a una regla. Solo resta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rebaja {
    /// La regla no se carga.
    Apagar,
    /// La regla se carga en auditoria aunque el paquete diga imponer.
    Auditoria,
}

/// Documento de ajustes del canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ajustes {
    /// Canal al que se aplica.
    pub canal: String,
    /// Epoca monotona propia de los ajustes.
    pub epoca: u64,
    /// Rebajas por identificador de regla.
    pub rebajas: BTreeMap<String, Rebaja>,
}

impl Ajustes {
    /// Codificacion canonica (identificadores en orden).
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut e = Escritor::nuevo();
        e.fijo(MAGIA_AJUSTES);
        e.u32(VERSION_AJUSTES);
        e.texto(&self.canal);
        e.u64(self.epoca);
        e.cuenta(self.rebajas.len());
        for (id, r) in &self.rebajas {
            e.texto(id);
            e.u8(match r {
                Rebaja::Apagar => 0,
                Rebaja::Auditoria => 1,
            });
        }
        e.fin()
    }

    /// Lee unos ajustes.
    ///
    /// # Errores
    /// [`ErrorFormato`] si no son canonicos (identificadores fuera de orden o
    /// repetidos incluidos).
    pub fn de_bytes(b: &[u8]) -> Result<Ajustes, ErrorFormato> {
        let mut l = Lector::nuevo(b);
        if l.fijo(8).ok() != Some(&MAGIA_AJUSTES[..]) {
            return Err(ErrorFormato(
                "no son ajustes de contenido de AegisCore".into(),
            ));
        }
        let version = l.u32()?;
        if version != VERSION_AJUSTES {
            return Err(ErrorFormato(format!("ajustes de la version {version}")));
        }
        let canal = l.texto(MAX_CANAL, "canal")?.to_string();
        let epoca = l.u64()?;
        let n = l.cuenta(MAX_ENTRADAS, "rebajas")?;
        let mut rebajas = BTreeMap::new();
        let mut anterior: Option<String> = None;
        for _ in 0..n {
            let id = l.texto(MAX_ID, "id de regla")?.to_string();
            if !id_valido(&id) {
                return Err(ErrorFormato(format!("identificador «{id}» invalido")));
            }
            if anterior.as_deref().is_some_and(|a| a >= id.as_str()) {
                return Err(ErrorFormato("rebajas fuera de orden o repetidas".into()));
            }
            let r = match l.u8()? {
                0 => Rebaja::Apagar,
                1 => Rebaja::Auditoria,
                x => return Err(ErrorFormato(format!("rebaja desconocida: {x}"))),
            };
            anterior = Some(id.clone());
            rebajas.insert(id, r);
        }
        l.terminar()?;
        Ok(Ajustes {
            canal,
            epoca,
            rebajas,
        })
    }

    /// La rebaja de una regla, si la hay.
    #[must_use]
    pub fn rebaja(&self, id: &str) -> Option<Rebaja> {
        self.rebajas.get(id).copied()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_ajustes_van_y_vuelven() {
        let mut rebajas = BTreeMap::new();
        rebajas.insert("B".to_string(), Rebaja::Auditoria);
        rebajas.insert("A".to_string(), Rebaja::Apagar);
        let a = Ajustes {
            canal: "estable".into(),
            epoca: 4,
            rebajas,
        };
        let b = Ajustes::de_bytes(&a.a_bytes()).unwrap();
        assert_eq!(a, b);
        assert_eq!(b.rebaja("A"), Some(Rebaja::Apagar));
        assert_eq!(b.rebaja("C"), None);
    }
}
