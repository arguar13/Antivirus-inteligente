//! Las tres delegaciones de Kerberos, que son tres caminos distintos.
//!
//! La delegacion permite que un servicio actue en nombre de un usuario. Bien
//! usada, es como funciona un servidor web que accede a una base de datos por ti.
//! Mal configurada, es uno de los caminos de escalada mas usados, y hay tres
//! formas de que este mal:
//!
//! 1. **Sin restricciones** (`TRUSTED_FOR_DELEGATION`): el equipo guarda el ticket
//!    de todo el que se autentica en el. Es una propiedad del equipo, no una
//!    arista hacia un objetivo, y se trata como exposicion.
//! 2. **Restringida** (`msDS-AllowedToDelegateTo`): el principal puede delegar solo
//!    hacia servicios concretos. Cada objetivo es una arista.
//! 3. **Basada en recursos** (`msDS-AllowedToActOnBehalfOfOtherIdentity`): el
//!    objetivo declara quien puede actuar en su nombre. Ese atributo es un
//!    **descriptor de seguridad**, y los principales de su DACL son los que
//!    pueden suplantar ante el objetivo.
//!
//! Este modulo convierte esos atributos, ya leidos del directorio, en aristas del
//! grafo. El parseo del descriptor de la delegacion basada en recursos reutiliza
//! el mismo lector byte a byte que las ACL ([`super::descriptor`]).

use super::descriptor::{self, DescriptorMalFormado};
use super::objeto::{Principal, Sid};
use super::relacion::{Arista, RelacionDirectorio};

/// Las aristas de delegacion restringida de un principal: una por cada servicio
/// hacia el que puede delegar (`msDS-AllowedToDelegateTo` ya resuelto a SID).
#[must_use]
pub fn aristas_delegacion_restringida(p: &Principal) -> Vec<Arista> {
    p.delegacion_a
        .iter()
        .map(|objetivo| {
            Arista::permanente(&p.sid, objetivo, RelacionDirectorio::DelegacionRestringida)
        })
        .collect()
}

/// Las aristas de delegacion basada en recursos hacia un objetivo, sacadas del
/// descriptor de seguridad de su `msDS-AllowedToActOnBehalfOfOtherIdentity`.
///
/// Cada principal de la DACL puede actuar en nombre de otros ante el objetivo, asi
/// que la arista va `principal_permitido -> objetivo`.
///
/// # Errores
/// [`DescriptorMalFormado`] si el atributo no es un descriptor bien formado.
pub fn aristas_delegacion_rbcd(
    objetivo: &Sid,
    atributo_rbcd: &[u8],
) -> Result<Vec<Arista>, DescriptorMalFormado> {
    let permitidos = descriptor::sids_permitidos(atributo_rbcd)?;
    Ok(permitidos
        .into_iter()
        .filter(|s| s != objetivo)
        .map(|permitido| {
            Arista::permanente(
                &permitido,
                objetivo,
                RelacionDirectorio::DelegacionBasadaEnRecursos,
            )
        })
        .collect())
}

#[cfg(test)]
mod pruebas {
    use super::super::objeto::ClasePrincipal;
    use super::*;

    #[test]
    fn la_delegacion_restringida_produce_una_arista_por_objetivo() {
        let mut p = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-2001"),
            ClasePrincipal::Equipo,
            "WEB01$",
        );
        p.delegacion_a = vec![
            Sid::nuevo("S-1-5-21-1-2-3-2100"),
            Sid::nuevo("S-1-5-21-1-2-3-2101"),
        ];
        let aristas = aristas_delegacion_restringida(&p);
        assert_eq!(aristas.len(), 2);
        assert!(aristas
            .iter()
            .all(|a| a.relacion == RelacionDirectorio::DelegacionRestringida));
        assert!(aristas.iter().all(|a| a.origen == "S-1-5-21-1-2-3-2001"));
    }

    /// Un descriptor de seguridad minimo con un ACE de acceso concedido a un SID.
    fn rbcd_con(rid: u32) -> Vec<u8> {
        // SID S-1-5-21-1-2-3-rid.
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, rid] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        // ACE de acceso concedido (mascara cualquiera; en RBCD basta la presencia).
        let ace_size = 8 + sid.len();
        let mut ace = vec![0u8, 0];
        ace.extend_from_slice(&(ace_size as u16).to_le_bytes());
        ace.extend_from_slice(&0x1000_0000u32.to_le_bytes());
        ace.extend_from_slice(&sid);
        // ACL.
        let acl_size = 8 + ace.len();
        let mut acl = vec![2u8, 0];
        acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
        acl.extend_from_slice(&1u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&ace);
        // Descriptor con DACL presente, sin propietario.
        let mut sd = vec![1u8, 0];
        sd.extend_from_slice(&0x0004u16.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes()); // owner
        sd.extend_from_slice(&0u32.to_le_bytes()); // group
        sd.extend_from_slice(&0u32.to_le_bytes()); // sacl
        sd.extend_from_slice(&20u32.to_le_bytes()); // dacl offset
        sd.extend_from_slice(&acl);
        sd
    }

    #[test]
    fn la_delegacion_basada_en_recursos_sale_del_descriptor() {
        let objetivo = Sid::nuevo("S-1-5-21-1-2-3-2200");
        let aristas =
            aristas_delegacion_rbcd(&objetivo, &rbcd_con(1104)).expect("descriptor valido");
        assert_eq!(aristas.len(), 1);
        assert_eq!(aristas[0].origen, "S-1-5-21-1-2-3-1104");
        assert_eq!(aristas[0].destino, "S-1-5-21-1-2-3-2200");
        assert_eq!(
            aristas[0].relacion,
            RelacionDirectorio::DelegacionBasadaEnRecursos
        );
    }

    #[test]
    fn un_atributo_rbcd_corrupto_da_su_motivo_no_una_lista_vacia() {
        let objetivo = Sid::nuevo("S-1-5-21-1-2-3-2200");
        assert!(aristas_delegacion_rbcd(&objetivo, &[0u8; 4]).is_err());
    }
}
