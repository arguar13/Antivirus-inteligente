//! El colector de directorio: solo lectura, y con el analisis separado de la red.
//!
//! # La frontera walled, y por que esta separada
//!
//! Leer un Active Directory por LDAP necesita un dominio real al que ligarse:
//! esa es la frontera de esta fase, igual que la captura de eventos 4769 lo es
//! del nucleo Kerberos. Pero el trabajo que DECIDE —convertir los registros del
//! directorio en principales, aristas y exposiciones— no necesita red, y por eso
//! esta aqui, sobre registros [`EntradaLdap`] en memoria, y se prueba entero.
//!
//! Un doble solo puede sustituir la **frontera** (el servidor LDAP), nunca una
//! decision. Por eso [`FuenteDirectorio`] es un rasgo con una sola operacion de
//! lectura, y la logica de [`construir_grafo`] es identica venga de un servidor
//! real o de un lote de registros de prueba construidos con SID y descriptores de
//! seguridad binarios reales.
//!
//! # Solo lectura, por construccion
//!
//! El rasgo no tiene ninguna operacion de escritura, y el lector en vivo se liga,
//! busca y se desliga. Un colector que pudiera escribir en el directorio seria una
//! herramienta de ataque; aqui la ausencia de esa operacion es la frontera.

use std::collections::BTreeMap;

use super::descriptor::DescriptorMalFormado;
use super::exposicion::Hueco;
use super::objeto::{BanderasUac, ClasePrincipal, Principal, Sid};
use super::relacion::{Arista, RelacionDirectorio};
use super::{delegacion, GrafoDirectorio};
use crate::ItdrError;

/// Un registro del directorio, tal como lo devuelve una busqueda LDAP: su DN y
/// sus atributos. Los atributos binarios (`objectSid`, `ntSecurityDescriptor`)
/// llegan como bytes; el resto, como texto.
#[derive(Debug, Clone, Default)]
pub struct EntradaLdap {
    /// El nombre distinguido.
    pub dn: String,
    /// Atributos de texto: nombre -> valores.
    pub texto: BTreeMap<String, Vec<String>>,
    /// Atributos binarios: nombre -> valores.
    pub binario: BTreeMap<String, Vec<Vec<u8>>>,
}

impl EntradaLdap {
    /// Un registro con solo su DN.
    #[must_use]
    pub fn nueva(dn: impl Into<String>) -> EntradaLdap {
        EntradaLdap {
            dn: dn.into(),
            ..EntradaLdap::default()
        }
    }

    /// Fija un atributo de texto (encadenable).
    #[must_use]
    pub fn con_texto(mut self, nombre: &str, valores: &[&str]) -> EntradaLdap {
        self.texto.insert(
            nombre.to_ascii_lowercase(),
            valores.iter().map(|s| (*s).to_string()).collect(),
        );
        self
    }

    /// Fija un atributo binario (encadenable).
    #[must_use]
    pub fn con_binario(mut self, nombre: &str, valor: Vec<u8>) -> EntradaLdap {
        self.binario
            .insert(nombre.to_ascii_lowercase(), vec![valor]);
        self
    }

    /// El primer valor de texto de un atributo.
    #[must_use]
    pub fn texto1(&self, nombre: &str) -> Option<&str> {
        self.texto
            .get(&nombre.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Todos los valores de texto de un atributo.
    #[must_use]
    pub fn textos(&self, nombre: &str) -> &[String] {
        self.texto
            .get(&nombre.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// El primer valor binario de un atributo.
    #[must_use]
    pub fn binario1(&self, nombre: &str) -> Option<&[u8]> {
        self.binario
            .get(&nombre.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(Vec::as_slice)
    }

    /// La clase de principal segun `objectClass`, si es un principal de seguridad.
    #[must_use]
    pub fn clase_principal(&self) -> Option<ClasePrincipal> {
        let clases: Vec<String> = self
            .textos("objectclass")
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if clases
            .iter()
            .any(|c| c == "msds-groupmanagedserviceaccount")
        {
            Some(ClasePrincipal::Gmsa)
        } else if clases.iter().any(|c| c == "computer") {
            Some(ClasePrincipal::Equipo)
        } else if clases.iter().any(|c| c == "group") {
            Some(ClasePrincipal::Grupo)
        } else if clases.iter().any(|c| c == "user") {
            Some(ClasePrincipal::Usuario)
        } else {
            None
        }
    }
}

/// La fuente de registros del directorio: la unica frontera con la red.
///
/// Solo lectura: no hay ninguna operacion que escriba en el directorio.
pub trait FuenteDirectorio {
    /// Devuelve los registros del directorio.
    ///
    /// # Errores
    /// [`ItdrError`] si la fuente no se pudo consultar.
    fn entradas(&self) -> Result<Vec<EntradaLdap>, ItdrError>;
}

/// Un lote de registros ya recolectados, como fuente. Es lo que usa la frontera
/// en vivo tras leerlos, y lo que usan las pruebas con registros reales.
pub struct Lote(pub Vec<EntradaLdap>);

impl FuenteDirectorio for Lote {
    fn entradas(&self) -> Result<Vec<EntradaLdap>, ItdrError> {
        Ok(self.0.clone())
    }
}

/// Construye el grafo del directorio a partir de los registros, declarando como
/// **hueco** todo lo que no se pudo interpretar en vez de callarlo.
///
/// # Errores
/// [`ItdrError`] si la fuente no se pudo consultar.
pub fn construir_grafo(
    fuente: &dyn FuenteDirectorio,
) -> Result<(GrafoDirectorio, Vec<Hueco>), ItdrError> {
    let entradas = fuente.entradas()?;
    let mut g = GrafoDirectorio::nuevo();
    let mut huecos: Vec<Hueco> = Vec::new();

    // Primera pasada: los principales y el indice DN -> SID, que hace falta para
    // resolver las pertenencias, que en el directorio van por DN y no por SID.
    let mut dn_a_sid: BTreeMap<String, Sid> = BTreeMap::new();
    for e in &entradas {
        let Some(clase) = e.clase_principal() else {
            continue;
        };
        let Some(bytes) = e.binario1("objectsid") else {
            huecos.push(Hueco::nuevo(
                e.dn.clone(),
                "sin objectSid legible: no se pudo dar identidad estable al principal",
            ));
            continue;
        };
        let Some(sid) = Sid::de_bytes(bytes) else {
            huecos.push(Hueco::nuevo(e.dn.clone(), "objectSid mal formado"));
            continue;
        };
        let nombre = e
            .texto1("samaccountname")
            .or_else(|| e.texto1("cn"))
            .unwrap_or(&e.dn)
            .to_string();
        let mut p = Principal::nuevo(sid.clone(), clase, nombre);
        p.dn = e.dn.clone();
        if let Some(uac) = e
            .texto1("useraccountcontrol")
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            p.uac = BanderasUac(uac);
        }
        if let Some(exp) = e
            .texto1("accountexpires")
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            // 0 y i64::MAX significan «nunca»; cualquier otro es una caducidad.
            if exp != 0 && exp != u64::from(u32::MAX) && exp != i64::MAX as u64 {
                p.caduca_filetime = Some(exp);
            }
        }
        dn_a_sid.insert(e.dn.to_ascii_lowercase(), sid.clone());
        g.agregar_principal(p)?;
    }

    // Segunda pasada: las aristas.
    for e in &entradas {
        let Some(_) = e.clase_principal() else {
            continue;
        };
        let Some(bytes) = e.binario1("objectsid") else {
            continue;
        };
        let Some(sid) = Sid::de_bytes(bytes) else {
            continue;
        };

        // Pertenencia: el atributo `member` lista DN; se resuelven a SID.
        for dn_miembro in e.textos("member") {
            match dn_a_sid.get(&dn_miembro.to_ascii_lowercase()) {
                Some(miembro) => {
                    let _ = g.conectar(Arista::permanente(
                        miembro,
                        &sid,
                        RelacionDirectorio::MiembroDe,
                    ));
                }
                None => huecos.push(Hueco::nuevo(
                    format!("miembro «{dn_miembro}» de «{}»", e.dn),
                    "el DN del miembro no esta entre los principales leidos",
                )),
            }
        }

        // Control por ACL: del descriptor de seguridad del objeto.
        if let Some(sd) = e.binario1("ntsecuritydescriptor") {
            if let Err(DescriptorMalFormado(m)) = g.incorporar_descriptor(&sid, sd) {
                huecos.push(Hueco::nuevo(
                    format!("ntSecurityDescriptor de «{}»", e.dn),
                    format!("descriptor mal formado: {m}"),
                ));
            }
        }

        // Delegacion basada en recursos: el atributo es un descriptor de seguridad.
        if let Some(rbcd) = e.binario1("msds-allowedtoactonbehalfofotheridentity") {
            match delegacion::aristas_delegacion_rbcd(&sid, rbcd) {
                Ok(aristas) => {
                    for a in aristas {
                        let _ = g.conectar(a);
                    }
                }
                Err(DescriptorMalFormado(m)) => huecos.push(Hueco::nuevo(
                    format!("msDS-AllowedToActOnBehalfOfOtherIdentity de «{}»", e.dn),
                    format!("descriptor mal formado: {m}"),
                )),
            }
        }
    }

    Ok((g, huecos))
}

// ── Frontera en vivo: el lector LDAP de solo lectura ─────────────────────────────
//
// Solo se compila con la caracteristica `live-ldap`, para no arrastrar un cliente
// LDAP en el arbol por defecto. Es la unica parte que habla con la red.
#[cfg(feature = "live-ldap")]
pub use vivo::LectorLdap;

#[cfg(feature = "live-ldap")]
mod vivo {
    use super::{EntradaLdap, FuenteDirectorio};
    use crate::ItdrError;
    use ldap3::{LdapConn, Scope, SearchEntry};

    /// Un lector LDAP de **solo lectura** contra un directorio real.
    ///
    /// Se liga, busca y se desliga. No tiene ninguna operacion de escritura.
    pub struct LectorLdap {
        /// URL del servidor, p. ej. `ldaps://dc.corp.local:636`.
        pub url: String,
        /// DN base de la busqueda, p. ej. `DC=corp,DC=local`.
        pub base: String,
        /// DN de enlace y contrasena, o `None` para enlace anonimo.
        pub credenciales: Option<(String, String)>,
    }

    impl FuenteDirectorio for LectorLdap {
        fn entradas(&self) -> Result<Vec<EntradaLdap>, ItdrError> {
            let mut ldap = LdapConn::new(&self.url).map_err(|e| {
                ItdrError::IdentidadDesconocida(format!("no se pudo conectar: {e}"))
            })?;
            match &self.credenciales {
                Some((dn, clave)) => {
                    ldap.simple_bind(dn, clave)
                        .and_then(ldap3::LdapResult::success)
                        .map_err(|e| ItdrError::IdentidadDesconocida(format!("enlace: {e}")))?;
                }
                None => {}
            }
            // Los atributos que el analisis necesita. El descriptor de seguridad
            // exige el control de servidor para que se devuelva la DACL.
            let atributos = vec![
                "objectClass",
                "objectSid",
                "sAMAccountName",
                "cn",
                "userAccountControl",
                "accountExpires",
                "member",
                "ntSecurityDescriptor",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "msDS-AllowedToDelegateTo",
            ];
            let (rs, _res) = ldap
                .search(
                    &self.base,
                    Scope::Subtree,
                    "(|(objectClass=user)(objectClass=computer)(objectClass=group))",
                    atributos,
                )
                .and_then(ldap3::SearchResult::success)
                .map_err(|e| ItdrError::IdentidadDesconocida(format!("busqueda: {e}")))?;

            let mut salida = Vec::with_capacity(rs.len());
            for entrada in rs {
                let se = SearchEntry::construct(entrada);
                let mut e = EntradaLdap::nueva(se.dn.clone());
                for (k, v) in se.attrs {
                    e.texto.insert(k.to_ascii_lowercase(), v);
                }
                for (k, v) in se.bin_attrs {
                    e.binario.insert(k.to_ascii_lowercase(), v);
                }
                salida.push(e);
            }
            let _ = ldap.unbind();
            Ok(salida)
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::directorio::exposicion::ClaseExposicion;

    /// Un objectSid binario `S-1-5-21-1-2-3-rid`.
    fn sid_bin(rid: u32) -> Vec<u8> {
        let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, rid] {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// Un descriptor con un ACE de WriteDacl para un trustee.
    fn sd_writedacl(rid_trustee: u32) -> Vec<u8> {
        let sid = sid_bin(rid_trustee);
        let ace_size = 8 + sid.len();
        let mut ace = vec![0u8, 0];
        ace.extend_from_slice(&(ace_size as u16).to_le_bytes());
        ace.extend_from_slice(&0x0004_0000u32.to_le_bytes()); // WRITE_DAC
        ace.extend_from_slice(&sid);
        let acl_size = 8 + ace.len();
        let mut acl = vec![2u8, 0];
        acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
        acl.extend_from_slice(&1u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&ace);
        let mut sd = vec![1u8, 0];
        sd.extend_from_slice(&0x0004u16.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&20u32.to_le_bytes());
        sd.extend_from_slice(&acl);
        sd
    }

    #[test]
    fn construir_grafo_desde_registros_reales_arma_principales_y_pertenencias() {
        let da = EntradaLdap::nueva("CN=Domain Admins,CN=Users,DC=corp,DC=local")
            .con_texto("objectClass", &["group"])
            .con_texto("sAMAccountName", &["Domain Admins"])
            .con_texto("member", &["CN=alice,CN=Users,DC=corp,DC=local"])
            .con_binario("objectSid", sid_bin(512));
        let alice = EntradaLdap::nueva("CN=alice,CN=Users,DC=corp,DC=local")
            .con_texto("objectClass", &["user"])
            .con_texto("sAMAccountName", &["alice"])
            .con_binario("objectSid", sid_bin(1104));

        let (g, huecos) = construir_grafo(&Lote(vec![da, alice])).expect("construccion");
        assert_eq!(g.principales(), 2);
        assert!(huecos.is_empty(), "todo se resolvio: {huecos:?}");
        let miembros = g.miembros_efectivos(&Sid::nuevo("S-1-5-21-1-2-3-512"));
        assert!(miembros.contains(&Sid::nuevo("S-1-5-21-1-2-3-1104")));
    }

    #[test]
    fn una_acl_del_descriptor_se_convierte_en_arista_y_en_exposicion() {
        let da = EntradaLdap::nueva("CN=Domain Admins,CN=Users,DC=corp,DC=local")
            .con_texto("objectClass", &["group"])
            .con_texto("sAMAccountName", &["Domain Admins"])
            .con_binario("objectSid", sid_bin(512))
            // El becario (RID 1104) tiene WriteDacl sobre Domain Admins.
            .con_binario("ntSecurityDescriptor", sd_writedacl(1104));
        let becario = EntradaLdap::nueva("CN=becario,CN=Users,DC=corp,DC=local")
            .con_texto("objectClass", &["user"])
            .con_texto("sAMAccountName", &["becario"])
            .con_binario("objectSid", sid_bin(1104));

        let (g, _h) = construir_grafo(&Lote(vec![da, becario])).unwrap();
        let inf = g.auditar();
        assert!(
            inf.exposiciones
                .iter()
                .any(|e| e.clase == ClaseExposicion::AclPeligrosa),
            "la ACL peligrosa leida del descriptor real se detecta"
        );
    }

    #[test]
    fn un_miembro_sin_su_objeto_es_un_hueco_no_una_ausencia() {
        // El grupo apunta a un DN que no vino en el lote: se declara hueco.
        let grupo = EntradaLdap::nueva("CN=G,DC=corp,DC=local")
            .con_texto("objectClass", &["group"])
            .con_texto("sAMAccountName", &["G"])
            .con_texto("member", &["CN=fantasma,DC=corp,DC=local"])
            .con_binario("objectSid", sid_bin(600));
        let (_g, huecos) = construir_grafo(&Lote(vec![grupo])).unwrap();
        assert!(
            huecos.iter().any(|h| h.que.contains("fantasma")),
            "un miembro sin objeto es un hueco declarado, no un grupo vacio"
        );
    }

    #[test]
    fn un_objectsid_ausente_es_un_hueco() {
        let sin_sid = EntradaLdap::nueva("CN=roto,DC=corp,DC=local")
            .con_texto("objectClass", &["user"])
            .con_texto("sAMAccountName", &["roto"]);
        let (g, huecos) = construir_grafo(&Lote(vec![sin_sid])).unwrap();
        assert_eq!(g.principales(), 0);
        assert!(huecos.iter().any(|h| h.motivo.contains("objectSid")));
    }
}
