//! Los objetos del directorio: principales de seguridad y objetos estructurales.
//!
//! # La identidad estable, y por que el SID y no el nombre
//!
//! `CORP\maria.lopez`, `maria.lopez@corp.local` y «María López» son la misma
//! persona, y ninguno de los tres es estable: la gente se casa, cambia de
//! departamento, y los dominios se migran. El identificador del directorio —el
//! **SID** en Active Directory— no cambia con nada de eso. Por eso cada principal
//! de seguridad (usuario, equipo, grupo, cuenta de servicio administrada) lleva
//! su `Eid` de clase [`aegis_entidad::Clase::Cuenta`] **derivada del SID**: es la
//! misma cuenta que ve la postura de nube (FASE 94) y el resto del producto, sin
//! correlacionar por texto.
//!
//! # Lo que NO es una cuenta
//!
//! Una GPO, una unidad organizativa, una plantilla de certificado o el propio
//! dominio son objetos del directorio, pero **no son principales de seguridad**:
//! no se puede «actuar como» una GPO. Modelarlos como cuentas seria mentir en el
//! modelo de entidad. Aqui son nodos **estructurales** del grafo, identificados
//! por su `objectGUID`, y las exposiciones que los nombran citan ese GUID y su DN
//! como evidencia; el `Eid` lo llevan los principales, que es lo que cruza
//! subsistemas.

use aegis_entidad::Eid;

/// Un SID (Security Identifier): la identidad estable de un principal.
///
/// Se guarda en su forma canonica de texto (`S-1-5-21-...-1104`). Es lo unico
/// que no cambia cuando el principal se renombra o se mueve de unidad.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid(String);

impl Sid {
    /// Construye un SID a partir de su forma de texto, normalizada a mayusculas.
    ///
    /// Un SID es insensible a mayusculas (`S-1-5-...` y `s-1-5-...` son el mismo),
    /// y normalizarlo aqui evita que el mismo principal entre dos veces en el
    /// grafo por un cambio de caja al leerlo de dos fuentes.
    #[must_use]
    pub fn nuevo(s: impl Into<String>) -> Sid {
        Sid(s.into().trim().to_ascii_uppercase())
    }

    /// El SID como texto.
    #[must_use]
    pub fn texto(&self) -> &str {
        &self.0
    }

    /// El RID (Relative Identifier): la ultima subautoridad del SID.
    ///
    /// Los RID bien conconocidos identifican principales que existen en todo
    /// dominio: 512 es «Domain Admins», 519 «Enterprise Admins», 500 el
    /// Administrador integrado. Se usan para dar nivel de privilegio sin depender
    /// del nombre, que se puede renombrar.
    #[must_use]
    pub fn rid(&self) -> Option<u32> {
        self.0.rsplit('-').next().and_then(|s| s.parse().ok())
    }

    /// Lee un SID de su forma binaria (`objectSid`, MS-DTYP 2.4.2).
    ///
    ///   Revision(1) SubAuthorityCount(1) IdentifierAuthority(6 BE) SubAuthority[N](4 LE)
    ///
    /// Devuelve `None` si los bytes no forman un SID: un `objectSid` que no cuadra
    /// no se resuelve a uno cualquiera, porque eso atribuiria a un principal lo que
    /// hizo otro.
    #[must_use]
    pub fn de_bytes(b: &[u8]) -> Option<Sid> {
        if b.len() < 8 {
            return None;
        }
        let revision = b[0];
        let sub_count = b[1] as usize;
        if sub_count > 15 || 8 + sub_count * 4 > b.len() {
            return None;
        }
        let mut autoridad: u64 = 0;
        for &x in &b[2..8] {
            autoridad = (autoridad << 8) | u64::from(x);
        }
        let mut s = format!("S-{revision}-{autoridad}");
        let mut p = 8;
        for _ in 0..sub_count {
            let sub = u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);
            s.push('-');
            s.push_str(&sub.to_string());
            p += 4;
        }
        Some(Sid::nuevo(s))
    }

    /// El `Eid` de este principal: clase `Cuenta`, derivada del SID.
    ///
    /// Es el puente con el modelo de entidad unico: la cuenta que aqui es un nodo
    /// del grafo de directorio es la MISMA `Eid` que la postura de nube atribuye a
    /// un rol y que el arbitro correlaciona.
    #[must_use]
    pub fn eid(&self) -> Eid {
        aegis_entidad::entidad::cuenta(&self.0)
    }
}

/// Un `objectGUID`: la identidad estable de un objeto del directorio que no es un
/// principal de seguridad (GPO, unidad organizativa, plantilla de certificado).
///
/// Se guarda como texto en minusculas y sin llaves, la forma canonica de un UUID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid(String);

impl Guid {
    /// Construye un GUID desde su forma de texto, normalizada.
    #[must_use]
    pub fn nuevo(s: impl Into<String>) -> Guid {
        Guid(
            s.into()
                .trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_ascii_lowercase(),
        )
    }

    /// El GUID como texto.
    #[must_use]
    pub fn texto(&self) -> &str {
        &self.0
    }
}

/// Banderas de `userAccountControl`.
///
/// Solo las que cambian el analisis de exposicion. El resto de los treinta y
/// tantos bits de UAC no dicen nada sobre quien puede sobre quien.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BanderasUac(pub u32);

impl BanderasUac {
    /// `ACCOUNTDISABLE` (0x2): la cuenta esta deshabilitada. Una cuenta
    /// deshabilitada no puede autenticarse, asi que no abre ningun camino.
    pub const DESHABILITADA: u32 = 0x0002;
    /// `DONT_EXPIRE_PASSWORD` (0x10000): la contrasena no caduca nunca. En una
    /// cuenta con privilegio es una exposicion: una credencial que no rota es una
    /// credencial que, si se filtro, sigue valiendo indefinidamente.
    pub const CLAVE_SIN_CADUCIDAD: u32 = 0x0001_0000;
    /// `TRUSTED_FOR_DELEGATION` (0x80000): delegacion **sin restricciones**. El
    /// equipo que la tiene guarda los tickets de todo el que se autentica en el,
    /// asi que comprometerlo entrega esos tickets. Es la delegacion mas peligrosa.
    pub const DELEGACION_SIN_RESTRICCIONES: u32 = 0x0008_0000;
    /// `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000): delegacion **restringida con
    /// transicion de protocolo**, que permite pedir un ticket en nombre de
    /// cualquiera sin que ese alguien se haya autenticado.
    pub const DELEGACION_CON_TRANSICION: u32 = 0x0100_0000;
    /// `NOT_DELEGATED` (0x100000): la cuenta esta marcada como sensible y **no se
    /// puede delegar**. Es una proteccion, no una exposicion: reduce el camino.
    pub const SENSIBLE_NO_DELEGABLE: u32 = 0x0010_0000;

    /// Si un bit esta puesto.
    #[must_use]
    pub fn tiene(self, bit: u32) -> bool {
        self.0 & bit != 0
    }

    /// La cuenta esta deshabilitada.
    #[must_use]
    pub fn deshabilitada(self) -> bool {
        self.tiene(Self::DESHABILITADA)
    }
}

/// Que clase de principal de seguridad es.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClasePrincipal {
    /// Una cuenta de usuario.
    Usuario,
    /// Una cuenta de equipo (un `Clase::Cuenta` por su SID, distinta de la
    /// `Clase::Maquina` de la flota, que se identifica por matriculacion).
    Equipo,
    /// Un grupo de seguridad.
    Grupo,
    /// Una cuenta de servicio administrada por grupo (gMSA).
    Gmsa,
}

impl ClasePrincipal {
    /// Nombre legible para la evidencia.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            ClasePrincipal::Usuario => "usuario",
            ClasePrincipal::Equipo => "equipo",
            ClasePrincipal::Grupo => "grupo",
            ClasePrincipal::Gmsa => "cuenta de servicio administrada",
        }
    }
}

/// Un principal de seguridad: el nodo del grafo que tiene identidad y privilegio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// La identidad estable.
    pub sid: Sid,
    /// Que clase de principal.
    pub clase: ClasePrincipal,
    /// El nombre de muestra (`sAMAccountName`), para que la evidencia se lea.
    pub nombre: String,
    /// El nombre distinguido (DN) completo, que sirve para el alcance de GPO y OU.
    pub dn: String,
    /// Las banderas de `userAccountControl`.
    pub uac: BanderasUac,
    /// `accountExpires` como FILETIME (100 ns desde 1601). `None` o el valor
    /// «nunca» (0 o `i64::MAX`) significa que la cuenta no caduca.
    pub caduca_filetime: Option<u64>,
    /// El SID objetivo de la delegacion restringida (`msDS-AllowedToDelegateTo`
    /// resuelto), si la tiene.
    pub delegacion_a: Vec<Sid>,
}

impl Principal {
    /// Construye un principal con los campos minimos.
    #[must_use]
    pub fn nuevo(sid: Sid, clase: ClasePrincipal, nombre: impl Into<String>) -> Principal {
        let nombre = nombre.into();
        Principal {
            dn: format!("CN={nombre}"),
            sid,
            clase,
            nombre,
            uac: BanderasUac::default(),
            caduca_filetime: None,
            delegacion_a: Vec::new(),
        }
    }

    /// El `Eid` de este principal.
    #[must_use]
    pub fn eid(&self) -> Eid {
        self.sid.eid()
    }

    /// Si es una cuenta con privilegio alto por su RID bien conocido.
    ///
    /// No depende del nombre —que se renombra— sino del RID, que es fijo: 512
    /// Domain Admins, 519 Enterprise Admins, 518 Schema Admins, 516 Domain
    /// Controllers, 500 el Administrador integrado.
    #[must_use]
    pub fn es_privilegiado_por_rid(&self) -> bool {
        matches!(self.sid.rid(), Some(500 | 512 | 516 | 518 | 519 | 520))
    }
}

/// Un objeto del directorio que no es un principal de seguridad.
///
/// No lleva `Eid`: no es una cuenta, y fingir que lo es partiria el modelo de
/// entidad. Se identifica por su `objectGUID` y se nombra por su DN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjetoEstructural {
    /// La identidad estable del objeto.
    pub guid: Guid,
    /// Que clase de objeto estructural.
    pub clase: ClaseEstructural,
    /// El nombre de muestra.
    pub nombre: String,
    /// El nombre distinguido completo.
    pub dn: String,
}

/// Que clase de objeto estructural del directorio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaseEstructural {
    /// Un objeto de directiva de grupo (GPO).
    Gpo,
    /// Una unidad organizativa (OU).
    UnidadOrganizativa,
    /// El objeto del dominio.
    Dominio,
    /// Una plantilla de certificado (`pKICertificateTemplate`).
    PlantillaCertificado,
    /// Una autoridad de certificacion (`pKIEnrollmentService`).
    AutoridadCertificacion,
    /// Un contenedor generico.
    Contenedor,
}

impl ClaseEstructural {
    /// Nombre legible.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            ClaseEstructural::Gpo => "GPO",
            ClaseEstructural::UnidadOrganizativa => "unidad organizativa",
            ClaseEstructural::Dominio => "dominio",
            ClaseEstructural::PlantillaCertificado => "plantilla de certificado",
            ClaseEstructural::AutoridadCertificacion => "autoridad de certificacion",
            ClaseEstructural::Contenedor => "contenedor",
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_sid_normaliza_la_caja_para_no_duplicar_el_principal() {
        let a = Sid::nuevo("S-1-5-21-AAA-512");
        let b = Sid::nuevo("s-1-5-21-aaa-512");
        assert_eq!(a, b, "el mismo SID en dos cajas es un principal, no dos");
        assert_eq!(a.eid(), b.eid());
    }

    #[test]
    fn el_rid_sale_de_la_ultima_subautoridad() {
        assert_eq!(Sid::nuevo("S-1-5-21-1-2-3-512").rid(), Some(512));
        assert_eq!(Sid::nuevo("S-1-5-18").rid(), Some(18));
        assert_eq!(Sid::nuevo("no-es-un-sid").rid(), None);
    }

    #[test]
    fn el_eid_de_un_principal_es_una_cuenta_del_modelo_unico() {
        let p = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-1104"),
            ClasePrincipal::Usuario,
            "maria.lopez",
        );
        assert_eq!(p.eid().clase(), aegis_entidad::Clase::Cuenta);
        // Y coincide con la misma cuenta derivada del SID en otro subsistema.
        assert_eq!(
            p.eid(),
            aegis_entidad::entidad::cuenta("S-1-5-21-1-2-3-1104")
        );
    }

    #[test]
    fn los_privilegiados_se_reconocen_por_rid_no_por_nombre() {
        // Un Domain Admins renombrado sigue siendo Domain Admins por su RID 512.
        let da = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-512"),
            ClasePrincipal::Grupo,
            "grupo-renombrado-a-proposito",
        );
        assert!(da.es_privilegiado_por_rid());
        let raso = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-1104"),
            ClasePrincipal::Usuario,
            "Administrador de Dominio (nombre enganoso)",
        );
        assert!(
            !raso.es_privilegiado_por_rid(),
            "el nombre no da privilegio"
        );
    }

    #[test]
    fn las_banderas_uac_leen_los_bits_que_cambian_el_analisis() {
        let u = BanderasUac(BanderasUac::DELEGACION_SIN_RESTRICCIONES | BanderasUac::DESHABILITADA);
        assert!(u.tiene(BanderasUac::DELEGACION_SIN_RESTRICCIONES));
        assert!(u.deshabilitada());
        assert!(!u.tiene(BanderasUac::CLAVE_SIN_CADUCIDAD));
    }

    #[test]
    fn el_guid_se_normaliza_sin_llaves_ni_mayusculas() {
        assert_eq!(
            Guid::nuevo("{AB12CD34-0000-0000-0000-000000000000}").texto(),
            "ab12cd34-0000-0000-0000-000000000000"
        );
    }
}
