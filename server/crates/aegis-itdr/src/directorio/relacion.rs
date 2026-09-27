//! Las relaciones del directorio: el conjunto de aristas que modela quien puede
//! sobre quien, con la **vigencia** de cada una.
//!
//! # Por que la vigencia esta en la arista, y por que eso gana a BloodHound
//!
//! BloodHound modela «alice tiene una sesion en pc-01» como un hecho sin tiempo.
//! Pero una sesion caduca: el ticket expira, el usuario cierra sesion, la
//! credencial cacheada se limpia. Un camino de ataque que depende de una sesion
//! que caduco hace dos meses **es un camino que ya no existe**, y actuar sobre el
//! es actuar sobre informacion vieja.
//!
//! Aqui cada arista lleva su [`Vigencia`]. Las relaciones **estructurales**
//! —pertenecer a un grupo, tener una ACL peligrosa sobre un objeto— son
//! [`Vigencia::Permanente`]: valen hasta que el directorio cambie. Las
//! relaciones **temporales** —una sesion viva, una credencial cacheada— llevan
//! una [`Ventana`] con su caducidad, y una consulta hecha en un instante solo ve
//! las que valen en ese instante. Esa es la diferencia que hace que el mismo
//! grafo, evaluado antes y despues de caducar una sesion, de un camino distinto.

use super::objeto::Sid;

/// Un instante, en segundos desde el epoch Unix.
///
/// El grafo del directorio se evalua «en un instante»: que caminos existen AHORA
/// depende de que sesiones siguen vivas ahora.
pub type Instante = u64;

/// La vigencia de una arista: hasta cuando vale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vigencia {
    /// Vale hasta que el directorio cambie: pertenencias, ACL, delegaciones.
    Permanente,
    /// Vale solo dentro de una ventana de tiempo: sesiones y credenciales.
    Ventana(Ventana),
}

impl Vigencia {
    /// Si la arista esta vigente en un instante.
    #[must_use]
    pub fn vigente_en(&self, t: Instante) -> bool {
        match self {
            Vigencia::Permanente => true,
            Vigencia::Ventana(v) => v.contiene(t),
        }
    }
}

/// La ventana de validez de una sesion o una credencial cacheada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ventana {
    /// Desde cuando (segundos Unix), inclusive.
    pub desde: Instante,
    /// Hasta cuando (segundos Unix), exclusivo. La caducidad.
    pub hasta: Instante,
}

impl Ventana {
    /// Una ventana `[desde, hasta)`.
    #[must_use]
    pub fn nueva(desde: Instante, hasta: Instante) -> Ventana {
        Ventana { desde, hasta }
    }

    /// Si el instante cae dentro de la ventana.
    #[must_use]
    pub fn contiene(&self, t: Instante) -> bool {
        self.desde <= t && t < self.hasta
    }
}

/// Direccion de una relacion de confianza entre dominios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DireccionConfianza {
    /// El dominio de origen confia en el de destino: los principales del destino
    /// pueden usarse en el origen. Es la direccion que abre un camino de ataque.
    Entrante,
    /// El origen es confiado por el destino.
    Saliente,
    /// Confianza en ambos sentidos.
    Bidireccional,
}

/// Tipo de una relacion de confianza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoConfianza {
    /// Padre-hijo dentro del mismo arbol: transitiva por defecto.
    PadreHijo,
    /// Raiz de arbol dentro del mismo bosque.
    RaizArbol,
    /// Entre bosques distintos.
    Bosque,
    /// Externa a un dominio suelto: no transitiva.
    Externa,
    /// Con un reino Kerberos ajeno (no AD).
    Reino,
}

/// Una relacion del directorio: el tipo de la arista `origen -> destino`, con el
/// significado «controlar el origen permite obtener/actuar sobre el destino».
///
/// Es el conjunto que modela BloodHound —pertenencia, ACL, delegacion, derechos
/// de ejecucion, GPO, confianzas, certificados— **mas** el alcance por red, que
/// BloodHound no tiene porque no ve el endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelacionDirectorio {
    // ── Pertenencia ────────────────────────────────────────────────────────────
    /// Es miembro de un grupo (`MemberOf`). Se resuelve de forma anidada.
    MiembroDe,

    // ── Control por ACL (los que abren la escalada silenciosa) ───────────────────
    /// Es el propietario del objeto (`Owns`): puede reescribir su DACL.
    Posee,
    /// `GenericAll`: control total sobre el objeto.
    ControlTotal,
    /// `GenericWrite`: escritura de la mayoria de atributos.
    EscrituraGenerica,
    /// `WriteDacl`: puede reescribir la lista de control de acceso, y con ella
    /// darse cualquier permiso.
    EscrituraDacl,
    /// `WriteOwner`: puede hacerse propietario, y de ahi reescribir la DACL.
    EscrituraPropietario,
    /// Puede anadir miembros al grupo (`AddMember`, escritura del atributo
    /// `member`).
    AnadirMiembro,
    /// Puede forzar el cambio de contrasena del principal (derecho extendido
    /// `User-Force-Change-Password`).
    ForzarCambioClave,
    /// Tiene todos los derechos extendidos sobre el objeto (`AllExtendedRights`),
    /// que incluye leer secretos como la contrasena de gMSA o LAPS.
    TodosDerechosExtendidos,
    /// Puede leer la contrasena de LAPS del equipo.
    LeerLaps,
    /// Puede leer la contrasena administrada de una gMSA.
    LeerGmsa,
    /// Tiene los derechos de replicacion del directorio (`DS-Replication-Get-Changes`
    /// y su variante `-All`): puede pedir los hashes de todo el dominio. Es el
    /// privilegio que convierte «control sobre una cuenta» en «control del dominio».
    ReplicaDirectorio,

    // ── Delegacion ───────────────────────────────────────────────────────────────
    /// El equipo tiene delegacion sin restricciones: guarda los tickets de todo
    /// el que se autentica en el (`TRUSTED_FOR_DELEGATION`).
    DelegacionSinRestricciones,
    /// Delegacion restringida hacia un servicio concreto
    /// (`msDS-AllowedToDelegateTo`).
    DelegacionRestringida,
    /// Delegacion restringida basada en recursos (`msDS-AllowedToActOnBehalfOf...`):
    /// el destino permite que el origen actue en su nombre.
    DelegacionBasadaEnRecursos,

    // ── Derechos de ejecucion sobre un host ──────────────────────────────────────
    /// Es administrador local del equipo (`AdminTo`).
    AdminLocalDe,
    /// Tiene derecho de escritorio remoto sobre el equipo (`CanRDP`).
    PuedeRdp,
    /// Puede ejecutar por DCOM sobre el equipo (`ExecuteDCOM`).
    PuedeDcom,
    /// Puede ejecutar por PowerShell Remoting sobre el equipo (`CanPSRemote`).
    PuedePsRemote,

    // ── Sesiones y credenciales (las temporales) ─────────────────────────────────
    /// Tiene una sesion viva en el equipo (`HasSession`): sus credenciales estan
    /// en memoria alli. Lleva ventana de vigencia.
    SesionEn,
    /// Tiene una credencial cacheada del principal (`HasCachedCredential`). Lleva
    /// ventana de vigencia.
    CredencialCacheadaDe,

    // ── GPO y jerarquia ──────────────────────────────────────────────────────────
    /// La GPO se aplica al objeto (`GpLink`). `impuesta` indica si el enlace esta
    /// marcado como forzado (no lo detiene un bloqueo de herencia).
    EnlazaGpo {
        /// Si el enlace esta forzado (`enforced`/`gpLink` con la bandera puesta).
        impuesta: bool,
    },
    /// El contenedor (OU/dominio) contiene al objeto (`Contains`), para el alcance
    /// de las GPO y la herencia. `bloquea_herencia` corta las GPO no impuestas de
    /// arriba.
    Contiene {
        /// Si el contenedor bloquea la herencia de directivas.
        bloquea_herencia: bool,
    },

    // ── Confianzas entre dominios y bosques ──────────────────────────────────────
    /// Una relacion de confianza, con su direccion, su tipo y si es transitiva.
    ConfiaEn {
        /// La direccion de la confianza.
        direccion: DireccionConfianza,
        /// El tipo de la confianza.
        tipo: TipoConfianza,
        /// Si la confianza es transitiva.
        transitiva: bool,
    },

    // ── Certificados (la familia ESC) ────────────────────────────────────────────
    /// Puede inscribir un certificado con la plantilla (`Enroll`).
    InscribeEn,
    /// Puede autoinscribirse con la plantilla (`AutoEnroll`).
    AutoInscribeEn,
    /// La plantilla esta publicada en la autoridad de certificacion.
    PublicadaEn,

    // ── Alcance por red (lo que BloodHound no tiene) ─────────────────────────────
    /// El origen alcanza por red un servicio expuesto del destino, segun la
    /// segmentacion observada por el endpoint. Sin control en medio.
    AlcanzaPorRed,
    /// Igual, pero a traves de un control de segmentacion: mas dificil.
    AlcanzaPorRedSegmentada,
}

impl RelacionDirectorio {
    /// Si controlar el origen otorga control **total** del destino.
    ///
    /// Estas son las aristas que abren una escalada silenciosa: quien las tiene
    /// puede, sin ser administrador del dominio, hacerse con una cuenta que si lo
    /// es. Son el corazon de lo que esta fase encuentra para que se remedie.
    #[must_use]
    pub fn otorga_control(self) -> bool {
        matches!(
            self,
            RelacionDirectorio::Posee
                | RelacionDirectorio::ControlTotal
                | RelacionDirectorio::EscrituraGenerica
                | RelacionDirectorio::EscrituraDacl
                | RelacionDirectorio::EscrituraPropietario
                | RelacionDirectorio::AnadirMiembro
                | RelacionDirectorio::ForzarCambioClave
                | RelacionDirectorio::TodosDerechosExtendidos
                | RelacionDirectorio::LeerLaps
                | RelacionDirectorio::LeerGmsa
                | RelacionDirectorio::ReplicaDirectorio
                | RelacionDirectorio::DelegacionBasadaEnRecursos
        )
    }

    /// Si la arista es un derecho de ejecucion sobre un host.
    #[must_use]
    pub fn es_ejecucion(self) -> bool {
        matches!(
            self,
            RelacionDirectorio::AdminLocalDe
                | RelacionDirectorio::PuedeRdp
                | RelacionDirectorio::PuedeDcom
                | RelacionDirectorio::PuedePsRemote
        )
    }

    /// Un verbo legible para la evidencia y el informe.
    #[must_use]
    pub fn describir(self) -> &'static str {
        match self {
            RelacionDirectorio::MiembroDe => "es miembro de",
            RelacionDirectorio::Posee => "es propietario de",
            RelacionDirectorio::ControlTotal => "tiene control total sobre",
            RelacionDirectorio::EscrituraGenerica => "puede escribir los atributos de",
            RelacionDirectorio::EscrituraDacl => "puede reescribir la DACL de",
            RelacionDirectorio::EscrituraPropietario => "puede hacerse propietario de",
            RelacionDirectorio::AnadirMiembro => "puede anadir miembros a",
            RelacionDirectorio::ForzarCambioClave => "puede forzar el cambio de clave de",
            RelacionDirectorio::TodosDerechosExtendidos => {
                "tiene todos los derechos extendidos sobre"
            }
            RelacionDirectorio::LeerLaps => "puede leer la contrasena LAPS de",
            RelacionDirectorio::LeerGmsa => "puede leer la contrasena gMSA de",
            RelacionDirectorio::ReplicaDirectorio => "puede replicar los secretos de",
            RelacionDirectorio::DelegacionSinRestricciones => "delega sin restricciones para",
            RelacionDirectorio::DelegacionRestringida => "delega de forma restringida hacia",
            RelacionDirectorio::DelegacionBasadaEnRecursos => {
                "puede actuar en nombre de otros ante"
            }
            RelacionDirectorio::AdminLocalDe => "es administrador local de",
            RelacionDirectorio::PuedeRdp => "puede abrir escritorio remoto en",
            RelacionDirectorio::PuedeDcom => "puede ejecutar por DCOM en",
            RelacionDirectorio::PuedePsRemote => "puede ejecutar por PowerShell remoto en",
            RelacionDirectorio::SesionEn => "tiene una sesion viva en",
            RelacionDirectorio::CredencialCacheadaDe => "tiene credenciales cacheadas de",
            RelacionDirectorio::EnlazaGpo { .. } => "aplica su directiva a",
            RelacionDirectorio::Contiene { .. } => "contiene a",
            RelacionDirectorio::ConfiaEn { .. } => "tiene una confianza con",
            RelacionDirectorio::InscribeEn => "puede inscribir con",
            RelacionDirectorio::AutoInscribeEn => "puede autoinscribirse con",
            RelacionDirectorio::PublicadaEn => "esta publicada en",
            RelacionDirectorio::AlcanzaPorRed => "alcanza por red",
            RelacionDirectorio::AlcanzaPorRedSegmentada => "alcanza por red segmentada",
        }
    }
}

/// Una arista del grafo del directorio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arista {
    /// El SID del principal de origen (o el GUID de un objeto estructural, como
    /// texto, para aristas de GPO/jerarquia).
    pub origen: String,
    /// El identificador del destino.
    pub destino: String,
    /// Que relacion.
    pub relacion: RelacionDirectorio,
    /// Hasta cuando vale.
    pub vigencia: Vigencia,
}

impl Arista {
    /// Una arista estructural (permanente).
    #[must_use]
    pub fn permanente(origen: &Sid, destino: &Sid, relacion: RelacionDirectorio) -> Arista {
        Arista {
            origen: origen.texto().to_string(),
            destino: destino.texto().to_string(),
            relacion,
            vigencia: Vigencia::Permanente,
        }
    }

    /// Una arista temporal, con su ventana de vigencia.
    #[must_use]
    pub fn temporal(
        origen: &Sid,
        destino: &Sid,
        relacion: RelacionDirectorio,
        ventana: Ventana,
    ) -> Arista {
        Arista {
            origen: origen.texto().to_string(),
            destino: destino.texto().to_string(),
            relacion,
            vigencia: Vigencia::Ventana(ventana),
        }
    }

    /// Una arista entre identificadores en crudo (para GPO/jerarquia, cuyo origen
    /// es un `objectGUID` y no un SID).
    #[must_use]
    pub fn entre(
        origen: impl Into<String>,
        destino: impl Into<String>,
        relacion: RelacionDirectorio,
    ) -> Arista {
        Arista {
            origen: origen.into(),
            destino: destino.into(),
            relacion,
            vigencia: Vigencia::Permanente,
        }
    }

    /// Si la arista esta vigente en un instante.
    #[must_use]
    pub fn vigente_en(&self, t: Instante) -> bool {
        self.vigencia.vigente_en(t)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_ventana_es_semiabierta() {
        let v = Ventana::nueva(100, 200);
        assert!(!v.contiene(99));
        assert!(v.contiene(100));
        assert!(v.contiene(199));
        assert!(!v.contiene(200), "la caducidad es exclusiva");
    }

    #[test]
    fn una_arista_permanente_vale_siempre() {
        let a = Arista::entre("a", "b", RelacionDirectorio::MiembroDe);
        assert!(a.vigente_en(0));
        assert!(a.vigente_en(u64::MAX));
    }

    #[test]
    fn una_sesion_caduca() {
        let s = Sid::nuevo("S-1-5-21-1-2-3-1104");
        let e = Sid::nuevo("S-1-5-21-1-2-3-2001");
        let a = Arista::temporal(
            &s,
            &e,
            RelacionDirectorio::SesionEn,
            Ventana::nueva(1000, 2000),
        );
        assert!(!a.vigente_en(999));
        assert!(a.vigente_en(1500));
        assert!(!a.vigente_en(2000), "una sesion caducada no abre camino");
    }

    #[test]
    fn las_aristas_de_control_son_las_que_abren_la_escalada() {
        assert!(RelacionDirectorio::EscrituraDacl.otorga_control());
        assert!(RelacionDirectorio::ForzarCambioClave.otorga_control());
        assert!(RelacionDirectorio::ReplicaDirectorio.otorga_control());
        // Pertenecer a un grupo no es «control total sobre el grupo».
        assert!(!RelacionDirectorio::MiembroDe.otorga_control());
        // Una sesion tampoco.
        assert!(!RelacionDirectorio::SesionEn.otorga_control());
    }

    #[test]
    fn los_derechos_de_ejecucion_se_agrupan() {
        for r in [
            RelacionDirectorio::AdminLocalDe,
            RelacionDirectorio::PuedeRdp,
            RelacionDirectorio::PuedeDcom,
            RelacionDirectorio::PuedePsRemote,
        ] {
            assert!(r.es_ejecucion());
        }
        assert!(!RelacionDirectorio::MiembroDe.es_ejecucion());
    }
}
