//! # AegisDirectory — el grafo completo del directorio, para exponer y remediar
//!
//! ## El inventario de partida: que modela hoy el ITDR y que modela BloodHound
//!
//! Antes de esta fase, el [grafo de identidad](crate::grafo) del ITDR era
//! minimo: nodos indexados por nombre, cinco tipos de relacion, una sola arista
//! por par, y sin tiempo en las aristas —asi que no podia expresar la caducidad
//! de una sesion—. BloodHound, en cambio, modela decenas de relaciones. Esta es
//! la tabla, relacion por relacion, que este modulo cierra:
//!
//! | Relacion de BloodHound | ITDR antes | Aqui |
//! |---|---|---|
//! | MemberOf (anidado) | parcial, sin ciclos | [`RelacionDirectorio::MiembroDe`], anidado y con ciclos resueltos |
//! | Owns / GenericAll / GenericWrite / WriteDacl / WriteOwner | no | del `ntSecurityDescriptor`, byte a byte ([`descriptor`]) |
//! | AddMember / ForceChangePassword / AllExtendedRights | no | derechos concretos por su GUID |
//! | DCSync (Get-Changes-All) | no | [`RelacionDirectorio::ReplicaDirectorio`] |
//! | Delegacion sin restricciones / restringida / RBCD | no | [`RelacionDirectorio`] + [`delegacion`] |
//! | AdminTo / CanRDP / ExecuteDCOM / CanPSRemote | no | derechos de ejecucion sobre el host |
//! | HasSession / HasCachedCredential | no | **con ventana de vigencia** ([`RelacionDirectorio::SesionEn`]) |
//! | GpLink / Contains (herencia) | no | [`RelacionDirectorio::EnlazaGpo`] / [`RelacionDirectorio::Contiene`] |
//! | Trust (direccion, tipo, transitividad) | no | [`RelacionDirectorio::ConfiaEn`] |
//! | Certificados (familia ESC) | no | [`certificados`] |
//! | **Alcance por red** | no | **[`RelacionDirectorio::AlcanzaPorRed`] — BloodHound no lo tiene** |
//!
//! ## En que se gana, y no es en el numero de relaciones
//!
//! 1. **La caducidad de la sesion esta en la arista.** Un camino que depende de
//!    una sesion caducada es un camino que no existe, y el grafo lo sabe: la misma
//!    consulta, evaluada antes y despues de caducar la sesion, da un camino
//!    distinto. BloodHound trata la sesion como un hecho sin tiempo.
//! 2. **El alcance por red.** El endpoint es nuestro: sabemos que maquina alcanza
//!    a cual de verdad, segun la segmentacion observada. BloodHound solo ve el
//!    directorio, asi que un camino que cruza un firewall que en realidad esta
//!    cerrado se le cuela.
//! 3. **La union con el modelo de entidad unico.** Cada principal es una
//!    [`aegis_entidad::Eid`] de clase `Cuenta` derivada de su SID: la misma cuenta
//!    que ve la postura de nube. El grafo no se correlaciona por texto.
//! 4. **La disciplina de contencion.** El grafo enriquecido alimenta
//!    `aegis-predict` (FASE 69), y los cinco frenos siguen gobernando lo que se
//!    puede tocar. El grafo completo **no sale del plano de control** ([`salida`]).
//!
//! ## Lo que este modulo hace y lo que no
//!
//! Lee el directorio en **solo lectura** y produce dos cosas: el **inventario de
//! exposiciones** con su remediacion ([`exposicion`]) y el **grafo** que
//! `aegis-predict` proyecta para decir que paso hay que cortar, siempre pasado por
//! los cinco frenos. No modifica el directorio, no emite certificados, y el mapa
//! completo de quien-puede-sobre-quien nunca abandona el plano de control.

pub mod certificados;
pub mod colector;
pub mod delegacion;
pub mod descriptor;
pub mod exposicion;
pub mod objeto;
pub mod relacion;
pub mod salida;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use certificados::PlantillaCertificado;
use exposicion::{ClaseExposicion, Exposicion, Hueco, InformeExposicion};
use objeto::{ClasePrincipal, ObjetoEstructural, Principal, Sid};
use relacion::{Arista, Instante, RelacionDirectorio};

use crate::{ItdrError, Severidad};

/// Tope de principales del grafo.
///
/// El grafo lo alimenta un colector, y un colector comprometido podria inflarlo
/// para agotar la memoria del plano de control. Igual que en `aegis-predict`, el
/// tope es parte del contrato, no una esperanza.
pub const MAX_PRINCIPALES: usize = 2_000_000;

/// Tope de aristas del grafo.
pub const MAX_ARISTAS: usize = 20_000_000;

/// Umbral de miembros efectivos por encima del cual un grupo privilegiado se
/// considera «demasiado amplio».
///
/// No es una ley: es un valor a mano y discutible, como los de `aegis-predict`.
/// Un grupo de administradores del dominio con mas de esto normalmente ha crecido
/// por acumulacion y merece una revision.
pub const UMBRAL_GRUPO_AMPLIO: usize = 10;

/// El grafo completo del directorio.
#[derive(Debug, Default)]
pub struct GrafoDirectorio {
    /// Principales de seguridad, indexados por SID en texto.
    principales: BTreeMap<String, Principal>,
    /// Objetos estructurales (GPO, OU, plantillas), indexados por GUID.
    estructurales: BTreeMap<String, ObjetoEstructural>,
    /// Aristas salientes por origen, en orden estable.
    salientes: BTreeMap<String, Vec<Arista>>,
    /// Plantillas de certificado, para la auditoria ESC.
    plantillas: Vec<PlantillaCertificado>,
    /// Cuenta de aristas, para el tope.
    aristas: usize,
}

impl GrafoDirectorio {
    /// Un grafo vacio.
    #[must_use]
    pub fn nuevo() -> GrafoDirectorio {
        GrafoDirectorio::default()
    }

    /// Numero de principales.
    #[must_use]
    pub fn principales(&self) -> usize {
        self.principales.len()
    }

    /// Numero de objetos estructurales.
    #[must_use]
    pub fn estructurales(&self) -> usize {
        self.estructurales.len()
    }

    /// Numero de aristas.
    #[must_use]
    pub fn aristas(&self) -> usize {
        self.aristas
    }

    /// Consulta un principal por su SID.
    #[must_use]
    pub fn principal(&self, sid: &Sid) -> Option<&Principal> {
        self.principales.get(sid.texto())
    }

    /// Recorre los principales en orden estable.
    pub fn iter_principales(&self) -> impl Iterator<Item = &Principal> {
        self.principales.values()
    }

    /// Las aristas salientes de un identificador, en orden estable.
    #[must_use]
    pub fn salientes(&self, origen: &str) -> &[Arista] {
        self.salientes.get(origen).map_or(&[], Vec::as_slice)
    }

    /// Todas las aristas del grafo, en orden estable por origen.
    pub fn iter_aristas(&self) -> impl Iterator<Item = &Arista> {
        self.salientes.values().flat_map(|v| v.iter())
    }

    /// Anade un principal.
    ///
    /// # Errores
    /// [`ItdrError`] con motivo si se supera [`MAX_PRINCIPALES`].
    pub fn agregar_principal(&mut self, p: Principal) -> Result<(), ItdrError> {
        if !self.principales.contains_key(p.sid.texto())
            && self.principales.len() >= MAX_PRINCIPALES
        {
            return Err(ItdrError::IdentidadDesconocida(format!(
                "el grafo supera el tope de {MAX_PRINCIPALES} principales"
            )));
        }
        self.principales.insert(p.sid.texto().to_string(), p);
        Ok(())
    }

    /// Anade un objeto estructural (GPO, OU, plantilla).
    pub fn agregar_estructural(&mut self, o: ObjetoEstructural) {
        self.estructurales.insert(o.guid.texto().to_string(), o);
    }

    /// Anade una plantilla de certificado para la auditoria ESC.
    pub fn agregar_plantilla(&mut self, p: PlantillaCertificado) {
        self.plantillas.push(p);
    }

    /// Anade una arista. Una arista repetida (mismo origen, destino y relacion) no
    /// se duplica: dos aristas identicas inflarian los caminos.
    ///
    /// # Errores
    /// [`ItdrError`] si se supera [`MAX_ARISTAS`].
    pub fn conectar(&mut self, a: Arista) -> Result<(), ItdrError> {
        if self.aristas >= MAX_ARISTAS {
            return Err(ItdrError::IdentidadDesconocida(format!(
                "el grafo supera el tope de {MAX_ARISTAS} aristas"
            )));
        }
        let v = self.salientes.entry(a.origen.clone()).or_default();
        if v.iter()
            .any(|e| e.destino == a.destino && e.relacion == a.relacion)
        {
            return Ok(());
        }
        v.push(a);
        self.aristas += 1;
        Ok(())
    }

    /// Anade las aristas de control derivadas del descriptor de seguridad de un
    /// objeto. Cada `(trustee, relacion)` se convierte en `trustee -> objetivo`.
    ///
    /// # Errores
    /// Propaga el motivo si el descriptor esta mal formado, para que quien llama
    /// lo declare como hueco y NO como «sin ACL peligrosas».
    pub fn incorporar_descriptor(
        &mut self,
        objetivo: &Sid,
        sd: &[u8],
    ) -> Result<(), descriptor::DescriptorMalFormado> {
        let relaciones = descriptor::relaciones_de_descriptor(sd, objetivo)?;
        for (trustee, relacion) in relaciones {
            // Un objeto no se controla a si mismo; y los principales bien conocidos
            // (SYSTEM, Domain Admins) sobre todo no son una exposicion.
            if trustee == *objetivo {
                continue;
            }
            let _ = self.conectar(Arista::permanente(&trustee, objetivo, relacion));
        }
        Ok(())
    }

    /// Los miembros **efectivos** de un grupo: todos los principales que, directa o
    /// indirectamente (por pertenencia anidada), pertenecen a el.
    ///
    /// Resuelve la anidacion y **soporta ciclos**: en un directorio real, A puede
    /// ser miembro de B y B de A, y sin un conjunto de visitados esto seria un
    /// bucle infinito. Se recorren las aristas `MiembroDe` entrantes al grupo.
    #[must_use]
    pub fn miembros_efectivos(&self, grupo: &Sid) -> BTreeSet<Sid> {
        // Indice inverso: para cada grupo, quien es miembro directo de el.
        // Se construye una vez por consulta; para el analisis completo se usa la
        // version amortizada de `auditar`.
        let mut miembros: BTreeSet<Sid> = BTreeSet::new();
        let mut vistos: BTreeSet<String> = BTreeSet::new();
        let mut cola: VecDeque<String> = VecDeque::new();
        cola.push_back(grupo.texto().to_string());
        vistos.insert(grupo.texto().to_string());
        while let Some(actual) = cola.pop_front() {
            for arista in self.iter_aristas() {
                if arista.relacion == RelacionDirectorio::MiembroDe && arista.destino == actual {
                    let m = &arista.origen;
                    if vistos.insert(m.clone()) {
                        miembros.insert(Sid::nuevo(m.clone()));
                        // Un grupo miembro aporta ademas a sus propios miembros.
                        cola.push_back(m.clone());
                    }
                }
            }
        }
        miembros
    }

    /// El conjunto de SID privilegiados: los privilegiados por RID y todos los
    /// miembros efectivos de los grupos privilegiados.
    #[must_use]
    fn conjunto_privilegiado(&self) -> BTreeSet<String> {
        let mut priv_set: BTreeSet<String> = BTreeSet::new();
        for p in self.principales.values() {
            if p.es_privilegiado_por_rid() {
                priv_set.insert(p.sid.texto().to_string());
                if p.clase == ClasePrincipal::Grupo {
                    for m in self.miembros_efectivos(&p.sid) {
                        priv_set.insert(m.texto().to_string());
                    }
                }
            }
        }
        priv_set
    }

    /// Audita la exposicion de identidad del directorio: que esta mal configurado
    /// y como se remedia, mas los huecos de lo que no se pudo mirar.
    ///
    /// El resultado es determinista: mismo grafo, mismas exposiciones, mismo orden.
    #[must_use]
    pub fn auditar(&self) -> InformeExposicion {
        let mut inf = InformeExposicion::default();
        let privilegiados = self.conjunto_privilegiado();

        for p in self.principales.values() {
            if p.uac.deshabilitada() {
                // Una cuenta deshabilitada no abre camino: no es una exposicion viva.
                continue;
            }
            let es_priv = privilegiados.contains(p.sid.texto());

            // Delegacion sin restricciones en un equipo.
            if p.clase == ClasePrincipal::Equipo
                && p.uac
                    .tiene(objeto::BanderasUac::DELEGACION_SIN_RESTRICCIONES)
            {
                inf.exposiciones.push(Exposicion::nueva(
                    ClaseExposicion::DelegacionSinRestricciones,
                    Severidad::Alta,
                    Some(p.eid()),
                    p.nombre.clone(),
                    format!(
                        "el equipo «{}» tiene delegacion Kerberos sin restricciones \
                         (TRUSTED_FOR_DELEGATION): guarda en memoria los tickets de todo el que \
                         se autentica en el. Verificar que no es un controlador de dominio, donde \
                         es esperado.",
                        p.nombre
                    ),
                ));
            }

            // Cuenta privilegiada delegable (sin el bit «sensible, no delegable»).
            if es_priv
                && p.clase == ClasePrincipal::Usuario
                && !p.uac.tiene(objeto::BanderasUac::SENSIBLE_NO_DELEGABLE)
            {
                inf.exposiciones.push(Exposicion::nueva(
                    ClaseExposicion::CuentaPrivilegiadaDelegable,
                    Severidad::Media,
                    Some(p.eid()),
                    p.nombre.clone(),
                    format!(
                        "la cuenta privilegiada «{}» no esta marcada como sensible/no delegable: \
                         si un equipo con delegacion captura su ticket, puede suplantarla.",
                        p.nombre
                    ),
                ));
            }

            // Credencial sin caducidad en una cuenta privilegiada.
            if es_priv && p.uac.tiene(objeto::BanderasUac::CLAVE_SIN_CADUCIDAD) {
                inf.exposiciones.push(Exposicion::nueva(
                    ClaseExposicion::CuentaSinCaducidad,
                    Severidad::Media,
                    Some(p.eid()),
                    p.nombre.clone(),
                    format!(
                        "la cuenta privilegiada «{}» tiene la contrasena marcada para no caducar: \
                         si se filtro, sigue valiendo indefinidamente.",
                        p.nombre
                    ),
                ));
            }
        }

        // Grupos privilegiados demasiado amplios.
        for p in self.principales.values() {
            if p.clase == ClasePrincipal::Grupo && p.es_privilegiado_por_rid() {
                let n = self.miembros_efectivos(&p.sid).len();
                if n > UMBRAL_GRUPO_AMPLIO {
                    inf.exposiciones.push(Exposicion::nueva(
                        ClaseExposicion::GrupoPrivilegiadoAmplio,
                        Severidad::Alta,
                        Some(p.eid()),
                        p.nombre.clone(),
                        format!(
                            "el grupo privilegiado «{}» tiene {n} miembros efectivos (directos y \
                             anidados), por encima del umbral de {UMBRAL_GRUPO_AMPLIO}: la \
                             superficie de compromiso del dominio es cada uno de ellos.",
                            p.nombre
                        ),
                    ));
                }
            }
        }

        // ACL peligrosas: un principal no privilegiado con control sobre uno
        // privilegiado, y delegacion basada en recursos hacia un objetivo priv.
        for arista in self.iter_aristas() {
            let destino_priv = privilegiados.contains(&arista.destino);
            let origen_priv = privilegiados.contains(&arista.origen);
            if arista.relacion.otorga_control() && destino_priv && !origen_priv {
                let nombre_origen = self
                    .principales
                    .get(&arista.origen)
                    .map_or(arista.origen.as_str(), |p| p.nombre.as_str());
                let nombre_destino = self
                    .principales
                    .get(&arista.destino)
                    .map_or(arista.destino.as_str(), |p| p.nombre.as_str());
                let sujeto = self.principales.get(&arista.origen).map(Principal::eid);
                inf.exposiciones.push(Exposicion::nueva(
                    ClaseExposicion::AclPeligrosa,
                    Severidad::Critica,
                    sujeto,
                    nombre_origen,
                    format!(
                        "el principal «{}», sin privilegio, {} «{}», que si lo tiene: un camino de \
                         escalada que no pasa por ningun grupo ni ninguna contrasena.",
                        nombre_origen,
                        arista.relacion.describir(),
                        nombre_destino
                    ),
                ));
            }
            if arista.relacion == RelacionDirectorio::DelegacionBasadaEnRecursos
                && destino_priv
                && !origen_priv
            {
                let sujeto = self.principales.get(&arista.origen).map(Principal::eid);
                let nombre = self
                    .principales
                    .get(&arista.origen)
                    .map_or(arista.origen.as_str(), |p| p.nombre.as_str());
                inf.exposiciones.push(Exposicion::nueva(
                    ClaseExposicion::DelegacionBasadaEnRecursos,
                    Severidad::Alta,
                    sujeto,
                    nombre,
                    format!(
                        "«{}» puede actuar en nombre de otros ante un objetivo privilegiado por \
                         delegacion basada en recursos.",
                        nombre
                    ),
                ));
            }
            if let RelacionDirectorio::ConfiaEn {
                direccion,
                transitiva,
                ..
            } = arista.relacion
            {
                if matches!(
                    direccion,
                    relacion::DireccionConfianza::Entrante
                        | relacion::DireccionConfianza::Bidireccional
                ) && transitiva
                {
                    inf.exposiciones.push(Exposicion::nueva(
                        ClaseExposicion::ConfianzaPeligrosa,
                        Severidad::Media,
                        None,
                        arista.origen.clone(),
                        format!(
                            "confianza entrante y transitiva desde «{}»: los principales de ese \
                             dominio pueden usarse aqui; conviene el filtrado de SID.",
                            arista.destino
                        ),
                    ));
                }
            }
        }

        // Plantillas de certificado (familia ESC).
        for pl in &self.plantillas {
            inf.exposiciones
                .extend(certificados::auditar_plantilla(pl, None));
        }

        inf.ordenar();
        inf
    }

    /// Declara un hueco de lectura en un informe: algo que no se pudo evaluar.
    ///
    /// Es un ayudante para que el colector registre el tri-estado sin inventar
    /// una ausencia.
    pub fn declarar_hueco(
        inf: &mut InformeExposicion,
        que: impl Into<String>,
        motivo: impl Into<String>,
    ) {
        inf.huecos.push(Hueco::nuevo(que, motivo));
    }
}

/// Devuelve las aristas vigentes en un instante, en orden estable.
///
/// Es lo que consume el puente hacia `aegis-predict`: solo los caminos que
/// existen AHORA. Una sesion caducada no aparece, y por eso el camino cambia.
#[must_use]
pub fn aristas_vigentes(g: &GrafoDirectorio, t: Instante) -> Vec<Arista> {
    let mut v: Vec<Arista> = g
        .iter_aristas()
        .filter(|a| a.vigente_en(t))
        .cloned()
        .collect();
    v.sort_by(|a, b| {
        a.origen
            .cmp(&b.origen)
            .then_with(|| a.destino.cmp(&b.destino))
    });
    v
}

#[cfg(test)]
mod pruebas {
    use super::objeto::{BanderasUac, ClasePrincipal, Principal, Sid};
    use super::relacion::{Arista, RelacionDirectorio, Ventana};
    use super::*;

    fn grupo(g: &mut GrafoDirectorio, sid: &str, nombre: &str) {
        g.agregar_principal(Principal::nuevo(
            Sid::nuevo(sid),
            ClasePrincipal::Grupo,
            nombre,
        ))
        .unwrap();
    }
    fn usuario(g: &mut GrafoDirectorio, sid: &str, nombre: &str) {
        g.agregar_principal(Principal::nuevo(
            Sid::nuevo(sid),
            ClasePrincipal::Usuario,
            nombre,
        ))
        .unwrap();
    }
    fn miembro(g: &mut GrafoDirectorio, quien: &str, grupo: &str) {
        g.conectar(Arista::permanente(
            &Sid::nuevo(quien),
            &Sid::nuevo(grupo),
            RelacionDirectorio::MiembroDe,
        ))
        .unwrap();
    }

    #[test]
    fn la_pertenencia_anidada_se_resuelve() {
        let mut g = GrafoDirectorio::nuevo();
        grupo(&mut g, "S-1-5-21-1-2-3-512", "Domain Admins");
        grupo(&mut g, "S-1-5-21-1-2-3-1200", "Operadores");
        usuario(&mut g, "S-1-5-21-1-2-3-1104", "alice");
        // alice -> Operadores -> Domain Admins.
        miembro(&mut g, "S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-512");
        miembro(&mut g, "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1200");

        let efectivos = g.miembros_efectivos(&Sid::nuevo("S-1-5-21-1-2-3-512"));
        assert!(
            efectivos.contains(&Sid::nuevo("S-1-5-21-1-2-3-1104")),
            "alice es DA por anidacion"
        );
        assert!(efectivos.contains(&Sid::nuevo("S-1-5-21-1-2-3-1200")));
    }

    #[test]
    fn un_ciclo_de_pertenencia_no_cuelga() {
        // A miembro de B, B miembro de A: sin conjunto de visitados seria infinito.
        let mut g = GrafoDirectorio::nuevo();
        grupo(&mut g, "S-1-5-21-1-2-3-1300", "A");
        grupo(&mut g, "S-1-5-21-1-2-3-1301", "B");
        miembro(&mut g, "S-1-5-21-1-2-3-1300", "S-1-5-21-1-2-3-1301");
        miembro(&mut g, "S-1-5-21-1-2-3-1301", "S-1-5-21-1-2-3-1300");
        // Los miembros efectivos de A son {B}: A no es miembro de si mismo. Lo que
        // importa es que la resolucion TERMINA pese al ciclo, en vez de colgarse.
        let m = g.miembros_efectivos(&Sid::nuevo("S-1-5-21-1-2-3-1300"));
        assert_eq!(m.len(), 1, "el ciclo se recorre una vez, no infinitas");
        assert!(m.contains(&Sid::nuevo("S-1-5-21-1-2-3-1301")));
    }

    #[test]
    fn una_acl_peligrosa_de_raso_a_privilegiado_es_critica() {
        let mut g = GrafoDirectorio::nuevo();
        grupo(&mut g, "S-1-5-21-1-2-3-512", "Domain Admins");
        usuario(&mut g, "S-1-5-21-1-2-3-1104", "becario");
        g.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::EscrituraDacl,
        ))
        .unwrap();
        let inf = g.auditar();
        let acl = inf
            .exposiciones
            .iter()
            .find(|e| e.clase == ClaseExposicion::AclPeligrosa)
            .expect("la ACL peligrosa se detecta");
        assert_eq!(acl.severidad, Severidad::Critica);
        assert!(acl.evidencia.contains("becario"));
        assert!(!acl.remediacion.is_empty());
    }

    #[test]
    fn un_admin_con_control_sobre_admin_no_es_una_acl_peligrosa() {
        // El caso decisivo, como en el grafo de identidad: un privilegiado que
        // controla a otro privilegiado es operacion normal, no una escalada.
        let mut g = GrafoDirectorio::nuevo();
        grupo(&mut g, "S-1-5-21-1-2-3-512", "Domain Admins");
        grupo(&mut g, "S-1-5-21-1-2-3-519", "Enterprise Admins");
        g.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-519"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::ControlTotal,
        ))
        .unwrap();
        let inf = g.auditar();
        assert!(
            !inf.exposiciones
                .iter()
                .any(|e| e.clase == ClaseExposicion::AclPeligrosa),
            "un privilegiado sobre otro no es una escalada"
        );
    }

    #[test]
    fn la_delegacion_sin_restricciones_se_senala() {
        let mut g = GrafoDirectorio::nuevo();
        let mut equipo = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-2001"),
            ClasePrincipal::Equipo,
            "WEB01$",
        );
        equipo.uac = BanderasUac(BanderasUac::DELEGACION_SIN_RESTRICCIONES);
        g.agregar_principal(equipo).unwrap();
        let inf = g.auditar();
        assert!(inf
            .exposiciones
            .iter()
            .any(|e| e.clase == ClaseExposicion::DelegacionSinRestricciones));
    }

    #[test]
    fn una_cuenta_deshabilitada_no_produce_exposiciones() {
        let mut g = GrafoDirectorio::nuevo();
        let mut equipo = Principal::nuevo(
            Sid::nuevo("S-1-5-21-1-2-3-2002"),
            ClasePrincipal::Equipo,
            "VIEJO$",
        );
        equipo.uac =
            BanderasUac(BanderasUac::DELEGACION_SIN_RESTRICCIONES | BanderasUac::DESHABILITADA);
        g.agregar_principal(equipo).unwrap();
        assert!(
            g.auditar().exposiciones.is_empty(),
            "lo deshabilitado no abre camino"
        );
    }

    #[test]
    fn el_grafo_no_duplica_una_arista_repetida() {
        let mut g = GrafoDirectorio::nuevo();
        usuario(&mut g, "S-1-5-21-1-2-3-1", "a");
        usuario(&mut g, "S-1-5-21-1-2-3-2", "b");
        for _ in 0..3 {
            g.conectar(Arista::permanente(
                &Sid::nuevo("S-1-5-21-1-2-3-1"),
                &Sid::nuevo("S-1-5-21-1-2-3-2"),
                RelacionDirectorio::MiembroDe,
            ))
            .unwrap();
        }
        assert_eq!(g.aristas(), 1);
    }

    #[test]
    fn solo_las_aristas_vigentes_aparecen_en_un_instante() {
        let mut g = GrafoDirectorio::nuevo();
        usuario(&mut g, "S-1-5-21-1-2-3-1104", "alice");
        usuario(&mut g, "S-1-5-21-1-2-3-2001", "WEB01");
        g.conectar(Arista::temporal(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-2001"),
            RelacionDirectorio::SesionEn,
            Ventana::nueva(1000, 2000),
        ))
        .unwrap();
        assert_eq!(aristas_vigentes(&g, 1500).len(), 1);
        assert_eq!(aristas_vigentes(&g, 2500).len(), 0, "la sesion caduco");
    }
}
