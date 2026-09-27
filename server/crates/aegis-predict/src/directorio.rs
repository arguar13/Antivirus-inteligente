//! El puente de produccion: del grafo del directorio (FASE 95) al grafo de ataque.
//!
//! # Por que este puente existe, y por que en produccion
//!
//! El grafo enriquecido del directorio —`aegis_itdr::directorio`— modela quien
//! puede sobre quien con todo el detalle de BloodHound. Este motor, `aegis-predict`,
//! ya sabe calcular sobre un grafo de ataque el camino mas probable, el radio y la
//! contencion con los cinco frenos. Lo que faltaba, y lo que la FASE 95 cierra, es
//! que **alguien en produccion** construya el grafo de ataque a partir del grafo de
//! directorio: hasta ahora solo lo hacia una prueba.
//!
//! # La caducidad de la sesion decide el camino
//!
//! El puente proyecta el grafo **en un instante**: solo las aristas vigentes en
//! ese momento entran en el grafo de ataque. Una sesion caducada no aparece, asi
//! que el camino mas probable calculado despues de que caduque es distinto —a
//! menudo, ya no existe—. Esa es la ventaja sobre BloodHound, que trata la sesion
//! como un hecho sin tiempo, hecha operativa.
//!
//! # La proyeccion sobre el vocabulario de la contencion
//!
//! El grafo de directorio tiene muchos tipos de arista; el grafo de ataque tiene
//! un vocabulario mas corto, calibrado para la contencion (`grafo::probabilidad`).
//! El puente PROYECTA cada relacion del directorio sobre la via de ataque que le
//! corresponde, y esa proyeccion esta escrita aqui, a la vista, para que se pueda
//! discutir —igual que las probabilidades—:
//!
//! - Pertenecer a un grupo -> pertenencia (heredar es automatico).
//! - Cualquier control por ACL (WriteDacl, GenericAll, forzar clave, RBCD...) ->
//!   impersonacion: quien controla el objeto puede actuar como el.
//! - Replicacion del directorio (DCSync), lectura de LAPS/gMSA, credencial
//!   cacheada -> control de credenciales: se obtiene el secreto.
//! - Una sesion viva se INVIERTE: si `alice` tiene sesion en `PC01`, quien
//!   controla `PC01` obtiene a `alice`; la arista de ataque va del equipo al
//!   usuario.
//! - Los derechos de ejecucion (AdminTo, RDP, DCOM, PSRemote) -> autenticarse en
//!   el host.
//! - El alcance por red -> salto de red, expuesto o segmentado.
//! - Lo estructural (GPO, jerarquia, confianzas, inscripcion de certificados) no
//!   se proyecta como paso directo de control: alimenta el inventario de
//!   exposiciones, no el calculo del camino mas corto de un principal a otro.

use aegis_itdr::directorio::objeto::ClasePrincipal;
use aegis_itdr::directorio::relacion::{Instante, RelacionDirectorio};
use aegis_itdr::directorio::{aristas_vigentes, GrafoDirectorio};
use aegis_itdr::grafo::Nivel;

use crate::error::ErrorPrediccion;
use crate::grafo::{Activo, ClaseActivo, Paso, RelacionSerializable, Via};
use crate::GrafoAtaque;

/// La via de ataque a la que se proyecta una relacion del directorio, y si la
/// arista se invierte al proyectarla.
///
/// `None` para las relaciones estructurales, que no son un paso directo de control
/// de un principal a otro.
fn proyeccion(rel: RelacionDirectorio) -> Option<(Via, bool)> {
    use RelacionDirectorio as R;
    let via = match rel {
        R::MiembroDe => Via::Identidad(RelacionSerializable::MiembroDe),

        // Control por ACL: quien controla el objeto puede actuar como el.
        R::Posee
        | R::ControlTotal
        | R::EscrituraGenerica
        | R::EscrituraDacl
        | R::EscrituraPropietario
        | R::AnadirMiembro
        | R::ForzarCambioClave
        | R::TodosDerechosExtendidos
        | R::DelegacionRestringida
        | R::DelegacionBasadaEnRecursos => Via::Identidad(RelacionSerializable::Impersona),

        // Obtener el secreto: replicacion (DCSync), LAPS/gMSA, credencial cacheada.
        R::ReplicaDirectorio | R::LeerLaps | R::LeerGmsa | R::CredencialCacheadaDe => {
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe)
        }

        // Una sesion viva se invierte: controlar el equipo entrega al usuario.
        R::SesionEn => {
            return Some((
                Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
                true,
            ))
        }

        // Ejecucion sobre un host.
        R::AdminLocalDe | R::PuedeRdp | R::PuedeDcom | R::PuedePsRemote => {
            Via::Identidad(RelacionSerializable::AutenticaEn)
        }

        // Alcance por red.
        R::AlcanzaPorRed => Via::RedExpuesta,
        R::AlcanzaPorRedSegmentada => Via::RedSegmentada,

        // Estructural: no es un paso directo de control principal a principal.
        R::DelegacionSinRestricciones
        | R::EnlazaGpo { .. }
        | R::Contiene { .. }
        | R::ConfiaEn { .. }
        | R::InscribeEn
        | R::AutoInscribeEn
        | R::PublicadaEn => return None,
    };
    Some((via, false))
}

/// El nivel de privilegio y el valor de negocio de un principal, para el grafo de
/// ataque.
///
/// Un principal privilegiado (por RID bien conocido o por pertenecer a un grupo
/// que lo es) es una joya: nivel maximo y valor 100. El resto hereda su valor de
/// lo que alcanza, que es lo que calcula la criticidad de `aegis-predict`.
fn nivel_y_valor(dir: &GrafoDirectorio, sid: &str, privilegiado: bool) -> (Nivel, u8) {
    if privilegiado {
        return (Nivel::AdminDominio, 100);
    }
    match dir
        .principal(&aegis_itdr::directorio::objeto::Sid::nuevo(sid))
        .map(|p| p.clase)
    {
        Some(ClasePrincipal::Equipo) => (Nivel::AdminLocal, 10),
        Some(ClasePrincipal::Grupo | ClasePrincipal::Gmsa) => (Nivel::Operador, 10),
        _ => (Nivel::Usuario, 10),
    }
}

/// Los SID privilegiados del directorio: los privilegiados por RID y todos los
/// miembros efectivos de los grupos privilegiados.
fn conjunto_privilegiado(dir: &GrafoDirectorio) -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    for p in dir.iter_principales() {
        if p.es_privilegiado_por_rid() {
            s.insert(p.sid.texto().to_string());
            if p.clase == ClasePrincipal::Grupo {
                for m in dir.miembros_efectivos(&p.sid) {
                    s.insert(m.texto().to_string());
                }
            }
        }
    }
    s
}

/// Construye el grafo de ataque a partir del grafo del directorio, evaluado en un
/// instante: solo las aristas vigentes en ese momento entran.
///
/// # Errores
/// [`ErrorPrediccion`] si el grafo resultante supera los topes de `aegis-predict`.
pub fn desde_directorio(
    dir: &GrafoDirectorio,
    instante: Instante,
) -> Result<GrafoAtaque, ErrorPrediccion> {
    let privilegiados = conjunto_privilegiado(dir);
    let mut g = GrafoAtaque::nuevo();

    // Un activo por principal. Los objetos estructurales no son principales y no
    // entran como nodos del grafo de ataque.
    for p in dir.iter_principales() {
        let sid = p.sid.texto();
        let (nivel, valor) = nivel_y_valor(dir, sid, privilegiados.contains(sid));
        g.agregar(Activo::nuevo(sid, ClaseActivo::Identidad, nivel, valor))?;
    }

    // Un paso por cada arista vigente que se proyecta a un paso de control.
    for a in aristas_vigentes(dir, instante) {
        let Some((via, invertir)) = proyeccion(a.relacion) else {
            continue;
        };
        let (origen, destino) = if invertir {
            (a.destino.as_str(), a.origen.as_str())
        } else {
            (a.origen.as_str(), a.destino.as_str())
        };
        // Solo entre principales conocidos: una arista estructural podria nombrar
        // un GUID que no es un activo, y no se fuerza.
        if g.activo(origen).is_some() && g.activo(destino).is_some() {
            g.conectar(Paso::nuevo(origen, destino, via))?;
        }
    }

    Ok(g)
}

#[cfg(test)]
mod pruebas {
    use aegis_itdr::directorio::objeto::{ClasePrincipal, Principal, Sid};
    use aegis_itdr::directorio::relacion::{Arista, RelacionDirectorio, Ventana};
    use aegis_itdr::directorio::GrafoDirectorio;

    use super::*;
    use crate::caminos::camino_mas_probable;
    use crate::contencion::{decidir, ConfigContencion, Veredicto};
    use crate::radio::radio_de_explosion;

    fn principal(g: &mut GrafoDirectorio, sid: &str, clase: ClasePrincipal, nombre: &str) {
        g.agregar_principal(Principal::nuevo(Sid::nuevo(sid), clase, nombre))
            .unwrap();
    }

    /// Un directorio con un camino que depende de una sesion: alice tiene una
    /// sesion en WEB01 (vigente [1000, 2000)), WEB01 es admin-local de DC01, y DC01
    /// controla Domain Admins.
    fn directorio_con_sesion() -> GrafoDirectorio {
        let mut g = GrafoDirectorio::nuevo();
        principal(
            &mut g,
            "S-1-5-21-1-2-3-1104",
            ClasePrincipal::Usuario,
            "alice",
        );
        principal(
            &mut g,
            "S-1-5-21-1-2-3-2001",
            ClasePrincipal::Equipo,
            "WEB01$",
        );
        principal(
            &mut g,
            "S-1-5-21-1-2-3-2002",
            ClasePrincipal::Equipo,
            "DC01$",
        );
        principal(
            &mut g,
            "S-1-5-21-1-2-3-512",
            ClasePrincipal::Grupo,
            "Domain Admins",
        );
        // alice tiene sesion en WEB01 solo en [1000, 2000).
        g.conectar(Arista::temporal(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-2001"),
            RelacionDirectorio::SesionEn,
            Ventana::nueva(1000, 2000),
        ))
        .unwrap();
        // WEB01 controla a alice (por la inversion de la sesion), y alice es admin
        // de Domain Admins por una ACL peligrosa: alice -> DA control total.
        g.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::ControlTotal,
        ))
        .unwrap();
        g
    }

    #[test]
    fn la_caducidad_de_la_sesion_cambia_el_camino() {
        let dir = directorio_con_sesion();

        // En t=1500 la sesion esta viva: WEB01 llega a Domain Admins pasando por
        // alice (WEB01 -controla-> alice -control total-> DA).
        let vivo = desde_directorio(&dir, 1500).unwrap();
        let con_sesion =
            camino_mas_probable(&vivo, "S-1-5-21-1-2-3-2001", "S-1-5-21-1-2-3-512").unwrap();
        assert!(
            con_sesion.is_some(),
            "con la sesion viva, WEB01 alcanza Domain Admins"
        );

        // En t=2500 la sesion caduco: WEB01 ya no llega a alice, asi que el camino
        // desaparece. Es la propiedad que BloodHound no puede dar.
        let caducado = desde_directorio(&dir, 2500).unwrap();
        let sin_sesion =
            camino_mas_probable(&caducado, "S-1-5-21-1-2-3-2001", "S-1-5-21-1-2-3-512").unwrap();
        assert!(
            sin_sesion.is_none(),
            "con la sesion caducada el camino ya no existe"
        );
    }

    #[test]
    fn los_cinco_frenos_siguen_funcionando_sobre_el_grafo_enriquecido() {
        // El grafo enriquecido del directorio, proyectado, se somete a la
        // contencion: los frenos tienen que decidir con normalidad. Es la
        // invariante 8 sobre datos que salen del directorio.
        let mut dir = GrafoDirectorio::nuevo();
        principal(
            &mut dir,
            "S-1-5-21-1-2-3-1104",
            ClasePrincipal::Usuario,
            "becario",
        );
        principal(
            &mut dir,
            "S-1-5-21-1-2-3-512",
            ClasePrincipal::Grupo,
            "Domain Admins",
        );
        // El becario, sin privilegio, tiene WriteDacl sobre Domain Admins.
        dir.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-1104"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::EscrituraDacl,
        ))
        .unwrap();

        let g = desde_directorio(&dir, 0).unwrap();
        let camino = camino_mas_probable(&g, "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-512").unwrap();
        let radio = radio_de_explosion(&g, "S-1-5-21-1-2-3-1104", 2000).unwrap();
        let v = decidir(&g, camino.as_ref(), &radio, &ConfigContencion::default()).unwrap();
        // Camino probable, radio pequeno, evidencia solida: se contiene, y se corta
        // en el origen (el becario), no en la joya.
        match v {
            Veredicto::Contener { sujeto, .. } => {
                assert_eq!(sujeto, "S-1-5-21-1-2-3-1104");
            }
            otro => panic!("los frenos deberian permitir contener el paso: {otro:?}"),
        }
    }

    #[test]
    fn un_activo_protegido_del_directorio_no_se_toca() {
        // FRENO 1 sobre el grafo enriquecido: si el origen del unico paso es un
        // controlador de dominio protegido, no se contiene.
        let mut dir = GrafoDirectorio::nuevo();
        principal(
            &mut dir,
            "S-1-5-21-1-2-3-516",
            ClasePrincipal::Grupo,
            "Domain Controllers",
        );
        principal(
            &mut dir,
            "S-1-5-21-1-2-3-512",
            ClasePrincipal::Grupo,
            "Domain Admins",
        );
        dir.conectar(Arista::permanente(
            &Sid::nuevo("S-1-5-21-1-2-3-516"),
            &Sid::nuevo("S-1-5-21-1-2-3-512"),
            RelacionDirectorio::ControlTotal,
        ))
        .unwrap();
        let mut g = desde_directorio(&dir, 0).unwrap();
        // Se marca el origen como protegido, como haria el plano de control con un DC.
        let protegido = Activo::nuevo(
            "S-1-5-21-1-2-3-516",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        )
        .protegido();
        g.agregar(protegido).unwrap();
        let camino = camino_mas_probable(&g, "S-1-5-21-1-2-3-516", "S-1-5-21-1-2-3-512").unwrap();
        let radio = radio_de_explosion(&g, "S-1-5-21-1-2-3-516", 2000).unwrap();
        let v = decidir(&g, camino.as_ref(), &radio, &ConfigContencion::default()).unwrap();
        assert!(
            matches!(v, Veredicto::NoActuar { .. }),
            "un activo protegido no se contiene: {v:?}"
        );
    }
}
