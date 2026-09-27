//! La ceguera y los cambios hablan el idioma del producto: una [`Senal`].
//!
//! Un cambio de integridad no es un evento suelto en un log aparte: se traduce a
//! una `Senal` del modelo unico, con su entidad, su severidad y su AUTOR en la
//! frase, y entra en el mismo arbitro que todo lo demas. Asi un cambio de
//! `sudoers` y una deteccion del emulador se combinan sobre la misma entidad, en
//! vez de vivir en dos productos que no se hablan.

use aegis_entidad::{Confianza, Juicio, Motor, Senal, Severidad};

use crate::autoria::CambioConAutor;
use crate::semantica::CambioSemantico;

/// El motor bajo el que observa la integridad: el plano conductual del host (un
/// proceso cambio un objeto del sistema). Es el mismo que usa la familia de
/// fichero del sensor (FASE 103).
const MOTOR: Motor = Motor::Conductual;

/// Confianza inicial segun la severidad del cambio. La `Senal` la acota luego al
/// tope del motor, asi que aqui se expresa la intencion, no el resultado.
fn confianza_de(sev: Severidad) -> Confianza {
    match sev {
        Severidad::Critica => Confianza::nueva(90),
        Severidad::Alta => Confianza::nueva(70),
        Severidad::Media => Confianza::nueva(50),
        Severidad::Baja => Confianza::nueva(30),
        Severidad::Info => Confianza::nueva(10),
    }
}

/// Convierte un cambio con autor y su significado en una senal para el arbitro.
///
/// El juicio es `Sospechoso`, no `Malicioso`: un cambio de integridad es un
/// indicio fuerte que el analista tiene que ver, y el arbitro lo combina con lo
/// demas; no es una condena por si solo. La frase lleva el AUTOR, que es lo que lo
/// hace accionable.
#[must_use]
pub fn senal_de_cambio(cambio: &CambioConAutor, semantico: &CambioSemantico) -> Senal {
    let sev = semantico.severidad();
    let porque = format!(
        "{}; lo hizo {} (uid {}{}){}",
        semantico.porque(),
        cambio.autor.proceso,
        cambio.autor.credenciales.uid,
        if cambio.autor.credenciales.escalo() {
            format!(", euid {} — escalada", cambio.autor.credenciales.euid)
        } else {
            String::new()
        },
        if cambio.autor.linaje.is_empty() {
            String::new()
        } else {
            format!(", con linaje de {} ancestro(s)", cambio.autor.linaje.len())
        }
    );
    Senal::nueva(
        MOTOR,
        cambio.objetivo.clone(),
        Juicio::Sospechoso,
        sev,
        confianza_de(sev),
        porque,
        cambio.cuando_ns,
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::autoria::{Autor, Credenciales};
    use aegis_entidad::entidad;
    use aegis_sensor::{Evento, Familia};

    fn cambio() -> CambioConAutor {
        let maq = entidad::maquina("m-1");
        let evento = Evento::nuevo(
            Familia::Fichero,
            entidad::ubicacion(&maq, "/etc/ssh/sshd_config"),
            Some("/etc/ssh/sshd_config".to_string()),
            vec![],
            42,
        );
        let autor = Autor::nuevo(
            entidad::proceso(&maq, 0, 4099, 0),
            Credenciales {
                uid: 1000,
                gid: 1000,
                euid: 0,
            },
            vec![entidad::proceso(&maq, 0, 1200, 0)],
        );
        CambioConAutor::desde_evento(&evento, autor)
    }

    #[test]
    fn un_cambio_critico_produce_una_senal_sospechosa_con_autor_en_la_frase() {
        let sem = CambioSemantico::PermitRootLogin {
            antes: "no".to_string(),
            despues: "yes".to_string(),
        };
        let s = senal_de_cambio(&cambio(), &sem);
        assert_eq!(s.motor, Motor::Conductual);
        assert_eq!(s.juicio, Juicio::Sospechoso);
        assert_eq!(s.severidad, Severidad::Critica);
        assert!(s.porque.contains("PermitRootLogin"));
        assert!(s.porque.contains("uid 1000"));
        assert!(
            s.porque.contains("escalada"),
            "euid 0 desde uid 1000: {}",
            s.porque
        );
        assert!(s.porque.contains("linaje"));
        assert!(s.aporta(), "un cambio critico aporta al veredicto");
    }
}
