//! La desviacion del perfil aprendido, al arbitro.
//!
//! # Por que es una senal debil, y por que se manda igual
//!
//! Un proceso que hace algo que no hizo mientras se aprendia puede estar
//! comprometido —la shell inversa que abre un socket que el servicio nunca
//! abrio— o puede estar haciendo algo legitimo que la ventana de aprendizaje no
//! cubrio. El perfil no sabe distinguirlo, y por eso la senal sale con confianza
//! BAJA: sola no mueve nada, pero corroborada por otro plano (una conexion rara
//! en la red, un fichero en el estatico) es exactamente lo que el arbitro
//! necesita para no depender de un solo motor.
//!
//! Un ensayo sin desviaciones NO se manda como «limpio»: no haber visto nada en
//! una ventana no dice nada del proceso fuera de ella.

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};

use crate::supervision::Desviacion;

/// La senal de una desviacion, si la hay.
///
/// `cuando_ns` lo pone quien llama: la misma desviacion tiene que dar la misma
/// senal.
#[must_use]
pub fn senal_de(proceso: Eid, desviaciones: &[Desviacion], cuando_ns: u64) -> Option<Senal> {
    if desviaciones.is_empty() {
        return None;
    }
    let lista: Vec<String> = desviaciones.iter().take(8).map(Desviacion::frase).collect();
    // Una familia de red nueva o una llamada nueva de las que dan control
    // (ptrace, cargar codigo) pesan mas que un fichero fuera de las reglas.
    let grave = desviaciones.iter().any(|d| match d {
        Desviacion::Familia(_) => true,
        Desviacion::Llamada(n) => matches!(
            n.as_str(),
            "ptrace"
                | "process_vm_writev"
                | "init_module"
                | "finit_module"
                | "bpf"
                | "execve"
                | "memfd_create"
        ),
        Desviacion::Fichero(..) => false,
    });
    Some(Senal::nueva(
        Motor::Conductual,
        proceso,
        Juicio::Sospechoso,
        if grave {
            Severidad::Media
        } else {
            Severidad::Baja
        },
        Confianza::BAJA,
        format!(
            "el proceso hizo {} cosa(s) que no hizo mientras se aprendia su perfil: {}{}",
            desviaciones.len(),
            lista.join(", "),
            if desviaciones.len() > 8 { ", ..." } else { "" }
        ),
        cuando_ns,
    ))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn eid() -> Eid {
        let m = aegis_entidad::entidad::maquina("m");
        aegis_entidad::entidad::proceso(&m, 1, 4242, 99)
    }

    #[test]
    fn sin_desviaciones_no_hay_senal_ni_siquiera_de_limpio() {
        assert!(senal_de(eid(), &[], 0).is_none());
    }

    #[test]
    fn una_desviacion_es_sospecha_debil_y_nombra_lo_que_paso() {
        let s = senal_de(eid(), &[Desviacion::Familia(2)], 0).expect("senal");
        assert_eq!(s.juicio, Juicio::Sospechoso);
        assert_eq!(s.motor, Motor::Conductual);
        assert!(s.confianza <= Confianza::BAJA);
        assert!(s.porque.contains("familia 2"), "{}", s.porque);
        assert_eq!(s.severidad, Severidad::Media);
        let f = senal_de(eid(), &[Desviacion::Llamada("getrandom".into())], 0).expect("senal");
        assert_eq!(f.severidad, Severidad::Baja);
    }
}
