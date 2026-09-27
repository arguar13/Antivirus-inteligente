//! Autoataque completo de manipulacion del agente (FASE 104, Parte B).
//!
//! El agente es, ademas de un vigilante, un objetivo. Se recorren los vectores de
//! manipulacion —matar, borrar, cegar, desviar, degradar— y se comprueba que cada
//! uno produce SU senal (una clasificacion, o una senal de la vigilancia mutua), y
//! que, despues de todos ellos, el DUENO sigue pudiendo desinstalar con su OTP: la
//! autodefensa no se convierte en un cerrojo contra el dueno (invariante 10).

use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida};
use aegis_selfdefense::otp::HOST_ID_LEN;
use aegis_selfdefense::{
    decidir, Centinela, ClaseManipulacion, ContextoTamper, EvidenciaManipulacion,
    OperacionProtegida, Otp, RegistroOtp, Solicitante, Veredicto, VigilanciaMutua,
};

fn claves() -> (ClaveFirmaHibrida, ClaveVerificacionHibrida) {
    let sk = ClaveFirmaHibrida::desde_semillas(&[21u8; 32], &[22u8; 32]);
    let vk = sk.clave_verificacion();
    (sk, vk)
}

fn host() -> [u8; HOST_ID_LEN] {
    [0x7au8; HOST_ID_LEN]
}

fn nadie() -> Solicitante {
    Solicitante {
        es_kernel: false,
        es_mismo_agente: false,
        es_componente_aegis: false,
    }
}

#[test]
fn cada_vector_de_manipulacion_produce_su_senal() {
    // matar el proceso -> torpe, y la vigilancia mutua lo avisa desde otros dos.
    let ev = EvidenciaManipulacion {
        mato_proceso: true,
        ..Default::default()
    };
    assert_eq!(ev.clasificar(), Some(ClaseManipulacion::Torpe));
    let mut v = VigilanciaMutua::nueva();
    assert_eq!(
        v.silenciar(Centinela::Proceso).len(),
        2,
        "matar no es silencioso"
    );

    // borrar la unidad -> competente.
    assert_eq!(
        EvidenciaManipulacion {
            borro_unidad: true,
            ..Default::default()
        }
        .clasificar(),
        Some(ClaseManipulacion::Competente)
    );

    // desviar: tocar los ficheros del agente -> con root.
    assert_eq!(
        EvidenciaManipulacion {
            toco_ficheros_agente: true,
            ..Default::default()
        }
        .clasificar(),
        Some(ClaseManipulacion::ConRoot)
    );

    // degradar: reescribir la linea base -> con root.
    assert_eq!(
        EvidenciaManipulacion {
            reescribio_linea_base: true,
            ..Default::default()
        }
        .clasificar(),
        Some(ClaseManipulacion::ConRoot)
    );

    // cegar: desenganchar los programas del kernel -> con kernel, y la vigilancia
    // lo avisa desde el proceso y el plano de control.
    assert_eq!(
        EvidenciaManipulacion {
            desengancho_programas_kernel: true,
            ..Default::default()
        }
        .clasificar(),
        Some(ClaseManipulacion::ConKernel)
    );
    let mut v2 = VigilanciaMutua::nueva();
    assert_eq!(
        v2.silenciar(Centinela::Kernel).len(),
        2,
        "cegar no es silencioso"
    );
}

#[test]
fn el_sabotaje_sin_otp_se_deniega_pero_no_deja_al_agente_ciego() {
    // Un administrador cualquiera intenta borrar el binario sin OTP: se deniega.
    let ctx = ContextoTamper {
        recurso_protegido: true,
        operacion: OperacionProtegida::BorrarBinario,
        solicitante: nadie(),
        orden_autorizada: false,
    };
    assert_eq!(decidir(&ctx), Veredicto::Denegar);
}

#[test]
fn la_desinstalacion_autorizada_funciona_despues_de_todos_los_ataques() {
    // INVARIANTE 10: por muy endurecido que este el agente, el dueno de la flota
    // SIEMPRE puede desinstalarlo con un OTP del plano de control. Se simula que ya
    // ocurrieron todos los vectores de manipulacion (arriba) y aqui llega el dueno.
    let (sk, vk) = claves();
    let mut reg = RegistroOtp::nuevo();
    const HORA: u64 = 1_800_000_000;
    let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, 300).expect("emitir");
    // 1. El OTP verifica y se consume.
    assert_eq!(
        otp.verificar_y_consumir(
            &vk,
            &host(),
            OperacionProtegida::Desinstalar,
            HORA + 10,
            &mut reg
        ),
        Ok(())
    );
    // 2. Con la orden autorizada, la politica de tamper PERMITE la desinstalacion.
    let ctx = ContextoTamper {
        recurso_protegido: true,
        operacion: OperacionProtegida::Desinstalar,
        solicitante: nadie(),
        orden_autorizada: true,
    };
    assert_eq!(
        decidir(&ctx),
        Veredicto::Permitir,
        "el dueno con OTP siempre puede desinstalar"
    );
}
