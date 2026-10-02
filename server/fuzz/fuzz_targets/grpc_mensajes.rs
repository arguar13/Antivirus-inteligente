#![no_main]
//! Fuzzing de los mensajes de la superficie gRPC (H-17, E6.13 de la FASE 6.2 del
//! MP-16).
//!
//! tonic decodifica con prost ANTES de llamar al manejador: un panico ahi tumba
//! la tarea de la conexion de un integrador autenticado. Se decodifican los
//! mensajes de las RPC del servicio y, si se aceptan, se exige la ida y vuelta.
//!
//! El primer byte elige el mensaje.

use libfuzzer_sys::fuzz_target;
use prost::Message;

use aegis_server::pb;

fn ida_y_vuelta<M: Message + Default + PartialEq + std::fmt::Debug>(datos: &[u8]) {
    if let Ok(m) = M::decode(datos) {
        let otra = M::decode(m.encode_to_vec().as_slice()).expect("lo codificado se decodifica");
        assert_eq!(m, otra);
    }
}

fuzz_target!(|datos: &[u8]| {
    let Some((&selector, resto)) = datos.split_first() else {
        return;
    };
    match selector % 6 {
        0 => ida_y_vuelta::<pb::SolicitudEnrolamiento>(resto),
        1 => ida_y_vuelta::<pb::RespuestaEnrolamiento>(resto),
        2 => ida_y_vuelta::<pb::Latido>(resto),
        3 => ida_y_vuelta::<pb::AckLatido>(resto),
        4 => ida_y_vuelta::<pb::ReporteEvento>(resto),
        _ => ida_y_vuelta::<pb::AckEvento>(resto),
    }
});
