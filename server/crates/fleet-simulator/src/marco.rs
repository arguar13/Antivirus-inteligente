//! Enmarcado asincrono, byte a byte identico al del agente.
//!
//! El agente real usa `aegis_fleet::rpc`, que trabaja sobre `Read`/`Write`
//! bloqueantes. Aqui hace falta lo mismo sobre E/S asincrona: es lo unico que
//! permite miles de agentes simultaneos en una maquina, porque un agente por
//! hilo se topa con el limite de hilos mucho antes que con el del protocolo.
//!
//! El FORMATO no cambia —se replica el de `aegis_fleet::rpc`, que a su vez es el
//! prefijo de cinco bytes de gRPC precedido de un byte de enrutado— asi que los
//! bytes que ve el servidor son exactamente los de un agente real. Los MENSAJES
//! se codifican con el codec autentico (`aegis_fleet::proto`), no con una copia.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Tamano maximo de trama, el mismo que impone el agente.
const MAX_TRAMA: usize = 4 * 1024 * 1024;

/// Escribe una trama: byte de enrutado + prefijo de gRPC + cuerpo.
pub async fn escribir<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    enrutado: u8,
    cuerpo: &[u8],
) -> io::Result<()> {
    let mut marco = Vec::with_capacity(6 + cuerpo.len());
    marco.push(enrutado);
    marco.push(0); // bandera de compresion: identidad
    marco.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes());
    marco.extend_from_slice(cuerpo);
    // Una sola escritura: partirla en dos haria que el servidor viera una
    // cabecera sin cuerpo y midiese latencias que no son del sistema, sino del
    // generador de carga.
    w.write_all(&marco).await
}

/// Lee una trama y devuelve (estado, cuerpo).
pub async fn leer<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut cabecera = [0u8; 6];
    r.read_exact(&mut cabecera).await?;

    let estado = cabecera[0];
    let largo = u32::from_be_bytes([cabecera[2], cabecera[3], cabecera[4], cabecera[5]]) as usize;
    if largo > MAX_TRAMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("trama de {largo} bytes, maximo {MAX_TRAMA}"),
        ));
    }

    let mut cuerpo = vec![0u8; largo];
    r.read_exact(&mut cuerpo).await?;
    Ok((estado, cuerpo))
}
