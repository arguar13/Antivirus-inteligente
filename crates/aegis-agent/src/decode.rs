//! Decodificacion de registros del ABI a eventos de dominio.
//!
//! Se mantiene aparte del cargador BPF a proposito: es la frontera por la que
//! entran datos producidos en Ring 0, y es la pieza que mas necesita pruebas.
//! Separandola, se ejercita entera sin kernel, sin privilegios y sin BTF.

use std::sync::Arc;

use aegis_ipc::abi::{
    AegisFdBind, AegisFileOp, AegisFileWrite, AegisNetConn, AegisProcCreate, AegisRemoteMem,
    AegisStr,
};
use aegis_ipc::{abi, EventView};

use crate::error::TelemetryError;
use crate::graph::ProcKey;
use crate::triage::TelemetryEvent;

/// Peticiones de `ptrace` que escriben en la memoria del proceso objetivo.
const PTRACE_POKETEXT: u32 = 4;
const PTRACE_POKEDATA: u32 = 5;

/// Convierte una referencia de cadena del ABI en un `Arc<str>`.
///
/// Las rutas y lineas de comandos de otros procesos no tienen por que ser UTF-8
/// valido: un atacante puede crear ficheros con bytes arbitrarios en el nombre
/// precisamente para romper analizadores. Se sustituyen los bytes invalidos en
/// vez de descartar el evento, porque perder telemetria por un nombre de
/// fichero raro es exactamente lo que ese atacante busca.
fn cadena(ev: &EventView<'_>, s: AegisStr) -> Arc<str> {
    match ev.resolve(s) {
        Some(bytes) => Arc::from(String::from_utf8_lossy(bytes).as_ref()),
        None => Arc::from(""),
    }
}

/// Decodifica un registro del ring buffer.
///
/// Devuelve `Ok(None)` para tipos de evento que este agente aun no interpreta:
/// un productor mas nuevo que el consumidor es una situacion normal durante una
/// actualizacion escalonada, y no debe interrumpir el consumo del resto.
pub fn decode(bytes: &[u8]) -> Result<Option<TelemetryEvent>, TelemetryError> {
    let ev = EventView::parse(bytes)
        .map_err(|_| TelemetryError::MalformedRecord("cabecera o longitud incoherentes"))?;

    let hdr = *ev.header();
    let actor = ProcKey(hdr.actor_key);
    let ts_ns = hdr.ts_ns;

    let evento = match ev.event_type() {
        abi::evt::PROCESS_CREATE => {
            let p: AegisProcCreate = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de PROCESS_CREATE truncado",
            ))?;
            TelemetryEvent::Exec {
                actor,
                pid: p.pid,
                parent: ProcKey(p.parent_key),
                image: cadena(&ev, p.image_path),
                cmdline: cadena(&ev, p.cmdline),
                started_ns: p.create_time,
                ts_ns,
            }
        }

        abi::evt::FILE_PRE_CREATE => {
            let f: AegisFileOp = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de fichero truncado",
            ))?;
            TelemetryEvent::FileWrite {
                actor,
                pid: f.pid,
                path: cadena(&ev, f.path),
                flags: f.desired_access,
                ts_ns,
            }
        }

        // FILE_RENAME comparte el registro de FILE_PRE_CREATE porque un
        // renombrado es una operacion de fichero con dos rutas, que es
        // exactamente lo que `aegis_file_op_t` modela con `path` y `new_path`.
        abi::evt::FILE_RENAME => {
            let f: AegisFileOp = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de renombrado truncado",
            ))?;
            TelemetryEvent::FileRename {
                actor,
                pid: f.pid,
                from: cadena(&ev, f.path),
                to: cadena(&ev, f.new_path),
                ts_ns,
            }
        }

        abi::evt::FILE_WRITE => {
            let w: AegisFileWrite = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de escritura truncado",
            ))?;
            // La muestra solo es valida si el kernel la marco como tomada. Sin
            // esta comprobacion, una escritura no muestreada entregaria el
            // contenido residual del registro como si fuese el buffer del
            // proceso, y la entropia se calcularia sobre basura.
            let sample: Arc<[u8]> = if w.flags & abi::write_flags::SAMPLED != 0 {
                match ev.resolve(w.sample) {
                    Some(b) => Arc::from(b),
                    None => Arc::from(&[][..]),
                }
            } else {
                Arc::from(&[][..])
            };
            TelemetryEvent::FileWriteSample {
                actor,
                pid: w.pid,
                fd: w.fd,
                bytes: w.bytes,
                sample,
                distinct_bytes: w.distinct_bytes,
                ts_ns,
            }
        }

        abi::evt::FILE_FD_BIND => {
            let b: AegisFdBind = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de asociacion de descriptor truncado",
            ))?;
            TelemetryEvent::FdBind {
                actor,
                pid: b.pid,
                fd: b.fd,
                path: cadena(&ev, b.path),
                open_flags: b.open_flags,
                ts_ns,
            }
        }

        abi::evt::HANDLE_REQUEST => {
            let m: AegisRemoteMem = ev.payload().ok_or(TelemetryError::MalformedRecord(
                "payload de ptrace truncado",
            ))?;
            let request = m.alloc_type;
            TelemetryEvent::Ptrace {
                actor,
                source_pid: m.source_pid,
                target_pid: m.target_pid,
                request,
                writes_memory: request == PTRACE_POKETEXT || request == PTRACE_POKEDATA,
                ts_ns,
            }
        }

        abi::evt::PROCESS_EXIT => TelemetryEvent::Exit { actor, ts_ns },

        abi::evt::NET_CONNECT => {
            let n: AegisNetConn = ev
                .payload()
                .ok_or(TelemetryError::MalformedRecord("payload de red truncado"))?;
            TelemetryEvent::NetConnect {
                actor,
                pid: n.pid,
                daddr: n.daddr,
                dport: n.dport,
                family: n.family,
                loopback: n.flags & abi::net_flags::LOOPBACK != 0,
                private_dst: n.flags & abi::net_flags::PRIVATE_DST != 0,
                ts_ns,
            }
        }

        _ => return Ok(None),
    };

    Ok(Some(evento))
}
