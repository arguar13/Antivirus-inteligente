//! Sonda de layout, lado Rust.
//!
//! Imprime exactamente el mismo formato que `tools/abi_probe.c`, usando los
//! nombres de C, para que `tools/abi-check.sh` pueda comparar ambas salidas con
//! un `diff`. Las aserciones `const _` de `abi.rs` ya fijan los valores
//! esperados; esta sonda comprueba lo complementario: que el compilador de C
//! llegue a los mismos numeros a partir del header.

use std::mem::{align_of, offset_of, size_of};

use aegis_ipc::abi::*;

macro_rules! p_size {
    ($c:literal, $t:ty) => {
        println!("{} sizeof {}", $c, size_of::<$t>())
    };
}
macro_rules! p_align {
    ($c:literal, $t:ty) => {
        println!("{} alignof {}", $c, align_of::<$t>())
    };
}
macro_rules! p_off {
    ($c:literal, $t:ty, $cf:literal, $f:ident) => {
        println!("{}.{} {}", $c, $cf, offset_of!($t, $f))
    };
}

// La sonda es deliberadamente una tabla alineada: una entrada de layout por
// linea, para que un `diff` contra la salida de C senale exactamente el campo
// que divergio. rustfmt la expandiria a seis lineas por entrada (su
// fn_call_width por defecto es 60) y la haria ilegible como tabla.
#[rustfmt::skip]
fn main() {
    p_size!("aegis_str_t", AegisStr);

    p_size!("aegis_evt_hdr_t", AegisEvtHdr);
    p_align!("aegis_evt_hdr_t", AegisEvtHdr);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "magic", magic);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "abi_version", abi_version);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "type", ty);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "total_len", total_len);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "flags", flags);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "seq", seq);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "ts_ns", ts_ns);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "actor_key", actor_key);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "target_key", target_key);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "cpu", cpu);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "verdict_id", verdict_id);
    p_off!("aegis_evt_hdr_t", AegisEvtHdr, "reserved", reserved);

    p_size!("aegis_proc_create_t", AegisProcCreate);
    p_off!("aegis_proc_create_t", AegisProcCreate, "parent_key", parent_key);
    p_off!("aegis_proc_create_t", AegisProcCreate, "creator_key", creator_key);
    p_off!("aegis_proc_create_t", AegisProcCreate, "image_id", image_id);
    p_off!("aegis_proc_create_t", AegisProcCreate, "create_time", create_time);
    p_off!("aegis_proc_create_t", AegisProcCreate, "pid", pid);
    p_off!("aegis_proc_create_t", AegisProcCreate, "parent_pid", parent_pid);
    p_off!("aegis_proc_create_t", AegisProcCreate, "session_id", session_id);
    p_off!("aegis_proc_create_t", AegisProcCreate, "token_flags", token_flags);
    p_off!("aegis_proc_create_t", AegisProcCreate, "integrity_level", integrity_level);
    p_off!("aegis_proc_create_t", AegisProcCreate, "signature_level", signature_level);
    p_off!("aegis_proc_create_t", AegisProcCreate, "image_path", image_path);
    p_off!("aegis_proc_create_t", AegisProcCreate, "cmdline", cmdline);
    p_off!("aegis_proc_create_t", AegisProcCreate, "user_sid", user_sid);

    p_size!("aegis_image_load_t", AegisImageLoad);
    p_off!("aegis_image_load_t", AegisImageLoad, "image_base", image_base);
    p_off!("aegis_image_load_t", AegisImageLoad, "image_size", image_size);
    p_off!("aegis_image_load_t", AegisImageLoad, "image_id", image_id);
    p_off!("aegis_image_load_t", AegisImageLoad, "pid", pid);
    p_off!("aegis_image_load_t", AegisImageLoad, "flags", flags);
    p_off!("aegis_image_load_t", AegisImageLoad, "signature_level", signature_level);
    p_off!("aegis_image_load_t", AegisImageLoad, "signature_type", signature_type);
    p_off!("aegis_image_load_t", AegisImageLoad, "image_path", image_path);
    p_off!("aegis_image_load_t", AegisImageLoad, "reserved", reserved);

    p_size!("aegis_file_op_t", AegisFileOp);
    p_off!("aegis_file_op_t", AegisFileOp, "file_id", file_id);
    p_off!("aegis_file_op_t", AegisFileOp, "volume_id", volume_id);
    p_off!("aegis_file_op_t", AegisFileOp, "bytes_written", bytes_written);
    p_off!("aegis_file_op_t", AegisFileOp, "pid", pid);
    p_off!("aegis_file_op_t", AegisFileOp, "desired_access", desired_access);
    p_off!("aegis_file_op_t", AegisFileOp, "create_options", create_options);
    p_off!("aegis_file_op_t", AegisFileOp, "info_flags", info_flags);
    p_off!("aegis_file_op_t", AegisFileOp, "entropy_before", entropy_before);
    p_off!("aegis_file_op_t", AegisFileOp, "entropy_after", entropy_after);
    p_off!("aegis_file_op_t", AegisFileOp, "path", path);
    p_off!("aegis_file_op_t", AegisFileOp, "new_path", new_path);
    p_off!("aegis_file_op_t", AegisFileOp, "reserved0", reserved0);
    p_off!("aegis_file_op_t", AegisFileOp, "reserved1", reserved1);

    p_size!("aegis_remote_mem_t", AegisRemoteMem);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "target_key", target_key);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "address", address);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "region_size", region_size);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "source_pid", source_pid);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "target_pid", target_pid);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "alloc_type", alloc_type);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "protect", protect);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "prev_protect", prev_protect);
    p_off!("aegis_remote_mem_t", AegisRemoteMem, "flags", flags);

    p_size!("aegis_syscall_anomaly_t", AegisSyscallAnomaly);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "return_address", return_address);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "region_base", region_base);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "region_size", region_size);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "pid", pid);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "tid", tid);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "ssn", ssn);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "region_protect", region_protect);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "region_type", region_type);
    p_off!("aegis_syscall_anomaly_t", AegisSyscallAnomaly, "flags", flags);

    p_size!("aegis_file_write_t", AegisFileWrite);
    p_off!("aegis_file_write_t", AegisFileWrite, "bytes", bytes);
    p_off!("aegis_file_write_t", AegisFileWrite, "file_id", file_id);
    p_off!("aegis_file_write_t", AegisFileWrite, "pid", pid);
    p_off!("aegis_file_write_t", AegisFileWrite, "fd", fd);
    p_off!("aegis_file_write_t", AegisFileWrite, "entropy_q8_8", entropy_q8_8);
    p_off!("aegis_file_write_t", AegisFileWrite, "distinct_bytes", distinct_bytes);
    p_off!("aegis_file_write_t", AegisFileWrite, "sample_len", sample_len);
    p_off!("aegis_file_write_t", AegisFileWrite, "flags", flags);
    p_off!("aegis_file_write_t", AegisFileWrite, "sample", sample);

    p_size!("aegis_fd_bind_t", AegisFdBind);
    p_off!("aegis_fd_bind_t", AegisFdBind, "pid", pid);
    p_off!("aegis_fd_bind_t", AegisFdBind, "fd", fd);
    p_off!("aegis_fd_bind_t", AegisFdBind, "open_flags", open_flags);
    p_off!("aegis_fd_bind_t", AegisFdBind, "path", path);

    p_size!("aegis_net_conn_t", AegisNetConn);
    p_off!("aegis_net_conn_t", AegisNetConn, "saddr", saddr);
    p_off!("aegis_net_conn_t", AegisNetConn, "daddr", daddr);
    p_off!("aegis_net_conn_t", AegisNetConn, "pid", pid);
    p_off!("aegis_net_conn_t", AegisNetConn, "sport", sport);
    p_off!("aegis_net_conn_t", AegisNetConn, "dport", dport);
    p_off!("aegis_net_conn_t", AegisNetConn, "family", family);
    p_off!("aegis_net_conn_t", AegisNetConn, "protocol", protocol);
    p_off!("aegis_net_conn_t", AegisNetConn, "old_state", old_state);
    p_off!("aegis_net_conn_t", AegisNetConn, "new_state", new_state);
    p_off!("aegis_net_conn_t", AegisNetConn, "flags", flags);

    p_size!("aegis_verdict_t", AegisVerdict);
    p_off!("aegis_verdict_t", AegisVerdict, "verdict_id", verdict_id);
    p_off!("aegis_verdict_t", AegisVerdict, "detection_id", detection_id);
    p_off!("aegis_verdict_t", AegisVerdict, "action", action);
    p_off!("aegis_verdict_t", AegisVerdict, "reason", reason);

    p_size!("aegis_ring_ctrl_t", AegisRingCtrl);
    p_align!("aegis_ring_ctrl_t", AegisRingCtrl);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "magic", magic);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "abi_version", abi_version);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "capacity", capacity);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "data_offset", data_offset);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "flags", flags);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "producer_head", producer_head);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "dropped_events", dropped_events);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "dropped_bytes", dropped_bytes);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "consumer_tail", consumer_tail);
    p_off!("aegis_ring_ctrl_t", AegisRingCtrl, "consumer_alive", consumer_alive);

    println!("const AEGIS_ABI_VERSION {}", AEGIS_ABI_VERSION);
    println!("const AEGIS_RING_MAGIC {}", AEGIS_RING_MAGIC);
    println!("const AEGIS_EVT_MAGIC {}", AEGIS_EVT_MAGIC);
    println!("const AEGIS_EVT_PROCESS_CREATE {}", evt::PROCESS_CREATE);
    println!("const AEGIS_EVT_IMAGE_LOAD {}", evt::IMAGE_LOAD);
    println!("const AEGIS_EVT_FILE_WRITE {}", evt::FILE_WRITE);
    println!("const AEGIS_EVT_REMOTE_ALLOC {}", evt::REMOTE_ALLOC);
    println!("const AEGIS_EVT_SYSCALL_ANOMALY {}", evt::SYSCALL_ANOMALY);
    println!("const AEGIS_EVT_PADDING {}", evt::PADDING);
    println!("const AEGIS_F_NEEDS_VERDICT {}", flags::NEEDS_VERDICT);
    println!("const AEGIS_ACTION_QUARANTINE {}", action::QUARANTINE);
    println!("const AEGIS_MEM_F_RX_TRANSITION {}", mem_flags::RX_TRANSITION);
    println!("const AEGIS_SYS_F_INDIRECT {}", sys_flags::INDIRECT);
    println!("const AEGIS_IL_MEDIUM {}", integrity::MEDIUM);
    println!("const AEGIS_EVT_NET_CONNECT {}", evt::NET_CONNECT);
    println!("const AEGIS_EVT_HANDLE_REQUEST {}", evt::HANDLE_REQUEST);
    println!("const AEGIS_EVT_PROCESS_EXIT {}", evt::PROCESS_EXIT);
    println!("const AEGIS_EVT_FILE_PRE_CREATE {}", evt::FILE_PRE_CREATE);
    println!("const AEGIS_NET_F_OUTBOUND {}", net_flags::OUTBOUND);
    println!("const AEGIS_EVT_NET_SCAN {}", evt::NET_SCAN);
    println!("const AEGIS_EVT_NET_BLOCKED {}", evt::NET_BLOCKED);
    println!("const AEGIS_NET_F_SYN {}", net_flags::SYN);
    println!("const AEGIS_NET_F_DROPPED {}", net_flags::DROPPED);
    println!("const AEGIS_NET_F_SCAN_SYN {}", net_flags::SCAN_SYN);
    println!("const AEGIS_NET_F_XDP {}", net_flags::XDP);
    println!("const AEGIS_EVT_FILE_FD_BIND {}", evt::FILE_FD_BIND);
    println!("const AEGIS_EVT_FILE_WRITE {}", evt::FILE_WRITE);
    println!("const AEGIS_EVT_FILE_RENAME {}", evt::FILE_RENAME);
    println!("const AEGIS_WRITE_F_SAMPLED {}", write_flags::SAMPLED);
    println!("const AEGIS_WRITE_F_HIGH_ENT {}", write_flags::HIGH_ENTROPY);
}
