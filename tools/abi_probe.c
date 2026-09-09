/*
 * Sonda de layout, lado C. Imprime el tamano y el offset de cada campo del ABI
 * tal y como los calcula el compilador de C (el que usa el driver).
 * tools/abi-check.sh compara esta salida con la de la sonda equivalente en Rust.
 */
#include <stdio.h>
#include <stddef.h>
#include "aegis_abi.h"

#define P_SIZE(t)      printf("%s sizeof %zu\n", #t, sizeof(t))
#define P_ALIGN(t)     printf("%s alignof %zu\n", #t, _Alignof(t))
#define P_OFF(t, f)    printf("%s.%s %zu\n", #t, #f, offsetof(t, f))

int main(void)
{
    P_SIZE(aegis_str_t);

    P_SIZE(aegis_evt_hdr_t);
    P_ALIGN(aegis_evt_hdr_t);
    P_OFF(aegis_evt_hdr_t, magic);
    P_OFF(aegis_evt_hdr_t, abi_version);
    P_OFF(aegis_evt_hdr_t, type);
    P_OFF(aegis_evt_hdr_t, total_len);
    P_OFF(aegis_evt_hdr_t, flags);
    P_OFF(aegis_evt_hdr_t, seq);
    P_OFF(aegis_evt_hdr_t, ts_ns);
    P_OFF(aegis_evt_hdr_t, actor_key);
    P_OFF(aegis_evt_hdr_t, target_key);
    P_OFF(aegis_evt_hdr_t, cpu);
    P_OFF(aegis_evt_hdr_t, verdict_id);
    P_OFF(aegis_evt_hdr_t, reserved);

    P_SIZE(aegis_proc_create_t);
    P_OFF(aegis_proc_create_t, parent_key);
    P_OFF(aegis_proc_create_t, creator_key);
    P_OFF(aegis_proc_create_t, image_id);
    P_OFF(aegis_proc_create_t, create_time);
    P_OFF(aegis_proc_create_t, pid);
    P_OFF(aegis_proc_create_t, parent_pid);
    P_OFF(aegis_proc_create_t, session_id);
    P_OFF(aegis_proc_create_t, token_flags);
    P_OFF(aegis_proc_create_t, integrity_level);
    P_OFF(aegis_proc_create_t, signature_level);
    P_OFF(aegis_proc_create_t, image_path);
    P_OFF(aegis_proc_create_t, cmdline);
    P_OFF(aegis_proc_create_t, user_sid);

    P_SIZE(aegis_image_load_t);
    P_OFF(aegis_image_load_t, image_base);
    P_OFF(aegis_image_load_t, image_size);
    P_OFF(aegis_image_load_t, image_id);
    P_OFF(aegis_image_load_t, pid);
    P_OFF(aegis_image_load_t, flags);
    P_OFF(aegis_image_load_t, signature_level);
    P_OFF(aegis_image_load_t, signature_type);
    P_OFF(aegis_image_load_t, image_path);
    P_OFF(aegis_image_load_t, reserved);

    P_SIZE(aegis_file_op_t);
    P_OFF(aegis_file_op_t, file_id);
    P_OFF(aegis_file_op_t, volume_id);
    P_OFF(aegis_file_op_t, bytes_written);
    P_OFF(aegis_file_op_t, pid);
    P_OFF(aegis_file_op_t, desired_access);
    P_OFF(aegis_file_op_t, create_options);
    P_OFF(aegis_file_op_t, info_flags);
    P_OFF(aegis_file_op_t, entropy_before);
    P_OFF(aegis_file_op_t, entropy_after);
    P_OFF(aegis_file_op_t, path);
    P_OFF(aegis_file_op_t, new_path);
    P_OFF(aegis_file_op_t, reserved0);
    P_OFF(aegis_file_op_t, reserved1);

    P_SIZE(aegis_remote_mem_t);
    P_OFF(aegis_remote_mem_t, target_key);
    P_OFF(aegis_remote_mem_t, address);
    P_OFF(aegis_remote_mem_t, region_size);
    P_OFF(aegis_remote_mem_t, source_pid);
    P_OFF(aegis_remote_mem_t, target_pid);
    P_OFF(aegis_remote_mem_t, alloc_type);
    P_OFF(aegis_remote_mem_t, protect);
    P_OFF(aegis_remote_mem_t, prev_protect);
    P_OFF(aegis_remote_mem_t, flags);

    P_SIZE(aegis_syscall_anomaly_t);
    P_OFF(aegis_syscall_anomaly_t, return_address);
    P_OFF(aegis_syscall_anomaly_t, region_base);
    P_OFF(aegis_syscall_anomaly_t, region_size);
    P_OFF(aegis_syscall_anomaly_t, pid);
    P_OFF(aegis_syscall_anomaly_t, tid);
    P_OFF(aegis_syscall_anomaly_t, ssn);
    P_OFF(aegis_syscall_anomaly_t, region_protect);
    P_OFF(aegis_syscall_anomaly_t, region_type);
    P_OFF(aegis_syscall_anomaly_t, flags);

    P_SIZE(aegis_verdict_t);
    P_OFF(aegis_verdict_t, verdict_id);
    P_OFF(aegis_verdict_t, detection_id);
    P_OFF(aegis_verdict_t, action);
    P_OFF(aegis_verdict_t, reason);

    P_SIZE(aegis_ring_ctrl_t);
    P_ALIGN(aegis_ring_ctrl_t);
    P_OFF(aegis_ring_ctrl_t, magic);
    P_OFF(aegis_ring_ctrl_t, abi_version);
    P_OFF(aegis_ring_ctrl_t, capacity);
    P_OFF(aegis_ring_ctrl_t, data_offset);
    P_OFF(aegis_ring_ctrl_t, flags);
    P_OFF(aegis_ring_ctrl_t, producer_head);
    P_OFF(aegis_ring_ctrl_t, dropped_events);
    P_OFF(aegis_ring_ctrl_t, dropped_bytes);
    P_OFF(aegis_ring_ctrl_t, consumer_tail);
    P_OFF(aegis_ring_ctrl_t, consumer_alive);

    /* Constantes: una divergencia aqui es tan grave como una de layout. */
    printf("const AEGIS_ABI_VERSION %u\n", AEGIS_ABI_VERSION);
    printf("const AEGIS_RING_MAGIC %u\n", AEGIS_RING_MAGIC);
    printf("const AEGIS_EVT_MAGIC %u\n", AEGIS_EVT_MAGIC);
    printf("const AEGIS_EVT_PROCESS_CREATE %u\n", AEGIS_EVT_PROCESS_CREATE);
    printf("const AEGIS_EVT_IMAGE_LOAD %u\n", AEGIS_EVT_IMAGE_LOAD);
    printf("const AEGIS_EVT_FILE_WRITE %u\n", AEGIS_EVT_FILE_WRITE);
    printf("const AEGIS_EVT_REMOTE_ALLOC %u\n", AEGIS_EVT_REMOTE_ALLOC);
    printf("const AEGIS_EVT_SYSCALL_ANOMALY %u\n", AEGIS_EVT_SYSCALL_ANOMALY);
    printf("const AEGIS_EVT_PADDING %u\n", AEGIS_EVT_PADDING);
    printf("const AEGIS_F_NEEDS_VERDICT %u\n", AEGIS_F_NEEDS_VERDICT);
    printf("const AEGIS_ACTION_QUARANTINE %u\n", AEGIS_ACTION_QUARANTINE);
    printf("const AEGIS_MEM_F_RX_TRANSITION %u\n", AEGIS_MEM_F_RX_TRANSITION);
    printf("const AEGIS_SYS_F_INDIRECT %u\n", AEGIS_SYS_F_INDIRECT);
    printf("const AEGIS_IL_MEDIUM %u\n", AEGIS_IL_MEDIUM);
    return 0;
}
