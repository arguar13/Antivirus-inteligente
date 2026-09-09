//! Contrato binario con el kernel para `PTRACE_GET_SYSCALL_INFO`.
//!
//! El kernel escribe una `struct ptrace_syscall_info` en un buffer del agente.
//! Si el layout que este crate cree que tiene diverge del real, el agente lee
//! el numero de syscall donde hay un puntero de instruccion y acusa de evasion
//! a codigo inocente —o peor, deja pasar al malo—. Las aserciones `const` de
//! aqui fijan los desplazamientos en Rust; la prueba `tests/abi.rs` compila una
//! sonda en C con el header real del kernel y comprueba que coinciden.
//!
//! La definicion del kernel (`include/uapi/linux/ptrace.h`):
//!
//! ```c
//! struct ptrace_syscall_info {
//!     __u8  op;                     // 0
//!     __u8  pad[3];                 // 1
//!     __u32 arch;                   // 4
//!     __u64 instruction_pointer;    // 8
//!     __u64 stack_pointer;          // 16
//!     union {
//!         struct { __u64 nr; __u64 args[6]; } entry;              // 24
//!         struct { __s64 rval; __u8 is_error; } exit;
//!         struct { __u64 nr; __u64 args[6]; __u32 ret_data; } seccomp;
//!     };
//! };
//! ```

/// Peticion `ptrace` que rellena una `ptrace_syscall_info`.
///
/// No esta en `libc` para todas las plataformas, asi que se fija aqui con el
/// valor de la ABI del kernel (`0x420e`).
pub const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;

/// `op`: no hay parada de syscall en curso.
pub const OP_NONE: u8 = 0;
/// `op`: parada en la ENTRADA de una syscall (registros de argumentos validos).
pub const OP_ENTRY: u8 = 1;
/// `op`: parada en la SALIDA de una syscall (valor de retorno valido).
pub const OP_EXIT: u8 = 2;
/// `op`: parada provocada por `seccomp` (`SECCOMP_RET_TRACE`).
pub const OP_SECCOMP: u8 = 3;

/// Espejo `repr(C)` de `struct ptrace_syscall_info`, con el brazo `entry` de la
/// union explicito y el resto de la union cubierto por relleno.
///
/// Se lee solo la variante de ENTRADA (`OP_ENTRY`) y la de `seccomp`, que
/// comparten el `nr` y los `args` en el mismo desplazamiento; por eso basta con
/// exponer ese brazo. El campo `_union_resto` existe para que el tamano de la
/// estructura iguale al del kernel: la variante `seccomp` lleva un `__u32`
/// extra que, con la alineacion a 8, agranda la union hasta 64 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PtraceSyscallInfo {
    /// Tipo de parada: uno de `OP_*`.
    pub op: u8,
    /// Relleno de alineacion del kernel.
    pub pad: [u8; 3],
    /// Arquitectura de audit (`AUDIT_ARCH_*`) de la syscall.
    pub arch: u32,
    /// Puntero de instruccion en el momento de la syscall.
    ///
    /// Apunta a la instruccion SIGUIENTE a la de la syscall: en x86-64, dos
    /// bytes despues del `0F 05`; en aarch64, cuatro despues del `svc`.
    pub instruction_pointer: u64,
    /// Puntero de pila en el momento de la syscall.
    pub stack_pointer: u64,
    /// Numero de syscall (brazos `entry` y `seccomp`).
    pub nr: u64,
    /// Argumentos de la syscall (brazos `entry` y `seccomp`).
    pub args: [u64; 6],
    /// Relleno que cubre el `__u32 ret_data` de la variante `seccomp`.
    pub _union_resto: u64,
}

impl PtraceSyscallInfo {
    /// Instancia a cero, lista para que `ptrace` la rellene.
    pub fn cero() -> Self {
        PtraceSyscallInfo {
            op: OP_NONE,
            pad: [0; 3],
            arch: 0,
            instruction_pointer: 0,
            stack_pointer: 0,
            nr: 0,
            args: [0; 6],
            _union_resto: 0,
        }
    }
}

// --- Aserciones de layout: fijadas contra la ABI del kernel -----------------

const _: () = {
    assert!(core::mem::offset_of!(PtraceSyscallInfo, op) == 0);
    assert!(core::mem::offset_of!(PtraceSyscallInfo, arch) == 4);
    assert!(core::mem::offset_of!(PtraceSyscallInfo, instruction_pointer) == 8);
    assert!(core::mem::offset_of!(PtraceSyscallInfo, stack_pointer) == 16);
    assert!(core::mem::offset_of!(PtraceSyscallInfo, nr) == 24);
    assert!(core::mem::offset_of!(PtraceSyscallInfo, args) == 32);
    assert!(core::mem::size_of::<PtraceSyscallInfo>() == 88);
    assert!(core::mem::align_of::<PtraceSyscallInfo>() == 8);
};

/// Desplazamiento que la sonda en C debe reproducir, para `tests/abi.rs`.
pub const OFFSETS: &[(&str, usize)] = &[
    ("op", 0),
    ("arch", 4),
    ("instruction_pointer", 8),
    ("stack_pointer", 16),
    ("entry.nr", 24),
    ("entry.args", 32),
    ("sizeof", 88),
];

// --- Instruccion de syscall por arquitectura --------------------------------

/// Bytes de la instruccion `syscall` en x86-64: `0F 05`.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_OPCODE: &[u8] = &[0x0F, 0x05];

/// Bytes de la instruccion `svc #0` en aarch64 (little-endian): `01 00 00 D4`.
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_OPCODE: &[u8] = &[0x01, 0x00, 0x00, 0xD4];

/// Distancia, hacia atras desde `instruction_pointer`, a la que empieza la
/// instruccion de syscall. Es el tamano del opcode.
pub const RETROCESO_OPCODE: u64 = SYSCALL_OPCODE.len() as u64;
