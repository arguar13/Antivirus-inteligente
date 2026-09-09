/*
 * Sonda de layout de `struct ptrace_syscall_info`, lado C.
 *
 * El kernel escribe esta estructura en el buffer del agente cuando responde a
 * PTRACE_GET_SYSCALL_INFO. Si el espejo `repr(C)` de `abi.rs` tiene un campo
 * desplazado respecto al header real del kernel, el agente lee el numero de
 * syscall donde hay un puntero de instruccion. Esta sonda imprime los offsets
 * que calcula el compilador de C con el header del kernel; la prueba en Rust
 * los compara con abi.rs::OFFSETS.
 */
#include <stdio.h>
#include <stddef.h>
#include <linux/ptrace.h>

#define P_OFF(f) printf("%s %zu\n", #f, offsetof(struct ptrace_syscall_info, f))

int main(void)
{
    P_OFF(op);
    P_OFF(arch);
    P_OFF(instruction_pointer);
    P_OFF(stack_pointer);
    P_OFF(entry.nr);
    P_OFF(entry.args);
    printf("sizeof %zu\n", sizeof(struct ptrace_syscall_info));
    return 0;
}
