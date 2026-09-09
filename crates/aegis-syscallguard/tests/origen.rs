//! Pruebas de la clasificacion de origen: el nucleo de la verificacion cruzada.
//!
//! Es logica pura sobre un mapa de memoria sintetico, asi que se prueba exacta
//! y sin hardware. Los casos cubren las cinco categorias y los limites de las
//! regiones.

use aegis_scal::memory::{MemoryRegion, Perms};
use aegis_syscallguard::origen::{clasificar, es_biblioteca_sistema, OrigenSyscall, Severidad};

fn region(start: u64, end: u64, exec: bool, path: Option<&str>) -> MemoryRegion {
    MemoryRegion {
        start,
        end,
        perms: Perms {
            read: true,
            write: false,
            exec,
            private: true,
        },
        offset: 0,
        inode: if path.is_some() { 10 } else { 0 },
        path: path.map(|s| s.to_string()),
    }
}

fn mapa() -> Vec<MemoryRegion> {
    vec![
        // .text del binario principal (estatico)
        region(0x400000, 0x450000, true, Some("/home/user/muestra")),
        // libc
        region(
            0x7f0000000000,
            0x7f0000200000,
            true,
            Some("/usr/lib/x86_64-linux-gnu/libc.so.6"),
        ),
        // enlazador dinamico
        region(
            0x7f0000200000,
            0x7f0000230000,
            true,
            Some("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
        ),
        // pagina anonima ejecutable (codigo desempaquetado / shellcode)
        region(0x7f0000400000, 0x7f0000401000, true, None),
        // vdso
        region(0x7ffff7ffd000, 0x7ffff7fff000, true, Some("[vdso]")),
        // pila (datos, no ejecutable)
        region(0x7ffffffde000, 0x7ffffffff000, false, Some("[stack]")),
    ]
}

#[test]
fn syscall_desde_libc_es_legitima() {
    let o = clasificar(0x7f0000000100, &mapa());
    assert_eq!(o, OrigenSyscall::Libc);
    assert_eq!(o.severidad(), Severidad::Ninguna);
    assert!(!o.es_evasion());
}

#[test]
fn syscall_desde_el_enlazador_es_legitima() {
    assert_eq!(clasificar(0x7f0000210000, &mapa()), OrigenSyscall::Libc);
}

#[test]
fn syscall_desde_vdso_es_legitima() {
    let o = clasificar(0x7ffff7ffe000, &mapa());
    assert_eq!(o, OrigenSyscall::Vdso);
    assert!(!o.es_evasion());
}

#[test]
fn syscall_desde_memoria_anonima_es_evasion() {
    let o = clasificar(0x7f0000400010, &mapa());
    assert_eq!(o, OrigenSyscall::MemoriaAnonima);
    assert_eq!(o.severidad(), Severidad::Alta);
    assert!(o.es_evasion());
}

#[test]
fn syscall_desde_el_binario_propio_se_informa_sin_alarmar() {
    let o = clasificar(0x401234, &mapa());
    assert_eq!(o, OrigenSyscall::BinarioEstatico);
    assert_eq!(o.severidad(), Severidad::Informativa);
    // Un binario estatico llama al kernel desde su .text: no es evasion.
    assert!(!o.es_evasion());
}

#[test]
fn syscall_fuera_de_toda_region_es_imposible() {
    let o = clasificar(0xdead0000, &mapa());
    assert_eq!(o, OrigenSyscall::Desconocido);
    assert!(o.es_evasion());
}

#[test]
fn syscall_desde_memoria_no_ejecutable_es_imposible() {
    // La pila no es ejecutable: una syscall no puede nacer ahi sin que algo
    // mienta.
    let o = clasificar(0x7ffffffe0000, &mapa());
    assert_eq!(o, OrigenSyscall::Desconocido);
}

#[test]
fn el_limite_superior_de_una_region_es_exclusivo() {
    // end es exclusivo: la primera direccion FUERA de libc no es libc.
    assert_eq!(clasificar(0x7f0000200000, &mapa()), OrigenSyscall::Libc); // ld
    assert_ne!(clasificar(0x7f0000230000, &mapa()), OrigenSyscall::Libc);
}

#[test]
fn reconoce_las_bibliotecas_del_sistema_por_nombre() {
    assert!(es_biblioteca_sistema("/usr/lib/libc.so.6"));
    assert!(es_biblioteca_sistema("/lib/x86_64-linux-gnu/libc-2.31.so"));
    assert!(es_biblioteca_sistema("/lib/ld-linux-x86-64.so.2"));
    assert!(es_biblioteca_sistema("/lib/ld-musl-x86_64.so.1"));
    assert!(es_biblioteca_sistema("/usr/lib/libpthread.so.0"));
    // No son bibliotecas del sistema:
    assert!(!es_biblioteca_sistema("/home/user/muestra"));
    assert!(!es_biblioteca_sistema("/tmp/payload.so"));
    assert!(!es_biblioteca_sistema("/usr/lib/libcrypto.so.3"));
}
