//! Sonda de layout del evento L7, lado Rust.
//!
//! Imprime EXACTAMENTE el mismo formato que `tools/abi_probe_l7.c`, usando los
//! nombres de C, para que `tools/abi-check-l7.sh` pueda comparar las dos salidas
//! con un `diff`. Las aserciones `const` de `abi.rs` ya fijan los valores
//! esperados en Rust; esta sonda comprueba lo complementario: que el compilador
//! de C llegue a los mismos numeros a partir de la cabecera con la que se compila
//! el programa eBPF.

use std::mem::{align_of, offset_of, size_of};

use aegis_l7hunter::abi::{Direccion, EventoL7Crudo, CARGA_MAX, COMM_MAX};

fn main() {
    println!(
        "struct aegis_l7_evento sizeof {}",
        size_of::<EventoL7Crudo>()
    );
    println!(
        "struct aegis_l7_evento alignof {}",
        align_of::<EventoL7Crudo>()
    );
    for (campo, off) in [
        ("tiempo_ns", offset_of!(EventoL7Crudo, tiempo_ns)),
        (
            "inicio_tarea_ns",
            offset_of!(EventoL7Crudo, inicio_tarea_ns),
        ),
        ("longitud_total", offset_of!(EventoL7Crudo, longitud_total)),
        ("pid", offset_of!(EventoL7Crudo, pid)),
        ("tid", offset_of!(EventoL7Crudo, tid)),
        ("direccion", offset_of!(EventoL7Crudo, direccion)),
        ("carga_len", offset_of!(EventoL7Crudo, carga_len)),
        ("comm", offset_of!(EventoL7Crudo, comm)),
        ("carga", offset_of!(EventoL7Crudo, carga)),
    ] {
        println!("struct aegis_l7_evento.{campo} {off}");
    }
    println!("AEGIS_L7_CARGA_MAX {CARGA_MAX}");
    println!("AEGIS_L7_COMM_MAX {COMM_MAX}");
    println!("AEGIS_L7_SALIENTE {}", Direccion::Saliente.a_cable());
    println!("AEGIS_L7_ENTRANTE {}", Direccion::Entrante.a_cable());
}
