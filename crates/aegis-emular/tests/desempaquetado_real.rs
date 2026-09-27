//! Desempaquetado generico de extremo a extremo, sobre un stub x86-64 REAL.
//!
//! Se monta un empaquetador sintetico —el patron que TODO empaquetador sigue,
//! escrito a mano en codigo maquina x86-64, no una firma— y se comprueba que el
//! emulador detecta el punto de entrada original por OBSERVACION, no por conocer el
//! empaquetador. Un empaquetador nuevo con el mismo patron se desempaquetaria igual.

use aegis_emular::{desempaquetar, Cpu, Entorno, Mmu, Permisos, PuntoEntradaOriginal};

/// La pagina de codigo del stub y la pagina destino del desempaquetado.
const STUB: u64 = 0x1000;
const DESTINO: u64 = 0x2000;

/// El stub: rellena la pagina destino (que empieza con alta entropia) con codigo
/// de baja entropia —simula la descompresion— y salta a el. En x86-64:
///
///   mov rsi, 0x2000        ; puntero destino
///   mov rcx, 0x1000        ; 4096 bytes (una pagina)
///   loop:
///     mov byte [rsi], 0x90 ; escribe (descomprime) en pagina ejecutable
///     inc rsi
///     dec rcx
///     jne loop
///   mov rax, 0x2000
///   jmp rax                ; salta al codigo desempaquetado (OEP)
fn stub() -> Vec<u8> {
    let mut c = Vec::new();
    // mov rsi, 0x2000
    c.extend_from_slice(&[0x48, 0xBE]);
    c.extend_from_slice(&DESTINO.to_le_bytes());
    // mov rcx, 0x1000
    c.extend_from_slice(&[0x48, 0xB9]);
    c.extend_from_slice(&0x1000u64.to_le_bytes());
    // loop:
    c.extend_from_slice(&[0xC6, 0x06, 0x90]); // mov byte [rsi], 0x90
    c.extend_from_slice(&[0x48, 0xFF, 0xC6]); // inc rsi
    c.extend_from_slice(&[0x48, 0xFF, 0xC9]); // dec rcx
    c.extend_from_slice(&[0x75, 0xF5]); // jne loop (rel8 -11)
                                        // mov rax, 0x2000 ; jmp rax
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&DESTINO.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xE0]);
    c
}

/// Bytes pseudoaleatorios de alta entropia: la region "empaquetada".
fn ruido(n: usize) -> Vec<u8> {
    let mut x = 0x243F_6A88_85A3_08D3u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn preparar() -> (Cpu, Mmu, Entorno) {
    let mut mmu = Mmu::nueva(1 << 20);
    // El stub, ejecutable.
    mmu.mapear(STUB, 0x1000, Permisos::rwx()).unwrap();
    mmu.escribir(STUB, &stub()).unwrap();
    // La pagina destino, ejecutable y con alta entropia (empaquetada).
    mmu.mapear(DESTINO, 0x1000, Permisos::rwx()).unwrap();
    mmu.escribir(DESTINO, &ruido(0x1000)).unwrap();

    let cpu = Cpu {
        rip: STUB,
        ..Cpu::default()
    };
    (cpu, mmu, Entorno::nuevo())
}

#[test]
fn el_stub_sintetico_se_desempaqueta_por_observacion() {
    let (cpu, mut mmu, entorno) = preparar();
    let d = desempaquetar(cpu, &mut mmu, &entorno, 100_000);

    let oep: PuntoEntradaOriginal = d.oep.expect("se detecta el OEP");
    assert_eq!(oep.direccion, DESTINO, "el OEP es la pagina desempaquetada");
    assert!(
        oep.escrita_por_la_muestra,
        "la pagina la escribio la muestra"
    );
    assert!(
        oep.salto_a_memoria_escrita,
        "el salto fue a memoria escrita"
    );
    assert!(
        oep.entropia_cayo,
        "la entropia cayo de la region empaquetada a la desempaquetada"
    );
    assert_eq!(
        oep.heuristicas(),
        3,
        "las tres heuristicas: {}",
        oep.evidencia()
    );
}

#[test]
fn la_emulacion_del_stub_es_determinista() {
    // Mismo estado inicial, misma emulacion: el desempaquetado es reproducible.
    let (c1, mut m1, e1) = preparar();
    let (c2, mut m2, e2) = preparar();
    let d1 = desempaquetar(c1, &mut m1, &e1, 100_000);
    let d2 = desempaquetar(c2, &mut m2, &e2, 100_000);
    assert_eq!(d1.oep, d2.oep);
    assert_eq!(d1.instrucciones, d2.instrucciones);
}

#[test]
fn el_presupuesto_corta_un_stub_que_no_termina() {
    // Cota dura: con un presupuesto pequeno, la emulacion para y lo dice, en vez de
    // recorrer el bucle 4096 veces.
    let (cpu, mut mmu, entorno) = preparar();
    let d = desempaquetar(cpu, &mut mmu, &entorno, 50);
    assert!(
        matches!(d.detencion, aegis_emular::Detencion::PresupuestoAgotado),
        "{:?}",
        d.detencion
    );
    assert_eq!(d.instrucciones, 50);
}
