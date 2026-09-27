//! Autoataque: la emulacion como via de agotamiento y como via de fuga.
//!
//! El emulador corre codigo que elige el atacante. Tiene que (a) no correr sin fin
//! —cota dura de instrucciones—, (b) no entrar en panico ante bytes arbitrarios, y
//! (c) no tener forma de tocar el sistema real. Lo tercero se verifica por AUSENCIA
//! en `tools/verificar-emular.sh` (ningun tipo abre fichero, socket, proceso ni
//! reloj reales); aqui se comprueban lo primero y lo segundo.

use aegis_emular::{emular, Cpu, Detencion, Entorno, Mmu, Permisos};

#[test]
fn un_bucle_infinito_se_corta_por_presupuesto() {
    // jmp $  (EB FE): salta a si mismo para siempre. La cota lo corta.
    let mut mmu = Mmu::nueva(1 << 20);
    mmu.mapear(0x1000, 0x1000, Permisos::rwx()).unwrap();
    mmu.escribir(0x1000, &[0xEB, 0xFE]).unwrap();
    let cpu = Cpu {
        rip: 0x1000,
        ..Cpu::default()
    };
    let e = emular(cpu, &mut mmu, &Entorno::nuevo(), 10_000);
    assert_eq!(e.detencion, Detencion::PresupuestoAgotado);
    assert_eq!(
        e.instrucciones, 10_000,
        "corrio justo el presupuesto, ni una mas"
    );
}

#[test]
fn bytes_hostiles_como_codigo_no_hacen_panico() {
    // Codigo pseudoaleatorio: el emulador para con un motivo (no modelada,
    // indecodificable, fallo de memoria o parada), nunca con un panico.
    let mut x = 0x9E37_79B9u64;
    for _ in 0..64 {
        let mut prog = Vec::with_capacity(256);
        for _ in 0..256 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            prog.push(x as u8);
        }
        let mut mmu = Mmu::nueva(1 << 20);
        mmu.mapear(0x1000, 0x1000, Permisos::rwx()).unwrap();
        mmu.escribir(0x1000, &prog).unwrap();
        // Stack por si toca push/pop/call.
        mmu.mapear(0x7000, 0x1000, Permisos::rw()).unwrap();
        let mut regs = [0u64; 16];
        regs[4] = 0x7800;
        let cpu = Cpu {
            rip: 0x1000,
            regs,
            ..Cpu::default()
        };
        let _ = emular(cpu, &mut mmu, &Entorno::nuevo(), 5_000);
        // No se afirma nada del resultado: solo que termino sin panico.
    }
}

#[test]
fn saltar_a_memoria_no_ejecutable_para_con_su_motivo() {
    // jmp a una pagina que existe pero no es ejecutable: W^X lo corta, sin panico.
    let mut mmu = Mmu::nueva(1 << 20);
    mmu.mapear(0x1000, 0x1000, Permisos::rwx()).unwrap();
    // mov rax, 0x9000 ; jmp rax
    let mut prog = vec![0x48, 0xB8];
    prog.extend_from_slice(&0x9000u64.to_le_bytes());
    prog.extend_from_slice(&[0xFF, 0xE0]);
    mmu.escribir(0x1000, &prog).unwrap();
    mmu.mapear(0x9000, 0x1000, Permisos::rw()).unwrap(); // datos, NO ejecutable
    let cpu = Cpu {
        rip: 0x1000,
        ..Cpu::default()
    };
    let e = emular(cpu, &mut mmu, &Entorno::nuevo(), 1000);
    assert!(
        matches!(e.detencion, Detencion::FalloMemoria { .. }),
        "saltar a datos no ejecutables tiene que parar: {:?}",
        e.detencion
    );
}
