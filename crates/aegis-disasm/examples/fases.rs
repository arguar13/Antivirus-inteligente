//! Mide cada fase del analisis sobre un ELF x86-64: `fases <ruta>`. Herramienta
//! de diagnostico del presupuesto del desensamblador.

use std::time::Instant;

use aegis_disasm::importaciones::Importaciones;
use aegis_disasm::llamadas::GrafoDeLlamadas;
use aegis_disasm::reglas::{evaluar, evaluar_una, Contexto, CATALOGO};
use aegis_disasm::{Arquitectura, Cfg, Plazo};

fn pico() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default()
}

fn main() {
    let ruta = std::env::args().nth(1).expect("ruta");
    let datos = std::fs::read(&ruta).expect("leer");
    let elf = goblin::elf::Elf::parse(&datos).expect("elf");
    let seg = elf
        .program_headers
        .iter()
        .find(|p| p.is_executable() && elf.entry >= p.p_vaddr && elf.entry < p.p_vaddr + p.p_filesz)
        .expect("segmento");
    let codigo = &datos[seg.p_offset as usize..(seg.p_offset + seg.p_filesz) as usize];
    let mut entradas = vec![elf.entry];
    for s in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if s.st_type() == goblin::elf::sym::STT_FUNC
            && s.st_value >= seg.p_vaddr
            && s.st_value < seg.p_vaddr + seg.p_filesz
        {
            entradas.push(s.st_value);
        }
    }
    entradas.sort_unstable();
    entradas.dedup();
    entradas.truncate(4096);
    let e = aegis_disasm::Entrada::minima(codigo, seg.p_vaddr, Arquitectura::X86_64, &entradas);
    let mut plazo = Plazo::default();
    let t = Instant::now();
    let tramo = aegis_disasm::x86::Tramo::nuevo(e.codigo, e.base, e.arquitectura).expect("tramo");
    let cfg = Cfg::construir(&tramo, e.datos, e.entradas, &mut plazo);
    println!(
        "cfg: {:?} pico={} instrucciones={} cortado={}",
        t.elapsed(),
        pico(),
        plazo.gastadas(),
        cfg.cobertura.cortado_por_plazo || cfg.cobertura.cortado_por_tope
    );
    let t = Instant::now();
    let llamadas = GrafoDeLlamadas::construir(&cfg);
    println!("llamadas: {:?} pico={}", t.elapsed(), pico());
    let t = Instant::now();
    let imp = Importaciones::buscar(&cfg, e.importadas, e.arquitectura);
    println!("importaciones: {:?} pico={}", t.elapsed(), pico());
    let ctx = Contexto::nuevo(&cfg, &llamadas, &imp, e.codigo, e.base, e.arquitectura);
    for r in CATALOGO {
        let t = Instant::now();
        let _ = evaluar_una(r, &ctx);
        let d = t.elapsed();
        if d.as_millis() > 50 {
            println!("  regla «{}»: {:?}", r.nombre, d);
        }
    }
    let t = Instant::now();
    let caps = evaluar(&ctx);
    println!(
        "reglas: {:?} pico={} capacidades={}",
        t.elapsed(),
        pico(),
        caps.len()
    );
}
