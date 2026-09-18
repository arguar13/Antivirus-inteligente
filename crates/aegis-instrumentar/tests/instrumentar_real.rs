//! La instrumentacion decidida sobre binarios reales de esta maquina.
//!
//! # Que se comprueba aqui, y por que no vale un caso construido
//!
//! La tesis del crate es que **el plan sale de lo que el analisis estatico no
//! pudo resolver**, y eso solo se puede comprobar contra codigo que el analisis
//! estatico resuelve casi entero. Sobre un caso construido a mano, cualquier
//! criterio parece bueno.
//!
//! Lo que tiene que cumplirse sobre un binario real:
//!
//! - El plan es **pequeno en proporcion al binario**: si instrumentara una de
//!   cada diez instrucciones, la ejecucion seria inservible.
//! - Todo punto cae **en codigo que el analisis vio**, no en una direccion
//!   cualquiera.
//! - Todo punto trae su razon escrita.

use std::path::Path;

use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::plazo::Plazo;
use aegis_disasm::{analizar, Entrada};
use aegis_instrumentar::plan::MAX_PUNTOS;
use aegis_instrumentar::{plan_desde, Que};

/// La seccion de codigo de un ELF de x86-64, con sus simbolos de funcion.
struct Codigo {
    bytes: Vec<u8>,
    base: u64,
    entradas: Vec<u64>,
}

fn texto_de(ruta: &Path) -> Option<Codigo> {
    let datos = std::fs::read(ruta).ok()?;
    let elf = goblin::elf::Elf::parse(&datos).ok()?;
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return None;
    }
    let s = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))?;
    let ini = s.sh_offset as usize;
    let fin = ini.checked_add(s.sh_size as usize)?;
    let tope = s.sh_addr.checked_add(s.sh_size)?;
    let mut entradas = vec![elf.header.e_entry];
    for sim in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sim.is_function() && sim.st_value >= s.sh_addr && sim.st_value < tope {
            entradas.push(sim.st_value);
        }
    }
    entradas.sort_unstable();
    entradas.dedup();
    Some(Codigo {
        bytes: datos.get(ini..fin)?.to_vec(),
        base: s.sh_addr,
        entradas,
    })
}

const BINARIOS: &[&str] = &["/bin/ls", "/bin/bash"];

/// Cuantos simbolos de funcion DENTRO de `.text` hacen falta para que el analisis
/// tenga por donde empezar.
///
/// El analisis no hace barrido lineal: parte de puntos de entrada conocidos y
/// sigue el flujo. Con solo `e_entry` no llega a ninguna parte, porque `_start`
/// salta al cargador por la PLT y ahi se acaba lo que se puede seguir en
/// estatico.
const MINIMO_ENTRADAS: usize = 50;

/// Un binario del sistema que sirva para comprobar el analisis, con su nombre.
///
/// # Por que se elige comprobando y no por nombre
///
/// Porque la premisa que este modulo necesita del binario no es "que exista":
/// es que **tenga simbolos de funcion dentro de `.text`**. Y eso depende de como
/// lo empaquete la distribucion, no del nombre.
///
/// Ubuntu 26.04 lo enseño: `/bin/ls` paso a ser uutils coreutils, un binario de
/// 11 MB y stripped cuyos 270 simbolos son TODOS importaciones con direccion 0.
/// Ninguno cae en `.text`, asi que el analisis arrancaba solo desde `e_entry` y
/// encontraba 0 llamadas directas —en un binario que tiene 37.564—. El test
/// fallaba diciendo "un binario real tiene muchas llamadas directas; salieron 0",
/// que es verdad y no dice nada de la causa.
///
/// Medido en esta maquina: /bin/ls 0 simbolos utiles, /bin/dash 0, /bin/bash
/// 1761. Por eso se prueban los candidatos y se coge el primero que sirva, en vez
/// de fijar uno y confiar.
fn binario_analizable() -> Option<(&'static str, Codigo)> {
    for ruta in BINARIOS {
        let Some(c) = texto_de(Path::new(ruta)) else {
            continue;
        };
        if c.entradas.len() >= MINIMO_ENTRADAS {
            return Some((ruta, c));
        }
    }
    None
}

#[test]
fn el_plan_de_un_binario_real_es_pequeno_y_cada_punto_esta_justificado() {
    let mut probados = 0;
    for nombre in BINARIOS {
        let Some(c) = texto_de(Path::new(nombre)) else {
            continue;
        };
        let e = Entrada::minima(&c.bytes, c.base, Arquitectura::X86_64, &c.entradas);
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(30), u64::MAX);
        let a = analizar(&e, &mut plazo);
        let plan = plan_desde(&a);

        eprintln!(
            "{nombre}: {} instrucciones analizadas -> {}",
            a.informe.cobertura.instrucciones,
            plan.frase()
        );

        assert!(
            plan.cuantos() <= MAX_PUNTOS,
            "{nombre}: el plan no respeta su propio tope"
        );
        for p in plan.puntos() {
            assert!(
                !p.porque.trim().is_empty(),
                "{nombre}: punto sin razon en {:#x}",
                p.direccion
            );
            assert!(
                p.direccion >= c.base && p.direccion < c.base + c.bytes.len() as u64,
                "{nombre}: el punto {:#x} cae fuera del codigo",
                p.direccion
            );
            // Salvo los de contenido escrito —que apuntan al salto, no al
            // destino—, todo punto tiene que caer donde el analisis vio codigo.
            assert!(
                a.cfg.bloque_que_contiene(p.direccion).is_some(),
                "{nombre}: el punto {:#x} no cae en codigo que el analisis viera",
                p.direccion
            );
        }
        probados += 1;
    }
    assert!(probados > 0, "esta prueba no ha comprobado nada");
}

#[test]
fn el_plan_no_instrumenta_lo_que_el_analisis_estatico_ya_resolvio() {
    // La propiedad que hace utilizable esto. En un binario real hay cientos de
    // llamadas directas, y ninguna necesita instrumentacion: su destino ya se
    // sabe. Instrumentarlas gastaria el presupuesto entero en confirmar lo
    // conocido.
    let Some((nombre, c)) = binario_analizable() else {
        panic!(
            "ningun binario de {BINARIOS:?} tiene al menos {MINIMO_ENTRADAS} simbolos de \
             funcion dentro de .text.\nSin ellos el analisis solo puede arrancar en \
             `e_entry` y no descubre nada, asi que la prueba no probaria nada. Pasa con \
             binarios stripped cuyos simbolos son solo importaciones."
        );
    };
    let e = Entrada::minima(&c.bytes, c.base, Arquitectura::X86_64, &c.entradas);
    let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(30), u64::MAX);
    let a = analizar(&e, &mut plazo);
    let plan = plan_desde(&a);

    let directas: Vec<u64> = a
        .llamadas
        .llamadas
        .iter()
        .filter(|l| l.resolucion == aegis_disasm::llamadas::Resolucion::Directa)
        .map(|l| l.desde)
        .collect();
    assert!(
        directas.len() > 50,
        "{nombre} tiene muchas llamadas directas y el analisis solo vio {} \
         (entradas de funcion: {})",
        directas.len(),
        c.entradas.len()
    );
    for p in plan.puntos() {
        if p.que != Que::DestinoDeLaTransferencia {
            continue;
        }
        assert!(
            !directas.contains(&p.direccion),
            "se instrumento una llamada cuyo destino ya se sabia: {:#x}",
            p.direccion
        );
    }
    eprintln!(
        "/bin/ls: {} llamadas directas, ninguna instrumentada; {} puntos de destino",
        directas.len(),
        plan.por_clase(Que::DestinoDeLaTransferencia)
    );
}

#[test]
fn el_plan_del_mismo_binario_es_siempre_el_mismo() {
    // Sin esto no se pueden comparar dos ejecuciones instrumentadas y saber que
    // lo que cambio fue el binario y no el plan.
    let Some(c) = texto_de(Path::new("/bin/ls")) else {
        panic!("no hay binario con el que comprobar esto");
    };
    let hacer = || {
        let e = Entrada::minima(&c.bytes, c.base, Arquitectura::X86_64, &c.entradas);
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(30), u64::MAX);
        plan_desde(&analizar(&e, &mut plazo))
    };
    let a = hacer();
    let b = hacer();
    assert_eq!(a.frase(), b.frase());
    let da: Vec<u64> = a.puntos().iter().map(|p| p.direccion).collect();
    let db: Vec<u64> = b.puntos().iter().map(|p| p.direccion).collect();
    assert_eq!(da, db);
}

#[test]
fn sobre_bytes_arbitrarios_el_plan_no_crece_sin_limite() {
    // Entrada hostil. Un fichero construido para eso puede tener una
    // transferencia indirecta cada dos bytes; el plan no puede crecer con el.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for caso in 0..16 {
        let mut bytes = Vec::with_capacity(16_384);
        for _ in 0..16_384 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            bytes.push(x as u8);
        }
        let entradas = [0x1000u64];
        let e = Entrada::minima(&bytes, 0x1000, Arquitectura::X86_64, &entradas);
        let a = analizar(&e, &mut Plazo::default());
        let plan = plan_desde(&a);
        assert!(
            plan.cuantos() <= MAX_PUNTOS,
            "caso {caso}: {} puntos",
            plan.cuantos()
        );
        for p in plan.puntos() {
            assert!(!p.porque.trim().is_empty(), "caso {caso}: punto sin razon");
        }
    }
}
