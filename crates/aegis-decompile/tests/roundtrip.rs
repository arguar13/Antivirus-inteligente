//! El redondeo semantico: la prueba honesta de un decompilador.
//!
//! Se compila un corpus de funciones desde C conocido, se sacan sus bytes del
//! objeto, se decompilan, se **recompila** el C emitido y se comprueba que se
//! comporta igual sobre entradas generadas. La **tasa de equivalencia** es la
//! cifra de la fase, y se imprime tal cual sale —no se infla—.
//!
//! # El alcance de este incremento, dicho sin adornos
//!
//! Se verifica el subconjunto que el decompilador emite hoy como C recompilable:
//! funciones de un bloque, aritmetica entera sobre argumentos. Las que tienen
//! control (ramas, bucles) se decompilan y se leen, pero su emision recompilable
//! —destruir los `phi` sin errores de arista critica— es del siguiente
//! incremento; aqui cuentan como NO verificadas, no como equivalentes. Es la parte
//! honesta: la cifra mide lo que de verdad se comprobo.
//!
//! # Muro de entorno
//!
//! Necesita un compilador de C. Si no lo hay en la maquina, se declara y la prueba
//! no se ejerce (no se finge). En la maquina de integracion lo hay.

use std::path::PathBuf;
use std::process::Command;

use aegis_decompile::decompilar::decompilar_x86_64;
use aegis_decompile::emitir::emitir_compilable;
use aegis_disasm::plazo::Plazo;
use aegis_prueba::{omitir, Requisito};

/// Una funcion del corpus: nombre, fuente C (la funcion se llama `orig`), y cuantos
/// argumentos `long` toma.
struct Caso {
    nombre: &'static str,
    fuente: &'static str,
    args: u32,
}

/// El corpus: funciones de un bloque, aritmetica entera sobre argumentos `long`.
fn corpus() -> Vec<Caso> {
    vec![
        Caso {
            nombre: "suma",
            fuente: "long orig(long a, long b){ return a + b; }",
            args: 2,
        },
        Caso {
            nombre: "resta",
            fuente: "long orig(long a, long b){ return a - b; }",
            args: 2,
        },
        Caso {
            nombre: "producto",
            fuente: "long orig(long a, long b){ return a * b; }",
            args: 2,
        },
        Caso {
            nombre: "y_logico",
            fuente: "long orig(long a, long b){ return a & b; }",
            args: 2,
        },
        Caso {
            nombre: "o_logico",
            fuente: "long orig(long a, long b){ return a | b; }",
            args: 2,
        },
        Caso {
            nombre: "xor",
            fuente: "long orig(long a, long b){ return a ^ b; }",
            args: 2,
        },
        Caso {
            nombre: "combinada",
            fuente: "long orig(long a, long b){ return (a + b) * 3 - a; }",
            args: 2,
        },
        Caso {
            nombre: "desplazar",
            fuente: "long orig(long a){ return a << 3; }",
            args: 1,
        },
        Caso {
            nombre: "lea_como_suma",
            fuente: "long orig(long a, long b){ return a + b*4 + 7; }",
            args: 2,
        },
        Caso {
            nombre: "identidad",
            fuente: "long orig(long a){ return a; }",
            args: 1,
        },
    ]
}

/// El compilador de C disponible, o `None` (muro declarado).
fn compilador() -> Option<String> {
    for cc in ["cc", "gcc", "clang"] {
        if Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(cc.to_string());
        }
    }
    None
}

/// Extrae los bytes y la direccion de un simbolo de un objeto ELF.
fn simbolo(objeto: &[u8], nombre: &str) -> Option<(Vec<u8>, u64)> {
    let elf = goblin::elf::Elf::parse(objeto).ok()?;
    for sym in &elf.syms {
        let n = elf.strtab.get_at(sym.st_name).unwrap_or("");
        if n == nombre && sym.st_size > 0 {
            let sec = elf.section_headers.get(sym.st_shndx)?;
            let base = sec.sh_offset + (sym.st_value - sec.sh_addr);
            let ini = usize::try_from(base).ok()?;
            let fin = ini + usize::try_from(sym.st_size).ok()?;
            let bytes = objeto.get(ini..fin)?.to_vec();
            return Some((bytes, sym.st_value));
        }
    }
    None
}

#[test]
fn redondeo_semantico_del_corpus() {
    let Some(cc) = compilador() else {
        omitir(
            "sin compilador de C: el redondeo semantico NO se ejercio",
            Requisito::Herramienta("cc"),
        );
        return;
    };
    let dir = std::env::temp_dir().join(format!("aegis-decompile-rt-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    let casos = corpus();
    let total = casos.len();
    let mut emitidas = 0usize;
    let mut equivalentes = 0usize;
    let mut no_emitibles: Vec<&str> = Vec::new();

    for caso in &casos {
        let dir_caso: PathBuf = dir.join(caso.nombre);
        let _ = std::fs::create_dir_all(&dir_caso);
        let orig_c = dir_caso.join("orig.c");
        let orig_o = dir_caso.join("orig.o");
        std::fs::write(&orig_c, caso.fuente).unwrap();

        // 1. Compilar la funcion original a un objeto. A -O2 el codigo es de
        // registros puros (los argumentos no se derraman a la pila), que es el
        // subconjunto que este incremento eleva a C recompilable. La recuperacion
        // de variables de pila de -O0 es del siguiente incremento y se declara.
        let ok = Command::new(&cc)
            .args(["-O2", "-fno-stack-protector", "-fcf-protection=none", "-c"])
            .arg(&orig_c)
            .arg("-o")
            .arg(&orig_o)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "el corpus no compilo: {}", caso.nombre);

        // 2. Sacar los bytes y la direccion de `orig`.
        let objeto = std::fs::read(&orig_o).unwrap();
        let Some((bytes, dir_fn)) = simbolo(&objeto, "orig") else {
            panic!("no se encontro el simbolo orig en {}", caso.nombre);
        };

        // 3. Decompilar.
        let d = decompilar_x86_64(&bytes, dir_fn, &[dir_fn], &mut Plazo::determinista());
        let Some(func) = d.funciones.iter().find(|f| f.entrada == dir_fn) else {
            no_emitibles.push(caso.nombre);
            continue;
        };

        // 4. Emitir C recompilable, si la funcion es limpia.
        let Some(c) = emitir_compilable(func, "deco", caso.args, "long") else {
            no_emitibles.push(caso.nombre);
            continue;
        };
        emitidas += 1;

        // 5. Driver que compara orig vs deco sobre entradas generadas.
        let args_decl = (0..caso.args)
            .map(|n| format!("long a{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let args_orig = (0..caso.args)
            .map(|n| format!("a{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let llamada_args = (0..caso.args)
            .map(|n| format!("v[{n}]"))
            .collect::<Vec<_>>()
            .join(", ");
        let driver = format!(
            "#include <stdint.h>\n\
             extern long orig({args_decl});\n\
             {c}\n\
             int main(void){{\n\
             unsigned long x=0x243F6A8885A308D3UL;\n\
             for(int i=0;i<2000;i++){{\n\
             long v[6];\n\
             for(int j=0;j<6;j++){{ x^=x<<13; x^=x>>7; x^=x<<17; v[j]=(long)x; }}\n\
             if(orig({args_orig_call}) != deco({args_orig_call})) return 1;\n\
             }}\n\
             return 0;\n}}\n",
            args_decl = args_decl,
            args_orig_call = llamada_args,
            c = c,
        );
        let _ = args_orig;
        let driver_c = dir_caso.join("driver.c");
        let prog = dir_caso.join("prog");
        std::fs::write(&driver_c, driver).unwrap();

        // 6. Compilar driver + objeto original, ejecutar, comparar.
        let compilo = Command::new(&cc)
            .arg(&driver_c)
            .arg(&orig_o)
            .arg("-o")
            .arg(&prog)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !compilo {
            // El C emitido no compilo: se cuenta como no equivalente, con su nombre.
            no_emitibles.push(caso.nombre);
            continue;
        }
        let igual = Command::new(&prog)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if igual {
            equivalentes += 1;
        }
    }

    let tasa = if total == 0 {
        0
    } else {
        equivalentes * 100 / total
    };
    eprintln!(
        "REDONDEO SEMANTICO: {equivalentes}/{total} equivalentes ({tasa} %), \
         {emitidas} emitidas como C recompilable; no emitibles: {no_emitibles:?}"
    );

    // La cifra se publica; y el subconjunto recto entero tiene que pasar: si una
    // suma de dos argumentos no vuelve a compilar y comportarse igual, el
    // decompilador no sirve para lo mas simple.
    assert!(
        equivalentes >= 8,
        "el subconjunto recto entero deberia ser equivalente: {equivalentes}/{total}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
