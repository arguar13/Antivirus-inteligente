//! Pruebas del desensamblador contra binarios reales del sistema.
//!
//! # Por que no hay ficheros de prueba en el repositorio
//!
//! Un fichero de prueba lo escribe quien escribe la prueba, y por tanto contiene
//! exactamente lo que esa persona creia que contenia. Un desensamblador validado
//! asi pasa sus pruebas y falla con el primer binario de verdad, porque el
//! compilador emite cosas que a nadie se le ocurre poner en un fichero de prueba:
//! relleno entre funciones, tablas incrustadas en el codigo, instrucciones de
//! extensiones que no se estudiaron.
//!
//! Aqui se desensambla `/bin/ls`, `/bin/bash` y la libc de la maquina, y el
//! resultado se coteja **instruccion a instruccion contra `objdump`**, que es una
//! implementacion independiente escrita por otra gente.
//!
//! # Que pasa si no estan
//!
//! La prueba se salta y **lo dice**. Una prueba que se salta en silencio cuenta
//! como verde en el informe y no ha comprobado nada, que es peor que no tenerla.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use aegis_disasm::cfg::{Cfg, SinDatos};
use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::llamadas::{GrafoDeLlamadas, Motivo, Resolucion};
use aegis_disasm::plazo::Plazo;
use aegis_disasm::x86;

/// La seccion de codigo de un ELF: sus bytes y la direccion en que se carga.
struct Codigo {
    bytes: Vec<u8>,
    base: u64,
    /// Por donde empezar a desensamblar.
    ///
    /// El punto de entrada **y los simbolos de funcion**, cuando el binario los
    /// trae. Descender solo desde el punto de entrada de una biblioteca alcanza
    /// lo que llama el arranque y nada mas —en la libc de esta maquina, 189
    /// funciones de varios miles—, y una medida tomada sobre esa muestra no dice
    /// nada de como se comporta el analisis con el binario entero. Un
    /// desensamblador de verdad usa la tabla de simbolos cuando la hay.
    entradas: Vec<u64>,
}

/// Lee `.text` de un ELF de x86-64, o `None` si no es uno.
fn texto_de(ruta: &Path) -> Option<Codigo> {
    let datos = std::fs::read(ruta).ok()?;
    let elf = goblin::elf::Elf::parse(&datos).ok()?;
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return None;
    }
    for s in &elf.section_headers {
        if elf.shdr_strtab.get_at(s.sh_name) == Some(".text") {
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
            return Some(Codigo {
                bytes: datos.get(ini..fin)?.to_vec(),
                base: s.sh_addr,
                entradas,
            });
        }
    }
    None
}

/// Los binarios de la maquina con los que se prueba.
const BINARIOS: &[&str] = &[
    "/bin/ls",
    "/bin/bash",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
];

/// Lo que `objdump` dice de un binario: la longitud de cada instruccion, por
/// direccion.
///
/// Solo se le piden direcciones y longitudes, no texto. Comparar el texto seria
/// comparar dos convenciones de formato —`objdump` e `iced` difieren en espacios
/// y en como escriben algunos operandos— cuando lo que importa es otra cosa:
/// **donde empieza y donde acaba cada instruccion**. Un desensamblador que
/// acierta los limites y escribe `mov` donde el otro escribe `movl` sirve; uno
/// que se desplaza un byte no sirve para nada, porque todo lo que viene detras
/// queda desplazado y produce un desensamblado que parece correcto.
///
/// Se llama a `objdump` **una vez por binario** y no una por funcion: con los
/// casi tres mil simbolos de la libc, una llamada por funcion serian tres mil
/// procesos, y una prueba que tarda minutos acaba desactivada.
fn objdump_longitudes(ruta: &Path) -> Option<BTreeMap<u64, u8>> {
    let salida = Command::new("objdump")
        .args([
            "-d",
            // Sin esto, objdump parte los bytes de una instruccion larga en
            // varias lineas y la segunda linea parece otra instruccion. Un `nop`
            // de once bytes —que los hay, de relleno entre funciones— saldria
            // como una de siete y otra de cuatro, y la prueba acusaria al
            // decodificador de un error que es del formato de la salida.
            "--insn-width=16",
            ruta.to_str()?,
        ])
        .output()
        .ok()?;
    if !salida.status.success() {
        return None;
    }
    let texto = String::from_utf8_lossy(&salida.stdout);
    let mut m: BTreeMap<u64, u8> = BTreeMap::new();
    let mut ultima: Option<u64> = None;
    for linea in texto.lines() {
        // Formato: "  401000:\t48 c7 c0 01 00 00 00 \tmov rax,0x1"
        let Some((izq, resto)) = linea.split_once(":\t") else {
            continue;
        };
        let Ok(dir) = u64::from_str_radix(izq.trim(), 16) else {
            continue;
        };
        // Una linea sin mnemonico es la continuacion de la anterior. Con
        // `--insn-width` no deberia haberlas, y si aparece una, sus bytes son de
        // la instruccion anterior y no de una nueva.
        if !resto.contains('\t') {
            if let Some(u) = ultima.and_then(|d| m.get_mut(&d)) {
                *u = u.saturating_add(resto.split_whitespace().count() as u8);
            }
            continue;
        }
        let bytes = resto.split('\t').next().unwrap_or("");
        let n = bytes.split_whitespace().count();
        if n == 0 || n > 16 {
            continue;
        }
        // `.byte 0x89` es objdump diciendo que el tampoco ha entendido lo que
        // hay ahi. Esa direccion se deja FUERA del mapa: comparar contra la
        // confusion de objdump no comprueba nada, y quien coteja se para al
        // llegar a un hueco.
        if resto.contains(".byte") {
            ultima = None;
            continue;
        }
        m.insert(dir, n as u8);
        ultima = Some(dir);
    }
    if m.is_empty() {
        None
    } else {
        Some(m)
    }
}

#[test]
fn se_coteja_instruccion_a_instruccion_contra_objdump() {
    if Command::new("objdump").arg("--version").output().is_err() {
        panic!("no hay objdump en la maquina: esta prueba no puede comprobar nada");
    }
    // El cotejo empieza en cada simbolo de funcion y sigue mientras objdump
    // tenga algo que decir de esa direccion. Arrancar en un desplazamiento
    // cualquiera de `.text` no vale: cae con frecuencia dentro de una tabla o de
    // un relleno, y ahi los dos desensambladores se resincronizan de forma
    // distinta. La discrepancia que saldria de eso no diria nada de si el
    // decodificador es correcto.
    let mut total = 0usize;
    let mut probados = 0;
    for nombre in BINARIOS {
        let ruta = Path::new(nombre);
        let Some(c) = texto_de(ruta) else { continue };
        let Some(esperado) = objdump_longitudes(ruta) else {
            continue;
        };
        let t = x86::Tramo::nuevo(&c.bytes, c.base, Arquitectura::X86_64).unwrap();
        let mut comparadas = 0usize;
        let mut funciones = 0usize;
        // Cada funcion se recorre hasta el simbolo SIGUIENTE. Sin ese tope el
        // recorrido sigue mientras objdump conozca la direccion —y las conoce
        // casi todas—, o sea que desde cada uno de los casi tres mil simbolos se
        // desensambla hasta el final de `.text`: el mismo coste cuadratico que
        // convierte una prueba en un cuelgue.
        let mut limites: Vec<(u64, u64)> = c.entradas.windows(2).map(|p| (p[0], p[1])).collect();
        if let Some(u) = c.entradas.last() {
            limites.push((*u, c.base + c.bytes.len() as u64));
        }
        for (entrada, tope) in limites {
            if !esperado.contains_key(&entrada) {
                continue;
            }
            // Se decodifica instruccion a instruccion y se para en cuanto
            // objdump no tenga nada que decir de la siguiente direccion —es dato
            // o no lo entendio—. Usar el barrido lineal seria decodificar desde
            // cada simbolo hasta el final de `.text`.
            let mut n = 0usize;
            let mut pc = entrada;
            while pc < tope {
                let Some(largo) = esperado.get(&pc) else {
                    break;
                };
                let Ok(mia) = t.en(pc) else { break };
                assert_eq!(
                    mia.longitud, *largo,
                    "{nombre}: longitud distinta en {pc:#x} ({} frente a {} de objdump); \
                     a partir de aqui los dos desensamblados van desplazados",
                    mia.longitud, largo
                );
                pc = mia.siguiente();
                n += 1;
            }
            comparadas += n;
            if n > 0 {
                funciones += 1;
            }
        }
        eprintln!(
            "{nombre}: {comparadas} instrucciones de {funciones} funciones, identicas a objdump"
        );
        total += comparadas;
        probados += 1;
    }
    assert!(
        probados > 0,
        "no habia ningun binario de x86-64 de los esperados en la maquina; \
         esta prueba no ha comprobado nada"
    );
    assert!(
        total > 100_000,
        "solo se cotejaron {total} instrucciones, muy pocas para que la prueba \
         signifique algo"
    );
}

#[test]
fn el_analisis_de_un_binario_real_termina_dentro_de_su_plazo() {
    // La propiedad que hace utilizable esto dentro del agente. No es una prueba
    // de velocidad: es una prueba de que la cota se respeta y de que ni el grafo
    // de flujo ni la propagacion de constantes se atascan con codigo real, que
    // es donde estan los ciclos, las funciones compartidas y los bloques con
    // veinte predecesores.
    let mut probados = 0;
    for nombre in BINARIOS {
        let Some(c) = texto_de(Path::new(nombre)) else {
            continue;
        };
        let t = x86::Tramo::nuevo(&c.bytes, c.base, Arquitectura::X86_64).unwrap();
        let mut plazo = Plazo::determinista();
        let reloj = Instant::now();
        let cfg = Cfg::construir(&t, &SinDatos, &c.entradas, &mut plazo);
        let g = GrafoDeLlamadas::construir(&cfg);
        let tardado = reloj.elapsed();

        // El plazo por defecto es de medio segundo. Se deja margen para la
        // construccion del grafo de llamadas, que va despues del plazo, y para
        // una maquina cargada; lo que se comprueba es que no hay atasco.
        assert!(
            tardado < std::time::Duration::from_secs(20),
            "{nombre}: {tardado:?} es un atasco, no una cota"
        );
        // La propiedad que hace que la propagacion de constantes signifique
        // algo: ningun bloque pasa por encima del principio de otro.
        //
        // No es lo mismo que «ninguna instruccion esta en dos bloques». En
        // x86-64 real sí las hay: en la libc de esta maquina hay diez —de
        // doscientas cincuenta mil— en sitios donde dos bloques empiezan con un
        // byte de diferencia, decodifican distinto y despues **convergen** en la
        // misma frontera. Esos dos caminos de ejecucion son los dos reales y
        // comparten bytes de verdad; partirlos seria inventarse que son el
        // mismo. Lo que no puede pasar —y es lo que se comprueba— es que un
        // bloque contenga en una de SUS fronteras el principio de otro, porque
        // eso es la misma instruccion analizada dos veces con dos estados.
        let inicios: std::collections::BTreeSet<u64> = cfg.bloques().map(|b| b.inicio).collect();
        for b in cfg.bloques() {
            for i in &b.instrucciones {
                assert!(
                    i.direccion == b.inicio || !inicios.contains(&i.direccion),
                    "{nombre}: el bloque {:#x} pasa por encima del principio del bloque {:#x}",
                    b.inicio,
                    i.direccion
                );
            }
        }
        eprintln!(
            "{nombre}: {tardado:?} — {} bloques, {}",
            cfg.cuantos_bloques(),
            g.frase()
        );
        probados += 1;
    }
    assert!(probados > 0, "esta prueba no ha comprobado nada");
}

#[test]
fn en_un_binario_real_las_indirectas_se_clasifican_y_la_evidencia_se_sostiene() {
    // Lo que se comprueba aqui NO es que se resuelvan muchas. Sobre un binario
    // benigno compilado de la forma normal el patron que resuelve el analisis de
    // constantes casi no aparece —el compilador que conoce la direccion de una
    // funcion emite una llamada directa—, y exigir resoluciones que el codigo no
    // contiene solo llevaria a relajar el analisis hasta que invente alguna.
    //
    // Se comprueba lo que si tiene que cumplirse siempre:
    //
    //  1. Que las que van por memoria se identifican COMO TALES. Son la tabla de
    //     importaciones, y confundirlas con «no se pudo» perderia la unica pista
    //     de que hay otra pieza que si las resuelve.
    //  2. Que toda resolucion trae una evidencia que APUNTA A CODIGO REAL. Una
    //     evidencia que apunte a ninguna parte es peor que no tenerla: da la
    //     apariencia de comprobable sin serlo.
    let Some(c) = texto_de(Path::new("/bin/bash")).or_else(|| texto_de(Path::new("/bin/ls")))
    else {
        panic!("no hay binario con el que comprobar esto");
    };
    let t = x86::Tramo::nuevo(&c.bytes, c.base, Arquitectura::X86_64).unwrap();
    let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(30), u64::MAX);
    let cfg = Cfg::construir(&t, &SinDatos, &c.entradas, &mut plazo);
    let g = GrafoDeLlamadas::construir(&cfg);

    assert!(g.cuantas_funciones() > 10, "{}", g.frase());
    assert!(!g.llamadas.is_empty(), "{}", g.frase());

    let por_memoria = g
        .sin_resolver
        .iter()
        .filter(|s| s.motivo == Motivo::EnMemoria)
        .count();
    assert!(
        por_memoria > 0,
        "en un binario enlazado dinamicamente TIENE que haber llamadas por la \
         tabla de importaciones; si no sale ninguna, es que no se estan \
         distinguiendo de las demas"
    );
    eprintln!(
        "{} funciones, {} llamadas, {} resueltas por constante, {} sin resolver \
         ({por_memoria} por memoria)",
        g.cuantas_funciones(),
        g.llamadas.len(),
        g.resueltas(),
        g.sin_resolver.len()
    );

    for l in &g.llamadas {
        if let Resolucion::PorConstante { definido_en, .. } = l.resolucion {
            assert!(
                cfg.bloque_que_contiene(definido_en).is_some(),
                "la evidencia de la llamada en {:#x} apunta a {definido_en:#x}, que no \
                 esta en el codigo analizado",
                l.desde
            );
        }
    }
}

#[test]
fn sobre_un_elf_ensamblado_de_verdad_si_se_resuelve_la_llamada_indirecta() {
    // El patron que este analisis existe para resolver, en un ELF producido por
    // un ensamblador de verdad y no por bytes escritos a mano. Es el idioma del
    // codigo empaquetado: materializar la direccion y saltar a ella.
    //
    // Si no hay ensamblador en la maquina la prueba lo dice y falla, en vez de
    // saltarse en silencio y contar como verde sin haber comprobado nada.
    let dir = std::env::temp_dir().join("aegis-disasm-prueba");
    let _ = std::fs::create_dir_all(&dir);
    let fuente = dir.join("indirecta.s");
    let objeto = dir.join("indirecta.o");
    std::fs::write(
        &fuente,
        ".text\n.globl principal\nprincipal:\n  movq $destino, %rax\n  call *%rax\n  ret\n\
         .globl destino\ndestino:\n  xorl %eax, %eax\n  ret\n",
    )
    .unwrap();
    let salida = Command::new("as")
        .args(["--64", "-o"])
        .arg(&objeto)
        .arg(&fuente)
        .output();
    let Ok(salida) = salida else {
        panic!("no hay ensamblador (`as`) en la maquina: esta prueba no comprueba nada");
    };
    assert!(
        salida.status.success(),
        "el ensamblador fallo: {}",
        String::from_utf8_lossy(&salida.stderr)
    );

    let c = texto_de(&objeto).expect("el objeto ensamblado tiene que tener .text");
    let t = x86::Tramo::nuevo(&c.bytes, c.base, Arquitectura::X86_64).unwrap();
    let mut plazo = Plazo::determinista();
    let cfg = Cfg::construir(&t, &SinDatos, &[0], &mut plazo);
    let g = GrafoDeLlamadas::construir(&cfg);

    let resueltas: Vec<_> = g
        .llamadas
        .iter()
        .filter(|l| matches!(l.resolucion, Resolucion::PorConstante { .. }))
        .collect();
    assert_eq!(
        resueltas.len(),
        1,
        "tenia que resolverse la llamada indirecta: {:?} / {:?}",
        g.llamadas,
        g.sin_resolver
    );
    // El destino es `destino`, que en el objeto sin enlazar queda en 0 por la
    // reubicacion pendiente. Lo que se comprueba es que se RESOLVIO y con que
    // evidencia, no la direccion final —que depende del enlazado.
    assert!(matches!(
        resueltas[0].resolucion,
        Resolucion::PorConstante { registro: 0, .. }
    ));
    eprintln!("ELF ensamblado: {}", resueltas[0].resolucion.frase());
}

#[test]
fn ningun_fichero_hostil_cuelga_ni_agota_la_memoria() {
    // Entrada arbitraria tratada como codigo. Lo que se comprueba no es que el
    // resultado sea bueno —sobre bytes al azar no lo puede ser— sino que el
    // analisis TERMINA, que respeta su cota y que no reserva memoria sin
    // limite. Es la unica forma de que un fichero pueda llegar al agente sin
    // que el agente sea el problema.
    let mut x = 0x853C_49E6_748F_EA9Bu64;
    for caso in 0..64 {
        let n = 4096 + (x as usize % 60_000);
        let mut bytes = Vec::with_capacity(n);
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            bytes.push(x as u8);
        }
        let reloj = Instant::now();
        let t = x86::Tramo::nuevo(&bytes, 0x40_0000, Arquitectura::X86_64).unwrap();
        let mut plazo = Plazo::determinista();
        let cfg = Cfg::construir(&t, &SinDatos, &[0x40_0000], &mut plazo);
        let g = GrafoDeLlamadas::construir(&cfg);
        let tardado = reloj.elapsed();
        assert!(
            tardado < std::time::Duration::from_secs(10),
            "caso {caso}: {tardado:?} con {n} bytes al azar"
        );
        // El grafo no puede tener mas bloques que bytes: cada bloque ocupa al
        // menos una instruccion, y cada instruccion al menos un byte. Si los
        // tuviera, seria que se estan creando bloques fuera del tramo.
        assert!(cfg.cuantos_bloques() <= n, "caso {caso}");
        assert!(g.llamadas.len() <= n, "caso {caso}");
    }
}

#[test]
fn sobre_un_tramo_vacio_no_se_afirma_nada() {
    // El caso negativo de la cobertura: con cero bytes no hay ni un «no hay
    // nada», hay un «no habia nada que mirar», y son frases distintas.
    let t = x86::Tramo::nuevo(&[], 0x1000, Arquitectura::X86_64).unwrap();
    let mut plazo = Plazo::determinista();
    let cfg = Cfg::construir(&t, &SinDatos, &[0x1000], &mut plazo);
    let g = GrafoDeLlamadas::construir(&cfg);
    assert_eq!(cfg.cuantos_bloques(), 0);
    assert!(g.llamadas.is_empty());
    assert!(g.sin_resolver.is_empty());
    assert_eq!(cfg.cobertura.fraccion_cubierta(), None);
}

#[test]
fn las_reglas_no_disparan_a_lo_loco_sobre_binarios_del_sistema() {
    // La medida que de verdad dice si el catalogo sirve. Un motor de capacidades
    // se juzga por lo que dice de los ficheros que NO son malware, porque son el
    // 99,99 % de los que va a ver. Uno que encuentre cinco capacidades en `ls`
    // llena la bandeja del analista de ruido, y una bandeja llena de ruido es
    // una bandeja que nadie mira.
    //
    // No se exige cero: `bash` habla por red, lee el registro de nadie pero si
    // consulta el entorno, y la libc trae dentro implementaciones de cifrado de
    // verdad. Lo que se exige es que lo que salga sea POCO y que salga **con su
    // evidencia dentro del codigo**, que es lo que permite descartarlo de un
    // vistazo en vez de tener que reanalizar el fichero.
    let mut probados = 0;
    for nombre in BINARIOS {
        let Some(c) = texto_de(Path::new(nombre)) else {
            continue;
        };
        let e = aegis_disasm::Entrada::minima(&c.bytes, c.base, Arquitectura::X86_64, &c.entradas);
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(60), u64::MAX);
        let a = aegis_disasm::analizar(&e, &mut plazo);
        let nombres: Vec<&str> = a.informe.capacidades().iter().map(|c| c.nombre).collect();
        eprintln!("{nombre}: {} capacidades {nombres:?}", nombres.len());

        for cap in a.informe.capacidades() {
            for ev in cap.evidencias() {
                assert!(
                    ev.donde >= c.base && ev.donde < c.base + c.bytes.len() as u64,
                    "{nombre}: «{}» apunta a {:#x}, fuera del codigo",
                    cap.nombre,
                    ev.donde
                );
            }
        }
        // Sin tabla de importaciones —aqui no se le da ninguna— las reglas que
        // miran nombres no pueden disparar, asi que lo que salga viene de
        // constantes y de instrucciones.
        //
        // La medida a dia de hoy es CERO en los tres binarios, y llegar ahi
        // costo tres correcciones: el ambito de funcion, la ventana de
        // proximidad y el segmento del bloque de entorno por anchura. El umbral
        // se deja en uno y no en cero para que la prueba no se rompa en una
        // maquina con otra libc, pero cualquier cosa por encima significa que se
        // ha reintroducido una regla que dispara sola.
        assert!(
            nombres.len() <= 1,
            "{nombre}: {} capacidades es demasiado ruido para un binario del \
             sistema: {nombres:?}",
            nombres.len()
        );
        probados += 1;
    }
    assert!(probados > 0, "esta prueba no ha comprobado nada");
}
