//! El analisis contra la memoria real de esta maquina.
//!
//! # Por que no vale un volcado de prueba
//!
//! Un volcado que escribe quien escribe la prueba contiene exactamente lo que
//! esa persona creia que contenia. El mapa de memoria de un proceso real tiene
//! cosas que a nadie se le ocurre poner en un fichero de prueba: regiones
//! anonimas ejecutables perfectamente legitimas —las que crea el enlazador
//! dinamico, las de un compilador al vuelo—, regiones con nombres raros,
//! mapeos de dispositivos, huecos.
//!
//! Aqui se lee `/proc/self/maps`, que es el mapa de este mismo proceso de
//! pruebas, y se comprueba lo que de verdad importa: que el analisis no marque
//! como hallazgo lo que hay en cualquier proceso de cualquier maquina.
//!
//! **No se lee `/proc/self/mem`.** No hace falta para lo que se comprueba aqui, y
//! este crate se define por lo que NO tiene: cuantos menos caminos de acceso a
//! memoria viva existan en el, mejor.

use std::collections::BTreeSet;

use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::plazo::Plazo;
use aegis_volcado::adquirir::EnMemoria;
use aegis_volcado::hallazgos::{analizar_memoria, Clase};
use aegis_volcado::regiones::{leer_mapa, Respaldo};

/// El mapa de este mismo proceso.
fn mapa_propio() -> String {
    std::fs::read_to_string("/proc/self/maps")
        .expect("esta prueba necesita /proc: sin el no comprueba nada")
}

#[test]
fn el_mapa_de_un_proceso_real_se_lee_entero_y_sin_lineas_ilegibles() {
    // Si el lector no entiende el formato de esta maquina, todo lo demas que
    // haga este crate esta construido sobre un mapa mal leido.
    let (regiones, ilegibles) = leer_mapa(&mapa_propio());
    assert!(
        regiones.len() > 5,
        "un proceso real tiene mas de cinco regiones; salieron {}",
        regiones.len()
    );
    assert_eq!(
        ilegibles, 0,
        "hay {ilegibles} lineas de /proc/self/maps que este lector no entiende"
    );
    eprintln!("/proc/self/maps: {} regiones leidas", regiones.len());
}

#[test]
fn las_regiones_de_un_proceso_real_no_se_solapan_ni_estan_al_reves() {
    // Propiedades que tiene cualquier mapa de verdad. Si el lector las rompiera,
    // seria que esta partiendo mal las lineas.
    let (regiones, _) = leer_mapa(&mapa_propio());
    for r in &regiones {
        assert!(r.valida(), "region al reves: {}", r.frase());
    }
    for par in regiones.windows(2) {
        assert!(
            par[0].fin <= par[1].inicio,
            "se solapan: {} y {}",
            par[0].frase(),
            par[1].frase()
        );
    }
}

#[test]
fn el_codigo_del_proceso_viene_de_ficheros_y_no_se_senala() {
    // El caso negativo que hace que lo demas signifique algo. Un proceso normal
    // tiene su codigo mapeado desde ficheros que siguen en disco, y un analisis
    // que lo senalara senalaria todos los procesos de todas las maquinas.
    let (regiones, _) = leer_mapa(&mapa_propio());
    let ejecutables: Vec<_> = regiones.iter().filter(|r| r.permisos.ejecucion).collect();
    assert!(
        !ejecutables.is_empty(),
        "un proceso tiene codigo; si no sale ninguna region ejecutable, el \
         lector esta leyendo mal los permisos"
    );
    let sin_respaldo: Vec<_> = ejecutables
        .iter()
        .filter(|r| r.codigo_sin_respaldo())
        .collect();
    eprintln!(
        "{} regiones ejecutables, {} de ellas sin respaldo de fichero",
        ejecutables.len(),
        sin_respaldo.len()
    );
    for r in &sin_respaldo {
        eprintln!("   sin respaldo: {}", r.frase());
    }
    // Un binario de pruebas de Rust no carga nada reflexivamente ni compila al
    // vuelo. Las regiones ejecutables sin respaldo tienen que ser pocas; si
    // salieran muchas, es que se estan leyendo mal los nombres.
    assert!(
        sin_respaldo.len() <= 2,
        "demasiadas regiones ejecutables sin respaldo en un proceso normal: {}",
        sin_respaldo.len()
    );
}

#[test]
fn ninguna_region_de_un_proceso_normal_es_escribible_y_ejecutable() {
    // Es la combinacion que ningun sistema moderno concede por defecto. Si
    // saliera alguna en este mismo proceso de pruebas, o la maquina esta
    // configurada de una forma muy rara o el lector de permisos esta mal.
    let (regiones, _) = leer_mapa(&mapa_propio());
    let rwx: Vec<_> = regiones
        .iter()
        .filter(|r| r.permisos.escribible_y_ejecutable())
        .collect();
    for r in &rwx {
        eprintln!("   rwx: {}", r.frase());
    }
    assert!(
        rwx.is_empty(),
        "hay {} regiones escribibles y ejecutables en este proceso",
        rwx.len()
    );
}

#[test]
fn el_analisis_del_mapa_de_un_proceso_real_no_produce_ruido() {
    // La medida que de verdad dice si esto sirve. Se analiza el mapa de este
    // proceso —sin leer su memoria— y se cuenta lo que sale.
    let (regiones, _) = leer_mapa(&mapa_propio());
    let total = regiones.len();
    // Sin bytes: lo que se ejercita es el analisis del MAPA, que es la parte que
    // mas dice por byte leido y la que corre siempre.
    let m = EnMemoria::nueva(Vec::new(), regiones);
    let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
    eprintln!("mapa de {total} regiones: {}", i.frase());
    let por_clase: BTreeSet<Clase> = i.hallazgos().iter().map(|h| h.clase).collect();
    assert!(
        i.hallazgos().len() <= 2,
        "{} hallazgos en un proceso normal es ruido: {:?}",
        i.hallazgos().len(),
        por_clase
    );
    // Y todo lo que salga tiene que traer su explicacion: un hallazgo sin ella
    // obliga a quien lo lea a fiarse.
    for h in i.hallazgos() {
        assert!(!h.porque.is_empty(), "hallazgo sin explicacion: {h:?}");
        assert!(!h.que.is_empty(), "hallazgo sin lo que se vio: {h:?}");
    }
}

#[test]
fn un_mapa_hostil_no_cuelga_ni_agota_la_memoria() {
    // El mapa de un volcado lo escribe la herramienta que hizo el volcado, y esa
    // herramienta puede estar rota o mentir. Lo que se comprueba no es que el
    // resultado sea bueno, sino que el analisis TERMINA y no reserva memoria por
    // lo que diga el fichero.
    let hostiles = [
        // Una region que dice ocupar todo el espacio de direcciones.
        "0-ffffffffffffffff rwxp 00000000 00:00 0 \n",
        // Mil regiones enormes.
        &(0..1000)
            .map(|n| {
                format!(
                    "{:x}-{:x} rwxp 0 00:00 0 \n",
                    n * 0x1000_0000_0000u64,
                    (n + 1) * 0x1000_0000_0000u64
                )
            })
            .collect::<String>(),
        // Lineas al reves, vacias y truncadas.
        "ffff-0000 rwxp 0 00:00 0 \n\n\nxx\n0-\n-0\n",
        // Un nombre enorme.
        &format!("1000-2000 rwxp 0 08:01 1 {}\n", "a".repeat(100_000)),
    ];
    for (n, texto) in hostiles.iter().enumerate() {
        let reloj = std::time::Instant::now();
        let (regiones, _) = leer_mapa(texto);
        let m = EnMemoria::nueva(Vec::new(), regiones);
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(
            reloj.elapsed() < std::time::Duration::from_secs(5),
            "el caso hostil {n} tardo {:?}",
            reloj.elapsed()
        );
        // Lo que no puede pasar es que una region declarada enorme haga leer o
        // reservar por su tamano declarado.
        for h in i.hallazgos() {
            assert!(!h.porque.is_empty());
        }
    }
}

#[test]
fn una_region_anonima_construida_a_mano_si_se_senala() {
    // El caso positivo, para que el negativo signifique algo: si el analisis no
    // senalara nunca nada, pasaria todas las pruebas anteriores sin servir.
    let (regiones, _) = leer_mapa("7f0000000000-7f0000001000 rwxp 00000000 00:00 0 \n");
    assert_eq!(regiones.len(), 1);
    assert_eq!(regiones[0].respaldo, Respaldo::Anonima);
    let m = EnMemoria::nueva(Vec::new(), regiones);
    let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
    assert!(
        i.hallazgos()
            .iter()
            .any(|h| h.clase == Clase::EscribibleYEjecutable),
        "{}",
        i.frase()
    );
    assert!(
        i.hallazgos()
            .iter()
            .any(|h| h.clase == Clase::CodigoSinRespaldo),
        "{}",
        i.frase()
    );
}
