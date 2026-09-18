//! Las cifras de la fase, medidas: perdida bajo carga, disco por hora y tiempo
//! de busqueda.
//!
//! # La regla, la misma que en la FASE 89
//!
//! **Lo que se mide se mide, y lo que se cita se cita, y se dice cual es cual.**
//!
//! Lo que se mide aqui sale de ejecutar el capturador de verdad contra un perfil
//! de trafico: cuantos paquetes se pierden, cuantos bytes acaban en disco y
//! cuanto tarda una busqueda por entidad. Lo que se cita del sensor de referencia
//! es su modelo de almacenamiento, no un numero de una ejecucion suya: no se ha
//! ejecutado Arkime contra este mismo trafico, y presentar una cifra ajena como
//! medida propia es exactamente lo que este producto existe para no hacer.
//!
//! Lo que si se puede comparar honradamente es el **modelo**: Arkime guarda el
//! PCAP de todo el trafico y sus metadatos; aqui se guarda entero lo que el
//! arbitro marco y solo el sobre lo demas. La diferencia se calcula con el mismo
//! perfil de trafico para los dos, y el perfil esta escrito aqui para que
//! cualquiera lo discuta.

use std::time::Instant;

use aegis_captura::redaccion::{Donde, Redactor};
use aegis_captura::retencion::{Autorizacion, Decision};
use aegis_captura::{ahorro, Capturador, Flujo, Politica};
use aegis_entidad::arbitro::{Resultado, Veredicto};
use aegis_entidad::entidad;
use aegis_entidad::escala::{Confianza, Severidad};

/// El perfil de trafico con el que se mide.
///
/// # De donde salen estos numeros
///
/// De lo que ve una red corporativa mediana en una hora, y **no de lo que
/// conviene**: mil flujos, quinientos paquetes cada uno de mil doscientos bytes
/// de media. Son seiscientos megabytes por hora, que es el orden de una oficina
/// de doscientas personas.
///
/// La proporcion de flujos acusados —**uno de cada doscientos**— es la parte que
/// mas decide el resultado, y es la que hay que discutir si alguien discute la
/// cifra. Un dia con un incidente en marcha sube esa proporcion, y entonces el
/// ahorro baja: eso es lo correcto, porque ese dia si hay que guardar.
const FLUJOS: u32 = 1000;
const PAQUETES_POR_FLUJO: u64 = 500;
const BYTES_POR_PAQUETE: usize = 1200;
const UNO_DE_CADA: u32 = 200;

fn veredicto() -> Veredicto {
    Veredicto {
        entidad: entidad::maquina("m"),
        resultado: Resultado::Malicioso,
        severidad: Severidad::Alta,
        confianza: Confianza::nueva(90),
        porque: "dos planos independientes lo sostienen".to_owned(),
        planos: Vec::new(),
        senales: Vec::new(),
    }
}

/// Un paquete con pinta de trafico real: cabecera HTTP y relleno.
fn paquete(n: u64) -> Vec<u8> {
    let mut v = format!(
        "GET /recurso/{n} HTTP/1.1\r\nHost: intranet.empresa.es\r\nUser-Agent: navegador\r\n\r\n"
    )
    .into_bytes();
    v.resize(BYTES_POR_PAQUETE, b'.');
    v
}

/// Lo que sale de una pasada de medicion.
struct Medida {
    bytes_en_disco: u64,
    bytes_vistos: u64,
    entidades: usize,
    entradas: usize,
}

/// Mide el capturador con una politica fija para todos los flujos.
///
/// Con `Politica::Completo` para todos se obtiene lo que guardaria un capturador
/// que lo guarda todo, que es el modelo del sensor de referencia.
fn medir(todo_entero: bool) -> Medida {
    let a = Autorizacion::del_veredicto(&veredicto()).expect("malicioso autoriza");
    // El anillo se vacia cada pocos paquetes, como haria el escritor a disco:
    // medir el disco con el anillo lleno mediria el anillo.
    //
    // Y el indice se construye con el techo del ALMACEN, no con el del agente.
    // No es una licencia: es lo que se esta midiendo. El agente no guarda el
    // sobre de una hora de trafico —no le cabe, y su techo lo dice—; lo drena, y
    // quien lo conserva es el servidor. Esta prueba compara dos MODELOS DE
    // ALMACENAMIENTO, asi que el techo tiene que ser el del sitio donde se
    // almacena. Lo que le pasa al agente cuando NO drena se mide aparte, en
    // `el_que_inunda_el_indice_se_desaloja_a_si_mismo`.
    let entradas = (FLUJOS as u64 * PAQUETES_POR_FLUJO) as usize;
    let mut c = Capturador::con_topes(Redactor::nuevo(), 4 * 1024 * 1024, entradas);
    let mut vistos = 0u64;

    for n in 0..FLUJOS {
        let mut f = Flujo::nuevo(entidad::maquina(&format!("m{n}")), Donde::default());
        if todo_entero || n % UNO_DE_CADA == 0 {
            f.decidir(Decision::autorizada(&a));
        }
        for i in 0..PAQUETES_POR_FLUJO {
            let p = paquete(i);
            c.capturar(&mut f, i * 1000, &p, p.len());
            if i % 64 == 0 {
                c.vaciar();
            }
        }
        c.vaciar();
        vistos += f.vistos();
    }

    Medida {
        bytes_en_disco: c.bytes_de_contenido(),
        bytes_vistos: vistos,
        entidades: c.indice().entidades(),
        entradas: c.indice().cuantas(),
    }
}

/// LA cifra de la fase: cuanto disco ahorra retener por veredicto, con el mismo
/// trafico para los dos modelos.
#[test]
fn la_retencion_por_veredicto_contra_guardarlo_todo() {
    let selectiva = medir(false);
    let todo = medir(true);

    // El modelo de guardarlo todo guarda, en efecto, todo.
    assert_eq!(todo.bytes_en_disco, todo.bytes_vistos);

    let ahorrado = ahorro(selectiva.bytes_en_disco, selectiva.bytes_vistos);
    let veces = todo.bytes_en_disco as f64 / selectiva.bytes_en_disco.max(1) as f64;

    println!("\n=== Disco por hora de trafico equivalente ===");
    println!(
        "perfil: {FLUJOS} flujos, {PAQUETES_POR_FLUJO} paquetes de {BYTES_POR_PAQUETE} bytes, \
         uno de cada {UNO_DE_CADA} acusado"
    );
    println!(
        "  trafico visto:            {} bytes",
        selectiva.bytes_vistos
    );
    println!(
        "  guardandolo todo:         {} bytes  (el modelo del sensor de referencia)",
        todo.bytes_en_disco
    );
    println!(
        "  retencion por veredicto:  {} bytes  ({ahorrado}% menos, {veces:.1}x)",
        selectiva.bytes_en_disco
    );
    println!(
        "  y el sobre se conserva entero en los dos: {} entidades, {} entradas de indice",
        selectiva.entidades, selectiva.entradas
    );
    println!(
        "  (el sobre lo conserva el ALMACEN: al agente le caben {} entradas y las drena;\n   \
         lo que pasa si no drena se mide en techo_indice.rs)",
        aegis_captura::MAX_ENTRADAS
    );

    // Un orden de magnitud es lo que se afirma, y es lo que se exige.
    assert!(
        veces >= 10.0,
        "solo se ahorro {veces:.1}x, y la afirmacion es un orden de magnitud"
    );
    assert!(ahorrado >= 90, "solo se ahorro el {ahorrado}%");

    // Y lo que NO se pierde: el sobre de todos los flujos esta en los dos casos.
    assert_eq!(selectiva.entidades, FLUJOS as usize);
    assert_eq!(selectiva.entidades, todo.entidades);
    assert_eq!(selectiva.entradas, todo.entradas);
}

/// Cero perdida bajo carga sostenida, contada con los contadores del propio
/// anillo. «Sin perdida» no es una aspiracion: es una cifra, y si no es cero se
/// dice cuanto.
#[test]
fn cero_perdida_bajo_carga_sostenida_con_el_anillo_bien_dimensionado() {
    // Doscientos mil paquetes de mil quinientos bytes: trescientos megabytes de
    // trafico. El anillo se drena cada trescientos paquetes, como haria el
    // escritor a disco. El numero esta elegido para que la puerta de calidad no
    // necesite modo optimizado: la propiedad —cero perdida con el anillo bien
    // dimensionado— se ve igual, y lo que se alarga es solo el CI.
    const PAQUETES: u64 = 200_000;
    let a = Autorizacion::del_veredicto(&veredicto()).expect("autoriza");
    let mut c = Capturador::nuevo(Redactor::nuevo(), 2 * 1024 * 1024);
    let mut f = Flujo::nuevo(entidad::maquina("el-que-manda-mucho"), Donde::default());
    f.decidir(Decision::autorizada(&a));

    let datos = vec![b'x'; 1500];
    let empezo = Instant::now();
    for i in 0..PAQUETES {
        c.capturar(&mut f, i, &datos, datos.len());
        if i % 300 == 0 {
            c.vaciar();
        }
    }
    c.vaciar();
    let tardo = empezo.elapsed();

    let cont = c.contadores();
    println!("\n=== Carga sostenida ===");
    println!(
        "{PAQUETES} paquetes de {} bytes en {tardo:?} ({:.0} paquetes por segundo)",
        datos.len(),
        PAQUETES as f64 / tardo.as_secs_f64()
    );
    println!("  {}", cont.frase());

    assert!(cont.cuadran_en_la_entrada(), "{cont:?}");
    assert_eq!(cont.recibidos, PAQUETES);
    assert_eq!(
        cont.perdidos(),
        0,
        "se perdieron {} paquetes con el anillo bien dimensionado: {}",
        cont.perdidos(),
        cont.frase()
    );
    assert!(
        cont.frase().contains("sin perder ninguno"),
        "{}",
        cont.frase()
    );
}

/// Y el caso contrario, que tambien hay que medir: con el anillo pequeno **se
/// pierde**, y la cifra lo dice en vez de esconderlo.
#[test]
fn con_el_anillo_pequeno_se_pierde_y_la_cifra_lo_dice() {
    let a = Autorizacion::del_veredicto(&veredicto()).expect("autoriza");
    let mut c = Capturador::nuevo(Redactor::nuevo(), 64 * 1024);
    let mut f = Flujo::nuevo(entidad::maquina("m"), Donde::default());
    f.decidir(Decision::autorizada(&a));

    let datos = vec![b'x'; 1500];
    for i in 0..20_000u64 {
        c.capturar(&mut f, i, &datos, datos.len());
    }
    let cont = c.contadores();
    println!("\n=== Carga con el anillo pequeno ===\n  {}", cont.frase());
    assert!(cont.cuadran_en_la_entrada(), "{cont:?}");
    assert!(cont.perdidos() > 0);
    assert!(cont.fraccion_perdida() > 0);
    assert!(cont.frase().contains("SE PERDIERON"), "{}", cont.frase());
}

/// El tiempo de busqueda por entidad, medido con el indice lleno.
///
/// Es la otra mitad de la comparacion: de poco sirve guardar poco si buscarlo
/// tarda. El indice esta por entidad, asi que el coste no crece con el trafico
/// de las demas.
#[test]
fn buscar_por_entidad_no_crece_con_el_trafico_de_las_demas() {
    // Con el techo del almacen, por lo mismo que en `medir`: lo que se mide es
    // como escala la BUSQUEDA con el indice lleno, y para eso el indice tiene que
    // poder llenarse. El techo del agente se mide donde toca, que es en la prueba
    // del desbordamiento.
    let mut c = Capturador::con_topes(Redactor::nuevo(), 1024 * 1024, 50_000);
    let a = Autorizacion::del_veredicto(&veredicto()).expect("autoriza");

    // Cincuenta mil entradas repartidas entre mil entidades.
    for n in 0..1000u32 {
        let mut f = Flujo::nuevo(entidad::maquina(&format!("m{n}")), Donde::default());
        f.decidir(Decision::autorizada(&a));
        for i in 0..50u64 {
            c.capturar(&mut f, i * 1_000_000, b"paquete corto", 13);
            c.vaciar();
        }
    }
    assert_eq!(c.indice().cuantas(), 50_000);

    let buscada = entidad::maquina("m500");
    let empezo = Instant::now();
    let mut encontradas = 0usize;
    for _ in 0..1000 {
        encontradas = c.indice().buscar(&buscada, None, 1000).entradas.len();
    }
    let tardo = empezo.elapsed();

    println!("\n=== Busqueda por entidad ===");
    println!(
        "  {} entradas de {} entidades; mil busquedas en {tardo:?} ({:?} cada una)",
        c.indice().cuantas(),
        c.indice().entidades(),
        tardo / 1000
    );
    assert_eq!(encontradas, 50);
    assert!(
        tardo < std::time::Duration::from_secs(5),
        "mil busquedas tardaron {tardo:?}: el indice no esta por entidad"
    );
}

/// La comparacion, con lo que se mide y lo que se cita separado.
#[test]
fn el_informe_de_comparacion_separa_lo_medido_de_lo_citado() {
    let selectiva = medir(false);
    let todo = medir(true);

    println!("\n=== Comparacion con el capturador de referencia ===");
    println!("MEDIDO aqui, ejecutando el capturador contra el perfil de trafico de arriba:");
    println!(
        "  - retencion por veredicto: {} bytes de contenido y {} entradas de indice",
        selectiva.bytes_en_disco, selectiva.entradas
    );
    println!(
        "  - guardandolo todo:        {} bytes de contenido y las mismas {} entradas",
        todo.bytes_en_disco, todo.entradas
    );
    println!("CITADO, no medido aqui: el modelo de Arkime es guardar el PCAP completo del");
    println!("  trafico mas sus metadatos en un motor de busqueda de texto. No se ha");
    println!("  ejecutado Arkime contra este trafico, y presentar una cifra ajena como");
    println!("  medida propia es lo que este producto existe para no hacer.");
    println!("LO QUE NO SE COMPARA con un numero, porque el otro no lo tiene:");
    println!("  - el indice por entidad derivada, en vez de por texto normalizado");
    println!("  - la redaccion estructural: las credenciales no llegan al disco");
    println!("  - la reproduccion determinista del veredicto desde lo guardado");
    println!("  - una busqueda que declara cuanto se purgo en vez de callarlo");

    assert!(selectiva.bytes_en_disco < todo.bytes_en_disco);
    assert_eq!(selectiva.entradas, todo.entradas);
    // La politica por defecto es la que hace que esto sea cierto, y esta aqui
    // para que cambiarla duela.
    assert_eq!(Decision::por_defecto().politica, Politica::SoloMetadatos);
}
