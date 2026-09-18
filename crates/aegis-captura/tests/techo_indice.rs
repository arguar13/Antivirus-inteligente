//! El techo del indice, medido con un asignador que cuenta.
//!
//! # Por que esta prueba existe
//!
//! El anillo acota el **contenido**. Pero el sobre —quien hablo con quien, cuando,
//! cuanto— se anota de TODO el trafico, tambien del noventa y nueve por ciento que
//! no se guarda. Un indice sin techo convierte «no guardamos casi nada» en una
//! memoria que crece con el trafico, y quien genera el trafico es justamente de
//! quien hay que defenderse. Es la misma forma de fallo que la invariante 9
//! describe para los disectores: **una cota por flujo no es una cota**, porque un
//! millon de flujos pequenos son un problema grande.
//!
//! Aqui se mide lo que el techo promete, y se mide de verdad:
//!
//!   1. Lo que ocupa una entrada, con un asignador que cuenta los bytes vivos, y
//!      no con una estimacion escrita en un comentario.
//!   2. Que el indice no pasa de su techo por mucho trafico que se le eche.
//!   3. Que el que inunda **se desaloja a si mismo**, y no a la maquina callada.
//!      Un indice que desalojara lo mas antiguo le daria al atacante un borrador
//!      de pruebas gratis: inundar el sensor le borraria el sobre a todos los
//!      demas, incluida la maquina que esta atacando.
//!   4. Que lo que se cae **se cuenta**, y aparte de lo que se purga por
//!      caducidad, porque las dos cosas se arreglan de forma distinta.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use aegis_captura::indice::{Entrada, Indice, Particion, COSTE_POR_ENTRADA, MAX_ENTRADAS};
use aegis_captura::redaccion::{Donde, Redactor};
use aegis_captura::retencion::{Autorizacion, Caducidad, Decision, Politica};
use aegis_captura::{Capturador, Flujo};
use aegis_entidad::arbitro::{Resultado, Veredicto};
use aegis_entidad::entidad;
use aegis_entidad::escala::{Confianza, Severidad};

/// Un asignador que cuenta los bytes vivos **de este hilo**.
///
/// # Por que no se mira el RSS del proceso
///
/// Porque no mide lo que se cree que mide. El RSS lo mueven el resto de hilos de
/// prueba, las paginas que el asignador guarda sin devolver al sistema y la cache
/// del fichero. En la FASE 89 una medida de `/proc/self/statm` dio ochenta
/// megabytes de crecimiento con un techo de treinta y dos y sin fuga ninguna.
/// Contar las llamadas al asignador da el numero que se busca y no otro parecido.
///
/// # Y por que por hilo y no un contador global
///
/// Porque un contador global tampoco lo mide. La primera version de esta prueba
/// usaba un `AtomicUsize` compartido y dio **237 bytes por entrada en una
/// ejecucion y 185 en la siguiente**, sin tocar el codigo: `cargo test` corre las
/// pruebas del mismo binario en paralelo, y lo que reservaban las otras caia
/// dentro de la medida. Una cifra que cambia un treinta por ciento entre dos
/// ejecuciones no es una medida, y una constante derivada de ella tampoco.
///
/// Con el contador en el hilo, lo que reserven las demas pruebas no entra. El
/// inicializador es `const` a proposito: un `thread_local!` perezoso reserva
/// memoria la primera vez que se toca, y reservar memoria dentro del asignador es
/// una recursion infinita.
struct Contando;

thread_local! {
    static VIVOS: Cell<isize> = const { Cell::new(0) };
}

fn suma(n: isize) {
    // `try_with` y no `with`: durante el desmontaje del hilo el `thread_local` ya
    // no esta, y un `with` ahi dentro entra en panico desde el asignador.
    let _ = VIVOS.try_with(|v| v.set(v.get() + n));
}

unsafe impl GlobalAlloc for Contando {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        suma(l.size() as isize);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        suma(-(l.size() as isize));
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, nuevo: usize) -> *mut u8 {
        suma(nuevo as isize - l.size() as isize);
        unsafe { System.realloc(p, l, nuevo) }
    }
}

#[global_allocator]
static ASIGNADOR: Contando = Contando;

fn vivos() -> isize {
    VIVOS.with(Cell::get)
}

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

fn entrada(eid: &aegis_entidad::entidad::Eid, cuando_ns: u64) -> Entrada {
    Entrada {
        entidad: eid.clone(),
        cuando_ns,
        particion: Particion::de(cuando_ns, Politica::SoloMetadatos),
        desde: 0,
        bytes: 1200,
        paquetes: 1,
        politica: Politica::SoloMetadatos,
        caducidad: Caducidad::de_politica(Politica::SoloMetadatos),
        bytes_tapados: 0,
    }
}

/// Lo que ocupa una entrada, medido, contra lo que dice la constante.
///
/// Si esta prueba falla es que una entrada ha engordado: un campo nuevo, un
/// `String` donde habia un `Eid`. Entonces `COSTE_POR_ENTRADA` esta mal y hay que
/// volver a medirla — que es el unico momento en el que se puede cambiar. Cambiar
/// la constante para que la prueba pase sin volver a medir es como subirle el
/// limite a la alarma para que deje de sonar.
#[test]
fn las_entradas_del_indice_ocupan_lo_que_dice_la_constante() {
    const CUANTAS: usize = 20_000;
    let eids: Vec<_> = (0..200u32)
        .map(|n| entidad::maquina(&format!("m{n}")))
        .collect();

    let antes = vivos();
    let mut i = Indice::con_tope(CUANTAS);
    for n in 0..CUANTAS as u64 {
        let eid = &eids[(n as usize) % eids.len()];
        i.anadir(entrada(eid, n * 1_000_000));
    }
    let ocupa = vivos().saturating_sub(antes).max(0) as usize;
    let por_entrada = ocupa / CUANTAS;

    println!("\n=== Lo que ocupa el indice ===");
    println!("  {CUANTAS} entradas de {} entidades", eids.len());
    println!("  {ocupa} bytes vivos, {por_entrada} por entrada");
    println!("  declarado: {COSTE_POR_ENTRADA} por entrada");
    println!(
        "  techo del agente: {MAX_ENTRADAS} entradas ({} bytes)",
        MAX_ENTRADAS * COSTE_POR_ENTRADA
    );

    assert_eq!(i.cuantas(), CUANTAS);
    assert!(i.cuadra());
    assert!(
        por_entrada <= COSTE_POR_ENTRADA,
        "una entrada ocupa {por_entrada} bytes y la constante dice {COSTE_POR_ENTRADA}: \
         vuelve a medirla, no la subas sin mas"
    );

    // Y que no este absurdamente por lo alto: una constante cuatro veces mayor
    // que lo medido tambien es una constante equivocada, solo que del otro lado —
    // haria creer que el indice ocupa mucho mas de lo que ocupa y el techo saldria
    // cuatro veces mas bajo de lo que podria ser. El margen que si hace falta es
    // el del arbol lleno en mal orden, que cabe de sobra en un factor de cuatro.
    assert!(
        por_entrada * 4 >= COSTE_POR_ENTRADA,
        "una entrada ocupa {por_entrada} bytes y se han reservado {COSTE_POR_ENTRADA}"
    );

    // La medida tiene que ser la misma en dos ejecuciones seguidas del mismo
    // hilo. Si no lo es, esta contaminada por otra cosa y no vale para derivar
    // una constante — que es exactamente lo que le pasaba con un contador global.
    let antes2 = vivos();
    let mut j = Indice::con_tope(CUANTAS);
    for n in 0..CUANTAS as u64 {
        j.anadir(entrada(&eids[(n as usize) % eids.len()], n * 1_000_000));
    }
    let ocupa2 = vivos().saturating_sub(antes2).max(0) as usize;
    assert_eq!(
        ocupa, ocupa2,
        "la medida cambia entre dos indices iguales: esta contaminada"
    );
    drop(j);

    drop(i);
}

/// El techo se cumple por muchas entradas que se metan.
#[test]
fn el_indice_del_agente_no_pasa_de_su_techo() {
    let mut i = Indice::nuevo();
    let eids: Vec<_> = (0..50u32)
        .map(|n| entidad::maquina(&format!("m{n}")))
        .collect();

    for n in 0..(MAX_ENTRADAS as u64 * 3) {
        let eid = &eids[(n as usize) % eids.len()];
        i.anadir(entrada(eid, n * 1000));
        assert!(
            i.cuantas() <= MAX_ENTRADAS,
            "el indice paso del techo en la entrada {n}: {} > {MAX_ENTRADAS}",
            i.cuantas()
        );
    }

    assert_eq!(i.cuantas(), MAX_ENTRADAS);
    assert!(i.cuadra(), "la contabilidad del indice no cuadra");
    // Lo que no cupo se conto: tres veces el techo metidas, dos veces el techo
    // fuera.
    assert_eq!(i.desbordadas(), MAX_ENTRADAS as u64 * 2);
}

/// **La cifra de esta invariante**: el que inunda se desaloja a si mismo.
///
/// Una maquina callada mete diez entradas. Otra inunda con cien veces el techo.
/// Si el desalojo fuera por antiguedad, las diez de la callada serian las
/// primeras en irse y el atacante habria borrado el sobre de la maquina que
/// ataca. Desalojando a la mas cargada, las diez siguen ahi.
#[test]
fn el_que_inunda_el_indice_se_desaloja_a_si_mismo() {
    let callada = entidad::maquina("la-que-no-dice-nada");
    let ruidosa = entidad::maquina("la-que-inunda");

    let mut i = Indice::nuevo();

    // Primero las diez de la callada: son las MAS ANTIGUAS del indice, que es lo
    // que las convertiria en las primeras victimas de un desalojo por antiguedad.
    for n in 0..10u64 {
        i.anadir(entrada(&callada, n * 1000));
    }

    // Y ahora la inundacion: cien veces el techo.
    for n in 0..(MAX_ENTRADAS as u64 * 100) {
        i.anadir(entrada(&ruidosa, 1_000_000 + n));
    }

    let p = i.buscar(&callada, None, 100);
    let q = i.buscar(&ruidosa, None, 10);

    println!("\n=== Inundacion del indice ===");
    println!("  techo: {MAX_ENTRADAS} entradas");
    println!(
        "  se metieron {} entradas de la ruidosa y 10 de la callada",
        MAX_ENTRADAS as u64 * 100
    );
    println!(
        "  a la callada le quedan {} de 10, y se le cayeron {} por desbordamiento",
        p.entradas.len(),
        p.desbordadas
    );
    println!("  a la ruidosa se le cayeron {}", q.desbordadas);
    println!("  en el indice quedan {} entradas", i.cuantas());

    assert_eq!(
        p.entradas.len(),
        10,
        "la maquina callada perdio sobre por el trafico de otra: eso es un borrador \
         de pruebas regalado al atacante"
    );
    assert_eq!(p.desbordadas, 0);
    assert!(q.desbordadas > 0, "la ruidosa tenia que haberse desalojado");
    assert!(i.cuantas() <= MAX_ENTRADAS);
    assert!(i.cuadra());

    // Y la perdida por desbordamiento NO se confunde con la de caducidad, que es
    // lo que separa «el producto funcionando» de «el agente quedandose corto».
    assert_eq!(p.purgadas, 0);
    assert_eq!(q.purgadas, 0);
}

/// El capturador entero, no solo el indice: el techo se sostiene con el camino
/// completo —redaccion, anillo, indice— y la contabilidad del anillo sigue
/// cuadrando.
#[test]
fn el_capturador_completo_respeta_el_techo_del_indice() {
    let a = Autorizacion::del_veredicto(&veredicto()).expect("autoriza");
    let mut c = Capturador::nuevo(Redactor::nuevo(), 256 * 1024);
    let mut f = Flujo::nuevo(entidad::maquina("el-que-manda-mucho"), Donde::default());
    f.decidir(Decision::autorizada(&a));

    let datos = vec![b'.'; 1200];
    for n in 0..(MAX_ENTRADAS as u64 * 4) {
        c.capturar(&mut f, n * 1000, &datos, datos.len());
        if n % 128 == 0 {
            c.vaciar();
        }
    }

    assert!(c.indice().cuantas() <= MAX_ENTRADAS);
    assert!(c.indice().cuadra());
    assert!(c.indice().desbordadas() > 0);
    assert!(
        c.contadores().cuadran_en_la_entrada(),
        "{:?}",
        c.contadores()
    );
}
