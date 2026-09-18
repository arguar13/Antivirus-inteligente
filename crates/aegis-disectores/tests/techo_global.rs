//! La invariante 9, medida: **una cota por flujo no es una cota**.
//!
//! # Por que esta prueba existe y por que con cien mil flujos
//!
//! Porque el atacante elige dos cosas, no una. Elige cuanto manda por flujo —y
//! contra eso vale el tope por flujo— y elige **cuantos flujos abre**, contra lo
//! que el tope por flujo no vale absolutamente nada. Con sesenta y cuatro
//! kilobytes por flujo y cien mil flujos son seis gigabytes que decide el
//! atacante, en un agente que corre en cada maquina de la flota.
//!
//! Cien mil no es un numero redondo elegido por sonar bien: es el orden del
//! numero de conexiones que ve un cortafuegos de una empresa mediana en un
//! minuto, y es tambien el tamano de flota para el que esta dimensionado el
//! plano de control (FASE 75). Si el sensor no aguanta eso, no aguanta el
//! producto.
//!
//! # Que se mide
//!
//! Dos cosas, y la diferencia entre ellas importa:
//!
//! 1. **Los bytes contabilizados**, que son el contrato: lo que el registro dice
//!    estar guardando. Tiene que quedarse bajo el techo global pase lo que pase.
//! 2. **Los bytes vivos de verdad**, contados por un asignador propio de este
//!    fichero de pruebas. Es lo que el proceso tiene reservado ahora mismo, y no
//!    puede cuadrar al byte con lo anterior porque el arbol que indexa los flujos
//!    tambien ocupa. Por eso se mide aparte y con un margen declarado, en vez de
//!    fingir que un contador es una medida.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use aegis_disectores::catalogo::registro_completo;
use aegis_disectores::disector::{Contexto, MAX_ESTADO_GLOBAL, MAX_ESTADO_POR_FLUJO};

/// Cuantos flujos se abren a la vez.
const FLUJOS: u64 = 100_000;

/// Bytes vivos ahora mismo, contados por el asignador.
static VIVOS: AtomicUsize = AtomicUsize::new(0);

/// Un asignador que cuenta lo que hay vivo.
///
/// # Por que esto y no la memoria residente del proceso
///
/// Porque la residente miente en las dos direcciones. Hacia arriba, porque el
/// asignador no devuelve al sistema lo que se libera, asi que se queda en el
/// maximo historico y no en lo que hay ahora. Y hacia abajo no, pero si mide
/// **el proceso entero**: las pruebas corren en hilos del mismo proceso, y la
/// primera version de este fichero medio como crecimiento de un disector la
/// memoria que estaba reservando otra prueba a la vez. El numero salio de
/// ochenta megas con un techo de treinta y dos, y no habia ninguna fuga.
///
/// Contar lo vivo en el asignador da la cifra que se quiere: lo que el registro
/// tiene reservado ahora. El ruido de otras pruebas concurrentes sigue ahi, pero
/// es de kilobytes contra un presupuesto de megas.
struct Contador;

unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            VIVOS.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        VIVOS.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, nuevo: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, nuevo) };
        if !q.is_null() {
            VIVOS.fetch_add(nuevo, Ordering::Relaxed);
            VIVOS.fetch_sub(l.size(), Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static ASIGNADOR: Contador = Contador;

/// Bytes vivos ahora mismo.
fn vivos() -> usize {
    VIVOS.load(Ordering::Relaxed)
}

#[test]
fn cien_mil_flujos_respetando_cada_uno_su_tope_no_pasan_del_global() {
    let mut r = registro_completo();
    let antes = vivos();

    // Cada flujo respeta su tope. Es justo el caso que el tope por flujo deja
    // pasar y el global tiene que parar.
    let trozo = vec![0x41u8; MAX_ESTADO_POR_FLUJO];
    for f in 0..FLUJOS {
        r.guardar(f, &trozo);
        // Y se comprueba en CADA paso, no solo al final: un techo que solo se
        // cumpla cuando se acaba el bucle no es un techo, es una limpieza.
        assert!(
            r.bytes_de_estado() <= MAX_ESTADO_GLOBAL,
            "en el flujo {f} habia {} bytes, por encima del techo global",
            r.bytes_de_estado()
        );
    }

    assert!(
        r.soltados > 0,
        "con {FLUJOS} flujos de {MAX_ESTADO_POR_FLUJO} bytes hubo que soltar estado, \
         y el recuento dice que no se solto ninguno"
    );
    // Lo que se suelta se cuenta Y se dice: un sensor que suelte estado en
    // silencio deja de ver cosas sin que nadie se entere.
    assert!(r.frase().contains("SE SOLTARON"), "{}", r.frase());

    // Y la realidad, aparte del contador del registro. El margen es de dos
    // veces el techo porque el arbol que indexa los flujos tambien ocupa, y ese
    // no es estado de protocolo: exigir que cuadre al byte seria medir el mapa y
    // no el presupuesto.
    let crecio = vivos().saturating_sub(antes);
    assert!(
        crecio <= MAX_ESTADO_GLOBAL * 2,
        "hay {crecio} bytes vivos con un techo de {MAX_ESTADO_GLOBAL}: el registro \
         reserva memoria que no contabiliza"
    );
    println!(
        "cien mil flujos: {} bytes contabilizados, {crecio} bytes vivos de verdad, \
         {} estados soltados",
        r.bytes_de_estado(),
        r.soltados
    );
}

#[test]
fn el_tope_por_flujo_no_se_puede_saltar_ni_con_un_byte() {
    let mut r = registro_completo();
    assert!(
        !r.guardar(1, &vec![0u8; MAX_ESTADO_POR_FLUJO + 1]),
        "un byte de mas del tope por flujo tiene que rechazarse"
    );
    assert!(r.guardar(1, &vec![0u8; MAX_ESTADO_POR_FLUJO]));
    assert_eq!(r.bytes_de_estado(), MAX_ESTADO_POR_FLUJO);
}

#[test]
fn cada_disector_nuevo_cabe_bajo_el_techo_que_ya_existia() {
    // La comprobacion que el encargo pide con atencion especial: lo que anade
    // esta fase tiene que caber bajo el techo GLOBAL que ya habia, no inventarse
    // uno nuevo al lado. El techo de este crate es una fraccion del que
    // `aegis-wire` ya usaba para los bufers de aplicacion, y eso se comprueba
    // aqui contra la constante de verdad, no contra la memoria de quien escribio
    // esto.
    // Que el techo no pase del del motor lo comprueba el propio crate en tiempo
    // de compilacion (`const _: () = assert!(...)` en `disector.rs`), que es mas
    // fuerte que una prueba: una prueba se puede saltar con `--skip`.
    //
    // Lo que se comprueba aqui es lo otro: que los dos topes son LOS MISMOS que
    // los del motor, no dos parecidos: un
    // numero copiado a mano se separa del original el dia que alguien cambia uno
    // de los dos, y entonces la flota tiene dos presupuestos que suman.
    assert_eq!(MAX_ESTADO_POR_FLUJO, aegis_wire::motor::MAX_BUFER_APP);
    assert_eq!(MAX_ESTADO_GLOBAL, aegis_wire::MAX_MEMORIA_APP);
}

#[test]
fn cien_mil_flujos_disecando_de_verdad_no_hacen_crecer_la_memoria() {
    // El otro camino: no guardar estado, sino disecar. Un disector que se
    // guardara algo por dentro —una cache, un contador por flujo, un `Vec` que
    // crece— no lo veria el contador del registro, porque el registro no sabe
    // nada de lo que un disector tenga dentro. Esto si lo veria.
    let mut r = registro_completo();
    let mensajes: Vec<(Vec<u8>, Contexto)> = vec![
        (
            vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
            ],
            Contexto::tcp_cliente(502),
        ),
        (
            b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n".to_vec(),
            Contexto::tcp_cliente(6379),
        ),
        (
            b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".to_vec(),
            Contexto::tcp_cliente(80),
        ),
        (
            vec![
                0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x9C, 0xB2, 0xC0, 0xC1, 0x01,
            ],
            Contexto::tcp_cliente(20000),
        ),
    ];

    // Una vuelta de calentamiento: la primera reserva de cada camino no es
    // crecimiento, es el coste fijo de arrancar.
    for (bytes, ctx) in &mensajes {
        r.disecar(bytes, ctx);
    }
    let antes = vivos();

    for i in 0..FLUJOS {
        let (bytes, ctx) = &mensajes[(i as usize) % mensajes.len()];
        let s = r.disecar(bytes, ctx);
        assert!(s.cobertura.vistos() >= 1);
    }

    let crecio = vivos().saturating_sub(antes);
    // Cien kilobytes de margen para el ruido de las pruebas que corren a la vez
    // en el mismo proceso. Un disector que se guardara algo por mensaje habria
    // dejado aqui megas, no kilobytes.
    assert!(
        crecio <= 100 * 1024,
        "disecar {FLUJOS} mensajes dejo {crecio} bytes vivos: algun disector se esta \
         guardando algo por dentro"
    );
    println!("{FLUJOS} disecciones: {crecio} bytes vivos al acabar");
    assert_eq!(r.cobertura.vistos(), FLUJOS + mensajes.len() as u64);
}
