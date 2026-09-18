//! La comparacion contra el sensor de referencia, medida y no proclamada.
//!
//! # La regla de esta prueba
//!
//! **Una mitad se mide y la otra se cita, y se dice cual es cual.**
//!
//! Lo que se mide aqui sale de construir el registro de verdad y preguntarle:
//! cuantos disectores hay, que protocolos cubren, que declara cada uno que
//! entiende y que declara que no, y que cifra de cobertura sale de un corpus de
//! trafico. Nada de eso viene de una lista escrita a mano.
//!
//! Lo que se cita es la relacion de analizadores de Zeek, transcrita de su
//! documentacion. No se ha ejecutado Zeek contra este corpus, y decirlo importa:
//! presentar un dato de segunda mano como si se hubiera medido es exactamente la
//! clase de cifra que este crate existe para no producir. Ese es el muro, y va
//! declarado en vez de escondido.
//!
//! # Lo que la comparacion de verdad demuestra
//!
//! No el recuento. Los dos numeros son del mismo orden y el recuento se puede
//! mover anadiendo disectores triviales. Lo que no se mueve es que **el otro no
//! contesta a la pregunta**: cuando un analizador de Zeek no entiende un mensaje
//! lo salta, y el analista ve una traza con menos lineas sin saber que faltan.

use aegis_disectores::catalogo::{
    registro_completo, Comparacion, Familia, Perfil, ANALIZADORES_DE_ZEEK,
    LO_QUE_NO_HACE_EL_DE_REFERENCIA,
};
use aegis_disectores::disector::{Contexto, Fuerza};

/// Un corpus de trafico con mensajes que este sensor entiende, mensajes que
/// reconoce y no analiza, y mensajes que no son de nadie.
///
/// La mezcla no es arbitraria: es la que hace que la cifra de cobertura diga
/// algo. Un corpus solo de mensajes validos daria el cien por cien y no probaria
/// nada; uno solo de ruido daria cero y tampoco.
fn corpus() -> Vec<(Vec<u8>, Contexto)> {
    let mut v: Vec<(Vec<u8>, Contexto)> = Vec::new();

    // Lo que se entiende entero.
    v.push((
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03,
        ],
        Contexto::tcp_cliente(502),
    ));
    v.push((
        vec![
            0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x9C, 0xB2, 0xC0, 0xC1, 0x01,
        ],
        Contexto::tcp_cliente(20000),
    ));
    v.push((
        vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08],
        Contexto::udp(47808),
    ));
    v.push((
        b"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n".to_vec(),
        Contexto::tcp_cliente(6379),
    ));
    v.push((
        b"PROPFIND /compartido HTTP/1.1\r\nHost: fs\r\n\r\n".to_vec(),
        Contexto::tcp_cliente(80),
    ));
    v.push((
        b"GET /latest/meta-data/iam/security-credentials/rol HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".to_vec(),
        Contexto::tcp_cliente(80),
    ));

    // Lo que se reconoce y no se analiza: el hueco declarado.
    v.push((
        {
            let mut b = vec![0u8];
            b.extend_from_slice(&4u32.to_be_bytes());
            b.extend_from_slice(&[0x08, 0x96, 0x01, 0x00]);
            b
        },
        Contexto::tcp_cliente(443),
    ));
    v.push((
        b"POST /acs HTTP/1.1\r\nHost: idp\r\n\r\nSAMLResponse=PHNhbWxw".to_vec(),
        Contexto::tcp_cliente(443),
    ));

    // Lo que esta cifrado: el muro que no arregla escribir codigo.
    v.push((
        vec![0x16, 0x03, 0x01, 0x00, 0x2a],
        Contexto::tcp_cliente(853),
    ));
    v.push((
        {
            let mut b = vec![1u8, 0, 0, 0];
            b.extend_from_slice(&7u32.to_le_bytes());
            b.resize(148, 0);
            b
        },
        Contexto::udp(51820),
    ));

    // Y lo que no es de nadie, que tambien es un hecho.
    v.push((
        b"basura que no es ningun protocolo".to_vec(),
        Contexto::tcp_cliente(9999),
    ));
    v.push((vec![0xDE, 0xAD, 0xBE, 0xEF], Contexto::udp(9999)));

    v
}

#[test]
fn el_informe_de_comparacion_sale_de_medir() {
    let c = Comparacion::medir();

    println!("\n=== Comparacion de alcance ===");
    println!("{}\n", c.frase());
    println!("Solo en este sensor ({}):", c.solo_nuestros.len());
    for p in &c.solo_nuestros {
        println!("  + {p}");
    }
    println!("\nSolo en el de referencia ({}):", c.solo_suyos.len());
    for p in &c.solo_suyos {
        println!("  - {p}");
    }
    println!("\nPropiedades que el de referencia no tiene en ningun protocolo:");
    for (que, por_que) in LO_QUE_NO_HACE_EL_DE_REFERENCIA {
        println!("  * {que}: {por_que}");
    }

    // Las dos mitades vienen de sitios distintos, y eso es el punto.
    assert!(c.nuestros >= 40, "se midieron {} protocolos", c.nuestros);
    assert_eq!(c.del_de_referencia, ANALIZADORES_DE_ZEEK.len());
    // Una comparacion en la que solo apareciera lo propio no seria una
    // comparacion: lo que falta tiene que salir igual de claro.
    assert!(!c.solo_suyos.is_empty());
    assert!(!c.solo_nuestros.is_empty());
}

#[test]
fn la_cifra_de_cobertura_sobre_un_corpus_mezclado_distingue_los_tres_casos() {
    let mut r = registro_completo();
    for (bytes, ctx) in corpus() {
        r.disecar(&bytes, &ctx);
    }

    println!("\n=== Cobertura medida sobre el corpus ===");
    println!("{}\n", r.frase());

    use aegis_disectores::Motivo;
    let c = &r.cobertura;
    assert!(c.entendidos >= 6, "se entendieron {}", c.entendidos);
    // Los tres motivos que hacen util la cifra tienen que aparecer, y separados.
    assert!(
        c.sin_analizar.contains_key(&Motivo::TipoNoImplementado),
        "falta el hueco declarado: {:?}",
        c.sin_analizar
    );
    assert!(
        c.sin_analizar.contains_key(&Motivo::Cifrado),
        "falta lo cifrado: {:?}",
        c.sin_analizar
    );
    assert!(
        c.sin_analizar.contains_key(&Motivo::NoReconocido),
        "falta lo no reconocido: {:?}",
        c.sin_analizar
    );
    // Y la distincion que decide en que trabajar: lo cifrado no cuenta como
    // deuda, porque escribir codigo no lo arregla.
    let deuda = c.perdidos_por_falta_de_codigo();
    assert!(deuda < c.perdidos(), "todo lo perdido no puede ser deuda");
    println!(
        "de {} mensajes perdidos, {deuda} se arreglarian escribiendo codigo y {} no",
        c.perdidos(),
        c.perdidos() - deuda
    );
}

#[test]
fn el_alcance_de_cada_perfil_se_mide_y_se_publica() {
    println!("\n=== Alcance por perfil ===");
    for p in [
        Perfil::Completo,
        Perfil::PuestoDeTrabajo,
        Perfil::Servidor,
        Perfil::PasarelaIndustrial,
    ] {
        let r = p.registro();
        println!(
            "{p:?}: {} disectores ({} por marca, {} por forma, {} por indicio) — {}",
            r.cuantos(),
            r.por_fuerza(Fuerza::Marca),
            r.por_fuerza(Fuerza::Forma),
            r.por_fuerza(Fuerza::Indicio),
            r.protocolos().join(", ")
        );
        assert!(r.cuantos() > 0);
    }
}

#[test]
fn la_cobertura_declarada_se_puede_publicar_entera() {
    // La propiedad que ningun otro sensor da: se puede saber que esperar de cada
    // disector ANTES de mandarle trafico. Esta prueba lo imprime entero porque
    // esa tabla es un entregable, no una curiosidad.
    println!("\n=== Cobertura declarada, disector a disector ===");
    let mut entendidos = 0usize;
    let mut huecos = 0usize;
    for f in Familia::TODAS {
        println!("\n-- {} --", f.nombre());
        for d in f.disectores() {
            println!("{}:", d.nombre());
            for m in d.mensajes_que_entiende() {
                println!("   entiende: {m}");
                entendidos += 1;
            }
            for m in d.mensajes_que_no_analiza() {
                println!("   NO analiza: {m}");
                huecos += 1;
            }
        }
    }
    println!("\ntotal: {entendidos} clases de mensaje entendidas, {huecos} huecos declarados");
    // Un sensor con cero huecos declarados esta diciendo que lo entiende todo, y
    // de estos cuarenta protocolos no se entiende ninguno entero.
    assert!(huecos >= 100, "solo {huecos} huecos declarados");
    assert!(entendidos >= 150, "solo {entendidos} clases de mensaje");
}
