//! El productor y el consumidor del ring, cara a cara, en el host.
//!
//! Estas pruebas comprueban las tres reglas del protocolo desde el otro lado
//! del que las prueba `ring.rs`: que lo que escribe el productor lo lee el
//! consumidor identico, que la envoltura al final del buffer no pierde ni
//! duplica registros, y que un ring lleno suelta en vez de corromper.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use aegis_ipc::{PushOutcome, RingConsumer, RingProducer};

const DATA_OFFSET: u64 = 256;

/// Mapeo compartido para las pruebas, con desmontaje al salir.
struct Mapa {
    base: *mut u8,
    layout: Layout,
    len: usize,
}

impl Mapa {
    fn nuevo(capacity: u64) -> Mapa {
        let len = (DATA_OFFSET + capacity) as usize;
        let layout = Layout::from_size_align(len, 64).unwrap();
        let base = unsafe { alloc_zeroed(layout) };
        assert!(!base.is_null());
        unsafe { RingProducer::format(base, len, capacity, DATA_OFFSET) }.unwrap();
        Mapa { base, layout, len }
    }
    fn productor(&self) -> RingProducer {
        unsafe { RingProducer::attach(self.base, self.len) }.unwrap()
    }
    fn consumidor(&self) -> RingConsumer {
        unsafe { RingConsumer::attach(self.base, self.len) }.unwrap()
    }
}

impl Drop for Mapa {
    fn drop(&mut self) {
        unsafe { dealloc(self.base, self.layout) };
    }
}

// SAFETY: el protocolo es SPSC; cada puntero cruza a un solo hilo a la vez.
unsafe impl Send for Mapa {}
unsafe impl Sync for Mapa {}

/// Cuerpo de un evento sintetico: primeros 8 bytes un contador, para poder
/// comprobar el orden a la salida.
fn cuerpo(n: u64, extra: usize) -> Vec<u8> {
    let mut v = vec![0u8; 8 + extra];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

#[test]
fn lo_que_escribe_el_productor_lo_lee_el_consumidor_identico() {
    let m = Mapa::nuevo(1 << 16);
    let mut p = m.productor();
    let mut c = m.consumidor();

    for i in 0..100u64 {
        assert!(p
            .push(0x0011, 0xAA00 | i, 1000 + i, &cuerpo(i, (i % 64) as usize))
            .is_pushed());
    }

    let mut vistos = Vec::new();
    let n = c
        .drain(1000, |ev| {
            let h = ev.header();
            let body = ev.payload_bytes();
            let contador = u64::from_le_bytes(body[..8].try_into().unwrap());
            vistos.push((h.actor_key, h.ts_ns, contador));
        })
        .unwrap();

    assert_eq!(n, 100);
    for (i, (actor, ts, contador)) in vistos.iter().enumerate() {
        let i = i as u64;
        assert_eq!(*actor, 0xAA00 | i);
        assert_eq!(*ts, 1000 + i);
        assert_eq!(*contador, i, "el orden FIFO se conserva");
    }
}

#[test]
fn la_envoltura_al_final_del_buffer_no_pierde_ni_duplica() {
    // Ring pequeno para forzar muchas vueltas.
    let m = Mapa::nuevo(1 << 12);
    let mut p = m.productor();
    let mut c = m.consumidor();

    let mut escritos = 0u64;
    let mut leidos = 0u64;
    let mut siguiente_esperado = 0u64;

    // Se alterna escribir y drenar para que el productor de muchas vueltas al
    // buffer sin llenarlo.
    for ronda in 0..2000u64 {
        let tam = (ronda % 200) as usize;
        if p.push(0x0011, ronda, ronda, &cuerpo(escritos, tam))
            .is_pushed()
        {
            escritos += 1;
        }
        if ronda % 3 == 0 {
            c.drain(64, |ev| {
                let contador = u64::from_le_bytes(ev.payload_bytes()[..8].try_into().unwrap());
                assert_eq!(
                    contador, siguiente_esperado,
                    "hueco o duplicado en la envoltura"
                );
                siguiente_esperado += 1;
                leidos += 1;
            })
            .unwrap();
        }
    }
    // Drenar lo que quede.
    c.drain(100_000, |ev| {
        let contador = u64::from_le_bytes(ev.payload_bytes()[..8].try_into().unwrap());
        assert_eq!(contador, siguiente_esperado);
        siguiente_esperado += 1;
        leidos += 1;
    })
    .unwrap();

    assert_eq!(
        escritos, leidos,
        "todo lo escrito se leyo exactamente una vez"
    );
    assert!(
        escritos > 500,
        "la prueba tiene que haber movido volumen real"
    );
    assert_eq!(
        p.dropped_events(),
        0,
        "con drenado intercalado no debe soltar"
    );
}

#[test]
fn un_ring_lleno_suelta_en_vez_de_corromper() {
    let m = Mapa::nuevo(1 << 10);
    let mut p = m.productor();
    let mut c = m.consumidor();

    // Se escribe sin drenar hasta que empieza a soltar.
    let mut pushed = 0u64;
    let mut dropped = 0u64;
    for i in 0..10_000u64 {
        match p.push(0x0011, i, i, &cuerpo(i, 0)) {
            PushOutcome::Pushed { .. } => pushed += 1,
            PushOutcome::Dropped => dropped += 1,
            PushOutcome::TooLarge { .. } => unreachable!(),
        }
    }
    assert!(
        dropped > 0,
        "un ring que no se drena tiene que acabar soltando"
    );
    assert_eq!(p.dropped_events(), dropped);

    // Y lo que SI entro sigue siendo interpretable: soltar no corrompe el flujo.
    let mut leidos = 0u64;
    let mut anterior = None;
    c.drain(100_000, |ev| {
        let contador = u64::from_le_bytes(ev.payload_bytes()[..8].try_into().unwrap());
        if let Some(a) = anterior {
            assert!(contador > a, "el orden se conserva entre lo que si entro");
        }
        anterior = Some(contador);
        leidos += 1;
    })
    .unwrap();
    assert_eq!(leidos, pushed, "se lee exactamente lo que se acepto");
}

#[test]
fn un_evento_mas_grande_que_el_ring_se_rechaza_sin_tocar_nada() {
    let m = Mapa::nuevo(1 << 8);
    let mut p = m.productor();
    let enorme = vec![0u8; 4096];
    match p.push(0x0011, 1, 1, &enorme) {
        PushOutcome::TooLarge { capacity, .. } => assert_eq!(capacity, 1 << 8),
        otro => panic!("se esperaba TooLarge, llego {otro:?}"),
    }
    assert_eq!(
        p.dropped_events(),
        0,
        "un error de programacion no es un drop"
    );
    assert_eq!(p.backlog_bytes(), 0, "no se escribio nada");
}

/// El caso que importa de verdad: productor y consumidor en HILOS DISTINTOS,
/// comunicandose solo por el ring, con las barreras de memoria del protocolo.
#[test]
fn productor_y_consumidor_concurrentes_no_pierden_datos() {
    const N: u64 = 200_000;
    let m = Arc::new(Mapa::nuevo(1 << 16));
    let fin = Arc::new(AtomicBool::new(false));
    let leidos = Arc::new(AtomicU64::new(0));

    let m_prod = m.clone();
    let fin_prod = fin.clone();
    let productor = std::thread::spawn(move || {
        let mut p = m_prod.productor();
        let mut enviados = 0u64;
        let mut soltados = 0u64;
        let mut i = 0u64;
        while enviados < N {
            match p.push(0x0011, i, i, &cuerpo(enviados, (i % 96) as usize)) {
                PushOutcome::Pushed { .. } => enviados += 1,
                PushOutcome::Dropped => {
                    soltados += 1;
                    std::thread::yield_now();
                }
                PushOutcome::TooLarge { .. } => unreachable!(),
            }
            i += 1;
        }
        fin_prod.store(true, Ordering::Release);
        (enviados, soltados)
    });

    let m_cons = m.clone();
    let fin_cons = fin.clone();
    let leidos_c = leidos.clone();
    let consumidor = std::thread::spawn(move || {
        let mut c = m_cons.consumidor();
        let mut esperado = 0u64;
        loop {
            let n = c
                .drain(4096, |ev| {
                    let contador = u64::from_le_bytes(ev.payload_bytes()[..8].try_into().unwrap());
                    assert_eq!(contador, esperado, "hueco o duplicado entre hilos");
                    esperado += 1;
                })
                .unwrap();
            leidos_c.fetch_add(n as u64, Ordering::Relaxed);
            if n == 0 {
                if fin_cons.load(Ordering::Acquire) && c.backlog_bytes() == 0 {
                    break;
                }
                std::thread::yield_now();
            }
        }
        esperado
    });

    let (enviados, _soltados) = productor.join().unwrap();
    let esperado_final = consumidor.join().unwrap();

    assert_eq!(enviados, N);
    assert_eq!(leidos.load(Ordering::Relaxed), N, "se leyo todo lo enviado");
    assert_eq!(esperado_final, N, "sin huecos ni duplicados en {N} eventos");
}
