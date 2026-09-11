//! Deteccion de ROP/JOP de extremo a extremo con codigo x86-64 REAL.
//!
//! Sin mocks: se ensambla a mano codigo maquina real (gadgets ROP autenticos),
//! se construye una traza Intel PT en formato binario real (paquetes TIP con los
//! destinos de cada salto), se decodifica con el decodificador del crate, se
//! reconstruye el flujo desensamblando con iced-x86, y el analisis decide. Sin
//! un chip con Intel PT, la CORRECCION del pipeline se demuestra igual, porque
//! el formato de la traza y el del codigo son los formatos reales.

use aegis_ptguard::analisis::{analizar_flujo, Veredicto};
use aegis_ptguard::paquete::{Decodificador, Paquete};
use aegis_ptguard::reconstruccion::{reconstruir, Imagen};

const BASE: u64 = 0x0000_0000_0040_0000;

/// Construye una imagen de codigo colocando cada gadget en un slot de 16 bytes.
/// Devuelve (bytes, direcciones de cada gadget).
fn imagen_con_gadgets(gadgets: &[&[u8]]) -> (Vec<u8>, Vec<u64>) {
    let mut bytes = Vec::new();
    let mut dirs = Vec::new();
    for (i, g) in gadgets.iter().enumerate() {
        let off = i * 16;
        bytes.resize(off, 0x90); // relleno con NOP entre slots
        dirs.push(BASE + off as u64);
        bytes.extend_from_slice(g);
    }
    (bytes, dirs)
}

/// Construye una traza PT real: un paquete TIP completo (8 bytes de IP) por cada
/// destino de salto indirecto.
fn traza_de_destinos(destinos: &[u64]) -> Vec<u8> {
    let mut t = Vec::new();
    // PSB al principio, como una traza real.
    for _ in 0..8 {
        t.extend_from_slice(&[0x02, 0x82]);
    }
    t.extend_from_slice(&[0x02, 0x23]); // PSBEND
    for &d in destinos {
        t.push(0xCD); // TIP, ipbytes=0b110 (IP completo de 8 bytes)
        t.extend_from_slice(&d.to_le_bytes());
    }
    t
}

fn tips_decodificados(traza: &[u8]) -> Vec<u64> {
    let mut d = Decodificador::new();
    d.decodificar_todo(traza)
        .unwrap()
        .into_iter()
        .filter_map(|p| match p {
            Paquete::Tip(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

#[test]
fn una_cadena_rop_real_se_detecta_de_extremo_a_extremo() {
    // Gadgets ROP autenticos: cada uno es 1-2 instrucciones terminadas en `ret`.
    //   pop rax; ret / pop rbx; ret / ... / xor eax,eax; ret
    let g: Vec<&[u8]> = vec![
        &[0x58, 0xC3],       // pop rax ; ret
        &[0x5B, 0xC3],       // pop rbx ; ret
        &[0x59, 0xC3],       // pop rcx ; ret
        &[0x5A, 0xC3],       // pop rdx ; ret
        &[0x5E, 0xC3],       // pop rsi ; ret
        &[0x5F, 0xC3],       // pop rdi ; ret
        &[0x58, 0xC3],       // pop rax ; ret
        &[0x5B, 0xC3],       // pop rbx ; ret
        &[0x31, 0xC0, 0xC3], // xor eax,eax ; ret
        &[0x59, 0xC3],       // pop rcx ; ret
    ];
    let (bytes, dirs) = imagen_con_gadgets(&g);
    let imagen = Imagen {
        base: BASE,
        bytes: &bytes,
    };

    // La cadena ROP salta de gadget en gadget: la traza son esos destinos.
    let traza = traza_de_destinos(&dirs);
    let destinos = tips_decodificados(&traza);
    assert_eq!(
        destinos, dirs,
        "los TIP decodificados son los destinos reales"
    );

    let flujo = reconstruir(&imagen, &destinos);
    let v = analizar_flujo(&flujo);
    match v.veredicto {
        Veredicto::Rop { longitud } => {
            assert!(longitud >= 8, "cadena de {longitud} gadgets ROP");
            assert!(v.severidad >= 2);
        }
        otro => panic!("se esperaba ROP, fue {otro:?}"),
    }
}

#[test]
fn una_cadena_jop_real_se_detecta() {
    // Gadgets JOP: terminan en `jmp rax` (0xFF 0xE0), no en ret.
    let g: Vec<&[u8]> = (0..9)
        .map(|_| [0x5B, 0xFF, 0xE0].as_slice()) // pop rbx ; jmp rax
        .collect();
    let (bytes, dirs) = imagen_con_gadgets(&g);
    let imagen = Imagen {
        base: BASE,
        bytes: &bytes,
    };
    let flujo = reconstruir(&imagen, &dirs);
    match analizar_flujo(&flujo).veredicto {
        Veredicto::Jop { longitud } => assert!(longitud >= 8, "cadena JOP de {longitud}"),
        otro => panic!("se esperaba JOP, fue {otro:?}"),
    }
}

#[test]
fn la_ejecucion_normal_no_es_rop() {
    // Un bloque largo: 20 NOPs y un ret. Es un `ret` normal de una funcion, no
    // un gadget: el bloque es largo, asi que no cuenta como eslabon de cadena.
    let mut funcion = vec![0x90u8; 20];
    funcion.push(0xC3); // ret
    let g: Vec<&[u8]> = vec![funcion.as_slice()];
    let (bytes, dirs) = imagen_con_gadgets(&g);
    let imagen = Imagen {
        base: BASE,
        bytes: &bytes,
    };
    let flujo = reconstruir(&imagen, &dirs);
    assert_eq!(
        analizar_flujo(&flujo).veredicto,
        Veredicto::Benigno,
        "un retorno de funcion normal (bloque largo) no es ROP"
    );
}

#[test]
fn pocos_gadgets_cortos_no_bastan_para_gritar_rop() {
    // Tres `ret` cortos seguidos: por debajo del minimo de cadena. La ejecucion
    // normal tiene rachas cortas; solo una rafaga larga es concluyente.
    let g: Vec<&[u8]> = vec![&[0x58, 0xC3], &[0x5B, 0xC3], &[0x59, 0xC3]];
    let (bytes, dirs) = imagen_con_gadgets(&g);
    let imagen = Imagen {
        base: BASE,
        bytes: &bytes,
    };
    let flujo = reconstruir(&imagen, &dirs);
    assert_eq!(
        analizar_flujo(&flujo).veredicto,
        Veredicto::Benigno,
        "tres gadgets no son una cadena: evita el falso positivo"
    );
}

#[test]
fn el_reporte_de_soporte_es_honesto_en_esta_maquina() {
    use aegis_ptguard::report::SoportePt;
    // Este entorno no tiene intel_pt: el reporte debe decirlo, no fingir soporte.
    let s = SoportePt::detectar();
    // No se afirma un valor concreto (otra maquina si podria tenerlo), pero si
    // que el resultado es coherente: si dice Disponible, la CPU tiene el flag.
    if s.disponible() {
        assert!(aegis_ptguard::report::cpu_tiene_intel_pt());
    }
}
