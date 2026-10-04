//! El vector de PRODUCCION: una sola funcion para el agente y para el
//! entrenamiento (FASE 4.4 del MP-16).
//!
//! # La causa raiz que cierra
//!
//! Un modelo se entrena sobre vectores y se ejecuta sobre vectores. Si los dos
//! los calcula codigo distinto —un script de Python que «imita» `features.rs`,
//! o el mismo Rust llamado con otras opciones (`to_vector` frente a
//! `to_vector_with_data`, otro `block_size`)—, el modelo se mide sobre una cosa
//! y decide sobre otra, y la tarjeta de modelo describe un producto que no
//! existe. Ese fallo no da error: da puntuaciones plausibles y equivocadas.
//!
//! Por eso:
//!
//! - [`vectorizar`] es la UNICA via de bytes a vector. La usa el analizador
//!   `Modelo` del trabajador confinado y la usa `aegis-vectorizar`, el binario
//!   que emite los vectores con los que se entrena. No hay otra.
//! - [`huella_extractor`] resume el comportamiento del extractor sobre unas
//!   sondas deterministas. El entrenamiento la graba en la tarjeta; el agente la
//!   recalcula al arrancar y, si no coincide (alguien cambio `features.rs`
//!   despues de entrenar), el modelo vuelve a ser de referencia
//!   ([`crate::puerta`]). No hace falta acordarse de subir una version: lo
//!   detecta el codigo.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::features::{self, FeatureExtractor, FEATURE_DIM};

/// Version del esquema del vector. Entra en la huella: cambiar la disposicion
/// a proposito se declara subiendola, y aun sin subirla la huella cambia.
pub const VERSION_VECTOR: u32 = 1;

/// El vector que ve el modelo para unos bytes.
///
/// Es exactamente lo que el trabajador calcula antes de inferir: extractor por
/// defecto y [`features::to_vector`] (sin los histogramas de bytes, que un
/// relleno al final del fichero mueve sin tocar una instruccion).
#[must_use]
pub fn vectorizar(datos: &[u8]) -> Vec<f32> {
    let rasgos = FeatureExtractor::default().extract(datos);
    features::to_vector(&rasgos)
}

/// Huella del extractor: SHA-256 de los vectores de unas sondas fijas.
///
/// Dos binarios con el mismo extractor dan la misma huella; un cambio en
/// cualquier caracteristica que las sondas ejerciten la cambia.
#[must_use]
pub fn huella_extractor() -> String {
    let mut h = Sha256::new();
    h.update(VERSION_VECTOR.to_le_bytes());
    h.update((FEATURE_DIM as u64).to_le_bytes());
    for sonda in sondas() {
        for x in vectorizar(&sonda) {
            h.update(x.to_bits().to_le_bytes());
        }
    }
    hex(&h.finalize())
}

/// SHA-256 en hexadecimal de unos bytes.
#[must_use]
pub fn sha256_hex(datos: &[u8]) -> String {
    hex(&Sha256::digest(datos))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Sondas deterministas: vacio, ceros, texto, ruido y un ELF minimo valido.
fn sondas() -> Vec<Vec<u8>> {
    let mut ruido = Vec::with_capacity(16_384);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..16_384 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ruido.push((x >> 24) as u8);
    }
    vec![
        Vec::new(),
        vec![0u8; 8192],
        b"#!/bin/sh\necho sonda del extractor de aegis-ml\n".repeat(64),
        ruido,
        elf_minimo(),
    ]
}

/// ELF64 x86-64 ejecutable de 129 bytes: cabecera, un PT_LOAD R+X y
/// `mov eax, 60; xor edi, edi; syscall`. Ejercita el camino ELF del extractor.
fn elf_minimo() -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    let codigo: [u8; 9] = [0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
    let total: u64 = 64 + 56 + codigo.len() as u64;
    let mut e = Vec::with_capacity(129);
    e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    e.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    e.extend_from_slice(&1u32.to_le_bytes()); // e_version
    e.extend_from_slice(&(BASE + 120).to_le_bytes()); // e_entry
    e.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    e.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    e.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    e.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    e.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    e.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    e.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    e.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    e.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    e.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    e.extend_from_slice(&total.to_le_bytes()); // p_filesz
    e.extend_from_slice(&total.to_le_bytes()); // p_memsz
    e.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    e.extend_from_slice(&codigo);
    e
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_vector_tiene_la_dimension_del_modelo() {
        for s in sondas() {
            assert_eq!(vectorizar(&s).len(), FEATURE_DIM);
        }
    }

    #[test]
    fn el_elf_minimo_mide_lo_que_dice() {
        assert_eq!(elf_minimo().len(), 129);
        let v = vectorizar(&elf_minimo());
        assert!(
            v[9] > 0.5,
            "el ELF minimo no se reconoce como ELF: {:?}",
            &v[..16]
        );
    }

    #[test]
    fn la_huella_es_determinista_y_sensible() {
        let a = huella_extractor();
        assert_eq!(a, huella_extractor());
        assert_eq!(a.len(), 64);
        // Lo que la huella resume: otro vector daria otra huella.
        let mut h = Sha256::new();
        h.update((VERSION_VECTOR + 1).to_le_bytes());
        assert_ne!(a, hex(&h.finalize()));
    }

    #[test]
    fn es_el_mismo_vector_que_el_camino_explicito() {
        let d = elf_minimo();
        let explicito = features::to_vector(&FeatureExtractor::default().extract(&d));
        assert_eq!(vectorizar(&d), explicito);
    }
}
