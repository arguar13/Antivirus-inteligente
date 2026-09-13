//! MD5, **y sólo como etiqueta de huella JA3**. Jamás para seguridad.
//!
//! # Por que hay MD5 en un producto de seguridad de 2026
//!
//! MD5 esta roto para cualquier uso criptografico y en este proyecto no se usa
//! para ninguno: las firmas son Ed25519 + ML-DSA-65 y los hashes de contenido
//! son SHA-256. Aqui aparece por una razon distinta y concreta: **el estandar
//! JA3 define la huella como el MD5 de una cadena**, y todas las bases de datos
//! de huellas JA3 del mundo —las publicas, las de los proveedores de
//! inteligencia y las que el cliente ya tenga— estan indexadas por ese MD5.
//!
//! Calcularlo con otro algoritmo daria una huella que no casa con nada. La
//! alternativa no es «usar algo mejor»: es quedarse sin poder cotejar JA3, que
//! es una de las senales mas utiles que hay para reconocer una familia de
//! malware por su pila TLS.
//!
//! Aqui MD5 es un **identificador de interoperabilidad**, no una afirmacion de
//! integridad. Que una colision sea trivial de fabricar no importa: un atacante
//! que quiera cambiar su huella JA3 no necesita colisionar nada, le basta con
//! cambiar su pila TLS.
//!
//! # Por que implementarlo aqui y no traer un crate
//!
//! Son ochenta lineas de aritmetica sin entrada dinamica —la entrada es una
//! cadena que este mismo modulo construye— y el proyecto trata el arbol de
//! dependencias del agente como superficie de ataque. Traer un crate para esto
//! cuesta mas de lo que ahorra.

/// Constantes de desplazamiento por ronda, tal y como las define el RFC 1321.
const DESPLAZAMIENTOS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Tabla de constantes: parte entera de `abs(sin(i + 1)) * 2^32`.
const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// El MD5 de `entrada`, en hexadecimal minusculo.
///
/// Ver la doctrina del modulo: esto es una **etiqueta de interoperabilidad JA3**,
/// no una afirmacion de integridad.
#[must_use]
pub fn hex(entrada: &[u8]) -> String {
    let d = digerir(entrada);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// El MD5 de `entrada`, en bruto.
#[must_use]
pub fn digerir(entrada: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    // Relleno: un bit a uno, ceros hasta 56 mod 64, y la longitud en bits.
    let mut mensaje = entrada.to_vec();
    let bits = (entrada.len() as u64).wrapping_mul(8);
    mensaje.push(0x80);
    while mensaje.len() % 64 != 56 {
        mensaje.push(0);
    }
    mensaje.extend_from_slice(&bits.to_le_bytes());

    for bloque in mensaje.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, trozo) in bloque.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([trozo[0], trozo[1], trozo[2], trozo[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let suma = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(suma.rotate_left(DESPLAZAMIENTOS[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut salida = [0u8; 16];
    salida[0..4].copy_from_slice(&a0.to_le_bytes());
    salida[4..8].copy_from_slice(&b0.to_le_bytes());
    salida[8..12].copy_from_slice(&c0.to_le_bytes());
    salida[12..16].copy_from_slice(&d0.to_le_bytes());
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// LOS VECTORES DEL RFC 1321. Una implementacion de MD5 que no de
    /// exactamente esto produce huellas JA3 que no casan con NINGUNA base de
    /// datos del mundo, y el fallo seria silencioso: huellas de aspecto normal
    /// que simplemente no coinciden con nada nunca.
    #[test]
    fn los_vectores_conocidos_del_rfc_1321_cuadran() {
        assert_eq!(hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(
            hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// Los limites del relleno son donde una implementacion a mano se rompe: 55
    /// y 56 bytes caen justo a los dos lados del bloque.
    #[test]
    fn los_limites_del_relleno_son_correctos() {
        // 55 bytes: cabe en un bloque con su relleno.
        let a = vec![b'a'; 55];
        // 56 bytes: obliga a un bloque mas.
        let b = vec![b'a'; 56];
        // 64 bytes: bloque exacto.
        let c = vec![b'a'; 64];
        for v in [&a, &b, &c] {
            assert_eq!(hex(v).len(), 32);
        }
        // Y son distintos entre si, que es lo minimo.
        assert_ne!(hex(&a), hex(&b));
        assert_ne!(hex(&b), hex(&c));
    }

    #[test]
    fn una_entrada_larga_no_provoca_panico() {
        let grande = vec![0xABu8; 100_000];
        assert_eq!(hex(&grande).len(), 32);
    }
}
