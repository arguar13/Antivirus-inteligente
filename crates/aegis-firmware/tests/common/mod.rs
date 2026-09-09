//! Utilidades COMPARTIDAS para construir vectores binarios reales.
//!
//! Estas funciones fabrican bytes exactamente como los produce el firmware,
//! segun el estandar TCG y la especificacion UEFI. No son mocks: son los mismos
//! bytes que un TPM y un firmware reales escriben, montados aqui para poder
//! ejercitar los analizadores sin el hardware. Que el analizador acepte estos
//! bytes y reproduzca los PCRs que de ellos se derivan es la prueba de que
//! aceptara los del hardware.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

/// Extiende un PCR en SHA-256, como el TPM: `H(pcr ‖ medida)`.
pub fn extend(pcr: [u8; 32], medida: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pcr);
    h.update(medida);
    h.finalize().into()
}

/// SHA-256 de unos bytes, como digest de evento.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-1 de unos bytes (para el registro heredado y los digests SHA-1).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    // SHA-1 minimo, solo para fabricar vectores de prueba del log heredado.
    // No es una primitiva del producto.
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for bloque in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, p) in bloque.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Constructor de un event log crypto-agil, byte a byte segun TCG.
pub struct LogBuilder {
    buf: Vec<u8>,
    bancos: Vec<(u16, u16)>, // (algorithmId, digestSize)
}

impl LogBuilder {
    /// Empieza un log crypto-agil que declara SHA-1 y SHA-256, con su primer
    /// registro `EV_NO_ACTION` + `Spec ID Event03` como manda el estandar.
    pub fn crypto_agile_sha1_sha256() -> LogBuilder {
        let bancos = vec![(0x0004u16, 20u16), (0x000Bu16, 32u16)];
        let mut b = LogBuilder {
            buf: Vec::new(),
            bancos: bancos.clone(),
        };
        b.registro_spec_id(&bancos);
        b
    }

    /// El primer registro: formato heredado, EV_NO_ACTION, con el
    /// TCG_EfiSpecIdEvent en el campo de datos.
    fn registro_spec_id(&mut self, bancos: &[(u16, u16)]) {
        // PCRIndex = 0, EventType = EV_NO_ACTION (0x03), digest SHA-1 a cero.
        self.buf.extend_from_slice(&0u32.to_le_bytes());
        self.buf.extend_from_slice(&0x0000_0003u32.to_le_bytes());
        self.buf.extend_from_slice(&[0u8; 20]);

        // Datos: TCG_EfiSpecIdEvent.
        let mut ev = Vec::new();
        ev.extend_from_slice(b"Spec ID Event03\0"); // firma (16)
        ev.extend_from_slice(&0u32.to_le_bytes()); // platformClass
        ev.push(0); // specVersionMinor
        ev.push(2); // specVersionMajor
        ev.push(0); // specErrata
        ev.push(2); // uintnSize
        ev.extend_from_slice(&(bancos.len() as u32).to_le_bytes()); // numberOfAlgorithms
        for (alg, size) in bancos {
            ev.extend_from_slice(&alg.to_le_bytes());
            ev.extend_from_slice(&size.to_le_bytes());
        }
        ev.push(0); // vendorInfoSize

        self.buf.extend_from_slice(&(ev.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&ev);
    }

    /// Anade un registro TCG_PCR_EVENT2 que mide `contenido` en `pcr`.
    ///
    /// El digest de cada banco es el hash real de `contenido`, igual que haria
    /// el firmware. Devuelve el par de digests para poder reproducir el PCR.
    pub fn medir(&mut self, pcr: u32, event_type: u32, contenido: &[u8]) -> ([u8; 20], [u8; 32]) {
        let d1 = sha1(contenido);
        let d256 = sha256(contenido);
        self.buf.extend_from_slice(&pcr.to_le_bytes());
        self.buf.extend_from_slice(&event_type.to_le_bytes());
        // TPML_DIGEST_VALUES: count y luego {algId, digest}.
        self.buf
            .extend_from_slice(&(self.bancos.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&0x0004u16.to_le_bytes());
        self.buf.extend_from_slice(&d1);
        self.buf.extend_from_slice(&0x000Bu16.to_le_bytes());
        self.buf.extend_from_slice(&d256);
        // EventSize y datos.
        self.buf
            .extend_from_slice(&(contenido.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(contenido);
        (d1, d256)
    }

    /// Anade un registro con un digest SHA-256 ARBITRARIO (no el de `contenido`),
    /// para fabricar un log que MIENTE: su medida declarada no es la real.
    pub fn medir_con_digest_falso(
        &mut self,
        pcr: u32,
        event_type: u32,
        contenido: &[u8],
        d256_falso: [u8; 32],
    ) {
        let d1 = sha1(contenido);
        self.buf.extend_from_slice(&pcr.to_le_bytes());
        self.buf.extend_from_slice(&event_type.to_le_bytes());
        self.buf
            .extend_from_slice(&(self.bancos.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&0x0004u16.to_le_bytes());
        self.buf.extend_from_slice(&d1);
        self.buf.extend_from_slice(&0x000Bu16.to_le_bytes());
        self.buf.extend_from_slice(&d256_falso);
        self.buf
            .extend_from_slice(&(contenido.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(contenido);
    }

    /// Devuelve el log completo.
    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

/// Construye una variable de efivarfs: 4 bytes de atributos LE y luego datos.
pub fn efivar(attributes: u32, data: &[u8]) -> Vec<u8> {
    let mut v = attributes.to_le_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

/// Bytes de cable de un GUID desde sus campos logicos.
pub fn guid_bytes(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&d1.to_le_bytes());
    v.extend_from_slice(&d2.to_le_bytes());
    v.extend_from_slice(&d3.to_le_bytes());
    v.extend_from_slice(&d4);
    v
}

/// Construye una EFI_SIGNATURE_LIST de hashes SHA-256 (EFI_CERT_SHA256).
pub fn signature_list_sha256(owner: [u8; 16], hashes: &[[u8; 32]]) -> Vec<u8> {
    // EFI_CERT_SHA256_GUID = c1c41626-504c-4092-aca9-41f936934328
    let tipo = guid_bytes(
        0xc1c41626,
        0x504c,
        0x4092,
        [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
    );
    let sig_size = 16u32 + 32; // owner + hash
    let header_size = 0u32;
    let list_size = 28u32 + header_size + sig_size * hashes.len() as u32;

    let mut v = Vec::new();
    v.extend_from_slice(&tipo);
    v.extend_from_slice(&list_size.to_le_bytes());
    v.extend_from_slice(&header_size.to_le_bytes());
    v.extend_from_slice(&sig_size.to_le_bytes());
    for h in hashes {
        v.extend_from_slice(&owner);
        v.extend_from_slice(h);
    }
    v
}

/// Construye una EFI_SIGNATURE_LIST de tipo EFI_CERT_X509_SHA256 (hash de cert
/// de 32 bytes + EFI_TIME de 16 = SignatureSize 64).
pub fn signature_list_x509_sha256(owner: [u8; 16], entradas: &[([u8; 32], [u8; 16])]) -> Vec<u8> {
    // EFI_CERT_X509_SHA256_GUID = 3bd2a492-96c0-4079-b420-fc40b64e2807
    let tipo = guid_bytes(
        0x3bd2a492,
        0x96c0,
        0x4079,
        [0xb4, 0x20, 0xfc, 0x40, 0xb6, 0x4e, 0x28, 0x07],
    );
    let sig_size = 16u32 + 32 + 16; // owner + hash + EFI_TIME
    let list_size = 28u32 + sig_size * entradas.len() as u32;
    let mut v = Vec::new();
    v.extend_from_slice(&tipo);
    v.extend_from_slice(&list_size.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&sig_size.to_le_bytes());
    for (hash, time) in entradas {
        v.extend_from_slice(&owner);
        v.extend_from_slice(hash);
        v.extend_from_slice(time);
    }
    v
}
