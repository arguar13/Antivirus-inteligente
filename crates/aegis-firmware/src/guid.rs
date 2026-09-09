//! GUID de EFI, con su codificacion de cable mixed-endian.
//!
//! Un `EFI_GUID` NO es 16 bytes en el mismo orden: `Data1` (u32), `Data2` (u16)
//! y `Data3` (u16) van en little-endian en el cable, mientras que `Data4[8]` va
//! en crudo (big-endian). Comparar los 16 bytes crudos es seguro y es lo que se
//! hace para identificar tipos; pero rendir la forma canonica `8-4-4-4-12`
//! obliga a intercambiar los bytes de los tres primeros campos. Volcar los 16
//! bytes tal cual da `2616c4c1-4c50-...` donde deberia decir `c1c41626-504c-...`
//! y entonces NINGUN GUID casa: es el error clasico, y por eso el formateo vive
//! aqui, en un solo sitio con pruebas.

/// Un GUID de EFI, guardado en su forma de cable (los 16 bytes tal cual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Construye un GUID desde sus campos logicos (como se escriben en la spec).
    pub const fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
        let a = d1.to_le_bytes();
        let b = d2.to_le_bytes();
        let c = d3.to_le_bytes();
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    /// Construye un GUID desde 16 bytes de cable. Bytes de menos se rellenan
    /// con cero, que es un GUID valido (el nulo) y evita un panico ante una
    /// entrada corta.
    pub fn from_bytes(b: &[u8]) -> Guid {
        let mut g = [0u8; 16];
        let n = b.len().min(16);
        g[..n].copy_from_slice(&b[..n]);
        Guid(g)
    }

    /// Forma canonica `8-4-4-4-12` en minusculas, con los tres primeros campos
    /// intercambiados a su orden logico.
    pub fn hyphenated(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0], // Data1, invertido
            b[5], b[4], // Data2, invertido
            b[7], b[6], // Data3, invertido
            b[8], b[9], // Data4[0..2], crudo
            b[10], b[11], b[12], b[13], b[14], b[15] // Data4[2..8], crudo
        )
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hyphenated())
    }
}
