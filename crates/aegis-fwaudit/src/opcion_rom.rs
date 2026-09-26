//! Option ROMs: el firmware de las tarjetas, que el firmware de la placa ejecuta.
//!
//! # Por que son superficie de implante
//!
//! Una tarjeta PCI (red, grafica, almacenamiento) lleva su propia ROM de
//! expansion, y el firmware de la placa **la ejecuta durante el arranque**, antes
//! que el sistema operativo y con todo el privilegio. Un implante en la ROM de
//! una tarjeta de red sobrevive a reflashear la BIOS de la placa, porque no esta
//! en ella: esta en la tarjeta. Es un vector publicado desde hace mas de una
//! decada y casi ninguna herramienta lo audita.
//!
//! # De donde se sacan las imagenes, y de donde NO
//!
//! Linux expone `/sys/bus/pci/devices/<bdf>/rom`, pero ese fichero **no se puede
//! leer tal cual**: primero hay que escribir `1` en el para que el kernel habilite
//! la decodificacion de la ROM en el dispositivo, y despues `0` para
//! deshabilitarla. Son dos escrituras en la configuracion de un dispositivo que
//! esta funcionando. No se hacen. Las imagenes se sacan de sitios donde no hace
//! falta escribir nada:
//!
//! - de la **imagen de la ROM SPI** (las tarjetas integradas en placa llevan su
//!   option ROM dentro del firmware de la placa),
//! - de un **volcado** que trae el analista,
//! - y, para las que el firmware ejecuto, de su **medida en el PCR 2** del event
//!   log, que es el hash Authenticode de lo que se ejecuto de verdad (ver
//!   [`crate::arranque`]).
//!
//! # El formato
//!
//! Cada imagen empieza por `55 AA`; en `0x18` hay un puntero a la estructura
//! `PCIR`, que da fabricante, dispositivo, longitud (en bloques de 512 bytes),
//! tipo de codigo (x86 heredado, EFI...) y si es la ultima imagen de la cadena.

use std::path::Path;

use aegis_firmware::report::CheckState;
use sha2::{Digest, Sha256};

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::linea_base::LineaBase;

/// Maximo de imagenes que se extraen de una region.
pub const MAX_IMAGENES: usize = 256;

/// Tipo de codigo de una imagen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoCodigo {
    /// x86 heredado (PC-AT).
    X86,
    /// Open Firmware.
    OpenFirmware,
    /// EFI.
    Efi,
    /// Otro.
    Otro(u8),
}

/// Una imagen de expansion PCI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagenRom {
    /// Desplazamiento dentro de lo analizado.
    pub desplazamiento: usize,
    /// Fabricante PCI.
    pub fabricante: u16,
    /// Dispositivo PCI.
    pub dispositivo: u16,
    /// Tipo de codigo.
    pub tipo: TipoCodigo,
    /// Longitud en bytes.
    pub largo: usize,
    /// Si es la ultima de su cadena.
    pub ultima: bool,
    /// Para EFI: tipo de maquina (0x8664 x64, 0xAA64 ARM64...).
    pub maquina_efi: Option<u16>,
    /// SHA-256 de la imagen.
    pub sha256: [u8; 32],
}

impl ImagenRom {
    /// `8086:15f3`.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{:04x}:{:04x}", self.fabricante, self.dispositivo)
    }

    /// El hash en hexadecimal.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Analiza la imagen que empieza en `off`, si la hay.
#[must_use]
pub fn analizar_en(b: &[u8], off: usize) -> Option<ImagenRom> {
    let img = b.get(off..)?;
    if img.get(0..2)? != [0x55, 0xAA] {
        return None;
    }
    let pcir = u16::from_le_bytes(img.get(0x18..0x1A)?.try_into().ok()?) as usize;
    let p = img.get(pcir..pcir.checked_add(0x18)?)?;
    if &p[0..4] != b"PCIR" {
        return None;
    }
    let bloques = u16::from_le_bytes([p[0x10], p[0x11]]) as usize;
    let largo = bloques * 512;
    if largo == 0 || largo > img.len() || pcir >= largo {
        return None;
    }
    let tipo = match p[0x14] {
        0 => TipoCodigo::X86,
        1 => TipoCodigo::OpenFirmware,
        3 => TipoCodigo::Efi,
        o => TipoCodigo::Otro(o),
    };
    let maquina_efi = (tipo == TipoCodigo::Efi
        && img
            .get(4..8)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            == Some(0x0EF1))
    .then(|| u16::from_le_bytes([img[0x0A], img[0x0B]]));
    Some(ImagenRom {
        desplazamiento: off,
        fabricante: u16::from_le_bytes([p[4], p[5]]),
        dispositivo: u16::from_le_bytes([p[6], p[7]]),
        tipo,
        largo,
        ultima: p[0x15] & 0x80 != 0,
        maquina_efi,
        sha256: Sha256::digest(&img[..largo]).into(),
    })
}

/// Extrae todas las imagenes de una region (una imagen de ROM SPI o un volcado).
///
/// Se busca en saltos de 512 bytes, que es la alineacion que exige el formato:
/// buscar `55 AA` byte a byte encuentra coincidencias en cualquier dato. Y se
/// exige la estructura PCIR completa y coherente, igual que para un PE se exige
/// algo mas que `MZ`.
#[must_use]
pub fn extraer(b: &[u8]) -> Vec<ImagenRom> {
    let mut v = Vec::new();
    let mut off = 0usize;
    while off + 0x1A <= b.len() && v.len() < MAX_IMAGENES {
        match analizar_en(b, off) {
            Some(i) => {
                off += i.largo;
                v.push(i);
            }
            None => off += 512,
        }
    }
    v
}

/// Cuantos dispositivos PCI anuncian una ROM en sysfs (que aqui no se lee).
#[must_use]
pub fn anunciadas_en_sysfs(raiz_sys: &Path) -> usize {
    std::fs::read_dir(raiz_sys.join(crate::pci::DIR_DISPOSITIVOS))
        .map(|e| {
            e.flatten()
                .filter(|d| d.path().join("rom").exists())
                .count()
        })
        .unwrap_or(0)
}

/// La comprobacion de option ROMs.
///
/// `imagenes` es `None` cuando no habia de donde sacarlas; `motivo` explica por
/// que, y va al informe tal cual.
#[must_use]
pub fn evaluar(imagenes: Option<&[ImagenRom]>, motivo: &str, base: &LineaBase) -> Comprobacion {
    let estado = match imagenes {
        None => CheckState::NoAplicable(motivo.to_string()),
        Some([]) => CheckState::Ok,
        Some(imgs) => {
            let mut malas = Vec::new();
            let mut desconocidas = 0usize;
            for i in imgs {
                if let Some(n) = base.revocados.get(&i.sha256) {
                    malas.push(format!(
                        "{} @{:#x} coincide con el implante conocido '{n}'",
                        i.id(),
                        i.desplazamiento
                    ));
                } else if let Some(e) = base.opciones_rom.get(&i.id()) {
                    if !e.iter().any(|x| x.sha256 == i.sha256) {
                        malas.push(format!(
                            "{} @{:#x} no es ninguna de las {} version(es) conocidas: la ROM de la tarjeta fue reescrita",
                            i.id(),
                            i.desplazamiento,
                            e.len()
                        ));
                    }
                } else {
                    desconocidas += 1;
                }
            }
            if !malas.is_empty() {
                CheckState::Fallo(malas.join("; "))
            } else if base.opciones_rom.is_empty() {
                CheckState::Indeterminado(format!(
                    "{} imagen(es) inventariadas sin linea base con que compararlas",
                    imgs.len()
                ))
            } else if desconocidas > 0 {
                CheckState::Indeterminado(format!(
                    "{desconocidas} de {} imagen(es) de dispositivos que la linea base no cubre",
                    imgs.len()
                ))
            } else {
                CheckState::Ok
            }
        }
    };
    Comprobacion::nueva(
        "option-rom-integridad",
        Superficie::OptionRom,
        Naturaleza::Compromiso,
        estado,
    )
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Construye una imagen de expansion REAL segun la especificacion PCI.
    pub(crate) fn imagen(
        fabricante: u16,
        dispositivo: u16,
        tipo: u8,
        bloques: u16,
        ultima: bool,
        relleno: u8,
    ) -> Vec<u8> {
        let mut v = vec![relleno; bloques as usize * 512];
        v[0] = 0x55;
        v[1] = 0xAA;
        v[2] = bloques as u8;
        if tipo == 3 {
            v[4..8].copy_from_slice(&0x0EF1u32.to_le_bytes());
            v[0x0A..0x0C].copy_from_slice(&0x8664u16.to_le_bytes());
        }
        v[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
        let p = 0x40;
        v[p..p + 4].copy_from_slice(b"PCIR");
        v[p + 4..p + 6].copy_from_slice(&fabricante.to_le_bytes());
        v[p + 6..p + 8].copy_from_slice(&dispositivo.to_le_bytes());
        v[p + 0x0A..p + 0x0C].copy_from_slice(&0x18u16.to_le_bytes());
        v[p + 0x10..p + 0x12].copy_from_slice(&bloques.to_le_bytes());
        v[p + 0x14] = tipo;
        v[p + 0x15] = if ultima { 0x80 } else { 0 };
        v
    }

    #[test]
    fn una_cadena_de_dos_imagenes_se_extrae_entera() {
        let mut b = vec![0u8; 1024];
        b.extend(imagen(0x8086, 0x15F3, 0, 4, false, 0x11));
        b.extend(imagen(0x8086, 0x15F3, 3, 8, true, 0x22));
        b.extend(vec![0xFFu8; 2048]);
        let v = extraer(&b);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].desplazamiento, 1024);
        assert_eq!(v[0].tipo, TipoCodigo::X86);
        assert_eq!(v[1].tipo, TipoCodigo::Efi);
        assert_eq!(v[1].maquina_efi, Some(0x8664));
        assert!(v[1].ultima);
        assert_eq!(v[0].id(), "8086:15f3");
    }

    #[test]
    fn un_55aa_suelto_no_es_una_rom() {
        let mut b = vec![0u8; 4096];
        b[512] = 0x55;
        b[513] = 0xAA;
        assert!(extraer(&b).is_empty());
        // PCIR apuntando fuera, y longitud cero.
        let mut i = imagen(1, 2, 0, 1, true, 0);
        i[0x18..0x1A].copy_from_slice(&0xFFF0u16.to_le_bytes());
        assert!(analizar_en(&i, 0).is_none());
        let mut j = imagen(1, 2, 0, 1, true, 0);
        j[0x50..0x52].copy_from_slice(&0u16.to_le_bytes());
        assert!(analizar_en(&j, 0).is_none());
        assert!(extraer(&[]).is_empty());
    }

    #[test]
    fn una_rom_reescrita_frente_a_su_linea_base_es_compromiso() {
        let buena = extraer(&imagen(0x8086, 0x15F3, 3, 4, true, 0x33));
        let base = LineaBase::analizar(&format!(
            "version 1\noprom 8086:15f3 {} NIC\n",
            buena[0].sha256_hex()
        ))
        .expect("base");
        assert_eq!(evaluar(Some(&buena), "", &base).estado, CheckState::Ok);
        let mala = extraer(&imagen(0x8086, 0x15F3, 3, 4, true, 0x34));
        let c = evaluar(Some(&mala), "", &base);
        assert_eq!(c.naturaleza, Naturaleza::Compromiso);
        assert!(format!("{:?}", c.estado).contains("reescrita"));
        assert!(matches!(
            evaluar(Some(&mala), "", &LineaBase::default()).estado,
            CheckState::Indeterminado(_)
        ));
        let n = evaluar(None, "el fichero rom de sysfs exige escribir", &base);
        assert!(matches!(n.estado, CheckState::NoAplicable(ref m) if m.contains("escribir")));
    }
}
