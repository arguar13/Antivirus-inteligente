//! La ROM SPI: como se descubre y como se delimitan sus regiones.
//!
//! # Que hay en una ROM SPI
//!
//! No es un solo binario. En una placa Intel moderna, la memoria flash lleva un
//! **Descriptor de Flash** al principio que reparte el resto en regiones:
//!
//! | Indice | Region | Que es |
//! |---|---|---|
//! | 0 | Descriptor | el propio mapa |
//! | 1 | BIOS | el firmware UEFI: los volumenes que audita [`crate::uefi`] |
//! | 2 | ME | el firmware del Management Engine (Ring -3) |
//! | 3 | GbE | el firmware de la tarjeta de red |
//!
//! Auditar «la ROM» sin leer el descriptor significa no saber donde empieza el
//! BIOS, y buscar la firma de un volumen UEFI por fuerza bruta sobre los 32 MiB
//! enteros encuentra coincidencias **dentro** de la region ME y dentro de datos
//! comprimidos. El descriptor es lo que convierte un barrido de firmas en una
//! delimitacion.
//!
//! # Esta maquina no tiene ROM SPI accesible, y eso se dice
//!
//! Comprobado: no existen `/dev/mtd*`, `/sys/class/mtd` ni `/proc/mtd`. Es lo
//! NORMAL —exponer la flash al espacio de usuario exige un controlador concreto
//! (`intel-spi`, `spi-nor`) y casi ninguna distribucion lo activa—, y por eso el
//! informe lo marca como **no aplicable** y no como fallo. Confundir «no se puede
//! mirar» con «esta bien» o con «esta mal» son los dos errores que el tri-estado
//! de [`aegis_firmware::report::CheckState`] existe para impedir.
//!
//! El **decisor** —decodificar el descriptor y delimitar las regiones— si se
//! prueba entero, con descriptores construidos byte a byte segun la
//! especificacion de Intel.

use std::path::{Path, PathBuf};

use crate::solo_lectura::{ErrorLectura, LecturaSolo};

/// Firma del Descriptor de Flash de Intel.
pub const FIRMA_DESCRIPTOR: u32 = 0x0FF0_A55A;

/// Desplazamiento canonico de la firma en una imagen COMPLETA de la ROM.
pub const OFF_FIRMA_CANONICO: u64 = 0x10;

/// Desplazamiento de la firma en los volcados que empiezan en el propio mapa.
pub const OFF_FIRMA_LEGADO: u64 = 0x00;

/// Tamano del descriptor.
pub const TAM_DESCRIPTOR: u64 = 4096;

/// Maximo de regiones que define el formato.
pub const MAX_REGIONES: usize = 16;

/// Nombres de region por indice, segun la especificacion de Intel.
const NOMBRES_REGION: [&str; MAX_REGIONES] = [
    "Descriptor",
    "BIOS",
    "ME",
    "GbE",
    "PDR",
    "DevExp1",
    "BIOS2",
    "reservada7",
    "EC/BMC",
    "DevExp2",
    "IE",
    "10GbE1",
    "10GbE2",
    "reservada13",
    "reservada14",
    "PTT",
];

/// Error al decodificar el descriptor.
#[derive(Debug, thiserror::Error)]
pub enum ErrorSpi {
    /// No se encontro la firma del descriptor en ninguno de los dos sitios.
    #[error("no se encontro la firma del descriptor de flash (0x0FF0A55A)")]
    SinFirma,
    /// La imagen es mas corta que un descriptor.
    #[error("la imagen mide {tenia} B; un descriptor son {TAM_DESCRIPTOR} B")]
    Corta {
        /// Bytes que tenia.
        tenia: u64,
    },
    /// Un campo apunta fuera de la imagen.
    #[error("el campo {campo} vale {valor}, fuera de la imagen")]
    FueraDeRango {
        /// Campo implicado.
        campo: &'static str,
        /// Valor leido.
        valor: u64,
    },
    /// Fallo de lectura.
    #[error(transparent)]
    Lectura(#[from] ErrorLectura),
}

/// Una region delimitada por el descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// Indice dentro del descriptor.
    pub indice: u8,
    /// Nombre legible.
    pub nombre: &'static str,
    /// Primer byte.
    pub base: u32,
    /// Ultimo byte, inclusive.
    pub limite: u32,
}

impl Region {
    /// `true` si la region esta en uso.
    ///
    /// Una region NO usada se codifica con `base > limite` (tipicamente base
    /// `0x7FFF000` y limite 0). Tratarla como usada daria un rango de tamano
    /// negativo o gigantesco, que es como se acaba leyendo fuera de la imagen.
    #[must_use]
    pub const fn usada(&self) -> bool {
        self.base <= self.limite
    }

    /// Tamano en bytes, 0 si no esta usada.
    #[must_use]
    pub const fn tamano(&self) -> u64 {
        if !self.usada() {
            return 0;
        }
        (self.limite as u64 - self.base as u64) + 1
    }
}

/// El descriptor de flash decodificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// Donde estaba la firma.
    pub offset_firma: u64,
    /// Direccion base del mapa de componentes.
    pub fcba: u32,
    /// Direccion base del mapa de regiones.
    pub frba: u32,
    /// Numero de regiones que declara el descriptor.
    pub regiones_declaradas: usize,
    /// Las regiones decodificadas.
    pub regiones: Vec<Region>,
}

impl Descriptor {
    /// La region del BIOS, que es la que contiene los volumenes UEFI.
    #[must_use]
    pub fn bios(&self) -> Option<&Region> {
        self.regiones.iter().find(|r| r.indice == 1 && r.usada())
    }

    /// Una region por indice.
    #[must_use]
    pub fn region(&self, indice: u8) -> Option<&Region> {
        self.regiones.iter().find(|r| r.indice == indice)
    }
}

/// Decodifica el descriptor de flash de una imagen de ROM.
///
/// Busca la firma en los dos desplazamientos conocidos: `0x10` en una imagen
/// completa, y `0x00` en los volcados que empiezan en el propio mapa. Buscarla
/// por fuerza bruta en toda la imagen seria un error: la secuencia aparece dentro
/// de datos comprimidos y dentro de la region ME.
///
/// # Errores
/// [`ErrorSpi`] si no hay firma, la imagen es corta o un campo apunta fuera.
pub fn decodificar_descriptor(imagen: &[u8]) -> Result<Descriptor, ErrorSpi> {
    if (imagen.len() as u64) < TAM_DESCRIPTOR {
        return Err(ErrorSpi::Corta {
            tenia: imagen.len() as u64,
        });
    }
    let leer_u32 = |o: usize| -> Option<u32> {
        imagen
            .get(o..o.checked_add(4)?)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
    };

    let offset_firma = [OFF_FIRMA_CANONICO, OFF_FIRMA_LEGADO]
        .into_iter()
        .find(|o| leer_u32(*o as usize) == Some(FIRMA_DESCRIPTOR))
        .ok_or(ErrorSpi::SinFirma)?;

    // FLMAP0 esta justo despues de la firma.
    let base_mapa = offset_firma as usize + 4;
    let flmap0 = leer_u32(base_mapa).ok_or(ErrorSpi::FueraDeRango {
        campo: "FLMAP0",
        valor: base_mapa as u64,
    })?;

    // FCBA = (FLMAP0 & 0xFF) << 4, NC = (FLMAP0 >> 8) & 0x3,
    // FRBA = ((FLMAP0 >> 16) & 0xFF) << 4.
    let fcba = (flmap0 & 0xFF) << 4;
    let frba = ((flmap0 >> 16) & 0xFF) << 4;
    // El numero de regiones se codifica en FLMAP0[26:24] en los descriptores
    // modernos; los antiguos no lo traen y se asume el maximo. Se acota a
    // MAX_REGIONES para que un valor absurdo no genere un bucle largo.
    let declaradas = (((flmap0 >> 24) & 0x7) as usize + 1).min(MAX_REGIONES);

    if (frba as u64) >= TAM_DESCRIPTOR {
        return Err(ErrorSpi::FueraDeRango {
            campo: "FRBA",
            valor: frba as u64,
        });
    }

    let mut regiones = Vec::with_capacity(declaradas);
    for i in 0..declaradas {
        let off = frba as usize + i * 4;
        let Some(flreg) = leer_u32(off) else {
            break;
        };
        // IFD v2 (Skylake en adelante): 15 bits de base y 15 de limite, en
        // unidades de 4 KiB. El limite es inclusivo y se rellena con 0xFFF.
        let base = (flreg & 0x7FFF) << 12;
        let limite = (((flreg >> 16) & 0x7FFF) << 12) | 0xFFF;
        regiones.push(Region {
            indice: i as u8,
            nombre: NOMBRES_REGION[i.min(MAX_REGIONES - 1)],
            base,
            limite,
        });
    }

    Ok(Descriptor {
        offset_firma,
        fcba,
        frba,
        regiones_declaradas: declaradas,
        regiones,
    })
}

// ---------------------------------------------------------------------------
// Descubrimiento del dispositivo (la frontera con el hardware)
// ---------------------------------------------------------------------------

/// Donde el kernel expone los dispositivos MTD.
pub const DIR_CLASE_MTD: &str = "/sys/class/mtd";

/// Un dispositivo MTD (la flash, cuando el kernel la expone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispositivoMtd {
    /// Indice (`mtd0`, `mtd1`...).
    pub indice: u32,
    /// Nombre que le da el controlador (`BIOS`, `Descriptor`...).
    pub nombre: String,
    /// Tipo (`nor`, `nand`...).
    pub tipo: String,
    /// Tamano en bytes.
    pub tamano: u64,
    /// Ruta del nodo de **solo lectura** (`/dev/mtdNro`).
    ///
    /// Se apunta al nodo `ro` a proposito, que es el que el kernel crea sin
    /// capacidad de escritura. Aunque este crate no pueda escribir por
    /// construccion, usar el nodo de escritura seria pedirle al kernel una
    /// capacidad que no hace falta.
    pub ruta_solo_lectura: PathBuf,
    /// `true` si ese nodo existe.
    pub nodo_presente: bool,
}

impl DispositivoMtd {
    /// `true` si parece la flash del sistema.
    #[must_use]
    pub fn parece_bios(&self) -> bool {
        self.nombre.eq_ignore_ascii_case("BIOS") || self.tipo == "nor"
    }
}

/// Enumera los dispositivos MTD de la maquina.
///
/// Devuelve una lista vacia cuando no hay, que es el caso normal.
#[must_use]
pub fn enumerar_mtd() -> Vec<DispositivoMtd> {
    let mut salida = Vec::new();
    let Ok(entradas) = std::fs::read_dir(DIR_CLASE_MTD) else {
        return salida;
    };
    for e in entradas.flatten() {
        let dir = e.path();
        let nombre_dir = e.file_name().to_string_lossy().to_string();
        // Solo `mtdN`, no `mtdNro` (que es el mismo dispositivo).
        let Some(resto) = nombre_dir.strip_prefix("mtd") else {
            continue;
        };
        let Ok(indice) = resto.parse::<u32>() else {
            continue;
        };
        let leer = |campo: &str| {
            std::fs::read_to_string(dir.join(campo))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let ruta = PathBuf::from(format!("/dev/mtd{indice}ro"));
        salida.push(DispositivoMtd {
            indice,
            nombre: leer("name"),
            tipo: leer("type"),
            tamano: leer("size").parse().unwrap_or(0),
            nodo_presente: ruta.exists(),
            ruta_solo_lectura: ruta,
        });
    }
    salida.sort_by_key(|d| d.indice);
    salida
}

/// Por que no hay ROM SPI accesible, para que el informe lo DIGA en vez de
/// callarse.
#[must_use]
pub fn motivo_sin_rom() -> String {
    if !Path::new(DIR_CLASE_MTD).is_dir() {
        return format!(
            "{DIR_CLASE_MTD} no existe: el kernel no expone la flash como MTD \
             (hace falta un controlador como intel-spi o spi-nor, que casi ninguna \
             distribucion activa)"
        );
    }
    let dispositivos = enumerar_mtd();
    if dispositivos.is_empty() {
        return format!("{DIR_CLASE_MTD} existe pero no hay ningun dispositivo MTD");
    }
    if !dispositivos.iter().any(|d| d.nodo_presente) {
        return "hay dispositivos MTD pero ninguno tiene nodo /dev/mtdNro accesible".to_string();
    }
    "hay ROM SPI accesible".to_string()
}

/// Abre la ROM SPI de solo lectura, si la hay.
///
/// # Errores
/// [`ErrorLectura::NoExiste`] cuando no hay dispositivo, que es el caso normal.
pub fn abrir_rom() -> Result<LecturaSolo, ErrorLectura> {
    let dispositivos = enumerar_mtd();
    let Some(d) = dispositivos
        .iter()
        .find(|d| d.nodo_presente && d.parece_bios())
        .or_else(|| dispositivos.iter().find(|d| d.nodo_presente))
    else {
        return Err(ErrorLectura::NoExiste(PathBuf::from(DIR_CLASE_MTD)));
    };
    // El tamano se toma de sysfs: un dispositivo de caracteres reporta 0 en
    // `metadata().len()`, y sin el las lecturas no se podrian acotar.
    Ok(LecturaSolo::abrir(&d.ruta_solo_lectura)?.con_tamano(d.tamano))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un descriptor de flash REAL byte a byte.
    pub(crate) fn descriptor(offset_firma: u64, regiones: &[(u8, u32, u32)]) -> Vec<u8> {
        let mut img = vec![0xFFu8; TAM_DESCRIPTOR as usize * 2];
        let frba: u32 = 0x40;
        let fcba: u32 = 0x30;
        // FLMAP0: FCBA>>4 en [7:0], FRBA>>4 en [23:16], (n-1) en [26:24].
        let n = regiones.len().max(1);
        let flmap0 = (fcba >> 4) | ((frba >> 4) << 16) | (((n - 1) as u32 & 0x7) << 24);
        let o = offset_firma as usize;
        img[o..o + 4].copy_from_slice(&FIRMA_DESCRIPTOR.to_le_bytes());
        img[o + 4..o + 8].copy_from_slice(&flmap0.to_le_bytes());
        for (indice, base, limite) in regiones {
            // FLREG: base>>12 en [14:0], limite>>12 en [30:16].
            let flreg = (base >> 12) | ((limite >> 12) << 16);
            let off = frba as usize + *indice as usize * 4;
            img[off..off + 4].copy_from_slice(&flreg.to_le_bytes());
        }
        img
    }

    #[test]
    fn el_descriptor_delimita_las_regiones_de_la_flash() {
        let img = descriptor(
            OFF_FIRMA_CANONICO,
            &[
                (0, 0x0000_0000, 0x0000_0FFF), // Descriptor
                (1, 0x0050_0000, 0x00FF_FFFF), // BIOS
                (2, 0x0000_3000, 0x004F_FFFF), // ME
                (3, 0x0000_1000, 0x0000_2FFF), // GbE
            ],
        );
        let d = decodificar_descriptor(&img).expect("descriptor valido");
        assert_eq!(d.offset_firma, OFF_FIRMA_CANONICO);
        assert_eq!(d.regiones_declaradas, 4);

        let bios = d.bios().expect("tiene que haber region BIOS");
        assert_eq!(bios.nombre, "BIOS");
        assert_eq!(bios.base, 0x0050_0000);
        assert_eq!(bios.limite, 0x00FF_FFFF);
        assert_eq!(bios.tamano(), 0x00B0_0000);

        assert_eq!(d.region(2).expect("ME").nombre, "ME");
        assert_eq!(d.region(3).expect("GbE").nombre, "GbE");
    }

    /// Una region NO usada se codifica con base > limite. Tratarla como usada
    /// daria un tamano gigantesco y se acabaria leyendo fuera de la imagen.
    #[test]
    fn una_region_no_usada_no_se_confunde_con_una_de_tamano_absurdo() {
        let img = descriptor(
            OFF_FIRMA_CANONICO,
            &[(0, 0, 0xFFF), (1, 0x1000, 0xFFFFF), (2, 0x7FFF000, 0x0)],
        );
        let d = decodificar_descriptor(&img).expect("valido");
        let me = d.region(2).expect("ME");
        assert!(!me.usada(), "base > limite significa no usada");
        assert_eq!(me.tamano(), 0);
        assert!(d.bios().is_some(), "la BIOS si esta usada");
    }

    #[test]
    fn el_descriptor_se_encuentra_en_los_dos_desplazamientos_conocidos() {
        for off in [OFF_FIRMA_CANONICO, OFF_FIRMA_LEGADO] {
            let img = descriptor(off, &[(0, 0, 0xFFF), (1, 0x1000, 0xFFFFF)]);
            let d = decodificar_descriptor(&img).expect("valido");
            assert_eq!(d.offset_firma, off);
        }
    }

    /// Buscar la firma por fuerza bruta en toda la imagen seria un error: la
    /// secuencia aparece dentro de datos comprimidos y de la region ME. Solo se
    /// mira donde la especificacion dice que esta.
    #[test]
    fn una_firma_en_mitad_de_la_imagen_no_se_toma_por_descriptor() {
        let mut img = vec![0u8; TAM_DESCRIPTOR as usize * 4];
        img[0x2000..0x2004].copy_from_slice(&FIRMA_DESCRIPTOR.to_le_bytes());
        assert!(matches!(
            decodificar_descriptor(&img),
            Err(ErrorSpi::SinFirma)
        ));
    }

    #[test]
    fn una_imagen_corta_o_sin_firma_se_rechaza_sin_panico() {
        assert!(matches!(
            decodificar_descriptor(&[]),
            Err(ErrorSpi::Corta { .. })
        ));
        assert!(matches!(
            decodificar_descriptor(&[0u8; 100]),
            Err(ErrorSpi::Corta { .. })
        ));
        assert!(matches!(
            decodificar_descriptor(&vec![0u8; 8192]),
            Err(ErrorSpi::SinFirma)
        ));
        // Y una firma con un FRBA imposible.
        let mut img = vec![0u8; 8192];
        img[0x10..0x14].copy_from_slice(&FIRMA_DESCRIPTOR.to_le_bytes());
        img[0x14..0x18].copy_from_slice(&0x00FF_0000u32.to_le_bytes()); // FRBA = 0xFF0
        let _ = decodificar_descriptor(&img);
    }

    /// ESTA MAQUINA no expone ROM SPI, y el modulo tiene que DECIRLO con un
    /// motivo util en vez de callarse o fingir un fallo.
    #[test]
    fn el_motivo_de_que_no_haya_rom_es_explicito() {
        let motivo = motivo_sin_rom();
        assert!(!motivo.is_empty());
        eprintln!("ROM SPI en esta maquina: {motivo}");
        let dispositivos = enumerar_mtd();
        if dispositivos.is_empty() {
            assert!(
                motivo.contains("no existe") || motivo.contains("no hay"),
                "el motivo tiene que explicar POR QUE: {motivo}"
            );
            assert!(matches!(abrir_rom(), Err(ErrorLectura::NoExiste(_))));
        } else {
            eprintln!("dispositivos MTD: {dispositivos:?}");
        }
    }
}
