//! **WPBT**: la tabla ACPI con la que el firmware le ordena al sistema operativo
//! ejecutar un binario en cada arranque.
//!
//! # Que es y por que importa tanto
//!
//! *Windows Platform Binary Table*. Su proposito declarado es legitimo: permitir
//! que un fabricante reinstale software (tipicamente antirrobo) aunque el usuario
//! formatee el disco. El mecanismo, en cambio, es exactamente el que querria un
//! implante: **el firmware entrega un ejecutable y el SO lo ejecuta en cada
//! arranque, con privilegios, sin que este en el disco**.
//!
//! Formatear no lo quita. Reinstalar el sistema no lo quita. Cambiar el disco no
//! lo quita. Vive en la placa base, y es el mecanismo por el que se han
//! distribuido implantes reales de nivel OEM.
//!
//! # Por que su mera presencia NO es un compromiso
//!
//! Y aqui esta el matiz que separa una deteccion util de una que nadie mira:
//! **muchos fabricantes legitimos envian WPBT**. Marcar «hay WPBT → critico»
//! produciria una alerta critica en una fraccion enorme de los portatiles
//! corporativos del mundo, y a la semana el analista dejaria de mirar la
//! categoria entera.
//!
//! Lo que se hace es reportar su presencia como **hecho**, y elevar a sospecha o a
//! critico solo cuando ademas hay algo que no cuadra:
//!
//! - `layout` o `content_type` fuera de los valores definidos,
//! - `arguments_length` incoherente con la longitud de la tabla,
//! - argumentos que son una linea de comandos de descarga y ejecucion
//!   (`powershell -enc`, una URL, `certutil`...), que es lo que hace un implante
//!   y no lo que hace un instalador de fabricante,
//! - `handoff_size` absurdo.

use crate::acpi::{CabeceraAcpi, TAM_CABECERA};

/// La firma de la tabla.
pub const FIRMA: [u8; 4] = *b"WPBT";

/// Desplazamiento de `handoff_size` (u32).
pub const OFF_HANDOFF_SIZE: usize = 36;
/// Desplazamiento de `handoff_address` (u64, **sin alinear**: la tabla va packed).
pub const OFF_HANDOFF_ADDRESS: usize = 40;
/// Desplazamiento de `layout` (u8).
pub const OFF_LAYOUT: usize = 48;
/// Desplazamiento de `content_type` (u8).
pub const OFF_CONTENT_TYPE: usize = 49;
/// Desplazamiento de `arguments_length` (u16), en bytes.
pub const OFF_ARGUMENTS_LENGTH: usize = 50;
/// Donde empiezan los argumentos, en UTF-16LE.
pub const OFF_ARGUMENTOS: usize = 52;
/// Tamano minimo de una WPBT valida (cabecera + campos, sin argumentos).
pub const TAM_MINIMO: usize = 52;

/// `layout` = 1: el contenido es una unica imagen PE.
pub const LAYOUT_IMAGEN_UNICA: u8 = 1;
/// `content_type` = 1: aplicacion nativa de espacio de usuario.
pub const TIPO_APLICACION_NATIVA: u8 = 1;

/// Tope razonable del binario que la tabla entrega.
///
/// El binario que un fabricante entrega por WPBT es un lanzador pequeno, de
/// decenas o cientos de kilobytes. 16 MiB deja margen enorme; por encima, o la
/// tabla miente o hay algo que no es un lanzador.
pub const TOPE_HANDOFF: u32 = 16 * 1024 * 1024;

/// Una tabla WPBT analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wpbt {
    /// La cabecera ACPI comun.
    pub cabecera: CabeceraAcpi,
    /// Tamano del binario que el firmware entrega.
    pub handoff_size: u32,
    /// Direccion fisica donde lo deja.
    pub handoff_address: u64,
    /// Disposicion del contenido (1 = imagen PE unica).
    pub layout: u8,
    /// Tipo de contenido (1 = aplicacion nativa).
    pub content_type: u8,
    /// Longitud declarada de los argumentos, en bytes.
    pub arguments_length: u16,
    /// Los argumentos, decodificados de UTF-16LE.
    pub argumentos: String,
    /// `true` si `arguments_length` no cabia en la tabla y se recorto.
    pub argumentos_recortados: bool,
}

/// Error al analizar una WPBT.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ErrorWpbt {
    /// La firma no es `WPBT`.
    #[error("no es una tabla WPBT")]
    NoEsWpbt,
    /// La tabla no llega al tamano minimo.
    #[error("la WPBT mide {tenia} B y el minimo son {TAM_MINIMO} B")]
    Corta {
        /// Bytes que tenia.
        tenia: usize,
    },
}

impl Wpbt {
    /// Analiza una tabla WPBT completa.
    ///
    /// # Errores
    /// [`ErrorWpbt`] si no es una WPBT o no llega al tamano minimo.
    pub fn analizar(bytes: &[u8]) -> Result<Wpbt, ErrorWpbt> {
        if bytes.len() < TAM_CABECERA || bytes[0..4] != FIRMA {
            return Err(ErrorWpbt::NoEsWpbt);
        }
        if bytes.len() < TAM_MINIMO {
            return Err(ErrorWpbt::Corta { tenia: bytes.len() });
        }
        let cabecera =
            CabeceraAcpi::analizar(bytes).map_err(|_| ErrorWpbt::Corta { tenia: bytes.len() })?;

        let u32_en = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("acotado"));
        let u64_en = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().expect("acotado"));
        let u16_en = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().expect("acotado"));

        let arguments_length = u16_en(OFF_ARGUMENTS_LENGTH);
        // Los argumentos son UTF-16, asi que su longitud EN BYTES tiene que ser
        // par; una impar significa que el campo miente. Se recorta hacia abajo en
        // vez de rechazar la tabla entera: lo que interesa es el contenido, y una
        // longitud impar ya se reporta como anomalia por su cuenta.
        let disponibles = bytes.len().saturating_sub(OFF_ARGUMENTOS);
        let pedidos = arguments_length as usize;
        let usables = pedidos.min(disponibles) & !1;
        let argumentos_recortados = pedidos > disponibles;

        let argumentos = utf16le_a_texto(&bytes[OFF_ARGUMENTOS..OFF_ARGUMENTOS + usables]);

        Ok(Wpbt {
            cabecera,
            handoff_size: u32_en(OFF_HANDOFF_SIZE),
            handoff_address: u64_en(OFF_HANDOFF_ADDRESS),
            layout: bytes[OFF_LAYOUT],
            content_type: bytes[OFF_CONTENT_TYPE],
            arguments_length,
            argumentos,
            argumentos_recortados,
        })
    }

    /// `true` si `layout` y `content_type` son los valores definidos.
    #[must_use]
    pub const fn campos_conocidos(&self) -> bool {
        self.layout == LAYOUT_IMAGEN_UNICA && self.content_type == TIPO_APLICACION_NATIVA
    }

    /// `true` si el tamano del binario entregado es plausible.
    #[must_use]
    pub const fn handoff_plausible(&self) -> bool {
        self.handoff_size > 0 && self.handoff_size <= TOPE_HANDOFF
    }

    /// Los indicios de linea de comandos de ataque en los argumentos.
    ///
    /// Devuelve los fragmentos concretos que se reconocieron, para que la
    /// evidencia del informe sea citable y el analista no tenga que fiarse.
    #[must_use]
    pub fn indicios_en_argumentos(&self) -> Vec<&'static str> {
        indicios_de_linea_de_comandos(&self.argumentos)
    }
}

/// Fragmentos que delatan una linea de comandos de descarga y ejecucion.
///
/// La lista es corta y deliberadamente especifica. No busca «cosas sospechosas»:
/// busca lo que hace un implante y **no** hace un instalador de fabricante. Un
/// lanzador OEM legitimo pasa rutas y modificadores propios; no pasa un comando
/// codificado en base64 ni una URL.
const INDICIOS: &[&str] = &[
    "powershell",
    "-enc",
    "-encodedcommand",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "iex",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "cmd.exe /c",
    "http://",
    "https://",
    "\\\\",
    "frombase64string",
];

/// Los indicios presentes en un texto de argumentos.
#[must_use]
pub fn indicios_de_linea_de_comandos(argumentos: &str) -> Vec<&'static str> {
    let bajo = argumentos.to_ascii_lowercase();
    INDICIOS
        .iter()
        .filter(|i| bajo.contains(**i))
        .copied()
        .collect()
}

/// Decodifica UTF-16LE a texto.
///
/// Los bytes vienen del firmware: no tienen por que ser UTF-16 valido. Los pares
/// que no forman un caracter se sustituyen por `?` en vez de descartar la cadena
/// entera — un argumento con basura intercalada sigue siendo evidencia, y a veces
/// la basura es justo la senal.
fn utf16le_a_texto(bytes: &[u8]) -> String {
    let unidades: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&unidades)
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Construye una WPBT REAL byte a byte, segun la especificacion.
    pub(crate) fn wpbt(
        handoff_size: u32,
        handoff_address: u64,
        layout: u8,
        tipo: u8,
        argumentos: &str,
    ) -> Vec<u8> {
        let args: Vec<u8> = argumentos
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut t = vec![0u8; OFF_ARGUMENTOS];
        t[0..4].copy_from_slice(&FIRMA);
        t[8] = 1;
        t[10..16].copy_from_slice(b"OEMCO ");
        t[16..24].copy_from_slice(b"WPBTTBL1");
        t[OFF_HANDOFF_SIZE..OFF_HANDOFF_SIZE + 4].copy_from_slice(&handoff_size.to_le_bytes());
        t[OFF_HANDOFF_ADDRESS..OFF_HANDOFF_ADDRESS + 8]
            .copy_from_slice(&handoff_address.to_le_bytes());
        t[OFF_LAYOUT] = layout;
        t[OFF_CONTENT_TYPE] = tipo;
        let largo_args = args.len() as u16;
        t[OFF_ARGUMENTS_LENGTH..OFF_ARGUMENTS_LENGTH + 2]
            .copy_from_slice(&largo_args.to_le_bytes());
        t.extend_from_slice(&args);
        let total = t.len() as u32;
        t[4..8].copy_from_slice(&total.to_le_bytes());
        let suma = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        t[9] = suma.wrapping_neg();
        t
    }

    #[test]
    fn una_wpbt_de_fabricante_se_analiza_entera() {
        let bytes = wpbt(102_400, 0x7FF0_0000, 1, 1, "/silent /oem");
        let w = Wpbt::analizar(&bytes).expect("WPBT valida");
        assert_eq!(w.handoff_size, 102_400);
        assert_eq!(w.handoff_address, 0x7FF0_0000);
        assert!(w.campos_conocidos());
        assert!(w.handoff_plausible());
        assert_eq!(w.argumentos, "/silent /oem");
        assert!(!w.argumentos_recortados);
        // Y NO tiene indicios: un lanzador OEM legitimo no pasa lineas de
        // descarga y ejecucion. Marcarlo seria el falso positivo que arruina la
        // categoria entera.
        assert!(w.indicios_en_argumentos().is_empty());
    }

    /// EL CASO QUE IMPORTA. Una WPBT que le dice al SO que ejecute PowerShell
    /// con un comando codificado, en cada arranque, desde la placa base.
    #[test]
    fn una_wpbt_con_linea_de_descarga_y_ejecucion_se_delata() {
        let bytes = wpbt(
            4096,
            0x7FF0_0000,
            1,
            1,
            "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
        );
        let w = Wpbt::analizar(&bytes).expect("WPBT valida");
        let indicios = w.indicios_en_argumentos();
        assert!(indicios.contains(&"powershell"), "{indicios:?}");
        assert!(indicios.contains(&"-enc"), "{indicios:?}");
        assert!(indicios.contains(&"-nop"), "{indicios:?}");
        assert!(indicios.len() >= 3);
    }

    #[test]
    fn una_url_en_los_argumentos_es_un_indicio() {
        let bytes = wpbt(4096, 0, 1, 1, "/install https://cdn.malo.example/p.exe");
        let w = Wpbt::analizar(&bytes).expect("valida");
        assert!(w.indicios_en_argumentos().contains(&"https://"));
    }

    #[test]
    fn los_campos_fuera_de_los_valores_definidos_se_detectan() {
        let bytes = wpbt(4096, 0, 7, 9, "x");
        let w = Wpbt::analizar(&bytes).expect("valida");
        assert!(
            !w.campos_conocidos(),
            "layout 7 / tipo 9 no estan definidos"
        );
    }

    #[test]
    fn un_handoff_absurdo_no_es_plausible() {
        assert!(!Wpbt::analizar(&wpbt(0, 0, 1, 1, "x"))
            .unwrap()
            .handoff_plausible());
        assert!(!Wpbt::analizar(&wpbt(u32::MAX, 0, 1, 1, "x"))
            .unwrap()
            .handoff_plausible());
        assert!(Wpbt::analizar(&wpbt(TOPE_HANDOFF, 0, 1, 1, "x"))
            .unwrap()
            .handoff_plausible());
    }

    /// Un `arguments_length` que promete mas bytes de los que hay en la tabla no
    /// puede provocar una lectura fuera de rango. Es un campo que controla el
    /// firmware, es decir, la superficie que estamos auditando.
    #[test]
    fn una_longitud_de_argumentos_mentirosa_no_lee_fuera_de_rango() {
        let mut bytes = wpbt(4096, 0, 1, 1, "corto");
        bytes[OFF_ARGUMENTS_LENGTH..OFF_ARGUMENTS_LENGTH + 2]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        let w = Wpbt::analizar(&bytes).expect("se analiza igual");
        assert!(w.argumentos_recortados, "el recorte tiene que declararse");
        assert!(w.argumentos.starts_with("corto"));
    }

    #[test]
    fn una_longitud_impar_no_parte_un_caracter_utf16() {
        let mut bytes = wpbt(4096, 0, 1, 1, "hola");
        bytes[OFF_ARGUMENTS_LENGTH..OFF_ARGUMENTS_LENGTH + 2].copy_from_slice(&7u16.to_le_bytes());
        let w = Wpbt::analizar(&bytes).expect("se analiza igual");
        assert_eq!(w.argumentos, "hol", "se recorta a un numero par de bytes");
    }

    #[test]
    fn lo_que_no_es_wpbt_se_rechaza() {
        assert_eq!(Wpbt::analizar(&[]), Err(ErrorWpbt::NoEsWpbt));
        assert_eq!(Wpbt::analizar(&[0u8; 100]), Err(ErrorWpbt::NoEsWpbt));
        let mut otra = wpbt(1, 0, 1, 1, "x");
        otra[0..4].copy_from_slice(b"FACP");
        assert_eq!(Wpbt::analizar(&otra), Err(ErrorWpbt::NoEsWpbt));
    }

    #[test]
    fn una_wpbt_truncada_se_rechaza_en_vez_de_leer_campos_inventados() {
        let completa = wpbt(4096, 0, 1, 1, "x");
        for n in TAM_CABECERA..TAM_MINIMO {
            let r = Wpbt::analizar(&completa[..n]);
            assert!(matches!(r, Err(ErrorWpbt::Corta { .. })), "n={n}: {r:?}");
        }
    }

    #[test]
    fn un_utf16_invalido_no_descarta_la_evidencia() {
        // Un sustituto suelto: no forma un caracter valido.
        let bytes: Vec<u8> = vec![0x00, 0xD8, b'A', 0x00];
        let t = utf16le_a_texto(&bytes);
        assert!(t.contains('A') || t.contains('\u{FFFD}'), "{t:?}");
    }

    #[test]
    fn los_indicios_no_marcan_argumentos_de_fabricante() {
        for benigno in [
            "/silent",
            "/S /norestart",
            "-install -quiet",
            "C:\\Program Files\\OEM\\agent.exe",
            "",
        ] {
            assert!(
                indicios_de_linea_de_comandos(benigno).is_empty(),
                "'{benigno}' no puede marcarse"
            );
        }
    }
}
