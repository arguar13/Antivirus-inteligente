//! La imagen PE: encabezados, secciones y directorios de datos.
//!
//! # El recorrido, y donde estan las trampas
//!
//! ```text
//!   0x00  "MZ"                        encabezado DOS
//!   0x3C  e_lfanew ------------------> "PE\0\0"
//!                                      encabezado COFF (20 bytes)
//!                                      encabezado opcional (PE32 o PE32+)
//!                                        ... NumberOfRvaAndSizes
//!                                        directorios de datos
//!                                      tabla de secciones (40 bytes cada una)
//! ```
//!
//! Tres cosas que este formato tiene y que casi todo el mundo se come:
//!
//! **1. El encabezado «opcional» no es opcional.** Se llama asi por herencia de
//! COFF. En un ejecutable siempre esta, y su tamano lo declara el encabezado
//! COFF: la tabla de secciones empieza donde ese tamano diga, no en un
//! desplazamiento fijo. Quien lo fija a mano lee basura en cuanto alguien pone
//! un `SizeOfOptionalHeader` distinto del habitual, que es trivial de hacer.
//!
//! **2. PE32 y PE32+ no se distinguen por la maquina, sino por `Magic`.** Y no
//! solo cambia `ImageBase` de 32 a 64 bits: cambia el DESPLAZAMIENTO de todo lo
//! que viene detras, incluidos `NumberOfRvaAndSizes` y los directorios. Un
//! lector que asuma uno de los dos formatos no falla ruidosamente en el otro:
//! lee campos desplazados y devuelve numeros con sentido aparente.
//!
//! **3. El directorio de seguridad no lleva una RVA.** Los dieciseis directorios
//! de datos llevan `VirtualAddress`, y en el numero 4 —la tabla de
//! certificados— ese campo es un **desplazamiento de fichero**, no una direccion
//! virtual. Es la unica excepcion del formato. Traducirlo como RVA, que es lo
//! que hace el codigo escrito por analogia con los otros quince, manda a leer a
//! cualquier sitio. Aqui se trata como lo que es, y esta escrito para que no se
//! vuelva a perder.

use crate::error::PeError;
use crate::lectura::Lector;

/// `IMAGE_SCN_MEM_EXECUTE`.
pub const SECCION_EJECUTABLE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`.
pub const SECCION_LEIBLE: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
pub const SECCION_ESCRIBIBLE: u32 = 0x8000_0000;

/// Indice del directorio de la tabla de certificados.
pub const DIR_SEGURIDAD: usize = 4;

/// El cargador de Windows no admite mas.
const MAX_SECCIONES: u16 = 96;

/// Ancho de los punteros de la imagen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Formato {
    /// `Magic` 0x10b: punteros de 32 bits.
    Pe32,
    /// `Magic` 0x20b: punteros de 64 bits.
    Pe32Mas,
}

/// Una entrada de la tabla de directorios de datos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Directorio {
    /// Direccion virtual... salvo en el de seguridad, donde es un
    /// desplazamiento de fichero. Ver la nota del modulo.
    pub direccion: u32,
    /// Tamano en bytes.
    pub tamano: u32,
}

impl Directorio {
    /// Si esta a cero, que en este formato significa «no hay».
    pub fn vacio(&self) -> bool {
        self.direccion == 0 || self.tamano == 0
    }
}

/// Una seccion de la imagen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seccion {
    /// Nombre, hasta ocho bytes, sin los ceros de relleno.
    ///
    /// Se guarda tal cual viene, con los bytes no imprimibles sustituidos: un
    /// nombre de seccion es texto que elige el atacante y acaba en informes y
    /// en consolas.
    pub nombre: String,
    /// Tamano que ocupara en memoria.
    pub tamano_virtual: u32,
    /// Direccion virtual relativa a la base de la imagen.
    pub rva: u32,
    /// Tamano en el fichero.
    pub tamano_bruto: u32,
    /// Desplazamiento en el fichero.
    pub offset_bruto: u32,
    /// Permisos y atributos.
    pub caracteristicas: u32,
}

impl Seccion {
    /// Si la seccion sera ejecutable en memoria.
    pub fn ejecutable(&self) -> bool {
        self.caracteristicas & SECCION_EJECUTABLE != 0
    }

    /// Si la seccion sera escribible en memoria.
    pub fn escribible(&self) -> bool {
        self.caracteristicas & SECCION_ESCRIBIBLE != 0
    }

    /// Si contiene una RVA dada.
    pub fn contiene_rva(&self, rva: u32) -> bool {
        // Se usa el mayor de los dos tamanos: una seccion con `tamano_virtual`
        // menor que `tamano_bruto` sigue teniendo mapeado todo lo bruto, y al
        // reves el cargador rellena con ceros. Quedarse con uno solo deja fuera
        // direcciones que en memoria SI pertenecen a la seccion.
        let largo = self.tamano_virtual.max(self.tamano_bruto);
        rva >= self.rva && (rva - self.rva) < largo.max(1)
    }
}

/// Un ejecutable de Windows ya leido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imagen {
    /// PE32 o PE32+.
    pub formato: Formato,
    /// Maquina objetivo (`IMAGE_FILE_MACHINE_*`).
    pub maquina: u16,
    /// Marca de tiempo de compilacion declarada.
    pub compilado: u32,
    /// Atributos del encabezado COFF.
    pub caracteristicas: u16,
    /// RVA del punto de entrada.
    pub punto_de_entrada: u32,
    /// Base preferida de carga.
    pub base: u64,
    /// Tamano de los encabezados, segun el propio fichero.
    pub tamano_encabezados: u32,
    /// Tamano de la imagen en memoria.
    pub tamano_imagen: u32,
    /// Subsistema (`IMAGE_SUBSYSTEM_*`).
    pub subsistema: u16,
    /// Atributos de DLL (ASLR, DEP, CFG...).
    pub caracteristicas_dll: u16,
    /// Los directorios de datos que declara.
    pub directorios: Vec<Directorio>,
    /// Las secciones.
    pub secciones: Vec<Seccion>,
    /// Desplazamiento del campo `CheckSum` dentro del fichero.
    ///
    /// Hace falta para la huella Authenticode, que lo salta. Se guarda al leer
    /// porque recalcularlo despues obligaria a repetir todo el recorrido de
    /// encabezados, y equivocarse en el produce una huella que no cuadra con la
    /// de Windows sin que nada lo indique.
    pub offset_checksum: u64,
    /// Desplazamiento de la entrada del directorio de seguridad.
    ///
    /// La huella Authenticode tambien lo salta, por la misma razon.
    pub offset_dir_seguridad: u64,
    /// Tamano del fichero del que se leyo.
    pub tamano_fichero: u64,
}

impl Imagen {
    /// Lee una imagen de unos bytes.
    pub fn leer(bytes: &[u8]) -> Result<Imagen, PeError> {
        let l = Lector::nuevo(bytes);

        // --- Encabezado DOS -------------------------------------------------
        let firma = l.tramo(0, 2, "la firma MZ")?;
        if firma != b"MZ" {
            return Err(PeError::NoEsMZ([firma[0], firma[1]]));
        }
        let lfanew = u64::from(l.u32(0x3C, "e_lfanew")?);

        // --- Firma PE -------------------------------------------------------
        let pe = l.tramo(lfanew, 4, "la firma PE")?;
        if pe != b"PE\0\0" {
            return Err(PeError::SinFirmaPe {
                offset: lfanew,
                encontrado: [pe[0], pe[1], pe[2], pe[3]],
            });
        }

        // --- Encabezado COFF ------------------------------------------------
        let coff = lfanew + 4;
        let maquina = l.u16(coff, "Machine")?;
        let n_secciones = l.u16(coff + 2, "NumberOfSections")?;
        if n_secciones > MAX_SECCIONES {
            return Err(PeError::DemasiadasSecciones(n_secciones));
        }
        let compilado = l.u32(coff + 4, "TimeDateStamp")?;
        let tam_opcional = l.u16(coff + 16, "SizeOfOptionalHeader")?;
        let caracteristicas = l.u16(coff + 18, "Characteristics")?;

        // --- Encabezado opcional --------------------------------------------
        let opt = coff + 20;
        let magic = l.u16(opt, "Magic del encabezado opcional")?;
        let formato = match magic {
            0x10b => Formato::Pe32,
            0x20b => Formato::Pe32Mas,
            otra => return Err(PeError::MagicDesconocida(otra)),
        };
        // El minimo para poder leer hasta `NumberOfRvaAndSizes`.
        let minimo = if formato == Formato::Pe32 { 96 } else { 112 };
        if u64::from(tam_opcional) < minimo {
            return Err(PeError::EncabezadoOpcionalCorto(tam_opcional));
        }

        let punto_de_entrada = l.u32(opt + 16, "AddressOfEntryPoint")?;
        let base = match formato {
            Formato::Pe32 => u64::from(l.u32(opt + 28, "ImageBase")?),
            Formato::Pe32Mas => l.u64(opt + 24, "ImageBase")?,
        };
        let tamano_imagen = l.u32(opt + 56, "SizeOfImage")?;
        let tamano_encabezados = l.u32(opt + 60, "SizeOfHeaders")?;
        let offset_checksum = opt + 64;
        let subsistema = l.u16(opt + 68, "Subsystem")?;
        let caracteristicas_dll = l.u16(opt + 70, "DllCharacteristics")?;

        // Aqui es donde los dos formatos divergen de verdad: todo lo que viene
        // detras de los tamanos de pila y monton esta desplazado 16 bytes.
        let (off_n_dirs, off_dirs) = match formato {
            Formato::Pe32 => (opt + 92, opt + 96),
            Formato::Pe32Mas => (opt + 108, opt + 112),
        };
        let n_dirs = l.u32(off_n_dirs, "NumberOfRvaAndSizes")?;
        // Dieciseis es el maximo que define el formato. Un valor mayor no se
        // rechaza —hay ficheros validos que lo declaran— pero no se leen mas:
        // leer los que diga seria dejar que el fichero eligiera cuanto se lee.
        let n_dirs = n_dirs.min(16) as u64;
        let mut directorios = Vec::with_capacity(n_dirs as usize);
        for i in 0..n_dirs {
            let d = off_dirs + i * 8;
            directorios.push(Directorio {
                direccion: l.u32(d, "VirtualAddress de un directorio")?,
                tamano: l.u32(d + 4, "Size de un directorio")?,
            });
        }
        let offset_dir_seguridad = off_dirs + (DIR_SEGURIDAD as u64) * 8;

        // --- Tabla de secciones ---------------------------------------------
        // Empieza donde diga `SizeOfOptionalHeader`, NO en un desplazamiento
        // fijo. Ver la nota del modulo.
        let tabla = opt + u64::from(tam_opcional);
        let mut secciones = Vec::with_capacity(n_secciones as usize);
        for i in 0..u64::from(n_secciones) {
            let s = tabla + i * 40;
            let nombre_bruto = l.tramo(s, 8, "el nombre de una seccion")?;
            secciones.push(Seccion {
                nombre: nombre_de_seccion(nombre_bruto),
                tamano_virtual: l.u32(s + 8, "VirtualSize")?,
                rva: l.u32(s + 12, "VirtualAddress")?,
                tamano_bruto: l.u32(s + 16, "SizeOfRawData")?,
                offset_bruto: l.u32(s + 20, "PointerToRawData")?,
                caracteristicas: l.u32(s + 36, "Characteristics")?,
            });
        }

        Ok(Imagen {
            formato,
            maquina,
            compilado,
            caracteristicas,
            punto_de_entrada,
            base,
            tamano_encabezados,
            tamano_imagen,
            subsistema,
            caracteristicas_dll,
            directorios,
            secciones,
            offset_checksum,
            offset_dir_seguridad,
            tamano_fichero: l.tamano(),
        })
    }

    /// El directorio de la tabla de certificados, si lo declara.
    pub fn directorio_de_seguridad(&self) -> Option<Directorio> {
        self.directorios
            .get(DIR_SEGURIDAD)
            .copied()
            .filter(|d| !d.vacio())
    }

    /// La seccion que contiene una RVA, si alguna.
    pub fn seccion_de_rva(&self, rva: u32) -> Option<&Seccion> {
        self.secciones.iter().find(|s| s.contiene_rva(rva))
    }

    /// Bytes del fichero que quedan por detras de todas las secciones.
    ///
    /// Es el «overlay»: instaladores, datos de configuracion y, en un ejecutable
    /// firmado, la propia tabla de certificados. Su tamano por si solo no dice
    /// nada; lo que dice algo es que haya overlay **mas alla** de la tabla de
    /// certificados, y de eso se ocupa [`crate::firma`].
    pub fn fin_de_secciones(&self) -> u64 {
        self.secciones
            .iter()
            .filter(|s| s.tamano_bruto > 0)
            .map(|s| u64::from(s.offset_bruto) + u64::from(s.tamano_bruto))
            .max()
            .unwrap_or(u64::from(self.tamano_encabezados))
    }
}

/// Convierte los ocho bytes del nombre de una seccion en texto presentable.
///
/// El nombre lo elige quien construye el fichero y acaba en informes, en
/// consolas y en registros. Un nombre con bytes de control puede mover el cursor
/// de un terminal, borrar lineas ya escritas o cortar un campo de un CSV. Se
/// sustituye todo lo que no sea imprimible ASCII.
fn nombre_de_seccion(bruto: &[u8]) -> String {
    bruto
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_fichero_que_no_empieza_por_mz_se_rechaza_diciendo_lo_que_traia() {
        let e = Imagen::leer(b"\x7fELF...").unwrap_err();
        assert!(matches!(e, PeError::NoEsMZ([0x7f, b'E'])), "{e}");
    }

    #[test]
    fn un_fichero_vacio_no_entra_en_panico() {
        assert!(Imagen::leer(&[]).is_err());
    }

    #[test]
    fn un_mz_sin_nada_detras_da_error_de_fichero_corto() {
        let e = Imagen::leer(b"MZ").unwrap_err();
        assert!(matches!(e, PeError::SeAcabaElFichero { .. }), "{e}");
    }

    #[test]
    fn el_nombre_de_seccion_no_deja_pasar_bytes_de_control() {
        // Un nombre con un retorno de carro y un escape mueve el cursor del
        // terminal de quien lea el informe y puede borrar lo ya escrito.
        assert_eq!(nombre_de_seccion(b".text\0\0\0"), ".text");
        // Lo que hace dano es el ESC; sin el, «[2K» es texto literal inofensivo.
        // Sustituir tambien los imprimibles seria destruir informacion util del
        // nombre sin ganar nada.
        assert_eq!(nombre_de_seccion(b"\x1b[2K\0\0\0\0"), ".[2K");
        assert_eq!(nombre_de_seccion(b"a\rb\0\0\0\0\0"), "a.b");
        assert_eq!(nombre_de_seccion(b"12345678"), "12345678", "sin ceros");
    }

    #[test]
    fn una_seccion_contiene_la_rva_por_el_mayor_de_sus_dos_tamanos() {
        // El caso que se cuela quedandose con `tamano_virtual`: una seccion con
        // virtual 0 —legal, y lo que ponen algunos empaquetadores— dejaria de
        // contener nada, y el punto de entrada pareceria estar fuera de toda
        // seccion.
        let s = Seccion {
            nombre: ".text".into(),
            tamano_virtual: 0,
            rva: 0x1000,
            tamano_bruto: 0x200,
            offset_bruto: 0x400,
            caracteristicas: SECCION_EJECUTABLE | SECCION_LEIBLE,
        };
        assert!(s.contiene_rva(0x1000));
        assert!(s.contiene_rva(0x11ff));
        assert!(!s.contiene_rva(0x1200));
        assert!(!s.contiene_rva(0xfff));
    }

    #[test]
    fn los_permisos_de_una_seccion_se_leen_de_sus_caracteristicas() {
        let s = Seccion {
            nombre: ".data".into(),
            tamano_virtual: 1,
            rva: 0x2000,
            tamano_bruto: 1,
            offset_bruto: 0x600,
            caracteristicas: SECCION_ESCRIBIBLE | SECCION_EJECUTABLE,
        };
        assert!(s.escribible() && s.ejecutable());
    }

    #[test]
    fn un_directorio_a_cero_es_ausencia_y_no_una_direccion() {
        assert!(Directorio::default().vacio());
        assert!(Directorio {
            direccion: 0x400,
            tamano: 0
        }
        .vacio());
        assert!(!Directorio {
            direccion: 0x400,
            tamano: 8
        }
        .vacio());
    }
}
