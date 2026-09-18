//! Un Mach-O de 64 bits: encabezado, comandos de carga y segmentos.
//!
//! # El recorrido
//!
//! ```text
//!   0x00  magic (0xfeedfacf)   cputype  cpusubtype  filetype
//!         ncmds  sizeofcmds  flags  reserved          = 32 bytes
//!   0x20  comando de carga 1   (cmd, cmdsize, carga)
//!         comando de carga 2
//!         ...                  ncmds veces
//! ```
//!
//! Todo lo que hace falta saber de un binario de macOS esta en esos comandos: el
//! punto de entrada (`LC_MAIN`), los segmentos con sus permisos
//! (`LC_SEGMENT_64`), las bibliotecas que carga (`LC_LOAD_DYLIB`), donde las
//! busca (`LC_RPATH`), si esta cifrado (`LC_ENCRYPTION_INFO_64`) y donde dice
//! tener su firma (`LC_CODE_SIGNATURE`).
//!
//! # `cmdsize` es el campo peligroso
//!
//! Es el que mueve el cursor. Un `cmdsize` de cero deja el bucle sin avanzar: un
//! fichero de treinta y dos bytes bien puestos cuelga al agente. Uno sin alinear
//! a ocho descoloca todos los comandos siguientes. Uno mayor que lo que queda
//! manda a leer fuera. Los tres se comprueban antes de moverse, y por eso este
//! modulo tiene un error propio para ellos.

use aegis_pe::lectura::Lector;

use crate::error::MachoError;

/// `MH_MAGIC_64`.
pub const MAGIC_64: u32 = 0xfeed_facf;
/// `MH_CIGAM_64`: el mismo, con los bytes al reves.
pub const CIGAM_64: u32 = 0xcffa_edfe;
/// `MH_MAGIC` de 32 bits.
pub const MAGIC_32: u32 = 0xfeed_face;
/// `MH_CIGAM` de 32 bits.
pub const CIGAM_32: u32 = 0xcefa_edfe;

/// `LC_SEGMENT_64`.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_LOAD_DYLIB`.
pub const LC_LOAD_DYLIB: u32 = 0x0c;
/// `LC_CODE_SIGNATURE`.
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// `LC_MAIN`.
pub const LC_MAIN: u32 = 0x8000_0028;
/// `LC_RPATH`.
pub const LC_RPATH: u32 = 0x8000_001c;
/// `LC_ENCRYPTION_INFO_64`.
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

/// `VM_PROT_WRITE`.
pub const PROT_ESCRITURA: u32 = 0x2;
/// `VM_PROT_EXECUTE`.
pub const PROT_EJECUCION: u32 = 0x4;

/// Ningun Mach-O real tiene mas comandos que esto.
const MAX_COMANDOS: u32 = 4096;

/// Un segmento de la imagen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segmento {
    /// Nombre (`__TEXT`, `__DATA`...), ya saneado.
    pub nombre: String,
    /// Direccion virtual.
    pub vmaddr: u64,
    /// Tamano en memoria.
    pub vmsize: u64,
    /// Desplazamiento en el fichero.
    pub fileoff: u64,
    /// Tamano en el fichero.
    pub filesize: u64,
    /// Permisos maximos que puede llegar a tener.
    pub maxprot: u32,
    /// Permisos con los que se mapea.
    pub initprot: u32,
}

impl Segmento {
    /// Si se mapea escribible y ejecutable a la vez.
    ///
    /// Se mira `initprot` y no `maxprot`: `maxprot` dice lo que el segmento
    /// PODRIA llegar a ser tras un `mprotect`, y en muchos binarios legitimos
    /// vale `rwx` sin que nada se mapee asi. Confundirlos convierte el indicio
    /// en ruido constante.
    pub fn escribible_y_ejecutable(&self) -> bool {
        self.initprot & PROT_ESCRITURA != 0 && self.initprot & PROT_EJECUCION != 0
    }
}

/// Un comando de carga, ya interpretado en lo que interesa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comando {
    /// Un segmento.
    Segmento(Segmento),
    /// Una biblioteca que el binario carga al arrancar.
    Dylib {
        /// Ruta tal y como la declara.
        ruta: String,
    },
    /// Una ruta de busqueda para `@rpath`.
    Rpath {
        /// Ruta tal y como la declara.
        ruta: String,
    },
    /// Donde dice tener la firma de codigo.
    FirmaDeCodigo {
        /// Desplazamiento en el fichero.
        offset: u32,
        /// Tamano.
        tamano: u32,
    },
    /// El punto de entrada.
    Main {
        /// Desplazamiento del punto de entrada.
        entryoff: u64,
    },
    /// El binario viene cifrado.
    Cifrado {
        /// Identificador del cifrado; distinto de cero significa cifrado.
        cryptid: u32,
    },
    /// Cualquier otro, que se conserva por su numero.
    Otro {
        /// Codigo del comando.
        cmd: u32,
    },
}

/// Un Mach-O de 64 bits ya leido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macho {
    /// Arquitectura (`CPU_TYPE_*`).
    pub cputype: i32,
    /// Subtipo de arquitectura.
    pub cpusubtype: i32,
    /// Tipo de fichero (`MH_EXECUTE`, `MH_DYLIB`...).
    pub filetype: u32,
    /// Atributos.
    pub flags: u32,
    /// Los comandos de carga.
    pub comandos: Vec<Comando>,
}

impl Macho {
    /// Lee un Mach-O de 64 bits.
    pub fn leer(bytes: &[u8]) -> Result<Macho, MachoError> {
        let l = Lector::nuevo(bytes);
        let magic = leer_u32(&l, 0, "el numero magico")?;
        match magic {
            MAGIC_64 | CIGAM_64 => {}
            MAGIC_32 | CIGAM_32 => return Err(MachoError::TreintaYDosBits),
            otra => return Err(MachoError::MagicDesconocida(otra)),
        }

        let cputype = leer_u32(&l, 4, "cputype")? as i32;
        let cpusubtype = leer_u32(&l, 8, "cpusubtype")? as i32;
        let filetype = leer_u32(&l, 12, "filetype")?;
        let ncmds = leer_u32(&l, 16, "ncmds")?;
        let flags = leer_u32(&l, 24, "flags")?;
        if ncmds > MAX_COMANDOS {
            return Err(MachoError::ComandoImposible {
                indice: 0,
                tamano: ncmds,
            });
        }

        let mut comandos = Vec::with_capacity(ncmds.min(64) as usize);
        let mut cursor: u64 = 32;
        for i in 0..ncmds {
            let cmd = leer_u32(&l, cursor, "cmd")?;
            let cmdsize = leer_u32(&l, cursor + 4, "cmdsize")?;
            // Las tres formas de que este campo cuelgue o descoloque el
            // recorrido, comprobadas antes de mover el cursor.
            if cmdsize < 8 || cmdsize % 8 != 0 || !l.cabe(cursor, u64::from(cmdsize)) {
                return Err(MachoError::ComandoImposible {
                    indice: i,
                    tamano: cmdsize,
                });
            }
            comandos.push(interpretar(&l, cursor, cmd, cmdsize)?);
            cursor += u64::from(cmdsize);
        }

        Ok(Macho {
            cputype,
            cpusubtype,
            filetype,
            flags,
            comandos,
        })
    }

    /// Los segmentos.
    pub fn segmentos(&self) -> impl Iterator<Item = &Segmento> {
        self.comandos.iter().filter_map(|c| match c {
            Comando::Segmento(s) => Some(s),
            _ => None,
        })
    }

    /// Las bibliotecas que carga.
    pub fn dylibs(&self) -> impl Iterator<Item = &str> {
        self.comandos.iter().filter_map(|c| match c {
            Comando::Dylib { ruta } => Some(ruta.as_str()),
            _ => None,
        })
    }

    /// Si declara una firma de codigo.
    ///
    /// Se llama asi y no `firmado` a proposito: declarar una firma y tener una
    /// firma valida son cosas distintas, y este crate solo comprueba la primera.
    pub fn declara_firma(&self) -> bool {
        self.comandos
            .iter()
            .any(|c| matches!(c, Comando::FirmaDeCodigo { .. }))
    }
}

/// Interpreta un comando de carga concreto.
fn interpretar(l: &Lector, base: u64, cmd: u32, cmdsize: u32) -> Result<Comando, MachoError> {
    Ok(match cmd {
        LC_SEGMENT_64 if cmdsize >= 72 => Comando::Segmento(Segmento {
            nombre: cadena_fija(l, base + 8, 16)?,
            vmaddr: leer_u64(l, base + 24, "vmaddr")?,
            vmsize: leer_u64(l, base + 32, "vmsize")?,
            fileoff: leer_u64(l, base + 40, "fileoff")?,
            filesize: leer_u64(l, base + 48, "filesize")?,
            maxprot: leer_u32(l, base + 56, "maxprot")?,
            initprot: leer_u32(l, base + 60, "initprot")?,
        }),
        LC_LOAD_DYLIB if cmdsize >= 24 => Comando::Dylib {
            ruta: cadena_en_comando(l, base, cmdsize, 8)?,
        },
        LC_RPATH if cmdsize >= 12 => Comando::Rpath {
            ruta: cadena_en_comando(l, base, cmdsize, 8)?,
        },
        LC_CODE_SIGNATURE if cmdsize >= 16 => Comando::FirmaDeCodigo {
            offset: leer_u32(l, base + 8, "dataoff")?,
            tamano: leer_u32(l, base + 12, "datasize")?,
        },
        LC_MAIN if cmdsize >= 24 => Comando::Main {
            entryoff: leer_u64(l, base + 8, "entryoff")?,
        },
        LC_ENCRYPTION_INFO_64 if cmdsize >= 24 => Comando::Cifrado {
            cryptid: leer_u32(l, base + 16, "cryptid")?,
        },
        otro => Comando::Otro { cmd: otro },
    })
}

/// Lee una cadena de longitud fija, saneada.
fn cadena_fija(l: &Lector, desde: u64, largo: u64) -> Result<String, MachoError> {
    let t = tramo(l, desde, largo, "una cadena de longitud fija")?;
    Ok(sanear(t))
}

/// Lee la cadena que un comando referencia por desplazamiento.
///
/// El desplazamiento es relativo al principio del comando, y puede apuntar mas
/// alla de su propio tamano: entonces la cadena que se leeria seria la del
/// comando siguiente. Se acota al comando.
fn cadena_en_comando(
    l: &Lector,
    base: u64,
    cmdsize: u32,
    campo: u64,
) -> Result<String, MachoError> {
    let off = u64::from(leer_u32(l, base + campo, "el desplazamiento de una ruta")?);
    if off >= u64::from(cmdsize) {
        // Una ruta que dice empezar fuera de su comando: se devuelve vacia en
        // vez de leer la del vecino, y el indicio de que algo no cuadra queda en
        // que la ruta este vacia y no en un texto de otro sitio.
        return Ok(String::new());
    }
    let largo = u64::from(cmdsize) - off;
    let t = tramo(l, base + off, largo, "la ruta de un comando")?;
    Ok(sanear(t))
}

/// Recorta en el primer cero y sustituye lo no imprimible.
///
/// Estas rutas las elige quien construye el binario y acaban en informes y en
/// consolas: un byte de control puede mover el cursor de un terminal o cortar un
/// campo de un CSV.
fn sanear(bruto: &[u8]) -> String {
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

fn tramo<'a>(
    l: &Lector<'a>,
    desde: u64,
    largo: u64,
    que: &'static str,
) -> Result<&'a [u8], MachoError> {
    l.tramo(desde, largo, que)
        .map_err(|_| MachoError::SeAcabaElFichero {
            que,
            desde,
            necesita: largo,
            hay: l.tamano().saturating_sub(desde),
        })
}

fn leer_u32(l: &Lector, desde: u64, que: &'static str) -> Result<u32, MachoError> {
    l.u32(desde, que).map_err(|_| MachoError::SeAcabaElFichero {
        que,
        desde,
        necesita: 4,
        hay: l.tamano().saturating_sub(desde),
    })
}

fn leer_u64(l: &Lector, desde: u64, que: &'static str) -> Result<u64, MachoError> {
    l.u64(desde, que).map_err(|_| MachoError::SeAcabaElFichero {
        que,
        desde,
        necesita: 8,
        hay: l.tamano().saturating_sub(desde),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_macho_de_32_bits_se_rechaza_con_su_propio_error() {
        // No es «no lo entiendo»: es «esto no lo ejecuta ningun Mac desde 2019»,
        // y son dos respuestas distintas para quien triaja un lote de ficheros.
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&MAGIC_32.to_le_bytes());
        assert_eq!(Macho::leer(&b).unwrap_err(), MachoError::TreintaYDosBits);
    }

    #[test]
    fn otra_magic_cualquiera_se_rechaza_diciendo_cual_era() {
        let b = b"\x7fELF\0\0\0\0";
        assert!(matches!(
            Macho::leer(b).unwrap_err(),
            MachoError::MagicDesconocida(_)
        ));
    }

    #[test]
    fn un_cmdsize_de_cero_no_cuelga_el_recorrido() {
        // El bucle avanza `cmdsize` bytes. Con cero no se mueve nunca: treinta y
        // dos bytes bien puestos cuelgan al agente.
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        b[32..36].copy_from_slice(&LC_MAIN.to_le_bytes());
        b[36..40].copy_from_slice(&0u32.to_le_bytes()); // cmdsize = 0
        assert!(matches!(
            Macho::leer(&b).unwrap_err(),
            MachoError::ComandoImposible { tamano: 0, .. }
        ));
    }

    #[test]
    fn un_cmdsize_sin_alinear_se_rechaza() {
        // Descoloca todos los comandos que vengan detras, y lo hace en silencio.
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[32..36].copy_from_slice(&LC_MAIN.to_le_bytes());
        b[36..40].copy_from_slice(&13u32.to_le_bytes());
        assert!(matches!(
            Macho::leer(&b).unwrap_err(),
            MachoError::ComandoImposible { tamano: 13, .. }
        ));
    }

    #[test]
    fn un_numero_de_comandos_absurdo_se_rechaza_antes_de_reservar() {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(
            Macho::leer(&b).unwrap_err(),
            MachoError::ComandoImposible { .. }
        ));
    }

    #[test]
    fn un_fichero_vacio_o_corto_no_entra_en_panico() {
        for n in 0..40 {
            let mut b = vec![0u8; n];
            if n >= 4 {
                b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
            }
            let _ = Macho::leer(&b);
        }
    }

    #[test]
    fn los_permisos_se_miran_por_initprot_y_no_por_maxprot() {
        // `maxprot` vale rwx en muchisimos binarios legitimos: dice lo que el
        // segmento PODRIA llegar a ser, no como se mapea. Mirarlo convertiria el
        // indicio en ruido constante.
        let s = Segmento {
            nombre: "__TEXT".into(),
            vmaddr: 0,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            maxprot: PROT_ESCRITURA | PROT_EJECUCION,
            initprot: PROT_EJECUCION,
        };
        assert!(!s.escribible_y_ejecutable());

        let s2 = Segmento {
            initprot: PROT_ESCRITURA | PROT_EJECUCION,
            ..s
        };
        assert!(s2.escribible_y_ejecutable());
    }

    #[test]
    fn una_ruta_que_empieza_fuera_de_su_comando_no_lee_la_del_vecino() {
        // El desplazamiento es relativo al comando y puede apuntar mas alla de
        // su tamano. Leer entonces devolveria el texto del comando siguiente,
        // que es una ruta legitima de otra biblioteca: el informe diria que el
        // binario carga algo que no carga.
        let mut b = vec![0u8; 128];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[32..36].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
        b[36..40].copy_from_slice(&24u32.to_le_bytes());
        b[40..44].copy_from_slice(&9999u32.to_le_bytes()); // fuera del comando
        let m = Macho::leer(&b).unwrap();
        assert_eq!(m.dylibs().collect::<Vec<_>>(), vec![""]);
    }

    #[test]
    fn el_nombre_de_un_segmento_no_deja_pasar_bytes_de_control() {
        assert_eq!(sanear(b"__TEXT\0\0\0\0\0\0\0\0\0\0"), "__TEXT");
        assert_eq!(sanear(b"a\x07b\0"), "a.b");
    }
}
