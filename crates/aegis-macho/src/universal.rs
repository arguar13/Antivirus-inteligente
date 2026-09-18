//! El binario universal: varios programas en un fichero.
//!
//! # El punto ciego que este modulo existe para cerrar
//!
//! Un ejecutable de macOS puede contener **varios programas a la vez**, uno por
//! arquitectura, y el sistema elige cual corre segun la maquina. Eso convierte
//! una practica habitual de analisis en un agujero con nombre: una herramienta
//! que abra el fichero, encuentre la primera rodaja y la analice esta analizando
//! **el programa que no se va a ejecutar** en la mitad del parque.
//!
//! Un atacante que ponga codigo limpio en la rodaja x86_64 y su carga en la
//! arm64 pasa por delante de cualquier analisis que no mire las dos. Y hoy los
//! Mac son arm64.
//!
//! Por eso [`Binario`] no tiene ninguna funcion que devuelva «la» rodaja. No
//! existe tal cosa: quien consuma esto tiene que decidir explicitamente que hace
//! con cada una. Una API comoda que devolviera la primera seria la forma mas
//! rapida de construir el punto ciego dentro del propio producto.
//!
//! # La trampa de los dos ordenes de byte
//!
//! El encabezado universal es **big-endian siempre**, por herencia de NeXT. Los
//! encabezados Mach-O de dentro son little-endian en todas las maquinas que
//! quedan. Leerlo en orden nativo funcionaba en un PowerPC de 2003; en cualquier
//! ordenador de hoy da un numero de rodajas absurdo —y si el lector se fia de
//! el, una reserva de memoria absurda—.
//!
//! # Y la de `0xcafebabe`
//!
//! Ese numero magico no es solo de Apple: un fichero `.class` de Java empieza
//! exactamente igual. macOS los distingue porque en un `.class` los dos campos
//! siguientes son numeros de version —que leidos como «numero de rodajas» dan un
//! valor enorme— y aqui se hace lo mismo: un recuento imposible se rechaza como
//! tal en vez de intentar leer cuarenta y cinco mil rodajas.

use aegis_pe::lectura::Lector;

use crate::error::MachoError;
use crate::macho::Macho;

/// `FAT_MAGIC`, tal y como aparece en el fichero (big-endian).
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// `FAT_MAGIC_64`.
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;

/// Ningun binario universal real pasa de esto.
///
/// Apple ha publicado como mucho cuatro arquitecturas a la vez. Veinte deja
/// margen de sobra y corta en seco el `.class` de Java, cuyo campo equivalente
/// vale decenas de miles.
const MAX_RODAJAS: u32 = 20;

/// Una rodaja del binario universal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rodaja {
    /// Arquitectura.
    pub cputype: i32,
    /// Subtipo.
    pub cpusubtype: i32,
    /// Donde empieza en el fichero.
    pub offset: u64,
    /// Cuanto ocupa.
    pub tamano: u64,
    /// El Mach-O de esta rodaja, si se pudo leer.
    ///
    /// Es un `Result` y no un `Option` a proposito: una rodaja que no se puede
    /// leer no es una rodaja ausente. El fichero sigue teniendola, el sistema
    /// puede ejecutarla, y lo unico que pasa es que este lector no pudo mirarla.
    /// Guardar el motivo deja que quien analice sepa que le falta.
    pub macho: Result<Macho, MachoError>,
}

impl Rodaja {
    /// Nombre legible de la arquitectura.
    pub fn arquitectura(&self) -> &'static str {
        match (self.cputype, self.cpusubtype & 0x00ff_ffff) {
            (0x0100_000c, _) => "arm64",
            (12, _) => "arm",
            (0x0100_0007, _) => "x86_64",
            (7, _) => "i386",
            (0x0100_0012, _) => "ppc64",
            (18, _) => "ppc",
            _ => "desconocida",
        }
    }
}

/// Un binario de macOS: una sola arquitectura o varias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binario {
    /// Un Mach-O suelto.
    Sencillo(Macho),
    /// Un contenedor con varias rodajas.
    Universal {
        /// Todas las rodajas, en el orden en que vienen.
        rodajas: Vec<Rodaja>,
    },
}

impl Binario {
    /// Lee un binario de macOS, sea del tipo que sea.
    pub fn leer(bytes: &[u8]) -> Result<Binario, MachoError> {
        let l = Lector::nuevo(bytes);
        // El encabezado universal va en big-endian. Este es el punto exacto en
        // el que un lector escrito en orden nativo se equivoca.
        let magic = be32(&l, 0)?;
        if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
            return Ok(Binario::Sencillo(Macho::leer(bytes)?));
        }
        let ancho_64 = magic == FAT_MAGIC_64;
        let n = be32(&l, 4)?;
        if n == 0 || n > MAX_RODAJAS {
            return Err(MachoError::DemasiadasRodajas(n));
        }

        let tam_entrada: u64 = if ancho_64 { 32 } else { 20 };
        let mut rodajas = Vec::with_capacity(n as usize);
        for i in 0..u64::from(n) {
            let e = 8 + i * tam_entrada;
            let cputype = be32(&l, e)? as i32;
            let cpusubtype = be32(&l, e + 4)? as i32;
            let (offset, tamano) = if ancho_64 {
                (be64(&l, e + 8)?, be64(&l, e + 16)?)
            } else {
                (u64::from(be32(&l, e + 8)?), u64::from(be32(&l, e + 12)?))
            };
            if !l.cabe(offset, tamano) {
                return Err(MachoError::RodajaFueraDelFichero {
                    indice: i as u32,
                    offset,
                    tamano,
                    fichero: l.tamano(),
                });
            }
            let trozo = &bytes[offset as usize..(offset + tamano) as usize];
            rodajas.push(Rodaja {
                cputype,
                cpusubtype,
                offset,
                tamano,
                macho: Macho::leer(trozo),
            });
        }

        // Dos rodajas que ocupan el mismo tramo hacen que dos herramientas lean
        // cosas distintas del mismo fichero segun por donde entren. No es solo
        // malformacion: es una forma de discrepancia deliberada.
        for i in 0..rodajas.len() {
            for j in (i + 1)..rodajas.len() {
                let (a, b) = (&rodajas[i], &rodajas[j]);
                if a.tamano > 0
                    && b.tamano > 0
                    && a.offset < b.offset + b.tamano
                    && b.offset < a.offset + a.tamano
                {
                    return Err(MachoError::RodajasQueSeSolapan {
                        una: i as u32,
                        otra: j as u32,
                    });
                }
            }
        }

        Ok(Binario::Universal { rodajas })
    }

    /// Cuantos programas distintos contiene el fichero.
    ///
    /// Uno para un Mach-O suelto; tantos como rodajas para un universal. Quien
    /// analice tiene que mirarlos todos, y este numero es lo que le dice cuantos
    /// son.
    pub fn cuantos_programas(&self) -> usize {
        match self {
            Binario::Sencillo(_) => 1,
            Binario::Universal { rodajas } => rodajas.len(),
        }
    }

    /// Las arquitecturas que trae.
    pub fn arquitecturas(&self) -> Vec<&'static str> {
        match self {
            Binario::Sencillo(m) => vec![Rodaja {
                cputype: m.cputype,
                cpusubtype: m.cpusubtype,
                offset: 0,
                tamano: 0,
                macho: Err(MachoError::TreintaYDosBits),
            }
            .arquitectura()],
            Binario::Universal { rodajas } => rodajas.iter().map(|r| r.arquitectura()).collect(),
        }
    }
}

fn be32(l: &Lector, desde: u64) -> Result<u32, MachoError> {
    let t =
        l.tramo(desde, 4, "un entero big-endian")
            .map_err(|_| MachoError::SeAcabaElFichero {
                que: "un entero big-endian",
                desde,
                necesita: 4,
                hay: l.tamano().saturating_sub(desde),
            })?;
    Ok(u32::from_be_bytes([t[0], t[1], t[2], t[3]]))
}

fn be64(l: &Lector, desde: u64) -> Result<u64, MachoError> {
    let t = l
        .tramo(desde, 8, "un entero big-endian de 64")
        .map_err(|_| MachoError::SeAcabaElFichero {
            que: "un entero big-endian de 64",
            desde,
            necesita: 8,
            hay: l.tamano().saturating_sub(desde),
        })?;
    Ok(u64::from_be_bytes([
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
    ]))
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::macho::MAGIC_64;

    /// Monta un contenedor universal con las rodajas que se le den.
    fn universal(rodajas: &[(i32, Vec<u8>)]) -> Vec<u8> {
        let cab = 8 + 20 * rodajas.len();
        let mut fichero = vec![0u8; cab];
        fichero[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        fichero[4..8].copy_from_slice(&(rodajas.len() as u32).to_be_bytes());
        for (i, (cpu, cuerpo)) in rodajas.iter().enumerate() {
            // Alineado a 16, como hace `lipo`.
            while fichero.len() % 16 != 0 {
                fichero.push(0);
            }
            let off = fichero.len() as u32;
            let e = 8 + i * 20;
            fichero[e..e + 4].copy_from_slice(&(*cpu as u32).to_be_bytes());
            fichero[e + 4..e + 8].copy_from_slice(&0u32.to_be_bytes());
            fichero[e + 8..e + 12].copy_from_slice(&off.to_be_bytes());
            fichero[e + 12..e + 16].copy_from_slice(&(cuerpo.len() as u32).to_be_bytes());
            fichero[e + 16..e + 20].copy_from_slice(&4u32.to_be_bytes());
            fichero.extend_from_slice(cuerpo);
        }
        fichero
    }

    fn macho_minimo(cpu: i32) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        b[4..8].copy_from_slice(&(cpu as u32).to_le_bytes());
        b
    }

    #[test]
    fn un_binario_universal_trae_todas_sus_rodajas() {
        let f = universal(&[
            (0x0100_0007, macho_minimo(0x0100_0007)), // x86_64
            (0x0100_000c, macho_minimo(0x0100_000c)), // arm64
        ]);
        let b = Binario::leer(&f).unwrap();
        assert_eq!(b.cuantos_programas(), 2, "son DOS programas, no uno");
        assert_eq!(b.arquitecturas(), vec!["x86_64", "arm64"]);
    }

    #[test]
    fn el_encabezado_universal_se_lee_en_big_endian() {
        // Si se leyera en orden nativo, el numero de rodajas de este fichero
        // saldria 0x02000000 —treinta y tres millones— y el lector intentaria
        // reservar para todas.
        let f = universal(&[(0x0100_000c, macho_minimo(0x0100_000c))]);
        assert_eq!(&f[0..4], &FAT_MAGIC.to_be_bytes());
        assert!(Binario::leer(&f).is_ok());
    }

    #[test]
    fn un_class_de_java_no_se_lee_como_un_binario_universal() {
        // Mismo numero magico. Lo que sigue en un .class son dos numeros de
        // version, que leidos como recuento de rodajas dan un valor enorme.
        let mut java = vec![0u8; 64];
        java[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        java[4..8].copy_from_slice(&0x0000_0041u32.to_be_bytes()); // version 65
        let e = Binario::leer(&java).unwrap_err();
        assert!(
            matches!(e, MachoError::DemasiadasRodajas(0x41)),
            "un .class tiene que rechazarse por el recuento: {e}"
        );
    }

    #[test]
    fn una_rodaja_que_apunta_fuera_del_fichero_se_rechaza() {
        let mut f = universal(&[(0x0100_000c, macho_minimo(0x0100_000c))]);
        f[16..20].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes()); // offset
        assert!(matches!(
            Binario::leer(&f).unwrap_err(),
            MachoError::RodajaFueraDelFichero { .. }
        ));
    }

    #[test]
    fn dos_rodajas_que_se_solapan_se_rechazan() {
        // Dos herramientas leerian cosas distintas del mismo fichero segun por
        // donde entren, que es el objetivo de construirlo asi.
        let cuerpo = macho_minimo(0x0100_000c);
        let mut f = universal(&[(0x0100_0007, cuerpo.clone()), (0x0100_000c, cuerpo)]);
        // Se apunta la segunda rodaja al mismo sitio que la primera.
        let off_primera = u32::from_be_bytes([f[16], f[17], f[18], f[19]]);
        f[36..40].copy_from_slice(&off_primera.to_be_bytes());
        assert!(matches!(
            Binario::leer(&f).unwrap_err(),
            MachoError::RodajasQueSeSolapan { una: 0, otra: 1 }
        ));
    }

    #[test]
    fn una_rodaja_ilegible_conserva_su_motivo_en_vez_de_desaparecer() {
        // Una rodaja que no se puede leer NO es una rodaja ausente: el fichero
        // la tiene y el sistema puede ejecutarla. Lo unico que pasa es que este
        // lector no pudo mirarla, y eso hay que poder decirlo.
        let f = universal(&[
            (0x0100_0007, macho_minimo(0x0100_0007)),
            (0x0100_000c, vec![0xff; 32]), // basura
        ]);
        let Binario::Universal { rodajas } = Binario::leer(&f).unwrap() else {
            panic!("tiene que ser universal");
        };
        assert_eq!(rodajas.len(), 2, "las dos siguen contando");
        assert!(rodajas[0].macho.is_ok());
        assert!(
            rodajas[1].macho.is_err(),
            "y la ilegible dice por que, en vez de no estar"
        );
    }

    #[test]
    fn cero_rodajas_se_rechaza() {
        let mut f = vec![0u8; 32];
        f[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        f[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            Binario::leer(&f).unwrap_err(),
            MachoError::DemasiadasRodajas(0)
        ));
    }

    #[test]
    fn un_macho_suelto_cuenta_como_un_solo_programa() {
        let b = Binario::leer(&macho_minimo(0x0100_000c)).unwrap();
        assert_eq!(b.cuantos_programas(), 1);
        assert_eq!(b.arquitecturas(), vec!["arm64"]);
    }
}
