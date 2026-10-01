//! El espacio de configuracion PCI, leido **solo** por sysfs.
//!
//! # Por que sysfs y no los puertos 0xCF8/0xCFC ni el ECAM por `/dev/mem`
//!
//! Los registros que deciden si la flash es escribible (BIOS_CNTL), si SMRAM esta
//! cerrada (SMRAMC, TSEGMB) o si el ME esta en modo fabricacion (HFSTS1) viven en
//! el espacio de configuracion de dispositivos concretos del chipset. Hay tres
//! formas de llegar a ellos, y solo una es aceptable en un producto que corre
//! desatendido en cien mil maquinas:
//!
//! - **Los puertos 0xCF8/0xCFC**: para leer hay que ESCRIBIR la direccion en 0xCF8.
//!   Es una escritura en el hardware, y ademas no es atomica frente al kernel,
//!   que usa los mismos puertos: una lectura nuestra entre su escritura y su
//!   lectura le devuelve a el el registro de otro dispositivo.
//! - **El ECAM por `/dev/mem`**: funciona, pero salta por encima del kernel, que
//!   es quien sabe que dispositivos existen y cuales estan ocultos.
//! - **`/sys/bus/pci/devices/<bdf>/config`**: el kernel hace la lectura con sus
//!   propios cerrojos. Es la unica via que no puede estropear nada, y es la que se
//!   usa.
//!
//! # El detalle que convierte un «todo bien» en una mentira
//!
//! Sysfs solo sirve los **primeros 64 bytes** de configuracion a quien no es root.
//! BIOS_CNTL esta en 0xDC. Un lector que no mirara la longitud leeria un cero
//! donde no habia dato, y un cero en BIOS_CNTL se lee como «BLE desactivado»: un
//! falso positivo de exposicion en cada maquina donde el agente arranque sin
//! privilegios. Por eso [`Config::u8`] y compania devuelven `None` fuera de lo
//! leido, y quien decide tiene que decir «no se pudo leer» en vez de inventar.

use std::path::{Path, PathBuf};

use crate::solo_lectura::{ErrorLectura, LecturaSolo};

/// Donde el kernel expone los dispositivos PCI, relativo a la raiz de sysfs.
pub const DIR_DISPOSITIVOS: &str = "bus/pci/devices";

/// Tamano maximo del espacio de configuracion (PCIe extendido).
pub const TAM_CONFIG_EXTENDIDA: usize = 4096;

/// Lo que sysfs sirve a un usuario sin privilegios.
pub const TAM_CONFIG_SIN_PRIVILEGIO: usize = 64;

/// Fabricante Intel.
pub const INTEL: u16 = 0x8086;
/// Fabricante AMD.
pub const AMD: u16 = 0x1022;

/// Direccion PCI: dominio, bus, dispositivo y funcion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bdf {
    /// Dominio (segmento).
    pub dominio: u32,
    /// Bus.
    pub bus: u8,
    /// Dispositivo (0-31).
    pub dispositivo: u8,
    /// Funcion (0-7).
    pub funcion: u8,
}

impl Bdf {
    /// Construye una direccion en el dominio 0.
    #[must_use]
    pub const fn nueva(bus: u8, dispositivo: u8, funcion: u8) -> Bdf {
        Bdf {
            dominio: 0,
            bus,
            dispositivo,
            funcion,
        }
    }

    /// Analiza `0000:00:1f.5`.
    ///
    /// Se rechaza cualquier cosa que no sea exactamente ese formato: el nombre
    /// viene de un directorio, y un directorio con otro nombre no es un
    /// dispositivo que se deba leer.
    #[must_use]
    pub fn analizar(s: &str) -> Option<Bdf> {
        let (dominio, resto) = s.split_once(':')?;
        let (bus, resto) = resto.split_once(':')?;
        let (dispositivo, funcion) = resto.split_once('.')?;
        if dominio.len() != 4 || bus.len() != 2 || dispositivo.len() != 2 || funcion.len() != 1 {
            return None;
        }
        let d = u8::from_str_radix(dispositivo, 16).ok()?;
        let f = u8::from_str_radix(funcion, 16).ok()?;
        if d > 31 || f > 7 {
            return None;
        }
        Some(Bdf {
            dominio: u32::from_str_radix(dominio, 16).ok()?,
            bus: u8::from_str_radix(bus, 16).ok()?,
            dispositivo: d,
            funcion: f,
        })
    }

    /// Forma canonica `0000:00:1f.5`.
    #[must_use]
    pub fn texto(&self) -> String {
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.dominio, self.bus, self.dispositivo, self.funcion
        )
    }
}

/// Un dispositivo PCI tal y como lo describe sysfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispositivo {
    /// Direccion.
    pub bdf: Bdf,
    /// Fabricante.
    pub fabricante: u16,
    /// Identificador de dispositivo.
    pub id: u16,
    /// Clase de 24 bits (clase, subclase, interfaz).
    pub clase: u32,
    /// Directorio del dispositivo en sysfs.
    pub dir: PathBuf,
}

impl Dispositivo {
    /// Clase base (los 8 bits altos).
    #[must_use]
    pub const fn clase_base(&self) -> u8 {
        (self.clase >> 16) as u8
    }

    /// Subclase.
    #[must_use]
    pub const fn subclase(&self) -> u8 {
        (self.clase >> 8) as u8
    }

    /// Nombre corto para un informe: `0000:00:1f.5 8086:a324`.
    #[must_use]
    pub fn nombre(&self) -> String {
        format!(
            "{} {:04x}:{:04x}",
            self.bdf.texto(),
            self.fabricante,
            self.id
        )
    }
}

/// El espacio de configuracion leido, con su longitud real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    bytes: Vec<u8>,
}

impl Config {
    /// Envuelve bytes ya leidos.
    #[must_use]
    pub fn de_bytes(bytes: Vec<u8>) -> Config {
        Config { bytes }
    }

    /// Cuantos bytes se leyeron de verdad.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Si no se leyo nada.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Si el registro en `offset` de `ancho` bytes esta dentro de lo leido.
    #[must_use]
    pub fn cubre(&self, offset: usize, ancho: usize) -> bool {
        offset
            .checked_add(ancho)
            .is_some_and(|fin| fin <= self.bytes.len())
    }

    /// Un byte, o `None` si no se leyo.
    #[must_use]
    pub fn u8(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// Dos bytes en little-endian.
    #[must_use]
    pub fn u16(&self, offset: usize) -> Option<u16> {
        let s = self.bytes.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Cuatro bytes en little-endian.
    #[must_use]
    pub fn u32(&self, offset: usize) -> Option<u32> {
        let s = self.bytes.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Ocho bytes en little-endian.
    #[must_use]
    pub fn u64(&self, offset: usize) -> Option<u64> {
        let s = self.bytes.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }

    /// La direccion fisica de un BAR de memoria, con su mitad alta si es de 64
    /// bits. `None` si el BAR es de E/S, esta vacio o no se leyo.
    #[must_use]
    pub fn bar_memoria(&self, indice: usize) -> Option<u64> {
        if indice > 5 {
            return None;
        }
        let off = 0x10 + indice * 4;
        let bajo = self.u32(off)?;
        // Bit 0 a uno: BAR de E/S, no de memoria.
        if bajo & 1 != 0 {
            return None;
        }
        let tipo = (bajo >> 1) & 0x3;
        let base_baja = u64::from(bajo & 0xFFFF_FFF0);
        let base = if tipo == 0x2 {
            let alto = u64::from(self.u32(off + 4)?);
            (alto << 32) | base_baja
        } else {
            base_baja
        };
        (base != 0).then_some(base)
    }
}

/// Por que no se pudo enumerar el bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinPci(pub String);

/// Enumera los dispositivos PCI bajo una raiz de sysfs.
///
/// # Errores
/// [`SinPci`] con el motivo si el directorio no existe o no se puede leer: una
/// maquina sin bus PCI visible (un contenedor, un ARM sin PCI) es «no aplicable»,
/// y el motivo tiene que llegar al informe.
pub fn enumerar(raiz_sys: &Path) -> Result<Vec<Dispositivo>, SinPci> {
    let dir = raiz_sys.join(DIR_DISPOSITIVOS);
    let entradas = std::fs::read_dir(&dir)
        .map_err(|e| SinPci(format!("{} no se puede leer: {e}", dir.display())))?;
    let mut salida = Vec::new();
    for e in entradas.flatten() {
        let nombre = e.file_name().to_string_lossy().to_string();
        let Some(bdf) = Bdf::analizar(&nombre) else {
            continue;
        };
        let d = e.path();
        let hex = |campo: &str| -> Option<u32> {
            let t = std::fs::read_to_string(d.join(campo)).ok()?;
            u32::from_str_radix(t.trim().trim_start_matches("0x"), 16).ok()
        };
        let (Some(fabricante), Some(id), Some(clase)) =
            (hex("vendor"), hex("device"), hex("class"))
        else {
            continue;
        };
        salida.push(Dispositivo {
            bdf,
            fabricante: fabricante as u16,
            id: id as u16,
            clase,
            dir: d,
        });
    }
    // Orden estable: dos auditorias de la misma maquina producen el mismo informe.
    salida.sort_by_key(|d| d.bdf);
    Ok(salida)
}

/// Lee el espacio de configuracion de un dispositivo, de solo lectura.
///
/// # Errores
/// [`ErrorLectura`] si el fichero no se puede abrir o leer.
pub fn leer_config(d: &Dispositivo) -> Result<Config, ErrorLectura> {
    let lector = LecturaSolo::abrir(&d.dir.join("config"))?;
    Ok(Config::de_bytes(lector.leer_todo(TAM_CONFIG_EXTENDIDA)?))
}

/// Busca un dispositivo por direccion.
#[must_use]
pub fn por_bdf(dispositivos: &[Dispositivo], bdf: Bdf) -> Option<&Dispositivo> {
    dispositivos.iter().find(|d| d.bdf == bdf)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    #[test]
    fn la_direccion_se_analiza_en_su_forma_canonica_y_nada_mas() {
        let b = Bdf::analizar("0000:00:1f.5").expect("valida");
        assert_eq!(b, Bdf::nueva(0, 0x1f, 5));
        assert_eq!(b.texto(), "0000:00:1f.5");
        // Los dominios de Hyper-V son grandes y siguen siendo validos.
        assert_eq!(
            Bdf::analizar("5582:00:00.0").expect("hyper-v").dominio,
            0x5582
        );
        for malo in [
            "",
            "0000:00:1f",
            "00:1f.5",
            "0000:00:20.0",
            "0000:00:1f.8",
            "zzzz:00:00.0",
            "0000:000:00.0",
            "..",
        ] {
            assert!(Bdf::analizar(malo).is_none(), "{malo:?}");
        }
    }

    /// FUERA DE LO LEIDO NO HAY DATO. Sysfs sirve 64 bytes a quien no es root, y
    /// un cero inventado en BIOS_CNTL se leeria como «BLE desactivado»: un falso
    /// positivo de exposicion en cada maquina sin privilegios.
    #[test]
    fn un_registro_fuera_de_lo_leido_es_none_y_no_cero() {
        let c = Config::de_bytes(vec![0xAB; TAM_CONFIG_SIN_PRIVILEGIO]);
        assert_eq!(c.u8(0x3F), Some(0xAB));
        assert_eq!(c.u8(0xDC), None);
        assert_eq!(c.u32(0x3E), None, "un registro a caballo del final tampoco");
        assert!(!c.cubre(0xDC, 1));
        assert_eq!(c.u64(usize::MAX), None);
    }

    #[test]
    fn un_bar_de_64_bits_junta_sus_dos_mitades() {
        let mut b = vec![0u8; 64];
        // BAR0: memoria, tipo 64 bits (bits 2:1 = 10), base baja 0xFE01_0000.
        b[0x10..0x14].copy_from_slice(&0xFE01_0004u32.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        // BAR2: E/S.
        b[0x18..0x1C].copy_from_slice(&0x0000_E001u32.to_le_bytes());
        let c = Config::de_bytes(b);
        assert_eq!(c.bar_memoria(0), Some(0x1_FE01_0000));
        assert_eq!(c.bar_memoria(2), None, "un BAR de E/S no es de memoria");
        assert_eq!(c.bar_memoria(4), None, "un BAR vacio no es una direccion");
        assert_eq!(c.bar_memoria(9), None);
    }

    /// EL BUS REAL DE ESTA MAQUINA. Se enumera y se lee la configuracion de cada
    /// dispositivo; lo que no se pueda leer se dice, no se omite.
    #[test]
    fn el_bus_pci_real_de_esta_maquina_se_enumera_y_se_lee() {
        let ds = match enumerar(Path::new("/sys")) {
            Ok(d) => d,
            Err(SinPci(m)) => {
                omitir(&format!("sin bus PCI legible: {m}"), Requisito::Pci);
                return;
            }
        };
        eprintln!("dispositivos PCI reales: {}", ds.len());
        for d in &ds {
            match leer_config(d) {
                Ok(c) => {
                    eprintln!(
                        "  {} clase {:06x}: {} B de configuracion",
                        d.nombre(),
                        d.clase,
                        c.len()
                    );
                    assert!(c.len() >= TAM_CONFIG_SIN_PRIVILEGIO);
                    // Los dos primeros registros repiten lo que dice sysfs: si no
                    // cuadran, el lector esta desplazado.
                    assert_eq!(c.u16(0), Some(d.fabricante), "{}", d.nombre());
                    assert_eq!(c.u16(2), Some(d.id), "{}", d.nombre());
                }
                Err(e) => eprintln!("  {}: ilegible ({e})", d.nombre()),
            }
        }
    }

    #[test]
    fn una_raiz_sin_bus_se_declara_con_su_motivo() {
        let r = enumerar(Path::new("/no/existe/sys"));
        match r {
            Err(SinPci(m)) => assert!(m.contains("no se puede leer"), "{m}"),
            Ok(_) => panic!("una raiz inexistente no tiene dispositivos"),
        }
    }
}
