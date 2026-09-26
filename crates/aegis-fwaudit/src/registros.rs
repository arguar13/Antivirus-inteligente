//! Los registros del chipset que deciden si el firmware se puede reescribir, si
//! SMRAM esta cerrada y si el ME esta en modo fabricacion.
//!
//! # Lo que se decide aqui, y por que es decision y no lectura
//!
//! Leer un bit es trivial. Lo que no lo es —y donde CHIPSEC tiene veinte anos de
//! oficio— es saber **que combinacion** de bits es una puerta abierta. Tres
//! ejemplos que un lector ingenuo resuelve mal:
//!
//! - `BLE = 1` parece proteccion, y lo es **solo si** `SMM_BWP = 1`. Sin el, entre
//!   que el SO pone `BIOSWE` y el SMI de `BLE` lo vuelve a bajar hay una ventana
//!   en la que un segundo nucleo escribe en la flash (la carrera publicada como
//!   *Speed Racer*). Mirar `BLE` solo da un verde falso.
//! - Los registros `PRx` protegen la region BIOS **aunque** `BLE` falle, porque los
//!   aplica el propio controlador SPI; pero solo si `FLOCKDN` esta puesto, o el SO
//!   los borra y escribe.
//! - `D_LCK` en SMRAMC es lo que impide abrir SMRAM desde el SO. `D_OPEN = 1` con
//!   `D_LCK = 1` es una SMRAM que se dejo abierta y luego se bloqueo asi.
//!
//! Todo esto son funciones puras sobre valores de registro, y por eso se prueban
//! con los valores que dan los datasheets de Intel, bit a bit, en vez de con la
//! placa que haya en la maquina de integracion.
//!
//! # Todo son EXPOSICIONES
//!
//! Ningun registro de este modulo dice que alguien actuo: dicen que se podria.
//! Por eso todas las comprobaciones salen con [`Naturaleza::Exposicion`] y
//! ninguna llega al arbitro como sospecha. Ver [`crate::comprobacion`].

use aegis_firmware::report::CheckState;

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::pci::{Bdf, Config, Dispositivo, AMD, INTEL};

// ─── BIOS_CNTL ────────────────────────────────────────────────────────────────

/// Desplazamiento de BIOS_CNTL en la configuracion del puente LPC (legado) o del
/// controlador SPI (PCH serie 100 en adelante).
pub const OFF_BIOS_CNTL: usize = 0xDC;

/// BIOS_CNTL: el registro de proteccion de escritura de la region BIOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiosCntl(pub u8);

impl BiosCntl {
    /// Bit 0, BIOSWE: la escritura en la region BIOS esta habilitada.
    #[must_use]
    pub const fn bioswe(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// Bit 1, BLE: poner BIOSWE dispara un SMI (que puede volver a bajarlo).
    #[must_use]
    pub const fn ble(self) -> bool {
        self.0 & 0x02 != 0
    }
    /// Bit 4, TSS: estado del intercambio de bloque superior (Top Swap).
    #[must_use]
    pub const fn tss(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// Bit 5, SMM_BWP (EISS en PCH 100+): solo SMM puede escribir la region BIOS.
    #[must_use]
    pub const fn smm_bwp(self) -> bool {
        self.0 & 0x20 != 0
    }
    /// Bit 7, BILD: bloquea la configuracion de arranque (BBS y Top Swap).
    #[must_use]
    pub const fn bild(self) -> bool {
        self.0 & 0x80 != 0
    }
}

// ─── Registros del controlador SPI (SPIBAR) ───────────────────────────────────

/// HSFS dentro de SPIBAR.
pub const OFF_HSFS: u64 = 0x04;
/// FRAP (permisos de acceso por region) dentro de SPIBAR.
pub const OFF_FRAP: u64 = 0x50;
/// FREG1 (limites de la region BIOS) dentro de SPIBAR.
pub const OFF_FREG1: u64 = 0x58;
/// PR0 en el PCH serie 100 en adelante.
pub const OFF_PR0_PCH100: u64 = 0x84;
/// PR0 en los ICH/PCH de legado (ICH9 hasta la serie 9).
pub const OFF_PR0_LEGADO: u64 = 0x74;
/// Numero de registros PRx.
pub const NUM_PR: usize = 5;

/// HSFS: estado del secuenciador hardware de la flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hsfs(pub u16);

impl Hsfs {
    /// Bit 13, FDOPSS: 1 = el pin de anulacion del descriptor NO esta puesto.
    #[must_use]
    pub const fn fdopss(self) -> bool {
        self.0 & (1 << 13) != 0
    }
    /// Bit 14, FDV: el descriptor de flash es valido.
    #[must_use]
    pub const fn fdv(self) -> bool {
        self.0 & (1 << 14) != 0
    }
    /// Bit 15, FLOCKDN: los registros PRx y FRAP quedan bloqueados hasta el reset.
    #[must_use]
    pub const fn flockdn(self) -> bool {
        self.0 & (1 << 15) != 0
    }
}

/// FRAP: que regiones puede leer y escribir el anfitrion (la CPU).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frap(pub u32);

impl Frap {
    /// BRRA: regiones que el anfitrion puede leer (bit N = region N).
    #[must_use]
    pub const fn brra(self) -> u8 {
        self.0 as u8
    }
    /// BRWA: regiones que el anfitrion puede escribir.
    #[must_use]
    pub const fn brwa(self) -> u8 {
        (self.0 >> 8) as u8
    }
}

/// Un rango de la flash `[base, limite]`, con el formato de FLREG/FREG/PRx: 15
/// bits de base y 15 de limite en unidades de 4 KiB, limite inclusivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rango {
    /// Primer byte.
    pub base: u32,
    /// Ultimo byte, inclusive.
    pub limite: u32,
}

impl Rango {
    /// Decodifica el formato comun de FREG y PRx.
    #[must_use]
    pub const fn de_registro(v: u32) -> Rango {
        Rango {
            base: (v & 0x7FFF) << 12,
            limite: (((v >> 16) & 0x7FFF) << 12) | 0xFFF,
        }
    }

    /// Si el rango esta en uso (una region vacia se codifica con base > limite).
    #[must_use]
    pub const fn usado(self) -> bool {
        self.base <= self.limite
    }
}

/// PRx: un rango protegido por el propio controlador SPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pr(pub u32);

impl Pr {
    /// El rango protegido.
    #[must_use]
    pub const fn rango(self) -> Rango {
        Rango::de_registro(self.0)
    }
    /// Bit 15, RPE: proteccion de lectura.
    #[must_use]
    pub const fn rpe(self) -> bool {
        self.0 & (1 << 15) != 0
    }
    /// Bit 31, WPE: proteccion de escritura.
    #[must_use]
    pub const fn wpe(self) -> bool {
        self.0 & (1 << 31) != 0
    }
}

/// Los registros de SPIBAR que importan a la auditoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrosSpi {
    /// Estado del secuenciador.
    pub hsfs: Hsfs,
    /// Permisos por region.
    pub frap: Frap,
    /// Region BIOS segun el controlador.
    pub bios: Rango,
    /// Los cinco PRx.
    pub pr: [Pr; NUM_PR],
}

impl RegistrosSpi {
    /// Si los PRx con proteccion de escritura cubren la region BIOS entera.
    ///
    /// Se comprueba cubrimiento de verdad y no «hay algun PR activo»: un PR que
    /// protege solo el bloque de arranque deja el resto de la BIOS escribible, y
    /// es exactamente lo que un implante necesita.
    #[must_use]
    pub fn prx_cubren_bios(&self) -> bool {
        if !self.bios.usado() {
            return false;
        }
        let mut rangos: Vec<Rango> = self
            .pr
            .iter()
            .filter(|p| p.wpe() && p.rango().usado())
            .map(|p| p.rango())
            .collect();
        rangos.sort_by_key(|r| r.base);
        let mut cubierto_hasta = u64::from(self.bios.base);
        for r in rangos {
            if u64::from(r.base) > cubierto_hasta {
                break;
            }
            cubierto_hasta = cubierto_hasta.max(u64::from(r.limite) + 1);
        }
        cubierto_hasta > u64::from(self.bios.limite)
    }
}

// ─── Puente anfitrion (00:00.0) ───────────────────────────────────────────────

/// SMRAMC en el puente anfitrion (u8).
pub const OFF_SMRAMC: usize = 0x88;
/// REMAPBASE (u64).
pub const OFF_REMAPBASE: usize = 0x90;
/// REMAPLIMIT (u64).
pub const OFF_REMAPLIMIT: usize = 0x98;
/// TOUUD (u64).
pub const OFF_TOUUD: usize = 0xA8;
/// BGSM (u32).
pub const OFF_BGSM: usize = 0xB4;
/// TSEGMB (u32).
pub const OFF_TSEGMB: usize = 0xB8;
/// TOLUD (u32).
pub const OFF_TOLUD: usize = 0xBC;

/// SMRAMC: control del espacio SMRAM heredado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smramc(pub u8);

impl Smramc {
    /// Bit 3, G_SMRAME: SMRAM habilitada.
    #[must_use]
    pub const fn g_smrame(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// Bit 4, D_LCK: la configuracion de SMRAM esta bloqueada.
    #[must_use]
    pub const fn d_lck(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// Bit 6, D_OPEN: SMRAM visible fuera de SMM.
    #[must_use]
    pub const fn d_open(self) -> bool {
        self.0 & 0x40 != 0
    }
}

/// Los registros del puente anfitrion que auditar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuenteAnfitrion {
    /// SMRAMC.
    pub smramc: Option<Smramc>,
    /// TSEGMB crudo.
    pub tsegmb: Option<u32>,
    /// BGSM crudo.
    pub bgsm: Option<u32>,
    /// TOLUD crudo.
    pub tolud: Option<u32>,
    /// TOUUD crudo.
    pub touud: Option<u64>,
    /// REMAPBASE crudo.
    pub remapbase: Option<u64>,
    /// REMAPLIMIT crudo.
    pub remaplimit: Option<u64>,
}

impl PuenteAnfitrion {
    /// Lee los registros de la configuracion del puente.
    #[must_use]
    pub fn de_config(c: &Config) -> PuenteAnfitrion {
        PuenteAnfitrion {
            smramc: c.u8(OFF_SMRAMC).map(Smramc),
            tsegmb: c.u32(OFF_TSEGMB),
            bgsm: c.u32(OFF_BGSM),
            tolud: c.u32(OFF_TOLUD),
            touud: c.u64(OFF_TOUUD),
            remapbase: c.u64(OFF_REMAPBASE),
            remaplimit: c.u64(OFF_REMAPLIMIT),
        }
    }

    /// La base de TSEG (bits 31:20 de TSEGMB).
    #[must_use]
    pub fn tseg_base(&self) -> Option<u64> {
        self.tsegmb.map(|v| u64::from(v & 0xFFF0_0000))
    }

    /// El final de TSEG, exclusivo: la base de la memoria robada de graficos.
    #[must_use]
    pub fn tseg_fin(&self) -> Option<u64> {
        self.bgsm.map(|v| u64::from(v & 0xFFF0_0000))
    }
}

// ─── PMC y ME ─────────────────────────────────────────────────────────────────

/// GEN_PMCON_A (PCH 100+, en el PMC) / GEN_PMCON_1 (legado, en el LPC).
pub const OFF_GEN_PMCON: usize = 0xA0;
/// HFSTS1 del ME, en la configuracion del HECI (00:16.0).
pub const OFF_HFSTS1: usize = 0x40;

/// HFSTS1: el primer registro de estado del firmware del ME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hfsts1(pub u32);

impl Hfsts1 {
    /// Bit 4: modo fabricacion.
    #[must_use]
    pub const fn modo_fabricacion(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    /// Bits 19:16: modo de operacion del ME.
    #[must_use]
    pub const fn modo_operacion(self) -> u8 {
        ((self.0 >> 16) & 0xF) as u8
    }
    /// Modo de operacion que indica que la seguridad del ME esta anulada
    /// (4: puente fisico de anulacion, 5: anulacion por mensaje MEI).
    #[must_use]
    pub const fn seguridad_anulada(self) -> bool {
        matches!(self.modo_operacion(), 4 | 5)
    }
}

// ─── Identificacion del chipset ───────────────────────────────────────────────

/// La generacion del chipset de Intel, que decide donde vive cada registro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generacion {
    /// ICH/PCH hasta la serie 9: BIOS_CNTL y GEN_PMCON en el LPC, SPIBAR por RCBA.
    Legado,
    /// PCH serie 100 en adelante: controlador SPI en 00:1f.5 y PMC en 00:1f.2.
    Pch100Mas,
}

/// Los dispositivos de un chipset de Intel que importan a la auditoria.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChipsetIntel {
    /// Generacion deducida.
    pub generacion: Generacion,
    /// Puente anfitrion (00:00.0).
    pub anfitrion: Option<Dispositivo>,
    /// Puente LPC/eSPI (00:1f.0).
    pub lpc: Option<Dispositivo>,
    /// Controlador SPI (00:1f.5). En muchos PCH esta OCULTO por el P2SB.
    pub spi: Option<Dispositivo>,
    /// PMC (00:1f.2), solo en PCH 100+.
    pub pmc: Option<Dispositivo>,
    /// HECI del ME (00:16.0).
    pub me: Option<Dispositivo>,
    /// Controlador SMBus (00:1f.4).
    pub smbus: Option<Dispositivo>,
}

/// Lo que hay en el bus 0 que importe a la auditoria.
///
/// La variante de Intel va en una caja: son seis dispositivos opcionales, y
/// guardarlos en linea haria que cada `Chipset` ocupara eso aunque fuera un
/// `Desconocido` con su motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chipset {
    /// Chipset de Intel, con los dispositivos que se encontraron.
    Intel(Box<ChipsetIntel>),
    /// Chipset de AMD.
    Amd {
        /// Puente anfitrion.
        anfitrion: Dispositivo,
    },
    /// No hay un chipset reconocible, con el motivo.
    Desconocido(String),
}

/// Identifica el chipset a partir de los dispositivos del bus.
#[must_use]
pub fn identificar(dispositivos: &[Dispositivo]) -> Chipset {
    let en = |b: Bdf, fabricante: u16| {
        dispositivos
            .iter()
            .find(|d| d.bdf == b && d.fabricante == fabricante)
            .cloned()
    };
    let anfitrion = en(Bdf::nueva(0, 0, 0), INTEL);
    let lpc = en(Bdf::nueva(0, 0x1f, 0), INTEL)
        .filter(|d| d.clase_base() == 0x06 && d.subclase() == 0x01);
    let spi = en(Bdf::nueva(0, 0x1f, 5), INTEL);
    // El PMC del PCH 100+ se anuncia como controlador de memoria "otro"
    // (clase 0x0580). En los chipsets de legado, 00:1f.2 es el SATA: si se
    // tomara por PMC, GEN_PMCON se leeria del registro de otro dispositivo.
    let pmc = en(Bdf::nueva(0, 0x1f, 2), INTEL).filter(|d| d.clase >> 8 == 0x0580);
    let me = en(Bdf::nueva(0, 0x16, 0), INTEL);
    let smbus = en(Bdf::nueva(0, 0x1f, 4), INTEL).filter(|d| d.clase >> 8 == 0x0C05);

    if anfitrion.is_some() || lpc.is_some() {
        let generacion = if spi.is_some() || pmc.is_some() {
            Generacion::Pch100Mas
        } else {
            Generacion::Legado
        };
        return Chipset::Intel(Box::new(ChipsetIntel {
            generacion,
            anfitrion,
            lpc,
            spi,
            pmc,
            me,
            smbus,
        }));
    }
    if let Some(a) = en(Bdf::nueva(0, 0, 0), AMD) {
        return Chipset::Amd { anfitrion: a };
    }
    let vistos: Vec<String> = dispositivos
        .iter()
        .map(|d| format!("{:04x}:{:04x}", d.fabricante, d.id))
        .collect();
    Chipset::Desconocido(if vistos.is_empty() {
        "no hay ningun dispositivo PCI visible".to_string()
    } else {
        format!(
            "no hay puente anfitrion ni LPC de Intel o AMD en el bus 0; los {} dispositivos \
             PCI visibles son {} — tipico de una maquina virtual, donde el chipset real \
             lo gobierna el hipervisor y no es visible al invitado",
            vistos.len(),
            vistos.join(", ")
        )
    })
}

// ─── Las decisiones ───────────────────────────────────────────────────────────

const CHIPSEC_BIOS_WP: &[&str] = &["common.bios_wp"];
const CHIPSEC_SPI_LOCK: &[&str] = &["common.spi_lock"];
const CHIPSEC_SPI_ACCESS: &[&str] = &["common.spi_access", "common.spi_desc"];
const CHIPSEC_SPI_FDOPSS: &[&str] = &["common.spi_fdopss"];
const CHIPSEC_BIOS_TS: &[&str] = &["common.bios_ts"];
const CHIPSEC_SMM: &[&str] = &["common.smm"];
const CHIPSEC_SMM_DMA: &[&str] = &["common.smm_dma"];
const CHIPSEC_MEMCONFIG: &[&str] = &["common.memconfig", "common.remap"];
const CHIPSEC_BIOS_SMI: &[&str] = &["common.bios_smi"];
const CHIPSEC_ME: &[&str] = &["common.me_mfg_mode"];
const CHIPSEC_SPD: &[&str] = &["common.spd_wd"];

/// HOSTC (configuracion del anfitrion SMBus), en la configuracion de 00:1f.4.
pub const OFF_HOSTC: usize = 0x40;

/// SPD_WD: sin el, se puede reescribir la EEPROM SPD de los modulos de memoria.
///
/// La SPD describe la memoria al firmware en cada arranque. Reescribirla deja la
/// maquina sin arrancar (un ladrillo por la memoria en vez de por la flash), y
/// en algunos modulos es un sitio donde esconder datos que sobreviven a todo.
#[must_use]
pub fn evaluar_spd_wd(hostc: Option<u8>) -> Comprobacion {
    let estado = match hostc {
        None => CheckState::Indeterminado("HOSTC del SMBus no se pudo leer".into()),
        Some(h) if h & 0x10 != 0 => CheckState::Ok,
        Some(h) => CheckState::Fallo(format!(
            "HOSTC={h:#04x}: SPD_WD=0, la EEPROM SPD de los modulos de memoria se puede \
             reescribir por SMBus desde el sistema operativo"
        )),
    };
    exposicion("chipset-spd-escritura", Superficie::Chipset, estado).como_chipsec(CHIPSEC_SPD)
}

fn exposicion(id: &'static str, s: Superficie, e: CheckState) -> Comprobacion {
    Comprobacion::nueva(id, s, Naturaleza::Exposicion, e)
}

/// La proteccion de escritura de la region BIOS: BIOSWE, BLE, SMM_BWP y PRx.
///
/// Sigue la regla de `common.bios_wp`: la region esta protegida si `BLE` y
/// `SMM_BWP` estan puestos, **o** si los PRx con escritura protegida cubren la
/// region BIOS entera y `FLOCKDN` impide borrarlos.
#[must_use]
pub fn evaluar_bios_wp(bc: Option<BiosCntl>, spi: Option<&RegistrosSpi>) -> Comprobacion {
    let Some(bc) = bc else {
        return exposicion(
            "spi-proteccion-escritura",
            Superficie::ProteccionFlash,
            CheckState::Indeterminado("BIOS_CNTL no se pudo leer".into()),
        )
        .como_chipsec(CHIPSEC_BIOS_WP);
    };
    let prx = spi.is_some_and(|s| s.hsfs.flockdn() && s.prx_cubren_bios());
    let estado = if bc.ble() && bc.smm_bwp() {
        CheckState::Ok
    } else if prx {
        // Los PRx los aplica el controlador SPI, por debajo de SMM: aunque BLE
        // falle, la escritura se rechaza en el hardware.
        CheckState::Ok
    } else if bc.bioswe() && !bc.ble() {
        CheckState::Fallo(format!(
            "BIOS_CNTL={:#04x}: BIOSWE=1 y BLE=0, la region BIOS de la flash es \
             escribible desde el sistema operativo ahora mismo, y ningun PRx la cubre",
            bc.0
        ))
    } else if !bc.ble() {
        CheckState::Fallo(format!(
            "BIOS_CNTL={:#04x}: BLE=0, cualquier codigo con privilegio puede poner BIOSWE \
             y escribir la region BIOS sin que SMM se entere, y ningun PRx la cubre",
            bc.0
        ))
    } else {
        CheckState::Fallo(format!(
            "BIOS_CNTL={:#04x}: BLE=1 pero SMM_BWP=0. Queda la ventana entre que el SO \
             pone BIOSWE y el SMI de BLE lo baja: otro nucleo escribe en ella (la \
             carrera publicada como Speed Racer). Ningun PRx cubre la region BIOS",
            bc.0
        ))
    };
    exposicion(
        "spi-proteccion-escritura",
        Superficie::ProteccionFlash,
        estado,
    )
    .como_chipsec(CHIPSEC_BIOS_WP)
}

/// FLOCKDN: sin el, los PRx y FRAP se pueden reprogramar desde el SO.
#[must_use]
pub fn evaluar_flockdn(spi: Option<&RegistrosSpi>) -> Comprobacion {
    let estado = match spi {
        None => CheckState::Indeterminado("los registros SPIBAR no se pudieron leer".into()),
        Some(s) if s.hsfs.flockdn() => CheckState::Ok,
        Some(s) => CheckState::Fallo(format!(
            "HSFS={:#06x}: FLOCKDN=0, los registros de proteccion del controlador SPI \
             (PRx, FRAP) se pueden reprogramar desde el sistema operativo",
            s.hsfs.0
        )),
    };
    exposicion("spi-flockdn", Superficie::ProteccionFlash, estado).como_chipsec(CHIPSEC_SPI_LOCK)
}

/// FRAP: el anfitrion no debe poder escribir el descriptor ni la region del ME.
#[must_use]
pub fn evaluar_frap(spi: Option<&RegistrosSpi>) -> Comprobacion {
    let estado = match spi {
        None => CheckState::Indeterminado("los registros SPIBAR no se pudieron leer".into()),
        Some(s) => {
            let brwa = s.frap.brwa();
            let mut problemas = Vec::new();
            if brwa & 0x01 != 0 {
                problemas.push("el DESCRIPTOR de flash (region 0): quien lo reescribe redefine que region es que y quien puede escribirla");
            }
            if brwa & 0x04 != 0 {
                problemas.push("la region del ME (region 2): firmware que corre por debajo del sistema operativo");
            }
            if problemas.is_empty() {
                CheckState::Ok
            } else {
                CheckState::Fallo(format!(
                    "FRAP={:#010x}: el anfitrion puede escribir {}",
                    s.frap.0,
                    problemas.join("; y ")
                ))
            }
        }
    };
    exposicion("spi-acceso-regiones", Superficie::ProteccionFlash, estado)
        .como_chipsec(CHIPSEC_SPI_ACCESS)
}

/// FDOPSS: el pin de anulacion de seguridad del descriptor.
#[must_use]
pub fn evaluar_fdopss(spi: Option<&RegistrosSpi>) -> Comprobacion {
    let estado = match spi {
        None => CheckState::Indeterminado("los registros SPIBAR no se pudieron leer".into()),
        Some(s) if s.hsfs.fdopss() => CheckState::Ok,
        Some(s) => CheckState::Fallo(format!(
            "HSFS={:#06x}: FDOPSS=0, el puente de anulacion del descriptor esta puesto: \
             las restricciones de acceso por region del descriptor NO se aplican",
            s.hsfs.0
        )),
    };
    exposicion(
        "spi-anulacion-descriptor",
        Superficie::ProteccionFlash,
        estado,
    )
    .como_chipsec(CHIPSEC_SPI_FDOPSS)
}

/// BILD: sin el, se puede cambiar el arranque a otro bloque (Top Swap).
#[must_use]
pub fn evaluar_bild(bc: Option<BiosCntl>) -> Comprobacion {
    let estado = match bc {
        None => CheckState::Indeterminado("BIOS_CNTL no se pudo leer".into()),
        Some(b) if b.bild() => CheckState::Ok,
        Some(b) => CheckState::Fallo(format!(
            "BIOS_CNTL={:#04x}: BILD=0, la seleccion del bloque de arranque (Top Swap y la \
             estrapa BBS) se puede cambiar desde el sistema operativo: el siguiente \
             arranque ejecutaria otro bloque de la flash",
            b.0
        )),
    };
    exposicion("spi-bloqueo-arranque", Superficie::ProteccionFlash, estado)
        .como_chipsec(CHIPSEC_BIOS_TS)
}

/// SMRAMC: D_LCK puesto y D_OPEN a cero.
#[must_use]
pub fn evaluar_smramc(p: &PuenteAnfitrion) -> Comprobacion {
    let estado = match p.smramc {
        None => CheckState::Indeterminado("SMRAMC no se pudo leer".into()),
        Some(s) if s.d_open() => CheckState::Fallo(format!(
            "SMRAMC={:#04x}: D_OPEN=1, SMRAM es visible y escribible fuera de SMM: el \
             sistema operativo puede reescribir el codigo que corre en el modo mas \
             privilegiado de la CPU",
            s.0
        )),
        Some(s) if !s.d_lck() => CheckState::Fallo(format!(
            "SMRAMC={:#04x}: D_LCK=0, la configuracion de SMRAM no esta bloqueada y el \
             sistema operativo puede abrirla",
            s.0
        )),
        Some(_) => CheckState::Ok,
    };
    exposicion("smm-bloqueo-smramc", Superficie::Smm, estado).como_chipsec(CHIPSEC_SMM)
}

/// TSEG frente a DMA: TSEGMB y BGSM bloqueados, y TSEG no vacio.
#[must_use]
pub fn evaluar_tseg(p: &PuenteAnfitrion) -> Comprobacion {
    let (Some(tsegmb), Some(bgsm)) = (p.tsegmb, p.bgsm) else {
        return exposicion(
            "smm-tseg-dma",
            Superficie::Smm,
            CheckState::Indeterminado("TSEGMB o BGSM no se pudieron leer".into()),
        )
        .como_chipsec(CHIPSEC_SMM_DMA);
    };
    let mut problemas = Vec::new();
    if tsegmb & 1 == 0 {
        problemas.push(format!("TSEGMB={tsegmb:#010x} sin bloquear"));
    }
    if bgsm & 1 == 0 {
        problemas.push(format!("BGSM={bgsm:#010x} sin bloquear"));
    }
    let (base, fin) = (p.tseg_base().unwrap_or(0), p.tseg_fin().unwrap_or(0));
    if fin <= base {
        problemas.push(format!(
            "TSEG vacio o invertido ({base:#x}..{fin:#x}): no hay region protegida frente a DMA"
        ));
    }
    let estado = if problemas.is_empty() {
        CheckState::Ok
    } else {
        CheckState::Fallo(format!(
            "{}: un dispositivo con DMA o el sistema operativo pueden mover la frontera \
             de TSEG y alcanzar SMRAM",
            problemas.join("; ")
        ))
    };
    exposicion("smm-tseg-dma", Superficie::Smm, estado).como_chipsec(CHIPSEC_SMM_DMA)
}

/// Los bloqueos del mapa de memoria del puente anfitrion.
#[must_use]
pub fn evaluar_bloqueos_memoria(p: &PuenteAnfitrion) -> Comprobacion {
    let registros: [(&str, Option<u64>); 4] = [
        ("TOLUD", p.tolud.map(u64::from)),
        ("TOUUD", p.touud),
        ("REMAPBASE", p.remapbase),
        ("REMAPLIMIT", p.remaplimit),
    ];
    if registros.iter().all(|(_, v)| v.is_none()) {
        return exposicion(
            "chipset-bloqueos-memoria",
            Superficie::Chipset,
            CheckState::Indeterminado(
                "los registros del mapa de memoria no se pudieron leer".into(),
            ),
        )
        .como_chipsec(CHIPSEC_MEMCONFIG);
    }
    let sin_bloqueo: Vec<String> = registros
        .iter()
        .filter_map(|(n, v)| v.filter(|x| x & 1 == 0).map(|x| format!("{n}={x:#x}")))
        .collect();
    let estado = if sin_bloqueo.is_empty() {
        CheckState::Ok
    } else {
        CheckState::Fallo(format!(
            "registros del mapa de memoria sin bloquear: {}. Moverlos permite \
             solapar memoria de dispositivo con TSEG o con la memoria del sistema",
            sin_bloqueo.join(", ")
        ))
    };
    exposicion("chipset-bloqueos-memoria", Superficie::Chipset, estado)
        .como_chipsec(CHIPSEC_MEMCONFIG)
}

/// SMI_LOCK: sin el, el SO puede desactivar las SMI globales (y con ellas BLE).
#[must_use]
pub fn evaluar_smi_lock(gen_pmcon: Option<u32>) -> Comprobacion {
    let estado = match gen_pmcon {
        None => CheckState::Indeterminado("GEN_PMCON no se pudo leer".into()),
        Some(v) if v & (1 << 4) != 0 => CheckState::Ok,
        Some(v) => CheckState::Fallo(format!(
            "GEN_PMCON={v:#010x}: SMI_LOCK=0, el sistema operativo puede apagar GBL_SMI_EN \
             y con ello todos los SMI, incluido el que hace cumplir BLE"
        )),
    };
    exposicion("chipset-bloqueo-smi", Superficie::Chipset, estado).como_chipsec(CHIPSEC_BIOS_SMI)
}

/// El modo del ME: ni fabricacion ni seguridad anulada.
#[must_use]
pub fn evaluar_me(hfsts1: Option<Hfsts1>) -> Comprobacion {
    let estado = match hfsts1 {
        None => CheckState::Indeterminado("HFSTS1 no se pudo leer".into()),
        Some(h) if h.modo_fabricacion() => CheckState::Fallo(format!(
            "HFSTS1={:#010x}: el ME esta en MODO FABRICACION: las protecciones del \
             firmware del ME y de las regiones de la flash no estan cerradas",
            h.0
        )),
        Some(h) if h.seguridad_anulada() => CheckState::Fallo(format!(
            "HFSTS1={:#010x}: modo de operacion {} del ME, seguridad ANULADA ({})",
            h.0,
            h.modo_operacion(),
            if h.modo_operacion() == 4 {
                "puente fisico de anulacion"
            } else {
                "anulacion por mensaje MEI"
            }
        )),
        Some(_) => CheckState::Ok,
    };
    exposicion("chipset-modo-me", Superficie::Chipset, estado).como_chipsec(CHIPSEC_ME)
}

/// Las comprobaciones de un chipset que no se pudo leer, con el mismo motivo.
///
/// Se emiten todas y no se calla ninguna: el informe tiene que ensenar cada cosa
/// que no se miro, porque el analista compara informes de maquinas distintas y
/// una comprobacion que desaparece se lee como una que paso.
#[must_use]
pub fn todas_sin_chipset(estado: &CheckState) -> Vec<Comprobacion> {
    let c = |id, s, chipsec: &'static [&'static str]| {
        exposicion(id, s, estado.clone()).como_chipsec(chipsec)
    };
    vec![
        c(
            "spi-proteccion-escritura",
            Superficie::ProteccionFlash,
            CHIPSEC_BIOS_WP,
        ),
        c("spi-flockdn", Superficie::ProteccionFlash, CHIPSEC_SPI_LOCK),
        c(
            "spi-acceso-regiones",
            Superficie::ProteccionFlash,
            CHIPSEC_SPI_ACCESS,
        ),
        c(
            "spi-anulacion-descriptor",
            Superficie::ProteccionFlash,
            CHIPSEC_SPI_FDOPSS,
        ),
        c(
            "spi-bloqueo-arranque",
            Superficie::ProteccionFlash,
            CHIPSEC_BIOS_TS,
        ),
        c("smm-bloqueo-smramc", Superficie::Smm, CHIPSEC_SMM),
        c("smm-tseg-dma", Superficie::Smm, CHIPSEC_SMM_DMA),
        c(
            "chipset-bloqueos-memoria",
            Superficie::Chipset,
            CHIPSEC_MEMCONFIG,
        ),
        c("chipset-bloqueo-smi", Superficie::Chipset, CHIPSEC_BIOS_SMI),
        c("chipset-modo-me", Superficie::Chipset, CHIPSEC_ME),
        c("chipset-spd-escritura", Superficie::Chipset, CHIPSEC_SPD),
    ]
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;
    use std::path::PathBuf;

    fn spi(hsfs: u16, frap: u32, bios: (u32, u32), pr: &[(u32, u32, bool)]) -> RegistrosSpi {
        let codificar = |base: u32, limite: u32| (base >> 12) | ((limite >> 12) << 16);
        let mut prs = [Pr(0); NUM_PR];
        for (i, (b, l, wpe)) in pr.iter().enumerate() {
            prs[i] = Pr(codificar(*b, *l) | if *wpe { 1 << 31 } else { 0 });
        }
        RegistrosSpi {
            hsfs: Hsfs(hsfs),
            frap: Frap(frap),
            bios: Rango::de_registro(codificar(bios.0, bios.1)),
            pr: prs,
        }
    }

    const FLOCKDN: u16 = 1 << 15;
    const FDOPSS: u16 = 1 << 13;
    const BIOS: (u32, u32) = (0x0050_0000, 0x00FF_FFFF);

    fn falla(c: &Comprobacion) -> bool {
        c.estado.es_fallo()
    }

    /// La tabla de verdad de `common.bios_wp`, fila a fila.
    #[test]
    fn la_proteccion_de_escritura_sigue_la_tabla_de_verdad_de_bios_wp() {
        // BLE + SMM_BWP: protegido.
        assert!(!falla(&evaluar_bios_wp(Some(BiosCntl(0x22)), None)));
        // BLE sin SMM_BWP y sin PRx: la carrera.
        let c = evaluar_bios_wp(Some(BiosCntl(0x02)), None);
        assert!(falla(&c));
        assert!(format!("{:?}", c.estado).contains("SMM_BWP=0"));
        // BIOSWE a uno y BLE a cero: escribible AHORA.
        let c = evaluar_bios_wp(Some(BiosCntl(0x01)), None);
        assert!(format!("{:?}", c.estado).contains("ahora mismo"));
        // Todo a cero: BLE=0.
        assert!(format!("{:?}", evaluar_bios_wp(Some(BiosCntl(0)), None).estado).contains("BLE=0"));
        // Y el mismo BLE=0 con PRx cubriendo la BIOS entera y FLOCKDN: protegido,
        // porque la escritura la rechaza el controlador SPI.
        let s = spi(FLOCKDN, 0, BIOS, &[(BIOS.0, BIOS.1, true)]);
        assert!(!falla(&evaluar_bios_wp(Some(BiosCntl(0)), Some(&s))));
        // PRx sin FLOCKDN no cuentan: el SO los borra y escribe.
        let s = spi(0, 0, BIOS, &[(BIOS.0, BIOS.1, true)]);
        assert!(falla(&evaluar_bios_wp(Some(BiosCntl(0)), Some(&s))));
    }

    /// Un PR que protege el bloque de arranque deja el resto de la BIOS abierta.
    /// «Hay algun PR activo» no es «la BIOS esta protegida».
    #[test]
    fn los_prx_tienen_que_cubrir_la_bios_entera_no_un_trozo() {
        let parcial = spi(FLOCKDN, 0, BIOS, &[(0x00F0_0000, 0x00FF_FFFF, true)]);
        assert!(!parcial.prx_cubren_bios());
        // Dos PR contiguos que juntos la cubren, en desorden: cubren.
        let dos = spi(
            FLOCKDN,
            0,
            BIOS,
            &[
                (0x00A0_0000, 0x00FF_FFFF, true),
                (0x0050_0000, 0x009F_FFFF, true),
            ],
        );
        assert!(dos.prx_cubren_bios());
        // Con un hueco de 4 KiB entre ellos: no cubren.
        let hueco = spi(
            FLOCKDN,
            0,
            BIOS,
            &[
                (0x0050_0000, 0x009F_EFFF, true),
                (0x00A0_0000, 0x00FF_FFFF, true),
            ],
        );
        assert!(!hueco.prx_cubren_bios());
        // Un PR sin WPE (solo lectura protegida) no protege la escritura.
        let sin_wpe = spi(FLOCKDN, 0, BIOS, &[(BIOS.0, BIOS.1, false)]);
        assert!(!sin_wpe.prx_cubren_bios());
    }

    #[test]
    fn el_formato_de_rango_es_el_de_freg_y_prx() {
        // base 0x500 (x4K), limite 0xFFF (x4K) + 0xFFF.
        let r = Rango::de_registro(0x0FFF_0500);
        assert_eq!(r.base, 0x0050_0000);
        assert_eq!(r.limite, 0x00FF_FFFF);
        assert!(r.usado());
        // Region vacia: base 0x7FFF, limite 0.
        assert!(!Rango::de_registro(0x0000_7FFF).usado());
        let p = Pr(0x8FFF_8500);
        assert!(p.wpe() && p.rpe());
    }

    #[test]
    fn flockdn_fdopss_y_frap_se_decodifican_y_se_juzgan() {
        let bien = spi(FLOCKDN | FDOPSS, 0x0000_0A0B, BIOS, &[]);
        assert!(!falla(&evaluar_flockdn(Some(&bien))));
        assert!(!falla(&evaluar_fdopss(Some(&bien))));
        assert!(
            !falla(&evaluar_frap(Some(&bien))),
            "BRWA=0x0A: BIOS y GbE, legitimo"
        );

        let mal = spi(0, 0x0000_0F0F, BIOS, &[]);
        assert!(falla(&evaluar_flockdn(Some(&mal))));
        assert!(falla(&evaluar_fdopss(Some(&mal))));
        let f = evaluar_frap(Some(&mal));
        let m = format!("{:?}", f.estado);
        assert!(m.contains("DESCRIPTOR") && m.contains("ME"), "{m}");

        for c in [
            evaluar_flockdn(None),
            evaluar_fdopss(None),
            evaluar_frap(None),
        ] {
            assert!(matches!(c.estado, CheckState::Indeterminado(_)));
        }
    }

    #[test]
    fn bild_decide_si_el_bloque_de_arranque_se_puede_cambiar() {
        assert!(!falla(&evaluar_bild(Some(BiosCntl(0xA2)))));
        assert!(falla(&evaluar_bild(Some(BiosCntl(0x22)))));
    }

    fn puente(smramc: u8, tsegmb: u32, bgsm: u32, tolud: u32) -> PuenteAnfitrion {
        let mut c = vec![0u8; 256];
        c[OFF_SMRAMC] = smramc;
        c[OFF_BGSM..OFF_BGSM + 4].copy_from_slice(&bgsm.to_le_bytes());
        c[OFF_TSEGMB..OFF_TSEGMB + 4].copy_from_slice(&tsegmb.to_le_bytes());
        c[OFF_TOLUD..OFF_TOLUD + 4].copy_from_slice(&tolud.to_le_bytes());
        c[OFF_TOUUD..OFF_TOUUD + 8].copy_from_slice(&0x4_6000_0001u64.to_le_bytes());
        c[OFF_REMAPBASE..OFF_REMAPBASE + 8].copy_from_slice(&0x1u64.to_le_bytes());
        c[OFF_REMAPLIMIT..OFF_REMAPLIMIT + 8].copy_from_slice(&0x1u64.to_le_bytes());
        PuenteAnfitrion::de_config(&Config::de_bytes(c))
    }

    #[test]
    fn smramc_bloqueada_y_cerrada_pasa_y_abierta_no() {
        // 0x1A: G_SMRAME, D_LCK, C_BASE_SEG=2.
        assert!(!falla(&evaluar_smramc(&puente(0x1A, 0, 0, 0))));
        let abierta = evaluar_smramc(&puente(0x5A, 0, 0, 0));
        assert!(format!("{:?}", abierta.estado).contains("D_OPEN=1"));
        let sin_lck = evaluar_smramc(&puente(0x0A, 0, 0, 0));
        assert!(format!("{:?}", sin_lck.estado).contains("D_LCK=0"));
    }

    #[test]
    fn tseg_tiene_que_estar_bloqueado_y_no_vacio() {
        let bien = puente(0x1A, 0x7B80_0001, 0x7C00_0001, 0x8000_0001);
        assert!(!falla(&evaluar_tseg(&bien)));
        assert_eq!(bien.tseg_base(), Some(0x7B80_0000));
        assert_eq!(bien.tseg_fin(), Some(0x7C00_0000));
        let sin_lock = puente(0x1A, 0x7B80_0000, 0x7C00_0001, 0x8000_0001);
        assert!(format!("{:?}", evaluar_tseg(&sin_lock).estado).contains("TSEGMB"));
        let vacio = puente(0x1A, 0x7C00_0001, 0x7C00_0001, 0x8000_0001);
        assert!(format!("{:?}", evaluar_tseg(&vacio).estado).contains("vacio"));
        assert!(!falla(&evaluar_bloqueos_memoria(&bien)));
        let tolud_abierto = puente(0x1A, 0x7B80_0001, 0x7C00_0001, 0x8000_0000);
        assert!(format!("{:?}", evaluar_bloqueos_memoria(&tolud_abierto).estado).contains("TOLUD"));
    }

    /// Sin privilegio, sysfs sirve 64 bytes: SMRAMC (0x88) no se leyo, y eso es
    /// INDETERMINADO. Un cero inventado seria «D_LCK=0», una exposicion falsa.
    #[test]
    fn una_configuracion_corta_da_indeterminado_y_no_un_fallo_inventado() {
        let p = PuenteAnfitrion::de_config(&Config::de_bytes(vec![0u8; 64]));
        for c in [
            evaluar_smramc(&p),
            evaluar_tseg(&p),
            evaluar_bloqueos_memoria(&p),
        ] {
            assert!(matches!(c.estado, CheckState::Indeterminado(_)), "{c:?}");
        }
        assert!(matches!(
            evaluar_bios_wp(None, None).estado,
            CheckState::Indeterminado(_)
        ));
    }

    #[test]
    fn el_me_en_fabricacion_o_con_la_seguridad_anulada_es_exposicion() {
        // 0x9000_0245: estado de trabajo normal (5), iniciado, modo 0, bit 4 a cero.
        assert!(!Hfsts1(0x9000_0245).modo_fabricacion());
        assert!(!falla(&evaluar_me(Some(Hfsts1(0x9000_0245)))));
        // El mismo con el bit 4: modo fabricacion.
        assert!(Hfsts1(0x9000_0255).modo_fabricacion());
        assert!(falla(&evaluar_me(Some(Hfsts1(0x0000_0010)))));
        let anulada = evaluar_me(Some(Hfsts1(0x0004_0200)));
        assert!(format!("{:?}", anulada.estado).contains("puente fisico"));
        assert!(falla(&evaluar_smi_lock(Some(0))));
        assert!(!falla(&evaluar_smi_lock(Some(0x10))));
    }

    #[test]
    fn ninguna_decision_de_registros_es_un_compromiso() {
        // Un registro dice que se PODRIA; nunca que alguien lo hizo.
        let s = spi(0, 0xFFFF, BIOS, &[]);
        let p = puente(0x40, 0, 0, 0);
        for c in [
            evaluar_bios_wp(Some(BiosCntl(1)), Some(&s)),
            evaluar_flockdn(Some(&s)),
            evaluar_frap(Some(&s)),
            evaluar_fdopss(Some(&s)),
            evaluar_bild(Some(BiosCntl(0))),
            evaluar_smramc(&p),
            evaluar_tseg(&p),
            evaluar_bloqueos_memoria(&p),
            evaluar_smi_lock(Some(0)),
            evaluar_me(Some(Hfsts1(0x10))),
        ] {
            assert!(c.estado.es_fallo(), "{c:?}");
            assert_eq!(c.naturaleza, Naturaleza::Exposicion, "{}", c.id);
            assert!(!c.chipsec.is_empty(), "{} sin equivalencia declarada", c.id);
        }
    }

    pub(crate) fn dispositivo(bdf: Bdf, fabricante: u16, id: u16, clase: u32) -> Dispositivo {
        Dispositivo {
            bdf,
            fabricante,
            id,
            clase,
            dir: PathBuf::from("/no/existe"),
        }
    }

    #[test]
    fn el_chipset_se_identifica_por_su_sitio_y_su_clase() {
        let pch = vec![
            dispositivo(Bdf::nueva(0, 0, 0), INTEL, 0x9b61, 0x060000),
            dispositivo(Bdf::nueva(0, 0x1f, 0), INTEL, 0x0284, 0x060100),
            dispositivo(Bdf::nueva(0, 0x1f, 2), INTEL, 0x0281, 0x058000),
            dispositivo(Bdf::nueva(0, 0x16, 0), INTEL, 0x02e0, 0x078000),
        ];
        match identificar(&pch) {
            Chipset::Intel(ci) => {
                let ChipsetIntel {
                    generacion,
                    spi,
                    pmc,
                    me,
                    ..
                } = *ci;
                assert_eq!(
                    generacion,
                    Generacion::Pch100Mas,
                    "el PMC delata la serie 100+"
                );
                assert!(spi.is_none(), "SPI oculto por el P2SB");
                assert!(pmc.is_some() && me.is_some());
            }
            otro => panic!("{otro:?}"),
        }
        // Legado: 00:1f.2 es SATA (clase 0x0106), NO un PMC.
        let legado = vec![
            dispositivo(Bdf::nueva(0, 0, 0), INTEL, 0x0c00, 0x060000),
            dispositivo(Bdf::nueva(0, 0x1f, 0), INTEL, 0x8c4e, 0x060100),
            dispositivo(Bdf::nueva(0, 0x1f, 2), INTEL, 0x8c02, 0x010601),
        ];
        match identificar(&legado) {
            Chipset::Intel(ci) => {
                assert_eq!(ci.generacion, Generacion::Legado);
                assert!(ci.pmc.is_none(), "el SATA no es un PMC");
            }
            otro => panic!("{otro:?}"),
        }
        let hyperv = vec![dispositivo(
            Bdf {
                dominio: 0x5582,
                bus: 0,
                dispositivo: 0,
                funcion: 0,
            },
            0x1af4,
            0x1043,
            0x010000,
        )];
        match identificar(&hyperv) {
            Chipset::Desconocido(m) => assert!(m.contains("1af4:1043"), "{m}"),
            otro => panic!("{otro:?}"),
        }
        assert!(matches!(identificar(&[]), Chipset::Desconocido(_)));
    }

    #[test]
    fn sin_chipset_se_emiten_todas_las_comprobaciones_con_su_motivo() {
        let v = todas_sin_chipset(&CheckState::NoAplicable("maquina virtual".into()));
        assert_eq!(v.len(), 11);
        let mut ids: Vec<_> = v.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 11, "ids repetidos");
        assert!(falla(&evaluar_spd_wd(Some(0x01))));
        assert!(!falla(&evaluar_spd_wd(Some(0x11))));
    }
}
