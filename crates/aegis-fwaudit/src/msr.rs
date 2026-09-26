//! Lecturas por debajo de sysfs: MMIO por `/dev/mem` y MSR por `/dev/cpu/N/msr`,
//! **ambas de solo lectura**, y los registros especificos de modelo que deciden
//! SMM, la depuracion y Boot Guard.
//!
//! # Por que estas dos vias, y con que cuidado
//!
//! Los PRx y FLOCKDN viven en la memoria del controlador SPI (SPIBAR), que no es
//! espacio de configuracion: solo se alcanzan leyendo memoria fisica. Y SMRR,
//! IA32_FEATURE_CONTROL o el estado de Boot Guard son MSR: solo se alcanzan con
//! `rdmsr`, que el kernel expone por el modulo `msr`.
//!
//! Las dos rutas son de las mas peligrosas que existen en un sistema:
//! `/dev/mem` abierto para escritura reescribe cualquier byte de la memoria
//! fisica, y `/dev/cpu/N/msr` abierto para escritura cambia la configuracion de
//! la CPU. Por eso las dos pasan por [`crate::solo_lectura::LecturaSolo`], que
//! abre `O_RDONLY` y no tiene operacion de escritura, y la prueba de integracion
//! intenta escribir por el descriptor real y exige que el kernel lo rechace.
//!
//! # Lo que se hace NO cargando nada
//!
//! Si `/dev/cpu` no existe es que el modulo `msr` no esta cargado. Cargarlo
//! (`modprobe msr`) es cambiar el nucleo de la maquina del cliente: no se hace.
//! Las comprobaciones de MSR salen **no aplicables con ese motivo**, que es
//! verdad, en vez de ejercer un privilegio que nadie ha concedido.
//!
//! # La escritura no se puede expresar
//!
//! [`LectorFisico`] sabe leer memoria fisica y MSR y **nada mas**: no hay
//! `wrmsr` ni escritura de memoria en el rasgo, asi que no hay configuracion,
//! error ni atacante que llegue a pedirla por aqui (`E0599`):
//!
//! ```compile_fail,E0599
//! use aegis_fwaudit::msr::{DispositivosDelSistema, LectorFisico};
//! let l = DispositivosDelSistema::nuevo(std::path::Path::new("/dev"));
//! l.escribir_msr(0, 0x3A, 0);
//! ```
//!
//! ```compile_fail,E0599
//! use aegis_fwaudit::msr::{DispositivosDelSistema, LectorFisico};
//! let l = DispositivosDelSistema::nuevo(std::path::Path::new("/dev"));
//! l.escribir_u32(0xFED1_F800, 0);
//! ```
//!
//! # El doble de frontera
//!
//! [`LectorFisico`] es una FRONTERA (el hardware), no una decision: su doble de
//! pruebas ([`MemoriaDeMentira`]) devuelve los valores que dicen los datasheets y
//! todo lo que decide que significan corre igual que en produccion.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aegis_firmware::report::CheckState;

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::solo_lectura::LecturaSolo;

// ─── La frontera ──────────────────────────────────────────────────────────────

/// Quien sabe leer memoria fisica y MSR.
pub trait LectorFisico {
    /// Lee 4 bytes de memoria fisica alineados.
    ///
    /// # Errores
    /// Un texto con el motivo si la direccion no se puede leer.
    fn leer_u32(&self, direccion: u64) -> Result<u32, String>;

    /// Lee `n` bytes de memoria fisica.
    ///
    /// # Errores
    /// Un texto con el motivo.
    fn leer_bytes(&self, direccion: u64, n: usize) -> Result<Vec<u8>, String>;

    /// Lee un MSR en una CPU logica.
    ///
    /// # Errores
    /// Un texto con el motivo (sin modulo `msr`, sin privilegio, MSR inexistente).
    fn leer_msr(&self, cpu: u32, msr: u32) -> Result<u64, String>;

    /// Las CPU logicas donde se pueden leer MSR.
    fn cpus(&self) -> Vec<u32>;
}

/// El lector real: `/dev/mem` y `/dev/cpu/N/msr`, siempre de solo lectura.
#[derive(Debug, Clone)]
pub struct DispositivosDelSistema {
    raiz_dev: PathBuf,
}

impl DispositivosDelSistema {
    /// Lector sobre una raiz de `/dev`.
    #[must_use]
    pub fn nuevo(raiz_dev: &Path) -> DispositivosDelSistema {
        DispositivosDelSistema {
            raiz_dev: raiz_dev.to_path_buf(),
        }
    }

    /// Por que no hay MSR, si no los hay.
    #[must_use]
    pub fn motivo_sin_msr(&self) -> Option<String> {
        let dir = self.raiz_dev.join("cpu");
        if !dir.is_dir() {
            return Some(format!(
                "{} no existe: el modulo `msr` del kernel no esta cargado. Cargarlo \
                 es cambiar el nucleo de la maquina del cliente, y no se hace",
                dir.display()
            ));
        }
        if self.cpus().is_empty() {
            return Some(format!(
                "{} existe pero no hay ningun nodo msr",
                dir.display()
            ));
        }
        None
    }
}

impl LectorFisico for DispositivosDelSistema {
    fn leer_u32(&self, direccion: u64) -> Result<u32, String> {
        let b = self.leer_bytes(direccion, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn leer_bytes(&self, direccion: u64, n: usize) -> Result<Vec<u8>, String> {
        let ruta = self.raiz_dev.join("mem");
        let l = LecturaSolo::abrir(&ruta).map_err(|e| e.to_string())?;
        let b = l.leer(direccion, n).map_err(|e| {
            // Con CONFIG_IO_STRICT_DEVMEM el kernel niega la lectura de un MMIO
            // que ya reclamo un controlador (intel-spi, por ejemplo). Decirlo es
            // la diferencia entre «no se pudo» y «esta mal».
            format!("{e} (el kernel puede negar /dev/mem sobre MMIO reclamado por un controlador)")
        })?;
        if b.len() != n {
            return Err(format!(
                "lectura corta de {direccion:#x}: {} de {n} B",
                b.len()
            ));
        }
        Ok(b)
    }

    fn leer_msr(&self, cpu: u32, msr: u32) -> Result<u64, String> {
        let ruta = self.raiz_dev.join(format!("cpu/{cpu}/msr"));
        let l = LecturaSolo::abrir(&ruta).map_err(|e| e.to_string())?;
        // El desplazamiento de la lectura ES el numero de MSR: asi lo define el
        // controlador `msr` del kernel.
        let b = l
            .leer(u64::from(msr), 8)
            .map_err(|e| format!("MSR {msr:#x} en la CPU {cpu}: {e}"))?;
        let arr: [u8; 8] = b
            .try_into()
            .map_err(|_| format!("MSR {msr:#x}: lectura corta"))?;
        Ok(u64::from_le_bytes(arr))
    }

    fn cpus(&self) -> Vec<u32> {
        let Ok(e) = std::fs::read_dir(self.raiz_dev.join("cpu")) else {
            return Vec::new();
        };
        let mut v: Vec<u32> = e
            .flatten()
            .filter_map(|x| x.file_name().to_str()?.parse().ok())
            .filter(|n: &u32| self.raiz_dev.join(format!("cpu/{n}/msr")).exists())
            .collect();
        v.sort_unstable();
        v
    }
}

/// Doble de FRONTERA: memoria fisica y MSR con valores fijados por la prueba.
#[derive(Debug, Clone, Default)]
pub struct MemoriaDeMentira {
    /// Palabras de memoria fisica por direccion.
    pub memoria: BTreeMap<u64, u8>,
    /// MSR por (cpu, numero).
    pub msrs: BTreeMap<(u32, u32), u64>,
    /// CPU presentes.
    pub num_cpus: u32,
}

impl MemoriaDeMentira {
    /// Escribe una palabra en la memoria del doble (no en ningun hardware).
    pub fn poner_u32(&mut self, dir: u64, v: u32) {
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            self.memoria.insert(dir + i as u64, *b);
        }
    }
}

impl LectorFisico for MemoriaDeMentira {
    fn leer_u32(&self, direccion: u64) -> Result<u32, String> {
        let b = self.leer_bytes(direccion, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn leer_bytes(&self, direccion: u64, n: usize) -> Result<Vec<u8>, String> {
        (0..n as u64)
            .map(|i| {
                self.memoria
                    .get(&(direccion + i))
                    .copied()
                    .ok_or_else(|| format!("{:#x} no mapeada", direccion + i))
            })
            .collect()
    }
    fn leer_msr(&self, cpu: u32, msr: u32) -> Result<u64, String> {
        self.msrs
            .get(&(cpu, msr))
            .copied()
            .ok_or_else(|| format!("MSR {msr:#x} no existe en la CPU {cpu}"))
    }
    fn cpus(&self) -> Vec<u32> {
        (0..self.num_cpus).collect()
    }
}

// ─── Los MSR ──────────────────────────────────────────────────────────────────

/// IA32_FEATURE_CONTROL.
pub const IA32_FEATURE_CONTROL: u32 = 0x3A;
/// BOOT_GUARD_SACM_INFO: el estado de Intel Boot Guard.
pub const BOOT_GUARD_SACM_INFO: u32 = 0x13A;
/// IA32_SMRR_PHYSBASE.
pub const IA32_SMRR_PHYSBASE: u32 = 0x1F2;
/// IA32_SMRR_PHYSMASK.
pub const IA32_SMRR_PHYSMASK: u32 = 0x1F3;
/// MSR_LT_LOCK_MEMORY.
pub const LT_LOCK_MEMORY: u32 = 0x2E7;
/// MSR_SMM_FEATURE_CONTROL.
pub const SMM_FEATURE_CONTROL: u32 = 0x4E0;
/// IA32_DEBUG_INTERFACE.
pub const IA32_DEBUG_INTERFACE: u32 = 0xC80;

/// Lo que dice SMRR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smrr {
    /// Base de la region.
    pub base: u64,
    /// Mascara.
    pub mascara: u64,
    /// Bit 11 de PHYSMASK: el rango esta activo.
    pub valido: bool,
    /// Tipo de memoria (bits 7:0 de PHYSBASE).
    pub tipo: u8,
}

impl Smrr {
    /// Decodifica el par de MSR.
    #[must_use]
    pub const fn de_msr(physbase: u64, physmask: u64) -> Smrr {
        Smrr {
            base: physbase & 0xFFFF_F000,
            mascara: physmask & 0xFFFF_F000,
            valido: physmask & (1 << 11) != 0,
            tipo: (physbase & 0xFF) as u8,
        }
    }

    /// Tamano del rango: la mascara es `!(tamano - 1)` dentro de los 32 bits.
    #[must_use]
    pub const fn tamano(&self) -> u64 {
        if self.mascara == 0 {
            return 0;
        }
        (!self.mascara & 0xFFFF_FFFF) + 1
    }

    /// Si cubre `[base, fin)`.
    #[must_use]
    pub const fn cubre(&self, base: u64, fin: u64) -> bool {
        self.valido && self.base <= base && self.base + self.tamano() >= fin
    }
}

/// Lee un MSR en todas las CPU y exige que valga lo mismo en todas.
///
/// # Por que en todas
///
/// Un bloqueo de CPU se aplica **por nucleo**. Un firmware que olvida bloquear
/// IA32_FEATURE_CONTROL en los nucleos que arranca tarde (los AP) deja una
/// puerta en cada uno de ellos, y mirar solo la CPU 0 da un verde falso. Es lo
/// que hace `common.ia32cfg` y es lo que se hace aqui.
///
/// # Errores
/// El motivo si no hay CPU legibles o alguna falla.
pub fn msr_en_todas(l: &dyn LectorFisico, msr: u32) -> Result<Vec<(u32, u64)>, String> {
    let cpus = l.cpus();
    if cpus.is_empty() {
        return Err("no hay ninguna CPU con MSR legible".into());
    }
    cpus.iter()
        .map(|c| l.leer_msr(*c, msr).map(|v| (*c, v)))
        .collect()
}

fn exposicion(
    id: &'static str,
    s: Superficie,
    e: CheckState,
    chipsec: &'static [&'static str],
) -> Comprobacion {
    Comprobacion::nueva(id, s, Naturaleza::Exposicion, e).como_chipsec(chipsec)
}

/// Aplica un criterio a un MSR en todas las CPU, y dice CUALES fallan.
fn por_cpu(
    l: &dyn LectorFisico,
    msr: u32,
    bien: impl Fn(u64) -> bool,
    que_falla: &str,
) -> CheckState {
    match msr_en_todas(l, msr) {
        Err(m) => CheckState::Indeterminado(m),
        Ok(v) => {
            let malas: Vec<String> = v
                .iter()
                .filter(|(_, x)| !bien(*x))
                .map(|(c, x)| format!("CPU{c}={x:#x}"))
                .collect();
            if malas.is_empty() {
                CheckState::Ok
            } else {
                CheckState::Fallo(format!(
                    "MSR {msr:#x}: {que_falla} en {} de {} CPU ({})",
                    malas.len(),
                    v.len(),
                    malas.join(", ")
                ))
            }
        }
    }
}

/// Las comprobaciones basadas en MSR.
///
/// `tseg` es el rango de TSEG que dio el puente anfitrion, si se pudo leer, para
/// comprobar que SMRR lo cubre de verdad y no un rango cualquiera.
#[must_use]
pub fn evaluar(l: &dyn LectorFisico, tseg: Option<(u64, u64)>) -> Vec<Comprobacion> {
    let mut v = vec![
        exposicion(
            "cpu-bloqueo-feature-control",
            Superficie::Chipset,
            por_cpu(l, IA32_FEATURE_CONTROL, |x| x & 1 != 0, "IA32_FEATURE_CONTROL sin su bit de bloqueo: la configuracion de VMX/SMX se puede cambiar"),
            &["common.ia32cfg"],
        ),
        exposicion(
            "cpu-depuracion",
            Superficie::Chipset,
            por_cpu(
                l,
                IA32_DEBUG_INTERFACE,
                // Bit 0: la depuracion por sonda (DCI/JTAG) esta habilitada. Bit 30:
                // bloqueo. Bien = deshabilitada y bloqueada.
                |x| x & 1 == 0 && x & (1 << 30) != 0,
                "la interfaz de depuracion por sonda esta habilitada o sin bloquear: un cable USB da control por debajo de todo",
            ),
            &["common.debugenabled"],
        ),
        exposicion(
            "cpu-bloqueo-memoria-lt",
            Superficie::Chipset,
            por_cpu(l, LT_LOCK_MEMORY, |x| x & 1 != 0, "LT_LOCK_MEMORY sin bloquear"),
            &["common.memlock"],
        ),
        exposicion(
            "smm-codigo-fuera-de-smram",
            Superficie::Smm,
            por_cpu(
                l,
                SMM_FEATURE_CONTROL,
                // Bit 0: bloqueo. Bit 2: SMM_Code_Chk_En, SMM no puede ejecutar
                // codigo fuera de SMRAM.
                |x| x & 1 != 0 && x & (1 << 2) != 0,
                "SMM puede ejecutar codigo fuera de SMRAM (SMM_Code_Chk_En=0) o la politica no esta bloqueada: el ataque clasico de «callout» de SMM",
            ),
            &["common.smm_code_chk"],
        ),
    ];

    // SMRR: valido, en todas las CPU igual, y cubriendo TSEG.
    let smrr = match (
        msr_en_todas(l, IA32_SMRR_PHYSBASE),
        msr_en_todas(l, IA32_SMRR_PHYSMASK),
    ) {
        (Ok(b), Ok(m)) => {
            let rangos: Vec<Smrr> = b
                .iter()
                .zip(m.iter())
                .map(|((_, base), (_, mask))| Smrr::de_msr(*base, *mask))
                .collect();
            let primero = rangos[0];
            if rangos.iter().any(|r| *r != primero) {
                CheckState::Fallo(
                    "SMRR no vale lo mismo en todas las CPU: el nucleo sin SMRR cachea SMRAM y \
                     la deja al alcance del ataque de envenenamiento de cache"
                        .into(),
                )
            } else if !primero.valido {
                CheckState::Fallo(
                    "SMRR no esta activo (bit V de IA32_SMRR_PHYSMASK a cero): SMRAM no esta \
                     protegida frente al envenenamiento de cache"
                        .into(),
                )
            } else if let Some((base, fin)) = tseg {
                if primero.cubre(base, fin) {
                    CheckState::Ok
                } else {
                    CheckState::Fallo(format!(
                        "SMRR cubre {:#x}+{:#x} pero TSEG es {base:#x}..{fin:#x}: una parte de \
                         SMRAM queda fuera de la proteccion",
                        primero.base,
                        primero.tamano()
                    ))
                }
            } else {
                CheckState::Ok
            }
        }
        (Err(e), _) | (_, Err(e)) => CheckState::Indeterminado(e),
    };
    v.push(exposicion(
        "smm-smrr",
        Superficie::Smm,
        smrr,
        &["common.smrr"],
    ));

    // Boot Guard: no es un bloqueo, es la raiz de verificacion del firmware. Sin
    // el, la primera instruccion que ejecuta la CPU es la que haya en la flash,
    // sea cual sea. CHIPSEC no tiene modulo para esto.
    let bg = match msr_en_todas(l, BOOT_GUARD_SACM_INFO) {
        Err(e) => CheckState::Indeterminado(e),
        Ok(v) => {
            let x = v[0].1;
            // Bit 5: arranque VERIFICADO. Bit 6: arranque MEDIDO por la ACM.
            let verificado = x & (1 << 5) != 0;
            let medido = x & (1 << 6) != 0;
            if verificado {
                CheckState::Ok
            } else {
                CheckState::Fallo(format!(
                    "BOOT_GUARD_SACM_INFO={x:#x}: Boot Guard no verifica el bloque de arranque{}. \
                     La CPU ejecuta lo que haya en la flash sin comprobar su firma",
                    if medido { " (solo lo mide)" } else { "" }
                ))
            }
        }
    };
    v.push(exposicion("cpu-boot-guard", Superficie::Chipset, bg, &[]));
    v
}

/// SMRAM tiene que ser ilegible desde el sistema operativo.
///
/// Con SMRR y TSEG bien puestos, leer SMRAM fuera de SMM devuelve todo unos:
/// el controlador de memoria aborta el acceso. Si devuelve otra cosa, el SO esta
/// leyendo el codigo de SMM, y lo que se puede leer asi casi siempre se puede
/// escribir por la misma via. Se leen solo 64 bytes del principio de TSEG, y
/// solo se leen: es exactamente lo que haria un atacante para comprobarlo, sin
/// ninguno de los pasos que haria despues.
#[must_use]
pub fn evaluar_smram_ilegible(l: &dyn LectorFisico, tseg_base: Option<u64>) -> Comprobacion {
    let estado = match tseg_base {
        None => CheckState::Indeterminado("no se conoce la base de TSEG".into()),
        Some(base) => match l.leer_bytes(base, 64) {
            Err(e) => CheckState::Indeterminado(format!("no se pudo leer {base:#x}: {e}")),
            Ok(b) if b.iter().all(|x| *x == 0xFF) => CheckState::Ok,
            Ok(b) => CheckState::Fallo(format!(
                "leer SMRAM ({base:#x}) desde el sistema operativo devuelve datos \
                 ({:02x?}...), no el patron de acceso abortado: SMRAM no esta protegida",
                &b[..8]
            )),
        },
    };
    exposicion(
        "smm-smram-ilegible",
        Superficie::Smm,
        estado,
        &["common.smrr"],
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn doble(cpus: u32, msrs: &[(u32, u64)]) -> MemoriaDeMentira {
        let mut d = MemoriaDeMentira {
            num_cpus: cpus,
            ..Default::default()
        };
        for c in 0..cpus {
            for (m, v) in msrs {
                d.msrs.insert((c, *m), *v);
            }
        }
        d
    }

    fn por_id<'a>(v: &'a [Comprobacion], id: &str) -> &'a Comprobacion {
        v.iter().find(|c| c.id == id).expect(id)
    }

    const SANO: &[(u32, u64)] = &[
        (IA32_FEATURE_CONTROL, 0x5),
        (IA32_DEBUG_INTERFACE, 1 << 30),
        (LT_LOCK_MEMORY, 1),
        (SMM_FEATURE_CONTROL, 0x5),
        (IA32_SMRR_PHYSBASE, 0x7B80_0006),
        // Mascara de 8 MiB con V puesto.
        (IA32_SMRR_PHYSMASK, 0xFF80_0800),
        (BOOT_GUARD_SACM_INFO, 0x0000_0071),
    ];

    #[test]
    fn una_plataforma_sana_pasa_todo_lo_de_msr() {
        let d = doble(4, SANO);
        let v = evaluar(&d, Some((0x7B80_0000, 0x7C00_0000)));
        for c in &v {
            assert_eq!(c.estado, CheckState::Ok, "{}", c.linea());
        }
    }

    /// UN SOLO NUCLEO SIN BLOQUEAR ES UNA PUERTA. Mirar solo la CPU 0 da un verde
    /// falso cuando el firmware olvida los procesadores que arranca despues.
    #[test]
    fn un_solo_nucleo_sin_bloqueo_hace_fallar_y_se_nombra() {
        let mut d = doble(4, SANO);
        d.msrs.insert((3, IA32_FEATURE_CONTROL), 0x4);
        let v = evaluar(&d, None);
        let c = por_id(&v, "cpu-bloqueo-feature-control");
        let m = format!("{:?}", c.estado);
        assert!(m.contains("1 de 4") && m.contains("CPU3"), "{m}");
    }

    #[test]
    fn smrr_tiene_que_estar_activo_ser_igual_y_cubrir_tseg() {
        let d = doble(2, SANO);
        let s = Smrr::de_msr(0x7B80_0006, 0xFF80_0800);
        assert_eq!(s.tamano(), 0x80_0000);
        assert!(s.cubre(0x7B80_0000, 0x7C00_0000));
        assert_eq!(
            por_id(&evaluar(&d, Some((0x7B80_0000, 0x7C00_0000))), "smm-smrr").estado,
            CheckState::Ok
        );
        // TSEG mas grande que SMRR: una parte de SMRAM fuera.
        let grande = evaluar(&d, Some((0x7B00_0000, 0x7C00_0000)));
        assert!(format!("{:?}", por_id(&grande, "smm-smrr").estado).contains("fuera"));
        // Sin el bit V.
        let mut sin_v = doble(2, SANO);
        sin_v.msrs.insert((0, IA32_SMRR_PHYSMASK), 0xFF80_0000);
        sin_v.msrs.insert((1, IA32_SMRR_PHYSMASK), 0xFF80_0000);
        assert!(
            format!("{:?}", por_id(&evaluar(&sin_v, None), "smm-smrr").estado)
                .contains("no esta activo")
        );
        // Distinto entre nucleos.
        let mut distinto = doble(2, SANO);
        distinto.msrs.insert((1, IA32_SMRR_PHYSMASK), 0xFF80_0000);
        assert!(
            format!("{:?}", por_id(&evaluar(&distinto, None), "smm-smrr").estado)
                .contains("todas las CPU")
        );
    }

    #[test]
    fn boot_guard_sin_verificacion_es_exposicion_y_dice_si_al_menos_mide() {
        let mut d = doble(1, SANO);
        d.msrs.insert((0, BOOT_GUARD_SACM_INFO), 1 << 6);
        let c = evaluar(&d, None);
        let bg = por_id(&c, "cpu-boot-guard");
        assert!(format!("{:?}", bg.estado).contains("solo lo mide"));
        assert_eq!(bg.naturaleza, Naturaleza::Exposicion);
    }

    #[test]
    fn sin_msr_todo_es_indeterminado_con_su_motivo_no_verde() {
        let d = MemoriaDeMentira::default();
        for c in evaluar(&d, None) {
            assert!(
                matches!(c.estado, CheckState::Indeterminado(_)),
                "{}",
                c.linea()
            );
        }
    }

    #[test]
    fn smram_legible_desde_el_so_es_un_fallo_y_abortada_no() {
        let mut d = MemoriaDeMentira::default();
        for i in 0..16 {
            d.poner_u32(0x7B80_0000 + i * 4, 0xFFFF_FFFF);
        }
        assert_eq!(
            evaluar_smram_ilegible(&d, Some(0x7B80_0000)).estado,
            CheckState::Ok
        );
        d.poner_u32(0x7B80_0010, 0x9090_90CC);
        let c = evaluar_smram_ilegible(&d, Some(0x7B80_0000));
        assert!(format!("{:?}", c.estado).contains("no esta protegida"));
        assert!(matches!(
            evaluar_smram_ilegible(&d, None).estado,
            CheckState::Indeterminado(_)
        ));
    }

    /// ESTA MAQUINA: si no hay modulo msr, se DICE por que, y no se carga.
    #[test]
    fn en_esta_maquina_el_motivo_sin_msr_es_explicito() {
        let s = DispositivosDelSistema::nuevo(Path::new("/dev"));
        match s.motivo_sin_msr() {
            Some(m) => {
                eprintln!("MSR no aplicable aqui: {m}");
                assert!(m.contains("msr"));
                for c in evaluar(&s, None) {
                    assert!(
                        !c.estado.es_fallo(),
                        "sin MSR no se puede afirmar un fallo: {}",
                        c.linea()
                    );
                }
            }
            None => {
                let v = evaluar(&s, None);
                for c in &v {
                    eprintln!("  {}", c.linea());
                }
            }
        }
    }
}
