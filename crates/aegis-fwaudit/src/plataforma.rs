//! La auditoria de plataforma completa: todas las superficies, en un informe.
//!
//! # Que junta y como lo junta
//!
//! Cada modulo del crate decide sobre su superficie. Este no decide nada: lee de
//! la maquina (sysfs, `/proc`, `/dev`, `/lib/firmware`), pasa lo leido al
//! decisor que corresponde y junta las comprobaciones. Lo unico que anade es la
//! **localizacion** de cada registro en su chipset —BIOS_CNTL vive en el puente
//! LPC en unos y en el controlador SPI en otros— y los motivos especificos de lo
//! que no se pudo mirar.
//!
//! # Raices parametrizables
//!
//! Todo se lee a partir de [`Raices`]. En produccion son las del sistema; en las
//! pruebas, un arbol sintetico con el formato real de sysfs. Es un doble de
//! FRONTERA (el disco), no de decision: los decisores son los mismos.
//!
//! # Un informe que no se calla nada
//!
//! Cada comprobacion sale siempre, con su estado. Una maquina virtual sin
//! chipset visible produce once comprobaciones de chipset «no aplicables» con el
//! motivo, no cero comprobaciones: comparar el informe de dos maquinas tiene que
//! ensenar que no se miro en cada una, y una linea que desaparece se lee como una
//! que paso.

use std::path::{Path, PathBuf};

use aegis_firmware::eventlog::parse;
use aegis_firmware::report::CheckState;
use aegis_firmware::tcg::HashAlg;

use crate::acpi;
use crate::aml;
use crate::arranque::{self, Cadena, Fuente};
use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::linea_base::LineaBase;
use crate::microcodigo;
use crate::mitigaciones;
use crate::msr::{self, DispositivosDelSistema, LectorFisico};
use crate::opcion_rom;
use crate::pci::{self, Config, Dispositivo};
use crate::registros::{
    self, BiosCntl, Chipset, ChipsetIntel, Frap, Generacion, Hfsts1, Hsfs, Pr, PuenteAnfitrion,
    Rango, RegistrosSpi,
};
use crate::solo_lectura::LecturaSolo;
use crate::spi;
use crate::tablas;
use crate::variables;

/// De donde se lee la maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raices {
    /// `/sys`.
    pub sys: PathBuf,
    /// `/proc`.
    pub proc_: PathBuf,
    /// `/dev`.
    pub dev: PathBuf,
    /// `/lib/firmware`.
    pub firmware: PathBuf,
}

impl Raices {
    /// Las del sistema.
    #[must_use]
    pub fn del_sistema() -> Raices {
        Raices {
            sys: PathBuf::from("/sys"),
            proc_: PathBuf::from("/proc"),
            dev: PathBuf::from("/dev"),
            firmware: PathBuf::from("/lib/firmware"),
        }
    }

    /// Todas bajo un directorio (para un arbol sintetico).
    #[must_use]
    pub fn bajo(raiz: &Path) -> Raices {
        Raices {
            sys: raiz.join("sys"),
            proc_: raiz.join("proc"),
            dev: raiz.join("dev"),
            firmware: raiz.join("lib/firmware"),
        }
    }

    fn es_el_sistema(&self) -> bool {
        *self == Raices::del_sistema()
    }
}

/// El informe de plataforma.
#[derive(Debug, Clone, Default)]
pub struct InformePlataforma {
    /// Todas las comprobaciones, en orden estable.
    pub comprobaciones: Vec<Comprobacion>,
    /// El chipset encontrado, en una frase.
    pub chipset: String,
    /// Si la maquina es virtual.
    pub virtualizada: bool,
    /// El analisis AML.
    pub aml: aml::Espacio,
    /// La cadena de arranque, si habia registro.
    pub cadena: Option<Cadena>,
    /// Las vulnerabilidades de CPU que publica el kernel.
    pub vulnerabilidades: Vec<mitigaciones::Vulnerabilidad>,
    /// Tablas ACPI leidas.
    pub tablas_acpi: usize,
    /// Dispositivos PCI vistos.
    pub dispositivos_pci: usize,
    /// Option ROMs que anuncia sysfs y que no se leen (exigen escribir).
    pub opciones_rom_anunciadas: usize,
    /// Option ROMs extraidas de la imagen de la ROM.
    pub opciones_rom: Vec<opcion_rom::ImagenRom>,
}

impl InformePlataforma {
    /// Si alguna comprobacion de COMPROMISO fallo.
    #[must_use]
    pub fn comprometido(&self) -> bool {
        self.comprobaciones
            .iter()
            .any(|c| c.falla_como(Naturaleza::Compromiso))
    }

    /// Las comprobaciones de compromiso que fallaron.
    #[must_use]
    pub fn compromisos(&self) -> Vec<&Comprobacion> {
        self.comprobaciones
            .iter()
            .filter(|c| c.falla_como(Naturaleza::Compromiso))
            .collect()
    }

    /// Las exposiciones: puertas abiertas, para el informe de postura.
    #[must_use]
    pub fn exposiciones(&self) -> Vec<&Comprobacion> {
        self.comprobaciones
            .iter()
            .filter(|c| c.falla_como(Naturaleza::Exposicion))
            .collect()
    }

    /// Una comprobacion por identificador.
    #[must_use]
    pub fn por_id(&self, id: &str) -> Option<&Comprobacion> {
        self.comprobaciones.iter().find(|c| c.id == id)
    }

    /// Cuantas se pudieron mirar de cada naturaleza: (miradas, total).
    #[must_use]
    pub fn cobertura(&self, n: Naturaleza) -> (usize, usize) {
        let de: Vec<_> = self
            .comprobaciones
            .iter()
            .filter(|c| c.naturaleza == n)
            .collect();
        (de.iter().filter(|c| c.se_miro()).count(), de.len())
    }
}

fn leer_config(d: &Option<Dispositivo>) -> Option<Config> {
    d.as_ref().and_then(|d| pci::leer_config(d).ok())
}

/// Lee los registros SPIBAR de memoria fisica.
fn leer_spibar(l: &dyn LectorFisico, base: u64, off_pr0: u64) -> Result<RegistrosSpi, String> {
    let r = |o: u64| l.leer_u32(base + o);
    let mut pr = [Pr(0); registros::NUM_PR];
    for (i, p) in pr.iter_mut().enumerate() {
        *p = Pr(r(off_pr0 + 4 * i as u64)?);
    }
    Ok(RegistrosSpi {
        hsfs: Hsfs(r(registros::OFF_HSFS)? as u16),
        frap: Frap(r(registros::OFF_FRAP)?),
        bios: Rango::de_registro(r(registros::OFF_FREG1)?),
        pr,
    })
}

/// Sustituye el motivo generico de «no se pudo leer» por el especifico.
fn con_motivo(mut c: Comprobacion, motivo: &Option<String>) -> Comprobacion {
    if let (CheckState::Indeterminado(_), Some(m)) = (&c.estado, motivo) {
        c.estado = CheckState::Indeterminado(m.clone());
    }
    c
}

/// Las comprobaciones de chipset, SMM por registros y MSR.
fn auditar_chipset(
    dispositivos: &Result<Vec<Dispositivo>, pci::SinPci>,
    lector: &dyn LectorFisico,
    motivo_sin_msr: Option<String>,
    informe: &mut InformePlataforma,
) {
    let chipset = match dispositivos {
        Err(pci::SinPci(m)) => Chipset::Desconocido(m.clone()),
        Ok(d) => registros::identificar(d),
    };
    let mut tseg: Option<(u64, u64)> = None;
    match &chipset {
        Chipset::Desconocido(m) => {
            informe.chipset = format!("sin chipset reconocible: {m}");
            informe
                .comprobaciones
                .extend(registros::todas_sin_chipset(&CheckState::NoAplicable(
                    m.clone(),
                )));
        }
        Chipset::Amd { anfitrion } => {
            let m = format!(
                "plataforma AMD ({}): las protecciones de su flash (ROM Protect del puente LPC, \
                 SPI_RestrictedCmd) y su SMM (TSEG en MSR de AMD) no se cubren en esta fase",
                anfitrion.nombre()
            );
            informe.chipset = m.clone();
            informe
                .comprobaciones
                .extend(registros::todas_sin_chipset(&CheckState::Indeterminado(m)));
        }
        Chipset::Intel(ci) => {
            let ChipsetIntel {
                generacion,
                anfitrion,
                lpc,
                spi,
                pmc,
                me,
                smbus,
            } = ci.as_ref();
            informe.chipset = format!(
                "Intel, {} (anfitrion {}, LPC {}, SPI {})",
                match generacion {
                    Generacion::Legado => "ICH/PCH de legado",
                    Generacion::Pch100Mas => "PCH serie 100 o posterior",
                },
                anfitrion.as_ref().map_or("—".into(), Dispositivo::nombre),
                lpc.as_ref().map_or("—".into(), Dispositivo::nombre),
                spi.as_ref().map_or("oculto".into(), Dispositivo::nombre),
            );
            let cfg_lpc = leer_config(lpc);
            let cfg_spi = leer_config(spi);
            // Donde vive BIOS_CNTL y como se llega a SPIBAR depende de la generacion.
            let (cfg_bios, spibar, off_pr0, motivo_spi) = match generacion {
                Generacion::Pch100Mas => match &cfg_spi {
                    Some(c) => (Some(c.clone()), c.bar_memoria(0), registros::OFF_PR0_PCH100, None),
                    None => (
                        None,
                        None,
                        registros::OFF_PR0_PCH100,
                        Some(
                            "el controlador SPI (00:1f.5) esta OCULTO por el P2SB: destaparlo exige \
                             escribir en la configuracion del P2SB, que es lo que hace CHIPSEC, y \
                             aqui no se escribe"
                                .to_string(),
                        ),
                    ),
                },
                Generacion::Legado => {
                    let rcba = cfg_lpc.as_ref().and_then(|c| c.u32(0xF0));
                    let base = rcba.filter(|r| r & 1 != 0).map(|r| u64::from(r & 0xFFFF_C000) + 0x3800);
                    (cfg_lpc.clone(), base, registros::OFF_PR0_LEGADO, None)
                }
            };
            let bc = cfg_bios
                .as_ref()
                .and_then(|c| c.u8(registros::OFF_BIOS_CNTL))
                .map(BiosCntl);
            let (regs, motivo_spi) = match spibar {
                Some(b) => match leer_spibar(lector, b, off_pr0) {
                    Ok(r) => (Some(r), None),
                    Err(e) => (None, Some(format!("SPIBAR en {b:#x} no se pudo leer: {e}"))),
                },
                None => (
                    None,
                    motivo_spi.or_else(|| Some("no se conoce la base de SPIBAR".into())),
                ),
            };
            let motivo_bc = if bc.is_none() {
                motivo_spi.clone().or_else(|| {
                    Some(
                        "BIOS_CNTL (0xDC) no se pudo leer: sin privilegio, sysfs solo sirve 64 B de \
                         configuracion"
                            .into(),
                    )
                })
            } else {
                None
            };
            let puente = leer_config(anfitrion)
                .map(|c| PuenteAnfitrion::de_config(&c))
                .unwrap_or(PuenteAnfitrion {
                    smramc: None,
                    tsegmb: None,
                    bgsm: None,
                    tolud: None,
                    touud: None,
                    remapbase: None,
                    remaplimit: None,
                });
            if let (Some(b), Some(f)) = (puente.tseg_base(), puente.tseg_fin()) {
                tseg = Some((b, f));
            }
            let gen_pmcon = match generacion {
                Generacion::Pch100Mas => leer_config(pmc),
                Generacion::Legado => cfg_lpc,
            }
            .and_then(|c| c.u32(registros::OFF_GEN_PMCON));
            let hfsts1 = leer_config(me)
                .and_then(|c| c.u32(registros::OFF_HFSTS1))
                .map(Hfsts1);
            let hostc = leer_config(smbus).and_then(|c| c.u8(registros::OFF_HOSTC));
            informe.comprobaciones.extend([
                con_motivo(registros::evaluar_bios_wp(bc, regs.as_ref()), &motivo_bc),
                con_motivo(registros::evaluar_flockdn(regs.as_ref()), &motivo_spi),
                con_motivo(registros::evaluar_frap(regs.as_ref()), &motivo_spi),
                con_motivo(registros::evaluar_fdopss(regs.as_ref()), &motivo_spi),
                con_motivo(registros::evaluar_bild(bc), &motivo_bc),
                registros::evaluar_smramc(&puente),
                registros::evaluar_tseg(&puente),
                registros::evaluar_bloqueos_memoria(&puente),
                registros::evaluar_smi_lock(gen_pmcon),
                registros::evaluar_me(hfsts1),
                registros::evaluar_spd_wd(hostc),
            ]);
        }
    }

    // MSR: sin modulo msr, NO APLICABLE con el motivo; no se carga nada.
    let mut de_msr = msr::evaluar(lector, tseg);
    let smram = match (&chipset, tseg) {
        (Chipset::Intel { .. }, Some((base, _))) => msr::evaluar_smram_ilegible(lector, Some(base)),
        _ => {
            let mut c = msr::evaluar_smram_ilegible(lector, None);
            c.estado = CheckState::NoAplicable(
                "no hay un puente anfitrion de Intel del que sacar TSEG".into(),
            );
            c
        }
    };
    if let Some(m) = motivo_sin_msr {
        for c in &mut de_msr {
            c.estado = CheckState::NoAplicable(m.clone());
        }
    }
    informe.comprobaciones.extend(de_msr);
    informe.comprobaciones.push(smram);
}

/// La auditoria de plataforma.
///
/// `imagen_rom` es una imagen de la ROM SPI que trae el analista (un volcado de
/// otro equipo, o la de esta maquina leida por otra via); sin ella se intenta la
/// ROM viva, y si tampoco hay, se dice.
#[must_use]
pub fn auditar_plataforma(
    r: &Raices,
    base: &LineaBase,
    imagen_rom: Option<&[u8]>,
) -> InformePlataforma {
    let mut informe = InformePlataforma::default();

    // ── CPU: la bandera de virtualizacion condiciona varias decisiones ──
    let cpuinfo = LecturaSolo::abrir(&r.proc_.join("cpuinfo"))
        .and_then(|l| l.leer_todo(4 * 1024 * 1024))
        .map_err(|e| format!("/proc/cpuinfo no se pudo leer: {e}"))
        .and_then(|b| microcodigo::analizar_cpuinfo(&String::from_utf8_lossy(&b)));
    informe.virtualizada = cpuinfo.as_ref().is_ok_and(|c| c.virtualizada);

    // ── ACPI: la auditoria de la FASE 67 y las tablas tipadas ──
    let tablas = acpi::leer_tablas_de(&r.sys.join("firmware/acpi/tables"));
    informe.tablas_acpi = tablas.len();
    let acpi_inf = crate::auditar_acpi_de(&tablas);
    for c in acpi_inf.checks {
        informe.comprobaciones.push(Comprobacion::nueva(
            c.nombre,
            Superficie::Acpi,
            Naturaleza::Compromiso,
            c.estado,
        ));
    }
    let tipadas = tablas::decodificar(&tablas);
    let iommu_activos = std::fs::read_dir(r.sys.join("class/iommu"))
        .map(|e| e.count())
        .unwrap_or(0);
    let hay_acpi = !tablas.is_empty();
    informe.comprobaciones.push(tablas::evaluar_iommu(
        &tipadas,
        iommu_activos,
        informe.virtualizada,
        hay_acpi,
    ));
    informe.comprobaciones.push(tablas::evaluar_wsmt(
        &tipadas,
        informe.virtualizada,
        hay_acpi,
    ));

    // ── AML ──
    informe.aml = aml::analizar_conjunto(&tablas, tipadas.fadt.map(|f| f.smi_cmd));
    informe
        .comprobaciones
        .extend(aml::evaluar(&informe.aml, base));

    // ── ROM SPI (FASE 67) y option ROMs de dentro ──
    let imagen_viva: Option<Vec<u8>> = if imagen_rom.is_some() || !r.es_el_sistema() {
        None
    } else {
        spi::abrir_rom().ok().and_then(|l| {
            let tope = usize::try_from(l.tamano()).unwrap_or(0).max(1);
            l.leer_todo(tope).ok()
        })
    };
    let imagen = imagen_rom.or(imagen_viva.as_deref());
    match imagen {
        Some(img) => {
            informe.comprobaciones.push(Comprobacion::nueva(
                "spi-rom",
                Superficie::RomSpi,
                Naturaleza::Compromiso,
                CheckState::Ok,
            ));
            for c in crate::auditar_rom(img, base).checks {
                informe.comprobaciones.push(Comprobacion::nueva(
                    c.nombre,
                    Superficie::RomSpi,
                    Naturaleza::Compromiso,
                    c.estado,
                ));
            }
            informe.opciones_rom = opcion_rom::extraer(img);
        }
        None => {
            let motivo = if r.es_el_sistema() {
                spi::motivo_sin_rom()
            } else {
                "no se aporto imagen de la ROM".to_string()
            };
            informe.comprobaciones.push(Comprobacion::nueva(
                "spi-rom",
                Superficie::RomSpi,
                Naturaleza::Compromiso,
                CheckState::NoAplicable(motivo),
            ));
        }
    }
    informe.opciones_rom_anunciadas = opcion_rom::anunciadas_en_sysfs(&r.sys);
    let motivo_oprom = format!(
        "no hay imagen de la ROM de la que extraerlas, y el fichero `rom` de sysfs ({} dispositivo(s) \
         lo anuncian) solo se lee despues de ESCRIBIR en el para habilitarlo: no se hace",
        informe.opciones_rom_anunciadas
    );
    informe.comprobaciones.push(opcion_rom::evaluar(
        imagen.map(|_| informe.opciones_rom.as_slice()),
        &motivo_oprom,
        base,
    ));

    // ── Chipset, SMM y MSR ──
    let dispositivos = pci::enumerar(&r.sys);
    informe.dispositivos_pci = dispositivos.as_ref().map(Vec::len).unwrap_or(0);
    let lector = DispositivosDelSistema::nuevo(&r.dev);
    let sin_msr = lector.motivo_sin_msr();
    auditar_chipset(&dispositivos, &lector, sin_msr.clone(), &mut informe);

    // ── CPU: mitigaciones y microcodigo ──
    let vulns = mitigaciones::leer(&r.sys);
    informe.comprobaciones.push(mitigaciones::evaluar(&vulns));
    informe.vulnerabilidades = vulns.unwrap_or_default();
    // IA32_PLATFORM_ID (0x17), bits 52:50: desempata entre microcodigos de Intel.
    let id_plataforma = if sin_msr.is_none() {
        lector
            .leer_msr(0, 0x17)
            .ok()
            .map(|v| ((v >> 50) & 0x7) as u32)
    } else {
        None
    };
    let referencia = cpuinfo
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|c| microcodigo::referencia(c, &r.firmware, id_plataforma));
    informe
        .comprobaciones
        .push(microcodigo::evaluar(&cpuinfo, &referencia));

    // ── Variables UEFI ──
    let almacen = variables::leer(&r.sys.join(variables::DIR_EFIVARS));
    informe.comprobaciones.extend(variables::evaluar(&almacen));

    // ── Cadena de arranque ──
    let ruta_log = r.sys.join(arranque::RUTA_LOG);
    let fuente = match LecturaSolo::abrir(&ruta_log) {
        Err(_) => Fuente::NoAplica(format!(
            "{} no existe: sin TPM, o el firmware no entrego registro de arranque medido",
            ruta_log.display()
        )),
        Ok(l) => match l
            .leer_todo(arranque::TOPE_LOG)
            .map_err(|e| e.to_string())
            .and_then(|b| parse(&b).map_err(|e| e.to_string()))
        {
            Ok(log) => Fuente::Registro(log),
            Err(e) => Fuente::Ilegible(format!("el registro de arranque no se pudo analizar: {e}")),
        },
    };
    let pcrs = if r.es_el_sistema() {
        aegis_firmware::tpm::leer_banco_sysfs(HashAlg::Sha256).ok()
    } else {
        None
    };
    let (cadena, de_cadena) =
        arranque::evaluar(&fuente, pcrs.as_ref(), almacen.as_ref().ok(), base);
    informe.cadena = cadena;
    informe.comprobaciones.extend(de_cadena);

    // Orden estable: por superficie y por identificador.
    informe
        .comprobaciones
        .sort_by(|a, b| a.superficie.cmp(&b.superficie).then(a.id.cmp(b.id)));
    informe
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    fn arbol(nombre: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("aegis-plataforma-{nombre}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("dir");
        d
    }

    /// Un arbol VACIO: cada comprobacion tiene que salir, y ninguna como fallo
    /// inventado. No mirar nada no es encontrar nada.
    #[test]
    fn una_maquina_sin_nada_que_mirar_no_da_ni_un_fallo_ni_un_verde_de_mentira() {
        let d = arbol("vacio");
        let inf = auditar_plataforma(&Raices::bajo(&d), &LineaBase::default(), None);
        for c in &inf.comprobaciones {
            eprintln!("{}", c.linea());
        }
        assert!(!inf.comprometido());
        assert!(
            inf.exposiciones().is_empty(),
            "sin datos no se puede afirmar ninguna exposicion: {:#?}",
            inf.exposiciones()
        );
        let (miradas_comp, total_comp) = inf.cobertura(Naturaleza::Compromiso);
        // ACPI, AML (2), ROM SPI, option ROM, entradas de arranque y las cuatro de
        // la cadena: diez como minimo, aunque no haya nada que mirar.
        assert!(total_comp >= 10, "{total_comp}");
        assert!(miradas_comp < total_comp);
        let mut ids: Vec<_> = inf.comprobaciones.iter().map(|c| c.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "identificadores repetidos");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Todos los identificadores que el informe puede producir.
    pub(crate) fn ids_posibles() -> Vec<&'static str> {
        let d = arbol("ids");
        let inf = auditar_plataforma(&Raices::bajo(&d), &LineaBase::default(), None);
        let _ = std::fs::remove_dir_all(&d);
        inf.comprobaciones.iter().map(|c| c.id).collect()
    }

    /// LA PLATAFORMA REAL DE ESTA MAQUINA, entera.
    #[test]
    fn la_plataforma_real_de_esta_maquina_se_audita_entera() {
        let inicio = std::time::Instant::now();
        let inf = auditar_plataforma(&Raices::del_sistema(), &LineaBase::default(), None);
        eprintln!("chipset: {}", inf.chipset);
        eprintln!(
            "virtualizada: {}  tablas ACPI: {}  PCI: {}  metodos AML: {}",
            inf.virtualizada,
            inf.tablas_acpi,
            inf.dispositivos_pci,
            inf.aml.metodos.len()
        );
        for c in &inf.comprobaciones {
            eprintln!("  {}", c.linea());
        }
        let (mc, tc) = inf.cobertura(Naturaleza::Compromiso);
        let (me, te) = inf.cobertura(Naturaleza::Exposicion);
        eprintln!(
            "compromiso: {mc}/{tc} miradas; exposicion: {me}/{te} miradas; {} exposicion(es); en {:?}",
            inf.exposiciones().len(),
            inicio.elapsed()
        );
        assert!(
            !inf.comprometido(),
            "el firmware de esta maquina no deberia dar compromisos: {:#?}",
            inf.compromisos()
        );
    }
}
