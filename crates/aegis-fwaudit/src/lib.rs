//! # `aegis-fwaudit` — AegisFirmwareAudit: auditoría de firmware, **sólo
//! lectura** (FASE 67)
//!
//! ## Por debajo del sistema operativo
//!
//! Una APT con recursos no se queda en el disco. Implanta en la **placa base**:
//! LoJax en el firmware UEFI, MoonBounce en la ROM SPI, CosmicStrand en el
//! bootkit. Desde ahí sobrevive a formatear el disco, a reinstalar el sistema y a
//! cambiar el disco duro, porque no está en ninguno de los tres.
//!
//! Este módulo audita las dos superficies donde eso se ve:
//!
//! 1. **Las tablas ACPI** que el firmware le entrega al kernel
//!    ([`acpi`], [`wpbt`]). El SO **se las cree**: son la palabra de algo que se
//!    ejecuta antes que él y por debajo de él. El caso extremo es **WPBT**, que
//!    literalmente dice «ejecuta este binario en cada arranque».
//! 2. **El contenido de la ROM SPI** ([`spi`], [`uefi`]): el descriptor de flash
//!    de Intel delimita la región BIOS, dentro viven los volúmenes de firmware, y
//!    dentro de ellos los ficheros FFS que un implante añade o sustituye.
//!
//! ## La regla que gobierna el módulo entero: JAMÁS se escribe
//!
//! Una escritura accidental en la ROM SPI no es un bug: es un **ladrillo**. Deja
//! la máquina sin arrancar y no hay recuperación por software. Un EDR capaz de
//! hacer eso es peor que el malware que busca.
//!
//! Por eso la garantía es estructural y tiene **dos capas independientes**:
//!
//! - El crate lleva `#![forbid(unsafe_code)]` y **todo** su acceso a disco pasa
//!   por [`solo_lectura::LecturaSolo`], un tipo que no expone ninguna operación
//!   de escritura. No es que no se use: es que no existe.
//! - Ese tipo abre siempre con `O_RDONLY`, así que quien prohíbe escribir es el
//!   **kernel**. `tests/solo_lectura.rs` lo **ejerce**: intenta `write`,
//!   `ftruncate` y `pwrite` sobre el descriptor y exige `EBADF` en los tres.
//!
//! Una capa sola no bastaría: `forbid(unsafe_code)` no impide llamar a
//! `File::write`, y `O_RDONLY` no impide un fallo lógico en otra parte.
//!
//! ## Honestidad de validación
//!
//! | Pieza | Aquí | Cómo |
//! |---|---|---|
//! | Parseo de tablas ACPI | **sí** | contra las tablas **reales** del firmware de esta máquina |
//! | Checksum ACPI | **sí** | el de una tabla auténtica tiene que dar cero, y da |
//! | Garantía de sólo lectura | **sí** | ejercida contra el kernel: `write`/`ftruncate`/`pwrite` → `EBADF` |
//! | WPBT, descriptor Intel, volúmenes UEFI, FFS | sí | vectores binarios construidos byte a byte según la especificación |
//! | Decisor de anomalías | sí | y el firmware real de la máquina **no** produce avisos |
//! | **Leer la ROM SPI** | — | esta máquina no la expone (`/sys/class/mtd` no existe); **no aplicable**, que no es lo mismo que «bien» ni que «mal» |
//!
//! Esa última fila es la razón de reutilizar el tri-estado de
//! [`aegis_firmware::report::CheckState`] en vez de un booleano: confundir «no se
//! puede mirar» con «está bien» o con «está mal» son los dos errores que ese
//! enumerado existe para impedir.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod acpi;
pub mod anomalias;
pub mod linea_base;
pub mod solo_lectura;
pub mod spi;
pub mod uefi;
pub mod wpbt;

pub use aegis_firmware::guid::Guid;
pub use aegis_firmware::report::{Check, CheckState};
pub use anomalias::{Anomalia, Severidad};

use linea_base::{LineaBase, Veredicto};

/// Qué se puede auditar en esta máquina.
///
/// Se calcula y se reporta ANTES de auditar, para que el informe distinga «no hay
/// anomalías» de «no se pudo mirar».
#[derive(Debug, Clone, Default)]
pub struct SoporteAuditoria {
    /// Tablas ACPI legibles.
    pub tablas_acpi: usize,
    /// Tablas que estaban pero no se pudieron leer o analizar.
    pub tablas_ilegibles: usize,
    /// Si hay una tabla WPBT.
    pub hay_wpbt: bool,
    /// Dispositivos MTD encontrados.
    pub dispositivos_mtd: Vec<spi::DispositivoMtd>,
    /// Si la ROM SPI es accesible de solo lectura.
    pub rom_accesible: bool,
    /// Por qué no lo es, cuando no lo es.
    pub motivo_sin_rom: String,
}

impl SoporteAuditoria {
    /// Sondea la máquina.
    #[must_use]
    pub fn detectar() -> SoporteAuditoria {
        let tablas = acpi::leer_tablas_del_sistema();
        let dispositivos = spi::enumerar_mtd();
        let motivo = spi::motivo_sin_rom();
        SoporteAuditoria {
            tablas_acpi: tablas.len(),
            tablas_ilegibles: tablas.ilegibles.len(),
            hay_wpbt: tablas.por_firma(b"WPBT").is_some(),
            rom_accesible: dispositivos.iter().any(|d| d.nodo_presente),
            dispositivos_mtd: dispositivos,
            motivo_sin_rom: motivo,
        }
    }

    /// `true` si hay al menos una superficie que auditar.
    #[must_use]
    pub fn algo_que_auditar(&self) -> bool {
        self.tablas_acpi > 0 || self.rom_accesible
    }
}

/// El veredicto completo de una auditoría.
#[derive(Debug, Clone, Default)]
pub struct InformeAuditoria {
    /// Las comprobaciones, con su tri-estado.
    pub checks: Vec<Check>,
    /// Las anomalías encontradas, de más grave a menos.
    pub anomalias: Vec<Anomalia>,
    /// Tablas ACPI examinadas.
    pub tablas_vistas: usize,
    /// Volúmenes de firmware examinados.
    pub volumenes_vistos: usize,
    /// Ficheros FFS examinados.
    pub ficheros_vistos: usize,
    /// Ficheros cuyo GUID no está en la línea base.
    pub ficheros_desconocidos: Vec<(Guid, String)>,
    /// Ficheros cuyo GUID está pero con otro hash: se reescribieron.
    pub ficheros_alterados: Vec<(Guid, String)>,
}

impl InformeAuditoria {
    /// `true` si alguna comprobación falló.
    #[must_use]
    pub fn comprometido(&self) -> bool {
        self.checks.iter().any(|c| c.estado.es_fallo())
    }

    /// La peor severidad encontrada.
    #[must_use]
    pub fn peor_severidad(&self) -> Option<Severidad> {
        self.anomalias.iter().map(|a| a.severidad).max()
    }

    /// Las comprobaciones que fallaron.
    #[must_use]
    pub fn fallos(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.estado.es_fallo()).collect()
    }
}

/// Audita las tablas ACPI de esta máquina.
///
/// Es la parte que **siempre** se puede hacer: `/sys/firmware/acpi/tables` está
/// en cualquier máquina con ACPI y no necesita más privilegio que leer.
#[must_use]
pub fn auditar_acpi() -> InformeAuditoria {
    let tablas = acpi::leer_tablas_del_sistema();
    let mut informe = InformeAuditoria {
        tablas_vistas: tablas.len(),
        anomalias: anomalias::auditar_conjunto(&tablas),
        ..Default::default()
    };

    if tablas.is_empty() {
        informe.checks.push(Check::new(
            "acpi-tablas",
            CheckState::NoAplicable(format!(
                "esta maquina no expone tablas ACPI en {}",
                acpi::DIR_TABLAS
            )),
        ));
        return informe;
    }

    let graves: Vec<&Anomalia> = informe
        .anomalias
        .iter()
        .filter(|a| a.severidad >= Severidad::Sospechosa)
        .collect();
    let estado = if graves.is_empty() {
        CheckState::Ok
    } else {
        CheckState::Fallo(
            graves
                .iter()
                .map(|a| format!("{} ({})", a.codigo, a.sujeto))
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    informe.checks.push(Check::new("acpi-tablas", estado));

    // La WPBT lleva su propia comprobacion: su presencia es un HECHO que el
    // analista quiere ver aunque no sea un fallo, y meterla dentro del check
    // general la haria invisible.
    let estado_wpbt = match tablas.por_firma(b"WPBT") {
        None => CheckState::Ok,
        Some(_) => {
            let criticas: Vec<&Anomalia> = informe
                .anomalias
                .iter()
                .filter(|a| a.codigo.starts_with("wpbt-") && a.severidad >= Severidad::Sospechosa)
                .collect();
            if criticas.is_empty() {
                CheckState::Indeterminado(
                    "hay una WPBT sin indicios de ataque: el firmware ejecuta un binario \
                     en cada arranque, lo cual es un mecanismo legitimo de fabricante y \
                     tambien la persistencia mas limpia que existe. Conviene identificar \
                     el binario"
                        .to_string(),
                )
            } else {
                CheckState::Fallo(
                    criticas
                        .iter()
                        .map(|a| a.detalle.clone())
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
        }
    };
    informe.checks.push(Check::new("acpi-wpbt", estado_wpbt));
    informe
}

/// Audita una imagen de ROM ya leída, contra una línea base.
///
/// Se toma la imagen en memoria y no una ruta a propósito: así la misma función
/// sirve para la ROM viva de la máquina y para un volcado que el analista trae de
/// otro equipo, sin duplicar el decisor.
#[must_use]
pub fn auditar_rom(imagen: &[u8], base: &LineaBase) -> InformeAuditoria {
    let mut informe = InformeAuditoria::default();

    // El descriptor delimita la region BIOS. Sin el se puede seguir, buscando
    // volumenes en toda la imagen, pero se DICE: buscar por fuerza bruta
    // encuentra coincidencias dentro de la region ME y de datos comprimidos.
    let (inicio, fin, con_descriptor) = match spi::decodificar_descriptor(imagen) {
        Ok(d) => match d.bios() {
            Some(b) => (b.base as u64, b.limite as u64 + 1, true),
            None => (0, imagen.len() as u64, false),
        },
        Err(_) => (0, imagen.len() as u64, false),
    };
    if !con_descriptor {
        informe.checks.push(Check::new(
            "spi-descriptor",
            CheckState::Indeterminado(
                "no se pudo delimitar la region BIOS con el descriptor de flash; se \
                 recorre la imagen entera y puede haber volumenes de la region ME"
                    .to_string(),
            ),
        ));
    } else {
        informe
            .checks
            .push(Check::new("spi-descriptor", CheckState::Ok));
    }

    let volumenes = uefi::localizar_volumenes(imagen, inicio, fin);
    informe.volumenes_vistos = volumenes.len();

    for v in &volumenes {
        if !v.checksum_ok {
            informe.anomalias.push(Anomalia::nueva(
                "fv-checksum-invalido",
                Severidad::Sospechosa,
                format!("volumen @{:#x}", v.offset),
                "el checksum de 16 bits de la cabecera del volumen no cuadra",
            ));
        }
        for f in uefi::recorrer_ficheros(imagen, v) {
            informe.ficheros_vistos += 1;
            match base.clasificar(&f.guid, &f.sha256) {
                Veredicto::Conocido(_) | Veredicto::SinBase => {}
                Veredicto::Desconocido => {
                    informe.ficheros_desconocidos.push((f.guid, f.sha256_hex()));
                }
                Veredicto::Alterado { esperado } => {
                    informe.ficheros_alterados.push((f.guid, f.sha256_hex()));
                    informe.anomalias.push(Anomalia::nueva(
                        "ffs-alterado",
                        Severidad::Critica,
                        f.guid.hyphenated(),
                        format!(
                            "el modulo '{esperado}' esta en el firmware con un hash \
                             distinto del conocido: fue reescrito"
                        ),
                    ));
                }
                Veredicto::Revocado(nombre) => {
                    informe.anomalias.push(Anomalia::nueva(
                        "ffs-revocado",
                        Severidad::Critica,
                        f.guid.hyphenated(),
                        format!("coincide con el implante conocido '{nombre}'"),
                    ));
                }
            }
        }
    }

    let estado = if base.vacia() {
        CheckState::Indeterminado(
            "no hay linea base cargada: se puede recorrer el firmware pero no decir \
             si su contenido es el que deberia"
                .to_string(),
        )
    } else if informe
        .anomalias
        .iter()
        .any(|a| a.severidad >= Severidad::Critica)
    {
        CheckState::Fallo(format!(
            "{} fichero(s) alterados o revocados",
            informe.ficheros_alterados.len()
        ))
    } else {
        CheckState::Ok
    };
    informe.checks.push(Check::new("spi-ficheros", estado));

    informe.anomalias.sort_by(|a, b| {
        b.severidad
            .cmp(&a.severidad)
            .then(a.codigo.cmp(b.codigo))
            .then(a.sujeto.cmp(&b.sujeto))
    });
    informe
}

/// La auditoría completa de esta máquina: ACPI siempre, y ROM SPI si la hay.
#[must_use]
pub fn auditar(base: &LineaBase) -> InformeAuditoria {
    let mut informe = auditar_acpi();

    match spi::abrir_rom() {
        Err(_) => {
            // NO APLICABLE, que no es ni «bien» ni «mal». Es el caso normal.
            informe.checks.push(Check::new(
                "spi-rom",
                CheckState::NoAplicable(spi::motivo_sin_rom()),
            ));
        }
        Ok(lector) => {
            let tope = usize::try_from(lector.tamano()).unwrap_or(0).max(1);
            match lector.leer_todo(tope) {
                Err(e) => {
                    informe.checks.push(Check::new(
                        "spi-rom",
                        CheckState::Indeterminado(format!("la ROM existe pero no se leyo: {e}")),
                    ));
                }
                Ok(imagen) => {
                    informe.checks.push(Check::new("spi-rom", CheckState::Ok));
                    let rom = auditar_rom(&imagen, base);
                    informe.checks.extend(rom.checks);
                    informe.anomalias.extend(rom.anomalias);
                    informe.volumenes_vistos = rom.volumenes_vistos;
                    informe.ficheros_vistos = rom.ficheros_vistos;
                    informe.ficheros_desconocidos = rom.ficheros_desconocidos;
                    informe.ficheros_alterados = rom.ficheros_alterados;
                }
            }
        }
    }
    informe
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_soporte_de_esta_maquina_se_declara_con_su_motivo() {
        let s = SoporteAuditoria::detectar();
        eprintln!(
            "tablas ACPI: {} (ilegibles {}), WPBT: {}, ROM SPI: {} — {}",
            s.tablas_acpi, s.tablas_ilegibles, s.hay_wpbt, s.rom_accesible, s.motivo_sin_rom
        );
        assert!(!s.motivo_sin_rom.is_empty(), "el motivo tiene que decirse");
        if !s.rom_accesible {
            assert!(
                s.motivo_sin_rom.contains("no existe") || s.motivo_sin_rom.contains("no hay"),
                "el motivo tiene que explicar POR QUE: {}",
                s.motivo_sin_rom
            );
        }
    }

    /// LA AUDITORIA REAL DE ESTA MAQUINA. Sus tablas ACPI se leen de verdad, y
    /// el veredicto tiene que ser limpio: si no lo fuera, o la maquina esta
    /// comprometida o el decisor esta mal calibrado — y lo segundo significa una
    /// alerta critica en cada endpoint del cliente el primer dia.
    #[test]
    fn la_auditoria_real_de_esta_maquina_es_limpia_y_declara_lo_que_no_pudo_mirar() {
        let informe = auditar(&LineaBase::default());
        for c in &informe.checks {
            eprintln!("  {:<16} {:?}", c.nombre, c.estado);
        }
        assert!(
            !informe.comprometido(),
            "el firmware de esta maquina no deberia dar fallos: {:#?}",
            informe.fallos()
        );
        // Y la ROM SPI tiene que salir como NO APLICABLE, no como Ok ni como
        // Fallo: no se pudo mirar, y eso es lo que hay que decir.
        let rom = informe
            .checks
            .iter()
            .find(|c| c.nombre == "spi-rom")
            .expect("la comprobacion de ROM tiene que estar siempre");
        match &rom.estado {
            CheckState::NoAplicable(m) => {
                assert!(!m.is_empty(), "el motivo no puede estar vacio");
            }
            CheckState::Ok => eprintln!("esta maquina SI expone la ROM SPI"),
            otro => panic!("estado inesperado para la ROM: {otro:?}"),
        }
    }

    #[test]
    fn una_rom_con_un_modulo_alterado_se_detecta() {
        use crate::uefi::pruebas::{ffs, volumen};

        let bueno = ffs([0xAA; 16], 7, 0xF8, b"modulo legitimo");
        let hash_bueno = uefi::hash_canonico(&bueno);
        let base = LineaBase::analizar(&format!(
            "version 1\nffs {} {} DxeCore\n",
            Guid([0xAA; 16]).hyphenated(),
            hash_bueno
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .expect("base valida");

        // La misma ROM, pero con el modulo reescrito.
        let malo = ffs([0xAA; 16], 7, 0xF8, b"modulo IMPLANTADO");
        let img = volumen(&[malo], 8192);

        let informe = auditar_rom(&img, &base);
        assert_eq!(informe.ficheros_vistos, 1);
        assert_eq!(informe.ficheros_alterados.len(), 1);
        assert!(informe.comprometido(), "{:#?}", informe.checks);
        assert!(informe.anomalias.iter().any(|a| a.codigo == "ffs-alterado"));
    }

    #[test]
    fn una_rom_intacta_contra_su_linea_base_no_da_fallos() {
        use crate::uefi::pruebas::{ffs, volumen};

        let f = ffs([0xBB; 16], 7, 0xF8, b"modulo legitimo");
        let hash = uefi::hash_canonico(&f);
        let base = LineaBase::analizar(&format!(
            "version 1\nffs {} {} DxeCore\n",
            Guid([0xBB; 16]).hyphenated(),
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
        .expect("base");
        let img = volumen(&[f], 8192);

        let informe = auditar_rom(&img, &base);
        assert_eq!(informe.ficheros_vistos, 1);
        assert!(informe.ficheros_alterados.is_empty());
        assert!(informe.ficheros_desconocidos.is_empty());
        assert!(!informe.comprometido());
    }

    /// SIN LINEA BASE no se afirma nada. Es la diferencia entre «el firmware esta
    /// bien» y «no tengo con que compararlo», y el tri-estado la conserva.
    #[test]
    fn sin_linea_base_el_veredicto_es_indeterminado_no_correcto() {
        use crate::uefi::pruebas::{ffs, volumen};
        let img = volumen(&[ffs([0xCC; 16], 7, 0xF8, b"algo")], 8192);
        let informe = auditar_rom(&img, &LineaBase::default());
        let c = informe
            .checks
            .iter()
            .find(|c| c.nombre == "spi-ficheros")
            .expect("check");
        assert!(
            matches!(c.estado, CheckState::Indeterminado(_)),
            "sin base no se puede decir Ok: {:?}",
            c.estado
        );
        assert!(!informe.comprometido());
    }
}
