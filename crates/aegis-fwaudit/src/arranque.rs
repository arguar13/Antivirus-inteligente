//! La cadena de arranque medido, eslabon a eslabon y **explicada**.
//!
//! # Lo que ya habia y lo que faltaba
//!
//! La FASE 26 reproduce el event log y comprueba que los PCR del TPM salen de el.
//! Eso demuestra que los **resumenes** del registro son los que se extendieron.
//! No dice que significan, ni demuestra que el **texto** de cada evento —«se
//! midio `SecureBoot = 1`», «se ejecuto `\EFI\ubuntu\shimx64.efi`»— sea verdad.
//!
//! Un atacante que controla el sistema puede reescribir el texto de un evento
//! dejando su resumen intacto: la reproduccion de PCR sigue cuadrando, y quien
//! lea el registro ve un arranque limpio. Para una familia de eventos la
//! especificacion TCG obliga a que el resumen sea el hash del propio texto del
//! evento (separadores, acciones, variables de configuracion), y ahi **se puede
//! comprobar**. Eso es lo que anade este modulo:
//!
//! 1. Cada medida, de PCR 0 al cargador, con su explicacion legible.
//! 2. Para los eventos autodescriptivos, la comprobacion de que el resumen es el
//!    hash de lo que dice. Un fallo ahi no tiene explicacion benigna.
//! 3. El resumen de la cadena: version del firmware, Secure Boot tal y como se
//!    midio, cargadores ejecutados, linea de ordenes del kernel, y las option ROM
//!    que el firmware ejecuto (PCR 2), contra la linea base.
//!
//! # Lo que NO se puede comprobar, y se dice
//!
//! Los eventos que miden **codigo** (firmware, aplicaciones EFI, controladores)
//! llevan el hash del binario, no del texto: su texto no se puede verificar sin
//! el binario. Se marcan `NoVerificable` con el motivo, que no es lo mismo que
//! «verificado».

use std::collections::BTreeSet;

use aegis_firmware::eventlog::{EventLog, LogEvent};
use aegis_firmware::guid::Guid;
use aegis_firmware::pcr::PcrBank;
use aegis_firmware::report::{check_pcr_log, contrastar_arranque, CheckState};
use aegis_firmware::tcg::HashAlg;
use aegis_firmware::uefi::parse_signature_lists;
use sha2::{Digest, Sha256};

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::linea_base::LineaBase;
use crate::ruta_dispositivo::{decodificar, utf16, Ruta};
use crate::variables::{analizar_opcion, Almacen};

/// Ruta del event log, relativa a la raiz de sysfs.
pub const RUTA_LOG: &str = "kernel/security/tpm0/binary_bios_measurements";
/// Tope de lo que se lee del event log.
pub const TOPE_LOG: usize = 16 * 1024 * 1024;

/// Nombre de un tipo de evento TCG.
#[must_use]
pub fn nombre_tipo(t: u32) -> &'static str {
    match t {
        0x0000_0000 => "EV_PREBOOT_CERT",
        0x0000_0001 => "EV_POST_CODE",
        0x0000_0003 => "EV_NO_ACTION",
        0x0000_0004 => "EV_SEPARATOR",
        0x0000_0005 => "EV_ACTION",
        0x0000_0006 => "EV_EVENT_TAG",
        0x0000_0007 => "EV_S_CRTM_CONTENTS",
        0x0000_0008 => "EV_S_CRTM_VERSION",
        0x0000_0009 => "EV_CPU_MICROCODE",
        0x0000_000A => "EV_PLATFORM_CONFIG_FLAGS",
        0x0000_000B => "EV_TABLE_OF_DEVICES",
        0x0000_000D => "EV_IPL",
        0x0000_000E => "EV_IPL_PARTITION_DATA",
        0x0000_000F => "EV_NONHOST_CODE",
        0x0000_0010 => "EV_NONHOST_CONFIG",
        0x0000_0011 => "EV_NONHOST_INFO",
        0x0000_0012 => "EV_OMIT_BOOT_DEVICE_EVENTS",
        0x8000_0001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x8000_0002 => "EV_EFI_VARIABLE_BOOT",
        0x8000_0003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x8000_0004 => "EV_EFI_BOOT_SERVICES_DRIVER",
        0x8000_0005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x8000_0006 => "EV_EFI_GPT_EVENT",
        0x8000_0007 => "EV_EFI_ACTION",
        0x8000_0008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x8000_0009 => "EV_EFI_HANDOFF_TABLES",
        0x8000_000A => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0x8000_000B => "EV_EFI_HANDOFF_TABLES2",
        0x8000_000C => "EV_EFI_VARIABLE_BOOT2",
        0x8000_0010 => "EV_EFI_HCRTM_EVENT",
        0x8000_00E0 => "EV_EFI_VARIABLE_AUTHORITY",
        0x8000_00E1 => "EV_EFI_SPDM_FIRMWARE_BLOB",
        0x8000_00E2 => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _ => "EV_DESCONOCIDO",
    }
}

/// Si el resumen de un evento corresponde a lo que el evento dice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verificacion {
    /// El resumen SHA-256 es el hash de lo que el evento describe.
    Coincide,
    /// NO lo es: el texto del evento no es lo que se midio.
    NoCoincide,
    /// No se puede comprobar, con el motivo.
    NoVerificable(&'static str),
}

/// Una variable UEFI tal y como aparece medida (`UEFI_VARIABLE_DATA`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableMedida {
    /// GUID.
    pub guid: Guid,
    /// Nombre.
    pub nombre: String,
    /// Datos.
    pub datos: Vec<u8>,
}

/// Decodifica `UEFI_VARIABLE_DATA`: GUID (16), longitud del nombre en
/// caracteres (8), longitud de los datos (8), nombre UTF-16 y datos.
#[must_use]
pub fn variable_medida(d: &[u8]) -> Option<VariableMedida> {
    let guid = Guid::from_bytes(d.get(0..16)?);
    let n_nombre = usize::try_from(u64::from_le_bytes(d.get(16..24)?.try_into().ok()?)).ok()?;
    let n_datos = usize::try_from(u64::from_le_bytes(d.get(24..32)?.try_into().ok()?)).ok()?;
    let fin_nombre = 32usize.checked_add(n_nombre.checked_mul(2)?)?;
    let nombre = utf16(d.get(32..fin_nombre)?);
    let datos = d
        .get(fin_nombre..fin_nombre.checked_add(n_datos)?)?
        .to_vec();
    Some(VariableMedida {
        guid,
        nombre,
        datos,
    })
}

/// Decodifica `UEFI_IMAGE_LOAD_EVENT` y devuelve la ruta y el tamano en memoria.
#[must_use]
pub fn imagen_cargada(d: &[u8]) -> Option<(Ruta, u64)> {
    let largo = u64::from_le_bytes(d.get(8..16)?.try_into().ok()?);
    let n = usize::try_from(u64::from_le_bytes(d.get(24..32)?.try_into().ok()?)).ok()?;
    let ruta = d.get(32..32usize.checked_add(n)?)?;
    Some((decodificar(ruta), largo))
}

/// Un eslabon de la cadena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eslabon {
    /// Posicion en el registro.
    pub indice: usize,
    /// PCR que extiende.
    pub pcr: u32,
    /// Tipo crudo.
    pub tipo: u32,
    /// Que se midio, en una frase.
    pub explicacion: String,
    /// El resumen SHA-256, si el registro lo trae.
    pub sha256: Option<Vec<u8>>,
    /// Si el resumen corresponde al texto.
    pub verificacion: Verificacion,
}

fn texto_imprimible(d: &[u8]) -> String {
    let t: String = String::from_utf8_lossy(d)
        .chars()
        .filter(|c| *c != '\0')
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = t.trim().to_string();
    if t.chars().count() > 160 {
        format!("{}…", t.chars().take(160).collect::<String>())
    } else {
        t
    }
}

fn resumir_variable(v: &VariableMedida) -> String {
    let valor = match v.nombre.as_str() {
        "SecureBoot" | "SetupMode" | "AuditMode" | "DeployedMode" => {
            format!("= {}", v.datos.first().copied().unwrap_or(0))
        }
        "PK" | "KEK" | "db" | "dbx" | "dbt" | "dbr" => match parse_signature_lists(&v.datos) {
            Ok(f) => format!("= {} firma(s)", f.len()),
            Err(_) => format!("= {} B (listas de firmas malformadas)", v.datos.len()),
        },
        "BootOrder" => format!(
            "= {}",
            v.datos
                .chunks_exact(2)
                .map(|c| format!("{:04X}", u16::from_le_bytes([c[0], c[1]])))
                .collect::<Vec<_>>()
                .join(",")
        ),
        n if n.starts_with("Boot") && n.len() == 8 => analizar_opcion(0, &v.datos)
            .map(|o| format!("= '{}' → {}", o.descripcion, o.ruta.texto()))
            .unwrap_or_else(|| format!("= {} B", v.datos.len())),
        _ => format!("= {} B", v.datos.len()),
    };
    format!("variable {} {valor}", v.nombre)
}

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

/// Explica y verifica un evento.
#[must_use]
pub fn eslabon(indice: usize, ev: &LogEvent) -> Eslabon {
    let tipo = ev.event_type.as_u32();
    let d = &ev.data;
    let digest = ev.digest(HashAlg::Sha256).map(<[u8]>::to_vec);
    let coincide_con = |candidatos: &[&[u8]]| -> Option<bool> {
        let dg = digest.as_deref()?;
        Some(candidatos.iter().any(|c| sha256(c).as_slice() == dg))
    };
    // Estricto: la norma exige que el resumen sea el hash de estos bytes.
    let estricto = |candidatos: &[&[u8]]| match coincide_con(candidatos) {
        None => Verificacion::NoVerificable("el registro no trae banco SHA-256"),
        Some(true) => Verificacion::Coincide,
        Some(false) => Verificacion::NoCoincide,
    };
    // Tolerante: los firmwares no se ponen de acuerdo en el formato; si no casa,
    // no se puede afirmar nada.
    let tolerante = |candidatos: &[&[u8]], motivo: &'static str| match coincide_con(candidatos) {
        Some(true) => Verificacion::Coincide,
        None => Verificacion::NoVerificable("el registro no trae banco SHA-256"),
        Some(false) => Verificacion::NoVerificable(motivo),
    };
    const CODIGO: Verificacion =
        Verificacion::NoVerificable("mide un binario, no lo que describe el evento");

    let (explicacion, verificacion) = match tipo {
        0x03 => (
            format!(
                "informativo, no extiende: {}",
                texto_imprimible(d.get(..16).unwrap_or(d))
            ),
            Verificacion::NoVerificable("no extiende ningun PCR"),
        ),
        0x04 => {
            let valor = d
                .get(0..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
            (
                match valor {
                    Some(0) => format!(
                        "separador: fin de la fase previa al SO en el PCR {}",
                        ev.pcr
                    ),
                    Some(u32::MAX) => format!(
                        "separador de ERROR en el PCR {}: el firmware fallo al medir",
                        ev.pcr
                    ),
                    _ => format!("separador con valor no normalizado ({} B)", d.len()),
                },
                estricto(&[d]),
            )
        }
        0x05 | 0x8000_0007 => (format!("accion: {}", texto_imprimible(d)), estricto(&[d])),
        0x08 => {
            let t = if d.len() >= 2 && d[1] == 0 {
                utf16(d)
            } else {
                texto_imprimible(d)
            };
            (
                format!("version del firmware (S-CRTM): {t}"),
                tolerante(&[d], "cada fabricante mide la version a su manera"),
            )
        }
        0x01 => (
            format!(
                "codigo de arranque del firmware (POST) {}",
                texto_imprimible(d)
            ),
            CODIGO,
        ),
        0x07 | 0x8000_0010 => (
            "contenido de la raiz de confianza de medida (S-CRTM)".to_string(),
            CODIGO,
        ),
        0x09 => ("microcodigo de la CPU".to_string(), CODIGO),
        0x8000_0008 => {
            let base = d
                .get(0..8)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            let largo = d
                .get(8..16)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            (
                format!("bloque de firmware en {base:#x}+{largo:#x}"),
                CODIGO,
            )
        }
        0x8000_000A => {
            let n = d.first().copied().unwrap_or(0) as usize;
            let desc = texto_imprimible(d.get(1..1 + n).unwrap_or(&[]));
            (format!("bloque de firmware '{desc}'"), CODIGO)
        }
        0x8000_0001 | 0x8000_0002 | 0x8000_000C | 0x8000_00E0 => match variable_medida(d) {
            Some(v) => {
                let exp = match tipo {
                    0x8000_00E0 => {
                        format!("autoridad que valido una imagen: {}", resumir_variable(&v))
                    }
                    0x8000_0001 => {
                        format!("configuracion de Secure Boot: {}", resumir_variable(&v))
                    }
                    _ => format!("arranque: {}", resumir_variable(&v)),
                };
                let ver = if tipo == 0x8000_0001 {
                    estricto(&[d])
                } else {
                    // En las de arranque unos firmwares miden la estructura entera y
                    // otros solo los datos; cualquiera de los dos es conforme.
                    match coincide_con(&[d, &v.datos]) {
                        Some(true) => Verificacion::Coincide,
                        Some(false) => Verificacion::NoCoincide,
                        None => Verificacion::NoVerificable("el registro no trae banco SHA-256"),
                    }
                };
                (exp, ver)
            }
            None => (
                format!("variable UEFI con estructura ilegible ({} B)", d.len()),
                Verificacion::NoVerificable("UEFI_VARIABLE_DATA malformada"),
            ),
        },
        0x8000_0003..=0x8000_0005 => {
            let que = match tipo {
                0x8000_0003 => "aplicacion EFI ejecutada",
                0x8000_0004 => "controlador EFI de arranque ejecutado",
                _ => "controlador EFI de ejecucion ejecutado",
            };
            match imagen_cargada(d) {
                Some((r, largo)) => (
                    format!("{que}: {} ({largo} B en memoria)", r.texto()),
                    CODIGO,
                ),
                None => (format!("{que} (ruta ilegible)"), CODIGO),
            }
        }
        0x8000_0006 => (
            format!("tabla de particiones GPT ({} B)", d.len()),
            tolerante(&[d], "la estructura medida de la GPT varia entre firmwares"),
        ),
        0x8000_0009 | 0x8000_000B => (
            "tablas de traspaso al sistema operativo".to_string(),
            CODIGO,
        ),
        0x0D => {
            let t = texto_imprimible(d);
            let sin_nulo = d.strip_suffix(&[0]).unwrap_or(d);
            let mut candidatos: Vec<&[u8]> = vec![d, sin_nulo];
            for prefijo in [
                &b"grub_cmd: "[..],
                b"kernel_cmdline: ",
                b"module_cmdline: ",
                b"grub_kernel_cmdline ",
            ] {
                if let Some(resto) = sin_nulo.strip_prefix(prefijo) {
                    candidatos.push(resto);
                }
            }
            (
                format!("cargador: {t}"),
                tolerante(&candidatos, "cada cargador mide sus ordenes a su manera"),
            )
        }
        _ => (
            format!("{} ({} B)", nombre_tipo(tipo), d.len()),
            Verificacion::NoVerificable("tipo de evento sin regla de resumen"),
        ),
    };
    Eslabon {
        indice,
        pcr: ev.pcr,
        tipo,
        explicacion,
        sha256: digest,
        verificacion,
    }
}

/// La cadena entera, con su resumen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cadena {
    /// Todos los eslabones, en orden.
    pub eslabones: Vec<Eslabon>,
    /// Version del firmware.
    pub version_firmware: Option<String>,
    /// El valor de `SecureBoot` tal y como se midio.
    pub secure_boot_medido: Option<bool>,
    /// Los cargadores ejecutados, en orden.
    pub cargadores: Vec<String>,
    /// La linea de ordenes del kernel medida por el cargador.
    pub linea_ordenes: Option<String>,
    /// Controladores ejecutados desde dispositivos PCI (option ROMs): ruta y
    /// resumen SHA-256.
    pub controladores_pci: Vec<(String, Vec<u8>)>,
    /// PCR con separador normal.
    pub separadores: BTreeSet<u32>,
    /// PCR con separador de error.
    pub separadores_error: BTreeSet<u32>,
    /// Si el registro es crypto-agil (trae SHA-256).
    pub crypto_agil: bool,
}

/// Reconstruye y explica la cadena.
#[must_use]
pub fn reconstruir(log: &EventLog) -> Cadena {
    let mut c = Cadena {
        crypto_agil: log.crypto_agile,
        ..Default::default()
    };
    for (i, ev) in log.events.iter().enumerate() {
        let e = eslabon(i, ev);
        let tipo = ev.event_type.as_u32();
        match tipo {
            0x04 => match ev.data.get(0..4) {
                Some([0, 0, 0, 0]) => {
                    c.separadores.insert(ev.pcr);
                }
                Some([0xFF, 0xFF, 0xFF, 0xFF]) => {
                    c.separadores_error.insert(ev.pcr);
                }
                _ => {}
            },
            0x08 => {
                c.version_firmware = Some(
                    e.explicacion
                        .trim_start_matches("version del firmware (S-CRTM): ")
                        .to_string(),
                );
            }
            0x8000_0001 => {
                if let Some(v) = variable_medida(&ev.data) {
                    if v.nombre == "SecureBoot" {
                        c.secure_boot_medido = Some(v.datos.first().copied().unwrap_or(0) == 1);
                    }
                }
            }
            0x8000_0003 => {
                if let Some((r, _)) = imagen_cargada(&ev.data) {
                    c.cargadores.push(r.fichero().unwrap_or_else(|| r.texto()));
                }
            }
            0x8000_0004 | 0x8000_0005 => {
                if let Some((r, _)) = imagen_cargada(&ev.data) {
                    if r.pasa_por_pci() && ev.pcr == 2 {
                        c.controladores_pci
                            .push((r.texto(), e.sha256.clone().unwrap_or_default()));
                    }
                }
            }
            0x0D => {
                let t = String::from_utf8_lossy(&ev.data).to_string();
                if let Some(resto) = t.strip_prefix("kernel_cmdline: ") {
                    c.linea_ordenes = Some(resto.trim_end_matches('\0').to_string());
                }
            }
            _ => {}
        }
        c.eslabones.push(e);
    }
    c
}

/// De donde sale el registro.
#[derive(Debug, Clone)]
pub enum Fuente {
    /// Leido y analizado.
    Registro(EventLog),
    /// No aplica, con el motivo.
    NoAplica(String),
    /// Esta pero no se pudo analizar.
    Ilegible(String),
}

/// Las comprobaciones de la cadena de arranque.
#[must_use]
pub fn evaluar(
    fuente: &Fuente,
    pcrs: Option<&PcrBank>,
    almacen: Option<&Almacen>,
    base: &LineaBase,
) -> (Option<Cadena>, Vec<Comprobacion>) {
    let log = match fuente {
        Fuente::Registro(l) => l,
        Fuente::NoAplica(m) | Fuente::Ilegible(m) => {
            let e = if matches!(fuente, Fuente::NoAplica(_)) {
                CheckState::NoAplicable(m.clone())
            } else {
                CheckState::Indeterminado(m.clone())
            };
            let c = |id, n| Comprobacion::nueva(id, Superficie::CadenaArranque, n, e.clone());
            return (
                None,
                vec![
                    c("cadena-pcr-reproducidos", Naturaleza::Compromiso),
                    c("cadena-resumenes", Naturaleza::Compromiso),
                    c("cadena-separadores", Naturaleza::Exposicion),
                    c("cadena-secure-boot-coherente", Naturaleza::Compromiso),
                    c("cadena-controladores-pci", Naturaleza::Compromiso),
                ],
            );
        }
    };
    let cad = reconstruir(log);
    let mut v = Vec::new();

    // 1. Los PCR del TPM salen del registro (la comprobacion de la FASE 26).
    let reproducidos = match pcrs {
        None => CheckState::Indeterminado(
            "hay registro pero no se pudieron leer los PCR del TPM".into(),
        ),
        Some(b) => check_pcr_log(&contrastar_arranque(log, b)).estado,
    };
    v.push(Comprobacion::nueva(
        "cadena-pcr-reproducidos",
        Superficie::CadenaArranque,
        Naturaleza::Compromiso,
        reproducidos,
    ));

    // 2. El texto de cada evento autodescriptivo corresponde a su resumen.
    let malos: Vec<String> = cad
        .eslabones
        .iter()
        .filter(|e| e.verificacion == Verificacion::NoCoincide)
        .map(|e| {
            format!(
                "#{} PCR{} {} «{}»",
                e.indice,
                e.pcr,
                nombre_tipo(e.tipo),
                e.explicacion
            )
        })
        .collect();
    let verificados = cad
        .eslabones
        .iter()
        .filter(|e| e.verificacion == Verificacion::Coincide)
        .count();
    let resumenes = if !malos.is_empty() {
        CheckState::Fallo(format!(
            "{} evento(s) dicen una cosa y su resumen es de otra: el texto del registro fue \
             reescrito despues de medirse. {}",
            malos.len(),
            malos.join("; ")
        ))
    } else if verificados == 0 {
        CheckState::Indeterminado(if cad.crypto_agil {
            "ningun evento autodescriptivo que comprobar".into()
        } else {
            "registro heredado de solo SHA-1: los resumenes no se comprueban aqui".into()
        })
    } else {
        CheckState::Ok
    };
    v.push(Comprobacion::nueva(
        "cadena-resumenes",
        Superficie::CadenaArranque,
        Naturaleza::Compromiso,
        resumenes,
    ));

    // 3. Separadores de las fases 0-7.
    let faltan: Vec<u32> = (0..8)
        .filter(|p| !cad.separadores.contains(p) && !cad.separadores_error.contains(p))
        .collect();
    let sep = if !cad.separadores_error.is_empty() {
        CheckState::Fallo(format!(
            "separador de ERROR en los PCR {:?}: el firmware declaro que no pudo medir algo de esas fases",
            cad.separadores_error
        ))
    } else if !faltan.is_empty() {
        CheckState::Indeterminado(format!(
            "sin separador en los PCR {faltan:?}: el registro esta truncado o esas fases no se cerraron"
        ))
    } else {
        CheckState::Ok
    };
    v.push(Comprobacion::nueva(
        "cadena-separadores",
        Superficie::CadenaArranque,
        Naturaleza::Exposicion,
        sep,
    ));

    // 4. Secure Boot tal y como se midio, frente a como esta ahora.
    let actual = almacen.and_then(|a| a.bandera("SecureBoot"));
    let sb = match (cad.secure_boot_medido, actual) {
        (Some(m), Some(a)) if m != a => CheckState::Fallo(format!(
            "el arranque midio SecureBoot={} y la variable dice ahora {}: o el registro miente o el \
             estado cambio despues de arrancar, y ninguna de las dos cosas pasa sola",
            u8::from(m),
            u8::from(a)
        )),
        (Some(_), Some(_)) => CheckState::Ok,
        (None, _) => CheckState::Indeterminado("el registro no mide la variable SecureBoot".into()),
        (Some(_), None) => CheckState::Indeterminado("no se pudo leer la variable SecureBoot actual".into()),
    };
    v.push(Comprobacion::nueva(
        "cadena-secure-boot-coherente",
        Superficie::CadenaArranque,
        Naturaleza::Compromiso,
        sb,
    ));

    // 5. Option ROMs que el firmware ejecuto, contra la linea base.
    let ctl = if cad.controladores_pci.is_empty() {
        CheckState::Ok
    } else {
        let mut revocados = Vec::new();
        let mut desconocidos = 0;
        for (ruta, d) in &cad.controladores_pci {
            let h: Option<[u8; 32]> = d.as_slice().try_into().ok();
            match h {
                Some(h) if base.revocados.contains_key(&h) => {
                    revocados.push(format!("{ruta} = {}", base.revocados[&h]))
                }
                Some(h) if base.controladores.contains_key(&h) => {}
                _ => desconocidos += 1,
            }
        }
        if !revocados.is_empty() {
            CheckState::Fallo(format!(
                "el firmware ejecuto option ROMs conocidas como maliciosas: {}",
                revocados.join("; ")
            ))
        } else if desconocidos > 0 {
            CheckState::Indeterminado(format!(
                "el firmware ejecuto {} controlador(es) de option ROM; {desconocidos} no estan en la linea base",
                cad.controladores_pci.len()
            ))
        } else {
            CheckState::Ok
        }
    };
    v.push(Comprobacion::nueva(
        "cadena-controladores-pci",
        Superficie::CadenaArranque,
        Naturaleza::Compromiso,
        ctl,
    ));
    (Some(cad), v)
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;
    use crate::ruta_dispositivo::pruebas::{nodo, ruta_disco};
    use aegis_firmware::eventlog::parse;
    use aegis_firmware::uefi::EFI_GLOBAL;

    /// Un registro crypto-agil REAL construido byte a byte segun la
    /// especificacion TCG PC Client: el evento Spec ID y luego eventos
    /// TCG_PCR_EVENT2 con un solo banco SHA-256.
    pub(crate) struct Registro(Vec<u8>);

    impl Registro {
        pub(crate) fn nuevo() -> Registro {
            let mut datos = Vec::new();
            datos.extend_from_slice(b"Spec ID Event03\0");
            datos.extend_from_slice(&0u32.to_le_bytes());
            datos.extend_from_slice(&[0, 2, 0, 2]);
            datos.extend_from_slice(&1u32.to_le_bytes());
            datos.extend_from_slice(&0x000Bu16.to_le_bytes());
            datos.extend_from_slice(&32u16.to_le_bytes());
            datos.push(0);
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&3u32.to_le_bytes());
            b.extend_from_slice(&[0u8; 20]);
            b.extend_from_slice(&(datos.len() as u32).to_le_bytes());
            b.extend_from_slice(&datos);
            Registro(b)
        }

        /// Un evento cuyo resumen se da explicitamente.
        pub(crate) fn evento_con(
            mut self,
            pcr: u32,
            tipo: u32,
            digest: [u8; 32],
            datos: &[u8],
        ) -> Registro {
            self.0.extend_from_slice(&pcr.to_le_bytes());
            self.0.extend_from_slice(&tipo.to_le_bytes());
            self.0.extend_from_slice(&1u32.to_le_bytes());
            self.0.extend_from_slice(&0x000Bu16.to_le_bytes());
            self.0.extend_from_slice(&digest);
            self.0
                .extend_from_slice(&(datos.len() as u32).to_le_bytes());
            self.0.extend_from_slice(datos);
            self
        }

        /// Un evento con el resumen que manda la norma: el hash de sus datos.
        pub(crate) fn evento(self, pcr: u32, tipo: u32, datos: &[u8]) -> Registro {
            let d = sha256(datos);
            self.evento_con(pcr, tipo, d, datos)
        }

        pub(crate) fn log(&self) -> EventLog {
            parse(&self.0).expect("registro valido")
        }
    }

    pub(crate) fn var_medida(nombre: &str, datos: &[u8]) -> Vec<u8> {
        let mut v = EFI_GLOBAL.0.to_vec();
        let n: Vec<u8> = nombre.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v.extend_from_slice(&((n.len() / 2) as u64).to_le_bytes());
        v.extend_from_slice(&(datos.len() as u64).to_le_bytes());
        v.extend_from_slice(&n);
        v.extend_from_slice(datos);
        v
    }

    pub(crate) fn imagen(ruta: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[8..16].copy_from_slice(&0x10_0000u64.to_le_bytes());
        v[24..32].copy_from_slice(&(ruta.len() as u64).to_le_bytes());
        v.extend_from_slice(ruta);
        v
    }

    /// Un arranque completo y sano.
    pub(crate) fn arranque_sano() -> Registro {
        let version: Vec<u8> = "1.23.0"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut r = Registro::nuevo()
            .evento(0, 0x08, &version)
            .evento(7, 0x8000_0001, &var_medida("SecureBoot", &[1]))
            .evento(7, 0x8000_0001, &var_medida("PK", &[]));
        for pcr in 0..8 {
            r = r.evento(pcr, 0x04, &[0, 0, 0, 0]);
        }
        let shim = imagen(&ruta_disco("\\EFI\\ubuntu\\shimx64.efi"));
        r.evento_con(4, 0x8000_0003, [0x5A; 32], &shim)
            .evento(4, 0x8000_0007, b"Calling EFI Application from Boot Option")
            .evento(
                8,
                0x0D,
                b"kernel_cmdline: /vmlinuz root=/dev/nvme0n1p2 ro\0",
            )
    }

    fn por_id<'a>(v: &'a [Comprobacion], id: &str) -> &'a Comprobacion {
        v.iter().find(|c| c.id == id).expect(id)
    }

    #[test]
    fn un_arranque_sano_se_explica_y_se_verifica_entero() {
        let log = arranque_sano().log();
        let cad = reconstruir(&log);
        assert_eq!(cad.version_firmware.as_deref(), Some("1.23.0"));
        assert_eq!(cad.secure_boot_medido, Some(true));
        assert_eq!(
            cad.cargadores,
            vec!["\\EFI\\ubuntu\\shimx64.efi".to_string()]
        );
        assert_eq!(
            cad.linea_ordenes.as_deref(),
            Some("/vmlinuz root=/dev/nvme0n1p2 ro")
        );
        assert_eq!(cad.separadores.len(), 8);
        let shim = cad
            .eslabones
            .iter()
            .find(|e| e.tipo == 0x8000_0003)
            .expect("shim");
        assert!(
            shim.explicacion.contains("shimx64.efi"),
            "{}",
            shim.explicacion
        );
        assert_eq!(shim.verificacion, CODIGO_ESPERADO);
        for e in &cad.eslabones {
            assert!(!e.explicacion.is_empty());
            assert_ne!(e.verificacion, Verificacion::NoCoincide, "{e:?}");
        }
        let (_, c) = evaluar(&Fuente::Registro(log), None, None, &LineaBase::default());
        assert_eq!(por_id(&c, "cadena-resumenes").estado, CheckState::Ok);
        assert_eq!(por_id(&c, "cadena-separadores").estado, CheckState::Ok);
    }

    const CODIGO_ESPERADO: Verificacion =
        Verificacion::NoVerificable("mide un binario, no lo que describe el evento");

    /// EL ATAQUE QUE ESTE MODULO VE Y LA REPRODUCCION DE PCR NO: reescribir el
    /// texto de un evento dejando su resumen intacto. El PCR sigue cuadrando; el
    /// evento dice SecureBoot=1 y lo que se midio fue SecureBoot=0.
    #[test]
    fn un_evento_cuyo_texto_fue_reescrito_se_delata() {
        let medido = sha256(&var_medida("SecureBoot", &[0]));
        let log = Registro::nuevo()
            .evento_con(7, 0x8000_0001, medido, &var_medida("SecureBoot", &[1]))
            .log();
        let (_, c) = evaluar(&Fuente::Registro(log), None, None, &LineaBase::default());
        let r = por_id(&c, "cadena-resumenes");
        assert_eq!(r.naturaleza, Naturaleza::Compromiso);
        let m = format!("{:?}", r.estado);
        assert!(m.contains("reescrito") && m.contains("SecureBoot"), "{m}");
    }

    #[test]
    fn un_separador_de_error_o_ausente_se_dice() {
        let mut r = Registro::nuevo();
        for pcr in 0..7 {
            r = r.evento(pcr, 0x04, &[0, 0, 0, 0]);
        }
        let log = r.log();
        let (_, c) = evaluar(&Fuente::Registro(log), None, None, &LineaBase::default());
        assert!(format!("{:?}", por_id(&c, "cadena-separadores").estado).contains("[7]"));
        let log = Registro::nuevo().evento(0, 0x04, &[0xFF; 4]).log();
        let (_, c) = evaluar(&Fuente::Registro(log), None, None, &LineaBase::default());
        assert!(por_id(&c, "cadena-separadores").estado.es_fallo());
    }

    #[test]
    fn secure_boot_medido_distinto_del_actual_es_compromiso() {
        let log = arranque_sano().log();
        let mut a = crate::variables::pruebas::almacen_sano();
        for v in &mut a.variables {
            if v.nombre == "SecureBoot" {
                v.datos = vec![0];
            }
        }
        let (_, c) = evaluar(
            &Fuente::Registro(log.clone()),
            None,
            Some(&a),
            &LineaBase::default(),
        );
        assert!(por_id(&c, "cadena-secure-boot-coherente").estado.es_fallo());
        let sano = crate::variables::pruebas::almacen_sano();
        let (_, c) = evaluar(
            &Fuente::Registro(log),
            None,
            Some(&sano),
            &LineaBase::default(),
        );
        assert_eq!(
            por_id(&c, "cadena-secure-boot-coherente").estado,
            CheckState::Ok
        );
    }

    #[test]
    fn las_option_roms_ejecutadas_se_cotejan_con_la_linea_base() {
        let mut ruta = nodo(0x02, 0x01, &[0xD0, 0x41, 0x03, 0x0A, 0, 0, 0, 0]);
        ruta.extend(nodo(0x01, 0x01, &[0, 0x1C]));
        ruta.extend(crate::ruta_dispositivo::pruebas::fin());
        let log = Registro::nuevo()
            .evento_con(2, 0x8000_0004, [0xAB; 32], &imagen(&ruta))
            .log();
        let cad = reconstruir(&log);
        assert_eq!(cad.controladores_pci.len(), 1);
        let (_, c) = evaluar(
            &Fuente::Registro(log.clone()),
            None,
            None,
            &LineaBase::default(),
        );
        assert!(matches!(
            por_id(&c, "cadena-controladores-pci").estado,
            CheckState::Indeterminado(_)
        ));
        let conocida = LineaBase::analizar(&format!("version 1\ndriver {} NIC\n", "ab".repeat(32)))
            .expect("base");
        let (_, c) = evaluar(&Fuente::Registro(log.clone()), None, None, &conocida);
        assert_eq!(
            por_id(&c, "cadena-controladores-pci").estado,
            CheckState::Ok
        );
        let mala = LineaBase::analizar(&format!(
            "version 1\nrevocado {} implante-nic\n",
            "ab".repeat(32)
        ))
        .expect("base");
        let (_, c) = evaluar(&Fuente::Registro(log), None, None, &mala);
        assert!(por_id(&c, "cadena-controladores-pci").estado.es_fallo());
    }

    #[test]
    fn sin_registro_todo_se_declara_con_su_motivo() {
        let (cad, c) = evaluar(
            &Fuente::NoAplica("sin TPM".into()),
            None,
            None,
            &LineaBase::default(),
        );
        assert!(cad.is_none());
        assert_eq!(c.len(), 5);
        assert!(c
            .iter()
            .all(|x| matches!(x.estado, CheckState::NoAplicable(_))));
    }

    #[test]
    fn las_estructuras_medidas_malformadas_no_leen_fuera() {
        assert!(variable_medida(&[0u8; 10]).is_none());
        let mut v = var_medida("SecureBoot", &[1]);
        v[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(variable_medida(&v).is_none());
        let mut i = imagen(&[]);
        i[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(imagen_cargada(&i).is_none());
    }
}
