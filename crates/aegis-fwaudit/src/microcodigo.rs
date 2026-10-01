//! El microcodigo cargado, frente a la ultima revision que publica el fabricante.
//!
//! # Por que importa en una auditoria de firmware
//!
//! Buena parte de las mitigaciones de ejecucion especulativa, y de los arreglos
//! de fallos de SMM y de SGX, **son** microcodigo. Una CPU con el microcodigo de
//! hace tres anos tiene abiertas todas las puertas que se cerraron despues, por
//! bien configurado que este todo lo demas. Y el kernel solo dice la revision
//! que hay; no dice si hay una mas nueva.
//!
//! # De donde sale «la ultima conocida»
//!
//! No de una tabla escrita aqui a mano, que caducaria el dia de la siguiente
//! publicacion. Sale de **los ficheros del propio fabricante** —el paquete
//! `intel-microcode` en `/lib/firmware/intel-ucode`, `amd64-microcode` en
//! `/lib/firmware/amd-ucode`—, que son lo que Intel y AMD publican y que la
//! distribucion actualiza. Se leen sus cabeceras con el formato de la
//! documentacion de cada fabricante y **se verifica su suma de comprobacion**:
//! un fichero que no suma cero no es un microcodigo del fabricante, y no puede
//! servir de referencia para nada.
//!
//! # El caso de la maquina virtual
//!
//! Un hipervisor suele ocultar la revision real al invitado y publicar
//! `0xffffffff`. Eso no es «atrasado» ni «al dia»: es que no se puede saber desde
//! aqui. Se dice asi, con la revision del fabricante al lado para que quien mire
//! el anfitrion sepa contra que comparar.

use std::collections::BTreeMap;
use std::path::Path;

use aegis_firmware::report::CheckState;

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::solo_lectura::LecturaSolo;

/// Tamano de la cabecera de una actualizacion de Intel.
pub const TAM_CABECERA_INTEL: usize = 48;
/// Tamano por defecto de los datos cuando la cabecera dice 0.
pub const DATOS_POR_DEFECTO: usize = 2000;
/// Tope de lo que se lee de un fichero de microcodigo.
pub const TOPE_FICHERO: usize = 16 * 1024 * 1024;
/// Firma del contenedor de AMD (`DMA\0` en little-endian).
pub const MAGIA_AMD: u32 = 0x0041_4D44;

/// La CPU, segun `/proc/cpuinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// `GenuineIntel`, `AuthenticAMD`...
    pub fabricante: String,
    /// Familia (ya combinada con la extendida, como la imprime el kernel).
    pub familia: u32,
    /// Modelo (ya combinado).
    pub modelo: u32,
    /// Escalon.
    pub escalon: u32,
    /// La revision de microcodigo de cada CPU logica, en orden.
    pub revisiones: Vec<u32>,
    /// La bandera `hypervisor`: corre dentro de una maquina virtual.
    pub virtualizada: bool,
}

impl Cpu {
    /// La firma CPUID(1).EAX que usan los ficheros de Intel.
    #[must_use]
    pub fn firma(&self) -> u32 {
        let (fam_base, fam_ext) = if self.familia >= 0xF {
            (0xF, self.familia - 0xF)
        } else {
            (self.familia, 0)
        };
        let (mod_base, mod_ext) = (self.modelo & 0xF, self.modelo >> 4);
        (fam_ext << 20) | (mod_ext << 16) | (fam_base << 8) | (mod_base << 4) | (self.escalon & 0xF)
    }

    /// El nombre de fichero de Intel: `06-a5-02`.
    #[must_use]
    pub fn fichero_intel(&self) -> String {
        format!(
            "{:02x}-{:02x}-{:02x}",
            self.familia, self.modelo, self.escalon
        )
    }

    /// El nombre de fichero de AMD: `microcode_amd_fam17h.bin` (o el generico
    /// para familias anteriores a la 0x15).
    #[must_use]
    pub fn fichero_amd(&self) -> String {
        if self.familia >= 0x15 {
            format!("microcode_amd_fam{:02x}h.bin", self.familia)
        } else {
            "microcode_amd.bin".to_string()
        }
    }
}

/// Analiza `/proc/cpuinfo`.
///
/// # Errores
/// El motivo si falta la familia, el modelo o el escalon.
pub fn analizar_cpuinfo(texto: &str) -> Result<Cpu, String> {
    let mut campos: BTreeMap<&str, &str> = BTreeMap::new();
    let mut revisiones = Vec::new();
    let mut virtualizada = false;
    for l in texto.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "microcode" => {
                if let Ok(r) = u32::from_str_radix(v.trim_start_matches("0x"), 16) {
                    revisiones.push(r);
                }
            }
            "flags" => {
                if v.split_whitespace().any(|f| f == "hypervisor") {
                    virtualizada = true;
                }
            }
            _ => {
                campos.entry(k).or_insert(v);
            }
        }
    }
    let num = |k: &str| -> Result<u32, String> {
        campos
            .get(k)
            .ok_or_else(|| format!("/proc/cpuinfo no trae '{k}'"))?
            .parse()
            .map_err(|_| format!("'{k}' no es un numero"))
    };
    Ok(Cpu {
        fabricante: campos.get("vendor_id").copied().unwrap_or("").to_string(),
        familia: num("cpu family")?,
        modelo: num("model")?,
        escalon: num("stepping")?,
        revisiones,
        virtualizada,
    })
}

/// Una actualizacion de microcodigo de Intel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActualizacionIntel {
    /// Revision.
    pub revision: u32,
    /// Fecha, `AAAA-MM-DD`.
    pub fecha: String,
    /// Firmas de procesador a las que aplica (la principal y las extendidas).
    pub firmas: Vec<(u32, u32)>,
    /// Si la suma de comprobacion de la parte principal da cero.
    pub suma_ok: bool,
}

/// Analiza un fichero de Intel, que puede llevar varias actualizaciones
/// concatenadas.
///
/// Cada tamano se comprueba antes de usarse: el fichero es entrada de disco, y
/// un `total_size` mentiroso no puede hacer leer fuera ni colgar el recorrido.
#[must_use]
pub fn analizar_intel(bytes: &[u8]) -> Vec<ActualizacionIntel> {
    let mut salida = Vec::new();
    let mut pos = 0usize;
    let dw = |b: &[u8], o: usize| -> Option<u32> {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    while pos + TAM_CABECERA_INTEL <= bytes.len() {
        let h = &bytes[pos..];
        if dw(h, 0) != Some(1) {
            break;
        }
        let (Some(rev), Some(fecha), Some(firma), Some(banderas), Some(ds), Some(ts)) = (
            dw(h, 4),
            dw(h, 8),
            dw(h, 12),
            dw(h, 24),
            dw(h, 28),
            dw(h, 32),
        ) else {
            break;
        };
        let datos = if ds == 0 {
            DATOS_POR_DEFECTO
        } else {
            ds as usize
        };
        let total = if ds == 0 { 2048 } else { ts as usize };
        let principal = datos + TAM_CABECERA_INTEL;
        if total < principal || pos.saturating_add(total) > bytes.len() || total % 4 != 0 {
            break;
        }
        let actualizacion = &bytes[pos..pos + total];
        let suma = |s: &[u8]| {
            s.chunks_exact(4).fold(0u32, |a, c| {
                a.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            })
        };
        let mut suma_ok = suma(&actualizacion[..principal]) == 0;
        let mut firmas = vec![(firma, banderas)];
        // Tabla de firmas extendidas, si la hay.
        if total > principal + 20 {
            let ext = &actualizacion[principal..];
            let n = dw(ext, 0).unwrap_or(0) as usize;
            let tam_ext = 20 + n.saturating_mul(12);
            if n > 0 && tam_ext <= ext.len() {
                suma_ok &= suma(&ext[..tam_ext]) == 0;
                for i in 0..n {
                    let o = 20 + i * 12;
                    if let (Some(s), Some(f)) = (dw(ext, o), dw(ext, o + 4)) {
                        firmas.push((s, f));
                    }
                }
            }
        }
        let bcd = format!("{fecha:08x}");
        salida.push(ActualizacionIntel {
            revision: rev,
            fecha: format!("{}-{}-{}", &bcd[4..8], &bcd[0..2], &bcd[2..4]),
            firmas,
            suma_ok,
        });
        pos += total;
    }
    salida
}

/// Un parche de AMD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParcheAmd {
    /// Revision (`patch_id`).
    pub revision: u32,
    /// Identificador de equivalencia de procesador al que aplica.
    pub equivalencia: u16,
}

/// Analiza un contenedor de AMD: tabla de equivalencias y parches.
///
/// Devuelve la tabla (firma CPUID → identificador de equivalencia) y los
/// parches. Un contenedor malformado devuelve lo que se pudo leer hasta ahi.
#[must_use]
pub fn analizar_amd(bytes: &[u8]) -> (BTreeMap<u32, u16>, Vec<ParcheAmd>) {
    let mut equivalencias = BTreeMap::new();
    let mut parches = Vec::new();
    let dw = |o: usize| -> Option<u32> {
        bytes
            .get(o..o.checked_add(4)?)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let mut pos = 0usize;
    // Puede haber varios contenedores concatenados.
    while dw(pos) == Some(MAGIA_AMD) {
        if dw(pos + 4) != Some(0) {
            break;
        }
        let Some(tam_tabla) = dw(pos + 8).map(|t| t as usize) else {
            break;
        };
        let inicio = pos + 12;
        let Some(fin_tabla) = inicio.checked_add(tam_tabla).filter(|f| *f <= bytes.len()) else {
            break;
        };
        for e in bytes[inicio..fin_tabla].chunks_exact(16) {
            let cpu = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            if cpu == 0 {
                break;
            }
            equivalencias.insert(cpu, u16::from_le_bytes([e[12], e[13]]));
        }
        pos = fin_tabla;
        while dw(pos) == Some(1) {
            let Some(tam) = dw(pos + 4).map(|t| t as usize) else {
                break;
            };
            let p = pos + 8;
            let Some(fin) = p.checked_add(tam).filter(|f| *f <= bytes.len()) else {
                return (equivalencias, parches);
            };
            if tam >= 0x20 {
                parches.push(ParcheAmd {
                    revision: u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap_or([0; 4])),
                    equivalencia: u16::from_le_bytes([bytes[p + 24], bytes[p + 25]]),
                });
            }
            pos = fin;
        }
    }
    (equivalencias, parches)
}

/// La revision mas alta que publica el fabricante para esta CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referencia {
    /// Revision.
    pub revision: u32,
    /// Fecha, si el formato la trae.
    pub fecha: Option<String>,
    /// De que fichero salio.
    pub fichero: String,
}

/// Busca la referencia del fabricante para una CPU.
///
/// `id_plataforma` (bits 52:50 de `IA32_PLATFORM_ID`) desempata entre
/// actualizaciones de Intel con la misma firma; sin el se toma la maxima y se
/// dice.
///
/// # Errores
/// El motivo si no hay ficheros o ninguno aplica.
pub fn referencia(
    cpu: &Cpu,
    raiz_firmware: &Path,
    id_plataforma: Option<u32>,
) -> Result<Referencia, String> {
    let leer = |ruta: &Path| -> Result<Vec<u8>, String> {
        LecturaSolo::abrir(ruta)
            .and_then(|l| l.leer_todo(TOPE_FICHERO))
            .map_err(|e| format!("{}: {e}", ruta.display()))
    };
    if cpu.fabricante == "AuthenticAMD" {
        let ruta = raiz_firmware.join("amd-ucode").join(cpu.fichero_amd());
        let b = leer(&ruta).map_err(|e| format!("sin microcodigo de AMD del fabricante ({e})"))?;
        let (eq, parches) = analizar_amd(&b);
        let id = eq.get(&cpu.firma()).ok_or_else(|| {
            format!(
                "{} no trae equivalencia para la firma {:#x}",
                ruta.display(),
                cpu.firma()
            )
        })?;
        let r = parches
            .iter()
            .filter(|p| p.equivalencia == *id)
            .map(|p| p.revision)
            .max()
            .ok_or_else(|| {
                format!(
                    "{} no trae parche para la equivalencia {id:#x}",
                    ruta.display()
                )
            })?;
        return Ok(Referencia {
            revision: r,
            fecha: None,
            fichero: ruta.display().to_string(),
        });
    }
    let ruta = raiz_firmware.join("intel-ucode").join(cpu.fichero_intel());
    let b = leer(&ruta).map_err(|e| {
        format!("sin microcodigo de Intel del fabricante para esta CPU ({e}); el paquete intel-microcode trae uno por firma")
    })?;
    let firma = cpu.firma();
    let candidatas: Vec<ActualizacionIntel> = analizar_intel(&b)
        .into_iter()
        .filter(|a| {
            a.firmas
                .iter()
                .any(|(s, f)| *s == firma && id_plataforma.is_none_or(|p| f & (1 << p) != 0))
        })
        .collect();
    if let Some(mala) = candidatas.iter().find(|a| !a.suma_ok) {
        return Err(format!(
            "{} trae una actualizacion (revision {:#x}) cuya suma de comprobacion no da cero: \
             no es un microcodigo integro del fabricante y no sirve de referencia",
            ruta.display(),
            mala.revision
        ));
    }
    let mejor = candidatas
        .iter()
        .max_by_key(|a| a.revision)
        .ok_or_else(|| {
            format!(
                "{} no trae ninguna actualizacion para la firma {firma:#x}",
                ruta.display()
            )
        })?;
    Ok(Referencia {
        revision: mejor.revision,
        fecha: Some(mejor.fecha.clone()),
        fichero: ruta.display().to_string(),
    })
}

/// La comprobacion.
#[must_use]
pub fn evaluar(cpu: &Result<Cpu, String>, referencia: &Result<Referencia, String>) -> Comprobacion {
    let estado = match (cpu, referencia) {
        (Err(e), _) => CheckState::NoAplicable(e.clone()),
        (Ok(c), _) if c.revisiones.is_empty() => {
            CheckState::Indeterminado("el kernel no publica la revision de microcodigo".into())
        }
        (Ok(c), r) => {
            let mut distintas: Vec<u32> = c.revisiones.clone();
            distintas.sort_unstable();
            distintas.dedup();
            let cargada = c.revisiones[0];
            if distintas.len() > 1 {
                CheckState::Fallo(format!(
                    "las CPU logicas tienen revisiones DISTINTAS ({}): una carga de \
                     microcodigo se quedo a medias y hay nucleos sin los arreglos",
                    distintas
                        .iter()
                        .map(|r| format!("{r:#x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            } else if cargada == u32::MAX || cargada == 0 {
                CheckState::Indeterminado(format!(
                    "la revision publicada es {cargada:#x}: {} oculta la real. {}",
                    if c.virtualizada { "el hipervisor" } else { "el sistema" },
                    match r {
                        Ok(r) => format!(
                            "El fabricante publica {:#x}{} para esta CPU: comparalo en el anfitrion",
                            r.revision,
                            r.fecha.as_deref().map(|f| format!(" ({f})")).unwrap_or_default()
                        ),
                        Err(e) => format!("Tampoco hay referencia: {e}"),
                    }
                ))
            } else {
                match r {
                    Err(e) => CheckState::Indeterminado(format!(
                        "revision cargada {cargada:#x}, pero no hay con que compararla: {e}"
                    )),
                    Ok(r) if cargada < r.revision => CheckState::Fallo(format!(
                        "microcodigo ATRASADO: cargada {cargada:#x}, el fabricante publica {:#x}{} \
                         en {}. Los arreglos publicados entre las dos no estan en esta CPU",
                        r.revision,
                        r.fecha.as_deref().map(|f| format!(" ({f})")).unwrap_or_default(),
                        r.fichero
                    )),
                    Ok(_) => CheckState::Ok,
                }
            }
        }
    };
    Comprobacion::nueva(
        "cpu-microcodigo",
        Superficie::Microcodigo,
        Naturaleza::Exposicion,
        estado,
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    /// Construye una actualizacion de Intel REAL byte a byte, con su suma bien.
    fn intel(
        rev: u32,
        fecha: u32,
        firma: u32,
        banderas: u32,
        datos: usize,
        ext: &[(u32, u32)],
    ) -> Vec<u8> {
        let principal = TAM_CABECERA_INTEL + datos;
        let tam_ext = if ext.is_empty() {
            0
        } else {
            20 + ext.len() * 12
        };
        let total = principal + tam_ext;
        let mut b = vec![0u8; total];
        let pon = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        pon(&mut b, 0, 1);
        pon(&mut b, 4, rev);
        pon(&mut b, 8, fecha);
        pon(&mut b, 12, firma);
        pon(&mut b, 20, 1);
        pon(&mut b, 24, banderas);
        pon(&mut b, 28, datos as u32);
        pon(&mut b, 32, total as u32);
        for (i, x) in b[TAM_CABECERA_INTEL..principal].iter_mut().enumerate() {
            *x = (i * 13 % 251) as u8;
        }
        let suma = |s: &[u8]| {
            s.chunks_exact(4).fold(0u32, |a, c| {
                a.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            })
        };
        let s = suma(&b[..principal]);
        pon(&mut b, 16, s.wrapping_neg());
        if !ext.is_empty() {
            pon(&mut b, principal, ext.len() as u32);
            for (i, (sig, f)) in ext.iter().enumerate() {
                pon(&mut b, principal + 20 + i * 12, *sig);
                pon(&mut b, principal + 24 + i * 12, *f);
            }
            let s = suma(&b[principal..]);
            pon(&mut b, principal + 4, s.wrapping_neg());
        }
        b
    }

    #[test]
    fn la_firma_se_compone_como_cpuid() {
        let c = Cpu {
            fabricante: "GenuineIntel".into(),
            familia: 6,
            modelo: 0xA5,
            escalon: 2,
            revisiones: vec![],
            virtualizada: false,
        };
        assert_eq!(c.firma(), 0x000A_0652);
        assert_eq!(c.fichero_intel(), "06-a5-02");
        let amd = Cpu {
            fabricante: "AuthenticAMD".into(),
            familia: 0x19,
            modelo: 0x21,
            escalon: 0,
            revisiones: vec![],
            virtualizada: false,
        };
        assert_eq!(amd.firma(), 0x00A2_0F10);
        assert_eq!(amd.fichero_amd(), "microcode_amd_fam19h.bin");
    }

    #[test]
    fn una_actualizacion_de_intel_se_lee_con_su_fecha_y_su_suma() {
        let mut f = intel(0xF8, 0x0518_2023, 0xA0652, 0x20, 2000, &[(0xA0653, 0x22)]);
        f.extend(intel(0xFA, 0x0102_2024, 0xA0655, 0x22, 1000, &[]));
        let a = analizar_intel(&f);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].revision, 0xF8);
        assert_eq!(a[0].fecha, "2023-05-18");
        assert!(a[0].suma_ok && a[1].suma_ok);
        assert_eq!(a[0].firmas, vec![(0xA0652, 0x20), (0xA0653, 0x22)]);
        // Un byte cambiado rompe la suma: ya no es del fabricante.
        let mut roto = intel(0xF8, 0x0518_2023, 0xA0652, 0x20, 2000, &[]);
        roto[100] ^= 1;
        assert!(!analizar_intel(&roto)[0].suma_ok);
    }

    #[test]
    fn un_tamano_mentiroso_no_lee_fuera_ni_cuelga() {
        let mut f = intel(1, 0x0101_2020, 1, 1, 100, &[]);
        f[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(analizar_intel(&f).is_empty());
        assert!(analizar_intel(&[]).is_empty());
        assert!(analizar_intel(&[1, 0, 0, 0]).is_empty());
        // Basura acotada: termina.
        let basura: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 256) as u8).collect();
        let _ = analizar_intel(&basura);
        let _ = analizar_amd(&basura);
    }

    fn contenedor_amd(cpu: u32, eq: u16, revs: &[(u32, u16)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&MAGIA_AMD.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&32u32.to_le_bytes());
        let mut e = [0u8; 16];
        e[0..4].copy_from_slice(&cpu.to_le_bytes());
        e[12..14].copy_from_slice(&eq.to_le_bytes());
        b.extend_from_slice(&e);
        b.extend_from_slice(&[0u8; 16]);
        for (rev, eq) in revs {
            let mut p = vec![0u8; 64];
            p[4..8].copy_from_slice(&rev.to_le_bytes());
            p[24..26].copy_from_slice(&eq.to_le_bytes());
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&(p.len() as u32).to_le_bytes());
            b.extend_from_slice(&p);
        }
        b
    }

    #[test]
    fn un_contenedor_de_amd_da_la_revision_por_equivalencia() {
        let b = contenedor_amd(
            0x00A2_0F10,
            0xA210,
            &[
                (0x0A20_1016, 0xA210),
                (0x0A20_1210, 0xA210),
                (0x0999, 0x1111),
            ],
        );
        let (eq, parches) = analizar_amd(&b);
        assert_eq!(eq.get(&0x00A2_0F10), Some(&0xA210));
        assert_eq!(parches.len(), 3);
        let dir = std::env::temp_dir().join(format!("aegis-ucode-amd-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("amd-ucode")).expect("dir");
        std::fs::write(dir.join("amd-ucode/microcode_amd_fam19h.bin"), &b).expect("escribir");
        let cpu = Cpu {
            fabricante: "AuthenticAMD".into(),
            familia: 0x19,
            modelo: 0x21,
            escalon: 0,
            revisiones: vec![0x0A20_1016],
            virtualizada: false,
        };
        let r = referencia(&cpu, &dir, None).expect("referencia");
        assert_eq!(r.revision, 0x0A20_1210);
        let c = evaluar(&Ok(cpu), &Ok(r));
        assert!(format!("{:?}", c.estado).contains("ATRASADO"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cpu(revs: &[u32], virt: bool) -> Result<Cpu, String> {
        Ok(Cpu {
            fabricante: "GenuineIntel".into(),
            familia: 6,
            modelo: 0xA5,
            escalon: 2,
            revisiones: revs.to_vec(),
            virtualizada: virt,
        })
    }

    fn refe(r: u32) -> Result<Referencia, String> {
        Ok(Referencia {
            revision: r,
            fecha: Some("2024-01-02".into()),
            fichero: "06-a5-02".into(),
        })
    }

    #[test]
    fn las_cuatro_respuestas_de_la_comparacion() {
        assert_eq!(
            evaluar(&cpu(&[0xFA, 0xFA], false), &refe(0xFA)).estado,
            CheckState::Ok
        );
        assert!(
            format!("{:?}", evaluar(&cpu(&[0xF0], false), &refe(0xFA)).estado).contains("ATRASADO")
        );
        assert!(format!(
            "{:?}",
            evaluar(&cpu(&[0xF0, 0xFA], false), &refe(0xFA)).estado
        )
        .contains("DISTINTAS"));
        let oculta = evaluar(&cpu(&[u32::MAX], true), &refe(0xFA));
        let m = format!("{:?}", oculta.estado);
        assert!(matches!(oculta.estado, CheckState::Indeterminado(_)), "{m}");
        assert!(m.contains("hipervisor") && m.contains("0xfa"), "{m}");
        assert!(matches!(
            evaluar(&cpu(&[0xF0], false), &Err("sin paquete".into())).estado,
            CheckState::Indeterminado(_)
        ));
    }

    #[test]
    fn cpuinfo_se_analiza_con_todas_sus_cpu() {
        let t = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 165\nstepping\t: 2\nmicrocode\t: 0xf8\nflags\t\t: fpu vmx hypervisor\n\n\
                 processor\t: 1\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 165\nstepping\t: 2\nmicrocode\t: 0xf8\nflags\t\t: fpu\n";
        let c = analizar_cpuinfo(t).expect("cpuinfo");
        assert_eq!((c.familia, c.modelo, c.escalon), (6, 165, 2));
        assert_eq!(c.revisiones, vec![0xf8, 0xf8]);
        assert!(c.virtualizada);
        assert!(analizar_cpuinfo("nada").is_err());
    }

    /// LOS FICHEROS REALES DEL FABRICANTE. Si el paquete esta instalado, cada
    /// actualizacion de cada fichero tiene que sumar cero: si no, o el lector
    /// esta mal o el fichero no es de Intel.
    #[test]
    fn los_ficheros_reales_de_intel_suman_cero_todos() {
        let dir = Path::new("/lib/firmware/intel-ucode");
        let Ok(e) = std::fs::read_dir(dir) else {
            omitir(
                &format!(
                    "{} no existe (paquete intel-microcode no instalado)",
                    dir.display()
                ),
                Requisito::Herramienta("intel-microcode"),
            );
            return;
        };
        let (mut ficheros, mut actualizaciones) = (0, 0);
        for x in e.flatten() {
            let b = std::fs::read(x.path()).expect("leer");
            let a = analizar_intel(&b);
            assert!(
                !a.is_empty(),
                "{} no tiene ninguna actualizacion legible",
                x.path().display()
            );
            for u in &a {
                assert!(
                    u.suma_ok,
                    "{}: revision {:#x} no suma cero",
                    x.path().display(),
                    u.revision
                );
            }
            ficheros += 1;
            actualizaciones += a.len();
        }
        eprintln!("microcodigo de Intel real: {ficheros} ficheros, {actualizaciones} actualizaciones, todas integras");
    }

    /// ESTA CPU contra SU fichero del fabricante.
    #[test]
    fn la_cpu_real_de_esta_maquina_contra_su_microcodigo_del_fabricante() {
        let Ok(t) = std::fs::read_to_string("/proc/cpuinfo") else {
            omitir("/proc/cpuinfo no se puede leer", Requisito::Entorno);
            return;
        };
        let c = analizar_cpuinfo(&t);
        let r = c
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|c| referencia(c, Path::new("/lib/firmware"), None));
        let comp = evaluar(&c, &r);
        eprintln!("CPU: {c:?}\nreferencia: {r:?}\n{}", comp.linea());
    }
}
