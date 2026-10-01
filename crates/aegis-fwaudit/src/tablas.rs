//! Las tablas ACPI que dicen algo de la seguridad de la plataforma, decodificadas
//! campo a campo.
//!
//! # Todas las tablas, no solo WPBT
//!
//! La FASE 67 miraba de cada tabla la cabecera y buscaba un ejecutable dentro;
//! el contenido solo lo interpretaba en WPBT. Pero varias tablas son
//! **declaraciones del firmware sobre su propia seguridad**, y leerlas es la
//! forma de saber que prometio:
//!
//! | Tabla | Que declara |
//! |---|---|
//! | FADT | el puerto por el que el SO dispara un SMI (`SMI_CMD`), y si la plataforma es de hardware reducido |
//! | DMAR (Intel) / IVRS (AMD) | que hay IOMMU, y si el firmware protegio la memoria frente a DMA durante el arranque |
//! | WSMT | que mitigaciones aplica el codigo de SMM a los punteros que recibe del SO |
//! | MCFG | donde esta la ventana de configuracion PCI por memoria |
//! | TPM2 | que hay un TPM 2.0 y como se le habla |
//!
//! Una tabla que falta o que se queda corta no se inventa: su decodificacion
//! devuelve `None` y la comprobacion dice que faltaba.

use aegis_firmware::report::CheckState;

use crate::acpi::{ConjuntoTablas, TablaAcpi};
use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};

fn u16_en(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_en(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_en(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o.checked_add(8)?)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Lo que importa de la FADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fadt {
    /// Revision de la tabla.
    pub revision: u8,
    /// Puerto de E/S con el que el SO pide cosas a SMM. 0 = no hay.
    pub smi_cmd: u32,
    /// Banderas de la FADT.
    pub banderas: u32,
    /// Direccion de 64 bits de la DSDT, si la revision la trae.
    pub x_dsdt: Option<u64>,
}

impl Fadt {
    /// Decodifica una FADT (firma `FACP`).
    #[must_use]
    pub fn analizar(t: &TablaAcpi) -> Option<Fadt> {
        if &t.cabecera.firma != b"FACP" {
            return None;
        }
        let b = &t.bytes;
        Some(Fadt {
            revision: t.cabecera.revision,
            smi_cmd: u32_en(b, 48)?,
            banderas: u32_en(b, 112).unwrap_or(0),
            x_dsdt: u64_en(b, 140),
        })
    }

    /// Bit 20: plataforma de hardware reducido (sin SMI_CMD ni PM1 clasicos).
    #[must_use]
    pub const fn hardware_reducido(&self) -> bool {
        self.banderas & (1 << 20) != 0
    }
}

/// La DMAR de Intel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dmar {
    /// Anchura de direccion del anfitrion (+1).
    pub anchura: u8,
    /// Banderas.
    pub banderas: u8,
    /// Unidades de remapeo (DRHD).
    pub unidades: usize,
    /// Regiones reservadas (RMRR): memoria a la que un dispositivo sigue
    /// pudiendo acceder por DMA aunque haya IOMMU.
    pub regiones_reservadas: usize,
}

impl Dmar {
    /// Decodifica una DMAR.
    #[must_use]
    pub fn analizar(t: &TablaAcpi) -> Option<Dmar> {
        if &t.cabecera.firma != b"DMAR" {
            return None;
        }
        let b = &t.bytes;
        let anchura = *b.get(36)?;
        let banderas = *b.get(37)?;
        let (mut unidades, mut regiones_reservadas) = (0, 0);
        let mut pos = 48usize;
        // Cada estructura declara su longitud; una de longitud menor que su
        // propia cabecera pararia el recorrido en vez de colgarlo.
        while let (Some(tipo), Some(largo)) = (u16_en(b, pos), u16_en(b, pos + 2)) {
            if largo < 4 {
                break;
            }
            match tipo {
                0 => unidades += 1,
                1 => regiones_reservadas += 1,
                _ => {}
            }
            pos += largo as usize;
        }
        Some(Dmar {
            anchura,
            banderas,
            unidades,
            regiones_reservadas,
        })
    }

    /// Bit 2, `DMA_CTRL_PLATFORM_OPT_IN`: el firmware protegio la memoria frente
    /// a DMA durante el arranque y pide al SO que mantenga la proteccion.
    #[must_use]
    pub const fn proteccion_dma_desde_el_arranque(&self) -> bool {
        self.banderas & 0x04 != 0
    }
}

/// La IVRS de AMD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ivrs {
    /// Bloques de definicion de IOMMU (IVHD).
    pub bloques: usize,
}

impl Ivrs {
    /// Decodifica una IVRS.
    #[must_use]
    pub fn analizar(t: &TablaAcpi) -> Option<Ivrs> {
        if &t.cabecera.firma != b"IVRS" {
            return None;
        }
        let b = &t.bytes;
        let mut bloques = 0;
        let mut pos = 48usize;
        while let (Some(tipo), Some(largo)) = (b.get(pos).copied(), u16_en(b, pos + 2)) {
            if largo < 4 {
                break;
            }
            if matches!(tipo, 0x10 | 0x11 | 0x40) {
                bloques += 1;
            }
            pos += largo as usize;
        }
        Some(Ivrs { bloques })
    }
}

/// La WSMT: que protege el codigo de SMM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wsmt(pub u32);

impl Wsmt {
    /// Decodifica una WSMT.
    #[must_use]
    pub fn analizar(t: &TablaAcpi) -> Option<Wsmt> {
        (&t.cabecera.firma == b"WSMT").then(|| u32_en(&t.bytes, 36).map(Wsmt))?
    }
    /// Bit 0: los buferes de comunicacion con SMM estan fijos (no los elige el SO).
    #[must_use]
    pub const fn buferes_fijos(self) -> bool {
        self.0 & 1 != 0
    }
    /// Bit 1: SMM valida los punteros anidados que recibe dentro de esos buferes.
    #[must_use]
    pub const fn punteros_anidados(self) -> bool {
        self.0 & 2 != 0
    }
    /// Bit 2: los recursos criticos del sistema estan bloqueados frente a SMM.
    #[must_use]
    pub const fn recursos_protegidos(self) -> bool {
        self.0 & 4 != 0
    }
}

/// Una ventana ECAM de la MCFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VentanaEcam {
    /// Direccion fisica base.
    pub base: u64,
    /// Segmento PCI.
    pub segmento: u16,
    /// Primer bus.
    pub bus_inicio: u8,
    /// Ultimo bus.
    pub bus_fin: u8,
}

/// Decodifica la MCFG.
#[must_use]
pub fn analizar_mcfg(t: &TablaAcpi) -> Option<Vec<VentanaEcam>> {
    if &t.cabecera.firma != b"MCFG" {
        return None;
    }
    Some(
        t.bytes
            .get(44..)?
            .chunks_exact(16)
            .map(|e| VentanaEcam {
                base: u64::from_le_bytes(e[0..8].try_into().unwrap_or([0; 8])),
                segmento: u16::from_le_bytes([e[8], e[9]]),
                bus_inicio: e[10],
                bus_fin: e[11],
            })
            .collect(),
    )
}

/// Lo que importa de la TPM2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tpm2 {
    /// Metodo de arranque (2 ACPI, 6 TIS, 7 CRB, 8 CRB+ACPI...).
    pub metodo_arranque: u32,
}

impl Tpm2 {
    /// Decodifica una TPM2.
    #[must_use]
    pub fn analizar(t: &TablaAcpi) -> Option<Tpm2> {
        (&t.cabecera.firma == b"TPM2")
            .then(|| u32_en(&t.bytes, 48).map(|m| Tpm2 { metodo_arranque: m }))?
    }
}

/// Todas las tablas tipadas de un conjunto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tipadas {
    /// FADT.
    pub fadt: Option<Fadt>,
    /// DMAR.
    pub dmar: Option<Dmar>,
    /// IVRS.
    pub ivrs: Option<Ivrs>,
    /// WSMT.
    pub wsmt: Option<Wsmt>,
    /// Ventanas ECAM.
    pub mcfg: Option<Vec<VentanaEcam>>,
    /// TPM2.
    pub tpm2: Option<Tpm2>,
}

/// Decodifica las tablas tipadas del conjunto.
#[must_use]
pub fn decodificar(c: &ConjuntoTablas) -> Tipadas {
    let f = |firma: &[u8; 4]| c.por_firma(firma);
    Tipadas {
        fadt: f(b"FACP").and_then(Fadt::analizar),
        dmar: f(b"DMAR").and_then(Dmar::analizar),
        ivrs: f(b"IVRS").and_then(Ivrs::analizar),
        wsmt: f(b"WSMT").and_then(Wsmt::analizar),
        mcfg: f(b"MCFG").and_then(analizar_mcfg),
        tpm2: f(b"TPM2").and_then(Tpm2::analizar),
    }
}

/// La proteccion frente a DMA.
///
/// `unidades_iommu_activas` es lo que dice `/sys/class/iommu`: el firmware puede
/// declarar un IOMMU que el kernel no usa (`intel_iommu=off`), y una promesa del
/// firmware que nadie cumple no protege nada.
#[must_use]
pub fn evaluar_iommu(
    t: &Tipadas,
    unidades_iommu_activas: usize,
    virtualizada: bool,
    hay_acpi: bool,
) -> Comprobacion {
    let declarado = t.dmar.as_ref().map(|d| d.unidades).unwrap_or(0)
        + t.ivrs.as_ref().map(|i| i.bloques).unwrap_or(0);
    let estado = if !hay_acpi {
        CheckState::NoAplicable(
            "no hay tablas ACPI legibles: no se puede saber si el firmware declara IOMMU".into(),
        )
    } else if declarado == 0 && t.dmar.is_none() && t.ivrs.is_none() {
        if virtualizada {
            CheckState::NoAplicable(
                "maquina virtual sin DMAR ni IVRS: el DMA de los dispositivos lo arbitra el \
                 hipervisor, y desde el invitado no se puede auditar"
                    .into(),
            )
        } else {
            CheckState::Fallo(
                "el firmware no declara ningun IOMMU (ni DMAR ni IVRS): cualquier dispositivo \
                 con DMA —Thunderbolt, una tarjeta PCIe— lee y escribe toda la memoria"
                    .into(),
            )
        }
    } else if unidades_iommu_activas == 0 {
        CheckState::Fallo(format!(
            "el firmware declara {declarado} unidad(es) de IOMMU pero el kernel no usa ninguna \
             (/sys/class/iommu vacio: ¿intel_iommu=off o amd_iommu=off?). Declarado y apagado \
             protege lo mismo que no tenerlo"
        ))
    } else if t
        .dmar
        .as_ref()
        .is_some_and(|d| !d.proteccion_dma_desde_el_arranque())
    {
        CheckState::Fallo(format!(
            "IOMMU activo ({unidades_iommu_activas} unidad(es)), pero la DMAR no lleva \
             DMA_CTRL_PLATFORM_OPT_IN: el firmware no protegio la memoria frente a DMA durante \
             el arranque, que es cuando atacan los dispositivos de Thunderbolt"
        ))
    } else {
        CheckState::Ok
    };
    Comprobacion::nueva(
        "iommu-proteccion-dma",
        Superficie::Iommu,
        Naturaleza::Exposicion,
        estado,
    )
}

/// Las mitigaciones de SMM que declara el firmware (WSMT).
#[must_use]
pub fn evaluar_wsmt(t: &Tipadas, virtualizada: bool, hay_acpi: bool) -> Comprobacion {
    let estado = match t.wsmt {
        None if !hay_acpi => CheckState::NoAplicable(
            "no hay tablas ACPI legibles: no se puede saber si el firmware publica WSMT".into(),
        ),
        None if virtualizada => CheckState::NoAplicable(
            "maquina virtual sin WSMT: el SMM de la maquina lo ejecuta el hipervisor".into(),
        ),
        None => CheckState::Fallo(
            "el firmware no publica WSMT: no declara ninguna mitigacion frente a los punteros \
             que SMM recibe del sistema operativo, que es la via clasica de ataque a SMM"
                .into(),
        ),
        Some(w) => {
            let mut faltan = Vec::new();
            if !w.buferes_fijos() {
                faltan.push("buferes de comunicacion fijos");
            }
            if !w.punteros_anidados() {
                faltan.push("validacion de punteros anidados");
            }
            if !w.recursos_protegidos() {
                faltan.push("proteccion de recursos del sistema");
            }
            if faltan.is_empty() {
                CheckState::Ok
            } else {
                CheckState::Fallo(format!(
                    "WSMT={:#x}: SMM no declara {}",
                    w.0,
                    faltan.join(", ")
                ))
            }
        }
    };
    Comprobacion::nueva("smm-wsmt", Superficie::Smm, Naturaleza::Exposicion, estado)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::acpi::analizar_tabla;
    use crate::acpi::pruebas::tabla;
    use aegis_prueba::{omitir, Requisito};
    use std::path::Path;

    fn t(firma: &[u8; 4], cuerpo: &[u8]) -> TablaAcpi {
        analizar_tabla(Path::new("/x"), tabla(firma, cuerpo), false).expect("valida")
    }

    fn dmar(banderas: u8, estructuras: &[(u16, u16)]) -> TablaAcpi {
        let mut c = vec![0u8; 12];
        c[0] = 38;
        c[1] = banderas;
        for (tipo, largo) in estructuras {
            let mut e = vec![0u8; *largo as usize];
            e[0..2].copy_from_slice(&tipo.to_le_bytes());
            e[2..4].copy_from_slice(&largo.to_le_bytes());
            c.extend(e);
        }
        t(b"DMAR", &c)
    }

    #[test]
    fn la_dmar_cuenta_sus_unidades_y_dice_si_protegio_el_arranque() {
        let d = Dmar::analizar(&dmar(0x05, &[(0, 16), (0, 24), (1, 32)])).expect("dmar");
        assert_eq!(d.unidades, 2);
        assert_eq!(d.regiones_reservadas, 1);
        assert!(d.proteccion_dma_desde_el_arranque());
        // Una estructura de longitud 0 no cuelga el recorrido.
        let mut c = vec![0u8; 12];
        c.extend([0, 0, 0, 0]);
        assert_eq!(Dmar::analizar(&t(b"DMAR", &c)).expect("dmar").unidades, 0);
    }

    #[test]
    fn iommu_declarado_activo_y_con_proteccion_de_arranque_pasa() {
        let ti = Tipadas {
            dmar: Dmar::analizar(&dmar(0x05, &[(0, 16)])),
            ..Default::default()
        };
        assert_eq!(evaluar_iommu(&ti, 1, false, true).estado, CheckState::Ok);
        let m = format!("{:?}", evaluar_iommu(&ti, 0, false, true).estado);
        assert!(m.contains("no usa ninguna"), "{m}");
        let sin_optin = Tipadas {
            dmar: Dmar::analizar(&dmar(0x01, &[(0, 16)])),
            ..Default::default()
        };
        assert!(
            format!("{:?}", evaluar_iommu(&sin_optin, 1, false, true).estado).contains("OPT_IN")
        );
        let nada = Tipadas::default();
        assert!(evaluar_iommu(&nada, 0, false, true).estado.es_fallo());
        assert!(matches!(
            evaluar_iommu(&nada, 0, true, true).estado,
            CheckState::NoAplicable(_)
        ));
    }

    #[test]
    fn la_wsmt_se_juzga_bit_a_bit() {
        let bien = Tipadas {
            wsmt: Wsmt::analizar(&t(b"WSMT", &7u32.to_le_bytes())),
            ..Default::default()
        };
        assert_eq!(evaluar_wsmt(&bien, false, true).estado, CheckState::Ok);
        let parcial = Tipadas {
            wsmt: Some(Wsmt(1)),
            ..Default::default()
        };
        let m = format!("{:?}", evaluar_wsmt(&parcial, false, true).estado);
        assert!(
            m.contains("punteros anidados") && m.contains("recursos"),
            "{m}"
        );
        assert!(evaluar_wsmt(&Tipadas::default(), false, true)
            .estado
            .es_fallo());
        assert!(matches!(
            evaluar_wsmt(&Tipadas::default(), true, true).estado,
            CheckState::NoAplicable(_)
        ));
    }

    #[test]
    fn mcfg_ivrs_y_tpm2_se_decodifican() {
        let mut m = vec![0u8; 8];
        m.extend(0xE000_0000u64.to_le_bytes());
        m.extend([0, 0, 0, 0xFF, 0, 0, 0, 0]);
        let v = analizar_mcfg(&t(b"MCFG", &m)).expect("mcfg");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].base, 0xE000_0000);
        assert_eq!(v[0].bus_fin, 0xFF);
        let mut i = vec![0u8; 12];
        i.extend([0x40, 0, 24, 0]);
        i.extend([0u8; 20]);
        assert_eq!(Ivrs::analizar(&t(b"IVRS", &i)).expect("ivrs").bloques, 1);
        let mut p = vec![0u8; 12];
        p.extend(7u32.to_le_bytes());
        assert_eq!(
            Tpm2::analizar(&t(b"TPM2", &p))
                .expect("tpm2")
                .metodo_arranque,
            7
        );
        // La firma equivocada no se decodifica como otra tabla.
        assert!(Fadt::analizar(&t(b"APIC", &[0; 200])).is_none());
    }

    /// LA FADT REAL DE ESTA MAQUINA.
    #[test]
    fn la_fadt_real_de_esta_maquina_se_decodifica() {
        let c = crate::acpi::leer_tablas_del_sistema();
        let Some(f) = c.por_firma(b"FACP") else {
            omitir("esta maquina no expone la FADT", Requisito::Acpi);
            return;
        };
        let fadt = Fadt::analizar(f).expect("una FADT real tiene que decodificarse");
        eprintln!(
            "FADT real: revision {}, SMI_CMD={:#x}, banderas={:#x}, hardware reducido={}, X_DSDT={:?}",
            fadt.revision, fadt.smi_cmd, fadt.banderas, fadt.hardware_reducido(), fadt.x_dsdt
        );
        let ti = decodificar(&c);
        assert!(ti.fadt.is_some());
    }
}
