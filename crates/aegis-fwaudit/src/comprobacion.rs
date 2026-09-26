//! Una comprobacion de plataforma: el tri-estado de siempre, mas **que clase de
//! cosa** es un fallo.
//!
//! # Por que hace falta un eje mas que el tri-estado
//!
//! Hasta la FASE 92 todo fallo de este crate era un **compromiso**: un checksum
//! ACPI roto, un fichero FFS reescrito, una WPBT que descarga y ejecuta. Eso no
//! tiene explicacion benigna, y es lo que el arbitro tiene que oir.
//!
//! Las superficies nuevas fallan de otra manera. Un BLE a cero, un SMRR sin
//! activar o un microcodigo atrasado **no son un implante**: son una puerta que
//! el fabricante dejo abierta y por la que un implante podria entrar. La inmensa
//! mayoria de las maquinas con esa puerta abierta no tienen a nadie dentro.
//!
//! Juntar las dos clases en un solo «fallo» produce los dos errores clasicos a la
//! vez: el arbitro recibe «sospechoso» sobre medio parque por una configuracion
//! de fabrica —y el analista aprende a ignorar la categoria—, y la exposicion
//! real, que es lo que un equipo de plataforma necesita para priorizar
//! actualizaciones de firmware, queda enterrada entre las alarmas. Por eso la
//! naturaleza es parte del tipo y viaja con cada comprobacion: al arbitro solo
//! llegan los compromisos; las exposiciones van al informe de postura.

use aegis_firmware::report::CheckState;

/// De que habla un fallo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Naturaleza {
    /// Hay indicios de que alguien actuo: no tiene explicacion benigna.
    Compromiso,
    /// La configuracion permitiria actuar, pero no dice que nadie lo hiciera.
    Exposicion,
}

impl Naturaleza {
    /// Nombre estable.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Naturaleza::Compromiso => "compromiso",
            Naturaleza::Exposicion => "exposicion",
        }
    }
}

/// La superficie de plataforma de la que habla una comprobacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Superficie {
    /// Tablas ACPI (cabeceras, WPBT, tablas tipadas).
    Acpi,
    /// Metodos AML de DSDT y SSDT.
    Aml,
    /// Contenido de la ROM SPI.
    RomSpi,
    /// Protecciones de escritura de la flash.
    ProteccionFlash,
    /// SMRAM y el modo de gestion del sistema.
    Smm,
    /// Bloqueos de configuracion del chipset y de la CPU.
    Chipset,
    /// IOMMU y proteccion contra DMA.
    Iommu,
    /// Mitigaciones de vulnerabilidades de CPU.
    Cpu,
    /// Microcodigo.
    Microcodigo,
    /// Variables UEFI y Secure Boot.
    VariablesUefi,
    /// Option ROMs de dispositivos PCI.
    OptionRom,
    /// La cadena de arranque medido.
    CadenaArranque,
}

impl Superficie {
    /// Nombre estable.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Superficie::Acpi => "acpi",
            Superficie::Aml => "aml",
            Superficie::RomSpi => "rom-spi",
            Superficie::ProteccionFlash => "proteccion-flash",
            Superficie::Smm => "smm",
            Superficie::Chipset => "chipset",
            Superficie::Iommu => "iommu",
            Superficie::Cpu => "cpu",
            Superficie::Microcodigo => "microcodigo",
            Superficie::VariablesUefi => "variables-uefi",
            Superficie::OptionRom => "option-rom",
            Superficie::CadenaArranque => "cadena-arranque",
        }
    }

    /// Todas, en orden estable.
    #[must_use]
    pub const fn todas() -> &'static [Superficie] {
        &[
            Superficie::Acpi,
            Superficie::Aml,
            Superficie::RomSpi,
            Superficie::ProteccionFlash,
            Superficie::Smm,
            Superficie::Chipset,
            Superficie::Iommu,
            Superficie::Cpu,
            Superficie::Microcodigo,
            Superficie::VariablesUefi,
            Superficie::OptionRom,
            Superficie::CadenaArranque,
        ]
    }
}

/// Una comprobacion de plataforma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comprobacion {
    /// Identificador corto y estable (`spi-ble`, `smm-dlck`...).
    pub id: &'static str,
    /// De que superficie habla.
    pub superficie: Superficie,
    /// Que clase de cosa es si falla.
    pub naturaleza: Naturaleza,
    /// El resultado, con el tri-estado de siempre.
    pub estado: CheckState,
    /// Los modulos de CHIPSEC que comprueban lo mismo, si los hay.
    pub chipsec: &'static [&'static str],
}

impl Comprobacion {
    /// Construye una comprobacion.
    #[must_use]
    pub fn nueva(
        id: &'static str,
        superficie: Superficie,
        naturaleza: Naturaleza,
        estado: CheckState,
    ) -> Comprobacion {
        Comprobacion {
            id,
            superficie,
            naturaleza,
            estado,
            chipsec: &[],
        }
    }

    /// Anota los modulos de CHIPSEC equivalentes.
    #[must_use]
    pub fn como_chipsec(mut self, modulos: &'static [&'static str]) -> Comprobacion {
        self.chipsec = modulos;
        self
    }

    /// Si es un fallo de la clase indicada.
    #[must_use]
    pub fn falla_como(&self, n: Naturaleza) -> bool {
        self.naturaleza == n && self.estado.es_fallo()
    }

    /// Si se pudo mirar: `Ok` o `Fallo`.
    #[must_use]
    pub fn se_miro(&self) -> bool {
        matches!(self.estado, CheckState::Ok | CheckState::Fallo(_))
    }

    /// Una linea legible.
    #[must_use]
    pub fn linea(&self) -> String {
        let estado = match &self.estado {
            CheckState::Ok => "OK".to_string(),
            CheckState::Fallo(m) => format!("{}: {m}", self.naturaleza.nombre().to_uppercase()),
            CheckState::NoAplicable(m) => format!("no aplicable ({m})"),
            CheckState::Indeterminado(m) => format!("indeterminado ({m})"),
        };
        format!("{:<16} {:<28} {estado}", self.superficie.nombre(), self.id)
    }
}

/// Atajo: `Ok` o `Fallo(motivo)` segun una condicion.
#[must_use]
pub fn ok_si(condicion: bool, motivo_fallo: impl FnOnce() -> String) -> CheckState {
    if condicion {
        CheckState::Ok
    } else {
        CheckState::Fallo(motivo_fallo())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_exposicion_no_cuenta_como_compromiso_ni_al_reves() {
        let c = Comprobacion::nueva(
            "spi-ble",
            Superficie::ProteccionFlash,
            Naturaleza::Exposicion,
            CheckState::Fallo("BLE=0".into()),
        );
        assert!(c.falla_como(Naturaleza::Exposicion));
        assert!(!c.falla_como(Naturaleza::Compromiso));
        assert!(c.se_miro());
    }

    #[test]
    fn no_aplicable_e_indeterminado_no_se_miraron() {
        for e in [
            CheckState::NoAplicable("x".into()),
            CheckState::Indeterminado("y".into()),
        ] {
            let c = Comprobacion::nueva("a", Superficie::Cpu, Naturaleza::Exposicion, e);
            assert!(!c.se_miro());
            assert!(!c.falla_como(Naturaleza::Exposicion));
        }
    }

    #[test]
    fn la_linea_dice_la_naturaleza_del_fallo() {
        let c = Comprobacion::nueva(
            "x",
            Superficie::Smm,
            Naturaleza::Compromiso,
            CheckState::Fallo("m".into()),
        );
        assert!(c.linea().contains("COMPROMISO: m"), "{}", c.linea());
    }

    #[test]
    fn los_nombres_de_superficie_son_unicos() {
        let mut v: Vec<_> = Superficie::todas().iter().map(|s| s.nombre()).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n);
    }
}
