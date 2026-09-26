//! La comparacion con CHIPSEC, como dato y no como folleto.
//!
//! # Como se mide
//!
//! CHIPSEC no se ha podido ejecutar en la maquina de integracion: su controlador
//! de kernel se compila contra las cabeceras del kernel en uso, y el kernel de
//! WSL no las publica. Asi que la comparacion no es de resultados sobre la misma
//! placa —que es la que valdria y queda declarada como pendiente—, sino de
//! **modulos equivalentes**: para cada modulo que CHIPSEC publica en su arbol
//! (`chipsec/modules/common` y `chipsec/modules/tools`), que comprobacion de aqui
//! mira lo mismo, o por que ninguna.
//!
//! La tabla es codigo y una prueba la recorre: cada identificador que cita tiene
//! que existir en el informe de plataforma, y cada modulo de CHIPSEC que una
//! comprobacion declara tiene que estar en la tabla. Asi no puede quedarse atras
//! el dia que se anada o se quite una comprobacion.
//!
//! # Las cuatro respuestas
//!
//! - **Cubierto**: una o varias comprobaciones miran lo mismo.
//! - **Parcial**: se mira una parte, y se dice cual falta.
//! - **No cubierto**: CHIPSEC lo mira y aqui no; es una derrota y se escribe asi.
//! - **Excluido**: el modulo **escribe o ataca** para confirmar (fuzzing de SMI,
//!   escritura de variables, reprogramar BARs). Aqui no se hace por diseno: un
//!   escaner no confirma un fallo explotandolo, y una auditoria que puede dejar
//!   una placa inservible no corre desatendida en cien mil maquinas. No se cuenta
//!   como victoria ni como derrota: se cuenta aparte.

/// Como cubre este crate un modulo de CHIPSEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cobertura {
    /// Cubierto por estas comprobaciones.
    Cubierto(&'static [&'static str]),
    /// Cubierto en parte, con lo que falta.
    Parcial(&'static [&'static str], &'static str),
    /// No cubierto, con el motivo.
    NoCubierto(&'static str),
    /// Excluido por diseno: el modulo escribe o ataca.
    Excluido(&'static str),
}

/// Un modulo de CHIPSEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modulo {
    /// Nombre (`common.bios_wp`).
    pub nombre: &'static str,
    /// Que comprueba, en una frase.
    pub que: &'static str,
    /// Como se cubre aqui.
    pub cobertura: Cobertura,
}

const fn m(nombre: &'static str, que: &'static str, cobertura: Cobertura) -> Modulo {
    Modulo {
        nombre,
        que,
        cobertura,
    }
}

/// La tabla.
pub const MODULOS: &[Modulo] = &[
    m("common.bios_wp", "proteccion de escritura de la region BIOS (BLE, SMM_BWP, PRx)", Cobertura::Cubierto(&["spi-proteccion-escritura"])),
    m("common.spi_lock", "bloqueo de la configuracion del controlador SPI (FLOCKDN)", Cobertura::Cubierto(&["spi-flockdn"])),
    m("common.spi_access", "permisos del anfitrion sobre las regiones de la flash (FRAP)", Cobertura::Cubierto(&["spi-acceso-regiones"])),
    m("common.spi_desc", "el descriptor de flash no es escribible", Cobertura::Cubierto(&["spi-acceso-regiones"])),
    m("common.spi_fdopss", "puente de anulacion del descriptor", Cobertura::Cubierto(&["spi-anulacion-descriptor"])),
    m("common.bios_ts", "bloqueo del intercambio de bloque de arranque (BILD)", Cobertura::Cubierto(&["spi-bloqueo-arranque"])),
    m("common.bios_smi", "SMI_LOCK, GBL_SMI_EN y el bloqueo del TCO", Cobertura::Parcial(&["chipset-bloqueo-smi"], "GBL_SMI_EN y TCO_LOCK viven en puertos de E/S del PMC, y leer E/S por /dev/port no se hace; se mira SMI_LOCK, que es el que impide cambiarlos")),
    m("common.smm", "SMRAMC bloqueada (D_LCK) y cerrada", Cobertura::Cubierto(&["smm-bloqueo-smramc"])),
    m("common.smm_dma", "TSEG protegido frente a DMA", Cobertura::Cubierto(&["smm-tseg-dma"])),
    m("common.smrr", "SMRR activo y cubriendo SMRAM", Cobertura::Cubierto(&["smm-smrr", "smm-smram-ilegible"])),
    m("common.smm_code_chk", "SMM no ejecuta codigo fuera de SMRAM", Cobertura::Cubierto(&["smm-codigo-fuera-de-smram"])),
    m("common.memconfig", "bloqueo de los registros del mapa de memoria", Cobertura::Cubierto(&["chipset-bloqueos-memoria"])),
    m("common.remap", "configuracion de REMAPBASE/REMAPLIMIT", Cobertura::Parcial(&["chipset-bloqueos-memoria"], "se comprueba que esten bloqueados, no la coherencia de sus valores con TOUUD")),
    m("common.memlock", "bloqueo de la configuracion de memoria (LT_LOCK_MEMORY)", Cobertura::Cubierto(&["cpu-bloqueo-memoria-lt"])),
    m("common.ia32cfg", "IA32_FEATURE_CONTROL bloqueado en todas las CPU", Cobertura::Cubierto(&["cpu-bloqueo-feature-control"])),
    m("common.debugenabled", "interfaz de depuracion por sonda deshabilitada", Cobertura::Cubierto(&["cpu-depuracion"])),
    m("common.me_mfg_mode", "el ME no esta en modo fabricacion", Cobertura::Cubierto(&["chipset-modo-me"])),
    m("common.spd_wd", "escritura de la SPD por SMBus deshabilitada", Cobertura::Cubierto(&["chipset-spd-escritura"])),
    m("common.rtclock", "bloqueo de la RAM del reloj (RTC)", Cobertura::NoCubierto("el bloqueo vive en el espacio RCBA/PCR del PCH, que en la serie 100+ solo se alcanza por el P2SB")),
    m("common.bios_kbrd_buffer", "el firmware limpia el bufer de teclado de la contrasena de BIOS", Cobertura::NoCubierto("exige leer la zona de datos de la BIOS en memoria baja; no se ha implementado")),
    m("common.sgx_check", "configuracion de SGX", Cobertura::NoCubierto("SGX esta retirado en los clientes desde la 11.a generacion; no se ha implementado")),
    m("common.uefi.s3bootscript", "el script de reanudacion S3 esta protegido", Cobertura::NoCubierto("exige localizar y leer el script de arranque en memoria; no se ha implementado")),
    m("common.cpu.cpu_info", "identificacion de la CPU", Cobertura::Cubierto(&["cpu-mitigaciones", "cpu-microcodigo"])),
    m("common.cpu.spectre_v2", "mitigacion de Spectre v2", Cobertura::Cubierto(&["cpu-mitigaciones"])),
    m("common.cpu.ia_untrusted", "modo IA_UNTRUSTED", Cobertura::NoCubierto("no se ha implementado")),
    m("common.secureboot.variables", "atributos de PK, KEK, db y dbx y estado de Secure Boot", Cobertura::Cubierto(&["uefi-atributos-seguridad", "uefi-secure-boot-imponiendo"])),
    m("common.uefi.access_uefispec", "atributos de las variables conforme a la especificacion", Cobertura::Parcial(&["uefi-atributos-seguridad"], "se comprueban las variables de seguridad, no todas las que define la especificacion")),
    m("tools.uefi.scan_image", "compara la imagen del firmware con una lista conocida", Cobertura::Cubierto(&["spi-ficheros"])),
    m("tools.uefi.scan_blocked", "busca modulos bloqueados en la imagen", Cobertura::Cubierto(&["spi-ficheros"])),
    m("tools.uefi.reputation", "consulta la reputacion de cada modulo en un servicio externo", Cobertura::NoCubierto("enviar hashes de firmware a un tercero revela la plataforma; si se quisiera, iria por el estrangulamiento de difusion, no desde el agente")),
    m("tools.smm.smm_ptr", "prueba los manejadores de SMI con punteros hostiles", Cobertura::Excluido("envia SMI con punteros elegidos para provocar escrituras en memoria: es un ataque, y puede dejar la maquina colgada")),
    m("tools.smm.rogue_mmio_bar", "reprograma BARs para atrapar escrituras de SMM", Cobertura::Excluido("reprograma la configuracion de dispositivos vivos")),
    m("tools.uefi.uefivar_fuzz", "fuzzing de variables UEFI", Cobertura::Excluido("escribe variables UEFI; una escritura mala ha dejado placas sin arrancar")),
    m("tools.cpu.sinkhole", "prueba la vulnerabilidad Sinkhole", Cobertura::Excluido("reubica el APIC sobre SMRAM para comprobar el fallo: es el exploit")),
    m("tools.secureboot.te", "prueba la confusion de cabeceras TE en Secure Boot", Cobertura::Excluido("escribe un binario modificado en la ESP y reinicia")),
    m("tools.vmm", "fuzzing del hipervisor (cpuid, E/S, MSR, PCIe, hiperllamadas)", Cobertura::Excluido("ataca al hipervisor anfitrion desde el invitado")),
];

/// Recuento: (cubiertos, parciales, no cubiertos, excluidos).
#[must_use]
pub fn recuento() -> (usize, usize, usize, usize) {
    MODULOS
        .iter()
        .fold((0, 0, 0, 0), |(c, p, n, e), x| match x.cobertura {
            Cobertura::Cubierto(_) => (c + 1, p, n, e),
            Cobertura::Parcial(..) => (c, p + 1, n, e),
            Cobertura::NoCubierto(_) => (c, p, n + 1, e),
            Cobertura::Excluido(_) => (c, p, n, e + 1),
        })
}

/// Lo que este crate audita y CHIPSEC no tiene como modulo.
pub const SOLO_AQUI: &[(&str, &str)] = &[
    (
        "acpi-wpbt",
        "WPBT: el binario que el firmware ordena ejecutar en cada arranque",
    ),
    (
        "aml-metodos-automaticos",
        "el AML que el sistema ejecuta solo, contra linea base",
    ),
    (
        "cadena-resumenes",
        "el texto de cada evento del registro de arranque corresponde a lo que se midio",
    ),
    (
        "cadena-secure-boot-coherente",
        "Secure Boot medido frente a Secure Boot actual",
    ),
    (
        "cadena-pcr-reproducidos",
        "los PCR del TPM salen del registro",
    ),
    (
        "cadena-controladores-pci",
        "las option ROM que el firmware ejecuto, contra linea base",
    ),
    (
        "option-rom-integridad",
        "las imagenes de expansion PCI, contra linea base",
    ),
    (
        "iommu-proteccion-dma",
        "IOMMU declarado, activo y protegiendo desde el arranque",
    ),
    (
        "smm-wsmt",
        "las mitigaciones de SMM que declara el firmware",
    ),
    (
        "cpu-microcodigo",
        "el microcodigo frente al publicado por el fabricante",
    ),
    (
        "cpu-boot-guard",
        "Boot Guard verificando el bloque de arranque",
    ),
    (
        "uefi-entradas-arranque",
        "arranques de una sola vez y primeras entradas anomalas",
    ),
    ("uefi-dbx", "lista de revocacion presente y no vacia"),
];

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn cada_identificador_de_la_tabla_existe_en_el_informe() {
        let ids = crate::plataforma::pruebas::ids_posibles();
        // Estos dos solo salen cuando hay imagen de ROM o tablas ACPI con WPBT.
        let condicionales = ["spi-ficheros", "acpi-wpbt"];
        for x in MODULOS {
            let citados: &[&str] = match x.cobertura {
                Cobertura::Cubierto(c) | Cobertura::Parcial(c, _) => c,
                _ => &[],
            };
            for id in citados {
                assert!(
                    ids.contains(id) || condicionales.contains(id),
                    "{}: cita {id}, que no existe",
                    x.nombre
                );
            }
        }
        for (id, _) in SOLO_AQUI {
            assert!(
                ids.contains(id) || condicionales.contains(id),
                "SOLO_AQUI cita {id}, que no existe"
            );
        }
    }

    #[test]
    fn cada_modulo_que_declara_una_comprobacion_esta_en_la_tabla() {
        let d = std::env::temp_dir().join(format!("aegis-chipsec-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let inf = crate::plataforma::auditar_plataforma(
            &crate::plataforma::Raices::bajo(&d),
            &crate::linea_base::LineaBase::default(),
            None,
        );
        let _ = std::fs::remove_dir_all(&d);
        for c in &inf.comprobaciones {
            for m in c.chipsec {
                assert!(
                    MODULOS.iter().any(|x| x.nombre == *m),
                    "{} declara {m}, que no esta en la tabla",
                    c.id
                );
            }
        }
    }

    #[test]
    fn el_recuento_cuadra_y_los_nombres_no_se_repiten() {
        let (c, p, n, e) = recuento();
        assert_eq!(c + p + n + e, MODULOS.len());
        let mut v: Vec<_> = MODULOS.iter().map(|x| x.nombre).collect();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), MODULOS.len());
        eprintln!("CHIPSEC: {} modulos — {c} cubiertos, {p} parciales, {n} no cubiertos, {e} excluidos por escribir o atacar; {} comprobaciones sin equivalente en CHIPSEC", MODULOS.len(), SOLO_AQUI.len());
    }
}
