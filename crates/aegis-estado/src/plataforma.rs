//! Proveedores de las tablas de plataforma y paquetes.
//!
//! # Lo que este modulo NO vuelve a escribir
//!
//! El inventario de paquetes ya existia: `aegis-vuln::inventory` lo lee desde la
//! FASE 20, parametrizado por raiz, y devuelve datos estructurados. Escribir un
//! segundo analizador de `dpkg` habria sido exactamente la duplicacion que esta
//! fase viene a corregir, asi que [`Paquetes`] envuelve el que hay.
//!
//! Lo mismo con el TPM y el arranque seguro: `aegis-firmware` los cubre desde la
//! FASE 49, y aqui solo se exponen como tabla.
//!
//! # Las tres respuestas de una mitigacion
//!
//! `/sys/devices/system/cpu/vulnerabilities/*` contesta una de tres cosas —«Not
//! affected», «Mitigation: ...» o «Vulnerable»— y las tres son distintas. Por
//! eso [`CPU_MITIGATIONS`] tiene dos booleanos y no uno: con una sola columna,
//! «este hardware no tiene el problema» y «el nucleo lo esta mitigando» se
//! escribirian igual, y la segunda la puede apagar alguien con `mitigations=off`
//! en la linea de arranque mientras que la primera no.

use aegis_parser::esquema::{plataforma as esq, Coste, Tabla as Esquema};

use crate::contexto::Contexto;
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

// ---------------------------------------------------------------------------
// packages
// ---------------------------------------------------------------------------

/// Los paquetes instalados.
#[derive(Debug, Clone, Copy, Default)]
pub struct Paquetes;

impl Tabla for Paquetes {
    fn esquema(&self) -> &'static Esquema {
        &esq::PACKAGES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let inventario = aegis_vuln::inventory::Inventory::collect(ctx.raiz());
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for (_, p) in inventario.packages.iter() {
            salida.examinadas += 1;
            c.texto("name", p.name.clone());
            c.texto("version", p.version.to_string());
            c.texto("arch", p.arch.clone());
            c.texto(
                "source",
                match p.source {
                    aegis_vuln::inventory::PackageSource::Dpkg => "dpkg",
                    aegis_vuln::inventory::PackageSource::Apk => "apk",
                    aegis_vuln::inventory::PackageSource::Rpm => "rpm",
                },
            );
            salida.filas.push(c.fin());
        }

        // EL MURO, declarado en la respuesta y no solo en la documentacion.
        //
        // En una maquina de la familia de RHEL la base de datos de paquetes es
        // un formato binario que el inventario todavia no lee. Devolver cero
        // filas ahi haria concluir que el servidor no tiene software instalado,
        // que es la clase de conclusion que hunde un informe.
        if salida.filas.is_empty() {
            let es_rpm = ctx.existe("var/lib/rpm") || ctx.existe("usr/lib/sysimage/rpm");
            salida.avisar(
                "el inventario de paquetes",
                if es_rpm {
                    MotivoNoLeible::NoExisteEnEsteNucleo {
                        interfaz: "lector de la base de datos binaria de RPM (muro declarado)",
                    }
                } else {
                    MotivoNoLeible::FuenteAusente {
                        ruta: "ni /var/lib/dpkg/status ni /lib/apk/db/installed".to_string(),
                    }
                },
            );
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// cpu_info
// ---------------------------------------------------------------------------

/// Lee el primer valor de una clave de `/proc/cpuinfo`.
fn campo_cpuinfo<'a>(texto: &'a str, clave: &str) -> Option<&'a str> {
    texto.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == clave).then(|| v.trim())
    })
}

/// El procesador.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpu;

impl Tabla for Cpu {
    fn esquema(&self) -> &'static Esquema {
        &esq::CPU_INFO
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/cpuinfo")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        let logicos = texto.lines().filter(|l| l.starts_with("processor")).count() as i64;
        let banderas = campo_cpuinfo(&texto, "flags")
            .or_else(|| campo_cpuinfo(&texto, "Features"))
            .unwrap_or("");

        salida.examinadas = 1;
        c.texto_opcional(
            "model",
            campo_cpuinfo(&texto, "model name").or_else(|| campo_cpuinfo(&texto, "Model")),
        );
        c.texto_opcional("vendor", campo_cpuinfo(&texto, "vendor_id"));
        c.entero("logical_cpus", logicos);
        if let Some(f) = campo_cpuinfo(&texto, "cpu family").and_then(|v| v.parse::<i64>().ok()) {
            c.entero("family", f);
        }
        if let Some(m) = campo_cpuinfo(&texto, "model").and_then(|v| v.parse::<i64>().ok()) {
            c.entero("model_id", m);
        }
        c.texto_opcional("microcode", campo_cpuinfo(&texto, "microcode"));
        // La bandera `hypervisor` la pone el propio procesador virtualizado: es
        // la forma barata de saber que esta maquina no es fisica.
        c.booleano(
            "hypervisor",
            banderas.split_whitespace().any(|f| f == "hypervisor"),
        );
        c.texto("flags", banderas);
        salida.filas.push(c.fin());
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// cpu_mitigations
// ---------------------------------------------------------------------------

/// Las mitigaciones de ejecucion especulativa.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mitigaciones;

/// Clasifica lo que dice el nucleo sobre una vulnerabilidad.
///
/// Devuelve `(mitigada, vulnerable)`, que son TRES estados y no dos: «no
/// afectada» es `(false, false)`, y es distinto de las otras dos.
pub fn clasificar_mitigacion(estado: &str) -> (bool, bool) {
    let e = estado.trim();
    if e.starts_with("Not affected") {
        return (false, false);
    }
    if e.starts_with("Vulnerable") {
        return (false, true);
    }
    if e.starts_with("Mitigation") {
        return (true, false);
    }
    // Lo que no encaja no se clasifica: decir «mitigada» ante una respuesta que
    // no se entiende es tranquilizar sin motivo.
    (false, false)
}

impl Tabla for Mitigaciones {
    fn esquema(&self) -> &'static Esquema {
        &esq::CPU_MITIGATIONS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let hijos = ctx.listar("sys/devices/system/cpu/vulnerabilities")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for ruta in hijos {
            let Some(nombre) = ruta.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(estado) = std::fs::read_to_string(&ruta) else {
                continue;
            };
            salida.examinadas += 1;
            let estado = estado.trim();
            let (mitigada, vulnerable) = clasificar_mitigacion(estado);
            c.texto("name", nombre);
            c.texto("status", estado);
            c.booleano("mitigated", mitigada);
            c.booleano("vulnerable", vulnerable);
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// memory_info
// ---------------------------------------------------------------------------

/// La memoria.
#[derive(Debug, Clone, Copy, Default)]
pub struct Memoria;

/// Lee un valor en kilobytes de `/proc/meminfo`.
fn kb_de_meminfo(texto: &str, clave: &str) -> Option<i64> {
    texto.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim() != clave {
            return None;
        }
        v.split_whitespace().next()?.parse().ok()
    })
}

impl Tabla for Memoria {
    fn esquema(&self) -> &'static Esquema {
        &esq::MEMORY_INFO
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/meminfo")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        salida.examinadas = 1;

        for (columna, clave) in [
            ("total_kb", "MemTotal"),
            ("free_kb", "MemFree"),
            ("available_kb", "MemAvailable"),
            ("swap_total_kb", "SwapTotal"),
            ("swap_free_kb", "SwapFree"),
        ] {
            // Una clave que no esta queda AUSENTE y no a cero: `MemAvailable` no
            // existe en nucleos antiguos, y un cero ahi se leeria como «esta
            // maquina no tiene memoria disponible».
            if let Some(v) = kb_de_meminfo(&texto, clave) {
                c.entero(columna, v);
            }
        }
        salida.filas.push(c.fin());
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// block_devices
// ---------------------------------------------------------------------------

/// Los dispositivos de bloques.
#[derive(Debug, Clone, Copy, Default)]
pub struct Discos;

impl Tabla for Discos {
    fn esquema(&self) -> &'static Esquema {
        &esq::BLOCK_DEVICES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let hijos = ctx.listar("sys/block")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for dir in hijos {
            let Some(nombre) = dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            salida.examinadas += 1;
            let leer = |hoja: &str| {
                std::fs::read_to_string(dir.join(hoja))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            let bandera = |hoja: &str| leer(hoja).map(|v| v == "1");

            c.texto("name", nombre);
            // `size` viene en sectores de 512 bytes, SIEMPRE, sea cual sea el
            // tamano real de sector del dispositivo. Multiplicar por el sector
            // fisico es el error clasico y da tamanos cuatro veces mayores.
            if let Some(sectores) = leer("size").and_then(|v| v.parse::<i64>().ok()) {
                c.entero("size_bytes", sectores.saturating_mul(512));
            }
            c.texto_opcional("model", leer("device/model"));
            if let Some(v) = bandera("removable") {
                c.booleano("removable", v);
            }
            if let Some(v) = bandera("queue/rotational") {
                c.booleano("rotational", v);
            }
            if let Some(v) = bandera("ro") {
                c.booleano("read_only", v);
            }
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// pci_devices
// ---------------------------------------------------------------------------

/// Los dispositivos PCI.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pci;

impl Tabla for Pci {
    fn esquema(&self) -> &'static Esquema {
        &esq::PCI_DEVICES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let hijos = ctx.listar("sys/bus/pci/devices")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for dir in hijos {
            let Some(slot) = dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            salida.examinadas += 1;
            let leer = |hoja: &str| {
                std::fs::read_to_string(dir.join(hoja))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            c.texto("slot", slot);
            c.texto_opcional("vendor_id", leer("vendor"));
            c.texto_opcional("device_id", leer("device"));
            c.texto_opcional("class", leer("class"));
            // El controlador es un enlace al modulo que lo maneja; un
            // dispositivo SIN controlador es uno que el nucleo no reconocio.
            c.texto_opcional(
                "driver",
                std::fs::read_link(dir.join("driver"))
                    .ok()
                    .and_then(|d| d.file_name().map(|n| n.to_string_lossy().to_string())),
            );
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// usb_devices
// ---------------------------------------------------------------------------

/// Los dispositivos USB.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usb;

impl Tabla for Usb {
    fn esquema(&self) -> &'static Esquema {
        &esq::USB_DEVICES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let hijos = ctx.listar("sys/bus/usb/devices")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for dir in hijos {
            let Some(puerto) = dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Las interfaces llevan `:` en el nombre y no son dispositivos.
            if puerto.contains(':') {
                continue;
            }
            let leer = |hoja: &str| {
                std::fs::read_to_string(dir.join(hoja))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            let Some(vendedor) = leer("idVendor") else {
                continue;
            };
            salida.examinadas += 1;
            c.texto("port", puerto);
            c.texto("vendor_id", vendedor);
            c.texto_opcional("product_id", leer("idProduct"));
            c.texto_opcional("manufacturer", leer("manufacturer"));
            c.texto_opcional("product", leer("product"));
            c.texto_opcional("serial", leer("serial"));
            c.texto_opcional("class", leer("bDeviceClass"));
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// firmware_info
// ---------------------------------------------------------------------------

/// El firmware.
#[derive(Debug, Clone, Copy, Default)]
pub struct Firmware;

impl Tabla for Firmware {
    fn esquema(&self) -> &'static Esquema {
        &esq::FIRMWARE_INFO
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let leer = |hoja: &str| {
            std::fs::read_to_string(ctx.ruta(hoja))
                .ok()
                .map(|s| s.trim().to_string())
        };
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        salida.examinadas = 1;

        c.texto_opcional("vendor", leer("sys/class/dmi/id/bios_vendor"));
        c.texto_opcional("version", leer("sys/class/dmi/id/bios_version"));
        c.texto_opcional("release_date", leer("sys/class/dmi/id/bios_date"));
        c.texto_opcional("product", leer("sys/class/dmi/id/product_name"));
        c.booleano("uefi", ctx.existe("sys/firmware/efi"));

        // El arranque seguro y el TPM los cubre `aegis-firmware` desde la FASE
        // 49: aqui solo se exponen como columnas.
        //
        // Se usa `imponiendo()` y no el campo `secure_boot` a secas, y la
        // diferencia no es un matiz: un firmware en MODO CONFIGURACION dice que
        // Secure Boot esta activo Y acepta que cualquiera matricule sus propias
        // claves, con lo que no impone absolutamente nada. Informar de esa
        // maquina como protegida seria el peor falso negativo posible, porque es
        // justo el estado en el que la deja quien quiere arrancar lo suyo.
        if ctx.es_el_sistema_real() {
            match aegis_firmware::uefi::estado_secure_boot() {
                Ok(estado) => {
                    c.booleano("secure_boot", estado.imponiendo());
                }
                // Sin UEFI o sin efivars no se afirma nada: `false` aqui diria
                // «el arranque seguro esta apagado», que es distinto de «esta
                // maquina no tiene arranque seguro que consultar».
                Err(_) => {
                    c.pon("secure_boot", aegis_parser::valor::Valor::Ausente);
                }
            }
        } else {
            c.pon("secure_boot", aegis_parser::valor::Valor::Ausente);
        }
        c.booleano(
            "tpm_present",
            ctx.existe("sys/class/tpm/tpm0") || ctx.existe("dev/tpm0"),
        );
        salida.filas.push(c.fin());
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// tpm_pcrs
// ---------------------------------------------------------------------------

/// Los registros del TPM.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pcrs;

impl Tabla for Pcrs {
    fn esquema(&self) -> &'static Esquema {
        &esq::TPM_PCRS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        // Sin TPM se DICE. Cero filas aqui haria que un informe concluyera que
        // el arranque medido no cuadra, cuando lo que pasa es que no hay nada
        // que medir.
        if !ctx.existe("sys/class/tpm/tpm0") {
            return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "TPM 2.0 (/sys/class/tpm/tpm0); esta maquina no tiene",
            });
        }

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for banco in ["sha256", "sha1", "sha384"] {
            let dir = format!("sys/class/tpm/tpm0/pcr-{banco}");
            let Ok(hijos) = ctx.listar(&dir) else {
                continue;
            };
            for ruta in hijos {
                let Some(indice) = ruta
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.parse::<i64>().ok())
                else {
                    continue;
                };
                let Ok(valor) = std::fs::read_to_string(&ruta) else {
                    continue;
                };
                salida.examinadas += 1;
                c.texto("bank", banco);
                c.entero("index", indice);
                c.texto("value", valor.trim());
                // Los PCR del 0 al 7 son los que mide el firmware durante el
                // arranque; del 8 en adelante los extiende el sistema operativo.
                c.booleano("measures_boot", (0..=7).contains(&indice));
                salida.filas.push(c.fin());
            }
        }

        if salida.filas.is_empty() {
            salida.avisar(
                "/sys/class/tpm/tpm0/pcr-*",
                MotivoNoLeible::SinPrivilegios {
                    operacion: "leer los registros del TPM",
                    necesita: "acceso de lectura a /sys/class/tpm",
                },
            );
        }
        Ok(salida)
    }
}

/// Las nueve tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Paquetes),
        Box::new(Cpu),
        Box::new(Mitigaciones),
        Box::new(Memoria),
        Box::new(Discos),
        Box::new(Pci),
        Box::new(Usb),
        Box::new(Firmware),
        Box::new(Pcrs),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
    }

    fn columna(t: &dyn Tabla, nombre: &str) -> usize {
        t.esquema()
            .columnas
            .iter()
            .position(|c| c.nombre == nombre)
            .unwrap_or_else(|| panic!("falta {nombre} en {}", t.nombre()))
    }

    #[test]
    fn las_tres_respuestas_de_una_mitigacion_se_distinguen() {
        // El fallo que esta funcion evita: con un solo booleano, «no afectada» y
        // «mitigada» se escriben igual, y la segunda la puede apagar alguien.
        assert_eq!(clasificar_mitigacion("Not affected"), (false, false));
        assert_eq!(
            clasificar_mitigacion("Mitigation: PTI"),
            (true, false),
            "una mitigacion activa"
        );
        assert_eq!(
            clasificar_mitigacion("Vulnerable: Clear CPU buffers attempted, no microcode"),
            (false, true)
        );
        // Una respuesta que no se entiende NO se da por mitigada.
        assert_eq!(clasificar_mitigacion("algo raro"), (false, false));
        assert_eq!(clasificar_mitigacion(""), (false, false));
    }

    #[test]
    fn el_cpuinfo_de_esta_maquina_se_lee() {
        let c = ctx();
        let r = Cpu.leer(&c, &Filtro::ninguno()).expect("leer cpuinfo");
        assert_eq!(r.filas.len(), 1);
        let i = columna(&Cpu, "logical_cpus");
        match r.filas[0].valor(i) {
            aegis_parser::valor::Valor::Entero(n) => assert!(*n >= 1, "al menos un procesador"),
            otro => panic!("logical_cpus no es entero: {otro:?}"),
        }
    }

    #[test]
    fn el_campo_de_cpuinfo_se_busca_por_clave_exacta() {
        let texto = "processor\t: 0\nmodel name\t: Un Procesador\nmodel\t: 85\n";
        assert_eq!(campo_cpuinfo(texto, "model name"), Some("Un Procesador"));
        // `model` no puede devolver el valor de `model name`.
        assert_eq!(campo_cpuinfo(texto, "model"), Some("85"));
        assert_eq!(campo_cpuinfo(texto, "no existe"), None);
    }

    #[test]
    fn la_memoria_de_esta_maquina_se_lee() {
        let c = ctx();
        let r = Memoria.leer(&c, &Filtro::ninguno()).expect("leer meminfo");
        let i = columna(&Memoria, "total_kb");
        match r.filas[0].valor(i) {
            aegis_parser::valor::Valor::Entero(n) => assert!(*n > 0),
            otro => panic!("total_kb no es entero: {otro:?}"),
        }
    }

    #[test]
    fn una_clave_de_meminfo_que_no_esta_queda_ausente() {
        // `MemAvailable` no existe en nucleos antiguos, y un cero ahi se leeria
        // como «no hay memoria disponible».
        let texto = "MemTotal:       16384 kB\nMemFree:         8192 kB\n";
        assert_eq!(kb_de_meminfo(texto, "MemTotal"), Some(16_384));
        assert_eq!(kb_de_meminfo(texto, "MemAvailable"), None);
    }

    #[test]
    fn sin_tpm_se_dice_en_vez_de_devolver_cero_pcrs() {
        let c = ctx();
        match Pcrs.leer(&c, &Filtro::ninguno()) {
            Ok(r) => assert!(!r.filas.is_empty() || !r.avisos.is_empty()),
            Err(MotivoNoLeible::NoAplicaEnEstaPlataforma { interfaz }) => {
                assert!(interfaz.contains("TPM"));
            }
            Err(otro) => panic!("motivo inesperado: {otro:?}"),
        }
    }

    #[test]
    fn los_paquetes_se_leen_o_se_declara_por_que_no() {
        // En una maquina de la familia RHEL el lector todavia no existe, y eso
        // es un muro DECLARADO: cero paquetes en un servidor seria una
        // conclusion falsa.
        let c = ctx();
        let r = Paquetes
            .leer(&c, &Filtro::ninguno())
            .expect("leer paquetes");
        if r.filas.is_empty() {
            assert!(!r.avisos.is_empty(), "sin paquetes hay que decir por que");
        }
    }

    #[test]
    fn el_tamano_de_un_disco_usa_sectores_de_512() {
        // `/sys/block/*/size` SIEMPRE cuenta en sectores de 512 bytes, sea cual
        // sea el sector fisico. Usar el sector fisico da tamanos cuatro veces
        // mayores en cualquier disco moderno.
        let c = ctx();
        if let Ok(r) = Discos.leer(&c, &Filtro::ninguno()) {
            let i = columna(&Discos, "size_bytes");
            for f in &r.filas {
                if let aegis_parser::valor::Valor::Entero(n) = f.valor(i) {
                    assert!(*n >= 0, "tamano negativo");
                }
            }
        }
    }

    #[test]
    fn las_nueve_tablas_dan_respuesta_o_motivo_en_esta_maquina() {
        let c = ctx();
        for t in tablas() {
            match t.leer(&c, &Filtro::ninguno()) {
                Ok(f) => {
                    if f.filas.is_empty() {
                        assert!(
                            f.examinadas > 0 || !f.avisos.is_empty(),
                            "{} devolvio vacio sin explicar nada",
                            t.nombre()
                        );
                    }
                }
                Err(m) => assert!(!m.frase().is_empty(), "{} sin frase", t.nombre()),
            }
        }
    }

    #[test]
    fn ninguna_tabla_de_plataforma_entra_en_panico_sobre_una_raiz_vacia() {
        // Una raiz de prueba sin nada: todas tienen que dar motivo, no reventar.
        let c = ctx().con_raiz("/tmp/aegis-raiz-vacia-plataforma");
        let _ = std::fs::create_dir_all("/tmp/aegis-raiz-vacia-plataforma");
        for t in tablas() {
            let _ = t.leer(&c, &Filtro::ninguno());
        }
        let _ = std::fs::remove_dir_all("/tmp/aegis-raiz-vacia-plataforma");
    }
}
