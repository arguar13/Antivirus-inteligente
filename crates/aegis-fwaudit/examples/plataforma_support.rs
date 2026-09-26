//! La auditoria de plataforma completa de ESTA maquina (FASE 92), tal y como la
//! veria un endpoint: cada comprobacion con su naturaleza y su tri-estado, el
//! resumen del AML, la cadena de arranque, la equivalencia con CHIPSEC y la senal
//! que llegaria al arbitro.
//!
//! Uso: `plataforma_support [--base <linea-base>] [--imagen <volcado-rom>]`
//!
//! Sale 0 salvo que haya un COMPROMISO. Las exposiciones se ensenan y no hacen
//! fallar: son postura, no incidente. No escribe nada en ningun sitio.

use std::process::ExitCode;

use aegis_fwaudit::chipsec;
use aegis_fwaudit::linea_base::LineaBase;
use aegis_fwaudit::{auditar_plataforma, Naturaleza, Raices};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let valor = |clave: &str| {
        args.iter()
            .position(|a| a == clave)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let base = match valor("--base") {
        None => LineaBase::default(),
        Some(r) => match LineaBase::cargar(std::path::Path::new(&r)) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("FALLO: la linea base '{r}' no se pudo cargar: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let imagen = match valor("--imagen") {
        None => None,
        Some(r) => match std::fs::read(&r) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("FALLO: la imagen '{r}' no se pudo leer: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let inicio = std::time::Instant::now();
    let inf = auditar_plataforma(&Raices::del_sistema(), &base, imagen.as_deref());
    let tiempo = inicio.elapsed();

    println!("chipset:        {}", inf.chipset);
    println!(
        "virtualizada:   {}",
        if inf.virtualizada { "si" } else { "no" }
    );
    println!(
        "vistos:         {} tablas ACPI, {} dispositivos PCI, {} option ROM anunciadas en sysfs (no leidas)",
        inf.tablas_acpi, inf.dispositivos_pci, inf.opciones_rom_anunciadas
    );
    let condicionales = inf.aml.metodos.iter().filter(|m| m.condicional).count();
    println!(
        "AML:            {} metodos ({} incondicionales, {} condicionales), {} decodificados, {} automaticos, {} errores",
        inf.aml.metodos.len(),
        inf.aml.metodos.len() - condicionales,
        condicionales,
        inf.aml.decodificados(),
        inf.aml.automaticos().len(),
        inf.aml.errores.len()
    );
    match &inf.cadena {
        Some(c) => println!(
            "arranque:       {} medidas, firmware {:?}, Secure Boot medido {:?}, cargadores {:?}",
            c.eslabones.len(),
            c.version_firmware,
            c.secure_boot_medido,
            c.cargadores
        ),
        None => println!("arranque:       sin registro de arranque medido"),
    }
    println!("\ncomprobaciones:");
    for c in &inf.comprobaciones {
        println!("  {}", c.linea());
    }
    let (mc, tc) = inf.cobertura(Naturaleza::Compromiso);
    let (me, te) = inf.cobertura(Naturaleza::Exposicion);
    println!(
        "\ncobertura:      compromiso {mc}/{tc} miradas, exposicion {me}/{te} miradas; {} exposicion(es); {} compromiso(s); en {tiempo:?}",
        inf.exposiciones().len(),
        inf.compromisos().len()
    );
    let (c, p, n, e) = chipsec::recuento();
    println!(
        "CHIPSEC:        {} modulos: {c} cubiertos, {p} parciales, {n} no cubiertos, {e} excluidos por escribir o atacar; {} comprobaciones sin equivalente",
        chipsec::MODULOS.len(),
        chipsec::SOLO_AQUI.len()
    );
    let maquina = aegis_entidad::entidad::maquina("plataforma-support");
    let s = aegis_fwaudit::senal::senal_de(&inf, maquina, 0);
    println!(
        "senal:          {} {} confianza {} — {}",
        s.juicio.nombre(),
        s.severidad.nombre(),
        s.confianza.centesimas(),
        s.porque
    );
    if inf.comprometido() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
