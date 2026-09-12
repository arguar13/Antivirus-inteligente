//! Informa de que puede auditar AegisFirmwareAudit en ESTA maquina, y audita.
//!
//! Es el companero de `firmware_support` de FASE 28, y existe por la misma razon:
//! la puerta de calidad tiene que DECIR que superficies de firmware existen aqui,
//! para que la diferencia entre "auditado y limpio" y "no se pudo mirar" este a la
//! vista y no escondida en un comentario.
//!
//! Uso opcional: `fwaudit_support [ruta-linea-base]`. Sin linea base el veredicto
//! sobre el contenido de la ROM es INDETERMINADO a proposito: recorrer el firmware
//! se puede sin ella, pero decir si su contenido es el que deberia, no.
//!
//! Sale 0 salvo que la auditoria encuentre un compromiso REAL. La ausencia de
//! ROM SPI expuesta NO es un compromiso: es una superficie que la maquina no da.
//!
//! No escribe nada, en ningun sitio. Ver la garantia de solo lectura del crate.

use std::process::ExitCode;

use aegis_fwaudit::linea_base::LineaBase;
use aegis_fwaudit::{CheckState, Severidad, SoporteAuditoria};

fn main() -> ExitCode {
    let s = SoporteAuditoria::detectar();
    println!("tablas ACPI:   {}", s.tablas_acpi);
    if s.tablas_ilegibles > 0 {
        println!("  ilegibles:   {}", s.tablas_ilegibles);
    }
    println!("WPBT:          {}", if s.hay_wpbt { "SI" } else { "no" });
    println!(
        "ROM SPI:       {}",
        if s.rom_accesible { "SI" } else { "NO" }
    );
    if !s.dispositivos_mtd.is_empty() {
        for d in &s.dispositivos_mtd {
            println!(
                "  {:10} {:>10} B  nodo {}  {}",
                d.nombre,
                d.tamano,
                if d.nodo_presente { "si" } else { "NO" },
                if d.parece_bios() { "(parece BIOS)" } else { "" }
            );
        }
    }
    if !s.rom_accesible {
        println!("  motivo:      {}", s.motivo_sin_rom);
    }

    // La linea base es OPCIONAL y su ausencia se dice, no se disimula: sin ella
    // el informe distingue "no hay anomalias" de "no tengo con que comparar".
    let base = match std::env::args().nth(1) {
        None => LineaBase::default(),
        Some(ruta) => match LineaBase::cargar(std::path::Path::new(&ruta)) {
            Ok(b) => {
                println!("linea base:    {} entrada(s) de {ruta}", b.len());
                b
            }
            Err(e) => {
                eprintln!("FALLO: no se pudo cargar la linea base '{ruta}': {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    if base.vacia() {
        println!("linea base:    ninguna (el contenido de la ROM quedara indeterminado)");
    }

    let informe = aegis_fwaudit::auditar(&base);
    println!("\nveredicto de la auditoria de firmware:");
    for c in &informe.checks {
        let etiqueta = match &c.estado {
            CheckState::Ok => "OK".to_string(),
            CheckState::Fallo(m) => format!("COMPROMISO: {m}"),
            CheckState::NoAplicable(m) => format!("no aplicable ({m})"),
            CheckState::Indeterminado(m) => format!("indeterminado ({m})"),
        };
        println!("  {:16} {etiqueta}", c.nombre);
    }
    println!(
        "\ntablas vistas: {}  volumenes: {}  ficheros FFS: {}",
        informe.tablas_vistas, informe.volumenes_vistos, informe.ficheros_vistos
    );

    if !informe.anomalias.is_empty() {
        println!("\nanomalias ({}):", informe.anomalias.len());
        for a in &informe.anomalias {
            let sev = match a.severidad {
                Severidad::Informativa => "info",
                Severidad::Sospechosa => "SOSP",
                Severidad::Critica => "CRIT",
            };
            println!("  [{sev}] {:24} {}: {}", a.codigo, a.sujeto, a.detalle);
        }
    }
    if !informe.ficheros_desconocidos.is_empty() {
        println!(
            "\n{} fichero(s) FFS fuera de la linea base (desconocido NO es malicioso; \
             es lo que aun no se ha catalogado)",
            informe.ficheros_desconocidos.len()
        );
    }

    if informe.comprometido() {
        eprintln!("\nFALLO: el firmware muestra evidencia de manipulacion");
        return ExitCode::FAILURE;
    }
    if !s.algo_que_auditar() {
        println!(
            "\nAVISO: esta maquina no expone ni tablas ACPI ni ROM SPI; la auditoria no \
             aplica aqui. La logica de analisis (WPBT, descriptor Intel, volumenes UEFI, \
             ficheros FFS) SI se prueba con vectores binarios reales."
        );
    }
    ExitCode::SUCCESS
}
