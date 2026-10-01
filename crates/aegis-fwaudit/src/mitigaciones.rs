//! Las vulnerabilidades de la CPU, segun el kernel que las mitiga.
//!
//! # Por que se le pregunta al kernel y no a CPUID
//!
//! Si una vulnerabilidad de ejecucion especulativa esta cubierta depende de
//! **tres** cosas a la vez: el silicio, el microcodigo cargado y lo que el kernel
//! decidio activar (y lo que el administrador desactivo con `mitigations=off`).
//! CPUID solo sabe la primera. El kernel escribe la conclusion de las tres en
//! `/sys/devices/system/cpu/vulnerabilities/<nombre>`, y esa es la unica fuente
//! que dice lo que de verdad esta pasando en ESTA maquina ahora.
//!
//! # Cuatro estados, no dos
//!
//! El texto del kernel no es un booleano. «Mitigation: Clear CPU buffers; SMT
//! vulnerable» esta mitigado **a medias**: el mismo nucleo fisico sigue
//! filtrando entre sus dos hilos. Y «Unknown: Dependent on hypervisor status»
//! significa que el invitado no puede saberlo — que no es ni si ni no. Aplanar
//! eso a «mitigado / vulnerable» es mentir en las dos direcciones.

use std::path::Path;

use aegis_firmware::report::CheckState;

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::solo_lectura::LecturaSolo;

/// Donde el kernel publica el estado, relativo a la raiz de sysfs.
pub const DIR_VULNERABILIDADES: &str = "devices/system/cpu/vulnerabilities";

/// El estado de una vulnerabilidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// El silicio no la tiene.
    NoAfectada,
    /// Mitigada.
    Mitigada(String),
    /// Mitigada salvo en algun caso que el propio kernel nombra (tipicamente SMT).
    Parcial(String),
    /// Vulnerable.
    Vulnerable(String),
    /// El kernel no puede saberlo (dentro de una maquina virtual, sobre todo).
    Desconocida(String),
}

/// Clasifica el texto que escribe el kernel.
///
/// El orden de las reglas importa: «Mitigation: ...; SMT vulnerable» contiene la
/// palabra `vulnerable` y es una mitigacion parcial, no una vulnerabilidad.
#[must_use]
pub fn clasificar(texto: &str) -> Estado {
    let t = texto.trim();
    // Algunas empiezan por el ambito ("KVM: Mitigation: VMX disabled"): se quita
    // para clasificar, pero el texto completo se conserva como evidencia.
    let sin_ambito = t
        .strip_prefix("KVM: ")
        .or_else(|| t.strip_prefix("XEN: "))
        .unwrap_or(t);
    let bajo = sin_ambito.to_ascii_lowercase();
    if bajo.starts_with("not affected") {
        Estado::NoAfectada
    } else if bajo.starts_with("vulnerable") {
        Estado::Vulnerable(t.to_string())
    } else if bajo.starts_with("mitigation") {
        if bajo.contains("vulnerable") {
            Estado::Parcial(t.to_string())
        } else {
            Estado::Mitigada(t.to_string())
        }
    } else if bajo.starts_with("unknown") {
        Estado::Desconocida(t.to_string())
    } else {
        // Un texto que el kernel no documenta todavia: no se adivina.
        Estado::Desconocida(t.to_string())
    }
}

/// Una vulnerabilidad con su nombre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerabilidad {
    /// Nombre del fichero (`spectre_v2`, `mds`...).
    pub nombre: String,
    /// Estado.
    pub estado: Estado,
}

/// Lee todas las vulnerabilidades que publica el kernel.
///
/// # Errores
/// El motivo, si el directorio no existe (kernel anterior a 4.15 o sysfs no
/// montado).
pub fn leer(raiz_sys: &Path) -> Result<Vec<Vulnerabilidad>, String> {
    let dir = raiz_sys.join(DIR_VULNERABILIDADES);
    let e = std::fs::read_dir(&dir).map_err(|e| {
        format!(
            "{} no se puede leer ({e}): el kernel no publica el estado de las mitigaciones",
            dir.display()
        )
    })?;
    let mut v = Vec::new();
    for x in e.flatten() {
        let nombre = x.file_name().to_string_lossy().to_string();
        let texto = LecturaSolo::abrir(&x.path())
            .and_then(|l| l.leer_todo(4096))
            .map(|b| String::from_utf8_lossy(&b).to_string());
        let estado = match texto {
            Ok(t) => clasificar(&t),
            Err(e) => Estado::Desconocida(format!("no se pudo leer: {e}")),
        };
        v.push(Vulnerabilidad { nombre, estado });
    }
    v.sort_by(|a, b| a.nombre.cmp(&b.nombre));
    Ok(v)
}

/// La comprobacion de mitigaciones.
///
/// Vulnerable o parcial es una EXPOSICION: la CPU filtra, pero eso no dice que
/// nadie este leyendo. Si no hay ninguna vulnerable pero alguna es desconocida,
/// el veredicto es indeterminado: no se puede afirmar que este todo cubierto.
#[must_use]
pub fn evaluar(v: &Result<Vec<Vulnerabilidad>, String>) -> Comprobacion {
    let estado = match v {
        Err(m) => CheckState::NoAplicable(m.clone()),
        Ok(v) if v.is_empty() => CheckState::Indeterminado("el directorio esta vacio".into()),
        Ok(v) => {
            let lista = |f: fn(&Estado) -> Option<&String>| -> Vec<String> {
                v.iter()
                    .filter_map(|x| f(&x.estado).map(|t| format!("{} ({t})", x.nombre)))
                    .collect()
            };
            let vulnerables = lista(|e| match e {
                Estado::Vulnerable(t) => Some(t),
                _ => None,
            });
            let parciales = lista(|e| match e {
                Estado::Parcial(t) => Some(t),
                _ => None,
            });
            let desconocidas = lista(|e| match e {
                Estado::Desconocida(t) => Some(t),
                _ => None,
            });
            if !vulnerables.is_empty() || !parciales.is_empty() {
                let mut partes = Vec::new();
                if !vulnerables.is_empty() {
                    partes.push(format!("VULNERABLES: {}", vulnerables.join("; ")));
                }
                if !parciales.is_empty() {
                    partes.push(format!("mitigadas a medias: {}", parciales.join("; ")));
                }
                CheckState::Fallo(partes.join(". "))
            } else if !desconocidas.is_empty() {
                CheckState::Indeterminado(format!(
                    "{} de {} sin estado conocido: {}",
                    desconocidas.len(),
                    v.len(),
                    desconocidas.join("; ")
                ))
            } else {
                CheckState::Ok
            }
        }
    };
    Comprobacion::nueva(
        "cpu-mitigaciones",
        Superficie::Cpu,
        Naturaleza::Exposicion,
        estado,
    )
    .como_chipsec(&["common.cpu.spectre_v2", "common.cpu.cpu_info"])
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    /// Los textos REALES que escribe el kernel, incluidos los de esta maquina.
    #[test]
    fn los_textos_del_kernel_se_clasifican_en_cuatro_estados() {
        assert_eq!(clasificar("Not affected\n"), Estado::NoAfectada);
        assert!(matches!(
            clasificar("Mitigation: Enhanced / Automatic IBRS; IBPB: conditional"),
            Estado::Mitigada(_)
        ));
        assert!(matches!(
            clasificar("Mitigation: Clear CPU buffers; SMT vulnerable"),
            Estado::Parcial(_)
        ));
        assert!(matches!(
            clasificar(
                "Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown"
            ),
            Estado::Vulnerable(_)
        ));
        assert!(matches!(
            clasificar("Unknown: Dependent on hypervisor status"),
            Estado::Desconocida(_)
        ));
        assert!(matches!(
            clasificar("KVM: Mitigation: VMX disabled"),
            Estado::Mitigada(_)
        ));
        assert!(matches!(
            clasificar("KVM: Vulnerable"),
            Estado::Vulnerable(_)
        ));
        assert!(matches!(
            clasificar("Algo que el kernel aun no documenta"),
            Estado::Desconocida(_)
        ));
    }

    fn v(pares: &[(&str, &str)]) -> Result<Vec<Vulnerabilidad>, String> {
        Ok(pares
            .iter()
            .map(|(n, t)| Vulnerabilidad {
                nombre: (*n).into(),
                estado: clasificar(t),
            })
            .collect())
    }

    #[test]
    fn una_vulnerable_es_exposicion_y_se_nombra() {
        let c = evaluar(&v(&[
            ("meltdown", "Not affected"),
            (
                "mmio_stale_data",
                "Vulnerable: Clear CPU buffers attempted, no microcode",
            ),
        ]));
        assert_eq!(c.naturaleza, Naturaleza::Exposicion);
        assert!(format!("{:?}", c.estado).contains("mmio_stale_data"));
    }

    #[test]
    fn desconocida_sin_vulnerables_es_indeterminado_y_no_verde() {
        let c = evaluar(&v(&[
            ("meltdown", "Not affected"),
            ("srbds", "Unknown: Dependent on hypervisor status"),
        ]));
        assert!(matches!(c.estado, CheckState::Indeterminado(_)), "{c:?}");
        let todo_bien = evaluar(&v(&[
            ("meltdown", "Not affected"),
            ("spectre_v1", "Mitigation: x"),
        ]));
        assert_eq!(todo_bien.estado, CheckState::Ok);
        assert!(matches!(
            evaluar(&Err("sin sysfs".into())).estado,
            CheckState::NoAplicable(_)
        ));
    }

    /// LA CPU REAL DE ESTA MAQUINA, sin valores esperados escritos a mano: lo que
    /// se comprueba es que cada fichero se lee, se clasifica, y que la
    /// comprobacion cuadra con la clasificacion.
    #[test]
    fn las_vulnerabilidades_reales_de_esta_maquina_se_leen_todas() {
        let r = leer(Path::new("/sys"));
        let Ok(lista) = &r else {
            omitir(
                &format!("el kernel no expone sus mitigaciones: {r:?}"),
                Requisito::Entorno,
            );
            return;
        };
        assert!(!lista.is_empty());
        for x in lista {
            eprintln!("  {:<28} {:?}", x.nombre, x.estado);
        }
        let hay_vulnerable = lista
            .iter()
            .any(|x| matches!(x.estado, Estado::Vulnerable(_) | Estado::Parcial(_)));
        let c = evaluar(&r);
        eprintln!("{}", c.linea());
        assert_eq!(c.estado.es_fallo(), hay_vulnerable);
    }
}
