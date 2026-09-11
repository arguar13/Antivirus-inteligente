//! La heuristica de comportamiento: a partir de la secuencia de eventos que dejo
//! la emulacion, decide si el binario es benigno o cae en un patron malicioso.
//!
//! Es la parte que puede estar MAL de forma peligrosa —de menos, deja pasar
//! malware; de mas, marca software legitimo empaquetado como una amenaza— y por
//! eso se prueba con casos decisivos, incluido el que separa un buen motor de uno
//! malo: un binario que solo lee un fichero y termina NO se marca.

use crate::syscalls::{Categoria, EventoComportamiento};

/// Severidad del veredicto, ordenada de menor a mayor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Sin comportamiento sospechoso.
    Informativa,
    /// Comportamiento a vigilar (p. ej. se desempaqueto: hay que escanear la
    /// carga real), pero no concluyente por si solo.
    Media,
    /// Patron caracteristico de codigo malicioso.
    Alta,
    /// Prueba fuerte de intencion maliciosa (auto-inyeccion de codigo).
    Critica,
}

/// La clase de comportamiento detectada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseComportamiento {
    /// Nada sospechoso.
    Benigno,
    /// El binario se desplego a si mismo en memoria (empaquetador).
    Desempaquetador,
    /// Reservo/reprotegio memoria como ejecutable y salto a codigo recien
    /// escrito, o manipulo otro proceso: auto-inyeccion de codigo.
    AutoInyeccion,
    /// Abrio red hacia un extremo remoto: posible mando y control (C2).
    C2,
    /// Abrio y sobrescribio muchos ficheros: patron de cifrado de ransomware.
    Ransomware,
    /// Lanzo otro programa.
    EjecucionDePrograma,
}

/// El veredicto del micro-sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veredicto {
    /// La clase de comportamiento.
    pub clase: ClaseComportamiento,
    /// La gravedad.
    pub severidad: Severidad,
    /// `true` si el comportamiento es concluyentemente malicioso (severidad
    /// Alta o Critica). Un desempaquetador es sospechoso pero no concluyente:
    /// se marca para escanear la carga, no para bloquear de plano.
    pub malicioso: bool,
    /// Explicacion legible, con los numeros que la anclan.
    pub evidencia: String,
}

/// Numero de escrituras de fichero a partir del cual el patron parece un
/// cifrador de ransomware.
pub const UMBRAL_RANSOMWARE: usize = 8;

/// Evalua la traza de comportamiento y emite un veredicto.
#[must_use]
pub fn evaluar(eventos: &[EventoComportamiento]) -> Veredicto {
    let mut desempaqueto = false;
    let mut mem_exec = 0usize;
    let mut red = 0usize;
    let mut manip = 0usize;
    let mut exec = 0usize;
    let mut escrituras = 0usize;
    let mut aperturas = 0usize;

    for e in eventos {
        match e {
            EventoComportamiento::Desempaquetado { .. } => desempaqueto = true,
            EventoComportamiento::LlamadaSistema { categoria, .. } => match categoria {
                Categoria::MemoriaEjecutable => mem_exec += 1,
                Categoria::Red => red += 1,
                Categoria::ManipulacionProceso => manip += 1,
                Categoria::EjecucionPrograma => exec += 1,
                Categoria::EscrituraArchivo => escrituras += 1,
                Categoria::AperturaArchivo => aperturas += 1,
                _ => {}
            },
        }
    }

    // Reglas en orden de severidad decreciente: la primera que encaja manda.
    if manip > 0 || (mem_exec > 0 && desempaqueto) {
        let motivo = if manip > 0 {
            format!("manipulo otro proceso ({manip} llamadas de inyeccion)")
        } else {
            "hizo memoria ejecutable y salto a codigo recien escrito".to_string()
        };
        return veredicto(
            ClaseComportamiento::AutoInyeccion,
            Severidad::Critica,
            format!("Auto-inyeccion de codigo: {motivo}."),
        );
    }
    if red > 0 {
        return veredicto(
            ClaseComportamiento::C2,
            Severidad::Alta,
            format!("Actividad de red ({red} llamadas): posible mando y control."),
        );
    }
    if escrituras >= UMBRAL_RANSOMWARE && aperturas > 0 {
        return veredicto(
            ClaseComportamiento::Ransomware,
            Severidad::Alta,
            format!("Abrio {aperturas} y sobrescribio {escrituras} ficheros: patron de cifrado."),
        );
    }
    if desempaqueto {
        return veredicto(
            ClaseComportamiento::Desempaquetador,
            Severidad::Media,
            "Se desplego a si mismo en memoria: hay una carga real que escanear.".to_string(),
        );
    }
    if exec > 0 {
        return veredicto(
            ClaseComportamiento::EjecucionDePrograma,
            Severidad::Media,
            format!("Lanzo otro programa ({exec} veces)."),
        );
    }
    veredicto(
        ClaseComportamiento::Benigno,
        Severidad::Informativa,
        "Sin comportamiento sospechoso durante la emulacion.".to_string(),
    )
}

fn veredicto(clase: ClaseComportamiento, severidad: Severidad, evidencia: String) -> Veredicto {
    Veredicto {
        clase,
        severidad,
        malicioso: severidad >= Severidad::Alta,
        evidencia,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall(categoria: Categoria) -> EventoComportamiento {
        EventoComportamiento::LlamadaSistema {
            numero: 0,
            nombre: "x",
            categoria,
        }
    }

    #[test]
    fn un_binario_que_solo_lee_y_termina_es_benigno() {
        // EL CASO DECISIVO: no marcar de mas.
        let ev = vec![
            syscall(Categoria::AperturaArchivo),
            syscall(Categoria::LecturaArchivo),
            syscall(Categoria::Salida),
        ];
        let v = evaluar(&ev);
        assert_eq!(v.clase, ClaseComportamiento::Benigno);
        assert!(!v.malicioso);
    }

    #[test]
    fn memoria_ejecutable_mas_desempaquetado_es_autoinyeccion() {
        let ev = vec![
            syscall(Categoria::MemoriaEjecutable),
            EventoComportamiento::Desempaquetado {
                base: 0x5000_0000,
                fin: 0x5000_0100,
            },
        ];
        let v = evaluar(&ev);
        assert_eq!(v.clase, ClaseComportamiento::AutoInyeccion);
        assert_eq!(v.severidad, Severidad::Critica);
        assert!(v.malicioso);
    }

    #[test]
    fn actividad_de_red_es_c2() {
        let v = evaluar(&[syscall(Categoria::Red)]);
        assert_eq!(v.clase, ClaseComportamiento::C2);
        assert!(v.malicioso);
    }

    #[test]
    fn desempaquetado_solo_es_sospechoso_no_concluyente() {
        let v = evaluar(&[EventoComportamiento::Desempaquetado {
            base: 0x1000,
            fin: 0x1100,
        }]);
        assert_eq!(v.clase, ClaseComportamiento::Desempaquetador);
        assert_eq!(v.severidad, Severidad::Media);
        assert!(!v.malicioso, "empaquetar no es, por si solo, malicioso");
    }

    #[test]
    fn muchas_escrituras_son_ransomware() {
        let mut ev = vec![syscall(Categoria::AperturaArchivo)];
        for _ in 0..UMBRAL_RANSOMWARE {
            ev.push(syscall(Categoria::EscrituraArchivo));
        }
        let v = evaluar(&ev);
        assert_eq!(v.clase, ClaseComportamiento::Ransomware);
        assert!(v.malicioso);
    }
}
