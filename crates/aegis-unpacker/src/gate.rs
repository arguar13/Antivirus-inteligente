//! Filtro de entrada: que binarios merecen desempaquetado dinamico.
//!
//! # Por que un filtro y no desempaquetar todo
//!
//! Desempaquetar es EJECUTAR el binario bajo control, con todo lo que eso cuesta
//! y arriesga. Hacerlo con cada fichero que se escanea seria a la vez carisimo y
//! peligroso. El filtro deja pasar solo lo que tiene la firma de un empaquetador:
//! **secciones ejecutables de entropia casi maxima**.
//!
//! Un binario normal tiene su codigo en sus secciones y su entropia es media:
//! las instrucciones se repiten, hay huecos, hay tablas. Un binario empaquetado
//! lleva su codigo real COMPRIMIDO o CIFRADO dentro de una seccion, y un flujo
//! comprimido o cifrado es indistinguible de ruido: entropia al maximo. Esa es
//! la senal, y es la misma que usa el motor de ransomware para el cifrado, solo
//! que aqui se mira sobre las secciones de un ejecutable.
//!
//! # Por que "casi todas las secciones ejecutables" y no "alguna"
//!
//! Un binario legitimo puede tener UNA seccion de alta entropia —recursos
//! comprimidos, una tabla de claves—. Lo que delata al empaquetador es que su
//! seccion de CODIGO, la que se ejecuta, es la de alta entropia: el codigo real
//! no esta ahi todavia, esta comprimido. Por eso el filtro pesa las secciones
//! ejecutables, no cualquier seccion.

use aegis_ml::entropy;

/// Umbral de entropia normalizada por encima del cual una seccion parece
/// comprimida o cifrada.
///
/// Se reutiliza la fraccion de cifrado del motor de ransomware: por debajo de
/// esto hay estructura (codigo, texto, tablas); por encima, ruido.
pub const UMBRAL_EMPAQUETADO: f64 = entropy::FRACCION_EMPAQUETADA;

/// Una seccion ejecutable de un binario, para el analisis de entropia.
#[derive(Debug, Clone)]
pub struct Seccion {
    /// Nombre, para el informe.
    pub nombre: String,
    /// Cierto si la seccion es ejecutable.
    pub ejecutable: bool,
    /// Contenido de la seccion en disco.
    pub datos: Vec<u8>,
}

/// Veredicto del filtro.
#[derive(Debug, Clone, PartialEq)]
pub struct GateVerdict {
    /// Cierto si el binario merece desempaquetado dinamico.
    pub empaquetado: bool,
    /// Entropia normalizada de cada seccion ejecutable evaluada.
    pub entropias: Vec<(String, f64)>,
    /// Motivo legible.
    pub motivo: String,
}

/// Decide si un conjunto de secciones corresponde a un binario empaquetado.
///
/// El criterio: existe al menos una seccion ejecutable, y TODAS las ejecutables
/// con datos suficientes tienen entropia por encima del umbral. Que todas la
/// tengan —no solo una— es lo que distingue un empaquetador de un binario que
/// casualmente lleva datos comprimidos en una seccion.
pub fn evaluar(secciones: &[Seccion]) -> GateVerdict {
    let mut entropias = Vec::new();
    let mut ejecutables_evaluadas = 0usize;
    let mut ejecutables_altas = 0usize;

    for s in secciones {
        if !s.ejecutable {
            continue;
        }
        let Some(e) = entropy::entropia_normalizada(&s.datos) else {
            // Seccion demasiado corta para medir: no cuenta ni a favor ni en
            // contra, pero se deja constancia.
            entropias.push((s.nombre.clone(), f64::NAN));
            continue;
        };
        entropias.push((s.nombre.clone(), e));
        ejecutables_evaluadas += 1;
        if e >= UMBRAL_EMPAQUETADO {
            ejecutables_altas += 1;
        }
    }

    let empaquetado = ejecutables_evaluadas > 0 && ejecutables_altas == ejecutables_evaluadas;
    let motivo = if empaquetado {
        format!(
            "las {ejecutables_evaluadas} seccion(es) ejecutable(s) tienen entropia \
             >= {UMBRAL_EMPAQUETADO:.2}: el codigo real esta comprimido o cifrado"
        )
    } else if ejecutables_evaluadas == 0 {
        "sin secciones ejecutables medibles".to_string()
    } else {
        format!(
            "{ejecutables_altas} de {ejecutables_evaluadas} secciones ejecutables \
             son de alta entropia: no es el patron de un empaquetador"
        )
    };

    GateVerdict {
        empaquetado,
        entropias,
        motivo,
    }
}
