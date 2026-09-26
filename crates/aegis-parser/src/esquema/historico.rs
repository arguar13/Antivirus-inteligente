//! Las tablas que solo existen en el historico, y las dos columnas que el
//! historico anade a TODAS.
//!
//! # Mismas tablas, dos columnas mas
//!
//! El almacen del plano de control (FASE 96) guarda las filas que los endpoints
//! devuelven con EXACTAMENTE el esquema con que las devuelven: una consulta
//! sobre `processes` se escribe igual contra una maquina viva que contra lo que
//! esa maquina dijo hace un mes. Lo que el historico sabe y el vivo no son dos
//! cosas, y se anaden como columnas a todas sus tablas:
//!
//! - `ts`: cuando se observo la fila, en nanosegundos Unix. Es la columna por la
//!   que se parte el almacen, y la que decide cuanto cuesta una consulta.
//! - `entity`: la entidad del modelo unico (FASE 79) a la que pertenece la fila,
//!   en su forma de texto (`proc:…`, `ubic:…`). Es el indice primario: buscar una
//!   entidad devuelve todo lo que se sabe de ella sin unir por cadenas de texto.
//!
//! Y tres tablas que el endpoint no tiene porque no son de ninguna maquina: los
//! eventos normalizados de la ingesta, los veredictos del arbitro y los casos.

use super::{Columna, Coste, Tabla, Tipo, TABLAS};

const fn col(nombre: &'static str, tipo: Tipo, descripcion: &'static str) -> Columna {
    Columna {
        nombre,
        tipo,
        coste: Coste::Trivial,
        descripcion,
    }
}

/// La columna del instante de observacion.
pub static TS: Columna = col(
    "ts",
    Tipo::Entero,
    "cuando se observo la fila, en nanosegundos Unix (solo en el historico)",
);

/// La columna de la entidad.
pub static ENTITY: Columna = col(
    "entity",
    Tipo::Texto,
    "entidad del modelo unico a la que pertenece la fila, p. ej. proc:… (solo en el historico)",
);

/// Las columnas que el historico anade a toda tabla.
pub static VIRTUALES: [&Columna; 2] = [&TS, &ENTITY];

/// Eventos normalizados de la ingesta (syslog, journald, EVTX, nube).
pub static EVENTS: Tabla = Tabla {
    nombre: "events",
    columnas: &[
        col("class", Tipo::Texto, "clase OCSF del evento"),
        col("category", Tipo::Texto, "categoria OCSF"),
        col("outcome", Tipo::Texto, "exito, fallo o desconocido"),
        col("severity", Tipo::Texto, "gravedad normalizada"),
        col(
            "source",
            Tipo::Texto,
            "origen: syslog, journald, evtx, nube, agente",
        ),
        col("host", Tipo::Texto, "anfitrion que lo produjo"),
        col("tenant", Tipo::Texto, "inquilino"),
        col("producer", Tipo::Texto, "programa o servicio productor"),
        Columna {
            nombre: "message",
            tipo: Tipo::Texto,
            coste: Coste::Medio,
            descripcion: "mensaje del evento; se descomprime entero para leerlo",
        },
        col("observed_ns", Tipo::Entero, "cuando llego a la ingesta"),
    ],
    descripcion: "eventos normalizados a OCSF por la ingesta (solo en el historico)",
};

/// Veredictos del arbitro.
pub static VERDICTS: Tabla = Tabla {
    nombre: "verdicts",
    columnas: &[
        col(
            "result",
            Tipo::Texto,
            "malicioso, sospechoso, limpio, en disputa o sin datos",
        ),
        col("confidence", Tipo::Entero, "confianza del veredicto, 0-100"),
        col("planes", Tipo::Entero, "planos que lo corroboran"),
        col("signals", Tipo::Entero, "senales que se arbitraron"),
        col("phrase", Tipo::Texto, "la frase que explica el veredicto"),
    ],
    descripcion: "veredictos del arbitro sobre cada entidad (solo en el historico)",
};

/// Casos abiertos sobre entidades.
pub static CASES: Tabla = Tabla {
    nombre: "cases",
    columnas: &[
        col("case_id", Tipo::Texto, "identificador del caso"),
        col("state", Tipo::Texto, "estado del caso"),
        col("title", Tipo::Texto, "titulo"),
        col("severity", Tipo::Texto, "gravedad del caso"),
    ],
    descripcion: "casos que implican a cada entidad (solo en el historico)",
};

/// Las tablas que solo existen en el historico.
pub static SOLO_HISTORICAS: [&Tabla; 3] = [&EVENTS, &VERDICTS, &CASES];

/// Busca una tabla del historico: las del endpoint y las propias.
#[must_use]
pub fn tabla(nombre: &str) -> Option<&'static Tabla> {
    TABLAS
        .iter()
        .find(|t| t.nombre == nombre)
        .or_else(|| SOLO_HISTORICAS.iter().copied().find(|t| t.nombre == nombre))
}

/// Todos los nombres de tabla del historico, para sugerir en un error.
#[must_use]
pub fn nombres() -> Vec<&'static str> {
    TABLAS
        .iter()
        .map(|t| t.nombre)
        .chain(SOLO_HISTORICAS.iter().map(|t| t.nombre))
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ninguna_tabla_del_endpoint_usa_ya_los_nombres_de_las_columnas_virtuales() {
        // Si una tabla del endpoint tuviera ya una columna `ts` o `entity`, la
        // virtual la taparia y la misma consulta significaria cosas distintas
        // contra el vivo y contra el historico.
        for t in TABLAS.iter().chain(SOLO_HISTORICAS.iter().copied()) {
            for v in VIRTUALES {
                assert!(
                    t.columna(v.nombre).is_none(),
                    "{} ya tiene una columna {}",
                    t.nombre,
                    v.nombre
                );
            }
        }
    }

    #[test]
    fn las_tablas_propias_no_chocan_con_las_del_endpoint() {
        for t in SOLO_HISTORICAS {
            assert!(TABLAS.iter().all(|e| e.nombre != t.nombre), "{}", t.nombre);
        }
    }
}
