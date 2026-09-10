//! Planificacion de una consulta AegisQL.
//!
//! POR QUE HAY PLANIFICADOR EN UN LENGUAJE TAN PEQUENO
//! ---------------------------------------------------
//! Porque el coste de las columnas es enormemente desigual y quien lo paga es
//! el endpoint de un cliente. Considerese:
//!
//! ```text
//! WHERE sha256 = '...' AND uid = 0
//! ```
//!
//! Evaluada de izquierda a derecha, hashea el ejecutable de CADA proceso de la
//! maquina para despues descartar casi todos por el uid. Reordenada, comprueba
//! primero un entero que ya esta en memoria y hashea solo los pocos que quedan.
//! En un portatil con dos mil procesos y un disco lento la diferencia son
//! minutos de E/S contra milisegundos, multiplicado por cada endpoint de la
//! flota.
//!
//! El planificador no cambia el SIGNIFICADO de la consulta: reordena cadenas de
//! AND y de OR, que son conmutativas, y no mueve nada de un lado a otro de una
//! negacion.
//!
//! COMO SE USA EL PLAN EN EL ENDPOINT
//! ----------------------------------
//! El ejecutor evalua las etapas en orden y descarta la fila en cuanto una
//! falla. `columnas_necesarias` le dice ademas que datos tiene que materializar
//! antes de empezar, para no consultar /proc dos veces por la misma cosa.

use std::collections::BTreeSet;

use crate::ast::{Consulta, Expr, Proyeccion};
use crate::esquema::{self, Coste};

/// Una consulta con sus predicados ordenados por coste.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// La consulta, con el filtro ya reordenado.
    pub consulta: Consulta,
    /// Columnas que el ejecutor tiene que poder obtener, sin repetir.
    pub columnas_necesarias: Vec<&'static str>,
    /// Coste maximo entre todas las columnas implicadas.
    ///
    /// El plano de control lo usa para decidir si una caceria puede ir a toda
    /// la flota a la vez o conviene lanzarla por tandas.
    pub coste_maximo: Coste,
}

/// Ordena los predicados de una consulta por coste creciente.
pub fn planificar(mut consulta: Consulta) -> Plan {
    let tabla = consulta.tabla;
    if let Some(f) = consulta.filtro.take() {
        consulta.filtro = Some(ordenar(f, tabla));
    }

    let mut necesarias: BTreeSet<&'static str> = BTreeSet::new();
    if let Some(f) = &consulta.filtro {
        f.para_cada_columna(&mut |c| {
            necesarias.insert(c);
        });
    }
    match &consulta.proyeccion {
        Proyeccion::Columnas(cols) => {
            for c in cols {
                necesarias.insert(c.nombre);
            }
        }
        // `SELECT *` se resuelve en el endpoint a las columnas de coste
        // trivial o barato de la tabla: ver `columnas_de_asterisco`.
        Proyeccion::Todo => {
            for c in columnas_de_asterisco(consulta.tabla) {
                necesarias.insert(c);
            }
        }
        // COUNT(*) no materializa ninguna columna por si mismo.
        Proyeccion::Cuenta => {}
    }
    if let Some(o) = &consulta.orden {
        necesarias.insert(o.columna);
    }

    let coste_maximo = necesarias
        .iter()
        .map(|n| coste_de(consulta.tabla, n))
        .max()
        .unwrap_or(Coste::Trivial);

    Plan {
        consulta,
        columnas_necesarias: necesarias.into_iter().collect(),
        coste_maximo,
    }
}

/// Columnas que devuelve `SELECT *` en una tabla.
///
/// Las caras quedan fuera a proposito. En una flota grande, un asterisco que
/// hashee cada ejecutable y calcule la entropia de cada region de memoria de
/// cada proceso es un incidente de disponibilidad provocado por el propio EDR.
/// Quien necesite esas columnas las nombra, y al nombrarlas asume el coste.
pub fn columnas_de_asterisco(tabla: &str) -> Vec<&'static str> {
    esquema::tabla(tabla)
        .map(|t| {
            t.columnas
                .iter()
                .filter(|c| c.coste <= Coste::Barato)
                .map(|c| c.nombre)
                .collect()
        })
        .unwrap_or_default()
}

/// Coste de una columna dentro de una tabla.
fn coste_de(tabla: &str, columna: &str) -> Coste {
    esquema::tabla(tabla)
        .and_then(|t| t.columna(columna))
        .map(|c| c.coste)
        // Una columna que no esta en el esquema no puede llegar hasta aqui: el
        // analizador la habria rechazado. Si algun dia llegara, tratarla como
        // cara es el fallo seguro: se evalua la ultima.
        .unwrap_or(Coste::Caro)
}

/// Reordena las cadenas de AND y de OR por coste creciente.
///
/// Las dos son conmutativas y todos los predicados de AegisQL son puros —no
/// tienen efectos—, asi que reordenarlos no puede cambiar el resultado. Lo que
/// cambia es cuanto trabajo se hace antes de descartar una fila:
///
///   - en un AND, el primer predicado falso descarta la fila;
///   - en un OR, el primer verdadero la acepta.
///
/// En ambos casos conviene preguntar antes lo barato.
///
/// Hay un requisito que el ejecutor tiene que cumplir para que esto sea
/// correcto: cuando un dato no se puede obtener (por ejemplo, el hash de un
/// ejecutable de otro usuario), el predicado vale FALSO, no un tercer valor. Un
/// resultado indefinido convertiria el filtro en logica de tres valores, donde
/// reordenar sigue siendo valido pero razonar sobre ello deja de ser evidente.
/// Con dos valores, la propiedad es trivial y se puede confiar en ella.
fn ordenar(e: Expr, tabla: &str) -> Expr {
    match e {
        Expr::Y(_, _) => {
            let mut partes = Vec::new();
            aplanar(e, Conector::Y, &mut partes);
            reconstruir(ordenar_partes(partes, tabla), Conector::Y)
        }
        Expr::O(_, _) => {
            let mut partes = Vec::new();
            aplanar(e, Conector::O, &mut partes);
            reconstruir(ordenar_partes(partes, tabla), Conector::O)
        }
        // Bajo una negacion se sigue ordenando lo de dentro: `NOT (a AND b)` es
        // `NOT` de una conjuncion, y ordenar esa conjuncion es igual de valido.
        Expr::No(a) => Expr::No(Box::new(ordenar(*a, tabla))),
        hoja => hoja,
    }
}

/// Cual de los dos conectores se esta aplanando.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Conector {
    Y,
    O,
}

/// Ordena cada parte por dentro y luego las partes entre si.
///
/// La ordenacion es ESTABLE a proposito: entre dos predicados del mismo coste
/// se conserva el orden que escribio el analista, que suele reflejar lo que el
/// cree mas selectivo. Reordenar ahi seria sustituir su criterio por ninguno.
fn ordenar_partes(partes: Vec<Expr>, tabla: &str) -> Vec<Expr> {
    let mut partes: Vec<Expr> = partes.into_iter().map(|p| ordenar(p, tabla)).collect();
    partes.sort_by_key(|p| coste_expr(p, tabla));
    partes
}

/// Aplana una cadena del mismo conector en una lista de operandos.
fn aplanar(e: Expr, conector: Conector, salida: &mut Vec<Expr>) {
    match (e, conector) {
        (Expr::Y(a, b), Conector::Y) => {
            aplanar(*a, conector, salida);
            aplanar(*b, conector, salida);
        }
        (Expr::O(a, b), Conector::O) => {
            aplanar(*a, conector, salida);
            aplanar(*b, conector, salida);
        }
        (otro, _) => salida.push(otro),
    }
}

/// Vuelve a montar la lista como una cadena asociada por la izquierda.
fn reconstruir(partes: Vec<Expr>, conector: Conector) -> Expr {
    let mut it = partes.into_iter();
    // `aplanar` siempre empuja al menos un operando, asi que la lista no puede
    // estar vacia. Si algun dia lo estuviera, un predicado que no filtra nada
    // es el fallo seguro: mejor devolver filas de mas que perder deteccion.
    let primera = it.next().unwrap_or(Expr::Bandera { columna: "__vacio" });
    it.fold(primera, |acc, p| match conector {
        Conector::Y => Expr::Y(Box::new(acc), Box::new(p)),
        Conector::O => Expr::O(Box::new(acc), Box::new(p)),
    })
}

/// Coste de evaluar una expresion: el de su columna mas cara.
fn coste_expr(e: &Expr, tabla: &str) -> Coste {
    let mut peor = Coste::Trivial;
    e.para_cada_columna(&mut |c| {
        let coste = coste_de(tabla, c);
        if coste > peor {
            peor = coste;
        }
    });
    peor
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::sintaxis::analizar;

    fn plan(q: &str) -> Plan {
        planificar(analizar(q).unwrap_or_else(|e| panic!("{}", e.dibujar(q))))
    }

    /// Devuelve las columnas del filtro en el orden en que se evaluarian.
    fn orden_de_evaluacion(p: &Plan) -> Vec<&'static str> {
        let mut v = Vec::new();
        if let Some(f) = &p.consulta.filtro {
            f.para_cada_columna(&mut |c| v.push(c));
        }
        v
    }

    #[test]
    fn lo_barato_se_evalua_antes_que_lo_caro() {
        // Escrito al reves a proposito: hashear cada ejecutable para despues
        // descartar por uid es exactamente el error que esto corrige.
        let p = plan("SELECT pid FROM processes WHERE sha256 = 'abc' AND uid = 0");
        assert_eq!(orden_de_evaluacion(&p), vec!["uid", "sha256"]);
    }

    #[test]
    fn la_cadena_entera_se_ordena_no_solo_los_dos_extremos() {
        let p = plan(
            "SELECT pid FROM processes \
             WHERE memory.entropy > 7.0 AND path LIKE '/tmp/%' AND uid = 0 AND network.port = 4444",
        );
        // trivial (uid) < barato (path) < medio (network.port) < caro (entropy)
        assert_eq!(
            orden_de_evaluacion(&p),
            vec!["uid", "path", "network.port", "memory.entropy"]
        );
    }

    #[test]
    fn el_or_tambien_se_ordena() {
        // En un OR, el primer verdadero acepta la fila: preguntar antes lo
        // barato ahorra igual que en un AND.
        let p = plan("SELECT pid FROM processes WHERE sha256 = 'abc' OR uid = 0");
        assert_eq!(orden_de_evaluacion(&p), vec!["uid", "sha256"]);
    }

    #[test]
    fn el_orden_entre_iguales_es_el_que_escribio_el_analista() {
        // gid y uid cuestan lo mismo: no hay motivo para cambiarlos de sitio, y
        // el analista suele poner primero lo que cree mas selectivo.
        let p = plan("SELECT pid FROM processes WHERE gid = 100 AND uid = 0 AND threads = 1");
        assert_eq!(orden_de_evaluacion(&p), vec!["gid", "uid", "threads"]);
    }

    #[test]
    fn se_ordena_tambien_dentro_de_los_parentesis() {
        let p = plan("SELECT pid FROM processes WHERE uid = 0 AND (sha256 = 'abc' OR threads > 8)");
        assert_eq!(orden_de_evaluacion(&p), vec!["uid", "threads", "sha256"]);
    }

    #[test]
    fn reordenar_no_cambia_el_conjunto_de_predicados() {
        // La garantia mas importante: se cambia el ORDEN, nunca el SIGNIFICADO.
        let q = "SELECT pid FROM processes \
                 WHERE sha256 = 'a' AND uid = 0 OR memory.rwx AND threads > 2";
        let p = plan(q);
        let mut antes: Vec<&str> = Vec::new();
        analizar(q)
            .unwrap()
            .filtro
            .unwrap()
            .para_cada_columna(&mut |c| antes.push(c));
        let mut despues = orden_de_evaluacion(&p);
        antes.sort_unstable();
        despues.sort_unstable();
        assert_eq!(antes, despues);
    }

    #[test]
    fn las_columnas_necesarias_incluyen_filtro_proyeccion_y_orden() {
        let p = plan("SELECT pid, path FROM processes WHERE uid = 0 ORDER BY memory.entropy DESC");
        assert_eq!(
            p.columnas_necesarias,
            vec!["memory.entropy", "path", "pid", "uid"]
        );
    }

    #[test]
    fn el_asterisco_deja_fuera_las_columnas_caras() {
        // Un asterisco que hashee cada ejecutable de cada proceso de cada
        // endpoint es una caida de servicio provocada por el propio EDR.
        let cols = columnas_de_asterisco("processes");
        assert!(cols.contains(&"pid"));
        assert!(cols.contains(&"path"));
        assert!(!cols.contains(&"sha256"), "sha256 es cara");
        assert!(!cols.contains(&"memory.entropy"), "la entropia es cara");
    }

    #[test]
    fn count_no_materializa_columnas_de_proyeccion() {
        let p = plan("SELECT COUNT(*) FROM processes WHERE uid = 0");
        assert_eq!(p.columnas_necesarias, vec!["uid"]);
    }

    #[test]
    fn el_coste_maximo_refleja_la_columna_mas_cara() {
        assert_eq!(
            plan("SELECT pid FROM processes").coste_maximo,
            Coste::Trivial
        );
        assert_eq!(
            plan("SELECT pid FROM processes WHERE path LIKE '/tmp/%'").coste_maximo,
            Coste::Barato
        );
        assert_eq!(
            plan("SELECT sha256 FROM processes").coste_maximo,
            Coste::Caro
        );
    }

    #[test]
    fn una_consulta_sin_filtro_se_planifica_igual() {
        let p = plan("SELECT pid FROM processes LIMIT 10");
        assert!(p.consulta.filtro.is_none());
        assert_eq!(p.columnas_necesarias, vec!["pid"]);
    }
}
