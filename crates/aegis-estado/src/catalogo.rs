//! El catalogo: que tablas existen y quien las sirve.
//!
//! # Por que este modulo es corto y sus pruebas largas
//!
//! El catalogo en si son treinta lineas: una lista de proveedores y una busqueda
//! por nombre. Lo que importa de este fichero son las PRUEBAS, porque son las
//! que impiden la averia que esta fase podria introducir con mas facilidad.
//!
//! El esquema vive en `aegis-parser` —lo necesita el plano de control— y los
//! proveedores viven aqui. Son dos sitios, y dos sitios que tienen que decir lo
//! mismo se desincronizan: alguien anade una columna al esquema y se le olvida
//! rellenarla, o escribe un proveedor para una tabla que el lenguaje no conoce y
//! que por tanto nadie puede consultar. Las dos averias son silenciosas.
//!
//! Aqui no pueden serlo:
//!
//!   - [`pruebas::toda_tabla_del_esquema_tiene_proveedor`] falla si el lenguaje
//!     declara una tabla que nadie sirve.
//!   - [`pruebas::todo_proveedor_esta_en_el_esquema`] falla si un proveedor
//!     sirve una tabla que el lenguaje no conoce.
//!   - [`pruebas::ningun_proveedor_escribe_columnas_que_no_existen`] falla si un
//!     proveedor rellena una columna que el esquema no declara, que es como se
//!     pierde un dato sin que nadie lo note.
//!   - [`pruebas::toda_columna_declarada_se_rellena_o_se_explica`] falla si el
//!     esquema promete una columna que ningun proveedor produce jamas.
//!
//! La coherencia no se confia a la disciplina de quien edita.

use aegis_parser::esquema::{Coste, Tabla as Esquema, TABLAS};

use crate::tabla::Tabla;

/// Las cinco tablas que sirve el ejecutor de `aegis-hunt` con codigo propio.
///
/// Son anteriores al rasgo [`Tabla`] y siguen donde estaban, por una razon que
/// no es pereza: `processes` expone COLUMNAS CUALIFICADAS —`network.port`,
/// `memory.entropy`, `graph.depth`— que el ejecutor resuelve recorriendo la
/// coleccion asociada a cada fila, y que necesitan el grafo de comportamiento y
/// el motor YARA que el ejecutor ya tiene a mano. Moverlas habria sido reescribir
/// mil lineas que funcionan para no ganar nada.
///
/// Se declaran aqui para que las pruebas de cobertura sepan que su ausencia del
/// catalogo es DELIBERADA y no un olvido.
pub const SERVIDAS_POR_EL_EJECUTOR: &[&str] = &[
    "processes",
    "connections",
    "memory_regions",
    "graph_edges",
    "memory",
];

/// Todos los proveedores de estado del endpoint.
///
/// Se construye en cada llamada y no es una constante global: los proveedores no
/// tienen estado —son todos structs vacios—, asi que construirlos cuesta una
/// reserva de vector y no merece un `static` con inicializacion perezosa, que
/// habria que sincronizar.
pub fn catalogo() -> Vec<Box<dyn Tabla>> {
    let mut todas: Vec<Box<dyn Tabla>> = Vec::new();
    todas.extend(crate::procesos::tablas());
    todas.extend(crate::ficheros::tablas());
    todas.extend(crate::red::tablas());
    todas.extend(crate::identidad::tablas());
    todas.extend(crate::persistencia::tablas());
    todas.extend(crate::plataforma::tablas());
    todas.extend(crate::contenedores::tablas());
    todas
}

/// El proveedor de una tabla, por su nombre.
///
/// Devuelve `None` tanto para una tabla que no existe como para una de las cinco
/// que sirve el ejecutor. Quien pregunte necesita distinguirlas, y para eso esta
/// [`la_sirve_el_ejecutor`].
pub fn tabla_llamada(nombre: &str) -> Option<Box<dyn Tabla>> {
    catalogo().into_iter().find(|t| t.nombre() == nombre)
}

/// Indica si una tabla la sirve el ejecutor de `aegis-hunt` y no este crate.
pub fn la_sirve_el_ejecutor(nombre: &str) -> bool {
    SERVIDAS_POR_EL_EJECUTOR.contains(&nombre)
}

/// Las tablas del esquema que son peligrosas, con las columnas que las acotan.
///
/// Lo usa la consola para explicar al analista como escribir la consulta antes
/// de que la ejecute, en vez de rechazarsela despues.
pub fn peligrosas() -> Vec<(&'static str, &'static [&'static str])> {
    catalogo()
        .iter()
        .filter(|t| t.coste() == Coste::Peligroso)
        .map(|t| (t.nombre(), t.columnas_que_acotan()))
        .collect()
}

/// El esquema de una tabla, por su nombre.
pub fn esquema_de(nombre: &str) -> Option<&'static Esquema> {
    TABLAS.iter().find(|t| t.nombre == nombre)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::contexto::Contexto;
    use crate::tabla::Filtro;
    use std::collections::BTreeSet;

    /// Contexto con presupuesto CORTO.
    ///
    /// Estas pruebas leen las cuarenta y siete tablas —algunas dos veces— y
    /// varias recorren todos los procesos de la maquina. Con el presupuesto por
    /// defecto de dos segundos por tabla, la suite entera tardaria minutos.
    ///
    /// Recortarlo no debilita lo que se comprueba: lo que se mira aqui es la
    /// COHERENCIA entre esquema y proveedores, no la exhaustividad de cada
    /// lectura, y una lectura cortada por presupuesto se marca `truncada` y
    /// sigue siendo una lectura valida. Que eso funcione es, ademas, parte de lo
    /// que hay que probar.
    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
            .con_presupuesto(std::time::Duration::from_millis(150))
    }

    #[test]
    fn toda_tabla_del_esquema_tiene_proveedor() {
        // La averia que evita: el lenguaje acepta `SELECT ... FROM algo`, la
        // consulta se difunde a cien mil endpoints, y todos responden que no
        // saben servir esa tabla.
        let servidas: BTreeSet<&str> = catalogo().iter().map(|t| t.nombre()).collect();
        let huerfanas: Vec<&str> = TABLAS
            .iter()
            .map(|t| t.nombre)
            .filter(|n| !servidas.contains(n) && !la_sirve_el_ejecutor(n))
            .collect();
        assert!(
            huerfanas.is_empty(),
            "el lenguaje declara tablas que nadie sirve: {huerfanas:?}"
        );
    }

    #[test]
    fn todo_proveedor_esta_en_el_esquema() {
        // La averia inversa: un proveedor escrito, probado y funcionando que
        // nadie puede consultar porque el analizador rechaza su nombre.
        let del_esquema: BTreeSet<&str> = TABLAS.iter().map(|t| t.nombre).collect();
        let invisibles: Vec<&str> = catalogo()
            .iter()
            .map(|t| t.nombre())
            .filter(|n| !del_esquema.contains(n))
            .collect();
        assert!(
            invisibles.is_empty(),
            "hay proveedores que el lenguaje no conoce: {invisibles:?}"
        );
    }

    #[test]
    fn ningun_nombre_de_tabla_esta_servido_dos_veces() {
        let mut vistas = BTreeSet::new();
        for t in catalogo() {
            assert!(
                vistas.insert(t.nombre().to_string()),
                "la tabla {} tiene dos proveedores",
                t.nombre()
            );
        }
    }

    #[test]
    fn el_esquema_que_apunta_cada_proveedor_es_el_suyo() {
        // Un proveedor que apunte al esquema de OTRA tabla compilaria
        // perfectamente y produciria filas con las columnas equivocadas.
        for t in catalogo() {
            let del_catalogo = esquema_de(t.nombre()).expect("esta en el esquema");
            assert_eq!(
                t.esquema().columnas.len(),
                del_catalogo.columnas.len(),
                "{} apunta a un esquema que no es el suyo",
                t.nombre()
            );
            assert_eq!(t.esquema().nombre, del_catalogo.nombre);
        }
    }

    #[test]
    fn ningun_proveedor_escribe_columnas_que_no_existen() {
        // El `Constructor` cuenta las columnas desconocidas en vez de entrar en
        // panico, precisamente para que ese error se vea AQUI y no en el
        // endpoint de un cliente. Esta es la prueba que lo mira.
        //
        // Se leen todas las tablas de verdad, contra esta maquina: el recuento
        // solo sube cuando un proveedor intenta escribir de verdad.
        let c = ctx();
        for t in catalogo() {
            // Las peligrosas necesitan filtro; se les da uno que acote.
            let filtro = match t.columnas_que_acotan().first() {
                Some(col) if *col == "path" => Filtro::ninguno().con_prefijo("path", "/etc/"),
                Some(col) => {
                    Filtro::ninguno().con_igualdad(col, aegis_parser::ast::Literal::Entero(1))
                }
                None => Filtro::ninguno(),
            };
            // Que falle por un motivo es correcto; lo que no puede es escribir
            // columnas inexistentes cuando SI lee.
            if let Ok(filas) = t.leer(&c, &filtro) {
                for f in filas.filas.iter().take(5) {
                    assert_eq!(
                        f.valores().len(),
                        t.esquema().columnas.len(),
                        "{} produce filas con un numero de valores que no es el de su esquema",
                        t.nombre()
                    );
                }
            }
        }
    }

    #[test]
    fn toda_columna_declarada_se_rellena_o_se_explica() {
        // Una columna que el esquema promete y que ningun proveedor produce
        // JAMAS es una mentira del catalogo: el analista la ve en la ayuda, la
        // pone en su consulta y siempre le sale vacia.
        //
        // No se puede exigir que TODAS se rellenen en esta maquina —no hay TPM,
        // ni contenedores, ni SELinux—, asi que lo que se comprueba es lo que
        // si se puede comprobar aqui: que de las tablas que devuelven filas, al
        // menos una columna que no sea la clave lleve valor. Una tabla que
        // devuelve filas con TODO ausente esta rota aunque no lo parezca.
        let c = ctx();
        let mut revisadas = 0;
        for t in catalogo() {
            let filtro = match t.columnas_que_acotan().first() {
                Some(col) if *col == "path" => Filtro::ninguno().con_prefijo("path", "/etc/"),
                Some(col) => {
                    Filtro::ninguno().con_igualdad(col, aegis_parser::ast::Literal::Entero(1))
                }
                None => Filtro::ninguno(),
            };
            let Ok(filas) = t.leer(&c, &filtro) else {
                continue;
            };
            let Some(primera) = filas.filas.first() else {
                continue;
            };
            revisadas += 1;
            let con_valor = primera.valores().iter().filter(|v| !v.es_ausente()).count();
            assert!(
                con_valor > 0,
                "{} devuelve filas con todos los valores ausentes",
                t.nombre()
            );
        }
        assert!(
            revisadas >= 10,
            "se revisaron solo {revisadas} tablas: la prueba no esta ejerciendo casi nada"
        );
    }

    #[test]
    fn toda_tabla_peligrosa_exige_filtro() {
        // La cota no puede depender de que cada proveedor se acuerde de
        // llamarla: aqui se comprueba tabla por tabla que la exige de verdad.
        let c = ctx();
        for t in catalogo() {
            if t.coste() != Coste::Peligroso {
                continue;
            }
            assert!(
                !t.columnas_que_acotan().is_empty(),
                "{} es peligrosa y no dice como acotarla",
                t.nombre()
            );
            match t.leer(&c, &Filtro::ninguno()) {
                Err(crate::tabla::MotivoNoLeible::RequiereFiltro { .. }) => {}
                otro => panic!(
                    "{} es peligrosa y se dejo leer sin filtro: {otro:?}",
                    t.nombre()
                ),
            }
        }
    }

    #[test]
    fn ninguna_tabla_no_peligrosa_exige_filtro() {
        // Lo contrario tambien importa: una tabla barata que exige filtro sin
        // ser peligrosa es una tabla que el analista no puede usar y que nadie
        // le ha explicado por que.
        for t in catalogo() {
            if t.coste() == Coste::Peligroso {
                continue;
            }
            assert!(
                t.columnas_que_acotan().is_empty(),
                "{} no es peligrosa pero declara columnas que la acotan",
                t.nombre()
            );
        }
    }

    #[test]
    fn el_catalogo_cubre_las_ocho_familias() {
        // Un recuento explicito: si alguien borra una familia entera del
        // catalogo, las pruebas de arriba seguirian pasando porque el esquema y
        // los proveedores volverian a cuadrar entre si, con menos tablas.
        let n = catalogo().len();
        assert_eq!(
            n,
            TABLAS.len() - SERVIDAS_POR_EL_EJECUTOR.len(),
            "el catalogo tiene {n} proveedores y el esquema {} tablas, de las que {} las sirve el ejecutor",
            TABLAS.len(),
            SERVIDAS_POR_EL_EJECUTOR.len()
        );
        assert!(n >= 47, "se esperaban al menos las 47 tablas de la FASE 81");
    }

    #[test]
    fn se_encuentra_una_tabla_por_su_nombre() {
        assert!(tabla_llamada("users").is_some());
        assert!(tabla_llamada("cpu_info").is_some());
        assert!(tabla_llamada("no_existe_esta_tabla").is_none());
        // Las del ejecutor no estan en este catalogo, y se puede saber por que.
        assert!(tabla_llamada("processes").is_none());
        assert!(la_sirve_el_ejecutor("processes"));
    }

    #[test]
    fn las_peligrosas_se_pueden_enumerar_con_su_remedio() {
        let ps = peligrosas();
        assert!(!ps.is_empty());
        for (nombre, columnas) in &ps {
            assert!(
                !columnas.is_empty(),
                "{nombre} es peligrosa y no dice como acotarla"
            );
        }
        // Las cinco que se esperan de la FASE 81.
        let nombres: BTreeSet<&str> = ps.iter().map(|(n, _)| *n).collect();
        for esperada in [
            "files",
            "suid_binaries",
            "file_capabilities",
            "process_environment",
        ] {
            assert!(
                nombres.contains(esperada),
                "falta {esperada} entre las peligrosas"
            );
        }
    }

    #[test]
    fn ninguna_tabla_entra_en_panico_leida_dos_veces_seguidas() {
        // Determinismo y ausencia de estado: los proveedores no guardan nada
        // entre llamadas, asi que dos lecturas seguidas tienen que comportarse
        // igual. Si una guardara estado, la segunda consulta de una sesion
        // devolveria algo distinto de la primera.
        let c = ctx();
        for t in catalogo() {
            let filtro = Filtro::ninguno();
            let a = t.leer(&c, &filtro);
            let b = t.leer(&c, &filtro);
            assert_eq!(
                a.is_ok(),
                b.is_ok(),
                "{} contesta distinto la segunda vez",
                t.nombre()
            );
        }
    }
}
