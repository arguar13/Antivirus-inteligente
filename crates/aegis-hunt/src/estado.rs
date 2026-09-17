//! El puente entre el ejecutor y los proveedores de `aegis-estado`.
//!
//! # Que hace este modulo y que sigue haciendo el ejecutor
//!
//! Las cinco tablas originales —`processes`, `connections`, `memory_regions`,
//! `graph_edges` y `memory`— las sigue sirviendo el ejecutor con su codigo, y
//! no por inercia: `processes` expone columnas CUALIFICADAS (`network.port`,
//! `memory.entropy`, `graph.depth`) que son cuantificadores existenciales sobre
//! la coleccion asociada a cada fila, y que necesitan el grafo de comportamiento
//! y el motor YARA que el ejecutor ya tiene a mano.
//!
//! Las cuarenta y siete de la FASE 81 son monovaluadas —una celda es un valor— y
//! las sirve el catalogo. Este modulo traduce entre los dos mundos, y la
//! traduccion tiene exactamente tres piezas:
//!
//!   1. El FILTRO que se empuja a la tabla, para que no enumere de mas.
//!   2. Una [`Fila`] sobre la fila del proveedor, para que el evaluador del
//!      filtro funcione igual con las cuarenta y siete que con las cinco.
//!   3. El MOTIVO, cuando la tabla no se pudo leer, que es la capacidad que
//!      esta fase anade y que no tenia donde vivir en el resultado.

use aegis_estado::tabla::Filtro;
use aegis_estado::Contexto;
use aegis_parser::ast::{Comparador, Expr, Literal, Proyeccion};
use aegis_parser::plan::{columnas_de_asterisco, Plan};
use aegis_parser::valor::Valor;

/// Lo que el ejecutor necesita saber de una lectura del catalogo.
#[derive(Debug, Default)]
pub struct Lectura {
    /// Las filas que pasaron el filtro, ya proyectadas a texto.
    pub filas: Vec<Vec<String>>,
    /// Cuantas pasaron el filtro, aunque no se devuelvan todas.
    pub coincidencias: u64,
    /// Cuantas unidades examino el proveedor.
    pub examinadas: u64,
    /// Valores que no se pudieron obtener.
    pub inaccesibles: u64,
    /// La lectura se corto por tope o por presupuesto.
    pub truncada: bool,
    /// Por que no hay tabla, si no la hay.
    pub motivo: Option<String>,
    /// Huecos declarados dentro de una lectura que si tuvo exito.
    pub avisos: Vec<String>,
}

/// El prefijo constante de un patron de `LIKE`, si lo tiene.
///
/// `'/tmp/%'` da `/tmp/`; `'%curl'` no da nada, porque un patron que empieza por
/// comodin no acota ningun subarbol. Devolver un prefijo de mas haria que la
/// tabla recorriera menos de lo que debe, que es la unica forma de que el empuje
/// pierda filas.
pub fn prefijo_constante(patron: &str) -> Option<String> {
    let fin = patron.find(['%', '_'])?;
    if fin == 0 {
        return None;
    }
    Some(patron[..fin].to_string())
}

/// Traduce el filtro de la consulta en lo que la tabla puede aprovechar.
///
/// # La regla que hace esto seguro
///
/// Solo se empujan predicados que esten en CONJUNCION PURA en la raiz. Bajo un
/// `OR`, saber que una rama pide `pid = 42` no autoriza a mirar solo el 42,
/// porque la otra rama puede aceptar cualquier otro; bajo un `NOT`, lo mismo al
/// reves. En los dos casos, empujar perderia filas en silencio, que es la unica
/// forma de que este mecanismo haga daño.
///
/// Lo que se empuja de mas no rompe nada: el ejecutor vuelve a evaluar el filtro
/// COMPLETO sobre lo que reciba.
pub fn empujar(plan: &Plan) -> Filtro {
    let mut filtro = Filtro::ninguno();
    if let Some(e) = &plan.consulta.filtro {
        recoger(e, &mut filtro);
    }
    // Las columnas que la consulta necesita de verdad: sin esto, un proveedor
    // no sabe que nadie pidio `sha256` y hashea el disco entero por si acaso.
    filtro.con_columnas(plan.columnas_necesarias.clone())
}

/// Recorre la conjuncion de la raiz recogiendo lo que se puede empujar.
fn recoger(e: &Expr, filtro: &mut Filtro) {
    match e {
        // La conjuncion se reparte: las dos ramas tienen que cumplirse, asi que
        // las dos acotan.
        Expr::Y(a, b) => {
            recoger(a, filtro);
            recoger(b, filtro);
        }
        Expr::Comparacion {
            columna,
            op: Comparador::Igual,
            valor,
        } => {
            *filtro = std::mem::take(filtro).con_igualdad(columna, valor.clone());
        }
        Expr::En {
            columna,
            valores,
            negado: false,
        } => {
            *filtro = std::mem::take(filtro).con_conjunto(columna, valores.clone());
        }
        Expr::Like {
            columna,
            patron,
            negado: false,
        } => {
            if let Some(p) = prefijo_constante(patron) {
                *filtro = std::mem::take(filtro).con_prefijo(columna, p);
            }
        }
        // Todo lo demas —`OR`, `NOT`, las comparaciones de orden, las banderas—
        // NO acota. Ver la nota de `empujar` sobre por que.
        _ => {}
    }
}

/// Una fila del catalogo, vista como la ve el evaluador del ejecutor.
///
/// Las tablas de la FASE 81 son monovaluadas: una celda es un valor, asi que
/// «alguno cumple» es «el valor cumple». Las cualificadas de `processes` son el
/// caso raro, no el normal.
pub struct FilaDeEstado<'a> {
    fila: &'a aegis_estado::Fila,
    esquema: &'static aegis_parser::esquema::Tabla,
    inaccesibles: u64,
}

impl<'a> FilaDeEstado<'a> {
    /// Envuelve una fila del catalogo.
    pub fn nueva(
        fila: &'a aegis_estado::Fila,
        esquema: &'static aegis_parser::esquema::Tabla,
    ) -> FilaDeEstado<'a> {
        FilaDeEstado {
            fila,
            esquema,
            inaccesibles: 0,
        }
    }

    /// El valor de una columna por su nombre.
    pub fn valor(&mut self, columna: &str) -> Valor {
        let Some(i) = self
            .esquema
            .columnas
            .iter()
            .position(|c| c.nombre == columna)
        else {
            // El analizador no deja pasar una columna que no existe; si llegara,
            // ausente es la respuesta segura.
            return Valor::Ausente;
        };
        let v = self.fila.valor(i).clone();
        if v.es_ausente() {
            self.inaccesibles += 1;
        }
        v
    }

    /// Cuantos valores no se pudieron obtener al leer esta fila.
    pub fn inaccesibles(&self) -> u64 {
        self.inaccesibles
    }
}

/// Ejecuta un plan contra el catalogo de `aegis-estado`.
///
/// Devuelve `None` si la tabla no la sirve el catalogo, que es como el ejecutor
/// distingue las cinco suyas sin repetir la lista.
pub fn ejecutar(plan: &Plan, ctx: &Contexto, limite: u32) -> Option<Lectura> {
    let tabla = aegis_estado::tabla_llamada(plan.consulta.tabla)?;
    let esquema = tabla.esquema();
    let filtro = empujar(plan);

    let mut salida = Lectura::default();
    let filas = match tabla.leer(ctx, &filtro) {
        Ok(f) => f,
        Err(m) => {
            // AQUI VIVE LA CAPACIDAD QUE OSQUERY NO TIENE: la tabla no se pudo
            // leer, y el resultado dice por que en vez de devolver cero filas.
            salida.motivo = Some(m.frase());
            return Some(salida);
        }
    };

    salida.examinadas = filas.examinadas;
    salida.truncada = filas.truncada;
    salida.avisos = filas
        .avisos
        .iter()
        .map(|a| format!("{}: {}", a.sujeto, a.motivo.frase()))
        .collect();

    let columnas = match &plan.consulta.proyeccion {
        Proyeccion::Columnas(cols) => cols.iter().map(|c| c.nombre).collect::<Vec<_>>(),
        Proyeccion::Todo => columnas_de_asterisco(plan.consulta.tabla),
        Proyeccion::Cuenta => Vec::new(),
    };

    for f in &filas.filas {
        let mut vista = FilaDeEstado::nueva(f, esquema);
        // El filtro COMPLETO se vuelve a evaluar: lo que el proveedor empujo es
        // una ayuda, no una garantia de exactitud.
        if let Some(e) = &plan.consulta.filtro {
            if !evaluar_sobre(e, &mut vista) {
                salida.inaccesibles += vista.inaccesibles();
                continue;
            }
        }
        salida.coincidencias += 1;
        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            salida.inaccesibles += vista.inaccesibles();
            continue;
        }
        if salida.filas.len() < limite as usize {
            let fila: Vec<String> = columnas.iter().map(|c| vista.valor(c).a_texto()).collect();
            salida.filas.push(fila);
        } else {
            salida.truncada = true;
        }
        salida.inaccesibles += vista.inaccesibles();
    }
    Some(salida)
}

/// Evalua un filtro sobre una fila del catalogo.
///
/// Es la misma semantica que el evaluador del ejecutor —un valor ausente no casa
/// nunca, `NOT LIKE` es «no casa» y no «alguno no casa»— sobre filas
/// monovaluadas, donde el cuantificador existencial es la identidad.
fn evaluar_sobre(e: &Expr, fila: &mut FilaDeEstado) -> bool {
    match e {
        Expr::Comparacion { columna, op, valor } => fila.valor(columna).compara(*op, valor),
        Expr::Like {
            columna,
            patron,
            negado,
        } => {
            let v = fila.valor(columna);
            let casa = !v.es_ausente() && v.casa_patron(patron);
            casa != *negado
        }
        Expr::En {
            columna,
            valores,
            negado,
        } => {
            let v = fila.valor(columna);
            let dentro = !v.es_ausente() && valores.iter().any(|l| v.compara(Comparador::Igual, l));
            dentro != *negado
        }
        Expr::Bandera { columna } => matches!(fila.valor(columna), Valor::Booleano(true)),
        Expr::Y(a, b) => evaluar_sobre(a, fila) && evaluar_sobre(b, fila),
        Expr::O(a, b) => evaluar_sobre(a, fila) || evaluar_sobre(b, fila),
        Expr::No(a) => !evaluar_sobre(a, fila),
    }
}

/// Un literal para construir filtros desde fuera, sin exponer el AST.
pub fn literal_entero(n: i64) -> Literal {
    Literal::Entero(n)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_parser::plan::planificar;
    use aegis_parser::sintaxis::analizar;

    fn plan(q: &str) -> Plan {
        planificar(analizar(q).unwrap_or_else(|e| panic!("{}", e.dibujar(q))))
    }

    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
    }

    #[test]
    fn el_prefijo_de_un_like_se_extrae_solo_si_es_constante() {
        assert_eq!(prefijo_constante("/tmp/%"), Some("/tmp/".to_string()));
        assert_eq!(prefijo_constante("/usr/bi%"), Some("/usr/bi".to_string()));
        assert_eq!(prefijo_constante("abc_"), Some("abc".to_string()));
        // Un patron que empieza por comodin NO acota nada: devolver un prefijo
        // ahi haria que la tabla recorriera menos de lo que debe.
        assert_eq!(prefijo_constante("%curl"), None);
        assert_eq!(prefijo_constante("_x"), None);
        // Sin comodines no es un prefijo, es el valor entero.
        assert_eq!(prefijo_constante("/bin/sh"), None);
    }

    #[test]
    fn una_igualdad_en_conjuncion_se_empuja() {
        let p = plan("SELECT username FROM users WHERE uid = 0 AND can_login");
        let f = empujar(&p);
        assert_eq!(f.entero("uid"), Some(0));
    }

    #[test]
    fn lo_que_esta_bajo_un_or_no_se_empuja() {
        // LA propiedad de correccion: saber que una rama pide `uid = 0` no
        // autoriza a mirar solo el uid 0, porque la otra rama acepta mas.
        let p = plan("SELECT username FROM users WHERE uid = 0 OR uid = 1000");
        let f = empujar(&p);
        assert_eq!(f.entero("uid"), None, "se empujo un predicado bajo un OR");
    }

    #[test]
    fn lo_que_esta_bajo_un_not_no_se_empuja() {
        let p = plan("SELECT username FROM users WHERE NOT uid = 0");
        let f = empujar(&p);
        assert_eq!(f.entero("uid"), None, "se empujo un predicado bajo un NOT");
    }

    #[test]
    fn una_comparacion_de_orden_no_se_empuja() {
        // `uid > 1000` podria acotar, y no se hace a proposito: razonar sobre
        // rangos es donde se cuela el error de signo que pierde filas.
        let p = plan("SELECT username FROM users WHERE uid > 1000");
        let f = empujar(&p);
        assert!(f.vacio() || f.entero("uid").is_none());
    }

    #[test]
    fn un_not_like_no_se_empuja_como_prefijo() {
        let p = plan("SELECT path FROM files WHERE path NOT LIKE '/usr/%'");
        let f = empujar(&p);
        assert_eq!(f.prefijo("path"), None);
    }

    #[test]
    fn las_columnas_necesarias_viajan_en_el_filtro() {
        // Sin esto, un proveedor no sabe que nadie pidio `sha256` y hashea todo
        // lo que recorre.
        let p = plan("SELECT path FROM files WHERE path LIKE '/etc/%'");
        let f = empujar(&p);
        assert!(f.necesita("path"));
        assert!(!f.necesita("sha256"), "nadie pidio el hash");
    }

    #[test]
    fn una_consulta_real_contra_el_catalogo_devuelve_filas() {
        let p = plan("SELECT username, uid FROM users WHERE uid = 0");
        let l = ejecutar(&p, &ctx(), 100).expect("users la sirve el catalogo");
        assert!(l.motivo.is_none(), "motivo inesperado: {:?}", l.motivo);
        assert!(!l.filas.is_empty(), "root tiene que estar");
        assert_eq!(l.filas[0][0], "root");
        assert_eq!(l.filas[0][1], "0");
    }

    #[test]
    fn el_filtro_completo_se_vuelve_a_evaluar_sobre_lo_que_devuelve_la_tabla() {
        // El proveedor puede devolver de mas; el ejecutor tiene que filtrar.
        let p = plan("SELECT username FROM users WHERE uid = 0");
        let l = ejecutar(&p, &ctx(), 100).unwrap();
        assert!(
            l.filas.iter().all(|f| f[0] == "root"),
            "se colaron filas que no cumplen el filtro: {:?}",
            l.filas
        );
    }

    #[test]
    fn una_tabla_que_no_se_puede_leer_devuelve_su_motivo() {
        // La capacidad entera de la fase, de extremo a extremo: la consulta no
        // falla y no miente, DICE por que no hay tabla.
        let p = plan("SELECT bank, value FROM tpm_pcrs");
        let l = ejecutar(&p, &ctx(), 100).unwrap();
        if l.filas.is_empty() {
            assert!(
                l.motivo.is_some() || !l.avisos.is_empty(),
                "sin TPM hay que decirlo"
            );
        }
    }

    #[test]
    fn una_tabla_peligrosa_sin_filtro_devuelve_el_motivo_y_no_toca_el_disco() {
        let p = plan("SELECT path FROM suid_binaries");
        let reloj = std::time::Instant::now();
        let l = ejecutar(&p, &ctx(), 100).unwrap();
        assert!(l.filas.is_empty());
        let motivo = l.motivo.expect("tiene que haber motivo");
        assert!(motivo.contains("acotar"), "{motivo}");
        // Y el rechazo es inmediato: no se recorrio nada.
        assert!(
            reloj.elapsed() < std::time::Duration::from_millis(200),
            "el rechazo tardo demasiado: se toco el disco"
        );
    }

    #[test]
    fn el_count_cuenta_sin_devolver_filas() {
        let p = plan("SELECT COUNT(*) FROM users");
        let l = ejecutar(&p, &ctx(), 100).unwrap();
        assert!(l.coincidencias > 0);
        assert!(l.filas.is_empty(), "COUNT no devuelve filas");
    }

    #[test]
    fn el_limite_trunca_y_lo_dice() {
        let p = plan("SELECT username FROM users LIMIT 2");
        let l = ejecutar(&p, &ctx(), 2).unwrap();
        assert!(l.filas.len() <= 2);
        if l.coincidencias > 2 {
            assert!(l.truncada, "se corto por limite y no lo dijo");
        }
    }

    #[test]
    fn una_tabla_del_ejecutor_no_la_sirve_el_catalogo() {
        // Asi es como el ejecutor distingue las suyas sin repetir la lista.
        let p = plan("SELECT pid FROM processes");
        assert!(ejecutar(&p, &ctx(), 10).is_none());
    }

    #[test]
    fn un_like_sobre_una_tabla_del_catalogo_funciona() {
        let p = plan("SELECT name FROM systemd_units WHERE name LIKE '%.service'");
        let l = ejecutar(&p, &ctx(), 50).unwrap();
        assert!(
            l.filas.iter().all(|f| f[0].ends_with(".service")),
            "el LIKE no filtro: {:?}",
            l.filas
        );
    }

    #[test]
    fn los_valores_ausentes_se_cuentan_como_inaccesibles() {
        // Es lo que permite al analista distinguir «no hay» de «no pude ver».
        let p = plan("SELECT username, password_state FROM users");
        let l = ejecutar(&p, &ctx(), 100).unwrap();
        // Con o sin privilegios, el recuento tiene que ser coherente.
        assert!(l.inaccesibles <= (l.filas.len() as u64) * 2);
    }
}
