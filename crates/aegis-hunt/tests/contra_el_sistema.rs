//! Pruebas del ejecutor de AegisQL contra el sistema REAL que las corre.
//!
//! No hay fuente de datos de mentira aqui, y es deliberado. Un ejecutor probado
//! contra una implementacion simulada demuestra que el evaluador funciona
//! contra esa simulacion; lo que hace falta demostrar es que lee /proc, la
//! tabla de sockets y el grafo de verdad. El proceso de prueba se usa a si
//! mismo como sujeto: si una consulta por su propio PID no lo encuentra, algo
//! esta roto de verdad.

use std::net::TcpListener;
use std::time::Duration;

use aegis_behavior::dag::{BehaviorGraph, EdgeKind, GraphLimits};
use aegis_hunt::ejecutor::Ejecutor;
use aegis_parser::plan::planificar;
use aegis_parser::sintaxis::analizar;

/// Analiza, planifica y ejecuta.
fn cazar(q: &str) -> aegis_hunt::ejecutor::Resultado {
    let c = analizar(q).unwrap_or_else(|e| panic!("{}", e.dibujar(q)));
    Ejecutor::nuevo().ejecutar(&planificar(c))
}

fn mi_pid() -> u32 {
    std::process::id()
}

#[test]
fn encuentra_el_proceso_de_esta_prueba_por_su_pid() {
    let r = cazar(&format!(
        "SELECT pid, name FROM processes WHERE pid = {}",
        mi_pid()
    ));
    assert_eq!(r.filas.len(), 1, "deberia encontrarse a si mismo");
    assert_eq!(r.filas[0][0], mi_pid().to_string());
    assert!(
        !r.filas[0][1].is_empty(),
        "el nombre del ejecutable de prueba no puede venir vacio"
    );
}

#[test]
fn el_filtro_de_verdad_filtra() {
    // Un PID que no puede existir: el maximo del sistema mas uno.
    let r = cazar("SELECT pid FROM processes WHERE pid = 4294967295");
    assert!(r.filas.is_empty());
    assert!(r.examinadas > 0, "aun asi examino la tabla entera");
}

#[test]
fn count_cuenta_todo_lo_que_pasa_el_filtro_aunque_el_limite_recorte() {
    // Distincion que importa a escala de flota: el analista quiere saber
    // CUANTOS hay, no cuantos le caben en la respuesta.
    let total = cazar("SELECT COUNT(*) FROM processes");
    let n: u64 = total.filas[0][0].parse().unwrap();
    assert!(n > 1, "esta maquina tiene mas de un proceso");

    let recortada = cazar("SELECT pid FROM processes LIMIT 2");
    assert_eq!(recortada.filas.len(), 2);
    assert_eq!(
        recortada.coincidencias, n,
        "coincidencias cuenta todas, no solo las devueltas"
    );
    assert!(recortada.incompleto, "se corto por LIMIT y hay que decirlo");
}

#[test]
fn el_hash_del_propio_ejecutable_se_calcula_y_es_estable() {
    let r = cazar(&format!(
        "SELECT sha256 FROM processes WHERE pid = {}",
        mi_pid()
    ));
    let h = &r.filas[0][0];
    assert_eq!(h.len(), 64, "un SHA-256 son 64 digitos hexadecimales: {h}");
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));

    // Dos ejecuciones tienen que dar lo mismo: si no, el hash no sirve para
    // comparar contra inteligencia de amenazas.
    let otra = cazar(&format!(
        "SELECT sha256 FROM processes WHERE pid = {}",
        mi_pid()
    ));
    assert_eq!(h, &otra.filas[0][0]);
}

#[test]
fn una_consulta_de_red_ve_un_socket_que_esta_prueba_abre() {
    // Se abre un socket de verdad y se busca por su puerto. Es la prueba de que
    // la atribucion socket -> proceso funciona de extremo a extremo.
    let escucha = TcpListener::bind("127.0.0.1:0").expect("no se pudo abrir un socket");
    let puerto = escucha.local_addr().unwrap().port();

    let r = cazar(&format!(
        "SELECT pid, network.local_port FROM processes \
         WHERE pid = {} AND network.local_port = {}",
        mi_pid(),
        puerto
    ));

    // Sin privilegios no se puede leer /proc/<pid>/fd de otros, pero el propio
    // siempre se puede: esta consulta tiene que encontrarlo siempre.
    assert_eq!(
        r.filas.len(),
        1,
        "no se encontro el socket {puerto} del propio proceso"
    );
    drop(escucha);
}

#[test]
fn la_columna_de_red_es_existencial_sobre_todos_los_sockets() {
    // El defecto que esta prueba fija: mirar solo el PRIMER socket del proceso.
    // Con dos abiertos, buscar por el segundo tiene que encontrarlo igual.
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let (pa, pb) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );

    for puerto in [pa, pb] {
        let r = cazar(&format!(
            "SELECT pid FROM processes WHERE pid = {} AND network.local_port = {}",
            mi_pid(),
            puerto
        ));
        assert_eq!(
            r.filas.len(),
            1,
            "el puerto {puerto} no se encontro: la busqueda no es existencial"
        );
    }
    drop((a, b));
}

#[test]
fn not_sobre_una_columna_existencial_significa_ninguno() {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();

    // `NOT network.local_port = P` = "no tiene ninguna conexion por P".
    // Como este proceso SI la tiene, no debe salir.
    let r = cazar(&format!(
        "SELECT pid FROM processes WHERE pid = {} AND NOT network.local_port = {}",
        mi_pid(),
        puerto
    ));
    assert!(
        r.filas.is_empty(),
        "NOT sobre una columna existencial tiene que significar 'ninguno'"
    );
    drop(escucha);
}

#[test]
fn like_funciona_sobre_la_linea_de_comandos_real() {
    let r = cazar(&format!(
        "SELECT pid, cmdline FROM processes WHERE pid = {} AND cmdline LIKE '%%'",
        mi_pid()
    ));
    assert_eq!(r.filas.len(), 1, "'%' casa con cualquier cosa");
}

#[test]
fn la_tabla_de_conexiones_se_consulta_directamente() {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();

    let r = cazar(&format!(
        "SELECT local_port, state FROM connections WHERE local_port = {puerto}"
    ));
    assert_eq!(r.filas.len(), 1);
    assert_eq!(r.filas[0][1], "listen");
    drop(escucha);
}

#[test]
fn las_regiones_de_memoria_del_propio_proceso_se_leen() {
    let r = cazar(&format!(
        "SELECT pid, perms FROM memory_regions WHERE pid = {} LIMIT 5",
        mi_pid()
    ));
    assert!(
        !r.filas.is_empty(),
        "todo proceso vivo tiene regiones de memoria"
    );
    for f in &r.filas {
        assert_eq!(
            f[1].len(),
            4,
            "los permisos son cuatro caracteres: {}",
            f[1]
        );
    }
}

#[test]
fn la_entropia_de_la_propia_memoria_esta_en_el_rango_valido() {
    let r = cazar(&format!(
        "SELECT entropy FROM memory_regions WHERE pid = {} AND private LIMIT 20",
        mi_pid()
    ));
    for f in &r.filas {
        if f[0].is_empty() {
            continue; // region no legible: valor ausente, ya contado
        }
        let h: f64 = f[0].parse().expect("la entropia tiene que ser un numero");
        assert!(
            (0.0..=8.0).contains(&h),
            "entropia fuera del rango teorico: {h}"
        );
    }
}

#[test]
fn el_presupuesto_corta_una_consulta_demasiado_cara() {
    // Presupuesto imposible: la consulta tiene que devolver lo que llevara y
    // DECIR que se agoto, no fallar en silencio ni quedarse colgada.
    let c = analizar("SELECT pid, sha256 FROM processes").unwrap();
    let r = Ejecutor::nuevo()
        .con_presupuesto(Duration::from_millis(1))
        .ejecutar(&planificar(c));
    assert!(r.agotado, "deberia haberse agotado el presupuesto");
    assert!(r.incompleto, "un resultado agotado es incompleto");
}

#[test]
fn el_grafo_de_comportamiento_alimenta_las_columnas_graph() {
    // Se construye un grafo real con el proceso de prueba dentro y una arista
    // de inyeccion, y se comprueba que la consulta la ve.
    use aegis_scal::process::{ProcessInfo, ProcessKey, ProcessState};

    let mut g = BehaviorGraph::new(GraphLimits::default());
    let yo = ProcessKey::new(mi_pid(), 1);
    let otro = ProcessKey::new(mi_pid() + 1, 2);

    let info = |k: ProcessKey, padre: u32| ProcessInfo {
        key: k,
        parent_pid: padre,
        image: Some(std::path::PathBuf::from("/bin/prueba")),
        cmdline: vec!["prueba".into()],
        uid: 0,
        gid: 0,
        threads: 1,
        state: ProcessState::Running,
    };
    g.insert(&info(otro, 1), 1_000);
    g.insert(&info(yo, otro.pid), 2_000);
    g.link(otro, yo, EdgeKind::Injected, 3_000).unwrap();

    let c = analizar(&format!(
        "SELECT pid, graph.injected_by FROM processes WHERE pid = {}",
        mi_pid()
    ))
    .unwrap();
    let r = Ejecutor::con_grafo(&g).ejecutar(&planificar(c));

    assert_eq!(r.filas.len(), 1);
    assert_eq!(
        r.filas[0][1],
        otro.pid.to_string(),
        "la arista de inyeccion tiene que aparecer en graph.injected_by"
    );
}

#[test]
fn sin_grafo_las_columnas_graph_quedan_ausentes_y_se_dice() {
    // Lo importante no es que devuelva vacio, es que lo CUENTE: un analista
    // tiene que distinguir "no hay nada" de "no pude mirar".
    let r = cazar(&format!(
        "SELECT graph.techniques FROM processes WHERE pid = {}",
        mi_pid()
    ));
    assert_eq!(r.filas.len(), 1);
    assert_eq!(r.filas[0][0], "", "sin grafo el valor esta ausente");
    assert!(r.inaccesibles > 0, "y tiene que quedar contado");
}

#[test]
fn las_aristas_del_grafo_se_consultan_como_tabla() {
    use aegis_scal::process::{ProcessInfo, ProcessKey, ProcessState};

    let mut g = BehaviorGraph::new(GraphLimits::default());
    let padre = ProcessKey::new(1000, 1);
    let hijo = ProcessKey::new(1001, 2);
    let info = |k: ProcessKey, p: u32| ProcessInfo {
        key: k,
        parent_pid: p,
        image: Some(std::path::PathBuf::from("/bin/sh")),
        cmdline: vec!["sh".into()],
        uid: 0,
        gid: 0,
        threads: 1,
        state: ProcessState::Running,
    };
    g.insert(&info(padre, 1), 1_000);
    g.insert(&info(hijo, padre.pid), 2_000);
    g.link(padre, hijo, EdgeKind::Injected, 3_000).unwrap();

    let c =
        analizar("SELECT src_pid, dst_pid, kind FROM graph_edges WHERE kind = 'injected'").unwrap();
    let r = Ejecutor::con_grafo(&g).ejecutar(&planificar(c));

    assert!(
        r.filas.iter().any(|f| f[0] == "1000" && f[1] == "1001"),
        "la arista de inyeccion no aparece: {:?}",
        r.filas
    );
}

#[test]
fn el_asterisco_no_dispara_las_columnas_caras() {
    // `SELECT *` sobre miles de procesos no puede hashear cada ejecutable.
    // Se comprueba por el tiempo: con hashes seria un orden de magnitud mas.
    let inicio = std::time::Instant::now();
    let r = cazar("SELECT * FROM processes LIMIT 50");
    assert!(!r.filas.is_empty());
    assert!(
        !r.columnas.contains(&"sha256".to_string()),
        "el asterisco no debe incluir columnas caras: {:?}",
        r.columnas
    );
    assert!(
        inicio.elapsed() < Duration::from_secs(3),
        "tardo demasiado: {:?}",
        inicio.elapsed()
    );
}
