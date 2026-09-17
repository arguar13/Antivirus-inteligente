//! Autoataque contra la capacidad que anade la FASE 81.
//!
//! # Que se ataca aqui
//!
//! No el sistema: el PRODUCTO. Cada capacidad nueva es superficie nueva, y estas
//! pruebas son el intento honesto de romper la que acaba de entrar. Las cuatro
//! vias por las que un proveedor de estado puede hacer daño en el endpoint de un
//! cliente:
//!
//!   1. **Agotamiento.** Una consulta que el propio cliente se difunde y que
//!      tarda minutos en cada una de sus cien mil maquinas. Es la mas probable
//!      de las cuatro, porque no hace falta un atacante: basta un analista con
//!      prisa.
//!   2. **Panico.** El agente corre con privilegios y `panic = abort`: un panico
//!      no es una excepcion, es el agente muerto y la maquina ciega.
//!   3. **Fuga.** Las tablas leen lo mas sensible de la maquina —el entorno de
//!      los procesos, `/etc/shadow`, las claves autorizadas— y el resultado
//!      viaja al plano de control.
//!   4. **Mentira.** Devolver cero filas cuando no se pudo mirar. Es la mas
//!      silenciosa y la que esta fase existe para cerrar.
//!
//! Que estas pruebas vivan en `tests/` y no junto al codigo es deliberado:
//! atacan el crate DESDE FUERA, por su interfaz publica, que es por donde lo
//! ataca cualquiera.

use aegis_estado::tabla::{Filtro, MotivoNoLeible};
use aegis_estado::{catalogo, Contexto, Tabla};
use aegis_parser::ast::Literal;
use aegis_parser::esquema::Coste;
use std::time::{Duration, Instant};

/// Contexto de ataque, con presupuesto corto.
fn ctx() -> Contexto {
    Contexto::del_sistema(aegis_entidad::entidad::maquina("autoataque"), 0, 0)
        .con_presupuesto(Duration::from_millis(250))
}

/// Filtro valido minimo para una tabla, sea peligrosa o no.
fn filtro_admisible(t: &dyn Tabla) -> Filtro {
    match t.columnas_que_acotan().first() {
        Some(c) if *c == "path" => Filtro::ninguno().con_prefijo("path", "/etc/"),
        Some(c) => Filtro::ninguno().con_igualdad(c, Literal::Entero(1)),
        None => Filtro::ninguno(),
    }
}

// ---------------------------------------------------------------------------
// 1. Agotamiento
// ---------------------------------------------------------------------------

#[test]
fn ninguna_tabla_se_salta_el_presupuesto() {
    // EL ATAQUE: difundir a la flota una consulta cuya tabla no mira el reloj.
    // No hace falta malicia; basta con que un proveedor se olvide del
    // presupuesto, que es lo que paso de verdad con `kernel_modules` y con el
    // recorrido de `/proc`, y lo que esta prueba impide que vuelva a pasar.
    //
    // El margen es generoso a proposito: lo que se comprueba es que la cota
    // EXISTE, no que sea precisa. Una tabla que tarda treinta veces su
    // presupuesto no tiene cota ninguna.
    let c = ctx();
    let margen = Duration::from_secs(5);
    for t in catalogo() {
        let filtro = filtro_admisible(t.as_ref());
        let reloj = Instant::now();
        let _ = t.leer(&c, &filtro);
        let tardo = reloj.elapsed();
        assert!(
            tardo < margen,
            "{} tardo {tardo:?} con un presupuesto de 250 ms: no respeta la cota",
            t.nombre()
        );
    }
}

#[test]
fn una_tabla_peligrosa_sin_filtro_no_toca_el_disco() {
    // EL ATAQUE: `SELECT * FROM files` a cien mil endpoints. El rechazo tiene
    // que ser INMEDIATO: si el proveedor empieza a recorrer y se para al ver que
    // no hay filtro, el daño ya esta hecho.
    let c = ctx();
    for t in catalogo() {
        if t.coste() != Coste::Peligroso {
            continue;
        }
        let reloj = Instant::now();
        let r = t.leer(&c, &Filtro::ninguno());
        let tardo = reloj.elapsed();
        assert!(
            matches!(r, Err(MotivoNoLeible::RequiereFiltro { .. })),
            "{} se dejo leer sin filtro",
            t.nombre()
        );
        assert!(
            tardo < Duration::from_millis(50),
            "{} tardo {tardo:?} en rechazar: toco el sistema antes de negarse",
            t.nombre()
        );
    }
}

#[test]
fn un_recorrido_no_sale_del_subarbol_que_se_le_dio() {
    // EL ATAQUE: dejar un enlace simbolico de `/tmp/algo` a `/`, para que una
    // consulta acotada a `/tmp` barra el disco entero de la maquina.
    let base = "/tmp/aegis-autoataque-fuga";
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(format!("{base}/dentro")).unwrap();
    std::fs::write(format!("{base}/dentro/fichero"), b"x").unwrap();
    std::os::unix::fs::symlink("/", format!("{base}/escape")).unwrap();
    std::os::unix::fs::symlink("/etc", format!("{base}/escape2")).unwrap();

    let c = ctx();
    let t = aegis_estado::tabla_llamada("files").expect("files existe");
    let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
    let r = t.leer(&c, &f).expect("leer");

    let i = t
        .esquema()
        .columnas
        .iter()
        .position(|c| c.nombre == "path")
        .unwrap();
    for fila in &r.filas {
        let ruta = fila.valor(i).a_texto();
        assert!(
            ruta.starts_with(base),
            "el recorrido se escapo del subarbol: {ruta}"
        );
    }
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn un_arbol_muy_hondo_se_corta_y_lo_dice() {
    // EL ATAQUE: un arbol de directorios de miles de niveles, que en un
    // recorrido recursivo agota la pila y mata al agente.
    let base = "/tmp/aegis-autoataque-hondo";
    let _ = std::fs::remove_dir_all(base);
    let mut ruta = std::path::PathBuf::from(base);
    for i in 0..60 {
        ruta.push(format!("n{i}"));
    }
    std::fs::create_dir_all(&ruta).unwrap();

    let c = ctx();
    let t = aegis_estado::tabla_llamada("files").expect("files existe");
    let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
    // Ni panico, ni desbordamiento de pila, ni cuelgue.
    let r = t.leer(&c, &f).expect("leer un arbol hondo no puede fallar");
    // Y la profundidad se declara como hueco o se trunca, nunca en silencio.
    assert!(
        r.truncada || !r.avisos.is_empty() || !r.filas.is_empty(),
        "un arbol de sesenta niveles no produjo ni filas ni aviso"
    );
    let _ = std::fs::remove_dir_all(base);
}

// ---------------------------------------------------------------------------
// 2. Panico
// ---------------------------------------------------------------------------

#[test]
fn ninguna_tabla_entra_en_panico_con_filtros_arbitrarios() {
    // EL ATAQUE: el filtro lo escribe un operador remoto. Se prueban las formas
    // que un analizador podria dejar pasar y que un proveedor descuidado
    // convierte en un indice fuera de rango o en una resta con acarreo.
    let c = ctx();
    let filtros = vec![
        Filtro::ninguno(),
        Filtro::ninguno().con_igualdad("pid", Literal::Entero(-1)),
        Filtro::ninguno().con_igualdad("pid", Literal::Entero(i64::MAX)),
        Filtro::ninguno().con_igualdad("pid", Literal::Entero(i64::MIN)),
        Filtro::ninguno().con_igualdad("path", Literal::Texto(String::new())),
        Filtro::ninguno().con_igualdad("path", Literal::Texto("/".repeat(512))),
        Filtro::ninguno().con_igualdad("path", Literal::Texto("../".repeat(256))),
        Filtro::ninguno().con_prefijo("path", ""),
        Filtro::ninguno().con_prefijo("path", "\0"),
        Filtro::ninguno().con_prefijo("path", "/etc/\u{202e}"),
        Filtro::ninguno().con_conjunto("pid", vec![]),
        Filtro::ninguno().con_conjunto("pid", (0..2000).map(Literal::Entero).collect()),
        Filtro::ninguno().con_igualdad("columna_que_no_existe", Literal::Entero(1)),
    ];
    for t in catalogo() {
        for f in &filtros {
            // Lo unico que se exige es que no entre en panico: el resultado
            // puede ser filas, puede ser motivo, y las dos cosas valen.
            let _ = t.leer(&c, f);
        }
    }
}

#[test]
fn una_ruta_que_no_es_utf8_valido_no_rompe_nada() {
    // EL ATAQUE: un nombre de fichero con bytes que no son UTF-8. En Linux un
    // nombre es una secuencia de bytes, no una cadena, y convertirlo con
    // `unwrap` es un panico esperando a que alguien cree ese fichero.
    use std::os::unix::ffi::OsStrExt;
    let base = "/tmp/aegis-autoataque-utf8";
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base).unwrap();
    let nombre = std::ffi::OsStr::from_bytes(b"malo-\xff\xfe-nombre");
    let ruta = std::path::Path::new(base).join(nombre);
    // Si el sistema de ficheros no lo admite, la prueba sigue valiendo para el
    // resto del arbol.
    let _ = std::fs::write(&ruta, b"x");

    let c = ctx();
    let t = aegis_estado::tabla_llamada("files").expect("files existe");
    let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
    let _ = t
        .leer(&c, &f)
        .expect("un nombre no-UTF8 no puede tumbar la tabla");
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn un_fichero_que_desaparece_a_mitad_de_la_lectura_no_rompe_nada() {
    // EL ATAQUE —y tambien el dia a dia de una maquina viva—: el fichero existe
    // cuando se enumera y ya no cuando se abre.
    let base = "/tmp/aegis-autoataque-carrera";
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base).unwrap();
    for i in 0..200 {
        std::fs::write(format!("{base}/f{i}"), b"x").unwrap();
    }

    let borrador = std::thread::spawn(move || {
        for i in 0..200 {
            let _ = std::fs::remove_file(format!("{base}/f{i}"));
            std::thread::sleep(Duration::from_micros(50));
        }
    });

    let c = ctx();
    let t = aegis_estado::tabla_llamada("files").expect("files existe");
    let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
    let _ = t
        .leer(&c, &f)
        .expect("una carrera no puede tumbar la tabla");
    borrador.join().unwrap();
    let _ = std::fs::remove_dir_all(base);
}

// ---------------------------------------------------------------------------
// 3. Fuga
// ---------------------------------------------------------------------------

#[test]
fn el_estado_de_la_contrasena_no_lleva_el_resumen() {
    // EL ATAQUE: usar la tabla de usuarios para sacar `/etc/shadow` de la
    // maquina. Lo que la tabla dice es si hay contrasena, si esta bloqueada o si
    // esta vacia; el hash no sale por aqui.
    let c = ctx();
    let t = aegis_estado::tabla_llamada("users").expect("users existe");
    let r = t.leer(&c, &Filtro::ninguno()).expect("leer usuarios");
    let i = t
        .esquema()
        .columnas
        .iter()
        .position(|c| c.nombre == "password_state")
        .unwrap();
    for fila in &r.filas {
        let v = fila.valor(i).a_texto();
        assert!(
            matches!(v.as_str(), "set" | "locked" | "empty" | "unknown" | ""),
            "password_state lleva algo que no es un estado: {v}"
        );
        assert!(!v.contains('$'), "se escapo un resumen: {v}");
    }
}

#[test]
fn el_entorno_no_se_puede_aspirar_de_toda_la_maquina() {
    // EL ATAQUE: `SELECT * FROM process_environment` difundido a la flota
    // entera. Es la consulta que juntaria todos los tokens de nube y todas las
    // contrasenas de la empresa en un solo sitio.
    let c = ctx();
    let t = aegis_estado::tabla_llamada("process_environment").expect("existe");
    match t.leer(&c, &Filtro::ninguno()) {
        Err(MotivoNoLeible::RequiereFiltro { columnas }) => {
            assert!(columnas.contains(&"pid") || columnas.contains(&"key"));
        }
        otro => panic!("el entorno se dejo aspirar entero: {otro:?}"),
    }
}

#[test]
fn una_tabla_no_devuelve_datos_de_fuera_de_su_raiz() {
    // EL ATAQUE: apuntar el contexto a un arbol de prueba y comprobar que las
    // tablas de ficheros NO leen la maquina real por detras. Si lo hicieran, una
    // prueba pasaria leyendo otra cosa, y eso invalida la suite entera.
    let base = "/tmp/aegis-autoataque-raiz";
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(format!("{base}/etc")).unwrap();
    std::fs::write(
        format!("{base}/etc/passwd"),
        "solo:x:1234:1234:inventado:/home/solo:/bin/sh\n",
    )
    .unwrap();

    let c = Contexto::del_sistema(aegis_entidad::entidad::maquina("autoataque"), 0, 0)
        .con_raiz(base)
        .con_presupuesto(Duration::from_millis(250));
    let t = aegis_estado::tabla_llamada("users").expect("users existe");
    let r = t.leer(&c, &Filtro::ninguno()).expect("leer");
    let i = t
        .esquema()
        .columnas
        .iter()
        .position(|c| c.nombre == "username")
        .unwrap();
    let nombres: Vec<String> = r.filas.iter().map(|f| f.valor(i).a_texto()).collect();
    assert_eq!(
        nombres,
        vec!["solo".to_string()],
        "la tabla leyo la maquina real en vez de la raiz que se le dio"
    );
    let _ = std::fs::remove_dir_all(base);
}

// ---------------------------------------------------------------------------
// 4. Mentira
// ---------------------------------------------------------------------------

#[test]
fn ninguna_tabla_devuelve_vacio_sin_explicarlo() {
    // EL ATAQUE es el producto contra si mismo: una tabla que calla cuando no
    // pudo mirar convierte un informe en una falsa tranquilidad. Es exactamente
    // lo que hace osquery, y lo unico que esta fase no puede permitirse.
    let c = ctx();
    let mut sin_filas = 0;
    for t in catalogo() {
        let filtro = filtro_admisible(t.as_ref());
        match t.leer(&c, &filtro) {
            Ok(f) if f.filas.is_empty() => {
                sin_filas += 1;
                assert!(
                    f.examinadas > 0 || !f.avisos.is_empty() || f.truncada,
                    "{} devolvio cero filas sin decir si miro o no",
                    t.nombre()
                );
            }
            Ok(_) => {}
            Err(m) => assert!(
                !m.frase().is_empty(),
                "{} fallo sin frase para el analista",
                t.nombre()
            ),
        }
    }
    assert!(
        sin_filas > 0,
        "en esta maquina ninguna tabla salio vacia: la prueba no esta ejerciendo su caso"
    );
}

#[test]
fn todo_motivo_es_comprensible_para_un_analista() {
    // Un motivo que dice `Os { code: 13 }` no le sirve a nadie. Cada frase tiene
    // que nombrar QUE se intentaba y POR QUE no se pudo.
    let c = ctx();
    for t in catalogo() {
        if let Err(m) = t.leer(&c, &filtro_admisible(t.as_ref())) {
            let f = m.frase();
            assert!(f.len() > 15, "{}: frase demasiado corta: {f}", t.nombre());
            assert!(
                !f.contains("Err(") && !f.contains("Error {") && !f.contains("code:"),
                "{}: la frase filtra un error crudo: {f}",
                t.nombre()
            );
        }
    }
}

#[test]
fn una_lectura_truncada_siempre_lo_declara() {
    // EL ATAQUE: creerse el numero de filas de una lista recortada en silencio.
    let c = Contexto::del_sistema(aegis_entidad::entidad::maquina("autoataque"), 0, 0)
        .con_presupuesto(Duration::from_nanos(1));
    std::thread::sleep(Duration::from_millis(2));

    let t = aegis_estado::tabla_llamada("files").expect("files existe");
    let f = Filtro::ninguno().con_prefijo("path", "/usr/");
    let r = t.leer(&c, &f).expect("leer");
    assert!(
        r.truncada,
        "se corto por presupuesto y devolvio la lista como si estuviera completa"
    );
}

#[test]
fn la_lectura_es_determinista() {
    // Dos lecturas del mismo estado dan el mismo resultado: sin esto, la misma
    // caceria sobre la misma maquina da dos respuestas y ninguna es explicable.
    let c = ctx();
    for nombre in ["users", "groups", "mounts", "cpu_mitigations", "interfaces"] {
        let t = aegis_estado::tabla_llamada(nombre).expect("existe");
        let a = t.leer(&c, &Filtro::ninguno());
        let b = t.leer(&c, &Filtro::ninguno());
        match (a, b) {
            (Ok(x), Ok(y)) => {
                assert_eq!(
                    x.filas.len(),
                    y.filas.len(),
                    "{nombre} devolvio distinto numero de filas en dos lecturas seguidas"
                );
                assert_eq!(x.filas, y.filas, "{nombre} no es determinista");
            }
            (Err(x), Err(y)) => assert_eq!(x.frase(), y.frase(), "{nombre} da dos motivos"),
            _ => panic!("{nombre} tuvo exito una vez y fallo la otra"),
        }
    }
}

#[test]
fn el_empuje_de_predicados_no_cambia_el_conjunto_de_filas() {
    // LA propiedad de correccion del empuje, comprobada de extremo a extremo:
    // lo que devuelve la consulta acotada tiene que estar contenido en lo que
    // devuelve la no acotada. Si no, el empuje pierde deteccion en silencio.
    let c = Contexto::del_sistema(aegis_entidad::entidad::maquina("autoataque"), 0, 0);
    let t = aegis_estado::tabla_llamada("users").expect("users existe");
    let i_uid = t
        .esquema()
        .columnas
        .iter()
        .position(|c| c.nombre == "uid")
        .unwrap();

    let todo = t.leer(&c, &Filtro::ninguno()).expect("sin acotar");
    let acotada = t
        .leer(
            &c,
            &Filtro::ninguno().con_igualdad("uid", Literal::Entero(0)),
        )
        .expect("acotada");

    let esperadas: Vec<_> = todo
        .filas
        .iter()
        .filter(|f| f.valor(i_uid) == &aegis_parser::valor::Valor::Entero(0))
        .collect();
    let obtenidas: Vec<_> = acotada
        .filas
        .iter()
        .filter(|f| f.valor(i_uid) == &aegis_parser::valor::Valor::Entero(0))
        .collect();
    assert_eq!(
        esperadas.len(),
        obtenidas.len(),
        "el empuje perdio filas que si cumplian el filtro"
    );
}
