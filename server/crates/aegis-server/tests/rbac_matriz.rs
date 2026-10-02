//! La matriz RBAC de la API, generada desde el codigo y recorrida entera contra
//! el servidor real (H-03, FASE 6.2 del MP-16).
//!
//! - Sin servicios (siempre): la tabla de autorizacion clasifica EXACTAMENTE las
//!   rutas que declara el enrutador; el documento generado es el del codigo; y
//!   toda ruta con cuerpo tiene esquema para el fuzzing de la API.
//! - Con PostgreSQL y Redis: cada celda rol x ruta x metodo se pide de verdad y
//!   la respuesta tiene que ser 403 si y solo si el RBAC la deniega. Despues,
//!   un administrador de un cliente recibe 403 en todo el contenido de
//!   plataforma.

mod comun;

use std::collections::BTreeSet;
use std::path::PathBuf;

use aegis_server::api;
use aegis_server::autorizacion::{
    self, permitido_por_rol, Alcance, Rol, INQUILINO_PLATAFORMA, REGLAS,
};
use axum::http::StatusCode;

/// Valor que no es de ningun recurso: UUID nulo.
const NADIE: &str = "00000000-0000-0000-0000-000000000000";

fn documento() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/generado/matriz-rbac.md")
}

#[test]
fn la_tabla_de_autorizacion_clasifica_exactamente_las_rutas_declaradas() {
    let declaradas: BTreeSet<(&str, &str)> = api::rutas_declaradas()
        .iter()
        .map(|r| (r.metodo, r.patron))
        .collect();
    let clasificadas: BTreeSet<(&str, &str)> =
        REGLAS.iter().map(|r| (r.metodo, r.patron)).collect();
    let sin_clasificar: Vec<_> = declaradas.difference(&clasificadas).collect();
    let muertas: Vec<_> = clasificadas.difference(&declaradas).collect();
    assert!(
        sin_clasificar.is_empty(),
        "rutas declaradas sin fila en autorizacion::REGLAS (se denegarian): {sin_clasificar:?}"
    );
    assert!(
        muertas.is_empty(),
        "filas de autorizacion::REGLAS sin ruta declarada: {muertas:?}"
    );
    for r in REGLAS {
        assert_eq!(
            r.alcance == Alcance::Publica,
            api::es_publica(r.metodo, r.patron),
            "{} {}: el alcance publico y RUTAS_PUBLICAS no coinciden",
            r.metodo,
            r.patron
        );
        assert_eq!(
            r.permiso.is_none(),
            matches!(r.alcance, Alcance::Publica | Alcance::Sesion),
            "{} {}: solo las publicas y cerrar sesion van sin permiso",
            r.metodo,
            r.patron
        );
        // Una ruta con {cn} o {id} de un recurso de cliente no puede tener un
        // alcance que no compruebe el dueno.
        if r.patron.contains("{cn}") {
            assert!(
                matches!(r.alcance, Alcance::Agente | Alcance::Plataforma),
                "{} {}: lleva un CN y no comprueba de quien es",
                r.metodo,
                r.patron
            );
        }
        if r.patron.starts_with("/api/casos/") {
            assert_eq!(r.alcance, Alcance::Caso, "{} {}", r.metodo, r.patron);
        }
        if r.patron.starts_with("/api/cacerias/") {
            assert_eq!(r.alcance, Alcance::Caza, "{} {}", r.metodo, r.patron);
        }
    }
}

#[test]
fn la_matriz_documentada_es_la_del_codigo() {
    let generada = autorizacion::matriz_markdown();
    let ruta = documento();
    if std::env::var("AEGIS_REGENERAR").as_deref() == Ok("1") {
        std::fs::create_dir_all(ruta.parent().unwrap()).unwrap();
        std::fs::write(&ruta, &generada).unwrap();
        return;
    }
    let escrita = std::fs::read_to_string(&ruta).unwrap_or_else(|e| {
        panic!(
            "falta {} ({e}): regenerala con AEGIS_REGENERAR=1 cargo test -p aegis-server \
             --test rbac_matriz",
            ruta.display()
        )
    });
    assert!(
        escrita == generada,
        "docs/generado/matriz-rbac.md no es la del codigo: regenerala con AEGIS_REGENERAR=1"
    );
}

#[test]
fn toda_ruta_con_cuerpo_tiene_esquema_para_el_fuzzing_de_la_api() {
    for r in api::rutas_declaradas() {
        if r.metodo == "GET" {
            continue;
        }
        let e = api::validar_cuerpo(r.metodo, r.patron, b"{}");
        assert_ne!(
            e.as_ref().err().map(String::as_str),
            Some(api::SIN_ESQUEMA),
            "{} {} no tiene esquema en api::validar_cuerpo: el objetivo de fuzzing \
             api_cuerpos no la cubriria",
            r.metodo,
            r.patron
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn la_matriz_rbac_se_recorre_entera_contra_el_servidor() {
    let Some((estado, almacen, _)) = comun::estado_real().await else {
        return;
    };
    let app = comun::app(estado);
    let mut celdas = 0usize;

    for rol in Rol::todos() {
        // Operador de PLATAFORMA: asi el 403 solo puede venir del rol. Los
        // recursos de cliente ({cn}, {id}) no son suyos y responden 404, que
        // no es 403: la celda sigue siendo inequivoca.
        let usuario = comun::operador(&almacen, rol, INQUILINO_PLATAFORMA).await;
        let token = comun::entrar(&app, &usuario).await;

        // Cerrar la sesion la ultima: invalida el token.
        let mut reglas: Vec<_> = REGLAS
            .iter()
            .filter(|r| r.alcance != Alcance::Publica)
            .collect();
        reglas.sort_by_key(|r| (r.metodo == "DELETE" && r.patron == "/api/sesion") as u8);

        for regla in reglas {
            let uri = comun::concretar(regla.patron, "nadie.plataforma", NADIE);
            // Sin cuerpo: un manejador al que se le deja pasar responde 415 o
            // 4xx antes de tocar nada, y la celda no tiene efectos.
            let (codigo, cuerpo) = comun::pedir(&app, regla.metodo, &uri, Some(&token), None).await;
            let permitido = permitido_por_rol(rol, regla);
            assert_ne!(
                codigo,
                StatusCode::UNAUTHORIZED,
                "{} {} {uri}: la sesion es valida",
                rol.nombre(),
                regla.metodo
            );
            assert_eq!(
                codigo == StatusCode::FORBIDDEN,
                !permitido,
                "{} {} {}: la matriz dice {} y el servidor respondio {codigo} ({cuerpo})",
                rol.nombre(),
                regla.metodo,
                regla.patron,
                if permitido { "permitido" } else { "denegado" }
            );
            celdas += 1;
        }
    }
    let esperadas = Rol::todos().len()
        * REGLAS
            .iter()
            .filter(|r| r.alcance != Alcance::Publica)
            .count();
    assert_eq!(celdas, esperadas, "se recorrio la matriz entera");
    println!("AEGIS-MEDIDA rbac_matriz celdas={celdas}");

    // El contenido de plataforma, con el rol que mas puede pero de un cliente.
    let admin = comun::operador(&almacen, Rol::Administrador, "flota-cliente-matriz").await;
    let token = comun::entrar(&app, &admin).await;
    for regla in REGLAS.iter().filter(|r| r.alcance == Alcance::Plataforma) {
        let uri = comun::concretar(regla.patron, "nadie.cliente-matriz", NADIE);
        let (codigo, _) = comun::pedir(&app, regla.metodo, &uri, Some(&token), None).await;
        assert_eq!(
            codigo,
            StatusCode::FORBIDDEN,
            "{} {}: un administrador de cliente no toca contenido de plataforma",
            regla.metodo,
            regla.patron
        );
    }
}
