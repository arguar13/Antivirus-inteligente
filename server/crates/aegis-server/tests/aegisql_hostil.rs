//! AegisQL hostil contra su limite de coste (H-25 y H-17, E6.12 de la FASE 6.2
//! del MP-16).
//!
//! Un corpus de consultas PATOLOGICAS, generado de forma determinista, contra
//! los dos analizadores (el del endpoint y el del historico) y contra la API:
//!
//! - ninguna entra en panico ni tarda mas de su presupuesto de analisis;
//! - toda la que se acepta respeta los techos (filas, profundidad, `IN`,
//!   subconsultas, grupos, ventana);
//! - el LIKE con retroceso catastrofico se evalua en tiempo acotado;
//! - por la API: ninguna caza por encima del coste del rol llega a persistirse
//!   ni a difundirse (422 ANTES de guardar), un texto desmesurado da 413, y por
//!   encima de [`MAX_CAZAS_ABIERTAS`] simultaneas, 429.
//!
//! [`MAX_CAZAS_ABIERTAS`]: aegis_server::autorizacion::MAX_CAZAS_ABIERTAS

mod comun;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use aegis_parser::{historico, plan, sintaxis};
use aegis_server::autorizacion::{self, Rol, MAX_CAZAS_ABIERTAS, MAX_CONSULTA_BYTES};
use axum::http::StatusCode;

/// Presupuesto de analisis por consulta. Generoso: las pruebas corren sin
/// optimizar y en una maquina compartida. Lo que se busca es el exponencial,
/// que no cabe ni en un segundo.
const PRESUPUESTO_ANALISIS: Duration = Duration::from_millis(500);

/// Generador congruencial: el corpus es el mismo en cada ejecucion.
struct Azar(u64);

impl Azar {
    fn siguiente(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn hasta(&mut self, n: u64) -> u64 {
        self.siguiente() % n.max(1)
    }
}

/// El corpus hostil.
fn corpus() -> Vec<String> {
    let mut v = Vec::new();
    let p = sintaxis::PROFUNDIDAD_MAXIMA;
    // Anidamiento justo en el tope, por encima y absurdo.
    for n in [p - 1, p, p + 1, 10 * p, 100_000] {
        v.push(format!(
            "SELECT pid FROM processes WHERE {}uid = 0{}",
            "(".repeat(n),
            ")".repeat(n)
        ));
        v.push(format!(
            "SELECT pid FROM processes WHERE {}uid = 0",
            "NOT ".repeat(n)
        ));
    }
    // Listas IN alrededor del tope.
    let e = sintaxis::ELEMENTOS_IN_MAXIMOS;
    for n in [e - 1, e, e + 1, 100_000] {
        let lista: Vec<String> = (0..n).map(|i| i.to_string()).collect();
        v.push(format!(
            "SELECT pid FROM processes WHERE uid IN ({})",
            lista.join(", ")
        ));
    }
    // Cadenas de AND/OR enormes.
    for n in [1_000, 20_000] {
        let t: Vec<&str> = (0..n).map(|_| "uid = 0").collect();
        v.push(format!(
            "SELECT pid FROM processes WHERE {}",
            t.join(" OR ")
        ));
        v.push(format!(
            "SELECT pid FROM processes WHERE {}",
            t.join(" AND ")
        ));
    }
    // Limites fuera de rango y numeros que desbordan.
    for l in ["0", "10001", "4294967296", "99999999999999999999999", "-1"] {
        v.push(format!("SELECT pid FROM processes LIMIT {l}"));
    }
    v.push("SELECT pid FROM processes WHERE uid = 99999999999999999999999".into());
    // Literales gigantes, comillas sin cerrar y bytes raros.
    v.push(format!(
        "SELECT pid FROM processes WHERE name = '{}'",
        "a".repeat(1 << 20)
    ));
    v.push("SELECT pid FROM processes WHERE name = 'sin cerrar".into());
    v.push("SELECT pid FROM processes WHERE name = '\u{0}\u{feff}\u{202e}'".into());
    // LIKE con retroceso catastrofico.
    v.push(format!(
        "SELECT pid FROM processes WHERE cmdline LIKE '{}b'",
        "%a".repeat(2_000)
    ));
    // Columnas caras y peligrosas: el coste lo decide el plan, no el texto.
    v.push("SELECT sha256 FROM processes".into());
    v.push("SELECT pid FROM processes WHERE memory.entropy > 7.0".into());
    // Historico: ventana de mas de diez anos, subconsultas, grupos y cubos.
    v.push("SELECT pid FROM processes DURING LAST 87840 HOURS".into());
    v.push("SELECT pid FROM processes DURING LAST 87841 HOURS".into());
    v.push("SELECT pid FROM processes DURING LAST 999999999999 HOURS".into());
    let sub = "entity IN (SELECT entity FROM verdicts LIMIT 5)";
    for n in [
        historico::SUBCONSULTAS_MAXIMAS,
        historico::SUBCONSULTAS_MAXIMAS + 1,
        1_000,
    ] {
        let partes: Vec<&str> = (0..n).map(|_| sub).collect();
        v.push(format!(
            "SELECT pid FROM processes WHERE {}",
            partes.join(" OR ")
        ));
    }
    let mut anidada = String::from("SELECT entity FROM verdicts LIMIT 5");
    for _ in 0..500 {
        anidada = format!("SELECT entity FROM verdicts WHERE entity IN ({anidada}) LIMIT 5");
    }
    v.push(anidada);
    v.push("SELECT name, COUNT(*) FROM processes GROUP BY name, uid, gid, path, state".into());
    v.push("SELECT COUNT(*) FROM processes GROUP BY EVERY 1 MILLISECONDS".into());
    // Mutaciones al azar de un corpus valido: cortar, duplicar, intercambiar.
    let base = [
        "SELECT pid, path, sha256 FROM processes WHERE network.port = 4444 AND memory.entropy > 7.0 ORDER BY memory.entropy DESC LIMIT 50",
        "SELECT COUNT(*) FROM processes WHERE name LIKE '%ssh%'",
        "SELECT pid FROM processes WHERE NOT (uid = 0 OR name IN ('init', 'systemd')) LIMIT 10",
        "SELECT name, COUNT(*) FROM processes GROUP BY name DURING LAST 24 HOURS",
    ];
    let mut azar = Azar(0x00ae_9150_c0de);
    for _ in 0..2_000 {
        let mut q: Vec<char> = base[azar.hasta(base.len() as u64) as usize]
            .chars()
            .collect();
        for _ in 0..(1 + azar.hasta(6)) {
            if q.is_empty() {
                break;
            }
            let i = azar.hasta(q.len() as u64) as usize;
            match azar.hasta(4) {
                0 => {
                    q.remove(i);
                }
                1 => {
                    let c = q[i];
                    for _ in 0..azar.hasta(64) {
                        q.insert(i, c);
                    }
                }
                2 => q.insert(i, ['(', ')', '\'', '%', ',', '*'][azar.hasta(6) as usize]),
                _ => {
                    let j = azar.hasta(q.len() as u64) as usize;
                    q.swap(i, j);
                }
            }
        }
        v.push(q.into_iter().collect());
    }
    v
}

#[test]
fn ninguna_consulta_hostil_rompe_ni_desborda_los_analizadores() {
    let mut aceptadas = (0usize, 0usize);
    let mut peor = Duration::ZERO;
    for q in corpus() {
        let inicio = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| sintaxis::analizar(&q)))
            .unwrap_or_else(|_| panic!("sintaxis::analizar entro en panico con: {q:.200}"));
        let t = inicio.elapsed();
        peor = peor.max(t);
        assert!(
            t < PRESUPUESTO_ANALISIS,
            "sintaxis tardo {t:?} con: {q:.200}"
        );
        if let Ok(c) = r {
            aceptadas.0 += 1;
            assert!(
                c.limite > 0 && c.limite <= sintaxis::LIMITE_MAXIMO,
                "{q:.200}"
            );
            let p = catch_unwind(AssertUnwindSafe(|| plan::planificar(c)))
                .unwrap_or_else(|_| panic!("planificar entro en panico con: {q:.200}"));
            assert!(!p.consulta.tabla.is_empty());
        }

        let inicio = Instant::now();
        let h = catch_unwind(AssertUnwindSafe(|| historico::analizar(&q)))
            .unwrap_or_else(|_| panic!("historico::analizar entro en panico con: {q:.200}"));
        let t = inicio.elapsed();
        peor = peor.max(t);
        assert!(
            t < PRESUPUESTO_ANALISIS,
            "historico tardo {t:?} con: {q:.200}"
        );
        if let Ok(c) = h {
            aceptadas.1 += 1;
            assert!(c.limite > 0, "{q:.200}");
            assert!(
                c.filtro.as_ref().map_or(0, |f| f.subconsultas().len())
                    <= historico::SUBCONSULTAS_MAXIMAS,
                "{q:.200}"
            );
            assert!(c.agrupar.len() <= historico::GRUPOS_MAXIMOS, "{q:.200}");
            if let Some(cada) = c.cada_ns {
                assert!(cada >= historico::CUBO_MINIMO_NS, "{q:.200}");
            }
            if let Some(historico::Ventana::Ultimos { ns }) = c.ventana {
                assert!(ns <= historico::VENTANA_MAXIMA_NS, "{q:.200}");
            }
        }
    }
    println!(
        "AEGIS-MEDIDA aegisql_hostil consultas={} aceptadas_endpoint={} aceptadas_historico={} peor_ms={}",
        corpus().len(),
        aceptadas.0,
        aceptadas.1,
        peor.as_millis()
    );
}

#[test]
fn el_like_con_retroceso_catastrofico_se_evalua_en_tiempo_acotado() {
    let texto = aegis_parser::valor::Valor::Texto("a".repeat(4_096));
    let patron = format!("{}b", "%a".repeat(256));
    let inicio = Instant::now();
    assert!(!texto.casa_patron(&patron));
    let t = inicio.elapsed();
    assert!(
        t < Duration::from_secs(2),
        "LIKE con retroceso: {t:?} (el algoritmo tiene que ser O(n*m), no exponencial)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn la_api_rechaza_antes_de_guardar_lo_que_supera_el_coste_del_rol() {
    let Some((estado, almacen, _)) = comun::estado_real().await else {
        return;
    };
    let pool = almacen.pool().clone();
    let app = comun::app(estado);
    let inq = format!("flota-aql{}", comun::unico());
    let analista = comun::operador(&almacen, Rol::Analista, &inq).await;
    let token = comun::entrar(&app, &analista).await;

    let cazas = |inq: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cacerias WHERE inquilino = $1")
                .bind(inq)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    // Cada consulta del corpus, por la API: nunca 5xx; si se acepta, su coste
    // cabe en el del rol; si no, no se guarda nada.
    let tope = autorizacion::coste_maximo_de(Rol::Analista);
    let mut aceptadas = 0i64;
    for q in corpus().into_iter().take(400) {
        if aceptadas >= MAX_CAZAS_ABIERTAS - 1 {
            break;
        }
        let antes = cazas(inq.clone()).await;
        let (c, cuerpo) = comun::pedir(
            &app,
            "POST",
            "/api/cacerias",
            Some(&token),
            Some(serde_json::json!({ "consulta": q })),
        )
        .await;
        assert!(!c.is_server_error(), "{c} con {q:.200}: {cuerpo}");
        let despues = cazas(inq.clone()).await;
        if c == StatusCode::ACCEPTED {
            aceptadas += 1;
            assert_eq!(despues, antes + 1);
            let analizada = sintaxis::analizar(&q).expect("aceptada por la API");
            assert!(plan::planificar(analizada).coste_maximo <= tope, "{q:.200}");
        } else {
            assert_eq!(
                despues, antes,
                "rechazada ({c}) y guardada igualmente: {q:.200}"
            );
        }
    }

    // Coste por encima del rol del analista: 422 y nada guardado.
    let antes = cazas(inq.clone()).await;
    let (c, cuerpo) = comun::pedir(
        &app,
        "POST",
        "/api/cacerias",
        Some(&token),
        Some(serde_json::json!({ "consulta": "SELECT pid, sha256 FROM processes" })),
    )
    .await;
    assert_eq!(c, StatusCode::UNPROCESSABLE_ENTITY, "{cuerpo}");
    assert_eq!(cazas(inq.clone()).await, antes);

    // Texto desmesurado: 413 sin analizar.
    let (c, _) = comun::pedir(
        &app,
        "POST",
        "/api/cacerias",
        Some(&token),
        Some(serde_json::json!({
            "consulta": format!("SELECT pid FROM processes WHERE name = '{}'", "x".repeat(MAX_CONSULTA_BYTES))
        })),
    )
    .await;
    assert_eq!(c, StatusCode::PAYLOAD_TOO_LARGE);

    // Cazas simultaneas: hasta el tope, y despues 429.
    let mut codigos = Vec::new();
    for i in 0..(MAX_CAZAS_ABIERTAS + 4) {
        let (c, _) = comun::pedir(
            &app,
            "POST",
            "/api/cacerias",
            Some(&token),
            Some(serde_json::json!({ "consulta": format!("SELECT pid FROM processes WHERE uid = {i}") })),
        )
        .await;
        codigos.push(c);
    }
    assert!(
        codigos.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{codigos:?}"
    );
    let abiertas = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM cacerias WHERE inquilino = $1 AND cerrada_en IS NULL",
    )
    .bind(&inq)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(abiertas <= MAX_CAZAS_ABIERTAS, "{abiertas} abiertas");
    println!("AEGIS-MEDIDA aegisql_hostil_api aceptadas={aceptadas} abiertas={abiertas}");
}
