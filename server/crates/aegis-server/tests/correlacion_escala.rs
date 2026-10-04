//! Coste de la correlacion distribuida con un historico realista (FASE 45).
//!
//! # Por que esto existe
//!
//! El modulo `correlador` afirma que el periodo de evaluacion se elige por el
//! COSTE de la evaluacion y no por la urgencia de la deteccion. Una afirmacion
//! asi no vale nada sin un numero: si una vuelta tardara mas que el periodo, el
//! motor se comeria la base de datos que necesita el resto del plano de control
//! —los latidos de diez mil agentes, las cacerias, la difusion de cuarentena—
//! y el producto se degradaria solo, sin que hubiera pasado nada.
//!
//! # Por que la siembra es masiva y no por la via del dominio
//!
//! Doscientas mil alertas por la via normal son doscientas mil transacciones:
//! la siembra tardaria mas que la propia suite y nadie ejecutaria la prueba. Lo
//! que se mide aqui es la CONSULTA de correlacion, no la ingesta, que ya se
//! mide en la prueba de carga (modulo 36). Los datos son los mismos que
//! produciria la via normal.
//!
//! Se ejecuta bajo demanda:
//!
//! ```text
//! AEGIS_BENCH_CORRELACION=1 cargo test -p aegis-server --test correlacion_escala -- --nocapture
//! ```

mod comun;
use aegis_prueba::{omitir, Requisito};
use aegis_server::heuristicas::NuevaHeuristica;
use comun::almacen_real;

/// Endpoints de la flota simulada.
const ENDPOINTS: usize = 10_000;
/// Alertas del historico dentro de la ventana.
///
/// Son veinte alertas por endpoint en cuarenta y ocho horas. Para un EDR que
/// solo avisa de hallazgos reales es una cifra ALTA, no media: la medida es
/// conservadora a proposito, porque de lo que se trata es de saber que pasa
/// cuando las cosas van mal.
const ALERTAS: usize = 200_000;
/// Cuentas distintas: es lo que fija cuantos GRUPOS tiene que formar la
/// consulta, y por tanto el coste de la agregacion.
const CUENTAS: usize = 500;
/// Tope que se exige a una vuelta completa.
///
/// DE DONDE SALE ESTE NUMERO
/// -------------------------
/// El primer valor que puse aqui fue 1.000 ms, elegido antes de medir nada. La
/// medida dio 1.030 ms de forma consistente, asi que la prueba fallaba por
/// treinta milisegundos de ruido de planificacion en vez de por una regresion.
/// Un tope que falla por ruido no protege: se acaba desactivando.
///
/// Lo que el producto tiene que garantizar no es un numero redondo, es que una
/// vuelta quepa HOLGADAMENTE en su periodo, porque comparte base de datos con
/// los latidos de diez mil agentes, las cacerias y la difusion de cuarentena.
/// Con el periodo de 60 s del motor, tres segundos son un 5 % de ciclo de
/// trabajo, y dejan un margen de tres veces sobre lo medido: se dispara ante
/// una regresion de verdad y no ante una maquina ocupada.
///
/// Medido en la maquina de integracion —cuatro nucleos, compartidos con el
/// propio PostgreSQL—: ~1,03 s. En un despliegue real la base de datos no
/// comparte nucleos con la suite de pruebas.
const TOPE_MS: u128 = 3_000;

#[tokio::test]
async fn una_vuelta_de_correlacion_cabe_de_sobra_en_su_periodo() {
    if std::env::var("AEGIS_BENCH_CORRELACION").is_err() {
        omitir(
            "exporta AEGIS_BENCH_CORRELACION=1 para medir",
            Requisito::Medida("AEGIS_BENCH_CORRELACION"),
        );
        return;
    }
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let pool = almacen.pool();
    let marca = uuid::Uuid::new_v4().simple().to_string();
    let categoria = format!("bench-{marca}");

    // --- Siembra -----------------------------------------------------------
    let inicio = std::time::Instant::now();
    sqlx::query(
        r#"INSERT INTO agentes (cn, id_agente, hostname, version_agente, id_flota)
           SELECT $1 || '-' || i, 'a', 'h' || i, '1.0', ''
             FROM generate_series(1, $2) AS i"#,
    )
    .bind(&marca)
    .bind(ENDPOINTS as i32)
    .execute(pool)
    .await
    .unwrap();

    // Las alertas se reparten por las 48 h de la ventana y por las cuentas.
    // Repartirlas en el tiempo importa: un historico concentrado en un instante
    // mediria un indice que en produccion nunca se comporta asi.
    //
    // POR QUE EL ENDPOINT SE SORTEA Y NO SE CALCULA CON UN MODULO
    // ----------------------------------------------------------
    // El primer intento asignaba el endpoint con `i % 10000` y la cuenta con
    // `i % 500`. Como 10.000 es multiplo de 500, las dos series quedan
    // acopladas: cada cuenta caia SIEMPRE en las mismas veinte maquinas, y la
    // siembra no producia ni un grupo por muchas alertas que tuviera. La medida
    // habria salido estupenda midiendo una consulta que no encontraba nada.
    //
    // Con semilla fija para que la medida sea repetible.
    sqlx::query("SELECT setseed(0.42)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO alertas
               (id, cn_agente, severidad, categoria, descripcion,
                tecnica_mitre, tactica_mitre, ocurrido_en, detalles)
           SELECT gen_random_uuid(),
                  $1 || '-' || (1 + floor(random() * $3)::int),
                  3, $2, 'siembra', 'T1087', 'Descubrimiento',
                  now() - make_interval(secs => (i % 172800)),
                  jsonb_build_object('cuenta', 'cuenta-' || (i % $4))
             FROM generate_series(1, $5) AS i"#,
    )
    .bind(&marca)
    .bind(&categoria)
    .bind(ENDPOINTS as i32)
    .bind(CUENTAS as i32)
    .bind(ALERTAS as i32)
    .execute(pool)
    .await
    .unwrap();

    // ANALYZE: sin estadisticas frescas, el planificador elige el plan de una
    // tabla vacia y la medida diria algo que no es.
    sqlx::query("ANALYZE alertas").execute(pool).await.unwrap();
    println!(
        "  siembra      : {ENDPOINTS} endpoints y {ALERTAS} alertas en {:.1}s",
        inicio.elapsed().as_secs_f64()
    );

    // --- Medida ------------------------------------------------------------
    let regla = NuevaHeuristica {
        nombre: categoria.clone(),
        patron: "Movimiento Lateral Distribuido".to_string(),
        tecnicas: vec![],
        categorias: vec![categoria.clone()],
        clave_detalle: "cuenta".to_string(),
        ventana_horas: 48,
        // Con 200.000 alertas repartidas entre 500 cuentas y 10.000 endpoints,
        // cada cuenta toca unas cuatrocientas maquinas distintas. El umbral se
        // pone alto —pero por debajo de eso— para que la consulta tenga que
        // agregar de verdad antes de filtrar, y para que TODOS los grupos
        // pasen: es el caso mas caro, no el mas favorable.
        minimo_endpoints: 200,
        severidad: 4,
        tecnica_mitre: Some("T1087".to_string()),
        tactica_mitre: Some("Descubrimiento".to_string()),
    }
    .validar()
    .unwrap();
    almacen.crear_heuristica(&regla, "bench").await.unwrap();
    let vigente = almacen
        .listar_heuristicas()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.nombre == categoria)
        .unwrap();

    // Una vuelta en frio y otra en caliente. La de frio es la que ve un plano de
    // control recien arrancado; la de caliente, la de regimen. Se exige el tope
    // a las DOS: un motor que solo cumple con la cache llena no cumple.
    // NADA de aserciones antes de la limpieza.
    //
    // La primera version afirmaba dentro del bucle. Cuando la siembra resulto
    // estar mal repartida, la prueba fallo AHI y dejo doscientas mil alertas y
    // diez mil agentes en la base de datos de pruebas: la suite entera paso de
    // dos segundos a treinta, y una prueba ajena empezo a fallar de forma
    // intermitente por datos que no eran suyos. Una herramienta de medida que
    // ensucia el sistema que mide no vale para medir dos veces.
    let mut medidas: Vec<(usize, u128)> = Vec::new();
    for vuelta in 0..2 {
        let t = std::time::Instant::now();
        let grupos = almacen.evaluar_heuristica(&vigente).await.unwrap();
        let total = t.elapsed();
        let evidencias: usize = grupos.iter().map(|(_, a)| a.len()).sum();
        println!(
            "  vuelta {vuelta}     : {} grupos, {evidencias} aportes  TOTAL={:.0}ms",
            grupos.len(),
            total.as_millis()
        );
        medidas.push((grupos.len(), total.as_millis()));
    }

    // --- Limpieza ----------------------------------------------------------
    // Doscientas mil alertas de una medicion no pueden quedarse en la base de
    // datos de pruebas: encarecerian todas las demas pruebas para siempre.
    sqlx::query("DELETE FROM alertas WHERE categoria = $1")
        .bind(&categoria)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM agentes WHERE cn LIKE $1")
        .bind(format!("{marca}-%"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM heuristicas_globales WHERE nombre = $1")
        .bind(&categoria)
        .execute(pool)
        .await
        .unwrap();

    for (i, (grupos, ms)) in medidas.iter().enumerate() {
        assert!(
            *grupos > 0,
            "la vuelta {i} no encontro ni un grupo: la siembra esta mal repartida y \
             la medida no diria nada sobre el coste real"
        );
        assert!(
            *ms <= TOPE_MS,
            "la vuelta {i} tardo {ms} ms y el tope es {TOPE_MS} ms: con el periodo \
             de 60 s del motor, eso ya no deja la base de datos libre para atender \
             a la flota"
        );
    }
}
