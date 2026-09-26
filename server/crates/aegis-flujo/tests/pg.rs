//! Los flujos contra el ESTADO REAL del plano de control: las tablas de
//! `aegis-server`, migradas en un esquema propio por prueba.
//!
//! Lo que se comprueba siempre es la base de datos, no el informe del motor: un
//! motor que dice «revertido» mientras la maquina sigue aislada es exactamente
//! la mentira que esta fase existe para impedir.

mod comun;

use aegis_case::auditoria::{Entrada, Rastro};
use aegis_case::{Accion, Severidad};
use aegis_entidad::Eid;
use aegis_flujo::catalogo::{
    AbrirCaso, Aislar, BloquearIndicador, Cuarentena, DeshabilitarCuenta, Enriquecer, Implicados,
    Indicador, Notificar, Tomar,
};
use aegis_flujo::paso::{ErrorPaso, Fut, Paso, Reversibilidad};
use aegis_flujo::pg::PuertosPg;
use aegis_flujo::tipos::{Contenido, Cuenta, Fichero, LocFichero, Maquina, Objetivo};
use aegis_flujo::{Estado, Flujo, Motor, ResultadoPaso, SinFirma};
use comun::{frenos, rt, Analista, Base};
use sqlx::Row;

const FLUJO: &str = "contencion de incidente";

/// La entrada de un flujo de contencion: todo lo que un incidente implica.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Incidente {
    maquina: Objetivo<Maquina>,
    cuenta: Objetivo<Cuenta>,
    red: Indicador,
    fichero: Objetivo<Fichero>,
}

impl Implicados for Incidente {
    fn implicados(&self) -> Vec<Eid> {
        vec![
            self.maquina.eid().clone(),
            self.cuenta.eid().clone(),
            self.fichero.eid().clone(),
        ]
    }
    fn describir(&self) -> String {
        format!(
            "{} / {} / {}",
            self.maquina.describir(),
            self.cuenta.describir(),
            self.red.describir()
        )
    }
}

fn incidente(cn: &str, cuenta: &str, red: &str, fichero_en: &str) -> Incidente {
    Incidente {
        maquina: Objetivo::en(cn.to_string()),
        cuenta: Objetivo::en(cuenta.to_string()),
        red: Indicador::nuevo(red).unwrap(),
        fichero: Objetivo::en(LocFichero {
            maquina: fichero_en.to_string(),
            ruta: "C:\\Users\\ana\\AppData\\Local\\Temp\\factura.exe".to_string(),
        }),
    }
}

/// Simula que el agente recoge sus ordenes pendientes (lo que hace en su
/// latido): a partir de aqui, retirar una orden ya no basta para deshacerla.
struct AgenteRecoge;

impl Paso<PuertosPg> for AgenteRecoge {
    type Entrada = Objetivo<Maquina>;
    type Salida = Objetivo<Maquina>;
    type Deshacer = ();
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = false;
    fn nombre(&self) -> &'static str {
        "el agente recoge"
    }
    fn objetivos<'a>(
        &'a self,
        _: &'a Objetivo<Maquina>,
        _: &'a PuertosPg,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn clave(&self, m: &Objetivo<Maquina>) -> String {
        m.loc().clone()
    }
    fn ejecutar<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        p: &'a PuertosPg,
    ) -> Fut<'a, Result<(Objetivo<Maquina>, ()), ErrorPaso>> {
        Box::pin(async move {
            sqlx::query("UPDATE comandos SET entregado_en = now() WHERE cn_agente = $1 AND entregado_en IS NULL")
                .bind(m.loc())
                .execute(p.pool())
                .await
                .map_err(|e| ErrorPaso::Fallo(e.to_string()))?;
            Ok((m.clone(), ()))
        })
    }
    fn revertir<'a>(&'a self, (): (), _: &'a PuertosPg) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async { Ok(()) })
    }
}

/// El flujo de contencion: aislar la maquina, deshabilitar la cuenta, bloquear
/// la red, abrir un caso, poner el fichero en cuarentena y avisar a la guardia.
fn contencion(ana: &Analista, inc: &Incidente, recoge: bool) -> Flujo<PuertosPg, Incidente> {
    let (mut f, e) = Flujo::<PuertosPg, Incidente>::nuevo(FLUJO);
    let m = f.paso(
        Tomar::nueva("maquina", |i: &Incidente| i.maquina.clone()),
        e,
        SinFirma,
    );
    let m = f.paso(
        Aislar,
        m,
        ana.aprueba(FLUJO, "aislar", &[inc.maquina.eid().clone()]),
    );
    if recoge {
        f.paso(AgenteRecoge, m, SinFirma);
    }
    let c = f.paso(
        Tomar::nueva("cuenta", |i: &Incidente| i.cuenta.clone()),
        e,
        SinFirma,
    );
    f.paso(
        DeshabilitarCuenta,
        c,
        ana.aprueba(FLUJO, "deshabilitar cuenta", &[inc.cuenta.eid().clone()]),
    );
    let r = f.paso(
        Tomar::nueva("red", |i: &Incidente| i.red.clone()),
        e,
        SinFirma,
    );
    f.paso(BloquearIndicador, r, SinFirma);
    f.paso(
        AbrirCaso::nuevo("contencion automatica", Severidad::Alta),
        e,
        SinFirma,
    );
    let fi = f.paso(
        Tomar::nueva("fichero", |i: &Incidente| i.fichero.clone()),
        e,
        SinFirma,
    );
    f.paso(Cuarentena, fi, SinFirma);
    f.paso(Notificar::a("guardia-soc"), e, SinFirma);
    f
}

async fn aislado(b: &Base, cn: &str) -> bool {
    sqlx::query_scalar("SELECT aislado FROM agentes WHERE cn = $1")
        .bind(cn)
        .fetch_one(&b.pool)
        .await
        .unwrap()
}

/// La fila de la cuarentena de red, entera, para comparar antes y despues.
async fn fila_cuarentena(b: &Base, red: &str) -> Option<String> {
    sqlx::query(
        r#"SELECT concat_ws('|', cn_origen, motivo, ordenada_por, ordenada_en, expira_en, levantada_en, levantada_por)
             FROM cuarentena WHERE direccion = $1::inet"#,
    )
    .bind(red)
    .fetch_optional(&b.pool)
    .await
    .unwrap()
    .map(|f| f.get::<String, _>(0))
}

/// Carga el rastro de un caso tal cual esta en disco y lo verifica.
async fn rastro(b: &Base, caso: &str) -> Rastro {
    let filas = sqlx::query(
        r#"SELECT secuencia, actor, accion, detalle,
                  (extract(epoch FROM cuando) * 1000000)::bigint * 1000 AS ns, anterior, resumen
             FROM caso_auditoria WHERE caso = $1 ORDER BY secuencia"#,
    )
    .bind(caso)
    .fetch_all(&b.pool)
    .await
    .unwrap();
    let mut r = Rastro::nuevo(caso);
    for f in filas {
        let accion = match f.get::<String, _>("accion").as_str() {
            "creado" => Accion::Creado,
            "cerrado" => Accion::Cerrado,
            otra => panic!("accion inesperada en el rastro: {otra}"),
        };
        r.cargar(Entrada {
            secuencia: u64::try_from(f.get::<i64, _>("secuencia")).unwrap(),
            caso: caso.to_string(),
            actor: f.get("actor"),
            accion,
            detalle: f.get("detalle"),
            cuando_ns: u64::try_from(f.get::<i64, _>("ns")).unwrap(),
            anterior: f.get("anterior"),
            resumen: f.get("resumen"),
        });
    }
    r
}

#[test]
fn un_flujo_completo_y_su_reintento_no_duplican_nada() {
    rt().block_on(async {
        let Some(b) = Base::abrir("completo").await else {
            return;
        };
        b.flota(40).await;
        let ana = Analista::nuevo("ana");
        let inc = incidente("srv-0001", "CORP\\jlopez", "198.51.100.23", "srv-0001");
        let f = contencion(&ana, &inc, false);
        let fr = frenos(40, &[]);
        let p = b.puertos("incidente-7731");

        let inf = Motor::nuevo(&p, &fr).ejecutar(&f, inc.clone()).await;
        assert_eq!(inf.estado, Estado::Completado, "{:#?}", inf.registro);
        assert!(aislado(&b, "srv-0001").await);
        assert_eq!(
            b.contar("SELECT count(*) FROM comandos WHERE accion = 'aislar'")
                .await,
            1
        );
        assert_eq!(
            b.contar("SELECT count(*) FROM comandos WHERE accion = 'cuarentena_fichero'")
                .await,
            1
        );
        assert_eq!(
            b.contar("SELECT count(*) FROM cuentas_deshabilitadas WHERE rehabilitada_en IS NULL")
                .await,
            1
        );
        assert_eq!(
            b.contar("SELECT count(*) FROM cuarentena WHERE levantada_en IS NULL")
                .await,
            1
        );
        assert_eq!(
            b.contar("SELECT count(*) FROM casos WHERE estado = 'nuevo'")
                .await,
            1
        );
        assert_eq!(b.contar("SELECT count(*) FROM caso_observables").await, 3);
        assert_eq!(b.contar("SELECT count(*) FROM notificaciones").await, 1);
        let caso: String = sqlx::query_scalar("SELECT id FROM casos")
            .fetch_one(&b.pool)
            .await
            .unwrap();
        let r = rastro(&b, &caso).await;
        assert!(r.intacto(), "{:?}", r.verificar());
        assert_eq!(r.actores(), ["flujo:contencion"]);
        // Quien aprobo cada paso firmado queda en el informe.
        let aprobados: Vec<_> = inf
            .registro
            .iter()
            .filter_map(|r| r.aprobado_por.as_deref())
            .collect();
        assert_eq!(aprobados, ["ana", "ana"]);

        // El reintento de la MISMA ejecucion no encola, abre ni avisa dos veces.
        let inf = Motor::nuevo(&p, &fr).ejecutar(&f, inc).await;
        assert_eq!(inf.estado, Estado::Completado);
        assert_eq!(b.contar("SELECT count(*) FROM comandos").await, 2);
        assert_eq!(b.contar("SELECT count(*) FROM ordenes_directorio").await, 1);
        assert_eq!(b.contar("SELECT count(*) FROM casos").await, 1);
        assert_eq!(b.contar("SELECT count(*) FROM caso_auditoria").await, 1);
        assert_eq!(b.contar("SELECT count(*) FROM notificaciones").await, 1);
        b.cerrar().await;
    });
}

#[test]
fn un_flujo_que_falla_a_medias_deja_la_base_como_estaba() {
    rt().block_on(async {
        let Some(b) = Base::abrir("amedias").await else { return };
        b.flota(40).await;
        // Antes del flujo, la red tuvo una cuarentena que un operador levanto.
        sqlx::query(
            r#"INSERT INTO cuarentena (direccion, motivo, ordenada_por, ordenada_en, levantada_en, levantada_por)
               VALUES ('203.0.113.7', 'C2 de la campana de marzo', 'marta',
                       '2026-03-02 10:00:00.123456+00', '2026-03-09 18:30:00.654321+00', 'luis')"#,
        )
        .execute(&b.pool)
        .await
        .unwrap();
        let antes = fila_cuarentena(&b, "203.0.113.7").await;

        let ana = Analista::nuevo("ana");
        // El fichero esta en una maquina que no es de la flota: la cuarentena,
        // el QUINTO paso con efecto, falla.
        let inc = incidente("srv-0002", "CORP\\ana.b", "203.0.113.7", "maquina-fantasma");
        let f = contencion(&ana, &inc, false);
        let fr = frenos(40, &[]);
        let p = b.puertos("incidente-9001");
        let inf = Motor::nuevo(&p, &fr).ejecutar(&f, inc).await;

        assert!(
            matches!(&inf.estado, Estado::Revertido { paso: "cuarentena", motivo } if motivo.contains("no esta en la flota")),
            "{:?}",
            inf.estado
        );
        let revertidos = inf.registro.iter().filter(|r| r.resultado == ResultadoPaso::Revertido).count();
        assert!(revertidos >= 4, "{:#?}", inf.registro);

        // La maquina: liberada, y la orden de aislar RETIRADA —el agente no la
        // habia recogido, asi que nunca la vera—.
        assert!(!aislado(&b, "srv-0002").await);
        assert_eq!(b.contar("SELECT count(*) FROM comandos").await, 0);
        // La cuenta: rehabilitada, con quien y cuando, y la orden al directorio.
        let f_cuenta = sqlx::query("SELECT rehabilitada_por FROM cuentas_deshabilitadas WHERE cuenta = 'CORP\\ana.b'")
            .fetch_one(&b.pool)
            .await
            .unwrap();
        assert_eq!(f_cuenta.get::<Option<String>, _>(0).as_deref(), Some("flujo:contencion"));
        let ordenes: Vec<String> =
            sqlx::query_scalar("SELECT accion FROM ordenes_directorio ORDER BY creada_en, accion")
                .fetch_all(&b.pool)
                .await
                .unwrap();
        assert_eq!(ordenes, ["deshabilitar", "rehabilitar"]);
        // La red: EXACTAMENTE la fila de antes, microsegundos incluidos.
        assert_eq!(fila_cuarentena(&b, "203.0.113.7").await, antes);
        // El caso: cerrado como no concluyente, con su rastro intacto.
        let caso = sqlx::query("SELECT id, estado, veredicto FROM casos").fetch_one(&b.pool).await.unwrap();
        assert_eq!(caso.get::<String, _>("estado"), "cerrado");
        assert_eq!(caso.get::<String, _>("veredicto"), "no-concluyente");
        let r = rastro(&b, &caso.get::<String, _>("id")).await;
        assert!(r.intacto(), "{:?}", r.verificar());
        assert_eq!(r.entradas().len(), 2);
        b.cerrar().await;
    });
}

#[test]
fn revertir_no_deshace_lo_que_el_flujo_no_hizo() {
    rt().block_on(async {
        let Some(b) = Base::abrir("ajeno").await else { return };
        b.flota(40).await;
        // Otra persona ya habia aislado la maquina, deshabilitado la cuenta y
        // bloqueado la red antes del flujo.
        sqlx::query("UPDATE agentes SET aislado = TRUE, aislado_en = now() WHERE cn = 'srv-0003'")
            .execute(&b.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO cuentas_deshabilitadas (cuenta, orden, ordenada_por) VALUES ('CORP\\x', gen_random_uuid(), 'marta')",
        )
        .execute(&b.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO cuarentena (direccion, motivo, ordenada_por) VALUES ('192.0.2.9', 'C2', 'marta')")
            .execute(&b.pool)
            .await
            .unwrap();
        let red_antes = fila_cuarentena(&b, "192.0.2.9").await;

        let ana = Analista::nuevo("ana");
        let inc = incidente("srv-0003", "CORP\\x", "192.0.2.9", "maquina-fantasma");
        let f = contencion(&ana, &inc, false);
        let inf = Motor::nuevo(&b.puertos("incidente-1"), &frenos(40, &[]))
            .ejecutar(&f, inc)
            .await;
        assert!(matches!(inf.estado, Estado::Revertido { paso: "cuarentena", .. }), "{:?}", inf.estado);

        assert!(aislado(&b, "srv-0003").await, "seguia aislada por otra persona");
        assert_eq!(b.contar("SELECT count(*) FROM comandos").await, 0);
        assert_eq!(
            b.contar("SELECT count(*) FROM cuentas_deshabilitadas WHERE rehabilitada_en IS NULL AND ordenada_por = 'marta'").await,
            1
        );
        assert_eq!(b.contar("SELECT count(*) FROM ordenes_directorio").await, 0);
        assert_eq!(fila_cuarentena(&b, "192.0.2.9").await, red_antes);
        b.cerrar().await;
    });
}

#[test]
fn una_orden_ya_recogida_se_compensa_con_la_contraria() {
    rt().block_on(async {
        let Some(b) = Base::abrir("recogida").await else {
            return;
        };
        b.flota(40).await;
        let ana = Analista::nuevo("ana");
        let inc = incidente("srv-0004", "CORP\\y", "198.51.100.99", "maquina-fantasma");
        let f = contencion(&ana, &inc, true);
        let inf = Motor::nuevo(&b.puertos("incidente-2"), &frenos(40, &[]))
            .ejecutar(&f, inc)
            .await;
        assert!(
            matches!(inf.estado, Estado::Revertido { .. }),
            "{:?}",
            inf.estado
        );
        assert!(!aislado(&b, "srv-0004").await);
        // El agente ya habia recogido «aislar»: no se puede retirar, se le manda
        // «liberar».
        let ordenes: Vec<String> = sqlx::query_scalar(
            "SELECT accion FROM comandos WHERE cn_agente = 'srv-0004' ORDER BY creado_en",
        )
        .fetch_all(&b.pool)
        .await
        .unwrap();
        assert_eq!(ordenes, ["aislar", "liberar"]);
        b.cerrar().await;
    });
}

#[test]
fn una_firma_para_otra_maquina_no_aisla_nada() {
    rt().block_on(async {
        let Some(b) = Base::abrir("firma").await else {
            return;
        };
        b.flota(40).await;
        let ana = Analista::nuevo("ana");
        let firmada = Objetivo::<Maquina>::en("srv-0005".to_string());
        let (mut f, m) = Flujo::<PuertosPg, Objetivo<Maquina>>::nuevo(FLUJO);
        f.paso(
            Aislar,
            m,
            ana.aprueba(FLUJO, "aislar", &[firmada.eid().clone()]),
        );
        // Ejecutado sobre OTRA maquina con la firma de srv-0005.
        let inf = Motor::nuevo(&b.puertos("incidente-3"), &frenos(40, &[]))
            .ejecutar(&f, Objetivo::en("srv-0006".to_string()))
            .await;
        assert_eq!(inf.registro[0].resultado, ResultadoPaso::SinPermiso);
        assert!(!aislado(&b, "srv-0006").await);
        assert_eq!(b.contar("SELECT count(*) FROM comandos").await, 0);
        b.cerrar().await;
    });
}

#[test]
fn enriquecer_lee_solo_lo_de_dentro() {
    rt().block_on(async {
        let Some(b) = Base::abrir("enriquecer").await else { return };
        b.flota(3).await;
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        for cn in ["srv-0000", "srv-0002", "srv-0002"] {
            sqlx::query(
                r#"INSERT INTO alertas (id, cn_agente, severidad, categoria, descripcion, detalles, ocurrido_en)
                   VALUES (gen_random_uuid(), $1, 3, 'malware', 'x', jsonb_build_object('sha256', upper($2)), now())"#,
            )
            .bind(cn)
            .bind(sha)
            .execute(&b.pool)
            .await
            .unwrap();
        }
        let (mut f, c) = Flujo::<PuertosPg, Objetivo<Contenido>>::nuevo("enriquecer");
        f.paso(Enriquecer, c, SinFirma);
        let inf = Motor::nuevo(&b.puertos("e-1"), &frenos(3, &[]))
            .ejecutar(&f, Objetivo::en(sha.to_string()))
            .await;
        assert_eq!(inf.estado, Estado::Completado);
        // El resultado se consulta directamente con los puertos.
        let e = aegis_flujo::catalogo::Puertos::enriquecer(&b.puertos("e-1"), sha).await.unwrap();
        assert_eq!(e.maquinas, ["srv-0000", "srv-0002"]);
        assert_eq!(e.alertas, 3);
        // Un «hash» que es un patron LIKE no se usa como patron.
        assert!(aegis_flujo::catalogo::Puertos::enriquecer(&b.puertos("e-1"), "%").await.is_err());
        b.cerrar().await;
    });
}
