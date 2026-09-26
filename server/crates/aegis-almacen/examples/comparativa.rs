//! Volumen realista y las diez consultas de un SOC, para medir el almacen y
//! cotejarlo con OpenSearch sobre EXACTAMENTE el mismo conjunto de datos.
//!
//! ```text
//! comparativa generar  <esquema> <dias> <anfitriones> <eventos_por_dia> <fichero.ndjson>
//! comparativa consultas <esquema> <repeticiones>
//! ```
//!
//! `generar` produce telemetria sintetica determinista (autenticaciones,
//! procesos, red y hallazgos de cientos de anfitriones), la ingiere en el
//! almacen y escribe el mismo conjunto como lote de OpenSearch. `consultas`
//! corre las diez consultas y da la mediana de su latencia.

use std::io::Write;
use std::time::Instant;

use aegis_almacen::retencion::Retencion;
use aegis_almacen::{Almacen, FilaEntrada};
use aegis_entidad::entidad;
use aegis_parser::valor::Valor;
use sqlx::postgres::PgPoolOptions;

const NS_DIA: u64 = 86_400_000_000_000;
/// El dia de referencia: 2026-09-01T00:00:00Z. El «ahora» de las consultas es
/// el final del ultimo dia generado.
const DIA0: u64 = 1_788_220_800_000_000_000;

/// Las diez consultas de un SOC: AegisQL y su equivalente de OpenSearch.
pub const CONSULTAS: &[(&str, &str)] = &[
    ("fallos de autenticacion, 24 h",
     "SELECT COUNT(*) FROM events WHERE class = 'autenticacion' AND outcome = 'fallo' DURING LAST 24 HOURS"),
    ("top anfitriones por fallos, 24 h",
     "SELECT host, COUNT(*) FROM events WHERE outcome = 'fallo' DURING LAST 24 HOURS GROUP BY host LIMIT 10"),
    ("eventos por hora de un anfitrion, 24 h",
     "SELECT bucket, COUNT(*) FROM events WHERE host = 'srv-0007' DURING LAST 24 HOURS GROUP BY EVERY 1 HOURS"),
    ("todo de una entidad, 7 dias",
     "SELECT ts, class, producer, message FROM events WHERE entity = '$ENTIDAD' DURING LAST 7 DAYS LIMIT 10000"),
    ("hallazgos criticos, 7 dias",
     "SELECT ts, host, message FROM events WHERE severity = 'critica' DURING LAST 7 DAYS ORDER BY ts DESC LIMIT 100"),
    ("sesiones de sshd, 3 dias",
     "SELECT COUNT(*) FROM events WHERE producer = 'sshd' DURING LAST 3 DAYS"),
    ("texto en el mensaje, 24 h",
     "SELECT host, message FROM events WHERE message LIKE '%powershell%' DURING LAST 24 HOURS LIMIT 100"),
    ("volumen por origen, 7 dias",
     "SELECT source, COUNT(*) FROM events DURING LAST 7 DAYS GROUP BY source"),
    ("ultimo evento por anfitrion, 1 dia",
     "SELECT host, MAX(ts) FROM events DURING LAST 1 DAYS GROUP BY host LIMIT 1000"),
    ("union por entidad: lo de quien tuvo un critico, 1 dia",
     "SELECT COUNT(*) FROM events WHERE entity IN (SELECT entity FROM events WHERE severity = 'critica' LIMIT 100) DURING LAST 1 DAYS"),
];

/// Generador determinista (xorshift64*): el mismo conjunto en cada ejecucion,
/// y en los dos almacenes.
struct Azar(u64);

impl Azar {
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn hasta(&mut self, n: u64) -> u64 {
        self.siguiente() % n.max(1)
    }
}

/// Un evento generado, con los campos de la tabla `events`.
struct Evento {
    ts: u64,
    host: String,
    clase: &'static str,
    categoria: &'static str,
    resultado: &'static str,
    severidad: &'static str,
    origen: &'static str,
    productor: &'static str,
    mensaje: String,
}

fn evento(a: &mut Azar, dia: u64, hosts: u64) -> Evento {
    let ts = DIA0 + dia * NS_DIA + a.hasta(NS_DIA);
    let h = a.hasta(hosts);
    let host = format!("srv-{h:04}");
    let r = a.hasta(1000);
    let (clase, categoria, productor, origen) = match r {
        0..=399 => (
            "autenticacion",
            "identidad",
            ["sshd", "sudo", "login"][(r % 3) as usize],
            "journald",
        ),
        400..=749 => (
            "actividad-de-proceso",
            "sistema",
            ["bash", "python3", "cron", "powershell"][(r % 4) as usize],
            "agente",
        ),
        750..=949 => (
            "actividad-de-red",
            "red",
            ["nginx", "sshd", "curl"][(r % 3) as usize],
            "syslog",
        ),
        _ => ("hallazgo-de-seguridad", "hallazgo", "aegis", "agente"),
    };
    let resultado = if clase == "autenticacion" && a.hasta(10) < 2 {
        "fallo"
    } else {
        "exito"
    };
    let severidad = match (clase, a.hasta(100)) {
        ("hallazgo-de-seguridad", 0..=19) => "critica",
        ("hallazgo-de-seguridad", _) => "alta",
        (_, 0..=4) => "media",
        _ => "info",
    };
    let usuario = a.hasta(50);
    let mensaje = match clase {
        "autenticacion" => format!(
            "{productor}: {resultado} de autenticacion para usuario{usuario} desde 10.{}.{}.{}",
            a.hasta(255),
            a.hasta(255),
            a.hasta(255)
        ),
        "actividad-de-proceso" if productor == "powershell" => format!(
            "powershell: tarea de mantenimiento {} lanzada por usuario{usuario}",
            a.hasta(1000)
        ),
        "actividad-de-proceso" => format!(
            "{productor} pid {} arrancado por usuario{usuario}",
            a.hasta(60_000)
        ),
        "actividad-de-red" => format!(
            "{productor} conexion a 203.0.{}.{}:{}",
            a.hasta(255),
            a.hasta(255),
            [22, 80, 443, 4444][a.hasta(4) as usize]
        ),
        _ => format!("regla {} disparada en {host}", a.hasta(40)),
    };
    Evento {
        ts,
        host,
        clase,
        categoria,
        resultado,
        severidad,
        origen,
        productor,
        mensaje,
    }
}

fn json_texto(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn url() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url())
        .await
        .expect("PostgreSQL");
    let esquema = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "almacen_comparativa".into());
    let dir = std::env::temp_dir().join(format!("aegis-{esquema}"));
    let retencion = Retencion {
        caliente_dias: 30,
        tibio_dias: 60,
        frio_dias: 395,
    };
    match args.first().map(String::as_str) {
        Some("generar") => {
            let dias: u64 = args[2].parse().expect("dias");
            let hosts: u64 = args[3].parse().expect("anfitriones");
            let por_dia: u64 = args[4].parse().expect("eventos por dia");
            let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS {esquema} CASCADE"))
                .execute(&pool)
                .await;
            let a = Almacen::abrir(pool.clone(), &esquema, retencion, dir)
                .await
                .expect("abrir");
            let mut nd = std::io::BufWriter::new(std::fs::File::create(&args[5]).expect("ndjson"));
            let mut azar = Azar(0x5EED_A3C1_5EED_A3C1);
            let (mut total, mut t_ingesta, mut crudos, mut comprimidos) = (0u64, 0f64, 0u64, 0u64);
            for d in 0..dias {
                let mut lote = Vec::with_capacity(por_dia as usize);
                for _ in 0..por_dia {
                    let e = evento(&mut azar, d, hosts);
                    let ent = entidad::maquina(&e.host);
                    writeln!(nd, "{{\"index\":{{}}}}").unwrap();
                    writeln!(
                        nd,
                        "{{\"ts\":{},\"entity\":{},\"class\":{},\"category\":{},\"outcome\":{},\"severity\":{},\"source\":{},\"host\":{},\"tenant\":\"cliente\",\"producer\":{},\"message\":{},\"observed_ns\":{}}}",
                        e.ts, json_texto(&ent.texto()), json_texto(e.clase), json_texto(e.categoria), json_texto(e.resultado),
                        json_texto(e.severidad), json_texto(e.origen), json_texto(&e.host), json_texto(e.productor),
                        json_texto(&e.mensaje), e.ts + 1_000_000
                    )
                    .unwrap();
                    lote.push(FilaEntrada {
                        ts_ns: e.ts,
                        entidad: Some(ent),
                        valores: vec![
                            Valor::Texto(e.clase.into()),
                            Valor::Texto(e.categoria.into()),
                            Valor::Texto(e.resultado.into()),
                            Valor::Texto(e.severidad.into()),
                            Valor::Texto(e.origen.into()),
                            Valor::Texto(e.host),
                            Valor::Texto("cliente".into()),
                            Valor::Texto(e.productor.into()),
                            Valor::Texto(e.mensaje),
                            Valor::Entero(i64::try_from(e.ts + 1_000_000).unwrap_or(i64::MAX)),
                        ],
                    });
                }
                let t = Instant::now();
                // Lotes de cien mil, como llegarian de la canalizacion.
                while !lote.is_empty() {
                    let resto = lote.split_off(lote.len().min(100_000));
                    let inf = a.ingerir("events", lote).await.expect("ingerir");
                    crudos += inf.bytes_crudos;
                    comprimidos += inf.bytes_comprimidos;
                    total += inf.filas;
                    lote = resto;
                }
                t_ingesta += t.elapsed().as_secs_f64();
                eprintln!(
                    "  dia {d}: {total} eventos, {:.1} s de ingesta acumulada",
                    t_ingesta
                );
            }
            nd.flush().unwrap();
            let disco: i64 = sqlx::query_scalar(
                "SELECT COALESCE(sum(pg_total_relation_size(c.oid)), 0)::bigint FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind IN ('r', 'i', 't')",
            )
            .bind(&esquema)
            .fetch_one(&pool)
            .await
            .unwrap();
            println!(
                "AEGIS ingesta: {total} eventos en {t_ingesta:.1} s ({:.0} eventos/s); columnas {:.1} MiB crudas -> {:.1} MiB comprimidas; disco en PostgreSQL {:.1} MiB",
                total as f64 / t_ingesta,
                crudos as f64 / 1_048_576.0,
                comprimidos as f64 / 1_048_576.0,
                disco as f64 / 1_048_576.0
            );
        }
        Some("consultas") => {
            let reps: usize = args.get(2).and_then(|x| x.parse().ok()).unwrap_or(5);
            let a = Almacen::abrir(pool.clone(), &esquema, retencion, dir)
                .await
                .expect("abrir");
            let dias: i32 =
                sqlx::query_scalar(&format!("SELECT count(*)::int FROM {esquema}.particiones"))
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            let ahora = DIA0 + u64::try_from(dias).unwrap_or(0) * NS_DIA;
            let entidad = entidad::maquina("srv-0007").texto();
            for (nombre, q) in CONSULTAS {
                let q = q.replace("$ENTIDAD", &entidad);
                let mut tiempos = Vec::new();
                let mut filas = 0;
                let mut coste = String::new();
                for _ in 0..reps {
                    let t = Instant::now();
                    let r = a
                        .consultar(&q, ahora)
                        .await
                        .unwrap_or_else(|e| panic!("{nombre}: {e}"));
                    tiempos.push(t.elapsed().as_secs_f64() * 1000.0);
                    filas = r.filas.len();
                    coste = r.coste.frase();
                }
                tiempos.sort_by(f64::total_cmp);
                println!(
                    "AEGIS {:>8.1} ms  {:<55} {} fila(s) | {}",
                    tiempos[tiempos.len() / 2],
                    nombre,
                    filas,
                    coste
                );
            }
            // Y la que NO se ejecuta: sin acotar.
            let t = Instant::now();
            match a
                .consultar("SELECT host FROM events WHERE message LIKE '%x%'", ahora)
                .await
            {
                Err(e) => println!(
                    "AEGIS {:>8.1} ms  rechazada sin leer: {e}",
                    t.elapsed().as_secs_f64() * 1000.0
                ),
                Ok(_) => println!("AEGIS la consulta sin acotar NO se rechazo"),
            }
        }
        _ => eprintln!("uso: comparativa generar|consultas ..."),
    }
}
