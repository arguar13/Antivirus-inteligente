//! Mide AegisQL contra el estado real de esta maquina, de extremo a extremo.
//!
//! # Que mide y por que estas diez consultas
//!
//! No son consultas de demostracion: son diez preguntas que un analista hace de
//! verdad durante un incidente, y cada una toca una familia distinta. Medir
//! `SELECT 1` no dice nada; medir «que unidades de systemd arrancan solas y no
//! vienen de ningun paquete» dice lo que cuesta una caza real.
//!
//! # Que NO se compara aqui, y por que
//!
//! osquery no esta instalado en la maquina de integracion, asi que sus cifras no
//! se miden: se citan de su documentacion, y se dice que son citadas. Inventar
//! una comparativa contra un rival que no corre seria exactamente la clase de
//! numero que este proyecto no publica.
//!
//! Se ejecuta desde `tools/verificar-estado.sh`.

use std::time::Instant;

/// Las diez preguntas, con lo que busca cada una.
const CONSULTAS: &[(&str, &str)] = &[
    (
        "cuentas con uid 0",
        "SELECT username, uid FROM users WHERE uid = 0",
    ),
    (
        "claves SSH autorizadas",
        "SELECT username, key_type, fingerprint FROM authorized_keys",
    ),
    (
        "sudo sin contrasena",
        "SELECT principal, command FROM sudoers WHERE nopasswd",
    ),
    (
        "servicios que arrancan solos y no vienen de un paquete",
        "SELECT name, exec_start FROM systemd_units WHERE enabled",
    ),
    (
        "tareas que se ejecutan en cada arranque",
        "SELECT username, command FROM cron_jobs WHERE at_reboot",
    ),
    (
        "modulos del nucleo sin fichero en disco",
        "SELECT name, size FROM kernel_modules",
    ),
    (
        "montajes escribibles y ejecutables",
        "SELECT mountpoint, fstype FROM mounts WHERE writable AND executable",
    ),
    (
        "vulnerabilidades de CPU sin mitigar",
        "SELECT name, status FROM cpu_mitigations WHERE vulnerable",
    ),
    (
        "sockets locales abstractos a la escucha",
        "SELECT path, kind FROM unix_sockets WHERE abstract_ns",
    ),
    (
        "binarios setuid fuera del sistema",
        "SELECT path, uid FROM suid_binaries WHERE path LIKE '/tmp/%'",
    ),
];

fn main() {
    let ctx =
        aegis_estado::Contexto::del_sistema(aegis_entidad::entidad::maquina("comparativa"), 0, 0);
    let ejecutor = aegis_hunt::ejecutor::Ejecutor::nuevo().con_estado(&ctx);

    // --- El tamano del catalogo -------------------------------------------
    let tablas = aegis_parser::esquema::TABLAS;
    let columnas: usize = tablas.iter().map(|t| t.columnas.len()).sum();
    let peligrosas = aegis_estado::peligrosas().len();
    println!("tablas            {}", tablas.len());
    println!("columnas          {columnas}");
    println!("peligrosas        {peligrosas} (exigen filtro; no se difunden sin acotar)");

    // --- Las diez consultas -----------------------------------------------
    let mut total_ms = 0u128;
    let mut con_motivo = 0;
    println!();
    println!("{:<52} {:>7}  resultado", "consulta", "ms");
    for (que, sql) in CONSULTAS {
        let arbol = match aegis_parser::sintaxis::analizar(sql) {
            Ok(a) => a,
            Err(e) => {
                println!("{que:<52} {:>7}  NO ANALIZA: {}", "-", e.dibujar(sql));
                continue;
            }
        };
        let plan = aegis_parser::plan::planificar(arbol);
        let reloj = Instant::now();
        let r = ejecutor.ejecutar(&plan);
        let ms = reloj.elapsed().as_millis();
        total_ms += ms;

        let resultado = match &r.motivo {
            Some(m) => {
                con_motivo += 1;
                format!("MOTIVO: {m}")
            }
            None => format!(
                "{} filas de {} examinadas{}{}",
                r.coincidencias,
                r.examinadas,
                if r.incompleto { ", truncada" } else { "" },
                if r.avisos.is_empty() {
                    String::new()
                } else {
                    format!(", {} hueco(s) declarado(s)", r.avisos.len())
                }
            ),
        };
        println!("{que:<52} {ms:>7}  {resultado}");
    }

    println!();
    println!("total             {total_ms} ms para las diez consultas");
    println!("con motivo        {con_motivo} de 10 no se pudieron responder Y DIJERON POR QUE");
}
