//! Salida de auditoria hacia el SIEM del cliente (FASE 46).
//!
//! # Que sale por aqui y por que no sale desde donde se produce
//!
//! Cada alerta y cada correlacion distribuida se escriben en el diario en disco
//! ANTES de que la llamada que las produjo devuelva. Lo que NO se hace es
//! enviarlas desde ahi: un endpoint que reporta una alerta no puede quedarse
//! esperando a que el SIEM del cliente conteste. Si el SIEM esta lento, diez mil
//! agentes se quedarian bloqueados detras de el, y el EDR dejaria de recibir
//! telemetria justo por intentar exportarla.
//!
//! El diario desacopla las dos velocidades: escribir en disco cuesta
//! microsegundos y la exportacion va por su cuenta.
//!
//! # Por que la escritura fallida se registra y no se propaga
//!
//! Si el diario esta lleno —el SIEM lleva horas caido y el presupuesto se
//! agoto— la alternativa seria devolverle un error al agente. No se hace: la
//! alerta YA esta en PostgreSQL, que es la fuente de la verdad del producto, y
//! rechazarla haria que el endpoint la reintentara y la duplicara ahi. Lo que
//! se pierde es la EXPORTACION, y eso se cuenta y se publica en `/salud` para
//! que se vea, en vez de convertirse en un fallo del camino de ingesta.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aegis_firehose::bomba::Bomba;
use aegis_firehose::destino::Destino;
use aegis_firehose::diario::{Config, Diario};
use aegis_firehose::reintento::Politica;
use aegis_firehose::syslog::{enmarcar, mensaje, severidad_de_aegis, Cabecera};

/// Un registro de auditoria listo para exportar.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Auditoria {
    /// Identificador estable del suceso; es la clave de desduplicacion.
    ///
    /// La entrega es «al menos una vez»: un acuse perdido reenvia el registro.
    /// Sin este identificador, el SIEM del cliente contaria dos veces el mismo
    /// incidente en un informe de cumplimiento.
    pub id: String,
    /// Tipo: `alerta` | `correlacion`.
    pub tipo: &'static str,
    /// Severidad 0..4.
    pub severidad: i16,
    /// Endpoint implicado, si lo hay.
    pub cn: Option<String>,
    /// Resumen legible.
    pub resumen: String,
    /// Tecnica MITRE ATT&CK, si se asigno.
    pub tecnica_mitre: Option<String>,
    /// Momento en formato RFC 3339.
    pub momento: String,
}

/// La salida de auditoria del plano de control.
pub struct Firehose {
    diario: Mutex<Diario>,
    /// Registros que no se pudieron ni siquiera escribir en el diario.
    no_exportados: AtomicU64,
    hostname: String,
}

impl Firehose {
    /// Abre el diario. Falla si el directorio no se puede usar.
    ///
    /// Fallar aqui es correcto: arrancar con una salida de auditoria que no
    /// puede escribir significa exportar cero registros sin que nadie lo sepa
    /// hasta que alguien busque la evidencia y no este.
    pub fn abrir(cfg: Config, hostname: &str) -> aegis_firehose::Resultado<Firehose> {
        Ok(Firehose {
            diario: Mutex::new(Diario::abrir(cfg)?),
            no_exportados: AtomicU64::new(0),
            hostname: hostname.to_string(),
        })
    }

    /// Anota un suceso para exportarlo. No espera al SIEM.
    pub fn anotar(&self, a: &Auditoria) {
        let Ok(carga) = serde_json::to_vec(a) else {
            self.no_exportados.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut d = match self.diario.lock() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        if let Err(e) = d.admitir(&carga) {
            // Ver el comentario del modulo: NO se propaga. La alerta ya esta en
            // PostgreSQL; lo que se pierde es la exportacion, y se cuenta.
            self.no_exportados.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %e, "AUDITORIA NO EXPORTADA: el diario no la admitio");
        }
    }

    /// Registros que no llegaron ni al diario.
    pub fn no_exportados(&self) -> u64 {
        self.no_exportados.load(Ordering::Relaxed)
    }

    /// Contadores del diario, para `/salud`.
    pub fn contadores(&self) -> aegis_firehose::Contadores {
        match self.diario.lock() {
            Ok(d) => d.contadores(),
            Err(e) => e.into_inner().contadores(),
        }
    }

    /// Marca un registro con la cabecera syslog de este plano de control.
    fn marcar(&self, carga: &[u8]) -> Vec<u8> {
        // La severidad se saca del propio registro: exportarlo todo como
        // informativo haria que las reglas de enrutado del SIEM del cliente no
        // distinguieran un ransomware de un cambio de configuracion.
        let (sev, tipo, id) = match serde_json::from_slice::<serde_json::Value>(carga) {
            Ok(v) => (
                v.get("severidad").and_then(|s| s.as_i64()).unwrap_or(0) as i16,
                v.get("tipo")
                    .and_then(|t| t.as_str())
                    .unwrap_or("auditoria")
                    .to_string(),
                v.get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("-")
                    .to_string(),
            ),
            Err(_) => (0, "auditoria".to_string(), "-".to_string()),
        };
        let cabecera = Cabecera {
            severidad: severidad_de_aegis(sev),
            momento: ahora_rfc3339(),
            hostname: self.hostname.clone(),
            app: "aegiscore".to_string(),
            procid: tipo,
            // El MSGID lleva el identificador del suceso: es lo que permite al
            // SIEM desduplicar sin abrir la carga.
            msgid: id,
        };
        enmarcar(&mensaje(&cabecera, None, &String::from_utf8_lossy(carga)))
    }

    /// Bucle de exportacion. No termina hasta que el proceso cierre.
    ///
    /// Se ejecuta en un hilo propio y no en el runtime: bloquea en E/S de disco
    /// y de red, y hacerlo en un worker de tokio castigaria a todo lo demas.
    pub fn exportar<D: Destino>(self: Arc<Self>, destino: D, politica: Politica) {
        let mut bomba = Bomba::nueva(destino, politica);
        loop {
            let resultado = {
                let mut d = match self.diario.lock() {
                    Ok(d) => d,
                    Err(e) => e.into_inner(),
                };
                bomba.vuelta(&mut d, &|c| self.marcar(c))
            };
            match resultado {
                Ok(v) if v.fallo => {
                    tracing::warn!(
                        destino = bomba.destino().nombre(),
                        espera_ms = v.espera.as_millis() as u64,
                        "el destino de auditoria no acepto el lote; se reintentara"
                    );
                    std::thread::sleep(v.espera);
                }
                // Nada pendiente: se espera un poco en vez de girar en vacio.
                // Sin esta espera, un plano de control ocioso consumiria un
                // nucleo entero preguntandole al disco si hay algo.
                Ok(v) if v.entregados == 0 => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "fallo al leer el diario de auditoria");
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
}

/// Instante actual en RFC 3339, que es lo que la RFC 5424 pide.
fn ahora_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
