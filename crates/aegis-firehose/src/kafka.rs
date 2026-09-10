//! Destino Kafka.
//!
//! # Por que Kafka y no otro HTTP mas
//!
//! Es donde ya esta la ingesta de la mayoria de los SIEM y SOAR grandes, y trae
//! dos cosas que un POST no da: **acuse de escritura con replicacion** y
//! **retencion del lado del receptor**. Lo primero es lo que permite que la
//! bomba confirme con fundamento; lo segundo permite que el SIEM se reprocese
//! sin volver a pedirnos nada.
//!
//! # Los tres ajustes que no son opcionales
//!
//! Se imponen en el codigo y no se dejan a la configuracion, porque un
//! despliegue que los relaje pierde auditoria sin enterarse:
//!
//! - `acks=all`. Con `acks=1` el lider acusa antes de replicar: si el lider
//!   muere en ese instante, el registro se pierde CON el visto bueno del
//!   productor, y la bomba ya lo habra borrado del diario.
//! - `enable.idempotence=true`. Sin idempotencia, un reintento interno tras un
//!   acuse perdido duplica dentro de Kafka y ademas puede REORDENAR: un
//!   «proceso terminado» delante de su «proceso creado» convierte una linea de
//!   tiempo forense en ruido.
//! - `max.in.flight.requests.per.connection <= 5`. Es el limite que la
//!   idempotencia admite manteniendo el orden.
//!
//! # Que se acusa y que no
//!
//! `entregar` no devuelve `Ok` hasta que el corredor acusa CADA registro del
//! lote. Es la diferencia real con el destino de syslog, que no tiene acuse de
//! aplicacion, y por eso los dos destinos no se presentan como equivalentes.
//!
//! # Lo que NO se pudo verificar aqui
//!
//! Contra un corredor real: nada. Este entorno de desarrollo no tiene salida
//! hacia los archivos de Apache —tres intentos, dos bloqueados por la politica
//! de red y uno agotado por tiempo— y no hay ningun corredor accesible. Lo que
//! si se comprueba de verdad es la propiedad que, si se rompiera, seria
//! catastrofica: **que un destino inalcanzable NUNCA devuelve exito**, porque
//! un exito falso hace que la bomba borre del diario evidencia que no llego a
//! ninguna parte.
//!
//! La verificacion de extremo a extremo esta escrita y es ejecutable en cuanto
//! haya un corredor: `tools/verificar-kafka.sh`.

use std::time::Duration;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;

use crate::destino::Destino;
use crate::error::{ErrorFirehose, Resultado};

/// Ajustes del destino Kafka.
#[derive(Debug, Clone)]
pub struct ConfigKafka {
    /// Lista `host:puerto` de corredores.
    pub corredores: String,
    /// Tema al que se publica.
    pub tema: String,
    /// Plazo de entrega de un lote.
    pub plazo: Duration,
    /// Ajustes adicionales del cliente.
    ///
    /// NO puede sobrescribir los tres de arriba: se aplican DESPUES. Un
    /// despliegue que pusiera `acks=1` por rendimiento perderia auditoria sin
    /// enterarse, y eso no puede depender de que nadie se equivoque.
    pub extra: Vec<(String, String)>,
}

/// Productor Kafka con acuse de escritura replicada.
pub struct DestinoKafka {
    cfg: ConfigKafka,
    productor: FutureProducer,
    runtime: tokio::runtime::Runtime,
}

impl DestinoKafka {
    /// Construye el productor.
    pub fn nuevo(cfg: ConfigKafka) -> Resultado<DestinoKafka> {
        if cfg.corredores.trim().is_empty() {
            return Err(ErrorFirehose::Config(
                "hace falta al menos un corredor de Kafka".to_string(),
            ));
        }
        if cfg.tema.trim().is_empty() {
            return Err(ErrorFirehose::Config(
                "hace falta un tema de Kafka".to_string(),
            ));
        }

        let mut c = ClientConfig::new();
        // Lo del despliegue va PRIMERO para que lo obligatorio lo pise.
        for (k, v) in &cfg.extra {
            c.set(k, v);
        }
        c.set("bootstrap.servers", &cfg.corredores)
            // Los tres innegociables. Ver el comentario del modulo.
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("max.in.flight.requests.per.connection", "5")
            // El diario ya reintenta: que la biblioteca no encole
            // indefinidamente por su cuenta. Si encolara, el fallo no llegaria
            // aqui y la bomba creeria que todo va bien mientras la memoria del
            // proceso crece.
            .set("message.timeout.ms", cfg.plazo.as_millis().to_string())
            .set("queue.buffering.max.ms", "5");

        let productor: FutureProducer = c
            .create()
            .map_err(|e| ErrorFirehose::Config(format!("productor de Kafka: {e}")))?;

        // Un runtime propio y pequeno: este destino se usa desde un hilo
        // sincrono, igual que el resto del firehose, y montar el productor
        // sobre el runtime de otro modulo ataria los dos ciclos de vida.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ErrorFirehose::Config(format!("runtime para Kafka: {e}")))?;

        Ok(DestinoKafka {
            cfg,
            productor,
            runtime,
        })
    }
}

impl Destino for DestinoKafka {
    fn nombre(&self) -> &str {
        "kafka"
    }

    fn entregar(&mut self, lote: &[&[u8]]) -> Resultado<()> {
        let plazo = self.plazo_restante();
        let tema = self.cfg.tema.clone();
        let productor = self.productor.clone();

        self.runtime.block_on(async move {
            // Se encolan TODOS y despues se esperan todos: encolar y esperar de
            // uno en uno haria un viaje de red por registro y desperdiciaria el
            // agrupamiento que Kafka hace solo.
            let mut esperas = Vec::with_capacity(lote.len());
            for carga in lote {
                let registro: FutureRecord<'_, (), [u8]> = FutureRecord::to(&tema).payload(*carga);
                esperas.push(productor.send(registro, Timeout::After(plazo)));
            }
            for espera in esperas {
                // UN solo fallo invalida el lote entero. No se confirma nada
                // parcialmente: la bomba reenviara el lote y duplicara antes
                // que dejar un hueco.
                espera.await.map_err(|(e, _)| {
                    ErrorFirehose::Config(format!("Kafka no acuso la escritura: {e}"))
                })?;
            }
            Ok(())
        })
    }
}

impl DestinoKafka {
    fn plazo_restante(&self) -> Duration {
        self.cfg.plazo
    }
}
