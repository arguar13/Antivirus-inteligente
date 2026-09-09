//! Puente de avisos entre instancias del plano de control.
//!
//! # El problema
//!
//! El plano de control se despliega con varias instancias detras de un
//! balanceador. Un agente mantiene su canal de suscripcion abierto contra UNA de
//! ellas, elegida por el balanceador; el operador publica una regla contra
//! OTRA. Si el aviso viviera solo en la memoria del proceso, ese endpoint no se
//! enteraria hasta reconectar, y una orden como "bloquear el puerto 445 en toda
//! la flota" llegaria a una parte de la flota y a otra no.
//!
//! # La solucion
//!
//! `LISTEN`/`NOTIFY` de PostgreSQL. La base de datos ya es el punto comun de
//! todas las instancias, asi que hace de bus sin anadir una pieza mas de
//! infraestructura que mantener y vigilar. Cada instancia escucha el canal y
//! reparte el aviso a los hilos de suscripcion que atiende.

use sqlx::postgres::PgListener;
use tokio::sync::watch;

use crate::almacen::CANAL_POLITICA;
use crate::error::Resultado;

/// Reparte a los suscriptores locales los avisos que llegan de la base de datos.
#[derive(Clone)]
pub struct Notificador {
    rx: watch::Receiver<i64>,
}

impl Notificador {
    /// Arranca la escucha del canal y devuelve el repartidor.
    ///
    /// La tarea de escucha vive mientras viva el proceso. Si la conexion con la
    /// base de datos se cae, `PgListener` reconecta por su cuenta; solo si falla
    /// de forma definitiva se abandona, y se deja constancia con nivel de error
    /// porque a partir de ese momento los empujes dejan de propagarse entre
    /// instancias.
    pub async fn iniciar(pg_url: &str, version_inicial: i64) -> Resultado<Notificador> {
        let (tx, rx) = watch::channel(version_inicial);
        let mut escucha = PgListener::connect(pg_url).await?;
        escucha.listen(CANAL_POLITICA).await?;

        tokio::spawn(async move {
            loop {
                match escucha.recv().await {
                    Ok(aviso) => {
                        let version = aviso.payload().parse::<i64>().unwrap_or(0);
                        // `send` despierta a los receptores aunque el valor no
                        // cambie: un aviso por un comando nuevo lleva la misma
                        // version de politica y aun asi tiene que despertar al
                        // canal para que recoja ese comando.
                        if tx.send(version).is_err() {
                            // Ya no queda ningun suscriptor: el proceso cierra.
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "la escucha de avisos de politica se detuvo; los empujes dejan \
                             de propagarse entre instancias hasta reiniciar el servicio"
                        );
                        break;
                    }
                }
            }
        });

        Ok(Notificador { rx })
    }

    /// Crea un receptor para un canal de suscripcion.
    pub fn suscriptor(&self) -> watch::Receiver<i64> {
        self.rx.clone()
    }

    /// Ultima version de politica anunciada.
    pub fn version_actual(&self) -> i64 {
        *self.rx.borrow()
    }
}
