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

use crate::almacen::{CANAL_CAZA, CANAL_POLITICA};
use crate::error::Resultado;

/// Lo que se reparte a los canales de suscripcion cuando algo cambia.
///
/// POR QUE HAY UNA GENERACION ADEMAS DE LA VERSION
/// -----------------------------------------------
/// Los canales despiertan por dos motivos que no son el mismo: hay politica
/// nueva, o hay una caceria que difundir. Si los dos avisos compartieran el
/// campo de version, difundir una caceria obligaria a inventarse un numero de
/// version de politica —y los agentes se descargarian una politica que no ha
/// cambiado, o peor, creerian tener una version que no existe—.
///
/// La generacion se incrementa con CUALQUIER aviso y solo sirve para despertar.
/// La version de politica sigue significando exactamente lo que significaba.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Aviso {
    /// Ultima version de politica anunciada.
    pub version_politica: i64,
    /// Contador que cambia con cada aviso, sea del tipo que sea.
    pub generacion: u64,
}

/// Reparte a los suscriptores locales los avisos que llegan de la base de datos.
#[derive(Clone)]
pub struct Notificador {
    rx: watch::Receiver<Aviso>,
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
        let (tx, rx) = watch::channel(Aviso {
            version_politica: version_inicial,
            generacion: 0,
        });
        let mut escucha = PgListener::connect(pg_url).await?;
        escucha.listen_all([CANAL_POLITICA, CANAL_CAZA]).await?;

        tokio::spawn(async move {
            let mut generacion = 0u64;
            loop {
                match escucha.recv().await {
                    Ok(aviso) => {
                        generacion = generacion.wrapping_add(1);
                        let anterior = tx.borrow().version_politica;
                        // Una caceria NO cambia la version de politica: el aviso
                        // solo sirve para despertar el canal, que despues
                        // averigua si a ese agente le toca alguna.
                        let version_politica = if aviso.channel() == CANAL_POLITICA {
                            aviso.payload().parse::<i64>().unwrap_or(anterior)
                        } else {
                            anterior
                        };
                        // `send` despierta a los receptores aunque el valor no
                        // cambie: un aviso por un comando nuevo lleva la misma
                        // version de politica y aun asi tiene que despertar al
                        // canal para que recoja ese comando.
                        if tx
                            .send(Aviso {
                                version_politica,
                                generacion,
                            })
                            .is_err()
                        {
                            // Ya no queda ningun suscriptor: el proceso cierra.
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "la escucha de avisos se detuvo; los empujes de politica y las \
                             cacerias dejan de propagarse entre instancias hasta reiniciar"
                        );
                        break;
                    }
                }
            }
        });

        Ok(Notificador { rx })
    }

    /// Crea un receptor para un canal de suscripcion.
    pub fn suscriptor(&self) -> watch::Receiver<Aviso> {
        self.rx.clone()
    }

    /// Ultima version de politica anunciada.
    pub fn version_actual(&self) -> i64 {
        self.rx.borrow().version_politica
    }
}
