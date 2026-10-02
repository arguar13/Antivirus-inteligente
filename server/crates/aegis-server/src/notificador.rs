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

use crate::almacen::{CANAL_CAZA, CANAL_CUARENTENA, CANAL_POLITICA};
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
///
/// Ademas hay una generacion POR TIPO. No es contabilidad decorativa: es lo que
/// permite que un canal sepa POR QUE le despertaron y consulte solo lo que hace
/// falta. Sin ellas, difundir una cuarentena a diez mil endpoints hacia que los
/// diez mil canales preguntaran a la base de datos por su politica, sus comandos
/// y sus cacerias —418.162 transacciones medidas— y la orden de contencion
/// tardaba segundos en llegar en vez de milisegundos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Aviso {
    /// Ultima version de politica anunciada.
    pub version_politica: i64,
    /// Contador que cambia con cada aviso, sea del tipo que sea.
    pub generacion: u64,
    /// Sube con cada aviso de POLITICA (o de comando nuevo).
    pub gen_politica: u64,
    /// Sube con cada aviso de CACERIA.
    pub gen_caza: u64,
}

/// POR QUE LA CUARENTENA NO VIAJA EN `Aviso`
/// -----------------------------------------
/// Los avisos los esperan los DIEZ MIL canales de suscripcion. Meter ahi la
/// cuarentena significaba despertarlos a todos dos veces por orden: una por el
/// aviso —que no pueden atender todavia, porque la lista aun no esta en la
/// cache— y otra por la publicacion de la cache. Veinte mil despertares y diez
/// mil reinscripciones en las esperas para difundir una sola orden, con el
/// agravante de que la mitad no servia para nada.
///
/// El aviso de cuarentena tiene UN suscriptor —la tarea que refresca la cache—
/// y son los canales los que esperan la publicacion de esa cache, que es lo
/// unico que pueden atender.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AvisoCuarentena {
    /// Sube con cada aviso de CUARENTENA.
    pub generacion: u64,
}

/// Reparte a los suscriptores locales los avisos que llegan de la base de datos.
#[derive(Clone)]
pub struct Notificador {
    rx: watch::Receiver<Aviso>,
    rx_cuarentena: watch::Receiver<AvisoCuarentena>,
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
            ..Default::default()
        });
        let (tx_cua, rx_cuarentena) = watch::channel(AvisoCuarentena::default());
        let mut escucha = PgListener::connect(pg_url).await?;
        escucha
            .listen_all([CANAL_POLITICA, CANAL_CAZA, CANAL_CUARENTENA])
            .await?;

        tokio::spawn(async move {
            let mut generacion = 0u64;
            let (mut g_pol, mut g_caza, mut g_cua) = (0u64, 0u64, 0u64);
            let mut fallos: u32 = 0;
            loop {
                match escucha.recv().await {
                    Ok(aviso) => {
                        if fallos > 0 {
                            tracing::info!(fallos, "escucha de avisos restablecida");
                            fallos = 0;
                        }
                        generacion = generacion.wrapping_add(1);
                        let anterior = tx.borrow().version_politica;
                        // Un aviso de cuarentena NO pasa por el canal de los
                        // diez mil: va por el suyo, a la tarea que refresca la
                        // cache. Ver `AvisoCuarentena`.
                        if aviso.channel() == CANAL_CUARENTENA {
                            g_cua = g_cua.wrapping_add(1);
                            if tx_cua.send(AvisoCuarentena { generacion: g_cua }).is_err() {
                                break; // el proceso cierra
                            }
                            continue;
                        }
                        // Una caceria no cambia la version de politica: el aviso
                        // solo sirve para despertar el canal, que despues
                        // averigua que le toca a ese agente.
                        let version_politica = if aviso.channel() == CANAL_POLITICA {
                            g_pol = g_pol.wrapping_add(1);
                            aviso.payload().parse::<i64>().unwrap_or(anterior)
                        } else {
                            g_caza = g_caza.wrapping_add(1);
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
                                gen_politica: g_pol,
                                gen_caza: g_caza,
                            })
                            .is_err()
                        {
                            // Ya no queda ningun suscriptor: el proceso cierra.
                            break;
                        }
                    }
                    Err(e) => {
                        // H-42 (FASE 6.4): `PgListener::recv` reconecta solo en
                        // la siguiente llamada. Salir del bucle aqui dejaba las
                        // instancias sordas a politica, cazas y cuarentena hasta
                        // reiniciar, tras CUALQUIER corte de PostgreSQL.
                        fallos = fallos.saturating_add(1);
                        let espera = std::time::Duration::from_millis(
                            250u64.saturating_mul(1u64 << fallos.min(7)),
                        );
                        tracing::warn!(
                            error = %e,
                            fallos,
                            espera_ms = espera.as_millis() as u64,
                            "la escucha de avisos perdio PostgreSQL; se reintentara"
                        );
                        tokio::time::sleep(espera).await;
                    }
                }
            }
        });

        Ok(Notificador { rx, rx_cuarentena })
    }

    /// Crea un receptor para un canal de suscripcion.
    pub fn suscriptor(&self) -> watch::Receiver<Aviso> {
        self.rx.clone()
    }

    /// Crea un receptor de avisos de cuarentena.
    ///
    /// Lo consume UNA sola tarea —la que refresca la cache—, no los canales.
    /// Ver [`AvisoCuarentena`].
    pub fn suscriptor_cuarentena(&self) -> watch::Receiver<AvisoCuarentena> {
        self.rx_cuarentena.clone()
    }

    /// Ultima version de politica anunciada.
    pub fn version_actual(&self) -> i64 {
        self.rx.borrow().version_politica
    }
}
