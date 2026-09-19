//! El motor que evalua las heuristicas globales (FASE 45).
//!
//! # Por que es un temporizador y no un disparo por evento
//!
//! Lo evidente seria evaluar al llegar cada alerta. No sirve: una flota de diez
//! mil endpoints entrega miles de alertas por minuto, y cada evaluacion es una
//! agregacion sobre la ventana entera. Evaluar por alerta multiplicaria ese
//! coste por el numero de alertas para obtener EXACTAMENTE la misma respuesta:
//! una correlacion sobre cuarenta y ocho horas no cambia por una alerta mas.
//!
//! Lo que se pierde es latencia, y la cantidad correcta de latencia se deduce
//! de lo que se busca: una campana que tarda dos dias en desplegarse no se
//! escapa por medio minuto. Lo que no puede pasar es lo contrario —que el motor
//! consuma la base de datos que necesita el resto del plano de control—, y por
//! eso el periodo se mide y se documenta en vez de elegirse a ojo.
//!
//! # Por que no se avisa en cada vuelta
//!
//! La evidencia sigue en la ventana despues de disparar. Un motor que avisara
//! en cada evaluacion convertiria una campana de tres dias en cuatro mil avisos
//! identicos. La primera apertura avisa; las siguientes ACTUALIZAN la misma
//! correlacion. Lo garantiza un indice unico parcial en la base de datos y no
//! el codigo, porque el plano de control corre con varias instancias y dos de
//! ellas pueden evaluar a la vez.

use std::sync::Arc;
use std::time::Duration;

use crate::dominio::ServicioFlota;
use crate::eventos::EventoPanel;

/// Cada cuanto se evaluan las reglas.
///
/// Ver el comentario del modulo: una campana distribuida tarda horas o dias en
/// desplegarse, asi que el valor no lo fija la urgencia de la deteccion sino el
/// coste de la evaluacion. Se mide con la flota cargada antes de bajarlo.
pub const PERIODO_POR_DEFECTO: Duration = Duration::from_secs(60);

/// Evalua las heuristicas globales contra el historico de alertas.
pub struct Correlador {
    servicio: Arc<ServicioFlota>,
    periodo: Duration,
}

/// Lo que produjo una vuelta de evaluacion.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vuelta {
    /// Reglas evaluadas.
    pub reglas: usize,
    /// Grupos que cumplian alguna regla.
    pub grupos: usize,
    /// Correlaciones abiertas por primera vez en esta vuelta.
    pub nuevas: usize,
    /// Grupos que cumplian la regla pero NO se abrieron porque la clave estaba
    /// excluida como falso positivo.
    ///
    /// Se cuenta, en vez de descartarse en silencio, porque distingue dos
    /// situaciones que se ven igual desde fuera: una regla que ya no encuentra
    /// nada, y una regla que encuentra lo mismo de siempre y se descarta entero
    /// por exclusiones. La segunda es una regla que hay que reescribir.
    pub descartadas: usize,
}

impl Correlador {
    /// Crea el motor con el periodo por defecto.
    pub fn nuevo(servicio: Arc<ServicioFlota>) -> Correlador {
        Correlador {
            servicio,
            periodo: PERIODO_POR_DEFECTO,
        }
    }

    /// Fija otro periodo de evaluacion.
    pub fn con_periodo(mut self, periodo: Duration) -> Correlador {
        self.periodo = periodo;
        self
    }

    /// Evalua todas las reglas activas UNA vez.
    ///
    /// Es publico a proposito: una prueba tiene que poder provocar la
    /// evaluacion en vez de dormir a esperar al temporizador. Una prueba que
    /// espera un minuto no se ejecuta, y una prueba que no se ejecuta no
    /// protege nada.
    pub async fn evaluar_una_vez(&self) -> crate::error::Resultado<Vuelta> {
        let reglas = self.servicio.almacen().heuristicas_activas().await?;
        let mut v = Vuelta {
            reglas: reglas.len(),
            ..Default::default()
        };

        for regla in &reglas {
            let grupos = match self.servicio.almacen().evaluar_heuristica(regla).await {
                Ok(g) => g,
                Err(e) => {
                    // Una regla que falla no puede parar a las demas: seria
                    // dejar ciega toda la deteccion distribuida por un error en
                    // una sola regla.
                    tracing::error!(
                        error = %e, regla = %regla.nombre,
                        "no se pudo evaluar la heuristica global"
                    );
                    continue;
                }
            };
            v.grupos += grupos.len();

            for (grupo, aportes) in &grupos {
                match self
                    .servicio
                    .almacen()
                    .abrir_o_actualizar_correlacion(regla.id, grupo, aportes)
                    .await
                {
                    Ok(Some((id, true))) => {
                        v.nuevas += 1;
                        // El nombre de la campana no es decorativo: a las tres
                        // de la manana, "Movimiento Lateral Distribuido" y la
                        // cuenta implicada es lo que decide si alguien se
                        // levanta.
                        tracing::warn!(
                            regla = %regla.nombre,
                            patron = %regla.patron,
                            endpoints = grupo.endpoints,
                            "CORRELACION DISTRIBUIDA ABIERTA"
                        );
                        self.servicio
                            .bus()
                            .publicar(EventoPanel::CorrelacionAbierta {
                                id: id.to_string(),
                                regla: regla.nombre.clone(),
                                patron: regla.patron.clone(),
                                // La clave la escribe, indirectamente, un endpoint:
                                // se acota antes de salir hacia la consola.
                                clave: grupo.clave.chars().take(256).collect(),
                                endpoints: grupo.endpoints,
                                severidad: regla.severidad,
                                tecnica_mitre: regla.tecnica_mitre.clone(),
                            });
                    }
                    Ok(Some((_, false))) => {}
                    // La clave se cerro como falso positivo mientras esta
                    // vuelta estaba en curso: no se reabre lo que el analista
                    // acaba de descartar.
                    Ok(None) => {
                        v.descartadas += 1;
                        tracing::debug!(
                            regla = %regla.nombre,
                            "grupo descartado: la clave esta excluida como falso positivo"
                        );
                    }
                    Err(e) => tracing::error!(
                        error = %e, regla = %regla.nombre,
                        "no se pudo registrar la correlacion"
                    ),
                }
            }
        }
        Ok(v)
    }

    /// Arranca el bucle de evaluacion. No termina hasta que el proceso cierre.
    pub async fn correr(self) {
        let mut tic = tokio::time::interval(self.periodo);
        // Si una vuelta tarda mas que el periodo, se salta la siguiente en vez
        // de acumular vueltas pendientes. Acumularlas convertiria una base de
        // datos momentaneamente lenta en una avalancha de evaluaciones que la
        // dejaria definitivamente lenta.
        tic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tic.tick().await;
            let inicio = std::time::Instant::now();
            match self.evaluar_una_vez().await {
                Ok(v) if v.nuevas > 0 => tracing::info!(
                    reglas = v.reglas,
                    grupos = v.grupos,
                    nuevas = v.nuevas,
                    ms = inicio.elapsed().as_millis() as u64,
                    "heuristicas globales evaluadas"
                ),
                Ok(v) => tracing::debug!(
                    reglas = v.reglas,
                    grupos = v.grupos,
                    ms = inicio.elapsed().as_millis() as u64,
                    "heuristicas globales evaluadas"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    "la evaluacion de heuristicas globales fallo; la deteccion \
                     distribuida esta ciega hasta la siguiente vuelta"
                ),
            }
        }
    }
}
