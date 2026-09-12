//! La maquina de estados de remediacion: elige el playbook, lo lanza en paralelo,
//! sobrevive a fallos parciales y no repite lo ya conseguido.

use aegis_itdr::{ClaseAmenaza, Severidad};
use futures::future::join_all;

use crate::{
    AccionRemediacion, Disparador, EjecutorRemediacion, EstadoAccion, EstadoPlaybook,
    InformeRemediacion, Objetivo, ResultadoAccion,
};

/// El orquestador de remediacion automatica del Control Plane.
#[derive(Debug, Clone, Copy)]
pub struct Orquestador {
    /// Severidad minima para remediar de forma automatica. Por debajo, la
    /// deteccion se deja para el analista: no se toca la flota por una sospecha
    /// debil.
    umbral: Severidad,
}

impl Default for Orquestador {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl Orquestador {
    /// Un orquestador que remedia automaticamente a partir de severidad `Alta`.
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            umbral: Severidad::Alta,
        }
    }

    /// Un orquestador con un umbral de severidad a medida.
    #[must_use]
    pub fn con_umbral(umbral: Severidad) -> Self {
        Self { umbral }
    }

    /// El playbook de acciones para una clase de amenaza. Es la parte de DISENO de
    /// la respuesta: que se hace ante cada ataque.
    #[must_use]
    pub fn playbook_para(clase: ClaseAmenaza) -> Vec<AccionRemediacion> {
        match clase {
            // Golden Ticket: compromiso del dominio. Respuesta completa.
            ClaseAmenaza::GoldenTicket => vec![
                AccionRemediacion::AislarRed,
                AccionRemediacion::MatarProcesosSospechosos,
                AccionRemediacion::RevocarTicketsKerberos,
                AccionRemediacion::VolcadoForenseMemoria,
            ],
            // Silver Ticket: falsificacion de un TGS concreto. Contener el
            // endpoint y recoger evidencia; no hay un krbtgt que revocar.
            ClaseAmenaza::SilverTicket => vec![
                AccionRemediacion::AislarRed,
                AccionRemediacion::MatarProcesosSospechosos,
                AccionRemediacion::VolcadoForenseMemoria,
            ],
            // Kerberoasting: robo de credenciales de servicio para crackear
            // offline. Revocar los tickets pedidos y recoger evidencia.
            ClaseAmenaza::Kerberoasting => vec![
                AccionRemediacion::RevocarTicketsKerberos,
                AccionRemediacion::VolcadoForenseMemoria,
            ],
            // Escalada de privilegios por impersonacion: contener, revocar la
            // identidad implicada y recoger evidencia.
            ClaseAmenaza::EscaladaPrivilegios => vec![
                AccionRemediacion::AislarRed,
                AccionRemediacion::RevocarTicketsKerberos,
                AccionRemediacion::VolcadoForenseMemoria,
            ],
        }
    }

    /// `true` si esta deteccion merece remediacion automatica (supera el umbral).
    #[must_use]
    fn debe_remediar(&self, disparador: &Disparador) -> bool {
        self.remediaria(disparador.severidad)
    }

    /// `true` si una deteccion de esta severidad se remediaria automaticamente.
    ///
    /// Es el mismo predicado que aplica [`Orquestador::remediar`], expuesto para
    /// que quien integra el orquestador en un flujo vivo pueda FILTRAR antes de
    /// actuar. Sin el, el integrador tendria que llamar a `remediar` para
    /// descubrir que la deteccion no procedia, y para entonces ya habria abierto
    /// un registro de remediacion, publicado un evento en la consola y
    /// consumido el cerrojo de una respuesta que nunca iba a ocurrir.
    ///
    /// Que la respuesta la de el propio orquestador —y no una copia del umbral
    /// en el integrador— es deliberado: dos sitios que deciden lo mismo acaban
    /// decidiendo distinto.
    #[must_use]
    pub fn remediaria(&self, severidad: Severidad) -> bool {
        severidad >= self.umbral
    }

    /// El umbral de severidad a partir del cual se remedia.
    #[must_use]
    pub const fn umbral(&self) -> Severidad {
        self.umbral
    }

    /// Remedia una deteccion sobre `host`: elige el playbook y lo ejecuta ENTERO
    /// en paralelo, resiliente a fallos parciales. Devuelve el informe transaccional.
    pub async fn remediar<E>(
        &self,
        disparador: &Disparador,
        host: &str,
        ejecutor: &E,
    ) -> InformeRemediacion
    where
        E: EjecutorRemediacion + Sync,
    {
        let objetivo = Objetivo {
            host: host.to_string(),
            sujeto: disparador.sujeto.clone(),
        };
        if !self.debe_remediar(disparador) {
            return InformeRemediacion {
                clase: disparador.clase,
                objetivo,
                resultados: Vec::new(),
                estado: EstadoPlaybook::NoAplica,
            };
        }
        let acciones = Self::playbook_para(disparador.clase);
        let resultados = ejecutar_en_paralelo(&acciones, &objetivo, ejecutor).await;
        let estado = estado_global(&resultados);
        InformeRemediacion {
            clase: disparador.clase,
            objetivo,
            resultados,
            estado,
        }
    }

    /// Reintenta un informe previo: re-ejecuta SOLO las acciones que fallaron y
    /// conserva las que ya tuvieron exito. Es la idempotencia de la maquina de
    /// estados: lo conseguido no se repite.
    pub async fn reintentar<E>(
        &self,
        previo: &InformeRemediacion,
        ejecutor: &E,
    ) -> InformeRemediacion
    where
        E: EjecutorRemediacion + Sync,
    {
        let fallidas = previo.acciones_fallidas();
        let nuevos = ejecutar_en_paralelo(&fallidas, &previo.objetivo, ejecutor).await;

        // Se fusiona: cada accion exitosa del informe previo se mantiene tal cual;
        // cada fallida toma su nuevo resultado (o se conserva si, por lo que sea,
        // no vino uno nuevo).
        let resultados: Vec<ResultadoAccion> = previo
            .resultados
            .iter()
            .map(|r| {
                if r.exito() {
                    r.clone()
                } else {
                    nuevos
                        .iter()
                        .find(|n| n.accion == r.accion)
                        .cloned()
                        .unwrap_or_else(|| r.clone())
                }
            })
            .collect();
        let estado = estado_global(&resultados);
        InformeRemediacion {
            clase: previo.clase,
            objetivo: previo.objetivo.clone(),
            resultados,
            estado,
        }
    }
}

/// Lanza todas las acciones A LA VEZ y espera a que todas acaben. Cada una triunfa
/// o falla por su cuenta: un fallo no aborta a las demas (resiliencia a fallo
/// parcial).
async fn ejecutar_en_paralelo<E>(
    acciones: &[AccionRemediacion],
    objetivo: &Objetivo,
    ejecutor: &E,
) -> Vec<ResultadoAccion>
where
    E: EjecutorRemediacion + Sync,
{
    let futuros = acciones.iter().map(|&accion| async move {
        let estado = match ejecutor.ejecutar(accion, objetivo).await {
            Ok(()) => EstadoAccion::Exito,
            Err(motivo) => EstadoAccion::Fallo(motivo),
        };
        ResultadoAccion { accion, estado }
    });
    join_all(futuros).await
}

/// El estado global: `Completado` si todas triunfaron, `CompletadoConFallos` si
/// alguna fallo (pero todas se intentaron).
fn estado_global(resultados: &[ResultadoAccion]) -> EstadoPlaybook {
    if resultados.iter().all(ResultadoAccion::exito) {
        EstadoPlaybook::Completado
    } else {
        EstadoPlaybook::CompletadoConFallos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Doble de la FRONTERA con los agentes: registra que acciones se le pidieron
    /// y falla las que se le indique. No es un mock de la logica; es el sustituto
    /// de la flota, que es el muro. La maquina de estados se prueba de verdad.
    struct EjecutorDoble {
        llamadas: Mutex<Vec<AccionRemediacion>>,
        fallan: HashSet<AccionRemediacion>,
    }

    impl EjecutorDoble {
        fn nuevo() -> Self {
            Self {
                llamadas: Mutex::new(Vec::new()),
                fallan: HashSet::new(),
            }
        }
        fn con_fallos(fallan: &[AccionRemediacion]) -> Self {
            Self {
                llamadas: Mutex::new(Vec::new()),
                fallan: fallan.iter().copied().collect(),
            }
        }
        fn llamadas(&self) -> Vec<AccionRemediacion> {
            self.llamadas.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl EjecutorRemediacion for EjecutorDoble {
        async fn ejecutar(
            &self,
            accion: AccionRemediacion,
            _objetivo: &Objetivo,
        ) -> Result<(), String> {
            self.llamadas.lock().unwrap().push(accion);
            if self.fallan.contains(&accion) {
                Err(format!("fallo simulado: {}", accion.descripcion()))
            } else {
                Ok(())
            }
        }
    }

    fn disp(clase: ClaseAmenaza, severidad: Severidad) -> Disparador {
        Disparador {
            clase,
            severidad,
            sujeto: "krbtgt".to_string(),
        }
    }

    #[tokio::test]
    async fn golden_ticket_lanza_las_cuatro_acciones() {
        let orq = Orquestador::nuevo();
        let ej = EjecutorDoble::nuevo();
        let inf = orq
            .remediar(
                &disp(ClaseAmenaza::GoldenTicket, Severidad::Critica),
                "host-7",
                &ej,
            )
            .await;
        assert_eq!(inf.estado, EstadoPlaybook::Completado);
        assert!(inf.todo_ok());
        assert_eq!(inf.resultados.len(), 4);
        // Se pidieron las cuatro (en cualquier orden: van en paralelo).
        let pedidas: HashSet<_> = ej.llamadas().into_iter().collect();
        assert_eq!(pedidas.len(), 4);
        assert!(pedidas.contains(&AccionRemediacion::AislarRed));
        assert!(pedidas.contains(&AccionRemediacion::MatarProcesosSospechosos));
        assert!(pedidas.contains(&AccionRemediacion::RevocarTicketsKerberos));
        assert!(pedidas.contains(&AccionRemediacion::VolcadoForenseMemoria));
    }

    #[tokio::test]
    async fn un_fallo_parcial_no_aborta_las_demas() {
        let orq = Orquestador::nuevo();
        let ej = EjecutorDoble::con_fallos(&[AccionRemediacion::MatarProcesosSospechosos]);
        let inf = orq
            .remediar(
                &disp(ClaseAmenaza::GoldenTicket, Severidad::Critica),
                "host-7",
                &ej,
            )
            .await;
        assert_eq!(inf.estado, EstadoPlaybook::CompletadoConFallos);
        // Las cuatro se intentaron pese al fallo de una.
        assert_eq!(ej.llamadas().len(), 4);
        assert_eq!(
            inf.acciones_fallidas(),
            vec![AccionRemediacion::MatarProcesosSospechosos]
        );
        assert_eq!(inf.resultados.iter().filter(|r| r.exito()).count(), 3);
    }

    #[tokio::test]
    async fn el_reintento_es_idempotente_solo_repite_lo_fallido() {
        let orq = Orquestador::nuevo();
        // Primer intento: falla el volcado forense.
        let ej1 = EjecutorDoble::con_fallos(&[AccionRemediacion::VolcadoForenseMemoria]);
        let inf1 = orq
            .remediar(
                &disp(ClaseAmenaza::GoldenTicket, Severidad::Critica),
                "host-7",
                &ej1,
            )
            .await;
        assert_eq!(inf1.estado, EstadoPlaybook::CompletadoConFallos);

        // Reintento con un ejecutor que ya no falla.
        let ej2 = EjecutorDoble::nuevo();
        let inf2 = orq.reintentar(&inf1, &ej2).await;
        assert_eq!(inf2.estado, EstadoPlaybook::Completado);
        // IDEMPOTENCIA: el reintento solo pidio la accion que habia fallado.
        assert_eq!(
            ej2.llamadas(),
            vec![AccionRemediacion::VolcadoForenseMemoria]
        );
        assert!(inf2.todo_ok());
        assert_eq!(inf2.resultados.len(), 4);
    }

    #[tokio::test]
    async fn una_deteccion_no_critica_no_toca_la_flota() {
        let orq = Orquestador::nuevo();
        let ej = EjecutorDoble::nuevo();
        // Kerberoasting de severidad Media: por debajo del umbral de remediacion.
        let inf = orq
            .remediar(
                &disp(ClaseAmenaza::Kerberoasting, Severidad::Media),
                "host-7",
                &ej,
            )
            .await;
        assert_eq!(inf.estado, EstadoPlaybook::NoAplica);
        assert!(inf.resultados.is_empty());
        assert!(
            ej.llamadas().is_empty(),
            "no se toca la flota por una sospecha debil"
        );
    }

    #[tokio::test]
    async fn el_predicado_publico_y_la_decision_interna_no_pueden_divergir() {
        // Quien integra el orquestador en un flujo vivo filtra con `remediaria`
        // ANTES de abrir registros y publicar eventos. Si ese predicado y el que
        // aplica `remediar` divergieran, el integrador abriria remediaciones que
        // el orquestador descarta —o peor, descartaria las que si procedian—.
        let orq = Orquestador::con_umbral(Severidad::Alta);
        for sev in [
            Severidad::Informativa,
            Severidad::Baja,
            Severidad::Media,
            Severidad::Alta,
            Severidad::Critica,
        ] {
            let ej = EjecutorDoble::nuevo();
            let inf = orq
                .remediar(&disp(ClaseAmenaza::GoldenTicket, sev), "host-7", &ej)
                .await;
            let actuo = inf.estado != EstadoPlaybook::NoAplica;
            assert_eq!(
                orq.remediaria(sev),
                actuo,
                "el predicado publico y la decision real divergen en {sev:?}"
            );
            assert_eq!(actuo, !ej.llamadas().is_empty());
        }
        assert_eq!(orq.umbral(), Severidad::Alta);
    }

    #[tokio::test]
    async fn cada_clase_tiene_su_playbook() {
        assert_eq!(
            Orquestador::playbook_para(ClaseAmenaza::GoldenTicket).len(),
            4
        );
        let silver = Orquestador::playbook_para(ClaseAmenaza::SilverTicket);
        assert!(silver.contains(&AccionRemediacion::AislarRed));
        assert!(!silver.contains(&AccionRemediacion::RevocarTicketsKerberos));
        let kerb = Orquestador::playbook_para(ClaseAmenaza::Kerberoasting);
        assert!(kerb.contains(&AccionRemediacion::RevocarTicketsKerberos));
        assert!(!kerb.contains(&AccionRemediacion::AislarRed));
    }
}
