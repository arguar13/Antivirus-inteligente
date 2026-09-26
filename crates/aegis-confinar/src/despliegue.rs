//! El ciclo de vida de un perfil, y la reversion automatica.
//!
//! # Los estados
//!
//! ```text
//! Aprendiendo --perfil--> Permisivo --confirmacion + ensayo limpio--> Obligatorio
//!                              ^                                           |
//!                              |                          N fallos en la ventana
//!                              +---- nuevo aprendizaje ---- Retirado <------+
//! ```
//!
//! # La reversion, y por que es pegajosa
//!
//! Si con el perfil impuesto el proceso falla o se reinicia demasiadas veces en
//! una ventana, el perfil se **retira solo** y se avisa: el siguiente arranque va
//! sin perfil. Un confinamiento que rompe la produccion y no se retira es peor que
//! no tenerlo, porque el cliente acaba quitandolo de toda la flota.
//!
//! Y la retirada es **pegajosa**: un perfil retirado no vuelve a imponerse solo
//! cuando el proceso se estabiliza. Estabilizarse sin perfil no demuestra que el
//! perfil fuera bueno —demuestra lo contrario—, y un perfil que entra y sale
//! solo convierte cada fallo en un bucle. Para volver hace falta aprender de
//! nuevo y una confirmacion nueva. Es la degradacion pegajosa de la FASE 71,
//! aplicada aqui.
//!
//! # Lo que no se puede deshacer, dicho
//!
//! seccomp y Landlock no se quitan de un proceso vivo: es la propiedad que los
//! hace utiles. «Retirar el perfil» es que el SIGUIENTE arranque vaya sin el; el
//! proceso que fallo ya fallo.

use std::collections::VecDeque;

use aegis_sandbox::supervisor::Fin;

use crate::modo::Confirmacion;
use crate::perfil::Perfil;

/// En que punto del ciclo esta un perfil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// Aun no hay perfil: se aprende.
    Aprendiendo,
    /// Hay perfil y se ensaya sin bloquear nada.
    Permisivo,
    /// El perfil se impone.
    Obligatorio {
        /// Quien lo confirmo.
        confirmacion: Confirmacion,
    },
    /// El perfil se retiro solo. No vuelve sin aprender de nuevo y confirmar.
    Retirado {
        /// Por que.
        motivo: String,
    },
}

/// Cuanto aguanta un perfil impuesto antes de retirarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoliticaReversion {
    /// Fallos (salidas no limpias) en la ventana que retiran el perfil.
    pub max_fallos: usize,
    /// Arranques en la ventana que lo retiran, aunque salgan bien: un servicio
    /// que se reinicia sin parar tambien esta roto.
    pub max_arranques: usize,
    /// La ventana, en nanosegundos.
    pub ventana_ns: u64,
}

impl Default for PoliticaReversion {
    fn default() -> Self {
        PoliticaReversion {
            max_fallos: 3,
            max_arranques: 10,
            ventana_ns: 10 * 60 * 1_000_000_000,
        }
    }
}

/// Lo que el despliegue avisa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aviso {
    /// El perfil se retiro solo.
    Retirado {
        /// Por que.
        motivo: String,
    },
}

/// Por que una transicion no se permite.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransicionInvalida {
    /// Se pidio imponer sin un ensayo limpio.
    #[error("no se impone un perfil sin un ensayo permisivo limpio: el ultimo ensayo habria bloqueado {0} cosa(s)")]
    EnsayoNoLimpio(usize),
    /// Se pidio imponer sin haber ensayado nunca.
    #[error("no se impone un perfil que no se ha ensayado nunca")]
    SinEnsayo,
    /// Se pidio imponer desde un estado que no lo admite.
    #[error("desde {0} no se puede imponer: hace falta un perfil aprendido y ensayado")]
    DesdeEstado(&'static str),
}

/// El despliegue de un perfil sobre un programa.
#[derive(Debug, Clone)]
pub struct Despliegue {
    perfil: Option<Perfil>,
    estado: Estado,
    politica: PoliticaReversion,
    ultimo_ensayo: Option<usize>,
    fallos: VecDeque<u64>,
    arranques: VecDeque<u64>,
}

impl Despliegue {
    /// Un despliegue nuevo: empieza aprendiendo.
    #[must_use]
    pub fn nuevo(politica: PoliticaReversion) -> Despliegue {
        Despliegue {
            perfil: None,
            estado: Estado::Aprendiendo,
            politica,
            ultimo_ensayo: None,
            fallos: VecDeque::new(),
            arranques: VecDeque::new(),
        }
    }

    /// El estado.
    #[must_use]
    pub fn estado(&self) -> &Estado {
        &self.estado
    }

    /// El perfil, si hay.
    #[must_use]
    pub fn perfil(&self) -> Option<&Perfil> {
        self.perfil.as_ref()
    }

    /// Entrega un perfil aprendido: se pasa a permisivo. Tambien es la unica
    /// salida de `Retirado`.
    pub fn aprendido(&mut self, perfil: Perfil) {
        self.perfil = Some(perfil);
        self.estado = Estado::Permisivo;
        self.ultimo_ensayo = None;
        self.fallos.clear();
        self.arranques.clear();
    }

    /// Anota el resultado de un ensayo permisivo.
    pub fn ensayado(&mut self, habria_bloqueado: usize) {
        if self.estado == Estado::Permisivo {
            self.ultimo_ensayo = Some(habria_bloqueado);
        }
    }

    /// Impone el perfil. Exige confirmacion Y un ensayo permisivo limpio.
    ///
    /// # Errores
    /// [`TransicionInvalida`] si no esta en permisivo o el ensayo no fue limpio.
    pub fn imponer(&mut self, confirmacion: Confirmacion) -> Result<(), TransicionInvalida> {
        let desde = match &self.estado {
            Estado::Permisivo => None,
            Estado::Aprendiendo => Some("aprendiendo"),
            Estado::Obligatorio { .. } => Some("obligatorio"),
            Estado::Retirado { .. } => Some("retirado"),
        };
        if let Some(d) = desde {
            return Err(TransicionInvalida::DesdeEstado(d));
        }
        match self.ultimo_ensayo {
            None => Err(TransicionInvalida::SinEnsayo),
            Some(n) if n > 0 => Err(TransicionInvalida::EnsayoNoLimpio(n)),
            Some(_) => {
                self.estado = Estado::Obligatorio { confirmacion };
                self.fallos.clear();
                self.arranques.clear();
                Ok(())
            }
        }
    }

    fn podar(cola: &mut VecDeque<u64>, ahora_ns: u64, ventana: u64) {
        while cola
            .front()
            .is_some_and(|t| ahora_ns.saturating_sub(*t) > ventana)
        {
            cola.pop_front();
        }
    }

    /// Anota como termino un arranque del programa, y retira el perfil si toca.
    pub fn registrar(&mut self, fin: Fin, ahora_ns: u64) -> Option<Aviso> {
        if !matches!(self.estado, Estado::Obligatorio { .. }) {
            return None;
        }
        let v = self.politica.ventana_ns;
        self.arranques.push_back(ahora_ns);
        Self::podar(&mut self.arranques, ahora_ns, v);
        if !fin.limpio() {
            self.fallos.push_back(ahora_ns);
        }
        Self::podar(&mut self.fallos, ahora_ns, v);

        let motivo = if self.fallos.len() >= self.politica.max_fallos {
            Some(format!(
                "{} fallos con el perfil impuesto en la ventana (el ultimo: {fin:?}); el tope es {}",
                self.fallos.len(),
                self.politica.max_fallos
            ))
        } else if self.arranques.len() >= self.politica.max_arranques {
            Some(format!(
                "{} arranques en la ventana: el proceso se reinicia sin parar con el perfil impuesto",
                self.arranques.len()
            ))
        } else {
            None
        };
        motivo.map(|m| {
            self.estado = Estado::Retirado { motivo: m.clone() };
            Aviso::Retirado { motivo: m }
        })
    }

    /// Si el siguiente arranque tiene que ir con el perfil impuesto.
    #[must_use]
    pub fn impone(&self) -> bool {
        matches!(self.estado, Estado::Obligatorio { .. })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::path::Path;

    fn conf() -> Confirmacion {
        Confirmacion::nueva("ana", "ensayo limpio", 1).expect("valida")
    }

    fn impuesto() -> Despliegue {
        let mut d = Despliegue::nuevo(PoliticaReversion::default());
        d.aprendido(Perfil::nuevo(Path::new("/x")));
        d.ensayado(0);
        d.imponer(conf()).expect("imponer");
        d
    }

    #[test]
    fn no_se_impone_sin_ensayo_limpio_ni_desde_aprendiendo() {
        let mut d = Despliegue::nuevo(PoliticaReversion::default());
        assert_eq!(
            d.imponer(conf()),
            Err(TransicionInvalida::DesdeEstado("aprendiendo"))
        );
        d.aprendido(Perfil::nuevo(Path::new("/x")));
        assert_eq!(d.imponer(conf()), Err(TransicionInvalida::SinEnsayo));
        d.ensayado(3);
        assert_eq!(
            d.imponer(conf()),
            Err(TransicionInvalida::EnsayoNoLimpio(3))
        );
        d.ensayado(0);
        assert!(d.imponer(conf()).is_ok());
        assert!(d.impone());
    }

    #[test]
    fn tres_fallos_en_la_ventana_retiran_el_perfil_y_se_avisa() {
        let mut d = impuesto();
        assert!(d.registrar(Fin::Codigo(3), 1).is_none());
        assert!(d.registrar(Fin::Codigo(0), 2).is_none());
        assert!(d.registrar(Fin::Senal(libc::SIGSYS), 3).is_none());
        let a = d.registrar(Fin::Codigo(1), 4);
        assert!(matches!(a, Some(Aviso::Retirado { .. })), "{a:?}");
        assert!(!d.impone(), "el siguiente arranque va SIN perfil");
    }

    #[test]
    fn los_fallos_fuera_de_la_ventana_no_cuentan() {
        let mut d = impuesto();
        let min = 60 * 1_000_000_000u64;
        d.registrar(Fin::Codigo(1), 0);
        d.registrar(Fin::Codigo(1), 11 * min);
        assert!(
            d.registrar(Fin::Codigo(1), 22 * min).is_none(),
            "tres fallos, pero en tres ventanas"
        );
        assert!(d.impone());
    }

    #[test]
    fn un_proceso_que_se_reinicia_sin_parar_tambien_lo_retira() {
        let mut d = impuesto();
        let mut aviso = None;
        for t in 0..10 {
            aviso = d.registrar(Fin::Codigo(0), t);
        }
        assert!(
            matches!(aviso, Some(Aviso::Retirado { ref motivo }) if motivo.contains("arranques"))
        );
    }

    /// DEGRADACION PEGAJOSA: retirado, no vuelve solo, ni con una confirmacion
    /// nueva. Hace falta aprender otra vez.
    #[test]
    fn la_retirada_es_pegajosa() {
        let mut d = impuesto();
        for t in 0..3 {
            d.registrar(Fin::Codigo(1), t);
        }
        assert!(matches!(d.estado(), Estado::Retirado { .. }));
        // Que el proceso vaya bien sin perfil no cambia nada.
        assert!(d.registrar(Fin::Codigo(0), 10).is_none());
        assert!(matches!(d.estado(), Estado::Retirado { .. }));
        // Ni una confirmacion nueva basta.
        assert_eq!(
            d.imponer(conf()),
            Err(TransicionInvalida::DesdeEstado("retirado"))
        );
        // Solo un aprendizaje nuevo lo saca, y vuelve a permisivo, no a obligatorio.
        d.aprendido(Perfil::nuevo(Path::new("/x")));
        assert_eq!(d.estado(), &Estado::Permisivo);
    }

    #[test]
    fn fuera_de_obligatorio_no_se_cuenta_nada() {
        let mut d = Despliegue::nuevo(PoliticaReversion::default());
        d.aprendido(Perfil::nuevo(Path::new("/x")));
        for t in 0..20 {
            assert!(d.registrar(Fin::Codigo(1), t).is_none());
        }
        assert_eq!(d.estado(), &Estado::Permisivo);
    }
}
