//! El modelo del caso: de alerta a cierre, con transiciones validadas.
//!
//! # Por que los estados son un enumerado y las transiciones una funcion
//!
//! Un caso con el estado en una cadena de texto acaba teniendo seis formas de
//! escribir «cerrado», y entonces la metrica de tiempo hasta cierre cuenta la
//! mitad de los casos. Peor: una transicion invalida —cerrar un caso que ya
//! estaba cerrado, reabrir uno que nunca se abrio— entra sin protesta y deja el
//! rastro de auditoria contando una historia que no ocurrio.
//!
//! Aqui la transicion es [`Estado::puede_pasar_a`], y lo que no se puede hacer
//! **se rechaza con un motivo legible**. Legible importa: el analista lo va a
//! leer en el panel a las tres de la mañana.
//!
//! # La regla que parece burocracia y no lo es
//!
//! **No se puede cerrar un caso con tareas abiertas sin justificarlo.**
//!
//! No es una regla de proceso: es la diferencia entre «se investigo y no era
//! nada» y «nadie llego a mirarlo». Las dos acaban con el caso cerrado, las dos
//! producen la misma metrica, y solo una es aceptable. Obligar a escribir el
//! motivo convierte la segunda en una decision con nombre en vez de en un
//! descuido invisible.

use std::collections::BTreeMap;
use std::fmt;

/// Estado de un caso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Estado {
    /// Recien abierto, sin nadie asignado.
    Nuevo,
    /// Alguien lo esta mirando.
    EnCurso,
    /// Esperando algo de fuera: al cliente, a un proveedor, a una ventana de
    /// mantenimiento.
    ///
    /// Existe como estado propio porque si no, el tiempo de espera se cuenta
    /// como tiempo de trabajo y la metrica de respuesta del equipo sale mal por
    /// algo que no depende del equipo.
    EnEspera,
    /// Contenido pero sin cerrar.
    ///
    /// El ataque esta parado y la investigacion sigue. Es el estado en el que
    /// mas tiempo pasa un caso serio, y confundirlo con «cerrado» hace que las
    /// metricas digan que se cierra mas rapido de lo que se cierra.
    Contenido,
    /// Cerrado con veredicto.
    Cerrado,
}

impl Estado {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Estado::Nuevo => "nuevo",
            Estado::EnCurso => "en-curso",
            Estado::EnEspera => "en-espera",
            Estado::Contenido => "contenido",
            Estado::Cerrado => "cerrado",
        }
    }

    /// Si el caso sigue vivo.
    #[must_use]
    pub fn abierto(self) -> bool {
        self != Estado::Cerrado
    }

    /// Si se puede pasar de un estado a otro.
    #[must_use]
    pub fn puede_pasar_a(self, otro: Estado) -> bool {
        use Estado::{Cerrado, Contenido, EnCurso, EnEspera, Nuevo};
        match (self, otro) {
            // Quedarse donde se esta no es una transicion.
            (a, b) if a == b => false,
            (Nuevo, EnCurso) => true,
            // De nuevo a cerrado SI se puede: un falso positivo evidente se
            // cierra sin pasar por «en curso», y obligar a un paso intermedio
            // solo produce ruido en el rastro.
            (Nuevo, Cerrado) => true,
            (EnCurso, EnEspera | Contenido | Cerrado) => true,
            (EnEspera, EnCurso | Contenido | Cerrado) => true,
            (Contenido, EnCurso | Cerrado) => true,
            // Reabrir: se puede, y por eso hay una accion de auditoria propia.
            // Un caso cerrado por error es frecuente; lo que no puede pasar es
            // que reabrirlo no deje rastro.
            (Cerrado, EnCurso) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Estado {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.nombre())
    }
}

/// Con que se cierra un caso.
///
/// **El tri-estado es obligatorio aqui**: `NoConcluyente` existe porque la
/// alternativa es que un caso que nadie pudo resolver se cierre como «falso
/// positivo», y entonces la metrica de falsos positivos por regla —que es la que
/// decide que reglas se apagan— cuenta como ruido lo que era una investigacion
/// que se quedo a medias. Apagar una regla por eso es exactamente el error que
/// deja un hueco de deteccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Veredicto {
    /// Era un ataque de verdad.
    Verdadero,
    /// No lo era: la regla se disparo con actividad legitima.
    FalsoPositivo,
    /// Era actividad esperada y autorizada.
    ///
    /// Distinto de falso positivo: la regla acerto, el hecho ocurrio, y estaba
    /// permitido. Confundirlos hace que se apague una regla que funciona.
    Autorizado,
    /// No se pudo determinar.
    NoConcluyente,
}

impl Veredicto {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Veredicto::Verdadero => "verdadero",
            Veredicto::FalsoPositivo => "falso-positivo",
            Veredicto::Autorizado => "autorizado",
            Veredicto::NoConcluyente => "no-concluyente",
        }
    }

    /// Si cuenta como ruido de la regla que lo disparo.
    ///
    /// Solo el falso positivo. Ni lo autorizado —la regla acerto— ni lo no
    /// concluyente —no se sabe— pueden contar, o se acaba apagando una regla
    /// buena.
    #[must_use]
    pub fn es_ruido(self) -> bool {
        self == Veredicto::FalsoPositivo
    }
}

/// Gravedad del caso, con la misma escala que el resto del producto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Informativo.
    Info,
    /// Baja.
    Baja,
    /// Media.
    Media,
    /// Alta.
    Alta,
    /// Critica.
    Critica,
}

impl Severidad {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Severidad::Info => "info",
            Severidad::Baja => "baja",
            Severidad::Media => "media",
            Severidad::Alta => "alta",
            Severidad::Critica => "critica",
        }
    }
}

/// Un observable: algo concreto del mundo que aparece en el caso.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Observable {
    /// Resumen de un fichero.
    Hash(String),
    /// Direccion IP.
    Ip(String),
    /// Nombre de dominio.
    Dominio(String),
    /// URL.
    Url(String),
    /// Ruta de un fichero.
    Ruta(String),
    /// Cuenta de usuario.
    Usuario(String),
    /// Maquina.
    Anfitrion(String),
    /// Linea de ordenes.
    Orden(String),
}

impl Observable {
    /// Tipo estable.
    #[must_use]
    pub fn tipo(&self) -> &'static str {
        match self {
            Observable::Hash(_) => "hash",
            Observable::Ip(_) => "ip",
            Observable::Dominio(_) => "dominio",
            Observable::Url(_) => "url",
            Observable::Ruta(_) => "ruta",
            Observable::Usuario(_) => "usuario",
            Observable::Anfitrion(_) => "anfitrion",
            Observable::Orden(_) => "orden",
        }
    }

    /// Valor.
    #[must_use]
    pub fn valor(&self) -> &str {
        match self {
            Observable::Hash(v)
            | Observable::Ip(v)
            | Observable::Dominio(v)
            | Observable::Url(v)
            | Observable::Ruta(v)
            | Observable::Usuario(v)
            | Observable::Anfitrion(v)
            | Observable::Orden(v) => v,
        }
    }
}

/// Estado de una tarea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoTarea {
    /// Pendiente.
    Pendiente,
    /// Hecha.
    Hecha,
    /// Descartada con motivo.
    Descartada,
}

/// Una tarea del caso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tarea {
    /// Identificador dentro del caso.
    pub id: u32,
    /// Que hay que hacer.
    pub titulo: String,
    /// Quien la tiene.
    pub asignada_a: Option<String>,
    /// Como esta.
    pub estado: EstadoTarea,
    /// Por que se descarto, si se descarto.
    pub motivo: Option<String>,
}

impl Tarea {
    /// Si sigue pendiente.
    #[must_use]
    pub fn abierta(&self) -> bool {
        self.estado == EstadoTarea::Pendiente
    }
}

/// Una alerta que puede abrir o alimentar un caso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alerta {
    /// Identificador.
    pub id: String,
    /// Inquilino.
    pub inquilino: String,
    /// Maquina afectada.
    pub anfitrion: String,
    /// Sujeto: el proceso, la cuenta o el fichero sobre el que va.
    ///
    /// Es la clave de fusion mas importante: mil alertas sobre el mismo sujeto
    /// son una campana, no mil incidentes.
    pub sujeto: String,
    /// Tecnica de MITRE ATT&CK, si se sabe.
    pub tecnica: Option<String>,
    /// Regla que la disparo.
    ///
    /// Hace falta para la metrica de falsos positivos POR REGLA, que es la que
    /// permite apagar las que solo hacen ruido.
    pub regla: String,
    /// Gravedad.
    pub severidad: Severidad,
    /// Cuando ocurrio, en nanosegundos Unix.
    pub ocurrio_ns: u64,
    /// Observables que trae.
    pub observables: Vec<Observable>,
    /// Texto legible.
    pub resumen: String,
}

/// Por que no se pudo hacer algo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rechazo {
    /// Motivo legible, para el panel.
    pub motivo: String,
}

impl fmt::Display for Rechazo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.motivo)
    }
}

/// Un caso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caso {
    /// Identificador.
    pub id: String,
    /// Inquilino.
    pub inquilino: String,
    /// Titulo legible.
    pub titulo: String,
    /// Estado.
    pub estado: Estado,
    /// Gravedad, que es la mayor de sus alertas.
    pub severidad: Severidad,
    /// Quien lo lleva.
    pub asignado_a: Option<String>,
    /// Alertas fusionadas, en orden de llegada.
    pub alertas: Vec<Alerta>,
    /// Observables acumulados, sin repetir.
    pub observables: Vec<Observable>,
    /// Tareas.
    pub tareas: Vec<Tarea>,
    /// Tecnicas de ATT&CK vistas.
    pub tecnicas: Vec<String>,
    /// Cuando se abrio.
    pub abierto_ns: u64,
    /// Cuando alguien lo miro por primera vez.
    pub primer_vistazo_ns: Option<u64>,
    /// Cuando se contuvo.
    pub contenido_ns: Option<u64>,
    /// Cuando se cerro.
    pub cerrado_ns: Option<u64>,
    /// Con que se cerro.
    pub veredicto: Option<Veredicto>,
    /// Por que se cerro con tareas abiertas, si fue el caso.
    pub justificacion_cierre: Option<String>,
}

impl Caso {
    /// Abre un caso a partir de una alerta.
    #[must_use]
    pub fn abrir(id: impl Into<String>, alerta: Alerta) -> Caso {
        let mut c = Caso {
            id: id.into(),
            inquilino: alerta.inquilino.clone(),
            titulo: alerta.resumen.clone(),
            estado: Estado::Nuevo,
            severidad: alerta.severidad,
            asignado_a: None,
            alertas: Vec::new(),
            observables: Vec::new(),
            tareas: Vec::new(),
            tecnicas: Vec::new(),
            abierto_ns: alerta.ocurrio_ns,
            primer_vistazo_ns: None,
            contenido_ns: None,
            cerrado_ns: None,
            veredicto: None,
            justificacion_cierre: None,
        };
        c.absorber(alerta);
        c
    }

    /// Mete una alerta en el caso.
    ///
    /// La gravedad del caso es **la mayor** de sus alertas y nunca baja: un caso
    /// que empieza con un hallazgo critico y sigue con cien informativos no se
    /// vuelve informativo, aunque el promedio lo diga.
    pub fn absorber(&mut self, alerta: Alerta) {
        self.severidad = self.severidad.max(alerta.severidad);
        if let Some(t) = &alerta.tecnica {
            if !self.tecnicas.contains(t) {
                self.tecnicas.push(t.clone());
            }
        }
        for o in &alerta.observables {
            if !self.observables.contains(o) {
                self.observables.push(o.clone());
            }
        }
        self.abierto_ns = self.abierto_ns.min(alerta.ocurrio_ns);
        self.alertas.push(alerta);
    }

    /// Tareas que siguen abiertas.
    #[must_use]
    pub fn tareas_abiertas(&self) -> usize {
        self.tareas.iter().filter(|t| t.abierta()).count()
    }

    /// Anade una tarea.
    pub fn anadir_tarea(&mut self, titulo: impl Into<String>) -> u32 {
        let id = self.tareas.len() as u32 + 1;
        self.tareas.push(Tarea {
            id,
            titulo: titulo.into(),
            asignada_a: None,
            estado: EstadoTarea::Pendiente,
            motivo: None,
        });
        id
    }

    /// Cierra una tarea.
    pub fn cerrar_tarea(&mut self, id: u32, motivo: Option<String>) -> Result<(), Rechazo> {
        let Some(t) = self.tareas.iter_mut().find(|t| t.id == id) else {
            return Err(Rechazo {
                motivo: format!("la tarea {id} no existe en este caso"),
            });
        };
        if !t.abierta() {
            return Err(Rechazo {
                motivo: format!("la tarea {id} ya estaba cerrada"),
            });
        }
        t.estado = if motivo.is_some() {
            EstadoTarea::Descartada
        } else {
            EstadoTarea::Hecha
        };
        t.motivo = motivo;
        Ok(())
    }

    /// Cambia de estado, validando la transicion.
    pub fn pasar_a(&mut self, nuevo: Estado, cuando_ns: u64) -> Result<(), Rechazo> {
        if !self.estado.puede_pasar_a(nuevo) {
            return Err(Rechazo {
                motivo: format!(
                    "un caso {} no puede pasar a {}",
                    self.estado.nombre(),
                    nuevo.nombre()
                ),
            });
        }
        if nuevo == Estado::Cerrado {
            return Err(Rechazo {
                motivo: "para cerrar un caso hay que usar `cerrar`, que exige veredicto".into(),
            });
        }
        if nuevo == Estado::EnCurso && self.primer_vistazo_ns.is_none() {
            self.primer_vistazo_ns = Some(cuando_ns);
        }
        if nuevo == Estado::Contenido && self.contenido_ns.is_none() {
            self.contenido_ns = Some(cuando_ns);
        }
        if self.estado == Estado::Cerrado {
            // Reabrir limpia el cierre: dejarlo puesto haria que la metrica de
            // tiempo hasta cierre contara un caso que volvio a abrirse.
            self.cerrado_ns = None;
            self.veredicto = None;
            self.justificacion_cierre = None;
        }
        self.estado = nuevo;
        Ok(())
    }

    /// Cierra el caso con un veredicto.
    ///
    /// # La regla que parece burocracia
    ///
    /// Con tareas abiertas hace falta una justificacion. No es proceso: es la
    /// diferencia entre «se investigo y no era nada» y «nadie llego a mirarlo».
    /// Las dos acaban con el caso cerrado y producen la misma metrica, y solo una
    /// es aceptable.
    pub fn cerrar(
        &mut self,
        veredicto: Veredicto,
        justificacion: Option<String>,
        cuando_ns: u64,
    ) -> Result<(), Rechazo> {
        if self.estado == Estado::Cerrado {
            return Err(Rechazo {
                motivo: "el caso ya estaba cerrado".into(),
            });
        }
        let abiertas = self.tareas_abiertas();
        if abiertas > 0 {
            let Some(j) = justificacion.as_ref().filter(|j| !j.trim().is_empty()) else {
                return Err(Rechazo {
                    motivo: format!(
                        "quedan {abiertas} tarea(s) abierta(s): para cerrar sin hacerlas hay que \
                         escribir por que, porque «se investigo y no era nada» y «nadie llego a \
                         mirarlo» acaban igual en el panel y no son lo mismo"
                    ),
                });
            };
            self.justificacion_cierre = Some(j.clone());
        }
        self.veredicto = Some(veredicto);
        self.cerrado_ns = Some(cuando_ns);
        self.estado = Estado::Cerrado;
        Ok(())
    }

    /// Cuentas por regla de las alertas del caso.
    ///
    /// Es lo que alimenta la metrica de ruido por regla.
    #[must_use]
    pub fn por_regla(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for a in &self.alertas {
            *m.entry(a.regla.clone()).or_insert(0) += 1;
        }
        m
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    pub(crate) fn alerta(id: &str, sujeto: &str, ns: u64) -> Alerta {
        Alerta {
            id: id.into(),
            inquilino: "cliente-1".into(),
            anfitrion: "maquina-17".into(),
            sujeto: sujeto.into(),
            tecnica: Some("T1059.001".into()),
            regla: "powershell-codificado".into(),
            severidad: Severidad::Alta,
            ocurrio_ns: ns,
            observables: vec![
                Observable::Anfitrion("maquina-17".into()),
                Observable::Usuario("operador".into()),
            ],
            resumen: "PowerShell con orden codificada".into(),
        }
    }

    #[test]
    fn las_transiciones_validas_son_las_que_son() {
        use Estado::{Cerrado, Contenido, EnCurso, EnEspera, Nuevo};
        assert!(Nuevo.puede_pasar_a(EnCurso));
        assert!(Nuevo.puede_pasar_a(Cerrado), "un falso positivo evidente");
        assert!(EnCurso.puede_pasar_a(Contenido));
        assert!(Contenido.puede_pasar_a(Cerrado));
        assert!(Cerrado.puede_pasar_a(EnCurso), "reabrir se puede");
        assert!(!Nuevo.puede_pasar_a(Contenido), "sin pasar por en-curso no");
        assert!(!Nuevo.puede_pasar_a(Nuevo), "quedarse no es transicion");
        assert!(!Cerrado.puede_pasar_a(Contenido));
        assert!(!EnEspera.puede_pasar_a(Nuevo), "no se vuelve al principio");
    }

    #[test]
    fn una_transicion_invalida_se_rechaza_con_un_motivo_legible() {
        // El analista lo va a leer en el panel a las tres de la manana.
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        let e = c.pasar_a(Estado::Contenido, AHORA).unwrap_err();
        assert!(e.motivo.contains("nuevo"), "{e}");
        assert!(e.motivo.contains("contenido"), "{e}");
        assert_eq!(c.estado, Estado::Nuevo, "y no cambio nada");
    }

    #[test]
    fn no_se_puede_cerrar_un_caso_con_tareas_abiertas_sin_justificarlo() {
        // LA REGLA QUE PARECE BUROCRACIA. «Se investigo y no era nada» y «nadie
        // llego a mirarlo» acaban igual en el panel y no son lo mismo.
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        c.anadir_tarea("aislar la maquina");
        c.anadir_tarea("mirar el linaje del proceso");
        c.pasar_a(Estado::EnCurso, AHORA + SEG).unwrap();

        let e = c
            .cerrar(Veredicto::FalsoPositivo, None, AHORA + 60 * SEG)
            .unwrap_err();
        assert!(e.motivo.contains("2 tarea"), "{e}");
        assert_eq!(c.estado, Estado::EnCurso);

        // Con justificacion si, y queda escrita.
        c.cerrar(
            Veredicto::FalsoPositivo,
            Some("la campana se cerro en otro caso".into()),
            AHORA + 60 * SEG,
        )
        .unwrap();
        assert_eq!(c.estado, Estado::Cerrado);
        assert!(c.justificacion_cierre.is_some());
    }

    #[test]
    fn una_justificacion_en_blanco_no_es_una_justificacion() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        c.anadir_tarea("mirar");
        c.pasar_a(Estado::EnCurso, AHORA).unwrap();
        assert!(c
            .cerrar(Veredicto::FalsoPositivo, Some("   ".into()), AHORA)
            .is_err());
    }

    #[test]
    fn sin_tareas_abiertas_se_cierra_sin_justificar() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        let t = c.anadir_tarea("mirar");
        c.pasar_a(Estado::EnCurso, AHORA).unwrap();
        c.cerrar_tarea(t, None).unwrap();
        assert!(c.cerrar(Veredicto::Verdadero, None, AHORA + SEG).is_ok());
    }

    #[test]
    fn cerrar_solo_se_puede_con_veredicto() {
        // Pasar a «cerrado» por la puerta de las transiciones dejaria un caso
        // cerrado sin decir con que, y esa es justo la metrica que importa.
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        let e = c.pasar_a(Estado::Cerrado, AHORA).unwrap_err();
        assert!(e.motivo.contains("veredicto"), "{e}");
    }

    #[test]
    fn reabrir_limpia_el_cierre() {
        // Dejarlo puesto haria que la metrica de tiempo hasta cierre contara un
        // caso que volvio a abrirse.
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        c.cerrar(Veredicto::FalsoPositivo, None, AHORA + SEG)
            .unwrap();
        assert!(c.cerrado_ns.is_some());
        c.pasar_a(Estado::EnCurso, AHORA + 2 * SEG).unwrap();
        assert!(c.cerrado_ns.is_none());
        assert!(c.veredicto.is_none());
    }

    #[test]
    fn la_gravedad_del_caso_nunca_baja() {
        // Un caso que empieza con un hallazgo critico y sigue con cien
        // informativos no se vuelve informativo, aunque el promedio lo diga.
        let mut a = alerta("A-1", "pid:4211", AHORA);
        a.severidad = Severidad::Critica;
        let mut c = Caso::abrir("C-1", a);
        for i in 0..100 {
            let mut b = alerta(&format!("A-{i}"), "pid:4211", AHORA + i * SEG);
            b.severidad = Severidad::Info;
            c.absorber(b);
        }
        assert_eq!(c.severidad, Severidad::Critica);
    }

    #[test]
    fn los_observables_no_se_repiten() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        for i in 0..50 {
            c.absorber(alerta(&format!("A-{i}"), "pid:4211", AHORA + i * SEG));
        }
        assert_eq!(c.observables.len(), 2, "{:?}", c.observables);
        assert_eq!(c.tecnicas.len(), 1);
    }

    #[test]
    fn el_caso_empieza_cuando_empezo_lo_mas_antiguo() {
        // Si una alerta mas vieja se fusiona despues, el caso empezo antes. Con
        // la hora de creacion del caso, la metrica de tiempo hasta deteccion
        // saldria corta justo en los ataques largos, que son los graves.
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        c.absorber(alerta("A-0", "pid:4211", AHORA - 3600 * SEG));
        assert_eq!(c.abierto_ns, AHORA - 3600 * SEG);
    }

    #[test]
    fn lo_autorizado_no_cuenta_como_ruido_de_la_regla() {
        // La regla ACERTO: el hecho ocurrio y estaba permitido. Contarlo como
        // falso positivo hace que se apague una regla que funciona.
        assert!(Veredicto::FalsoPositivo.es_ruido());
        assert!(!Veredicto::Autorizado.es_ruido());
        assert!(!Veredicto::NoConcluyente.es_ruido());
        assert!(!Veredicto::Verdadero.es_ruido());
    }

    #[test]
    fn una_tarea_que_no_existe_se_dice_en_vez_de_ignorarse() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        assert!(c.cerrar_tarea(99, None).is_err());
        let t = c.anadir_tarea("x");
        c.cerrar_tarea(t, None).unwrap();
        assert!(c.cerrar_tarea(t, None).is_err(), "ya estaba cerrada");
    }

    #[test]
    fn las_alertas_se_cuentan_por_regla() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        let mut otra = alerta("A-2", "pid:4211", AHORA + SEG);
        otra.regla = "otra-regla".into();
        c.absorber(otra);
        let m = c.por_regla();
        assert_eq!(m["powershell-codificado"], 1);
        assert_eq!(m["otra-regla"], 1);
    }

    #[test]
    fn un_caso_cerrado_no_se_cierra_dos_veces() {
        let mut c = Caso::abrir("C-1", alerta("A-1", "pid:4211", AHORA));
        c.cerrar(Veredicto::Verdadero, None, AHORA).unwrap();
        assert!(c.cerrar(Veredicto::Verdadero, None, AHORA).is_err());
    }
}
