//! El grafo de ataque: identidades de la FASE 58 y topologia de red, juntas.
//!
//! # Por que hay que unirlos
//!
//! Un atacante no se mueve por el grafo de identidad **o** por el de red: los
//! alterna. Roba credenciales en una maquina (identidad), las usa para llegar a
//! otra (red), y alli saca las credenciales cacheadas de alguien con mas
//! privilegio (identidad otra vez). Mirar cada grafo por separado deja
//! precisamente los caminos que el atacante usa: los que cambian de plano.
//!
//! # De donde salen las probabilidades, que es la parte delicada
//!
//! Cada arista lleva una probabilidad de que un atacante que controla el origen
//! consiga el destino. Esos numeros **no estan entrenados**, estan calibrados a
//! mano a partir de lo que cuesta cada paso, y estan aqui —con su razon— en vez
//! de en un modelo opaco, por una razon concreta: **este motor propone aislar
//! maquinas de produccion**. Una prediccion que no se puede explicar no se puede
//! discutir, y una que no se puede discutir no se puede poner delante de nadie.
//!
//! | Paso | p | Por que |
//! |---|---|---|
//! | Miembro de un grupo | 0,99 | Es automatico: si controlas la cuenta, tienes lo del grupo |
//! | Credenciales cacheadas | 0,95 | Con SYSTEM en la maquina, sacarlas de `lsass` es rutina |
//! | Impersonar un token | 0,90 | Requiere el token vivo en la maquina |
//! | Actuar como | 0,85 | Requiere el contexto del proceso |
//! | Autenticarse en otro host | 0,60 | Hace falta que el servicio acepte y la sesion valga |
//! | Salto de red a un servicio expuesto | 0,50 | Depende del servicio y de que haya con que entrar |
//! | Salto de red segmentado | 0,15 | Hay un control en medio que hay que saltarse |
//!
//! # El descuento que impide que el atacante dirija la prediccion
//!
//! Aqui esta el problema que no se puede ignorar: **el atacante fabrica aristas**.
//! Es el que se mueve lateralmente, el que se autentica, el que deja credenciales
//! cacheadas. Si el motor tomara cada arista observada al pie de la letra, un
//! adversario podria construirse un camino de ataque *a traves de la maquina que
//! quiere tirar*, y conseguir que la propia defensa la aisle. Eso convierte
//! AegisPredict en una primitiva de denegacion de servicio manejada por el
//! adversario — el equivalente en la FASE 69 del problema que resolvio la 68.
//!
//! La defensa es [`Evidencia`]: una arista vista **una sola vez, hace poco y por
//! un solo observador** vale menos que una que lleva meses siendo parte de como
//! funciona la organizacion. El descuento no la borra —la observacion es real y
//! esconderla seria peor— pero le quita el peso que haria que mueva una decision
//! automatica.

use std::collections::BTreeMap;

use aegis_itdr::grafo::{Nivel, Relacion};

use crate::error::ErrorPrediccion;

/// Probabilidad de cada relacion de identidad.
///
/// Publicas a proposito: un cliente tiene que poder ver —y discutir— con que
/// numeros se decide aislar una de sus maquinas.
pub mod probabilidad {
    /// Pertenencia a grupo: automatica.
    pub const MIEMBRO_DE: f64 = 0.99;
    /// Credenciales cacheadas en la maquina.
    pub const CONTROLA_CREDENCIALES: f64 = 0.95;
    /// Impersonacion de un token vivo.
    pub const IMPERSONA: f64 = 0.90;
    /// Actuar como otra identidad.
    pub const ACTUA_COMO: f64 = 0.85;
    /// Autenticarse en otro host.
    pub const AUTENTICA_EN: f64 = 0.60;
    /// Salto de red hacia un servicio expuesto.
    pub const RED_EXPUESTA: f64 = 0.50;
    /// Salto de red a traves de un control de segmentacion.
    pub const RED_SEGMENTADA: f64 = 0.15;
}

/// Cuanto se descuenta una arista con evidencia debil.
///
/// No la anula: la observacion es real. Le quita el peso suficiente para que no
/// mueva por si sola una decision automatica.
pub const DESCUENTO_EVIDENCIA_DEBIL: f64 = 0.35;

/// Observaciones minimas para que una arista cuente con todo su peso.
pub const OBSERVACIONES_PARA_PESO_PLENO: u32 = 3;

/// Tope de nodos del grafo.
///
/// El grafo lo alimenta la telemetria de la flota, que un colector comprometido
/// puede inflar. Sin tope, el motor de prediccion es la via para agotar la
/// memoria del plano de control.
pub const MAX_NODOS: usize = 100_000;

/// Tope de aristas.
pub const MAX_ARISTAS: usize = 1_000_000;

/// Qué es un nodo del grafo de ataque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ClaseActivo {
    /// Una identidad (usuario, servicio, grupo).
    Identidad,
    /// Un endpoint de la flota.
    Endpoint,
    /// Un servicio de infraestructura (controlador de dominio, base de datos).
    Servicio,
}

/// Un activo: el nodo del grafo de ataque.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Activo {
    /// Nombre unico y estable.
    pub nombre: String,
    /// Que clase de cosa es.
    pub clase: ClaseActivo,
    /// Nivel de privilegio que confiere controlarlo.
    pub nivel: Nivel,
    /// Valor para el negocio, de 0 a 100. Las **joyas de la corona** son las de
    /// valor alto, y son lo que la criticidad propaga hacia atras.
    pub valor: u8,
    /// Si **nunca** puede contenerse de forma preventiva.
    ///
    /// El plano de control, los controladores de dominio y lo que el cliente
    /// declare. Sin esto, una prediccion puede cortar la capacidad del defensor
    /// de responder, que es exactamente lo que el atacante quiere.
    pub protegido: bool,
}

impl Activo {
    /// Un activo corriente.
    #[must_use]
    pub fn nuevo(nombre: impl Into<String>, clase: ClaseActivo, nivel: Nivel, valor: u8) -> Activo {
        Activo {
            nombre: nombre.into(),
            clase,
            nivel,
            valor: valor.min(100),
            protegido: false,
        }
    }

    /// Marca el activo como intocable para la contencion preventiva.
    #[must_use]
    pub fn protegido(mut self) -> Activo {
        self.protegido = true;
        self
    }

    /// Si cuenta como joya de la corona.
    #[must_use]
    pub fn es_joya(&self) -> bool {
        self.valor >= 80 || self.nivel == Nivel::AdminDominio
    }
}

/// Cuanto se ha visto una arista, y desde cuando.
///
/// Es lo que separa «asi funciona la organizacion» de «esto aparecio hace diez
/// minutos», y por eso es lo que impide que el atacante dirija la prediccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Evidencia {
    /// Veces observada.
    pub observaciones: u32,
    /// Cuantos observadores distintos la vieron.
    pub observadores: u32,
    /// Antiguedad de la primera observacion, en segundos.
    pub antiguedad_seg: u64,
}

impl Default for Evidencia {
    fn default() -> Evidencia {
        Evidencia {
            observaciones: OBSERVACIONES_PARA_PESO_PLENO,
            observadores: 2,
            antiguedad_seg: 30 * 24 * 3600,
        }
    }
}

impl Evidencia {
    /// Evidencia de una sola observacion reciente: el caso sospechoso.
    #[must_use]
    pub fn recien_vista() -> Evidencia {
        Evidencia {
            observaciones: 1,
            observadores: 1,
            antiguedad_seg: 0,
        }
    }

    /// Si la evidencia es lo bastante solida para pesar entera.
    ///
    /// Hacen falta las tres cosas: verse varias veces, por mas de un observador,
    /// y llevar mas de un dia. Exigir solo una de las tres deja el hueco: un
    /// atacante puede repetir una accion mil veces en un minuto desde la misma
    /// maquina, y eso no es corroboro, es la misma observacion mil veces.
    #[must_use]
    pub fn solida(&self) -> bool {
        self.observaciones >= OBSERVACIONES_PARA_PESO_PLENO
            && self.observadores >= 2
            && self.antiguedad_seg >= 24 * 3600
    }
}

/// Una arista del grafo de ataque.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Paso {
    /// De donde.
    pub origen: String,
    /// A donde.
    pub destino: String,
    /// Como.
    pub via: Via,
    /// Probabilidad base, antes de descontar por evidencia.
    pub probabilidad: f64,
    /// Que respalda esta arista.
    pub evidencia: Evidencia,
}

/// Por que camino se pasa de un activo a otro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Via {
    /// Una relacion del grafo de identidad de la FASE 58.
    Identidad(RelacionSerializable),
    /// Un salto de red hacia un servicio expuesto.
    RedExpuesta,
    /// Un salto de red a traves de un control de segmentacion.
    RedSegmentada,
}

/// Copia serializable de [`Relacion`], que no lo es en origen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RelacionSerializable {
    /// Actuar como otra identidad.
    ActuaComo,
    /// Impersonar.
    Impersona,
    /// Pertenecer a un grupo.
    MiembroDe,
    /// Controlar credenciales cacheadas.
    ControlaCredencialesDe,
    /// Autenticarse en un host.
    AutenticaEn,
}

impl From<Relacion> for RelacionSerializable {
    fn from(r: Relacion) -> RelacionSerializable {
        match r {
            Relacion::ActuaComo => RelacionSerializable::ActuaComo,
            Relacion::Impersona => RelacionSerializable::Impersona,
            Relacion::MiembroDe => RelacionSerializable::MiembroDe,
            Relacion::ControlaCredencialesDe => RelacionSerializable::ControlaCredencialesDe,
            Relacion::AutenticaEn => RelacionSerializable::AutenticaEn,
        }
    }
}

impl Via {
    /// La probabilidad base de este tipo de paso.
    #[must_use]
    pub fn probabilidad_base(self) -> f64 {
        match self {
            Via::Identidad(r) => match r {
                RelacionSerializable::MiembroDe => probabilidad::MIEMBRO_DE,
                RelacionSerializable::ControlaCredencialesDe => probabilidad::CONTROLA_CREDENCIALES,
                RelacionSerializable::Impersona => probabilidad::IMPERSONA,
                RelacionSerializable::ActuaComo => probabilidad::ACTUA_COMO,
                RelacionSerializable::AutenticaEn => probabilidad::AUTENTICA_EN,
            },
            Via::RedExpuesta => probabilidad::RED_EXPUESTA,
            Via::RedSegmentada => probabilidad::RED_SEGMENTADA,
        }
    }

    /// Descripcion legible, para que el informe se pueda leer sin el codigo.
    #[must_use]
    pub fn describir(self) -> &'static str {
        match self {
            Via::Identidad(RelacionSerializable::MiembroDe) => "es miembro de",
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe) => {
                "tiene credenciales cacheadas de"
            }
            Via::Identidad(RelacionSerializable::Impersona) => "puede impersonar a",
            Via::Identidad(RelacionSerializable::ActuaComo) => "puede actuar como",
            Via::Identidad(RelacionSerializable::AutenticaEn) => "se autentica en",
            Via::RedExpuesta => "alcanza por red un servicio expuesto de",
            Via::RedSegmentada => "alcanza por red, a traves de segmentacion,",
        }
    }
}

impl Paso {
    /// Un paso con la probabilidad base de su via y evidencia solida.
    #[must_use]
    pub fn nuevo(origen: impl Into<String>, destino: impl Into<String>, via: Via) -> Paso {
        Paso {
            origen: origen.into(),
            destino: destino.into(),
            via,
            probabilidad: via.probabilidad_base(),
            evidencia: Evidencia::default(),
        }
    }

    /// El mismo paso con otra evidencia.
    #[must_use]
    pub fn con_evidencia(mut self, e: Evidencia) -> Paso {
        self.evidencia = e;
        self
    }

    /// La probabilidad **efectiva**, ya descontada por la fuerza de la evidencia.
    ///
    /// Es la que usan todos los algoritmos. La base sin descontar se conserva
    /// para el informe, porque un analista tiene que poder ver que el motor
    /// rebajo una arista y por que.
    #[must_use]
    pub fn probabilidad_efectiva(&self) -> f64 {
        if self.evidencia.solida() {
            self.probabilidad
        } else {
            self.probabilidad * DESCUENTO_EVIDENCIA_DEBIL
        }
    }
}

/// El grafo de ataque completo.
#[derive(Debug, Default, Clone)]
pub struct GrafoAtaque {
    activos: BTreeMap<String, Activo>,
    /// Aristas salientes por origen.
    salientes: BTreeMap<String, Vec<Paso>>,
    aristas: usize,
}

impl GrafoAtaque {
    /// Un grafo vacio.
    #[must_use]
    pub fn nuevo() -> GrafoAtaque {
        GrafoAtaque::default()
    }

    /// Activos.
    #[must_use]
    pub fn activos(&self) -> usize {
        self.activos.len()
    }

    /// Aristas.
    #[must_use]
    pub fn aristas(&self) -> usize {
        self.aristas
    }

    /// Consulta un activo.
    #[must_use]
    pub fn activo(&self, nombre: &str) -> Option<&Activo> {
        self.activos.get(nombre)
    }

    /// Nombres de los activos, en orden estable.
    ///
    /// El orden importa: el motor tiene que dar el mismo resultado en dos
    /// ejecuciones sobre la misma entrada, y un recorrido por una tabla hash lo
    /// rompe. De ahi el `BTreeMap` en vez de `HashMap`.
    pub fn nombres(&self) -> impl Iterator<Item = &String> {
        self.activos.keys()
    }

    /// Pasos que salen de un activo, en orden estable.
    #[must_use]
    pub fn salientes(&self, origen: &str) -> &[Paso] {
        self.salientes.get(origen).map_or(&[], Vec::as_slice)
    }

    /// Las joyas de la corona.
    pub fn joyas(&self) -> impl Iterator<Item = &Activo> {
        self.activos.values().filter(|a| a.es_joya())
    }

    /// Anade un activo.
    ///
    /// # Errores
    /// [`ErrorPrediccion::LimiteExcedido`] si se pasa de [`MAX_NODOS`].
    pub fn agregar(&mut self, a: Activo) -> Result<(), ErrorPrediccion> {
        if !self.activos.contains_key(&a.nombre) && self.activos.len() >= MAX_NODOS {
            return Err(ErrorPrediccion::LimiteExcedido {
                campo: "activos",
                valor: self.activos.len() + 1,
                tope: MAX_NODOS,
            });
        }
        self.activos.insert(a.nombre.clone(), a);
        Ok(())
    }

    /// Anade un paso entre dos activos ya presentes.
    ///
    /// # Errores
    /// [`ErrorPrediccion::ActivoDesconocido`] si falta alguno de los extremos,
    /// [`ErrorPrediccion::ProbabilidadInvalida`] si la probabilidad no esta en
    /// (0, 1], o [`ErrorPrediccion::LimiteExcedido`] si se pasa de
    /// [`MAX_ARISTAS`].
    pub fn conectar(&mut self, p: Paso) -> Result<(), ErrorPrediccion> {
        if !self.activos.contains_key(&p.origen) {
            return Err(ErrorPrediccion::ActivoDesconocido(p.origen));
        }
        if !self.activos.contains_key(&p.destino) {
            return Err(ErrorPrediccion::ActivoDesconocido(p.destino));
        }
        // NaN falla las tres comparaciones a la vez, asi que este predicado ya
        // lo rechaza; `is_finite` cierra ademas los infinitos.
        if !(p.probabilidad > 0.0 && p.probabilidad <= 1.0 && p.probabilidad.is_finite()) {
            return Err(ErrorPrediccion::ProbabilidadInvalida {
                arista: format!("{} -> {}", p.origen, p.destino),
                valor: p.probabilidad,
            });
        }
        if self.aristas >= MAX_ARISTAS {
            return Err(ErrorPrediccion::LimiteExcedido {
                campo: "aristas",
                valor: self.aristas + 1,
                tope: MAX_ARISTAS,
            });
        }
        let salientes = self.salientes.entry(p.origen.clone()).or_default();
        // Una arista repetida REFUERZA la evidencia en vez de duplicarse: dos
        // aristas identicas darian un grafo con caminos paralelos que la
        // percolacion contaria dos veces, inflando el radio.
        if let Some(existente) = salientes
            .iter_mut()
            .find(|e| e.destino == p.destino && e.via == p.via)
        {
            existente.evidencia.observaciones = existente.evidencia.observaciones.saturating_add(1);
            existente.evidencia.observadores = existente
                .evidencia
                .observadores
                .max(p.evidencia.observadores);
            existente.evidencia.antiguedad_seg = existente
                .evidencia
                .antiguedad_seg
                .max(p.evidencia.antiguedad_seg);
            return Ok(());
        }
        salientes.push(p);
        self.aristas += 1;
        Ok(())
    }

    /// Importa el grafo de identidad de la FASE 58.
    ///
    /// # Errores
    /// Los de [`GrafoAtaque::agregar`] y [`GrafoAtaque::conectar`].
    pub fn importar_identidades(
        &mut self,
        identidades: &[(String, Nivel, u8)],
        relaciones: &[(String, String, Relacion)],
    ) -> Result<(), ErrorPrediccion> {
        for (nombre, nivel, valor) in identidades {
            self.agregar(Activo::nuevo(
                nombre.clone(),
                ClaseActivo::Identidad,
                *nivel,
                *valor,
            ))?;
        }
        for (o, d, r) in relaciones {
            self.conectar(Paso::nuevo(
                o.clone(),
                d.clone(),
                Via::Identidad((*r).into()),
            ))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// EL ORDEN DE LAS PROBABILIDADES **ES** EL MODELO, y por eso se afirma en
    /// **tiempo de compilacion** y no en una prueba: si alguien ajusta un numero
    /// y rompe el orden, el crate no compila, en vez de fallar una prueba que
    /// alguien podria marcar como `ignore` un viernes por la tarde.
    ///
    /// Romperlo significaria que el motor cree que colarse por un firewall es
    /// mas facil que heredar los permisos de un grupo al que ya perteneces, y a
    /// partir de ahi todos los caminos que calcule estaran del reves.
    const _ORDEN_DE_DIFICULTAD: () = {
        assert!(probabilidad::MIEMBRO_DE > probabilidad::CONTROLA_CREDENCIALES);
        assert!(probabilidad::CONTROLA_CREDENCIALES > probabilidad::IMPERSONA);
        assert!(probabilidad::IMPERSONA > probabilidad::ACTUA_COMO);
        assert!(probabilidad::ACTUA_COMO > probabilidad::AUTENTICA_EN);
        assert!(probabilidad::AUTENTICA_EN > probabilidad::RED_EXPUESTA);
        assert!(probabilidad::RED_EXPUESTA > probabilidad::RED_SEGMENTADA);
    };

    /// Y que todas sean probabilidades de verdad, tambien en compilacion.
    const _SON_PROBABILIDADES: () = {
        assert!(probabilidad::MIEMBRO_DE > 0.0 && probabilidad::MIEMBRO_DE <= 1.0);
        assert!(probabilidad::CONTROLA_CREDENCIALES > 0.0);
        assert!(probabilidad::IMPERSONA > 0.0);
        assert!(probabilidad::ACTUA_COMO > 0.0);
        assert!(probabilidad::AUTENTICA_EN > 0.0);
        assert!(probabilidad::RED_EXPUESTA > 0.0);
        // El cero esta EXCLUIDO: -log 0 es infinito, y una arista imposible no
        // es un camino caro, es la ausencia de arista.
        assert!(probabilidad::RED_SEGMENTADA > 0.0);
    };

    /// LA DEFENSA CONTRA EL ATACANTE QUE DIRIGE LA PREDICCION: una arista recien
    /// aparecida, vista una sola vez por un solo observador, pesa mucho menos.
    #[test]
    fn una_arista_recien_vista_pesa_menos_que_una_consolidada() {
        let consolidado = Paso::nuevo("a", "b", Via::Identidad(RelacionSerializable::MiembroDe));
        let recien = Paso::nuevo("a", "b", Via::Identidad(RelacionSerializable::MiembroDe))
            .con_evidencia(Evidencia::recien_vista());

        assert_eq!(
            consolidado.probabilidad_efectiva(),
            probabilidad::MIEMBRO_DE
        );
        assert!(
            recien.probabilidad_efectiva() < consolidado.probabilidad_efectiva() / 2.0,
            "una arista que el atacante acaba de fabricar no puede pesar igual"
        );
        // Pero NO se borra: la observacion es real y esconderla seria peor.
        assert!(recien.probabilidad_efectiva() > 0.0);
    }

    /// Las tres condiciones de evidencia solida hacen falta a la vez. Repetir
    /// mil veces la misma accion desde la misma maquina en un minuto no es
    /// corroboro: es la misma observacion mil veces.
    #[test]
    fn la_evidencia_solida_exige_las_tres_condiciones() {
        let base = Evidencia {
            observaciones: 10,
            observadores: 3,
            antiguedad_seg: 30 * 24 * 3600,
        };
        assert!(base.solida());

        assert!(!Evidencia {
            observaciones: 1,
            ..base
        }
        .solida());
        assert!(!Evidencia {
            observadores: 1,
            ..base
        }
        .solida());
        assert!(!Evidencia {
            antiguedad_seg: 60,
            ..base
        }
        .solida());
    }

    #[test]
    fn una_arista_repetida_refuerza_la_evidencia_en_vez_de_duplicarse() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "a",
            ClaseActivo::Identidad,
            Nivel::Usuario,
            10,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "b",
            ClaseActivo::Identidad,
            Nivel::Usuario,
            10,
        ))
        .unwrap();

        let p = Paso::nuevo("a", "b", Via::RedExpuesta).con_evidencia(Evidencia::recien_vista());
        for _ in 0..5 {
            g.conectar(p.clone()).unwrap();
        }
        assert_eq!(g.aristas(), 1, "no se duplica");
        assert_eq!(g.salientes("a")[0].evidencia.observaciones, 5);
    }

    #[test]
    fn una_probabilidad_fuera_de_rango_se_rechaza() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "a",
            ClaseActivo::Identidad,
            Nivel::Usuario,
            1,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "b",
            ClaseActivo::Identidad,
            Nivel::Usuario,
            1,
        ))
        .unwrap();
        for mala in [0.0, -0.5, 1.5, f64::NAN, f64::INFINITY] {
            let mut p = Paso::nuevo("a", "b", Via::RedExpuesta);
            p.probabilidad = mala;
            assert!(
                matches!(
                    g.conectar(p),
                    Err(ErrorPrediccion::ProbabilidadInvalida { .. })
                ),
                "{mala} no es una probabilidad valida"
            );
        }
    }

    #[test]
    fn conectar_activos_que_no_existen_se_rechaza() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "a",
            ClaseActivo::Identidad,
            Nivel::Usuario,
            1,
        ))
        .unwrap();
        assert!(matches!(
            g.conectar(Paso::nuevo("a", "fantasma", Via::RedExpuesta)),
            Err(ErrorPrediccion::ActivoDesconocido(_))
        ));
        assert!(matches!(
            g.conectar(Paso::nuevo("fantasma", "a", Via::RedExpuesta)),
            Err(ErrorPrediccion::ActivoDesconocido(_))
        ));
    }

    #[test]
    fn el_recorrido_de_activos_es_estable_entre_ejecuciones() {
        // Un resultado que cambia entre dos ejecuciones sobre la misma entrada
        // no se puede poner delante de un cliente cuya maquina se va a aislar.
        let construir = || {
            let mut g = GrafoAtaque::nuevo();
            for n in ["zeta", "alfa", "mu", "beta"] {
                g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, Nivel::Usuario, 10))
                    .unwrap();
            }
            g.nombres().cloned().collect::<Vec<_>>()
        };
        assert_eq!(construir(), construir());
        assert_eq!(construir(), vec!["alfa", "beta", "mu", "zeta"]);
    }

    #[test]
    fn un_admin_de_dominio_es_joya_aunque_no_se_le_ponga_valor() {
        let a = Activo::nuevo("krbtgt", ClaseActivo::Identidad, Nivel::AdminDominio, 0);
        assert!(a.es_joya(), "el control del dominio siempre es la joya");
        let b = Activo::nuevo("pc-raso", ClaseActivo::Endpoint, Nivel::Usuario, 10);
        assert!(!b.es_joya());
    }

    #[test]
    fn el_grafo_de_identidad_de_la_fase_58_se_importa() {
        let mut g = GrafoAtaque::nuevo();
        g.importar_identidades(
            &[
                ("alice".to_string(), Nivel::Usuario, 10),
                ("svc-backup".to_string(), Nivel::Operador, 40),
                ("Domain Admins".to_string(), Nivel::AdminDominio, 100),
            ],
            &[
                (
                    "alice".to_string(),
                    "svc-backup".to_string(),
                    Relacion::ControlaCredencialesDe,
                ),
                (
                    "svc-backup".to_string(),
                    "Domain Admins".to_string(),
                    Relacion::MiembroDe,
                ),
            ],
        )
        .expect("importacion");
        assert_eq!(g.activos(), 3);
        assert_eq!(g.aristas(), 2);
        assert_eq!(g.joyas().count(), 1);
    }
}
