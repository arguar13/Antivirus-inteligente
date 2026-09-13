//! Actualizacion progresiva y politica de compatibilidad del contrato.
//!
//! # El problema, dicho sin adornos
//!
//! Una flota de cien mil agentes **no se actualiza de golpe**. Tarda dias, a
//! veces semanas, y durante todo ese tiempo hay agentes de la version vieja y de
//! la nueva hablando con un plano de control que tambien se esta actualizando
//! nodo a nodo. En cualquier instante de la ventana hay cuatro combinaciones
//! vivas, y las cuatro tienen que funcionar.
//!
//! # La trampa de protobuf, que es la que de verdad muerde
//!
//! Protobuf presume de compatibilidad hacia delante: un lector viejo **ignora en
//! silencio** los campos que no conoce. Para un campo de telemetria eso es
//! exactamente lo que se quiere.
//!
//! Para un campo con **significado de seguridad, es un agujero**. Supongamos que
//! la version nueva del agente anade un campo «he puesto esta maquina en
//! cuarentena». Un nodo del plano de control de la version anterior recibe el
//! mensaje, ignora el campo, y **cree que no ha pasado nada**. La maquina esta
//! contenida y el panel dice que no. Nadie ve un error: el mensaje se acepto, se
//! guardo y se contesto que si.
//!
//! De ahi la regla que gobierna este modulo:
//!
//! > **Un cambio que NO se puede ignorar no va en un campo nuevo: va en un metodo
//! > nuevo.** Un metodo que el servidor viejo no conoce falla ruidosamente —«no
//! > implementado»— y el agente se entera. Un campo que no conoce, no.
//!
//! # Las reglas del contrato, que son las de siempre y hay que cumplirlas
//!
//! 1. Un numero de campo **nunca** se reutiliza. Reutilizarlo hace que un lector
//!    viejo interprete los bytes nuevos como el campo antiguo, con el tipo
//!    antiguo, sin error.
//! 2. Un campo **nunca** se borra: se marca obsoleto y se reserva su numero.
//! 3. Un campo nuevo es **siempre** opcional, y su ausencia tiene un significado
//!    escrito.
//! 4. Un enumerado **nunca** se renumera, y siempre tiene un valor cero que
//!    significa «desconocido»; sin el, un valor nuevo llega a un lector viejo
//!    como el primero de la lista, que suele ser el benigno.
//! 5. Cambiar el **significado** de un campo existente esta prohibido. Es lo
//!    mismo que reutilizar el numero, pero sin dejar rastro en el `.proto`.

use std::fmt;

/// Version del contrato entre agente y plano de control.
///
/// Dos numeros, y solo el mayor rompe: el menor anade cosas que el otro lado
/// puede ignorar sin consecuencias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Cambios que rompen.
    pub mayor: u16,
    /// Anadidos compatibles.
    pub menor: u16,
}

impl Version {
    /// Crea una version.
    #[must_use]
    pub fn nueva(mayor: u16, menor: u16) -> Version {
        Version { mayor, menor }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.mayor, self.menor)
    }
}

/// Version actual del contrato.
pub const ACTUAL: Version = Version { mayor: 1, menor: 3 };

/// Version mayor mas antigua que este plano de control sigue atendiendo.
///
/// # Por que hay un minimo y por que es este
///
/// Sin minimo, el codigo del servidor acumula caminos para versiones que ya no
/// existe nadie que hable, y cada uno es una rama sin probar que algun dia se
/// ejecuta. Con un minimo demasiado alto, una actualizacion deja fuera a los
/// agentes que no llegaron a tiempo —que son justo los de las maquinas que menos
/// se tocan, y por tanto las mas expuestas—.
///
/// **Una version mayor de margen.** Es suficiente para una campana de
/// actualizacion completa en una flota grande, y acota el numero de caminos vivos
/// a dos.
pub const MINIMA_SOPORTADA: u16 = 1;

/// Lo que decide el plano de control sobre un agente que se presenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibilidad {
    /// Hablan la misma version.
    Igual,
    /// El agente es mas viejo pero se le atiende.
    ///
    /// Lleva que funciones no va a poder usar: decirlo es lo que convierte «va
    /// raro» en «le falta esto».
    AgenteAntiguo {
        /// Version del agente.
        version: Version,
        /// Lo que no tendra hasta que se actualice.
        sin: Vec<&'static str>,
    },
    /// El agente es mas nuevo que este nodo.
    ///
    /// Pasa **durante toda actualizacion progresiva**: los agentes se actualizan
    /// contra los nodos ya nuevos y despues aterrizan en uno viejo. Se atiende
    /// con el contrato del nodo, y el agente lo sabe.
    AgenteNuevo {
        /// Version del agente.
        version: Version,
    },
    /// No se pueden entender.
    ///
    /// **Se dice con nombre y con que hacer**, en vez de cortar la conexion: un
    /// agente rechazado en silencio reintenta para siempre, y el operador ve una
    /// maquina «sin conectar» sin ninguna pista.
    Incompatible {
        /// Version del agente.
        version: Version,
        /// Por que.
        motivo: String,
    },
}

/// Decide si un agente y un nodo se entienden.
#[must_use]
pub fn compatibilidad(agente: Version, nodo: Version) -> Compatibilidad {
    if agente.mayor < MINIMA_SOPORTADA {
        return Compatibilidad::Incompatible {
            version: agente,
            motivo: format!(
                "el contrato {agente} es anterior al minimo soportado ({MINIMA_SOPORTADA}.0); \
                 actualiza el agente"
            ),
        };
    }
    if agente.mayor > nodo.mayor {
        // El agente habla un contrato que este nodo no conoce. Durante una
        // actualizacion progresiva es lo normal; fuera de ella, significa que
        // alguien actualizo la flota antes que el plano de control.
        return Compatibilidad::AgenteNuevo { version: agente };
    }
    if agente.mayor < nodo.mayor {
        return Compatibilidad::Incompatible {
            version: agente,
            motivo: format!(
                "el contrato {agente} no es compatible con {nodo}; actualiza el agente"
            ),
        };
    }
    match agente.menor.cmp(&nodo.menor) {
        std::cmp::Ordering::Equal => Compatibilidad::Igual,
        std::cmp::Ordering::Less => Compatibilidad::AgenteAntiguo {
            version: agente,
            sin: funciones_desde(agente.menor, nodo.menor),
        },
        std::cmp::Ordering::Greater => Compatibilidad::AgenteNuevo { version: agente },
    }
}

/// Que aporto cada version menor, para poder decirle a un agente antiguo que le
/// falta.
///
/// Es una tabla y no un comentario porque se consulta en caliente: el panel
/// enseña «esta maquina no recibe reglas del corpus mundial porque su agente es
/// 1.1», que es accionable, en vez de «version antigua», que no lo es.
const APORTES: &[(u16, &str)] = &[
    (1, "telemetria basica y latido"),
    (2, "reglas del corpus mundial y cuarentena de enjambre"),
    (
        3,
        "ingesta de registros de terceros y contrapresion con senal",
    ),
];

fn funciones_desde(del_agente: u16, del_nodo: u16) -> Vec<&'static str> {
    APORTES
        .iter()
        .filter(|(v, _)| *v > del_agente && *v <= del_nodo)
        .map(|(_, f)| *f)
        .collect()
}

/// Clase de cambio en el contrato, con lo que exige cada una.
///
/// Existe como enumerado para que la decision se tome **al escribir el cambio** y
/// no al depurar el incidente: quien anade un campo tiene que elegir una variante,
/// y la variante dice si vale con un campo o hace falta un metodo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cambio {
    /// Un campo nuevo que el otro lado puede ignorar sin consecuencias.
    ///
    /// Telemetria, metricas, contexto. Sube la version menor.
    CampoIgnorable,
    /// Un campo nuevo cuyo desconocimiento cambia una decision.
    ///
    /// **No se puede hacer con un campo.** Ver el encabezado del modulo: un nodo
    /// viejo lo ignoraria y creeria que no paso nada.
    CampoConSignificado,
    /// Un metodo nuevo.
    ///
    /// Es la forma correcta de anadir algo que no se puede ignorar: el nodo viejo
    /// responde «no implementado» y el agente se entera.
    MetodoNuevo,
    /// Cambiar el significado o el tipo de un campo existente.
    ///
    /// Prohibido. Es reutilizar el numero sin dejar rastro en el `.proto`.
    CambioDeSignificado,
    /// Quitar un campo.
    ///
    /// Prohibido: se marca obsoleto y se reserva su numero.
    BorrarCampo,
}

/// Que hay que hacer con un cambio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// Vale, y sube la version menor.
    SubeMenor,
    /// Vale, y sube la version mayor.
    SubeMayor,
    /// No se puede hacer asi. Lleva la alternativa.
    Prohibido {
        /// Por que, y que hacer en su lugar.
        motivo: &'static str,
    },
}

/// Aplica la politica a un cambio propuesto.
#[must_use]
pub fn evaluar(cambio: Cambio) -> Veredicto {
    match cambio {
        Cambio::CampoIgnorable | Cambio::MetodoNuevo => Veredicto::SubeMenor,
        Cambio::CampoConSignificado => Veredicto::Prohibido {
            motivo: "un nodo de la version anterior ignoraria el campo en SILENCIO y creeria que \
                     no ha pasado nada; usa un metodo nuevo, que el nodo viejo rechaza con «no \
                     implementado» y el agente se entera",
        },
        Cambio::CambioDeSignificado => Veredicto::Prohibido {
            motivo:
                "cambiar lo que significa un campo es reutilizar su numero sin dejar rastro en \
                     el .proto; anade un campo nuevo y marca el viejo obsoleto",
        },
        Cambio::BorrarCampo => Veredicto::Prohibido {
            motivo: "borrar un campo libera su numero para que otro lo reutilice, y entonces un \
                     lector viejo interpreta los bytes nuevos como el campo antiguo sin dar \
                     error; marcalo obsoleto y reserva el numero",
        },
    }
}

/// Estado de un nodo durante una actualizacion progresiva.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fase {
    /// Atendiendo con la version anterior.
    Anterior,
    /// Drenando: no acepta conexiones nuevas, atiende las que tiene.
    ///
    /// **Es la fase que casi siempre falta.** Sin drenaje, actualizar un nodo
    /// corta de golpe sus veinte mil conexiones y provoca la manada contra los
    /// demas; y como los demas tambien se van a actualizar, la manada se repite
    /// una vez por nodo.
    Drenando,
    /// Parado para actualizarse.
    Parado,
    /// Atendiendo con la version nueva.
    Nueva,
}

/// Plan de una actualizacion progresiva.
#[derive(Debug, Clone)]
pub struct Progresiva {
    nodos: Vec<(String, Fase)>,
    /// Cuantos pueden estar fuera a la vez.
    tolerancia: usize,
}

impl Progresiva {
    /// Prepara una actualizacion.
    ///
    /// `tolerancia` es cuantos nodos pueden estar fuera a la vez. Uno es lo
    /// prudente; mas acelera el despliegue a costa de dejar menos capacidad para
    /// la flota que reconecta.
    #[must_use]
    pub fn nueva(nodos: &[String], tolerancia: usize) -> Progresiva {
        Progresiva {
            nodos: nodos.iter().map(|n| (n.clone(), Fase::Anterior)).collect(),
            tolerancia: tolerancia.max(1),
        }
    }

    /// Fase de un nodo.
    #[must_use]
    pub fn fase(&self, nodo: &str) -> Option<Fase> {
        self.nodos.iter().find(|(n, _)| n == nodo).map(|(_, f)| *f)
    }

    /// Nodos que pueden atender conexiones nuevas.
    #[must_use]
    pub fn disponibles(&self) -> Vec<&str> {
        self.nodos
            .iter()
            .filter(|(_, f)| matches!(f, Fase::Anterior | Fase::Nueva))
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Si la actualizacion termino.
    #[must_use]
    pub fn terminada(&self) -> bool {
        self.nodos.iter().all(|(_, f)| *f == Fase::Nueva)
    }

    /// Avanza un paso. Devuelve el nodo que cambio de fase, si alguno.
    ///
    /// **Nunca deja a la flota sin canal**: no saca a un nodo si eso dejaria
    /// menos de los necesarios. Es la unica regla que importa aqui, y por eso
    /// esta en el codigo y no en el manual de operaciones.
    pub fn avanzar(&mut self) -> Option<(String, Fase)> {
        let fuera = self
            .nodos
            .iter()
            .filter(|(_, f)| matches!(f, Fase::Drenando | Fase::Parado))
            .count();

        // Se mantiene la tolerancia OCUPADA: mientras quepa otro nodo fuera y
        // queden nodos por actualizar, se saca uno. Terminar siempre lo empezado
        // antes de empezar otro convertiria cualquier tolerancia en uno, y el
        // despliegue de una flota grande tardaria tantas ventanas como nodos.
        if fuera < self.tolerancia {
            for (nombre, fase) in &mut self.nodos {
                if *fase == Fase::Anterior {
                    *fase = Fase::Drenando;
                    return Some((nombre.clone(), *fase));
                }
            }
        }

        // Y si no cabe otro —o ya no quedan—, se avanza lo que esta a medias,
        // empezando por lo mas adelantado: es lo que libera capacidad antes.
        for (nombre, fase) in &mut self.nodos {
            if *fase == Fase::Parado {
                *fase = Fase::Nueva;
                return Some((nombre.clone(), *fase));
            }
        }
        for (nombre, fase) in &mut self.nodos {
            if *fase == Fase::Drenando {
                *fase = Fase::Parado;
                return Some((nombre.clone(), *fase));
            }
        }
        None
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // --- La politica del contrato -------------------------------------------

    #[test]
    fn un_campo_con_significado_no_se_puede_anadir_como_campo() {
        // LA TRAMPA DE PROTOBUF. Un nodo viejo recibe el mensaje, ignora el
        // campo, y cree que no ha pasado nada: la maquina esta contenida y el
        // panel dice que no. Nadie ve un error.
        let v = evaluar(Cambio::CampoConSignificado);
        match v {
            Veredicto::Prohibido { motivo } => {
                assert!(motivo.contains("metodo nuevo"), "{motivo}");
                assert!(motivo.contains("SILENCIO"));
            }
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn un_metodo_nuevo_si_vale_porque_falla_ruidosamente() {
        assert_eq!(evaluar(Cambio::MetodoNuevo), Veredicto::SubeMenor);
    }

    #[test]
    fn borrar_un_campo_y_cambiar_su_significado_estan_prohibidos() {
        for c in [Cambio::BorrarCampo, Cambio::CambioDeSignificado] {
            assert!(matches!(evaluar(c), Veredicto::Prohibido { .. }), "{c:?}");
        }
    }

    #[test]
    fn un_campo_de_telemetria_solo_sube_la_menor() {
        assert_eq!(evaluar(Cambio::CampoIgnorable), Veredicto::SubeMenor);
    }

    // --- La compatibilidad ---------------------------------------------------

    #[test]
    fn un_agente_de_la_version_anterior_sigue_funcionando_y_se_le_dice_que_le_falta() {
        // «Esta maquina no recibe reglas del corpus mundial porque su agente es
        // 1.1» es accionable; «version antigua» no lo es.
        let c = compatibilidad(Version::nueva(1, 1), ACTUAL);
        match c {
            Compatibilidad::AgenteAntiguo { version, sin } => {
                assert_eq!(version, Version::nueva(1, 1));
                assert!(sin.iter().any(|f| f.contains("corpus mundial")), "{sin:?}");
                assert!(sin.iter().any(|f| f.contains("ingesta")), "{sin:?}");
            }
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn un_agente_mas_nuevo_que_el_nodo_se_atiende_igual() {
        // Pasa durante TODA actualizacion progresiva: los agentes se actualizan
        // contra los nodos ya nuevos y despues aterrizan en uno viejo.
        let nodo_viejo = Version::nueva(1, 1);
        let c = compatibilidad(ACTUAL, nodo_viejo);
        assert!(matches!(c, Compatibilidad::AgenteNuevo { .. }), "{c:?}");
    }

    #[test]
    fn las_cuatro_combinaciones_de_una_actualizacion_funcionan() {
        // En cualquier instante de la ventana hay cuatro combinaciones vivas.
        let viejo = Version::nueva(1, 1);
        let nuevo = ACTUAL;
        for (a, n) in [
            (viejo, viejo),
            (viejo, nuevo),
            (nuevo, viejo),
            (nuevo, nuevo),
        ] {
            assert!(
                !matches!(compatibilidad(a, n), Compatibilidad::Incompatible { .. }),
                "agente {a} contra nodo {n}"
            );
        }
    }

    #[test]
    fn un_agente_demasiado_viejo_se_rechaza_con_nombre_y_con_que_hacer() {
        // Un agente rechazado en silencio reintenta para siempre, y el operador
        // ve una maquina «sin conectar» sin ninguna pista.
        let c = compatibilidad(Version::nueva(0, 9), ACTUAL);
        match c {
            Compatibilidad::Incompatible { motivo, .. } => {
                assert!(motivo.contains("actualiza el agente"), "{motivo}");
            }
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn la_misma_version_no_dice_que_falte_nada() {
        assert_eq!(compatibilidad(ACTUAL, ACTUAL), Compatibilidad::Igual);
    }

    // --- La actualizacion progresiva ----------------------------------------

    #[test]
    fn la_actualizacion_nunca_deja_a_la_flota_sin_canal() {
        // La unica regla que importa aqui, y por eso esta en el codigo y no en
        // el manual de operaciones.
        let nodos: Vec<String> = (0..4).map(|i| format!("nodo-{i}")).collect();
        let mut p = Progresiva::nueva(&nodos, 1);
        let mut pasos = 0;
        while !p.terminada() {
            assert!(
                p.disponibles().len() >= nodos.len() - 1,
                "quedaron {} nodos disponibles",
                p.disponibles().len()
            );
            assert!(p.avanzar().is_some(), "se atasco");
            pasos += 1;
            assert!(pasos < 100, "no termina");
        }
        assert!(p.terminada());
    }

    #[test]
    fn un_nodo_drena_antes_de_pararse() {
        // Sin drenaje, actualizar un nodo corta de golpe sus veinte mil
        // conexiones y provoca la manada contra los demas; y como los demas
        // tambien se van a actualizar, la manada se repite una vez por nodo.
        let nodos: Vec<String> = (0..3).map(|i| format!("nodo-{i}")).collect();
        let mut p = Progresiva::nueva(&nodos, 1);
        let (n, f) = p.avanzar().unwrap();
        assert_eq!(f, Fase::Drenando);
        assert!(!p.disponibles().contains(&n.as_str()), "sigue aceptando");
        let (n2, f2) = p.avanzar().unwrap();
        assert_eq!(n2, n);
        assert_eq!(f2, Fase::Parado);
    }

    #[test]
    fn con_tolerancia_uno_se_termina_un_nodo_antes_de_tocar_el_siguiente() {
        // Un nodo a medias es capacidad perdida: con la tolerancia agotada, lo
        // unico que se puede hacer es adelantar el que ya esta fuera.
        let nodos: Vec<String> = (0..4).map(|i| format!("nodo-{i}")).collect();
        let mut p = Progresiva::nueva(&nodos, 1);
        let (primero, _) = p.avanzar().unwrap();
        for _ in 0..2 {
            let (n, _) = p.avanzar().unwrap();
            assert_eq!(n, primero, "empezo otro antes de terminar el primero");
        }
        assert_eq!(p.fase(&primero), Some(Fase::Nueva));
    }

    #[test]
    fn con_mas_tolerancia_se_actualiza_mas_deprisa_y_con_menos_capacidad() {
        let nodos: Vec<String> = (0..8).map(|i| format!("nodo-{i}")).collect();
        let contar = |tolerancia| {
            let mut p = Progresiva::nueva(&nodos, tolerancia);
            let mut minimo = nodos.len();
            let mut pasos = 0;
            while !p.terminada() {
                minimo = minimo.min(p.disponibles().len());
                p.avanzar();
                pasos += 1;
                assert!(pasos < 200);
            }
            (pasos, minimo)
        };
        let (_, min1) = contar(1);
        let (_, min3) = contar(3);
        assert!(min3 < min1, "mas tolerancia deja menos capacidad");
        assert!(min1 >= 7, "con tolerancia 1 siempre quedan 7 de 8");
    }

    #[test]
    fn una_actualizacion_de_un_solo_nodo_termina() {
        // El caso limite: no hay a quien drenar.
        let mut p = Progresiva::nueva(&["solo".to_string()], 1);
        let mut pasos = 0;
        while !p.terminada() {
            assert!(p.avanzar().is_some());
            pasos += 1;
            assert!(pasos < 10);
        }
    }
}
