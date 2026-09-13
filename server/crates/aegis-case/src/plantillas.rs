//! Plantillas de respuesta por clase de incidente.
//!
//! # El orden de las tareas no es el mismo para todos los incidentes
//!
//! Es lo unico interesante de este modulo, y lo que casi todas las plantillas
//! genericas hacen mal: ponen «contener» siempre en el primer paso.
//!
//! * **Ransomware cifrando**: se contiene PRIMERO y se investiga despues. Cada
//!   minuto son ficheros. Aqui «investigar antes de actuar» cuesta datos.
//! * **Cuenta comprometida con acceso persistente**: se investiga primero.
//!   Bloquear la cuenta le dice al atacante que se le ha visto, y lo que hace es
//!   cambiar al acceso de reserva que nadie ha encontrado todavia. Aqui
//!   «contener antes de investigar» cuesta la investigacion, y a menudo el
//!   incidente entero.
//! * **Movimiento lateral en curso**: se contiene el origen y se observa el
//!   resto. Contener todo a la vez deja al atacante sin camino... y al defensor
//!   sin saber cuantas maquinas tenia.
//!
//! Poner el orden en la plantilla —y **decir por que**— es lo que convierte una
//! lista de tareas en algo que ayuda a las tres de la manana. Una plantilla que
//! solo enumera pasos genera casos con las mismas cinco tareas en todos, que es
//! lo mismo que no tener plantilla.
//!
//! # Lo que la plantilla NO hace
//!
//! No ejecuta nada y no cierra tareas sola. **Propone**, y quien decide es una
//! persona: una plantilla que actuara convertiria un error de clasificacion en un
//! aislamiento automatico de una maquina de produccion.

use crate::modelo::Caso;

/// Clase de incidente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clase {
    /// Cifrado masivo en curso.
    Ransomware,
    /// Credenciales comprometidas.
    CuentaComprometida,
    /// El atacante se mueve entre maquinas.
    MovimientoLateral,
    /// Se estan sacando datos.
    Exfiltracion,
    /// El atacante se asegura de volver.
    Persistencia,
    /// Alguien mina con la maquina del cliente.
    Mineria,
    /// Correo con carga o enlace.
    Phishing,
    /// No se sabe todavia.
    ///
    /// Tiene plantilla propia y no se queda sin ella: un caso sin clasificar es
    /// justo en el que mas falta hace saber por donde empezar.
    SinClasificar,
}

impl Clase {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Clase::Ransomware => "ransomware",
            Clase::CuentaComprometida => "cuenta-comprometida",
            Clase::MovimientoLateral => "movimiento-lateral",
            Clase::Exfiltracion => "exfiltracion",
            Clase::Persistencia => "persistencia",
            Clase::Mineria => "mineria",
            Clase::Phishing => "phishing",
            Clase::SinClasificar => "sin-clasificar",
        }
    }
}

/// Que hay que hacer primero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orden {
    /// Contener y despues investigar. Cada minuto cuesta datos.
    ContenerPrimero,
    /// Investigar y despues contener. Contener antes avisa al atacante.
    InvestigarPrimero,
    /// Contener el origen y observar el resto.
    ContenerElOrigen,
}

impl Orden {
    /// Por que, en una frase que se lee en el panel.
    #[must_use]
    pub fn motivo(self) -> &'static str {
        match self {
            Orden::ContenerPrimero => {
                "cada minuto son ficheros: investigar antes de actuar cuesta datos"
            }
            Orden::InvestigarPrimero => {
                "bloquear ahora le dice al atacante que se le ha visto, y cambiara al acceso de \
                 reserva que todavia no se ha encontrado"
            }
            Orden::ContenerElOrigen => {
                "contener todo a la vez deja al atacante sin camino y al defensor sin saber \
                 cuantas maquinas tenia"
            }
        }
    }
}

/// Una plantilla de respuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plantilla {
    /// A que clase corresponde.
    pub clase: Clase,
    /// Que hacer primero, y por que.
    pub orden: Orden,
    /// Las tareas, en el orden en que hay que hacerlas.
    pub tareas: &'static [&'static str],
    /// Que hay que preguntar antes de cerrar.
    ///
    /// Va aparte de las tareas porque no es trabajo: es la comprobacion de que
    /// el trabajo respondio a algo. Un caso cerrado sin respuesta a esto es un
    /// caso cerrado sin saber si se acabo.
    pub antes_de_cerrar: &'static [&'static str],
}

/// Tecnicas de ATT&CK que apuntan a cada clase.
///
/// Es una tabla y no una cadena de `if`: la lista crece, y una cadena de `if`
/// crece con ella hasta que nadie sabe cual gana.
const SENALES: &[(&str, Clase)] = &[
    ("T1486", Clase::Ransomware),
    ("T1490", Clase::Ransomware),
    ("T1489", Clase::Ransomware),
    ("T1078", Clase::CuentaComprometida),
    ("T1110", Clase::CuentaComprometida),
    ("T1556", Clase::CuentaComprometida),
    ("T1021", Clase::MovimientoLateral),
    ("T1570", Clase::MovimientoLateral),
    ("T1550", Clase::MovimientoLateral),
    ("T1041", Clase::Exfiltracion),
    ("T1567", Clase::Exfiltracion),
    ("T1048", Clase::Exfiltracion),
    ("T1053", Clase::Persistencia),
    ("T1543", Clase::Persistencia),
    ("T1547", Clase::Persistencia),
    ("T1546", Clase::Persistencia),
    ("T1496", Clase::Mineria),
    ("T1566", Clase::Phishing),
];

/// Deduce la clase de un caso por sus tecnicas.
///
/// Si hay varias, gana la de **mas urgencia**, que es el orden del enumerado. No
/// es una eleccion estetica: un caso que es a la vez persistencia y ransomware se
/// atiende como ransomware, porque la persistencia se puede investigar despues y
/// los ficheros cifrados no se descifran.
#[must_use]
pub fn clasificar(caso: &Caso) -> Clase {
    let mut mejor = Clase::SinClasificar;
    for t in &caso.tecnicas {
        for (senal, clase) in SENALES {
            // Se compara por prefijo: `T1059.001` y `T1059` son la misma tecnica
            // con distinto grado de detalle, y exigir igualdad exacta deja sin
            // clasificar justo los casos mejor identificados.
            if t.starts_with(senal) && *clase < mejor {
                mejor = *clase;
            }
        }
    }
    mejor
}

/// La plantilla de una clase.
#[must_use]
pub fn para(clase: Clase) -> Plantilla {
    match clase {
        Clase::Ransomware => Plantilla {
            clase,
            orden: Orden::ContenerPrimero,
            tareas: &[
                "aislar de red las maquinas que estan cifrando, AHORA",
                "parar el proceso que cifra y conservar su imagen antes de matarlo",
                "identificar el alcance: que recursos compartidos estaban montados",
                "comprobar si las copias de seguridad son alcanzables desde las maquinas afectadas",
                "buscar la nota de rescate y la familia, para saber si hay descifrador",
                "identificar la entrada: casi nunca es la maquina que cifra",
                "revisar si se exfiltro antes de cifrar, que es lo habitual desde 2020",
            ],
            antes_de_cerrar: &[
                "¿se sabe por donde entraron?",
                "¿las copias de seguridad estan fuera del alcance del atacante?",
                "¿se ha descartado la exfiltracion previa?",
            ],
        },
        Clase::CuentaComprometida => Plantilla {
            clase,
            orden: Orden::InvestigarPrimero,
            tareas: &[
                "NO bloquear todavia: enumerar primero todo lo que la cuenta ha tocado",
                "buscar accesos de reserva: claves, tokens, reglas de reenvio, aplicaciones \
                 autorizadas",
                "revisar si la cuenta creo o modifico otras cuentas",
                "preparar el bloqueo de TODO a la vez: cuenta, sesiones, tokens y accesos de \
                 reserva",
                "ejecutar el bloqueo completo",
                "rotar las credenciales de lo que la cuenta pudiera alcanzar",
            ],
            antes_de_cerrar: &[
                "¿se han revocado tambien las sesiones y los tokens vivos?",
                "¿se ha comprobado que no quedan accesos de reserva?",
                "¿se sabe como se obtuvo la credencial?",
            ],
        },
        Clase::MovimientoLateral => Plantilla {
            clase,
            orden: Orden::ContenerElOrigen,
            tareas: &[
                "aislar la maquina de origen y dejar el resto observado",
                "reconstruir el camino: que credenciales se usaron en cada salto",
                "identificar hasta donde llego, que casi siempre es mas lejos de lo que parece",
                "buscar persistencia en cada maquina alcanzada antes de limpiarla",
                "contener el resto cuando se sepa el alcance completo",
            ],
            antes_de_cerrar: &[
                "¿se ha reconstruido el camino entero o solo el ultimo salto?",
                "¿se ha buscado persistencia en TODAS las maquinas alcanzadas?",
            ],
        },
        Clase::Exfiltracion => Plantilla {
            clase,
            orden: Orden::ContenerPrimero,
            tareas: &[
                "cortar la salida hacia el destino, sin tocar la maquina todavia",
                "medir que se fue: volumen, ficheros y desde cuando",
                "conservar la evidencia de red antes de que rote",
                "determinar si hay obligacion de notificar y en que plazo",
                "identificar la entrada y la persistencia",
            ],
            antes_de_cerrar: &[
                "¿se sabe QUE se fue, no solo cuanto?",
                "¿se ha evaluado la obligacion de notificar?",
            ],
        },
        Clase::Persistencia => Plantilla {
            clase,
            orden: Orden::InvestigarPrimero,
            tareas: &[
                "enumerar TODOS los mecanismos antes de quitar ninguno",
                "buscar los que se instalaron para reponer a los demas",
                "identificar cuando se instalo el primero: es la fecha real del compromiso",
                "quitarlos todos a la vez",
                "vigilar la reaparicion durante los dias siguientes",
            ],
            antes_de_cerrar: &[
                "¿se quitaron TODOS a la vez o uno a uno?",
                "¿se sabe la fecha real del compromiso?",
            ],
        },
        Clase::Mineria => Plantilla {
            clase,
            orden: Orden::ContenerPrimero,
            tareas: &[
                "parar el minero y cortar su salida",
                "buscar como entro: la mineria casi nunca viene sola",
                "revisar si hay persistencia y credenciales tocadas",
            ],
            antes_de_cerrar: &["¿se ha descartado que la mineria fuera lo unico que hicieron?"],
        },
        Clase::Phishing => Plantilla {
            clase,
            orden: Orden::InvestigarPrimero,
            tareas: &[
                "conservar el correo entero con sus cabeceras",
                "identificar a todos los que lo recibieron, no solo al que informo",
                "comprobar quien pincho y quien metio credenciales",
                "retirar el correo de los buzones",
                "tratar como cuenta comprometida a quien metio credenciales",
            ],
            antes_de_cerrar: &[
                "¿se ha revisado quien mas lo recibio?",
                "¿se ha comprobado si alguien metio credenciales?",
            ],
        },
        Clase::SinClasificar => Plantilla {
            clase,
            orden: Orden::InvestigarPrimero,
            tareas: &[
                "reconstruir el linaje del proceso o de la cuenta implicada",
                "determinar si la actividad es autorizada, y por quien",
                "buscar la misma actividad en el resto de la flota",
                "clasificar el caso cuando se sepa que es",
            ],
            antes_de_cerrar: &["¿se ha determinado que clase de incidente era?"],
        },
    }
}

/// Propone las tareas de un caso segun su clase.
///
/// **Propone**: no las crea. Quien decide es una persona, y una plantilla que
/// actuara convertiria un error de clasificacion en un aislamiento automatico de
/// una maquina de produccion.
#[must_use]
pub fn proponer(caso: &Caso) -> Plantilla {
    para(clasificar(caso))
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Alerta, Observable, Severidad};

    const AHORA: u64 = 1_700_000_000_000_000_000;

    fn caso_con(tecnicas: &[&str]) -> Caso {
        let mut c = Caso::abrir(
            "C-1",
            Alerta {
                id: "A-1".into(),
                inquilino: "c".into(),
                anfitrion: "m".into(),
                sujeto: "pid:1".into(),
                tecnica: tecnicas.first().map(|t| (*t).to_string()),
                regla: "r".into(),
                severidad: Severidad::Alta,
                ocurrio_ns: AHORA,
                observables: vec![Observable::Anfitrion("m".into())],
                resumen: "x".into(),
            },
        );
        for t in tecnicas.iter().skip(1) {
            if !c.tecnicas.contains(&(*t).to_string()) {
                c.tecnicas.push((*t).to_string());
            }
        }
        c
    }

    #[test]
    fn el_ransomware_se_contiene_primero_y_se_dice_por_que() {
        // Cada minuto son ficheros. Aqui «investigar antes de actuar» cuesta
        // datos.
        let p = proponer(&caso_con(&["T1486"]));
        assert_eq!(p.clase, Clase::Ransomware);
        assert_eq!(p.orden, Orden::ContenerPrimero);
        assert!(p.tareas[0].contains("aislar"), "{}", p.tareas[0]);
        assert!(p.orden.motivo().contains("ficheros"));
    }

    #[test]
    fn una_cuenta_comprometida_se_investiga_primero_y_se_dice_por_que() {
        // Bloquear la cuenta le dice al atacante que se le ha visto, y cambiara
        // al acceso de reserva que nadie ha encontrado todavia. Aqui «contener
        // antes de investigar» cuesta la investigacion, y a menudo el incidente.
        let p = proponer(&caso_con(&["T1078"]));
        assert_eq!(p.clase, Clase::CuentaComprometida);
        assert_eq!(p.orden, Orden::InvestigarPrimero);
        assert!(p.tareas[0].contains("NO bloquear"), "{}", p.tareas[0]);
        assert!(p.orden.motivo().contains("reserva"));
    }

    #[test]
    fn el_movimiento_lateral_contiene_el_origen_y_observa_el_resto() {
        // Contener todo a la vez deja al atacante sin camino y al defensor sin
        // saber cuantas maquinas tenia.
        let p = proponer(&caso_con(&["T1021.001"]));
        assert_eq!(p.clase, Clase::MovimientoLateral);
        assert_eq!(p.orden, Orden::ContenerElOrigen);
    }

    #[test]
    fn una_tecnica_con_subtecnica_se_reconoce_igual() {
        // Exigir igualdad exacta dejaria sin clasificar justo los casos mejor
        // identificados.
        assert_eq!(clasificar(&caso_con(&["T1486.000"])), Clase::Ransomware);
        assert_eq!(clasificar(&caso_con(&["T1566.002"])), Clase::Phishing);
    }

    #[test]
    fn con_varias_tecnicas_gana_la_mas_urgente() {
        // Un caso que es a la vez persistencia y ransomware se atiende como
        // ransomware: la persistencia se investiga despues y los ficheros
        // cifrados no se descifran.
        let c = caso_con(&["T1053", "T1486"]);
        assert_eq!(clasificar(&c), Clase::Ransomware);
    }

    #[test]
    fn un_caso_sin_clasificar_tambien_tiene_plantilla() {
        // Es justo en el que mas falta hace saber por donde empezar.
        let p = proponer(&caso_con(&["T9999"]));
        assert_eq!(p.clase, Clase::SinClasificar);
        assert!(!p.tareas.is_empty());
        assert!(!p.antes_de_cerrar.is_empty());
    }

    #[test]
    fn toda_plantilla_pregunta_algo_antes_de_cerrar() {
        // No es trabajo: es la comprobacion de que el trabajo respondio a algo.
        // Un caso cerrado sin respuesta a esto es un caso cerrado sin saber si se
        // acabo.
        for clase in [
            Clase::Ransomware,
            Clase::CuentaComprometida,
            Clase::MovimientoLateral,
            Clase::Exfiltracion,
            Clase::Persistencia,
            Clase::Mineria,
            Clase::Phishing,
            Clase::SinClasificar,
        ] {
            let p = para(clase);
            assert!(!p.tareas.is_empty(), "{}", clase.nombre());
            assert!(!p.antes_de_cerrar.is_empty(), "{}", clase.nombre());
            assert!(
                p.antes_de_cerrar.iter().all(|q| q.contains('?')),
                "{} no pregunta, afirma",
                clase.nombre()
            );
        }
    }

    #[test]
    fn cada_clase_tiene_su_orden_y_no_todas_contienen_primero() {
        // Es lo que casi todas las plantillas genericas hacen mal: ponen
        // «contener» siempre en el primer paso.
        let ordenes: std::collections::BTreeSet<&str> = [
            Clase::Ransomware,
            Clase::CuentaComprometida,
            Clase::MovimientoLateral,
        ]
        .iter()
        .map(|c| match para(*c).orden {
            Orden::ContenerPrimero => "contener",
            Orden::InvestigarPrimero => "investigar",
            Orden::ContenerElOrigen => "origen",
        })
        .collect();
        assert_eq!(ordenes.len(), 3, "las tres clases tienen el mismo orden");
    }

    #[test]
    fn el_ransomware_recuerda_mirar_la_exfiltracion_previa() {
        // Es lo habitual desde 2020 y es lo que decide si hay que notificar.
        let p = para(Clase::Ransomware);
        assert!(p.tareas.iter().any(|t| t.contains("exfiltr")));
        assert!(p.antes_de_cerrar.iter().any(|q| q.contains("exfiltracion")));
    }

    #[test]
    fn la_plantilla_no_crea_ni_cierra_tareas_sola() {
        // Una plantilla que actuara convertiria un error de clasificacion en un
        // aislamiento automatico de una maquina de produccion.
        let c = caso_con(&["T1486"]);
        let antes = c.tareas.len();
        let _ = proponer(&c);
        assert_eq!(c.tareas.len(), antes, "la plantilla toco el caso");
    }
}
