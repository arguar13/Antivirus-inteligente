//! El inventario: que subsistema produce veredictos hoy, con que vocabulario y
//! sobre que identificador de entidad.
//!
//! # Por que el inventario va PRIMERO, y va en el codigo
//!
//! Unificar sin haber contado es adivinar. Antes de esta fase el arbol tenia
//! **doce enumerados de veredicto y nueve de severidad** —veintiuno, sin contar
//! los que hablan de otras cosas—, ninguno mal por separado, y ni una sola tabla
//! que dijera cual se traduce a cual. La
//! consecuencia practica no es estetica: ante un mismo ataque salian nueve
//! sucesos sin relacion, y el analista tenia que hacer la union a mano — que es
//! exactamente el trabajo que un producto integrado existe para ahorrar.
//!
//! Este modulo es ese recuento, y esta en el codigo y no en un documento **por
//! una razon comprobable**: un documento se queda viejo en silencio. Aqui la
//! puerta de calidad recorre [`escala::Motor::todos`] y exige que cada motor
//! tenga su fila; un motor nuevo sin traduccion declarada **rompe la
//! compilacion de las pruebas**, no pasa desapercibido.
//!
//! # Lo que cada fila dice
//!
//! Cuatro cosas, y las cuatro hacian falta para poder unificar:
//!
//! 1. **Que subsistema** — el crate y la fase en que se construyo.
//! 2. **Con que vocabulario hablaba antes** — el enumerado nativo, tal cual. No
//!    se borra: sigue existiendo y sigue siendo el correcto *dentro* de su
//!    subsistema. Lo que cambia es que ahora hay una traduccion escrita.
//! 3. **Sobre que clase de entidad** — la clase de [`entidad::Clase`] que nombra.
//! 4. **Como la nombra** — de que hechos deriva el identificador, que es lo que
//!    permite que dos subsistemas lleguen al mismo nombre sin hablar entre ellos.
//!
//! # Los productores que NO son motores de deteccion
//!
//! Estos tambien producen un enumerado con forma de veredicto, y **a proposito
//! no entran en la tabla de motores**: mezclarlos seria darle voto en el arbitro
//! a algo que no observo nada.
//!
//! | Subsistema | Que produce | Por que no es una señal |
//! |---|---|---|
//! | `aegis-case` | `Veredicto` de cierre: verdadero / falso positivo / autorizado / no concluyente | Es el juicio de **una persona** al cerrar, y llega despues; darle voto seria realimentar la deteccion con su propio resultado |
//! | `aegis-predict` | `Veredicto` de contencion: contener / escalar / no actuar | Es una **decision de respuesta**, no una observacion: consume veredictos, no los produce |
//! | `aegis-share` | `Retenido`: por que algo no se distribuye | Es control de difusion; no dice nada sobre si la cosa es maliciosa |
//! | `aegis-enrich` | `Fusion` sobre dictamenes de terceros | Si entra, pero **como un solo motor**, [`escala::Motor::Intel`]: veinte proveedores que repiten a un mismo origen no son veinte planos |
//!
//! La ultima fila es la decision que mas cambia el resultado, y viene de
//! `aegis-share::procedencia`: **dos canales que repiten al mismo son una
//! fuente**. Aplicada aqui: toda la inteligencia externa es un unico motor.

use aegis_entidad::entidad::Clase;
use aegis_entidad::escala::{Motor, Plano};

/// Una fila del inventario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fila {
    /// El motor, en el vocabulario unico.
    pub motor: Motor,
    /// El crate que lo implementa.
    pub crate_: &'static str,
    /// La fase en que se construyo.
    pub fase: u16,
    /// Con que hablaba antes de esta fase, tal cual.
    ///
    /// Se conserva escrito porque sigue existiendo: la traduccion no borra el
    /// vocabulario nativo, lo acota a su subsistema.
    pub vocabulario_nativo: &'static str,
    /// Que clase de entidad nombra.
    pub clase: Clase,
    /// De que hechos deriva el identificador.
    pub derivacion: &'static str,
}

impl Fila {
    /// El plano en el que observa, que lo fija el motor y no la fila.
    ///
    /// Esta aqui y no duplicado en la tabla **a proposito**: un plano escrito dos
    /// veces es un plano que puede discrepar consigo mismo.
    #[must_use]
    pub fn plano(&self) -> Plano {
        self.motor.plano()
    }

    /// Una linea legible, para el informe del inventario.
    #[must_use]
    pub fn linea(&self) -> String {
        format!(
            "{:<12} FASE {:<3} {:<18} plano {:<11} entidad {:<10} · {}",
            self.motor.nombre(),
            self.fase,
            self.crate_,
            self.plano().nombre(),
            self.clase.prefijo(),
            self.derivacion
        )
    }
}

/// El censo completo, una fila por motor.
///
/// El orden es el de [`escala::Motor::todos`], que a su vez va por planos: leerlo
/// de arriba abajo es leer el producto por capas de observacion.
pub const CENSO: &[Fila] = &[
    Fila {
        motor: Motor::Estatico,
        crate_: "aegis-scan",
        fase: 3,
        vocabulario_nativo: "coincidencia de firma / regla YARA, sin enumerado de veredicto propio",
        clase: Clase::Contenido,
        derivacion: "SHA-256 del fichero",
    },
    Fila {
        motor: Motor::Aprendizaje,
        crate_: "aegis-edgeml",
        fase: 21,
        vocabulario_nativo: "Veredicto{Benigno,Sospechoso,Malicioso} + puntuacion f32 [0,1]",
        clase: Clase::Contenido,
        derivacion: "SHA-256 del fichero que se puntuo",
    },
    Fila {
        motor: Motor::Conductual,
        crate_: "aegis-behavior",
        fase: 8,
        vocabulario_nativo: "puntuacion acumulada por reglas de comportamiento",
        clase: Clase::Proceso,
        derivacion: "(maquina, boot, pid, arranque_ns)",
    },
    Fila {
        motor: Motor::SyscallGuard,
        crate_: "aegis-syscallguard",
        fase: 46,
        vocabulario_nativo: "Severidad{Info,Baja,Media,Alta,Critica} sobre el origen de la llamada",
        clase: Clase::Proceso,
        derivacion: "(maquina, boot, pid, arranque_ns)",
    },
    Fila {
        motor: Motor::MemHunter,
        crate_: "aegis-memhunter",
        fase: 65,
        vocabulario_nativo: "Severidad{Info,Baja,Media,Alta,Critica} sobre la region de memoria",
        clase: Clase::Proceso,
        derivacion: "(maquina, boot, pid, arranque_ns) del proceso con la region",
    },
    Fila {
        motor: Motor::Wire,
        crate_: "aegis-wire",
        fase: 70,
        vocabulario_nativo: "Hecho{23 variantes} — no dice «malicioso», dice QUE paso",
        clase: Clase::Flujo,
        derivacion: "(maquina, extremo menor, extremo mayor, protocolo, primer_ns)",
    },
    Fila {
        motor: Motor::Ips,
        crate_: "aegis-ips",
        fase: 71,
        vocabulario_nativo: "Confianza{Baja,Media,Alta} — solo Alta puede cortar",
        clase: Clase::Flujo,
        derivacion: "misma clave de flujo que Wire, a proposito",
    },
    Fila {
        motor: Motor::L7Hunter,
        crate_: "aegis-l7hunter",
        fase: 66,
        vocabulario_nativo: "Veredicto{SinMuestra,Irregular,BalizaConJitter,BalizaExacta}",
        clase: Clase::Flujo,
        derivacion: "clave de flujo del canal cifrado observado con uprobes",
    },
    Fila {
        motor: Motor::Itdr,
        crate_: "aegis-itdr",
        fase: 56,
        vocabulario_nativo:
            "Severidad{Info,Baja,Media,Alta,Critica} + Nivel del grafo de identidad",
        clase: Clase::Cuenta,
        derivacion: "identificador de directorio (SID, objectGUID), no el nombre de inicio",
    },
    Fila {
        motor: Motor::FirmwareAudit,
        crate_: "aegis-fwaudit",
        fase: 67,
        vocabulario_nativo: "Veredicto{de linea base} + Severidad{de anomalia ACPI}",
        clase: Clase::Maquina,
        derivacion: "matricula de la maquina",
    },
    Fila {
        motor: Motor::Nucleo,
        crate_: "aegis-kintegrity",
        fase: 25,
        vocabulario_nativo: "AnomalyKind{dkom, oculto-en-userland, ...} + severidad /100",
        clase: Clase::Maquina,
        derivacion: "matricula de la maquina: lo comprometido es el kernel que miente",
    },
    Fila {
        motor: Motor::Detonate,
        crate_: "aegis-detonate",
        fase: 73,
        vocabulario_nativo: "Veredicto{SinHallazgos,ConHallazgos{hechos},NoConcluyente{motivo}}",
        clase: Clase::Artefacto,
        derivacion: "(SHA-256 de la muestra, resumen de la configuracion de detonacion)",
    },
    Fila {
        motor: Motor::Intel,
        crate_: "aegis-enrich + aegis-share",
        fase: 77,
        vocabulario_nativo: "Veredicto{Malicioso,Sospechoso,Limpio,EnDisputa,SinDatos}",
        clase: Clase::Contenido,
        derivacion: "el observable consultado; para un fichero, su SHA-256",
    },
    Fila {
        motor: Motor::Enjambre,
        crate_: "aegis-swarm",
        fase: 68,
        vocabulario_nativo: "Veredicto{Insuficiente,Corroborado,Repetido,YaAvisado}",
        clase: Clase::Contenido,
        derivacion: "el Ioc corroborado; para un fichero, su SHA-256",
    },
];

/// La fila de un motor.
///
/// No devuelve `Option`: la puerta de calidad garantiza que todos estan, asi que
/// un `None` aqui seria un fallo de invariante y no un caso que el llamante deba
/// tratar.
///
/// # Panics
///
/// Si el motor no tiene fila. No puede ocurrir con el censo completo, y la prueba
/// `todos_los_motores_tienen_fila` lo mantiene asi.
#[must_use]
pub fn fila(motor: Motor) -> &'static Fila {
    CENSO
        .iter()
        .find(|f| f.motor == motor)
        .unwrap_or_else(|| panic!("motor «{}» sin fila en el censo", motor.nombre()))
}

/// Cuantos motores observan en cada plano.
///
/// Es la cifra que decide si el producto tiene corroboracion de verdad: dos
/// motores del mismo plano no corroboran nada, por distintos que sean.
#[must_use]
pub fn motores_por_plano() -> Vec<(Plano, usize)> {
    Plano::todos()
        .iter()
        .map(|p| (*p, CENSO.iter().filter(|f| f.plano() == *p).count()))
        .collect()
}

/// El informe del inventario, legible.
#[must_use]
pub fn informe() -> String {
    let mut s = String::new();
    s.push_str("INVENTARIO DE VEREDICTOS · un motor por fila, un plano por motor\n");
    for f in CENSO {
        s.push_str("  ");
        s.push_str(&f.linea());
        s.push('\n');
    }
    s.push_str("\nMOTORES POR PLANO (dos del mismo plano no corroboran)\n");
    for (p, n) in motores_por_plano() {
        s.push_str(&format!("  {:<12} {n}\n", p.nombre()));
    }
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::collections::BTreeSet;

    /// LA PRUEBA QUE MANTIENE VIVO EL INVENTARIO. Un motor nuevo sin fila no pasa
    /// de aqui: no hay forma de añadirlo al producto sin declarar en que plano
    /// observa, sobre que entidad y con que vocabulario hablaba antes.
    #[test]
    fn todos_los_motores_tienen_fila() {
        for m in Motor::todos() {
            let f = fila(*m);
            assert_eq!(f.motor, *m);
            assert!(!f.crate_.is_empty(), "{}", m.nombre());
            assert!(!f.vocabulario_nativo.is_empty(), "{}", m.nombre());
            assert!(!f.derivacion.is_empty(), "{}", m.nombre());
            assert!(f.fase > 0, "{}", m.nombre());
        }
        assert_eq!(CENSO.len(), Motor::todos().len());
    }

    /// Un motor no puede aparecer dos veces: si apareciera, su voto contaria
    /// doble en cualquier recuento por plano.
    #[test]
    fn ningun_motor_esta_repetido() {
        let unicos: BTreeSet<Motor> = CENSO.iter().map(|f| f.motor).collect();
        assert_eq!(unicos.len(), CENSO.len());
    }

    /// EL PLANO EXTERNO ESTA POBLADO Y NO DECIDE SOLO. Intel y Enjambre son los
    /// dos motores que **repiten** en vez de observar, y el arbitro tiene una
    /// regla entera dedicada a que no basten por si solos.
    #[test]
    fn lo_externo_son_dos_motores_y_un_solo_plano() {
        let externos: Vec<&Fila> = CENSO
            .iter()
            .filter(|f| f.plano() == Plano::Externo)
            .collect();
        assert_eq!(externos.len(), 2);
        assert!(externos.iter().any(|f| f.motor == Motor::Intel));
        assert!(externos.iter().any(|f| f.motor == Motor::Enjambre));
    }

    /// EL ESTATICO Y EL MODELO NOMBRAN LA MISMA ENTIDAD Y COMPARTEN PLANO. Es la
    /// fila del inventario que mas dice: se alimentan de lo mismo, asi que si
    /// coinciden **no se estan corroborando**, se estan repitiendo.
    #[test]
    fn el_estatico_y_el_modelo_comparten_entrada() {
        let e = fila(Motor::Estatico);
        let a = fila(Motor::Aprendizaje);
        assert_eq!(e.clase, a.clase);
        assert_eq!(e.derivacion, "SHA-256 del fichero");
        assert_eq!(e.plano(), a.plano());
    }

    /// Todo plano declarado tiene al menos un motor. Un plano vacio en la escala
    /// seria una capa de observacion que el producto dice tener y no tiene.
    #[test]
    fn ningun_plano_se_queda_sin_motor() {
        for (p, n) in motores_por_plano() {
            assert!(n > 0, "el plano «{}» no tiene ningun motor", p.nombre());
        }
    }

    /// El informe nombra los trece motores y los siete planos: es lo que se
    /// imprime en la puerta de calidad, y un informe que se deja algo fuera es
    /// peor que no tenerlo.
    #[test]
    fn el_informe_nombra_todo() {
        let i = informe();
        for m in Motor::todos() {
            assert!(i.contains(m.nombre()), "falta «{}»", m.nombre());
        }
        for p in Plano::todos() {
            assert!(i.contains(p.nombre()), "falta el plano «{}»", p.nombre());
        }
    }

    /// La clase de entidad de cada fila es una de las declaradas. Suena trivial y
    /// no lo es: es lo que garantiza que el identificador que produce cada
    /// subsistema se puede volver a derivar desde otro.
    #[test]
    fn cada_fila_nombra_una_clase_declarada() {
        for f in CENSO {
            assert!(
                Clase::todas().contains(&f.clase),
                "{} nombra una clase que no existe",
                f.motor.nombre()
            );
            assert_eq!(Clase::de_prefijo(f.clase.prefijo()), Some(f.clase));
        }
    }

    /// La traduccion de escala existe para todos: el inventario y la escala son
    /// la misma lista vista de dos maneras, y si se separan el producto vuelve a
    /// tener dos verdades.
    #[test]
    fn el_censo_y_la_escala_son_la_misma_lista() {
        let del_censo: BTreeSet<&str> = CENSO.iter().map(|f| f.motor.nombre()).collect();
        let de_la_escala: BTreeSet<&str> = Motor::todos().iter().map(|m| m.nombre()).collect();
        assert_eq!(del_censo, de_la_escala);
    }
}
