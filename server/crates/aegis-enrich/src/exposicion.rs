//! Que sale de la organizacion, dicho antes de que salga.
//!
//! # La regla que define la fase
//!
//! **Consultar por un resumen le dice al proveedor que ese fichero esta en tu
//! red.** No es un efecto secundario: es la operacion. Le das informacion que no
//! tenia, gratis, y no se puede retirar.
//!
//! Casi siempre compensa. Pero «casi siempre» es una decision, y una decision que
//! nadie ve no es una decision: es un valor por defecto. Asi que el marco obliga a
//! **declarar** la exposicion, y el panel se la enseña al analista **antes** de
//! ejecutar el analizador.
//!
//! # Por que la declaracion es un tipo y no un texto
//!
//! Un campo `descripcion: String` se rellena con «consulta reputacion» y no dice
//! nada. [`Exposicion`] obliga a enumerar **que campos** salen, **a donde**, con
//! **que retencion** y bajo **que jurisdiccion**, y todo eso son enumerados
//! cerrados. Lo que no se puede expresar no se puede declarar mal.
//!
//! Y lo que es mas importante: la declaracion es un campo **obligatorio del
//! analizador**, no una llamada que se pueda olvidar. Un analizador sin exposicion
//! declarada no compila.
//!
//! # Lo que esto NO es
//!
//! No es un control de acceso. Un analizador que declara `Destino::Externo` y
//! ademas se le entrega la salida de red, sale. La declaracion sirve para que la
//! decision sea **visible y revisable**; quien impide fisicamente la salida es
//! [`crate::salida`], que es otra cosa y esta a proposito separada. Confundir
//! «declarado» con «impedido» es el error clasico de estos marcos.

use std::fmt;

/// Que pieza de informacion sale.
///
/// Cerrado a proposito: un campo libre acaba siendo «datos» y entonces la
/// declaracion no declara nada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Campo {
    /// El resumen del fichero. Revela que ese fichero exacto esta en la red.
    ResumenDeFichero,
    /// El fichero entero. Revela su CONTENIDO.
    ContenidoDeFichero,
    /// Un nombre de dominio consultado.
    Dominio,
    /// Una direccion IP.
    DireccionIp,
    /// Una URL completa, con su cadena de consulta.
    UrlCompleta,
    /// Metadatos del fichero: tamaño, nombre, tipo.
    MetadatosDeFichero,
    /// La marca de tiempo en que se vio.
    MomentoDeObservacion,
    /// Que organizacion pregunta.
    IdentidadDelConsultante,
}

impl Campo {
    /// Nombre estable, para el panel y el informe.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Campo::ResumenDeFichero => "resumen-de-fichero",
            Campo::ContenidoDeFichero => "contenido-de-fichero",
            Campo::Dominio => "dominio",
            Campo::DireccionIp => "direccion-ip",
            Campo::UrlCompleta => "url-completa",
            Campo::MetadatosDeFichero => "metadatos-de-fichero",
            Campo::MomentoDeObservacion => "momento-de-observacion",
            Campo::IdentidadDelConsultante => "identidad-del-consultante",
        }
    }

    /// Que revela este campo, en una frase que se lee en el panel.
    #[must_use]
    pub fn revela(self) -> &'static str {
        match self {
            Campo::ResumenDeFichero => {
                "que ese fichero exacto esta en tu red; quien ya tenga el fichero puede \
                 confirmarlo comparando resumenes"
            }
            Campo::ContenidoDeFichero => {
                "el contenido completo del fichero, que si es un documento interno es una fuga en \
                 el sentido literal"
            }
            Campo::Dominio => "que alguien de tu red resolvio ese dominio",
            Campo::DireccionIp => "que alguien de tu red hablo con esa direccion",
            Campo::UrlCompleta => {
                "la ruta y la cadena de consulta, que pueden llevar identificadores de sesion"
            }
            Campo::MetadatosDeFichero => {
                "el nombre del fichero, que a menudo lleva el del proyecto o el del cliente"
            }
            Campo::MomentoDeObservacion => {
                "cuando lo viste, que permite situarte en la cronologia de una campana"
            }
            Campo::IdentidadDelConsultante => {
                "que eres TU quien pregunta, que convierte todo lo anterior en atribuible"
            }
        }
    }

    /// Si este campo, por si solo, ya es una fuga de contenido.
    ///
    /// Se usa para exigir confirmacion explicita: mandar un resumen es discutible,
    /// mandar el fichero entero no lo es.
    #[must_use]
    pub fn es_contenido(self) -> bool {
        matches!(self, Campo::ContenidoDeFichero)
    }
}

/// A donde va la consulta.
///
/// **No hay variante «no se sabe».** Un destino desconocido no se puede enseñar
/// al analista, y un marco en el que el destino puede ser desconocido es un marco
/// en el que nadie sabe que sale. La ausencia es la frontera, igual que en
/// `aegis-detonate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destino {
    /// No sale nada: el analizador solo mira datos que ya estan dentro.
    ///
    /// Es el unico destino que sigue funcionando en modo sin salida.
    Local,
    /// Un servicio de la propia organizacion, en su infraestructura.
    ///
    /// Sale del proceso pero no de la organizacion. Cuenta como salida porque el
    /// dato cruza una frontera de confianza, aunque sea una frontera interna.
    Interno {
        /// Como se llama ese servicio.
        servicio: String,
    },
    /// Un tercero.
    Externo {
        /// Quien.
        proveedor: String,
        /// Donde estan sus servidores.
        jurisdiccion: Jurisdiccion,
        /// Cuanto guardan lo que reciben.
        retencion: Retencion,
    },
}

impl Destino {
    /// Si esto saca datos de la organizacion.
    #[must_use]
    pub fn sale_de_la_organizacion(&self) -> bool {
        matches!(self, Destino::Externo { .. })
    }

    /// Si esto necesita red.
    ///
    /// `Interno` tambien la necesita: un servicio propio en otra maquina es una
    /// llamada de red, y en modo sin salida tampoco esta disponible.
    #[must_use]
    pub fn necesita_red(&self) -> bool {
        !matches!(self, Destino::Local)
    }

    /// Nombre corto para el informe.
    #[must_use]
    pub fn nombre(&self) -> String {
        match self {
            Destino::Local => "local".to_string(),
            Destino::Interno { servicio } => format!("interno:{servicio}"),
            Destino::Externo { proveedor, .. } => format!("externo:{proveedor}"),
        }
    }
}

/// Donde viven los servidores del proveedor.
///
/// Importa por una razon practica y no ideologica: la jurisdiccion decide quien
/// puede obligar al proveedor a entregar lo que recibio, y eso cambia el calculo
/// de si compensa consultarle. Tambien decide si la transferencia es legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jurisdiccion {
    /// El mismo pais que la organizacion.
    Nacional,
    /// Espacio Economico Europeo.
    Eee,
    /// Fuera del EEE, con decision de adecuacion.
    ConAdecuacion,
    /// Fuera del EEE, sin decision de adecuacion.
    ///
    /// No prohibe: obliga a que alguien lo vea y lo decida.
    SinAdecuacion,
}

impl Jurisdiccion {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Jurisdiccion::Nacional => "nacional",
            Jurisdiccion::Eee => "eee",
            Jurisdiccion::ConAdecuacion => "con-adecuacion",
            Jurisdiccion::SinAdecuacion => "sin-adecuacion",
        }
    }
}

/// Cuanto guarda el proveedor lo que recibe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retencion {
    /// No lo guarda.
    Ninguna,
    /// Lo guarda un tiempo acotado, en dias.
    Dias(u32),
    /// Lo guarda indefinidamente.
    ///
    /// Es lo normal en los servicios de reputacion, y lo que hace que una consulta
    /// sea irreversible: no hay forma de retirar lo que ya se dijo.
    Indefinida,
    /// Lo guarda y ademas lo comparte con otros.
    ///
    /// Es el caso de los agregadores multimotor: lo que subes lo ven los demas
    /// participantes. Para una muestra de malware es deseable; para un documento
    /// interno es una fuga con reparto.
    IndefinidaYCompartida,
}

impl Retencion {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Retencion::Ninguna => "ninguna",
            Retencion::Dias(_) => "dias",
            Retencion::Indefinida => "indefinida",
            Retencion::IndefinidaYCompartida => "indefinida-y-compartida",
        }
    }

    /// Si lo que se manda acaba siendo visible para terceros ademas del proveedor.
    #[must_use]
    pub fn se_comparte(self) -> bool {
        self == Retencion::IndefinidaYCompartida
    }
}

/// La declaracion completa de lo que sale al ejecutar un analizador.
///
/// Es un campo obligatorio del analizador, no una llamada opcional: un analizador
/// sin esto no compila.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposicion {
    /// A donde va.
    pub destino: Destino,
    /// Que campos salen. Vacio solo tiene sentido con [`Destino::Local`].
    pub campos: Vec<Campo>,
}

impl Exposicion {
    /// Una exposicion que no saca nada.
    #[must_use]
    pub fn ninguna() -> Exposicion {
        Exposicion {
            destino: Destino::Local,
            campos: Vec::new(),
        }
    }

    /// Si esta declaracion es coherente consigo misma.
    ///
    /// Se comprueba **al registrar el analizador**, no al ejecutarlo: una
    /// declaracion incoherente es un error de programacion, y el sitio donde se
    /// tiene que ver es el arranque, no la primera consulta de un incidente a las
    /// tres de la mañana.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo de la incoherencia.
    pub fn coherente(&self) -> Result<(), &'static str> {
        match (&self.destino, self.campos.is_empty()) {
            (Destino::Local, false) => Err(
                "un analizador con destino local declara campos que salen: o el destino esta mal \
                 o los campos lo estan, y las dos posibilidades son un fallo",
            ),
            (d, true) if d.necesita_red() => Err(
                "un analizador que necesita red no declara ningun campo: algo sale, aunque solo \
                 sea el hecho de preguntar",
            ),
            _ => Ok(()),
        }
    }

    /// Si esto exige que una persona lo autorice antes de ejecutarse.
    ///
    /// Tres casos, y los tres por la misma razon: son irreversibles y
    /// desproporcionados frente a lo que aporta una consulta rutinaria.
    ///
    /// 1. **Sale contenido.** Mandar el fichero entero no es consultar, es
    ///    entregar.
    /// 2. **Se comparte con terceros.** Lo que subes lo ven otros participantes.
    /// 3. **Jurisdiccion sin adecuacion.** No lo prohibe: obliga a que alguien lo
    ///    mire y lo decida.
    #[must_use]
    pub fn exige_autorizacion(&self) -> bool {
        if self.campos.iter().any(|c| c.es_contenido()) {
            return true;
        }
        match &self.destino {
            Destino::Externo {
                jurisdiccion,
                retencion,
                ..
            } => *jurisdiccion == Jurisdiccion::SinAdecuacion || retencion.se_comparte(),
            _ => false,
        }
    }

    /// El aviso que ve el analista **antes** de ejecutar, linea a linea.
    ///
    /// Se genera de la declaracion y no se escribe a mano: un texto escrito a mano
    /// deja de corresponderse con lo que el analizador hace en cuanto alguien
    /// cambia el analizador y no el texto.
    #[must_use]
    pub fn aviso(&self) -> Vec<String> {
        let mut lineas = Vec::new();
        match &self.destino {
            Destino::Local => {
                lineas.push("No sale nada de la organizacion.".to_string());
                return lineas;
            }
            Destino::Interno { servicio } => {
                lineas.push(format!(
                    "Sale hacia un servicio propio ({servicio}). No abandona la organizacion, pero \
                     si el proceso."
                ));
            }
            Destino::Externo {
                proveedor,
                jurisdiccion,
                retencion,
            } => {
                lineas.push(format!(
                    "Sale hacia un tercero: {proveedor} (jurisdiccion {}).",
                    jurisdiccion.nombre()
                ));
                lineas.push(match retencion {
                    Retencion::Ninguna => "No conserva lo que recibe.".to_string(),
                    Retencion::Dias(d) => format!("Conserva lo que recibe {d} dias."),
                    Retencion::Indefinida => {
                        "Conserva lo que recibe INDEFINIDAMENTE: la consulta no se puede retirar."
                            .to_string()
                    }
                    Retencion::IndefinidaYCompartida => {
                        "Conserva lo que recibe indefinidamente y LO COMPARTE con otros \
                         participantes."
                            .to_string()
                    }
                });
            }
        }
        for c in &self.campos {
            lineas.push(format!("  - {}: revela {}", c.nombre(), c.revela()));
        }
        if self.exige_autorizacion() {
            lineas.push(
                "Esta consulta EXIGE autorizacion explicita: es irreversible y desproporcionada \
                 para un enriquecimiento rutinario."
                    .to_string(),
            );
        }
        lineas
    }
}

impl fmt::Display for Exposicion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let campos: Vec<&str> = self.campos.iter().map(|c| c.nombre()).collect();
        write!(f, "{} [{}]", self.destino.nombre(), campos.join(", "))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn externo(j: Jurisdiccion, r: Retencion) -> Exposicion {
        Exposicion {
            destino: Destino::Externo {
                proveedor: "reputacion.example".into(),
                jurisdiccion: j,
                retencion: r,
            },
            campos: vec![Campo::ResumenDeFichero, Campo::IdentidadDelConsultante],
        }
    }

    #[test]
    fn una_exposicion_local_sin_campos_es_coherente() {
        assert!(Exposicion::ninguna().coherente().is_ok());
    }

    #[test]
    fn un_destino_local_que_declara_campos_es_un_fallo() {
        // O el destino esta mal o los campos lo estan. Las dos posibilidades son
        // un error, y se ve al registrar y no en la primera consulta de un
        // incidente a las tres de la mañana.
        let e = Exposicion {
            destino: Destino::Local,
            campos: vec![Campo::Dominio],
        };
        assert!(e.coherente().is_err());
    }

    #[test]
    fn un_destino_con_red_y_sin_campos_es_un_fallo() {
        // Algo sale, aunque solo sea el hecho de preguntar.
        let e = Exposicion {
            destino: Destino::Interno {
                servicio: "cmdb".into(),
            },
            campos: vec![],
        };
        assert!(e.coherente().is_err());
    }

    #[test]
    fn lo_local_no_necesita_red_y_lo_interno_si() {
        assert!(!Destino::Local.necesita_red());
        assert!(Destino::Interno {
            servicio: "cmdb".into()
        }
        .necesita_red());
        // Y lo interno NO sale de la organizacion aunque necesite red: son dos
        // preguntas distintas, y mezclarlas haria que un servicio propio se
        // tratara como un tercero o al reves.
        assert!(!Destino::Interno {
            servicio: "cmdb".into()
        }
        .sale_de_la_organizacion());
    }

    #[test]
    fn mandar_el_fichero_entero_exige_autorizacion_siempre() {
        // Aunque el proveedor sea nacional y no conserve nada: mandar el fichero
        // no es consultar, es entregar.
        let mut e = externo(Jurisdiccion::Nacional, Retencion::Ninguna);
        assert!(!e.exige_autorizacion());
        e.campos.push(Campo::ContenidoDeFichero);
        assert!(e.exige_autorizacion());
    }

    #[test]
    fn compartir_con_terceros_exige_autorizacion() {
        // Para una muestra de malware es deseable; para un documento interno es
        // una fuga con reparto. Lo decide una persona, no un valor por defecto.
        assert!(externo(Jurisdiccion::Eee, Retencion::IndefinidaYCompartida).exige_autorizacion());
    }

    #[test]
    fn una_jurisdiccion_sin_adecuacion_exige_autorizacion() {
        assert!(externo(Jurisdiccion::SinAdecuacion, Retencion::Ninguna).exige_autorizacion());
        assert!(!externo(Jurisdiccion::ConAdecuacion, Retencion::Ninguna).exige_autorizacion());
    }

    #[test]
    fn el_aviso_dice_que_revela_cada_campo_y_no_solo_su_nombre() {
        let e = externo(Jurisdiccion::Eee, Retencion::Indefinida);
        let aviso = e.aviso();
        let todo = aviso.join("\n");
        assert!(todo.contains("reputacion.example"));
        assert!(todo.contains("INDEFINIDAMENTE"));
        // Lo que importa no es que salga «resumen-de-fichero» sino que salga QUE
        // significa mandarlo. El nombre solo no informa a nadie.
        assert!(todo.contains("ese fichero exacto esta en tu red"));
        assert!(todo.contains("eres TU quien pregunta"));
    }

    #[test]
    fn el_aviso_de_lo_local_es_una_linea_y_no_enumera_nada() {
        assert_eq!(Exposicion::ninguna().aviso().len(), 1);
    }

    #[test]
    fn todo_campo_dice_que_revela() {
        for c in [
            Campo::ResumenDeFichero,
            Campo::ContenidoDeFichero,
            Campo::Dominio,
            Campo::DireccionIp,
            Campo::UrlCompleta,
            Campo::MetadatosDeFichero,
            Campo::MomentoDeObservacion,
            Campo::IdentidadDelConsultante,
        ] {
            assert!(c.revela().len() > 25, "{c:?} no explica que revela");
            assert!(!c.nombre().is_empty());
        }
    }

    #[test]
    fn el_aviso_avisa_de_que_hace_falta_autorizacion() {
        let e = externo(Jurisdiccion::SinAdecuacion, Retencion::Indefinida);
        assert!(e.aviso().iter().any(|l| l.contains("EXIGE autorizacion")));
    }
}
