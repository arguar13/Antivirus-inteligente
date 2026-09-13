//! El esquema comun: un contrato, no una estructura.
//!
//! # Por que OCSF y no ECS
//!
//! La eleccion se justifica aqui porque es la decision mas cara de deshacer de
//! toda la fase: cambiar el esquema despues no es una edicion, es una migracion
//! de todo lo que un cliente tenga almacenado.
//!
//! **ECS** (Elastic Common Schema) es mas maduro, tiene un vocabulario enorme y
//! lo entiende cualquier SIEM. Su fuerza es la amplitud: hay un campo para casi
//! todo.
//!
//! **OCSF** (Open Cybersecurity Schema Framework) es mas nuevo y mas estrecho, y
//! **esa estrechez es justamente la razon para elegirlo**: su taxonomia esta
//! ENUMERADA. Una actividad es un identificador de una lista cerrada, no una
//! cadena libre. Eso tiene dos consecuencias que a un EDR le importan mas que la
//! amplitud:
//!
//! 1. **La normalizacion se puede comprobar.** Un campo o encaja en una clase
//!    conocida o no encaja, y cuando no encaja se rechaza CON NOMBRE en vez de
//!    guardarse como texto libre que nadie volvera a consultar. Con un
//!    vocabulario abierto no existe la nocion de «esto no se supo normalizar»,
//!    asi que tampoco existe la cifra de cobertura.
//! 2. **La correlacion es determinista.** Dos registros de origenes distintos que
//!    describen el mismo hecho —un inicio de sesion fallido en syslog y en
//!    EVTX— caen en el mismo identificador de actividad, y se pueden contar
//!    juntos sin una tabla de equivalencias que alguien tiene que mantener.
//!
//! Lo que se pierde es real y se dice: hay campos de ECS que aqui no tienen
//! sitio, y acaban en [`Evento::campos`] como extension. No se tiran.
//!
//! # La version del esquema es parte del contrato
//!
//! [`VERSION`] sube cuando cambia el significado de un campo, no cuando se anade
//! uno. Un evento de una version que no se conoce **no se interpreta**: leerlo
//! mal produciria correlaciones silenciosamente equivocadas, que es peor que no
//! tenerlas.
//!
//! # La hora tiene dos campos y una confianza, y eso es el corazon del modulo
//!
//! Un endpoint que estuvo apagado un dia entrega su lote entero al reconectar.
//! Si los eventos se ordenaran por **llegada**, un ataque repartido en dos dias
//! pareceria un pico de un segundo, y todas las heuristicas de ritmo lo leerian
//! al reves. Se ordena por **ocurrencia**.
//!
//! Pero la hora de ocurrencia sale del registro, y el registro lo escribe
//! cualquiera. Un atacante que quiera esconderse en el pasado solo tiene que
//! fechar sus lineas en 2019. Por eso no basta con tener el campo: hace falta
//! [`ConfianzaReloj`], que dice **de donde salio esa hora**, y una comprobacion
//! de verosimilitud que marque lo que no cuadra en vez de creerselo.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version del esquema.
///
/// Sube cuando cambia el **significado** de un campo. Anadir un campo nuevo no
/// la sube: quien lea con la version anterior lo ignorara, que es el
/// comportamiento correcto.
pub const VERSION: u32 = 1;

/// Bytes maximos del mensaje normalizado.
pub const MAX_MENSAJE: usize = 16 * 1024;

/// Bytes maximos del registro crudo que se conserva.
///
/// El crudo se guarda porque es la evidencia: si la normalizacion se equivoco,
/// es lo unico que permite verlo despues. Pero lo escribe el atacante, asi que
/// tiene tope como todo lo demas.
pub const MAX_CRUDO: usize = 64 * 1024;

/// Campos de extension maximos por evento.
pub const MAX_CAMPOS: usize = 128;

/// Bytes maximos de una clave o un valor de extension.
pub const MAX_CAMPO: usize = 4096;

/// De donde salio la hora de ocurrencia de un evento.
///
/// Es un campo de primera clase y no un detalle: decide si el evento se puede
/// usar para razonar sobre el orden de los hechos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfianzaReloj {
    /// El registro traia una marca de tiempo y es verosimil.
    DelOrigen,
    /// El registro traia marca, pero no cuadra con cuando se leyo.
    ///
    /// Puede ser un lote legitimo de un endpoint que estuvo apagado, o puede ser
    /// un atacante fechando sus lineas en el pasado para esconderse debajo de una
    /// ventana de correlacion. **El esquema no decide cual**: lo marca, conserva
    /// las dos horas, y deja que quien correlaciona lo vea.
    Sospechosa,
    /// El registro no traia hora y se uso la de lectura.
    ///
    /// Ordenar por esto es ordenar por llegada, con todo lo que eso arruina. Se
    /// marca para que una correlacion que dependa del orden sepa que aqui no
    /// puede fiarse.
    DeLlegada,
}

impl ConfianzaReloj {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            ConfianzaReloj::DelOrigen => "del-origen",
            ConfianzaReloj::Sospechosa => "sospechosa",
            ConfianzaReloj::DeLlegada => "de-llegada",
        }
    }

    /// Si se puede razonar sobre el orden de los hechos con esta hora.
    #[must_use]
    pub fn sirve_para_ordenar(self) -> bool {
        self != ConfianzaReloj::DeLlegada
    }
}

/// Margen hacia el futuro antes de considerar la hora sospechosa.
///
/// Cinco minutos: lo que un reloj mal sincronizado se adelanta de forma normal.
/// Mas que eso no es desviacion, es una marca puesta a mano.
pub const MARGEN_FUTURO_NS: u64 = 5 * 60 * 1_000_000_000;

/// Margen hacia el pasado antes de considerar la hora sospechosa.
///
/// Dos dias. Un endpoint apagado un fin de semana entrega su lote con horas de
/// hasta tres dias atras, y eso es legitimo y frecuente; por eso el margen es
/// generoso y por eso la marca es «sospechosa» y no «rechazada». Lo que NO puede
/// pasar es que una linea fechada hace dos anos entre como si nada.
pub const MARGEN_PASADO_NS: u64 = 2 * 24 * 60 * 60 * 1_000_000_000;

/// Categoria de alto nivel, segun OCSF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Categoria {
    /// Actividad del sistema: procesos, ficheros, kernel.
    Sistema,
    /// Hallazgos de seguridad.
    Hallazgo,
    /// Identidad y acceso.
    Identidad,
    /// Actividad de red.
    Red,
    /// Aplicaciones.
    Aplicacion,
    /// Descubrimiento e inventario.
    Descubrimiento,
}

impl Categoria {
    /// Identificador de categoria de OCSF.
    #[must_use]
    pub fn uid(self) -> u16 {
        match self {
            Categoria::Sistema => 1,
            Categoria::Hallazgo => 2,
            Categoria::Identidad => 3,
            Categoria::Red => 4,
            Categoria::Descubrimiento => 5,
            Categoria::Aplicacion => 6,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Categoria::Sistema => "sistema",
            Categoria::Hallazgo => "hallazgo",
            Categoria::Identidad => "identidad",
            Categoria::Red => "red",
            Categoria::Aplicacion => "aplicacion",
            Categoria::Descubrimiento => "descubrimiento",
        }
    }
}

/// Clase de evento: lo que de verdad paso.
///
/// La lista es **cerrada** a proposito. Lo que no encaja se rechaza con nombre y
/// se cuenta, y de ahi sale la cifra de cobertura de la normalizacion. Con una
/// cadena libre no existiria esa cifra, y nadie sabria que parte de los registros
/// se esta perdiendo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Clase {
    /// Se creo, ejecuto o termino un proceso.
    ActividadDeProceso,
    /// Se toco un fichero.
    ActividadDeFichero,
    /// Se toco el registro o la configuracion del sistema.
    ActividadDeConfiguracion,
    /// Se inicio o cerro una sesion.
    Autenticacion,
    /// Cambio en cuentas, grupos o privilegios.
    GestionDeCuentas,
    /// Conexion de red.
    ActividadDeRed,
    /// Consulta DNS.
    ActividadDns,
    /// Peticion HTTP.
    ActividadHttp,
    /// Se instalo, arranco o paro un servicio.
    ActividadDeServicio,
    /// Actividad de un plano de control en la nube.
    ApiDeNube,
    /// Hallazgo de seguridad de otra herramienta.
    HallazgoDeSeguridad,
    /// El sistema dice algo de si mismo que no encaja en lo anterior.
    ActividadDelSistema,
}

impl Clase {
    /// Identificador de clase de OCSF.
    #[must_use]
    pub fn uid(self) -> u32 {
        match self {
            Clase::ActividadDeFichero => 1001,
            Clase::ActividadDeProceso => 1007,
            Clase::ActividadDeConfiguracion => 1008,
            Clase::ActividadDelSistema => 1000,
            Clase::HallazgoDeSeguridad => 2001,
            Clase::Autenticacion => 3002,
            Clase::GestionDeCuentas => 3001,
            Clase::ActividadDeRed => 4001,
            Clase::ActividadDns => 4003,
            Clase::ActividadHttp => 4002,
            Clase::ActividadDeServicio => 1009,
            Clase::ApiDeNube => 6003,
        }
    }

    /// La categoria a la que pertenece.
    #[must_use]
    pub fn categoria(self) -> Categoria {
        match self {
            Clase::ActividadDeProceso
            | Clase::ActividadDeFichero
            | Clase::ActividadDeConfiguracion
            | Clase::ActividadDeServicio
            | Clase::ActividadDelSistema => Categoria::Sistema,
            Clase::HallazgoDeSeguridad => Categoria::Hallazgo,
            Clase::Autenticacion | Clase::GestionDeCuentas => Categoria::Identidad,
            Clase::ActividadDeRed | Clase::ActividadDns | Clase::ActividadHttp => Categoria::Red,
            Clase::ApiDeNube => Categoria::Aplicacion,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Clase::ActividadDeProceso => "actividad-de-proceso",
            Clase::ActividadDeFichero => "actividad-de-fichero",
            Clase::ActividadDeConfiguracion => "actividad-de-configuracion",
            Clase::Autenticacion => "autenticacion",
            Clase::GestionDeCuentas => "gestion-de-cuentas",
            Clase::ActividadDeRed => "actividad-de-red",
            Clase::ActividadDns => "actividad-dns",
            Clase::ActividadHttp => "actividad-http",
            Clase::ActividadDeServicio => "actividad-de-servicio",
            Clase::ApiDeNube => "api-de-nube",
            Clase::HallazgoDeSeguridad => "hallazgo-de-seguridad",
            Clase::ActividadDelSistema => "actividad-del-sistema",
        }
    }
}

/// Como acabo lo que el evento describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Resultado {
    /// Salio bien.
    Exito,
    /// Salio mal.
    Fallo,
    /// El registro no lo dice.
    ///
    /// Existe porque inventarlo seria peor: un inicio de sesion cuyo resultado no
    /// consta NO es un inicio de sesion correcto.
    Desconocido,
}

impl Resultado {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Resultado::Exito => "exito",
            Resultado::Fallo => "fallo",
            Resultado::Desconocido => "desconocido",
        }
    }
}

/// Gravedad, con la escala de OCSF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// Identificador de OCSF.
    #[must_use]
    pub fn uid(self) -> u8 {
        match self {
            Severidad::Info => 1,
            Severidad::Baja => 2,
            Severidad::Media => 3,
            Severidad::Alta => 4,
            Severidad::Critica => 5,
        }
    }

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

/// De donde se leyo el registro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Origen {
    /// syslog RFC 5424.
    Syslog5424,
    /// syslog RFC 3164, el formato viejo.
    Syslog3164,
    /// Diario binario de systemd.
    Journald,
    /// Registro de eventos de Windows.
    Evtx,
    /// Fichero de log plano.
    Fichero,
    /// Plano de control de nube.
    Nube,
    /// Telemetria del propio agente.
    Agente,
}

impl Origen {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Origen::Syslog5424 => "syslog-5424",
            Origen::Syslog3164 => "syslog-3164",
            Origen::Journald => "journald",
            Origen::Evtx => "evtx",
            Origen::Fichero => "fichero",
            Origen::Nube => "nube",
            Origen::Agente => "agente",
        }
    }

    /// Prioridad con la que se conserva bajo presion.
    ///
    /// La telemetria del propio agente y los hallazgos de seguridad van antes que
    /// el log de una aplicacion: cuando hay que tirar algo, se tira lo que menos
    /// cuesta perder, y eso es una decision de seguridad, no de implementacion.
    #[must_use]
    pub fn prioridad(self) -> Prioridad {
        match self {
            Origen::Agente | Origen::Evtx => Prioridad::Seguridad,
            Origen::Journald | Origen::Syslog5424 | Origen::Syslog3164 => Prioridad::Sistema,
            Origen::Fichero | Origen::Nube => Prioridad::Aplicacion,
        }
    }
}

/// Que se conserva primero cuando no cabe todo.
///
/// El orden importa y esta al reves de lo intuitivo: `Seguridad` es el valor
/// **mayor** para que un `max` o un `sort` conserven lo que mas vale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Prioridad {
    /// Log de aplicacion. Es lo primero que se tira.
    Aplicacion,
    /// Log del sistema operativo.
    Sistema,
    /// Telemetria de seguridad. Es lo ultimo que se tira.
    Seguridad,
}

impl Prioridad {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Prioridad::Aplicacion => "aplicacion",
            Prioridad::Sistema => "sistema",
            Prioridad::Seguridad => "seguridad",
        }
    }
}

/// Un valor de extension.
///
/// Deliberadamente pobre: texto, entero o booleano. Sin anidamiento y sin listas,
/// porque un valor anidado sin tope de profundidad es la forma clasica de tumbar
/// un analizador con entrada hostil, y porque lo que no cabe aqui es senal de que
/// falta una clase en el esquema, no de que falte expresividad.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Valor {
    /// Cadena.
    Texto(String),
    /// Entero.
    Entero(i64),
    /// Booleano.
    Booleano(bool),
}

impl Valor {
    /// Representacion en texto, para el informe y la huella.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Valor::Texto(s) => s.clone(),
            Valor::Entero(n) => n.to_string(),
            Valor::Booleano(b) => b.to_string(),
        }
    }
}

/// Un evento normalizado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evento {
    /// Version del esquema con la que se produjo.
    pub version: u32,
    /// Identificador estable, para desduplicar.
    ///
    /// Se deriva del contenido y del ancla, no de un contador: la entrega es
    /// **al menos una vez**, asi que el mismo registro puede llegar dos veces
    /// por caminos distintos, y solo un identificador derivado de lo que el
    /// registro ES los une. Ver [`derivar_id`].
    pub id: String,
    /// De donde salio exactamente este registro dentro de su origen.
    ///
    /// # Sin esto la deduplicacion destruye evidencia
    ///
    /// Deducir el identificador solo del contenido parece limpio hasta que se
    /// mira lo que pasa con un ataque de fuerza bruta: veinte intentos de
    /// contrasena fallidos del mismo usuario, en el mismo segundo, contra el
    /// mismo servicio, producen **veinte lineas identicas byte a byte** —RFC
    /// 3164 fecha con resolucion de segundo—. Un identificador de solo contenido
    /// las fundiria en una, y la deteccion de fuerza bruta veria un intento
    /// aislado donde hubo veinte. La deduplicacion habria borrado justo la senal
    /// que importaba.
    ///
    /// El ancla es lo que distingue «el mismo registro entregado dos veces» de
    /// «dos registros que dicen lo mismo»: el desplazamiento en el fichero, el
    /// cursor del diario, el numero de registro de EVTX, la posicion en el
    /// flujo. Dos entregas del mismo registro comparten ancla; dos hechos
    /// distintos, no.
    pub ancla: String,
    /// Cuando ocurrio, en nanosegundos desde la epoca Unix.
    pub ocurrio_ns: u64,
    /// Cuando se leyo.
    ///
    /// Se conserva SIEMPRE, incluso cuando la ocurrencia es fiable: la distancia
    /// entre las dos es en si misma un dato —dice cuanto tardo en llegar— y es lo
    /// unico que permite auditar despues si una hora de ocurrencia era creible.
    pub observado_ns: u64,
    /// De donde salio la hora de ocurrencia.
    pub reloj: ConfianzaReloj,
    /// Que clase de hecho es.
    pub clase: Clase,
    /// Como acabo.
    pub resultado: Resultado,
    /// Gravedad.
    pub severidad: Severidad,
    /// De donde se leyo.
    pub origen: Origen,
    /// Maquina de la que viene.
    pub anfitrion: String,
    /// Inquilino al que pertenece.
    ///
    /// Va en el evento y no en el transporte: un evento que pierde su inquilino
    /// por el camino es un evento que puede acabar en el panel de otro cliente.
    pub inquilino: String,
    /// Quien lo produjo: servicio, programa o unidad.
    pub productor: String,
    /// Mensaje legible.
    pub mensaje: String,
    /// Campos que no encajan en el esquema, conservados.
    pub campos: BTreeMap<String, Valor>,
    /// El registro tal y como llego, si se conserva.
    pub crudo: Option<Vec<u8>>,
}

impl Evento {
    /// Categoria, derivada de la clase.
    #[must_use]
    pub fn categoria(&self) -> Categoria {
        self.clase.categoria()
    }

    /// Recalcula [`Evento::id`] a partir del resto del evento.
    ///
    /// Lo llama todo analizador justo antes de entregar: el identificador es una
    /// funcion del evento, no un campo que se rellena aparte. Dejarlo a cargo de
    /// cada analizador garantizaria que alguno se olvidara de algun campo, y el
    /// sintoma —eventos distintos con el mismo identificador— aparece meses
    /// despues y en el plano de control, no aqui.
    pub fn sellar(&mut self) {
        self.id = derivar_id(
            &self.ancla,
            self.ocurrio_ns,
            self.clase,
            self.resultado,
            self.severidad,
            self.origen,
            &self.anfitrion,
            &self.inquilino,
            &self.productor,
            &self.mensaje,
            &self.campos,
        );
    }

    /// Comprueba que el identificador corresponde al contenido.
    ///
    /// El plano de control lo usa como control de integridad barato: un evento
    /// cuyo identificador no cuadra con su contenido ha sido manipulado por el
    /// camino, o lo produjo una version del esquema que no es esta.
    #[must_use]
    pub fn sello_valido(&self) -> bool {
        let esperado = derivar_id(
            &self.ancla,
            self.ocurrio_ns,
            self.clase,
            self.resultado,
            self.severidad,
            self.origen,
            &self.anfitrion,
            &self.inquilino,
            &self.productor,
            &self.mensaje,
            &self.campos,
        );
        esperado == self.id
    }

    /// Prioridad con la que se conserva bajo presion.
    ///
    /// Un hallazgo de seguridad se conserva como tal venga de donde venga: si un
    /// fichero de log trae la deteccion de otra herramienta, eso vale mas que el
    /// resto de ese mismo fichero.
    #[must_use]
    pub fn prioridad(&self) -> Prioridad {
        if self.clase == Clase::HallazgoDeSeguridad || self.severidad >= Severidad::Alta {
            return Prioridad::Seguridad;
        }
        self.origen.prioridad()
    }

    /// Cuanto tardo en llegar, en nanosegundos.
    ///
    /// Negativo se aplasta a cero: un evento del futuro no ha tardado menos que
    /// nada, y dejar que el retraso saliera negativo estropearia cualquier
    /// estadistica que lo promedie.
    #[must_use]
    pub fn retraso_ns(&self) -> u64 {
        self.observado_ns.saturating_sub(self.ocurrio_ns)
    }

    /// Tamano aproximado en memoria, para las cotas de la cola.
    #[must_use]
    pub fn bytes(&self) -> usize {
        let campos: usize = self
            .campos
            .iter()
            .map(|(k, v)| k.len() + v.texto().len() + 32)
            .sum();
        self.id.len()
            + self.anfitrion.len()
            + self.inquilino.len()
            + self.productor.len()
            + self.mensaje.len()
            + campos
            + self.crudo.as_ref().map_or(0, Vec::len)
            + 128
    }
}

/// Deriva el identificador de deduplicacion de un evento.
///
/// # Que entra y que NO entra, y por que
///
/// Entra todo lo que hace que un registro sea ESE registro: el ancla, la hora de
/// ocurrencia, la taxonomia, la maquina, el inquilino, el productor, el mensaje
/// y los campos de extension.
///
/// **No entra [`Evento::observado_ns`]**, y es la decision que hace que esto
/// funcione: la hora de lectura cambia en cada entrega. Si entrara, el mismo
/// registro reenviado tras un reinicio —que es exactamente lo que la entrega
/// al-menos-una-vez garantiza que va a pasar— produciria un identificador nuevo
/// y la deduplicacion no desduplicaria nada.
///
/// **Tampoco entra [`Evento::crudo`]**: es el mismo texto del que salio el resto
/// y meterlo solo duplicaria el coste del resumen.
///
/// Los campos se separan con un byte que no puede aparecer dentro de ninguno de
/// ellos (`0x1F`, separador de unidad) para que dos repartos distintos del mismo
/// texto no colisionen: sin separador, `("ab", "c")` y `("a", "bc")` darian el
/// mismo resumen.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn derivar_id(
    ancla: &str,
    ocurrio_ns: u64,
    clase: Clase,
    resultado: Resultado,
    severidad: Severidad,
    origen: Origen,
    anfitrion: &str,
    inquilino: &str,
    productor: &str,
    mensaje: &str,
    campos: &BTreeMap<String, Valor>,
) -> String {
    const SEP: &[u8] = &[0x1F];
    let mut h = Sha256::new();
    h.update(VERSION.to_be_bytes());
    h.update(SEP);
    h.update(ancla.as_bytes());
    h.update(SEP);
    h.update(ocurrio_ns.to_be_bytes());
    h.update(SEP);
    h.update(clase.uid().to_be_bytes());
    h.update(SEP);
    h.update(resultado.nombre().as_bytes());
    h.update(SEP);
    h.update(severidad.uid().to_be_bytes());
    h.update(SEP);
    h.update(origen.nombre().as_bytes());
    h.update(SEP);
    h.update(anfitrion.as_bytes());
    h.update(SEP);
    h.update(inquilino.as_bytes());
    h.update(SEP);
    h.update(productor.as_bytes());
    h.update(SEP);
    h.update(mensaje.as_bytes());
    // El BTreeMap recorre en orden de clave, asi que el resumen no depende del
    // orden en que el analizador encontrara los campos. Con un mapa desordenado
    // el mismo registro daria identificadores distintos en cada ejecucion y la
    // deduplicacion no serviria para nada.
    for (k, v) in campos {
        h.update(SEP);
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.texto().as_bytes());
    }
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decide la confianza de una hora comparandola con cuando se leyo.
///
/// # Por que no se rechaza lo que no cuadra
///
/// La tentacion es descartar una linea fechada hace dos anos. Seria un error: un
/// endpoint apagado tres dias entrega un lote legitimo con horas viejas, y
/// rechazarlo perderia justo la evidencia del rato en que nadie miraba.
///
/// Y la tentacion contraria —aceptarla sin mas— regala al atacante la forma mas
/// barata de esconderse: fechar sus lineas fuera de cualquier ventana de
/// correlacion.
///
/// La salida es no decidir aqui: se **marca**, se conservan las dos horas, y
/// quien correlaciona lo ve.
#[must_use]
pub fn confianza(ocurrio_ns: Option<u64>, observado_ns: u64) -> (u64, ConfianzaReloj) {
    let Some(o) = ocurrio_ns else {
        return (observado_ns, ConfianzaReloj::DeLlegada);
    };
    if o > observado_ns.saturating_add(MARGEN_FUTURO_NS) {
        return (o, ConfianzaReloj::Sospechosa);
    }
    if observado_ns.saturating_sub(o) > MARGEN_PASADO_NS {
        return (o, ConfianzaReloj::Sospechosa);
    }
    (o, ConfianzaReloj::DelOrigen)
}

/// Recorta una cadena al tope respetando las fronteras de caracter.
#[must_use]
pub fn recortar(s: &str, tope: usize) -> String {
    if s.len() <= tope {
        return s.to_string();
    }
    let mut n = tope;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    // --- La taxonomia es cerrada y coherente -------------------------------

    #[test]
    fn cada_clase_tiene_su_categoria_y_su_identificador() {
        // La taxonomia cerrada es lo que hace que la normalizacion se pueda
        // comprobar: una clase o esta o no esta.
        let todas = [
            Clase::ActividadDeProceso,
            Clase::ActividadDeFichero,
            Clase::ActividadDeConfiguracion,
            Clase::Autenticacion,
            Clase::GestionDeCuentas,
            Clase::ActividadDeRed,
            Clase::ActividadDns,
            Clase::ActividadHttp,
            Clase::ActividadDeServicio,
            Clase::ApiDeNube,
            Clase::HallazgoDeSeguridad,
            Clase::ActividadDelSistema,
        ];
        let mut uids = std::collections::BTreeSet::new();
        for c in todas {
            assert!(!c.nombre().is_empty());
            assert!(c.uid() > 0);
            assert!(uids.insert(c.uid()), "uid repetido en {}", c.nombre());
            assert!(c.categoria().uid() > 0);
        }
        assert_eq!(uids.len(), todas.len());
    }

    #[test]
    fn la_autenticacion_y_las_cuentas_caen_en_identidad() {
        // Es lo que permite contar juntos un inicio de sesion de syslog y otro de
        // EVTX sin una tabla de equivalencias que alguien tenga que mantener.
        assert_eq!(Clase::Autenticacion.categoria(), Categoria::Identidad);
        assert_eq!(Clase::GestionDeCuentas.categoria(), Categoria::Identidad);
        assert_eq!(Clase::ActividadDns.categoria(), Categoria::Red);
    }

    // --- El reloj: el corazon del modulo -----------------------------------

    #[test]
    fn una_hora_normal_es_del_origen() {
        let (o, c) = confianza(Some(AHORA - 2 * SEG), AHORA);
        assert_eq!(o, AHORA - 2 * SEG);
        assert_eq!(c, ConfianzaReloj::DelOrigen);
        assert!(c.sirve_para_ordenar());
    }

    #[test]
    fn un_lote_de_un_endpoint_apagado_el_fin_de_semana_sigue_valiendo() {
        // Tres dias de retraso es legitimo y frecuente. Rechazarlo perderia justo
        // la evidencia del rato en que nadie miraba... pero dos dias es el limite
        // que separa «estuvo apagado» de «alguien puso la fecha a mano».
        let (_, c) = confianza(Some(AHORA - 36 * 3600 * SEG), AHORA);
        assert_eq!(c, ConfianzaReloj::DelOrigen, "dia y medio es normal");

        let (_, c) = confianza(Some(AHORA - 5 * 24 * 3600 * SEG), AHORA);
        assert_eq!(c, ConfianzaReloj::Sospechosa, "cinco dias ya no lo es");
    }

    #[test]
    fn una_linea_fechada_hace_dos_anos_se_marca_pero_no_se_tira() {
        // Marcarla en vez de tirarla: tirarla perderia evidencia si fuera
        // legitima, y creersela le regalaria al atacante la forma mas barata de
        // esconderse debajo de cualquier ventana de correlacion.
        let (o, c) = confianza(Some(AHORA - 2 * 365 * 24 * 3600 * SEG), AHORA);
        assert_eq!(c, ConfianzaReloj::Sospechosa);
        assert_eq!(o, AHORA - 2 * 365 * 24 * 3600 * SEG, "la hora se conserva");
        assert!(c.sirve_para_ordenar(), "sigue sirviendo, pero marcada");
    }

    #[test]
    fn una_hora_del_futuro_tambien_es_sospechosa() {
        // Un reloj desincronizado se adelanta minutos, no horas.
        let (_, c) = confianza(Some(AHORA + 60 * SEG), AHORA);
        assert_eq!(
            c,
            ConfianzaReloj::DelOrigen,
            "un minuto es desviacion normal"
        );

        let (_, c) = confianza(Some(AHORA + 3600 * SEG), AHORA);
        assert_eq!(
            c,
            ConfianzaReloj::Sospechosa,
            "una hora es una marca puesta a mano"
        );
    }

    #[test]
    fn sin_hora_en_el_registro_se_usa_la_de_llegada_y_se_dice() {
        // Ordenar por llegada arruina cualquier razonamiento sobre el ritmo de un
        // ataque, asi que quien lo haga tiene que saber que lo esta haciendo.
        let (o, c) = confianza(None, AHORA);
        assert_eq!(o, AHORA);
        assert_eq!(c, ConfianzaReloj::DeLlegada);
        assert!(!c.sirve_para_ordenar());
    }

    #[test]
    fn el_retraso_nunca_sale_negativo() {
        let e = evento_de_prueba(AHORA + 10 * SEG, AHORA);
        assert_eq!(
            e.retraso_ns(),
            0,
            "un evento del futuro no tarda menos que nada"
        );
    }

    // --- La prioridad decide que se conserva --------------------------------

    fn evento_de_prueba(ocurrio: u64, observado: u64) -> Evento {
        Evento {
            version: VERSION,
            id: "abc".into(),
            ancla: "fichero:/var/log/x@0".into(),
            ocurrio_ns: ocurrio,
            observado_ns: observado,
            reloj: ConfianzaReloj::DelOrigen,
            clase: Clase::ActividadDelSistema,
            resultado: Resultado::Desconocido,
            severidad: Severidad::Info,
            origen: Origen::Fichero,
            anfitrion: "maquina".into(),
            inquilino: "cliente".into(),
            productor: "prog".into(),
            mensaje: "algo".into(),
            campos: BTreeMap::new(),
            crudo: None,
        }
    }

    #[test]
    fn la_telemetria_de_seguridad_se_conserva_antes_que_el_log_de_aplicacion() {
        // Cuando hay que tirar algo, se tira lo que menos cuesta perder. Es una
        // decision de seguridad, no de implementacion.
        assert!(Prioridad::Seguridad > Prioridad::Sistema);
        assert!(Prioridad::Sistema > Prioridad::Aplicacion);
        assert_eq!(Origen::Agente.prioridad(), Prioridad::Seguridad);
        assert_eq!(Origen::Fichero.prioridad(), Prioridad::Aplicacion);
    }

    #[test]
    fn un_hallazgo_de_seguridad_vale_como_tal_venga_de_donde_venga() {
        // Si un fichero de log trae la deteccion de otra herramienta, eso vale
        // mas que el resto de ese mismo fichero.
        let mut e = evento_de_prueba(AHORA, AHORA);
        assert_eq!(e.prioridad(), Prioridad::Aplicacion);
        e.clase = Clase::HallazgoDeSeguridad;
        assert_eq!(e.prioridad(), Prioridad::Seguridad);
    }

    #[test]
    fn la_severidad_alta_sube_la_prioridad_aunque_el_origen_sea_humilde() {
        let mut e = evento_de_prueba(AHORA, AHORA);
        e.severidad = Severidad::Critica;
        assert_eq!(e.prioridad(), Prioridad::Seguridad);
    }

    // --- Los topes ----------------------------------------------------------

    #[test]
    fn recortar_no_parte_un_caracter_multibyte() {
        // El mensaje lo escribe el atacante: puede elegir dónde caen los bytes.
        let s = "ñ".repeat(100);
        let r = recortar(&s, 51);
        assert!(r.len() <= 51);
        assert!(s.starts_with(&r));
    }

    #[test]
    fn recortar_deja_intacto_lo_que_cabe() {
        assert_eq!(recortar("corto", 100), "corto");
        assert_eq!(recortar("", 10), "");
    }

    #[test]
    fn el_tamano_de_un_evento_se_puede_medir_para_acotar_la_cola() {
        let mut e = evento_de_prueba(AHORA, AHORA);
        let base = e.bytes();
        let mensaje_viejo = e.mensaje.len();
        e.mensaje = "x".repeat(1000);
        // El mensaje se SUSTITUYE: lo que crece es la diferencia.
        assert_eq!(e.bytes(), base - mensaje_viejo + 1000);
        e.crudo = Some(vec![0u8; 5000]);
        assert_eq!(e.bytes(), base - mensaje_viejo + 1000 + 5000);
    }

    // --- El contrato --------------------------------------------------------

    #[test]
    fn un_evento_va_y_vuelve_por_json_sin_perder_nada() {
        let mut e = evento_de_prueba(AHORA, AHORA);
        e.campos
            .insert("usuario".into(), Valor::Texto("administrador".into()));
        e.campos.insert("puerto".into(), Valor::Entero(22));
        e.campos.insert("exito".into(), Valor::Booleano(false));

        let texto = serde_json::to_string(&e).unwrap();
        let vuelta: Evento = serde_json::from_str(&texto).unwrap();
        assert_eq!(vuelta, e);
    }

    // --- El sello: la deduplicacion correcta --------------------------------

    #[test]
    fn el_mismo_registro_reentregado_da_el_mismo_identificador() {
        // Es lo unico que hace que la entrega al-menos-una-vez sea utilizable:
        // tras un reinicio se reenvia lo que no se confirmo, y si el
        // identificador cambiara la deduplicacion no desduplicaria nada.
        let mut a = evento_de_prueba(AHORA, AHORA);
        let mut b = evento_de_prueba(AHORA, AHORA + 9_999 * SEG); // se leyo mucho despues
        a.sellar();
        b.sellar();
        assert_eq!(a.id, b.id, "la hora de LECTURA no puede entrar en el sello");
        assert!(a.sello_valido());
    }

    #[test]
    fn veinte_intentos_de_contrasena_identicos_siguen_siendo_veinte() {
        // EL CASO QUE UNA DEDUPLICACION INGENUA DESTRUYE. Veinte fallos de
        // autenticacion del mismo usuario en el mismo segundo contra el mismo
        // servicio son veinte lineas identicas byte a byte: RFC 3164 fecha con
        // resolucion de segundo. Sin ancla se funden en una, y la deteccion de
        // fuerza bruta ve un intento aislado donde hubo veinte.
        let mut ids = std::collections::BTreeSet::new();
        for intento in 0..20u32 {
            let mut e = evento_de_prueba(AHORA, AHORA);
            e.clase = Clase::Autenticacion;
            e.resultado = Resultado::Fallo;
            e.mensaje = "Failed password for root from 10.0.0.9 port 22 ssh2".into();
            // Mismo contenido, distinto sitio en el fichero.
            e.ancla = format!("fichero:/var/log/auth.log@{}", intento * 64);
            e.sellar();
            assert!(ids.insert(e.id.clone()), "intento {intento} se fundio");
        }
        assert_eq!(ids.len(), 20);
    }

    #[test]
    fn dos_campos_repartidos_distinto_no_colisionan() {
        // Sin separador entre campos, («ab», «c») y («a», «bc») darian el mismo
        // resumen y dos eventos distintos se desduplicarian en uno.
        let mut a = evento_de_prueba(AHORA, AHORA);
        a.anfitrion = "ab".into();
        a.inquilino = "c".into();
        a.sellar();
        let mut b = evento_de_prueba(AHORA, AHORA);
        b.anfitrion = "a".into();
        b.inquilino = "bc".into();
        b.sellar();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn el_orden_en_que_se_encuentran_los_campos_no_cambia_el_sello() {
        // Determinismo: el mismo registro crudo produce el mismo evento
        // normalizado, insercion a insercion.
        let mut a = evento_de_prueba(AHORA, AHORA);
        a.campos.insert("z".into(), Valor::Entero(1));
        a.campos.insert("a".into(), Valor::Texto("x".into()));
        a.sellar();
        let mut b = evento_de_prueba(AHORA, AHORA);
        b.campos.insert("a".into(), Valor::Texto("x".into()));
        b.campos.insert("z".into(), Valor::Entero(1));
        b.sellar();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn tocar_cualquier_campo_significativo_invalida_el_sello() {
        // Es el control de integridad barato del plano de control: un evento
        // manipulado por el camino deja de cuadrar.
        let mut e = evento_de_prueba(AHORA, AHORA);
        e.sellar();
        assert!(e.sello_valido());
        e.mensaje.push('!');
        assert!(!e.sello_valido());
    }

    #[test]
    fn el_sello_es_un_resumen_hexadecimal_completo() {
        let mut e = evento_de_prueba(AHORA, AHORA);
        e.sellar();
        assert_eq!(e.id.len(), 64);
        assert!(e.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn el_inquilino_va_dentro_del_evento_y_no_en_el_transporte() {
        // Un evento que pierde su inquilino por el camino es un evento que puede
        // acabar en el panel de otro cliente.
        let e = evento_de_prueba(AHORA, AHORA);
        assert!(!e.inquilino.is_empty());
        let texto = serde_json::to_string(&e).unwrap();
        assert!(texto.contains("inquilino"), "{texto}");
    }
}
