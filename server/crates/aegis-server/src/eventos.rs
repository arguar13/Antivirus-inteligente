//! Bus de eventos del panel: lo que convierte la consola en tiempo real.
//!
//! # Por que un bus y no que el panel pregunte
//!
//! Un panel que sondea cada pocos segundos llega tarde a lo unico que importa:
//! la alerta critica. Y con una flota grande, ese sondeo multiplicado por cada
//! operador conectado se convierte en carga constante sobre la base de datos
//! para no descubrir nada la mayoria de las veces.
//!
//! Aqui el flujo se invierte: cuando algo pasa —una alerta, un endpoint que se
//! cae, una regla publicada— se publica en este bus y llega por WebSocket a
//! todas las consolas abiertas en el mismo instante.
//!
//! # Por que un canal de difusion con perdida
//!
//! `broadcast` descarta los mensajes mas viejos cuando un receptor se queda
//! atras, en vez de crecer sin limite. Es lo correcto AQUI: una consola lenta no
//! puede consumir la memoria del servidor, y lo que necesita no es el historico
//! completo —eso lo tiene en la base de datos— sino el estado actual. Cuando un
//! receptor pierde mensajes se le avisa y pide una instantanea.

use serde::Serialize;
use tokio::sync::broadcast;

/// Cuantos eventos se retienen para los receptores que van por detras.
///
/// Con 256 una consola puede quedarse casi un segundo entero congelada en una
/// tormenta de alertas sin perder nada; mas alla de eso, lo sano es que pida una
/// instantanea en vez de reproducir el pasado.
const CAPACIDAD: usize = 256;

/// Un suceso que el panel debe conocer al instante.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "tipo", rename_all = "snake_case")]
pub enum EventoPanel {
    /// Un agente se ha enrolado en la flota.
    AgenteEnrolado {
        /// Identidad autenticada.
        cn: String,
        /// Nombre de maquina.
        hostname: String,
    },
    /// Un agente ha latido: sirve para el mapa de topologia.
    Latido {
        /// Identidad autenticada.
        cn: String,
        /// Memoria residente reportada.
        rss_kb: i64,
        /// Amenazas activas reportadas.
        amenazas: i64,
    },
    /// Ha entrado una alerta de seguridad.
    AlertaNueva {
        /// Identificador del incidente.
        id: String,
        /// Agente que la reporto.
        cn: String,
        /// Severidad 0..4.
        severidad: i16,
        /// Categoria declarada.
        categoria: String,
        /// Descripcion legible.
        descripcion: String,
        /// Tecnica MITRE ATT&CK asignada.
        tecnica_mitre: Option<String>,
    },
    /// Un endpoint ha sido aislado o liberado.
    AislamientoCambiado {
        /// Identidad del endpoint.
        cn: String,
        /// Si queda aislado.
        aislado: bool,
        /// Operador que lo ordeno.
        por: String,
    },
    /// Una heuristica global ha encontrado una campana distribuida.
    ///
    /// Se publica SOLO cuando la correlacion se abre por primera vez, no en
    /// cada evaluacion. El motor evalua cada minuto; avisar en cada vuelta
    /// convertiria una campana de tres dias en cuatro mil avisos identicos, y
    /// una consola que avisa cuatro mil veces de lo mismo deja de mirarse.
    CorrelacionAbierta {
        /// Identificador de la correlacion.
        id: String,
        /// Regla que la produjo.
        regla: String,
        /// Patron legible ("Movimiento Lateral Distribuido").
        patron: String,
        /// Valor agrupado (la cuenta, el hash...).
        clave: String,
        /// Endpoints DISTINTOS implicados.
        endpoints: i32,
        /// Severidad heredada de la regla.
        severidad: i16,
        /// Tecnica MITRE ATT&CK.
        tecnica_mitre: Option<String>,
    },
    /// Se ha publicado una politica nueva.
    PoliticaPublicada {
        /// Version publicada.
        version: i64,
        /// Numero de reglas activas.
        reglas: usize,
    },
    /// Se ha lanzado una caceria AegisQL a la flota.
    CazaLanzada {
        /// Identificador de la caceria.
        caza_id: String,
        /// Consulta tal y como se escribio.
        consulta: String,
        /// Operador que la ordeno.
        por: String,
        /// Endpoints en linea al lanzarla: el denominador de la cobertura.
        objetivo: i64,
    },
    /// Un endpoint ha respondido a una caceria.
    ///
    /// Se publica por CADA respuesta y no solo al terminar. Una caceria sobre
    /// diez mil endpoints tarda; el analista tiene que ver llegar los hallazgos
    /// segun aparecen, no una barra de progreso.
    CazaRespuesta {
        /// Caceria a la que responde.
        caza_id: String,
        /// Endpoint que respondio.
        cn: String,
        /// Coincidencias que encontro.
        coincidencias: i64,
        /// Valores que no pudo leer.
        inaccesibles: i64,
        /// Si agoto su presupuesto de tiempo.
        agotado: bool,
        /// Error informado, si lo hubo.
        error: String,
    },
    /// Ha cambiado la cuarentena de enjambre.
    CuarentenaCambiada {
        /// Direccion afectada.
        direccion: String,
        /// Si queda aislada de la flota.
        activa: bool,
        /// Por que.
        motivo: String,
        /// Operador que lo ordeno.
        por: String,
    },
    /// Ha llegado inteligencia nueva.
    InteligenciaNueva {
        /// Agente que la entrego.
        cn: String,
        /// Objetos STIX ingeridos.
        objetos: u64,
    },
}

/// Bus de difusion de eventos del panel.
#[derive(Clone)]
pub struct BusEventos {
    emisor: broadcast::Sender<EventoPanel>,
}

impl Default for BusEventos {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl BusEventos {
    /// Crea el bus.
    pub fn nuevo() -> BusEventos {
        let (emisor, _) = broadcast::channel(CAPACIDAD);
        BusEventos { emisor }
    }

    /// Publica un evento.
    ///
    /// Que no haya ningun operador conectado no es un error: el evento
    /// simplemente no interesa a nadie ahora mismo, y su registro duradero esta
    /// en la base de datos.
    pub fn publicar(&self, evento: EventoPanel) {
        let _ = self.emisor.send(evento);
    }

    /// Abre un receptor para una consola.
    pub fn suscribir(&self) -> broadcast::Receiver<EventoPanel> {
        self.emisor.subscribe()
    }

    /// Numero de consolas conectadas.
    pub fn consolas(&self) -> usize {
        self.emisor.receiver_count()
    }
}
