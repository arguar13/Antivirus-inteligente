//! El enlace de un agente con el plano de control: cola acotada, reintento y
//! reconciliacion (H-23, E6.5 del MP-16).
//!
//! # El problema
//!
//! El agente produce veredictos a su ritmo y el plano de control esta a veces,
//! no siempre: se reinicia, se corta la red, la base de datos se cae. Entre los
//! dos hace falta algo que cumpla tres reglas a la vez:
//!
//! 1. **Nunca frena al productor.** [`Enlace::ofrecer`] toma un cerrojo corto,
//!    mete el elemento en la cola y vuelve. No serializa, no toca la red y no
//!    espera a nadie: la serializacion la paga el hilo del enlace al enviar.
//! 2. **Nunca crece sin limite.** La cola tiene techo en bytes y en elementos,
//!    y el llamante lo saca de su presupuesto de memoria. Bajo presion de
//!    memoria el techo baja ([`Medida::capacidad_bytes`]) y lo que sobra se
//!    suelta, empezando por lo menos grave.
//! 3. **Nunca pierde en silencio.** Todo lo que entra acaba enviado, en la cola
//!    o contado como perdido CON SU CAUSA. La cuenta se publica y cuadra:
//!    `ofrecidos = enviados + en_cola + perdidos` ([`Instantanea::cuadra`]).
//!
//! # Que se desaloja cuando no cabe
//!
//! Lo nuevo solo entra desalojando algo de prioridad ESTRICTAMENTE menor. Entre
//! iguales se rechaza lo nuevo: si lo nuevo pudiera echar a lo viejo de su misma
//! clase, quien pudiera generar volumen podria expulsar de la cola el veredicto
//! que lo delata. Es la misma doctrina que la cola de `aegis-ingest`.
//!
//! # Al menos una vez
//!
//! Un elemento sale de la cola solo cuando el plano de control acusa recibo con
//! `recibido`. Si la conexion cae entre el envio y el acuse, se reenvia al
//! volver: puede llegar dos veces, nunca cero. El reenvio se cuenta
//! (`reenviados`) y cada elemento lleva su identificador para poder deduplicar.
//! El elemento que se esta enviando esta «en vuelo» y ningun desalojo lo toca.
//!
//! # Reintento
//!
//! Exponencial con tope, mas un desfase DETERMINISTA por agente dentro de una
//! ventana: la misma formula que `aegis_scale::sesion::desfase_ms` en el plano
//! de control. Un reintento solo exponencial no deshace la manada tras un
//! reinicio del servidor —todos los agentes crecen igual y vuelven a coincidir—;
//! el desfase por identidad si, y el servidor puede predecirlo.
//!
//! # Solo auditoria
//!
//! El enlace informa; no obedece. No abre el canal de politica y no aplica
//! comandos: un `hay_comando` del latido se cuenta (`comandos_ignorados`) y nada
//! mas. Obedecer al plano de control es otra fase, con su propia puerta.
//!
//! # Transporte
//!
//! Aqui no hay TLS: el enlace habla por [`Conector`] y [`SesionEnlace`]. En
//! produccion el conector es [`ConectorFlota`], que usa [`crate::ClienteFlota`]
//! —el mismo mTLS, la misma CA y el mismo codec que el resto de la flota—. Las
//! pruebas lo sustituyen por un conector en memoria que se cae cuando se le
//! pide.

use std::collections::VecDeque;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::cliente::{ClienteFlota, SesionFlota};
use crate::error::{FleetError, Resultado};
use crate::pki::ahora_unix;
use crate::proto::{
    AckEstado, AckEvento, AckLatido, EstadoAgente, Latido, ReporteEvento, RespuestaEnrolamiento,
    SolicitudEnrolamiento,
};
use crate::rotacion::RotadorCertificados;

/// Ventana en la que se reparten las reconexiones de la flota.
///
/// La misma que `aegis_scale::sesion::VENTANA_RECONEXION_MS` en el plano de
/// control: sesenta segundos.
pub const VENTANA_RECONEXION: Duration = Duration::from_secs(60);

/// Tamano maximo del estado que declara el agente, en bytes.
///
/// El plano de control rechaza mas de 16 KiB; aqui se corta antes, con margen
/// para el envoltorio que anade el enlace.
pub const MAX_ESTADO_AGENTE: usize = 12 * 1024;

/// Coste fijo del enlace en memoria, aparte de su cola, en bytes.
///
/// Cuenta la pila TOCADA del hilo (la reservada es virtual y no ocupa), la
/// sesion TLS con sus buferes de registro, y los mensajes en construccion. Es
/// una cota con margen, no una medida: la prueba de extremo a extremo mide el
/// crecimiento real del proceso y lo compara con esta cifra mas la cola.
pub const COSTE_FIJO: usize = 1024 * 1024;

/// Longitud maxima del ultimo error que se guarda y se publica.
const MAX_ERROR: usize = 240;

/// Algo que el enlace sabe encolar y enviar.
pub trait Reportable: Send + 'static {
    /// Bytes que ocupa en memoria mientras espera. Cota superior, no exacta.
    fn peso(&self) -> usize;

    /// Prioridad: con la cola llena, lo nuevo solo entra desalojando algo de
    /// prioridad estrictamente menor.
    fn prioridad(&self) -> u8;

    /// El mensaje de cable.
    ///
    /// Se construye al ENVIAR, en el hilo del enlace, y no al encolar: el
    /// productor no paga la serializacion.
    fn reporte(&self, id_agente: &str) -> ReporteEvento;
}

/// Que paso con un elemento ofrecido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admision {
    /// Entro sin desalojar nada.
    Encolado,
    /// Entro desalojando ese numero de elementos de menor prioridad, que
    /// quedan contados como perdidos.
    Desalojando(usize),
    /// No entro: la cola esta llena de cosas igual o mas importantes.
    Rechazado,
    /// No entro: la presion de memoria dejo la cola sin sitio para el.
    SinMemoria,
    /// No entrara nunca: pesa mas que la cola entera.
    Enorme,
}

/// Cola acotada en bytes y en elementos.
///
/// Es publica para poder probarla sola; el enlace la usa tras un cerrojo.
pub struct Cola<T> {
    elementos: VecDeque<(T, usize)>,
    bytes: usize,
    capacidad_bytes: usize,
    capacidad_maxima: usize,
    capacidad_elementos: usize,
    en_vuelo: bool,
    pico_bytes: usize,
}

impl<T: Reportable> Cola<T> {
    /// Crea una cola vacia con esos techos.
    pub fn nueva(capacidad_bytes: usize, capacidad_elementos: usize) -> Cola<T> {
        Cola {
            elementos: VecDeque::new(),
            bytes: 0,
            capacidad_bytes,
            capacidad_maxima: capacidad_bytes,
            capacidad_elementos,
            en_vuelo: false,
            pico_bytes: 0,
        }
    }

    /// Elementos en la cola.
    pub fn len(&self) -> usize {
        self.elementos.len()
    }

    /// Si esta vacia.
    pub fn is_empty(&self) -> bool {
        self.elementos.is_empty()
    }

    /// Bytes que ocupa ahora.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Lo maximo que llego a ocupar.
    pub fn pico_bytes(&self) -> usize {
        self.pico_bytes
    }

    /// Techo de bytes vigente, que la presion de memoria puede haber bajado.
    pub fn capacidad_bytes(&self) -> usize {
        self.capacidad_bytes
    }

    /// Intenta meter un elemento.
    pub fn admitir(&mut self, item: T) -> Admision {
        let peso = item.peso().max(1);
        if peso > self.capacidad_maxima || self.capacidad_elementos == 0 {
            return Admision::Enorme;
        }
        if peso > self.capacidad_bytes {
            return Admision::SinMemoria;
        }
        let prioridad = item.prioridad();

        // Antes de soltar nada se comprueba que soltando TODO lo soltable
        // cabria. Si no, se rechaza sin haber desalojado a nadie: desalojar para
        // luego no caber seria perder dos veces.
        let desde = usize::from(self.en_vuelo);
        let (liberable, n_liberable) = self
            .elementos
            .iter()
            .skip(desde)
            .filter(|(e, _)| e.prioridad() < prioridad)
            .fold((0usize, 0usize), |(b, n), (_, p)| (b + p, n + 1));
        let bytes_minimos = self.bytes - liberable;
        let elementos_minimos = self.elementos.len() - n_liberable;
        if bytes_minimos + peso > self.capacidad_bytes
            || elementos_minimos + 1 > self.capacidad_elementos
        {
            return Admision::Rechazado;
        }

        let mut desalojados = 0;
        while self.bytes + peso > self.capacidad_bytes
            || self.elementos.len() + 1 > self.capacidad_elementos
        {
            match self.victima(Some(prioridad)) {
                Some(i) => {
                    self.quitar(i);
                    desalojados += 1;
                }
                // No ocurre: se comprobo arriba que cabia.
                None => return Admision::Rechazado,
            }
        }
        self.bytes += peso;
        self.elementos.push_back((item, peso));
        self.pico_bytes = self.pico_bytes.max(self.bytes);
        if desalojados == 0 {
            Admision::Encolado
        } else {
            Admision::Desalojando(desalojados)
        }
    }

    /// Ajusta el techo de bytes a la presion de memoria del momento, sin pasar
    /// nunca del techo con el que se creo. Devuelve cuantos elementos solto.
    pub fn ajustar(&mut self, capacidad_bytes: usize) -> usize {
        self.capacidad_bytes = capacidad_bytes.min(self.capacidad_maxima);
        let mut soltados = 0;
        while self.bytes > self.capacidad_bytes {
            match self.victima(None) {
                Some(i) => {
                    self.quitar(i);
                    soltados += 1;
                }
                // Solo queda el que esta en vuelo: se suelta al acusarlo.
                None => break,
            }
        }
        soltados
    }

    /// Marca el frente como «en vuelo» y lo devuelve.
    pub fn frente(&mut self) -> Option<&T> {
        if self.elementos.is_empty() {
            return None;
        }
        self.en_vuelo = true;
        self.elementos.front().map(|(e, _)| e)
    }

    /// El plano de control acuso el frente (o se descarta): sale de la cola.
    pub fn confirmar_frente(&mut self) -> Option<T> {
        self.en_vuelo = false;
        self.quitar(0)
    }

    /// El envio del frente fallo: sigue en la cola y deja de estar en vuelo.
    pub fn soltar_frente(&mut self) {
        self.en_vuelo = false;
    }

    /// Lo que se desaloja: la prioridad mas baja y, entre iguales, lo mas
    /// reciente, que es lo que menos contexto quita. Nunca el que esta en vuelo.
    /// Con `bajo_de`, solo lo de prioridad estrictamente menor.
    fn victima(&self, bajo_de: Option<u8>) -> Option<usize> {
        let desde = usize::from(self.en_vuelo);
        let mut mejor: Option<(usize, u8)> = None;
        for (i, (e, _)) in self.elementos.iter().enumerate().skip(desde) {
            let p = e.prioridad();
            if bajo_de.is_some_and(|b| p >= b) {
                continue;
            }
            // `<=`: entre iguales gana el que aparece despues, el mas reciente.
            if mejor.is_none_or(|(_, mp)| p <= mp) {
                mejor = Some((i, p));
            }
        }
        mejor.map(|(i, _)| i)
    }

    fn quitar(&mut self, i: usize) -> Option<T> {
        let (e, p) = self.elementos.remove(i)?;
        self.bytes -= p;
        Some(e)
    }
}

/// Las cuentas del enlace en un instante.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Instantanea {
    /// Si hay una sesion abierta y enrolada con el plano de control.
    pub conectado: bool,
    /// Elementos ofrecidos desde el arranque.
    pub ofrecidos: u64,
    /// Elementos que el plano de control acuso como guardados.
    pub enviados: u64,
    /// Envios repetidos de un elemento que ya se habia intentado.
    pub reenviados: u64,
    /// Elementos esperando en la cola.
    pub en_cola: u64,
    /// Bytes que ocupa la cola.
    pub bytes_en_cola: u64,
    /// Lo maximo que llego a ocupar la cola.
    pub pico_bytes: u64,
    /// Techo de bytes vigente de la cola.
    pub capacidad_bytes: u64,
    /// Perdidos: la cola estaba llena de cosas igual o mas importantes.
    pub perdidos_por_tope: u64,
    /// Perdidos: desalojados por algo mas grave.
    pub desalojados_por_prioridad: u64,
    /// Perdidos: soltados, o no admitidos, por presion de memoria.
    pub perdidos_por_memoria: u64,
    /// Perdidos: pesaban mas que la cola entera.
    pub enormes: u64,
    /// Perdidos: el plano de control los rechazo una y otra vez.
    pub rechazados_por_servidor: u64,
    /// Envios que el plano de control APLAZO (`reintentar`): su base de datos
    /// no estaba y el elemento sigue en la cola. Contrapresion, no perdida
    /// (FASE 6.4 del MP-16); no entra en `perdidos()`.
    pub aplazados_por_servidor: u64,
    /// Sesiones abiertas y enroladas.
    pub conexiones: u64,
    /// Intentos de conexion o enrolamiento fallidos.
    pub fallos_conexion: u64,
    /// Latidos acusados.
    pub latidos: u64,
    /// Estados de agente guardados por el plano de control.
    pub estados: u64,
    /// Estados de agente que el plano de control no guardo.
    pub estados_no_guardados: u64,
    /// Latidos que traian un comando, que en solo-auditoria no se ejecuta.
    pub comandos_ignorados: u64,
    /// El ultimo error de red o de protocolo, recortado.
    pub ultimo_error: Option<String>,
}

impl Instantanea {
    /// Todo lo perdido, sumando las causas.
    pub fn perdidos(&self) -> u64 {
        self.perdidos_por_tope
            + self.desalojados_por_prioridad
            + self.perdidos_por_memoria
            + self.enormes
            + self.rechazados_por_servidor
    }

    /// `ofrecidos = enviados + en_cola + perdidos`: nada se pierde sin contarlo.
    pub fn cuadra(&self) -> bool {
        self.ofrecidos == self.enviados + self.en_cola + self.perdidos()
    }

    /// Las cuentas como objeto JSON, para el estado que se publica.
    pub fn json(&self) -> String {
        format!(
            "{{\"solo_auditoria\":true,\"conectado\":{},\"ofrecidos\":{},\"enviados\":{},\
             \"reenviados\":{},\"en_cola\":{},\"bytes_en_cola\":{},\"pico_bytes\":{},\
             \"capacidad_bytes\":{},\"perdidos\":{},\"perdidos_por_causa\":{{\"tope\":{},\
             \"prioridad\":{},\"memoria\":{},\"enormes\":{},\"servidor\":{}}},\
             \"conexiones\":{},\"fallos_conexion\":{},\"latidos\":{},\
             \"comandos_ignorados\":{},\"cuadra\":{},\"ultimo_error\":{}}}",
            self.conectado,
            self.ofrecidos,
            self.enviados,
            self.reenviados,
            self.en_cola,
            self.bytes_en_cola,
            self.pico_bytes,
            self.capacidad_bytes,
            self.perdidos(),
            self.perdidos_por_tope,
            self.desalojados_por_prioridad,
            self.perdidos_por_memoria,
            self.enormes,
            self.rechazados_por_servidor,
            self.conexiones,
            self.fallos_conexion,
            self.latidos,
            self.comandos_ignorados,
            self.cuadra(),
            self.ultimo_error
                .as_deref()
                .map_or_else(|| "null".to_string(), cadena_json),
        )
    }
}

/// Ajustes del enlace.
#[derive(Debug, Clone, Copy)]
pub struct ConfigEnlace {
    /// Techo de bytes de la cola. Sale del presupuesto de memoria del agente.
    pub capacidad_bytes: usize,
    /// Techo de elementos de la cola.
    pub capacidad_elementos: usize,
    /// Intervalo de latido hasta que el enrolamiento diga otro.
    pub latido: Duration,
    /// Primera espera tras un fallo.
    pub reintento_base: Duration,
    /// Espera maxima entre intentos, sin contar el desfase.
    pub reintento_tope: Duration,
    /// Anchura maxima del desfase determinista por agente.
    pub ventana_desfase: Duration,
    /// Rechazos seguidos del plano de control antes de descartar un elemento.
    pub max_rechazos: u32,
    /// Elementos enviados por vuelta antes de volver a mirar el latido.
    pub lote: usize,
}

impl Default for ConfigEnlace {
    fn default() -> ConfigEnlace {
        ConfigEnlace {
            capacidad_bytes: 256 * 1024,
            capacidad_elementos: 1024,
            latido: Duration::from_secs(30),
            reintento_base: Duration::from_secs(1),
            reintento_tope: Duration::from_secs(300),
            ventana_desfase: VENTANA_RECONEXION,
            max_rechazos: 5,
            lote: 64,
        }
    }
}

/// Lo que el agente mide de si mismo en cada latido.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Medida {
    /// Memoria residente del agente, en KiB.
    pub rss_kb: u64,
    /// Amenazas activas que declara el agente.
    pub amenazas_activas: u64,
    /// Techo de bytes que la cola puede ocupar AHORA, segun la presion de
    /// memoria. `None` deja el vigente.
    pub capacidad_bytes: Option<usize>,
}

/// Abre sesiones con el plano de control.
pub trait Conector: Send + 'static {
    /// La sesion que abre.
    type Sesion: SesionEnlace;

    /// Identidad estable del agente (el CN de su certificado).
    fn id_agente(&self) -> String;

    /// Abre una sesion nueva, sin enrolar aun.
    fn conectar(&mut self) -> Resultado<Self::Sesion>;
}

/// Las llamadas que el enlace hace sobre una sesion abierta.
pub trait SesionEnlace {
    /// Enrola al agente.
    fn enrolar(&mut self) -> Resultado<RespuestaEnrolamiento>;
    /// Emite un latido.
    fn latir(&mut self, latido: &Latido) -> Resultado<AckLatido>;
    /// Declara el estado de motores y del enlace.
    fn reportar_estado(&mut self, estado: &EstadoAgente) -> Resultado<AckEstado>;
    /// Reporta un elemento de la cola.
    fn reportar(&mut self, reporte: &ReporteEvento) -> Resultado<AckEvento>;
}

/// El conector de produccion: el cliente mTLS de la flota.
pub struct ConectorFlota {
    direccion: String,
    ca_der: CertificateDer<'static>,
    rotador: Arc<RotadorCertificados>,
    hostname: String,
    version: String,
    plazo: Duration,
}

impl ConectorFlota {
    /// Conector hacia `direccion` (`host:puerto`), confiando en `ca_der` y
    /// presentando la identidad que gestiona `rotador`.
    ///
    /// `plazo` acota la conexion y cada lectura o escritura: un plano de
    /// control que deja de contestar no puede colgar al enlace para siempre.
    pub fn nuevo(
        direccion: &str,
        ca_der: CertificateDer<'static>,
        rotador: Arc<RotadorCertificados>,
        hostname: &str,
        version: &str,
        plazo: Duration,
    ) -> ConectorFlota {
        ConectorFlota {
            direccion: direccion.to_string(),
            ca_der,
            rotador,
            hostname: hostname.to_string(),
            version: version.to_string(),
            plazo,
        }
    }
}

impl Conector for ConectorFlota {
    type Sesion = SesionEnlaceFlota;

    fn id_agente(&self) -> String {
        self.rotador.cn().to_string()
    }

    fn conectar(&mut self) -> Resultado<SesionEnlaceFlota> {
        // Se resuelve en CADA intento: el plano de control puede cambiar de
        // direccion detras de su nombre mientras el agente espera.
        let direccion = self
            .direccion
            .to_socket_addrs()
            .map_err(|e| FleetError::Red {
                op: "resolver el plano de control",
                source: e,
            })?
            .next()
            .ok_or_else(|| FleetError::Red {
                op: "resolver el plano de control",
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "sin direcciones"),
            })?;
        let cliente = ClienteFlota::nuevo(
            direccion,
            self.ca_der.clone(),
            Arc::clone(&self.rotador),
            &self.hostname,
            &self.version,
        );
        let sesion = cliente.abrir_sesion_con_plazo(self.plazo)?;
        let solicitud = cliente.solicitud_enrolamiento()?;
        Ok(SesionEnlaceFlota { sesion, solicitud })
    }
}

/// Sesion de produccion: una [`SesionFlota`] y la solicitud con la que enrolar.
pub struct SesionEnlaceFlota {
    sesion: SesionFlota,
    solicitud: SolicitudEnrolamiento,
}

impl SesionEnlace for SesionEnlaceFlota {
    fn enrolar(&mut self) -> Resultado<RespuestaEnrolamiento> {
        self.sesion.enrolar(&self.solicitud)
    }

    fn latir(&mut self, latido: &Latido) -> Resultado<AckLatido> {
        self.sesion.latir(latido)
    }

    fn reportar_estado(&mut self, estado: &EstadoAgente) -> Resultado<AckEstado> {
        self.sesion.reportar_estado(estado)
    }

    fn reportar(&mut self, reporte: &ReporteEvento) -> Resultado<AckEvento> {
        self.sesion.reportar_evento(reporte)
    }
}

/// Lo que comparten el productor y el hilo del enlace, tras un cerrojo.
struct Estado<T> {
    cola: Cola<T>,
    cuentas: Instantanea,
    parar: bool,
    estado_agente: Option<String>,
}

struct Compartido<T> {
    estado: Mutex<Estado<T>>,
    aviso: Condvar,
}

impl<T> Compartido<T> {
    /// El cerrojo, tambien si otro hilo cayo con el tomado: el enlace no
    /// convierte un panico ajeno en otro propio.
    fn cerrar(&self) -> MutexGuard<'_, Estado<T>> {
        self.estado.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn instantanea<T: Reportable>(e: &Estado<T>) -> Instantanea {
    let mut i = e.cuentas.clone();
    i.en_cola = e.cola.len() as u64;
    i.bytes_en_cola = e.cola.bytes() as u64;
    i.pico_bytes = e.cola.pico_bytes() as u64;
    i.capacidad_bytes = e.cola.capacidad_bytes() as u64;
    i
}

/// El enlace: un hilo propio con su cola.
pub struct Enlace<T: Reportable> {
    compartido: Arc<Compartido<T>>,
    hilo: Option<JoinHandle<()>>,
}

impl<T: Reportable> Enlace<T> {
    /// Arranca el hilo del enlace.
    ///
    /// `medir` se llama en cada latido, en el hilo del enlace: devuelve la
    /// memoria del agente, sus amenazas activas y el techo de cola que permite
    /// la presion de memoria del momento.
    pub fn arrancar<C: Conector>(
        conector: C,
        cfg: ConfigEnlace,
        medir: Box<dyn FnMut() -> Medida + Send>,
    ) -> Resultado<Enlace<T>> {
        let compartido = Arc::new(Compartido {
            estado: Mutex::new(Estado {
                cola: Cola::nueva(cfg.capacidad_bytes, cfg.capacidad_elementos),
                cuentas: Instantanea::default(),
                parar: false,
                estado_agente: None,
            }),
            aviso: Condvar::new(),
        });
        let c = Arc::clone(&compartido);
        let hilo = std::thread::Builder::new()
            .name("aegis-enlace".to_string())
            .spawn(move || bucle(&c, conector, &cfg, medir))
            .map_err(|e| FleetError::Red {
                op: "arrancar el hilo del enlace",
                source: e,
            })?;
        Ok(Enlace {
            compartido,
            hilo: Some(hilo),
        })
    }

    /// Ofrece un elemento. No bloquea mas que un cerrojo corto.
    pub fn ofrecer(&self, item: T) -> Admision {
        let mut e = self.compartido.cerrar();
        e.cuentas.ofrecidos += 1;
        let admision = e.cola.admitir(item);
        match admision {
            Admision::Encolado => {}
            Admision::Desalojando(n) => e.cuentas.desalojados_por_prioridad += n as u64,
            Admision::Rechazado => e.cuentas.perdidos_por_tope += 1,
            Admision::SinMemoria => e.cuentas.perdidos_por_memoria += 1,
            Admision::Enorme => e.cuentas.enormes += 1,
        }
        drop(e);
        if matches!(admision, Admision::Encolado | Admision::Desalojando(_)) {
            self.compartido.aviso.notify_one();
        }
        admision
    }

    /// Publica el estado del agente (un objeto JSON). Gana el ultimo y viaja con
    /// el siguiente latido.
    pub fn publicar_estado(&self, json: String) {
        let json = if json.len() > MAX_ESTADO_AGENTE {
            format!("{{\"recortado\":true,\"bytes\":{}}}", json.len())
        } else {
            json
        };
        self.compartido.cerrar().estado_agente = Some(json);
    }

    /// Las cuentas ahora mismo.
    pub fn instantanea(&self) -> Instantanea {
        instantanea(&self.compartido.cerrar())
    }

    /// Para el hilo y devuelve las cuentas finales.
    ///
    /// Lo que quede en la cola no se envia: queda en `en_cola`, y quien para el
    /// enlace tiene que decirlo. Si el hilo esta a mitad de una llamada de red,
    /// la espera la acota el plazo del conector.
    pub fn parar(mut self) -> Instantanea {
        self.detener();
        self.instantanea()
    }

    fn detener(&mut self) {
        if let Some(h) = self.hilo.take() {
            self.compartido.cerrar().parar = true;
            self.compartido.aviso.notify_all();
            let _ = h.join();
        }
    }
}

impl<T: Reportable> Drop for Enlace<T> {
    fn drop(&mut self) {
        self.detener();
    }
}

/// El ritmo del hilo del enlace mientras hay sesion.
struct Ritmo {
    latido_cada: Duration,
    proximo_latido: Instant,
    pausa_hasta: Instant,
    rechazos: u32,
    aplazos: u32,
    frente_intentado: bool,
}

/// El hilo del enlace.
fn bucle<T: Reportable, C: Conector>(
    compartido: &Compartido<T>,
    mut conector: C,
    cfg: &ConfigEnlace,
    mut medir: Box<dyn FnMut() -> Medida + Send>,
) {
    let id = conector.id_agente();
    let mut sesion: Option<C::Sesion> = None;
    let mut intentos: u32 = 0;
    let mut proximo_intento = Instant::now();
    let mut ritmo = Ritmo {
        latido_cada: cfg.latido,
        proximo_latido: Instant::now(),
        pausa_hasta: Instant::now(),
        rechazos: 0,
        aplazos: 0,
        frente_intentado: false,
    };

    loop {
        // 1. Dormir hasta que haya algo que hacer, o hasta que se pida parar.
        {
            let mut e = compartido.cerrar();
            loop {
                if e.parar {
                    return;
                }
                let ahora = Instant::now();
                let despierta = if sesion.is_none() {
                    proximo_intento
                } else if e.cola.is_empty() {
                    ritmo.proximo_latido
                } else {
                    ritmo.pausa_hasta.min(ritmo.proximo_latido)
                };
                if despierta <= ahora {
                    break;
                }
                e = compartido
                    .aviso
                    .wait_timeout(e, despierta - ahora)
                    .map(|(g, _)| g)
                    .unwrap_or_else(|p| p.into_inner().0);
            }
        }

        // 2. Conectar y enrolar si no hay sesion.
        if sesion.is_none() {
            match conectar_y_enrolar(&mut conector) {
                Ok((s, intervalo)) => {
                    if let Some(i) = intervalo {
                        ritmo.latido_cada = i;
                    }
                    sesion = Some(s);
                    intentos = 0;
                    ritmo.proximo_latido = Instant::now();
                    ritmo.pausa_hasta = Instant::now();
                    let mut e = compartido.cerrar();
                    e.cuentas.conexiones += 1;
                    e.cuentas.conectado = true;
                }
                Err(err) => {
                    intentos = intentos.saturating_add(1);
                    proximo_intento = Instant::now() + espera_reintento(cfg, &id, intentos);
                    let mut e = compartido.cerrar();
                    e.cuentas.fallos_conexion += 1;
                    e.cuentas.ultimo_error = Some(recortar(&err.to_string(), MAX_ERROR));
                    continue;
                }
            }
        }

        // 3. Latir y drenar. Un fallo tira la sesion y el siguiente intento
        //    espera su turno de reintento.
        let resultado = match sesion.as_mut() {
            Some(s) => trabajar(compartido, s, &id, cfg, &mut ritmo, &mut *medir),
            None => continue,
        };
        if let Err(err) = resultado {
            sesion = None;
            intentos = 1;
            proximo_intento = Instant::now() + espera_reintento(cfg, &id, intentos);
            let mut e = compartido.cerrar();
            e.cuentas.conectado = false;
            e.cuentas.ultimo_error = Some(recortar(&err.to_string(), MAX_ERROR));
        }
    }
}

fn conectar_y_enrolar<C: Conector>(c: &mut C) -> Resultado<(C::Sesion, Option<Duration>)> {
    let mut s = c.conectar()?;
    let r = s.enrolar()?;
    if !r.aceptado {
        return Err(FleetError::NoEnrolado(r.motivo));
    }
    let intervalo = (r.intervalo_latido_seg > 0)
        .then(|| Duration::from_secs(r.intervalo_latido_seg.clamp(1, 3600)));
    Ok((s, intervalo))
}

/// Una vuelta con sesion: el latido si toca y un lote de la cola.
fn trabajar<T: Reportable, S: SesionEnlace>(
    compartido: &Compartido<T>,
    s: &mut S,
    id: &str,
    cfg: &ConfigEnlace,
    ritmo: &mut Ritmo,
    medir: &mut dyn FnMut() -> Medida,
) -> Resultado<()> {
    if Instant::now() >= ritmo.proximo_latido {
        latir(compartido, s, id, medir)?;
        ritmo.proximo_latido = Instant::now() + ritmo.latido_cada;
    }
    if Instant::now() < ritmo.pausa_hasta {
        return Ok(());
    }
    for _ in 0..cfg.lote.max(1) {
        let reporte = {
            let mut e = compartido.cerrar();
            if e.parar {
                return Ok(());
            }
            match e.cola.frente() {
                Some(item) => item.reporte(id),
                None => return Ok(()),
            }
        };
        if ritmo.frente_intentado {
            compartido.cerrar().cuentas.reenviados += 1;
        }
        ritmo.frente_intentado = true;
        let ack = match s.reportar(&reporte) {
            Ok(a) => a,
            Err(err) => {
                compartido.cerrar().cola.soltar_frente();
                return Err(err);
            }
        };
        let mut e = compartido.cerrar();
        if ack.recibido {
            e.cola.confirmar_frente();
            e.cuentas.enviados += 1;
            ritmo.rechazos = 0;
            ritmo.aplazos = 0;
            ritmo.frente_intentado = false;
            continue;
        }
        if ack.reintentar {
            // Contrapresion (FASE 6.4): el plano de control esta vivo pero no
            // puede guardar. El elemento NO cuenta para `max_rechazos` —no es
            // un rechazo suyo— y descartarlo convertiria una caida de
            // PostgreSQL en perdida. Espera, con el desfase de este agente.
            e.cola.soltar_frente();
            e.cuentas.aplazados_por_servidor += 1;
            ritmo.aplazos = ritmo.aplazos.saturating_add(1);
            drop(e);
            ritmo.pausa_hasta = Instant::now() + espera_reintento(cfg, id, ritmo.aplazos);
            return Ok(());
        }
        // El plano de control contesto pero no lo guardo (su base de datos
        // cayo, o no le gusta el elemento). No se insiste en caliente: se
        // espera, y tras `max_rechazos` seguidos el elemento se descarta
        // CONTADO para que no atasque a los que vienen detras.
        ritmo.rechazos += 1;
        if ritmo.rechazos >= cfg.max_rechazos.max(1) {
            e.cola.confirmar_frente();
            e.cuentas.rechazados_por_servidor += 1;
            ritmo.rechazos = 0;
            ritmo.frente_intentado = false;
        } else {
            e.cola.soltar_frente();
        }
        drop(e);
        ritmo.pausa_hasta = Instant::now() + espera_reintento(cfg, id, ritmo.rechazos.max(1));
        return Ok(());
    }
    Ok(())
}

/// El latido y, en la misma vuelta, el estado del agente con las cuentas.
fn latir<T: Reportable, S: SesionEnlace>(
    compartido: &Compartido<T>,
    s: &mut S,
    id: &str,
    medir: &mut dyn FnMut() -> Medida,
) -> Resultado<()> {
    let medida = medir();
    let (agente, cuentas) = {
        let mut e = compartido.cerrar();
        if let Some(c) = medida.capacidad_bytes {
            let soltados = e.cola.ajustar(c);
            e.cuentas.perdidos_por_memoria += soltados as u64;
        }
        (e.estado_agente.clone(), instantanea(&e))
    };
    let ack = s.latir(&Latido {
        id_agente: id.to_string(),
        momento_unix: ahora_unix(),
        rss_kb: medida.rss_kb,
        amenazas_activas: medida.amenazas_activas,
        // Solo auditoria: el agente no carga politica del plano de control.
        version_politica: 0,
    })?;
    let guardado = s.reportar_estado(&EstadoAgente {
        id_agente: id.to_string(),
        momento_unix: ahora_unix(),
        estado_json: format!(
            "{{\"agente\":{},\"enlace\":{}}}",
            agente.as_deref().unwrap_or("null"),
            cuentas.json()
        ),
    })?;
    let mut e = compartido.cerrar();
    e.cuentas.latidos += 1;
    if ack.hay_comando {
        e.cuentas.comandos_ignorados += 1;
    }
    if guardado.recibido {
        e.cuentas.estados += 1;
    } else {
        e.cuentas.estados_no_guardados += 1;
    }
    Ok(())
}

/// Espera antes del intento numero `intento` (desde 1).
///
/// `min(base * 2^(intento-1), tope)` mas un desfase determinista del agente
/// dentro de `min(ese paso, ventana)`: dos agentes distintos no vuelven a la
/// vez, y el mismo agente cae siempre en el mismo hueco.
pub fn espera_reintento(cfg: &ConfigEnlace, id_agente: &str, intento: u32) -> Duration {
    let exponente = intento.saturating_sub(1).min(16);
    let paso = cfg
        .reintento_base
        .saturating_mul(1u32 << exponente)
        .min(cfg.reintento_tope);
    let ancho = paso.min(cfg.ventana_desfase);
    let ancho_ms = u64::try_from(ancho.as_millis()).unwrap_or(u64::MAX);
    paso + Duration::from_millis(desfase_ms(id_agente, ancho_ms))
}

/// Desfase determinista de un agente en una ventana, en milisegundos.
///
/// Es la formula de `aegis_scale::sesion::desfase_ms`: los primeros ocho bytes
/// del SHA-256 de la identidad, modulo la ventana. El agente y el servidor
/// calculan lo mismo sin hablar.
pub fn desfase_ms(agente: &str, ventana_ms: u64) -> u64 {
    if ventana_ms == 0 {
        return 0;
    }
    let d = Sha256::digest(agente.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b) % ventana_ms
}

/// Recorta un texto a `max` bytes sin partir un caracter UTF-8.
pub fn recortar(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut fin = max;
    while fin > 0 && !s.is_char_boundary(fin) {
        fin -= 1;
    }
    s[..fin].to_string()
}

/// Una cadena como literal JSON, con comillas y escapes.
pub fn cadena_json(s: &str) -> String {
    let mut r = String::with_capacity(s.len() + 2);
    r.push('"');
    for c in s.chars() {
        match c {
            '"' => r.push_str("\\\""),
            '\\' => r.push_str("\\\\"),
            '\n' => r.push_str("\\n"),
            '\r' => r.push_str("\\r"),
            '\t' => r.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                r.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => r.push(c),
        }
    }
    r.push('"');
    r
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un elemento de prueba.
    struct Item {
        texto: String,
        prioridad: u8,
        peso: usize,
    }

    fn item(texto: &str, prioridad: u8, peso: usize) -> Item {
        Item {
            texto: texto.to_string(),
            prioridad,
            peso,
        }
    }

    impl Reportable for Item {
        fn peso(&self) -> usize {
            self.peso
        }
        fn prioridad(&self) -> u8 {
            self.prioridad
        }
        fn reporte(&self, id_agente: &str) -> ReporteEvento {
            ReporteEvento {
                id_agente: id_agente.to_string(),
                descripcion: self.texto.clone(),
                ..Default::default()
            }
        }
    }

    fn textos(c: &mut Cola<Item>) -> Vec<String> {
        let mut v = Vec::new();
        while let Some(i) = c.confirmar_frente() {
            v.push(i.texto);
        }
        v
    }

    #[test]
    fn la_cola_respeta_sus_techos_y_lo_igual_no_expulsa_a_lo_igual() {
        let mut c = Cola::nueva(1000, 3);
        assert_eq!(c.admitir(item("a", 1, 100)), Admision::Encolado);
        assert_eq!(c.admitir(item("b", 1, 100)), Admision::Encolado);
        assert_eq!(c.admitir(item("c", 1, 100)), Admision::Encolado);
        // Tope de elementos con la misma prioridad: se rechaza lo NUEVO.
        assert_eq!(c.admitir(item("d", 1, 100)), Admision::Rechazado);
        // Algo mas grave entra desalojando lo menos grave MAS RECIENTE.
        assert_eq!(c.admitir(item("e", 2, 100)), Admision::Desalojando(1));
        assert_eq!(c.admitir(item("gigante", 9, 1001)), Admision::Enorme);
        assert!(c.bytes() <= 1000 && c.len() <= 3);
        assert_eq!(textos(&mut c), ["a", "b", "e"]);
    }

    #[test]
    fn no_se_desaloja_para_luego_no_caber() {
        let mut c = Cola::nueva(300, 10);
        for t in ["a", "b", "c"] {
            assert_eq!(c.admitir(item(t, 0, 100)), Admision::Encolado);
        }
        c.frente().expect("frente");
        // Con «a» en vuelo solo se pueden soltar 200 bytes: 250 no caben y no se
        // toca a nadie.
        assert_eq!(c.admitir(item("grave", 5, 250)), Admision::Rechazado);
        assert_eq!(c.len(), 3);
        assert_eq!(c.confirmar_frente().map(|i| i.texto), Some("a".into()));
        assert_eq!(c.admitir(item("grave", 5, 250)), Admision::Desalojando(2));
        assert_eq!(textos(&mut c), ["grave"]);
    }

    #[test]
    fn el_frente_en_vuelo_no_se_desaloja_ni_bajo_presion_de_memoria() {
        let mut c = Cola::nueva(400, 10);
        c.admitir(item("viejo-leve", 0, 100));
        c.admitir(item("grave", 3, 100));
        c.admitir(item("reciente-leve", 0, 100));
        c.frente().expect("frente");
        // Bajar el techo a 150 suelta lo leve que no esta en vuelo, empezando
        // por lo mas reciente, y despues lo grave. El frente se queda.
        assert_eq!(c.ajustar(150), 2);
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.confirmar_frente().map(|i| i.texto),
            Some("viejo-leve".into())
        );
        // Con la memoria agotada no entra nada, y no es «enorme»: es memoria.
        assert_eq!(c.ajustar(0), 0);
        assert_eq!(c.admitir(item("x", 9, 10)), Admision::SinMemoria);
        // Al aflojar la presion vuelve el techo, pero nunca por encima del
        // original.
        c.ajustar(10_000);
        assert_eq!(c.capacidad_bytes(), 400);
    }

    #[test]
    fn el_retroceso_crece_hasta_el_tope_y_reparte_a_la_flota() {
        let cfg = ConfigEnlace::default();
        let seg = Duration::from_secs;
        for (intento, paso) in [(1, 1), (2, 2), (3, 4), (9, 256), (10, 300), (40, 300)] {
            let e = espera_reintento(&cfg, "agente-1", intento);
            let ancho = seg(paso).min(cfg.ventana_desfase);
            assert!(e >= seg(paso) && e < seg(paso) + ancho, "{intento}: {e:?}");
            // Determinista: el mismo agente cae siempre en el mismo hueco.
            assert_eq!(e, espera_reintento(&cfg, "agente-1", intento));
        }
        // Mil agentes con el servidor recien vuelto se reparten por la ventana.
        let desfases: Vec<u64> = (0..1000)
            .map(|i| desfase_ms(&format!("agente-{i}"), 60_000))
            .collect();
        assert!(desfases.iter().min().copied().unwrap_or(0) < 1_000);
        assert!(desfases.iter().max().copied().unwrap_or(0) > 59_000);
        assert_eq!(desfase_ms("x", 0), 0);
    }

    #[test]
    fn los_textos_se_recortan_sin_partir_caracteres_y_se_escapan() {
        assert_eq!(recortar("año", 2), "a");
        assert_eq!(recortar("corto", 99), "corto");
        assert_eq!(cadena_json("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    // ── El enlace entero, contra un plano de control en memoria ─────────────

    #[derive(Default)]
    struct Servidor {
        vivo: bool,
        conexiones: u64,
        recibidos: Vec<String>,
        estados: Vec<String>,
        latidos: u64,
        /// Tras tantos reportes buenos, el siguiente tira el servidor.
        cortar_tras: Option<usize>,
        /// El reporte con esta descripcion se contesta con `recibido: false`.
        rechazar: Option<String>,
        /// Si los latidos traen un comando.
        con_comando: bool,
    }

    type Compartida = Arc<Mutex<Servidor>>;

    fn caido() -> FleetError {
        FleetError::Red {
            op: "prueba",
            source: std::io::Error::new(std::io::ErrorKind::ConnectionReset, "caido"),
        }
    }

    struct ConectorFalso(Compartida);
    struct SesionFalsa(Compartida);

    impl Conector for ConectorFalso {
        type Sesion = SesionFalsa;
        fn id_agente(&self) -> String {
            "agente-prueba".to_string()
        }
        fn conectar(&mut self) -> Resultado<SesionFalsa> {
            let mut g = self.0.lock().unwrap();
            if !g.vivo {
                return Err(caido());
            }
            g.conexiones += 1;
            Ok(SesionFalsa(Arc::clone(&self.0)))
        }
    }

    impl SesionEnlace for SesionFalsa {
        fn enrolar(&mut self) -> Resultado<RespuestaEnrolamiento> {
            if !self.0.lock().unwrap().vivo {
                return Err(caido());
            }
            Ok(RespuestaEnrolamiento {
                aceptado: true,
                ..Default::default()
            })
        }
        fn latir(&mut self, _l: &Latido) -> Resultado<AckLatido> {
            let mut g = self.0.lock().unwrap();
            if !g.vivo {
                return Err(caido());
            }
            g.latidos += 1;
            Ok(AckLatido {
                recibido: true,
                hay_comando: g.con_comando,
                ..Default::default()
            })
        }
        fn reportar_estado(&mut self, e: &EstadoAgente) -> Resultado<AckEstado> {
            let mut g = self.0.lock().unwrap();
            if !g.vivo {
                return Err(caido());
            }
            g.estados.push(e.estado_json.clone());
            Ok(AckEstado { recibido: true })
        }
        fn reportar(&mut self, r: &ReporteEvento) -> Resultado<AckEvento> {
            let mut g = self.0.lock().unwrap();
            if !g.vivo {
                return Err(caido());
            }
            if let Some(n) = g.cortar_tras {
                if n == 0 {
                    g.vivo = false;
                    g.cortar_tras = None;
                    return Err(caido());
                }
                g.cortar_tras = Some(n - 1);
            }
            if g.rechazar.as_deref() == Some(r.descripcion.as_str()) {
                return Ok(AckEvento::default());
            }
            g.recibidos.push(r.descripcion.clone());
            Ok(AckEvento {
                recibido: true,
                ..Default::default()
            })
        }
    }

    fn cfg_rapida() -> ConfigEnlace {
        ConfigEnlace {
            capacidad_bytes: 10_000,
            capacidad_elementos: 100,
            latido: Duration::from_millis(20),
            reintento_base: Duration::from_millis(5),
            reintento_tope: Duration::from_millis(20),
            ventana_desfase: Duration::from_millis(10),
            max_rechazos: 3,
            lote: 64,
        }
    }

    fn arrancar(srv: &Compartida, cfg: ConfigEnlace) -> Enlace<Item> {
        Enlace::arrancar(
            ConectorFalso(Arc::clone(srv)),
            cfg,
            Box::new(Medida::default),
        )
        .expect("arranque del enlace")
    }

    fn esperar(que: &str, mut cond: impl FnMut() -> bool) {
        let limite = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < limite, "no llego a pasar: {que}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn sin_servidor_se_encola_y_al_volver_se_reconcilia_en_orden() {
        let srv: Compartida = Arc::default();
        srv.lock().unwrap().con_comando = true;
        let enlace = arrancar(&srv, cfg_rapida());
        for i in 0..5 {
            assert_eq!(
                enlace.ofrecer(item(&format!("v{i}"), 1, 50)),
                Admision::Encolado
            );
        }
        esperar("varios intentos fallidos", || {
            enlace.instantanea().fallos_conexion >= 2
        });
        let i = enlace.instantanea();
        assert!(!i.conectado);
        assert_eq!((i.enviados, i.en_cola), (0, 5));
        assert!(i.ultimo_error.is_some());
        assert!(i.cuadra(), "{i:?}");

        srv.lock().unwrap().vivo = true;
        esperar("todo entregado", || enlace.instantanea().enviados == 5);
        esperar("un estado que ya lo cuenta", || {
            srv.lock()
                .unwrap()
                .estados
                .iter()
                .any(|e| e.contains("\"enviados\":5"))
        });
        let fin = enlace.parar();
        assert!(fin.cuadra(), "{fin:?}");
        assert_eq!(fin.en_cola, 0);
        assert!(fin.latidos >= 1);
        // Solo auditoria: el comando se cuenta, no se ejecuta.
        assert!(fin.comandos_ignorados >= 1);
        let g = srv.lock().unwrap();
        assert_eq!(g.recibidos, ["v0", "v1", "v2", "v3", "v4"]);
        assert!(g.latidos >= 1 && g.conexiones >= 1);
    }

    #[test]
    fn un_corte_a_mitad_no_pierde_el_elemento_en_vuelo() {
        let srv: Compartida = Arc::default();
        {
            let mut g = srv.lock().unwrap();
            g.vivo = true;
            g.cortar_tras = Some(2);
        }
        let enlace = arrancar(&srv, cfg_rapida());
        for i in 0..5 {
            enlace.ofrecer(item(&format!("v{i}"), 1, 50));
        }
        esperar("el corte", || {
            let i = enlace.instantanea();
            !i.conectado && i.enviados == 2
        });
        assert_eq!(enlace.instantanea().en_cola, 3);
        srv.lock().unwrap().vivo = true;
        esperar("la reconciliacion", || enlace.instantanea().enviados == 5);
        let fin = enlace.parar();
        assert!(fin.cuadra(), "{fin:?}");
        assert!(fin.reenviados >= 1, "el que estaba en vuelo se reenvia");
        assert!(fin.conexiones >= 2);
        let g = srv.lock().unwrap();
        assert!(g.conexiones >= 2);
        assert_eq!(g.recibidos, ["v0", "v1", "v2", "v3", "v4"]);
    }

    #[test]
    fn lo_que_el_servidor_rechaza_se_descarta_contado_sin_atascar_la_cola() {
        let srv: Compartida = Arc::default();
        {
            let mut g = srv.lock().unwrap();
            g.vivo = true;
            g.rechazar = Some("malo".into());
        }
        let enlace = arrancar(&srv, cfg_rapida());
        enlace.ofrecer(item("malo", 1, 50));
        enlace.ofrecer(item("b", 1, 50));
        enlace.ofrecer(item("c", 1, 50));
        esperar("los buenos llegan", || enlace.instantanea().enviados == 2);
        let fin = enlace.parar();
        assert_eq!(fin.rechazados_por_servidor, 1);
        assert!(fin.cuadra(), "{fin:?}");
        assert_eq!(srv.lock().unwrap().recibidos, ["b", "c"]);
    }

    #[test]
    fn lo_que_no_cabe_se_cuenta_y_la_cuenta_cuadra() {
        let srv: Compartida = Arc::default();
        let cfg = ConfigEnlace {
            capacidad_elementos: 3,
            ..cfg_rapida()
        };
        let enlace = arrancar(&srv, cfg);
        for i in 0..10 {
            enlace.ofrecer(item(&format!("v{i}"), 1, 50));
        }
        let i = enlace.instantanea();
        assert_eq!((i.en_cola, i.perdidos_por_tope), (3, 7));
        assert!(i.cuadra(), "{i:?}");
        srv.lock().unwrap().vivo = true;
        esperar("lo que cupo llega", || enlace.instantanea().enviados == 3);
        let fin = enlace.parar();
        assert!(fin.cuadra(), "{fin:?}");
        assert!(fin.json().contains("\"tope\":7"));
    }

    #[test]
    fn parar_no_espera_al_retroceso() {
        let srv: Compartida = Arc::default();
        let cfg = ConfigEnlace {
            reintento_base: Duration::from_secs(30),
            reintento_tope: Duration::from_secs(60),
            ..cfg_rapida()
        };
        let enlace = arrancar(&srv, cfg);
        enlace.ofrecer(item("pendiente", 1, 50));
        esperar("primer fallo", || enlace.instantanea().fallos_conexion >= 1);
        let t = Instant::now();
        let fin = enlace.parar();
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        // Lo que no se entrego queda dicho, no borrado.
        assert_eq!(fin.en_cola, 1);
        assert!(fin.cuadra());
    }

    #[test]
    fn el_estado_del_agente_viaja_envuelto_y_acotado() {
        let srv: Compartida = Arc::default();
        srv.lock().unwrap().vivo = true;
        let enlace = arrancar(&srv, cfg_rapida());
        enlace.publicar_estado("{\"motores\":3}".to_string());
        esperar("estado con el agente", || {
            srv.lock()
                .unwrap()
                .estados
                .iter()
                .any(|e| e.starts_with("{\"agente\":{\"motores\":3},\"enlace\":{"))
        });
        enlace.publicar_estado("x".repeat(MAX_ESTADO_AGENTE + 1));
        esperar("estado recortado", || {
            srv.lock()
                .unwrap()
                .estados
                .iter()
                .any(|e| e.contains("\"recortado\":true"))
        });
        drop(enlace);
    }
}
