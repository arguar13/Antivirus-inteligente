//! Protocolo de control entre `aegisctl` y el agente.
//!
//! # Por que un formato de texto y una conexion por peticion
//!
//! El canal de control es local (un socket Unix) y de bajo volumen: un operador
//! escribe `aegisctl status` de vez en cuando. No hay ninguna necesidad de un
//! formato binario ni de multiplexar peticiones en una conexion. Un protocolo
//! de texto, una peticion por conexion, es inspeccionable con `socat` y trivial
//! de razonar: se lee una linea de peticion, se escribe la respuesta, se cierra.
//!
//! # Formato
//!
//! Peticion: una linea, campos separados por tabulador.
//! ```text
//! status
//! scan\t/ruta/absoluta
//! isolate\tcontainment
//! quarantine\tlist
//! ```
//!
//! Respuesta: primera linea `OK` o `ERR\t<motivo>`, y a continuacion un cuerpo
//! de lineas `clave=valor` o de elementos, segun el comando. La conexion se
//! cierra al terminar, asi que el cliente lee hasta el fin de flujo.

use std::fmt;

/// Modo de aislamiento de red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolateMode {
    /// Deja abierta la ruta de administracion (para no perder el acceso remoto).
    Containment,
    /// Corta todo el trafico salvo loopback.
    Total,
}

impl IsolateMode {
    /// Nombre en el protocolo.
    pub fn as_str(self) -> &'static str {
        match self {
            IsolateMode::Containment => "containment",
            IsolateMode::Total => "total",
        }
    }

    /// Analiza el nombre.
    pub fn parse(s: &str) -> Option<IsolateMode> {
        match s {
            "containment" => Some(IsolateMode::Containment),
            "total" => Some(IsolateMode::Total),
            _ => None,
        }
    }
}

/// Peticion de control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Estado de recursos y del pipeline.
    Status,
    /// Escaneo bajo demanda de una ruta.
    Scan {
        /// Ruta absoluta a escanear.
        path: String,
    },
    /// Aislamiento de red de emergencia.
    Isolate {
        /// Modo.
        mode: IsolateMode,
    },
    /// Listado de la cuarentena.
    QuarantineList,
}

impl Request {
    /// Serializa la peticion a su linea de protocolo.
    pub fn encode(&self) -> String {
        match self {
            Request::Status => "status".to_string(),
            Request::Scan { path } => format!("scan\t{path}"),
            Request::Isolate { mode } => format!("isolate\t{}", mode.as_str()),
            Request::QuarantineList => "quarantine\tlist".to_string(),
        }
    }

    /// Analiza una linea de peticion.
    pub fn parse(linea: &str) -> Result<Request, ProtocolError> {
        let linea = linea.trim_end_matches(['\n', '\r']);
        let mut it = linea.split('\t');
        let verbo = it.next().unwrap_or("");
        match verbo {
            "status" => Ok(Request::Status),
            "scan" => {
                let path = it
                    .next()
                    .ok_or(ProtocolError::MissingArg("scan requiere una ruta"))?;
                if path.is_empty() {
                    return Err(ProtocolError::MissingArg("scan requiere una ruta"));
                }
                Ok(Request::Scan {
                    path: path.to_string(),
                })
            }
            "isolate" => {
                let m = it
                    .next()
                    .ok_or(ProtocolError::MissingArg("isolate requiere un modo"))?;
                let mode =
                    IsolateMode::parse(m).ok_or(ProtocolError::BadValue("modo de aislamiento"))?;
                Ok(Request::Isolate { mode })
            }
            "quarantine" => match it.next() {
                Some("list") => Ok(Request::QuarantineList),
                _ => Err(ProtocolError::BadValue("subcomando de quarantine")),
            },
            otro => Err(ProtocolError::UnknownVerb(otro.to_string())),
        }
    }
}

/// Respuesta de control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Estado del agente.
    Status(StatusInfo),
    /// Resultado de un escaneo.
    Scan(ScanInfo),
    /// Resultado de un aislamiento.
    Isolated(IsolateInfo),
    /// Listado de cuarentena.
    Quarantine(Vec<String>),
    /// Error atendiendo la peticion.
    Error(String),
}

/// Estado de recursos y del pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusInfo {
    /// Memoria residente en KB.
    pub rss_kb: u64,
    /// Segundos desde el arranque.
    pub uptime_s: u64,
    /// Eventos recibidos del kernel.
    pub events_received: u64,
    /// Eventos escalados al motor de heuristica.
    pub events_escalated: u64,
    /// Estado textual (p. ej. "running", "isolated").
    pub state: String,
    /// El detalle del agente, una linea por pieza: el arbitro y su camino
    /// caliente, cada motor con su latencia y sus «sin datos», el trabajador
    /// confinado y la perdida de eventos por familia. Son las mismas lineas que
    /// el agente publica en su registro, en su ultimo informe.
    pub detalle: Vec<String>,
}

/// Resultado de un escaneo bajo demanda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanInfo {
    /// Ruta escaneada.
    pub path: String,
    /// Si hubo deteccion.
    pub detected: bool,
    /// Reglas que dispararon.
    pub rules: Vec<String>,
}

/// Resultado de un aislamiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolateInfo {
    /// Modo aplicado.
    pub mode: String,
    /// Si se aplico de verdad o fue simulacro.
    pub applied: bool,
    /// Numero de reglas del conjunto aplicado.
    pub rule_lines: usize,
}

impl Response {
    /// Serializa la respuesta al formato de texto.
    pub fn encode(&self) -> String {
        match self {
            Response::Status(s) => {
                let mut out = format!(
                    "OK\nrss_kb={}\nuptime_s={}\nevents_received={}\nevents_escalated={}\nstate={}\n",
                    s.rss_kb, s.uptime_s, s.events_received, s.events_escalated, s.state
                );
                for d in &s.detalle {
                    // Una linea de protocolo por linea de detalle: un salto de
                    // linea dentro partiria la respuesta.
                    out.push_str(&format!("detalle={}\n", d.replace(['\n', '\r'], " ")));
                }
                out
            }
            Response::Scan(s) => {
                let mut out = format!("OK\npath={}\ndetected={}\n", s.path, s.detected);
                for r in &s.rules {
                    out.push_str(&format!("rule={r}\n"));
                }
                out
            }
            Response::Isolated(i) => format!(
                "OK\nmode={}\napplied={}\nrule_lines={}\n",
                i.mode, i.applied, i.rule_lines
            ),
            Response::Quarantine(ids) => {
                let mut out = String::from("OK\n");
                for id in ids {
                    out.push_str(&format!("id={id}\n"));
                }
                out
            }
            Response::Error(msg) => format!("ERR\t{msg}\n"),
        }
    }

    /// Analiza una respuesta recibida.
    pub fn parse(texto: &str) -> Result<Response, ProtocolError> {
        let mut lineas = texto.lines();
        let cabecera = lineas.next().unwrap_or("");
        if let Some(motivo) = cabecera.strip_prefix("ERR") {
            return Ok(Response::Error(motivo.trim_start_matches('\t').to_string()));
        }
        if cabecera != "OK" {
            return Err(ProtocolError::BadValue("cabecera de respuesta"));
        }

        let mut mapa: Vec<(String, String)> = Vec::new();
        for l in lineas {
            if let Some((k, v)) = l.split_once('=') {
                mapa.push((k.to_string(), v.to_string()));
            }
        }
        let get = |clave: &str| {
            mapa.iter()
                .find(|(k, _)| k == clave)
                .map(|(_, v)| v.clone())
        };
        let todos = |clave: &str| -> Vec<String> {
            mapa.iter()
                .filter(|(k, _)| k == clave)
                .map(|(_, v)| v.clone())
                .collect()
        };

        // Se infiere el tipo por las claves presentes.
        if let Some(state) = get("state") {
            return Ok(Response::Status(StatusInfo {
                rss_kb: get("rss_kb").and_then(|v| v.parse().ok()).unwrap_or(0),
                uptime_s: get("uptime_s").and_then(|v| v.parse().ok()).unwrap_or(0),
                events_received: get("events_received")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                events_escalated: get("events_escalated")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                state,
                detalle: todos("detalle"),
            }));
        }
        if let Some(detected) = get("detected") {
            return Ok(Response::Scan(ScanInfo {
                path: get("path").unwrap_or_default(),
                detected: detected == "true",
                rules: todos("rule"),
            }));
        }
        if let Some(mode) = get("mode") {
            return Ok(Response::Isolated(IsolateInfo {
                mode,
                applied: get("applied").map(|v| v == "true").unwrap_or(false),
                rule_lines: get("rule_lines").and_then(|v| v.parse().ok()).unwrap_or(0),
            }));
        }
        // OK sin claves de otro tipo: es un listado de cuarentena (posiblemente
        // vacio).
        Ok(Response::Quarantine(todos("id")))
    }
}

/// Error de protocolo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// Verbo desconocido.
    #[error("comando desconocido: {0:?}")]
    UnknownVerb(String),
    /// Falta un argumento obligatorio.
    #[error("{0}")]
    MissingArg(&'static str),
    /// Valor invalido.
    #[error("valor invalido: {0}")]
    BadValue(&'static str),
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}
