//! Códec protobuf sobre el cable y los mensajes del servicio de flota.
//!
//! # Por que a mano y no con `prost`/`protoc`
//!
//! El formato de cable de Protocol Buffers es pequeno y estable: varints,
//! campos con etiqueta y campos delimitados por longitud. Generarlo desde un
//! `.proto` exige `protoc`, que no esta en la maquina de integracion, y arrastra
//! una cadena de dependencias grande. Aqui se implementa el formato REAL de
//! cable —el mismo que produce cualquier compilador de protobuf— en lo justo
//! para los mensajes del servicio. Es interoperable byte a byte con un cliente
//! protobuf de verdad; lo prueban las vueltas de ida y vuelta de `tests/proto`.
//!
//! # El formato, en una frase
//!
//! Cada campo es una etiqueta varint `(numero << 3) | tipo` seguida del valor:
//! tipo 0 = varint (enteros, booleanos), tipo 2 = delimitado por longitud
//! (cadenas y bytes: una longitud varint y luego los bytes).

use crate::error::{FleetError, Resultado};

/// Tipo de cable: varint (enteros y booleanos).
const WIRE_VARINT: u64 = 0;
/// Tipo de cable: delimitado por longitud (cadenas y bytes).
const WIRE_BYTES: u64 = 2;

// --- Primitivas del formato de cable ----------------------------------------

/// Anade un `u64` en formato varint (base 128, bit de continuacion).
pub fn escribir_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Anade la etiqueta de un campo.
fn escribir_tag(buf: &mut Vec<u8>, numero: u64, tipo: u64) {
    escribir_varint(buf, (numero << 3) | tipo);
}

/// Anade un campo entero (varint).
pub fn escribir_u64(buf: &mut Vec<u8>, numero: u64, v: u64) {
    if v == 0 {
        return; // los ceros no se serializan (semantica de protobuf proto3)
    }
    escribir_tag(buf, numero, WIRE_VARINT);
    escribir_varint(buf, v);
}

/// Anade un campo booleano.
pub fn escribir_bool(buf: &mut Vec<u8>, numero: u64, v: bool) {
    if v {
        escribir_tag(buf, numero, WIRE_VARINT);
        escribir_varint(buf, 1);
    }
}

/// Anade un campo de bytes (delimitado por longitud).
pub fn escribir_bytes(buf: &mut Vec<u8>, numero: u64, datos: &[u8]) {
    if datos.is_empty() {
        return;
    }
    escribir_tag(buf, numero, WIRE_BYTES);
    escribir_varint(buf, datos.len() as u64);
    buf.extend_from_slice(datos);
}

/// Anade un campo de cadena.
pub fn escribir_str(buf: &mut Vec<u8>, numero: u64, s: &str) {
    escribir_bytes(buf, numero, s.as_bytes());
}

/// Lector de una trama protobuf, campo a campo.
pub struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

/// Un campo leido: su numero y su valor sin interpretar.
pub enum Campo<'a> {
    /// Valor entero (tipo varint).
    Entero(u64, u64),
    /// Valor de bytes (tipo delimitado por longitud).
    Bytes(u64, &'a [u8]),
}

impl<'a> Lector<'a> {
    /// Crea un lector sobre una trama.
    pub fn nuevo(datos: &'a [u8]) -> Lector<'a> {
        Lector { datos, pos: 0 }
    }

    /// Lee un varint crudo.
    fn leer_varint(&mut self) -> Resultado<u64> {
        let mut resultado = 0u64;
        let mut desplazamiento = 0u32;
        loop {
            let byte = *self
                .datos
                .get(self.pos)
                .ok_or_else(|| FleetError::Protocolo("varint truncado".into()))?;
            self.pos += 1;
            if desplazamiento >= 64 {
                return Err(FleetError::Protocolo("varint demasiado largo".into()));
            }
            resultado |= ((byte & 0x7f) as u64) << desplazamiento;
            if byte & 0x80 == 0 {
                return Ok(resultado);
            }
            desplazamiento += 7;
        }
    }

    /// Devuelve el siguiente campo, o `None` al terminar la trama.
    pub fn siguiente(&mut self) -> Resultado<Option<Campo<'a>>> {
        if self.pos >= self.datos.len() {
            return Ok(None);
        }
        let etiqueta = self.leer_varint()?;
        let numero = etiqueta >> 3;
        let tipo = etiqueta & 0x7;
        match tipo {
            WIRE_VARINT => Ok(Some(Campo::Entero(numero, self.leer_varint()?))),
            WIRE_BYTES => {
                let len = self.leer_varint()? as usize;
                let fin = self
                    .pos
                    .checked_add(len)
                    .filter(|&f| f <= self.datos.len())
                    .ok_or_else(|| FleetError::Protocolo("campo de bytes truncado".into()))?;
                let bytes = &self.datos[self.pos..fin];
                self.pos = fin;
                Ok(Some(Campo::Bytes(numero, bytes)))
            }
            otro => Err(FleetError::Protocolo(format!(
                "tipo de cable no soportado: {otro}"
            ))),
        }
    }
}

/// Interpreta un campo de bytes como cadena UTF-8.
fn como_str(bytes: &[u8]) -> Resultado<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| FleetError::Protocolo("cadena no es UTF-8 valido".into()))
}

// --- Mensajes del servicio AegisFleet ---------------------------------------

/// `EnrollRequest`: el agente pide entrar en la flota.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SolicitudEnrolamiento {
    /// Identidad estable del agente (CN de su certificado).
    pub id_agente: String,
    /// Nombre de maquina.
    pub hostname: String,
    /// Version del agente.
    pub version_agente: String,
    /// Huella del certificado con el que se conecta.
    pub huella_cert: Vec<u8>,
}

impl SolicitudEnrolamiento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_str(&mut b, 2, &self.hostname);
        escribir_str(&mut b, 3, &self.version_agente);
        escribir_bytes(&mut b, 4, &self.huella_cert);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Bytes(2, v) => m.hostname = como_str(v)?,
                Campo::Bytes(3, v) => m.version_agente = como_str(v)?,
                Campo::Bytes(4, v) => m.huella_cert = v.to_vec(),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EnrollResponse`: la respuesta del plano de control.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RespuestaEnrolamiento {
    /// Si el agente queda enrolado.
    pub aceptado: bool,
    /// Identificador que la flota asigna al agente.
    pub id_flota: String,
    /// Intervalo de latido en segundos.
    pub intervalo_latido_seg: u64,
    /// Motivo del rechazo, si lo hubo.
    pub motivo: String,
}

impl RespuestaEnrolamiento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.aceptado);
        escribir_str(&mut b, 2, &self.id_flota);
        escribir_u64(&mut b, 3, self.intervalo_latido_seg);
        escribir_str(&mut b, 4, &self.motivo);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.aceptado = v != 0,
                Campo::Bytes(2, v) => m.id_flota = como_str(v)?,
                Campo::Entero(3, v) => m.intervalo_latido_seg = v,
                Campo::Bytes(4, v) => m.motivo = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `Heartbeat`: el pulso periodico del agente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latido {
    /// Identidad del agente.
    pub id_agente: String,
    /// Instante Unix del latido.
    pub momento_unix: u64,
    /// Memoria residente del agente, en KiB.
    pub rss_kb: u64,
    /// Amenazas activas en el endpoint.
    pub amenazas_activas: u64,
    /// Version de politica que el agente tiene cargada.
    pub version_politica: u64,
}

impl Latido {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.momento_unix);
        escribir_u64(&mut b, 3, self.rss_kb);
        escribir_u64(&mut b, 4, self.amenazas_activas);
        escribir_u64(&mut b, 5, self.version_politica);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.momento_unix = v,
                Campo::Entero(3, v) => m.rss_kb = v,
                Campo::Entero(4, v) => m.amenazas_activas = v,
                Campo::Entero(5, v) => m.version_politica = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `HeartbeatAck`: la respuesta al latido.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckLatido {
    /// Si el plano de control recibio el latido.
    pub recibido: bool,
    /// Ultima version de politica disponible en la flota.
    pub version_politica_disponible: u64,
    /// Si hay un comando encolado para el agente.
    pub hay_comando: bool,
}

impl AckLatido {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_u64(&mut b, 2, self.version_politica_disponible);
        escribir_bool(&mut b, 3, self.hay_comando);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Entero(2, v) => m.version_politica_disponible = v,
                Campo::Entero(3, v) => m.hay_comando = v != 0,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EventReport`: el agente reporta un evento de seguridad.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReporteEvento {
    /// Identidad del agente.
    pub id_agente: String,
    /// Severidad (0..=3).
    pub severidad: u64,
    /// Categoria (p. ej. "ransomware", "syscall-directa").
    pub categoria: String,
    /// Descripcion legible.
    pub descripcion: String,
    /// Instante Unix del evento.
    pub momento_unix: u64,
    /// Atributos estructurados del hallazgo, como objeto JSON.
    ///
    /// POR QUE HACE FALTA ADEMAS DE LA DESCRIPCION
    /// -------------------------------------------
    /// La descripcion es para que la lea una persona. Correlacionar entre
    /// endpoints necesita algo con lo que AGRUPAR: la cuenta bajo la que se
    /// ejecuto, el hash del binario, la direccion de destino. Sacar eso de la
    /// descripcion con expresiones regulares en el plano de control seria
    /// convertir un texto libre —que cada detector escribe a su manera y que
    /// cambia con cada version del agente— en el eje de una deteccion.
    ///
    /// Vacio es valido y significa "este detector no aporta atributos": una
    /// heuristica que agrupe por un atributo que falta simplemente no ve esa
    /// alerta, que es lo correcto. Lo que no puede pasar es que se la invente.
    pub detalles_json: String,
}

impl ReporteEvento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.severidad);
        escribir_str(&mut b, 3, &self.categoria);
        escribir_str(&mut b, 4, &self.descripcion);
        escribir_u64(&mut b, 5, self.momento_unix);
        escribir_str(&mut b, 6, &self.detalles_json);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.severidad = v,
                Campo::Bytes(3, v) => m.categoria = como_str(v)?,
                Campo::Bytes(4, v) => m.descripcion = como_str(v)?,
                Campo::Entero(5, v) => m.momento_unix = v,
                Campo::Bytes(6, v) => m.detalles_json = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EventAck`: acuse del reporte de evento.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckEvento {
    /// Si el evento se registro.
    pub recibido: bool,
    /// Identificador de incidente asignado.
    pub id_incidente: String,
}

impl AckEvento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_str(&mut b, 2, &self.id_incidente);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Bytes(2, v) => m.id_incidente = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// FASE 38: telemetria de inteligencia y empuje de politica
// ---------------------------------------------------------------------------

/// Numero maximo de nodos que se aceptan en un grafo.
///
/// El tamano de trama ya acota la memoria, pero un limite explicito sobre el
/// NUMERO de nodos protege ademas el coste de insertarlos en la base de datos:
/// un agente comprometido no debe poder convertir un reporte en una carga de
/// escritura arbitraria sobre el plano de control.
pub const MAX_NODOS_GRAFO: usize = 4096;

/// `StixReport`: el agente entrega un bundle STIX 2.1 completo.
///
/// El bundle viaja como JSON porque STIX 2.1 ES JSON: reempaquetarlo en campos
/// protobuf obligaria a mantener aqui un esquema paralelo al estandar y a
/// reconstruirlo en el servidor, con la garantia de divergir en cuanto el
/// estandar evolucione. Se transporta tal cual lo genera `aegis-forensics`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReporteStix {
    /// Identidad del agente que lo envia.
    pub id_agente: String,
    /// Bundle STIX 2.1 serializado en JSON.
    pub bundle_json: String,
    /// Momento de generacion en el endpoint.
    pub momento_unix: u64,
}

impl ReporteStix {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_str(&mut b, 2, &self.bundle_json);
        escribir_u64(&mut b, 3, self.momento_unix);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Bytes(2, v) => m.bundle_json = como_str(v)?,
                Campo::Entero(3, v) => m.momento_unix = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `StixAck`: acuse de la ingesta del bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckStix {
    /// Si el bundle se ingirio.
    pub recibido: bool,
    /// Cuantos objetos STIX se dieron de alta.
    pub objetos_ingeridos: u64,
    /// Motivo del rechazo, si lo hubo.
    pub motivo: String,
}

impl AckStix {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_u64(&mut b, 2, self.objetos_ingeridos);
        escribir_str(&mut b, 3, &self.motivo);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Entero(2, v) => m.objetos_ingeridos = v,
                Campo::Bytes(3, v) => m.motivo = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// Un nodo del grafo de linaje de procesos.
///
/// Refleja el `ProcessNode` del agente. La clave NO es un PID: los PID se
/// reciclan, y un ataque que espere al reciclado consigue que la telemetria
/// atribuya sus acciones a un proceso inocente ya terminado. La clave deriva de
/// `(pid, start_boottime)`, cuyo par no se repite en la vida del sistema.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodoProceso {
    /// Identidad estable del proceso.
    pub clave: u64,
    /// PID observado (informativo).
    pub pid: u32,
    /// Clave del padre.
    pub padre: u64,
    /// Clave del creador real (puede diferir del padre tras un reparento).
    pub creador: u64,
    /// Profundidad en el linaje.
    pub profundidad: u32,
    /// Ruta de la imagen ejecutada.
    pub imagen: String,
    /// Linea de comandos.
    pub cmdline: String,
    /// Clase de imagen segun la clasificacion del agente.
    pub clase: u32,
    /// Instante de arranque en nanosegundos de monotonico.
    pub iniciado_ns: u64,
    /// Instante de salida, 0 si sigue vivo.
    pub terminado_ns: u64,
    /// Marcas de contaminacion propagadas.
    pub taints: u32,
    /// Puntuacion de comportamiento acumulada.
    pub puntuacion: u32,
}

impl NodoProceso {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_u64(&mut b, 1, self.clave);
        escribir_u64(&mut b, 2, self.pid as u64);
        escribir_u64(&mut b, 3, self.padre);
        escribir_u64(&mut b, 4, self.creador);
        escribir_u64(&mut b, 5, self.profundidad as u64);
        escribir_str(&mut b, 6, &self.imagen);
        escribir_str(&mut b, 7, &self.cmdline);
        escribir_u64(&mut b, 8, self.clase as u64);
        escribir_u64(&mut b, 9, self.iniciado_ns);
        escribir_u64(&mut b, 10, self.terminado_ns);
        escribir_u64(&mut b, 11, self.taints as u64);
        escribir_u64(&mut b, 12, self.puntuacion as u64);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.clave = v,
                Campo::Entero(2, v) => m.pid = v as u32,
                Campo::Entero(3, v) => m.padre = v,
                Campo::Entero(4, v) => m.creador = v,
                Campo::Entero(5, v) => m.profundidad = v as u32,
                Campo::Bytes(6, v) => m.imagen = como_str(v)?,
                Campo::Bytes(7, v) => m.cmdline = como_str(v)?,
                Campo::Entero(8, v) => m.clase = v as u32,
                Campo::Entero(9, v) => m.iniciado_ns = v,
                Campo::Entero(10, v) => m.terminado_ns = v,
                Campo::Entero(11, v) => m.taints = v as u32,
                Campo::Entero(12, v) => m.puntuacion = v as u32,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `GraphReport`: el subgrafo de linaje que rodea a una deteccion.
///
/// Una deteccion aislada casi nunca concluye nada: `python` abriendo un socket
/// es rutina; `libreoffice -> sh -> python` abriendo un socket es un incidente.
/// Por eso el agente no envia el proceso culpable, sino su linaje.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReporteGrafo {
    /// Identidad del agente.
    pub id_agente: String,
    /// Clave del nodo que disparo el reporte.
    pub raiz: u64,
    /// Momento de captura en el endpoint.
    pub momento_unix: u64,
    /// Nodos del subgrafo.
    pub nodos: Vec<NodoProceso>,
}

impl ReporteGrafo {
    /// Serializa al formato de cable.
    ///
    /// Los nodos van como campo repetido delimitado por longitud, que es
    /// exactamente como protobuf codifica un `repeated message`.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.raiz);
        escribir_u64(&mut b, 3, self.momento_unix);
        for nodo in &self.nodos {
            escribir_bytes(&mut b, 4, &nodo.codificar());
        }
        b
    }

    /// Deserializa desde el formato de cable.
    ///
    /// Rechaza un grafo con mas nodos de los permitidos ANTES de haberlos
    /// materializado todos: el limite no sirve de nada si para comprobarlo hay
    /// que reservar primero la memoria que se queria acotar.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.raiz = v,
                Campo::Entero(3, v) => m.momento_unix = v,
                Campo::Bytes(4, v) => {
                    if m.nodos.len() >= MAX_NODOS_GRAFO {
                        return Err(FleetError::Protocolo(format!(
                            "el grafo excede los {MAX_NODOS_GRAFO} nodos permitidos"
                        )));
                    }
                    m.nodos.push(NodoProceso::decodificar(v)?);
                }
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `GraphAck`: acuse del subgrafo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckGrafo {
    /// Si el grafo se ingirio.
    pub recibido: bool,
    /// Identificador asignado al grafo.
    pub id_grafo: String,
    /// Numero de nodos dados de alta.
    pub nodos_ingeridos: u64,
}

impl AckGrafo {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_str(&mut b, 2, &self.id_grafo);
        escribir_u64(&mut b, 3, self.nodos_ingeridos);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Bytes(2, v) => m.id_grafo = como_str(v)?,
                Campo::Entero(3, v) => m.nodos_ingeridos = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `PolicySubscribe`: el agente abre un canal para RECIBIR politica.
///
/// A diferencia de las demas llamadas, esta no se responde y se cierra: la
/// conexion queda abierta y el servidor escribe por ella cuando hay algo que
/// entregar. Es lo que convierte la entrega de politica en un EMPUJE real —el
/// endpoint se entera en milisegundos de que el operador bloqueo un puerto— en
/// vez de esperar al siguiente latido.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuscripcionPolitica {
    /// Identidad del agente.
    pub id_agente: String,
    /// Version de politica que el agente ya tiene aplicada.
    pub version_conocida: u64,
}

impl SuscripcionPolitica {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.version_conocida);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.version_conocida = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `ServerPush`: lo que el servidor escribe por el canal de suscripcion.
///
/// POR QUE LA CAZA VIAJA POR ESTE MISMO CANAL
/// ------------------------------------------
/// Difundir una consulta de caza a la flota es exactamente el mismo problema
/// que empujar una politica: llegar a decenas de miles de endpoints en
/// milisegundos, sin esperar a su siguiente latido.
///
/// Ese canal YA existe, ya esta abierto contra cada agente, ya tiene latido
/// propio, y su coste esta MEDIDO: 10.000 canales simultaneos cuestan 10.006
/// hilos y 10.046 descriptores en el servidor (FASE 41, docs/36-carga.md).
/// Abrir un segundo canal por agente para las cacerias duplicaria exactamente
/// ese coste a cambio de nada. Se reutiliza.
///
/// Los campos nuevos no rompen a un agente antiguo: el decodificador ignora los
/// campos que no conoce, asi que uno que no entienda de cazas seguira aplicando
/// politica igual que antes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmpujePolitica {
    /// Version de la politica que se entrega.
    pub version: u64,
    /// Politica en JSON (reglas globales).
    pub politica_json: String,
    /// Comandos dirigidos a ESTE agente, en JSON.
    pub comandos_json: String,
    /// Identificador de la caceria, si este empuje lleva una.
    ///
    /// Vacio cuando el empuje es solo de politica. El agente lo devuelve con
    /// los resultados para que el plano de control sepa a que caceria
    /// corresponden: sin el, dos cacerias lanzadas con segundos de diferencia
    /// mezclarian sus respuestas.
    pub caza_id: String,
    /// Consulta AegisQL a ejecutar.
    pub caza_ql: String,
    /// Direcciones que este endpoint debe dejar de atender, separadas por coma.
    ///
    /// Es el CONJUNTO COMPLETO vigente, no un incremento. Enviar incrementos
    /// obligaria a que los dos extremos estuvieran de acuerdo sobre cuales se
    /// aplicaron ya, y un mensaje perdido dejaria a un endpoint con una regla
    /// de firewall que nadie recuerda haber puesto —o, peor, sin una que
    /// creemos puesta—. Con el conjunto completo, cada empuje deja al endpoint
    /// en un estado conocido, y una reconexion basta para reconciliar.
    ///
    /// El campo `cuarentena_valida` distingue "no hay ninguna" de "este empuje
    /// no habla de cuarentena", que en un mecanismo de contencion no pueden
    /// confundirse: interpretar lo segundo como lo primero levantaria todas las
    /// cuarentenas de la flota con un latido de canal.
    pub cuarentena: String,
    /// Si este empuje lleva estado de cuarentena.
    pub cuarentena_valida: bool,
    /// Si el marco es solo una senal de vida sin contenido nuevo.
    ///
    /// Un canal que solo habla cuando hay novedades es indistinguible de un
    /// canal muerto. El latido del canal permite a los dos extremos detectar la
    /// caida sin esperar al plazo del sistema operativo.
    pub es_keepalive: bool,
}

impl EmpujePolitica {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_u64(&mut b, 1, self.version);
        escribir_str(&mut b, 2, &self.politica_json);
        escribir_str(&mut b, 3, &self.comandos_json);
        escribir_bool(&mut b, 4, self.es_keepalive);
        escribir_str(&mut b, 5, &self.caza_id);
        escribir_str(&mut b, 6, &self.caza_ql);
        escribir_str(&mut b, 7, &self.cuarentena);
        escribir_bool(&mut b, 8, self.cuarentena_valida);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.version = v,
                Campo::Bytes(2, v) => m.politica_json = como_str(v)?,
                Campo::Bytes(3, v) => m.comandos_json = como_str(v)?,
                Campo::Entero(4, v) => m.es_keepalive = v != 0,
                Campo::Bytes(5, v) => m.caza_id = como_str(v)?,
                Campo::Bytes(6, v) => m.caza_ql = como_str(v)?,
                Campo::Bytes(7, v) => m.cuarentena = como_str(v)?,
                Campo::Entero(8, v) => m.cuarentena_valida = v != 0,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// Filas maximas que un agente puede devolver en un informe de caza.
///
/// Coincide con el techo que impone el analizador de AegisQL. Se comprueba
/// tambien aqui, y no solo alli, porque un agente comprometido podria enviar un
/// informe que nunca paso por ese analizador: el plano de control no puede
/// confiar en que el otro extremo respeto un limite.
pub const MAX_FILAS_CAZA: usize = 10_000;

/// Celdas maximas por fila.
pub const MAX_CELDAS_FILA: usize = 32;

/// Una fila de resultado de caza: celdas ya convertidas a texto.
///
/// Se transportan como texto y no con tipos porque el destino es una tabla en
/// una consola: el tipo ya lo declara el esquema de AegisQL, y arrastrar una
/// union por celda multiplicaria el tamano del mensaje por cada fila de cada
/// endpoint sin anadir nada que el analista pueda ver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilaCaza {
    /// Celdas, en el orden de las columnas declaradas.
    pub celdas: Vec<String>,
}

impl FilaCaza {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for c in &self.celdas {
            escribir_str(&mut b, 1, c);
        }
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            if let Campo::Bytes(1, v) = campo {
                if m.celdas.len() >= MAX_CELDAS_FILA {
                    return Err(FleetError::Protocolo(format!(
                        "una fila de caza excede las {MAX_CELDAS_FILA} celdas"
                    )));
                }
                m.celdas.push(como_str(v)?);
            }
        }
        Ok(m)
    }
}

/// `HuntReport`: lo que un agente responde a una caceria.
///
/// Lleva contadores ademas de filas, y esa es la parte que hace util la
/// agregacion: el plano de control puede decirle al analista "9.847 endpoints
/// respondieron, 12 encontraron algo, 3 no pudieron leer parte de su memoria",
/// en vez de una lista de filas sin contexto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReporteCaza {
    /// Identidad del agente.
    pub id_agente: String,
    /// Caceria a la que responde.
    pub caza_id: String,
    /// Nombres de las columnas, en orden.
    pub columnas: Vec<String>,
    /// Filas devueltas.
    pub filas: Vec<FilaCaza>,
    /// Filas que pasaron el filtro, aunque no se devolvieran todas.
    pub coincidencias: u64,
    /// Filas examinadas.
    pub examinadas: u64,
    /// Valores que el endpoint no pudo obtener.
    pub inaccesibles: u64,
    /// Cierto si el resultado se corto por limite o por presupuesto.
    pub incompleto: bool,
    /// Cierto si se corto por PRESUPUESTO: la consulta es demasiado cara aqui.
    pub agotado: bool,
    /// Milisegundos empleados en el endpoint.
    pub duracion_ms: u64,
    /// Motivo por el que el endpoint no pudo ejecutar la consulta, si aplica.
    ///
    /// Un endpoint que rechaza la consulta tiene que DECIRLO. Si se limitara a
    /// no responder, seria indistinguible de uno apagado, y el analista creeria
    /// que su caceria cubrio una flota que en realidad no cubrio.
    pub error: String,
}

impl ReporteCaza {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_str(&mut b, 2, &self.caza_id);
        for c in &self.columnas {
            escribir_str(&mut b, 3, c);
        }
        for f in &self.filas {
            escribir_bytes(&mut b, 4, &f.codificar());
        }
        escribir_u64(&mut b, 5, self.coincidencias);
        escribir_u64(&mut b, 6, self.examinadas);
        escribir_u64(&mut b, 7, self.inaccesibles);
        escribir_bool(&mut b, 8, self.incompleto);
        escribir_bool(&mut b, 9, self.agotado);
        escribir_u64(&mut b, 10, self.duracion_ms);
        escribir_str(&mut b, 11, &self.error);
        b
    }

    /// Deserializa desde el formato de cable.
    ///
    /// El limite de filas se comprueba DURANTE el recorrido y no despues: un
    /// limite que para comprobarse exige haber reservado ya la memoria que se
    /// queria acotar no protege de nada.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Bytes(2, v) => m.caza_id = como_str(v)?,
                Campo::Bytes(3, v) => {
                    if m.columnas.len() >= MAX_CELDAS_FILA {
                        return Err(FleetError::Protocolo(format!(
                            "un informe de caza excede las {MAX_CELDAS_FILA} columnas"
                        )));
                    }
                    m.columnas.push(como_str(v)?);
                }
                Campo::Bytes(4, v) => {
                    if m.filas.len() >= MAX_FILAS_CAZA {
                        return Err(FleetError::Protocolo(format!(
                            "un informe de caza excede las {MAX_FILAS_CAZA} filas"
                        )));
                    }
                    m.filas.push(FilaCaza::decodificar(v)?);
                }
                Campo::Entero(5, v) => m.coincidencias = v,
                Campo::Entero(6, v) => m.examinadas = v,
                Campo::Entero(7, v) => m.inaccesibles = v,
                Campo::Entero(8, v) => m.incompleto = v != 0,
                Campo::Entero(9, v) => m.agotado = v != 0,
                Campo::Entero(10, v) => m.duracion_ms = v,
                Campo::Bytes(11, v) => m.error = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `HuntAck`: acuse del informe de caza.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckCaza {
    /// Si el informe se acepto.
    pub recibido: bool,
    /// Motivo del rechazo, si lo hubo.
    pub motivo: String,
}

impl AckCaza {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_str(&mut b, 2, &self.motivo);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Bytes(2, v) => m.motivo = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}
