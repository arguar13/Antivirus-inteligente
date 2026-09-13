//! El canal entre el invitado y el anfitrion, y por que es como es.
//!
//! # La propiedad de seguridad de la fase, en una frase
//!
//! **El invitado puede contar lo que le pasa. No puede pedir nada.**
//!
//! La maquina que esta al otro lado de este canal se esta infectando a
//! proposito: la muestra corre ahi con los mismos permisos que el agente
//! invitado, y en cuanto escala los tiene todos. Cualquier via por la que el
//! invitado pudiera ordenar algo al anfitrion —«abre este fichero», «ejecuta
//! esto», «apagame»— seria una fuga del sandbox implementada por nosotros.
//!
//! Eso no se resuelve con una comprobacion en el anfitrion, se resuelve con el
//! **tipo**: [`Evento`] no tiene ni una variante que sea una orden, y el lector
//! del anfitrion no devuelve otra cosa. No hay nada que validar porque no hay
//! nada que ejecutar.
//!
//! # Todo lo que llega por aqui lo escribe el malware
//!
//! La traza la produce un proceso que la muestra puede haber comprometido. Por
//! tanto, y sin excepcion:
//!
//! - **Toda longitud tiene tope.** Un `u32` de longitud sin cota es la forma mas
//!   corta de escribir una denegacion de servicio por memoria contra el propio
//!   analizador.
//! - **Toda cadena puede no ser UTF-8.** Una ruta de Linux es una secuencia de
//!   bytes sin codificacion, y el malware la elige. No se rechaza: se **escapa**,
//!   porque tirar el evento perderia justo la evidencia que se buscaba.
//! - **Toda trama lleva numero de secuencia.** Un hueco significa que el invitado
//!   dejo de hablar —lo mataron, se colgo, se le lleno el canal— y eso es un dato
//!   del informe, no un motivo para abortar. Abortar convertiria «el malware mata
//!   al trazador» en «no hay informe», que es exactamente lo que el malware
//!   quiere.
//!
//! # Formato
//!
//! ```text
//!   magia[4] version[2] tipo[2] secuencia[8] largo[4] carga[largo]
//! ```
//!
//! Longitudes fijas y orden explicito: el mismo manifiesto tiene que dar los
//! mismos bytes en el invitado y en el anfitrion, que se compilan por separado.

/// Marca de trama.
pub const MAGIA: [u8; 4] = *b"AEGD";

/// Version del protocolo.
///
/// Una trama de version desconocida **no se interpreta**: leer mal los campos
/// produciria una traza silenciosamente equivocada, que es peor que no tenerla.
pub const VERSION: u16 = 1;

/// Bytes de la cabecera de trama.
pub const CABECERA: usize = 4 + 2 + 2 + 8 + 4;

/// Carga maxima de una trama, en bytes.
///
/// Ningun evento de traza legitimo necesita mas: la ruta mas larga de Linux son
/// 4096 bytes y el argumento mas largo de una llamada cabe de sobra. El tope
/// existe porque el campo de longitud lo escribe el malware.
pub const MAX_CARGA: usize = 64 * 1024;

/// Bytes maximos de una cadena dentro de una carga.
pub const MAX_CADENA: usize = 4096;

/// Elementos maximos de una lista dentro de una carga.
pub const MAX_LISTA: usize = 256;

/// Clase de evento. Es el campo `tipo` de la trama.
///
/// **Ninguna es una orden.** Si alguna vez alguien anade una que lo sea, habra
/// abierto una fuga del sandbox, y por eso la lista esta aqui y no repartida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clase {
    /// El invitado arranco y esta listo.
    Preparado,
    /// Un proceso nacio, ejecuto o murio.
    Proceso,
    /// Acceso a fichero.
    Fichero,
    /// Actividad de red.
    Red,
    /// Llamada al sistema sin clasificar.
    Llamada,
    /// El invitado marca el final de la detonacion.
    Fin,
    /// El invitado no pudo seguir trazando y dice por que.
    Degradado,
}

impl Clase {
    /// Discriminante en el cable. Cambiarlo obliga a subir [`VERSION`].
    #[must_use]
    pub fn tag(self) -> u16 {
        match self {
            Clase::Preparado => 1,
            Clase::Proceso => 2,
            Clase::Fichero => 3,
            Clase::Red => 4,
            Clase::Llamada => 5,
            Clase::Fin => 6,
            Clase::Degradado => 7,
        }
    }

    /// Recupera la clase de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u16) -> Option<Clase> {
        match t {
            1 => Some(Clase::Preparado),
            2 => Some(Clase::Proceso),
            3 => Some(Clase::Fichero),
            4 => Some(Clase::Red),
            5 => Some(Clase::Llamada),
            6 => Some(Clase::Fin),
            7 => Some(Clase::Degradado),
            _ => None,
        }
    }

    /// Nombre estable para el informe.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Clase::Preparado => "preparado",
            Clase::Proceso => "proceso",
            Clase::Fichero => "fichero",
            Clase::Red => "red",
            Clase::Llamada => "llamada",
            Clase::Fin => "fin",
            Clase::Degradado => "degradado",
        }
    }
}

/// Que le paso a un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccionProceso {
    /// Se creo (`fork`, `clone`).
    Nace,
    /// Cambio de imagen (`execve`).
    Ejecuta,
    /// Termino.
    Muere,
}

impl AccionProceso {
    /// Discriminante en el cable.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            AccionProceso::Nace => 1,
            AccionProceso::Ejecuta => 2,
            AccionProceso::Muere => 3,
        }
    }

    /// Recupera la accion de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<AccionProceso> {
        match t {
            1 => Some(AccionProceso::Nace),
            2 => Some(AccionProceso::Ejecuta),
            3 => Some(AccionProceso::Muere),
            _ => None,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            AccionProceso::Nace => "nace",
            AccionProceso::Ejecuta => "ejecuta",
            AccionProceso::Muere => "muere",
        }
    }
}

/// Que le paso a un fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccionFichero {
    /// Se abrio para lectura.
    Lee,
    /// Se abrio o se uso para escritura.
    Escribe,
    /// Se borro.
    Borra,
    /// Se renombro.
    Renombra,
    /// Se le cambiaron los permisos.
    Permisos,
}

impl AccionFichero {
    /// Discriminante en el cable.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            AccionFichero::Lee => 1,
            AccionFichero::Escribe => 2,
            AccionFichero::Borra => 3,
            AccionFichero::Renombra => 4,
            AccionFichero::Permisos => 5,
        }
    }

    /// Recupera la accion de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<AccionFichero> {
        match t {
            1 => Some(AccionFichero::Lee),
            2 => Some(AccionFichero::Escribe),
            3 => Some(AccionFichero::Borra),
            4 => Some(AccionFichero::Renombra),
            5 => Some(AccionFichero::Permisos),
            _ => None,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            AccionFichero::Lee => "lee",
            AccionFichero::Escribe => "escribe",
            AccionFichero::Borra => "borra",
            AccionFichero::Renombra => "renombra",
            AccionFichero::Permisos => "permisos",
        }
    }
}

/// Que intento hacer en la red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccionRed {
    /// Abrio un socket.
    Socket,
    /// Intento conectar.
    Conecta,
    /// Se puso a escuchar.
    Escucha,
    /// Envio datos.
    Envia,
    /// Resolvio un nombre.
    Resuelve,
}

impl AccionRed {
    /// Discriminante en el cable.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            AccionRed::Socket => 1,
            AccionRed::Conecta => 2,
            AccionRed::Escucha => 3,
            AccionRed::Envia => 4,
            AccionRed::Resuelve => 5,
        }
    }

    /// Recupera la accion de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<AccionRed> {
        match t {
            1 => Some(AccionRed::Socket),
            2 => Some(AccionRed::Conecta),
            3 => Some(AccionRed::Escucha),
            4 => Some(AccionRed::Envia),
            5 => Some(AccionRed::Resuelve),
            _ => None,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            AccionRed::Socket => "socket",
            AccionRed::Conecta => "conecta",
            AccionRed::Escucha => "escucha",
            AccionRed::Envia => "envia",
            AccionRed::Resuelve => "resuelve",
        }
    }
}

/// Un hecho observado dentro del invitado.
///
/// No hay ninguna variante que sea una orden, y esa ausencia **es** la frontera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evento {
    /// El agente invitado esta en marcha.
    Preparado {
        /// Version del agente invitado, para cuadrar informes entre revisiones.
        version: String,
    },
    /// Un proceso nacio, ejecuto o murio.
    Proceso {
        /// PID dentro del invitado.
        pid: i32,
        /// PID del padre.
        padre: i32,
        /// Que le paso.
        accion: AccionProceso,
        /// Imagen o nombre, tal y como lo vio el trazador.
        imagen: String,
        /// Argumentos, si los habia.
        argumentos: Vec<String>,
    },
    /// Acceso a fichero.
    Fichero {
        /// PID que lo hizo.
        pid: i32,
        /// Que le hizo.
        accion: AccionFichero,
        /// Ruta, escapada si no era UTF-8.
        ruta: String,
        /// Bytes implicados, si se supieron.
        bytes: u64,
    },
    /// Actividad de red.
    Red {
        /// PID que lo hizo.
        pid: i32,
        /// Que intento.
        accion: AccionRed,
        /// Destino en texto: IP, nombre o ruta de socket.
        destino: String,
        /// Puerto, si aplicaba.
        puerto: u16,
        /// Bytes enviados, si se supieron.
        bytes: u64,
    },
    /// Una llamada al sistema que no encaja en las anteriores.
    Llamada {
        /// PID que la hizo.
        pid: i32,
        /// Numero de llamada.
        numero: u64,
        /// Nombre, si se conoce.
        nombre: String,
    },
    /// El invitado termino la detonacion.
    Fin {
        /// Codigo de salida de la muestra, si termino por si sola.
        codigo: i32,
        /// Eventos que el invitado dice haber emitido.
        ///
        /// Es una **afirmacion del invitado**, no un hecho: el anfitrion la
        /// compara con lo que de verdad ha recibido, y la discrepancia va al
        /// informe. Creersela sin contrastar seria dejar que el malware decida
        /// cuanta evidencia hay.
        emitidos: u64,
        /// Si la MUESTRA llego a su fin, en vez de que la cortaran.
        ///
        /// # Por que hace falta un campo y no basta el codigo de salida
        ///
        /// El codigo de salida que el anfitrion ve es el del AGENTE INVITADO, y
        /// el agente termina limpiamente tanto si la muestra acabo como si tuvo
        /// que matarla por plazo. Las dos cosas le llegan al anfitrion como un
        /// cero, y son la diferencia entre «no hizo nada» y «no le dio tiempo»
        /// — que es exactamente la confusion que hace que alguien despliegue una
        /// muestra creyendo que esta limpia.
        ///
        /// Un `false` el anfitrion se lo cree siempre: nadie miente para que su
        /// informe valga menos. Un `true` **no** se cree solo: el anfitrion lo
        /// cruza con su propio plazo, con si tuvo que matar la maquina y con sus
        /// anomalias, porque ese si seria util falsificarlo.
        completo: bool,
    },
    /// El trazador no pudo seguir, y dice por que.
    ///
    /// Es informacion de primera: un malware que detecta el trazador y lo mata
    /// produce este evento, y su ausencia con un hueco en la secuencia dice algo
    /// distinto —que lo mato sin darle tiempo—. Las dos cosas importan.
    Degradado {
        /// Que paso, en texto.
        causa: String,
    },
}

impl Evento {
    /// Clase de la que es.
    #[must_use]
    pub fn clase(&self) -> Clase {
        match self {
            Evento::Preparado { .. } => Clase::Preparado,
            Evento::Proceso { .. } => Clase::Proceso,
            Evento::Fichero { .. } => Clase::Fichero,
            Evento::Red { .. } => Clase::Red,
            Evento::Llamada { .. } => Clase::Llamada,
            Evento::Fin { .. } => Clase::Fin,
            Evento::Degradado { .. } => Clase::Degradado,
        }
    }

    /// PID al que se refiere, si se refiere a alguno.
    #[must_use]
    pub fn pid(&self) -> Option<i32> {
        match self {
            Evento::Proceso { pid, .. }
            | Evento::Fichero { pid, .. }
            | Evento::Red { pid, .. }
            | Evento::Llamada { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}

// --- Codificacion -------------------------------------------------------------

/// Escribe una cadena con prefijo de longitud, recortando al tope.
fn poner_cadena(salida: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(MAX_CADENA);
    // El recorte respeta las fronteras de caracter: cortar un UTF-8 por la mitad
    // produciria una cadena que el otro lado no puede leer, y el otro lado es
    // quien tiene que poder leerlo todo.
    let mut n = n;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    salida.extend_from_slice(&(n as u32).to_le_bytes());
    salida.extend_from_slice(&bytes[..n]);
}

/// Errores al leer una trama.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorProtocolo {
    /// No lleva la marca.
    SinMarca,
    /// Version que esta compilacion no entiende.
    VersionDesconocida(u16),
    /// Clase de evento desconocida.
    ClaseDesconocida(u16),
    /// La carga declara mas bytes de los permitidos.
    CargaExcesiva {
        /// Lo que declaraba.
        declarado: usize,
        /// El tope.
        tope: usize,
    },
    /// Los bytes se acaban antes de lo que la trama declara.
    Truncada,
    /// Un campo no cuadra con lo que su clase exige.
    CampoInvalido(&'static str),
}

impl core::fmt::Display for ErrorProtocolo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorProtocolo::SinMarca => write!(f, "la trama no lleva la marca de AegisDetonate"),
            ErrorProtocolo::VersionDesconocida(v) => write!(
                f,
                "trama de la version {v}; esta compilacion entiende la {VERSION}, y no se \
                 interpreta: leer mal los campos daria una traza silenciosamente equivocada"
            ),
            ErrorProtocolo::ClaseDesconocida(t) => write!(f, "clase de evento desconocida: {t}"),
            ErrorProtocolo::CargaExcesiva { declarado, tope } => write!(
                f,
                "la trama declara {declarado} bytes de carga y el tope es {tope}: el campo de \
                 longitud lo escribe el invitado, que esta infectado a proposito"
            ),
            ErrorProtocolo::Truncada => write!(f, "la trama se acaba antes de lo que declara"),
            ErrorProtocolo::CampoInvalido(q) => write!(f, "campo invalido: {q}"),
        }
    }
}

/// Una trama completa: cabecera mas evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trama {
    /// Numero de secuencia dentro de la detonacion.
    pub secuencia: u64,
    /// El hecho.
    pub evento: Evento,
}

impl Trama {
    /// Serializa la trama entera, lista para el canal.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let carga = codificar(&self.evento);
        let mut v = Vec::with_capacity(CABECERA + carga.len());
        v.extend_from_slice(&MAGIA);
        v.extend_from_slice(&VERSION.to_le_bytes());
        v.extend_from_slice(&self.evento.clase().tag().to_le_bytes());
        v.extend_from_slice(&self.secuencia.to_le_bytes());
        v.extend_from_slice(&(carga.len() as u32).to_le_bytes());
        v.extend_from_slice(&carga);
        v
    }

    /// Lee una trama del principio de `datos`.
    ///
    /// Devuelve la trama y cuantos bytes ha consumido, para que quien lea de un
    /// flujo pueda seguir. Un `Ok(None)` significa «aun no hay trama entera
    /// aqui», que no es un error: es un canal que va llegando.
    ///
    /// # Errores
    /// [`ErrorProtocolo`] cuando lo que hay **no puede llegar a ser** una trama
    /// valida por mucho que lleguen mas bytes.
    pub fn de_bytes(datos: &[u8]) -> Result<Option<(Trama, usize)>, ErrorProtocolo> {
        if datos.len() < CABECERA {
            // Puede que aun no haya llegado la cabecera entera. Pero si los
            // bytes que ya hay contradicen la marca, esto no va a mejorar.
            let n = datos.len().min(4);
            if datos[..n] != MAGIA[..n] {
                return Err(ErrorProtocolo::SinMarca);
            }
            return Ok(None);
        }
        if datos[..4] != MAGIA {
            return Err(ErrorProtocolo::SinMarca);
        }
        let version = u16::from_le_bytes([datos[4], datos[5]]);
        if version != VERSION {
            return Err(ErrorProtocolo::VersionDesconocida(version));
        }
        let tag = u16::from_le_bytes([datos[6], datos[7]]);
        let clase = Clase::desde_tag(tag).ok_or(ErrorProtocolo::ClaseDesconocida(tag))?;
        let mut sec = [0u8; 8];
        sec.copy_from_slice(&datos[8..16]);
        let secuencia = u64::from_le_bytes(sec);
        let largo = u32::from_le_bytes([datos[16], datos[17], datos[18], datos[19]]) as usize;

        // El tope se comprueba ANTES de mirar si los bytes han llegado: si no se
        // hiciera, un invitado podria declarar cuatro gigas y dejar al anfitrion
        // esperandolos con el bufer creciendo.
        if largo > MAX_CARGA {
            return Err(ErrorProtocolo::CargaExcesiva {
                declarado: largo,
                tope: MAX_CARGA,
            });
        }
        if datos.len() < CABECERA + largo {
            return Ok(None);
        }

        let evento = decodificar(clase, &datos[CABECERA..CABECERA + largo])?;
        Ok(Some((Trama { secuencia, evento }, CABECERA + largo)))
    }
}

fn codificar(e: &Evento) -> Vec<u8> {
    let mut v = Vec::new();
    match e {
        Evento::Preparado { version } => poner_cadena(&mut v, version),
        Evento::Proceso {
            pid,
            padre,
            accion,
            imagen,
            argumentos,
        } => {
            v.extend_from_slice(&pid.to_le_bytes());
            v.extend_from_slice(&padre.to_le_bytes());
            v.push(accion.tag());
            poner_cadena(&mut v, imagen);
            let n = argumentos.len().min(MAX_LISTA);
            v.extend_from_slice(&(n as u32).to_le_bytes());
            for a in argumentos.iter().take(n) {
                poner_cadena(&mut v, a);
            }
        }
        Evento::Fichero {
            pid,
            accion,
            ruta,
            bytes,
        } => {
            v.extend_from_slice(&pid.to_le_bytes());
            v.push(accion.tag());
            poner_cadena(&mut v, ruta);
            v.extend_from_slice(&bytes.to_le_bytes());
        }
        Evento::Red {
            pid,
            accion,
            destino,
            puerto,
            bytes,
        } => {
            v.extend_from_slice(&pid.to_le_bytes());
            v.push(accion.tag());
            poner_cadena(&mut v, destino);
            v.extend_from_slice(&puerto.to_le_bytes());
            v.extend_from_slice(&bytes.to_le_bytes());
        }
        Evento::Llamada {
            pid,
            numero,
            nombre,
        } => {
            v.extend_from_slice(&pid.to_le_bytes());
            v.extend_from_slice(&numero.to_le_bytes());
            poner_cadena(&mut v, nombre);
        }
        Evento::Fin {
            codigo,
            emitidos,
            completo,
        } => {
            v.extend_from_slice(&codigo.to_le_bytes());
            v.extend_from_slice(&emitidos.to_le_bytes());
            v.push(u8::from(*completo));
        }
        Evento::Degradado { causa } => poner_cadena(&mut v, causa),
    }
    v
}

/// Lector de campos con el cursor dentro de la carga.
struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    fn nuevo(datos: &'a [u8]) -> Lector<'a> {
        Lector { datos, pos: 0 }
    }

    fn tomar(&mut self, n: usize) -> Result<&'a [u8], ErrorProtocolo> {
        if self.datos.len() - self.pos < n {
            return Err(ErrorProtocolo::Truncada);
        }
        let t = &self.datos[self.pos..self.pos + n];
        self.pos += n;
        Ok(t)
    }

    fn i32(&mut self) -> Result<i32, ErrorProtocolo> {
        let b = self.tomar(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ErrorProtocolo> {
        let b = self.tomar(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn u16(&mut self) -> Result<u16, ErrorProtocolo> {
        let b = self.tomar(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u8(&mut self) -> Result<u8, ErrorProtocolo> {
        Ok(self.tomar(1)?[0])
    }

    /// Lee una cadena con prefijo de longitud.
    ///
    /// Los bytes que no son UTF-8 **no tiran el evento**: se escapan. Una ruta de
    /// Linux es una secuencia de bytes sin codificacion y el malware la elige;
    /// rechazar el evento por eso perderia justo la evidencia que interesa, y le
    /// daria al malware una forma trivial de borrar su rastro del informe.
    fn cadena(&mut self) -> Result<String, ErrorProtocolo> {
        let n = {
            let b = self.tomar(4)?;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        };
        if n > MAX_CADENA {
            return Err(ErrorProtocolo::CargaExcesiva {
                declarado: n,
                tope: MAX_CADENA,
            });
        }
        let bytes = self.tomar(n)?;
        Ok(escapar(bytes))
    }

    fn lista(&mut self) -> Result<Vec<String>, ErrorProtocolo> {
        let n = {
            let b = self.tomar(4)?;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        };
        if n > MAX_LISTA {
            return Err(ErrorProtocolo::CargaExcesiva {
                declarado: n,
                tope: MAX_LISTA,
            });
        }
        let mut v = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            v.push(self.cadena()?);
        }
        Ok(v)
    }
}

/// Convierte bytes arbitrarios en texto legible, escapando lo que no es UTF-8.
///
/// Se conserva todo: lo imprimible tal cual y el resto como `\xNN`. El informe
/// tiene que poder ensenar la ruta que el malware uso de verdad, incluso —sobre
/// todo— cuando la eligio para que no se pudiera ensenar.
#[must_use]
pub fn escapar(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(|c| c.is_control()) => s.to_string(),
        _ => {
            let mut out = String::with_capacity(bytes.len());
            for &b in bytes {
                if b.is_ascii_graphic() || b == b' ' || b == b'/' {
                    out.push(b as char);
                } else {
                    out.push_str(&format!("\\x{b:02x}"));
                }
            }
            out
        }
    }
}

fn decodificar(clase: Clase, carga: &[u8]) -> Result<Evento, ErrorProtocolo> {
    let mut l = Lector::nuevo(carga);
    let e = match clase {
        Clase::Preparado => Evento::Preparado {
            version: l.cadena()?,
        },
        Clase::Proceso => {
            let pid = l.i32()?;
            let padre = l.i32()?;
            let accion = AccionProceso::desde_tag(l.u8()?)
                .ok_or(ErrorProtocolo::CampoInvalido("accion de proceso"))?;
            Evento::Proceso {
                pid,
                padre,
                accion,
                imagen: l.cadena()?,
                argumentos: l.lista()?,
            }
        }
        Clase::Fichero => {
            let pid = l.i32()?;
            let accion = AccionFichero::desde_tag(l.u8()?)
                .ok_or(ErrorProtocolo::CampoInvalido("accion de fichero"))?;
            Evento::Fichero {
                pid,
                accion,
                ruta: l.cadena()?,
                bytes: l.u64()?,
            }
        }
        Clase::Red => {
            let pid = l.i32()?;
            let accion = AccionRed::desde_tag(l.u8()?)
                .ok_or(ErrorProtocolo::CampoInvalido("accion de red"))?;
            Evento::Red {
                pid,
                accion,
                destino: l.cadena()?,
                puerto: l.u16()?,
                bytes: l.u64()?,
            }
        }
        Clase::Llamada => Evento::Llamada {
            pid: l.i32()?,
            numero: l.u64()?,
            nombre: l.cadena()?,
        },
        Clase::Fin => Evento::Fin {
            codigo: l.i32()?,
            emitidos: l.u64()?,
            completo: l.u8()? != 0,
        },
        Clase::Degradado => Evento::Degradado { causa: l.cadena()? },
    };
    Ok(e)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ida_y_vuelta(e: Evento) {
        let t = Trama {
            secuencia: 42,
            evento: e.clone(),
        };
        let bytes = t.a_bytes();
        let (leida, n) = Trama::de_bytes(&bytes).unwrap().unwrap();
        assert_eq!(n, bytes.len(), "se tiene que consumir la trama entera");
        assert_eq!(leida.secuencia, 42);
        assert_eq!(leida.evento, e);
    }

    #[test]
    fn todos_los_eventos_van_y_vuelven() {
        ida_y_vuelta(Evento::Preparado {
            version: "1.2.3".into(),
        });
        ida_y_vuelta(Evento::Proceso {
            pid: 100,
            padre: 1,
            accion: AccionProceso::Ejecuta,
            imagen: "/tmp/muestra".into(),
            argumentos: vec!["-x".into(), "-y".into()],
        });
        ida_y_vuelta(Evento::Fichero {
            pid: 100,
            accion: AccionFichero::Escribe,
            ruta: "/home/victima/documento.docx.cifrado".into(),
            bytes: 4096,
        });
        ida_y_vuelta(Evento::Red {
            pid: 100,
            accion: AccionRed::Conecta,
            destino: "203.0.113.5".into(),
            puerto: 443,
            bytes: 0,
        });
        ida_y_vuelta(Evento::Llamada {
            pid: 100,
            numero: 59,
            nombre: "execve".into(),
        });
        ida_y_vuelta(Evento::Fin {
            codigo: 0,
            emitidos: 1234,
            completo: true,
        });
        ida_y_vuelta(Evento::Fin {
            codigo: -1,
            emitidos: 7,
            completo: false,
        });
        ida_y_vuelta(Evento::Degradado {
            causa: "el trazador perdio el proceso".into(),
        });
    }

    #[test]
    fn los_discriminantes_van_y_vuelven() {
        for c in [
            Clase::Preparado,
            Clase::Proceso,
            Clase::Fichero,
            Clase::Red,
            Clase::Llamada,
            Clase::Fin,
            Clase::Degradado,
        ] {
            assert_eq!(Clase::desde_tag(c.tag()), Some(c));
            assert!(!c.nombre().is_empty());
        }
        for a in [
            AccionProceso::Nace,
            AccionProceso::Ejecuta,
            AccionProceso::Muere,
        ] {
            assert_eq!(AccionProceso::desde_tag(a.tag()), Some(a));
        }
        for a in [
            AccionFichero::Lee,
            AccionFichero::Escribe,
            AccionFichero::Borra,
            AccionFichero::Renombra,
            AccionFichero::Permisos,
        ] {
            assert_eq!(AccionFichero::desde_tag(a.tag()), Some(a));
        }
        for a in [
            AccionRed::Socket,
            AccionRed::Conecta,
            AccionRed::Escucha,
            AccionRed::Envia,
            AccionRed::Resuelve,
        ] {
            assert_eq!(AccionRed::desde_tag(a.tag()), Some(a));
        }
    }

    // --- Lo que el invitado puede intentar ---------------------------------

    #[test]
    fn una_longitud_absurda_se_rechaza_sin_reservar_nada() {
        // El campo de longitud lo escribe un proceso que la muestra puede haber
        // comprometido. Cuatro gigas declarados no pueden traducirse en cuatro
        // gigas reservados, ni en un anfitrion esperandolos.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIA);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&Clase::Llamada.tag().to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        match Trama::de_bytes(&bytes) {
            Err(ErrorProtocolo::CargaExcesiva { declarado, tope }) => {
                assert_eq!(declarado, u32::MAX as usize);
                assert_eq!(tope, MAX_CARGA);
            }
            otro => panic!("se esperaba CargaExcesiva, hubo {otro:?}"),
        }
    }

    #[test]
    fn una_cadena_que_declara_de_mas_no_desborda() {
        let mut carga = Vec::new();
        carga.extend_from_slice(&7i32.to_le_bytes()); // pid
        carga.extend_from_slice(&9u64.to_le_bytes()); // numero
        carga.extend_from_slice(&(MAX_CADENA as u32 + 1).to_le_bytes());
        let r = decodificar(Clase::Llamada, &carga);
        assert!(
            matches!(r, Err(ErrorProtocolo::CargaExcesiva { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn una_lista_interminable_no_agota_la_memoria() {
        let mut carga = Vec::new();
        carga.extend_from_slice(&7i32.to_le_bytes());
        carga.extend_from_slice(&1i32.to_le_bytes());
        carga.push(AccionProceso::Nace.tag());
        carga.extend_from_slice(&0u32.to_le_bytes()); // imagen vacia
        carga.extend_from_slice(&u32::MAX.to_le_bytes()); // argumentos
        let r = decodificar(Clase::Proceso, &carga);
        assert!(
            matches!(r, Err(ErrorProtocolo::CargaExcesiva { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn una_carga_truncada_se_detecta_y_no_panica() {
        let mut carga = Vec::new();
        carga.extend_from_slice(&7i32.to_le_bytes());
        // Faltan los ocho bytes del numero de llamada.
        assert_eq!(
            decodificar(Clase::Llamada, &carga),
            Err(ErrorProtocolo::Truncada)
        );
    }

    #[test]
    fn una_accion_inventada_se_rechaza_con_nombre() {
        let mut carga = Vec::new();
        carga.extend_from_slice(&7i32.to_le_bytes());
        carga.push(99); // no existe
        carga.extend_from_slice(&0u32.to_le_bytes());
        carga.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            decodificar(Clase::Fichero, &carga),
            Err(ErrorProtocolo::CampoInvalido("accion de fichero"))
        );
    }

    #[test]
    fn una_clase_inventada_se_rechaza() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIA);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&999u16.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Trama::de_bytes(&bytes),
            Err(ErrorProtocolo::ClaseDesconocida(999))
        );
    }

    #[test]
    fn una_version_desconocida_no_se_interpreta() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIA);
        bytes.extend_from_slice(&77u16.to_le_bytes());
        bytes.extend_from_slice(&Clase::Fin.tag().to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&12u32.to_le_bytes());
        assert_eq!(
            Trama::de_bytes(&bytes),
            Err(ErrorProtocolo::VersionDesconocida(77))
        );
    }

    #[test]
    fn basura_que_no_lleva_la_marca_se_corta_enseguida() {
        // No hace falta esperar a tener cabecera entera: si los primeros bytes
        // ya contradicen la marca, mas bytes no lo van a arreglar, y seguir
        // acumulando seria dejar que el invitado llene el bufer del anfitrion.
        assert_eq!(Trama::de_bytes(b"X"), Err(ErrorProtocolo::SinMarca));
        assert_eq!(Trama::de_bytes(b"AEGX"), Err(ErrorProtocolo::SinMarca));
        assert_eq!(
            Trama::de_bytes(b"basura sin sentido"),
            Err(ErrorProtocolo::SinMarca)
        );
    }

    #[test]
    fn una_trama_incompleta_no_es_un_error() {
        // El canal va llegando: faltar bytes es lo normal, no un ataque.
        let t = Trama {
            secuencia: 1,
            evento: Evento::Fin {
                codigo: 0,
                emitidos: 0,
                completo: true,
            },
        };
        let bytes = t.a_bytes();
        for corte in 0..bytes.len() {
            assert_eq!(
                Trama::de_bytes(&bytes[..corte]),
                Ok(None),
                "con {corte} bytes tendria que pedir mas"
            );
        }
        assert!(Trama::de_bytes(&bytes).unwrap().is_some());
    }

    // --- El escapado -------------------------------------------------------

    #[test]
    fn una_ruta_que_no_es_utf8_se_conserva_escapada() {
        // Perderla seria darle al malware una forma trivial de borrar su rastro:
        // basta con elegir un nombre de fichero que el informe no sepa escribir.
        let ruta = b"/tmp/\xff\xfe/carga\x00util";
        let escapada = escapar(ruta);
        assert!(escapada.contains("\\xff"), "{escapada}");
        assert!(escapada.contains("\\x00"), "{escapada}");
        assert!(escapada.contains("/tmp/"), "{escapada}");
        assert!(escapada.contains("carga"), "{escapada}");
    }

    #[test]
    fn el_texto_normal_no_se_toca() {
        assert_eq!(escapar(b"/usr/bin/curl"), "/usr/bin/curl");
        assert_eq!(
            escapar("documento cifrado.txt".as_bytes()),
            "documento cifrado.txt"
        );
    }

    #[test]
    fn una_cadena_mas_larga_que_el_tope_se_recorta_por_caracteres() {
        // Recortar por bytes partiria un UTF-8 multibyte y el otro lado no
        // podria leer lo que se le manda.
        let larga = "ñ".repeat(MAX_CADENA);
        let mut v = Vec::new();
        poner_cadena(&mut v, &larga);
        let n = u32::from_le_bytes([v[0], v[1], v[2], v[3]]) as usize;
        assert!(n <= MAX_CADENA);
        assert!(
            core::str::from_utf8(&v[4..4 + n]).is_ok(),
            "recorte no valido"
        );
    }

    #[test]
    fn el_flujo_se_puede_trocear_en_varias_tramas() {
        let mut flujo = Vec::new();
        for i in 0..5u64 {
            flujo.extend_from_slice(
                &Trama {
                    secuencia: i,
                    evento: Evento::Llamada {
                        pid: 7,
                        numero: i,
                        nombre: format!("llamada{i}"),
                    },
                }
                .a_bytes(),
            );
        }
        let mut pos = 0usize;
        let mut vistas = 0u64;
        while let Some((t, n)) = Trama::de_bytes(&flujo[pos..]).unwrap() {
            assert_eq!(t.secuencia, vistas);
            vistas += 1;
            pos += n;
            if pos >= flujo.len() {
                break;
            }
        }
        assert_eq!(vistas, 5);
        assert_eq!(pos, flujo.len());
    }
}
