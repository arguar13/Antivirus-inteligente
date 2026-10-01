//! Errores del enjambre.
//!
//! Cada variante nombra **por que se rechazo algo**, y esa precision no es
//! cosmetica: un mensaje rechazado en una malla de seguridad es una senal, y
//! «error de protocolo» a secas no permite distinguir un agente con una version
//! vieja de un atacante probando el formato.

use thiserror::Error;

/// Lo que puede salir mal al procesar algo del enjambre.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorEnjambre {
    /// El buffer se acabo antes que el campo que se estaba leyendo.
    #[error("mensaje truncado: se esperaban {esperados} bytes en {campo} y habia {habia}")]
    Truncado {
        /// Campo que se estaba leyendo.
        campo: &'static str,
        /// Bytes que hacian falta.
        esperados: usize,
        /// Bytes disponibles.
        habia: usize,
    },

    /// La marca del protocolo no cuadra: esto no es un mensaje del enjambre.
    #[error("marca de protocolo invalida")]
    MarcaInvalida,

    /// Version del formato que este agente no habla.
    #[error("version de formato {0} no soportada")]
    VersionNoSoportada(u8),

    /// Discriminante de tipo de mensaje desconocido.
    #[error("tipo de mensaje desconocido: {0}")]
    TipoDesconocido(u8),

    /// Un campo declara una longitud que no cabe en lo que queda.
    #[error("longitud declarada de {campo} ({declarada}) fuera de lo disponible ({disponible})")]
    LongitudImposible {
        /// Campo cuya longitud miente.
        campo: &'static str,
        /// Lo que declara.
        declarada: usize,
        /// Lo que hay.
        disponible: usize,
    },

    /// Texto que decia ser UTF-8 y no lo era.
    #[error("el campo {0} no es UTF-8 valido")]
    NoEsUtf8(&'static str),

    /// Discriminante de tipo de indicador desconocido.
    #[error("tipo de indicador desconocido: {0}")]
    IndicadorDesconocido(u8),

    /// Accion de orden desconocida.
    #[error("accion de orden desconocida: {0}")]
    AccionDesconocida(u8),

    /// La firma no verifica: la del plano de control (ordenes, artefactos,
    /// credenciales de par) o la del par sobre su observacion.
    #[error("firma invalida: {0}")]
    FirmaInvalida(String),

    /// La orden pide algo que **jamas** puede viajar por el enjambre.
    ///
    /// No es un fallo criptografico: es de clase. Ver `orden::Accion::gossipable`.
    #[error("accion no propagable por el enjambre: {0}")]
    AccionNoPropagable(&'static str),

    /// La orden ya caduco.
    #[error("orden caducada: caduco en {caduca_en}, ahora es {ahora}")]
    Caducada {
        /// Momento de caducidad declarado.
        caduca_en: u64,
        /// Momento actual.
        ahora: u64,
    },

    /// La orden viene del futuro mas alla de la holgura de reloj admitida.
    #[error("orden del futuro: emitida en {emitida_en}, ahora es {ahora}")]
    DelFuturo {
        /// Momento de emision declarado.
        emitida_en: u64,
        /// Momento actual.
        ahora: u64,
    },

    /// Una epoca que ya fue superada para ese sujeto: es una reproduccion.
    #[error("epoca {recibida} ya superada para este sujeto (vigente: {vigente})")]
    EpocaSuperada {
        /// Epoca del mensaje.
        recibida: u64,
        /// Epoca que ya se conocia.
        vigente: u64,
    },

    /// Un par matriculado firmo una observacion con un origen que no es el suyo.
    ///
    /// No es ruido de red: la firma es buena, asi que quien la emitio tiene una
    /// credencial de verdad y la esta usando para pasar por otro. Es el intento
    /// de Sybil de un equipo comprometido, y queda identificado.
    #[error("origen suplantado: declara {declarado} y firma {autenticado}")]
    OrigenSuplantado {
        /// El origen que declara el mensaje.
        declarado: String,
        /// El CN de la credencial que firma.
        autenticado: String,
    },

    /// Un trozo de artefacto que no encaja con lo que se estaba reensamblando.
    #[error("trozo incoherente: {0}")]
    TrozoIncoherente(&'static str),

    /// El contenido reensamblado no da el hash que el descriptor prometia.
    #[error("el artefacto reensamblado no coincide con su identificador de contenido")]
    ContenidoNoCoincide,

    /// Se paso un limite duro del protocolo.
    #[error("limite excedido en {campo}: {valor} > {tope}")]
    LimiteExcedido {
        /// Que limite.
        campo: &'static str,
        /// Valor visto.
        valor: usize,
        /// Tope.
        tope: usize,
    },
}
