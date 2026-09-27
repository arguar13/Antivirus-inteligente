//! # `aegis-itdr` — Deteccion y respuesta a amenazas de identidad (FASE 58)
//!
//! ## Por que la identidad es el nuevo perimetro
//!
//! El malware moderno no siempre "explota" nada: **inicia sesion**. Roba un
//! ticket, falsifica una credencial, o pide en masa tickets de servicio para
//! crackearlos offline. El endpoint ve procesos legitimos (`lsass`, `kerberos`)
//! haciendo cosas legitimas; lo que delata al atacante es la **forma de la
//! identidad**: un cifrado degradado a RC4 para poder crackearlo, un barrido de
//! SPNs, un ticket de servicio que la KDC nunca emitio, o una cadena de
//! impersonaciones que lleva de un usuario raso a Administrador de Dominio.
//!
//! Este crate es el **motor ITDR del Control Plane**. No sustituye a la deteccion
//! del endpoint; correlaciona la capa de autenticacion de TODA la flota, que es
//! donde estos ataques se ven enteros. Tiene dos mitades:
//!
//! 1. **Analisis de Kerberos** ([`kerberos`], [`kerberoasting`], [`forjados`]):
//!    detecta **Kerberoasting**, **Golden Ticket** y **Silver Ticket** sobre los
//!    eventos de la KDC (4768/4769/4770) y el uso real de tickets en los
//!    servicios.
//! 2. **Grafo de identidad** ([`grafo`]): mapea que identidad puede actuar como
//!    cual (tokens de acceso en Windows, `euid` en Linux) y detecta **escaladas
//!    de privilegio anomalas** por alcanzabilidad y por **centralidad de
//!    intermediacion** (algoritmo de Brandes, implementado aqui).
//! 3. **Grafo completo del directorio** ([`directorio`], FASE 95): el modelo de
//!    exposicion de identidad al nivel de BloodHound —pertenencia anidada, ACL del
//!    `ntSecurityDescriptor`, delegacion, derechos de ejecucion, GPO, confianzas y
//!    plantillas de certificado— **mas la caducidad de la sesion en cada arista y
//!    el alcance por red**, que BloodHound no tiene. Se lee en solo lectura, se
//!    entrega como inventario de exposiciones con su remediacion, y alimenta la
//!    prediccion de `aegis-predict` sin que el grafo completo salga del plano de
//!    control.
//!
//! ## Honestidad de validacion: el nucleo se prueba, la captura en vivo se declara
//!
//! Como en PTGuard (FASE 51) y los honey-tokens (FASE 52), la parte que puede
//! estar **mal de forma peligrosa** —decidir si un patron de identidad es un
//! ataque— es logica pura y se prueba de verdad en cada `make ci`, con eventos
//! Kerberos reales, **tickets DER reales parseados byte a byte**, y grafos cuya
//! centralidad se compara contra un valor calculado a mano (un KAT de grafos).
//!
//! Lo que aqui es un **muro** es la **captura en vivo**: leer los eventos 4769
//! de un Controlador de Dominio real (Registro de Seguridad de Windows / ETW-Ti),
//! o los tickets de la red (RPC/SMB), necesita un dominio Active Directory y
//! privilegios que el runner del CI no tiene. Esa fontaneria de ingesta se aisla
//! y el CI **declara** que no se ejercio aqui; nunca se finge un evento.
//!
//! ## La linea etica
//!
//! El ITDR **observa y avisa**. No toca cuentas ni revoca tickets por su cuenta:
//! eso es una decision del dueno de la flota desde el Control Plane. Cerrar la
//! sesion de un usuario por un falso positivo es tan danino como no detectar al
//! atacante; por eso cada deteccion lleva su **evidencia** y una **severidad**, y
//! la respuesta automatica queda fuera de este motor.

#![forbid(unsafe_code)]

pub mod directorio;
pub mod forjados;
pub mod grafo;
pub mod kerberoasting;
pub mod kerberos;

use thiserror::Error;

/// Error del motor ITDR.
///
/// Las variantes fallan de forma RUIDOSA: un ticket mal formado o un grafo
/// inconsistente nunca deben confundirse silenciosamente con "sin amenaza".
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ItdrError {
    /// Un ticket Kerberos en el cable no respeta la codificacion DER de la
    /// estructura de RFC 4120. Se nombra que parte falla: un ticket que no
    /// decodifica es, o bien corrupcion en la red, o bien un intento de confundir
    /// al parser, y en ambos casos se rechaza en vez de adivinar.
    #[error("ticket Kerberos mal formado: {0}")]
    KerberosMalFormado(&'static str),

    /// Se pidio construir o consultar un grafo de identidad con una referencia a
    /// una identidad que no existe en el.
    #[error("identidad desconocida en el grafo: {0}")]
    IdentidadDesconocida(String),
}

/// Familia de la amenaza detectada. Cada valor corresponde a un detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaseAmenaza {
    /// Peticion masiva de tickets de servicio para crackearlos offline
    /// (normalmente con cifrado degradado a RC4). Ver [`kerberoasting`].
    Kerberoasting,
    /// TGT falsificado con la clave de `krbtgt`: la KDC nunca lo emitio. Ver
    /// [`forjados`].
    GoldenTicket,
    /// Ticket de servicio (TGS) falsificado con la clave de la cuenta de
    /// servicio: nunca paso por la KDC. Ver [`forjados`].
    SilverTicket,
    /// Cadena de impersonaciones que abre un camino nuevo de un privilegio bajo
    /// a uno alto. Ver [`grafo`].
    EscaladaPrivilegios,
}

/// Severidad de una deteccion. Ordena de menor a mayor para poder priorizar la
/// cola de alertas del Control Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Contexto util, no accionable por si solo.
    Informativa,
    /// Sospecha debil: un solo indicador flojo.
    Baja,
    /// Indicadores que, juntos, cuesta explicar como actividad legitima.
    Media,
    /// Patron caracteristico de un ataque conocido.
    Alta,
    /// Prueba de compromiso de la infraestructura de identidad (p. ej. un ticket
    /// que la KDC nunca emitio). Es lo mas grave que puede ver este motor.
    Critica,
}

/// Una deteccion del motor ITDR: que clase de amenaza, con que gravedad, sobre
/// que sujeto (la cuenta o identidad implicada) y con la evidencia que la
/// justifica.
///
/// La `evidencia` es texto en espanol pensado para el analista del Control
/// Plane: una deteccion sin evidencia legible es una alarma que nadie sabe si
/// atender, y las alarmas que no se atienden ensenan a ignorar el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deteccion {
    /// Familia del ataque.
    pub clase: ClaseAmenaza,
    /// Gravedad, para priorizar.
    pub severidad: Severidad,
    /// La cuenta o identidad implicada (p. ej. la cuenta que pidio los tickets).
    pub sujeto: String,
    /// Explicacion legible de por que se disparo, con los numeros que la anclan.
    pub evidencia: String,
}

impl Deteccion {
    /// Construye una deteccion. Interno de los detectores; el `sujeto` se
    /// normaliza a `String` para que la alerta sea autocontenida.
    pub(crate) fn nueva(
        clase: ClaseAmenaza,
        severidad: Severidad,
        sujeto: impl Into<String>,
        evidencia: impl Into<String>,
    ) -> Self {
        Self {
            clase,
            severidad,
            sujeto: sujeto.into(),
            evidencia: evidencia.into(),
        }
    }
}
