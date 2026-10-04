//! # aegis-contenido
//!
//! El canal de contenido: reglas y modelos que viajan SEPARADOS del binario del
//! agente, firmados y versionados (FASE 4, punto 5, del MP-16).
//!
//! # La causa raiz que cierra
//!
//! El contenido de deteccion viajaba dentro del binario (`aegis-scan` empotra
//! su conjunto base). Cambiar una regla exigia publicar un agente entero, y no
//! habia forma de encenderla en unos pocos equipos, ni de apagarla sola, ni de
//! volver atras sin reinstalar. Y lo peor: nada impedia que una regla que no
//! compila, o que se come la CPU, llegase a toda la flota a la vez.
//!
//! # Lo que garantiza, y donde
//!
//! | Garantia | Donde se impone |
//! |---|---|
//! | Solo se carga lo que firmo el plano de control (hibrida, con dominio) | [`almacen::Almacen::instalar`] y [`almacen::Almacen::cargar`] |
//! | Un paquete autentico pero VIEJO no se repone | epoca monotona en [`almacen::Almacen::instalar`] |
//! | El anillo lo decide el servidor y lo comprueba el agente | [`anillo::Anillo::incluye`], [`anillo::comprobar_escalera`] |
//! | Cada regla con su modo (auditoria / imponer) y apagado individual | [`paquete::Entrada`], [`ajustes::Ajustes`] |
//! | Imponer exige numeros medidos | [`paquete::Medicion::permite_imponer`] |
//! | Rollback en un comando | [`almacen::Almacen::revertir`] (local) y [`publicar::revertir`] (flota) |
//! | Un paquete que rompe un motor no se firma | [`publicar::preparar`], unica forma de obtener un [`publicar::Firmable`] |
//! | ... y si alguien lo firma saltandose la puerta, el agente no lo carga | [`validar::Validadores`] tambien en el agente |
//!
//! # Lo que este crate NO hace
//!
//! Transportar paquetes (eso es del canal de flota) ni ejecutar las reglas
//! (eso es de los motores). Entrega a los motores la lista de reglas activas con
//! su modo efectivo: [`almacen::ContenidoActivo`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod ajustes;
pub mod almacen;
pub mod anillo;
pub mod codificacion;
pub mod fuente;
pub mod paquete;
pub mod publicar;
pub mod validar;

pub use ajustes::{Ajustes, Rebaja, CTX_AJUSTES};
pub use almacen::{Almacen, ContenidoActivo, Estado, ReglaActiva, Verificacion};
pub use anillo::{Anillo, Peldano};
pub use codificacion::ErrorFormato;
pub use paquete::{Coste, Entrada, Manifiesto, Medicion, Modo, Sellado, Tipo, CTX_CONTENIDO};
pub use publicar::{Borrador, Destino, Firmable, Historial};
pub use validar::{FalloRegla, Informe, Medir, Validador, ValidadorYara, Validadores};

// Los tipos de clave, para que quien use el canal no tenga que depender de
// aegis-update ni de aegis-pqc directamente.
pub use aegis_update::{ClaveFirmaHibrida, ClaveVerificacionHibrida};

use aegis_update::SignatureError;

/// Una regla que rompe su motor, con lo que falla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotura {
    /// La regla.
    pub id: String,
    /// Lo que falla.
    pub fallo: FalloRegla,
}

fn resumen_roturas(r: &[Rotura]) -> String {
    r.iter()
        .map(|x| format!("«{}»: {}", x.id, x.fallo))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Errores del canal de contenido, en el publicador y en el agente.
#[derive(Debug, thiserror::Error)]
pub enum ErrorCanal {
    /// Los bytes no tienen la forma de un paquete o de unos ajustes.
    #[error("mal formado: {0}")]
    Formato(#[from] ErrorFormato),
    /// La firma no verifica (manipulado, otra clave, otro dominio o downgrade).
    #[error("la firma no verifica: {0}")]
    Firma(#[from] SignatureError),
    /// El paquete es de otro canal.
    #[error("paquete del canal «{ofrecido}»; este agente sigue el canal «{esperado}»")]
    OtroCanal {
        /// El canal que trae.
        ofrecido: String,
        /// El canal que se sigue.
        esperado: String,
    },
    /// La epoca no avanza: autentico y anterior, repuesto.
    #[error(
        "epoca {ofrecida} no supera la ya vista ({vista}): es contenido ANTERIOR con firma \
         valida, y reponerlo devolveria al equipo a reglas que no conocen lo de hoy"
    )]
    Retroceso {
        /// Epoca ofrecida.
        ofrecida: u64,
        /// Epoca mas alta ya aceptada.
        vista: u64,
    },
    /// El equipo no esta en el anillo del paquete. No es un ataque ni un error:
    /// todavia no le toca. El estado no se toca.
    #[error("este equipo no esta en el anillo «{anillo}» de la epoca {epoca}: todavia no le toca")]
    FueraDeAnillo {
        /// Nombre del anillo.
        anillo: &'static str,
        /// Epoca del paquete.
        epoca: u64,
    },
    /// La escalera de despliegue no se sostiene.
    #[error("escalera de despliegue invalida: {0}")]
    Escalera(String),
    /// La estructura del paquete no cumple las reglas del canal.
    #[error("estructura: {0}")]
    Estructura(String),
    /// Alguna regla rompe su motor.
    #[error("{} regla(s) rompen su motor: {}", .0.len(), resumen_roturas(.0))]
    Roto(Vec<Rotura>),
    /// Error de E/S en el almacen.
    #[error("E/S en {ruta}: {error}")]
    Io {
        /// Ruta implicada.
        ruta: String,
        /// El error.
        error: std::io::Error,
    },
    /// El estado del almacen no cuadra con lo que hay en disco.
    #[error("estado del almacen: {0}")]
    Estado(String),
    /// No hay version anterior que restaurar.
    #[error("no hay version anterior que restaurar")]
    SinAnterior,
    /// No hay contenido instalado.
    #[error("no hay contenido instalado")]
    SinContenido,
}
