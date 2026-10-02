//! El destino: adonde sale la auditoria, y con que garantia.
//!
//! # Por que el destino es un trait y no una funcion
//!
//! Lo que el diario garantiza —que nada se pierde— no depende de si al otro
//! lado hay un Kafka o un syslog. Separarlo permite probar la garantia de
//! verdad, con un destino que falla cuando la prueba quiere que falle, sin
//! tener que provocar averias en un SIEM real.
//!
//! El contrato tiene una sola regla y es la que sostiene todo lo demas:
//! **`entregar` solo devuelve `Ok` cuando el destino ha ACUSADO los registros**.
//! Un destino que devuelva `Ok` al meter los bytes en un socket esta mintiendo:
//! el diario borrara los registros y, si la conexion se corta antes de que
//! lleguen, la auditoria se pierde con el visto bueno de todo el sistema.

use crate::error::Resultado;

/// Adonde va la auditoria.
pub trait Destino: Send {
    /// Nombre para los registros y las metricas.
    fn nombre(&self) -> &str;

    /// Entrega un lote y devuelve `Ok` SOLO si el destino lo acuso.
    ///
    /// Ver la regla del modulo: devolver `Ok` antes del acuse convierte «sin
    /// perdida» en una frase de folleto.
    fn entregar(&mut self, lote: &[&[u8]]) -> Resultado<()>;

    /// Cierra la conexion para que el siguiente envio la reabra.
    ///
    /// Se llama tras un fallo. Reutilizar una conexion que acaba de fallar es
    /// la forma mas comun de convertir un corte de red de dos segundos en un
    /// destino que no vuelve nunca: el socket queda medio abierto, las
    /// escrituras «funcionan» y nada llega.
    fn reiniciar(&mut self) {}

    /// Si la conexion con el destino sigue viva AHORA, sin enviar nada.
    ///
    /// La usa la retencion de la bomba (`Bomba::con_retencion`) antes de dar
    /// por guardado un lote en un destino SIN acuse: un colector que murio
    /// con el lote en su bufer no lo guardo, aunque el envio diera `Ok`. Por
    /// defecto `true`: un destino con acuse no la necesita.
    fn vivo(&mut self) -> bool {
        true
    }
}
