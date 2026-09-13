//! Lo que el motor decide sobre un flujo, y por que lo decidio.
//!
//! # Un veredicto sin explicacion no vale
//!
//! Cuando un cliente pregunta «¿por que se ha cortado esta conexion?», la
//! respuesta tiene que ser una frase, no una invitacion a mirar registros. Por
//! eso un veredicto lleva dentro la regla que lo produjo, su confianza y el
//! motivo: con eso se escribe la frase sin reconstruir nada.
//!
//! Y lo mismo, mas importante todavia, cuando NO se corta: saber que una regla
//! caso pero no corto —y si fue por el modo, por la confianza, por la lista de
//! protegidos o por el limitador— es lo que permite ajustar el producto en vez
//! de adivinar.

use std::net::IpAddr;

use crate::confianza::Confianza;
use crate::protegidos::MotivoProteccion;

/// Que se hace con el flujo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accion {
    /// Se corta.
    Cortar,
    /// Se alerta y se deja pasar.
    Alertar,
}

/// Por que NO se corto algo que caso una regla.
///
/// Existe para que «la regla caso y no paso nada» nunca sea una respuesta: cada
/// no-corte tiene una causa concreta y se puede contar por separado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoNoCorte {
    /// El modo no corta.
    Modo,
    /// La regla no tiene confianza suficiente.
    Confianza,
    /// Uno de los extremos esta en la lista de protegidos.
    Protegido(MotivoProteccion),
    /// El limitador degrado el motor.
    Degradado,
}

impl MotivoNoCorte {
    /// Codigo estable, para contar y para informar.
    #[must_use]
    pub fn codigo(self) -> &'static str {
        match self {
            MotivoNoCorte::Modo => "modo",
            MotivoNoCorte::Confianza => "confianza-insuficiente",
            MotivoNoCorte::Protegido(_) => "activo-protegido",
            MotivoNoCorte::Degradado => "motor-degradado",
        }
    }
}

/// El flujo sobre el que se decide, normalizado.
///
/// Los dos sentidos de una conversacion dan la MISMA clave, con el mismo criterio
/// que usa el programa eBPF. Si no coincidieran, un veredicto escrito viendo el
/// sentido de ida no cortaria el de vuelta, que es por donde llega la respuesta
/// del servidor de mando y control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flujo {
    /// El extremo menor.
    pub ip_a: IpAddr,
    /// Puerto del extremo menor.
    pub puerto_a: u16,
    /// El extremo mayor.
    pub ip_b: IpAddr,
    /// Puerto del extremo mayor.
    pub puerto_b: u16,
    /// Protocolo de transporte, con el numero de IANA.
    pub protocolo: u8,
}

impl Flujo {
    /// Normaliza un par origen/destino en una clave estable.
    #[must_use]
    pub fn normalizado(origen: (IpAddr, u16), destino: (IpAddr, u16), protocolo: u8) -> Flujo {
        let (a, b) = if (origen.0, origen.1) <= (destino.0, destino.1) {
            (origen, destino)
        } else {
            (destino, origen)
        };
        Flujo {
            ip_a: a.0,
            puerto_a: a.1,
            ip_b: b.0,
            puerto_b: b.1,
            protocolo,
        }
    }
}

/// La decision sobre un flujo, con su justificacion completa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veredicto {
    /// Sobre que flujo.
    pub flujo: Flujo,
    /// Que se hace.
    pub accion: Accion,
    /// Identificador de la regla que lo decidio.
    pub regla: u64,
    /// Nombre de la regla, para poder leerlo sin consultar el catalogo.
    pub nombre_regla: String,
    /// Con cuanta confianza.
    pub confianza: Confianza,
    /// Si no se corto, por que no. `None` cuando la accion es cortar.
    pub no_corte: Option<MotivoNoCorte>,
    /// Instante de la decision.
    pub momento_us: u64,
}

impl Veredicto {
    /// Una frase que explica la decision, para un informe o un registro.
    #[must_use]
    pub fn explicacion(&self) -> String {
        match (self.accion, self.no_corte) {
            (Accion::Cortar, _) => format!(
                "cortado por la regla {} ({}), confianza {}",
                self.regla,
                self.nombre_regla,
                self.confianza.nombre()
            ),
            (Accion::Alertar, Some(MotivoNoCorte::Protegido(m))) => format!(
                "NO cortado: la regla {} ({}) caso, pero un extremo es un activo protegido ({})",
                self.regla,
                self.nombre_regla,
                m.codigo()
            ),
            (Accion::Alertar, Some(motivo)) => format!(
                "NO cortado: la regla {} ({}) caso, pero {}",
                self.regla,
                self.nombre_regla,
                motivo.codigo()
            ),
            (Accion::Alertar, None) => {
                format!("alerta de la regla {} ({})", self.regla, self.nombre_regla)
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    /// LOS DOS SENTIDOS TIENEN QUE DAR LA MISMA CLAVE. Si no, un veredicto
    /// escrito viendo la ida no corta la vuelta, que es por donde llega la
    /// respuesta del C2.
    #[test]
    fn los_dos_sentidos_dan_la_misma_clave() {
        let ida = Flujo::normalizado((ip(1), 50_000), (ip(2), 443), 6);
        let vuelta = Flujo::normalizado((ip(2), 443), (ip(1), 50_000), 6);
        assert_eq!(ida, vuelta);
    }

    /// Pero un protocolo distinto es un flujo distinto: el 53 por UDP y el 53
    /// por TCP son dos conversaciones y cortar una no puede cortar la otra.
    #[test]
    fn el_protocolo_forma_parte_de_la_identidad_del_flujo() {
        let tcp = Flujo::normalizado((ip(1), 50_000), (ip(2), 53), 6);
        let udp = Flujo::normalizado((ip(1), 50_000), (ip(2), 53), 17);
        assert_ne!(tcp, udp);
    }

    /// Y dos puertos distintos del mismo par de maquinas tambien son flujos
    /// distintos: cortar una sesion no puede cortarlas todas.
    #[test]
    fn dos_puertos_distintos_son_dos_flujos() {
        let a = Flujo::normalizado((ip(1), 50_000), (ip(2), 443), 6);
        let b = Flujo::normalizado((ip(1), 50_001), (ip(2), 443), 6);
        assert_ne!(a, b);
    }

    /// La explicacion tiene que decir POR QUE no se corto, no solo que no se
    /// corto: sin eso, ajustar el producto es adivinar.
    #[test]
    fn la_explicacion_de_un_no_corte_dice_la_causa() {
        let v = Veredicto {
            flujo: Flujo::normalizado((ip(1), 1), (ip(2), 2), 6),
            accion: Accion::Alertar,
            regla: 7,
            nombre_regla: "c2-conocido".to_string(),
            confianza: Confianza::Alta,
            no_corte: Some(MotivoNoCorte::Protegido(
                MotivoProteccion::ControladorDeDominio,
            )),
            momento_us: 1,
        };
        let texto = v.explicacion();
        assert!(texto.contains("NO cortado"), "{texto}");
        assert!(texto.contains("controlador-de-dominio"), "{texto}");
        assert!(texto.contains("c2-conocido"), "{texto}");
    }

    #[test]
    fn la_explicacion_de_un_corte_nombra_la_regla_y_su_confianza() {
        let v = Veredicto {
            flujo: Flujo::normalizado((ip(1), 1), (ip(2), 2), 6),
            accion: Accion::Cortar,
            regla: 9,
            nombre_regla: "hash-conocido".to_string(),
            confianza: Confianza::Alta,
            no_corte: None,
            momento_us: 1,
        };
        let texto = v.explicacion();
        assert!(texto.contains("cortado por la regla 9"), "{texto}");
        assert!(texto.contains("alta"), "{texto}");
    }
}
