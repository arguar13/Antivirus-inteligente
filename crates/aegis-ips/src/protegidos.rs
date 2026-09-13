//! La lista de nunca-bloquear.
//!
//! # Que pasa si se corta la maquina equivocada
//!
//! Cortar un endpoint infectado es contencion. Cortar el controlador de dominio
//! es un apagon: nadie se autentica, nadie entra a su equipo, y el incidente
//! pasa de «una maquina comprometida» a «la organizacion parada». Lo mismo con
//! el DNS de la organizacion —sin el, todo lo demas deja de resolver— y con el
//! propio plano de control de AegisCore: cortarlo deja a la flota sin consola
//! **justo cuando hace falta**, y encima ciega la vista desde la que se veria
//! que el corte fue un error.
//!
//! # Y no es solo un accidente: es un objetivo
//!
//! Un atacante que sepa que hay un IPS automatico intentara que corte por el. Es
//! barato: basta con hacer que el trafico hacia el controlador de dominio se
//! parezca a lo que la regla busca. Si lo consigue, ha conseguido una denegacion
//! de servicio sobre la infraestructura critica **usando la propia defensa como
//! arma**, sin tener que vulnerar nada.
//!
//! Es la misma doctrina de activos protegidos de la FASE 69, aplicada aqui: hay
//! maquinas que no se tocan, y la unica forma de que la salvaguarda sirva es que
//! **ninguna regla pueda saltarsela**, por alta que sea su confianza.
//!
//! # Por que la lista tambien vive en el kernel
//!
//! Esta comprobacion se hace aqui arriba y **otra vez** en el programa TC, antes
//! de mirar el veredicto. No es redundancia por gusto: una salvaguarda que
//! depende de que el codigo de decision este bien no protege del caso que
//! importa, que es justamente que el codigo de decision este mal.

use std::collections::BTreeMap;
use std::net::IpAddr;

/// Por que una maquina esta protegida.
///
/// Se guarda el motivo porque una lista de direcciones sin explicacion se
/// convierte, en dos anos, en una lista que nadie se atreve a tocar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoProteccion {
    /// El plano de control de AegisCore.
    PlanoDeControl,
    /// Un controlador de dominio.
    ControladorDeDominio,
    /// Un servidor DNS de la organizacion.
    ServidorDns,
    /// Una puerta de enlace o encaminador.
    PuertaDeEnlace,
    /// Declarado por el cliente.
    DeclaradoPorElCliente,
}

impl MotivoProteccion {
    /// Codigo estable, para registros e informes.
    #[must_use]
    pub fn codigo(self) -> &'static str {
        match self {
            MotivoProteccion::PlanoDeControl => "plano-de-control",
            MotivoProteccion::ControladorDeDominio => "controlador-de-dominio",
            MotivoProteccion::ServidorDns => "servidor-dns",
            MotivoProteccion::PuertaDeEnlace => "puerta-de-enlace",
            MotivoProteccion::DeclaradoPorElCliente => "declarado-por-el-cliente",
        }
    }

    /// Valor numerico que viaja al mapa eBPF.
    #[must_use]
    pub fn numero(self) -> u32 {
        match self {
            MotivoProteccion::PlanoDeControl => 1,
            MotivoProteccion::ControladorDeDominio => 2,
            MotivoProteccion::ServidorDns => 3,
            MotivoProteccion::PuertaDeEnlace => 4,
            MotivoProteccion::DeclaradoPorElCliente => 5,
        }
    }
}

/// El conjunto de maquinas que no se cortan jamas.
#[derive(Debug, Clone, Default)]
pub struct Protegidos {
    entradas: BTreeMap<IpAddr, MotivoProteccion>,
}

impl Protegidos {
    /// Una lista vacia.
    #[must_use]
    pub fn nueva() -> Protegidos {
        Protegidos::default()
    }

    /// Anade una direccion protegida.
    ///
    /// Si ya estaba, se conserva el motivo mas fuerte —el de menor numero— para
    /// que declarar algo «por el cliente» no degrade una proteccion estructural.
    pub fn proteger(&mut self, ip: IpAddr, motivo: MotivoProteccion) {
        self.entradas
            .entry(ip)
            .and_modify(|m| {
                if motivo.numero() < m.numero() {
                    *m = motivo;
                }
            })
            .or_insert(motivo);
    }

    /// Retira una proteccion.
    ///
    /// Devuelve el motivo que tenia, para que quitarla quede registrado con lo
    /// que se estaba quitando y no como un borrado anonimo.
    pub fn desproteger(&mut self, ip: &IpAddr) -> Option<MotivoProteccion> {
        self.entradas.remove(ip)
    }

    /// Si una direccion esta protegida, y por que.
    #[must_use]
    pub fn motivo(&self, ip: &IpAddr) -> Option<MotivoProteccion> {
        self.entradas.get(ip).copied()
    }

    /// Si CUALQUIERA de los dos extremos de un flujo esta protegido.
    ///
    /// Se miran los dos a proposito. Proteger solo el destino dejaria sin cubrir
    /// el trafico que SALE de un controlador de dominio, y cortarle la salida lo
    /// deja igual de inutil que cortarle la entrada.
    #[must_use]
    pub fn alguno_protegido(&self, origen: &IpAddr, destino: &IpAddr) -> Option<MotivoProteccion> {
        self.motivo(origen).or_else(|| self.motivo(destino))
    }

    /// Cuantas direcciones hay protegidas.
    #[must_use]
    pub fn cuantas(&self) -> usize {
        self.entradas.len()
    }

    /// Recorre las entradas, para poder bajarlas al mapa del kernel.
    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &MotivoProteccion)> {
        self.entradas.iter()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    #[test]
    fn una_direccion_protegida_se_reconoce_por_los_dos_extremos() {
        let mut p = Protegidos::nueva();
        p.proteger(ip(1), MotivoProteccion::ControladorDeDominio);

        assert!(p.alguno_protegido(&ip(1), &ip(9)).is_some(), "como origen");
        assert!(p.alguno_protegido(&ip(9), &ip(1)).is_some(), "como destino");
        assert!(
            p.alguno_protegido(&ip(8), &ip(9)).is_none(),
            "y dos maquinas cualesquiera no estan protegidas"
        );
    }

    /// Declarar algo «por el cliente» no puede DEGRADAR una proteccion
    /// estructural: si el plano de control acaba marcado como una preferencia
    /// del cliente, alguien lo quitara pensando que es opcional.
    #[test]
    fn el_motivo_mas_fuerte_gana_y_no_se_degrada() {
        let mut p = Protegidos::nueva();
        p.proteger(ip(1), MotivoProteccion::PlanoDeControl);
        p.proteger(ip(1), MotivoProteccion::DeclaradoPorElCliente);
        assert_eq!(p.motivo(&ip(1)), Some(MotivoProteccion::PlanoDeControl));

        // Y al reves: una proteccion mas fuerte SI sustituye a una mas debil.
        let mut q = Protegidos::nueva();
        q.proteger(ip(2), MotivoProteccion::DeclaradoPorElCliente);
        q.proteger(ip(2), MotivoProteccion::PlanoDeControl);
        assert_eq!(q.motivo(&ip(2)), Some(MotivoProteccion::PlanoDeControl));
    }

    /// Quitar una proteccion devuelve lo que se quito: un borrado anonimo deja
    /// el registro sin decir que se acaba de desproteger al controlador.
    #[test]
    fn desproteger_dice_que_se_quito() {
        let mut p = Protegidos::nueva();
        p.proteger(ip(1), MotivoProteccion::ServidorDns);
        assert_eq!(
            p.desproteger(&ip(1)),
            Some(MotivoProteccion::ServidorDns),
            "tiene que decir QUE se ha quitado"
        );
        assert_eq!(p.desproteger(&ip(1)), None, "y la segunda vez, nada");
        assert_eq!(p.cuantas(), 0);
    }

    /// IPv4 e IPv6 son direcciones distintas aunque se parezcan.
    #[test]
    fn ipv4_e_ipv6_no_se_confunden() {
        let mut p = Protegidos::nueva();
        let v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let v6: IpAddr = "::1".parse().unwrap();
        p.proteger(v4, MotivoProteccion::PuertaDeEnlace);
        assert!(p.motivo(&v4).is_some());
        assert!(p.motivo(&v6).is_none());
    }
}
