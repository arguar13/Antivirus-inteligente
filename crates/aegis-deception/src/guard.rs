//! Barandillas del bloqueo automatico.
//!
//! # Por que este modulo es el mas importante del crate
//!
//! Un motor que bloquea direcciones solo tiene una forma de fallar
//! catastroficamente: bloquear la que no debia. Bloquear la puerta de enlace
//! deja la maquina incomunicada; bloquear la red de administracion deja al
//! equipo sin poder entrar a arreglarlo, **incluido el arreglo de quitar el
//! bloqueo**. Es un fallo del que no se sale por control remoto.
//!
//! Por eso las exclusiones no son configuracion opcional: la puerta de enlace y
//! las direcciones propias se detectan solas y no se pueden desactivar.

use std::net::{IpAddr, Ipv4Addr};

/// Barandilla que decide si una direccion se puede bloquear.
#[derive(Debug, Clone, Default)]
pub struct Guard {
    /// Direcciones que nunca se bloquean, ademas de las automaticas.
    ///
    /// Aqui van los escaneres autorizados de la organizacion y la red de
    /// administracion.
    pub allowlist: Vec<IpAddr>,
    /// Puertas de enlace detectadas.
    gateways: Vec<IpAddr>,
}

impl Guard {
    /// Construye la barandilla detectando las puertas de enlace del sistema.
    pub fn detect(allowlist: Vec<IpAddr>) -> Guard {
        Guard {
            allowlist,
            gateways: gateways_ipv4(),
        }
    }

    /// Barandilla con una lista de puertas de enlace fija, para las pruebas.
    pub fn with_gateways(allowlist: Vec<IpAddr>, gateways: Vec<IpAddr>) -> Guard {
        Guard {
            allowlist,
            gateways,
        }
    }

    /// Puertas de enlace que se estan protegiendo.
    pub fn gateways(&self) -> &[IpAddr] {
        &self.gateways
    }

    /// Motivo por el que NO se puede bloquear una direccion, si lo hay.
    pub fn refusal(&self, addr: IpAddr) -> Option<&'static str> {
        if addr.is_loopback() {
            return Some("es la propia maquina");
        }
        if addr.is_unspecified() {
            return Some("es la direccion sin especificar");
        }
        if let IpAddr::V4(v4) = addr {
            if v4.is_broadcast() {
                return Some("es la direccion de difusion");
            }
            // La red local de enlace incluye APIPA y, en la nube, el servicio de
            // metadatos: cortarlo deja la instancia sin credenciales ni DNS.
            if v4.is_link_local() {
                return Some("es una direccion de enlace local");
            }
        }
        if addr.is_multicast() {
            return Some("es una direccion de multidifusion");
        }
        if self.gateways.contains(&addr) {
            return Some("es la puerta de enlace: bloquearla deja la maquina incomunicada");
        }
        if self.allowlist.contains(&addr) {
            return Some("esta en la lista de exclusion");
        }
        None
    }

    /// Indica si la direccion se puede bloquear.
    pub fn may_block(&self, addr: IpAddr) -> bool {
        self.refusal(addr).is_none()
    }
}

/// Lee las puertas de enlace IPv4 de `/proc/net/route`.
///
/// El fichero lleva las direcciones en hexadecimal y en el orden de bytes del
/// HOST, que en las maquinas donde esto corre es el de menor peso primero. Leerlo
/// como big-endian da una direccion invertida —una puerta de enlace `192.0.2.1`
/// se leeria `1.2.0.192`— y la barandilla dejaria de proteger la de verdad.
pub fn gateways_ipv4() -> Vec<IpAddr> {
    let Ok(texto) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    parse_routes(&texto)
}

/// Analiza el contenido de `/proc/net/route`.
pub fn parse_routes(texto: &str) -> Vec<IpAddr> {
    let mut salida = Vec::new();
    for linea in texto.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 3 {
            continue;
        }
        // Solo la ruta por defecto tiene destino 0.0.0.0.
        if campos[1] != "00000000" {
            continue;
        }
        let Ok(crudo) = u32::from_str_radix(campos[2], 16) else {
            continue;
        };
        if crudo == 0 {
            continue;
        }
        let gw = Ipv4Addr::from(crudo.to_le_bytes());
        let ip = IpAddr::V4(gw);
        if !salida.contains(&ip) {
            salida.push(ip);
        }
    }
    salida
}
