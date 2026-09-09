//! Aplicacion del bloqueo en XDP.
//!
//! Es el mismo veredicto del motor, aplicado una capa mas abajo. Descartar en
//! XDP cuesta unos 50 ns frente a los microsegundos de una regla de netfilter, y
//! un paquete descartado ahi **nunca puede explotar un fallo del stack TCP/IP**,
//! porque no llega a el.
//!
//! Solo cubre IPv4: el programa XDP del producto lleva un mapa de direcciones de
//! cuatro bytes. Pedir bloquear una IPv6 devuelve un error explicito en vez de
//! aceptarlo en silencio, que dejaria al llamante creyendo que hay una
//! contencion que no existe.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use aegis_scal::error::ScalError;
use aegis_scal::netfilter::{BlockReason, BlockedAddress, NetworkFilter};
use aegis_scal::platform::Platform;

use aegis_net::xdp::{BlockReason as XdpReason, XdpFilter};

/// Adaptador que expone un [`XdpFilter`] como [`NetworkFilter`].
///
/// El `Mutex` no es por comodidad: los mapas de eBPF se actualizan por llamada
/// al sistema y el rasgo entrega `&self`, asi que la exclusion tiene que estar
/// en alguna parte. Es un bloqueo tomado una vez por bloqueo de direccion, no
/// por paquete.
#[derive(Debug)]
pub struct XdpNetworkFilter {
    filtro: Mutex<XdpFilter>,
}

impl XdpNetworkFilter {
    /// Envuelve un filtro XDP ya cargado.
    pub fn new(filtro: XdpFilter) -> XdpNetworkFilter {
        XdpNetworkFilter {
            filtro: Mutex::new(filtro),
        }
    }
}

fn traducir(r: BlockReason) -> XdpReason {
    match r {
        BlockReason::Reconnaissance => XdpReason::PortScan,
        BlockReason::LateralMovement => XdpReason::PortScan,
        BlockReason::CommandAndControl => XdpReason::Manual,
        BlockReason::ThreatIntel => XdpReason::Manual,
        BlockReason::Manual => XdpReason::Manual,
    }
}

fn solo_v4(addr: IpAddr) -> Result<std::net::Ipv4Addr, ScalError> {
    match addr {
        IpAddr::V4(v) => Ok(v),
        IpAddr::V6(_) => Err(ScalError::unsupported(
            "netfilter.block(IPv6)",
            "el mapa de bloqueo del programa XDP es de direcciones de 4 bytes",
        )),
    }
}

impl NetworkFilter for XdpNetworkFilter {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn available(&self) -> bool {
        self.filtro.lock().is_ok()
    }

    fn block(
        &self,
        addr: IpAddr,
        reason: BlockReason,
        ttl: Option<Duration>,
    ) -> Result<(), ScalError> {
        let v4 = solo_v4(addr)?;
        let f = self.filtro.lock().map_err(|_| ScalError::Backend {
            backend: "xdp",
            detail: "el filtro quedo envenenado por un panico".into(),
        })?;
        f.block(v4, ttl, traducir(reason))
            .map_err(|e| ScalError::Backend {
                backend: "xdp",
                detail: e.to_string(),
            })
    }

    fn unblock(&self, addr: IpAddr) -> Result<(), ScalError> {
        let v4 = solo_v4(addr)?;
        let f = self.filtro.lock().map_err(|_| ScalError::Backend {
            backend: "xdp",
            detail: "el filtro quedo envenenado por un panico".into(),
        })?;
        f.unblock(v4).map_err(|e| ScalError::Backend {
            backend: "xdp",
            detail: e.to_string(),
        })
    }

    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError> {
        let f = self.filtro.lock().map_err(|_| ScalError::Backend {
            backend: "xdp",
            detail: "el filtro quedo envenenado por un panico".into(),
        })?;
        let entradas = f.blocklist().map_err(|e| ScalError::Backend {
            backend: "xdp",
            detail: e.to_string(),
        })?;
        Ok(entradas
            .into_iter()
            .map(|e| BlockedAddress {
                addr: IpAddr::V4(e.address),
                reason: match e.reason {
                    XdpReason::PortScan => BlockReason::Reconnaissance,
                    XdpReason::CommandAndControl => BlockReason::CommandAndControl,
                    XdpReason::Exfiltration => BlockReason::CommandAndControl,
                    XdpReason::Manual => BlockReason::Manual,
                },
                ttl: e.remaining_ns.map(Duration::from_nanos),
            })
            .collect())
    }

    fn flush(&self) -> Result<(), ScalError> {
        let f = self.filtro.lock().map_err(|_| ScalError::Backend {
            backend: "xdp",
            detail: "el filtro quedo envenenado por un panico".into(),
        })?;
        let entradas = f.blocklist().map_err(|e| ScalError::Backend {
            backend: "xdp",
            detail: e.to_string(),
        })?;
        for e in entradas {
            f.unblock(e.address).map_err(|err| ScalError::Backend {
                backend: "xdp",
                detail: err.to_string(),
            })?;
        }
        Ok(())
    }
}
