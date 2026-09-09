//! Deteccion de barridos de red en espacio de usuario.
//!
//! El programa XDP ya hace una deteccion barata en el kernel, pero con una
//! aproximacion: cuenta puertos distintos con un mapa de bits de 64 posiciones
//! indexado por `puerto % 64`, porque un conjunto exacto por IP no cabe en el
//! presupuesto de un programa que corre por cada paquete. Esa aproximacion
//! SUBESTIMA el numero de puertos distintos.
//!
//! Aqui se hace la cuenta exacta sobre la muestra que el kernel envia. El
//! reparto es deliberado: el kernel filtra el 99,9 % del trafico con un coste
//! de nanosegundos, y userland decide sobre lo poco que llega con toda la
//! precision. Poner la decision abajo obligaria a meter politica en la ruta de
//! paquetes; ponerla toda arriba significaria enviar cada SYN a userland.
//!
//! Se detectan dos formas distintas de reconocimiento que suelen confundirse:
//!
//! - **Barrido de puertos** (vertical): un origen prueba MUCHOS PUERTOS de un
//!   mismo destino. Es la fase de inventario de servicios de un host concreto.
//! - **Barrido de hosts** (horizontal): un origen prueba EL MISMO PUERTO en
//!   muchos destinos. Es como se propaga un gusano y como se busca una version
//!   vulnerable concreta por toda una red.
//!
//! El segundo pasa desapercibido para cualquier detector que solo cuente
//! puertos por origen, que es el error habitual.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// Umbrales del detector.
#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Ventana de observacion, en nanosegundos.
    pub window_ns: u64,
    /// Puertos distintos sobre un mismo destino que definen un barrido vertical.
    pub port_threshold: usize,
    /// Destinos distintos sobre un mismo puerto que definen un barrido horizontal.
    pub host_threshold: usize,
    /// SYN minimos en la ventana. Exigirlo ademas del umbral de puertos evita
    /// clasificar como barrido a un cliente que abre unas pocas conexiones
    /// dispersas de forma legitima.
    pub syn_threshold: u32,
    /// Numero maximo de origenes en seguimiento.
    pub max_sources: usize,
    /// Numero maximo de puertos y destinos que se recuerdan por origen.
    pub max_tracked_per_source: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            window_ns: 1_000_000_000, // 1 s
            port_threshold: 15,
            host_threshold: 20,
            syn_threshold: 15,
            max_sources: 8192,
            max_tracked_per_source: 1024,
        }
    }
}

/// Tipo de barrido detectado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// Muchos puertos de un mismo destino.
    PortScan,
    /// Un mismo puerto en muchos destinos.
    HostSweep,
}

/// Barrido detectado.
#[derive(Debug, Clone)]
pub struct ScanVerdict {
    /// Origen.
    pub source: Ipv4Addr,
    /// Tipo.
    pub kind: ScanKind,
    /// Puertos distintos observados.
    pub distinct_ports: usize,
    /// Destinos distintos observados.
    pub distinct_hosts: usize,
    /// SYN observados en la ventana.
    pub syn_count: u32,
    /// Duracion de la ventana en el momento de la deteccion.
    pub elapsed_ns: u64,
}

#[derive(Debug)]
struct SourceState {
    window_start_ns: u64,
    ports: HashSet<u16>,
    hosts: HashSet<Ipv4Addr>,
    syn_count: u32,
    /// Ya se notifico en esta ventana: evita repetir la misma alerta por cada
    /// paquete posterior del mismo barrido.
    reported: bool,
    last_seen_ns: u64,
}

/// Detector de barridos.
#[derive(Debug)]
pub struct ScanDetector {
    config: ScanConfig,
    sources: HashMap<Ipv4Addr, SourceState>,
}

impl ScanDetector {
    /// Crea un detector.
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            sources: HashMap::new(),
        }
    }

    /// Numero de origenes en seguimiento.
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    /// Registra un SYN y devuelve un veredicto si cruza algun umbral.
    ///
    /// Devuelve `Some` UNA sola vez por ventana y origen. Repetir la alerta por
    /// cada paquete de un barrido de 65.000 puertos generaria 65.000 alertas
    /// del mismo hecho.
    pub fn observe(
        &mut self,
        source: Ipv4Addr,
        dest: Ipv4Addr,
        dst_port: u16,
        ts_ns: u64,
    ) -> Option<ScanVerdict> {
        // Cota de memoria: un atacante que falsifique la IP origen de cada
        // paquete crearia una entrada por paquete. Al llenarse se expulsa el
        // origen visto hace mas tiempo, no se deja de detectar.
        if !self.sources.contains_key(&source) && self.sources.len() >= self.config.max_sources {
            self.evict_oldest();
        }

        let cfg = self.config;
        let st = self.sources.entry(source).or_insert_with(|| SourceState {
            window_start_ns: ts_ns,
            ports: HashSet::new(),
            hosts: HashSet::new(),
            syn_count: 0,
            reported: false,
            last_seen_ns: ts_ns,
        });

        if ts_ns.saturating_sub(st.window_start_ns) > cfg.window_ns {
            st.window_start_ns = ts_ns;
            st.ports.clear();
            st.hosts.clear();
            st.syn_count = 0;
            st.reported = false;
        }

        st.last_seen_ns = ts_ns;
        st.syn_count = st.syn_count.saturating_add(1);
        if st.ports.len() < cfg.max_tracked_per_source {
            st.ports.insert(dst_port);
        }
        if st.hosts.len() < cfg.max_tracked_per_source {
            st.hosts.insert(dest);
        }

        if st.reported || st.syn_count < cfg.syn_threshold {
            return None;
        }

        let puertos = st.ports.len();
        let hosts = st.hosts.len();

        // El orden importa: un barrido horizontal toca muchos hosts y pocos
        // puertos, asi que comprobar primero el umbral de puertos lo
        // clasificaria mal.
        let kind = if hosts >= cfg.host_threshold && puertos < cfg.port_threshold {
            ScanKind::HostSweep
        } else if puertos >= cfg.port_threshold {
            ScanKind::PortScan
        } else {
            return None;
        };

        st.reported = true;
        Some(ScanVerdict {
            source,
            kind,
            distinct_ports: puertos,
            distinct_hosts: hosts,
            syn_count: st.syn_count,
            elapsed_ns: ts_ns.saturating_sub(st.window_start_ns),
        })
    }

    /// Elimina los origenes sin actividad reciente.
    ///
    /// Se llama periodicamente, no por paquete.
    pub fn prune(&mut self, now_ns: u64) -> usize {
        let ventana = self.config.window_ns.saturating_mul(4);
        let antes = self.sources.len();
        self.sources
            .retain(|_, st| now_ns.saturating_sub(st.last_seen_ns) < ventana);
        antes - self.sources.len()
    }

    fn evict_oldest(&mut self) {
        if let Some(victima) = self
            .sources
            .iter()
            .min_by_key(|(_, st)| st.last_seen_ns)
            .map(|(ip, _)| *ip)
        {
            self.sources.remove(&victima);
        }
    }
}

impl Default for ScanDetector {
    fn default() -> Self {
        Self::new(ScanConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn detecta_barrido_vertical_de_puertos() {
        let mut d = ScanDetector::default();
        let origen = ip(10, 0, 0, 66);
        let destino = ip(10, 0, 0, 1);

        let mut veredicto = None;
        for p in 1..=40u16 {
            if let Some(v) = d.observe(origen, destino, p, u64::from(p) * MS) {
                veredicto = Some(v);
                break;
            }
        }
        let v = veredicto.expect("40 puertos distintos en 40 ms es un barrido");
        assert_eq!(v.kind, ScanKind::PortScan);
        assert!(v.distinct_ports >= 15);
        assert_eq!(v.distinct_hosts, 1);
    }

    #[test]
    fn detecta_barrido_horizontal_de_hosts() {
        let mut d = ScanDetector::default();
        let origen = ip(10, 0, 0, 66);

        // El mismo puerto en muchos destinos: como se propaga un gusano.
        // Un detector que solo cuente puertos por origen no ve esto.
        let mut veredicto = None;
        for h in 1..=40u8 {
            if let Some(v) = d.observe(origen, ip(10, 0, 0, h), 445, u64::from(h) * MS) {
                veredicto = Some(v);
                break;
            }
        }
        let v = veredicto.expect("el mismo puerto en 40 hosts es un barrido horizontal");
        assert_eq!(v.kind, ScanKind::HostSweep);
        assert_eq!(v.distinct_ports, 1);
        assert!(v.distinct_hosts >= 20);
    }

    #[test]
    fn no_alerta_por_trafico_normal() {
        let mut d = ScanDetector::default();
        let cliente = ip(192, 168, 1, 50);
        let servidor = ip(192, 168, 1, 1);

        // Un navegador abriendo varias conexiones al mismo servicio.
        for i in 0..10u64 {
            assert!(d.observe(cliente, servidor, 443, i * 50 * MS).is_none());
        }
        // Y a un puñado de servicios distintos.
        for (i, p) in [80u16, 443, 8080, 22].iter().enumerate() {
            assert!(d
                .observe(cliente, servidor, *p, (i as u64 + 20) * 50 * MS)
                .is_none());
        }
    }

    #[test]
    fn solo_alerta_una_vez_por_ventana() {
        let mut d = ScanDetector::default();
        let origen = ip(10, 0, 0, 66);
        let destino = ip(10, 0, 0, 1);

        let mut alertas = 0;
        // Un barrido completo de 1000 puertos.
        for p in 1..=1000u16 {
            if d.observe(origen, destino, p, u64::from(p) * 100_000)
                .is_some()
            {
                alertas += 1;
            }
        }
        // Repetir la alerta por cada paquete generaria cientos de alertas del
        // mismo hecho.
        assert_eq!(alertas, 1, "un barrido es un hecho, no mil");
    }

    #[test]
    fn la_ventana_se_reinicia_y_vuelve_a_poder_alertar() {
        let mut d = ScanDetector::default();
        let origen = ip(10, 0, 0, 66);
        let destino = ip(10, 0, 0, 1);

        for p in 1..=40u16 {
            d.observe(origen, destino, p, u64::from(p) * MS);
        }
        // Muy por encima de la ventana de 1 s: es un barrido NUEVO.
        let base = 10_000 * MS;
        let mut segunda = None;
        for p in 1..=40u16 {
            if let Some(v) = d.observe(origen, destino, p, base + u64::from(p) * MS) {
                segunda = Some(v);
                break;
            }
        }
        assert!(
            segunda.is_some(),
            "un barrido posterior debe volver a alertar"
        );
    }

    #[test]
    fn el_trafico_lento_no_cruza_el_umbral_de_syn() {
        let mut d = ScanDetector::default();
        let origen = ip(10, 0, 0, 66);
        let destino = ip(10, 0, 0, 1);

        // Muchos puertos distintos pero repartidos: cada uno cae en su propia
        // ventana, asi que nunca se acumulan.
        for p in 1..=50u16 {
            assert!(
                d.observe(origen, destino, p, u64::from(p) * 2_000 * MS)
                    .is_none(),
                "un puerto cada 2 s no es un barrido"
            );
        }
    }

    #[test]
    fn la_memoria_esta_acotada_ante_origenes_falsificados() {
        let mut d = ScanDetector::new(ScanConfig {
            max_sources: 100,
            ..Default::default()
        });
        // Un atacante que falsifique la IP origen de cada paquete crearia una
        // entrada por paquete si no hubiera cota.
        for i in 0..5000u32 {
            let o = Ipv4Addr::from(i.to_be_bytes());
            d.observe(o, ip(10, 0, 0, 1), 80, u64::from(i) * MS);
        }
        assert!(
            d.tracked_sources() <= 100,
            "se rastrean {} origenes, el limite es 100",
            d.tracked_sources()
        );
    }

    #[test]
    fn el_podado_libera_origenes_inactivos() {
        let mut d = ScanDetector::default();
        for i in 0..50u8 {
            d.observe(ip(10, 0, 0, i), ip(10, 0, 1, 1), 80, 1000);
        }
        assert_eq!(d.tracked_sources(), 50);
        let liberados = d.prune(100_000 * MS);
        assert_eq!(liberados, 50);
        assert_eq!(d.tracked_sources(), 0);
    }
}
