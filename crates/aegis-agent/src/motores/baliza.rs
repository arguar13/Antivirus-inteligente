//! Balizas de mando y control por el ritmo de las conexiones (FASE 2 del MP-16,
//! ola A: la parte de `aegis-l7hunter` que no necesita uprobes).
//!
//! Un implante duerme, pregunta a su servidor y vuelve a dormir, con jitter
//! uniforme para disimular; `aegis_l7hunter::baliza` demuestra que esa serie
//! tiene un coeficiente de variacion acotado (0,578) que el trafico humano a
//! rafagas no respeta. Las sondas del agente ya ven cada `connect` TCP: este
//! motor agrupa las marcas por (proceso, destino, puerto) y, en el camino frio,
//! pregunta al detector.
//!
//! # Lo que NO hace todavia
//!
//! Leer el contenido TLS en claro (uprobes sobre `SSL_write`, el resto de
//! l7hunter). Eso es un gancho nuevo sobre bibliotecas de terceros y va en su
//! propia entrega; esto solo usa telemetria que ya existe.
//!
//! # Coste
//!
//! Caliente: anotar una marca en un anillo acotado (O(1)). Frio: analizar solo
//! las series que crecieron desde la ultima pasada.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala, y como sospecha: un sondeo automatico legitimo tambien es
//! periodico. Cuanto pesa esto frente al ruido real lo mide la FASE 4.

use std::collections::{HashMap, VecDeque};

use aegis_entidad::{Confianza, Eid, Juicio, Motor as Firma, Senal, Severidad};
use aegis_l7hunter::baliza::{analizar, Veredicto, MINIMO_INTERVALOS};
use aegis_motor::{Camino, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::motores::EventoAgente;
use crate::triage::TelemetryEvent;

/// Marcas que se guardan por serie: bastan para el analisis y acotan memoria.
const MARCAS_POR_SERIE: usize = 64;
/// Series que se siguen a la vez.
const MAX_SERIES: usize = 2048;
/// Cada cuanto se analizan las series que crecieron.
const CADA_NS: u64 = 10_000_000_000;
/// Una serie sin marcas en este tiempo se olvida.
const OLVIDO_NS: u64 = 3_600_000_000_000;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Clave {
    entidad: Eid,
    destino: [u8; 16],
    puerto: u16,
}

struct Serie {
    marcas: VecDeque<u64>,
    /// Marcas nuevas desde el ultimo analisis.
    nuevas: usize,
    privado: bool,
    familia: u16,
    notificada: bool,
}

/// Balizas por el ritmo de `connect`.
pub struct MotorBaliza {
    series: HashMap<Clave, Serie>,
    ultimo_ns: u64,
    /// Series que no se pudieron seguir por el tope: se publica.
    descartadas: u64,
    /// Los resolvedores DNS configurados en el sistema, en el formato de 16
    /// bytes de la telemetria. Su puerto 53 no se sigue.
    resolutores: Vec<[u8; 16]>,
}

/// Donde el sistema declara sus resolvedores: el de la libc y, con
/// systemd-resolved, los servidores reales a los que reenvia el stub local.
const FICHEROS_RESOLV: [&str; 2] = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];

/// Las direcciones `nameserver` de un `resolv.conf`, en 16 bytes (IPv4 en los
/// cuatro primeros, como las entrega la sonda).
fn resolutores_de(texto: &str) -> Vec<[u8; 16]> {
    texto
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "nameserver").then_some(())?;
            // Una direccion IPv6 de enlace lleva `%interfaz`: se quita.
            let dir = it.next()?.split('%').next()?;
            match dir.parse::<std::net::IpAddr>().ok()? {
                std::net::IpAddr::V4(v4) => {
                    let mut b = [0u8; 16];
                    b[..4].copy_from_slice(&v4.octets());
                    Some(b)
                }
                std::net::IpAddr::V6(v6) => Some(v6.octets()),
            }
        })
        .collect()
}

impl MotorBaliza {
    /// Vacio, con los resolvedores que el sistema declara ahora.
    pub fn nuevo() -> MotorBaliza {
        let mut resolutores: Vec<[u8; 16]> = FICHEROS_RESOLV
            .iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .flat_map(|t| resolutores_de(&t))
            .collect();
        resolutores.sort_unstable();
        resolutores.dedup();
        MotorBaliza::con_resolutores(resolutores)
    }

    fn con_resolutores(resolutores: Vec<[u8; 16]>) -> MotorBaliza {
        MotorBaliza {
            series: HashMap::new(),
            ultimo_ns: 0,
            descartadas: 0,
            resolutores,
        }
    }

    /// Series que no cupieron.
    pub fn descartadas(&self) -> u64 {
        self.descartadas
    }
}

impl Default for MotorBaliza {
    fn default() -> Self {
        MotorBaliza::nuevo()
    }
}

fn destino(d: &[u8; 16], familia: u16, puerto: u16) -> String {
    if familia == libc_af_inet() {
        format!("{}.{}.{}.{}:{puerto}", d[0], d[1], d[2], d[3])
    } else {
        format!("[{}]:{puerto}", std::net::Ipv6Addr::from(*d))
    }
}

/// `AF_INET` sin depender de libc en este modulo.
const fn libc_af_inet() -> u16 {
    2
}

impl Motor<EventoAgente> for MotorBaliza {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "baliza",
            firma: Firma::L7Hunter,
            camino: Camino::Frio,
            presupuesto: Presupuesto::caliente(20, MAX_SERIES * (MARCAS_POR_SERIE * 8 + 96)),
            requisitos: &[Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        let TelemetryEvent::NetConnect {
            daddr,
            dport,
            family,
            loopback,
            private_dst,
            ts_ns,
            ..
        } = &ev.evento
        else {
            return Dictamen::NoAplica;
        };
        if *loopback || (*dport == 53 && self.resolutores.contains(daddr)) {
            return Dictamen::NoAplica;
        }
        let clave = Clave {
            entidad: ev.entidad.clone(),
            destino: *daddr,
            puerto: *dport,
        };
        if !self.series.contains_key(&clave) && self.series.len() >= MAX_SERIES {
            self.descartadas += 1;
            return Dictamen::NoAplica;
        }
        let s = self.series.entry(clave).or_insert_with(|| Serie {
            marcas: VecDeque::with_capacity(MARCAS_POR_SERIE),
            nuevas: 0,
            privado: *private_dst,
            familia: *family,
            notificada: false,
        });
        if s.marcas.len() == MARCAS_POR_SERIE {
            s.marcas.pop_front();
        }
        s.marcas.push_back(*ts_ns);
        s.nuevas += 1;
        Dictamen::NoAplica
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        if ahora_ns.saturating_sub(self.ultimo_ns) < CADA_NS {
            return Vec::new();
        }
        self.ultimo_ns = ahora_ns;
        self.series.retain(|_, s| {
            s.marcas
                .back()
                .is_some_and(|u| ahora_ns.saturating_sub(*u) < OLVIDO_NS)
        });
        let mut salida = Vec::new();
        for (clave, s) in &mut self.series {
            if s.nuevas == 0 || s.notificada || s.marcas.len() <= MINIMO_INTERVALOS {
                continue;
            }
            s.nuevas = 0;
            let marcas: Vec<u64> = s.marcas.iter().copied().collect();
            let a = analizar(&marcas);
            if !a.veredicto.es_baliza() {
                continue;
            }
            s.notificada = true;
            let Some(m) = a.metricas else { continue };
            // Hacia fuera pesa mas: una baliza interna suele ser un sondeo de
            // monitorizacion, aunque tambien puede ser movimiento lateral.
            let sev = if s.privado {
                Severidad::Baja
            } else {
                Severidad::Media
            };
            let conf = (a.confianza * 50.0).round().clamp(10.0, 50.0) as u8;
            let tipo = match a.veredicto {
                Veredicto::BalizaExacta => "periodica casi exacta",
                _ => "periodica con jitter",
            };
            let senal = Senal::nueva(
                Firma::L7Hunter,
                clave.entidad.clone(),
                Juicio::Sospechoso,
                sev,
                Confianza::nueva(conf),
                format!(
                    "conexiones a {} {tipo}: {} intervalos, CV {:.3} (cota de baliza 0,578), jitter estimado {:.0} %",
                    destino(&clave.destino, s.familia, clave.puerto),
                    m.intervalos,
                    m.cv,
                    m.jitter_estimado() * 100.0
                ),
                ahora_ns,
            );
            salida.push((clave.entidad.clone(), Dictamen::Senales(vec![senal])));
        }
        salida
    }

    fn memoria(&self) -> usize {
        self.series.len() * 96
            + self
                .series
                .values()
                .map(|s| s.marcas.len() * 8)
                .sum::<usize>()
    }

    fn aligerar(&mut self) {
        // Bajo presion se quedan las series con mas historia: son las unicas
        // que pueden llegar a un veredicto pronto.
        self.series
            .retain(|_, s| s.marcas.len() > MINIMO_INTERVALOS / 2);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::graph::ProcKey;
    use crate::motores::Identidad;

    const S: u64 = 1_000_000_000;

    fn connect(ts: u64, publico: bool) -> EventoAgente {
        EventoAgente::nuevo(
            TelemetryEvent::NetConnect {
                actor: ProcKey(77),
                pid: 77,
                daddr: [203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dport: 443,
                family: 2,
                loopback: false,
                private_dst: !publico,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    fn plazo() -> Plazo {
        Plazo::desde_ahora(std::time::Duration::from_secs(1))
    }

    /// Generador determinista (xorshift) para el jitter: la prueba da lo mismo
    /// en cada corrida.
    fn jitter(estado: &mut u64) -> f64 {
        *estado ^= *estado << 13;
        *estado ^= *estado >> 7;
        *estado ^= *estado << 17;
        (*estado % 10_000) as f64 / 10_000.0
    }

    #[test]
    fn una_baliza_de_60_s_con_jitter_del_30_por_ciento_se_señala_una_vez() {
        let mut m = MotorBaliza::nuevo();
        let mut t = 1_000 * S;
        let mut e = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..40 {
            let _ = m.evaluar(&connect(t, true), &plazo());
            // U[S(1-J), S] con S = 60 s y J = 0,3.
            t += (60.0 * (1.0 - 0.3 * jitter(&mut e)) * S as f64) as u64;
        }
        let d = m.mantener(t);
        assert_eq!(d.len(), 1, "{:?}", d.len());
        let Dictamen::Senales(s) = &d[0].1 else {
            panic!()
        };
        assert_eq!(s[0].juicio, Juicio::Sospechoso);
        assert!(s[0].porque.contains("203.0.113.9:443"), "{}", s[0].porque);
        let _ = m.evaluar(&connect(t + 60 * S, true), &plazo());
        assert!(
            m.mantener(t + 3_600 * S / 2).is_empty(),
            "una serie se señala una vez"
        );
    }

    #[test]
    fn las_rafagas_de_un_navegador_no_son_una_baliza() {
        let mut m = MotorBaliza::nuevo();
        let mut t = 1_000 * S;
        let mut e = 42;
        for _ in 0..6 {
            for _ in 0..8 {
                let _ = m.evaluar(&connect(t, true), &plazo());
                t += (0.05 * jitter(&mut e) * S as f64) as u64 + 1;
            }
            t += (30.0 + 300.0 * jitter(&mut e)) as u64 * S;
        }
        assert!(m.mantener(t).is_empty());
    }

    #[test]
    fn el_resolvedor_del_sistema_no_se_sigue_y_otro_puerto_53_si() {
        let conf = "# comentario\nnameserver 203.0.113.9\nnameserver fe80::1%eth0\nsearch x\n";
        let r = resolutores_de(conf);
        assert_eq!(r.len(), 2, "{r:?}");
        let mut m = MotorBaliza::con_resolutores(r);
        let mut ev = connect(S, true);
        if let TelemetryEvent::NetConnect { dport, .. } = &mut ev.evento {
            *dport = 53;
        }
        let _ = m.evaluar(&ev, &plazo());
        assert!(
            m.series.is_empty(),
            "el resolvedor configurado no es una baliza"
        );
        let mut otro = ev.clone();
        if let TelemetryEvent::NetConnect { daddr, .. } = &mut otro.evento {
            daddr[3] = 10;
        }
        let _ = m.evaluar(&otro, &plazo());
        assert_eq!(
            m.series.len(),
            1,
            "un servidor DNS que el sistema no usa si se sigue"
        );
    }

    #[test]
    fn el_tope_de_series_se_respeta_y_se_cuenta() {
        let mut m = MotorBaliza::nuevo();
        for i in 0..(MAX_SERIES as u16 + 10) {
            let mut ev = connect(S, true);
            if let TelemetryEvent::NetConnect { dport, .. } = &mut ev.evento {
                *dport = i;
            }
            let _ = m.evaluar(&ev, &plazo());
        }
        assert_eq!(m.series.len(), MAX_SERIES);
        assert_eq!(m.descartadas(), 10);
    }
}
