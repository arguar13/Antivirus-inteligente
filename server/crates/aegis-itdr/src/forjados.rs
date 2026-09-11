//! Deteccion de tickets forjados: Golden Ticket y Silver Ticket.
//!
//! ## El ataque
//!
//! - **Golden Ticket**: el atacante robo la clave de la cuenta `krbtgt` y forja
//!   un **TGT** a medida. Como lo fabrica offline, controla todos los campos: se
//!   pone la vida que quiere (Mimikatz, 10 anos por defecto) y el usuario que
//!   quiere. Lo delator es que **la KDC nunca lo emitio**: el atacante usa ese
//!   TGT forjado para pedir servicios (4769) sin haberse autenticado antes
//!   (4768).
//! - **Silver Ticket**: el atacante robo la clave de una **cuenta de servicio** y
//!   forja directamente un **ticket de servicio** (TGS) para ella. Es aun mas
//!   sigiloso: **nunca toca la KDC**, asi que no hay ni 4768 ni 4769. Solo se ve
//!   en el propio servicio, cuando el ticket forjado se **usa**.
//!
//! ## Como se detectan sin falsos positivos
//!
//! El riesgo de estos detectores es al reves que el de Kerberoasting: aqui es
//! facil disparar de mas. Un usuario legitimo que obtuvo su TGT hace seis horas
//! y pide servicios toda la tarde **no** es un Golden Ticket, aunque su 4768 sea
//! viejo. Por eso:
//!
//! - El **TGT huerfano** solo se marca cuando una cuenta tiene actividad de
//!   servicio (4769) a lo largo de **mas de una vida de TGT** y en todo ese lapso
//!   **no aparece ni un solo** 4768/4770. Un TGT legitimo caduca a las 10 horas y
//!   obliga a reautenticarse; una cuenta activa 10+ horas sin un solo 4768 esta
//!   usando un TGT que la KDC no emitio.
//! - La **vida imposible** se marca cuando la vida solicitada supera el tope de
//!   renovacion del dominio (7 dias). Ni con renovaciones un TGT real llega ahi.
//! - El **Silver** se marca cuando un ticket se **usa** en un servicio y la KDC
//!   no tiene el 4769 que lo respalde dentro de la ventana (con una tolerancia de
//!   reloj). Si la KDC nunca lo emitio, se forjo.

use std::collections::{BTreeMap, BTreeSet};

use crate::kerberos::{EventoKdc, PoliticaDominio, TipoEventoKdc, UsoServicio};
use crate::{ClaseAmenaza, Deteccion, Severidad};

/// Detector de Golden Ticket sobre los eventos de la KDC.
#[derive(Debug, Clone, Copy)]
pub struct DetectorGolden {
    /// Ventana de correlacion, en segundos: cuanto tiene que abarcar la
    /// actividad de servicio de una cuenta —sin un solo TGT— para considerarla un
    /// TGT huerfano. Por defecto una vida de TGT (10 horas).
    pub ventana_correlacion_seg: u64,
    /// Politica del dominio (define el tope de vida contra el que se juzga lo
    /// imposible).
    pub politica: PoliticaDominio,
}

impl Default for DetectorGolden {
    fn default() -> Self {
        Self {
            ventana_correlacion_seg: 36_000,
            politica: PoliticaDominio::tipica(),
        }
    }
}

impl DetectorGolden {
    /// El detector con los valores por defecto.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Evalua un lote de eventos de la KDC y devuelve una deteccion por cada
    /// cuenta con indicios de un TGT forjado. Orden estable por cuenta.
    #[must_use]
    pub fn evaluar(&self, eventos: &[EventoKdc]) -> Vec<Deteccion> {
        // Por cuenta: momentos de actividad de TGT (4768/4770), momentos de
        // servicio (4769) y la peor vida solicitada vista.
        struct Actividad {
            tgt: bool,
            servicio: Vec<u64>,
            vida_max_vista: Option<u32>,
        }
        let mut por_cuenta: BTreeMap<&str, Actividad> = BTreeMap::new();

        for e in eventos {
            let a = por_cuenta.entry(e.cuenta.as_str()).or_insert(Actividad {
                tgt: false,
                servicio: Vec::new(),
                vida_max_vista: None,
            });
            match e.tipo {
                TipoEventoKdc::SolicitudTgt | TipoEventoKdc::RenovacionTgt => a.tgt = true,
                TipoEventoKdc::SolicitudServicio => a.servicio.push(e.momento_unix),
                TipoEventoKdc::PreautenticacionFallida => {}
            }
            if let Some(v) = e.vida_solicitada_seg {
                a.vida_max_vista = Some(a.vida_max_vista.map_or(v, |m| m.max(v)));
            }
        }

        let mut detecciones = Vec::new();
        for (cuenta, a) in &por_cuenta {
            let mut motivos: Vec<String> = Vec::new();

            // Regla 1: TGT huerfano.
            if !a.tgt && !a.servicio.is_empty() {
                let min = a.servicio.iter().copied().min().unwrap_or(0);
                let max = a.servicio.iter().copied().max().unwrap_or(0);
                if max - min >= self.ventana_correlacion_seg {
                    motivos.push(format!(
                        "pidio servicios (4769) durante {}s sin un solo TGT emitido (4768/4770): \
                         el TGT se forjo (Golden Ticket)",
                        max - min
                    ));
                }
            }

            // Regla 2: vida imposible.
            if let Some(v) = a.vida_max_vista {
                if u64::from(v) > u64::from(self.politica.vida_max_renovacion_seg) {
                    motivos.push(format!(
                        "solicito un ticket con vida de {v}s, por encima del tope de renovacion \
                         del dominio ({}s): imposible en un TGT legitimo",
                        self.politica.vida_max_renovacion_seg
                    ));
                }
            }

            if !motivos.is_empty() {
                detecciones.push(Deteccion::nueva(
                    ClaseAmenaza::GoldenTicket,
                    Severidad::Critica,
                    *cuenta,
                    format!("La cuenta '{cuenta}' {}.", motivos.join("; y ")),
                ));
            }
        }
        detecciones
    }
}

/// Detector de Silver Ticket: cruza el uso de tickets en los servicios con lo
/// que la KDC emitio.
#[derive(Debug, Clone, Copy)]
pub struct DetectorSilver {
    /// Ventana, en segundos, en la que un uso de ticket debe tener un 4769 que lo
    /// respalde. Por defecto una vida de ticket de servicio (10 horas).
    pub ventana_seg: u64,
    /// Tolerancia de reloj, en segundos, entre el reloj de la KDC y el del
    /// servicio, para no marcar un uso legitimo por un desfase de relojes.
    pub tolerancia_reloj_seg: u64,
}

impl Default for DetectorSilver {
    fn default() -> Self {
        Self {
            ventana_seg: 36_000,
            tolerancia_reloj_seg: 300,
        }
    }
}

impl DetectorSilver {
    /// El detector con los valores por defecto.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Cruza los usos de tickets con los eventos de la KDC. Un uso sin 4769 que
    /// lo respalde es un ticket forjado que nunca paso por la KDC (Silver
    /// Ticket). Devuelve una deteccion por cada par (cuenta, SPN) huerfano.
    #[must_use]
    pub fn evaluar(&self, kdc: &[EventoKdc], usos: &[UsoServicio]) -> Vec<Deteccion> {
        // Indice de las emisiones de la KDC por (cuenta, SPN) -> momentos.
        let mut emitidos: BTreeMap<(&str, &str), Vec<u64>> = BTreeMap::new();
        for e in kdc {
            if e.tipo == TipoEventoKdc::SolicitudServicio {
                if let Some(spn) = &e.spn {
                    emitidos
                        .entry((e.cuenta.as_str(), spn.as_str()))
                        .or_default()
                        .push(e.momento_unix);
                }
            }
        }

        let mut vistos: BTreeSet<(&str, &str)> = BTreeSet::new();
        let mut detecciones = Vec::new();
        for uso in usos {
            let clave = (uso.cuenta.as_str(), uso.spn.as_str());
            let respaldado = emitidos.get(&clave).is_some_and(|momentos| {
                momentos.iter().any(|&t0| {
                    // El 4769 debe ser anterior al uso (con tolerancia de reloj)
                    // y dentro de la ventana de validez.
                    let dentro_por_delante = uso.momento_unix + self.tolerancia_reloj_seg >= t0;
                    let dentro_por_detras = t0 + self.ventana_seg >= uso.momento_unix;
                    dentro_por_delante && dentro_por_detras
                })
            });

            if !respaldado && vistos.insert(clave) {
                detecciones.push(Deteccion::nueva(
                    ClaseAmenaza::SilverTicket,
                    Severidad::Critica,
                    uso.cuenta.clone(),
                    format!(
                        "La cuenta '{}' uso un ticket para '{}' en '{}' que la KDC nunca emitio \
                         (sin 4769 que lo respalde): ticket de servicio forjado (Silver Ticket).",
                        uso.cuenta, uso.spn, uso.host_servicio
                    ),
                ));
            }
        }
        detecciones
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kerberos::TipoCifrado;

    const T0: u64 = 1_800_000_000;
    const HORA: u64 = 3_600;

    // --- Golden ------------------------------------------------------------

    #[test]
    fn un_tgt_huerfano_es_golden_ticket() {
        // La cuenta pide servicios durante 12 horas y NUNCA hay un 4768/4770.
        let mut ev = Vec::new();
        for i in 0..12 {
            ev.push(EventoKdc::solicitud_servicio(
                "administrator",
                "CIFS/dc.corp.local",
                TipoCifrado::Rc4Hmac,
                T0 + i * HORA,
            ));
        }
        let det = DetectorGolden::nuevo().evaluar(&ev);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].clase, ClaseAmenaza::GoldenTicket);
        assert_eq!(det[0].severidad, Severidad::Critica);
    }

    #[test]
    fn un_usuario_con_tgt_viejo_pero_valido_no_es_golden() {
        // EL CASO DECISIVO del Golden: un 4768 a las 08:00 y servicios toda la
        // tarde. El TGT es viejo pero LEGITIMO: no se marca.
        let mut ev = vec![EventoKdc::solicitud_tgt("alice", TipoCifrado::Aes256, T0)];
        for i in 1..10 {
            ev.push(EventoKdc::solicitud_servicio(
                "alice",
                "HTTP/intranet.corp.local",
                TipoCifrado::Aes256,
                T0 + i * HORA,
            ));
        }
        assert!(
            DetectorGolden::nuevo().evaluar(&ev).is_empty(),
            "un TGT viejo pero valido no es un Golden Ticket"
        );
    }

    #[test]
    fn una_rafaga_corta_sin_tgt_no_se_marca_por_huerfano() {
        // Sin ventana suficiente (rafaga de 5 min), la regla de huerfano NO
        // dispara: preferimos no inventar un Golden sobre datos parciales. (Este
        // caso stealth se atrapa por otras vias, no fingiendo certeza.)
        let mut ev = Vec::new();
        for i in 0..5 {
            ev.push(EventoKdc::solicitud_servicio(
                "svc-x",
                "MSSQLSvc/db:1433",
                TipoCifrado::Aes256,
                T0 + i * 60,
            ));
        }
        assert!(DetectorGolden::nuevo().evaluar(&ev).is_empty());
    }

    #[test]
    fn una_vida_de_diez_anos_es_golden_por_imposible() {
        // Regla independiente: aunque hubiera un 4768, una vida de 10 anos es
        // imposible en un dominio real.
        let ev = vec![EventoKdc {
            tipo: TipoEventoKdc::SolicitudTgt,
            cuenta: "administrator".into(),
            spn: None,
            cifrado: TipoCifrado::Rc4Hmac,
            momento_unix: T0,
            vida_solicitada_seg: Some(315_360_000), // 10 anos
        }];
        let det = DetectorGolden::nuevo().evaluar(&ev);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].clase, ClaseAmenaza::GoldenTicket);
    }

    // --- Silver ------------------------------------------------------------

    #[test]
    fn un_uso_sin_4769_es_silver_ticket() {
        // El atacante forja un TGS para MSSQLSvc y lo usa. La KDC no tiene NADA
        // para esa cuenta y servicio.
        let kdc = vec![EventoKdc::solicitud_servicio(
            "alice",
            "HTTP/web.corp.local",
            TipoCifrado::Aes256,
            T0,
        )];
        let usos = vec![UsoServicio {
            cuenta: "attacker".into(),
            spn: "MSSQLSvc/db.corp.local:1433".into(),
            cifrado: TipoCifrado::Rc4Hmac,
            momento_unix: T0 + 100,
            host_servicio: "db.corp.local".into(),
        }];
        let det = DetectorSilver::nuevo().evaluar(&kdc, &usos);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].clase, ClaseAmenaza::SilverTicket);
        assert_eq!(det[0].sujeto, "attacker");
    }

    #[test]
    fn un_uso_respaldado_por_su_4769_no_es_silver() {
        // EL CASO DECISIVO del Silver: el uso legitimo SIEMPRE tiene su 4769
        // emitido antes por la KDC.
        let kdc = vec![EventoKdc::solicitud_servicio(
            "alice",
            "HTTP/web.corp.local",
            TipoCifrado::Aes256,
            T0,
        )];
        let usos = vec![UsoServicio {
            cuenta: "alice".into(),
            spn: "HTTP/web.corp.local".into(),
            cifrado: TipoCifrado::Aes256,
            momento_unix: T0 + 60,
            host_servicio: "web.corp.local".into(),
        }];
        assert!(DetectorSilver::nuevo().evaluar(&kdc, &usos).is_empty());
    }

    #[test]
    fn el_4769_de_otra_cuenta_no_respalda_el_uso() {
        // La KDC emitio un ticket para 'bob' hacia el servicio, pero el uso lo
        // hace 'alice': el ticket de alice sigue siendo huerfano (forjado).
        let kdc = vec![EventoKdc::solicitud_servicio(
            "bob",
            "HTTP/web.corp.local",
            TipoCifrado::Aes256,
            T0,
        )];
        let usos = vec![UsoServicio {
            cuenta: "alice".into(),
            spn: "HTTP/web.corp.local".into(),
            cifrado: TipoCifrado::Aes256,
            momento_unix: T0 + 60,
            host_servicio: "web.corp.local".into(),
        }];
        let det = DetectorSilver::nuevo().evaluar(&kdc, &usos);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].sujeto, "alice");
    }
}
