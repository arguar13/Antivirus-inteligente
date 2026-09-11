//! Deteccion de Kerberoasting.
//!
//! ## Que es y como se ve
//!
//! Kerberoasting abusa de un hecho de diseno de Kerberos: cualquier usuario
//! autenticado puede pedir un ticket de servicio (`TGS`) para cualquier SPN, y
//! ese ticket va cifrado con la clave de la **cuenta de servicio**. El atacante
//! pide tickets en masa y los craquea **offline** para recuperar la contrasena
//! de la cuenta de servicio; la KDC no ve nada raro, porque pedir tickets es lo
//! normal.
//!
//! Lo que delata al atacante son DOS formas, no el volumen:
//!
//! 1. **Barrido de SPN**: una sola cuenta pide tickets para MUCHOS servicios
//!    distintos en poco tiempo. Un usuario normal usa un punado de servicios; un
//!    atacante enumera el dominio entero.
//! 2. **Degradado de cifrado**: pedir **RC4** (crackeable rapido) en un dominio
//!    que usa AES. No hay razon legitima para que un cliente moderno pida RC4
//!    para varios servicios distintos; el atacante lo hace para que el crackeo
//!    sea viable.
//!
//! ## El caso que separa un buen detector de uno malo
//!
//! El test decisivo no es "detecta el barrido" —eso lo hace cualquier contador—.
//! Es **no disparar con un servicio legitimo de alto volumen**: una cuenta de
//! monitorizacion (SCOM, un backup) pide EL MISMO punado de tickets miles de
//! veces con AES. Tiene volumen enorme pero **pocos SPN distintos** y **cero
//! degradado**, asi que no es Kerberoasting. Un detector que cuente solicitudes
//! ahogaria al analista en falsos positivos —y una alarma que casi siempre
//! miente ensena a ignorar todas—. Por eso aqui se cuentan **SPN distintos** y
//! **degradados distintos**, no solicitudes.

use std::collections::{BTreeMap, HashMap};

use crate::kerberos::{EventoKdc, PoliticaDominio, TipoEventoKdc};
use crate::{ClaseAmenaza, Deteccion, Severidad};

/// Detector de Kerberoasting sobre un lote de eventos de la KDC.
#[derive(Debug, Clone, Copy)]
pub struct DetectorKerberoasting {
    /// Ventana deslizante, en segundos, sobre la que se cuentan los SPN
    /// distintos de una cuenta. Por defecto una hora.
    pub ventana_seg: u64,
    /// SPN distintos en la ventana para considerarlo un barrido. Por defecto 12:
    /// un cliente legitimo rara vez toca tantos servicios distintos en una hora.
    pub umbral_spns: usize,
    /// SPN distintos pedidos con cifrado debil (RC4/DES) para considerarlo un
    /// degradado deliberado. Por defecto 5: un par de servicios heredados en RC4
    /// es normal; cinco servicios distintos degradados a la vez, no.
    pub umbral_debiles: usize,
    /// Politica del dominio (si exige AES, un degradado es sospechoso).
    pub politica: PoliticaDominio,
}

impl Default for DetectorKerberoasting {
    fn default() -> Self {
        Self {
            ventana_seg: 3_600,
            umbral_spns: 12,
            umbral_debiles: 5,
            politica: PoliticaDominio::tipica(),
        }
    }
}

impl DetectorKerberoasting {
    /// El detector con los umbrales por defecto.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Evalua un lote de eventos y devuelve una deteccion por cada cuenta cuya
    /// actividad de peticion de tickets encaja con Kerberoasting. El orden es
    /// estable (por nombre de cuenta) para que las pruebas y la cola de alertas
    /// sean deterministas.
    #[must_use]
    pub fn evaluar(&self, eventos: &[EventoKdc]) -> Vec<Deteccion> {
        // Agrupar las solicitudes de servicio (4769) por cuenta.
        let mut por_cuenta: BTreeMap<&str, Vec<(u64, &str, bool)>> = BTreeMap::new();
        for e in eventos {
            if e.tipo == TipoEventoKdc::SolicitudServicio {
                if let Some(spn) = &e.spn {
                    por_cuenta.entry(e.cuenta.as_str()).or_default().push((
                        e.momento_unix,
                        spn.as_str(),
                        e.cifrado.es_debil(),
                    ));
                }
            }
        }

        let mut detecciones = Vec::new();
        for (cuenta, mut lista) in por_cuenta {
            lista.sort_by_key(|(t, _, _)| *t);
            let (distintos, debiles, total) = self.ventana_maxima(&lista);
            if let Some(det) = self.juzgar(cuenta, distintos, debiles, total) {
                detecciones.push(det);
            }
        }
        detecciones
    }

    /// Desliza la ventana sobre las solicitudes ordenadas de una cuenta y
    /// devuelve `(max SPN distintos, max SPN debiles distintos, total)` en la
    /// ventana mas densa. Cuenta SPN distintos, no solicitudes: esa es la
    /// diferencia entre detectar un barrido y castigar a un servicio ocupado.
    fn ventana_maxima(&self, lista: &[(u64, &str, bool)]) -> (usize, usize, usize) {
        let mut activos: HashMap<&str, (u32, u32)> = HashMap::new(); // spn -> (total, debiles)
        let mut inicio = 0usize;
        let mut max_distintos = 0usize;
        let mut max_debiles = 0usize;

        for j in 0..lista.len() {
            let (tj, spnj, debilj) = lista[j];
            let ent = activos.entry(spnj).or_insert((0, 0));
            ent.0 += 1;
            if debilj {
                ent.1 += 1;
            }

            // Encoger por la izquierda mientras la ventana sea demasiado ancha.
            while tj - lista[inicio].0 > self.ventana_seg {
                let (_, spni, debili) = lista[inicio];
                if let Some(e) = activos.get_mut(spni) {
                    e.0 -= 1;
                    if debili {
                        e.1 -= 1;
                    }
                    if e.0 == 0 {
                        activos.remove(spni);
                    }
                }
                inicio += 1;
            }

            let distintos = activos.len();
            let debiles = activos.values().filter(|&&(_, d)| d > 0).count();
            max_distintos = max_distintos.max(distintos);
            max_debiles = max_debiles.max(debiles);
        }
        (max_distintos, max_debiles, lista.len())
    }

    /// Aplica las dos reglas a los maximos de una cuenta.
    fn juzgar(
        &self,
        cuenta: &str,
        distintos: usize,
        debiles: usize,
        total: usize,
    ) -> Option<Deteccion> {
        let barrido = distintos >= self.umbral_spns;
        let degradado_amplio = self.politica.exige_aes && debiles >= self.umbral_debiles;
        if !barrido && !degradado_amplio {
            return None;
        }

        let severidad = if barrido && debiles >= self.umbral_debiles {
            Severidad::Critica
        } else {
            Severidad::Alta
        };

        let motivo = if barrido {
            "barrido de SPN"
        } else {
            "degradado de cifrado en varios servicios (Kerberoasting sigiloso)"
        };
        let evidencia = format!(
            "La cuenta '{cuenta}' pidio {distintos} SPN distintos ({total} solicitudes) en una \
             ventana de {vent}s, {debiles} de ellos con cifrado debil (RC4/DES). Patron: {motivo}. \
             Umbrales: barrido>={ub}, degradado>={ud}.",
            vent = self.ventana_seg,
            ub = self.umbral_spns,
            ud = self.umbral_debiles,
        );

        Some(Deteccion::nueva(
            ClaseAmenaza::Kerberoasting,
            severidad,
            cuenta,
            evidencia,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kerberos::TipoCifrado;

    const T0: u64 = 1_800_000_000;

    fn s4769(cuenta: &str, spn: &str, cif: TipoCifrado, t: u64) -> EventoKdc {
        EventoKdc::solicitud_servicio(cuenta, spn, cif, t)
    }

    #[test]
    fn un_barrido_de_spn_con_rc4_es_kerberoasting_critico() {
        // El atacante enumera 40 servicios distintos en 30 segundos, todos RC4.
        let mut ev = Vec::new();
        for i in 0..40 {
            ev.push(s4769(
                "wsx-comprometida",
                &format!("MSSQLSvc/host{i}.corp.local:1433"),
                TipoCifrado::Rc4Hmac,
                T0 + i,
            ));
        }
        let det = DetectorKerberoasting::nuevo().evaluar(&ev);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].clase, ClaseAmenaza::Kerberoasting);
        assert_eq!(det[0].severidad, Severidad::Critica);
        assert_eq!(det[0].sujeto, "wsx-comprometida");
    }

    #[test]
    fn un_servicio_legitimo_de_alto_volumen_no_dispara() {
        // EL CASO DECISIVO. Una cuenta de monitorizacion pide EL MISMO punado de
        // 3 tickets 150 veces en una hora, todo AES256. Volumen enorme, pero
        // pocos SPN distintos y cero degradado: NO es Kerberoasting.
        let spns = [
            "HTTP/monitor.corp.local",
            "MSSQLSvc/db.corp.local:1433",
            "HOST/dc.corp.local",
        ];
        let mut ev = Vec::new();
        for i in 0..150u64 {
            let spn = spns[(i % 3) as usize];
            ev.push(s4769("svc-monitor", spn, TipoCifrado::Aes256, T0 + i * 20));
        }
        let det = DetectorKerberoasting::nuevo().evaluar(&ev);
        assert!(
            det.is_empty(),
            "un servicio legitimo de alto volumen no debe dispararse: {det:?}"
        );
    }

    #[test]
    fn una_estacion_normal_con_pocos_servicios_no_dispara() {
        // Un usuario real toca 6 servicios distintos a lo largo del dia, con AES.
        let spns = [
            "CIFS/fs1.corp.local",
            "HTTP/intranet.corp.local",
            "HOST/print1.corp.local",
            "LDAP/dc.corp.local",
            "MSSQLSvc/erp.corp.local:1433",
            "TERMSRV/jump.corp.local",
        ];
        let mut ev = Vec::new();
        for (i, spn) in spns.iter().enumerate() {
            ev.push(s4769(
                "alice",
                spn,
                TipoCifrado::Aes256,
                T0 + (i as u64) * 3_600,
            ));
        }
        assert!(DetectorKerberoasting::nuevo().evaluar(&ev).is_empty());
    }

    #[test]
    fn un_degradado_sigiloso_por_debajo_del_barrido_se_detecta() {
        // 8 SPN distintos (por debajo del umbral de barrido, 12) pero TODOS RC4
        // en un dominio AES: la regla de degradado amplio lo caza. Es el atacante
        // "lento y sigiloso" que evita el barrido evidente.
        let mut ev = Vec::new();
        for i in 0..8 {
            ev.push(s4769(
                "cuenta-sigilosa",
                &format!("HTTP/app{i}.corp.local"),
                TipoCifrado::Rc4Hmac,
                T0 + i * 120,
            ));
        }
        let det = DetectorKerberoasting::nuevo().evaluar(&ev);
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].severidad, Severidad::Alta);
    }

    #[test]
    fn un_par_de_servicios_heredados_en_rc4_no_dispara() {
        // Dos servicios legacy que legitimamente usan RC4: por debajo del umbral
        // de degradado (5), no se castiga la realidad de un dominio con historia.
        let ev = vec![
            s4769("bob", "HTTP/legacy1.corp.local", TipoCifrado::Rc4Hmac, T0),
            s4769(
                "bob",
                "HTTP/legacy2.corp.local",
                TipoCifrado::Rc4Hmac,
                T0 + 60,
            ),
        ];
        assert!(DetectorKerberoasting::nuevo().evaluar(&ev).is_empty());
    }

    #[test]
    fn el_barrido_solo_cuenta_dentro_de_la_ventana() {
        // 20 SPN distintos pero repartidos en 20 horas (uno por hora): en ninguna
        // ventana de 1h hay mas de un pico bajo. No es un barrido.
        let mut ev = Vec::new();
        for i in 0..20 {
            ev.push(s4769(
                "cuenta-lenta",
                &format!("HTTP/app{i}.corp.local"),
                TipoCifrado::Aes256,
                T0 + i * 3_600,
            ));
        }
        assert!(DetectorKerberoasting::nuevo().evaluar(&ev).is_empty());
    }
}
