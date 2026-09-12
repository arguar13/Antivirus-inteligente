//! Motor ITDR del Control Plane (FASE 58): correlacion de identidad de la flota.
//!
//! El crate [`aegis_itdr`] trae la logica pura de deteccion —Kerberoasting,
//! Golden/Silver Ticket y escaladas sobre el grafo de identidad—. Este modulo la
//! **conecta al plano de control**: mantiene el grafo de identidad de TODA la
//! flota (vivo entre lotes), recibe la telemetria de identidad que suben los
//! agentes, ejecuta los detectores y traduce cada hallazgo a una
//! [`EventoPanel::AlertaNueva`], para que salga por el mismo bus WebSocket que el
//! resto de alertas y con su tecnica MITRE ATT&CK asignada.
//!
//! # Honestidad de validacion
//!
//! La correlacion —lo que puede estar mal de forma peligrosa— se prueba de
//! verdad aqui, de extremo a extremo, con un lote de telemetria de flota realista
//! (un barrido de Kerberoasting, un Silver Ticket y una escalada a la vez). Lo
//! que es un **muro** es la **captura en vivo**: normalizar los eventos 4769 del
//! Registro de Seguridad de un Controlador de Dominio real (o de ETW-Ti, o de la
//! red RPC/SMB) a [`EventoKdc`]/[`UsoServicio`] necesita un dominio Active
//! Directory y privilegios que el CI no tiene. Ese colector se declara gated en
//! `tools/verificar-itdr.sh`; el motor que decide, no.

use aegis_itdr::forjados::{DetectorGolden, DetectorSilver};
use aegis_itdr::grafo::{GrafoIdentidad, Identidad, Relacion};
use aegis_itdr::kerberoasting::DetectorKerberoasting;
use aegis_itdr::kerberos::{EventoKdc, UsoServicio};
use aegis_itdr::{ClaseAmenaza, Deteccion, ItdrError, Severidad};

use crate::eventos::EventoPanel;

/// Una relacion de identidad observada en la flota (una arista del grafo).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AristaObservada {
    /// Identidad de origen (la que gana el acceso).
    pub origen: String,
    /// Identidad de destino (a la que se accede o como la que se actua).
    pub destino: String,
    /// Naturaleza de la relacion.
    pub relacion: Relacion,
}

impl AristaObservada {
    /// Construye una arista observada.
    #[must_use]
    pub fn nueva(
        origen: impl Into<String>,
        destino: impl Into<String>,
        relacion: Relacion,
    ) -> Self {
        Self {
            origen: origen.into(),
            destino: destino.into(),
            relacion,
        }
    }
}

/// Un lote de telemetria de identidad que sube la flota al plano de control.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TelemetriaIdentidad {
    /// Identidades a dar de alta o refrescar en el grafo antes de correlacionar.
    pub identidades: Vec<Identidad>,
    /// Eventos de la KDC (4768/4769/4770) del periodo.
    pub eventos_kdc: Vec<EventoKdc>,
    /// Usos de tickets de servicio observados en los propios servicios.
    pub usos_servicio: Vec<UsoServicio>,
    /// Relaciones ya conocidas que se cargan en el grafo SIN evaluar escalada
    /// (el estado de partida: pertenencias a grupos, credenciales cacheadas).
    pub relaciones_conocidas: Vec<AristaObservada>,
    /// Relaciones nuevas observadas en este periodo: cada una se evalua por si
    /// abre una escalada de privilegios.
    pub relaciones_nuevas: Vec<AristaObservada>,
}

/// El motor ITDR del plano de control. Mantiene el grafo de identidad de la
/// flota vivo entre lotes; los detectores de Kerberos son sin estado y operan
/// sobre cada lote.
#[derive(Debug)]
pub struct MotorItdr {
    kerberoasting: DetectorKerberoasting,
    golden: DetectorGolden,
    silver: DetectorSilver,
    grafo: GrafoIdentidad,
}

impl Default for MotorItdr {
    fn default() -> Self {
        Self {
            kerberoasting: DetectorKerberoasting::nuevo(),
            golden: DetectorGolden::nuevo(),
            silver: DetectorSilver::nuevo(),
            grafo: GrafoIdentidad::nuevo(),
        }
    }
}

impl MotorItdr {
    /// Un motor con los detectores por defecto y un grafo de identidad vacio.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Correlaciona un lote de telemetria de identidad de la flota y devuelve las
    /// detecciones, en orden estable: Kerberoasting, Golden, Silver y luego las
    /// escaladas en el orden en que se observaron.
    ///
    /// # Errores
    /// [`ItdrError::IdentidadDesconocida`] si una relacion referencia una
    /// identidad que no se dio de alta en este lote ni en uno anterior.
    pub fn analizar(&mut self, tel: &TelemetriaIdentidad) -> Result<Vec<Deteccion>, ItdrError> {
        // 1. Dar de alta las identidades del lote.
        for id in &tel.identidades {
            self.grafo.agregar_identidad(id.clone());
        }
        // 2. Cargar el estado conocido del grafo (sin evaluar escaladas).
        for a in &tel.relaciones_conocidas {
            self.grafo
                .agregar_arista(&a.origen, &a.destino, a.relacion)?;
        }

        let mut detecciones = Vec::new();
        // 3. Detectores de Kerberos sobre el lote.
        detecciones.extend(self.kerberoasting.evaluar(&tel.eventos_kdc));
        detecciones.extend(self.golden.evaluar(&tel.eventos_kdc));
        detecciones.extend(self.silver.evaluar(&tel.eventos_kdc, &tel.usos_servicio));

        // 4. Escaladas: cada relacion nueva puede abrir un camino a mas privilegio.
        for a in &tel.relaciones_nuevas {
            if let Some(det) = self
                .grafo
                .observar_arista(&a.origen, &a.destino, a.relacion)?
            {
                detecciones.push(det);
            }
        }
        Ok(detecciones)
    }

    /// Las identidades mas centrales del grafo por intermediacion (los cuellos de
    /// botella del movimiento lateral que conviene endurecer primero).
    #[must_use]
    pub fn nodos_criticos(&self, top: usize) -> Vec<(String, f64)> {
        self.grafo.nodos_criticos(top)
    }
}

/// Traduce una deteccion del motor a una alerta del bus del panel, para que
/// salga por el mismo WebSocket que el resto y con su tecnica MITRE ATT&CK.
///
/// `origen_cn` es el agente/Controlador de Dominio que aporto la telemetria (el
/// campo `cn` del bus); el sujeto de la deteccion (la cuenta implicada) ya viaja
/// dentro de la descripcion.
#[must_use]
pub fn a_evento_panel(det: &Deteccion, origen_cn: &str, id: impl Into<String>) -> EventoPanel {
    let (categoria, mitre) = categoria_y_mitre(det.clase);
    EventoPanel::AlertaNueva {
        id: id.into(),
        cn: origen_cn.to_string(),
        severidad: severidad_num(det.severidad),
        categoria: categoria.to_string(),
        descripcion: det.evidencia.clone(),
        tecnica_mitre: Some(mitre.to_string()),
    }
}

/// Mapea la severidad del motor al 0..4 que usa el panel.
fn severidad_num(s: Severidad) -> i16 {
    match s {
        Severidad::Informativa => 0,
        Severidad::Baja => 1,
        Severidad::Media => 2,
        Severidad::Alta => 3,
        Severidad::Critica => 4,
    }
}

/// La categoria legible y la tecnica MITRE ATT&CK de cada clase de amenaza.
fn categoria_y_mitre(clase: ClaseAmenaza) -> (&'static str, &'static str) {
    match clase {
        // Kerberoasting.
        ClaseAmenaza::Kerberoasting => ("Kerberoasting", "T1558.003"),
        // Forjado de TGT con la clave de krbtgt.
        ClaseAmenaza::GoldenTicket => ("Golden Ticket", "T1558.001"),
        // Forjado de TGS con la clave de la cuenta de servicio.
        ClaseAmenaza::SilverTicket => ("Silver Ticket", "T1558.002"),
        // Manipulacion de token de acceso / impersonacion.
        ClaseAmenaza::EscaladaPrivilegios => ("Escalada de Privilegios", "T1134"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_itdr::grafo::{ClaseIdentidad, Nivel};
    use aegis_itdr::kerberos::TipoCifrado;

    const T0: u64 = 1_800_000_000;
    const HORA: u64 = 3_600;

    fn identidad(nombre: &str, clase: ClaseIdentidad, nivel: Nivel) -> Identidad {
        Identidad::nueva(nombre, clase, nivel)
    }

    /// Un lote realista de flota con TRES ataques a la vez: un barrido de
    /// Kerberoasting, un Golden Ticket, un Silver Ticket y una escalada. El motor
    /// del plano de control los detecta todos, de extremo a extremo.
    #[test]
    fn correlaciona_un_lote_de_flota_con_varios_ataques() {
        let mut tel = TelemetriaIdentidad {
            identidades: vec![
                identidad("alice", ClaseIdentidad::Usuario, Nivel::Usuario),
                identidad("svc-backup", ClaseIdentidad::Servicio, Nivel::Operador),
                identidad("da-root", ClaseIdentidad::Usuario, Nivel::AdminDominio),
            ],
            relaciones_conocidas: vec![AristaObservada::nueva(
                "svc-backup",
                "da-root",
                Relacion::ControlaCredencialesDe,
            )],
            relaciones_nuevas: vec![AristaObservada::nueva(
                "alice",
                "svc-backup",
                Relacion::Impersona,
            )],
            ..Default::default()
        };

        // Kerberoasting: 'wsx' barre 40 SPN distintos con RC4 en 40 s.
        for i in 0..40 {
            tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
                "wsx",
                format!("MSSQLSvc/h{i}.corp.local:1433"),
                TipoCifrado::Rc4Hmac,
                T0 + i,
            ));
        }
        // Golden: 'administrator' pide el MISMO servicio 12 h sin un solo TGT.
        for i in 0..12 {
            tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
                "administrator",
                "CIFS/dc.corp.local",
                TipoCifrado::Rc4Hmac,
                T0 + i * HORA,
            ));
        }
        // Silver: 'attacker' usa un TGS que la KDC nunca emitio.
        tel.usos_servicio.push(UsoServicio {
            cuenta: "attacker".into(),
            spn: "HOST/fileserver.corp.local".into(),
            cifrado: TipoCifrado::Rc4Hmac,
            momento_unix: T0 + 500,
            host_servicio: "fileserver.corp.local".into(),
        });

        let det = MotorItdr::nuevo().analizar(&tel).expect("analisis");
        let clases: Vec<ClaseAmenaza> = det.iter().map(|d| d.clase).collect();
        assert!(clases.contains(&ClaseAmenaza::Kerberoasting), "{clases:?}");
        assert!(clases.contains(&ClaseAmenaza::GoldenTicket), "{clases:?}");
        assert!(clases.contains(&ClaseAmenaza::SilverTicket), "{clases:?}");
        assert!(
            clases.contains(&ClaseAmenaza::EscaladaPrivilegios),
            "{clases:?}"
        );
    }

    #[test]
    fn el_grafo_persiste_entre_lotes() {
        // La escalada usa un camino cargado en un lote ANTERIOR: el grafo es vivo.
        let mut motor = MotorItdr::nuevo();
        let lote1 = TelemetriaIdentidad {
            identidades: vec![
                identidad("svc-x", ClaseIdentidad::Servicio, Nivel::Operador),
                identidad("da", ClaseIdentidad::Usuario, Nivel::AdminDominio),
                identidad("juan", ClaseIdentidad::Usuario, Nivel::Usuario),
            ],
            relaciones_conocidas: vec![AristaObservada::nueva(
                "svc-x",
                "da",
                Relacion::ControlaCredencialesDe,
            )],
            ..Default::default()
        };
        assert!(motor.analizar(&lote1).expect("lote1").is_empty());

        let lote2 = TelemetriaIdentidad {
            relaciones_nuevas: vec![AristaObservada::nueva("juan", "svc-x", Relacion::Impersona)],
            ..Default::default()
        };
        let det = motor.analizar(&lote2).expect("lote2");
        assert_eq!(det.len(), 1);
        assert_eq!(det[0].clase, ClaseAmenaza::EscaladaPrivilegios);
    }

    #[test]
    fn el_mapeo_al_panel_asigna_severidad_y_mitre() {
        let det = Deteccion {
            clase: ClaseAmenaza::Kerberoasting,
            severidad: Severidad::Critica,
            sujeto: "wsx".into(),
            evidencia: "barrido de SPN".into(),
        };
        let ev = a_evento_panel(&det, "dc01", "inc-1");
        match ev {
            EventoPanel::AlertaNueva {
                severidad,
                categoria,
                tecnica_mitre,
                cn,
                ..
            } => {
                assert_eq!(severidad, 4);
                assert_eq!(categoria, "Kerberoasting");
                assert_eq!(tecnica_mitre.as_deref(), Some("T1558.003"));
                assert_eq!(cn, "dc01");
            }
            otro => panic!("se esperaba AlertaNueva, no {otro:?}"),
        }
    }

    #[test]
    fn cada_clase_tiene_su_tecnica_mitre() {
        assert_eq!(
            categoria_y_mitre(ClaseAmenaza::Kerberoasting).1,
            "T1558.003"
        );
        assert_eq!(categoria_y_mitre(ClaseAmenaza::GoldenTicket).1, "T1558.001");
        assert_eq!(categoria_y_mitre(ClaseAmenaza::SilverTicket).1, "T1558.002");
        assert_eq!(
            categoria_y_mitre(ClaseAmenaza::EscaladaPrivilegios).1,
            "T1134"
        );
    }
}
