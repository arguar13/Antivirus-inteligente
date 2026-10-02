//! Nucleo del plano de control: la logica, independiente del transporte.
//!
//! # Por que existe esta capa
//!
//! El mismo agente puede llegar por dos caminos: el transporte NATIVO de la
//! flota (protobuf con enmarcado de gRPC sobre mTLS crudo, que es lo que habla
//! el agente real) y la superficie gRPC ESTANDAR sobre HTTP/2 (para
//! integraciones de terceros y SIEM). Si cada transporte llevara su propia
//! logica, acabarian divergiendo y un endpoint recibiria una decision distinta
//! segun por donde entrase. Aqui la decision es una sola; los transportes solo
//! traducen bytes.

use chrono::{DateTime, TimeZone, Utc};

use crate::almacen::{Almacen, EstadoLatido, IngestaStix, NodoGrafo, NuevaAlerta};
use crate::error::Resultado;
use crate::eventos::{BusEventos, EventoPanel};

/// Servicio de flota: la logica que ven todos los transportes.
#[derive(Clone)]
pub struct ServicioFlota {
    almacen: Almacen,
    intervalo_latido_seg: u64,
    /// Bus por el que los sucesos llegan al panel en tiempo real.
    bus: BusEventos,
    /// Salida de auditoria hacia el SIEM del cliente. `None` = no configurada.
    firehose: Option<std::sync::Arc<crate::firehose::Firehose>>,
}

/// Clasificacion MITRE ATT&CK de una categoria de evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaseMitre {
    /// Identificador de la tecnica, p. ej. `T1055`.
    pub tecnica: &'static str,
    /// Tactica a la que pertenece.
    pub tactica: &'static str,
}

/// Traduce la categoria que reporta el agente a una tecnica de MITRE ATT&CK.
///
/// El agente reporta lo que OBSERVA ("inyeccion", "ransomware"); el analista
/// razona en el marco de ATT&CK. Esta traduccion es la que permite que una
/// alerta encaje en un mapa de cobertura y se correlacione con inteligencia
/// externa, en vez de quedarse en una etiqueta propia que solo entiende este
/// producto.
///
/// Las categorias corresponden a los detectores del agente (FASES 1-35).
pub fn clasificar_mitre(categoria: &str) -> Option<ClaseMitre> {
    let c = categoria.to_ascii_lowercase();
    let clase = match c.as_str() {
        "inyeccion" | "inyeccion_proceso" | "hollowing" => ClaseMitre {
            tecnica: "T1055",
            tactica: "Evasion de defensas",
        },
        "ransomware" | "cifrado_masivo" => ClaseMitre {
            tecnica: "T1486",
            tactica: "Impacto",
        },
        "rootkit" | "dkom" | "proceso_oculto" => ClaseMitre {
            tecnica: "T1014",
            tactica: "Evasion de defensas",
        },
        "bootkit" | "firmware" | "arranque_seguro" => ClaseMitre {
            tecnica: "T1542",
            tactica: "Persistencia",
        },
        "persistencia" | "servicio" | "tarea_programada" => ClaseMitre {
            tecnica: "T1543",
            tactica: "Persistencia",
        },
        "credenciales" | "volcado_lsass" => ClaseMitre {
            tecnica: "T1003",
            tactica: "Acceso a credenciales",
        },
        "escalada" | "escalada_privilegios" => ClaseMitre {
            tecnica: "T1068",
            tactica: "Escalada de privilegios",
        },
        "syscall_directa" | "evasion" | "desenganche" => ClaseMitre {
            tecnica: "T1562.001",
            tactica: "Evasion de defensas",
        },
        "empaquetado" | "ofuscacion" | "unpacker" => ClaseMitre {
            tecnica: "T1027.002",
            tactica: "Evasion de defensas",
        },
        "exfiltracion" | "c2" | "baliza" => ClaseMitre {
            tecnica: "T1041",
            tactica: "Exfiltracion",
        },
        // --- Identidad (ITDR, FASE 58) -----------------------------------
        // Estas cuatro entran con el nombre EXACTO con el que
        // `crate::itdr::categoria_y_mitre` las anuncia en el bus del panel. Si
        // no estuvieran, la misma deteccion saldria al WebSocket con tecnica y
        // se persistiria sin ella: las heuristicas globales (FASE 45) agrupan
        // por tecnica, asi que media campana caeria en un grupo y media en
        // ninguno, y ninguno alcanzaria el minimo de endpoints para disparar.
        "kerberoasting" => ClaseMitre {
            tecnica: "T1558.003",
            tactica: "Acceso a credenciales",
        },
        "golden ticket" | "golden_ticket" => ClaseMitre {
            tecnica: "T1558.001",
            tactica: "Acceso a credenciales",
        },
        "silver ticket" | "silver_ticket" => ClaseMitre {
            tecnica: "T1558.002",
            tactica: "Acceso a credenciales",
        },
        // OJO: no es la misma tecnica que `escalada_privilegios` de arriba, y no
        // es un descuido. Aquella es la escalada LOCAL que ve el agente
        // (explotacion de una vulnerabilidad, T1068); esta es la escalada por
        // IMPERSONACION que ve el grafo de identidad del plano de control
        // (manipulacion de token de acceso, T1134). Colapsarlas en una sola
        // tecnica haria que un exploit local y un robo de identidad de dominio
        // se agruparan como la misma campana.
        "escalada de privilegios" => ClaseMitre {
            tecnica: "T1134",
            tactica: "Escalada de privilegios",
        },
        "movimiento_lateral" | "smb" => ClaseMitre {
            tecnica: "T1021",
            tactica: "Movimiento lateral",
        },
        "manipulacion_logs" | "borrado_evidencia" => ClaseMitre {
            tecnica: "T1070",
            tactica: "Evasion de defensas",
        },
        _ => return None,
    };
    Some(clase)
}

/// Convierte una marca Unix del agente en fecha, acotando valores absurdos.
///
/// Un agente con el reloj roto —o manipulado por el atacante para enterrar una
/// alerta en el pasado— no debe poder escribir una fecha arbitraria en el
/// historico. Fuera de rango, se usa la hora de recepcion.
fn momento_o_ahora(unix: u64) -> DateTime<Utc> {
    let ahora = Utc::now();
    if unix == 0 {
        return ahora;
    }
    match Utc.timestamp_opt(unix as i64, 0) {
        chrono::LocalResult::Single(t) => {
            let margen = chrono::Duration::days(365);
            if t > ahora + chrono::Duration::hours(1) || t < ahora - margen {
                ahora
            } else {
                t
            }
        }
        _ => ahora,
    }
}

/// Acota la severidad que declara el agente al rango del esquema.
fn severidad_acotada(s: u64) -> i16 {
    s.min(4) as i16
}

impl ServicioFlota {
    /// Crea el servicio sobre un almacen.
    pub fn nuevo(almacen: Almacen, intervalo_latido_seg: u64) -> ServicioFlota {
        ServicioFlota {
            almacen,
            intervalo_latido_seg,
            bus: BusEventos::nuevo(),
            firehose: None,
        }
    }

    /// Conecta la salida de auditoria hacia el SIEM del cliente (FASE 46).
    ///
    /// Es OPCIONAL a proposito. Un despliegue sin SIEM tiene que funcionar
    /// igual: el producto no puede dejar de detectar porque el cliente aun no
    /// haya integrado su plataforma de eventos.
    pub fn con_firehose(mut self, f: std::sync::Arc<crate::firehose::Firehose>) -> ServicioFlota {
        self.firehose = Some(f);
        self
    }

    /// Salida de auditoria, si esta configurada.
    pub fn firehose(&self) -> Option<&std::sync::Arc<crate::firehose::Firehose>> {
        self.firehose.as_ref()
    }

    /// Crea el servicio compartiendo un bus de eventos ya existente.
    pub fn con_bus(almacen: Almacen, intervalo_latido_seg: u64, bus: BusEventos) -> ServicioFlota {
        ServicioFlota {
            almacen,
            intervalo_latido_seg,
            bus,
            firehose: None,
        }
    }

    /// Bus de eventos, para que la API abra suscripciones de WebSocket.
    pub fn bus(&self) -> &BusEventos {
        &self.bus
    }

    /// Acceso al almacen, para la API de administracion.
    pub fn almacen(&self) -> &Almacen {
        &self.almacen
    }

    /// Intervalo de latido que se entrega a los agentes.
    pub fn intervalo_latido_seg(&self) -> u64 {
        self.intervalo_latido_seg
    }

    /// Enrola un agente. `cn` viene del certificado, no del mensaje.
    pub async fn enrolar(
        &self,
        cn: &str,
        id_agente: &str,
        hostname: &str,
        version_agente: &str,
        huella_cert: &[u8],
    ) -> Resultado<String> {
        // El identificador de flota se deriva del CN autenticado: un agente no
        // puede elegir en que flota entra declarandolo en el mensaje.
        // La misma regla con la que la API decide de quien es un agente.
        let id_flota = crate::autorizacion::inquilino_de_cn(cn);
        self.almacen
            .enrolar(
                cn,
                id_agente,
                hostname,
                version_agente,
                huella_cert,
                &id_flota,
            )
            .await?;
        Ok(id_flota)
    }

    /// Procesa un latido.
    pub async fn latido(
        &self,
        cn: &str,
        rss_kb: u64,
        amenazas_activas: u64,
        version_politica: u64,
    ) -> Resultado<EstadoLatido> {
        let estado = self
            .almacen
            .registrar_latido(
                cn,
                rss_kb.min(i64::MAX as u64) as i64,
                amenazas_activas.min(i64::MAX as u64) as i64,
                version_politica.min(i64::MAX as u64) as i64,
            )
            .await?;
        // El latido alimenta el mapa de topologia: es lo que hace que un
        // endpoint pase de gris a verde en la consola sin recargar la pagina.
        self.bus.publicar(EventoPanel::Latido {
            cn: cn.to_string(),
            rss_kb: rss_kb.min(i64::MAX as u64) as i64,
            amenazas: amenazas_activas.min(i64::MAX as u64) as i64,
        });
        Ok(estado)
    }

    /// Registra un evento de seguridad y devuelve el identificador de incidente.
    pub async fn evento(
        &self,
        cn: &str,
        severidad: u64,
        categoria: &str,
        descripcion: &str,
        momento_unix: u64,
        detalles_json: &str,
    ) -> Resultado<uuid::Uuid> {
        let clase = clasificar_mitre(categoria);
        // Los atributos se normalizan ANTES de tocar la base de datos. Un
        // objeto anidado o desmesurado no llega a persistirse: ver
        // `crate::heuristicas::normalizar_detalles` para por que cada limite.
        let detalles = crate::heuristicas::normalizar_detalles(detalles_json)?;
        let alerta = NuevaAlerta {
            severidad: severidad_acotada(severidad),
            categoria,
            descripcion,
            tecnica: clase.map(|c| c.tecnica),
            tactica: clase.map(|c| c.tactica),
            ocurrido_en: momento_o_ahora(momento_unix),
            detalles,
        };
        let id = self.almacen.registrar_alerta(cn, &alerta).await?;

        // La auditoria se anota DESPUES de persistir y ANTES de publicar en el
        // panel: si se anotara antes de persistir, el SIEM del cliente podria
        // tener un evento que la base de datos del producto no tiene, y
        // reconciliarlos despues es imposible.
        if let Some(f) = &self.firehose {
            f.anotar(&crate::firehose::Auditoria {
                id: id.to_string(),
                tipo: "alerta",
                severidad: alerta.severidad,
                cn: Some(cn.to_string()),
                resumen: descripcion.chars().take(512).collect(),
                tecnica_mitre: clase.map(|c| c.tecnica.to_string()),
                momento: alerta.ocurrido_en.to_rfc3339(),
            });
        }
        // Una alerta critica que espera al siguiente sondeo del panel es una
        // alerta que llega tarde.
        self.bus.publicar(EventoPanel::AlertaNueva {
            id: id.to_string(),
            cn: cn.to_string(),
            severidad: alerta.severidad,
            categoria: categoria.to_string(),
            descripcion: descripcion.chars().take(512).collect(),
            tecnica_mitre: clase.map(|c| c.tecnica.to_string()),
        });
        Ok(id)
    }
}

impl ServicioFlota {
    /// Ingiere un bundle de inteligencia STIX 2.1 entregado por un agente.
    pub async fn ingerir_stix(
        &self,
        cn: &str,
        bundle_json: &str,
        momento_unix: u64,
    ) -> Resultado<IngestaStix> {
        // Un bundle desmesurado no debe poder convertirse en una carga de
        // escritura arbitraria: el transporte ya acota la trama, y aqui se acota
        // ademas lo que se acepta analizar.
        const MAX_BUNDLE: usize = 2 * 1024 * 1024;
        if bundle_json.len() > MAX_BUNDLE {
            return Err(crate::error::ErrorServidor::Config(format!(
                "el bundle ocupa {} bytes y el maximo es {MAX_BUNDLE}",
                bundle_json.len()
            )));
        }
        let ingesta = self
            .almacen
            .ingerir_stix(cn, bundle_json, Some(momento_o_ahora(momento_unix)))
            .await?;
        self.bus.publicar(EventoPanel::InteligenciaNueva {
            cn: cn.to_string(),
            objetos: ingesta.objetos,
        });
        Ok(ingesta)
    }

    /// Ingiere el subgrafo de linaje que rodea a una deteccion.
    pub async fn ingerir_grafo(
        &self,
        cn: &str,
        raiz: u64,
        momento_unix: u64,
        nodos: &[aegis_fleet::proto::NodoProceso],
    ) -> Resultado<(uuid::Uuid, u64)> {
        let convertidos: Vec<NodoGrafo> = nodos
            .iter()
            .map(|n| NodoGrafo {
                clave: n.clave as i64,
                pid: n.pid as i64,
                padre: n.padre as i64,
                creador: n.creador as i64,
                profundidad: n.profundidad.min(i32::MAX as u32) as i32,
                // La ruta y la linea de comandos las controla el endpoint: se
                // acotan para que un agente comprometido no pueda escribir un
                // texto de tamano arbitrario en la base de datos.
                imagen: recortar(&n.imagen, 4096),
                cmdline: recortar(&n.cmdline, 8192),
                clase: n.clase.min(i32::MAX as u32) as i32,
                iniciado_ns: n.iniciado_ns as i64,
                terminado_ns: if n.terminado_ns == 0 {
                    None
                } else {
                    Some(n.terminado_ns as i64)
                },
                taints: n.taints as i64,
                puntuacion: n.puntuacion.min(i32::MAX as u32) as i32,
            })
            .collect();

        self.almacen
            .ingerir_grafo(cn, raiz as i64, momento_o_ahora(momento_unix), &convertidos)
            .await
    }
}

/// Recorta un texto controlado por el par a un maximo de bytes, sin partir un
/// caracter UTF-8 por la mitad.
fn recortar(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut fin = max;
    while fin > 0 && !s.is_char_boundary(fin) {
        fin -= 1;
    }
    s[..fin].to_string()
}

/// Tamano maximo del estado que declara un agente, en bytes.
pub const MAX_ESTADO_AGENTE: usize = 16 * 1024;

/// Valida el estado que declara un agente antes de guardarlo (H-23).
///
/// Tiene que ser un objeto JSON y caber en [`MAX_ESTADO_AGENTE`]. Su forma la
/// decide el agente —motores, omitidos, cuentas del enlace—, pero su tamano no:
/// sin techo, un agente comprometido convertiria el latido en una escritura
/// arbitraria en el inventario de la flota.
pub fn normalizar_estado_agente(json: &str) -> Resultado<serde_json::Value> {
    let recorte = json.trim();
    if recorte.len() > MAX_ESTADO_AGENTE {
        return Err(crate::error::ErrorServidor::Config(format!(
            "el estado del agente ocupa {} bytes y el maximo es {MAX_ESTADO_AGENTE}",
            recorte.len()
        )));
    }
    let valor: serde_json::Value = serde_json::from_str(recorte).map_err(|e| {
        crate::error::ErrorServidor::Config(format!("el estado del agente no es JSON: {e}"))
    })?;
    if !valor.is_object() {
        return Err(crate::error::ErrorServidor::Config(
            "el estado del agente tiene que ser un objeto JSON".to_string(),
        ));
    }
    Ok(valor)
}

impl ServicioFlota {
    /// Guarda el estado de motores y del enlace que declara el agente (H-23).
    ///
    /// `cn` viene del certificado, no del mensaje. Reemplaza el anterior: es un
    /// estado, no un historico.
    pub async fn estado_agente(&self, cn: &str, json: &str) -> Resultado<()> {
        let valor = normalizar_estado_agente(json)?;
        self.almacen.registrar_estado_agente(cn, &valor).await
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn las_categorias_del_agente_se_traducen_a_tecnicas_de_att_ck() {
        assert_eq!(clasificar_mitre("ransomware").unwrap().tecnica, "T1486");
        assert_eq!(clasificar_mitre("INYECCION").unwrap().tecnica, "T1055");
        assert_eq!(
            clasificar_mitre("rootkit").unwrap().tactica,
            "Evasion de defensas"
        );
        // Una categoria desconocida no inventa una tecnica: se guarda sin mapeo
        // antes que con un mapeo falso que enganaria al analista.
        assert!(clasificar_mitre("categoria_que_no_existe").is_none());
    }

    /// Las categorias con las que el motor ITDR anuncia en el bus tienen que
    /// tener tecnica TAMBIEN al persistirse. Es la prueba que ata los dos
    /// caminos de la misma deteccion: si alguien renombra una categoria en
    /// `itdr::categoria_y_mitre` y no la anade aqui, esta prueba lo para antes
    /// de que la correlacion de la FASE 45 se quede a medias en produccion.
    #[test]
    fn toda_categoria_del_motor_de_identidad_tiene_tecnica_al_persistirse() {
        use aegis_itdr::ClaseAmenaza::{
            EscaladaPrivilegios, GoldenTicket, Kerberoasting, SilverTicket,
        };
        for clase in [
            Kerberoasting,
            GoldenTicket,
            SilverTicket,
            EscaladaPrivilegios,
        ] {
            let (categoria, mitre) = crate::itdr::categoria_y_mitre_publica(clase);
            let clasificada = clasificar_mitre(categoria).unwrap_or_else(|| {
                panic!("la categoria '{categoria}' del motor ITDR no se clasifica al persistirse")
            });
            assert_eq!(
                clasificada.tecnica, mitre,
                "la tecnica de '{categoria}' difiere entre el bus y la persistencia"
            );
        }
    }

    #[test]
    fn una_severidad_absurda_se_acota_al_rango_del_esquema() {
        assert_eq!(severidad_acotada(0), 0);
        assert_eq!(severidad_acotada(4), 4);
        // Un agente comprometido no puede escribir 9999 en una columna que el
        // esquema restringe a 0..4: se acota antes de tocar la base de datos.
        assert_eq!(severidad_acotada(9999), 4);
    }

    #[test]
    fn un_reloj_manipulado_no_puede_enterrar_una_alerta_en_el_pasado() {
        let ahora = Utc::now();
        // Una fecha de hace diez anos se descarta: entraria al final del
        // historico y el analista no la veria nunca.
        let vieja = momento_o_ahora(1_000_000_000);
        assert!((vieja - ahora).num_seconds().abs() < 5);
        // Una fecha en el futuro tampoco: quedaria siempre arriba del listado.
        let futura = momento_o_ahora((ahora.timestamp() + 86_400) as u64);
        assert!((futura - ahora).num_seconds().abs() < 5);
        // Una marca reciente y legitima SI se respeta.
        let buena_unix = (ahora.timestamp() - 60) as u64;
        assert_eq!(momento_o_ahora(buena_unix).timestamp(), buena_unix as i64);
    }

    #[test]
    fn el_estado_del_agente_se_valida_antes_de_guardarse() {
        let bueno = r#"{"agente":null,"enlace":{"enviados":1,"cuadra":true}}"#;
        assert!(normalizar_estado_agente(bueno).is_ok());
        assert!(normalizar_estado_agente("[1, 2]").is_err());
        assert!(normalizar_estado_agente("no es json").is_err());
        let enorme = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_ESTADO_AGENTE));
        assert!(normalizar_estado_agente(&enorme).is_err());
    }
}
