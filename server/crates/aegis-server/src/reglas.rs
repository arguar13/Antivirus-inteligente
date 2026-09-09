//! Motor de reglas globales.
//!
//! # Que resuelve
//!
//! Un operador que quiere "bloquear el puerto 445 en toda la flota" no puede
//! entrar endpoint por endpoint. Define una REGLA en el plano de control; el
//! motor la valida, la compila junto a las demas en un documento de politica
//! versionado, y ese documento se EMPUJA a cada agente conectado.
//!
//! # Por que se valida aqui y no en el agente
//!
//! Una regla mal formada que el agente ignore en silencio es lo peor de los dos
//! mundos: el operador cree que la flota esta protegida y no lo esta. La
//! validacion ocurre al DEFINIRLA, se rechaza en la cara del operador, y a la
//! flota solo baja politica que se sabe aplicable.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tipo de regla, que determina como la interpreta el agente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoRegla {
    /// Denegar trafico hacia o desde un puerto.
    BloquearPuerto,
    /// Impedir la ejecucion de un fichero por su SHA-256.
    BloquearHash,
    /// Impedir la ejecucion de una imagen por su ruta.
    BloquearProceso,
    /// Denegar conexiones a una red en notacion CIDR.
    BloquearRed,
    /// Aislar el endpoint cuando la puntuacion de comportamiento supere el umbral.
    AislarPorPuntuacion,
}

impl TipoRegla {
    /// Nombre estable con el que viaja en la politica y en la base de datos.
    pub fn como_str(self) -> &'static str {
        match self {
            TipoRegla::BloquearPuerto => "bloquear_puerto",
            TipoRegla::BloquearHash => "bloquear_hash",
            TipoRegla::BloquearProceso => "bloquear_proceso",
            TipoRegla::BloquearRed => "bloquear_red",
            TipoRegla::AislarPorPuntuacion => "aislar_por_puntuacion",
        }
    }

    /// Tipo a partir de su nombre estable.
    pub fn de_str(s: &str) -> Option<TipoRegla> {
        match s {
            "bloquear_puerto" => Some(TipoRegla::BloquearPuerto),
            "bloquear_hash" => Some(TipoRegla::BloquearHash),
            "bloquear_proceso" => Some(TipoRegla::BloquearProceso),
            "bloquear_red" => Some(TipoRegla::BloquearRed),
            "aislar_por_puntuacion" => Some(TipoRegla::AislarPorPuntuacion),
            _ => None,
        }
    }
}

/// Una regla global tal y como vive en el plano de control.
#[derive(Debug, Clone, Serialize)]
pub struct Regla {
    /// Identificador.
    pub id: Uuid,
    /// Nombre legible, unico.
    pub nombre: String,
    /// Que hace.
    pub tipo: String,
    /// Parametros ya validados.
    pub parametros: serde_json::Value,
    /// Si esta en vigor.
    pub activa: bool,
    /// Severidad 0..4.
    pub severidad: i16,
    /// Quien la creo.
    pub creada_por: String,
}

/// Error de validacion de una regla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRegla(pub String);

impl std::fmt::Display for ErrorRegla {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Valida los parametros de una regla segun su tipo.
///
/// Devuelve los parametros NORMALIZADOS: el motor guarda una forma canonica, no
/// lo que el operador escribiera. Asi dos reglas equivalentes escritas distinto
/// no acaban conviviendo como si fueran dos.
pub fn validar(
    tipo: TipoRegla,
    parametros: &serde_json::Value,
) -> Result<serde_json::Value, ErrorRegla> {
    let obj = parametros
        .as_object()
        .ok_or_else(|| ErrorRegla("los parametros deben ser un objeto JSON".into()))?;

    match tipo {
        TipoRegla::BloquearPuerto => {
            let puerto = obj
                .get("puerto")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ErrorRegla("falta 'puerto' (entero)".into()))?;
            // El puerto 0 no es una direccion valida y 65535 es el maximo: una
            // regla fuera de rango no la puede aplicar ningun endpoint.
            if puerto == 0 || puerto > 65_535 {
                return Err(ErrorRegla(format!(
                    "puerto {puerto} fuera del rango 1..65535"
                )));
            }
            let direccion = obj
                .get("direccion")
                .and_then(|v| v.as_str())
                .unwrap_or("ambas");
            if !matches!(direccion, "entrada" | "salida" | "ambas") {
                return Err(ErrorRegla(
                    "'direccion' debe ser entrada, salida o ambas".into(),
                ));
            }
            Ok(serde_json::json!({ "puerto": puerto, "direccion": direccion }))
        }

        TipoRegla::BloquearHash => {
            let hash = obj
                .get("sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorRegla("falta 'sha256'".into()))?;
            // Un hash de longitud incorrecta jamas casaria con nada: la regla
            // quedaria en la politica dando una falsa sensacion de proteccion.
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ErrorRegla(
                    "'sha256' debe ser 64 digitos hexadecimales".into(),
                ));
            }
            Ok(serde_json::json!({ "sha256": hash.to_ascii_lowercase() }))
        }

        TipoRegla::BloquearProceso => {
            let imagen = obj
                .get("imagen")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorRegla("falta 'imagen'".into()))?;
            if imagen.trim().is_empty() {
                return Err(ErrorRegla("'imagen' no puede estar vacia".into()));
            }
            // Una ruta relativa depende del directorio de trabajo del proceso:
            // la misma regla bloquearia cosas distintas en cada endpoint.
            if !imagen.starts_with('/') && !imagen.contains(":\\") {
                return Err(ErrorRegla("'imagen' debe ser una ruta absoluta".into()));
            }
            Ok(serde_json::json!({ "imagen": imagen }))
        }

        TipoRegla::BloquearRed => {
            let cidr = obj
                .get("cidr")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorRegla("falta 'cidr'".into()))?;
            validar_cidr(cidr)?;
            Ok(serde_json::json!({ "cidr": cidr }))
        }

        TipoRegla::AislarPorPuntuacion => {
            let umbral = obj
                .get("umbral")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ErrorRegla("falta 'umbral' (entero)".into()))?;
            // Un umbral de 0 aislaria la flota entera en cuanto se aplicara la
            // politica. Es el error de configuracion mas caro posible.
            if umbral == 0 || umbral > 1000 {
                return Err(ErrorRegla(format!(
                    "umbral {umbral} fuera del rango 1..1000; un umbral de 0 aislaria toda la flota"
                )));
            }
            Ok(serde_json::json!({ "umbral": umbral }))
        }
    }
}

/// Comprueba que una cadena es un CIDR IPv4 o IPv6 plausible.
fn validar_cidr(cidr: &str) -> Result<(), ErrorRegla> {
    let (ip, prefijo) = cidr
        .split_once('/')
        .ok_or_else(|| ErrorRegla("'cidr' debe tener la forma direccion/prefijo".into()))?;
    let prefijo: u32 = prefijo
        .parse()
        .map_err(|_| ErrorRegla("el prefijo del CIDR no es un numero".into()))?;

    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        if prefijo > 32 {
            return Err(ErrorRegla("el prefijo IPv4 no puede pasar de 32".into()));
        }
        return Ok(());
    }
    if ip.parse::<std::net::Ipv6Addr>().is_ok() {
        if prefijo > 128 {
            return Err(ErrorRegla("el prefijo IPv6 no puede pasar de 128".into()));
        }
        return Ok(());
    }
    Err(ErrorRegla(format!("'{ip}' no es una direccion IP valida")))
}

/// Compila las reglas activas en el documento de politica que se empuja.
///
/// El documento lleva su version dentro, no solo en el sobre: un agente que
/// guarde la politica en disco puede comprobar despues cual tiene aplicada sin
/// depender de haber apuntado el numero por separado.
pub fn compilar_politica(version: i64, reglas: &[Regla]) -> serde_json::Value {
    let activas: Vec<serde_json::Value> = reglas
        .iter()
        .filter(|r| r.activa)
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "nombre": r.nombre,
                "tipo": r.tipo,
                "parametros": r.parametros,
                "severidad": r.severidad,
            })
        })
        .collect();

    serde_json::json!({
        "version": version,
        "generada_en": chrono::Utc::now().to_rfc3339(),
        "reglas": activas,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_regla_de_puerto_valida_se_normaliza() {
        let p = validar(
            TipoRegla::BloquearPuerto,
            &serde_json::json!({"puerto": 445}),
        )
        .unwrap();
        assert_eq!(p["puerto"], 445);
        // La direccion se rellena con su valor por defecto en vez de quedar
        // ausente: la politica que baja a la flota no tiene huecos.
        assert_eq!(p["direccion"], "ambas");
    }

    #[test]
    fn un_puerto_fuera_de_rango_se_rechaza_al_definirlo() {
        for puerto in [0u64, 65_536, 999_999] {
            let r = validar(
                TipoRegla::BloquearPuerto,
                &serde_json::json!({ "puerto": puerto }),
            );
            assert!(r.is_err(), "el puerto {puerto} debe rechazarse");
        }
    }

    #[test]
    fn un_hash_mal_formado_no_llega_a_la_politica() {
        // Un hash corto jamas casaria con nada: quedaria en la politica dando
        // una falsa sensacion de proteccion.
        assert!(validar(
            TipoRegla::BloquearHash,
            &serde_json::json!({"sha256": "abcd"})
        )
        .is_err());
        assert!(validar(
            TipoRegla::BloquearHash,
            &serde_json::json!({"sha256": "z".repeat(64)})
        )
        .is_err());

        let bueno = "a".repeat(64);
        let p = validar(
            TipoRegla::BloquearHash,
            &serde_json::json!({ "sha256": bueno.to_uppercase() }),
        )
        .unwrap();
        assert_eq!(p["sha256"], bueno, "se normaliza a minusculas");
    }

    #[test]
    fn una_ruta_relativa_se_rechaza_porque_significa_algo_distinto_en_cada_endpoint() {
        assert!(validar(
            TipoRegla::BloquearProceso,
            &serde_json::json!({"imagen": "malware.exe"})
        )
        .is_err());
        assert!(validar(
            TipoRegla::BloquearProceso,
            &serde_json::json!({"imagen": "/usr/bin/nc"})
        )
        .is_ok());
        assert!(validar(
            TipoRegla::BloquearProceso,
            &serde_json::json!({"imagen": "C:\\Windows\\evil.exe"})
        )
        .is_ok());
    }

    #[test]
    fn un_cidr_invalido_se_rechaza() {
        assert!(validar(
            TipoRegla::BloquearRed,
            &serde_json::json!({"cidr": "10.0.0.0/8"})
        )
        .is_ok());
        assert!(validar(
            TipoRegla::BloquearRed,
            &serde_json::json!({"cidr": "::1/128"})
        )
        .is_ok());
        assert!(validar(
            TipoRegla::BloquearRed,
            &serde_json::json!({"cidr": "10.0.0.0/33"})
        )
        .is_err());
        assert!(validar(
            TipoRegla::BloquearRed,
            &serde_json::json!({"cidr": "no-una-ip/8"})
        )
        .is_err());
        assert!(validar(
            TipoRegla::BloquearRed,
            &serde_json::json!({"cidr": "10.0.0.0"})
        )
        .is_err());
    }

    #[test]
    fn un_umbral_de_cero_se_rechaza_porque_aislaria_la_flota_entera() {
        let r = validar(
            TipoRegla::AislarPorPuntuacion,
            &serde_json::json!({"umbral": 0}),
        );
        assert!(r.is_err());
        assert!(
            format!("{}", r.unwrap_err()).contains("aislaria"),
            "el error debe explicar la consecuencia, no solo el rango"
        );
    }

    #[test]
    fn la_politica_compilada_solo_lleva_las_reglas_activas() {
        let reglas = vec![
            Regla {
                id: Uuid::new_v4(),
                nombre: "smb".into(),
                tipo: "bloquear_puerto".into(),
                parametros: serde_json::json!({"puerto": 445}),
                activa: true,
                severidad: 3,
                creada_por: "operador".into(),
            },
            Regla {
                id: Uuid::new_v4(),
                nombre: "rdp-desactivada".into(),
                tipo: "bloquear_puerto".into(),
                parametros: serde_json::json!({"puerto": 3389}),
                activa: false,
                severidad: 2,
                creada_por: "operador".into(),
            },
        ];
        let pol = compilar_politica(4, &reglas);
        assert_eq!(pol["version"], 4);
        let arr = pol["reglas"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "la desactivada no baja a la flota");
        assert_eq!(arr[0]["parametros"]["puerto"], 445);
    }
}
