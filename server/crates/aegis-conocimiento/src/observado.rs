//! Lo observado: el punto donde el conocimiento toca este despliegue.
//!
//! # Observables y entidades
//!
//! El conocimiento habla de observables —un hash, una direccion, un dominio,
//! una cuenta—; la telemetria habla de entidades del modelo unico (FASE 79). El
//! puente es [`Observable`]: se saca de un objeto STIX (un SCO o el patron de un
//! indicador) y de lo que vio un agente, y los dos lados se encuentran por el
//! MISMO valor normalizado.
//!
//! Donde el modelo unico tiene clase —el contenido de un fichero por su
//! SHA-256, una cuenta de directorio—, el observable se nombra con su [`Eid`]:
//! `cont:…` es el mismo identificador que usan el almacen, el arbitro y los
//! casos. Donde no la tiene —una direccion o un dominio no son una entidad del
//! modelo, son un atributo de un flujo—, el observable se nombra por su valor,
//! y se dice ([`Observable::local`]).

use std::net::IpAddr;

use aegis_entidad::{entidad, Eid};
use aegis_share::stix::{Objeto, Tipo};

/// Un observable, normalizado.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Observable {
    /// El contenido de un fichero, por su SHA-256 en minusculas.
    Sha256(String),
    /// Una direccion.
    Ip(IpAddr),
    /// Un nombre de dominio, en minusculas y sin punto final.
    Dominio(String),
    /// Una URL, tal cual.
    Url(String),
    /// Una cuenta, por su identificador en el directorio.
    Cuenta(String),
}

impl Observable {
    /// Un SHA-256, si lo es.
    #[must_use]
    pub fn sha256(s: &str) -> Option<Observable> {
        let s = s.trim().to_ascii_lowercase();
        (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(Observable::Sha256(s))
    }

    /// Un dominio, normalizado.
    #[must_use]
    pub fn dominio(s: &str) -> Option<Observable> {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        (!s.is_empty() && s.len() <= 253 && s.contains('.')).then_some(Observable::Dominio(s))
    }

    /// La clave con que este despliegue lo nombra.
    ///
    /// Un [`Eid`] del modelo unico si su clase existe; si no, su valor con un
    /// prefijo que no puede chocar con un `Eid` ni con un identificador STIX.
    #[must_use]
    pub fn local(&self) -> Local {
        match self {
            Observable::Sha256(h) => Local::Entidad(entidad::contenido(h)),
            Observable::Cuenta(c) => Local::Entidad(entidad::cuenta(c)),
            Observable::Ip(ip) => Local::Valor(format!("valor:ip:{ip}")),
            Observable::Dominio(d) => Local::Valor(format!("valor:dominio:{d}")),
            Observable::Url(u) => Local::Valor(format!("valor:url:{u}")),
        }
    }

    /// Los observables que declara un objeto STIX: un SCO por su valor, un
    /// indicador por su patron.
    ///
    /// Un patron se traduce solo si es una igualdad simple (la misma regla que
    /// el puente del enjambre, `aegis_share::puente::traducir`): un patron
    /// compuesto traducido a medias uniria el conocimiento con algo que su autor
    /// no escribio.
    #[must_use]
    pub fn de_objeto(o: &Objeto) -> Vec<Observable> {
        let mut v = Vec::new();
        match &o.tipo {
            Tipo::Indicator => {
                if let Some((clase, valor)) = o.patron().and_then(aegis_share::puente::traducir) {
                    v.extend(Observable::de_clase(clase, &valor));
                }
            }
            Tipo::Otro(t) => match t.as_str() {
                "file" => {
                    if let Some(h) = o
                        .crudo
                        .get("hashes")
                        .and_then(|h| h.get("SHA-256").or_else(|| h.get("SHA256")))
                        .and_then(serde_json::Value::as_str)
                    {
                        v.extend(Observable::sha256(h));
                    }
                }
                "ipv4-addr" | "ipv6-addr" => {
                    if let Some(ip) = o.texto("value").and_then(|s| s.parse::<IpAddr>().ok()) {
                        v.push(Observable::Ip(ip));
                    }
                }
                "domain-name" => v.extend(o.texto("value").and_then(Observable::dominio)),
                "url" => v.extend(
                    o.texto("value")
                        .map(|u| Observable::Url(u.trim().to_string())),
                ),
                "user-account" => {
                    if let Some(c) = o.texto("user_id").or_else(|| o.texto("account_login")) {
                        v.push(Observable::Cuenta(c.trim().to_string()));
                    }
                }
                _ => {}
            },
            _ => {}
        }
        v
    }

    fn de_clase(clase: &str, valor: &str) -> Option<Observable> {
        match clase {
            "file-sha256" => Observable::sha256(valor),
            "ip" => valor.parse().ok().map(Observable::Ip),
            "domain" => Observable::dominio(valor),
            "url" => Some(Observable::Url(valor.to_string())),
            _ => None,
        }
    }
}

/// Como nombra este despliegue algo que observo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Local {
    /// Una entidad del modelo unico.
    Entidad(Eid),
    /// Un valor sin clase en el modelo unico.
    Valor(String),
}

impl Local {
    /// Texto estable.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Local::Entidad(e) => e.texto(),
            Local::Valor(v) => v.clone(),
        }
    }
}

/// Algo que un agente de este despliegue vio de verdad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avistamiento {
    /// Que se vio.
    pub observable: Observable,
    /// Donde.
    pub maquina: Eid,
    /// Cuando, en nanosegundos Unix.
    pub cuando_ns: u64,
}

impl Avistamiento {
    /// La fuente con que entra en la procedencia: la maquina que lo vio.
    ///
    /// Cada maquina es una raiz independiente: dos maquinas que ven el mismo
    /// hash son dos testigos, no uno.
    #[must_use]
    pub fn fuente(&self) -> String {
        format!("observado:{}", self.maquina.texto())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use serde_json::json;

    fn objeto(v: serde_json::Value) -> Objeto {
        let texto = json!({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": [v]});
        let p = aegis_share::Paquete::validar(&texto.to_string()).unwrap();
        p.objetos.into_values().next().unwrap()
    }

    #[test]
    fn un_sha256_es_el_mismo_eid_que_usa_el_resto_del_producto() {
        let h = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let o = Observable::sha256(h).unwrap();
        assert_eq!(o.local(), Local::Entidad(entidad::contenido(h)));
        assert!(Observable::sha256("no-es-un-hash").is_none());
    }

    #[test]
    fn los_observables_salen_del_sco_y_del_patron() {
        let f = objeto(json!({
            "type": "file", "spec_version": "2.1",
            "id": "file--5a27d487-c542-5f97-a131-a8866b477b46",
            "hashes": {"SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        }));
        assert_eq!(Observable::de_objeto(&f).len(), 1);
        let i = objeto(json!({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
            "pattern": "[domain-name:value = 'Malo.Example.']", "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z"
        }));
        assert_eq!(
            Observable::de_objeto(&i),
            [Observable::Dominio("malo.example".into())]
        );
        // Un patron compuesto no se traduce a medias.
        let c = objeto(json!({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--9e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
            "pattern": "[domain-name:value = 'a.example' AND ipv4-addr:value = '10.0.0.1']",
            "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"
        }));
        assert!(Observable::de_objeto(&c).is_empty());
    }
}
