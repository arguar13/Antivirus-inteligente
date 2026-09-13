//! Las reglas: que se busca en los hechos y con cuanta confianza.
//!
//! # Por que las reglas miran HECHOS y no bytes
//!
//! Un IPS clasico busca cadenas dentro del paquete. Eso funciona y tiene dos
//! problemas conocidos: se evade cambiando la codificacion o partiendo la cadena
//! entre dos segmentos, y no puede decir nada del trafico cifrado.
//!
//! Aqui las reglas miran lo que produce [`aegis_wire`]: un nombre DNS ya
//! descomprimido, una huella JA3 ya calculada, el SHA-256 de un fichero ya
//! reensamblado. Eso cierra las dos evasiones de golpe —el disector ya
//! reensamblo y ya normalizo— y permite escribir reglas sobre sesiones cifradas
//! sin descifrar nada, porque la huella y el SNI viajan en claro.
//!
//! # Lo que NO hace una regla
//!
//! Decidir si corta. Una regla dice «esto coincide, con esta confianza»; quien
//! decide es [`crate::decisor`], que ademas mira el modo, los protegidos y el
//! limitador. Separarlo es lo que permite probar la decision sin inventarse
//! reglas y probar las reglas sin montar el motor entero.

use aegis_wire::hecho::{Hecho, ProtocoloApp};

use crate::confianza::Confianza;

/// Que busca una regla dentro de un hecho.
#[derive(Debug, Clone, PartialEq)]
pub enum Criterio {
    /// Un nombre DNS exacto, sin distinguir mayusculas.
    NombreDns(String),
    /// Un sufijo de nombre DNS: `evil.com` casa con `a.b.evil.com`.
    ///
    /// El corte se comprueba en el punto, no por `ends_with` a secas: si no,
    /// `noevil.com` casaria con `evil.com` y se cortaria a un tercero.
    SufijoDns(String),
    /// Tunelizacion por DNS, por encima de un umbral de entropia.
    TunelDns {
        /// Bits por caracter a partir de los cuales la regla casa.
        entropia_minima: f64,
    },
    /// Una huella JA3 exacta.
    Ja3(String),
    /// Una huella JA4 exacta.
    Ja4(String),
    /// Un nombre de servidor TLS exacto.
    Sni(String),
    /// Un sufijo de nombre de servidor TLS.
    SufijoSni(String),
    /// El SHA-256 de un fichero transferido, en minusculas.
    HashFichero(String),
    /// Un ejecutable transferido por un protocolo dado.
    EjecutableTransferido(ProtocoloApp),
    /// Un codigo de anomalia de flujo de [`aegis_wire`].
    Anomalia(String),
    /// Un certificado TLS autofirmado.
    CertificadoAutofirmado,
}

/// Una regla de deteccion de red.
#[derive(Debug, Clone, PartialEq)]
pub struct Regla {
    /// Identificador estable, para poder auditar por que se corto algo.
    pub id: u64,
    /// Nombre legible.
    pub nombre: String,
    /// Cuanto se fia el producto de esta regla.
    pub confianza: Confianza,
    /// Que busca.
    pub criterio: Criterio,
}

impl Regla {
    /// Si el hecho hace casar la regla.
    #[must_use]
    pub fn casa(&self, hecho: &Hecho) -> bool {
        match (&self.criterio, hecho) {
            (Criterio::NombreDns(n), Hecho::ConsultaDns { nombre, .. }) => {
                nombre.eq_ignore_ascii_case(n)
            }
            (Criterio::NombreDns(n), Hecho::RespuestaDns { registros, .. }) => {
                registros.iter().any(|r| r.nombre.eq_ignore_ascii_case(n))
            }
            (Criterio::SufijoDns(s), Hecho::ConsultaDns { nombre, .. }) => es_subdominio(nombre, s),
            (Criterio::SufijoDns(s), Hecho::RespuestaDns { registros, .. }) => {
                registros.iter().any(|r| es_subdominio(&r.nombre, s))
            }
            (Criterio::TunelDns { entropia_minima }, Hecho::IndicioTunelDns { entropia, .. }) => {
                entropia >= entropia_minima
            }
            (Criterio::Ja3(h), Hecho::SaludoClienteTls { ja3, .. }) => ja3.eq_ignore_ascii_case(h),
            (Criterio::Ja4(h), Hecho::SaludoClienteTls { ja4, .. }) => ja4.eq_ignore_ascii_case(h),
            (Criterio::Sni(s), Hecho::SaludoClienteTls { sni, .. }) => sni.eq_ignore_ascii_case(s),
            (Criterio::SufijoSni(s), Hecho::SaludoClienteTls { sni, .. }) => es_subdominio(sni, s),
            (Criterio::HashFichero(h), Hecho::FicheroTransferido { sha256, .. }) => {
                sha256.eq_ignore_ascii_case(h)
            }
            (Criterio::EjecutableTransferido(p), Hecho::FicheroTransferido { via, nombre, .. }) => {
                via == p && parece_ejecutable(nombre)
            }
            (Criterio::Anomalia(c), Hecho::AnomaliaDeFlujo { codigo, .. }) => c == codigo,
            (Criterio::CertificadoAutofirmado, Hecho::CertificadoTls { autofirmado, .. }) => {
                *autofirmado
            }
            _ => false,
        }
    }
}

/// Si `nombre` es el dominio `sufijo` o un subdominio suyo.
///
/// El corte se comprueba EN EL PUNTO. Con un `ends_with` pelado, una regla para
/// `evil.com` cortaria tambien `noevil.com`, que es de otro: un falso positivo
/// que ademas es trivial de provocar a proposito para que cortemos a un tercero.
#[must_use]
fn es_subdominio(nombre: &str, sufijo: &str) -> bool {
    let n = nombre.trim_end_matches('.').to_ascii_lowercase();
    let s = sufijo.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return false;
    }
    if n == s {
        return true;
    }
    n.len() > s.len() && n.ends_with(&s) && n.as_bytes()[n.len() - s.len() - 1] == b'.'
}

/// Si el nombre declarado tiene extension de ejecutable.
///
/// Es una PISTA sobre lo que dijo el emisor, no una verdad sobre el contenido:
/// el tipo real lo determina [`aegis_wire::ficheros`] por la magia de los bytes.
/// Aqui sirve para escribir reglas sobre lo que se anuncia.
#[must_use]
fn parece_ejecutable(nombre: &str) -> bool {
    const EXTENSIONES: [&str; 10] = [
        "exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "js", "jar", "msi",
    ];
    let Some((_, ext)) = nombre.rsplit_once('.') else {
        return false;
    };
    EXTENSIONES.contains(&ext.trim().to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_wire::hecho::RespuestaDns;

    fn regla(criterio: Criterio, confianza: Confianza) -> Regla {
        Regla {
            id: 1,
            nombre: "prueba".to_string(),
            confianza,
            criterio,
        }
    }

    fn consulta(nombre: &str) -> Hecho {
        Hecho::ConsultaDns {
            id: 1,
            nombre: nombre.to_string(),
            tipo: "A".to_string(),
        }
    }

    #[test]
    fn un_nombre_dns_exacto_casa_sin_distinguir_mayusculas() {
        let r = regla(
            Criterio::NombreDns("Malo.Example.Com".to_string()),
            Confianza::Alta,
        );
        assert!(r.casa(&consulta("malo.example.com")));
        assert!(!r.casa(&consulta("otro.example.com")));
    }

    /// EL FALSO POSITIVO QUE CORTA A UN TERCERO: con `ends_with` pelado, una
    /// regla para `evil.com` cortaria tambien `noevil.com`, que no tiene nada
    /// que ver y que es trivial de registrar a proposito.
    #[test]
    fn un_sufijo_dns_corta_en_el_punto_y_no_por_los_pelos() {
        let r = regla(Criterio::SufijoDns("evil.com".to_string()), Confianza::Alta);
        assert!(r.casa(&consulta("evil.com")), "el dominio exacto casa");
        assert!(r.casa(&consulta("a.b.evil.com")), "un subdominio casa");
        assert!(
            !r.casa(&consulta("noevil.com")),
            "pero NO un dominio distinto que acaba igual"
        );
        assert!(!r.casa(&consulta("evil.com.es")));
    }

    /// El punto final de un nombre absoluto no puede cambiar el resultado.
    #[test]
    fn el_punto_final_de_un_nombre_absoluto_no_cambia_nada() {
        let r = regla(Criterio::SufijoDns("evil.com".to_string()), Confianza::Alta);
        assert!(r.casa(&consulta("a.evil.com.")));
    }

    #[test]
    fn el_umbral_de_entropia_se_respeta_en_los_dos_lados() {
        let r = regla(
            Criterio::TunelDns {
                entropia_minima: 4.0,
            },
            Confianza::Media,
        );
        let alto = Hecho::IndicioTunelDns {
            nombre: "x.tunel.com".to_string(),
            entropia: 4.5,
            etiqueta_mas_larga: 40,
        };
        let bajo = Hecho::IndicioTunelDns {
            nombre: "y.tunel.com".to_string(),
            entropia: 3.2,
            etiqueta_mas_larga: 12,
        };
        assert!(r.casa(&alto));
        assert!(!r.casa(&bajo));
    }

    #[test]
    fn una_huella_ja3_casa_y_no_se_confunde_con_ja4() {
        let hecho = Hecho::SaludoClienteTls {
            version: "1.3".to_string(),
            sni: "cdn.ejemplo.com".to_string(),
            alpn: vec!["h2".to_string()],
            ja3: "aaaa".to_string(),
            ja4: "bbbb".to_string(),
        };
        assert!(regla(Criterio::Ja3("aaaa".to_string()), Confianza::Alta).casa(&hecho));
        assert!(!regla(Criterio::Ja3("bbbb".to_string()), Confianza::Alta).casa(&hecho));
        assert!(regla(Criterio::Ja4("bbbb".to_string()), Confianza::Alta).casa(&hecho));
    }

    #[test]
    fn el_hash_de_un_fichero_casa_sin_distinguir_mayusculas() {
        let hecho = Hecho::FicheroTransferido {
            nombre: "a.bin".to_string(),
            via: ProtocoloApp::Http,
            tamano: 10,
            sha256: "ABCDEF".to_string(),
        };
        assert!(regla(Criterio::HashFichero("abcdef".to_string()), Confianza::Alta).casa(&hecho));
    }

    /// Una regla NO puede casar con un hecho de otra clase. Si lo hiciera, una
    /// regla de DNS cortaria una sesion TLS que no ha hecho nada.
    #[test]
    fn una_regla_no_casa_con_un_hecho_de_otra_clase() {
        let r = regla(Criterio::NombreDns("malo.com".to_string()), Confianza::Alta);
        let tls = Hecho::SaludoClienteTls {
            version: "1.3".to_string(),
            sni: "malo.com".to_string(),
            alpn: vec![],
            ja3: "x".to_string(),
            ja4: "y".to_string(),
        };
        assert!(!r.casa(&tls), "el SNI no es una consulta DNS");
    }

    #[test]
    fn una_respuesta_dns_casa_por_cualquiera_de_sus_registros() {
        let hecho = Hecho::RespuestaDns {
            id: 1,
            codigo: "NOERROR".to_string(),
            registros: vec![
                RespuestaDns {
                    nombre: "bueno.com".to_string(),
                    tipo: "A".to_string(),
                    valor: "1.2.3.4".to_string(),
                    ttl: 300,
                },
                RespuestaDns {
                    nombre: "a.evil.com".to_string(),
                    tipo: "CNAME".to_string(),
                    valor: "evil.com".to_string(),
                    ttl: 60,
                },
            ],
        };
        assert!(regla(Criterio::SufijoDns("evil.com".to_string()), Confianza::Alta).casa(&hecho));
    }

    #[test]
    fn un_certificado_autofirmado_casa_solo_si_lo_es() {
        let cert = |auto: bool| Hecho::CertificadoTls {
            sujeto: "CN=x".to_string(),
            emisor: "CN=x".to_string(),
            huella: "aa".to_string(),
            autofirmado: auto,
        };
        let r = regla(Criterio::CertificadoAutofirmado, Confianza::Baja);
        assert!(r.casa(&cert(true)));
        assert!(!r.casa(&cert(false)));
    }

    #[test]
    fn un_ejecutable_se_reconoce_por_su_extension_declarada() {
        let f = |n: &str| Hecho::FicheroTransferido {
            nombre: n.to_string(),
            via: ProtocoloApp::Http,
            tamano: 1,
            sha256: "x".to_string(),
        };
        let r = regla(
            Criterio::EjecutableTransferido(ProtocoloApp::Http),
            Confianza::Media,
        );
        assert!(r.casa(&f("carga.EXE")));
        assert!(r.casa(&f("script.ps1")));
        assert!(!r.casa(&f("informe.pdf")));
        assert!(!r.casa(&f("sin_extension")));
    }

    /// Un sufijo vacio no puede casar con todo: seria una regla que corta la red
    /// entera por un fallo de configuracion.
    #[test]
    fn un_sufijo_vacio_no_casa_con_nada() {
        let r = regla(Criterio::SufijoDns(String::new()), Confianza::Alta);
        assert!(!r.casa(&consulta("cualquier.cosa.com")));
    }
}
