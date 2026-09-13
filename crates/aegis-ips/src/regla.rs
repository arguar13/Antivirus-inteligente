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

    // ---------------------------------------------------------------------
    // Criterios sobre los «sticky buffers» que usa el contenido publico
    // ---------------------------------------------------------------------
    //
    // Las reglas de red modernas —Emerging Threats y companeras— ya casi no
    // buscan bytes en la carga cruda: buscan en el campo semantico concreto
    // (`http.uri`, `tls.sni`, `http.user_agent`). Eso es exactamente lo que
    // produce aegis-wire, asi que soportar estos criterios NO es ampliar por
    // ampliar: es lo que hace que el corpus publico se pueda compilar de verdad
    // en vez de rechazarse regla por regla.
    /// Metodo HTTP exacto, sin distinguir mayusculas.
    MetodoHttp(String),
    /// Subcadena dentro de la URI de una peticion HTTP.
    ContenidoUriHttp {
        /// Lo que se busca.
        aguja: String,
        /// Si se distingue mayusculas.
        distingue_mayusculas: bool,
    },
    /// Cabecera `Host` exacta.
    HostHttp(String),
    /// Sufijo de la cabecera `Host`, con corte en el punto.
    SufijoHostHttp(String),
    /// Subcadena dentro del `User-Agent`.
    AgenteHttp(String),
    /// Subcadena dentro del valor de una cabecera HTTP concreta.
    CabeceraHttp {
        /// Nombre de la cabecera, sin distinguir mayusculas.
        nombre: String,
        /// Lo que tiene que contener su valor.
        contiene: String,
    },
    /// Codigo de estado exacto de una respuesta HTTP.
    EstadoHttp(u16),
    /// Subcadena dentro del sujeto de un certificado TLS.
    SujetoCertificado(String),
    /// Huella SHA-256 exacta de un certificado TLS.
    HuellaCertificado(String),
    /// Huella JA3S exacta del saludo del servidor.
    Ja3s(String),
    /// Subcadena dentro de la cadena de version de SSH.
    VersionSsh(String),
    /// Subcadena dentro del recurso de una operacion SMB.
    RecursoSmb(String),
    /// Servicio Kerberos exacto solicitado.
    ServicioKerberos(String),
    /// Nombre distinguido LDAP que contiene una subcadena.
    DnLdap(String),
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

            // --- Sticky buffers HTTP ---
            (Criterio::MetodoHttp(m), Hecho::PeticionHttp { metodo, .. }) => {
                metodo.eq_ignore_ascii_case(m)
            }
            (
                Criterio::ContenidoUriHttp {
                    aguja,
                    distingue_mayusculas,
                },
                Hecho::PeticionHttp { uri, .. },
            ) => contiene(uri, aguja, *distingue_mayusculas),
            (Criterio::HostHttp(h), Hecho::PeticionHttp { host, .. }) => {
                host.eq_ignore_ascii_case(h)
            }
            (Criterio::SufijoHostHttp(s), Hecho::PeticionHttp { host, .. }) => {
                // El puerto no forma parte del nombre: `evil.com:8080` sigue
                // siendo `evil.com`, y no recortarlo dejaria pasar la regla con
                // solo anadir un puerto explicito.
                es_subdominio(host.split(':').next().unwrap_or(host), s)
            }
            (Criterio::AgenteHttp(a), Hecho::PeticionHttp { agente, .. }) => {
                contiene(agente, a, false)
            }
            (
                Criterio::CabeceraHttp {
                    nombre,
                    contiene: c,
                },
                Hecho::PeticionHttp { cabeceras, .. },
            ) => cabeceras
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case(nombre) && contiene(v, c, false)),
            (
                Criterio::CabeceraHttp {
                    nombre,
                    contiene: c,
                },
                Hecho::RespuestaHttp { cabeceras, .. },
            ) => cabeceras
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case(nombre) && contiene(v, c, false)),
            (Criterio::EstadoHttp(e), Hecho::RespuestaHttp { estado, .. }) => estado == e,

            // --- Sticky buffers TLS ---
            (Criterio::SujetoCertificado(s), Hecho::CertificadoTls { sujeto, .. }) => {
                contiene(sujeto, s, false)
            }
            (Criterio::HuellaCertificado(h), Hecho::CertificadoTls { huella, .. }) => {
                huella.eq_ignore_ascii_case(h)
            }
            (Criterio::Ja3s(h), Hecho::SaludoServidorTls { ja3s, .. }) => {
                ja3s.eq_ignore_ascii_case(h)
            }

            // --- Otros protocolos ---
            (Criterio::VersionSsh(v), Hecho::VersionSsh { version, .. }) => {
                contiene(version, v, false)
            }
            (Criterio::RecursoSmb(r), Hecho::OperacionSmb { recurso, .. }) => {
                contiene(recurso, r, false)
            }
            (Criterio::ServicioKerberos(s), Hecho::MensajeKerberos { servicio, .. }) => {
                servicio.eq_ignore_ascii_case(s)
            }
            (Criterio::DnLdap(d), Hecho::OperacionLdap { dn, .. }) => contiene(dn, d, false),

            _ => false,
        }
    }
}

/// Si `heno` contiene `aguja`, distinguiendo mayusculas o no.
///
/// La version que no distingue no usa `to_lowercase` sobre el heno entero por
/// cada comparacion: con miles de reglas y un hecho por paquete, eso es trabajo
/// repetido en el camino caliente. Se compara byte a byte con la ventana del
/// tamano de la aguja, que ademas es correcto para el ASCII que traen estos
/// campos.
#[must_use]
fn contiene(heno: &str, aguja: &str, distingue_mayusculas: bool) -> bool {
    if aguja.is_empty() {
        return false;
    }
    if distingue_mayusculas {
        return heno.contains(aguja);
    }
    let h = heno.as_bytes();
    let a = aguja.as_bytes();
    if a.len() > h.len() {
        return false;
    }
    h.windows(a.len()).any(|v| v.eq_ignore_ascii_case(a))
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

    fn peticion(metodo: &str, uri: &str, host: &str, agente: &str) -> Hecho {
        Hecho::PeticionHttp {
            metodo: metodo.to_string(),
            uri: uri.to_string(),
            version: "HTTP/1.1".to_string(),
            host: host.to_string(),
            agente: agente.to_string(),
            cabeceras: vec![
                ("Host".to_string(), host.to_string()),
                ("User-Agent".to_string(), agente.to_string()),
                ("X-Custom".to_string(), "valor-secreto".to_string()),
            ],
        }
    }

    /// LOS STICKY BUFFERS son como se escriben hoy las reglas publicas. Si no
    /// casaran, el corpus de Emerging Threats se rechazaria regla por regla.
    #[test]
    fn los_criterios_http_casan_sobre_su_campo_y_solo_sobre_el_suyo() {
        let h = peticion("POST", "/admin/login.php", "victima.com", "curl/7.1");

        assert!(regla(Criterio::MetodoHttp("post".into()), Confianza::Alta).casa(&h));
        assert!(!regla(Criterio::MetodoHttp("GET".into()), Confianza::Alta).casa(&h));

        assert!(regla(
            Criterio::ContenidoUriHttp {
                aguja: "/admin/".into(),
                distingue_mayusculas: false
            },
            Confianza::Alta
        )
        .casa(&h));
        assert!(regla(Criterio::HostHttp("VICTIMA.COM".into()), Confianza::Alta).casa(&h));
        assert!(regla(Criterio::AgenteHttp("curl".into()), Confianza::Media).casa(&h));
        assert!(regla(
            Criterio::CabeceraHttp {
                nombre: "x-custom".into(),
                contiene: "secreto".into()
            },
            Confianza::Media
        )
        .casa(&h));

        // Y NO casa por el campo equivocado: un criterio de URI no puede casar
        // porque la cadena aparezca en el User-Agent.
        let confuso = peticion("GET", "/", "x.com", "/admin/ en el agente");
        assert!(!regla(
            Criterio::ContenidoUriHttp {
                aguja: "/admin/".into(),
                distingue_mayusculas: false
            },
            Confianza::Alta
        )
        .casa(&confuso));
    }

    /// El modificador de mayusculas de `content` se respeta en los dos sentidos:
    /// una regla que pide distincion NO puede casar sin ella.
    #[test]
    fn la_distincion_de_mayusculas_se_respeta_en_los_dos_sentidos() {
        let h = peticion("GET", "/Admin/Panel", "x.com", "ua");
        let sensible = Criterio::ContenidoUriHttp {
            aguja: "/admin/".into(),
            distingue_mayusculas: true,
        };
        let insensible = Criterio::ContenidoUriHttp {
            aguja: "/admin/".into(),
            distingue_mayusculas: false,
        };
        assert!(!regla(sensible, Confianza::Alta).casa(&h));
        assert!(regla(insensible, Confianza::Alta).casa(&h));
    }

    /// Un `Host` con puerto explicito sigue siendo el mismo dominio. Si no se
    /// recortara, anadir `:8080` bastaria para saltarse la regla.
    #[test]
    fn el_puerto_en_el_host_no_permite_saltarse_la_regla() {
        let con_puerto = peticion("GET", "/", "a.evil.com:8080", "ua");
        assert!(
            regla(Criterio::SufijoHostHttp("evil.com".into()), Confianza::Alta).casa(&con_puerto)
        );
    }

    /// Los criterios de TLS, SSH, SMB, Kerberos y LDAP casan sobre su hecho.
    #[test]
    fn los_criterios_de_los_demas_protocolos_casan_sobre_su_hecho() {
        let cert = Hecho::CertificadoTls {
            sujeto: "CN=malo.example.com, O=Nadie".to_string(),
            emisor: "CN=CA".to_string(),
            huella: "AABBCC".to_string(),
            autofirmado: false,
        };
        assert!(regla(
            Criterio::SujetoCertificado("malo.example".into()),
            Confianza::Alta
        )
        .casa(&cert));
        assert!(regla(
            Criterio::HuellaCertificado("aabbcc".into()),
            Confianza::Alta
        )
        .casa(&cert));

        let ssh = Hecho::VersionSsh {
            version: "SSH-2.0-libssh_0.9.6".to_string(),
            implementacion: "libssh".to_string(),
        };
        assert!(regla(Criterio::VersionSsh("libssh".into()), Confianza::Media).casa(&ssh));

        let smb = Hecho::OperacionSmb {
            orden: "CREATE".to_string(),
            recurso: "\\\\srv\\C$\\Windows\\Temp\\a.exe".to_string(),
        };
        assert!(regla(Criterio::RecursoSmb("C$".into()), Confianza::Media).casa(&smb));

        let krb = Hecho::MensajeKerberos {
            tipo: "TGS-REQ".to_string(),
            cliente: "admin@DOM".to_string(),
            servicio: "cifs/srv.dom".to_string(),
            cifrado: "RC4-HMAC".to_string(),
        };
        assert!(regla(
            Criterio::ServicioKerberos("CIFS/SRV.DOM".into()),
            Confianza::Alta
        )
        .casa(&krb));

        let ldap = Hecho::OperacionLdap {
            operacion: "bind".to_string(),
            dn: "CN=admin,DC=dom,DC=local".to_string(),
        };
        assert!(regla(Criterio::DnLdap("CN=admin".into()), Confianza::Media).casa(&ldap));
    }

    /// Una aguja vacia no puede casar con todo: seria una regla que corta la red
    /// entera por un fallo de configuracion del feed.
    #[test]
    fn una_aguja_vacia_no_casa_con_nada() {
        let h = peticion("GET", "/x", "a.com", "ua");
        assert!(!regla(
            Criterio::ContenidoUriHttp {
                aguja: String::new(),
                distingue_mayusculas: false
            },
            Confianza::Alta
        )
        .casa(&h));
        assert!(!regla(Criterio::AgenteHttp(String::new()), Confianza::Alta).casa(&h));
    }

    /// Un sufijo vacio no puede casar con todo: seria una regla que corta la red
    /// entera por un fallo de configuracion.
    #[test]
    fn un_sufijo_vacio_no_casa_con_nada() {
        let r = regla(Criterio::SufijoDns(String::new()), Confianza::Alta);
        assert!(!r.casa(&consulta("cualquier.cosa.com")));
    }
}
