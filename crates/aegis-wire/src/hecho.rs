//! Los **hechos**: lo que un disector afirma haber visto.
//!
//! # Por que un hecho y no un evento suelto por protocolo
//!
//! Si cada disector emitiera su propia estructura, correlacionar «esta consulta
//! DNS» con «esta conexion TLS» con «este fichero transferido por SMB» exigiria
//! una capa de union que alguien tendria que escribir y mantener. Eso es
//! exactamente lo que le pasa al stack de referencia: Zeek ve un flujo, ClamAV ve
//! un fichero, y son dos registros que no se conocen.
//!
//! Aqui todos los disectores emiten el MISMO tipo, atado al mismo flujo, con la
//! misma nocion de tiempo y de direccion. La union no hay que hacerla despues
//! porque nunca se rompio.
//!
//! # El tri-estado tambien vive aqui
//!
//! Un disector que no pudo analizar algo emite [`Hecho::NoAnalizable`] con su
//! motivo. No emitir nada seria indistinguible de «lo mire y estaba limpio», y
//! esa confusion es la que el producto entero existe para no cometer.

use std::net::IpAddr;

use crate::error::ErrorDiseccion;

/// Sentido de un dato dentro de un flujo.
///
/// «Cliente» es quien abrio la conexion. En un flujo capturado a medias eso no
/// se sabe, y se dice: ver [`Direccion::Indeterminada`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direccion {
    /// Del que abrio la conexion hacia el que la acepto.
    ClienteAServidor,
    /// Del que acepto hacia el que abrio.
    ServidorACliente,
    /// No se vio el inicio del flujo, asi que no se sabe quien abrio.
    Indeterminada,
}

impl Direccion {
    /// La contraria.
    #[must_use]
    pub fn opuesta(self) -> Direccion {
        match self {
            Direccion::ClienteAServidor => Direccion::ServidorACliente,
            Direccion::ServidorACliente => Direccion::ClienteAServidor,
            Direccion::Indeterminada => Direccion::Indeterminada,
        }
    }

    /// Nombre estable para el registro.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Direccion::ClienteAServidor => "c->s",
            Direccion::ServidorACliente => "s->c",
            Direccion::Indeterminada => "?",
        }
    }
}

/// Protocolo de transporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transporte {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP o ICMPv6.
    Icmp,
}

impl Transporte {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Transporte::Tcp => "tcp",
            Transporte::Udp => "udp",
            Transporte::Icmp => "icmp",
        }
    }
}

/// Protocolo de aplicacion reconocido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocoloApp {
    /// Sistema de nombres.
    Dns,
    /// HTTP sin cifrar.
    Http,
    /// TLS (de cualquier version).
    Tls,
    /// SSH.
    Ssh,
    /// SMB2 o SMB3.
    Smb,
    /// Kerberos.
    Kerberos,
    /// LDAP.
    Ldap,
    /// DHCP.
    Dhcp,
    /// NTP.
    Ntp,
    /// SMTP.
    Smtp,
    /// FTP (canal de control).
    Ftp,
    /// QUIC.
    Quic,
    /// Se vio trafico pero no se reconocio el protocolo.
    Desconocido,
}

impl ProtocoloApp {
    /// Nombre estable, que es el que aparece en el registro y en el SIEM del
    /// cliente. Cambiarlo rompe sus consultas guardadas: es un contrato.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            ProtocoloApp::Dns => "dns",
            ProtocoloApp::Http => "http",
            ProtocoloApp::Tls => "tls",
            ProtocoloApp::Ssh => "ssh",
            ProtocoloApp::Smb => "smb",
            ProtocoloApp::Kerberos => "kerberos",
            ProtocoloApp::Ldap => "ldap",
            ProtocoloApp::Dhcp => "dhcp",
            ProtocoloApp::Ntp => "ntp",
            ProtocoloApp::Smtp => "smtp",
            ProtocoloApp::Ftp => "ftp",
            ProtocoloApp::Quic => "quic",
            ProtocoloApp::Desconocido => "desconocido",
        }
    }
}

/// Los cinco campos que identifican un flujo.
///
/// Se guarda **normalizada**: el extremo menor primero, para que los dos
/// sentidos de la misma conversacion caigan en la misma clave. Sin eso, cada
/// conversacion ocuparia dos entradas y ningun disector veria los dos lados.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClaveFlujo {
    /// Extremo menor (por orden de IP y puerto).
    pub a: (IpAddr, u16),
    /// Extremo mayor.
    pub b: (IpAddr, u16),
    /// Transporte.
    pub transporte: Transporte,
}

impl ClaveFlujo {
    /// Construye la clave normalizada, y dice si hubo que dar la vuelta.
    ///
    /// El segundo valor es lo que permite recuperar la direccion original: si se
    /// dio la vuelta, el origen del paquete es `b`, no `a`.
    #[must_use]
    pub fn normalizada(
        origen: (IpAddr, u16),
        destino: (IpAddr, u16),
        transporte: Transporte,
    ) -> (ClaveFlujo, bool) {
        if (origen.0, origen.1) <= (destino.0, destino.1) {
            (
                ClaveFlujo {
                    a: origen,
                    b: destino,
                    transporte,
                },
                false,
            )
        } else {
            (
                ClaveFlujo {
                    a: destino,
                    b: origen,
                    transporte,
                },
                true,
            )
        }
    }
}

/// Un registro de recurso DNS, ya interpretado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaDns {
    /// Nombre consultado.
    pub nombre: String,
    /// Tipo, con su nombre estable ("A", "AAAA", "CNAME"...).
    pub tipo: String,
    /// Valor, ya formateado (una IP, un nombre, un texto).
    pub valor: String,
    /// Tiempo de vida declarado.
    pub ttl: u32,
}

/// Un hecho observado en el trafico.
///
/// Todos los disectores emiten esto. Es el contrato con el resto del producto.
///
/// No deriva `Eq` —y no se fuerza— porque [`Hecho::IndicioTunelDns`] lleva una
/// entropia en coma flotante. Una igualdad total sobre un `f64` seria una
/// mentira comoda: NaN no es igual ni a si mismo, y un hecho que se compara mal
/// acabaria deduplicando alertas que no son la misma.
#[derive(Debug, Clone, PartialEq)]
pub enum Hecho {
    /// Se identifico el protocolo de aplicacion del flujo.
    ProtocoloIdentificado(ProtocoloApp),

    /// Consulta DNS.
    ConsultaDns {
        /// Identificador de la transaccion.
        id: u16,
        /// Nombre consultado.
        nombre: String,
        /// Tipo consultado.
        tipo: String,
    },
    /// Respuesta DNS.
    RespuestaDns {
        /// Identificador de la transaccion.
        id: u16,
        /// Codigo de respuesta, con su nombre ("NOERROR", "NXDOMAIN"...).
        codigo: String,
        /// Registros devueltos.
        registros: Vec<RespuestaDns>,
    },
    /// Indicios de tunelizacion sobre DNS.
    ///
    /// No es un veredicto: es una observacion con sus numeros, para que el
    /// arbitro decida. Un disector no decide si algo es malicioso.
    IndicioTunelDns {
        /// Nombre implicado.
        nombre: String,
        /// Entropia de Shannon de las etiquetas, en bits por caracter.
        entropia: f64,
        /// Longitud de la etiqueta mas larga.
        etiqueta_mas_larga: usize,
    },

    /// Peticion HTTP.
    PeticionHttp {
        /// Metodo.
        metodo: String,
        /// Ruta solicitada.
        uri: String,
        /// Version.
        version: String,
        /// Cabecera `Host`.
        host: String,
        /// Cabecera `User-Agent`.
        agente: String,
        /// Cabeceras completas, en orden de aparicion.
        cabeceras: Vec<(String, String)>,
    },
    /// Respuesta HTTP.
    RespuestaHttp {
        /// Codigo de estado.
        estado: u16,
        /// Tipo de contenido declarado.
        tipo_contenido: String,
        /// Longitud declarada, si la hubo.
        longitud: Option<u64>,
        /// Cabeceras completas.
        cabeceras: Vec<(String, String)>,
    },

    /// Saludo TLS del cliente.
    SaludoClienteTls {
        /// Version anunciada.
        version: String,
        /// Nombre del servidor solicitado.
        sni: String,
        /// Protocolos ofrecidos por ALPN.
        alpn: Vec<String>,
        /// Huella JA3.
        ja3: String,
        /// Huella JA4.
        ja4: String,
    },
    /// Saludo TLS del servidor.
    SaludoServidorTls {
        /// Version negociada.
        version: String,
        /// Suite elegida.
        suite: u16,
        /// Huella JA3S.
        ja3s: String,
    },
    /// Certificado presentado.
    CertificadoTls {
        /// Sujeto, tal y como venia.
        sujeto: String,
        /// Emisor.
        emisor: String,
        /// SHA-256 del certificado en formato DER.
        huella: String,
        /// Si es autofirmado (sujeto igual a emisor).
        autofirmado: bool,
    },

    /// Intercambio de version de SSH.
    VersionSsh {
        /// Cadena de version anunciada.
        version: String,
        /// Implementacion, extraida de la cadena.
        implementacion: String,
    },

    /// Operacion SMB.
    OperacionSmb {
        /// Orden ("NEGOTIATE", "SESSION_SETUP", "CREATE"...).
        orden: String,
        /// Recurso o fichero implicado.
        recurso: String,
    },

    /// Mensaje Kerberos.
    MensajeKerberos {
        /// Tipo ("AS-REQ", "TGS-REQ"...).
        tipo: String,
        /// Principal del cliente.
        cliente: String,
        /// Servicio solicitado.
        servicio: String,
        /// Tipo de cifrado, con su nombre.
        cifrado: String,
    },

    /// Operacion LDAP.
    OperacionLdap {
        /// Operacion ("bind", "search"...).
        operacion: String,
        /// Nombre distinguido implicado.
        dn: String,
    },

    /// Concesion DHCP.
    DhcpVisto {
        /// Tipo de mensaje.
        tipo: String,
        /// Direccion fisica del cliente.
        mac: String,
        /// Nombre de equipo anunciado.
        nombre: String,
    },

    /// Sincronizacion NTP.
    NtpVisto {
        /// Modo, con su nombre.
        modo: String,
        /// Estrato declarado.
        estrato: u8,
    },

    /// Orden SMTP.
    OrdenSmtp {
        /// Verbo.
        verbo: String,
        /// Argumento.
        argumento: String,
    },

    /// Orden FTP.
    OrdenFtp {
        /// Verbo.
        verbo: String,
        /// Argumento.
        argumento: String,
    },

    /// Saludo inicial de QUIC.
    InicioQuic {
        /// Version.
        version: u32,
        /// Nombre del servidor, si se pudo ver.
        sni: String,
    },

    /// Un fichero transferido, ya reconstruido.
    FicheroTransferido {
        /// Nombre, si se supo.
        nombre: String,
        /// Protocolo por el que viajo.
        via: ProtocoloApp,
        /// Tamano en bytes.
        tamano: usize,
        /// SHA-256 del contenido.
        sha256: String,
    },

    /// El reensamblado vio algo que hay que contar.
    AnomaliaDeFlujo {
        /// Codigo estable.
        codigo: &'static str,
        /// Detalle legible.
        detalle: String,
    },

    /// **No se pudo analizar**, y se dice por que.
    ///
    /// Emitir esto en vez de callar es lo que impide confundir «no pude mirar»
    /// con «lo mire y estaba limpio».
    NoAnalizable {
        /// Que protocolo se intentaba.
        protocolo: ProtocoloApp,
        /// Por que no se pudo.
        motivo: String,
    },
}

impl Hecho {
    /// Construye un [`Hecho::NoAnalizable`] desde un error de diseccion.
    #[must_use]
    pub fn no_analizable(protocolo: ProtocoloApp, e: &ErrorDiseccion) -> Hecho {
        Hecho::NoAnalizable {
            protocolo,
            motivo: e.to_string(),
        }
    }

    /// Codigo estable del hecho, para agrupar y contar.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            Hecho::ProtocoloIdentificado(_) => "protocolo",
            Hecho::ConsultaDns { .. } => "dns-consulta",
            Hecho::RespuestaDns { .. } => "dns-respuesta",
            Hecho::IndicioTunelDns { .. } => "dns-tunel",
            Hecho::PeticionHttp { .. } => "http-peticion",
            Hecho::RespuestaHttp { .. } => "http-respuesta",
            Hecho::SaludoClienteTls { .. } => "tls-cliente",
            Hecho::SaludoServidorTls { .. } => "tls-servidor",
            Hecho::CertificadoTls { .. } => "tls-certificado",
            Hecho::VersionSsh { .. } => "ssh-version",
            Hecho::OperacionSmb { .. } => "smb-operacion",
            Hecho::MensajeKerberos { .. } => "kerberos-mensaje",
            Hecho::OperacionLdap { .. } => "ldap-operacion",
            Hecho::DhcpVisto { .. } => "dhcp",
            Hecho::NtpVisto { .. } => "ntp",
            Hecho::OrdenSmtp { .. } => "smtp-orden",
            Hecho::OrdenFtp { .. } => "ftp-orden",
            Hecho::InicioQuic { .. } => "quic-inicio",
            Hecho::FicheroTransferido { .. } => "fichero",
            Hecho::AnomaliaDeFlujo { .. } => "anomalia",
            Hecho::NoAnalizable { .. } => "no-analizable",
        }
    }
}

/// Un hecho con su contexto: de que flujo, en que sentido y cuando.
///
/// Es lo que sale del motor. Que el contexto viaje PEGADO al hecho —y no en una
/// tabla aparte que haya que unir— es la propiedad que el stack de referencia no
/// tiene.
#[derive(Debug, Clone, PartialEq)]
pub struct HechoConContexto {
    /// A que flujo pertenece.
    pub flujo: ClaveFlujo,
    /// En que sentido se observo.
    pub direccion: Direccion,
    /// Cuando, en microsegundos Unix (lo pone quien alimenta el motor).
    pub momento_us: u64,
    /// El hecho.
    pub hecho: Hecho,
}

#[cfg(test)]
mod pruebas {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    /// LA PROPIEDAD QUE HACE UTIL LA CLAVE: los dos sentidos de la misma
    /// conversacion caen en la MISMA entrada. Sin esto, cada conversacion
    /// ocuparia dos y ningun disector veria los dos lados.
    #[test]
    fn los_dos_sentidos_de_una_conversacion_dan_la_misma_clave() {
        let (ida, invertida_ida) =
            ClaveFlujo::normalizada((ip(1), 5000), (ip(2), 443), Transporte::Tcp);
        let (vuelta, invertida_vuelta) =
            ClaveFlujo::normalizada((ip(2), 443), (ip(1), 5000), Transporte::Tcp);
        assert_eq!(ida, vuelta);
        assert_ne!(
            invertida_ida, invertida_vuelta,
            "y la marca de inversion permite recuperar quien hablaba"
        );
    }

    #[test]
    fn flujos_distintos_dan_claves_distintas() {
        let (a, _) = ClaveFlujo::normalizada((ip(1), 5000), (ip(2), 443), Transporte::Tcp);
        let (b, _) = ClaveFlujo::normalizada((ip(1), 5001), (ip(2), 443), Transporte::Tcp);
        let (c, _) = ClaveFlujo::normalizada((ip(1), 5000), (ip(2), 443), Transporte::Udp);
        assert_ne!(a, b, "otro puerto es otro flujo");
        assert_ne!(a, c, "otro transporte es otro flujo");
    }

    #[test]
    fn la_direccion_opuesta_es_involutiva_y_la_indeterminada_se_conserva() {
        assert_eq!(
            Direccion::ClienteAServidor.opuesta().opuesta(),
            Direccion::ClienteAServidor
        );
        assert_eq!(
            Direccion::Indeterminada.opuesta(),
            Direccion::Indeterminada,
            "no saber quien abrio no se puede invertir en saberlo"
        );
    }

    /// Los nombres son un CONTRATO con el SIEM del cliente: cambiarlos rompe sus
    /// consultas guardadas. Esta prueba existe para que cambiarlos duela.
    #[test]
    fn los_nombres_de_protocolo_son_estables_y_no_se_solapan() {
        let todos = [
            ProtocoloApp::Dns,
            ProtocoloApp::Http,
            ProtocoloApp::Tls,
            ProtocoloApp::Ssh,
            ProtocoloApp::Smb,
            ProtocoloApp::Kerberos,
            ProtocoloApp::Ldap,
            ProtocoloApp::Dhcp,
            ProtocoloApp::Ntp,
            ProtocoloApp::Smtp,
            ProtocoloApp::Ftp,
            ProtocoloApp::Quic,
            ProtocoloApp::Desconocido,
        ];
        let mut vistos = Vec::new();
        for p in todos {
            assert!(!p.nombre().is_empty());
            assert!(!vistos.contains(&p.nombre()), "repetido: {}", p.nombre());
            vistos.push(p.nombre());
        }
        assert_eq!(ProtocoloApp::Dns.nombre(), "dns");
        assert_eq!(ProtocoloApp::Kerberos.nombre(), "kerberos");
    }

    #[test]
    fn un_error_de_diseccion_se_convierte_en_un_hecho_que_dice_por_que() {
        let e = ErrorDiseccion::Truncado {
            campo: "cabecera",
            esperados: 12,
            habia: 3,
        };
        let h = Hecho::no_analizable(ProtocoloApp::Dns, &e);
        match h {
            Hecho::NoAnalizable { protocolo, motivo } => {
                assert_eq!(protocolo, ProtocoloApp::Dns);
                assert!(
                    motivo.contains("cabecera"),
                    "el motivo tiene que decir que: {motivo}"
                );
            }
            otro => panic!("se esperaba NoAnalizable: {otro:?}"),
        }
    }
}
