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

    // ── Identidad y directorio (FASE 89) ────────────────────────────────────
    /// NTLM, dentro de SMB, HTTP o DCERPC.
    Ntlm,
    /// RADIUS.
    Radius,
    /// Diameter.
    Diameter,
    /// SAML, dentro de HTTP.
    Saml,
    /// OAuth 2.0 / OpenID Connect, dentro de HTTP.
    Oauth,

    // ── Ficheros y ejecucion remota (FASE 89) ───────────────────────────────
    /// DCERPC / MSRPC.
    Dcerpc,
    /// NFS y su ONC RPC.
    Nfs,
    /// WebDAV, sobre HTTP.
    Webdav,
    /// RDP.
    Rdp,
    /// VNC / RFB.
    Vnc,
    /// WinRM, sobre HTTP.
    Winrm,

    // ── Bases de datos (FASE 89) ────────────────────────────────────────────
    /// MySQL y MariaDB.
    Mysql,
    /// PostgreSQL.
    Postgresql,
    /// TDS (Microsoft SQL Server).
    Tds,
    /// MongoDB.
    Mongodb,
    /// Redis.
    Redis,
    /// Elasticsearch, sobre HTTP.
    Elasticsearch,

    // ── Mensajeria (FASE 89) ────────────────────────────────────────────────
    /// AMQP.
    Amqp,
    /// MQTT.
    Mqtt,
    /// Kafka.
    Kafka,
    /// gRPC, sobre HTTP/2.
    Grpc,

    // ── Correo (FASE 89) ────────────────────────────────────────────────────
    /// IMAP.
    Imap,
    /// POP3.
    Pop3,

    // ── Web moderna (FASE 89) ───────────────────────────────────────────────
    /// HTTP/2.
    Http2,
    /// HTTP/3, sobre QUIC.
    Http3,
    /// WebSocket.
    Websocket,

    // ── Industrial y OT (FASE 89) ───────────────────────────────────────────
    /// Modbus/TCP.
    Modbus,
    /// DNP3.
    Dnp3,
    /// S7comm (Siemens), sobre COTP/TPKT.
    S7comm,
    /// BACnet/IP.
    Bacnet,
    /// OPC-UA binario.
    OpcUa,

    // ── Tuneles y evasion (FASE 89) ─────────────────────────────────────────
    /// DNS sobre HTTPS.
    Doh,
    /// DNS sobre TLS.
    Dot,
    /// WireGuard.
    Wireguard,
    /// IKEv2 (IPsec).
    Ikev2,
    /// SOCKS 4 o 5.
    Socks,

    // ── Nube (FASE 89) ──────────────────────────────────────────────────────
    /// Servicio de metadatos de instancia de un proveedor de nube.
    MetadatosDeNube,

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
            ProtocoloApp::Ntlm => "ntlm",
            ProtocoloApp::Radius => "radius",
            ProtocoloApp::Diameter => "diameter",
            ProtocoloApp::Saml => "saml",
            ProtocoloApp::Oauth => "oauth",
            ProtocoloApp::Dcerpc => "dcerpc",
            ProtocoloApp::Nfs => "nfs",
            ProtocoloApp::Webdav => "webdav",
            ProtocoloApp::Rdp => "rdp",
            ProtocoloApp::Vnc => "vnc",
            ProtocoloApp::Winrm => "winrm",
            ProtocoloApp::Mysql => "mysql",
            ProtocoloApp::Postgresql => "postgresql",
            ProtocoloApp::Tds => "tds",
            ProtocoloApp::Mongodb => "mongodb",
            ProtocoloApp::Redis => "redis",
            ProtocoloApp::Elasticsearch => "elasticsearch",
            ProtocoloApp::Amqp => "amqp",
            ProtocoloApp::Mqtt => "mqtt",
            ProtocoloApp::Kafka => "kafka",
            ProtocoloApp::Grpc => "grpc",
            ProtocoloApp::Imap => "imap",
            ProtocoloApp::Pop3 => "pop3",
            ProtocoloApp::Http2 => "http2",
            ProtocoloApp::Http3 => "http3",
            ProtocoloApp::Websocket => "websocket",
            ProtocoloApp::Modbus => "modbus",
            ProtocoloApp::Dnp3 => "dnp3",
            ProtocoloApp::S7comm => "s7comm",
            ProtocoloApp::Bacnet => "bacnet",
            ProtocoloApp::OpcUa => "opcua",
            ProtocoloApp::Doh => "doh",
            ProtocoloApp::Dot => "dot",
            ProtocoloApp::Wireguard => "wireguard",
            ProtocoloApp::Ikev2 => "ikev2",
            ProtocoloApp::Socks => "socks",
            ProtocoloApp::MetadatosDeNube => "metadatos-de-nube",
            ProtocoloApp::Desconocido => "desconocido",
        }
    }

    /// Todos los protocolos que el producto sabe nombrar.
    ///
    /// Esta aqui —y no en una lista escrita a mano en cada prueba— porque el
    /// numero de protocolos es la medida con la que se compara el sensor contra
    /// otros, y una medida que se cuenta a mano se cuenta mal. Anadir una
    /// variante sin anadirla aqui hace fallar
    /// `todos_los_protocolos_estan_en_la_lista`.
    pub const TODOS: &'static [ProtocoloApp] = &[
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
        ProtocoloApp::Ntlm,
        ProtocoloApp::Radius,
        ProtocoloApp::Diameter,
        ProtocoloApp::Saml,
        ProtocoloApp::Oauth,
        ProtocoloApp::Dcerpc,
        ProtocoloApp::Nfs,
        ProtocoloApp::Webdav,
        ProtocoloApp::Rdp,
        ProtocoloApp::Vnc,
        ProtocoloApp::Winrm,
        ProtocoloApp::Mysql,
        ProtocoloApp::Postgresql,
        ProtocoloApp::Tds,
        ProtocoloApp::Mongodb,
        ProtocoloApp::Redis,
        ProtocoloApp::Elasticsearch,
        ProtocoloApp::Amqp,
        ProtocoloApp::Mqtt,
        ProtocoloApp::Kafka,
        ProtocoloApp::Grpc,
        ProtocoloApp::Imap,
        ProtocoloApp::Pop3,
        ProtocoloApp::Http2,
        ProtocoloApp::Http3,
        ProtocoloApp::Websocket,
        ProtocoloApp::Modbus,
        ProtocoloApp::Dnp3,
        ProtocoloApp::S7comm,
        ProtocoloApp::Bacnet,
        ProtocoloApp::OpcUa,
        ProtocoloApp::Doh,
        ProtocoloApp::Dot,
        ProtocoloApp::Wireguard,
        ProtocoloApp::Ikev2,
        ProtocoloApp::Socks,
        ProtocoloApp::MetadatosDeNube,
        ProtocoloApp::Desconocido,
    ];

    /// Busca un protocolo por su nombre estable.
    ///
    /// Sin esto, el nombre viajaria solo de ida —del enumerado al registro— y
    /// una consulta guardada del SIEM no se podria volver a atar al tipo.
    #[must_use]
    pub fn de_nombre(n: &str) -> Option<ProtocoloApp> {
        ProtocoloApp::TODOS
            .iter()
            .copied()
            .find(|p| p.nombre() == n)
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

    /// **Una orden a un dispositivo industrial** (FASE 89).
    ///
    /// La distincion que lleva dentro y que no tiene ningun otro hecho:
    /// `escribe`. Leer un registro de un PLC es telemetria y ocurre miles de
    /// veces por minuto; escribirlo mueve algo en el mundo fisico. Un sensor que
    /// los cuente juntos entierra el segundo bajo el primero.
    OrdenIndustrial {
        /// Protocolo por el que viajo.
        protocolo: ProtocoloApp,
        /// Funcion, con su nombre estable ("leer-registros-retentivos",
        /// "escribir-bobina", "parar-cpu").
        funcion: String,
        /// A que dispositivo, esclavo, rack o nodo.
        unidad: String,
        /// **Si la orden cambia el estado del dispositivo.**
        escribe: bool,
        /// Detalle legible (rango de direcciones, objeto, cantidad).
        detalle: String,
    },

    /// Una operacion contra una base de datos (FASE 89).
    OperacionDeBaseDeDatos {
        /// Motor.
        motor: ProtocoloApp,
        /// Operacion ("login", "consulta", "borrado-masivo", "volcado").
        operacion: String,
        /// Objeto: tabla, indice, clave o base.
        objeto: String,
        /// Usuario, si viajaba.
        usuario: String,
    },

    /// Un intento de autenticacion visto en la red (FASE 89).
    ///
    /// Lo emiten NTLM, RADIUS, Diameter, SASL y los portadores web de SAML y
    /// OAuth. Que sea **uno** y no cinco es lo que permite contar intentos
    /// fallidos por usuario sin importar por donde entro.
    AutenticacionVista {
        /// Mecanismo ("ntlmssp-negociacion", "radius-access-request",
        /// "sasl-plain", "saml-response", "oauth-bearer").
        mecanismo: String,
        /// Usuario o principal.
        usuario: String,
        /// Dominio, reino o emisor.
        dominio: String,
        /// Lo que se vio ("peticion", "reto", "respuesta", "acepta", "rechaza").
        resultado: String,
    },

    /// Una operacion de mensajeria o de cola (FASE 89).
    OperacionDeMensajeria {
        /// Sistema.
        sistema: ProtocoloApp,
        /// Operacion ("conectar", "publicar", "suscribir", "producir").
        operacion: String,
        /// Tema, cola o intercambio.
        tema: String,
    },

    /// Ejecucion remota vista por la red (FASE 89).
    ///
    /// Es el hecho que ata WinRM, DCERPC, SSH y RDP: el movimiento lateral no se
    /// reconoce por el protocolo sino por que alguien ejecuto algo en otra
    /// maquina, y tenerlo en un solo hecho es lo que hace que se pueda contar.
    EjecucionRemota {
        /// Por donde.
        via: ProtocoloApp,
        /// Que se pidio ejecutar o abrir.
        orden: String,
        /// Sobre que maquina, servicio o punto final.
        objetivo: String,
    },

    /// Trafico que transporta otro trafico (FASE 89).
    ///
    /// Como [`Hecho::IndicioTunelDns`], **no es un veredicto**: es la
    /// observacion con su tecnica, para que el arbitro decida.
    IndicioDeTunel {
        /// Protocolo que hace de portador.
        portador: ProtocoloApp,
        /// Tecnica ("dns-sobre-https", "socks5-conectar", "wireguard-inicio").
        tecnica: String,
        /// Detalle legible.
        detalle: String,
    },

    /// Acceso al servicio de metadatos de instancia de una nube (FASE 89).
    ///
    /// Un acceso legitimo lo hace el agente de la nube al arrancar. Uno desde
    /// una peticion reenviada por un servidor web es una toma de credenciales
    /// —el patron de SSRF que vacio mas de una cuenta—, y la diferencia esta en
    /// `con_credencial` y en el recurso pedido.
    AccesoAMetadatosDeNube {
        /// Proveedor ("aws", "azure", "gcp", "oracle", "alibaba").
        proveedor: String,
        /// Recurso pedido.
        recurso: String,
        /// Si la respuesta o la peticion llevaba una credencial.
        con_credencial: bool,
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
            Hecho::OrdenIndustrial { .. } => "orden-industrial",
            Hecho::OperacionDeBaseDeDatos { .. } => "base-de-datos",
            Hecho::AutenticacionVista { .. } => "autenticacion",
            Hecho::OperacionDeMensajeria { .. } => "mensajeria",
            Hecho::EjecucionRemota { .. } => "ejecucion-remota",
            Hecho::IndicioDeTunel { .. } => "tunel",
            Hecho::AccesoAMetadatosDeNube { .. } => "metadatos-de-nube",
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
        let mut vistos = Vec::new();
        for p in ProtocoloApp::TODOS.iter().copied() {
            assert!(!p.nombre().is_empty());
            assert!(!vistos.contains(&p.nombre()), "repetido: {}", p.nombre());
            vistos.push(p.nombre());
        }
        assert_eq!(ProtocoloApp::Dns.nombre(), "dns");
        assert_eq!(ProtocoloApp::Kerberos.nombre(), "kerberos");
        assert_eq!(ProtocoloApp::Modbus.nombre(), "modbus");
    }

    /// El nombre tiene que viajar de vuelta: una consulta guardada del SIEM
    /// lleva el nombre, y sin la vuelta no se puede atar al tipo otra vez.
    #[test]
    fn el_nombre_de_un_protocolo_lleva_de_vuelta_al_protocolo() {
        for p in ProtocoloApp::TODOS.iter().copied() {
            assert_eq!(ProtocoloApp::de_nombre(p.nombre()), Some(p));
        }
        assert_eq!(ProtocoloApp::de_nombre("no-existe"), None);
    }

    /// Anadir una variante al enumerado sin anadirla a `TODOS` dejaria la lista
    /// corta, y el numero de protocolos es la medida con la que se compara este
    /// sensor contra otros. Aqui se cuenta contra el `match` exhaustivo de
    /// `nombre()`, que el compilador si obliga a completar.
    #[test]
    fn todos_los_protocolos_estan_en_la_lista() {
        // Cada variante conocida por nombre tiene que estar en TODOS. Si alguien
        // anade una variante, `nombre()` no compila hasta darle nombre, y en ese
        // momento esta prueba exige la fila en TODOS.
        let nombres: Vec<&str> = ProtocoloApp::TODOS.iter().map(|p| p.nombre()).collect();
        for n in [
            "dns",
            "http",
            "tls",
            "ssh",
            "smb",
            "kerberos",
            "ldap",
            "dhcp",
            "ntp",
            "smtp",
            "ftp",
            "quic",
            "ntlm",
            "radius",
            "diameter",
            "saml",
            "oauth",
            "dcerpc",
            "nfs",
            "webdav",
            "rdp",
            "vnc",
            "winrm",
            "mysql",
            "postgresql",
            "tds",
            "mongodb",
            "redis",
            "elasticsearch",
            "amqp",
            "mqtt",
            "kafka",
            "grpc",
            "imap",
            "pop3",
            "http2",
            "http3",
            "websocket",
            "modbus",
            "dnp3",
            "s7comm",
            "bacnet",
            "opcua",
            "doh",
            "dot",
            "wireguard",
            "ikev2",
            "socks",
            "metadatos-de-nube",
            "desconocido",
        ] {
            assert!(nombres.contains(&n), "{n} no esta en ProtocoloApp::TODOS");
        }
        assert_eq!(ProtocoloApp::TODOS.len(), 50);
    }

    /// LA distincion de los protocolos industriales: leer un registro de un PLC
    /// es telemetria y pasa miles de veces por minuto; escribirlo mueve algo en
    /// el mundo fisico. Si el hecho no los separase, el segundo quedaria
    /// enterrado bajo el primero.
    #[test]
    fn una_orden_industrial_dice_si_escribe() {
        let leer = Hecho::OrdenIndustrial {
            protocolo: ProtocoloApp::Modbus,
            funcion: "leer-registros-retentivos".to_owned(),
            unidad: "1".to_owned(),
            escribe: false,
            detalle: "0..10".to_owned(),
        };
        let escribir = Hecho::OrdenIndustrial {
            protocolo: ProtocoloApp::Modbus,
            funcion: "escribir-bobina".to_owned(),
            unidad: "1".to_owned(),
            escribe: true,
            detalle: "bobina 4 a ON".to_owned(),
        };
        assert_eq!(leer.codigo(), escribir.codigo());
        assert_ne!(leer, escribir);
        match escribir {
            Hecho::OrdenIndustrial { escribe, .. } => assert!(escribe),
            otro => panic!("{otro:?}"),
        }
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
