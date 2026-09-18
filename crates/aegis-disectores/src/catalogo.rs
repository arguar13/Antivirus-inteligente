//! El catalogo: los disectores que existen, el perfil con el que se montan, y
//! la comparacion contra el sensor de referencia.
//!
//! # Por que hay perfiles y no un solo registro
//!
//! Porque una pasarela industrial no necesita el disector de Kafka y un servidor
//! de aplicaciones no necesita el de Modbus. Cargar los cuarenta y nueve en todas
//! partes cuesta memoria y, peor, cuesta **tiempo por paquete**: cada disector
//! que no va a reconocer nada se prueba igual. Los perfiles son lo que hace que
//! el crate separado sirva de algo.
//!
//! # La cifra que este crate existe para dar
//!
//! [`Registro::frase`] dice cuantos mensajes se entendieron y cuantos no, con su
//! motivo. Es lo que ni Wireshark ni Zeek dan, y es lo que distingue «este flujo
//! no llevaba nada» de «este flujo llevaba algo que no supimos leer».

use crate::bases;
use crate::correo;
use crate::disector::{Disector, Registro};
use crate::identidad;
use crate::industrial;
use crate::mensajeria;
use crate::nube;
use crate::remoto;
use crate::tuneles;
use crate::web;

/// La familia a la que pertenece un disector.
///
/// Es lo que define un perfil: no se eligen disectores de uno en uno —eso seria
/// una lista que nadie mantiene al dia— sino familias enteras.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Familia {
    /// Quien dice ser quien: NTLM, RADIUS, Diameter, SAML, OAuth.
    Identidad,
    /// Ficheros y ejecucion remota: DCERPC, NFS, WebDAV, RDP, VNC, WinRM.
    EjecucionRemota,
    /// Bases de datos: MySQL, PostgreSQL, TDS, MongoDB, Redis, Elasticsearch.
    BasesDeDatos,
    /// Colas y temas: AMQP, MQTT, Kafka, gRPC.
    Mensajeria,
    /// Correo: IMAP, POP3 y sus adjuntos.
    Correo,
    /// Web moderna: HTTP/2, HTTP/3, WebSocket.
    Web,
    /// Industrial y tecnologia de operacion: Modbus, DNP3, S7comm, BACnet, OPC-UA.
    Industrial,
    /// Tuneles y evasion: DoH, DoT, WireGuard, IKEv2, SOCKS y los tuneles.
    Tuneles,
    /// Servicios de metadatos de instancia de las nubes.
    Nube,
}

impl Familia {
    /// Todas.
    pub const TODAS: &'static [Familia] = &[
        Familia::Identidad,
        Familia::EjecucionRemota,
        Familia::BasesDeDatos,
        Familia::Mensajeria,
        Familia::Correo,
        Familia::Web,
        Familia::Industrial,
        Familia::Tuneles,
        Familia::Nube,
    ];

    /// Nombre estable, que es el que aparece en la configuracion del cliente.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Familia::Identidad => "identidad",
            Familia::EjecucionRemota => "ejecucion-remota",
            Familia::BasesDeDatos => "bases-de-datos",
            Familia::Mensajeria => "mensajeria",
            Familia::Correo => "correo",
            Familia::Web => "web",
            Familia::Industrial => "industrial",
            Familia::Tuneles => "tuneles",
            Familia::Nube => "nube",
        }
    }

    /// Los disectores de esta familia, recien construidos.
    #[must_use]
    pub fn disectores(self) -> Vec<Box<dyn Disector + Send + Sync>> {
        match self {
            Familia::Identidad => vec![
                Box::new(identidad::Ntlm),
                Box::new(identidad::Radius),
                Box::new(identidad::Diameter),
                Box::new(identidad::Saml),
                Box::new(identidad::Oauth),
            ],
            Familia::EjecucionRemota => vec![
                Box::new(remoto::Dcerpc),
                Box::new(remoto::Nfs),
                Box::new(remoto::Webdav),
                Box::new(remoto::Rdp),
                Box::new(remoto::Vnc),
                Box::new(remoto::Winrm),
            ],
            Familia::BasesDeDatos => vec![
                Box::new(bases::Mysql),
                Box::new(bases::Postgresql),
                Box::new(bases::Tds),
                Box::new(bases::Mongodb),
                Box::new(bases::Redis),
                Box::new(bases::Elasticsearch),
            ],
            Familia::Mensajeria => vec![
                Box::new(mensajeria::Amqp),
                Box::new(mensajeria::Mqtt),
                Box::new(mensajeria::Kafka),
                Box::new(mensajeria::Grpc),
            ],
            Familia::Correo => vec![Box::new(correo::Imap), Box::new(correo::Pop3)],
            Familia::Web => vec![
                Box::new(web::Http2),
                Box::new(web::Http3),
                Box::new(web::Websocket),
            ],
            Familia::Industrial => vec![
                Box::new(industrial::Modbus),
                Box::new(industrial::Dnp3),
                Box::new(industrial::S7comm),
                Box::new(industrial::Bacnet),
                Box::new(industrial::OpcUa),
            ],
            Familia::Tuneles => vec![
                Box::new(tuneles::Doh),
                Box::new(tuneles::Dot),
                Box::new(tuneles::Wireguard),
                Box::new(tuneles::Ikev2),
                Box::new(tuneles::Socks),
                Box::new(tuneles::Tunel),
            ],
            Familia::Nube => vec![Box::new(nube::MetadatosDeNube)],
        }
    }
}

/// Un perfil: que familias se cargan en una maquina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perfil {
    /// Todo. Es el que se usa en un sensor de red dedicado.
    Completo,
    /// Puesto de trabajo: lo que ve un portatil.
    PuestoDeTrabajo,
    /// Servidor de aplicaciones: bases de datos, colas y web.
    Servidor,
    /// Pasarela industrial: lo de planta y lo que llega desde la oficina.
    PasarelaIndustrial,
}

impl Perfil {
    /// Las familias de este perfil.
    #[must_use]
    pub fn familias(self) -> Vec<Familia> {
        match self {
            Perfil::Completo => Familia::TODAS.to_vec(),
            // Un portatil ve identidad, correo, web y tuneles. No ve Modbus ni
            // Kafka, y cargar esos disectores solo anadiria tiempo por paquete.
            Perfil::PuestoDeTrabajo => vec![
                Familia::Identidad,
                Familia::EjecucionRemota,
                Familia::Correo,
                Familia::Web,
                Familia::Tuneles,
                Familia::Nube,
            ],
            Perfil::Servidor => vec![
                Familia::Identidad,
                Familia::EjecucionRemota,
                Familia::BasesDeDatos,
                Familia::Mensajeria,
                Familia::Web,
                Familia::Tuneles,
                Familia::Nube,
            ],
            // La pasarela es el sitio donde un ataque pasa de la red de oficina a
            // la de planta: hace falta ver las dos, y por eso lleva identidad y
            // ejecucion remota ademas de lo industrial.
            Perfil::PasarelaIndustrial => vec![
                Familia::Industrial,
                Familia::Identidad,
                Familia::EjecucionRemota,
                Familia::Tuneles,
            ],
        }
    }

    /// Un registro con los disectores de este perfil.
    #[must_use]
    pub fn registro(self) -> Registro {
        let mut r = Registro::vacio();
        for f in self.familias() {
            for d in f.disectores() {
                r.anadir(d);
            }
        }
        r
    }
}

/// Un registro con TODOS los disectores de este crate.
#[must_use]
pub fn registro_completo() -> Registro {
    Perfil::Completo.registro()
}

/// Cuantos disectores anade esta fase.
///
/// Esta escrito y se comprueba contra el registro construido: un disector nuevo
/// que no toque este numero hace fallar la prueba, y asi la cifra que aparece en
/// un informe no se puede quedar desfasada.
pub const DISECTORES_DE_ESTA_FASE: usize = 38;

// ════════════════════════════════════════════════════════════════════════════
// La comparacion contra el sensor de referencia
// ════════════════════════════════════════════════════════════════════════════

/// Los analizadores de protocolo de aplicacion que Zeek trae de serie.
///
/// # Que es esta lista y que no es
///
/// **No es una medida hecha aqui.** Es la relacion de analizadores que la
/// documentacion de Zeek 7 publica, transcrita para poder comparar el alcance de
/// los dos sensores en el mismo sitio. Decirlo importa: una comparacion que
/// presente un dato de segunda mano como si se hubiera medido es exactamente el
/// tipo de cifra que este crate existe para no producir.
///
/// Lo que **si** se mide aqui es lo de la derecha: los protocolos de este
/// producto salen de construir el registro y preguntarle, no de una lista.
///
/// Tres cosas que su documentacion lista y que **no** estan aqui, para que la
/// comparacion no se infle sola contando de mas a nadie: `conn`, que es el
/// registro de conexiones y no un analizador de protocolo; `krb`, que es otro
/// nombre del mismo analizador que `kerberos`; y `ssl_tunnel`, que es una
/// variante del de TLS. Contarlas subiria su numero sin que analizara nada mas,
/// y una comparacion se hace igual de deshonesta inflando al otro que
/// inflandose uno.
///
/// Dos cosas que su documentacion lista y que **no** estan aqui, para que la
/// comparacion no se infle sola: `conn`, que es el registro de conexiones y no un
/// analizador de protocolo, y `krb`, que es otro nombre del mismo analizador que
/// `kerberos`. Contarlas subiria su numero sin que analizara nada mas.
pub static ANALIZADORES_DE_ZEEK: &[&str] = &[
    "dns",
    "http",
    "ssl",
    "x509",
    "ssh",
    "smb",
    "dce_rpc",
    "ntlm",
    "kerberos",
    "ldap",
    "dhcp",
    "ntp",
    "smtp",
    "ftp",
    "quic",
    "imap",
    "pop3",
    "irc",
    "rdp",
    "radius",
    "sip",
    "snmp",
    "syslog",
    "socks",
    "mysql",
    "postgresql",
    "tds",
    "mqtt",
    "modbus",
    "dnp3",
    "bacnet",
    "amqp",
    "websocket",
    "rfb",
    "nfs",
    "mount",
    "portmap",
    "gssapi",
    "xmpp",
    "finger",
    "ident",
    "telnet",
    "login",
    "ayiya",
    "teredo",
    "gtpv1",
    "vxlan",
];

/// Lo que ninguno de los analizadores de Zeek hace, y este crate si.
///
/// No es una lista de protocolos: es una lista de **propiedades**, que es donde
/// esta la diferencia que importa. Zeek diseca mas cosas en algunos sitios; lo
/// que no hace, en ninguno, es decir cuanto no entendio.
pub static LO_QUE_NO_HACE_EL_DE_REFERENCIA: &[(&str, &str)] = &[
    (
        "cifra de cobertura por flujo",
        "cuando un analizador no entiende un mensaje lo salta o lo marca como \
         malformado, y el analista ve una traza con menos lineas sin saber que faltan",
    ),
    (
        "separar lo no implementado de lo cifrado",
        "uno se arregla escribiendo codigo y el otro no, y mezclarlos hace que la \
         cifra parezca un problema de esfuerzo cuando no lo es",
    ),
    (
        "declarar por adelantado lo que cada disector no analiza",
        "se puede saber que esperar de un sensor antes de mandarle trafico, en vez \
         de descubrirlo cuando falta una alerta",
    ),
    (
        "un solo tipo de hecho para todos los protocolos",
        "correlacionar una consulta a una base con una ejecucion remota y con un \
         fichero por correo no necesita una capa de union que alguien mantenga",
    ),
    (
        "marcar si una orden industrial escribe",
        "leer un registro de un PLC es telemetria y escribirlo mueve algo en el \
         mundo fisico; contarlos juntos entierra el segundo",
    ),
    (
        "un techo GLOBAL de memoria con recuento de lo que se suelta",
        "una cota por flujo no es una cota, porque el atacante elige tambien el \
         numero de flujos",
    ),
    (
        "OPC-UA y S7comm",
        "son los dos protocolos con los que se para una planta, y el sensor de \
         referencia no trae analizador de ninguno de los dos",
    ),
];

/// El resultado de comparar los dos sensores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparacion {
    /// Protocolos que este producto diseca, contando los de `aegis-wire`.
    pub nuestros: usize,
    /// Analizadores que la documentacion del sensor de referencia relaciona.
    pub del_de_referencia: usize,
    /// Protocolos que este producto diseca y el otro no relaciona.
    pub solo_nuestros: Vec<&'static str>,
    /// Los que el otro relaciona y este producto no diseca.
    pub solo_suyos: Vec<&'static str>,
    /// Propiedades que el otro no tiene en ningun protocolo.
    pub propiedades_que_le_faltan: usize,
}

impl Comparacion {
    /// Mide, construyendo el registro de verdad.
    ///
    /// Los nuestros salen de preguntarle al registro y al enumerado de
    /// protocolos; los suyos, de la lista transcrita. Que las dos mitades se
    /// obtengan de sitios distintos es el punto: una se mide y la otra se cita.
    #[must_use]
    pub fn medir() -> Comparacion {
        use aegis_wire::hecho::ProtocoloApp;

        let nuestros: Vec<&'static str> = ProtocoloApp::TODOS
            .iter()
            .map(|p| p.nombre())
            .filter(|n| *n != "desconocido")
            .collect();

        // Los nombres no coinciden entre los dos: `dce_rpc` y `dcerpc` son el
        // mismo protocolo, y `rfb` es VNC. Sin esta tabla, la comparacion daria
        // una diferencia inventada a favor nuestro.
        fn equivalente(nuestro: &str) -> &str {
            match nuestro {
                "dcerpc" => "dce_rpc",
                "vnc" => "rfb",
                "postgresql" => "postgresql",
                "tls" => "ssl",
                "http2" => "http",
                "http3" => "quic",
                otro => otro,
            }
        }

        let solo_nuestros: Vec<&'static str> = nuestros
            .iter()
            .copied()
            .filter(|n| !ANALIZADORES_DE_ZEEK.contains(&equivalente(n)))
            .collect();

        let suyos_traducidos: Vec<&'static str> = ANALIZADORES_DE_ZEEK
            .iter()
            .copied()
            .filter(|s| !nuestros.iter().any(|n| equivalente(n) == *s))
            .collect();

        Comparacion {
            nuestros: nuestros.len(),
            del_de_referencia: ANALIZADORES_DE_ZEEK.len(),
            solo_nuestros,
            solo_suyos: suyos_traducidos,
            propiedades_que_le_faltan: LO_QUE_NO_HACE_EL_DE_REFERENCIA.len(),
        }
    }

    /// Como se cuenta esta comparacion en un informe, sin adornarla.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "este sensor diseca {} protocolos y el de referencia relaciona {} analizadores. \
             {} son solo nuestros y {} son solo suyos — que es un hueco declarado y no una \
             derrota escondida. La diferencia que importa no es el recuento: son las {} \
             propiedades que el otro no tiene en NINGUN protocolo, empezando por decir \
             cuanto no entendio",
            self.nuestros,
            self.del_de_referencia,
            self.solo_nuestros.len(),
            self.solo_suyos.len(),
            self.propiedades_que_le_faltan
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::disector::Contexto;

    #[test]
    fn el_registro_completo_lleva_los_disectores_que_dice() {
        // Un disector nuevo que no toque la constante hace fallar esto, y asi la
        // cifra de un informe no se queda desfasada.
        let r = registro_completo();
        assert_eq!(r.cuantos(), DISECTORES_DE_ESTA_FASE);
        assert_eq!(r.protocolos().len(), DISECTORES_DE_ESTA_FASE);
    }

    #[test]
    fn ningun_disector_repite_nombre() {
        // Dos con el mismo nombre harian que uno no apareciera nunca en el
        // registro del cliente y nadie se enterara.
        let r = registro_completo();
        let mut nombres = r.protocolos();
        let antes = nombres.len();
        nombres.sort_unstable();
        nombres.dedup();
        assert_eq!(nombres.len(), antes);
    }

    #[test]
    fn cada_familia_aporta_disectores_y_ninguna_esta_vacia() {
        for f in Familia::TODAS {
            assert!(!f.disectores().is_empty(), "{}", f.nombre());
            assert!(!f.nombre().is_empty());
        }
    }

    #[test]
    fn los_perfiles_son_subconjuntos_del_completo_y_ninguno_esta_vacio() {
        let completo = registro_completo().cuantos();
        for p in [
            Perfil::PuestoDeTrabajo,
            Perfil::Servidor,
            Perfil::PasarelaIndustrial,
        ] {
            let n = p.registro().cuantos();
            assert!(n > 0, "{p:?}");
            assert!(n < completo, "{p:?} no puede llevarlo todo");
        }
        assert_eq!(Perfil::Completo.registro().cuantos(), completo);
    }

    /// La pasarela es el sitio por donde un ataque pasa de la oficina a la
    /// planta: si solo llevara lo industrial, veria la orden que para la CPU y no
    /// veria por donde entro quien la mando.
    #[test]
    fn la_pasarela_industrial_ve_las_dos_redes() {
        let f = Perfil::PasarelaIndustrial.familias();
        assert!(f.contains(&Familia::Industrial));
        assert!(f.contains(&Familia::Identidad));
        assert!(f.contains(&Familia::EjecucionRemota));
        let r = Perfil::PasarelaIndustrial.registro();
        for p in ["modbus", "s7comm", "opcua", "ntlm", "dcerpc"] {
            assert!(r.protocolos().contains(&p), "falta {p}");
        }
    }

    #[test]
    fn el_puesto_de_trabajo_no_carga_lo_que_nunca_va_a_ver() {
        // Cada disector que no va a reconocer nada se prueba igual con cada
        // paquete: cargarlos todos en todas partes cuesta tiempo por paquete.
        let r = Perfil::PuestoDeTrabajo.registro();
        for p in ["modbus", "dnp3", "s7comm", "kafka", "mysql"] {
            assert!(!r.protocolos().contains(&p), "sobra {p}");
        }
    }

    /// El registro entero ante un mensaje real de cada familia: gana el disector
    /// que lo reconoce **por contenido**, y ninguno se lleva lo que no es suyo.
    #[test]
    fn el_registro_entero_encamina_cada_mensaje_a_su_disector() {
        use aegis_wire::hecho::{Hecho, ProtocoloApp};

        let casos: Vec<(&str, Vec<u8>, Contexto, ProtocoloApp)> = vec![
            (
                "modbus",
                vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A],
                Contexto::tcp_cliente(502),
                ProtocoloApp::Modbus,
            ),
            (
                "dnp3",
                vec![
                    0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x9C, 0xB2, 0xC0, 0xC1, 0x01,
                ],
                Contexto::tcp_cliente(20000),
                ProtocoloApp::Dnp3,
            ),
            (
                "bacnet",
                vec![
                    0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08,
                ],
                Contexto::udp(47808),
                ProtocoloApp::Bacnet,
            ),
            (
                "redis",
                b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n".to_vec(),
                Contexto::tcp_cliente(6379),
                ProtocoloApp::Redis,
            ),
            (
                "socks",
                {
                    let mut v = vec![5u8, 1, 0, 1, 10, 0, 0, 1];
                    v.extend_from_slice(&445u16.to_be_bytes());
                    v
                },
                Contexto::tcp_cliente(1080),
                ProtocoloApp::Socks,
            ),
            (
                "metadatos-de-nube",
                b"GET /latest/meta-data/iam/security-credentials/rol HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".to_vec(),
                Contexto::tcp_cliente(80),
                ProtocoloApp::MetadatosDeNube,
            ),
        ];

        let mut r = registro_completo();
        for (nombre, bytes, ctx, esperado) in casos {
            let s = r.disecar(&bytes, &ctx);
            let visto = s.hechos.iter().find_map(|h| match h {
                Hecho::ProtocoloIdentificado(p) => Some(*p),
                _ => None,
            });
            assert_eq!(visto, Some(esperado), "{nombre} se fue a otro disector");
        }
    }

    #[test]
    fn el_registro_declara_lo_que_no_reconocio() {
        // Un sensor que calle lo que no entiende produce informes que parecen
        // completos.
        let mut r = registro_completo();
        let s = r.disecar(&[0x00; 3], &Contexto::tcp_cliente(12345));
        assert!(s.hechos.is_empty());
        assert!(!r.cobertura.completa());
        assert!(r.frase().contains("disectores"), "{}", r.frase());
    }

    #[test]
    fn la_comparacion_se_mide_de_un_lado_y_se_cita_del_otro() {
        let c = Comparacion::medir();
        // Los nuestros salen del enumerado de protocolos, no de una lista.
        assert_eq!(c.nuestros, aegis_wire::hecho::ProtocoloApp::TODOS.len() - 1);
        assert_eq!(c.del_de_referencia, ANALIZADORES_DE_ZEEK.len());
        assert!(c.nuestros > c.del_de_referencia / 2);
        assert_eq!(
            c.propiedades_que_le_faltan,
            LO_QUE_NO_HACE_EL_DE_REFERENCIA.len()
        );
        assert!(c.frase().contains("hueco declarado"), "{}", c.frase());
    }

    /// Los dos protocolos con los que se para una planta, y que el sensor de
    /// referencia no trae. Es la diferencia que este modulo existe para medir.
    #[test]
    fn los_dos_que_paran_una_planta_son_solo_nuestros() {
        let c = Comparacion::medir();
        assert!(c.solo_nuestros.contains(&"s7comm"), "{:?}", c.solo_nuestros);
        assert!(c.solo_nuestros.contains(&"opcua"), "{:?}", c.solo_nuestros);
    }

    /// Y lo que le falta a este sensor se dice igual de claro. Una comparacion
    /// que solo cuente lo propio no es una comparacion.
    #[test]
    fn lo_que_no_se_diseca_tambien_aparece() {
        let c = Comparacion::medir();
        assert!(!c.solo_suyos.is_empty(), "no hay comparacion sin esto");
        for esperado in ["sip", "snmp", "xmpp", "telnet"] {
            assert!(c.solo_suyos.contains(&esperado), "{:?}", c.solo_suyos);
        }
    }

    #[test]
    fn los_nombres_equivalentes_no_inventan_una_diferencia() {
        // `dce_rpc` y `dcerpc` son el mismo protocolo, y `rfb` es VNC: contarlos
        // como distintos daria una ventaja que no existe.
        let c = Comparacion::medir();
        for no_deberia in ["dcerpc", "vnc", "tls", "ntlm", "radius", "mysql"] {
            assert!(
                !c.solo_nuestros.contains(&no_deberia),
                "{no_deberia} tambien lo tiene el otro"
            );
        }
    }

    #[test]
    fn cada_propiedad_que_le_falta_al_otro_esta_explicada() {
        // Una fila que solo diga el nombre no vale para nada en un informe.
        for (que, por_que) in LO_QUE_NO_HACE_EL_DE_REFERENCIA {
            assert!(!que.is_empty());
            assert!(
                por_que.len() > 60,
                "{que}: la explicacion es demasiado corta"
            );
        }
    }
}
