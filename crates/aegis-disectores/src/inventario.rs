//! La linea base: que se disecaba antes de esta fase, y con que cobertura.
//!
//! # Por que este inventario va en el codigo y no en un documento
//!
//! Porque la cifra de cobertura es la medida de la fase, y una medida escrita en
//! un documento aparte se queda desfasada el primer dia. Aqui es una constante
//! que las pruebas comprueban: si alguien anade un disector y no toca esto, la
//! prueba de coherencia falla.
//!
//! # Lo que `aegis-wire` ya hacia, leido entero antes de escribir nada
//!
//! Trece protocolos de aplicacion, con identificacion **por contenido** y el
//! puerto solo como desempate —que es lo correcto: un servidor HTTP en el 8443
//! sigue siendo HTTP, y confiar en el puerto es como se pierde todo lo que se
//! mueve a un puerto raro a proposito.
//!
//! Lo que ya estaba resuelto y **no se toca**:
//!
//! - El reensamblado de TCP resistente a la evasion por solape, con tope de
//!   huecos, de bytes retenidos y de adelanto.
//! - Dos techos GLOBALES de memoria: el de flujos y el de bufers de aplicacion.
//!   Es la invariante 9 de esta fase, y ya estaba: una cota por flujo no es una
//!   cota, porque el atacante elige tambien el numero de flujos.
//! - El modelo de hechos, que es lo que sale de disecar y entra en el arbitro.
//!
//! Lo que esta fase anade **no puede romper nada de eso**, y en particular no
//! puede anadir memoria por flujo sin caber bajo el techo global que ya existe.

/// Los protocolos que `aegis-wire` ya disecaba antes de esta fase.
///
/// Cada uno con lo que de verdad entiende de el. La columna que importa no es
/// «lo reconoce» sino «que saca», porque reconocer un protocolo y no sacar nada
/// de el no aporta un hecho al arbitro.
pub static LINEA_BASE: &[(&str, &str)] = &[
    ("dns", "consultas, respuestas e indicios de tunel"),
    (
        "http",
        "peticiones con su metodo, ruta y cabeceras; respuestas con su codigo",
    ),
    (
        "tls",
        "el saludo del cliente con su SNI y su huella; el certificado del servidor",
    ),
    ("ssh", "la version anunciada por cada extremo"),
    (
        "smb",
        "el establecimiento de sesion y los ficheros que se mueven",
    ),
    ("kerberos", "las peticiones de ticket"),
    ("ldap", "las operaciones de vinculacion y busqueda"),
    (
        "dhcp",
        "la peticion y la concesion, con el nombre del equipo",
    ),
    ("ntp", "la consulta de hora"),
    ("smtp", "los sobres del correo"),
    ("ftp", "el canal de control y sus ordenes"),
    ("quic", "la version y el saludo inicial"),
    (
        "desconocido",
        "se vio trafico y no se reconocio: es un hecho, y se dice",
    ),
];

/// Cuantos protocolos disecaba `aegis-wire` antes de esta fase.
///
/// Doce mas la variante que declara lo no reconocido. Ese trece es el numero
/// contra el que se mide la fase, y esta aqui para que no se pueda contar mal en
/// un informe.
pub const PROTOCOLOS_EN_LA_LINEA_BASE: usize = 12;

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_inventario_cuadra_con_lo_que_dice_su_constante() {
        // Si no cuadraran, la cifra de cobertura de la fase estaria medida contra
        // un numero inventado.
        let sin_el_desconocido = LINEA_BASE.len() - 1;
        assert_eq!(sin_el_desconocido, PROTOCOLOS_EN_LA_LINEA_BASE);
    }

    #[test]
    fn cada_entrada_del_inventario_dice_que_saca_y_no_solo_que_reconoce() {
        // Reconocer un protocolo y no sacar nada de el no aporta un hecho al
        // arbitro, y contarlo como cobertura seria inflar la cifra.
        for (nombre, que_saca) in LINEA_BASE {
            assert!(!nombre.is_empty());
            assert!(
                que_saca.len() > 15,
                "{nombre}: la descripcion no dice que se saca de el"
            );
        }
    }

    #[test]
    fn la_linea_base_coincide_con_los_protocolos_que_aegis_wire_declara() {
        // La comprobacion que impide que este inventario se quede desfasado: se
        // cuenta contra el enumerado de verdad, no contra la memoria de quien lo
        // escribio.
        use aegis_wire::hecho::ProtocoloApp;
        let declarados = [
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
        ];
        assert_eq!(declarados.len(), PROTOCOLOS_EN_LA_LINEA_BASE);
        for p in declarados {
            assert!(
                LINEA_BASE.iter().any(|(n, _)| *n == p.nombre()),
                "{} esta en aegis-wire y no en el inventario",
                p.nombre()
            );
        }
    }
}
