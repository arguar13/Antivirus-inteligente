//! Renderizado de credenciales senuelo CREIBLES.
//!
//! Un honey-token solo funciona si el atacante se lo cree. Una credencial mal
//! formada la descarta a simple vista —o su herramienta la rechaza al parsearla—
//! y el senuelo no dispara. Por eso cada artefacto se genera con la forma real de
//! su tipo, y las pruebas lo validan con parsers REALES (ssh-key, roxmltree): si
//! el artefacto no parsea como lo que dice ser, no engana a nadie.
//!
//! El marcador atribuible ([`crate::token::Marcador`]) se embebe en un campo que
//! el atacante conservaria al robar la credencial: el comentario de la clave, el
//! usuario del `.pgpass`, el nombre de cuenta del XML.

use crate::token::Marcador;

/// Un cuerpo de clave publica ed25519 con estructura OpenSSH valida. Es un
/// senuelo: no corresponde a ninguna clave privada util, pero parsea como una
/// clave OpenSSH de verdad, que es lo que la hace creible en un `authorized_keys`
/// o un `.pub` filtrado.
const CUERPO_SSH_ED25519: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

/// Los tipos de artefacto senuelo que se saben renderizar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Artefacto {
    /// Una linea de clave publica OpenSSH autorizada (el marcador va en el
    /// comentario).
    ClaveSshAutorizada,
    /// Una linea de `~/.pgpass` (el marcador va en el nombre de usuario).
    PgpassLinea,
    /// Una linea de `/etc/shadow` de una cuenta de alta jerarquia falsa.
    ShadowLinea,
    /// Un `credentials.xml` estilo servicio (el marcador va en la cuenta).
    CredentialsXml,
    /// Un nombre de DNS interno que no resuelve a nada util.
    ///
    /// Es el unico artefacto que puede delatar al atacante **sin que toque la
    /// maquina**: cuando la credencial sale de la organizacion y alguien resuelve
    /// el nombre que venia con ella, la consulta llega al servidor autoritativo
    /// propio y el marcador esta en la etiqueta.
    NombreDns,
    /// Una clave de API con la forma que usan los servicios de nube.
    ///
    /// La forma importa: una herramienta de robo de secretos busca por expresion
    /// regular, y una clave que no case con la de su catalogo ni la recoge.
    ClaveDeApi,
    /// Una fila de tabla lista para insertar en una base senuelo.
    ///
    /// Nadie consulta una fila concreta de una tabla de clientes por casualidad,
    /// pero un `SELECT *` se la lleva entera: es lo que delata el volcado.
    FilaDeTabla,
    /// Un fichero `.env` de aplicacion, que es donde mira todo el mundo primero.
    FicheroEnv,
}

impl Artefacto {
    /// Todos, para recorrerlos en pruebas y en el sembrado por perfil.
    pub const TODOS: [Artefacto; 8] = [
        Artefacto::ClaveSshAutorizada,
        Artefacto::PgpassLinea,
        Artefacto::ShadowLinea,
        Artefacto::CredentialsXml,
        Artefacto::NombreDns,
        Artefacto::ClaveDeApi,
        Artefacto::FilaDeTabla,
        Artefacto::FicheroEnv,
    ];

    /// Nombre corto y estable, para informes.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Artefacto::ClaveSshAutorizada => "clave-ssh-autorizada",
            Artefacto::PgpassLinea => "pgpass",
            Artefacto::ShadowLinea => "shadow",
            Artefacto::CredentialsXml => "credentials-xml",
            Artefacto::NombreDns => "nombre-dns",
            Artefacto::ClaveDeApi => "clave-de-api",
            Artefacto::FilaDeTabla => "fila-de-tabla",
            Artefacto::FicheroEnv => "fichero-env",
        }
    }
}

/// Renderiza un artefacto senuelo con el marcador embebido. El resultado es un
/// texto listo para sembrar en un fichero o en la memoria de un proceso.
pub fn render(art: Artefacto, marcador: &Marcador) -> String {
    let m = marcador.hex();
    match art {
        Artefacto::ClaveSshAutorizada => {
            // Comentario tipico de una clave de servicio; el marcador va ahi.
            format!("ssh-ed25519 {CUERPO_SSH_ED25519} svc-backup-{m}@aegis")
        }
        Artefacto::PgpassLinea => {
            // host:port:db:usuario:password — el usuario lleva el marcador.
            format!("db-prod.internal:5432:*:svc_report_{m}:R3port!ng2024")
        }
        Artefacto::ShadowLinea => {
            // Cuenta de administrador falsa; el marcador va en el nombre.
            format!("adminops_{m}:$6$aegishoney$3xampl3H4shN0tR34lL0ngEn0ughToLo0kR34l0000:19700:0:99999:7:::")
        }
        Artefacto::CredentialsXml => {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n                 <credentials>\n                   <service name=\"vault\">\n                     <account>svc_deploy_{m}</account>\n                     <secret>Depl0y!Token2024xY</secret>\n                   </service>\n                 </credentials>\n"
            )
        }
        // Una etiqueta de DNS admite 63 caracteres; el marcador son 32, asi que
        // cabe entero en una sola etiqueta y no hay que partirlo. Que quepa entero
        // importa: un resolutor que trocee el nombre romperia la atribucion.
        Artefacto::NombreDns => format!("backup-{m}.interno.empresa.es"),
        // La forma de una clave de AWS: `AKIA` y veinte caracteres en mayusculas
        // para el identificador, y un secreto de cuarenta. El marcador va en el
        // secreto, que es la parte que el ladron se lleva entera.
        Artefacto::ClaveDeApi => {
            format!("AKIAIOSFODNN7EXAMPLE:{m}wJalrXUtnFEMI8K7MDENG")
        }
        // Lista para un `INSERT`, con el marcador en una columna de texto libre:
        // las notas de un cliente son justo donde nadie mira y todo el mundo
        // exporta.
        Artefacto::FilaDeTabla => {
            format!(
                "INSERT INTO clientes (nombre, contacto, notas) VALUES \
                 ('Consultora Vega SL', 'operaciones@vega-sl.es', 'acceso portal: svc_{m}');"
            )
        }
        Artefacto::FicheroEnv => {
            format!(
                "# generado por el despliegue, no editar a mano\n\
                 APP_ENV=production\n\
                 DATABASE_URL=postgres://svc_app_{m}:Pr0d!Db2024@db-prod.internal:5432/app\n\
                 SESSION_SECRET=c1f5a9d4e7b2{m}\n"
            )
        }
    }
}
