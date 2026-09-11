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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    }
}
