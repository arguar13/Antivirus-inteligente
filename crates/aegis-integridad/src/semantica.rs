//! Integridad POR SIGNIFICADO: el cambio se expresa en la semantica del fichero.
//!
//! # Un diff de hash no distingue un comentario de una puerta trasera
//!
//! Wazuh FIM, AIDE y Tripwire comparan hashes: cualquier byte que cambie dispara
//! la misma alerta. Anadir un comentario a `sshd_config` y anadir
//! `PermitRootLogin yes` producen, para ellos, el mismo evento «`/etc/ssh/sshd_config`
//! cambio». Uno es ruido; el otro es una puerta trasera. Tratarlos igual es lo que
//! entrena a los analistas a ignorar las alertas del FIM.
//!
//! Aqui los ficheros de configuracion se PARSEAN y el cambio se expresa en su
//! significado: «se dio NOPASSWD a este usuario», «se cambio `PermitRootLogin` de
//! `no` a `yes`», «se anadio esta clave autorizada». Un cambio que solo toca
//! comentarios o espacios produce CERO cambios semanticos. Todo el parseo es puro
//! y no entra en panico ante entrada hostil (invariante del producto).

use aegis_entidad::Severidad;

/// El formato de un fichero de configuracion que sabemos leer por significado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Formato {
    /// `sshd_config`: directivas `Clave Valor`.
    SshdConfig,
    /// `sudoers`: reglas, de las que nos importan las concesiones `NOPASSWD`.
    Sudoers,
    /// `authorized_keys`: una clave publica por linea.
    AuthorizedKeys,
}

/// Un cambio expresado en el significado del fichero, no en su hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CambioSemantico {
    /// Cambio de la directiva de acceso de root por SSH. El caso estrella: pasar
    /// de `no`/`prohibit-password` a `yes` abre la puerta.
    PermitRootLogin {
        /// Valor anterior.
        antes: String,
        /// Valor nuevo.
        despues: String,
    },
    /// Cambio de cualquier otra directiva de SSH que reconocemos como sensible.
    DirectivaSsh {
        /// La directiva (en minusculas).
        clave: String,
        /// Valor anterior, si existia.
        antes: Option<String>,
        /// Valor nuevo, si existe.
        despues: Option<String>,
    },
    /// Se concedio `NOPASSWD` a un principal (usuario o `%grupo`): sudo sin
    /// contrasena es una escalada permanente.
    NopasswdConcedido {
        /// El principal (usuario o grupo).
        principal: String,
    },
    /// Se retiro un `NOPASSWD`.
    NopasswdRetirado {
        /// El principal.
        principal: String,
    },
    /// Se anadio una clave autorizada: el mecanismo de persistencia SSH mas comun.
    ClaveAutorizadaAnadida {
        /// Huella corta de la clave (BLAKE3 del blob).
        huella: String,
    },
    /// Se retiro una clave autorizada.
    ClaveAutorizadaRetirada {
        /// Huella corta.
        huella: String,
    },
}

impl CambioSemantico {
    /// La severidad del cambio para el arbitro. Abrir root por SSH, conceder
    /// NOPASSWD o anadir una clave autorizada son criticos; el resto, medios.
    #[must_use]
    pub fn severidad(&self) -> Severidad {
        match self {
            CambioSemantico::PermitRootLogin { despues, .. }
                if despues.eq_ignore_ascii_case("yes") =>
            {
                Severidad::Critica
            }
            CambioSemantico::NopasswdConcedido { .. }
            | CambioSemantico::ClaveAutorizadaAnadida { .. } => Severidad::Critica,
            CambioSemantico::PermitRootLogin { .. } | CambioSemantico::DirectivaSsh { .. } => {
                Severidad::Alta
            }
            CambioSemantico::NopasswdRetirado { .. }
            | CambioSemantico::ClaveAutorizadaRetirada { .. } => Severidad::Media,
        }
    }

    /// Una frase legible del cambio, para el analista.
    #[must_use]
    pub fn porque(&self) -> String {
        match self {
            CambioSemantico::PermitRootLogin { antes, despues } => {
                format!("PermitRootLogin cambio de «{antes}» a «{despues}»")
            }
            CambioSemantico::DirectivaSsh {
                clave,
                antes,
                despues,
            } => format!(
                "directiva SSH «{clave}» cambio de {} a {}",
                antes.as_deref().unwrap_or("(ausente)"),
                despues.as_deref().unwrap_or("(ausente)")
            ),
            CambioSemantico::NopasswdConcedido { principal } => {
                format!("se concedio NOPASSWD a «{principal}»: sudo sin contrasena")
            }
            CambioSemantico::NopasswdRetirado { principal } => {
                format!("se retiro NOPASSWD a «{principal}»")
            }
            CambioSemantico::ClaveAutorizadaAnadida { huella } => {
                format!("se anadio la clave autorizada {huella}")
            }
            CambioSemantico::ClaveAutorizadaRetirada { huella } => {
                format!("se retiro la clave autorizada {huella}")
            }
        }
    }
}

/// Las directivas de SSH que se vigilan por significado. El resto de cambios en
/// `sshd_config` no son de seguridad y no se elevan como tales.
const DIRECTIVAS_SSH_SENSIBLES: &[&str] = &[
    "permitrootlogin",
    "passwordauthentication",
    "pubkeyauthentication",
    "permitemptypasswords",
    "authorizedkeysfile",
    "allowusers",
    "allowgroups",
    "denyusers",
    "usepam",
    "x11forwarding",
    "permittunnel",
];

/// Analiza un cambio entre dos versiones de un fichero, por su significado.
///
/// Devuelve solo los cambios SEMANTICOS: si lo unico que cambio fueron comentarios
/// o espacios, la lista es vacia. Es la diferencia con un diff de hash, que habria
/// disparado igual.
#[must_use]
pub fn analizar_cambio(formato: Formato, antes: &str, despues: &str) -> Vec<CambioSemantico> {
    match formato {
        Formato::SshdConfig => diff_sshd(antes, despues),
        Formato::Sudoers => diff_sudoers(antes, despues),
        Formato::AuthorizedKeys => diff_authorized_keys(antes, despues),
    }
}

/// Quita comentarios (`#...`) y espacios de una linea; devuelve `None` si no queda
/// nada util. Es lo que hace que un comentario nuevo no sea un cambio.
fn util(linea: &str) -> Option<&str> {
    let sin_comentario = match linea.find('#') {
        Some(i) => &linea[..i],
        None => linea,
    };
    let t = sin_comentario.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Parsea `sshd_config` a un mapa `directiva_en_minusculas -> valor`. La ultima
/// aparicion gana, como hace el propio sshd.
fn parsear_sshd(texto: &str) -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    for linea in texto.lines() {
        let Some(t) = util(linea) else { continue };
        let mut it = t.splitn(2, char::is_whitespace);
        let Some(clave) = it.next() else { continue };
        let valor = it.next().unwrap_or("").trim().to_string();
        m.insert(clave.to_ascii_lowercase(), valor);
    }
    m
}

fn diff_sshd(antes: &str, despues: &str) -> Vec<CambioSemantico> {
    let a = parsear_sshd(antes);
    let d = parsear_sshd(despues);
    let mut cambios = Vec::new();
    for clave in DIRECTIVAS_SSH_SENSIBLES {
        let va = a.get(*clave);
        let vd = d.get(*clave);
        if va == vd {
            continue;
        }
        if *clave == "permitrootlogin" {
            cambios.push(CambioSemantico::PermitRootLogin {
                antes: va.cloned().unwrap_or_else(|| "(por defecto)".to_string()),
                despues: vd.cloned().unwrap_or_else(|| "(por defecto)".to_string()),
            });
        } else {
            cambios.push(CambioSemantico::DirectivaSsh {
                clave: (*clave).to_string(),
                antes: va.cloned(),
                despues: vd.cloned(),
            });
        }
    }
    cambios
}

/// Extrae el conjunto de principales con `NOPASSWD` de un `sudoers`.
fn nopasswd_de(texto: &str) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    for linea in texto.lines() {
        let Some(t) = util(linea) else { continue };
        // Nos importan las lineas de regla que conceden NOPASSWD. El principal es
        // el primer token (usuario o `%grupo`). Las lineas `Defaults` y los alias
        // no conceden acceso por si mismas.
        if t.to_ascii_uppercase().contains("NOPASSWD") {
            if let Some(princ) = t.split_whitespace().next() {
                if !princ.eq_ignore_ascii_case("Defaults") {
                    set.insert(princ.to_string());
                }
            }
        }
    }
    set
}

fn diff_sudoers(antes: &str, despues: &str) -> Vec<CambioSemantico> {
    let a = nopasswd_de(antes);
    let d = nopasswd_de(despues);
    let mut cambios = Vec::new();
    for p in d.difference(&a) {
        cambios.push(CambioSemantico::NopasswdConcedido {
            principal: p.clone(),
        });
    }
    for p in a.difference(&d) {
        cambios.push(CambioSemantico::NopasswdRetirado {
            principal: p.clone(),
        });
    }
    cambios
}

/// Huella corta y estable de una clave autorizada: BLAKE3 del blob normalizado.
fn huella_clave(linea: &str) -> String {
    // Formato: `tipo base64 [comentario]`. La identidad es tipo+base64; el
    // comentario no cuenta (cambiarlo no cambia la clave).
    let mut it = linea.split_whitespace();
    let blob = match (it.next(), it.next()) {
        (Some(tipo), Some(b64)) => format!("{tipo} {b64}"),
        _ => linea.trim().to_string(),
    };
    let h = blake3::hash(blob.as_bytes());
    h.to_hex()[..16].to_string()
}

fn claves_de(texto: &str) -> std::collections::BTreeSet<String> {
    texto.lines().filter_map(util).map(huella_clave).collect()
}

fn diff_authorized_keys(antes: &str, despues: &str) -> Vec<CambioSemantico> {
    let a = claves_de(antes);
    let d = claves_de(despues);
    let mut cambios = Vec::new();
    for h in d.difference(&a) {
        cambios.push(CambioSemantico::ClaveAutorizadaAnadida { huella: h.clone() });
    }
    for h in a.difference(&d) {
        cambios.push(CambioSemantico::ClaveAutorizadaRetirada { huella: h.clone() });
    }
    cambios
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_comentario_nuevo_no_es_un_cambio_semantico() {
        // EL punto de la fase: un diff de hash dispararia; aqui no pasa nada,
        // porque el significado del fichero no cambio.
        let antes = "PermitRootLogin no\nPort 22\n";
        let despues = "# comentario nuevo y espacios\nPermitRootLogin no\n\nPort 22\n";
        assert!(analizar_cambio(Formato::SshdConfig, antes, despues).is_empty());
    }

    #[test]
    fn abrir_root_por_ssh_es_un_cambio_critico_y_preciso() {
        let antes = "PermitRootLogin no\n";
        let despues = "PermitRootLogin yes\n";
        let c = analizar_cambio(Formato::SshdConfig, antes, despues);
        assert_eq!(c.len(), 1);
        assert!(matches!(
            &c[0],
            CambioSemantico::PermitRootLogin { antes, despues }
                if antes == "no" && despues == "yes"
        ));
        assert_eq!(c[0].severidad(), Severidad::Critica);
    }

    #[test]
    fn conceder_nopasswd_se_ve_como_tal() {
        let antes = "root ALL=(ALL) ALL\n";
        let despues = "root ALL=(ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n";
        let c = analizar_cambio(Formato::Sudoers, antes, despues);
        assert_eq!(c.len(), 1);
        assert!(
            matches!(&c[0], CambioSemantico::NopasswdConcedido { principal } if principal == "alice")
        );
        assert_eq!(c[0].severidad(), Severidad::Critica);
    }

    #[test]
    fn anadir_una_clave_autorizada_se_detecta_y_el_comentario_no_cuenta() {
        let antes = "ssh-ed25519 AAAAC3Nkey1 alice@host\n";
        // Misma clave, comentario distinto: NO es un cambio.
        let igual = "ssh-ed25519 AAAAC3Nkey1 alice@OTRO-host\n";
        assert!(analizar_cambio(Formato::AuthorizedKeys, antes, igual).is_empty());
        // Clave nueva: SI es un cambio, y critico.
        let nueva = "ssh-ed25519 AAAAC3Nkey1 alice@host\nssh-rsa AAAAB3Nkey2 atacante\n";
        let c = analizar_cambio(Formato::AuthorizedKeys, antes, nueva);
        assert_eq!(c.len(), 1);
        assert!(matches!(
            &c[0],
            CambioSemantico::ClaveAutorizadaAnadida { .. }
        ));
        assert_eq!(c[0].severidad(), Severidad::Critica);
    }

    #[test]
    fn entrada_hostil_no_entra_en_panico() {
        // Basura, lineas larguisimas, sin saltos: no debe cundir el panico.
        let basura = "\0\0\0 ###\n".repeat(100) + &"x".repeat(10_000);
        let _ = analizar_cambio(Formato::SshdConfig, &basura, "");
        let _ = analizar_cambio(Formato::Sudoers, &basura, &basura);
        let _ = analizar_cambio(Formato::AuthorizedKeys, "", &basura);
    }
}
