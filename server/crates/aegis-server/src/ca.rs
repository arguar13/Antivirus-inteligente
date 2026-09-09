//! Custodia de la autoridad certificadora de la flota.
//!
//! # Por que este modulo existe
//!
//! El plano de control ES la CA de la flota: quien firma los certificados con
//! los que los agentes se autentican. Ese material tiene dos propiedades
//! incomodas a la vez:
//!
//! 1. **Tiene que sobrevivir al proceso.** Una CA que se regenera en cada
//!    arranque invalida los certificados de TODA la flota en el primer
//!    reinicio: miles de endpoints dejarian de reportar a la vez.
//! 2. **Es el secreto mas valioso del sistema.** Quien tenga la clave de la CA
//!    puede emitir un certificado valido para cualquier identidad y hacerse
//!    pasar por el plano de control ante toda la flota, o por cualquier agente
//!    ante el plano de control.
//!
//! De ahi las dos reglas que impone este modulo: la CA se PERSISTE, y se niega
//! a arrancar si el fichero de la clave es legible por alguien mas que su dueno.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aegis_fleet::pki::AutoridadCertificadora;

use crate::error::{ErrorServidor, Resultado};

/// Nombre del fichero del certificado de la CA (publico).
const FICHERO_CERT: &str = "flota-ca.crt";
/// Nombre del fichero de la clave de la CA (secreto).
const FICHERO_CLAVE: &str = "flota-ca.key";
/// Nombre distinguido de la CA de la flota.
const NOMBRE_CA: &str = "AegisFleet Root CA";

/// Permisos del directorio: solo el dueno entra.
const MODO_DIR: u32 = 0o700;
/// Permisos del certificado: publico, es el ancla que se distribuye.
const MODO_CERT: u32 = 0o644;
/// Permisos de la clave: solo el dueno lee y escribe.
const MODO_CLAVE: u32 = 0o600;

/// Resultado de resolver la CA al arrancar.
pub struct CaDeFlota {
    /// La autoridad, lista para emitir.
    pub autoridad: AutoridadCertificadora,
    /// Ruta del certificado, para decirle al operador que provisionar.
    pub ruta_cert: PathBuf,
    /// Si se ha creado en este arranque (y por tanto la flota hay que
    /// reprovisionarla con el ancla nueva).
    pub recien_creada: bool,
}

/// Carga la CA del directorio, o la crea si aun no existe.
///
/// El comportamiento es deliberadamente idempotente: arrancar dos veces sobre
/// el mismo directorio da la MISMA autoridad, que es justo lo que necesita un
/// servicio que se reinicia.
pub fn cargar_o_crear(dir: &Path) -> Resultado<CaDeFlota> {
    let ruta_cert = dir.join(FICHERO_CERT);
    let ruta_clave = dir.join(FICHERO_CLAVE);

    if ruta_cert.exists() && ruta_clave.exists() {
        verificar_permisos_clave(&ruta_clave)?;
        let cert_pem = leer(&ruta_cert)?;
        let clave_pem = leer(&ruta_clave)?;
        let autoridad = AutoridadCertificadora::desde_pem(&cert_pem, &clave_pem)?;
        return Ok(CaDeFlota {
            autoridad,
            ruta_cert,
            recien_creada: false,
        });
    }

    // Que exista SOLO uno de los dos ficheros es un estado corrupto: seguir
    // adelante generaria una CA nueva y machacaria silenciosamente material que
    // quiza aun este provisionado en la flota.
    if ruta_cert.exists() != ruta_clave.exists() {
        return Err(ErrorServidor::Config(format!(
            "el material de la CA esta incompleto en {}: existe uno de los dos ficheros \
             ({} / {}). No se genera una CA nueva encima; revisa la copia de seguridad.",
            dir.display(),
            FICHERO_CERT,
            FICHERO_CLAVE
        )));
    }

    crear_directorio(dir)?;
    let autoridad = AutoridadCertificadora::nueva(NOMBRE_CA)?;
    escribir(&ruta_cert, &autoridad.cert_pem(), MODO_CERT)?;
    escribir(&ruta_clave, &autoridad.clave_pem(), MODO_CLAVE)?;

    Ok(CaDeFlota {
        autoridad,
        ruta_cert,
        recien_creada: true,
    })
}

/// Crea el directorio de la CA con permisos restrictivos.
fn crear_directorio(dir: &Path) -> Resultado<()> {
    fs::create_dir_all(dir).map_err(|e| ErrorServidor::Io {
        op: "crear el directorio de la CA",
        source: e,
    })?;
    // `create_dir_all` respeta la umask, que puede dejar el directorio abierto:
    // se fija el modo explicitamente en vez de confiar en el entorno.
    fs::set_permissions(dir, fs::Permissions::from_mode(MODO_DIR)).map_err(|e| ErrorServidor::Io {
        op: "fijar permisos del directorio de la CA",
        source: e,
    })
}

/// Lee un fichero de texto.
fn leer(ruta: &Path) -> Resultado<String> {
    fs::read_to_string(ruta).map_err(|e| ErrorServidor::Io {
        op: "leer material de la CA",
        source: e,
    })
}

/// Escribe un fichero creandolo con el modo pedido desde el principio.
///
/// El modo se pasa a `open`, no se corrige despues: si se creara con permisos
/// abiertos y se ajustaran a continuacion, existiria una ventana —por breve que
/// sea— en la que la clave de la CA es legible por cualquiera del sistema.
fn escribir(ruta: &Path, contenido: &str, modo: u32) -> Resultado<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(modo)
        .open(ruta)
        .map_err(|e| ErrorServidor::Io {
            op: "crear fichero de la CA",
            source: e,
        })?;
    f.write_all(contenido.as_bytes())
        .map_err(|e| ErrorServidor::Io {
            op: "escribir material de la CA",
            source: e,
        })?;
    // Un fichero que sobrevive a un corte de corriente a medio escribir dejaria
    // una CA ilegible y el servicio no arrancaria nunca mas.
    f.sync_all().map_err(|e| ErrorServidor::Io {
        op: "sincronizar material de la CA",
        source: e,
    })?;
    // Si el fichero ya existia con otro modo, `mode()` no lo cambia: se fuerza.
    fs::set_permissions(ruta, fs::Permissions::from_mode(modo)).map_err(|e| ErrorServidor::Io {
        op: "fijar permisos del material de la CA",
        source: e,
    })
}

/// Se niega a usar una clave de CA que otros puedan leer.
///
/// No es celo excesivo: la clave de la CA de la flota permite suplantar a
/// cualquier endpoint Y al propio plano de control. Si esta expuesta, arrancar
/// el servicio es peor que no arrancarlo, porque da la impresion de que todo
/// funciona mientras la confianza de la flota entera esta comprometida.
fn verificar_permisos_clave(ruta: &Path) -> Resultado<()> {
    let meta = fs::metadata(ruta).map_err(|e| ErrorServidor::Io {
        op: "consultar permisos de la clave de la CA",
        source: e,
    })?;
    let modo = meta.permissions().mode() & 0o777;
    if modo & 0o077 != 0 {
        return Err(ErrorServidor::Config(format!(
            "la clave de la CA en {} tiene permisos {:o}: es legible por el grupo o por otros. \
             Corrigelo con `chmod 600 {}` antes de arrancar; con esa clave se puede suplantar \
             a cualquier agente y al propio plano de control.",
            ruta.display(),
            modo,
            ruta.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Directorio temporal propio, para no depender de crates externos.
    fn dir_temporal(nombre: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-ca-{}-{}",
            nombre,
            uuid::Uuid::new_v4().simple()
        ));
        d
    }

    #[test]
    fn la_ca_se_crea_la_primera_vez_y_se_reutiliza_despues() {
        let dir = dir_temporal("idempotente");
        let primera = cargar_o_crear(&dir).unwrap();
        assert!(primera.recien_creada, "la primera vez se crea");
        let ancla_1 = primera.autoridad.cert_der();

        // Segundo arranque sobre el mismo directorio: la MISMA autoridad.
        let segunda = cargar_o_crear(&dir).unwrap();
        assert!(!segunda.recien_creada, "la segunda vez se reutiliza");
        assert_eq!(
            ancla_1.as_ref(),
            segunda.autoridad.cert_der().as_ref(),
            "reiniciar el plano de control no puede cambiar el ancla de la flota"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn la_clave_se_escribe_con_permisos_restrictivos() {
        let dir = dir_temporal("permisos");
        cargar_o_crear(&dir).unwrap();

        let modo_clave = fs::metadata(dir.join(FICHERO_CLAVE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(modo_clave, MODO_CLAVE, "la clave solo la lee su dueno");

        let modo_dir = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo_dir, MODO_DIR, "el directorio no lo recorre nadie mas");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_clave_legible_por_otros_impide_arrancar() {
        let dir = dir_temporal("expuesta");
        cargar_o_crear(&dir).unwrap();

        // Alguien deja la clave abierta.
        fs::set_permissions(dir.join(FICHERO_CLAVE), fs::Permissions::from_mode(0o644)).unwrap();

        let r = cargar_o_crear(&dir);
        assert!(
            r.is_err(),
            "con la clave de la CA expuesta hay que negarse a arrancar"
        );
        let msg = format!("{}", r.err().unwrap());
        assert!(
            msg.contains("legible"),
            "el error debe explicar el problema: {msg}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn el_material_incompleto_no_se_machaca_en_silencio() {
        let dir = dir_temporal("incompleto");
        cargar_o_crear(&dir).unwrap();

        // Se pierde la clave pero queda el certificado: estado corrupto.
        fs::remove_file(dir.join(FICHERO_CLAVE)).unwrap();

        let r = cargar_o_crear(&dir);
        assert!(
            r.is_err(),
            "generar una CA nueva encima destruiria el ancla que la flota ya tiene"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
