//! Atributos extendidos: lo que un fichero lleva encima y no se ve en `ls`.
//!
//! # Por que esto esta en la SCAL y no en quien lo usa
//!
//! Leer atributos extendidos no tiene equivalente en `std`: hacen falta
//! `llistxattr` y `lgetxattr`, que son llamadas al sistema con buffers crudos.
//! La regla del producto es que el `unsafe` vive concentrado aqui, revisado, y
//! que quien consume estos datos —`aegis-estado`, desde la FASE 81— lo hace con
//! `#![forbid(unsafe_code)]` y sin enterarse.
//!
//! # Por que las variantes que NO siguen enlaces
//!
//! Se usan `llistxattr` y `lgetxattr`, no `listxattr` y `getxattr`. La
//! diferencia es que las primeras NO siguen enlaces simbolicos, y en un
//! contexto de seguridad esa es la unica eleccion defendible: si un atacante
//! deja un enlace de `/tmp/algo` a `/etc/shadow`, la version que sigue enlaces
//! haria que el agente leyera los atributos de `/etc/shadow` creyendo que mira
//! el fichero de `/tmp`. Es la misma clase de fallo que un TOCTOU, y se evita
//! no pidiendolo nunca.
//!
//! # Lo que aqui interesa de verdad
//!
//! Tres atributos concretos son deteccion, no inventario:
//!
//!   - `security.capability`: capacidades de fichero. Un binario con
//!     `CAP_SYS_ADMIN` en su xattr es un `setuid` moderno que `find -perm -4000`
//!     no encuentra.
//!   - `system.posix_acl_access`: ACL POSIX. Un fichero con permisos `600` puede
//!     ser legible por medio mundo a traves de su ACL, y el modo no lo enseña.
//!   - `security.selinux`: el contexto del fichero.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Tope de bytes que se leen de un atributo.
///
/// Un atributo extendido puede llegar al tamaño de un bloque del sistema de
/// ficheros. Nada de lo que aqui interesa pasa de unos cientos de bytes, y un
/// tope evita que un fichero preparado a proposito haga que el agente reserve
/// memoria a demanda de quien escribio el fichero.
pub const TOPE_VALOR: usize = 64 * 1024;

/// Tope de bytes de la lista de nombres de atributos.
pub const TOPE_LISTA: usize = 64 * 1024;

/// Error al leer atributos extendidos.
#[derive(Debug, thiserror::Error)]
pub enum XattrError {
    /// El sistema de ficheros no los soporta, o el fichero no tiene ninguno.
    #[error("el sistema de ficheros no soporta atributos extendidos")]
    NoSoportado,
    /// No hay permiso para leerlos.
    #[error("sin permiso para leer los atributos extendidos")]
    SinPermiso,
    /// El fichero no existe.
    #[error("el fichero no existe")]
    NoExiste,
    /// La ruta lleva un byte nulo y no se puede pasar al sistema.
    #[error("la ruta no es valida para el sistema")]
    RutaInvalida,
    /// Cualquier otro error del sistema.
    #[error("error del sistema al leer atributos extendidos: {0}")]
    Sistema(i32),
}

/// Traduce el `errno` actual a un error con significado.
fn desde_errno() -> XattrError {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        // ENOTSUP / EOPNOTSUPP: el sistema de ficheros no los tiene. ENODATA: el
        // fichero no tiene ese atributo. Las dos son "no hay", no "fallo".
        Some(libc::ENOTSUP) | Some(libc::ENODATA) => XattrError::NoSoportado,
        Some(libc::EACCES) | Some(libc::EPERM) => XattrError::SinPermiso,
        Some(libc::ENOENT) => XattrError::NoExiste,
        Some(otro) => XattrError::Sistema(otro),
        None => XattrError::Sistema(0),
    }
}

/// Convierte una ruta en la cadena con terminador nulo que pide el sistema.
fn como_c(ruta: &Path) -> Result<CString, XattrError> {
    CString::new(ruta.as_os_str().as_bytes()).map_err(|_| XattrError::RutaInvalida)
}

/// Nombres de los atributos extendidos de un fichero, sin seguir enlaces.
///
/// Devuelve la lista vacia —y no un error— cuando el fichero sencillamente no
/// tiene ninguno, que es el caso de la inmensa mayoria de los ficheros de una
/// maquina. Distinguir "no tiene" de "no pude" es justamente lo que hace util
/// esta funcion para el tri-estado de la FASE 81.
pub fn nombres(ruta: &Path) -> Result<Vec<String>, XattrError> {
    let c = como_c(ruta)?;

    // Primera llamada con tamaño 0: el sistema devuelve cuantos bytes hacen
    // falta, sin escribir nada. Es el modo documentado de `llistxattr`.
    //
    // SAFETY: `c` es una `CString` viva durante toda la llamada, y se pasa un
    // puntero nulo con longitud 0, que es exactamente el modo de consulta que
    // la pagina de manual describe. El sistema no escribe en ningun buffer.
    let necesarios = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
    if necesarios < 0 {
        let e = desde_errno();
        // "No soportado" aqui significa que no hay atributos que listar.
        return match e {
            XattrError::NoSoportado => Ok(Vec::new()),
            otro => Err(otro),
        };
    }
    if necesarios == 0 {
        return Ok(Vec::new());
    }

    let cuantos = (necesarios as usize).min(TOPE_LISTA);
    let mut buffer = vec![0u8; cuantos];

    // SAFETY: `buffer` tiene `cuantos` bytes reservados y se le pasa esa misma
    // longitud, asi que el sistema no puede escribir fuera. `c` sigue viva. El
    // puntero se convierte a `*mut c_char` porque la firma lo pide; el buffer
    // es de bytes y c_char es un byte con signo, misma representacion.
    let escritos = unsafe {
        libc::llistxattr(
            c.as_ptr(),
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
        )
    };
    if escritos < 0 {
        let e = desde_errno();
        return match e {
            XattrError::NoSoportado => Ok(Vec::new()),
            otro => Err(otro),
        };
    }
    buffer.truncate(escritos as usize);

    // La lista viene como nombres separados por byte nulo.
    Ok(buffer
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// Valor de un atributo extendido, sin seguir enlaces.
///
/// Devuelve los bytes tal cual: `security.capability` y
/// `system.posix_acl_access` son estructuras binarias, no texto, y convertirlas
/// aqui a cadena perderia informacion. Quien las entiende las decodifica.
pub fn valor(ruta: &Path, nombre: &str) -> Result<Vec<u8>, XattrError> {
    let c = como_c(ruta)?;
    let n = CString::new(nombre).map_err(|_| XattrError::RutaInvalida)?;

    // SAFETY: mismo contrato que en `nombres`: consulta de tamaño con puntero
    // nulo y longitud 0. `c` y `n` viven durante toda la llamada.
    let necesarios = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if necesarios < 0 {
        return Err(desde_errno());
    }
    if necesarios == 0 {
        return Ok(Vec::new());
    }

    let cuantos = (necesarios as usize).min(TOPE_VALOR);
    let mut buffer = vec![0u8; cuantos];

    // SAFETY: `buffer` tiene `cuantos` bytes y se pasa esa longitud exacta.
    let escritos = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            n.as_ptr(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };
    if escritos < 0 {
        return Err(desde_errno());
    }
    buffer.truncate(escritos as usize);
    Ok(buffer)
}

/// Indica si una ruta tiene el atributo de capacidades de fichero.
pub fn tiene_capacidades(ruta: &Path) -> bool {
    matches!(valor(ruta, "security.capability"), Ok(v) if !v.is_empty())
}

// ---------------------------------------------------------------------------
// Decodificacion de `security.capability`
// ---------------------------------------------------------------------------

/// Magia y version del formato `vfs_cap_data` del nucleo.
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
/// Version 2: dos palabras por conjunto. Es la que escribe `setcap` desde 2008.
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
/// Version 3: como la 2 mas el uid del espacio de nombres al final.
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
/// Bit de "efectivo" en la cabecera de magia.
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;

/// Las capacidades que lleva un fichero en su atributo extendido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapacidadesDeFichero {
    /// Mascara de capacidades permitidas.
    pub permitidas: u64,
    /// Mascara de capacidades heredables.
    pub heredables: u64,
    /// Si las permitidas se activan de forma efectiva al ejecutar.
    pub efectivas: bool,
}

/// Decodifica el contenido binario de `security.capability`.
///
/// El formato es `struct vfs_cap_data` del nucleo: una palabra de magia con la
/// version y el bit de efectivo, y luego dos palabras (permitido, heredable) por
/// cada una de las dos mitades de la mascara de 64 bits, todo en little-endian
/// con independencia de la maquina. Devuelve `None` ante cualquier cosa que no
/// case exactamente, porque un atributo malformado en un binario es justo lo que
/// pondria un atacante para confundir a un analizador permisivo.
pub fn decodificar_capacidades(bytes: &[u8]) -> Option<CapacidadesDeFichero> {
    if bytes.len() < 12 {
        return None;
    }
    let magia = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = magia & VFS_CAP_REVISION_MASK;
    let esperado = match version {
        VFS_CAP_REVISION_2 => 20,
        VFS_CAP_REVISION_3 => 24,
        _ => return None,
    };
    if bytes.len() != esperado {
        return None;
    }
    let permitido_bajo = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as u64;
    let heredable_bajo = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as u64;
    let permitido_alto = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as u64;
    let heredable_alto = u32::from_le_bytes(bytes[16..20].try_into().ok()?) as u64;

    Some(CapacidadesDeFichero {
        permitidas: permitido_bajo | (permitido_alto << 32),
        heredables: heredable_bajo | (heredable_alto << 32),
        efectivas: magia & VFS_CAP_FLAGS_EFFECTIVE != 0,
    })
}

// ---------------------------------------------------------------------------
// Decodificacion de ACL POSIX
// ---------------------------------------------------------------------------

/// Version del formato de ACL POSIX en disco.
const ACL_EA_VERSION: u32 = 0x0002;

/// Tipo de entrada de una ACL POSIX, tal y como lo define `acl/libacl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoEntradaAcl {
    /// El dueno del fichero.
    DuenoUsuario,
    /// Un usuario nombrado.
    Usuario(u32),
    /// El grupo del fichero.
    DuenoGrupo,
    /// Un grupo nombrado.
    Grupo(u32),
    /// La mascara que acota a los nombrados.
    Mascara,
    /// Todos los demas.
    Otros,
}

/// Una entrada de una ACL POSIX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntradaAcl {
    /// A quien aplica.
    pub tipo: TipoEntradaAcl,
    /// Permisos: bit 2 lectura, bit 1 escritura, bit 0 ejecucion.
    pub permisos: u16,
}

impl EntradaAcl {
    /// Los permisos en la forma `rwx` de siempre.
    pub fn rwx(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.permisos & 0b100 != 0 { 'r' } else { '-' });
        s.push(if self.permisos & 0b010 != 0 { 'w' } else { '-' });
        s.push(if self.permisos & 0b001 != 0 { 'x' } else { '-' });
        s
    }

    /// El nombre de a quien aplica, en la forma de `getfacl`.
    pub fn quien(&self) -> String {
        match self.tipo {
            TipoEntradaAcl::DuenoUsuario => "user::".to_string(),
            TipoEntradaAcl::Usuario(uid) => format!("user:{uid}:"),
            TipoEntradaAcl::DuenoGrupo => "group::".to_string(),
            TipoEntradaAcl::Grupo(gid) => format!("group:{gid}:"),
            TipoEntradaAcl::Mascara => "mask::".to_string(),
            TipoEntradaAcl::Otros => "other::".to_string(),
        }
    }
}

/// Decodifica el contenido binario de una ACL POSIX.
///
/// Formato: una palabra de version, y luego entradas de ocho bytes —etiqueta de
/// 16 bits, permisos de 16 bits, identificador de 32 bits—, todo little-endian.
/// Como en las capacidades, cualquier desviacion devuelve `None` en vez de
/// interpretar a medias.
pub fn decodificar_acl(bytes: &[u8]) -> Option<Vec<EntradaAcl>> {
    if bytes.len() < 4 {
        return None;
    }
    if u32::from_le_bytes(bytes[0..4].try_into().ok()?) != ACL_EA_VERSION {
        return None;
    }
    let cuerpo = &bytes[4..];
    if cuerpo.len() % 8 != 0 {
        return None;
    }
    let mut salida = Vec::with_capacity(cuerpo.len() / 8);
    for trozo in cuerpo.chunks_exact(8) {
        let etiqueta = u16::from_le_bytes(trozo[0..2].try_into().ok()?);
        let permisos = u16::from_le_bytes(trozo[2..4].try_into().ok()?);
        let id = u32::from_le_bytes(trozo[4..8].try_into().ok()?);
        let tipo = match etiqueta {
            0x01 => TipoEntradaAcl::DuenoUsuario,
            0x02 => TipoEntradaAcl::Usuario(id),
            0x04 => TipoEntradaAcl::DuenoGrupo,
            0x08 => TipoEntradaAcl::Grupo(id),
            0x10 => TipoEntradaAcl::Mascara,
            0x20 => TipoEntradaAcl::Otros,
            _ => return None,
        };
        salida.push(EntradaAcl { tipo, permisos });
    }
    Some(salida)
}

/// Nombre del atributo que guarda la ACL de acceso.
pub const ACL_ACCESO: &str = "system.posix_acl_access";
/// Nombre del atributo que guarda la ACL por defecto de un directorio.
pub const ACL_DEFECTO: &str = "system.posix_acl_default";
/// Nombre del atributo que guarda las capacidades de un fichero.
pub const CAPACIDADES: &str = "security.capability";

/// Indica si un nombre de atributo es de los que no se deben difundir.
///
/// `security.*` y `trusted.*` pueden llevar material sensible —el contexto de
/// confinamiento, claves de cifrado por fichero—, asi que el consumidor tiene
/// que poder distinguirlos sin volver a escribir esta lista.
pub fn es_sensible(nombre: &str) -> bool {
    nombre.starts_with("trusted.") || nombre.starts_with("security.evm")
}

/// Ruta de un `OsStr`, para quien tenga el nombre y no el `Path`.
pub fn ruta_de(nombre: &OsStr) -> &Path {
    Path::new(nombre)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::io::Write;

    #[test]
    fn un_fichero_normal_no_tiene_atributos_y_eso_no_es_un_error() {
        let mut f = tempfile_en("/tmp/aegis-xattr-normal");
        writeln!(f, "hola").unwrap();
        let ruta = Path::new("/tmp/aegis-xattr-normal");
        let n = nombres(ruta).expect("listar no deberia fallar");
        assert!(
            n.is_empty(),
            "un fichero recien creado no tiene xattrs: {n:?}"
        );
        let _ = std::fs::remove_file(ruta);
    }

    #[test]
    fn un_fichero_que_no_existe_da_no_existe() {
        match nombres(Path::new("/tmp/aegis-xattr-no-existe-jamas")) {
            Err(XattrError::NoExiste) => {}
            otro => panic!("se esperaba NoExiste, salio {otro:?}"),
        }
    }

    #[test]
    fn un_atributo_ausente_no_es_un_fallo_del_sistema() {
        let mut f = tempfile_en("/tmp/aegis-xattr-sin-cap");
        writeln!(f, "hola").unwrap();
        let ruta = Path::new("/tmp/aegis-xattr-sin-cap");
        assert!(!tiene_capacidades(ruta));
        let _ = std::fs::remove_file(ruta);
    }

    #[test]
    fn las_capacidades_de_fichero_se_decodifican() {
        // `vfs_cap_data` version 2 con CAP_NET_RAW (bit 13) permitida y
        // efectiva, construido a mano tal y como lo escribiria `setcap`.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE).to_le_bytes());
        bytes.extend_from_slice(&(1u32 << 13).to_le_bytes()); // permitido bajo
        bytes.extend_from_slice(&0u32.to_le_bytes()); // heredable bajo
        bytes.extend_from_slice(&0u32.to_le_bytes()); // permitido alto
        bytes.extend_from_slice(&0u32.to_le_bytes()); // heredable alto

        let c = decodificar_capacidades(&bytes).expect("v2 valida");
        assert_eq!(c.permitidas, 1 << 13);
        assert_eq!(c.heredables, 0);
        assert!(c.efectivas);
    }

    #[test]
    fn las_capacidades_altas_no_se_pierden() {
        // CAP_BPF es el bit 39: cae en la palabra ALTA. Un decodificador que
        // solo mire la baja diria que el binario no tiene capacidades, que es
        // precisamente lo que un atacante querria.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&VFS_CAP_REVISION_2.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(1u32 << 7).to_le_bytes()); // bit 39 = 32 + 7
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let c = decodificar_capacidades(&bytes).expect("v2 valida");
        assert_eq!(c.permitidas, 1u64 << 39);
        assert!(!c.efectivas);
    }

    #[test]
    fn un_atributo_de_capacidades_malformado_se_rechaza_entero() {
        // Ni version desconocida, ni longitud rara, ni vacio se interpretan a
        // medias: un binario con un xattr preparado no puede colarse como si
        // no tuviera capacidades.
        assert!(decodificar_capacidades(&[]).is_none());
        assert!(decodificar_capacidades(&[0u8; 12]).is_none());
        let mut corto = Vec::new();
        corto.extend_from_slice(&VFS_CAP_REVISION_2.to_le_bytes());
        corto.extend_from_slice(&[0u8; 8]);
        assert!(
            decodificar_capacidades(&corto).is_none(),
            "longitud v2 mala"
        );
    }

    #[test]
    fn la_version_3_se_acepta_con_su_longitud() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&VFS_CAP_REVISION_3.to_le_bytes());
        bytes.extend_from_slice(&(1u32 << 21).to_le_bytes()); // CAP_SYS_ADMIN
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // uid del espacio
        let c = decodificar_capacidades(&bytes).expect("v3 valida");
        assert_eq!(c.permitidas, 1 << 21);
    }

    #[test]
    fn una_acl_posix_se_decodifica_entrada_a_entrada() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ACL_EA_VERSION.to_le_bytes());
        // user:: rw-
        bytes.extend_from_slice(&0x01u16.to_le_bytes());
        bytes.extend_from_slice(&0b110u16.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        // user:1000: r--
        bytes.extend_from_slice(&0x02u16.to_le_bytes());
        bytes.extend_from_slice(&0b100u16.to_le_bytes());
        bytes.extend_from_slice(&1000u32.to_le_bytes());
        // other:: ---
        bytes.extend_from_slice(&0x20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        let acl = decodificar_acl(&bytes).expect("acl valida");
        assert_eq!(acl.len(), 3);
        assert_eq!(acl[0].tipo, TipoEntradaAcl::DuenoUsuario);
        assert_eq!(acl[0].rwx(), "rw-");
        assert_eq!(acl[1].tipo, TipoEntradaAcl::Usuario(1000));
        assert_eq!(acl[1].quien(), "user:1000:");
        assert_eq!(acl[1].rwx(), "r--");
        assert_eq!(acl[2].tipo, TipoEntradaAcl::Otros);
        assert_eq!(acl[2].rwx(), "---");
    }

    #[test]
    fn una_acl_malformada_se_rechaza() {
        assert!(decodificar_acl(&[]).is_none());
        // Version equivocada.
        let mut mala = Vec::new();
        mala.extend_from_slice(&99u32.to_le_bytes());
        assert!(decodificar_acl(&mala).is_none());
        // Longitud que no es multiplo de ocho.
        let mut corta = Vec::new();
        corta.extend_from_slice(&ACL_EA_VERSION.to_le_bytes());
        corta.extend_from_slice(&[0u8; 5]);
        assert!(decodificar_acl(&corta).is_none());
        // Etiqueta desconocida.
        let mut rara = Vec::new();
        rara.extend_from_slice(&ACL_EA_VERSION.to_le_bytes());
        rara.extend_from_slice(&0x77u16.to_le_bytes());
        rara.extend_from_slice(&0u16.to_le_bytes());
        rara.extend_from_slice(&0u32.to_le_bytes());
        assert!(decodificar_acl(&rara).is_none());
    }

    #[test]
    fn se_reconocen_los_atributos_que_no_se_deben_difundir() {
        assert!(es_sensible("trusted.algo"));
        assert!(es_sensible("security.evm"));
        assert!(!es_sensible("user.comentario"));
        assert!(!es_sensible("security.selinux"));
    }

    /// Crea un fichero de prueba, fallando con un mensaje util si no se puede.
    fn tempfile_en(ruta: &str) -> std::fs::File {
        std::fs::File::create(ruta)
            .unwrap_or_else(|e| panic!("no se pudo crear {ruta} para la prueba: {e}"))
    }
}
