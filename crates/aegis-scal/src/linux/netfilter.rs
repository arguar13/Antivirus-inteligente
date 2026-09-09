//! Bloqueo de direcciones en Linux, sobre `nftables`.
//!
//! # Por que una tabla propia
//!
//! Todo lo que aplica este backend vive en la tabla `inet aegis_scal` y solo
//! ahi. Un motor de respuesta que anada reglas a las tablas del administrador
//! no puede retirarlas despues sin arriesgarse a borrar las de otro, y un
//! producto de seguridad que deja restos en el cortafuegos de una maquina tras
//! un falso positivo pierde la confianza del equipo que lo opera.
//!
//! # Por que un conjunto y no una regla por direccion
//!
//! Las reglas se evaluan en orden: mil direcciones bloqueadas serian mil
//! comparaciones por paquete. Un conjunto de nftables es una tabla hash en el
//! kernel, asi que el coste por paquete no crece con el numero de bloqueos, y
//! anadir o quitar una direccion no reescribe la cadena.
//!
//! # Por que caducidad en el elemento
//!
//! El propio kernel expira los elementos con `flags timeout`. Si la caducidad
//! la llevara el agente, un reinicio del agente dejaria bloqueos permanentes
//! que nadie recuerda haber puesto.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::ScalError;
use crate::netfilter::{BlockReason, BlockedAddress, NetworkFilter};
use crate::platform::Platform;

/// Nombre de la tabla propia del producto.
pub const TABLA: &str = "aegis_scal";
/// Conjunto de direcciones IPv4 bloqueadas.
pub const SET_V4: &str = "blk4";
/// Conjunto de direcciones IPv6 bloqueadas.
pub const SET_V6: &str = "blk6";

/// Conjunto de reglas que crea la tabla, los conjuntos y las cadenas.
///
/// Se emite entero en UNA transaccion de `nft -f -`, y esta escrito en forma
/// `add`/`flush chain` en vez de como un bloque `table { ... }`:
///
/// - `add` es idempotente, asi que arrancar dos veces no falla.
/// - `flush chain` vacia SOLO las cadenas antes de reponer sus reglas, de modo
///   que llamar a esto de nuevo no duplica reglas **y no toca los conjuntos**.
///   Un `flush table` habria borrado los bloqueos vigentes en cada arranque,
///   que es exactamente lo que un atacante querria provocar.
fn ruleset() -> String {
    format!(
        "add table inet {TABLA}\n\
         add set inet {TABLA} {SET_V4} {{ type ipv4_addr; flags timeout; }}\n\
         add set inet {TABLA} {SET_V6} {{ type ipv6_addr; flags timeout; }}\n\
         add chain inet {TABLA} ingress {{ type filter hook prerouting priority raw; policy accept; }}\n\
         add chain inet {TABLA} egress {{ type filter hook output priority raw; policy accept; }}\n\
         flush chain inet {TABLA} ingress\n\
         flush chain inet {TABLA} egress\n\
         add rule inet {TABLA} ingress ip saddr @{SET_V4} drop\n\
         add rule inet {TABLA} ingress ip6 saddr @{SET_V6} drop\n\
         add rule inet {TABLA} egress ip daddr @{SET_V4} drop\n\
         add rule inet {TABLA} egress ip6 daddr @{SET_V6} drop\n"
    )
}

/// Filtro de red de Linux.
#[derive(Debug, Clone, Copy, Default)]
pub struct NftablesFilter {
    /// Si esta activo, se genera el conjunto de reglas pero no se ejecuta nada.
    ///
    /// Existe para poder probar la generacion y el flujo de decision en
    /// maquinas sin privilegios, no para simular un bloqueo: `available()`
    /// devuelve `false` en este modo, de forma que ningun motor de respuesta
    /// pueda creer que ha contenido algo cuando no lo ha hecho.
    pub dry_run: bool,
}

impl NftablesFilter {
    /// Crea un filtro que aplica los cambios de verdad.
    pub const fn new() -> NftablesFilter {
        NftablesFilter { dry_run: false }
    }

    /// Crea un filtro que solo genera reglas.
    pub const fn dry_run() -> NftablesFilter {
        NftablesFilter { dry_run: true }
    }

    /// Conjunto de reglas que instala este filtro. Publico para poder
    /// auditarlo y probarlo sin tocar el sistema.
    pub fn ruleset(&self) -> String {
        ruleset()
    }

    fn nft(&self, args: &[&str], stdin: Option<&str>) -> Result<String, ScalError> {
        let mut cmd = Command::new("nft");
        cmd.args(args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut hijo = match cmd.spawn() {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScalError::MissingTool {
                    tool: "nft",
                    purpose: "bloquear direcciones en el cortafuegos",
                })
            }
            Err(source) => return Err(ScalError::Os { op: "nft", source }),
        };

        if let Some(texto) = stdin {
            use std::io::Write;
            if let Some(mut w) = hijo.stdin.take() {
                w.write_all(texto.as_bytes())
                    .map_err(|source| ScalError::Os { op: "nft", source })?;
            }
        }

        let salida = hijo
            .wait_with_output()
            .map_err(|source| ScalError::Os { op: "nft", source })?;
        if !salida.status.success() {
            return Err(ScalError::ToolFailed {
                tool: "nft",
                code: salida.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&salida.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
    }

    /// Crea la tabla, los conjuntos y las cadenas si no existen.
    ///
    /// Es idempotente y conserva los bloqueos ya aplicados.
    pub fn ensure(&self) -> Result<(), ScalError> {
        if self.dry_run {
            return Ok(());
        }
        self.nft(&["-f", "-"], Some(&ruleset()))?;
        Ok(())
    }

    fn set_de(addr: IpAddr) -> &'static str {
        match addr {
            IpAddr::V4(_) => SET_V4,
            IpAddr::V6(_) => SET_V6,
        }
    }
}

/// Indica si el error de `nft` significa "eso no existe", que para retirar algo
/// es exito y no fallo.
fn es_inexistente(e: &ScalError) -> bool {
    match e {
        ScalError::ToolFailed { stderr, .. } => {
            stderr.contains("No such file")
                || stderr.contains("does not exist")
                || stderr.contains("No such")
        }
        _ => false,
    }
}

/// Extrae los elementos de la salida de `nft list set`.
///
/// La salida trae el bloque `elements = { ... }`, que puede ocupar varias
/// lineas. Se localizan las llaves de ese bloque en vez de analizar linea a
/// linea porque nft parte los elementos donde le conviene segun el ancho.
pub fn parse_elements(salida: &str, por_defecto: BlockReason) -> Vec<BlockedAddress> {
    let Some(inicio) = salida.find("elements = {") else {
        return Vec::new();
    };
    let resto = &salida[inicio + "elements = {".len()..];
    let Some(fin) = resto.find('}') else {
        return Vec::new();
    };
    let cuerpo = &resto[..fin];

    let mut salida_v = Vec::new();
    for entrada in cuerpo.split(',') {
        let entrada = entrada.trim();
        if entrada.is_empty() {
            continue;
        }
        let mut it = entrada.split_whitespace();
        let Some(dir) = it.next() else { continue };
        let Ok(addr) = dir.parse::<IpAddr>() else {
            continue;
        };
        salida_v.push(BlockedAddress {
            addr,
            reason: parse_reason(entrada).unwrap_or(por_defecto),
            ttl: parse_timeout(entrada),
        });
    }
    salida_v
}

/// Recupera el motivo del comentario del elemento.
fn parse_reason(entrada: &str) -> Option<BlockReason> {
    let i = entrada.find("comment \"")? + "comment \"".len();
    let resto = &entrada[i..];
    let j = resto.find('"')?;
    match &resto[..j] {
        "recon" => Some(BlockReason::Reconnaissance),
        "lateral" => Some(BlockReason::LateralMovement),
        "c2" => Some(BlockReason::CommandAndControl),
        "intel" => Some(BlockReason::ThreatIntel),
        "manual" => Some(BlockReason::Manual),
        _ => None,
    }
}

/// Recupera la caducidad configurada del elemento.
///
/// nft imprime `timeout 10m expires 9m58s`: interesa el PRIMERO, que es la
/// caducidad pedida; `expires` es lo que queda y cambia en cada lectura.
fn parse_timeout(entrada: &str) -> Option<Duration> {
    let i = entrada.find("timeout ")? + "timeout ".len();
    let resto = &entrada[i..];
    let texto: String = resto.chars().take_while(|c| !c.is_whitespace()).collect();
    parse_duracion_nft(&texto)
}

/// Analiza una duracion en el formato de nft: `1d2h3m4s`, o `600s`.
pub fn parse_duracion_nft(texto: &str) -> Option<Duration> {
    let mut total: u64 = 0;
    let mut numero: u64 = 0;
    let mut visto = false;
    for c in texto.chars() {
        if let Some(d) = c.to_digit(10) {
            numero = numero.checked_mul(10)?.checked_add(d as u64)?;
            visto = true;
            continue;
        }
        let mult = match c {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        total = total.checked_add(numero.checked_mul(mult)?)?;
        numero = 0;
    }
    if !visto {
        return None;
    }
    // Un numero sin sufijo son segundos, que es como lo acepta nft.
    Some(Duration::from_secs(total + numero))
}

impl NetworkFilter for NftablesFilter {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn available(&self) -> bool {
        if self.dry_run {
            return false;
        }
        // No basta con que el binario exista: en un contenedor sin
        // CAP_NET_ADMIN, o con un kernel sin nf_tables, `nft` esta ahi y falla
        // al primer intento. Se comprueba con una operacion real y barata.
        self.nft(&["list", "tables"], None).is_ok()
    }

    fn block(
        &self,
        addr: IpAddr,
        reason: BlockReason,
        ttl: Option<Duration>,
    ) -> Result<(), ScalError> {
        if self.dry_run {
            return Ok(());
        }
        self.ensure()?;
        let plazo = match ttl {
            Some(d) => format!(" timeout {}s", d.as_secs().max(1)),
            None => String::new(),
        };
        // `addr` es un `IpAddr` ya analizado y `reason` un enumerado cerrado:
        // ninguno de los dos puede introducir texto arbitrario en el guion.
        let elemento = format!("{{ {addr}{plazo} comment \"{}\" }}", reason.as_str());
        let set = NftablesFilter::set_de(addr);
        self.nft(&["add", "element", "inet", TABLA, set, &elemento], None)?;
        Ok(())
    }

    fn unblock(&self, addr: IpAddr) -> Result<(), ScalError> {
        if self.dry_run {
            return Ok(());
        }
        let elemento = format!("{{ {addr} }}");
        let set = NftablesFilter::set_de(addr);
        match self.nft(&["delete", "element", "inet", TABLA, set, &elemento], None) {
            Ok(_) => Ok(()),
            // Que no estuviera bloqueada es el resultado deseado.
            Err(e) if es_inexistente(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError> {
        if self.dry_run {
            return Ok(Vec::new());
        }
        let mut todo = Vec::new();
        for set in [SET_V4, SET_V6] {
            match self.nft(&["list", "set", "inet", TABLA, set], None) {
                Ok(salida) => todo.extend(parse_elements(&salida, BlockReason::Manual)),
                // Sin tabla no hay bloqueos: lista vacia, no error.
                Err(e) if es_inexistente(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(todo)
    }

    fn flush(&self) -> Result<(), ScalError> {
        if self.dry_run {
            return Ok(());
        }
        match self.nft(&["delete", "table", "inet", TABLA], None) {
            Ok(_) => Ok(()),
            Err(e) if es_inexistente(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
