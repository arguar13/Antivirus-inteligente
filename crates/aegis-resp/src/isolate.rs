//! Aislamiento de red del host.
//!
//! # La regla que gobierna el modulo
//!
//! **Todas las reglas viven en una tabla propia, `aegiscore`, y jamas se toca
//! nada fuera de ella.** Aislar y despues liberar tiene que devolver el sistema
//! EXACTAMENTE al estado anterior. Un producto de seguridad que reescribe el
//! cortafuegos del cliente y no sabe deshacerlo con precision es peor que no
//! aislar: deja la maquina en un estado que nadie sabe reconstruir.
//!
//! Borrar la tabla propia restaura el estado previo de forma exacta, sin
//! necesidad de recordar ni reproducir la configuracion anterior.
//!
//! # La lista de permitidos que evita el desastre operativo
//!
//! Aislar un endpoint comprometido y perder el acceso remoto a el es un error
//! clasico y caro: el equipo queda inalcanzable justo cuando hay que
//! investigarlo. El aislamiento preserva por defecto:
//!
//! - El trafico del propio agente hacia la nube, o se pierde la telemetria
//!   justo del incidente.
//! - DNS hacia los resolutores configurados; sin el, hasta el propio agente
//!   falla al resolver.
//! - DHCP, o el equipo pierde la IP y se vuelve inalcanzable de todos modos.
//! - El rango de administracion, para que el operador pueda entrar.
//!
//! El aislamiento TOTAL existe como modo aparte y avisa de que el equipo
//! quedara inalcanzable.
//!
//! # Limitacion conocida
//!
//! Las reglas afectan a las conexiones NUEVAS. Un canal de mando y control ya
//! establecido sigue funcionando hasta que se corta explicitamente. Es la misma
//! distincion que en Windows entre un filtro WFP y abortar un flujo, y se
//! resuelve igual: terminando los sockets vivos ademas de instalar las reglas.

use std::net::IpAddr;
use std::process::Command;

/// Nombre de la tabla nftables propia. Nunca se toca nada fuera de ella.
pub const TABLE: &str = "aegiscore";

/// Error del aislamiento.
#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    /// No se encontro la herramienta de cortafuegos.
    #[error("no se encontro 'nft' en el sistema; el aislamiento necesita nftables")]
    ToolMissing,

    /// La herramienta devolvio error.
    #[error("nft fallo ({code}): {stderr}")]
    ToolFailed {
        /// Codigo de salida.
        code: i32,
        /// Salida de error.
        stderr: String,
    },

    /// Error al ejecutar el proceso.
    #[error("no se pudo ejecutar nft: {0}")]
    Spawn(#[from] std::io::Error),
}

/// Politica de aislamiento.
#[derive(Debug, Clone)]
pub struct IsolationPolicy {
    /// Permitir DNS hacia los resolutores indicados.
    pub dns_servers: Vec<IpAddr>,
    /// Permitir DHCP (puertos 67 y 68).
    pub allow_dhcp: bool,
    /// Rangos desde y hacia los que se permite administracion, en notacion CIDR.
    pub admin_cidrs: Vec<String>,
    /// Puertos de salida que el agente necesita para hablar con la nube.
    pub agent_ports: Vec<u16>,
    /// Permitir trafico de bucle local.
    ///
    /// Bloquearlo rompe casi todo el software de la maquina, incluida la
    /// comunicacion entre el agente y su interfaz.
    pub allow_loopback: bool,
    /// Permitir conexiones ya establecidas.
    ///
    /// A `false` corta tambien las sesiones vivas, incluido cualquier SSH
    /// abierto contra la maquina.
    pub allow_established: bool,
}

impl IsolationPolicy {
    /// Politica de contencion con acceso de administracion preservado.
    ///
    /// Es el valor por defecto correcto: contiene la amenaza sin dejar la
    /// maquina inalcanzable.
    pub fn containment() -> IsolationPolicy {
        IsolationPolicy {
            dns_servers: read_resolvers(),
            allow_dhcp: true,
            admin_cidrs: Vec::new(),
            agent_ports: vec![443],
            allow_loopback: true,
            // Se preservan las sesiones establecidas para no expulsar al
            // operador que ya esta conectado investigando.
            allow_established: true,
        }
    }

    /// Aislamiento total: nada entra ni sale salvo el bucle local.
    ///
    /// **El equipo quedara inalcanzable por red.** Solo debe usarse con acceso
    /// fisico o por consola fuera de banda.
    pub fn total() -> IsolationPolicy {
        IsolationPolicy {
            dns_servers: Vec::new(),
            allow_dhcp: false,
            admin_cidrs: Vec::new(),
            agent_ports: Vec::new(),
            allow_loopback: true,
            allow_established: false,
        }
    }

    /// Indica si la politica deja alguna via de administracion.
    pub fn leaves_admin_path(&self) -> bool {
        !self.admin_cidrs.is_empty() || self.allow_established
    }
}

/// Lee los resolutores de `/etc/resolv.conf`.
pub fn read_resolvers() -> Vec<IpAddr> {
    let Ok(txt) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolvers(&txt)
}

/// Analiza el contenido de un `resolv.conf`.
pub fn parse_resolvers(texto: &str) -> Vec<IpAddr> {
    texto
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') || l.starts_with(';') {
                return None;
            }
            let mut it = l.split_whitespace();
            if it.next()? != "nameserver" {
                return None;
            }
            it.next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

/// Genera el conjunto de reglas nftables de la politica.
///
/// Es una funcion PURA: no toca el sistema. Eso permite revisar y probar
/// exactamente lo que se va a aplicar antes de aplicarlo, que en algo capaz de
/// dejar una maquina incomunicada no es un lujo.
pub fn build_ruleset(policy: &IsolationPolicy) -> String {
    let mut s = String::new();

    // Se borra la tabla propia si existiera, para que aplicar dos veces sea
    // idempotente. `destroy` no falla si no existe; `delete` si.
    s.push_str(&format!("table inet {TABLE} {{}}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));

    for (cadena, hook) in [("entrada", "input"), ("salida", "output")] {
        // Prioridad -150: por delante de filter (0) para que nuestras reglas
        // decidan antes que cualquier regla existente, sin modificarlas.
        s.push_str(&format!(
            "  chain {cadena} {{\n    type filter hook {hook} priority -150; policy drop;\n"
        ));

        if policy.allow_loopback {
            s.push_str("    iif lo accept\n");
            s.push_str("    oif lo accept\n");
        }
        if policy.allow_established {
            s.push_str("    ct state established,related accept\n");
        }
        if policy.allow_dhcp {
            s.push_str("    udp sport 67 udp dport 68 accept\n");
            s.push_str("    udp sport 68 udp dport 67 accept\n");
        }
        for dns in &policy.dns_servers {
            let campo = if hook == "output" { "daddr" } else { "saddr" };
            let familia = if dns.is_ipv4() { "ip" } else { "ip6" };
            s.push_str(&format!(
                "    {familia} {campo} {dns} udp dport 53 accept\n"
            ));
            s.push_str(&format!(
                "    {familia} {campo} {dns} tcp dport 53 accept\n"
            ));
        }
        for cidr in &policy.admin_cidrs {
            let campo = if hook == "output" { "daddr" } else { "saddr" };
            let familia = if cidr.contains(':') { "ip6" } else { "ip" };
            s.push_str(&format!("    {familia} {campo} {cidr} accept\n"));
        }
        if hook == "output" {
            for p in &policy.agent_ports {
                s.push_str(&format!("    tcp dport {p} accept\n"));
            }
        }
        // Contador del trafico bloqueado: sin el, nadie sabe si el aislamiento
        // esta conteniendo algo o si el proceso ya habia terminado.
        s.push_str("    counter\n");
        s.push_str("  }\n");
    }

    s.push_str("}\n");
    s
}

/// Estado del aislamiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationStatus {
    /// La tabla propia esta instalada.
    Isolated,
    /// No hay aislamiento activo.
    Released,
}

/// Motor de aislamiento.
#[derive(Debug, Default)]
pub struct Isolator {
    /// Si esta activo, no se ejecuta nada: solo se genera el conjunto de reglas.
    pub dry_run: bool,
}

impl Isolator {
    /// Crea un motor que aplica los cambios de verdad.
    pub fn new() -> Isolator {
        Isolator { dry_run: false }
    }

    /// Crea un motor que solo genera reglas, sin tocar el sistema.
    pub fn dry_run() -> Isolator {
        Isolator { dry_run: true }
    }

    fn nft(&self, args: &[&str], stdin: Option<&str>) -> Result<String, IsolationError> {
        if self.dry_run {
            return Ok(String::new());
        }
        let mut cmd = Command::new("nft");
        cmd.args(args);
        cmd.stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut hijo = match cmd.spawn() {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(IsolationError::ToolMissing)
            }
            Err(e) => return Err(IsolationError::Spawn(e)),
        };

        if let Some(texto) = stdin {
            use std::io::Write;
            if let Some(mut w) = hijo.stdin.take() {
                w.write_all(texto.as_bytes())?;
            }
        }

        let salida = hijo.wait_with_output()?;
        if !salida.status.success() {
            return Err(IsolationError::ToolFailed {
                code: salida.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&salida.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
    }

    /// Aplica el aislamiento.
    ///
    /// Devuelve el conjunto de reglas aplicado, para poder registrarlo: un
    /// cambio de red de este calibre tiene que quedar por escrito.
    pub fn isolate(&self, policy: &IsolationPolicy) -> Result<String, IsolationError> {
        let reglas = build_ruleset(policy);
        // Todo el conjunto se aplica en UNA transaccion. Aplicarlo por partes
        // dejaria ventanas en las que la maquina esta a medio aislar, que es
        // peor que cualquiera de los dos estados completos.
        self.nft(&["-f", "-"], Some(&reglas))?;
        Ok(reglas)
    }

    /// Retira el aislamiento devolviendo el sistema al estado anterior.
    pub fn release(&self) -> Result<(), IsolationError> {
        match self.nft(&["delete", "table", "inet", TABLE], None) {
            Ok(_) => Ok(()),
            // Que la tabla no exista significa que no habia aislamiento: el
            // resultado deseado ya se cumple, asi que no es un error.
            Err(IsolationError::ToolFailed { stderr, .. })
                if stderr.contains("No such file")
                    || stderr.contains("does not exist")
                    || stderr.contains("No such") =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Consulta si el aislamiento esta activo.
    pub fn status(&self) -> Result<IsolationStatus, IsolationError> {
        match self.nft(&["list", "table", "inet", TABLE], None) {
            Ok(_) => Ok(IsolationStatus::Isolated),
            Err(IsolationError::ToolFailed { .. }) => Ok(IsolationStatus::Released),
            Err(e) => Err(e),
        }
    }
}
