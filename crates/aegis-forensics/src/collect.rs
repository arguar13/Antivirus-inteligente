//! Recogida automatica de artefactos.
//!
//! Todo lo que se lee viene de la capa de abstraccion o de `procfs`, y **nada
//! detiene al proceso**: parar a un sospechoso es observable por el —que es como
//! el malware descubre que lo estan mirando— y ademas congela algo que todavia
//! puede resultar legitimo.
//!
//! # Todos los limites son explicitos
//!
//! Una recogida sin cotas es una denegacion de servicio contra el propio agente:
//! un arbol de mil procesos con diez mil sockets produciria un informe que no
//! cabe en el registro de auditoria y una pausa larguisima en mitad de un
//! incidente. Cada limite esta en [`CollectConfig`] y lo que se deja fuera se
//! anota en `gaps`, nunca se descarta en silencio.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use aegis_scal::memory::RegionClass;
use aegis_scal::process::ProcessLifecycleProvider;

use crate::artifacts::{
    IncidentArtifacts, MemoryArtifact, ProcessArtifact, RegionArtifact, SocketArtifact,
    SocketProto, Trigger,
};
use crate::dump::{DumpPolicy, MemoryDump};
use crate::report::ForensicReport;
use crate::tiempo;

/// Limites de la recogida.
#[derive(Debug, Clone, Copy)]
pub struct CollectConfig {
    /// Procesos maximos del arbol.
    pub max_processes: usize,
    /// Profundidad maxima de descendientes.
    pub max_depth: u16,
    /// Sockets maximos.
    pub max_sockets: usize,
    /// Regiones anonimas ejecutables que se listan.
    pub max_regions: usize,
    /// Tamano maximo de binario que se hashea.
    ///
    /// Hashear un binario de 500 MB en mitad de un incidente cuesta segundos de
    /// E/S. Los binarios de malware son pequenos; los enormes son motores de
    /// bases de datos y navegadores, cuya identidad ya se conoce.
    pub max_hash_bytes: u64,
    /// Si es cierto, se vuelca y analiza la memoria del proceso raiz.
    pub inspect_memory: bool,
}

impl Default for CollectConfig {
    fn default() -> Self {
        Self {
            max_processes: 64,
            max_depth: 8,
            max_sockets: 256,
            max_regions: 64,
            max_hash_bytes: 128 * 1024 * 1024,
            inspect_memory: true,
        }
    }
}

/// Recolector de artefactos.
#[derive(Debug)]
pub struct Collector<P: ProcessLifecycleProvider> {
    provider: P,
    config: CollectConfig,
}

impl<P: ProcessLifecycleProvider> Collector<P> {
    /// Crea el recolector.
    pub fn new(provider: P, config: CollectConfig) -> Collector<P> {
        Collector { provider, config }
    }

    /// Recoge todo lo que se pueda sobre el incidente centrado en `pid`.
    ///
    /// No falla: lo que no se pueda leer se anota en `gaps`. Abortar la recogida
    /// entera porque un proceso murio a mitad dejaria sin evidencia un incidente
    /// del que si se pudo capturar casi todo.
    pub fn collect(&self, pid: u32, trigger: Trigger) -> IncidentArtifacts {
        let mut gaps = Vec::new();
        let procesos = self.arbol(pid, &mut gaps);
        let sockets = self.sockets(&procesos, &mut gaps);
        let memory = if self.config.inspect_memory {
            self.memoria(pid, &mut gaps)
        } else {
            MemoryArtifact::default()
        };

        let mut a = IncidentArtifacts {
            id: String::new(),
            collected_at: tiempo::ahora(),
            trigger,
            root_pid: pid,
            processes: procesos,
            sockets,
            memory,
            gaps,
        };
        a.id = identificador(&a);
        a
    }

    /// Arbol de procesos: la raiz y sus descendientes, en anchura.
    fn arbol(&self, raiz: u32, gaps: &mut Vec<String>) -> Vec<ProcessArtifact> {
        let mut salida = Vec::new();
        let mut vistos: HashSet<u32> = HashSet::new();
        let mut cola = vec![(raiz, 0u16)];

        while let Some((pid, prof)) = cola.pop() {
            if salida.len() >= self.config.max_processes {
                gaps.push(format!(
                    "el arbol se corto en {} procesos por el limite de la recogida",
                    self.config.max_processes
                ));
                break;
            }
            if !vistos.insert(pid) {
                continue;
            }
            match self.provider.info(pid) {
                Ok(i) => {
                    let (sha, tam) = match &i.image {
                        Some(p) => self.hash_imagen(p, gaps),
                        None => (None, None),
                    };
                    salida.push(ProcessArtifact {
                        pid: i.key.pid,
                        ppid: i.parent_pid,
                        start_stamp: i.key.start_stamp,
                        image: i.image.clone(),
                        cmdline: i.cmdline.clone(),
                        uid: i.uid,
                        sha256: sha,
                        image_size: tam,
                    });
                }
                Err(e) => {
                    // Que un proceso desaparezca a mitad es lo normal en un
                    // incidente vivo, y es informacion: consta en el informe.
                    gaps.push(format!("no se pudo retratar el proceso {pid}: {e}"));
                    continue;
                }
            }
            if prof >= self.config.max_depth {
                continue;
            }
            match self.provider.children_of(pid) {
                Ok(hijos) => cola.extend(hijos.into_iter().map(|h| (h, prof + 1))),
                Err(e) => gaps.push(format!("no se pudieron enumerar los hijos de {pid}: {e}")),
            }
        }
        salida
    }

    /// SHA-256 del binario, con el tamano.
    fn hash_imagen(&self, ruta: &Path, gaps: &mut Vec<String>) -> (Option<String>, Option<u64>) {
        let meta = match std::fs::metadata(ruta) {
            Ok(m) => m,
            Err(_) => {
                // Un binario que ya no esta en disco no es un fallo: es un dato.
                // Significa que el proceso se borro a si mismo.
                gaps.push(format!(
                    "el binario {} ya no esta en disco: la evidencia se destruyo",
                    ruta.display()
                ));
                return (None, None);
            }
        };
        let tam = meta.len();
        if tam > self.config.max_hash_bytes {
            gaps.push(format!(
                "{} ocupa {tam} bytes y supera el limite de hasheo",
                ruta.display()
            ));
            return (None, Some(tam));
        }
        match sha256_fichero(ruta) {
            Ok(h) => (Some(h), Some(tam)),
            Err(e) => {
                gaps.push(format!("no se pudo hashear {}: {e}", ruta.display()));
                (None, Some(tam))
            }
        }
    }

    /// Sockets abiertos por los procesos del arbol.
    fn sockets(&self, procesos: &[ProcessArtifact], gaps: &mut Vec<String>) -> Vec<SocketArtifact> {
        // Las tablas de `/proc/net` se leen UNA vez y se indexan por inodo. Un
        // arbol de cincuenta procesos las releeria cincuenta veces, y cada una
        // son miles de lineas en una maquina con carga.
        let mut tablas = Vec::new();
        for proto in [
            SocketProto::Tcp,
            SocketProto::Tcp6,
            SocketProto::Udp,
            SocketProto::Udp6,
        ] {
            match std::fs::read_to_string(format!("/proc/net/{}", proto.procfile())) {
                Ok(t) => tablas.push((proto, parse_proc_net(&t, proto))),
                Err(_) => {
                    // Un contenedor sin IPv6 no tiene `tcp6`: no es un fallo.
                }
            }
        }

        let mut salida = Vec::new();
        for p in procesos {
            if salida.len() >= self.config.max_sockets {
                gaps.push(format!(
                    "la lista de sockets se corto en {}",
                    self.config.max_sockets
                ));
                break;
            }
            let inodos = match inodos_de_socket(p.pid) {
                Ok(i) => i,
                Err(e) => {
                    gaps.push(format!("no se pudieron leer los sockets de {}: {e}", p.pid));
                    continue;
                }
            };
            for (_, entradas) in &tablas {
                for e in entradas {
                    if inodos.contains(&e.inode) && salida.len() < self.config.max_sockets {
                        salida.push(SocketArtifact {
                            pid: p.pid,
                            ..e.clone()
                        });
                    }
                }
            }
        }
        salida
    }

    /// Memoria del proceso raiz: regiones anonimas ejecutables y hallazgos.
    fn memoria(&self, pid: u32, gaps: &mut Vec<String>) -> MemoryArtifact {
        let regiones = match aegis_scan::memory::regions_of(pid as i32) {
            Ok(r) => r,
            Err(e) => {
                gaps.push(format!("no se pudo leer el mapa de memoria de {pid}: {e}"));
                return MemoryArtifact::default();
            }
        };

        let anon: Vec<RegionArtifact> = regiones
            .iter()
            .filter(|r| r.class() == RegionClass::AnonymousExec)
            .take(self.config.max_regions)
            .map(|r| RegionArtifact {
                start: r.start,
                len: r.len(),
                perms: format!(
                    "{}{}{}{}",
                    if r.perms.read { "r" } else { "-" },
                    if r.perms.write { "w" } else { "-" },
                    if r.perms.exec { "x" } else { "-" },
                    if r.perms.private { "p" } else { "s" }
                ),
                path: r.path.clone(),
            })
            .collect();

        let dump = match MemoryDump::capture(pid as i32, &DumpPolicy::default()) {
            Ok(d) => d,
            Err(e) => {
                gaps.push(format!("no se pudo volcar la memoria de {pid}: {e}"));
                return MemoryArtifact {
                    regions_total: regiones.len(),
                    anonymous_exec: anon,
                    bytes_read: 0,
                    findings: Vec::new(),
                };
            }
        };
        let informe = ForensicReport::analyze(pid as i32, &dump, &regiones);

        MemoryArtifact {
            regions_total: regiones.len(),
            anonymous_exec: anon,
            bytes_read: dump.total_bytes,
            findings: hallazgos(&informe),
        }
    }
}

/// Resume los hallazgos del analisis de exploits en frases legibles.
///
/// Se guardan como texto y no como estructuras porque su destino es un informe
/// STIX y una consola: lo que necesita el analista es "que se encontro y donde",
/// y el detalle binario ya no esta cuando lee el informe, porque la memoria del
/// proceso hace tiempo que se libero.
fn hallazgos(r: &ForensicReport) -> Vec<String> {
    let mut v = Vec::new();
    for h in &r.hooked_vtables {
        v.push(format!(
            "vtable secuestrada en el desplazamiento {:#x}: {} de {} entradas \
             apuntan a codigo anonimo",
            h.offset, h.anon_entries, h.entries
        ));
    }
    for p in &r.pivots {
        v.push(format!(
            "gadget de pivote de pila en el desplazamiento {:#x}: {}",
            p.offset, p.what
        ));
    }
    for s in &r.shellcode {
        v.push(format!(
            "firma de shellcode en el desplazamiento {:#x}: {}",
            s.offset, s.what
        ));
    }
    if v.is_empty() {
        v.push(format!(
            "sin hallazgos de exploit en {} bytes analizados",
            r.bytes_analyzed
        ));
    }
    v
}

/// Entrada de `/proc/net/{tcp,udp}` ya analizada.
///
/// El `pid` se rellena despues, al cruzarla con los descriptores del proceso:
/// `/proc/net` es global y no dice de quien es cada socket.
pub fn parse_proc_net(texto: &str, proto: SocketProto) -> Vec<SocketArtifact> {
    let mut salida = Vec::new();
    for linea in texto.lines().skip(1) {
        let c: Vec<&str> = linea.split_whitespace().collect();
        if c.len() < 10 {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_addr(c[1], proto), parse_addr(c[2], proto)) else {
            continue;
        };
        let Ok(inode) = c[9].parse::<u64>() else {
            continue;
        };
        salida.push(SocketArtifact {
            pid: 0,
            proto,
            local,
            remote,
            state: estado_tcp(c[3]),
            inode,
        });
    }
    salida
}

/// Analiza una direccion de `procfs` (`0100007F:1F90`).
///
/// Las direcciones vienen en hexadecimal y por palabras de 32 bits en el orden
/// de bytes del HOST, mientras que el PUERTO viene en orden de red. Mezclar los
/// dos criterios es el error clasico de este analizador y produce direcciones
/// invertidas que no corresponden a nada.
pub fn parse_addr(campo: &str, proto: SocketProto) -> Option<std::net::SocketAddr> {
    let (dir, puerto) = campo.split_once(':')?;
    let puerto = u16::from_str_radix(puerto, 16).ok()?;

    match proto {
        SocketProto::Tcp | SocketProto::Udp => {
            if dir.len() != 8 {
                return None;
            }
            let crudo = u32::from_str_radix(dir, 16).ok()?;
            let ip = std::net::Ipv4Addr::from(crudo.to_le_bytes());
            Some(std::net::SocketAddr::from((ip, puerto)))
        }
        SocketProto::Tcp6 | SocketProto::Udp6 => {
            if dir.len() != 32 {
                return None;
            }
            let mut bytes = [0u8; 16];
            // Cuatro palabras de 32 bits, cada una en el orden del host.
            for i in 0..4 {
                let palabra = u32::from_str_radix(&dir[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&palabra.to_le_bytes());
            }
            let ip = std::net::Ipv6Addr::from(bytes);
            Some(std::net::SocketAddr::from((ip, puerto)))
        }
    }
}

/// Traduce el estado hexadecimal de `procfs` al nombre habitual.
pub fn estado_tcp(codigo: &str) -> &'static str {
    match codigo {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Inodos de los sockets que un proceso tiene abiertos.
///
/// Se leen de `/proc/<pid>/fd`, donde cada socket aparece como un enlace a
/// `socket:[<inodo>]`. Es la unica forma de atribuir a un proceso las entradas
/// de `/proc/net`, que son globales.
pub fn inodos_de_socket(pid: u32) -> Result<HashSet<u64>, std::io::Error> {
    let mut salida = HashSet::new();
    for e in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let Ok(e) = e else { continue };
        let Ok(destino) = std::fs::read_link(e.path()) else {
            // Un descriptor que se cierra mientras se enumera es normal.
            continue;
        };
        let s = destino.to_string_lossy();
        if let Some(resto) = s.strip_prefix("socket:[") {
            if let Some(n) = resto.strip_suffix(']') {
                if let Ok(i) = n.parse::<u64>() {
                    salida.insert(i);
                }
            }
        }
    }
    Ok(salida)
}

/// SHA-256 de un fichero, leido por trozos.
///
/// Por trozos y no de una vez: cargar en memoria un binario de cien megabytes
/// para hashearlo se saltaria el presupuesto de memoria del agente entero.
pub fn sha256_fichero(ruta: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(ruta)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Codifica bytes en hexadecimal minusculo.
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Identificador del incidente, derivado de su contenido.
///
/// Deterministico a proposito: dos agentes que recojan el mismo incidente
/// producen el mismo identificador, de modo que la consola puede deduplicar sin
/// tener que comparar informes enteros.
fn identificador(a: &IncidentArtifacts) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(a.trigger.source.as_bytes());
    h.update(a.trigger.reason.as_bytes());
    h.update(a.root_pid.to_le_bytes());
    for p in &a.processes {
        h.update(p.pid.to_le_bytes());
        h.update(p.start_stamp.to_le_bytes());
        if let Some(s) = &p.sha256 {
            h.update(s.as_bytes());
        }
    }
    hex(&h.finalize()[..16])
}
