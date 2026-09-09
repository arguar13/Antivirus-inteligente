//! Comprobaciones de postura del host.
//!
//! Un CVE dice que tienes software con un fallo conocido. La postura dice que
//! tienes el sistema mal configurado, que es la via de compromiso mas comun y
//! la que ningun feed de vulnerabilidades detecta. Un `/etc/shadow` legible por
//! todos no aparece en ningun CVE y entrega la maquina entera.
//!
//! Todas las comprobaciones toman una raiz como parametro para poder
//! ejercitarse contra arboles de ficheros sinteticos. Un escaner de postura que
//! solo se puede probar modificando la maquina real, en la practica no se prueba.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::cve::Severity;
use crate::{Category, Finding};

/// Ejecuta todas las comprobaciones de postura.
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut f = Vec::new();
    check_file_permissions(root, &mut f);
    check_ld_preload(root, &mut f);
    check_sshd_config(root, &mut f);
    check_sysctl(root, &mut f);
    check_accounts(root, &mut f);
    check_world_writable_in_path(root, &mut f);
    check_suid_in_temp(root, &mut f);
    check_listening_ports(root, &mut f);
    f
}

fn leer(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel.trim_start_matches('/'))).ok()
}

// ---------------------------------------------------------------------------
// Permisos de ficheros sensibles
// ---------------------------------------------------------------------------

/// Ficheros cuyos permisos no pueden ser mas laxos que el maximo indicado.
///
/// El maximo se expresa como mascara de bits que NO deben estar puestos.
const PERMISOS_ESPERADOS: &[(&str, u32, Severity, &str)] = &[
    // Un /etc/shadow legible por otros entrega todos los hashes de la maquina
    // a cualquier usuario local, y de ahi a un ataque de diccionario offline.
    (
        "/etc/shadow",
        0o640,
        Severity::Critical,
        "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
    ),
    (
        "/etc/gshadow",
        0o640,
        Severity::High,
        "chmod 640 /etc/gshadow",
    ),
    (
        "/etc/passwd",
        0o644,
        Severity::Medium,
        "chmod 644 /etc/passwd",
    ),
    ("/etc/group", 0o644, Severity::Low, "chmod 644 /etc/group"),
    // Escribible por un no-root significa escalada inmediata a root.
    (
        "/etc/sudoers",
        0o440,
        Severity::Critical,
        "chmod 440 /etc/sudoers",
    ),
    (
        "/etc/ssh/sshd_config",
        0o600,
        Severity::Medium,
        "chmod 600 /etc/ssh/sshd_config",
    ),
    (
        "/etc/crontab",
        0o600,
        Severity::High,
        "chmod 600 /etc/crontab",
    ),
];

fn check_file_permissions(root: &Path, out: &mut Vec<Finding>) {
    for (rel, maximo, sev, remedio) in PERMISOS_ESPERADOS {
        let ruta = root.join(rel.trim_start_matches('/'));
        let Ok(md) = std::fs::metadata(&ruta) else {
            continue; // el fichero no existe en este sistema: no es un hallazgo
        };
        let modo = md.permissions().mode() & 0o7777;
        let excedente = modo & !maximo;
        if excedente != 0 {
            out.push(Finding {
                id: format!("AEGIS-PERM-{}", rel.replace('/', "-").trim_matches('-')),
                category: Category::Permissions,
                severity: *sev,
                title: format!("Permisos excesivos en {rel}"),
                evidence: format!(
                    "modo actual {:04o}, maximo admitido {:04o} (bits de mas: {:04o})",
                    modo, maximo, excedente
                ),
                remediation: remedio.to_string(),
            });
        }

        // Propietario distinto de root sobre un fichero del sistema es tan
        // grave como los permisos: quien lo posee puede cambiarlos.
        if md.uid() != 0 {
            out.push(Finding {
                id: format!("AEGIS-OWNER-{}", rel.replace('/', "-").trim_matches('-')),
                category: Category::Permissions,
                severity: Severity::High,
                title: format!("{rel} no pertenece a root"),
                evidence: format!("uid del propietario: {}", md.uid()),
                remediation: format!("chown root {rel}"),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Cargador dinamico
// ---------------------------------------------------------------------------

fn check_ld_preload(root: &Path, out: &mut Vec<Finding>) {
    let ruta = root.join("etc/ld.so.preload");
    let Ok(contenido) = std::fs::read_to_string(&ruta) else {
        return; // no existir es el estado correcto
    };
    let entradas: Vec<&str> = contenido
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if entradas.is_empty() {
        return;
    }

    // Una linea aqui inyecta una biblioteca en CADA proceso que arranque
    // despues, incluidos los de seguridad. Es la persistencia mas silenciosa
    // que existe en Linux y casi nunca tiene un uso legitimo.
    out.push(Finding {
        id: "AEGIS-LDPRELOAD-001".into(),
        category: Category::Persistence,
        severity: Severity::Critical,
        title: "/etc/ld.so.preload contiene bibliotecas precargadas".into(),
        evidence: entradas.join(", "),
        remediation: "Verificar cada entrada. Si no procede de software instalado a proposito, \
             vaciar el fichero y buscar el proceso que lo escribio."
            .into(),
    });
}

// ---------------------------------------------------------------------------
// Configuracion de SSH
// ---------------------------------------------------------------------------

/// Lee una directiva de sshd_config.
///
/// La ULTIMA aparicion gana, que es como sshd resuelve duplicados: comprobar
/// solo la primera es un error clasico que hace que un `PermitRootLogin yes`
/// anadido al final pase desapercibido.
fn directiva_sshd(config: &str, clave: &str) -> Option<String> {
    let mut valor = None;
    for linea in config.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut it = l.split_whitespace();
        let Some(k) = it.next() else { continue };
        if k.eq_ignore_ascii_case(clave) {
            valor = it.next().map(|v| v.to_ascii_lowercase());
        }
    }
    valor
}

fn check_sshd_config(root: &Path, out: &mut Vec<Finding>) {
    let Some(cfg) = leer(root, "/etc/ssh/sshd_config") else {
        return;
    };

    // PermitRootLogin: el valor por defecto de OpenSSH moderno es
    // prohibit-password, pero muchas imagenes lo cambian.
    match directiva_sshd(&cfg, "PermitRootLogin").as_deref() {
        Some("yes") => out.push(Finding {
            id: "AEGIS-SSH-001".into(),
            category: Category::Hardening,
            severity: Severity::High,
            title: "SSH permite iniciar sesion como root con contrasena".into(),
            evidence: "PermitRootLogin yes".into(),
            remediation: "Poner 'PermitRootLogin prohibit-password' o 'no' y recargar sshd".into(),
        }),
        None => out.push(Finding {
            id: "AEGIS-SSH-002".into(),
            category: Category::Hardening,
            severity: Severity::Low,
            title: "SSH no declara PermitRootLogin explicitamente".into(),
            evidence: "directiva ausente; se aplica el valor por defecto de la version instalada"
                .into(),
            remediation: "Declararla de forma explicita para no depender del valor por defecto"
                .into(),
        }),
        _ => {}
    }

    if directiva_sshd(&cfg, "PermitEmptyPasswords").as_deref() == Some("yes") {
        out.push(Finding {
            id: "AEGIS-SSH-003".into(),
            category: Category::Hardening,
            severity: Severity::Critical,
            title: "SSH acepta contrasenas vacias".into(),
            evidence: "PermitEmptyPasswords yes".into(),
            remediation: "Poner 'PermitEmptyPasswords no'".into(),
        });
    }

    if directiva_sshd(&cfg, "PasswordAuthentication").as_deref() == Some("yes") {
        out.push(Finding {
            id: "AEGIS-SSH-004".into(),
            category: Category::Hardening,
            severity: Severity::Medium,
            title: "SSH acepta autenticacion por contrasena".into(),
            evidence: "PasswordAuthentication yes".into(),
            remediation: "Migrar a claves y poner 'PasswordAuthentication no'".into(),
        });
    }
}

// ---------------------------------------------------------------------------
// Parametros del kernel
// ---------------------------------------------------------------------------

/// Parametro de kernel, valor minimo aceptable y por que importa.
struct Sysctl {
    ruta: &'static str,
    nombre: &'static str,
    minimo: i64,
    severidad: Severity,
    motivo: &'static str,
}

const SYSCTLS: &[Sysctl] = &[
    Sysctl {
        ruta: "/proc/sys/kernel/randomize_va_space",
        nombre: "kernel.randomize_va_space",
        minimo: 2,
        severidad: Severity::High,
        motivo: "ASLR completo. Sin el, las direcciones son predecibles y un desbordamiento \
                 se convierte en ejecucion de codigo fiable en vez de en un fallo",
    },
    Sysctl {
        ruta: "/proc/sys/kernel/kptr_restrict",
        nombre: "kernel.kptr_restrict",
        minimo: 1,
        severidad: Severity::Medium,
        motivo: "oculta las direcciones de kernel en /proc, que un exploit local usa para \
                 saltarse KASLR",
    },
    Sysctl {
        ruta: "/proc/sys/kernel/dmesg_restrict",
        nombre: "kernel.dmesg_restrict",
        minimo: 1,
        severidad: Severity::Low,
        motivo: "el buffer del kernel filtra direcciones y estado interno",
    },
    Sysctl {
        ruta: "/proc/sys/kernel/yama/ptrace_scope",
        nombre: "kernel.yama.ptrace_scope",
        minimo: 1,
        severidad: Severity::High,
        motivo: "sin restriccion, cualquier proceso del usuario puede leer la memoria de \
                 cualquier otro y robar credenciales y tokens de sesion",
    },
    Sysctl {
        ruta: "/proc/sys/fs/suid_dumpable",
        nombre: "fs.suid_dumpable",
        minimo: 0,
        severidad: Severity::Medium,
        motivo: "los volcados de procesos setuid pueden contener secretos",
    },
    Sysctl {
        ruta: "/proc/sys/net/ipv4/tcp_syncookies",
        nombre: "net.ipv4.tcp_syncookies",
        minimo: 1,
        severidad: Severity::Low,
        motivo: "mitiga el agotamiento de la cola de conexiones a medio abrir",
    },
];

fn check_sysctl(root: &Path, out: &mut Vec<Finding>) {
    for s in SYSCTLS {
        let Some(txt) = leer(root, s.ruta) else {
            continue; // el parametro no existe en este kernel
        };
        let Ok(valor) = txt.trim().parse::<i64>() else {
            continue;
        };

        // suid_dumpable es el unico donde el valor seguro es el MAXIMO, no el
        // minimo: 0 es seguro y 2 es el peligroso.
        let inseguro = if s.nombre == "fs.suid_dumpable" {
            valor > s.minimo
        } else {
            valor < s.minimo
        };

        if inseguro {
            out.push(Finding {
                id: format!("AEGIS-SYSCTL-{}", s.nombre.replace('.', "-")),
                category: Category::Hardening,
                severity: s.severidad,
                title: format!("{} = {} (se esperaba {})", s.nombre, valor, s.minimo),
                evidence: format!("{} contiene {}", s.ruta, valor),
                remediation: format!(
                    "sysctl -w {}={} y persistirlo en /etc/sysctl.d/. Motivo: {}",
                    s.nombre, s.minimo, s.motivo
                ),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Cuentas
// ---------------------------------------------------------------------------

fn check_accounts(root: &Path, out: &mut Vec<Finding>) {
    if let Some(passwd) = leer(root, "/etc/passwd") {
        for linea in passwd.lines() {
            let campos: Vec<&str> = linea.split(':').collect();
            if campos.len() < 7 {
                continue;
            }
            let (usuario, uid, shell) = (campos[0], campos[2], campos[6]);

            // Una segunda cuenta con UID 0 es una puerta trasera clasica: no
            // aparece como "root" en ningun listado superficial pero tiene sus
            // mismos privilegios.
            if uid == "0" && usuario != "root" {
                out.push(Finding {
                    id: format!("AEGIS-ACCT-UID0-{usuario}"),
                    category: Category::Accounts,
                    severity: Severity::Critical,
                    title: format!("La cuenta '{usuario}' tiene UID 0"),
                    evidence: linea.to_string(),
                    remediation: format!(
                        "Verificar si '{usuario}' es legitima. Si no, eliminarla y auditar \
                         cuando se creo."
                    ),
                });
            }

            // Contrasena vacia en el campo de passwd (formato antiguo).
            if campos[1].is_empty() && !shell.contains("nologin") && !shell.contains("false") {
                out.push(Finding {
                    id: format!("AEGIS-ACCT-NOPASS-{usuario}"),
                    category: Category::Accounts,
                    severity: Severity::Critical,
                    title: format!("La cuenta '{usuario}' no tiene contrasena"),
                    evidence: linea.to_string(),
                    remediation: format!("passwd -l {usuario} o asignarle una contrasena"),
                });
            }
        }
    }

    if let Some(shadow) = leer(root, "/etc/shadow") {
        for linea in shadow.lines() {
            let campos: Vec<&str> = linea.split(':').collect();
            if campos.len() < 2 {
                continue;
            }
            // Campo de hash vacio = se entra sin contrasena.
            if campos[1].is_empty() {
                out.push(Finding {
                    id: format!("AEGIS-SHADOW-NOPASS-{}", campos[0]),
                    category: Category::Accounts,
                    severity: Severity::Critical,
                    title: format!("La cuenta '{}' tiene hash de contrasena vacio", campos[0]),
                    evidence: format!("{}: campo de hash vacio en /etc/shadow", campos[0]),
                    remediation: format!("passwd -l {}", campos[0]),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ficheros escribibles por todos y SUID
// ---------------------------------------------------------------------------

const DIRECTORIOS_PATH: [&str; 5] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

fn check_world_writable_in_path(root: &Path, out: &mut Vec<Finding>) {
    for dir in DIRECTORIOS_PATH {
        let ruta = root.join(dir.trim_start_matches('/'));
        let Ok(entradas) = std::fs::read_dir(&ruta) else {
            continue;
        };
        for e in entradas.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if !md.is_file() {
                continue;
            }
            // Escribible por todos en un directorio del PATH significa que
            // cualquier usuario local puede sustituir un binario que root
            // ejecutara.
            if md.permissions().mode() & 0o002 != 0 {
                out.push(Finding {
                    id: format!("AEGIS-WW-{}", e.file_name().to_string_lossy()),
                    category: Category::Permissions,
                    severity: Severity::Critical,
                    title: format!("{} es escribible por cualquier usuario", e.path().display()),
                    evidence: format!("modo {:04o}", md.permissions().mode() & 0o7777),
                    remediation: format!("chmod o-w {}", e.path().display()),
                });
            }
        }
    }
}

const DIRECTORIOS_TEMPORALES: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

fn check_suid_in_temp(root: &Path, out: &mut Vec<Finding>) {
    for dir in DIRECTORIOS_TEMPORALES {
        let ruta = root.join(dir.trim_start_matches('/'));
        let Ok(entradas) = std::fs::read_dir(&ruta) else {
            continue;
        };
        for e in entradas.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if !md.is_file() {
                continue;
            }
            let modo = md.permissions().mode();
            if modo & 0o4000 != 0 || modo & 0o2000 != 0 {
                // Un binario setuid en un directorio temporal no tiene ninguna
                // explicacion benigna: es una puerta trasera esperando a ser
                // usada, casi siempre dejada tras un compromiso.
                out.push(Finding {
                    id: format!("AEGIS-SUIDTMP-{}", e.file_name().to_string_lossy()),
                    category: Category::Persistence,
                    severity: Severity::Critical,
                    title: format!(
                        "Binario setuid/setgid en directorio temporal: {}",
                        e.path().display()
                    ),
                    evidence: format!("modo {:04o}, uid propietario {}", modo & 0o7777, md.uid()),
                    remediation: format!(
                        "Poner en cuarentena {} y auditar como llego ahi",
                        e.path().display()
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Puertos a la escucha
// ---------------------------------------------------------------------------

/// Estado TCP "LISTEN" tal y como lo publica /proc/net/tcp.
const TCP_LISTEN: &str = "0A";

/// Puertos a la escucha, sin necesidad de `ss` ni `netstat`.
fn parse_proc_net(texto: &str, ipv6: bool) -> Vec<(String, u16)> {
    let mut puertos = Vec::new();
    for linea in texto.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 4 || campos[3] != TCP_LISTEN {
            continue;
        }
        let Some((dir_hex, puerto_hex)) = campos[1].split_once(':') else {
            continue;
        };
        let Ok(puerto) = u16::from_str_radix(puerto_hex, 16) else {
            continue;
        };
        // Solo interesa distinguir "escucha en todas las interfaces" de
        // "escucha solo en loopback": lo primero expone el servicio a la red.
        let solo_local = if ipv6 {
            dir_hex.eq_ignore_ascii_case("00000000000000000000000001000000")
        } else {
            dir_hex.eq_ignore_ascii_case("0100007F")
        };
        let ambito = if solo_local {
            "loopback"
        } else {
            "todas las interfaces"
        };
        puertos.push((ambito.to_string(), puerto));
    }
    puertos
}

fn check_listening_ports(root: &Path, out: &mut Vec<Finding>) {
    let mut expuestos: Vec<u16> = Vec::new();

    for (rel, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Some(txt) = leer(root, rel) else { continue };
        for (ambito, puerto) in parse_proc_net(&txt, v6) {
            if ambito != "loopback" && !expuestos.contains(&puerto) {
                expuestos.push(puerto);
            }
        }
    }

    if expuestos.is_empty() {
        return;
    }
    expuestos.sort_unstable();

    // No es un fallo por si mismo: es superficie de ataque que hay que
    // justificar. Se reporta como informativo salvo que haya servicios de
    // riesgo conocido.
    let riesgo: Vec<u16> = expuestos
        .iter()
        .copied()
        .filter(|p| matches!(p, 21 | 23 | 25 | 111 | 512 | 513 | 514 | 2049 | 3389 | 5900))
        .collect();

    out.push(Finding {
        id: "AEGIS-NET-001".into(),
        category: Category::Network,
        severity: if riesgo.is_empty() {
            Severity::Info
        } else {
            Severity::High
        },
        title: format!(
            "{} puerto(s) TCP a la escucha en todas las interfaces",
            expuestos.len()
        ),
        evidence: format!(
            "puertos: {}{}",
            expuestos
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            if riesgo.is_empty() {
                String::new()
            } else {
                format!(
                    " | de riesgo conocido (protocolos sin cifrar o de acceso remoto): {}",
                    riesgo
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ),
        remediation: "Cerrar los servicios que no sean necesarios o limitarlos a loopback \
                      y a rangos concretos mediante cortafuegos"
            .into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ultima_directiva_de_sshd_gana() {
        // Comprobar solo la primera aparicion es el error clasico que hace que
        // un PermitRootLogin yes anadido al final pase desapercibido.
        let cfg = "PermitRootLogin no\n# comentario\nPermitRootLogin yes\n";
        assert_eq!(
            directiva_sshd(cfg, "PermitRootLogin").as_deref(),
            Some("yes")
        );

        let cfg2 = "#PermitRootLogin yes\nPermitRootLogin no\n";
        assert_eq!(
            directiva_sshd(cfg2, "PermitRootLogin").as_deref(),
            Some("no")
        );

        // La clave no distingue mayusculas, como en sshd.
        let cfg3 = "permitrootlogin YES\n";
        assert_eq!(
            directiva_sshd(cfg3, "PermitRootLogin").as_deref(),
            Some("yes")
        );
    }

    #[test]
    fn los_puertos_a_la_escucha_se_analizan() {
        let tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   2: 00000000:0050 5DB8D85D:C350 01 00000000:00000000 00:00000000 00000000     0
";
        let p = parse_proc_net(tcp, false);
        // Solo los que estan en LISTEN (0A); el tercero esta ESTABLISHED.
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], ("loopback".to_string(), 22));
        assert_eq!(p[1], ("todas las interfaces".to_string(), 8080));
    }
}
