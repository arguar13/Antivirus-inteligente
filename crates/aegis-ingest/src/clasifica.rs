//! De un texto libre a una clase de la taxonomia.
//!
//! # Donde se gana o se pierde la ingesta de registros
//!
//! Analizar syslog es facil: el formato esta en un RFC. Lo dificil —y lo que
//! separa una canalizacion que sirve de un almacen de texto— es lo de despues:
//! decidir que `Failed password for root from 10.0.0.9 port 22 ssh2` es un
//! **fallo de autenticacion contra la cuenta root desde 10.0.0.9**, y no una
//! cadena de sesenta caracteres.
//!
//! Sin esto, buscar fuerza bruta en el panel significa escribir la subcadena a
//! mano, distinta para cada demonio, y la deteccion se queda en «lo que a
//! alguien se le ocurrio buscar».
//!
//! # Por que reglas explicitas y no expresiones regulares
//!
//! Esto corre en el AGENTE. Un motor de expresiones regulares con retroceso
//! aplicado a texto que escribe el atacante es la receta clasica del bloqueo por
//! explosion combinatoria: una linea preparada cuesta segundos de CPU, y quien
//! la escribe decide cuantas manda. Aqui cada regla es un puñado de busquedas de
//! subcadena con coste lineal y cota conocida, sin dependencias y sin estado.
//!
//! # La cobertura se mide, no se promete
//!
//! Toda clasificacion dice si salio de una regla concreta o del ultimo recurso
//! ([`Clasificacion::especifica`]). De ahi sale la cifra de cobertura que
//! publica [`crate::Contadores`]: no «normalizamos syslog», sino «el 94 % de las
//! lineas de esta maquina encajaron en una clase, y estas son las que no».

use std::collections::BTreeMap;

use crate::esquema::{recortar, Clase, Resultado, Severidad, Valor, MAX_CAMPO};

/// Resultado de clasificar una linea.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clasificacion {
    /// Que clase de hecho es.
    pub clase: Clase,
    /// Como acabo.
    pub resultado: Resultado,
    /// Gravedad sugerida, si la regla sabe mas que la del transporte.
    ///
    /// Un fallo de autenticacion llega por syslog con severidad «info» porque el
    /// demonio lo considera rutina. Para un EDR no lo es.
    pub severidad: Option<Severidad>,
    /// Si encajo en una regla concreta o cayo en el ultimo recurso.
    pub especifica: bool,
    /// Lo que la regla supo extraer.
    pub campos: BTreeMap<String, Valor>,
}

impl Clasificacion {
    /// El ultimo recurso: no se supo, y se dice.
    fn generica() -> Clasificacion {
        Clasificacion {
            clase: Clase::ActividadDelSistema,
            resultado: Resultado::Desconocido,
            severidad: None,
            especifica: false,
            campos: BTreeMap::new(),
        }
    }

    fn nueva(clase: Clase, resultado: Resultado) -> Clasificacion {
        Clasificacion {
            clase,
            resultado,
            severidad: None,
            especifica: true,
            campos: BTreeMap::new(),
        }
    }

    fn con(mut self, clave: &str, valor: impl Into<String>) -> Clasificacion {
        let v: String = valor.into();
        if !v.is_empty() {
            self.campos
                .insert(clave.to_string(), Valor::Texto(recortar(&v, MAX_CAMPO)));
        }
        self
    }

    fn con_numero(mut self, clave: &str, valor: Option<i64>) -> Clasificacion {
        if let Some(n) = valor {
            self.campos.insert(clave.to_string(), Valor::Entero(n));
        }
        self
    }

    fn grave(mut self, s: Severidad) -> Clasificacion {
        self.severidad = Some(s);
        self
    }
}

/// Clasifica una linea a partir de quien la escribio y que dice.
///
/// `productor` es el `APP-NAME` de RFC 5424, la etiqueta de RFC 3164, el
/// `SYSLOG_IDENTIFIER` de journald o el nombre del proveedor de EVTX. Se compara
/// sin distinguir mayusculas y descartando la ruta: `/usr/sbin/sshd` y `sshd`
/// son el mismo demonio, y un recolector mal configurado manda uno u otro.
#[must_use]
pub fn clasificar(productor: &str, mensaje: &str) -> Clasificacion {
    let prod = nombre_corto(productor);
    match prod.as_str() {
        "sshd" | "sshd-session" | "dropbear" => ssh(mensaje),
        "sudo" | "sudo-io" => sudo(mensaje),
        "su" => su(mensaje),
        "login" | "systemd-logind" | "sshd-auth" => sesion(mensaje),
        "systemd" | "init" => systemd(mensaje),
        "cron" | "crond" | "cronie" | "anacron" | "atd" => cron(mensaje),
        "useradd" | "usermod" | "userdel" | "groupadd" | "groupdel" | "groupmod" | "passwd"
        | "chage" | "gpasswd" | "chpasswd" => cuentas(prod.as_str(), mensaje),
        "kernel" => kernel(mensaje),
        "auditd" | "audispd" | "audit" => auditoria(mensaje),
        "named" | "dnsmasq" | "unbound" | "systemd-resolved" | "bind" => dns(mensaje),
        "nginx" | "httpd" | "apache2" | "caddy" | "traefik" | "haproxy" => http(mensaje),
        "ufw" | "iptables" | "nftables" | "firewalld" | "kernel-firewall" => cortafuegos(mensaje),
        "clamd" | "clamav" | "freshclam" | "rkhunter" | "aide" | "falco" | "suricata" | "snort"
        | "ossec" | "wazuh" | "aegis-agent" | "aegiscore" => hallazgo(mensaje),
        "dockerd" | "containerd" | "kubelet" | "crio" | "podman" => contenedor(mensaje),
        "polkitd" | "polkit" | "dbus-daemon" => polkit(mensaje),
        "sendmail" | "postfix" | "postfix/smtpd" | "dovecot" | "exim" => correo(mensaje),
        _ => {
            // Ultimo recurso por contenido: hay demonios propios de cada casa y
            // no se puede tener una regla para cada uno, pero `pam_unix` lo
            // escribe medio mundo y decirlo mal seria peor que no clasificarlo.
            if mensaje.contains("pam_unix(") || mensaje.contains("authentication failure") {
                return pam(mensaje);
            }
            Clasificacion::generica()
        }
    }
}

/// Reduce `/usr/sbin/sshd` a `sshd` y lo pasa a minusculas.
///
/// Tambien quita el `[pid]` que algunos emisores dejan pegado a la etiqueta
/// cuando el analizador de RFC 3164 no lo separo.
fn nombre_corto(productor: &str) -> String {
    let sin_ruta = productor.rsplit('/').next().unwrap_or(productor);
    let sin_pid = sin_ruta.split('[').next().unwrap_or(sin_ruta);
    let s = sin_pid.trim().to_ascii_lowercase();
    recortar(&s, 64)
}

// --- SSH: la puerta por la que se entra ------------------------------------

fn ssh(m: &str) -> Clasificacion {
    // El orden importa: «Failed password» y «Accepted password» comparten casi
    // todo el resto de la linea, asi que el fallo se mira primero.
    if m.starts_with("Failed ") || m.starts_with("error: PAM: Authentication failure") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Media)
            .con("usuario", usuario_ssh(m))
            .con(
                "ip_origen",
                entre(m, " from ", " port ").unwrap_or_default(),
            )
            .con_numero("puerto_origen", numero(entre(m, " port ", " ")))
            .con("metodo", metodo_ssh(m));
    }
    if m.starts_with("Accepted ") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .con("usuario", usuario_ssh(m))
            .con(
                "ip_origen",
                entre(m, " from ", " port ").unwrap_or_default(),
            )
            .con_numero("puerto_origen", numero(entre(m, " port ", " ")))
            .con("metodo", metodo_ssh(m));
    }
    if m.starts_with("Invalid user ") || m.starts_with("User ") && m.contains(" not allowed ") {
        // Un usuario que no existe es una senal mas fuerte que una contrasena
        // equivocada: nadie se equivoca de nombre de cuenta veinte veces.
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("usuario", tras(m, "Invalid user ").unwrap_or_default())
            .con("ip_origen", tras(m, " from ").unwrap_or_default())
            .con("motivo", "cuenta inexistente");
    }
    if m.contains("maximum authentication attempts exceeded") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("usuario", entre(m, " for ", " from ").unwrap_or_default())
            .con(
                "ip_origen",
                entre(m, " from ", " port ").unwrap_or_default(),
            )
            .con("motivo", "intentos agotados");
    }
    if m.starts_with("Disconnected from authenticating user")
        || m.starts_with("Connection closed by authenticating user")
    {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Baja)
            .con("motivo", "corto la conexion durante la autenticacion");
    }
    if m.starts_with("Server listening on") || m.starts_with("Received signal") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Exito);
    }
    if m.contains("session opened for user") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito).con(
            "usuario",
            entre(m, "session opened for user ", "(").unwrap_or_default(),
        );
    }
    if m.contains("session closed for user") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .con(
                "usuario",
                tras(m, "session closed for user ").unwrap_or_default(),
            )
            .con("accion", "cierre");
    }
    Clasificacion::nueva(Clase::ActividadDeRed, Resultado::Desconocido)
}

/// `Failed password for root from ...` y `Failed password for invalid user pi from ...`
/// entregan el nombre en sitios distintos. Es el error mas facil de cometer aqui
/// y deja el campo `usuario` con el valor literal «invalid».
fn usuario_ssh(m: &str) -> String {
    if let Some(u) = entre(m, " for invalid user ", " from ") {
        return u;
    }
    entre(m, " for ", " from ").unwrap_or_default()
}

fn metodo_ssh(m: &str) -> String {
    for metodo in [
        "publickey",
        "password",
        "keyboard-interactive",
        "none",
        "gssapi-with-mic",
    ] {
        if m.contains(metodo) {
            return metodo.to_string();
        }
    }
    String::new()
}

// --- Elevacion de privilegios ----------------------------------------------

fn sudo(m: &str) -> Clasificacion {
    if m.contains("incorrect password attempt") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("usuario", hasta(m, " :").unwrap_or_default())
            .con("motivo", "contrasena incorrecta en sudo");
    }
    if m.contains("user NOT in sudoers") || m.contains("command not allowed") {
        // Alguien con sesion valida intentando hacer algo que no le toca. Es de
        // lo mas parecido a un movimiento lateral que se ve en un log.
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("usuario", hasta(m, " :").unwrap_or_default())
            .con("orden", resto(m, "COMMAND=").unwrap_or_default())
            .con("motivo", "sin autorizacion");
    }
    if m.contains("COMMAND=") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .grave(Severidad::Media)
            .con("usuario", hasta(m, " :").unwrap_or_default())
            .con(
                "usuario_destino",
                entre(m, "USER=", " ;").unwrap_or_default(),
            )
            .con("orden", resto(m, "COMMAND=").unwrap_or_default())
            .con("terminal", entre(m, "TTY=", " ;").unwrap_or_default())
            .con("directorio", entre(m, "PWD=", " ;").unwrap_or_default());
    }
    if m.contains("pam_unix(") {
        return pam(m);
    }
    Clasificacion::nueva(Clase::Autenticacion, Resultado::Desconocido)
}

fn su(m: &str) -> Clasificacion {
    if m.starts_with("FAILED su for") || m.contains("authentication failure") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con(
                "usuario_destino",
                entre(m, "FAILED su for ", " by ").unwrap_or_default(),
            )
            .con("usuario", tras(m, " by ").unwrap_or_default());
    }
    if m.starts_with("(to ") || m.contains("Successful su for") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .grave(Severidad::Media)
            .con("usuario_destino", entre(m, "(to ", ")").unwrap_or_default())
            .con("usuario", entre(m, ") ", " on ").unwrap_or_default());
    }
    Clasificacion::nueva(Clase::Autenticacion, Resultado::Desconocido)
}

fn sesion(m: &str) -> Clasificacion {
    if m.contains("FAILED LOGIN") || m.contains("LOGIN FAILURE") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("usuario", tras(m, "FOR ").unwrap_or_default());
    }
    if m.contains("New session ") || m.contains("session opened") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .con("usuario", tras(m, " of user ").unwrap_or_default());
    }
    if m.contains("Removed session") || m.contains("session closed") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .con("accion", "cierre");
    }
    if m.contains("pam_unix(") {
        return pam(m);
    }
    Clasificacion::nueva(Clase::Autenticacion, Resultado::Desconocido)
}

/// `pam_unix` lo escriben media docena de demonios distintos con el mismo
/// formato, asi que la regla vive aparte y la llaman todos.
fn pam(m: &str) -> Clasificacion {
    let base = if m.contains("session opened") {
        Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
    } else if m.contains("session closed") {
        Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito).con("accion", "cierre")
    } else if m.contains("authentication failure") || m.contains("auth could not identify") {
        Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo).grave(Severidad::Media)
    } else if m.contains("account ") && m.contains("expired") {
        Clasificacion::nueva(Clase::Autenticacion, Resultado::Fallo).grave(Severidad::Baja)
    } else {
        Clasificacion::nueva(Clase::Autenticacion, Resultado::Desconocido)
    };
    // `user=root` va al final y `for user root` en medio: los dos existen.
    let usuario = clave_valor(m, "user=")
        .or_else(|| entre(m, "session opened for user ", "("))
        .or_else(|| tras(m, "session closed for user "))
        .unwrap_or_default();
    base.con("usuario", usuario)
        .con("ip_origen", clave_valor(m, "rhost=").unwrap_or_default())
        .con("terminal", clave_valor(m, "tty=").unwrap_or_default())
        .con_numero("uid", numero(clave_valor(m, "uid=")))
}

// --- Servicios y procesos ---------------------------------------------------

fn systemd(m: &str) -> Clasificacion {
    if m.starts_with("Started ") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Exito)
            .con("accion", "arranque")
            .con("servicio", tras(m, "Started ").unwrap_or_default());
    }
    if m.starts_with("Stopped ") || m.starts_with("Stopping ") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Exito)
            .con("accion", "parada")
            .con("servicio", tras(m, "Stopped ").unwrap_or_default());
    }
    if m.starts_with("Failed to start") || m.contains("Failed with result") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Fallo)
            .grave(Severidad::Media)
            .con("servicio", tras(m, "Failed to start ").unwrap_or_default());
    }
    if m.starts_with("Reloading") || m.starts_with("Reached target") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Exito);
    }
    if m.contains("Deactivated successfully") {
        return Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Exito)
            .con("accion", "parada");
    }
    Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Desconocido)
}

fn cron(m: &str) -> Clasificacion {
    if m.contains("CMD (") {
        // `cron` es un mecanismo de persistencia de manual, asi que la orden se
        // extrae siempre: sin ella el evento no sirve para buscar despues.
        return Clasificacion::nueva(Clase::ActividadDeProceso, Resultado::Exito)
            .con("usuario", entre(m, "(", ")").unwrap_or_default())
            .con("orden", entre(m, "CMD (", ")").unwrap_or_default());
    }
    if m.contains("RELOAD") || m.contains("LIST") || m.contains("(crontab") {
        return Clasificacion::nueva(Clase::ActividadDeConfiguracion, Resultado::Exito)
            .grave(Severidad::Media)
            .con("orden", "crontab");
    }
    if m.contains("pam_unix(") {
        return pam(m);
    }
    Clasificacion::nueva(Clase::ActividadDeProceso, Resultado::Desconocido)
}

fn contenedor(m: &str) -> Clasificacion {
    Clasificacion::nueva(Clase::ActividadDeServicio, Resultado::Desconocido)
        .con("plataforma", "contenedor")
        .con(
            "contenedor",
            clave_valor(m, "container=").unwrap_or_default(),
        )
}

fn polkit(m: &str) -> Clasificacion {
    if m.contains("Operator of unix-session") || m.contains("AUTHORIZING") {
        return Clasificacion::nueva(Clase::Autenticacion, Resultado::Exito)
            .grave(Severidad::Media)
            .con("mecanismo", "polkit");
    }
    Clasificacion::nueva(Clase::Autenticacion, Resultado::Desconocido).con("mecanismo", "polkit")
}

fn correo(m: &str) -> Clasificacion {
    Clasificacion::nueva(Clase::ActividadDelSistema, Resultado::Desconocido)
        .con("subsistema", "correo")
        .con("remitente", entre(m, "from=<", ">").unwrap_or_default())
        .con("destinatario", entre(m, "to=<", ">").unwrap_or_default())
}

// --- Cuentas ----------------------------------------------------------------

fn cuentas(prod: &str, m: &str) -> Clasificacion {
    // Crear una cuenta o meterla en un grupo privilegiado es persistencia. Se
    // clasifica alto aunque el demonio lo escriba como informativo.
    let accion = match prod {
        "useradd" => "alta de cuenta",
        "userdel" => "baja de cuenta",
        "usermod" => "cambio de cuenta",
        "groupadd" => "alta de grupo",
        "groupdel" => "baja de grupo",
        "groupmod" | "gpasswd" => "cambio de grupo",
        _ => "cambio de contrasena",
    };
    let grave = matches!(prod, "useradd" | "usermod" | "groupadd" | "gpasswd");
    let c = Clasificacion::nueva(Clase::GestionDeCuentas, Resultado::Exito)
        .con("accion", accion)
        .con(
            "usuario",
            clave_valor(m, "name=")
                .or_else(|| entre(m, "new user: name=", ","))
                .or_else(|| tras(m, "password changed for "))
                .or_else(|| entre(m, "'", "'"))
                .unwrap_or_default(),
        )
        .con_numero(
            "uid",
            numero(clave_valor(m, "UID=").or_else(|| clave_valor(m, "uid="))),
        )
        .con("grupo", clave_valor(m, "GROUP=").unwrap_or_default());
    if grave {
        c.grave(Severidad::Alta)
    } else {
        c.grave(Severidad::Media)
    }
}

// --- Kernel, auditoria, red -------------------------------------------------

fn kernel(m: &str) -> Clasificacion {
    if m.starts_with("audit:") || m.contains("type=") && m.contains("audit(") {
        return auditoria(m);
    }
    if m.contains("SRC=") && m.contains("DST=") {
        return cortafuegos(m);
    }
    if m.contains("segfault at") || m.contains("general protection fault") {
        // Una caida repetida en el mismo binario es el aspecto que tiene un
        // exploit que todavia no funciona.
        return Clasificacion::nueva(Clase::ActividadDeProceso, Resultado::Fallo)
            .grave(Severidad::Media)
            .con("proceso", hasta(m, "[").unwrap_or_default())
            .con("motivo", "violacion de segmento");
    }
    if m.contains("Out of memory") || m.contains("oom-kill") {
        return Clasificacion::nueva(Clase::ActividadDeProceso, Resultado::Fallo)
            .grave(Severidad::Alta)
            .con("motivo", "sin memoria")
            .con("proceso", clave_valor(m, "comm=").unwrap_or_default());
    }
    if m.contains("Kernel module")
        || m.contains("module verification failed")
        || m.contains("loading out-of-tree module")
    {
        // Cargar un modulo sin firma es, casi literalmente, la definicion de un
        // rootkit de kernel llegando a casa.
        return Clasificacion::nueva(Clase::ActividadDeConfiguracion, Resultado::Desconocido)
            .grave(Severidad::Alta)
            .con("componente", "modulo de kernel");
    }
    Clasificacion::nueva(Clase::ActividadDelSistema, Resultado::Desconocido)
}

fn auditoria(m: &str) -> Clasificacion {
    let tipo = clave_valor(m, "type=").unwrap_or_default();
    let base = match tipo.as_str() {
        "USER_AUTH" | "USER_LOGIN" | "CRED_ACQ" | "USER_ACCT" => {
            let exito = m.contains("res=success") || m.contains("res=success'");
            Clasificacion::nueva(
                Clase::Autenticacion,
                if exito {
                    Resultado::Exito
                } else {
                    Resultado::Fallo
                },
            )
        }
        "ADD_USER" | "ADD_GROUP" | "USER_MGMT" | "ROLE_ASSIGN" | "DEL_USER" => {
            Clasificacion::nueva(Clase::GestionDeCuentas, Resultado::Exito).grave(Severidad::Alta)
        }
        "EXECVE" | "SYSCALL" => Clasificacion::nueva(Clase::ActividadDeProceso, Resultado::Exito),
        "PATH" | "OPEN" => Clasificacion::nueva(Clase::ActividadDeFichero, Resultado::Exito),
        "AVC" | "SECCOMP" | "SELINUX_ERR" | "ANOM_ABEND" => {
            Clasificacion::nueva(Clase::HallazgoDeSeguridad, Resultado::Fallo)
                .grave(Severidad::Alta)
        }
        "CONFIG_CHANGE" | "DAEMON_START" | "DAEMON_END" => {
            Clasificacion::nueva(Clase::ActividadDeConfiguracion, Resultado::Exito)
                .grave(Severidad::Alta)
        }
        _ => Clasificacion::nueva(Clase::ActividadDelSistema, Resultado::Desconocido),
    };
    base.con("tipo_auditoria", tipo)
        .con("usuario", clave_valor(m, "acct=").unwrap_or_default())
        .con("ejecutable", clave_valor(m, "exe=").unwrap_or_default())
        .con("ruta", clave_valor(m, "name=").unwrap_or_default())
        .con("terminal", clave_valor(m, "terminal=").unwrap_or_default())
        .con("ip_origen", clave_valor(m, "addr=").unwrap_or_default())
        .con_numero("pid", numero(clave_valor(m, "pid=")))
        .con_numero("uid", numero(clave_valor(m, "uid=")))
}

fn cortafuegos(m: &str) -> Clasificacion {
    // Un bloqueo es un fallo desde el punto de vista del que lo intento, y eso
    // es justo lo que interesa contar.
    let bloqueado = m.contains("BLOCK") || m.contains("DROP") || m.contains("REJECT");
    Clasificacion::nueva(
        Clase::ActividadDeRed,
        if bloqueado {
            Resultado::Fallo
        } else {
            Resultado::Exito
        },
    )
    .con("accion", if bloqueado { "bloqueo" } else { "permitido" })
    .con("ip_origen", clave_valor(m, "SRC=").unwrap_or_default())
    .con("ip_destino", clave_valor(m, "DST=").unwrap_or_default())
    .con("protocolo", clave_valor(m, "PROTO=").unwrap_or_default())
    .con("interfaz", clave_valor(m, "IN=").unwrap_or_default())
    .con_numero("puerto_origen", numero(clave_valor(m, "SPT=")))
    .con_numero("puerto_destino", numero(clave_valor(m, "DPT=")))
}

fn dns(m: &str) -> Clasificacion {
    if let Some(dominio) = entre(m, "query[", "]")
        .and_then(|_| entre(m, "] ", " from "))
        .or_else(|| entre(m, "query: ", " IN"))
    {
        return Clasificacion::nueva(Clase::ActividadDns, Resultado::Exito)
            .con("dominio", dominio)
            .con("tipo", entre(m, "query[", "]").unwrap_or_default())
            .con("ip_origen", tras(m, " from ").unwrap_or_default());
    }
    if m.contains("NXDOMAIN") || m.contains("SERVFAIL") || m.contains("REFUSED") {
        return Clasificacion::nueva(Clase::ActividadDns, Resultado::Fallo).con(
            "codigo",
            palabra_de(m, &["NXDOMAIN", "SERVFAIL", "REFUSED"]),
        );
    }
    Clasificacion::nueva(Clase::ActividadDns, Resultado::Desconocido)
}

fn http(m: &str) -> Clasificacion {
    // Formato combinado: `1.2.3.4 - - [fecha] "GET /x HTTP/1.1" 200 1234 "ref" "ua"`
    let metodo = palabra_de(
        m,
        &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE",
        ],
    );
    let codigo = codigo_http(m);
    let fallo = codigo.is_some_and(|c| c >= 400);
    Clasificacion::nueva(
        Clase::ActividadHttp,
        if fallo {
            Resultado::Fallo
        } else {
            Resultado::Exito
        },
    )
    .con("metodo", metodo)
    .con(
        "ruta",
        entre(m, " /", " HTTP/")
            .map(|r| format!("/{r}"))
            .unwrap_or_default(),
    )
    .con("ip_origen", hasta(m, " ").unwrap_or_default())
    .con_numero("codigo", codigo.map(i64::from))
}

fn hallazgo(m: &str) -> Clasificacion {
    // Un hallazgo de otra herramienta entra como hallazgo, no como texto de un
    // programa cualquiera: es lo que permite contarlo junto a los propios.
    Clasificacion::nueva(Clase::HallazgoDeSeguridad, Resultado::Desconocido)
        .grave(Severidad::Alta)
        .con("ruta", entre(m, ": ", " FOUND").unwrap_or_default())
        .con(
            "firma",
            entre(m, " ", " FOUND")
                .filter(|_| m.contains("FOUND"))
                .unwrap_or_default(),
        )
}

// --- Extractores ------------------------------------------------------------
//
// Todos son de coste lineal y sin retroceso. Es deliberado: ver el encabezado
// del modulo.

/// Texto entre dos marcas, la primera vez que aparecen en ese orden.
fn entre(m: &str, desde: &str, hasta: &str) -> Option<String> {
    let i = m.find(desde)? + desde.len();
    let resto = m.get(i..)?;
    let j = resto.find(hasta)?;
    let v = resto.get(..j)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Todo lo que queda despues de una marca, hasta el final.
///
/// Hace falta para los campos que son una orden entera: cortar `COMMAND=` por el
/// primer espacio deja «/bin/cat» donde ponia «/bin/cat /etc/shadow», y la
/// diferencia entre esas dos lineas es la diferencia entre un comando rutinario
/// y la exfiltracion de las contrasenas de la maquina.
fn resto(m: &str, desde: &str) -> Option<String> {
    let i = m.find(desde)? + desde.len();
    let v = m.get(i..)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Primera palabra despues de una marca.
fn tras(m: &str, desde: &str) -> Option<String> {
    let i = m.find(desde)? + desde.len();
    let resto = m.get(i..)?;
    let v = resto
        .split([' ', '\t', ',', ';', ')'])
        .next()
        .unwrap_or("")
        .trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Todo lo que hay antes de una marca.
fn hasta(m: &str, marca: &str) -> Option<String> {
    let j = m.find(marca)?;
    let v = m.get(..j)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Valor de un `clave=valor`, con o sin comillas.
///
/// La busqueda exige que la clave empiece linea o venga tras un separador: sin
/// eso, buscar `uid=` encontraria el `uid=` de `auid=` y el evento saldria con
/// el identificador equivocado. Es el fallo clasico de los normalizadores
/// escritos con prisa, y produce atribuciones erroneas que nadie revisa.
fn clave_valor(m: &str, clave: &str) -> Option<String> {
    let bytes = m.as_bytes();
    let mut desde = 0usize;
    while let Some(rel) = m.get(desde..)?.find(clave) {
        let i = desde + rel;
        let anterior_ok = i == 0
            || matches!(
                bytes.get(i - 1),
                Some(b' ' | b'\t' | b'(' | b',' | b';' | b'[' | b'"' | b'\'')
            );
        if anterior_ok {
            let j = i + clave.len();
            let resto = m.get(j..)?;
            let (v, _) = if let Some(sin_comilla) = resto.strip_prefix('"') {
                let fin = sin_comilla.find('"').unwrap_or(sin_comilla.len());
                (sin_comilla.get(..fin)?, fin)
            } else {
                let fin = resto
                    .find([' ', '\t', ',', ';', ')', '\'', '"'])
                    .unwrap_or(resto.len());
                (resto.get(..fin)?, fin)
            };
            let v = v.trim_end_matches('\'');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
        desde = i + clave.len();
    }
    None
}

/// La primera de una lista de palabras que aparezca, como palabra suelta.
fn palabra_de(m: &str, palabras: &[&str]) -> String {
    for t in m.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        for p in palabras {
            if t == *p {
                return (*p).to_string();
            }
        }
    }
    String::new()
}

/// El codigo de estado del formato combinado: el numero de tres cifras que va
/// justo detras de la peticion entrecomillada.
fn codigo_http(m: &str) -> Option<u16> {
    let tras_comillas = m.split('"').nth(2)?;
    let t = tras_comillas.split_whitespace().next()?;
    if t.len() != 3 {
        return None;
    }
    let c: u16 = t.parse().ok()?;
    (100..600).contains(&c).then_some(c)
}

fn numero(s: Option<String>) -> Option<i64> {
    s?.parse().ok()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Las lineas de estas pruebas estan copiadas de registros reales. Es la
    // unica forma de que las reglas valgan: una linea inventada se ajusta sin
    // querer a la regla que se acaba de escribir.

    #[test]
    fn el_fallo_de_contrasena_de_ssh_sale_entero() {
        let c = clasificar(
            "sshd",
            "Failed password for root from 10.0.0.9 port 54321 ssh2",
        );
        assert_eq!(c.clase, Clase::Autenticacion);
        assert_eq!(c.resultado, Resultado::Fallo);
        assert!(c.especifica);
        assert_eq!(c.campos["usuario"], Valor::Texto("root".into()));
        assert_eq!(c.campos["ip_origen"], Valor::Texto("10.0.0.9".into()));
        assert_eq!(c.campos["puerto_origen"], Valor::Entero(54321));
        assert_eq!(c.campos["metodo"], Valor::Texto("password".into()));
    }

    #[test]
    fn el_usuario_invalido_no_se_llama_invalid() {
        // «Failed password for invalid user pi from ...» entrega el nombre en
        // otro sitio. Es el error mas facil de cometer aqui, y deja el campo
        // `usuario` con el valor literal «invalid» en media flota.
        let c = clasificar(
            "sshd",
            "Failed password for invalid user pi from 192.168.1.5 port 40000 ssh2",
        );
        assert_eq!(c.campos["usuario"], Valor::Texto("pi".into()));
        assert_eq!(c.campos["ip_origen"], Valor::Texto("192.168.1.5".into()));
    }

    #[test]
    fn una_cuenta_inexistente_pesa_mas_que_una_contrasena_mala() {
        // Nadie se equivoca de nombre de cuenta veinte veces.
        let c = clasificar("sshd", "Invalid user admin from 203.0.113.7 port 33333");
        assert_eq!(c.resultado, Resultado::Fallo);
        assert_eq!(c.severidad, Some(Severidad::Alta));
        assert_eq!(c.campos["usuario"], Valor::Texto("admin".into()));
    }

    #[test]
    fn la_entrada_correcta_por_clave_publica_tambien_se_reconoce() {
        let c = clasificar(
            "sshd",
            "Accepted publickey for operador from 10.1.2.3 port 5000 ssh2: RSA SHA256:abc",
        );
        assert_eq!(c.resultado, Resultado::Exito);
        assert_eq!(c.campos["metodo"], Valor::Texto("publickey".into()));
        assert_eq!(c.campos["usuario"], Valor::Texto("operador".into()));
    }

    #[test]
    fn sudo_entrega_la_orden_y_a_quien_se_eleva() {
        let c = clasificar(
            "sudo",
            "  operador : TTY=pts/0 ; PWD=/home/operador ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        );
        assert_eq!(c.clase, Clase::Autenticacion);
        assert_eq!(c.resultado, Resultado::Exito);
        assert_eq!(c.campos["usuario"], Valor::Texto("operador".into()));
        assert_eq!(c.campos["usuario_destino"], Valor::Texto("root".into()));
        assert_eq!(
            c.campos["orden"],
            Valor::Texto("/bin/cat /etc/shadow".into())
        );
    }

    #[test]
    fn sudo_sin_autorizacion_es_alta_y_no_media() {
        // Alguien con sesion valida intentando lo que no le toca: de lo mas
        // parecido a un movimiento lateral que se ve en un log.
        let c = clasificar(
            "sudo",
            "operador : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
        );
        assert_eq!(c.resultado, Resultado::Fallo);
        assert_eq!(c.severidad, Some(Severidad::Alta));
    }

    #[test]
    fn pam_se_reconoce_venga_del_demonio_que_venga() {
        let c = clasificar(
            "cualquier-demonio-de-la-casa",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh \
             ruser= rhost=198.51.100.4 user=root",
        );
        assert!(c.especifica, "pam_unix lo escribe media docena de demonios");
        assert_eq!(c.clase, Clase::Autenticacion);
        assert_eq!(c.resultado, Resultado::Fallo);
        assert_eq!(c.campos["ip_origen"], Valor::Texto("198.51.100.4".into()));
        assert_eq!(c.campos["usuario"], Valor::Texto("root".into()));
    }

    #[test]
    fn uid_no_se_confunde_con_auid() {
        // El fallo clasico del normalizador escrito con prisa: buscar `uid=`
        // encuentra el de `auid=` y el evento sale con el identificador
        // equivocado. Nadie revisa esas atribuciones despues.
        let m = "type=USER_AUTH msg=audit(1700000000.123:456): pid=1234 uid=0 auid=1000 \
                 acct=\"operador\" exe=\"/usr/bin/sudo\" res=failed";
        let c = clasificar("auditd", m);
        assert_eq!(c.campos["uid"], Valor::Entero(0), "uid=0, no auid=1000");
        assert_eq!(c.campos["usuario"], Valor::Texto("operador".into()));
        assert_eq!(c.resultado, Resultado::Fallo);
    }

    #[test]
    fn el_bloqueo_del_cortafuegos_sale_con_sus_cinco_campos() {
        let c = clasificar(
            "kernel",
            "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.9 DST=10.0.0.2 LEN=60 \
             PROTO=TCP SPT=45678 DPT=22 WINDOW=1024",
        );
        assert_eq!(c.clase, Clase::ActividadDeRed);
        assert_eq!(c.resultado, Resultado::Fallo);
        assert_eq!(c.campos["ip_origen"], Valor::Texto("203.0.113.9".into()));
        assert_eq!(c.campos["ip_destino"], Valor::Texto("10.0.0.2".into()));
        assert_eq!(c.campos["puerto_destino"], Valor::Entero(22));
        assert_eq!(c.campos["protocolo"], Valor::Texto("TCP".into()));
    }

    #[test]
    fn systemd_distingue_arrancar_de_fallar_al_arrancar() {
        let a = clasificar("systemd", "Started OpenSSH server daemon.");
        assert_eq!(a.clase, Clase::ActividadDeServicio);
        assert_eq!(a.resultado, Resultado::Exito);
        assert_eq!(a.campos["accion"], Valor::Texto("arranque".into()));

        let b = clasificar("systemd", "Failed to start Some Broken Unit.");
        assert_eq!(b.resultado, Resultado::Fallo);
    }

    #[test]
    fn cron_entrega_siempre_la_orden() {
        // cron es un mecanismo de persistencia de manual: sin la orden el evento
        // no sirve para buscar despues.
        let c = clasificar("CRON", "(root) CMD (/usr/local/bin/backup.sh --full)");
        assert_eq!(c.clase, Clase::ActividadDeProceso);
        assert_eq!(c.campos["usuario"], Valor::Texto("root".into()));
        assert_eq!(
            c.campos["orden"],
            Valor::Texto("/usr/local/bin/backup.sh --full".into())
        );
    }

    #[test]
    fn crear_una_cuenta_se_clasifica_alto_aunque_el_demonio_lo_escriba_informativo() {
        // Crear una cuenta es persistencia.
        let c = clasificar(
            "useradd",
            "new user: name=puerta, UID=0, GID=0, home=/root, shell=/bin/bash",
        );
        assert_eq!(c.clase, Clase::GestionDeCuentas);
        assert_eq!(c.severidad, Some(Severidad::Alta));
        assert_eq!(c.campos["usuario"], Valor::Texto("puerta".into()));
        assert_eq!(c.campos["uid"], Valor::Entero(0));
    }

    #[test]
    fn el_modulo_de_kernel_sin_firma_es_grave() {
        let c = clasificar(
            "kernel",
            "module verification failed: signature and/or required key missing - tainting kernel",
        );
        assert_eq!(c.severidad, Some(Severidad::Alta));
        assert_eq!(c.clase, Clase::ActividadDeConfiguracion);
    }

    #[test]
    fn el_http_sale_con_metodo_ruta_y_codigo() {
        let c = clasificar(
            "nginx",
            "10.0.0.5 - - [15/Jun/2023:12:00:00 +0000] \"GET /admin/../etc/passwd HTTP/1.1\" \
             404 153 \"-\" \"curl/8.0\"",
        );
        assert_eq!(c.clase, Clase::ActividadHttp);
        assert_eq!(c.resultado, Resultado::Fallo, "404 es fallo");
        assert_eq!(c.campos["metodo"], Valor::Texto("GET".into()));
        assert_eq!(c.campos["codigo"], Valor::Entero(404));
        assert_eq!(
            c.campos["ruta"],
            Valor::Texto("/admin/../etc/passwd".into())
        );
    }

    #[test]
    fn un_hallazgo_de_otra_herramienta_entra_como_hallazgo() {
        // Es lo que permite contarlo junto a los propios.
        let c = clasificar(
            "clamd",
            "/home/victima/factura.doc: Doc.Dropper.Agent-6 FOUND",
        );
        assert_eq!(c.clase, Clase::HallazgoDeSeguridad);
        assert_eq!(c.severidad, Some(Severidad::Alta));
    }

    #[test]
    fn la_ruta_y_el_pid_no_cambian_el_demonio() {
        // Un recolector mal configurado manda `/usr/sbin/sshd[1234]` en vez de
        // `sshd`, y eso no puede dejar la linea sin clasificar.
        let a = clasificar(
            "/usr/sbin/sshd",
            "Failed password for root from 1.2.3.4 port 22 ssh2",
        );
        let b = clasificar(
            "sshd[4242]",
            "Failed password for root from 1.2.3.4 port 22 ssh2",
        );
        let c = clasificar("SSHD", "Failed password for root from 1.2.3.4 port 22 ssh2");
        assert_eq!(a.clase, Clase::Autenticacion);
        assert_eq!(b.clase, Clase::Autenticacion);
        assert_eq!(c.clase, Clase::Autenticacion);
    }

    #[test]
    fn lo_que_no_se_sabe_se_dice_en_vez_de_inventarse() {
        // De aqui sale la cifra de cobertura: no «normalizamos syslog», sino
        // «el 94 % encajo, y estas son las que no».
        let c = clasificar("un-programa-de-la-casa", "todo bien por aqui");
        assert!(!c.especifica);
        assert_eq!(c.clase, Clase::ActividadDelSistema);
        assert_eq!(c.resultado, Resultado::Desconocido);
        assert!(c.campos.is_empty());
    }

    // --- Entrada hostil -----------------------------------------------------

    #[test]
    fn una_linea_preparada_no_cuelga_ni_desborda() {
        // Coste lineal y sin retroceso: una linea de un mega cuesta lo que mide,
        // no lo que su estructura sugiera.
        let bomba = format!("Failed password for {} from ", "a".repeat(400_000));
        let inicio = std::time::Instant::now();
        let c = clasificar("sshd", &bomba);
        assert!(
            inicio.elapsed() < std::time::Duration::from_millis(500),
            "una linea preparada no puede costar tiempo cuadratico"
        );
        // Y lo que salga esta acotado: el atacante no decide cuanta memoria
        // ocupa el evento.
        for v in c.campos.values() {
            assert!(v.texto().len() <= MAX_CAMPO);
        }
    }

    #[test]
    fn los_caracteres_multibyte_no_parten_ningun_campo() {
        // Los indices son de byte; cortar en medio de un caracter entraria en
        // panico, y el mensaje lo escribe el atacante.
        let c = clasificar("sshd", "Failed password for ñññ from ñ.ñ.ñ.ñ port 22 ssh2");
        assert_eq!(c.clase, Clase::Autenticacion);
        let c2 = clasificar("sudo", "ñ : TTY=ñ ; PWD=ñ ; USER=ñ ; COMMAND=ñ");
        assert!(c2.especifica);
    }

    #[test]
    fn un_mensaje_vacio_no_entra_en_panico() {
        for prod in [
            "sshd", "sudo", "su", "systemd", "kernel", "auditd", "nginx", "cron", "",
        ] {
            let c = clasificar(prod, "");
            assert!(c.campos.values().all(|v| !v.texto().is_empty()));
        }
    }

    #[test]
    fn un_valor_entrecomillado_con_espacios_se_lee_entero() {
        let c = clasificar(
            "auditd",
            "type=EXECVE msg=audit(1.1:1): exe=\"/usr/bin/mi programa\" pid=7",
        );
        assert_eq!(
            c.campos["ejecutable"],
            Valor::Texto("/usr/bin/mi programa".into())
        );
        assert_eq!(c.campos["pid"], Valor::Entero(7));
    }

    #[test]
    fn un_numero_que_no_cabe_no_se_cuela_como_cero() {
        // `parse` falla y el campo no se pone, que es honesto. Ponerlo a cero
        // diria que el puerto era el cero, y el cero es un puerto.
        let c = clasificar(
            "kernel",
            "SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=99999999999999999999 DPT=22",
        );
        assert!(!c.campos.contains_key("puerto_origen"));
        assert_eq!(c.campos["puerto_destino"], Valor::Entero(22));
    }
}
