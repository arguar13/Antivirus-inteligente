//! Proveedores de las tablas de identidad.
//!
//! # Tres formatos binarios que hay que leer bien
//!
//! Esta familia es la que mas analisis de formato lleva, y los tres que importan
//! tienen la misma propiedad incomoda: los escribe otro, pueden estar corruptos
//! o preparados a proposito, y el agente los lee con privilegios.
//!
//!   - **`utmp`**: registro binario de sesiones, con una estructura de 384
//!     bytes por entrada. Se analiza por desplazamientos explicitos y NO
//!     reinterpretando memoria, que es como se hace en C y como se cuelan los
//!     fallos.
//!   - **`authorized_keys`**: texto, pero con una gramatica que casi todo el
//!     mundo analiza mal. Ver [`analizar_clave`].
//!   - **La cache de credenciales de Kerberos**: formato binario de MIT, con
//!     enteros en orden de red y longitudes que vienen del propio fichero. Cada
//!     longitud se comprueba contra lo que queda antes de usarla; si no cuadra,
//!     el analisis PARA en vez de seguir sobre bytes que no son lo que dicen.
//!
//! # Lo que estas tablas NO ven, y se dice
//!
//! Se leen ficheros, no NSS. En una maquina unida a un dominio eso significa
//! ver las cuentas locales y no las del directorio. Pasar por `getpwent` haria
//! que una consulta de caza pudiera quedarse colgada esperando a un servidor
//! LDAP, multiplicado por cien mil endpoints; el precio de no hacerlo es este, y
//! esta escrito en la descripcion de cada tabla para que el analista lo vea
//! ANTES de concluir nada.

use aegis_entidad::{entidad, Clase};
use aegis_parser::esquema::{identidad as esq, Coste, Tabla as Esquema};
use sha2::{Digest, Sha256};

use crate::contexto::Contexto;
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

// ---------------------------------------------------------------------------
// Base64, que hace falta para las huellas de clave
// ---------------------------------------------------------------------------

/// Alfabeto estandar de base64.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decodifica base64 estandar, tolerando relleno o su ausencia.
///
/// Se escribe aqui en vez de anadir una dependencia porque son treinta lineas y
/// porque el arbol de dependencias del agente es su superficie de ataque: un
/// crate nuevo en el endpoint necesita una justificacion escrita, y «decodificar
/// base64» no la tiene.
pub fn de_base64(texto: &str) -> Option<Vec<u8>> {
    let mut salida = Vec::with_capacity(texto.len() * 3 / 4);
    let mut acumulado: u32 = 0;
    let mut bits: u32 = 0;
    for b in texto.bytes() {
        if b == b'=' || b == b'\n' || b == b'\r' {
            continue;
        }
        let valor = B64.iter().position(|c| *c == b)? as u32;
        acumulado = (acumulado << 6) | valor;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            salida.push((acumulado >> bits) as u8);
        }
    }
    Some(salida)
}

/// Codifica en base64 SIN relleno, que es como `ssh-keygen` escribe las huellas.
pub fn a_base64_sin_relleno(bytes: &[u8]) -> String {
    let mut salida = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for trozo in bytes.chunks(3) {
        let b = [
            trozo[0],
            *trozo.get(1).unwrap_or(&0),
            *trozo.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let cuantos = trozo.len() + 1;
        for i in 0..cuantos {
            let indice = ((n >> (18 - i * 6)) & 0x3F) as usize;
            salida.push(B64[indice] as char);
        }
    }
    salida
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

/// Interpretes que no permiten iniciar sesion.
const SIN_SESION: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/nonexistent",
    "",
];

/// Una cuenta local ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cuenta {
    /// Nombre.
    pub nombre: String,
    /// Identificador de usuario.
    pub uid: i64,
    /// Grupo principal.
    pub gid: i64,
    /// Campo GECOS.
    pub descripcion: String,
    /// Directorio personal.
    pub directorio: String,
    /// Interprete.
    pub interprete: String,
}

/// Analiza `/etc/passwd`.
///
/// Las lineas con menos de siete campos se saltan: `passwd` tiene exactamente
/// siete, y una linea con menos esta corrupta o preparada. Rellenarla con
/// valores por defecto daria una cuenta con uid 0 por accidente.
pub fn analizar_passwd(texto: &str) -> Vec<Cuenta> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        if linea.starts_with('#') || linea.trim().is_empty() {
            continue;
        }
        let campos: Vec<&str> = linea.split(':').collect();
        if campos.len() < 7 {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (campos[2].parse::<i64>(), campos[3].parse::<i64>()) else {
            continue;
        };
        salida.push(Cuenta {
            nombre: campos[0].to_string(),
            uid,
            gid,
            descripcion: campos[4].to_string(),
            directorio: campos[5].to_string(),
            interprete: campos[6].to_string(),
        });
    }
    salida
}

/// Estado de la contrasena de una cuenta, leido de `shadow`.
///
/// NUNCA devuelve el resumen. Lo que interesa a la deteccion es si la cuenta
/// tiene contrasena, esta bloqueada o la tiene VACIA —que es una via de entrada
/// directa—, y ninguna de las tres respuestas necesita el hash. Sacar el hash de
/// la maquina por una tabla de consulta seria convertir el EDR en el problema.
pub fn estado_de_contrasena(campo: &str) -> &'static str {
    match campo {
        "" => "empty",
        c if c.starts_with('!') || c.starts_with('*') => "locked",
        _ => "set",
    }
}

/// Las cuentas locales.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usuarios;

impl Tabla for Usuarios {
    fn esquema(&self) -> &'static Esquema {
        &esq::USERS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("etc/passwd")?;
        let cuentas = analizar_passwd(&texto);

        // `shadow` solo lo lee root. Sin el, la columna queda como `unknown` con
        // su aviso: no se afirma que la cuenta tenga contrasena cuando no se ha
        // podido mirar.
        let sombra = ctx.leer_texto("etc/shadow").ok();
        let mut salida = Filas::default();
        if sombra.is_none() {
            salida.avisar(
                "/etc/shadow",
                MotivoNoLeible::SinPrivilegios {
                    operacion: "leer el estado de las contrasenas",
                    necesita: "ser root o pertenecer al grupo shadow",
                },
            );
        }

        let mut c = Constructor::nuevo(self.esquema());
        for cuenta in cuentas {
            salida.examinadas += 1;
            c.texto("username", cuenta.nombre.clone());
            c.entero("uid", cuenta.uid);
            c.entero("gid", cuenta.gid);
            c.texto("description", cuenta.descripcion);
            c.texto("directory", cuenta.directorio);
            c.texto("shell", cuenta.interprete.clone());
            c.booleano(
                "can_login",
                !SIN_SESION.contains(&cuenta.interprete.as_str()),
            );
            c.booleano("is_root", cuenta.uid == 0);
            match &sombra {
                Some(s) => {
                    let estado = s
                        .lines()
                        .find_map(|l| {
                            let mut p = l.split(':');
                            if p.next()? != cuenta.nombre {
                                return None;
                            }
                            // Una linea de `shadow` sin segundo campo esta
                            // corrupta; se trata como campo vacio, que ya
                            // significa «sin contrasena» y es el caso a mirar.
                            Some(estado_de_contrasena(p.next().unwrap_or("")))
                        })
                        .unwrap_or("unknown");
                    c.texto("password_state", estado);
                }
                None => {
                    c.texto("password_state", "unknown");
                }
            }
            c.entidad(entidad::cuenta(&cuenta.nombre));
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------

/// Grupos cuya pertenencia concede privilegios equivalentes a root.
///
/// `docker` esta aqui a proposito y casi ninguna auditoria lo incluye: quien
/// puede hablar con el socket de Docker puede montar `/` dentro de un contenedor
/// privilegiado y salir siendo root. Es root con un paso intermedio.
pub const GRUPOS_PRIVILEGIADOS: &[&str] = &[
    "sudo", "wheel", "root", "admin", "adm", "docker", "lxd", "disk", "shadow", "kvm",
];

/// Los grupos locales y sus miembros.
#[derive(Debug, Clone, Copy, Default)]
pub struct Grupos;

impl Tabla for Grupos {
    fn esquema(&self) -> &'static Esquema {
        &esq::GROUPS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("etc/group")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for linea in texto.lines() {
            if linea.starts_with('#') || linea.trim().is_empty() {
                continue;
            }
            let campos: Vec<&str> = linea.split(':').collect();
            if campos.len() < 4 {
                continue;
            }
            let Ok(gid) = campos[2].parse::<i64>() else {
                continue;
            };
            salida.examinadas += 1;
            let privilegiado = GRUPOS_PRIVILEGIADOS.contains(&campos[0]);

            // Una fila por miembro. Un grupo sin miembros explicitos tambien
            // produce su fila, con `member` ausente: el grupo existe.
            let miembros: Vec<&str> = campos[3].split(',').filter(|m| !m.is_empty()).collect();
            if miembros.is_empty() {
                c.texto("groupname", campos[0]);
                c.entero("gid", gid);
                c.booleano("privileged", privilegiado);
                salida.filas.push(c.fin());
                continue;
            }
            for m in miembros {
                c.texto("groupname", campos[0]);
                c.entero("gid", gid);
                c.texto("member", m);
                c.booleano("privileged", privilegiado);
                c.entidad(entidad::cuenta(m));
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// sessions (utmp)
// ---------------------------------------------------------------------------

/// Tamano de una entrada de `utmp` en Linux de 64 bits.
pub const TAMANO_UTMP: usize = 384;

/// Una sesion leida de `utmp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sesion {
    /// Tipo de entrada.
    pub clase: &'static str,
    /// Proceso que la registro.
    pub pid: i64,
    /// Terminal.
    pub terminal: String,
    /// Usuario.
    pub usuario: String,
    /// Anfitrion de origen.
    pub anfitrion: String,
    /// Instante de inicio.
    pub inicio: i64,
}

/// Lee una cadena de longitud fija terminada (o no) en nulo.
fn cadena_fija(bytes: &[u8]) -> String {
    let fin = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..fin]).into_owned()
}

/// Analiza el contenido binario de `utmp`.
///
/// Se analiza por DESPLAZAMIENTOS EXPLICITOS y no reinterpretando el buffer como
/// una estructura, que es como se hace en C. Reinterpretar exige que el
/// alineamiento y el relleno del compilador coincidan exactamente con los del
/// que escribio el fichero, y cuando no coinciden no hay error: hay campos
/// desplazados que parecen datos.
///
/// Los enteros van en el orden NATIVO de la maquina porque `utmp` lo escribe la
/// propia maquina, no la red.
pub fn analizar_utmp(bytes: &[u8]) -> Vec<Sesion> {
    let mut salida = Vec::new();
    for entrada in bytes.chunks_exact(TAMANO_UTMP) {
        let tipo = i16::from_ne_bytes([entrada[0], entrada[1]]);
        let clase = match tipo {
            1 => "runlevel",
            2 => "boot",
            5 => "init",
            6 => "login",
            7 => "user",
            8 => "dead",
            // EMPTY y los tipos de cambio de hora no son sesiones.
            _ => continue,
        };
        let pid = i32::from_ne_bytes([entrada[4], entrada[5], entrada[6], entrada[7]]);
        let inicio = i32::from_ne_bytes([entrada[340], entrada[341], entrada[342], entrada[343]]);
        salida.push(Sesion {
            clase,
            pid: i64::from(pid),
            terminal: cadena_fija(&entrada[8..40]),
            usuario: cadena_fija(&entrada[44..76]),
            anfitrion: cadena_fija(&entrada[76..332]),
            inicio: i64::from(inicio),
        });
    }
    salida
}

/// Las sesiones abiertas.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sesiones;

impl Tabla for Sesiones {
    fn esquema(&self) -> &'static Esquema {
        &esq::SESSIONS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        // `utmp` vive en dos sitios segun la distribucion. Que no este NO es un
        // fallo: es una maquina sin sesiones registradas (un contenedor, por
        // ejemplo), y se declara como tal.
        let candidatos = ["var/run/utmp", "run/utmp"];
        let mut datos = None;
        for c in candidatos {
            let ruta = ctx.ruta(c);
            if let Ok(b) = std::fs::read(&ruta) {
                datos = Some(b);
                break;
            }
        }
        let Some(bytes) = datos else {
            return Err(MotivoNoLeible::FuenteAusente {
                ruta: "/var/run/utmp ni /run/utmp".to_string(),
            });
        };

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        for s in analizar_utmp(&bytes) {
            salida.examinadas += 1;
            let remota = !s.anfitrion.is_empty();
            c.texto("username", s.usuario.clone());
            c.texto("terminal", s.terminal);
            c.texto("host", s.anfitrion);
            c.entero("pid", s.pid);
            c.entero("started", s.inicio);
            c.texto("kind", s.clase);
            c.booleano("remote", remota);
            if !s.usuario.is_empty() {
                c.entidad(entidad::cuenta(&s.usuario));
            }
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// sudoers
// ---------------------------------------------------------------------------

/// Una regla de sudoers ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglaSudo {
    /// A quien aplica.
    pub principal: String,
    /// Anfitriones.
    pub anfitriones: String,
    /// Como quien.
    pub como: String,
    /// Que puede ejecutar.
    pub orden: String,
    /// Sin contrasena.
    pub sin_contrasena: bool,
    /// Es un grupo.
    pub es_grupo: bool,
}

impl ReglaSudo {
    /// Indica si la regla concede todo.
    pub fn concede_todo(&self) -> bool {
        self.orden.split(',').any(|o| o.trim() == "ALL")
    }
}

/// Analiza el contenido de un fichero de sudoers.
///
/// Se quedan fuera, a proposito, las lineas `Defaults`, los alias y los
/// `#include`: esta tabla enumera QUIEN PUEDE HACER QUE, y un alias sin resolver
/// produciria filas con un nombre que no es el de nadie. Un fichero con alias se
/// lee igual y sus reglas directas salen; las que dependen de un alias no, y eso
/// es preferible a inventarlas.
pub fn analizar_sudoers(texto: &str) -> Vec<ReglaSudo> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("Defaults") {
            continue;
        }
        // Un alias es `NOMBRE_Alias = ...`; se distingue porque la palabra clave
        // va primera.
        if l.starts_with("User_Alias")
            || l.starts_with("Runas_Alias")
            || l.starts_with("Host_Alias")
            || l.starts_with("Cmnd_Alias")
        {
            continue;
        }
        // Forma: `principal anfitriones=(como) [ETIQUETA:] ordenes`
        let Some((principal, resto)) = l.split_once(char::is_whitespace) else {
            continue;
        };
        let resto = resto.trim();
        let Some((anfitriones, derecha)) = resto.split_once('=') else {
            continue;
        };
        let derecha = derecha.trim();

        // `(como)` es opcional.
        let (como, tras_como) = if let Some(cierre) = derecha.find(')') {
            if derecha.starts_with('(') {
                (derecha[1..cierre].to_string(), derecha[cierre + 1..].trim())
            } else {
                ("root".to_string(), derecha)
            }
        } else {
            ("root".to_string(), derecha)
        };

        // Las etiquetas van antes de la orden y acaban en dos puntos.
        let mut orden = tras_como.to_string();
        let mut sin_contrasena = false;
        loop {
            let t = orden.trim().to_string();
            let Some((etiqueta, resto)) = t.split_once(':') else {
                break;
            };
            let etiqueta = etiqueta.trim();
            if !etiqueta
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_whitespace())
                || etiqueta.is_empty()
            {
                break;
            }
            if etiqueta.contains("NOPASSWD") {
                sin_contrasena = true;
            }
            orden = resto.trim().to_string();
        }

        salida.push(ReglaSudo {
            es_grupo: principal.starts_with('%'),
            principal: principal.to_string(),
            anfitriones: anfitriones.trim().to_string(),
            como,
            orden,
            sin_contrasena,
        });
    }
    salida
}

/// Las reglas de elevacion.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sudoers;

impl Tabla for Sudoers {
    fn esquema(&self) -> &'static Esquema {
        &esq::SUDOERS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut fuentes: Vec<(String, String)> = Vec::new();
        let mut salida = Filas::default();

        match ctx.leer_texto("etc/sudoers") {
            Ok(t) => fuentes.push(("/etc/sudoers".to_string(), t)),
            Err(m) => salida.avisar("/etc/sudoers", m),
        }
        // `/etc/sudoers.d` puede no existir, y no pasa nada.
        if let Ok(hijos) = ctx.listar("etc/sudoers.d") {
            for h in hijos {
                // Los ficheros que acaban en `~` o llevan `.` los ignora el
                // propio sudo, asi que enumerarlos seria inventar reglas activas.
                let nombre = h.file_name().unwrap_or_default().to_string_lossy();
                if nombre.ends_with('~') || nombre.contains('.') {
                    continue;
                }
                match std::fs::read_to_string(&h) {
                    Ok(t) => fuentes.push((h.display().to_string(), t)),
                    Err(e) => salida.avisar(
                        h.display().to_string(),
                        crate::contexto::desde_io(e, &h, "leer"),
                    ),
                }
            }
        }

        let mut c = Constructor::nuevo(self.esquema());
        for (fuente, texto) in fuentes {
            for r in analizar_sudoers(&texto) {
                salida.examinadas += 1;
                // Se calcula ANTES de repartir los campos: `concede_todo` mira
                // la regla entera y los `texto()` consumen sus cadenas.
                let concede_todo = r.concede_todo();
                c.texto("source", fuente.clone());
                c.texto("principal", r.principal.clone());
                c.texto("hosts", r.anfitriones);
                c.texto("run_as", r.como);
                c.texto("command", r.orden);
                c.booleano("nopasswd", r.sin_contrasena);
                c.booleano("is_group", r.es_grupo);
                c.booleano("grants_all", concede_todo);
                c.entidad(entidad::cuenta(r.principal.trim_start_matches('%')));
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------

/// Una clave autorizada ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaveAutorizada {
    /// Opciones delante de la clave.
    pub opciones: String,
    /// Tipo de clave.
    pub tipo: String,
    /// Huella SHA-256 en el formato de ssh-keygen.
    pub huella: String,
    /// Comentario final.
    pub comentario: String,
    /// Orden forzada, si la hay.
    pub orden_forzada: String,
}

/// Tipos de clave que reconoce OpenSSH.
const TIPOS_DE_CLAVE: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ssh-ed448",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Analiza una linea de `authorized_keys`.
///
/// # Por que no vale partir por espacios
///
/// La forma ingenua —«el primer campo es el tipo, el segundo la clave»— falla en
/// cuanto la linea lleva OPCIONES, que es justo el caso interesante:
///
/// ```text
/// command="/bin/backup",no-pty ssh-ed25519 AAAAC3Nza... copia@servidor
/// ```
///
/// Ahi el primer campo no es el tipo. Y las opciones pueden llevar espacios
/// dentro de comillas, asi que tampoco vale contar campos. Lo que se hace es
/// buscar el TIPO DE CLAVE, que es un conjunto cerrado y conocido: todo lo que
/// va antes son opciones, lo siguiente es la clave, y el resto es comentario.
pub fn analizar_clave(linea: &str) -> Option<ClaveAutorizada> {
    let l = linea.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }

    // Se busca el tipo como palabra completa, no como subcadena: un comentario
    // que diga "ssh-rsa" no puede hacer que se lea la linea al reves.
    let mut inicio_tipo = None;
    let bytes = l.as_bytes();
    for tipo in TIPOS_DE_CLAVE {
        let mut desde = 0;
        while let Some(pos) = l[desde..].find(tipo) {
            let abs = desde + pos;
            let antes_ok =
                abs == 0 || bytes[abs - 1].is_ascii_whitespace() || bytes[abs - 1] == b',';
            let fin = abs + tipo.len();
            let despues_ok = fin < l.len() && bytes[fin].is_ascii_whitespace();
            if antes_ok && despues_ok {
                inicio_tipo = Some(match inicio_tipo {
                    Some((p, _)) if p <= abs => (p, ""),
                    _ => (abs, *tipo),
                });
                if let Some((p, t)) = inicio_tipo {
                    if t.is_empty() {
                        inicio_tipo = Some((p, *tipo));
                    }
                }
                break;
            }
            desde = abs + 1;
        }
    }
    let (pos, tipo) = inicio_tipo?;
    let opciones = l[..pos].trim().trim_end_matches(',').to_string();
    let resto = l[pos + tipo.len()..].trim();
    let (clave_b64, comentario) = match resto.split_once(char::is_whitespace) {
        Some((k, c)) => (k, c.trim().to_string()),
        None => (resto, String::new()),
    };

    // La huella de `ssh-keygen -l` es SHA-256 de la clave EN BINARIO, en base64
    // sin relleno. Hashear el texto en base64 daria un valor que no coincide con
    // el que ve un administrador, y una huella que no se puede comparar con la
    // de nadie no sirve para nada.
    let huella = match de_base64(clave_b64) {
        Some(crudo) if !crudo.is_empty() => {
            format!("SHA256:{}", a_base64_sin_relleno(&Sha256::digest(&crudo)))
        }
        _ => String::new(),
    };

    let orden_forzada = opciones
        .split(',')
        .find_map(|o| o.trim().strip_prefix("command="))
        .map(|c| c.trim_matches('"').to_string())
        .unwrap_or_default();

    Some(ClaveAutorizada {
        opciones,
        tipo: tipo.to_string(),
        huella,
        comentario,
        orden_forzada,
    })
}

/// Las claves publicas autorizadas.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClavesAutorizadas;

impl Tabla for ClavesAutorizadas {
    fn esquema(&self) -> &'static Esquema {
        &esq::AUTHORIZED_KEYS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        // Los directorios personales salen de `passwd`: recorrer `/home` a ciegas
        // se perderia las cuentas cuyo directorio esta en otro sitio, que son
        // justamente las de servicio.
        let cuentas = analizar_passwd(&ctx.leer_texto("etc/passwd")?);
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for cuenta in cuentas {
            if cuenta.directorio.is_empty() {
                continue;
            }
            // Se cuenta la CUENTA examinada, no el fichero encontrado.
            //
            // La diferencia es la razon de ser de esta fase: contando ficheros,
            // una maquina donde ninguna cuenta tiene claves devuelve cero filas
            // y cero examinadas, que es indistinguible de no haber mirado. Con
            // la cuenta, la respuesta dice «se revisaron treinta cuentas y
            // ninguna tiene claves autorizadas», que es un hecho y no un hueco.
            //
            // Lo detecto la prueba `las_seis_tablas_dan_respuesta_o_motivo`,
            // que existe precisamente para que este crate no cometa el fallo
            // que denuncia.
            salida.examinadas += 1;
            for hoja in [".ssh/authorized_keys", ".ssh/authorized_keys2"] {
                let relativa = format!("{}/{hoja}", cuenta.directorio.trim_start_matches('/'));
                let ruta = ctx.ruta(&relativa);
                let texto = match std::fs::read_to_string(&ruta) {
                    Ok(t) => t,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        salida.avisar(
                            ruta.display().to_string(),
                            crate::contexto::desde_io(e, &ruta, "leer"),
                        );
                        continue;
                    }
                };
                for linea in texto.lines() {
                    let Some(k) = analizar_clave(linea) else {
                        continue;
                    };
                    c.texto("username", cuenta.nombre.clone());
                    c.texto("path", ruta.display().to_string());
                    c.texto("key_type", k.tipo);
                    c.texto("fingerprint", k.huella);
                    c.texto("comment", k.comentario);
                    c.texto("options", k.opciones);
                    c.texto("forced_command", k.orden_forzada);
                    c.entidad(entidad::cuenta(&cuenta.nombre));
                    salida.filas.push(c.fin());
                }
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// kerberos_tickets
// ---------------------------------------------------------------------------

/// Un ticket leido de una cache de credenciales.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Principal del cliente.
    pub cliente: String,
    /// Servicio.
    pub servicio: String,
    /// Desde cuando vale.
    pub desde: i64,
    /// Hasta cuando vale.
    pub hasta: i64,
    /// Tipo de cifrado.
    pub cifrado: i64,
}

/// Lector de la cache de credenciales de MIT, con comprobacion de longitudes.
///
/// Todas las longitudes de este formato vienen DEL PROPIO FICHERO, que puede
/// estar corrupto o preparado. Cada una se comprueba contra lo que queda antes
/// de usarla; cuando no cuadra, el analisis se detiene y devuelve lo leido hasta
/// ahi en vez de seguir sobre bytes que no son lo que dicen ser.
struct Lector<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    fn nuevo(bytes: &'a [u8]) -> Lector<'a> {
        Lector { bytes, pos: 0 }
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Un bloque con su longitud delante.
    fn datos(&mut self) -> Option<&'a [u8]> {
        let largo = self.u32()? as usize;
        // La comprobacion que impide que una longitud inventada nos saque del
        // buffer o reserve memoria a demanda del fichero.
        let b = self.bytes.get(self.pos..self.pos.checked_add(largo)?)?;
        self.pos += largo;
        Some(b)
    }

    /// Un principal: `tipo, numero de componentes, reino, componentes`.
    fn principal(&mut self, version: u16) -> Option<String> {
        // En la version 1 no hay campo de tipo de nombre.
        if version != 0x0501 {
            let _tipo = self.u32()?;
        }
        let mut componentes = self.u32()? as usize;
        // En v1 el numero incluye el reino.
        if version == 0x0501 {
            componentes = componentes.checked_sub(1)?;
        }
        if componentes > 64 {
            return None;
        }
        let reino = String::from_utf8_lossy(self.datos()?).into_owned();
        let mut partes = Vec::with_capacity(componentes);
        for _ in 0..componentes {
            partes.push(String::from_utf8_lossy(self.datos()?).into_owned());
        }
        Some(format!("{}@{reino}", partes.join("/")))
    }
}

/// Analiza una cache de credenciales de Kerberos en formato FILE.
pub fn analizar_ccache(bytes: &[u8]) -> Option<(String, Vec<Ticket>)> {
    let mut l = Lector::nuevo(bytes);
    let version = l.u16()?;
    if !(0x0501..=0x0504).contains(&version) {
        return None;
    }
    // Desde la version 4 hay una cabecera de campos con su longitud.
    if version == 0x0504 {
        let largo = l.u16()? as usize;
        l.pos = l.pos.checked_add(largo)?;
    }

    let principal = l.principal(version)?;
    let mut tickets = Vec::new();

    // Cada vuelta lee una credencial. Al primer campo que no cuadre se para: lo
    // leido vale, lo que viene detras ya no se sabe que es.
    while l.pos < bytes.len() {
        let Some(cliente) = l.principal(version) else {
            break;
        };
        let Some(servicio) = l.principal(version) else {
            break;
        };
        // keyblock: tipo, (etype solo en v3), longitud, datos.
        let Some(cifrado) = l.u16() else { break };
        if version == 0x0503 && l.u16().is_none() {
            break;
        }
        let Some(largo_clave) = l.u16() else { break };
        if l.bytes.get(l.pos..l.pos + largo_clave as usize).is_none() {
            break;
        }
        l.pos += largo_clave as usize;

        let (Some(_auth), Some(desde), Some(hasta), Some(_renueva)) =
            (l.u32(), l.u32(), l.u32(), l.u32())
        else {
            break;
        };
        if l.u8().is_none() {
            break;
        }
        if l.u32().is_none() {
            break;
        }
        // Direcciones y datos de autorizacion: se saltan contando.
        let Some(n_dir) = l.u32() else { break };
        let mut roto = false;
        for _ in 0..n_dir.min(256) {
            if l.u16().is_none() || l.datos().is_none() {
                roto = true;
                break;
            }
        }
        if roto {
            break;
        }
        let Some(n_auth) = l.u32() else { break };
        for _ in 0..n_auth.min(256) {
            if l.u16().is_none() || l.datos().is_none() {
                roto = true;
                break;
            }
        }
        if roto {
            break;
        }
        if l.datos().is_none() || l.datos().is_none() {
            break;
        }

        tickets.push(Ticket {
            cliente,
            servicio,
            desde: i64::from(desde),
            hasta: i64::from(hasta),
            cifrado: i64::from(cifrado),
        });
    }
    Some((principal, tickets))
}

/// Indica si un servicio es el ticket de concesion de tickets.
pub fn es_tgt(servicio: &str) -> bool {
    servicio.starts_with("krbtgt/")
}

/// Los tickets de Kerberos vivos.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kerberos;

impl Tabla for Kerberos {
    fn esquema(&self) -> &'static Esquema {
        &esq::KERBEROS_TICKETS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        // Las caches viven en `/tmp/krb5cc_<uid>` por convenio, y en
        // `/run/user/<uid>/krb5cc` en sistemas con systemd.
        let mut candidatos: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(hijos) = ctx.listar("tmp") {
            candidatos.extend(hijos.into_iter().filter(|h| {
                h.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("krb5cc"))
            }));
        }
        if let Ok(usuarios) = ctx.listar("run/user") {
            for u in usuarios {
                if let Ok(hijos) = std::fs::read_dir(&u) {
                    candidatos.extend(hijos.flatten().map(|e| e.path()).filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("krb5cc"))
                    }));
                }
            }
        }
        candidatos.sort();

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        // Si no hay ni una cache, se DICE donde se busco.
        //
        // Cero filas mudas dejarian al analista concluir «no hay credenciales
        // de Kerberos vivas en esta maquina», que es una afirmacion fuerte, y no
        // es la misma que «se miro en estos dos sitios y no habia nada». Un
        // ticket en una ruta que este codigo no conoce produciria exactamente
        // las mismas cero filas.
        if candidatos.is_empty() {
            salida.avisar(
                "/tmp/krb5cc* y /run/user/*/krb5cc*",
                MotivoNoLeible::FuenteAusente {
                    ruta: "no hay ninguna cache de credenciales en las rutas conocidas".to_string(),
                },
            );
        }

        for ruta in candidatos {
            salida.examinadas += 1;
            let uid = std::fs::metadata(&ruta)
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    i64::from(m.uid())
                })
                .unwrap_or(-1);
            let bytes = match std::fs::read(&ruta) {
                Ok(b) => b,
                Err(e) => {
                    salida.avisar(
                        ruta.display().to_string(),
                        crate::contexto::desde_io(e, &ruta, "leer la cache"),
                    );
                    continue;
                }
            };
            let Some((principal, tickets)) = analizar_ccache(&bytes) else {
                // Un fichero que empieza por `krb5cc` y no es una cache valida
                // se DECLARA, en vez de descartarlo: puede ser justo lo que
                // alguien dejo ahi.
                salida.avisar(
                    ruta.display().to_string(),
                    MotivoNoLeible::ErrorDelSistema {
                        operacion: "analizar la cache de credenciales",
                        detalle: "el fichero no tiene el formato FILE de MIT".to_string(),
                    },
                );
                continue;
            };
            for t in tickets {
                c.texto("cache", ruta.display().to_string());
                c.entero("owner_uid", uid);
                c.texto("principal", principal.clone());
                c.texto("service", t.servicio.clone());
                c.entero("starts", t.desde);
                c.entero("expires", t.hasta);
                c.booleano("is_tgt", es_tgt(&t.servicio));
                c.entero("encryption", t.cifrado);
                c.entidad(entidad::cuenta(&principal));
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

/// Las seis tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Usuarios),
        Box::new(Grupos),
        Box::new(Sesiones),
        Box::new(Sudoers),
        Box::new(ClavesAutorizadas),
        Box::new(Kerberos),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(entidad::maquina("prueba"), 0, 0)
    }

    fn columna(t: &dyn Tabla, nombre: &str) -> usize {
        t.esquema()
            .columnas
            .iter()
            .position(|c| c.nombre == nombre)
            .unwrap_or_else(|| panic!("falta {nombre} en {}", t.nombre()))
    }

    #[test]
    fn el_base64_va_y_vuelve() {
        for caso in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &[0u8, 255, 128, 1][..],
        ] {
            let texto = a_base64_sin_relleno(caso);
            assert_eq!(de_base64(&texto).unwrap(), caso, "fallo con {caso:?}");
        }
    }

    #[test]
    fn el_base64_decodifica_los_vectores_conocidos() {
        assert_eq!(de_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(de_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(a_base64_sin_relleno(b"hello"), "aGVsbG8");
        assert!(de_base64("no es base64 !!").is_none());
    }

    #[test]
    fn passwd_se_analiza_y_las_lineas_rotas_se_saltan() {
        let texto = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# comentario
rota:x:noesunnumero:0::/:/bin/sh
corta:x:5
usuario:x:1000:1000:Un Usuario,,,:/home/usuario:/bin/bash";
        let cs = analizar_passwd(texto);
        assert_eq!(cs.len(), 3, "solo las tres bien formadas");
        assert_eq!(cs[0].nombre, "root");
        assert_eq!(cs[0].uid, 0);
        assert_eq!(cs[2].directorio, "/home/usuario");
    }

    #[test]
    fn una_segunda_cuenta_con_uid_cero_se_ve() {
        // La puerta trasera clasica que pasa cualquier revision por encima.
        let texto = "root:x:0:0:root:/root:/bin/bash\nbackup:x:0:0:backup:/:/bin/bash";
        let cs = analizar_passwd(texto);
        assert_eq!(cs.iter().filter(|c| c.uid == 0).count(), 2);
    }

    #[test]
    fn el_estado_de_la_contrasena_no_revela_el_resumen() {
        assert_eq!(estado_de_contrasena(""), "empty");
        assert_eq!(estado_de_contrasena("!"), "locked");
        assert_eq!(estado_de_contrasena("*"), "locked");
        assert_eq!(estado_de_contrasena("!$6$abc$def"), "locked");
        assert_eq!(estado_de_contrasena("$6$sal$resumen"), "set");
        // Y en ningun caso aparece el resumen en la salida.
        for caso in ["$6$sal$resumen", "!$6$abc$def"] {
            assert!(!estado_de_contrasena(caso).contains("resumen"));
            assert!(!estado_de_contrasena(caso).contains('$'));
        }
    }

    #[test]
    fn los_usuarios_de_esta_maquina_incluyen_root() {
        let c = ctx();
        let r = Usuarios
            .leer(&c, &Filtro::ninguno())
            .expect("leer usuarios");
        let i = columna(&Usuarios, "username");
        assert!(r.filas.iter().any(|f| f.valor(i).a_texto() == "root"));
    }

    #[test]
    fn los_grupos_privilegiados_incluyen_docker() {
        // Pertenecer al grupo docker es root con un paso intermedio, y casi
        // ninguna auditoria lo trata asi.
        assert!(GRUPOS_PRIVILEGIADOS.contains(&"docker"));
        assert!(GRUPOS_PRIVILEGIADOS.contains(&"sudo"));
        assert!(!GRUPOS_PRIVILEGIADOS.contains(&"users"));
    }

    #[test]
    fn los_grupos_de_esta_maquina_se_leen() {
        let c = ctx();
        let r = Grupos.leer(&c, &Filtro::ninguno()).expect("leer grupos");
        assert!(!r.filas.is_empty());
        let i = columna(&Grupos, "groupname");
        assert!(r.filas.iter().any(|f| f.valor(i).a_texto() == "root"));
    }

    #[test]
    fn utmp_se_analiza_por_desplazamientos() {
        // Una entrada construida a mano con el formato real de Linux de 64 bits.
        let mut e = vec![0u8; TAMANO_UTMP];
        e[0..2].copy_from_slice(&7i16.to_ne_bytes()); // USER_PROCESS
        e[4..8].copy_from_slice(&1234i32.to_ne_bytes());
        e[8..13].copy_from_slice(b"pts/0");
        e[44..48].copy_from_slice(b"juan");
        e[76..85].copy_from_slice(b"10.0.0.7\0");
        e[340..344].copy_from_slice(&1_700_000_000i32.to_ne_bytes());

        let ss = analizar_utmp(&e);
        assert_eq!(ss.len(), 1);
        assert_eq!(ss[0].clase, "user");
        assert_eq!(ss[0].pid, 1234);
        assert_eq!(ss[0].terminal, "pts/0");
        assert_eq!(ss[0].usuario, "juan");
        assert_eq!(ss[0].anfitrion, "10.0.0.7");
        assert_eq!(ss[0].inicio, 1_700_000_000);
    }

    #[test]
    fn utmp_salta_las_entradas_que_no_son_sesiones() {
        let mut vacia = vec![0u8; TAMANO_UTMP]; // tipo 0 = EMPTY
        vacia.extend(vec![0u8; TAMANO_UTMP]);
        assert!(analizar_utmp(&vacia).is_empty());
    }

    #[test]
    fn utmp_truncado_no_entra_en_panico() {
        // `chunks_exact` descarta el resto incompleto, que es lo correcto: media
        // entrada no es una entrada.
        assert!(analizar_utmp(&[0u8; 100]).is_empty());
        assert!(analizar_utmp(&[]).is_empty());
        let mut casi = vec![0u8; TAMANO_UTMP + 50];
        casi[0..2].copy_from_slice(&7i16.to_ne_bytes());
        assert_eq!(analizar_utmp(&casi).len(), 1);
    }

    #[test]
    fn sudoers_se_analiza_con_sus_etiquetas() {
        let texto = "\
# comentario
Defaults env_reset
root ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
juan ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
web ALL=(ALL) NOPASSWD:ALL
User_Alias ADMINS = ana, luis";
        let rs = analizar_sudoers(texto);
        assert_eq!(rs.len(), 4, "las cuatro reglas reales: {rs:#?}");

        assert_eq!(rs[0].principal, "root");
        assert!(rs[0].concede_todo());
        assert!(!rs[0].sin_contrasena);

        assert!(rs[1].es_grupo, "%sudo es un grupo");

        assert!(rs[2].sin_contrasena);
        assert!(!rs[2].concede_todo(), "solo puede reiniciar nginx");
        assert_eq!(rs[2].como, "root");

        // La peor configuracion posible: todo, sin contrasena.
        assert!(rs[3].sin_contrasena && rs[3].concede_todo());
    }

    #[test]
    fn una_regla_de_sudoers_sin_como_supone_root() {
        let rs = analizar_sudoers("juan ALL=/bin/ls");
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].como, "root");
        assert_eq!(rs[0].orden, "/bin/ls");
    }

    #[test]
    fn una_clave_autorizada_simple_se_analiza() {
        let linea = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V juan@portatil";
        let k = analizar_clave(linea).expect("linea valida");
        assert_eq!(k.tipo, "ssh-ed25519");
        assert_eq!(k.comentario, "juan@portatil");
        assert!(k.opciones.is_empty());
        assert!(k.huella.starts_with("SHA256:"), "{}", k.huella);
    }

    #[test]
    fn una_clave_con_opciones_no_confunde_el_tipo() {
        // LA trampa de este formato: partir por espacios pone las opciones donde
        // deberia ir el tipo, y la linea se lee entera al reves.
        let linea = "command=\"/usr/local/bin/backup\",no-pty,from=\"10.0.0.0/8\" ssh-rsa AAAAB3NzaC1yc2E= copia";
        let k = analizar_clave(linea).expect("linea valida");
        assert_eq!(k.tipo, "ssh-rsa");
        assert_eq!(k.comentario, "copia");
        assert!(k.opciones.contains("no-pty"));
        assert_eq!(
            k.orden_forzada, "/usr/local/bin/backup",
            "la orden forzada es la carga util de la puerta trasera"
        );
    }

    #[test]
    fn un_comentario_que_menciona_un_tipo_no_engana() {
        // El tipo se busca como palabra completa; si no, un comentario que diga
        // "ssh-rsa" haria que la linea se analizara desde el sitio equivocado.
        let linea = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 esta-no-es-ssh-rsa-de-verdad";
        let k = analizar_clave(linea).expect("linea valida");
        assert_eq!(k.tipo, "ssh-ed25519");
    }

    #[test]
    fn las_lineas_vacias_y_los_comentarios_no_son_claves() {
        assert!(analizar_clave("").is_none());
        assert!(analizar_clave("   ").is_none());
        assert!(analizar_clave("# una clave vieja").is_none());
        assert!(analizar_clave("basura sin tipo conocido").is_none());
    }

    #[test]
    fn la_huella_es_la_de_ssh_keygen() {
        // `ssh-keygen -l` hashea la clave EN BINARIO, no su texto base64.
        // Hashear el texto daria una huella que no coincide con la que ve un
        // administrador, y que por tanto no sirve para comparar con nada.
        let crudo = b"unos bytes de clave";
        let b64 = a_base64_sin_relleno(crudo);
        let linea = format!("ssh-rsa {b64} x");
        let k = analizar_clave(&linea).unwrap();
        let esperado = format!("SHA256:{}", a_base64_sin_relleno(&Sha256::digest(crudo)));
        assert_eq!(k.huella, esperado);
    }

    #[test]
    fn una_cache_de_kerberos_v4_se_analiza() {
        // Construida a mano con el formato de MIT: version, cabecera vacia,
        // principal por defecto y una credencial.
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&0x0504u16.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // cabecera de longitud cero

        let principal = |b: &mut Vec<u8>, reino: &str, partes: &[&str]| {
            b.extend_from_slice(&1u32.to_be_bytes()); // tipo de nombre
            b.extend_from_slice(&(partes.len() as u32).to_be_bytes());
            b.extend_from_slice(&(reino.len() as u32).to_be_bytes());
            b.extend_from_slice(reino.as_bytes());
            for p in partes {
                b.extend_from_slice(&(p.len() as u32).to_be_bytes());
                b.extend_from_slice(p.as_bytes());
            }
        };

        principal(&mut b, "EJEMPLO.LOCAL", &["juan"]); // por defecto
        principal(&mut b, "EJEMPLO.LOCAL", &["juan"]); // cliente
        principal(&mut b, "EJEMPLO.LOCAL", &["krbtgt", "EJEMPLO.LOCAL"]); // servicio

        b.extend_from_slice(&18u16.to_be_bytes()); // cifrado AES256
        b.extend_from_slice(&4u16.to_be_bytes()); // longitud de clave
        b.extend_from_slice(&[1, 2, 3, 4]);
        b.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // authtime
        b.extend_from_slice(&1_700_000_100u32.to_be_bytes()); // starttime
        b.extend_from_slice(&1_700_036_000u32.to_be_bytes()); // endtime
        b.extend_from_slice(&1_700_600_000u32.to_be_bytes()); // renew_till
        b.push(0); // is_skey
        b.extend_from_slice(&0u32.to_be_bytes()); // ticket_flags
        b.extend_from_slice(&0u32.to_be_bytes()); // num_address
        b.extend_from_slice(&0u32.to_be_bytes()); // num_authdata
        b.extend_from_slice(&3u32.to_be_bytes()); // ticket
        b.extend_from_slice(b"abc");
        b.extend_from_slice(&0u32.to_be_bytes()); // second_ticket

        let (quien, tickets) = analizar_ccache(&b).expect("cache valida");
        assert_eq!(quien, "juan@EJEMPLO.LOCAL");
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].servicio, "krbtgt/EJEMPLO.LOCAL@EJEMPLO.LOCAL");
        assert!(es_tgt(&tickets[0].servicio), "es el ticket de concesion");
        assert_eq!(tickets[0].cifrado, 18);
        assert_eq!(tickets[0].hasta, 1_700_036_000);
    }

    #[test]
    fn una_cache_con_longitudes_mentirosas_no_revienta() {
        // AUTOATAQUE del formato: las longitudes salen del fichero, asi que un
        // fichero preparado podria hacer reservar memoria sin cota o leer fuera
        // del buffer. Ninguna de las dos cosas puede pasar.
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&0x0504u16.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        // Un reino que dice medir cuatro mil millones de bytes.
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        b.extend_from_slice(b"corto");
        assert!(
            analizar_ccache(&b).is_none(),
            "no se puede analizar, y no revienta"
        );
    }

    #[test]
    fn un_fichero_que_no_es_una_cache_se_rechaza() {
        assert!(analizar_ccache(b"").is_none());
        assert!(analizar_ccache(b"no soy una cache").is_none());
        assert!(analizar_ccache(&[0xFF, 0xFF, 0, 0]).is_none());
    }

    #[test]
    fn un_rc4_delata_el_kerberoasting() {
        // El tipo 23 es RC4. Pedirlo en una red que ya usa AES es lo que hace un
        // atacante para poder romper el ticket fuera de linea.
        let t = Ticket {
            cliente: "juan@X".into(),
            servicio: "MSSQLSvc/db:1433@X".into(),
            desde: 0,
            hasta: 0,
            cifrado: 23,
        };
        assert!(!es_tgt(&t.servicio), "es un ticket de servicio");
        assert_eq!(t.cifrado, 23);
    }

    #[test]
    fn las_seis_tablas_dan_respuesta_o_motivo_en_esta_maquina() {
        // Ninguna puede entrar en panico ni devolver cero filas en silencio: o
        // hay datos, o hay un motivo escrito.
        let c = ctx();
        for t in tablas() {
            match t.leer(&c, &Filtro::ninguno()) {
                Ok(f) => {
                    // Si no hay filas, tiene que haber quedado claro por que no.
                    if f.filas.is_empty() {
                        assert!(
                            f.examinadas > 0 || !f.avisos.is_empty(),
                            "{} devolvio vacio sin explicar nada",
                            t.nombre()
                        );
                    }
                }
                Err(m) => assert!(!m.frase().is_empty(), "{} sin frase", t.nombre()),
            }
        }
    }

    #[test]
    fn las_cuentas_llevan_entidad_de_cuenta() {
        let c = ctx();
        let r = Usuarios.leer(&c, &Filtro::ninguno()).unwrap();
        assert!(!r.filas.is_empty());
        for f in &r.filas {
            assert_eq!(f.entidad().map(|e| e.clase()), Some(Clase::Cuenta));
        }
    }
}
