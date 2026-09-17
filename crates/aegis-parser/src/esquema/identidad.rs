//! Tablas de identidad anadidas por la FASE 81.
//!
//! # Por que estas seis y no las de `getpwent`
//!
//! La forma «correcta» de enumerar usuarios en Unix es la familia
//! `getpwent`/`getgrent`, que pasa por NSS y por tanto puede consultar LDAP,
//! SSSD o lo que el cliente tenga configurado. Un EDR no puede hacer eso: una
//! consulta de caza no puede quedarse colgada tres segundos porque el servidor
//! de directorio no contesta, multiplicado por cien mil endpoints.
//!
//! Aqui se leen los FICHEROS —`/etc/passwd`, `/etc/group`, `/etc/sudoers`—, que
//! es una lectura acotada, sin red y sin bloqueo. El precio es real y se
//! declara: en una maquina unida a un dominio, estas tablas ven las cuentas
//! locales y no las del directorio. Lo dice la descripcion de cada tabla, y la
//! diferencia entre decirlo y no decirlo es que un informe concluya «solo hay
//! tres usuarios» en una maquina con cuatro mil.
//!
//! # La que mas incidentes cierra
//!
//! [`AUTHORIZED_KEYS`]. Una clave publica anadida al `authorized_keys` de root
//! es la persistencia mas limpia que existe: no es un proceso, no es un fichero
//! ejecutable, no toca el registro de nada, sobrevive a reinicios y a
//! actualizaciones, y ningun antivirus la mira. Es una linea de texto.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------
const COLUMNAS_USUARIOS: &[Columna] = &[
    Columna {
        nombre: "username",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre de la cuenta",
    },
    Columna {
        nombre: "uid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "identificador de usuario",
    },
    Columna {
        nombre: "gid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "grupo principal",
    },
    Columna {
        nombre: "description",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "campo GECOS",
    },
    Columna {
        nombre: "directory",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "directorio personal",
    },
    Columna {
        nombre: "shell",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "interprete de arranque; nologin significa que no inicia sesion",
    },
    Columna {
        nombre: "can_login",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "su interprete permite iniciar sesion",
    },
    Columna {
        nombre: "is_root",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "uid 0; puede haber MAS DE UNA cuenta con uid 0, y eso es el hallazgo",
    },
    Columna {
        nombre: "password_state",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "set, locked, empty o unknown, leido de shadow sin revelar el resumen",
    },
];

/// Una cuenta local.
///
/// `is_root` no es redundante con `uid = 0`: existe para que la consulta que
/// importa —«hay mas de una cuenta con uid 0»— se escriba sin conocer el
/// convenio. Una segunda cuenta con uid 0 y nombre inocente es una puerta
/// trasera clasica que pasa cualquier revision por encima.
///
/// `password_state` dice si la cuenta tiene contrasena, esta bloqueada o la
/// tiene VACIA —que es una via de entrada— sin exponer jamas el resumen: el
/// hash de `/etc/shadow` no sale de la maquina por esta tabla.
pub const USERS: Tabla = Tabla {
    nombre: "users",
    columnas: COLUMNAS_USUARIOS,
    descripcion: "una cuenta local de /etc/passwd (no incluye cuentas de directorio)",
};

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------
const COLUMNAS_GRUPOS: &[Columna] = &[
    Columna {
        nombre: "groupname",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del grupo",
    },
    Columna {
        nombre: "gid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "identificador de grupo",
    },
    Columna {
        nombre: "member",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "un miembro; hay una fila por miembro, no una lista en una celda",
    },
    Columna {
        nombre: "privileged",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "pertenecer a el da privilegios: sudo, wheel, docker, adm, disk",
    },
];

/// La pertenencia de una cuenta a un grupo.
///
/// Una fila por MIEMBRO y no una lista separada por comas: `WHERE member =
/// 'www-data' AND privileged` es una consulta; buscar una subcadena dentro de
/// una celda con comas encuentra tambien a `www-data-backup`.
///
/// `privileged` incluye `docker` a proposito: pertenecer al grupo docker es
/// equivalente a ser root —se monta `/` en un contenedor y se acabo—, y casi
/// ninguna auditoria lo trata como tal.
pub const GROUPS: Tabla = Tabla {
    nombre: "groups",
    columnas: COLUMNAS_GRUPOS,
    descripcion: "la pertenencia de una cuenta a un grupo local, una fila por miembro",
};

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------
const COLUMNAS_SESIONES: &[Columna] = &[
    Columna {
        nombre: "username",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "quien inicio la sesion",
    },
    Columna {
        nombre: "terminal",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "terminal o pseudoterminal",
    },
    Columna {
        nombre: "host",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "de donde vino; vacio si es local",
    },
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso que registro la sesion",
    },
    Columna {
        nombre: "started",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "instante de inicio, en segundos desde la epoca",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "user, boot, runlevel, login o dead",
    },
    Columna {
        nombre: "remote",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "la sesion viene de otra maquina",
    },
];

/// Una sesion abierta.
///
/// Se lee de `utmp`, que es un fichero binario que cualquiera con privilegios
/// puede reescribir —y que los atacantes reescriben para borrar su sesion—. Por
/// eso esta tabla vale para ver quien esta, y NO vale como prueba de quien
/// estuvo: para eso esta la linea temporal forense de la FASE 82.
pub const SESSIONS: Tabla = Tabla {
    nombre: "sessions",
    columnas: COLUMNAS_SESIONES,
    descripcion: "una sesion abierta segun utmp (que un atacante con privilegios puede reescribir)",
};

// ---------------------------------------------------------------------------
// sudoers
// ---------------------------------------------------------------------------
const COLUMNAS_SUDOERS: &[Columna] = &[
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero del que sale la regla",
    },
    Columna {
        nombre: "principal",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "a quien aplica: un usuario, o un grupo si empieza por %",
    },
    Columna {
        nombre: "hosts",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "en que anfitriones vale la regla",
    },
    Columna {
        nombre: "run_as",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "como quien puede ejecutar",
    },
    Columna {
        nombre: "command",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "que puede ejecutar; ALL es todo",
    },
    Columna {
        nombre: "nopasswd",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "sin pedir contrasena",
    },
    Columna {
        nombre: "is_group",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "la regla aplica a un grupo entero",
    },
    Columna {
        nombre: "grants_all",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "concede ALL como cualquiera: es root con otro nombre",
    },
];

/// Una regla de elevacion de privilegios.
///
/// `grants_all` y `nopasswd` juntos describen la configuracion mas peligrosa que
/// existe en una maquina Unix, y son dos columnas booleanas justamente para que
/// la consulta que las busca quepa en una linea y no dependa de que alguien sepa
/// leer la sintaxis de sudoers.
pub const SUDOERS: Tabla = Tabla {
    nombre: "sudoers",
    columnas: COLUMNAS_SUDOERS,
    descripcion: "una regla de sudoers, con si concede todo y si pide contrasena",
};

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------
const COLUMNAS_CLAVES: &[Columna] = &[
    Columna {
        nombre: "username",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "cuenta en cuyo authorized_keys esta la clave",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero del que sale",
    },
    Columna {
        nombre: "key_type",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256...",
    },
    Columna {
        nombre: "fingerprint",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "huella SHA-256 de la clave, en el formato de ssh-keygen",
    },
    Columna {
        nombre: "comment",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "comentario final, que suele decir de quien es",
    },
    Columna {
        nombre: "options",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "opciones delante de la clave: command=, from=, no-pty...",
    },
    Columna {
        nombre: "forced_command",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "el command= forzado, si lo hay: se ejecuta pase lo que pase",
    },
];

/// Una clave publica autorizada para entrar por SSH.
///
/// La persistencia mas limpia que existe: no es un proceso, no es un ejecutable,
/// sobrevive a reinicios y a actualizaciones, y ningun antivirus mira un fichero
/// de texto con una clave publica. `forced_command` esta aparte porque una clave
/// con `command=` ejecuta ESO y nada mas al conectar, lo que la convierte en una
/// puerta trasera con carga util incluida.
pub const AUTHORIZED_KEYS: Tabla = Tabla {
    nombre: "authorized_keys",
    columnas: COLUMNAS_CLAVES,
    descripcion: "una clave publica que puede entrar por SSH, con su huella y su command forzado",
};

// ---------------------------------------------------------------------------
// kerberos_tickets
// ---------------------------------------------------------------------------
const COLUMNAS_KERBEROS: &[Columna] = &[
    Columna {
        nombre: "cache",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero de cache de credenciales",
    },
    Columna {
        nombre: "owner_uid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "dueno del fichero de cache",
    },
    Columna {
        nombre: "principal",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "principal por defecto de la cache: usuario@REINO",
    },
    Columna {
        nombre: "service",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "servicio del ticket; krbtgt/REINO@REINO es el ticket de concesion",
    },
    Columna {
        nombre: "starts",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "desde cuando vale",
    },
    Columna {
        nombre: "expires",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "hasta cuando vale",
    },
    Columna {
        nombre: "is_tgt",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "es el ticket de concesion: con el se piden todos los demas",
    },
    Columna {
        nombre: "encryption",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "tipo de cifrado; 23 es RC4 y delata un ataque de kerberoasting",
    },
];

/// Un ticket de Kerberos vivo en la maquina.
///
/// Un TGT robado de una cache es movimiento lateral sin contrasena, y las caches
/// viven en ficheros que un proceso con los privilegios adecuados puede copiar.
/// `encryption` merece su columna: un ticket de servicio con RC4 (tipo 23) en
/// una red que ya usa AES es la firma de un intento de kerberoasting, porque el
/// atacante PIDE ese cifrado a proposito para poder romperlo fuera de linea.
pub const KERBEROS_TICKETS: Tabla = Tabla {
    nombre: "kerberos_tickets",
    columnas: COLUMNAS_KERBEROS,
    descripcion: "un ticket de Kerberos vivo, con su caducidad y su tipo de cifrado",
};
