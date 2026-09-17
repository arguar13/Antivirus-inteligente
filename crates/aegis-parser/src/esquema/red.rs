//! Tablas de red anadidas por la FASE 81.
//!
//! `connections` —sockets TCP y UDP con su proceso— ya existia y esta en
//! [`super::nucleo`]. Estas cinco son lo que faltaba para poder responder a
//! «como esta conectada esta maquina» sin salir del producto: por donde sale el
//! trafico, con que interfaces, a que vecinos ve, que corta el cortafuegos, y
//! que canales locales hay abiertos.
//!
//! # El hueco que cierra `unix_sockets`
//!
//! De las cinco, la menos evidente es la que mas gana: un socket de dominio
//! UNIX no aparece en `connections`, no lo ve un cortafuegos, no lo registra un
//! IDS de red y no sale en `netstat -tn`. Y es por donde habla un contenedor con
//! su runtime, por donde un implante habla con su parte residente, y por donde
//! se pide a `systemd` que arranque algo. Un EDR que no los enumera tiene un
//! punto ciego del tamaño de toda la comunicacion local de la maquina.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------
const COLUMNAS_RUTAS: &[Columna] = &[
    Columna {
        nombre: "destination",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "red de destino; 0.0.0.0 es la ruta por defecto",
    },
    Columna {
        nombre: "netmask",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "mascara de red",
    },
    Columna {
        nombre: "gateway",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "por donde se sale; 0.0.0.0 si es directa",
    },
    Columna {
        nombre: "interface",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "interfaz de salida",
    },
    Columna {
        nombre: "metric",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "metrica; la mas baja gana cuando dos rutas compiten",
    },
    Columna {
        nombre: "family",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ipv4 o ipv6",
    },
    Columna {
        nombre: "is_default",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "es la ruta por defecto",
    },
];

/// Una ruta de la tabla de encaminamiento.
///
/// Una ruta por defecto que cambia, o una ruta mas especifica hacia una red que
/// nadie declaro, es como se ve un secuestro de trafico desde el endpoint.
pub const ROUTES: Tabla = Tabla {
    nombre: "routes",
    columnas: COLUMNAS_RUTAS,
    descripcion: "una ruta de la tabla de encaminamiento del sistema",
};

// ---------------------------------------------------------------------------
// interfaces
// ---------------------------------------------------------------------------
const COLUMNAS_INTERFACES: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre de la interfaz",
    },
    Columna {
        nombre: "mac",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion fisica",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "up, down, unknown...",
    },
    Columna {
        nombre: "mtu",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "unidad maxima de transmision",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ethernet, loopback, tunnel, bridge, veth, wireguard u other",
    },
    Columna {
        nombre: "promiscuous",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "en modo promiscuo: alguien esta capturando todo el trafico del segmento",
    },
    Columna {
        nombre: "rx_bytes",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "bytes recibidos desde el arranque",
    },
    Columna {
        nombre: "tx_bytes",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "bytes enviados desde el arranque",
    },
];

/// Una interfaz de red.
///
/// `promiscuous` y `kind` son las dos columnas que hacen deteccion: una interfaz
/// en promiscuo que nadie puso es un capturador de trafico, y un `tunnel` o un
/// `wireguard` que aparece sin que nadie lo haya desplegado es un tunel de
/// salida.
pub const INTERFACES: Tabla = Tabla {
    nombre: "interfaces",
    columnas: COLUMNAS_INTERFACES,
    descripcion: "una interfaz de red, con su modo y su contabilidad",
};

// ---------------------------------------------------------------------------
// arp_cache
// ---------------------------------------------------------------------------
const COLUMNAS_ARP: &[Columna] = &[
    Columna {
        nombre: "address",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion IP del vecino",
    },
    Columna {
        nombre: "mac",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion fisica asociada",
    },
    Columna {
        nombre: "interface",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "interfaz por la que se le ve",
    },
    Columna {
        nombre: "flags",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "banderas de la entrada, en hexadecimal",
    },
    Columna {
        nombre: "permanent",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "entrada estatica, puesta a mano y que no caduca",
    },
];

/// Una entrada de la tabla de vecinos.
///
/// Dos direcciones IP con la MISMA direccion fisica es la firma clasica de un
/// envenenamiento ARP, y es una consulta que se escribe en una linea sobre esta
/// tabla.
pub const ARP_CACHE: Tabla = Tabla {
    nombre: "arp_cache",
    columnas: COLUMNAS_ARP,
    descripcion: "un vecino de la red local visto por esta maquina",
};

// ---------------------------------------------------------------------------
// firewall_rules
// ---------------------------------------------------------------------------
const COLUMNAS_CORTAFUEGOS: &[Columna] = &[
    Columna {
        nombre: "backend",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nftables o iptables-legacy",
    },
    Columna {
        nombre: "table",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "tabla a la que pertenece",
    },
    Columna {
        nombre: "chain",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "cadena",
    },
    Columna {
        nombre: "rule",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "la regla tal y como la escribe el sistema",
    },
    Columna {
        nombre: "position",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "posicion dentro de la cadena; el orden decide cual se aplica",
    },
    Columna {
        nombre: "is_ours",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "la puso AegisCore; lo demas es politica del cliente o de un tercero",
    },
];

/// Una regla del cortafuegos del sistema.
///
/// `is_ours` existe por una razon operativa concreta: AegisCore tiene su propia
/// tabla de bloqueo (`aegis_scal`), y un analista que vea una regla de bloqueo
/// tiene que poder distinguir en un vistazo la que puso el producto de la que
/// puso el cliente —o de la que puso un atacante para abrirse un camino—.
pub const FIREWALL_RULES: Tabla = Tabla {
    nombre: "firewall_rules",
    columnas: COLUMNAS_CORTAFUEGOS,
    descripcion: "una regla del cortafuegos del sistema, sea de quien sea",
};

// ---------------------------------------------------------------------------
// unix_sockets
// ---------------------------------------------------------------------------
const COLUMNAS_UNIX: &[Columna] = &[
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ruta del socket; vacia si es anonimo o abstracto",
    },
    Columna {
        nombre: "inode",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "inodo, que es lo que lo une con el proceso que lo tiene abierto",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "listening, connected, connecting o disconnected",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "stream, datagram o seqpacket",
    },
    Columna {
        nombre: "abstract_ns",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "vive en el espacio abstracto: no tiene fichero y no deja rastro en disco",
    },
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Medio,
        descripcion: "proceso que lo tiene abierto, cruzando inodos con /proc",
    },
];

/// Un socket de dominio UNIX.
///
/// `abstract_ns` es la columna que justifica la tabla: un socket abstracto no
/// existe en el sistema de ficheros, asi que ninguna tabla de ficheros lo ve,
/// ningun FIM lo detecta y no deja rastro al reiniciar. Es donde se esconde la
/// comunicacion local que no quiere ser vista.
pub const UNIX_SOCKETS: Tabla = Tabla {
    nombre: "unix_sockets",
    columnas: COLUMNAS_UNIX,
    descripcion: "un socket de dominio UNIX, incluidos los abstractos que no tocan el disco",
};
