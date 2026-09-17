//! Tablas de plataforma y paquetes anadidas por la FASE 81.
//!
//! # Por que el inventario de paquetes esta aqui
//!
//! Porque responde a la misma pregunta que las demas de este modulo: «que ES
//! esta maquina». La version del nucleo, el modelo de CPU, las mitigaciones
//! activas y la lista de paquetes instalados son todos propiedades del sistema,
//! no cosas que ocurren en el. Separarlas en dos modulos habria sido ordenado y
//! no habria ayudado a nadie a encontrarlas.
//!
//! # Las dos que hacen deteccion y no inventario
//!
//! [`CPU_MITIGATIONS`] y [`TPM_PCRS`]. El resto describe la maquina; esas dos
//! dicen si la maquina esta en el estado en el que deberia estar. Una
//! mitigacion desactivada a mano —`mitigations=off` en la linea de arranque—
//! reabre agujeros de ejecucion especulativa que el proveedor ya cerro, y un
//! PCR que no coincide con el de la flota significa que el arranque medido de
//! esta maquina no es el de sus hermanas.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// packages
// ---------------------------------------------------------------------------
const COLUMNAS_PAQUETES: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del paquete",
    },
    Columna {
        nombre: "version",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "version instalada",
    },
    Columna {
        nombre: "arch",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "arquitectura",
    },
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "gestor del que sale: dpkg, apk o rpm",
    },
];

/// Un paquete instalado.
///
/// Se lee de la base de datos del gestor, no de su binario: lanzar `dpkg -l` o
/// `rpm -qa` por consulta, en una flota, es un subproceso por endpoint y una
/// espera que no se puede acotar.
///
/// MURO DECLARADO: la lectura de RPM esta pendiente —la base de datos de RPM es
/// un formato binario (BerkeleyDB o sqlite segun la version) y no un fichero de
/// texto como las otras dos—. En una maquina de esa familia, la tabla devuelve
/// su MOTIVO y no una lista vacia, que es lo que haria creer que no hay paquetes
/// instalados en un servidor de RHEL.
pub const PACKAGES: Tabla = Tabla {
    nombre: "packages",
    columnas: COLUMNAS_PAQUETES,
    descripcion: "un paquete instalado, leido de la base de datos de su gestor",
};

// ---------------------------------------------------------------------------
// cpu_info
// ---------------------------------------------------------------------------
const COLUMNAS_CPU: &[Columna] = &[
    Columna {
        nombre: "model",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre comercial del procesador",
    },
    Columna {
        nombre: "vendor",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fabricante",
    },
    Columna {
        nombre: "logical_cpus",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "procesadores logicos que ve el nucleo",
    },
    Columna {
        nombre: "family",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "familia",
    },
    Columna {
        nombre: "model_id",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "modelo numerico",
    },
    Columna {
        nombre: "microcode",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "version del microcodigo cargado; un microcodigo viejo deja agujeros abiertos",
    },
    Columna {
        nombre: "hypervisor",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "se esta ejecutando bajo un hipervisor",
    },
    Columna {
        nombre: "flags",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "capacidades del procesador, separadas por espacios",
    },
];

/// El procesador de la maquina.
pub const CPU_INFO: Tabla = Tabla {
    nombre: "cpu_info",
    columnas: COLUMNAS_CPU,
    descripcion: "el procesador de la maquina, con su microcodigo y sus capacidades",
};

// ---------------------------------------------------------------------------
// cpu_mitigations
// ---------------------------------------------------------------------------
const COLUMNAS_MITIGACIONES: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "vulnerabilidad: spectre_v2, meltdown, mds, retbleed...",
    },
    Columna {
        nombre: "status",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "lo que dice el nucleo, literalmente",
    },
    Columna {
        nombre: "mitigated",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el nucleo la considera mitigada",
    },
    Columna {
        nombre: "vulnerable",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el nucleo dice que la maquina es vulnerable",
    },
];

/// El estado de una mitigacion de ejecucion especulativa.
///
/// Hay TRES estados y no dos, y por eso hay dos columnas booleanas en vez de
/// una: el nucleo puede decir «Mitigation: ...», «Vulnerable» o «Not affected».
/// Con una sola columna, «no afectada» y «mitigada» se escribirian igual, y son
/// cosas distintas: la primera es una propiedad del hardware y la segunda es una
/// defensa activa que alguien puede apagar.
pub const CPU_MITIGATIONS: Tabla = Tabla {
    nombre: "cpu_mitigations",
    columnas: COLUMNAS_MITIGACIONES,
    descripcion: "el estado de una mitigacion de ejecucion especulativa, segun el nucleo",
};

// ---------------------------------------------------------------------------
// memory_info
// ---------------------------------------------------------------------------
const COLUMNAS_MEMORIA: &[Columna] = &[
    Columna {
        nombre: "total_kb",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "memoria fisica total",
    },
    Columna {
        nombre: "free_kb",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "memoria sin usar",
    },
    Columna {
        nombre: "available_kb",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "memoria que se podria pedir sin entrar en intercambio",
    },
    Columna {
        nombre: "swap_total_kb",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "espacio de intercambio total",
    },
    Columna {
        nombre: "swap_free_kb",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "espacio de intercambio libre",
    },
];

/// La memoria de la maquina.
pub const MEMORY_INFO: Tabla = Tabla {
    nombre: "memory_info",
    columnas: COLUMNAS_MEMORIA,
    descripcion: "la memoria fisica y de intercambio de la maquina",
};

// ---------------------------------------------------------------------------
// block_devices
// ---------------------------------------------------------------------------
const COLUMNAS_DISCOS: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del dispositivo",
    },
    Columna {
        nombre: "size_bytes",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "tamano en bytes",
    },
    Columna {
        nombre: "model",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "modelo que declara el dispositivo",
    },
    Columna {
        nombre: "removable",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "extraible; un disco extraible es una via de entrada y de salida",
    },
    Columna {
        nombre: "rotational",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "es un disco mecanico",
    },
    Columna {
        nombre: "read_only",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el dispositivo es de solo lectura",
    },
];

/// Un dispositivo de bloques.
pub const BLOCK_DEVICES: Tabla = Tabla {
    nombre: "block_devices",
    columnas: COLUMNAS_DISCOS,
    descripcion: "un dispositivo de bloques, con si es extraible",
};

// ---------------------------------------------------------------------------
// pci_devices
// ---------------------------------------------------------------------------
const COLUMNAS_PCI: &[Columna] = &[
    Columna {
        nombre: "slot",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion del dispositivo en el bus",
    },
    Columna {
        nombre: "vendor_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador del fabricante",
    },
    Columna {
        nombre: "device_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador del dispositivo",
    },
    Columna {
        nombre: "class",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "clase del dispositivo",
    },
    Columna {
        nombre: "driver",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "controlador que lo maneja",
    },
];

/// Un dispositivo del bus PCI.
///
/// Importa por una razon concreta: un dispositivo PCI puede hacer DMA, es decir,
/// leer y escribir la memoria de la maquina sin pasar por la CPU. Un dispositivo
/// que aparece y que nadie enchufo es un ataque de hardware, y ningun antivirus
/// lo mira.
pub const PCI_DEVICES: Tabla = Tabla {
    nombre: "pci_devices",
    columnas: COLUMNAS_PCI,
    descripcion: "un dispositivo del bus PCI, que puede acceder a memoria por DMA",
};

// ---------------------------------------------------------------------------
// usb_devices
// ---------------------------------------------------------------------------
const COLUMNAS_USB: &[Columna] = &[
    Columna {
        nombre: "port",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "puerto en el arbol USB",
    },
    Columna {
        nombre: "vendor_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador del fabricante",
    },
    Columna {
        nombre: "product_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador del producto",
    },
    Columna {
        nombre: "manufacturer",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fabricante, segun el propio dispositivo",
    },
    Columna {
        nombre: "product",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del producto, segun el propio dispositivo",
    },
    Columna {
        nombre: "serial",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "numero de serie que declara el dispositivo",
    },
    Columna {
        nombre: "class",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "clase: 03 es teclado o raton, 08 es almacenamiento",
    },
];

/// Un dispositivo USB conectado.
///
/// Todos los campos salvo el puerto los declara EL PROPIO DISPOSITIVO, y esa es
/// la nota que tiene que llevar la tabla: un dispositivo puede decir que es un
/// teclado y serlo, o decir que es un teclado y ser un inyector de pulsaciones.
/// La clase `03` en algo que el usuario cree que es un disco es exactamente esa
/// familia de ataque.
pub const USB_DEVICES: Tabla = Tabla {
    nombre: "usb_devices",
    columnas: COLUMNAS_USB,
    descripcion: "un dispositivo USB conectado, segun lo que el propio dispositivo declara",
};

// ---------------------------------------------------------------------------
// firmware_info
// ---------------------------------------------------------------------------
const COLUMNAS_FIRMWARE: &[Columna] = &[
    Columna {
        nombre: "vendor",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fabricante del firmware",
    },
    Columna {
        nombre: "version",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "version del firmware",
    },
    Columna {
        nombre: "release_date",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fecha de publicacion",
    },
    Columna {
        nombre: "product",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "modelo de la maquina",
    },
    Columna {
        nombre: "uefi",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "arranco por UEFI y no por BIOS heredada",
    },
    Columna {
        nombre: "secure_boot",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "el arranque seguro esta activo",
    },
    Columna {
        nombre: "tpm_present",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "hay un TPM accesible",
    },
];

/// El firmware de la maquina.
pub const FIRMWARE_INFO: Tabla = Tabla {
    nombre: "firmware_info",
    columnas: COLUMNAS_FIRMWARE,
    descripcion: "el firmware de la maquina, con el estado del arranque seguro y del TPM",
};

// ---------------------------------------------------------------------------
// tpm_pcrs
// ---------------------------------------------------------------------------
const COLUMNAS_PCR: &[Columna] = &[
    Columna {
        nombre: "bank",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "banco de resumen: sha1, sha256...",
    },
    Columna {
        nombre: "index",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero de registro, de 0 a 23",
    },
    Columna {
        nombre: "value",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "valor en hexadecimal",
    },
    Columna {
        nombre: "measures_boot",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "es uno de los registros del 0 al 7, que miden la cadena de arranque",
    },
];

/// Un registro de configuracion de plataforma del TPM.
///
/// Es la unica medida del arranque que un atacante con root NO puede falsificar
/// desde el sistema en marcha: los PCR solo se extienden, nunca se escriben, y
/// el que los extiende es el firmware antes de que exista sistema operativo.
/// Comparar los PCR de una maquina con los de sus hermanas de la flota es como
/// se ve un bootkit sin confiar en nada de lo que la maquina diga de si misma.
pub const TPM_PCRS: Tabla = Tabla {
    nombre: "tpm_pcrs",
    columnas: COLUMNAS_PCR,
    descripcion: "un registro del TPM, que mide el arranque y no se puede falsificar en caliente",
};
