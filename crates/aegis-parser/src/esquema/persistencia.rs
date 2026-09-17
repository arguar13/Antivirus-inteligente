//! Tablas de persistencia anadidas por la FASE 81.
//!
//! # Por que ocho tablas y no una
//!
//! Habria sido mas corto exponer una sola tabla `persistence` con una columna
//! `kind`, y habria sido peor. Las ocho formas de arraigarse en una maquina
//! Linux no comparten esquema: una unidad de systemd tiene `ExecStart` y
//! `Restart`, una entrada de cron tiene una expresion horaria, un modulo del
//! nucleo tiene firma y direccion de carga. Meterlas en una tabla con una
//! columna `detail` de texto libre obliga al analista a saber que hay dentro de
//! esa columna para cada valor de `kind`, que es exactamente el trabajo que la
//! tabla tendria que ahorrarle.
//!
//! # Lo que ninguna de las ocho puede hacer
//!
//! Decir que una persistencia es maliciosa. Todas describen configuracion
//! LEGITIMA que un atacante tambien usa: `sshd` tambien es una unidad de
//! systemd. Lo que hacen es exponer las columnas por las que se distingue una
//! de otra —de que paquete viene, cuando se escribio, si esta fuera del arbol,
//! si se reinicia sola— y esa distincion la hace el arbitro con todo lo demas
//! que sabe, no una columna de esta tabla.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// systemd_units
// ---------------------------------------------------------------------------
const COLUMNAS_UNIDADES: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre de la unidad, con su sufijo",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "service, socket, timer, mount, path, target...",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero que la define",
    },
    Columna {
        nombre: "scope",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "system o user; una unidad de usuario arranca sin ser root",
    },
    Columna {
        nombre: "exec_start",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "que ejecuta",
    },
    Columna {
        nombre: "user",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "como quien se ejecuta; vacio significa root",
    },
    Columna {
        nombre: "restart",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "politica de reinicio; always es lo que hace que vuelva al matarla",
    },
    Columna {
        nombre: "enabled",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "tiene un enlace que la arranca en el arranque",
    },
    Columna {
        nombre: "vendor_packaged",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "vive en el directorio del sistema y no en el del administrador",
    },
];

/// Una unidad de systemd.
///
/// `scope` y `vendor_packaged` son las dos columnas de deteccion. Una unidad de
/// USUARIO se arranca sin privilegios y sobrevive al reinicio igual que una del
/// sistema, y casi ninguna auditoria las mira. Y una unidad en
/// `/etc/systemd/system` que no viene de ningun paquete es, por definicion, algo
/// que alguien escribio a mano en esa maquina.
pub const SYSTEMD_UNITS: Tabla = Tabla {
    nombre: "systemd_units",
    columnas: COLUMNAS_UNIDADES,
    descripcion: "una unidad de systemd, del sistema o de usuario, con lo que ejecuta",
};

// ---------------------------------------------------------------------------
// systemd_timers
// ---------------------------------------------------------------------------
const COLUMNAS_TEMPORIZADORES: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del temporizador",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero que lo define",
    },
    Columna {
        nombre: "unit",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "unidad que dispara; por convenio la del mismo nombre",
    },
    Columna {
        nombre: "schedule",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "cuando dispara: OnCalendar, OnBootSec, OnUnitActiveSec...",
    },
    Columna {
        nombre: "persistent",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "si la maquina estaba apagada, dispara al encender",
    },
    Columna {
        nombre: "scope",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "system o user",
    },
];

/// Un temporizador de systemd.
///
/// Es el `cron` moderno, y por eso hay que mirarlo igual: un temporizador que
/// dispara cada cinco minutos una unidad que se conecta a internet es una baliza
/// con otro nombre.
pub const SYSTEMD_TIMERS: Tabla = Tabla {
    nombre: "systemd_timers",
    columnas: COLUMNAS_TEMPORIZADORES,
    descripcion: "un temporizador de systemd, con su horario y la unidad que dispara",
};

// ---------------------------------------------------------------------------
// cron_jobs
// ---------------------------------------------------------------------------
const COLUMNAS_CRON: &[Columna] = &[
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero del que sale",
    },
    Columna {
        nombre: "username",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "como quien se ejecuta",
    },
    Columna {
        nombre: "schedule",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "expresion horaria, o @reboot, @daily...",
    },
    Columna {
        nombre: "command",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "que ejecuta",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "system (con usuario), user (crontab personal) o drop_in (cron.d)",
    },
    Columna {
        nombre: "at_reboot",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "se ejecuta en cada arranque",
    },
];

/// Una tarea programada de cron.
///
/// Los tres formatos de cron NO son el mismo: el crontab personal de un usuario
/// no lleva columna de usuario y el del sistema si, y analizarlos con las mismas
/// reglas hace que el primer campo del comando se lea como nombre de cuenta —o
/// al reves, que el usuario se lea como parte del horario—. `kind` existe para
/// que esa distincion sea visible y no una suposicion.
pub const CRON_JOBS: Tabla = Tabla {
    nombre: "cron_jobs",
    columnas: COLUMNAS_CRON,
    descripcion: "una tarea de cron, en cualquiera de sus tres formatos",
};

// ---------------------------------------------------------------------------
// kernel_modules
// ---------------------------------------------------------------------------
const COLUMNAS_MODULOS: &[Columna] = &[
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del modulo",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "bytes que ocupa en memoria del nucleo",
    },
    Columna {
        nombre: "used_by_count",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "cuantos dependen de el",
    },
    Columna {
        nombre: "used_by",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "quienes dependen de el",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "Live, Loading o Unloading",
    },
    Columna {
        nombre: "address",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion de carga; cero si el agente no puede verla",
    },
    Columna {
        nombre: "on_disk",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "hay un fichero .ko suyo en el arbol de modulos del nucleo",
    },
    Columna {
        nombre: "tainted",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "marcas de contaminacion del modulo: O fuera del arbol, E sin firma",
    },
];

/// Un modulo cargado en el nucleo.
///
/// `on_disk` es la columna que caza un rootkit: un modulo cargado cuyo fichero
/// `.ko` no esta en `/lib/modules` se cargo desde otro sitio y se borro, o se
/// cargo desde memoria. No hay ninguna razon legitima para eso en una maquina
/// normal.
pub const KERNEL_MODULES: Tabla = Tabla {
    nombre: "kernel_modules",
    columnas: COLUMNAS_MODULOS,
    descripcion: "un modulo cargado en el nucleo, y si su fichero sigue en el disco",
};

// ---------------------------------------------------------------------------
// boot_images
// ---------------------------------------------------------------------------
const COLUMNAS_IMAGENES: &[Columna] = &[
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ruta de la imagen",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "kernel, initramfs o microcode",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "tamano en bytes",
    },
    Columna {
        nombre: "mtime",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "ultima modificacion",
    },
    Columna {
        nombre: "sha256",
        tipo: Tipo::Texto,
        coste: Coste::Caro,
        descripcion: "hash del contenido",
    },
];

/// Una imagen de arranque.
///
/// El `initramfs` es el punto ciego mas grande de casi todos los EDR: se
/// reconstruye localmente en cada actualizacion de nucleo, asi que no tiene hash
/// conocido contra el que comparar, y se ejecuta ANTES que cualquier agente. Un
/// implante ahi arranca antes que su detector. Esta tabla no lo resuelve —no
/// puede—, pero pone su hash y su fecha donde se puedan comparar con los de la
/// flota, y una maquina cuyo initramfs cambio sin que cambiara su nucleo es una
/// pregunta que merece respuesta.
pub const BOOT_IMAGES: Tabla = Tabla {
    nombre: "boot_images",
    columnas: COLUMNAS_IMAGENES,
    descripcion: "una imagen de arranque (nucleo o initramfs) con su hash y su fecha",
};

// ---------------------------------------------------------------------------
// boot_entries
// ---------------------------------------------------------------------------
const COLUMNAS_ENTRADAS: &[Columna] = &[
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero de configuracion del que sale",
    },
    Columna {
        nombre: "title",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "titulo que ve el usuario",
    },
    Columna {
        nombre: "kernel",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "imagen del nucleo que arranca",
    },
    Columna {
        nombre: "initrd",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "imagen inicial",
    },
    Columna {
        nombre: "options",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "linea de comandos del nucleo",
    },
    Columna {
        nombre: "loader",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "grub o systemd-boot",
    },
    Columna {
        nombre: "weakens_security",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "sus opciones apagan una defensa: selinux=0, apparmor=0, nokaslr, init=",
    },
];

/// Una entrada del gestor de arranque.
///
/// `weakens_security` mira la linea de comandos del nucleo, que es donde se
/// apagan las defensas de forma permanente y sin tocar un solo fichero del
/// sistema: `selinux=0` desactiva el confinamiento entero, `init=/bin/bash` da
/// una consola de root sin contrasena, y `nokaslr` hace predecible la memoria
/// del nucleo. Nada de eso deja rastro en un antivirus.
pub const BOOT_ENTRIES: Tabla = Tabla {
    nombre: "boot_entries",
    columnas: COLUMNAS_ENTRADAS,
    descripcion: "una entrada del gestor de arranque, con si sus opciones debilitan la seguridad",
};

// ---------------------------------------------------------------------------
// shell_profiles
// ---------------------------------------------------------------------------
const COLUMNAS_PERFILES: &[Columna] = &[
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero de perfil",
    },
    Columna {
        nombre: "username",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "cuenta a la que pertenece; vacio si es del sistema",
    },
    Columna {
        nombre: "scope",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "system o user",
    },
    Columna {
        nombre: "line_number",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero de linea dentro del fichero",
    },
    Columna {
        nombre: "line",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "la linea, sin espacios de sobra",
    },
    Columna {
        nombre: "executes",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "la linea ejecuta algo, en vez de solo definir una variable",
    },
];

/// Una linea con contenido de un perfil de interprete.
///
/// Una fila por LINEA y no por fichero: la persistencia en un `.bashrc` son dos
/// lineas dentro de trescientas legitimas, y una tabla que devuelva el fichero
/// entero en una celda obliga al analista a leerlo a ojo. `executes` separa las
/// lineas que hacen algo de las que solo declaran variables, que es el primer
/// filtro que aplicaria cualquiera.
pub const SHELL_PROFILES: Tabla = Tabla {
    nombre: "shell_profiles",
    columnas: COLUMNAS_PERFILES,
    descripcion: "una linea con contenido de un perfil de interprete, del sistema o de un usuario",
};

// ---------------------------------------------------------------------------
// preload
// ---------------------------------------------------------------------------
const COLUMNAS_PRECARGA: &[Columna] = &[
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "de donde sale: /etc/ld.so.preload, el entorno de un proceso...",
    },
    Columna {
        nombre: "library",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "biblioteca que se precarga",
    },
    Columna {
        nombre: "exists",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "el fichero existe; si no, el nombre esta ahi esperando a que aparezca",
    },
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Medio,
        descripcion: "proceso cuyo entorno la lleva; ausente si es global",
    },
    Columna {
        nombre: "scope",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "global (todo el sistema) o process (solo ese proceso)",
    },
];

/// Una biblioteca precargada.
///
/// `LD_PRELOAD` y `/etc/ld.so.preload` son la forma mas directa de secuestrar
/// CADA proceso de una maquina sin tocar un solo binario: la biblioteca se carga
/// antes que la libc y puede sustituir cualquier funcion, incluidas las que usa
/// el propio EDR para mirar.
///
/// Tiene tabla propia en vez de salir de `process_environment` —que tambien la
/// tiene— porque esa es peligrosa y esta no: preguntar por UNA variable conocida
/// no arrastra los secretos de la flota, asi que esta pregunta concreta se puede
/// hacer sin acotar.
pub const PRELOAD: Tabla = Tabla {
    nombre: "preload",
    columnas: COLUMNAS_PRECARGA,
    descripcion: "una biblioteca precargada, global o de un proceso concreto",
};
