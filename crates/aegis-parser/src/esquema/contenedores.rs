//! Tablas de contenedores anadidas por la FASE 81.
//!
//! # De donde salen estos datos, que no es de donde todo el mundo los saca
//!
//! Lo habitual —y lo que hace osquery— es hablar con el socket de Docker.
//! Aqui no, por tres razones que se sostienen solas:
//!
//!   1. **Hablar con el socket de Docker es ser root.** Quien puede escribir en
//!      `/var/run/docker.sock` puede arrancar un contenedor privilegiado que
//!      monte `/` y salir siendo root del anfitrion. Un EDR que necesita ese
//!      acceso para leer una tabla se ha concedido a si mismo la escalada que
//!      deberia estar vigilando.
//!   2. **Hay mas de un runtime.** Docker, containerd, CRI-O y podman hablan
//!      protocolos distintos, y un cliente por cada uno es superficie nueva en
//!      el endpoint por cada uno.
//!   3. **El runtime puede mentir, el nucleo no.** Un contenedor se ve desde el
//!      anfitrion en sus cgroups y sus espacios de nombres, que son estado del
//!      nucleo. Si un proceso se esconde del runtime —lo que hace cualquier
//!      implante que no arranque por la via normal—, en los cgroups sigue
//!      estando.
//!
//! Asi que [`CONTAINERS`] se deriva del NUCLEO y no necesita permiso ninguno.
//! Lo que si necesita hablar con el runtime —el nombre legible de la imagen, los
//! volumenes declarados— se lee de sus ficheros de estado cuando son legibles, y
//! se DECLARA como hueco cuando no lo son.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------
const COLUMNAS_CONTENEDORES: &[Columna] = &[
    Columna {
        nombre: "id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador del contenedor, sacado de su cgroup",
    },
    Columna {
        nombre: "runtime",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "docker, containerd, crio, podman, lxc o unknown",
    },
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "un proceso que corre dentro; hay una fila por proceso",
    },
    Columna {
        nombre: "process",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre de ese proceso",
    },
    Columna {
        nombre: "cgroup_path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ruta completa del cgroup",
    },
    Columna {
        nombre: "pid_namespace",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "inodo de su espacio de nombres de procesos",
    },
    Columna {
        nombre: "shares_host_pid",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "comparte el espacio de PID del anfitrion: NO esta contenido",
    },
    Columna {
        nombre: "shares_host_net",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "comparte la red del anfitrion",
    },
];

/// Un proceso que corre dentro de un contenedor.
///
/// Las dos ultimas columnas son las que convierten esta tabla en deteccion: un
/// contenedor que comparte el espacio de PID o la red del anfitrion no esta
/// aislado de el, y es exactamente la configuracion que pide un atacante —o que
/// deja un despliegue descuidado— para poder salir.
pub const CONTAINERS: Tabla = Tabla {
    nombre: "containers",
    columnas: COLUMNAS_CONTENEDORES,
    descripcion: "un proceso dentro de un contenedor, visto desde el nucleo del anfitrion",
};

// ---------------------------------------------------------------------------
// container_images
// ---------------------------------------------------------------------------
const COLUMNAS_IMAGENES: &[Columna] = &[
    Columna {
        nombre: "id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "identificador de la imagen",
    },
    Columna {
        nombre: "reference",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre con el que se descargo, incluido el registro de origen",
    },
    Columna {
        nombre: "runtime",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "runtime que la tiene",
    },
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero de estado del que sale el dato",
    },
];

/// Una imagen de contenedor presente en la maquina.
///
/// `reference` incluye el REGISTRO de origen a proposito: una imagen que viene
/// de un registro que no es el de la empresa es la pregunta que hay que poder
/// hacer, y con el nombre corto —`nginx:latest`— no se puede.
pub const CONTAINER_IMAGES: Tabla = Tabla {
    nombre: "container_images",
    columnas: COLUMNAS_IMAGENES,
    descripcion: "una imagen de contenedor presente en la maquina, con su registro de origen",
};

// ---------------------------------------------------------------------------
// container_mounts
// ---------------------------------------------------------------------------
const COLUMNAS_MONTAJES: &[Columna] = &[
    Columna {
        nombre: "container_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "contenedor al que pertenece",
    },
    Columna {
        nombre: "source",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "ruta del ANFITRION que se monto dentro",
    },
    Columna {
        nombre: "destination",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "donde aparece dentro del contenedor",
    },
    Columna {
        nombre: "writable",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el contenedor puede escribir ahi",
    },
    Columna {
        nombre: "escapes_container",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el origen es una via de escape conocida: /, /proc, el socket del runtime",
    },
];

/// Un montaje del anfitrion dentro de un contenedor.
///
/// `escapes_container` es la columna que justifica la tabla. Montar
/// `/var/run/docker.sock` dentro de un contenedor le da a ese contenedor el
/// control del anfitrion entero; montar `/` en escritura es lo mismo por otra
/// via. Las dos son configuraciones que se ponen «temporalmente» y se quedan.
pub const CONTAINER_MOUNTS: Tabla = Tabla {
    nombre: "container_mounts",
    columnas: COLUMNAS_MONTAJES,
    descripcion: "un montaje del anfitrion dentro de un contenedor, y si es una via de escape",
};

// ---------------------------------------------------------------------------
// container_capabilities
// ---------------------------------------------------------------------------
const COLUMNAS_CAPACIDADES: &[Columna] = &[
    Columna {
        nombre: "container_id",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "contenedor al que pertenece",
    },
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso del que se leyo",
    },
    Columna {
        nombre: "capability",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "capacidad que conserva dentro del contenedor",
    },
    Columna {
        nombre: "dangerous",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "es una de las que permiten salir del contenedor",
    },
];

/// Una capacidad que un proceso conserva dentro de un contenedor.
///
/// El runtime de contenedores quita casi todas las capacidades por defecto, y
/// por eso las que QUEDAN son informativas: `CAP_SYS_ADMIN` dentro de un
/// contenedor permite montar sistemas de ficheros y es, en la practica, una
/// salida; `CAP_SYS_MODULE` permite cargar un modulo en el nucleo del ANFITRION,
/// que es la salida mas completa que existe.
pub const CONTAINER_CAPABILITIES: Tabla = Tabla {
    nombre: "container_capabilities",
    columnas: COLUMNAS_CAPACIDADES,
    descripcion: "una capacidad que un proceso conserva dentro de un contenedor",
};
