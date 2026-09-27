//! Cobertura de lo que NO es un fichero.
//!
//! La persistencia no vive solo en `/etc`. Vive en unidades de systemd, en `cron`,
//! en modulos del kernel, en el `initramfs`, en las entradas de arranque, en las
//! ACL y los atributos extendidos, en las capacidades de fichero, y —lo que casi
//! nadie vigila— en el propio arbol del agente. Un FIM que solo mira contenidos de
//! ficheros deja abiertas todas esas puertas.
//!
//! Cada objeto se reduce a una IDENTIDAD estable (su clave en la linea base) y a
//! una HUELLA canonica (BLAKE3 de su representacion). Un cambio es una huella
//! distinta para la misma identidad. Las clases estan en el tipo: la cobertura es
//! comprobable, no una lista en la documentacion.

/// Un objeto de integridad que no es (solo) el contenido de un fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Objeto {
    /// Una unidad de systemd (servicio, temporizador, socket).
    UnidadSystemd {
        /// Nombre de la unidad (`sshd.service`).
        nombre: String,
        /// Contenido de la unidad.
        contenido: String,
    },
    /// Una entrada de `cron` (de un usuario o del sistema).
    EntradaCron {
        /// Dueno de la tabla.
        usuario: String,
        /// La linea de cron.
        linea: String,
    },
    /// Un modulo del kernel cargable.
    ModuloKernel {
        /// Nombre del modulo.
        nombre: String,
        /// Huella del binario del modulo.
        huella: [u8; 32],
    },
    /// La imagen `initramfs`: el arranque temprano, donde se esconde un rootkit.
    Initramfs {
        /// Huella de la imagen.
        huella: [u8; 32],
    },
    /// Una entrada del gestor de arranque, con su linea de comandos del kernel.
    EntradaArranque {
        /// Identificador de la entrada.
        id: String,
        /// La linea de comandos (`cmdline`) del kernel: un `init=` cambiado es un
        /// secuestro del arranque.
        cmdline: String,
    },
    /// La ACL POSIX de una ruta.
    Acl {
        /// Ruta.
        ruta: String,
        /// Representacion textual de la ACL.
        acl: String,
    },
    /// Un atributo extendido de una ruta (p. ej. `security.*`).
    Xattr {
        /// Ruta.
        ruta: String,
        /// Nombre del atributo.
        nombre: String,
        /// Valor.
        valor: Vec<u8>,
    },
    /// Las capacidades de fichero de un binario (`cap_setuid`, etc.): una forma de
    /// escalada que no aparece en el bit setuid.
    CapacidadFichero {
        /// Ruta del binario.
        ruta: String,
        /// Capacidades, en texto.
        caps: String,
    },
    /// Un fichero del propio arbol del agente: protegerse a uno mismo es parte de
    /// la integridad.
    ArbolAgente {
        /// Ruta dentro del arbol del agente.
        ruta: String,
        /// Huella del contenido.
        huella: [u8; 32],
    },
}

impl Objeto {
    /// La clase del objeto, para el informe y para la cobertura.
    #[must_use]
    pub fn clase(&self) -> &'static str {
        match self {
            Objeto::UnidadSystemd { .. } => "unidad-systemd",
            Objeto::EntradaCron { .. } => "entrada-cron",
            Objeto::ModuloKernel { .. } => "modulo-kernel",
            Objeto::Initramfs { .. } => "initramfs",
            Objeto::EntradaArranque { .. } => "entrada-arranque",
            Objeto::Acl { .. } => "acl",
            Objeto::Xattr { .. } => "xattr",
            Objeto::CapacidadFichero { .. } => "capacidad-fichero",
            Objeto::ArbolAgente { .. } => "arbol-agente",
        }
    }

    /// La identidad estable del objeto: su clave en la linea base.
    #[must_use]
    pub fn identidad(&self) -> String {
        match self {
            Objeto::UnidadSystemd { nombre, .. } => format!("unidad-systemd::{nombre}"),
            Objeto::EntradaCron { usuario, .. } => format!("entrada-cron::{usuario}"),
            Objeto::ModuloKernel { nombre, .. } => format!("modulo-kernel::{nombre}"),
            Objeto::Initramfs { .. } => "initramfs".to_string(),
            Objeto::EntradaArranque { id, .. } => format!("entrada-arranque::{id}"),
            Objeto::Acl { ruta, .. } => format!("acl::{ruta}"),
            Objeto::Xattr { ruta, nombre, .. } => format!("xattr::{ruta}::{nombre}"),
            Objeto::CapacidadFichero { ruta, .. } => format!("capacidad-fichero::{ruta}"),
            Objeto::ArbolAgente { ruta, .. } => format!("arbol-agente::{ruta}"),
        }
    }

    /// La huella canonica del ESTADO del objeto. Dos objetos con la misma
    /// identidad y distinta huella representan un cambio.
    #[must_use]
    pub fn huella(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(self.clase().as_bytes());
        h.update(&[0]);
        match self {
            Objeto::UnidadSystemd { nombre, contenido } => {
                h.update(nombre.as_bytes());
                h.update(&[0]);
                h.update(contenido.as_bytes());
            }
            Objeto::EntradaCron { usuario, linea } => {
                h.update(usuario.as_bytes());
                h.update(&[0]);
                h.update(linea.as_bytes());
            }
            Objeto::ModuloKernel { nombre, huella } => {
                h.update(nombre.as_bytes());
                h.update(huella);
            }
            Objeto::Initramfs { huella } => {
                h.update(huella);
            }
            Objeto::EntradaArranque { id, cmdline } => {
                h.update(id.as_bytes());
                h.update(&[0]);
                h.update(cmdline.as_bytes());
            }
            Objeto::Acl { ruta, acl } => {
                h.update(ruta.as_bytes());
                h.update(&[0]);
                h.update(acl.as_bytes());
            }
            Objeto::Xattr {
                ruta,
                nombre,
                valor,
            } => {
                h.update(ruta.as_bytes());
                h.update(&[0]);
                h.update(nombre.as_bytes());
                h.update(&[0]);
                h.update(valor);
            }
            Objeto::CapacidadFichero { ruta, caps } => {
                h.update(ruta.as_bytes());
                h.update(&[0]);
                h.update(caps.as_bytes());
            }
            Objeto::ArbolAgente { ruta, huella } => {
                h.update(ruta.as_bytes());
                h.update(huella);
            }
        }
        *h.finalize().as_bytes()
    }

    /// Si este objeto representa un cambio respecto a un estado conocido-bueno de
    /// la MISMA identidad. Si las identidades difieren, no es comparable.
    #[must_use]
    pub fn cambio_respecto_a(&self, conocido_bueno: &Objeto) -> bool {
        self.identidad() == conocido_bueno.identidad() && self.huella() != conocido_bueno.huella()
    }

    /// Todas las clases de objeto que se cubren. Es la lista que la prueba de
    /// cobertura fija: anadir una clase obliga a anadirla aqui.
    #[must_use]
    pub fn clases_cubiertas() -> &'static [&'static str] {
        &[
            "unidad-systemd",
            "entrada-cron",
            "modulo-kernel",
            "initramfs",
            "entrada-arranque",
            "acl",
            "xattr",
            "capacidad-fichero",
            "arbol-agente",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_unidad_de_systemd_cambiada_se_detecta() {
        let bueno = Objeto::UnidadSystemd {
            nombre: "sshd.service".to_string(),
            contenido: "ExecStart=/usr/sbin/sshd\n".to_string(),
        };
        let malo = Objeto::UnidadSystemd {
            nombre: "sshd.service".to_string(),
            contenido: "ExecStart=/usr/sbin/sshd\nExecStartPre=/tmp/puerta\n".to_string(),
        };
        assert!(malo.cambio_respecto_a(&bueno));
        assert!(!bueno.cambio_respecto_a(&bueno));
    }

    #[test]
    fn objetos_de_distinta_identidad_no_son_comparables() {
        let a = Objeto::EntradaCron {
            usuario: "root".to_string(),
            linea: "* * * * * /bin/x".to_string(),
        };
        let b = Objeto::EntradaCron {
            usuario: "alice".to_string(),
            linea: "* * * * * /bin/x".to_string(),
        };
        // Distinto usuario => distinta identidad => cambio_respecto_a es falso.
        assert!(!a.cambio_respecto_a(&b));
    }

    #[test]
    fn la_cobertura_de_clases_esta_completa_y_es_unica() {
        let clases = Objeto::clases_cubiertas();
        let mut orden: Vec<&str> = clases.to_vec();
        let antes = orden.len();
        orden.sort_unstable();
        orden.dedup();
        assert_eq!(antes, orden.len(), "no hay clases repetidas");
        assert_eq!(antes, 9, "las nueve clases de objeto no-fichero");
    }
}
