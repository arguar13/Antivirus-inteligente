//! **La garantia del modulo**: el unico punto del crate donde se abre un fichero,
//! y se abre siempre de solo lectura.
//!
//! # Por que esto merece un modulo entero
//!
//! Este crate lee la ROM SPI de la placa base y las tablas que el firmware
//! entrega al kernel. Una escritura accidental ahi no es un bug: es un
//! **ladrillo**. Una ROM SPI mal escrita deja la maquina sin arrancar, y no hay
//! recuperacion por software —hace falta un programador externo y abrir el
//! equipo—. Un EDR que pueda dejar sin arrancar el portatil de un cliente es
//! peor que el malware que busca.
//!
//! Por eso la garantia no es una convencion ni un comentario: es **estructural**.
//!
//! 1. Todo acceso a disco del crate pasa por [`LecturaSolo`]. No hay otra ruta.
//! 2. [`LecturaSolo`] no expone **ninguna** operacion de escritura. No es que no
//!    se use: es que no existe en el tipo, asi que no se puede escribir aunque
//!    alguien lo intente.
//! 3. El descriptor se abre con `O_RDONLY`, asi que la prohibicion la impone el
//!    **kernel**, no este codigo. Un `write(2)` sobre el devuelve `EBADF`.
//! 4. Se anade `O_NOFOLLOW`: si `/dev/mtd0` fuera un enlace simbolico plantado
//!    por un atacante hacia otro dispositivo, la apertura falla en vez de seguir
//!    el enlace. Y `O_CLOEXEC`, para que el descriptor no se filtre a un proceso
//!    hijo que si pudiera reabrirlo de otra forma.
//!
//! El punto 3 es el que convierte la garantia en comprobable: la prueba de este
//! modulo **intenta escribir de verdad** sobre un descriptor abierto asi y exige
//! que el kernel lo rechace. Afirmar "solo lectura" sin ejercerlo contra el
//! kernel seria afirmarlo sobre el papel.
//!
//! # Lo que no compila (FASE 92)
//!
//! La FASE 92 lleva este tipo a superficies mucho mas peligrosas que un fichero:
//! la configuracion PCI del chipset, `/dev/mem` y los MSR de la CPU. La garantia
//! del punto 2 se comprueba por lo que FALTA, con el codigo de error atado para
//! que una errata no la haga pasar:
//!
//! No hay operacion de escritura (`E0599`: el metodo no existe):
//!
//! ```compile_fail,E0599
//! use aegis_fwaudit::solo_lectura::LecturaSolo;
//! let l = LecturaSolo::abrir(std::path::Path::new("/dev/mem")).unwrap();
//! l.escribir(0, &[0xFF]);
//! ```
//!
//! No es un `io::Write` (`E0277`: no cumple el rasgo):
//!
//! ```compile_fail,E0277
//! use aegis_fwaudit::solo_lectura::LecturaSolo;
//! use std::io::Write;
//! let mut l = LecturaSolo::abrir(std::path::Path::new("/dev/mem")).unwrap();
//! l.write_all(&[0xFF]).unwrap();
//! ```
//!
//! Y no se puede sacar el fichero de dentro para escribir por el (`E0616`: el
//! campo es privado):
//!
//! ```compile_fail,E0616
//! use aegis_fwaudit::solo_lectura::LecturaSolo;
//! let l = LecturaSolo::abrir(std::path::Path::new("/dev/mem")).unwrap();
//! let _f = &l.fichero;
//! ```

use std::path::{Path, PathBuf};

/// Banderas con las que se abre TODO en este crate.
///
/// - `O_RDONLY`: el kernel rechaza cualquier escritura sobre el descriptor.
/// - `O_CLOEXEC`: el descriptor no sobrevive a un `exec`, asi que no se filtra a
///   un proceso hijo.
/// - `O_NOFOLLOW`: si la ruta es un enlace simbolico, la apertura falla. Contra
///   un atacante que sustituye `/dev/mtd0` por un enlace a otra cosa, seguir el
///   enlace seria leer —o, con otras banderas, escribir— donde el decida.
pub const BANDERAS_SOLO_LECTURA: i32 = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;

/// Tamano de la ventana de lectura por defecto, en bytes.
///
/// La ROM se recorre por ventanas y no se carga entera: son hasta 32 MiB, y el
/// presupuesto de memoria del agente en reposo son 48 MiB en una pasarela y 81
/// en una estacion, para TODO. Cargar la ROM completa lo reventaria por si sola
/// en las dos, y en la pasarela ni siquiera cabria.
pub const TAMANO_VENTANA: usize = 64 * 1024;

/// Error de lectura.
#[derive(Debug, thiserror::Error)]
pub enum ErrorLectura {
    /// La ruta no existe (lo normal: casi ninguna maquina expone la ROM SPI).
    #[error("no existe: {0}")]
    NoExiste(PathBuf),
    /// No hay permiso para leerla.
    #[error("sin permiso para leer {0}")]
    SinPermiso(PathBuf),
    /// Se pidio un rango que no cabe en el fichero.
    #[error("lectura fuera de rango: {pedidos} B desde {offset} en un fichero de {tamano} B")]
    FueraDeRango {
        /// Desplazamiento pedido.
        offset: u64,
        /// Bytes pedidos.
        pedidos: usize,
        /// Tamano real.
        tamano: u64,
    },
    /// Cualquier otro fallo de entrada/salida.
    #[error("leyendo {ruta}: {source}")]
    Io {
        /// Ruta implicada.
        ruta: PathBuf,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
}

/// Un fichero abierto **solo para lectura**, sin ninguna operacion de escritura
/// disponible en el tipo.
#[derive(Debug)]
pub struct LecturaSolo {
    fichero: std::fs::File,
    ruta: PathBuf,
    tamano: u64,
}

impl LecturaSolo {
    /// Abre una ruta de solo lectura.
    ///
    /// # Errores
    /// [`ErrorLectura::NoExiste`] si la ruta no esta (el caso normal en una
    /// maquina sin ROM SPI expuesta), [`ErrorLectura::SinPermiso`] si falta
    /// privilegio, o [`ErrorLectura::Io`] para el resto.
    pub fn abrir(ruta: &Path) -> Result<LecturaSolo, ErrorLectura> {
        use std::os::unix::fs::OpenOptionsExt;

        let fichero = std::fs::OpenOptions::new()
            .read(true)
            // Explicitos aunque sean el valor por defecto: el que lea esto tiene
            // que ver que NADA de esto escribe, sin ir a buscar los defectos de
            // `OpenOptions`.
            .write(false)
            .append(false)
            .create(false)
            .truncate(false)
            .custom_flags(BANDERAS_SOLO_LECTURA)
            .open(ruta)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ErrorLectura::NoExiste(ruta.to_path_buf()),
                std::io::ErrorKind::PermissionDenied => {
                    ErrorLectura::SinPermiso(ruta.to_path_buf())
                }
                _ => ErrorLectura::Io {
                    ruta: ruta.to_path_buf(),
                    source: e,
                },
            })?;

        // El tamano NO sale de `metadata().len()` sin mas: los ficheros de
        // caracteres (`/dev/mtd0`) reportan 0 ahi. Para esos, el tamano real lo
        // da recorrer hasta el final, y quien los use lo aporta aparte.
        let tamano = fichero.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(LecturaSolo {
            fichero,
            ruta: ruta.to_path_buf(),
            tamano,
        })
    }

    /// La ruta abierta.
    #[must_use]
    pub fn ruta(&self) -> &Path {
        &self.ruta
    }

    /// El tamano conocido, o 0 si el objeto no lo declara (dispositivos).
    #[must_use]
    pub const fn tamano(&self) -> u64 {
        self.tamano
    }

    /// Fija un tamano conocido por otra via (p. ej. `/sys/class/mtd/mtdN/size`).
    #[must_use]
    pub const fn con_tamano(mut self, tamano: u64) -> LecturaSolo {
        self.tamano = tamano;
        self
    }

    /// Lee `len` bytes desde `offset`.
    ///
    /// Usa `pread`, que no toca el cursor del descriptor: asi dos lecturas de
    /// distintas partes de la ROM no se pisan, y no hace falta serializar.
    ///
    /// # Errores
    /// [`ErrorLectura::FueraDeRango`] si el rango no cabe en un tamano conocido,
    /// o [`ErrorLectura::Io`].
    pub fn leer(&self, offset: u64, len: usize) -> Result<Vec<u8>, ErrorLectura> {
        use std::os::unix::fs::FileExt;

        if self.tamano > 0 {
            let fin = offset.saturating_add(len as u64);
            if fin > self.tamano {
                return Err(ErrorLectura::FueraDeRango {
                    offset,
                    pedidos: len,
                    tamano: self.tamano,
                });
            }
        }
        let mut buffer = vec![0u8; len];
        let mut leidos = 0usize;
        while leidos < len {
            match self
                .fichero
                .read_at(&mut buffer[leidos..], offset + leidos as u64)
            {
                // Fin de fichero antes de lo pedido: se devuelve lo leido. Un
                // volcado truncado es un dato, no un fallo del producto.
                Ok(0) => {
                    buffer.truncate(leidos);
                    break;
                }
                Ok(n) => leidos += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(ErrorLectura::Io {
                        ruta: self.ruta.clone(),
                        source: e,
                    })
                }
            }
        }
        Ok(buffer)
    }

    /// Lee el fichero entero, hasta un tope.
    ///
    /// El tope no es decorativo: una tabla ACPI que declara 4 GiB de longitud es
    /// un fichero preparado a mano, y reservar esa memoria a partir de un numero
    /// que controla el firmware es exactamente como se tumba un agente.
    ///
    /// # Errores
    /// [`ErrorLectura::Io`].
    pub fn leer_todo(&self, tope: usize) -> Result<Vec<u8>, ErrorLectura> {
        use std::os::unix::fs::FileExt;

        // POSICIONAL, desde el offset 0, y NO con el cursor del descriptor.
        //
        // Con el cursor compartido, dos llamadas seguidas sobre el mismo lector
        // no devuelven lo mismo: la segunda empieza donde acabo la primera. Eso
        // rompe dos cosas a la vez —la idempotencia, y la propiedad de que dos
        // lecturas concurrentes no se pisen, que es justo por lo que el resto del
        // modulo usa `pread`—. Lo encontro la prueba que llama dos veces.
        let mut buffer = Vec::new();
        let mut offset = 0u64;
        let mut trozo = vec![0u8; TAMANO_VENTANA.min(tope.max(1))];
        while buffer.len() < tope {
            let quedan = tope - buffer.len();
            let pedir = trozo.len().min(quedan);
            match self.fichero.read_at(&mut trozo[..pedir], offset) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&trozo[..n]);
                    offset += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(ErrorLectura::Io {
                        ruta: self.ruta.clone(),
                        source: e,
                    })
                }
            }
        }
        Ok(buffer)
    }
}

/// Presta el descriptor, que es de solo lectura por construccion.
///
/// Existe para que la prueba de integracion pueda EJERCER la garantia contra el
/// kernel —intentar escribir y exigir `EBADF`—. La biblioteca misma lleva
/// `#![forbid(unsafe_code)]`, asi que esa comprobacion no puede vivir dentro: es
/// justamente lo correcto, porque la prohibicion de `unsafe` en la biblioteca es
/// parte de la garantia, y la prueba que la ejerce tiene que ser externa.
///
/// Prestar el descriptor no debilita nada: esta abierto `O_RDONLY`, asi que quien
/// lo reciba tampoco puede escribir por el. Esa es la diferencia entre una
/// garantia del kernel y una convencion del codigo.
impl std::os::fd::AsFd for LecturaSolo {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fichero.as_fd()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn fichero_temporal(nombre: &str, contenido: &[u8]) -> PathBuf {
        let ruta =
            std::env::temp_dir().join(format!("aegis-fwaudit-{}-{nombre}", std::process::id()));
        std::fs::write(&ruta, contenido).expect("crear el fichero de prueba");
        ruta
    }

    /// `O_NOFOLLOW`: un enlace simbolico plantado en lugar del dispositivo no se
    /// sigue. Contra un atacante que sustituye `/dev/mtd0`, seguirlo seria leer
    /// donde el decida.
    #[test]
    fn un_enlace_simbolico_no_se_sigue() {
        let real = fichero_temporal("destino", b"datos reales");
        let enlace =
            std::env::temp_dir().join(format!("aegis-fwaudit-{}-enlace", std::process::id()));
        let _ = std::fs::remove_file(&enlace);
        std::os::unix::fs::symlink(&real, &enlace).expect("crear el enlace");

        let r = LecturaSolo::abrir(&enlace);
        assert!(
            r.is_err(),
            "un enlace simbolico en la ruta del dispositivo no puede seguirse"
        );
        // Y el fichero real sigue siendo accesible por su propia ruta.
        assert!(LecturaSolo::abrir(&real).is_ok());

        let _ = std::fs::remove_file(&enlace);
        let _ = std::fs::remove_file(&real);
    }

    #[test]
    fn una_lectura_fuera_de_rango_se_rechaza_en_vez_de_devolver_basura() {
        let ruta = fichero_temporal("rango", &[0x11u8; 100]);
        let l = LecturaSolo::abrir(&ruta).expect("abrir");
        assert_eq!(l.tamano(), 100);
        assert!(l.leer(0, 100).is_ok());
        assert!(matches!(
            l.leer(50, 100),
            Err(ErrorLectura::FueraDeRango { .. })
        ));
        assert!(matches!(
            l.leer(u64::MAX - 1, 10),
            Err(ErrorLectura::FueraDeRango { .. })
        ));
        let _ = std::fs::remove_file(&ruta);
    }

    /// Dos lecturas del mismo lector tienen que dar LO MISMO. Con el cursor
    /// compartido del descriptor no lo daban: la segunda empezaba donde acabo la
    /// primera. Ademas de romper la idempotencia, eso invalidaba la propiedad de
    /// que dos lecturas concurrentes no se pisen.
    #[test]
    fn dos_lecturas_del_mismo_lector_dan_lo_mismo() {
        let ruta = fichero_temporal("idempotente", &vec![0x33u8; 5000]);
        let l = LecturaSolo::abrir(&ruta).expect("abrir");
        let a = l.leer_todo(usize::MAX).expect("primera");
        let b = l.leer_todo(usize::MAX).expect("segunda");
        assert_eq!(a, b);
        assert_eq!(a.len(), 5000);
        // Y lo mismo con `leer` posicional, mezclada entre medias.
        assert_eq!(l.leer(100, 10).expect("x"), l.leer(100, 10).expect("y"));
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn leer_todo_respeta_el_tope() {
        let ruta = fichero_temporal("tope", &vec![0x22u8; 10_000]);
        let l = LecturaSolo::abrir(&ruta).expect("abrir");
        assert_eq!(l.leer_todo(1000).expect("leer").len(), 1000);
        assert_eq!(l.leer_todo(usize::MAX).expect("leer").len(), 10_000);
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn una_ruta_que_no_existe_se_distingue_de_un_fallo() {
        // Es el caso NORMAL: casi ninguna maquina expone la ROM SPI. Tiene que
        // distinguirse de un error de verdad, o el informe diria "fallo" donde
        // corresponde "no aplicable".
        let r = LecturaSolo::abrir(Path::new("/dev/mtd-que-no-existe-jamas"));
        assert!(matches!(r, Err(ErrorLectura::NoExiste(_))), "{r:?}");
    }
}
