//! Entidades tipadas: `Ref<Proceso>`, `Ref<Fichero>`, `Ref<Cuenta>`...
//!
//! # Por que el tipo va en la entidad y no en una cadena
//!
//! En un SOAR corriente, la salida de un paso es un diccionario y la entrada
//! del siguiente, otro: `{{ steps.find.output.id }}`. Si la plantilla se
//! equivoca y pasa el identificador de un fichero a «matar proceso», el error
//! aparece cuando el flujo corre —o no aparece, y se mata el proceso cuyo pid
//! coincide con un numero que no era un pid—.
//!
//! Aqui cada entidad lleva su clase en el TIPO. `Ref<Proceso>` solo se puede
//! construir a partir de un identificador cuya clase es proceso
//! ([`Ref::nueva`]), y un paso que declara `Entrada = Ref<Proceso>` solo se
//! puede enganchar a la salida de un paso que produce `Ref<Proceso>`: el
//! compilador lo comprueba (ver [`crate::flujo`]).
//!
//! # Identidad y localizacion, juntas y coherentes
//!
//! Para actuar no basta la identidad: matar un proceso exige saber en que
//! maquina vive, con que pid y desde que arranque. [`Objetivo`] lleva las dos
//! cosas, y la identidad se DERIVA de la localizacion con las funciones del
//! modelo unico ([`aegis_entidad::entidad`]). No se pueden dar por separado, asi
//! que no pueden contradecirse: no existe un objetivo cuya identidad diga «el
//! proceso 4242 de srv-1» y cuya localizacion apunte al 4243 de srv-2 —que
//! seria exactamente el error de plantilla que convierte una respuesta en un
//! incidente—.

use std::marker::PhantomData;

use aegis_entidad::entidad::{self, Clase};
use aegis_entidad::Eid;

/// Una clase de entidad sobre la que puede actuar un paso.
pub trait Tipo: Send + Sync + 'static {
    /// La clase del modelo unico que le corresponde.
    const CLASE: Clase;
    /// Nombre para los mensajes.
    const NOMBRE: &'static str;
    /// Como se encuentra en la flota.
    type Localizador: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync + 'static;
    /// La identidad que le corresponde a una localizacion, por las funciones
    /// del modelo unico.
    fn derivar(l: &Self::Localizador) -> Eid;
}

/// Donde vive un proceso: maquina, arranque del sistema, pid e instante de
/// arranque del proceso (sin el, un pid reutilizado seria otro proceso con la
/// misma identidad).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocProceso {
    /// Matricula (CN) de la maquina.
    pub maquina: String,
    /// Contador de arranques de la maquina.
    pub boot: u64,
    /// Pid.
    pub pid: u32,
    /// Instante de arranque del proceso, en ns.
    pub arranque_ns: u64,
}

/// Donde esta un fichero.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocFichero {
    /// Matricula (CN) de la maquina.
    pub maquina: String,
    /// Ruta.
    pub ruta: String,
}

/// Un proceso vivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Proceso;
impl Tipo for Proceso {
    const CLASE: Clase = Clase::Proceso;
    const NOMBRE: &'static str = "proceso";
    type Localizador = LocProceso;
    fn derivar(l: &LocProceso) -> Eid {
        entidad::proceso(&entidad::maquina(&l.maquina), l.boot, l.pid, l.arranque_ns)
    }
}

/// Un fichero en una ruta de una maquina.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fichero;
impl Tipo for Fichero {
    const CLASE: Clase = Clase::Ubicacion;
    const NOMBRE: &'static str = "fichero";
    type Localizador = LocFichero;
    fn derivar(l: &LocFichero) -> Eid {
        entidad::ubicacion(&entidad::maquina(&l.maquina), &l.ruta)
    }
}

/// Un contenido, por su SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Contenido;
impl Tipo for Contenido {
    const CLASE: Clase = Clase::Contenido;
    const NOMBRE: &'static str = "contenido";
    type Localizador = String;
    fn derivar(sha256: &String) -> Eid {
        entidad::contenido(sha256)
    }
}

/// Una cuenta de un directorio, por su identificador en el directorio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cuenta;
impl Tipo for Cuenta {
    const CLASE: Clase = Clase::Cuenta;
    const NOMBRE: &'static str = "cuenta";
    type Localizador = String;
    fn derivar(id: &String) -> Eid {
        entidad::cuenta(id)
    }
}

/// Una maquina de la flota, por su matricula (el CN de su certificado).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Maquina;
impl Tipo for Maquina {
    const CLASE: Clase = Clase::Maquina;
    const NOMBRE: &'static str = "maquina";
    type Localizador = String;
    fn derivar(cn: &String) -> Eid {
        entidad::maquina(cn)
    }
}

/// Una entidad de una clase concreta.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Ref<T: Tipo> {
    eid: Eid,
    _tipo: PhantomData<T>,
}

impl<T: Tipo> Clone for Ref<T> {
    fn clone(&self) -> Self {
        Ref {
            eid: self.eid.clone(),
            _tipo: PhantomData,
        }
    }
}

/// Una entidad que no es de la clase que se esperaba.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("se esperaba un {esperada} y la entidad {entidad} es de otra clase")]
pub struct ClaseEquivocada {
    /// La clase esperada.
    pub esperada: &'static str,
    /// La entidad recibida.
    pub entidad: String,
}

impl<T: Tipo> Ref<T> {
    /// Envuelve un identificador, comprobando que es de la clase del tipo.
    ///
    /// Es la UNICA forma de construir un `Ref<T>`: el campo es privado.
    ///
    /// # Errors
    ///
    /// [`ClaseEquivocada`] si no lo es.
    pub fn nueva(eid: Eid) -> Result<Ref<T>, ClaseEquivocada> {
        if eid.clase() == T::CLASE {
            Ok(Ref {
                eid,
                _tipo: PhantomData,
            })
        } else {
            Err(ClaseEquivocada {
                esperada: T::NOMBRE,
                entidad: eid.texto(),
            })
        }
    }

    /// El identificador.
    #[must_use]
    pub fn eid(&self) -> &Eid {
        &self.eid
    }
}

/// Una entidad tipada con su localizacion: sobre lo que actua un paso del
/// catalogo.
///
/// La identidad se deriva de la localizacion al construirlo y los campos son
/// privados: no hay forma de tener una identidad y una localizacion que no se
/// correspondan.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Objetivo<T: Tipo> {
    r: Ref<T>,
    loc: T::Localizador,
}

impl<T: Tipo> Clone for Objetivo<T> {
    fn clone(&self) -> Self {
        Objetivo {
            r: self.r.clone(),
            loc: self.loc.clone(),
        }
    }
}

impl<T: Tipo> Objetivo<T> {
    /// El objetivo que vive en `loc`.
    #[must_use]
    pub fn en(loc: T::Localizador) -> Objetivo<T> {
        Objetivo {
            r: Ref {
                eid: T::derivar(&loc),
                _tipo: PhantomData,
            },
            loc,
        }
    }

    /// Su identidad tipada.
    #[must_use]
    pub fn referencia(&self) -> &Ref<T> {
        &self.r
    }

    /// Su identidad.
    #[must_use]
    pub fn eid(&self) -> &Eid {
        self.r.eid()
    }

    /// Donde vive.
    #[must_use]
    pub fn loc(&self) -> &T::Localizador {
        &self.loc
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    #[test]
    fn un_ref_solo_se_construye_con_la_clase_de_su_tipo() {
        let m = entidad::maquina("equipo-1");
        let p = entidad::proceso(&m, 1, 4242, 1_000);
        assert!(Ref::<Proceso>::nueva(p.clone()).is_ok());
        let e = Ref::<Fichero>::nueva(p).unwrap_err();
        assert_eq!(e.esperada, "fichero");
        assert!(Ref::<Maquina>::nueva(m).is_ok());
    }

    #[test]
    fn la_identidad_de_un_objetivo_sale_de_su_localizacion() {
        let loc = LocProceso {
            maquina: "srv-1".into(),
            boot: 3,
            pid: 4242,
            arranque_ns: 99,
        };
        let o = Objetivo::<Proceso>::en(loc.clone());
        assert_eq!(
            o.eid(),
            &entidad::proceso(&entidad::maquina("srv-1"), 3, 4242, 99)
        );
        assert_eq!(o.eid().clase(), Clase::Proceso);
        // Otro pid es otra identidad: no hay forma de que coincidan.
        let otro = Objetivo::<Proceso>::en(LocProceso { pid: 4243, ..loc });
        assert_ne!(o.eid(), otro.eid());
        let f = Objetivo::<Fichero>::en(LocFichero {
            maquina: "srv-1".into(),
            ruta: "C:\\Temp\\x.exe".into(),
        });
        assert_eq!(f.eid().clase(), Clase::Ubicacion);
    }
}
