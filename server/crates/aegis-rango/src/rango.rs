//! El rango: el entorno declarado donde —y solo donde— se emula, y la prueba de
//! estar en el.
//!
//! # Por que la prueba es un tipo y no una bandera
//!
//! Una bandera `es_rango: bool` se pone a `true` por error, en produccion, un
//! viernes. Un tipo no: [`PruebaDeRango`] no tiene constructor publico ni campos
//! publicos, y la unica forma de obtener una es pedirsela a un [`Rango`] ya
//! declarado. Como [`Tecnica::ejecutar`](crate::tecnica::Tecnica::ejecutar) exige
//! esa prueba, **no hay ninguna ruta de codigo que ejecute una emulacion fuera de
//! un rango declarado**. Se verifica por lo que falta: no existe
//! `PruebaDeRango::nueva`.
//!
//! # Y por que declarar el rango exige una confirmacion con autor
//!
//! Igual que el modo obligatorio del confinamiento (FASE 93): declarar un rango es
//! una decision con consecuencias —se van a materializar y borrar artefactos—, asi
//! que lleva un [`ConfirmacionRango`] con quien lo ordeno y por que. No tiene valor
//! por defecto ni campos publicos: no se puede fabricar sin dejar constancia.
//!
//! La prueba de rango no se puede fabricar por fuera: el campo es privado (E0451):
//!
//! ```compile_fail,E0451
//! let _ = aegis_rango::rango::PruebaDeRango { _sello: core::marker::PhantomData };
//! ```
//!
//! Ni tiene valor por defecto con el que colarla:
//!
//! ```compile_fail
//! let _p: aegis_rango::rango::PruebaDeRango = Default::default();
//! ```

use core::marker::PhantomData;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// La plataforma del rango. Una tecnica solo aplica en las suyas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Plataforma {
    /// Linux.
    Linux,
    /// Windows.
    Windows,
    /// macOS.
    Macos,
}

impl Plataforma {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Plataforma::Linux => "linux",
            Plataforma::Windows => "windows",
            Plataforma::Macos => "macos",
        }
    }

    /// La plataforma sobre la que corre esta compilacion, para saber que se puede
    /// ejercer de verdad aqui y que se declara «no aplicable».
    #[must_use]
    pub fn actual() -> Plataforma {
        if cfg!(target_os = "windows") {
            Plataforma::Windows
        } else if cfg!(target_os = "macos") {
            Plataforma::Macos
        } else {
            Plataforma::Linux
        }
    }
}

/// Lo que puede salir mal en el rango.
#[derive(Debug, Error)]
pub enum ErrorRango {
    /// El directorio del rango no se pudo preparar o limpiar.
    #[error("error de entrada/salida en el rango: {0}")]
    Es(#[from] std::io::Error),

    /// Una tecnica dijo haber tenido exito y su comprobacion dice que no, o dejo
    /// residuo tras revertir. Falla RUIDOSAMENTE: una emulacion a medias es peor
    /// que ninguna.
    #[error("la tecnica «{tecnica}» {que}")]
    Inconsistente {
        /// La tecnica implicada.
        tecnica: String,
        /// Que fallo.
        que: &'static str,
    },
}

/// La confirmacion de que se declara un rango, con autor y motivo.
///
/// Sin valor por defecto ni campos publicos: declarar un rango deja constancia de
/// quien y por que, como el modo obligatorio del confinamiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmacionRango {
    operador: String,
    motivo: String,
}

impl ConfirmacionRango {
    /// Declara la intencion de levantar un rango.
    #[must_use]
    pub fn nueva(operador: impl Into<String>, motivo: impl Into<String>) -> ConfirmacionRango {
        ConfirmacionRango {
            operador: operador.into(),
            motivo: motivo.into(),
        }
    }

    /// Quien lo ordeno.
    #[must_use]
    pub fn operador(&self) -> &str {
        &self.operador
    }

    /// Por que.
    #[must_use]
    pub fn motivo(&self) -> &str {
        &self.motivo
    }
}

/// La prueba de estar dentro de un rango declarado.
///
/// **Opaca a proposito**: sin constructor publico ni campos publicos. La unica
/// forma de tener una es [`Rango::prueba`]. Es lo que impide, por tipo, ejecutar
/// una emulacion fuera del rango.
#[derive(Debug)]
pub struct PruebaDeRango {
    // Sentinela privado: nadie fuera de este modulo puede construir el valor, ni
    // con `PruebaDeRango { .. }` (campo privado) ni con `Default` (no se deriva).
    // `PhantomData` es un marcador que el compilador considera usado, asi que no
    // hace falta silenciar ningun aviso para tener un tipo que no se puede
    // fabricar por fuera.
    _sello: PhantomData<()>,
}

/// El rango de emulacion: una plataforma declarada y un directorio jaula donde se
/// materializan y borran los artefactos.
#[derive(Debug)]
pub struct Rango {
    plataforma: Plataforma,
    raiz: PathBuf,
    confirmacion: ConfirmacionRango,
}

impl Rango {
    /// Declara un rango sobre una plataforma, con su directorio jaula y su
    /// confirmacion. Prepara el directorio si no existe.
    ///
    /// # Errores
    /// [`ErrorRango::Es`] si el directorio jaula no se puede preparar.
    pub fn declarar(
        plataforma: Plataforma,
        raiz: impl Into<PathBuf>,
        confirmacion: ConfirmacionRango,
    ) -> Result<Rango, ErrorRango> {
        let raiz = raiz.into();
        std::fs::create_dir_all(&raiz)?;
        Ok(Rango {
            plataforma,
            raiz,
            confirmacion,
        })
    }

    /// Acuna la prueba de estar en este rango. Es el unico sitio del que sale una
    /// [`PruebaDeRango`].
    #[must_use]
    pub fn prueba(&self) -> PruebaDeRango {
        PruebaDeRango {
            _sello: PhantomData,
        }
    }

    /// La plataforma del rango.
    #[must_use]
    pub fn plataforma(&self) -> Plataforma {
        self.plataforma
    }

    /// El directorio jaula.
    #[must_use]
    pub fn raiz(&self) -> &Path {
        &self.raiz
    }

    /// La confirmacion con la que se declaro.
    #[must_use]
    pub fn confirmacion(&self) -> &ConfirmacionRango {
        &self.confirmacion
    }

    /// La ruta, dentro de la jaula, del artefacto marcador de una tecnica.
    ///
    /// Siempre bajo [`Rango::raiz`]: una tecnica no toca nada fuera de la jaula.
    #[must_use]
    pub fn ruta_marcador(&self, id_tecnica: &str) -> PathBuf {
        // El id de una tecnica es un identificador ATT&CK (`T1059`), sin separadores
        // de ruta; aun asi se sanea para que ningun catalogo pueda escapar de la
        // jaula con `../`.
        let seguro: String = id_tecnica
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        self.raiz.join(format!("marcador_{seguro}.rango"))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn rango_tmp() -> Rango {
        let raiz = std::env::temp_dir().join(format!("aegis-rango-{}", std::process::id()));
        Rango::declarar(
            Plataforma::Linux,
            raiz,
            ConfirmacionRango::nueva("ci", "prueba de cobertura"),
        )
        .expect("declarar rango")
    }

    #[test]
    fn la_prueba_de_rango_solo_sale_de_un_rango() {
        // No hay `PruebaDeRango::nueva` ni campos publicos: la unica via es esta.
        let r = rango_tmp();
        let _prueba = r.prueba();
        // Que compile esto y NO exista otra via es la garantia; lo segundo se fija
        // en un doctest compile_fail del rasgo Tecnica.
    }

    #[test]
    fn el_marcador_no_escapa_de_la_jaula() {
        let r = rango_tmp();
        let ruta = r.ruta_marcador("../../etc/passwd");
        assert!(
            ruta.starts_with(r.raiz()),
            "un id malicioso no puede sacar el marcador de la jaula: {ruta:?}"
        );
    }

    #[test]
    fn la_confirmacion_lleva_autor_y_motivo() {
        let c = ConfirmacionRango::nueva("ana", "validar deteccion de persistencia");
        assert_eq!(c.operador(), "ana");
        assert!(!c.motivo().is_empty());
    }
}
