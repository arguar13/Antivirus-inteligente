//! El coste de una tabla, y el rechazo —en compilacion— de lo que no se puede
//! difundir a una flota.
//!
//! # El problema real, que no es de rendimiento
//!
//! Una consulta que tarda un minuto en una maquina tarda un minuto en las cien
//! mil, a la vez. Eso no es una consulta lenta: es una denegacion de servicio
//! que el cliente se hace a si mismo con su propia herramienta de seguridad, y
//! ademas se la hace durante un incidente, que es cuando esta cazando. El EDR
//! que tumba la produccion mientras la investiga no vuelve a instalarse.
//!
//! Hay dos caminos por los que una consulta llega a ejecutarse, y cada uno
//! necesita su defensa:
//!
//!   1. **Texto que escribe un operador** en la consola. Ahi no hay compilador
//!      que valga: se valida al analizar, y la tabla peligrosa que no viene
//!      acotada devuelve [`MotivoNoLeible::RequiereFiltro`] SIN tocar el
//!      sistema. Ver [`validar`].
//!   2. **Codigo del propio producto** que construye una caceria —una respuesta
//!      automatica, una comprobacion periodica, una regla—. Ese camino es mas
//!      peligroso que el primero, porque no hay nadie mirando cuando se
//!      ejecuta. Para ese camino, la combinacion prohibida NO COMPILA.
//!
//! # Como se consigue que no compile
//!
//! Con el coste y la acotacion como PARAMETROS DE TIPO, y un rasgo
//! [`SePuedeDifundir`] que sencillamente no tiene implementacion para las
//! combinaciones prohibidas. No hay comprobacion que saltarse ni bandera que
//! levantar: el metodo `difundir` exige `(C, A): SePuedeDifundir`, y para
//! `(Caro, SinAcotar)` esa implementacion no existe.
//!
//! Es la doctrina de «la ausencia es la frontera» aplicada al coste: lo que no
//! se puede expresar no se puede configurar mal.
//!
//! ```
//! use aegis_estado::coste::{Barato, Caceria, SinAcotar};
//!
//! // Una tabla barata se difunde sin acotar: esto compila y corre.
//! let c: Caceria<Barato, SinAcotar> = Caceria::nueva("SELECT pid FROM processes");
//! assert!(c.difundir().starts_with("SELECT"));
//! ```
//!
//! ```compile_fail
//! use aegis_estado::coste::{Caro, Caceria, SinAcotar};
//!
//! // Una tabla CARA sin acotar, difundida a la flota entera. Esto es lo que
//! // tiene que ser imposible, y lo es: no hay `SePuedeDifundir` para esta
//! // combinacion, asi que el programa NO COMPILA.
//! let c: Caceria<Caro, SinAcotar> = Caceria::nueva("SELECT sha256 FROM files");
//! c.difundir();
//! ```
//!
//! ```compile_fail
//! use aegis_estado::coste::{Peligroso, Caceria, SinAcotar};
//!
//! // Y lo peligroso, con mas razon.
//! let c: Caceria<Peligroso, SinAcotar> = Caceria::nueva("SELECT path FROM suid_binaries");
//! c.difundir();
//! ```
//!
//! ```
//! use aegis_estado::coste::{Acotada, Caceria, Peligroso};
//!
//! // Acotada, la misma tabla peligrosa se difunde sin problema.
//! let c: Caceria<Peligroso, Acotada> =
//!     Caceria::nueva("SELECT path FROM suid_binaries WHERE path LIKE '/tmp/%'");
//! assert!(c.difundir().contains("WHERE"));
//! ```

use std::marker::PhantomData;

use aegis_parser::esquema::Coste;

use crate::tabla::{Filtro, MotivoNoLeible, Tabla};

/// Un nivel de coste, como tipo.
pub trait NivelDeCoste {
    /// El valor equivalente en el esquema.
    const COSTE: Coste;
}

/// Coste trivial: el dato ya esta en memoria.
#[derive(Debug, Clone, Copy)]
pub struct Trivial;
/// Coste barato: una o dos lecturas por fila.
#[derive(Debug, Clone, Copy)]
pub struct Barato;
/// Coste medio: recorre una coleccion por fila.
#[derive(Debug, Clone, Copy)]
pub struct Medio;
/// Coste caro: lee y procesa contenido.
#[derive(Debug, Clone, Copy)]
pub struct Caro;
/// Coste peligroso: no lo acota el tamaño de la tabla.
#[derive(Debug, Clone, Copy)]
pub struct Peligroso;

impl NivelDeCoste for Trivial {
    const COSTE: Coste = Coste::Trivial;
}
impl NivelDeCoste for Barato {
    const COSTE: Coste = Coste::Barato;
}
impl NivelDeCoste for Medio {
    const COSTE: Coste = Coste::Medio;
}
impl NivelDeCoste for Caro {
    const COSTE: Coste = Coste::Caro;
}
impl NivelDeCoste for Peligroso {
    const COSTE: Coste = Coste::Peligroso;
}

/// Si la consulta acota la tabla o la recorre entera.
pub trait Acotacion {}

/// La consulta no acota: la tabla se recorre entera.
#[derive(Debug, Clone, Copy)]
pub struct SinAcotar;
/// La consulta acota por alguna columna que la tabla sabe aprovechar.
#[derive(Debug, Clone, Copy)]
pub struct Acotada;

impl Acotacion for SinAcotar {}
impl Acotacion for Acotada {}

/// Combinaciones de coste y acotacion que se pueden difundir a una flota.
///
/// LA AUSENCIA ES LA FRONTERA. Lo que hace el trabajo aqui no son las
/// implementaciones que hay, sino las DOS QUE FALTAN: `(Caro, SinAcotar)` y
/// `(Peligroso, SinAcotar)`. Anadir cualquiera de las dos —"solo para una
/// prueba", "solo para este caso"— desarma la garantia entera, y por eso este
/// rasgo es sellado: no se puede implementar desde fuera del crate.
pub trait SePuedeDifundir: sellado::Sellado {}

mod sellado {
    /// Impide implementar `SePuedeDifundir` desde otro crate.
    ///
    /// Sin esto, cualquiera podria escribir
    /// `impl SePuedeDifundir for (Caro, SinAcotar) {}` en su propio crate y la
    /// garantia se evaporaria sin tocar una linea de este fichero.
    pub trait Sellado {}
    impl Sellado for (super::Trivial, super::SinAcotar) {}
    impl Sellado for (super::Barato, super::SinAcotar) {}
    impl Sellado for (super::Medio, super::SinAcotar) {}
    impl<C: super::NivelDeCoste> Sellado for (C, super::Acotada) {}
}

impl SePuedeDifundir for (Trivial, SinAcotar) {}
impl SePuedeDifundir for (Barato, SinAcotar) {}
impl SePuedeDifundir for (Medio, SinAcotar) {}
impl<C: NivelDeCoste> SePuedeDifundir for (C, Acotada) {}

/// Una caceria con su coste y su acotacion escritos en el tipo.
///
/// El texto se guarda tal cual; lo que esta clase aporta no es analizarlo —de
/// eso ya se ocupa `aegis-parser`— sino que la combinacion coste/acotacion sea
/// una propiedad que el compilador comprueba, y no un comentario que alguien
/// leyo una vez.
#[derive(Debug, Clone)]
pub struct Caceria<C: NivelDeCoste, A: Acotacion> {
    texto: String,
    marca: PhantomData<(C, A)>,
}

impl<C: NivelDeCoste, A: Acotacion> Caceria<C, A> {
    /// Envuelve el texto de una consulta.
    pub fn nueva(texto: impl Into<String>) -> Caceria<C, A> {
        Caceria {
            texto: texto.into(),
            marca: PhantomData,
        }
    }

    /// El texto, sin comprobar nada. Para registro y diagnostico.
    pub fn texto(&self) -> &str {
        &self.texto
    }

    /// El coste declarado, como valor.
    pub fn coste(&self) -> Coste {
        C::COSTE
    }

    /// Entrega el texto para difundirlo a la flota.
    ///
    /// Solo compila si la combinacion de coste y acotacion lo permite.
    pub fn difundir(&self) -> &str
    where
        (C, A): SePuedeDifundir,
    {
        &self.texto
    }
}

/// Comprueba, en tiempo de ejecucion, lo mismo que los tipos comprueban en
/// compilacion.
///
/// Es la defensa del camino 1 —texto escrito por un operador—, donde no hay
/// tipos que valgan porque la tabla se decide al analizar la cadena. Devuelve
/// el motivo SIN tocar el sistema: una consulta rechazada no cuesta una sola
/// lectura de disco en ninguno de los cien mil endpoints.
pub fn validar(tabla: &dyn Tabla, filtro: &Filtro) -> Result<(), MotivoNoLeible> {
    tabla.exige_cota(filtro)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_coste_del_tipo_coincide_con_el_del_esquema() {
        // Los dos mundos —el de tipos y el de valores— tienen que decir lo
        // mismo. Si divergieran, el compilador estaria protegiendo de una cosa
        // y el validador de otra.
        assert_eq!(Trivial::COSTE, Coste::Trivial);
        assert_eq!(Barato::COSTE, Coste::Barato);
        assert_eq!(Medio::COSTE, Coste::Medio);
        assert_eq!(Caro::COSTE, Coste::Caro);
        assert_eq!(Peligroso::COSTE, Coste::Peligroso);
    }

    #[test]
    fn lo_barato_sin_acotar_se_difunde() {
        let c: Caceria<Barato, SinAcotar> = Caceria::nueva("SELECT pid FROM processes");
        assert_eq!(c.difundir(), "SELECT pid FROM processes");
        assert_eq!(c.coste(), Coste::Barato);
    }

    #[test]
    fn lo_caro_acotado_se_difunde() {
        let c: Caceria<Caro, Acotada> =
            Caceria::nueva("SELECT sha256 FROM files WHERE path = '/bin/sh'");
        assert!(c.difundir().contains("WHERE"));
    }

    #[test]
    fn lo_peligroso_acotado_se_difunde() {
        let c: Caceria<Peligroso, Acotada> =
            Caceria::nueva("SELECT path FROM suid_binaries WHERE path LIKE '/tmp/%'");
        assert!(c.difundir().contains("suid_binaries"));
    }

    #[test]
    fn lo_caro_sin_acotar_conserva_su_texto_aunque_no_se_pueda_difundir() {
        // Se puede CONSTRUIR y se puede registrar —hace falta para poder decirle
        // al operador que consulta se rechazo—; lo unico que no se puede es
        // difundirla, y eso lo impide el compilador.
        let c: Caceria<Caro, SinAcotar> = Caceria::nueva("SELECT sha256 FROM files");
        assert_eq!(c.texto(), "SELECT sha256 FROM files");
        assert_eq!(c.coste(), Coste::Caro);
    }
}
