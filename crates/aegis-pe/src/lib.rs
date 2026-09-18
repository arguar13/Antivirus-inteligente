//! # aegis-pe
//!
//! Lector de ejecutables de Windows (PE/COFF) y de la huella Authenticode.
//!
//! # El hueco que cierra
//!
//! El agente sabia mirar un proceso de Windows por fuera —quien lo lanzo, con
//! quien habla, que hace— y **no sabia abrir su fichero**. Todo lo que un EDR
//! decide sobre un ejecutable antes de dejarlo correr sale de dentro: si esta
//! firmado y por quien, si le han quitado la firma, si le han pegado algo
//! detras, si su punto de entrada esta donde deberia, si viene empaquetado.
//!
//! Sin eso, la paridad con Linux era de nombre: alli el agente lee ELF, `/proc`
//! y los mapas de memoria; en Windows tenia el esqueleto de la SCAL devolviendo
//! `Unsupported` con el nombre de la interfaz que falta. Honesto, y vacio.
//!
//! # Lo que hay
//!
//! | Pieza | Que resuelve | Modulo |
//! |---|---|---|
//! | Lectura acotada | que un fichero hostil no pueda tumbar el agente con un desplazamiento | [`lectura`] |
//! | Encabezados y secciones | PE32 y PE32+, tabla donde el fichero diga, no donde suela estar | [`imagen`] |
//! | Firma | donde esta la tabla de certificados y **que bytes cubre de verdad** | [`firma`] |
//! | Indicios | los hechos de la forma del fichero, cada uno con su falso positivo | [`indicios`] |
//!
//! # Las tres decisiones
//!
//! **Ninguna indexacion cruda.** Este crate lee enteros de desplazamientos que
//! vienen dentro del propio fichero: es decir, el atacante elige los
//! desplazamientos. Todo pasa por [`lectura::Lector`], que comprueba el limite y
//! devuelve un error con nombre. Un panico aqui, con `panic = "abort"`, es el
//! agente entero muriendose por un fichero — y un EDR que se puede matar
//! mandandole un fichero se desinstala solo.
//!
//! **La huella no es el hash del fichero.** Authenticode salta el `CheckSum`, la
//! entrada del directorio de seguridad y la tabla de certificados, y recorre las
//! secciones por orden de desplazamiento y no por el de la tabla. Saltarse de
//! mas deja editar el ejecutable sin invalidar la firma; saltarse de menos hace
//! que nada cuadre nunca. Ver [`firma`].
//!
//! **Indicios, no veredictos.** Cada hecho de [`indicios`] tiene falsos
//! positivos conocidos y los dice en su propia frase. Quien decide es el motor
//! de veredicto, con el linaje y el comportamiento delante.
//!
//! # Lo que este crate NO hace
//!
//! **No valida la firma criptograficamente.** Localiza la tabla de certificados,
//! calcula la huella que Windows compara y dice que bytes quedan fuera. Validar
//! el PKCS#7 —la cadena de confianza, la marca de tiempo, la revocacion— es otro
//! trabajo y otra superficie; presentarlo como hecho aqui seria decir «firma
//! valida» cuando lo que se comprobo es «hay una firma». Son cosas distintas y
//! este crate solo afirma la segunda.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate parsea entrada hostil. Es exactamente donde el producto no admite
// `unsafe`: un desbordamiento aqui es corrupcion de memoria en el camino por el
// que entra lo que escribe el atacante, en un proceso privilegiado.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod firma;
pub mod imagen;
pub mod indicios;
pub mod lectura;

pub use error::PeError;
pub use firma::{huella_authenticode, Certificado, Firma};
pub use imagen::{Directorio, Formato, Imagen, Seccion};
pub use indicios::Indicio;

/// Todo lo que se puede decir de un ejecutable de una sola pasada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Informe {
    /// Los encabezados y las secciones.
    pub imagen: Imagen,
    /// La tabla de certificados, si la lleva.
    pub firma: Option<Firma>,
    /// La huella que Windows compara con la que va dentro del PKCS#7.
    pub huella: [u8; 32],
    /// Los hechos sobre su forma.
    pub indicios: Vec<Indicio>,
}

impl Informe {
    /// Lee un ejecutable entero.
    pub fn de(bytes: &[u8]) -> Result<Informe, PeError> {
        let imagen = Imagen::leer(bytes)?;
        let firma = Firma::leer(&imagen, bytes)?;
        let huella = huella_authenticode(&imagen, bytes)?;
        let indicios = indicios::de(&imagen, firma.as_ref());
        Ok(Informe {
            imagen,
            firma,
            huella,
            indicios,
        })
    }

    /// Si lleva tabla de certificados.
    ///
    /// Se llama asi y no `firmado` a proposito: que haya una tabla no dice que
    /// la firma sea valida, ni de quien es. Un metodo llamado `firmado()`
    /// acabaria leyendose como lo segundo.
    pub fn lleva_tabla_de_certificados(&self) -> bool {
        self.firma.is_some()
    }
}
