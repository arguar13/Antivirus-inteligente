//! El clasificador de disparo: decidir si un evento toco un honey-token.
//!
//! Es la parte que puede estar mal de forma peligrosa. Un disparo de MENOS deja
//! pasar al atacante que ya esta recolectando credenciales —el momento exacto
//! que toda la fase existe para cazar—. Uno de MAS convierte una lectura
//! legitima en una alarma, y una decepcion que grita por nada se ignora enseguida.
//! Por eso el disparo exige que aparezca un marcador REGISTRADO: no "algo que
//! parece una credencial", sino UNO DE NUESTROS senuelos, atribuible.

use crate::destino::Destino;
use crate::registry::Registro;
use crate::token::{Atribucion, Marcador};

/// Un evento de kernel ya normalizado que podria haber tocado un token.
#[derive(Debug, Clone)]
pub enum Evento {
    /// Alguien leyo memoria de otro proceso (`process_vm_readv`/ptrace) y estos
    /// son los bytes que se llevo.
    LecturaMemoria {
        /// El proceso que hizo la lectura (el sospechoso).
        lector: String,
        /// Los bytes leidos.
        contenido: Vec<u8>,
    },
    /// Alguien abrio un fichero; esta es su ruta.
    AperturaFichero {
        /// El proceso que abrio el fichero.
        lector: String,
        /// La ruta abierta.
        ruta: String,
    },
}

/// Como se toco el token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComoDisparo {
    /// Leido de la memoria de un proceso por `lector`.
    LeidoDeMemoria {
        /// El proceso que lo leyo.
        lector: String,
    },
    /// El honey-file `ruta` fue abierto por `lector`.
    FicheroAbierto {
        /// El proceso que lo abrio.
        lector: String,
        /// La ruta del senuelo.
        ruta: String,
    },
}

/// Un disparo confirmado: un senuelo atribuible fue tocado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disparo {
    /// A quien estaba atado el token tocado.
    pub token: Atribucion,
    /// El marcador que aparecio.
    pub marcador: Marcador,
    /// Como se toco.
    pub como: ComoDisparo,
}

/// Clasifica un evento contra el registro, que es la **unica** fuente.
///
/// Devuelve todos los disparos: una lectura de memoria puede llevarse varios
/// tokens de una vez, y salen en el orden en que aparecen en los bytes.
///
/// # El marcador de un honey-file no se inventa
///
/// La version anterior rellenaba con `Marcador([0u8; 16])` el disparo de una
/// apertura de fichero, porque la ruta venia de una tabla aparte que no sabia el
/// marcador. Eso es un disparo que dice «se toco un senuelo» y no dice cual —y
/// ademas, todos los rellenos de ceros son el mismo marcador, asi que dos
/// senuelos distintos producian disparos indistinguibles—. Ahora la ruta ES el
/// destino ([`Destino::Fichero`]) y el registro devuelve el marcador autentico.
#[must_use]
pub fn clasificar(evento: &Evento, registro: &Registro) -> Vec<Disparo> {
    match evento {
        Evento::LecturaMemoria { lector, contenido } => registro
            .buscar_en(contenido)
            .into_iter()
            .map(|(marcador, token)| Disparo {
                token,
                marcador,
                como: ComoDisparo::LeidoDeMemoria {
                    lector: lector.clone(),
                },
            })
            .collect(),
        Evento::AperturaFichero { lector, ruta } => {
            let destino = Destino::Fichero { ruta: ruta.clone() };
            match registro.en_destino(&destino) {
                Some((marcador, atrib)) => vec![Disparo {
                    token: atrib.clone(),
                    marcador,
                    como: ComoDisparo::FicheroAbierto {
                        lector: lector.clone(),
                        ruta: ruta.clone(),
                    },
                }],
                None => Vec::new(),
            }
        }
    }
}
