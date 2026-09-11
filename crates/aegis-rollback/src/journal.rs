//! El diario de copias-sombra: decide QUE se copia y CUANDO.
//!
//! Es la logica que puede estar mal de forma peligrosa. Dos errores opuestos, y
//! los dos se pagan con ficheros:
//!
//! - **Copiar la version equivocada.** Si se guarda la copia DESPUES de que el
//!   ransomware cifre el fichero, la copia-sombra es la version cifrada y el
//!   rollback restaura basura. Por eso la copia se hace desde el contenido
//!   PREVIO a la escritura, y solo la PRIMERA vez que se toca cada fichero: la
//!   segunda pasada ya no piso la copia buena.
//! - **No copiar a tiempo.** Si se espera al veredicto del detector, los
//!   primeros ficheros ya estan cifrados y perdidos. Por eso el diario tambien
//!   dispara ante la senal cruda —una escritura que convierte un documento de
//!   baja entropia en algo de alta entropia— antes de que el veredicto global
//!   llegue.

use std::collections::HashSet;

/// Umbral por debajo del cual el contenido se considera "documento" (texto,
/// ofimatica): entropia normalizada baja.
pub const ENTROPIA_DOCUMENTO: f64 = 0.55;
/// Umbral por encima del cual el contenido se considera cifrado o comprimido:
/// entropia normalizada alta.
pub const ENTROPIA_CIFRADO: f64 = 0.85;

/// Que hacer ante una escritura observada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionDiario {
    /// Guardar una copia-sombra del contenido PREVIO antes de dejar escribir.
    Copiar,
    /// Ya se guardo una copia de este fichero en este incidente: no pisarla.
    YaCopiado,
    /// Nada sugiere cifrado y no hay incidente activo: dejar pasar sin copiar.
    Ignorar,
}

/// El diario: recuerda que ficheros ya tienen copia-sombra en este incidente y
/// decide sobre cada escritura nueva.
pub struct Journal {
    copiados: HashSet<[u8; 32]>,
    incidente_activo: bool,
    doc: f64,
    cifrado: f64,
}

impl Default for Journal {
    fn default() -> Journal {
        Journal::new()
    }
}

impl Journal {
    /// Un diario nuevo con los umbrales por defecto.
    pub fn new() -> Journal {
        Journal {
            copiados: HashSet::new(),
            incidente_activo: false,
            doc: ENTROPIA_DOCUMENTO,
            cifrado: ENTROPIA_CIFRADO,
        }
    }

    /// Marca que el detector (`aegis-ransom`) ya confirmo un incidente: a partir
    /// de aqui se preserva la primera version de CADA fichero que el proceso
    /// toque, sin esperar a ver la transicion de entropia fichero a fichero.
    pub fn activar_incidente(&mut self) {
        self.incidente_activo = true;
    }

    /// `true` si hay un incidente confirmado en curso.
    pub fn incidente_activo(&self) -> bool {
        self.incidente_activo
    }

    /// Huella estable de una ruta, para deduplicar sin guardar la ruta entera.
    fn huella(ruta: &[u8]) -> [u8; 32] {
        *blake3::hash(ruta).as_bytes()
    }

    /// Decide sobre una escritura. `muestra_previa` es el contenido actual del
    /// fichero (lo que se sobreescribiria); `muestra_nueva` es lo que se va a
    /// escribir. Ambas pueden ser un prefijo del fichero: la entropia de unos
    /// pocos KB ya distingue cifrado de documento.
    pub fn evaluar(
        &mut self,
        ruta: &[u8],
        muestra_previa: &[u8],
        muestra_nueva: &[u8],
    ) -> DecisionDiario {
        let h = Self::huella(ruta);
        if self.copiados.contains(&h) {
            return DecisionDiario::YaCopiado;
        }

        let disparar = if self.incidente_activo {
            // Incidente confirmado: preservar todo lo que el proceso toque.
            true
        } else {
            // Sin veredicto aun: disparar ante la firma cruda del cifrado, una
            // escritura que sube la entropia de documento a cifrado.
            let prev = entropia(muestra_previa);
            let nueva = entropia(muestra_nueva);
            prev <= self.doc && nueva >= self.cifrado
        };

        if disparar {
            self.copiados.insert(h);
            DecisionDiario::Copiar
        } else {
            DecisionDiario::Ignorar
        }
    }

    /// Cuantos ficheros se han preservado en este incidente.
    pub fn preservados(&self) -> usize {
        self.copiados.len()
    }

    /// Reinicia el diario al cerrar un incidente (tras revertir o descartar).
    pub fn reiniciar(&mut self) {
        self.copiados.clear();
        self.incidente_activo = false;
    }
}

/// Entropia normalizada [0,1] de una muestra. Una muestra vacia es 0 (no hay
/// nada que delate cifrado).
fn entropia(datos: &[u8]) -> f64 {
    aegis_ml::entropy::entropia_normalizada(datos).unwrap_or(0.0)
}
