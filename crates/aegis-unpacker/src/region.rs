//! Modelo de las regiones de codigo que aparecen en tiempo de ejecucion.
//!
//! El desempaquetado se basa en una distincion: las regiones ejecutables que ya
//! existian al arrancar el proceso —el propio binario, `libc`, el enlazador—
//! son de confianza; las que APARECEN despues, ejecutables y sin fichero detras,
//! son donde el empaquetador escribe el codigo real. El OEP (*Original Entry
//! Point*) es la primera instruccion que se ejecuta en una de esas regiones
//! nuevas.

/// Un rango de direcciones ejecutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rango {
    /// Direccion inicial.
    pub inicio: u64,
    /// Direccion final, exclusiva.
    pub fin: u64,
}

impl Rango {
    /// Indica si una direccion cae dentro del rango.
    pub fn contiene(&self, addr: u64) -> bool {
        addr >= self.inicio && addr < self.fin
    }

    /// Tamano en bytes.
    pub fn len(&self) -> u64 {
        self.fin.saturating_sub(self.inicio)
    }

    /// Indica si el rango esta vacio.
    pub fn is_empty(&self) -> bool {
        self.fin <= self.inicio
    }
}

/// Conjunto de regiones ejecutables, con la frontera entre las de arranque y
/// las que aparecieron en tiempo de ejecucion.
#[derive(Debug, Clone, Default)]
pub struct MapaEjecutable {
    /// Regiones ejecutables presentes al arrancar (de confianza).
    de_arranque: Vec<Rango>,
    /// Regiones ejecutables aparecidas despues (sospechosas).
    nuevas: Vec<Rango>,
}

impl MapaEjecutable {
    /// Crea un mapa con las regiones ejecutables iniciales.
    pub fn con_arranque(de_arranque: Vec<Rango>) -> MapaEjecutable {
        MapaEjecutable {
            de_arranque,
            nuevas: Vec::new(),
        }
    }

    /// Registra una region ejecutable aparecida en tiempo de ejecucion.
    ///
    /// Si solapa con una de arranque conocida, no es nueva: es una recarga de
    /// algo que ya estaba (el enlazador dinamico remapeando, por ejemplo).
    pub fn anadir_nueva(&mut self, r: Rango) {
        if self.es_de_arranque(r.inicio) {
            return;
        }
        // Fusion simple: si ya hay una nueva que la contiene, no se duplica.
        if self.nuevas.iter().any(|n| n.contiene(r.inicio)) {
            return;
        }
        self.nuevas.push(r);
    }

    /// Indica si una direccion cae en una region ejecutable de arranque.
    pub fn es_de_arranque(&self, addr: u64) -> bool {
        self.de_arranque.iter().any(|r| r.contiene(addr))
    }

    /// Devuelve la region NUEVA que contiene una direccion, si la hay.
    ///
    /// Que el puntero de instruccion caiga aqui es la senal del OEP: el proceso
    /// esta ejecutando codigo que no existia al arrancar.
    pub fn region_nueva_de(&self, addr: u64) -> Option<Rango> {
        self.nuevas.iter().copied().find(|r| r.contiene(addr))
    }

    /// Regiones nuevas registradas.
    pub fn nuevas(&self) -> &[Rango] {
        &self.nuevas
    }
}
