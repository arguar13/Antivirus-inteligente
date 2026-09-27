//! La MMU del emulador: paginas con permisos reales.
//!
//! # Por que los permisos importan aqui, y no en cualquier emulador
//!
//! Un empaquetador escribe el codigo desempaquetado en memoria y luego SALTA a el.
//! Para verlo —y desempaquetar sin firma— la MMU tiene que distinguir una escritura
//! de una ejecucion y recordar que una pagina ejecutable fue ESCRITA despues de
//! mapearse. Un emulador que trate la memoria como un `Vec<u8>` plano no puede ver
//! eso, y por eso el desempaquetado generico empieza aqui.
//!
//! # La cota
//!
//! El total de memoria mapeada esta acotado: una muestra no puede pedir que el
//! emulador reserve sin limite. Pasado el tope, mapear falla, y eso es un hecho que
//! el emulador declara, no un cuelgue.

use std::collections::BTreeMap;

/// El tamano de pagina del emulador. 4 KiB, como la mayoria de las plataformas.
pub const PAGINA: u64 = 0x1000;

/// Permisos de una pagina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permisos {
    /// Lectura.
    pub leer: bool,
    /// Escritura.
    pub escribir: bool,
    /// Ejecucion.
    pub ejecutar: bool,
}

impl Permisos {
    /// Solo lectura.
    #[must_use]
    pub const fn r() -> Permisos {
        Permisos {
            leer: true,
            escribir: false,
            ejecutar: false,
        }
    }
    /// Lectura y escritura.
    #[must_use]
    pub const fn rw() -> Permisos {
        Permisos {
            leer: true,
            escribir: true,
            ejecutar: false,
        }
    }
    /// Lectura y ejecucion.
    #[must_use]
    pub const fn rx() -> Permisos {
        Permisos {
            leer: true,
            escribir: false,
            ejecutar: true,
        }
    }
    /// Lectura, escritura y ejecucion (lo que un empaquetador pide, y una senal
    /// por si sola).
    #[must_use]
    pub const fn rwx() -> Permisos {
        Permisos {
            leer: true,
            escribir: true,
            ejecutar: true,
        }
    }
}

/// Por que fallo un acceso a memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalloMemoria {
    /// La direccion no esta mapeada.
    NoMapeada,
    /// La pagina no permite la operacion (leer/escribir/ejecutar).
    SinPermiso,
    /// Se supero el tope de memoria mapeada.
    TopeExcedido,
}

/// Una pagina de memoria.
#[derive(Debug, Clone)]
struct Pagina {
    bytes: [u8; PAGINA as usize],
    permisos: Permisos,
    /// Si esta pagina se escribio DESPUES de mapearse. Es la senal de
    /// desempaquetado: codigo que aparece en tiempo de ejecucion.
    escrita_tras_mapear: bool,
}

/// La unidad de gestion de memoria del emulador.
#[derive(Debug, Default)]
pub struct Mmu {
    paginas: BTreeMap<u64, Pagina>,
    /// Tope de paginas mapeadas.
    tope_paginas: usize,
}

impl Mmu {
    /// Una MMU con un tope de memoria (en bytes, redondeado a paginas).
    #[must_use]
    pub fn nueva(tope_bytes: u64) -> Mmu {
        Mmu {
            paginas: BTreeMap::new(),
            tope_paginas: (tope_bytes / PAGINA).max(1) as usize,
        }
    }

    /// Numero de paginas mapeadas.
    #[must_use]
    pub fn paginas_mapeadas(&self) -> usize {
        self.paginas.len()
    }

    /// La direccion base de la pagina que contiene `dir`.
    #[must_use]
    fn base(dir: u64) -> u64 {
        dir & !(PAGINA - 1)
    }

    /// Mapea un rango con unos permisos, rellenando con ceros.
    ///
    /// # Errores
    /// [`FalloMemoria::TopeExcedido`] si se pasa del tope de paginas.
    pub fn mapear(&mut self, dir: u64, tam: u64, permisos: Permisos) -> Result<(), FalloMemoria> {
        let ini = Self::base(dir);
        let fin = Self::base(dir + tam.saturating_sub(1)) + PAGINA;
        let mut p = ini;
        while p < fin {
            if !self.paginas.contains_key(&p) {
                if self.paginas.len() >= self.tope_paginas {
                    return Err(FalloMemoria::TopeExcedido);
                }
                self.paginas.insert(
                    p,
                    Pagina {
                        bytes: [0u8; PAGINA as usize],
                        permisos,
                        escrita_tras_mapear: false,
                    },
                );
            } else if let Some(pag) = self.paginas.get_mut(&p) {
                pag.permisos = permisos;
            }
            p += PAGINA;
        }
        Ok(())
    }

    /// Escribe bytes en memoria, comprobando permiso de escritura. Marca las
    /// paginas como escritas-tras-mapear: la senal de desempaquetado.
    ///
    /// # Errores
    /// [`FalloMemoria`] si algun byte cae fuera de mapa o sin permiso de escritura.
    pub fn escribir(&mut self, dir: u64, datos: &[u8]) -> Result<(), FalloMemoria> {
        for (i, &b) in datos.iter().enumerate() {
            let d = dir.wrapping_add(i as u64);
            let base = Self::base(d);
            let pag = self.paginas.get_mut(&base).ok_or(FalloMemoria::NoMapeada)?;
            if !pag.permisos.escribir {
                return Err(FalloMemoria::SinPermiso);
            }
            pag.bytes[(d - base) as usize] = b;
            pag.escrita_tras_mapear = true;
        }
        Ok(())
    }

    /// Lee bytes de memoria, comprobando permiso de lectura.
    ///
    /// # Errores
    /// [`FalloMemoria`] si algun byte cae fuera de mapa o sin permiso de lectura.
    pub fn leer(&self, dir: u64, tam: usize) -> Result<Vec<u8>, FalloMemoria> {
        let mut out = Vec::with_capacity(tam);
        for i in 0..tam {
            let d = dir.wrapping_add(i as u64);
            let base = Self::base(d);
            let pag = self.paginas.get(&base).ok_or(FalloMemoria::NoMapeada)?;
            if !pag.permisos.leer {
                return Err(FalloMemoria::SinPermiso);
            }
            out.push(pag.bytes[(d - base) as usize]);
        }
        Ok(out)
    }

    /// Lee para EJECUTAR: exige permiso de ejecucion. Es la operacion que el
    /// interprete usa para traer la siguiente instruccion, y separarla de una
    /// lectura de datos es lo que hace cumplir W^X.
    ///
    /// # Errores
    /// [`FalloMemoria`] si no esta mapeada o no es ejecutable.
    pub fn leer_para_ejecutar(&self, dir: u64, tam: usize) -> Result<Vec<u8>, FalloMemoria> {
        let base = Self::base(dir);
        let pag = self.paginas.get(&base).ok_or(FalloMemoria::NoMapeada)?;
        if !pag.permisos.ejecutar {
            return Err(FalloMemoria::SinPermiso);
        }
        // La lectura en si comprueba el resto de paginas por permiso de lectura;
        // una pagina ejecutable es tambien legible en este modelo.
        self.leer(dir, tam)
    }

    /// Las paginas ejecutables que se escribieron despues de mapearse, en orden.
    /// Son las candidatas a contener codigo desempaquetado.
    #[must_use]
    pub fn paginas_escritas_y_ejecutables(&self) -> Vec<u64> {
        self.paginas
            .iter()
            .filter(|(_, p)| p.escrita_tras_mapear && p.permisos.ejecutar)
            .map(|(dir, _)| *dir)
            .collect()
    }

    /// La entropia de Shannon (en bits por byte, 0..8) de una pagina, para detectar
    /// la caida de entropia que marca el fin del desempaquetado.
    #[must_use]
    pub fn entropia_pagina(&self, dir: u64) -> Option<f64> {
        let pag = self.paginas.get(&Self::base(dir))?;
        let mut cuenta = [0u32; 256];
        for &b in &pag.bytes {
            cuenta[b as usize] += 1;
        }
        let total = PAGINA as f64;
        let mut h = 0.0;
        for &c in &cuenta {
            if c > 0 {
                let p = f64::from(c) / total;
                h -= p * p.log2();
            }
        }
        Some(h)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_escritura_sin_permiso_falla_en_vez_de_ocurrir() {
        let mut m = Mmu::nueva(1 << 20);
        m.mapear(0x1000, 0x1000, Permisos::rx()).unwrap();
        assert_eq!(m.escribir(0x1000, &[0x90]), Err(FalloMemoria::SinPermiso));
    }

    #[test]
    fn leer_sin_mapear_falla() {
        let m = Mmu::nueva(1 << 20);
        assert_eq!(m.leer(0x1000, 1), Err(FalloMemoria::NoMapeada));
    }

    #[test]
    fn una_pagina_ejecutable_escrita_es_candidata_a_desempaquetado() {
        // El nucleo del desempaquetado generico: codigo que aparece en ejecucion.
        let mut m = Mmu::nueva(1 << 20);
        m.mapear(0x2000, 0x1000, Permisos::rwx()).unwrap();
        assert!(
            m.paginas_escritas_y_ejecutables().is_empty(),
            "recien mapeada, no escrita"
        );
        m.escribir(0x2000, &[0x48, 0x31, 0xc0]).unwrap();
        assert_eq!(m.paginas_escritas_y_ejecutables(), vec![0x2000]);
    }

    #[test]
    fn ejecutar_una_pagina_no_ejecutable_falla() {
        let mut m = Mmu::nueva(1 << 20);
        m.mapear(0x1000, 0x1000, Permisos::rw()).unwrap();
        m.escribir(0x1000, &[0x90]).unwrap();
        assert_eq!(
            m.leer_para_ejecutar(0x1000, 1),
            Err(FalloMemoria::SinPermiso)
        );
    }

    #[test]
    fn el_tope_de_memoria_se_respeta() {
        let mut m = Mmu::nueva(2 * PAGINA); // dos paginas
        m.mapear(0x1000, 0x1000, Permisos::rw()).unwrap();
        m.mapear(0x2000, 0x1000, Permisos::rw()).unwrap();
        assert_eq!(
            m.mapear(0x3000, 0x1000, Permisos::rw()),
            Err(FalloMemoria::TopeExcedido)
        );
    }

    #[test]
    fn la_entropia_de_ceros_es_cero_y_la_de_ruido_es_alta() {
        let mut m = Mmu::nueva(1 << 20);
        m.mapear(0x1000, 0x1000, Permisos::rw()).unwrap();
        assert_eq!(
            m.entropia_pagina(0x1000),
            Some(0.0),
            "una pagina de ceros no tiene entropia"
        );
        let ruido: Vec<u8> = (0..=255u16).cycle().take(4096).map(|x| x as u8).collect();
        m.escribir(0x1000, &ruido).unwrap();
        assert!(
            m.entropia_pagina(0x1000).unwrap() > 7.0,
            "ruido uniforme: entropia alta"
        );
    }
}
