//! La adquisicion de memoria, y lo que este tipo **no tiene**.
//!
//! # La invariante, y por que se verifica por ausencia
//!
//! Un adquiridor de memoria forense es una pieza que lee la memoria de procesos
//! ajenos con privilegios. La diferencia entre esa herramienta y una de ataque
//! no esta en la intencion de quien la use: esta en **qué operaciones existen**.
//! Un adquiridor que pudiera escribir seria una primitiva de inyeccion con otro
//! nombre, y la tendria cualquiera que se hiciera con el agente.
//!
//! Por eso aqui no hay ninguna operacion de escritura. No es que este
//! desactivada, ni protegida por una bandera, ni condicionada a un permiso: es
//! que **no existe**. [`Lectura`] tiene un metodo y devuelve bytes; no hay
//! `escribir`, no hay `ptrace(POKEDATA)`, no hay `process_vm_writev`, no hay un
//! descriptor abierto para escritura en todo el crate.
//!
//! Eso se comprueba de la unica forma que se puede comprobar una ausencia: la
//! puerta `tools/verificar-volcado.sh` busca esos caminos y falla si aparecen.
//! Es la invariante 9 del encargo — «se verifica por lo que FALTA, no por lo que
//! comprueba».
//!
//! # Por que la fuente es un rasgo y no un fichero
//!
//! Porque la memoria de un incidente llega de sitios distintos —un volcado en
//! disco, `/proc/<pid>/mem` de una maquina viva, la memoria de una microVM
//! pausada— y el analisis de [`crate::hallazgos`] tiene que ser el mismo para
//! los tres. Si el analisis supiera de donde vienen los bytes, habria tres
//! analisis y dos de ellos estarian peor probados.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::VolcadoError;
use crate::regiones::Region;

/// De donde salen los bytes de una memoria que se analiza.
///
/// **Solo lectura.** No hay en este rasgo ninguna operacion que modifique nada,
/// y anadir una convertiria el crate entero en otra cosa. Ver la cabecera del
/// modulo.
pub trait Lectura {
    /// Lee `cuantos` bytes desde `direccion`.
    ///
    /// Devuelve lo que se pudo leer, que puede ser menos de lo pedido: en una
    /// memoria real hay huecos sin mapear, y el que los haya es informacion, no
    /// un fallo. Devolver ceros por un hueco seria inventarse el contenido de
    /// una pagina que no existe.
    fn leer(&self, direccion: u64, cuantos: usize) -> Result<Vec<u8>, VolcadoError>;

    /// El mapa de lo que hay en esta memoria.
    fn regiones(&self) -> &[Region];
}

/// Tope de bytes que se leen de una vez.
///
/// Sin el, una region declarada de un terabyte —y un volcado puede declararlo,
/// porque el mapa lo escribe quien hizo el volcado— haria reservar un terabyte.
/// Diez megabytes cubren cualquier region de codigo real; las de datos se leen
/// por trozos.
pub const MAX_LECTURA: usize = 10 * 1024 * 1024;

/// Una memoria ya volcada a un fichero, con su mapa.
///
/// Es el caso forense clasico: alguien volco la memoria de una maquina y lo que
/// llega es eso, inerte. **Nada de lo que hay aqui se ejecuta**, y no hay camino
/// para que se ejecute: los bytes salen como `Vec<u8>` y el unico sitio al que
/// van es al desensamblador, que tampoco ejecuta nada.
#[derive(Debug)]
pub struct Volcado {
    fichero: File,
    regiones: Vec<Region>,
}

impl Volcado {
    /// Abre un volcado en disco con su mapa de regiones.
    ///
    /// El fichero se abre **para leer y nada mas**. `File::open` no da permiso
    /// de escritura, y en todo el crate no hay un `OpenOptions` que lo pida.
    pub fn abrir(ruta: &Path, regiones: Vec<Region>) -> Result<Volcado, VolcadoError> {
        let fichero = File::open(ruta).map_err(|e| VolcadoError::NoSePudoAbrir {
            ruta: ruta.display().to_string(),
            causa: e.to_string(),
        })?;
        let mut regiones = regiones;
        regiones.sort_by_key(|r| r.inicio);
        Ok(Volcado { fichero, regiones })
    }

    /// Donde cae `direccion` dentro del fichero, si cae en alguna region.
    fn desplazamiento(&self, direccion: u64) -> Option<(u64, u64)> {
        let r = self
            .regiones
            .iter()
            .find(|r| direccion >= r.inicio && direccion < r.fin)?;
        let dentro = direccion - r.inicio;
        Some((
            r.desplazamiento_en_volcado.checked_add(dentro)?,
            r.fin - direccion,
        ))
    }
}

impl Lectura for Volcado {
    fn leer(&self, direccion: u64, cuantos: usize) -> Result<Vec<u8>, VolcadoError> {
        let Some((off, hasta_el_final)) = self.desplazamiento(direccion) else {
            return Err(VolcadoError::SinMapear { direccion });
        };
        // Se lee hasta el final de la region y no mas: una lectura que cruzara
        // a la region siguiente devolveria bytes de otra parte del espacio de
        // direcciones como si fueran contiguos, y el analisis los leeria como
        // codigo continuo.
        let n = cuantos.min(MAX_LECTURA).min(hasta_el_final as usize);
        let mut v = vec![0u8; n];
        let mut f = &self.fichero;
        f.seek(SeekFrom::Start(off))
            .map_err(|e| VolcadoError::NoSePudoLeer {
                direccion,
                causa: e.to_string(),
            })?;
        let leidos = leer_todo(&mut f, &mut v);
        v.truncate(leidos);
        Ok(v)
    }

    fn regiones(&self) -> &[Region] {
        &self.regiones
    }
}

/// Lee todo lo que pueda en `destino` y devuelve cuanto leyo.
///
/// Un `read` corto no es un error: en un volcado truncado —que los hay, porque
/// volcar memoria de una maquina en marcha es una carrera— la ultima region
/// esta a medias. Lo que se devuelve es lo que habia, y quien lo reciba puede
/// verlo por el tamano.
fn leer_todo(f: &mut &File, destino: &mut [u8]) -> usize {
    let mut total = 0;
    while total < destino.len() {
        match f.read(&mut destino[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    total
}

/// Una memoria que ya esta en la propia memoria del analizador.
///
/// Para analizar lo que otra pieza ya trajo —la memoria de una microVM pausada,
/// una region que `aegis-memhunter` marco— sin volver a pasar por disco.
#[derive(Debug, Clone)]
pub struct EnMemoria {
    bytes: Vec<u8>,
    regiones: Vec<Region>,
}

impl EnMemoria {
    /// Envuelve unos bytes con su mapa.
    pub fn nueva(bytes: Vec<u8>, regiones: Vec<Region>) -> EnMemoria {
        let mut regiones = regiones;
        regiones.sort_by_key(|r| r.inicio);
        EnMemoria { bytes, regiones }
    }

    /// Una sola region, que es el caso de analizar un trozo suelto.
    pub fn una_region(bytes: Vec<u8>, base: u64, r: Region) -> EnMemoria {
        let mut r = r;
        r.inicio = base;
        r.fin = base.saturating_add(bytes.len() as u64);
        r.desplazamiento_en_volcado = 0;
        EnMemoria {
            bytes,
            regiones: vec![r],
        }
    }
}

impl Lectura for EnMemoria {
    fn leer(&self, direccion: u64, cuantos: usize) -> Result<Vec<u8>, VolcadoError> {
        let r = self
            .regiones
            .iter()
            .find(|r| direccion >= r.inicio && direccion < r.fin)
            .ok_or(VolcadoError::SinMapear { direccion })?;
        let dentro = (direccion - r.inicio) as usize;
        let off = r.desplazamiento_en_volcado as usize + dentro;
        let hasta_el_final = (r.fin - direccion) as usize;
        let n = cuantos.min(MAX_LECTURA).min(hasta_el_final);
        let fin = off.saturating_add(n).min(self.bytes.len());
        Ok(self.bytes.get(off..fin).unwrap_or(&[]).to_vec())
    }

    fn regiones(&self) -> &[Region] {
        &self.regiones
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::regiones::{Permisos, Respaldo};

    fn region(inicio: u64, fin: u64, off: u64) -> Region {
        Region {
            inicio,
            fin,
            permisos: Permisos {
                lectura: true,
                escritura: false,
                ejecucion: false,
            },
            respaldo: Respaldo::Anonima,
            desplazamiento_en_volcado: off,
        }
    }

    #[test]
    fn una_lectura_no_cruza_de_una_region_a_la_siguiente() {
        // Dos regiones separadas en el espacio de direcciones y contiguas en el
        // fichero. Una lectura que cruzara devolveria bytes de otra parte del
        // espacio de direcciones como si fueran continuos, y el desensamblador
        // los leeria como codigo seguido: instrucciones que el programa no tiene.
        let m = EnMemoria::nueva(
            vec![0xAA; 8].into_iter().chain(vec![0xBB; 8]).collect(),
            vec![region(0x1000, 0x1008, 0), region(0x9000, 0x9008, 8)],
        );
        let v = m.leer(0x1000, 64).unwrap();
        assert_eq!(v.len(), 8, "se para en el final de la region");
        assert!(v.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn una_direccion_sin_mapear_da_error_y_no_ceros() {
        // Devolver ceros seria inventarse el contenido de una pagina que no
        // existe, y el analisis de arriba no tendria forma de distinguir «aqui
        // hay ceros» de «aqui no hay nada».
        let m = EnMemoria::nueva(vec![0xAA; 8], vec![region(0x1000, 0x1008, 0)]);
        assert!(matches!(
            m.leer(0x5000, 8),
            Err(VolcadoError::SinMapear { .. })
        ));
    }

    #[test]
    fn una_peticion_enorme_no_reserva_memoria_enorme() {
        // El mapa de un volcado lo escribe quien hizo el volcado. Una region
        // declarada de un terabyte no puede hacer reservar un terabyte.
        let m = EnMemoria::nueva(vec![0xAA; 8], vec![region(0x1000, 0x1008, 0)]);
        let v = m.leer(0x1000, usize::MAX).unwrap();
        assert_eq!(v.len(), 8);
    }

    #[test]
    fn un_volcado_truncado_devuelve_lo_que_habia_y_se_nota_en_el_tamano() {
        // Volcar la memoria de una maquina en marcha es una carrera, y los
        // volcados a medias existen. Lo que se devuelve es lo que habia.
        let m = EnMemoria::nueva(vec![0xAA; 4], vec![region(0x1000, 0x1100, 0)]);
        let v = m.leer(0x1000, 256).unwrap();
        assert_eq!(v.len(), 4, "la region decia 256 y el fichero tenia 4");
    }

    #[test]
    fn las_regiones_salen_ordenadas_por_direccion() {
        // Para que dos analisis del mismo volcado recorran lo mismo en el mismo
        // orden y produzcan el mismo informe.
        let m = EnMemoria::nueva(
            vec![0; 32],
            vec![
                region(0x9000, 0x9008, 0),
                region(0x1000, 0x1008, 8),
                region(0x5000, 0x5008, 16),
            ],
        );
        let d: Vec<u64> = m.regiones().iter().map(|r| r.inicio).collect();
        assert_eq!(d, vec![0x1000, 0x5000, 0x9000]);
    }
}
