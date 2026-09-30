//! El canal entre el agente y su trabajador confinado.
//!
//! # La propiedad de seguridad, en una frase
//!
//! **El trabajador solo puede opinar como analisis estatico, y nunca pedir nada.**
//!
//! Al otro lado de este canal corre codigo que acaba de leer bytes escritos por
//! un atacante: hay que suponerlo comprometido. Por eso:
//!
//! - Ninguna trama que envia el trabajador es una orden: solo hay [`Hola`],
//!   [`Informe`] y [`Tipo::Fallo`]. El agente no ejecuta nada de lo que llega.
//! - Un hallazgo solo puede ir firmado como [`Motor::Estatico`] o
//!   [`Motor::Aprendizaje`]: el decodificador rechaza cualquier otra firma. Y por
//!   las reglas del arbitro, un plano estatico solo NUNCA llega a «malicioso»
//!   (regla 6: hacen falta dos planos que acusen) ni a severidad critica (regla
//!   4). Un trabajador comprometido puede, como mucho, mentir en el plano en el
//!   que ya se desconfia: no puede provocar una contencion por su cuenta.
//! - Toda longitud tiene tope y se comprueba ANTES de reservar memoria. El campo
//!   de longitud lo escribe quien puede estar comprometido.
//!
//! # Formato
//!
//! ```text
//!   magia[4] version[2] tipo[2] id[8] largo[4] carga[largo]
//! ```
//!
//! Enteros en little-endian y longitudes fijas: el mismo binario hace de agente
//! y de trabajador, pero el protocolo no depende de ello para poder probarse y
//! mutarse (fuzzing) por separado.

use std::fmt;
use std::io::{self, Read, Write};

use aegis_entidad::{Confianza, Juicio, Motor, Severidad};

use crate::analizadores::Analizador;

/// Marca de trama.
pub const MAGIA: [u8; 4] = *b"AGTR";

/// Version del protocolo. Una trama de otra version no se interpreta.
pub const VERSION: u16 = 1;

/// Bytes de la cabecera.
pub const CABECERA: usize = 4 + 2 + 2 + 8 + 4;

/// Carga maxima de una trama: el fichero mas grande que se analiza, mas margen.
pub const MAX_CARGA: usize = MAX_DATOS + 64;

/// Bytes maximos de los datos de una peticion.
///
/// Un ejecutable legitimo de mas de 48 MiB existe (navegadores, toolchains), y
/// no se analiza entero: el agente lo declara `SinDatos` por tamaño en vez de
/// mandarlo. El tope protege al trabajador y al canal, no es un umbral de
/// deteccion.
pub const MAX_DATOS: usize = 48 * 1024 * 1024;

/// Hallazgos maximos en un informe.
pub const MAX_HALLAZGOS: usize = 64;

/// Bytes maximos del texto de un hallazgo o de un fallo.
pub const MAX_TEXTO: usize = 2048;

/// Analizadores maximos que puede anunciar un trabajador.
pub const MAX_ANALIZADORES: usize = 64;

/// Clase de trama.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tipo {
    /// Del trabajador: arranco, esta confinado y esto es lo que sabe hacer.
    Hola,
    /// Del agente: analiza estos bytes con este analizador.
    Peticion,
    /// Del trabajador: lo que encontro.
    Informe,
    /// Del trabajador: no pudo analizarlo, y por que.
    Fallo,
}

impl Tipo {
    fn tag(self) -> u16 {
        match self {
            Tipo::Hola => 1,
            Tipo::Peticion => 2,
            Tipo::Informe => 3,
            Tipo::Fallo => 4,
        }
    }

    fn desde_tag(t: u16) -> Option<Tipo> {
        match t {
            1 => Some(Tipo::Hola),
            2 => Some(Tipo::Peticion),
            3 => Some(Tipo::Informe),
            4 => Some(Tipo::Fallo),
            _ => None,
        }
    }
}

/// Una trama del canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trama {
    /// Su clase.
    pub tipo: Tipo,
    /// Identificador de la peticion a la que pertenece (0 en `Hola`).
    pub id: u64,
    /// La carga, sin interpretar.
    pub carga: Vec<u8>,
}

/// Lo que puede ir mal leyendo del canal.
#[derive(Debug)]
pub enum ErrorProtocolo {
    /// El canal se cerro (el otro extremo murio).
    Cerrado,
    /// Error de E/S.
    Es(io::Error),
    /// La trama no es de este protocolo o de esta version, o viola un tope.
    Invalida(String),
}

impl fmt::Display for ErrorProtocolo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorProtocolo::Cerrado => f.write_str("canal cerrado"),
            ErrorProtocolo::Es(e) => write!(f, "error de E/S: {e}"),
            ErrorProtocolo::Invalida(m) => write!(f, "trama invalida: {m}"),
        }
    }
}

impl std::error::Error for ErrorProtocolo {}

fn invalida(m: impl Into<String>) -> ErrorProtocolo {
    ErrorProtocolo::Invalida(m.into())
}

/// Escribe una trama.
///
/// # Errores
///
/// Los de E/S, o una carga por encima de [`MAX_CARGA`].
pub fn escribir(w: &mut impl Write, t: &Trama) -> io::Result<()> {
    if t.carga.len() > MAX_CARGA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "carga por encima del tope del protocolo",
        ));
    }
    let mut cab = [0u8; CABECERA];
    cab[0..4].copy_from_slice(&MAGIA);
    cab[4..6].copy_from_slice(&VERSION.to_le_bytes());
    cab[6..8].copy_from_slice(&t.tipo.tag().to_le_bytes());
    cab[8..16].copy_from_slice(&t.id.to_le_bytes());
    cab[16..20].copy_from_slice(&(t.carga.len() as u32).to_le_bytes());
    w.write_all(&cab)?;
    w.write_all(&t.carga)?;
    w.flush()
}

/// Lee una trama, comprobando cabecera y topes antes de reservar memoria.
///
/// # Errores
///
/// [`ErrorProtocolo::Cerrado`] si el canal se cerro limpiamente entre tramas;
/// [`ErrorProtocolo::Invalida`] si la trama no es valida.
pub fn leer(r: &mut impl Read) -> Result<Trama, ErrorProtocolo> {
    let mut cab = [0u8; CABECERA];
    match r.read_exact(&mut cab) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ErrorProtocolo::Cerrado),
        Err(e) => return Err(ErrorProtocolo::Es(e)),
    }
    decodificar_cabecera(&cab).and_then(|(tipo, id, largo)| {
        let mut carga = vec![0u8; largo];
        r.read_exact(&mut carga).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                ErrorProtocolo::Cerrado
            } else {
                ErrorProtocolo::Es(e)
            }
        })?;
        Ok(Trama { tipo, id, carga })
    })
}

/// Interpreta una cabecera: `(tipo, id, largo)`.
///
/// # Errores
///
/// Magia, version o tipo desconocidos, o un largo por encima del tope.
pub fn decodificar_cabecera(cab: &[u8; CABECERA]) -> Result<(Tipo, u64, usize), ErrorProtocolo> {
    if cab[0..4] != MAGIA {
        return Err(invalida("magia desconocida"));
    }
    let version = u16::from_le_bytes([cab[4], cab[5]]);
    if version != VERSION {
        return Err(invalida(format!(
            "version {version}, se esperaba {VERSION}"
        )));
    }
    let tipo = Tipo::desde_tag(u16::from_le_bytes([cab[6], cab[7]]))
        .ok_or_else(|| invalida("tipo desconocido"))?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&cab[8..16]);
    let largo = u32::from_le_bytes([cab[16], cab[17], cab[18], cab[19]]) as usize;
    if largo > MAX_CARGA {
        return Err(invalida(format!(
            "largo {largo} por encima del tope {MAX_CARGA}"
        )));
    }
    Ok((tipo, u64::from_le_bytes(id), largo))
}

// ── Cargas ───────────────────────────────────────────────────────────────────

/// Lector de una carga con comprobacion de limites en cada paso.
struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn nuevo(b: &'a [u8]) -> Cursor<'a> {
        Cursor { b, i: 0 }
    }
    fn tomar(&mut self, n: usize) -> Result<&'a [u8], ErrorProtocolo> {
        let fin = self
            .i
            .checked_add(n)
            .ok_or_else(|| invalida("desbordamiento"))?;
        let s = self
            .b
            .get(self.i..fin)
            .ok_or_else(|| invalida("carga corta"))?;
        self.i = fin;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ErrorProtocolo> {
        Ok(self.tomar(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ErrorProtocolo> {
        let s = self.tomar(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn texto(&mut self) -> Result<String, ErrorProtocolo> {
        let n = usize::from(self.u16()?);
        if n > MAX_TEXTO {
            return Err(invalida("texto por encima del tope"));
        }
        // Se escapa en vez de rechazar: el texto puede citar bytes del fichero.
        Ok(String::from_utf8_lossy(self.tomar(n)?).into_owned())
    }
    fn resto(&mut self) -> &'a [u8] {
        let s = &self.b[self.i..];
        self.i = self.b.len();
        s
    }
    fn fin(&self) -> Result<(), ErrorProtocolo> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(invalida("bytes sobrantes en la carga"))
        }
    }
}

fn poner_texto(v: &mut Vec<u8>, s: &str) {
    let mut n = s.len().min(MAX_TEXTO);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    v.extend_from_slice(&(n as u16).to_le_bytes());
    v.extend_from_slice(&s.as_bytes()[..n]);
}

/// Lo primero que dice el trabajador: que arranco, como quedo confinado y que
/// sabe analizar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hola {
    /// Los analizadores que sabe ejecutar.
    pub analizadores: Vec<Analizador>,
    /// El confinamiento que se aplico a si mismo, en una frase por capa.
    pub confinamiento: String,
}

impl Hola {
    /// Codifica.
    #[must_use]
    pub fn codificar(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let n = self.analizadores.len().min(MAX_ANALIZADORES);
        v.extend_from_slice(&(n as u16).to_le_bytes());
        for a in &self.analizadores[..n] {
            v.extend_from_slice(&a.tag().to_le_bytes());
        }
        poner_texto(&mut v, &self.confinamiento);
        v
    }

    /// Decodifica. Un analizador de tag desconocido se ignora: el agente solo
    /// pide lo que ambos conocen.
    ///
    /// # Errores
    ///
    /// Carga mal formada.
    pub fn decodificar(b: &[u8]) -> Result<Hola, ErrorProtocolo> {
        let mut c = Cursor::nuevo(b);
        let n = usize::from(c.u16()?);
        if n > MAX_ANALIZADORES {
            return Err(invalida("demasiados analizadores"));
        }
        let mut analizadores = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(a) = Analizador::desde_tag(c.u16()?) {
                analizadores.push(a);
            }
        }
        let confinamiento = c.texto()?;
        c.fin()?;
        Ok(Hola {
            analizadores,
            confinamiento,
        })
    }
}

/// Una peticion de analisis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peticion {
    /// Con que analizar.
    pub analizador: Analizador,
    /// Los bytes, tal cual.
    pub datos: Vec<u8>,
}

impl Peticion {
    /// Codifica.
    #[must_use]
    pub fn codificar(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + self.datos.len());
        v.extend_from_slice(&self.analizador.tag().to_le_bytes());
        v.extend_from_slice(&self.datos);
        v
    }

    /// Decodifica.
    ///
    /// # Errores
    ///
    /// Analizador desconocido o datos por encima del tope.
    pub fn decodificar(b: &[u8]) -> Result<Peticion, ErrorProtocolo> {
        let mut c = Cursor::nuevo(b);
        let analizador =
            Analizador::desde_tag(c.u16()?).ok_or_else(|| invalida("analizador desconocido"))?;
        let datos = c.resto();
        if datos.len() > MAX_DATOS {
            return Err(invalida("datos por encima del tope"));
        }
        Ok(Peticion {
            analizador,
            datos: datos.to_vec(),
        })
    }
}

/// Algo que el trabajador encontro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hallazgo {
    /// En nombre de quien: solo [`Motor::Estatico`] o [`Motor::Aprendizaje`].
    pub firma: Motor,
    /// Que dice.
    pub juicio: Juicio,
    /// Cuanto daño haria si fuera verdad.
    pub severidad: Severidad,
    /// Cuanto se cree.
    pub confianza: Confianza,
    /// Por que, en una frase.
    pub porque: String,
}

/// Lo que el trabajador encontro en unos bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Informe {
    /// Lo encontrado. Vacio no es «limpio»: solo que nadie acuso.
    pub hallazgos: Vec<Hallazgo>,
    /// Si el analisis cubrio todo lo que debia (sin cortes por plazo o tope).
    pub completo: bool,
}

fn tag_firma(m: Motor) -> Option<u8> {
    match m {
        Motor::Estatico => Some(1),
        Motor::Aprendizaje => Some(2),
        _ => None,
    }
}

fn firma_de(t: u8) -> Option<Motor> {
    match t {
        1 => Some(Motor::Estatico),
        2 => Some(Motor::Aprendizaje),
        _ => None,
    }
}

fn tag_juicio(j: Juicio) -> u8 {
    match j {
        Juicio::Malicioso => 0,
        Juicio::Sospechoso => 1,
        Juicio::Limpio => 2,
        Juicio::NoConcluyente => 3,
    }
}

fn juicio_de(t: u8) -> Option<Juicio> {
    Juicio::todos().get(usize::from(t)).copied()
}

fn severidad_de(t: u8) -> Option<Severidad> {
    Severidad::todas().get(usize::from(t)).copied()
}

fn tag_severidad(s: Severidad) -> u8 {
    Severidad::todas()
        .iter()
        .position(|x| *x == s)
        .map_or(0, |p| p as u8)
}

impl Informe {
    /// Codifica. Una firma que el protocolo no admite no se codifica: el
    /// trabajador no puede ni expresarla.
    #[must_use]
    pub fn codificar(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(u8::from(self.completo));
        let validos: Vec<&Hallazgo> = self
            .hallazgos
            .iter()
            .filter(|h| tag_firma(h.firma).is_some())
            .take(MAX_HALLAZGOS)
            .collect();
        v.extend_from_slice(&(validos.len() as u16).to_le_bytes());
        for h in validos {
            v.push(tag_firma(h.firma).unwrap_or(1));
            v.push(tag_juicio(h.juicio));
            v.push(tag_severidad(h.severidad));
            v.push(h.confianza.centesimas());
            poner_texto(&mut v, &h.porque);
        }
        v
    }

    /// Decodifica, rechazando cualquier firma que no sea estatica.
    ///
    /// # Errores
    ///
    /// Carga mal formada, o un hallazgo firmado en nombre de otro plano.
    pub fn decodificar(b: &[u8]) -> Result<Informe, ErrorProtocolo> {
        let mut c = Cursor::nuevo(b);
        let completo = c.u8()? != 0;
        let n = usize::from(c.u16()?);
        if n > MAX_HALLAZGOS {
            return Err(invalida("demasiados hallazgos"));
        }
        let mut hallazgos = Vec::with_capacity(n);
        for _ in 0..n {
            let firma = firma_de(c.u8()?)
                .ok_or_else(|| invalida("hallazgo firmado fuera del plano estatico"))?;
            let juicio = juicio_de(c.u8()?).ok_or_else(|| invalida("juicio desconocido"))?;
            let severidad =
                severidad_de(c.u8()?).ok_or_else(|| invalida("severidad desconocida"))?;
            let confianza = Confianza::nueva(c.u8()?);
            let porque = c.texto()?;
            hallazgos.push(Hallazgo {
                firma,
                juicio,
                severidad,
                confianza,
                porque,
            });
        }
        c.fin()?;
        Ok(Informe {
            hallazgos,
            completo,
        })
    }
}

/// Codifica el texto de un fallo.
#[must_use]
pub fn codificar_fallo(motivo: &str) -> Vec<u8> {
    let mut v = Vec::new();
    poner_texto(&mut v, motivo);
    v
}

/// Decodifica el texto de un fallo.
///
/// # Errores
///
/// Carga mal formada.
pub fn decodificar_fallo(b: &[u8]) -> Result<String, ErrorProtocolo> {
    let mut c = Cursor::nuevo(b);
    let t = c.texto()?;
    c.fin()?;
    Ok(t)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ida_y_vuelta(t: &Trama) -> Trama {
        let mut v = Vec::new();
        escribir(&mut v, t).unwrap();
        leer(&mut v.as_slice()).unwrap()
    }

    #[test]
    fn una_trama_va_y_vuelve_igual() {
        let t = Trama {
            tipo: Tipo::Peticion,
            id: 42,
            carga: b"hola".to_vec(),
        };
        assert_eq!(ida_y_vuelta(&t), t);
    }

    #[test]
    fn un_largo_desorbitado_se_rechaza_sin_reservar() {
        let mut cab = [0u8; CABECERA];
        cab[0..4].copy_from_slice(&MAGIA);
        cab[4..6].copy_from_slice(&VERSION.to_le_bytes());
        cab[6..8].copy_from_slice(&3u16.to_le_bytes());
        cab[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decodificar_cabecera(&cab),
            Err(ErrorProtocolo::Invalida(_))
        ));
    }

    #[test]
    fn otra_version_no_se_interpreta() {
        let mut v = Vec::new();
        escribir(
            &mut v,
            &Trama {
                tipo: Tipo::Hola,
                id: 0,
                carga: vec![],
            },
        )
        .unwrap();
        v[4] = 9;
        assert!(matches!(
            leer(&mut v.as_slice()),
            Err(ErrorProtocolo::Invalida(_))
        ));
    }

    #[test]
    fn un_canal_cerrado_se_distingue_de_una_trama_mala() {
        assert!(matches!(leer(&mut &[][..]), Err(ErrorProtocolo::Cerrado)));
    }

    #[test]
    fn el_informe_va_y_vuelve() {
        let i = Informe {
            hallazgos: vec![Hallazgo {
                firma: Motor::Aprendizaje,
                juicio: Juicio::Sospechoso,
                severidad: Severidad::Media,
                confianza: Confianza::nueva(55),
                porque: "puntuacion 0,71".into(),
            }],
            completo: true,
        };
        assert_eq!(Informe::decodificar(&i.codificar()).unwrap(), i);
    }

    #[test]
    fn un_trabajador_comprometido_no_puede_firmar_como_otro_plano() {
        // A mano, sin pasar por `codificar` (que ni lo permite): firma 7.
        let mut b = vec![1u8];
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&[7, 0, 4, 99]);
        b.extend_from_slice(&0u16.to_le_bytes());
        assert!(Informe::decodificar(&b).is_err());
        // Y `codificar` descarta lo que no puede expresar.
        let i = Informe {
            hallazgos: vec![Hallazgo {
                firma: Motor::Detonate,
                juicio: Juicio::Malicioso,
                severidad: Severidad::Critica,
                confianza: Confianza::CIERTA,
                porque: "confia en mi".into(),
            }],
            completo: true,
        };
        assert!(Informe::decodificar(&i.codificar())
            .unwrap()
            .hallazgos
            .is_empty());
    }

    #[test]
    fn un_texto_largo_se_recorta_en_frontera_de_caracter() {
        let largo = "ñ".repeat(MAX_TEXTO);
        let mut v = Vec::new();
        poner_texto(&mut v, &largo);
        let t = Cursor::nuevo(&v).texto().unwrap();
        assert!(t.len() <= MAX_TEXTO);
        assert!(t.chars().all(|c| c == 'ñ'));
    }

    #[test]
    fn el_saludo_va_y_vuelve_e_ignora_lo_desconocido() {
        let h = Hola {
            analizadores: vec![Analizador::Modelo, Analizador::Pe],
            confinamiento: "red: cortada".into(),
        };
        assert_eq!(Hola::decodificar(&h.codificar()).unwrap(), h);
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&Analizador::Pe.tag().to_le_bytes());
        b.extend_from_slice(&999u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            Hola::decodificar(&b).unwrap().analizadores,
            vec![Analizador::Pe]
        );
    }
}
