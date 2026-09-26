//! Codificacion por columna, y compresion.
//!
//! # Por que por columna
//!
//! La telemetria es muy repetitiva POR COLUMNA y muy poco por fila: mil filas
//! de `processes` tienen mil `uid` casi todos iguales, mil `start_ns` crecientes
//! que se diferencian en unos pocos microsegundos y mil `path` que se repiten
//! entre una docena. Guardadas fila a fila, esa redundancia no la ve ningun
//! compresor; guardadas columna a columna, cada columna se codifica con lo que
//! sabe de si misma y luego se comprime:
//!
//! | Tipo | Codificacion |
//! |---|---|
//! | Entero | delta con el anterior, zigzag y varint: una serie de instantes crecientes cabe en uno o dos bytes por valor |
//! | Real | XOR con el anterior (la idea de Gorilla): valores parecidos dan muchos ceros |
//! | Texto | diccionario si se repite (cada valor es un indice), plano si no |
//! | Booleano | un bit por valor |
//!
//! Y un mapa de presencia cuando falta algun valor: [`Valor::Ausente`] es un
//! valor mas del modelo —lo que no se pudo leer en el endpoint— y tiene que
//! sobrevivir al almacen, no convertirse en cero ni en cadena vacia.
//!
//! Ademas, leer una columna es leer SOLO esa columna: una consulta que filtra
//! por `ts` y devuelve `name` no descomprime `cmdline`.
//!
//! # Entrada que vuelve de disco
//!
//! Lo que se decodifica viene de la base de datos: no lo escribio un atacante,
//! pero puede estar corrupto. Decodificar nunca entra en panico, respeta un tope
//! de filas y de bytes, y un bloque que no cuadra es un error, no una columna a
//! medias.

use aegis_parser::esquema::Tipo;
use aegis_parser::valor::Valor;

/// Filas maximas de un segmento.
pub const MAX_FILAS: usize = 65_536;

/// Bytes maximos de una columna descomprimida.
pub const MAX_DESCOMPRIMIDO: usize = 64 * 1024 * 1024;

/// Error de decodificacion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorCodec {
    /// El bloque no se descomprime.
    #[error("columna corrupta: {0}")]
    Corrupta(&'static str),
    /// Mas filas de las que un segmento puede tener.
    #[error("la columna declara {0} filas, por encima del tope")]
    DemasiadasFilas(usize),
}

const PLANO_ENTERO: u8 = 1;
const XOR_REAL: u8 = 2;
const TEXTO_PLANO: u8 = 3;
const TEXTO_DICCIONARIO: u8 = 4;
const BITS_BOOLEANO: u8 = 5;

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn dezigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Lector acotado de un bloque.
struct Lector<'a> {
    b: &'a [u8],
    p: usize,
}

impl Lector<'_> {
    fn byte(&mut self) -> Result<u8, ErrorCodec> {
        let v = *self
            .b
            .get(self.p)
            .ok_or(ErrorCodec::Corrupta("bloque truncado"))?;
        self.p += 1;
        Ok(v)
    }
    fn varint(&mut self) -> Result<u64, ErrorCodec> {
        let mut v: u64 = 0;
        for desplaz in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << desplaz;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(ErrorCodec::Corrupta("varint demasiado largo"))
    }
    fn bytes(&mut self, n: usize) -> Result<&[u8], ErrorCodec> {
        let fin = self
            .p
            .checked_add(n)
            .ok_or(ErrorCodec::Corrupta("longitud"))?;
        let r = self
            .b
            .get(self.p..fin)
            .ok_or(ErrorCodec::Corrupta("bloque truncado"))?;
        self.p = fin;
        Ok(r)
    }
}

/// Una columna codificada y comprimida, con su mapa de zona.
#[derive(Debug, Clone, PartialEq)]
pub struct Bloque {
    /// Los bytes comprimidos.
    pub datos: Vec<u8>,
    /// Minimo de la columna (solo enteros; `None` si no hay presentes).
    pub minimo: Option<i64>,
    /// Maximo de la columna.
    pub maximo: Option<i64>,
    /// Bytes sin comprimir, para declarar el coste.
    pub crudos: usize,
}

/// Codifica y comprime una columna de un tipo.
///
/// `nivel` es el de deflate (0-10): la retencion caliente usa uno rapido y la
/// tibia recomprime con uno alto.
#[must_use]
pub fn codificar(tipo: Tipo, valores: &[Valor], nivel: u8) -> Bloque {
    let n = valores.len();
    let mut out = Vec::with_capacity(n * 2 + 16);
    varint(&mut out, n as u64);
    // Mapa de presencia, solo si falta algo.
    let ausentes = valores.iter().any(Valor::es_ausente);
    out.push(u8::from(ausentes));
    if ausentes {
        let mut bits = vec![0u8; n.div_ceil(8)];
        for (i, v) in valores.iter().enumerate() {
            if !v.es_ausente() {
                bits[i / 8] |= 1 << (i % 8);
            }
        }
        out.extend_from_slice(&bits);
    }
    let presentes = valores.iter().filter(|v| !v.es_ausente());
    let (mut minimo, mut maximo) = (None::<i64>, None::<i64>);
    match tipo {
        Tipo::Entero => {
            out.push(PLANO_ENTERO);
            let mut previo = 0i64;
            for v in presentes {
                let x = match v {
                    Valor::Entero(x) => *x,
                    Valor::Real(r) => *r as i64,
                    Valor::Booleano(b) => i64::from(*b),
                    _ => 0,
                };
                minimo = Some(minimo.map_or(x, |m| m.min(x)));
                maximo = Some(maximo.map_or(x, |m| m.max(x)));
                varint(&mut out, zigzag(x.wrapping_sub(previo)));
                previo = x;
            }
        }
        Tipo::Real => {
            out.push(XOR_REAL);
            let mut previo = 0u64;
            for v in presentes {
                let x = match v {
                    Valor::Real(r) => *r,
                    Valor::Entero(e) => *e as f64,
                    _ => 0.0,
                };
                let bits = x.to_bits();
                varint(&mut out, bits ^ previo);
                previo = bits;
            }
        }
        Tipo::Booleano => {
            out.push(BITS_BOOLEANO);
            let vals: Vec<bool> = presentes
                .map(|v| matches!(v, Valor::Booleano(true)))
                .collect();
            let mut bits = vec![0u8; vals.len().div_ceil(8)];
            for (i, b) in vals.iter().enumerate() {
                if *b {
                    bits[i / 8] |= 1 << (i % 8);
                }
            }
            out.extend_from_slice(&bits);
        }
        Tipo::Texto => {
            let textos: Vec<&str> = presentes
                .map(|v| match v {
                    Valor::Texto(s) => s.as_str(),
                    _ => "",
                })
                .collect();
            let mut indice: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
            let mut orden: Vec<&str> = Vec::new();
            for t in &textos {
                if !indice.contains_key(t) {
                    indice.insert(t, orden.len() as u64);
                    orden.push(t);
                }
            }
            // Diccionario si se repite lo bastante para compensar la tabla.
            if orden.len() * 2 <= textos.len() {
                out.push(TEXTO_DICCIONARIO);
                varint(&mut out, orden.len() as u64);
                for t in &orden {
                    varint(&mut out, t.len() as u64);
                    out.extend_from_slice(t.as_bytes());
                }
                for t in &textos {
                    varint(&mut out, indice[t]);
                }
            } else {
                out.push(TEXTO_PLANO);
                for t in &textos {
                    varint(&mut out, t.len() as u64);
                    out.extend_from_slice(t.as_bytes());
                }
            }
        }
    }
    let crudos = out.len();
    Bloque {
        datos: miniz_oxide::deflate::compress_to_vec(&out, nivel.min(10)),
        minimo,
        maximo,
        crudos,
    }
}

/// Descomprime y decodifica una columna.
///
/// # Errors
///
/// [`ErrorCodec`] si el bloque esta corrupto o se pasa de un tope.
pub fn decodificar(datos: &[u8]) -> Result<Vec<Valor>, ErrorCodec> {
    let crudo = miniz_oxide::inflate::decompress_to_vec_with_limit(datos, MAX_DESCOMPRIMIDO)
        .map_err(|_| ErrorCodec::Corrupta("deflate"))?;
    let mut l = Lector { b: &crudo, p: 0 };
    let n = usize::try_from(l.varint()?).map_err(|_| ErrorCodec::Corrupta("longitud"))?;
    if n > MAX_FILAS {
        return Err(ErrorCodec::DemasiadasFilas(n));
    }
    let presencia: Option<Vec<u8>> = match l.byte()? {
        0 => None,
        1 => Some(l.bytes(n.div_ceil(8))?.to_vec()),
        _ => return Err(ErrorCodec::Corrupta("marca de presencia")),
    };
    let presente = |i: usize| {
        presencia
            .as_ref()
            .is_none_or(|b| b[i / 8] & (1 << (i % 8)) != 0)
    };
    let cuantos = (0..n).filter(|i| presente(*i)).count();
    let codec = l.byte()?;
    let mut vals: Vec<Valor> = Vec::with_capacity(cuantos);
    match codec {
        PLANO_ENTERO => {
            let mut previo = 0i64;
            for _ in 0..cuantos {
                previo = previo.wrapping_add(dezigzag(l.varint()?));
                vals.push(Valor::Entero(previo));
            }
        }
        XOR_REAL => {
            let mut previo = 0u64;
            for _ in 0..cuantos {
                previo ^= l.varint()?;
                vals.push(Valor::Real(f64::from_bits(previo)));
            }
        }
        BITS_BOOLEANO => {
            let bits = l.bytes(cuantos.div_ceil(8))?;
            for i in 0..cuantos {
                vals.push(Valor::Booleano(bits[i / 8] & (1 << (i % 8)) != 0));
            }
        }
        TEXTO_PLANO => {
            for _ in 0..cuantos {
                let largo =
                    usize::try_from(l.varint()?).map_err(|_| ErrorCodec::Corrupta("longitud"))?;
                let t = l.bytes(largo)?;
                vals.push(Valor::Texto(String::from_utf8_lossy(t).into_owned()));
            }
        }
        TEXTO_DICCIONARIO => {
            let d = usize::try_from(l.varint()?).map_err(|_| ErrorCodec::Corrupta("longitud"))?;
            if d > cuantos.max(1) {
                return Err(ErrorCodec::Corrupta("diccionario mayor que la columna"));
            }
            let mut dic = Vec::with_capacity(d);
            for _ in 0..d {
                let largo =
                    usize::try_from(l.varint()?).map_err(|_| ErrorCodec::Corrupta("longitud"))?;
                dic.push(String::from_utf8_lossy(l.bytes(largo)?).into_owned());
            }
            for _ in 0..cuantos {
                let i = usize::try_from(l.varint()?).map_err(|_| ErrorCodec::Corrupta("indice"))?;
                vals.push(Valor::Texto(
                    dic.get(i)
                        .cloned()
                        .ok_or(ErrorCodec::Corrupta("indice fuera del diccionario"))?,
                ));
            }
        }
        _ => return Err(ErrorCodec::Corrupta("codificacion desconocida")),
    }
    if l.p != crudo.len() {
        return Err(ErrorCodec::Corrupta("sobran bytes"));
    }
    // Se reintercalan los ausentes.
    let mut it = vals.into_iter();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if presente(i) {
            out.push(it.next().ok_or(ErrorCodec::Corrupta("faltan valores"))?);
        } else {
            out.push(Valor::Ausente);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ida_y_vuelta(tipo: Tipo, v: Vec<Valor>) -> Bloque {
        let b = codificar(tipo, &v, 6);
        assert_eq!(decodificar(&b.datos).unwrap(), v);
        b
    }

    #[test]
    fn enteros_crecientes_con_ausentes_y_extremos() {
        let mut v: Vec<Valor> = (0..5000)
            .map(|i| Valor::Entero(1_788_220_800_000_000_000 + i * 1_000_137))
            .collect();
        v[7] = Valor::Ausente;
        v.push(Valor::Entero(i64::MIN));
        v.push(Valor::Entero(i64::MAX));
        let b = ida_y_vuelta(Tipo::Entero, v);
        assert_eq!(b.minimo, Some(i64::MIN));
        assert_eq!(b.maximo, Some(i64::MAX));
        // 5002 instantes de 8 bytes son 40 KB; en delta+varint+deflate, mucho menos.
        assert!(b.datos.len() < 6_000, "{} bytes", b.datos.len());
    }

    #[test]
    fn reales_texto_y_booleanos() {
        ida_y_vuelta(
            Tipo::Real,
            vec![
                Valor::Real(7.25),
                Valor::Real(-0.0),
                Valor::Ausente,
                Valor::Real(f64::MAX),
            ],
        );
        let rep: Vec<Valor> = (0..1000)
            .map(|i| {
                Valor::Texto(["/usr/bin/bash", "/usr/sbin/sshd", "/usr/bin/python3"][i % 3].into())
            })
            .collect();
        let b = ida_y_vuelta(Tipo::Texto, rep);
        assert!(b.datos.len() < 200, "diccionario: {} bytes", b.datos.len());
        ida_y_vuelta(
            Tipo::Texto,
            vec![
                Valor::Texto("ñandú".into()),
                Valor::Texto(String::new()),
                Valor::Ausente,
            ],
        );
        ida_y_vuelta(
            Tipo::Booleano,
            (0..77)
                .map(|i| {
                    if i % 5 == 0 {
                        Valor::Ausente
                    } else {
                        Valor::Booleano(i % 3 == 0)
                    }
                })
                .collect(),
        );
        ida_y_vuelta(Tipo::Entero, vec![]);
    }

    #[test]
    fn un_bloque_corrupto_es_un_error_y_nunca_un_panico() {
        let b = codificar(
            Tipo::Texto,
            &[Valor::Texto("hola".into()), Valor::Texto("hola".into())],
            6,
        );
        assert!(decodificar(&b.datos[..b.datos.len() / 2]).is_err());
        assert!(decodificar(b"basura").is_err());
        // Un bloque bien comprimido cuyo contenido miente sobre su longitud.
        let mentira = miniz_oxide::deflate::compress_to_vec(&[0xff, 0xff, 0xff, 0x7f], 6);
        assert!(matches!(
            decodificar(&mentira),
            Err(ErrorCodec::DemasiadasFilas(_))
        ));
        for corte in 0..b.datos.len() {
            let _ = decodificar(&b.datos[..corte]);
        }
    }
}
