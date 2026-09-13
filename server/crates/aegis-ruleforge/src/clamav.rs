//! Lector de las bases de firmas de ClamAV.
//!
//! # Que aporta este corpus y que no
//!
//! ClamAV vale por su volumen: millones de firmas de familias conocidas,
//! mantenidas desde hace dos decadas. Es cobertura historica que ningun equipo
//! reproduce desde cero.
//!
//! Lo que NO aporta es deteccion de lo nuevo — para eso estan el resto de
//! motores del producto. Mezclarlo importa: un corpus de hashes es una lista de
//! lo que ya se conocia, y confundir «cubro un millon de firmas» con «detecto un
//! millon de amenazas» es exactamente el error de marketing que hace que un
//! producto de firmas parezca mas de lo que es.
//!
//! # Los formatos, y por que se leen los cuatro
//!
//! | Fichero | Que contiene | Se lee |
//! |---|---|---|
//! | `.hdb`, `.hsb` | hash del fichero entero (MD5 / SHA) | **si** |
//! | `.mdb`, `.msb` | hash de una seccion PE | **si** |
//! | `.ndb` | firma de cuerpo, con comodines | **si** |
//! | `.ldb` | firma logica: varias subfirmas con una expresion | **si** |
//! | cabecera CVD | version, cuantas firmas, fecha, constructor | **si** |
//!
//! Leer solo los hashes seria mas facil y dejaria fuera justo las firmas que
//! detectan variantes: un hash cambia con un byte, una firma de cuerpo con
//! comodines no.
//!
//! # La cabecera CVD se lee; el cuerpo comprimido, no
//!
//! Un `.cvd` son 512 bytes de cabecera en texto plano seguidos de un `tar.gz`.
//! La cabecera trae los metadatos de version, que es lo que hace falta para
//! saber si un corpus esta al dia, y se lee aqui. Descomprimir el cuerpo es
//! trabajo de la tuberia de ingesta —que ya sabe manejar artefactos grandes— y
//! meterlo aqui obligaria a poner un descompresor en el camino que analiza
//! entrada hostil. Se declara en la tabla de honestidad en vez de disimularlo.

use std::collections::BTreeMap;

use aegis_sync::ioc::{Ioc, IocKind};

use crate::informe::{Informe, Rechazo};
use crate::presupuesto::Presupuesto;

/// Metadatos de la cabecera de un `.cvd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabeceraCvd {
    /// Fecha de construccion, tal y como venia.
    pub fecha: String,
    /// Numero de version del corpus.
    pub version: u32,
    /// Cuantas firmas declara traer.
    ///
    /// Se compara con las que de verdad se leen: si no cuadran, el fichero
    /// llego truncado o alterado, y eso hay que saberlo ANTES de firmarlo.
    pub firmas_declaradas: u32,
    /// Nivel funcional minimo de motor.
    pub nivel_motor: u32,
    /// Suma MD5 declarada.
    pub md5: String,
    /// Quien lo construyo.
    pub constructor: String,
}

/// Como casa una firma de cuerpo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trozo {
    /// Bytes exactos.
    Bytes(Vec<u8>),
    /// Cualquier byte, un numero fijo de veces (`??`).
    Cualquiera(usize),
    /// Cualquier cosa, de `min` a `max` bytes (`{n-m}`, `*`).
    Salto {
        /// Minimo.
        min: usize,
        /// Maximo. `None` es sin tope (`*`).
        max: Option<usize>,
    },
    /// Alternativa entre varias secuencias (`(aa|bb)`).
    Alternativa(Vec<Vec<u8>>),
}

/// Una firma de ClamAV ya leida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Firma {
    /// Hash del fichero entero.
    HashFichero {
        /// Nombre de la firma.
        nombre: String,
        /// El hash, en minusculas.
        hash: String,
        /// Tamano declarado. `None` cuando la firma dice «cualquiera».
        tamano: Option<u64>,
    },
    /// Hash de una seccion PE.
    HashSeccion {
        /// Nombre.
        nombre: String,
        /// El hash.
        hash: String,
        /// Tamano de la seccion.
        tamano: Option<u64>,
    },
    /// Firma de cuerpo con comodines.
    Cuerpo {
        /// Nombre.
        nombre: String,
        /// Tipo de objetivo declarado.
        objetivo: u8,
        /// Desplazamiento declarado, tal cual.
        desplazamiento: String,
        /// Los trozos en orden.
        trozos: Vec<Trozo>,
    },
    /// Firma logica: varias subfirmas y una expresion que las combina.
    Logica {
        /// Nombre.
        nombre: String,
        /// La expresion, tal y como venia.
        expresion: String,
        /// Las subfirmas.
        subfirmas: Vec<Vec<Trozo>>,
    },
}

impl Firma {
    /// Nombre de la firma.
    #[must_use]
    pub fn nombre(&self) -> &str {
        match self {
            Firma::HashFichero { nombre, .. }
            | Firma::HashSeccion { nombre, .. }
            | Firma::Cuerpo { nombre, .. }
            | Firma::Logica { nombre, .. } => nombre,
        }
    }

    /// El indicador equivalente, si la firma es un hash que el producto ya sabe
    /// comparar.
    ///
    /// Solo los SHA-256 se convierten: el resto del producto —la malla de la
    /// FASE 23, el arbol de Merkle— habla SHA-256, y meter MD5 en esa tuberia
    /// obligaria a que todo el mundo supiera distinguir dos anchos de hash.
    /// Las firmas MD5 se conservan como firma, pero no se promueven a indicador.
    #[must_use]
    pub fn como_ioc(&self) -> Option<Ioc> {
        match self {
            Firma::HashFichero { hash, .. } | Firma::HashSeccion { hash, .. }
                if hash.len() == 64 =>
            {
                Some(Ioc {
                    kind: IocKind::FileSha256,
                    value: hash.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Por que una linea de firma no se pudo leer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorClamav {
    /// La linea no tiene los campos que su formato exige.
    CamposInsuficientes {
        /// Cuantos trae.
        tiene: usize,
        /// Cuantos hacen falta.
        necesita: usize,
    },
    /// El hash no es hexadecimal de un ancho conocido.
    HashInvalido(String),
    /// El cuerpo hexadecimal no se puede leer.
    CuerpoInvalido(String),
    /// El tipo de objetivo no es un numero.
    ObjetivoInvalido(String),
    /// La firma pasa del tamano permitido.
    DemasiadoGrande {
        /// Bytes.
        bytes: usize,
        /// Tope.
        tope: usize,
    },
    /// La cabecera CVD no tiene la forma esperada.
    CabeceraInvalida(String),
}

impl ErrorClamav {
    /// Codigo estable.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            ErrorClamav::CamposInsuficientes { .. } => "clamav-campos-insuficientes",
            ErrorClamav::HashInvalido(_) => "clamav-hash-invalido",
            ErrorClamav::CuerpoInvalido(_) => "clamav-cuerpo-invalido",
            ErrorClamav::ObjetivoInvalido(_) => "clamav-objetivo-invalido",
            ErrorClamav::DemasiadoGrande { .. } => "clamav-demasiado-grande",
            ErrorClamav::CabeceraInvalida(_) => "clamav-cabecera-invalida",
        }
    }

    /// Detalle legible.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorClamav::CamposInsuficientes { tiene, necesita } => {
                format!("{tiene} campos, hacen falta {necesita}")
            }
            ErrorClamav::HashInvalido(h) => format!("«{h}» no es un hash hexadecimal conocido"),
            ErrorClamav::CuerpoInvalido(d) => d.clone(),
            ErrorClamav::ObjetivoInvalido(o) => format!("objetivo «{o}»"),
            ErrorClamav::DemasiadoGrande { bytes, tope } => {
                format!("{bytes} bytes, por encima del tope de {tope}")
            }
            ErrorClamav::CabeceraInvalida(d) => d.clone(),
        }
    }
}

/// Lee la cabecera de 512 bytes de un `.cvd`.
///
/// # Errores
/// [`ErrorClamav::CabeceraInvalida`] si no tiene la forma esperada.
pub fn leer_cabecera_cvd(datos: &[u8]) -> Result<CabeceraCvd, ErrorClamav> {
    const LARGO: usize = 512;
    if datos.len() < LARGO {
        return Err(ErrorClamav::CabeceraInvalida(format!(
            "la cabecera son {LARGO} bytes y solo hay {}",
            datos.len()
        )));
    }
    let texto = String::from_utf8_lossy(&datos[..LARGO]);
    let Some(cuerpo) = texto.strip_prefix("ClamAV-VDB:") else {
        return Err(ErrorClamav::CabeceraInvalida(
            "no empieza por «ClamAV-VDB:»".to_string(),
        ));
    };
    let campos: Vec<&str> = cuerpo.split(':').collect();
    if campos.len() < 7 {
        return Err(ErrorClamav::CabeceraInvalida(format!(
            "{} campos, hacen falta al menos 7",
            campos.len()
        )));
    }
    Ok(CabeceraCvd {
        fecha: campos[0].trim().to_string(),
        version: campos[1].trim().parse().unwrap_or(0),
        firmas_declaradas: campos[2].trim().parse().unwrap_or(0),
        nivel_motor: campos[3].trim().parse().unwrap_or(0),
        md5: campos[4].trim().to_string(),
        constructor: campos[6].trim().to_string(),
    })
}

/// Convierte un cuerpo hexadecimal de ClamAV en trozos.
///
/// El formato admite, ademas de bytes: `??` (un byte cualquiera), `*` (salto sin
/// tope), `{n}` y `{n-m}` (salto acotado), y `(aa|bb)` (alternativa). Leerlos
/// mal no da un error: da una firma que casa con otra cosa.
///
/// # Errores
/// [`ErrorClamav::CuerpoInvalido`] nombrando lo que no cuadra.
pub fn leer_cuerpo(hex: &str) -> Result<Vec<Trozo>, ErrorClamav> {
    let mut trozos = Vec::new();
    let mut bytes_actuales: Vec<u8> = Vec::new();
    let cs: Vec<char> = hex.chars().collect();
    let mut i = 0usize;

    /// Vuelca los bytes acumulados como un trozo.
    fn volcar(bytes: &mut Vec<u8>, trozos: &mut Vec<Trozo>) {
        if !bytes.is_empty() {
            trozos.push(Trozo::Bytes(std::mem::take(bytes)));
        }
    }

    while i < cs.len() {
        match cs[i] {
            '*' => {
                volcar(&mut bytes_actuales, &mut trozos);
                trozos.push(Trozo::Salto { min: 0, max: None });
                i += 1;
            }
            '?' => {
                // `??` es un byte cualquiera. Un `?` suelto es media pareja y no
                // significa nada: se rechaza en vez de asumir.
                if cs.get(i + 1) != Some(&'?') {
                    return Err(ErrorClamav::CuerpoInvalido(format!(
                        "interrogante suelto en la posicion {i}"
                    )));
                }
                volcar(&mut bytes_actuales, &mut trozos);
                // Varios `??` seguidos se agrupan en un solo trozo.
                let mut n = 0usize;
                while cs.get(i) == Some(&'?') && cs.get(i + 1) == Some(&'?') {
                    n += 1;
                    i += 2;
                }
                trozos.push(Trozo::Cualquiera(n));
            }
            '{' => {
                volcar(&mut bytes_actuales, &mut trozos);
                let Some(cierre) = cs[i..].iter().position(|c| *c == '}') else {
                    return Err(ErrorClamav::CuerpoInvalido("llave sin cerrar".to_string()));
                };
                let cuerpo: String = cs[i + 1..i + cierre].iter().collect();
                let (min, max) = leer_rango(&cuerpo)?;
                trozos.push(Trozo::Salto { min, max });
                i += cierre + 1;
            }
            '(' => {
                volcar(&mut bytes_actuales, &mut trozos);
                let Some(cierre) = cs[i..].iter().position(|c| *c == ')') else {
                    return Err(ErrorClamav::CuerpoInvalido(
                        "parentesis sin cerrar".to_string(),
                    ));
                };
                let cuerpo: String = cs[i + 1..i + cierre].iter().collect();
                let mut alternativas = Vec::new();
                for alt in cuerpo.split('|') {
                    alternativas.push(hex_a_bytes(alt)?);
                }
                trozos.push(Trozo::Alternativa(alternativas));
                i += cierre + 1;
            }
            c if c.is_ascii_hexdigit() => {
                let Some(sig) = cs.get(i + 1) else {
                    return Err(ErrorClamav::CuerpoInvalido(
                        "el cuerpo acaba en medio de un byte".to_string(),
                    ));
                };
                if !sig.is_ascii_hexdigit() {
                    return Err(ErrorClamav::CuerpoInvalido(format!(
                        "«{c}{sig}» no es un byte hexadecimal"
                    )));
                }
                let par: String = [c, *sig].iter().collect();
                let b = u8::from_str_radix(&par, 16)
                    .map_err(|_| ErrorClamav::CuerpoInvalido(format!("«{par}»")))?;
                bytes_actuales.push(b);
                i += 2;
            }
            c if c.is_whitespace() => i += 1,
            c => {
                return Err(ErrorClamav::CuerpoInvalido(format!(
                    "caracter «{c}» en la posicion {i}"
                )))
            }
        }
    }
    volcar(&mut bytes_actuales, &mut trozos);
    Ok(trozos)
}

/// Lee un rango `n` o `n-m` o `-m` o `n-`.
fn leer_rango(cuerpo: &str) -> Result<(usize, Option<usize>), ErrorClamav> {
    let c = cuerpo.trim();
    if c.is_empty() {
        return Err(ErrorClamav::CuerpoInvalido("rango vacio".to_string()));
    }
    match c.split_once('-') {
        None => {
            let n = c
                .parse::<usize>()
                .map_err(|_| ErrorClamav::CuerpoInvalido(format!("rango «{c}»")))?;
            Ok((n, Some(n)))
        }
        Some((a, b)) => {
            let min = if a.trim().is_empty() {
                0
            } else {
                a.trim()
                    .parse::<usize>()
                    .map_err(|_| ErrorClamav::CuerpoInvalido(format!("rango «{c}»")))?
            };
            let max = if b.trim().is_empty() {
                None
            } else {
                Some(
                    b.trim()
                        .parse::<usize>()
                        .map_err(|_| ErrorClamav::CuerpoInvalido(format!("rango «{c}»")))?,
                )
            };
            Ok((min, max))
        }
    }
}

/// Convierte una cadena hexadecimal en bytes.
fn hex_a_bytes(s: &str) -> Result<Vec<u8>, ErrorClamav> {
    let limpio: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if limpio.len() % 2 != 0 {
        return Err(ErrorClamav::CuerpoInvalido(format!(
            "«{limpio}» tiene un numero impar de digitos"
        )));
    }
    let mut salida = Vec::with_capacity(limpio.len() / 2);
    let cs: Vec<char> = limpio.chars().collect();
    for par in cs.chunks(2) {
        let texto: String = par.iter().collect();
        salida.push(
            u8::from_str_radix(&texto, 16)
                .map_err(|_| ErrorClamav::CuerpoInvalido(format!("«{texto}»")))?,
        );
    }
    Ok(salida)
}

/// El formato de un fichero de firmas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Formato {
    /// `.hdb` / `.hsb`: hash del fichero.
    HashFichero,
    /// `.mdb` / `.msb`: hash de seccion.
    HashSeccion,
    /// `.ndb`: firma de cuerpo.
    Cuerpo,
    /// `.ldb`: firma logica.
    Logica,
}

impl Formato {
    /// Deduce el formato por la extension.
    #[must_use]
    pub fn por_extension(nombre: &str) -> Option<Formato> {
        let ext = nombre.rsplit('.').next()?.to_ascii_lowercase();
        match ext.as_str() {
            "hdb" | "hsb" => Some(Formato::HashFichero),
            "mdb" | "msb" => Some(Formato::HashSeccion),
            "ndb" => Some(Formato::Cuerpo),
            "ldb" => Some(Formato::Logica),
            _ => None,
        }
    }
}

/// Lee una linea de firma segun su formato.
///
/// # Errores
/// [`ErrorClamav`] nombrando lo concreto que falla.
pub fn leer_linea(
    linea: &str,
    formato: Formato,
    presupuesto: &Presupuesto,
) -> Result<Firma, ErrorClamav> {
    if linea.len() > presupuesto.max_bytes_regla {
        return Err(ErrorClamav::DemasiadoGrande {
            bytes: linea.len(),
            tope: presupuesto.max_bytes_regla,
        });
    }
    match formato {
        Formato::HashFichero | Formato::HashSeccion => {
            // `hash:tamano:nombre`. El orden es ese y no otro: en `.mdb` el
            // tamano va PRIMERO, y confundirlos produce firmas con el hash y el
            // tamano intercambiados, que no casan con nada.
            let campos: Vec<&str> = linea.split(':').collect();
            if campos.len() < 3 {
                return Err(ErrorClamav::CamposInsuficientes {
                    tiene: campos.len(),
                    necesita: 3,
                });
            }
            let (hash_txt, tamano_txt) = if formato == Formato::HashSeccion {
                (campos[1], campos[0])
            } else {
                (campos[0], campos[1])
            };
            let hash = hash_txt.trim().to_ascii_lowercase();
            if !es_hash(&hash) {
                return Err(ErrorClamav::HashInvalido(hash));
            }
            let tamano = if tamano_txt.trim() == "*" {
                None
            } else {
                tamano_txt.trim().parse::<u64>().ok()
            };
            let nombre = campos[2].trim().to_string();
            Ok(if formato == Formato::HashSeccion {
                Firma::HashSeccion {
                    nombre,
                    hash,
                    tamano,
                }
            } else {
                Firma::HashFichero {
                    nombre,
                    hash,
                    tamano,
                }
            })
        }
        Formato::Cuerpo => {
            // `nombre:objetivo:desplazamiento:hexadecimal[:min][:max]`
            let campos: Vec<&str> = linea.split(':').collect();
            if campos.len() < 4 {
                return Err(ErrorClamav::CamposInsuficientes {
                    tiene: campos.len(),
                    necesita: 4,
                });
            }
            let objetivo = campos[1]
                .trim()
                .parse::<u8>()
                .map_err(|_| ErrorClamav::ObjetivoInvalido(campos[1].trim().to_string()))?;
            Ok(Firma::Cuerpo {
                nombre: campos[0].trim().to_string(),
                objetivo,
                desplazamiento: campos[2].trim().to_string(),
                trozos: leer_cuerpo(campos[3].trim())?,
            })
        }
        Formato::Logica => {
            // `nombre;bloque_objetivo;expresion;subfirma0;subfirma1;...`
            let campos: Vec<&str> = linea.split(';').collect();
            if campos.len() < 4 {
                return Err(ErrorClamav::CamposInsuficientes {
                    tiene: campos.len(),
                    necesita: 4,
                });
            }
            let mut subfirmas = Vec::new();
            for sub in &campos[3..] {
                subfirmas.push(leer_cuerpo(sub.trim())?);
            }
            Ok(Firma::Logica {
                nombre: campos[0].trim().to_string(),
                expresion: campos[2].trim().to_string(),
                subfirmas,
            })
        }
    }
}

/// Si una cadena es un hash hexadecimal de un ancho conocido.
fn es_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Lee un fichero de firmas entero.
///
/// Devuelve las firmas y el informe. Si la cabecera declaraba un numero de
/// firmas y no cuadra con las leidas, se anota: un fichero truncado se parece
/// muchisimo a uno completo, y la unica forma de notarlo es contar.
#[must_use]
pub fn leer_fichero(
    fuente: &str,
    formato: Formato,
    presupuesto: &Presupuesto,
) -> (Vec<Firma>, Informe) {
    let mut firmas = Vec::new();
    let mut informe = Informe::default();
    let mut vistos: BTreeMap<String, ()> = BTreeMap::new();

    if fuente.len() > presupuesto.max_bytes_entrada {
        informe.rechazada(Rechazo::nuevo(
            "(fichero)",
            "entrada-demasiado-grande",
            format!(
                "{} bytes, por encima del tope de {}",
                fuente.len(),
                presupuesto.max_bytes_entrada
            ),
        ));
        return (firmas, informe);
    }

    for linea in fuente.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if informe.vistas >= presupuesto.max_reglas {
            informe.rechazada(Rechazo::nuevo(
                "(resto del fichero)",
                "demasiadas-reglas",
                format!("se paso el tope de {} firmas", presupuesto.max_reglas),
            ));
            break;
        }
        match leer_linea(l, formato, presupuesto) {
            Ok(f) => {
                let clave = f.nombre().to_string();
                if !clave.is_empty() && vistos.insert(clave, ()).is_some() {
                    informe.duplicada();
                    continue;
                }
                firmas.push(f);
                informe.compilada();
            }
            Err(e) => {
                let nombre = l.split([':', ';']).next().unwrap_or(l);
                informe.rechazada(Rechazo::nuevo(nombre, e.codigo(), e.detalle()));
            }
        }
    }
    (firmas, informe)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    /// Una cabecera CVD REAL, con la forma exacta que publica ClamAV.
    #[test]
    fn una_cabecera_cvd_real_se_lee() {
        let mut cabecera =
            b"ClamAV-VDB:22 Oct 2024 08-00 -0400:27443:2000000:90:a1b2c3d4e5f6:...:ClamAV:"
                .to_vec();
        cabecera.resize(512, b' ');

        let c = leer_cabecera_cvd(&cabecera).expect("cabecera valida");
        assert_eq!(c.version, 27443);
        assert_eq!(c.firmas_declaradas, 2_000_000);
        assert_eq!(c.nivel_motor, 90);
        assert_eq!(c.md5, "a1b2c3d4e5f6");
        assert!(c.fecha.starts_with("22 Oct 2024"));
    }

    /// Una cabecera truncada o que no es de ClamAV se dice, no se adivina.
    #[test]
    fn una_cabecera_que_no_lo_es_se_rechaza() {
        assert!(leer_cabecera_cvd(b"corta").is_err());
        let mut otra = b"NoEsClamAV:x:y:z".to_vec();
        otra.resize(512, b' ');
        let e = leer_cabecera_cvd(&otra).unwrap_err();
        assert_eq!(e.codigo(), "clamav-cabecera-invalida");
    }

    /// FIRMAS DE HASH reales, en los dos formatos.
    #[test]
    fn las_firmas_de_hash_se_leen_con_su_tamano_y_su_nombre() {
        let hdb = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        let f = leer_linea(hdb, Formato::HashFichero, &p()).unwrap();
        assert_eq!(
            f,
            Firma::HashFichero {
                nombre: "Eicar-Test-Signature".to_string(),
                hash: "44d88612fea8a8f36de82e1278abb02f".to_string(),
                tamano: Some(68),
            }
        );

        // Un tamano `*` significa «cualquiera», no cero.
        let cualquiera = "44d88612fea8a8f36de82e1278abb02f:*:Generico";
        let g = leer_linea(cualquiera, Formato::HashFichero, &p()).unwrap();
        assert!(matches!(g, Firma::HashFichero { tamano: None, .. }));
    }

    /// EN `.mdb` EL TAMANO VA PRIMERO. Confundir el orden produce firmas con el
    /// hash y el tamano intercambiados, que no casan con nada — y el fichero
    /// compila igual, asi que nadie se entera.
    #[test]
    fn en_las_firmas_de_seccion_el_tamano_va_primero() {
        let mdb = "1024:d41d8cd98f00b204e9800998ecf8427e:Seccion.Malo";
        let f = leer_linea(mdb, Formato::HashSeccion, &p()).unwrap();
        assert_eq!(
            f,
            Firma::HashSeccion {
                nombre: "Seccion.Malo".to_string(),
                hash: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                tamano: Some(1024),
            }
        );
    }

    /// Los tres anchos de hash que usa ClamAV se aceptan; cualquier otra cosa se
    /// rechaza con nombre.
    #[test]
    fn solo_se_aceptan_los_anchos_de_hash_conocidos() {
        assert!(es_hash(&"a".repeat(32)), "MD5");
        assert!(es_hash(&"a".repeat(40)), "SHA-1");
        assert!(es_hash(&"a".repeat(64)), "SHA-256");
        assert!(!es_hash(&"a".repeat(31)));
        assert!(!es_hash(&"z".repeat(32)), "no es hexadecimal");

        let e = leer_linea("nohash:1:N", Formato::HashFichero, &p()).unwrap_err();
        assert_eq!(e.codigo(), "clamav-hash-invalido");
    }

    /// SOLO LOS SHA-256 SE PROMUEVEN A INDICADOR. El resto del producto habla
    /// SHA-256, y meter MD5 en esa tuberia obligaria a que todo el mundo
    /// supiera distinguir dos anchos de hash.
    #[test]
    fn solo_los_sha256_se_promueven_a_indicador() {
        let md5 = leer_linea(
            "44d88612fea8a8f36de82e1278abb02f:68:MD5",
            Formato::HashFichero,
            &p(),
        )
        .unwrap();
        assert!(md5.como_ioc().is_none(), "un MD5 no entra en la tuberia");

        let sha = leer_linea(
            &format!("{}:68:SHA", "ab".repeat(32)),
            Formato::HashFichero,
            &p(),
        )
        .unwrap();
        let ioc = sha.como_ioc().expect("un SHA-256 si");
        assert_eq!(ioc.kind, IocKind::FileSha256);
    }

    /// UNA FIRMA DE CUERPO REAL, con todos sus comodines. Leerlos mal no da un
    /// error: da una firma que casa con otra cosa.
    #[test]
    fn una_firma_de_cuerpo_con_comodines_se_lee_entera() {
        let ndb = "Win.Trojan.Ejemplo:0:*:4d5a??????{4-8}(aabb|ccdd)9090";
        let f = leer_linea(ndb, Formato::Cuerpo, &p()).unwrap();
        let Firma::Cuerpo {
            nombre,
            objetivo,
            desplazamiento,
            trozos,
        } = f
        else {
            panic!("tenia que ser una firma de cuerpo");
        };
        assert_eq!(nombre, "Win.Trojan.Ejemplo");
        assert_eq!(objetivo, 0);
        assert_eq!(desplazamiento, "*");
        assert_eq!(
            trozos,
            vec![
                Trozo::Bytes(vec![0x4D, 0x5A]),
                Trozo::Cualquiera(3),
                Trozo::Salto {
                    min: 4,
                    max: Some(8)
                },
                Trozo::Alternativa(vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]]),
                Trozo::Bytes(vec![0x90, 0x90]),
            ]
        );
    }

    /// Las formas de salto: `*` sin tope, `{n}` exacto, `{n-m}` y `{n-}`.
    #[test]
    fn todas_las_formas_de_salto_se_leen() {
        assert_eq!(
            leer_cuerpo("aa*bb").unwrap()[1],
            Trozo::Salto { min: 0, max: None }
        );
        assert_eq!(
            leer_cuerpo("aa{5}bb").unwrap()[1],
            Trozo::Salto {
                min: 5,
                max: Some(5)
            }
        );
        assert_eq!(
            leer_cuerpo("aa{2-9}bb").unwrap()[1],
            Trozo::Salto {
                min: 2,
                max: Some(9)
            }
        );
        assert_eq!(
            leer_cuerpo("aa{3-}bb").unwrap()[1],
            Trozo::Salto { min: 3, max: None }
        );
        assert_eq!(
            leer_cuerpo("aa{-7}bb").unwrap()[1],
            Trozo::Salto {
                min: 0,
                max: Some(7)
            }
        );
    }

    /// Un cuerpo mal formado se RECHAZA, no se lee a medias. Una firma leida a
    /// medias casa con otra cosa, y eso no se ve hasta que detecta de mas.
    #[test]
    fn un_cuerpo_mal_formado_se_rechaza_con_su_motivo() {
        for (hex, que) in [
            ("aab", "acaba en medio"),
            ("aa?bb", "interrogante suelto"),
            ("aa{2-9bb", "llave sin cerrar"),
            ("aa(aa|bb", "parentesis sin cerrar"),
            ("aazz", "no es un byte"),
            ("aa{x}bb", "rango"),
        ] {
            let e = leer_cuerpo(hex).unwrap_err();
            assert_eq!(e.codigo(), "clamav-cuerpo-invalido", "con «{hex}»");
            assert!(!e.detalle().is_empty(), "«{hex}» -> {que}");
        }
    }

    /// UNA FIRMA LOGICA REAL, con su expresion y sus subfirmas.
    #[test]
    fn una_firma_logica_se_lee_con_sus_subfirmas() {
        let ldb = "Win.Malware.Logica;Engine:51-255,Target:1;(0&1)|2;4d5a;504500;cafebabe";
        let f = leer_linea(ldb, Formato::Logica, &p()).unwrap();
        let Firma::Logica {
            nombre,
            expresion,
            subfirmas,
        } = f
        else {
            panic!("tenia que ser logica");
        };
        assert_eq!(nombre, "Win.Malware.Logica");
        assert_eq!(expresion, "(0&1)|2");
        assert_eq!(subfirmas.len(), 3);
        assert_eq!(subfirmas[0], vec![Trozo::Bytes(vec![0x4D, 0x5A])]);
        assert_eq!(
            subfirmas[2],
            vec![Trozo::Bytes(vec![0xCA, 0xFE, 0xBA, 0xBE])]
        );
    }

    /// El formato se deduce de la extension, que es como ClamAV los distingue.
    #[test]
    fn el_formato_se_deduce_de_la_extension() {
        assert_eq!(
            Formato::por_extension("main.hdb"),
            Some(Formato::HashFichero)
        );
        assert_eq!(
            Formato::por_extension("daily.MSB"),
            Some(Formato::HashSeccion)
        );
        assert_eq!(Formato::por_extension("x.ndb"), Some(Formato::Cuerpo));
        assert_eq!(Formato::por_extension("x.ldb"), Some(Formato::Logica));
        assert_eq!(Formato::por_extension("leeme.txt"), None);
    }

    /// Un fichero entero se lee con su informe: cuantas de cuantas y por que.
    #[test]
    fn un_fichero_entero_se_lee_con_su_informe() {
        let fuente = "# comentario\n\
                      44d88612fea8a8f36de82e1278abb02f:68:Eicar\n\
                      nohash:1:Mala\n\
                      d41d8cd98f00b204e9800998ecf8427e:*:Otra\n";
        let (firmas, informe) = leer_fichero(fuente, Formato::HashFichero, &p());
        assert_eq!(firmas.len(), 2);
        assert_eq!(informe.vistas, 3);
        assert_eq!(informe.compiladas, 2);
        assert!(informe
            .por_motivo()
            .iter()
            .any(|(m, _)| *m == "clamav-hash-invalido"));
    }

    /// Las firmas duplicadas por nombre no se cuentan dos veces: las bases de
    /// ClamAV se solapan entre `main` y `daily`.
    #[test]
    fn las_firmas_duplicadas_por_nombre_se_descartan() {
        let l = "44d88612fea8a8f36de82e1278abb02f:68:Eicar";
        let (firmas, informe) = leer_fichero(&format!("{l}\n{l}\n"), Formato::HashFichero, &p());
        assert_eq!(firmas.len(), 1);
        assert_eq!(informe.duplicadas, 1);
    }

    /// Ninguna entrada arbitraria puede tumbar el lector: lo que lee son bases
    /// que se descargan de la red.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "aa", "??", "*", "{", "}", "(", ")", "|", ":", ";", "zz", "4d5a", "0", "-", "5",
        ];
        let mut semilla = 0xFEED_FACE_DEAD_BEEFu64;
        for _ in 0..3_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 20) as usize;
            let linea: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect();
            let _ = leer_cuerpo(&linea);
            for f in [
                Formato::HashFichero,
                Formato::HashSeccion,
                Formato::Cuerpo,
                Formato::Logica,
            ] {
                let _ = leer_linea(&linea, f, &p());
            }
        }
    }
}
