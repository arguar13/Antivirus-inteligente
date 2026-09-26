//! Lo que un binario dice de si mismo: con que se compilo y que lleva dentro.
//!
//! # Tres formas de saber que hay dentro de un ejecutable
//!
//! 1. **Metadatos de compilacion incrustados.** `cargo-auditable` guarda en la
//!    seccion `.dep-v0` la lista exacta de crates con que se compilo un binario
//!    de Rust; el enlazador de Go guarda en `.go.buildinfo` la de modulos. Es un
//!    hecho declarado por la cadena de compilacion, no una inferencia, y es lo
//!    unico que ve dentro de un binario enlazado estaticamente sin adivinar.
//! 2. **Firmas.** Una biblioteca enlazada estaticamente no deja rastro en el
//!    gestor de paquetes, pero algunas escriben su version en el binario —
//!    OpenSSL lo hace, `OpenSSL 3.0.2 15 Mar 2022`—. Es una inferencia, y se
//!    marca como tal ([`crate::componente::Procedencia::Firma`]).
//! 3. **Las bibliotecas que pide.** `DT_NEEDED`: eso lo usa la alcanzabilidad,
//!    no el inventario, porque la biblioteca ya la inventaria su paquete.
//!
//! # Se lee la tabla de secciones, no el fichero
//!
//! Los directorios de ejecutables de una maquina suman cientos de megas. Leer
//! cada fichero entero para mirar si tiene una seccion de cien bytes seria el
//! coste dominante del inventario. Se lee la cabecera, la tabla de secciones y la
//! seccion que interesa, cada una con lectura posicionada y tope.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::componente::{Componente, Ecosistema, Procedencia};

/// Tope de la seccion de metadatos comprimida que se lee.
pub const MAX_SECCION: u64 = 4 * 1024 * 1024;

/// Tope de lo que se descomprime de una seccion de metadatos.
///
/// Sin tope, cuatro megas de zlib bien elegidos se convierten en gigas: una
/// bomba de descompresion dentro de un binario es la forma barata de tumbar el
/// inventario de una maquina.
pub const MAX_DESCOMPRIMIDO: usize = 16 * 1024 * 1024;

/// Tope de componentes que se aceptan de un binario.
pub const MAX_COMPONENTES_POR_BINARIO: usize = 10_000;

/// Tope de bytes de un fichero en el que se buscan firmas.
pub const MAX_FIRMA: u64 = 256 * 1024 * 1024;

/// Una seccion de un ELF: nombre, desplazamiento y tamano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seccion {
    /// Nombre.
    pub nombre: String,
    /// Desplazamiento en el fichero.
    pub desplazamiento: u64,
    /// Tamano en el fichero.
    pub tamano: u64,
}

/// Lee `n` bytes en `pos`, sin pasar del final.
#[cfg(unix)]
fn leer_en(f: &File, pos: u64, n: usize) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut v = vec![0u8; n];
    f.read_exact_at(&mut v, pos).ok()?;
    Some(v)
}

#[cfg(not(unix))]
fn leer_en(f: &File, pos: u64, n: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = f.try_clone().ok()?;
    f.seek(SeekFrom::Start(pos)).ok()?;
    let mut v = vec![0u8; n];
    f.read_exact(&mut v).ok()?;
    Some(v)
}

fn u16_le(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn u32_le(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn u64_le(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

/// La tabla de secciones de un ELF de 64 bits little-endian, sin leer el resto.
///
/// Devuelve `None` si no es un ELF de esa clase o si la tabla es incoherente:
/// un fichero que dice tener cien mil secciones o una tabla fuera del fichero no
/// se sigue.
#[must_use]
pub fn secciones(ruta: &Path) -> Option<Vec<Seccion>> {
    let f = File::open(ruta).ok()?;
    let largo = f.metadata().ok()?.len();
    let cab = leer_en(&f, 0, 64)?;
    // \x7fELF, clase 2 (64 bits), datos 1 (little-endian).
    if cab.get(..4)? != b"\x7fELF" || cab[4] != 2 || cab[5] != 1 {
        return None;
    }
    let shoff = u64_le(&cab, 0x28)?;
    let shentsize = u64::from(u16_le(&cab, 0x3A)?);
    let shnum = u64::from(u16_le(&cab, 0x3C)?);
    let shstrndx = u64::from(u16_le(&cab, 0x3E)?);
    if shentsize < 64 || shnum == 0 || shnum > 4096 || shstrndx >= shnum {
        return None;
    }
    let tabla_len = shentsize.checked_mul(shnum)?;
    if shoff.checked_add(tabla_len)? > largo {
        return None;
    }
    let tabla = leer_en(&f, shoff, usize::try_from(tabla_len).ok()?)?;
    let ent = |i: u64| -> Option<(u32, u64, u64, u32)> {
        let base = usize::try_from(i * shentsize).ok()?;
        Some((
            u32_le(&tabla, base)?,        // sh_name
            u64_le(&tabla, base + 0x18)?, // sh_offset
            u64_le(&tabla, base + 0x20)?, // sh_size
            u32_le(&tabla, base + 4)?,    // sh_type
        ))
    };
    let (_, str_off, str_tam, _) = ent(shstrndx)?;
    if str_tam > 1024 * 1024 || str_off.checked_add(str_tam)? > largo {
        return None;
    }
    let nombres = leer_en(&f, str_off, usize::try_from(str_tam).ok()?)?;
    let mut v = Vec::with_capacity(usize::try_from(shnum).ok()?);
    for i in 0..shnum {
        let (n, off, tam, tipo) = ent(i)?;
        let ini = usize::try_from(n).ok()?;
        let nombre = nombres
            .get(ini..)
            .and_then(|r| r.split(|b| *b == 0).next())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        // SHT_NOBITS (8) no ocupa sitio en el fichero: `.bss`.
        let tam = if tipo == 8 { 0 } else { tam };
        v.push(Seccion {
            nombre,
            desplazamiento: off,
            tamano: tam,
        });
    }
    Some(v)
}

/// El contenido de una seccion, con tope.
fn contenido(ruta: &Path, s: &Seccion) -> Option<Vec<u8>> {
    if s.tamano == 0 || s.tamano > MAX_SECCION {
        return None;
    }
    let f = File::open(ruta).ok()?;
    leer_en(&f, s.desplazamiento, usize::try_from(s.tamano).ok()?)
}

/// Lo que se saco de los metadatos de un binario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadatos {
    /// El binario no trae metadatos de compilacion que se sepan leer.
    Ninguno,
    /// Los trae y se leyeron.
    Leidos(Vec<Componente>),
    /// Los trae y no se pudieron leer: se dice por que, porque «este binario
    /// no tiene dependencias conocidas» y «no se pudieron leer» son dos
    /// respuestas distintas.
    Ilegibles {
        /// Que formato.
        formato: &'static str,
        /// Por que.
        motivo: String,
    },
}

/// Lee los metadatos de compilacion de un ELF, si los tiene.
#[must_use]
pub fn metadatos(ruta: &Path) -> Metadatos {
    let Some(secs) = secciones(ruta) else {
        return Metadatos::Ninguno;
    };
    if let Some(s) = secs.iter().find(|s| s.nombre == ".dep-v0") {
        return match contenido(ruta, s) {
            Some(b) => match auditable(&b, ruta) {
                Ok(v) => Metadatos::Leidos(v),
                Err(motivo) => Metadatos::Ilegibles {
                    formato: FORMATO_AUDITABLE,
                    motivo,
                },
            },
            None => Metadatos::Ilegibles {
                formato: FORMATO_AUDITABLE,
                motivo: format!("la seccion mide {} bytes, fuera del tope", s.tamano),
            },
        };
    }
    if let Some(s) = secs.iter().find(|s| s.nombre == ".go.buildinfo") {
        return match contenido(ruta, s) {
            Some(b) => match go_buildinfo(&b, ruta) {
                Ok(v) => Metadatos::Leidos(v),
                Err(motivo) => Metadatos::Ilegibles {
                    formato: FORMATO_GO,
                    motivo,
                },
            },
            None => Metadatos::Ilegibles {
                formato: FORMATO_GO,
                motivo: format!("la seccion mide {} bytes, fuera del tope", s.tamano),
            },
        };
    }
    Metadatos::Ninguno
}

/// Nombre del formato de `cargo-auditable`.
pub const FORMATO_AUDITABLE: &str = "cargo-auditable";
/// Nombre del formato de Go.
pub const FORMATO_GO: &str = "go-buildinfo";

/// Descomprime zlib con tope.
fn inflar_zlib(b: &[u8]) -> Result<Vec<u8>, String> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(b, MAX_DESCOMPRIMIDO)
        .map_err(|e| format!("zlib: {:?}", e.status))
}

/// Lee la seccion `.dep-v0` de `cargo-auditable`.
///
/// Es JSON comprimido con zlib: `{"packages":[{"name","version","source",
/// "kind","dependencies","root"}]}`. Se quedan las dependencias de ejecucion:
/// las de compilacion (`"kind":"build"`) no viajan dentro del binario, y
/// contarlas pondria en el inventario codigo que no esta en la maquina.
///
/// # Errors
///
/// Si no se descomprime o no es el JSON esperado.
pub fn auditable(comprimido: &[u8], binario: &Path) -> Result<Vec<Componente>, String> {
    let json = inflar_zlib(comprimido)?;
    let v: serde_json::Value = serde_json::from_slice(&json).map_err(|e| format!("JSON: {e}"))?;
    let paquetes = v
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or("falta `packages`")?;
    let mut out = Vec::new();
    for p in paquetes.iter().take(MAX_COMPONENTES_POR_BINARIO) {
        let (Some(nombre), Some(version)) = (
            p.get("name").and_then(|x| x.as_str()),
            p.get("version").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        if p.get("kind").and_then(|k| k.as_str()) == Some("build") {
            continue;
        }
        out.push(Componente::nuevo(
            Ecosistema::Cargo,
            nombre,
            version,
            Procedencia::MetadatosDeCompilacion {
                binario: binario.to_path_buf(),
                formato: FORMATO_AUDITABLE,
            },
        ));
    }
    if out.is_empty() {
        return Err("la lista de paquetes esta vacia".into());
    }
    Ok(out)
}

/// La marca con que empieza la informacion de compilacion de Go.
pub const MAGIA_GO: &[u8] = b"\xff Go buildinf:";

/// Lee un entero de longitud variable (LEB128 sin signo), como lo escribe Go.
fn varint(b: &[u8], i: &mut usize) -> Option<usize> {
    let mut v: u64 = 0;
    for desplaz in (0..64).step_by(7) {
        let byte = *b.get(*i)?;
        *i += 1;
        v |= u64::from(byte & 0x7f) << desplaz;
        if byte & 0x80 == 0 {
            return usize::try_from(v).ok();
        }
    }
    None
}

/// Lee la seccion `.go.buildinfo`.
///
/// Desde Go 1.18 la version y la informacion de modulos van EN LINEA tras una
/// cabecera de 32 bytes: magia (14), tamano de puntero (1), banderas (1; el bit
/// 2 marca el formato en linea), relleno, y luego dos cadenas con su longitud
/// como varint. La de modulos va entre dos centinelas de 16 bytes y tiene una
/// linea por modulo: `path`, `mod` (el principal), `dep` y `=>` (sustitucion).
///
/// El formato anterior guarda punteros a las cadenas en vez de las cadenas, y
/// seguirlos exige cargar el binario como lo haria el cargador. **No se hace**, y
/// se dice: un binario de Go anterior a 1.18 da [`Metadatos::Ilegibles`], no una
/// lista vacia.
///
/// # Errors
///
/// Si no es el formato en linea o esta truncado.
pub fn go_buildinfo(b: &[u8], binario: &Path) -> Result<Vec<Componente>, String> {
    if b.get(..MAGIA_GO.len()) != Some(MAGIA_GO) {
        return Err("sin la marca de Go".into());
    }
    let banderas = *b.get(15).ok_or("cabecera truncada")?;
    if banderas & 0x2 == 0 {
        return Err("formato anterior a Go 1.18 (punteros en vez de cadenas): no se sigue".into());
    }
    let mut i = 32;
    let n = varint(b, &mut i).ok_or("longitud de version ilegible")?;
    let fin = i.checked_add(n).ok_or("longitud desbordada")?;
    let version_go = b.get(i..fin).ok_or("version truncada")?;
    i = fin;
    let n = varint(b, &mut i).ok_or("longitud de modulos ilegible")?;
    let fin = i.checked_add(n).ok_or("longitud desbordada")?;
    let mut info = b.get(i..fin).ok_or("informacion de modulos truncada")?;
    // Los centinelas de 16 bytes a cada lado.
    if info.len() >= 33 && info[info.len() - 17] == b'\n' {
        info = &info[16..info.len() - 16];
    }
    let texto = String::from_utf8_lossy(info);
    let mut out = Vec::new();
    let proc = || Procedencia::MetadatosDeCompilacion {
        binario: binario.to_path_buf(),
        formato: FORMATO_GO,
    };
    // La biblioteca estandar va en el binario y tiene sus propios avisos: es un
    // componente, con la version del compilador.
    let vgo = String::from_utf8_lossy(version_go);
    if let Some(v) = vgo.strip_prefix("go") {
        out.push(Componente::nuevo(
            Ecosistema::Go,
            "stdlib",
            format!("v{v}"),
            proc(),
        ));
    }
    for linea in texto.lines().take(MAX_COMPONENTES_POR_BINARIO) {
        let campos: Vec<&str> = linea.split('\t').collect();
        match campos.as_slice() {
            ["mod", ruta, version, ..] | ["dep", ruta, version, ..] => {
                // `(devel)` es el modulo principal compilado desde un arbol sin
                // version: no se puede casar con ningun aviso y no se inventa una.
                if *version != "(devel)" {
                    out.push(Componente::nuevo(Ecosistema::Go, *ruta, *version, proc()));
                }
            }
            // La sustitucion reemplaza al `dep` anterior: el codigo que va dentro
            // es el del sustituto.
            ["=>", ruta, version, ..] => {
                if let Some(ultimo) = out.last_mut() {
                    ultimo.nombre = (*ruta).to_string();
                    ultimo.version = (*version).to_string();
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Una firma de version de una biblioteca que se enlaza estaticamente.
#[derive(Debug, Clone, Copy)]
pub struct Firma {
    /// Nombre de la firma.
    pub nombre: &'static str,
    /// El prefijo que la identifica.
    pub prefijo: &'static [u8],
    /// El componente al que corresponde.
    pub componente: &'static str,
}

/// Las firmas que se reconocen.
///
/// # Solo las comprobadas contra un binario real
///
/// Cada firma de esta tabla se coteja en las pruebas con una biblioteca real de
/// la maquina de integracion. Una firma que nadie ha comprobado es una suposicion
/// sobre como escribe su version una biblioteca, y la de zlib es el ejemplo: la
/// cadena `deflate 1.x Copyright` que cita la documentacion no esta en la
/// `libz.so` de esta maquina. No se incluye.
pub const FIRMAS: &[Firma] = &[Firma {
    nombre: "openssl-version",
    prefijo: b"OpenSSL ",
    componente: "openssl",
}];

/// Busca las firmas en unos bytes: devuelve (firma, version) de cada una.
///
/// La version tiene que tener forma de version —digitos y puntos, con una letra
/// opcional detras—: `OpenSSL ` seguido de cualquier otra cosa es texto, no una
/// firma.
#[must_use]
pub fn firmas_en(bytes: &[u8]) -> Vec<(&'static Firma, String)> {
    let mut out: Vec<(&'static Firma, String)> = Vec::new();
    for f in FIRMAS {
        let mut desde = 0;
        while let Some(pos) = buscar(&bytes[desde..], f.prefijo) {
            let ini = desde + pos + f.prefijo.len();
            let resto = &bytes[ini..bytes.len().min(ini + 32)];
            // La version tiene que TERMINAR dentro de lo leido. Una que llega al
            // final del bufer puede estar cortada —`3.0.12` leida como `3.0.1`—,
            // y una version cortada tiene forma de version: se anotaria una
            // falsa. Al leer por trozos, el solape hace que se vea entera en el
            // siguiente.
            let Some(fin) = resto
                .iter()
                .position(|b| !(b.is_ascii_alphanumeric() || *b == b'.'))
            else {
                desde = ini;
                continue;
            };
            let v = &resto[..fin];
            let forma_de_version = v.first().is_some_and(u8::is_ascii_digit)
                && v.iter().filter(|b| **b == b'.').count() >= 2;
            if forma_de_version {
                let v = String::from_utf8_lossy(v).into_owned();
                if !out.iter().any(|(g, w)| g.nombre == f.nombre && *w == v) {
                    out.push((f, v));
                }
            }
            desde = ini;
        }
    }
    out
}

fn buscar(pajar: &[u8], aguja: &[u8]) -> Option<usize> {
    pajar.windows(aguja.len()).position(|w| w == aguja)
}

/// Tamano del trozo con que se busca una firma.
pub const TROZO_FIRMA: usize = 1024 * 1024;

/// Lo que se solapa un trozo con el siguiente: el prefijo mas largo y la version
/// que se lee detras, para que una firma partida entre dos trozos se vea entera
/// en uno de ellos.
const SOLAPE_FIRMA: usize = 64;

/// Busca las firmas en un fichero sin cargarlo entero.
///
/// Leerlo entero —la primera version lo hacia— ponia el inventario por encima
/// del presupuesto de memoria del agente en cuanto habia un ejecutable grande
/// sin paquete: los de Trivy o Syft pesan cientos de megas, y el pico medido
/// fue de 414 MB. Por trozos de un mega con solape, la memoria es la de un trozo
/// sea cual sea el tamano del fichero.
///
/// # Errors
///
/// Si el fichero no se puede leer.
pub fn firmas_en_fichero(ruta: &Path) -> std::io::Result<Vec<(&'static Firma, String)>> {
    use std::io::Read;
    let mut f = File::open(ruta)?;
    let mut buf = vec![0u8; TROZO_FIRMA + SOLAPE_FIRMA];
    let mut arrastre = 0usize;
    let mut out: Vec<(&'static Firma, String)> = Vec::new();
    let mut leidos: u64 = 0;
    loop {
        let n = f.read(&mut buf[arrastre..])?;
        if n == 0 {
            break;
        }
        leidos += n as u64;
        let fin = arrastre + n;
        for (firma, v) in firmas_en(&buf[..fin]) {
            if !out.iter().any(|(g, w)| g.nombre == firma.nombre && *w == v) {
                out.push((firma, v));
            }
        }
        if leidos > MAX_FIRMA {
            break;
        }
        // Se conserva la cola para el siguiente trozo.
        let cola = fin.min(SOLAPE_FIRMA);
        buf.copy_within(fin - cola..fin, 0);
        arrastre = cola;
    }
    Ok(out)
}

/// Los componentes que las firmas reconocen en un fichero.
#[must_use]
pub fn por_firma(ruta: &Path) -> Vec<Componente> {
    let Ok(firmas) = firmas_en_fichero(ruta) else {
        return Vec::new();
    };
    firmas
        .into_iter()
        .map(|(f, v)| {
            let mut c = Componente::nuevo(
                Ecosistema::Generico,
                f.componente,
                v,
                Procedencia::Firma {
                    fichero: ruta.to_path_buf(),
                    firma: f.nombre,
                },
            );
            c.ficheros = vec![PathBuf::from(ruta)];
            c
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn zlib(datos: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(datos, 6)
    }

    #[test]
    fn auditable_quita_las_dependencias_de_compilacion() {
        let json = br#"{"packages":[
            {"name":"sudo-rs","version":"0.2.2","source":"local","root":true},
            {"name":"libc","version":"0.2.153","source":"crates.io","dependencies":[]},
            {"name":"cc","version":"1.0.90","source":"crates.io","kind":"build"}
        ]}"#;
        let v = auditable(&zlib(json), Path::new("/usr/bin/sudo")).unwrap();
        let nombres: Vec<&str> = v.iter().map(|c| c.nombre.as_str()).collect();
        assert_eq!(nombres, ["sudo-rs", "libc"]);
        assert_eq!(v[1].purl(), "pkg:cargo/libc@0.2.153");
    }

    #[test]
    fn una_bomba_de_zlib_no_pasa_del_tope() {
        // Cien megas de ceros comprimen a unos cien kilobytes.
        let bomba = zlib(&vec![0u8; 100 * 1024 * 1024]);
        assert!(bomba.len() < 1024 * 1024);
        assert!(auditable(&bomba, Path::new("x")).is_err());
    }

    fn buildinfo(version: &str, modinfo: &str) -> Vec<u8> {
        let mut b = MAGIA_GO.to_vec();
        b.push(8); // tamano de puntero
        b.push(0x2); // en linea
        b.resize(32, 0);
        let mut cadena = |s: &[u8]| {
            let mut n = s.len();
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    b.push(byte);
                    break;
                }
                b.push(byte | 0x80);
            }
            b.extend_from_slice(s);
        };
        cadena(version.as_bytes());
        let mut info = vec![0x30u8; 16];
        info.extend_from_slice(modinfo.as_bytes());
        info.extend_from_slice(&[0xf9u8; 16]);
        cadena(&info);
        b
    }

    #[test]
    fn go_en_linea_con_sustitucion() {
        let modinfo = "path\texample.com/app\n\
                       mod\texample.com/app\t(devel)\t\n\
                       dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n\
                       dep\tgithub.com/viejo/lib\tv1.0.0\t\n\
                       =>\tgithub.com/nuevo/lib\tv1.2.0\th1:def=\n";
        let b = buildinfo("go1.21.5", modinfo);
        let v = go_buildinfo(&b, Path::new("/usr/bin/app")).unwrap();
        let pares: Vec<(&str, &str)> = v
            .iter()
            .map(|c| (c.nombre.as_str(), c.version.as_str()))
            .collect();
        assert_eq!(
            pares,
            [
                ("stdlib", "v1.21.5"),
                ("golang.org/x/net", "v0.17.0"),
                ("github.com/nuevo/lib", "v1.2.0"),
            ]
        );
    }

    #[test]
    fn go_anterior_a_1_18_se_declara_ilegible() {
        let mut b = MAGIA_GO.to_vec();
        b.push(8);
        b.push(0); // punteros
        b.resize(64, 0);
        assert!(go_buildinfo(&b, Path::new("x"))
            .unwrap_err()
            .contains("1.18"));
    }

    #[test]
    fn go_truncado_no_revienta() {
        let b = buildinfo("go1.22", "dep\ta\tv1\t\n");
        for n in 0..b.len() {
            let _ = go_buildinfo(&b[..n], Path::new("x"));
        }
    }

    #[test]
    fn una_firma_partida_entre_dos_trozos_se_encuentra() {
        // La firma empieza justo antes del final del primer trozo.
        let dir = std::env::temp_dir().join(format!("aegis-sbom-trozo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("grande");
        let mut b = vec![b'x'; TROZO_FIRMA - 5];
        b.extend_from_slice(b"OpenSSL 3.0.2 15 Mar 2022\0");
        b.extend(std::iter::repeat_n(b'y', 3 * TROZO_FIRMA));
        b.extend_from_slice(b"OpenSSL 1.1.1w  11 Sep 2023\0");
        std::fs::write(&f, &b).unwrap();
        let v: Vec<String> = firmas_en_fichero(&f)
            .unwrap()
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        assert_eq!(v, ["3.0.2", "1.1.1w"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_version_cortada_al_final_del_bufer_no_se_anota() {
        assert!(firmas_en(b"OpenSSL 3.0.1").is_empty(), "podria ser 3.0.12");
        assert_eq!(firmas_en(b"OpenSSL 3.0.12\0").len(), 1);
    }

    #[test]
    fn la_firma_exige_forma_de_version() {
        let b = b"...OpenSSL 3.0.2 15 Mar 2022\0OpenSSL cannot\0OpenSSL 1.1.1w  11 Sep 2023\0";
        let v: Vec<String> = firmas_en(b).into_iter().map(|(_, v)| v).collect();
        assert_eq!(v, ["3.0.2", "1.1.1w"]);
    }

    #[test]
    fn una_tabla_de_secciones_incoherente_no_se_sigue() {
        let dir = std::env::temp_dir().join(format!("aegis-sbom-elf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("roto");
        let mut cab = vec![0u8; 64];
        cab[..4].copy_from_slice(b"\x7fELF");
        cab[4] = 2;
        cab[5] = 1;
        cab[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes()); // tabla fuera
        cab[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        cab[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());
        std::fs::write(&f, &cab).unwrap();
        assert!(secciones(&f).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
