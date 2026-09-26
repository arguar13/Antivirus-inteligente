//! Un lector de tar en flujo y un descompresor gzip en flujo, con topes.
//!
//! # Por que en flujo
//!
//! Una capa de una imagen de contenedor pesa cientos de megas y va comprimida.
//! Descomprimirla entera en memoria para buscar cinco ficheros pondria el
//! inventario de una sola imagen por encima del presupuesto de memoria del
//! agente. Aqui la capa se descomprime por trozos mientras el tar se va leyendo,
//! y de cada entrada solo se guarda el contenido si interesa; el resto se
//! consume y se tira.
//!
//! # Por que no el crate `tar`
//!
//! Porque de un tar aqui solo hace falta LEER nombres y contenidos, y el lector
//! entero son cien lineas que se pueden auditar. Lo que un tar hostil puede
//! intentar —tamanos gigantes, nombres largos encadenados, cabeceras corruptas—
//! esta acotado abajo, cada caso con su prueba.

use std::io::{self, Read};

/// Tope de bytes que se guardan de una entrada interesante.
pub const MAX_ENTRADA: u64 = 32 * 1024 * 1024;

/// Tope de bytes de un nombre largo (GNU `L` o `path` de pax).
pub const MAX_NOMBRE: u64 = 64 * 1024;

/// Tope de entradas de un tar.
pub const MAX_ENTRADAS: usize = 2_000_000;

/// Una entrada de un tar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Ruta, sin `./` ni `/` delante.
    pub ruta: String,
    /// Tipo: `'0'` fichero, `'5'` directorio, `'2'` enlace simbolico...
    pub tipo: u8,
    /// Tamano declarado del contenido.
    pub tamano: u64,
}

impl Entrada {
    /// Si es un fichero regular.
    #[must_use]
    pub fn es_fichero(&self) -> bool {
        matches!(self.tipo, b'0' | 0)
    }
}

/// Lee un campo octal (o en base 256, la extension de GNU para tamanos grandes).
fn numero(campo: &[u8]) -> Option<u64> {
    if campo.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = u64::from(campo[0] & 0x7f);
        for b in &campo[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(*b))?;
        }
        return Some(v);
    }
    let s = std::str::from_utf8(campo).ok()?;
    let s = s.trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

fn cadena(campo: &[u8]) -> String {
    let fin = campo.iter().position(|b| *b == 0).unwrap_or(campo.len());
    String::from_utf8_lossy(&campo[..fin]).into_owned()
}

/// Normaliza una ruta de tar: sin `./` ni `/` delante.
#[must_use]
pub fn normalizar(ruta: &str) -> String {
    let mut r = ruta;
    loop {
        if let Some(x) = r.strip_prefix("./") {
            r = x;
        } else if let Some(x) = r.strip_prefix('/') {
            r = x;
        } else {
            break;
        }
    }
    r.trim_end_matches('/').to_string()
}

/// Lee exactamente `n` bytes o devuelve error.
fn leer_n(r: &mut dyn Read, n: u64) -> io::Result<Vec<u8>> {
    let mut v = Vec::with_capacity(usize::try_from(n.min(1 << 20)).unwrap_or(0));
    r.take(n).read_to_end(&mut v)?;
    if v.len() as u64 != n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "entrada truncada",
        ));
    }
    Ok(v)
}

/// Consume `n` bytes sin guardarlos.
fn saltar(r: &mut dyn Read, n: u64) -> io::Result<()> {
    let copiados = io::copy(&mut r.take(n), &mut io::sink())?;
    if copiados != n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "entrada truncada",
        ));
    }
    Ok(())
}

/// El relleno hasta el siguiente bloque de 512.
fn relleno(n: u64) -> u64 {
    (512 - n % 512) % 512
}

/// Recorre un tar llamando a `visitar` por cada entrada.
///
/// `visitar` decide si quiere el contenido: si devuelve `true`, se le entrega
/// (hasta [`MAX_ENTRADA`]) en `recibir`. Devuelve cuantas entradas se vieron.
///
/// # Errors
///
/// Si el tar esta truncado, una cabecera no es valida o se pasa de un tope.
pub fn recorrer(
    r: &mut dyn Read,
    visitar: &mut dyn FnMut(&Entrada) -> bool,
    recibir: &mut dyn FnMut(&Entrada, Vec<u8>),
) -> io::Result<usize> {
    let invalido = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let mut vistas = 0usize;
    let mut nombre_largo: Option<String> = None;
    let mut cab = [0u8; 512];
    loop {
        if r.read(&mut cab[..1])? == 0 {
            // Final sin los dos bloques de ceros: lo aceptan todas las
            // herramientas, y aqui tambien.
            return Ok(vistas);
        }
        r.read_exact(&mut cab[1..])?;
        if cab.iter().all(|b| *b == 0) {
            return Ok(vistas);
        }
        // La suma de comprobacion: los bytes de la cabecera con el campo de la
        // suma contado como espacios.
        let suma_declarada = numero(&cab[148..156]).ok_or_else(|| invalido("suma ilegible"))?;
        let suma: u64 = cab
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if suma != suma_declarada {
            return Err(invalido(
                "cabecera de tar con suma de comprobacion incorrecta",
            ));
        }
        vistas += 1;
        if vistas > MAX_ENTRADAS {
            return Err(invalido("demasiadas entradas"));
        }
        let tamano = numero(&cab[124..136]).ok_or_else(|| invalido("tamano ilegible"))?;
        let tipo = cab[156];
        let pad = relleno(tamano);
        match tipo {
            // Nombre largo de GNU: el contenido es el nombre de la siguiente.
            b'L' => {
                if tamano > MAX_NOMBRE {
                    return Err(invalido("nombre largo por encima del tope"));
                }
                let n = leer_n(r, tamano)?;
                saltar(r, pad)?;
                nombre_largo = Some(cadena(&n));
                continue;
            }
            // Cabecera pax: se busca `path=`.
            b'x' => {
                if tamano > MAX_NOMBRE {
                    return Err(invalido("cabecera pax por encima del tope"));
                }
                let n = leer_n(r, tamano)?;
                saltar(r, pad)?;
                let texto = String::from_utf8_lossy(&n);
                for reg in texto.lines() {
                    if let Some((_, kv)) = reg.split_once(' ') {
                        if let Some(p) = kv.strip_prefix("path=") {
                            nombre_largo = Some(p.to_string());
                        }
                    }
                }
                continue;
            }
            // Cabecera pax global: no afecta a los nombres.
            b'g' => {
                saltar(r, tamano + pad)?;
                continue;
            }
            _ => {}
        }
        let ruta = match nombre_largo.take() {
            Some(n) => n,
            None => {
                let nombre = cadena(&cab[0..100]);
                let prefijo = if &cab[257..262] == b"ustar" {
                    cadena(&cab[345..500])
                } else {
                    String::new()
                };
                if prefijo.is_empty() {
                    nombre
                } else {
                    format!("{prefijo}/{nombre}")
                }
            }
        };
        let e = Entrada {
            ruta: normalizar(&ruta),
            tipo,
            tamano,
        };
        // Los enlaces y directorios declaran tamano cero; si uno declara otro,
        // su contenido se salta igual.
        if e.es_fichero() && tamano <= MAX_ENTRADA && visitar(&e) {
            let c = leer_n(r, tamano)?;
            saltar(r, pad)?;
            recibir(&e, c);
        } else {
            saltar(r, tamano + pad)?;
        }
    }
}

// --- gzip en flujo ------------------------------------------------------------

/// Tabla del CRC-32 de gzip (polinomio 0xEDB88320).
fn tabla_crc() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, e) in t.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *e = c;
    }
    t
}

/// CRC-32 incremental.
#[derive(Clone)]
pub struct Crc32 {
    tabla: [u32; 256],
    valor: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Crc32 {
            tabla: tabla_crc(),
            valor: 0xFFFF_FFFF,
        }
    }
}

impl Crc32 {
    /// Anade bytes.
    pub fn anadir(&mut self, b: &[u8]) {
        for x in b {
            self.valor =
                self.tabla[((self.valor ^ u32::from(*x)) & 0xff) as usize] ^ (self.valor >> 8);
        }
    }
    /// El valor.
    #[must_use]
    pub fn valor(&self) -> u32 {
        !self.valor
    }
}

/// Un lector que descomprime gzip en flujo y comprueba el CRC al final.
///
/// Comprobar el CRC no es un lujo: una capa truncada o corrupta descomprime
/// «algo», y un inventario hecho sobre ese algo es un inventario falso que no
/// avisa. Con el CRC, lo que no cuadra es un error.
pub struct Gzip<R: Read> {
    dentro: R,
    estado: Box<miniz_oxide::inflate::stream::InflateState>,
    entrada: Vec<u8>,
    ini: usize,
    fin: usize,
    crc: Crc32,
    total: u64,
    acabado: bool,
    cabecera_leida: bool,
}

impl<R: Read> Gzip<R> {
    /// Envuelve un lector de gzip.
    pub fn nuevo(dentro: R) -> Gzip<R> {
        Gzip {
            dentro,
            estado: miniz_oxide::inflate::stream::InflateState::new_boxed(
                miniz_oxide::DataFormat::Raw,
            ),
            entrada: vec![0u8; 64 * 1024],
            ini: 0,
            fin: 0,
            crc: Crc32::default(),
            total: 0,
            acabado: false,
            cabecera_leida: false,
        }
    }

    fn byte(&mut self) -> io::Result<u8> {
        if self.ini == self.fin {
            self.rellenar()?;
            if self.ini == self.fin {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "gzip truncado",
                ));
            }
        }
        let b = self.entrada[self.ini];
        self.ini += 1;
        Ok(b)
    }

    fn rellenar(&mut self) -> io::Result<()> {
        if self.ini < self.fin {
            return Ok(());
        }
        self.ini = 0;
        self.fin = self.dentro.read(&mut self.entrada)?;
        Ok(())
    }

    /// Cabecera de RFC 1952: magia, metodo 8, banderas y sus campos opcionales.
    fn cabecera(&mut self) -> io::Result<()> {
        let invalido = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        let mut c = [0u8; 10];
        for b in &mut c {
            *b = self.byte()?;
        }
        if c[0] != 0x1f || c[1] != 0x8b || c[2] != 8 {
            return Err(invalido("no es gzip"));
        }
        let banderas = c[3];
        if banderas & 0x04 != 0 {
            let n = u16::from(self.byte()?) | (u16::from(self.byte()?) << 8);
            for _ in 0..n {
                self.byte()?;
            }
        }
        for bit in [0x08, 0x10] {
            if banderas & bit != 0 {
                // Nombre o comentario terminado en cero, con tope.
                let mut n = 0;
                while self.byte()? != 0 {
                    n += 1;
                    if n > MAX_NOMBRE {
                        return Err(invalido("campo de cabecera gzip sin terminar"));
                    }
                }
            }
        }
        if banderas & 0x02 != 0 {
            self.byte()?;
            self.byte()?;
        }
        Ok(())
    }

    fn cola(&mut self) -> io::Result<()> {
        let mut t = [0u8; 8];
        for b in &mut t {
            *b = self.byte()?;
        }
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        if crc != self.crc.valor() || isize != (self.total & 0xFFFF_FFFF) as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gzip con CRC o longitud que no cuadra: capa corrupta o truncada",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for Gzip<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        use miniz_oxide::inflate::stream::inflate;
        use miniz_oxide::{MZFlush, MZStatus};
        if !self.cabecera_leida {
            self.cabecera()?;
            self.cabecera_leida = true;
        }
        if self.acabado || out.is_empty() {
            return Ok(0);
        }
        loop {
            self.rellenar()?;
            let r = inflate(
                &mut self.estado,
                &self.entrada[self.ini..self.fin],
                out,
                MZFlush::None,
            );
            self.ini += r.bytes_consumed;
            let escritos = r.bytes_written;
            self.crc.anadir(&out[..escritos]);
            self.total += escritos as u64;
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    self.acabado = true;
                    self.cola()?;
                    return Ok(escritos);
                }
                Ok(_) => {
                    if escritos > 0 {
                        return Ok(escritos);
                    }
                    if r.bytes_consumed == 0 && self.ini == self.fin {
                        self.rellenar()?;
                        if self.ini == self.fin {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "gzip truncado",
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("deflate: {e:?}"),
                    ))
                }
            }
        }
    }
}

/// Un tar escrito a mano, para las pruebas de este crate.
#[cfg(test)]
pub mod pruebas_tar {
    /// Una cabecera ustar valida.
    pub fn cabecera(nombre: &str, tamano: usize, tipo: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..nombre.len()].copy_from_slice(nombre.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{tamano:011o}").as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = tipo;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let s: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{s:06o}\0").as_bytes());
        h
    }

    /// Un tar con esas entradas (nombre, contenido).
    pub fn tar(entradas: &[(&str, &[u8])]) -> Vec<u8> {
        let mut t = Vec::new();
        for (n, c) in entradas {
            t.extend_from_slice(&cabecera(n, c.len(), b'0'));
            t.extend_from_slice(c);
            t.resize(t.len() + (512 - c.len() % 512) % 512, 0);
        }
        t.resize(t.len() + 1024, 0);
        t
    }

    /// gzip de unos bytes.
    pub fn gzip(datos: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        g.extend(miniz_oxide::deflate::compress_to_vec(datos, 6));
        let mut c = super::Crc32::default();
        c.anadir(datos);
        g.extend_from_slice(&c.valor().to_le_bytes());
        g.extend_from_slice(&(datos.len() as u32).to_le_bytes());
        g
    }
}

#[cfg(test)]
mod pruebas {
    use super::pruebas_tar::*;
    use super::*;

    /// Entradas vistas y (ruta, contenido) de las que interesaban.
    type Leido = (usize, Vec<(String, Vec<u8>)>);

    fn leer_todo(t: &[u8], quiero: &str) -> io::Result<Leido> {
        let mut v = Vec::new();
        let n = recorrer(&mut &t[..], &mut |e| e.ruta == quiero, &mut |e, c| {
            v.push((e.ruta.clone(), c))
        })?;
        Ok((n, v))
    }

    #[test]
    fn se_leen_solo_las_entradas_que_interesan() {
        let t = tar(&[
            ("./etc/os-release", b"ID=alpine\n"),
            ("./lib/apk/db/installed", b"P:musl\nV:1.2.4-r2\n\n"),
        ]);
        let (n, v) = leer_todo(&t, "lib/apk/db/installed").unwrap();
        assert_eq!(n, 2);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, b"P:musl\nV:1.2.4-r2\n\n");
    }

    #[test]
    fn nombre_largo_de_gnu() {
        let largo = format!("{}/Cargo.lock", "d".repeat(150));
        let mut t = Vec::new();
        t.extend_from_slice(&cabecera("././@LongLink", largo.len() + 1, b'L'));
        let mut n = largo.clone().into_bytes();
        n.push(0);
        t.extend_from_slice(&n);
        t.resize(t.len() + (512 - n.len() % 512) % 512, 0);
        t.extend_from_slice(&cabecera("recortado", 3, b'0'));
        t.extend_from_slice(b"abc");
        t.resize(t.len() + 509 + 1024, 0);
        let (_, v) = leer_todo(&t, &largo).unwrap();
        assert_eq!(v.len(), 1, "el nombre largo sustituye al recortado");
    }

    #[test]
    fn una_cabecera_con_suma_mala_es_un_error_y_no_basura() {
        let mut t = tar(&[("a", b"x")]);
        t[0] = b'b';
        assert!(leer_todo(&t, "a").is_err());
    }

    #[test]
    fn un_tar_truncado_es_un_error() {
        let t = tar(&[("a", &[7u8; 2000])]);
        assert!(leer_todo(&t[..1200], "a").is_err());
    }

    #[test]
    fn gzip_en_flujo_con_crc() {
        let datos: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let g = gzip(&datos);
        let mut out = Vec::new();
        Gzip::nuevo(&g[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, datos);
    }

    #[test]
    fn gzip_corrupto_o_truncado_no_pasa() {
        let datos = vec![5u8; 100_000];
        let mut g = gzip(&datos);
        let n = g.len();
        g[n - 6] ^= 0xff; // el CRC
        let mut out = Vec::new();
        assert!(Gzip::nuevo(&g[..]).read_to_end(&mut out).is_err());
        let g = gzip(&datos);
        let mut out = Vec::new();
        assert!(Gzip::nuevo(&g[..g.len() / 2])
            .read_to_end(&mut out)
            .is_err());
    }

    #[test]
    fn el_tar_se_lee_a_traves_del_gzip() {
        let t = tar(&[("var/lib/dpkg/status", b"Package: a\n")]);
        let g = gzip(&t);
        let mut v = Vec::new();
        recorrer(&mut Gzip::nuevo(&g[..]), &mut |_| true, &mut |e, c| {
            v.push((e.ruta.clone(), c))
        })
        .unwrap();
        assert_eq!(
            v,
            [("var/lib/dpkg/status".to_string(), b"Package: a\n".to_vec())]
        );
    }
}
