//! Lo que comparten los disectores de protocolos de texto: lineas, cabeceras
//! HTTP, base64 y entropia.
//!
//! # Por que esta escrito aqui y no se trae una biblioteca
//!
//! Porque estas cuatro cosas son cuarenta lineas cada una y entran en la ruta
//! mas expuesta del agente: los bytes que llegan aqui los escribe el atacante,
//! sin autenticacion previa y a velocidad de linea. Es la regla que ya seguia
//! `aegis-wire` —«cero dependencias externas nuevas, y no es una postura»— y no
//! cambia porque el crate sea otro.
//!
//! # La regla que cumplen todas las funciones de aqui
//!
//! Ninguna reserva memoria proporcional a un campo que venga en los datos sin
//! un tope, y ninguna puede entrar en un bucle sin fin. Con cuarenta disectores
//! llamandolas, una sola que lo incumpliera bastaria para tumbar el agente con
//! un paquete preparado.

/// Cuanto texto se mira de una cabecera antes de rendirse.
///
/// Un cliente legitimo no manda cabeceras de mas de ocho kilobytes; uno que las
/// mande esta buscando justamente que el sensor las recorra enteras.
pub const MAX_CABECERAS: usize = 8 * 1024;

/// La linea que empieza en `datos`, sin su terminador, y cuanto ocupo.
///
/// Acepta `\r\n` y `\n`: un emisor que use solo `\n` en un protocolo que exige
/// `\r\n` esta fuera de norma, y muchos servidores lo aceptan — un disector que
/// no lo acepte ve menos que el servidor al que protege.
#[must_use]
pub fn linea(datos: &[u8]) -> Option<(&[u8], usize)> {
    let fin = datos.iter().take(MAX_CABECERAS).position(|&b| b == b'\n')?;
    let sin_lf = &datos[..fin];
    let limpio = match sin_lf.last() {
        Some(b'\r') => &sin_lf[..sin_lf.len() - 1],
        _ => sin_lf,
    };
    Some((limpio, fin + 1))
}

/// Las lineas de una cabecera de estilo HTTP, hasta la linea en blanco.
///
/// Se para en [`MAX_CABECERAS`] bytes o en doscientas lineas, lo que llegue
/// antes. Sin ninguno de los dos topes, un flujo sin linea en blanco haria que
/// el disector recorriera el buffer entero por cada trozo que llega.
#[must_use]
pub fn lineas_de_cabecera(datos: &[u8]) -> Vec<&[u8]> {
    const MAX_LINEAS: usize = 200;
    let mut salida = Vec::new();
    let mut pos = 0;
    while pos < datos.len() && pos < MAX_CABECERAS && salida.len() < MAX_LINEAS {
        let Some((l, avance)) = linea(&datos[pos..]) else {
            break;
        };
        pos += avance;
        if l.is_empty() {
            break;
        }
        salida.push(l);
    }
    salida
}

/// El valor de una cabecera de estilo HTTP, buscada sin distinguir mayusculas.
///
/// **Salta la primera linea**, que en HTTP es la de peticion o la de estado.
/// Para un bloque que no la lleve —una parte MIME dentro de un correo— esta
/// [`cabecera_mime`]: confundir los dos hace perder la primera cabecera de la
/// parte, que muchas veces es justo la codificacion del adjunto.
#[must_use]
pub fn cabecera(datos: &[u8], nombre: &str) -> Option<String> {
    buscar_cabecera(datos, nombre, 1)
}

/// El valor de una cabecera en un bloque **sin** linea de peticion.
#[must_use]
pub fn cabecera_mime(datos: &[u8], nombre: &str) -> Option<String> {
    buscar_cabecera(datos, nombre, 0)
}

fn buscar_cabecera(datos: &[u8], nombre: &str, saltar: usize) -> Option<String> {
    let nombre = nombre.as_bytes();
    for l in lineas_de_cabecera(datos).into_iter().skip(saltar) {
        let Some(dos) = l.iter().position(|&b| b == b':') else {
            continue;
        };
        let (clave, valor) = l.split_at(dos);
        if clave.len() == nombre.len()
            && clave
                .iter()
                .zip(nombre)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            let v = valor[1..]
                .iter()
                .copied()
                .skip_while(u8::is_ascii_whitespace)
                .collect::<Vec<u8>>();
            return Some(aegis_wire::lector::ascii_legible(&v));
        }
    }
    None
}

/// La linea de peticion de HTTP: `(metodo, ruta, version)`.
///
/// Solo reconoce un metodo de letras mayusculas y una version que empiece por
/// `HTTP/`: sin esas dos condiciones, cualquier linea de texto con dos espacios
/// pasaria por una peticion HTTP y el registro se llenaria de protocolos
/// inventados.
#[must_use]
pub fn peticion_http(datos: &[u8]) -> Option<(String, String, String)> {
    let (l, _) = linea(datos)?;
    let mut partes = l.splitn(3, |&b| b == b' ');
    let metodo = partes.next()?;
    let ruta = partes.next()?;
    let version = partes.next()?;
    if metodo.is_empty() || metodo.len() > 24 || !metodo.iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    if !version.starts_with(b"HTTP/") {
        return None;
    }
    if ruta.is_empty() || ruta.len() > 4096 {
        return None;
    }
    Some((
        aegis_wire::lector::ascii_legible(metodo),
        aegis_wire::lector::ascii_legible(ruta),
        aegis_wire::lector::ascii_legible(version),
    ))
}

/// Donde acaba la cabecera de estilo HTTP y empieza el cuerpo.
#[must_use]
pub fn fin_de_cabecera(datos: &[u8]) -> Option<usize> {
    let tope = datos.len().min(MAX_CABECERAS);
    datos[..tope]
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| {
            datos[..tope]
                .windows(2)
                .position(|v| v == b"\n\n")
                .map(|p| p + 2)
        })
}

/// Cuanto puede salir de una decodificacion base64 de este crate.
///
/// El tope es del **resultado**, no de la entrada: sin el, una cadena de un
/// megabyte haria reservar setecientos cincuenta kilobytes por cada mensaje, y
/// eso lo elige quien manda el mensaje.
pub const MAX_BASE64: usize = 256 * 1024;

const NO_ES_BASE64: u8 = 0xFF;

/// El valor de un caracter base64, aceptando tambien el alfabeto de URL.
fn valor_base64(b: u8) -> u8 {
    match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => NO_ES_BASE64,
    }
}

/// Decodifica base64, tolerando espacios y saltos de linea.
///
/// Acepta los dos alfabetos —el estandar y el de URL— y el relleno opcional,
/// porque los dos aparecen en la red: NTLM sobre HTTP usa el estandar y DNS
/// sobre HTTPS usa el de URL sin relleno. Lo que **no** acepta es mezclarlos, y
/// eso no es purismo: una frontera MIME es una fila de guiones, y un
/// decodificador que tome el guion por un caracter valido se traga la frontera y
/// devuelve un adjunto con siete bytes de mas que nadie mando.
///
/// Devuelve `None` si aparece un caracter que no es de ninguno de los dos
/// alfabetos, si se mezclan, o si el resultado pasaria de [`MAX_BASE64`].
#[must_use]
pub fn base64(datos: &[u8]) -> Option<Vec<u8>> {
    decodificar_base64(datos, true)
}

/// Decodifica base64 **estandar**, rechazando el alfabeto de URL.
///
/// Es la que usan los adjuntos de correo y NTLM dentro de HTTP. Existe aparte
/// porque el guion es un caracter valido del otro alfabeto y una frontera MIME es
/// una fila de guiones: un decodificador que acepte los dos a la vez se traga la
/// frontera y devuelve un adjunto con bytes que nadie mando. Quien sabe en que
/// alfabeto viene lo dice, y asi no hay que adivinarlo.
#[must_use]
pub fn base64_estandar(datos: &[u8]) -> Option<Vec<u8>> {
    decodificar_base64(datos, false)
}

fn decodificar_base64(datos: &[u8], acepta_url: bool) -> Option<Vec<u8>> {
    let mut salida = Vec::new();
    let mut acumulado: u32 = 0;
    let mut bits = 0u32;
    let mut estandar = false;
    let mut de_url = false;
    for &b in datos {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        match b {
            b'+' | b'/' => estandar = true,
            b'-' | b'_' => {
                if !acepta_url {
                    return None;
                }
                de_url = true;
            }
            _ => {}
        }
        if estandar && de_url {
            return None;
        }
        let v = valor_base64(b);
        if v == NO_ES_BASE64 {
            return None;
        }
        acumulado = (acumulado << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if salida.len() >= MAX_BASE64 {
                return None;
            }
            salida.push(((acumulado >> bits) & 0xFF) as u8);
        }
    }
    Some(salida)
}

/// Que fraccion de estos bytes pertenece al alfabeto base64, en centesimas.
///
/// Sirve para reconocer datos codificados dentro de un campo que deberia ser
/// texto —una cookie que lleva un tunel, por ejemplo— sin tener que decodificar
/// nada.
#[must_use]
pub fn fraccion_base64(datos: &[u8]) -> u8 {
    if datos.is_empty() {
        return 0;
    }
    let buenos = datos
        .iter()
        .filter(|&&b| valor_base64(b) != NO_ES_BASE64 || b == b'=')
        .count();
    ((buenos * 100) / datos.len()).min(100) as u8
}

/// Entropia de Shannon en bits por byte, de cero a ocho.
///
/// Es la misma medida que `aegis-wire` usa para los indicios de tunel sobre
/// DNS, y esta aqui otra vez —sobre bytes y no sobre etiquetas— porque los
/// tuneles sobre HTTP e ICMP se reconocen igual: contenido que no se parece a
/// lo que ese campo lleva normalmente.
#[must_use]
pub fn entropia(datos: &[u8]) -> f64 {
    if datos.is_empty() {
        return 0.0;
    }
    let mut cuentas = [0usize; 256];
    for &b in datos {
        cuentas[b as usize] += 1;
    }
    let total = datos.len() as f64;
    cuentas
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Si estos bytes son texto imprimible en su mayoria.
#[must_use]
pub fn parece_texto(datos: &[u8]) -> bool {
    if datos.is_empty() {
        return false;
    }
    let buenos = datos
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n')
        .count();
    buenos * 10 >= datos.len() * 9
}

/// Una cadena terminada en cero, con tope.
///
/// El tope no es cosmetico: sin el, un buffer sin ningun cero haria que la
/// cadena creciera hasta el final del mensaje, que es un tamano que elige el
/// emisor.
#[must_use]
pub fn cadena_con_cero(datos: &[u8], tope: usize) -> Option<(String, usize)> {
    let fin = datos.iter().take(tope).position(|&b| b == 0)?;
    Some((aegis_wire::lector::ascii_legible(&datos[..fin]), fin + 1))
}

/// Texto UTF-16 en orden little-endian, como lo mandan Windows y TDS.
#[must_use]
pub fn utf16le(datos: &[u8]) -> String {
    datos
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .map(|u| char::from_u32(u32::from(u)).unwrap_or('\u{FFFD}'))
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_linea_acaba_igual_con_crlf_que_con_lf() {
        // Un emisor que use solo LF esta fuera de norma y muchos servidores lo
        // aceptan: un disector que no lo acepte ve menos que el servidor.
        assert_eq!(linea(b"hola\r\nmundo"), Some((&b"hola"[..], 6)));
        assert_eq!(linea(b"hola\nmundo"), Some((&b"hola"[..], 5)));
        assert_eq!(linea(b"sin final"), None);
    }

    #[test]
    fn las_cabeceras_se_buscan_sin_distinguir_mayusculas() {
        let d = b"GET / HTTP/1.1\r\nHost: ejemplo\r\nX-Cosa: 1\r\n\r\n";
        assert_eq!(cabecera(d, "host").as_deref(), Some("ejemplo"));
        assert_eq!(cabecera(d, "HOST").as_deref(), Some("ejemplo"));
        assert_eq!(cabecera(d, "no-esta"), None);
    }

    #[test]
    fn la_primera_linea_no_se_lee_como_cabecera() {
        // Sin saltarla, una peticion a `http://x/a:b` daria una cabecera con el
        // nombre «GET /a» que nadie mando.
        let d = b"GET /a:b HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(cabecera(d, "GET /a"), None);
    }

    #[test]
    fn una_linea_de_texto_cualquiera_no_pasa_por_peticion_http() {
        // Sin las dos condiciones —metodo en mayusculas y version HTTP/— el
        // registro se llenaria de protocolos inventados.
        assert!(peticion_http(b"hola que tal\r\n").is_none());
        assert!(peticion_http(b"get / HTTP/1.1\r\n").is_none());
        assert_eq!(
            peticion_http(b"POST /x HTTP/1.1\r\n").map(|(m, r, _)| (m, r)),
            Some(("POST".to_owned(), "/x".to_owned()))
        );
    }

    #[test]
    fn base64_acepta_los_dos_alfabetos_y_rechaza_lo_que_no_lo_es() {
        assert_eq!(base64(b"aG9sYQ==").as_deref(), Some(&b"hola"[..]));
        // El alfabeto de URL, sin relleno, que es el que usa DNS sobre HTTPS.
        assert_eq!(base64(b"-_8").map(|v| v.len()), Some(2));
        assert_eq!(base64(b"no es base64!"), None);
        // Mezclar los dos alfabetos no es base64 de nadie.
        assert_eq!(base64(b"ab+cd-ef"), None);
    }

    #[test]
    fn base64_no_se_traga_una_frontera_mime() {
        // El guion es un caracter del alfabeto de URL, asi que el decodificador
        // permisivo se traga la frontera: devuelve bytes que nadie mando. El que
        // sabe que viene en el alfabeto estandar la rechaza, y por eso los
        // adjuntos usan ese.
        assert!(base64(b"aG9sYQ==\r\n--frontera--").is_some());
        assert_eq!(base64_estandar(b"aG9sYQ==\r\n--frontera--"), None);
        assert_eq!(base64_estandar(b"aG9sYQ==").as_deref(), Some(&b"hola"[..]));
        // Y el de URL sigue valiendo donde toca: DNS sobre HTTPS lo usa.
        assert_eq!(base64(b"-_8").map(|v| v.len()), Some(2));
    }

    #[test]
    fn una_cabecera_mime_no_pierde_su_primera_linea() {
        // En una parte de un correo no hay linea de peticion delante, y saltarla
        // hace perder justo la codificacion del adjunto.
        let parte = b"Content-Transfer-Encoding: base64\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(
            cabecera_mime(parte, "Content-Transfer-Encoding").as_deref(),
            Some("base64")
        );
        assert_eq!(cabecera(parte, "Content-Transfer-Encoding"), None);
    }

    #[test]
    fn base64_no_reserva_lo_que_diga_el_emisor() {
        // El tope es del resultado: sin el, la memoria que se reserva por
        // mensaje la elige quien manda el mensaje.
        let enorme = vec![b'A'; MAX_BASE64 * 2];
        assert_eq!(base64(&enorme), None);
    }

    #[test]
    fn la_entropia_separa_texto_de_datos_comprimidos() {
        let texto = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(entropia(texto) < 1.0);
        let variado: Vec<u8> = (0..=255u8).collect();
        assert!(entropia(&variado) > 7.9);
        assert_eq!(entropia(b""), 0.0);
    }

    #[test]
    fn una_cadena_sin_cero_no_crece_hasta_el_final_del_mensaje() {
        // Sin el tope, la longitud de la cadena la elegiria el emisor.
        let sin_cero = vec![b'A'; 1000];
        assert_eq!(cadena_con_cero(&sin_cero, 32), None);
        assert_eq!(
            cadena_con_cero(b"hola\0resto", 32),
            Some(("hola".to_owned(), 5))
        );
    }

    #[test]
    fn el_utf16_de_windows_se_lee_como_texto() {
        let mut v = Vec::new();
        for c in "SELECT 1".chars() {
            v.extend_from_slice(&(c as u16).to_le_bytes());
        }
        assert_eq!(utf16le(&v), "SELECT 1");
    }

    #[test]
    fn el_fin_de_cabecera_se_encuentra_con_los_dos_finales() {
        assert_eq!(fin_de_cabecera(b"a\r\n\r\ncuerpo"), Some(5));
        assert_eq!(fin_de_cabecera(b"a\n\ncuerpo"), Some(3));
        assert_eq!(fin_de_cabecera(b"sin final"), None);
    }
}
