//! Syslog RFC 5424 sobre TLS: el destino que todo SIEM entiende.
//!
//! # Por que contar octetos y no delimitar por salto de linea
//!
//! La forma tradicional de meter syslog en un flujo TCP es separar mensajes con
//! `\n`. Es una vulnerabilidad, no una simplificacion: los mensajes de un EDR
//! llevan **lineas de comandos de procesos**, y una linea de comandos puede
//! contener un salto de linea porque la escribe el atacante.
//!
//! Con delimitacion por salto:
//!
//! ```text
//! <134>1 ... proceso ejecutado: cmd.exe /c whoami
//! <134>1 2024-01-01T00:00:00Z servidor - - - todo correcto
//! ```
//!
//! El SIEM ve DOS eventos, y el segundo lo escribio el atacante. Puede
//! fabricarse acuses de inocencia, borrar la sospecha de una investigacion o
//! desbordar una regla de correlacion, todo desde el nombre de un proceso.
//!
//! El marcado por conteo de octetos de la RFC 6587 —`LONGITUD ESPACIO
//! MENSAJE`— hace que eso sea imposible por construccion: el receptor lee
//! exactamente los bytes que se le anuncian y lo que haya dentro es carga, no
//! sintaxis. No hay nada que escapar y, por tanto, nada que se pueda olvidar
//! escapar.
//!
//! # Lo que se sanea de todas formas
//!
//! El conteo de octetos protege el MARCADO. No protege los campos de la
//! CABECERA —hostname, app-name, procid— que la RFC define como
//! `PRINTUSASCII` sin espacios: un hostname con un espacio corre los campos
//! siguientes y el SIEM lee la fecha donde deberia leer el programa. Esos
//! campos se sanean; el mensaje, no, porque ahi no hace falta y recortarlo
//! seria perder evidencia.

use std::fmt::Write as _;

/// Facility `local0`, la habitual para aplicaciones.
const FACILITY: u8 = 16;

/// Severidades de syslog que se usan.
///
/// Se mapean desde la severidad interna (0..4) en [`prioridad`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severidad {
    /// Sistema inutilizable.
    Emergencia = 0,
    /// Hay que actuar de inmediato.
    Alerta = 1,
    /// Condicion critica.
    Critica = 2,
    /// Error.
    Error = 3,
    /// Aviso.
    Aviso = 4,
    /// Condicion normal pero significativa.
    Notable = 5,
    /// Informativo.
    Informativo = 6,
}

/// Prioridad RFC 5424: `facility * 8 + severidad`.
pub fn prioridad(s: Severidad) -> u8 {
    FACILITY * 8 + s as u8
}

/// Traduce la severidad interna de AegisCore (0..4) a la de syslog.
///
/// No es una tabla arbitraria: la severidad 4 de AegisCore es «critica» y para
/// un SOC eso significa que alguien tiene que mirarlo ya, que es exactamente lo
/// que `Alerta` significa en syslog. Mapearlo todo a `Informativo` —lo comodo—
/// haria que las reglas de enrutado del SIEM del cliente no distinguieran un
/// ransomware de un cambio de configuracion.
pub fn severidad_de_aegis(sev: i16) -> Severidad {
    match sev {
        4 => Severidad::Alerta,
        3 => Severidad::Critica,
        2 => Severidad::Error,
        1 => Severidad::Aviso,
        _ => Severidad::Informativo,
    }
}

/// Campos de la cabecera de un mensaje.
#[derive(Debug, Clone)]
pub struct Cabecera {
    /// Severidad del suceso.
    pub severidad: Severidad,
    /// Marca de tiempo RFC 3339 con huso.
    pub momento: String,
    /// Maquina que lo origina.
    pub hostname: String,
    /// Programa.
    pub app: String,
    /// Identificador de proceso o de flujo.
    pub procid: String,
    /// Tipo de mensaje.
    pub msgid: String,
}

/// Longitud maxima de un campo de cabecera segun la RFC 5424.
const MAX_HOSTNAME: usize = 255;
const MAX_APP: usize = 48;
const MAX_PROCID: usize = 128;
const MAX_MSGID: usize = 32;

/// Sanea un campo de cabecera.
///
/// La RFC exige `PRINTUSASCII` (33..=126): imprimible y SIN espacios. Un
/// hostname con un espacio correria los campos siguientes y el SIEM leeria la
/// fecha donde deberia leer el programa. Lo que no encaja se sustituye en vez
/// de eliminarse: eliminar podria juntar dos valores distintos en el mismo
/// texto y hacerlos indistinguibles.
fn campo(v: &str, maximo: usize) -> String {
    let limpio: String = v
        .chars()
        .map(|c| if ('!'..='~').contains(&c) { c } else { '_' })
        .take(maximo)
        .collect();
    if limpio.is_empty() {
        "-".to_string()
    } else {
        limpio
    }
}

/// Compone un mensaje RFC 5424 completo (sin el marcado de transporte).
pub fn mensaje(c: &Cabecera, datos_estructurados: Option<&str>, texto: &str) -> String {
    let mut s = String::with_capacity(128 + texto.len());
    // El `unwrap` de `write!` sobre un String no puede fallar; se evita con
    // `let _` para no meter un panico en el camino de la auditoria.
    let _ = write!(
        s,
        "<{}>1 {} {} {} {} {} {} ",
        prioridad(c.severidad),
        campo(&c.momento, 64),
        campo(&c.hostname, MAX_HOSTNAME),
        campo(&c.app, MAX_APP),
        campo(&c.procid, MAX_PROCID),
        campo(&c.msgid, MAX_MSGID),
        datos_estructurados.unwrap_or("-")
    );
    // El BOM le dice al receptor que el mensaje es UTF-8. Sin el, la RFC
    // permite interpretarlo como una codificacion desconocida, y los nombres de
    // fichero de una deteccion llevan acentos y caracteres de otros alfabetos.
    s.push('\u{feff}');
    s.push_str(texto);
    s
}

/// Envuelve un mensaje con el marcado por conteo de octetos (RFC 6587).
///
/// La longitud se cuenta en BYTES, no en caracteres: un mensaje con una enye
/// ocupa mas bytes que caracteres, y anunciar caracteres dejaria al receptor
/// leyendo a destiempo el resto del flujo.
pub fn enmarcar(mensaje: &str) -> Vec<u8> {
    let cuerpo = mensaje.as_bytes();
    let mut salida = Vec::with_capacity(cuerpo.len() + 12);
    salida.extend_from_slice(cuerpo.len().to_string().as_bytes());
    salida.push(b' ');
    salida.extend_from_slice(cuerpo);
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn cabecera() -> Cabecera {
        Cabecera {
            severidad: Severidad::Alerta,
            momento: "2026-09-10T08:00:00Z".to_string(),
            hostname: "control-plane".to_string(),
            app: "aegiscore".to_string(),
            procid: "firehose".to_string(),
            msgid: "ALERTA".to_string(),
        }
    }

    #[test]
    fn un_salto_de_linea_en_la_carga_no_puede_partir_el_mensaje() {
        // EL motivo de todo el modulo. La linea de comandos la escribe el
        // atacante; con delimitacion por salto de linea, esto serian DOS
        // eventos para el SIEM y el segundo lo habria escrito el.
        let malicioso = "cmd.exe /c whoami\n<134>1 2026-01-01T00:00:00Z x - - - todo correcto";
        let m = mensaje(&cabecera(), None, malicioso);
        let marco = enmarcar(&m);

        let espacio = marco.iter().position(|b| *b == b' ').unwrap();
        let anunciada: usize = std::str::from_utf8(&marco[..espacio])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            anunciada,
            marco.len() - espacio - 1,
            "la longitud anunciada tiene que cubrir el mensaje ENTERO, saltos incluidos"
        );
        // Y el salto sigue dentro, porque es evidencia y no se recorta.
        assert!(m.contains('\n'));
    }

    #[test]
    fn la_longitud_se_cuenta_en_bytes_y_no_en_caracteres() {
        // Un nombre de fichero con acentos ocupa mas bytes que caracteres.
        // Anunciar caracteres dejaria al receptor leyendo a destiempo TODO el
        // resto del flujo: un solo mensaje con una enye desincroniza la sesion.
        let m = mensaje(&cabecera(), None, "fichero: contraseñas.txt — cifrado");
        let marco = enmarcar(&m);
        let espacio = marco.iter().position(|b| *b == b' ').unwrap();
        let anunciada: usize = std::str::from_utf8(&marco[..espacio])
            .unwrap()
            .parse()
            .unwrap();
        // `len()` de un `str` YA cuenta bytes en Rust; la comparacion con
        // `chars().count()` deja constancia de que son cosas distintas y de que
        // este mensaje concreto las distingue.
        assert_eq!(anunciada, m.len());
        assert_ne!(anunciada, m.chars().count(), "la prueba tiene que ser util");
    }

    #[test]
    fn un_hostname_con_espacios_no_corre_los_campos_de_la_cabecera() {
        // Sin sanear, el SIEM leeria la fecha donde deberia leer el programa y
        // el evento entero quedaria mal atribuido.
        let mut c = cabecera();
        c.hostname = "maquina de ventas".to_string();
        let m = mensaje(&c, None, "algo");
        let campos: Vec<&str> = m.splitn(8, ' ').collect();
        assert_eq!(campos[2], "maquina_de_ventas");
        assert_eq!(campos[3], "aegiscore", "el programa sigue en su sitio");
    }

    #[test]
    fn un_campo_vacio_se_convierte_en_el_nil_de_la_rfc() {
        let mut c = cabecera();
        c.procid = String::new();
        let m = mensaje(&c, None, "algo");
        let campos: Vec<&str> = m.splitn(8, ' ').collect();
        assert_eq!(campos[4], "-");
    }

    #[test]
    fn la_severidad_critica_no_se_degrada_a_informativa() {
        // Si todo saliera como informativo, las reglas de enrutado del SIEM del
        // cliente no distinguirian un ransomware de un cambio de configuracion.
        assert_eq!(severidad_de_aegis(4), Severidad::Alerta);
        assert_eq!(severidad_de_aegis(0), Severidad::Informativo);
        assert_ne!(severidad_de_aegis(4), severidad_de_aegis(0));
        // local0 (16) * 8 + 1 = 129
        assert_eq!(prioridad(Severidad::Alerta), 129);
    }

    #[test]
    fn el_mensaje_declara_utf8_con_el_bom() {
        // Sin BOM, la RFC permite interpretarlo como codificacion desconocida, y
        // los nombres de fichero de una deteccion llevan acentos.
        let m = mensaje(&cabecera(), None, "café");
        assert!(m.contains('\u{feff}'));
        assert!(m.ends_with("café"));
    }
}
