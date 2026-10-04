//! Redaccion de lo que sale del endpoint hacia una persona: el diagnostico de
//! soporte (`aegis-agent --diagnostico`) y el detalle de `status`.
//!
//! # Por que aqui
//!
//! Lo que el canal de control entrega al operador es lo que sale de la maquina,
//! y decidir que no puede salir es de quien lo entrega. Las credenciales en
//! claro las reconoce el redactor de `aegis-captura` —el mismo que decide que
//! no se guarda de una captura de trafico—, y no una lista copiada: dos listas
//! de patrones divergirian. A eso se añade lo propio de un informe de soporte:
//! el nombre del equipo, las rutas de usuario, los correos y las IPv4.
//!
//! El redactor vive en este crate (capa `es`) y no en el agente porque la puerta
//! `motores` exige que los crates de la capa de motores que el agente enlaza
//! DIRECTAMENTE solo se usen desde `src/motores/`: `aegis-captura` no se usa
//! aqui como motor, sino como la definicion unica de «credencial en claro», y
//! llega al agente por este crate, como ya llega `aegis-scan`.
//!
//! # Que no tapa (dicho, no escondido)
//!
//! Secretos con forma propia en una linea de ordenes (`-pSECRETO`), direcciones
//! IPv6 y nombres de OTROS equipos. Quien llama no debe copiar lineas de ordenes
//! enteras en lo que publica.

/// Largo maximo, en bytes, de cada texto redactado.
pub const MAX_TEXTO: usize = 400;
/// Largo maximo, en bytes, de lo que se llega a mirar de un texto de entrada.
const MAX_ENTRADA: usize = 4096;

/// El nombre de este equipo, de `/proc/sys/kernel/hostname`.
#[must_use]
pub fn nombre_del_host() -> Option<String> {
    let t = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    let t = t.trim().to_owned();
    (!t.is_empty()).then_some(t)
}

/// Texto que YA paso por la redaccion. Su unico constructor es
/// [`Redaccion::limpiar`]: no hay `From<String>` ni campo publico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Texto(String);

impl Texto {
    /// El texto, ya limpio.
    #[must_use]
    pub fn como_str(&self) -> &str {
        &self.0
    }
}

/// Lo que se tapo, por clase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cuentas {
    /// Credenciales en claro (redactor de `aegis-captura`).
    pub credenciales: u64,
    /// Rutas bajo `/home/<usuario>` o `/run/user/<uid>`.
    pub rutas_de_usuario: u64,
    /// Direcciones de correo.
    pub correos: u64,
    /// Direcciones IPv4 que no son de bucle local.
    pub direcciones: u64,
    /// Apariciones del nombre de este equipo.
    pub anfitrion: u64,
    /// Textos recortados por largo.
    pub recortes: u64,
}

/// Decide que se tapa de un texto antes de que llegue al informe.
#[derive(Debug, Clone)]
pub struct Redaccion {
    anfitrion: Option<String>,
    credenciales: aegis_captura::Redactor,
    cuentas: Cuentas,
}

impl Redaccion {
    /// Una redaccion que ademas tapa el nombre de equipo dado. Un nombre de
    /// menos de cuatro letras o `localhost` no se tapa: taparlo destrozaria
    /// el resto del texto sin proteger nada.
    #[must_use]
    pub fn nueva(anfitrion: Option<&str>) -> Redaccion {
        let anfitrion = anfitrion
            .map(str::trim)
            .filter(|a| a.len() >= 4 && *a != "localhost")
            .map(str::to_owned);
        Redaccion {
            anfitrion,
            credenciales: aegis_captura::Redactor::nuevo(),
            cuentas: Cuentas::default(),
        }
    }

    /// La redaccion de este equipo (su nombre sale de `/proc/sys/kernel/hostname`).
    #[must_use]
    pub fn del_host() -> Redaccion {
        Redaccion::nueva(nombre_del_host().as_deref())
    }

    /// Lo que se ha tapado hasta ahora.
    #[must_use]
    pub fn cuentas(&self) -> Cuentas {
        self.cuentas
    }

    /// Limpia un texto y lo cuenta. Es el UNICO constructor de [`Texto`].
    pub fn limpiar(&mut self, s: &str) -> Texto {
        let mut c = self.cuentas;
        let t = self.redactar(s, &mut c);
        self.cuentas = c;
        Texto(t)
    }

    /// La redaccion en si, sin construir un [`Texto`] y contando en `c`: para
    /// quien guarda texto ya limpio que redactara otra vez al publicarlo.
    #[must_use]
    pub fn redactar(&self, s: &str, c: &mut Cuentas) -> String {
        let mut t = recortar(s, MAX_ENTRADA, &mut c.recortes);
        if let Some(a) = &self.anfitrion {
            t = sin_caso(&t, a, "<anfitrion>", &mut c.anfitrion);
        }
        let limpio = self
            .credenciales
            .limpiar(t.as_bytes(), aegis_captura::Donde::default());
        if !limpio.intacto() {
            c.credenciales += limpio.tapados().len() as u64;
            t = String::from_utf8_lossy(limpio.bytes()).into_owned();
        }
        t = tapar_rutas_de_usuario(&t, &mut c.rutas_de_usuario);
        t = tapar_correos(&t, &mut c.correos);
        t = tapar_ipv4(&t, &mut c.direcciones);
        recortar(&t, MAX_TEXTO, &mut c.recortes)
    }
}

/// Sustituye `aguja` sin distinguir mayusculas ASCII. Pasar a minusculas ASCII
/// no cambia la posicion de ningun byte, asi que los indices valen en el original.
fn sin_caso(t: &str, aguja: &str, por: &str, n: &mut u64) -> String {
    let pajar = t.to_ascii_lowercase();
    let aguja = aguja.to_ascii_lowercase();
    if aguja.is_empty() {
        return t.to_owned();
    }
    let mut out = String::with_capacity(t.len());
    let mut copiado = 0;
    for (i, _) in pajar.match_indices(aguja.as_str()) {
        if i < copiado {
            continue;
        }
        out.push_str(&t[copiado..i]);
        out.push_str(por);
        copiado = i + aguja.len();
        *n += 1;
    }
    out.push_str(&t[copiado..]);
    out
}

/// Recorta a `max` bytes sin partir un caracter, y lo dice.
fn recortar(s: &str, max: usize, recortes: &mut u64) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut corte = max;
    while corte > 0 && !s.is_char_boundary(corte) {
        corte -= 1;
    }
    *recortes += 1;
    format!("{}…[recortado]", &s[..corte])
}

/// `/home/ana/x` -> `/home/<usuario>/x`; `/run/user/1000/y` -> `/run/user/<uid>/y`.
fn tapar_rutas_de_usuario(s: &str, n: &mut u64) -> String {
    const MARCAS: [(&str, &str); 2] = [("/home/", "<usuario>"), ("/run/user/", "<uid>")];
    let mut out = String::with_capacity(s.len());
    let mut resto = s;
    loop {
        let primera = MARCAS
            .iter()
            .filter_map(|(m, r)| resto.find(m).map(|i| (i, *m, *r)))
            .min_by_key(|(i, _, _)| *i);
        let Some((i, marca, relleno)) = primera else {
            out.push_str(resto);
            return out;
        };
        out.push_str(&resto[..i + marca.len()]);
        let tras = &resto[i + marca.len()..];
        let fin = tras
            .find(|c: char| {
                c == '/'
                    || c.is_whitespace()
                    || matches!(c, '"' | '\'' | '»' | '«' | ',' | ';' | ')' | ']' | ':')
            })
            .unwrap_or(tras.len());
        if fin > 0 && !tras.starts_with('<') {
            out.push_str(relleno);
            *n += 1;
        } else {
            out.push_str(&tras[..fin]);
        }
        resto = &tras[fin..];
    }
}

/// `nombre@dominio.tld` -> `<correo>`.
fn tapar_correos(s: &str, n: &mut u64) -> String {
    let b = s.as_bytes();
    let es = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-');
    let mut out = String::with_capacity(s.len());
    let mut copiado = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'@' {
            let mut ini = i;
            while ini > copiado && es(b[ini - 1]) {
                ini -= 1;
            }
            let mut fin = i + 1;
            while fin < b.len() && es(b[fin]) {
                fin += 1;
            }
            let dominio = &s[i + 1..fin];
            if ini < i && dominio.contains('.') && !dominio.starts_with('.') {
                out.push_str(&s[copiado..ini]);
                out.push_str("<correo>");
                copiado = fin;
                *n += 1;
                i = fin;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[copiado..]);
    out
}

/// Lee una IPv4 que empieza en `i`: devuelve donde acaba y sus octetos.
fn leer_ipv4(b: &[u8], inicio: usize) -> Option<(usize, [u8; 4])> {
    let mut i = inicio;
    let mut octetos = [0u8; 4];
    for (k, o) in octetos.iter_mut().enumerate() {
        let ini = i;
        let mut v: u32 = 0;
        while i < b.len() && b[i].is_ascii_digit() && i - ini < 3 {
            v = v * 10 + u32::from(b[i] - b'0');
            i += 1;
        }
        if i == ini {
            return None;
        }
        *o = u8::try_from(v).ok()?;
        if k < 3 {
            if i < b.len() && b[i] == b'.' {
                i += 1;
            } else {
                return None;
            }
        }
    }
    // Un cuarto octeto seguido de mas cifras o de «.cifra» no es una IPv4
    // (es una version de cinco piezas, o un numero largo).
    if i < b.len()
        && (b[i].is_ascii_digit() || (b[i] == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)))
    {
        return None;
    }
    Some((i, octetos))
}

/// IPv4 -> `<ip>`, salvo bucle local (127.0.0.0/8) y `0.0.0.0`.
fn tapar_ipv4(s: &str, n: &mut u64) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copiado = 0;
    let mut i = 0;
    while i < b.len() {
        let previo_libre = i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'.');
        if previo_libre && b[i].is_ascii_digit() {
            if let Some((fin, o)) = leer_ipv4(b, i) {
                if o[0] != 127 && o != [0, 0, 0, 0] {
                    out.push_str(&s[copiado..i]);
                    out.push_str("<ip>");
                    copiado = fin;
                    *n += 1;
                }
                i = fin;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[copiado..]);
    out
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn tapa_credenciales_con_el_redactor_de_captura() {
        let mut r = Redaccion::nueva(None);
        let t = r.limpiar("login con password=hunter2 y curl -H Authorization: Bearer abc.def");
        assert!(!t.como_str().contains("hunter2"), "{}", t.como_str());
        assert!(!t.como_str().contains("abc.def"), "{}", t.como_str());
        assert!(t.como_str().starts_with("login con password="));
        assert_eq!(r.cuentas().credenciales, 2);
    }

    #[test]
    fn tapa_equipo_rutas_correos_e_ipv4_y_lo_cuenta() {
        let mut r = Redaccion::nueva(Some("pc-contabilidad-07"));
        let t = r.limpiar(
            "PC-CONTABILIDAD-07 pc-contabilidad-07 /home/ana/x ana@empresa.es 192.168.1.20 127.0.0.1",
        );
        assert_eq!(
            t.como_str(),
            "<anfitrion> <anfitrion> /home/<usuario>/x <correo> <ip> 127.0.0.1",
            "el nombre se tapa sin distinguir mayusculas"
        );
        let c = r.cuentas();
        assert_eq!(
            (c.anfitrion, c.rutas_de_usuario, c.correos, c.direcciones),
            (2, 1, 1, 1)
        );
    }

    #[test]
    fn redactar_dos_veces_no_cambia_nada() {
        let mut r = Redaccion::nueva(Some("pc-contabilidad-07"));
        let una = r.limpiar("pc-contabilidad-07 /home/ana password=x 10.0.0.1");
        let dos = r.limpiar(una.como_str());
        assert_eq!(una, dos);
    }

    #[test]
    fn recorta_sin_partir_caracteres() {
        let mut r = Redaccion::nueva(None);
        let t = r.limpiar(&"ñ".repeat(3000));
        assert!(t.como_str().ends_with("…[recortado]"));
        assert!(t.como_str().len() <= MAX_TEXTO + "…[recortado]".len());
        assert_eq!(
            r.cuentas().recortes,
            2,
            "uno a la entrada y otro a la salida"
        );
    }

    #[test]
    fn redaccion_de_bordes() {
        let mut c = 0;
        assert_eq!(
            tapar_ipv4("v 6.8.0.1.2 y 1.2.3.4", &mut c),
            "v 6.8.0.1.2 y <ip>"
        );
        assert_eq!(c, 1);
        let mut c = 0;
        assert_eq!(
            tapar_ipv4("kernel 6.8.0-45 en 0.0.0.0", &mut c),
            "kernel 6.8.0-45 en 0.0.0.0"
        );
        assert_eq!(c, 0);
        let mut c = 0;
        assert_eq!(
            tapar_correos("root@localhost y @x.y y a@b.c", &mut c),
            "root@localhost y @x.y y <correo>"
        );
        let mut c = 0;
        assert_eq!(
            tapar_rutas_de_usuario("/home/ana /home/<usuario> /run/user/1000/bus", &mut c),
            "/home/<usuario> /home/<usuario> /run/user/<uid>/bus"
        );
        assert_eq!(c, 2, "lo ya tapado no se cuenta otra vez");
        let mut n = 0;
        let largo = "ñ".repeat(MAX_TEXTO);
        let r = recortar(&largo, MAX_TEXTO, &mut n);
        assert!(r.ends_with("…[recortado]") && n == 1);
        let mut r = Redaccion::nueva(Some("pc"));
        assert_eq!(
            r.limpiar("pc-x").como_str(),
            "pc-x",
            "nombres cortos no se tapan"
        );
    }
}
