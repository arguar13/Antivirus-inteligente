//! El informe de credenciales de AWS IAM como fuente de estado de claves.
//!
//! # Por que se acepta, siendo una instantanea
//!
//! Todo el crate reconstruye de eventos, y el muro de eso es la antiguedad de
//! las claves: una clave creada antes de la ventana no tiene evento de alta, y
//! su edad no se puede afirmar. El informe de credenciales
//! (`aws iam generate-credential-report` / `get-credential-report`) es un CSV
//! que AWS genera con `access_key_1_last_rotated` y `access_key_2_last_rotated`
//! de TODOS los usuarios: exactamente lo que el muro tapa.
//!
//! No rompe el principio de «sin credenciales de lectura en la nube»: el
//! producto no lo pide, lo ACEPTA si el cliente lo sube. Y se dice lo que es:
//! una foto del momento en que se genero, citada como tal en la evidencia
//! ([`Referencia::InformeCredenciales`](crate::modelo::Referencia)), no un
//! evento.
//!
//! # Entrada hostil
//!
//! El CSV lo sube alguien; se lee con tope de tamaño, de filas, de columnas y de
//! celda, sin reservar memoria por lo que diga ningun campo. Un nombre de
//! usuario de IAM admite comas (`+=,.@_-`), asi que las comillas de RFC 4180 se
//! interpretan de verdad y no con un `split(',')`.

use aegis_ingest::tiempo::desde_rfc3339;

/// Bytes maximos del informe. Diez mil usuarios con sus veintidos columnas
/// caben en unos 4 MiB.
pub const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Filas de datos maximas. Lo que excede se cuenta y se dice.
pub const MAX_FILAS: usize = 10_000;

/// Columnas maximas por fila. El formato actual tiene 22.
pub const MAX_COLUMNAS: usize = 64;

/// Bytes maximos de una celda.
pub const MAX_CELDA: usize = 2048;

/// Las columnas que hacen falta.
const COLUMNAS: [&str; 6] = [
    "user",
    "arn",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_2_active",
    "access_key_2_last_rotated",
];

/// Una clave de acceso segun el informe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaClave {
    /// Fila de datos, empezando en 1.
    pub fila: usize,
    /// Nombre del usuario (`<root_account>` para la raiz).
    pub usuario: String,
    /// ARN del usuario.
    pub arn: String,
    /// Ranura: 1 o 2.
    pub ranura: u8,
    /// Si esta activa.
    pub activa: bool,
    /// Ultima rotacion, si la columna trae una fecha legible.
    pub rotada_ns: Option<u64>,
    /// La celda tal como venia (`N/A`, una fecha, o algo ilegible).
    pub rotada_texto: String,
}

/// Un informe de credenciales leido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InformeCredenciales {
    /// Cuando lo genero AWS, en nanosegundos Unix (lo da quien lo sube: viene
    /// en la respuesta de `GetCredentialReport`, no en el CSV).
    pub generado_ns: u64,
    /// Las claves: dos ranuras por usuario.
    pub claves: Vec<FilaClave>,
    /// Filas que no se leyeron por exceder [`MAX_FILAS`] o por mal formadas.
    pub filas_descartadas: usize,
}

/// Por que no se pudo leer un informe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCredenciales {
    /// Mayor que [`MAX_BYTES`].
    Grande(usize),
    /// No es UTF-8.
    NoUtf8,
    /// No tiene cabecera.
    SinCabecera,
    /// Falta una columna necesaria.
    FaltaColumna(&'static str),
}

impl std::fmt::Display for ErrorCredenciales {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCredenciales::Grande(n) => {
                write!(f, "informe de {n} bytes, mayor que el tope de {MAX_BYTES}")
            }
            ErrorCredenciales::NoUtf8 => write!(f, "el informe no es UTF-8"),
            ErrorCredenciales::SinCabecera => write!(f, "el informe no tiene cabecera"),
            ErrorCredenciales::FaltaColumna(c) => write!(f, "falta la columna {c}"),
        }
    }
}

impl std::error::Error for ErrorCredenciales {}

/// Lee un informe de credenciales.
///
/// # Errors
///
/// Si supera el tope, no es UTF-8, no tiene cabecera o le falta alguna de las
/// columnas necesarias. Una fila mal formada no es un error: se descarta y se
/// cuenta.
pub fn leer(bytes: &[u8], generado_ns: u64) -> Result<InformeCredenciales, ErrorCredenciales> {
    if bytes.len() > MAX_BYTES {
        return Err(ErrorCredenciales::Grande(bytes.len()));
    }
    let texto = std::str::from_utf8(bytes).map_err(|_| ErrorCredenciales::NoUtf8)?;
    let texto = texto.strip_prefix('\u{feff}').unwrap_or(texto);
    let mut filas = Filas::nuevo(texto);
    let cabecera = filas.siguiente().ok_or(ErrorCredenciales::SinCabecera)?;
    let mut indices = [0usize; COLUMNAS.len()];
    for (i, c) in COLUMNAS.iter().enumerate() {
        indices[i] = cabecera
            .iter()
            .position(|h| h.trim() == *c)
            .ok_or(ErrorCredenciales::FaltaColumna(c))?;
    }
    let [i_user, i_arn, i_a1, i_r1, i_a2, i_r2] = indices;
    let mut claves = Vec::new();
    let mut descartadas = 0usize;
    let mut n = 0usize;
    while let Some(fila) = filas.siguiente() {
        if fila.len() == 1 && fila[0].is_empty() {
            continue;
        }
        n += 1;
        if n > MAX_FILAS {
            descartadas += 1;
            continue;
        }
        let celda = |i: usize| fila.get(i).map(String::as_str);
        let (Some(usuario), Some(arn)) = (celda(i_user), celda(i_arn)) else {
            descartadas += 1;
            continue;
        };
        for (ranura, ia, ir) in [(1u8, i_a1, i_r1), (2u8, i_a2, i_r2)] {
            let activa = celda(ia).is_some_and(|a| a.trim().eq_ignore_ascii_case("true"));
            let rotada_texto = celda(ir).unwrap_or("").trim().to_string();
            claves.push(FilaClave {
                fila: n,
                usuario: usuario.to_string(),
                arn: arn.to_string(),
                ranura,
                activa,
                rotada_ns: desde_rfc3339(&rotada_texto),
                rotada_texto,
            });
        }
    }
    Ok(InformeCredenciales {
        generado_ns,
        claves,
        filas_descartadas: descartadas,
    })
}

/// Lector de filas CSV (RFC 4180) con tope de columnas y de celda.
struct Filas<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Filas<'a> {
    fn nuevo(t: &'a str) -> Filas<'a> {
        Filas {
            b: t.as_bytes(),
            i: 0,
        }
    }

    fn siguiente(&mut self) -> Option<Vec<String>> {
        if self.i >= self.b.len() {
            return None;
        }
        let mut fila = Vec::new();
        let mut celda: Vec<u8> = Vec::new();
        let mut comillas = false;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if comillas {
                if c == b'"' {
                    if self.b.get(self.i) == Some(&b'"') {
                        self.i += 1;
                        empujar(&mut celda, b'"');
                    } else {
                        comillas = false;
                    }
                } else {
                    empujar(&mut celda, c);
                }
                continue;
            }
            match c {
                b'"' => comillas = true,
                b',' => cerrar(&mut fila, &mut celda),
                b'\n' => break,
                b'\r' => {}
                _ => empujar(&mut celda, c),
            }
        }
        cerrar(&mut fila, &mut celda);
        Some(fila)
    }
}

fn empujar(celda: &mut Vec<u8>, c: u8) {
    if celda.len() < MAX_CELDA {
        celda.push(c);
    }
}

fn cerrar(fila: &mut Vec<String>, celda: &mut Vec<u8>) {
    if fila.len() < MAX_COLUMNAS {
        // El recorte por bytes puede partir un caracter; se sustituye en vez
        // de fallar.
        fila.push(String::from_utf8_lossy(celda).into_owned());
    }
    celda.clear();
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// La cabecera real del informe (22 columnas), con dos filas de forma real.
    pub(crate) const INFORME: &str = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2019-01-10T08:00:00+00:00,not_supported,2026-09-01T10:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
\"ci,deploy\",arn:aws:iam::123456789012:user/ci-deploy,2021-03-02T09:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-11-20T12:00:00+00:00,2026-09-25T03:00:00+00:00,eu-west-1,s3,true,2026-09-01T12:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A
";

    #[test]
    fn el_informe_real_se_lee_con_sus_comillas() {
        let inf = leer(INFORME.as_bytes(), 1).unwrap();
        assert_eq!(inf.claves.len(), 4);
        let ci = &inf.claves[2];
        assert_eq!(
            ci.usuario, "ci,deploy",
            "la coma dentro de comillas es del nombre"
        );
        assert!(ci.activa);
        assert!(ci.rotada_ns.is_some());
        assert!(!inf.claves[0].activa);
        assert_eq!(inf.claves[0].rotada_texto, "N/A");
    }

    #[test]
    fn un_informe_sin_las_columnas_se_rechaza_con_nombre() {
        assert_eq!(
            leer(b"user,arn\nx,y\n", 1),
            Err(ErrorCredenciales::FaltaColumna("access_key_1_active"))
        );
        assert_eq!(leer(b"", 1), Err(ErrorCredenciales::SinCabecera));
    }

    #[test]
    fn un_informe_hostil_esta_acotado() {
        assert!(matches!(
            leer(&vec![b'a'; MAX_BYTES + 1], 1),
            Err(ErrorCredenciales::Grande(_))
        ));
        // Una celda gigante, miles de columnas y mas filas que el tope.
        let mut s = String::from(INFORME.lines().next().unwrap());
        s.push('\n');
        s.push_str(&"x".repeat(100_000));
        s.push_str(&",".repeat(10_000));
        s.push('\n');
        for _ in 0..(MAX_FILAS + 5) {
            s.push_str("u,a,,,,,,,true,N/A\n");
        }
        let inf = leer(s.as_bytes(), 1).unwrap();
        assert!(inf.filas_descartadas >= 5);
        assert!(inf.claves.len() <= 2 * MAX_FILAS);
        assert!(inf.claves.iter().all(|c| c.usuario.len() <= MAX_CELDA));
    }

    #[test]
    fn unas_comillas_sin_cerrar_no_cuelgan_el_lector() {
        let mut s = String::from(INFORME.lines().next().unwrap());
        s.push_str("\n\"sin cerrar,");
        s.push_str(&"y".repeat(10_000));
        let inf = leer(s.as_bytes(), 1).unwrap();
        assert!(inf.claves.len() <= 2);
    }
}
