//! Privacidad OBLIGATORIA en el tipo: la redaccion no es opcional (FASE 107).
//!
//! Lo que se captura en claro es lo mas sensible del sistema: contrasenas, tokens,
//! cookies de sesion, datos personales. Un cazador de TLS en claro que guarde eso
//! sin redactar es, el mismo, la mayor fuga de la maquina. Por eso aqui la
//! redaccion es parte del TIPO: la unica forma de obtener una [`CapturaEnClaro`] es
//! aplicando una [`PoliticaRedaccion`], y el tipo **no expone** el texto sin
//! redactar —no hay un `bruto()` que llamar—. Y la difusion pasa por el
//! estrangulamiento de la FASE 78: hay un presupuesto de cuanto puede salir, y
//! excederlo para.

/// Una clase de secreto que se redacta siempre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaseSecreto {
    /// Cabecera `Authorization` (Bearer, Basic...).
    Autorizacion,
    /// Cabeceras `Cookie` / `Set-Cookie`.
    Cookie,
    /// Un campo de contrasena (`password=`, `passwd=`, `pwd=`).
    Contrasena,
    /// Un token o clave de API en un parametro (`token=`, `api_key=`, `secret=`).
    Token,
}

impl ClaseSecreto {
    /// Todas las clases: la redaccion por defecto las cubre TODAS.
    #[must_use]
    pub fn todas() -> [ClaseSecreto; 4] {
        [
            ClaseSecreto::Autorizacion,
            ClaseSecreto::Cookie,
            ClaseSecreto::Contrasena,
            ClaseSecreto::Token,
        ]
    }
}

/// La marca que sustituye a un secreto redactado.
const MARCA: &str = "«REDACTADO»";

/// La politica de redaccion. Por defecto redacta TODAS las clases de secreto:
/// olvidarse de una es como se filtra justo la que importaba.
#[derive(Debug, Clone)]
pub struct PoliticaRedaccion {
    clases: Vec<ClaseSecreto>,
}

impl Default for PoliticaRedaccion {
    fn default() -> PoliticaRedaccion {
        PoliticaRedaccion {
            clases: ClaseSecreto::todas().to_vec(),
        }
    }
}

impl PoliticaRedaccion {
    /// La politica estricta por defecto: redacta todo lo sensible.
    #[must_use]
    pub fn estricta() -> PoliticaRedaccion {
        PoliticaRedaccion::default()
    }

    fn redacta(&self, clase: ClaseSecreto) -> bool {
        self.clases.contains(&clase)
    }

    /// Aplica la redaccion a un texto en claro. Sustituye el VALOR de cada secreto
    /// por la marca, conservando la estructura (para que el analista vea que habia
    /// una cabecera `Authorization`, pero no su contenido).
    #[must_use]
    fn aplicar(&self, bruto: &str) -> String {
        let mut salida = Vec::new();
        for linea in bruto.lines() {
            salida.push(self.redactar_linea(linea));
        }
        salida.join("\n")
    }

    fn redactar_linea(&self, linea: &str) -> String {
        let bajo = linea.to_ascii_lowercase();
        // Cabeceras: se redacta desde los dos puntos.
        if self.redacta(ClaseSecreto::Autorizacion) && bajo.starts_with("authorization:") {
            return format!("Authorization: {MARCA}");
        }
        if self.redacta(ClaseSecreto::Cookie)
            && (bajo.starts_with("cookie:") || bajo.starts_with("set-cookie:"))
        {
            let etiqueta = &linea[..linea.find(':').unwrap_or(0)];
            return format!("{etiqueta}: {MARCA}");
        }
        // Parametros clave=valor en cuerpos o URLs.
        let mut l = linea.to_string();
        if self.redacta(ClaseSecreto::Contrasena) {
            l = redactar_parametros(&l, &["password", "passwd", "pwd"]);
        }
        if self.redacta(ClaseSecreto::Token) {
            l = redactar_parametros(
                &l,
                &["token", "api_key", "apikey", "secret", "access_token"],
            );
        }
        l
    }
}

/// Redacta el valor de `clave=valor` para cada clave dada (sin distinguir mayus).
///
/// El cursor avanza SIEMPRE mas alla de la marca insertada, asi que un `clave=` no
/// se vuelve a encontrar en el mismo sitio: la busqueda termina siempre.
fn redactar_parametros(linea: &str, claves: &[&str]) -> String {
    let mut resultado = linea.to_string();
    for clave in claves {
        let patron = format!("{clave}=");
        let mut desde = 0usize;
        while desde <= resultado.len() {
            let bajo = resultado.to_ascii_lowercase();
            let Some(rel) = bajo[desde..].find(&patron) else {
                break;
            };
            let inicio_valor = desde + rel + patron.len();
            // El valor va hasta el proximo separador (&, ;, espacio) o el final.
            let fin = resultado[inicio_valor..]
                .find(['&', ';', ' ', '\t'])
                .map_or(resultado.len(), |o| inicio_valor + o);
            resultado.replace_range(inicio_valor..fin, MARCA);
            // Avanzar PASADA la marca: nunca se re-encuentra el mismo `clave=`.
            desde = inicio_valor + MARCA.len();
        }
    }
    resultado
}

/// Una captura de trafico en claro. Su UNICO constructor aplica la redaccion; el
/// tipo no expone el texto sin redactar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturaEnClaro {
    redactado: String,
}

impl CapturaEnClaro {
    /// Captura texto en claro aplicando la politica de redaccion. No hay otra via:
    /// no existe un constructor que deje el texto sin redactar.
    #[must_use]
    pub fn capturar(bruto: &str, politica: &PoliticaRedaccion) -> CapturaEnClaro {
        CapturaEnClaro {
            redactado: politica.aplicar(bruto),
        }
    }

    /// El texto YA redactado. Es lo unico que se puede leer.
    #[must_use]
    pub fn texto_redactado(&self) -> &str {
        &self.redactado
    }

    /// El tamano del texto redactado, para el presupuesto de difusion.
    #[must_use]
    pub fn tam(&self) -> usize {
        self.redactado.len()
    }
}

/// El presupuesto de difusion (estrangulamiento de la FASE 78): cuanto texto en
/// claro puede salir hacia fuera. Excederlo para: una fuga con interfaz bonita
/// sigue siendo una fuga.
#[derive(Debug, Clone)]
pub struct PresupuestoDifusion {
    max_bytes: usize,
    gastado: usize,
}

impl PresupuestoDifusion {
    /// Un presupuesto con su tope.
    #[must_use]
    pub fn nuevo(max_bytes: usize) -> PresupuestoDifusion {
        PresupuestoDifusion {
            max_bytes,
            gastado: 0,
        }
    }

    /// Intenta difundir una captura. Devuelve `true` si cabe en el presupuesto y lo
    /// consume; `false` si excederia el tope (y no difunde).
    pub fn intentar_difundir(&mut self, captura: &CapturaEnClaro) -> bool {
        let nuevo = self.gastado.saturating_add(captura.tam());
        if nuevo > self.max_bytes {
            return false;
        }
        self.gastado = nuevo;
        true
    }

    /// Cuanto se ha difundido ya.
    #[must_use]
    pub fn gastado(&self) -> usize {
        self.gastado
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_contrasena_y_el_token_se_redactan() {
        let bruto = "POST /login\r\nuser=alice&password=s3cr3t&token=abc123def";
        let c = CapturaEnClaro::capturar(bruto, &PoliticaRedaccion::estricta());
        let t = c.texto_redactado();
        assert!(!t.contains("s3cr3t"), "la contrasena no puede quedar: {t}");
        assert!(!t.contains("abc123def"), "el token no puede quedar: {t}");
        assert!(t.contains("user=alice"), "lo no sensible se conserva: {t}");
        assert!(t.contains(MARCA));
    }

    #[test]
    fn las_cabeceras_de_autorizacion_y_cookie_se_redactan() {
        let bruto = "GET /\r\nAuthorization: Bearer eyJhbGc.secreto\r\nCookie: sid=abc; t=xyz";
        let c = CapturaEnClaro::capturar(bruto, &PoliticaRedaccion::estricta());
        let t = c.texto_redactado();
        assert!(!t.contains("eyJhbGc.secreto"), "{t}");
        assert!(!t.contains("sid=abc"), "{t}");
        // Pero se ve que HABIA una cabecera Authorization (estructura conservada).
        assert!(t.contains("Authorization:"), "{t}");
        assert!(t.contains("Cookie:"), "{t}");
    }

    #[test]
    fn no_hay_forma_de_leer_el_texto_sin_redactar() {
        // El tipo solo expone `texto_redactado()`. Esta prueba lo documenta: si
        // alguien anadiera un `bruto()`, tendria que cambiar el tipo a proposito.
        let c = CapturaEnClaro::capturar("password=hunter2", &PoliticaRedaccion::estricta());
        assert!(!c.texto_redactado().contains("hunter2"));
    }

    #[test]
    fn la_difusion_no_puede_exceder_el_presupuesto() {
        let mut p = PresupuestoDifusion::nuevo(20);
        let c = CapturaEnClaro::capturar("user=alice", &PoliticaRedaccion::estricta());
        assert!(p.intentar_difundir(&c), "cabe la primera");
        assert!(p.intentar_difundir(&c), "cabe la segunda (20 bytes)");
        // La tercera excederia: no difunde.
        assert!(!p.intentar_difundir(&c), "excede el tope: no sale");
        assert!(p.gastado() <= 20);
    }
}
