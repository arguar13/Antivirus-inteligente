//! El observable, y lo que NUNCA puede salir de la organizacion.
//!
//! # La pregunta que este modulo contesta antes que ninguna otra
//!
//! No es «que se puede consultar», es **«que revela consultarlo»**.
//!
//! Consultar un resumen en un servicio publico le dice a ese servicio que ese
//! fichero esta en tu red. Es informacion que no tenia, se la das gratis, y no se
//! puede retirar. Para un resumen de una muestra de malware eso normalmente
//! compensa. Para el resumen de un documento interno, no: acabas de decirle a un
//! tercero que un fichero con ese contenido exacto existe en tu organizacion, y
//! quien ya tenga el documento puede confirmarlo comparando resumenes.
//!
//! # Lo que no sale nunca, y por que es una propiedad del TIPO
//!
//! Hay observables cuya consulta externa no tiene ningun valor y si un coste
//! directo:
//!
//! - Una direccion **privada** (RFC 1918, enlace local, carrier-grade NAT). El
//!   proveedor no sabe nada de tu `10.4.1.7`, asi que la respuesta es siempre
//!   «desconocido» — y a cambio le has dibujado tu plan de direccionamiento
//!   interno. Consultarla es coste sin beneficio, y se repite miles de veces al
//!   dia.
//! - Un **nombre de maquina interno** o un dominio de los reservados
//!   (`.local`, `.internal`, `.corp`, `.home.arpa`). Igual: revela tu
//!   nomenclatura, tus unidades de negocio y a menudo tu proveedor de directorio.
//! - Una **cuenta de usuario**. Es un dato personal, y en casi cualquier regimen
//!   de proteccion de datos sacarlo a un tercero necesita una base legal que un
//!   enriquecimiento automatico no tiene.
//! - Una **ruta de fichero**. Lleva el nombre del usuario, el del proyecto y a
//!   veces el del cliente.
//!
//! Podria comprobarse en cada analizador. No se hace: se comprueba **aqui**, una
//! vez, y [`Observable::puede_salir`] es la unica respuesta. Una regla de
//! privacidad repartida por veinte analizadores es una regla que un analizador
//! nuevo se salta sin que nadie lo note.

use std::fmt;

/// Algo concreto del mundo sobre lo que se puede preguntar.
///
/// Los tipos son los mismos que los de `aegis-case`, a proposito: un observable
/// de un caso se enriquece sin traducirlo, y dos taxonomias es la forma de que un
/// dia una ruta sea un `Ruta` en un sitio y un `Fichero` en otro.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Observable {
    /// Resumen criptografico de un fichero.
    Hash(String),
    /// Direccion IP.
    Ip(String),
    /// Nombre de dominio.
    Dominio(String),
    /// URL completa.
    Url(String),
    /// Ruta de un fichero en una maquina.
    Ruta(String),
    /// Cuenta de usuario.
    Usuario(String),
    /// Nombre de una maquina.
    Anfitrion(String),
    /// Linea de ordenes.
    Orden(String),
}

impl Observable {
    /// Tipo estable, para la cache, las cuotas y el informe.
    #[must_use]
    pub fn tipo(&self) -> Tipo {
        match self {
            Observable::Hash(_) => Tipo::Hash,
            Observable::Ip(_) => Tipo::Ip,
            Observable::Dominio(_) => Tipo::Dominio,
            Observable::Url(_) => Tipo::Url,
            Observable::Ruta(_) => Tipo::Ruta,
            Observable::Usuario(_) => Tipo::Usuario,
            Observable::Anfitrion(_) => Tipo::Anfitrion,
            Observable::Orden(_) => Tipo::Orden,
        }
    }

    /// El valor en crudo.
    #[must_use]
    pub fn valor(&self) -> &str {
        match self {
            Observable::Hash(v)
            | Observable::Ip(v)
            | Observable::Dominio(v)
            | Observable::Url(v)
            | Observable::Ruta(v)
            | Observable::Usuario(v)
            | Observable::Anfitrion(v)
            | Observable::Orden(v) => v,
        }
    }

    /// Si este observable puede salir de la organizacion, y si no, por que no.
    ///
    /// **Es la funcion mas importante del crate.** Se evalua una sola vez, en el
    /// orquestador, antes de entregar el observable a ningun analizador externo.
    ///
    /// Devuelve `Ok(())` si puede salir; `Err(motivo)` con un texto que va al
    /// informe y al panel, porque «no se consulto» sin motivo se lee igual que
    /// «se consulto y no habia nada».
    ///
    /// # Errors
    ///
    /// Devuelve el motivo por el que el observable no puede salir.
    pub fn puede_salir(&self) -> Result<(), MotivoRetencion> {
        match self {
            // Un dato personal no sale por un enriquecimiento automatico. No es
            // una politica configurable: es que la base legal para sacarlo no la
            // da un proceso que corre solo.
            Observable::Usuario(_) => Err(MotivoRetencion::DatoPersonal),
            // Una ruta lleva el nombre del usuario, el del proyecto y a veces el
            // del cliente. `C:\Users\maria.lopez\Proyecto Adquisicion Norte\...`
            // dice tres cosas confidenciales y no ayuda a decidir nada.
            Observable::Ruta(_) => Err(MotivoRetencion::RevelaInterno),
            // Una linea de ordenes lleva con frecuencia credenciales en claro.
            Observable::Orden(_) => Err(MotivoRetencion::PuedeLlevarSecretos),
            Observable::Anfitrion(v) | Observable::Dominio(v) => juzgar_anfitrion(v),
            Observable::Ip(v) => {
                if ip_no_enrutable(v) {
                    Err(MotivoRetencion::DireccionPrivada)
                } else {
                    Ok(())
                }
            }
            // Una URL lleva el anfitrion dentro, asi que hereda su regla — y
            // ademas puede llevar un identificador de sesion en la cadena de
            // consulta, que es una credencial.
            Observable::Url(v) => match anfitrion_de_url(v) {
                Some(h) => juzgar_anfitrion(&h),
                None => Ok(()),
            },
            Observable::Hash(_) => Ok(()),
        }
    }
}

impl fmt::Display for Observable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.tipo().nombre(), self.valor())
    }
}

/// Tipo de observable, sin el valor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tipo {
    /// Resumen de fichero.
    Hash,
    /// Direccion IP.
    Ip,
    /// Nombre de dominio.
    Dominio,
    /// URL.
    Url,
    /// Ruta de fichero.
    Ruta,
    /// Cuenta de usuario.
    Usuario,
    /// Nombre de maquina.
    Anfitrion,
    /// Linea de ordenes.
    Orden,
}

impl Tipo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Tipo::Hash => "hash",
            Tipo::Ip => "ip",
            Tipo::Dominio => "dominio",
            Tipo::Url => "url",
            Tipo::Ruta => "ruta",
            Tipo::Usuario => "usuario",
            Tipo::Anfitrion => "anfitrion",
            Tipo::Orden => "orden",
        }
    }

    /// Todos los tipos, para recorrerlos sin olvidar ninguno.
    #[must_use]
    pub fn todos() -> &'static [Tipo] {
        &[
            Tipo::Hash,
            Tipo::Ip,
            Tipo::Dominio,
            Tipo::Url,
            Tipo::Ruta,
            Tipo::Usuario,
            Tipo::Anfitrion,
            Tipo::Orden,
        ]
    }
}

/// Por que un observable no sale de la organizacion.
///
/// Va al informe. Un analizador que no se ejecuto tiene que decir **por que**, o
/// el analista lee «sin resultados» y entiende «limpio».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoRetencion {
    /// Es un dato personal.
    DatoPersonal,
    /// Revela nomenclatura o topologia interna.
    RevelaInterno,
    /// Una direccion que el proveedor no puede conocer.
    DireccionPrivada,
    /// Puede llevar credenciales en claro.
    PuedeLlevarSecretos,
}

impl MotivoRetencion {
    /// Explicacion para el panel, en una frase.
    #[must_use]
    pub fn texto(self) -> &'static str {
        match self {
            MotivoRetencion::DatoPersonal => {
                "es un dato personal: sacarlo a un tercero necesita una base legal que un \
                 enriquecimiento automatico no tiene"
            }
            MotivoRetencion::RevelaInterno => {
                "revela nomenclatura o topologia interna, y el proveedor no sabe nada de ella: \
                 coste sin beneficio"
            }
            MotivoRetencion::DireccionPrivada => {
                "es una direccion no enrutable: la respuesta seria «desconocido» siempre, y a \
                 cambio dibuja el direccionamiento interno"
            }
            MotivoRetencion::PuedeLlevarSecretos => {
                "puede llevar credenciales en claro, y una credencial enviada a un tercero esta \
                 comprometida aunque el tercero sea de fiar"
            }
        }
    }
}

/// Sufijos reservados para uso interno.
///
/// `.local` es mDNS; `.internal` y `.home.arpa` estan reservados por el IETF;
/// `.corp`, `.lan` y `.intranet` no existen en la raiz publica y se usan en media
/// industria. Consultarlos fuera no puede devolver nada util.
const SUFIJOS_INTERNOS: &[&str] = &[
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".corp",
    ".lan",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
];

/// Juzga un anfitrion, sea nombre o direccion literal.
///
/// # El orden importa, y el error que evita
///
/// Primero se decide **si es una direccion**, y solo despues se pregunta lo que
/// corresponda. Mezclar las dos preguntas produce dos fallos reales, y los dos son
/// silenciosos:
///
/// - `ip_no_enrutable` es conservador con lo que no entiende —lo que no parsea se
///   queda dentro—, que es correcto para algo que **dice ser** una IP y desastroso
///   como prueba de «¿esto es una IP?»: cualquier dominio publico la falla y deja
///   de consultarse, y nadie lo nota porque el sintoma es un enriquecimiento
///   silenciosamente pobre.
/// - `nombre_interno` trata «sin punto» como nombre de maquina corto, y un literal
///   IPv6 —`[fd00::1]`— no tiene puntos. Se clasificaria como nombre interno: se
///   queda dentro, que es lo correcto, pero **por el motivo equivocado**, y el
///   motivo es lo que lee el analista en el informe.
fn juzgar_anfitrion(h: &str) -> Result<(), MotivoRetencion> {
    if es_direccion(h) {
        return if ip_no_enrutable(h) {
            Err(MotivoRetencion::DireccionPrivada)
        } else {
            Ok(())
        };
    }
    if nombre_interno(h) {
        return Err(MotivoRetencion::RevelaInterno);
    }
    Ok(())
}

/// Si un anfitrion **pretende ser** una direccion literal y no un nombre.
///
/// Es deliberadamente generoso: `010.0.0.1` no es una IPv4 valida segun
/// [`ip_no_enrutable`] —el cero a la izquierda es ambiguo— pero es evidentemente
/// un intento de escribir una, y tratarla como nombre la dejaria salir.
#[must_use]
pub fn es_direccion(h: &str) -> bool {
    let t = h.trim();
    if t.is_empty() {
        return false;
    }
    // Un literal IPv6 va entre corchetes en una URL, y siempre lleva dos puntos.
    if t.starts_with('[') || t.contains(':') {
        return true;
    }
    // Solo digitos y puntos: es una IPv4 o un intento de serlo.
    t.contains('.') && t.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Si un nombre es interno y no debe consultarse fuera.
///
/// **Solo responde sobre nombres.** Una direccion literal no es un nombre, y
/// preguntarselo aqui da una respuesta sin sentido: ver [`juzgar_anfitrion`].
#[must_use]
pub fn nombre_interno(nombre: &str) -> bool {
    let n = nombre.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() {
        return true;
    }
    if es_direccion(&n) {
        return false;
    }
    if n == "localhost" {
        return true;
    }
    // Un nombre sin punto es un nombre de maquina corto —`dc-01`, `srv-nomina`—.
    // Nunca es un dominio publico, asi que consultarlo solo revela como se llaman
    // las maquinas de dentro.
    if !n.contains('.') {
        return true;
    }
    SUFIJOS_INTERNOS.iter().any(|s| n.ends_with(s))
}

/// Si una direccion IP no es enrutable en la Internet publica.
///
/// Cubre IPv4 e IPv6. Se escribe a mano y sin dependencias porque es una decision
/// de privacidad: tiene que poder leerse entera en una revision, y un crate de
/// terceros que un dia cambie de criterio cambiaria en silencio lo que sale de la
/// organizacion.
#[must_use]
pub fn ip_no_enrutable(dir: &str) -> bool {
    let d = dir.trim();
    if d.contains(':') {
        return ipv6_no_enrutable(d);
    }
    let Some(o) = octetos(d) else {
        // Lo que no es una IP valida no se manda fuera: si no se entiende, no se
        // puede razonar sobre lo que revela.
        return true;
    };
    match o {
        [0, ..] => true,                                 // «esta red»
        [10, ..] => true,                                // privada
        [100, b, ..] if (64..=127).contains(&b) => true, // CGNAT
        [127, ..] => true,                               // bucle local
        [169, 254, ..] => true,                          // enlace local
        [172, b, ..] if (16..=31).contains(&b) => true,  // privada
        [192, 0, 0, _] => true,                          // asignaciones de protocolo
        [192, 0, 2, _] => true,                          // documentacion
        [192, 168, ..] => true,                          // privada
        [198, 18 | 19, ..] => true,                      // pruebas de rendimiento
        [198, 51, 100, _] => true,                       // documentacion
        [203, 0, 113, _] => true,                        // documentacion
        [a, ..] if a >= 224 => true,                     // multidifusion y reservado
        _ => false,
    }
}

/// Los cuatro octetos de una IPv4, si la cadena lo es.
fn octetos(d: &str) -> Option<[u8; 4]> {
    let mut salida = [0u8; 4];
    let mut vistos = 0usize;
    for parte in d.split('.') {
        if vistos == 4 || parte.is_empty() || parte.len() > 3 {
            return None;
        }
        // Un cero a la izquierda se interpreta como octal en muchas bibliotecas y
        // como decimal en otras: `010.0.0.1` puede ser 8.0.0.1 o 10.0.0.1. La
        // ambiguedad se rechaza en vez de elegirse, porque elegir mal aqui saca
        // fuera una direccion privada.
        if parte.len() > 1 && parte.starts_with('0') {
            return None;
        }
        salida[vistos] = parte.parse().ok()?;
        vistos += 1;
    }
    (vistos == 4).then_some(salida)
}

/// Si una IPv6 no es enrutable.
fn ipv6_no_enrutable(d: &str) -> bool {
    let n = d.trim_start_matches('[').trim_end_matches(']');
    // Se recorta la zona (`%eth0`), que ya de por si es una marca de enlace local.
    let n = n.split('%').next().unwrap_or(n).to_ascii_lowercase();
    if n == "::1" || n == "::" {
        return true;
    }
    // `::ffff:10.0.0.1` es una IPv4 disfrazada, y es la forma clasica de colar una
    // direccion privada por una comprobacion que solo mira IPv6.
    if let Some(resto) = n.rsplit(':').next() {
        if resto.contains('.') && ip_no_enrutable(resto) {
            return true;
        }
    }
    n.starts_with("fe8")   // enlace local fe80::/10
        || n.starts_with("fe9")
        || n.starts_with("fea")
        || n.starts_with("feb")
        || n.starts_with("fc")  // unica local fc00::/7
        || n.starts_with("fd")
        || n.starts_with("ff")  // multidifusion
        || n.starts_with("2001:db8") // documentacion
}

/// El anfitrion de una URL, sin dependencias.
///
/// No valida la URL: extrae lo justo para decidir si sale o no. Un analizador que
/// necesite la URL entera la recibe entera; esto es solo la comprobacion de
/// privacidad, y para eso sobra con el anfitrion.
#[must_use]
pub fn anfitrion_de_url(url: &str) -> Option<String> {
    let sin_esquema = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    // Se quita la parte de credenciales (`usuario:clave@`) quedandose con lo que
    // hay tras la ULTIMA arroba: con la primera, un `http://a@b@interno/` se leeria
    // como anfitrion `b@interno` y la comprobacion de sufijo fallaria.
    let sin_credenciales = match sin_esquema.rfind('@') {
        Some(i) => &sin_esquema[i + 1..],
        None => sin_esquema,
    };
    let fin = sin_credenciales
        .find(['/', '?', '#'])
        .unwrap_or(sin_credenciales.len());
    let autoridad = &sin_credenciales[..fin];
    if autoridad.is_empty() {
        return None;
    }
    // IPv6 entre corchetes: `[::1]:8080`.
    if let Some(cierre) = autoridad.find(']') {
        return Some(autoridad[..=cierre].to_string());
    }
    let anfitrion = autoridad.split(':').next().unwrap_or(autoridad);
    (!anfitrion.is_empty()).then(|| anfitrion.to_string())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_resumen_sale_y_una_cuenta_no() {
        assert!(Observable::Hash("abc".into()).puede_salir().is_ok());
        assert_eq!(
            Observable::Usuario("maria.lopez".into()).puede_salir(),
            Err(MotivoRetencion::DatoPersonal)
        );
    }

    #[test]
    fn una_ruta_no_sale_porque_lleva_nombres_dentro() {
        // `C:\Users\maria.lopez\Adquisicion Norte\...` dice el nombre del usuario,
        // el del proyecto y a menudo el del cliente, y no ayuda a decidir nada.
        assert_eq!(
            Observable::Ruta("C:\\Users\\maria.lopez\\Adquisicion Norte\\plan.xlsx".into())
                .puede_salir(),
            Err(MotivoRetencion::RevelaInterno)
        );
    }

    #[test]
    fn una_orden_no_sale_porque_suele_llevar_credenciales() {
        assert_eq!(
            Observable::Orden("mysql -u root -pSecreta123".into()).puede_salir(),
            Err(MotivoRetencion::PuedeLlevarSecretos)
        );
    }

    #[test]
    fn las_direcciones_privadas_se_quedan_dentro() {
        for d in [
            "10.4.1.7",
            "192.168.0.1",
            "172.16.5.5",
            "172.31.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(ip_no_enrutable(d), "{d} deberia quedarse dentro");
        }
    }

    #[test]
    fn las_direcciones_publicas_salen() {
        for d in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
        ] {
            assert!(!ip_no_enrutable(d), "{d} deberia poder salir");
        }
    }

    #[test]
    fn una_ipv4_con_cero_a_la_izquierda_se_rechaza_en_vez_de_interpretarse() {
        // `010.0.0.1` es 8.0.0.1 leido como octal y 10.0.0.1 leido como decimal.
        // Elegir mal saca fuera una direccion privada, asi que no se elige: se
        // trata como no enrutable y se queda dentro.
        assert!(ip_no_enrutable("010.0.0.1"));
        assert!(ip_no_enrutable("0177.0.0.1"));
    }

    #[test]
    fn lo_que_no_es_una_ip_se_queda_dentro() {
        // Si no se entiende, no se puede razonar sobre lo que revela.
        assert!(ip_no_enrutable("8.8.8"));
        assert!(ip_no_enrutable("8.8.8.8.8"));
        assert!(ip_no_enrutable("ochenta"));
        assert!(ip_no_enrutable(""));
    }

    #[test]
    fn una_ipv4_disfrazada_de_ipv6_no_se_cuela() {
        // `::ffff:10.0.0.1` es la forma clasica de colar una direccion privada por
        // una comprobacion que solo mira el prefijo IPv6.
        assert!(ip_no_enrutable("::ffff:10.0.0.1"));
        assert!(ip_no_enrutable("::ffff:192.168.1.1"));
        assert!(!ip_no_enrutable("::ffff:8.8.8.8"));
    }

    #[test]
    fn las_ipv6_internas_se_quedan_dentro() {
        for d in [
            "::1",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(ip_no_enrutable(d), "{d} deberia quedarse dentro");
        }
        assert!(!ip_no_enrutable("2606:4700:4700::1111"));
    }

    #[test]
    fn los_nombres_internos_se_quedan_dentro() {
        for n in [
            "dc-01",
            "dc-01.corp.local",
            "nomina.internal",
            "algo.lan",
            "localhost",
            "x.home.arpa",
            "",
        ] {
            assert!(nombre_interno(n), "{n} deberia quedarse dentro");
        }
        assert!(!nombre_interno("evil.example.com."));
        assert!(!nombre_interno("cdn.cloudflare.net"));
    }

    #[test]
    fn un_nombre_de_maquina_corto_nunca_sale() {
        // Sin punto no es un dominio publico: consultarlo solo revela como se
        // llaman las maquinas de dentro, y la respuesta es siempre «desconocido».
        assert_eq!(
            Observable::Anfitrion("srv-nomina".into()).puede_salir(),
            Err(MotivoRetencion::RevelaInterno)
        );
        assert!(Observable::Anfitrion("evil.example.com".into())
            .puede_salir()
            .is_ok());
    }

    #[test]
    fn un_dominio_publico_no_se_confunde_con_una_ip_que_no_parsea() {
        // El fallo que esto fija: `ip_no_enrutable` deja dentro lo que no entiende
        // —correcto para algo que DICE ser una IP— y usarlo como prueba de «¿esto
        // es una IP?» hace que TODO dominio publico la falle y deje de
        // consultarse. El sintoma seria un enriquecimiento silenciosamente pobre,
        // que es de los que no se notan nunca.
        for d in [
            "evil.example.com",
            "cdn.cloudflare.net",
            "micorreo.es",
            "xn--80ak6aa92e.com",
        ] {
            assert!(!es_direccion(d), "{d} no es una direccion");
            assert!(
                Observable::Dominio(d.into()).puede_salir().is_ok(),
                "{d} deberia poder consultarse"
            );
            assert!(Observable::Url(format!("https://{d}/a"))
                .puede_salir()
                .is_ok());
        }
    }

    #[test]
    fn una_direccion_se_reconoce_aunque_este_mal_escrita() {
        // `010.0.0.1` no es una IPv4 valida —el cero a la izquierda es ambiguo—
        // pero es evidentemente un intento de escribir una, y tratarla como nombre
        // la dejaria salir.
        assert!(es_direccion("010.0.0.1"));
        assert!(es_direccion("[fd00::1]"));
        assert!(es_direccion("fe80::1"));
        assert!(es_direccion("1.2.3.4"));
        assert!(!es_direccion("servidor1"));
        assert!(!es_direccion(""));
        assert_eq!(
            Observable::Anfitrion("010.0.0.1".into()).puede_salir(),
            Err(MotivoRetencion::DireccionPrivada)
        );
    }

    #[test]
    fn una_ip_literal_no_es_un_nombre_interno() {
        // Se queda dentro igual, pero con el MOTIVO correcto: el motivo es lo que
        // lee el analista en el informe.
        assert!(!nombre_interno("[fd00::1]"));
        assert!(!nombre_interno("10.0.0.1"));
        assert_eq!(
            Observable::Anfitrion("10.0.0.1".into()).puede_salir(),
            Err(MotivoRetencion::DireccionPrivada)
        );
    }

    #[test]
    fn una_url_hereda_la_regla_de_su_anfitrion() {
        assert_eq!(
            Observable::Url("https://intranet.corp/nominas?id=3".into()).puede_salir(),
            Err(MotivoRetencion::RevelaInterno)
        );
        assert_eq!(
            Observable::Url("http://10.4.1.7:8080/x".into()).puede_salir(),
            Err(MotivoRetencion::DireccionPrivada)
        );
        assert!(Observable::Url("https://evil.example.com/a.exe".into())
            .puede_salir()
            .is_ok());
    }

    #[test]
    fn la_arroba_no_sirve_para_disfrazar_un_anfitrion_interno() {
        // Con la PRIMERA arroba, `http://a@b@intranet.corp/` daria anfitrion
        // «b@intranet.corp», el sufijo no casaria y saldria fuera. Con la ultima,
        // da «intranet.corp» y se queda dentro, que es lo correcto y ademas lo que
        // hace un navegador.
        assert_eq!(
            anfitrion_de_url("http://a@b@intranet.corp/x").as_deref(),
            Some("intranet.corp")
        );
        assert_eq!(
            Observable::Url("http://a@b@intranet.corp/x".into()).puede_salir(),
            Err(MotivoRetencion::RevelaInterno)
        );
    }

    #[test]
    fn el_anfitrion_de_una_url_se_extrae_con_sus_formas_raras() {
        assert_eq!(
            anfitrion_de_url("https://ejemplo.com:443/a?b#c").as_deref(),
            Some("ejemplo.com")
        );
        assert_eq!(
            anfitrion_de_url("http://[2001:db8::1]:8080/x").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            anfitrion_de_url("ejemplo.com/x").as_deref(),
            Some("ejemplo.com")
        );
        assert_eq!(anfitrion_de_url("https:///solo-ruta"), None);
    }

    #[test]
    fn una_url_con_ipv6_interna_entre_corchetes_no_sale() {
        assert_eq!(
            Observable::Url("http://[fd00::1]/panel".into()).puede_salir(),
            Err(MotivoRetencion::DireccionPrivada)
        );
    }

    #[test]
    fn cada_tipo_tiene_nombre_y_estan_todos() {
        assert_eq!(Tipo::todos().len(), 8);
        let mut nombres: Vec<&str> = Tipo::todos().iter().map(|t| t.nombre()).collect();
        nombres.sort_unstable();
        nombres.dedup();
        assert_eq!(nombres.len(), 8, "dos tipos comparten nombre");
    }

    #[test]
    fn todo_motivo_de_retencion_explica_por_que() {
        for m in [
            MotivoRetencion::DatoPersonal,
            MotivoRetencion::RevelaInterno,
            MotivoRetencion::DireccionPrivada,
            MotivoRetencion::PuedeLlevarSecretos,
        ] {
            // «No se consultó» sin motivo se lee igual que «se consultó y no habia
            // nada», y esa confusion es exactamente lo que hace inutil un informe.
            assert!(m.texto().len() > 40, "{m:?} no explica nada");
        }
    }
}
