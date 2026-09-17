//! Valores concretos leidos del endpoint, y su comparacion.
//!
//! POR QUE ESTE MODULO VIVE EN EL LENGUAJE Y NO EN EL EJECUTOR
//! ----------------------------------------------------------
//! Hasta la FASE 81 vivia en `aegis-hunt`, junto al unico codigo que producia
//! valores. Desde la FASE 81 los produce `aegis-estado`, que son sesenta y cinco
//! proveedores de tabla, y `aegis-hunt` pasa a ser su consumidor. Si el tipo se
//! hubiera quedado donde estaba, el proveedor tendria que depender del ejecutor
//! que lo llama, que es la dependencia al reves.
//!
//! Colocarlo aqui no cuesta nada: `Valor` es el otro lado de [`Literal`], no
//! tiene dependencias y no toca el sistema. `aegis-hunt` lo reexporta, de modo
//! que `aegis_hunt::valor::Valor` sigue siendo el mismo tipo de siempre.
//!
//! LA DECISION QUE GOBIERNA ESTE MODULO
//! ------------------------------------
//! Un dato del sistema puede no estar disponible: el ejecutable de un proceso
//! de otro usuario, la memoria de un proceso protegido, un fichero borrado
//! mientras se leia. La pregunta es que hace el filtro con esos casos, y hay
//! dos respuestas posibles:
//!
//!   a) Logica de tres valores (como el NULL de SQL), donde `x = 1` puede ser
//!      cierto, falso o desconocido.
//!   b) Dos valores, donde un dato ausente simplemente NO CASA.
//!
//! AegisCore elige (b), y no por comodidad. Con tres valores, `NOT (x = 1)` no
//! es lo contrario de `x = 1`, y un analista que escribe `NOT path LIKE
//! '/usr/%'` para buscar binarios fuera del sistema dejaria de ver, sin
//! enterarse, todos los procesos cuya ruta no se pudo leer —que son justo los
//! que mas le interesan—. Con dos valores la respuesta es siempre completa y
//! explicable: lo que no se pudo leer, no casa.
//!
//! El coste de esa eleccion es real y se asume: un dato ausente es
//! indistinguible de uno que no cumple. Por eso el ejecutor cuenta aparte
//! cuantos valores no pudo obtener y lo devuelve con el resultado, para que el
//! analista sepa si su caceria vio toda la maquina o solo una parte. Desde la
//! FASE 81 hay ademas un segundo nivel de honestidad: cuando lo que falla no es
//! un valor suelto sino la tabla entera, el proveedor devuelve el MOTIVO por el
//! que no se pudo leer. Ver `aegis_estado::MotivoNoLeible`.

use crate::ast::{Comparador, Literal};

/// Un dato leido del endpoint.
#[derive(Debug, Clone, PartialEq)]
pub enum Valor {
    /// Entero con signo.
    Entero(i64),
    /// Real de doble precision.
    Real(f64),
    /// Texto.
    Texto(String),
    /// Booleano.
    Booleano(bool),
    /// No se pudo obtener. Ver la nota de cabecera.
    Ausente,
}

impl Valor {
    /// Indica si el valor no se pudo obtener.
    pub fn es_ausente(&self) -> bool {
        matches!(self, Valor::Ausente)
    }

    /// Representacion textual para el informe que vuelve al plano de control.
    pub fn a_texto(&self) -> String {
        match self {
            Valor::Entero(n) => n.to_string(),
            // Se limita la precision: un f64 completo son diecisiete digitos
            // que nadie lee, multiplicados por cada fila de cada endpoint.
            Valor::Real(x) => format!("{x:.4}"),
            Valor::Texto(s) => s.clone(),
            Valor::Booleano(b) => b.to_string(),
            Valor::Ausente => String::new(),
        }
    }

    /// Compara este valor con un literal de la consulta.
    ///
    /// Un valor ausente devuelve siempre `false`, sea cual sea el comparador.
    pub fn compara(&self, op: Comparador, lit: &Literal) -> bool {
        let Some(orden) = self.orden_contra(lit) else {
            return false;
        };
        match op {
            Comparador::Igual => orden == std::cmp::Ordering::Equal,
            Comparador::Distinto => orden != std::cmp::Ordering::Equal,
            Comparador::Menor => orden == std::cmp::Ordering::Less,
            Comparador::MenorIgual => orden != std::cmp::Ordering::Greater,
            Comparador::Mayor => orden == std::cmp::Ordering::Greater,
            Comparador::MayorIgual => orden != std::cmp::Ordering::Less,
        }
    }

    /// Orden entre este valor y un literal, o `None` si no son comparables.
    fn orden_contra(&self, lit: &Literal) -> Option<std::cmp::Ordering> {
        match (self, lit) {
            (Valor::Entero(a), Literal::Entero(b)) => Some(a.cmp(b)),
            (Valor::Texto(a), Literal::Texto(b)) => Some(a.as_str().cmp(b.as_str())),
            (Valor::Booleano(a), Literal::Booleano(b)) => Some(a.cmp(b)),

            // Mezcla de entero y real. Se compara en f64 y se trata NaN como
            // "no comparable": un NaN que se cuela por una lectura corrupta no
            // puede hacer que un `>` y un `<=` sean ambos ciertos.
            (Valor::Real(a), Literal::Real(b)) => a.partial_cmp(b),
            (Valor::Real(a), Literal::Entero(b)) => a.partial_cmp(&(*b as f64)),
            (Valor::Entero(a), Literal::Real(b)) => (*a as f64).partial_cmp(b),

            _ => None,
        }
    }

    /// Comparacion de texto con comodines `%` (cualquier cosa) y `_` (un
    /// caracter). Devuelve `false` si el valor no es texto o esta ausente.
    pub fn casa_patron(&self, patron: &str) -> bool {
        match self {
            Valor::Texto(s) => casa(s, patron),
            _ => false,
        }
    }
}

/// Comparacion con comodines, iterativa y con retroceso acotado.
///
/// POR QUE NO ES RECURSIVA
/// -----------------------
/// La implementacion recursiva evidente de `%` tiene coste exponencial ante
/// patrones como `%a%a%a%a%a%a%b` sobre una cadena de aes: es el ataque clasico
/// de retroceso catastrofico, y aqui el patron lo escribe un operador remoto y
/// se ejecuta contra la linea de comandos de cada proceso de cada endpoint.
///
/// Este algoritmo recuerda la ultima posicion en la que hubo un `%` y retrocede
/// a ella, lo que da coste O(n*m) en el peor caso y O(n+m) en el habitual, sin
/// consumir pila.
fn casa(texto: &str, patron: &str) -> bool {
    let t: Vec<char> = texto.chars().collect();
    let p: Vec<char> = patron.chars().collect();

    let (mut i, mut j) = (0usize, 0usize);
    // Posicion del ultimo `%` visto y donde estaba el texto entonces.
    let mut comodin: Option<(usize, usize)> = None;

    while i < t.len() {
        if j < p.len() && (p[j] == '_' || p[j] == t[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '%' {
            comodin = Some((j, i));
            j += 1;
        } else if let Some((pj, ti)) = comodin {
            // Retroceso: el ultimo `%` se come un caracter mas.
            j = pj + 1;
            i = ti + 1;
            comodin = Some((pj, i));
        } else {
            return false;
        }
    }
    // Los `%` que sobren al final casan con la cadena vacia.
    while j < p.len() && p[j] == '%' {
        j += 1;
    }
    j == p.len()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_valor_ausente_no_casa_con_nada() {
        // Ni con `=`, ni con `!=`. Es la propiedad que hace que el filtro tenga
        // dos valores y no tres.
        let a = Valor::Ausente;
        assert!(!a.compara(Comparador::Igual, &Literal::Entero(0)));
        assert!(!a.compara(Comparador::Distinto, &Literal::Entero(0)));
        assert!(!a.compara(Comparador::Mayor, &Literal::Entero(0)));
        assert!(!a.casa_patron("%"));
    }

    #[test]
    fn entero_y_real_se_comparan_entre_si() {
        assert!(Valor::Real(7.5).compara(Comparador::Mayor, &Literal::Entero(7)));
        assert!(Valor::Entero(7).compara(Comparador::Menor, &Literal::Real(7.5)));
    }

    #[test]
    fn un_nan_no_es_mayor_ni_menor_ni_igual() {
        // Si NaN se colara como "siempre falso" en un lado y "siempre cierto"
        // en el otro, `x > 7` y `x <= 7` podrian ser ambos ciertos y el filtro
        // dejaria de ser una particion.
        let n = Valor::Real(f64::NAN);
        assert!(!n.compara(Comparador::Mayor, &Literal::Real(7.0)));
        assert!(!n.compara(Comparador::MenorIgual, &Literal::Real(7.0)));
        assert!(!n.compara(Comparador::Igual, &Literal::Real(f64::NAN)));
    }

    #[test]
    fn tipos_incompatibles_no_casan() {
        assert!(!Valor::Texto("7".into()).compara(Comparador::Igual, &Literal::Entero(7)));
    }

    #[test]
    fn los_comodines_funcionan_como_en_sql() {
        assert!(casa("/usr/bin/curl", "/usr/%"));
        assert!(casa("/usr/bin/curl", "%curl"));
        assert!(casa("/usr/bin/curl", "%bin%"));
        assert!(casa("curl", "____"));
        assert!(casa("curl", "%"));
        assert!(casa("", "%"));
        assert!(casa("", ""));

        assert!(!casa("/usr/bin/curl", "/etc/%"));
        assert!(!casa("curl", "___"));
        assert!(!casa("", "_"));
        assert!(!casa("abc", "abcd"));
    }

    #[test]
    fn varios_comodines_seguidos_se_comportan_como_uno() {
        assert!(casa("abc", "%%%"));
        assert!(casa("abc", "a%%c"));
    }

    #[test]
    fn el_patron_patologico_no_tarda_una_eternidad() {
        // Retroceso catastrofico: la version recursiva ingenua no termina.
        // El patron lo escribe un operador remoto, asi que esto es una via de
        // denegacion de servicio contra cada endpoint de la flota.
        let texto = "a".repeat(64);
        let patron = format!("{}b", "%a".repeat(24));
        let inicio = std::time::Instant::now();
        assert!(!casa(&texto, &patron));
        assert!(
            inicio.elapsed().as_millis() < 200,
            "tardo {:?}: hay retroceso catastrofico",
            inicio.elapsed()
        );
    }

    #[test]
    fn el_texto_multibyte_se_compara_por_caracteres() {
        // `_` casa UN caracter, no un byte: si contara bytes, una ruta con
        // acentos daria resultados distintos segun la codificacion.
        assert!(casa("año", "a_o"));
        assert!(!casa("año", "a__o"));
    }

    #[test]
    fn el_real_se_recorta_al_convertirlo_a_texto() {
        assert_eq!(Valor::Real(7.987654321).a_texto(), "7.9877");
    }
}
