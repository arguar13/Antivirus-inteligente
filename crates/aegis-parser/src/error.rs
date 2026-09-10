//! Errores de AegisQL, con la posicion exacta dentro de la consulta.
//!
//! POR QUE ESTO MERECE UN MODULO PROPIO
//! ------------------------------------
//! Quien escribe una consulta de caza suele estar en mitad de un incidente, a
//! deshoras y con prisa. Un "error de sintaxis" a secas le obliga a releer su
//! propia consulta letra a letra; un error que le senala la columna y le
//! propone la correccion le devuelve al incidente en segundos.
//!
//! Ademas, estos mensajes viajan a la consola de un cliente: no pueden filtrar
//! rutas internas, ni nombres de fichero del servidor, ni nada que no sea la
//! consulta que el propio operador escribio.

use std::fmt;

/// Que fue mal, y donde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorConsulta {
    /// Descripcion legible del problema.
    pub mensaje: String,
    /// Desplazamiento en bytes donde empieza el tramo culpable.
    pub inicio: usize,
    /// Desplazamiento en bytes donde termina (exclusivo).
    pub fin: usize,
    /// Correccion propuesta, si la hay.
    pub sugerencia: Option<String>,
}

impl ErrorConsulta {
    /// Error sin sugerencia.
    pub fn nuevo(mensaje: impl Into<String>, inicio: usize, fin: usize) -> ErrorConsulta {
        ErrorConsulta {
            mensaje: mensaje.into(),
            inicio,
            fin,
            sugerencia: None,
        }
    }

    /// Anade una correccion propuesta.
    pub fn con_sugerencia(mut self, s: impl Into<String>) -> ErrorConsulta {
        self.sugerencia = Some(s.into());
        self
    }

    /// Dibuja el error debajo de la consulta, con un subrayado.
    ///
    /// La consulta se recorta a la LINEA del error: una consulta larga pegada
    /// entera en un mensaje de error entierra el dato util.
    ///
    /// El subrayado se calcula en CARACTERES y no en bytes, porque las
    /// posiciones vienen en bytes y una ruta con acentos o un nombre de proceso
    /// en otro alfabeto desplazaria el acento respecto del texto.
    pub fn dibujar(&self, consulta: &str) -> String {
        let (linea, inicio_linea, numero) = self.linea_de(consulta);

        // Se acota a la longitud de la linea: una posicion fuera de rango es un
        // error de quien construyo el ErrorConsulta, y no debe convertirse en
        // un panico dentro del manejador de errores.
        let rel_inicio = self.inicio.saturating_sub(inicio_linea).min(linea.len());
        let rel_fin = self.fin.saturating_sub(inicio_linea).min(linea.len());

        let sangria = linea[..rel_inicio].chars().count();
        let ancho = linea[rel_inicio..rel_fin].chars().count().max(1);

        let mut s = String::new();
        s.push_str(&format!("error: {}\n", self.mensaje));
        s.push_str(&format!("  {numero} | {linea}\n"));
        s.push_str(&format!(
            "  {} | {}{}\n",
            " ".repeat(numero.to_string().len()),
            " ".repeat(sangria),
            "^".repeat(ancho)
        ));
        if let Some(sug) = &self.sugerencia {
            s.push_str(&format!("  ayuda: {sug}\n"));
        }
        s
    }

    /// Devuelve la linea que contiene el error, donde empieza y su numero.
    fn linea_de<'a>(&self, consulta: &'a str) -> (&'a str, usize, usize) {
        let pos = self.inicio.min(consulta.len());
        let inicio = consulta[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let fin = consulta[inicio..]
            .find('\n')
            .map(|i| inicio + i)
            .unwrap_or(consulta.len());
        let numero = consulta[..inicio].matches('\n').count() + 1;
        (&consulta[inicio..fin], inicio, numero)
    }
}

impl fmt::Display for ErrorConsulta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mensaje)?;
        if let Some(s) = &self.sugerencia {
            write!(f, " ({s})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ErrorConsulta {}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_subrayado_cae_bajo_el_tramo_culpable() {
        let consulta = "SELECT pdi FROM processes";
        let e = ErrorConsulta::nuevo("columna desconocida 'pdi'", 7, 10)
            .con_sugerencia("quiza querias decir 'pid'");
        let dibujo = e.dibujar(consulta);

        let lineas: Vec<&str> = dibujo.lines().collect();
        let texto = lineas[1];
        let acento = lineas[2];
        // El acento tiene que empezar justo debajo de la 'p' de 'pdi'.
        assert_eq!(
            acento.find('^').unwrap(),
            texto.find("pdi").unwrap(),
            "el subrayado esta desalineado:\n{dibujo}"
        );
        assert_eq!(acento.matches('^').count(), 3);
        assert!(dibujo.contains("quiza querias decir 'pid'"));
    }

    #[test]
    fn se_recorta_a_la_linea_del_error_y_la_numera() {
        let consulta = "SELECT pid\n  FROM procesos\n WHERE pid > 1";
        let inicio = consulta.find("procesos").unwrap();
        let e = ErrorConsulta::nuevo("tabla desconocida", inicio, inicio + 8);
        let dibujo = e.dibujar(consulta);

        assert!(dibujo.contains("2 |"), "numera la linea:\n{dibujo}");
        assert!(!dibujo.contains("SELECT pid"), "no arrastra otras lineas");
        assert!(!dibujo.contains("WHERE"), "no arrastra otras lineas");
    }

    #[test]
    fn el_acento_se_alinea_aunque_haya_caracteres_multibyte() {
        // Las posiciones son en BYTES; el subrayado se cuenta en caracteres.
        // Si se confundieran, este caso desplazaria el acento tres columnas.
        let consulta = "SELECT path WHERE path = 'año' AND pid = x";
        let inicio = consulta.rfind('x').unwrap();
        let e = ErrorConsulta::nuevo("se esperaba un literal", inicio, inicio + 1);
        let dibujo = e.dibujar(consulta);
        let lineas: Vec<&str> = dibujo.lines().collect();
        assert_eq!(
            lineas[2].find('^').unwrap(),
            lineas[1].chars().count() - 1,
            "el acento no cae bajo la 'x':\n{dibujo}"
        );
    }

    #[test]
    fn una_posicion_fuera_de_rango_no_entra_en_panico() {
        // El manejador de errores no puede ser una fuente de errores.
        let e = ErrorConsulta::nuevo("final inesperado", 900, 950);
        let dibujo = e.dibujar("SELECT pid");
        assert!(dibujo.contains("final inesperado"));
    }

    #[test]
    fn una_consulta_vacia_no_entra_en_panico() {
        let e = ErrorConsulta::nuevo("consulta vacia", 0, 0);
        assert!(e.dibujar("").contains("consulta vacia"));
    }
}
