//! La metrica de calidad: parte de la salida, no un informe aparte.
//!
//! Un decompilador que no dice lo bueno que fue su resultado obliga a confiar a
//! ciegas. Aqui la calidad viaja con el pseudo-C: cuanto se elevo, cuantos `goto`
//! hubo que emitir, cuantas variables quedaron sin tipo, cuantas funciones se
//! abandonaron por el plazo. Son las cuatro cifras que un analista necesita para
//! saber si puede fiarse de lo que lee.

/// La calidad de una decompilacion.
///
/// Todas las cuentas son acumulables: se suman las de cada funcion para dar la del
/// binario entero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Calidad {
    /// Instrucciones que se elevaron a la IR.
    pub instrucciones_elevadas: u64,
    /// Instrucciones que se vieron (elevadas o no). El cociente es la cobertura de
    /// elevacion.
    pub instrucciones_totales: u64,
    /// `goto` emitidos: cada uno es una perdida de estructura medida. Un grafo
    /// irreducible obliga a alguno; contarlos dice cuanto.
    pub gotos_emitidos: u64,
    /// Variables que quedaron `desconocido` porque no se pudo reconstruir su tipo.
    pub variables_sin_tipo: u64,
    /// Variables totales.
    pub variables_totales: u64,
    /// Funciones que se abandonaron por agotar el plazo.
    pub funciones_abandonadas: u64,
    /// Funciones totales.
    pub funciones_totales: u64,
}

impl Calidad {
    /// Suma dos calidades (la de dos funciones, para dar la del binario).
    #[must_use]
    pub fn mas(self, otra: Calidad) -> Calidad {
        Calidad {
            instrucciones_elevadas: self.instrucciones_elevadas + otra.instrucciones_elevadas,
            instrucciones_totales: self.instrucciones_totales + otra.instrucciones_totales,
            gotos_emitidos: self.gotos_emitidos + otra.gotos_emitidos,
            variables_sin_tipo: self.variables_sin_tipo + otra.variables_sin_tipo,
            variables_totales: self.variables_totales + otra.variables_totales,
            funciones_abandonadas: self.funciones_abandonadas + otra.funciones_abandonadas,
            funciones_totales: self.funciones_totales + otra.funciones_totales,
        }
    }

    /// Porcentaje de instrucciones elevadas (0..=100), o `None` si no se vio
    /// ninguna —que no es 0 %: es «no habia nada que elevar»—.
    #[must_use]
    pub fn cobertura_elevacion(&self) -> Option<u8> {
        porcentaje(self.instrucciones_elevadas, self.instrucciones_totales)
    }

    /// Porcentaje de variables con tipo reconstruido (0..=100), o `None`.
    #[must_use]
    pub fn cobertura_tipos(&self) -> Option<u8> {
        let con_tipo = self
            .variables_totales
            .saturating_sub(self.variables_sin_tipo);
        porcentaje(con_tipo, self.variables_totales)
    }

    /// Una frase legible con las cuatro cifras, para acompanar al pseudo-C.
    #[must_use]
    pub fn frase(&self) -> String {
        let elev = self
            .cobertura_elevacion()
            .map_or_else(|| "sin instrucciones".to_string(), |p| format!("{p} %"));
        let tip = self
            .cobertura_tipos()
            .map_or_else(|| "sin variables".to_string(), |p| format!("{p} %"));
        format!(
            "calidad: {elev} de instrucciones elevadas, {tip} de variables tipadas, \
             {} goto emitido(s), {}/{} funciones abandonadas por el plazo",
            self.gotos_emitidos, self.funciones_abandonadas, self.funciones_totales
        )
    }
}

/// Porcentaje entero, o `None` si el total es cero.
fn porcentaje(parte: u64, total: u64) -> Option<u8> {
    if total == 0 {
        None
    } else {
        Some(u8::try_from(parte.saturating_mul(100) / total).unwrap_or(100))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_cobertura_de_cero_de_cero_es_no_se_y_no_cero_por_ciento() {
        // Distinguir «no elevo nada de lo que habia» de «no habia nada» es la misma
        // disciplina de tri-estado del resto del producto.
        assert_eq!(Calidad::default().cobertura_elevacion(), None);
    }

    #[test]
    fn las_calidades_se_suman_por_funcion() {
        let a = Calidad {
            instrucciones_elevadas: 8,
            instrucciones_totales: 10,
            gotos_emitidos: 1,
            variables_totales: 4,
            variables_sin_tipo: 1,
            funciones_totales: 1,
            ..Calidad::default()
        };
        let b = Calidad {
            instrucciones_elevadas: 90,
            instrucciones_totales: 90,
            variables_totales: 6,
            funciones_totales: 1,
            ..Calidad::default()
        };
        let t = a.mas(b);
        assert_eq!(t.instrucciones_elevadas, 98);
        assert_eq!(t.instrucciones_totales, 100);
        assert_eq!(t.cobertura_elevacion(), Some(98));
        // 10 variables totales, 1 sin tipo -> 9 con tipo -> 90 %.
        assert_eq!(t.cobertura_tipos(), Some(90));
        assert_eq!(t.funciones_totales, 2);
    }

    #[test]
    fn la_frase_lleva_las_cuatro_cifras() {
        let q = Calidad {
            instrucciones_elevadas: 95,
            instrucciones_totales: 100,
            gotos_emitidos: 3,
            variables_totales: 10,
            variables_sin_tipo: 2,
            funciones_totales: 4,
            funciones_abandonadas: 1,
        };
        let f = q.frase();
        assert!(f.contains("95 %"));
        assert!(f.contains("80 %"));
        assert!(f.contains("3 goto"));
        assert!(f.contains("1/4"));
    }
}
