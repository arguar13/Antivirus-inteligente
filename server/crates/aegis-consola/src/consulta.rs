//! El coste de una consulta de caza, mostrado ANTES de ejecutar (FASE 110).
//!
//! Hoy `lanzar_caza` devuelve el coste DESPUES de lanzar: la caza ya se persistio y
//! se difundio a la flota cuando el operador se entera de lo que costaba. Una
//! consola que ensena el coste despues no ayuda a decidir. Aqui la previsualizacion
//! calcula el coste SIN efectos —no lanza nada, no toca la flota— para que el
//! analista lo vea y decida antes de ejecutar. Es una funcion pura sobre el plan.

/// El coste estimado de una consulta, antes de ejecutarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosteConsulta {
    /// Tablas que toca, en orden.
    pub tablas: Vec<String>,
    /// Filas estimadas que se recorren (el limite acota el resultado, no el
    /// recorrido).
    pub filas_estimadas: u64,
    /// Coste en puntos: la suma del coste por tabla, escalada por el recorrido.
    pub puntos: u64,
}

impl CosteConsulta {
    /// Si el coste cabe en un tope. Es lo que la consola comprueba antes de dejar
    /// pulsar «ejecutar».
    #[must_use]
    pub fn dentro_de(&self, tope_puntos: u64) -> bool {
        self.puntos <= tope_puntos
    }
}

/// Previsualiza el coste de una consulta SIN ejecutarla.
///
/// `tablas` son las tablas que toca con su coste por fila declarado (del esquema
/// de AegisQL). `filas_por_tabla` es el tamano estimado de cada una. El limite
/// acota el RESULTADO, pero el coste refleja el RECORRIDO, que es lo que de verdad
/// cuesta —una consulta sin indice recorre toda la tabla aunque devuelva una fila—.
#[must_use]
pub fn previsualizar(tablas: &[(String, u64)], filas_por_tabla: u64) -> CosteConsulta {
    let nombres: Vec<String> = tablas.iter().map(|(n, _)| n.clone()).collect();
    let filas = filas_por_tabla.saturating_mul(tablas.len() as u64);
    let puntos = tablas
        .iter()
        .map(|(_, coste_fila)| coste_fila.saturating_mul(filas_por_tabla))
        .fold(0u64, u64::saturating_add);
    CosteConsulta {
        tablas: nombres,
        filas_estimadas: filas,
        puntos,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_coste_se_calcula_sin_ejecutar_y_suma_por_tabla() {
        // Dos tablas: procesos (coste 2/fila) y conexiones (coste 3/fila), 1000
        // filas cada una. Coste = (2+3)*1000 = 5000.
        let c = previsualizar(&[("procesos".into(), 2), ("conexiones".into(), 3)], 1000);
        assert_eq!(c.puntos, 5000);
        assert_eq!(c.filas_estimadas, 2000);
        assert_eq!(c.tablas, vec!["procesos", "conexiones"]);
    }

    #[test]
    fn una_consulta_cara_se_detecta_antes_de_ejecutar() {
        let barata = previsualizar(&[("procesos".into(), 1)], 100);
        assert!(barata.dentro_de(1000));
        let cara = previsualizar(&[("eventos".into(), 50)], 1_000_000);
        assert!(!cara.dentro_de(1000), "50M puntos no caben en 1000");
    }

    #[test]
    fn previsualizar_no_tiene_efectos() {
        // Es una funcion pura: llamarla dos veces da lo mismo y no cambia nada.
        let a = previsualizar(&[("t".into(), 4)], 10);
        let b = previsualizar(&[("t".into(), 4)], 10);
        assert_eq!(a, b);
    }
}
