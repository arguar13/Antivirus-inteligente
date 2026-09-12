//! Criticidad: cuanto importa un activo por lo que permite alcanzar.
//!
//! # La idea en una frase
//!
//! Un portatil de becario no vale nada por si mismo. Vale exactamente lo que
//! valen las cosas a las que da acceso. La criticidad propaga el valor **hacia
//! atras** desde las joyas de la corona, por las aristas de ataque y descontado
//! por su probabilidad:
//!
//! ```text
//! c(v) = valor(v) + α · Σ  p(v→u) · c(u)
//!                    v→u
//! ```
//!
//! Es *message passing* sobre el grafo —cada iteracion es una ronda de mensajes
//! de los vecinos— con los pesos **puestos a mano**, no entrenados.
//!
//! # Por que a mano y no entrenado
//!
//! Un modelo entrenado necesitaria un corpus etiquetado de brechas reales de
//! esta organizacion, que no existe; con datos de otra, aprenderia la topologia
//! de otra. Pero la razon de fondo es otra: **esto autoriza aislar maquinas de
//! produccion**. Con pesos a mano se puede responder «este portatil sale critico
//! porque a dos saltos llega a Domain Admins con probabilidad 0,94». Con pesos
//! aprendidos, la respuesta es un numero.
//!
//! # Por que converge, y por que eso importa
//!
//! El factor de amortiguacion `α < 1` hace que la iteracion sea una
//! **contraccion**: cada ronda el cambio se multiplica como mucho por `α`, asi
//! que la sucesion converge a un unico punto fijo, sin depender del orden en que
//! se visiten los nodos ni del valor inicial.
//!
//! Sin `α`, un ciclo en el grafo —y los hay siempre: A puede actuar como B y B
//! como A— haria que el valor diera vueltas amplificandose y la criticidad
//! creciera sin limite. No seria un numero grande: seria infinito.

use std::collections::BTreeMap;

use crate::error::ErrorPrediccion;
use crate::grafo::GrafoAtaque;

/// Factor de amortiguacion.
///
/// 0,85 es el mismo valor clasico de PageRank, y por la misma razon: alto para
/// que el valor llegue a varios saltos de distancia, y estrictamente menor que 1
/// para que la iteracion converja.
pub const AMORTIGUACION: f64 = 0.85;

/// Iteraciones maximas.
pub const MAX_ITERACIONES: usize = 200;

/// Cambio por debajo del cual se considera convergido.
pub const TOLERANCIA: f64 = 1e-9;

/// El resultado de la propagacion.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Criticidades {
    /// Criticidad de cada activo, en orden estable.
    pub valores: BTreeMap<String, f64>,
    /// Iteraciones hasta converger.
    pub iteraciones: usize,
    /// Si de verdad convergio dentro del limite.
    ///
    /// Se reporta en vez de asumirse: un resultado que se corto por el limite de
    /// iteraciones no es el punto fijo, y quien lo use tiene que poder saberlo.
    pub convergio: bool,
}

impl Criticidades {
    /// Criticidad de un activo.
    #[must_use]
    pub fn de(&self, activo: &str) -> f64 {
        self.valores.get(activo).copied().unwrap_or(0.0)
    }

    /// Los activos mas criticos, de mas a menos.
    #[must_use]
    pub fn ranking(&self, tope: usize) -> Vec<(String, f64)> {
        let mut v: Vec<(String, f64)> = self.valores.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Desempate estable: el ranking no puede bailar entre ejecuciones.
                .then_with(|| a.0.cmp(&b.0))
        });
        v.truncate(tope);
        v
    }
}

/// Propaga la criticidad por el grafo.
///
/// # Errores
/// [`ErrorPrediccion::SinJoyasDeLaCorona`] si no hay nada declarado como
/// critico: sin eso, todo el mundo tiene criticidad cero y el resultado seria
/// una lista de ceros presentada como analisis.
pub fn propagar(g: &GrafoAtaque) -> Result<Criticidades, ErrorPrediccion> {
    if g.joyas().next().is_none() {
        return Err(ErrorPrediccion::SinJoyasDeLaCorona);
    }

    // Valor propio de cada activo: el punto de partida.
    let mut c: BTreeMap<&str, f64> = g
        .nombres()
        .map(|n| {
            let v = g.activo(n).map_or(0.0, |a| f64::from(a.valor));
            (n.as_str(), v)
        })
        .collect();

    let mut iteraciones = 0;
    let mut convergio = false;

    for _ in 0..MAX_ITERACIONES {
        iteraciones += 1;
        let mut siguiente: BTreeMap<&str, f64> = BTreeMap::new();
        let mut cambio_max = 0.0f64;

        for nombre in g.nombres() {
            let propio = g.activo(nombre).map_or(0.0, |a| f64::from(a.valor));
            let mut recibido = 0.0;
            for paso in g.salientes(nombre) {
                let vecino = c.get(paso.destino.as_str()).copied().unwrap_or(0.0);
                recibido += paso.probabilidad_efectiva() * vecino;
            }
            let nuevo = propio + AMORTIGUACION * recibido;
            let anterior = c.get(nombre.as_str()).copied().unwrap_or(0.0);
            cambio_max = cambio_max.max((nuevo - anterior).abs());
            siguiente.insert(nombre.as_str(), nuevo);
        }

        c = siguiente;
        if cambio_max < TOLERANCIA {
            convergio = true;
            break;
        }
    }

    Ok(Criticidades {
        valores: c.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        iteraciones,
        convergio,
    })
}

#[cfg(test)]
mod pruebas {
    use aegis_itdr::grafo::Nivel;

    use super::*;
    use crate::grafo::{Activo, ClaseActivo, Evidencia, Paso, RelacionSerializable, Via};

    fn via_segura() -> Via {
        Via::Identidad(RelacionSerializable::MiembroDe)
    }

    /// EL CASO QUE JUSTIFICA EL MODULO: un portatil sin valor propio sale mas
    /// critico que otro igual, sólo porque desde el se llega a la joya.
    #[test]
    fn un_portatil_sin_valor_propio_hereda_la_criticidad_de_lo_que_alcanza() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "portatil-becario",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "portatil-aislado",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "portatil-becario",
            "Domain Admins",
            via_segura(),
        ))
        .unwrap();

        let c = propagar(&g).unwrap();
        assert!(c.convergio);
        assert_eq!(c.de("portatil-aislado"), 0.0);
        assert!(
            c.de("portatil-becario") > 80.0,
            "el portatil que alcanza la joya tiene que heredar su valor: {}",
            c.de("portatil-becario")
        );
        // Y el valor exacto se puede comprobar a mano: 0 + 0,85 · 0,99 · 100.
        assert!((c.de("portatil-becario") - 0.85 * 0.99 * 100.0).abs() < 1e-6);
    }

    /// EL VALOR SE APAGA CON LA DISTANCIA: un activo a tres saltos hereda menos
    /// que uno a uno. Si no fuera asi, toda la flota saldria igual de critica y
    /// el ranking no diria nada.
    #[test]
    fn la_criticidad_decae_con_la_distancia_a_la_joya() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["lejos", "medio", "cerca"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, Nivel::Usuario, 0))
                .unwrap();
        }
        g.agregar(Activo::nuevo(
            "joya",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo("lejos", "medio", via_segura()))
            .unwrap();
        g.conectar(Paso::nuevo("medio", "cerca", via_segura()))
            .unwrap();
        g.conectar(Paso::nuevo("cerca", "joya", via_segura()))
            .unwrap();

        let c = propagar(&g).unwrap();
        assert!(c.de("cerca") > c.de("medio"));
        assert!(c.de("medio") > c.de("lejos"));
        assert!(c.de("lejos") > 0.0, "pero llega algo, que es el punto");
    }

    /// LA RAZON DE LA AMORTIGUACION: sin ella, un ciclo haria crecer la
    /// criticidad sin limite. Con ella, converge.
    #[test]
    fn un_ciclo_converge_en_vez_de_crecer_sin_limite() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["a", "b", "c"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Identidad, Nivel::Usuario, 0))
                .unwrap();
        }
        g.agregar(Activo::nuevo(
            "joya",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo("a", "b", via_segura())).unwrap();
        g.conectar(Paso::nuevo("b", "c", via_segura())).unwrap();
        g.conectar(Paso::nuevo("c", "a", via_segura())).unwrap();
        g.conectar(Paso::nuevo("c", "joya", via_segura())).unwrap();

        let c = propagar(&g).unwrap();
        assert!(c.convergio, "un ciclo tiene que converger, no dispararse");
        for n in ["a", "b", "c"] {
            assert!(
                c.de(n).is_finite() && c.de(n) < 1000.0,
                "{n} = {} se disparo",
                c.de(n)
            );
        }
    }

    /// El determinismo otra vez: mismo grafo, mismos numeros y mismo ranking.
    #[test]
    fn dos_ejecuciones_dan_las_mismas_criticidades_y_el_mismo_ranking() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["zeta", "alfa", "mu"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, Nivel::Usuario, 0))
                .unwrap();
        }
        g.agregar(Activo::nuevo(
            "joya",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        for n in ["zeta", "alfa", "mu"] {
            g.conectar(Paso::nuevo(n, "joya", via_segura())).unwrap();
        }
        let a = propagar(&g).unwrap();
        for _ in 0..20 {
            let b = propagar(&g).unwrap();
            assert_eq!(a, b);
            assert_eq!(a.ranking(10), b.ranking(10));
        }
        // Con tres activos empatados, el desempate por nombre los ordena.
        let r = a.ranking(4);
        assert_eq!(r[0].0, "joya");
        assert_eq!(
            r[1..].iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["alfa", "mu", "zeta"]
        );
    }

    /// Una arista recien fabricada por el atacante transmite mucha menos
    /// criticidad: la defensa anti-manipulacion llega tambien hasta aqui.
    #[test]
    fn una_arista_recien_fabricada_transmite_mucha_menos_criticidad() {
        let construir = |e: Evidencia| {
            let mut g = GrafoAtaque::nuevo();
            g.agregar(Activo::nuevo(
                "pc",
                ClaseActivo::Endpoint,
                Nivel::Usuario,
                0,
            ))
            .unwrap();
            g.agregar(Activo::nuevo(
                "joya",
                ClaseActivo::Identidad,
                Nivel::AdminDominio,
                100,
            ))
            .unwrap();
            g.conectar(Paso::nuevo("pc", "joya", via_segura()).con_evidencia(e))
                .unwrap();
            propagar(&g).unwrap().de("pc")
        };
        let solida = construir(Evidencia::default());
        let recien = construir(Evidencia::recien_vista());
        assert!(
            recien < solida / 2.0,
            "recien = {recien}, solida = {solida}"
        );
    }

    #[test]
    fn sin_joyas_declaradas_se_niega_en_vez_de_devolver_ceros() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo("a", ClaseActivo::Endpoint, Nivel::Usuario, 5))
            .unwrap();
        assert_eq!(propagar(&g), Err(ErrorPrediccion::SinJoyasDeLaCorona));
    }

    #[test]
    fn la_convergencia_se_reporta_y_no_se_asume() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "joya",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        let c = propagar(&g).unwrap();
        assert!(c.convergio);
        assert!(c.iteraciones <= MAX_ITERACIONES);
        assert!(c.iteraciones >= 1);
    }

    /// La condicion de convergencia, afirmada en **tiempo de compilacion**: si
    /// alguien sube la amortiguacion a 1 o mas, la iteracion deja de ser una
    /// contraccion y un ciclo hace crecer la criticidad sin limite. Que el crate
    /// no compile es mucho mejor que descubrirlo con un numero infinito en el
    /// panel de un cliente.
    const _CONVERGE: () = {
        assert!(AMORTIGUACION > 0.0);
        assert!(AMORTIGUACION < 1.0);
    };
}
