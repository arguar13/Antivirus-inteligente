//! Radio de explosion: que se lleva por delante un endpoint comprometido.
//!
//! # Por que Monte Carlo y no una formula
//!
//! La pregunta —«dado que el atacante controla X, cuantos activos caen»— es la
//! **fiabilidad de una red**, y calcularla de forma exacta es #P-completo: no hay
//! formula cerrada ni algoritmo eficiente, y no lo habra. Lo que si hay es
//! **percolacion**: se sortea cada arista segun su probabilidad, se mira que
//! queda alcanzable, y se repite. La media de muchas pasadas converge al valor
//! real, con un error que baja como `1/√n`.
//!
//! Eso no es una aproximacion vergonzante, es **la** forma de responder a esta
//! pregunta. Lo que si seria un error es presentarlo como exacto, y por eso
//! [`RadioExplosion`] lleva su margen de error dentro.
//!
//! # El sembrado determinista NO es comodidad, es requisito de producto
//!
//! Este motor autoriza **aislar maquinas de un cliente**. Si dos ejecuciones
//! sobre el mismo grafo dieran radios distintos, el informe que justifica la
//! decision no seria reproducible: el analista que revisa el caso el martes
//! veria numeros distintos de los que dispararon la accion el lunes, y no habria
//! forma de auditar nada.
//!
//! Por eso el generador es un PRNG propio, sembrado de forma explicita y
//! **derivada del origen del analisis**. Dos consecuencias buenas: el mismo
//! endpoint da siempre el mismo resultado, y dos endpoints distintos no comparten
//! el mismo sorteo —que haria que sus radios estuvieran correlacionados por un
//! artefacto del muestreo y no por la topologia real.
//!
//! # Lo que este modulo NO hace
//!
//! No decide aislar nada. Da un numero con su margen. La decision, con todos sus
//! frenos, esta en [`crate::contencion`], y esa separacion es deliberada: la
//! pregunta «cuanto se quema» y la pregunta «que hago» tienen respuestas
//! distintas, y mezclarlas es como se acaba aislando media empresa por una
//! prediccion.

use std::collections::BTreeSet;

use crate::error::ErrorPrediccion;
use crate::grafo::GrafoAtaque;

/// Pasadas por defecto del muestreo.
///
/// Con 2000 el error tipico de la media queda por debajo del 1 % de la flota,
/// que es mas fino que cualquier umbral con el que se decide.
pub const PASADAS_POR_DEFECTO: usize = 2000;

/// Tope de pasadas.
pub const MAX_PASADAS: usize = 100_000;

/// Generador determinista propio (xorshift64*).
///
/// Se implementa aqui, en doce lineas auditables, en vez de traer una
/// dependencia: el proyecto trata el arbol de dependencias como superficie de
/// ataque, y para sortear aristas no hace falta calidad criptografica — hace
/// falta que sea **reproducible**, que es justo lo que una fuente del sistema no
/// da.
#[derive(Debug, Clone)]
pub struct Generador {
    estado: u64,
}

impl Generador {
    /// Nuevo generador con la semilla dada.
    ///
    /// Una semilla de cero rompe xorshift (se queda clavado en cero), asi que se
    /// sustituye por una constante. No es un caso raro: es el que sale de sembrar
    /// con un contador que empieza en cero.
    #[must_use]
    pub fn nuevo(semilla: u64) -> Generador {
        Generador {
            estado: if semilla == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                semilla
            },
        }
    }

    /// Semilla derivada de un texto, para que cada origen tenga su propio sorteo.
    #[must_use]
    pub fn desde_texto(s: &str) -> Generador {
        // FNV-1a de 64 bits: estable entre plataformas y versiones, que es lo que
        // hace falta. `DefaultHasher` NO lo es —su salida puede cambiar entre
        // versiones de Rust— y con el, el radio de un endpoint cambiaria al
        // recompilar.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in s.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        Generador::nuevo(h)
    }

    /// Siguiente entero.
    pub fn siguiente(&mut self) -> u64 {
        let mut x = self.estado;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.estado = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Siguiente real en [0, 1).
    pub fn siguiente_f64(&mut self) -> f64 {
        // 53 bits de mantisa: el maximo que un f64 representa sin perder nada.
        (self.siguiente() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// El radio de explosion estimado.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RadioExplosion {
    /// Desde donde se midio.
    pub origen: String,
    /// Media de activos alcanzados, sin contar el origen.
    pub activos_esperados: f64,
    /// Margen de error de la media (una desviacion tipica).
    ///
    /// Va dentro del resultado a proposito: un numero de Monte Carlo sin su
    /// margen se lee como exacto, y no lo es.
    pub margen: f64,
    /// Joyas de la corona esperadas dentro del radio.
    pub joyas_esperadas: f64,
    /// Activos que caen en **mas de la mitad** de las pasadas: el nucleo duro.
    pub casi_seguros: Vec<String>,
    /// Pasadas ejecutadas.
    pub pasadas: usize,
}

impl RadioExplosion {
    /// Fraccion de la flota que se espera perder.
    #[must_use]
    pub fn fraccion(&self, total_activos: usize) -> f64 {
        if total_activos <= 1 {
            return 0.0;
        }
        self.activos_esperados / (total_activos - 1) as f64
    }
}

/// Estima el radio de explosion desde `origen`.
///
/// # Errores
/// [`ErrorPrediccion::ActivoDesconocido`] si el origen no existe, o
/// [`ErrorPrediccion::LimiteExcedido`] si se piden mas de [`MAX_PASADAS`].
pub fn radio_de_explosion(
    g: &GrafoAtaque,
    origen: &str,
    pasadas: usize,
) -> Result<RadioExplosion, ErrorPrediccion> {
    if g.activo(origen).is_none() {
        return Err(ErrorPrediccion::ActivoDesconocido(origen.to_string()));
    }
    if pasadas > MAX_PASADAS {
        return Err(ErrorPrediccion::LimiteExcedido {
            campo: "pasadas",
            valor: pasadas,
            tope: MAX_PASADAS,
        });
    }
    let pasadas = pasadas.max(1);

    // La semilla se deriva del ORIGEN: el mismo endpoint da siempre el mismo
    // resultado, y dos endpoints distintos no comparten sorteo.
    let mut rng = Generador::desde_texto(origen);

    let mut suma = 0.0f64;
    let mut suma_cuadrados = 0.0f64;
    let mut suma_joyas = 0.0f64;
    let mut cuenta_por_activo: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();

    for _ in 0..pasadas {
        let alcanzados = una_pasada(g, origen, &mut rng);
        let n = alcanzados.len() as f64;
        suma += n;
        suma_cuadrados += n * n;
        suma_joyas += alcanzados
            .iter()
            .filter(|a| g.activo(a).is_some_and(crate::grafo::Activo::es_joya))
            .count() as f64;
        for a in alcanzados {
            *cuenta_por_activo.entry(a).or_insert(0) += 1;
        }
    }

    let n = pasadas as f64;
    let media = suma / n;
    // Varianza de la muestra, y de ahi el error tipico de la MEDIA (/√n).
    let varianza = (suma_cuadrados / n - media * media).max(0.0);
    let margen = (varianza / n).sqrt();

    let mut casi_seguros: Vec<String> = cuenta_por_activo
        .iter()
        .filter(|(_, &c)| c * 2 > pasadas)
        .map(|(a, _)| (*a).to_string())
        .collect();
    casi_seguros.sort();

    Ok(RadioExplosion {
        origen: origen.to_string(),
        activos_esperados: media,
        margen,
        joyas_esperadas: suma_joyas / n,
        casi_seguros,
        pasadas,
    })
}

/// Una pasada de percolacion: sortea cada arista y devuelve lo alcanzable.
fn una_pasada<'g>(g: &'g GrafoAtaque, origen: &str, rng: &mut Generador) -> BTreeSet<&'g str> {
    let mut vistos: BTreeSet<&str> = BTreeSet::new();
    let mut alcanzados: BTreeSet<&str> = BTreeSet::new();
    let mut pila: Vec<&str> = Vec::new();

    // El origen se recorre pero NO se cuenta: el atacante ya lo tenia, y
    // contarlo inflaria todos los radios en uno.
    if let Some(a) = g.activo(origen) {
        vistos.insert(a.nombre.as_str());
        pila.push(a.nombre.as_str());
    }

    while let Some(actual) = pila.pop() {
        for paso in g.salientes(actual) {
            if vistos.contains(paso.destino.as_str()) {
                continue;
            }
            // El sorteo se hace por arista y por pasada: la misma arista puede
            // salir en una pasada y no en otra, que es lo que modela la
            // incertidumbre real.
            if rng.siguiente_f64() < paso.probabilidad_efectiva() {
                let d = paso.destino.as_str();
                vistos.insert(d);
                alcanzados.insert(d);
                pila.push(d);
            }
        }
    }
    alcanzados
}

#[cfg(test)]
mod pruebas {
    use aegis_itdr::grafo::Nivel;

    use super::*;
    use crate::grafo::{Activo, ClaseActivo, Paso, Via};

    fn cadena(n: usize, p: Via) -> GrafoAtaque {
        let mut g = GrafoAtaque::nuevo();
        for i in 0..n {
            g.agregar(Activo::nuevo(
                format!("n{i}"),
                ClaseActivo::Endpoint,
                Nivel::Usuario,
                10,
            ))
            .unwrap();
        }
        for i in 0..n - 1 {
            g.conectar(Paso::nuevo(format!("n{i}"), format!("n{}", i + 1), p))
                .unwrap();
        }
        g
    }

    /// EL DETERMINISMO, que es requisito de producto y no comodidad.
    #[test]
    fn dos_ejecuciones_dan_exactamente_el_mismo_radio() {
        let g = cadena(10, Via::RedExpuesta);
        let a = radio_de_explosion(&g, "n0", 500).unwrap();
        for _ in 0..20 {
            assert_eq!(radio_de_explosion(&g, "n0", 500).unwrap(), a);
        }
    }

    /// Y la semilla NO puede venir de `DefaultHasher`, cuya salida puede cambiar
    /// entre versiones de Rust: el radio de un endpoint cambiaria al recompilar.
    /// Se fija el valor de FNV-1a para que eso se note si alguien lo toca.
    #[test]
    fn la_semilla_es_estable_entre_compilaciones() {
        // FNV-1a de "abc", calculado a mano.
        let esperado: u64 = {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in b"abc" {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
            h
        };
        assert_eq!(Generador::desde_texto("abc").estado, esperado);
        assert_eq!(esperado, 0xe71f_a2190541574b);
    }

    /// EL VALOR, contra una cuenta hecha a mano. Una cadena de dos aristas de
    /// probabilidad p alcanza en media p + p² activos.
    #[test]
    fn el_radio_converge_al_valor_analitico() {
        // Dos aristas de p = 0,99 (MiembroDe con evidencia solida).
        let g = cadena(
            3,
            Via::Identidad(crate::grafo::RelacionSerializable::MiembroDe),
        );
        let r = radio_de_explosion(&g, "n0", 20_000).unwrap();
        let p: f64 = 0.99;
        let esperado = p + p * p;
        assert!(
            (r.activos_esperados - esperado).abs() < 0.02,
            "radio {} vs analitico {esperado}",
            r.activos_esperados
        );
    }

    /// Y con una probabilidad baja, donde la varianza es grande, tambien.
    #[test]
    fn el_radio_converge_tambien_con_probabilidad_baja() {
        // Dos aristas de p = 0,15 (red segmentada).
        let g = cadena(3, Via::RedSegmentada);
        let r = radio_de_explosion(&g, "n0", 40_000).unwrap();
        let p: f64 = 0.15;
        let esperado = p + p * p;
        assert!(
            (r.activos_esperados - esperado).abs() < 0.02,
            "radio {} vs analitico {esperado}",
            r.activos_esperados
        );
    }

    /// EL MARGEN va dentro del resultado: un numero de Monte Carlo sin su margen
    /// se lee como exacto, y no lo es.
    #[test]
    fn el_margen_se_reporta_y_encoge_con_mas_pasadas() {
        let g = cadena(8, Via::RedExpuesta);
        let pocas = radio_de_explosion(&g, "n0", 200).unwrap();
        let muchas = radio_de_explosion(&g, "n0", 20_000).unwrap();
        assert!(pocas.margen > 0.0);
        assert!(
            muchas.margen < pocas.margen / 2.0,
            "el margen tiene que encoger como 1/sqrt(n): {} vs {}",
            muchas.margen,
            pocas.margen
        );
    }

    /// La segmentacion REDUCE el radio. Es la comprobacion de que el motor
    /// premia lo que un defensor hace bien; si no lo hiciera, el modelo estaria
    /// invertido y aconsejaria al reves.
    #[test]
    fn segmentar_la_red_reduce_el_radio() {
        let expuesta = radio_de_explosion(&cadena(8, Via::RedExpuesta), "n0", 5000).unwrap();
        let segmentada = radio_de_explosion(&cadena(8, Via::RedSegmentada), "n0", 5000).unwrap();
        assert!(
            segmentada.activos_esperados < expuesta.activos_esperados / 2.0,
            "segmentada {} vs expuesta {}",
            segmentada.activos_esperados,
            expuesta.activos_esperados
        );
    }

    #[test]
    fn el_origen_no_se_cuenta_en_su_propio_radio() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "solo",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            1,
        ))
        .unwrap();
        let r = radio_de_explosion(&g, "solo", 100).unwrap();
        assert_eq!(r.activos_esperados, 0.0, "el atacante ya tenia el origen");
    }

    #[test]
    fn los_casi_seguros_son_los_que_caen_en_mas_de_la_mitad_de_las_pasadas() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["origen", "casi-siempre", "casi-nunca"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, Nivel::Usuario, 10))
                .unwrap();
        }
        g.conectar(Paso::nuevo(
            "origen",
            "casi-siempre",
            Via::Identidad(crate::grafo::RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo("origen", "casi-nunca", Via::RedSegmentada))
            .unwrap();

        let r = radio_de_explosion(&g, "origen", 5000).unwrap();
        assert_eq!(r.casi_seguros, vec!["casi-siempre"]);
    }

    #[test]
    fn las_joyas_dentro_del_radio_se_cuentan_aparte() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "origen",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            10,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "joya",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "raso",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            10,
        ))
        .unwrap();
        for d in ["joya", "raso"] {
            g.conectar(Paso::nuevo(
                "origen",
                d,
                Via::Identidad(crate::grafo::RelacionSerializable::MiembroDe),
            ))
            .unwrap();
        }
        let r = radio_de_explosion(&g, "origen", 5000).unwrap();
        assert!(
            (r.joyas_esperadas - 0.99).abs() < 0.02,
            "{}",
            r.joyas_esperadas
        );
        assert!(r.activos_esperados > r.joyas_esperadas);
    }

    #[test]
    fn un_ciclo_no_cuelga_la_percolacion() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["a", "b", "c"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, Nivel::Usuario, 10))
                .unwrap();
        }
        let v = Via::Identidad(crate::grafo::RelacionSerializable::MiembroDe);
        g.conectar(Paso::nuevo("a", "b", v)).unwrap();
        g.conectar(Paso::nuevo("b", "c", v)).unwrap();
        g.conectar(Paso::nuevo("c", "a", v)).unwrap();
        let r = radio_de_explosion(&g, "a", 500).unwrap();
        assert!(r.activos_esperados <= 2.0);
    }

    #[test]
    fn una_semilla_de_cero_no_deja_el_generador_clavado() {
        let mut g = Generador::nuevo(0);
        let primeros: Vec<u64> = (0..5).map(|_| g.siguiente()).collect();
        assert!(
            primeros.iter().any(|&x| x != primeros[0]),
            "xorshift con semilla cero se queda en cero para siempre"
        );
    }

    #[test]
    fn el_generador_produce_reales_dentro_del_intervalo() {
        let mut g = Generador::desde_texto("prueba");
        for _ in 0..100_000 {
            let x = g.siguiente_f64();
            assert!((0.0..1.0).contains(&x), "fuera de [0,1): {x}");
        }
    }

    #[test]
    fn pedir_demasiadas_pasadas_se_rechaza() {
        let g = cadena(3, Via::RedExpuesta);
        assert!(matches!(
            radio_de_explosion(&g, "n0", MAX_PASADAS + 1),
            Err(ErrorPrediccion::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn dos_origenes_distintos_no_comparten_sorteo() {
        // Si compartieran semilla, sus radios estarian correlacionados por un
        // artefacto del muestreo y no por la topologia real.
        assert_ne!(
            Generador::desde_texto("endpoint-a").estado,
            Generador::desde_texto("endpoint-b").estado
        );
    }
}
