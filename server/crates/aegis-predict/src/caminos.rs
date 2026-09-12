//! El camino de ataque mas probable, exacto y explicable.
//!
//! # La transformacion que convierte un producto en una suma
//!
//! La probabilidad de que un atacante recorra un camino entero es el **producto**
//! de las de sus pasos:
//!
//! ```text
//! P(camino) = p1 · p2 · … · pn
//! ```
//!
//! El camino mas probable es el que maximiza ese producto. Dijkstra no maximiza
//! productos, minimiza sumas — pero el logaritmo convierte una cosa en la otra:
//!
//! ```text
//! maximizar  ∏ pi     ⟺     minimizar  Σ −log(pi)
//! ```
//!
//! y como cada `pi ∈ (0, 1]`, cada `−log(pi) ≥ 0`: **todos los pesos son no
//! negativos**, que es justo la condicion que Dijkstra necesita. De ahi que el
//! resultado no sea una aproximacion ni una heuristica, sino **el optimo exacto**.
//!
//! Por eso el cero esta excluido del rango de probabilidades: `−log 0` es
//! infinito, y una arista imposible no es un camino caro, es la ausencia de
//! arista.
//!
//! # Por que esto y no una red neuronal
//!
//! Podria hacerse con un modelo entrenado. No se hace, y la razon es lo que este
//! motor autoriza: **aislar maquinas de produccion**. Un camino calculado asi se
//! puede imprimir paso a paso —«alice tiene credenciales cacheadas de svc-backup,
//! que es miembro de Domain Admins; probabilidad 0,94»— y un analista puede
//! mirarlo y decir que no. Un vector de activaciones no se discute.
//!
//! Ademas es **determinista**: dos ejecuciones sobre el mismo grafo dan el mismo
//! camino, incluido el desempate. Eso no es comodidad, es un requisito de
//! producto: el informe que justifica aislar la maquina de un cliente no puede
//! cambiar entre dos ejecuciones.

use std::collections::{BTreeMap, BinaryHeap};

use crate::error::ErrorPrediccion;
use crate::grafo::{GrafoAtaque, Paso};

/// Un camino de ataque encontrado.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CaminoAtaque {
    /// Desde donde.
    pub origen: String,
    /// Hasta donde.
    pub destino: String,
    /// Los pasos, en orden.
    pub pasos: Vec<Paso>,
    /// Probabilidad total del camino: el producto de sus pasos.
    pub probabilidad: f64,
}

impl CaminoAtaque {
    /// Numero de saltos.
    #[must_use]
    pub fn saltos(&self) -> usize {
        self.pasos.len()
    }

    /// El camino en texto, para el informe del analista.
    ///
    /// Que exista esta funcion es parte del diseno: una prediccion que autoriza
    /// aislar una maquina tiene que poder leerse en una frase.
    #[must_use]
    pub fn explicar(&self) -> String {
        let mut s = format!("{} ", self.origen);
        for p in &self.pasos {
            s.push_str(&format!("{} {} ", p.via.describir(), p.destino));
        }
        s.push_str(&format!("(p = {:.4})", self.probabilidad));
        s
    }

    /// El paso mas debil: el mejor sitio donde cortar.
    ///
    /// Cortar por el eslabon menos probable es lo que **menos** reduce el riesgo:
    /// el atacante ya tenia dificil ese paso. El que interesa cortar es el que
    /// mas sube la dificultad del camino entero, y en un producto ese es el de
    /// probabilidad **mas alta**: eliminarlo es lo que mas baja el producto.
    #[must_use]
    pub fn eslabon_mas_valioso(&self) -> Option<&Paso> {
        self.pasos.iter().max_by(|a, b| {
            a.probabilidad_efectiva()
                .partial_cmp(&b.probabilidad_efectiva())
                .unwrap_or(std::cmp::Ordering::Equal)
                // Desempate estable por nombre: el resultado no puede depender
                // del orden en que se recorrieron los pasos.
                .then_with(|| b.destino.cmp(&a.destino))
        })
    }
}

/// Coste en una cola de prioridad, ordenado al reves para tener un mini-monton.
///
/// `f64` no es `Ord` porque existe NaN. Aqui no puede haberlo —las
/// probabilidades estan validadas en (0, 1], asi que `−log p` es finito y no
/// negativo—, pero en lugar de confiar en eso se ordena de forma total y
/// explicita, con desempate por nombre para que el resultado sea determinista.
#[derive(Debug, PartialEq)]
struct EnCola {
    coste: f64,
    nombre: String,
}

impl Eq for EnCola {}

impl Ord for EnCola {
    fn cmp(&self, otro: &EnCola) -> std::cmp::Ordering {
        otro.coste
            .partial_cmp(&self.coste)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| otro.nombre.cmp(&self.nombre))
    }
}

impl PartialOrd for EnCola {
    fn partial_cmp(&self, otro: &EnCola) -> Option<std::cmp::Ordering> {
        Some(self.cmp(otro))
    }
}

/// El camino mas probable de `origen` a `destino`.
///
/// Devuelve `None` si no hay camino.
///
/// # Errores
/// [`ErrorPrediccion::ActivoDesconocido`] si alguno de los extremos no esta en
/// el grafo.
pub fn camino_mas_probable(
    g: &GrafoAtaque,
    origen: &str,
    destino: &str,
) -> Result<Option<CaminoAtaque>, ErrorPrediccion> {
    if g.activo(origen).is_none() {
        return Err(ErrorPrediccion::ActivoDesconocido(origen.to_string()));
    }
    if g.activo(destino).is_none() {
        return Err(ErrorPrediccion::ActivoDesconocido(destino.to_string()));
    }
    if origen == destino {
        return Ok(Some(CaminoAtaque {
            origen: origen.to_string(),
            destino: destino.to_string(),
            pasos: Vec::new(),
            probabilidad: 1.0,
        }));
    }

    let mut coste: BTreeMap<&str, f64> = BTreeMap::new();
    let mut previo: BTreeMap<&str, &Paso> = BTreeMap::new();
    let mut cola = BinaryHeap::new();

    coste.insert(origen, 0.0);
    cola.push(EnCola {
        coste: 0.0,
        nombre: origen.to_string(),
    });

    while let Some(EnCola { coste: c, nombre }) = cola.pop() {
        // Entrada obsoleta: ya se llego mas barato.
        if c > *coste.get(nombre.as_str()).unwrap_or(&f64::INFINITY) {
            continue;
        }
        if nombre == destino {
            break;
        }
        for paso in g.salientes(&nombre) {
            let p = paso.probabilidad_efectiva();
            // `p` esta validada en (0, 1] al construir el grafo, asi que el
            // logaritmo es finito. Se comprueba igualmente: un NaN colandose
            // aqui envenenaria el orden de la cola en silencio.
            let peso = -p.ln();
            if !peso.is_finite() {
                continue;
            }
            let nuevo = c + peso;
            let actual = *coste.get(paso.destino.as_str()).unwrap_or(&f64::INFINITY);
            if nuevo < actual {
                coste.insert(&paso.destino, nuevo);
                previo.insert(&paso.destino, paso);
                cola.push(EnCola {
                    coste: nuevo,
                    nombre: paso.destino.clone(),
                });
            }
        }
    }

    if !coste.contains_key(destino) {
        return Ok(None);
    }

    // Reconstruccion hacia atras.
    let mut pasos = Vec::new();
    let mut actual = destino;
    while actual != origen {
        let Some(paso) = previo.get(actual) else {
            return Ok(None);
        };
        pasos.push((*paso).clone());
        actual = &paso.origen;
    }
    pasos.reverse();

    let probabilidad = pasos.iter().map(Paso::probabilidad_efectiva).product();
    Ok(Some(CaminoAtaque {
        origen: origen.to_string(),
        destino: destino.to_string(),
        pasos,
        probabilidad,
    }))
}

/// Los caminos mas probables desde `origen` a **todas** las joyas de la corona,
/// ordenados de mas probable a menos.
///
/// # Errores
/// [`ErrorPrediccion::ActivoDesconocido`] si el origen no existe, o
/// [`ErrorPrediccion::SinJoyasDeLaCorona`] si no hay nada declarado como
/// critico: sin saber que hay que proteger, la pregunta no tiene sentido.
pub fn caminos_a_las_joyas(
    g: &GrafoAtaque,
    origen: &str,
) -> Result<Vec<CaminoAtaque>, ErrorPrediccion> {
    if g.activo(origen).is_none() {
        return Err(ErrorPrediccion::ActivoDesconocido(origen.to_string()));
    }
    let joyas: Vec<String> = g.joyas().map(|a| a.nombre.clone()).collect();
    if joyas.is_empty() {
        return Err(ErrorPrediccion::SinJoyasDeLaCorona);
    }

    let mut salida = Vec::new();
    for joya in joyas {
        if joya == origen {
            continue;
        }
        if let Some(c) = camino_mas_probable(g, origen, &joya)? {
            salida.push(c);
        }
    }
    salida.sort_by(|a, b| {
        b.probabilidad
            .partial_cmp(&a.probabilidad)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.destino.cmp(&b.destino))
    });
    Ok(salida)
}

#[cfg(test)]
mod pruebas {
    use aegis_itdr::grafo::Nivel;

    use super::*;
    use crate::grafo::{Activo, ClaseActivo, Evidencia, RelacionSerializable, Via};

    fn via(r: RelacionSerializable) -> Via {
        Via::Identidad(r)
    }

    /// La cadena clasica: un usuario raso llega a Administrador de Dominio.
    fn cadena_clasica() -> GrafoAtaque {
        let mut g = GrafoAtaque::nuevo();
        for (n, nivel, valor) in [
            ("alice", Nivel::Usuario, 10u8),
            ("pc-alice", Nivel::Usuario, 10),
            ("svc-backup", Nivel::Operador, 40),
            ("Domain Admins", Nivel::AdminDominio, 100),
        ] {
            let clase = if n.starts_with("pc-") {
                ClaseActivo::Endpoint
            } else {
                ClaseActivo::Identidad
            };
            g.agregar(Activo::nuevo(n, clase, nivel, valor)).unwrap();
        }
        g.conectar(Paso::nuevo(
            "alice",
            "pc-alice",
            via(RelacionSerializable::AutenticaEn),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "pc-alice",
            "svc-backup",
            via(RelacionSerializable::ControlaCredencialesDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "svc-backup",
            "Domain Admins",
            via(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        g
    }

    /// EL CALCULO, contra un valor hecho a mano. Si el motor deja de dar esto,
    /// esta mal, y no hay que discutirlo.
    #[test]
    fn la_probabilidad_del_camino_es_el_producto_de_sus_pasos() {
        let g = cadena_clasica();
        let c = camino_mas_probable(&g, "alice", "Domain Admins")
            .unwrap()
            .expect("hay camino");

        assert_eq!(c.saltos(), 3);
        // 0,60 · 0,95 · 0,99 = 0,5643
        let esperado = 0.60 * 0.95 * 0.99;
        assert!(
            (c.probabilidad - esperado).abs() < 1e-12,
            "p = {}, esperado {esperado}",
            c.probabilidad
        );
    }

    /// Dijkstra sobre −log p tiene que encontrar el camino de MAYOR producto,
    /// que no es el de menos saltos: un atajo improbable es peor que un rodeo
    /// facil, y ese es justo el error que comete una busqueda en anchura.
    #[test]
    fn el_camino_mas_probable_no_es_el_mas_corto() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["inicio", "puente", "joya"] {
            g.agregar(Activo::nuevo(
                n,
                ClaseActivo::Identidad,
                if n == "joya" {
                    Nivel::AdminDominio
                } else {
                    Nivel::Usuario
                },
                if n == "joya" { 100 } else { 10 },
            ))
            .unwrap();
        }
        // Atajo de un salto, muy improbable (segmentado: 0,15).
        g.conectar(Paso::nuevo("inicio", "joya", Via::RedSegmentada))
            .unwrap();
        // Rodeo de dos saltos, muy probable: 0,99 · 0,99 = 0,9801.
        g.conectar(Paso::nuevo(
            "inicio",
            "puente",
            via(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "puente",
            "joya",
            via(RelacionSerializable::MiembroDe),
        ))
        .unwrap();

        let c = camino_mas_probable(&g, "inicio", "joya").unwrap().unwrap();
        assert_eq!(c.saltos(), 2, "tiene que preferir el rodeo facil: {c:?}");
        assert!((c.probabilidad - 0.99 * 0.99).abs() < 1e-12);
    }

    /// EL RESULTADO SE PUEDE LEER. Es un requisito, no un adorno: esto autoriza
    /// aislar la maquina de un cliente.
    #[test]
    fn el_camino_se_explica_en_una_frase() {
        let g = cadena_clasica();
        let c = camino_mas_probable(&g, "alice", "Domain Admins")
            .unwrap()
            .unwrap();
        let texto = c.explicar();
        assert!(texto.contains("alice"));
        assert!(texto.contains("se autentica en"));
        assert!(texto.contains("tiene credenciales cacheadas de"));
        assert!(texto.contains("es miembro de"));
        assert!(texto.contains("Domain Admins"));
    }

    /// DETERMINISMO: el mismo grafo da el mismo camino, siempre. Un informe que
    /// cambia entre ejecuciones no se puede poner delante de nadie.
    #[test]
    fn dos_ejecuciones_sobre_el_mismo_grafo_dan_el_mismo_camino() {
        let g = cadena_clasica();
        let a = camino_mas_probable(&g, "alice", "Domain Admins").unwrap();
        for _ in 0..50 {
            assert_eq!(
                camino_mas_probable(&g, "alice", "Domain Admins").unwrap(),
                a
            );
        }
    }

    /// Y con empates exactos tambien: ahi es donde un orden de tabla hash
    /// haria que el resultado bailara.
    #[test]
    fn los_empates_se_rompen_de_forma_estable() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["inicio", "via-a", "via-b", "joya"] {
            g.agregar(Activo::nuevo(
                n,
                ClaseActivo::Identidad,
                if n == "joya" {
                    Nivel::AdminDominio
                } else {
                    Nivel::Usuario
                },
                if n == "joya" { 100 } else { 10 },
            ))
            .unwrap();
        }
        for intermedio in ["via-a", "via-b"] {
            g.conectar(Paso::nuevo(
                "inicio",
                intermedio,
                via(RelacionSerializable::MiembroDe),
            ))
            .unwrap();
            g.conectar(Paso::nuevo(
                intermedio,
                "joya",
                via(RelacionSerializable::MiembroDe),
            ))
            .unwrap();
        }
        let primero = camino_mas_probable(&g, "inicio", "joya").unwrap().unwrap();
        for _ in 0..100 {
            assert_eq!(
                camino_mas_probable(&g, "inicio", "joya").unwrap().unwrap(),
                primero,
                "con dos caminos identicos, el elegido tiene que ser siempre el mismo"
            );
        }
    }

    /// El eslabon que hay que cortar es el de probabilidad MAS ALTA: cortar el
    /// mas improbable es cortar lo que al atacante ya le costaba.
    #[test]
    fn el_eslabon_a_cortar_es_el_que_mas_baja_el_producto() {
        let g = cadena_clasica();
        let c = camino_mas_probable(&g, "alice", "Domain Admins")
            .unwrap()
            .unwrap();
        let eslabon = c.eslabon_mas_valioso().expect("hay pasos");
        assert_eq!(
            eslabon.destino, "Domain Admins",
            "el paso de 0,99 es el que mas baja el producto al cortarlo"
        );
    }

    #[test]
    fn sin_camino_se_dice_que_no_lo_hay_en_vez_de_inventarlo() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["islote", "joya"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Identidad, Nivel::Usuario, 10))
                .unwrap();
        }
        assert_eq!(camino_mas_probable(&g, "islote", "joya").unwrap(), None);
    }

    #[test]
    fn un_ciclo_no_cuelga_la_busqueda() {
        let mut g = GrafoAtaque::nuevo();
        for n in ["a", "b", "c"] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Identidad, Nivel::Usuario, 10))
                .unwrap();
        }
        g.conectar(Paso::nuevo("a", "b", via(RelacionSerializable::MiembroDe)))
            .unwrap();
        g.conectar(Paso::nuevo("b", "c", via(RelacionSerializable::MiembroDe)))
            .unwrap();
        g.conectar(Paso::nuevo("c", "a", via(RelacionSerializable::MiembroDe)))
            .unwrap();
        let c = camino_mas_probable(&g, "a", "c").unwrap().unwrap();
        assert_eq!(c.saltos(), 2);
    }

    #[test]
    fn un_activo_desconocido_se_rechaza_en_vez_de_devolver_que_no_hay_camino() {
        let g = cadena_clasica();
        assert!(matches!(
            camino_mas_probable(&g, "fantasma", "Domain Admins"),
            Err(ErrorPrediccion::ActivoDesconocido(_))
        ));
        assert!(matches!(
            camino_mas_probable(&g, "alice", "fantasma"),
            Err(ErrorPrediccion::ActivoDesconocido(_))
        ));
    }

    /// Sin joyas declaradas, el motor se NIEGA en vez de decir cualquier cosa
    /// con aplomo.
    #[test]
    fn sin_joyas_declaradas_el_motor_se_niega() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "a",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            10,
        ))
        .unwrap();
        assert_eq!(
            caminos_a_las_joyas(&g, "a"),
            Err(ErrorPrediccion::SinJoyasDeLaCorona)
        );
    }

    /// LA DEFENSA ANTI-MANIPULACION, de extremo a extremo: una arista que el
    /// atacante acaba de fabricar produce un camino mucho menos probable.
    #[test]
    fn un_camino_por_una_arista_recien_fabricada_sale_mucho_menos_probable() {
        let mut g = GrafoAtaque::nuevo();
        for (n, nivel, v) in [
            ("atacante", Nivel::Usuario, 10u8),
            ("victima", Nivel::Usuario, 10),
            ("joya", Nivel::AdminDominio, 100),
        ] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Identidad, nivel, v))
                .unwrap();
        }
        // El atacante acaba de autenticarse contra la victima: arista real,
        // pero recien nacida y vista una sola vez.
        g.conectar(
            Paso::nuevo(
                "atacante",
                "victima",
                via(RelacionSerializable::ControlaCredencialesDe),
            )
            .con_evidencia(Evidencia::recien_vista()),
        )
        .unwrap();
        g.conectar(Paso::nuevo(
            "victima",
            "joya",
            via(RelacionSerializable::MiembroDe),
        ))
        .unwrap();

        let c = camino_mas_probable(&g, "atacante", "joya")
            .unwrap()
            .unwrap();
        // 0,95 · 0,35 · 0,99 = 0,3292…, en vez de 0,9405.
        assert!(
            c.probabilidad < 0.4,
            "una arista recien fabricada no puede dar un camino casi seguro: {}",
            c.probabilidad
        );
    }

    #[test]
    fn los_caminos_a_las_joyas_salen_ordenados_de_mas_probable_a_menos() {
        let mut g = cadena_clasica();
        g.agregar(Activo::nuevo(
            "servidor-nomina",
            ClaseActivo::Servicio,
            Nivel::AdminLocal,
            95,
        ))
        .unwrap();
        g.conectar(Paso::nuevo("alice", "servidor-nomina", Via::RedSegmentada))
            .unwrap();

        let cs = caminos_a_las_joyas(&g, "alice").unwrap();
        assert_eq!(cs.len(), 2);
        for par in cs.windows(2) {
            assert!(par[0].probabilidad >= par[1].probabilidad);
        }
        assert_eq!(cs[0].destino, "Domain Admins");
    }
}
