//! Lo que devuelve una ejecucion instrumentada, y lo que su silencio significa.
//!
//! # La pregunta que toda traza tiene que poder contestar
//!
//! «Esto no aparece en la traza» admite tres lecturas y solo una es buena:
//!
//! 1. No ocurrio.
//! 2. Ocurrio en un sitio donde no habia punto de observacion.
//! 3. Ocurrio, pero la ejecucion se corto antes.
//!
//! Un sistema que no las distinga acaba diciendo que una muestra no hace algo
//! cuando lo que pasa es que no se miro. Por eso [`Traza`] lleva **el plan con el
//! que se tomo** y **como termino la ejecucion**: con las dos cosas, las tres
//! lecturas se separan.
//!
//! # Por que este modulo no ejecuta nada
//!
//! Porque la ejecucion la hace la microVM, en otro crate y en otra maquina
//! virtual. Aqui solo esta el modelo de lo que devuelve, para que el analisis de
//! esa traza no dependa de como se tomo. Ver [`crate::plan`].

use std::collections::BTreeMap;

use crate::plan::Plan;
use crate::punto::Que;

/// Como termino una ejecucion instrumentada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Final {
    /// El programa termino por su cuenta.
    Termino {
        /// Con que codigo.
        codigo: i32,
    },
    /// Se agoto el tiempo que se le dio.
    ///
    /// Es lo normal con una muestra que espera, y no es un fallo: es el limite
    /// que se le puso. Lo que no puede es confundirse con «termino y no hizo
    /// nada».
    SeAgotoElTiempo,
    /// Se paro al llegar al tope de sucesos.
    SeLlenoLaTraza,
    /// La ejecucion no llego a arrancar.
    NoArranco {
        /// Por que.
        porque: String,
    },
}

impl Final {
    /// Si la ejecucion llego hasta el final del programa.
    ///
    /// **Es lo unico que autoriza a leer un silencio como «no ocurrio».**
    pub fn completa(&self) -> bool {
        matches!(self, Final::Termino { .. })
    }

    /// Como se lee en un informe.
    pub fn frase(&self) -> String {
        match self {
            Final::Termino { codigo } => format!("el programa termino por su cuenta ({codigo})"),
            Final::SeAgotoElTiempo => {
                "SE AGOTO EL TIEMPO: lo que no aparece aqui puede no haber ocurrido o puede \
                 no haber dado tiempo"
                    .to_owned()
            }
            Final::SeLlenoLaTraza => {
                "SE LLENO LA TRAZA: a partir de cierto punto ya no se anoto nada".to_owned()
            }
            Final::NoArranco { porque } => format!("LA EJECUCION NO ARRANCO: {porque}"),
        }
    }
}

/// Un suceso observado en un punto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suceso {
    /// En que punto del plan.
    pub donde: u64,
    /// Que se observaba ahi.
    pub que: Que,
    /// Lo que se vio, en el lenguaje de lo observado.
    pub valor: String,
    /// El orden en que ocurrio.
    ///
    /// Un numero de secuencia y no una marca de reloj: el orden es lo que dice
    /// algo —«escribio y despues salto ahi»— y el reloj de una ejecucion
    /// instrumentada no se parece al de una normal.
    pub orden: u64,
}

/// Tope de sucesos de una traza.
///
/// Un bucle instrumentado produce millones de sucesos identicos. Sin tope, la
/// traza de una muestra construida para eso llena la memoria del analizador.
pub const MAX_SUCESOS: usize = 100_000;

/// Lo que devolvio una ejecucion instrumentada.
#[derive(Debug, Clone)]
pub struct Traza {
    sucesos: Vec<Suceso>,
    /// El plan con el que se tomo.
    ///
    /// Va dentro y no al lado: sin el, un silencio no se puede interpretar.
    pub plan: Plan,
    /// Como termino.
    pub final_: Final,
    /// Cuantos sucesos se descartaron por el tope.
    pub descartados: u64,
}

impl Traza {
    /// Una traza vacia de una ejecucion que no arranco.
    pub fn no_arranco(plan: Plan, porque: impl Into<String>) -> Traza {
        Traza {
            sucesos: Vec::new(),
            plan,
            final_: Final::NoArranco {
                porque: porque.into(),
            },
            descartados: 0,
        }
    }

    /// Construye una traza con sus sucesos.
    pub fn nueva(plan: Plan, final_: Final, sucesos: Vec<Suceso>) -> Traza {
        let descartados = sucesos.len().saturating_sub(MAX_SUCESOS) as u64;
        let mut sucesos = sucesos;
        sucesos.truncate(MAX_SUCESOS);
        sucesos.sort_by_key(|s| s.orden);
        Traza {
            sucesos,
            plan,
            final_,
            descartados,
        }
    }

    /// Los sucesos, en el orden en que ocurrieron.
    pub fn sucesos(&self) -> &[Suceso] {
        &self.sucesos
    }

    /// Si de esta traza se puede concluir que algo **no** ocurrio.
    ///
    /// Hacen falta las tres cosas: que la ejecucion llegara al final, que el
    /// plan no se recortara y que la traza no se llenara. Con cualquiera a
    /// medias, un silencio no dice nada.
    pub fn el_silencio_significa_algo(&self) -> bool {
        self.final_.completa() && !self.plan.se_recorto() && self.descartados == 0
    }

    /// Si en la traza aparece algun suceso de esta clase.
    pub fn hubo(&self, que: Que) -> bool {
        self.sucesos.iter().any(|s| s.que == que)
    }

    /// Los destinos a los que fueron las transferencias que el analisis estatico
    /// no pudo resolver.
    ///
    /// Es el producto mas valioso de una ejecucion instrumentada: responde
    /// exactamente las preguntas que el analisis estatico dejo abiertas, y esos
    /// destinos se pueden volver a desensamblar.
    pub fn destinos_descubiertos(&self) -> BTreeMap<u64, Vec<&str>> {
        let mut m: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
        for s in &self.sucesos {
            if s.que == Que::DestinoDeLaTransferencia {
                let v = m.entry(s.donde).or_default();
                if !v.contains(&s.valor.as_str()) {
                    v.push(&s.valor);
                }
            }
        }
        m
    }

    /// Los puntos del plan por los que NO paso nada.
    ///
    /// Solo significa «no se ejecuto» cuando
    /// [`Traza::el_silencio_significa_algo`]. Se devuelve igualmente porque
    /// saber que parte del binario no corrio es informacion aunque sea parcial.
    pub fn sin_visitar(&self) -> Vec<u64> {
        let visitados: Vec<u64> = self.sucesos.iter().map(|s| s.donde).collect();
        let mut v: Vec<u64> = self
            .plan
            .puntos()
            .iter()
            .map(|p| p.direccion)
            .filter(|d| !visitados.contains(d))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// La frase con la que esta traza aparece en un informe.
    pub fn frase(&self) -> String {
        let mut s = format!(
            "{} sucesos sobre un plan de {} puntos; {}",
            self.sucesos.len(),
            self.plan.cuantos(),
            self.final_.frase()
        );
        if self.descartados > 0 {
            s.push_str(&format!(
                ". SE DESCARTARON {} sucesos por el tope de la traza",
                self.descartados
            ));
        }
        if !self.el_silencio_significa_algo() {
            s.push_str(
                ". LO QUE NO APAREZCA AQUI PUEDE SER QUE NO OCURRIERA O PUEDE SER QUE NO \
                 SE MIRARA",
            );
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::punto::Punto;

    fn plan_de(n: u64) -> Plan {
        let mut p = Plan::vacio();
        for i in 0..n {
            p.anadir(Punto::nuevo(0x1000 + i * 8, Que::Paso, "una razon").unwrap());
        }
        p
    }

    fn suceso(donde: u64, que: Que, valor: &str, orden: u64) -> Suceso {
        Suceso {
            donde,
            que,
            valor: valor.to_owned(),
            orden,
        }
    }

    #[test]
    fn un_silencio_solo_significa_algo_si_la_ejecucion_llego_al_final() {
        // Las tres lecturas de «esto no aparece en la traza», separadas.
        let entera = Traza::nueva(plan_de(3), Final::Termino { codigo: 0 }, vec![]);
        assert!(entera.el_silencio_significa_algo());

        let cortada = Traza::nueva(plan_de(3), Final::SeAgotoElTiempo, vec![]);
        assert!(!cortada.el_silencio_significa_algo());
        assert!(cortada.frase().contains("SE AGOTO"), "{}", cortada.frase());
    }

    #[test]
    fn un_plan_recortado_tambien_quita_significado_al_silencio() {
        // La ejecucion llego al final, pero habia sitios sin punto de
        // observacion. Eso es la segunda de las tres lecturas.
        let mut plan = plan_de(0);
        for n in 0..(crate::plan::MAX_PUNTOS as u64 + 5) {
            plan.anadir(Punto::nuevo(0x1000 + n * 8, Que::Paso, "una razon").unwrap());
        }
        assert!(plan.se_recorto());
        let t = Traza::nueva(plan, Final::Termino { codigo: 0 }, vec![]);
        assert!(!t.el_silencio_significa_algo());
    }

    #[test]
    fn una_traza_llena_tambien_lo_quita_y_lo_dice() {
        let sucesos: Vec<Suceso> = (0..(MAX_SUCESOS as u64 + 10))
            .map(|n| suceso(0x1000, Que::Paso, "si", n))
            .collect();
        let t = Traza::nueva(plan_de(1), Final::Termino { codigo: 0 }, sucesos);
        assert_eq!(t.sucesos().len(), MAX_SUCESOS);
        assert_eq!(t.descartados, 10);
        assert!(!t.el_silencio_significa_algo());
        assert!(t.frase().contains("SE DESCARTARON"), "{}", t.frase());
    }

    #[test]
    fn los_destinos_descubiertos_son_lo_que_el_analisis_estatico_no_supo() {
        // El producto mas valioso de una ejecucion instrumentada: responde
        // exactamente las preguntas que el analisis estatico dejo abiertas.
        let t = Traza::nueva(
            plan_de(1),
            Final::Termino { codigo: 0 },
            vec![
                suceso(0x1000, Que::DestinoDeLaTransferencia, "0x401000", 1),
                suceso(0x1000, Que::DestinoDeLaTransferencia, "0x402000", 2),
                suceso(0x1000, Que::DestinoDeLaTransferencia, "0x401000", 3),
            ],
        );
        let d = t.destinos_descubiertos();
        assert_eq!(d.len(), 1);
        assert_eq!(d[&0x1000], vec!["0x401000", "0x402000"]);
    }

    #[test]
    fn los_puntos_por_los_que_no_paso_nada_se_pueden_consultar() {
        let t = Traza::nueva(
            plan_de(3),
            Final::Termino { codigo: 0 },
            vec![suceso(0x1000, Que::Paso, "si", 1)],
        );
        assert_eq!(t.sin_visitar(), vec![0x1008, 0x1010]);
    }

    #[test]
    fn los_sucesos_salen_en_el_orden_en_que_ocurrieron() {
        // El orden es lo que dice algo: «escribio y despues salto ahi» no es lo
        // mismo que «salto ahi y despues escribio».
        let t = Traza::nueva(
            plan_de(2),
            Final::Termino { codigo: 0 },
            vec![
                suceso(0x1008, Que::Paso, "b", 7),
                suceso(0x1000, Que::Paso, "a", 2),
            ],
        );
        let ordenes: Vec<u64> = t.sucesos().iter().map(|s| s.orden).collect();
        assert_eq!(ordenes, vec![2, 7]);
    }

    #[test]
    fn una_ejecucion_que_no_arranco_no_se_confunde_con_una_que_no_hizo_nada() {
        // Las dos producen una traza vacia, y solo una significa algo.
        let t = Traza::no_arranco(plan_de(3), "el binario no es de esta arquitectura");
        assert!(t.sucesos().is_empty());
        assert!(!t.el_silencio_significa_algo());
        assert!(t.frase().contains("NO ARRANCO"), "{}", t.frase());
    }
}
