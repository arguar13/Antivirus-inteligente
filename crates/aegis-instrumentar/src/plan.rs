//! El plan de instrumentacion, y la operacion que este crate NO tiene.
//!
//! # La invariante, y por que es de este tipo concreto
//!
//! Un instrumentador escribe en el espacio de direcciones de un proceso: pone un
//! `0xCC` donde habia una instruccion, redirige una llamada, parchea una tabla.
//! Eso es exactamente lo que hace una inyeccion de codigo. La diferencia entre
//! una herramienta de analisis y una primitiva de ataque **no esta en la
//! intencion de quien la use**, esta en donde puede escribir.
//!
//! Por eso [`Plan`] **no tiene `aplicar`**. No lo tiene desactivado, ni detras de
//! una bandera, ni condicionado a un permiso: no existe. Un `Plan` es una lista
//! de direcciones con sus razones, y lo unico que se puede hacer con el es
//! leerlo.
//!
//! Quien lo aplica es la microVM, que esta en otro crate, corre en otra maquina
//! virtual y no comparte espacio de direcciones con nada del host. Ese reparto
//! es la invariante 9 del encargo: **el instrumentador no tiene variante de
//! «escribir en proceso» fuera de la microVM**.
//!
//! # Por que eso no es una formalidad
//!
//! Porque el agente corre con privilegios en cada maquina de la flota. Si este
//! crate tuviera un `aplicar(pid)`, cualquiera que se hiciera con el agente
//! tendria una primitiva de inyeccion escrita, probada y firmada por el
//! fabricante. La puerta `tools/verificar-instrumentar.sh` comprueba que esa
//! funcion no aparece, que es la unica forma de comprobar una ausencia.
//!
//! # Lo que si hace este crate
//!
//! Decidir **donde** merece la pena mirar, que es un problema de analisis y no
//! de ejecucion: un plan con mil puntos hace que la ejecucion tarde mil veces
//! mas y no dice mil veces mas. Ver [`crate::donde`].

use crate::punto::{Punto, Que};

/// Tope de puntos de un plan.
///
/// # Por que hay tope y no «los que hagan falta»
///
/// Porque cada punto cuesta tiempo de ejecucion, y una ejecucion instrumentada
/// que tarda diez minutos no se hace: se desactiva. Un plan con mil puntos no
/// dice mil veces mas que uno con cien; dice lo mismo mas tarde y con mas
/// probabilidad de que el proceso observado note que va lento y se comporte
/// distinto, que es precisamente lo que hace el codigo que interesa.
pub const MAX_PUNTOS: usize = 256;

/// Un plan de instrumentacion: donde mirar y por que.
///
/// **Es un dato inerte.** No tiene ninguna operacion que escriba en ningun
/// proceso; ver la cabecera del modulo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    puntos: Vec<Punto>,
    /// Cuantos puntos se descartaron por llegar al tope.
    ///
    /// Se cuenta y se dice: un plan recortado que no lo declarara produciria una
    /// traza con huecos que nadie sabria explicar.
    pub descartados: usize,
}

impl Plan {
    /// Un plan vacio.
    pub fn vacio() -> Plan {
        Plan::default()
    }

    /// Anade un punto. Devuelve si cupo.
    ///
    /// Los puntos repetidos no se anaden dos veces —observar la misma direccion
    /// dos veces no aporta nada y gasta presupuesto— y eso no cuenta como
    /// descarte.
    pub fn anadir(&mut self, p: Punto) -> bool {
        if self
            .puntos
            .iter()
            .any(|otro| otro.direccion == p.direccion && otro.que == p.que)
        {
            return true;
        }
        if self.puntos.len() >= MAX_PUNTOS {
            self.descartados += 1;
            return false;
        }
        self.puntos.push(p);
        true
    }

    /// Los puntos, ordenados por direccion.
    ///
    /// El orden es estable para que dos analisis del mismo binario produzcan el
    /// mismo plan y se puedan comparar dos ejecuciones.
    pub fn puntos(&self) -> Vec<&Punto> {
        let mut v: Vec<&Punto> = self.puntos.iter().collect();
        v.sort_by_key(|p| (p.direccion, p.que));
        v
    }

    /// Cuantos puntos tiene.
    pub fn cuantos(&self) -> usize {
        self.puntos.len()
    }

    /// Si esta vacio.
    pub fn vacio_esta(&self) -> bool {
        self.puntos.is_empty()
    }

    /// Cuantos puntos hay de cada clase.
    pub fn por_clase(&self, que: Que) -> usize {
        self.puntos.iter().filter(|p| p.que == que).count()
    }

    /// Si el plan se recorto.
    ///
    /// Con esto en cierto, una traza sin un suceso **no significa que no
    /// ocurriera**: puede que ese sitio no llevara punto. Es la misma distincion
    /// que la cobertura en `aegis-disasm`.
    pub fn se_recorto(&self) -> bool {
        self.descartados > 0
    }

    /// La frase con la que este plan aparece en un informe.
    pub fn frase(&self) -> String {
        if self.puntos.is_empty() {
            return "no se puso ningun punto de observacion".to_owned();
        }
        let mut s = format!(
            "{} puntos de observacion: {} de paso, {} de destino de transferencia, \
             {} de argumentos, {} de contenido escrito",
            self.puntos.len(),
            self.por_clase(Que::Paso),
            self.por_clase(Que::DestinoDeLaTransferencia),
            self.por_clase(Que::Argumentos),
            self.por_clase(Que::ContenidoEscrito)
        );
        if self.se_recorto() {
            s.push_str(&format!(
                ". EL PLAN SE RECORTO: {} puntos se quedaron fuera por el tope, asi que \
                 lo que no aparezca en la traza puede ser que no ocurriera o puede ser \
                 que ahi no hubiera punto",
                self.descartados
            ));
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn punto(d: u64) -> Punto {
        Punto::nuevo(d, Que::Paso, "una razon cualquiera").unwrap()
    }

    #[test]
    fn el_mismo_punto_dos_veces_no_ocupa_dos_sitios() {
        // Observar la misma direccion dos veces no aporta nada y gasta el
        // presupuesto que hace falta en otro sitio.
        let mut p = Plan::vacio();
        assert!(p.anadir(punto(0x1000)));
        assert!(p.anadir(punto(0x1000)));
        assert_eq!(p.cuantos(), 1);
        assert!(!p.se_recorto(), "un repetido no es un descarte");
    }

    #[test]
    fn el_plan_tiene_tope_y_dice_cuando_lo_alcanza() {
        // Un plan recortado que no lo declarara produciria una traza con huecos
        // que nadie sabria explicar.
        let mut p = Plan::vacio();
        for n in 0..(MAX_PUNTOS as u64 + 10) {
            p.anadir(punto(0x1000 + n * 4));
        }
        assert_eq!(p.cuantos(), MAX_PUNTOS);
        assert_eq!(p.descartados, 10);
        assert!(p.se_recorto());
        assert!(p.frase().contains("SE RECORTO"), "{}", p.frase());
    }

    #[test]
    fn los_puntos_salen_siempre_en_el_mismo_orden() {
        // Para que dos analisis del mismo binario produzcan el mismo plan y se
        // puedan comparar dos ejecuciones.
        let mut a = Plan::vacio();
        for d in [0x3000u64, 0x1000, 0x2000] {
            a.anadir(punto(d));
        }
        let mut b = Plan::vacio();
        for d in [0x1000u64, 0x2000, 0x3000] {
            b.anadir(punto(d));
        }
        let da: Vec<u64> = a.puntos().iter().map(|p| p.direccion).collect();
        let db: Vec<u64> = b.puntos().iter().map(|p| p.direccion).collect();
        assert_eq!(da, db);
        assert_eq!(da, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn un_plan_vacio_lo_dice_en_vez_de_parecer_que_no_habia_nada_que_ver() {
        let p = Plan::vacio();
        assert!(p.vacio_esta());
        assert!(p.frase().contains("ningun punto"), "{}", p.frase());
    }

    #[test]
    fn dos_observaciones_distintas_de_la_misma_direccion_si_caben() {
        // Saber que el control paso por una direccion y saber a donde fue desde
        // ahi son dos cosas distintas.
        let mut p = Plan::vacio();
        p.anadir(Punto::nuevo(0x1000, Que::Paso, "por algo").unwrap());
        p.anadir(Punto::nuevo(0x1000, Que::DestinoDeLaTransferencia, "por algo").unwrap());
        assert_eq!(p.cuantos(), 2);
    }
}
