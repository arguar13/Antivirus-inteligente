//! La cifra de cobertura: cuantos mensajes se entendieron y cuantos no.
//!
//! # Lo que ni Wireshark ni Zeek dan
//!
//! Los dos disecan mucho y los dos contestan lo mismo a la pregunta importante:
//! nada. Cuando un disector no entiende un mensaje, lo marca como malformado o lo
//! salta, y el analista ve una traza con menos lineas sin saber que faltan. La
//! diferencia entre «este flujo no llevaba nada» y «este flujo llevaba algo que
//! no supimos leer» no aparece en ninguna parte.
//!
//! Esa diferencia es un incidente. Un atacante que use una extension del
//! protocolo que el disector no conoce pasa por delante de un sensor que no
//! declara su cobertura, y el informe dice que no paso nada.
//!
//! # Que se cuenta
//!
//! Por disector y por protocolo: mensajes **entendidos**, mensajes
//! **reconocidos y no analizados** —se supo que eran, no se supo leerlos— y
//! mensajes **no reconocidos**. Los tres numeros, no uno.
//!
//! Con los tres, [`Cobertura::completa`] dice si de este flujo se puede concluir
//! algo. Sin ellos, la lista de hechos de un flujo es una afirmacion sobre el
//! flujo entero que solo es cierta si se entendio entero.

use std::collections::BTreeMap;

use aegis_wire::error::ErrorDiseccion;

/// Por que un mensaje no se analizo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Motivo {
    /// El tipo de mensaje se reconoce y este disector no lo analiza.
    ///
    /// Es un hueco **declarado**: se sabe que hay ahi y se sabe que no se miro.
    TipoNoImplementado,
    /// El mensaje esta cifrado y no hay clave.
    ///
    /// No es un fallo del disector: es que el contenido no esta. Distinguirlo de
    /// lo no implementado importa, porque uno se arregla escribiendo codigo y el
    /// otro no.
    Cifrado,
    /// El mensaje estaba incompleto en lo que se recibio.
    Truncado,
    /// El mensaje no cumple su propia especificacion.
    ///
    /// Puede ser un fallo del emisor y puede ser un intento de confundir al
    /// sensor. Las dos cosas son informacion.
    Malformado,
    /// No se reconocio ni el tipo.
    NoReconocido,
}

impl Motivo {
    /// Si esto se arregla escribiendo codigo.
    ///
    /// La distincion que hace util el recuento: lo no implementado es una tarea,
    /// y lo cifrado es un limite. Mezclarlos haria que la cifra de cobertura
    /// pareciera un problema de esfuerzo cuando no lo es.
    pub fn se_arregla_escribiendo_codigo(self) -> bool {
        matches!(self, Motivo::TipoNoImplementado | Motivo::NoReconocido)
    }

    /// El motivo que corresponde a un error del lector acotado.
    ///
    /// La traduccion no es mecanica y por eso esta escrita una sola vez: un
    /// buffer que se acaba es **truncado** —puede ser una captura cortada—, y
    /// una longitud declarada que no cabe es **malformado**, porque ahi el
    /// emisor mintio. Confundirlos borraria justo la senal: un protocolo
    /// malformado a proposito es una tecnica de evasion conocida.
    pub fn de_error(e: &ErrorDiseccion) -> Motivo {
        match e {
            ErrorDiseccion::Truncado { .. } => Motivo::Truncado,
            ErrorDiseccion::NoEsEsteProtocolo(_) => Motivo::NoReconocido,
            ErrorDiseccion::LongitudImposible { .. }
            | ErrorDiseccion::ValorInvalido { .. }
            | ErrorDiseccion::LimiteExcedido { .. }
            | ErrorDiseccion::AnidamientoExcesivo { .. }
            | ErrorDiseccion::CodificacionInvalida(_) => Motivo::Malformado,
        }
    }

    /// Como se lee en un informe.
    pub fn frase(self) -> &'static str {
        match self {
            Motivo::TipoNoImplementado => {
                "se reconocio el tipo de mensaje y este disector no lo analiza"
            }
            Motivo::Cifrado => {
                "el mensaje va cifrado y no hay clave: el contenido no esta, y eso no lo \
                 arregla escribir mas codigo"
            }
            Motivo::Truncado => "el mensaje llego incompleto",
            Motivo::Malformado => {
                "el mensaje no cumple su propia especificacion, que puede ser un fallo \
                 del emisor o un intento de confundir al sensor"
            }
            Motivo::NoReconocido => "no se reconocio ni el tipo de mensaje",
        }
    }
}

/// Lo que un disector entendio y lo que no.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cobertura {
    /// Mensajes analizados por completo.
    pub entendidos: u64,
    /// Los que no, con su motivo.
    pub sin_analizar: BTreeMap<Motivo, u64>,
}

impl Cobertura {
    /// Sin nada visto todavia.
    pub fn nueva() -> Cobertura {
        Cobertura::default()
    }

    /// Anota un mensaje entendido.
    pub fn entendido(&mut self) {
        self.entendidos += 1;
    }

    /// Anota un mensaje que no se analizo, con su motivo.
    pub fn sin_analizar(&mut self, m: Motivo) {
        *self.sin_analizar.entry(m).or_insert(0) += 1;
    }

    /// Cuantos mensajes se vieron en total.
    pub fn vistos(&self) -> u64 {
        self.entendidos + self.sin_analizar.values().sum::<u64>()
    }

    /// Cuantos se quedaron sin analizar.
    pub fn perdidos(&self) -> u64 {
        self.sin_analizar.values().sum()
    }

    /// Si se entendio todo lo que se vio.
    ///
    /// **Es lo unico que autoriza a leer una lista de hechos vacia como «este
    /// flujo no llevaba nada».** Con esto en falso, la lista significa «esto es
    /// lo que supimos leer», que es otra frase.
    pub fn completa(&self) -> bool {
        self.sin_analizar.is_empty()
    }

    /// Que fraccion se entendio, en centesimas.
    ///
    /// Devuelve `None` cuando no se vio ningun mensaje: un cero por division
    /// entre cero se leeria como «no se entendio nada», que es lo contrario de
    /// la verdad.
    pub fn fraccion(&self) -> Option<u8> {
        let v = self.vistos();
        if v == 0 {
            return None;
        }
        // En 128 bits a proposito: `entendidos * 100` se sale de `u64` con
        // pocos millones de mensajes, y al saturar daria una fraccion de uno por
        // ciento sobre una cobertura perfecta — el peor error posible en la
        // cifra que decide si se puede leer el silencio.
        let f = (u128::from(self.entendidos) * 100) / u128::from(v);
        Some(f.min(100) as u8)
    }

    /// Cuantos de los perdidos se arreglarian escribiendo codigo.
    ///
    /// Es la cifra que de verdad sirve para decidir en que trabajar: separa la
    /// deuda del limite.
    pub fn perdidos_por_falta_de_codigo(&self) -> u64 {
        self.sin_analizar
            .iter()
            .filter(|(m, _)| m.se_arregla_escribiendo_codigo())
            .map(|(_, n)| *n)
            .sum()
    }

    /// Suma otra cobertura a esta.
    pub fn sumar(&mut self, otra: &Cobertura) {
        self.entendidos += otra.entendidos;
        for (m, n) in &otra.sin_analizar {
            *self.sin_analizar.entry(*m).or_insert(0) += n;
        }
    }

    /// La frase con la que esta cobertura aparece en un informe.
    pub fn frase(&self) -> String {
        let Some(f) = self.fraccion() else {
            return "no se vio ningun mensaje de este protocolo".to_owned();
        };
        if self.completa() {
            return format!(
                "se entendieron los {} mensajes vistos ({f}%)",
                self.entendidos
            );
        }
        let detalle: Vec<String> = self
            .sin_analizar
            .iter()
            .map(|(m, n)| format!("{n} porque {}", m.frase()))
            .collect();
        format!(
            "se entendieron {} de {} mensajes ({f}%); los {} restantes NO SE ANALIZARON: \
             {}. Lo que no aparezca entre los hechos puede ser que no ocurriera o puede \
             ser que estuviera en uno de esos",
            self.entendidos,
            self.vistos(),
            self.perdidos(),
            detalle.join(", ")
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_cobertura_entera_autoriza_a_leer_el_silencio() {
        let mut c = Cobertura::nueva();
        for _ in 0..10 {
            c.entendido();
        }
        assert!(c.completa());
        assert_eq!(c.fraccion(), Some(100));
        assert!(c.frase().contains("se entendieron los 10"), "{}", c.frase());
    }

    #[test]
    fn un_mensaje_sin_analizar_quita_ese_permiso_y_lo_dice() {
        // La diferencia entre «este flujo no llevaba nada» y «llevaba algo que no
        // supimos leer». Un atacante que use una extension que el disector no
        // conoce pasa por delante de un sensor que no declara esto.
        let mut c = Cobertura::nueva();
        for _ in 0..9 {
            c.entendido();
        }
        c.sin_analizar(Motivo::TipoNoImplementado);
        assert!(!c.completa());
        assert_eq!(c.fraccion(), Some(90));
        assert!(c.frase().contains("NO SE ANALIZARON"), "{}", c.frase());
        assert!(
            c.frase().contains("puede ser que no ocurriera"),
            "{}",
            c.frase()
        );
    }

    #[test]
    fn lo_cifrado_y_lo_no_implementado_se_cuentan_por_separado() {
        // Uno se arregla escribiendo codigo y el otro no. Mezclarlos haria que la
        // cifra de cobertura pareciera un problema de esfuerzo cuando no lo es.
        let mut c = Cobertura::nueva();
        c.sin_analizar(Motivo::Cifrado);
        c.sin_analizar(Motivo::Cifrado);
        c.sin_analizar(Motivo::TipoNoImplementado);
        assert_eq!(c.perdidos(), 3);
        assert_eq!(c.perdidos_por_falta_de_codigo(), 1);
        assert!(!Motivo::Cifrado.se_arregla_escribiendo_codigo());
        assert!(Motivo::TipoNoImplementado.se_arregla_escribiendo_codigo());
    }

    #[test]
    fn sin_ningun_mensaje_visto_no_se_reporta_cero_por_ciento() {
        // Un cero por division entre cero se leeria como «no se entendio nada»,
        // que es lo contrario de la verdad: no habia nada que entender.
        let c = Cobertura::nueva();
        assert_eq!(c.fraccion(), None);
        assert!(c.frase().contains("ningun mensaje"), "{}", c.frase());
    }

    #[test]
    fn dos_coberturas_se_suman_sin_perder_los_motivos() {
        // El motor las junta de todos los flujos, y si la suma perdiera los
        // motivos la cifra global no diria en que trabajar.
        let mut a = Cobertura::nueva();
        a.entendido();
        a.sin_analizar(Motivo::Cifrado);
        let mut b = Cobertura::nueva();
        b.entendido();
        b.sin_analizar(Motivo::Malformado);
        a.sumar(&b);
        assert_eq!(a.entendidos, 2);
        assert_eq!(a.perdidos(), 2);
        assert_eq!(a.sin_analizar.len(), 2);
    }

    #[test]
    fn la_fraccion_no_pasa_de_cien() {
        let mut c = Cobertura::nueva();
        c.entendidos = u64::MAX;
        assert_eq!(c.fraccion(), Some(100));
    }

    #[test]
    fn cada_motivo_explica_algo_distinto() {
        // Un motivo que no se distinga de otro no aporta nada al recuento y
        // convierte la cifra en ruido.
        let mut vistas = std::collections::BTreeSet::new();
        for m in [
            Motivo::TipoNoImplementado,
            Motivo::Cifrado,
            Motivo::Truncado,
            Motivo::Malformado,
            Motivo::NoReconocido,
        ] {
            assert!(vistas.insert(m.frase()), "{m:?} repite la frase de otro");
            assert!(m.frase().len() > 15, "{m:?}");
        }
    }
}
