//! Los modos de operacion, y por que el que viene puesto importa tanto.
//!
//! # Un IPS que llega bloqueando tira la produccion el primer dia
//!
//! Es la diferencia practica entre un IDS y un IPS: un falso positivo en un IDS
//! es una alerta que alguien descarta; en un IPS es una **interrupcion de
//! servicio**. Y los falsos positivos no son hipoteticos —toda regla nueva los
//! tiene hasta que se ajusta contra el trafico real del cliente, que nadie
//! conoce de antemano.
//!
//! Por eso el modo por defecto es [`Modo::SoloDeteccion`] y el camino natural es
//! escalonado:
//!
//! 1. **Solo deteccion.** Se ve lo que hay, no se toca nada.
//! 2. **Bloqueo con aprendizaje.** Se registra lo que se HABRIA cortado, con su
//!    regla y su flujo, sin cortarlo. El cliente mira esa lista y decide.
//! 3. **Bloqueo.** Solo cuando la lista anterior ya no tiene sorpresas.
//!
//! El paso 2 es el que hace posible el 3 sin apostar. Sin el, activar el bloqueo
//! es un salto a ciegas sobre la red de otro.
//!
//! # El modo lo aplica el KERNEL
//!
//! Estos valores viajan al mapa de configuracion eBPF y es el programa TC quien
//! los comprueba antes de cortar. No es un detalle de implementacion: si la
//! decision de cortar viviera solo aqui arriba, un fallo de logica en este crate
//! cortaria trafico de un cliente que habia pedido expresamente que no se
//! cortara nada. Con la comprobacion abajo, para que eso ocurra hace falta
//! cambiar el modo **a proposito**.

/// Modo de operacion del IPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Modo {
    /// Se detecta y se alerta. No se corta nada, nunca.
    ///
    /// Es el modo por defecto, y lo es a proposito: ver la doctrina del modulo.
    #[default]
    SoloDeteccion,

    /// Se registra lo que se habria cortado, sin cortarlo.
    ///
    /// La diferencia con [`Modo::SoloDeteccion`] no es lo que se hace con el
    /// trafico —en los dos casos, nada— sino lo que se ANOTA: aqui cada
    /// veredicto de corte se escribe con su regla y su flujo, para que el
    /// cliente tenga la lista exacta de lo que perderia al activar el bloqueo.
    BloqueoConAprendizaje,

    /// Se corta de verdad.
    Bloqueo,
}

impl Modo {
    /// Si en este modo se corta trafico de verdad.
    #[must_use]
    pub fn corta(self) -> bool {
        matches!(self, Modo::Bloqueo)
    }

    /// El valor que entiende el programa eBPF.
    ///
    /// Tiene que coincidir con `AEGIS_IPS_MODO_*` de `aegis_bpf_common.h`.
    #[must_use]
    pub fn codigo(self) -> u32 {
        match self {
            Modo::SoloDeteccion => 0,
            Modo::Bloqueo => 1,
            Modo::BloqueoConAprendizaje => 2,
        }
    }

    /// Nombre estable, para registros e informes.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Modo::SoloDeteccion => "solo-deteccion",
            Modo::BloqueoConAprendizaje => "bloqueo-con-aprendizaje",
            Modo::Bloqueo => "bloqueo",
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// EL VALOR POR DEFECTO ES UNA DECISION DE SEGURIDAD, no una preferencia.
    /// Si algun dia alguien lo cambia, que sea rompiendo esta prueba.
    #[test]
    fn el_modo_por_defecto_no_corta_nada() {
        assert_eq!(Modo::default(), Modo::SoloDeteccion);
        assert!(!Modo::default().corta());
    }

    /// SOLO uno de los tres modos corta. El de aprendizaje existe precisamente
    /// para no cortar, y confundirlo con el de bloqueo seria romper la promesa
    /// que hace posible que un cliente lo active.
    #[test]
    fn solo_el_modo_de_bloqueo_corta() {
        assert!(Modo::Bloqueo.corta());
        assert!(!Modo::BloqueoConAprendizaje.corta());
        assert!(!Modo::SoloDeteccion.corta());
    }

    /// Los codigos son un contrato con el programa eBPF: el kernel compara
    /// contra estos numeros por cada paquete. Cambiarlos sin cambiar el header
    /// haria que el modo dejara de significar lo que dice.
    #[test]
    fn los_codigos_coinciden_con_el_contrato_del_kernel() {
        assert_eq!(Modo::SoloDeteccion.codigo(), 0);
        assert_eq!(Modo::Bloqueo.codigo(), 1);
        assert_eq!(Modo::BloqueoConAprendizaje.codigo(), 2);
    }
}
