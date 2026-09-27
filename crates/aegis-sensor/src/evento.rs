//! El evento del sensor: lo que se capturo EN EL KERNEL, en el instante del hecho.
//!
//! # Ninguna decision sobre datos que pudieron cambiar
//!
//! El atacante renombra el fichero entre la llamada y la lectura, o recicla el PID,
//! y un sensor que lee `/proc` DESPUES del evento decide sobre el estado nuevo, no
//! sobre el que provoco el evento. Eso no es un defecto de calidad: es una EVASION
//! documentada.
//!
//! Aqui el evento lleva sus campos ya CAPTURADOS —la ruta completa resuelta, los
//! argumentos, el `Eid` derivado— y **no hay ninguna operacion que vuelva a leer el
//! sistema**. Se verifica por lo que FALTA del tipo: no existe un `leer_proc()`. Lo
//! que el analisis necesita esta en el evento o no esta, y si no esta se dice.

use aegis_entidad::Eid;

use crate::familia::Familia;

/// Un evento capturado por el sensor.
///
/// Todos sus campos se fijaron en el kernel en el instante del evento. No hay
/// forma de re-leer el sistema desde aqui: lo que hay es lo que se capturo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evento {
    /// La familia a la que pertenece.
    pub familia: Familia,
    /// La entidad afectada, del modelo unico, derivada en el kernel.
    pub entidad: Eid,
    /// La ruta completa RESUELTA en el kernel, si el evento la tiene. Es la del
    /// instante del evento, no la de ahora.
    ruta_capturada: Option<String>,
    /// Los argumentos capturados, ya copiados (no punteros a memoria que pudo
    /// cambiar).
    argumentos: Vec<String>,
    /// Cuando ocurrio, en nanosegundos monotonos del kernel.
    pub cuando_ns: u64,
}

impl Evento {
    /// Construye un evento con sus campos ya capturados.
    #[must_use]
    pub fn nuevo(
        familia: Familia,
        entidad: Eid,
        ruta: Option<String>,
        argumentos: Vec<String>,
        cuando_ns: u64,
    ) -> Evento {
        Evento {
            familia,
            entidad,
            ruta_capturada: ruta,
            argumentos,
            cuando_ns,
        }
    }

    /// La ruta capturada en el kernel. **No relee el disco**: devuelve lo que se
    /// guardo. Si el fichero se renombro despues, esto sigue siendo la ruta del
    /// evento —que es la que importa—.
    #[must_use]
    pub fn ruta(&self) -> Option<&str> {
        self.ruta_capturada.as_deref()
    }

    /// Los argumentos capturados.
    #[must_use]
    pub fn argumentos(&self) -> &[String] {
        &self.argumentos
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    #[test]
    fn el_evento_conserva_lo_capturado_aunque_el_mundo_cambie_despues() {
        // TOCTOU: se captura la ruta en el instante del evento. Que "el sistema"
        // cambie despues (aqui, que borremos la variable original) no altera lo
        // que el evento guardo. No hay relectura posible.
        let maq = entidad::maquina("m-1");
        let e = Evento::nuevo(
            Familia::Fichero,
            entidad::ubicacion(&maq, "/tmp/objetivo-original"),
            Some("/tmp/objetivo-original".to_string()),
            vec!["O_WRONLY".to_string()],
            1_000,
        );
        // El evento sigue diciendo la ruta del instante del hecho.
        assert_eq!(e.ruta(), Some("/tmp/objetivo-original"));
        assert_eq!(e.argumentos(), &["O_WRONLY".to_string()]);
        // Y la entidad es la de esa ubicacion, no la de una relectura.
        assert_eq!(
            e.entidad,
            entidad::ubicacion(&maq, "/tmp/objetivo-original")
        );
    }

    #[test]
    fn dos_eventos_con_la_misma_captura_son_iguales() {
        // Determinismo: el evento es datos, no una vista viva del sistema.
        let ent = entidad::contenido("abcd");
        let a = Evento::nuevo(Familia::Proceso, ent.clone(), None, vec![], 5);
        let b = Evento::nuevo(Familia::Proceso, ent, None, vec![], 5);
        assert_eq!(a, b);
    }
}
