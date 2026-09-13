//! AegisPipeline: la canalizacion de registros del plano de control.
//!
//! # Donde encaja
//!
//! `aegis-ingest` corre en el **endpoint**: lee, normaliza, acota y entrega con
//! garantia de al-menos-una-vez. Esto corre en el **plano de control** y hace lo
//! que solo se puede hacer teniendo delante a toda la flota:
//!
//! 1. [`admision`] — **cuotas por inquilino**. Un cliente ruidoso no degrada a
//!    los demas, y el ruido de una aplicacion no apaga la telemetria de
//!    seguridad del mismo cliente.
//! 2. [`dedupe`] — **deduplicacion**. La entrega es al-menos-una-vez a
//!    proposito, asi que aqui llegan duplicados por contrato.
//! 3. [`orden`] — **orden por ocurrencia**. Un ataque repartido en dos dias no
//!    puede parecer un pico de un segundo.
//! 4. [`nube`] — **registros de nube**. CloudTrail, Azure Activity y GCP Audit
//!    no salen de ninguna maquina del cliente, asi que entran por aqui.
//!
//! # El orden de las etapas no es arbitrario
//!
//! ```text
//!   entrada --> ADMISION --> DEDUPLICACION --> ORDEN --> correlacion
//! ```
//!
//! * **La admision va primera** porque es la unica etapa cuyo coste es constante
//!   por evento. Ponerla detras de la deduplicacion significaria pagar el
//!   resumen y la busqueda de un evento que se iba a rechazar de todas formas,
//!   que es exactamente lo que un cliente ruidoso necesita para hacer dano.
//! * **La deduplicacion va antes que el orden** porque el reordenador tiene una
//!   cota de memoria: llenarla con duplicados obligaria a emitir eventos
//!   desordenados a la fuerza, y entonces el duplicado habria estropeado el
//!   orden de eventos legitimos.
//!
//! # El esquema es uno solo
//!
//! Este crate **no define** su propio evento: usa el de `aegis-ingest`. Dos
//! definiciones del mismo contrato divergen, y el dia que lo hagan se
//! correlacionaran cosas distintas creyendo que son la misma.

#![forbid(unsafe_code)]

pub mod admision;
pub mod dedupe;
pub mod nube;
pub mod orden;

pub use admision::{Admision, Cuota, Decision, Senal};
pub use dedupe::{Deduplicador, Veredicto};
pub use orden::Reordenador;

use aegis_ingest::esquema::Evento;

/// Lo que paso con un lote al atravesar la canalizacion entera.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Informe {
    /// Eventos que entraron.
    pub entraron: u64,
    /// Rechazados por cuota o saturacion.
    pub rechazados: u64,
    /// Descartados por duplicados.
    pub duplicados: u64,
    /// Eventos listos para correlacionar.
    pub salieron: u64,
}

/// La canalizacion completa del plano de control.
///
/// Existe para que el orden de las etapas no dependa de que quien llama se
/// acuerde: ver el encabezado del modulo.
#[derive(Debug, Default)]
pub struct Canalizacion {
    /// Cuotas y contrapresion.
    pub admision: Admision,
    /// Deduplicacion con ventana.
    pub dedupe: Deduplicador,
    /// Orden por ocurrencia.
    pub orden: Reordenador,
}

impl Canalizacion {
    /// Crea la canalizacion con los valores por defecto.
    #[must_use]
    pub fn nueva() -> Canalizacion {
        Canalizacion::default()
    }

    /// Pasa un lote por las tres etapas y devuelve lo que sale, en orden.
    pub fn procesar(&mut self, lote: Vec<Evento>, ahora_ns: u64) -> (Vec<Evento>, Informe) {
        let mut informe = Informe {
            entraron: lote.len() as u64,
            ..Informe::default()
        };
        let admitidos = self.admision.filtrar(lote, ahora_ns);
        informe.rechazados = informe.entraron - admitidos.len() as u64;

        let antes = admitidos.len() as u64;
        let unicos = self.dedupe.filtrar(admitidos, ahora_ns);
        informe.duplicados = antes - unicos.len() as u64;

        // El lote se admite ENTERO y solo despues se vacia lo vencido: si cada
        // admision vaciara, el lote saldria en el orden en que llego y no en el
        // suyo, que es justo lo que esta etapa existe para arreglar.
        let mut salida = Vec::new();
        for e in unicos {
            salida.extend(self.orden.admitir(e, ahora_ns));
        }
        salida.extend(self.orden.vencidos(ahora_ns));
        informe.salieron = salida.len() as u64;
        (salida, informe)
    }

    /// Vacia el reordenador: lo llama el apagado ordenado.
    pub fn vaciar(&mut self) -> Vec<Evento> {
        self.orden.vaciar()
    }
}

#[cfg(test)]
pub(crate) mod pruebas_comunes {
    use aegis_ingest::esquema::{
        Clase, ConfianzaReloj, Evento, Origen, Resultado, Severidad, VERSION,
    };
    use std::collections::BTreeMap;

    /// Un evento normalizado cualquiera, ya sellado.
    pub fn evento(inquilino: &str, ancla: &str, ocurrio_ns: u64) -> Evento {
        evento_en(inquilino, ancla, ocurrio_ns)
    }

    /// Igual, con la hora explicita en el nombre para las pruebas de orden.
    pub fn evento_en(inquilino: &str, ancla: &str, ocurrio_ns: u64) -> Evento {
        let mut e = Evento {
            version: VERSION,
            id: String::new(),
            ancla: ancla.to_string(),
            ocurrio_ns,
            observado_ns: ocurrio_ns,
            reloj: ConfianzaReloj::DelOrigen,
            clase: Clase::ActividadDelSistema,
            resultado: Resultado::Desconocido,
            severidad: Severidad::Info,
            origen: Origen::Fichero,
            anfitrion: "maquina".into(),
            inquilino: inquilino.to_string(),
            productor: "prog".into(),
            mensaje: "algo".into(),
            campos: BTreeMap::new(),
            crudo: None,
        };
        e.sellar();
        e
    }

    /// Un evento de prioridad de seguridad.
    pub fn evento_de_seguridad(inquilino: &str, ancla: &str, ocurrio_ns: u64) -> Evento {
        let mut e = evento_en(inquilino, ancla, ocurrio_ns);
        e.clase = Clase::HallazgoDeSeguridad;
        e.severidad = Severidad::Alta;
        e.origen = Origen::Agente;
        e.sellar();
        e
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::pruebas_comunes::{evento_de_seguridad, evento_en};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    #[test]
    fn un_lote_normal_atraviesa_las_tres_etapas() {
        let mut c = Canalizacion::nueva();
        let lote: Vec<_> = (0..10u64)
            .map(|i| evento_en("cliente", &format!("e{i}"), AHORA - 3600 * SEG + i))
            .collect();
        let (salida, informe) = c.procesar(lote, AHORA);
        assert_eq!(informe.entraron, 10);
        assert_eq!(informe.rechazados, 0);
        assert_eq!(informe.duplicados, 0);
        assert_eq!(salida.len(), 10);
        for par in salida.windows(2) {
            assert!(par[0].ocurrio_ns <= par[1].ocurrio_ns);
        }
    }

    #[test]
    fn el_mismo_lote_reenviado_no_duplica_nada() {
        // La entrega es al-menos-una-vez: reenviar es lo normal, no la
        // excepcion.
        let mut c = Canalizacion::nueva();
        let lote: Vec<_> = (0..10u64)
            .map(|i| evento_en("cliente", &format!("e{i}"), AHORA - 3600 * SEG + i))
            .collect();
        let (primera, _) = c.procesar(lote.clone(), AHORA);
        let (segunda, informe) = c.procesar(lote, AHORA);
        assert_eq!(primera.len(), 10);
        assert!(segunda.is_empty());
        assert_eq!(informe.duplicados, 10);
    }

    #[test]
    fn un_cliente_ruidoso_no_llena_el_reordenador_con_duplicados() {
        // POR QUE LA DEDUPLICACION VA ANTES QUE EL ORDEN. Llenar la ventana con
        // duplicados obligaria a emitir eventos LEGITIMOS desordenados.
        let mut c = Canalizacion::new_para_pruebas();
        let uno = evento_en("cliente", "repetido", AHORA);
        for _ in 0..1000 {
            let (_, _) = c.procesar(vec![uno.clone()], AHORA);
        }
        assert!(c.orden.en_vuelo() <= 1, "en vuelo {}", c.orden.en_vuelo());
        assert_eq!(c.orden.contadores().emitidos_a_la_fuerza, 0);
    }

    #[test]
    fn un_evento_rechazado_por_cuota_no_llega_a_pagar_el_resumen() {
        // POR QUE LA ADMISION VA PRIMERA: pagar el resumen de un evento que se
        // iba a rechazar es lo que un cliente ruidoso necesita para hacer dano.
        let mut c = Canalizacion::nueva();
        c.admision.configurar(
            "ruidoso",
            Cuota {
                eventos_por_segundo: 1,
                rafaga: 2,
                reserva_seguridad: 1,
            },
            AHORA,
        );
        let lote: Vec<_> = (0..500u64)
            .map(|i| evento_en("ruidoso", &format!("e{i}"), AHORA))
            .collect();
        let (_, informe) = c.procesar(lote, AHORA);
        assert!(informe.rechazados > 490, "{informe:?}");
        assert_eq!(
            c.dedupe.contadores().vistos,
            informe.entraron - informe.rechazados,
            "la deduplicacion solo vio lo que paso la cuota"
        );
    }

    #[test]
    fn el_apagado_no_deja_eventos_dentro() {
        let mut c = Canalizacion::nueva();
        let lote: Vec<_> = (0..50u64)
            .map(|i| evento_en("cliente", &format!("e{i}"), AHORA + i))
            .collect();
        let (salida, _) = c.procesar(lote, AHORA);
        let restantes = c.vaciar();
        assert_eq!(salida.len() + restantes.len(), 50);
        assert_eq!(c.orden.en_vuelo(), 0);
    }

    #[test]
    fn la_telemetria_de_seguridad_atraviesa_un_plano_de_control_saturado() {
        let mut c = Canalizacion::nueva();
        c.admision.publicar_ocupacion(95);
        let lote = vec![
            evento_en("cliente", "app", AHORA - 3600 * SEG),
            evento_de_seguridad("cliente", "grave", AHORA - 3600 * SEG),
        ];
        let (salida, informe) = c.procesar(lote, AHORA);
        assert_eq!(informe.rechazados, 1);
        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].ancla, "grave");
    }

    impl Canalizacion {
        /// Canalizacion con un reordenador diminuto, para poder provocar la cota
        /// sin escribir un millon de eventos.
        fn new_para_pruebas() -> Canalizacion {
            Canalizacion {
                orden: Reordenador::nuevo(orden::GRACIA_NS, 4),
                ..Canalizacion::default()
            }
        }
    }
}
