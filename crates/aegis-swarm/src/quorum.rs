//! Corroboro: cuando la evidencia de varios pares basta para actuar.
//!
//! # Por que contar pares DISTINTOS y no observaciones
//!
//! El error que hay que no cometer es contar mensajes. Un par comprometido puede
//! emitir mil observaciones de lo mismo en un segundo; si el contador subiera
//! con cada una, un solo equipo alcanzaria cualquier umbral y el quorum seria
//! decorativo. Se cuentan **origenes distintos**, y el segundo mensaje del mismo
//! origen no suma nada.
//!
//! # La ventana, y por que no es opcional
//!
//! Un corroboro sin caducidad acumula para siempre: tres equipos que vieron algo
//! en marzo, junio y octubre no son tres testigos del mismo incidente, son tres
//! hechos sueltos. La ventana ([`Corroboro::ventana_seg`]) exige que los K
//! testigos coincidan **en el tiempo**, que es lo que hace que la evidencia
//! signifique «esto esta pasando ahora».
//!
//! # Lo que este modulo NO decide
//!
//! No decide que hacer. Dice si hay corroboro suficiente y quien lo aporto; la
//! politica local decide la accion, con el mismo criterio con el que decide ante
//! una deteccion propia. Mantener esa separacion es lo que impide que el
//! protocolo de red acabe mandando sobre el motor de respuesta.

use std::collections::BTreeMap;

use crate::observacion::Observacion;

/// Umbral por defecto de pares distintos.
///
/// Tres es el minimo que hace falta para que el fallo de un solo equipo no
/// mueva nada y para que dos equipos comprometidos tampoco basten.
pub const UMBRAL_POR_DEFECTO: usize = 3;

/// Ventana por defecto en la que los testigos tienen que coincidir: una hora.
pub const VENTANA_POR_DEFECTO_SEG: u64 = 3600;

/// Tope de indicadores distintos que se siguen a la vez.
///
/// Sin el, un par que emita observaciones de indicadores siempre nuevos hace
/// crecer la memoria del receptor sin limite: es una denegacion de servicio con
/// mensajes perfectamente validos.
pub const MAX_INDICADORES_SEGUIDOS: usize = 4096;

/// Tope de testigos que se recuerdan por indicador.
pub const MAX_TESTIGOS_POR_INDICADOR: usize = 64;

/// Estado del corroboro de un indicador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstadoCorroboro {
    /// Quienes lo han visto, con el momento de su observacion mas reciente.
    pub testigos: BTreeMap<String, u64>,
    /// La observacion mas reciente, para poder describir el hallazgo.
    pub ultima: Observacion,
}

impl EstadoCorroboro {
    /// Testigos dentro de la ventana que termina en `ahora`.
    #[must_use]
    pub fn testigos_vigentes(&self, ahora: u64, ventana: u64) -> usize {
        self.testigos
            .values()
            .filter(|t| ahora.saturating_sub(**t) <= ventana)
            .count()
    }
}

/// El resultado de incorporar una observacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// Aun no hay bastantes testigos distintos.
    Insuficiente {
        /// Testigos vigentes ahora mismo.
        testigos: usize,
        /// Los que harian falta.
        umbral: usize,
    },
    /// Se alcanzo el umbral **en esta observacion**.
    ///
    /// Se emite una sola vez por indicador y ventana: la politica de respuesta no
    /// puede recibir el mismo hallazgo cien veces porque lleguen cien mensajes.
    Corroborado {
        /// La observacion que cerro el quorum.
        observacion: Observacion,
        /// Quienes lo vieron.
        testigos: Vec<String>,
    },
    /// Ya estaba corroborado y ya se aviso.
    YaAvisado,
    /// El emisor ya habia dicho esto: no suma.
    Repetido,
}

/// Acumulador de corroboro.
#[derive(Debug, Clone)]
pub struct Corroboro {
    /// Pares distintos que hacen falta.
    pub umbral: usize,
    /// Ventana en la que tienen que coincidir.
    pub ventana_seg: u64,
    estados: BTreeMap<(u8, String), EstadoCorroboro>,
    avisados: BTreeMap<(u8, String), u64>,
}

impl Default for Corroboro {
    fn default() -> Corroboro {
        Corroboro::nuevo(UMBRAL_POR_DEFECTO, VENTANA_POR_DEFECTO_SEG)
    }
}

impl Corroboro {
    /// Nuevo acumulador.
    ///
    /// Un umbral de 0 o 1 se sube a 2: con 1 el quorum no existe —cualquier par
    /// suelto movería a la flota— y aceptarlo en silencio convertiria un error de
    /// configuracion en una via de ataque.
    #[must_use]
    pub fn nuevo(umbral: usize, ventana_seg: u64) -> Corroboro {
        Corroboro {
            umbral: umbral.max(2),
            ventana_seg: ventana_seg.max(1),
            estados: BTreeMap::new(),
            avisados: BTreeMap::new(),
        }
    }

    /// Indicadores en seguimiento.
    #[must_use]
    pub fn seguidos(&self) -> usize {
        self.estados.len()
    }

    /// Incorpora una observacion ya autenticada y devuelve el veredicto.
    ///
    /// `ahora` es el reloj local, no el del mensaje: el emisor podria fechar su
    /// observacion en el futuro para que nunca caduque.
    pub fn incorporar(&mut self, o: &Observacion, ahora: u64) -> Veredicto {
        let (tag, valor) = o.clave_corroboro();
        let clave = (tag, valor.to_string());

        self.caducar(ahora);

        let nuevo = !self.estados.contains_key(&clave);
        if nuevo && self.estados.len() >= MAX_INDICADORES_SEGUIDOS {
            // Lleno: se descarta el indicador nuevo en vez de crecer. Descartar
            // lo nuevo y no lo viejo es deliberado: lo viejo ya tiene testigos
            // acumulados, y tirarlo regalaria al atacante una forma de borrar
            // corroboros a punto de cerrarse inundando con indicadores nuevos.
            return Veredicto::Insuficiente {
                testigos: 0,
                umbral: self.umbral,
            };
        }

        let estado = self
            .estados
            .entry(clave.clone())
            .or_insert_with(|| EstadoCorroboro {
                testigos: BTreeMap::new(),
                ultima: o.clone(),
            });
        estado.ultima = o.clone();

        let repetido = estado.testigos.contains_key(&o.origen);
        if !repetido && estado.testigos.len() >= MAX_TESTIGOS_POR_INDICADOR {
            // Ya hay de sobra para cualquier umbral razonable; no se crece mas.
            return Veredicto::YaAvisado;
        }
        estado.testigos.insert(o.origen.clone(), ahora);

        let vigentes = estado.testigos_vigentes(ahora, self.ventana_seg);
        if vigentes < self.umbral {
            return Veredicto::Insuficiente {
                testigos: vigentes,
                umbral: self.umbral,
            };
        }

        if self.avisados.contains_key(&clave) {
            return if repetido {
                Veredicto::Repetido
            } else {
                Veredicto::YaAvisado
            };
        }
        self.avisados.insert(clave, ahora);
        let mut testigos: Vec<String> = estado.testigos.keys().cloned().collect();
        testigos.sort();
        Veredicto::Corroborado {
            observacion: o.clone(),
            testigos,
        }
    }

    /// Descarta lo que ya salio de la ventana.
    ///
    /// Se llama en cada incorporacion: sin esto la memoria solo crece, y un
    /// indicador avisado hace un ano seguiria bloqueando un aviso legitimo hoy.
    pub fn caducar(&mut self, ahora: u64) {
        let ventana = self.ventana_seg;
        self.estados.retain(|_, e| {
            e.testigos
                .retain(|_, t| ahora.saturating_sub(*t) <= ventana);
            !e.testigos.is_empty()
        });
        self.avisados
            .retain(|_, t| ahora.saturating_sub(*t) <= ventana);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_sync::ioc::{Ioc, IocKind};

    fn obs(origen: &str, valor: &str, vista_en: u64) -> Observacion {
        Observacion {
            origen: origen.to_string(),
            indicador: Ioc {
                kind: IocKind::FileSha256,
                value: valor.to_string(),
            },
            tecnica: "T1486".to_string(),
            confianza: 90,
            vista_en,
        }
    }

    /// EL CASO QUE JUSTIFICA LA FASE: tres equipos distintos ven lo mismo y la
    /// flota reacciona sin plano de control.
    #[test]
    fn tres_pares_distintos_corroboran_y_se_avisa_una_sola_vez() {
        let mut c = Corroboro::nuevo(3, 3600);
        assert!(matches!(
            c.incorporar(&obs("e1", "hash", 100), 100),
            Veredicto::Insuficiente { testigos: 1, .. }
        ));
        assert!(matches!(
            c.incorporar(&obs("e2", "hash", 110), 110),
            Veredicto::Insuficiente { testigos: 2, .. }
        ));
        let v = c.incorporar(&obs("e3", "hash", 120), 120);
        match v {
            Veredicto::Corroborado { testigos, .. } => {
                assert_eq!(testigos, vec!["e1", "e2", "e3"]);
            }
            otro => panic!("se esperaba corroboro: {otro:?}"),
        }
        // Y NO se vuelve a avisar: la politica de respuesta no puede recibir el
        // mismo hallazgo cien veces porque lleguen cien mensajes.
        assert!(matches!(
            c.incorporar(&obs("e4", "hash", 130), 130),
            Veredicto::YaAvisado
        ));
    }

    /// EL ATAQUE QUE ESTO PARA: un equipo comprometido grita mil veces y no
    /// consigue mover nada.
    #[test]
    fn un_solo_par_no_alcanza_el_quorum_por_muchas_veces_que_lo_repita() {
        let mut c = Corroboro::nuevo(3, 3600);
        for i in 0..1000 {
            let v = c.incorporar(&obs("comprometido", "hash", 100 + i), 100 + i);
            assert!(
                matches!(v, Veredicto::Insuficiente { testigos: 1, .. }),
                "un solo origen no puede pasar de un testigo (iteracion {i}): {v:?}"
            );
        }
    }

    /// Y tampoco dos, que es el punto de poner el umbral en tres.
    #[test]
    fn dos_pares_comprometidos_tampoco_bastan_con_el_umbral_por_defecto() {
        let mut c = Corroboro::default();
        assert_eq!(c.umbral, 3);
        c.incorporar(&obs("malo1", "hash", 100), 100);
        let v = c.incorporar(&obs("malo2", "hash", 101), 101);
        assert!(matches!(v, Veredicto::Insuficiente { testigos: 2, .. }));
    }

    /// Tres testigos separados por meses no son tres testigos del mismo
    /// incidente: son tres hechos sueltos.
    #[test]
    fn los_testigos_tienen_que_coincidir_en_la_ventana() {
        let mut c = Corroboro::nuevo(3, 3600);
        c.incorporar(&obs("e1", "hash", 0), 0);
        c.incorporar(&obs("e2", "hash", 10_000), 10_000);
        let v = c.incorporar(&obs("e3", "hash", 20_000), 20_000);
        assert!(
            matches!(v, Veredicto::Insuficiente { testigos: 1, .. }),
            "los dos primeros ya caducaron: {v:?}"
        );
    }

    #[test]
    fn un_umbral_de_uno_se_corrige_porque_seria_no_tener_quorum() {
        for u in [0, 1] {
            assert_eq!(
                Corroboro::nuevo(u, 3600).umbral,
                2,
                "un umbral de {u} dejaria que un par suelto moviese a la flota"
            );
        }
    }

    /// Un par que inventa indicadores nuevos sin parar no puede hacer crecer la
    /// memoria del receptor sin limite.
    #[test]
    fn inundar_con_indicadores_nuevos_no_hace_crecer_la_memoria_sin_limite() {
        let mut c = Corroboro::nuevo(3, 3600);
        for i in 0..(MAX_INDICADORES_SEGUIDOS * 2) {
            c.incorporar(&obs("inundador", &format!("hash-{i}"), 100), 100);
        }
        assert!(
            c.seguidos() <= MAX_INDICADORES_SEGUIDOS,
            "seguidos = {}",
            c.seguidos()
        );
    }

    /// Y descartar lo NUEVO y no lo viejo importa: si al llenarse se tirara lo
    /// viejo, inundar con indicadores nuevos borraria corroboros a punto de
    /// cerrarse, que es justo lo que el atacante querria.
    #[test]
    fn llenar_el_seguimiento_no_borra_un_corroboro_a_punto_de_cerrarse() {
        let mut c = Corroboro::nuevo(3, 3600);
        c.incorporar(&obs("e1", "el-importante", 100), 100);
        c.incorporar(&obs("e2", "el-importante", 100), 100);

        for i in 0..(MAX_INDICADORES_SEGUIDOS * 2) {
            c.incorporar(&obs("inundador", &format!("ruido-{i}"), 100), 100);
        }

        let v = c.incorporar(&obs("e3", "el-importante", 100), 100);
        match v {
            Veredicto::Corroborado { testigos, .. } => {
                assert_eq!(testigos, vec!["e1", "e2", "e3"]);
            }
            otro => panic!("la inundacion no puede borrar el corroboro en curso: {otro:?}"),
        }
    }

    #[test]
    fn indicadores_distintos_no_se_corroboran_entre_si() {
        let mut c = Corroboro::nuevo(3, 3600);
        c.incorporar(&obs("e1", "hash-a", 100), 100);
        c.incorporar(&obs("e2", "hash-b", 100), 100);
        let v = c.incorporar(&obs("e3", "hash-c", 100), 100);
        assert!(matches!(v, Veredicto::Insuficiente { testigos: 1, .. }));
    }

    #[test]
    fn tras_caducar_la_ventana_un_indicador_puede_volver_a_avisar() {
        let mut c = Corroboro::nuevo(3, 100);
        c.incorporar(&obs("e1", "hash", 0), 0);
        c.incorporar(&obs("e2", "hash", 0), 0);
        assert!(matches!(
            c.incorporar(&obs("e3", "hash", 0), 0),
            Veredicto::Corroborado { .. }
        ));

        // Mucho despues, el mismo indicador vuelve a verse: es un incidente
        // nuevo y tiene que poder avisar otra vez.
        c.incorporar(&obs("e1", "hash", 10_000), 10_000);
        c.incorporar(&obs("e2", "hash", 10_000), 10_000);
        assert!(matches!(
            c.incorporar(&obs("e3", "hash", 10_000), 10_000),
            Veredicto::Corroborado { .. }
        ));
    }

    #[test]
    fn el_reloj_del_mensaje_no_manda_sobre_el_local() {
        let mut c = Corroboro::nuevo(2, 100);
        // El emisor fecha su observacion muy en el futuro para que no caduque
        // nunca; el acumulador usa el reloj LOCAL y no se deja.
        c.incorporar(&obs("e1", "hash", u64::MAX), 0);
        c.caducar(1000);
        assert_eq!(c.seguidos(), 0, "la caducidad la manda el reloj local");
    }
}
