//! Corroboro: cuando la evidencia de varios pares basta para actuar.
//!
//! # Por que contar TESTIGOS AUTENTICADOS distintos y no observaciones
//!
//! El error que hay que no cometer es contar mensajes. Un par comprometido puede
//! emitir mil observaciones de lo mismo en un segundo; si el contador subiera
//! con cada una, un solo equipo alcanzaria cualquier umbral y el quorum seria
//! decorativo. Se cuentan **testigos distintos**, y el segundo mensaje del mismo
//! testigo no suma nada.
//!
//! Y «distinto» se decide por la identidad AUTENTICADA, nunca por lo que el
//! mensaje declare. [`Corroboro::incorporar`] recibe un [`Testigo`], que solo sale
//! de verificar la credencial firmada por el plano de control y la firma del par
//! ([`crate::observacion::verificar`]); el campo `Observacion::origen` no se lee
//! aqui. Contar `origen` era el Sybil de H-04: un equipo declaraba `e1`, `e2` y
//! `e3` y cerraba el quorum el solo.
//!
//! # La ventana, y por que no es opcional
//!
//! Un corroboro sin caducidad acumula para siempre: tres equipos que vieron algo
//! en marzo, junio y octubre no son tres testigos del mismo incidente, son tres
//! hechos sueltos. La ventana ([`Corroboro::ventana_seg`]) exige que los K
//! testigos coincidan **en el tiempo**, que es lo que hace que la evidencia
//! signifique «esto esta pasando ahora».
//!
//! El momento de un testigo es el MENOR entre el reloj local y el `vista_en`
//! firmado: el emisor no puede fecharse en el futuro para no caducar nunca, y una
//! observacion vieja reinyectada no rejuvenece a su testigo.
//!
//! # Lo que este modulo NO decide
//!
//! No decide que hacer. Dice si hay corroboro suficiente y quien lo aporto; la
//! politica local decide la accion, con el mismo criterio con el que decide ante
//! una deteccion propia. Mantener esa separacion es lo que impide que el
//! protocolo de red acabe mandando sobre el motor de respuesta.

use std::collections::BTreeMap;

use crate::credencial::Testigo;
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
    /// CN autenticados de quienes lo han visto, con el momento de su observacion
    /// mas reciente.
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
        /// CN autenticados de quienes lo vieron.
        testigos: Vec<String>,
    },
    /// Ya estaba corroborado y ya se aviso.
    YaAvisado,
    /// El testigo ya habia dicho esto: no suma.
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

    /// Incorpora la observacion de un testigo **ya autenticado** y devuelve el
    /// veredicto.
    ///
    /// Quien cuenta es `testigo`, no `o.origen`: el tipo [`Testigo`] no se puede
    /// fabricar desde un texto, asi que no hay forma de sumar un testigo que no
    /// haya pasado por la verificacion de su credencial.
    ///
    /// `ahora` es el reloj local, no el del mensaje: el emisor podria fechar su
    /// observacion en el futuro para que nunca caduque.
    pub fn incorporar(&mut self, testigo: &Testigo, o: &Observacion, ahora: u64) -> Veredicto {
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

        let repetido = estado.testigos.contains_key(testigo.cn());
        if !repetido && estado.testigos.len() >= MAX_TESTIGOS_POR_INDICADOR {
            // Ya hay de sobra para cualquier umbral razonable; no se crece mas.
            return Veredicto::YaAvisado;
        }
        // El momento del testigo: el menor entre el reloj local y lo firmado, y
        // nunca hacia atras. Una observacion vieja del mismo testigo no le quita
        // vigencia a una reciente, y tampoco le da una que no tenia.
        let momento = o.vista_en.min(ahora);
        let t = estado
            .testigos
            .entry(testigo.cn().to_string())
            .or_insert(momento);
        *t = (*t).max(momento);

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

    /// Incorpora una observacion honesta: el testigo autenticado es su origen.
    /// La autenticacion en si se ejerce en `observacion::verificar` y en
    /// `tests/sybil.rs`, con claves de verdad.
    fn inc(c: &mut Corroboro, origen: &str, valor: &str, ahora: u64) -> Veredicto {
        c.incorporar(
            &Testigo::de_prueba(origen),
            &obs(origen, valor, ahora),
            ahora,
        )
    }

    /// EL CASO QUE JUSTIFICA LA FASE: tres equipos distintos ven lo mismo y la
    /// flota reacciona sin plano de control.
    #[test]
    fn tres_pares_distintos_corroboran_y_se_avisa_una_sola_vez() {
        let mut c = Corroboro::nuevo(3, 3600);
        assert!(matches!(
            inc(&mut c, "e1", "hash", 100),
            Veredicto::Insuficiente { testigos: 1, .. }
        ));
        assert!(matches!(
            inc(&mut c, "e2", "hash", 110),
            Veredicto::Insuficiente { testigos: 2, .. }
        ));
        let v = inc(&mut c, "e3", "hash", 120);
        match v {
            Veredicto::Corroborado { testigos, .. } => {
                assert_eq!(testigos, vec!["e1", "e2", "e3"]);
            }
            otro => panic!("se esperaba corroboro: {otro:?}"),
        }
        // Y NO se vuelve a avisar: la politica de respuesta no puede recibir el
        // mismo hallazgo cien veces porque lleguen cien mensajes.
        assert!(matches!(
            inc(&mut c, "e4", "hash", 130),
            Veredicto::YaAvisado
        ));
    }

    /// EL ATAQUE QUE ESTO PARA: un equipo comprometido grita mil veces y no
    /// consigue mover nada.
    #[test]
    fn un_solo_par_no_alcanza_el_quorum_por_muchas_veces_que_lo_repita() {
        let mut c = Corroboro::nuevo(3, 3600);
        for i in 0..1000 {
            let v = inc(&mut c, "comprometido", "hash", 100 + i);
            assert!(
                matches!(v, Veredicto::Insuficiente { testigos: 1, .. }),
                "un solo testigo no puede pasar de uno (iteracion {i}): {v:?}"
            );
        }
    }

    /// PUERTA H-04 (Sybil). Un mismo testigo autenticado que declara mil
    /// origenes distintos sigue siendo UN testigo: el quorum no lee `origen`.
    /// Si alguien vuelve a contar el campo declarado, esta prueba cae.
    #[test]
    fn un_testigo_que_declara_mil_origenes_sigue_siendo_uno() {
        let mut c = Corroboro::nuevo(3, 3600);
        let comprometido = Testigo::de_prueba("comprometido");
        for i in 0..1000u64 {
            let o = obs(&format!("e{i}"), "hash", 100 + i);
            let v = c.incorporar(&comprometido, &o, 100 + i);
            assert!(
                matches!(v, Veredicto::Insuficiente { testigos: 1, .. }),
                "el origen declarado sumo un testigo (iteracion {i}): {v:?}"
            );
        }
    }

    /// Y tampoco dos, que es el punto de poner el umbral en tres.
    #[test]
    fn dos_pares_comprometidos_tampoco_bastan_con_el_umbral_por_defecto() {
        let mut c = Corroboro::default();
        assert_eq!(c.umbral, 3);
        inc(&mut c, "malo1", "hash", 100);
        let v = inc(&mut c, "malo2", "hash", 101);
        assert!(matches!(v, Veredicto::Insuficiente { testigos: 2, .. }));
    }

    /// Tres testigos separados por meses no son tres testigos del mismo
    /// incidente: son tres hechos sueltos.
    #[test]
    fn los_testigos_tienen_que_coincidir_en_la_ventana() {
        let mut c = Corroboro::nuevo(3, 3600);
        inc(&mut c, "e1", "hash", 0);
        inc(&mut c, "e2", "hash", 10_000);
        let v = inc(&mut c, "e3", "hash", 20_000);
        assert!(
            matches!(v, Veredicto::Insuficiente { testigos: 1, .. }),
            "los dos primeros ya caducaron: {v:?}"
        );
    }

    /// Una observacion vieja que llega tarde cuenta en SU momento, no en el de
    /// llegada: reinyectarla no la convierte en testigo de lo que pasa ahora.
    #[test]
    fn una_observacion_vieja_que_llega_tarde_no_es_testigo_de_ahora() {
        let mut c = Corroboro::nuevo(3, 3600);
        inc(&mut c, "e1", "hash", 10_000);
        inc(&mut c, "e2", "hash", 10_000);
        let vieja = obs("e3", "hash", 0);
        let v = c.incorporar(&Testigo::de_prueba("e3"), &vieja, 10_000);
        assert!(
            matches!(v, Veredicto::Insuficiente { testigos: 2, .. }),
            "una observacion de hace casi tres horas cerro el quorum: {v:?}"
        );
    }

    /// Y una vieja del mismo testigo no le quita la vigencia que ya tenia.
    #[test]
    fn una_observacion_vieja_no_retrasa_a_un_testigo_vigente() {
        let mut c = Corroboro::nuevo(2, 3600);
        inc(&mut c, "e1", "hash", 10_000);
        let vieja = obs("e1", "hash", 0);
        c.incorporar(&Testigo::de_prueba("e1"), &vieja, 10_000);
        let v = inc(&mut c, "e2", "hash", 10_001);
        assert!(matches!(v, Veredicto::Corroborado { .. }), "{v:?}");
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
            inc(&mut c, "inundador", &format!("hash-{i}"), 100);
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
        inc(&mut c, "e1", "el-importante", 100);
        inc(&mut c, "e2", "el-importante", 100);

        for i in 0..(MAX_INDICADORES_SEGUIDOS * 2) {
            inc(&mut c, "inundador", &format!("ruido-{i}"), 100);
        }

        let v = inc(&mut c, "e3", "el-importante", 100);
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
        inc(&mut c, "e1", "hash-a", 100);
        inc(&mut c, "e2", "hash-b", 100);
        let v = inc(&mut c, "e3", "hash-c", 100);
        assert!(matches!(v, Veredicto::Insuficiente { testigos: 1, .. }));
    }

    #[test]
    fn tras_caducar_la_ventana_un_indicador_puede_volver_a_avisar() {
        let mut c = Corroboro::nuevo(3, 100);
        inc(&mut c, "e1", "hash", 0);
        inc(&mut c, "e2", "hash", 0);
        assert!(matches!(
            inc(&mut c, "e3", "hash", 0),
            Veredicto::Corroborado { .. }
        ));

        // Mucho despues, el mismo indicador vuelve a verse: es un incidente
        // nuevo y tiene que poder avisar otra vez.
        inc(&mut c, "e1", "hash", 10_000);
        inc(&mut c, "e2", "hash", 10_000);
        assert!(matches!(
            inc(&mut c, "e3", "hash", 10_000),
            Veredicto::Corroborado { .. }
        ));
    }

    #[test]
    fn el_reloj_del_mensaje_no_manda_sobre_el_local() {
        let mut c = Corroboro::nuevo(2, 100);
        // El emisor fecha su observacion muy en el futuro para que no caduque
        // nunca; el acumulador usa el reloj LOCAL y no se deja.
        c.incorporar(&Testigo::de_prueba("e1"), &obs("e1", "hash", u64::MAX), 0);
        c.caducar(1000);
        assert_eq!(c.seguidos(), 0, "la caducidad la manda el reloj local");
    }
}
