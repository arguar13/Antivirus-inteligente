//! La cache, que ademas de rendimiento es una medida de privacidad.
//!
//! # Los dos motivos, y el segundo es el que suele olvidarse
//!
//! 1. **Cuota.** Los proveedores cobran o limitan por consulta, y un SOC pregunta
//!    por el mismo resumen cien veces al dia.
//! 2. **Exposicion.** Cada consulta que **no** se hace es una vez menos que le
//!    dices al proveedor que ese fichero esta en tu red. La cache no reduce lo que
//!    ya se revelo, pero si la frecuencia con la que se confirma — y la frecuencia
//!    es lo que permite a un proveedor reconstruir tu cronologia.
//!
//! # La caducidad va por TIPO, y no es una preferencia
//!
//! Sale de cuanto tarda el mundo real en cambiar, y es la misma tabla que usa
//! [`crate::fusion::caducidad_ns`] — una sola definicion, porque dos tablas de
//! caducidad acaban discrepando y entonces la cache devuelve algo que la fusion
//! considera caducado.
//!
//! # El acierto negativo no dura lo mismo que el positivo
//!
//! Es el error clasico. Si «no lo conozco» se guarda tanto como «es malicioso»,
//! un fichero que el proveedor incorpora hoy **te sigue pareciendo desconocido
//! durante meses**. Y el caso en que eso ocurre es precisamente el que importa:
//! malware nuevo, que primero nadie conoce y a las pocas horas conoce todo el
//! mundo.
//!
//! Por eso [`TTL_NEGATIVO`] es corto y fijo, independiente del tipo.
//!
//! # La clave es un resumen, no el valor
//!
//! Una clave con el valor en claro convierte un volcado de la cache —o de la
//! memoria del proceso— en la lista de todo lo que se ha mirado, con rutas de
//! fichero y nombres de cuenta incluidos. Cuesta lo mismo guardar el resumen.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::dictamen::{Dictamen, Juicio};
use crate::observable::Observable;

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;

/// Cuanto vale un «no lo conozco».
///
/// Una hora. Corto a proposito: malware nuevo es desconocido durante horas y
/// conocido despues, y guardar el desconocimiento una semana significa no
/// enterarse durante esa semana justo del caso que importa.
pub const TTL_NEGATIVO: u64 = 3600 * SEG;

/// Entradas maximas por fuente.
///
/// Acotado porque la cache vive en el proceso del plano de control, y un SOC
/// grande genera millones de observables distintos al dia. Sin tope, la cache es
/// una fuga de memoria con buenos modales.
pub const MAX_ENTRADAS: usize = 50_000;

/// Lo guardado para un observable y una fuente.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entrada {
    dictamen: Dictamen,
    guardado_ns: u64,
    vence_ns: u64,
    /// Para el desalojo: el ultimo que se uso es el ultimo que se tira.
    usado_ns: u64,
}

/// Por que se sirvio —o no— desde la cache.
///
/// Va al informe. Un analista que ve un veredicto tiene derecho a saber si se
/// consulto ahora o se esta leyendo algo de hace tres dias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Procedencia {
    /// Se consulto a la fuente en este momento.
    Consultado,
    /// Vino de la cache, con su antiguedad en segundos.
    DeCache {
        /// Cuantos segundos hace que se guardo.
        hace_s: u64,
    },
}

impl Procedencia {
    /// Texto para el informe.
    #[must_use]
    pub fn texto(self) -> String {
        match self {
            Procedencia::Consultado => "consultado ahora".to_string(),
            Procedencia::DeCache { hace_s } => {
                format!("de cache, guardado hace {hace_s} s")
            }
        }
    }

    /// Si esta consulta salio a la red.
    ///
    /// **Un acierto de cache no es una exposicion.** Es la propiedad que convierte
    /// la cache en una medida de privacidad y no solo de rendimiento, y el informe
    /// de exposicion la usa para contar lo que de verdad salio.
    #[must_use]
    pub fn hubo_exposicion(self) -> bool {
        self == Procedencia::Consultado
    }
}

/// La cache de dictamenes.
///
/// No usa reloj: el tiempo entra como argumento en cada operacion, igual que en
/// `aegis-case` y `aegis-scale`. Es lo que permite probar la caducidad de seis
/// meses en un microsegundo.
#[derive(Debug, Default)]
pub struct Cache {
    entradas: HashMap<String, Entrada>,
    aciertos: u64,
    fallos: u64,
    desalojos: u64,
}

impl Cache {
    /// Una cache vacia.
    #[must_use]
    pub fn nueva() -> Cache {
        Cache::default()
    }

    /// La clave de un (fuente, observable).
    ///
    /// Resumen y no valor en claro: ver el encabezado del modulo.
    #[must_use]
    pub fn clave(fuente: &str, observable: &Observable) -> String {
        let mut h = Sha256::new();
        h.update(fuente.as_bytes());
        h.update([0x1f]);
        h.update(observable.tipo().nombre().as_bytes());
        h.update([0x1f]);
        h.update(observable.valor().as_bytes());
        let d = h.finalize();
        let mut s = String::with_capacity(32);
        use std::fmt::Write as _;
        for b in &d[..16] {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Busca un dictamen vigente.
    ///
    /// Devuelve `None` si no esta o si vencio. Lo vencido se borra al pasar por
    /// aqui, que es la unica limpieza que hace falta: una cache que solo se limpia
    /// con un barrido periodico crece entre barridos justo cuando hay mas carga.
    pub fn buscar(
        &mut self,
        fuente: &str,
        observable: &Observable,
        ahora_ns: u64,
    ) -> Option<(Dictamen, Procedencia)> {
        let clave = Cache::clave(fuente, observable);
        let e = self.entradas.get_mut(&clave)?;
        if ahora_ns >= e.vence_ns {
            self.entradas.remove(&clave);
            self.fallos += 1;
            return None;
        }
        e.usado_ns = ahora_ns;
        let hace_s = (ahora_ns.saturating_sub(e.guardado_ns)) / SEG;
        self.aciertos += 1;
        Some((e.dictamen.clone(), Procedencia::DeCache { hace_s }))
    }

    /// Guarda un dictamen.
    ///
    /// La vigencia sale del tipo del observable para lo positivo y de
    /// [`TTL_NEGATIVO`] para lo desconocido.
    pub fn guardar(&mut self, dictamen: &Dictamen, ahora_ns: u64) {
        let vigencia = if dictamen.juicio == Juicio::Desconocido {
            TTL_NEGATIVO
        } else {
            crate::fusion::caducidad_ns(dictamen.observable.tipo())
        };
        // Un dictamen que la fuente observo hace tiempo no empieza a contar ahora:
        // vence cuando venceria de todas formas. Sin esto, volver a consultar una
        // fuente que repite un dato antiguo lo rejuvenece indefinidamente.
        let base = dictamen.observado_ns.min(ahora_ns);
        let vence_ns = base.saturating_add(vigencia).max(ahora_ns + SEG);

        let clave = Cache::clave(&dictamen.fuente, &dictamen.observable);
        if self.entradas.len() >= MAX_ENTRADAS && !self.entradas.contains_key(&clave) {
            self.desalojar(ahora_ns);
        }
        self.entradas.insert(
            clave,
            Entrada {
                dictamen: dictamen.clone(),
                guardado_ns: ahora_ns,
                vence_ns,
                usado_ns: ahora_ns,
            },
        );
    }

    /// Tira lo vencido y, si aun no cabe, lo menos usado recientemente.
    fn desalojar(&mut self, ahora_ns: u64) {
        let antes = self.entradas.len();
        self.entradas.retain(|_, e| ahora_ns < e.vence_ns);
        self.desalojos += (antes - self.entradas.len()) as u64;
        if self.entradas.len() < MAX_ENTRADAS {
            return;
        }
        // Se tira un decimo de golpe y no una sola entrada: desalojar de una en
        // una con la cache llena hace un recorrido completo por cada insercion, y
        // eso es cuadratico justo cuando hay mas trafico.
        let a_tirar = MAX_ENTRADAS / 10;
        let mut por_uso: Vec<(String, u64)> = self
            .entradas
            .iter()
            .map(|(k, e)| (k.clone(), e.usado_ns))
            .collect();
        por_uso.sort_unstable_by_key(|(_, u)| *u);
        for (k, _) in por_uso.into_iter().take(a_tirar) {
            self.entradas.remove(&k);
            self.desalojos += 1;
        }
    }

    /// Borra todo lo de una fuente.
    ///
    /// Hace falta de verdad: cuando un proveedor corrige una clasificacion
    /// equivocada, lo que tenemos guardado sigue siendo el error, y sin esto
    /// seguimos actuando sobre el durante meses.
    pub fn olvidar_fuente(&mut self, fuente: &str) -> usize {
        let antes = self.entradas.len();
        self.entradas.retain(|_, e| e.dictamen.fuente != fuente);
        antes - self.entradas.len()
    }

    /// Cuantas entradas hay.
    #[must_use]
    pub fn entradas(&self) -> usize {
        self.entradas.len()
    }

    /// Aciertos, fallos y desalojos.
    #[must_use]
    pub fn cuentas(&self) -> (u64, u64, u64) {
        (self.aciertos, self.fallos, self.desalojos)
    }

    /// Cuantas consultas se ahorraron, que son cuantas exposiciones no ocurrieron.
    #[must_use]
    pub fn exposiciones_evitadas(&self) -> u64 {
        self.aciertos
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::dictamen::Clase;

    const AHORA: u64 = 1_700_000_000 * SEG;
    const DIA: u64 = 24 * 3600 * SEG;

    fn d(juicio: Juicio, obs: Observable, hace: u64) -> Dictamen {
        Dictamen {
            fuente: "rep".into(),
            clase: Clase::Reputacion,
            observable: obs,
            juicio,
            confianza: if juicio == Juicio::Desconocido { 0 } else { 80 },
            observado_ns: AHORA - hace,
            porque: "x".into(),
            etiquetas: vec![],
        }
    }

    #[test]
    fn un_acierto_devuelve_el_dictamen_y_dice_que_es_de_cache() {
        let mut c = Cache::nueva();
        let obs = Observable::Hash("abc".into());
        c.guardar(&d(Juicio::Malicioso, obs.clone(), 0), AHORA);

        let (visto, proc) = c.buscar("rep", &obs, AHORA + 30 * SEG).expect("esta");
        assert_eq!(visto.juicio, Juicio::Malicioso);
        assert_eq!(proc, Procedencia::DeCache { hace_s: 30 });
        // La propiedad que convierte la cache en medida de privacidad.
        assert!(!proc.hubo_exposicion());
        assert!(Procedencia::Consultado.hubo_exposicion());
    }

    #[test]
    fn el_desconocido_caduca_en_una_hora_y_el_malicioso_no() {
        // El error clasico: si «no lo conozco» durase lo mismo, un fichero que el
        // proveedor incorpora hoy te seguiria pareciendo desconocido durante meses
        // — y ese es justo el caso que importa, malware nuevo.
        let mut c = Cache::nueva();
        let obs = Observable::Hash("abc".into());

        c.guardar(&d(Juicio::Desconocido, obs.clone(), 0), AHORA);
        assert!(c.buscar("rep", &obs, AHORA + TTL_NEGATIVO - SEG).is_some());
        assert!(c.buscar("rep", &obs, AHORA + TTL_NEGATIVO).is_none());

        c.guardar(&d(Juicio::Malicioso, obs.clone(), 0), AHORA);
        assert!(c.buscar("rep", &obs, AHORA + TTL_NEGATIVO + SEG).is_some());
    }

    #[test]
    fn una_ip_caduca_mucho_antes_que_un_resumen() {
        let mut c = Cache::nueva();
        let ip = Observable::Ip("8.8.8.8".into());
        let hash = Observable::Hash("abc".into());
        c.guardar(&d(Juicio::Malicioso, ip.clone(), 0), AHORA);
        c.guardar(&d(Juicio::Malicioso, hash.clone(), 0), AHORA);

        let luego = AHORA + 3 * DIA;
        assert!(c.buscar("rep", &ip, luego).is_none(), "la IP ya no vale");
        assert!(c.buscar("rep", &hash, luego).is_some(), "el resumen si");
    }

    #[test]
    fn un_dato_que_la_fuente_observo_hace_tiempo_no_se_rejuvenece() {
        // Sin esto, volver a preguntar a una fuente que repite un dato antiguo lo
        // pone otra vez a estrenar y nunca caduca.
        let mut c = Cache::nueva();
        let ip = Observable::Ip("8.8.8.8".into());
        // Observado hace dia y medio; la caducidad de una IP son dos dias.
        c.guardar(&d(Juicio::Malicioso, ip.clone(), 36 * 3600 * SEG), AHORA);
        assert!(c.buscar("rep", &ip, AHORA + 11 * 3600 * SEG).is_some());
        assert!(
            c.buscar("rep", &ip, AHORA + 13 * 3600 * SEG).is_none(),
            "vence a las 48 h de OBSERVARSE, no de guardarse"
        );
    }

    #[test]
    fn un_dato_ya_caducado_al_guardarse_vive_al_menos_un_segundo() {
        // Si venciera en el pasado, la entrada seria inutil y ademas se volveria a
        // consultar en bucle en la misma rafaga de trabajo.
        let mut c = Cache::nueva();
        let ip = Observable::Ip("8.8.8.8".into());
        c.guardar(&d(Juicio::Malicioso, ip.clone(), 30 * DIA), AHORA);
        assert!(c.buscar("rep", &ip, AHORA).is_some());
    }

    #[test]
    fn la_clave_no_lleva_el_valor_en_claro() {
        // Un volcado de la cache no puede ser la lista de todo lo que se ha
        // mirado, con rutas de fichero y nombres de cuenta incluidos.
        let obs = Observable::Ruta("C:\\Users\\maria.lopez\\secreto.docx".into());
        let k = Cache::clave("rep", &obs);
        assert!(!k.contains("maria"));
        assert!(!k.contains("secreto"));
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn dos_tipos_con_el_mismo_valor_no_comparten_entrada() {
        // `Dominio("1.2.3.4")` y `Ip("1.2.3.4")` son preguntas distintas con
        // caducidades distintas; compartir clave mezclaria las respuestas.
        let a = Cache::clave("rep", &Observable::Ip("1.2.3.4".into()));
        let b = Cache::clave("rep", &Observable::Dominio("1.2.3.4".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn dos_fuentes_no_comparten_entrada() {
        let a = Cache::clave("rep-a", &Observable::Hash("abc".into()));
        let b = Cache::clave("rep-b", &Observable::Hash("abc".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn la_cache_esta_acotada_y_desaloja_lo_menos_usado() {
        // Sin tope es una fuga de memoria con buenos modales: un SOC grande genera
        // millones de observables distintos al dia.
        let mut c = Cache::nueva();
        for i in 0..MAX_ENTRADAS + 2000 {
            let obs = Observable::Hash(format!("h{i}"));
            c.guardar(&d(Juicio::Malicioso, obs, 0), AHORA + i as u64);
        }
        assert!(
            c.entradas() <= MAX_ENTRADAS,
            "se paso del tope: {}",
            c.entradas()
        );
        let (_, _, desalojos) = c.cuentas();
        assert!(desalojos > 0);
        // Lo ultimo guardado sigue estando; lo primero ya no.
        assert!(c
            .buscar(
                "rep",
                &Observable::Hash(format!("h{}", MAX_ENTRADAS + 1999)),
                AHORA + 60 * DIA
            )
            .is_some());
    }

    #[test]
    fn olvidar_una_fuente_la_borra_entera() {
        // Cuando un proveedor corrige una clasificacion equivocada, lo que tenemos
        // guardado sigue siendo el error.
        let mut c = Cache::nueva();
        for i in 0..10 {
            let mut x = d(Juicio::Malicioso, Observable::Hash(format!("h{i}")), 0);
            x.fuente = if i % 2 == 0 { "a".into() } else { "b".into() };
            c.guardar(&x, AHORA);
        }
        assert_eq!(c.olvidar_fuente("a"), 5);
        assert_eq!(c.entradas(), 5);
    }

    #[test]
    fn se_cuentan_las_exposiciones_evitadas() {
        let mut c = Cache::nueva();
        let obs = Observable::Hash("abc".into());
        c.guardar(&d(Juicio::Malicioso, obs.clone(), 0), AHORA);
        for _ in 0..7 {
            c.buscar("rep", &obs, AHORA + SEG);
        }
        // Siete veces que NO se le dijo al proveedor que ese fichero esta aqui.
        assert_eq!(c.exposiciones_evitadas(), 7);
    }

    #[test]
    fn lo_vencido_se_borra_al_pasar_por_encima() {
        // Una cache que solo se limpia con un barrido periodico crece entre
        // barridos justo cuando hay mas carga.
        let mut c = Cache::nueva();
        let obs = Observable::Ip("8.8.8.8".into());
        c.guardar(&d(Juicio::Malicioso, obs.clone(), 0), AHORA);
        assert_eq!(c.entradas(), 1);
        assert!(c.buscar("rep", &obs, AHORA + 10 * DIA).is_none());
        assert_eq!(c.entradas(), 0, "la entrada vencida se fue al consultarla");
    }
}
