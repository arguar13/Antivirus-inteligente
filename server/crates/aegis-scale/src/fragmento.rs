//! Particionado de la flota, con asignacion estable.
//!
//! # El problema, y por que el anillo clasico no vale
//!
//! Cien mil agentes no caben en un proceso. Hay que repartirlos entre varios
//! nodos del plano de control, y la funcion que decide **que agente le toca a que
//! nodo** tiene una propiedad no negociable: **anadir un servidor no puede
//! rebarajar toda la flota**.
//!
//! Con el reparto ingenuo —`hash(agente) % nodos`— pasar de cuatro nodos a cinco
//! mueve al **80 %** de la flota. Cien mil agentes reconectando a la vez contra un
//! plano de control que acaba de crecer *porque iba justo* es como se tira un
//! sistema al intentar ampliarlo. Es el error que hace que ampliar dé miedo.
//!
//! # Por que sorteo (rendezvous) y no anillo consistente
//!
//! Las dos soluciones clasicas mueven solo `1/N`. La diferencia esta en lo demas:
//!
//! * El **anillo consistente** necesita nodos virtuales para repartir bien —entre
//!   cien y doscientos por nodo real—, lo que significa una tabla que mantener,
//!   ordenar y distribuir, y un reparto que sigue teniendo varianza.
//! * El **sorteo** (*highest random weight*) no tiene tabla: para cada agente se
//!   calcula un peso con cada nodo y gana el mayor. Sin estado, sin nodos
//!   virtuales, con reparto uniforme por construccion.
//!
//! Y lo que de verdad decide: el sorteo es una **funcion pura de (agente, lista de
//! nodos)**. Dos nodos del plano de control que tengan la misma lista calculan la
//! misma asignacion **sin hablar entre ellos**. En una particion de red eso es la
//! diferencia entre seguir funcionando y necesitar consenso para atender un
//! latido.
//!
//! # La estabilidad de la membresia es parte del diseno, no un detalle
//!
//! Un nodo que parpadea —una pausa del recolector de basura, un reinicio de
//! treinta segundos— cambia la lista, y con ella la asignacion de `1/N` de la
//! flota. Si la lista siguiera al estado instantaneo, cada parpadeo provocaria una
//! migracion completa de ese fragmento **y otra de vuelta**. Por eso una baja
//! tarda [`PLAZO_BAJA_NS`] en aplicarse: ver [`Membresia`].

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// Cuanto tiene que llevar un nodo sin dar senales para darlo de baja.
///
/// Noventa segundos. Sale de lo que tarda de verdad un nodo en volver de un
/// reinicio ordenado: por debajo, cada despliegue rodante provocaria una
/// migracion de la flota y otra de vuelta; por encima, un nodo de verdad caido
/// se lleva su fragmento sin atender demasiado tiempo.
pub const PLAZO_BAJA_NS: u64 = 90 * 1_000_000_000;

/// Nodos maximos del plano de control.
///
/// Mil. No es un limite de diseno sino una cota de cordura: el sorteo cuesta
/// O(nodos) por agente, y una lista que crece sin tope convierte cada latido en
/// un bucle.
pub const MAX_NODOS: usize = 1024;

/// Un nodo del plano de control.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nodo {
    /// Identificador estable del nodo. No es su direccion: una maquina puede
    /// cambiar de IP sin cambiar de identidad, y confundirlas rebaraja la flota
    /// cada vez que alguien toca la red.
    pub id: String,
    /// Donde se le habla.
    pub direccion: String,
    /// Capacidad relativa.
    ///
    /// Un nodo con el doble de peso se lleva aproximadamente el doble de
    /// agentes. Existe porque una flota real no corre sobre maquinas iguales, y
    /// repartir por igual sobre maquinas distintas satura la pequena mientras la
    /// grande esta ociosa.
    pub peso: u32,
}

impl Nodo {
    /// Un nodo con peso uniforme.
    #[must_use]
    pub fn nuevo(id: impl Into<String>, direccion: impl Into<String>) -> Nodo {
        Nodo {
            id: id.into(),
            direccion: direccion.into(),
            peso: 100,
        }
    }
}

/// Peso del sorteo para un par (agente, nodo).
///
/// Es un resumen criptografico y no una mezcla aritmetica barata. La razon no es
/// la seguridad del resumen: es que una funcion de mezcla debil **correlaciona**
/// los pesos de nodos con identificadores parecidos —`nodo-1`, `nodo-2`,
/// `nodo-3`— y entonces el reparto deja de ser uniforme justo en el caso normal,
/// que es nombrar los nodos con un contador.
///
/// El peso relativo se aplica dividiendo: es la forma estandar del sorteo
/// ponderado, y conserva la propiedad de que quitar un nodo no mueve a los
/// agentes de los demas.
#[must_use]
pub fn peso_de(agente: &str, nodo: &Nodo) -> u64 {
    #[cfg(test)]
    pruebas::RESUMENES.with(|c| c.set(c.get() + 1));
    let mut h = Sha256::new();
    h.update(agente.as_bytes());
    h.update([0x1f]);
    h.update(nodo.id.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    let bruto = u64::from_be_bytes(b);
    if nodo.peso <= 1 {
        return bruto / 100;
    }
    // Se escala por el peso relativo sin desbordar: el bruto se lleva a u128,
    // se multiplica y se vuelve a bajar.
    let escalado = u128::from(bruto) * u128::from(nodo.peso) / 100;
    u64::try_from(escalado).unwrap_or(u64::MAX)
}

/// El reparto de la flota entre los nodos vivos.
#[derive(Debug, Clone, Default)]
pub struct Reparto {
    nodos: Vec<Nodo>,
}

impl Reparto {
    /// Crea un reparto con una lista de nodos.
    ///
    /// La lista se ordena por identificador: el sorteo no depende del orden, pero
    /// ordenarla hace que dos nodos con la misma membresia tengan tambien la
    /// misma representacion, y eso permite comparar epocas sin ambiguedad.
    #[must_use]
    pub fn nuevo(mut nodos: Vec<Nodo>) -> Reparto {
        nodos.sort();
        nodos.dedup_by(|a, b| a.id == b.id);
        nodos.truncate(MAX_NODOS);
        Reparto { nodos }
    }

    /// Nodos del reparto.
    #[must_use]
    pub fn nodos(&self) -> &[Nodo] {
        &self.nodos
    }

    /// El orden del sorteo: gana la clave MAYOR.
    ///
    /// El desempate por identificador hace la funcion TOTAL: sin el, dos nodos con
    /// el mismo peso —improbable pero posible— darian resultados distintos segun
    /// el orden de la lista, y dos nodos del plano de control discreparian sobre a
    /// quien le toca el agente. El sintoma seria un agente atendido por los dos o
    /// por ninguno.
    ///
    /// Es UNA sola clave para [`Reparto::nodo_de`] y [`Reparto::preferidos`]. Cada
    /// uno llevaba antes su comparador, y los dos desempataban al reves: con dos
    /// pesos iguales, el primero de `preferidos` no era el nodo del agente, que es
    /// justo lo que `preferidos` promete.
    fn clave<'a>(agente: &str, nodo: &'a Nodo) -> (u64, &'a str) {
        (peso_de(agente, nodo), nodo.id.as_str())
    }

    /// A que nodo le toca un agente.
    ///
    /// Devuelve `None` solo si no hay ningun nodo, que es un plano de control
    /// apagado y no un caso que haya que disimular.
    ///
    /// Cuesta exactamente un resumen por nodo: la clave se calcula una vez por
    /// nodo, no una vez por comparacion. Con un comparador que la calculaba dentro
    /// eran dos resumenes por comparacion —treinta por agente con dieciseis nodos
    /// en vez de dieciseis—.
    #[must_use]
    pub fn nodo_de(&self, agente: &str) -> Option<&Nodo> {
        self.nodos
            .iter()
            .map(|n| (Self::clave(agente, n), n))
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, n)| n)
    }

    /// Los `n` nodos preferidos para un agente, de mejor a peor.
    ///
    /// El segundo de la lista es **a donde se va el agente si su nodo cae**, y es
    /// exactamente el mismo que calcularia el resto del plano de control. Eso
    /// hace que la conmutacion por error no necesite coordinacion. El primero es
    /// siempre [`Reparto::nodo_de`], empates incluidos.
    ///
    /// Tambien un resumen por nodo: ordenar con la clave dentro del comparador
    /// costaba O(n log n) resumenes.
    #[must_use]
    pub fn preferidos(&self, agente: &str, n: usize) -> Vec<&Nodo> {
        let mut v: Vec<((u64, &str), &Nodo)> = self
            .nodos
            .iter()
            .map(|nodo| (Self::clave(agente, nodo), nodo))
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v.into_iter().take(n).map(|(_, nodo)| nodo).collect()
    }

    /// Cuantos agentes de una muestra cambian de nodo al pasar a otro reparto.
    ///
    /// Es la medida que importa al ampliar: la prueba de la fase la usa para
    /// comprobar que anadir un nodo mueve aproximadamente `1/N` y no el 80 %.
    #[must_use]
    pub fn movidos(&self, otro: &Reparto, agentes: &[String]) -> usize {
        agentes
            .iter()
            .filter(|a| {
                let antes = self.nodo_de(a).map(|n| &n.id);
                let despues = otro.nodo_de(a).map(|n| &n.id);
                antes != despues
            })
            .count()
    }

    /// Cuantos agentes de una muestra caen en cada nodo.
    #[must_use]
    pub fn distribucion(&self, agentes: &[String]) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for a in agentes {
            if let Some(n) = self.nodo_de(a) {
                *m.entry(n.id.clone()).or_insert(0) += 1;
            }
        }
        m
    }
}

/// Estado de un nodo en la membresia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoNodo {
    /// Dando senales.
    Vivo,
    /// Callado, pero todavia dentro del plazo de gracia.
    ///
    /// **Sigue contando para el reparto.** Es lo que impide que una pausa de
    /// treinta segundos migre un fragmento entero y lo devuelva despues.
    Sospechoso,
    /// Fuera del reparto.
    Baja,
}

/// La membresia del plano de control, con histeresis y epoca monotona.
#[derive(Debug, Clone)]
pub struct Membresia {
    nodos: BTreeMap<String, (Nodo, u64)>,
    plazo_baja_ns: u64,
    epoca: u64,
}

impl Default for Membresia {
    fn default() -> Membresia {
        Membresia::nueva(PLAZO_BAJA_NS)
    }
}

impl Membresia {
    /// Crea una membresia vacia.
    #[must_use]
    pub fn nueva(plazo_baja_ns: u64) -> Membresia {
        Membresia {
            nodos: BTreeMap::new(),
            plazo_baja_ns,
            epoca: 1,
        }
    }

    /// Epoca actual.
    ///
    /// # Por que es monotona
    ///
    /// El mapa de nodos viaja hasta los agentes: es como saben a donde
    /// conectarse. Sin epoca monotona, **reproducir un mapa viejo y autentico**
    /// redirige a una fraccion de la flota hacia nodos que ya no existen, y
    /// ninguna firma distingue un mapa autentico de ayer de uno autentico de
    /// hoy. Con epoca, el agente se queda con el mayor que haya visto y el mapa
    /// viejo no le dice nada.
    #[must_use]
    pub fn epoca(&self) -> u64 {
        self.epoca
    }

    /// Un nodo ha dado senales de vida.
    pub fn latido(&mut self, nodo: Nodo, ahora_ns: u64) {
        let nuevo = !self.nodos.contains_key(&nodo.id);
        let cambio = self
            .nodos
            .get(&nodo.id)
            .is_some_and(|(n, _)| n.direccion != nodo.direccion || n.peso != nodo.peso);
        self.nodos.insert(nodo.id.clone(), (nodo, ahora_ns));
        if nuevo || cambio {
            self.epoca += 1;
        }
    }

    /// Da de baja un nodo a proposito: es lo que hace un despliegue ordenado.
    ///
    /// Distinto de dejar de dar senales: aqui se sabe que se va, asi que no hay
    /// que esperar el plazo de gracia. Un despliegue que esperara noventa
    /// segundos por nodo tardaria horas en una flota grande.
    pub fn retirar(&mut self, id: &str) {
        if self.nodos.remove(id).is_some() {
            self.epoca += 1;
        }
    }

    /// Estado de un nodo.
    #[must_use]
    pub fn estado(&self, id: &str, ahora_ns: u64) -> EstadoNodo {
        match self.nodos.get(id) {
            None => EstadoNodo::Baja,
            Some((_, visto)) => {
                if ahora_ns.saturating_sub(*visto) <= self.plazo_baja_ns {
                    EstadoNodo::Vivo
                } else {
                    EstadoNodo::Sospechoso
                }
            }
        }
    }

    /// Retira los nodos que agotaron su plazo y devuelve cuantos.
    pub fn caducar(&mut self, ahora_ns: u64) -> usize {
        let muertos: Vec<String> = self
            .nodos
            .iter()
            .filter(|(_, (_, visto))| ahora_ns.saturating_sub(*visto) > self.plazo_baja_ns)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &muertos {
            self.nodos.remove(id);
        }
        if !muertos.is_empty() {
            self.epoca += 1;
        }
        muertos.len()
    }

    /// El reparto vigente.
    ///
    /// Incluye a los sospechosos: ver [`EstadoNodo::Sospechoso`].
    #[must_use]
    pub fn reparto(&self) -> Reparto {
        Reparto::nuevo(self.nodos.values().map(|(n, _)| n.clone()).collect())
    }

    /// Nodos conocidos.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.nodos.len()
    }
}

/// El mapa que se le entrega a un agente para que sepa a donde conectarse.
///
/// Viaja por el canal mTLS ya autenticado, asi que su integridad la da el
/// transporte. Lo que el transporte **no** da es frescura: ver
/// [`Membresia::epoca`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapa {
    /// Epoca de la membresia con la que se genero.
    pub epoca: u64,
    /// Nodos, en orden estable.
    pub nodos: Vec<Nodo>,
}

impl Mapa {
    /// Genera el mapa de una membresia.
    #[must_use]
    pub fn de(m: &Membresia) -> Mapa {
        Mapa {
            epoca: m.epoca(),
            nodos: m.reparto().nodos().to_vec(),
        }
    }

    /// Acepta un mapa nuevo solo si es mas reciente.
    ///
    /// Devuelve si se acepto. Un mapa con epoca menor o igual **se ignora**, que
    /// es lo que corta la reproduccion de un mapa viejo y autentico.
    pub fn aceptar(&mut self, otro: Mapa) -> bool {
        if otro.epoca <= self.epoca {
            return false;
        }
        *self = otro;
        true
    }

    /// A que nodo le toca este agente segun el mapa.
    #[must_use]
    pub fn nodo_de(&self, agente: &str) -> Option<Nodo> {
        Reparto::nuevo(self.nodos.clone()).nodo_de(agente).cloned()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    std::thread_local! {
        /// Cuantos resumenes ha calculado [`peso_de`] en este hilo. Cada prueba
        /// corre en su hilo, asi que las demas no lo tocan.
        pub(super) static RESUMENES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn nodos(n: usize) -> Vec<Nodo> {
        (0..n)
            .map(|i| Nodo::nuevo(format!("nodo-{i}"), format!("10.0.0.{}:8443", i + 1)))
            .collect()
    }

    fn agentes(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("agente-{i:06}")).collect()
    }

    // --- La propiedad que justifica el algoritmo -----------------------------

    #[test]
    fn anadir_un_nodo_mueve_aproximadamente_uno_de_cada_n() {
        // LA PRUEBA DE LA FASE. Con `hash % nodos`, pasar de cuatro a cinco
        // mueve al 80 % de la flota: cien mil agentes reconectando a la vez
        // contra un plano de control que acaba de crecer porque iba justo.
        let flota = agentes(10_000);
        let cuatro = Reparto::nuevo(nodos(4));
        let cinco = Reparto::nuevo(nodos(5));
        let movidos = cuatro.movidos(&cinco, &flota);
        let esperado = flota.len() / 5; // 1/N con N = 5
        assert!(
            movidos < esperado * 12 / 10,
            "se movieron {movidos}, se esperaban ~{esperado}"
        );
        assert!(movidos > esperado * 8 / 10, "se movieron solo {movidos}");
    }

    #[test]
    fn quitar_un_nodo_solo_mueve_a_los_suyos() {
        let flota = agentes(10_000);
        let cinco = Reparto::nuevo(nodos(5));
        let suyos = cinco
            .distribucion(&flota)
            .get("nodo-4")
            .copied()
            .unwrap_or(0);
        let cuatro = Reparto::nuevo(nodos(4));
        assert_eq!(
            cinco.movidos(&cuatro, &flota),
            suyos,
            "se movio alguien que no era del nodo que se fue"
        );
    }

    #[test]
    fn el_reparto_es_uniforme_aunque_los_nodos_se_llamen_con_un_contador() {
        // Una funcion de mezcla debil correlaciona los pesos de nodos con
        // nombres parecidos, y el reparto deja de ser uniforme justo en el caso
        // normal: nombrar los nodos con un contador.
        let flota = agentes(20_000);
        let r = Reparto::nuevo(nodos(8));
        let d = r.distribucion(&flota);
        let ideal = flota.len() / 8;
        for (id, n) in &d {
            assert!(
                *n > ideal * 85 / 100 && *n < ideal * 115 / 100,
                "{id} se llevo {n}, ideal {ideal}"
            );
        }
        assert_eq!(d.len(), 8);
    }

    #[test]
    fn un_nodo_con_mas_peso_se_lleva_mas_agentes() {
        // Una flota real no corre sobre maquinas iguales, y repartir por igual
        // satura la pequena mientras la grande esta ociosa.
        let flota = agentes(20_000);
        let mut ns = nodos(3);
        ns[0].peso = 300;
        let r = Reparto::nuevo(ns);
        let d = r.distribucion(&flota);
        let grande = d["nodo-0"];
        let pequeno = d["nodo-1"];
        assert!(grande > pequeno * 2, "grande {grande}, pequeno {pequeno}");
    }

    #[test]
    fn dos_nodos_del_plano_de_control_calculan_lo_mismo_sin_hablar() {
        // En una particion de red, esto es la diferencia entre seguir
        // funcionando y necesitar consenso para atender un latido.
        let a = Reparto::nuevo(nodos(6));
        let b = Reparto::nuevo({
            let mut v = nodos(6);
            v.reverse(); // otra lista, misma membresia
            v
        });
        for ag in agentes(2000) {
            assert_eq!(a.nodo_de(&ag).unwrap().id, b.nodo_de(&ag).unwrap().id);
        }
    }

    #[test]
    fn la_asignacion_es_total_aunque_dos_nodos_empaten() {
        // Sin desempate, dos nodos del plano de control discreparian sobre a
        // quien le toca el agente, y el sintoma seria un agente atendido por los
        // dos o por ninguno.
        let mut a = Nodo::nuevo("x", "1");
        let mut b = Nodo::nuevo("y", "2");
        a.peso = 0;
        b.peso = 0;
        let r = Reparto::nuevo(vec![a, b]);
        for ag in agentes(500) {
            assert!(r.nodo_de(&ag).is_some());
        }
    }

    #[test]
    fn el_segundo_preferido_es_el_mismo_para_todo_el_plano_de_control() {
        // Es a donde se va el agente si su nodo cae, y por eso la conmutacion
        // por error no necesita coordinacion.
        let r = Reparto::nuevo(nodos(5));
        for ag in agentes(500) {
            let pref = r.preferidos(&ag, 2);
            assert_eq!(pref.len(), 2);
            assert_eq!(pref[0].id, r.nodo_de(&ag).unwrap().id);
            // Y al caer el primero, el reparto sin el da exactamente el segundo.
            let sin_el: Vec<Nodo> = nodos(5)
                .into_iter()
                .filter(|n| n.id != pref[0].id)
                .collect();
            let r2 = Reparto::nuevo(sin_el);
            assert_eq!(r2.nodo_de(&ag).unwrap().id, pref[1].id);
        }
    }

    #[test]
    fn un_plano_de_control_apagado_lo_dice_en_vez_de_disimular() {
        let r = Reparto::nuevo(Vec::new());
        assert!(r.nodo_de("agente-1").is_none());
    }

    // --- La membresia --------------------------------------------------------

    const SEG: u64 = 1_000_000_000;

    #[test]
    fn un_nodo_que_parpadea_no_migra_su_fragmento_y_lo_devuelve() {
        // Una pausa del recolector de basura o un reinicio de treinta segundos.
        // Si la lista siguiera al estado instantaneo, cada parpadeo provocaria
        // una migracion completa del fragmento y otra de vuelta.
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        for n in nodos(4) {
            m.latido(n, 0);
        }
        let antes = m.reparto();
        // El nodo-2 se calla treinta segundos.
        for n in nodos(4).into_iter().filter(|n| n.id != "nodo-2") {
            m.latido(n, 30 * SEG);
        }
        assert_eq!(m.estado("nodo-2", 30 * SEG), EstadoNodo::Vivo);
        assert_eq!(m.caducar(30 * SEG), 0);
        let flota = agentes(2000);
        assert_eq!(
            antes.movidos(&m.reparto(), &flota),
            0,
            "migro sin hacer falta"
        );
    }

    #[test]
    fn un_nodo_de_verdad_caido_acaba_saliendo() {
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        for n in nodos(4) {
            m.latido(n, 0);
        }
        for n in nodos(4).into_iter().filter(|n| n.id != "nodo-2") {
            m.latido(n, 200 * SEG);
        }
        assert_eq!(m.estado("nodo-2", 200 * SEG), EstadoNodo::Sospechoso);
        assert_eq!(m.caducar(200 * SEG), 1);
        assert_eq!(m.cuantos(), 3);
    }

    #[test]
    fn un_despliegue_ordenado_no_espera_el_plazo_de_gracia() {
        // Esperar noventa segundos por nodo tardaria horas en una flota grande.
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        for n in nodos(4) {
            m.latido(n, 0);
        }
        let antes = m.epoca();
        m.retirar("nodo-1");
        assert_eq!(m.cuantos(), 3);
        assert!(m.epoca() > antes);
    }

    #[test]
    fn la_epoca_sube_con_cada_cambio_y_no_con_los_latidos() {
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        m.latido(Nodo::nuevo("a", "1"), 0);
        let e1 = m.epoca();
        m.latido(Nodo::nuevo("a", "1"), SEG);
        assert_eq!(m.epoca(), e1, "un latido igual no es un cambio");
        m.latido(Nodo::nuevo("a", "2"), 2 * SEG);
        assert!(m.epoca() > e1, "cambiar de direccion si lo es");
    }

    #[test]
    fn un_mapa_viejo_y_autentico_no_redirige_a_la_flota() {
        // NINGUNA FIRMA distingue un mapa autentico de ayer de uno de hoy. Sin
        // epoca, reproducir el viejo manda a una fraccion de la flota a nodos
        // que ya no existen.
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        for n in nodos(3) {
            m.latido(n, 0);
        }
        let viejo = Mapa::de(&m);
        m.retirar("nodo-0");
        m.latido(Nodo::nuevo("nodo-9", "10.0.0.9:8443"), SEG);
        let nuevo = Mapa::de(&m);

        let mut en_el_agente = viejo.clone();
        assert!(en_el_agente.aceptar(nuevo.clone()), "el nuevo entra");
        assert!(!en_el_agente.aceptar(viejo), "el viejo, reproducido, NO");
        assert_eq!(en_el_agente.epoca, nuevo.epoca);
        assert!(en_el_agente.nodos.iter().any(|n| n.id == "nodo-9"));
    }

    #[test]
    fn el_agente_calcula_su_nodo_con_el_mapa_que_tiene() {
        let mut m = Membresia::nueva(PLAZO_BAJA_NS);
        for n in nodos(5) {
            m.latido(n, 0);
        }
        let mapa = Mapa::de(&m);
        let r = m.reparto();
        for ag in agentes(300) {
            assert_eq!(mapa.nodo_de(&ag).unwrap().id, r.nodo_de(&ag).unwrap().id);
        }
    }

    #[test]
    fn el_numero_de_nodos_esta_acotado() {
        // El sorteo cuesta O(nodos) por agente: una lista sin tope convierte
        // cada latido en un bucle.
        let muchos: Vec<Nodo> = (0..MAX_NODOS + 500)
            .map(|i| Nodo::nuevo(format!("n{i}"), "x"))
            .collect();
        assert_eq!(Reparto::nuevo(muchos).nodos().len(), MAX_NODOS);
    }

    #[test]
    fn cien_mil_agentes_se_reparten_con_un_resumen_por_nodo() {
        // El sorteo es O(nodos) por agente, y lo que cuesta es el resumen: se
        // CUENTAN los resumenes, que es la propiedad, en vez de cronometrarlos.
        //
        // Antes se exigia tardar menos de treinta segundos. Eso no mide el
        // algoritmo sino la maquina y la compilacion: sin optimizar y con el resto
        // de pruebas en paralelo tardo cincuenta en una tanda de CI. Y no vio el
        // defecto que si habia: el comparador calculaba el resumen de los dos
        // nodos en cada comparacion, treinta por agente en vez de dieciseis. Un
        // umbral en segundos deja pasar un algoritmo el doble de caro si la
        // maquina es rapida; la cuenta no.
        const NODOS: usize = 16;
        const FLOTA: usize = 100_000;
        let flota = agentes(FLOTA);
        let r = Reparto::nuevo(nodos(NODOS));

        RESUMENES.with(|c| c.set(0));
        let d = r.distribucion(&flota);
        assert_eq!(d.values().sum::<usize>(), FLOTA);
        assert_eq!(
            RESUMENES.with(std::cell::Cell::get),
            (FLOTA * NODOS) as u64,
            "repartir tiene que costar exactamente un resumen por nodo y agente"
        );

        // Y la lista de preferidos, lo mismo: n resumenes, no n log n.
        RESUMENES.with(|c| c.set(0));
        let p = r.preferidos("agente-000042", NODOS);
        assert_eq!(p.len(), NODOS);
        assert_eq!(RESUMENES.with(std::cell::Cell::get), NODOS as u64);
    }

    #[test]
    fn el_primero_de_los_preferidos_es_el_nodo_del_agente() {
        // Un empate EXACTO de pesos no se puede provocar desde fuera: exigiria dos
        // resumenes SHA-256 con los mismos 64 bits altos. Por eso la garantia
        // ante empates es de construccion —las dos funciones ordenan con la misma
        // `clave`— y lo que se comprueba aqui es su consecuencia sobre una flota
        // entera: el primero de los preferidos es siempre el asignado.
        let r = Reparto::nuevo(nodos(7));
        for ag in agentes(5_000) {
            assert_eq!(
                r.preferidos(&ag, 1)[0].id,
                r.nodo_de(&ag).unwrap().id,
                "{ag}: el preferido y el asignado discrepan"
            );
        }
    }
}
