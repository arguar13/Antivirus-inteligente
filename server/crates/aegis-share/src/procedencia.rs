//! De donde vino cada cosa, y como se deshace un canal envenenado.
//!
//! # El problema, dicho por el final
//!
//! Un canal comunitario mete durante tres semanas indicadores fabricados: la IP
//! del resolutor publico que usa media industria, el resumen de una biblioteca
//! firmada, el dominio de un proveedor de correo. Se descubre. **¿Y ahora que?**
//!
//! Sin procedencia, la respuesta es «no se sabe cuales eran suyos», y entonces
//! solo quedan dos salidas y las dos son malas: vaciar la base entera y volver a
//! poblarla —perdiendo lo bueno de tres semanas—, o dejarlo y seguir bloqueando
//! el resolutor publico. El envenenamiento no se nota cuando ocurre; se nota
//! cuando hay que deshacerlo y no se puede.
//!
//! # Las dos decisiones que hacen esto reversible
//!
//! 1. **La confianza no se guarda, se calcula.** Si se guardara un escalar,
//!    quitar un aporte dejaria el numero inflado que ese aporte ayudo a subir. Se
//!    recalcula de los aportes vivos, siempre.
//! 2. **Un objeto con varios aportes sobrevive a la revocacion de uno.** Lo que
//!    dijeron los demas sigue siendo cierto. Borrar el objeto entero castigaria a
//!    las fuentes buenas por haber coincidido con la mala.
//!
//! # Y la que casi nadie toma: dos canales que repiten al mismo no son dos
//!
//! Si el canal A y el canal B se nutren los dos del canal C, «dos fuentes
//! coinciden» es **una** fuente contada dos veces. Es la forma mas comun de que
//! un indicador parezca corroborado sin estarlo, y es exactamente lo que
//! aprovecha quien envenena: envenena C y cobra en A y en B.
//!
//! Por eso un aporte lleva su **cadena de origen** —por donde paso antes de
//! llegar— y [`Ficha::fuentes_independientes`] cuenta raices distintas, no
//! aportes. Ver [`Aporte::raiz`].

use std::collections::{BTreeMap, BTreeSet};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;
/// Un dia, en nanosegundos.
const DIA: u64 = 24 * 3600 * SEG;

/// Aportes maximos por objeto.
///
/// Acotado porque el numero de aportes lo decide **quien comparte**: una
/// federacion con cien instancias que reemiten en bucle acumularia aportes sin
/// fin sobre el mismo objeto. Al llegar al tope se conserva el mas reciente de
/// cada fuente, que es lo unico que aporta informacion.
pub const MAX_APORTES: usize = 64;

/// Cuanto tarda un aporte en dejar de contar, si nadie lo repite.
///
/// Noventa dias. Un canal que dijo algo hace tres meses y no lo ha vuelto a decir
/// puede haberlo retirado sin avisar —es lo normal en los canales abiertos— y
/// seguir contandolo es sostener un indicador que su propia fuente ya no sostiene.
pub const VIGENCIA_APORTE_NS: u64 = 90 * DIA;

/// Como de fiable es una fuente.
///
/// El orden es de **mas a menos**, igual que las clases de `aegis-enrich`, y por
/// la misma razon: es el orden de autoridad y la resolucion de conflictos lo usa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fiabilidad {
    /// Observacion propia: lo vimos nosotros.
    Propia,
    /// Un socio con acuerdo y responsabilidad.
    Acordada,
    /// Una comunidad cerrada de la que se conoce a los miembros.
    Comunidad,
    /// Un canal abierto.
    ///
    /// Util y a menudo el primero en ver una campana. Tambien el unico que
    /// cualquiera puede envenenar sin identificarse.
    Abierta,
}

impl Fiabilidad {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Fiabilidad::Propia => "propia",
            Fiabilidad::Acordada => "acordada",
            Fiabilidad::Comunidad => "comunidad",
            Fiabilidad::Abierta => "abierta",
        }
    }

    /// Peso en centesimas para el calculo de confianza.
    #[must_use]
    pub fn peso(self) -> u32 {
        match self {
            Fiabilidad::Propia => 100,
            Fiabilidad::Acordada => 70,
            Fiabilidad::Comunidad => 45,
            Fiabilidad::Abierta => 20,
        }
    }
}

/// Lo que una fuente aporto sobre un objeto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aporte {
    /// Quien lo entrego a esta instancia.
    pub fuente: String,
    /// De que clase es esa fuente.
    pub fiabilidad: Fiabilidad,
    /// Por donde paso antes de llegar, del origen al ultimo salto.
    ///
    /// Vacio significa que la fuente **es** el origen. Ver
    /// [`Ficha::fuentes_independientes`].
    pub cadena: Vec<String>,
    /// Cuando llego, en nanosegundos Unix.
    pub cuando_ns: u64,
    /// Que confianza declaro la fuente, en centesimas.
    pub confianza_declarada: u8,
    /// El identificador del objeto tal y como lo nombraba la fuente.
    ///
    /// Se guarda porque en una federacion el mismo indicador llega con
    /// identificadores distintos, y sin esto no se puede reconstruir que mando
    /// exactamente cada uno cuando hay que discutirlo.
    pub id_en_origen: String,
}

impl Aporte {
    /// La raiz de la cadena: de donde salio esto de verdad.
    ///
    /// Es lo que permite no contar dos veces al mismo. Si el canal A y el canal B
    /// se nutren los dos de C, sus aportes tienen la misma raiz y cuentan como
    /// **una** fuente.
    #[must_use]
    pub fn raiz(&self) -> &str {
        self.cadena.first().unwrap_or(&self.fuente)
    }

    /// Si sigue vigente.
    #[must_use]
    pub fn vigente(&self, ahora_ns: u64) -> bool {
        ahora_ns.saturating_sub(self.cuando_ns) <= VIGENCIA_APORTE_NS
    }
}

/// Todo lo que se sabe del origen de un objeto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ficha {
    /// El identificador del objeto en esta instancia.
    pub id: String,
    /// Los aportes, el mas reciente primero.
    pub aportes: Vec<Aporte>,
}

impl Ficha {
    /// Una ficha vacia.
    #[must_use]
    pub fn nueva(id: impl Into<String>) -> Ficha {
        Ficha {
            id: id.into(),
            aportes: Vec::new(),
        }
    }

    /// Anota un aporte.
    ///
    /// Si esa fuente ya habia aportado, se **sustituye**: lo que dice hoy manda
    /// sobre lo que dijo ayer, y acumular las dos versiones haria que una fuente
    /// que repite mucho pesara mas que una que acierta.
    pub fn anotar(&mut self, aporte: Aporte) {
        self.aportes.retain(|a| a.fuente != aporte.fuente);
        self.aportes.push(aporte);
        self.aportes
            .sort_by(|a, b| b.cuando_ns.cmp(&a.cuando_ns).then(a.fuente.cmp(&b.fuente)));
        self.aportes.truncate(MAX_APORTES);
    }

    /// Aportes vigentes.
    #[must_use]
    pub fn vivos(&self, ahora_ns: u64) -> Vec<&Aporte> {
        self.aportes
            .iter()
            .filter(|a| a.vigente(ahora_ns))
            .collect()
    }

    /// Cuantas fuentes **de verdad distintas** sostienen esto.
    ///
    /// Cuenta raices de cadena, no aportes. Es la cifra que importa: tres canales
    /// que repiten al mismo no son tres opiniones, son una repetida tres veces —
    /// y quien envenena el de arriba cobra en los tres.
    #[must_use]
    pub fn fuentes_independientes(&self, ahora_ns: u64) -> usize {
        self.vivos(ahora_ns)
            .iter()
            .map(|a| a.raiz())
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// La confianza efectiva, en centesimas.
    ///
    /// **Se calcula, no se guarda.** Si se guardara, quitar un aporte dejaria el
    /// numero inflado que ese aporte ayudo a subir, y la revocacion de un canal
    /// envenenado no se notaria en la cifra que decide si se bloquea.
    ///
    /// El criterio: manda la fuente **mas fiable** que lo sostiene, y las demas
    /// **raices independientes** suman un poco. Sumar por aporte en vez de por
    /// raiz seria contar la repeticion como corroboracion.
    #[must_use]
    pub fn confianza(&self, ahora_ns: u64) -> u8 {
        let vivos = self.vivos(ahora_ns);
        if vivos.is_empty() {
            return 0;
        }
        let mejor = vivos
            .iter()
            .min_by_key(|a| a.fiabilidad)
            .expect("no esta vacio");
        let base = u32::from(mejor.confianza_declarada).min(mejor.fiabilidad.peso());

        // Cada raiz independiente ADICIONAL suma un octavo de lo que falta para
        // cien. Es asintotico a proposito: por muchos canales que repitan algo,
        // la repeticion no lo convierte en observacion propia.
        let extra = self.fuentes_independientes(ahora_ns).saturating_sub(1);
        let mut c = base;
        for _ in 0..extra.min(8) {
            c += (100 - c) / 8;
        }
        u8::try_from(c.min(100)).unwrap_or(100)
    }

    /// La fiabilidad de la mejor fuente que lo sostiene.
    #[must_use]
    pub fn mejor_fiabilidad(&self, ahora_ns: u64) -> Option<Fiabilidad> {
        self.vivos(ahora_ns).iter().map(|a| a.fiabilidad).min()
    }

    /// Si esto lo sostiene alguien que no sea la fuente dada.
    #[must_use]
    pub fn sostenido_sin(&self, fuente: &str, ahora_ns: u64) -> bool {
        self.vivos(ahora_ns)
            .iter()
            .any(|a| a.fuente != fuente && a.raiz() != fuente)
    }
}

/// Lo que paso al revocar una fuente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocacion {
    /// Objetos que desaparecen: nadie mas los sostenia.
    pub caidos: Vec<String>,
    /// Objetos que siguen, con su confianza antes y despues.
    ///
    /// Es lo que hace la revocacion **auditable**: un informe que solo dice
    /// «retirados 412» no permite comprobar nada. Con el antes y el despues se
    /// puede revisar si el resultado tiene sentido.
    pub rebajados: Vec<(String, u8, u8)>,
    /// Cuantos aportes se quitaron en total.
    pub aportes_retirados: usize,
}

impl Revocacion {
    /// Si no cambio nada.
    #[must_use]
    pub fn vacia(&self) -> bool {
        self.caidos.is_empty() && self.rebajados.is_empty()
    }

    /// Resumen legible.
    #[must_use]
    pub fn resumen(&self, fuente: &str) -> String {
        format!(
            "revocada «{fuente}»: {} objeto(s) caen porque nadie mas los sostenia, {} siguen con \
             la confianza recalculada, {} aporte(s) retirados",
            self.caidos.len(),
            self.rebajados.len(),
            self.aportes_retirados
        )
    }
}

/// El registro de procedencia de todos los objetos.
#[derive(Debug, Clone, Default)]
pub struct Registro {
    fichas: BTreeMap<String, Ficha>,
}

impl Registro {
    /// Un registro vacio.
    #[must_use]
    pub fn nuevo() -> Registro {
        Registro::default()
    }

    /// Anota un aporte sobre un objeto.
    pub fn anotar(&mut self, id: &str, aporte: Aporte) {
        self.fichas
            .entry(id.to_string())
            .or_insert_with(|| Ficha::nueva(id))
            .anotar(aporte);
    }

    /// La ficha de un objeto.
    #[must_use]
    pub fn ficha(&self, id: &str) -> Option<&Ficha> {
        self.fichas.get(id)
    }

    /// Cuantos objetos hay.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.fichas.len()
    }

    /// Los objetos que una fuente aporto, directamente o como raiz de la cadena.
    ///
    /// Incluye lo que llego **a traves de otros**: si el canal envenenado es la
    /// raiz, da igual por cuantos saltos haya pasado.
    #[must_use]
    pub fn aportados_por(&self, fuente: &str, ahora_ns: u64) -> Vec<&str> {
        self.fichas
            .values()
            .filter(|f| {
                f.vivos(ahora_ns).iter().any(|a| {
                    a.fuente == fuente || a.raiz() == fuente || a.cadena.iter().any(|c| c == fuente)
                })
            })
            .map(|f| f.id.as_str())
            .collect()
    }

    /// Revoca todo lo que venga de una fuente, directa o indirectamente.
    ///
    /// Es la operacion que da sentido al modulo entero: sin ella, descubrir un
    /// canal envenenado deja dos salidas y las dos son malas — vaciar la base
    /// entera, o seguir bloqueando el resolutor publico que metio.
    pub fn revocar_fuente(&mut self, fuente: &str, ahora_ns: u64) -> Revocacion {
        let mut r = Revocacion::default();
        let mut a_borrar: Vec<String> = Vec::new();

        for f in self.fichas.values_mut() {
            let antes = f.confianza(ahora_ns);
            let previos = f.aportes.len();
            // Se quita tanto lo que entrego esa fuente como lo que paso POR ella:
            // un aporte que llego a traves del canal envenenado lo pudo alterar
            // al reemitirlo, y no hay forma de saber que no lo hizo.
            f.aportes.retain(|a| {
                a.fuente != fuente && a.raiz() != fuente && !a.cadena.iter().any(|c| c == fuente)
            });
            r.aportes_retirados += previos - f.aportes.len();

            if f.aportes.is_empty() {
                a_borrar.push(f.id.clone());
                r.caidos.push(f.id.clone());
            } else {
                let despues = f.confianza(ahora_ns);
                if despues != antes {
                    r.rebajados.push((f.id.clone(), antes, despues));
                }
            }
        }
        for id in a_borrar {
            self.fichas.remove(&id);
        }
        r.caidos.sort();
        r.rebajados.sort();
        r
    }

    /// Cuanto aporta cada fuente, para ver de un vistazo de quien se depende.
    #[must_use]
    pub fn por_fuente(&self, ahora_ns: u64) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for f in self.fichas.values() {
            for a in f.vivos(ahora_ns) {
                *m.entry(a.fuente.clone()).or_insert(0) += 1;
            }
        }
        m
    }

    /// Objetos que dependen de **una sola** raiz, agrupados por esa raiz.
    ///
    /// Es la cifra de riesgo real de la base: son los que caerian enteros si esa
    /// fuente resultara envenenada. Un panel que solo enseña «450.000
    /// indicadores» no dice nada; uno que enseña «310.000 dependen de un solo
    /// canal abierto» dice bastante.
    #[must_use]
    pub fn dependencia_unica(&self, ahora_ns: u64) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for f in self.fichas.values() {
            if f.fuentes_independientes(ahora_ns) == 1 {
                if let Some(a) = f.vivos(ahora_ns).first() {
                    *m.entry(a.raiz().to_string()).or_insert(0) += 1;
                }
            }
        }
        m
    }

    /// Quita los aportes caducados y los objetos que se quedan sin ninguno.
    pub fn purgar(&mut self, ahora_ns: u64) -> usize {
        let antes = self.fichas.len();
        for f in self.fichas.values_mut() {
            f.aportes.retain(|a| a.vigente(ahora_ns));
        }
        self.fichas.retain(|_, f| !f.aportes.is_empty());
        antes - self.fichas.len()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const AHORA: u64 = 1_700_000_000 * SEG;

    fn aporte(fuente: &str, fiab: Fiabilidad, cadena: &[&str], hace: u64) -> Aporte {
        Aporte {
            fuente: fuente.into(),
            fiabilidad: fiab,
            cadena: cadena.iter().map(|s| (*s).to_string()).collect(),
            cuando_ns: AHORA - hace,
            confianza_declarada: 80,
            id_en_origen: format!("indicator--de-{fuente}"),
        }
    }

    #[test]
    fn un_objeto_con_dos_aportes_sobrevive_a_revocar_uno() {
        // Lo que dijeron los demas sigue siendo cierto. Borrar el objeto entero
        // castigaria a las fuentes buenas por haber coincidido con la mala.
        let mut r = Registro::nuevo();
        r.anotar("ind-1", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        r.anotar("ind-1", aporte("socio", Fiabilidad::Acordada, &[], 0));

        let rev = r.revocar_fuente("veneno", AHORA);
        assert!(
            rev.caidos.is_empty(),
            "no deberia caer: lo sostiene el socio"
        );
        assert_eq!(rev.aportes_retirados, 1);
        assert!(r.ficha("ind-1").is_some());
    }

    #[test]
    fn un_objeto_que_solo_sostenia_el_canal_envenenado_cae() {
        let mut r = Registro::nuevo();
        r.anotar("ind-solo", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        let rev = r.revocar_fuente("veneno", AHORA);
        assert_eq!(rev.caidos, vec!["ind-solo".to_string()]);
        assert!(r.ficha("ind-solo").is_none());
    }

    #[test]
    fn la_confianza_se_recalcula_al_revocar() {
        // Si se guardara un escalar, quitar un aporte dejaria el numero inflado
        // que ese aporte ayudo a subir, y la revocacion no se notaria en la cifra
        // que decide si se bloquea.
        let mut r = Registro::nuevo();
        r.anotar("ind-1", aporte("socio", Fiabilidad::Acordada, &[], 0));
        r.anotar("ind-1", aporte("com-a", Fiabilidad::Comunidad, &[], 0));
        r.anotar("ind-1", aporte("com-b", Fiabilidad::Comunidad, &[], 0));
        let antes = r.ficha("ind-1").expect("esta").confianza(AHORA);

        let rev = r.revocar_fuente("com-a", AHORA);
        let despues = r.ficha("ind-1").expect("sigue").confianza(AHORA);
        assert!(
            despues < antes,
            "la confianza no bajo: {antes} -> {despues}"
        );
        // Y queda registrado el antes y el despues, para poder auditarlo.
        assert_eq!(rev.rebajados, vec![("ind-1".to_string(), antes, despues)]);
    }

    #[test]
    fn tres_canales_que_repiten_al_mismo_cuentan_como_uno() {
        // La forma mas comun de que un indicador parezca corroborado sin estarlo,
        // y lo que aprovecha quien envenena: envenena el de arriba y cobra en los
        // tres de abajo.
        let mut r = Registro::nuevo();
        r.anotar(
            "ind-1",
            aporte("canal-a", Fiabilidad::Comunidad, &["origen"], 0),
        );
        r.anotar(
            "ind-1",
            aporte("canal-b", Fiabilidad::Comunidad, &["origen"], 0),
        );
        r.anotar(
            "ind-1",
            aporte("canal-c", Fiabilidad::Comunidad, &["origen"], 0),
        );

        let f = r.ficha("ind-1").expect("esta");
        assert_eq!(f.vivos(AHORA).len(), 3, "hay tres aportes");
        assert_eq!(
            f.fuentes_independientes(AHORA),
            1,
            "pero una sola fuente de verdad"
        );

        // Y revocar el origen se lo lleva todo, aunque llegara por otros.
        let rev = r.revocar_fuente("origen", AHORA);
        assert_eq!(rev.caidos, vec!["ind-1".to_string()]);
    }

    #[test]
    fn tres_fuentes_independientes_dan_mas_confianza_que_una() {
        let mut uno = Registro::nuevo();
        uno.anotar("x", aporte("a", Fiabilidad::Comunidad, &[], 0));

        let mut tres = Registro::nuevo();
        tres.anotar("x", aporte("a", Fiabilidad::Comunidad, &[], 0));
        tres.anotar("x", aporte("b", Fiabilidad::Comunidad, &[], 0));
        tres.anotar("x", aporte("c", Fiabilidad::Comunidad, &[], 0));

        assert!(
            tres.ficha("x").expect("x").confianza(AHORA)
                > uno.ficha("x").expect("x").confianza(AHORA)
        );
    }

    #[test]
    fn la_repeticion_no_convierte_un_canal_abierto_en_observacion_propia() {
        // Asintotico a proposito: por muchos canales que repitan algo, la
        // repeticion no lo convierte en haberlo visto.
        let mut r = Registro::nuevo();
        for i in 0..40 {
            r.anotar(
                "x",
                aporte(&format!("abierto-{i}"), Fiabilidad::Abierta, &[], 0),
            );
        }
        let c = r.ficha("x").expect("x").confianza(AHORA);
        assert!(c < 100, "llego a certeza por repeticion: {c}");

        let mut propia = Registro::nuevo();
        let mut a = aporte("nuestro-laboratorio", Fiabilidad::Propia, &[], 0);
        a.confianza_declarada = 99;
        propia.anotar("x", a);
        assert!(propia.ficha("x").expect("x").confianza(AHORA) > c);
    }

    #[test]
    fn una_fuente_que_repite_no_pesa_mas_que_una_que_acierta() {
        // Acumular las dos versiones del mismo emisor haria que repetir mucho
        // contara como corroborar.
        let mut r = Registro::nuevo();
        for i in 0..10 {
            r.anotar("x", aporte("canal", Fiabilidad::Abierta, &[], i * SEG));
        }
        assert_eq!(r.ficha("x").expect("x").aportes.len(), 1);
    }

    #[test]
    fn un_aporte_viejo_deja_de_contar() {
        // Un canal que dijo algo hace tres meses y no lo ha repetido puede
        // haberlo retirado sin avisar, y seguir contandolo es sostener un
        // indicador que su propia fuente ya no sostiene.
        let mut r = Registro::nuevo();
        r.anotar(
            "x",
            aporte(
                "canal",
                Fiabilidad::Comunidad,
                &[],
                VIGENCIA_APORTE_NS + DIA,
            ),
        );
        assert_eq!(r.ficha("x").expect("x").confianza(AHORA), 0);
        assert_eq!(r.ficha("x").expect("x").vivos(AHORA).len(), 0);
        assert_eq!(r.purgar(AHORA), 1);
        assert_eq!(r.cuantos(), 0);
    }

    #[test]
    fn revocar_lo_que_paso_por_la_fuente_envenenada_tambien() {
        // Un aporte que llego a traves del canal envenenado lo pudo alterar al
        // reemitirlo, y no hay forma de saber que no lo hizo.
        let mut r = Registro::nuevo();
        r.anotar(
            "x",
            aporte(
                "destino",
                Fiabilidad::Comunidad,
                &["origen-bueno", "veneno"],
                0,
            ),
        );
        let rev = r.revocar_fuente("veneno", AHORA);
        assert_eq!(rev.caidos, vec!["x".to_string()]);
    }

    #[test]
    fn revocar_es_idempotente() {
        // Si no lo fuera, ejecutar la limpieza dos veces —algo que pasa— daria
        // resultados distintos y el informe de la segunda seria mentira.
        let mut r = Registro::nuevo();
        r.anotar("a", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        r.anotar("b", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        r.anotar("b", aporte("socio", Fiabilidad::Acordada, &[], 0));

        let una = r.revocar_fuente("veneno", AHORA);
        let dos = r.revocar_fuente("veneno", AHORA);
        assert!(!una.vacia());
        assert!(dos.vacia(), "la segunda revocacion cambio algo");
    }

    #[test]
    fn se_ve_de_que_fuente_depende_la_base() {
        // Un panel que solo enseña «450.000 indicadores» no dice nada; uno que
        // enseña «310.000 dependen de un solo canal abierto» dice bastante.
        let mut r = Registro::nuevo();
        for i in 0..10 {
            r.anotar(
                &format!("solo-{i}"),
                aporte("abierto", Fiabilidad::Abierta, &[], 0),
            );
        }
        for i in 0..3 {
            let id = format!("doble-{i}");
            r.anotar(&id, aporte("abierto", Fiabilidad::Abierta, &[], 0));
            r.anotar(&id, aporte("socio", Fiabilidad::Acordada, &[], 0));
        }
        let dep = r.dependencia_unica(AHORA);
        assert_eq!(dep.get("abierto"), Some(&10));
        assert_eq!(r.por_fuente(AHORA).get("abierto"), Some(&13));
    }

    #[test]
    fn se_listan_los_objetos_de_una_fuente_antes_de_revocarla() {
        // Hay que poder mirar lo que se va a tirar ANTES de tirarlo: una
        // revocacion a ciegas sobre cuatrocientos mil indicadores no la firma
        // nadie.
        let mut r = Registro::nuevo();
        r.anotar("a", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        r.anotar("b", aporte("otro", Fiabilidad::Abierta, &["veneno"], 0));
        r.anotar("c", aporte("limpio", Fiabilidad::Acordada, &[], 0));

        let mut suyos = r.aportados_por("veneno", AHORA);
        suyos.sort_unstable();
        assert_eq!(suyos, vec!["a", "b"]);
    }

    #[test]
    fn el_numero_de_aportes_esta_acotado() {
        // Lo decide quien comparte: una federacion de cien instancias que
        // reemiten en bucle acumularia aportes sin fin sobre el mismo objeto.
        let mut r = Registro::nuevo();
        for i in 0..(MAX_APORTES * 3) {
            r.anotar(
                "x",
                aporte(&format!("f-{i}"), Fiabilidad::Abierta, &[], i as u64),
            );
        }
        assert_eq!(r.ficha("x").expect("x").aportes.len(), MAX_APORTES);
    }

    #[test]
    fn la_revocacion_se_explica() {
        let mut r = Registro::nuevo();
        r.anotar("a", aporte("veneno", Fiabilidad::Abierta, &[], 0));
        let rev = r.revocar_fuente("veneno", AHORA);
        let t = rev.resumen("veneno");
        assert!(t.contains("veneno") && t.contains("1 objeto"));
    }

    #[test]
    fn manda_la_fuente_mas_fiable_y_no_la_que_mas_confianza_declara() {
        // Un canal abierto que se declara al 100 % no puede pesar mas que nuestro
        // propio laboratorio: declarar confianza es gratis.
        let mut r = Registro::nuevo();
        let mut fanfarron = aporte("abierto", Fiabilidad::Abierta, &[], 0);
        fanfarron.confianza_declarada = 100;
        r.anotar("x", fanfarron);
        let solo_abierto = r.ficha("x").expect("x").confianza(AHORA);
        assert!(
            solo_abierto <= Fiabilidad::Abierta.peso() as u8,
            "un canal abierto se creyo su propio 100 %"
        );

        r.anotar("x", aporte("laboratorio", Fiabilidad::Propia, &[], 0));
        assert_eq!(
            r.ficha("x").expect("x").mejor_fiabilidad(AHORA),
            Some(Fiabilidad::Propia)
        );
        assert!(r.ficha("x").expect("x").confianza(AHORA) > solo_abierto);
    }
}
