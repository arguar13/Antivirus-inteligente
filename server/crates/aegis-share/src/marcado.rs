//! TLP y PAP, impuestos en el codigo y no en un documento.
//!
//! # Los dos ejes, y por que confundirlos es el fallo clasico
//!
//! Casi todo el mundo implementa TLP y se olvida de PAP, o peor: los trata como
//! si fueran el mismo eje. Son dos preguntas distintas:
//!
//! - **TLP** (*Traffic Light Protocol*) responde a **quien puede VERLO**.
//! - **PAP** (*Permissible Actions Protocol*) responde a **que puedes HACER con
//!   ello sin que el adversario lo note**.
//!
//! La combinacion que enseña por que hacen falta los dos es `TLP:GREEN` con
//! `PAP:RED`: el dominio de mando y control se puede compartir con toda la
//! comunidad, **y no se puede bloquear**. Porque bloquearlo le dice al atacante
//! que se le ha visto, y entonces cambia de infraestructura y se pierde la
//! visibilidad que costo meses conseguir.
//!
//! Un producto que solo implementa TLP hace exactamente eso: recibe un indicador
//! compartible, lo empuja al motor de bloqueo, y quema la operacion de quien lo
//! compartio. La siguiente vez no se lo mandan.
//!
//! # El retículo: solo se puede restringir, nunca aflojar
//!
//! Es la misma doctrina de la FASE 23 y del enjambre —solo se puede anadir
//! proteccion, jamas quitarla— aplicada al marcado:
//!
//! - Al **combinar** dos objetos, el resultado toma el marcado **mas
//!   restrictivo** de los dos. Un informe que cita una fuente `TLP:RED` es
//!   `TLP:RED`, por mucho que lo demas fuera publico.
//! - Al **propagarse**, un marcado puede subir de restriccion y nunca bajar. Una
//!   instancia que recibiera un objeto `TLP:AMBER` y lo reemitiera como
//!   `TLP:CLEAR` estaria filtrando, y lo estaria haciendo con formato valido.
//!
//! Por eso [`Marcado::combinar`] y [`Marcado::admite_reemision_como`] existen, y
//! por eso no hay ninguna funcion que afloje.

use std::fmt;

/// Quien puede ver algo.
///
/// El orden del enumerado es de **menos a mas restrictivo**, y la comparacion se
/// usa de verdad: `Tlp::Clear < Tlp::Red`. Que el orden sea el de la semantica y
/// no el alfabetico es lo que permite que `max` sea «lo mas restrictivo de los
/// dos» sin escribir una tabla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tlp {
    /// Sin restriccion: se puede publicar.
    ///
    /// TLP 2.0 lo llama `CLEAR`; `WHITE` es el nombre de TLP 1.0 y sigue
    /// apareciendo en fuentes antiguas. Se acepta al leer y **no** se emite.
    Clear,
    /// Se puede compartir con la comunidad, sin publicar.
    Green,
    /// Solo con la propia organizacion y sus clientes.
    Amber,
    /// Solo con la propia organizacion, **sin** sus clientes.
    ///
    /// `TLP:AMBER+STRICT` es **mas** restrictivo que `TLP:AMBER`, y el orden del
    /// enumerado lo refleja: mezclarlos al reves es una fuga con formato valido.
    ///
    /// Y el nombre de la variante tiene que decir lo mismo que su valor. Aqui
    /// estuvieron cambiados: `Tlp::Amber` valia `TLP:AMBER+STRICT` y viceversa.
    /// El orden y las comprobaciones eran correctos —las pruebas pasaban—, pero
    /// quien escribiera `Tlp::Amber` leyendo «AMBER» obtenia otra cosa, y el
    /// error no aparece hasta que alguien comparte de mas con un `<=` que
    /// creia entender. Un identificador que miente sobre su valor es un fallo
    /// de seguridad aunque la aritmetica este bien.
    AmberStrict,
    /// Solo para quien lo recibio en persona. No se reenvia.
    Red,
}

impl Tlp {
    /// Nombre canonico de TLP 2.0.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Tlp::Clear => "TLP:CLEAR",
            Tlp::Green => "TLP:GREEN",
            Tlp::Amber => "TLP:AMBER",
            Tlp::AmberStrict => "TLP:AMBER+STRICT",
            Tlp::Red => "TLP:RED",
        }
    }

    /// Interpreta una etiqueta escrita por otro.
    ///
    /// # Lo que hace aqui la ausencia de un valor por defecto permisivo
    ///
    /// Devuelve `None` si no se reconoce, y quien llama **trata lo desconocido
    /// como [`Tlp::Red`]**. Un marcado que no se entiende no puede resolverse
    /// «hacia lo abierto»: si un dia aparece `TLP:PINK` en una comunidad y lo
    /// leyeramos como `CLEAR`, publicariamos algo cuya restriccion no supimos
    /// leer.
    #[must_use]
    pub fn de_etiqueta(s: &str) -> Option<Tlp> {
        let n = s.trim().to_ascii_uppercase().replace(' ', "");
        let n = n.strip_prefix("TLP:").unwrap_or(&n);
        match n {
            // `WHITE` es TLP 1.0. Se acepta al leer porque sigue circulando, y no
            // se emite nunca: ver `nombre`.
            "CLEAR" | "WHITE" => Some(Tlp::Clear),
            "GREEN" => Some(Tlp::Green),
            "AMBER" => Some(Tlp::Amber),
            "AMBER+STRICT" | "AMBERSTRICT" => Some(Tlp::AmberStrict),
            "RED" => Some(Tlp::Red),
            _ => None,
        }
    }

    /// Si esto se puede publicar sin restriccion.
    #[must_use]
    pub fn publicable(self) -> bool {
        self == Tlp::Clear
    }
}

/// Que se puede HACER con ello sin que el adversario lo note.
///
/// Mismo criterio de orden: de menos a mas restrictivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pap {
    /// Se puede actuar sin restriccion, incluida accion visible para el
    /// adversario: bloquear, publicar una firma, retirar un dominio.
    Clear,
    /// Accion permitida si el adversario **no puede atribuirla** a esta fuente.
    ///
    /// Bloquear en el perimetro propio, si. Publicar una firma con el nombre de
    /// quien lo compartio, no.
    Green,
    /// Solo accion pasiva: buscar en lo que ya se tiene, sin tocar nada vivo.
    ///
    /// Nada de resolver el dominio, escanear la IP ni mandar la muestra a un
    /// servicio: cualquiera de esas cosas aparece en los registros del
    /// adversario si controla la infraestructura, y varias los controlan.
    Amber,
    /// **Ninguna accion.** Solo conocimiento.
    ///
    /// Es la que se olvida. Con `PAP:RED`, meter el indicador en el motor de
    /// bloqueo quema la operacion de quien lo compartio, aunque el TLP permitiera
    /// contarselo a medio mundo.
    Red,
}

impl Pap {
    /// Nombre canonico.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Pap::Clear => "PAP:CLEAR",
            Pap::Green => "PAP:GREEN",
            Pap::Amber => "PAP:AMBER",
            Pap::Red => "PAP:RED",
        }
    }

    /// Interpreta una etiqueta escrita por otro. Lo desconocido es `None`.
    #[must_use]
    pub fn de_etiqueta(s: &str) -> Option<Pap> {
        let n = s.trim().to_ascii_uppercase().replace(' ', "");
        let n = n.strip_prefix("PAP:").unwrap_or(&n);
        match n {
            "CLEAR" | "WHITE" => Some(Pap::Clear),
            "GREEN" => Some(Pap::Green),
            "AMBER" => Some(Pap::Amber),
            "RED" => Some(Pap::Red),
            _ => None,
        }
    }

    /// Si permite una accion que el adversario puede observar.
    ///
    /// Es la pregunta que hay que hacerse antes de empujar un indicador al motor
    /// de bloqueo, y la que nadie hace.
    #[must_use]
    pub fn permite_accion_visible(self) -> bool {
        self == Pap::Clear
    }

    /// Si permite bloquear en la propia infraestructura.
    #[must_use]
    pub fn permite_bloqueo_propio(self) -> bool {
        self <= Pap::Green
    }

    /// Si permite siquiera buscarlo en lo que ya se tiene.
    ///
    /// `PAP:RED` permite **conocer** y nada mas. Ni la busqueda retroactiva, que
    /// parece inocua: en un entorno donde el adversario tiene visibilidad del
    /// SIEM —y en un compromiso serio la tiene— una consulta es una señal.
    #[must_use]
    pub fn permite_busqueda(self) -> bool {
        self <= Pap::Amber
    }
}

/// El marcado completo de un objeto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Marcado {
    /// Quien puede verlo.
    pub tlp: Tlp,
    /// Que se puede hacer con ello.
    pub pap: Pap,
}

impl Marcado {
    /// El marcado por defecto de lo que entra sin decir nada.
    ///
    /// **Lo mas restrictivo que existe.** Un objeto que llega sin marcado no es
    /// un objeto publico: es un objeto cuyo marcado no sabemos. Tratarlo como
    /// abierto es la forma mas facil y mas silenciosa de filtrar lo de otro.
    #[must_use]
    pub fn desconocido() -> Marcado {
        Marcado {
            tlp: Tlp::Red,
            pap: Pap::Red,
        }
    }

    /// Un marcado explicito.
    #[must_use]
    pub fn nuevo(tlp: Tlp, pap: Pap) -> Marcado {
        Marcado { tlp, pap }
    }

    /// Lo mas abierto posible.
    #[must_use]
    pub fn publico() -> Marcado {
        Marcado {
            tlp: Tlp::Clear,
            pap: Pap::Clear,
        }
    }

    /// Combina dos marcados quedandose con **lo mas restrictivo de cada eje**.
    ///
    /// Los dos ejes se combinan por separado, y eso importa: un objeto
    /// `TLP:CLEAR/PAP:RED` combinado con `TLP:RED/PAP:CLEAR` da
    /// `TLP:RED/PAP:RED`. Tomar «el peor de los dos objetos» como bloque daria
    /// uno de los dos originales y perderia la mitad de la restriccion.
    #[must_use]
    pub fn combinar(self, otro: Marcado) -> Marcado {
        Marcado {
            tlp: self.tlp.max(otro.tlp),
            pap: self.pap.max(otro.pap),
        }
    }

    /// Si se puede reemitir con este otro marcado.
    ///
    /// Solo hacia **igual o mas restrictivo**. Una instancia que recibiera un
    /// objeto `TLP:AMBER` y lo reemitiera como `TLP:CLEAR` estaria filtrando, y
    /// lo estaria haciendo con un documento perfectamente valido — que es
    /// justamente por lo que hace falta comprobarlo en el codigo.
    #[must_use]
    pub fn admite_reemision_como(self, nuevo: Marcado) -> bool {
        nuevo.tlp >= self.tlp && nuevo.pap >= self.pap
    }

    /// Si esto puede salir hacia un destinatario que solo admite hasta `tope`.
    #[must_use]
    pub fn visible_para(self, tope: Tlp) -> bool {
        self.tlp <= tope
    }

    /// Las dos etiquetas, para el documento STIX.
    #[must_use]
    pub fn etiquetas(self) -> [&'static str; 2] {
        [self.tlp.nombre(), self.pap.nombre()]
    }
}

impl fmt::Display for Marcado {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.tlp.nombre(), self.pap.nombre())
    }
}

/// Lo que unas etiquetas dicen de CADA eje, sin resolver todavia lo que callan.
///
/// # Por que hace falta separar esto
///
/// Un objeto STIX puede declarar su TLP por **etiqueta** y su PAP por
/// **referencia a un marcado**, o al reves. Si cada parte resolviera por su cuenta
/// «lo que no dice es RED», la parte que si venia por la otra via quedaria pisada
/// por ese valor por defecto — y un objeto correctamente marcado como
/// `TLP:AMBER` acabaria en `TLP:RED` sin que nadie lo hubiera pedido.
///
/// Eso no filtra, pero hace **inservible** el sistema: todo acaba en el nivel mas
/// restrictivo y deja de compartirse nada. Asi que las partes se combinan primero
/// y el valor por defecto se aplica **una sola vez, al final**.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Parcial {
    /// Lo que se sabe del eje TLP.
    pub tlp: Option<Tlp>,
    /// Lo que se sabe del eje PAP.
    pub pap: Option<Pap>,
}

impl Parcial {
    /// Combina dos lecturas parciales quedandose con lo mas restrictivo conocido.
    #[must_use]
    pub fn combinar(self, otro: Parcial) -> Parcial {
        Parcial {
            tlp: match (self.tlp, otro.tlp) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            pap: match (self.pap, otro.pap) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
        }
    }

    /// Resuelve lo que falta con la regla de lo desconocido: lo mas restrictivo.
    #[must_use]
    pub fn resolver(self) -> Marcado {
        Marcado {
            tlp: self.tlp.unwrap_or(Tlp::Red),
            pap: self.pap.unwrap_or(Pap::Red),
        }
    }

    /// Si se sabe algo de los dos ejes.
    #[must_use]
    pub fn completa(self) -> bool {
        self.tlp.is_some() && self.pap.is_some()
    }
}

/// Lee lo que unas etiquetas dicen de cada eje.
///
/// Lo ilegible se resuelve **aqui mismo** a `Red` y no se deja como `None`: una
/// etiqueta que no se entiende SI dice algo —dice que hay una restriccion que no
/// sabemos leer— y dejarla como «no dice nada» permitiria que otra via la
/// aflojara.
#[must_use]
pub fn parcial_de_etiquetas(etiquetas: &[String]) -> Parcial {
    let mut p = Parcial::default();
    for e in etiquetas {
        let limpia = e.trim();
        let alta = limpia.to_ascii_uppercase();
        if alta.starts_with("TLP:") {
            // Si vienen varias, manda la mas restrictiva: un objeto con dos
            // etiquetas TLP es un objeto mal marcado, y resolverlo hacia lo
            // abierto es resolver un error a favor de la fuga.
            let t = Tlp::de_etiqueta(limpia).unwrap_or(Tlp::Red);
            p.tlp = Some(p.tlp.map_or(t, |v: Tlp| v.max(t)));
        } else if alta.starts_with("PAP:") {
            let v = Pap::de_etiqueta(limpia).unwrap_or(Pap::Red);
            p.pap = Some(p.pap.map_or(v, |x: Pap| x.max(v)));
        }
    }
    p
}

/// Lee el marcado de una lista de etiquetas, con la regla de lo desconocido.
///
/// # La regla, en una frase
///
/// **Lo que no se entiende cuenta como lo mas restrictivo.** Si entre las
/// etiquetas hay una que empieza por `TLP:` o `PAP:` y no se reconoce, el
/// resultado es `Red` en ese eje. Y si no hay ninguna etiqueta de un eje, tambien.
///
/// Suena excesivo hasta que se piensa en el caso contrario: un `TLP:PINK` que
/// aparezca el año que viene en una comunidad, leido como «no reconozco esto,
/// sera publico», se publica. No hay vuelta atras de eso.
#[must_use]
pub fn de_etiquetas(etiquetas: &[String]) -> Marcado {
    parcial_de_etiquetas(etiquetas).resolver()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_orden_del_reticulo_es_el_de_la_semantica() {
        assert!(Tlp::Clear < Tlp::Green);
        assert!(Tlp::Green < Tlp::Amber);
        // `AMBER+STRICT` es MAS restrictivo que `AMBER`: mezclarlos al reves es
        // una fuga con formato valido.
        assert!(Tlp::Amber < Tlp::AmberStrict);
        assert!(Tlp::AmberStrict < Tlp::Red);
        assert!(Pap::Clear < Pap::Green);
        assert!(Pap::Green < Pap::Amber);
        assert!(Pap::Amber < Pap::Red);
    }

    #[test]
    fn tlp_y_pap_son_ejes_independientes() {
        // La combinacion que enseña por que hacen falta los dos: el dominio de
        // C2 se puede compartir con toda la comunidad Y no se puede bloquear,
        // porque bloquearlo le dice al atacante que se le ha visto.
        let m = Marcado::nuevo(Tlp::Green, Pap::Red);
        assert!(m.visible_para(Tlp::Green), "se puede compartir");
        assert!(!m.pap.permite_bloqueo_propio(), "y NO se puede bloquear");
        assert!(!m.pap.permite_busqueda(), "ni siquiera buscarlo");
    }

    #[test]
    fn combinar_toma_lo_peor_de_cada_eje_y_no_el_peor_objeto() {
        // Tomar «el peor de los dos objetos» como bloque daria uno de los dos
        // originales y perderia la mitad de la restriccion.
        let a = Marcado::nuevo(Tlp::Clear, Pap::Red);
        let b = Marcado::nuevo(Tlp::Red, Pap::Clear);
        let c = a.combinar(b);
        assert_eq!(c, Marcado::nuevo(Tlp::Red, Pap::Red));
        assert_ne!(c, a);
        assert_ne!(c, b);
    }

    #[test]
    fn combinar_es_conmutativo_y_asociativo() {
        // Si no lo fuera, el marcado de un informe dependeria del orden en que se
        // juntaron sus fuentes, y dos nodos darian marcados distintos al mismo
        // documento.
        let a = Marcado::nuevo(Tlp::Green, Pap::Clear);
        let b = Marcado::nuevo(Tlp::AmberStrict, Pap::Amber);
        let c = Marcado::nuevo(Tlp::Clear, Pap::Red);
        assert_eq!(a.combinar(b), b.combinar(a));
        assert_eq!(a.combinar(b).combinar(c), a.combinar(b.combinar(c)));
    }

    #[test]
    fn solo_se_puede_reemitir_hacia_mas_restrictivo() {
        let amber = Marcado::nuevo(Tlp::AmberStrict, Pap::Amber);
        assert!(amber.admite_reemision_como(Marcado::nuevo(Tlp::Red, Pap::Red)));
        assert!(amber.admite_reemision_como(amber));
        // Esto es la fuga con documento valido.
        assert!(!amber.admite_reemision_como(Marcado::nuevo(Tlp::Clear, Pap::Amber)));
        assert!(!amber.admite_reemision_como(Marcado::nuevo(Tlp::AmberStrict, Pap::Clear)));
    }

    #[test]
    fn lo_que_llega_sin_marcado_es_lo_mas_restrictivo() {
        // Un objeto sin marcado no es publico: es un objeto cuyo marcado no
        // sabemos, y tratarlo como abierto es filtrar lo de otro en silencio.
        let m = de_etiquetas(&[]);
        assert_eq!(m, Marcado::desconocido());
        assert_eq!(m.tlp, Tlp::Red);
        assert_eq!(m.pap, Pap::Red);
    }

    #[test]
    fn una_etiqueta_tlp_desconocida_no_se_resuelve_hacia_lo_abierto() {
        // El `TLP:PINK` que aparezca el año que viene. Leerlo como «no reconozco
        // esto, sera publico» lo publica, y no hay vuelta atras.
        let m = de_etiquetas(&["TLP:PINK".into(), "PAP:CLEAR".into()]);
        assert_eq!(m.tlp, Tlp::Red);
        assert_eq!(m.pap, Pap::Clear);
    }

    #[test]
    fn sin_pap_explicito_no_se_puede_actuar() {
        // El caso que mas veces se da —casi nadie marca PAP— y el que mas daño
        // hace con un valor por defecto permisivo.
        let m = de_etiquetas(&["TLP:CLEAR".into()]);
        assert_eq!(m.tlp, Tlp::Clear);
        assert_eq!(m.pap, Pap::Red);
        assert!(!m.pap.permite_bloqueo_propio());
    }

    #[test]
    fn dos_etiquetas_del_mismo_eje_resuelven_a_la_mas_restrictiva() {
        // Un objeto con dos etiquetas TLP esta mal marcado, y resolver un error a
        // favor de la fuga es la peor forma de resolverlo.
        let m = de_etiquetas(&["TLP:CLEAR".into(), "TLP:RED".into(), "PAP:CLEAR".into()]);
        assert_eq!(m.tlp, Tlp::Red);
    }

    #[test]
    fn se_lee_el_tlp_1_0_y_no_se_emite() {
        // `WHITE` sigue circulando en fuentes antiguas, asi que hay que leerlo.
        assert_eq!(Tlp::de_etiqueta("TLP:WHITE"), Some(Tlp::Clear));
        // Pero lo que sale por la puerta lleva el nombre de TLP 2.0.
        assert_eq!(Tlp::Clear.nombre(), "TLP:CLEAR");
        for t in [
            Tlp::Clear,
            Tlp::Green,
            Tlp::Amber,
            Tlp::AmberStrict,
            Tlp::Red,
        ] {
            assert!(!t.nombre().contains("WHITE"));
        }
    }

    #[test]
    fn las_etiquetas_se_leen_con_sus_formas_raras() {
        assert_eq!(Tlp::de_etiqueta("  tlp:green "), Some(Tlp::Green));
        assert_eq!(Tlp::de_etiqueta("AMBER"), Some(Tlp::Amber));
        assert_eq!(
            Tlp::de_etiqueta("TLP:AMBER + STRICT"),
            Some(Tlp::AmberStrict)
        );
        assert_eq!(Tlp::de_etiqueta("tlp:rojo"), None);
        assert_eq!(Pap::de_etiqueta("pap:amber"), Some(Pap::Amber));
    }

    /// EL NOMBRE DE LA VARIANTE TIENE QUE DECIR LO MISMO QUE SU VALOR.
    ///
    /// Aqui estuvieron cambiados: `Tlp::Amber` valia `TLP:AMBER+STRICT` y
    /// `Tlp::AmberStrict` valia `TLP:AMBER`. El orden era correcto y todas las
    /// comprobaciones funcionaban, asi que **ninguna prueba lo veia**: la ida y
    /// vuelta de etiqueta es estable con los nombres cambiados, porque solo
    /// compara el sistema consigo mismo.
    ///
    /// Lo que rompe es quien escribe `Tlp::Amber` creyendo que pone AMBER y
    /// resulta poner la restriccion de mas arriba — o, en la direccion peligrosa,
    /// quien escribe `if tlp <= Tlp::Amber { compartir }` y sin saberlo deja
    /// pasar tambien AMBER+STRICT. Un identificador que miente sobre su valor es
    /// un fallo de seguridad aunque la aritmetica este bien, y la unica prueba
    /// que lo detecta es la que ata el nombre al texto canonico.
    #[test]
    fn cada_variante_se_llama_como_lo_que_vale() {
        assert_eq!(Tlp::Clear.nombre(), "TLP:CLEAR");
        assert_eq!(Tlp::Green.nombre(), "TLP:GREEN");
        assert_eq!(Tlp::Amber.nombre(), "TLP:AMBER");
        assert_eq!(Tlp::AmberStrict.nombre(), "TLP:AMBER+STRICT");
        assert_eq!(Tlp::Red.nombre(), "TLP:RED");

        assert_eq!(Pap::Clear.nombre(), "PAP:CLEAR");
        assert_eq!(Pap::Green.nombre(), "PAP:GREEN");
        assert_eq!(Pap::Amber.nombre(), "PAP:AMBER");
        assert_eq!(Pap::Red.nombre(), "PAP:RED");

        // Y el orden sigue siendo el de la semantica: AMBER+STRICT restringe mas
        // que AMBER, que es lo que el nombre ya decia y ahora tambien dice la
        // variante.
        assert!(Tlp::Amber < Tlp::AmberStrict);
    }

    #[test]
    fn toda_ida_y_vuelta_de_etiqueta_es_estable() {
        // Si el nombre emitido no se volviera a leer igual, una federacion de dos
        // saltos degradaria el marcado a «desconocido» y todo acabaria en RED —
        // que no filtra, pero hace inservible el sistema.
        for t in [
            Tlp::Clear,
            Tlp::Green,
            Tlp::Amber,
            Tlp::AmberStrict,
            Tlp::Red,
        ] {
            assert_eq!(Tlp::de_etiqueta(t.nombre()), Some(t), "{}", t.nombre());
        }
        for p in [Pap::Clear, Pap::Green, Pap::Amber, Pap::Red] {
            assert_eq!(Pap::de_etiqueta(p.nombre()), Some(p), "{}", p.nombre());
        }
        let m = Marcado::nuevo(Tlp::AmberStrict, Pap::Green);
        let etiquetas: Vec<String> = m.etiquetas().iter().map(|s| (*s).to_string()).collect();
        assert_eq!(de_etiquetas(&etiquetas), m);
    }

    #[test]
    fn el_pap_gradua_lo_que_se_puede_hacer() {
        assert!(Pap::Clear.permite_accion_visible());
        assert!(!Pap::Green.permite_accion_visible());

        assert!(Pap::Green.permite_bloqueo_propio());
        assert!(!Pap::Amber.permite_bloqueo_propio());

        // PAP:RED permite CONOCER y nada mas — ni la busqueda retroactiva, que
        // parece inocua: donde el adversario ve el SIEM, una consulta es señal.
        assert!(Pap::Amber.permite_busqueda());
        assert!(!Pap::Red.permite_busqueda());
    }

    #[test]
    fn visible_para_respeta_el_tope_del_destinatario() {
        let verde = Marcado::nuevo(Tlp::Green, Pap::Clear);
        assert!(verde.visible_para(Tlp::Green));
        assert!(verde.visible_para(Tlp::Red));
        assert!(!verde.visible_para(Tlp::Clear), "no se publica lo verde");
    }
}
