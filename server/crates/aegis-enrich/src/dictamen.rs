//! Lo que dice una fuente, y por que se sanea antes de creerlo.
//!
//! # La salida de un analizador es entrada no confiable
//!
//! Suena exagerado hasta que se mira de donde viene: el analizador traduce lo que
//! contesto **un tercero por Internet**. Ese tercero puede estar comprometido,
//! roto, o simplemente devolver algo que no esperabamos. Y el orquestador corre
//! dentro del plano de control, que es el sitio con mas privilegios del producto.
//!
//! De modo que lo que sale de un analizador pasa por [`Dictamen::sanear`] antes de
//! entrar en la fusion, igual que un registro que llega por el puerto 514.
//!
//! # Lo que se sanea, y que ataque concreto para cada cosa
//!
//! | Se acota | Sin acotar |
//! |---|---|
//! | Longitud de cada texto | Un motivo de un gigabyte llena la memoria del plano de control |
//! | Numero de etiquetas | Igual, por la via de la cantidad en vez de la del tamaño |
//! | Confianza | Un `200 %` desequilibra la fusion a favor de quien lo mande |
//! | Antiguedad | Una fecha en el futuro hace que un dictamen viejo nunca caduque |
//!
//! # Y lo que NO se sanea porque no se acepta de entrada
//!
//! **La clase de la fuente no viene en la respuesta.** Viene del registro del
//! analizador. Si viniera en la respuesta, un canal comunitario podria declararse
//! autoritativo y saltarse la jerarquia entera de la fusion — que es exactamente
//! la escalada de privilegios que se puede montar sobre un sistema de reputacion.

use std::fmt;

use crate::observable::Observable;

/// Longitud maxima de un texto que venga de una fuente.
pub const MAX_TEXTO: usize = 512;

/// Numero maximo de etiquetas por dictamen.
pub const MAX_ETIQUETAS: usize = 32;

/// Confianza maxima, en centesimas.
pub const MAX_CONFIANZA: u8 = 100;

/// Que dice una fuente sobre un observable.
///
/// El tri-estado del resto del producto, con `Desconocido` como cuarta opcion
/// **que no es un veredicto sino su ausencia**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Juicio {
    /// Es malicioso.
    Malicioso,
    /// Tiene indicios, sin llegar a malicioso.
    Sospechoso,
    /// La fuente lo conoce y dice que es legitimo.
    ///
    /// **Distinto de no conocerlo.** Un fabricante que firma un binario y lo
    /// declara suyo es informacion; no tener el binario en la base de datos no lo
    /// es. Juntarlos es el error que convierte «nadie lo ha visto» en «esta
    /// limpio», que es exactamente lo que hace un fichero recien compilado por un
    /// atacante.
    Limpio,
    /// La fuente no sabe nada de esto.
    Desconocido,
}

impl Juicio {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Juicio::Malicioso => "malicioso",
            Juicio::Sospechoso => "sospechoso",
            Juicio::Limpio => "limpio",
            Juicio::Desconocido => "desconocido",
        }
    }

    /// Si este juicio aporta algo a la decision.
    ///
    /// `Desconocido` no aporta. Cuatro fuentes que no saben nada **no suman** a
    /// «probablemente limpio»: siguen sin saber nada. Es la misma disciplina de
    /// tri-estado que el resto del producto, y aqui es donde mas se nota, porque
    /// la tentacion de contar los desconocidos como votos a favor es enorme.
    #[must_use]
    pub fn aporta(self) -> bool {
        self != Juicio::Desconocido
    }
}

/// De que clase es una fuente.
///
/// **Viene del registro del analizador, nunca de la respuesta.** El orden del
/// enumerado es el orden de autoridad, de mas a menos, y la fusion lo usa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clase {
    /// Observacion propia y directa: una detonacion en el laboratorio, una regla
    /// YARA sobre el fichero que tenemos, una firma verificada.
    ///
    /// Es la unica clase que **vio la cosa**. Todas las demas repiten lo que
    /// alguien dijo.
    Propia,
    /// Un servicio de reputacion con nombre y responsabilidad.
    Reputacion,
    /// Un canal comunitario o una lista abierta.
    ///
    /// Util y a menudo el primero en ver una campana. Tambien el primero en
    /// envenenarse: apuntar una IP de un competidor a una lista abierta cuesta
    /// poco.
    Comunitaria,
    /// Una heuristica calculada sobre el propio observable: entropia del dominio,
    /// antiguedad del registro, forma de la URL.
    ///
    /// No es informacion sobre ESTE caso, es una probabilidad a priori.
    Heuristica,
}

impl Clase {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Clase::Propia => "propia",
            Clase::Reputacion => "reputacion",
            Clase::Comunitaria => "comunitaria",
            Clase::Heuristica => "heuristica",
        }
    }

    /// Si esta clase vio la cosa en vez de repetir lo que otro dijo.
    #[must_use]
    pub fn observacion_directa(self) -> bool {
        self == Clase::Propia
    }
}

/// El veredicto de una fuente sobre un observable, ya saneado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dictamen {
    /// Que analizador lo produjo.
    pub fuente: String,
    /// De que clase es esa fuente. **No la elige la respuesta.**
    pub clase: Clase,
    /// Sobre que.
    pub observable: Observable,
    /// Que dice.
    pub juicio: Juicio,
    /// Como de seguro esta, en centesimas.
    pub confianza: u8,
    /// Cuando lo observo la fuente, en nanosegundos Unix.
    ///
    /// **No es cuando se consulto.** Un servicio de reputacion que contesta hoy
    /// puede estar repitiendo lo que vio hace dos años, y esa diferencia decide si
    /// el dato vale.
    pub observado_ns: u64,
    /// Por que lo dice, en texto legible.
    pub porque: String,
    /// Etiquetas de la fuente: familia de malware, campana, tecnica.
    pub etiquetas: Vec<String>,
}

impl Dictamen {
    /// Un dictamen de «no se nada», que es lo que devuelve una fuente que no
    /// encontro el observable.
    #[must_use]
    pub fn desconocido(
        fuente: impl Into<String>,
        clase: Clase,
        observable: Observable,
        cuando_ns: u64,
    ) -> Dictamen {
        Dictamen {
            fuente: fuente.into(),
            clase,
            observable,
            juicio: Juicio::Desconocido,
            confianza: 0,
            observado_ns: cuando_ns,
            porque: "la fuente no tiene datos sobre este observable".to_string(),
            etiquetas: Vec::new(),
        }
    }

    /// Sanea un dictamen que viene de una fuente.
    ///
    /// Se llama **siempre**, en el orquestador, antes de que el dictamen entre en
    /// la fusion. No se confia en que el analizador ya lo hiciera: el analizador
    /// solo traduce lo que le mandaron.
    ///
    /// `ahora_ns` hace falta para acotar una fecha en el futuro, que es la forma
    /// mas facil de conseguir que un dictamen no caduque nunca.
    pub fn sanear(&mut self, ahora_ns: u64) {
        self.fuente = recortar(&self.fuente, MAX_TEXTO);
        self.porque = recortar(&self.porque, MAX_TEXTO);
        self.confianza = self.confianza.min(MAX_CONFIANZA);

        self.etiquetas.truncate(MAX_ETIQUETAS);
        for e in &mut self.etiquetas {
            *e = recortar(e, MAX_TEXTO);
        }
        // Se ordena y se quita el repetido: una fuente que manda la misma etiqueta
        // treinta veces la haria parecer treinta indicios distintos en el informe.
        self.etiquetas.sort_unstable();
        self.etiquetas.dedup();

        // Una fecha en el futuro se trae al presente. No se descarta el dictamen
        // —el reloj del otro puede ir adelantado por una razon inocente— pero
        // tampoco se le deja no caducar nunca.
        if self.observado_ns > ahora_ns {
            self.observado_ns = ahora_ns;
        }

        // Un juicio con confianza cero no es un juicio: es un desconocido con
        // adorno. Se normaliza para que la fusion no tenga que tratar el caso.
        if self.confianza == 0 && self.juicio != Juicio::Desconocido {
            self.juicio = Juicio::Desconocido;
        }
        // Y al reves: un desconocido con confianza es una contradiccion, y la
        // confianza es lo que la fusion pondera. Se pone a cero.
        if self.juicio == Juicio::Desconocido {
            self.confianza = 0;
        }
    }

    /// Cuanto hace que la fuente observo esto, en nanosegundos.
    #[must_use]
    pub fn antiguedad_ns(&self, ahora_ns: u64) -> u64 {
        ahora_ns.saturating_sub(self.observado_ns)
    }
}

impl fmt::Display for Dictamen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {} al {} % — {}",
            self.fuente,
            self.clase.nombre(),
            self.juicio.nombre(),
            self.confianza,
            self.porque
        )
    }
}

/// Recorta por BYTES respetando los limites de caracter.
///
/// Por bytes y no por caracteres porque el tope existe para acotar la MEMORIA, y
/// un caracter puede ocupar cuatro. Con un tope por caracteres, una fuente que
/// manda emojis ocupa el cuadruple de lo previsto.
fn recortar(s: &str, tope: usize) -> String {
    if s.len() <= tope {
        return s.to_string();
    }
    let mut n = tope;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn base() -> Dictamen {
        Dictamen {
            fuente: "reputacion.example".into(),
            clase: Clase::Reputacion,
            observable: Observable::Hash("abc".into()),
            juicio: Juicio::Malicioso,
            confianza: 80,
            observado_ns: AHORA - 3600 * SEG,
            porque: "detectado por 42 motores".into(),
            etiquetas: vec!["ransomware".into()],
        }
    }

    #[test]
    fn una_confianza_imposible_se_acota() {
        // Un 200 % desequilibraria la fusion a favor de quien lo mande.
        let mut d = base();
        d.confianza = 255;
        d.sanear(AHORA);
        assert_eq!(d.confianza, MAX_CONFIANZA);
    }

    #[test]
    fn un_texto_enorme_se_recorta_por_bytes() {
        let mut d = base();
        d.porque = "€".repeat(MAX_TEXTO);
        d.sanear(AHORA);
        assert!(d.porque.len() <= MAX_TEXTO);
        assert!(d.porque.is_char_boundary(d.porque.len()));
    }

    #[test]
    fn una_avalancha_de_etiquetas_se_acota_y_se_desduplica() {
        // Sin tope, el ataque es por cantidad en vez de por tamaño. Y sin
        // desduplicar, la misma etiqueta treinta veces parece treinta indicios.
        let mut d = base();
        d.etiquetas = (0..1000).map(|i| format!("e{i}")).collect();
        d.sanear(AHORA);
        assert_eq!(d.etiquetas.len(), MAX_ETIQUETAS);

        let mut d = base();
        d.etiquetas = vec!["ransomware".into(); 30];
        d.sanear(AHORA);
        assert_eq!(d.etiquetas, vec!["ransomware".to_string()]);
    }

    #[test]
    fn una_fecha_en_el_futuro_se_trae_al_presente() {
        // Es la forma mas facil de conseguir que un dictamen no caduque nunca. No
        // se descarta —el reloj del otro puede ir adelantado— pero no se le deja
        // ser eterno.
        let mut d = base();
        d.observado_ns = AHORA + 365 * 24 * 3600 * SEG;
        d.sanear(AHORA);
        assert_eq!(d.observado_ns, AHORA);
        assert_eq!(d.antiguedad_ns(AHORA), 0);
    }

    #[test]
    fn un_juicio_sin_confianza_es_un_desconocido() {
        let mut d = base();
        d.confianza = 0;
        d.sanear(AHORA);
        assert_eq!(d.juicio, Juicio::Desconocido);
    }

    #[test]
    fn un_desconocido_no_arrastra_confianza() {
        // Un desconocido con confianza es una contradiccion, y la confianza es lo
        // que la fusion pondera: dejarla puesta le daria peso a una no-respuesta.
        let mut d = base();
        d.juicio = Juicio::Desconocido;
        d.confianza = 90;
        d.sanear(AHORA);
        assert_eq!(d.confianza, 0);
    }

    #[test]
    fn desconocido_no_aporta_y_los_demas_si() {
        assert!(!Juicio::Desconocido.aporta());
        for j in [Juicio::Malicioso, Juicio::Sospechoso, Juicio::Limpio] {
            assert!(j.aporta());
        }
    }

    #[test]
    fn limpio_y_desconocido_son_cosas_distintas() {
        // Un fabricante que firma un binario y lo declara suyo es informacion; no
        // tener el binario en la base de datos no lo es. Juntarlos convierte
        // «nadie lo ha visto» en «esta limpio», que es justo lo que parece un
        // fichero recien compilado por un atacante.
        assert_ne!(Juicio::Limpio, Juicio::Desconocido);
        assert!(Juicio::Limpio.aporta());
        assert!(!Juicio::Desconocido.aporta());
    }

    #[test]
    fn el_orden_de_las_clases_es_el_de_autoridad() {
        assert!(Clase::Propia < Clase::Reputacion);
        assert!(Clase::Reputacion < Clase::Comunitaria);
        assert!(Clase::Comunitaria < Clase::Heuristica);
        assert!(Clase::Propia.observacion_directa());
        assert!(!Clase::Reputacion.observacion_directa());
    }

    #[test]
    fn un_desconocido_se_construye_sin_confianza_y_con_motivo() {
        let d = Dictamen::desconocido(
            "x",
            Clase::Reputacion,
            Observable::Hash("abc".into()),
            AHORA,
        );
        assert_eq!(d.juicio, Juicio::Desconocido);
        assert_eq!(d.confianza, 0);
        assert!(!d.porque.is_empty(), "un desconocido tambien dice por que");
    }

    #[test]
    fn sanear_es_idempotente() {
        // Si no lo fuera, sanear dos veces —algo que pasa en cuanto hay una cache
        // por medio— cambiaria el dictamen y la fusion dejaria de ser determinista.
        let mut a = base();
        a.confianza = 200;
        a.etiquetas = vec!["b".into(), "a".into(), "a".into()];
        a.sanear(AHORA);
        let mut b = a.clone();
        b.sanear(AHORA);
        assert_eq!(a, b);
    }
}
