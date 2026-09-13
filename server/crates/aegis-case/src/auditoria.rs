//! El rastro de auditoria: quien vio que, quien cambio que, y cuando.
//!
//! # Por que esto no es un registro mas
//!
//! Un caso de seguridad es **potencialmente prueba judicial**. Y aunque no llegue
//! a un juzgado, es lo que un cliente enseña a su regulador y lo que un analista
//! usa seis meses despues para reconstruir por que se decidio lo que se decidio.
//!
//! Un registro que se puede editar despues no sirve para ninguna de las tres
//! cosas. Y no hace falta un atacante para romperlo: basta con alguien con
//! permiso de escritura en la base de datos y una razon para que el informe diga
//! otra cosa.
//!
//! # La cadena, y lo que de verdad garantiza
//!
//! Cada entrada lleva el resumen de la anterior. Alterar la entrada `n`
//! invalida el resumen de la `n+1`, que invalida el de la `n+2`, y asi hasta el
//! final: **no se puede cambiar una linea sin reescribir todo lo que vino
//! despues**.
//!
//! Eso convierte la manipulacion silenciosa en manipulacion detectable, que es un
//! salto grande. Pero hay que ser exacto sobre lo que NO garantiza:
//!
//! > Quien pueda reescribir la cadena **entera** —todas las entradas y todos los
//! > resumenes— produce una cadena internamente consistente. La cadena sola no lo
//! > detecta.
//!
//! Por eso el resumen de la cabeza se **ancla fuera**: se publica periodicamente
//! por el canal de atestacion, que ya existe y esta firmado. A partir de ese
//! momento, una reescritura tiene que cuadrar con un valor que ya salio del
//! sistema, y eso ya no se puede hacer desde la base de datos. [`Ancla`].
//!
//! Sin el anclaje, decir «rastro inmutable» seria una promesa a medias. Con el,
//! es una propiedad con una frontera escrita: **todo lo anterior al ultimo
//! anclaje es inmutable; lo posterior es detectable**.

use std::fmt;

use sha2::{Digest, Sha256};

/// Bytes maximos del detalle de una entrada.
pub const MAX_DETALLE: usize = 4096;

/// Que paso.
///
/// La lista es cerrada a proposito: un rastro con una accion de texto libre no se
/// puede consultar —«enseñame quien cerro casos este mes» deja de tener
/// respuesta— y ademas invita a meter ahi lo que no cabia en otro sitio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Accion {
    /// Se creo el caso.
    Creado,
    /// Cambio de estado.
    CambioDeEstado,
    /// Se asigno a alguien.
    Asignado,
    /// Se fusiono una alerta en el caso.
    AlertaFusionada,
    /// Se anadio un observable.
    ObservableAnadido,
    /// Se creo una tarea.
    TareaCreada,
    /// Se cerro una tarea.
    TareaCerrada,
    /// Alguien comento.
    Comentario,
    /// Alguien LEYO el caso.
    ///
    /// Se registra porque «quien vio que» es parte de la pregunta: en una
    /// investigacion interna, quien miro el caso antes de que pasara algo es un
    /// dato, y en un regimen de proteccion de datos, el acceso a informacion
    /// personal se audita por obligacion.
    Consultado,
    /// Se ejecuto una remediacion desde el caso.
    RemediacionOrdenada,
    /// Se cerro el caso con veredicto.
    Cerrado,
    /// Se reabrio un caso cerrado.
    Reabierto,
}

impl Accion {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Accion::Creado => "creado",
            Accion::CambioDeEstado => "cambio-de-estado",
            Accion::Asignado => "asignado",
            Accion::AlertaFusionada => "alerta-fusionada",
            Accion::ObservableAnadido => "observable-anadido",
            Accion::TareaCreada => "tarea-creada",
            Accion::TareaCerrada => "tarea-cerrada",
            Accion::Comentario => "comentario",
            Accion::Consultado => "consultado",
            Accion::RemediacionOrdenada => "remediacion-ordenada",
            Accion::Cerrado => "cerrado",
            Accion::Reabierto => "reabierto",
        }
    }
}

/// Una entrada del rastro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Posicion en la cadena, empezando en 1.
    pub secuencia: u64,
    /// Caso al que pertenece.
    pub caso: String,
    /// Quien lo hizo. Nunca vacio: ver [`Rastro::anotar`].
    pub actor: String,
    /// Que hizo.
    pub accion: Accion,
    /// El detalle, ya recortado.
    pub detalle: String,
    /// Cuando, en nanosegundos Unix.
    pub cuando_ns: u64,
    /// Resumen de la entrada anterior.
    pub anterior: String,
    /// Resumen de esta entrada.
    pub resumen: String,
}

impl Entrada {
    /// Construye una entrada ya normalizada y con su resumen calculado.
    ///
    /// # Por que esto existe, y no se arma la estructura a mano
    ///
    /// El resumen se calcula sobre el detalle **ya recortado**. Si quien persiste
    /// la entrada recortara de otra forma —por caracteres en vez de por bytes, por
    /// ejemplo—, guardaria un detalle distinto del que se uso para el resumen. La
    /// cadena verificaria en memoria y **fallaria al leerla de disco**, acusando
    /// de manipulacion una entrada honesta.
    ///
    /// Y esa es la peor averia posible en este modulo: un rastro que grita cuando
    /// no pasa nada se deja de mirar, exactamente igual que la regla ruidosa que
    /// [`crate::metricas`] existe para apagar.
    ///
    /// Asi que el recorte y el resumen ocurren en un solo sitio, y los dos
    /// caminos —el de memoria y el de la base de datos— pasan por aqui.
    #[must_use]
    pub fn nueva(
        secuencia: u64,
        caso: impl Into<String>,
        actor: impl Into<String>,
        accion: Accion,
        detalle: &str,
        cuando_ns: u64,
        anterior: impl Into<String>,
    ) -> Entrada {
        let mut e = Entrada {
            secuencia,
            caso: caso.into(),
            actor: actor.into(),
            accion,
            detalle: recortar(detalle, MAX_DETALLE),
            cuando_ns,
            anterior: anterior.into(),
            resumen: String::new(),
        };
        e.resumen = e.calcular();
        e
    }

    /// Recalcula el resumen de esta entrada.
    ///
    /// Entra **todo** lo que la identifica, incluido el resumen de la anterior.
    /// Dejar fuera cualquier campo permitiria cambiarlo sin romper la cadena, y
    /// el campo que alguien querria cambiar es justo el actor o el detalle.
    #[must_use]
    pub fn calcular(&self) -> String {
        const SEP: &[u8] = &[0x1f];
        let mut h = Sha256::new();
        h.update(self.secuencia.to_be_bytes());
        h.update(SEP);
        h.update(self.caso.as_bytes());
        h.update(SEP);
        h.update(self.actor.as_bytes());
        h.update(SEP);
        h.update(self.accion.nombre().as_bytes());
        h.update(SEP);
        h.update(self.detalle.as_bytes());
        h.update(SEP);
        h.update(self.cuando_ns.to_be_bytes());
        h.update(SEP);
        h.update(self.anterior.as_bytes());
        hex(&h.finalize())
    }
}

impl fmt::Display for Entrada {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} {} {}: {}",
            self.secuencia,
            self.cuando_ns,
            self.actor,
            self.accion.nombre(),
            self.detalle
        )
    }
}

/// Por que una cadena no cuadra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotura {
    /// Una entrada tiene un resumen que no corresponde a su contenido.
    ContenidoAlterado {
        /// Cual.
        secuencia: u64,
    },
    /// Una entrada no engancha con la anterior.
    EslabonRoto {
        /// Cual.
        secuencia: u64,
    },
    /// Falta una entrada de la secuencia.
    ///
    /// Distinto de alterar: borrar una entrada es la forma mas limpia de
    /// manipular un rastro, y sin numero de secuencia no se distinguiria de una
    /// cadena corta.
    Hueco {
        /// Donde.
        esperada: u64,
    },
    /// La cadena no cuadra con un anclaje publicado.
    ///
    /// Es la unica rotura que detecta una reescritura COMPLETA.
    AnclajeRoto {
        /// Hasta que entrada cubria el anclaje.
        hasta: u64,
    },
}

/// Un anclaje publicado del rastro.
///
/// Es el resumen de la cabeza en un momento dado, sacado del sistema por el canal
/// de atestacion. A partir de ahi, reescribir la historia anterior obliga a
/// cuadrar con un valor que ya no se controla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancla {
    /// Hasta que numero de secuencia cubre.
    pub hasta: u64,
    /// Resumen de la cabeza en ese momento.
    pub resumen: String,
    /// Cuando se publico.
    pub cuando_ns: u64,
}

/// El rastro de un caso: una cadena de entradas enganchadas.
#[derive(Debug, Clone, Default)]
pub struct Rastro {
    caso: String,
    entradas: Vec<Entrada>,
    anclas: Vec<Ancla>,
}

/// Resumen de la entrada cero: el ancla de la cadena vacia.
///
/// Es publico porque quien persiste el rastro necesita el mismo valor: si la
/// capa de base de datos escribiera otro «anterior» para la primera entrada, la
/// cadena cargada de disco no verificaria contra la calculada en memoria y el
/// rastro pareceria manipulado sin estarlo.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl Rastro {
    /// Crea el rastro de un caso.
    #[must_use]
    pub fn nuevo(caso: impl Into<String>) -> Rastro {
        Rastro {
            caso: caso.into(),
            entradas: Vec::new(),
            anclas: Vec::new(),
        }
    }

    /// Entradas del rastro.
    #[must_use]
    pub fn entradas(&self) -> &[Entrada] {
        &self.entradas
    }

    /// Resumen de la cabeza.
    #[must_use]
    pub fn cabeza(&self) -> String {
        self.entradas
            .last()
            .map_or_else(|| GENESIS.to_string(), |e| e.resumen.clone())
    }

    /// Anota una accion.
    ///
    /// `actor` **no puede estar vacio**: una entrada sin actor convierte el
    /// rastro en un registro de sucesos, que es otra cosa. Si el cambio lo hizo
    /// el sistema y no una persona, el actor es el sistema y se dice.
    pub fn anotar(
        &mut self,
        actor: &str,
        accion: Accion,
        detalle: &str,
        cuando_ns: u64,
    ) -> Result<&Entrada, &'static str> {
        if actor.trim().is_empty() {
            return Err("una entrada de auditoria sin actor no es una entrada de auditoria");
        }
        let anterior = self.cabeza();
        let e = Entrada::nueva(
            self.entradas.len() as u64 + 1,
            self.caso.clone(),
            actor,
            accion,
            detalle,
            cuando_ns,
            anterior,
        );
        self.entradas.push(e);
        Ok(self.entradas.last().expect("acabamos de meter una"))
    }

    /// Carga una entrada tal y como estaba guardada, SIN recalcular nada.
    ///
    /// Es lo que permite comprobar un rastro que vive en disco: se cargan las
    /// entradas como estan y se verifica. Recalcular al cargar haria que la
    /// comprobacion siempre saliera bien —se estaria comparando el resumen
    /// consigo mismo— y el rastro seria decorativo.
    pub fn cargar(&mut self, entrada: Entrada) {
        self.entradas.push(entrada);
    }

    /// Carga un anclaje publicado.
    pub fn cargar_ancla(&mut self, ancla: Ancla) {
        self.anclas.push(ancla);
    }

    /// Publica un anclaje de la cabeza actual.
    pub fn anclar(&mut self, cuando_ns: u64) -> Ancla {
        let a = Ancla {
            hasta: self.entradas.len() as u64,
            resumen: self.cabeza(),
            cuando_ns,
        };
        self.anclas.push(a.clone());
        a
    }

    /// Anclajes publicados.
    #[must_use]
    pub fn anclas(&self) -> &[Ancla] {
        &self.anclas
    }

    /// Comprueba la cadena entera.
    ///
    /// Devuelve **todas** las roturas y no solo la primera: quien manipula un
    /// rastro suele tocar varias cosas, y parar en la primera esconde el resto.
    #[must_use]
    pub fn verificar(&self) -> Vec<Rotura> {
        let mut roturas = Vec::new();
        let mut anterior = GENESIS.to_string();
        for (i, e) in self.entradas.iter().enumerate() {
            let esperada = i as u64 + 1;
            if e.secuencia != esperada {
                roturas.push(Rotura::Hueco { esperada });
            }
            if e.anterior != anterior {
                roturas.push(Rotura::EslabonRoto {
                    secuencia: e.secuencia,
                });
            }
            if e.calcular() != e.resumen {
                roturas.push(Rotura::ContenidoAlterado {
                    secuencia: e.secuencia,
                });
            }
            anterior = e.resumen.clone();
        }
        // Y contra los anclajes: la unica comprobacion que detecta una
        // reescritura COMPLETA, porque el valor ya salio del sistema.
        for a in &self.anclas {
            let en_la_cadena = if a.hasta == 0 {
                GENESIS.to_string()
            } else {
                self.entradas
                    .get(usize::try_from(a.hasta - 1).unwrap_or(usize::MAX))
                    .map_or_else(String::new, |e| e.resumen.clone())
            };
            if en_la_cadena != a.resumen {
                roturas.push(Rotura::AnclajeRoto { hasta: a.hasta });
            }
        }
        roturas
    }

    /// Si la cadena esta intacta.
    #[must_use]
    pub fn intacto(&self) -> bool {
        self.verificar().is_empty()
    }

    /// Quien toco el caso, en orden de primera aparicion.
    #[must_use]
    pub fn actores(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for e in &self.entradas {
            if !v.contains(&e.actor) {
                v.push(e.actor.clone());
            }
        }
        v
    }

    /// Entradas de una accion concreta.
    #[must_use]
    pub fn de(&self, accion: Accion) -> Vec<&Entrada> {
        self.entradas
            .iter()
            .filter(|e| e.accion == accion)
            .collect()
    }
}

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

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    #[test]
    fn el_detalle_se_recorta_por_bytes_y_nunca_parte_un_caracter() {
        // Un detalle de caracteres de tres bytes que pasa del tope. Recortar por
        // CARACTERES daria una cadena distinta a recortar por BYTES, y como el
        // resumen se calcula sobre el detalle ya recortado, los dos caminos
        // —memoria y base de datos— producirian resumenes distintos para la misma
        // entrada. La cadena verificaria en memoria y fallaria al leerla de disco.
        let largo = "€".repeat(MAX_DETALLE);
        let e = Entrada::nueva(1, "c", "ana", Accion::Comentario, &largo, AHORA, GENESIS);

        assert!(e.detalle.len() <= MAX_DETALLE, "el tope es de BYTES");
        assert!(
            e.detalle.is_char_boundary(e.detalle.len()),
            "no se parte un caracter por la mitad"
        );
        // 4096 no es multiplo de 3, asi que el recorte por bytes cae dentro de un
        // caracter y hay que retroceder: 1365 caracteres, 4095 bytes.
        assert_eq!(e.detalle.chars().count(), MAX_DETALLE / 3);
        assert_eq!(e.detalle.len(), (MAX_DETALLE / 3) * 3);
    }

    #[test]
    fn construir_la_entrada_a_mano_da_el_mismo_resumen_que_anotar() {
        // Es la propiedad que hace que el rastro de la base de datos y el de
        // memoria sean EL MISMO rastro. `aegis-server` reconstruye las entradas
        // con `Entrada::nueva` desde las filas; si esto dejara de cuadrar, la
        // verificacion acusaria de manipulacion a un rastro intacto — y un rastro
        // que grita cuando no pasa nada se deja de mirar.
        let detalle = "€".repeat(MAX_DETALLE);
        let mut r = Rastro::nuevo("c");
        r.anotar("ana", Accion::Comentario, &detalle, AHORA)
            .expect("actor no vacio");

        let a_mano = Entrada::nueva(1, "c", "ana", Accion::Comentario, &detalle, AHORA, GENESIS);

        assert_eq!(r.entradas()[0], a_mano);
        assert_eq!(r.cabeza(), a_mano.resumen);
    }

    fn rastro_de_ejemplo() -> Rastro {
        let mut r = Rastro::nuevo("CASO-2024-0001");
        r.anotar(
            "sistema",
            Accion::Creado,
            "alerta 9911 abrio el caso",
            AHORA,
        )
        .unwrap();
        r.anotar("ana", Accion::Asignado, "asignado a ana", AHORA + SEG)
            .unwrap();
        r.anotar(
            "ana",
            Accion::Comentario,
            "el proceso padre es legitimo, el hijo no",
            AHORA + 60 * SEG,
        )
        .unwrap();
        r.anotar(
            "ana",
            Accion::RemediacionOrdenada,
            "aislamiento de maquina-17",
            AHORA + 120 * SEG,
        )
        .unwrap();
        r
    }

    #[test]
    fn una_cadena_recien_escrita_esta_intacta() {
        let r = rastro_de_ejemplo();
        assert!(r.intacto(), "{:?}", r.verificar());
        assert_eq!(r.entradas().len(), 4);
        assert_eq!(r.entradas()[0].anterior, GENESIS);
        assert_eq!(r.entradas()[1].anterior, r.entradas()[0].resumen);
    }

    #[test]
    fn cambiar_una_linea_rompe_todo_lo_que_vino_despues() {
        // LA PROPIEDAD QUE JUSTIFICA LA CADENA. Y no hace falta un atacante:
        // basta con alguien con permiso de escritura en la base de datos y una
        // razon para que el informe diga otra cosa.
        let mut r = rastro_de_ejemplo();
        r.entradas[1].actor = "quien-no-fue".into();
        let roturas = r.verificar();
        assert!(
            roturas.contains(&Rotura::ContenidoAlterado { secuencia: 2 }),
            "{roturas:?}"
        );
        assert!(!r.intacto());
    }

    #[test]
    fn recalcular_el_resumen_de_la_entrada_tocada_no_basta() {
        // El intento obvio de quien manipula: cambiar la linea Y su resumen.
        // Entonces se rompe el enganche de la SIGUIENTE.
        let mut r = rastro_de_ejemplo();
        r.entradas[1].detalle = "asignado a otro".into();
        r.entradas[1].resumen = r.entradas[1].calcular();
        let roturas = r.verificar();
        assert!(
            roturas.contains(&Rotura::EslabonRoto { secuencia: 3 }),
            "{roturas:?}"
        );
    }

    #[test]
    fn borrar_una_entrada_se_detecta_por_el_numero_de_secuencia() {
        // Borrar es la forma mas limpia de manipular un rastro, y sin numero de
        // secuencia no se distinguiria de una cadena corta.
        let mut r = rastro_de_ejemplo();
        r.entradas.remove(1);
        let roturas = r.verificar();
        assert!(
            roturas.iter().any(|x| matches!(x, Rotura::Hueco { .. })),
            "{roturas:?}"
        );
    }

    #[test]
    fn se_devuelven_todas_las_roturas_y_no_solo_la_primera() {
        // Quien manipula un rastro suele tocar varias cosas, y parar en la
        // primera esconde el resto.
        let mut r = rastro_de_ejemplo();
        r.entradas[0].detalle = "otra cosa".into();
        r.entradas[2].actor = "otro".into();
        let roturas = r.verificar();
        assert!(roturas.len() >= 2, "{roturas:?}");
    }

    #[test]
    fn una_reescritura_completa_produce_una_cadena_consistente() {
        // LO QUE LA CADENA SOLA NO DETECTA, y por eso hace falta el anclaje.
        // Decirlo es la diferencia entre una propiedad y una promesa a medias.
        let mut falso = Rastro::nuevo("CASO-2024-0001");
        falso
            .anotar("sistema", Accion::Creado, "nada que ver aqui", AHORA)
            .unwrap();
        falso
            .anotar("ana", Accion::Cerrado, "falso positivo", AHORA + SEG)
            .unwrap();
        assert!(
            falso.intacto(),
            "una cadena reescrita entera es internamente consistente"
        );
    }

    #[test]
    fn con_anclaje_la_reescritura_completa_si_se_detecta() {
        // A partir del anclaje, reescribir obliga a cuadrar con un valor que ya
        // salio del sistema, y eso ya no se puede hacer desde la base de datos.
        let mut r = rastro_de_ejemplo();
        let ancla = r.anclar(AHORA + 200 * SEG);
        assert!(r.intacto());

        // Alguien reescribe la historia entera y conserva el anclaje publicado.
        let mut falso = Rastro::nuevo("CASO-2024-0001");
        falso
            .anotar("sistema", Accion::Creado, "nada que ver aqui", AHORA)
            .unwrap();
        falso.anclas.push(ancla);
        let roturas = falso.verificar();
        assert!(
            roturas
                .iter()
                .any(|x| matches!(x, Rotura::AnclajeRoto { .. })),
            "{roturas:?}"
        );
    }

    #[test]
    fn el_anclaje_marca_la_frontera_de_lo_inmutable() {
        // «Todo lo anterior al ultimo anclaje es inmutable; lo posterior es
        // detectable». La frontera es una propiedad con nombre, no una promesa.
        let mut r = rastro_de_ejemplo();
        let a = r.anclar(AHORA + 200 * SEG);
        assert_eq!(a.hasta, 4);
        r.anotar(
            "ana",
            Accion::Cerrado,
            "contenido y cerrado",
            AHORA + 300 * SEG,
        )
        .unwrap();
        assert!(r.intacto(), "seguir escribiendo no rompe el anclaje");
        assert_eq!(r.anclas()[0].hasta, 4);
    }

    #[test]
    fn una_entrada_sin_actor_no_se_admite() {
        // Sin actor, el rastro es un registro de sucesos, que es otra cosa. Si el
        // cambio lo hizo el sistema, el actor es el sistema y se dice.
        let mut r = Rastro::nuevo("C-1");
        assert!(r.anotar("", Accion::Creado, "x", AHORA).is_err());
        assert!(r.anotar("   ", Accion::Creado, "x", AHORA).is_err());
        assert!(r.anotar("sistema", Accion::Creado, "x", AHORA).is_ok());
    }

    #[test]
    fn quien_leyo_el_caso_tambien_queda() {
        // En una investigacion interna, quien miro el caso antes de que pasara
        // algo es un dato; y el acceso a informacion personal se audita por
        // obligacion en cualquier regimen de proteccion de datos.
        let mut r = rastro_de_ejemplo();
        r.anotar(
            "auditor",
            Accion::Consultado,
            "leyo el caso",
            AHORA + 500 * SEG,
        )
        .unwrap();
        assert_eq!(r.de(Accion::Consultado).len(), 1);
        assert!(r.actores().contains(&"auditor".to_string()));
    }

    #[test]
    fn el_detalle_esta_acotado() {
        let mut r = Rastro::nuevo("C-1");
        let largo = "x".repeat(MAX_DETALLE * 3);
        r.anotar("ana", Accion::Comentario, &largo, AHORA).unwrap();
        assert!(r.entradas()[0].detalle.len() <= MAX_DETALLE);
        assert!(r.intacto());
    }

    #[test]
    fn un_rastro_vacio_esta_intacto_y_su_cabeza_es_el_genesis() {
        let mut r = Rastro::nuevo("C-1");
        assert!(r.intacto());
        assert_eq!(r.cabeza(), GENESIS);
        assert_eq!(r.anclar(AHORA).hasta, 0);
    }

    #[test]
    fn dos_rastros_con_las_mismas_acciones_tienen_la_misma_cabeza() {
        // Determinismo: es lo que permite comparar dos replicas de la base de
        // datos y decir si dicen lo mismo, sin leer entrada a entrada.
        let a = rastro_de_ejemplo();
        let b = rastro_de_ejemplo();
        assert_eq!(a.cabeza(), b.cabeza());
    }

    #[test]
    fn cambiar_el_caso_de_una_entrada_tambien_rompe() {
        // Mover una entrada de un caso a otro es manipulacion, aunque el
        // contenido no cambie.
        let mut r = rastro_de_ejemplo();
        r.entradas[2].caso = "CASO-2024-0002".into();
        assert!(!r.intacto());
    }
}
