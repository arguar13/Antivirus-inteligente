//! Deduplicacion en el plano de control.
//!
//! # Por que hace falta: la entrega es al-menos-una-vez A PROPOSITO
//!
//! El endpoint reenvia lo que no se le acuso. Es lo correcto —perder evidencia
//! no se arregla despues y duplicarla si— pero significa que **aqui llegan
//! duplicados de verdad**, no como excepcion sino como parte del contrato.
//!
//! # Por que NO se usa un filtro de Bloom, que es lo que sugiere el manual
//!
//! Un filtro de Bloom es la respuesta habitual a «desduplicar mil millones de
//! identificadores con poca memoria», y aqui seria un **error de seguridad**.
//!
//! Un falso positivo de un Bloom significa «este identificador ya lo he visto»
//! cuando no es cierto. Y lo que se hace con un duplicado es **tirarlo**. O sea:
//! un falso positivo **borra un evento unico**, en silencio, sin dejar rastro y
//! sin posibilidad de saber cual. En una canalizacion de seguridad eso es
//! exactamente el fallo que no se puede tener, y la probabilidad no es cero por
//! definicion.
//!
//! La estructura de aqui es **exacta**: un conjunto acotado con ventana
//! temporal. Su fallo posible es el contrario —un duplicado que llega despues de
//! que su identificador saliera de la ventana **pasa**— y ese fallo es
//! inofensivo: el analista ve el mismo evento dos veces, con el mismo
//! identificador, y se cuenta.
//!
//! **Falso positivo: se borra evidencia. Falso negativo: se ve dos veces lo
//! mismo.** No son intercambiables, y por eso la estructura no es
//! intercambiable.
//!
//! # El aislamiento entre inquilinos no es opcional
//!
//! El estado esta **partido por inquilino**. Con un conjunto global, un cliente
//! ruidoso desaloja los identificadores de otro y le provoca duplicados en su
//! panel; y peor, dos clientes cuyos eventos colisionaran compartirian decision.
//! Cada inquilino tiene su ventana y su cuota.

use std::collections::{BTreeMap, HashSet, VecDeque};

use aegis_ingest::esquema::Evento;

/// Duracion de un cubo de la ventana, en nanosegundos.
///
/// Diez minutos. Es el grano con el que se olvida: cuando la ventana avanza, se
/// tira un cubo entero de golpe en vez de ir borrando identificador a
/// identificador, que costaria mantener un orden y no aporta nada.
pub const CUBO_NS: u64 = 10 * 60 * 1_000_000_000;

/// Cubos que se conservan por inquilino.
///
/// Seis cubos de diez minutos es una hora de ventana. La eleccion sale de lo que
/// de verdad produce duplicados: un reinicio del endpoint reenvia lo que tenia
/// pendiente, y lo pendiente son minutos, no dias. Una ventana de un dia
/// costaria cien veces mas memoria para atrapar los mismos duplicados.
pub const CUBOS: usize = 6;

/// Identificadores maximos por inquilino.
///
/// La cota dura: pase lo que pase, un inquilino no ocupa mas que esto. Cuando se
/// alcanza, se tira el cubo mas antiguo aunque su tiempo no haya vencido, y **se
/// cuenta**: ese contador dejando de ser cero significa que la ventana efectiva
/// de ese cliente es mas corta que la nominal, y que puede estar viendo
/// duplicados.
pub const MAX_POR_INQUILINO: usize = 200_000;

/// Identificadores maximos en un solo cubo.
///
/// # Sin esto la cota dura no se aplica nunca
///
/// El desalojo tira **cubos enteros**, asi que necesita que haya mas de uno. Un
/// pico que llegue dentro del mismo intervalo de diez minutos —que es
/// exactamente lo que hace un cliente ruidoso— cae todo en el mismo cubo, no hay
/// nada que desalojar, y la ventana crece sin tope pese a la cota. Con este
/// limite, un cubo lleno cierra y se abre otro aunque el reloj no haya avanzado.
pub const MAX_POR_CUBO: usize = MAX_POR_INQUILINO / CUBOS;

/// Inquilinos maximos con estado a la vez.
pub const MAX_INQUILINOS: usize = 4096;

/// Lo que se decidio sobre un evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// No se habia visto: pasa.
    Nuevo,
    /// Ya se habia visto en la ventana: es un duplicado y se descarta.
    Duplicado,
    /// El identificador no cuadra con el contenido.
    ///
    /// No se desduplica y **no se descarta**: se marca. Un evento manipulado por
    /// el camino sigue siendo evidencia de que alguien lo manipulo, y tirarlo
    /// seria borrar justo eso.
    SelloRoto,
}

/// Contadores de la deduplicacion.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos vistos.
    pub vistos: u64,
    /// Eventos que pasaron.
    pub nuevos: u64,
    /// Duplicados descartados.
    pub duplicados: u64,
    /// Eventos con el sello roto.
    pub sellos_rotos: u64,
    /// Cubos tirados antes de tiempo por alcanzar la cota de memoria.
    ///
    /// Que deje de ser cero significa que la ventana efectiva de algun cliente
    /// es mas corta que la nominal. No es un fallo: es un dato que hay que ver.
    pub desalojos_prematuros: u64,
    /// Inquilinos que no cupieron.
    pub inquilinos_rechazados: u64,
}

/// Ventana de identificadores de un inquilino.
#[derive(Debug, Default)]
struct Ventana {
    /// Cubos de mas antiguo a mas reciente.
    cubos: VecDeque<Cubo>,
    total: usize,
}

#[derive(Debug)]
struct Cubo {
    /// Instante en el que empieza el cubo, redondeado a [`CUBO_NS`].
    inicio_ns: u64,
    ids: HashSet<String>,
}

/// Deduplicador con ventana, exacto y acotado.
#[derive(Debug, Default)]
pub struct Deduplicador {
    inquilinos: BTreeMap<String, Ventana>,
    contadores: Contadores,
}

impl Deduplicador {
    /// Crea un deduplicador vacio.
    #[must_use]
    pub fn nuevo() -> Deduplicador {
        Deduplicador::default()
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Identificadores en memoria, sumando todos los inquilinos.
    #[must_use]
    pub fn tamano(&self) -> usize {
        self.inquilinos.values().map(|v| v.total).sum()
    }

    /// Inquilinos con estado.
    #[must_use]
    pub fn inquilinos(&self) -> usize {
        self.inquilinos.len()
    }

    /// Decide sobre un evento y lo registra si es nuevo.
    ///
    /// `ahora_ns` es la hora del plano de control, no la del evento: la ventana
    /// se mide contra el reloj del que recibe. Usar la del evento dejaria que un
    /// atacante fechara sus lineas en el futuro para quedarse en la ventana para
    /// siempre, o en el pasado para salirse de ella y colar duplicados.
    pub fn ver(&mut self, evento: &Evento, ahora_ns: u64) -> Veredicto {
        self.contadores.vistos += 1;
        if !evento.sello_valido() {
            self.contadores.sellos_rotos += 1;
            return Veredicto::SelloRoto;
        }
        if !self.inquilinos.contains_key(&evento.inquilino)
            && self.inquilinos.len() >= MAX_INQUILINOS
        {
            // Sin estado no se puede desduplicar, y eso es mejor que tirar el
            // evento: se deja pasar y se cuenta.
            self.contadores.inquilinos_rechazados += 1;
            self.contadores.nuevos += 1;
            return Veredicto::Nuevo;
        }
        let ventana = self.inquilinos.entry(evento.inquilino.clone()).or_default();
        let inicio = ahora_ns - ahora_ns % CUBO_NS;

        // Se olvida lo que ya vencio, cubo entero de golpe.
        while ventana
            .cubos
            .front()
            .is_some_and(|c| inicio.saturating_sub(c.inicio_ns) >= CUBOS as u64 * CUBO_NS)
        {
            if let Some(c) = ventana.cubos.pop_front() {
                ventana.total -= c.ids.len();
            }
        }

        if ventana.cubos.iter().any(|c| c.ids.contains(&evento.id)) {
            self.contadores.duplicados += 1;
            return Veredicto::Duplicado;
        }

        // La cota dura de memoria: antes de crecer, se hace sitio.
        while ventana.total >= MAX_POR_INQUILINO && ventana.cubos.len() > 1 {
            if let Some(c) = ventana.cubos.pop_front() {
                ventana.total -= c.ids.len();
                self.contadores.desalojos_prematuros += 1;
            }
        }

        match ventana.cubos.back_mut() {
            Some(c) if c.inicio_ns == inicio && c.ids.len() < MAX_POR_CUBO => {
                c.ids.insert(evento.id.clone());
            }
            _ => {
                let mut ids = HashSet::new();
                ids.insert(evento.id.clone());
                ventana.cubos.push_back(Cubo {
                    inicio_ns: inicio,
                    ids,
                });
            }
        }
        ventana.total += 1;
        self.contadores.nuevos += 1;
        Veredicto::Nuevo
    }

    /// Filtra un lote, devolviendo solo lo que pasa.
    ///
    /// Un evento con el sello roto **pasa y se marca**: ver
    /// [`Veredicto::SelloRoto`].
    pub fn filtrar(&mut self, lote: Vec<Evento>, ahora_ns: u64) -> Vec<Evento> {
        let mut salida = Vec::with_capacity(lote.len());
        for e in lote {
            match self.ver(&e, ahora_ns) {
                Veredicto::Nuevo | Veredicto::SelloRoto => salida.push(e),
                Veredicto::Duplicado => {}
            }
        }
        salida
    }

    /// Olvida el estado de un inquilino que ya no existe.
    pub fn olvidar(&mut self, inquilino: &str) {
        self.inquilinos.remove(inquilino);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::pruebas_comunes::evento;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    #[test]
    fn el_mismo_evento_reentregado_se_descarta_una_sola_vez() {
        let mut d = Deduplicador::nuevo();
        let e = evento("cliente-1", "ancla#1", AHORA);
        assert_eq!(d.ver(&e, AHORA), Veredicto::Nuevo);
        assert_eq!(d.ver(&e, AHORA), Veredicto::Duplicado);
        assert_eq!(d.ver(&e, AHORA + SEG), Veredicto::Duplicado);
        assert_eq!(d.contadores().duplicados, 2);
        assert_eq!(d.contadores().nuevos, 1);
    }

    #[test]
    fn dos_hechos_distintos_con_el_mismo_texto_no_se_funden() {
        // El ancla los distingue: veinte fallos de contrasena identicos en el
        // mismo segundo son veinte hechos.
        let mut d = Deduplicador::nuevo();
        for i in 0..20 {
            let e = evento("cliente-1", &format!("fichero:1:2@{}", i * 64), AHORA);
            assert_eq!(d.ver(&e, AHORA), Veredicto::Nuevo, "el intento {i}");
        }
        assert_eq!(d.contadores().duplicados, 0);
    }

    #[test]
    fn un_inquilino_ruidoso_no_provoca_duplicados_en_el_panel_de_otro() {
        // Con un conjunto global, el ruidoso desaloja los identificadores del
        // otro y le provoca duplicados en su panel.
        let mut d = Deduplicador::nuevo();
        let importante = evento("cliente-tranquilo", "ancla#1", AHORA);
        assert_eq!(d.ver(&importante, AHORA), Veredicto::Nuevo);

        for i in 0..(MAX_POR_INQUILINO + 1000) {
            let ruido = evento("cliente-ruidoso", &format!("ruido#{i}"), AHORA);
            d.ver(&ruido, AHORA);
        }

        assert_eq!(
            d.ver(&importante, AHORA),
            Veredicto::Duplicado,
            "el tranquilo perdio su estado por culpa del ruidoso"
        );
    }

    #[test]
    fn la_memoria_de_un_inquilino_esta_acotada() {
        // LA INVARIANTE: ninguna estructura crece sin limite.
        let mut d = Deduplicador::nuevo();
        for i in 0..(MAX_POR_INQUILINO * 2) {
            let e = evento("cliente-1", &format!("a#{i}"), AHORA);
            d.ver(&e, AHORA);
        }
        assert!(
            d.tamano() <= MAX_POR_INQUILINO + 1,
            "creci hasta {}",
            d.tamano()
        );
        assert!(d.contadores().desalojos_prematuros > 0, "y se cuenta");
    }

    #[test]
    fn lo_que_sale_de_la_ventana_pasa_en_vez_de_borrarse() {
        // EL FALLO QUE SI SE ACEPTA: un duplicado muy tardio se ve dos veces.
        // El contrario —borrar un evento unico— es el que no se puede tener.
        let mut d = Deduplicador::nuevo();
        let e = evento("cliente-1", "ancla#1", AHORA);
        assert_eq!(d.ver(&e, AHORA), Veredicto::Nuevo);
        let mucho_despues = AHORA + (CUBOS as u64 + 2) * CUBO_NS;
        assert_eq!(
            d.ver(&e, mucho_despues),
            Veredicto::Nuevo,
            "la ventana paso"
        );
    }

    #[test]
    fn dentro_de_la_ventana_el_duplicado_se_atrapa_aunque_pase_media_hora() {
        let mut d = Deduplicador::nuevo();
        let e = evento("cliente-1", "ancla#1", AHORA);
        d.ver(&e, AHORA);
        assert_eq!(d.ver(&e, AHORA + 30 * 60 * SEG), Veredicto::Duplicado);
    }

    #[test]
    fn un_evento_manipulado_por_el_camino_se_marca_pero_no_se_tira() {
        // Un evento manipulado sigue siendo evidencia de que alguien lo
        // manipulo; tirarlo seria borrar justo eso.
        let mut d = Deduplicador::nuevo();
        let mut e = evento("cliente-1", "ancla#1", AHORA);
        e.mensaje.push_str(" — cambiado por el camino");
        assert_eq!(d.ver(&e, AHORA), Veredicto::SelloRoto);
        let pasan = d.filtrar(vec![e], AHORA);
        assert_eq!(pasan.len(), 1, "pasa, marcado");
        // Dos: la consulta directa y la del filtro. Cada pasada decide por su
        // cuenta, que es lo correcto — el sello no se cachea.
        assert_eq!(d.contadores().sellos_rotos, 2);
    }

    #[test]
    fn la_ventana_se_mide_con_el_reloj_del_que_recibe() {
        // Con la hora del evento, un atacante que fechara sus lineas en el
        // futuro se quedaria en la ventana para siempre, y fechandolas en el
        // pasado colaria duplicados.
        let mut d = Deduplicador::nuevo();
        let mut e = evento("cliente-1", "ancla#1", AHORA);
        e.ocurrio_ns = AHORA + 10 * 365 * 24 * 3600 * SEG; // dentro de diez anos
        e.sellar();
        assert_eq!(d.ver(&e, AHORA), Veredicto::Nuevo);
        assert_eq!(d.ver(&e, AHORA), Veredicto::Duplicado);
        // Y sale de la ventana con el reloj de AQUI, no con el suyo.
        let despues = AHORA + (CUBOS as u64 + 2) * CUBO_NS;
        assert_eq!(d.ver(&e, despues), Veredicto::Nuevo);
    }

    #[test]
    fn el_numero_de_inquilinos_esta_acotado_y_el_que_sobra_pasa() {
        // Sin estado no se puede desduplicar, y dejar pasar es mejor que tirar.
        let mut d = Deduplicador::nuevo();
        for i in 0..MAX_INQUILINOS {
            let e = evento(&format!("cliente-{i}"), "a#1", AHORA);
            d.ver(&e, AHORA);
        }
        let extra = evento("cliente-que-no-cabe", "a#1", AHORA);
        assert_eq!(d.ver(&extra, AHORA), Veredicto::Nuevo);
        assert_eq!(d.ver(&extra, AHORA), Veredicto::Nuevo, "sigue sin estado");
        assert!(d.contadores().inquilinos_rechazados >= 2);
        assert_eq!(d.inquilinos(), MAX_INQUILINOS);
    }

    #[test]
    fn filtrar_un_lote_quita_solo_los_duplicados() {
        let mut d = Deduplicador::nuevo();
        let a = evento("c", "a#1", AHORA);
        let b = evento("c", "a#2", AHORA);
        let lote = vec![a.clone(), b.clone(), a.clone(), b, a];
        let pasan = d.filtrar(lote, AHORA);
        assert_eq!(pasan.len(), 2);
        assert_eq!(d.contadores().duplicados, 3);
    }

    #[test]
    fn olvidar_un_inquilino_libera_su_estado() {
        let mut d = Deduplicador::nuevo();
        let e = evento("c", "a#1", AHORA);
        d.ver(&e, AHORA);
        assert_eq!(d.inquilinos(), 1);
        d.olvidar("c");
        assert_eq!(d.inquilinos(), 0);
        assert_eq!(d.ver(&e, AHORA), Veredicto::Nuevo);
    }
}
