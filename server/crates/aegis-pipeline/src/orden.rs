//! Orden por hora de OCURRENCIA, no de llegada.
//!
//! # El defecto que esto corrige, y por que se corrige dos veces
//!
//! Un endpoint que estuvo apagado un dia entrega su lote entero al reconectar.
//! Si los eventos se ordenaran por **llegada**, un ataque repartido en dos dias
//! apareceria como un pico de un segundo: todas las heuristicas de ritmo —fuerza
//! bruta, exfiltracion lenta, balizas— lo leerian exactamente al reves de como
//! ocurrio.
//!
//! Ya se corrigio una vez en la FASE 45. Aqui se corrige en el sitio donde de
//! verdad se decide: el punto por el que pasan todos los eventos de todos los
//! origenes antes de correlacionarse.
//!
//! # Lo que esta ventana NO hace: retrasar
//!
//! La confusion habitual con una ventana de reordenacion es creer que retiene
//! los eventos viejos. Es al reves: **los eventos viejos salen inmediatamente**,
//! porque su hora ya esta fuera de la ventana. Lo que la ventana sostiene unos
//! segundos es lo **reciente**, que es lo unico que todavia puede llegar
//! desordenado.
//!
//! Asi que el lote de un endpoint que estuvo un dia apagado atraviesa esto sin
//! esperar ni un milisegundo, ordenado entre si y con sus horas reales. Que es
//! justo lo que hace falta.
//!
//! # La marca de agua, y por que es monotona
//!
//! La **marca de agua** es la hora por debajo de la cual ya no va a salir nada
//! mas. Es lo que permite a la correlacion cerrar una ventana de tiempo y
//! decidir.
//!
//! Y es **monotona a la fuerza**, lo cual no es un detalle de implementacion
//! sino una defensa: la hora de ocurrencia sale del registro, y el registro lo
//! escribe cualquiera. Sin monotonia, un atacante que fechara una linea en 2019
//! haria retroceder la marca de agua y **reabriria ventanas de correlacion ya
//! cerradas**, con lo que podria obligar al plano de control a recalcular
//! historia indefinidamente. Con monotonia, su linea entra —marcada como
//! sospechosa, conservando su hora— y no mueve nada.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use aegis_ingest::esquema::{ConfianzaReloj, Evento};

/// Cuanto se sostiene lo reciente antes de darlo por ordenado.
///
/// Treinta segundos. Sale de lo que de verdad desordena los eventos: varios
/// endpoints con relojes que difieren unos segundos, colas que se vacian a
/// ritmos distintos y reintentos cortos. Mas ventana no ordenaria mas y anadiria
/// retraso a la deteccion, que es lo que un EDR no puede permitirse.
pub const GRACIA_NS: u64 = 30 * 1_000_000_000;

/// Eventos que pueden estar esperando a la vez.
///
/// La cota dura. Al alcanzarla se emite el mas antiguo aunque no haya cumplido
/// su gracia: **se pierde orden, no se pierden eventos**. Es la eleccion
/// correcta aqui, al reves que en la cola del endpoint: alli no hay sitio y hay
/// que tirar algo; aqui si lo hay, y un evento desordenado sigue siendo
/// evidencia mientras que uno tirado no.
pub const MAX_EN_VUELO: usize = 50_000;

/// Clave de orden: la hora, y el identificador para desempatar.
///
/// El desempate por identificador **no es un capricho**: sin el, dos eventos con
/// la misma hora salen en un orden que depende de como quedara el monton, y eso
/// rompe el determinismo de toda la canalizacion. Con el, el mismo lote produce
/// siempre la misma secuencia.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Clave {
    ocurrio_ns: u64,
    id: String,
}

/// Contadores del reordenador.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos admitidos.
    pub admitidos: u64,
    /// Eventos emitidos.
    pub emitidos: u64,
    /// Eventos que salieron desordenados por alcanzar la cota de memoria.
    pub emitidos_a_la_fuerza: u64,
    /// Eventos que llegaron por debajo de la marca de agua ya emitida.
    ///
    /// Son eventos que la correlacion ya no puede colocar en su sitio. No se
    /// tiran —siguen siendo evidencia— pero se cuentan, porque si esta cifra
    /// crece, la ventana de gracia se ha quedado corta para esta instalacion.
    pub tardios: u64,
    /// Eventos cuya hora no sirve para ordenar.
    pub sin_reloj_fiable: u64,
}

/// Reordena por ocurrencia con una ventana de gracia acotada.
#[derive(Debug)]
pub struct Reordenador {
    gracia_ns: u64,
    maximo: usize,
    espera: BinaryHeap<Reverse<(Clave, usize)>>,
    eventos: Vec<Option<Evento>>,
    /// Huecos reutilizables en `eventos`, para no crecer sin fin.
    libres: Vec<usize>,
    marca_de_agua: u64,
    contadores: Contadores,
}

impl Default for Reordenador {
    fn default() -> Reordenador {
        Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO)
    }
}

impl Reordenador {
    /// Crea un reordenador.
    #[must_use]
    pub fn nuevo(gracia_ns: u64, maximo: usize) -> Reordenador {
        Reordenador {
            gracia_ns,
            maximo: maximo.max(1),
            espera: BinaryHeap::new(),
            eventos: Vec::new(),
            libres: Vec::new(),
            marca_de_agua: 0,
            contadores: Contadores::default(),
        }
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Eventos esperando.
    #[must_use]
    pub fn en_vuelo(&self) -> usize {
        self.espera.len()
    }

    /// Hora por debajo de la cual ya no saldra nada mas.
    #[must_use]
    pub fn marca_de_agua(&self) -> u64 {
        self.marca_de_agua
    }

    /// Mete un evento en la ventana.
    ///
    /// **No emite nada por vencimiento**, y eso es deliberado: emitir dentro de
    /// `admitir` haria que un lote que llega junto saliera en el orden en que se
    /// admitio, porque cada evento se emitiria antes de ver al siguiente. Es
    /// exactamente lo contrario de lo que este modulo existe para hacer. Quien
    /// llama admite todo el lote y despues pide [`Reordenador::vencidos`].
    ///
    /// Lo unico que devuelve es lo que hubo que emitir **a la fuerza** por
    /// alcanzar la cota de memoria.
    pub fn admitir(&mut self, evento: Evento, _ahora_ns: u64) -> Vec<Evento> {
        self.contadores.admitidos += 1;
        if evento.reloj == ConfianzaReloj::DeLlegada {
            // Su hora es la de lectura: ordenar por ella es ordenar por llegada.
            // Se admite igual —es lo unico que hay— pero se cuenta, porque una
            // instalacion donde esta cifra domina no puede razonar sobre ritmos.
            self.contadores.sin_reloj_fiable += 1;
        }
        if evento.ocurrio_ns < self.marca_de_agua {
            self.contadores.tardios += 1;
        }

        let clave = Clave {
            ocurrio_ns: evento.ocurrio_ns,
            id: evento.id.clone(),
        };
        let hueco = match self.libres.pop() {
            Some(i) => {
                self.eventos[i] = Some(evento);
                i
            }
            None => {
                self.eventos.push(Some(evento));
                self.eventos.len() - 1
            }
        };
        self.espera.push(Reverse((clave, hueco)));

        let mut salida = Vec::new();
        // La cota dura primero: si no cabe, sale el mas antiguo aunque no haya
        // cumplido su gracia.
        while self.espera.len() > self.maximo {
            if let Some(e) = self.sacar_el_primero() {
                self.contadores.emitidos_a_la_fuerza += 1;
                salida.push(e);
            }
        }
        salida
    }

    /// Emite todo lo que ya cumplio su gracia.
    pub fn vencidos(&mut self, ahora_ns: u64) -> Vec<Evento> {
        let frontera = ahora_ns.saturating_sub(self.gracia_ns);
        let mut salida = Vec::new();
        while self
            .espera
            .peek()
            .is_some_and(|Reverse((c, _))| c.ocurrio_ns <= frontera)
        {
            if let Some(e) = self.sacar_el_primero() {
                salida.push(e);
            }
        }
        // La marca de agua sube hasta la frontera, y NUNCA baja: ver el
        // encabezado del modulo.
        self.marca_de_agua = self.marca_de_agua.max(frontera);
        salida
    }

    /// Vacia la ventana entera, en orden.
    ///
    /// Lo llama el apagado ordenado: dejar eventos dentro al parar seria
    /// perderlos, y esta es la unica etapa de la canalizacion que los tiene solo
    /// en memoria.
    pub fn vaciar(&mut self) -> Vec<Evento> {
        let mut salida = Vec::with_capacity(self.espera.len());
        while let Some(e) = self.sacar_el_primero() {
            salida.push(e);
        }
        salida
    }

    fn sacar_el_primero(&mut self) -> Option<Evento> {
        let Reverse((clave, hueco)) = self.espera.pop()?;
        let evento = self.eventos[hueco].take()?;
        self.libres.push(hueco);
        self.contadores.emitidos += 1;
        self.marca_de_agua = self.marca_de_agua.max(clave.ocurrio_ns);
        Some(evento)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::pruebas_comunes::evento_en;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    #[test]
    fn dos_eventos_que_llegan_al_reves_salen_en_orden() {
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        let tarde = evento_en("c", "b", AHORA - 2 * SEG);
        let pronto = evento_en("c", "a", AHORA - 5 * SEG);
        assert!(r.admitir(tarde, AHORA).is_empty());
        assert!(r.admitir(pronto, AHORA).is_empty());
        assert!(r.vencidos(AHORA).is_empty(), "todavia en gracia");

        let salida = r.vencidos(AHORA + GRACIA_NS);
        assert_eq!(salida.len(), 2);
        assert!(salida[0].ocurrio_ns < salida[1].ocurrio_ns);
    }

    #[test]
    fn el_lote_de_un_endpoint_apagado_un_dia_no_espera_ni_un_milisegundo() {
        // LA CONFUSION HABITUAL: creer que la ventana retiene lo viejo. Es al
        // reves: lo viejo ya esta fuera de la ventana y sale de inmediato.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        let ayer = AHORA - 24 * 3600 * SEG;
        for i in 0..10u64 {
            r.admitir(evento_en("c", &format!("v{i}"), ayer + i * 60 * SEG), AHORA);
        }
        let salida = r.vencidos(AHORA);
        assert_eq!(salida.len(), 10, "salieron todos ya, sin esperar");
        for par in salida.windows(2) {
            assert!(par[0].ocurrio_ns <= par[1].ocurrio_ns, "y en su orden real");
        }
    }

    #[test]
    fn un_ataque_repartido_en_dos_dias_no_parece_un_pico_de_un_segundo() {
        // EL DEFECTO QUE ESTO CORRIGE, entero: los eventos llegan JUNTOS pero
        // ocurrieron separados, y lo que sale conserva la separacion.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        let dia1 = AHORA - 48 * 3600 * SEG;
        let dia2 = AHORA - 24 * 3600 * SEG;
        // Llegan mezclados, todos en el mismo instante de lectura.
        for (i, t) in [dia2, dia1, dia2, dia1].iter().enumerate() {
            assert!(r
                .admitir(evento_en("c", &format!("e{i}"), *t), AHORA)
                .is_empty());
        }
        let salida = r.vencidos(AHORA);
        assert_eq!(salida.len(), 4);
        assert_eq!(salida[0].ocurrio_ns, dia1);
        assert_eq!(salida[1].ocurrio_ns, dia1);
        assert_eq!(salida[3].ocurrio_ns, dia2);
        let separacion = salida[3].ocurrio_ns - salida[0].ocurrio_ns;
        assert_eq!(separacion, 24 * 3600 * SEG, "un dia, no un segundo");
    }

    #[test]
    fn una_linea_fechada_en_2019_no_reabre_ventanas_ya_cerradas() {
        // Sin monotonia, un atacante haria retroceder la marca de agua y
        // obligaria al plano de control a recalcular historia indefinidamente.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        r.admitir(evento_en("c", "normal", AHORA - 60 * SEG), AHORA);
        let _ = r.vencidos(AHORA);
        let marca = r.marca_de_agua();
        assert!(marca > 0);

        let viejo = AHORA - 5 * 365 * 24 * 3600 * SEG;
        assert!(r
            .admitir(evento_en("c", "antiguo", viejo), AHORA)
            .is_empty());
        let salida = r.vencidos(AHORA);
        assert_eq!(salida.len(), 1, "entra y sale, no se pierde");
        assert_eq!(r.marca_de_agua(), marca, "pero no mueve la marca");
        assert_eq!(r.contadores().tardios, 1, "y se cuenta");
    }

    #[test]
    fn la_marca_de_agua_no_baja_nunca() {
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        let _ = r.vencidos(AHORA);
        let alta = r.marca_de_agua();
        let _ = r.vencidos(AHORA - 3600 * SEG);
        assert_eq!(r.marca_de_agua(), alta);
    }

    #[test]
    fn la_memoria_esta_acotada_y_se_pierde_orden_en_vez_de_eventos() {
        // Al reves que en la cola del endpoint: alli no hay sitio y hay que
        // tirar algo; aqui si lo hay, y un evento desordenado sigue siendo
        // evidencia mientras que uno tirado no.
        let mut r = Reordenador::nuevo(GRACIA_NS, 100);
        let mut salidos = 0usize;
        for i in 0..10_000u64 {
            // Todos en el futuro: ninguno vence por gracia, asi que lo unico que
            // puede sacarlos es la cota de memoria.
            salidos += r
                .admitir(evento_en("c", &format!("e{i}"), AHORA + i), AHORA)
                .len();
            assert!(r.en_vuelo() <= 100, "en vuelo {}", r.en_vuelo());
        }
        salidos += r.vaciar().len();
        assert_eq!(salidos, 10_000, "no se perdio ninguno");
        assert!(r.contadores().emitidos_a_la_fuerza > 0, "y se cuenta");
    }

    #[test]
    fn el_orden_es_determinista_ante_horas_iguales() {
        // Sin desempate por identificador, dos eventos con la misma hora salen
        // en un orden que depende de como quedara el monton, y eso rompe el
        // determinismo de toda la canalizacion.
        let secuencia = |semilla: usize| {
            let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
            let mut ids: Vec<String> = (0..50).map(|i| format!("a{i:02}")).collect();
            if semilla == 1 {
                ids.reverse();
            }
            for id in ids {
                r.admitir(evento_en("c", &id, AHORA - 3600 * SEG), AHORA);
            }
            r.vaciar().into_iter().map(|e| e.ancla).collect::<Vec<_>>()
        };
        assert_eq!(secuencia(0), secuencia(1));
    }

    #[test]
    fn un_evento_sin_hora_fiable_se_admite_pero_se_cuenta() {
        // Una instalacion donde esta cifra domina no puede razonar sobre ritmos,
        // y eso hay que poder verlo.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        let mut e = evento_en("c", "a", AHORA);
        e.reloj = ConfianzaReloj::DeLlegada;
        e.sellar();
        r.admitir(e, AHORA);
        assert_eq!(r.contadores().sin_reloj_fiable, 1);
    }

    #[test]
    fn vaciar_no_deja_nada_dentro() {
        // Dejar eventos dentro al parar seria perderlos: esta es la unica etapa
        // que los tiene solo en memoria.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        for i in 0..100u64 {
            r.admitir(evento_en("c", &format!("e{i}"), AHORA + i), AHORA);
        }
        assert_eq!(r.vaciar().len(), 100);
        assert_eq!(r.en_vuelo(), 0);
        assert!(r.vaciar().is_empty());
    }

    #[test]
    fn los_huecos_del_almacen_se_reutilizan() {
        // Sin reutilizar, el vector interno crece con el numero total de eventos
        // vistos en vez de con los que hay en vuelo: una fuga lenta que solo se
        // ve tras dias de servicio.
        let mut r = Reordenador::nuevo(GRACIA_NS, MAX_EN_VUELO);
        for i in 0..10_000u64 {
            r.admitir(evento_en("c", &format!("e{i}"), AHORA - 3600 * SEG), AHORA);
            let _ = r.vencidos(AHORA);
        }
        assert!(
            r.eventos.len() < 100,
            "el almacen crecio a {}",
            r.eventos.len()
        );
    }
}
