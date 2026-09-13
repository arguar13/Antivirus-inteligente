//! Conexiones: cien mil sesiones mTLS no caben en un proceso.
//!
//! # El numero que decide el diseno
//!
//! Una conexion TLS viva no es gratis. Entre los buferes de entrada y salida de
//! la biblioteca, el estado de la sesion, el socket del nucleo y lo que cuesta
//! seguirla en el bucle de eventos, sale del orden de **48 KiB por conexion**.
//! Cien mil conexiones son unos **4,7 GiB solo en estar conectado**, sin haber
//! procesado un evento. Mas los descriptores: el limite por defecto de un proceso
//! son 1024, y llegar a cien mil exige subirlo a proposito.
//!
//! Asi que «un proceso con cien mil conexiones» no es una meta de ingenieria: es
//! una forma de no haber hecho las cuentas.
//!
//! # Las dos ideas que hacen que quepa
//!
//! **1. La mayoria de los agentes no necesita estar conectada.** Un agente en
//! reposo manda un latido cada pocos minutos y recibe una politica de vez en
//! cuando. Lo que necesita una conexion viva es un agente **con trabajo
//! pendiente**: una caceria en curso, una orden de contencion, una descarga.
//!
//! Por eso la conexion es un **arriendo** ([`Arriendo`]) y no un estado
//! permanente: se toma, dura un rato, y se suelta. Un nodo con capacidad para
//! diez mil conexiones vivas atiende a cien mil agentes si cada uno esta
//! conectado el diez por ciento del tiempo, que es de sobra para el ritmo de
//! latido de un EDR.
//!
//! **2. El desfase tiene que ser determinista, no aleatorio.** Cuando un nodo se
//! reinicia, sus veinte mil agentes intentan reconectar. Si todos lo hacen a la
//! vez, el nodo se levanta y se cae otra vez; y como el reintento suele ser
//! periodico, vuelven a coincidir en la siguiente. Es la manada, y no se arregla
//! con reintentos exponenciales porque todos crecen igual.
//!
//! Se arregla **repartiendo a los agentes en la ventana**, y el reparto se
//! calcula con el identificador del agente ([`desfase_ms`]): sin generador
//! aleatorio, igual en el agente y en el servidor —asi que el servidor puede
//! predecir la carga— y estable entre reinicios, que es lo que impide que un
//! agente desafortunado caiga siempre en el mismo pico.
//!
//! # Y cuando el nodo que te toca esta lleno
//!
//! El sorteo dice a **que** nodo le toca un agente; la capacidad dice si ese nodo
//! **puede**. Cuando no puede, el agente va a su siguiente preferido y **queda
//! anotado**: un desbordamiento que no se cuenta es un plano de control
//! sobrecargado que parece sano.

use sha2::{Digest, Sha256};

/// Coste estimado de una conexion mTLS viva, en bytes.
///
/// Sale de sumar lo que de verdad ocupa: los buferes de la biblioteca de TLS, el
/// estado de la sesion, el socket del nucleo y la entrada en el bucle de
/// eventos. Es una estimacion **conservadora a proposito**: quedarse corto aqui
/// se paga con un nodo que acepta conexiones hasta que el nucleo lo mata.
pub const COSTE_CONEXION: u64 = 48 * 1024;

/// Ventana en la que se reparten las reconexiones, en milisegundos.
///
/// Sesenta segundos. Con veinte mil agentes por nodo salen unos trescientos
/// treinta por segundo, que un nodo acepta sin despeinarse. Una ventana mas
/// corta reconstruye la manada; una mas larga deja a la flota sin canal
/// demasiado tiempo despues de un reinicio.
pub const VENTANA_RECONEXION_MS: u64 = 60_000;

/// Duracion por defecto de un arriendo de conexion, en milisegundos.
///
/// Cinco minutos. Es el compromiso entre dos costes: soltar antes multiplica los
/// apretones de manos de TLS, que es lo caro de verdad; soltar despues ocupa un
/// hueco que otro agente necesita.
pub const ARRIENDO_MS: u64 = 5 * 60_000;

/// Estado de una peticion de conexion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resultado {
    /// Conectado a este nodo, con arriendo hasta el instante dado.
    Aceptado {
        /// Nodo que lo atiende.
        nodo: String,
        /// Cuando expira el arriendo, en nanosegundos.
        hasta_ns: u64,
    },
    /// El nodo que le tocaba estaba lleno; va al siguiente preferido.
    ///
    /// **Se cuenta.** Un desbordamiento que no se cuenta es un plano de control
    /// sobrecargado que parece sano.
    Desbordado {
        /// Nodo al que va realmente.
        nodo: String,
        /// Nodo al que le tocaba.
        preferido: String,
        /// Cuando expira el arriendo.
        hasta_ns: u64,
    },
    /// No hay sitio en ningun nodo preferido.
    ///
    /// El agente sigue trabajando **sin canal**: detecta, contiene con su
    /// politica local y acumula telemetria en su diario. Ver la FASE 68 y la 74.
    /// Lo que no hace es reintentar de inmediato: se le dice cuando volver.
    SinSitio {
        /// Milisegundos hasta el siguiente intento, ya desfasados.
        reintentar_en_ms: u64,
    },
}

/// Contadores del repartidor de conexiones.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Conexiones concedidas en el nodo preferido.
    pub aceptadas: u64,
    /// Conexiones concedidas en un nodo que no era el preferido.
    pub desbordadas: u64,
    /// Peticiones sin sitio en ningun nodo.
    pub sin_sitio: u64,
    /// Arriendos caducados y recogidos.
    pub caducados: u64,
    /// Pico de conexiones vivas a la vez.
    pub pico: u64,
}

/// Capacidad de un nodo del plano de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacidad {
    /// Memoria que el nodo dedica a conexiones, en bytes.
    pub memoria_conexiones: u64,
    /// Descriptores de fichero disponibles para sockets.
    pub descriptores: u64,
}

impl Capacidad {
    /// Cuantas conexiones vivas admite.
    ///
    /// Es el **minimo** de las dos cotas, no la que salga mas bonita: un nodo con
    /// memoria de sobra y el limite de descriptores por defecto se para en 1024
    /// conexiones, y el sintoma —«demasiados ficheros abiertos»— no se parece en
    /// nada a la causa.
    #[must_use]
    pub fn conexiones(&self) -> u64 {
        (self.memoria_conexiones / COSTE_CONEXION).min(self.descriptores)
    }

    /// Cuantos agentes atiende con un ciclo de trabajo dado, en centesimas.
    ///
    /// Es la cuenta que convierte «diez mil conexiones» en «cien mil agentes», y
    /// la que hay que enseñar cuando alguien pregunta si el plano de control
    /// aguanta la flota.
    #[must_use]
    pub fn agentes(&self, ciclo_centesimas: u64) -> u64 {
        if ciclo_centesimas == 0 {
            return u64::MAX;
        }
        self.conexiones() * 100 / ciclo_centesimas
    }
}

/// Un arriendo de conexion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arriendo {
    /// Agente que lo tiene.
    pub agente: String,
    /// Nodo que lo atiende.
    pub nodo: String,
    /// Cuando expira.
    pub hasta_ns: u64,
}

/// Desfase determinista de un agente dentro de una ventana, en milisegundos.
///
/// # Por que no es aleatorio
///
/// Tres razones, y las tres importan:
///
/// 1. **El agente y el servidor calculan lo mismo.** El servidor puede predecir
///    la curva de reconexion de su fragmento sin que nadie se la cuente.
/// 2. **Es estable entre reinicios.** Con azar, un agente desafortunado cae en el
///    pico una vez de cada tantas; con esto, cada agente tiene su hueco y siempre
///    es el suyo.
/// 3. **Se puede probar.** Una prueba comprueba que cien mil agentes se reparten
///    de verdad en la ventana, cosa que con un generador aleatorio seria una
///    prueba sobre el generador.
#[must_use]
pub fn desfase_ms(agente: &str, ventana_ms: u64) -> u64 {
    if ventana_ms == 0 {
        return 0;
    }
    let d = Sha256::digest(agente.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b) % ventana_ms
}

/// Reparte conexiones entre los nodos, respetando la capacidad de cada uno.
#[derive(Debug)]
pub struct Repartidor {
    capacidad: std::collections::BTreeMap<String, Capacidad>,
    vivos: std::collections::BTreeMap<String, Vec<Arriendo>>,
    arriendo_ms: u64,
    contadores: Contadores,
}

impl Repartidor {
    /// Crea un repartidor.
    #[must_use]
    pub fn nuevo(arriendo_ms: u64) -> Repartidor {
        Repartidor {
            capacidad: std::collections::BTreeMap::new(),
            vivos: std::collections::BTreeMap::new(),
            arriendo_ms,
            contadores: Contadores::default(),
        }
    }

    /// Declara la capacidad de un nodo.
    pub fn declarar(&mut self, nodo: &str, capacidad: Capacidad) {
        self.capacidad.insert(nodo.to_string(), capacidad);
        self.vivos.entry(nodo.to_string()).or_default();
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Conexiones vivas en un nodo.
    #[must_use]
    pub fn vivas(&self, nodo: &str) -> usize {
        self.vivos.get(nodo).map_or(0, Vec::len)
    }

    /// Conexiones vivas en total.
    #[must_use]
    pub fn vivas_totales(&self) -> usize {
        self.vivos.values().map(Vec::len).sum()
    }

    /// Capacidad total de la flota de nodos, en conexiones.
    #[must_use]
    pub fn capacidad_total(&self) -> u64 {
        self.capacidad.values().map(Capacidad::conexiones).sum()
    }

    /// Recoge los arriendos vencidos.
    ///
    /// Se llama antes de repartir: un hueco que no se recoge es un hueco que otro
    /// agente no puede usar, y en una flota grande eso es la diferencia entre
    /// caber y no caber.
    pub fn recoger(&mut self, ahora_ns: u64) -> usize {
        let mut n = 0;
        for lista in self.vivos.values_mut() {
            let antes = lista.len();
            lista.retain(|a| a.hasta_ns > ahora_ns);
            n += antes - lista.len();
        }
        self.contadores.caducados += n as u64;
        n
    }

    /// Pide conexion para un agente, con su lista de nodos preferidos.
    pub fn conectar(&mut self, agente: &str, preferidos: &[String], ahora_ns: u64) -> Resultado {
        let hasta_ns = ahora_ns + self.arriendo_ms * 1_000_000;
        for (i, nodo) in preferidos.iter().enumerate() {
            let cap = self.capacidad.get(nodo).map_or(0, Capacidad::conexiones);
            let vivas = self.vivas(nodo) as u64;
            if vivas < cap {
                self.vivos.entry(nodo.clone()).or_default().push(Arriendo {
                    agente: agente.to_string(),
                    nodo: nodo.clone(),
                    hasta_ns,
                });
                let total = self.vivas_totales() as u64;
                self.contadores.pico = self.contadores.pico.max(total);
                if i == 0 {
                    self.contadores.aceptadas += 1;
                    return Resultado::Aceptado {
                        nodo: nodo.clone(),
                        hasta_ns,
                    };
                }
                self.contadores.desbordadas += 1;
                return Resultado::Desbordado {
                    nodo: nodo.clone(),
                    preferido: preferidos[0].clone(),
                    hasta_ns,
                };
            }
        }
        self.contadores.sin_sitio += 1;
        Resultado::SinSitio {
            // Con desfase: si todos los que no caben reintentaran a la vez,
            // reconstruirian la manada contra un plano de control que ya iba
            // lleno.
            reintentar_en_ms: VENTANA_RECONEXION_MS + desfase_ms(agente, VENTANA_RECONEXION_MS),
        }
    }

    /// Suelta la conexion de un agente.
    pub fn soltar(&mut self, agente: &str, nodo: &str) {
        if let Some(lista) = self.vivos.get_mut(nodo) {
            lista.retain(|a| a.agente != agente);
        }
    }

    /// Simula la caida de un nodo: sus arriendos desaparecen.
    ///
    /// Devuelve los agentes que se quedaron sin canal, que son exactamente los
    /// que van a reconectar. Es lo que permite medir la manada antes de que
    /// ocurra en produccion.
    pub fn caer(&mut self, nodo: &str) -> Vec<String> {
        self.capacidad.remove(nodo);
        self.vivos
            .remove(nodo)
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.agente)
            .collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const SEG_NS: u64 = 1_000_000_000;

    fn capacidad(conexiones: u64) -> Capacidad {
        Capacidad {
            memoria_conexiones: conexiones * COSTE_CONEXION,
            descriptores: conexiones,
        }
    }

    // --- Las cuentas que decidieron el diseno --------------------------------

    #[test]
    fn cien_mil_conexiones_no_caben_en_un_proceso_y_la_cuenta_lo_dice() {
        // «Un proceso con cien mil conexiones» no es una meta de ingenieria: es
        // una forma de no haber hecho las cuentas.
        let un_proceso = Capacidad {
            memoria_conexiones: 2048 * MIB,
            descriptores: 100_000,
        };
        assert!(
            un_proceso.conexiones() < 50_000,
            "con 2 GiB salen {} conexiones",
            un_proceso.conexiones()
        );
    }

    #[test]
    fn el_limite_de_descriptores_manda_aunque_sobre_memoria() {
        // El sintoma —«demasiados ficheros abiertos»— no se parece en nada a la
        // causa, y por eso la cota se calcula como el MINIMO de las dos.
        let c = Capacidad {
            memoria_conexiones: 64 * 1024 * MIB,
            descriptores: 1024, // el limite por defecto de un proceso
        };
        assert_eq!(c.conexiones(), 1024);
    }

    #[test]
    fn diez_mil_conexiones_atienden_a_cien_mil_agentes() {
        // La cuenta que convierte una cosa en la otra, y la que hay que ensenar
        // cuando alguien pregunta si el plano de control aguanta la flota.
        let c = capacidad(10_000);
        assert_eq!(c.agentes(10), 100_000, "con un ciclo del 10 %");
        assert_eq!(c.agentes(100), 10_000, "si todos estuvieran siempre, no");
    }

    // --- La manada -----------------------------------------------------------

    #[test]
    fn cien_mil_agentes_se_reparten_de_verdad_en_la_ventana() {
        // Es la prueba que con un generador aleatorio seria una prueba sobre el
        // generador.
        let mut cubos = [0usize; 60];
        for i in 0..100_000u32 {
            let d = desfase_ms(&format!("agente-{i:06}"), VENTANA_RECONEXION_MS);
            cubos[usize::try_from(d / 1000).unwrap_or(59).min(59)] += 1;
        }
        let ideal = 100_000 / 60;
        for (s, n) in cubos.iter().enumerate() {
            assert!(
                *n > ideal * 85 / 100 && *n < ideal * 115 / 100,
                "el segundo {s} recibe {n}, ideal {ideal}"
            );
        }
    }

    #[test]
    fn el_desfase_de_un_agente_no_cambia_entre_reinicios() {
        // Con azar, un agente desafortunado cae en el pico una vez de cada
        // tantas; con esto, cada agente tiene su hueco y siempre es el suyo.
        let a = desfase_ms("agente-000042", VENTANA_RECONEXION_MS);
        let b = desfase_ms("agente-000042", VENTANA_RECONEXION_MS);
        assert_eq!(a, b);
        assert!(a < VENTANA_RECONEXION_MS);
    }

    #[test]
    fn el_agente_y_el_servidor_calculan_el_mismo_desfase() {
        // El servidor puede predecir la curva de reconexion de su fragmento sin
        // que nadie se la cuente.
        for i in 0..1000 {
            let id = format!("agente-{i}");
            assert_eq!(
                desfase_ms(&id, VENTANA_RECONEXION_MS),
                desfase_ms(&id, VENTANA_RECONEXION_MS)
            );
        }
    }

    // --- El reparto ----------------------------------------------------------

    #[test]
    fn un_nodo_lleno_manda_al_siguiente_preferido_y_lo_cuenta() {
        // Un desbordamiento que no se cuenta es un plano de control sobrecargado
        // que parece sano.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        r.declarar("a", capacidad(2));
        r.declarar("b", capacidad(10));
        let pref = vec!["a".to_string(), "b".to_string()];

        for i in 0..2 {
            assert!(matches!(
                r.conectar(&format!("ag{i}"), &pref, 0),
                Resultado::Aceptado { .. }
            ));
        }
        let tercero = r.conectar("ag2", &pref, 0);
        assert!(
            matches!(&tercero, Resultado::Desbordado { nodo, preferido, .. }
            if nodo == "b" && preferido == "a"),
            "{tercero:?}"
        );
        assert_eq!(r.contadores().desbordadas, 1);
    }

    #[test]
    fn sin_sitio_en_ninguno_se_dice_cuando_volver_y_con_desfase() {
        // Si todos los que no caben reintentaran a la vez, reconstruirian la
        // manada contra un plano de control que ya iba lleno.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        r.declarar("a", capacidad(1));
        let pref = vec!["a".to_string()];
        let _ = r.conectar("ag0", &pref, 0);

        let mut esperas = std::collections::BTreeSet::new();
        for i in 1..200 {
            match r.conectar(&format!("ag{i}"), &pref, 0) {
                Resultado::SinSitio { reintentar_en_ms } => {
                    assert!(reintentar_en_ms >= VENTANA_RECONEXION_MS);
                    esperas.insert(reintentar_en_ms);
                }
                otro => panic!("{otro:?}"),
            }
        }
        assert!(
            esperas.len() > 150,
            "solo {} esperas distintas",
            esperas.len()
        );
    }

    #[test]
    fn un_arriendo_que_vence_libera_su_hueco() {
        // Un hueco que no se recoge es un hueco que otro agente no puede usar, y
        // en una flota grande eso es la diferencia entre caber y no caber.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        r.declarar("a", capacidad(1));
        let pref = vec!["a".to_string()];
        assert!(matches!(
            r.conectar("ag0", &pref, 0),
            Resultado::Aceptado { .. }
        ));
        assert!(matches!(
            r.conectar("ag1", &pref, 0),
            Resultado::SinSitio { .. }
        ));

        let despues = ARRIENDO_MS * 1_000_000 + SEG_NS;
        assert_eq!(r.recoger(despues), 1);
        assert!(matches!(
            r.conectar("ag1", &pref, despues),
            Resultado::Aceptado { .. }
        ));
    }

    #[test]
    fn la_caida_de_un_nodo_devuelve_exactamente_quien_va_a_reconectar() {
        // Es lo que permite medir la manada antes de que ocurra en produccion.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        r.declarar("a", capacidad(100));
        r.declarar("b", capacidad(100));
        let pref_a = vec!["a".to_string(), "b".to_string()];
        for i in 0..50 {
            let _ = r.conectar(&format!("ag{i}"), &pref_a, 0);
        }
        let huerfanos = r.caer("a");
        assert_eq!(huerfanos.len(), 50);
        assert_eq!(r.vivas_totales(), 0);

        // Y todos caben en el que queda.
        let pref_b = vec!["b".to_string()];
        for ag in &huerfanos {
            assert!(matches!(
                r.conectar(ag, &pref_b, SEG_NS),
                Resultado::Aceptado { .. }
            ));
        }
    }

    #[test]
    fn soltar_devuelve_el_hueco_de_inmediato() {
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        r.declarar("a", capacidad(1));
        let pref = vec!["a".to_string()];
        let _ = r.conectar("ag0", &pref, 0);
        r.soltar("ag0", "a");
        assert_eq!(r.vivas("a"), 0);
        assert!(matches!(
            r.conectar("ag1", &pref, 0),
            Resultado::Aceptado { .. }
        ));
    }

    #[test]
    fn la_flota_entera_cabe_con_el_ciclo_de_trabajo_previsto() {
        // La afirmacion de la fase, hecha cuenta: dieciseis nodos con diez mil
        // conexiones cada uno, con agentes conectados el diez por ciento del
        // tiempo, atienden a mas de cien mil.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        for i in 0..16 {
            r.declarar(&format!("nodo-{i}"), capacidad(10_000));
        }
        assert_eq!(r.capacidad_total(), 160_000);
        let atiende: u64 = r.capacidad.values().map(|c| c.agentes(10)).sum();
        assert!(atiende >= 1_000_000, "atiende a {atiende}");
    }

    #[test]
    fn un_nodo_sin_capacidad_declarada_no_recibe_nada() {
        // Aceptar en un nodo del que no se sabe la capacidad es aceptar hasta
        // que el nucleo lo mate.
        let mut r = Repartidor::nuevo(ARRIENDO_MS);
        let pref = vec!["desconocido".to_string()];
        assert!(matches!(
            r.conectar("ag0", &pref, 0),
            Resultado::SinSitio { .. }
        ));
    }
}
