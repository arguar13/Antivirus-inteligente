//! El espacio de PID en tramos, y que tramos sondea cada barrido.
//!
//! # El defecto que esto arregla
//!
//! La vista C sondea el espacio de PID numero a numero con
//! `bpf_task_from_pid()`, y una invocacion del programa eBPF sondea como mucho
//! [`MAX_BARRIDO`] numeros (65536). Antes se pedia el rango entero en UNA
//! invocacion y el programa lo recortaba a esos 65536 sin decirlo. Pero
//! `pid_max` llega a [`PID_MAX_LIMIT`] (4194304), que es justo el valor que fija
//! systemd en 64 bits —Ubuntu, Fedora—: toda tarea con PID por encima de 65536
//! quedaba en la vista B y fuera de la C, y un proceso escondido por DKOM con
//! un PID alto no estaba en NINGUNA de las tres vistas. El informe salia limpio.
//!
//! # Tramos: las dos vistas siguen juntas
//!
//! El rango se parte en tramos alineados de [`MAX_BARRIDO`] PID ([`partir`]).
//! Cada tramo es UNA lectura del iterador en la que el programa toma B
//! (quedandose con las tareas del tramo) y C (sondeando el tramo): la propiedad
//! de «las dos vistas de un PID en la misma invocacion» se conserva por tramo.
//! Ninguna invocacion pasa de 65536 sondeos, y entre una y otra el hilo vuelve
//! a espacio de usuario: el barrido no acapara una CPU. Una peticion mayor que
//! un tramo la RECHAZA el programa (`ERR_ARGS`): ya no hay recorte silencioso.
//!
//! # Presupuesto: no todos los tramos en cada barrido
//!
//! Cada tramo cuesta 65536 llamadas a `bpf_task_from_pid` mas un recorrido de
//! la lista de tareas. Con `pid_max` = 4194304 son 64 tramos, y barrerlos
//! todos cada 30 s es gastar CPU sobre todo en numeros vacios. Un barrido
//! sondea como mucho `presupuesto` tramos ([`PRESUPUESTO_TRAMOS`] por defecto,
//! 2^20 PID), elegidos asi ([`Rotacion::planificar`]):
//!
//! 1. **Relevantes**, hasta una cuarta parte del presupuesto (al menos uno),
//!    en este orden: el tramo del propio agente, que es la sonda de la
//!    precondicion; los de sospechas con racha abierta, para que se confirmen
//!    en barridos CONSECUTIVOS; y los de los PID asignados desde el barrido
//!    anterior segun `ns_last_pid` ([`nacidos`]), para que un proceso recien
//!    escondido se vea en el barrido siguiente y no dentro de una vuelta.
//! 2. **Rotacion**, el resto: los tramos que hace mas barridos que no se
//!    sondean. Pase lo que pase con los relevantes, todo tramo se sondea al
//!    menos una vez cada [`Plan::barridos_por_vuelta`] barridos. Un DKOM es un
//!    estado que persiste, no un instante: una cota de vuelta basta para verlo.
//!
//! Si el rango cabe en el presupuesto (`pid_max` <= 2^20, el caso de 32768),
//! cada barrido lo sondea entero y no hay rotacion.
//!
//! Lo que un barrido no sondea se CUENTA ([`Plan::sin_sondear`]) y el motor lo
//! publica en el informe: un barrido parcial no autoriza la frase «no hay nada
//! oculto».
//!
//! # Por que no sondear solo los PID que B y `/proc` conocen
//!
//! Porque la vista C existe para encontrar lo que B y `/proc` NO conocen: una
//! tarea desenlazada por DKOM no esta en ninguna de las dos. Sondear solo esos
//! PID convierte C en una confirmacion de B y deja ciego al detector justo
//! donde tiene que mirar. Los «huecos relevantes» que se priorizan son los que
//! se pueden razonar sin preguntar al sistema comprometido —el cursor del
//! asignador—, y aun ese dato solo ordena: la cota de la rotacion no depende de
//! el, asi que un rootkit que lo falsee retrasa la deteccion, no la evita.

use std::collections::BTreeMap;

use crate::abi::MAX_BARRIDO;

/// `PID_MAX_LIMIT` del kernel en 64 bits (2^22): ningun PID llega aqui.
pub const PID_MAX_LIMIT: i32 = 4_194_304;

/// Tramos que sondea, como mucho, un barrido si no se configura otra cosa.
///
/// 16 tramos son 2^20 PID: cubre entero en cada barrido cualquier `pid_max`
/// hasta 1048576, y con 4194304 da una vuelta completa cada 6 barridos (12
/// tramos de rotacion por barrido).
pub const PRESUPUESTO_TRAMOS: usize = 16;

/// El ancho de un tramo, como PID.
const PASO: i32 = MAX_BARRIDO as i32;

// Un tramo tiene que caber en un `i32` y el limite tiene que ser multiplo del
// tramo, o el ultimo tramo alineado se saldria del espacio de PID.
const _: () = assert!(PASO > 0 && PID_MAX_LIMIT % PASO == 0);

/// Un tramo del espacio de PID, inclusive en los dos extremos.
///
/// Mide como mucho [`MAX_BARRIDO`] PID: es lo que el programa eBPF acepta en
/// una invocacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tramo {
    /// Primer PID.
    pub primero: i32,
    /// Ultimo PID, inclusive.
    pub ultimo: i32,
}

impl Tramo {
    /// Cuantos PID abarca.
    pub fn len(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            (i64::from(self.ultimo) - i64::from(self.primero) + 1) as u64
        }
    }

    /// Si no abarca ninguno.
    pub fn is_empty(&self) -> bool {
        self.ultimo < self.primero
    }

    /// Si contiene ese TID.
    pub fn contiene(&self, tid: u32) -> bool {
        (i64::from(self.primero)..=i64::from(self.ultimo)).contains(&i64::from(tid))
    }

    /// El numero del tramo alineado al que pertenece: la clave de la rotacion,
    /// estable aunque `pid_max` cambie entre barridos.
    fn indice(&self) -> i32 {
        self.primero.max(0) / PASO
    }
}

/// Parte `[primero, ultimo]` en tramos alineados de [`MAX_BARRIDO`] PID.
///
/// El rango se recorta a `[0, PID_MAX_LIMIT - 1]`. Los tramos van en orden,
/// son contiguos y su union es exactamente el rango recortado: ningun PID se
/// queda entre dos tramos ni se sondea dos veces.
pub fn partir(primero: i32, ultimo: i32) -> Vec<Tramo> {
    let primero = primero.max(0);
    let ultimo = ultimo.min(PID_MAX_LIMIT - 1);
    let mut salida = Vec::new();
    if ultimo < primero {
        return salida;
    }
    let mut inicio = primero;
    loop {
        let fin = ((inicio / PASO) * PASO + (PASO - 1)).min(ultimo);
        salida.push(Tramo {
            primero: inicio,
            ultimo: fin,
        });
        if fin >= ultimo {
            return salida;
        }
        inicio = fin + 1;
    }
}

/// Un representante por tramo de los PID asignados desde `antes` hasta
/// `ahora` (los dos, valores de `ns_last_pid`), del mas reciente al mas viejo.
///
/// El asignador es ciclico: al llegar a `pid_max` vuelve a empezar por abajo,
/// asi que si `ahora` < `antes` los nacidos son `(antes, ultimo]` y
/// `[primero, ahora]`. Sin barrido anterior (`antes` = `None`) solo se sabe
/// donde esta el cursor ahora. Como mucho devuelve un PID por tramo del rango.
pub fn nacidos(antes: Option<i32>, ahora: i32, primero: i32, ultimo: i32) -> Vec<u32> {
    let primero = primero.max(0);
    let ultimo = ultimo.min(PID_MAX_LIMIT - 1);
    if ultimo < primero {
        return Vec::new();
    }
    let ahora = ahora.clamp(primero, ultimo);
    let Some(antes) = antes.map(|a| a.clamp(primero, ultimo)) else {
        return vec![ahora as u32];
    };
    let tope = (ultimo / PASO - primero / PASO + 1) as usize;
    let mut salida = Vec::new();
    let mut pid = ahora;
    // `pid` recorre hacia atras, un tramo por paso, desde el cursor de ahora
    // hasta el tramo del cursor anterior. Con vuelta del asignador por medio,
    // el tramo de `antes` se alcanza por arriba: por eso se exige `pid >= antes`.
    for _ in 0..tope {
        salida.push(pid as u32);
        if pid / PASO == antes / PASO && pid >= antes {
            break;
        }
        let base = (pid / PASO) * PASO;
        pid = if base <= primero { ultimo } else { base - 1 };
    }
    salida
}

/// Lo que sondea un barrido.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Tramos a sondear, en orden creciente.
    pub tramos: Vec<Tramo>,
    /// PID que cubren esos tramos.
    pub sondeados: u64,
    /// PID del rango configurado que este barrido NO sondea.
    pub sin_sondear: u64,
    /// Barridos que tarda, como mucho, en sondearse el rango entero: 1 si cada
    /// barrido lo cubre todo.
    pub barridos_por_vuelta: u32,
}

impl Plan {
    /// El plan que lo sondea todo, en tramos.
    pub fn completo(primero: i32, ultimo: i32) -> Plan {
        let tramos = partir(primero, ultimo);
        let sondeados = tramos.iter().map(Tramo::len).sum();
        Plan {
            tramos,
            sondeados,
            sin_sondear: 0,
            barridos_por_vuelta: 1,
        }
    }

    /// Si este barrido sondea ese TID.
    pub fn cubre(&self, tid: u32) -> bool {
        // Los tramos van en orden: el primero que acaba en `tid` o despues es
        // el unico que puede contenerlo.
        let i = self
            .tramos
            .partition_point(|t| i64::from(t.ultimo) < i64::from(tid));
        self.tramos.get(i).is_some_and(|t| t.contiene(tid))
    }
}

/// Memoria de la rotacion: en que barrido se sondeo por ultima vez cada tramo.
#[derive(Debug, Clone, Default)]
pub struct Rotacion {
    /// Indice de tramo alineado -> ultimo barrido que lo sondeo (0: nunca).
    visto: BTreeMap<i32, u64>,
    /// Barridos planificados hasta ahora.
    barrido: u64,
}

impl Rotacion {
    /// Elige los tramos del siguiente barrido.
    ///
    /// `relevantes` son TID por orden de prioridad (ver la documentacion del
    /// modulo); los que caen fuera del rango se ignoran. `presupuesto` se toma
    /// como al menos 2: uno para la sonda y uno para la rotacion.
    ///
    /// # La cota de la vuelta
    ///
    /// La rotacion recibe al menos `presupuesto - cuota_relevante` plazas y las
    /// da a los tramos sondeados hace mas tiempo (a igualdad, el de menor
    /// indice). Un tramo X que no sale en un barrido tiene por delante —con un
    /// sondeo mas antiguo, o igual de antiguo y menor indice— al menos tantos
    /// tramos como plazas de rotacion; todos ellos pasan a tener un sondeo mas
    /// reciente que X, y ninguno vuelve a ponerse por delante porque el sondeo
    /// de X no cambia. Como por delante hay como mucho `n - 1`, X sale en como
    /// mucho `ceil(n / plazas)` barridos: eso es [`Plan::barridos_por_vuelta`].
    pub fn planificar(
        &mut self,
        primero: i32,
        ultimo: i32,
        presupuesto: usize,
        relevantes: &[u32],
    ) -> Plan {
        self.barrido += 1;
        let todos = partir(primero, ultimo);
        let total: u64 = todos.iter().map(Tramo::len).sum();
        let presupuesto = presupuesto.max(2);
        let cuota_relevante = (presupuesto / 4).max(1);
        let plazas_rotacion = presupuesto - cuota_relevante;

        let elegidos: Vec<usize> = if todos.len() <= presupuesto {
            (0..todos.len()).collect()
        } else {
            let mut e: Vec<usize> = Vec::with_capacity(todos.len());
            for &tid in relevantes {
                if e.len() >= cuota_relevante {
                    break;
                }
                if let Some(i) = todos.iter().position(|t| t.contiene(tid)) {
                    if !e.contains(&i) {
                        e.push(i);
                    }
                }
            }
            let mut resto: Vec<usize> = (0..todos.len()).filter(|i| !e.contains(i)).collect();
            resto.sort_by_key(|&i| {
                let visto = self.visto.get(&todos[i].indice()).copied().unwrap_or(0);
                (visto, i)
            });
            let libres = presupuesto - e.len();
            e.extend(resto.into_iter().take(libres));
            e.sort_unstable();
            e
        };

        for &i in &elegidos {
            self.visto.insert(todos[i].indice(), self.barrido);
        }
        let barridos_por_vuelta = if todos.len() <= presupuesto {
            1
        } else {
            todos.len().div_ceil(plazas_rotacion)
        };
        let tramos: Vec<Tramo> = elegidos.iter().map(|&i| todos[i]).collect();
        let sondeados: u64 = tramos.iter().map(Tramo::len).sum();
        Plan {
            tramos,
            sondeados,
            sin_sondear: total - sondeados,
            barridos_por_vuelta: u32::try_from(barridos_por_vuelta).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// El `pid_max` de Ubuntu y Fedora, como ultimo PID asignable.
    const ULTIMO_UBUNTU: i32 = PID_MAX_LIMIT - 1;

    #[test]
    fn los_tramos_cubren_el_rango_entero_sin_huecos_ni_solapes() {
        for (a, b) in [
            (1, 32_767),
            (1, 32_768),
            (1, 65_535),
            (1, 65_536),
            (1, ULTIMO_UBUNTU),
            (300, 4_194_304), // pid_max tal cual: se recorta al limite
            (70_000, 70_000),
        ] {
            let t = partir(a, b);
            let b = b.min(ULTIMO_UBUNTU);
            assert_eq!(t.first().map(|x| x.primero), Some(a), "{a}..{b}");
            assert_eq!(t.last().map(|x| x.ultimo), Some(b), "{a}..{b}");
            for par in t.windows(2) {
                assert_eq!(par[0].ultimo + 1, par[1].primero, "contiguos: {par:?}");
            }
            assert!(t
                .iter()
                .all(|x| !x.is_empty() && x.len() <= u64::from(MAX_BARRIDO)));
            let suma: u64 = t.iter().map(Tramo::len).sum();
            assert_eq!(suma, (i64::from(b) - i64::from(a) + 1) as u64);
        }
        assert_eq!(partir(1, ULTIMO_UBUNTU).len(), 64);
        assert_eq!(partir(1, 32_767).len(), 1);
        assert!(partir(10, 9).is_empty());
    }

    #[test]
    fn un_pid_por_encima_de_65536_cae_en_un_tramo_del_plan_completo() {
        // El defecto de partida: con un solo barrido de MAX_BARRIDO numeros,
        // estos PID no los sondeaba nadie.
        let plan = Plan::completo(1, ULTIMO_UBUNTU);
        for tid in [65_536u32, 65_537, 70_000, 1_000_000, 4_194_303] {
            assert!(
                plan.cubre(tid),
                "el PID {tid} tiene que estar en la vista C"
            );
        }
        assert!(!plan.cubre(0));
        assert!(!plan.cubre(4_194_304));
        assert_eq!(plan.sondeados, 4_194_303);
        assert_eq!(plan.sin_sondear, 0);
    }

    #[test]
    fn con_pid_max_pequeno_cada_barrido_lo_sondea_todo() {
        let mut r = Rotacion::default();
        for _ in 0..3 {
            let p = r.planificar(1, 32_767, PRESUPUESTO_TRAMOS, &[]);
            assert_eq!(p.tramos, partir(1, 32_767));
            assert_eq!((p.sin_sondear, p.barridos_por_vuelta), (0, 1));
        }
    }

    #[test]
    fn la_rotacion_lo_sondea_todo_dentro_de_su_cota_y_respeta_el_presupuesto() {
        let mut r = Rotacion::default();
        let todos = partir(1, ULTIMO_UBUNTU);
        let mut ultima_vez: BTreeMap<Tramo, u32> = BTreeMap::new();
        let mut cota = 0;
        // Relevantes que cambian cada barrido y empujan a la rotacion: aun asi,
        // la cota se cumple.
        for b in 1..=40u32 {
            let ruido = [b * 97_003 % 4_194_303, b * 31_337 % 4_194_303];
            let p = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &ruido);
            cota = p.barridos_por_vuelta;
            assert!(p.tramos.len() <= PRESUPUESTO_TRAMOS, "{}", p.tramos.len());
            assert_eq!(p.sondeados + p.sin_sondear, 4_194_303);
            assert!(p.sin_sondear > 0, "64 tramos no caben en 16");
            for t in &p.tramos {
                ultima_vez.insert(*t, b);
            }
            if b > cota {
                for t in &todos {
                    let visto = ultima_vez.get(t).copied().unwrap_or(0);
                    assert!(
                        b - visto < cota,
                        "el tramo {t:?} lleva {} barridos sin sondearse (cota {cota})",
                        b - visto
                    );
                }
            }
        }
        // 16 de presupuesto: 4 relevantes y 12 de rotacion, 64 tramos.
        assert_eq!(cota, 6);
    }

    #[test]
    fn lo_relevante_se_sondea_en_el_mismo_barrido() {
        let mut r = Rotacion::default();
        // Un barrido para que la rotacion ya no empiece por abajo.
        let _ = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &[]);
        let sonda = 3_000_001u32;
        let racha = 2_100_000u32;
        let p = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &[sonda, racha]);
        assert!(p.cubre(sonda) && p.cubre(racha), "{:?}", p.tramos);
        // Un relevante fuera del rango no gasta plaza.
        let p = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &[u32::MAX]);
        assert_eq!(p.tramos.len(), PRESUPUESTO_TRAMOS);
    }

    #[test]
    fn la_cuota_relevante_no_se_come_la_rotacion() {
        let mut r = Rotacion::default();
        // Un relevante en cada tramo: solo entran 4; los otros 12 son rotacion.
        let todos: Vec<u32> = (0..64u32).map(|k| k * 65_536 + 5).collect();
        let p1 = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &todos);
        let p2 = r.planificar(1, ULTIMO_UBUNTU, PRESUPUESTO_TRAMOS, &todos);
        assert_eq!(p1.tramos.len(), PRESUPUESTO_TRAMOS);
        assert_ne!(p1.tramos, p2.tramos, "la rotacion avanza");
    }

    #[test]
    fn los_nacidos_van_del_cursor_hacia_atras_y_dan_la_vuelta() {
        // Sin barrido anterior: solo el cursor.
        assert_eq!(nacidos(None, 200_000, 1, ULTIMO_UBUNTU), vec![200_000]);
        // Sin nacimientos: el tramo del cursor.
        assert_eq!(
            nacidos(Some(200_000), 200_000, 1, ULTIMO_UBUNTU),
            vec![200_000]
        );
        // De 100000 a 200000: tramos 3, 2 y 1, del mas reciente al mas viejo.
        let n = nacidos(Some(100_000), 200_000, 1, ULTIMO_UBUNTU);
        assert_eq!(n, vec![200_000, 196_607, 131_071]);
        // Con vuelta: de 4190000 a 1000 pasando por el tope.
        let n = nacidos(Some(4_190_000), 1_000, 300, ULTIMO_UBUNTU);
        assert_eq!(n, vec![1_000, 4_194_303]);
        // Una vuelta entera: todos los tramos, y ni uno mas.
        let n = nacidos(Some(1_000), 500, 1, ULTIMO_UBUNTU);
        assert_eq!(n.len(), 64);
        let plan = Plan {
            tramos: partir(1, ULTIMO_UBUNTU),
            ..Plan::default()
        };
        assert!(n.iter().all(|t| plan.cubre(*t)));
    }
}
