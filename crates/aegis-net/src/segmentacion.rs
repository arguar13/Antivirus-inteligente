//! Micro-segmentacion Zero-Trust: cuarentena de enjambre en el endpoint.
//!
//! QUE PROBLEMA RESUELVE
//! ---------------------
//! Cuando se confirma que una maquina esta comprometida, aislarla desde ella
//! misma tiene un problema de fondo: el aislamiento lo aplica su propio agente,
//! y la fiabilidad de ese agente es justo lo que ha dejado de estar clara. Un
//! atacante con privilegios de kernel en esa maquina puede desactivarlo.
//!
//! La cuarentena de enjambre invierte el planteamiento: son TODAS LAS DEMAS
//! maquinas las que dejan de hablar con la comprometida. Cada endpoint sano
//! instala la regla en su propio kernel, con su propio agente, que sigue siendo
//! de fiar. Aunque el agente de la maquina infectada este muerto, secuestrado o
//! mintiendo, sus paquetes no llegan a ninguna parte.
//!
//! POR QUE HACEN FALTA DOS CAPAS
//! -----------------------------
//! XDP se ejecuta en el camino de RECEPCION, antes de que el paquete toque la
//! pila de red. Es el sitio mas barato y mas temprano donde se puede descartar
//! algo... y **no existe un hook XDP de salida**. XDP no puede filtrar trafico
//! saliente, y decir lo contrario seria vender una contencion que no existe.
//!
//! Por eso:
//!
//! | Sentido  | Capa      | Donde actua                        |
//! |----------|-----------|------------------------------------|
//! | Entrante | XDP       | en el driver, antes de la pila      |
//! | Saliente | nftables  | hook `output`, en la pila           |
//!
//! Las dos son necesarias. Solo con XDP, la maquina comprometida no puede
//! hablarnos pero nosotros si podriamos hablarle —y un implante que espera
//! conexiones entrantes seguiria recibiendolas—. Solo con nftables, se pierde el
//! descarte temprano que hace que una inundacion no consuma CPU.
//!
//! SI UNA CAPA FALLA, SE DICE
//! --------------------------
//! Una cuarentena aplicada solo a medias es una contencion parcial, y el
//! operador tiene que saberlo: creer que una maquina esta aislada cuando solo lo
//! esta en un sentido es peor que saber que no lo esta.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use aegis_scal::netfilter::{BlockReason as MotivoNft, NetworkFilter};

/// Resultado de reconciliar la cuarentena con el estado del kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciliacion {
    /// Direcciones que se anadieron.
    pub anadidas: Vec<IpAddr>,
    /// Direcciones que se retiraron.
    pub retiradas: Vec<IpAddr>,
    /// Direcciones que quedaron aplicadas SOLO en el sentido entrante.
    ///
    /// No es un detalle: significa que esa maquina no puede hablarnos, pero
    /// nosotros si podriamos hablarle.
    pub solo_entrante: Vec<IpAddr>,
    /// Direcciones que quedaron aplicadas SOLO en el sentido saliente.
    pub solo_saliente: Vec<IpAddr>,
    /// Direcciones que no se pudieron aplicar en ninguna capa.
    pub fallidas: Vec<IpAddr>,
}

impl Reconciliacion {
    /// Indica si toda la cuarentena quedo aplicada en los dos sentidos.
    pub fn completa(&self) -> bool {
        self.solo_entrante.is_empty() && self.solo_saliente.is_empty() && self.fallidas.is_empty()
    }
}

/// Aplica en el kernel local la cuarentena que ordena el plano de control.
///
/// Es generico sobre las dos capas para poder ejercitarlo sin privilegios de
/// kernel; en produccion recibe el filtro XDP y el bloqueador de nftables
/// reales. La logica de reconciliacion —que es donde estan los errores
/// interesantes— es la misma en los dos casos.
pub struct Segmentador<E, S> {
    entrante: E,
    saliente: S,
    /// Lo que se cree aplicado ahora mismo.
    aplicadas: BTreeSet<IpAddr>,
    /// Direcciones de ESTA maquina, que nunca se bloquean.
    ///
    /// POR QUE LA AUTO-EXCLUSION SE HACE AQUI Y NO EN EL SERVIDOR
    /// ----------------------------------------------------------
    /// Un endpoint que se bloquea a si mismo se queda sin plano de control:
    /// deja de poder recibir incluso la orden de que la cuarentena se levanto,
    /// y a partir de ahi solo se recupera yendo fisicamente a la maquina.
    ///
    /// El servidor podria quitarle su direccion a cada agente, pero solo conoce
    /// UNA: la que vio en el handshake. Una maquina tiene varias —dos
    /// interfaces, una VPN, una IP flotante— y la cuarentena podria caer sobre
    /// cualquiera de las otras. Quien las conoce todas es la maquina.
    ///
    /// Ademas, hacerlo aqui permite que la lista que envia el servidor sea
    /// IDENTICA para toda la flota, y por tanto se lea una sola vez por cambio
    /// en vez de una vez por endpoint.
    propias: BTreeSet<IpAddr>,
}

/// Capa que descarta trafico ENTRANTE de una direccion.
pub trait BloqueoEntrante {
    /// Empieza a descartar lo que venga de esa direccion.
    fn bloquear(&self, addr: Ipv4Addr, ttl: Option<Duration>) -> Result<(), String>;
    /// Deja de descartarlo.
    fn desbloquear(&self, addr: Ipv4Addr) -> Result<(), String>;
}

/// Capa que descarta trafico SALIENTE hacia una direccion.
pub trait BloqueoSaliente {
    /// Empieza a descartar lo que vaya a esa direccion.
    fn bloquear(&self, addr: IpAddr, ttl: Option<Duration>) -> Result<(), String>;
    /// Deja de descartarlo.
    fn desbloquear(&self, addr: IpAddr) -> Result<(), String>;
}

// Las dos capas suelen pertenecer a otro: el filtro XDP lo posee el agente y
// vive mas que cualquier reconciliacion. Estas implementaciones permiten pasar
// una referencia sin obligar a mover la capa dentro del segmentador ni a
// envolverla en un Arc solo por satisfacer al sistema de tipos.
impl<T: BloqueoEntrante + ?Sized> BloqueoEntrante for &T {
    fn bloquear(&self, addr: Ipv4Addr, ttl: Option<Duration>) -> Result<(), String> {
        (**self).bloquear(addr, ttl)
    }
    fn desbloquear(&self, addr: Ipv4Addr) -> Result<(), String> {
        (**self).desbloquear(addr)
    }
}

impl<T: BloqueoSaliente + ?Sized> BloqueoSaliente for &T {
    fn bloquear(&self, addr: IpAddr, ttl: Option<Duration>) -> Result<(), String> {
        (**self).bloquear(addr, ttl)
    }
    fn desbloquear(&self, addr: IpAddr) -> Result<(), String> {
        (**self).desbloquear(addr)
    }
}

impl<E: BloqueoEntrante, S: BloqueoSaliente> Segmentador<E, S> {
    /// Crea un segmentador sobre las dos capas.
    pub fn nuevo(entrante: E, saliente: S) -> Segmentador<E, S> {
        Segmentador {
            entrante,
            saliente,
            aplicadas: BTreeSet::new(),
            propias: BTreeSet::new(),
        }
    }

    /// Declara las direcciones de esta maquina, que nunca se bloquearan.
    pub fn con_propias(mut self, propias: &[IpAddr]) -> Segmentador<E, S> {
        self.propias = propias.iter().copied().collect();
        self
    }

    /// Direcciones que este endpoint cree tener en cuarentena.
    pub fn aplicadas(&self) -> Vec<IpAddr> {
        self.aplicadas.iter().copied().collect()
    }

    /// Lleva el kernel al conjunto que ordena el plano de control.
    ///
    /// Recibe el conjunto COMPLETO vigente, no un incremento. Con incrementos,
    /// un mensaje perdido dejaria al endpoint con una regla que nadie recuerda
    /// haber puesto —o sin una que creemos puesta—, y la unica forma de saberlo
    /// seria auditar maquina por maquina. Con el conjunto completo, cada empuje
    /// deja al endpoint en un estado conocido.
    pub fn reconciliar(&mut self, deseadas: &[IpAddr], ttl: Option<Duration>) -> Reconciliacion {
        // Las propias se descartan ANTES de nada. Ni se aplican, ni cuentan
        // como fallo: no aplicarlas es la conducta correcta, no un problema.
        let deseadas: BTreeSet<IpAddr> = deseadas
            .iter()
            .copied()
            .filter(|d| !self.propias.contains(d))
            .collect();
        let mut r = Reconciliacion::default();

        // --- Retirar lo que ya no esta en la orden ---
        //
        // Se hace ANTES de anadir: si el kernel tuviera un limite de entradas y
        // se anadiera primero, una cuarentena que sustituye a otra podria
        // rebotar por falta de sitio cuando en realidad hay hueco de sobra.
        for addr in self.aplicadas.clone().difference(&deseadas) {
            let e = self.retirar(*addr);
            if e {
                r.retiradas.push(*addr);
                self.aplicadas.remove(addr);
            }
            // Si no se pudo retirar, se deja en `aplicadas`: seguira
            // intentandose en la siguiente reconciliacion. Olvidarla haria que
            // el endpoint creyera que la maquina tiene red cuando no la tiene.
        }

        // --- Anadir lo nuevo ---
        for addr in deseadas.difference(&self.aplicadas.clone()) {
            let ent = match addr {
                IpAddr::V4(v4) => self.entrante.bloquear(*v4, ttl).is_ok(),
                // El filtro XDP indexa por IPv4. Una direccion IPv6 no puede
                // bloquearse ahi, y decirlo es mejor que fingir que se hizo.
                IpAddr::V6(_) => false,
            };
            let sal = self.saliente.bloquear(*addr, ttl).is_ok();

            match (ent, sal) {
                (true, true) => {
                    r.anadidas.push(*addr);
                    self.aplicadas.insert(*addr);
                }
                (true, false) => {
                    r.solo_entrante.push(*addr);
                    self.aplicadas.insert(*addr);
                }
                (false, true) => {
                    r.solo_saliente.push(*addr);
                    self.aplicadas.insert(*addr);
                }
                (false, false) => r.fallidas.push(*addr),
            }
        }
        r
    }

    /// Retira una direccion de las dos capas.
    ///
    /// Solo se considera retirada si las DOS lo confirman: dejar media regla
    /// puesta es lo que produce una maquina que "a veces" tiene red.
    fn retirar(&self, addr: IpAddr) -> bool {
        let ent = match addr {
            IpAddr::V4(v4) => self.entrante.desbloquear(v4).is_ok(),
            IpAddr::V6(_) => true, // nunca se aplico en XDP
        };
        let sal = self.saliente.desbloquear(addr).is_ok();
        ent && sal
    }
}

/// Analiza la lista de direcciones que viene en el empuje del plano de control.
///
/// Las direcciones que no se entienden se DESCARTAN y se cuentan aparte, en vez
/// de abortar la lista entera: una entrada corrupta no puede impedir que se
/// apliquen las demas, porque las demas son contencion de un incidente en
/// curso.
pub fn analizar_lista(texto: &str) -> (Vec<IpAddr>, usize) {
    let mut salida = Vec::new();
    let mut invalidas = 0;
    for parte in texto.split(',') {
        let t = parte.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<IpAddr>() {
            Ok(ip) => salida.push(ip),
            Err(_) => invalidas += 1,
        }
    }
    (salida, invalidas)
}

/// Adaptador del bloqueador de nftables de `aegis-scal` a la capa de salida.
pub struct SalidaNftables<'a, B: NetworkFilter>(pub &'a B);

impl<B: NetworkFilter> BloqueoSaliente for SalidaNftables<'_, B> {
    fn bloquear(&self, addr: IpAddr, ttl: Option<Duration>) -> Result<(), String> {
        self.0
            .block(addr, MotivoNft::Manual, ttl)
            .map_err(|e| e.to_string())
    }

    fn desbloquear(&self, addr: IpAddr) -> Result<(), String> {
        self.0.unblock(addr).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet as Conjunto;

    /// Capa de prueba que registra lo que se le pide y puede fallar a voluntad.
    ///
    /// No sustituye al kernel: sustituye a la capa cuyo comportamiento ya se
    /// prueba en su propio modulo. Lo que se ejercita aqui es la RECONCILIACION
    /// —que es donde estan los errores interesantes— y los casos de fallo
    /// parcial, que con un kernel real no se pueden provocar a voluntad.
    #[derive(Default)]
    struct Capa {
        puestas: RefCell<Conjunto<IpAddr>>,
        falla_al_poner: bool,
        falla_al_quitar: bool,
    }

    impl BloqueoEntrante for Capa {
        fn bloquear(&self, addr: Ipv4Addr, _ttl: Option<Duration>) -> Result<(), String> {
            if self.falla_al_poner {
                return Err("sin privilegios".into());
            }
            self.puestas.borrow_mut().insert(IpAddr::V4(addr));
            Ok(())
        }
        fn desbloquear(&self, addr: Ipv4Addr) -> Result<(), String> {
            if self.falla_al_quitar {
                return Err("sin privilegios".into());
            }
            self.puestas.borrow_mut().remove(&IpAddr::V4(addr));
            Ok(())
        }
    }

    impl BloqueoSaliente for Capa {
        fn bloquear(&self, addr: IpAddr, _ttl: Option<Duration>) -> Result<(), String> {
            if self.falla_al_poner {
                return Err("sin privilegios".into());
            }
            self.puestas.borrow_mut().insert(addr);
            Ok(())
        }
        fn desbloquear(&self, addr: IpAddr) -> Result<(), String> {
            if self.falla_al_quitar {
                return Err("sin privilegios".into());
            }
            self.puestas.borrow_mut().remove(&addr);
            Ok(())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn una_direccion_nueva_se_bloquea_en_los_dos_sentidos() {
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default());
        let r = seg.reconciliar(&[ip("10.0.0.5")], None);

        assert_eq!(r.anadidas, vec![ip("10.0.0.5")]);
        assert!(
            r.completa(),
            "tiene que quedar aplicada en los dos sentidos"
        );
        assert!(seg.entrante.puestas.borrow().contains(&ip("10.0.0.5")));
        assert!(seg.saliente.puestas.borrow().contains(&ip("10.0.0.5")));
    }

    #[test]
    fn reconciliar_es_idempotente() {
        // El plano de control reenvia el conjunto completo en cada empuje. Si
        // cada empuje reaplicara todo, un endpoint pagaria una escritura al
        // kernel por cada latido del canal.
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default());
        let uno = seg.reconciliar(&[ip("10.0.0.5")], None);
        let dos = seg.reconciliar(&[ip("10.0.0.5")], None);

        assert_eq!(uno.anadidas.len(), 1);
        assert!(dos.anadidas.is_empty(), "la segunda vez no anade nada");
        assert!(dos.retiradas.is_empty());
    }

    #[test]
    fn una_direccion_que_desaparece_de_la_orden_se_retira() {
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default());
        seg.reconciliar(&[ip("10.0.0.5"), ip("10.0.0.6")], None);
        let r = seg.reconciliar(&[ip("10.0.0.6")], None);

        assert_eq!(r.retiradas, vec![ip("10.0.0.5")]);
        assert_eq!(seg.aplicadas(), vec![ip("10.0.0.6")]);
        assert!(!seg.entrante.puestas.borrow().contains(&ip("10.0.0.5")));
        assert!(!seg.saliente.puestas.borrow().contains(&ip("10.0.0.5")));
    }

    #[test]
    fn una_lista_vacia_levanta_toda_la_cuarentena() {
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default());
        seg.reconciliar(&[ip("10.0.0.5"), ip("10.0.0.6")], None);
        let r = seg.reconciliar(&[], None);

        assert_eq!(r.retiradas.len(), 2);
        assert!(seg.aplicadas().is_empty());
    }

    #[test]
    fn si_solo_funciona_una_capa_se_dice_cual() {
        // Media contencion es peor que ninguna si nadie sabe que es media.
        let mut seg = Segmentador::nuevo(
            Capa::default(),
            Capa {
                falla_al_poner: true,
                ..Default::default()
            },
        );
        let r = seg.reconciliar(&[ip("10.0.0.5")], None);

        assert!(r.anadidas.is_empty());
        assert_eq!(r.solo_entrante, vec![ip("10.0.0.5")]);
        assert!(!r.completa(), "no puede darse por completa");
    }

    #[test]
    fn si_no_funciona_ninguna_capa_la_direccion_no_se_da_por_aplicada() {
        let mut seg = Segmentador::nuevo(
            Capa {
                falla_al_poner: true,
                ..Default::default()
            },
            Capa {
                falla_al_poner: true,
                ..Default::default()
            },
        );
        let r = seg.reconciliar(&[ip("10.0.0.5")], None);

        assert_eq!(r.fallidas, vec![ip("10.0.0.5")]);
        assert!(
            seg.aplicadas().is_empty(),
            "no puede creerse aplicada algo que fallo en las dos capas"
        );
    }

    #[test]
    fn una_retirada_que_falla_no_se_olvida() {
        // Olvidarla haria que el endpoint creyera que esa maquina tiene red
        // cuando en realidad sigue bloqueada: una maquina sana sin red y nadie
        // sabiendo por que.
        let mut seg = Segmentador::nuevo(
            Capa::default(),
            Capa {
                falla_al_quitar: true,
                ..Default::default()
            },
        );
        seg.reconciliar(&[ip("10.0.0.5")], None);
        let r = seg.reconciliar(&[], None);

        assert!(r.retiradas.is_empty());
        assert_eq!(
            seg.aplicadas(),
            vec![ip("10.0.0.5")],
            "sigue en la lista para reintentarlo"
        );
    }

    #[test]
    fn una_direccion_ipv6_solo_puede_bloquearse_en_salida() {
        // XDP indexa por IPv4. Fingir que se bloqueo seria vender una
        // contencion que no existe.
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default());
        let r = seg.reconciliar(&[ip("2001:db8::5")], None);

        assert!(r.anadidas.is_empty());
        assert_eq!(r.solo_saliente, vec![ip("2001:db8::5")]);
        assert!(!r.completa());
    }

    #[test]
    fn un_endpoint_nunca_se_bloquea_a_si_mismo() {
        // Bloquearse a si mismo deja al endpoint sin plano de control: sin poder
        // recibir siquiera la orden de que la cuarentena se levanto. A partir de
        // ahi solo se recupera yendo fisicamente a la maquina.
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default())
            .con_propias(&[ip("10.0.0.5"), ip("192.168.1.5")]);

        let r = seg.reconciliar(&[ip("10.0.0.5"), ip("10.0.0.9")], None);

        assert_eq!(r.anadidas, vec![ip("10.0.0.9")], "solo la ajena");
        assert!(r.fallidas.is_empty(), "saltarse la propia no es un fallo");
        assert!(!seg.entrante.puestas.borrow().contains(&ip("10.0.0.5")));
        assert!(!seg.saliente.puestas.borrow().contains(&ip("10.0.0.5")));
    }

    #[test]
    fn se_protegen_todas_las_direcciones_de_la_maquina_no_solo_una() {
        // El servidor solo conoce la direccion que vio en el handshake. Una
        // maquina tiene varias —dos interfaces, una VPN, una IP flotante— y la
        // cuarentena puede caer sobre cualquiera de las otras.
        let mut seg = Segmentador::nuevo(Capa::default(), Capa::default()).con_propias(&[
            ip("10.0.0.5"),
            ip("172.16.0.5"),
            ip("192.168.1.5"),
        ]);

        let r = seg.reconciliar(&[ip("172.16.0.5"), ip("192.168.1.5")], None);
        assert!(r.anadidas.is_empty());
        assert!(seg.aplicadas().is_empty());
    }

    #[test]
    fn una_entrada_corrupta_no_impide_aplicar_las_demas() {
        let (ips, malas) = analizar_lista("10.0.0.5, no-es-una-ip ,10.0.0.6,");
        assert_eq!(ips, vec![ip("10.0.0.5"), ip("10.0.0.6")]);
        assert_eq!(malas, 1);
    }

    #[test]
    fn una_lista_vacia_se_analiza_como_vacia_y_no_como_error() {
        let (ips, malas) = analizar_lista("");
        assert!(ips.is_empty());
        assert_eq!(malas, 0);
    }
}
