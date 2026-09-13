//! La tabla de flujos: acotada, con expulsion, y que dice lo que tira.
//!
//! # Por que la cota es lo primero y no lo ultimo
//!
//! Quien decide cuantos flujos existen es **el atacante**: abrir un millon de
//! conexiones a medias es trivial y es, literalmente, el ataque SYN de toda la
//! vida. Una tabla de flujos sin cota convierte al sensor en la victima, y ese
//! fallo tiene una propiedad especialmente mala: cuando el sensor muere, el
//! atacante deja de ser observado justo cuando mas se le estaba mirando.
//!
//! Por eso aqui el orden es: cota, expulsion, y CONTAR lo expulsado. Un flujo
//! que se tira sin contarlo es un agujero de visibilidad que nadie sabe que
//! tiene.
//!
//! # A quien se expulsa
//!
//! Al que lleva mas tiempo sin actividad. No al mas antiguo: un flujo largo y
//! activo —una sesion SSH de tres horas, una transferencia grande— es
//! exactamente el que MAS interesa seguir viendo, y expulsarlo por viejo seria
//! elegir el peor candidato posible.
//!
//! # Dos cotas, porque una sola no acota nada
//!
//! Contar flujos NO acota la memoria. Cada flujo tiene su propia cota de
//! reensamblado, pero el producto de las dos es lo que se reserva de verdad:
//! cien mil flujos por dos sentidos por un mega retenido son doscientos gigas,
//! en un agente cuyo presupuesto entero son cuarenta y cinco megas. Una cota por
//! flujo sin cota global es una cota que TRANQUILIZA sin proteger, y el atacante
//! elige los dos factores.
//!
//! Por eso hay dos topes independientes —numero de flujos y BYTES totales— y los
//! dos expulsan. El de bytes es el que de verdad sostiene el presupuesto.

use std::collections::BTreeMap;

use crate::hecho::{ClaveFlujo, Direccion, ProtocoloApp, Transporte};
use crate::reensamblado::{Politica, Sentido};

/// Tope de flujos seguidos a la vez.
///
/// Cien mil flujos cubren cualquier endpoint real. Este tope acota el numero de
/// conversaciones seguidas, NO la memoria: de eso se ocupa [`MAX_MEMORIA`].
pub const MAX_FLUJOS: usize = 100_000;

/// Tope de bytes reservados por TODOS los reensamblados a la vez.
///
/// # De donde sale el numero
///
/// Es el caso de la estacion tipica: la cuota de red de un host de 16 GiB son
/// 12 MiB, de los que dos tercios van al reensamblado. Con esto, el peor caso
/// real deja de ser el producto de las cotas por flujo y pasa a ser este numero,
/// que es el que se puede defender.
///
/// En el agente **no se usa esta constante**: se usa
/// [`crate::motor::ConfigMotor::para_presupuesto`], que pide la cuota al host.
/// Una pasarela de 1 GiB no puede gastar ocho megas aqui, y un servidor de
/// 768 GiB no tiene por que quedarse en ellos —cada flujo que expulsa por falta
/// de sitio es un trozo de conversacion que deja de ver.
///
/// Cuando se llega al tope se expulsa por inactividad igual que por falta de
/// sitio, y se CUENTA: ver caer este contador es ver al sensor quedarse ciego.
pub const MAX_MEMORIA: usize = 8 * 1024 * 1024;

/// Inactividad tras la cual un flujo TCP se da por muerto, en microsegundos.
pub const EXPIRACION_TCP_US: u64 = 300 * 1_000_000;

/// Inactividad tras la cual un flujo UDP se da por muerto.
///
/// Mucho mas corta que la de TCP porque UDP no tiene cierre: un flujo UDP
/// «abierto» solo significa que se vio un datagrama, y mantenerlo cinco minutos
/// llenaria la tabla de conversaciones DNS de un segundo.
pub const EXPIRACION_UDP_US: u64 = 60 * 1_000_000;

/// Contadores de la tabla.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContadoresTabla {
    /// Flujos creados en total.
    pub creados: u64,
    /// Flujos expulsados por falta de sitio.
    ///
    /// Este numero es un agujero de visibilidad medido: si crece, el sensor esta
    /// dejando de ver cosas y hay que saberlo.
    pub expulsados_por_sitio: u64,
    /// Flujos expulsados por llegar al techo de memoria.
    ///
    /// Se cuenta aparte de `expulsados_por_sitio` porque la causa es distinta y
    /// la respuesta tambien: llenar la tabla de flujos vacios es un ataque de
    /// apertura masiva; llenar la memoria con pocos flujos es un ataque de
    /// retencion, y se corrige con otro tope.
    pub expulsados_por_memoria: u64,
    /// Flujos cerrados por expiracion.
    pub expirados: u64,
    /// Flujos cerrados limpiamente (FIN o RST).
    pub cerrados: u64,
}

/// El estado de un flujo mientras vive.
#[derive(Debug, Clone)]
pub struct Flujo {
    /// Su clave normalizada.
    pub clave: ClaveFlujo,
    /// Protocolo de aplicacion, cuando se identifique.
    pub protocolo: ProtocoloApp,
    /// Primer momento observado, en microsegundos.
    pub inicio_us: u64,
    /// Ultimo momento observado.
    pub ultimo_us: u64,
    /// Bytes vistos de `a` hacia `b`.
    pub bytes_ab: u64,
    /// Bytes vistos de `b` hacia `a`.
    pub bytes_ba: u64,
    /// Paquetes de `a` hacia `b`.
    pub paquetes_ab: u64,
    /// Paquetes de `b` hacia `a`.
    pub paquetes_ba: u64,
    /// Si se vio el SYN y por tanto se sabe quien abrio.
    pub inicio_visto: bool,
    /// Quien es el cliente: `true` si es el extremo `a`.
    pub cliente_es_a: bool,
    /// Reensamblado del sentido `a` → `b` (solo TCP).
    pub sentido_ab: Sentido,
    /// Reensamblado del sentido `b` → `a` (solo TCP).
    pub sentido_ba: Sentido,
    /// Estado opaco del disector de aplicacion, si lo hay.
    pub estado_app: EstadoApp,
}

/// Estado que un disector de aplicacion necesita conservar entre paquetes.
///
/// Es un enumerado y no un objeto dinamico a proposito: el conjunto de
/// protocolos es cerrado y conocido, y un `Box<dyn ...>` por flujo son cien mil
/// reservas de memoria que no hacen falta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EstadoApp {
    /// Aun no se identifico el protocolo.
    #[default]
    Ninguno,
    /// HTTP: puede haber una respuesta a medias cuyo cuerpo sigue llegando.
    Http {
        /// Bytes de cuerpo que faltan por leer.
        cuerpo_pendiente: u64,
        /// Si el cuerpo viene por trozos.
        por_trozos: bool,
    },
    /// TLS: el handshake puede venir repartido en varios registros.
    Tls {
        /// Si ya se vio el saludo del cliente.
        cliente_visto: bool,
        /// Si ya se vio el del servidor.
        servidor_visto: bool,
    },
}

impl Flujo {
    /// Un flujo nuevo.
    #[must_use]
    pub fn nuevo(clave: ClaveFlujo, momento_us: u64, politica: Politica) -> Flujo {
        Flujo {
            clave,
            protocolo: ProtocoloApp::Desconocido,
            inicio_us: momento_us,
            ultimo_us: momento_us,
            bytes_ab: 0,
            bytes_ba: 0,
            paquetes_ab: 0,
            paquetes_ba: 0,
            inicio_visto: false,
            cliente_es_a: true,
            sentido_ab: Sentido::nuevo(politica),
            sentido_ba: Sentido::nuevo(politica),
            estado_app: EstadoApp::Ninguno,
        }
    }

    /// Duracion observada, en microsegundos.
    #[must_use]
    pub fn duracion_us(&self) -> u64 {
        self.ultimo_us.saturating_sub(self.inicio_us)
    }

    /// Bytes totales.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes_ab.saturating_add(self.bytes_ba)
    }

    /// Traduce «del extremo `a`» a «del cliente», sabiendo quien abrio.
    ///
    /// Si no se vio el inicio, se dice [`Direccion::Indeterminada`] en vez de
    /// adivinar. Adivinar por numero de puerto acierta casi siempre y falla
    /// justo en el trafico raro, que es el que interesa.
    #[must_use]
    pub fn direccion_de(&self, desde_a: bool) -> Direccion {
        if !self.inicio_visto {
            return Direccion::Indeterminada;
        }
        if desde_a == self.cliente_es_a {
            Direccion::ClienteAServidor
        } else {
            Direccion::ServidorACliente
        }
    }

    /// Si el flujo ya deberia darse por muerto.
    #[must_use]
    pub fn expirado(&self, ahora_us: u64) -> bool {
        let inactivo = ahora_us.saturating_sub(self.ultimo_us);
        let tope = match self.clave.transporte {
            Transporte::Tcp => EXPIRACION_TCP_US,
            Transporte::Udp | Transporte::Icmp => EXPIRACION_UDP_US,
        };
        inactivo > tope
    }

    /// Si los dos sentidos estan cerrados.
    #[must_use]
    pub fn terminado(&self) -> bool {
        self.sentido_ab.cerrado() && self.sentido_ba.cerrado()
    }

    /// Bytes que este flujo tiene reservados en sus dos reensambladores.
    #[must_use]
    pub fn memoria(&self) -> usize {
        self.sentido_ab.memoria() + self.sentido_ba.memoria()
    }
}

/// La tabla de flujos.
pub struct TablaFlujos {
    flujos: BTreeMap<ClaveFlujo, Flujo>,
    politica: Politica,
    max: usize,
    max_bytes: usize,
    /// Bytes reservados AHORA por los reensamblados de todos los flujos.
    ///
    /// Se lleva incrementalmente y no recorriendo la tabla: recorrer cien mil
    /// flujos por paquete convertiria la propia cota en el ataque.
    bytes: usize,
    /// Claves expulsadas desde la ultima vez que se pregunto.
    ///
    /// Existen porque quien expulsa es la tabla, pero los recursos asociados a
    /// un flujo —el bufer de aplicacion del motor, por ejemplo— viven fuera de
    /// ella. Sin avisar de la expulsion esos recursos se quedan huerfanos para
    /// siempre: no es un peor caso teorico, es una fuga.
    expulsadas: Vec<ClaveFlujo>,
    contadores: ContadoresTabla,
}

impl TablaFlujos {
    /// Una tabla con los topes por defecto.
    #[must_use]
    pub fn nueva(politica: Politica) -> TablaFlujos {
        TablaFlujos::con_tope(politica, MAX_FLUJOS)
    }

    /// Una tabla con un tope de flujos explicito y el de memoria por defecto.
    ///
    /// Un tope de cero no tiene sentido y se sube a uno: una tabla que no puede
    /// guardar ningun flujo no protege, y aceptarlo en silencio convertiria un
    /// error de configuracion en ceguera total.
    #[must_use]
    pub fn con_tope(politica: Politica, max: usize) -> TablaFlujos {
        TablaFlujos::con_topes(politica, max, MAX_MEMORIA)
    }

    /// Una tabla con los dos topes explicitos.
    #[must_use]
    pub fn con_topes(politica: Politica, max: usize, max_bytes: usize) -> TablaFlujos {
        TablaFlujos {
            flujos: BTreeMap::new(),
            politica,
            max: max.max(1),
            max_bytes,
            bytes: 0,
            expulsadas: Vec::new(),
            contadores: ContadoresTabla::default(),
        }
    }

    /// Entrega las claves expulsadas desde la ultima llamada y las olvida.
    ///
    /// El llamante DEBE usarlas para soltar lo que tenga asociado a esos flujos.
    /// La lista se vacia al leerla para que no crezca sola.
    pub fn drenar_expulsadas(&mut self) -> Vec<ClaveFlujo> {
        std::mem::take(&mut self.expulsadas)
    }

    /// Flujos vivos.
    #[must_use]
    pub fn vivos(&self) -> usize {
        self.flujos.len()
    }

    /// Bytes reservados ahora mismo por los reensamblados.
    #[must_use]
    pub fn bytes_reservados(&self) -> usize {
        self.bytes
    }

    /// Contadores.
    #[must_use]
    pub fn contadores(&self) -> &ContadoresTabla {
        &self.contadores
    }

    /// Consulta un flujo.
    #[must_use]
    pub fn obtener(&self, clave: &ClaveFlujo) -> Option<&Flujo> {
        self.flujos.get(clave)
    }

    /// Opera sobre el flujo de una clave, creandolo si no existe.
    ///
    /// # Por que es un ambito cerrado y no un `&mut Flujo` suelto
    ///
    /// La contabilidad de memoria se lleva incrementalmente, asi que hay que
    /// medir ANTES y DESPUES de cada cambio. Entregar una referencia mutable
    /// suelta dejaria que el llamante retuviera megabytes sin que la tabla se
    /// enterara, y una contabilidad que se puede olvidar de actualizar se acaba
    /// olvidando. Cerrando el ambito, la cuenta no puede descuadrar.
    pub fn con_flujo<R>(
        &mut self,
        clave: ClaveFlujo,
        momento_us: u64,
        accion: impl FnOnce(&mut Flujo) -> R,
    ) -> R {
        let flujo = self.obtener_o_crear(clave, momento_us);
        let antes = flujo.memoria();
        let salida = accion(flujo);
        let despues = flujo.memoria();
        self.recontar(antes, despues);
        self.aplicar_techo_de_memoria(clave);
        salida
    }

    /// Ajusta el total reservado tras un cambio en un flujo.
    fn recontar(&mut self, antes: usize, despues: usize) {
        // Se hace con saturacion en los dos sentidos: un descuadre nunca puede
        // convertirse en un desbordamiento que reviente el sensor.
        if despues >= antes {
            self.bytes = self.bytes.saturating_add(despues - antes);
        } else {
            self.bytes = self.bytes.saturating_sub(antes - despues);
        }
    }

    /// Expulsa flujos inactivos hasta volver por debajo del techo de memoria.
    ///
    /// Nunca expulsa el flujo que se acaba de tocar: tirar justo el que esta
    /// activo dejaria al sensor girando en vacio sin analizar nada.
    fn aplicar_techo_de_memoria(&mut self, protegido: ClaveFlujo) {
        while self.bytes > self.max_bytes {
            let victima = self
                .flujos
                .iter()
                .filter(|(k, _)| **k != protegido)
                .min_by_key(|(_, f)| f.ultimo_us)
                .map(|(k, _)| *k);
            let Some(k) = victima else {
                // Solo queda el flujo protegido. Su propia cota por flujo ya lo
                // limita; seguir buscando victimas seria un bucle infinito.
                break;
            };
            if let Some(f) = self.flujos.remove(&k) {
                let suyos = f.memoria();
                self.bytes = self.bytes.saturating_sub(suyos);
                self.contadores.expulsados_por_memoria += 1;
                self.expulsadas.push(k);
            }
        }
    }

    /// Recupera o crea el flujo de una clave, expulsando si hace falta.
    ///
    /// Privado a proposito: ver [`TablaFlujos::con_flujo`].
    fn obtener_o_crear(&mut self, clave: ClaveFlujo, momento_us: u64) -> &mut Flujo {
        if !self.flujos.contains_key(&clave) {
            if self.flujos.len() >= self.max {
                self.expulsar_el_mas_inactivo();
            }
            self.contadores.creados += 1;
            self.flujos
                .insert(clave, Flujo::nuevo(clave, momento_us, self.politica));
        }
        let f = self
            .flujos
            .get_mut(&clave)
            .expect("se acaba de insertar si no estaba");
        f.ultimo_us = f.ultimo_us.max(momento_us);
        f
    }

    /// Expulsa el flujo que lleva mas tiempo sin actividad.
    ///
    /// El mas INACTIVO, no el mas antiguo: una sesion SSH de tres horas que
    /// sigue viva es justo la que mas interesa seguir viendo.
    fn expulsar_el_mas_inactivo(&mut self) {
        let victima = self
            .flujos
            .iter()
            .min_by_key(|(_, f)| f.ultimo_us)
            .map(|(k, _)| *k);
        if let Some(k) = victima {
            if let Some(f) = self.flujos.remove(&k) {
                let suyos = f.memoria();
                self.bytes = self.bytes.saturating_sub(suyos);
            }
            self.contadores.expulsados_por_sitio += 1;
            self.expulsadas.push(k);
        }
    }

    /// Cierra y devuelve los flujos expirados o terminados.
    ///
    /// Devolverlos en vez de tirarlos permite emitir su registro de conexion:
    /// un flujo que muere sin dejar registro es trafico que ocurrio y que nadie
    /// puede consultar despues.
    pub fn recolectar(&mut self, ahora_us: u64) -> Vec<Flujo> {
        let muertos: Vec<ClaveFlujo> = self
            .flujos
            .iter()
            .filter(|(_, f)| f.expirado(ahora_us) || f.terminado())
            .map(|(k, _)| *k)
            .collect();
        let mut salida = Vec::with_capacity(muertos.len());
        for k in muertos {
            if let Some(f) = self.flujos.remove(&k) {
                let suyos = f.memoria();
                self.bytes = self.bytes.saturating_sub(suyos);
                if f.terminado() {
                    self.contadores.cerrados += 1;
                } else {
                    self.contadores.expirados += 1;
                }
                salida.push(f);
            }
        }
        salida
    }

    /// Vacia la tabla y devuelve todo lo que quedaba.
    pub fn vaciar(&mut self) -> Vec<Flujo> {
        let salida: Vec<Flujo> = self.flujos.values().cloned().collect();
        self.flujos.clear();
        self.bytes = 0;
        salida
    }
}

#[cfg(test)]
mod pruebas {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn clave(puerto: u16) -> ClaveFlujo {
        let (k, _) = ClaveFlujo::normalizada(
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), puerto),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
            Transporte::Tcp,
        );
        k
    }

    /// LA COTA: un millon de flujos no puede tumbar al sensor. Y lo que se tira
    /// se CUENTA, porque un flujo tirado en silencio es un agujero de
    /// visibilidad que nadie sabe que tiene.
    #[test]
    fn abrir_flujos_sin_parar_no_hace_crecer_la_tabla_sin_limite() {
        let mut t = TablaFlujos::con_tope(Politica::PrimeroGana, 1000);
        for p in 1..50_000u32 {
            t.obtener_o_crear(clave((p % 65_535) as u16), u64::from(p));
        }
        assert!(t.vivos() <= 1000, "vivos = {}", t.vivos());
        assert!(
            t.contadores().expulsados_por_sitio > 0,
            "lo expulsado tiene que contarse"
        );
    }

    /// Se expulsa al MAS INACTIVO, no al mas antiguo: una sesion larga y activa
    /// es la que mas interesa conservar.
    #[test]
    fn se_expulsa_al_mas_inactivo_y_no_a_la_sesion_larga_activa() {
        let mut t = TablaFlujos::con_tope(Politica::PrimeroGana, 3);

        // Una sesion larga que sigue viva.
        let larga = clave(1000);
        t.obtener_o_crear(larga, 1);
        // Dos flujos que se quedan quietos.
        t.obtener_o_crear(clave(1001), 2);
        t.obtener_o_crear(clave(1002), 3);
        // La sesion larga tiene actividad reciente.
        t.obtener_o_crear(larga, 10_000);

        // Entra uno nuevo: hay que expulsar a alguien.
        t.obtener_o_crear(clave(1003), 10_001);

        assert!(
            t.obtener(&larga).is_some(),
            "la sesion activa NO puede ser la victima"
        );
    }

    #[test]
    fn un_flujo_udp_expira_mucho_antes_que_uno_tcp() {
        let (k_udp, _) = ClaveFlujo::normalizada(
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53),
            Transporte::Udp,
        );
        let udp = Flujo::nuevo(k_udp, 0, Politica::PrimeroGana);
        let tcp = Flujo::nuevo(clave(5000), 0, Politica::PrimeroGana);

        let t = EXPIRACION_UDP_US + 1;
        assert!(udp.expirado(t), "UDP no tiene cierre: expira pronto");
        assert!(!tcp.expirado(t), "TCP aguanta mas");
        assert!(tcp.expirado(EXPIRACION_TCP_US + 1));
    }

    /// Sin haber visto el inicio NO se adivina quien es el cliente. Adivinar por
    /// numero de puerto acierta casi siempre y falla justo en el trafico raro,
    /// que es el que interesa.
    #[test]
    fn sin_ver_el_inicio_la_direccion_es_indeterminada_y_no_se_adivina() {
        let mut f = Flujo::nuevo(clave(5000), 0, Politica::PrimeroGana);
        assert_eq!(f.direccion_de(true), Direccion::Indeterminada);
        assert_eq!(f.direccion_de(false), Direccion::Indeterminada);

        f.inicio_visto = true;
        f.cliente_es_a = true;
        assert_eq!(f.direccion_de(true), Direccion::ClienteAServidor);
        assert_eq!(f.direccion_de(false), Direccion::ServidorACliente);
    }

    /// Un flujo que muere tiene que salir para poder emitir su registro: si se
    /// tirara, seria trafico que ocurrio y que nadie puede consultar despues.
    #[test]
    fn los_flujos_muertos_salen_para_que_se_pueda_registrar_lo_que_paso() {
        let mut t = TablaFlujos::nueva(Politica::PrimeroGana);
        t.obtener_o_crear(clave(5000), 0);
        t.obtener_o_crear(clave(5001), 0);

        assert!(t.recolectar(100).is_empty(), "aun estan vivos");

        let muertos = t.recolectar(EXPIRACION_TCP_US + 1);
        assert_eq!(muertos.len(), 2);
        assert_eq!(t.vivos(), 0);
        assert_eq!(t.contadores().expirados, 2);
    }

    #[test]
    fn un_flujo_cerrado_limpiamente_se_distingue_de_uno_expirado() {
        let mut t = TablaFlujos::nueva(Politica::PrimeroGana);
        let k = clave(5000);
        let f = t.obtener_o_crear(k, 0);
        f.sentido_ab.cerrar();
        f.sentido_ba.cerrar();

        let muertos = t.recolectar(1);
        assert_eq!(muertos.len(), 1);
        assert_eq!(t.contadores().cerrados, 1);
        assert_eq!(t.contadores().expirados, 0);
    }

    #[test]
    fn un_tope_de_cero_se_corrige_porque_seria_ceguera_total() {
        let mut t = TablaFlujos::con_tope(Politica::PrimeroGana, 0);
        t.obtener_o_crear(clave(5000), 0);
        assert_eq!(t.vivos(), 1, "una tabla que no guarda nada no protege");
    }

    #[test]
    fn el_mismo_flujo_por_los_dos_sentidos_no_crea_dos_entradas() {
        let mut t = TablaFlujos::nueva(Politica::PrimeroGana);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (ida, _) = ClaveFlujo::normalizada((a, 5000), (b, 443), Transporte::Tcp);
        let (vuelta, _) = ClaveFlujo::normalizada((b, 443), (a, 5000), Transporte::Tcp);
        t.obtener_o_crear(ida, 0);
        t.obtener_o_crear(vuelta, 1);
        assert_eq!(t.vivos(), 1, "es UNA conversacion, no dos");
    }
}
