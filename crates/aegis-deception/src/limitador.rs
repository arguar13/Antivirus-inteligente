//! El limitador del senuelo: lo que impide que la trampa sea el arma.
//!
//! # Las dos formas en que un senuelo se vuelve contra su dueno
//!
//! **Como amplificador.** Un servicio que contesta mas de lo que le preguntan es
//! un multiplicador de trafico. Con un transporte sin conexion —UDP— el atacante
//! falsifica la direccion de origen, pone la de su victima, y el senuelo le manda
//! a ELLA la respuesta: el ataque sale de nuestra maquina. No es teorico; es
//! exactamente como se han usado NTP, DNS, memcached y **BACnet**, que es uno de
//! los protocolos industriales que este producto finge. Un senuelo que amplifica
//! convierte una herramienta de deteccion en un participante de una denegacion de
//! servicio contra un tercero, con nuestra direccion en los registros.
//!
//! **Como agotamiento.** Aunque no amplifique, un senuelo que atiende sin limite
//! deja que quien genere conexiones decida cuanta CPU y cuanta memoria gasta el
//! agente. La trampa se convierte en el camino para apagar la defensa.
//!
//! # Como se paran, y por que no con una opcion de configuracion
//!
//! La primera se para con una propiedad **estructural** que depende del
//! transporte:
//!
//! - En **UDP no hay saludo y la respuesta nunca es mayor que la pregunta**. El
//!   factor de amplificacion queda acotado por uno por construccion, asi que
//!   falsificar el origen no sirve de nada: lo que el atacante consigue mandar a
//!   su victima es, como mucho, lo que el mismo mando.
//! - En **TCP** la direccion de origen la verifica el saludo de tres vias, asi que
//!   la reflexion no aplica; ahi lo que se acota es el total absoluto, que es lo
//!   que para el agotamiento.
//!
//! Esa diferencia no es un detalle de implementacion: es la razon por la que la
//! misma regla no vale para los dos, y por la que aplicar la de UDP a TCP haria
//! imposible un dialogo creible —ningun servicio real contesta a un `USER pepe`
//! con menos bytes de los que recibio—.
//!
//! La segunda se para con cubos de fichas por origen y un total por segundo. El
//! reloj entra por parametro: este modulo no lo mira, igual que los disectores y
//! el capturador, y por eso se puede probar el agotamiento entero sin esperar.

/// Por donde llega la conversacion.
///
/// # Por que el transporte es parte del tipo y no una bandera
///
/// Porque decide la regla de amplificacion, y una bandera que decide una
/// propiedad de seguridad es una bandera que alguien pone mal. Al ir en el tipo,
/// un senuelo de UDP no puede construirse sin la regla de UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transporte {
    /// Con conexion: el saludo de tres vias verifica la direccion de origen.
    Tcp,
    /// Sin conexion: **cualquiera puede decir que es cualquiera**.
    Udp,
}

impl Transporte {
    /// Nombre corto para informes.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Transporte::Tcp => "tcp",
            Transporte::Udp => "udp",
        }
    }

    /// Si en este transporte el origen puede estar falsificado.
    ///
    /// Es lo mismo que preguntar si la respuesta puede acabar en una victima que
    /// no pidio nada, y por tanto si hace falta la cota de amplificacion.
    #[must_use]
    pub fn el_origen_puede_ser_falso(self) -> bool {
        matches!(self, Transporte::Udp)
    }
}

/// Cuantos bytes puede emitir un senuelo por segundo, en total.
///
/// No sale de una medida de rendimiento: sale de que un senuelo **no tiene por
/// que ir rapido**. Cada conexion ya es un incidente, y lo que interesa es
/// contarlo, no atender a mucha gente. Medio megabyte por segundo atiende de
/// sobra a un atacante humano y a un escaner, y no da para participar en nada.
pub const BYTES_POR_SEGUNDO: u64 = 512 * 1024;

/// Cuantos mensajes por segundo se atienden de un mismo origen.
pub const MENSAJES_POR_SEGUNDO_Y_ORIGEN: u32 = 50;

/// Cuantos origenes distintos se recuerdan a la vez.
///
/// Tiene techo por lo mismo que el indice de la FASE 90: una estructura que crece
/// con el numero de direcciones que escriba el atacante es una estructura que el
/// atacante hace crecer. Cuando se llena se desaloja al **mas viejo**, que aqui si
/// es lo correcto: lo que se pierde es la cuenta de un origen que lleva rato sin
/// hablar, y se le vuelve a abrir cubo si vuelve.
pub const ORIGENES_RECORDADOS: usize = 4096;

/// Por que no se contesto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorte {
    /// Se contesto entero.
    Nada,
    /// La respuesta se acorto para no ser mayor que la pregunta.
    ///
    /// Es la cota de amplificacion actuando. Que se cuente importa: si pasa mucho,
    /// el dialogo esta escrito de forma que no cabe en UDP y hay que arreglarlo,
    /// no subir el limite.
    PorAmplificacion,
    /// Este origen ha hablado demasiado en este segundo.
    PorRitmoDelOrigen,
    /// El senuelo ya ha emitido su cupo de bytes en este segundo.
    PorCupoTotal,
}

/// Lo que ha pasado por el limitador, contado.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cuentas {
    /// Mensajes entrantes.
    pub entrantes: u64,
    /// Bytes entrantes.
    pub bytes_entrantes: u64,
    /// Bytes emitidos.
    pub bytes_emitidos: u64,
    /// Respuestas acortadas por la cota de amplificacion.
    pub recortadas: u64,
    /// Mensajes no contestados por ritmo del origen.
    pub calladas_por_origen: u64,
    /// Mensajes no contestados por cupo total.
    pub calladas_por_cupo: u64,
    /// Origenes desalojados del recuerdo.
    pub origenes_olvidados: u64,
}

impl Cuentas {
    /// El factor de amplificacion medido: bytes emitidos entre bytes recibidos,
    /// en centesimas para no usar coma flotante.
    ///
    /// **Es LA cifra de esta invariante.** Por encima de 100 el senuelo devuelve
    /// mas de lo que le dan; en un transporte donde el origen puede ser falso,
    /// eso es un arma apuntando a un tercero.
    #[must_use]
    pub fn amplificacion_en_centesimas(&self) -> u64 {
        if self.bytes_entrantes == 0 {
            return if self.bytes_emitidos == 0 {
                0
            } else {
                u64::MAX
            };
        }
        (u128::from(self.bytes_emitidos) * 100 / u128::from(self.bytes_entrantes)) as u64
    }

    /// Como se cuenta en un informe.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "{} mensajes, {} bytes dentro, {} fuera (x{}.{:02}); {} recortadas, \
             {} calladas por ritmo, {} por cupo",
            self.entrantes,
            self.bytes_entrantes,
            self.bytes_emitidos,
            self.amplificacion_en_centesimas() / 100,
            self.amplificacion_en_centesimas() % 100,
            self.recortadas,
            self.calladas_por_origen,
            self.calladas_por_cupo
        )
    }
}

/// El cubo de fichas de un origen.
#[derive(Debug, Clone, Copy)]
struct Cubo {
    origen: u128,
    fichas: u32,
    segundo: u64,
    ultimo_ns: u64,
}

/// El limitador de una red de senuelos.
///
/// # Por que es UNO para todos y no uno por conversacion
///
/// Porque un cubo de fichas por conexion no limita nada: quien quiera pasarse
/// abre otra conexion y empieza con el cubo lleno. La primera version lo tenia
/// dentro de [`crate::dialogo::Conversacion`], y la prueba de autoataque lo
/// enseno — el ritmo por origen solo significa algo si sobrevive a que el origen
/// cuelgue y vuelva a llamar.
///
/// La cota de amplificacion si es de cada mensaje, porque compara una respuesta
/// con su pregunta, y esa la aplica la conversacion con el transporte de su
/// dialogo. Cada cosa donde tiene sentido.
///
/// Sans-IO: no mira el reloj. El instante entra por parametro en cada llamada,
/// que es lo que permite probar el agotamiento entero sin esperar y sin carreras.
#[derive(Debug, Default)]
pub struct Limitador {
    cubos: Vec<Cubo>,
    bytes_del_segundo: u64,
    segundo_actual: u64,
    cuentas: Cuentas,
}

impl Limitador {
    /// Un limitador nuevo, para toda la red de senuelos.
    #[must_use]
    pub fn nuevo() -> Limitador {
        Limitador::default()
    }

    /// Lo contado.
    #[must_use]
    pub fn cuentas(&self) -> Cuentas {
        self.cuentas
    }

    /// Cuantos origenes se recuerdan ahora mismo.
    #[must_use]
    pub fn origenes(&self) -> usize {
        self.cubos.len()
    }

    /// Filtra una respuesta.
    ///
    /// `transporte` es el del dialogo que contesta y decide si aplica la cota de
    /// amplificacion; `origen` identifica a quien pregunta (una IPv4 o IPv6 como
    /// entero), `ahora_ns` es el instante, `pregunta` lo que mando y `respuesta` lo
    /// que el dialogo quiere contestar. Devuelve lo que de verdad sale al cable,
    /// que puede ser menos, y el motivo.
    pub fn filtrar(
        &mut self,
        transporte: Transporte,
        origen: u128,
        ahora_ns: u64,
        pregunta: &[u8],
        respuesta: Vec<u8>,
    ) -> (Vec<u8>, Recorte) {
        let segundo = ahora_ns / 1_000_000_000;
        if segundo != self.segundo_actual {
            self.segundo_actual = segundo;
            self.bytes_del_segundo = 0;
        }
        self.cuentas.entrantes += 1;
        self.cuentas.bytes_entrantes += pregunta.len() as u64;

        if !self.hay_ficha(origen, segundo, ahora_ns) {
            self.cuentas.calladas_por_origen += 1;
            return (Vec::new(), Recorte::PorRitmoDelOrigen);
        }

        // La cota de amplificacion, que solo aplica donde el origen puede ser
        // falso. Ver la cabecera del modulo.
        let (mut salida, motivo) =
            if transporte.el_origen_puede_ser_falso() && respuesta.len() > pregunta.len() {
                let mut r = respuesta;
                r.truncate(pregunta.len());
                self.cuentas.recortadas += 1;
                (r, Recorte::PorAmplificacion)
            } else {
                (respuesta, Recorte::Nada)
            };

        let cupo = BYTES_POR_SEGUNDO.saturating_sub(self.bytes_del_segundo);
        if (salida.len() as u64) > cupo {
            salida.truncate(cupo as usize);
            self.cuentas.calladas_por_cupo += 1;
            self.bytes_del_segundo += salida.len() as u64;
            self.cuentas.bytes_emitidos += salida.len() as u64;
            return (salida, Recorte::PorCupoTotal);
        }

        self.bytes_del_segundo += salida.len() as u64;
        self.cuentas.bytes_emitidos += salida.len() as u64;
        (salida, motivo)
    }

    /// Si a este origen le queda ficha en este segundo, gastandola si la hay.
    fn hay_ficha(&mut self, origen: u128, segundo: u64, ahora_ns: u64) -> bool {
        if let Some(i) = self.cubos.iter().position(|c| c.origen == origen) {
            let c = &mut self.cubos[i];
            c.ultimo_ns = ahora_ns;
            if c.segundo != segundo {
                c.segundo = segundo;
                c.fichas = MENSAJES_POR_SEGUNDO_Y_ORIGEN;
            }
            if c.fichas == 0 {
                return false;
            }
            c.fichas -= 1;
            return true;
        }

        if self.cubos.len() >= ORIGENES_RECORDADOS {
            // Se olvida al que lleva mas rato callado. Aqui si es lo correcto
            // desalojar por antiguedad: lo que se pierde es la cuenta de quien ya
            // no habla, no la evidencia de nadie — la evidencia es la alerta, que
            // ya salio.
            if let Some(i) = self
                .cubos
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.ultimo_ns)
                .map(|(i, _)| i)
            {
                self.cubos.swap_remove(i);
                self.cuentas.origenes_olvidados += 1;
            }
        }
        self.cubos.push(Cubo {
            origen,
            fichas: MENSAJES_POR_SEGUNDO_Y_ORIGEN - 1,
            segundo,
            ultimo_ns: ahora_ns,
        });
        true
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn en_udp_la_respuesta_nunca_es_mayor_que_la_pregunta() {
        let mut l = Limitador::nuevo();
        let (salida, motivo) = l.filtrar(Transporte::Udp, 1, 0, b"corta", vec![b'X'; 5000]);
        assert_eq!(salida.len(), 5, "se recorto a la longitud de la pregunta");
        assert_eq!(motivo, Recorte::PorAmplificacion);
        assert!(l.cuentas().amplificacion_en_centesimas() <= 100);
    }

    #[test]
    fn en_tcp_se_puede_contestar_mas_porque_el_origen_esta_verificado() {
        let mut l = Limitador::nuevo();
        let (salida, motivo) = l.filtrar(Transporte::Tcp, 1, 0, b"GET /", vec![b'X'; 500]);
        assert_eq!(salida.len(), 500);
        assert_eq!(motivo, Recorte::Nada);
    }

    #[test]
    fn un_origen_que_grita_se_queda_sin_fichas_y_los_demas_no() {
        let mut l = Limitador::nuevo();
        for _ in 0..MENSAJES_POR_SEGUNDO_Y_ORIGEN {
            let (s, m) = l.filtrar(Transporte::Tcp, 7, 0, b"hola", b"adios".to_vec());
            assert_eq!(m, Recorte::Nada);
            assert!(!s.is_empty());
        }
        let (s, m) = l.filtrar(Transporte::Tcp, 7, 0, b"hola", b"adios".to_vec());
        assert!(s.is_empty());
        assert_eq!(m, Recorte::PorRitmoDelOrigen);

        // Y el vecino callado sigue teniendo servicio: el que inunda se limita a
        // si mismo, igual que en el indice de la FASE 90.
        let (s, m) = l.filtrar(Transporte::Tcp, 8, 0, b"hola", b"adios".to_vec());
        assert_eq!(m, Recorte::Nada);
        assert!(!s.is_empty());
    }

    #[test]
    fn las_fichas_vuelven_al_segundo_siguiente() {
        let mut l = Limitador::nuevo();
        for _ in 0..MENSAJES_POR_SEGUNDO_Y_ORIGEN {
            l.filtrar(Transporte::Tcp, 7, 0, b"hola", b"adios".to_vec());
        }
        assert_eq!(
            l.filtrar(Transporte::Tcp, 7, 0, b"h", b"a".to_vec()).1,
            Recorte::PorRitmoDelOrigen
        );
        assert_eq!(
            l.filtrar(Transporte::Tcp, 7, 1_000_000_000, b"h", b"a".to_vec())
                .1,
            Recorte::Nada
        );
    }

    #[test]
    fn el_cupo_total_acota_lo_que_sale_por_segundo() {
        let mut l = Limitador::nuevo();
        let grande = vec![b'X'; 64 * 1024];
        let mut emitido = 0u64;
        // Con muchos origenes distintos para no chocar con el limite por origen.
        for o in 0..200u128 {
            let (s, _) = l.filtrar(Transporte::Tcp, o, 0, b"x", grande.clone());
            emitido += s.len() as u64;
        }
        assert_eq!(emitido, BYTES_POR_SEGUNDO, "{}", l.cuentas().frase());
        assert!(l.cuentas().calladas_por_cupo > 0);
    }

    #[test]
    fn los_origenes_recordados_tienen_techo() {
        let mut l = Limitador::nuevo();
        for o in 0..(ORIGENES_RECORDADOS as u128 * 2) {
            l.filtrar(Transporte::Tcp, o, o as u64, b"x", b"y".to_vec());
            assert!(l.origenes() <= ORIGENES_RECORDADOS);
        }
        assert_eq!(l.origenes(), ORIGENES_RECORDADOS);
        assert!(l.cuentas().origenes_olvidados > 0);
    }

    #[test]
    fn la_amplificacion_sin_trafico_entrante_no_divide_entre_cero() {
        let l = Limitador::nuevo();
        assert_eq!(l.cuentas().amplificacion_en_centesimas(), 0);
    }

    #[test]
    fn el_mismo_limitador_sirve_a_transportes_distintos() {
        // La red tiene senuelos de los dos, y el cupo total es de la red entera.
        // La cota de amplificacion, en cambio, la decide el transporte de cada
        // mensaje: eso es lo que permite que un limitador compartido no relaje la
        // regla de UDP ni endurezca la de TCP.
        let mut l = Limitador::nuevo();
        let (udp, m1) = l.filtrar(Transporte::Udp, 1, 0, b"ocho byt", vec![b'X'; 100]);
        let (tcp, m2) = l.filtrar(Transporte::Tcp, 2, 0, b"ocho byt", vec![b'X'; 100]);
        assert_eq!(udp.len(), 8);
        assert_eq!(m1, Recorte::PorAmplificacion);
        assert_eq!(tcp.len(), 100);
        assert_eq!(m2, Recorte::Nada);
    }
}
