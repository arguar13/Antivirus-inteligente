//! Senuelos que **conversan**: varios turnos de protocolo, sin ejecutar nada.
//!
//! # Que significa aqui «alta interaccion», y que NO significa
//!
//! Un senuelo de baja interaccion acepta la conexion, manda un saludo y cierra.
//! Sirve para contar escaneos y poco mas: el atacante ve que el servicio no
//! responde a nada, lo descarta y se va. Lo que interesa —que herramienta usa, que
//! credenciales prueba, que hace cuando cree haber entrado— no llega a pasar.
//!
//! Un senuelo de alta interaccion **completa el protocolo**: negocia, acepta un
//! usuario, contesta a `LIST`, devuelve filas, responde a una lectura de registros
//! Modbus. El atacante avanza, y cada turno que avanza es informacion.
//!
//! Lo que aqui NO significa es lo que significa en un tarro de miel clasico:
//! **no hay sistema operativo detras, no se ejecuta nada y no se escribe nada**.
//! Cowrie y compania dan un interprete de ordenes de verdad sobre un sistema de
//! ficheros de verdad, y por eso son un riesgo por si mismos: un fallo en la
//! carcel deja al atacante dentro de una maquina real. Aqui un dialogo es una
//! **maquina de estados pura** que transforma bytes en bytes. No tiene forma de
//! ejecutar nada porque no hay nada que ejecutar, y eso no es una promesa de
//! configuracion: es lo que el tipo permite expresar.
//!
//! # Sans-IO, por tercera vez en el producto
//!
//! Como los disectores de la FASE 89 y el capturador de la FASE 90: un dialogo no
//! abre sockets, no mira el reloj y no toca el disco. Recibe bytes y devuelve
//! bytes. Es lo que permite probar los diecinueve senuelos, con entradas hostiles,
//! sin red, sin privilegios y sin condiciones de carrera — y es tambien la razon
//! por la que **la ausencia de ejecucion es comprobable**: no hay a donde
//! esconderla.
//!
//! # El techo de la conversacion
//!
//! Un dialogo tiene un numero maximo de turnos y un estado acotado. Sin eso,
//! quien hable con el senuelo decide cuanta memoria gasta el agente — la misma
//! invariante que el indice de la FASE 90, aplicada a una conversacion.

use crate::limitador::{Limitador, Recorte, Transporte};

/// Cuantos turnos como mucho dura una conversacion.
///
/// Diez son mas que suficientes para ver lo que interesa: quien entra prueba
/// credenciales, mira que hay y se va, y todo eso cabe de sobra. Lo que la cota
/// impide es que alguien se quede hablando para siempre y el senuelo le siga
/// guardando estado.
pub const MAX_TURNOS: u32 = 10;

/// Cuanto estado guarda una conversacion, como mucho.
pub const MAX_ESTADO: usize = 4096;

/// Lo que el senuelo hace con un mensaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paso {
    /// Contesta y sigue escuchando.
    Responde(Vec<u8>),
    /// Contesta y cierra: el protocolo acabo, o el cliente dijo algo que el
    /// servicio real no perdona.
    RespondeYCierra(Vec<u8>),
    /// Cierra sin contestar, que es lo que hace un servicio real ante basura.
    Cierra,
}

impl Paso {
    /// Los bytes que saldrian al cable.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Paso::Responde(v) | Paso::RespondeYCierra(v) => v,
            Paso::Cierra => &[],
        }
    }

    /// Si tras este paso se cierra.
    #[must_use]
    pub fn cierra(&self) -> bool {
        matches!(self, Paso::RespondeYCierra(_) | Paso::Cierra)
    }
}

/// Lo que el atacante revelo en un turno, ya interpretado.
///
/// **Es el producto del senuelo.** Una conexion dice «alguien esta mirando»; un
/// usuario y una contrasena dicen que credenciales tiene, y de donde las saco; una
/// orden industrial de escritura dice que venia a parar una planta y no a mirar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revelacion {
    /// Se identifico con un nombre de cliente o version.
    Herramienta {
        /// Lo que dijo ser.
        texto: String,
    },
    /// Probo unas credenciales.
    Credencial {
        /// Usuario.
        usuario: String,
        /// Contrasena, si la mando en claro.
        clave: String,
    },
    /// Pidio algo concreto: una ruta, una tabla, una clave.
    Peticion {
        /// Que pidio.
        que: String,
    },
    /// Mando una orden que **cambia el estado** de un dispositivo.
    ///
    /// Es la mas grave de todas y por eso va aparte: en un senuelo industrial
    /// distingue a quien estaba inventariando de quien venia a parar la planta.
    OrdenDeEscritura {
        /// Que orden.
        que: String,
    },
}

impl Revelacion {
    /// Como se lee en una alerta.
    #[must_use]
    pub fn frase(&self) -> String {
        match self {
            Revelacion::Herramienta { texto } => format!("se identifico como «{texto}»"),
            Revelacion::Credencial { usuario, clave } => {
                format!("probo el usuario «{usuario}» con la clave «{clave}»")
            }
            Revelacion::Peticion { que } => format!("pidio «{que}»"),
            Revelacion::OrdenDeEscritura { que } => {
                format!("mando ESCRIBIR: «{que}» — no venia a mirar")
            }
        }
    }

    /// Si esto implica que el visitante iba a por el dispositivo y no de paseo.
    #[must_use]
    pub fn es_grave(&self) -> bool {
        matches!(self, Revelacion::OrdenDeEscritura { .. })
    }
}

/// Un senuelo que conversa.
///
/// # El contrato
///
/// - `saludo` se llama una vez, antes de que el cliente hable. En UDP devuelve
///   siempre `None`: un servicio sin conexion que habla sin que le pregunten es,
///   literalmente, un amplificador.
/// - `turno` transforma bytes en bytes. **No ejecuta, no abre, no escribe.**
/// - `revelado` acumula lo que el visitante dijo de si mismo.
pub trait Dialogo {
    /// Que servicio se finge.
    fn servicio(&self) -> &'static str;

    /// Por donde se habla.
    fn transporte(&self) -> Transporte;

    /// Lo que se manda nada mas aceptar, si el servicio real saluda.
    fn saludo(&mut self) -> Option<Vec<u8>> {
        None
    }

    /// Un turno de conversacion.
    fn turno(&mut self, entrada: &[u8]) -> Paso;

    /// Lo que el visitante ha revelado hasta ahora.
    fn revelado(&self) -> &[Revelacion];

    /// Cuanto estado guarda ahora mismo, en bytes.
    ///
    /// Se declara para poder comprobar el techo desde fuera: un dialogo que
    /// acumule sin limite es quien habla decidiendo la memoria del agente.
    fn estado(&self) -> usize {
        0
    }
}

/// Para poder tener una conversacion con un dialogo elegido en tiempo de
/// ejecucion: el catalogo devuelve `Box<dyn Dialogo>` y el envoltorio no tiene
/// que saber cual es.
impl Dialogo for Box<dyn Dialogo> {
    fn servicio(&self) -> &'static str {
        (**self).servicio()
    }
    fn transporte(&self) -> Transporte {
        (**self).transporte()
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        (**self).saludo()
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        (**self).turno(entrada)
    }
    fn revelado(&self) -> &[Revelacion] {
        (**self).revelado()
    }
    fn estado(&self) -> usize {
        (**self).estado()
    }
}

/// Como acabo una conversacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Final {
    /// Sigue abierta.
    Abierta,
    /// El dialogo la cerro.
    LaCerroElSenuelo,
    /// Se agotaron los turnos.
    SeAcabaronLosTurnos,
}

/// Una conversacion en marcha.
///
/// # Por que los bytes salen por aqui y no por el dialogo
///
/// Porque si cada dialogo aplicara su propio limite, el dialogo nuevo que alguien
/// escriba dentro de un ano no lo aplicaria — y no fallaria ruidosamente, sino
/// que amplificaria en silencio. Con el filtro en el envoltorio, **no hay forma de
/// anadir un senuelo que se salte la cota**: el unico camino de los bytes al cable
/// pasa por aqui. Es la misma tecnica que el `Limpio` de la FASE 90.
///
/// El [`Limitador`] no vive aqui dentro: **se pasa**, porque es de la red entera.
/// Ver su documentacion — un cubo de fichas por conexion no limita nada, y esta
/// conversacion dura una conexion.
pub struct Conversacion<D: Dialogo> {
    dialogo: D,
    turnos: u32,
    final_: Final,
    cuentas: crate::limitador::Cuentas,
}

impl<D: Dialogo> Conversacion<D> {
    /// Abre una conversacion con un dialogo.
    pub fn nueva(dialogo: D) -> Conversacion<D> {
        Conversacion {
            dialogo,
            turnos: 0,
            final_: Final::Abierta,
            cuentas: crate::limitador::Cuentas::default(),
        }
    }

    /// El saludo que sale al cable, ya filtrado.
    ///
    /// En UDP no hay saludo: se devuelve vacio pase lo que pase, porque un
    /// servicio sin conexion que habla sin que le pregunten manda bytes a quien no
    /// los pidio.
    pub fn saludo(&mut self) -> Vec<u8> {
        if self.dialogo.transporte().el_origen_puede_ser_falso() {
            return Vec::new();
        }
        self.dialogo.saludo().unwrap_or_default()
    }

    /// Un turno: lo que entra, lo que sale y por que salio eso.
    ///
    /// El `limitador` es el de la red, compartido por todas las conversaciones.
    pub fn turno(
        &mut self,
        limitador: &mut Limitador,
        origen: u128,
        ahora_ns: u64,
        entrada: &[u8],
    ) -> (Vec<u8>, Recorte) {
        if self.final_ != Final::Abierta {
            return (Vec::new(), Recorte::Nada);
        }
        self.turnos += 1;
        let paso = self.dialogo.turno(entrada);
        if paso.cierra() {
            self.final_ = Final::LaCerroElSenuelo;
        } else if self.turnos >= MAX_TURNOS {
            self.final_ = Final::SeAcabaronLosTurnos;
        }
        let bytes = paso.bytes().to_vec();
        let (salida, motivo) =
            limitador.filtrar(self.dialogo.transporte(), origen, ahora_ns, entrada, bytes);
        // Las cuentas de ESTA conversacion, ademas de las de la red: es lo que
        // permite decir si un visitante concreto intento usar el senuelo para
        // amplificar, y no solo si alguien lo intento.
        self.cuentas.entrantes += 1;
        self.cuentas.bytes_entrantes += entrada.len() as u64;
        self.cuentas.bytes_emitidos += salida.len() as u64;
        if motivo == Recorte::PorAmplificacion {
            self.cuentas.recortadas += 1;
        }
        (salida, motivo)
    }

    /// Como acabo.
    #[must_use]
    pub fn como_acabo(&self) -> Final {
        self.final_
    }

    /// Cuantos turnos se han dado.
    #[must_use]
    pub fn turnos(&self) -> u32 {
        self.turnos
    }

    /// Lo que el visitante revelo.
    #[must_use]
    pub fn revelado(&self) -> &[Revelacion] {
        self.dialogo.revelado()
    }

    /// Las cuentas de esta conversacion.
    #[must_use]
    pub fn cuentas(&self) -> crate::limitador::Cuentas {
        self.cuentas
    }

    /// El dialogo, para preguntarle su estado.
    #[must_use]
    pub fn dialogo(&self) -> &D {
        &self.dialogo
    }
}

/// Recorta una linea de texto a lo que cabe en el estado, sin panico en UTF-8.
///
/// Los dialogos guardan lo que el visitante dice —el usuario que probo, la ruta
/// que pidio— y eso lo escribe el atacante. Sin recorte, un `USER` de un megabyte
/// es un megabyte guardado por conexion.
#[must_use]
pub fn recortado(entrada: &[u8], tope: usize) -> String {
    let n = entrada.len().min(tope);
    String::from_utf8_lossy(&entrada[..n])
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

/// Los primeros `n` **caracteres** de un texto, no los primeros `n` bytes.
///
/// # Por que esto existe y no se corta con `&s[..n]`
///
/// Porque cortar un texto por un indice de byte revienta si el byte cae dentro de
/// un caracter de varios, y el texto que se corta aqui lo escribe el visitante.
/// La primera version de los senuelos de FTP y de Redis devolvia el mando
/// desconocido con `&otra[..otra.len().min(16)]`, y mandarles `ññññ…` **tumbaba el
/// agente**: apagar la defensa mandando un paquete raro es el mejor resultado
/// posible para quien ataca, y lo encontro la prueba de autoataque.
///
/// Contando caracteres no hay borde que caiga en mal sitio.
#[must_use]
pub fn primeros(texto: &str, n: usize) -> String {
    texto.chars().take(n).collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un dialogo de mentira que contesta mil bytes a lo que sea.
    struct Charlatan {
        t: Transporte,
        dicho: Vec<Revelacion>,
    }

    impl Dialogo for Charlatan {
        fn servicio(&self) -> &'static str {
            "charlatan"
        }
        fn transporte(&self) -> Transporte {
            self.t
        }
        fn saludo(&mut self) -> Option<Vec<u8>> {
            Some(vec![b'S'; 1000])
        }
        fn turno(&mut self, _entrada: &[u8]) -> Paso {
            Paso::Responde(vec![b'R'; 1000])
        }
        fn revelado(&self) -> &[Revelacion] {
            &self.dicho
        }
    }

    #[test]
    fn en_udp_no_hay_saludo_por_mucho_que_el_dialogo_quiera() {
        let mut c = Conversacion::nueva(Charlatan {
            t: Transporte::Udp,
            dicho: Vec::new(),
        });
        assert!(
            c.saludo().is_empty(),
            "un servicio sin conexion que saluda solo manda bytes a quien no los pidio"
        );
    }

    #[test]
    fn el_envoltorio_acota_al_dialogo_aunque_el_dialogo_no_se_acote() {
        // El charlatan contesta mil bytes a una pregunta de uno. En UDP no puede.
        let mut l = Limitador::nuevo();
        let mut c = Conversacion::nueva(Charlatan {
            t: Transporte::Udp,
            dicho: Vec::new(),
        });
        let (salida, motivo) = c.turno(&mut l, 1, 0, b"x");
        assert_eq!(salida.len(), 1);
        assert_eq!(motivo, Recorte::PorAmplificacion);
        assert!(c.cuentas().amplificacion_en_centesimas() <= 100);
    }

    #[test]
    fn la_conversacion_se_acaba_sola() {
        let mut l = Limitador::nuevo();
        let mut c = Conversacion::nueva(Charlatan {
            t: Transporte::Tcp,
            dicho: Vec::new(),
        });
        for _ in 0..MAX_TURNOS {
            c.turno(&mut l, 1, 0, b"sigue");
        }
        assert_eq!(c.como_acabo(), Final::SeAcabaronLosTurnos);
        let (salida, _) = c.turno(&mut l, 1, 0, b"sigue");
        assert!(salida.is_empty(), "una conversacion acabada no contesta");
        assert_eq!(c.turnos(), MAX_TURNOS);
    }

    #[test]
    fn el_ritmo_por_origen_sobrevive_a_que_el_origen_cuelgue_y_vuelva() {
        // **El fallo que encontro la prueba de autoataque.** Con el limitador
        // dentro de la conversacion, colgar y volver a llamar daba un cubo nuevo,
        // asi que el limite no limitaba nada.
        let mut l = Limitador::nuevo();
        let mut atendidas = 0;
        for _ in 0..(crate::limitador::MENSAJES_POR_SEGUNDO_Y_ORIGEN * 3) {
            let mut c = Conversacion::nueva(Charlatan {
                t: Transporte::Tcp,
                dicho: Vec::new(),
            });
            let (s, _) = c.turno(&mut l, 7, 0, b"otra conexion");
            if !s.is_empty() {
                atendidas += 1;
            }
        }
        assert_eq!(
            atendidas,
            crate::limitador::MENSAJES_POR_SEGUNDO_Y_ORIGEN as usize,
            "abrir conexiones nuevas se saltaba el limite de ritmo"
        );
    }

    #[test]
    fn recortado_no_se_pasa_ni_se_rompe_con_utf8_partido() {
        assert_eq!(recortado(b"hola\r\n", 100), "hola");
        assert_eq!(recortado(&vec![b'a'; 1000], 10).len(), 10);
        // Un caracter multibyte partido por el tope no puede hacer panico.
        let s = "ñññññ".as_bytes();
        let _ = recortado(s, 3);
    }
}
