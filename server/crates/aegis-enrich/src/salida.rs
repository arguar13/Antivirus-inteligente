//! La salida de red, entregada como capacidad.
//!
//! # La decision que hace verdadero el modo sin salida
//!
//! Lo obvio seria una bandera: `if sin_salida { return NoAplicable }` al principio
//! de cada analizador. Y no sirve, por dos motivos que se ven en cuanto se piensa
//! en quien escribe el analizador siguiente:
//!
//! 1. Es **opcional**. El analizador que se escriba el mes que viene se la olvida,
//!    y nadie lo nota hasta que un cliente con la red aislada ve trafico saliente.
//! 2. Es **una comprobacion, no una frontera**. Comprueba la intencion declarada,
//!    no la capacidad real. Un analizador que abre su propio socket se la salta
//!    sin querer.
//!
//! Aqui la salida es una **capacidad**: un objeto que el analizador recibe como
//! argumento y sin el cual no tiene forma de hablar con nadie. En modo sin salida
//! ese objeto sencillamente **no existe**, asi que no hay nada que entregar.
//!
//! La diferencia es la que va de «prometio no salir» a «no se le dio por donde».
//!
//! # La ausencia es la frontera
//!
//! Igual que en `aegis-detonate`: [`Salida`] no tiene ninguna variante que
//! signifique «red sin restricciones». Un analizador recibe `Option<&Salida>`, y
//! `None` no es un caso de error que se pueda ignorar — es que no hay a quien
//! preguntar.
//!
//! # El muro, dicho aqui y no en un anexo
//!
//! Esto impide la salida **por la via que el marco ofrece**. Un analizador escrito
//! en este mismo proceso que llame directamente a `std::net::TcpStream` sale
//! igual: Rust no tiene forma de negarle el acceso a la biblioteca estandar. Lo
//! que hace que eso no sea un agujero real:
//!
//! - Los analizadores viven **en el arbol** y pasan por revision, igual que el
//!   resto del servidor. No son complementos de terceros que se carguen en
//!   caliente, y `lib.rs` lo dice.
//! - La puerta de calidad comprueba que ningun analizador enlaza contra las
//!   primitivas de red directamente (`tools/verificar-enrich.sh`).
//! - Y el confinamiento de verdad, cuando hace falta, es el del sistema: el
//!   proceso del servidor corre con su propia politica de red. Esa es la frontera
//!   que un fallo de programacion no atraviesa.
//!
//! Decirlo es parte del diseño. Un marco que promete aislamiento que no tiene es
//! peor que uno que no lo promete, porque invita a confiar en el.

use std::time::Duration;

use crate::exposicion::Destino;

/// Cuanto puede tardar como maximo una consulta por la red.
///
/// Cinco segundos. No es un numero redondo por gusto: un analizador de
/// enriquecimiento corre **mientras un analista espera**, y por encima de unos
/// segundos deja de usarse. Un analizador lento no es un analizador degradado, es
/// un analizador que nadie ejecuta.
pub const PLAZO_POR_DEFECTO: Duration = Duration::from_secs(5);

/// Bytes maximos que se aceptan de una respuesta.
///
/// Un megabyte. La respuesta la escribe **el proveedor**, que desde el punto de
/// vista de este proceso es una entrada no confiable: sin tope, un proveedor
/// comprometido —o simplemente roto— tumba el servidor mandando una respuesta
/// interminable, y eso es una denegacion de servicio que entra por la puerta que
/// nosotros abrimos.
pub const MAX_RESPUESTA: usize = 1024 * 1024;

/// Lo que un analizador puede pedirle a la red.
///
/// **No hay variante «red sin restricciones».** La ausencia es la frontera.
pub trait Salida: Send + Sync {
    /// Hace una consulta y devuelve la respuesta en crudo.
    ///
    /// La respuesta es **no confiable**: la escribe el proveedor. Quien la reciba
    /// la trata como entrada hostil, igual que un registro que llega por el puerto
    /// 514.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo del fallo, que va al informe tal cual.
    fn consultar(&self, peticion: &Peticion) -> Result<Vec<u8>, FalloDeSalida>;

    /// A que destino esta atada esta salida.
    ///
    /// Una salida se entrega **atada** al destino que el analizador declaro. Sin
    /// esto, un analizador que declara `Interno` recibiria una salida con la que
    /// puede llamar a cualquiera, y la declaracion no valdria nada.
    fn destino(&self) -> &Destino;
}

/// Una consulta a un servicio externo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peticion {
    /// Camino dentro del servicio. No lleva el anfitrion: lo pone la salida, que
    /// es quien sabe a donde esta atada.
    pub camino: String,
    /// Parametros de la consulta.
    pub parametros: Vec<(String, String)>,
    /// Cuerpo, si lo hay.
    pub cuerpo: Vec<u8>,
    /// Cuanto se espera como maximo.
    pub plazo: Duration,
}

impl Peticion {
    /// Una consulta simple por camino y parametros.
    #[must_use]
    pub fn nueva(camino: impl Into<String>) -> Peticion {
        Peticion {
            camino: camino.into(),
            parametros: Vec::new(),
            cuerpo: Vec::new(),
            plazo: PLAZO_POR_DEFECTO,
        }
    }

    /// Añade un parametro.
    #[must_use]
    pub fn con(mut self, clave: impl Into<String>, valor: impl Into<String>) -> Peticion {
        self.parametros.push((clave.into(), valor.into()));
        self
    }

    /// Fija el plazo.
    #[must_use]
    pub fn en(mut self, plazo: Duration) -> Peticion {
        self.plazo = plazo;
        self
    }
}

/// Por que fallo una consulta.
///
/// Los motivos estan separados porque **no significan lo mismo para el analista**.
/// Un tiempo agotado puede reintentarse; una cuota agotada no; y una respuesta
/// demasiado grande es un indicio de que algo va mal al otro lado. Un unico
/// `Error(String)` los haria indistinguibles justo cuando hay que decidir si se
/// vuelve a intentar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalloDeSalida {
    /// Se agoto el plazo.
    TiempoAgotado {
        /// Cuanto se espero.
        plazo: Duration,
    },
    /// El servicio contesto con un error.
    Rechazada {
        /// Que dijo.
        motivo: String,
    },
    /// La respuesta paso del tope.
    RespuestaExcesiva {
        /// Cuantos bytes llegaron antes de cortar.
        bytes: usize,
    },
    /// No se pudo hablar con el servicio.
    NoAlcanzable {
        /// Que paso.
        motivo: String,
    },
}

impl FalloDeSalida {
    /// Si tiene sentido volver a intentarlo.
    ///
    /// Reintentar una cuota agotada la agota mas, y reintentar una respuesta
    /// excesiva vuelve a traer la misma respuesta excesiva.
    #[must_use]
    pub fn merece_reintento(&self) -> bool {
        matches!(
            self,
            FalloDeSalida::TiempoAgotado { .. } | FalloDeSalida::NoAlcanzable { .. }
        )
    }

    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            FalloDeSalida::TiempoAgotado { plazo } => {
                format!("no contesto en {} ms", plazo.as_millis())
            }
            FalloDeSalida::Rechazada { motivo } => {
                format!("el servicio rechazo la consulta: {motivo}")
            }
            FalloDeSalida::RespuestaExcesiva { bytes } => format!(
                "la respuesta paso del tope de {MAX_RESPUESTA} bytes (se cortaron {bytes}); una \
                 respuesta asi es un indicio de que algo va mal al otro lado"
            ),
            FalloDeSalida::NoAlcanzable { motivo } => format!("no se pudo alcanzar: {motivo}"),
        }
    }
}

/// El interruptor general.
///
/// Es un tipo y no un `bool` por la misma razon que [`Destino`] es un enumerado:
/// un `bool` invertido por error en un refactor no se ve en la revision, y aqui lo
/// que se invierte es si los datos del cliente salen de su red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modo {
    /// Se permiten consultas por red a los destinos declarados.
    Conectado,
    /// **No sale nada.** Ni a terceros ni a servicios internos.
    ///
    /// Los analizadores locales siguen funcionando con normalidad. Los que
    /// necesitan red devuelven `NoAplicable` **con su motivo**, nunca un resultado
    /// vacio que se lea como «limpio».
    SinSalida,
}

impl Modo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Modo::Conectado => "conectado",
            Modo::SinSalida => "sin-salida",
        }
    }

    /// Si en este modo se puede entregar una salida hacia ese destino.
    ///
    /// En `SinSalida` la respuesta es `false` para **todo** lo que necesite red,
    /// interno incluido: una red aislada lo esta tambien para los servicios
    /// propios que vivan al otro lado del aislamiento.
    #[must_use]
    pub fn permite(self, destino: &Destino) -> bool {
        match self {
            Modo::Conectado => true,
            Modo::SinSalida => !destino.necesita_red(),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::exposicion::{Jurisdiccion, Retencion};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn externo() -> Destino {
        Destino::Externo {
            proveedor: "reputacion.example".into(),
            jurisdiccion: Jurisdiccion::Eee,
            retencion: Retencion::Indefinida,
        }
    }

    /// Una salida que cuenta cuantas veces la han usado.
    struct SalidaContada {
        destino: Destino,
        veces: Arc<AtomicUsize>,
    }

    impl Salida for SalidaContada {
        fn consultar(&self, _p: &Peticion) -> Result<Vec<u8>, FalloDeSalida> {
            self.veces.fetch_add(1, Ordering::SeqCst);
            Ok(b"{}".to_vec())
        }
        fn destino(&self) -> &Destino {
            &self.destino
        }
    }

    #[test]
    fn en_modo_sin_salida_no_se_permite_ni_lo_interno() {
        // Una red aislada lo esta tambien para los servicios propios que vivan al
        // otro lado del aislamiento. Permitir «solo lo interno» seria justo el
        // matiz que hace que el modo no valga para lo que existe.
        assert!(!Modo::SinSalida.permite(&externo()));
        assert!(!Modo::SinSalida.permite(&Destino::Interno {
            servicio: "cmdb".into()
        }));
        assert!(Modo::SinSalida.permite(&Destino::Local));
    }

    #[test]
    fn en_modo_conectado_se_permite_todo_lo_declarado() {
        assert!(Modo::Conectado.permite(&externo()));
        assert!(Modo::Conectado.permite(&Destino::Local));
    }

    #[test]
    fn la_salida_va_atada_a_su_destino() {
        // Sin esto, un analizador que declara `Interno` recibiria una salida con
        // la que puede llamar a cualquiera y la declaracion no valdria nada.
        let s = SalidaContada {
            destino: externo(),
            veces: Arc::new(AtomicUsize::new(0)),
        };
        assert!(s.destino().sale_de_la_organizacion());
    }

    #[test]
    fn una_salida_se_usa_solo_si_se_entrega() {
        // La prueba de que el modo sin salida es por CONSTRUCCION: el analizador
        // recibe `Option<&dyn Salida>`, y con `None` no hay forma de consultar
        // aunque quiera.
        let veces = Arc::new(AtomicUsize::new(0));
        let s = SalidaContada {
            destino: externo(),
            veces: Arc::clone(&veces),
        };

        let entregada: Option<&dyn Salida> = None;
        assert!(entregada.is_none());
        assert_eq!(veces.load(Ordering::SeqCst), 0);

        let entregada: Option<&dyn Salida> = Some(&s);
        if let Some(via) = entregada {
            let _ = via.consultar(&Peticion::nueva("/v1/hash"));
        }
        assert_eq!(veces.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn solo_se_reintenta_lo_que_puede_salir_distinto() {
        // Reintentar una cuota agotada la agota mas; reintentar una respuesta
        // excesiva vuelve a traer la misma respuesta excesiva.
        assert!(FalloDeSalida::TiempoAgotado {
            plazo: PLAZO_POR_DEFECTO
        }
        .merece_reintento());
        assert!(FalloDeSalida::NoAlcanzable {
            motivo: "dns".into()
        }
        .merece_reintento());
        assert!(!FalloDeSalida::Rechazada {
            motivo: "429".into()
        }
        .merece_reintento());
        assert!(!FalloDeSalida::RespuestaExcesiva {
            bytes: MAX_RESPUESTA + 1
        }
        .merece_reintento());
    }

    #[test]
    fn todo_fallo_se_explica_en_el_informe() {
        for f in [
            FalloDeSalida::TiempoAgotado {
                plazo: PLAZO_POR_DEFECTO,
            },
            FalloDeSalida::Rechazada {
                motivo: "429".into(),
            },
            FalloDeSalida::RespuestaExcesiva { bytes: 9_000_000 },
            FalloDeSalida::NoAlcanzable {
                motivo: "dns".into(),
            },
        ] {
            assert!(f.texto().len() > 10, "{f:?} no se explica");
        }
    }

    #[test]
    fn la_peticion_se_compone_sin_anfitrion() {
        // El anfitrion lo pone la SALIDA, que es quien sabe a donde esta atada. Si
        // lo pusiera el analizador, podria apuntar a otro sitio.
        let p = Peticion::nueva("/v1/hash")
            .con("h", "abc")
            .en(Duration::from_secs(2));
        assert_eq!(p.camino, "/v1/hash");
        assert_eq!(p.parametros, vec![("h".to_string(), "abc".to_string())]);
        assert_eq!(p.plazo, Duration::from_secs(2));
        assert!(!p.camino.contains("://"), "la peticion no lleva anfitrion");
    }
}
