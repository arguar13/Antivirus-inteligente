//! El nucleo del enjambre: una maquina de estados **sin entrada/salida**.
//!
//! # Por que sans-io y no un socket aqui dentro
//!
//! Este tipo no abre sockets, no conoce libp2p y no sabe que existe la red. Se
//! le entregan bytes con el nombre de quien los mando y devuelve **decisiones**.
//! Tiene tres consecuencias, y las tres importan:
//!
//! 1. **Se prueba entero sin red.** Cada ataque de esta fase —reproduccion,
//!    inundacion, Sybil, envenenamiento de trozos— se construye de verdad en una
//!    prueba, en vez de quedarse en «no se puede ejercitar aqui».
//! 2. **El transporte es intercambiable.** libp2p vive en `swarm-net/`, fuera
//!    del workspace del agente, y consume este nucleo. Si manana el transporte
//!    cambia, las decisiones no se tocan.
//! 3. **El agente no paga el transporte.** Ver la doctrina del modulo raiz: 340
//!    crates y un runtime async no entran en un proceso privilegiado que corre en
//!    cada endpoint.
//!
//! # Las cuatro cotas, y por que el orden en que se aplican es el diseno
//!
//! Un mensaje entrante recorre este orden, y no es negociable:
//!
//! 1. **Tasa por par** — antes de nada. Un par que inunda se descarta sin que se
//!    haya tocado un solo byte de criptografia. Verificar primero y limitar
//!    despues convierte la malla en un amplificador de CPU: mandar basura firmada
//!    con cualquier cosa costaria al receptor una verificacion ML-DSA por
//!    mensaje, que es justo lo que un atacante quiere.
//! 2. **Tamano y formato** — acotado, sin reservar memoria por lo que diga nadie.
//! 3. **Deduplicacion** — lo ya visto ni se procesa ni se reenvia. Es lo que
//!    corta los caminos redundantes de la inundacion.
//! 4. **Autenticidad** — al final, y segun la clase: firma del plano de control
//!    para ordenes y artefactos, firma del par para observaciones.
//!
//! # El aislamiento, que es el caso para el que existe la fase
//!
//! [`EstadoEnlace::Aislado`] significa que el plano de control no se alcanza. Es
//! cuando el enjambre pasa de ser un atajo a ser el unico camino.
//!
//! Y aqui hay una tentacion que hay que nombrar para no caer en ella: parece
//! razonable **relajar** el umbral de corroboro cuando se esta aislado, «porque
//! no hay nadie a quien preguntar». Es exactamente al reves. Un adversario
//! competente **provoca** el aislamiento como primer paso, precisamente para que
//! la flota decida sola. Estar aislado es motivo para ser mas cuidadoso, no
//! menos, asi que el umbral **no baja nunca**: lo unico que cambia al aislarse es
//! que el enjambre se convierte en el transporte, no en la autoridad.

use std::collections::BTreeMap;

use aegis_update::signature::ClaveActualizacion;

use crate::artefacto::{Descriptor, Reensamblado, Trozo};
use crate::error::ErrorEnjambre;
use crate::mensaje::{Sobre, TipoMensaje};
use crate::observacion::Observacion;
use crate::orden::Orden;
use crate::quorum::{Corroboro, Veredicto};

/// Saltos por defecto que le quedan a un mensaje nuevo.
pub const SALTOS_POR_DEFECTO: u8 = 3;

/// Mensajes por par y ventana admitidos por defecto.
pub const TASA_POR_DEFECTO: u32 = 64;

/// Ventana de la tasa, en segundos.
pub const VENTANA_TASA_SEG: u64 = 10;

/// Tope de identificadores recordados para deduplicar.
pub const MAX_VISTOS: usize = 8192;

/// Tope de reensamblados en curso a la vez.
///
/// Sin el, un par anuncia mil artefactos y nunca manda los trozos: cada anuncio
/// ocupa una ranura y el receptor se queda sin sitio para el paquete de reglas
/// de verdad. Es una denegacion de servicio con mensajes validos.
pub const MAX_REENSAMBLADOS: usize = 8;

/// Estado del enlace con el plano de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EstadoEnlace {
    /// Se alcanza el plano de control: el enjambre es un atajo.
    #[default]
    Conectado,
    /// No se alcanza: el enjambre es el unico camino.
    Aislado,
}

/// Por que se descarto un mensaje.
///
/// Es un enumerado y no un texto porque estas cuentas son telemetria de
/// seguridad: «cuantos mensajes descarto este endpoint por tasa» es la senal de
/// que un vecino esta inundando, y se pierde si el motivo es una cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MotivoDescarte {
    /// El par paso su cuota en la ventana.
    Tasa,
    /// Ya se habia visto este mensaje.
    Duplicado,
    /// No se pudo analizar.
    Malformado,
    /// La firma no verifica.
    FirmaInvalida,
    /// La accion no puede viajar por el enjambre.
    ClaseProhibida,
    /// Fuera de su ventana temporal.
    Caducado,
    /// Una epoca ya superada: reproduccion.
    Reproduccion,
    /// Un trozo que no cuadra con su descriptor.
    TrozoInvalido,
    /// No quedan ranuras de reensamblado.
    SinRanura,
}

/// Lo que el enjambre decide que hay que hacer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Salida {
    /// Aplicar una orden del plano de control.
    AplicarOrden(Box<Orden>),
    /// Un indicador ha sido corroborado por bastantes pares distintos.
    ///
    /// **No es una orden**: es evidencia suficiente para que la politica local
    /// decida, con el mismo criterio con el que decide ante una deteccion propia.
    Corroborado {
        /// La observacion que cerro el quorum.
        observacion: Box<Observacion>,
        /// Quienes lo vieron.
        testigos: Vec<String>,
    },
    /// Un artefacto quedo completo y verificado.
    ArtefactoListo {
        /// Su descriptor.
        descriptor: Box<Descriptor>,
        /// Su contenido.
        contenido: Vec<u8>,
    },
    /// Hay que pedir estos trozos.
    PedirTrozos {
        /// Artefacto.
        id: [u8; 32],
        /// Indices que faltan.
        indices: Vec<u32>,
    },
    /// Reenviar este mensaje a los vecinos.
    Reenviar(Vec<u8>),
    /// Se descarto, y por que.
    Descartado(MotivoDescarte),
}

/// Configuracion del enjambre.
#[derive(Debug, Clone)]
pub struct ConfigEnjambre {
    /// Clave publica del plano de control, para ordenes y artefactos.
    pub clave_plano_control: ClaveActualizacion,
    /// Saltos con los que sale un mensaje propio.
    pub saltos: u8,
    /// Mensajes por par y ventana.
    pub tasa: u32,
    /// Umbral de corroboro.
    pub umbral_corroboro: usize,
    /// Ventana de corroboro.
    pub ventana_corroboro_seg: u64,
}

/// Contadores del enjambre.
#[derive(Debug, Clone, Default)]
pub struct Contadores {
    /// Mensajes aceptados.
    pub aceptados: u64,
    /// Mensajes reenviados.
    pub reenviados: u64,
    /// Descartes por motivo.
    pub descartes: BTreeMap<MotivoDescarte, u64>,
}

impl Contadores {
    /// Total de descartes.
    #[must_use]
    pub fn descartados(&self) -> u64 {
        self.descartes.values().sum()
    }

    /// Descartes de un motivo.
    #[must_use]
    pub fn de(&self, m: MotivoDescarte) -> u64 {
        self.descartes.get(&m).copied().unwrap_or(0)
    }
}

/// Cuota de un par dentro de la ventana.
#[derive(Debug, Clone, Copy)]
struct Cuota {
    inicio: u64,
    cuenta: u32,
}

/// El nucleo del enjambre.
pub struct Enjambre {
    config: ConfigEnjambre,
    enlace: EstadoEnlace,
    corroboro: Corroboro,
    vistos: BTreeMap<[u8; 32], u64>,
    orden_vistos: Vec<[u8; 32]>,
    cuotas: BTreeMap<String, Cuota>,
    epocas: BTreeMap<(u8, String), u64>,
    reensamblados: BTreeMap<[u8; 32], Reensamblado>,
    contadores: Contadores,
}

impl Enjambre {
    /// Nuevo enjambre.
    #[must_use]
    pub fn nuevo(config: ConfigEnjambre) -> Enjambre {
        let corroboro = Corroboro::nuevo(config.umbral_corroboro, config.ventana_corroboro_seg);
        Enjambre {
            config,
            enlace: EstadoEnlace::default(),
            corroboro,
            vistos: BTreeMap::new(),
            orden_vistos: Vec::new(),
            cuotas: BTreeMap::new(),
            epocas: BTreeMap::new(),
            reensamblados: BTreeMap::new(),
            contadores: Contadores::default(),
        }
    }

    /// Estado del enlace con el plano de control.
    #[must_use]
    pub fn enlace(&self) -> EstadoEnlace {
        self.enlace
    }

    /// Declara el estado del enlace.
    ///
    /// Cambiarlo **no** toca el umbral de corroboro, a proposito: ver la
    /// doctrina del modulo.
    pub fn declarar_enlace(&mut self, e: EstadoEnlace) {
        self.enlace = e;
    }

    /// Contadores.
    #[must_use]
    pub fn contadores(&self) -> &Contadores {
        &self.contadores
    }

    /// Umbral de corroboro vigente.
    #[must_use]
    pub fn umbral(&self) -> usize {
        self.corroboro.umbral
    }

    /// Reensamblados en curso.
    #[must_use]
    pub fn reensamblados_en_curso(&self) -> usize {
        self.reensamblados.len()
    }

    fn descartar(&mut self, m: MotivoDescarte) -> Salida {
        *self.contadores.descartes.entry(m).or_insert(0) += 1;
        Salida::Descartado(m)
    }

    /// Aplica el limite de tasa. `true` si el par se pasa.
    fn se_pasa_de_tasa(&mut self, de: &str, ahora: u64) -> bool {
        let c = self.cuotas.entry(de.to_string()).or_insert(Cuota {
            inicio: ahora,
            cuenta: 0,
        });
        if ahora.saturating_sub(c.inicio) > VENTANA_TASA_SEG {
            c.inicio = ahora;
            c.cuenta = 0;
        }
        c.cuenta = c.cuenta.saturating_add(1);
        c.cuenta > self.config.tasa
    }

    /// Registra un identificador. `true` si ya se habia visto.
    fn ya_visto(&mut self, id: [u8; 32], ahora: u64) -> bool {
        if self.vistos.contains_key(&id) {
            return true;
        }
        if self.orden_vistos.len() >= MAX_VISTOS {
            // Se olvida lo mas antiguo. Olvidar tiene un coste real —un mensaje
            // muy viejo podria volver a reenviarse— y es preferible a crecer sin
            // limite, que es una via de agotamiento de memoria.
            let viejo = self.orden_vistos.remove(0);
            self.vistos.remove(&viejo);
        }
        self.vistos.insert(id, ahora);
        self.orden_vistos.push(id);
        false
    }

    /// Procesa un mensaje entrante.
    ///
    /// `de` es la identidad **autenticada por el transporte** del par que lo
    /// entrego, no un campo del mensaje: si viniera dentro, cualquiera se haria
    /// pasar por otro para gastarle la cuota.
    pub fn recibir(&mut self, de: &str, bytes: &[u8], ahora: u64) -> Vec<Salida> {
        // 1. TASA, antes de cualquier criptografia.
        if self.se_pasa_de_tasa(de, ahora) {
            return vec![self.descartar(MotivoDescarte::Tasa)];
        }

        // 2. FORMATO, acotado.
        let sobre = match Sobre::desde_bytes(bytes) {
            Ok(s) => s,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };

        // 3. DEDUPLICACION.
        if self.ya_visto(sobre.id(), ahora) {
            return vec![self.descartar(MotivoDescarte::Duplicado)];
        }

        // 4. AUTENTICIDAD Y SEMANTICA, segun la clase.
        let mut salidas = match sobre.tipo {
            TipoMensaje::Orden => self.recibir_orden(&sobre, ahora),
            TipoMensaje::Observacion => self.recibir_observacion(&sobre, ahora),
            TipoMensaje::DescriptorArtefacto => self.recibir_descriptor(&sobre),
            TipoMensaje::TrozoArtefacto => self.recibir_trozo(&sobre),
            TipoMensaje::PeticionTrozos => Vec::new(),
        };

        let acepto = !salidas.iter().any(|s| matches!(s, Salida::Descartado(_)));
        if acepto {
            self.contadores.aceptados += 1;
            if let Some(reenvio) = self.reenvio_de(&sobre) {
                self.contadores.reenviados += 1;
                salidas.push(Salida::Reenviar(reenvio));
            }
        }
        salidas
    }

    /// Prepara el reenvio, si aun le quedan saltos.
    fn reenvio_de(&self, sobre: &Sobre) -> Option<Vec<u8>> {
        let quedan = sobre.saltos.checked_sub(1)?;
        if quedan == 0 {
            return None;
        }
        Some(
            Sobre {
                saltos: quedan,
                ..sobre.clone()
            }
            .a_bytes(),
        )
    }

    fn recibir_orden(&mut self, sobre: &Sobre, ahora: u64) -> Vec<Salida> {
        let orden = match Orden::desde_bytes(&sobre.cuerpo) {
            Ok(o) => o,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };
        match orden.verificar(&self.config.clave_plano_control, &sobre.firma, ahora) {
            Ok(()) => {}
            Err(ErrorEnjambre::AccionNoPropagable(_)) => {
                return vec![self.descartar(MotivoDescarte::ClaseProhibida)]
            }
            Err(ErrorEnjambre::Caducada { .. } | ErrorEnjambre::DelFuturo { .. }) => {
                return vec![self.descartar(MotivoDescarte::Caducado)]
            }
            Err(_) => return vec![self.descartar(MotivoDescarte::FirmaInvalida)],
        }

        // EPOCA MONOTONA. La firma es autentica; lo que esto para es que una
        // orden VIEJA Y AUTENTICA se reproduzca durante el corte.
        let clave = (orden.accion.tag(), orden.sujeto.clone());
        if let Some(vigente) = self.epocas.get(&clave) {
            if orden.epoca <= *vigente {
                return vec![self.descartar(MotivoDescarte::Reproduccion)];
            }
        }
        self.epocas.insert(clave, orden.epoca);
        vec![Salida::AplicarOrden(Box::new(orden))]
    }

    fn recibir_observacion(&mut self, sobre: &Sobre, ahora: u64) -> Vec<Salida> {
        let o = match Observacion::desde_bytes(&sobre.cuerpo) {
            Ok(o) => o,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };
        if o.validar().is_err() {
            return vec![self.descartar(MotivoDescarte::Malformado)];
        }
        match self.corroboro.incorporar(&o, ahora) {
            Veredicto::Corroborado {
                observacion,
                testigos,
            } => vec![Salida::Corroborado {
                observacion: Box::new(observacion),
                testigos,
            }],
            // Insuficiente, repetido o ya avisado NO son descartes: el mensaje
            // era valido y se acepto; simplemente aun no hay bastante evidencia,
            // o ya se dio. Contarlos como descarte enterraria la senal de tasa.
            _ => Vec::new(),
        }
    }

    fn recibir_descriptor(&mut self, sobre: &Sobre) -> Vec<Salida> {
        let d = match Descriptor::desde_bytes(&sobre.cuerpo) {
            Ok(d) => d,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };
        // Un artefacto se reparte porque el plano de control lo firmo. Sin firma
        // valida no se abre ni una ranura de reensamblado: abrirla antes de
        // verificar dejaria que cualquier par agote las ranuras gratis.
        if self
            .config
            .clave_plano_control
            .verificar(
                &d.bytes_firmados(),
                crate::artefacto::CTX_ARTEFACTO,
                &sobre.firma,
            )
            .is_err()
        {
            return vec![self.descartar(MotivoDescarte::FirmaInvalida)];
        }
        if self.reensamblados.contains_key(&d.id) {
            return Vec::new();
        }
        if self.reensamblados.len() >= MAX_REENSAMBLADOS {
            return vec![self.descartar(MotivoDescarte::SinRanura)];
        }
        let r = match Reensamblado::nuevo(d.clone()) {
            Ok(r) => r,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };
        let faltan = r.faltan();
        self.reensamblados.insert(d.id, r);
        vec![Salida::PedirTrozos {
            id: d.id,
            indices: faltan,
        }]
    }

    fn recibir_trozo(&mut self, sobre: &Sobre) -> Vec<Salida> {
        let t = match Trozo::desde_bytes(&sobre.cuerpo) {
            Ok(t) => t,
            Err(_) => return vec![self.descartar(MotivoDescarte::Malformado)],
        };
        let Some(r) = self.reensamblados.get_mut(&t.id) else {
            // Un trozo de algo que nadie anuncio no abre nada: el descriptor
            // firmado es el unico que puede abrir un reensamblado.
            return vec![self.descartar(MotivoDescarte::TrozoInvalido)];
        };
        if r.incorporar(&t).is_err() {
            return vec![self.descartar(MotivoDescarte::TrozoInvalido)];
        }
        if !r.completo() {
            return Vec::new();
        }
        let Some(r) = self.reensamblados.remove(&t.id) else {
            return Vec::new();
        };
        let descriptor = r.descriptor().clone();
        match r.terminar() {
            Ok(contenido) => vec![Salida::ArtefactoListo {
                descriptor: Box::new(descriptor),
                contenido,
            }],
            Err(_) => vec![self.descartar(MotivoDescarte::TrozoInvalido)],
        }
    }

    /// Prepara un mensaje propio para salir.
    #[must_use]
    pub fn emitir(&self, tipo: TipoMensaje, cuerpo: Vec<u8>, firma: Vec<u8>) -> Vec<u8> {
        Sobre {
            tipo,
            saltos: self.config.saltos,
            cuerpo,
            firma,
        }
        .a_bytes()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::orden::Accion;

    /// Clave que no verifica nada: sirve para los caminos que no dependen de la
    /// criptografia (tasa, deduplicacion, formato). Los caminos que SI dependen
    /// de ella se prueban en `tests/circuito.rs` con claves de verdad.
    fn clave_imposible() -> ClaveActualizacion {
        ClaveActualizacion::Clasica(
            aegis_update::signature::UpdateKey::from_bytes(&[0u8; 32])
                .expect("una clave de ceros es un punto valido para este uso"),
        )
    }

    fn config() -> ConfigEnjambre {
        ConfigEnjambre {
            clave_plano_control: clave_imposible(),
            saltos: SALTOS_POR_DEFECTO,
            tasa: TASA_POR_DEFECTO,
            umbral_corroboro: 3,
            ventana_corroboro_seg: 3600,
        }
    }

    fn obs_sobre(origen: &str, valor: &str, saltos: u8) -> Vec<u8> {
        use aegis_sync::ioc::{Ioc, IocKind};
        let o = Observacion {
            origen: origen.to_string(),
            indicador: Ioc {
                kind: IocKind::FileSha256,
                value: valor.to_string(),
            },
            tecnica: "T1486".to_string(),
            confianza: 90,
            vista_en: 1000,
        };
        Sobre {
            tipo: TipoMensaje::Observacion,
            saltos,
            cuerpo: o.a_bytes(),
            firma: vec![0u8; 64],
        }
        .a_bytes()
    }

    /// LA COTA MAS IMPORTANTE: el que inunda se descarta ANTES de gastar una
    /// verificacion de firma. Si no, la malla es un amplificador de CPU.
    #[test]
    fn un_par_que_inunda_se_corta_antes_de_tocar_criptografia() {
        let mut e = Enjambre::nuevo(ConfigEnjambre {
            tasa: 8,
            ..config()
        });
        let mut cortados = 0;
        for i in 0..100 {
            let s = e.recibir("inundador", &obs_sobre("inundador", &format!("h{i}"), 3), 0);
            if matches!(s.first(), Some(Salida::Descartado(MotivoDescarte::Tasa))) {
                cortados += 1;
            }
        }
        assert!(cortados > 80, "cortados = {cortados}");
        assert_eq!(e.contadores().de(MotivoDescarte::Tasa), cortados);
    }

    /// Y la cuota es POR PAR: que uno inunde no puede silenciar a los demas.
    #[test]
    fn la_cuota_de_un_par_no_silencia_a_los_otros() {
        let mut e = Enjambre::nuevo(ConfigEnjambre {
            tasa: 4,
            ..config()
        });
        for i in 0..50 {
            e.recibir("inundador", &obs_sobre("inundador", &format!("h{i}"), 3), 0);
        }
        let s = e.recibir("honesto", &obs_sobre("honesto", "algo", 3), 0);
        assert!(
            !matches!(s.first(), Some(Salida::Descartado(MotivoDescarte::Tasa))),
            "el par honesto no puede pagar la inundacion del otro: {s:?}"
        );
    }

    #[test]
    fn la_ventana_de_tasa_se_renueva_con_el_tiempo() {
        let mut e = Enjambre::nuevo(ConfigEnjambre {
            tasa: 2,
            ..config()
        });
        for i in 0..10 {
            e.recibir("par", &obs_sobre("par", &format!("h{i}"), 3), 0);
        }
        let s = e.recibir("par", &obs_sobre("par", "tarde", 3), VENTANA_TASA_SEG + 1);
        assert!(
            !matches!(s.first(), Some(Salida::Descartado(MotivoDescarte::Tasa))),
            "pasada la ventana el par vuelve a poder hablar: {s:?}"
        );
    }

    /// EL DUPLICADO: el mismo mensaje por dos caminos se procesa una vez y no se
    /// reenvia dos. Sin esto la inundacion no converge.
    #[test]
    fn el_mismo_mensaje_por_dos_caminos_se_procesa_una_vez() {
        let mut e = Enjambre::nuevo(config());
        let m = obs_sobre("e1", "hash", 3);
        let primera = e.recibir("vecino-a", &m, 0);
        assert!(!matches!(
            primera.first(),
            Some(Salida::Descartado(MotivoDescarte::Duplicado))
        ));
        let segunda = e.recibir("vecino-b", &m, 0);
        assert!(matches!(
            segunda.first(),
            Some(Salida::Descartado(MotivoDescarte::Duplicado))
        ));
    }

    /// Un mensaje con otros saltos ES el mismo mensaje: si la deduplicacion no
    /// lo reconociera, la inundacion rebotaria para siempre.
    #[test]
    fn cambiar_los_saltos_no_esquiva_la_deduplicacion() {
        let mut e = Enjambre::nuevo(config());
        e.recibir("a", &obs_sobre("e1", "hash", 3), 0);
        let s = e.recibir("b", &obs_sobre("e1", "hash", 2), 0);
        assert!(matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::Duplicado))
        ));
    }

    /// EL REENVIO SE AGOTA: sin esto, tres agentes que reciben algo a la vez lo
    /// reenvian los tres y saturan la red local.
    #[test]
    fn los_saltos_se_agotan_y_el_reenvio_para() {
        let mut e = Enjambre::nuevo(config());
        let s = e.recibir("a", &obs_sobre("e1", "h1", 3), 0);
        assert!(s.iter().any(|x| matches!(x, Salida::Reenviar(_))));

        // Con un salto restante ya no se reenvia: este es el ultimo.
        let s = e.recibir("a", &obs_sobre("e2", "h2", 1), 0);
        assert!(
            !s.iter().any(|x| matches!(x, Salida::Reenviar(_))),
            "un mensaje sin saltos no se reenvia: {s:?}"
        );

        // Y con cero tampoco, sin restar por debajo de cero.
        let s = e.recibir("a", &obs_sobre("e3", "h3", 0), 0);
        assert!(!s.iter().any(|x| matches!(x, Salida::Reenviar(_))));
    }

    #[test]
    fn el_reenvio_lleva_un_salto_menos() {
        let mut e = Enjambre::nuevo(config());
        let s = e.recibir("a", &obs_sobre("e1", "h", 3), 0);
        let reenvio = s
            .iter()
            .find_map(|x| match x {
                Salida::Reenviar(b) => Some(b.clone()),
                _ => None,
            })
            .expect("tiene que reenviarse");
        let sobre = Sobre::desde_bytes(&reenvio).expect("valido");
        assert_eq!(sobre.saltos, 2);
    }

    /// TRES PARES DISTINTOS, SIN PLANO DE CONTROL: el caso que justifica la fase.
    #[test]
    fn tres_pares_distintos_corroboran_y_el_nucleo_lo_saca_una_vez() {
        let mut e = Enjambre::nuevo(config());
        e.declarar_enlace(EstadoEnlace::Aislado);
        assert!(e
            .recibir("v", &obs_sobre("e1", "hash", 3), 0)
            .iter()
            .all(|s| !matches!(s, Salida::Corroborado { .. })));
        assert!(e
            .recibir("v", &obs_sobre("e2", "hash", 3), 0)
            .iter()
            .all(|s| !matches!(s, Salida::Corroborado { .. })));
        let s = e.recibir("v", &obs_sobre("e3", "hash", 3), 0);
        let c = s
            .iter()
            .find_map(|x| match x {
                Salida::Corroborado { testigos, .. } => Some(testigos.clone()),
                _ => None,
            })
            .expect("el tercer par distinto cierra el quorum");
        assert_eq!(c, vec!["e1", "e2", "e3"]);
    }

    /// LA TENTACION QUE NO SE CAE: aislarse NO baja el umbral. Un adversario
    /// competente provoca el aislamiento precisamente para que la flota decida
    /// sola; estar aislado es motivo para ser mas cuidadoso, no menos.
    #[test]
    fn aislarse_no_relaja_el_umbral_de_corroboro() {
        let mut e = Enjambre::nuevo(config());
        let antes = e.umbral();
        e.declarar_enlace(EstadoEnlace::Aislado);
        assert_eq!(
            e.umbral(),
            antes,
            "el aislamiento no puede rebajar el quorum"
        );

        // Y en la practica: dos pares siguen sin bastar estando aislado.
        e.recibir("v", &obs_sobre("e1", "h", 3), 0);
        let s = e.recibir("v", &obs_sobre("e2", "h", 3), 0);
        assert!(!s.iter().any(|x| matches!(x, Salida::Corroborado { .. })));
    }

    #[test]
    fn un_mensaje_malformado_se_descarta_sin_panico() {
        let mut e = Enjambre::nuevo(config());
        for basura in [
            vec![],
            vec![0u8; 3],
            vec![0xFFu8; 64],
            vec![0u8; super::super::mensaje::MAX_MENSAJE + 1],
        ] {
            let s = e.recibir("a", &basura, 0);
            assert!(matches!(
                s.first(),
                Some(Salida::Descartado(MotivoDescarte::Malformado))
            ));
        }
    }

    /// Una orden de las que retiran proteccion se descarta POR CLASE, sin
    /// llegar siquiera a mirar la firma.
    #[test]
    fn una_orden_de_levantar_aislamiento_se_descarta_por_clase() {
        let mut e = Enjambre::nuevo(config());
        let o = Orden {
            accion: Accion::LevantarAislamiento,
            sujeto: "endpoint-1".to_string(),
            incidente: "inc".to_string(),
            epoca: 99,
            emitida_en: 0,
            caduca_en: u64::MAX,
        };
        let m = Sobre {
            tipo: TipoMensaje::Orden,
            saltos: 3,
            cuerpo: o.a_bytes(),
            firma: vec![0u8; 64],
        }
        .a_bytes();
        let s = e.recibir("a", &m, 0);
        assert!(
            matches!(
                s.first(),
                Some(Salida::Descartado(MotivoDescarte::ClaseProhibida))
            ),
            "{s:?}"
        );
    }

    /// Un trozo suelto no abre un reensamblado: solo lo abre un descriptor
    /// firmado. Si no, cualquier par agota las ranuras gratis.
    #[test]
    fn un_trozo_sin_descriptor_no_abre_nada() {
        let mut e = Enjambre::nuevo(config());
        let t = Trozo {
            id: [7u8; 32],
            indice: 0,
            datos: vec![1, 2, 3],
        };
        let m = Sobre {
            tipo: TipoMensaje::TrozoArtefacto,
            saltos: 3,
            cuerpo: t.a_bytes(),
            firma: Vec::new(),
        }
        .a_bytes();
        let s = e.recibir("a", &m, 0);
        assert!(matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::TrozoInvalido))
        ));
        assert_eq!(e.reensamblados_en_curso(), 0);
    }

    #[test]
    fn el_registro_de_vistos_no_crece_sin_limite() {
        let mut e = Enjambre::nuevo(ConfigEnjambre {
            tasa: u32::MAX,
            ..config()
        });
        for i in 0..(MAX_VISTOS + 500) {
            e.recibir("a", &obs_sobre("e1", &format!("h{i}"), 3), 0);
        }
        assert!(e.vistos.len() <= MAX_VISTOS, "vistos = {}", e.vistos.len());
    }

    #[test]
    fn los_contadores_distinguen_los_motivos_de_descarte() {
        let mut e = Enjambre::nuevo(ConfigEnjambre {
            tasa: 2,
            ..config()
        });
        e.recibir("a", &obs_sobre("e1", "h", 3), 0);
        e.recibir("a", &obs_sobre("e1", "h", 3), 0); // duplicado
        for i in 0..10 {
            e.recibir("a", &obs_sobre("e1", &format!("x{i}"), 3), 0); // tasa
        }
        e.recibir("b", &[0u8; 3], 0); // malformado
        assert!(e.contadores().de(MotivoDescarte::Duplicado) >= 1);
        assert!(e.contadores().de(MotivoDescarte::Tasa) >= 1);
        assert!(e.contadores().de(MotivoDescarte::Malformado) >= 1);
        assert_eq!(
            e.contadores().descartados(),
            e.contadores().de(MotivoDescarte::Duplicado)
                + e.contadores().de(MotivoDescarte::Tasa)
                + e.contadores().de(MotivoDescarte::Malformado)
        );
    }
}
