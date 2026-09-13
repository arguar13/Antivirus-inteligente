//! AegisIngest: ingerir, normalizar y entregar registros de cualquier origen.
//!
//! # El hueco que cierra
//!
//! Hasta aqui AegisCore consumia **su propia telemetria**: lo que ven sus
//! sensores. Eso lo hace un EDR. Una plataforma tiene que tragarse ademas lo que
//! ya escribe el resto de la casa —el syslog de los cortafuegos, el diario de
//! los servidores Linux, el registro de sucesos de los Windows, los ficheros de
//! las aplicaciones— y correlacionarlo con lo propio. Sin esto, el analista
//! tiene dos paneles y ninguna correlacion entre ellos.
//!
//! # Las cuatro cosas que hacen que esto sea una canalizacion y no un tubo
//!
//! **1. La entrega es al-menos-una-vez, y se nota.** Un endpoint que se reinicia
//! ni pierde lo que ya habia leido ni lo reenvia sin que nadie lo sepa. La
//! mecanica esta en [`punto`] y la regla de orden —sincronizar y **despues**
//! avanzar— es la unica fuente de correccion de toda la fase.
//!
//! **2. La contrapresion llega hasta el emisor.** Cuando el plano de control va
//! saturado, la cola local se llena; cuando la cola local se llena, el lector
//! reduce el ritmo; y si aun asi no cabe, se descarta **por prioridad** y se
//! cuenta. Ninguna cola crece sin limite en ningun punto. Ver [`cola`].
//!
//! **3. Los eventos se ordenan por cuando OCURRIERON.** Un endpoint que estuvo
//! apagado un dia entrega su lote al reconectar; si se ordenara por llegada, un
//! ataque repartido en dos dias pareceria un pico de un segundo. Ver
//! [`esquema::ConfianzaReloj`].
//!
//! **4. La normalizacion es determinista y se puede medir.** El mismo registro
//! crudo produce siempre el mismo evento, byte a byte, incluido su
//! identificador; y lo que no encaja en la taxonomia **se cuenta** en vez de
//! guardarse como texto libre. De ahi sale [`Contadores::cobertura`], que es una
//! cifra y no una promesa.
//!
//! # Lo que se reutiliza en vez de duplicarse
//!
//! El diario durable de la FASE 46 (`aegis-firehose::Diario`) ya resuelve el
//! problema de tener registros en disco hasta que alguien los acusa. Aqui **se
//! usa**, no se reescribe: dos verdades sobre la durabilidad son dos verdades
//! que un dia divergen, y ese dia se pierde evidencia.

#![forbid(unsafe_code)]

pub mod clasifica;
pub mod error;
pub mod esquema;
pub mod evtx;
pub mod syslog;
pub mod tiempo;

#[cfg(feature = "endpoint")]
pub mod cola;
#[cfg(feature = "endpoint")]
pub mod fichero;
#[cfg(feature = "endpoint")]
pub mod journald;
#[cfg(feature = "endpoint")]
pub mod punto;

pub use error::{ErrorIngesta, Resultado};
pub use esquema::{Clase, Evento, Origen, Prioridad, Resultado as ResultadoEvento, Severidad};

#[cfg(feature = "endpoint")]
mod tuberia;
#[cfg(feature = "endpoint")]
pub use tuberia::{Config, Fuente, Ingesta};

/// Lo que todo analizador necesita saber y no esta en el registro.
///
/// Va en una estructura y no en parametros sueltos porque el inquilino es un
/// dato de seguridad: un evento que pierde su inquilino por el camino puede
/// acabar en el panel de otro cliente, y eso no puede depender de que quien
/// llame se acuerde de pasar el argumento en la posicion correcta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contexto {
    /// A que cliente pertenece lo que se ingiere.
    pub inquilino: String,
    /// Maquina que se atribuye a un registro que no dice de cual viene.
    pub anfitrion_por_defecto: String,
    /// Cuando se leyo, en nanosegundos Unix.
    pub observado_ns: u64,
    /// Si se conserva el registro original junto al normalizado.
    ///
    /// Cuesta memoria y disco, y aun asi el valor por defecto en una instalacion
    /// de seguridad es conservarlo: si la normalizacion se equivoco, el crudo es
    /// lo unico que permite verlo despues, y en una investigacion se mira.
    pub conservar_crudo: bool,
}

impl Contexto {
    /// Contexto con la hora actual del sistema.
    #[must_use]
    pub fn ahora(inquilino: impl Into<String>, anfitrion: impl Into<String>) -> Contexto {
        Contexto {
            inquilino: inquilino.into(),
            anfitrion_por_defecto: anfitrion.into(),
            observado_ns: ahora_ns(),
            conservar_crudo: true,
        }
    }
}

/// Nanosegundos Unix de ahora mismo.
///
/// Se aplasta a cero si el reloj esta antes de la epoca: un sistema con la BIOS
/// a 1970 existe, y devolver un error aqui dejaria al agente sin ingerir nada en
/// vez de con eventos mal fechados —que al menos se marcan—.
#[must_use]
pub fn ahora_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Contadores de la normalizacion.
///
/// # Por que la cobertura es una cifra y no una promesa
///
/// «Normalizamos syslog» no significa nada. «El 94 % de las lineas de esta
/// maquina encajaron en una clase de la taxonomia, y estas cien no» es
/// accionable: alguien mira las cien, escribe la regla que falta, y la cifra
/// sube. Con un vocabulario abierto —una cadena libre por actividad— esta cifra
/// **no existiria**, porque todo «encajaria».
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Registros leidos.
    pub leidos: u64,
    /// Registros que produjeron un evento.
    pub normalizados: u64,
    /// Registros que encajaron en una regla concreta.
    pub especificos: u64,
    /// Registros que cayeron en el ultimo recurso de la taxonomia.
    pub genericos: u64,
    /// Registros que no se pudieron analizar.
    pub ilegibles: u64,
    /// Registros que superaban un tope.
    pub excedidos: u64,
}

impl Contadores {
    /// Porcentaje de registros que encajaron en una clase concreta.
    ///
    /// Devuelve `None` cuando todavia no se ha leido nada: cero de cero no es
    /// el cero por ciento, y publicarlo como tal haria saltar alarmas de
    /// cobertura en cada arranque.
    #[must_use]
    pub fn cobertura(&self) -> Option<u32> {
        if self.leidos == 0 {
            return None;
        }
        u32::try_from(self.especificos * 100 / self.leidos).ok()
    }

    /// Registros perdidos por no poder analizarse.
    #[must_use]
    pub fn perdidos(&self) -> u64 {
        self.ilegibles + self.excedidos
    }

    /// Anota el resultado de un intento de normalizar.
    pub fn anotar(&mut self, r: &Resultado<Evento>, especifico: bool) {
        self.leidos += 1;
        match r {
            Ok(_) => {
                self.normalizados += 1;
                if especifico {
                    self.especificos += 1;
                } else {
                    self.genericos += 1;
                }
            }
            Err(ErrorIngesta::Excedido { .. }) => self.excedidos += 1,
            Err(_) => self.ilegibles += 1,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_cobertura_no_existe_antes_de_leer_nada() {
        // Cero de cero no es el cero por ciento, y publicarlo como tal haria
        // saltar alarmas de cobertura en cada arranque.
        let k = Contadores::default();
        assert_eq!(k.cobertura(), None);
    }

    #[test]
    fn la_cobertura_sale_de_lo_que_encajo_en_una_clase_concreta() {
        let mut k = Contadores::default();
        let ctx = Contexto::ahora("cliente", "maquina");
        for _ in 0..94 {
            let e = syslog::normalizar(
                b"<38>1 2023-10-11T22:14:15Z h sshd - - - Failed password for r from 1.2.3.4 port 2 ssh2",
                "a#1",
                &ctx,
            );
            k.anotar(&e, true);
        }
        for _ in 0..6 {
            let e = syslog::normalizar(b"<13>1 - - propio - - - algo de la casa", "a#2", &ctx);
            k.anotar(&e, false);
        }
        assert_eq!(k.cobertura(), Some(94));
        assert_eq!(k.normalizados, 100);
        assert_eq!(k.perdidos(), 0);
    }

    #[test]
    fn lo_ilegible_y_lo_excedido_se_cuentan_por_separado() {
        // Un registro demasiado grande puede estar diciendo que los topes se
        // quedaron cortos; confundirlo con basura esconderia esa senal.
        let mut k = Contadores::default();
        let ctx = Contexto::ahora("c", "h");
        k.anotar(&syslog::normalizar(b"sin prioridad", "a#1", &ctx), false);
        k.anotar(
            &syslog::normalizar(&vec![b'x'; syslog::MAX_TRAMA + 1], "a#2", &ctx),
            false,
        );
        assert_eq!(k.ilegibles, 1);
        assert_eq!(k.excedidos, 1);
        assert_eq!(k.perdidos(), 2);
        assert_eq!(k.cobertura(), Some(0));
    }

    #[test]
    fn el_contexto_lleva_el_inquilino_y_no_se_puede_olvidar() {
        // Un evento que pierde su inquilino por el camino puede acabar en el
        // panel de otro cliente.
        let c = Contexto::ahora("cliente-7", "maquina-1");
        assert_eq!(c.inquilino, "cliente-7");
        assert!(c.conservar_crudo, "en seguridad, el crudo se guarda");
        assert!(c.observado_ns > 1_600_000_000_000_000_000);
    }
}
