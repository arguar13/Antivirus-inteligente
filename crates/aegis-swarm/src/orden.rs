//! Ordenes de contencion: lo unico del enjambre que manda hacer algo.
//!
//! # El problema que define este modulo
//!
//! Una orden de cuarentena que se propaga de agente a agente es, si se disena
//! mal, **una primitiva de movimiento lateral regalada al atacante**. Quien
//! comprometa UN endpoint y pueda decirle al enjambre «aisla al equipo X»
//! consigue de golpe un boton de denegacion de servicio sobre toda la flota, y
//! algo peor: puede aislar precisamente las maquinas que lo habrian detectado, o
//! el salto del SOC desde el que se responde.
//!
//! La FASE 23 esquivo el problema declarando que una vacuna solo puede ANADIR
//! indicadores, nunca retirarlos. Aqui no se puede esquivar, porque el requisito
//! es repartir ordenes. Hay que resolverlo.
//!
//! # La regla: el enjambre TRANSPORTA autoridad, no la CONCEDE
//!
//! Una orden solo es valida si trae una firma del **plano de control**, cuya
//! clave privada no esta en ningun agente. El enjambre no fabrica ordenes: lleva
//! ordenes que el plano de control YA emitio, cuando el enlace con el plano de
//! control no esta disponible. Es un transporte de ultimo recurso, no un
//! consenso.
//!
//! De ahi salen las tres defensas, y ninguna sobra:
//!
//! 1. **Firma hibrida con contexto propio.** Se verifica con
//!    [`ClaveActualizacion::verificar`] bajo [`CTX_ORDEN`], que es DISTINTO del
//!    contexto del canal de actualizaciones. Sin esa separacion de dominio, una
//!    firma legitima de otro canal podria reinterpretarse como una orden.
//! 2. **Ventana temporal y epoca monotona.** Una orden caduca, y una epoca ya
//!    superada para ese sujeto se rechaza. Sin esto, el atacante que provoca el
//!    aislamiento reproduce una orden antigua y valida: la firma verifica
//!    perfectamente, porque es autentica.
//! 3. **Clases que no viajan, firmadas o no.** Ver [`Accion::gossipable`].
//!
//! # Por que la tercera defensa no es criptografica
//!
//! Levantar un aislamiento, desactivar una regla o degradar la proteccion son
//! exactamente los efectos que el atacante quiere. Una orden de esas, **aunque
//! su firma sea autentica**, no puede aceptarse por el enjambre: reproducida en
//! el momento justo del corte, apaga la defensa con una firma valida de verdad.
//! Retirar proteccion exige el canal directo con el plano de control, que el
//! atacante tendria que comprometer aparte.
//!
//! Es la misma doctrina de la FASE 23 —solo se puede anadir proteccion, jamas
//! quitarla— llevada de los indicadores a las ordenes.

use aegis_update::signature::ClaveActualizacion;

use crate::error::ErrorEnjambre;
use crate::mensaje::{escribir_texto, escribir_u64, lector::Lector, MAX_TEXTO};

/// Contexto de firma de las ordenes del enjambre.
///
/// Separa el dominio: una firma del canal de actualizaciones no vale aqui, y una
/// orden del enjambre no vale alli.
pub const CTX_ORDEN: &[u8] = b"aegis-swarm/orden/v1";

/// Holgura de reloj admitida hacia el futuro, en segundos.
///
/// Los relojes de una flota no estan sincronizados al segundo. Cinco minutos
/// absorbe la deriva normal sin abrir una ventana util para reproducir.
pub const HOLGURA_RELOJ_SEG: u64 = 300;

/// Lo que una orden manda hacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Accion {
    /// Aislar el endpoint de la red (la misma orden que el boton de la consola).
    AislarRed,
    /// Matar los procesos del arbol indicado.
    MatarProceso,
    /// Poner un fichero en cuarentena.
    Cuarentena,
    /// Revocar los tickets Kerberos del sujeto.
    RevocarTickets,
    /// Levantar el aislamiento de red.
    LevantarAislamiento,
    /// Desactivar una regla de deteccion.
    DesactivarRegla,
    /// Bajar el nivel de proteccion del agente.
    DegradarProteccion,
}

impl Accion {
    /// Discriminante de red.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Accion::AislarRed => 1,
            Accion::MatarProceso => 2,
            Accion::Cuarentena => 3,
            Accion::RevocarTickets => 4,
            Accion::LevantarAislamiento => 200,
            Accion::DesactivarRegla => 201,
            Accion::DegradarProteccion => 202,
        }
    }

    /// Recupera la accion desde su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<Accion> {
        match t {
            1 => Some(Accion::AislarRed),
            2 => Some(Accion::MatarProceso),
            3 => Some(Accion::Cuarentena),
            4 => Some(Accion::RevocarTickets),
            200 => Some(Accion::LevantarAislamiento),
            201 => Some(Accion::DesactivarRegla),
            202 => Some(Accion::DegradarProteccion),
            _ => None,
        }
    }

    /// Nombre estable para el registro y la consola.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Accion::AislarRed => "aislar-red",
            Accion::MatarProceso => "matar-proceso",
            Accion::Cuarentena => "cuarentena",
            Accion::RevocarTickets => "revocar-tickets",
            Accion::LevantarAislamiento => "levantar-aislamiento",
            Accion::DesactivarRegla => "desactivar-regla",
            Accion::DegradarProteccion => "degradar-proteccion",
        }
    }

    /// Si esta accion puede viajar por el enjambre.
    ///
    /// **Solo las que ANADEN contencion.** Las que la retiran quedan fuera por
    /// clase, con firma valida o sin ella: reproducidas en el instante del corte
    /// apagan la defensa usando una firma autentica. Retirar proteccion exige el
    /// canal directo con el plano de control.
    #[must_use]
    pub fn gossipable(self) -> bool {
        match self {
            Accion::AislarRed
            | Accion::MatarProceso
            | Accion::Cuarentena
            | Accion::RevocarTickets => true,
            Accion::LevantarAislamiento | Accion::DesactivarRegla | Accion::DegradarProteccion => {
                false
            }
        }
    }
}

/// Una orden emitida por el plano de control.
///
/// Los campos van todos dentro de lo firmado: cambiar cualquiera invalida la
/// firma. Ver [`Orden::bytes_firmados`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orden {
    /// Que hacer.
    pub accion: Accion,
    /// Sobre quien: el CN del agente, o el identificador del recurso.
    pub sujeto: String,
    /// Incidente que la motiva, para que el endpoint pueda correlacionar.
    pub incidente: String,
    /// Epoca monotona por (accion, sujeto). Una epoca ya superada no se acepta.
    pub epoca: u64,
    /// Momento de emision, en segundos Unix.
    pub emitida_en: u64,
    /// Momento a partir del cual deja de valer.
    pub caduca_en: u64,
}

impl Orden {
    /// Los bytes exactos que cubre la firma.
    ///
    /// El formato es explicito y con longitudes por delante: si dos campos de
    /// texto se concatenaran sin longitud, `sujeto="ab"`+`incidente="c"` y
    /// `sujeto="a"`+`incidente="bc"` firmarian lo mismo, y una orden contra un
    /// equipo valdria contra otro.
    #[must_use]
    pub fn bytes_firmados(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.sujeto.len() + self.incidente.len());
        v.extend_from_slice(CTX_ORDEN);
        v.push(self.accion.tag());
        escribir_texto(&mut v, &self.sujeto);
        escribir_texto(&mut v, &self.incidente);
        escribir_u64(&mut v, self.epoca);
        escribir_u64(&mut v, self.emitida_en);
        escribir_u64(&mut v, self.caduca_en);
        v
    }

    /// Serializa la orden (sin la firma, que viaja aparte en el sobre).
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.accion.tag());
        escribir_texto(&mut v, &self.sujeto);
        escribir_texto(&mut v, &self.incidente);
        escribir_u64(&mut v, self.epoca);
        escribir_u64(&mut v, self.emitida_en);
        escribir_u64(&mut v, self.caduca_en);
        v
    }

    /// Analiza una orden desde su forma de red.
    ///
    /// # Errores
    /// Si esta truncada, si la accion no se conoce o si un texto miente sobre su
    /// longitud o no es UTF-8.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Orden, ErrorEnjambre> {
        let mut l = Lector::nuevo(bytes);
        let tag = l.u8("accion")?;
        let accion = Accion::desde_tag(tag).ok_or(ErrorEnjambre::AccionDesconocida(tag))?;
        let sujeto = l.texto("sujeto")?;
        let incidente = l.texto("incidente")?;
        Ok(Orden {
            accion,
            sujeto,
            incidente,
            epoca: l.u64("epoca")?,
            emitida_en: l.u64("emitida_en")?,
            caduca_en: l.u64("caduca_en")?,
        })
    }

    /// Clave de epoca: el par sobre el que la monotonia tiene que valer.
    #[must_use]
    pub fn clave_epoca(&self) -> (u8, &str) {
        (self.accion.tag(), self.sujeto.as_str())
    }

    /// Comprueba la orden entera: clase, firma y ventana temporal.
    ///
    /// El orden de las comprobaciones importa y es deliberado:
    ///
    /// 1. **Limites de tamano** primero, para no trabajar sobre algo absurdo.
    /// 2. **Clase** despues: una accion que no puede viajar se rechaza ANTES de
    ///    gastar una verificacion de firma post-cuantica, que es cara. Un
    ///    atacante que inunde con ordenes de «levantar aislamiento» no consigue
    ///    asi un amplificador de CPU.
    /// 3. **Firma** despues, porque es lo que establece la autenticidad.
    /// 4. **Ventana temporal** al final: solo tiene sentido discutir la frescura
    ///    de algo que ya se sabe autentico.
    ///
    /// # Errores
    /// [`ErrorEnjambre::AccionNoPropagable`], [`ErrorEnjambre::FirmaInvalida`],
    /// [`ErrorEnjambre::Caducada`] o [`ErrorEnjambre::DelFuturo`].
    pub fn verificar(
        &self,
        clave: &ClaveActualizacion,
        firma: &[u8],
        ahora: u64,
    ) -> Result<(), ErrorEnjambre> {
        if self.sujeto.len() > MAX_TEXTO {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "sujeto",
                valor: self.sujeto.len(),
                tope: MAX_TEXTO,
            });
        }
        if !self.accion.gossipable() {
            return Err(ErrorEnjambre::AccionNoPropagable(self.accion.nombre()));
        }
        clave
            .verificar(&self.bytes_firmados(), CTX_ORDEN, firma)
            .map_err(|e| ErrorEnjambre::FirmaInvalida(e.to_string()))?;
        if ahora > self.caduca_en {
            return Err(ErrorEnjambre::Caducada {
                caduca_en: self.caduca_en,
                ahora,
            });
        }
        if self.emitida_en > ahora.saturating_add(HOLGURA_RELOJ_SEG) {
            return Err(ErrorEnjambre::DelFuturo {
                emitida_en: self.emitida_en,
                ahora,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn orden(accion: Accion) -> Orden {
        Orden {
            accion,
            sujeto: "endpoint-17".to_string(),
            incidente: "inc-2026-0042".to_string(),
            epoca: 7,
            emitida_en: 1_000_000,
            caduca_en: 1_003_600,
        }
    }

    #[test]
    fn una_orden_va_y_vuelve_de_su_forma_de_red_sin_perder_nada() {
        for a in [
            Accion::AislarRed,
            Accion::MatarProceso,
            Accion::Cuarentena,
            Accion::RevocarTickets,
            Accion::LevantarAislamiento,
        ] {
            let o = orden(a);
            let vuelta = Orden::desde_bytes(&o.a_bytes()).expect("ida y vuelta");
            assert_eq!(o, vuelta, "la orden {} no sobrevive al viaje", a.nombre());
        }
    }

    /// LA REGLA DE CLASE. Retirar proteccion no viaja por el enjambre, y da
    /// igual lo buena que sea la firma: reproducida en el corte, apaga la
    /// defensa con una firma autentica.
    #[test]
    fn retirar_proteccion_no_es_propagable_aunque_la_firma_fuese_perfecta() {
        for a in [
            Accion::LevantarAislamiento,
            Accion::DesactivarRegla,
            Accion::DegradarProteccion,
        ] {
            assert!(
                !a.gossipable(),
                "{} no puede viajar por el enjambre",
                a.nombre()
            );
        }
        for a in [
            Accion::AislarRed,
            Accion::MatarProceso,
            Accion::Cuarentena,
            Accion::RevocarTickets,
        ] {
            assert!(a.gossipable(), "{} si tiene que poder viajar", a.nombre());
        }
    }

    /// Los discriminantes de red son un contrato entre versiones del agente: si
    /// se renumeran, dos agentes de versiones distintas interpretan la misma
    /// orden como acciones diferentes, y una de ellas sera la equivocada.
    #[test]
    fn los_discriminantes_son_estables_y_no_se_solapan() {
        let todas = [
            Accion::AislarRed,
            Accion::MatarProceso,
            Accion::Cuarentena,
            Accion::RevocarTickets,
            Accion::LevantarAislamiento,
            Accion::DesactivarRegla,
            Accion::DegradarProteccion,
        ];
        let mut vistos = Vec::new();
        for a in todas {
            assert!(
                !vistos.contains(&a.tag()),
                "discriminante repetido: {}",
                a.tag()
            );
            vistos.push(a.tag());
            assert_eq!(Accion::desde_tag(a.tag()), Some(a));
        }
        // Y las que retiran proteccion viven en un rango aparte (>= 200), para
        // que anadir una accion nueva no la haga propagable por descuido.
        for a in todas {
            assert_eq!(
                a.gossipable(),
                a.tag() < 200,
                "el rango y la clase tienen que decir lo mismo para {}",
                a.nombre()
            );
        }
    }

    /// Dos campos de texto concatenados sin longitud permiten mover el limite
    /// entre ellos y firmar lo mismo: una orden contra un equipo valdria contra
    /// otro.
    #[test]
    fn mover_el_limite_entre_sujeto_e_incidente_cambia_lo_firmado() {
        let a = Orden {
            sujeto: "ab".to_string(),
            incidente: "c".to_string(),
            ..orden(Accion::AislarRed)
        };
        let b = Orden {
            sujeto: "a".to_string(),
            incidente: "bc".to_string(),
            ..orden(Accion::AislarRed)
        };
        assert_ne!(
            a.bytes_firmados(),
            b.bytes_firmados(),
            "el marco de longitudes tiene que separar los campos"
        );
    }

    #[test]
    fn el_contexto_de_firma_entra_en_lo_firmado_y_es_propio_del_enjambre() {
        let o = orden(Accion::AislarRed);
        assert!(
            o.bytes_firmados().starts_with(CTX_ORDEN),
            "el contexto separa el dominio de firma del canal de actualizaciones"
        );
        assert_ne!(CTX_ORDEN, b"aegis-update/reglas/v1");
    }

    #[test]
    fn una_orden_truncada_se_rechaza_en_vez_de_leer_campos_inventados() {
        let o = orden(Accion::AislarRed);
        let bytes = o.a_bytes();
        for corte in 0..bytes.len() {
            let r = Orden::desde_bytes(&bytes[..corte]);
            assert!(r.is_err(), "un prefijo de {corte} bytes no es una orden");
        }
        assert!(Orden::desde_bytes(&bytes).is_ok());
    }

    #[test]
    fn una_accion_desconocida_se_rechaza_sin_panico() {
        let mut bytes = orden(Accion::AislarRed).a_bytes();
        bytes[0] = 99;
        assert_eq!(
            Orden::desde_bytes(&bytes),
            Err(ErrorEnjambre::AccionDesconocida(99))
        );
    }

    /// Hay DOS guardas distintas sobre la longitud de un texto y las dos tienen
    /// que ejercerse, porque protegen de cosas distintas: el tope absoluto
    /// impide que un par haga crecer la memoria del receptor con un nombre
    /// gigante, y la comprobacion contra lo que queda impide leer fuera del
    /// buffer. Una longitud enorme dispara la primera y nunca llega a la
    /// segunda, asi que probar solo con `0xFFFF` dejaria la segunda sin probar.
    #[test]
    fn una_longitud_de_texto_mentirosa_no_lee_fuera_de_rango() {
        // El texto del sujeto empieza en 1; su longitud es un u16 little-endian.
        let poner = |n: u16| {
            let mut b = orden(Accion::AislarRed).a_bytes();
            b[1..3].copy_from_slice(&n.to_le_bytes());
            b
        };

        // (a) Por encima del tope absoluto.
        assert!(
            matches!(
                Orden::desde_bytes(&poner(u16::MAX)),
                Err(ErrorEnjambre::LimiteExcedido { .. })
            ),
            "una longitud desmesurada tiene que chocar con el tope"
        );

        // (b) Por debajo del tope pero mas alla de lo que queda en el buffer.
        let dentro_del_tope = u16::try_from(MAX_TEXTO).expect("cabe") - 1;
        assert!(
            matches!(
                Orden::desde_bytes(&poner(dentro_del_tope)),
                Err(ErrorEnjambre::LongitudImposible { .. })
            ),
            "una longitud creible pero imposible tiene que chocar con el buffer"
        );
    }

    #[test]
    fn la_clave_de_epoca_distingue_accion_y_sujeto() {
        let a = orden(Accion::AislarRed);
        let mut b = orden(Accion::AislarRed);
        b.sujeto = "endpoint-18".to_string();
        let c = orden(Accion::Cuarentena);
        assert_ne!(a.clave_epoca(), b.clave_epoca());
        assert_ne!(a.clave_epoca(), c.clave_epoca());
    }
}
