//! Observaciones: lo que un par puede decir por su cuenta.
//!
//! # La diferencia con una orden, que es toda la seguridad de la fase
//!
//! Una [`crate::orden::Orden`] MANDA hacer algo y por eso exige la firma del
//! plano de control. Una observacion **cuenta lo que un agente vio en su
//! maquina** y no manda nada: es evidencia. Un par puede emitirla por su cuenta
//! porque no concede autoridad sobre nadie.
//!
//! Lo que convierte evidencia en accion no es la observacion, es el
//! **corroboro**: la politica local actua cuando K pares DISTINTOS han visto lo
//! mismo ([`crate::quorum`]). Eso transforma «un endpoint comprometido mueve a
//! toda la flota» en «hacen falta K endpoints comprometidos», que es exactamente
//! el objetivo.
//!
//! # La honestidad del limite
//!
//! El quorum vale lo que cuesta comprometer K endpoints matriculados. **No
//! defiende** contra un adversario que ya controla K equipos de la flota, y no
//! se debe vender como si lo hiciera. Lo que si hace, y es mucho, es que un solo
//! equipo comprometido no pueda mover nada, que es el caso abrumadoramente mas
//! comun.
//!
//! La identidad del origen es el **CN de matriculacion** (el mismo del mTLS de
//! la flota), no un identificador que el par elija: si el par pudiera inventar
//! su nombre, fabricaria K identidades desde una maquina y el quorum no valdria
//! nada. Esa es la propiedad de la que depende todo lo demas, y esta anotada
//! aqui porque quien toque este modulo tiene que saberlo.
//!
//! # Solo se anade
//!
//! Igual que las vacunas de la FASE 23, una observacion **solo puede afirmar**
//! que algo es sospechoso. No existe la observacion que dice «esto es benigno,
//! quitalo de la lista»: retirar proteccion es justo lo que el atacante quiere,
//! y por eso no esta en el vocabulario del protocolo. No es una comprobacion que
//! se pueda olvidar: es que el tipo no puede expresarlo.

use aegis_sync::ioc::{Ioc, IocKind};

use crate::error::ErrorEnjambre;
use crate::mensaje::{escribir_texto, escribir_u64, lector::Lector, MAX_TEXTO};

/// Contexto de firma de las observaciones.
pub const CTX_OBSERVACION: &[u8] = b"aegis-swarm/observacion/v1";

/// Lo que un agente vio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observacion {
    /// Quien lo vio: CN de matriculacion, no un nombre que el par elija.
    pub origen: String,
    /// El indicador observado.
    pub indicador: Ioc,
    /// Tecnica MITRE que lo motiva, si se supo clasificar.
    pub tecnica: String,
    /// Confianza local del emisor, de 0 a 100.
    pub confianza: u8,
    /// Cuando se vio, en segundos Unix.
    pub vista_en: u64,
}

impl Observacion {
    /// Los bytes que cubre la firma del par.
    #[must_use]
    pub fn bytes_firmados(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(CTX_OBSERVACION);
        v.extend_from_slice(&self.a_bytes());
        v
    }

    /// Serializa la observacion.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        escribir_texto(&mut v, &self.origen);
        v.push(self.indicador.kind.tag());
        escribir_texto(&mut v, &self.indicador.value);
        escribir_texto(&mut v, &self.tecnica);
        v.push(self.confianza);
        escribir_u64(&mut v, self.vista_en);
        v
    }

    /// Analiza una observacion desde la red.
    ///
    /// # Errores
    /// Truncamiento, tipo de indicador desconocido, longitud mentirosa o texto
    /// que no es UTF-8.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Observacion, ErrorEnjambre> {
        let mut l = Lector::nuevo(bytes);
        let origen = l.texto("origen")?;
        let tag = l.u8("tipo_indicador")?;
        let kind = IocKind::from_tag(tag).ok_or(ErrorEnjambre::IndicadorDesconocido(tag))?;
        let value = l.texto("valor_indicador")?;
        let tecnica = l.texto("tecnica")?;
        let confianza = l.u8("confianza")?;
        let vista_en = l.u64("vista_en")?;
        Ok(Observacion {
            origen,
            indicador: Ioc { kind, value },
            tecnica,
            confianza: confianza.min(100),
            vista_en,
        })
    }

    /// Clave de corroboro: **el indicador, no el emisor**.
    ///
    /// Dos pares que ven el mismo hash tienen que caer en el mismo cubo para que
    /// se cuenten como corroboro. Si la clave incluyera el origen, cada par
    /// tendria su propio cubo de uno y el quorum no se alcanzaria jamas.
    #[must_use]
    pub fn clave_corroboro(&self) -> (u8, &str) {
        (self.indicador.kind.tag(), self.indicador.value.as_str())
    }

    /// Comprueba los limites estructurales antes de tocar criptografia.
    ///
    /// # Errores
    /// [`ErrorEnjambre::LimiteExcedido`] si un texto pasa del tope.
    pub fn validar(&self) -> Result<(), ErrorEnjambre> {
        for (campo, s) in [
            ("origen", &self.origen),
            ("valor_indicador", &self.indicador.value),
            ("tecnica", &self.tecnica),
        ] {
            if s.len() > MAX_TEXTO {
                return Err(ErrorEnjambre::LimiteExcedido {
                    campo,
                    valor: s.len(),
                    tope: MAX_TEXTO,
                });
            }
        }
        if self.origen.is_empty() {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "origen",
                valor: 0,
                tope: MAX_TEXTO,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn obs(origen: &str, valor: &str) -> Observacion {
        Observacion {
            origen: origen.to_string(),
            indicador: Ioc {
                kind: IocKind::FileSha256,
                value: valor.to_string(),
            },
            tecnica: "T1059.001".to_string(),
            confianza: 80,
            vista_en: 1_000_000,
        }
    }

    #[test]
    fn una_observacion_va_y_vuelve_sin_perder_nada() {
        let o = obs("endpoint-3", "a".repeat(64).as_str());
        assert_eq!(Observacion::desde_bytes(&o.a_bytes()).expect("vuelta"), o);
    }

    /// La clave de corroboro NO puede incluir el origen: si lo incluyera, cada
    /// par tendria su cubo de uno y el quorum no se alcanzaria nunca.
    #[test]
    fn dos_pares_que_ven_lo_mismo_caen_en_la_misma_clave_de_corroboro() {
        let a = obs("endpoint-3", "deadbeef");
        let b = obs("endpoint-9", "deadbeef");
        assert_eq!(a.clave_corroboro(), b.clave_corroboro());

        let c = obs("endpoint-3", "otracosa");
        assert_ne!(a.clave_corroboro(), c.clave_corroboro());
    }

    #[test]
    fn el_contexto_de_firma_es_propio_y_distinto_del_de_las_ordenes() {
        let o = obs("e1", "x");
        assert!(o.bytes_firmados().starts_with(CTX_OBSERVACION));
        assert_ne!(CTX_OBSERVACION, crate::orden::CTX_ORDEN);
    }

    #[test]
    fn una_observacion_truncada_se_rechaza_sin_panico() {
        let bytes = obs("endpoint-3", "deadbeef").a_bytes();
        for corte in 0..bytes.len() {
            assert!(Observacion::desde_bytes(&bytes[..corte]).is_err());
        }
        assert!(Observacion::desde_bytes(&bytes).is_ok());
    }

    #[test]
    fn un_tipo_de_indicador_desconocido_se_rechaza() {
        let mut bytes = obs("e", "x").a_bytes();
        // Tras el texto del origen ("e": 2 bytes de longitud + 1 de contenido).
        bytes[3] = 99;
        assert_eq!(
            Observacion::desde_bytes(&bytes),
            Err(ErrorEnjambre::IndicadorDesconocido(99))
        );
    }

    #[test]
    fn un_origen_vacio_se_rechaza_porque_no_puede_contar_para_el_quorum() {
        let mut o = obs("", "x");
        o.origen = String::new();
        assert!(o.validar().is_err(), "sin origen no hay a quien atribuir");
    }

    #[test]
    fn un_texto_desmesurado_se_rechaza() {
        let o = obs("e", &"x".repeat(MAX_TEXTO + 1));
        assert!(matches!(
            o.validar(),
            Err(ErrorEnjambre::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn la_confianza_se_acota_al_analizar_en_vez_de_creerse_un_201() {
        let mut bytes = obs("e", "x").a_bytes();
        let ultimo = bytes.len() - 9;
        bytes[ultimo] = 201;
        let o = Observacion::desde_bytes(&bytes).expect("valida");
        assert_eq!(o.confianza, 100, "una confianza de 201 no existe");
    }
}
