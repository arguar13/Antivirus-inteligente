//! Credencial de par: la identidad del enjambre que un par NO puede inventarse.
//!
//! # El fallo que esto cierra (H-04)
//!
//! El quorum de K testigos contaba valores distintos de `Observacion::origen`,
//! un campo del cuerpo que rellena el propio emisor, y la firma del sobre no se
//! miraba. Un solo equipo comprometido mandaba tres observaciones con origenes
//! `e1`, `e2` y `e3` y cerraba el quorum el solo: un Sybil de tres lineas. La
//! doctrina decia «la identidad del origen es el CN de matriculacion»; el codigo
//! contaba un texto libre.
//!
//! # La identidad la concede el plano de control, antes del corte
//!
//! Al matricular un agente, el plano de control le emite una [`Credencial`]: su
//! CN de matriculacion, la clave publica HIBRIDA (Ed25519 + ML-DSA-65) con la que
//! ese agente firma sus observaciones y una vigencia, todo firmado con la MISMA
//! clave del plano de control que ya firma ordenes y artefactos
//! (`ConfigEnjambre::clave_plano_control`). No hay criptografia nueva: se
//! reutiliza `aegis_update::signature::ClaveActualizacion` para las dos firmas.
//!
//! Cada observacion viaja con la credencial de su emisor, y el emisor firma
//! `CTX_OBSERVACION || huella(credencial) || observacion`. El receptor, aislado,
//! lo comprueba todo sin preguntar a nadie:
//!
//! 1. la credencial la firmo el plano de control y esta vigente;
//! 2. la observacion la firmo la clave que esa credencial nombra;
//! 3. el origen declarado ES el CN de la credencial (si no, es una suplantacion);
//! 4. la observacion esta dentro de la ventana de corroboro (la firma cubre
//!    `vista_en`, asi que no se puede refrescar sin romperla).
//!
//! Lo unico que sale de ahi es un [`Testigo`]: un CN que el plano de control
//! firmo. El quorum solo acepta testigos, y un `Testigo` no se puede construir
//! fuera de este modulo sin pasar por [`Credencial::verificar`]. Fabricar K
//! testigos exige K credenciales, es decir, comprometer K equipos matriculados,
//! que es exactamente lo que el quorum promete.
//!
//! # Por que ni el `PeerId` de libp2p ni el certificado mTLS de la flota
//!
//! - El `PeerId` de `swarm-net` es efimero (`SwarmBuilder::with_new_identity`) y
//!   mDNS acepta a cualquiera de la red local: un equipo crea mil en un segundo.
//!   Sirve para repartir la cuota de tasa, no para contar testigos.
//! - El certificado mTLS de `aegis-fleet` autentica al agente ante el plano de
//!   control, no ante sus pares, y arrastraria rustls/ring al nucleo. Ademas, en
//!   una malla el que entrega el mensaje casi nunca es quien lo emitio: la
//!   identidad tiene que viajar CON el mensaje y verificarse en cualquier salto.
//!
//! # Lo que la credencial NO es
//!
//! No es autoridad. Con ella un par firma evidencia, nunca ordenes: las ordenes se
//! verifican contra la clave del plano de control con otro contexto de firma, y
//! levantar un aislamiento no viaja por el enjambre con ninguna firma
//! (invariante 10, `orden::Accion::gossipable`).
//!
//! # Limites, dichos
//!
//! - **Revocacion.** Una credencial robada vale hasta que caduca; por eso la
//!   vigencia esta acotada a [`MAX_VIGENCIA_SEG`]. No hay lista de revocacion que
//!   viaje por el enjambre.
//! - **K equipos comprometidos** siguen bastando. El quorum vale lo que cuesta
//!   comprometer K equipos matriculados, ni mas ni menos.

use aegis_update::signature::ClaveActualizacion;
use aegis_update::ClaveVerificacionHibrida;
use sha2::{Digest, Sha256};

use crate::error::ErrorEnjambre;
use crate::mensaje::{escribir_bloque, escribir_texto, escribir_u64, lector::Lector, MAX_TEXTO};
use crate::orden::HOLGURA_RELOJ_SEG;

/// Contexto de firma de las credenciales de par.
///
/// Distinto del de las ordenes y del de los artefactos: una credencial firmada no
/// se puede presentar como orden, ni al reves.
pub const CTX_CREDENCIAL: &[u8] = b"aegis-swarm/credencial/v1";

/// Vigencia maxima de una credencial: treinta dias.
///
/// Es la epoca de la identidad. Una credencial robada deja de servir, como mucho,
/// cuando acaba su vigencia; una credencial «para siempre» convertiria el robo de
/// un equipo dado de baja en un testigo eterno. Si el aislamiento dura mas que la
/// vigencia, el enjambre deja de corroborar: falla hacia no actuar, que es el
/// lado seguro para evidencia.
pub const MAX_VIGENCIA_SEG: u64 = 30 * 24 * 3600;

/// Identidad de un par **comprobada criptograficamente**.
///
/// Es lo unico que el quorum cuenta. Su campo es privado y el unico constructor
/// fuera de pruebas es [`Credencial::verificar`]: no existe un camino que
/// convierta un texto declarado en un testigo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Testigo {
    cn: String,
}

impl Testigo {
    /// El CN de matriculacion autenticado.
    #[must_use]
    pub fn cn(&self) -> &str {
        &self.cn
    }

    /// Solo para las pruebas unitarias del quorum, que ejercen el recuento sin
    /// criptografia. No existe fuera de `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn de_prueba(cn: &str) -> Testigo {
        Testigo { cn: cn.to_string() }
    }
}

/// Credencial de par emitida por el plano de control al matricular un agente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credencial {
    /// CN de matriculacion del agente.
    pub cn: String,
    /// Clave publica hibrida del agente, en el formato de
    /// `ClaveVerificacionHibrida::a_bytes`.
    pub clave_par: Vec<u8>,
    /// Inicio de la vigencia, en segundos Unix.
    pub valida_desde: u64,
    /// Fin de la vigencia, en segundos Unix.
    pub valida_hasta: u64,
    /// Firma del plano de control sobre [`Credencial::bytes_firmados`].
    pub firma_plano: Vec<u8>,
}

impl Credencial {
    fn escribir_contenido(&self, v: &mut Vec<u8>) {
        escribir_texto(v, &self.cn);
        escribir_bloque(v, &self.clave_par);
        escribir_u64(v, self.valida_desde);
        escribir_u64(v, self.valida_hasta);
    }

    /// Los bytes que firma el plano de control.
    #[must_use]
    pub fn bytes_firmados(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(CTX_CREDENCIAL);
        self.escribir_contenido(&mut v);
        v
    }

    /// Huella del contenido firmado de la credencial.
    ///
    /// Entra en lo que firma el par: una firma de observacion queda atada a ESTA
    /// credencial (este CN, esta clave, esta vigencia) y no se puede trasplantar a
    /// otra.
    #[must_use]
    pub fn huella(&self) -> [u8; 32] {
        Sha256::digest(self.bytes_firmados()).into()
    }

    /// Serializa la credencial.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.escribir_contenido(&mut v);
        escribir_bloque(&mut v, &self.firma_plano);
        v
    }

    /// Analiza una credencial desde la red.
    ///
    /// # Errores
    /// Truncamiento, longitud mentirosa, texto que no es UTF-8 o bytes sobrantes.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Credencial, ErrorEnjambre> {
        let mut l = Lector::nuevo(bytes);
        let cn = l.texto("cn")?;
        let clave_par = l.bloque("clave_par")?.to_vec();
        let valida_desde = l.u64("valida_desde")?;
        let valida_hasta = l.u64("valida_hasta")?;
        let firma_plano = l.bloque("firma_plano")?.to_vec();
        if l.restante() != 0 {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "credencial_sobrante",
                valor: l.restante(),
                tope: 0,
            });
        }
        Ok(Credencial {
            cn,
            clave_par,
            valida_desde,
            valida_hasta,
            firma_plano,
        })
    }

    /// Limites estructurales, antes de tocar criptografia.
    ///
    /// # Errores
    /// [`ErrorEnjambre::LimiteExcedido`] si el CN esta vacio o es desmesurado, o
    /// si la vigencia esta invertida o pasa de [`MAX_VIGENCIA_SEG`].
    pub fn validar(&self) -> Result<(), ErrorEnjambre> {
        if self.cn.is_empty() || self.cn.len() > MAX_TEXTO {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "cn",
                valor: self.cn.len(),
                tope: MAX_TEXTO,
            });
        }
        let tope = usize::try_from(MAX_VIGENCIA_SEG).unwrap_or(usize::MAX);
        let Some(vigencia) = self.valida_hasta.checked_sub(self.valida_desde) else {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "vigencia_invertida",
                valor: usize::MAX,
                tope,
            });
        };
        if vigencia > MAX_VIGENCIA_SEG {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "vigencia_credencial",
                valor: usize::try_from(vigencia).unwrap_or(usize::MAX),
                tope,
            });
        }
        Ok(())
    }

    /// Comprueba la credencial entera y devuelve la clave del par y su testigo.
    ///
    /// Mismo orden que `Orden::verificar`: limites, firma, y la ventana temporal
    /// al final, porque solo tiene sentido discutir la vigencia de algo que ya se
    /// sabe autentico.
    ///
    /// # Errores
    /// [`ErrorEnjambre::LimiteExcedido`], [`ErrorEnjambre::FirmaInvalida`] si el
    /// plano de control no la firmo o la clave del par no es una clave hibrida
    /// valida, [`ErrorEnjambre::Caducada`] o [`ErrorEnjambre::DelFuturo`].
    pub fn verificar(
        &self,
        clave_plano: &ClaveActualizacion,
        ahora: u64,
    ) -> Result<(ClaveActualizacion, Testigo), ErrorEnjambre> {
        self.validar()?;
        clave_plano
            .verificar(&self.bytes_firmados(), CTX_CREDENCIAL, &self.firma_plano)
            .map_err(|e| ErrorEnjambre::FirmaInvalida(e.to_string()))?;
        // Solo hibrida: un par nuevo no tiene legado que conservar, y aceptar aqui
        // una clave clasica seria abrir un downgrade en un protocolo que nace hoy.
        let clave = ClaveVerificacionHibrida::desde_bytes(&self.clave_par)
            .map_err(|e| ErrorEnjambre::FirmaInvalida(e.to_string()))?;
        if ahora > self.valida_hasta {
            return Err(ErrorEnjambre::Caducada {
                caduca_en: self.valida_hasta,
                ahora,
            });
        }
        if self.valida_desde > ahora.saturating_add(HOLGURA_RELOJ_SEG) {
            return Err(ErrorEnjambre::DelFuturo {
                emitida_en: self.valida_desde,
                ahora,
            });
        }
        Ok((
            ClaveActualizacion::Hibrida(Box::new(clave)),
            Testigo {
                cn: self.cn.clone(),
            },
        ))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn credencial() -> Credencial {
        Credencial {
            cn: "endpoint-17".to_string(),
            clave_par: vec![7u8; 40],
            valida_desde: 1_000,
            valida_hasta: 2_000,
            firma_plano: vec![9u8; 64],
        }
    }

    #[test]
    fn una_credencial_va_y_vuelve_sin_perder_nada() {
        let c = credencial();
        assert_eq!(Credencial::desde_bytes(&c.a_bytes()).expect("vuelta"), c);
    }

    #[test]
    fn cualquier_prefijo_de_una_credencial_se_rechaza_sin_panico() {
        let bytes = credencial().a_bytes();
        for corte in 0..bytes.len() {
            assert!(Credencial::desde_bytes(&bytes[..corte]).is_err());
        }
    }

    /// Bytes de mas detras de la credencial la harian cambiar de identificador
    /// de mensaje sin cambiar de contenido: se rechazan.
    #[test]
    fn bytes_sobrantes_tras_la_credencial_se_rechazan() {
        let mut bytes = credencial().a_bytes();
        bytes.push(0);
        assert!(Credencial::desde_bytes(&bytes).is_err());
    }

    /// La firma del plano de control cubre CN, clave y vigencia: cambiar
    /// cualquiera cambia lo firmado. La firma misma no entra en la huella.
    #[test]
    fn lo_firmado_cubre_cn_clave_y_vigencia() {
        let base = credencial();
        let mut otra = base.clone();
        otra.cn = "endpoint-18".to_string();
        assert_ne!(base.bytes_firmados(), otra.bytes_firmados());
        let mut otra = base.clone();
        otra.clave_par[0] ^= 1;
        assert_ne!(base.bytes_firmados(), otra.bytes_firmados());
        let mut otra = base.clone();
        otra.valida_hasta += 1;
        assert_ne!(base.bytes_firmados(), otra.bytes_firmados());
        let mut otra = base.clone();
        otra.firma_plano[0] ^= 1;
        assert_eq!(base.huella(), otra.huella());
    }

    #[test]
    fn el_contexto_de_credencial_no_es_el_de_ordenes_ni_el_de_artefactos() {
        assert!(credencial().bytes_firmados().starts_with(CTX_CREDENCIAL));
        assert_ne!(CTX_CREDENCIAL, crate::orden::CTX_ORDEN);
        assert_ne!(CTX_CREDENCIAL, crate::artefacto::CTX_ARTEFACTO);
        assert_ne!(CTX_CREDENCIAL, crate::observacion::CTX_OBSERVACION);
    }

    #[test]
    fn un_cn_vacio_o_una_vigencia_desmesurada_o_invertida_se_rechazan() {
        let mut c = credencial();
        c.cn = String::new();
        assert!(c.validar().is_err(), "sin CN no hay a quien contar");

        let mut c = credencial();
        c.valida_hasta = c.valida_desde + MAX_VIGENCIA_SEG + 1;
        assert!(
            c.validar().is_err(),
            "una credencial eterna es un testigo eterno"
        );

        let mut c = credencial();
        c.valida_hasta = c.valida_desde - 1;
        assert!(c.validar().is_err());

        let mut c = credencial();
        c.valida_hasta = c.valida_desde + MAX_VIGENCIA_SEG;
        assert!(c.validar().is_ok(), "el tope exacto se admite");
    }
}
