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
//! # Quien es «distinto»: la identidad autenticada, nunca el campo `origen`
//!
//! Todo lo anterior solo es verdad si el par no puede inventarse su nombre. Por
//! eso una observacion viaja con la [`Credencial`] de su emisor —firmada por el
//! plano de control al matricularlo— y con la firma del emisor sobre
//! [`Observacion::bytes_firmados`]. [`verificar`] comprueba las dos firmas, exige
//! que `origen` sea el CN de la credencial y devuelve un
//! [`Testigo`](crate::credencial::Testigo), que es lo unico que el quorum cuenta.
//! El campo `origen` se conserva para describir el hallazgo; **no cuenta**.
//!
//! Ver [`crate::credencial`] para el porque y los limites (H-04).
//!
//! # La honestidad del limite
//!
//! El quorum vale lo que cuesta comprometer K endpoints matriculados. **No
//! defiende** contra un adversario que ya controla K equipos de la flota, y no
//! se debe vender como si lo hiciera. Lo que si hace, y es mucho, es que un solo
//! equipo comprometido no pueda mover nada, que es el caso abrumadoramente mas
//! comun.
//!
//! # Solo se anade
//!
//! Igual que las vacunas de la FASE 23, una observacion **solo puede afirmar**
//! que algo es sospechoso. No existe la observacion que dice «esto es benigno,
//! quitalo de la lista»: retirar proteccion es justo lo que el atacante quiere,
//! y por eso no esta en el vocabulario del protocolo. No es una comprobacion que
//! se pueda olvidar: es que el tipo no puede expresarlo.

use aegis_sync::ioc::{Ioc, IocKind};
use aegis_update::signature::ClaveActualizacion;

use crate::credencial::{Credencial, Testigo};
use crate::error::ErrorEnjambre;
use crate::mensaje::{escribir_bloque, escribir_texto, escribir_u64, lector::Lector, MAX_TEXTO};
use crate::orden::HOLGURA_RELOJ_SEG;

/// Contexto de firma de las observaciones: lo usa el PAR, con su clave.
pub const CTX_OBSERVACION: &[u8] = b"aegis-swarm/observacion/v1";

/// Lo que un agente vio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observacion {
    /// Quien dice haberlo visto. Tiene que coincidir con el CN de la credencial
    /// que firma; el quorum no lo lee, cuenta el [`Testigo`] autenticado.
    pub origen: String,
    /// El indicador observado.
    pub indicador: Ioc,
    /// Tecnica MITRE que lo motiva, si se supo clasificar.
    pub tecnica: String,
    /// Confianza local del emisor, de 0 a 100.
    pub confianza: u8,
    /// Cuando se vio, en segundos Unix. Va dentro de lo firmado: es lo que ata
    /// la observacion a su ventana y hace inutil reinyectarla mas tarde.
    pub vista_en: u64,
}

impl Observacion {
    /// Los bytes que firma el par: contexto, huella de SU credencial y la
    /// observacion.
    ///
    /// La huella ata la firma a una credencial concreta: la misma firma no vale
    /// presentada con otra credencial, aunque sea del mismo equipo.
    #[must_use]
    pub fn bytes_firmados(&self, credencial: &Credencial) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(CTX_OBSERVACION);
        v.extend_from_slice(&credencial.huella());
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

/// Cuerpo de un sobre de observacion: la credencial del emisor y la observacion.
///
/// La firma del par va en `Sobre::firma`, como la del plano de control en las
/// ordenes.
#[must_use]
pub fn empaquetar(credencial: &Credencial, o: &Observacion) -> Vec<u8> {
    let mut v = Vec::new();
    escribir_bloque(&mut v, &credencial.a_bytes());
    v.extend_from_slice(&o.a_bytes());
    v
}

/// Separa el cuerpo de un sobre de observacion.
///
/// Exige forma canonica: lo que se lee, reserializado, tiene que dar los mismos
/// bytes. Sin eso, un reenviador podria anadir relleno o variar una codificacion
/// equivalente y obtener otro identificador de mensaje con el mismo contenido.
///
/// # Errores
/// Los de [`Credencial::desde_bytes`] y [`Observacion::desde_bytes`], o
/// [`ErrorEnjambre::LimiteExcedido`] si la observacion no esta en forma canonica.
pub fn desempaquetar(cuerpo: &[u8]) -> Result<(Credencial, Observacion), ErrorEnjambre> {
    let mut l = Lector::nuevo(cuerpo);
    let credencial = Credencial::desde_bytes(l.bloque("credencial")?)?;
    let resto = &cuerpo[cuerpo.len() - l.restante()..];
    let o = Observacion::desde_bytes(resto)?;
    if o.a_bytes() != resto {
        return Err(ErrorEnjambre::LimiteExcedido {
            campo: "observacion_no_canonica",
            valor: resto.len(),
            tope: o.a_bytes().len(),
        });
    }
    Ok((credencial, o))
}

/// Verifica una observacion recibida y devuelve **quien** la atestigua.
///
/// Orden de las comprobaciones, el mismo que en `Orden::verificar`:
///
/// 1. **Formato y limites**, sin criptografia.
/// 2. **Credencial**: firmada por el plano de control y vigente.
/// 3. **Firma del par** sobre esta observacion y esta credencial.
/// 4. **Origen = CN autenticado.** Si no coincide, la firma es buena y el emisor
///    esta matriculado: es un equipo de la flota intentando pasar por otro, y se
///    informa como tal ([`ErrorEnjambre::OrigenSuplantado`]).
/// 5. **Ventana**: ni del futuro mas alla de la holgura, ni mas vieja que la
///    ventana de corroboro. Como `vista_en` va firmado, una observacion grabada y
///    reinyectada fuera de su ventana no se puede rejuvenecer sin romper la firma.
///
/// # Errores
/// Los de formato, [`ErrorEnjambre::FirmaInvalida`],
/// [`ErrorEnjambre::OrigenSuplantado`], [`ErrorEnjambre::Caducada`] o
/// [`ErrorEnjambre::DelFuturo`].
pub fn verificar(
    clave_plano: &ClaveActualizacion,
    cuerpo: &[u8],
    firma: &[u8],
    ahora: u64,
    ventana_seg: u64,
) -> Result<(Testigo, Observacion), ErrorEnjambre> {
    let (credencial, o) = desempaquetar(cuerpo)?;
    o.validar()?;

    let (clave_par, testigo) = credencial.verificar(clave_plano, ahora)?;

    clave_par
        .verificar(&o.bytes_firmados(&credencial), CTX_OBSERVACION, firma)
        .map_err(|e| ErrorEnjambre::FirmaInvalida(e.to_string()))?;

    if o.origen != testigo.cn() {
        return Err(ErrorEnjambre::OrigenSuplantado {
            declarado: o.origen,
            autenticado: testigo.cn().to_string(),
        });
    }

    if o.vista_en > ahora.saturating_add(HOLGURA_RELOJ_SEG) {
        return Err(ErrorEnjambre::DelFuturo {
            emitida_en: o.vista_en,
            ahora,
        });
    }
    if ahora.saturating_sub(o.vista_en) > ventana_seg {
        return Err(ErrorEnjambre::Caducada {
            caduca_en: o.vista_en.saturating_add(ventana_seg),
            ahora,
        });
    }
    Ok((testigo, o))
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

    fn credencial(cn: &str) -> Credencial {
        Credencial {
            cn: cn.to_string(),
            clave_par: vec![7u8; 40],
            valida_desde: 0,
            valida_hasta: 1_000,
            firma_plano: vec![9u8; 64],
        }
    }

    #[test]
    fn una_observacion_va_y_vuelve_sin_perder_nada() {
        let o = obs("endpoint-3", "a".repeat(64).as_str());
        assert_eq!(Observacion::desde_bytes(&o.a_bytes()).expect("vuelta"), o);
    }

    #[test]
    fn un_cuerpo_con_credencial_va_y_vuelve_sin_perder_nada() {
        let c = credencial("endpoint-3");
        let o = obs("endpoint-3", "deadbeef");
        let (c2, o2) = desempaquetar(&empaquetar(&c, &o)).expect("vuelta");
        assert_eq!(c2, c);
        assert_eq!(o2, o);
    }

    #[test]
    fn cualquier_prefijo_de_un_cuerpo_con_credencial_se_rechaza_sin_panico() {
        let bytes = empaquetar(&credencial("e"), &obs("e", "x"));
        for corte in 0..bytes.len() {
            assert!(desempaquetar(&bytes[..corte]).is_err());
        }
    }

    /// Relleno detras de la observacion cambiaria el identificador del mensaje
    /// sin cambiar lo que dice: se rechaza.
    #[test]
    fn un_cuerpo_con_relleno_no_es_canonico_y_se_rechaza() {
        let mut bytes = empaquetar(&credencial("e"), &obs("e", "x"));
        bytes.push(0);
        assert!(desempaquetar(&bytes).is_err());
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
        assert!(o
            .bytes_firmados(&credencial("e1"))
            .starts_with(CTX_OBSERVACION));
        assert_ne!(CTX_OBSERVACION, crate::orden::CTX_ORDEN);
    }

    /// La firma del par queda atada a su credencial: la misma observacion bajo
    /// otra credencial son otros bytes firmados.
    #[test]
    fn lo_firmado_por_el_par_depende_de_su_credencial_y_de_cuando_lo_vio() {
        let o = obs("e1", "x");
        assert_ne!(
            o.bytes_firmados(&credencial("e1")),
            o.bytes_firmados(&credencial("e2"))
        );
        let mut tarde = o.clone();
        tarde.vista_en += 1;
        assert_ne!(
            o.bytes_firmados(&credencial("e1")),
            tarde.bytes_firmados(&credencial("e1")),
            "vista_en va firmado: rejuvenecer una observacion rompe su firma"
        );
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
