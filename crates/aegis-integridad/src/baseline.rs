//! La linea base FIRMADA por el plano de control y SELLADA contra el TPM.
//!
//! # El fallo clasico de AIDE y de Tripwire
//!
//! Un atacante con root reescribe el fichero, y luego reescribe la base de datos
//! de integridad y la vuelve a calcular. Al comparar, todo cuadra: la puerta
//! trasera pasa a formar parte del «estado bueno». Con root, la linea base local
//! no vale nada.
//!
//! Aqui la linea base la FIRMA el plano de control con la firma hibrida (Ed25519 +
//! ML-DSA-65) y se SELLA contra un conjunto de PCR del TPM. Root puede reescribir
//! los bytes de la linea base cuanto quiera, pero **no puede volver a firmarla**
//! sin la clave privada del plano de control, y no puede reproducir un sello de
//! un arranque que no ocurrio. Reescribir y recalcular ya no basta: la firma no
//! verifica, y el cambio se ve.
//!
//! # La frontera
//!
//! Sellar y des-sellar de verdad exige hablar con el chip TPM; esa fontaneria
//! vive, como en `aegis-attest`, tras una feature de hardware. Aqui esta la parte
//! que puede estar MAL de forma peligrosa —VERIFICAR la firma y el sello— en Rust
//! puro, probada con firmas hibridas REALES en cada `make ci`.

use std::collections::BTreeMap;

use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida, FirmaHibrida};

use crate::semantica::{analizar_cambio, CambioSemantico, Formato};

/// El contexto de dominio de la firma: separa estas firmas de las de un OTP o de
/// cualquier otra cosa que firme el plano de control.
const DOMINIO: &[u8] = b"aegis-integridad::linea-base::v1";

/// Un digest de PCR (un banco del TPM), modelado como 32 bytes.
pub type Pcr = [u8; 32];

/// Una entrada de la linea base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntradaBase {
    /// Un binario o un fichero opaco: solo su hash conocido-bueno.
    Binario {
        /// BLAKE3 del contenido conocido-bueno.
        huella: [u8; 32],
    },
    /// Un fichero de configuracion: se guarda su contenido conocido-bueno para
    /// poder comparar POR SIGNIFICADO, no solo por hash.
    Config {
        /// El formato que se sabe leer.
        formato: Formato,
        /// El contenido conocido-bueno.
        contenido: String,
    },
}

/// La linea base ya abierta (firma verificada y sello comprobado): ruta -> entrada.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineaBase {
    entradas: BTreeMap<String, EntradaBase>,
}

impl LineaBase {
    /// Una linea base vacia.
    #[must_use]
    pub fn nueva() -> LineaBase {
        LineaBase::default()
    }

    /// Anade un binario por su contenido conocido-bueno.
    #[must_use]
    pub fn con_binario(mut self, ruta: &str, contenido: &[u8]) -> LineaBase {
        self.entradas.insert(
            ruta.to_string(),
            EntradaBase::Binario {
                huella: *blake3::hash(contenido).as_bytes(),
            },
        );
        self
    }

    /// Anade un fichero de configuracion por su contenido conocido-bueno.
    #[must_use]
    pub fn con_config(mut self, ruta: &str, formato: Formato, contenido: &str) -> LineaBase {
        self.entradas.insert(
            ruta.to_string(),
            EntradaBase::Config {
                formato,
                contenido: contenido.to_string(),
            },
        );
        self
    }

    /// Numero de entradas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Si esta vacia.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Compara el contenido ACTUAL de un fichero contra la linea base.
    ///
    /// - Para un binario, un hash distinto es un solo cambio opaco (se representa
    ///   como una directiva sin significado, para el caso no-config).
    /// - Para una configuracion, devuelve los cambios POR SIGNIFICADO: un
    ///   comentario nuevo no aparece; una puerta trasera, si.
    ///
    /// Un fichero que no esta en la linea base devuelve vacio: no es una
    /// desviacion de un estado bueno que no se declaro.
    #[must_use]
    pub fn cambios(&self, ruta: &str, contenido_actual: &[u8]) -> Vec<CambioSemantico> {
        match self.entradas.get(ruta) {
            Some(EntradaBase::Config { formato, contenido }) => {
                let actual = String::from_utf8_lossy(contenido_actual);
                analizar_cambio(*formato, contenido, &actual)
            }
            Some(EntradaBase::Binario { huella }) => {
                if *blake3::hash(contenido_actual).as_bytes() == *huella {
                    Vec::new()
                } else {
                    // Un binario cambiado no tiene «significado» que parsear; se
                    // expresa como una directiva opaca para que el arbitro lo vea.
                    vec![CambioSemantico::DirectivaSsh {
                        clave: format!("contenido-binario::{ruta}"),
                        antes: Some("(hash conocido-bueno)".to_string()),
                        despues: Some("(hash distinto)".to_string()),
                    }]
                }
            }
            None => Vec::new(),
        }
    }

    /// Sella y firma esta linea base contra un PCR, produciendo la forma que se
    /// almacena y se transmite. Lo hace el plano de control, que tiene la clave.
    #[must_use]
    pub fn sellar(&self, pcr: Pcr, clave: &ClaveFirmaHibrida) -> Option<LineaBaseSellada> {
        let cuerpo = self.a_bytes();
        let mensaje = mensaje_a_firmar(&cuerpo, &pcr);
        let firma = clave.firmar(&mensaje, DOMINIO).ok()?;
        Some(LineaBaseSellada {
            cuerpo,
            pcr_sellado: pcr,
            firma,
        })
    }

    /// Codificacion canonica y determinista (el `BTreeMap` itera ordenado), para
    /// que dos lineas base iguales produzcan los mismos bytes y la misma firma.
    fn a_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.entradas.len() as u32).to_be_bytes());
        for (ruta, entrada) in &self.entradas {
            escribir_bytes(&mut out, ruta.as_bytes());
            match entrada {
                EntradaBase::Binario { huella } => {
                    out.push(0);
                    out.extend_from_slice(huella);
                }
                EntradaBase::Config { formato, contenido } => {
                    out.push(1);
                    out.push(codigo_formato(*formato));
                    escribir_bytes(&mut out, contenido.as_bytes());
                }
            }
        }
        out
    }

    /// Reconstruye una linea base desde su codificacion canonica. Sin panicos ante
    /// bytes corruptos: devuelve `None`.
    fn desde_bytes(bytes: &[u8]) -> Option<LineaBase> {
        let mut lector = Lector::new(bytes);
        let n = lector.u32()?;
        let mut entradas = BTreeMap::new();
        for _ in 0..n {
            let ruta = String::from_utf8(lector.bytes()?.to_vec()).ok()?;
            let tag = lector.u8()?;
            let entrada = match tag {
                0 => {
                    let h = lector.exactos(32)?;
                    let mut huella = [0u8; 32];
                    huella.copy_from_slice(h);
                    EntradaBase::Binario { huella }
                }
                1 => {
                    let formato = formato_de_codigo(lector.u8()?)?;
                    let contenido = String::from_utf8(lector.bytes()?.to_vec()).ok()?;
                    EntradaBase::Config { formato, contenido }
                }
                _ => return None,
            };
            entradas.insert(ruta, entrada);
        }
        // No debe sobrar nada: bytes de mas es corrupcion.
        if lector.resto() != 0 {
            return None;
        }
        Some(LineaBase { entradas })
    }
}

/// La linea base sellada y firmada: la forma que se almacena y se transmite.
///
/// No deriva `Debug` a proposito: la [`FirmaHibrida`] no lo hace, y no hay motivo
/// para volcar una firma a un log.
#[derive(Clone)]
pub struct LineaBaseSellada {
    cuerpo: Vec<u8>,
    pcr_sellado: Pcr,
    firma: FirmaHibrida,
}

/// Por que no se pudo abrir una linea base sellada.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorLineaBase {
    /// La firma no verifica: NO la emitio el plano de control. Es el caso del
    /// atacante con root que reescribio la linea base y la volvio a calcular: sin
    /// la clave privada del plano de control, no puede volver a firmarla.
    #[error("firma invalida: la linea base no la emitio el plano de control (root no basta)")]
    FirmaInvalida,
    /// El PCR actual no coincide con el sellado: el arranque medido cambio.
    #[error("sello roto: el PCR actual no coincide con el sellado (el arranque cambio)")]
    SelloRoto,
    /// El cuerpo no se pudo decodificar.
    #[error("cuerpo de la linea base corrupto")]
    CuerpoCorrupto,
}

impl LineaBaseSellada {
    /// Abre la linea base: verifica la firma, comprueba el sello contra el PCR
    /// actual, y solo entonces decodifica el cuerpo.
    ///
    /// El orden importa: primero la firma (¿la emitio el plano de control?), luego
    /// el sello (¿es este el arranque para el que se sello?). Una linea base cuya
    /// firma no verifica no se abre, punto.
    pub fn abrir(
        &self,
        clave: &ClaveVerificacionHibrida,
        pcr_actual: Pcr,
    ) -> Result<LineaBase, ErrorLineaBase> {
        let mensaje = mensaje_a_firmar(&self.cuerpo, &self.pcr_sellado);
        if !clave.verificar(&mensaje, DOMINIO, &self.firma) {
            return Err(ErrorLineaBase::FirmaInvalida);
        }
        if pcr_actual != self.pcr_sellado {
            return Err(ErrorLineaBase::SelloRoto);
        }
        LineaBase::desde_bytes(&self.cuerpo).ok_or(ErrorLineaBase::CuerpoCorrupto)
    }

    /// Los bytes con los que se transmite (para pruebas y para el transporte).
    #[must_use]
    pub fn cuerpo(&self) -> &[u8] {
        &self.cuerpo
    }

    /// Sustituye el cuerpo por otro SIN volver a firmar. Modela al atacante con
    /// root que reescribe la linea base: la firma dejara de verificar.
    #[must_use]
    pub fn con_cuerpo_reescrito(mut self, nuevo_cuerpo: Vec<u8>) -> LineaBaseSellada {
        self.cuerpo = nuevo_cuerpo;
        self
    }
}

fn mensaje_a_firmar(cuerpo: &[u8], pcr: &Pcr) -> Vec<u8> {
    let mut m = Vec::with_capacity(cuerpo.len() + pcr.len());
    m.extend_from_slice(cuerpo);
    m.extend_from_slice(pcr);
    m
}

fn codigo_formato(f: Formato) -> u8 {
    match f {
        Formato::SshdConfig => 0,
        Formato::Sudoers => 1,
        Formato::AuthorizedKeys => 2,
    }
}

fn formato_de_codigo(c: u8) -> Option<Formato> {
    match c {
        0 => Some(Formato::SshdConfig),
        1 => Some(Formato::Sudoers),
        2 => Some(Formato::AuthorizedKeys),
        _ => None,
    }
}

fn escribir_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Un lector de bytes que jamas entra en panico: cada lectura comprueba que hay
/// suficiente y devuelve `None` si no.
struct Lector<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Lector<'a> {
    fn new(b: &'a [u8]) -> Lector<'a> {
        Lector { b, i: 0 }
    }
    fn exactos(&mut self, n: usize) -> Option<&'a [u8]> {
        let fin = self.i.checked_add(n)?;
        if fin > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..fin];
        self.i = fin;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.exactos(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.exactos(4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.exactos(n)
    }
    fn resto(&self) -> usize {
        self.b.len() - self.i
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn claves() -> (ClaveFirmaHibrida, ClaveVerificacionHibrida) {
        let sk = ClaveFirmaHibrida::desde_semillas(&[7u8; 32], &[13u8; 32]);
        let vk = sk.clave_verificacion();
        (sk, vk)
    }

    fn base_ejemplo() -> LineaBase {
        LineaBase::nueva()
            .con_binario("/usr/sbin/sshd", b"binario conocido bueno")
            .con_config(
                "/etc/ssh/sshd_config",
                Formato::SshdConfig,
                "PermitRootLogin no\nPort 22\n",
            )
    }

    #[test]
    fn una_linea_base_bien_firmada_se_abre_con_el_pcr_correcto() {
        let (sk, vk) = claves();
        let pcr = [1u8; 32];
        let sellada = base_ejemplo().sellar(pcr, &sk).unwrap();
        let abierta = sellada.abrir(&vk, pcr).unwrap();
        assert_eq!(abierta.len(), 2);
    }

    #[test]
    fn root_reescribe_la_linea_base_y_la_firma_no_verifica() {
        // EL punto de la fase: root cambia la linea base (mete su binario como
        // «bueno») y la recalcula, pero no puede volver a firmarla.
        let (sk, vk) = claves();
        let pcr = [1u8; 32];
        let sellada = base_ejemplo().sellar(pcr, &sk).unwrap();
        let malvada =
            LineaBase::nueva().con_binario("/usr/sbin/sshd", b"binario con puerta trasera");
        let reescrita = sellada.con_cuerpo_reescrito(malvada.a_bytes());
        assert_eq!(
            reescrita.abrir(&vk, pcr),
            Err(ErrorLineaBase::FirmaInvalida)
        );
    }

    #[test]
    fn root_firma_con_su_propia_clave_y_tampoco_cuela() {
        // Root genera SU clave y firma una linea base con su binario. Al abrirla
        // con la clave del plano de control, la firma no verifica.
        let (_, vk_plano) = claves();
        let sk_atacante = ClaveFirmaHibrida::desde_semillas(&[66u8; 32], &[66u8; 32]);
        let pcr = [1u8; 32];
        let sellada = base_ejemplo().sellar(pcr, &sk_atacante).unwrap();
        assert_eq!(
            sellada.abrir(&vk_plano, pcr),
            Err(ErrorLineaBase::FirmaInvalida)
        );
    }

    #[test]
    fn un_arranque_distinto_rompe_el_sello() {
        let (sk, vk) = claves();
        let sellada = base_ejemplo().sellar([1u8; 32], &sk).unwrap();
        // El PCR actual es otro (el arranque medido cambio): sello roto.
        assert_eq!(
            sellada.abrir(&vk, [2u8; 32]),
            Err(ErrorLineaBase::SelloRoto)
        );
    }

    #[test]
    fn tras_abrir_el_cambio_semantico_se_ve_y_el_comentario_no() {
        let (sk, vk) = claves();
        let pcr = [9u8; 32];
        let base = sellar_ejemplo_y_abrir(&sk, &vk, pcr);
        // Un comentario nuevo: sin cambios.
        assert!(base
            .cambios(
                "/etc/ssh/sshd_config",
                b"# nota\nPermitRootLogin no\nPort 22\n"
            )
            .is_empty());
        // Abrir root: un cambio critico.
        let c = base.cambios("/etc/ssh/sshd_config", b"PermitRootLogin yes\nPort 22\n");
        assert_eq!(c.len(), 1);
        assert!(matches!(&c[0], CambioSemantico::PermitRootLogin { .. }));
    }

    fn sellar_ejemplo_y_abrir(
        sk: &ClaveFirmaHibrida,
        vk: &ClaveVerificacionHibrida,
        pcr: Pcr,
    ) -> LineaBase {
        base_ejemplo()
            .sellar(pcr, sk)
            .unwrap()
            .abrir(vk, pcr)
            .unwrap()
    }

    #[test]
    fn el_ida_y_vuelta_de_bytes_es_estable_y_no_panica_con_basura() {
        let base = base_ejemplo();
        let bytes = base.a_bytes();
        assert_eq!(LineaBase::desde_bytes(&bytes), Some(base));
        // Basura: None, sin panico.
        assert_eq!(LineaBase::desde_bytes(&[0xff; 3]), None);
        assert_eq!(LineaBase::desde_bytes(&[]), None);
        for corte in 0..bytes.len() {
            let _ = LineaBase::desde_bytes(&bytes[..corte]);
        }
    }
}
