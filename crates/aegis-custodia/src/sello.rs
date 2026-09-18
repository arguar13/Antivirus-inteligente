//! El sello: unos bytes atados a quien los recogio, cuando y por que.
//!
//! # Que problema resuelve
//!
//! Un volcado forense sin sello es un fichero. Puede ser autentico, y no hay
//! forma de demostrarlo: nada lo ata a la maquina de la que salio, a la version
//! del agente que lo recogio, ni al momento. Cuando alguien discute la prueba
//! —el cliente, su aseguradora, un juez, o el propio analista seis meses
//! despues— la respuesta «lo sacamos del endpoint 7» no es verificable.
//!
//! El sello ata cuatro cosas en una sola firma:
//!
//! 1. **Los bytes exactos**, por su resumen y por su longitud.
//! 2. **De donde salieron**: caso, endpoint, agente que los recogio.
//! 3. **Cuando**, por los dos relojes (ver [`crate::reloj`]).
//! 4. **Por que**: que disparo la recogida y con que tecnicas se relaciono.
//!
//! Cambiar cualquiera de las cuatro invalida la firma. No hay forma de mover un
//! artefacto de un caso a otro, de adelantar su hora o de atribuirlo a otra
//! maquina sin que la verificacion lo diga.
//!
//! # Por que el sello NO lleva dentro la clave publica
//!
//! Seria comodo y no serviria de nada: quien pueda cambiar los bytes puede
//! cambiar tambien la clave que los acompana y volver a firmar. Una firma solo
//! prueba algo contra una clave que el verificador ya tenia por otra via, asi
//! que el sello lleva la IDENTIDAD del firmante y el verificador busca su clave
//! en la PKI de la flota. Un firmante que no consta es un error explicito
//! ([`crate::CustodiaError::FirmanteDesconocido`]) y nunca un aprobado.
//!
//! # Por que firma hibrida
//!
//! La evidencia de un incidente se conserva anos, y a veces se discute mas tarde
//! todavia. Una firma Ed25519 que hoy es solida puede no serlo cuando toque
//! defenderla. Se firma con el par hibrido del producto —Ed25519 **y**
//! ML-DSA-65, ambas tienen que validar—, de modo que la prueba siga en pie si
//! una de las dos cae.

use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida, FirmaHibrida};

use crate::canon::{hex, resumir, Codificador, Resumen};
use crate::error::CustodiaError;
use crate::reloj::Marca;

/// Contexto de firma de un sello.
///
/// Separa el dominio: una firma de sello no puede presentarse como firma de un
/// eslabon de custodia ni al reves, porque el contexto entra en lo que se firma.
pub const CTX_SELLO: &[u8] = b"aegis-custodia/sello/v1";

/// Que clase de artefacto se sello.
///
/// Los discriminantes son parte del formato canonico: **no se pueden cambiar**.
/// Cambiar uno invalidaria la verificacion de toda la evidencia ya sellada, que
/// es justo lo que este crate existe para impedir. Anadir una clase nueva usa un
/// numero nuevo; no se reutiliza ninguno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Clase {
    /// Arbol de procesos: quien lanzo a quien.
    ArbolDeProcesos = 1,
    /// Sockets abiertos: con quien hablaba.
    Sockets = 2,
    /// Un binario en disco, entero o por su resumen.
    Binario = 3,
    /// Una region de memoria volcada del proceso vivo.
    Memoria = 4,
    /// Un fichero cualquiera recogido del disco.
    Fichero = 5,
    /// Un tramo del registro de auditoria del propio agente.
    Auditoria = 6,
}

impl Clase {
    /// Nombre legible, para el informe.
    pub fn nombre(&self) -> &'static str {
        match self {
            Clase::ArbolDeProcesos => "arbol de procesos",
            Clase::Sockets => "sockets",
            Clase::Binario => "binario",
            Clase::Memoria => "memoria",
            Clase::Fichero => "fichero",
            Clase::Auditoria => "auditoria",
        }
    }
}

/// De donde sale un artefacto y por que se recogio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Procedencia {
    /// Caso al que pertenece la evidencia.
    pub caso: String,
    /// Endpoint del que salio.
    pub endpoint: String,
    /// Identidad del agente que la recogio, tal y como la conoce la PKI de la
    /// flota. Es la clave con la que el verificador buscara su clave publica.
    pub agente: String,
    /// Version del agente que la recogio.
    ///
    /// Un fallo en la recogida afecta a lo recogido. Saber con que version se
    /// tomo cada artefacto es lo que permite, el dia que se encuentra ese fallo,
    /// decir exactamente que evidencia queda en entredicho en vez de sospechar
    /// de toda.
    pub version_agente: String,
    /// Que clase de artefacto es.
    pub clase: Clase,
    /// Que disparo la recogida, en una frase.
    pub motivo: String,
    /// Tecnicas de MITRE atribuidas, por identificador (`T1055`).
    pub tecnicas: Vec<String>,
    /// Cuando se recogio, por los dos relojes.
    pub recogido: Marca,
}

impl Procedencia {
    /// Anade la procedencia a una codificacion canonica, en orden fijo.
    fn codificar(&self, c: &mut Codificador) {
        c.texto(&self.caso)
            .texto(&self.endpoint)
            .texto(&self.agente)
            .texto(&self.version_agente)
            .u8(self.clase as u8)
            .texto(&self.motivo)
            .lista(&self.tecnicas);
        self.recogido.codificar(c);
    }
}

/// Un artefacto sellado: su procedencia, su huella y la firma que las ata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sello {
    /// De donde sale y por que.
    pub procedencia: Procedencia,
    /// Resumen SHA-256 de los bytes del artefacto.
    pub evidencia: Resumen,
    /// Longitud en bytes del artefacto.
    pub tamano: u64,
    /// Firma hibrida sobre la codificacion canonica de todo lo anterior.
    pub firma: Vec<u8>,
}

impl Sello {
    /// Sella unos bytes en el momento de recogerlos.
    pub fn sellar(
        bytes: &[u8],
        procedencia: Procedencia,
        clave: &ClaveFirmaHibrida,
    ) -> Result<Sello, CustodiaError> {
        let evidencia = resumir(bytes);
        let tamano = bytes.len() as u64;
        let mensaje = Sello::mensaje(&procedencia, &evidencia, tamano);
        let firma = clave
            .firmar(&mensaje, CTX_SELLO)
            .map_err(|e| CustodiaError::NoSePudoFirmar(format!("{e:?}")))?;
        Ok(Sello {
            procedencia,
            evidencia,
            tamano,
            firma: firma.a_bytes(),
        })
    }

    /// Los bytes canonicos que la firma cubre.
    fn mensaje(procedencia: &Procedencia, evidencia: &Resumen, tamano: u64) -> Vec<u8> {
        let mut c = Codificador::nuevo("aegis-custodia/sello/v1");
        procedencia.codificar(&mut c);
        c.resumen_de(evidencia).u64(tamano);
        c.fin()
    }

    /// Resumen de lo que la firma cubre, sin la firma.
    ///
    /// Es la huella del CONTENIDO del sello: los mismos datos dan siempre la
    /// misma, con independencia de quien firme. Sirve para tres cosas:
    ///
    /// - Indexar la evidencia por lo que afirma y no por quien lo afirma.
    /// - Comparar dos sellos del mismo artefacto —dos recogidas, dos testigos—
    ///   y ver si dicen exactamente lo mismo.
    /// - Congelar el formato canonico en una prueba, para que un cambio
    ///   accidental en la codificacion rompa la compilacion en vez de romper la
    ///   reverificacion de la evidencia ya sellada.
    pub fn huella_de_lo_firmado(&self) -> Resumen {
        resumir(&Sello::mensaje(
            &self.procedencia,
            &self.evidencia,
            self.tamano,
        ))
    }

    /// Identidad del sello: el resumen de lo que cubre, mas su firma.
    ///
    /// Es el ancla de la cadena de custodia. Incluye la firma a proposito: dos
    /// sellos con la misma procedencia y los mismos bytes pero firmados por
    /// agentes distintos son dos hechos distintos —dos recogidas— y no pueden
    /// compartir identidad.
    pub fn identidad(&self) -> Resumen {
        let mut c = Codificador::nuevo("aegis-custodia/identidad-de-sello/v1");
        c.bytes(&Sello::mensaje(
            &self.procedencia,
            &self.evidencia,
            self.tamano,
        ))
        .bytes(&self.firma);
        c.resumen()
    }

    /// Comprueba que la firma del sello es de `clave`.
    ///
    /// No mira los bytes del artefacto: para eso esta [`Sello::cubre`]. Estan
    /// separadas porque son dos preguntas distintas y a veces solo se puede
    /// contestar una —el sello viaja en el indice del caso y el artefacto, que
    /// puede pesar gigabytes, en otro sitio—.
    pub fn firma_valida(&self, clave: &ClaveVerificacionHibrida) -> Result<(), CustodiaError> {
        let Ok(firma) = FirmaHibrida::desde_bytes(&self.firma) else {
            return Err(CustodiaError::FirmaQueNoCubre {
                que: "el sello (firma mal formada)".into(),
            });
        };
        let mensaje = Sello::mensaje(&self.procedencia, &self.evidencia, self.tamano);
        if clave.verificar(&mensaje, CTX_SELLO, &firma) {
            Ok(())
        } else {
            Err(CustodiaError::FirmaQueNoCubre {
                que: "el sello".into(),
            })
        }
    }

    /// Comprueba que `bytes` son exactamente los sellados.
    ///
    /// Se comprueba la longitud ademas del resumen. No es redundante: pilla un
    /// truncamiento sin depender de la resistencia a colisiones de SHA-256, y lo
    /// dice con un error que nombra la diferencia en vez de con un «no coincide»
    /// que obliga a investigar.
    pub fn cubre(&self, bytes: &[u8]) -> Result<(), CustodiaError> {
        let n = bytes.len() as u64;
        if n != self.tamano {
            return Err(CustodiaError::OtraLongitud {
                esperado: self.tamano,
                recibido: n,
            });
        }
        let r = resumir(bytes);
        if r != self.evidencia {
            return Err(CustodiaError::OtrosBytes {
                esperado: hex(&self.evidencia),
                recibido: hex(&r),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn procedencia() -> Procedencia {
        Procedencia {
            caso: "CASO-2026-0007".into(),
            endpoint: "endpoint-7".into(),
            agente: "agente-7".into(),
            version_agente: "1.0.0".into(),
            clase: Clase::Memoria,
            motivo: "region anonima ejecutable en un proceso sin fichero".into(),
            tecnicas: vec!["T1055".into()],
            recogido: Marca::ahora(),
        }
    }

    fn clave() -> ClaveFirmaHibrida {
        ClaveFirmaHibrida::generar_aleatorio().expect("generar clave")
    }

    #[test]
    fn un_sello_recien_hecho_verifica_contra_sus_bytes_y_su_clave() {
        let k = clave();
        let bytes = b"volcado de la region 0x7f0000000000";
        let s = Sello::sellar(bytes, procedencia(), &k).unwrap();
        s.firma_valida(&k.clave_verificacion()).unwrap();
        s.cubre(bytes).unwrap();
    }

    #[test]
    fn cambiar_un_solo_byte_del_artefacto_lo_delata() {
        let k = clave();
        let s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        let err = s.cubre(b"evidencih").unwrap_err();
        assert!(
            matches!(err, CustodiaError::OtrosBytes { .. }),
            "un byte distinto tiene que salir como otros bytes: {err}"
        );
    }

    #[test]
    fn un_artefacto_truncado_se_detecta_por_la_longitud() {
        let k = clave();
        let s = Sello::sellar(b"evidencia entera", procedencia(), &k).unwrap();
        let err = s.cubre(b"evidencia").unwrap_err();
        assert!(
            matches!(
                err,
                CustodiaError::OtraLongitud {
                    esperado: 16,
                    recibido: 9
                }
            ),
            "el truncamiento se nombra por su longitud: {err}"
        );
    }

    #[test]
    fn mover_la_evidencia_a_otro_caso_invalida_la_firma() {
        // El ataque util: la evidencia es autentica y se reetiqueta para que
        // pertenezca a otro incidente. La firma cubre el caso, asi que no cuela.
        let k = clave();
        let mut s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        s.procedencia.caso = "CASO-2026-0008".into();
        let err = s.firma_valida(&k.clave_verificacion()).unwrap_err();
        assert!(
            matches!(err, CustodiaError::FirmaQueNoCubre { .. }),
            "{err}"
        );
    }

    #[test]
    fn atribuir_la_evidencia_a_otra_maquina_invalida_la_firma() {
        let k = clave();
        let mut s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        s.procedencia.endpoint = "endpoint-9".into();
        assert!(s.firma_valida(&k.clave_verificacion()).is_err());
    }

    #[test]
    fn adelantar_la_hora_de_recogida_invalida_la_firma() {
        let k = clave();
        let mut s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        s.procedencia.recogido.pared += 3600;
        assert!(
            s.firma_valida(&k.clave_verificacion()).is_err(),
            "la hora entra en lo firmado: no se puede mover una hora despues"
        );
    }

    #[test]
    fn cambiar_la_clase_del_artefacto_invalida_la_firma() {
        let k = clave();
        let mut s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        s.procedencia.clase = Clase::Fichero;
        assert!(s.firma_valida(&k.clave_verificacion()).is_err());
    }

    #[test]
    fn la_firma_de_otra_clave_no_vale() {
        let k = clave();
        let otra = clave();
        let s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        assert!(
            s.firma_valida(&otra.clave_verificacion()).is_err(),
            "una firma solo prueba algo contra la clave que de verdad firmo"
        );
    }

    #[test]
    fn una_firma_con_basura_se_rechaza_sin_entrar_en_panico() {
        let k = clave();
        let mut s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        s.firma = vec![0u8; 3];
        let err = s.firma_valida(&k.clave_verificacion()).unwrap_err();
        assert!(
            matches!(err, CustodiaError::FirmaQueNoCubre { .. }),
            "{err}"
        );
    }

    #[test]
    fn dos_recogidas_distintas_del_mismo_artefacto_tienen_identidades_distintas() {
        // Dos agentes recogen los MISMOS bytes del mismo proceso. Son dos hechos
        // —dos recogidas, con dos testigos— y la cadena de cada una tiene que
        // poder anclarse por separado.
        let a = clave();
        let b = clave();
        let mut pa = procedencia();
        pa.agente = "agente-a".into();
        let mut pb = procedencia();
        pb.agente = "agente-b".into();
        let sa = Sello::sellar(b"evidencia", pa, &a).unwrap();
        let sb = Sello::sellar(b"evidencia", pb, &b).unwrap();
        assert_ne!(sa.identidad(), sb.identidad());
    }

    #[test]
    fn la_identidad_de_un_sello_es_estable() {
        let k = clave();
        let s = Sello::sellar(b"evidencia", procedencia(), &k).unwrap();
        assert_eq!(s.identidad(), s.identidad());
        assert_eq!(s.clone().identidad(), s.identidad());
    }

    #[test]
    fn el_artefacto_vacio_se_sella_y_se_verifica() {
        // Un artefacto vacio es un hecho: la region no se pudo leer y se
        // recogio lo que habia. Tiene que poder sellarse como cualquier otro.
        let k = clave();
        let s = Sello::sellar(b"", procedencia(), &k).unwrap();
        s.firma_valida(&k.clave_verificacion()).unwrap();
        s.cubre(b"").unwrap();
        assert_eq!(s.tamano, 0);
    }
}
