//! El artefacto firmado: lo que de verdad viaja del plano de control al agente.
//!
//! # El ataque que ninguna firma detiene
//!
//! Un corpus se firma para que nadie pueda fabricar uno. Eso deja fuera al
//! atacante que **inventa** contenido, y no deja fuera al que **repite** el
//! nuestro: coger el corpus de hace seis meses —autentico, firmado por nosotros,
//! con la firma perfecta— y reponerlo en la flota. Ninguna verificacion
//! criptografica lo distingue del bueno, porque no hay nada que distinguir: es
//! nuestro. Lo que consigue es que el endpoint vuelva a un corpus que no conoce
//! el ransomware de este mes, y lo consigue **sin romper nada**.
//!
//! Es el mismo ataque que la FASE 68 encontro en la malla, y lleva la misma
//! respuesta: una **epoca monotona**. El agente recuerda la epoca mas alta que ha
//! visto y rechaza cualquier corpus con una epoca igual o menor, tenga la firma
//! que tenga. Retroceder deja de ser posible sin tocar el estado del agente, que
//! es otro nivel de compromiso entero.
//!
//! # Separacion de dominio
//!
//! La firma lleva contexto ([`CTX_CORPUS`]). Sin el, una firma valida sobre un
//! corpus podria reinterpretarse como firma valida sobre otra cosa que el mismo
//! canal distribuye —un binario del agente, por ejemplo— si los dos formatos
//! llegaran a solaparse en bytes. Cuesta una cadena constante y cierra una
//! familia entera de confusiones de tipo.
//!
//! # Que cubre la firma, exactamente
//!
//! Se firma **el manifiesto**, y el manifiesto **se compromete con el SHA-256 del
//! indice**. Asi una sola firma cubre las dos cosas.
//!
//! La alternativa —firmar el manifiesto y el indice por separado— seria peor y no
//! es obvio por que: con dos firmas independientes, un atacante puede quedarse el
//! manifiesto de la version 5 y el indice de la version 4, y **las dos firmas
//! verifican**. El resultado es un corpus que nunca existio, montado enteramente
//! con piezas autenticas.
//!
//! # Codificacion canonica
//!
//! El manifiesto se serializa a mano, con campos de longitud fija y cadenas con
//! prefijo de longitud. No se usa un formato con varias representaciones validas
//! del mismo valor: si dos codificaciones del mismo manifiesto dieran bytes
//! distintos, la firma dejaria de significar «este manifiesto» para significar
//! «estos bytes», y quien controlase la serializacion podria fabricar dos
//! manifiestos con sentidos distintos y una sola firma.

use aegis_sync::{reconcile, CountingView, Ioc, MerkleTree, SyncDiff};
use aegis_update::{ClaveActualizacion, SignatureError};
use sha2::{Digest, Sha256};

use crate::canario::Veredicto;

/// Marca del manifiesto.
pub const MAGIA: &[u8; 8] = b"AEGISCRP";

/// Version del formato del manifiesto.
pub const VERSION: u32 = 1;

/// Contexto de dominio de la firma del corpus.
///
/// Lo consume [`ClaveActualizacion::verificar`] en la suite hibrida. Cambiarlo
/// invalida todas las firmas anteriores **a proposito**: es la palanca para
/// retirar de golpe un corpus firmado con una clave comprometida.
pub const CTX_CORPUS: &[u8] = b"aegiscore/corpus/v1";

/// Lo que el manifiesto dice del paso por el canario.
///
/// Va **dentro** de lo firmado, y [`Corpus::verificar`] lo comprueba. Llevarlo
/// sin comprobarlo seria teatro: el que firmase saltandose la puerta obtendria
/// un artefacto con un sello que dice «paso el canario» y que nadie contrasta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelloCanario {
    /// Firmas que el canario evaluo.
    pub evaluadas: u64,
    /// Muestras de software legitimo contra las que se probo.
    pub muestras: u64,
    /// Firmas que el canario rechazo. **Tiene que ser cero.**
    pub rechazadas: u64,
}

impl SelloCanario {
    /// Construye el sello a partir de un veredicto.
    #[must_use]
    pub fn de(veredicto: &Veredicto) -> SelloCanario {
        SelloCanario {
            evaluadas: veredicto.evaluadas as u64,
            muestras: veredicto.muestras as u64,
            rechazadas: veredicto.firmas_rechazadas().len() as u64,
        }
    }

    /// Si el sello acredita un paso limpio por la puerta.
    ///
    /// Cero muestras **no** vale: significa que la puerta no llego a probar
    /// nada, y un aval sin prueba es peor que ningun aval.
    #[must_use]
    pub fn aprobado(&self) -> bool {
        self.rechazadas == 0 && self.muestras > 0
    }
}

/// Lo que se firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifiesto {
    /// Version del formato.
    pub version: u32,
    /// Epoca monotona. Un corpus con epoca menor o igual a la ya vista se
    /// rechaza **aunque su firma sea perfecta**.
    pub epoca: u64,
    /// Cuando se genero, en nanosegundos desde la epoca Unix.
    ///
    /// Es informativo y **no** decide nada: un reloj se puede mover, y colgar de
    /// el la defensa contra el retroceso la dejaria en manos de quien controle la
    /// hora del endpoint. Para eso esta [`Manifiesto::epoca`].
    pub generado_ns: u64,
    /// Raiz del arbol de Merkle de los indicadores, para sincronizar por
    /// diferencias en vez de mandar el corpus entero.
    pub raiz_merkle: [u8; 32],
    /// Entradas del indice.
    pub entradas: u64,
    /// SHA-256 del fichero de indice al que este manifiesto se compromete.
    pub sha256_indice: [u8; 32],
    /// Lo que dijo el canario.
    pub canario: SelloCanario,
}

/// Errores del corpus.
#[derive(Debug, thiserror::Error)]
pub enum ErrorCorpus {
    /// Los bytes no son un manifiesto.
    #[error("no es un manifiesto de corpus de AegisCore (falta la marca)")]
    NoEsManifiesto,
    /// La version no se conoce.
    #[error(
        "manifiesto de la version {encontrada}; esta compilacion entiende la {esperada}. No se \
         interpreta: leer mal los campos daria un corpus silenciosamente equivocado"
    )]
    VersionDesconocida {
        /// Version que trae.
        encontrada: u32,
        /// Version que se entiende.
        esperada: u32,
    },
    /// Los bytes estan truncados o no cuadran.
    #[error("manifiesto corrupto: {0}")]
    Corrupto(String),
    /// La firma no verifica.
    #[error("la firma del corpus no verifica: {0}")]
    Firma(#[from] SignatureError),
    /// El indice no es el que el manifiesto dice.
    #[error(
        "el indice no es el que el manifiesto firma (esperado {esperado}, recibido {recibido}): \
         manifiesto y datos de versiones distintas, cada uno autentico por su lado"
    )]
    IndiceNoCuadra {
        /// Hash que el manifiesto firma.
        esperado: String,
        /// Hash de lo que ha llegado.
        recibido: String,
    },
    /// La epoca no avanza: es un corpus viejo, autentico, repuesto.
    #[error(
        "epoca {ofrecida} no supera la ya vista ({vista}): es un corpus ANTERIOR con firma \
         valida. Reponerlo devolveria al endpoint a un corpus que no conoce las amenazas de hoy"
    )]
    Retroceso {
        /// Epoca del corpus ofrecido.
        ofrecida: u64,
        /// Epoca mas alta ya aceptada.
        vista: u64,
    },
    /// El corpus no acredita haber pasado el canario.
    #[error(
        "el corpus no acredita el canario ({rechazadas} firmas rechazadas sobre {muestras} \
         muestras): un corpus que dispara sobre software legitimo apaga la flota sin que haya \
         atacante"
    )]
    CanarioNoAprobado {
        /// Firmas que el canario rechazo.
        rechazadas: u64,
        /// Muestras contra las que probo.
        muestras: u64,
    },
}

/// Bytes de un manifiesto codificado.
///
/// Tamano fijo: marca (8) + version (4) + epoca (8) + generado (8) + raiz (32) +
/// entradas (8) + sha256 (32) + canario (24).
pub const BYTES_MANIFIESTO: usize = 8 + 4 + 8 + 8 + 32 + 8 + 32 + 24;

impl Manifiesto {
    /// Codificacion canonica: los bytes exactos que se firman.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BYTES_MANIFIESTO);
        v.extend_from_slice(MAGIA);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.generado_ns.to_le_bytes());
        v.extend_from_slice(&self.raiz_merkle);
        v.extend_from_slice(&self.entradas.to_le_bytes());
        v.extend_from_slice(&self.sha256_indice);
        v.extend_from_slice(&self.canario.evaluadas.to_le_bytes());
        v.extend_from_slice(&self.canario.muestras.to_le_bytes());
        v.extend_from_slice(&self.canario.rechazadas.to_le_bytes());
        debug_assert_eq!(v.len(), BYTES_MANIFIESTO);
        v
    }

    /// Lee un manifiesto de su codificacion canonica.
    ///
    /// # Errores
    /// [`ErrorCorpus`] si no lleva la marca, si la version no se conoce o si los
    /// bytes no dan de si.
    pub fn de_bytes(b: &[u8]) -> Result<Manifiesto, ErrorCorpus> {
        if b.len() < 12 || &b[..8] != MAGIA {
            return Err(ErrorCorpus::NoEsManifiesto);
        }
        let version = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        // La version se comprueba ANTES que la longitud: un manifiesto de una
        // version futura sera mas largo o mas corto, y decir «corrupto» cuando lo
        // que pasa es que es de otra version manda a depurar al sitio equivocado.
        if version != VERSION {
            return Err(ErrorCorpus::VersionDesconocida {
                encontrada: version,
                esperada: VERSION,
            });
        }
        if b.len() != BYTES_MANIFIESTO {
            return Err(ErrorCorpus::Corrupto(format!(
                "{} bytes, se esperaban {BYTES_MANIFIESTO}",
                b.len()
            )));
        }

        let u64_en = |i: usize| -> u64 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(a)
        };
        let h32_en = |i: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b[i..i + 32]);
            a
        };

        Ok(Manifiesto {
            version,
            epoca: u64_en(12),
            generado_ns: u64_en(20),
            raiz_merkle: h32_en(28),
            entradas: u64_en(60),
            sha256_indice: h32_en(68),
            canario: SelloCanario {
                evaluadas: u64_en(100),
                muestras: u64_en(108),
                rechazadas: u64_en(116),
            },
        })
    }
}

/// Un corpus listo para distribuir: manifiesto firmado mas su indice.
#[derive(Debug, Clone)]
pub struct Corpus {
    /// El manifiesto.
    pub manifiesto: Manifiesto,
    /// Firma sobre [`Manifiesto::a_bytes`] bajo [`CTX_CORPUS`].
    pub firma: Vec<u8>,
}

/// SHA-256 de unos bytes, en crudo.
#[must_use]
pub fn sha256(datos: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(datos);
    h.finalize().into()
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Prepara el manifiesto de un corpus.
///
/// No firma: firmar necesita la clave privada, que vive en el firmador y no en
/// esta biblioteca. Lo que hace es dejar los bytes exactos que hay que firmar.
///
/// # Errores
/// [`ErrorCorpus::CanarioNoAprobado`] si el veredicto del canario no acredita un
/// paso limpio. **La puerta esta aqui y no en quien llama**: dejar construir el
/// manifiesto y confiar en que alguien mire el veredicto antes de firmarlo es
/// dejar la puerta abierta con un cartel al lado.
pub fn preparar(
    epoca: u64,
    generado_ns: u64,
    indice: &[u8],
    entradas: u64,
    iocs: &[Ioc],
    canario: &Veredicto,
) -> Result<Manifiesto, ErrorCorpus> {
    let sello = SelloCanario::de(canario);
    if !sello.aprobado() {
        return Err(ErrorCorpus::CanarioNoAprobado {
            rechazadas: sello.rechazadas,
            muestras: sello.muestras,
        });
    }
    Ok(Manifiesto {
        version: VERSION,
        epoca,
        generado_ns,
        raiz_merkle: MerkleTree::build(iocs.to_vec()).root(),
        entradas,
        sha256_indice: sha256(indice),
        canario: sello,
    })
}

impl Corpus {
    /// Verifica un corpus recibido, entero.
    ///
    /// Las cuatro comprobaciones, en el orden en que hay que hacerlas:
    ///
    /// 1. **La firma.** Si no es nuestro, no se mira nada mas.
    /// 2. **La epoca.** Autentico y anterior sigue siendo un ataque.
    /// 3. **El indice.** Que el manifiesto firme el indice que ha llegado, y no
    ///    otro igual de autentico de otra version.
    /// 4. **El canario.** Que acredite haber pasado la puerta de falsos
    ///    positivos.
    ///
    /// El orden importa: comprobar la epoca antes que la firma le dejaria a
    /// cualquiera mover el estado del agente mandandole basura con una epoca
    /// enorme.
    ///
    /// # Errores
    /// El primer [`ErrorCorpus`] que se encuentre, en ese orden.
    pub fn verificar(
        &self,
        clave: &ClaveActualizacion,
        indice: &[u8],
        epoca_vista: u64,
    ) -> Result<(), ErrorCorpus> {
        let bytes = self.manifiesto.a_bytes();
        clave.verificar(&bytes, CTX_CORPUS, &self.firma)?;

        if self.manifiesto.epoca <= epoca_vista {
            return Err(ErrorCorpus::Retroceso {
                ofrecida: self.manifiesto.epoca,
                vista: epoca_vista,
            });
        }

        let real = sha256(indice);
        if real != self.manifiesto.sha256_indice {
            return Err(ErrorCorpus::IndiceNoCuadra {
                esperado: hex(&self.manifiesto.sha256_indice),
                recibido: hex(&real),
            });
        }

        if !self.manifiesto.canario.aprobado() {
            return Err(ErrorCorpus::CanarioNoAprobado {
                rechazadas: self.manifiesto.canario.rechazadas,
                muestras: self.manifiesto.canario.muestras,
            });
        }
        Ok(())
    }
}

/// Que le falta y que le sobra al agente respecto del corpus del servidor.
///
/// Si las raices coinciden termina con una sola comparacion de hash y sin
/// transferir nada: es la razon de ser del arbol. Con dos millones de firmas y un
/// cambio de veinte, mandar el corpus entero cada vez seria gastar gigabytes de
/// la red del cliente para entregar unos kilobytes de novedad.
#[must_use]
pub fn diferencia(local: &MerkleTree, remoto: &MerkleTree) -> SyncDiff {
    reconcile(local, &CountingView::new(remoto))
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_sync::IocKind;
    use aegis_update::ClaveFirmaHibrida;

    fn veredicto_bueno() -> Veredicto {
        Veredicto {
            evaluadas: 1200,
            muestras: 14,
            rechazos: Vec::new(),
        }
    }

    fn iocs(n: u32) -> Vec<Ioc> {
        (0..n)
            .map(|i| Ioc {
                kind: IocKind::FileSha256,
                value: format!("{i:064x}"),
            })
            .collect()
    }

    fn manifiesto(epoca: u64, indice: &[u8]) -> Manifiesto {
        preparar(
            epoca,
            1_700_000_000_000_000_000,
            indice,
            1200,
            &iocs(64),
            &veredicto_bueno(),
        )
        .unwrap()
    }

    /// Par de claves hibridas deterministas para las pruebas de firma.
    fn claves_desde(semilla: u8) -> (ClaveFirmaHibrida, ClaveActualizacion) {
        let firmante = ClaveFirmaHibrida::desde_semillas(&[semilla; 32], &[semilla ^ 0x5a; 32]);
        let verificadora = firmante.clave_verificacion();
        (
            firmante,
            ClaveActualizacion::Hibrida(Box::new(verificadora)),
        )
    }

    fn claves() -> (ClaveFirmaHibrida, ClaveActualizacion) {
        claves_desde(7)
    }

    fn firmar_con_ctx(firmante: &ClaveFirmaHibrida, m: &Manifiesto, ctx: &[u8]) -> Vec<u8> {
        firmante.firmar(&m.a_bytes(), ctx).unwrap().a_bytes()
    }

    fn firmar(firmante: &ClaveFirmaHibrida, m: &Manifiesto) -> Vec<u8> {
        firmar_con_ctx(firmante, m, CTX_CORPUS)
    }

    // --- Codificacion canonica --------------------------------------------

    #[test]
    fn el_manifiesto_va_y_vuelve_sin_perder_nada() {
        let m = manifiesto(42, b"indice de prueba");
        let bytes = m.a_bytes();
        assert_eq!(bytes.len(), BYTES_MANIFIESTO);
        assert_eq!(Manifiesto::de_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn la_codificacion_es_estable_entre_llamadas() {
        // Si dos codificaciones del mismo manifiesto dieran bytes distintos, la
        // firma dejaria de significar «este manifiesto».
        let m = manifiesto(9, b"x");
        assert_eq!(m.a_bytes(), m.a_bytes());
        assert_eq!(m.clone().a_bytes(), m.a_bytes());
    }

    #[test]
    fn unos_bytes_cualesquiera_no_son_un_manifiesto() {
        assert!(matches!(
            Manifiesto::de_bytes(b"hola que tal"),
            Err(ErrorCorpus::NoEsManifiesto)
        ));
        assert!(matches!(
            Manifiesto::de_bytes(b""),
            Err(ErrorCorpus::NoEsManifiesto)
        ));
    }

    #[test]
    fn un_manifiesto_de_otra_version_no_se_interpreta() {
        let m = manifiesto(1, b"i");
        let mut bytes = m.a_bytes();
        bytes[8] = 99;
        match Manifiesto::de_bytes(&bytes) {
            Err(ErrorCorpus::VersionDesconocida {
                encontrada,
                esperada,
            }) => {
                assert_eq!(encontrada, 99);
                assert_eq!(esperada, VERSION);
            }
            otro => panic!("se esperaba VersionDesconocida, hubo {otro:?}"),
        }
    }

    #[test]
    fn un_manifiesto_truncado_se_detecta() {
        let m = manifiesto(1, b"i");
        let bytes = m.a_bytes();
        assert!(matches!(
            Manifiesto::de_bytes(&bytes[..BYTES_MANIFIESTO - 1]),
            Err(ErrorCorpus::Corrupto(_))
        ));
    }

    // --- La puerta del canario --------------------------------------------

    #[test]
    fn un_corpus_que_no_paso_el_canario_no_llega_ni_a_manifiesto() {
        // La puerta esta en `preparar` y no en quien llama: confiar en que
        // alguien mire el veredicto antes de firmar es dejarla abierta.
        let malo = Veredicto {
            evaluadas: 1200,
            muestras: 14,
            rechazos: vec![crate::canario::Rechazo {
                firma: "Mala.Firma".to_string(),
                motivo: crate::canario::Motivo::Disparo {
                    muestra: "/bin/ls".to_string(),
                },
            }],
        };
        let r = preparar(1, 0, b"i", 1200, &iocs(4), &malo);
        assert!(matches!(r, Err(ErrorCorpus::CanarioNoAprobado { .. })));
    }

    #[test]
    fn un_canario_sin_muestras_tampoco_acredita_nada() {
        let sin_muestras = Veredicto {
            evaluadas: 1200,
            muestras: 0,
            rechazos: Vec::new(),
        };
        let r = preparar(1, 0, b"i", 1200, &iocs(4), &sin_muestras);
        assert!(matches!(r, Err(ErrorCorpus::CanarioNoAprobado { .. })));
    }

    // --- Firma ------------------------------------------------------------

    #[test]
    fn un_corpus_bien_firmado_verifica() {
        let (firmante, clave) = claves();
        let indice = b"el indice de verdad".to_vec();
        let m = manifiesto(5, &indice);
        let c = Corpus {
            firma: firmar(&firmante, &m),
            manifiesto: m,
        };
        assert!(c.verificar(&clave, &indice, 4).is_ok());
    }

    #[test]
    fn un_manifiesto_alterado_no_verifica() {
        let (firmante, clave) = claves();
        let indice = b"el indice".to_vec();
        let m = manifiesto(5, &indice);
        let firma = firmar(&firmante, &m);

        // Se sube la epoca a mano, que es justo lo que haria quien quisiera
        // colar un corpus viejo saltandose la defensa contra el retroceso.
        let mut alterado = m.clone();
        alterado.epoca = 9999;
        let c = Corpus {
            manifiesto: alterado,
            firma,
        };
        assert!(matches!(
            c.verificar(&clave, &indice, 4),
            Err(ErrorCorpus::Firma(_))
        ));
    }

    #[test]
    fn una_firma_de_otro_dominio_no_vale_para_un_corpus() {
        // Separacion de dominio: la misma clave, los mismos bytes, otro contexto.
        let (firmante, clave) = claves();
        let indice = b"i".to_vec();
        let m = manifiesto(5, &indice);
        let firma_de_binario = firmar_con_ctx(&firmante, &m, b"aegiscore/binario/v1");
        let c = Corpus {
            manifiesto: m,
            firma: firma_de_binario,
        };
        assert!(matches!(
            c.verificar(&clave, &indice, 4),
            Err(ErrorCorpus::Firma(_))
        ));
    }

    #[test]
    fn una_clave_ajena_no_firma_nuestro_corpus() {
        let (_, clave) = claves();
        let (otro, _) = claves_desde(9);
        let indice = b"i".to_vec();
        let m = manifiesto(5, &indice);
        let c = Corpus {
            firma: firmar(&otro, &m),
            manifiesto: m,
        };
        assert!(matches!(
            c.verificar(&clave, &indice, 4),
            Err(ErrorCorpus::Firma(_))
        ));
    }

    // --- EL ATAQUE CENTRAL: reponer un corpus viejo y autentico ------------

    #[test]
    fn un_corpus_anterior_con_firma_perfecta_se_rechaza() {
        // No hay nada malformado aqui. El corpus es nuestro, la firma es
        // nuestra, el indice cuadra. Lo unico que pasa es que es de antes, y
        // reponerlo devolveria al endpoint a un corpus que no conoce el
        // ransomware de este mes. Ninguna verificacion criptografica lo ve.
        let (firmante, clave) = claves();
        let indice = b"corpus de hace seis meses".to_vec();
        let viejo = manifiesto(10, &indice);
        let c = Corpus {
            firma: firmar(&firmante, &viejo),
            manifiesto: viejo,
        };

        // Con la firma intacta y todo en regla: se rechaza por la epoca.
        match c.verificar(&clave, &indice, 47) {
            Err(ErrorCorpus::Retroceso { ofrecida, vista }) => {
                assert_eq!(ofrecida, 10);
                assert_eq!(vista, 47);
            }
            otro => panic!("un corpus anterior tiene que rechazarse, hubo {otro:?}"),
        }
    }

    #[test]
    fn repetir_la_misma_epoca_tampoco_vale() {
        // Estrictamente mayor, no mayor o igual: si se aceptara la igualdad, dos
        // corpus distintos con la misma epoca serian intercambiables y el
        // atacante elegiria cual.
        let (firmante, clave) = claves();
        let indice = b"i".to_vec();
        let m = manifiesto(47, &indice);
        let c = Corpus {
            firma: firmar(&firmante, &m),
            manifiesto: m,
        };
        assert!(matches!(
            c.verificar(&clave, &indice, 47),
            Err(ErrorCorpus::Retroceso { .. })
        ));
    }

    #[test]
    fn la_epoca_se_comprueba_despues_de_la_firma() {
        // Si se mirase la epoca primero, cualquiera podria mover el estado del
        // agente mandandole basura con una epoca enorme y sin firma valida.
        let (_, clave) = claves();
        let indice = b"i".to_vec();
        let m = manifiesto(999_999, &indice);
        let c = Corpus {
            manifiesto: m,
            firma: vec![0u8; 3374],
        };
        assert!(
            matches!(c.verificar(&clave, &indice, 1), Err(ErrorCorpus::Firma(_))),
            "sin firma valida no se llega a mirar la epoca"
        );
    }

    // --- Mezclar piezas autenticas de versiones distintas ------------------

    #[test]
    fn el_manifiesto_de_una_version_con_el_indice_de_otra_no_cuela() {
        // Las dos piezas son autenticas. El corpus que forman no existio nunca.
        let (firmante, clave) = claves();
        let indice_v5 = b"indice de la version 5".to_vec();
        let indice_v4 = b"indice de la version 4".to_vec();
        let m5 = manifiesto(5, &indice_v5);
        let c = Corpus {
            firma: firmar(&firmante, &m5),
            manifiesto: m5,
        };

        assert!(c.verificar(&clave, &indice_v5, 4).is_ok());
        match c.verificar(&clave, &indice_v4, 4) {
            Err(ErrorCorpus::IndiceNoCuadra { esperado, recibido }) => {
                assert_ne!(esperado, recibido);
            }
            otro => panic!("mezclar versiones tiene que rechazarse, hubo {otro:?}"),
        }
    }

    // --- Sincronizacion por diferencias ------------------------------------

    #[test]
    fn dos_corpus_iguales_no_transfieren_nada() {
        let a = MerkleTree::build(iocs(500));
        let b = MerkleTree::build(iocs(500));
        let d = diferencia(&a, &b);
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(d.differing_buckets, 0);
    }

    #[test]
    fn un_cambio_pequeno_mueve_pocos_cubos() {
        // LA CIFRA QUE JUSTIFICA EL ARBOL: con dos mil indicadores y veinte
        // nuevos, no se transfieren dos mil.
        let local = MerkleTree::build(iocs(2000));
        let remoto = MerkleTree::build(iocs(2020));
        let d = diferencia(&local, &remoto);

        assert_eq!(d.to_add.len(), 20, "solo lo nuevo");
        assert!(d.to_remove.is_empty());
        assert!(
            d.differing_buckets <= 20,
            "veinte indicadores no pueden mover mas de veinte cubos, movieron {}",
            d.differing_buckets
        );
    }

    #[test]
    fn una_revocacion_se_ve_como_sobra() {
        // Quitar una firma es tan importante como anadirla: una regla revocada
        // que se queda en el endpoint sigue dando falsos positivos.
        let local = MerkleTree::build(iocs(100));
        let remoto = MerkleTree::build(iocs(99));
        let d = diferencia(&local, &remoto);
        assert_eq!(d.to_remove.len(), 1);
        assert!(d.to_add.is_empty());
    }

    #[test]
    fn la_raiz_del_manifiesto_es_la_del_arbol_de_sus_indicadores() {
        // Si no lo fuera, el agente reconciliaria contra una raiz que no
        // corresponde al corpus firmado y nunca convergeria.
        let lista = iocs(300);
        let m = preparar(1, 0, b"i", 300, &lista, &veredicto_bueno()).unwrap();
        assert_eq!(m.raiz_merkle, MerkleTree::build(lista).root());
    }
}
