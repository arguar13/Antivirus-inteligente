//! La linea base: los hashes que **deberian** estar en el firmware.
//!
//! # Por que una linea base y no firmas de malware
//!
//! Un implante de firmware no se parece a nada conocido: es un modulo DXE mas,
//! escrito para esa placa. Buscar firmas de malware ahi encuentra lo que ya se
//! encontro en otra maquina, que es justo lo que una APT no repite.
//!
//! Lo que si se puede afirmar es lo contrario: **que deberia haber**. El firmware
//! de un modelo de placa con una version concreta tiene un conjunto fijo de
//! ficheros FFS con hashes fijos. Un fichero que no esta en esa lista, o que esta
//! con otro hash, es la deteccion — sin saber nada del implante.
//!
//! # Los tres veredictos, y por que «desconocido» no es «malicioso»
//!
//! - **Conocido**: el GUID esta y el hash coincide.
//! - **Alterado**: el GUID esta y el hash NO coincide. Es la senal fuerte: ese
//!   modulo se reescribio.
//! - **Desconocido**: el GUID no esta en la base.
//!
//! El tercero **no** es un compromiso por si solo, y tratarlo como tal seria el
//! error que hace inservible a la herramienta: una actualizacion legitima de BIOS
//! cambia decenas de ficheros, y un parque con quince modelos de portatil tiene
//! quince firmwares distintos. «Desconocido» significa «esta base no cubre esta
//! maquina», y el informe lo dice asi. Solo sube a critico si ademas coincide con
//! un hash **revocado**, que son los implantes ya publicados.
//!
//! # Formato
//!
//! Texto plano, una entrada por linea, sin dependencias de serializacion:
//!
//! ```text
//! version 1
//! fv    8c8ce578-8a3d-4f1c-9935-896185c32dd3
//! ffs   a1b2c3d4-...  <sha256 en hex>  nombre-legible
//! revocado <sha256 en hex>  LoJax/SecDxe
//! aml   \_SB.PCI0._INI  <sha256 del cuerpo>  placa-x v1.2
//! oprom 8086:15f3  <sha256 de la imagen>  NIC integrada
//! driver <sha256 Authenticode>  controlador de la GPU
//! ```
//!
//! Las tres ultimas claves son de la FASE 92: los metodos AML que el sistema
//! ejecuta solo, las imagenes de expansion PCI y los controladores que el
//! firmware mide en el PCR 2. Siguen la misma regla que los ficheros FFS: un hash
//! revocado gana siempre, y lo que no esta en la base es «desconocido», no
//! «malicioso».

use std::collections::BTreeMap;

use aegis_firmware::guid::Guid;

/// Error al leer una linea base.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ErrorBase {
    /// Una linea no tiene el formato esperado.
    #[error("linea {linea}: {motivo}")]
    LineaMalformada {
        /// Numero de linea (base 1).
        linea: usize,
        /// Que fallaba.
        motivo: &'static str,
    },
    /// La version del formato no se reconoce.
    #[error("version de formato desconocida: {0}")]
    VersionDesconocida(String),
    /// No traia la cabecera de version.
    #[error("falta la linea 'version N' al principio")]
    SinVersion,
}

/// Una entrada conocida de la base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Hash canonico esperado.
    pub sha256: [u8; 32],
    /// Nombre legible, para el informe.
    pub etiqueta: String,
}

/// La base de hashes conocidos.
#[derive(Debug, Clone, Default)]
pub struct LineaBase {
    /// GUID de sistema de ficheros de volumen esperados.
    pub volumenes: Vec<Guid>,
    /// Ficheros conocidos, por GUID.
    ///
    /// Un GUID puede tener VARIOS hashes validos: la misma placa con dos
    /// versiones de BIOS. Aceptar solo uno obligaria a una base por version y
    /// convertiria cada actualizacion en una tormenta de alertas.
    pub ficheros: BTreeMap<Guid, Vec<Entrada>>,
    /// Hashes de implantes conocidos.
    pub revocados: BTreeMap<[u8; 32], String>,
    /// Cuerpos conocidos de metodos AML, por ruta legible (`\_SB.PCI0._INI`).
    pub metodos_aml: BTreeMap<String, Vec<Entrada>>,
    /// Imagenes de expansion PCI conocidas, por `fabricante:dispositivo` en
    /// minusculas.
    pub opciones_rom: BTreeMap<String, Vec<Entrada>>,
    /// Hashes Authenticode de controladores conocidos medidos en el PCR 2.
    pub controladores: BTreeMap<[u8; 32], String>,
}

/// El veredicto sobre un fichero FFS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// El GUID esta y el hash coincide.
    Conocido(String),
    /// El GUID esta y el hash NO coincide: el modulo se reescribio.
    Alterado {
        /// Nombre del modulo que deberia ser.
        esperado: String,
    },
    /// El GUID no esta en la base.
    ///
    /// NO es un compromiso: significa que esta base no cubre esta maquina.
    Desconocido,
    /// El hash coincide con un implante publicado.
    Revocado(String),
    /// No hay base cargada: no se puede afirmar nada.
    SinBase,
}

impl LineaBase {
    /// `true` si la base no tiene ninguna entrada.
    #[must_use]
    pub fn vacia(&self) -> bool {
        self.ficheros.is_empty()
            && self.revocados.is_empty()
            && self.metodos_aml.is_empty()
            && self.opciones_rom.is_empty()
            && self.controladores.is_empty()
    }

    /// Si la base dice algo de los ficheros FFS de la ROM.
    #[must_use]
    pub fn cubre_ffs(&self) -> bool {
        !self.ficheros.is_empty() || !self.revocados.is_empty()
    }

    /// Cuantos ficheros conocidos hay.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ficheros.values().map(Vec::len).sum()
    }

    /// `true` si no hay ficheros conocidos.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clasifica un fichero FFS contra la base.
    ///
    /// El orden importa: **revocado gana siempre**. Un implante publicado puede
    /// haber reutilizado el GUID de un modulo legitimo justamente para pasar por
    /// conocido; comprobar el GUID primero lo dejaria pasar.
    #[must_use]
    pub fn clasificar(&self, guid: &Guid, sha256: &[u8; 32]) -> Veredicto {
        if let Some(nombre) = self.revocados.get(sha256) {
            return Veredicto::Revocado(nombre.clone());
        }
        // Sin entradas de FFS no se puede afirmar nada de un FFS, aunque la base
        // traiga AML u option ROMs: son otra superficie.
        if !self.cubre_ffs() {
            return Veredicto::SinBase;
        }
        match self.ficheros.get(guid) {
            None => Veredicto::Desconocido,
            Some(entradas) => {
                if let Some(e) = entradas.iter().find(|e| e.sha256 == *sha256) {
                    Veredicto::Conocido(e.etiqueta.clone())
                } else {
                    Veredicto::Alterado {
                        esperado: entradas
                            .first()
                            .map(|e| e.etiqueta.clone())
                            .unwrap_or_default(),
                    }
                }
            }
        }
    }

    /// Analiza una linea base en texto.
    ///
    /// # Errores
    /// [`ErrorBase`] si falta la version, no se reconoce, o una linea esta mal.
    /// Se falla en vez de ignorar la linea mala a proposito: una base cargada a
    /// medias haria que el auditor reportara «desconocido» sobre ficheros que si
    /// estaban, y el analista perseguiria fantasmas.
    pub fn analizar(texto: &str) -> Result<LineaBase, ErrorBase> {
        let mut base = LineaBase::default();
        let mut version_vista = false;

        for (i, cruda) in texto.lines().enumerate() {
            let linea = i + 1;
            let l = cruda.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let mut campos = l.split_whitespace();
            let Some(clave) = campos.next() else {
                continue;
            };
            match clave {
                "version" => {
                    let v = campos.next().unwrap_or_default();
                    if v != "1" {
                        return Err(ErrorBase::VersionDesconocida(v.to_string()));
                    }
                    version_vista = true;
                }
                _ if !version_vista => return Err(ErrorBase::SinVersion),
                "fv" => {
                    let g = campos.next().ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "falta el GUID del volumen",
                    })?;
                    base.volumenes
                        .push(guid_de_texto(g).ok_or(ErrorBase::LineaMalformada {
                            linea,
                            motivo: "GUID invalido",
                        })?);
                }
                "ffs" => {
                    let (Some(g), Some(h)) = (campos.next(), campos.next()) else {
                        return Err(ErrorBase::LineaMalformada {
                            linea,
                            motivo: "se esperaba: ffs <guid> <sha256> <etiqueta>",
                        });
                    };
                    let guid = guid_de_texto(g).ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "GUID invalido",
                    })?;
                    let sha256 = hash_de_texto(h).ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "SHA-256 invalido (se esperaban 64 hex)",
                    })?;
                    let etiqueta = campos.collect::<Vec<_>>().join(" ");
                    base.ficheros.entry(guid).or_default().push(Entrada {
                        sha256,
                        etiqueta: if etiqueta.is_empty() {
                            "(sin etiqueta)".to_string()
                        } else {
                            etiqueta
                        },
                    });
                }
                "revocado" => {
                    let h = campos.next().ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "falta el SHA-256",
                    })?;
                    let sha = hash_de_texto(h).ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "SHA-256 invalido",
                    })?;
                    let etiqueta = campos.collect::<Vec<_>>().join(" ");
                    base.revocados.insert(sha, etiqueta);
                }
                "aml" | "oprom" => {
                    let (Some(objeto), Some(h)) = (campos.next(), campos.next()) else {
                        return Err(ErrorBase::LineaMalformada {
                            linea,
                            motivo: "se esperaba: aml <ruta> <sha256> <etiqueta> u oprom <vvvv:dddd> <sha256> <etiqueta>",
                        });
                    };
                    let objeto = if clave == "oprom" {
                        if !es_id_pci(objeto) {
                            return Err(ErrorBase::LineaMalformada {
                                linea,
                                motivo: "identificador PCI invalido (se esperaba vvvv:dddd en hex)",
                            });
                        }
                        objeto.to_ascii_lowercase()
                    } else {
                        if !objeto.starts_with('\\') {
                            return Err(ErrorBase::LineaMalformada {
                                linea,
                                motivo: "la ruta AML tiene que ser absoluta (empieza por \\)",
                            });
                        }
                        objeto.to_string()
                    };
                    let sha256 = hash_de_texto(h).ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "SHA-256 invalido (se esperaban 64 hex)",
                    })?;
                    let etiqueta = campos.collect::<Vec<_>>().join(" ");
                    let destino = if clave == "aml" {
                        &mut base.metodos_aml
                    } else {
                        &mut base.opciones_rom
                    };
                    destino.entry(objeto).or_default().push(Entrada {
                        sha256,
                        etiqueta: if etiqueta.is_empty() {
                            "(sin etiqueta)".to_string()
                        } else {
                            etiqueta
                        },
                    });
                }
                "driver" => {
                    let h = campos.next().ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "falta el SHA-256",
                    })?;
                    let sha = hash_de_texto(h).ok_or(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "SHA-256 invalido",
                    })?;
                    base.controladores
                        .insert(sha, campos.collect::<Vec<_>>().join(" "));
                }
                _ => {
                    return Err(ErrorBase::LineaMalformada {
                        linea,
                        motivo: "clave desconocida (se esperaba fv/ffs/revocado/aml/oprom/driver)",
                    })
                }
            }
        }
        if !version_vista {
            return Err(ErrorBase::SinVersion);
        }
        Ok(base)
    }

    /// Carga una linea base de un fichero.
    ///
    /// # Errores
    /// [`ErrorBase`] si el contenido esta mal. Un fichero que no se puede leer
    /// devuelve una base VACIA, no un error: no tener base es un estado normal
    /// («no se puede afirmar nada»), y distinto de tener una base corrupta.
    pub fn cargar(ruta: &std::path::Path) -> Result<LineaBase, ErrorBase> {
        match std::fs::read_to_string(ruta) {
            Ok(t) => LineaBase::analizar(&t),
            Err(_) => Ok(LineaBase::default()),
        }
    }
}

/// `8c8ce578-8a3d-4f1c-9935-896185c32dd3` -> `Guid`.
///
/// El formato canonico mezcla endianness: los tres primeros campos van en
/// little-endian y los dos ultimos en big-endian. Tratarlo como 16 bytes
/// seguidos produce un GUID distinto que NUNCA casaria con el de la ROM, y el
/// sintoma seria «todos los ficheros desconocidos» sin explicacion.
#[must_use]
pub fn guid_de_texto(s: &str) -> Option<Guid> {
    let limpio: Vec<&str> = s.split('-').collect();
    if limpio.len() != 5 {
        return None;
    }
    let d1 = u32::from_str_radix(limpio[0], 16).ok()?;
    let d2 = u16::from_str_radix(limpio[1], 16).ok()?;
    let d3 = u16::from_str_radix(limpio[2], 16).ok()?;
    if limpio[3].len() != 4 || limpio[4].len() != 12 {
        return None;
    }
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&d1.to_le_bytes());
    b[4..6].copy_from_slice(&d2.to_le_bytes());
    b[6..8].copy_from_slice(&d3.to_le_bytes());
    for (i, par) in limpio[3]
        .as_bytes()
        .chunks_exact(2)
        .chain(limpio[4].as_bytes().chunks_exact(2))
        .enumerate()
    {
        let t = std::str::from_utf8(par).ok()?;
        b[8 + i] = u8::from_str_radix(t, 16).ok()?;
    }
    Some(Guid(b))
}

/// `8086:15f3`: dos campos de cuatro digitos hexadecimales.
#[must_use]
pub fn es_id_pci(s: &str) -> bool {
    s.split_once(':').is_some_and(|(v, d)| {
        v.len() == 4 && d.len() == 4 && v.chars().chain(d.chars()).all(|c| c.is_ascii_hexdigit())
    })
}

/// 64 caracteres hexadecimales -> 32 bytes.
#[must_use]
pub fn hash_de_texto(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, par) in s.as_bytes().chunks_exact(2).enumerate() {
        let t = std::str::from_utf8(par).ok()?;
        out[i] = u8::from_str_radix(t, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const HASH_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HASH_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const HASH_IMPLANTE: &str = "dead00000000000000000000000000000000000000000000000000000000beef";
    const GUID_A: &str = "8c8ce578-8a3d-4f1c-9935-896185c32dd3";

    fn base() -> LineaBase {
        LineaBase::analizar(&format!(
            "version 1\n\
             # comentario\n\
             fv    {GUID_A}\n\
             ffs   {GUID_A} {HASH_A} DxeCore v1\n\
             ffs   {GUID_A} {HASH_B} DxeCore v2\n\
             revocado {HASH_IMPLANTE} LoJax/SecDxe\n"
        ))
        .expect("base valida")
    }

    #[test]
    fn la_base_se_analiza_con_sus_tres_clases_de_entrada() {
        let b = base();
        assert_eq!(b.volumenes.len(), 1);
        assert_eq!(b.len(), 2, "dos versiones del mismo GUID");
        assert_eq!(b.revocados.len(), 1);
        assert!(!b.vacia());
    }

    /// Un GUID con DOS hashes validos: la misma placa con dos versiones de BIOS.
    /// Aceptar solo uno obligaria a una base por version y convertiria cada
    /// actualizacion legitima en una tormenta de alertas.
    #[test]
    fn un_guid_puede_tener_varias_versiones_validas() {
        let b = base();
        let g = guid_de_texto(GUID_A).expect("guid");
        assert!(matches!(
            b.clasificar(&g, &hash_de_texto(HASH_A).unwrap()),
            Veredicto::Conocido(_)
        ));
        assert!(matches!(
            b.clasificar(&g, &hash_de_texto(HASH_B).unwrap()),
            Veredicto::Conocido(_)
        ));
    }

    #[test]
    fn un_hash_distinto_sobre_un_guid_conocido_es_alteracion() {
        let b = base();
        let g = guid_de_texto(GUID_A).expect("guid");
        let otro = [0x99u8; 32];
        match b.clasificar(&g, &otro) {
            Veredicto::Alterado { esperado } => assert!(esperado.starts_with("DxeCore")),
            otro => panic!("se esperaba Alterado, no {otro:?}"),
        }
    }

    /// «Desconocido» NO es «malicioso». Una actualizacion legitima de BIOS cambia
    /// decenas de ficheros, y un parque con quince modelos tiene quince
    /// firmwares. Tratarlo como compromiso haria inservible la herramienta.
    #[test]
    fn un_guid_que_no_esta_en_la_base_es_desconocido_no_malicioso() {
        let b = base();
        let g = guid_de_texto("00000000-0000-0000-0000-000000000001").expect("guid");
        assert_eq!(b.clasificar(&g, &[0u8; 32]), Veredicto::Desconocido);
    }

    /// REVOCADO GANA SIEMPRE. Un implante publicado puede reutilizar el GUID de
    /// un modulo legitimo justamente para pasar por conocido; comprobar el GUID
    /// primero lo dejaria pasar.
    #[test]
    fn un_hash_revocado_gana_aunque_su_guid_sea_conocido() {
        let implante = hash_de_texto(HASH_IMPLANTE).unwrap();
        let mut b = base();
        // Se mete el hash del implante TAMBIEN como bueno, que es el peor caso.
        b.ficheros
            .entry(guid_de_texto(GUID_A).unwrap())
            .or_default()
            .push(Entrada {
                sha256: implante,
                etiqueta: "parece legitimo".into(),
            });
        let g = guid_de_texto(GUID_A).unwrap();
        match b.clasificar(&g, &implante) {
            Veredicto::Revocado(n) => assert_eq!(n, "LoJax/SecDxe"),
            otro => panic!("un hash revocado tiene que ganar, llego {otro:?}"),
        }
    }

    #[test]
    fn sin_base_cargada_no_se_afirma_nada() {
        let vacia = LineaBase::default();
        assert_eq!(
            vacia.clasificar(&Guid([0; 16]), &[0; 32]),
            Veredicto::SinBase
        );
    }

    /// El formato canonico de GUID mezcla endianness. Tratarlo como 16 bytes
    /// seguidos produce un GUID distinto que nunca casaria, y el sintoma seria
    /// «todos los ficheros desconocidos» sin explicacion.
    #[test]
    fn el_guid_respeta_la_mezcla_de_endianness_del_formato_canonico() {
        let g = guid_de_texto("8c8ce578-8a3d-4f1c-9935-896185c32dd3").expect("guid");
        assert_eq!(
            g.0,
            [
                0x78, 0xE5, 0x8C, 0x8C, // d1 little-endian
                0x3D, 0x8A, // d2 little-endian
                0x1C, 0x4F, // d3 little-endian
                0x99, 0x35, // d4 tal cual
                0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3, // d5 tal cual
            ]
        );
        // Y el ida y vuelta con el formateador de aegis-firmware.
        assert_eq!(g.hyphenated(), "8c8ce578-8a3d-4f1c-9935-896185c32dd3");
    }

    #[test]
    fn una_base_malformada_se_rechaza_en_vez_de_cargarse_a_medias() {
        // Sin version.
        assert!(matches!(
            LineaBase::analizar("ffs 8c8ce578-8a3d-4f1c-9935-896185c32dd3 x y"),
            Err(ErrorBase::SinVersion)
        ));
        // Version desconocida.
        assert!(matches!(
            LineaBase::analizar("version 9\n"),
            Err(ErrorBase::VersionDesconocida(_))
        ));
        // Hash de longitud equivocada.
        assert!(matches!(
            LineaBase::analizar(&format!("version 1\nffs {GUID_A} abc nombre\n")),
            Err(ErrorBase::LineaMalformada { .. })
        ));
        // GUID invalido.
        assert!(matches!(
            LineaBase::analizar(&format!("version 1\nffs no-es-un-guid {HASH_A} n\n")),
            Err(ErrorBase::LineaMalformada { .. })
        ));
        // Clave desconocida: se rechaza en vez de ignorarla, porque una base
        // cargada a medias hace perseguir fantasmas.
        assert!(matches!(
            LineaBase::analizar("version 1\nvacuna algo\n"),
            Err(ErrorBase::LineaMalformada { .. })
        ));
    }

    #[test]
    fn las_claves_de_la_fase_92_se_analizan_y_se_validan() {
        let b = LineaBase::analizar(&format!(
            "version 1\n\
             aml \\_SB.PCI0._INI {HASH_A} placa x\n\
             oprom 8086:15F3 {HASH_B} NIC\n\
             driver {HASH_A} GPU\n"
        ))
        .expect("base");
        assert_eq!(b.metodos_aml["\\_SB.PCI0._INI"].len(), 1);
        assert!(
            b.opciones_rom.contains_key("8086:15f3"),
            "el id se normaliza a minusculas"
        );
        assert_eq!(b.controladores.len(), 1);
        assert!(!b.vacia());
        // Una base que solo trae AML no dice nada de los FFS.
        assert!(!b.cubre_ffs());
        assert_eq!(b.clasificar(&Guid([1; 16]), &[0; 32]), Veredicto::SinBase);
        for mala in [
            format!("version 1\noprom 8086-15f3 {HASH_A} x\n"),
            format!("version 1\naml _SB.X {HASH_A} x\n"),
            "version 1\naml \\X corto\n".to_string(),
            "version 1\ndriver zz\n".to_string(),
        ] {
            assert!(
                matches!(
                    LineaBase::analizar(&mala),
                    Err(ErrorBase::LineaMalformada { .. })
                ),
                "{mala}"
            );
        }
    }

    #[test]
    fn una_base_que_no_existe_no_es_un_error() {
        let b = LineaBase::cargar(std::path::Path::new("/no/existe/base.txt")).expect("sin error");
        assert!(b.vacia());
    }

    #[test]
    fn el_hash_hexadecimal_solo_acepta_lo_que_es() {
        assert!(hash_de_texto(HASH_A).is_some());
        assert!(hash_de_texto("").is_none());
        assert!(hash_de_texto(&"a".repeat(63)).is_none());
        assert!(hash_de_texto(&"a".repeat(65)).is_none());
        assert!(hash_de_texto(&"z".repeat(64)).is_none());
    }
}
