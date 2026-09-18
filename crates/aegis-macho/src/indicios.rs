//! Lo que la forma de un binario de macOS delata, y lo que no.
//!
//! Igual que en Windows: **indicios, no veredictos**. Cada hecho lleva su falso
//! positivo en la propia frase, porque un indicio sin el acaba tratado como
//! veredicto por quien lo lea deprisa.

use crate::macho::{Comando, Macho};
use crate::universal::Binario;

/// Un hecho sobre la forma de un binario de macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndicioMac {
    /// El fichero contiene mas de un programa.
    ///
    /// No es sospechoso por si mismo —Apple distribuyo binarios universales
    /// durante dos transiciones de arquitectura— pero SI cambia lo que hay que
    /// hacer: analizar una rodaja no es analizar el fichero.
    VariosProgramasEnUnFichero {
        /// Cuantos.
        cuantos: usize,
        /// Las arquitecturas.
        arquitecturas: Vec<String>,
    },
    /// Una rodaja no se pudo leer.
    RodajaIlegible {
        /// Que arquitectura.
        arquitectura: String,
        /// Por que.
        motivo: String,
    },
    /// Un segmento se mapea escribible y ejecutable.
    SegmentoEscribibleYEjecutable {
        /// Nombre del segmento.
        segmento: String,
    },
    /// No declara firma de codigo.
    SinFirmaDeCodigo,
    /// Viene cifrado, asi que su contenido no se puede analizar en disco.
    Cifrado,
    /// Carga una biblioteca por una ruta que se puede secuestrar.
    ///
    /// `@rpath`, `@executable_path` y las rutas relativas se resuelven en
    /// ejecucion, y quien pueda escribir en el sitio donde se resuelven decide
    /// que codigo se carga. Es la tecnica de persistencia mas usada en macOS.
    DylibSecuestrable {
        /// La ruta tal y como la declara.
        ruta: String,
    },
}

impl IndicioMac {
    /// La frase con la que aparece en un informe, con su falso positivo.
    pub fn frase(&self) -> String {
        match self {
            IndicioMac::VariosProgramasEnUnFichero {
                cuantos,
                arquitecturas,
            } => format!(
                "el fichero contiene {cuantos} programas ({}), asi que analizar uno no es \
                 analizar el fichero; tambien lo hacen los binarios universales legitimos \
                 de Apple, y por eso hay que mirarlos todos y no sospechar del formato",
                arquitecturas.join(", ")
            ),
            IndicioMac::RodajaIlegible {
                arquitectura,
                motivo,
            } => format!(
                "la rodaja {arquitectura} no se pudo leer ({motivo}); el fichero la sigue \
                 teniendo y el sistema puede ejecutarla, asi que esto es cobertura que \
                 falta y no una rodaja que no existe"
            ),
            IndicioMac::SegmentoEscribibleYEjecutable { segmento } => format!(
                "el segmento «{segmento}» se mapea escribible y ejecutable; tambien lo hacen \
                 los compiladores JIT, que son legitimos y abundantes"
            ),
            IndicioMac::SinFirmaDeCodigo => "no declara firma de codigo; en macOS moderno es \
                 raro en un ejecutable distribuido, y normal en uno recien compilado en la \
                 propia maquina"
                .into(),
            IndicioMac::Cifrado => "viene cifrado, asi que su contenido no se puede analizar \
                 en disco; tambien lo estan las aplicaciones distribuidas por la App Store"
                .into(),
            IndicioMac::DylibSecuestrable { ruta } => format!(
                "carga «{ruta}», que se resuelve en ejecucion: quien pueda escribir donde se \
                 resuelve decide que codigo se carga. Tambien lo usan casi todas las \
                 aplicaciones empaquetadas para encontrar sus propias bibliotecas"
            ),
        }
    }
}

/// Reune los indicios de un binario de macOS.
pub fn de(binario: &Binario) -> Vec<IndicioMac> {
    let mut v = Vec::new();

    if let Binario::Universal { rodajas } = binario {
        v.push(IndicioMac::VariosProgramasEnUnFichero {
            cuantos: rodajas.len(),
            arquitecturas: rodajas
                .iter()
                .map(|r| r.arquitectura().to_owned())
                .collect(),
        });
        for r in rodajas {
            if let Err(e) = &r.macho {
                v.push(IndicioMac::RodajaIlegible {
                    arquitectura: r.arquitectura().to_owned(),
                    motivo: e.to_string(),
                });
            }
        }
    }

    // Cada programa se mira por separado. Un `for` sobre todas las rodajas y no
    // sobre «la» rodaja: es la diferencia entre analizar el fichero y analizar
    // una parte de el.
    let machos: Vec<&Macho> = match binario {
        Binario::Sencillo(m) => vec![m],
        Binario::Universal { rodajas } => rodajas
            .iter()
            .filter_map(|r| r.macho.as_ref().ok())
            .collect(),
    };

    for m in machos {
        for s in m.segmentos() {
            if s.escribible_y_ejecutable() {
                v.push(IndicioMac::SegmentoEscribibleYEjecutable {
                    segmento: s.nombre.clone(),
                });
            }
        }
        if !m.declara_firma() {
            v.push(IndicioMac::SinFirmaDeCodigo);
        }
        for c in &m.comandos {
            if let Comando::Cifrado { cryptid } = c {
                if *cryptid != 0 {
                    v.push(IndicioMac::Cifrado);
                }
            }
        }
        for d in m.dylibs() {
            if secuestrable(d) {
                v.push(IndicioMac::DylibSecuestrable { ruta: d.to_owned() });
            }
        }
    }

    v.dedup();
    v
}

/// Si una ruta de biblioteca se resuelve en ejecucion.
fn secuestrable(ruta: &str) -> bool {
    ruta.starts_with("@rpath")
        || ruta.starts_with("@executable_path")
        || ruta.starts_with("@loader_path")
        // Una ruta que no es absoluta se busca en el directorio de trabajo, que
        // lo elige quien lanza el proceso.
        || (!ruta.is_empty() && !ruta.starts_with('/') && !ruta.starts_with('@'))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn las_rutas_que_se_resuelven_en_ejecucion_se_senalan() {
        assert!(secuestrable("@rpath/libfoo.dylib"));
        assert!(secuestrable("@executable_path/../Frameworks/x.dylib"));
        assert!(secuestrable("@loader_path/x.dylib"));
        assert!(
            secuestrable("libfoo.dylib"),
            "relativa: el cwd lo elige otro"
        );
    }

    #[test]
    fn una_ruta_absoluta_del_sistema_no_se_senala() {
        // Si se senalara, cada binario de macOS produciria una decena de
        // indicios por `/usr/lib/libSystem.B.dylib` y nadie los leeria.
        assert!(!secuestrable("/usr/lib/libSystem.B.dylib"));
        assert!(!secuestrable(
            "/System/Library/Frameworks/Foundation.framework/Foundation"
        ));
        assert!(!secuestrable(""));
    }

    #[test]
    fn cada_frase_dice_su_falso_positivo() {
        for i in [
            IndicioMac::SinFirmaDeCodigo,
            IndicioMac::Cifrado,
            IndicioMac::SegmentoEscribibleYEjecutable {
                segmento: "__TEXT".into(),
            },
            IndicioMac::DylibSecuestrable {
                ruta: "@rpath/x".into(),
            },
        ] {
            // Sin distinguir mayusculas: la frase puede empezar por «Tambien»
            // segun donde caiga en el texto, y una prueba que dependa de eso
            // falla por un detalle de redaccion en vez de por lo que comprueba.
            let f = i.frase().to_lowercase();
            assert!(
                f.contains("tambien") || f.contains("normal en"),
                "esta frase no dice su falso positivo: {f}"
            );
        }
    }

    #[test]
    fn un_universal_siempre_avisa_de_que_son_varios_programas() {
        use crate::macho::MAGIC_64;
        use crate::universal::Rodaja;
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&MAGIC_64.to_le_bytes());
        let m = Macho::leer(&b).unwrap();
        let binario = Binario::Universal {
            rodajas: vec![
                Rodaja {
                    cputype: 0x0100_0007,
                    cpusubtype: 0,
                    offset: 0,
                    tamano: 32,
                    macho: Ok(m.clone()),
                },
                Rodaja {
                    cputype: 0x0100_000c,
                    cpusubtype: 0,
                    offset: 32,
                    tamano: 32,
                    macho: Ok(m),
                },
            ],
        };
        let v = de(&binario);
        assert!(v
            .iter()
            .any(|x| matches!(x, IndicioMac::VariosProgramasEnUnFichero { cuantos: 2, .. })));
    }
}
