//! Lo que la forma de un ejecutable delata, y lo que no.
//!
//! # Esto son indicios, no veredictos
//!
//! Cada cosa de este modulo tiene falsos positivos conocidos, y se dicen. Una
//! seccion escribible y ejecutable la produce un empaquetador —y tambien un
//! compilador viejo, y algun instalador legitimo—. Un ejecutable sin firma es lo
//! normal en casi todo el disco. Un overlay grande lo tiene cualquier instalador.
//!
//! Por eso este crate **no clasifica**. Devuelve hechos sobre la forma del
//! fichero, con su frase y su explicacion, y quien decide es el motor de
//! veredicto con todo lo demas delante: el linaje, el comportamiento, la
//! reputacion. Un lector de formato que se pusiera a decir «malicioso» seria un
//! antivirus de los noventa, con su tasa de falsos positivos.
//!
//! Lo que si hace es dar los hechos que un analista no puede sacar de otra
//! forma sin abrir el fichero a mano.

use crate::firma::Firma;
use crate::imagen::Imagen;

/// Un hecho sobre la forma de un ejecutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indicio {
    /// Una seccion se mapea escribible **y** ejecutable.
    SeccionEscribibleYEjecutable {
        /// Nombre de la seccion.
        seccion: String,
    },
    /// El punto de entrada no cae dentro de ninguna seccion.
    PuntoDeEntradaFueraDeTodaSeccion {
        /// RVA declarada.
        rva: u32,
    },
    /// El punto de entrada cae en una seccion escribible.
    PuntoDeEntradaEnSeccionEscribible {
        /// Nombre de la seccion.
        seccion: String,
    },
    /// Dos secciones ocupan el mismo tramo del fichero.
    SeccionesQueSeSolapan {
        /// Primera seccion.
        una: String,
        /// Segunda seccion.
        otra: String,
    },
    /// Una seccion ocupara en memoria muchisimo mas de lo que trae en disco.
    TamanoVirtualDesproporcionado {
        /// Nombre de la seccion.
        seccion: String,
        /// Cuantas veces mas grande en memoria.
        veces: u32,
    },
    /// No lleva tabla de certificados.
    SinFirma,
    /// Hay bytes pegados por detras de la tabla de certificados.
    DatosPegadosTrasLaFirma {
        /// Cuantos.
        bytes: u64,
    },
    /// No pide reubicacion aleatoria (ASLR).
    SinAslr,
    /// No pide prevencion de ejecucion de datos (DEP).
    SinDep,
}

impl Indicio {
    /// La frase con la que aparece en un informe, y su falso positivo conocido.
    pub fn frase(&self) -> String {
        match self {
            Indicio::SeccionEscribibleYEjecutable { seccion } => format!(
                "la seccion «{seccion}» se mapea escribible y ejecutable a la vez, que es \
                 como se desempaqueta codigo en memoria; tambien lo hacen algunos \
                 empaquetadores comerciales y compiladores antiguos"
            ),
            Indicio::PuntoDeEntradaFueraDeTodaSeccion { rva } => format!(
                "el punto de entrada ({rva:#x}) no cae en ninguna seccion declarada: el \
                 fichero dice empezar a ejecutar donde el no ha puesto nada"
            ),
            Indicio::PuntoDeEntradaEnSeccionEscribible { seccion } => format!(
                "el punto de entrada esta en «{seccion}», que es escribible: el codigo \
                 que arranca puede reescribirse a si mismo"
            ),
            Indicio::SeccionesQueSeSolapan { una, otra } => format!(
                "«{una}» y «{otra}» ocupan el mismo tramo del fichero; el cargador \
                 resolvera el solape de una forma y quien analice el fichero puede \
                 resolverlo de otra"
            ),
            Indicio::TamanoVirtualDesproporcionado { seccion, veces } => format!(
                "«{seccion}» ocupara {veces} veces mas en memoria que en disco, que es la \
                 forma de un empaquetador que se descomprime al arrancar; tambien la de \
                 una seccion de datos sin inicializar"
            ),
            Indicio::SinFirma => "no lleva firma Authenticode, como la mayoria de los \
                 ejecutables de una maquina"
                .into(),
            Indicio::DatosPegadosTrasLaFirma { bytes } => format!(
                "hay {bytes} bytes pegados POR DETRAS de la tabla de certificados; la \
                 firma no los cubre y hay herramientas que aun asi llaman «firmado» al \
                 fichero entero"
            ),
            Indicio::SinAslr => "no pide reubicacion aleatoria (ASLR): sus direcciones son \
                 predecibles en cada arranque"
                .into(),
            Indicio::SinDep => {
                "no pide prevencion de ejecucion de datos (DEP): su pila y su monton seran \
                 ejecutables"
                    .into()
            }
        }
    }
}

/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`.
const DLL_ASLR: u16 = 0x0040;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
const DLL_DEP: u16 = 0x0100;

/// Cuantas veces mas grande en memoria que en disco empieza a llamar la atencion.
///
/// Diez es un umbral con criterio y no un numero redondo: una `.bss` normal
/// —datos sin inicializar— pasa de largo, y los empaquetadores tipicos
/// multiplican por mucho mas. Al ser un indicio y no un veredicto, errar por
/// exceso aqui cuesta una linea en un informe, no un bloqueo.
const VECES_SOSPECHOSAS: u32 = 10;

/// Reune los indicios de la forma de un ejecutable.
pub fn de(imagen: &Imagen, firma: Option<&Firma>) -> Vec<Indicio> {
    let mut v = Vec::new();

    for s in &imagen.secciones {
        if s.escribible() && s.ejecutable() {
            v.push(Indicio::SeccionEscribibleYEjecutable {
                seccion: s.nombre.clone(),
            });
        }
        if s.tamano_bruto > 0 {
            let veces = s.tamano_virtual / s.tamano_bruto.max(1);
            if veces >= VECES_SOSPECHOSAS {
                v.push(Indicio::TamanoVirtualDesproporcionado {
                    seccion: s.nombre.clone(),
                    veces,
                });
            }
        }
    }

    // Solapes en el fichero. Se comparan todas contra todas porque el maximo son
    // 96 secciones: 4560 comparaciones en el peor caso, que no es nada, y una
    // ordenacion previa se equivocaria con las de tamano cero.
    let con_bytes: Vec<_> = imagen
        .secciones
        .iter()
        .filter(|s| s.tamano_bruto > 0)
        .collect();
    for (i, a) in con_bytes.iter().enumerate() {
        for b in con_bytes.iter().skip(i + 1) {
            let (a0, a1) = (
                u64::from(a.offset_bruto),
                u64::from(a.offset_bruto) + u64::from(a.tamano_bruto),
            );
            let (b0, b1) = (
                u64::from(b.offset_bruto),
                u64::from(b.offset_bruto) + u64::from(b.tamano_bruto),
            );
            if a0 < b1 && b0 < a1 {
                v.push(Indicio::SeccionesQueSeSolapan {
                    una: a.nombre.clone(),
                    otra: b.nombre.clone(),
                });
            }
        }
    }

    // El punto de entrada. Un punto de entrada a cero es legal en una DLL sin
    // `DllMain`, asi que no se mira: acusar ahi seria acusar a media biblioteca
    // del sistema.
    if imagen.punto_de_entrada != 0 {
        match imagen.seccion_de_rva(imagen.punto_de_entrada) {
            None => v.push(Indicio::PuntoDeEntradaFueraDeTodaSeccion {
                rva: imagen.punto_de_entrada,
            }),
            Some(s) if s.escribible() => v.push(Indicio::PuntoDeEntradaEnSeccionEscribible {
                seccion: s.nombre.clone(),
            }),
            Some(_) => {}
        }
    }

    match firma {
        None => v.push(Indicio::SinFirma),
        Some(f) if f.bytes_tras_la_tabla > 0 => v.push(Indicio::DatosPegadosTrasLaFirma {
            bytes: f.bytes_tras_la_tabla,
        }),
        Some(_) => {}
    }

    if imagen.caracteristicas_dll & DLL_ASLR == 0 {
        v.push(Indicio::SinAslr);
    }
    if imagen.caracteristicas_dll & DLL_DEP == 0 {
        v.push(Indicio::SinDep);
    }

    v
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::imagen::{Directorio, Formato, Seccion, SECCION_EJECUTABLE, SECCION_ESCRIBIBLE};

    fn imagen(secciones: Vec<Seccion>, entrada: u32, dll: u16) -> Imagen {
        Imagen {
            formato: Formato::Pe32Mas,
            maquina: 0x8664,
            compilado: 0,
            caracteristicas: 0,
            punto_de_entrada: entrada,
            base: 0x1_4000_0000,
            tamano_encabezados: 0x400,
            tamano_imagen: 0x4000,
            subsistema: 3,
            caracteristicas_dll: dll,
            directorios: vec![Directorio::default(); 16],
            secciones,
            offset_checksum: 0x100,
            offset_dir_seguridad: 0x200,
            tamano_fichero: 0x1000,
        }
    }

    fn seccion(nombre: &str, rva: u32, off: u32, largo: u32, carac: u32) -> Seccion {
        Seccion {
            nombre: nombre.into(),
            tamano_virtual: largo,
            rva,
            tamano_bruto: largo,
            offset_bruto: off,
            caracteristicas: carac,
        }
    }

    #[test]
    fn una_seccion_escribible_y_ejecutable_se_senala() {
        let i = imagen(
            vec![seccion(
                ".text",
                0x1000,
                0x400,
                0x200,
                SECCION_EJECUTABLE | SECCION_ESCRIBIBLE,
            )],
            0x1000,
            DLL_ASLR | DLL_DEP,
        );
        let v = de(&i, None);
        assert!(v
            .iter()
            .any(|x| matches!(x, Indicio::SeccionEscribibleYEjecutable { .. })));
    }

    #[test]
    fn un_punto_de_entrada_fuera_de_toda_seccion_se_senala() {
        let i = imagen(
            vec![seccion(".text", 0x1000, 0x400, 0x200, SECCION_EJECUTABLE)],
            0x9999,
            DLL_ASLR | DLL_DEP,
        );
        assert!(de(&i, None)
            .iter()
            .any(|x| matches!(x, Indicio::PuntoDeEntradaFueraDeTodaSeccion { rva: 0x9999 })));
    }

    #[test]
    fn un_punto_de_entrada_a_cero_no_se_acusa() {
        // Es legal en una DLL sin DllMain. Acusar ahi seria acusar a media
        // biblioteca del sistema, y un indicio que salta siempre no es un
        // indicio.
        let i = imagen(
            vec![seccion(".text", 0x1000, 0x400, 0x200, SECCION_EJECUTABLE)],
            0,
            DLL_ASLR | DLL_DEP,
        );
        let v = de(&i, None);
        assert!(!v
            .iter()
            .any(|x| matches!(x, Indicio::PuntoDeEntradaFueraDeTodaSeccion { .. })));
    }

    #[test]
    fn dos_secciones_que_ocupan_el_mismo_tramo_se_senalan_una_sola_vez() {
        let i = imagen(
            vec![
                seccion(".text", 0x1000, 0x400, 0x400, SECCION_EJECUTABLE),
                seccion(".data", 0x2000, 0x600, 0x400, 0),
            ],
            0x1000,
            DLL_ASLR | DLL_DEP,
        );
        let solapes: Vec<_> = de(&i, None)
            .into_iter()
            .filter(|x| matches!(x, Indicio::SeccionesQueSeSolapan { .. }))
            .collect();
        assert_eq!(solapes.len(), 1, "cada par se cuenta una vez: {solapes:?}");
    }

    #[test]
    fn dos_secciones_pegadas_pero_sin_solape_no_se_senalan() {
        // El caso de frontera que un `<=` mal puesto convierte en falso
        // positivo en TODOS los ejecutables, porque las secciones van pegadas.
        let i = imagen(
            vec![
                seccion(".text", 0x1000, 0x400, 0x200, SECCION_EJECUTABLE),
                seccion(".data", 0x2000, 0x600, 0x200, 0),
            ],
            0x1000,
            DLL_ASLR | DLL_DEP,
        );
        assert!(!de(&i, None)
            .iter()
            .any(|x| matches!(x, Indicio::SeccionesQueSeSolapan { .. })));
    }

    #[test]
    fn una_seccion_que_crece_diez_veces_en_memoria_se_senala() {
        let mut s = seccion(".packed", 0x1000, 0x400, 0x100, SECCION_EJECUTABLE);
        s.tamano_virtual = 0x100 * 12;
        let i = imagen(vec![s], 0x1000, DLL_ASLR | DLL_DEP);
        assert!(de(&i, None)
            .iter()
            .any(|x| matches!(x, Indicio::TamanoVirtualDesproporcionado { veces: 12, .. })));
    }

    #[test]
    fn sin_aslr_y_sin_dep_se_senalan_por_separado() {
        let i = imagen(
            vec![seccion(".text", 0x1000, 0x400, 0x200, SECCION_EJECUTABLE)],
            0x1000,
            0,
        );
        let v = de(&i, None);
        assert!(v.contains(&Indicio::SinAslr));
        assert!(v.contains(&Indicio::SinDep));
    }

    #[test]
    fn con_aslr_y_dep_no_se_dice_nada_de_ellos() {
        let i = imagen(
            vec![seccion(".text", 0x1000, 0x400, 0x200, SECCION_EJECUTABLE)],
            0x1000,
            DLL_ASLR | DLL_DEP,
        );
        let v = de(&i, None);
        assert!(!v.contains(&Indicio::SinAslr));
        assert!(!v.contains(&Indicio::SinDep));
    }

    #[test]
    fn cada_frase_explica_el_hecho_y_su_falso_positivo() {
        // Un indicio sin su falso positivo escrito acaba tratado como veredicto
        // por quien lo lea deprisa.
        for i in [
            Indicio::SeccionEscribibleYEjecutable {
                seccion: ".text".into(),
            },
            Indicio::TamanoVirtualDesproporcionado {
                seccion: ".x".into(),
                veces: 30,
            },
            Indicio::SinFirma,
        ] {
            let f = i.frase();
            assert!(
                f.contains("tambien") || f.contains("como la mayoria"),
                "esta frase no dice su falso positivo: {f}"
            );
        }
    }
}
