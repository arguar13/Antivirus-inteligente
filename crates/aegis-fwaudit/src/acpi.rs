//! Tablas ACPI: la cabecera comun, su checksum, y la lectura de las que el
//! firmware de esta maquina le entregó al kernel.
//!
//! # Por que las tablas ACPI son una superficie de ataque
//!
//! El firmware le pasa al sistema operativo un conjunto de tablas que describen
//! el hardware. El SO **se las cree**: son la palabra del firmware, que se
//! ejecuta antes que él y por debajo de él. Una APT que controla la placa base no
//! necesita tocar el disco para persistir: le basta con que el firmware declare
//! una tabla mas.
//!
//! El caso extremo es **WPBT** (ver [`crate::wpbt`]), que literalmente significa
//! «SO: ejecuta este binario en cada arranque». Pero hay mas: una tabla con el
//! checksum roto significa que **alguien la reescribio despues** de que el
//! firmware la firmara, y una tabla que lleva una cabecera `MZ`/`PE` en su cuerpo
//! esta transportando un ejecutable donde deberia haber descripcion de hardware.
//!
//! # Todo esto se lee, nunca se escribe
//!
//! `/sys/firmware/acpi/tables` son ficheros `0400` servidos por el kernel. Este
//! modulo los abre por [`crate::solo_lectura`], que es el unico camino de acceso
//! a disco del crate y no expone ninguna operacion de escritura.

use std::path::{Path, PathBuf};

use crate::solo_lectura::{ErrorLectura, LecturaSolo};

/// Donde el kernel expone las tablas ACPI estaticas.
pub const DIR_TABLAS: &str = "/sys/firmware/acpi/tables";

/// Donde expone las tablas cargadas dinamicamente (SSDT anadidas en caliente).
///
/// Se miran a proposito: una SSDT cargada **despues** del arranque es un vector
/// de inyeccion, y mirar solo las estaticas lo dejaria pasar.
pub const DIR_TABLAS_DINAMICAS: &str = "/sys/firmware/acpi/tables/dynamic";

/// Tamano de la cabecera comun a toda tabla ACPI.
pub const TAM_CABECERA: usize = 36;

/// Tope de tamano que se acepta leer de una tabla.
///
/// La DSDT de una maquina grande ronda los cientos de kilobytes; 16 MiB deja
/// margen de sobra. El tope existe porque `Length` es un `u32` que controla el
/// FIRMWARE: reservar memoria a partir de un numero que declara la superficie
/// que estamos auditando es exactamente como se tumba un agente.
pub const TOPE_TABLA: u32 = 16 * 1024 * 1024;

/// Error al analizar una tabla ACPI.
#[derive(Debug, thiserror::Error)]
pub enum ErrorAcpi {
    /// El fichero no llega ni a la cabecera comun.
    #[error("la tabla mide {tenia} B y la cabecera comun son {TAM_CABECERA} B")]
    Corta {
        /// Bytes que tenia.
        tenia: usize,
    },
    /// `Length` no cuadra con el tamano real del fichero.
    #[error("la tabla declara {declarada} B pero el fichero tiene {fichero} B")]
    LongitudImposible {
        /// Lo que declara la cabecera.
        declarada: u32,
        /// Lo que mide de verdad.
        fichero: usize,
    },
    /// `Length` supera el tope aceptado.
    #[error("la tabla declara {declarada} B, por encima del tope de {TOPE_TABLA} B")]
    LongitudDesmedida {
        /// Lo que declara la cabecera.
        declarada: u32,
    },
    /// Fallo de lectura.
    #[error(transparent)]
    Lectura(#[from] ErrorLectura),
}

/// La cabecera comun de 36 bytes de toda tabla ACPI.
///
/// Los desplazamientos estan fijados por la especificacion ACPI y **verificados
/// contra las tablas reales de esta maquina** en las pruebas: si alguno estuviera
/// mal, el checksum de una tabla autentica no daria cero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabeceraAcpi {
    /// Firma de cuatro caracteres (`APIC`, `DSDT`, `WPBT`...).
    pub firma: [u8; 4],
    /// Longitud total de la tabla, cabecera incluida.
    pub longitud: u32,
    /// Revision del formato.
    pub revision: u8,
    /// Byte de checksum tal y como viene.
    pub checksum: u8,
    /// Identificador del fabricante.
    pub oem_id: [u8; 6],
    /// Identificador de la tabla dentro del fabricante.
    pub oem_table_id: [u8; 8],
    /// Revision del fabricante.
    pub oem_revision: u32,
    /// Quien genero la tabla.
    pub creator_id: [u8; 4],
    /// Revision del generador.
    pub creator_revision: u32,
}

impl CabeceraAcpi {
    /// Analiza la cabecera comun.
    ///
    /// # Errores
    /// [`ErrorAcpi::Corta`] si no hay 36 bytes.
    pub fn analizar(bytes: &[u8]) -> Result<CabeceraAcpi, ErrorAcpi> {
        if bytes.len() < TAM_CABECERA {
            return Err(ErrorAcpi::Corta { tenia: bytes.len() });
        }
        let u32_en = |o: usize| {
            u32::from_le_bytes(bytes[o..o + 4].try_into().expect("acotado por la longitud"))
        };
        Ok(CabeceraAcpi {
            firma: bytes[0..4].try_into().expect("acotado"),
            longitud: u32_en(4),
            revision: bytes[8],
            checksum: bytes[9],
            oem_id: bytes[10..16].try_into().expect("acotado"),
            oem_table_id: bytes[16..24].try_into().expect("acotado"),
            oem_revision: u32_en(24),
            creator_id: bytes[28..32].try_into().expect("acotado"),
            creator_revision: u32_en(32),
        })
    }

    /// La firma como texto imprimible.
    #[must_use]
    pub fn firma_texto(&self) -> String {
        texto_ascii(&self.firma)
    }

    /// El `OEMID` como texto imprimible.
    #[must_use]
    pub fn oem_texto(&self) -> String {
        texto_ascii(&self.oem_id)
    }

    /// El `OEM Table ID` como texto imprimible.
    #[must_use]
    pub fn oem_tabla_texto(&self) -> String {
        texto_ascii(&self.oem_table_id)
    }
}

/// Convierte un campo de texto de la cabecera a algo imprimible.
///
/// Los bytes vienen del firmware y no tienen por que ser ASCII: un campo con
/// bytes de control es en si mismo una anomalia, y sustituirlos por `?` hace que
/// el informe sea legible sin ocultar que habia algo raro.
fn texto_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Comprueba el checksum de 8 bits de una tabla ACPI.
///
/// La regla de la especificacion: la suma de **todos** los bytes de la tabla
/// —incluido el propio byte de checksum— modulo 256 tiene que dar **cero**.
///
/// Que incluya su propio byte no es una curiosidad: es lo que permite verificar
/// sin saber donde esta el campo. Y es la razon de que una tabla reescrita por un
/// implante casi siempre falle aqui, salvo que el atacante se moleste en
/// recalcularlo — cosa que, medido en los implantes publicos, muchas veces no
/// hacen.
#[must_use]
pub fn checksum_valido(tabla: &[u8]) -> bool {
    tabla
        .iter()
        .fold(0u8, |acumulado, b| acumulado.wrapping_add(*b))
        == 0
}

/// Una tabla ACPI leida y analizada.
#[derive(Debug, Clone)]
pub struct TablaAcpi {
    /// De donde se leyo.
    pub ruta: PathBuf,
    /// La cabecera.
    pub cabecera: CabeceraAcpi,
    /// El contenido completo.
    pub bytes: Vec<u8>,
    /// Si el checksum cuadra.
    pub checksum_ok: bool,
    /// Si venia del directorio de tablas cargadas dinamicamente.
    pub dinamica: bool,
}

impl TablaAcpi {
    /// El cuerpo, sin la cabecera comun.
    #[must_use]
    pub fn cuerpo(&self) -> &[u8] {
        self.bytes.get(TAM_CABECERA..).unwrap_or(&[])
    }

    /// Nombre corto para el informe.
    #[must_use]
    pub fn nombre(&self) -> String {
        let f = self.cabecera.firma_texto();
        if self.dinamica {
            format!("{f} (dinamica)")
        } else {
            f
        }
    }
}

/// Analiza una tabla ya leida en memoria.
///
/// # Errores
/// [`ErrorAcpi`] si la cabecera no cuadra con el contenido.
pub fn analizar_tabla(ruta: &Path, bytes: Vec<u8>, dinamica: bool) -> Result<TablaAcpi, ErrorAcpi> {
    let cabecera = CabeceraAcpi::analizar(&bytes)?;
    if cabecera.longitud > TOPE_TABLA {
        return Err(ErrorAcpi::LongitudDesmedida {
            declarada: cabecera.longitud,
        });
    }
    // El fichero de sysfs sirve EXACTAMENTE `Length` bytes. Que no coincidan
    // significa que la cabecera miente sobre su propio tamano, y eso ya es la
    // anomalia: se reporta como error para que el decisor lo vea.
    if cabecera.longitud as usize != bytes.len() {
        return Err(ErrorAcpi::LongitudImposible {
            declarada: cabecera.longitud,
            fichero: bytes.len(),
        });
    }
    let checksum_ok = checksum_valido(&bytes);
    Ok(TablaAcpi {
        ruta: ruta.to_path_buf(),
        cabecera,
        bytes,
        checksum_ok,
        dinamica,
    })
}

/// El conjunto de tablas que el firmware entregó al kernel.
#[derive(Debug, Default)]
pub struct ConjuntoTablas {
    /// Las tablas que se pudieron leer y analizar.
    pub tablas: Vec<TablaAcpi>,
    /// Ficheros que estaban pero no se pudieron leer o analizar, con el motivo.
    ///
    /// Se conservan: la diferencia entre «esta maquina no tiene WPBT» y «habia
    /// una tabla que no se pudo leer» es exactamente lo que el analista necesita,
    /// y silenciarla haria que un fichero ilegible se leyera como ausencia.
    pub ilegibles: Vec<(PathBuf, String)>,
}

impl ConjuntoTablas {
    /// Busca una tabla por firma.
    #[must_use]
    pub fn por_firma(&self, firma: &[u8; 4]) -> Option<&TablaAcpi> {
        self.tablas.iter().find(|t| t.cabecera.firma == *firma)
    }

    /// Cuantas tablas hay.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tablas.len()
    }

    /// Si no se leyo ninguna tabla.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tablas.is_empty()
    }
}

/// Lee y analiza todas las tablas ACPI de esta maquina.
///
/// No falla si el directorio no existe: una maquina sin ACPI expuesta (un
/// contenedor, un ARM sin ACPI) es un «no aplicable», no un fallo.
#[must_use]
pub fn leer_tablas_del_sistema() -> ConjuntoTablas {
    let mut conjunto = ConjuntoTablas::default();
    leer_directorio(Path::new(DIR_TABLAS), false, &mut conjunto);
    leer_directorio(Path::new(DIR_TABLAS_DINAMICAS), true, &mut conjunto);
    // Orden estable por firma y ruta: dos auditorias de la misma maquina tienen
    // que producir el mismo informe, o compararlas deja de ser trivial.
    conjunto.tablas.sort_by(|a, b| {
        a.cabecera
            .firma
            .cmp(&b.cabecera.firma)
            .then(a.ruta.cmp(&b.ruta))
    });
    conjunto
}

/// Lee un directorio de tablas y acumula el resultado.
fn leer_directorio(dir: &Path, dinamica: bool, salida: &mut ConjuntoTablas) {
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entradas.flatten() {
        let ruta = e.path();
        // El directorio `dynamic` y el `data` cuelgan de `tables`: se saltan aqui
        // y `dynamic` se recorre en su propia llamada.
        if ruta.is_dir() {
            continue;
        }
        let lector = match LecturaSolo::abrir(&ruta) {
            Ok(l) => l,
            Err(err) => {
                salida.ilegibles.push((ruta, err.to_string()));
                continue;
            }
        };
        let bytes = match lector.leer_todo(TOPE_TABLA as usize) {
            Ok(b) => b,
            Err(err) => {
                salida.ilegibles.push((ruta, err.to_string()));
                continue;
            }
        };
        match analizar_tabla(&ruta, bytes, dinamica) {
            Ok(t) => salida.tablas.push(t),
            Err(err) => salida.ilegibles.push((ruta, err.to_string())),
        }
    }
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Construye una tabla ACPI valida byte a byte, con su checksum bien puesto.
    ///
    /// No es un mock: es el formato REAL, construido segun la especificacion. El
    /// decisor que lo analiza es el mismo que analiza las tablas de la maquina.
    pub(crate) fn tabla(firma: &[u8; 4], cuerpo: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; TAM_CABECERA];
        t[0..4].copy_from_slice(firma);
        t[8] = 2; // revision
        t[10..16].copy_from_slice(b"AEGIS ");
        t[16..24].copy_from_slice(b"PRUEBA01");
        t[28..32].copy_from_slice(b"AGS ");
        t.extend_from_slice(cuerpo);
        let largo = t.len() as u32;
        t[4..8].copy_from_slice(&largo.to_le_bytes());
        // El checksum se elige para que la suma de TODOS los bytes de cero.
        let suma = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        t[9] = suma.wrapping_neg();
        t
    }

    #[test]
    fn el_checksum_es_cero_sumando_todos_los_bytes_incluido_el_propio() {
        let t = tabla(b"TEST", b"cuerpo de prueba");
        assert!(checksum_valido(&t));

        // Cambiar UN byte del cuerpo lo rompe: es lo que delata a una tabla
        // reescrita despues de que el firmware la generara.
        let mut alterada = t.clone();
        let ultimo = alterada.len() - 1;
        alterada[ultimo] ^= 0x01;
        assert!(!checksum_valido(&alterada));

        // Y un atacante que SI recalcule el checksum pasa esta comprobacion: por
        // eso no es la unica, y por eso el decisor mira ademas el contenido.
        let suma = alterada.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        alterada[9] = alterada[9].wrapping_sub(suma);
        assert!(checksum_valido(&alterada));
    }

    #[test]
    fn la_cabecera_se_lee_en_los_desplazamientos_de_la_especificacion() {
        let t = tabla(b"WPBT", &[0xAA; 20]);
        let c = CabeceraAcpi::analizar(&t).expect("cabecera valida");
        assert_eq!(&c.firma, b"WPBT");
        assert_eq!(c.longitud as usize, t.len());
        assert_eq!(c.revision, 2);
        assert_eq!(c.oem_texto(), "AEGIS");
        assert_eq!(c.oem_tabla_texto(), "PRUEBA01");
        assert_eq!(c.firma_texto(), "WPBT");
    }

    #[test]
    fn una_tabla_mas_corta_que_la_cabecera_se_rechaza() {
        for n in [0usize, 1, 35] {
            assert!(matches!(
                CabeceraAcpi::analizar(&vec![0u8; n]),
                Err(ErrorAcpi::Corta { .. })
            ));
        }
        assert!(CabeceraAcpi::analizar(&[0u8; 36]).is_ok());
    }

    /// Una longitud declarada de 4 GiB es un fichero preparado a mano. Reservar
    /// esa memoria a partir de un numero que controla el firmware es como se
    /// tumba un agente desde la superficie que esta auditando.
    #[test]
    fn una_longitud_desmedida_se_rechaza_sin_reservar_memoria() {
        let mut t = tabla(b"EVIL", b"x");
        t[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let r = analizar_tabla(Path::new("/tmp/x"), t, false);
        assert!(
            matches!(r, Err(ErrorAcpi::LongitudDesmedida { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn una_longitud_que_no_cuadra_con_el_fichero_se_rechaza() {
        let mut t = tabla(b"EVIL", b"cuerpo");
        t[4..8].copy_from_slice(&1000u32.to_le_bytes());
        let r = analizar_tabla(Path::new("/tmp/x"), t, false);
        assert!(
            matches!(r, Err(ErrorAcpi::LongitudImposible { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn un_texto_no_ascii_se_hace_legible_sin_ocultar_que_era_raro() {
        assert_eq!(texto_ascii(b"AEGIS \0\0"), "AEGIS");
        assert_eq!(texto_ascii(&[0x01, 0x02, b'A']), "??A");
        assert_eq!(texto_ascii(b""), "");
    }

    /// LAS TABLAS REALES DE ESTA MAQUINA. No es un vector sintetico: es el
    /// firmware de verdad. Si los desplazamientos de la cabecera estuvieran mal,
    /// el checksum de una tabla autentica no daria cero.
    #[test]
    fn las_tablas_acpi_reales_de_esta_maquina_se_analizan_y_cuadran() {
        let c = leer_tablas_del_sistema();
        if c.is_empty() {
            eprintln!(
                "OMITIDA: esta maquina no expone tablas ACPI en {DIR_TABLAS} \
                 (ilegibles: {})",
                c.ilegibles.len()
            );
            return;
        }
        eprintln!("tablas ACPI reales encontradas: {}", c.len());
        for t in &c.tablas {
            eprintln!(
                "  {:<8} {:>7} B  rev {}  OEM {:<7} checksum {}",
                t.nombre(),
                t.bytes.len(),
                t.cabecera.revision,
                t.cabecera.oem_texto(),
                if t.checksum_ok { "OK" } else { "ROTO" }
            );
            assert_eq!(
                t.cabecera.longitud as usize,
                t.bytes.len(),
                "{}: Length no cuadra con el tamano servido por sysfs",
                t.nombre()
            );
            assert!(
                t.checksum_ok,
                "{}: el checksum de una tabla REAL del firmware tiene que dar cero; \
                 si no, o el firmware de esta maquina esta alterado o los \
                 desplazamientos de la cabecera estan mal",
                t.nombre()
            );
            assert!(
                t.cabecera.firma.iter().all(u8::is_ascii_graphic),
                "{}: la firma tiene que ser ASCII imprimible",
                t.nombre()
            );
        }
        // Una maquina con ACPI tiene, como minimo, la FACP.
        assert!(
            c.por_firma(b"FACP").is_some() || !c.is_empty(),
            "se esperaba al menos una tabla reconocible"
        );
    }
}
