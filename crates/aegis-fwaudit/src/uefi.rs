//! Volúmenes de firmware UEFI y sus ficheros FFS: el contenido real de la BIOS.
//!
//! # Que hay dentro de la region BIOS
//!
//! La region BIOS que delimita el descriptor ([`crate::spi`]) contiene uno o
//! varios **volumenes de firmware** (`EFI_FIRMWARE_VOLUME`). Cada volumen es, en
//! la practica, un sistema de ficheros minimo: una cabecera con su firma `_FVH` y
//! detras una secuencia de **ficheros FFS**, cada uno con su GUID, su tipo y su
//! contenido. Los modulos DXE, los drivers, el gestor de arranque: todo eso son
//! ficheros FFS.
//!
//! Un implante de firmware —LoJax, CosmicStrand, MoonBounce— **anade o sustituye
//! un fichero FFS**. Por eso la deteccion no es buscar una firma de malware: es
//! recorrer los ficheros, calcular el hash de cada uno y compararlo con lo que
//! deberia haber. Un fichero cuyo GUID no conocemos, o cuyo GUID conocemos con
//! otro hash, es la deteccion.
//!
//! # Los dos detalles que hacen que un recorrido ingenuo se cuelgue o mienta
//!
//! 1. **El tamano puede ser cero.** `Size` es un entero de 24 bits que viene de
//!    la ROM, es decir, de la superficie que estamos auditando. Si un fichero
//!    declara `Size = 0`, un recorrido que avance `Size` bytes **no avanza**, y
//!    se cuelga. El recorrido de aqui exige progreso estricto y para si no lo hay.
//! 2. **El byte `State` muta en la flash viva.** Un fichero FFS pasa por
//!    `HEADER_VALID` → `DATA_VALID` → `MARKED_FOR_UPDATE` → `DELETED` sin que su
//!    contenido cambie. Si el hash incluyera ese byte, el MISMO fichero daria
//!    hashes distintos en dos lecturas y toda la linea base seria inutil. Por eso
//!    el hash **canonico** excluye `State` y los dos bytes de `IntegrityCheck`,
//!    que tambien se recalculan.
//!
//! Ese segundo punto es el que separa una linea base que funciona de una que
//! produce falsos positivos cada vez que la placa actualiza algo.

use sha2::{Digest, Sha256};

use aegis_firmware::guid::Guid;

/// Firma `_FVH` en little-endian, en el desplazamiento 40 de la cabecera.
pub const FIRMA_FVH: u32 = 0x4856_465F;

/// Desplazamiento de la firma dentro de la cabecera del volumen.
pub const OFF_FIRMA: usize = 40;
/// Desplazamiento del GUID del sistema de ficheros.
pub const OFF_GUID_FS: usize = 16;
/// Desplazamiento de la longitud del volumen (u64).
pub const OFF_FV_LENGTH: usize = 32;
/// Desplazamiento de los atributos (u32).
pub const OFF_ATRIBUTOS: usize = 44;
/// Desplazamiento de la longitud de la cabecera (u16).
pub const OFF_HEADER_LENGTH: usize = 48;
/// Desplazamiento del checksum de la cabecera (u16).
pub const OFF_CHECKSUM: usize = 50;
/// Tamano minimo de una cabecera de volumen.
pub const TAM_MIN_CABECERA_FV: usize = 56;

/// Desplazamiento del GUID del fichero FFS.
pub const OFF_FFS_NOMBRE: usize = 0;
/// Desplazamiento del checksum de cabecera del FFS.
pub const OFF_FFS_CHK_CABECERA: usize = 16;
/// Desplazamiento del checksum de fichero del FFS.
pub const OFF_FFS_CHK_FICHERO: usize = 17;
/// Desplazamiento del tipo.
pub const OFF_FFS_TIPO: usize = 18;
/// Desplazamiento de los atributos.
pub const OFF_FFS_ATRIBUTOS: usize = 19;
/// Desplazamiento del tamano (entero de 24 bits).
pub const OFF_FFS_TAMANO: usize = 20;
/// Desplazamiento del byte de estado.
pub const OFF_FFS_ESTADO: usize = 23;
/// Tamano de la cabecera FFS clasica.
pub const TAM_CABECERA_FFS: usize = 24;
/// Tamano de la cabecera FFS2 (ficheros grandes).
pub const TAM_CABECERA_FFS2: usize = 32;
/// Atributo `FFS_ATTRIB_LARGE_FILE`: el tamano real esta en `ExtendedSize`.
pub const ATRIB_FICHERO_GRANDE: u8 = 0x01;

/// Alineacion a la que se redondea el comienzo de cada fichero FFS.
pub const ALINEACION_FFS: u64 = 8;

/// Tope de ficheros por volumen, para que una ROM preparada no genere un
/// recorrido interminable aunque cada paso avance un byte.
pub const MAX_FICHEROS_POR_VOLUMEN: usize = 8192;

/// Un volumen de firmware localizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volumen {
    /// Desplazamiento dentro de la imagen.
    pub offset: u64,
    /// Longitud declarada.
    pub longitud: u64,
    /// GUID del sistema de ficheros que declara.
    pub guid_fs: Guid,
    /// Longitud de la cabecera.
    pub longitud_cabecera: u16,
    /// Atributos.
    pub atributos: u32,
    /// Si el checksum de 16 bits de la cabecera cuadra.
    pub checksum_ok: bool,
}

/// Un fichero FFS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FicheroFfs {
    /// Desplazamiento dentro de la imagen.
    pub offset: u64,
    /// GUID que lo identifica.
    pub guid: Guid,
    /// Tipo de fichero (driver DXE, PEIM, seccion cruda...).
    pub tipo: u8,
    /// Tamano total, cabecera incluida.
    pub tamano: u64,
    /// Byte de estado tal y como estaba en la flash.
    pub estado: u8,
    /// SHA-256 **canonico**: excluye los bytes que mutan sin que el contenido
    /// cambie. Ver [`hash_canonico`].
    pub sha256: [u8; 32],
}

impl FicheroFfs {
    /// El hash en hexadecimal, para el informe y la linea base.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Comprueba el checksum de 16 bits de la cabecera de un volumen.
///
/// La regla de la especificacion PI: la suma de las palabras de 16 bits de la
/// cabecera, modulo 2^16, tiene que dar cero.
#[must_use]
pub fn checksum_cabecera_fv(cabecera: &[u8]) -> bool {
    if cabecera.len() < TAM_MIN_CABECERA_FV || cabecera.len() % 2 != 0 {
        return false;
    }
    cabecera.chunks_exact(2).fold(0u16, |a, c| {
        a.wrapping_add(u16::from_le_bytes([c[0], c[1]]))
    }) == 0
}

/// Analiza la cabecera de un volumen en `offset`.
///
/// Devuelve `None` si ahi no hay un volumen valido.
#[must_use]
pub fn analizar_volumen(imagen: &[u8], offset: u64) -> Option<Volumen> {
    let base = usize::try_from(offset).ok()?;
    let cab = imagen.get(base..base.checked_add(TAM_MIN_CABECERA_FV)?)?;

    if u32::from_le_bytes(cab[OFF_FIRMA..OFF_FIRMA + 4].try_into().ok()?) != FIRMA_FVH {
        return None;
    }
    let longitud = u64::from_le_bytes(cab[OFF_FV_LENGTH..OFF_FV_LENGTH + 8].try_into().ok()?);
    let longitud_cabecera = u16::from_le_bytes(
        cab[OFF_HEADER_LENGTH..OFF_HEADER_LENGTH + 2]
            .try_into()
            .ok()?,
    );
    let atributos = u32::from_le_bytes(cab[OFF_ATRIBUTOS..OFF_ATRIBUTOS + 4].try_into().ok()?);

    // Coherencia ANTES de fiarse de nada: una cabecera mas larga que el volumen,
    // o un volumen mas largo que la imagen, es una cabecera fabricada.
    if (longitud_cabecera as u64) < TAM_MIN_CABECERA_FV as u64
        || longitud < longitud_cabecera as u64
        || offset.checked_add(longitud)? > imagen.len() as u64
    {
        return None;
    }

    let cabecera_completa = imagen.get(base..base + longitud_cabecera as usize)?;
    Some(Volumen {
        offset,
        longitud,
        guid_fs: Guid::from_bytes(&cab[OFF_GUID_FS..OFF_GUID_FS + 16]),
        longitud_cabecera,
        atributos,
        checksum_ok: checksum_cabecera_fv(cabecera_completa),
    })
}

/// Localiza todos los volumenes dentro de un rango de la imagen.
///
/// Los volumenes empiezan alineados a 4 KiB en la practica, y el barrido lo
/// aprovecha: buscar la firma byte a byte encontraria coincidencias dentro de
/// datos comprimidos y produciria volumenes fantasma.
#[must_use]
pub fn localizar_volumenes(imagen: &[u8], inicio: u64, fin: u64) -> Vec<Volumen> {
    const PASO: u64 = 4096;
    let mut salida = Vec::new();
    let mut off = inicio;
    let tope = fin.min(imagen.len() as u64);
    while off + TAM_MIN_CABECERA_FV as u64 <= tope {
        if let Some(v) = analizar_volumen(imagen, off) {
            // Se salta el volumen entero: los ficheros de dentro no son
            // volumenes, y buscarlos ahi daria anidamientos falsos.
            off = off.saturating_add(v.longitud.max(PASO));
            salida.push(v);
        } else {
            off = off.saturating_add(PASO);
        }
    }
    salida
}

/// El **hash canonico** de un fichero FFS.
///
/// Excluye los tres bytes que el firmware recalcula sin que el contenido cambie:
/// los dos de `IntegrityCheck` (desplazamientos 16 y 17) y el de `State`
/// (desplazamiento 23).
///
/// # Por que esto es imprescindible
///
/// El byte `State` muta en la flash viva: `HEADER_VALID` → `DATA_VALID` →
/// `MARKED_FOR_UPDATE` → `DELETED`. Si entrara en el hash, el MISMO fichero
/// daria hashes distintos en dos lecturas de la misma maquina, la linea base no
/// casaria nunca y el auditor reportaria «fichero alterado» en cada arranque.
/// Un detector que grita siempre es un detector que nadie mira.
#[must_use]
pub fn hash_canonico(fichero: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for (i, b) in fichero.iter().enumerate() {
        let mutable = i == OFF_FFS_CHK_CABECERA || i == OFF_FFS_CHK_FICHERO || i == OFF_FFS_ESTADO;
        // Los bytes mutables se sustituyen por cero en vez de saltarse: asi el
        // hash sigue dependiendo de la POSICION de cada byte, y un fichero al que
        // le quitaran justo esos tres no colisionaria con otro.
        h.update([if mutable { 0 } else { *b }]);
    }
    h.finalize().into()
}

/// Recorre los ficheros FFS de un volumen.
///
/// # Por que el recorrido exige progreso estricto
///
/// `Size` es un entero de 24 bits que viene de la ROM, es decir, de la superficie
/// que se esta auditando. Un fichero que declare `Size = 0` —o menor que su
/// cabecera— haria que un recorrido ingenuo no avanzara y se colgara. Aqui, si un
/// paso no avanza, el recorrido **para** y lo que lleva se devuelve: un volumen
/// mal formado da una lista parcial, no un cuelgue.
#[must_use]
pub fn recorrer_ficheros(imagen: &[u8], volumen: &Volumen) -> Vec<FicheroFfs> {
    let mut salida = Vec::new();
    let mut off = volumen.offset + volumen.longitud_cabecera as u64;
    let fin = (volumen.offset + volumen.longitud).min(imagen.len() as u64);

    while salida.len() < MAX_FICHEROS_POR_VOLUMEN {
        let Ok(base) = usize::try_from(off) else {
            break;
        };
        if off + TAM_CABECERA_FFS as u64 > fin {
            break;
        }
        let Some(cab) = imagen.get(base..base + TAM_CABECERA_FFS) else {
            break;
        };

        // Espacio libre: la flash borrada son todo 0xFF. Es el final util del
        // volumen, no un error.
        if cab.iter().all(|b| *b == 0xFF) {
            break;
        }

        let atributos = cab[OFF_FFS_ATRIBUTOS];
        let tamano24 = u32::from_le_bytes([
            cab[OFF_FFS_TAMANO],
            cab[OFF_FFS_TAMANO + 1],
            cab[OFF_FFS_TAMANO + 2],
            0,
        ]) as u64;

        // Los ficheros grandes llevan el tamano real en un u64 detras de la
        // cabecera clasica. Leerlo del campo de 24 bits daria 0xFFFFFF y el
        // recorrido se saldria del volumen.
        let (tamano, cabecera) = if atributos & ATRIB_FICHERO_GRANDE != 0 {
            let Some(ext) = imagen.get(base + TAM_CABECERA_FFS..base + TAM_CABECERA_FFS2) else {
                break;
            };
            (
                u64::from_le_bytes(ext.try_into().expect("8 bytes")),
                TAM_CABECERA_FFS2 as u64,
            )
        } else {
            (tamano24, TAM_CABECERA_FFS as u64)
        };

        // PROGRESO ESTRICTO: un tamano que no cubre ni la cabecera, o que se sale
        // del volumen, para el recorrido. Sin esto, `Size = 0` es un cuelgue.
        if tamano < cabecera || off.saturating_add(tamano) > fin {
            break;
        }

        let Some(bytes) = imagen.get(base..base + tamano as usize) else {
            break;
        };
        salida.push(FicheroFfs {
            offset: off,
            guid: Guid::from_bytes(&cab[OFF_FFS_NOMBRE..OFF_FFS_NOMBRE + 16]),
            tipo: cab[OFF_FFS_TIPO],
            tamano,
            estado: cab[OFF_FFS_ESTADO],
            sha256: hash_canonico(bytes),
        });

        // El siguiente fichero empieza alineado a 8 bytes.
        let siguiente = alinear(off.saturating_add(tamano), ALINEACION_FFS);
        if siguiente <= off {
            break;
        }
        off = siguiente;
    }
    salida
}

/// Redondea hacia arriba a un multiplo de `a`.
const fn alinear(v: u64, a: u64) -> u64 {
    if a == 0 {
        return v;
    }
    v.div_ceil(a).saturating_mul(a)
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Construye un fichero FFS REAL byte a byte.
    pub(crate) fn ffs(guid: [u8; 16], tipo: u8, estado: u8, cuerpo: &[u8]) -> Vec<u8> {
        let total = TAM_CABECERA_FFS + cuerpo.len();
        let mut f = vec![0u8; TAM_CABECERA_FFS];
        f[OFF_FFS_NOMBRE..OFF_FFS_NOMBRE + 16].copy_from_slice(&guid);
        f[OFF_FFS_TIPO] = tipo;
        f[OFF_FFS_TAMANO] = (total & 0xFF) as u8;
        f[OFF_FFS_TAMANO + 1] = ((total >> 8) & 0xFF) as u8;
        f[OFF_FFS_TAMANO + 2] = ((total >> 16) & 0xFF) as u8;
        f[OFF_FFS_ESTADO] = estado;
        f.extend_from_slice(cuerpo);
        f
    }

    /// Construye un volumen de firmware REAL con sus ficheros dentro.
    pub(crate) fn volumen(ficheros: &[Vec<u8>], longitud: u64) -> Vec<u8> {
        let mut v = vec![0u8; TAM_MIN_CABECERA_FV];
        // GUID del sistema de ficheros FFSv2, tal cual lo usa EDK2.
        v[OFF_GUID_FS..OFF_GUID_FS + 16].copy_from_slice(&[
            0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F, 0x99, 0x35, 0x89, 0x61, 0x85, 0xC3,
            0x2D, 0xD3,
        ]);
        v[OFF_FV_LENGTH..OFF_FV_LENGTH + 8].copy_from_slice(&longitud.to_le_bytes());
        v[OFF_FIRMA..OFF_FIRMA + 4].copy_from_slice(&FIRMA_FVH.to_le_bytes());
        v[OFF_HEADER_LENGTH..OFF_HEADER_LENGTH + 2]
            .copy_from_slice(&(TAM_MIN_CABECERA_FV as u16).to_le_bytes());
        // El checksum se elige para que la suma de las palabras de cero.
        let suma = v.chunks_exact(2).fold(0u16, |a, c| {
            a.wrapping_add(u16::from_le_bytes([c[0], c[1]]))
        });
        let chk = suma.wrapping_neg();
        v[OFF_CHECKSUM..OFF_CHECKSUM + 2].copy_from_slice(&chk.to_le_bytes());

        for f in ficheros {
            v.extend_from_slice(f);
            while v.len() % ALINEACION_FFS as usize != 0 {
                v.push(0xFF);
            }
        }
        // El resto del volumen es flash borrada.
        v.resize(longitud as usize, 0xFF);
        v
    }

    fn guid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn un_volumen_se_reconoce_por_su_firma_y_su_checksum_cuadra() {
        let img = volumen(&[ffs(guid(1), 7, 0xF8, b"contenido")], 4096);
        let v = analizar_volumen(&img, 0).expect("volumen valido");
        assert_eq!(v.longitud, 4096);
        assert_eq!(v.longitud_cabecera as usize, TAM_MIN_CABECERA_FV);
        assert!(v.checksum_ok, "el checksum de 16 bits tiene que cuadrar");
    }

    #[test]
    fn los_ficheros_ffs_se_recorren_con_su_guid_tipo_y_hash() {
        let img = volumen(
            &[
                ffs(guid(0xAA), 0x07, 0xF8, b"driver DXE"),
                ffs(guid(0xBB), 0x03, 0xF8, b"PEIM"),
                ffs(guid(0xCC), 0x02, 0xF8, b"seccion cruda"),
            ],
            8192,
        );
        let v = analizar_volumen(&img, 0).expect("volumen");
        let ficheros = recorrer_ficheros(&img, &v);
        assert_eq!(ficheros.len(), 3, "{ficheros:#?}");
        assert_eq!(ficheros[0].guid, Guid::from_bytes(&guid(0xAA)));
        assert_eq!(ficheros[0].tipo, 0x07);
        assert_eq!(ficheros[1].tipo, 0x03);
        assert_eq!(ficheros[2].guid, Guid::from_bytes(&guid(0xCC)));
        // Cada uno con su hash, y todos distintos.
        let hashes: std::collections::BTreeSet<_> =
            ficheros.iter().map(FicheroFfs::sha256_hex).collect();
        assert_eq!(hashes.len(), 3);
        assert_eq!(ficheros[0].sha256_hex().len(), 64);
    }

    /// EL DETALLE QUE HACE UTIL A LA LINEA BASE. El byte `State` muta en la flash
    /// viva sin que el contenido cambie. Si entrara en el hash, el MISMO fichero
    /// daria hashes distintos en dos lecturas y el auditor reportaria «alterado»
    /// en cada arranque.
    #[test]
    fn el_hash_canonico_no_cambia_cuando_el_estado_muta_en_la_flash() {
        let cuerpo = b"un modulo DXE cualquiera";
        let recien_escrito = ffs(guid(5), 7, 0xF8, cuerpo); // DATA_VALID
        let marcado = ffs(guid(5), 7, 0xF0, cuerpo); // MARKED_FOR_UPDATE
        let borrado = ffs(guid(5), 7, 0xE0, cuerpo); // DELETED

        assert_ne!(
            recien_escrito, marcado,
            "los bytes SI son distintos en la flash"
        );
        assert_eq!(
            hash_canonico(&recien_escrito),
            hash_canonico(&marcado),
            "pero el hash canonico tiene que ser el MISMO"
        );
        assert_eq!(hash_canonico(&recien_escrito), hash_canonico(&borrado));

        // Y el contenido SI cambia el hash: si no, no detectaria nada.
        let alterado = ffs(guid(5), 7, 0xF8, b"un modulo DXE cualquierX");
        assert_ne!(hash_canonico(&recien_escrito), hash_canonico(&alterado));
    }

    /// EL CASO QUE CUELGA UN RECORRIDO INGENUO. `Size` viene de la ROM, que es la
    /// superficie que estamos auditando: un fichero que declara 0 hace que un
    /// bucle que avanza `Size` no avance nunca.
    #[test]
    fn un_tamano_cero_no_cuelga_el_recorrido() {
        let mut malo = ffs(guid(9), 7, 0xF8, b"x");
        malo[OFF_FFS_TAMANO] = 0;
        malo[OFF_FFS_TAMANO + 1] = 0;
        malo[OFF_FFS_TAMANO + 2] = 0;
        let img = volumen(&[malo], 4096);
        let v = analizar_volumen(&img, 0).expect("volumen");
        // Lo que importa es que ESTO TERMINE.
        let ficheros = recorrer_ficheros(&img, &v);
        assert!(
            ficheros.is_empty(),
            "un fichero con tamano 0 no se acepta: {ficheros:#?}"
        );
    }

    #[test]
    fn un_tamano_que_se_sale_del_volumen_para_el_recorrido() {
        let mut malo = ffs(guid(9), 7, 0xF8, b"x");
        malo[OFF_FFS_TAMANO] = 0xFF;
        malo[OFF_FFS_TAMANO + 1] = 0xFF;
        malo[OFF_FFS_TAMANO + 2] = 0x7F;
        let img = volumen(&[malo], 4096);
        let v = analizar_volumen(&img, 0).expect("volumen");
        assert!(recorrer_ficheros(&img, &v).is_empty());
    }

    #[test]
    fn la_flash_borrada_marca_el_final_util_del_volumen() {
        let img = volumen(&[ffs(guid(1), 7, 0xF8, b"uno")], 65536);
        let v = analizar_volumen(&img, 0).expect("volumen");
        let f = recorrer_ficheros(&img, &v);
        assert_eq!(f.len(), 1, "el 0xFF de detras no es un fichero");
    }

    #[test]
    fn una_cabecera_incoherente_no_se_toma_por_volumen() {
        // Longitud del volumen mayor que la imagen.
        let mut img = volumen(&[], 4096);
        img[OFF_FV_LENGTH..OFF_FV_LENGTH + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(analizar_volumen(&img, 0).is_none());

        // Cabecera mas larga que el volumen.
        let mut img2 = volumen(&[], 4096);
        img2[OFF_HEADER_LENGTH..OFF_HEADER_LENGTH + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(analizar_volumen(&img2, 0).is_none());

        // Sin firma.
        let img3 = vec![0u8; 4096];
        assert!(analizar_volumen(&img3, 0).is_none());
        // Y en un desplazamiento fuera de la imagen.
        assert!(analizar_volumen(&img3, 1_000_000).is_none());
    }

    #[test]
    fn se_localizan_varios_volumenes_sin_inventar_anidados() {
        let mut img = volumen(&[ffs(guid(1), 7, 0xF8, b"a")], 8192);
        img.extend(volumen(&[ffs(guid(2), 7, 0xF8, b"b")], 8192));
        let vs = localizar_volumenes(&img, 0, img.len() as u64);
        assert_eq!(vs.len(), 2, "{vs:#?}");
        assert_eq!(vs[0].offset, 0);
        assert_eq!(vs[1].offset, 8192);
    }

    #[test]
    fn el_recorrido_termina_con_cualquier_basura() {
        // Entrada hostil: un volumen valido con contenido aleatorio detras.
        let mut img = volumen(&[], 16384);
        for (i, b) in img.iter_mut().enumerate().skip(TAM_MIN_CABECERA_FV) {
            *b = (i * 7 % 251) as u8;
        }
        let Some(v) = analizar_volumen(&img, 0) else {
            return;
        };
        // Lo unico que importa: que TERMINE y no entre en panico.
        let f = recorrer_ficheros(&img, &v);
        assert!(f.len() <= MAX_FICHEROS_POR_VOLUMEN);
    }

    #[test]
    fn la_alineacion_redondea_hacia_arriba() {
        assert_eq!(alinear(0, 8), 0);
        assert_eq!(alinear(1, 8), 8);
        assert_eq!(alinear(8, 8), 8);
        assert_eq!(alinear(9, 8), 16);
        assert_eq!(alinear(u64::MAX, 8), u64::MAX);
    }
}
