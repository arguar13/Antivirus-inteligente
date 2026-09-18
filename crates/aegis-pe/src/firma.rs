//! La firma Authenticode: donde esta, que cubre y —sobre todo— que NO cubre.
//!
//! # La huella no es el hash del fichero
//!
//! Es el error que parece una optimizacion y es un agujero. Un ejecutable
//! firmado lleva la firma DENTRO de si mismo, asi que el hash del fichero
//! cambiaria al firmarlo y la firma no podria cubrirse a si misma. Authenticode
//! resuelve eso saltandose tres tramos, y hay que saltarse **exactamente** esos
//! tres:
//!
//! 1. El campo `CheckSum` del encabezado opcional, cuatro bytes. Windows lo
//!    recalcula al firmar.
//! 2. La entrada del directorio de seguridad, ocho bytes. Apunta a la propia
//!    firma, que todavia no existe cuando se calcula la huella.
//! 3. La tabla de certificados entera, al final del fichero. Es la firma.
//!
//! Y el resto **si** se cubre, en un orden concreto: los encabezados hasta
//! `SizeOfHeaders`, luego cada seccion **por orden creciente de
//! `PointerToRawData`** —no por orden de la tabla, que puede estar desordenada—
//! y por ultimo lo que quede del fichero por delante de la tabla de
//! certificados.
//!
//! # Por que cada salto de mas o de menos es explotable
//!
//! - **Saltarse de mas** hace que un byte cambiado no mueva la huella: se puede
//!   editar el ejecutable y la firma sigue validando.
//! - **Saltarse de menos** hace que la huella no cuadre nunca y todo salga como
//!   no firmado, que en la practica significa desactivar la comprobacion de
//!   firma porque nadie aguanta ese ruido.
//! - **Ordenar las secciones por la tabla en vez de por su desplazamiento** da
//!   una huella distinta a la de Windows en cuanto alguien desordena la tabla, y
//!   desordenarla es legal.
//!
//! El unico caso de los tres que se nota en pruebas hechas con ficheros
//! bonitos es ninguno. Por eso las de este crate se hacen contra PE **reales**
//! construidos en la maquina de integracion, y comprueban las propiedades que
//! definen la huella: que cambiar el `CheckSum` no la mueve, y que cambiar
//! cualquier otro byte si.

use sha2::{Digest, Sha256};

use crate::error::PeError;
use crate::imagen::Imagen;
use crate::lectura::Lector;

/// Una entrada de la tabla de certificados (`WIN_CERTIFICATE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificado {
    /// Desplazamiento de la entrada en el fichero.
    pub offset: u64,
    /// Longitud declarada, incluida la cabecera de ocho bytes.
    pub longitud: u32,
    /// Revision del formato (`WIN_CERT_REVISION_*`).
    pub revision: u16,
    /// Tipo (`WIN_CERT_TYPE_PKCS_SIGNED_DATA` = 2 es lo normal).
    pub tipo: u16,
}

/// Lo que se sabe de la firma de un ejecutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firma {
    /// Las entradas de la tabla de certificados.
    pub certificados: Vec<Certificado>,
    /// Desplazamiento de la tabla en el fichero.
    pub offset_tabla: u64,
    /// Tamano declarado de la tabla.
    pub tamano_tabla: u64,
    /// Bytes que hay en el fichero POR DETRAS de la tabla de certificados.
    ///
    /// En un ejecutable firmado normal esto vale cero: la tabla es lo ultimo.
    /// Cualquier otra cosa significa que alguien anadio datos detras de la
    /// firma, y ese es un truco con nombre propio —el adjunto que viaja pegado a
    /// un instalador legitimo— porque hay herramientas que siguen llamando
    /// «firmado» al fichero resultante.
    pub bytes_tras_la_tabla: u64,
}

impl Firma {
    /// Lee la tabla de certificados de una imagen, si la declara.
    ///
    /// Devuelve `Ok(None)` cuando el ejecutable no esta firmado, que no es un
    /// error: la mayoria de los ficheros de una maquina no lo estan.
    pub fn leer(imagen: &Imagen, bytes: &[u8]) -> Result<Option<Firma>, PeError> {
        let Some(dir) = imagen.directorio_de_seguridad() else {
            return Ok(None);
        };
        let l = Lector::nuevo(bytes);
        // OJO: en el directorio de seguridad este campo es un desplazamiento de
        // fichero, no una RVA. Ver la nota de `crate::imagen`.
        let offset_tabla = u64::from(dir.direccion);
        let tamano_tabla = u64::from(dir.tamano);
        if !l.cabe(offset_tabla, tamano_tabla) {
            return Err(PeError::DirectorioFueraDelFichero {
                indice: crate::imagen::DIR_SEGURIDAD,
                offset: offset_tabla,
                tamano: tamano_tabla,
                fichero: l.tamano(),
            });
        }

        let mut certificados = Vec::new();
        let mut cursor = offset_tabla;
        let fin = offset_tabla + tamano_tabla;
        while cursor + 8 <= fin {
            let longitud = l.u32(cursor, "dwLength de un certificado")?;
            // Una longitud que no cubre ni su propia cabecera haria avanzar el
            // cursor cero bytes o hacia atras: bucle infinito con un fichero
            // que lo unico que tiene de especial es un campo a cero.
            if u64::from(longitud) < 8 || cursor + u64::from(longitud) > fin {
                return Err(PeError::CertificadoMalFormado {
                    offset: cursor,
                    longitud: u64::from(longitud),
                    tabla: tamano_tabla,
                });
            }
            certificados.push(Certificado {
                offset: cursor,
                longitud,
                revision: l.u16(cursor + 4, "wRevision")?,
                tipo: l.u16(cursor + 6, "wCertificateType")?,
            });
            // Las entradas van alineadas a ocho bytes.
            let avance = (u64::from(longitud) + 7) & !7;
            cursor += avance;
        }

        Ok(Some(Firma {
            certificados,
            offset_tabla,
            tamano_tabla,
            bytes_tras_la_tabla: l.tamano().saturating_sub(fin),
        }))
    }
}

/// Calcula la huella Authenticode SHA-256 de un ejecutable.
///
/// Es la huella que Windows compara con la que va firmada dentro del PKCS#7. No
/// es el SHA-256 del fichero, y la diferencia es el modulo entero: ver la nota
/// de cabecera.
pub fn huella_authenticode(imagen: &Imagen, bytes: &[u8]) -> Result<[u8; 32], PeError> {
    let l = Lector::nuevo(bytes);
    let tam_encabezados = u64::from(imagen.tamano_encabezados);
    if tam_encabezados > l.tamano() {
        return Err(PeError::CabecerasFueraDelFichero {
            declarado: tam_encabezados,
            fichero: l.tamano(),
        });
    }

    let mut h = Sha256::new();

    // --- 1. Del principio al CheckSum -------------------------------------
    h.update(l.tramo(0, imagen.offset_checksum, "hasta el CheckSum")?);

    // --- 2. Del CheckSum a la entrada del directorio de seguridad ---------
    let tras_checksum = imagen.offset_checksum + 4;
    let hasta_dir = imagen
        .offset_dir_seguridad
        .checked_sub(tras_checksum)
        .ok_or(PeError::SeAcabaElFichero {
            que: "el tramo entre el CheckSum y el directorio de seguridad",
            desde: tras_checksum,
            necesita: 0,
            hay: 0,
        })?;
    h.update(l.tramo(tras_checksum, hasta_dir, "hasta el directorio")?);

    // --- 3. Del directorio de seguridad al final de los encabezados -------
    let tras_dir = imagen.offset_dir_seguridad + 8;
    let resto = tam_encabezados
        .checked_sub(tras_dir)
        .ok_or(PeError::CabecerasFueraDelFichero {
            declarado: tam_encabezados,
            fichero: l.tamano(),
        })?;
    h.update(l.tramo(tras_dir, resto, "el resto de los encabezados")?);

    // --- 4. Cada seccion, por orden de desplazamiento ---------------------
    // Por DESPLAZAMIENTO, no por el orden de la tabla. La tabla puede venir
    // desordenada y sigue siendo un fichero valido; ordenar por ella daria una
    // huella distinta de la de Windows sin que nada lo indicase.
    let mut orden: Vec<_> = imagen
        .secciones
        .iter()
        .filter(|s| s.tamano_bruto > 0)
        .collect();
    orden.sort_by_key(|s| s.offset_bruto);

    let mut cubiertos = tam_encabezados;
    for s in orden {
        let off = u64::from(s.offset_bruto);
        let largo = u64::from(s.tamano_bruto);
        if !l.cabe(off, largo) {
            return Err(PeError::SeccionFueraDelFichero {
                nombre: s.nombre.clone(),
                offset: off,
                tamano: largo,
                fichero: l.tamano(),
            });
        }
        h.update(l.tramo(off, largo, "los bytes de una seccion")?);
        cubiertos += largo;
    }

    // --- 5. Lo que quede, por delante de la tabla de certificados ---------
    // La tabla de certificados ES la firma, asi que se excluye. Lo que haya
    // entre el final de las secciones y la tabla —el overlay— SI se cubre: es
    // donde un instalador lleva su carga, y dejarlo fuera permitiria cambiarla
    // sin invalidar la firma.
    let tamano_firma = imagen
        .directorio_de_seguridad()
        .map(|d| u64::from(d.tamano))
        .unwrap_or(0);
    let hasta = l.tamano().saturating_sub(tamano_firma);
    if hasta > cubiertos {
        h.update(l.tramo(cubiertos, hasta - cubiertos, "el overlay")?);
    }

    Ok(h.finalize().into())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_ejecutable_sin_directorio_de_seguridad_no_esta_firmado_y_no_es_un_error() {
        // La mayoria de los ficheros de una maquina no estan firmados. Tratarlo
        // como error obligaria a quien llama a distinguir «no firmado» de «no se
        // pudo leer», que es justo lo que no hay que confundir.
        let imagen = Imagen {
            formato: crate::imagen::Formato::Pe32Mas,
            maquina: 0x8664,
            compilado: 0,
            caracteristicas: 0,
            punto_de_entrada: 0x1000,
            base: 0x1_4000_0000,
            tamano_encabezados: 0x400,
            tamano_imagen: 0x2000,
            subsistema: 3,
            caracteristicas_dll: 0,
            directorios: vec![Default::default(); 16],
            secciones: vec![],
            offset_checksum: 0x100,
            offset_dir_seguridad: 0x200,
            tamano_fichero: 0x400,
        };
        assert_eq!(Firma::leer(&imagen, &[0u8; 0x400]).unwrap(), None);
    }

    #[test]
    fn una_longitud_de_certificado_a_cero_no_cuelga_el_lector() {
        // El bucle avanza `dwLength` bytes. Con `dwLength` = 0 el cursor no se
        // mueve y el bucle no termina nunca: un fichero de ocho bytes bien
        // puestos cuelga el agente. Se rechaza en vez de avanzar a ciegas.
        let mut bytes = vec![0u8; 0x100];
        // Tabla de 16 bytes en el desplazamiento 0x40, con dwLength = 0.
        bytes[0x40..0x44].copy_from_slice(&0u32.to_le_bytes());
        let imagen = imagen_con_firma(0x40, 16, bytes.len() as u64);
        let e = Firma::leer(&imagen, &bytes).unwrap_err();
        assert!(matches!(e, PeError::CertificadoMalFormado { .. }), "{e}");
    }

    #[test]
    fn una_longitud_de_certificado_mayor_que_la_tabla_se_rechaza() {
        let mut bytes = vec![0u8; 0x100];
        bytes[0x40..0x44].copy_from_slice(&9_999u32.to_le_bytes());
        let imagen = imagen_con_firma(0x40, 16, bytes.len() as u64);
        assert!(matches!(
            Firma::leer(&imagen, &bytes).unwrap_err(),
            PeError::CertificadoMalFormado { .. }
        ));
    }

    #[test]
    fn una_tabla_que_apunta_fuera_del_fichero_se_rechaza() {
        let bytes = vec![0u8; 0x100];
        let imagen = imagen_con_firma(0x1000, 16, bytes.len() as u64);
        assert!(matches!(
            Firma::leer(&imagen, &bytes).unwrap_err(),
            PeError::DirectorioFueraDelFichero { .. }
        ));
    }

    #[test]
    fn se_cuentan_los_bytes_que_haya_por_detras_de_la_firma() {
        // La tabla ocupa de 0x40 a 0x50 y el fichero mide 0x100: hay 0xb0 bytes
        // pegados detras de la firma.
        let mut bytes = vec![0u8; 0x100];
        bytes[0x40..0x44].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x44..0x46].copy_from_slice(&0x0200u16.to_le_bytes());
        bytes[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        let imagen = imagen_con_firma(0x40, 16, bytes.len() as u64);
        let f = Firma::leer(&imagen, &bytes).unwrap().unwrap();
        assert_eq!(f.certificados.len(), 1);
        assert_eq!(f.certificados[0].tipo, 2, "PKCS#7");
        assert_eq!(f.bytes_tras_la_tabla, 0x100 - 0x50);
    }

    fn imagen_con_firma(offset: u32, tamano: u32, fichero: u64) -> Imagen {
        let mut directorios = vec![crate::imagen::Directorio::default(); 16];
        directorios[crate::imagen::DIR_SEGURIDAD] = crate::imagen::Directorio {
            direccion: offset,
            tamano,
        };
        Imagen {
            formato: crate::imagen::Formato::Pe32Mas,
            maquina: 0x8664,
            compilado: 0,
            caracteristicas: 0,
            punto_de_entrada: 0x1000,
            base: 0x1_4000_0000,
            tamano_encabezados: 0x400,
            tamano_imagen: 0x2000,
            subsistema: 3,
            caracteristicas_dll: 0,
            directorios,
            secciones: vec![],
            offset_checksum: 0x100,
            offset_dir_seguridad: 0x200,
            tamano_fichero: fichero,
        }
    }
}
