//! Extraccion de ficheros transferidos, identificados por CONTENIDO.
//!
//! # Que aporta esto que no aporte el analisis de ficheros en disco
//!
//! Un fichero malicioso que llega por la red se puede ver **dos veces**: cuando
//! viaja y cuando se escribe. Verlo cuando viaja tiene tres ventajas que el
//! analisis en disco no puede dar:
//!
//! 1. Llega **antes** de que exista en la maquina.
//! 2. Se ve aunque el destino nunca lo escriba —ejecucion en memoria, carga
//!    reflectiva, un descargador que no toca el disco—, que es justo lo que hace
//!    el malware moderno para no dejar rastro.
//! 3. Se ve el **contexto**: de donde venia, por que protocolo, en que sesion.
//!    Un hash en disco no sabe nada de eso.
//!
//! # La identificacion va por magia, nunca por nombre ni por `Content-Type`
//!
//! Las dos cosas las escribe quien manda el fichero. Un `Content-Type:
//! text/plain` sobre un PE no es un caso raro: es la tecnica. Aqui el tipo sale
//! **de los bytes**, y la contradiccion entre lo declarado y lo real se emite
//! como senal propia, porque mentir sobre el tipo es en si mismo un indicio.
//!
//! # Memoria: se calcula el hash sin guardar el fichero
//!
//! El tamano del fichero lo elige el atacante. Guardar el contenido para
//! hashearlo al final seria dejarle reservar la memoria que quiera. Aqui el
//! SHA-256 se calcula **incrementalmente** y solo se conserva un prefijo corto
//! —el necesario para reconocer la magia—, asi que el coste por transferencia
//! esta acotado sea cual sea su tamano.
//!
//! # Lo que NO hace
//!
//! No reconstruye el fichero en disco ni lo entrega al motor antivirus: eso es
//! trabajo de otra capa, y mezclarlo aqui pondria escritura a disco dentro del
//! camino de paquete. Aqui se produce la identidad —tipo, tamano, hash— que esa
//! capa necesita para decidir.

use sha2::{Digest, Sha256};

use crate::hecho::{Hecho, ProtocoloApp};

/// Bytes iniciales que se conservan para reconocer el tipo.
///
/// Ninguna magia conocida necesita mas: la mas larga de las que se reconocen
/// aqui son los ocho bytes de la cabecera OLE.
pub const BYTES_PARA_TIPO: usize = 64;

/// Tamano a partir del cual una transferencia se considera desmesurada.
///
/// No corta la extraccion —el hash sigue siendo correcto— pero se DECLARA, para
/// que nadie confunda «un fichero enorme» con «un fichero normal».
pub const TAMANO_DESMESURADO: usize = 256 * 1024 * 1024;

/// Tipos de fichero reconocidos por sus bytes.
///
/// La lista no pretende ser exhaustiva: cubre lo que de verdad se usa para
/// entregar codigo en una intrusion. Un tipo no reconocido se dice como tal y
/// **no** se disfraza de `Desconocido` silencioso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoFichero {
    /// Ejecutable de Windows (`MZ`, PE).
    EjecutableWindows,
    /// Ejecutable de Linux (ELF).
    EjecutableLinux,
    /// Ejecutable de macOS (Mach-O).
    EjecutableMac,
    /// Contenedor ZIP. Incluye JAR, APK y los formatos de Office modernos.
    Zip,
    /// Contenedor OLE: los formatos de Office clasicos y los MSI.
    Ole,
    /// PDF.
    Pdf,
    /// RAR.
    Rar,
    /// 7-Zip.
    SieteZip,
    /// GZIP.
    Gzip,
    /// XZ.
    Xz,
    /// BZIP2.
    Bzip2,
    /// Cabinet de Windows.
    Cab,
    /// Guion con linea `#!`.
    GuionConInterprete,
    /// Clase compilada de Java.
    ClaseJava,
    /// Imagen de disco ISO.
    Iso,
    /// Acceso directo de Windows (`.lnk`).
    AccesoDirectoWindows,
}

impl TipoFichero {
    /// Codigo estable, para agrupar y para las reglas.
    #[must_use]
    pub fn codigo(self) -> &'static str {
        match self {
            TipoFichero::EjecutableWindows => "pe",
            TipoFichero::EjecutableLinux => "elf",
            TipoFichero::EjecutableMac => "macho",
            TipoFichero::Zip => "zip",
            TipoFichero::Ole => "ole",
            TipoFichero::Pdf => "pdf",
            TipoFichero::Rar => "rar",
            TipoFichero::SieteZip => "7z",
            TipoFichero::Gzip => "gzip",
            TipoFichero::Xz => "xz",
            TipoFichero::Bzip2 => "bzip2",
            TipoFichero::Cab => "cab",
            TipoFichero::GuionConInterprete => "guion",
            TipoFichero::ClaseJava => "class",
            TipoFichero::Iso => "iso",
            TipoFichero::AccesoDirectoWindows => "lnk",
        }
    }

    /// Si el tipo puede ejecutar codigo por si mismo.
    ///
    /// Un ZIP no ejecuta nada; un PE si. La distincion importa porque un
    /// ejecutable llegando por un canal que normalmente no los lleva es una
    /// senal mucho mas fuerte que un contenedor.
    #[must_use]
    pub fn ejecuta_codigo(self) -> bool {
        matches!(
            self,
            TipoFichero::EjecutableWindows
                | TipoFichero::EjecutableLinux
                | TipoFichero::EjecutableMac
                | TipoFichero::GuionConInterprete
                | TipoFichero::ClaseJava
                | TipoFichero::AccesoDirectoWindows
        )
    }
}

/// Identifica el tipo de un fichero por sus primeros bytes.
///
/// Devuelve `None` cuando la magia no corresponde a ninguno de los tipos
/// reconocidos. `None` significa «no lo reconozco», NO «es inofensivo».
#[must_use]
pub fn identificar(datos: &[u8]) -> Option<TipoFichero> {
    // El orden importa donde una magia es prefijo de otra.
    const MACHO: [&[u8]; 4] = [
        &[0xFE, 0xED, 0xFA, 0xCE],
        &[0xFE, 0xED, 0xFA, 0xCF],
        &[0xCE, 0xFA, 0xED, 0xFE],
        &[0xCF, 0xFA, 0xED, 0xFE],
    ];

    if datos.starts_with(b"MZ") {
        return Some(TipoFichero::EjecutableWindows);
    }
    if datos.starts_with(b"\x7FELF") {
        return Some(TipoFichero::EjecutableLinux);
    }
    if MACHO.iter().any(|m| datos.starts_with(m)) {
        return Some(TipoFichero::EjecutableMac);
    }
    // `PK\x03\x04` es el registro local; `PK\x05\x06` es un ZIP vacio y
    // `PK\x07\x08` uno partido. Los tres son ZIP y omitir los dos ultimos deja
    // pasar contenedores validos.
    if datos.starts_with(b"PK\x03\x04")
        || datos.starts_with(b"PK\x05\x06")
        || datos.starts_with(b"PK\x07\x08")
    {
        return Some(TipoFichero::Zip);
    }
    if datos.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Some(TipoFichero::Ole);
    }
    if datos.starts_with(b"%PDF-") {
        return Some(TipoFichero::Pdf);
    }
    if datos.starts_with(b"Rar!\x1A\x07") {
        return Some(TipoFichero::Rar);
    }
    if datos.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(TipoFichero::SieteZip);
    }
    if datos.starts_with(&[0x1F, 0x8B]) {
        return Some(TipoFichero::Gzip);
    }
    if datos.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(TipoFichero::Xz);
    }
    if datos.starts_with(b"BZh") {
        return Some(TipoFichero::Bzip2);
    }
    if datos.starts_with(b"MSCF") {
        return Some(TipoFichero::Cab);
    }
    if datos.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return Some(TipoFichero::ClaseJava);
    }
    // La cabecera de un `.lnk`: tamano fijo 0x4C y el GUID de la clase.
    if datos.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Some(TipoFichero::AccesoDirectoWindows);
    }
    if datos.starts_with(b"#!") {
        return Some(TipoFichero::GuionConInterprete);
    }
    // La magia de ISO 9660 no esta al principio, sino en el sector 16.
    if datos.len() >= ISO_DESPLAZAMIENTO + ISO_MAGIA.len()
        && &datos[ISO_DESPLAZAMIENTO..ISO_DESPLAZAMIENTO + ISO_MAGIA.len()] == ISO_MAGIA
    {
        return Some(TipoFichero::Iso);
    }
    None
}

/// Donde vive la magia de ISO 9660: sector 16, primer byte del descriptor.
const ISO_DESPLAZAMIENTO: usize = 0x8001;

/// La magia de ISO 9660.
const ISO_MAGIA: &[u8; 5] = b"CD001";

/// Traduce un `Content-Type` declarado al tipo que implicaria.
///
/// Se usa SOLO para contrastarlo con la realidad, nunca para decidir el tipo.
#[must_use]
pub fn tipo_declarado(content_type: &str) -> Option<TipoFichero> {
    let limpio = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match limpio.as_str() {
        "application/x-msdownload" | "application/vnd.microsoft.portable-executable" => {
            Some(TipoFichero::EjecutableWindows)
        }
        "application/x-executable" | "application/x-elf" => Some(TipoFichero::EjecutableLinux),
        "application/pdf" => Some(TipoFichero::Pdf),
        "application/zip"
        | "application/java-archive"
        | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            Some(TipoFichero::Zip)
        }
        "application/msword" | "application/vnd.ms-excel" | "application/x-msi" => {
            Some(TipoFichero::Ole)
        }
        "application/gzip" | "application/x-gzip" => Some(TipoFichero::Gzip),
        "application/x-rar-compressed" | "application/vnd.rar" => Some(TipoFichero::Rar),
        "application/x-7z-compressed" => Some(TipoFichero::SieteZip),
        _ => None,
    }
}

/// Extrae un fichero de un flujo, con el hash calculado al vuelo.
///
/// Se alimenta por trozos segun van llegando. No guarda el contenido: ver la
/// doctrina del modulo.
#[derive(Debug, Clone)]
pub struct Extractor {
    via: ProtocoloApp,
    nombre: String,
    declarado: Option<TipoFichero>,
    prefijo: Vec<u8>,
    tamano: usize,
    resumen: Sha256,
    /// Cuantos bytes quedan por ver, si el emisor declaro un tamano.
    esperados: Option<u64>,
    /// Los bytes que ocupan el sitio de la magia ISO, capturados al pasar.
    ///
    /// La magia de ISO 9660 vive 32 KiB dentro del fichero. Guardar 32 KiB de
    /// cada transferencia para poder mirarla seria justo la memoria que el
    /// atacante quiere que se reserve; capturar cinco bytes al vuelo cuando el
    /// flujo cruza ese punto cuesta nada y ve lo mismo. Las ISO son un vehiculo
    /// de entrega real y actual —sirven para saltarse la marca de procedencia de
    /// Windows—, asi que renunciar a verlas no era una opcion.
    marca_iso: [u8; ISO_MAGIA.len()],
    /// Cuantos bytes de `marca_iso` se han rellenado ya.
    marca_iso_vista: usize,
}

impl Extractor {
    /// Un extractor para una transferencia.
    ///
    /// `nombre` y `content_type` son **lo que el emisor dice**, y se guardan
    /// solo para poder contrastarlos.
    #[must_use]
    pub fn nuevo(
        via: ProtocoloApp,
        nombre: &str,
        content_type: &str,
        esperados: Option<u64>,
    ) -> Extractor {
        Extractor {
            via,
            nombre: nombre.to_string(),
            declarado: tipo_declarado(content_type),
            prefijo: Vec::new(),
            tamano: 0,
            resumen: Sha256::new(),
            esperados,
            marca_iso: [0; ISO_MAGIA.len()],
            marca_iso_vista: 0,
        }
    }

    /// Bytes vistos hasta ahora.
    #[must_use]
    pub fn tamano(&self) -> usize {
        self.tamano
    }

    /// Tipo real, si ya se han visto bytes suficientes para saberlo.
    #[must_use]
    pub fn tipo(&self) -> Option<TipoFichero> {
        if let Some(t) = identificar(&self.prefijo) {
            return Some(t);
        }
        if self.marca_iso_vista == ISO_MAGIA.len() && &self.marca_iso == ISO_MAGIA {
            return Some(TipoFichero::Iso);
        }
        None
    }

    /// Captura, al vuelo, los bytes que caen en el sitio de la magia ISO.
    ///
    /// `desde` es el desplazamiento del primer byte de `datos` dentro del
    /// fichero. No guarda nada mas que los cinco bytes que interesan.
    fn mirar_marca_iso(&mut self, desde: usize, datos: &[u8]) {
        let fin_marca = ISO_DESPLAZAMIENTO + ISO_MAGIA.len();
        let hasta = desde.saturating_add(datos.len());
        if hasta <= ISO_DESPLAZAMIENTO || desde >= fin_marca {
            return;
        }
        for i in desde.max(ISO_DESPLAZAMIENTO)..hasta.min(fin_marca) {
            let en_marca = i - ISO_DESPLAZAMIENTO;
            let en_datos = i - desde;
            if let (Some(destino), Some(&b)) =
                (self.marca_iso.get_mut(en_marca), datos.get(en_datos))
            {
                *destino = b;
                // Solo cuenta como vista si se rellena en orden: un trozo
                // perdido en medio no puede dar por buena media magia.
                if en_marca == self.marca_iso_vista {
                    self.marca_iso_vista += 1;
                }
            }
        }
    }

    /// Si ya se ha visto todo lo que el emisor declaro.
    #[must_use]
    pub fn completo(&self) -> bool {
        match self.esperados {
            Some(n) => self.tamano as u64 >= n,
            None => false,
        }
    }

    /// Incorpora un trozo del fichero.
    pub fn incorporar(&mut self, datos: &[u8]) {
        if datos.is_empty() {
            return;
        }
        if self.prefijo.len() < BYTES_PARA_TIPO {
            let falta = BYTES_PARA_TIPO - self.prefijo.len();
            let cuanto = falta.min(datos.len());
            self.prefijo.extend_from_slice(&datos[..cuanto]);
        }
        self.mirar_marca_iso(self.tamano, datos);
        self.tamano = self.tamano.saturating_add(datos.len());
        self.resumen.update(datos);
    }

    /// Cierra la extraccion y produce los hechos.
    ///
    /// Devuelve mas de un hecho cuando ademas del fichero hay algo que contar:
    /// una contradiccion entre el tipo declarado y el real, un tamano que no
    /// cuadra con el declarado, o una transferencia desmesurada.
    #[must_use]
    pub fn cerrar(self) -> Vec<Hecho> {
        if self.tamano == 0 {
            return Vec::new();
        }
        let real = self.tipo();
        let sha256 = format!("{:x}", self.resumen.finalize());
        let mut salida = vec![Hecho::FicheroTransferido {
            nombre: self.nombre.clone(),
            via: self.via,
            tamano: self.tamano,
            sha256,
        }];

        // MENTIR SOBRE EL TIPO ES LA TECNICA, no un descuido. Se emite aparte
        // del fichero para que valga como senal por si misma.
        if let (Some(d), Some(r)) = (self.declarado, real) {
            if d != r {
                salida.push(Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-tipo-contradictorio",
                    detalle: format!(
                        "declarado {} pero el contenido es {}",
                        d.codigo(),
                        r.codigo()
                    ),
                });
            }
        }

        // Un ejecutable cuyo nombre dice otra cosa: misma idea, por la otra via.
        if let Some(r) = real {
            if r.ejecuta_codigo() && nombre_enganoso(&self.nombre, r) {
                salida.push(Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-nombre-enganoso",
                    detalle: format!("«{}» es en realidad {}", self.nombre, r.codigo()),
                });
            }
        }

        // El tamano declarado y el real tienen que cuadrar. Que no cuadren es
        // como se cuelan bytes detras de lo que el receptor cree que ha leido.
        if let Some(n) = self.esperados {
            if self.tamano as u64 != n {
                salida.push(Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-tamano-contradictorio",
                    detalle: format!("declarados {n}, recibidos {}", self.tamano),
                });
            }
        }

        if self.tamano >= TAMANO_DESMESURADO {
            salida.push(Hecho::AnomaliaDeFlujo {
                codigo: "fichero-desmesurado",
                detalle: format!("{} bytes", self.tamano),
            });
        }

        salida
    }
}

/// Si la extension del nombre contradice al contenido real.
///
/// Solo dice que si la extension es de un tipo INOFENSIVO conocido y el
/// contenido ejecuta codigo. Una extension desconocida no acusa a nadie.
#[must_use]
fn nombre_enganoso(nombre: &str, real: TipoFichero) -> bool {
    const INOFENSIVAS: [&str; 14] = [
        "txt", "log", "csv", "jpg", "jpeg", "png", "gif", "bmp", "pdf", "doc", "xls", "rtf", "ico",
        "svg",
    ];
    let Some((_, ext)) = nombre.rsplit_once('.') else {
        return false;
    };
    let ext = ext.trim().to_ascii_lowercase();
    if !INOFENSIVAS.contains(&ext.as_str()) {
        return false;
    }
    // Un `.pdf` que es de verdad un PDF no enganaba a nadie.
    if ext == "pdf" && real == TipoFichero::Pdf {
        return false;
    }
    real.ejecuta_codigo()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn pe() -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.extend_from_slice(&[0u8; 62]);
        v.extend_from_slice(b"PE\0\0");
        v
    }

    #[test]
    fn cada_magia_conocida_se_reconoce() {
        assert_eq!(identificar(&pe()), Some(TipoFichero::EjecutableWindows));
        assert_eq!(
            identificar(b"\x7FELF\x02\x01\x01"),
            Some(TipoFichero::EjecutableLinux)
        );
        assert_eq!(
            identificar(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0]),
            Some(TipoFichero::EjecutableMac)
        );
        assert_eq!(identificar(b"PK\x03\x04aa"), Some(TipoFichero::Zip));
        assert_eq!(identificar(b"PK\x05\x06aa"), Some(TipoFichero::Zip));
        assert_eq!(
            identificar(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0]),
            Some(TipoFichero::Ole)
        );
        assert_eq!(identificar(b"%PDF-1.7"), Some(TipoFichero::Pdf));
        assert_eq!(identificar(b"Rar!\x1A\x07\x00"), Some(TipoFichero::Rar));
        assert_eq!(
            identificar(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            Some(TipoFichero::SieteZip)
        );
        assert_eq!(identificar(&[0x1F, 0x8B, 0x08]), Some(TipoFichero::Gzip));
        assert_eq!(identificar(b"BZh9"), Some(TipoFichero::Bzip2));
        assert_eq!(identificar(b"MSCF\0\0"), Some(TipoFichero::Cab));
        assert_eq!(
            identificar(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0]),
            Some(TipoFichero::ClaseJava)
        );
        assert_eq!(
            identificar(b"#!/bin/sh\n"),
            Some(TipoFichero::GuionConInterprete)
        );
        assert_eq!(
            identificar(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]),
            Some(TipoFichero::AccesoDirectoWindows)
        );
    }

    /// Lo que no se reconoce se dice que no se reconoce. `None` NO significa
    /// «inofensivo», y confundir las dos cosas es como se pierde lo nuevo.
    #[test]
    fn lo_desconocido_no_se_inventa() {
        assert_eq!(identificar(b"hola que tal"), None);
        assert_eq!(identificar(b""), None);
        assert_eq!(identificar(b"M"), None, "un prefijo a medias no es un PE");
    }

    /// La ISO tiene su magia en el sector 16, no al principio: buscarla solo al
    /// principio es como se pierde un contenedor entero.
    #[test]
    fn la_iso_se_reconoce_donde_de_verdad_esta_su_magia() {
        let mut v = vec![0u8; 0x8006];
        v[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(identificar(&v), Some(TipoFichero::Iso));
        // Y no se confunde con tener «CD001» en cualquier otro sitio.
        let mut otro = vec![0u8; 0x8006];
        otro[100..105].copy_from_slice(b"CD001");
        assert_eq!(identificar(&otro), None);
    }

    #[test]
    fn el_hash_es_el_de_verdad_y_el_tamano_tambien() {
        let mut e = Extractor::nuevo(
            ProtocoloApp::Http,
            "x.bin",
            "application/octet-stream",
            None,
        );
        e.incorporar(b"abc");
        assert_eq!(e.tamano(), 3);
        let hechos = e.cerrar();
        let Hecho::FicheroTransferido { sha256, tamano, .. } = &hechos[0] else {
            panic!("{hechos:?}");
        };
        // Vector conocido de SHA-256 para "abc".
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(*tamano, 3);
    }

    /// El hash de un fichero entregado a trozos tiene que ser el mismo que el
    /// del fichero entero: si no, fragmentar la transferencia evadiria la
    /// comparacion contra indicadores.
    #[test]
    fn trocear_la_transferencia_no_cambia_el_hash() {
        let datos: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();

        let mut entero = Extractor::nuevo(ProtocoloApp::Http, "a", "", None);
        entero.incorporar(&datos);
        let mut troceado = Extractor::nuevo(ProtocoloApp::Http, "a", "", None);
        for trozo in datos.chunks(7) {
            troceado.incorporar(trozo);
        }

        let (a, b) = (entero.cerrar(), troceado.cerrar());
        assert_eq!(a, b);
    }

    /// LA SENAL: un ejecutable entregado como `text/plain`.
    #[test]
    fn un_ejecutable_disfrazado_de_texto_se_delata() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "factura", "application/pdf", None);
        e.incorporar(&pe());
        let hechos = e.cerrar();
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-tipo-contradictorio",
                    ..
                }
            )),
            "{hechos:?}"
        );
    }

    /// Y por la otra via: el nombre dice `.txt` y el contenido es un PE.
    #[test]
    fn un_ejecutable_con_nombre_inofensivo_se_delata() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "notas.txt", "", None);
        e.incorporar(&pe());
        let hechos = e.cerrar();
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-nombre-enganoso",
                    ..
                }
            )),
            "{hechos:?}"
        );
    }

    /// Un PDF que se llama `.pdf` y es un PDF NO puede levantar la senal: si lo
    /// hiciera, el indicio quedaria enterrado en ruido.
    #[test]
    fn un_fichero_honesto_no_levanta_ninguna_senal() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "informe.pdf", "application/pdf", None);
        e.incorporar(b"%PDF-1.7 contenido");
        let hechos = e.cerrar();
        assert_eq!(hechos.len(), 1, "{hechos:?}");
        assert!(matches!(hechos[0], Hecho::FicheroTransferido { .. }));
    }

    /// El tamano declarado que no cuadra con el recibido se delata: es la forma
    /// de colar bytes detras de lo que el receptor cree haber leido.
    #[test]
    fn un_tamano_que_no_cuadra_se_delata() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "a.bin", "", Some(10));
        e.incorporar(b"solo siete");
        e.incorporar(b" y mas");
        let hechos = e.cerrar();
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-tamano-contradictorio",
                    ..
                }
            )),
            "{hechos:?}"
        );
    }

    /// LA COTA: hashear un fichero gigante no puede hacer crecer la memoria del
    /// extractor. El tamano lo elige el atacante.
    #[test]
    fn un_fichero_gigante_no_hace_crecer_el_extractor() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "g.bin", "", None);
        let trozo = vec![0xABu8; 64 * 1024];
        for _ in 0..256 {
            e.incorporar(&trozo);
        }
        assert_eq!(e.tamano(), 16 * 1024 * 1024);
        assert!(
            e.prefijo.len() <= BYTES_PARA_TIPO,
            "prefijo = {}",
            e.prefijo.len()
        );
    }

    /// Una transferencia vacia no produce un fichero fantasma.
    #[test]
    fn una_transferencia_vacia_no_produce_hecho() {
        let e = Extractor::nuevo(ProtocoloApp::Http, "a", "", None);
        assert!(e.cerrar().is_empty());
    }

    /// El tipo se reconoce aunque la magia llegue partida entre dos trozos.
    #[test]
    fn la_magia_partida_entre_trozos_se_reconoce_igual() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "a", "", None);
        e.incorporar(b"%P");
        e.incorporar(b"DF-1.4 resto");
        assert_eq!(e.tipo(), Some(TipoFichero::Pdf));
    }

    /// Una ISO se reconoce EN FLUJO, con su magia 32 KiB dentro, sin que el
    /// extractor guarde esos 32 KiB. Es el vehiculo de entrega que se usa para
    /// saltarse la marca de procedencia de Windows.
    #[test]
    fn una_iso_se_reconoce_en_flujo_sin_guardarla() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "parche.iso", "", None);
        let mut escritos = 0usize;
        // Se entrega a trozos de 1000, que NO estan alineados con la magia: la
        // magia cae partida entre dos trozos, que es el caso que se rompe solo.
        while escritos < ISO_DESPLAZAMIENTO + ISO_MAGIA.len() + 100 {
            let mut trozo = vec![0u8; 1000];
            for (i, b) in trozo.iter_mut().enumerate() {
                let pos = escritos + i;
                if (ISO_DESPLAZAMIENTO..ISO_DESPLAZAMIENTO + ISO_MAGIA.len()).contains(&pos) {
                    *b = ISO_MAGIA[pos - ISO_DESPLAZAMIENTO];
                }
            }
            e.incorporar(&trozo);
            escritos += 1000;
        }
        assert_eq!(e.tipo(), Some(TipoFichero::Iso));
        assert!(
            e.prefijo.len() <= BYTES_PARA_TIPO,
            "y sin guardar el fichero: {}",
            e.prefijo.len()
        );
    }

    /// Los mismos bytes en otro sitio NO son una ISO: si lo fueran, cualquier
    /// descarga con «CD001» dentro se marcaria sola.
    #[test]
    fn la_magia_iso_fuera_de_su_sitio_no_cuenta() {
        let mut e = Extractor::nuevo(ProtocoloApp::Http, "a", "", None);
        let mut datos = vec![0u8; ISO_DESPLAZAMIENTO + 100];
        datos[500..505].copy_from_slice(ISO_MAGIA);
        e.incorporar(&datos);
        assert_eq!(e.tipo(), None);
    }

    /// El `Content-Type` se lee sin sus parametros y sin importar mayusculas.
    #[test]
    fn el_tipo_declarado_se_normaliza() {
        assert_eq!(
            tipo_declarado("Application/PDF; charset=utf-8"),
            Some(TipoFichero::Pdf)
        );
        assert_eq!(tipo_declarado("text/plain"), None);
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        for n in 0..512usize {
            let datos: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(37) % 256) as u8).collect();
            let _ = identificar(&datos);
            let mut e = Extractor::nuevo(ProtocoloApp::Http, "a.b", "x/y", Some(n as u64));
            e.incorporar(&datos);
            let _ = e.cerrar();
        }
    }
}
