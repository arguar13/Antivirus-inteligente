//! El formato PCAP clasico, para escribirlo y para leerlo.
//!
//! # Por que el formato de todo el mundo y no uno propio
//!
//! Porque la captura es una prueba, y una prueba que solo puede leer la
//! herramienta que la produjo no vale delante de nadie. El analista del cliente
//! abre el fichero en Wireshark; el perito lo abre dentro de tres anos, cuando
//! este producto puede no existir. Un formato propio seria mas compacto y haria
//! la captura inutil para las dos cosas.
//!
//! Se elige el PCAP clasico y no el pcapng: el clasico son veinticuatro bytes de
//! cabecera y dieciseis por paquete, lo lee todo desde hace treinta anos, y no
//! tiene bloques de longitud variable —que es justo por donde entran los fallos
//! de analizador que este producto existe para no tener—.
//!
//! # Leer un PCAP es entrada hostil
//!
//! El lector de aqui no se usa solo con ficheros propios: se usa para reproducir
//! capturas que trae el cliente, que pudo generarlas cualquiera. Por eso cada
//! longitud se comprueba contra lo que queda, hay un tope por paquete, y el
//! numero de paquetes no lo decide el fichero.

/// El numero magico del PCAP clasico, en el orden del anfitrion.
pub const MAGIA: u32 = 0xa1b2_c3d4;

/// El mismo numero visto del reves: el fichero lo escribio una maquina del otro
/// orden de bytes. Reconocerlo es lo que separa leer un fichero ajeno de
/// rechazarlo por no ser nuestro.
pub const MAGIA_INVERTIDA: u32 = 0xd4c3_b2a1;

/// La variante con marcas de tiempo en nanosegundos.
pub const MAGIA_NANO: u32 = 0xa1b2_3c4d;

/// Y su inversa.
pub const MAGIA_NANO_INVERTIDA: u32 = 0x4d3c_b2a1;

/// Longitud de la cabecera global.
pub const CABECERA_GLOBAL: usize = 24;

/// Longitud de la cabecera de cada paquete.
pub const CABECERA_PAQUETE: usize = 16;

/// Tipo de enlace: Ethernet.
pub const ENLACE_ETHERNET: u32 = 1;

/// Tipo de enlace: IP cruda, que es lo que se ve capturando desde el propio
/// equipo sin la trama de nivel dos.
pub const ENLACE_IP_CRUDA: u32 = 101;

/// Cuanto puede medir un paquete como maximo.
///
/// Un jumbo de nueve mil bytes es lo mas grande que se ve en una red real; el
/// margen cubre el encapsulado. Que este numero exista es lo que impide que un
/// fichero preparado haga reservar lo que diga su campo de longitud.
pub const MAX_PAQUETE: usize = 262_144;

/// Lo que puede salir mal leyendo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No empieza por ningun numero magico conocido.
    NoEsPcap,
    /// Se acabo el fichero en medio de algo.
    Truncado {
        /// Que se estaba leyendo.
        campo: &'static str,
    },
    /// Un paquete declara una longitud que no cabe o que es imposible.
    LongitudImposible {
        /// Lo que declara.
        declarada: usize,
        /// Lo que hay.
        disponible: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoEsPcap => write!(f, "no empieza por ningun numero magico de PCAP"),
            Error::Truncado { campo } => write!(f, "el fichero se acaba en medio de {campo}"),
            Error::LongitudImposible {
                declarada,
                disponible,
            } => write!(
                f,
                "un paquete declara {declarada} bytes y quedan {disponible}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Escribe un PCAP.
#[derive(Debug, Clone)]
pub struct Escritor {
    bytes: Vec<u8>,
    enlace: u32,
    paquetes: u64,
}

impl Escritor {
    /// Un escritor nuevo, con su cabecera global ya puesta.
    ///
    /// `instantanea` es cuanto se guarda como maximo de cada paquete. Va en la
    /// cabecera **y se respeta**: un fichero que declare una instantanea y luego
    /// lleve paquetes mas largos es un fichero que otras herramientas leen mal.
    #[must_use]
    pub fn nuevo(enlace: u32, instantanea: u32) -> Escritor {
        let mut bytes = Vec::with_capacity(CABECERA_GLOBAL);
        bytes.extend_from_slice(&MAGIA_NANO.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes()); // version mayor
        bytes.extend_from_slice(&4u16.to_le_bytes()); // version menor
        bytes.extend_from_slice(&0i32.to_le_bytes()); // huso: siempre UTC
        bytes.extend_from_slice(&0u32.to_le_bytes()); // precision declarada
        bytes.extend_from_slice(&instantanea.to_le_bytes());
        bytes.extend_from_slice(&enlace.to_le_bytes());
        Escritor {
            bytes,
            enlace,
            paquetes: 0,
        }
    }

    /// Anade un paquete.
    ///
    /// `original` es lo que medía en el cable, que puede ser mas que lo que se
    /// guarda. Conservar los dos numeros es lo que permite que un analista vea
    /// que un paquete venia recortado en vez de creerse que era corto.
    pub fn anadir(&mut self, cuando_ns: u64, datos: &[u8], original: usize) {
        let segundos = (cuando_ns / 1_000_000_000) as u32;
        let nanos = (cuando_ns % 1_000_000_000) as u32;
        self.bytes.extend_from_slice(&segundos.to_le_bytes());
        self.bytes.extend_from_slice(&nanos.to_le_bytes());
        self.bytes
            .extend_from_slice(&(datos.len() as u32).to_le_bytes());
        self.bytes
            .extend_from_slice(&(original.max(datos.len()) as u32).to_le_bytes());
        self.bytes.extend_from_slice(datos);
        self.paquetes += 1;
    }

    /// Cuantos paquetes lleva.
    #[must_use]
    pub fn paquetes(&self) -> u64 {
        self.paquetes
    }

    /// Cuantos bytes ocupa el fichero.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes.len()
    }

    /// El tipo de enlace declarado.
    #[must_use]
    pub fn enlace(&self) -> u32 {
        self.enlace
    }

    /// El fichero terminado.
    #[must_use]
    pub fn terminar(self) -> Vec<u8> {
        self.bytes
    }
}

/// Un paquete leido de un PCAP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leido {
    /// Cuando llego, en nanosegundos desde la epoca.
    pub cuando_ns: u64,
    /// Lo que se guardo.
    pub datos: Vec<u8>,
    /// Lo que medía en el cable.
    pub original: usize,
}

impl Leido {
    /// Si el paquete venia recortado.
    ///
    /// Un analista que no sepa esto lee un paquete corto y concluye que la
    /// peticion era corta.
    #[must_use]
    pub fn recortado(&self) -> bool {
        self.original > self.datos.len()
    }
}

/// Lo que sale de leer un PCAP entero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lectura {
    /// Tipo de enlace declarado.
    pub enlace: u32,
    /// Los paquetes.
    pub paquetes: Vec<Leido>,
    /// Si el fichero se acabo en medio de un paquete.
    ///
    /// **No es un error**: una captura en marcha que se copia mientras se escribe
    /// acaba asi, y lo que hay antes del corte es valido. Lo que no vale es
    /// callarlo.
    pub cortado: bool,
}

/// Lee un PCAP.
///
/// `tope` acota cuantos paquetes se leen. El numero de paquetes lo decide el
/// fichero, y el fichero puede haberlo escrito cualquiera.
///
/// # Errores
///
/// [`Error::NoEsPcap`] si no empieza por un numero magico conocido, y
/// [`Error::LongitudImposible`] si un paquete declara mas de [`MAX_PAQUETE`].
pub fn leer(bytes: &[u8], tope: usize) -> Result<Lectura, Error> {
    if bytes.len() < CABECERA_GLOBAL {
        return Err(Error::Truncado {
            campo: "la cabecera global",
        });
    }
    let magia = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (invertido, nanos) = match magia {
        MAGIA => (false, false),
        MAGIA_NANO => (false, true),
        MAGIA_INVERTIDA => (true, false),
        MAGIA_NANO_INVERTIDA => (true, true),
        _ => return Err(Error::NoEsPcap),
    };
    let u32_en = |b: &[u8]| -> u32 {
        let v = [b[0], b[1], b[2], b[3]];
        if invertido {
            u32::from_be_bytes(v)
        } else {
            u32::from_le_bytes(v)
        }
    };
    let enlace = u32_en(&bytes[20..24]);

    let mut paquetes = Vec::new();
    let mut pos = CABECERA_GLOBAL;
    let mut cortado = false;
    while paquetes.len() < tope {
        if pos == bytes.len() {
            break;
        }
        if pos + CABECERA_PAQUETE > bytes.len() {
            cortado = true;
            break;
        }
        let segundos = u64::from(u32_en(&bytes[pos..pos + 4]));
        let fraccion = u64::from(u32_en(&bytes[pos + 4..pos + 8]));
        let guardado = u32_en(&bytes[pos + 8..pos + 12]) as usize;
        let original = u32_en(&bytes[pos + 12..pos + 16]) as usize;
        pos += CABECERA_PAQUETE;

        // El tope es del PRODUCTO, no del fichero: sin el, un campo de longitud
        // preparado haria reservar lo que diga.
        if guardado > MAX_PAQUETE {
            return Err(Error::LongitudImposible {
                declarada: guardado,
                disponible: bytes.len() - pos,
            });
        }
        if pos + guardado > bytes.len() {
            cortado = true;
            break;
        }
        paquetes.push(Leido {
            cuando_ns: segundos * 1_000_000_000 + if nanos { fraccion } else { fraccion * 1000 },
            datos: bytes[pos..pos + guardado].to_vec(),
            original: original.max(guardado),
        });
        pos += guardado;
    }
    Ok(Lectura {
        enlace,
        paquetes,
        cortado,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn lo_que_se_escribe_es_lo_que_se_lee() {
        let mut e = Escritor::nuevo(ENLACE_ETHERNET, 65535);
        e.anadir(1_700_000_000_123_456_789, b"primero", 7);
        e.anadir(1_700_000_001_000_000_000, b"segundo mas largo", 100);
        let bytes = e.terminar();

        let l = leer(&bytes, 1000).expect("se lee");
        assert_eq!(l.enlace, ENLACE_ETHERNET);
        assert!(!l.cortado);
        assert_eq!(l.paquetes.len(), 2);
        assert_eq!(l.paquetes[0].datos, b"primero");
        assert_eq!(l.paquetes[0].cuando_ns, 1_700_000_000_123_456_789);
        assert!(!l.paquetes[0].recortado());
        // El segundo venia recortado, y eso se conserva: un analista que no lo
        // sepa lee un paquete corto y concluye que la peticion era corta.
        assert!(l.paquetes[1].recortado());
        assert_eq!(l.paquetes[1].original, 100);
    }

    #[test]
    fn la_cabecera_global_es_la_que_espera_todo_el_mundo() {
        let e = Escritor::nuevo(ENLACE_IP_CRUDA, 4096);
        let b = e.terminar();
        assert_eq!(b.len(), CABECERA_GLOBAL);
        assert_eq!(u32::from_le_bytes([b[0], b[1], b[2], b[3]]), MAGIA_NANO);
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 2);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 4);
        assert_eq!(u32::from_le_bytes([b[16], b[17], b[18], b[19]]), 4096);
        assert_eq!(
            u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            ENLACE_IP_CRUDA
        );
    }

    /// Un fichero escrito por una maquina del otro orden de bytes es un fichero
    /// valido. Rechazarlo por no ser nuestro haria inutil el lector justo cuando
    /// el cliente trae una captura de otro sitio.
    #[test]
    fn se_lee_un_pcap_del_otro_orden_de_bytes() {
        let mut b = MAGIA_INVERTIDA.to_le_bytes().to_vec();
        b.extend_from_slice(&2u16.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&65535u32.to_be_bytes());
        b.extend_from_slice(&ENLACE_ETHERNET.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes()); // segundos
        b.extend_from_slice(&500_000u32.to_be_bytes()); // microsegundos
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(b"hola");

        let l = leer(&b, 10).expect("se lee del reves");
        assert_eq!(l.enlace, ENLACE_ETHERNET);
        assert_eq!(l.paquetes[0].datos, b"hola");
        assert_eq!(l.paquetes[0].cuando_ns, 7_500_000_000);
    }

    #[test]
    fn un_fichero_cortado_entrega_lo_que_hay_y_lo_dice() {
        // Una captura en marcha que se copia mientras se escribe acaba asi. Lo
        // que hay antes del corte es valido; lo que no vale es callarlo.
        let mut e = Escritor::nuevo(ENLACE_ETHERNET, 65535);
        e.anadir(1, b"entero", 6);
        e.anadir(2, b"este se corta", 13);
        let mut bytes = e.terminar();
        bytes.truncate(bytes.len() - 5);

        let l = leer(&bytes, 10).expect("se lee lo que hay");
        assert_eq!(l.paquetes.len(), 1);
        assert!(l.cortado, "el corte tiene que decirse");
    }

    #[test]
    fn una_longitud_preparada_no_hace_reservar_lo_que_diga() {
        // El tope es del producto y no del fichero: sin el, un campo de longitud
        // preparado haria reservar cuatro gigabytes por paquete.
        let mut b = MAGIA.to_le_bytes().to_vec();
        b.resize(CABECERA_GLOBAL, 0);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        match leer(&b, 10) {
            Err(Error::LongitudImposible { declarada, .. }) => {
                assert_eq!(declarada, 0xFFFF_FFFF);
            }
            otro => panic!("tenia que rechazarlo: {otro:?}"),
        }
    }

    #[test]
    fn el_numero_de_paquetes_no_lo_decide_el_fichero() {
        let mut e = Escritor::nuevo(ENLACE_ETHERNET, 65535);
        for i in 0..1000u64 {
            e.anadir(i, b"x", 1);
        }
        let l = leer(&e.terminar(), 10).expect("se lee");
        assert_eq!(l.paquetes.len(), 10, "el tope lo pone quien lee");
    }

    #[test]
    fn lo_que_no_es_un_pcap_se_rechaza_y_no_se_interpreta() {
        assert_eq!(
            leer(b"", 10),
            Err(Error::Truncado {
                campo: "la cabecera global"
            })
        );
        let basura = vec![0x41u8; 100];
        assert_eq!(leer(&basura, 10), Err(Error::NoEsPcap));
    }

    #[test]
    fn un_pcap_sin_paquetes_es_valido_y_esta_vacio() {
        let e = Escritor::nuevo(ENLACE_ETHERNET, 65535);
        let l = leer(&e.terminar(), 10).expect("una captura vacia es valida");
        assert!(l.paquetes.is_empty());
        assert!(!l.cortado);
    }

    #[test]
    fn el_lector_aguanta_entrada_hostil_sin_romperse() {
        // El lector se usa con capturas que trae el cliente, que pudo generarlas
        // cualquiera. Ninguna entrada puede provocar un panico.
        let mut semilla = 0x5EEDu64 | 1;
        for largo in [0usize, 1, 23, 24, 25, 39, 40, 41, 100, 1000] {
            for intento in 0..64 {
                let mut b = Vec::with_capacity(largo);
                for _ in 0..largo {
                    semilla ^= semilla >> 12;
                    semilla ^= semilla << 25;
                    semilla ^= semilla >> 27;
                    b.push((semilla.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8);
                }
                if intento % 2 == 0 && b.len() >= 4 {
                    b[..4].copy_from_slice(&MAGIA.to_le_bytes());
                }
                let _ = leer(&b, 32);
            }
        }
    }
}
