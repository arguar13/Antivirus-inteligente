//! Rutas de dispositivo EFI: el «desde donde» de cada cosa que arranca.
//!
//! # Por que hace falta decodificarlas
//!
//! Una entrada `Boot0003` no dice «arranca Ubuntu»: dice una secuencia binaria de
//! nodos —este bus PCI, este disco NVMe, esta particion GPT, este fichero—. Y el
//! event log mide cada aplicacion EFI con la misma secuencia. Sin decodificarla,
//! la pregunta «¿que cargador se ejecuto?» no tiene respuesta legible, y la
//! pregunta «¿se ejecuto desde un USB, desde la red o desde un fichero fuera de
//! `\EFI\`?» —que es donde se nota un cargador puesto por un atacante— no se
//! puede ni formular.
//!
//! # Robustez
//!
//! Los bytes vienen de una variable o del event log, es decir, de lo que se esta
//! auditando. Cada nodo declara su longitud; una longitud menor que la cabecera
//! (4 bytes) haria no avanzar al recorrido, y una mayor que lo que queda lo haria
//! leer fuera. Las dos cosas paran el recorrido y se marcan como truncado.

use aegis_firmware::guid::Guid;

/// Tope de nodos por ruta: una ruta real tiene menos de diez.
pub const MAX_NODOS: usize = 64;

/// Un nodo decodificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nodo {
    /// PCI: dispositivo y funcion.
    Pci {
        /// Funcion.
        funcion: u8,
        /// Dispositivo.
        dispositivo: u8,
    },
    /// Raiz ACPI (`PciRoot`), con su HID y UID.
    Acpi {
        /// HID comprimido.
        hid: u32,
        /// UID.
        uid: u32,
    },
    /// Disco SATA.
    Sata {
        /// Puerto.
        puerto: u16,
    },
    /// Espacio de nombres NVMe.
    Nvme {
        /// Identificador del espacio de nombres.
        espacio: u32,
    },
    /// USB.
    Usb {
        /// Puerto del padre.
        puerto: u8,
    },
    /// Direccion MAC: arranque por red.
    Mac,
    /// IPv4: arranque por red.
    Ipv4,
    /// IPv6: arranque por red.
    Ipv6,
    /// URI: arranque HTTP.
    Uri(String),
    /// Particion de disco duro.
    Particion {
        /// Numero de particion.
        numero: u32,
        /// Firma GPT de la particion, si es GPT.
        guid: Option<Guid>,
    },
    /// CD-ROM (El Torito).
    Cdrom,
    /// Ruta de fichero.
    Fichero(String),
    /// Volumen de firmware (PIWG): codigo que vive DENTRO de la ROM.
    VolumenFirmware(Guid),
    /// Fichero de un volumen de firmware (PIWG).
    FicheroFirmware(Guid),
    /// Cualquier otro nodo, con su tipo y subtipo.
    Otro {
        /// Tipo.
        tipo: u8,
        /// Subtipo.
        subtipo: u8,
    },
}

/// Una ruta decodificada.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ruta {
    /// Los nodos, hasta el final de la primera instancia.
    pub nodos: Vec<Nodo>,
    /// Si se paro antes del nodo final por datos incoherentes.
    pub truncada: bool,
}

impl Ruta {
    /// El fichero de la ruta, si la hay (`\EFI\ubuntu\shimx64.efi`).
    #[must_use]
    pub fn fichero(&self) -> Option<String> {
        let partes: Vec<&str> = self
            .nodos
            .iter()
            .filter_map(|n| match n {
                Nodo::Fichero(f) => Some(f.as_str()),
                _ => None,
            })
            .collect();
        if partes.is_empty() {
            None
        } else {
            Some(partes.join(""))
        }
    }

    /// De donde sale: disco, extraible, red o la propia ROM.
    #[must_use]
    pub fn origen(&self) -> Origen {
        if self
            .nodos
            .iter()
            .any(|n| matches!(n, Nodo::Mac | Nodo::Ipv4 | Nodo::Ipv6 | Nodo::Uri(_)))
        {
            Origen::Red
        } else if self
            .nodos
            .iter()
            .any(|n| matches!(n, Nodo::Usb { .. } | Nodo::Cdrom))
        {
            Origen::Extraible
        } else if self
            .nodos
            .iter()
            .any(|n| matches!(n, Nodo::VolumenFirmware(_) | Nodo::FicheroFirmware(_)))
        {
            Origen::Firmware
        } else if self
            .nodos
            .iter()
            .any(|n| matches!(n, Nodo::Particion { .. }))
        {
            Origen::Disco
        } else {
            Origen::Desconocido
        }
    }

    /// Si pasa por un dispositivo PCI (lo que tiene una option ROM).
    #[must_use]
    pub fn pasa_por_pci(&self) -> bool {
        self.nodos.iter().any(|n| matches!(n, Nodo::Pci { .. }))
    }

    /// Texto al estilo de la especificacion UEFI.
    #[must_use]
    pub fn texto(&self) -> String {
        let mut s: Vec<String> = self
            .nodos
            .iter()
            .map(|n| match n {
                Nodo::Pci {
                    funcion,
                    dispositivo,
                } => format!("Pci({dispositivo:#x},{funcion:#x})"),
                Nodo::Acpi { hid, uid } => {
                    if *hid == 0x0A03_41D0 || *hid == 0x0A08_41D0 {
                        format!("PciRoot({uid:#x})")
                    } else {
                        format!("Acpi({hid:#x},{uid:#x})")
                    }
                }
                Nodo::Sata { puerto } => format!("Sata({puerto:#x})"),
                Nodo::Nvme { espacio } => format!("NVMe({espacio:#x})"),
                Nodo::Usb { puerto } => format!("USB({puerto:#x})"),
                Nodo::Mac => "MAC()".into(),
                Nodo::Ipv4 => "IPv4()".into(),
                Nodo::Ipv6 => "IPv6()".into(),
                Nodo::Uri(u) => format!("Uri({u})"),
                Nodo::Particion { numero, guid } => match guid {
                    Some(g) => format!("HD({numero},GPT,{g})"),
                    None => format!("HD({numero},MBR)"),
                },
                Nodo::Cdrom => "CDROM()".into(),
                Nodo::Fichero(f) => f.clone(),
                Nodo::VolumenFirmware(g) => format!("Fv({g})"),
                Nodo::FicheroFirmware(g) => format!("FvFile({g})"),
                Nodo::Otro { tipo, subtipo } => format!("Path({tipo},{subtipo})"),
            })
            .collect();
        if self.truncada {
            s.push("<truncada>".into());
        }
        s.join("/")
    }
}

/// De donde se carga algo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origen {
    /// Una particion de un disco interno.
    Disco,
    /// Un USB o un CD.
    Extraible,
    /// La red (PXE o HTTP).
    Red,
    /// Un volumen de la propia ROM.
    Firmware,
    /// No se sabe.
    Desconocido,
}

/// UTF-16LE terminado en cero a texto.
#[must_use]
pub fn utf16(bytes: &[u8]) -> String {
    let u: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|x| *x != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

/// Decodifica una ruta de dispositivo hasta el final de su primera instancia.
#[must_use]
pub fn decodificar(bytes: &[u8]) -> Ruta {
    let mut r = Ruta::default();
    let mut pos = 0usize;
    while r.nodos.len() < MAX_NODOS {
        let Some(cab) = bytes.get(pos..pos + 4) else {
            r.truncada = true;
            break;
        };
        let (tipo, subtipo) = (cab[0], cab[1]);
        let largo = u16::from_le_bytes([cab[2], cab[3]]) as usize;
        if tipo == 0x7F {
            // Fin de instancia (0x01) o de ruta (0xFF): los dos cierran lo que se
            // decodifica, que es la primera instancia.
            break;
        }
        if largo < 4 {
            r.truncada = true;
            break;
        }
        let Some(nodo) = bytes.get(pos..pos + largo) else {
            r.truncada = true;
            break;
        };
        let d = &nodo[4..];
        let u16a = |o: usize| d.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
        let u32a = |o: usize| {
            d.get(o..o + 4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        let n = match (tipo, subtipo) {
            (0x01, 0x01) if d.len() >= 2 => Nodo::Pci {
                funcion: d[0],
                dispositivo: d[1],
            },
            (0x02, 0x01) => Nodo::Acpi {
                hid: u32a(0).unwrap_or(0),
                uid: u32a(4).unwrap_or(0),
            },
            (0x03, 0x12) => Nodo::Sata {
                puerto: u16a(0).unwrap_or(0),
            },
            (0x03, 0x17) => Nodo::Nvme {
                espacio: u32a(0).unwrap_or(0),
            },
            (0x03, 0x05) if !d.is_empty() => Nodo::Usb { puerto: d[0] },
            (0x03, 0x0B) => Nodo::Mac,
            (0x03, 0x0C) => Nodo::Ipv4,
            (0x03, 0x0D) => Nodo::Ipv6,
            (0x03, 0x18) => Nodo::Uri(String::from_utf8_lossy(d).to_string()),
            (0x04, 0x01) => {
                // HD: numero(4) inicio(8) tamano(8) firma(16) formato(1) tipo_firma(1).
                let numero = u32a(0).unwrap_or(0);
                let guid = (d.len() >= 38 && d[37] == 0x02).then(|| Guid::from_bytes(&d[20..36]));
                Nodo::Particion { numero, guid }
            }
            (0x04, 0x02) => Nodo::Cdrom,
            (0x04, 0x04) => Nodo::Fichero(utf16(d)),
            (0x04, 0x06) if d.len() >= 16 => Nodo::FicheroFirmware(Guid::from_bytes(&d[..16])),
            (0x04, 0x07) if d.len() >= 16 => Nodo::VolumenFirmware(Guid::from_bytes(&d[..16])),
            _ => Nodo::Otro { tipo, subtipo },
        };
        r.nodos.push(n);
        pos += largo;
    }
    r
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    pub(crate) fn nodo(tipo: u8, subtipo: u8, datos: &[u8]) -> Vec<u8> {
        let mut v = vec![tipo, subtipo];
        v.extend_from_slice(&((datos.len() + 4) as u16).to_le_bytes());
        v.extend_from_slice(datos);
        v
    }

    pub(crate) fn fichero(f: &str) -> Vec<u8> {
        let d: Vec<u8> = f
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        nodo(0x04, 0x04, &d)
    }

    pub(crate) fn fin() -> Vec<u8> {
        vec![0x7F, 0xFF, 4, 0]
    }

    /// La ruta de un Ubuntu tipico en NVMe, construida segun la especificacion.
    pub(crate) fn ruta_disco(f: &str) -> Vec<u8> {
        let mut v = nodo(0x02, 0x01, &[0xD0, 0x41, 0x03, 0x0A, 0, 0, 0, 0]);
        v.extend(nodo(0x01, 0x01, &[0x00, 0x1D]));
        v.extend(nodo(0x03, 0x17, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        let mut hd = vec![0u8; 38];
        hd[0] = 1;
        hd[20..36].copy_from_slice(&[0xAB; 16]);
        hd[36] = 0x02;
        hd[37] = 0x02;
        v.extend(nodo(0x04, 0x01, &hd));
        v.extend(fichero(f));
        v.extend(fin());
        v
    }

    #[test]
    fn una_ruta_de_disco_se_decodifica_entera() {
        let r = decodificar(&ruta_disco("\\EFI\\ubuntu\\shimx64.efi"));
        assert!(!r.truncada);
        assert_eq!(r.fichero().as_deref(), Some("\\EFI\\ubuntu\\shimx64.efi"));
        assert_eq!(r.origen(), Origen::Disco);
        assert!(r.pasa_por_pci());
        let t = r.texto();
        assert!(
            t.starts_with("PciRoot(0x0)/Pci(0x1d,0x0)/NVMe(0x1)/HD(1,GPT,"),
            "{t}"
        );
    }

    #[test]
    fn la_red_y_el_usb_se_distinguen_del_disco() {
        let mut red = nodo(0x03, 0x0B, &[0; 33]);
        red.extend(nodo(0x03, 0x18, b"http://arranque.example/x.efi"));
        red.extend(fin());
        assert_eq!(decodificar(&red).origen(), Origen::Red);
        let mut usb = nodo(0x03, 0x05, &[2, 0]);
        usb.extend(fichero("\\EFI\\BOOT\\BOOTX64.EFI"));
        usb.extend(fin());
        assert_eq!(decodificar(&usb).origen(), Origen::Extraible);
        let mut fv = nodo(0x04, 0x07, &[0x11; 16]);
        fv.extend(nodo(0x04, 0x06, &[0x22; 16]));
        fv.extend(fin());
        assert_eq!(decodificar(&fv).origen(), Origen::Firmware);
    }

    /// Entrada hostil: una longitud 0 no puede colgar el recorrido, y una mayor
    /// que lo que queda no puede leer fuera.
    #[test]
    fn las_longitudes_mentirosas_paran_el_recorrido() {
        let cero = [0x04u8, 0x04, 0, 0, 1, 2, 3, 4];
        assert!(decodificar(&cero).truncada);
        let larga = [0x04u8, 0x04, 0xFF, 0xFF, b'a', 0];
        assert!(decodificar(&larga).truncada);
        assert!(decodificar(&[]).truncada);
        // Sin nodo final: se lee lo que haya y se dice.
        let sin_fin = fichero("\\x");
        let r = decodificar(&sin_fin);
        assert!(r.truncada && r.fichero().is_some());
        // Barrido acotado de basura.
        for s in 0..64u8 {
            let b: Vec<u8> = (0..128u32)
                .map(|i| ((i * 31 + u32::from(s) * 7) % 256) as u8)
                .collect();
            let r = decodificar(&b);
            assert!(r.nodos.len() <= MAX_NODOS);
        }
    }
}
