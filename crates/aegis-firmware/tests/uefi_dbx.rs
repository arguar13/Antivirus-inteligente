//! Pruebas del analizador de Secure Boot y de la DBX, contra vectores reales.
//!
//! Cada trampa que el reconocimiento de hardware marco como el error numero uno
//! tiene aqui su prueba: el prefijo de 4 bytes de efivarfs, las multiples
//! EFI_SIGNATURE_LIST concatenadas, el SignatureSize que INCLUYE el GUID de
//! propietario, y el estado SecureBoot=1 + SetupMode=1 que no impone nada.

mod common;
use common::{efivar, signature_list_sha256, signature_list_x509_sha256};

use aegis_firmware::guid::Guid;
use aegis_firmware::uefi::{self, attr, Dbx, SecureBootState};

const OWNER_MS: [u8; 16] = [
    0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b,
];

// --- El prefijo de 4 bytes ---

#[test]
fn el_prefijo_de_atributos_se_separa_de_los_datos() {
    // efivarfs antepone 4 bytes de atributos en little-endian. Saltarselos
    // desplaza cada offset del analisis; leerlos como datos corrompe todo.
    let raw = efivar(attr::BOOTSERVICE_ACCESS | attr::RUNTIME_ACCESS, &[0x01]);
    assert_eq!(raw.len(), 5, "4 de prefijo + 1 de dato");
    let v = uefi::parse_variable_bytes(&raw).unwrap();
    assert_eq!(v.attributes, 0x06, "BS|RT");
    assert!(v.tiene(attr::BOOTSERVICE_ACCESS) && v.tiene(attr::RUNTIME_ACCESS));
    assert!(!v.tiene(attr::NON_VOLATILE));
    assert_eq!(
        v.data,
        vec![0x01],
        "el dato es un solo byte, Secure Boot activo"
    );
    // Y una DBX real lleva NV|BS|RT|TIME_BASED = 0x27.
    let dbx_raw = efivar(0x27, &[0xFF; 8]);
    let vd = uefi::parse_variable_bytes(&dbx_raw).unwrap();
    assert!(vd.tiene(attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS));
}

#[test]
fn una_variable_mas_corta_que_el_prefijo_se_rechaza() {
    // Un fichero de 3 bytes no puede tener el prefijo de 4: leerlo como si lo
    // tuviera desbordaria. La funcion devuelve el tamano, no un panico.
    assert_eq!(uefi::parse_variable_bytes(&[0u8, 1, 2]), Err(3));
    assert_eq!(uefi::parse_variable_bytes(&[]), Err(0));
    // Exactamente 4 bytes: atributos y datos vacios, valido.
    let v = uefi::parse_variable_bytes(&[0x06, 0, 0, 0]).unwrap();
    assert!(v.data.is_empty());
}

// --- Secure Boot enforcing ---

#[test]
fn secure_boot_solo_impone_con_setup_mode_apagado() {
    // SecureBoot=1 NO basta: con SetupMode=1 cualquiera matricula claves sin
    // autenticar, que es el estado que busca un bootkit.
    assert!(SecureBootState {
        secure_boot: true,
        setup_mode: false
    }
    .imponiendo());
    assert!(!SecureBootState {
        secure_boot: true,
        setup_mode: true
    }
    .imponiendo());
    assert!(!SecureBootState {
        secure_boot: false,
        setup_mode: false
    }
    .imponiendo());
}

// --- DBX ---

#[test]
fn la_dbx_con_una_lista_de_hashes_se_analiza() {
    let h1 = [0x11u8; 32];
    let h2 = [0x22u8; 32];
    let lista = signature_list_sha256(OWNER_MS, &[h1, h2]);
    let dbx = Dbx::parse(&lista).unwrap();
    assert_eq!(dbx.num_hashes_sha256(), 2);
    assert!(dbx.revoca_hash(&h1), "h1 esta revocado");
    assert!(dbx.revoca_hash(&h2));
    assert!(!dbx.revoca_hash(&[0x33u8; 32]), "un hash ajeno no");
}

#[test]
fn la_dbx_recorre_todas_las_listas_concatenadas() {
    // Una DBX real es varias EFI_SIGNATURE_LIST concatenadas: quedarse en la
    // primera pierde la mayoria de las revocaciones. Aqui se concatenan una
    // lista de hashes SHA-256 y una de certificados X509_SHA256.
    let hbootkit = [0xABu8; 32];
    let mut buf = signature_list_sha256(OWNER_MS, &[[0x01; 32], hbootkit]);
    // Segunda lista: un certificado revocado (X509_SHA256, SignatureSize 64).
    let cert_hash = [0xCDu8; 32];
    let efi_time = [0u8; 16];
    buf.extend_from_slice(&signature_list_x509_sha256(
        OWNER_MS,
        &[(cert_hash, efi_time)],
    ));
    // Tercera: mas hashes.
    buf.extend_from_slice(&signature_list_sha256(OWNER_MS, &[[0x02; 32]]));

    let dbx = Dbx::parse(&buf).unwrap();
    // 3 hashes SHA-256 (2 + 1) mas 1 entrada de certificado.
    assert_eq!(dbx.num_hashes_sha256(), 3, "las tres listas se recorren");
    assert_eq!(dbx.firmas.len(), 4, "cuatro firmas en total");
    assert!(
        dbx.revoca_hash(&hbootkit),
        "el hash de la primera lista esta revocado"
    );
    assert!(
        dbx.revoca_hash(&[0x02; 32]),
        "el hash de la TERCERA lista tambien: no nos quedamos en la primera"
    );
    // El hash del certificado NO es un hash de binario: no revoca un binario.
    assert!(!dbx.revoca_hash(&cert_hash));
}

#[test]
fn el_signature_size_incluye_el_guid_de_propietario() {
    // SignatureSize = 16 (owner) + 32 (hash). El hash empieza en +16, no en +0.
    // Si se leyera desde +0, el "hash" seria el GUID de propietario y ninguna
    // comparacion casaria.
    let owner = [0x5A; 16];
    let hash = [0x7Cu8; 32];
    let lista = signature_list_sha256(owner, &[hash]);
    let dbx = Dbx::parse(&lista).unwrap();
    assert_eq!(dbx.firmas[0].owner, Guid::from_bytes(&owner));
    assert_eq!(
        dbx.firmas[0].hash_sha256(),
        Some(&hash[..]),
        "el hash es el dato tras el GUID de propietario, no el propio GUID"
    );
}

#[test]
fn una_dbx_malformada_se_rechaza_sin_desbordar() {
    // SignatureListSize que se sale del buffer, SignatureSize imposible, area
    // no multiplo del tamano de firma: todo tiene que fallar limpio.
    let h = [0u8; 32];
    let buena = signature_list_sha256(OWNER_MS, &[h]);

    // list_size mentido a un valor enorme.
    let mut mala = buena.clone();
    mala[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(Dbx::parse(&mala).is_err());

    // sig_size <= 16 (sin sitio ni para el owner).
    let mut mala2 = buena.clone();
    mala2[24..28].copy_from_slice(&8u32.to_le_bytes());
    assert!(Dbx::parse(&mala2).is_err());

    // Cualquier truncamiento: nunca panica.
    for corte in 0..buena.len() {
        let _ = Dbx::parse(&buena[..corte]);
    }
}

// --- GUID mixed-endian ---

#[test]
fn el_guid_se_formatea_en_su_orden_logico_no_en_el_de_cable() {
    // Los tres primeros campos van intercambiados en el cable. Volcarlos tal
    // cual da un GUID que no casa con ninguno.
    assert_eq!(
        uefi::EFI_CERT_SHA256.hyphenated(),
        "c1c41626-504c-4092-aca9-41f936934328"
    );
    assert_eq!(
        uefi::EFI_GLOBAL.hyphenated(),
        "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    );
    assert_eq!(
        uefi::EFI_CERT_X509_SHA256.hyphenated(),
        "3bd2a492-96c0-4079-b420-fc40b64e2807"
    );
    // Y el GUID corregido de SHA-384 (no el de SHA-224).
    assert_eq!(
        uefi::EFI_CERT_SHA384.hyphenated(),
        "ff3e5307-9fd0-48c9-85f7-8ba0b6c92e83"
    );
    // Ida y vuelta: de bytes de cable a forma canonica y de vuelta a bytes.
    let g = Guid::from_bytes(&common::guid_bytes(
        0xc1c41626,
        0x504c,
        0x4092,
        [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
    ));
    assert_eq!(g, uefi::EFI_CERT_SHA256);
}
