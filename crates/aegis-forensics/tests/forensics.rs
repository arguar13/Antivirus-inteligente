//! Pruebas del analisis forense en vivo.
//!
//! El analisis de patrones se prueba con buffers construidos a mano —una vtable
//! secuestrada, un gadget de pivote, shellcode— porque provocar un exploit real
//! en una prueba es ni fiable ni seguro. El volcado en vivo SI se prueba contra
//! memoria real: se mapea una region, se escribe, y se lee con
//! `process_vm_readv` sobre el propio proceso, que es exactamente lo que hace el
//! producto contra un proceso ajeno.

use aegis_forensics::dump::{DumpPolicy, MemoryDump};
use aegis_forensics::exploit::{self, PointerTarget};
use aegis_forensics::report::{ForensicReport, ForensicSeverity};
use aegis_scan::memory::{MemoryRegion, Perms};

fn region(start: u64, end: u64, perms: &str, path: Option<&str>) -> MemoryRegion {
    MemoryRegion {
        start,
        end,
        perms: Perms::parse(perms),
        offset: 0,
        inode: if path.is_some_and(|p| p.starts_with('/')) {
            10
        } else {
            0
        },
        path: path.map(str::to_string),
    }
}

/// Un mapa sintetico: una biblioteca con codigo (file-exec) y una region
/// ejecutable anonima (donde vive el codigo del atacante).
fn mapa() -> Vec<MemoryRegion> {
    vec![
        region(0x400000, 0x450000, "r-xp", Some("/usr/lib/libapp.so")),
        region(0x600000, 0x610000, "rw-p", Some("[heap]")),
        region(0x7f0000000000, 0x7f0000010000, "rwxp", None), // anon exec
    ]
}

// ---------------------------------------------------------------------------
// Clasificacion de punteros
// ---------------------------------------------------------------------------

#[test]
fn los_punteros_se_clasifican_por_su_destino() {
    let m = mapa();
    assert_eq!(
        exploit::classify_pointer(0x401000, &m),
        PointerTarget::FileExec
    );
    assert_eq!(
        exploit::classify_pointer(0x7f0000000100, &m),
        PointerTarget::AnonExec
    );
    assert_eq!(
        exploit::classify_pointer(0x600100, &m),
        PointerTarget::NonExec
    );
    assert_eq!(
        exploit::classify_pointer(0x999999, &m),
        PointerTarget::Unmapped
    );
}

// ---------------------------------------------------------------------------
// Vtable hooking
// ---------------------------------------------------------------------------

fn punteros(addrs: &[u64]) -> Vec<u8> {
    let mut v = Vec::new();
    for a in addrs {
        v.extend_from_slice(&a.to_le_bytes());
    }
    v
}

#[test]
fn una_vtable_limpia_no_se_marca() {
    let m = mapa();
    // Cuatro metodos, todos en el codigo de la biblioteca.
    let data = punteros(&[0x401000, 0x401100, 0x401200, 0x401300]);
    assert!(exploit::scan_vtables(&data, &m).is_empty());
}

#[test]
fn una_vtable_con_una_entrada_secuestrada_se_detecta() {
    let m = mapa();
    // Tres metodos legitimos y uno redirigido a codigo anonimo.
    let data = punteros(&[0x401000, 0x401100, 0x7f0000000200, 0x401300]);
    let hallazgos = exploit::scan_vtables(&data, &m);
    assert_eq!(hallazgos.len(), 1);
    assert_eq!(hallazgos[0].entries, 4);
    assert_eq!(hallazgos[0].anon_entries, 1);
}

#[test]
fn unos_pocos_punteros_no_bastan_para_una_vtable() {
    let m = mapa();
    // Dos punteros (uno anonimo) por debajo del minimo: no es una vtable.
    let data = punteros(&[0x7f0000000200, 0x401000]);
    assert!(exploit::scan_vtables(&data, &m).is_empty());
}

// ---------------------------------------------------------------------------
// Stack pivots y shellcode
// ---------------------------------------------------------------------------

#[test]
fn los_gadgets_de_stack_pivot_se_reconocen() {
    // xchg eax,esp; ret  precedido y seguido de relleno.
    let mut code = vec![0x55, 0x48, 0x89, 0xe5]; // prologo normal
    code.extend_from_slice(&[0x94, 0xc3]); // el gadget
    code.extend_from_slice(&[0x90, 0x90]);
    let hallazgos = exploit::scan_pivots(&code);
    assert!(
        hallazgos.iter().any(|h| h.what.contains("xchg eax,esp")),
        "{hallazgos:?}"
    );
}

#[test]
fn el_codigo_normal_no_dispara_falsos_pivotes() {
    // Un prologo y epilogo corrientes, sin gadgets de pivote.
    let code = vec![
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x7d, 0xf8, 0xc9, 0xc3,
    ];
    assert!(exploit::scan_pivots(&code).is_empty());
}

#[test]
fn el_shellcode_en_datos_se_detecta() {
    // Tobogan de NOP seguido de un stub de syscall: shellcode de manual.
    let mut data = vec![0x90u8; 32];
    data.extend_from_slice(&[0x0f, 0x05]); // syscall
    let hallazgos = exploit::scan_shellcode(&data);
    assert!(
        hallazgos.iter().any(|h| h.what.contains("NOP")),
        "{hallazgos:?}"
    );
    assert!(
        hallazgos.iter().any(|h| h.what.contains("syscall")),
        "{hallazgos:?}"
    );
}

#[test]
fn un_texto_normal_no_parece_shellcode() {
    let data = b"documento de trabajo con contenido inocuo y ningun stub".to_vec();
    assert!(exploit::scan_shellcode(&data).is_empty());
}

// ---------------------------------------------------------------------------
// Informe combinado sobre un volcado sintetico
// ---------------------------------------------------------------------------

/// Construye un MemoryDump a mano a partir de regiones y sus contenidos.
fn dump_sintetico(piezas: Vec<(MemoryRegion, Vec<u8>)>) -> MemoryDump {
    use aegis_forensics::dump::RegionDump;
    let mut d = MemoryDump::default();
    for (region, bytes) in piezas {
        d.total_bytes += bytes.len();
        d.regions.push(RegionDump {
            region,
            bytes,
            partial: false,
        });
    }
    d
}

#[test]
fn una_vtable_secuestrada_hace_el_informe_malicioso() {
    let m = mapa();
    let heap = region(0x600000, 0x610000, "rw-p", Some("[heap]"));
    let data = punteros(&[0x401000, 0x401100, 0x7f0000000200, 0x401300]);
    let dump = dump_sintetico(vec![(heap, data)]);
    let informe = ForensicReport::analyze(1234, &dump, &m);
    assert_eq!(informe.severity(), ForensicSeverity::Malicious);
    assert_eq!(informe.hooked_vtables.len(), 1);
}

#[test]
fn shellcode_mas_pivote_es_malicioso_pero_por_separado_es_sospechoso() {
    let m = mapa();
    // Region de datos con shellcode.
    let mut sc = vec![0x90u8; 32];
    sc.extend_from_slice(&[0x0f, 0x05]);
    let heap = region(0x600000, 0x610000, "rw-p", Some("[heap]"));
    // Solo shellcode: sospechoso.
    let solo_sc = ForensicReport::analyze(1, &dump_sintetico(vec![(heap.clone(), sc.clone())]), &m);
    assert_eq!(solo_sc.severity(), ForensicSeverity::Suspicious);

    // Shellcode en datos + gadget de pivote en codigo anonimo: malicioso.
    let anon = region(0x7f0000000000, 0x7f0000010000, "rwxp", None);
    let pivote = vec![0x94u8, 0xc3];
    let combo = ForensicReport::analyze(1, &dump_sintetico(vec![(heap, sc), (anon, pivote)]), &m);
    assert_eq!(combo.severity(), ForensicSeverity::Malicious);
}

#[test]
fn un_proceso_sin_indicios_da_informe_limpio() {
    let m = mapa();
    let heap = region(0x600000, 0x610000, "rw-p", Some("[heap]"));
    let data = b"solo datos normales de una aplicacion".to_vec();
    let informe = ForensicReport::analyze(1, &dump_sintetico(vec![(heap, data)]), &m);
    assert_eq!(informe.severity(), ForensicSeverity::Clean);
}

// ---------------------------------------------------------------------------
// Volcado en vivo contra memoria REAL
// ---------------------------------------------------------------------------

#[test]
fn el_volcado_en_vivo_lee_la_memoria_real_del_proceso_sin_pararlo() {
    // Se mapea una region anonima escribible y se le escribe un patron
    // reconocible; luego se vuelca la memoria del propio proceso y se comprueba
    // que el patron aparece en el volcado. Es exactamente el camino que sigue el
    // producto contra un proceso ajeno, sobre uno mismo por seguridad.
    let len = 64 * 1024;
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(addr, libc::MAP_FAILED, "mmap fallo");
    let marca = b"AEGIS-FORENSICS-MARCADOR-UNICO-9f3a";
    unsafe {
        std::ptr::copy_nonoverlapping(marca.as_ptr(), addr as *mut u8, marca.len());
    }

    let yo = std::process::id() as i32;
    let dump = MemoryDump::capture(yo, &DumpPolicy::default()).unwrap();

    // El marcador tiene que aparecer en alguna region escribible del volcado.
    let encontrado = dump
        .writable_regions()
        .any(|d| ventana_contiene(&d.bytes, marca));
    assert!(
        encontrado,
        "el volcado en vivo no capturo la memoria escrita ({} regiones, {} bytes)",
        dump.regions.len(),
        dump.total_bytes
    );

    unsafe {
        libc::munmap(addr, len);
    }
}

fn ventana_contiene(heno: &[u8], aguja: &[u8]) -> bool {
    heno.windows(aguja.len()).any(|w| w == aguja)
}
