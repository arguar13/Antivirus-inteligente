//! Pruebas de deteccion de evasion con material real.
//!
//! # Como se fabrican los fixtures
//!
//! No hay mapas de memoria escritos a mano donde importa. La prueba de vaciado
//! **mapea de verdad** una biblioteca del sistema con `MAP_PRIVATE|PROT_EXEC`,
//! le cambia los bytes por copia-sobre-escritura y despues lee su propia
//! memoria con `process_vm_readv`, que es exactamente lo que hace el producto
//! contra un proceso ajeno. La region resultante es indistinguible de un
//! vaciado: `/proc/self/maps` la muestra respaldada por el fichero, con permiso
//! de ejecucion, y su contenido ya no es el del fichero.
//!
//! Se hace sobre un mapeo propio y no sobre el `.text` del proceso de prueba
//! porque reescribir el codigo que uno mismo esta ejecutando es una forma
//! elaborada de fallar por segmentacion.

use std::ffi::CString;

use aegis_evasion::hollow::{self, HollowVerdict};
use aegis_evasion::hooks::{self, PatchKind, ResolvedSymbol, SIMBOLOS_VIGILADOS};
use aegis_evasion::inject::{scan_injection, InjectionKind, ARENA_JIT_MIN};
use aegis_evasion::report::{EvasionReport, EvasionSeverity};
use aegis_scan::memory::{self, MemoryRegion, Perms};

const PAGINA: usize = 4096;

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

/// Un mapeo creado por la prueba, que se desmonta al salir.
struct Mapeo {
    addr: *mut libc::c_void,
    len: usize,
}

impl Drop for Mapeo {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.addr, self.len) };
    }
}

/// Mapea `len` bytes de `ruta` desde `offset`, privado y ejecutable.
fn mapear_privado_exec(ruta: &str, offset: i64, len: usize) -> Option<Mapeo> {
    let c = CString::new(ruta).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            fd,
            offset,
        )
    };
    unsafe { libc::close(fd) };
    if addr == libc::MAP_FAILED {
        return None;
    }
    Some(Mapeo { addr, len })
}

/// Mapea memoria anonima con los permisos indicados.
fn mapear_anonimo(len: usize, prot: i32) -> Option<Mapeo> {
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return None;
    }
    Some(Mapeo { addr, len })
}

/// Sobrescribe un mapeo ejecutable, como haria un vaciado.
fn sobrescribir(m: &Mapeo, patron: u8, cuantos: usize) -> bool {
    if unsafe { libc::mprotect(m.addr, m.len, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return false;
    }
    unsafe {
        std::ptr::write_bytes(m.addr.cast::<u8>(), patron, cuantos.min(m.len));
    }
    unsafe { libc::mprotect(m.addr, m.len, libc::PROT_READ | libc::PROT_EXEC) == 0 }
}

/// Una biblioteca del sistema con un segmento ejecutable utilizable.
///
/// Se busca en el propio mapa del proceso en vez de codificar una ruta: el
/// nombre y la ubicacion de libc cambian entre distribuciones y entre arquit.
fn biblioteca_ejecutable() -> Option<(String, u64, usize)> {
    let regs = memory::regions_of(std::process::id() as i32).ok()?;
    for r in regs {
        if !r.perms.exec || r.perms.write {
            continue;
        }
        let Some(p) = r.path.clone() else { continue };
        if !p.starts_with('/') || p.ends_with(" (deleted)") {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        let necesario = r.offset + 16 * PAGINA as u64;
        if meta.len() > necesario && r.len() >= 8 * PAGINA as u64 {
            return Some((p, r.offset, 8 * PAGINA));
        }
    }
    None
}

fn region(start: u64, end: u64, perms: &str, path: Option<&str>) -> MemoryRegion {
    MemoryRegion {
        start,
        end,
        perms: Perms::parse(perms),
        offset: 0,
        inode: if path.is_some_and(|p| p.starts_with('/')) {
            42
        } else {
            0
        },
        path: path.map(str::to_string),
    }
}

// ---------------------------------------------------------------------------
// 1. Vaciado de proceso contra un mapeo real
// ---------------------------------------------------------------------------

/// El caso central: una region respaldada por fichero cuyo contenido ya no es
/// el del fichero.
#[test]
fn un_mapeo_ejecutable_sobrescrito_se_detecta_como_vaciado() {
    let Some((ruta, offset, largo)) = biblioteca_ejecutable() else {
        eprintln!("sin biblioteca utilizable; se omite");
        return;
    };
    let Some(m) = mapear_privado_exec(&ruta, offset as i64, largo) else {
        eprintln!("mmap no disponible; se omite");
        return;
    };
    let inicio = m.addr as u64;

    let yo = std::process::id() as i32;

    // Antes de tocarlo: coincide con el disco.
    let regs = memory::regions_of(yo).unwrap();
    let nuestra: Vec<MemoryRegion> = regs.iter().filter(|r| r.start == inicio).cloned().collect();
    assert_eq!(
        nuestra.len(),
        1,
        "el mapeo deberia aparecer en /proc/self/maps"
    );
    assert_eq!(
        nuestra[0].offset, offset,
        "el desplazamiento del mapeo debe ser el que pedimos"
    );

    let limpio = hollow::compare_process(yo, &nuestra).unwrap();
    assert_eq!(limpio.regions_compared, 1);
    assert!(
        limpio.findings.is_empty(),
        "un mapeo intacto no puede divergir: {:?}",
        limpio.findings
    );

    // Ahora el vaciado: se sustituye el codigo por otro.
    assert!(sobrescribir(&m, 0x90, largo), "no se pudo reescribir");

    let regs = memory::regions_of(yo).unwrap();
    let nuestra: Vec<MemoryRegion> = regs.iter().filter(|r| r.start == inicio).cloned().collect();
    assert_eq!(nuestra.len(), 1);
    let sucio = hollow::compare_process(yo, &nuestra).unwrap();

    assert_eq!(sucio.verdict(), HollowVerdict::Hollowed, "{sucio:?}");
    let f = &sucio.findings[0];
    assert_eq!(f.path, ruta);
    assert!(
        f.fraction() > hollow::FRACCION_VACIADO,
        "fraccion {:.4} por debajo del umbral",
        f.fraction()
    );
    assert_eq!(
        f.differing_blocks, f.blocks,
        "un vaciado toca todos los bloques"
    );
    assert_eq!(sucio.score(), 90);
}

/// Sustituir solo unas instrucciones no es un vaciado: es un parche. La
/// distincion importa porque un parche lo hace tambien software legitimo
/// (compatibilidad, instrumentacion) y matar por eso seria inaceptable.
#[test]
fn un_parche_pequeno_no_se_confunde_con_un_vaciado() {
    let Some((_, offset, largo)) = biblioteca_ejecutable() else {
        return;
    };
    let Some((ruta, _, _)) = biblioteca_ejecutable() else {
        return;
    };
    let Some(m) = mapear_privado_exec(&ruta, offset as i64, largo) else {
        return;
    };
    let inicio = m.addr as u64;
    let yo = std::process::id() as i32;

    // 64 bytes de 32 KB: el orden de magnitud de una resolucion de IFUNC.
    assert!(sobrescribir(&m, 0xCC, 64));

    let regs = memory::regions_of(yo).unwrap();
    let nuestra: Vec<MemoryRegion> = regs.iter().filter(|r| r.start == inicio).cloned().collect();
    let inf = hollow::compare_process(yo, &nuestra).unwrap();

    assert_ne!(
        inf.verdict(),
        HollowVerdict::Hollowed,
        "64 bytes de {largo} no pueden ser un vaciado: {:?}",
        inf.findings
    );
}

/// La calibracion del umbral, sin necesitar un proceso.
#[test]
fn el_umbral_separa_el_parcheo_del_vaciado() {
    // Una resolucion de IFUNC: decenas de bytes repartidos en pocos bloques.
    assert_eq!(
        hollow::clasificar(48, 262_144, 3, 64),
        HollowVerdict::Intact
    );
    // Instrumentacion agresiva: por encima del aviso, lejos del vaciado.
    assert_eq!(
        hollow::clasificar(8_000, 262_144, 20, 64),
        HollowVerdict::Patched
    );
    // Segmento sustituido.
    assert_eq!(
        hollow::clasificar(200_000, 262_144, 64, 64),
        HollowVerdict::Hollowed
    );
    // Todos los bloques tocados aunque la fraccion sea moderada: un atacante
    // que conserve parte del relleno sigue sin poder dejar bloques limpios.
    assert_eq!(
        hollow::clasificar(20_000, 262_144, 64, 64),
        HollowVerdict::Hollowed
    );
    // Nada comparado, nada que decir.
    assert_eq!(hollow::clasificar(0, 0, 0, 0), HollowVerdict::Intact);
}

#[test]
fn el_conteo_por_bloques_distingue_disperso_de_masivo() {
    let a = vec![0u8; 16384];
    let mut b = a.clone();
    assert_eq!(hollow::diff_blocks(&a, &b), (0, 0, 4));

    // Un byte en cada bloque: disperso.
    for i in 0..4 {
        b[i * 4096] = 1;
    }
    assert_eq!(hollow::diff_blocks(&a, &b), (4, 4, 4));

    // Todo distinto.
    let c = vec![0xFFu8; 16384];
    assert_eq!(hollow::diff_blocks(&a, &c), (16384, 4, 4));

    // Longitudes distintas: se compara lo que hay en comun.
    let corto = vec![0xFFu8; 100];
    assert_eq!(hollow::diff_blocks(&a, &corto), (100, 1, 1));
}

/// Los procesos reales de la maquina no pueden dar falsos positivos: si dieran,
/// el producto seria inutilizable el primer dia.
#[test]
fn los_procesos_reales_del_sistema_no_dan_falsos_positivos() {
    let mut comparados = 0usize;
    let mut bytes = 0usize;
    let mut sospechosos = Vec::new();

    let Ok(dir) = std::fs::read_dir("/proc") else {
        return;
    };
    for e in dir.flatten() {
        let Some(s) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = s.parse::<i32>() else { continue };
        if memory::is_kernel_thread(pid) {
            continue;
        }
        let Ok(regs) = memory::regions_of(pid) else {
            continue;
        };
        let Ok(inf) = hollow::compare_process(pid, &regs) else {
            continue;
        };
        if inf.regions_compared == 0 {
            continue;
        }
        comparados += inf.regions_compared;
        bytes += inf.bytes_compared;
        for f in &inf.findings {
            if f.verdict != HollowVerdict::Intact {
                sospechosos.push(format!("pid {pid} {} {:.4}%", f.path, f.fraction() * 100.0));
            }
        }
    }

    assert!(
        comparados > 0,
        "no se comparo ninguna region: la prueba no estaria probando nada"
    );
    assert!(
        sospechosos.is_empty(),
        "falsos positivos sobre {comparados} regiones ({} MB): {sospechosos:?}",
        bytes / 1_000_000
    );
}

// ---------------------------------------------------------------------------
// 2. Inyeccion reflectiva
// ---------------------------------------------------------------------------

/// Memoria anonima RWX creada de verdad con `mmap`, vista a traves del mapa
/// real del proceso.
#[test]
fn una_region_anonima_rwx_real_se_detecta() {
    let Some(m) = mapear_anonimo(
        64 * PAGINA,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ) else {
        eprintln!("el sistema no permite RWX; se omite");
        return;
    };
    let inicio = m.addr as u64;

    let regs = memory::regions_of(std::process::id() as i32).unwrap();
    let nuestra: Vec<MemoryRegion> = regs.into_iter().filter(|r| r.start == inicio).collect();
    assert_eq!(nuestra.len(), 1, "el mapeo anonimo deberia aparecer");

    let inf = scan_injection(&nuestra);
    assert_eq!(inf.anon_exec_regions, 1);
    assert_eq!(inf.findings.len(), 1);
    assert_eq!(inf.findings[0].kind, InjectionKind::AnonymousRwx);
    assert_eq!(inf.findings[0].size, (64 * PAGINA) as u64);
    assert!(inf.score() > 0);
}

#[test]
fn la_pila_y_el_monton_ejecutables_pesan_mas_que_una_carga_util() {
    let pila = scan_injection(&[region(0x1000, 0x9000, "rwxp", Some("[stack]"))]);
    assert_eq!(pila.findings[0].kind, InjectionKind::ExecutableStack);

    let monton = scan_injection(&[region(0x1000, 0x9000, "rwxp", Some("[heap]"))]);
    assert_eq!(monton.findings[0].kind, InjectionKind::ExecutableHeap);

    let carga = scan_injection(&[region(0x1000, 0x9000, "r-xp", None)]);
    assert_eq!(carga.findings[0].kind, InjectionKind::AnonymousExecPayload);

    assert!(pila.score() > carga.score());
    assert!(monton.score() > carga.score());
}

/// Un JIT es la explicacion benigna de la memoria anonima ejecutable. Si no se
/// descuenta, cada navegador de la flota es una alerta.
#[test]
fn un_runtime_de_jit_atenua_la_puntuacion_pero_no_la_anula() {
    let sin_jit = scan_injection(&[region(0x400000, 0x500000, "rwxp", None)]);

    let con_jit = scan_injection(&[
        region(0x400000, 0x500000, "rwxp", None),
        region(
            0x7f0000000000,
            0x7f0001000000,
            "r-xp",
            Some("/usr/lib/libv8.so"),
        ),
    ]);

    assert_eq!(con_jit.jit_runtimes, vec!["libv8"]);
    assert!(
        con_jit.score() < sin_jit.score(),
        "el JIT deberia atenuar: {} vs {}",
        con_jit.score(),
        sin_jit.score()
    );
    assert!(
        con_jit.score() > 0,
        "pero no anular: un JIT es tambien donde mejor se esconde el codigo"
    );
}

/// Regresion medida sobre un proceso real de Node: reserva **64 MB de RWX de
/// una vez** para el espacio de codigo de V8, y no mapea ningun `libv8.so`
/// porque lo lleva enlazado dentro.
///
/// La primera version clasificaba eso como `AnonymousRwx` (peso 45) porque
/// miraba los permisos antes que el tamano, y cualquier proceso de Node de la
/// flota salia como Medium de forma permanente. Una carga util reflectiva son
/// cientos de KB; a los 64 MB el tamano manda.
#[test]
fn la_arena_rwx_de_un_jit_enlazado_estaticamente_no_es_una_inyeccion() {
    let arena = 64 * 1024 * 1024u64;
    assert!(arena >= ARENA_JIT_MIN);

    let inf = scan_injection(&[
        region(0x7f927fcd6000, 0x7f927fcd6000 + arena, "rwxp", None),
        region(0x400000, 0x900000, "r-xp", Some("/usr/bin/node")),
    ]);
    assert_eq!(inf.findings[0].kind, InjectionKind::AnonymousRwxArena);
    assert_eq!(
        inf.jit_runtimes,
        vec!["node"],
        "el JIT hay que reconocerlo por el ejecutable: Node no mapea libv8.so"
    );
    assert!(
        inf.score() < 40,
        "un proceso de Node no puede salir como Medium permanente: {}",
        inf.score()
    );
    assert!(
        inf.score() > 0,
        "pero RWX viola W^X a cualquier tamano y tiene que quedar registrado"
    );

    // Del tamano de una carga util, el mismo RWX si es grave.
    let payload = scan_injection(&[region(0x400000, 0x400000 + 300 * 1024, "rwxp", None)]);
    assert_eq!(payload.findings[0].kind, InjectionKind::AnonymousRwx);
    assert!(payload.score() > inf.score());
}

/// El analisis completo sobre los procesos vivos de la maquina. Es la unica
/// prueba que dice si los umbrales sirven en un sistema real.
#[test]
fn el_analisis_completo_no_marca_como_graves_los_procesos_del_sistema() {
    let mut analizados = 0usize;
    let mut simbolos = 0usize;
    let mut graves = Vec::new();

    let Ok(dir) = std::fs::read_dir("/proc") else {
        return;
    };
    for e in dir.flatten() {
        let Some(s) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = s.parse::<i32>() else { continue };
        if memory::is_kernel_thread(pid) {
            continue;
        }
        let Ok(inf) = aegis_evasion::analyze_process(pid) else {
            continue;
        };
        if inf.hollow.regions_compared == 0 && inf.hooks.checked == 0 {
            continue;
        }
        analizados += 1;
        simbolos += inf.hooks.checked;
        if inf.severity() >= EvasionSeverity::Medium {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            graves.push(format!(
                "{pid} {} score {} {:?}",
                comm.trim(),
                inf.score(),
                inf.signals()
            ));
        }
    }

    assert!(analizados > 0, "no se analizo ningun proceso");
    assert!(
        simbolos > 0,
        "no se comprobo ningun simbolo: la parte de enganches no estaria probando nada"
    );
    assert!(
        graves.is_empty(),
        "{analizados} procesos analizados y {} marcados como graves: {graves:?}",
        graves.len()
    );
}

/// Una arena grande de JIT no puede puntuar, o todo proceso con JIT seria una
/// alerta permanente.
#[test]
fn una_arena_grande_se_registra_sin_puntuar() {
    let inf = scan_injection(&[region(0x400000, 0x400000 + 32 * 1024 * 1024, "r-xp", None)]);
    assert_eq!(inf.findings[0].kind, InjectionKind::AnonymousExecArena);
    assert_eq!(inf.score(), 0);
    assert_eq!(inf.anon_exec_regions, 1, "pero si se registra");
}

/// Un mapeo de fichero escribible y ejecutable es como se parchea codigo ajeno
/// sin tocar el disco.
#[test]
fn un_mapeo_de_fichero_escribible_y_ejecutable_se_detecta() {
    let inf = scan_injection(&[region(
        0x7f0000000000,
        0x7f0000010000,
        "rwxp",
        Some("/usr/lib/libc.so.6"),
    )]);
    assert_eq!(inf.findings[0].kind, InjectionKind::FileBackedWx);
    assert_eq!(inf.anon_exec_regions, 0, "no es anonima");
}

#[test]
fn las_regiones_normales_no_producen_hallazgos() {
    let inf = scan_injection(&[
        region(0x400000, 0x410000, "r-xp", Some("/usr/bin/algo")),
        region(0x410000, 0x420000, "r--p", Some("/usr/bin/algo")),
        region(0x420000, 0x430000, "rw-p", Some("/usr/bin/algo")),
        region(0x500000, 0x600000, "rw-p", Some("[heap]")),
        region(0x7ffd00000000, 0x7ffd00021000, "rw-p", Some("[stack]")),
        region(0x7fff00000000, 0x7fff00001000, "r-xp", Some("[vdso]")),
    ]);
    assert!(inf.findings.is_empty(), "{:?}", inf.findings);
    assert_eq!(inf.score(), 0);
}

// ---------------------------------------------------------------------------
// 3. Integridad de los stubs
// ---------------------------------------------------------------------------

#[test]
fn se_reconocen_las_cuatro_formas_de_saltar() {
    assert_eq!(
        hooks::reconocer_salto(&[0xE9, 0x11, 0x22, 0x33, 0x44]),
        Some(PatchKind::JmpRel32)
    );
    assert_eq!(
        hooks::reconocer_salto(&[0xFF, 0x25, 0, 0, 0, 0]),
        Some(PatchKind::JmpIndirect)
    );
    assert_eq!(
        hooks::reconocer_salto(&[0x68, 1, 2, 3, 4, 0xC3]),
        Some(PatchKind::PushRet)
    );
    assert_eq!(
        hooks::reconocer_salto(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xE0]),
        Some(PatchKind::MovRaxJmp)
    );
    // Un prologo corriente de x86-64 no es un salto.
    assert_eq!(
        hooks::reconocer_salto(&[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5]),
        None
    );
    // Truncados: no se reconoce lo que no cabe.
    assert_eq!(hooks::reconocer_salto(&[0xE9, 0x11]), None);
    assert_eq!(hooks::reconocer_salto(&[]), None);
}

/// El enganche: los bytes en memoria son un salto y los del fichero no.
#[test]
fn un_stub_enganchado_se_detecta_con_su_forma() {
    let mut disco = vec![0u8; 4096];
    // Prologo tipico: endbr64; push rbp; mov rbp,rsp
    disco[512..520].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5]);

    let mut memoria = disco[512..528].to_vec();
    memoria[0] = 0xE9;
    memoria[1..5].copy_from_slice(&0x1234_5678u32.to_le_bytes());

    let simbolos = vec![ResolvedSymbol {
        name: "open".into(),
        library: "/lib/libc.so.6".into(),
        address: 0x7f0000001000,
        file_offset: 512,
    }];

    let inf = hooks::scan_hooks(
        &simbolos,
        |_, n| Some(memoria[..n.min(memoria.len())].to_vec()),
        |_| Some(disco.clone()),
    );

    assert_eq!(inf.checked, 1);
    assert_eq!(inf.findings.len(), 1);
    assert_eq!(inf.findings[0].kind, PatchKind::JmpRel32);
    assert_eq!(inf.findings[0].symbol, "open");
    assert_eq!(inf.hooked(), 1);
    assert_eq!(inf.score(), 40);
}

/// Un stub intacto no genera nada. Es el caso del 99,99% de los simbolos y
/// tiene que ser silencioso.
#[test]
fn un_stub_intacto_no_genera_hallazgo() {
    let disco = vec![0xAAu8; 4096];
    let simbolos = vec![ResolvedSymbol {
        name: "read".into(),
        library: "/lib/libc.so.6".into(),
        address: 0x1000,
        file_offset: 0,
    }];
    let inf = hooks::scan_hooks(
        &simbolos,
        |_, n| Some(vec![0xAAu8; n]),
        |_| Some(disco.clone()),
    );
    assert_eq!(inf.checked, 1);
    assert!(inf.findings.is_empty());
    assert_eq!(inf.score(), 0);
}

/// Una diferencia que no es un salto pesa poco: es lo que produce una
/// reubicacion, y tratarla como un enganche llenaria el informe de ruido.
#[test]
fn una_diferencia_que_no_es_un_salto_apenas_puntua() {
    let disco = vec![0x00u8; 4096];
    let simbolos = vec![ResolvedSymbol {
        name: "write".into(),
        library: "/lib/libc.so.6".into(),
        address: 0x1000,
        file_offset: 0,
    }];
    let inf = hooks::scan_hooks(
        &simbolos,
        |_, n| {
            let mut v = vec![0x00u8; n];
            v[7] = 0x42;
            Some(v)
        },
        |_| Some(disco.clone()),
    );
    assert_eq!(inf.findings[0].kind, PatchKind::Unknown);
    assert_eq!(inf.hooked(), 0, "no es un enganche");
    assert_eq!(inf.score(), 5);
}

#[test]
fn lo_que_no_se_puede_leer_se_cuenta_como_omitido_y_no_como_limpio() {
    let simbolos = vec![
        ResolvedSymbol {
            name: "a".into(),
            library: "/lib/inexistente.so".into(),
            address: 0x1000,
            file_offset: 0,
        },
        ResolvedSymbol {
            name: "b".into(),
            library: "/lib/libc.so.6".into(),
            address: 0x2000,
            file_offset: 0,
        },
        ResolvedSymbol {
            name: "c".into(),
            library: "/lib/libc.so.6".into(),
            address: 0x3000,
            file_offset: 99_999,
        },
    ];
    let inf = hooks::scan_hooks(
        &simbolos,
        |a, _| if a == 0x2000 { None } else { Some(vec![0; 16]) },
        |l| {
            if l.contains("inexistente") {
                None
            } else {
                Some(vec![0u8; 4096])
            }
        },
    );
    assert_eq!(inf.checked, 0);
    assert_eq!(
        inf.skipped, 3,
        "fichero ausente, memoria ilegible y offset fuera"
    );
    assert!(inf.findings.is_empty());
}

/// Los simbolos se resuelven de una libc real del sistema, no de un ELF
/// inventado: la traduccion de direccion virtual a desplazamiento de fichero es
/// donde se cometen los errores, y solo un ELF de verdad la ejercita.
#[test]
fn los_simbolos_vigilados_se_resuelven_de_una_libc_real() {
    let Some((ruta, _, _)) = biblioteca_ejecutable() else {
        return;
    };
    let Ok(datos) = std::fs::read(&ruta) else {
        return;
    };
    let Ok(simbolos) = hooks::resolver_simbolos(&ruta, &datos, 0x7f0000000000, SIMBOLOS_VIGILADOS)
    else {
        return;
    };
    if simbolos.is_empty() {
        eprintln!("{ruta} no exporta ninguno de los simbolos vigilados; se omite");
        return;
    }

    for s in &simbolos {
        assert!(
            SIMBOLOS_VIGILADOS.contains(&s.name.as_str()),
            "{} no esta en la lista",
            s.name
        );
        assert!(
            (s.file_offset as usize) < datos.len(),
            "{} apunta fuera del fichero: {} de {}",
            s.name,
            s.file_offset,
            datos.len()
        );
        assert!(s.address > 0x7f0000000000, "{} sin rebasar", s.name);
    }

    // Y comparados contra si mismos, ninguno esta enganchado.
    let inf = hooks::scan_hooks(
        &simbolos,
        |_, n| Some(vec![0u8; n]),
        |_| Some(datos.clone()),
    );
    assert_eq!(inf.checked, simbolos.len());
}

// ---------------------------------------------------------------------------
// 4. Informe combinado
// ---------------------------------------------------------------------------

#[test]
fn un_proceso_limpio_no_produce_informe() {
    let inf = EvasionReport {
        pid: 1,
        injection: scan_injection(&[region(0x400000, 0x410000, "r-xp", Some("/usr/bin/algo"))]),
        ..Default::default()
    };
    assert_eq!(inf.score(), 0);
    assert_eq!(inf.severity(), EvasionSeverity::Clean);
    assert!(inf.signals().is_empty());
}

/// Un vaciado es grave por si solo: no hay explicacion benigna para que el
/// codigo que corre no sea el del fichero que dice ejecutar.
#[test]
fn un_vaciado_es_grave_sin_necesitar_otras_senales() {
    let mut inf = EvasionReport::default();
    inf.hollow.findings.push(hollow::HollowFinding {
        start: 0x400000,
        path: "/usr/bin/algo".into(),
        file_offset: 0,
        compared: 262_144,
        differing: 200_000,
        differing_blocks: 64,
        blocks: 64,
        verdict: HollowVerdict::Hollowed,
    });
    assert_eq!(inf.severity(), EvasionSeverity::High);
    assert_eq!(inf.signals().len(), 1);
}

/// Las senales sueltas no bastan; su coincidencia si. Es la razon de que el
/// crate tenga tres modulos y no uno.
#[test]
fn las_senales_se_acumulan_hasta_ser_concluyentes() {
    let solo_inyeccion = EvasionReport {
        injection: scan_injection(&[region(0x400000, 0x420000, "r-xp", None)]),
        ..Default::default()
    };
    assert_eq!(solo_inyeccion.severity(), EvasionSeverity::Low);

    let mut ambas = solo_inyeccion.clone();
    ambas.hooks.findings.push(hooks::HookFinding {
        symbol: "connect".into(),
        library: "/lib/libc.so.6".into(),
        address: 0x7f0000001000,
        kind: PatchKind::JmpRel32,
        in_memory: vec![0xE9, 0, 0, 0, 0],
        on_disk: vec![0xF3, 0x0F, 0x1E, 0xFA, 0x55],
    });
    assert!(ambas.score() > solo_inyeccion.score());
    assert_eq!(ambas.severity(), EvasionSeverity::Medium);

    let mut tres = ambas.clone();
    tres.injection = scan_injection(&[
        region(0x400000, 0x420000, "rwxp", None),
        region(0x500000, 0x520000, "rwxp", Some("[stack]")),
    ]);
    assert_eq!(tres.severity(), EvasionSeverity::High);
    assert_eq!(tres.signals().len(), 2);
}
