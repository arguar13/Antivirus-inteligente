//! Pruebas del motor de respuesta activa.
//!
//! La terminacion de procesos se prueba contra procesos REALES creados por la
//! propia prueba, no contra simulaciones: una carrera de reciclado de PID o un
//! huerfano que sobrevive solo aparecen con el planificador de verdad.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aegis_prueba::{omitir, Requisito};
use aegis_resp::isolate::{build_ruleset, parse_resolvers, IsolationPolicy, Isolator, TABLE};
use aegis_resp::kill::{
    collect_tree, parse_stat, protection_reason, self_ancestry, snapshot_processes,
};
use aegis_resp::quarantine::{FileMetadata, Quarantine, QuarantineError, QuarantineId};
use aegis_resp::{kill_process_tree, KillOptions};

// ---------------------------------------------------------------------------
// Analisis de /proc
// ---------------------------------------------------------------------------

#[test]
fn parse_stat_soporta_nombres_con_parentesis_y_espacios() {
    // Un proceso llamado "evil ) 1 2 3 (" rompe cualquier analisis que trocee
    // por espacios desde el principio. El unico anclaje fiable es el ULTIMO ')'.
    let linea = "1234 (evil ) 1 2 3 () S 1000 1234 1234 0 -1 4194304 100 0 0 0 5 6 0 0 20 0 1 0 99887766 12345 0 0 0";
    let f = parse_stat(linea).expect("debe analizarse");
    assert_eq!(f.pid, 1234);
    assert_eq!(f.comm, "evil ) 1 2 3 (");
    assert_eq!(f.state, 'S');
    assert_eq!(f.ppid, 1000);
    assert_eq!(f.starttime, 99887766);
    // 4194304 = 0x400000, sin PF_KTHREAD (0x200000).
    assert_eq!(f.flags & aegis_resp::kill::PF_KTHREAD, 0);
}

#[test]
fn los_hilos_de_kernel_se_reconocen_por_su_bandera_no_por_su_enlace_exe() {
    // Detectarlos por si /proc/<pid>/exe se resuelve clasifica mal a los
    // ZOMBIS, que tampoco tienen ese enlace. Un proceso normal marcado por
    // error como hilo de kernel queda protegido y sobrevive a la respuesta.
    let con_bandera = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0 0";
    let f = parse_stat(con_bandera).expect("analiza");
    assert_ne!(f.flags & aegis_resp::kill::PF_KTHREAD, 0);

    // Y ahora sobre el sistema real.
    //
    // Los hilos de kernel se buscan POR LO QUE SON, no por su numero. La version
    // anterior daba por hecho que el PID 2 es `kthreadd`, que es cierto en un
    // Linux nativo y falso en cuanto hay un espacio de nombres de PID de por
    // medio: en WSL2 con systemd el PID 1 es `systemd`, el 2 es el `init` de
    // Microsoft —un proceso de usuario corriente— y no existen ni el 3 ni el 4.
    // Exigirle al PID 2 que fuera hilo de kernel hacia fallar la prueba
    // acusando al codigo de un defecto que no tenia.
    //
    // Identificar un hilo de kernel por su PID es, ademas, la misma clase de
    // error que esta prueba existe para impedir: fijarse en algo que no lo
    // define.
    let ps = snapshot_processes(Path::new("/proc")).unwrap();

    let yo = ps
        .iter()
        .find(|p| p.pid == std::process::id() as i32)
        .unwrap();
    assert!(!yo.is_kernel_thread);

    let kernel: Vec<_> = ps.iter().filter(|p| p.is_kernel_thread).collect();
    if kernel.is_empty() {
        // No es un aprobado disimulado: es que esta maquina no tiene hilos de
        // kernel QUE VER. Pasa en WSL2 y en contenedores con espacio de nombres
        // de PID, donde /proc solo muestra los procesos del espacio. Lo que la
        // prueba afirma sobre la bandera ya quedo comprobado arriba con una
        // linea de `stat` autentica de kthreadd.
        omitir(
            &format!(
                "esta maquina no expone hilos de kernel en /proc \
                 ({} procesos, ninguno con PF_KTHREAD). La deteccion por bandera se \
                 comprobo igual sobre la linea de stat de kthreadd.",
                ps.len()
            ),
            Requisito::Entorno,
        );
        return;
    }

    // Donde SI los hay, tienen que cumplir lo que los define: sin imagen
    // ejecutable. Es la comprobacion que de verdad separa mirar la bandera de
    // mirar el enlace `exe`.
    for k in &kernel {
        assert!(
            std::fs::read_link(format!("/proc/{}/exe", k.pid)).is_err(),
            "PID {} ({}) esta marcado como hilo de kernel pero tiene exe resoluble",
            k.pid,
            k.comm
        );
    }
}

#[test]
fn parse_stat_rechaza_lineas_incoherentes() {
    assert!(parse_stat("").is_none());
    assert!(parse_stat("1234 sin parentesis S 1").is_none());
    assert!(parse_stat("1234 )invertido( S 1").is_none());
}

#[test]
fn el_inventario_de_procesos_ve_el_sistema_real() {
    let ps = snapshot_processes(Path::new("/proc")).expect("leer /proc");
    assert!(ps.len() > 5, "solo {} procesos", ps.len());
    assert!(ps.iter().any(|p| p.pid == std::process::id() as i32));
}

// ---------------------------------------------------------------------------
// Protecciones
// ---------------------------------------------------------------------------

#[test]
fn nunca_se_termina_init_ni_el_propio_agente() {
    let opts = KillOptions::default();
    let cadena = self_ancestry(&opts.proc_root);
    let ps = snapshot_processes(&opts.proc_root).unwrap();

    let init = ps.iter().find(|p| p.pid == 1).expect("PID 1 existe");
    let motivo = protection_reason(init, &opts, &cadena).expect("init debe estar protegido");
    assert!(motivo.contains("init"), "motivo: {motivo}");

    let yo = ps
        .iter()
        .find(|p| p.pid == std::process::id() as i32)
        .expect("el proceso de prueba existe");
    // Terminar el propio agente lo desarmaria justo cuando esta respondiendo a
    // un incidente.
    assert!(protection_reason(yo, &opts, &cadena).is_some());
}

#[test]
fn pedir_el_arbol_de_init_se_rechaza_entero_sin_matar_nada() {
    // Esta es la prueba mas importante del modulo.
    //
    // Una version anterior protegia al PID 1 pero seguia terminando a sus
    // DESCENDIENTES, con lo que "termina el arbol del PID 1" significaba
    // "termina todos los procesos de la maquina". Ese codigo mato el contenedor
    // de pruebas la primera vez que se ejecuto esta suite.
    //
    // El contrato correcto: si la raiz esta protegida, la operacion entera se
    // rechaza y no se toca ni un solo proceso.
    let antes = snapshot_processes(Path::new("/proc")).unwrap().len();

    let e = kill_process_tree(
        1,
        &KillOptions {
            immediate: true,
            ..Default::default()
        },
    )
    .expect_err("el arbol de init tiene que rechazarse");

    assert!(
        matches!(e, aegis_resp::KillError::Protected { .. }),
        "se esperaba un rechazo, no {e:?}"
    );

    let despues = snapshot_processes(Path::new("/proc")).unwrap().len();
    // Margen por los procesos que van y vienen normalmente durante la prueba.
    assert!(
        despues + 5 >= antes,
        "el rechazo no debe matar nada: {antes} procesos antes, {despues} despues"
    );
}

#[test]
fn un_arbol_por_encima_de_la_cota_se_rechaza_y_no_deja_procesos_congelados() {
    let mut hijo = lanzar_arbol(3);
    let raiz = hijo.id() as i32;
    esperar_a_que_aparezca(raiz, 3);

    // Cota de 1: cualquier arbol con mas de un proceso la supera.
    let e = kill_process_tree(
        raiz,
        &KillOptions {
            max_tree_size: 1,
            immediate: true,
            ..Default::default()
        },
    )
    .expect_err("debe rechazarse por tamano");
    assert!(
        matches!(e, aegis_resp::KillError::TreeTooLarge { .. }),
        "error: {e:?}"
    );

    // La raiz se congela antes de enumerar; un rechazo tiene que reanudarla.
    // Dejarla detenida seria bloquear un servicio legitimo por un rechazo.
    std::thread::sleep(Duration::from_millis(100));
    let ps = snapshot_processes(Path::new("/proc")).unwrap();
    let estado = ps.iter().find(|p| p.pid == raiz).map(|p| p.state);
    assert_ne!(
        estado,
        Some('T'),
        "la raiz quedo detenida tras un rechazo (estado {estado:?})"
    );

    // Limpieza.
    let _ = kill_process_tree(
        raiz,
        &KillOptions {
            immediate: true,
            ..Default::default()
        },
    );
    let _ = hijo.wait();
}

// ---------------------------------------------------------------------------
// Terminacion real de arboles
// ---------------------------------------------------------------------------

/// Lanza un arbol real de procesos de tres niveles.
///
/// Estructura: sh raiz -> (sh intermedio -> 2 sleep) + 1 sleep. Son procesos de
/// verdad con relacion padre-hijo de verdad: una carrera de reciclado de PID o
/// un huerfano que sobrevive solo aparecen con el planificador real.
fn lanzar_arbol(_profundidad: u32) -> Child {
    Command::new("sh")
        .arg("-c")
        .arg("sh -c 'sleep 300 & sleep 300 & wait' & sleep 300 & wait")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("lanzar el arbol de prueba")
}

fn esperar_a_que_aparezca(pid: i32, minimo: usize) {
    for _ in 0..50 {
        if let Ok(t) = collect_tree(Path::new("/proc"), pid) {
            if t.members.len() >= minimo {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn termina_un_arbol_completo_sin_dejar_huerfanos() {
    let mut hijo = lanzar_arbol(3);
    let raiz = hijo.id() as i32;
    esperar_a_que_aparezca(raiz, 3);

    let arbol = collect_tree(Path::new("/proc"), raiz).expect("arbol visible");
    assert!(
        arbol.members.len() >= 3,
        "el arbol de prueba solo tiene {} miembros",
        arbol.members.len()
    );
    let pids: Vec<i32> = arbol.members.iter().map(|p| p.pid).collect();

    // El orden de terminacion va de las HOJAS a la raiz: matar al padre primero
    // reasignaria sus hijos a init y sobrevivirian.
    assert_eq!(*pids.last().unwrap(), raiz, "la raiz va la ultima");

    let informe = kill_process_tree(
        raiz,
        &KillOptions {
            immediate: true,
            ..Default::default()
        },
    )
    .expect("terminar");

    assert!(
        informe.complete(),
        "supervivientes: {:?}",
        informe.survivors()
    );
    let _ = hijo.wait();

    // Verificacion independiente: ninguno de los PID sigue vivo.
    std::thread::sleep(Duration::from_millis(100));
    let vivos = snapshot_processes(Path::new("/proc")).unwrap();
    for pid in pids {
        let sigue = vivos.iter().any(|p| p.pid == pid && p.state != 'Z');
        assert!(!sigue, "el proceso {pid} sobrevivio al arbol");
    }
}

#[test]
fn terminar_un_pid_inexistente_da_error_claro() {
    // Un PID altisimo que no puede existir.
    let e = kill_process_tree(4_194_303, &KillOptions::default()).unwrap_err();
    assert!(
        matches!(e, aegis_resp::KillError::NoSuchProcess(4_194_303)),
        "error: {e:?}"
    );
}

// ---------------------------------------------------------------------------
// Cuarentena
// ---------------------------------------------------------------------------

struct DirTemporal(PathBuf);

impl DirTemporal {
    fn nuevo(nombre: &str) -> DirTemporal {
        let p = std::env::temp_dir().join(format!(
            "aegis-resp-{nombre}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        DirTemporal(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn el_ciclo_de_cuarentena_es_reversible_bit_a_bit() {
    let d = DirTemporal::nuevo("ciclo");
    let almacen = d.path().join("store");
    let muestra = d.path().join("muestra.bin");

    // Contenido con bytes no imprimibles y no UTF-8: un contenedor que solo
    // funcione con texto no sirve para muestras reales.
    let contenido: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    std::fs::write(&muestra, &contenido).unwrap();
    std::fs::set_permissions(
        &muestra,
        std::os::unix::fs::PermissionsExt::from_mode(0o750),
    )
    .unwrap();

    let q = Quarantine::open(&almacen).expect("abrir almacen");
    let id = q
        .quarantine_file(&muestra, "prueba", "muestra de laboratorio")
        .expect("poner en cuarentena");

    // El original desaparece: dejarlo seria dejar la amenaza en el disco.
    assert!(!muestra.exists(), "el original debe eliminarse");
    assert!(q.container_path(id).exists());

    let meta = q.inspect(id).expect("metadatos legibles");
    assert_eq!(meta.size, 10_000);
    assert_eq!(meta.mode & 0o777, 0o750);
    assert_eq!(meta.reason, "muestra de laboratorio");

    let destino = q.restore(id, None).expect("restaurar");
    let recuperado = std::fs::read(&destino).unwrap();
    assert_eq!(recuperado, contenido, "la restauracion debe ser bit a bit");

    // Los permisos vuelven: restaurar sin ellos destruye la evidencia y a
    // menudo rompe la aplicacion que usaba el fichero.
    let modo = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&destino).unwrap().permissions(),
    );
    assert_eq!(modo & 0o777, 0o750);

    // El contenedor se retira tras restaurar.
    assert!(!q.container_path(id).exists());
}

#[test]
fn un_contenedor_alterado_no_se_descifra() {
    let d = DirTemporal::nuevo("integridad");
    let almacen = d.path().join("store");
    let muestra = d.path().join("m.bin");
    std::fs::write(&muestra, b"contenido original").unwrap();

    let q = Quarantine::open(&almacen).unwrap();
    let id = q.quarantine_file(&muestra, "prueba", "x").unwrap();

    let ruta = q.container_path(id);
    let mut bytes = std::fs::read(&ruta).unwrap();

    // Alterar un byte del texto cifrado.
    let ultimo = bytes.len() - 1;
    bytes[ultimo] ^= 0xFF;
    assert!(
        matches!(
            q.open_container(&bytes).unwrap_err(),
            QuarantineError::IntegrityFailure
        ),
        "un contenido alterado debe fallar la verificacion"
    );

    // Alterar la CABECERA, que va en claro. Sin autenticarla como AAD, esto
    // pasaria desapercibido y permitiria un ataque de sustitucion.
    let mut bytes2 = std::fs::read(&ruta).unwrap();
    bytes2[30] ^= 0xFF; // dentro del nonce
    assert!(matches!(
        q.open_container(&bytes2).unwrap_err(),
        QuarantineError::IntegrityFailure
    ));
}

#[test]
fn otro_almacen_no_puede_descifrar_el_contenedor() {
    let d = DirTemporal::nuevo("claves");
    let muestra = d.path().join("m.bin");
    std::fs::write(&muestra, b"secreto").unwrap();

    let q1 = Quarantine::open(&d.path().join("store1")).unwrap();
    let id = q1.quarantine_file(&muestra, "p", "x").unwrap();
    let bytes = std::fs::read(q1.container_path(id)).unwrap();

    // Almacen distinto = clave maestra distinta.
    let q2 = Quarantine::open(&d.path().join("store2")).unwrap();
    assert!(matches!(
        q2.open_container(&bytes).unwrap_err(),
        QuarantineError::IntegrityFailure
    ));
}

#[test]
fn cada_fichero_usa_una_clave_y_un_nonce_distintos() {
    let d = DirTemporal::nuevo("nonce");
    let almacen = d.path().join("store");
    let q = Quarantine::open(&almacen).unwrap();

    let mut nonces = std::collections::HashSet::new();
    let mut cifrados = std::collections::HashSet::new();

    for i in 0..20 {
        let m = d.path().join(format!("m{i}.bin"));
        // Contenido IDENTICO en todos: si la clave o el nonce se repitieran,
        // el texto cifrado tambien se repetiria, y eso en GCM es catastrofico.
        std::fs::write(&m, b"exactamente el mismo contenido").unwrap();
        let id = q.quarantine_file(&m, "p", "x").unwrap();
        let bytes = std::fs::read(q.container_path(id)).unwrap();
        nonces.insert(bytes[24..36].to_vec());
        cifrados.insert(bytes[48..].to_vec());
    }
    assert_eq!(nonces.len(), 20, "los nonces deben ser todos distintos");
    assert_eq!(
        cifrados.len(),
        20,
        "contenidos identicos deben producir cifrados distintos"
    );
}

#[test]
fn no_se_restaura_encima_de_un_fichero_existente() {
    let d = DirTemporal::nuevo("sobrescritura");
    let almacen = d.path().join("store");
    let muestra = d.path().join("m.bin");
    std::fs::write(&muestra, b"original").unwrap();

    let q = Quarantine::open(&almacen).unwrap();
    let id = q.quarantine_file(&muestra, "p", "x").unwrap();

    // Alguien crea otro fichero en esa ruta mientras tanto.
    std::fs::write(&muestra, b"fichero nuevo e importante").unwrap();

    // Restaurar encima destruiria ese fichero.
    assert!(matches!(
        q.restore(id, None).unwrap_err(),
        QuarantineError::DestinationExists(_)
    ));
    assert_eq!(
        std::fs::read(&muestra).unwrap(),
        b"fichero nuevo e importante"
    );
}

#[test]
fn los_metadatos_sobreviven_a_nombres_hostiles() {
    // Un atacante puede crear ficheros cuyo nombre inyecte lineas falsas en los
    // metadatos si estos se guardaran en texto plano sin codificar.
    let meta = FileMetadata {
        original_path: PathBuf::from("/tmp/mal\nsize=999999\nreason=benigno"),
        size: 42,
        sha256: [7u8; 32],
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        atime_ns: 2,
        quarantined_at_ns: 3,
        engine: "yara".into(),
        reason: "linea1\nsize=0".into(),
    };
    let decodificado = FileMetadata::decode(&meta.encode()).expect("ida y vuelta");
    assert_eq!(decodificado, meta);
    assert_eq!(
        decodificado.size, 42,
        "la inyeccion no debe alterar el tamano"
    );
}

#[test]
fn el_identificador_va_y_vuelve_de_hexadecimal() {
    let id = QuarantineId::generate();
    assert_eq!(QuarantineId::from_hex(&id.to_hex()), Some(id));
    assert_eq!(QuarantineId::from_hex("corto"), None);
    assert_eq!(QuarantineId::from_hex("zz".repeat(16).as_str()), None);
}

// ---------------------------------------------------------------------------
// Aislamiento de red
// ---------------------------------------------------------------------------

#[test]
fn el_conjunto_de_reglas_solo_toca_la_tabla_propia() {
    let reglas = build_ruleset(&IsolationPolicy::containment());
    // Aislar y liberar tiene que devolver el sistema EXACTAMENTE al estado
    // anterior; eso solo se cumple si nunca se toca nada fuera de la tabla.
    for linea in reglas.lines() {
        let l = linea.trim();
        if l.starts_with("table") || l.starts_with("delete table") {
            assert!(l.contains(TABLE), "toca una tabla ajena: {l}");
        }
        assert!(
            !l.starts_with("flush ruleset"),
            "jamas se vacia el ruleset entero"
        );
    }
}

#[test]
fn la_politica_de_contencion_preserva_el_acceso_de_administracion() {
    let p = IsolationPolicy::containment();
    // Aislar un equipo comprometido y perder el acceso para investigarlo es un
    // error clasico y caro.
    assert!(p.leaves_admin_path());
    assert!(
        p.allow_loopback,
        "sin loopback se rompe casi todo el software local"
    );

    let reglas = build_ruleset(&p);
    assert!(reglas.contains("iif lo accept"));
    assert!(reglas.contains("ct state established,related accept"));
    assert!(reglas.contains("udp sport 67 udp dport 68 accept"), "DHCP");
    assert!(reglas.contains("tcp dport 443 accept"), "canal del agente");
}

#[test]
fn el_aislamiento_total_avisa_de_que_no_deja_via_de_entrada() {
    let p = IsolationPolicy::total();
    assert!(!p.leaves_admin_path());
    let reglas = build_ruleset(&p);
    assert!(!reglas.contains("ct state established"));
    assert!(reglas.contains("policy drop"));
}

#[test]
fn las_reglas_se_generan_de_forma_idempotente() {
    let p = IsolationPolicy::containment();
    // El conjunto empieza creando y borrando la tabla, para que aplicarlo dos
    // veces seguidas no falle ni duplique reglas.
    let reglas = build_ruleset(&p);
    assert!(reglas.starts_with(&format!("table inet {TABLE} {{}}")));
    assert!(reglas.contains(&format!("delete table inet {TABLE}")));
    assert_eq!(build_ruleset(&p), reglas, "la generacion es determinista");
}

#[test]
fn se_leen_los_resolutores_de_resolv_conf() {
    let txt =
        "# comentario\nnameserver 8.8.8.8\nsearch local\nnameserver 2001:4860:4860::8888\n;otro\n";
    let r = parse_resolvers(txt);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].to_string(), "8.8.8.8");
    assert_eq!(r[1].to_string(), "2001:4860:4860::8888");
}

#[test]
fn el_modo_de_simulacion_no_toca_el_sistema() {
    // Esta prueba corre en la maquina de CI: si `isolate` no respetara el modo
    // de simulacion, la dejaria sin red a mitad de la suite.
    let sim = Isolator::dry_run();
    let reglas = sim
        .isolate(&IsolationPolicy::containment())
        .expect("la simulacion nunca falla");
    assert!(reglas.contains(TABLE));
    assert!(sim.release().is_ok());
}
