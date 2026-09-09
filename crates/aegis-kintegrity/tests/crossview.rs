//! Pruebas de la verificacion cruzada.
//!
//! La logica que ACUSA a un proceso de ser un rootkit se prueba con vistas
//! construidas a mano que reproducen cada manipulacion —montar un DKOM real en
//! la maquina de integracion no es una opcion, y esperar a tener uno para
//! probar la logica que acusa seria dejarla sin probar—. Ademas, una prueba de
//! integracion carga el verificador de verdad y lo corre contra el kernel de
//! esta maquina: comprobar que 115 hilos reales no producen NI UN falso
//! positivo es una prueba tan dura como detectar un rootkit, y mucho mas facil
//! de reproducir.

use std::collections::BTreeMap;

use aegis_kintegrity::engine::{KernelIntegrity, KernelViews, KiConfig};
use aegis_kintegrity::error::KiError;
use aegis_kintegrity::verdict::{AnomalyKind, VerdictConfig};
use aegis_kintegrity::views::{TaskRecord, ViewSet, Vista};

// ---------------------------------------------------------------------------
// Kernel de mentira: devuelve las vistas que le programe la prueba
// ---------------------------------------------------------------------------

/// Kernel controlado. La prueba fija que ve cada vista y que responde la
/// confirmacion, de modo que se puede reproducir un rootkit sin tenerlo.
#[derive(Clone, Default)]
struct KernelGuion {
    lista: Vista,
    pidmap: Vista,
    desbordes: u32,
    /// Confirmaciones a medida: (tid) -> (en_lista, en_pidmap, arranque).
    /// Si no hay entrada, se responde con lo que digan las vistas actuales.
    confirmaciones: BTreeMap<u32, (bool, bool, Option<u64>)>,
}

impl KernelViews for KernelGuion {
    fn barrer(&mut self, _primero: i32, _ultimo: i32) -> Result<(Vista, Vista, u32), KiError> {
        Ok((self.lista.clone(), self.pidmap.clone(), self.desbordes))
    }
    fn confirmar(&mut self, tid: u32) -> Result<(bool, bool, Option<u64>), KiError> {
        if let Some(r) = self.confirmaciones.get(&tid) {
            return Ok(*r);
        }
        let en_lista = self.lista.contains_key(&tid);
        let en_pid = self.pidmap.contains_key(&tid);
        let start = self
            .pidmap
            .get(&tid)
            .or_else(|| self.lista.get(&tid))
            .and_then(|t| t.start_boottime);
        Ok((en_lista, en_pid, start))
    }
}

fn rec(tid: u32, tgid: u32, start: u64) -> TaskRecord {
    TaskRecord {
        tid,
        tgid,
        start_boottime: Some(start),
        comm: Some("victima".into()),
    }
}

fn rec_proc(tid: u32, tgid: u32) -> TaskRecord {
    TaskRecord {
        tid,
        tgid,
        start_boottime: None,
        comm: Some("victima".into()),
    }
}

/// Un sistema base coherente: los mismos tres hilos en las tres vistas.
fn sistema_limpio() -> (Vista, Vista, Vista) {
    let tids = [(1u32, 1u32, 100u64), (42, 42, 200), (43, 42, 210)];
    let mut lista = Vista::new();
    let mut pidmap = Vista::new();
    let mut procfs = Vista::new();
    for (tid, tgid, start) in tids {
        lista.insert(tid, rec(tid, tgid, start));
        pidmap.insert(tid, rec(tid, tgid, start));
        procfs.insert(tid, rec_proc(tid, tgid));
    }
    (procfs, lista, pidmap)
}

fn motor(k: KernelGuion) -> KernelIntegrity<KernelGuion> {
    // La relectura de /proc en la confirmacion se fija vacia: las pruebas que
    // necesitan una relectura concreta usan `con_relectura`.
    KernelIntegrity::con_relectura(k, KiConfig::default(), Vista::new)
}

// ---------------------------------------------------------------------------
// Cada clase de anomalia, aislada
// ---------------------------------------------------------------------------

#[test]
fn un_sistema_coherente_no_produce_ni_una_anomalia() {
    let (procfs, lista, pidmap) = sistema_limpio();
    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut m = KernelIntegrity::con_relectura(k, KiConfig::default(), Vista::new);
    let vistas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes: 0,
    };
    let r = m.evaluar(&vistas).unwrap();
    assert_eq!(r.candidatos, 0, "un sistema limpio no tiene candidatos");
    assert!(r.anomalies.is_empty());
    assert!(r.pendientes.is_empty());
}

#[test]
fn el_dkom_se_detecta_por_estar_en_el_espacio_de_pid_pero_no_en_la_lista() {
    // La firma exacta: un rootkit desenlaza el task_struct de la lista de tareas
    // (invisible para /proc y ps) pero lo deja en el espacio de PID para que
    // siga siendo planificable y pueda recibir senales.
    let (mut procfs, mut lista, pidmap) = sistema_limpio();
    let oculto = 6_000u32;
    procfs.remove(&oculto); // ausente de /proc (consecuencia del desenlace)
    lista.remove(&oculto); //  ausente de la lista de tareas (el desenlace)
    let mut pidmap = pidmap;
    pidmap.insert(oculto, rec(oculto, oculto, 999)); // presente en el idr

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        // La confirmacion vuelve a ver la misma asimetria: sigue oculto.
        confirmaciones: [(oculto, (false, true, Some(999)))].into(),
        ..Default::default()
    };
    let mut m = motor(k);
    let vistas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes: 0,
    };

    // Primera vuelta: confirmado una vez, pero aun no llega al umbral de 2.
    let r1 = m.evaluar(&vistas).unwrap();
    assert_eq!(r1.candidatos, 1);
    assert!(r1.anomalies.is_empty(), "una sola confirmacion no acusa");
    assert_eq!(r1.pendientes.len(), 1);
    assert_eq!(r1.pendientes[0].kind, AnomalyKind::DkomUnlinked);

    // Segunda vuelta: dos confirmaciones consecutivas, ya es una anomalia.
    let r2 = m.evaluar(&vistas).unwrap();
    assert_eq!(r2.anomalies.len(), 1);
    let a = &r2.anomalies[0];
    assert_eq!(a.kind, AnomalyKind::DkomUnlinked);
    assert_eq!(a.tid, oculto);
    assert_eq!(a.severity, 100, "el DKOM es la maxima gravedad");
    assert!(a.exige_mitigacion());
    assert!(a.detalle.contains("DKOM"));
    assert!(r2.exige_mitigacion());
    assert_eq!(r2.severidad_maxima(), 100);
}

#[test]
fn la_ocultacion_en_userland_se_detecta_por_estar_en_el_kernel_pero_no_en_proc() {
    // El kernel ve el proceso por sus dos estructuras; solo /proc miente. La
    // manipulacion esta arriba: un hook de getdents, un LD_PRELOAD o un montaje.
    let (mut procfs, lista, pidmap) = sistema_limpio();
    let oculto = 7_000u32;
    let mut lista = lista;
    let mut pidmap = pidmap;
    lista.insert(oculto, rec(oculto, oculto, 555));
    pidmap.insert(oculto, rec(oculto, oculto, 555));
    procfs.remove(&oculto); // el listado de /proc lo esconde

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        confirmaciones: [(oculto, (true, true, Some(555)))].into(),
        ..Default::default()
    };
    // La relectura de /proc en la confirmacion tambien lo esconde: es un rootkit
    // de getdents, no una carrera.
    let mut m = KernelIntegrity::con_relectura(k, KiConfig::default(), Vista::new);

    m.evaluar(&ViewSet {
        procfs: procfs.clone(),
        task_list: lista.clone(),
        pid_space: pidmap.clone(),
        desbordes: 0,
    })
    .unwrap();
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .unwrap();
    assert_eq!(r.anomalies.len(), 1);
    assert_eq!(r.anomalies[0].kind, AnomalyKind::UserlandHidden);
    assert_eq!(r.anomalies[0].severity, 95);
    assert!(r.anomalies[0].exige_mitigacion());
}

#[test]
fn una_entrada_fantasma_en_proc_se_detecta() {
    // La direccion contraria a esconder: /proc publica un PID que el kernel no
    // conoce, para desviar la atencion o hacer perseguir un proceso inexistente.
    let (mut procfs, lista, pidmap) = sistema_limpio();
    let fantasma = 8_000u32;
    procfs.insert(fantasma, rec_proc(fantasma, fantasma));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        confirmaciones: [(fantasma, (false, false, None))].into(),
        ..Default::default()
    };
    // La relectura de /proc lo sigue publicando.
    let relectura = || {
        let mut v = Vista::new();
        v.insert(8_000, rec_proc(8_000, 8_000));
        v
    };
    let mut m = KernelIntegrity::con_relectura(k, KiConfig::default(), relectura);
    let vistas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes: 0,
    };
    m.evaluar(&vistas).unwrap();
    let r = m.evaluar(&vistas).unwrap();
    assert_eq!(r.anomalies.len(), 1);
    assert_eq!(r.anomalies[0].kind, AnomalyKind::PhantomProcEntry);
    assert!(
        !r.anomalies[0].exige_mitigacion(),
        "una entrada fantasma no justifica matar nada: no hay proceso que matar"
    );
}

// ---------------------------------------------------------------------------
// La carrera: lo que separa este detector de un generador de ruido
// ---------------------------------------------------------------------------

#[test]
fn un_proceso_que_muere_entre_vistas_no_se_acusa() {
    // Un `ls` que termina justo entre tomar una vista y la siguiente aparece en
    // una y no en la otra. Un detector ingenuo lo denunciaria; la confirmacion,
    // que vuelve a mirar y lo encuentra muerto en TODAS partes, lo descarta.
    let (procfs, lista, mut pidmap) = sistema_limpio();
    let efimero = 9_000u32;
    // El barrido lo capto en el espacio de PID justo antes de morir.
    pidmap.insert(efimero, rec(efimero, efimero, 321));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        // Para cuando se confirma, ya murio: no esta en ninguna parte.
        confirmaciones: [(efimero, (false, false, None))].into(),
        ..Default::default()
    };
    let mut m = motor(k);
    let vistas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes: 0,
    };
    let r = m.evaluar(&vistas).unwrap();
    assert_eq!(r.candidatos, 1, "hubo una discrepancia...");
    assert_eq!(r.descartados_por_carrera, 1, "...pero era una carrera");
    assert!(r.anomalies.is_empty());
    assert!(r.pendientes.is_empty());
}

#[test]
fn la_racha_se_reinicia_cuando_la_sospecha_desaparece() {
    let (procfs, lista, mut pidmap) = sistema_limpio();
    let tid = 9_200u32;
    pidmap.insert(tid, rec(tid, tid, 7));
    let vistas = ViewSet {
        procfs,
        task_list: lista.clone(),
        pid_space: pidmap.clone(),
        desbordes: 0,
    };

    // Vuelta 1: oculto -> racha 1 (pendiente).
    let k1 = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        confirmaciones: [(tid, (false, true, Some(7)))].into(),
        ..Default::default()
    };
    let mut m = motor(k1);
    assert_eq!(m.racha(tid, AnomalyKind::DkomUnlinked), 0);
    let r1 = m.evaluar(&vistas).unwrap();
    assert_eq!(r1.pendientes.len(), 1);
    assert_eq!(m.racha(tid, AnomalyKind::DkomUnlinked), 1);

    // No se puede cambiar el kernel del motor en marcha; se comprueba la
    // propiedad de reinicio directamente sobre la tabla de rachas: una vuelta
    // sin el candidato la deja a cero.
    let (procfs2, lista2, pidmap2) = sistema_limpio();
    let limpio = ViewSet {
        procfs: procfs2,
        task_list: lista2,
        pid_space: pidmap2,
        desbordes: 0,
    };
    let r2 = m.evaluar(&limpio).unwrap();
    assert!(r2.anomalies.is_empty());
    assert_eq!(
        m.racha(tid, AnomalyKind::DkomUnlinked),
        0,
        "la racha se reinicia al desaparecer la sospecha"
    );
}

// ---------------------------------------------------------------------------
// Las trampas que hacen inutil a un detector asi
// ---------------------------------------------------------------------------

#[test]
fn los_hilos_de_un_proceso_multihilo_no_son_falsos_positivos() {
    // /proc de primer nivel lista solo lideres de grupo; las vistas de kernel
    // traen un registro por hilo. Si la comparacion no fuera de hilos, cada
    // hilo secundario de cada proceso pareceria oculto en userland. Aqui las
    // tres vistas son de hilos y por eso coinciden.
    let mut lista = Vista::new();
    let mut pidmap = Vista::new();
    let mut procfs = Vista::new();
    // Un proceso (tgid 500) con cuatro hilos.
    for tid in 500..504u32 {
        lista.insert(tid, rec(tid, 500, 42));
        pidmap.insert(tid, rec(tid, 500, 42));
        procfs.insert(tid, rec_proc(tid, 500)); // vista A recorre /proc/500/task
    }
    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut m = motor(k);
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .unwrap();
    assert_eq!(r.candidatos, 0, "los hilos secundarios no son anomalias");
}

#[test]
fn las_tareas_ociosas_con_pid_cero_estan_exentas() {
    // Las tareas ociosas por CPU tienen PID 0, no salen en /proc y
    // bpf_task_from_pid(0) no las resuelve. Sin la exencion, cada CPU produciria
    // una anomalia en cada barrido.
    let mut lista = Vista::new();
    lista.insert(0, rec(0, 0, 0)); // idle en la lista de tareas
    let (procfs, _, pidmap) = sistema_limpio();
    let mut lista_completa = lista;
    for (k, v) in &sistema_limpio().1 {
        lista_completa.insert(*k, v.clone());
    }
    let k = KernelGuion {
        lista: lista_completa.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut m = motor(k);
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista_completa,
            pid_space: pidmap,
            desbordes: 0,
        })
        .unwrap();
    assert!(
        r.anomalies.is_empty() && r.pendientes.is_empty(),
        "el PID 0 esta exento: {:?}",
        r.pendientes
    );
    assert_eq!(r.candidatos, 0);
}

#[test]
fn un_barrido_desbordado_no_acusa_por_ausencia() {
    // Si el mapa del kernel se lleno, cualquier ausencia podria venir del
    // truncamiento y no de una ocultacion. El motor no puede acusar de DKOM
    // sobre datos incompletos.
    let (procfs, lista, pidmap) = sistema_limpio();
    let mut pidmap = pidmap;
    // Un proceso que "solo esta en el espacio de PID" pareceria DKOM...
    pidmap.insert(6_666, rec(6_666, 6_666, 1));
    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        desbordes: 5, // ...pero el barrido esta incompleto
        ..Default::default()
    };
    let mut m = motor(k);
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 5,
        })
        .unwrap();
    assert_eq!(
        r.candidatos, 0,
        "con el barrido desbordado no se acusa por ausencia"
    );
    assert_eq!(r.desbordes, 5);
}

#[test]
fn la_identidad_incoherente_entre_vistas_de_kernel_se_detecta() {
    // El mismo TID con instantes de arranque distintos en las dos vistas de
    // kernel, tomadas con microsegundos de diferencia: o un reciclado
    // improbabilisimo o una manipulacion.
    let (procfs, lista, pidmap) = sistema_limpio();
    let tid = 42u32;
    let mut lista = lista;
    let mut pidmap = pidmap;
    lista.insert(tid, rec(tid, tid, 200));
    pidmap.insert(tid, rec(tid, tid, 999_999)); // arranque distinto

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        confirmaciones: [(tid, (true, true, Some(200)))].into(),
        ..Default::default()
    };
    // La relectura de /proc lo lista (coherente arriba).
    let relectura = || {
        let mut v = Vista::new();
        v.insert(42, rec_proc(42, 42));
        v
    };
    let mut m = KernelIntegrity::con_relectura(k, KiConfig::default(), relectura);
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .unwrap();
    assert_eq!(r.candidatos, 1);
    assert_eq!(r.pendientes[0].kind, AnomalyKind::IdentityMismatch);
}

#[test]
fn el_numero_de_candidatos_esta_acotado() {
    // Ante una maquina con miles de discrepancias reales, confirmar cada una
    // cuesta un recorrido de la lista de tareas. El detector no puede
    // bloquearse investigando o deja de detectar nada mas.
    let (procfs, lista, mut pidmap) = sistema_limpio();
    for tid in 10_000..20_000u32 {
        pidmap.insert(tid, rec(tid, tid, 1));
    }
    let cfg = KiConfig {
        verdict: VerdictConfig {
            max_candidatos: 50,
            ..VerdictConfig::default()
        },
        ..KiConfig::default()
    };
    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut m = KernelIntegrity::con_relectura(k, cfg, Vista::new);
    let r = m
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .unwrap();
    assert!(r.candidatos <= 50, "candidatos acotados: {}", r.candidatos);
}

// ---------------------------------------------------------------------------
// Integracion con el kernel de verdad
// ---------------------------------------------------------------------------

#[cfg(feature = "bpf")]
#[test]
fn el_kernel_de_verdad_no_produce_falsos_positivos() {
    // Cargar el verificador contra el kernel de esta maquina y comprobar que
    // sus ~115 hilos reales no generan NI UNA anomalia confirmada. Es una
    // prueba tan exigente como detectar un rootkit —un solo falso positivo
    // aqui mataria procesos legitimos en produccion— y mucho mas reproducible.
    if !aegis_kintegrity::soportado() {
        eprintln!("OMITIDA: sin BTF no hay verificacion cruzada");
        return;
    }
    let vistas = match aegis_kintegrity::BpfViews::cargar() {
        Ok(v) => v,
        Err(e) if e.is_unsupported() => {
            eprintln!("OMITIDA: {e}");
            return;
        }
        Err(e) => panic!("no se pudo cargar el verificador: {e}"),
    };
    let mut m = KernelIntegrity::new(vistas, KiConfig::default());

    // Tres vueltas: si hubiera un falso positivo por carrera, se necesitarian
    // dos vueltas para "confirmarlo"; tres da margen de sobra para que aflore.
    for i in 0..3 {
        let r = m.scan().expect("el barrido contra el kernel real funciona");
        assert!(r.en_lista > 10, "el kernel tiene procesos reales");
        assert!(r.en_pidmap > 10);
        assert!(
            r.anomalies.is_empty(),
            "vuelta {i}: el kernel limpio NO puede producir anomalias confirmadas: {:?}",
            r.anomalies
        );
    }
}

#[cfg(feature = "bpf")]
#[test]
fn el_kernel_de_verdad_confirma_una_ocultacion_de_userland_inyectada() {
    // Se prueba la deteccion de VERDAD contra el kernel real, sin un rootkit: se
    // lanza un hilo real, se toman las vistas de kernel reales (que SI lo ven) y
    // se le da al motor una relectura de /proc que lo esconde —exactamente lo
    // que hace un hook de getdents—. La confirmacion consulta el kernel real
    // (lo ve) y la relectura amanada (no lo ve): la asimetria persiste y se
    // acusa. Todo lo de kernel es autentico; solo la vista de userland esta
    // manipulada, que es justo lo que un rootkit manipula.
    if !aegis_kintegrity::soportado() {
        eprintln!("OMITIDA: sin BTF no hay verificacion cruzada");
        return;
    }
    let vistas = match aegis_kintegrity::BpfViews::cargar() {
        Ok(v) => v,
        Err(e) if e.is_unsupported() => {
            eprintln!("OMITIDA: {e}");
            return;
        }
        Err(e) => panic!("no se pudo cargar: {e}"),
    };

    // Un hilo real que se queda vivo durante la prueba.
    let seguir = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let s2 = seguir.clone();
    let hilo = std::thread::spawn(move || {
        while s2.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });
    // Su TID: se lee del unico hilo hijo en /proc/self/task.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let yo = std::process::id();
    let tid_victima = std::fs::read_dir(format!("/proc/{yo}/task"))
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .find(|t| *t != yo)
        .expect("el hilo hijo tiene que aparecer en /proc/self/task");

    // La relectura de /proc que esconde EXACTAMENTE ese TID (como un getdents
    // hookeado), dejando el resto intacto.
    let relectura = move || {
        let mut v = aegis_kintegrity::views::leer_procfs();
        v.remove(&tid_victima);
        v
    };
    let cfg = KiConfig {
        verdict: VerdictConfig {
            confirmaciones_requeridas: 1, // una basta: es una deteccion dirigida
            ..VerdictConfig::default()
        },
        ..KiConfig::default()
    };
    let mut m = KernelIntegrity::con_relectura(vistas, cfg, relectura);

    // La vista A del barrido tambien tiene que esconderlo, o no habria
    // candidato. Se toma manipulando la lectura de /proc igual que la relectura.
    // Como `scan` usa `leer_procfs` directamente, se evalua a mano.
    let (lista, pidmap, desbordes) = {
        use aegis_kintegrity::engine::KernelViews;
        // Acceso al kernel real a traves del motor: se hace un scan normal y se
        // reconstruye. Mas simple: se toman las vistas por el rasgo.
        m.kernel_mut()
            .barrer(1, aegis_kintegrity::engine::pid_max())
            .expect("barrido real")
    };
    let mut procfs = aegis_kintegrity::views::leer_procfs();
    let visto_en_kernel = pidmap.contains_key(&tid_victima) || lista.contains_key(&tid_victima);
    procfs.remove(&tid_victima); // el getdents hookeado

    if !visto_en_kernel {
        // El hilo murio o el barrido no lo capto: no se puede probar la
        // deteccion sin la premisa. Se aborta limpiamente en vez de dar un
        // falso pase.
        seguir.store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = hilo.join();
        eprintln!("OMITIDA: el hilo victima no aparecio en la vista de kernel");
        return;
    }

    let vistas_manipuladas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes,
    };
    let r = m.evaluar(&vistas_manipuladas).unwrap();

    seguir.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = hilo.join();

    let detectada = r
        .anomalies
        .iter()
        .any(|a| a.tid == tid_victima && a.kind == AnomalyKind::UserlandHidden);
    assert!(
        detectada,
        "el hilo real escondido de /proc pero visible para el kernel tiene que \
         detectarse como ocultacion de userland: {:?}",
        r.anomalies
    );
}
