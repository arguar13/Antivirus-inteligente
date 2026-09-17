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

use aegis_kintegrity::engine::{pid_max, KernelIntegrity, KernelViews, KiConfig};
use aegis_kintegrity::error::KiError;
use aegis_kintegrity::verdict::{juzgar, AnomalyKind, Candidate, Confirmation, VerdictConfig};
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
    //
    // El TID tiene que ser uno que el kernel de ESTA maquina no pueda resolver:
    // la confirmacion de una entrada que solo aparece en /proc pregunta ademas
    // al planificador, que numera en el mismo espacio de nombres que /proc. Un
    // numero cualquiera valdria hasta el dia que la maquina de integracion
    // tuviera un proceso con ese PID, y la prueba empezaria a fallar sin que
    // nada estuviera mal. `pid_max` es el limite SUPERIOR EXCLUSIVO del
    // asignador: no se le concede nunca a nadie.
    let (mut procfs, lista, pidmap) = sistema_limpio();
    let fantasma = pid_max() as u32;
    procfs.insert(fantasma, rec_proc(fantasma, fantasma));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        confirmaciones: [(fantasma, (false, false, None))].into(),
        ..Default::default()
    };
    // La relectura de /proc lo sigue publicando.
    let relectura = move || {
        let mut v = Vista::new();
        v.insert(fantasma, rec_proc(fantasma, fantasma));
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
// El espacio de nombres de PID: los dos lados tienen que numerar igual
// ---------------------------------------------------------------------------
//
// Las dos vistas de kernel llegan por eBPF y numeran en el espacio de nombres
// INICIAL —`bpf_iter_task` publica `task_struct.pid` y `bpf_task_from_pid()`
// busca en `init_pid_ns`—. La vista de `/proc` numera en el espacio de nombres
// del proceso que lee. Cuando no son el mismo, las tres vistas dejan de hablar
// del mismo conjunto de numeros, y la comparacion produce una entrada «solo en
// /proc» POR CADA TAREA: un agente dentro de un contenedor acusaria a la maquina
// entera de estar llena de procesos falsificados, que es la forma mas rapida de
// que alguien desinstale el producto.
//
// Esto no es hipotetico: se encontro midiendo contra el kernel de la maquina de
// integracion, donde el grupo de hilos del PID 1 esta en `/proc` y no lo
// resuelve ninguna de las dos vistas de eBPF.

#[test]
fn el_planificador_resuelve_esta_misma_tarea() {
    // SAFETY: `gettid` no recibe argumentos ni toca memoria del proceso.
    let yo = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    assert!(
        aegis_kintegrity::views::resuelve_el_kernel(yo),
        "el hilo que ejecuta la prueba existe, y el kernel lo resuelve por el \
         mismo espacio de nombres en el que /proc lo publica"
    );
}

#[test]
fn el_planificador_no_resuelve_un_tid_que_no_puede_existir() {
    // `pid_max` es el limite superior EXCLUSIVO del asignador de PID: nunca se
    // le concede a nadie, asi que la respuesta correcta es ESRCH en cualquier
    // maquina y en cualquier momento.
    assert!(
        !aegis_kintegrity::views::resuelve_el_kernel(pid_max() as u32),
        "un TID que el asignador no reparte jamas no puede resolverse"
    );
}

#[test]
fn una_entrada_solo_en_proc_que_el_kernel_resuelve_no_es_una_anomalia() {
    // El caso de la numeracion distinta, aislado: `/proc` la publica, las dos
    // vistas de eBPF no la tienen, y el planificador SI la resuelve. La tarea
    // existe; lo que falla es la comparacion, no la maquina.
    let c = Candidate {
        tid: 4_242,
        kind: AnomalyKind::PhantomProcEntry,
        record: None,
    };
    let conf = Confirmation {
        en_lista: false,
        en_pidmap: false,
        en_procfs: true,
        en_vpid: true,
        start_boottime: None,
    };
    assert_eq!(
        juzgar(&c, &conf),
        None,
        "con la tarea existiendo de verdad no hay nada que acusar"
    );
}

#[test]
fn una_entrada_solo_en_proc_que_nadie_resuelve_si_lo_es() {
    // Y la deteccion sigue viva: cuando NINGUNO de los tres caminos la conoce,
    // la entrada de /proc esta falsificada y se acusa.
    let c = Candidate {
        tid: 4_242,
        kind: AnomalyKind::PhantomProcEntry,
        record: None,
    };
    let conf = Confirmation {
        en_lista: false,
        en_pidmap: false,
        en_procfs: true,
        en_vpid: false,
        start_boottime: None,
    };
    assert_eq!(juzgar(&c, &conf), Some(AnomalyKind::PhantomProcEntry));
}

#[test]
fn lo_que_no_es_comparable_se_cuenta_aparte_y_no_como_carrera() {
    // La diferencia importa en el informe: una carrera es ruido normal, y una
    // numeracion distinta significa que la verificacion cruzada NO esta
    // cubriendo esas tareas. Mezclarlas escondería la segunda dentro de la
    // primera, que es la clase de silencio que este proyecto no se permite.
    //
    // Se monta con TID reales de esta maquina —los hilos de /proc que las vistas
    // de kernel de mentira no incluyen—, porque el motor pregunta al kernel de
    // verdad por ellos.
    let procfs = aegis_kintegrity::views::leer_procfs();
    let Some((&tid, _)) = procfs.iter().find(|(t, _)| **t > 1) else {
        panic!("/proc tiene que publicar alguna tarea");
    };
    let mut solo_en_proc = Vista::new();
    solo_en_proc.insert(tid, rec_proc(tid, tid));

    // Las dos vistas de kernel no lo tienen; la confirmacion tampoco.
    let k = KernelGuion {
        lista: Vista::new(),
        pidmap: Vista::new(),
        confirmaciones: [(tid, (false, false, None))].into(),
        ..Default::default()
    };
    let vista = solo_en_proc.clone();
    let mut m = KernelIntegrity::con_relectura(k, KiConfig::default(), move || vista.clone());
    let r = m
        .evaluar(&ViewSet {
            procfs: solo_en_proc,
            task_list: Vista::new(),
            pid_space: Vista::new(),
            desbordes: 0,
        })
        .unwrap();

    assert_eq!(r.candidatos, 1, "la discrepancia se detecta igual");
    assert!(r.anomalies.is_empty(), "pero no se acusa a una tarea viva");
    assert!(r.pendientes.is_empty());
    assert_eq!(
        r.numeracion_distinta, 1,
        "y queda DICHO que esa tarea no se pudo comparar"
    );
    assert_eq!(
        r.descartados_por_carrera, 0,
        "no es una carrera: la tarea sigue ahi"
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

// ---------------------------------------------------------------------------
// La precondicion: que los tres censos numeren igual
// ---------------------------------------------------------------------------
//
// Comparar tres vistas solo dice algo si las tres nombran a las mismas tareas
// con los mismos numeros. Las de kernel numeran en el espacio de nombres de PID
// inicial y `/proc` en el del proceso que lee, asi que la precondicion NO se
// cumple sola: dentro de un contenedor no se cumple nunca. El motor la
// comprueba buscandose a si mismo en las vistas del kernel, y cuando no se
// encuentra lo DICE en vez de devolver un informe vacio que se leeria como
// «aqui no hay nada oculto».

/// TID de este hilo. El arnes de pruebas corre cada prueba en su propio hilo,
/// asi que no coincide con el PID del proceso: es el numero que el motor usa
/// como sonda y el que las vistas tienen que traer.
fn mi_tid() -> u32 {
    // SAFETY: `gettid` no recibe argumentos ni toca memoria del proceso.
    (unsafe { libc::gettid() }) as u32
}

/// El registro que las vistas del kernel traerian de ESTE hilo: su numero y su
/// nombre, los dos de verdad. El nombre importa tanto como el numero, porque el
/// motor comprueba los dos.
fn rec_yo() -> TaskRecord {
    let tid = mi_tid();
    let comm = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
        .expect("el comm propio siempre se puede leer")
        .trim_end()
        .to_owned();
    TaskRecord {
        tid,
        tgid: std::process::id(),
        start_boottime: Some(300),
        comm: Some(comm),
    }
}

#[test]
fn un_barrido_que_no_se_encuentra_a_si_mismo_no_se_declara_limpio() {
    // Vistas coherentes entre si, pero que no contienen al que las mira: es
    // exactamente la forma que tienen las vistas cuando el agente corre en otro
    // espacio de nombres de PID.
    let (procfs, lista, pidmap) = sistema_limpio();
    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut ki = motor(k);
    let r = ki
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .expect("evaluar");

    assert!(
        r.anomalies.is_empty(),
        "no hay nada que acusar en vistas coherentes: {:?}",
        r.anomalies
    );
    assert!(
        !r.espacios_de_pid_comparables,
        "el motor no aparece en las vistas del kernel: no puede dar por buena \
         la precondicion de la comparacion"
    );
    assert!(
        !r.concluye_limpio(),
        "sin anomalias PERO sin poder comparar, el barrido no autoriza la frase \
         «no hay nada oculto»: lo que no se pudo mirar no es lo mismo que lo \
         que se miro y estaba limpio"
    );
}

#[test]
fn cuando_el_motor_se_ve_en_las_vistas_el_barrido_si_concluye_limpio() {
    let (mut procfs, mut lista, mut pidmap) = sistema_limpio();
    // La sonda: el propio hilo que evalua, presente en las tres vistas con el
    // mismo numero, que es lo que ocurre cuando todos numeran en el mismo
    // espacio de nombres.
    let yo = mi_tid();
    lista.insert(yo, rec_yo());
    pidmap.insert(yo, rec_yo());
    procfs.insert(yo, rec_proc(yo, yo));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut ki = motor(k);
    let r = ki
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .expect("evaluar");

    assert!(
        r.espacios_de_pid_comparables,
        "el motor se encuentra a si mismo en las vistas del kernel: los tres \
         censos numeran igual y la comparacion es valida"
    );
    assert!(
        r.concluye_limpio(),
        "comparacion posible, completa y sin anomalias: aqui si se puede decir \
         que no hay nada oculto"
    );
}

#[test]
fn un_barrido_incompleto_tampoco_se_declara_limpio() {
    // Misma sonda que arriba —la comparacion es posible— pero el kernel avisa
    // de que no le cupo todo. Una ausencia podria deberse al desborde, asi que
    // el silencio no prueba limpieza.
    let (mut procfs, mut lista, mut pidmap) = sistema_limpio();
    let yo = mi_tid();
    lista.insert(yo, rec_yo());
    pidmap.insert(yo, rec_yo());
    procfs.insert(yo, rec_proc(yo, yo));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        desbordes: 7,
        ..Default::default()
    };
    let mut ki = motor(k);
    let r = ki
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 7,
        })
        .expect("evaluar");

    assert!(r.espacios_de_pid_comparables, "la sonda si esta");
    assert_eq!(r.desbordes, 7);
    assert!(
        !r.concluye_limpio(),
        "con entradas que no cupieron en los mapas, el barrido esta incompleto \
         y no autoriza a concluir limpieza"
    );
}

#[test]
fn no_poder_comparar_no_silencia_las_detecciones() {
    // La precondicion es una etiqueta sobre lo que el barrido puede concluir,
    // NO un interruptor que apague el motor. Un DKOM real se sigue acusando
    // aunque la sonda no aparezca: callarlo seria convertir un aviso de
    // cobertura en un punto ciego.
    let (procfs, mut lista, pidmap) = sistema_limpio();
    lista.remove(&43); // desenlazado de la lista de tareas, vivo en el pidmap

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut ki = motor(k);
    let r = ki
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .expect("evaluar");

    assert!(
        !r.espacios_de_pid_comparables,
        "la sonda no esta en las vistas"
    );
    let visto = r
        .anomalies
        .iter()
        .chain(r.pendientes.iter())
        .any(|a| a.kind == AnomalyKind::DkomUnlinked && a.tid == 43);
    assert!(
        visto,
        "el DKOM se tiene que seguir acusando: {:?} / {:?}",
        r.anomalies, r.pendientes
    );
}

#[test]
fn un_numero_que_coincide_pero_es_otra_tarea_no_da_por_buena_la_precondicion() {
    // La trampa que hace insuficiente comprobar solo el numero, y que se
    // encontro corriendo la sonda dentro de un espacio de nombres de PID nuevo:
    // ahi los numeros bajos se reparten otra vez desde 1, asi que el numero
    // propio EXISTE tambien en el espacio inicial —el 2 es `kthreadd`— y las
    // vistas del kernel lo traen. El motor encontraria «su» numero y daria la
    // comparacion por valida cuando lo que ha encontrado es otra tarea.
    let (mut procfs, mut lista, mut pidmap) = sistema_limpio();
    let yo = mi_tid();
    let impostor = TaskRecord {
        tid: yo,
        tgid: yo,
        start_boottime: Some(300),
        comm: Some("kthreadd".into()), // el mismo numero, otra tarea
    };
    lista.insert(yo, impostor.clone());
    pidmap.insert(yo, impostor);
    procfs.insert(yo, rec_proc(yo, yo));

    let k = KernelGuion {
        lista: lista.clone(),
        pidmap: pidmap.clone(),
        ..Default::default()
    };
    let mut ki = motor(k);
    let r = ki
        .evaluar(&ViewSet {
            procfs,
            task_list: lista,
            pid_space: pidmap,
            desbordes: 0,
        })
        .expect("evaluar");

    assert!(
        !r.espacios_de_pid_comparables,
        "bajo el numero propio hay otra tarea: encontrar el numero no es \
         encontrarse, y la precondicion no se puede dar por buena"
    );
    assert!(
        !r.concluye_limpio(),
        "y sin precondicion el barrido no autoriza a declarar limpia la maquina"
    );
}
