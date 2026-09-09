//! Pruebas del motor conductual.
//!
//! El listón de estas pruebas no es "el codigo hace lo que dice el codigo",
//! sino **que decide bien**: que la cadena de una intrusion real cruza el umbral
//! de aislamiento, que la actividad normal de un servidor no lo cruza, y que
//! ninguna observacion suelta basta para cortar un proceso.

use std::path::PathBuf;

use aegis_behavior::dag::{EdgeKind, GraphError, GraphLimits};
use aegis_behavior::engine::{BehavioralGraphEngine, EngineConfig};
use aegis_behavior::score::{suma_decaida, Action, UMBRAL_AISLAMIENTO};
use aegis_behavior::technique::{Tactic, Technique, CATALOGO};
use aegis_scal::process::{ProcessInfo, ProcessKey, ProcessState};

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

fn proc(pid: u32, ppid: u32, image: &str) -> ProcessInfo {
    ProcessInfo {
        // La marca de arranque se deriva del PID para que dos procesos de la
        // prueba nunca compartan identidad por descuido.
        key: ProcessKey::new(pid, 1_000 + pid as u64),
        parent_pid: ppid,
        image: Some(PathBuf::from(image)),
        cmdline: vec![image.to_string()],
        uid: 33,
        gid: 33,
        threads: 1,
        state: ProcessState::Running,
    }
}

fn motor() -> BehavioralGraphEngine {
    BehavioralGraphEngine::new(EngineConfig::default())
}

/// Monta la cadena canonica de una ejecucion remota de codigo en un servidor
/// web: nginx atiende una peticion, abre un interprete, el interprete se trae
/// una segunda etapa con `curl`, le da permisos con `chmod` y la ejecuta desde
/// `/tmp`.
fn cadena_web_rce(m: &mut BehavioralGraphEngine) -> ProcessKey {
    let nginx = proc(100, 1, "/usr/sbin/nginx");
    let sh = proc(101, 100, "/bin/sh");
    let curl = proc(102, 101, "/usr/bin/curl");
    let chmod = proc(103, 101, "/usr/bin/chmod");
    let carga = proc(104, 101, "/tmp/.update");

    m.track(&nginx, 1);
    m.track(&sh, 2);
    m.track(&curl, 3);
    m.track(&chmod, 4);

    m.observe(sh.key, Technique::CommandInterpreter).unwrap();
    m.observe(curl.key, Technique::IngressToolTransfer).unwrap();
    m.observe(chmod.key, Technique::PermissionsModification)
        .unwrap();

    m.track(&carga, 5);
    carga.key
}

// ---------------------------------------------------------------------------
// Catalogo de tecnicas
// ---------------------------------------------------------------------------

#[test]
fn ninguna_tecnica_suelta_puede_aislar_un_proceso() {
    // Cortar un proceso por UNA observacion es como se saca de produccion algo
    // que funcionaba. La acumulacion y la cadena son las que llevan al umbral.
    for t in CATALOGO {
        assert!(
            t.weight() < UMBRAL_AISLAMIENTO,
            "{t} pesa {} y llegaria sola al umbral",
            t.weight()
        );
        assert!(t.weight() > 0, "{t} con peso cero no aporta nada al motor");
        assert!(!t.id().is_empty() && t.id().starts_with('T'));
        assert!(!t.name().is_empty());
    }
}

#[test]
fn las_tecnicas_ubicuas_pesan_menos_que_las_que_casi_nunca_son_legitimas() {
    // Es la propiedad que evita que el motor escale cada `cron` de la maquina.
    assert!(Technique::CommandInterpreter.weight() < Technique::ProcessInjection.weight());
    assert!(Technique::CommandInterpreter.weight() < Technique::DataEncryptedForImpact.weight());
    assert!(Technique::ApplicationLayerProtocol.weight() < Technique::IndicatorRemoval.weight());
    assert_eq!(Technique::ProcessInjection.id(), "T1055");
    assert_eq!(Technique::CommandInterpreter.id(), "T1059");
    assert_eq!(Technique::DataEncryptedForImpact.id(), "T1486");
    assert_eq!(Technique::DataEncryptedForImpact.tactic(), Tactic::Impact);
    assert_eq!(Tactic::Impact.as_str(), "Impact");
    // Los identificadores no se repiten: dos tecnicas con el mismo T-id serian
    // indistinguibles en cualquier informe.
    let mut ids: Vec<&str> = CATALOGO.iter().map(|t| t.id()).collect();
    ids.sort_unstable();
    let antes = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), antes, "hay identificadores de MITRE repetidos");
}

// ---------------------------------------------------------------------------
// Puntuacion
// ---------------------------------------------------------------------------

#[test]
fn acumular_ruido_no_lleva_al_umbral() {
    // Diez tecnicas ubicuas de peso 10 sumarian 100 a pelo y aislarian un
    // proceso normal. Con decaimiento, la mas grave manda.
    let ruido = suma_decaida(vec![10; 10]);
    assert!(
        ruido < UMBRAL_AISLAMIENTO as f32,
        "diez tecnicas ubicuas dan {ruido} y aislarian un proceso legitimo"
    );
    // Y la mas grave sigue mandando: 60 solo ya es mas que diez dieces.
    assert!(suma_decaida(vec![60]) > suma_decaida(vec![10; 6]));
}

#[test]
fn la_puntuacion_no_depende_del_orden_en_que_llegan_las_observaciones() {
    // Si dependiera, la misma actividad puntuaria distinto segun el momento en
    // que el ring entregara cada evento, y la deteccion seria irreproducible.
    let a = suma_decaida(vec![45, 15, 30]);
    let b = suma_decaida(vec![15, 30, 45]);
    let c = suma_decaida(vec![30, 45, 15]);
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn el_riesgo_se_hereda_atenuado_y_la_inyeccion_atenua_mucho_menos() {
    let mut m = motor();
    let malo = proc(200, 1, "/tmp/dropper");
    let lanzado = proc(201, 200, "/usr/bin/id");
    let inyectado = proc(202, 1, "/usr/bin/gnome-calculator");
    m.track(&malo, 1);
    m.track(&lanzado, 2);
    m.track(&inyectado, 3);

    m.observe(malo.key, Technique::ProcessInjection).unwrap();
    m.observe(malo.key, Technique::IndicatorRemoval).unwrap();
    m.link(malo.key, inyectado.key, EdgeKind::Injected, 4)
        .unwrap();

    let por_linaje = m.assess(lanzado.key).unwrap().score;
    let por_inyeccion = m.assess(inyectado.key).unwrap().score;

    assert_eq!(por_linaje.own, 0, "el hijo no hizo nada por si mismo");
    assert!(por_linaje.inherited > 0, "pero arrastra a quien lo lanzo");
    assert!(
        por_inyeccion.inherited > por_linaje.inherited,
        "inyectar es una relacion mucho mas fuerte que lanzar: {} vs {}",
        por_inyeccion.inherited,
        por_linaje.inherited
    );
}

#[test]
fn una_cadena_larga_de_inocuos_no_escala_por_ser_larga() {
    // Si la herencia se sumara en vez de tomar el maximo, veinte procesos
    // inocentes encadenados acabarian aislandose entre ellos.
    let mut m = motor();
    m.track(&proc(300, 1, "/usr/sbin/sshd"), 1);
    for i in 1..20u32 {
        let p = proc(300 + i, 300 + i - 1, "/usr/bin/env");
        m.track(&p, i as u64 + 1);
    }
    let ultimo = ProcessKey::new(319, 1_000 + 319);
    let s = m.assess(ultimo).unwrap();
    assert_eq!(s.action, Action::Observe, "puntuo {}", s.score.total);
    assert!(s.score.total < 10);
}

// ---------------------------------------------------------------------------
// La cadena que importa
// ---------------------------------------------------------------------------

#[test]
fn la_cadena_de_ejecucion_remota_en_un_servidor_web_se_aisla_sola() {
    let mut m = motor();
    let carga = cadena_web_rce(&mut m);

    let a = m.assess(carga).expect("el nodo esta en el grafo");
    assert!(
        a.score.chains.contains(&"web-rce"),
        "la cadena tiene que reconocerse: {:?}",
        a.score.chains
    );
    assert!(
        a.score.total > UMBRAL_AISLAMIENTO,
        "servidor -> interprete -> descarga -> permisos -> /tmp tiene que aislar, \
         puntuo {} (propia {}, heredada {}, cadena {})",
        a.score.total,
        a.score.own,
        a.score.inherited,
        a.score.chain
    );
    assert_eq!(a.action, Action::Isolate);
    assert_eq!(m.stats().aislamientos, 1);
}

#[test]
fn el_aislamiento_se_decide_una_sola_vez_por_proceso() {
    // Sin deduplicar, el motor de respuesta recibiria la misma orden decenas de
    // veces por segundo mientras el proceso siga generando eventos.
    let mut m = motor();
    let carga = cadena_web_rce(&mut m);
    let repetido = m
        .observe(carga, Technique::ApplicationLayerProtocol)
        .unwrap();
    assert!(
        repetido.is_none(),
        "un proceso ya sentenciado no vuelve a pedir aislamiento"
    );
    assert_eq!(m.stats().aislamientos, 1);
}

#[test]
fn una_alerta_que_luego_se_agrava_vuelve_a_decidir() {
    // Es la trampa de deduplicar por presencia en vez de por nivel: el proceso
    // alerta a 60, se marca como "ya decidido", y cuando despues llega a 92 la
    // escalada a aislamiento se pierde. El proceso seguiria corriendo con una
    // alerta antigua como unica constancia.
    let mut m = motor();
    let p = proc(650, 1, "/usr/bin/tar");
    m.track(&p, 1);

    let primera = m
        .observe(p.key, Technique::DataEncryptedForImpact)
        .unwrap()
        .expect("cifrar ya merece alerta");
    assert_eq!(primera.action, Action::Alert);

    let segunda = m
        .observe(p.key, Technique::IndicatorRemoval)
        .unwrap()
        .expect("agravarse tiene que volver a decidir");
    assert_eq!(segunda.action, Action::Isolate);
    assert_eq!(m.stats().alertas, 1);
    assert_eq!(m.stats().aislamientos, 1);

    // Y a partir de ahi ya no se repite.
    assert!(m
        .observe(p.key, Technique::ProcessDiscovery)
        .unwrap()
        .is_none());
    assert_eq!(m.stats().aislamientos, 1);
}

#[test]
fn la_misma_cadena_sin_el_servidor_expuesto_no_se_aisla_sola() {
    // Un administrador que abre una shell, descarga algo, lo hace ejecutable y
    // lo ejecuta desde /tmp esta haciendo su trabajo. Lo que convierte esa
    // secuencia en un compromiso es que la ORIGINE un servidor expuesto.
    let mut m = motor();
    let sshd = proc(400, 1, "/usr/sbin/sshd");
    let sh = proc(401, 400, "/bin/bash");
    let curl = proc(402, 401, "/usr/bin/curl");
    let chmod = proc(403, 401, "/usr/bin/chmod");
    let bin = proc(404, 401, "/tmp/instalador");
    m.track(&sshd, 1);
    m.track(&sh, 2);
    m.track(&curl, 3);
    m.track(&chmod, 4);
    m.observe(sh.key, Technique::CommandInterpreter).unwrap();
    m.observe(curl.key, Technique::IngressToolTransfer).unwrap();
    m.observe(chmod.key, Technique::PermissionsModification)
        .unwrap();
    m.track(&bin, 5);

    let a = m.assess(bin.key).unwrap();
    assert!(
        !a.score.chains.contains(&"web-rce"),
        "sin servidor expuesto no es la cadena web-rce"
    );
    assert_ne!(a.action, Action::Isolate, "puntuo {}", a.score.total);
}

#[test]
fn un_nodo_intermedio_no_puede_consumir_el_paso_final_de_la_cadena() {
    // Evasion real: si el emparejamiento fuera voraz y sin anclar, bastaria con
    // que un nodo INTERMEDIO cumpliera por casualidad el ultimo paso —aqui, un
    // interprete que ademas vive en /tmp— para que consumiera ese paso y la
    // cadena de verdad dejara de reconocerse. Un atacante puede provocarlo a
    // proposito copiando su shell a /tmp.
    let mut m = motor();
    let nginx = proc(1300, 1, "/usr/sbin/nginx");
    let sh = proc(1301, 1300, "/tmp/sh");
    let curl = proc(1302, 1301, "/usr/bin/curl");
    let chmod = proc(1303, 1301, "/usr/bin/chmod");
    let carga = proc(1304, 1301, "/tmp/.update");
    m.track(&nginx, 1);
    m.track(&sh, 2);
    m.track(&curl, 3);
    m.track(&chmod, 4);
    m.observe(sh.key, Technique::CommandInterpreter).unwrap();
    m.observe(curl.key, Technique::IngressToolTransfer).unwrap();
    m.observe(chmod.key, Technique::PermissionsModification)
        .unwrap();
    m.track(&carga, 5);

    let a = m.assess(carga.key).unwrap();
    assert!(
        a.score.chains.contains(&"web-rce"),
        "mover el interprete a /tmp no puede esconder la cadena: {:?}",
        a.score.chains
    );
    assert_eq!(a.action, Action::Isolate);

    // Y el paso final sigue anclado: el interprete intermedio, valorado por si
    // mismo, no arrastra la cadena entera.
    let del_interprete = m.assess(sh.key).unwrap();
    assert!(
        !del_interprete.score.chains.contains(&"web-rce"),
        "la cadena culmina en la carga, no en el interprete"
    );
}

#[test]
fn la_actividad_normal_de_un_servidor_no_escala() {
    let mut m = motor();
    let sshd = proc(500, 1, "/usr/sbin/sshd");
    let bash = proc(501, 500, "/bin/bash");
    let ls = proc(502, 501, "/usr/bin/ls");
    m.track(&sshd, 1);
    m.track(&bash, 2);
    m.observe(bash.key, Technique::CommandInterpreter).unwrap();
    let alta = m.track(&ls, 3);

    assert!(alta.is_none(), "un `ls` bajo un `bash` no puede escalar");
    assert_eq!(m.assess(ls.key).unwrap().action, Action::Observe);
    assert_eq!(m.stats().aislamientos, 0);
    assert_eq!(m.stats().alertas, 0);
}

#[test]
fn cifrar_y_luego_borrar_rastros_se_reconoce_en_un_solo_proceso() {
    let mut m = motor();
    let p = proc(600, 1, "/usr/bin/tar");
    m.track(&p, 1);
    m.observe(p.key, Technique::DataEncryptedForImpact).unwrap();
    let tras_borrar = m.observe(p.key, Technique::IndicatorRemoval).unwrap();

    let a = tras_borrar.expect("cifrar y borrar rastros tiene que actuar");
    assert!(a.score.chains.contains(&"impacto-y-borrado"));
    assert_eq!(a.action, Action::Isolate, "puntuo {}", a.score.total);
}

#[test]
fn el_modo_observacion_alerta_pero_no_corta() {
    // Es como se despliega el motor la primera semana en produccion: se quiere
    // ver que HABRIA hecho, no que lo haga.
    let mut m = BehavioralGraphEngine::new(EngineConfig {
        autonomous: false,
        ..EngineConfig::default()
    });
    let carga = cadena_web_rce(&mut m);
    let a = m.assess(carga).unwrap();

    assert_eq!(a.action, Action::Alert, "en observacion no se corta");
    // Pero la puntuacion NO se rebaja: esconderla ocultaria que la maquina
    // tiene un proceso que merece aislamiento.
    assert!(a.score.total > UMBRAL_AISLAMIENTO);
    assert_eq!(m.stats().aislamientos, 0);
}

// ---------------------------------------------------------------------------
// Invariantes del grafo
// ---------------------------------------------------------------------------

#[test]
fn dos_procesos_que_se_inyectan_mutuamente_no_cuelgan_el_motor() {
    // Es una tecnica de evasion real. Si el grafo aceptara el ciclo, cualquier
    // recorrido de ancestros dejaria de terminar: una denegacion de servicio
    // contra el propio motor.
    let mut m = motor();
    let a = proc(700, 1, "/tmp/a");
    let b = proc(701, 1, "/tmp/b");
    m.track(&a, 1);
    m.track(&b, 2);

    m.link(a.key, b.key, EdgeKind::Injected, 3).unwrap();
    // La segunda inyeccion, en sentido contrario, cerraria el ciclo.
    m.link(b.key, a.key, EdgeKind::Injected, 4).unwrap();
    assert_eq!(m.stats().ciclos_rechazados, 1);

    // Y el recorrido termina.
    assert!(m.assess(a.key).is_some());
    assert!(m.assess(b.key).is_some());
    assert_eq!(m.graph().causal_path(b.key), vec![a.key, b.key]);
}

#[test]
fn el_grafo_rechaza_las_aristas_imposibles() {
    let mut m = motor();
    let a = proc(800, 1, "/bin/true");
    m.track(&a, 1);
    let fantasma = ProcessKey::new(9999, 1);

    assert_eq!(
        m.link(a.key, a.key, EdgeKind::Injected, 2).unwrap_err(),
        GraphError::SelfEdge(a.key)
    );
    assert_eq!(
        m.link(a.key, fantasma, EdgeKind::Injected, 2).unwrap_err(),
        GraphError::UnknownNode(fantasma)
    );
    assert!(m.observe(fantasma, Technique::ProcessInjection).is_err());
}

#[test]
fn la_misma_arista_observada_dos_veces_no_se_duplica() {
    // La misma inyeccion la pueden ver dos sondas distintas.
    let mut m = motor();
    let a = proc(810, 1, "/tmp/a");
    let b = proc(811, 1, "/tmp/b");
    m.track(&a, 1);
    m.track(&b, 2);
    m.link(a.key, b.key, EdgeKind::Injected, 3).unwrap();
    m.link(a.key, b.key, EdgeKind::Injected, 4).unwrap();
    assert_eq!(m.graph().node(a.key).unwrap().out.len(), 1);
    assert_eq!(m.graph().node(b.key).unwrap().incoming.len(), 1);
}

#[test]
fn un_pid_reciclado_no_hereda_el_historial_del_anterior() {
    let mut m = motor();
    let viejo = proc(900, 1, "/tmp/malo");
    m.track(&viejo, 1);
    m.observe(viejo.key, Technique::DataEncryptedForImpact)
        .unwrap();
    m.on_process(
        &aegis_scal::process::ProcessEvent::Exited {
            key: viejo.key,
            exit_code: None,
        },
        2,
    );

    // Otro proceso reutiliza el numero. Es OTRA identidad.
    let nuevo = ProcessInfo {
        key: ProcessKey::new(900, 999_999),
        ..proc(900, 1, "/usr/bin/ls")
    };
    m.track(&nuevo, 3);

    let s = m.assess(nuevo.key).unwrap().score;
    assert_eq!(s.own, 0, "el proceso nuevo no hizo nada");
    assert!(
        s.techniques.is_empty(),
        "ni heredo las tecnicas del anterior"
    );
    assert_ne!(nuevo.key, viejo.key);
    // El historial del viejo sigue ahi durante la gracia, sin mezclarse.
    assert!(m.graph().node(viejo.key).is_some());
}

#[test]
fn los_nodos_muertos_expiran_y_no_dejan_aristas_colgando() {
    let mut m = BehavioralGraphEngine::new(EngineConfig {
        limits: GraphLimits {
            max_nodes: 1024,
            dead_grace_ns: 1_000,
            max_depth: 64,
        },
        autonomous: true,
    });
    let padre = proc(1000, 1, "/bin/sh");
    let hijo = proc(1001, 1000, "/usr/bin/id");
    m.track(&padre, 1);
    m.track(&hijo, 2);
    assert_eq!(m.graph().node(hijo.key).unwrap().incoming.len(), 1);

    m.on_process(
        &aegis_scal::process::ProcessEvent::Exited {
            key: padre.key,
            exit_code: None,
        },
        10,
    );
    assert_eq!(m.maintain(10 + 2_000), 1, "el padre muerto expira");
    assert!(m.graph().node(padre.key).is_none());
    // Dejar la arista colgando cortaria la cadena en silencio en el siguiente
    // recorrido; el hijo tiene que quedar limpio.
    assert!(
        m.graph().node(hijo.key).unwrap().incoming.is_empty(),
        "no pueden quedar aristas hacia un nodo que ya no existe"
    );
    assert_eq!(m.graph().causal_path(hijo.key), vec![hijo.key]);
}

#[test]
fn la_presion_de_memoria_expulsa_muertos_y_nunca_vivos() {
    // Expulsar vivos dejaria ciego al motor sobre procesos que estan corriendo
    // AHORA, que es lo unico que todavia se puede contener.
    let mut m = BehavioralGraphEngine::new(EngineConfig {
        limits: GraphLimits {
            max_nodes: 4,
            dead_grace_ns: u64::MAX,
            max_depth: 64,
        },
        autonomous: true,
    });
    for i in 0..3u32 {
        let p = proc(1100 + i, 1, "/usr/bin/muerto");
        m.track(&p, i as u64);
        m.on_process(
            &aegis_scal::process::ProcessEvent::Exited {
                key: p.key,
                exit_code: None,
            },
            i as u64 + 1,
        );
    }
    let vivos: Vec<ProcessInfo> = (0..4u32)
        .map(|i| proc(1200 + i, 1, "/usr/bin/vivo"))
        .collect();
    for (i, v) in vivos.iter().enumerate() {
        m.track(v, 100 + i as u64);
    }
    assert_eq!(m.graph().len(), 7);

    m.maintain(200);
    assert_eq!(m.graph().len(), 4, "se recorta hasta el limite");
    for v in &vivos {
        assert!(
            m.graph().node(v.key).is_some(),
            "un proceso vivo no se puede expulsar"
        );
    }
}

#[test]
fn la_profundidad_del_recorrido_esta_acotada() {
    // Un `fork` en cadena de miles de niveles no puede convertir una valoracion
    // en un recorrido de miles de saltos por evento.
    let mut m = BehavioralGraphEngine::new(EngineConfig {
        limits: GraphLimits {
            max_nodes: 100_000,
            dead_grace_ns: u64::MAX,
            max_depth: 8,
        },
        autonomous: true,
    });
    m.track(&proc(2000, 1, "/bin/sh"), 1);
    for i in 1..50u32 {
        m.track(&proc(2000 + i, 2000 + i - 1, "/bin/sh"), i as u64);
    }
    let hondo = ProcessKey::new(2049, 1_000 + 2049);
    assert_eq!(m.graph().causal_path(hondo).len(), 8);
}

#[test]
fn las_estadisticas_cuadran_con_lo_que_paso() {
    let mut m = motor();
    cadena_web_rce(&mut m);
    let s = m.stats();
    assert_eq!(s.nodos_altas, 5);
    assert_eq!(s.observaciones, 3);
    assert_eq!(s.aislamientos, 1);
    assert_eq!(s.ciclos_rechazados, 0);
    assert_eq!(m.graph().len(), 5);
}
