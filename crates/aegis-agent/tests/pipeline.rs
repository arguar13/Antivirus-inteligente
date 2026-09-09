//! Pruebas del pipeline de correlacion.
//!
//! Todas corren sin kernel, sin privilegios y sin BTF: la logica que decide es
//! la parte del agente que mas cobertura necesita, y atarla a un entorno con
//! root significaria en la practica no probarla.

use std::sync::Arc;

use aegis_agent::graph::{classify_image, is_temp_path, ExecEvent, ImageClass};
use aegis_agent::triage::{classify_path, DiscardReason, EscalationReason, PathSensitivity};
use aegis_agent::{
    GraphConfig, Pipeline, ProcKey, ProcessGraph, TaintSet, TelemetryEvent, Verdict,
};

const S: u64 = 1_000_000_000;

fn exec(key: u64, parent: u64, image: &str, ts: u64) -> TelemetryEvent {
    TelemetryEvent::Exec {
        actor: ProcKey(key),
        pid: key as u32,
        parent: ProcKey(parent),
        image: Arc::from(image),
        cmdline: Arc::from(image),
        started_ns: ts,
        ts_ns: ts,
    }
}

fn escritura(actor: u64, path: &str, ts: u64) -> TelemetryEvent {
    TelemetryEvent::FileWrite {
        actor: ProcKey(actor),
        pid: actor as u32,
        path: Arc::from(path),
        flags: 0o1101,
        ts_ns: ts,
    }
}

fn conexion(actor: u64, dport: u16, loopback: bool, private_dst: bool, ts: u64) -> TelemetryEvent {
    TelemetryEvent::NetConnect {
        actor: ProcKey(actor),
        pid: actor as u32,
        daddr: [93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        dport,
        family: 2,
        loopback,
        private_dst,
        ts_ns: ts,
    }
}

// ---------------------------------------------------------------------------
// Clasificacion
// ---------------------------------------------------------------------------

#[test]
fn las_imagenes_se_clasifican_por_familia() {
    assert_eq!(classify_image("/bin/bash"), ImageClass::Shell);
    assert_eq!(classify_image("/usr/bin/python3"), ImageClass::Interpreter);
    // El sufijo de version no debe romper la clasificacion.
    assert_eq!(
        classify_image("/usr/bin/python3.11"),
        ImageClass::Interpreter
    );
    assert_eq!(classify_image("/opt/firefox/firefox"), ImageClass::Browser);
    assert_eq!(
        classify_image("/usr/lib/libreoffice/soffice"),
        ImageClass::Office
    );
    assert_eq!(classify_image("/usr/sbin/sshd"), ImageClass::RemoteAccess);
    assert_eq!(classify_image("/usr/bin/cargo"), ImageClass::BuildSystem);
    assert_eq!(classify_image("/opt/app/mi-servicio"), ImageClass::Other);
}

#[test]
fn las_rutas_se_clasifican_por_sensibilidad() {
    // ld.so.preload debe resolverse ANTES que el prefijo generico /etc/: es la
    // persistencia mas silenciosa que existe en Linux.
    assert_eq!(
        classify_path("/etc/ld.so.preload"),
        PathSensitivity::DynamicLoader
    );
    assert_eq!(classify_path("/etc/shadow"), PathSensitivity::Credentials);
    assert_eq!(
        classify_path("/home/ana/.ssh/authorized_keys"),
        PathSensitivity::Credentials
    );
    assert_eq!(
        classify_path("/etc/cron.d/backup"),
        PathSensitivity::Persistence
    );
    assert_eq!(
        classify_path("/home/ana/.config/autostart/x.desktop"),
        PathSensitivity::Persistence
    );
    assert_eq!(
        classify_path("/home/ana/.bashrc"),
        PathSensitivity::Persistence
    );
    assert_eq!(classify_path("/usr/bin/ls"), PathSensitivity::SystemBinary);
    assert_eq!(classify_path("/proc/self/status"), PathSensitivity::Noise);
    assert_eq!(
        classify_path("/home/ana/notas.txt"),
        PathSensitivity::Normal
    );
}

#[test]
fn las_rutas_temporales_se_reconocen() {
    assert!(is_temp_path("/tmp/carga"));
    assert!(is_temp_path("/dev/shm/x"));
    assert!(!is_temp_path("/usr/bin/ls"));
    // Que la ruta CONTENGA /tmp/ no basta: tiene que empezar por ahi.
    assert!(!is_temp_path("/home/ana/tmp/x"));
}

// ---------------------------------------------------------------------------
// Grafo y herencia de marcas
// ---------------------------------------------------------------------------

#[test]
fn las_marcas_se_heredan_por_toda_la_cadena() {
    let g = ProcessGraph::default();

    g.on_exec(ExecEvent {
        key: ProcKey(1),
        pid: 1,
        parent: ProcKey::NONE,
        creator: ProcKey::NONE,
        image: Arc::from("/usr/lib/libreoffice/soffice"),
        cmdline: Arc::from("soffice doc.odt"),
        started_ns: 0,
    });

    // soffice -> sh -> python -> curl. La marca de origen ofimatico tiene que
    // sobrevivir los tres saltos: esa persistencia es lo que hace util al grafo,
    // porque el atacante cambia el nombre del proceso final trivialmente pero
    // no puede cambiar de donde vino la cadena.
    for (key, parent, img) in [
        (2u64, 1u64, "/bin/sh"),
        (3, 2, "/usr/bin/python3"),
        (4, 3, "/usr/bin/curl"),
    ] {
        g.on_exec(ExecEvent {
            key: ProcKey(key),
            pid: key as u32,
            parent: ProcKey(parent),
            creator: ProcKey(parent),
            image: Arc::from(img),
            cmdline: Arc::from(img),
            started_ns: 0,
        });
    }

    assert!(g.has_taint(ProcKey(4), TaintSet::OFFICE_CHILD));
    assert!(g.has_taint(ProcKey(4), TaintSet::SHELL_CHILD));
    assert!(g.has_taint(ProcKey(4), TaintSet::INTERPRETER_CHILD));

    let ancestros = g.ancestry(ProcKey(4)).expect("cadena valida");
    assert_eq!(ancestros.len(), 3);
    assert_eq!(&*ancestros[0].image, "/usr/bin/python3");
    assert_eq!(&*ancestros[2].image, "/usr/lib/libreoffice/soffice");
}

#[test]
fn la_profundidad_se_acota() {
    let g = ProcessGraph::new(GraphConfig {
        max_depth: 4,
        ..Default::default()
    });
    for i in 1..=10u64 {
        g.on_exec(ExecEvent {
            key: ProcKey(i),
            pid: i as u32,
            parent: ProcKey(i.saturating_sub(1)),
            creator: ProcKey(i.saturating_sub(1)),
            image: Arc::from("/bin/true"),
            cmdline: Arc::from("true"),
            started_ns: 0,
        });
    }
    // Una cadena mas profunda que el limite se corta en vez de recorrerse sin
    // fin: es la defensa contra una bomba de fork anidada.
    assert!(g.ancestry(ProcKey(10)).is_err());
}

#[test]
fn los_nodos_muertos_expiran_pero_no_al_instante() {
    let g = ProcessGraph::new(GraphConfig {
        dead_grace_ns: 10 * S,
        ..Default::default()
    });
    g.on_exec(ExecEvent {
        key: ProcKey(1),
        pid: 1,
        parent: ProcKey::NONE,
        creator: ProcKey::NONE,
        image: Arc::from("/bin/true"),
        cmdline: Arc::from("true"),
        started_ns: 0,
    });
    g.on_exit(ProcKey(1), 100 * S);

    // Dentro de la gracia el nodo sigue disponible: una deteccion puede llegar
    // despues de que el proceso muera, y sin su nodo se pierde el linaje.
    assert_eq!(g.reap(105 * S), 0);
    assert!(g.snapshot(ProcKey(1)).is_some());
    assert!(!g.snapshot(ProcKey(1)).unwrap().alive);

    assert_eq!(g.reap(111 * S), 1);
    assert!(g.snapshot(ProcKey(1)).is_none());
}

#[test]
fn la_presion_de_memoria_expulsa_muertos_antes_de_la_gracia() {
    let g = ProcessGraph::new(GraphConfig {
        max_nodes: 3,
        dead_grace_ns: 10_000 * S,
        ..Default::default()
    });
    for i in 1..=6u64 {
        g.on_exec(ExecEvent {
            key: ProcKey(i),
            pid: i as u32,
            parent: ProcKey::NONE,
            creator: ProcKey::NONE,
            image: Arc::from("/bin/true"),
            cmdline: Arc::from("true"),
            started_ns: 0,
        });
        g.on_exit(ProcKey(i), i * S);
    }
    assert_eq!(g.len(), 6);
    g.reap(7 * S);
    // Perder contexto historico es preferible a que el agente crezca sin limite
    // en un servidor que crea miles de procesos por minuto.
    assert!(
        g.len() <= 3,
        "el grafo debe respetar max_nodes, tiene {}",
        g.len()
    );
}

#[test]
fn los_nodos_vivos_nunca_se_expulsan_por_presion() {
    let g = ProcessGraph::new(GraphConfig {
        max_nodes: 2,
        ..Default::default()
    });
    for i in 1..=5u64 {
        g.on_exec(ExecEvent {
            key: ProcKey(i),
            pid: i as u32,
            parent: ProcKey::NONE,
            creator: ProcKey::NONE,
            image: Arc::from("/bin/true"),
            cmdline: Arc::from("true"),
            started_ns: 0,
        });
    }
    // Ninguno ha muerto: reap no tiene nada que expulsar y debe rendirse en vez
    // de bloquearse buscando candidatos.
    assert_eq!(g.reap(10 * S), 0);
    assert_eq!(g.len(), 5);
}

// ---------------------------------------------------------------------------
// Triaje
// ---------------------------------------------------------------------------

#[test]
fn el_ruido_de_sistemas_de_ficheros_virtuales_se_descarta() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/htop", 0));

    assert!(matches!(
        p.triage
            .classify(&p.graph, &escritura(1, "/proc/1/oom_score_adj", S)),
        Verdict::Discard(DiscardReason::VirtualFilesystem)
    ));
    assert!(matches!(
        p.triage
            .classify(&p.graph, &escritura(1, "/run/user/1000/x", S)),
        Verdict::Discard(DiscardReason::RuntimeState)
    ));
}

#[test]
fn el_ruido_de_compilacion_se_descarta_solo_bajo_un_arbol_de_build() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/cargo", 0));
    p.ingest(exec(2, 1, "/usr/bin/rustc", 0));

    // Bajo cargo, un .o en target/ es ruido.
    assert!(matches!(
        p.triage.classify(
            &p.graph,
            &escritura(2, "/home/ana/proj/target/debug/x.o", S)
        ),
        Verdict::Discard(DiscardReason::BuildArtifact)
    ));

    // El MISMO fichero escrito por un proceso sin ese linaje no es ruido.
    let q = Pipeline::default();
    q.ingest(exec(9, 0, "/tmp/dropper", 0));
    assert!(!matches!(
        q.triage.classify(
            &q.graph,
            &escritura(9, "/home/ana/proj/target/debug/x.o", S)
        ),
        Verdict::Discard(_)
    ));
}

#[test]
fn la_escritura_en_ld_so_preload_escala_con_maxima_prioridad() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/tee", 0));
    let v = p
        .triage
        .classify(&p.graph, &escritura(1, "/etc/ld.so.preload", S));
    match v {
        Verdict::Escalate(e) => assert_eq!(e.reason, EscalationReason::DynamicLoader),
        otro => panic!("se esperaba escalado, no {otro:?}"),
    }
}

#[test]
fn el_gestor_de_paquetes_puede_reescribir_binarios_del_sistema() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/dpkg", 0));
    p.ingest(exec(2, 1, "/usr/bin/install", 0));

    // Sin esta excepcion, cada `apt upgrade` seria un incidente masivo.
    assert!(matches!(
        p.triage
            .classify(&p.graph, &escritura(2, "/usr/bin/curl", S)),
        Verdict::Record
    ));

    // Un proceso cualquiera reescribiendo el mismo binario si escala.
    let q = Pipeline::default();
    q.ingest(exec(5, 0, "/tmp/x", 0));
    match q
        .triage
        .classify(&q.graph, &escritura(5, "/usr/bin/curl", S))
    {
        Verdict::Escalate(e) => assert_eq!(e.reason, EscalationReason::SystemBinary),
        otro => panic!("se esperaba escalado, no {otro:?}"),
    }
}

#[test]
fn la_cadena_ofimatica_a_interprete_escala() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/lib/libreoffice/soffice", 0));

    // La regla no mira el nombre del proceso que ejecuta, que el atacante
    // cambia trivialmente, sino el origen de la cadena.
    let esc = p.ingest(exec(2, 1, "/bin/sh", S));
    let esc = esc.expect("soffice -> sh debe escalar");
    assert_eq!(esc.reason, EscalationReason::LivingOffTheLand);

    // La misma ejecucion sin ese origen es rutina.
    let q = Pipeline::default();
    q.ingest(exec(1, 0, "/usr/bin/make", 0));
    assert!(q.ingest(exec(2, 1, "/bin/sh", S)).is_none());
}

#[test]
fn ptrace_sobre_otro_proceso_escala_siempre() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/gdb", 0));

    let ev = TelemetryEvent::Ptrace {
        actor: ProcKey(1),
        source_pid: 1,
        target_pid: 4242,
        request: 5,
        writes_memory: true,
        ts_ns: S,
    };
    let esc = p.ingest(ev).expect("ptrace entre procesos escala");
    assert_eq!(esc.reason, EscalationReason::CrossProcessMemory);
    // Escribir en la memoria ajena pesa mas que solo leerla.
    assert!(esc.score >= 50, "score fue {}", esc.score);
}

fn ptrace(actor: u64, target_pid: u32, writes: bool, ts: u64) -> TelemetryEvent {
    TelemetryEvent::Ptrace {
        actor: ProcKey(actor),
        source_pid: actor as u32,
        target_pid,
        request: if writes { 5 } else { 2 },
        writes_memory: writes,
        ts_ns: ts,
    }
}

#[test]
fn una_sesion_de_trazado_alerta_una_vez_y_no_una_por_llamada() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/strace", 0));

    // Primer enganche: alerta.
    assert!(
        p.ingest(ptrace(1, 4242, false, S)).is_some(),
        "el primer enganche de A sobre B es el hecho que hay que alertar"
    );

    // Las siguientes 200 llamadas de la MISMA sesion no vuelven a alertar.
    // Un solo strace genero 140 escalados en una prueba real contra el kernel
    // antes de esta deduplicacion, y eso ahoga la alerta util.
    let mut repetidos = 0;
    for i in 0..200u64 {
        if p.ingest(ptrace(1, 4242, false, S + i)).is_some() {
            repetidos += 1;
        }
    }
    assert_eq!(repetidos, 0, "la misma sesion no debe repetir alerta");
    assert_eq!(p.triage.tracked_ptrace_sessions(), 1);
}

#[test]
fn pasar_de_leer_a_escribir_memoria_ajena_vuelve_a_alertar() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/gdb", 0));

    assert!(
        p.ingest(ptrace(1, 99, false, S)).is_some(),
        "primer enganche"
    );
    assert!(
        p.ingest(ptrace(1, 99, false, S + 1)).is_none(),
        "misma sesion"
    );

    // Observar es depurar; escribir es inyectar. El cambio de severidad si
    // merece una alerta nueva dentro de la misma sesion.
    let esc = p
        .ingest(ptrace(1, 99, true, S + 2))
        .expect("la escritura en memoria ajena debe volver a alertar");
    assert_eq!(esc.reason, EscalationReason::CrossProcessMemory);

    // Pero solo una vez.
    assert!(p.ingest(ptrace(1, 99, true, S + 3)).is_none());
}

#[test]
fn un_objetivo_distinto_es_una_sesion_distinta() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/tmp/inyector", 0));
    assert!(p.ingest(ptrace(1, 100, false, S)).is_some());
    assert!(
        p.ingest(ptrace(1, 200, false, S + 1)).is_some(),
        "engancharse a un proceso nuevo es un hecho nuevo"
    );
    assert_eq!(p.triage.tracked_ptrace_sessions(), 2);
}

#[test]
fn las_sesiones_de_trazado_se_olvidan_al_expirar() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/gdb", 0));
    p.ingest(ptrace(1, 77, false, S));
    assert_eq!(p.triage.tracked_ptrace_sessions(), 1);

    // Sin podado, el mapa crece con cada par que haya existido en la vida del
    // agente.
    let (_, olvidadas) = p.maintain(1000 * S);
    assert_eq!(olvidadas, 1);
    assert_eq!(p.triage.tracked_ptrace_sessions(), 0);

    // Pasada la ventana, un reenganche vuelve a ser noticia.
    assert!(p.ingest(ptrace(1, 77, false, 1001 * S)).is_some());
}

#[test]
fn ptrace_sobre_uno_mismo_no_escala() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/strace", 0));
    let ev = TelemetryEvent::Ptrace {
        actor: ProcKey(1),
        source_pid: 1,
        target_pid: 1,
        request: 16,
        writes_memory: false,
        ts_ns: S,
    };
    assert!(p.ingest(ev).is_none());
}

#[test]
fn la_salida_a_internet_escala_solo_si_el_actor_esta_contaminado() {
    // Un navegador hablando por 443 es su trabajo.
    let limpio = Pipeline::default();
    limpio.ingest(exec(1, 0, "/opt/firefox/firefox", 0));
    assert!(limpio.ingest(conexion(1, 443, false, false, S)).is_none());

    // Un descendiente de un documento haciendo lo mismo es C2 o exfiltracion.
    let sucio = Pipeline::default();
    sucio.ingest(exec(1, 0, "/usr/lib/libreoffice/soffice", 0));
    sucio.ingest(exec(2, 1, "/usr/bin/curl", S));
    let esc = sucio
        .ingest(conexion(2, 443, false, false, 2 * S))
        .expect("salida desde linaje ofimatico debe escalar");
    assert_eq!(esc.reason, EscalationReason::TaintedEgress);
}

#[test]
fn el_trafico_local_se_descarta_y_el_privado_solo_se_registra() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/psql", 0));
    assert!(matches!(
        p.triage
            .classify(&p.graph, &conexion(1, 5432, true, false, S)),
        Verdict::Discard(DiscardReason::Loopback)
    ));
    assert!(matches!(
        p.triage
            .classify(&p.graph, &conexion(1, 5432, false, true, S)),
        Verdict::Record
    ));
}

#[test]
fn la_acumulacion_escala_sin_que_ningun_evento_baste_por_si_solo() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/opt/app/agente", 0));

    // Conexiones a puertos fuera del ruido de fondo: ninguna alerta por si
    // sola, pero el acumulado cruza el umbral.
    let mut escalados = 0;
    for i in 0..8u64 {
        if p.ingest(conexion(1, 4444, false, false, i * S / 4))
            .is_some()
        {
            escalados += 1;
        }
    }
    assert!(
        escalados > 0,
        "la acumulacion debe acabar escalando; el proceso que hace muchas cosas \
         levemente raras es justo el que hay que detectar"
    );
}

#[test]
fn la_puntuacion_decae_con_el_tiempo() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/opt/app/agente", 0));

    // Cuatro eventos leves seguidos.
    for i in 0..4u64 {
        p.ingest(conexion(1, 4444, false, false, i * S / 10));
    }
    let alto = p
        .graph
        .with_behavior(ProcKey(1), |b| b.score(S))
        .expect("nodo presente");

    // Diez minutos despues, el mismo estado sin actividad nueva.
    let bajo = p
        .graph
        .with_behavior(ProcKey(1), |b| b.score(600 * S))
        .expect("nodo presente");

    assert!(
        bajo < alto,
        "sin decaimiento un proceso de vida larga acumularia puntuacion \
         indefinidamente por actividad benigna dispersa en horas ({alto} -> {bajo})"
    );
}

// ---------------------------------------------------------------------------
// Contadores
// ---------------------------------------------------------------------------

#[test]
fn los_contadores_del_pipeline_reflejan_los_tres_destinos() {
    let p = Pipeline::default();
    p.ingest(exec(1, 0, "/usr/bin/htop", 0)); // Record
    p.ingest(escritura(1, "/proc/1/stat", S)); // Discard
    p.ingest(escritura(1, "/etc/shadow", 2 * S)); // Escalate

    let s: std::collections::HashMap<_, _> = p.stats.snapshot().into_iter().collect();
    assert_eq!(s["recibidos"], 0, "ingest directo no cuenta como recibido");
    assert_eq!(s["descartados"], 1);
    assert_eq!(s["escalados"], 1);
    assert_eq!(s["registrados"], 1);
}

#[test]
fn un_registro_ilegible_no_interrumpe_el_consumo() {
    let p = Pipeline::default();
    // Bytes que no son un registro del ABI.
    assert!(p.ingest_raw(&[0u8; 16]).is_none());
    assert!(p.ingest_raw(&[0xFF; 512]).is_none());

    let s: std::collections::HashMap<_, _> = p.stats.snapshot().into_iter().collect();
    assert_eq!(s["recibidos"], 2);
    assert_eq!(s["malformados"], 2);
    // Abortar el consumo por un registro malo dejaria de procesar todos los
    // siguientes, que es peor que perder uno.
}
