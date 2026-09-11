//! Deteccion de zero-day por comportamiento, de extremo a extremo y sin nube.
//!
//! Sin mocks: se construyen secuencias de syscalls REALES —las que produciria un
//! ransomware, un robo de credenciales, un backup legitimo—, se extraen sus
//! features y el modelo ONNX embebido, cargado con tract, emite el veredicto. Se
//! comprueba lo que un modelo entrenado a ojo NO consigue: separar el ransomware
//! del backup, que escriben lo mismo pero uno cifra-y-borra y el otro no.

use aegis_edgeml::behavior::{CatSyscall, Dag, EventoSyscall, Traza};
use aegis_edgeml::modelo::{ModeloComportamiento, Veredicto};

fn ev(cat: CatSyscall) -> EventoSyscall {
    EventoSyscall::de(cat)
}

fn escritura_cifrada() -> EventoSyscall {
    EventoSyscall {
        cat: CatSyscall::Write,
        entropia: Some(0.98), // datos de alta entropia: cifrado
    }
}

fn escritura_normal() -> EventoSyscall {
    EventoSyscall {
        cat: CatSyscall::Write,
        entropia: Some(0.15), // datos de baja entropia: copia sin cifrar
    }
}

/// Ransomware: por cada fichero, open-read-write(cifrado)-unlink, en rafaga.
fn traza_ransomware() -> Traza {
    let mut eventos = Vec::new();
    for _ in 0..200 {
        eventos.push(ev(CatSyscall::Open));
        eventos.push(ev(CatSyscall::Read));
        eventos.push(escritura_cifrada());
        eventos.push(ev(CatSyscall::GetRandom));
        eventos.push(ev(CatSyscall::Unlink));
    }
    Traza {
        eventos,
        dag: Dag::default(),
        duracion_seg: 0.4,
        ficheros_distintos: 200,
    }
}

/// Robo de credenciales: ptrace + process_vm_readv contra otro proceso.
fn traza_robo_credenciales() -> Traza {
    let mut eventos = Vec::new();
    for _ in 0..20 {
        eventos.push(ev(CatSyscall::Ptrace));
        eventos.push(ev(CatSyscall::ProcVm));
        eventos.push(ev(CatSyscall::Read));
    }
    Traza {
        eventos,
        dag: Dag::default(),
        duracion_seg: 0.2,
        ficheros_distintos: 0,
    }
}

/// Backup legitimo: escribe MUCHO, pero sin cifrar (baja entropia) y sin borrar
/// el original. El falso positivo que un detector solo-de-escritura cometeria.
fn traza_backup() -> Traza {
    let mut eventos = Vec::new();
    for _ in 0..200 {
        eventos.push(ev(CatSyscall::Open));
        eventos.push(ev(CatSyscall::Read));
        eventos.push(escritura_normal());
    }
    Traza {
        eventos,
        dag: Dag::default(),
        duracion_seg: 2.0,
        ficheros_distintos: 200,
    }
}

/// Actividad normal: un editor abre, lee y guarda un fichero.
fn traza_benigna() -> Traza {
    Traza {
        eventos: vec![
            ev(CatSyscall::Open),
            ev(CatSyscall::Read),
            escritura_normal(),
            ev(CatSyscall::Net),
        ],
        dag: Dag::default(),
        duracion_seg: 1.0,
        ficheros_distintos: 1,
    }
}

#[test]
fn el_modelo_embebido_carga_e_infiere() {
    let m = ModeloComportamiento::embebido().expect("el modelo embebido debe cargar");
    let p = m.analizar(&traza_benigna()).unwrap();
    assert!(
        (0.0..=1.0).contains(&p.score),
        "la salida es una probabilidad"
    );
}

#[test]
fn el_ransomware_se_aisla_sin_preguntar_a_la_nube() {
    let m = ModeloComportamiento::embebido().unwrap();
    let p = m.analizar(&traza_ransomware()).unwrap();
    assert_eq!(
        p.veredicto,
        Veredicto::Malicioso,
        "leer-cifrar-borrar en rafaga es ransomware (score {:.3})",
        p.score
    );
}

#[test]
fn el_robo_de_credenciales_se_detecta() {
    let m = ModeloComportamiento::embebido().unwrap();
    let p = m.analizar(&traza_robo_credenciales()).unwrap();
    assert_eq!(
        p.veredicto,
        Veredicto::Malicioso,
        "ptrace + process_vm_readv es robo de credenciales (score {:.3})",
        p.score
    );
}

#[test]
fn el_backup_legitimo_no_se_bloquea() {
    let m = ModeloComportamiento::embebido().unwrap();
    let p = m.analizar(&traza_backup()).unwrap();
    // El backup escribe tanto como el ransomware. Lo que lo salva es que no cifra
    // ni borra: el modelo tiene que verlo.
    assert_ne!(
        p.veredicto,
        Veredicto::Malicioso,
        "un backup legitimo no puede bloquearse (score {:.3})",
        p.score
    );
}

#[test]
fn la_actividad_normal_es_benigna() {
    let m = ModeloComportamiento::embebido().unwrap();
    let p = m.analizar(&traza_benigna()).unwrap();
    assert_eq!(p.veredicto, Veredicto::Benigno, "score {:.3}", p.score);
}

#[test]
fn el_ransomware_puntua_muy_por_encima_del_backup() {
    let m = ModeloComportamiento::embebido().unwrap();
    let ransom = m.analizar(&traza_ransomware()).unwrap().score;
    let backup = m.analizar(&traza_backup()).unwrap().score;
    assert!(
        ransom - backup > 0.45,
        "el modelo debe separar ransomware ({ransom:.3}) de backup ({backup:.3}) \
         por su forma, no por el volumen de escritura"
    );
}
