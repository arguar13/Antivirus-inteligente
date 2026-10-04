//! Las ordenes `--contenido` del agente sobre un almacen y una clave reales
//! (FASE 4.5 del MP-16): instalar, estado, reponer lo viejo, revertir.

use std::path::PathBuf;

use aegis_agent::contenido::{ejecutar_orden, interpretar, Config, Orden};
use aegis_contenido::publicar::preparar;
use aegis_contenido::{
    Anillo, Borrador, ClaveFirmaHibrida, Coste, Destino, Entrada, Historial, Medicion, Modo, Tipo,
    Validadores,
};

const EQUIPO: &str = "maq:prueba-agente";

struct Lab(PathBuf);
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn regla(id: &str) -> Entrada {
    let marcador = format!("AEGIS-AGENTE-CANAL-{id}");
    Entrada {
        id: id.into(),
        tipo: Tipo::Yara,
        modo: Modo::Auditoria,
        activa: true,
        coste: Coste {
            pasos_por_byte: 4,
            micros_por_64k: 20_000,
        },
        medicion: Medicion::default(),
        fuente: format!("rule {id}\n{{\n    strings:\n        $a = \"{marcador}\"\n    condition:\n        $a\n}}\n")
            .into_bytes(),
        dispara: vec![marcador.into_bytes()],
        no_dispara: vec![b"nada que ver".to_vec()],
    }
}

fn paquete(f: &ClaveFirmaHibrida, epoca: u64, id: &str) -> Vec<u8> {
    preparar(
        Borrador {
            canal: "estable".into(),
            entradas: vec![regla(id)],
        },
        Destino {
            epoca,
            generado_ns: 0,
            anillo: Anillo::canario(&[EQUIPO]),
            escalera: Vec::new(),
            revierte_a: 0,
        },
        &Historial::nuevo(),
        &Validadores::por_defecto(),
    )
    .unwrap()
    .firmar(f)
    .unwrap()
}

#[test]
fn las_ordenes_de_contenido_del_agente() {
    let lab =
        Lab(std::env::temp_dir().join(format!("aegis-agente-contenido-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&lab.0);
    std::fs::create_dir_all(&lab.0).unwrap();

    let f = ClaveFirmaHibrida::desde_semillas(&[21; 32], &[22; 32]);
    let clave = lab.0.join("contenido.pub");
    std::fs::write(&clave, f.clave_verificacion().a_bytes()).unwrap();
    let e1 = lab.0.join("e1.aegc");
    let e2 = lab.0.join("e2.aegc");
    std::fs::write(&e1, paquete(&f, 1, "R_Uno")).unwrap();
    std::fs::write(&e2, paquete(&f, 2, "R_Dos")).unwrap();

    let cfg = Config {
        dir: lab.0.join("almacen"),
        clave,
        canal: "estable".into(),
    };
    let ejecutar = |o: Orden| ejecutar_orden(&o, &cfg, EQUIPO);

    assert!(ejecutar(Orden::Estado).is_err(), "sin nada instalado");
    assert!(ejecutar(Orden::Instalar(e1.clone()))
        .unwrap()
        .contains("epoca 1"));
    assert!(ejecutar(Orden::Instalar(e2)).unwrap().contains("epoca 2"));
    // Reponer el viejo: rechazado.
    assert!(ejecutar(Orden::Instalar(e1))
        .unwrap_err()
        .contains("no supera"));
    let estado = ejecutar(Orden::Estado).unwrap();
    assert!(
        estado.contains("epoca=2") && estado.contains("auditoria=1"),
        "{estado}"
    );
    // Rollback local en un comando.
    assert!(ejecutar(Orden::Revertir).unwrap().contains("epoca 1"));
    let estado = ejecutar(Orden::Estado).unwrap();
    assert!(estado.contains("epoca=1 epoca_vista=2"), "{estado}");
    // Otro equipo, fuera del canario: no instala.
    let otro = ejecutar_orden(
        &Orden::Instalar(lab.0.join("e1.aegc")),
        &Config {
            dir: lab.0.join("otro"),
            ..cfg.clone()
        },
        "maq:otro",
    );
    assert!(otro.unwrap_err().contains("anillo"));
}

#[test]
fn la_linea_de_ordenes_es_estricta() {
    let a = |v: &[&str]| interpretar(&v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
    let (o, cfg) = a(&["instalar", "/tmp/p.aegc", "--dir", "/tmp/d"]).unwrap();
    assert_eq!(o, Orden::Instalar("/tmp/p.aegc".into()));
    assert_eq!(cfg.dir, PathBuf::from("/tmp/d"));
    assert!(a(&[]).is_err());
    assert!(a(&["estado", "revertir"]).is_err());
    assert!(a(&["--config", "x"]).is_err());
    assert!(a(&["instalar"]).is_err());
}
