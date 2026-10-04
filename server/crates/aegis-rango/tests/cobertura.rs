//! La medida de cobertura de extremo a extremo, contra la FUENTE DE VERDAD del
//! agente (Hallazgo 0 de la FASE 4 del MP-16).
//!
//! # Que cambio, y por que era una mentira
//!
//! Antes esta prueba tenia una lista `cableados` ESCRITA A MANO —Detonate, Wire,
//! Ips, L7Hunter, Itdr, FirmwareAudit, Intel, Enjambre— que nadie contrastaba con
//! el agente. Era falsa en los dos sentidos: daba por cableados motores que el
//! arbitro no registra y por hueco el conductual, que si lo esta desde la FASE 1.
//! La cifra de cobertura salia de esa tabla, no del producto.
//!
//! Ahora las firmas que el arbitro PODRIA emitir se leen de
//! `docs/generado/motores.txt`, que genera el propio agente (`aegis-agent
//! --motores`) y que una puerta de make ci mantiene al dia
//! (`registro::el_fichero_generado_esta_al_dia`, en el agente). Esto NO ejecuta
//! ataques: mide la cobertura que PERMITIRIAN los motores registrados. La medida
//! real, con ataques y telemetria, la da la prueba de matriz `rango-en-vivo`.

use std::collections::{BTreeSet, HashMap};

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};
use aegis_rango::catalogo::catalogo_completo;
use aegis_rango::cobertura::{medir_cobertura, Estado, FuenteSenales};
use aegis_rango::rango::{ConfirmacionRango, Plataforma, Rango};

const AHORA: u64 = 1_700_000_000_000_000_000;

/// La fuente de verdad, relativa al manifiesto del crate: repo/docs/generado.
const MOTORES_TXT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../docs/generado/motores.txt"
);

/// Las firmas que el arbitro del agente podria emitir hoy, leidas del fichero que
/// genera el propio agente. Si el fichero falta o esta vacio, FALLA: sin fuente de
/// verdad no hay medida honesta, y fingir una era justo el Hallazgo 0.
fn firmas_registrables() -> BTreeSet<Motor> {
    let texto = std::fs::read_to_string(MOTORES_TXT).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer la fuente de verdad {MOTORES_TXT}: {e}. \
             Regenerala: cargo run -p aegis-agent --features bpf -- --motores > docs/generado/motores.txt"
        )
    });
    let mut firmas = BTreeSet::new();
    for l in texto.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // nombre <TAB> firma <TAB> camino <TAB> requisitos
        let firma_nombre = l.split('\t').nth(1).unwrap_or_default();
        let motor = Motor::todos()
            .iter()
            .copied()
            .find(|m| m.nombre() == firma_nombre)
            .unwrap_or_else(|| panic!("firma desconocida en motores.txt: «{firma_nombre}»"));
        firmas.insert(motor);
    }
    assert!(
        !firmas.is_empty(),
        "la fuente de verdad no declara ningun motor"
    );
    firmas
}

/// Una fuente de señales que reproduce lo que un motor REGISTRADO observaria.
///
/// No decide nada: la decision detectada/hueco la toma el arbitro real sobre lo
/// que esta fuente entrega. Solo emite señal para la entidad de una tecnica cuando
/// su motor esperado esta entre las firmas registrables del agente. Que un motor
/// esperado no este registrado es lo que el rango revela como hueco, y es la
/// medida honesta, no un fallo de la prueba.
struct FuenteDelProducto {
    por_entidad: HashMap<Eid, Motor>,
    registrables: BTreeSet<Motor>,
}

impl FuenteSenales for FuenteDelProducto {
    fn senales(&self, entidad: &Eid, _rango: &Rango) -> Vec<Senal> {
        match self.por_entidad.get(entidad) {
            Some(motor) if self.registrables.contains(motor) => vec![Senal::nueva(
                *motor,
                entidad.clone(),
                Juicio::Malicioso,
                Severidad::Alta,
                Confianza::ALTA,
                "un motor registrado observaria la emulacion",
                AHORA,
            )],
            _ => Vec::new(),
        }
    }
}

fn rango_de_prueba(nombre: &str) -> Rango {
    let raiz = std::env::temp_dir().join(format!("aegis-rango-{}-{}", nombre, std::process::id()));
    let _ = std::fs::remove_dir_all(&raiz);
    Rango::declarar(
        Plataforma::actual(),
        raiz,
        ConfirmacionRango::nueva("ci", "medida de cobertura de deteccion"),
    )
    .expect("declarar rango")
}

fn fuente(rango: &Rango) -> FuenteDelProducto {
    let registrables = firmas_registrables();
    let mut por_entidad = HashMap::new();
    for t in catalogo_completo() {
        por_entidad.insert(t.entidad_afectada(rango), t.deteccion_esperada());
    }
    FuenteDelProducto {
        por_entidad,
        registrables,
    }
}

#[test]
fn cada_tecnica_recibe_un_estado_y_ninguna_se_pierde() {
    let rango = rango_de_prueba("estados");
    let cat = catalogo_completo();
    let n = cat.len();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");
    assert_eq!(inf.resultados.len(), n, "una tecnica se quedo sin medir");
}

#[test]
fn el_estado_de_cada_tecnica_sale_de_la_fuente_de_verdad_y_no_de_una_lista() {
    // La correccion del Hallazgo 0: una tecnica se detecta EXACTAMENTE cuando su
    // motor esperado esta entre las firmas registrables del agente. Se comprueba
    // que el estado que da el rango coincide con lo que dice la fuente de verdad,
    // aplicable por aplicable.
    let rango = rango_de_prueba("verdad");
    let cat = catalogo_completo();
    let registrables = firmas_registrables();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");
    let plataforma = rango.plataforma();
    for t in &cat {
        if !t.aplica_en(plataforma) {
            continue;
        }
        let r = inf.resultados.iter().find(|r| r.id == t.id()).unwrap();
        let deberia = registrables.contains(&t.deteccion_esperada());
        assert_eq!(
            r.estado.detectado(),
            deberia,
            "«{}»: esperado {} (motor {:?}), y el rango dijo {:?}",
            t.id(),
            if deberia { "detectada" } else { "hueco" },
            t.deteccion_esperada(),
            r.estado
        );
    }
}

#[test]
fn el_conductual_se_detecta_y_los_motores_de_red_salen_como_hueco() {
    // El error concreto que este cambio arregla: el conductual esta registrado
    // (T1059), y Wire/Ips/etc. no (T1071, T1190). La lista vieja lo tenia al reves.
    let rango = rango_de_prueba("conductual");
    let cat = catalogo_completo();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");
    let estado_de = |id: &str| {
        inf.resultados
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.estado.clone())
    };

    if Plataforma::actual() == Plataforma::Linux {
        assert!(
            matches!(estado_de("T1059"), Some(Estado::Detectado { .. })),
            "T1059 (conductual, REGISTRADO desde FASE 1) tiene que detectarse"
        );
    }
    assert!(
        matches!(estado_de("T1071"), Some(Estado::NoDetectado)),
        "T1071 (wire, no registrado) tiene que salir como hueco"
    );
    let huecos = inf.nombres_de_huecos();
    assert!(huecos.iter().any(|(id, _)| id == "T1071"));
}

#[test]
fn una_no_aplicable_nunca_cuenta_como_detectada() {
    let rango = rango_de_prueba("noaplica");
    let cat = catalogo_completo();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");

    if Plataforma::actual() != Plataforma::Windows {
        let r = inf.resultados.iter().find(|r| r.id == "T1490").unwrap();
        assert!(
            matches!(r.estado, Estado::NoAplicable { .. }),
            "T1490 no aplica fuera de Windows"
        );
        assert!(
            !r.estado.detectado(),
            "una no aplicable no puede ser detectada"
        );
    }

    let cob = inf.cobertura().expect("hay tecnicas aplicables");
    assert!((0.0..=1.0).contains(&cob));
    assert_eq!(
        inf.detectadas() + inf.huecos() + inf.no_aplicables(),
        cat.len()
    );
}

#[test]
fn la_cifra_de_cobertura_es_reproducible_entre_ejecuciones() {
    let rango = rango_de_prueba("reproducible");
    let cat = catalogo_completo();
    let a = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir a");
    let b = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir b");
    let estados = |inf: &aegis_rango::InformeCobertura| -> Vec<(String, bool, bool)> {
        inf.resultados
            .iter()
            .map(|r| (r.id.clone(), r.estado.detectado(), r.estado.es_hueco()))
            .collect()
    };
    assert_eq!(estados(&a), estados(&b));
    assert_eq!(a.detectadas(), b.detectadas());
    assert_eq!(a.huecos(), b.huecos());
}

#[test]
fn tras_medir_no_queda_ningun_residuo_en_el_rango() {
    let rango = rango_de_prueba("residuo");
    let cat = catalogo_completo();
    let _ = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");
    let restos: Vec<_> = std::fs::read_dir(rango.raiz())
        .expect("leer jaula")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("marcador_"))
        .collect();
    assert!(
        restos.is_empty(),
        "quedaron {} marcador(es) tras revertir: {:?}",
        restos.len(),
        restos
            .iter()
            .map(std::fs::DirEntry::file_name)
            .collect::<Vec<_>>()
    );
}
