//! La medida de cobertura de extremo a extremo: se ejecuta el catalogo, se mide
//! contra el arbitro real, y se comprueba que el informe es honesto, reproducible
//! y que no queda residuo.

use std::collections::{BTreeSet, HashMap};

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};
use aegis_rango::catalogo::catalogo_completo;
use aegis_rango::cobertura::{medir_cobertura, Estado, FuenteSenales};
use aegis_rango::rango::{ConfirmacionRango, Plataforma, Rango};

const AHORA: u64 = 1_700_000_000_000_000_000;

/// Una fuente de señales que refleja QUE motores entregan señal al arbitro hoy.
///
/// No decide nada: reproduce lo que un detector cableado observaria. Los motores
/// que hoy detectan pero no entregan señal —el conductual y el forense de memoria,
/// segun el inventario— no estan en `cableados`, y por eso sus tecnicas saldran
/// como hueco. Eso es la medida honesta, no un fallo de la prueba.
struct FuenteDelProducto {
    por_entidad: HashMap<Eid, Motor>,
    cableados: BTreeSet<Motor>,
}

impl FuenteSenales for FuenteDelProducto {
    fn senales(&self, entidad: &Eid, _rango: &Rango) -> Vec<Senal> {
        match self.por_entidad.get(entidad) {
            Some(motor) if self.cableados.contains(motor) => vec![Senal::nueva(
                *motor,
                entidad.clone(),
                Juicio::Malicioso,
                Severidad::Alta,
                Confianza::ALTA,
                "el detector cableado observo la emulacion",
                AHORA,
            )],
            // Motor no cableado, o entidad desconocida: sin señal. El arbitro dira
            // SinDatos, y el rango lo contara como hueco de cobertura.
            _ => Vec::new(),
        }
    }
}

fn rango_de_prueba(nombre: &str) -> Rango {
    let raiz = std::env::temp_dir().join(format!("aegis-rango-{}-{}", nombre, std::process::id()));
    // Se limpia por si una ejecucion anterior dejo algo.
    let _ = std::fs::remove_dir_all(&raiz);
    Rango::declarar(
        Plataforma::actual(),
        raiz,
        ConfirmacionRango::nueva("ci", "medida de cobertura de deteccion"),
    )
    .expect("declarar rango")
}

fn fuente(rango: &Rango) -> FuenteDelProducto {
    // Los motores que HOY entregan señal al arbitro. El conductual, el forense de
    // memoria, el syscallguard y el modelo del endpoint no estan: son los huecos
    // que el rango revela.
    let cableados: BTreeSet<Motor> = [
        Motor::Estatico,
        Motor::Detonate,
        Motor::Wire,
        Motor::Ips,
        Motor::L7Hunter,
        Motor::Itdr,
        Motor::FirmwareAudit,
        Motor::Intel,
        Motor::Enjambre,
    ]
    .into_iter()
    .collect();

    let mut por_entidad = HashMap::new();
    for t in catalogo_completo() {
        por_entidad.insert(t.entidad_afectada(rango), t.deteccion_esperada());
    }
    FuenteDelProducto {
        por_entidad,
        cableados,
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
fn las_tecnicas_de_un_motor_cableado_se_detectan_y_las_de_uno_no_cableado_son_hueco() {
    let rango = rango_de_prueba("huecos");
    let cat = catalogo_completo();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");

    let estado_de = |id: &str| {
        inf.resultados
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.estado.clone())
    };

    // Kerberoasting lo firma el ITDR, que si esta cableado: detectada.
    assert!(
        matches!(estado_de("T1558"), Some(Estado::Detectado { .. })),
        "T1558 (ITDR, cableado) deberia detectarse"
    );
    // La ofuscacion la firma el estatico, cableado: detectada.
    assert!(matches!(estado_de("T1027"), Some(Estado::Detectado { .. })));
    // La inyeccion en memoria la firma memhunter, que hoy NO entrega señal: hueco.
    assert!(
        matches!(estado_de("T1055"), Some(Estado::NoDetectado)),
        "T1055 (memhunter, no cableado) tiene que salir como hueco, no como detectada"
    );
    // El interprete de comandos lo firma el conductual, hoy sin cablear: hueco.
    assert!(matches!(estado_de("T1059"), Some(Estado::NoDetectado)));

    // Y el informe nombra los huecos, para que se cierre el cableado.
    let huecos = inf.nombres_de_huecos();
    assert!(huecos.iter().any(|(id, _)| id == "T1055"));
    assert!(huecos.iter().any(|(id, _)| id == "T1059"));
}

#[test]
fn una_no_aplicable_nunca_cuenta_como_detectada() {
    let rango = rango_de_prueba("noaplica");
    let cat = catalogo_completo();
    let inf = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir");

    // T1490 (inhibir la recuperacion) es solo Windows. En Linux/macOS es
    // NoAplicable, y jamas Detectado.
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

    // La cobertura se mide sobre lo aplicable: detectadas + huecos, sin contar las
    // no aplicables.
    let cob = inf.cobertura().expect("hay tecnicas aplicables");
    assert!((0.0..=1.0).contains(&cob));
    assert_eq!(
        inf.detectadas() + inf.huecos() + inf.no_aplicables(),
        cat.len()
    );
}

#[test]
fn la_cifra_de_cobertura_es_reproducible_entre_ejecuciones() {
    // Mismo rango, mismo catalogo, misma fuente: el informe de estados tiene que
    // ser identico, o no se puede comparar con el de ayer.
    let rango = rango_de_prueba("reproducible");
    let cat = catalogo_completo();
    let a = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir a");
    let b = medir_cobertura(&rango, &cat, &fuente(&rango), AHORA).expect("medir b");
    // Se comparan los estados tecnica a tecnica (la latencia puede variar, pero el
    // ESTADO no).
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
    // INVARIANTE DE LA FASE: una emulacion que deja una puerta abierta es un
    // incidente. Tras medir el catalogo entero, no queda ni un marcador.
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
