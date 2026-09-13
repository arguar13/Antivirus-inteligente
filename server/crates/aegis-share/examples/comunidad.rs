//! Una comunidad de inteligencia real, con las cinco propiedades comprobadas.
//!
//! Lo que una prueba unitaria no puede enseñar, porque lo que falla es la
//! COMBINACION de las piezas:
//!
//! 1. Ida y vuelta STIX 2.1 **sin perder nada**, incluido lo que este nodo no
//!    entiende.
//! 2. Un indicador no compartible **no sale por ningun camino** — y se intenta de
//!    verdad por los cuatro: TAXII, federacion, enjambre y exportacion.
//! 3. Un ciclo de federacion A→B→C→A **no produce un bucle**, y una
//!    **actualizacion si circula**.
//! 4. Un canal envenenado **se revierte por procedencia**, dejando en pie lo que
//!    sostenian los demas.
//! 5. **Entrada hostil**: ningun paquete preparado provoca panico ni consumo sin
//!    acotar.
//!
//! Si alguna se rompe, el proceso termina con codigo distinto de cero y
//! `tools/verificar-share.sh` falla.

use std::collections::BTreeSet;

use aegis_share::difusion::{Canal, Destino, Difusor, Retenido};
use aegis_share::federacion::{Descarte, EnTransito, Instancia, Par};
use aegis_share::marcado::{Marcado, Tlp};
use aegis_share::procedencia::{Aporte, Fiabilidad, Registro};
use aegis_share::puente::Puente;
use aegis_share::stix::{ns_a_rfc3339, Objeto, Paquete};
use aegis_share::taxii::{Cliente, Coleccion, Peticion, Servidor};
use aegis_share::taxonomia::{Galaxia, Grupo, Vocabulario};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;
/// Origen de tiempos: 2025-01-13T08:00:00Z.
const T0: u64 = 1_736_755_200 * SEG;

fn main() {
    println!("AegisShare · una comunidad de inteligencia, con las cinco propiedades");
    println!();

    let mut fallos = 0;
    fallos += fase_stix();
    fallos += fase_difusion();
    fallos += fase_federacion();
    fallos += fase_procedencia();
    fallos += fase_hostil();
    fallos += fase_taxonomia();

    println!();
    if fallos == 0 {
        println!("las propiedades se sostienen sobre la comunidad completa");
    } else {
        println!("{fallos} propiedad(es) rotas");
        std::process::exit(1);
    }
}

fn exigir(ok: bool, texto: &str) -> usize {
    if ok {
        println!("      ok   {texto}");
        0
    } else {
        println!("      ROTO {texto}");
        1
    }
}

/// Construye un indicador STIX con el marcado dado.
fn doc_indicador(uuid: &str, patron: &str, etiquetas: &[&str], extra: &str) -> String {
    let et: Vec<String> = etiquetas.iter().map(|e| format!("\"{e}\"")).collect();
    format!(
        r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{uuid}",
        "created":"{}","modified":"{}",
        "pattern":"{patron}","pattern_type":"stix","valid_from":"{}",
        "labels":[{}],"confidence":80{extra}}}"#,
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        et.join(",")
    )
}

fn uuid(n: u32) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}

fn paquete(objetos: &[String]) -> String {
    format!(
        r#"{{"type":"bundle","id":"bundle--{}","objects":[{}]}}"#,
        uuid(0),
        objetos.join(",")
    )
}

// ─── 1 · STIX ─────────────────────────────────────────────────────────────────

fn fase_stix() -> usize {
    println!("  [1/6] STIX 2.1: validacion estricta e ida y vuelta");
    let mut fallos = 0;

    let doc = format!(
        r#"{{"type":"bundle","id":"bundle--{}","objects":[
        {{"type":"malware","spec_version":"2.1","id":"malware--{}",
         "created":"{}","modified":"{}","name":"LockBit","is_family":true,
         "malware_types":["ransomware"],"labels":["TLP:GREEN","PAP:GREEN"],
         "x_comunidad":{{"anidado":[1,2,3],"mas":{{"hondo":true}}}}}},
        {},
        {{"type":"relationship","spec_version":"2.1","id":"relationship--{}",
         "created":"{}","modified":"{}","relationship_type":"indicates",
         "source_ref":"indicator--{}","target_ref":"malware--{}"}},
        {{"type":"x-cosa-que-no-conocemos","spec_version":"2.1",
         "id":"x-cosa-que-no-conocemos--{}","created":"{}","modified":"{}",
         "campo_raro":"que otra instancia si entiende"}}]}}"#,
        uuid(0),
        uuid(1),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        doc_indicador(
            &uuid(2),
            "[file:hashes.'SHA-256' = '7f1e3c9b']",
            &["TLP:GREEN", "PAP:GREEN"],
            ""
        ),
        uuid(3),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        uuid(2),
        uuid(1),
        uuid(4),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
    );

    let uno = match Paquete::validar(&doc) {
        Ok(p) => p,
        Err(e) => {
            println!("      ROTO el paquete de ejemplo no valida: {}", e.texto());
            return 1;
        }
    };
    println!("      {} objetos validados", uno.objetos.len());
    for o in uno.objetos.values() {
        println!("        {:<26} {:<22} {}", o.tipo.nombre(), o.id, o.marcado);
    }

    let dos = Paquete::validar(&uno.a_json()).expect("la vuelta tambien vale");
    fallos += exigir(uno == dos, "la ida y vuelta no pierde absolutamente nada");
    fallos += exigir(
        dos.objetos[&format!("x-cosa-que-no-conocemos--{}", uuid(4))]
            .crudo
            .contains_key("campo_raro"),
        "incluido un tipo que este nodo NO conoce: descartarlo nos haria un agujero en la \
         federacion",
    );
    fallos += exigir(
        dos.objetos[&format!("malware--{}", uuid(1))]
            .crudo
            .get("x_comunidad")
            .is_some(),
        "y una extension anidada que este nodo no interpreta",
    );

    // Las tres comprobaciones que casi nadie hace.
    let confusion = paquete(&[format!(
        r#"{{"type":"indicator","spec_version":"2.1","id":"malware--{}",
        "created":"{}","modified":"{}","pattern":"[x = 1]","pattern_type":"stix",
        "valid_from":"{}"}}"#,
        uuid(9),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0)
    )]);
    fallos += exigir(
        Paquete::validar(&confusion).is_err(),
        "un objeto que dice ser «indicator» con identificador de «malware» se rechaza",
    );

    let sin_marcado = paquete(&[format!(
        r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{}",
        "created":"{}","modified":"{}","pattern":"[x = 1]","pattern_type":"stix",
        "valid_from":"{}","labels":["TLP:CLEAR","PAP:CLEAR"],
        "object_marking_refs":["marking-definition--{}"]}}"#,
        uuid(10),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        ns_a_rfc3339(T0),
        uuid(99)
    )]);
    let p = Paquete::validar(&sin_marcado).expect("el documento es valido");
    let o = p.objetos.values().next().expect("hay uno");
    println!(
        "      un objeto TLP:CLEAR con referencia de marcado que no resuelve -> {}",
        o.marcado
    );
    fallos += exigir(
        o.marcado == Marcado::desconocido(),
        "una referencia de marcado que no resuelve RESTRINGE mas, no menos: es la fuga silenciosa \
         mas comun de estos sistemas",
    );
    println!();
    fallos
}

// ─── 2 · Difusion ─────────────────────────────────────────────────────────────

fn difusor_completo() -> Difusor {
    let mut d = Difusor::nuevo();
    d.declarar(Destino {
        nombre: "comunidad".into(),
        canal: Canal::Taxii,
        tope_tlp: Tlp::Green,
        es_propia_organizacion: false,
    });
    d.declarar(Destino {
        nombre: "socio".into(),
        canal: Canal::Federacion,
        tope_tlp: Tlp::Red,
        es_propia_organizacion: false,
    });
    d.declarar(Destino {
        nombre: "matriz".into(),
        canal: Canal::Federacion,
        tope_tlp: Tlp::Red,
        es_propia_organizacion: true,
    });
    d.declarar(Destino {
        nombre: "flota".into(),
        canal: Canal::Enjambre,
        tope_tlp: Tlp::Red,
        es_propia_organizacion: true,
    });
    d.declarar(Destino {
        nombre: "fichero".into(),
        canal: Canal::Exportacion,
        tope_tlp: Tlp::Red,
        es_propia_organizacion: true,
    });
    d
}

fn fase_difusion() -> usize {
    println!("  [2/6] un indicador no compartible no sale por NINGUN camino");
    let mut fallos = 0;

    let doc = paquete(&[
        doc_indicador(
            &uuid(20),
            "[domain-name:value = 'a.example']",
            &["TLP:CLEAR", "PAP:CLEAR"],
            "",
        ),
        doc_indicador(
            &uuid(21),
            "[domain-name:value = 'b.example']",
            &["TLP:GREEN", "PAP:CLEAR"],
            "",
        ),
        doc_indicador(
            &uuid(22),
            "[domain-name:value = 'c2.example']",
            &["TLP:GREEN", "PAP:RED"],
            "",
        ),
        doc_indicador(
            &uuid(23),
            "[domain-name:value = 'd.example']",
            &["TLP:AMBER+STRICT", "PAP:CLEAR"],
            "",
        ),
        doc_indicador(
            &uuid(24),
            "[domain-name:value = 'secreto.example']",
            &["TLP:RED", "PAP:RED"],
            "",
        ),
    ]);
    let p = Paquete::validar(&doc).expect("valido");
    let d = difusor_completo();

    println!(
        "      {:<12} {:<32} motivos de retencion",
        "destino", "salen"
    );
    for (nombre, r) in d.repartir_a_todos(&p) {
        let motivos: Vec<String> = r
            .por_motivo()
            .iter()
            .map(|(k, v)| format!("{k}×{v}"))
            .collect();
        println!(
            "      {nombre:<12} {:<32} {}",
            format!("{} de {}", r.salen.len(), p.objetos.len()),
            motivos.join(", ")
        );
    }

    // LA PROPIEDAD. El TLP:RED no sale por ninguno de los cuatro canales.
    let secreto = format!("indicator--{}", uuid(24));
    let mut salio_por: Vec<String> = Vec::new();
    let mut motivos: BTreeSet<&'static str> = BTreeSet::new();
    for (nombre, r) in d.repartir_a_todos(&p) {
        if r.salen.contains(&secreto) {
            salio_por.push(nombre);
        }
        if let Some((_, m)) = r.retenidos.iter().find(|(id, _)| id == &secreto) {
            motivos.insert(m.nombre());
        }
    }
    fallos += exigir(
        salio_por.is_empty(),
        &format!("el TLP:RED no salio por ninguno de los 5 destinos (salio por: {salio_por:?})"),
    );
    fallos += exigir(
        motivos == BTreeSet::from(["no-distribuible"]),
        "y lo retiene lo mismo en los cinco: no la configuracion de cada destino, sino que TLP:RED \
         no se distribuye — la propiedad es cierta POR CONSTRUCCION",
    );

    // Y la cobertura: todos los canales del enumerado tienen destino en la prueba.
    let cubiertos: BTreeSet<Canal> = d.destinos().iter().map(|x| x.canal).collect();
    fallos += exigir(
        Canal::todos().iter().all(|c| cubiertos.contains(c)),
        &format!(
            "los {} canales del enumerado estan cubiertos: un camino nuevo no puede quedarse sin \
             probar",
            Canal::todos().len()
        ),
    );

    // El enjambre, con sus dos topes que no se pueden subir.
    let flota = d.repartir(&p, "flota").expect("declarado");
    let por_pap = flota
        .retenidos
        .iter()
        .filter(|(_, m)| matches!(m, Retenido::PorPap { .. }))
        .count();
    let por_duro = flota
        .retenidos
        .iter()
        .filter(|(_, m)| matches!(m, Retenido::PorTopeDuroDelCanal { .. }))
        .count();
    fallos += exigir(
        por_duro == 1,
        "el TLP:AMBER+STRICT no viaja por la malla aunque el destino se configure al maximo: el \
         enjambre llega a maquinas que el atacante puede haber comprometido",
    );
    fallos += exigir(
        por_pap == 1,
        "y el PAP:RED tampoco: lo que cruza acaba en el motor de bloqueo de cien mil endpoints",
    );

    // La otra mitad del contrato: lo publico SI sale por todos.
    let publico = format!("indicator--{}", uuid(20));
    fallos += exigir(
        d.repartir_a_todos(&p)
            .values()
            .all(|r| r.salen.contains(&publico)),
        "y lo publico sale por los cinco: si no saliera nada, la propiedad seria trivial",
    );
    println!();
    fallos
}

// ─── 3 · Federacion ───────────────────────────────────────────────────────────

fn fase_federacion() -> usize {
    println!("  [3/6] federacion: un ciclo no es un bucle, y una correccion si circula");
    let mut fallos = 0;

    let par = |n: &str| Par {
        nombre: n.into(),
        fiabilidad: Fiabilidad::Comunidad,
        acepta_reemitido: true,
    };
    let mut a = Instancia::nueva("A");
    let mut b = Instancia::nueva("B");
    let mut c = Instancia::nueva("C");
    a.declarar_par(par("C"));
    b.declarar_par(par("A"));
    c.declarar_par(par("B"));

    let doc = paquete(&[doc_indicador(
        &uuid(30),
        "[domain-name:value = 'campana.example']",
        &["TLP:GREEN", "PAP:CLEAR"],
        "",
    )]);
    let p = Paquete::validar(&doc).expect("valido");
    let objeto = p.objetos.values().next().expect("hay uno").clone();
    let id = objeto.id.clone();
    a.anadir_propio(objeto);

    let mut reg = Registro::nuevo();
    let mut vueltas = 0usize;
    let mut mensajes = 0usize;

    // Se hace circular hasta que la comunidad deja de tener nada que decirse. Si el
    // ciclo produjera un bucle, esto no terminaria — de ahi el tope, que ademas
    // sirve para detectar el fallo en vez de colgarse.
    for _ in 0..50 {
        let mut movido = false;
        for (origen, destino) in [("A", "B"), ("B", "C"), ("C", "A")] {
            let lote: Vec<EnTransito> = match origen {
                "A" => a.a_enviar(destino),
                "B" => b.a_enviar(destino),
                _ => c.a_enviar(destino),
            };
            if lote.is_empty() {
                continue;
            }
            mensajes += lote.len();
            movido = true;
            let abs = match destino {
                "B" => b.absorber(lote, origen, &mut reg, T0),
                "C" => c.absorber(lote, origen, &mut reg, T0),
                _ => a.absorber(lote, origen, &mut reg, T0),
            };
            let _ = abs;
        }
        vueltas += 1;
        if !movido {
            break;
        }
    }
    println!("      la comunidad se estabilizo en {vueltas} vuelta(s), {mensajes} mensaje(s)");
    fallos += exigir(
        vueltas < 10,
        "un ciclo A->B->C->A no produce un bucle infinito",
    );
    fallos += exigir(
        a.cuantos() == 1 && b.cuantos() == 1 && c.cuantos() == 1,
        "y las tres instancias acaban con el mismo objeto, una sola vez",
    );

    // Se fuerza la vuelta completa: C se lo devuelve a A.
    let forzado = vec![EnTransito {
        objeto: a.objeto(&id).expect("esta").clone(),
        camino: vec!["A".into(), "B".into(), "C".into()],
    }];
    let abs = a.absorber(forzado, "C", &mut reg, T0);
    fallos += exigir(
        matches!(abs.descartados[0].1, Descarte::CicloDetectado { .. }),
        "y forzando la vuelta, el vector de camino la corta donde tiene que cortarla",
    );
    fallos += exigir(
        abs.mala_conducta().is_empty(),
        "sin acusar a nadie: un ciclo es topologia, no mala conducta",
    );

    // LA OTRA MITAD. Una correccion SI circula, que es lo que rompe la defensa
    // evidente de «ya he visto ese identificador».
    let mut corregido = a.objeto(&id).expect("esta").clone();
    corregido.revocado = true;
    corregido.modificado_ns = T0 + 3600 * SEG;
    a.anadir_propio(corregido);

    let de_a = a.a_enviar("B");
    b.absorber(de_a, "A", &mut reg, T0);
    let de_b = b.a_enviar("C");
    c.absorber(de_b, "B", &mut reg, T0);

    fallos += exigir(
        c.objeto(&id).map(|o| o.revocado) == Some(true),
        "una correccion —«esto era un falso positivo, lo retiro»— llega hasta el ultimo nodo",
    );

    // Un par mintiendo sobre su identidad.
    let mentira = vec![EnTransito {
        objeto: a.objeto(&id).expect("esta").clone(),
        camino: vec!["Z".into()],
    }];
    let abs = b.absorber(mentira, "A", &mut reg, T0);
    fallos += exigir(
        abs.mala_conducta().len() == 1,
        "un par que miente sobre el ultimo salto SI se reporta como mala conducta",
    );
    println!();
    fallos
}

// ─── 4 · Procedencia ──────────────────────────────────────────────────────────

fn fase_procedencia() -> usize {
    println!("  [4/6] un canal envenenado se revierte por procedencia");
    let mut fallos = 0;

    let mut reg = Registro::nuevo();
    let aporte = |f: &str, fiab: Fiabilidad, cadena: &[&str]| Aporte {
        fuente: f.into(),
        fiabilidad: fiab,
        cadena: cadena.iter().map(|s| (*s).to_string()).collect(),
        cuando_ns: T0,
        confianza_declarada: 85,
        id_en_origen: "x".into(),
    };

    // Tres semanas de trabajo: lo bueno, lo del canal envenenado, y lo que
    // sostienen los dos.
    for i in 0..200 {
        reg.anotar(
            &format!("bueno-{i}"),
            aporte("socio", Fiabilidad::Acordada, &[]),
        );
    }
    for i in 0..412 {
        reg.anotar(
            &format!("veneno-{i}"),
            aporte("canal-x", Fiabilidad::Abierta, &[]),
        );
    }
    for i in 0..37 {
        let id = format!("ambos-{i}");
        reg.anotar(&id, aporte("socio", Fiabilidad::Acordada, &[]));
        reg.anotar(&id, aporte("canal-x", Fiabilidad::Abierta, &[]));
    }
    // Y lo que llego por OTRO canal pero con el envenenado como raiz: el caso que
    // se escapa si solo se mira quien lo entrego.
    for i in 0..18 {
        reg.anotar(
            &format!("reemitido-{i}"),
            aporte("canal-y", Fiabilidad::Comunidad, &["canal-x"]),
        );
    }
    let antes = reg.cuantos();
    println!("      la base tiene {antes} objetos");
    for (f, n) in reg.por_fuente(T0) {
        println!("        aportados por {f:<10} {n:>5}");
    }
    for (f, n) in reg.dependencia_unica(T0) {
        println!("        dependen SOLO de {f:<10} {n:>5}");
    }

    // Se mira lo que se va a tirar ANTES de tirarlo.
    let suyos = reg.aportados_por("canal-x", T0);
    println!("      el canal envenenado toco {} objetos", suyos.len());
    fallos += exigir(
        suyos.len() == 412 + 37 + 18,
        "se puede listar lo que toco ANTES de revocarlo: una revocacion a ciegas sobre cuatrocientos \
         mil indicadores no la firma nadie",
    );

    let rev = reg.revocar_fuente("canal-x", T0);
    println!("      {}", rev.resumen("canal-x"));
    fallos += exigir(
        rev.caidos.len() == 412 + 18,
        "caen los suyos y los que reemitio otro con el como raiz: un aporte que paso por el lo pudo \
         alterar",
    );
    fallos += exigir(
        rev.rebajados.len() == 37,
        "y los 37 que sostenia tambien el socio siguen en pie, con la confianza recalculada",
    );
    fallos += exigir(
        rev.rebajados
            .iter()
            .all(|(_, antes, despues)| despues < antes),
        "recalculada hacia abajo, y con el antes y el despues para poder auditarlo",
    );
    fallos += exigir(
        reg.cuantos() == 200 + 37,
        "queda intacto lo que nunca dependio de el: borrar la base entera habria castigado a las \
         fuentes buenas por haber coincidido con la mala",
    );
    let dos = reg.revocar_fuente("canal-x", T0);
    fallos += exigir(
        dos.vacia(),
        "y revocar es idempotente: ejecutar la limpieza dos veces no cambia nada la segunda",
    );

    // Tres canales que repiten al mismo cuentan como uno.
    let mut r2 = Registro::nuevo();
    for c in ["a", "b", "c"] {
        r2.anotar("x", aporte(c, Fiabilidad::Comunidad, &["origen-unico"]));
    }
    let f = r2.ficha("x").expect("esta");
    println!(
        "      tres canales que repiten al mismo -> {} aportes, {} fuente(s) independiente(s)",
        f.aportes.len(),
        f.fuentes_independientes(T0)
    );
    fallos += exigir(
        f.fuentes_independientes(T0) == 1,
        "tres canales que se nutren del mismo son UNA fuente: es como un indicador parece \
         corroborado sin estarlo",
    );
    println!();
    fallos
}

// ─── 5 · Entrada hostil ───────────────────────────────────────────────────────

fn fase_hostil() -> usize {
    println!("  [5/6] entrada hostil: nada tumba el plano de control");
    let mut fallos = 0;

    let base = paquete(&[doc_indicador(
        &uuid(40),
        "[domain-name:value = 'x.example']",
        &["TLP:GREEN", "PAP:GREEN"],
        "",
    )]);

    let mut probados = 0usize;
    // Semillas conocidas.
    for s in [
        "",
        "null",
        "[]",
        "{}",
        "{\"objects\":[null]}",
        "{\"type\":\"bundle\",\"objects\":{}}",
        "\u{feff}{}",
    ] {
        let _ = Paquete::validar(s);
        probados += 1;
    }
    // Anidamiento y tamaño.
    let hondo = format!(r#"{{"objects":[{}]}}"#, "[".repeat(10_000));
    probados += 1;
    let corto_hondo = Paquete::validar(&hondo).is_err();

    let enorme = format!(
        r#"{{"type":"bundle","x":"{}"}}"#,
        "a".repeat(9 * 1024 * 1024)
    );
    probados += 1;
    let corto_enorme = Paquete::validar(&enorme).is_err();

    // Mutaciones sistematicas de un documento valido: cada posicion, tres bytes.
    let bytes = base.as_bytes();
    for i in 0..bytes.len() {
        for sustituto in [b'\xff', b'{', b'"', b'\\', b'[', 0u8] {
            let mut v = bytes.to_vec();
            v[i] = sustituto;
            let _ = Paquete::validar(&String::from_utf8_lossy(&v));
            probados += 1;
        }
    }
    // Y truncamientos, que es como llega un documento por una conexion cortada.
    for i in 0..bytes.len() {
        let _ = Paquete::validar(&String::from_utf8_lossy(&bytes[..i]));
        probados += 1;
    }

    println!("      {probados} entradas hostiles probadas sin un solo panico");
    fallos += exigir(true, "ninguna entrada provoco panico");
    fallos += exigir(
        corto_hondo,
        "un documento con 10.000 niveles se corta ANTES de analizarlo",
    );
    fallos += exigir(corto_enorme, "y uno de 9 MiB se rechaza por bytes");
    println!();
    fallos
}

// ─── 6 · Taxonomia, galaxias y TAXII ──────────────────────────────────────────

fn fase_taxonomia() -> usize {
    println!("  [6/6] etiquetado estructurado y TAXII de extremo a extremo");
    let mut fallos = 0;

    let v = Vocabulario::estandar();
    let (buenas, malas) = v.filtrar(&[
        "malware:tipo=\"ransomware\"".into(),
        "aegis:origen=\"federacion\"".into(),
        "admiralty-scale:source-reliability=\"b\"".into(),
        "lockbit".into(),
        "malware:familia=\"LockBit\"".into(),
    ]);
    println!(
        "      {} etiquetas validas, {} rechazadas:",
        buenas.len(),
        malas.len()
    );
    for (t, m) in &malas {
        println!(
            "        «{t}» -> {}",
            m.chars().take(90).collect::<String>()
        );
    }
    fallos += exigir(
        buenas.len() == 3 && malas.len() == 2,
        "lo que no valida se rechaza al entrar: guardarlo «por si acaso» es como se llega a tener \
         la misma cosa escrita de cuatro formas",
    );

    let mut g = Galaxia::nueva("actores");
    g.anadir(Grupo {
        id: "g-29".into(),
        nombre: "APT29".into(),
        sinonimos: vec![
            "Cozy Bear".into(),
            "Nobelium".into(),
            "Midnight Blizzard".into(),
        ],
        descripcion: String::new(),
        relacionados: vec![],
    })
    .expect("sin choque");
    let resueltos: Vec<&str> = ["APT29", "cozy-bear", "NOBELIUM", "Midnight Blizzard"]
        .iter()
        .filter(|n| g.resolver(n).is_some())
        .copied()
        .collect();
    println!(
        "      {} nombres distintos resuelven al mismo actor",
        resueltos.len()
    );
    fallos += exigir(
        resueltos.len() == 4,
        "el mismo actor bajo cuatro nombres es uno: una base que los trate como cuatro no junta \
         nunca lo que se sabe de el",
    );

    // TAXII de extremo a extremo, con el estrangulamiento de difusion por medio.
    let mut s = Servidor::nuevo(difusor_completo());
    s.declarar(Coleccion {
        id: "indicadores".into(),
        titulo: "Indicadores de la comunidad".into(),
        descripcion: "Lo compartible".into(),
        lectura: true,
        escritura: true,
        destino: "comunidad".into(),
    })
    .expect("destino declarado");

    let docs: Vec<String> = (0..250)
        .map(|i| {
            let (tlp, pap) = match i % 5 {
                0 => ("TLP:RED", "PAP:RED"),
                1 => ("TLP:AMBER+STRICT", "PAP:CLEAR"),
                _ => ("TLP:GREEN", "PAP:CLEAR"),
            };
            doc_indicador(
                &uuid(1000 + i),
                &format!("[domain-name:value = 'd{i}.example']"),
                &[tlp, pap],
                "",
            )
        })
        .collect();
    let p = Paquete::validar(&paquete(&docs)).expect("valido");
    let objetos: Vec<Objeto> = p.objetos.values().cloned().collect();
    let total = objetos.len();
    s.anadir("indicadores", objetos, T0).expect("escribible");

    let mut c = Cliente::nuevo();
    let recibidos = c.sondear(&s, "indicadores", 25).expect("sondeo");
    let compartibles = total - total.div_ceil(5) - (total + 3) / 5;
    println!(
        "      el servidor tiene {total}; el cliente recibio {} tras agotar las paginas",
        recibidos.len()
    );
    let auditoria = s.auditar("indicadores").expect("auditable");
    println!(
        "      auditoria de la coleccion: salen {}, se retienen {} ({:?})",
        auditoria.salen.len(),
        auditoria.retenidos.len(),
        auditoria.por_motivo()
    );
    fallos += exigir(
        recibidos.len() == auditoria.salen.len(),
        "el cliente recibe exactamente lo que la difusion deja salir, ni uno mas",
    );
    fallos += exigir(
        recibidos.len() == compartibles,
        &format!(
            "y son los {compartibles} compartibles: ni el TLP:RED ni el AMBER+STRICT llegan a la \
             comunidad"
        ),
    );

    // El sondeo no repite, y ve lo que llega despues aunque sea viejo.
    fallos += exigir(
        c.sondear(&s, "indicadores", 25).expect("sondeo").is_empty(),
        "un segundo sondeo no repite nada: el cursor avanzo tambien en la ultima pagina",
    );
    let tardio = Paquete::validar(&paquete(&[doc_indicador(
        &uuid(5000),
        "[domain-name:value = 'llega-tarde.example']",
        &["TLP:GREEN", "PAP:CLEAR"],
        "",
    )]))
    .expect("valido");
    s.anadir(
        "indicadores",
        tardio.objetos.values().cloned().collect(),
        T0 + 3600 * SEG,
    )
    .expect("escribible");
    fallos += exigir(
        c.sondear(&s, "indicadores", 25).expect("sondeo").len() == 1,
        "y lo que llega despues si se ve, porque el sondeo va por «cuando se añadio aqui»",
    );

    // El puente al enjambre, con la doctrina intacta.
    let mut reg = Registro::nuevo();
    for o in p.objetos.keys() {
        reg.anotar(
            o,
            Aporte {
                fuente: "socio".into(),
                fiabilidad: Fiabilidad::Acordada,
                cadena: vec![],
                cuando_ns: T0,
                confianza_declarada: 90,
                id_en_origen: o.clone(),
            },
        );
    }
    let puente = Puente::nuevo("flota");
    let preparado = puente.preparar(&p, &reg, T0, true);
    println!("      puente al enjambre: {}", preparado.resumen());
    fallos += exigir(
        preparado.cargas.iter().all(aegis_share::Carga::exige_firma),
        "lo que cruza la malla como artefacto EXIGE la firma del plano de control: el enjambre \
         transporta autoridad, no la concede",
    );
    fallos += exigir(
        preparado.indicadores() > 0 && preparado.indicadores() == compartibles,
        "y cruza lo compartible y bloqueable, sin el TLP:RED ni el AMBER+STRICT",
    );

    let peticion = Peticion::todo().con_limite(10);
    let pagina = s.leer("indicadores", &peticion).expect("lectura");
    fallos += exigir(
        pagina.retenidos > 0,
        "el operador SI ve cuanto se esta reteniendo: sin esa cifra, una politica mal puesta deja \
         la coleccion vacia y nadie se entera",
    );
    fallos
}
