//! La tuberia entera, con contenido de feed del mundo real.
//!
//! Las pruebas unitarias cubren cada analizador por dentro. Lo que se ejercita
//! aqui es lo que ninguna de ellas puede ver: cuatro formatos entrando a la vez
//! en la misma fabrica, el informe sumando por encima de todos, el canario
//! bloqueando con firmas que vienen de un feed y no de un `vec![]`, y el
//! artefacto llegando firmado al otro lado.
//!
//! El contenido de los feeds es sintaxis real —de Emerging Threats, del catalogo
//! Sigma, de las bases de ClamAV y de colecciones YARA publicas— y no un
//! esqueleto fabricado para que pase. Un banco de pruebas con sintaxis de juguete
//! mide lo bien que se lee el juguete.

use aegis_ruleforge::canario::Canario;
use aegis_ruleforge::clamav::Formato;
use aegis_ruleforge::corpus::{self, CTX_CORPUS};
use aegis_ruleforge::{compilar_corpus, Corpus, ErrorFabrica, Fabrica, Fuente, Indice};
use aegis_update::{ClaveActualizacion, ClaveFirmaHibrida};

// ---------------------------------------------------------------------------
// Contenido de feed, con la sintaxis que traen de verdad
// ---------------------------------------------------------------------------

/// Reglas de Suricata con las dos sintaxis que conviven en los feeds.
///
/// La diferencia entre `http.uri` (bufer pegajoso, moderno: mira hacia ADELANTE)
/// y `http_uri` (modificador clasico: mira hacia ATRAS, al `content` anterior)
/// es el error que hace que los campos salgan desplazados uno.
const SURICATA: &str = r#"
# Emerging Threats, sintaxis moderna de bufer pegajoso
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Baliza sospechosa"; flow:established,to_server; http.uri; content:"/gate.php"; http.user_agent; content:"Mozilla/4.0"; classtype:trojan-activity; sid:2000001; rev:3;)
# La misma idea con la sintaxis clasica de modificador
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Baliza clasica"; flow:established,to_server; content:"/panel/gate.php"; http_uri; nocase; classtype:trojan-activity; sid:2000002; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET MALWARE Certificado conocido"; tls.cert_subject; content:"CN=malicioso.example"; sid:2000003; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"ET DNS Dominio de C2"; dns.query; content:"c2.example.com"; nocase; sid:2000004; rev:1;)
# Esta esta rota a proposito: le falta el parentesis de cierre
alert http any any -> any any (msg:"Rota"; sid:2000005;
"#;

/// Una regla Sigma real, con condicion compuesta y modificadores.
const SIGMA_BUENA: &str = r#"
title: Ejecucion sospechosa de rundll32
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
description: rundll32 lanzado desde un proceso de ofimatica
logsource:
    category: process_creation
    product: windows
detection:
    seleccion:
        Image|endswith: '\rundll32.exe'
    padre:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
    filtro:
        CommandLine|contains: 'legitimo.dll'
    condition: seleccion and padre and not filtro
level: high
"#;

/// Y una que el analizador tiene que rechazar CON NOMBRE, no aceptar a medias.
const SIGMA_ROTA: &str = r#"
title: Sin deteccion
logsource:
    category: process_creation
"#;

/// Firmas de ClamAV, en los formatos que trae la base.
const CLAMAV_CUERPO: &str = "\
Win.Trojan.Demo-1:0:*:4d5a90000300000004000000ffff0000b800000000000000\n\
Win.Trojan.Demo-2:0:*:504b0304140000000800{4-8}abcdef0123456789abcdef\n\
# comentario del feed\n\
\n\
Linea.Rota.Sin.Campos\n";

/// Reglas YARA con dependencia cruzada y uso de modulo.
const YARA_A: &str = r#"
import "pe"

private rule EsPeValido
{
    condition:
        uint16(0) == 0x5a4d and pe.number_of_sections > 0
}
"#;

const YARA_B: &str = r#"
rule TroyanoDemo
{
    meta:
        author = "prueba"
    strings:
        $a = "cadena bastante larga y especifica del troyano"
        $b = { 4d 5a 90 00 03 00 00 00 }
    condition:
        EsPeValido and ($a or $b)
}
"#;

fn fabrica_con_todo() -> Fabrica {
    let mut f = Fabrica::nueva();
    f.ingerir(Fuente::Suricata {
        nombre: "emerging-trojan.rules",
        contenido: SURICATA,
    });
    f.ingerir(Fuente::Sigma {
        nombre: "sigma/windows.yml",
        documentos: &[SIGMA_BUENA, SIGMA_ROTA],
    });
    f.ingerir(Fuente::ClamAv {
        nombre: "main.ndb",
        formato: Formato::Cuerpo,
        contenido: CLAMAV_CUERPO,
    });
    // El orden de las fuentes YARA es el CONTRARIO al de dependencias, a
    // proposito: la reunion tiene que arreglarlo.
    f.ingerir(Fuente::Yara {
        nombre: "b.yar",
        contenido: YARA_B,
    });
    f.ingerir(Fuente::Yara {
        nombre: "a.yar",
        contenido: YARA_A,
    });
    f
}

/// Un canario con software legitimo de verdad, y del sistema si lo hay.
fn canario() -> Canario {
    let mut c = Canario::del_sistema();
    c.anadir(
        "documento.txt",
        b"Un texto plano cualquiera, sin nada que ver con las firmas.".to_vec(),
    );
    c.anadir("binario-inocente.bin", vec![0x00u8; 8192]);
    c
}

fn claves() -> (ClaveFirmaHibrida, ClaveActualizacion) {
    let firmante = ClaveFirmaHibrida::desde_semillas(&[11u8; 32], &[22u8; 32]);
    let verificadora = firmante.clave_verificacion();
    (
        firmante,
        ClaveActualizacion::Hibrida(Box::new(verificadora)),
    )
}

// ---------------------------------------------------------------------------
// Los cuatro formatos, a la vez
// ---------------------------------------------------------------------------

#[test]
fn los_cuatro_formatos_entran_en_la_misma_fabrica() {
    let (compilado, informe) = fabrica_con_todo().cerrar();

    assert!(
        !compilado.red.is_empty(),
        "ninguna regla de Suricata: {}",
        informe.resumen()
    );
    assert!(
        !compilado.eventos.is_empty(),
        "ninguna regla Sigma: {}",
        informe.resumen()
    );
    assert!(
        !compilado.firmas.is_empty(),
        "ninguna firma de ClamAV: {}",
        informe.resumen()
    );
    assert!(
        !compilado.yara.reglas.is_empty(),
        "ninguna regla YARA: {}",
        informe.resumen()
    );
}

#[test]
fn lo_que_no_se_entiende_se_rechaza_con_nombre_y_se_cuenta() {
    // La invariante 2 en una sola comprobacion: hay rechazos, tienen codigo, y
    // la cobertura sale de contarlos. Un analizador permisivo daria cobertura 1
    // y nadie sabria lo que se esta perdiendo.
    let (_, informe) = fabrica_con_todo().cerrar();

    assert!(
        informe.rechazadas() > 0,
        "las reglas rotas tienen que salir"
    );
    assert!(informe.compiladas > 0);

    let por_motivo = informe.por_motivo();
    assert!(!por_motivo.is_empty());
    for (codigo, cuantas) in &por_motivo {
        assert!(
            !codigo.is_empty(),
            "un rechazo sin codigo no se puede agrupar"
        );
        assert!(*cuantas > 0);
    }

    let cobertura = informe.cobertura();
    assert!(
        cobertura > 0.0 && cobertura < 1.0,
        "cobertura {cobertura} con feeds que traen reglas buenas Y rotas"
    );
}

#[test]
fn el_orden_de_las_reglas_yara_respeta_las_dependencias() {
    // Se ingirieron al reves. YARA exige que una regla vaya despues de aquellas a
    // las que se refiere, o no compila.
    let (compilado, _) = fabrica_con_todo().cerrar();
    let nombres: Vec<&str> = compilado
        .yara
        .reglas
        .iter()
        .map(|r| r.nombre.as_str())
        .collect();
    let i_base = nombres.iter().position(|n| *n == "EsPeValido");
    let i_uso = nombres.iter().position(|n| *n == "TroyanoDemo");
    match (i_base, i_uso) {
        (Some(a), Some(b)) => assert!(a < b, "orden {nombres:?}"),
        _ => panic!("faltan reglas: {nombres:?}"),
    }
    // Y el texto reunido sale en ese orden, listo para compilar.
    let fuente = compilado.yara.fuente();
    assert!(fuente.find("EsPeValido").unwrap() < fuente.find("TroyanoDemo").unwrap());
}

// ---------------------------------------------------------------------------
// El circuito completo: compilar, firmar, entregar, verificar
// ---------------------------------------------------------------------------

#[test]
fn el_circuito_completo_llega_firmado_al_otro_lado() {
    let dir = tempfile::tempdir().unwrap();
    let ruta = dir.path().join("corpus.idx");
    let (firmante, clave) = claves();

    let (compilado, informe) = fabrica_con_todo().cerrar();
    let (manifiesto, veredicto) = compilar_corpus(
        &compilado,
        &canario(),
        &ruta,
        100,
        1_700_000_000_000_000_000,
    )
    .unwrap();

    assert!(veredicto.aprobado(), "{}", veredicto.resumen());
    assert!(manifiesto.entradas > 0, "{}", informe.resumen());

    // El plano de control firma el manifiesto, que se compromete con el indice.
    let firma = firmante.firmar(&manifiesto.a_bytes(), CTX_CORPUS).unwrap();
    let paquete = Corpus {
        manifiesto,
        firma: firma.a_bytes(),
    };

    // Y el agente, al otro lado, lo verifica entero.
    let indice = std::fs::read(&ruta).unwrap();
    paquete.verificar(&clave, &indice, 99).unwrap();

    // Lo que recibe se puede consultar sin cargarlo entero.
    let mut idx = Indice::abrir(&ruta).unwrap();
    assert_eq!(idx.len(), paquete.manifiesto.entradas);
    let clave_buscada = aegis_ruleforge::indice::clave_de_nombre("Win.Trojan.Demo-1");
    assert!(
        idx.buscar(&clave_buscada).unwrap().is_some(),
        "la firma compilada tiene que estar en el indice"
    );
}

#[test]
fn el_corpus_de_ayer_no_se_puede_reponer_hoy() {
    // EL ATAQUE CENTRAL DE LA FASE. El corpus es nuestro, la firma es nuestra, el
    // indice cuadra. Lo unico que pasa es que es anterior, y reponerlo devolveria
    // al endpoint a un corpus que no conoce el ransomware de este mes. Ninguna
    // verificacion criptografica lo distingue del bueno.
    let dir = tempfile::tempdir().unwrap();
    let ruta = dir.path().join("corpus.idx");
    let (firmante, clave) = claves();

    let (compilado, _) = fabrica_con_todo().cerrar();
    let (manifiesto, _) = compilar_corpus(&compilado, &canario(), &ruta, 10, 0).unwrap();
    let firma = firmante.firmar(&manifiesto.a_bytes(), CTX_CORPUS).unwrap();
    let viejo = Corpus {
        manifiesto,
        firma: firma.a_bytes(),
    };
    let indice = std::fs::read(&ruta).unwrap();

    // Con la firma intacta y el indice correcto: se rechaza por la epoca.
    match viejo.verificar(&clave, &indice, 250) {
        Err(corpus::ErrorCorpus::Retroceso { ofrecida, vista }) => {
            assert_eq!(ofrecida, 10);
            assert_eq!(vista, 250);
        }
        otro => panic!("un corpus anterior tiene que rechazarse: {otro:?}"),
    }
}

#[test]
fn un_feed_con_una_firma_que_dispara_sobre_el_sistema_no_llega_a_artefacto() {
    // El feed trae una firma corta —el error que un analista comete con prisa—.
    // Un corpus asi, distribuido con el corte activo, mata software legitimo en
    // toda la flota a la vez, sin que haya atacante.
    let dir = tempfile::tempdir().unwrap();
    let ruta = dir.path().join("corpus.idx");

    let mut f = Fabrica::nueva();
    f.ingerir(Fuente::ClamAv {
        nombre: "envenenado.ndb",
        formato: Formato::Cuerpo,
        // Los cuatro bytes del comienzo de cualquier ELF.
        contenido: "Mala.Generica:0:*:7f454c46",
    });
    let (compilado, _) = f.cerrar();
    assert_eq!(compilado.firmas.len(), 1, "la firma se compila bien");

    let r = compilar_corpus(&compilado, &canario(), &ruta, 1, 0);
    assert!(
        matches!(r, Err(ErrorFabrica::Canario(_))),
        "el canario tiene que bloquear: {r:?}"
    );
    assert!(
        !ruta.exists(),
        "y no puede quedar un artefacto escrito esperando a que alguien mire"
    );
}

#[test]
fn el_manifiesto_no_vale_con_el_indice_de_otra_compilacion() {
    // Las dos piezas son autenticas. El corpus que forman no existio nunca.
    let dir = tempfile::tempdir().unwrap();
    let ruta_a = dir.path().join("a.idx");
    let ruta_b = dir.path().join("b.idx");
    let (firmante, clave) = claves();

    let (compilado_a, _) = fabrica_con_todo().cerrar();
    let (manifiesto_a, _) = compilar_corpus(&compilado_a, &canario(), &ruta_a, 10, 0).unwrap();

    let mut fb = Fabrica::nueva();
    fb.ingerir(Fuente::ClamAv {
        nombre: "otro.ndb",
        formato: Formato::Cuerpo,
        contenido: "Otra.Firma:0:*:4d5a90000300000004000000ffff0000ab",
    });
    let (compilado_b, _) = fb.cerrar();
    compilar_corpus(&compilado_b, &canario(), &ruta_b, 11, 0).unwrap();

    let firma = firmante
        .firmar(&manifiesto_a.a_bytes(), CTX_CORPUS)
        .unwrap();
    let paquete = Corpus {
        manifiesto: manifiesto_a,
        firma: firma.a_bytes(),
    };

    let indice_b = std::fs::read(&ruta_b).unwrap();
    assert!(matches!(
        paquete.verificar(&clave, &indice_b, 9),
        Err(corpus::ErrorCorpus::IndiceNoCuadra { .. })
    ));
}

// ---------------------------------------------------------------------------
// Lo que el corpus le cuesta al agente
// ---------------------------------------------------------------------------

#[test]
fn un_corpus_grande_no_se_lleva_la_cuota_de_memoria_del_agente() {
    // LA CIFRA QUE JUSTIFICA EL INDICE EN DISCO. Se construye un corpus de
    // tamano realista, se consulta ENTERO —el caso peor para la residencia— y se
    // mide lo que ocupa en memoria contra la cuota que el host le concede.
    use aegis_presupuesto::{Componente, Presupuesto};

    const GIB: u64 = 1024 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let ruta = dir.path().join("grande.idx");

    // 40.000 firmas de cuerpo: un orden de magnitud realista para un feed.
    let mut fuente = String::new();
    for n in 0..40_000u32 {
        fuente.push_str(&format!(
            "Feed.Grande.{n}:0:*:4d5a9000030000000400{:08x}ffff0000\n",
            n
        ));
    }
    let mut f = Fabrica::nueva();
    f.ingerir(Fuente::ClamAv {
        nombre: "grande.ndb",
        formato: Formato::Cuerpo,
        contenido: &fuente,
    });
    let (compilado, informe) = f.cerrar();
    assert_eq!(informe.rechazadas(), 0, "{}", informe.resumen());
    assert_eq!(compilado.firmas.len(), 40_000);

    let canario = Canario::del_sistema();
    if canario.is_empty() {
        // Sin binarios del sistema el canario no aprobaria, y forzar un canario
        // de mentira para que esta prueba pase seria justo lo que el modulo
        // existe para evitar.
        return;
    }
    compilar_corpus(&compilado, &canario, &ruta, 1, 0).unwrap();

    let en_disco = std::fs::metadata(&ruta).unwrap().len();
    let mut residencias = Vec::new();

    for memoria in [GIB, 16 * GIB, 768 * GIB] {
        let presupuesto = Presupuesto::para(memoria);
        let cuota = presupuesto.cuota(Componente::Corpus);
        let mut idx = Indice::abrir_para(&ruta, &presupuesto).unwrap();

        // Se consultan TODAS: el caso peor para la residencia.
        for n in 0..40_000u32 {
            let clave = aegis_ruleforge::indice::clave_de_nombre(&format!("Feed.Grande.{n}"));
            assert!(idx.buscar(&clave).unwrap().is_some(), "falta la {n}");
        }

        let residencia = idx.residencia_bytes() as u64;
        assert!(
            residencia <= cuota,
            "host de {memoria} B: residencia {residencia} pasa de la cuota {cuota}"
        );

        // Cuando el corpus no cabe en la cuota, la mayor parte se queda en
        // disco: esa es la propiedad que justifica el modulo. Cuando SI cabe
        // —un servidor con 106 MiB de cuota y un indice de dos megas— se queda
        // entero en RAM, y eso NO es un fallo: es el reparto haciendo su
        // trabajo, porque cada firma que no esta en memoria es una lectura de
        // disco que compite con la carga real de la maquina.
        if cuota < en_disco {
            assert!(
                residencia < en_disco,
                "con cuota {cuota} menor que el indice ({en_disco}), la residencia \
                 ({residencia}) tiene que quedarse corta"
            );
        }
        residencias.push(residencia);
    }

    // Y el reparto se nota de verdad: la pasarela retiene estrictamente menos
    // que el servidor. Si las dos cifras salieran iguales, la cuota por clase de
    // host seria decorativa.
    assert!(
        residencias[0] < residencias[2],
        "pasarela {} contra servidor {}",
        residencias[0],
        residencias[2]
    );
}
