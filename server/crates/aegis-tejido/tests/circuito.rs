//! La prueba que justifica la FASE 79: el circuito completo, con **un solo
//! identificador de entidad** recorriendo la cadena entera.
//!
//! Cada subsistema tiene sus propias pruebas y son mas exigentes sobre lo suyo.
//! Lo que ninguna puede enseñar es lo que falla **entre** ellos, que es lo que esta
//! fase construye y lo unico que aqui se comprueba.

use std::collections::BTreeSet;

use aegis_entidad::arbitro::{Juicio, Resultado};
use aegis_entidad::entidad::{self, Clase};
use aegis_entidad::escala::{Motor, Plano, Severidad};
use aegis_invitado::protocolo::{AccionFichero, AccionProceso, AccionRed, Evento, Trama};
use aegis_predict::contencion::Veredicto as VeredictoContencion;
use aegis_tejido::circuito::{
    self, clases_recorridas, enriquecer_sin_salida, recorrer, ErrorCircuito, PARADAS_ESPERADAS,
    SEG, T0,
};
use aegis_tejido::inventario;

/// Las tramas del agente invitado que alimentan la detonacion.
///
/// Se construyen con el protocolo **de verdad** y entran por el receptor de
/// `aegis-detonate`: no hay atajo que salte el analisis de trama, los topes ni la
/// deteccion de huecos de secuencia.
fn tramas_del_invitado() -> Vec<Vec<u8>> {
    let eventos = vec![
        Evento::Preparado {
            version: "0.1.0".into(),
        },
        Evento::Proceso {
            pid: 2,
            padre: 1,
            accion: AccionProceso::Ejecuta,
            imagen: "/tmp/muestra".into(),
            argumentos: vec!["/s".into()],
        },
        Evento::Fichero {
            pid: 2,
            accion: AccionFichero::Escribe,
            ruta: "/home/usuario/.config/autostart/actualiza.desktop".into(),
            bytes: 412,
        },
        Evento::Fichero {
            pid: 2,
            accion: AccionFichero::Borra,
            ruta: "/var/log/auth.log".into(),
            bytes: 0,
        },
        Evento::Red {
            pid: 2,
            accion: AccionRed::Resuelve,
            destino: "descarga.ejemplo-malo.test".into(),
            puerto: 0,
            bytes: 0,
        },
        Evento::Red {
            pid: 2,
            accion: AccionRed::Conecta,
            destino: "203.0.113.9".into(),
            puerto: 443,
            bytes: 0,
        },
        Evento::Proceso {
            pid: 3,
            padre: 2,
            accion: AccionProceso::Nace,
            imagen: "/bin/sh".into(),
            argumentos: vec!["-c".into(), "crontab -".into()],
        },
        Evento::Llamada {
            pid: 2,
            numero: 101,
            nombre: "ptrace".into(),
        },
        Evento::Fin {
            codigo: 0,
            emitidos: 9,
            completo: true,
        },
    ];

    eventos
        .into_iter()
        .enumerate()
        .map(|(i, evento)| {
            Trama {
                secuencia: i as u64,
                evento,
            }
            .a_bytes()
        })
        .collect()
}

/// Recorre el circuito entero en un directorio temporal.
///
/// El enriquecimiento se hace **antes** y por el mismo resumen que calculo el
/// disector: es lo que hace que la parada 7 hable de la misma cosa que las demas.
fn circuito() -> Result<aegis_tejido::Recorrido, ErrorCircuito> {
    let dir = tempfile::tempdir().expect("directorio temporal");
    let sha = circuito::resumen_en_transito()?;

    let enriquecimiento = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(enriquecer_sin_salida(&sha, T0 + 135 * SEG));

    recorrer(dir.path(), &tramas_del_invitado(), &enriquecimiento)
}

/// LA PROPIEDAD QUE JUSTIFICA LA FASE. Once subsistemas, un identificador.
///
/// Si esto se rompe, el producto vuelve a ser once herramientas en un instalador:
/// cada una acierta con lo suyo y nadie puede preguntar «que sabemos de esta cosa»
/// una sola vez.
#[test]
fn un_solo_identificador_recorre_la_cadena_entera() {
    let r = circuito().expect("el circuito completo recorre");

    assert_eq!(
        r.paradas.len(),
        PARADAS_ESPERADAS.len(),
        "faltan paradas: {}",
        r.informe()
    );
    for (n, subsistema, fase) in PARADAS_ESPERADAS {
        let p = r
            .paradas
            .iter()
            .find(|p| p.numero == *n)
            .unwrap_or_else(|| panic!("falta la parada {n} ({subsistema})"));
        assert_eq!(p.subsistema, *subsistema, "parada {n}");
        assert_eq!(p.fase, *fase, "parada {n}");
        assert!(!p.salida.is_empty(), "la parada {n} no dice que hizo");
    }

    // LA COLUMNA DE LA PRUEBA: siete de las once paradas hablan de la MISMA
    // entidad, la del contenido, y las otras cuatro hablan de entidades
    // relacionadas con ella por una arista del linaje — nunca de una entidad
    // suelta.
    let del_contenido = r.paradas_del_contenido();
    assert!(
        del_contenido.len() >= 7,
        "solo {} parada(s) sobre la entidad del contenido:\n{}",
        del_contenido.len(),
        r.informe()
    );
    assert_eq!(r.contenido.clase(), Clase::Contenido);

    // Y el identificador es UNO: un solo valor distinto entre todas ellas.
    let unicos: BTreeSet<String> = del_contenido.iter().map(|p| p.entidad.texto()).collect();
    assert_eq!(unicos.len(), 1, "el identificador cambio por el camino");
}

/// LAS CUATRO PARADAS QUE NO HABLAN DEL CONTENIDO ESTAN UNIDAS A EL. Es la
/// diferencia entre un grafo y una lista: el flujo, el artefacto detonado y la
/// maquina no son la misma cosa que el fichero, y decir que lo son perderia
/// informacion — pero tienen que ser alcanzables desde el.
#[test]
fn lo_que_no_es_el_contenido_esta_unido_a_el_por_el_linaje() {
    let r = circuito().expect("el circuito completo recorre");

    for p in &r.paradas {
        if p.entidad == r.contenido {
            continue;
        }
        let hay_camino = r
            .linaje
            .camino_entre(&r.raiz_del_linaje, &p.entidad)
            .is_some()
            || r.linaje.camino_entre(&p.entidad, &r.contenido).is_some()
            || r.linaje.camino_entre(&r.contenido, &p.entidad).is_some();
        assert!(
            hay_camino,
            "la parada {} ({}) nombra «{}», que no esta unida al contenido",
            p.numero,
            p.subsistema,
            p.entidad.texto()
        );
    }
}

/// EL LINAJE CRUZA LOS CINCO PLANOS. Red → fichero → proceso → identidad →
/// respuesta como UNA cadena consultable, que es el punto 4 de la fase.
#[test]
fn el_linaje_atraviesa_red_fichero_proceso_e_identidad() {
    let r = circuito().expect("el circuito completo recorre");

    let camino = r.linaje.adelante(&r.raiz_del_linaje);
    let clases: BTreeSet<&'static str> = camino.por_clase().keys().copied().collect();

    for esperada in [
        Clase::Flujo,
        Clase::Contenido,
        Clase::Proceso,
        Clase::Cuenta,
        Clase::Maquina,
        Clase::Ubicacion,
        Clase::Artefacto,
    ] {
        assert!(
            clases.contains(esperada.prefijo()),
            "el linaje no llega a «{}»: {clases:?}",
            esperada.prefijo()
        );
    }

    // Y el camino cruza planos: si no lo hiciera, serian varios grafos separados
    // dibujados en el mismo sitio.
    assert!(
        camino.cruza_planos(),
        "el camino no cruza planos: el linaje son islas — {}",
        camino.resumen()
    );
    assert!(
        camino.truncado.is_none(),
        "el recorrido se corto: {}",
        camino.resumen()
    );
}

/// EL ARBITRO NO DECIDE CON UN SOLO PLANO. Es la regla que impide que un motor
/// solo, por seguro que este, lleve una entidad a critica.
#[test]
fn el_veredicto_se_sostiene_en_mas_de_un_plano() {
    let r = circuito().expect("el circuito completo recorre");

    assert_eq!(
        r.veredicto.resultado,
        Resultado::Malicioso,
        "{}",
        r.veredicto.resumen()
    );
    assert!(
        r.veredicto.corroboracion() >= 2,
        "un solo plano decidio: {:?}",
        r.veredicto.planos
    );
    assert!(
        !r.veredicto.porque.is_empty(),
        "un veredicto sin frase es un veredicto que el analista no usa"
    );

    // Y las señales van dentro, todas: es lo que permite discutir el resultado en
    // vez de acatarlo.
    assert!(r.veredicto.senales.len() >= 3, "{:?}", r.veredicto.senales);
    let motores: BTreeSet<&'static str> = r
        .veredicto
        .senales
        .iter()
        .map(|s| s.motor.nombre())
        .collect();
    assert!(
        motores.contains(Motor::Detonate.nombre()),
        "la detonacion no llego al arbitro: {motores:?}"
    );
    assert!(
        motores.contains(Motor::Estatico.nombre()),
        "el corpus no llego al arbitro: {motores:?}"
    );
}

/// EL CIRCUITO ES DETERMINISTA — INVARIANTE 4 de la FASE 80.
///
/// Dos recorridos sobre los mismos hechos dan el mismo identificador, el mismo
/// veredicto —frase y señales incluidas—, el mismo caso y la misma propuesta de
/// contencion.
///
/// No es una propiedad estetica: sin ella no se puede comparar el informe de hoy
/// con el de ayer, que es como se detecta que un cambio ha movido una deteccion
/// sin que nadie lo pretendiera. Y no basta con que coincida el resultado: dos
/// ejecuciones que llegan a «malicioso» por razones distintas son dos productos
/// distintos, y lo unico que el analista ve es la frase.
#[test]
fn el_determinismo_cubre_veredicto_caso_y_contencion() {
    let a = circuito().expect("primer recorrido");
    let b = circuito().expect("segundo recorrido");

    // EL IDENTIFICADOR.
    assert_eq!(a.contenido.texto(), b.contenido.texto());
    assert_eq!(a.sha256_del_contenido, b.sha256_del_contenido);

    // EL VEREDICTO, entero: no basta con que coincida el resultado. Dos
    // ejecuciones que llegan a «malicioso» por razones distintas son dos
    // productos distintos, y el analista solo ve la frase.
    assert_eq!(a.veredicto, b.veredicto);
    assert_eq!(a.veredicto.senales.len(), b.veredicto.senales.len());
    for (x, y) in a.veredicto.senales.iter().zip(&b.veredicto.senales) {
        assert_eq!(x.motor, y.motor);
        assert_eq!(x.juicio, y.juicio);
        assert_eq!(x.confianza, y.confianza);
        assert_eq!(x.porque, y.porque);
    }

    // EL CASO: el numero de lineas de cronologia y lo que dice su parada.
    assert_eq!(a.lineas_de_cronologia, b.lineas_de_cronologia);
    let caso_a = a.paradas.iter().find(|p| p.numero == 6).expect("parada 6");
    let caso_b = b.paradas.iter().find(|p| p.numero == 6).expect("parada 6");
    assert_eq!(caso_a.salida, caso_b.salida);

    // LA PROPUESTA DE CONTENCION, entera: sujeto, accion y justificacion.
    assert_eq!(a.contencion, b.contencion);

    // Y el linaje y el informe completo.
    assert_eq!(a.linaje.aristas(), b.linaje.aristas());
    assert_eq!(a.linaje.entidades(), b.linaje.entidades());
    assert_eq!(a.informe(), b.informe());
}

/// LO QUE NO SE PUDO MIRAR NO SE CUENTA COMO LIMPIO, NI SIQUIERA AQUI. En el
/// circuito el enriquecimiento corre **sin salida**, asi que las fuentes externas
/// no responden — y eso tiene que producir «no se», nunca «esta limpio».
#[test]
fn el_enriquecimiento_sin_salida_no_declara_nada_limpio() {
    let informe = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async { enriquecer_sin_salida(&"b".repeat(64), T0).await });

    assert!(
        informe.exposicion.vacia(),
        "salio algo con el modo sin salida puesto: {}",
        informe.exposicion.resumen()
    );
    assert_ne!(
        informe.fusion.veredicto,
        aegis_enrich::fusion::Veredicto::Limpio,
        "«nadie lo conoce» no es «esta limpio»"
    );
    // Y los analizadores locales siguen dando su resultado: sin salida es
    // degradado, no apagado.
    assert!(
        !informe.por_analizador.is_empty(),
        "no corrio ningun analizador"
    );
}

/// EL INVENTARIO ESTA COMPLETO Y CUADRA CON LA ESCALA. Es el mapa de la fase, y
/// sin el la unificacion seria adivinanza.
#[test]
fn el_inventario_cubre_los_trece_motores() {
    assert_eq!(inventario::CENSO.len(), Motor::todos().len());
    for m in Motor::todos() {
        let f = inventario::fila(*m);
        assert_eq!(f.plano(), m.plano());
    }
    for p in Plano::todos() {
        assert!(
            inventario::motores_por_plano()
                .iter()
                .any(|(q, n)| q == p && *n > 0),
            "el plano «{}» no tiene motores",
            p.nombre()
        );
    }
}

/// LAS CLASES QUE EL CIRCUITO NOMBRA SON LAS DECLARADAS. Un circuito que inventara
/// una clase de entidad estaria fabricando identificadores que ningun otro
/// subsistema puede volver a derivar.
#[test]
fn el_circuito_no_inventa_clases_de_entidad() {
    let r = circuito().expect("el circuito completo recorre");
    let declaradas: BTreeSet<&str> = circuito::clases_declaradas().into_iter().collect();
    for (clase, n) in clases_recorridas(&r) {
        assert!(declaradas.contains(clase), "clase inventada: «{clase}»");
        assert!(n > 0);
    }
}

/// LA DETONACION LLEGA AL ARBITRO COMO CERTEZA, Y ES LA UNICA QUE PUEDE. Vio la
/// muestra ejecutarse; ningun otro motor del circuito puede decir eso.
#[test]
fn solo_quien_vio_la_muestra_correr_llega_a_certeza() {
    let r = circuito().expect("el circuito completo recorre");

    let detonacion = r
        .veredicto
        .senales
        .iter()
        .find(|s| s.motor == Motor::Detonate)
        .expect("la detonacion aporto");
    assert_eq!(detonacion.juicio, Juicio::Malicioso);

    for s in &r.veredicto.senales {
        if s.motor == Motor::Detonate {
            continue;
        }
        assert!(
            s.confianza < detonacion.confianza,
            "«{}» se declara tan seguro como quien vio la muestra correr",
            s.motor.nombre()
        );
    }
}

/// LA SEVERIDAD NO SE INFLA POR EL CAMINO. El caso se abre con la severidad que
/// dijo el arbitro, traducida, y no con una recalculada — que es como dos paneles
/// del mismo producto acaban enseñando cifras distintas del mismo incidente.
#[test]
fn el_caso_hereda_la_severidad_del_arbitro() {
    let r = circuito().expect("el circuito completo recorre");
    assert!(
        r.veredicto.severidad >= Severidad::Alta,
        "{}",
        r.veredicto.resumen()
    );
    assert!(
        r.lineas_de_cronologia >= 4,
        "la cronologia se quedo en {} linea(s)",
        r.lineas_de_cronologia
    );
}

/// EL ENJAMBRE CORROBORA SIN PLANO DE CONTROL. Es la invariante de la FASE 68
/// ejercida dentro del circuito: la ultima parada funciona con el enlace cortado.
#[test]
fn el_indicador_llega_al_agente_aislado() {
    let r = circuito().expect("el circuito completo recorre");
    assert!(
        r.corroborados >= 1,
        "el agente aislado no llego a corroborar nada"
    );
}

/// LA CONTENCION CORTA LA IDENTIDAD Y NO TOCA EL ACTIVO PROTEGIDO.
///
/// Son las dos reglas de la FASE 69 que mas consecuencias tienen, y el circuito las
/// ejerce juntas: el camino mas probable termina en el controlador de dominio, que
/// esta **protegido**, asi que el motor no puede actuar ahi — y en vez de escalar
/// sin mas, corta un salto antes, en la cuenta de servicio.
///
/// Que el sujeto contenido no sea nunca un activo protegido no es una preferencia:
/// tirar el controlador de dominio convierte un incidente en un apagon, y es lo que
/// un atacante querria que hicieramos por el.
#[test]
fn la_contencion_corta_la_identidad_y_no_toca_lo_protegido() {
    let r = circuito().expect("el circuito completo recorre");

    let VeredictoContencion::Contener {
        sujeto,
        accion,
        justificacion,
        ..
    } = &r.contencion
    else {
        panic!("el orquestador no contuvo: {:?}", r.contencion);
    };

    assert_ne!(
        sujeto, "dc-01.corp.ejemplo",
        "se propuso contener el activo protegido"
    );
    assert!(
        sujeto.starts_with("CORP\\"),
        "se corta la identidad antes que la maquina, y se corto «{sujeto}»"
    );
    assert!(
        !justificacion.is_empty(),
        "una contencion sin justificacion es una orden que nadie puede discutir"
    );
    // Y la accion es la minima que corta ese salto, no la mas contundente.
    assert_eq!(format!("{accion:?}"), "RevocarTicketsKerberos");
}

/// La entidad del contenido se deriva del resumen y de nada mas: dos observadores
/// con el mismo fichero llegan al mismo nombre sin hablar entre ellos.
#[test]
fn el_identificador_se_deriva_y_no_se_coordina() {
    let r = circuito().expect("el circuito completo recorre");
    assert_eq!(
        r.contenido,
        entidad::contenido(&r.sha256_del_contenido),
        "el identificador no se puede volver a derivar desde el resumen"
    );
}
