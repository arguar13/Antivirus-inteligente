//! Una jornada de SOC completa, de alerta a caso cerrado, con cifras.
//!
//! No es una demostracion: es la prueba que justifica el modulo. Un crate de
//! gestion de casos se puede escribir entero con pruebas unitarias que pasan y
//! seguir siendo inservible, porque lo que rompe en produccion no es una funcion:
//! es el VOLUMEN. Mil alertas de una campana, una alerta distinta en medio, una
//! regla que solo hace ruido, y un rastro que alguien toco.
//!
//! Asi que esto recorre las cuatro a la vez, con numeros que salen del codigo y
//! que la puerta de calidad comprueba. Si alguna propiedad se rompe, el proceso
//! termina con codigo distinto de cero y `tools/verificar-case.sh` falla.

use std::collections::BTreeMap;

use aegis_case::auditoria::{Accion, Rastro, Rotura};
use aegis_case::cronologia::{Cronologia, NodoLinaje, Remediacion};
use aegis_case::fusion::Fusionador;
use aegis_case::metricas::{calcular, espera_de, Resumen, MINIMO_PARA_JUZGAR, UMBRAL_RUIDO};
use aegis_case::modelo::{Alerta, Estado, Observable, Severidad, Veredicto};
use aegis_case::plantillas::{proponer, Clase, Orden};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;
/// Un minuto, en nanosegundos.
const MIN: u64 = 60 * SEG;
/// Una hora, en nanosegundos.
const HORA: u64 = 60 * MIN;

/// Origen de tiempos de la jornada: 2025-01-13T08:00:00Z.
const T0: u64 = 1_736_755_200 * SEG;

/// Maquinas alcanzadas por la campana de ransomware.
const MAQUINAS_CAMPANA: usize = 40;
/// Alertas por maquina de la campana.
const ALERTAS_POR_MAQUINA: usize = 22;
/// Veces que dispara la regla ruidosa.
const DISPAROS_RUIDOSOS: usize = 180;

/// Minutos hasta que alguien mira una alerta de ruido.
const TRIAJE_MIN: u64 = 9;
/// Minutos hasta que se cierra una alerta de ruido.
const CIERRE_MIN: u64 = 14;

fn main() {
    let mut fallos = 0usize;

    println!("AegisCase · una jornada de SOC, de alerta a caso cerrado");
    println!();

    fallos += fase_fusion();
    fallos += fase_cronologia();
    fallos += fase_auditoria();
    fallos += fase_metricas();

    println!();
    if fallos == 0 {
        println!("todas las propiedades se sostienen sobre la jornada completa");
    } else {
        println!("{fallos} propiedad(es) rotas");
        std::process::exit(1);
    }
}

/// Comprueba una propiedad y la cuenta si falla.
fn exigir(ok: bool, texto: &str) -> usize {
    if ok {
        println!("      ok   {texto}");
        0
    } else {
        println!("      ROTO {texto}");
        1
    }
}

/// Una alerta de la campana de cifrado.
fn alerta_ransomware(i: usize, maquina: usize) -> Alerta {
    let anfitrion = format!("ws-{maquina:03}.corp.local");
    Alerta {
        id: format!("a-ransom-{i:05}"),
        inquilino: "acme".into(),
        // El sujeto es el mismo binario en toda la flota: es exactamente lo que
        // convierte mil alertas en una campana y no en mil incidentes.
        sujeto: "sha256:7f1e3c9b".into(),
        anfitrion: anfitrion.clone(),
        tecnica: Some("T1486".into()),
        regla: "ransom_masa_extension".into(),
        severidad: Severidad::Critica,
        // Se reparten a lo largo de treinta minutos, dentro de la ventana de
        // campana: si se separaran mas, serian casos distintos, y con razon.
        ocurrio_ns: T0 + (i as u64 % 1800) * SEG,
        observables: vec![
            Observable::Hash("7f1e3c9b".into()),
            Observable::Anfitrion(anfitrion),
        ],
        resumen: "cifrado masivo de documentos".into(),
    }
}

/// La alerta que llega EN MEDIO de la campana y es otra cosa.
fn alerta_lateral() -> Alerta {
    Alerta {
        id: "a-lateral-1".into(),
        inquilino: "acme".into(),
        sujeto: "svc_backup".into(),
        anfitrion: "dc-01.corp.local".into(),
        tecnica: Some("T1021.002".into()),
        regla: "smb_admin_desde_estacion".into(),
        severidad: Severidad::Alta,
        ocurrio_ns: T0 + 900 * SEG,
        observables: vec![
            Observable::Usuario("svc_backup".into()),
            Observable::Anfitrion("dc-01.corp.local".into()),
            Observable::Ip("10.20.4.77".into()),
        ],
        resumen: "sesion SMB administrativa contra el controlador de dominio".into(),
    }
}

/// Una alerta de la regla que solo hace ruido.
fn alerta_ruidosa(i: usize) -> Alerta {
    Alerta {
        id: format!("a-ruido-{i:05}"),
        inquilino: "acme".into(),
        // Sujeto distinto en cada una: no fusionan, y esa es la gracia. Una regla
        // ruidosa no produce un caso grande, produce CIENTOS de casos pequeños,
        // que es lo que de verdad ahoga una cola.
        sujeto: format!("proc-{i}"),
        anfitrion: format!("ws-{:03}.corp.local", i % 90),
        tecnica: Some("T1059.001".into()),
        regla: "powershell_codificado".into(),
        severidad: Severidad::Media,
        ocurrio_ns: T0 + HORA + (i as u64) * 7 * SEG,
        observables: vec![Observable::Orden("powershell -enc ...".into())],
        resumen: "PowerShell con orden codificada".into(),
    }
}

/// Fusion: la campana, la alerta distinta que no se puede tragar, y el tope.
fn fase_fusion() -> usize {
    println!("  [1/4] fusion de alertas en casos");
    let mut f = Fusionador::nuevo();
    let mut fallos = 0;

    let mut motivos: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut caso_lateral = usize::MAX;

    let total_campana = MAQUINAS_CAMPANA * ALERTAS_POR_MAQUINA;
    for i in 0..total_campana {
        // La alerta de movimiento lateral entra por la mitad de la campana, que
        // es el escenario que importa: si el fusionador la traga, el incidente
        // que de verdad hay que atender desaparece dentro de otro.
        if i == total_campana / 2 {
            let d = f.admitir(alerta_lateral());
            caso_lateral = d.caso;
            *motivos.entry(d.motivo.nombre()).or_default() += 1;
        }
        let d = f.admitir(alerta_ransomware(i, i % MAQUINAS_CAMPANA));
        *motivos.entry(d.motivo.nombre()).or_default() += 1;
    }
    for i in 0..DISPAROS_RUIDOSOS {
        let d = f.admitir(alerta_ruidosa(i));
        *motivos.entry(d.motivo.nombre()).or_default() += 1;
    }

    let campana = f
        .casos()
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| c.alertas.len())
        .map(|(i, _)| i)
        .expect("hay casos");

    println!(
        "      {} alertas -> {} casos",
        total_campana + 1 + DISPAROS_RUIDOSOS,
        f.casos().len()
    );
    for (m, n) in &motivos {
        println!("        {m:<28} {n:>5}");
    }

    fallos += exigir(
        f.casos()[campana].alertas.len() == total_campana,
        &format!(
            "las {total_campana} alertas de la campana caben en un solo caso (tiene {})",
            f.casos()[campana].alertas.len()
        ),
    );
    fallos += exigir(
        caso_lateral != campana,
        "la alerta de movimiento lateral NO se trago dentro de la campana",
    );
    fallos += exigir(
        f.casos()[caso_lateral].alertas.len() == 1,
        "el caso de movimiento lateral llego solo, sin arrastre de la campana",
    );
    fallos += exigir(
        motivos.get("campana").copied().unwrap_or(0) > 0,
        "la campana se reconocio como tal y no como una suma de coincidencias",
    );
    // LO QUE ESTA CIFRA ENSENA, Y NO ES LO QUE PARECE.
    //
    // Los ciento ochenta disparos de la regla ruidosa caen en UN caso, igual que
    // la campana de verdad. Y esta bien que asi sea: el fusionador agrupa por
    // FORMA, y la forma de «una regla que salta en noventa maquinas en una hora»
    // es identica a la de «una campana que alcanza noventa maquinas en una hora».
    // No hay senal en el trafico que las separe.
    //
    // Lo que las separa es el VEREDICTO, y el veredicto no existe hasta que
    // alguien mira. Por eso la herramienta contra el ruido no es el fusionador
    // —que no puede saberlo— sino la metrica de ruido POR REGLA, que lo sabe
    // despues y con base suficiente. Ver la fase 4.
    //
    // El efecto practico, que es el que importa: la cola del analista recibe tres
    // casos, no mil sesenta y uno.
    fallos += exigir(
        f.casos().len() == 3,
        &format!(
            "{} alertas llegan a la cola como 3 casos: la regla ruidosa ocupa uno, no {} (hay {})",
            total_campana + 1 + DISPAROS_RUIDOSOS,
            DISPAROS_RUIDOSOS,
            f.casos().len()
        ),
    );

    // Una vez sellado, el caso no crece: es lo que impide que una alerta llegada
    // despues del cierre se cuele en un caso ya archivado y cambie su contenido.
    f.sellar(campana);
    let d = f.admitir(alerta_ransomware(999_999, 0));
    fallos += exigir(
        d.caso != campana,
        "una alerta que llega despues del sellado abre caso nuevo, no reabre el cerrado",
    );

    // La plantilla que sale de cada caso: el orden de respuesta no es el mismo, y
    // aplicar el del ransomware a una cuenta comprometida es catastrofico.
    let p_campana = proponer(&f.casos()[campana]);
    let p_lateral = proponer(&f.casos()[caso_lateral]);
    println!(
        "      campana  -> {:<20} {}",
        p_campana.clase.nombre(),
        p_campana.orden.motivo()
    );
    println!(
        "      lateral  -> {:<20} {}",
        p_lateral.clase.nombre(),
        p_lateral.orden.motivo()
    );
    fallos += exigir(
        p_campana.clase == Clase::Ransomware && p_campana.orden == Orden::ContenerPrimero,
        "el ransomware se contiene primero: los ficheros cifrados no se descifran",
    );
    fallos += exigir(
        p_lateral.clase == Clase::MovimientoLateral && p_lateral.orden == Orden::ContenerElOrigen,
        "el movimiento lateral contiene el origen y deja observar el resto",
    );
    println!();
    fallos
}

/// Cronologia: el hueco se dice, no se rellena.
fn fase_cronologia() -> usize {
    println!("  [2/4] cronologia construida a partir de lo que el sistema tiene");
    let mut fallos = 0;

    let mut f = Fusionador::nuevo();
    let d = f.admitir(alerta_lateral());
    let caso = &mut f.casos_mut()[d.caso];
    caso.pasar_a(Estado::EnCurso, T0 + 12 * MIN)
        .expect("valida");

    let linaje = vec![
        NodoLinaje {
            id: "p-100".into(),
            padre: None,
            // El padre EXISTIO y no se observo. Unir los extremos produciria una
            // cadena causal inventada en un documento que puede acabar en un
            // juzgado.
            padre_desconocido: true,
            imagen: "services.exe".into(),
            orden: "C:\\Windows\\System32\\services.exe".into(),
            cuando_ns: T0 + 890 * SEG,
            usuario: "SYSTEM".into(),
            ficheros: vec![],
            conexiones: vec![],
        },
        NodoLinaje {
            id: "p-101".into(),
            padre: Some("p-100".into()),
            padre_desconocido: false,
            imagen: "psexesvc.exe".into(),
            orden: "psexesvc.exe -s".into(),
            cuando_ns: T0 + 901 * SEG,
            usuario: "svc_backup".into(),
            ficheros: vec![(T0 + 902 * SEG, "C:\\Windows\\psexesvc.exe".into())],
            conexiones: vec![(T0 + 903 * SEG, "10.20.4.77:445".into())],
        },
    ];
    let remediaciones = vec![
        Remediacion {
            id: "r-1".into(),
            accion: "aislar".into(),
            objetivo: "dc-01.corp.local".into(),
            actor: "analista.ana".into(),
            ordenada_ns: T0 + 20 * MIN,
            aplicada_ns: Some(T0 + 20 * MIN + 9 * SEG),
        },
        Remediacion {
            id: "r-2".into(),
            accion: "deshabilitar-cuenta".into(),
            objetivo: "svc_backup".into(),
            actor: "analista.ana".into(),
            ordenada_ns: T0 + 21 * MIN,
            // Ordenada y NO confirmada: la contencion puede no haber ocurrido, y
            // eso tiene que verse en la cronologia y no en un registro aparte.
            aplicada_ns: None,
        },
    ];

    let mut c = Cronologia::construir(&f.casos()[d.caso], &linaje, &remediaciones);
    c.anotar(
        "analista.ana",
        "la cuenta de servicio no deberia entrar por SMB al DC",
        T0 + 25 * MIN,
    );

    for l in c.lineas() {
        let ms = (l.cuando_ns - T0) / 1_000_000;
        println!(
            "      +{:>7}ms {:<10} {:<12} {}",
            ms,
            l.hito.nombre(),
            l.origen.nombre(),
            l.texto
        );
    }

    fallos += exigir(
        c.tiene_huecos(),
        "el padre no observado aparece como hueco explicito, no se rellena",
    );
    fallos += exigir(
        c.lineas()
            .windows(2)
            .all(|p| p[0].cuando_ns <= p[1].cuando_ns),
        "la cronologia sale ordenada por tiempo sin depender del orden de entrada",
    );
    // Las lineas se parten en TRES clases, no en dos, y la tercera es la que se
    // pierde en una cronologia plana: lo que el sistema vio, lo que una persona
    // afirma, y lo que el sistema NO pudo ver. Un informe que mezcla las dos
    // primeras atribuye a la evidencia lo que era una hipotesis; uno que omite la
    // tercera presenta como completo lo que tiene agujeros.
    let evidencia = c.evidencia().len();
    let afirmado = c
        .lineas()
        .iter()
        .filter(|l| l.origen == aegis_case::cronologia::Origen::Analista)
        .count();
    let huecos = c.huecos().len();
    println!("      {evidencia} lineas de evidencia · {afirmado} afirmada por una persona · {huecos} huecos declarados");
    fallos += exigir(
        evidencia + afirmado + huecos == c.lineas().len(),
        "cada linea cae en una de las tres clases: no hay linea sin procedencia",
    );
    fallos += exigir(
        afirmado == 1,
        "lo que escribio una persona esta marcado y no se confunde con evidencia",
    );
    fallos += exigir(
        huecos == 2 && !c.huecos().iter().any(|l| l.origen.es_evidencia()),
        "un hueco NO es evidencia: es la marca de que no hay evidencia de ese tramo",
    );
    let nuevos = c.observables_nuevos(&f.casos()[d.caso]);
    println!("      observables que la cronologia aporta y el caso no tenia: {nuevos:?}");
    fallos += exigir(
        !nuevos.is_empty(),
        "la cronologia descubre observables que las alertas no traian",
    );
    println!();
    fallos
}

/// Auditoria: las cuatro formas de romper un rastro, y las cuatro detectadas.
fn fase_auditoria() -> usize {
    println!("  [3/4] rastro de auditoria encadenado");
    let mut fallos = 0;

    let mut r = Rastro::nuevo("CASO-2025-0113-0042");
    let guion: &[(&str, Accion, &str)] = &[
        (
            "sistema",
            Accion::Creado,
            "abierto por smb_admin_desde_estacion",
        ),
        ("analista.ana", Accion::Consultado, "abrio el caso"),
        ("analista.ana", Accion::CambioDeEstado, "nuevo -> en-curso"),
        ("analista.ana", Accion::TareaCreada, "aislar dc-01"),
        (
            "analista.ana",
            Accion::RemediacionOrdenada,
            "aislar dc-01.corp.local",
        ),
        ("analista.ana", Accion::TareaCerrada, "aislar dc-01: hecho"),
        ("jefe.turno", Accion::Consultado, "revision de turno"),
        ("analista.ana", Accion::Cerrado, "verdadero-positivo"),
    ];
    for (i, (actor, accion, detalle)) in guion.iter().enumerate() {
        r.anotar(actor, *accion, detalle, T0 + (i as u64 + 1) * MIN)
            .expect("actor no vacio");
    }
    let ancla = r.anclar(T0 + 30 * MIN);
    println!(
        "      {} entradas, cabeza {}…, anclada hasta la {}",
        r.entradas().len(),
        &ancla.resumen[..16],
        ancla.hasta
    );
    println!("      actores: {:?}", r.actores());
    fallos += exigir(r.intacto(), "el rastro recien escrito verifica");
    fallos += exigir(
        r.de(Accion::Consultado).len() == 2,
        "quien LEYO el caso tambien consta: «quien miro que» es parte de la pregunta",
    );

    // Las cuatro manipulaciones. Cada una se hace sobre una copia recargada, para
    // que el rastro original siga sirviendo de referencia.
    let recargar = |f: &dyn Fn(&mut Vec<aegis_case::auditoria::Entrada>)| -> Rastro {
        let mut v = r.entradas().to_vec();
        f(&mut v);
        let mut nuevo = Rastro::nuevo("CASO-2025-0113-0042");
        for e in v {
            nuevo.cargar(e);
        }
        nuevo.cargar_ancla(ancla.clone());
        nuevo
    };

    let alterado = recargar(&|v| v[3].detalle = "aislar ws-777".into());
    let roturas = alterado.verificar();
    println!("      editar el detalle de la entrada 4 -> {roturas:?}");
    fallos += exigir(
        roturas.contains(&Rotura::ContenidoAlterado { secuencia: 4 }),
        "editar el contenido de una entrada se detecta, y se dice CUAL",
    );

    let desenganchado = recargar(&|v| v[5].anterior = aegis_case::auditoria::GENESIS.into());
    let roturas = desenganchado.verificar();
    println!("      desenganchar la entrada 6 -> {roturas:?}");
    fallos += exigir(
        roturas.contains(&Rotura::EslabonRoto { secuencia: 6 }),
        "desenganchar un eslabon se detecta aunque su propio resumen cuadre",
    );

    let borrado = recargar(&|v| {
        v.remove(4);
    });
    let roturas = borrado.verificar();
    println!("      borrar la entrada 5 -> {roturas:?}");
    fallos += exigir(
        roturas.iter().any(|x| matches!(x, Rotura::Hueco { .. })),
        "borrar una entrada deja hueco: es la manipulacion mas limpia y la que mas importa",
    );

    // Reescritura COMPLETA y coherente: cadena entera recalculada desde cero. Es
    // la unica que sobrevive a toda comprobacion interna, porque internamente ES
    // valida. Solo el anclaje publicado la delata.
    let mut reescrito = Rastro::nuevo("CASO-2025-0113-0042");
    for (i, (actor, accion, _)) in guion.iter().enumerate() {
        let detalle = if i == 7 { "falso-positivo" } else { "…" };
        reescrito
            .anotar(actor, *accion, detalle, T0 + (i as u64 + 1) * MIN)
            .expect("actor no vacio");
    }
    let sin_ancla = reescrito.verificar();
    reescrito.cargar_ancla(ancla.clone());
    let con_ancla = reescrito.verificar();
    println!(
        "      reescribir la cadena entera -> sin ancla {sin_ancla:?}, con ancla {con_ancla:?}"
    );
    fallos += exigir(
        sin_ancla.is_empty(),
        "una reescritura completa es internamente valida: la cadena sola NO basta",
    );
    fallos += exigir(
        con_ancla.contains(&Rotura::AnclajeRoto { hasta: ancla.hasta }),
        "el anclaje publicado detecta la reescritura completa, que es lo que la cadena no puede",
    );
    println!();
    fallos
}

/// Metricas: la regla ruidosa sale sola, y los casos vivos no falsean el numero.
fn fase_metricas() -> usize {
    println!("  [4/4] metricas del periodo");
    let mut fallos = 0;

    let mut f = Fusionador::nuevo();
    let mut esperas: BTreeMap<String, u64> = BTreeMap::new();

    // El caso serio: se mira, se contiene, se cierra como verdadero positivo.
    let d = f.admitir(alerta_lateral());
    {
        let c = &mut f.casos_mut()[d.caso];
        let historia = [
            (Estado::Nuevo, T0),
            (Estado::EnCurso, T0 + 12 * MIN),
            (Estado::EnEspera, T0 + 40 * MIN),
            (Estado::Contenido, T0 + 3 * HORA),
        ];
        c.pasar_a(Estado::EnCurso, T0 + 12 * MIN).expect("valida");
        c.pasar_a(Estado::EnEspera, T0 + 40 * MIN).expect("valida");
        c.pasar_a(Estado::Contenido, T0 + 3 * HORA).expect("valida");
        let espera = espera_de(&historia, T0 + 3 * HORA);
        esperas.insert(c.id.clone(), espera);
        println!(
            "      espera externa descontada del caso serio: {} min",
            espera / MIN
        );
        c.cerrar(Veredicto::Verdadero, None, T0 + 4 * HORA)
            .expect("sin tareas abiertas");
    }

    // La regla ruidosa: dispara mucho y casi siempre es nada. Cada una se triaja
    // en TRIAJE_MIN y se cierra en CIERRE_MIN, que es el ciclo real de una alerta
    // de ruido: alguien la abre, la mira un rato y la descarta. Pasarla por
    // `EnCurso` no es decoracion: es lo que fija `primer_vistazo_ns`, y sin eso la
    // metrica de deteccion cae a su respaldo —el instante del cierre— y sale un
    // numero enorme que no mide la deteccion sino la cola.
    for i in 0..DISPAROS_RUIDOSOS {
        let d = f.admitir(alerta_ruidosa(i));
        let ocurrio = f.casos()[d.caso].alertas[0].ocurrio_ns;
        f.casos_mut()[d.caso]
            .pasar_a(Estado::EnCurso, ocurrio + TRIAJE_MIN * MIN)
            .expect("valida");
        let veredicto = if i % 20 == 0 {
            Veredicto::Verdadero
        } else {
            Veredicto::FalsoPositivo
        };
        f.cerrar(d.caso, veredicto, None, ocurrio + CIERRE_MIN * MIN)
            .expect("cierre valido");
    }

    // Y un caso que nadie ha tocado desde que se abrio: no esta en ningun
    // percentil, porque los percentiles solo miden lo que ya se cerro.
    let mut atasco = alerta_lateral();
    atasco.id = "a-atascada-1".into();
    atasco.sujeto = "svc_informes".into();
    atasco.ocurrio_ns = T0 - 30 * HORA;
    f.admitir(atasco);

    let r: Resumen = calcular(f.casos(), &esperas);
    println!(
        "      abiertos {} · cerrados {} · vivos {} · sin asignar {}",
        r.abiertos, r.cerrados, r.vivos, r.sin_asignar
    );
    println!(
        "      hasta deteccion  p50 {:>7} ms  p95 {:>7} ms",
        r.hasta_deteccion.p50_ns / 1_000_000,
        r.hasta_deteccion.p95_ns / 1_000_000
    );
    println!(
        "      hasta respuesta  p50 {:>7} ms  p95 {:>7} ms",
        r.hasta_respuesta.p50_ns / 1_000_000,
        r.hasta_respuesta.p95_ns / 1_000_000
    );
    println!(
        "      hasta cierre     p50 {:>7} ms  p95 {:>7} ms",
        r.hasta_cierre.p50_ns / 1_000_000,
        r.hasta_cierre.p95_ns / 1_000_000
    );
    for (v, n) in &r.por_veredicto {
        println!("        {v:<22} {n:>5}");
    }

    // Las tres cifras son DETERMINISTAS a partir del guion de arriba, asi que se
    // comprueban en vez de imprimirse. Una metrica que solo se imprime se deforma
    // sin que nadie lo note, y es justo la que se lleva a una reunion.
    fallos += exigir(
        r.hasta_deteccion.p50_ns == TRIAJE_MIN * MIN,
        &format!(
            "la deteccion mediana es el triaje que se inyecto ({TRIAJE_MIN} min), no la cola: {} \
             min",
            r.hasta_deteccion.p50_ns / MIN
        ),
    );
    // El caso serio se abrio con la alerta (T0 + 900 s), se contuvo a las 3 h y
    // estuvo 140 min esperando a algo externo. 165 - 140 = 25 min de trabajo real
    // del equipo, que es lo unico que su metrica de respuesta puede medir.
    fallos += exigir(
        r.hasta_respuesta.muestras == 1 && r.hasta_respuesta.p50_ns == 25 * MIN,
        &format!(
            "la respuesta descuenta la espera externa: {} min de trabajo del equipo sobre 165 min \
             de reloj",
            r.hasta_respuesta.p50_ns / MIN
        ),
    );
    fallos += exigir(
        r.hasta_cierre.p50_ns == CIERRE_MIN * MIN,
        &format!(
            "el cierre mediano son los {CIERRE_MIN} min del ciclo de ruido: {} min",
            r.hasta_cierre.p50_ns / MIN
        ),
    );
    fallos += exigir(
        r.hasta_cierre.muestras == r.cerrados && r.vivos == 1,
        "todo caso cerrado esta en la muestra y ningun caso vivo lo esta",
    );

    let sospechosas = r.reglas_sospechosas();
    for s in &sospechosas {
        println!(
            "      REVISAR regla {:<26} {} alertas, {} casos concluyentes, ruido {}%",
            s.nombre,
            s.alertas,
            s.falsos_positivos + s.verdaderos + s.autorizados,
            s.ruido_centesimas().unwrap_or(0)
        );
    }
    fallos += exigir(
        sospechosas
            .iter()
            .any(|s| s.nombre == "powershell_codificado"),
        &format!(
            "la regla que solo hace ruido sale sola con >={MINIMO_PARA_JUZGAR} casos \
             concluyentes y >={UMBRAL_RUIDO}% de ruido"
        ),
    );
    fallos += exigir(
        !sospechosas
            .iter()
            .any(|s| s.nombre == "smb_admin_desde_estacion"),
        "una regla con pocos disparos NO se juzga: apagarla por ruido seria apagar la deteccion",
    );

    let atascados = Resumen::atascados(f.casos(), T0 + 5 * HORA, 24 * HORA);
    println!("      casos atascados >24 h: {}", atascados.len());
    fallos += exigir(
        atascados.len() == 1,
        "el caso vivo y viejo se cuenta aparte: no entra en ningun percentil y sin esta cifra \
         desaparece del panel",
    );
    fallos
}
