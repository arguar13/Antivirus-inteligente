//! Prueba de carga de cien mil agentes contra el plano de control.
//!
//! # Que mide esto y que NO, dicho antes que nada
//!
//! Esta prueba levanta **cien mil agentes** y hace pasar su telemetria por las
//! cuatro piezas que deciden si el plano de control aguanta la flota: el reparto
//! por fragmentos, el repartidor de conexiones, la admision con cuotas y la
//! canalizacion de eventos —deduplicacion y orden por ocurrencia—. Mide la
//! latencia en los percentiles 50, 95 y 99, la memoria, la profundidad de las
//! colas, y **comprueba que no se pierde un solo evento en silencio**.
//!
//! **Lo que NO mide, y se declara en vez de disimularse:**
//!
//! * **No levanta cien mil conexiones mTLS reales.** Eso necesita cien mil
//!   descriptores y varios gigas solo en estar conectado, y es precisamente por
//!   eso por lo que el diseno no las levanta: ver `aegis_scale::sesion`. Lo que
//!   si se hace aqui es **la cuenta completa de capacidad** y la simulacion del
//!   reparto, incluida la caida de un nodo y la manada que provoca.
//! * **No escribe en PostgreSQL.** El escenario contra base de datos real existe
//!   y se lanza con `fleet_simulator` —el otro binario—, que habla el protocolo
//!   autentico con certificados de la CA real. Aqui se mide la parte que decide
//!   el resultado a esta escala y que se puede ejecutar en cualquier maquina de
//!   integracion, para que la cifra este en la puerta de calidad y no en un
//!   documento.
//!
//! La diferencia entre las dos cosas importa: un numero que solo se puede
//! reproducir con un despliegue completo acaba siendo un numero que nadie vuelve
//! a comprobar.
//!
//! # La telemetria es realista, no vacia
//!
//! Un evento vacio mide el coste de mover punteros. Aqui cada agente produce la
//! mezcla que produce un endpoint de verdad: mayoria de actividad de proceso y
//! fichero, algo de red y de autenticacion, y una minoria de hallazgos de
//! seguridad —que son los que tienen prioridad y los que NO pueden perderse—.
//! Los mensajes tienen el tamano que tienen en produccion, los campos que tienen,
//! y horas de ocurrencia repartidas, incluido **un lote de un endpoint que estuvo
//! un dia apagado**, que es el caso que rompe cualquier canalizacion que ordene
//! por llegada.

use std::collections::BTreeMap;
use std::time::Instant;

use aegis_ingest::esquema::{
    Clase, ConfianzaReloj, Evento, Origen, Resultado as ResultadoEvento, Severidad, Valor, VERSION,
};
use aegis_pipeline::{Canalizacion, Cuota};
use aegis_scale::fragmento::{Membresia, Nodo};
use aegis_scale::sesion::{Capacidad, Repartidor, Resultado, ARRIENDO_MS, VENTANA_RECONEXION_MS};

/// Agentes de la flota simulada.
const AGENTES: usize = 100_000;

/// Nodos del plano de control.
const NODOS: usize = 16;

/// Conexiones vivas que admite cada nodo.
const CONEXIONES_POR_NODO: u64 = 10_000;

/// Eventos que produce cada agente en la ventana medida.
const EVENTOS_POR_AGENTE: usize = 4;

/// Inquilinos entre los que se reparte la flota.
const INQUILINOS: usize = 32;

/// Objetivo de latencia del percentil 99, en microsegundos.
///
/// El numero no es una aspiracion: es la cota que, si se supera, hace fallar la
/// prueba. Una prueba de carga que solo imprime numeros no protege de nada,
/// porque la regresion se ve el dia que alguien se molesta en comparar.
const OBJETIVO_P99_US: u64 = 5_000;

const SEG_NS: u64 = 1_000_000_000;

fn main() {
    let mut fallos = 0usize;
    println!("== AegisScale · prueba de carga de {AGENTES} agentes ==");

    fallos += reparto_de_la_flota();
    fallos += conexiones_y_manada();
    let (ok, informe) = canalizacion_a_escala();
    fallos += ok;
    println!("{informe}");

    if fallos == 0 {
        println!("\x1b[32m==> escala verificada\x1b[0m");
    } else {
        println!("\x1b[31m==> escala: {fallos} fallo(s)\x1b[0m");
    }
    std::process::exit(i32::try_from(fallos).unwrap_or(1));
}

/// El reparto de la flota entre los nodos, y lo que cuesta ampliar.
fn reparto_de_la_flota() -> usize {
    let mut fallos = 0;
    let agentes: Vec<String> = (0..AGENTES).map(|i| format!("agente-{i:07}")).collect();

    let mut m = Membresia::default();
    for i in 0..NODOS {
        m.latido(
            Nodo::nuevo(format!("nodo-{i:02}"), format!("10.0.{i}.1:8443")),
            0,
        );
    }
    let inicio = Instant::now();
    let reparto = m.reparto();
    let d = reparto.distribucion(&agentes);
    let coste = inicio.elapsed();

    let ideal = AGENTES / NODOS;
    let min = d.values().copied().min().unwrap_or(0);
    let max = d.values().copied().max().unwrap_or(0);
    let desviacion = (max - min) * 100 / ideal;
    println!(
        "  reparto      {NODOS} nodos · ideal {ideal} · min {min} · max {max} \
         · desviacion {desviacion} % · {coste:?}"
    );
    if desviacion > 20 {
        println!("    \x1b[31mFALLO\x1b[0m: el reparto no es uniforme");
        fallos += 1;
    }

    // Ampliar de 16 a 17 nodos: lo que de verdad importa es cuantos se mueven.
    m.latido(Nodo::nuevo("nodo-16", "10.0.16.1:8443"), SEG_NS);
    let movidos = reparto.movidos(&m.reparto(), &agentes);
    let esperado = AGENTES / (NODOS + 1);
    println!(
        "  ampliacion   16 -> 17 nodos · se mueven {movidos} de {AGENTES} \
         ({} %) · con «hash % nodos» serian ~{} %",
        movidos * 100 / AGENTES,
        (NODOS) * 100 / (NODOS + 1)
    );
    if movidos > esperado * 12 / 10 {
        println!("    \x1b[31mFALLO\x1b[0m: ampliar rebaraja mas de 1/N");
        fallos += 1;
    }
    fallos
}

/// Las conexiones, la caida de un nodo y la manada que provoca.
fn conexiones_y_manada() -> usize {
    let mut fallos = 0;
    let agentes: Vec<String> = (0..AGENTES).map(|i| format!("agente-{i:07}")).collect();

    let mut m = Membresia::default();
    for i in 0..NODOS {
        m.latido(
            Nodo::nuevo(format!("nodo-{i:02}"), format!("10.0.{i}.1:8443")),
            0,
        );
    }
    let reparto = m.reparto();

    let mut r = Repartidor::nuevo(ARRIENDO_MS);
    for i in 0..NODOS {
        r.declarar(
            &format!("nodo-{i:02}"),
            Capacidad {
                memoria_conexiones: CONEXIONES_POR_NODO * aegis_scale::sesion::COSTE_CONEXION,
                descriptores: CONEXIONES_POR_NODO,
            },
        );
    }

    // El diez por ciento de la flota conectada a la vez: es el ciclo de trabajo
    // de un EDR en reposo, y la razon por la que cien mil agentes caben en
    // ciento sesenta mil huecos de conexion sin necesitar cien mil.
    let conectados = AGENTES / 10;
    let mut sin_sitio = 0;
    for ag in agentes.iter().take(conectados) {
        let pref: Vec<String> = reparto
            .preferidos(ag, 3)
            .into_iter()
            .map(|n| n.id.clone())
            .collect();
        if matches!(r.conectar(ag, &pref, 0), Resultado::SinSitio { .. }) {
            sin_sitio += 1;
        }
    }
    println!(
        "  conexiones   {conectados} vivas de {AGENTES} agentes (ciclo del 10 %) \
         · capacidad {} · sin sitio {sin_sitio}",
        r.capacidad_total()
    );
    if sin_sitio > 0 {
        println!("    \x1b[31mFALLO\x1b[0m: no cabe la flota con el ciclo previsto");
        fallos += 1;
    }

    // Cae un nodo: los suyos reconectan. Lo que se mide es el pico por segundo.
    let huerfanos = r.caer("nodo-00");
    let mut por_segundo = [0usize; 60];
    for ag in &huerfanos {
        let s = aegis_scale::sesion::desfase_ms(ag, VENTANA_RECONEXION_MS) / 1000;
        por_segundo[usize::try_from(s).unwrap_or(0).min(59)] += 1;
    }
    let pico = por_segundo.iter().copied().max().unwrap_or(0);
    let plano = huerfanos.len() / 60;
    println!(
        "  caida        nodo-00 pierde {} conexiones · pico de reconexion {pico}/s \
         (plano {plano}/s) · sin desfase serian {}/s",
        huerfanos.len(),
        huerfanos.len()
    );
    if pico > plano * 2 && plano > 0 {
        println!("    \x1b[31mFALLO\x1b[0m: el desfase no aplana la manada");
        fallos += 1;
    }
    fallos
}

/// La canalizacion entera, con telemetria realista.
fn canalizacion_a_escala() -> (usize, String) {
    let mut fallos = 0;
    let mut c = Canalizacion::nueva();
    // Cuota holgada pero real: la prueba mide la canalizacion, no el
    // estrangulamiento. Que exista la cuota es lo que se comprueba en las
    // pruebas de `aegis-pipeline`.
    for i in 0..INQUILINOS {
        c.admision.configurar(
            &format!("inquilino-{i:02}"),
            Cuota {
                eventos_por_segundo: 1_000_000,
                rafaga: 10_000_000,
                reserva_seguridad: 1_000_000,
            },
            0,
        );
    }

    let ahora = 1_700_000_000 * SEG_NS;
    let rss_antes = rss_kib();
    let mut latencias: Vec<u64> = Vec::with_capacity(AGENTES);
    let mut entraron = 0u64;
    let mut salieron = 0u64;
    let mut rechazados = 0u64;
    let mut duplicados = 0u64;
    let mut pico_en_vuelo = 0usize;
    let mut pico_dedupe = 0usize;

    let inicio = Instant::now();
    for i in 0..AGENTES {
        let lote = telemetria_de(i, ahora);
        entraron += lote.len() as u64;
        let t0 = Instant::now();
        let (salida, informe) = c.procesar(lote, ahora);
        latencias.push(u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX));
        salieron += salida.len() as u64;
        rechazados += informe.rechazados;
        duplicados += informe.duplicados;
        pico_en_vuelo = pico_en_vuelo.max(c.orden.en_vuelo());
        pico_dedupe = pico_dedupe.max(c.dedupe.tamano());
    }
    let restantes = c.vaciar();
    salieron += restantes.len() as u64;
    let total = inicio.elapsed();
    let rss_despues = rss_kib();

    latencias.sort_unstable();
    let p = |q: usize| latencias[(latencias.len() * q / 100).min(latencias.len() - 1)];
    let eventos_por_s = if total.as_secs_f64() > 0.0 {
        (entraron as f64 / total.as_secs_f64()) as u64
    } else {
        0
    };

    let mut informe = String::new();
    use std::fmt::Write as _;
    let _ = write!(
        informe,
        "  canalizacion {entraron} eventos de {AGENTES} agentes en {INQUILINOS} inquilinos\n\
         \x20               latencia por lote  p50 {} us · p95 {} us · p99 {} us\n\
         \x20               rendimiento        {eventos_por_s} eventos/s · total {total:?}\n\
         \x20               colas              orden {pico_en_vuelo} en vuelo · \
         deduplicacion {pico_dedupe} identificadores\n\
         \x20               memoria            {} MiB -> {} MiB (delta {} MiB)\n\
         \x20               cuentas            salieron {salieron} · rechazados {rechazados} \
         · duplicados {duplicados}",
        p(50),
        p(95),
        p(99),
        rss_antes / 1024,
        rss_despues / 1024,
        (rss_despues.saturating_sub(rss_antes)) / 1024,
    );

    // LA COMPROBACION QUE JUSTIFICA LA PRUEBA: no se pierde nada en silencio.
    if entraron != salieron + rechazados + duplicados {
        let _ = write!(
            informe,
            "\n    \x1b[31mFALLO\x1b[0m: entraron {entraron} y se explican \
             {}: hay eventos perdidos EN SILENCIO",
            salieron + rechazados + duplicados
        );
        fallos += 1;
    } else {
        let _ = write!(
            informe,
            "\n    \x1b[32mOK\x1b[0m: cada evento que entro esta contado en la salida, \
             en el rechazo o en el duplicado"
        );
    }
    if p(99) > OBJETIVO_P99_US {
        let _ = write!(
            informe,
            "\n    \x1b[31mFALLO\x1b[0m: el p99 de {} us pasa del objetivo de {OBJETIVO_P99_US} us",
            p(99)
        );
        fallos += 1;
    }
    if pico_en_vuelo > aegis_pipeline::orden::MAX_EN_VUELO {
        let _ = write!(
            informe,
            "\n    \x1b[31mFALLO\x1b[0m: el reordenador crecio por encima de su cota"
        );
        fallos += 1;
    }
    (fallos, informe)
}

/// La telemetria de un agente: la mezcla que produce un endpoint de verdad.
fn telemetria_de(i: usize, ahora_ns: u64) -> Vec<Evento> {
    let inquilino = format!("inquilino-{:02}", i % INQUILINOS);
    let anfitrion = format!("maquina-{i:07}");
    let mut lote = Vec::with_capacity(EVENTOS_POR_AGENTE);

    for k in 0..EVENTOS_POR_AGENTE {
        // La mezcla real: mayoria de proceso y fichero, algo de red y
        // autenticacion, y una minoria de hallazgos, que son los que tienen
        // prioridad y los que NO pueden perderse.
        let (clase, origen, severidad, productor, mensaje) = match (i + k) % 10 {
            0..=3 => (
                Clase::ActividadDeProceso,
                Origen::Agente,
                Severidad::Info,
                "aegis-agent",
                format!("proceso creado: /usr/bin/python3 -c import os; os.system('id') [{i}]"),
            ),
            4..=6 => (
                Clase::ActividadDeFichero,
                Origen::Agente,
                Severidad::Info,
                "aegis-agent",
                format!("/var/lib/app/datos-{i}.db abierto para escritura por pid 4211"),
            ),
            7 => (
                Clase::ActividadDeRed,
                Origen::Journald,
                Severidad::Baja,
                "kernel",
                format!(
                    "SRC=10.1.{}.{} DST=203.0.113.9 PROTO=TCP SPT=4{i:04} DPT=443",
                    i % 250,
                    i % 200
                ),
            ),
            8 => (
                Clase::Autenticacion,
                Origen::Syslog3164,
                Severidad::Media,
                "sshd",
                format!(
                    "Failed password for operador from 198.51.100.{} port 5{i:04} ssh2",
                    i % 250
                ),
            ),
            _ => (
                Clase::HallazgoDeSeguridad,
                Origen::Agente,
                Severidad::Alta,
                "aegis-agent",
                format!("YARA Win.Trojan.Generic sobre /tmp/.cache-{i}"),
            ),
        };

        // La hora de ocurrencia se reparte como se reparte de verdad, y cada
        // caso ejercita una parte distinta de la canalizacion:
        //
        // * uno de cada mil agentes entrega el lote de un dia apagado, que es el
        //   caso que rompe cualquier canalizacion que ordene por llegada;
        // * la mitad de los eventos son RECIENTES —dentro de la ventana de
        //   gracia— y por tanto se quedan en el reordenador, que es lo unico que
        //   mide de verdad su profundidad de cola. Con todos los eventos viejos,
        //   el reordenador sale siempre a cero y la medida no diria nada.
        let (ocurrio_ns, reloj) = if i % 1000 == 0 {
            (
                ahora_ns - 24 * 3600 * SEG_NS + (k as u64) * 3600 * SEG_NS,
                ConfianzaReloj::DelOrigen,
            )
        } else if k % 2 == 0 {
            (
                ahora_ns - (k as u64 % 20) * SEG_NS,
                ConfianzaReloj::DelOrigen,
            )
        } else {
            (
                ahora_ns - 3600 * SEG_NS + (k as u64) * SEG_NS,
                ConfianzaReloj::DelOrigen,
            )
        };

        let mut campos = BTreeMap::new();
        campos.insert("pid".into(), Valor::Entero(4211 + i as i64 % 30000));
        campos.insert("usuario".into(), Valor::Texto("operador".into()));
        campos.insert(
            "ruta".into(),
            Valor::Texto(format!("/usr/lib/aegis/{i}/modulo.so")),
        );

        let mut e = Evento {
            version: VERSION,
            id: String::new(),
            ancla: format!("agente-{i:07}#{k}"),
            ocurrio_ns,
            observado_ns: ahora_ns,
            reloj,
            clase,
            resultado: ResultadoEvento::Desconocido,
            severidad,
            origen,
            anfitrion: anfitrion.clone(),
            inquilino: inquilino.clone(),
            productor: productor.to_string(),
            mensaje,
            campos,
            crudo: None,
        };
        e.sellar();
        lote.push(e);
    }
    lote
}

/// Memoria residente del proceso, en KiB.
///
/// Se lee de `/proc` porque es la unica cifra que no depende de lo que el
/// asignador diga que ha devuelto: lo que importa es lo que el nucleo tiene
/// reservado de verdad.
fn rss_kib() -> u64 {
    let Ok(texto) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for linea in texto.lines() {
        if let Some(v) = linea.strip_prefix("VmRSS:") {
            return v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}
