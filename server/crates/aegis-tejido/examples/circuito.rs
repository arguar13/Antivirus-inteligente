//! El circuito completo de AegisCore, de extremo a extremo, en una ejecucion.
//!
//! Lo que una prueba unitaria no puede enseñar, porque lo que falla es la
//! COMBINACION de las piezas:
//!
//! 1. **El inventario**: quien produce veredictos hoy, con que vocabulario y sobre
//!    que entidad — recorrido y comprobado, no declarado.
//! 2. **El circuito**: once subsistemas encadenados sobre **un solo
//!    identificador**, de un paquete en la red a un indicador repartido entre
//!    agentes aislados.
//! 3. **El linaje**: la cadena red → fichero → proceso → identidad → respuesta,
//!    consultable en las dos direcciones.
//! 4. **La ruta caliente**: la latencia del camino que corre en el endpoint, medida
//!    contra la de antes de unificar.
//! 5. **El determinismo**: dos recorridos sobre los mismos hechos dan exactamente
//!    lo mismo, frase incluida.
//!
//! Si alguna se rompe, el proceso termina con codigo distinto de cero y
//! `tools/verificar-fabric.sh` falla.

use std::collections::BTreeSet;
use std::time::Instant;

use aegis_entidad::arbitro::{arbitrar, Juicio, Resultado, Senal};
use aegis_entidad::entidad::{self, Clase};
use aegis_entidad::escala::{Confianza, Motor, Plano, Severidad};
use aegis_invitado::protocolo::{AccionFichero, AccionProceso, AccionRed, Evento, Trama};
use aegis_tejido::circuito::{self, enriquecer_sin_salida, recorrer, Recorrido, SEG, T0};
use aegis_tejido::inventario;

fn main() {
    println!("AegisFabric · un solo modelo de entidad, un solo veredicto");
    println!();

    let mut fallos = 0;
    fallos += fase_inventario();
    fallos += fase_circuito();
    fallos += fase_linaje();
    fallos += fase_ruta_caliente();
    fallos += fase_determinismo();

    println!();
    if fallos == 0 {
        println!("las cinco propiedades se sostienen sobre el producto entero");
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

/// Las tramas del agente invitado que alimentan la detonacion.
fn tramas() -> Vec<Vec<u8>> {
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

/// Recorre el circuito entero.
fn correr() -> Recorrido {
    let dir = tempfile::tempdir().expect("directorio temporal");
    let sha = circuito::resumen_en_transito().expect("el disector extrae el fichero");
    let enriquecimiento = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(enriquecer_sin_salida(&sha, T0 + 135 * SEG));
    recorrer(dir.path(), &tramas(), &enriquecimiento).expect("el circuito completo recorre")
}

// ─── 1. EL INVENTARIO ──────────────────────────────────────────────────────────

fn fase_inventario() -> usize {
    println!("  [1/5] el inventario: quien produce veredictos, y sobre que entidad");
    let mut fallos = 0;

    print!("{}", inventario::informe());

    fallos += exigir(
        inventario::CENSO.len() == Motor::todos().len(),
        &format!(
            "los {} motores de la escala tienen fila declarada",
            Motor::todos().len()
        ),
    );

    let planos_poblados = inventario::motores_por_plano()
        .iter()
        .filter(|(_, n)| *n > 0)
        .count();
    fallos += exigir(
        planos_poblados == Plano::todos().len(),
        &format!("los {planos_poblados} planos de observacion tienen al menos un motor"),
    );

    // LA FILA QUE MAS DICE. El estatico y el modelo del endpoint comparten la
    // entrada entera: ponerlos en planos distintos convertiria «coinciden» en
    // corroboracion, que es la falsa confirmacion mas facil de fabricar.
    fallos += exigir(
        Motor::Estatico.plano() == Motor::Aprendizaje.plano(),
        "el estatico y el modelo del endpoint comparten plano, no se corroboran",
    );

    // Y lo externo —reputacion y enjambre— es UN plano, no dos fuentes.
    let externos = inventario::CENSO
        .iter()
        .filter(|f| f.plano() == Plano::Externo)
        .count();
    fallos += exigir(
        externos == 2 && Motor::Intel.plano() == Motor::Enjambre.plano(),
        "toda la inteligencia de fuera cae en un solo plano",
    );

    println!();
    fallos
}

// ─── 2. EL CIRCUITO ────────────────────────────────────────────────────────────

fn fase_circuito() -> usize {
    println!("  [2/5] el circuito: once subsistemas, un identificador");
    let mut fallos = 0;

    let r = correr();
    print!("{}", r.informe());
    println!("      entidad: {}", r.contenido.texto());
    println!("      veredicto: {}", r.veredicto.resumen());

    fallos += exigir(
        r.paradas.len() == circuito::PARADAS_ESPERADAS.len(),
        &format!("las {} paradas se recorren", r.paradas.len()),
    );

    // LA PROPIEDAD QUE JUSTIFICA LA FASE.
    let del_contenido = r.paradas_del_contenido();
    let unicos: BTreeSet<String> = del_contenido.iter().map(|p| p.entidad.texto()).collect();
    fallos += exigir(
        unicos.len() == 1 && del_contenido.len() >= 7,
        &format!(
            "{} paradas hablan de la misma entidad, con UN identificador",
            del_contenido.len()
        ),
    );

    fallos += exigir(
        r.veredicto.resultado == Resultado::Malicioso && r.veredicto.corroboracion() >= 2,
        &format!(
            "el veredicto se sostiene en {} plano(s), no en uno solo",
            r.veredicto.corroboracion()
        ),
    );

    fallos += exigir(
        !r.veredicto.porque.is_empty() && r.veredicto.senales.len() >= 3,
        &format!(
            "el veredicto lleva su frase y las {} señales que lo sostienen",
            r.veredicto.senales.len()
        ),
    );

    for s in &r.veredicto.senales {
        println!(
            "        {:<12} {:<14} {:<8} {}",
            s.motor.nombre(),
            s.juicio.nombre(),
            s.confianza.to_string(),
            s.porque
        );
    }

    // LOS FRENOS SE VEN. El camino mas probable acaba en el controlador de
    // dominio, que esta protegido: el motor corta un salto antes, en la identidad,
    // con la accion minima que cierra ese salto.
    let contuvo_identidad = match &r.contencion {
        aegis_predict::contencion::Veredicto::Contener { sujeto, accion, .. } => {
            println!("      contencion: «{sujeto}» → {accion:?}");
            sujeto != "dc-01.corp.ejemplo" && sujeto.starts_with("CORP\\")
        }
        otro => {
            println!("      contencion: {otro:?}");
            false
        }
    };
    fallos += exigir(
        contuvo_identidad,
        "se corta la identidad, y el activo protegido no se toca jamas",
    );

    fallos += exigir(
        r.corroborados >= 1,
        "el indicador llega al agente aislado, sin plano de control",
    );

    println!();
    fallos
}

// ─── 3. EL LINAJE ──────────────────────────────────────────────────────────────

fn fase_linaje() -> usize {
    println!("  [3/5] el linaje: red → fichero → proceso → identidad → respuesta");
    let mut fallos = 0;

    let r = correr();
    let adelante = r.linaje.adelante(&r.raiz_del_linaje);
    println!("      hacia adelante: {}", adelante.resumen());

    let atras = r.linaje.atras(&r.contenido);
    println!("      hacia atras desde el fichero: {}", atras.resumen());

    let causa = r.linaje.causa(&r.contenido);
    println!("      solo lo que explica la causa: {}", causa.resumen());

    let clases: BTreeSet<&str> = adelante.por_clase().keys().copied().collect();
    let esperadas = [
        Clase::Flujo,
        Clase::Contenido,
        Clase::Proceso,
        Clase::Cuenta,
        Clase::Maquina,
        Clase::Ubicacion,
        Clase::Artefacto,
    ];
    fallos += exigir(
        esperadas.iter().all(|c| clases.contains(c.prefijo())),
        &format!("la cadena atraviesa {} clases de entidad", clases.len()),
    );

    fallos += exigir(
        adelante.cruza_planos() && adelante.truncado.is_none(),
        "el recorrido cruza planos y no se corto",
    );

    // LA MAQUINA NO PROPAGA CAUSA. Que dos ficheros esten en la misma maquina no
    // relaciona lo que hacen: si `ResideEn` propagara, preguntar por cualquier
    // cosa devolveria el equipo entero y el linaje dejaria de servir.
    let con_maquina = r.linaje.adelante(&entidad::maquina(circuito::MAQUINA));
    fallos += exigir(
        causa.entidades().len() < adelante.entidades().len(),
        "el recorrido de causa es mas estrecho que el de alcance",
    );
    let _ = con_maquina;

    println!("      observadores del linaje:");
    for (quien, cuantas) in r.linaje.observadores() {
        println!("        {quien:<14} {cuantas} arista(s)");
    }

    println!();
    fallos
}

// ─── 4. LA RUTA CALIENTE ───────────────────────────────────────────────────────

/// El numero de decisiones que se cronometran en cada pasada.
const DECISIONES: usize = 200_000;

/// Cuantas pasadas se cronometran; se queda la mas rapida.
const PASADAS: usize = 5;

/// Nanosegundos por iteracion de la pasada MAS RAPIDA de `f`.
///
/// Se toma el minimo y no la media porque lo que se quiere medir es lo que cuesta
/// el codigo, y lo unico que puede hacer una pasada mas lenta que ese coste es que
/// otra cosa le quite la CPU: una interrupcion, otro proceso compilando al lado.
/// Ninguna pasada puede salir MAS rapida que el codigo, asi que el minimo es la
/// cifra que no depende de lo cargada que este la maquina en ese momento.
fn ns_por_iteracion(mut f: impl FnMut()) -> u128 {
    (0..PASADAS)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..DECISIONES {
                f();
            }
            t.elapsed().as_nanos() / DECISIONES as u128
        })
        .min()
        .unwrap_or(u128::MAX)
}

fn fase_ruta_caliente() -> usize {
    println!("  [4/5] la ruta caliente: unificar no puede haber costado latencia");
    let mut fallos = 0;

    let sha = "c".repeat(64);
    let e = entidad::contenido(&sha);

    // Las señales de un caso corriente en el endpoint: el estatico, el modelo y el
    // conductual. No es el caso del circuito —ese lleva detonacion, que ocurre en
    // el servidor—: es lo que de verdad corre en cada maquina, muchas veces.
    let senales = vec![
        Senal::nueva(
            Motor::Estatico,
            e.clone(),
            Juicio::Malicioso,
            Severidad::Alta,
            Confianza::ALTA,
            "el corpus reconoce el fichero exacto",
            T0,
        ),
        Senal::nueva(
            Motor::Aprendizaje,
            e.clone(),
            Juicio::Sospechoso,
            Severidad::Media,
            Confianza::MEDIA,
            "el modelo del endpoint puntua alto",
            T0,
        ),
        Senal::nueva(
            Motor::Conductual,
            e.clone(),
            Juicio::Malicioso,
            Severidad::Alta,
            Confianza::ALTA,
            "el proceso escribio en el arranque y borro el registro",
            T0,
        ),
    ];

    // ANTES: cada motor decidia solo y el consumidor se quedaba con el peor. Es lo
    // que habia, y es la referencia honesta contra la que medir.
    let mut suma = 0u64;
    let ns_antes = ns_por_iteracion(|| {
        let peor = senales
            .iter()
            .filter(|s| s.juicio.acusa())
            .map(|s| s.severidad)
            .max()
            .unwrap_or(Severidad::Info);
        suma = suma.wrapping_add(std::hint::black_box(peor) as u64);
    });

    // DESPUES: el arbitro unificado, con sus seis reglas, el recuento de planos y
    // la frase.
    let mut ultimo = Resultado::SinDatos;
    let ns_despues = ns_por_iteracion(|| {
        let v = std::hint::black_box(arbitrar(&e, &senales, T0 + SEG));
        ultimo = v.resultado;
        suma = suma.wrapping_add(v.confianza.centesimas().into());
    });

    println!("      antes  (peor severidad, sin explicacion): {ns_antes:>6} ns/decision");
    println!("      ahora  (arbitro con frase y planos):      {ns_despues:>6} ns/decision");
    println!(
        "      veredicto: {} · suma de control {suma}",
        ultimo.nombre()
    );

    // EL CRITERIO, DICHO ANTES DE MEDIR. El arbitro hace cosas que el maximo no
    // hacia —cuenta planos, acota por corroboracion, construye la frase y adjunta
    // las señales—, asi que no puede costar lo mismo. Lo que la fase promete es
    // que sigue siendo **despreciable frente al trabajo que ya habia**: la
    // deteccion que produce esas tres señales cuesta microsegundos por si sola.
    //
    // Cinco microsegundos por decision es el techo. A mil decisiones por segundo
    // —que es una maquina bajo ataque, no una en reposo— son 5 ms/s: cinco
    // milesimas del 1 % de una CPU.
    //
    // EL TECHO ES DEL BINARIO QUE SE DISTRIBUYE. Sin optimizar, el mismo arbitro
    // cuesta unas diez veces mas —medido en la maquina de integracion: ~600 ns
    // optimizado, entre 5 500 y 13 000 sin optimizar—, y juzgarlo asi hacia que
    // la propiedad pasara o fallara segun la maquina y el momento, sin que el
    // arbitro cambiara. Sobre un binario sin optimizar la cifra no dice nada del
    // producto: no se juzga, y tampoco se da por buena, se declara rota para que
    // nadie la lea como una medida. `tools/verificar-fabric.sh` lo ejecuta con
    // `--release`.
    const TECHO_NS: u128 = 5_000;
    if cfg!(debug_assertions) {
        fallos += exigir(
            false,
            "el techo de latencia solo se juzga sobre el binario optimizado: ejecutar con --release",
        );
    } else {
        fallos += exigir(
            ns_despues <= TECHO_NS,
            &format!("el arbitro decide en {ns_despues} ns, por debajo del techo de {TECHO_NS} ns"),
        );
    }

    // Y el resultado no es el mismo que el del maximo: el arbitro llega a
    // `Malicioso` **y** dice con cuantos planos, que es justo lo que el maximo no
    // podia decir.
    fallos += exigir(
        ultimo == Resultado::Malicioso,
        "el arbitro llega al mismo veredicto que el criterio de antes",
    );
    let v = arbitrar(&e, &senales, T0 + SEG);
    fallos += exigir(
        v.corroboracion() == 2,
        &format!(
            "y ademas dice que lo sostienen {} planos, no tres motores",
            v.corroboracion()
        ),
    );

    println!();
    fallos
}

// ─── 5. EL DETERMINISMO ────────────────────────────────────────────────────────

fn fase_determinismo() -> usize {
    println!("  [5/5] el determinismo: dos recorridos, el mismo informe");
    let mut fallos = 0;

    let a = correr();
    let b = correr();

    fallos += exigir(
        a.contenido == b.contenido,
        "el identificador de entidad es el mismo",
    );
    fallos += exigir(
        a.veredicto == b.veredicto,
        "el veredicto es el mismo, frase y señales incluidas",
    );
    fallos += exigir(a.informe() == b.informe(), "el informe es identico");

    // Y la entidad se puede volver a derivar desde el resumen, sin coordinacion:
    // dos observadores con el mismo fichero llegan al mismo nombre sin hablar.
    fallos += exigir(
        a.contenido == entidad::contenido(&a.sha256_del_contenido),
        "la entidad se deriva del resumen, no se asigna",
    );

    println!();
    fallos
}
