//! El motor Sigma del agente con telemetria de verdad (sin kernel).
//!
//! Dos partes:
//! 1. La traduccion evento -> categoria -> campos, con reglas SINTETICAS de
//!    valores inocuos: lo que se prueba es el adaptador, no un contenido.
//! 2. TODAS las reglas incluidas: sus eventos generados (aegis_sigma::generador)
//!    se convierten en eventos del kernel y pasan por el motor; el que dispara
//!    tiene que producir una señal con el id de la regla, y el que no, no.
//!    Un evento generado que la telemetria no puede producir (una IP a medias,
//!    un puerto no numerico) se cuenta y se lista como «no representable».

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aegis_agent::motores::sigma::MotorSigma;
use aegis_agent::motores::{EventoAgente, Identidad};
use aegis_agent::{ProcKey, TelemetryEvent};
use aegis_entidad::{Juicio, Motor as Firma};
use aegis_motor::{Dictamen, Motor, Plazo};
use aegis_sigma::compacta::{Campo, Categoria, Juego};
use aegis_sigma::contenido::{leer_presupuestos, prueba_de};
use aegis_sigma::generador::Evento;
use aegis_sigma::incluidas::{LINUX, PRESUPUESTOS};
use aegis_sigma::regla::Topes;

fn id() -> Identidad {
    Identidad::fija("pruebas-sigma")
}

fn plazo() -> Plazo {
    Plazo::desde_ahora(Duration::from_secs(1))
}

fn sintetica(nombre: &str, categoria: &str, deteccion: &str) -> String {
    format!(
        "title: Sintetica {nombre}\nid: {nombre}\nlogsource:\n    product: linux\n    \
         category: {categoria}\ndetection:\n{deteccion}level: medium\ntags:\n    - attack.t0000\n"
    )
}

fn motor(fuentes: &[String]) -> MotorSigma {
    let pares: Vec<(&str, &str)> = fuentes.iter().map(|f| ("s.yml", f.as_str())).collect();
    let juego = Juego::cargar(&pares, &Topes::default());
    assert!(juego.rechazos().is_empty(), "{:?}", juego.rechazos());
    MotorSigma::con_juego(juego)
}

fn exec(actor: u64, padre: u64, imagen: &str, linea: &str) -> TelemetryEvent {
    TelemetryEvent::Exec {
        actor: ProcKey(actor),
        pid: actor as u32,
        parent: ProcKey(padre),
        image: Arc::from(imagen),
        cmdline: Arc::from(linea),
        started_ns: 1,
        ts_ns: 1,
    }
}

fn pasar(m: &mut MotorSigma, ev: TelemetryEvent) -> Dictamen {
    m.evaluar(&EventoAgente::nuevo(ev, &id()), &plazo())
}

fn ids(d: &Dictamen) -> Vec<String> {
    match d {
        Dictamen::Senales(s) => s.iter().map(|x| x.porque.clone()).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn un_exec_que_casa_da_una_senal_sospechosa_con_id_y_titulo_una_vez() {
    let mut m = motor(&[sintetica(
        "sint-exec",
        "process_creation",
        "    sel:\n        Image|endswith: '/alfa'\n        CommandLine|contains: 'beta'\n    \
         condition: sel\n",
    )]);
    let d = pasar(&mut m, exec(10, 1, "/opt/prueba/alfa", "alfa beta"));
    let Dictamen::Senales(s) = &d else {
        panic!("{d:?}")
    };
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].juicio, Juicio::Sospechoso);
    assert_eq!(s[0].motor, Firma::Conductual);
    assert!(s[0].porque.contains("sint-exec"), "{}", s[0].porque);
    assert!(
        s[0].porque.contains("Sintetica sint-exec"),
        "{}",
        s[0].porque
    );
    assert!(s[0].porque.contains("attack.t0000"), "{}", s[0].porque);

    // El mismo proceso con la misma imagen no repite; otro proceso si.
    assert!(matches!(
        pasar(&mut m, exec(10, 1, "/opt/prueba/alfa", "alfa beta")),
        Dictamen::NoAplica
    ));
    assert_eq!(m.contadores().repetidos, 1);
    assert!(matches!(
        pasar(&mut m, exec(11, 1, "/opt/prueba/alfa", "alfa beta")),
        Dictamen::Senales(_)
    ));
    assert!(matches!(
        pasar(&mut m, exec(12, 1, "/opt/prueba/alfa", "alfa gamma")),
        Dictamen::NoAplica
    ));
}

#[test]
fn el_padre_sale_del_contexto_y_su_ausencia_se_cuenta() {
    let mut m = motor(&[sintetica(
        "sint-padre",
        "process_creation",
        "    padre:\n        ParentImage|endswith: '/delta'\n    hijo:\n        \
         Image|endswith: '/epsilon'\n    condition: padre and hijo\n",
    )]);
    let _ = pasar(&mut m, exec(20, 1, "/opt/prueba/delta", "delta"));
    let d = pasar(&mut m, exec(21, 20, "/opt/prueba/epsilon", "epsilon"));
    assert!(ids(&d).iter().any(|p| p.contains("sint-padre")), "{d:?}");

    // Un hijo de un proceso que el agente no vio ejecutar: sin ParentImage.
    let antes = m.contadores().sin_padre;
    let d = pasar(&mut m, exec(22, 999, "/opt/prueba/epsilon", "epsilon"));
    assert!(matches!(d, Dictamen::NoAplica), "{d:?}");
    assert_eq!(m.contadores().sin_padre, antes + 1);
}

#[test]
fn escrituras_y_renombrados_son_file_event_con_la_imagen_del_actor() {
    let mut m = motor(&[sintetica(
        "sint-fichero",
        "file_event",
        "    sel:\n        Image|endswith: '/zeta'\n        \
         TargetFilename|startswith: '/opt/prueba/datos/'\n    condition: sel\n",
    )]);
    let _ = pasar(&mut m, exec(30, 1, "/opt/prueba/zeta", "zeta"));
    let escritura = TelemetryEvent::FileWrite {
        actor: ProcKey(30),
        pid: 30,
        path: Arc::from("/opt/prueba/datos/uno.conf"),
        flags: 0o1101,
        ts_ns: 2,
    };
    assert!(ids(&pasar(&mut m, escritura))
        .iter()
        .any(|p| p.contains("sint-fichero")));

    let _ = pasar(&mut m, exec(31, 1, "/opt/prueba/zeta", "zeta"));
    let renombrado = TelemetryEvent::FileRename {
        actor: ProcKey(31),
        pid: 31,
        from: Arc::from("/opt/prueba/tmp/dos"),
        to: Arc::from("/opt/prueba/datos/dos.conf"),
        ts_ns: 3,
    };
    assert!(ids(&pasar(&mut m, renombrado))
        .iter()
        .any(|p| p.contains("sint-fichero")));

    // Tras el Exit, el actor ya no tiene contexto: sin Image, no casa.
    let _ = pasar(
        &mut m,
        TelemetryEvent::Exit {
            actor: ProcKey(30),
            ts_ns: 4,
        },
    );
    let otra = TelemetryEvent::FileWrite {
        actor: ProcKey(30),
        pid: 30,
        path: Arc::from("/opt/prueba/datos/tres.conf"),
        flags: 0o1101,
        ts_ns: 5,
    };
    assert!(matches!(pasar(&mut m, otra), Dictamen::NoAplica));
    assert!(m.contadores().sin_imagen >= 1);
}

#[test]
fn una_conexion_es_network_connection_con_ip_y_puerto_como_texto() {
    let mut m = motor(&[sintetica(
        "sint-red",
        "network_connection",
        "    sel:\n        DestinationIp|startswith: '192.0.2.'\n        \
         DestinationPort: 50001\n        Initiated: 'true'\n        \
         DestinationIsIpv6: 'false'\n    condition: sel\n",
    )]);
    let conexion = |puerto: u16| {
        let mut d = [0u8; 16];
        d[..4].copy_from_slice(&[192, 0, 2, 10]);
        TelemetryEvent::NetConnect {
            actor: ProcKey(40),
            pid: 40,
            daddr: d,
            dport: puerto,
            family: 2,
            loopback: false,
            private_dst: false,
            ts_ns: 6,
        }
    };
    assert!(matches!(pasar(&mut m, conexion(50002)), Dictamen::NoAplica));
    assert!(ids(&pasar(&mut m, conexion(50001)))
        .iter()
        .any(|p| p.contains("sint-red")));
}

#[test]
fn el_contexto_de_procesos_esta_acotado_y_se_suelta_bajo_presion() {
    let mut m = motor(&[sintetica(
        "sint-cota",
        "process_creation",
        "    sel:\n        Image|endswith: '/nunca-casa'\n    condition: sel\n",
    )]);
    let tope = aegis_agent::motores::sigma::MAX_PROCESOS as u64;
    for k in 0..tope + 5 {
        let _ = pasar(&mut m, exec(1_000 + k, 1, "/opt/prueba/x", "x"));
    }
    assert_eq!(m.procesos() as u64, tope);
    assert_eq!(m.contadores().procesos_descartados, 5);
    assert!(m.memoria() <= m.ficha().presupuesto.memoria);
    m.aligerar();
    assert_eq!(m.procesos(), 0);
}

/// Un evento generado, como eventos del kernel. `Err` si la telemetria no
/// puede producirlo.
fn a_telemetria(
    categoria: Categoria,
    ev: &Evento,
    base: u64,
) -> Result<Vec<TelemetryEvent>, String> {
    let texto = |c: Campo| -> Result<Option<String>, String> {
        ev.get(&c)
            .map(|v| {
                String::from_utf8(v.clone()).map_err(|_| format!("{} no es UTF-8", c.nombre()))
            })
            .transpose()
    };
    let pid = match texto(Campo::Pid)? {
        Some(p) => p
            .trim()
            .parse::<u32>()
            .map_err(|_| "ProcessId no numerico".to_string())?,
        None => base as u32,
    };
    let actor = base;
    let mut salida = Vec::new();
    let preparar_imagen = |salida: &mut Vec<TelemetryEvent>| -> Result<(), String> {
        if let Some(img) = texto(Campo::Imagen)? {
            salida.push(exec(actor, base + 9, &img, ""));
        }
        Ok(())
    };
    match categoria {
        Categoria::CreacionProceso => {
            let padre_img = texto(Campo::ImagenPadre)?;
            let padre_linea = texto(Campo::LineaComandosPadre)?;
            let padre = if padre_img.is_some() || padre_linea.is_some() {
                salida.push(exec(
                    base + 1,
                    base + 8,
                    padre_img.as_deref().unwrap_or(""),
                    padre_linea.as_deref().unwrap_or(""),
                ));
                base + 1
            } else {
                base + 9
            };
            let img = texto(Campo::Imagen)?.unwrap_or_default();
            let linea = texto(Campo::LineaComandos)?.unwrap_or_default();
            let mut e = exec(actor, padre, &img, &linea);
            if let TelemetryEvent::Exec { pid: p, .. } = &mut e {
                *p = pid;
            }
            salida.push(e);
        }
        Categoria::EventoFichero => {
            preparar_imagen(&mut salida)?;
            let destino = texto(Campo::FicheroDestino)?.unwrap_or_default();
            salida.push(match texto(Campo::FicheroOrigen)? {
                Some(o) => TelemetryEvent::FileRename {
                    actor: ProcKey(actor),
                    pid,
                    from: Arc::from(o.as_str()),
                    to: Arc::from(destino.as_str()),
                    ts_ns: 2,
                },
                None => TelemetryEvent::FileWrite {
                    actor: ProcKey(actor),
                    pid,
                    path: Arc::from(destino.as_str()),
                    flags: 0o1101,
                    ts_ns: 2,
                },
            });
        }
        Categoria::ConexionRed => {
            preparar_imagen(&mut salida)?;
            let ip: IpAddr = match texto(Campo::IpDestino)? {
                Some(t) => t
                    .parse()
                    .map_err(|_| format!("DestinationIp «{t}» no es una IP"))?,
                None => IpAddr::from([0, 0, 0, 0]),
            };
            let puerto = match texto(Campo::PuertoDestino)? {
                Some(t) => t
                    .parse::<u16>()
                    .map_err(|_| format!("DestinationPort «{t}»"))?,
                None => 0,
            };
            if let Some(t) = texto(Campo::Iniciada)? {
                if !t.eq_ignore_ascii_case("true") {
                    return Err(format!(
                        "Initiated «{t}»: el agente solo ve conexiones salientes"
                    ));
                }
            }
            if let Some(t) = texto(Campo::DestinoIpv6)? {
                if !t.eq_ignore_ascii_case(if ip.is_ipv6() { "true" } else { "false" }) {
                    return Err(format!("DestinationIsIpv6 «{t}» no cuadra con {ip}"));
                }
            }
            let (daddr, family) = match ip {
                IpAddr::V4(v4) => {
                    let mut d = [0u8; 16];
                    d[..4].copy_from_slice(&v4.octets());
                    (d, 2)
                }
                IpAddr::V6(v6) => (v6.octets(), 10),
            };
            salida.push(TelemetryEvent::NetConnect {
                actor: ProcKey(actor),
                pid,
                daddr,
                dport: puerto,
                family,
                loopback: false,
                private_dst: false,
                ts_ns: 3,
            });
        }
    }
    Ok(salida)
}

/// Pasa los eventos y devuelve si el ULTIMO (el protagonista) dio una señal de
/// la regla.
fn dispara_la_regla(m: &mut MotorSigma, eventos: Vec<TelemetryEvent>, regla: &str) -> bool {
    let mut ultimo = Dictamen::NoAplica;
    for e in eventos {
        ultimo = pasar(m, e);
    }
    ids(&ultimo).iter().any(|p| p.contains(regla))
}

#[test]
fn cada_regla_incluida_dispara_con_su_evento_y_calla_con_el_otro() {
    // Sobre el juego cargado y no `LINUX.is_empty()` (clippy: const_is_empty).
    // Los rechazos de las incluidas los caza la prueba de aegis-sigma.
    let juego = Juego::cargar(LINUX, &Topes::default());
    if juego.is_empty() && juego.rechazos().is_empty() {
        eprintln!("sin reglas incluidas: SIN CONTENIDO, nada que pasar por el motor");
        return;
    }
    let presupuestos = leer_presupuestos(PRESUPUESTOS).expect("PRESUPUESTOS");
    let mut m = MotorSigma::incluidas();
    let mut fallos = Vec::new();
    let mut no_representables = BTreeMap::new();
    let mut base = 1_000_000u64;
    for c in Categoria::TODAS {
        for r in juego.reglas(c) {
            let p = match prueba_de(r, &presupuestos) {
                Ok(p) => p,
                Err(e) => {
                    fallos.push(format!("{}: [{}] {}", r.id(), e.codigo, e.detalle));
                    continue;
                }
            };
            for (positivo, ev) in [(true, &p.dispara), (false, &p.no_dispara)] {
                base += 16;
                match a_telemetria(c, ev, base) {
                    Ok(eventos) => {
                        if dispara_la_regla(&mut m, eventos, r.id()) != positivo {
                            fallos.push(format!(
                                "{}: el evento {} no se comporta en el motor",
                                r.id(),
                                if positivo {
                                    "que dispara"
                                } else {
                                    "que no dispara"
                                }
                            ));
                        }
                    }
                    Err(motivo) => {
                        no_representables.insert(format!("{} ({})", r.id(), positivo), motivo);
                    }
                }
            }
        }
    }
    println!(
        "{} reglas; {} eventos no representables por la telemetria:",
        juego.len(),
        no_representables.len()
    );
    for (k, v) in &no_representables {
        println!("  {k}: {v}");
    }
    assert!(
        fallos.is_empty(),
        "{} fallo(s):\n{}",
        fallos.len(),
        fallos.join("\n")
    );
}
