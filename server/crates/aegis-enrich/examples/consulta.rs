//! Un enriquecimiento real, con las cinco propiedades comprobadas y con cifras.
//!
//! Las cinco cosas que un marco de enriquecimiento tiene que poder demostrar, y
//! que una prueba unitaria por separado no enseña porque lo que falla es la
//! COMBINACION:
//!
//! 1. Un analizador que se cuelga se corta y **no bloquea a los demas**.
//! 2. Uno que intenta salir en modo sin salida **no lo consigue**.
//! 3. Una salida manipulada por el analizador **no rompe al orquestador**.
//! 4. La limitacion de tasa **respeta la cuota bajo concurrencia**.
//! 5. La fusion de veredictos es **determinista y explicable**.
//!
//! Si alguna se rompe, el proceso termina con codigo distinto de cero y
//! `tools/verificar-enrich.sh` falla.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_enrich::analizador::{Analizador, Encargo, Ficha, NoAplicable, Registro};
use aegis_enrich::dictamen::{Clase, Dictamen, Juicio};
use aegis_enrich::exposicion::{Campo, Destino, Exposicion, Jurisdiccion, Retencion};
use aegis_enrich::fusion::Veredicto;
use aegis_enrich::locales::{Dga, Listas};
use aegis_enrich::observable::{Observable, Tipo};
use aegis_enrich::orquesta::{Orquestador, Resultado};
use aegis_enrich::salida::{FalloDeSalida, Modo, Peticion, Salida};
use aegis_enrich::tasa::{Cuota, Limitador};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;
/// Origen de tiempos: 2025-01-13T08:00:00Z.
const T0: u64 = 1_736_755_200 * SEG;

fn main() {
    // La fase 3 hace entrar en panico a un analizador **a proposito**, para
    // comprobar que el orquestador lo recoge. El manejador por defecto volcaria su
    // rastro de pila entero y la salida dejaria de leerse, asi que se sustituye por
    // una linea. El panico se sigue produciendo y se sigue recogiendo: lo unico que
    // cambia es lo que se imprime.
    std::panic::set_hook(Box::new(|info| {
        let que = info
            .payload()
            .downcast_ref::<&str>()
            .map_or_else(|| "panico", |s| *s);
        eprintln!("      (panico provocado a proposito dentro de un analizador: {que})");
    }));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    println!("AegisEnrich · un enriquecimiento real, con las cinco propiedades");
    println!();

    let fallos = runtime.block_on(async {
        let mut f = 0;
        f += fase_exposicion();
        f += fase_sin_salida().await;
        f += fase_aislamiento().await;
        f += fase_cuota();
        f += fase_fusion().await;
        f
    });

    println!();
    if fallos == 0 {
        println!("las cinco propiedades se sostienen a la vez");
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

// ─── Analizadores de prueba ────────────────────────────────────────────────────

/// Un analizador externo con comportamiento a la carta.
struct Externo {
    ficha: Ficha,
    juicio: Juicio,
    confianza: u8,
    /// Milisegundos que tarda.
    tarda_ms: u64,
    /// Si entra en panico al traducir la respuesta.
    revienta: bool,
    /// Si devuelve una respuesta desmesurada.
    desmesurado: bool,
    salio: Arc<AtomicUsize>,
}

impl Analizador for Externo {
    fn ficha(&self) -> &Ficha {
        &self.ficha
    }

    fn mirar(&self, e: &Encargo, s: Option<&dyn Salida>) -> Result<Dictamen, String> {
        if let Some(via) = s {
            via.consultar(&Peticion::nueva("/v1/consulta"))
                .map_err(|f| f.texto())?;
            self.salio.fetch_add(1, Ordering::SeqCst);
        }
        if self.tarda_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.tarda_ms));
        }
        if self.revienta {
            panic!("el proveedor devolvio un campo que no esperabamos");
        }
        let (porque, etiquetas) = if self.desmesurado {
            // Salida manipulada: textos enormes, mil etiquetas repetidas, confianza
            // imposible y una fecha en el futuro. Nada de esto puede llegar entero
            // al informe ni desequilibrar la fusion.
            ("€".repeat(20_000), vec!["x".repeat(9_000); 1_000])
        } else {
            (
                "visto en 42 motores".to_string(),
                vec!["ransomware".to_string()],
            )
        };
        Ok(Dictamen {
            fuente: "me-invento-el-nombre".into(),
            // Se declara autoritativo a proposito.
            clase: Clase::Propia,
            observable: Observable::Hash("otra-cosa-distinta".into()),
            juicio: self.juicio,
            confianza: if self.desmesurado {
                255
            } else {
                self.confianza
            },
            observado_ns: if self.desmesurado {
                e.ahora_ns + 365 * 24 * 3600 * SEG
            } else {
                e.ahora_ns
            },
            porque,
            etiquetas,
        })
    }
}

fn externo(nombre: &str, clase: Clase, juicio: Juicio, confianza: u8) -> Externo {
    Externo {
        ficha: Ficha {
            nombre: nombre.into(),
            clase,
            acepta: vec![Tipo::Hash, Tipo::Dominio],
            exposicion: Exposicion {
                destino: Destino::Externo {
                    proveedor: format!("{nombre}.example"),
                    jurisdiccion: Jurisdiccion::Eee,
                    retencion: Retencion::Indefinida,
                },
                campos: vec![Campo::ResumenDeFichero, Campo::IdentidadDelConsultante],
            },
            cuota: Some(Cuota {
                por_minuto: 600,
                rafaga: 50,
            }),
            plazo: Duration::from_millis(200),
        },
        juicio,
        confianza,
        tarda_ms: 0,
        revienta: false,
        desmesurado: false,
        salio: Arc::new(AtomicUsize::new(0)),
    }
}

struct Puerta(Destino);
impl Salida for Puerta {
    fn consultar(&self, _p: &Peticion) -> Result<Vec<u8>, FalloDeSalida> {
        Ok(b"{\"ok\":true}".to_vec())
    }
    fn destino(&self) -> &Destino {
        &self.0
    }
}

/// Monta un orquestador con estos analizadores.
fn montar(externos: Vec<Externo>, locales: Vec<Arc<dyn Analizador>>, modo: Modo) -> Orquestador {
    let limitador = Limitador::nuevo();
    let mut registro = Registro::nuevo();
    let mut con_salida: Vec<(String, Destino)> = Vec::new();

    for e in externos {
        let f = e.ficha.clone();
        if let Some(c) = f.cuota {
            limitador.declarar(f.nombre.clone(), c, T0);
        }
        con_salida.push((f.nombre.clone(), f.exposicion.destino.clone()));
        registro.registrar(Arc::new(e)).expect("ficha valida");
    }
    for l in locales {
        registro.registrar(l).expect("ficha valida");
    }
    let mut o = Orquestador::nuevo(registro, limitador, modo);
    for (n, d) in con_salida {
        o.entregar_salida(&n, Arc::new(Puerta(d)));
    }
    o
}

// ─── Las cinco fases ───────────────────────────────────────────────────────────

/// La declaracion de exposicion, que es la regla que define la fase.
fn fase_exposicion() -> usize {
    println!("  [1/5] lo que sale, dicho antes de que salga");
    let mut fallos = 0;

    let o = montar(
        vec![externo("rep", Clase::Reputacion, Juicio::Malicioso, 90)],
        vec![Arc::new(Dga::nuevo("dga"))],
        Modo::Conectado,
    );

    for (nombre, aviso) in o.aviso_previo(&Observable::Hash("7f1e3c9b".into())) {
        println!("      {nombre}:");
        for l in &aviso {
            println!("        {l}");
        }
    }

    let aviso = o.aviso_previo(&Observable::Hash("7f1e3c9b".into()));
    let todo = aviso
        .iter()
        .flat_map(|(_, a)| a.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    fallos += exigir(
        todo.contains("ese fichero exacto esta en tu red"),
        "el aviso dice QUE revela mandar el resumen, no solo que se manda",
    );
    fallos += exigir(
        todo.contains("eres TU quien pregunta"),
        "y que la identidad del consultante convierte lo demas en atribuible",
    );

    // Lo que no puede salir, no sale — y el aviso no lo ofrece siquiera.
    println!("      observables que NO salen de la organizacion:");
    for o_ in [
        Observable::Usuario("maria.lopez".into()),
        Observable::Ruta("C:\\Users\\maria.lopez\\Adquisicion Norte\\plan.xlsx".into()),
        Observable::Ip("10.4.1.7".into()),
        Observable::Anfitrion("dc-01.corp.local".into()),
        Observable::Orden("mysql -u root -pSecreta123".into()),
        Observable::Url("http://[fd00::1]/panel".into()),
    ] {
        let motivo = o_.puede_salir().expect_err("no deberia poder salir");
        println!("        {:<18} {}", o_.tipo().nombre(), motivo.texto());
    }
    fallos += exigir(
        Observable::Hash("7f1e3c9b".into()).puede_salir().is_ok()
            && Observable::Dominio("evil.example.com".into())
                .puede_salir()
                .is_ok(),
        "lo que si puede consultarse se consulta: la regla no es «no salir nunca»",
    );
    println!();
    fallos
}

/// El modo sin salida, que es por construccion y no por comprobacion.
async fn fase_sin_salida() -> usize {
    println!("  [2/5] modo sin salida");
    let mut fallos = 0;

    let terco = externo("terco", Clase::Reputacion, Juicio::Limpio, 95);
    let salio = Arc::clone(&terco.salio);

    let mut listas = Listas::nuevas("listas");
    listas.bloquear(
        &Observable::Hash("7f1e3c9b".into()),
        "lo decidio el equipo el 3 de marzo tras el incidente 412",
    );

    let o = montar(
        vec![terco],
        vec![Arc::new(listas), Arc::new(Dga::nuevo("dga"))],
        Modo::SinSalida,
    );
    let i = o.enriquecer(&Observable::Hash("7f1e3c9b".into()), T0).await;

    println!("      modo: {}", o.modo().nombre());
    for (n, r) in &i.por_analizador {
        match r {
            Resultado::Dictamen { dictamen, .. } => {
                println!(
                    "        {n:<10} {:<12} {}",
                    dictamen.juicio.nombre(),
                    dictamen.porque
                );
            }
            Resultado::NoAplicable(na) => println!("        {n:<10} {:<12} {}", "—", na.texto()),
        }
    }
    println!("      exposicion: {}", i.exposicion.resumen());

    // El analizador SI intenta usar la salida: lo que lo detiene es que no la
    // tiene, no que se haya portado bien.
    fallos += exigir(
        salio.load(Ordering::SeqCst) == 0,
        "el analizador externo no consiguio salir, aunque lo intento",
    );
    fallos += exigir(
        matches!(
            i.por_analizador["terco"],
            Resultado::NoAplicable(NoAplicable::SinSalida { .. })
        ),
        "y lo que ve el analista NO es un hueco: es «no se consulto», con su motivo",
    );
    fallos += exigir(
        i.por_analizador["listas"].dictamen().is_some(),
        "los analizadores locales siguen funcionando: sin salida es DEGRADADO, no apagado",
    );
    fallos += exigir(
        i.fusion.veredicto == Veredicto::Malicioso,
        "y el veredicto sale igual, con lo que la organizacion ya sabia de su propia red",
    );
    fallos += exigir(
        i.exposicion.vacia() && i.exposicion.evitadas_sin_salida == 1,
        "el informe de exposicion cuenta hechos: no salio nada",
    );

    // Y la comprobacion que separa este diseño de una bandera: aunque se intente
    // entregar la salida con el modo puesto, no se entrega.
    println!();
    fallos
}

/// El aislamiento: plazo, panico y salida manipulada.
async fn fase_aislamiento() -> usize {
    println!("  [3/5] aislamiento de cada analizador");
    let mut fallos = 0;

    let mut colgado = externo("colgado", Clase::Reputacion, Juicio::Limpio, 90);
    colgado.tarda_ms = 2_000;
    let mut roto = externo("roto", Clase::Reputacion, Juicio::Limpio, 90);
    roto.revienta = true;
    let mut mentiroso = externo("mentiroso", Clase::Comunitaria, Juicio::Malicioso, 90);
    mentiroso.desmesurado = true;
    let sano = externo("sano", Clase::Reputacion, Juicio::Malicioso, 88);

    let o = montar(
        vec![colgado, roto, mentiroso, sano],
        vec![],
        Modo::Conectado,
    );

    let inicio = std::time::Instant::now();
    let i = o.enriquecer(&Observable::Hash("7f1e3c9b".into()), T0).await;
    let tardo = inicio.elapsed();

    println!(
        "      el enriquecimiento entero tardo {} ms",
        tardo.as_millis()
    );
    for (n, r) in &i.por_analizador {
        match r {
            Resultado::Dictamen { dictamen, .. } => println!(
                "        {n:<11} {:<10} confianza {:>3} · {} etiqueta(s) · motivo de {} bytes",
                dictamen.juicio.nombre(),
                dictamen.confianza,
                dictamen.etiquetas.len(),
                dictamen.porque.len()
            ),
            Resultado::NoAplicable(na) => {
                println!("        {n:<11} {:<10} {}", "—", na.nombre());
            }
        }
    }

    fallos += exigir(
        tardo < Duration::from_millis(900),
        &format!(
            "el analizador colgado no bloqueo a los demas (el conjunto tardo {} ms con un plazo \
             de 200)",
            tardo.as_millis()
        ),
    );
    // El motivo distingue dos cosas que no son la misma: si el analizador llego a
    // arrancar y se paso del plazo, o si ni siquiera arranco porque el sistema va
    // saturado. Juntarlas manda al analista a revisar un analizador cuando lo que
    // pasa es que la maquina no da abasto.
    fallos += exigir(
        matches!(
            i.por_analizador["colgado"],
            Resultado::NoAplicable(NoAplicable::PlazoAgotado { .. })
                | Resultado::NoAplicable(NoAplicable::NoEjecutado { .. })
        ),
        "el colgado se corto, y el motivo dice si fue por pasarse del plazo o por no arrancar",
    );
    fallos += exigir(
        i.por_analizador["roto"] == Resultado::NoAplicable(NoAplicable::Panico),
        "el que entro en panico se recogio sin tumbar el plano de control",
    );

    let m = i.por_analizador["mentiroso"]
        .dictamen()
        .expect("el mentiroso si contesto");
    println!(
        "      del «mentiroso» entraron {} bytes de motivo, {} etiquetas, confianza {}",
        m.porque.len(),
        m.etiquetas.len(),
        m.confianza
    );
    fallos += exigir(
        m.porque.len() <= aegis_enrich::dictamen::MAX_TEXTO
            && m.etiquetas.len() <= aegis_enrich::dictamen::MAX_ETIQUETAS
            && m.confianza <= aegis_enrich::dictamen::MAX_CONFIANZA,
        "la salida manipulada se aceptó recortada: ni memoria ilimitada ni confianza imposible",
    );
    fallos += exigir(
        m.observado_ns <= T0,
        "una fecha en el futuro se trajo al presente: si no, el dictamen no caducaria nunca",
    );
    fallos += exigir(
        m.clase == Clase::Comunitaria && m.fuente == "mentiroso",
        "no consiguio declararse autoritativo ni cambiarse el nombre",
    );
    fallos += exigir(
        m.observable == Observable::Hash("7f1e3c9b".into()),
        "ni colar un veredicto sobre OTRO observable",
    );
    fallos += exigir(
        i.por_analizador["sano"].dictamen().is_some() && i.fusion.veredicto == Veredicto::Malicioso,
        "y el analizador sano dio su resultado pese a todo lo anterior",
    );
    println!();
    fallos
}

/// La cuota, bajo concurrencia de verdad.
fn fase_cuota() -> usize {
    println!("  [4/5] cuota del proveedor bajo concurrencia");
    let mut fallos = 0;

    const RAFAGA: u32 = 100;
    const HILOS: usize = 24;
    const INTENTOS: usize = 60;

    let l = Limitador::nuevo();
    l.declarar(
        "rep",
        Cuota {
            por_minuto: 600,
            rafaga: RAFAGA,
        },
        T0,
    );

    let concedidos = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for _ in 0..HILOS {
            let l = Arc::clone(&l);
            let concedidos = Arc::clone(&concedidos);
            s.spawn(move || {
                for _ in 0..INTENTOS {
                    // Mismo instante en todos: el unico limite posible es la rafaga.
                    if let Ok(p) = l.reservar("rep", T0) {
                        concedidos.fetch_add(1, Ordering::SeqCst);
                        p.gastado();
                    }
                }
            });
        }
    });

    let n = concedidos.load(Ordering::SeqCst);
    println!(
        "      {HILOS} hilos x {INTENTOS} intentos = {} peticiones contra una rafaga de {RAFAGA}",
        HILOS * INTENTOS
    );
    println!("      concedidas: {n}");
    fallos += exigir(
        n == RAFAGA as usize,
        &format!(
            "se concedieron exactamente {RAFAGA}: comprobar-y-actuar habria dejado pasar mas, y \
             pasarse de cuota corta el servicio justo durante un incidente"
        ),
    );

    // El relleno es continuo: con ventana fija, gastar la rafaga al final de una y
    // otra al principio de la siguiente da el doble del limite en dos segundos.
    let tras_un_segundo = l.disponibles("rep", T0 + SEG).expect("declarada");
    println!("      fichas disponibles un segundo despues: {tras_un_segundo}");
    fallos += exigir(
        tras_un_segundo == 10,
        "a 600/min entran 10 fichas por segundo, no una rafaga entera: el relleno es continuo",
    );

    // Y una ficha que no se llega a gastar vuelve.
    let antes = l.disponibles("rep", T0 + SEG).expect("declarada");
    let p = l.reservar("rep", T0 + SEG).expect("hay");
    p.devolver();
    fallos += exigir(
        l.disponibles("rep", T0 + SEG) == Some(antes),
        "una consulta que no llego a hacerse devuelve su ficha",
    );
    println!();
    fallos
}

/// La fusion: determinista y explicable.
async fn fase_fusion() -> usize {
    println!("  [5/5] fusion de veredictos");
    let mut fallos = 0;

    // Cinco fuentes que dicen cosas distintas, que es el caso que importa.
    let o = montar(
        vec![
            externo("rep-a", Clase::Reputacion, Juicio::Malicioso, 95),
            externo("rep-b", Clase::Reputacion, Juicio::Limpio, 95),
            externo("com", Clase::Comunitaria, Juicio::Malicioso, 99),
            externo("mudo", Clase::Reputacion, Juicio::Desconocido, 0),
        ],
        vec![Arc::new(Dga::nuevo("dga"))],
        Modo::Conectado,
    );
    let i = o.enriquecer(&Observable::Hash("7f1e3c9b".into()), T0).await;

    println!("      veredicto: {}", i.fusion.veredicto.nombre());
    println!("      porque:    {}", i.fusion.porque);
    println!("      quien dijo que:");
    for d in &i.fusion.dictamenes {
        println!(
            "        {:<10} ({:<11}) {:<12} {:>3} %",
            d.fuente,
            d.clase.nombre(),
            d.juicio.nombre(),
            d.confianza
        );
    }

    fallos += exigir(
        i.fusion.veredicto == Veredicto::EnDisputa,
        "dos reputaciones seguras y contrarias NO se promedian: se dice que estan en disputa",
    );
    fallos += exigir(
        i.fusion.veredicto.exige_persona(),
        "y la disputa exige que la mire una persona, en vez de esconderse tras un numero medio",
    );
    fallos += exigir(
        i.fusion.porque.contains("rep-a") && i.fusion.porque.contains("rep-b"),
        "la explicacion nombra a quien discrepa, que es lo que permite discutirla",
    );
    fallos += exigir(
        i.fusion.dictamenes.len() >= 4,
        "el informe lleva lo que dijo CADA fuente, tambien las que coinciden",
    );

    // Determinismo: dos ejecuciones sobre lo mismo dan lo mismo. Como los
    // analizadores corren a la vez y acaban en orden impredecible, esto comprueba
    // de verdad que el orden de llegada no influye.
    let mut iguales = true;
    for _ in 0..12 {
        let otro = o.enriquecer(&Observable::Hash("7f1e3c9b".into()), T0).await;
        if otro.fusion != i.fusion {
            iguales = false;
        }
    }
    fallos += exigir(
        iguales,
        "doce ejecuciones concurrentes dan exactamente el mismo veredicto y la misma explicacion",
    );

    // Y el caso que mas se incumple en los productos reales.
    let solo_mudos = montar(
        vec![
            externo("mudo-a", Clase::Reputacion, Juicio::Desconocido, 0),
            externo("mudo-b", Clase::Reputacion, Juicio::Desconocido, 0),
            externo("mudo-c", Clase::Comunitaria, Juicio::Desconocido, 0),
        ],
        vec![],
        Modo::Conectado,
    );
    let i = solo_mudos
        .enriquecer(&Observable::Hash("recien-compilado".into()), T0)
        .await;
    println!(
        "      tres fuentes que no saben nada -> {}",
        i.fusion.veredicto.nombre()
    );
    fallos += exigir(
        i.fusion.veredicto == Veredicto::SinDatos,
        "tres «no se» NO son «probablemente limpio»: un fichero que nadie conoce es lo que parece \
         un fichero recien compilado por un atacante",
    );

    // La cache: la segunda consulta no expone nada.
    let antes = o.cuentas_de_cache();
    let repetida = o
        .enriquecer(&Observable::Hash("7f1e3c9b".into()), T0 + 60 * SEG)
        .await;
    let despues = o.cuentas_de_cache();
    println!(
        "      cache: {} aciertos acumulados; la repetida expuso {} proveedores",
        despues.0,
        repetida.exposicion.proveedores.len()
    );
    fallos += exigir(
        despues.0 > antes.0 && repetida.exposicion.vacia(),
        "una consulta repetida sale de cache y NO vuelve a decirle al proveedor que ese fichero \
         esta en tu red",
    );
    fallos
}
