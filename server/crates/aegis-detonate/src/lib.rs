//! # aegis-detonate
//!
//! Detonar una muestra a proposito y contar lo que hizo, sin que lo que haga
//! toque nada real.
//!
//! ## Las tres promesas, y cual se cumple donde
//!
//! **1. La muestra no alcanza nada real.** Es la unica razon por la que el resto
//! puede existir. [`frontera`] la define con dos piezas: un confinamiento y una
//! salida de red que **no tiene variante para «red de verdad»**. En el camino de
//! espacios de nombres se comprueba de verdad —hay una prueba que intenta una
//! conexion real desde dentro y falla— y en el de maquina virtual la aporta el
//! hipervisor.
//!
//! **2. La maquina se destruye siempre.** Esta en [`Drop`] y no solo en un
//! metodo, porque un metodo se olvida en el camino de error y el camino de error
//! es justo el que se toma cuando algo ha ido mal con una muestra que muerde. Una
//! maquina de detonacion que sobrevive a su detonacion es una maquina infectada
//! corriendo en la infraestructura del que analiza, y ademas invisible.
//!
//! **3. El informe no puede mentir.** Hay tres cosas que un sandbox descuidado
//! escribe igual: «corrio entera y no hizo nada», «detecto el entorno y se
//! marcho» y «se corto antes de empezar». Solo la primera es benigna, y
//! [`informe::Informe::veredicto`] no tiene ningun camino que llegue a
//! [`informe::Veredicto::SinHallazgos`] sin haber descartado las otras dos.
//!
//! ## Todo lo que sube el invitado lo escribe el malware
//!
//! La traza la produce un proceso que corre en una maquina que se esta
//! infectando. [`receptor`] parte de ahi: topes en cada longitud, huecos de
//! secuencia anotados en vez de abortados, y un error de protocolo que **cierra
//! el canal sin resincronizar**, porque resincronizar le dejaria al invitado
//! colocar la marca donde quiera y fabricar tramas.
//!
//! Y el canal solo transporta hechos: [`aegis_invitado::protocolo::Evento`] no
//! tiene ni una variante que sea una orden. El anfitrion no valida nada porque no
//! hay nada que ejecutar.
//!
//! ## El muro, declarado
//!
//! Arrancar una maquina virtual necesita `/dev/kvm`. Donde no lo hay —una maquina
//! de integracion que ya corre dentro de otra maquina virtual, por ejemplo— se
//! genera y se comprueba su configuracion pieza a pieza, pero **no se arranca**,
//! y [`maquina::hay_virtualizacion`] lo dice. Lo que si se ejercita entero en
//! cualquier sitio es el resto: el trazador contra procesos reales, el
//! aislamiento de red contra una direccion real, el canal contra un socket real,
//! y la destruccion garantizada contra un proceso real.
//!
//! Detonar muestras de Windows necesita ademas una licencia y una imagen que no
//! se puede distribuir. La orquestacion, la frontera y el analisis son los
//! mismos; lo que cambia es el invitado.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod antivm;
pub mod frontera;
pub mod informe;
pub mod maquina;
pub mod receptor;
pub mod red_simulada;

use aegis_vmi::modo::Modo;

// El modo forma parte de la API de esta caja: esta en `Peticion` y en `Informe`.
// Se reexporta para que quien use la detonacion pueda nombrarlo sin tener que
// conocer el crate del hipervisor ni anadirlo a sus dependencias.
pub use aegis_vmi::modo::{Delator, Modo as ModoDeObservacion, Observacion};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use frontera::{Confinamiento, Frontera, Limites, Salida};
pub use informe::{Comportamiento, Final, Informe, Muestra, Veredicto};
pub use maquina::{Destruccion, Jaula};
pub use receptor::{Anomalia, Recepcion, Topes};
pub use red_simulada::RedSimulada;

/// Que se detona y con que.
#[derive(Debug, Clone)]
pub struct Peticion {
    /// La muestra.
    pub muestra: PathBuf,
    /// Argumentos con los que se lanza.
    pub argumentos: Vec<String>,
    /// La frontera.
    pub frontera: Frontera,
    /// El binario del agente invitado.
    ///
    /// En produccion vive **dentro de la imagen del invitado** y esta ruta es la
    /// de dentro. En el camino de espacios de nombres es la del anfitrion.
    pub agente_invitado: PathBuf,
    /// Directorio para el socket del canal y lo que haga falta.
    pub trabajo: PathBuf,
    /// Si lo que se detona es una muestra real y no un ejercicio.
    ///
    /// Lo sabe quien llama y nadie mas, por eso es un campo suyo. Decide si el
    /// aislamiento debil se acepta.
    pub muestra_real: bool,
    /// Como se observa a la muestra.
    ///
    /// Con agente dentro se ve mas contexto, y ese agente EXISTE dentro: una
    /// muestra que lo busque lo encuentra. En modo fantasma se ve menos y no hay
    /// nada que encontrar. La eleccion la hace quien llama porque depende de si
    /// la maquina trae hipervisor con tabla de paginas extendida, y el informe la
    /// DECLARA porque cambia lo que significa no haber visto nada.
    pub modo: Modo,
}

/// Lo que puede salir mal.
#[derive(Debug, thiserror::Error)]
pub enum ErrorDetonacion {
    /// La frontera no se sostiene.
    #[error("{0}")]
    Frontera(#[from] frontera::ErrorFrontera),
    /// La maquina no arranco.
    #[error("{0}")]
    Maquina(#[from] maquina::ErrorMaquina),
    /// Fallo de disco o de red del anfitrion.
    #[error("fallo del anfitrion: {0}")]
    Anfitrion(String),
    /// La muestra no esta.
    #[error("la muestra no esta en «{0}»")]
    SinMuestra(String),
}

/// Detona una muestra y devuelve el informe.
///
/// # El orden importa
///
/// 1. **Verificar la frontera antes de tocar la muestra.** Comprobarla despues de
///    arrancar seria comprobarla cuando ya no sirve de nada.
/// 2. Levantar el receptor **antes** que el invitado: si el invitado arranca
///    primero, sus primeras tramas —las que dicen que se preparo y con que
///    version— se pierden contra un canal que aun no existe.
/// 3. Destruir **siempre**, en cualquier camino de salida. Lo garantiza el
///    [`Drop`] de [`Jaula`], no la disciplina de quien escribe el codigo.
///
/// # Errores
/// [`ErrorDetonacion`] si la frontera no se sostiene, si la muestra no esta o si
/// el anfitrion no puede levantar el canal.
pub fn detonar(peticion: &Peticion) -> Result<Informe, ErrorDetonacion> {
    peticion.frontera.verificar(peticion.muestra_real)?;

    let datos = std::fs::read(&peticion.muestra)
        .map_err(|_| ErrorDetonacion::SinMuestra(peticion.muestra.display().to_string()))?;
    let muestra = Muestra::de_bytes(
        &peticion
            .muestra
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        &datos,
    );

    std::fs::create_dir_all(&peticion.trabajo)
        .map_err(|e| ErrorDetonacion::Anfitrion(e.to_string()))?;
    let socket = peticion.trabajo.join("canal.sock");

    // Los servicios falsos, solo donde el confinamiento puede alcanzarlos. La
    // frontera ya ha rechazado la combinacion imposible, asi que aqui no hay que
    // decidir nada: se hace lo que la frontera dijo.
    let red = match peticion.frontera.salida {
        Salida::Simulada => Some(
            RedSimulada::levantar("127.0.0.1")
                .map_err(|e| ErrorDetonacion::Anfitrion(e.to_string()))?,
        ),
        Salida::Ninguna => None,
    };

    let topes = Topes {
        max_eventos: peticion.frontera.limites.max_eventos,
        max_bytes: peticion.frontera.limites.max_captura,
    };
    let plazo = peticion.frontera.limites.plazo;

    // El receptor va en su propio hilo y se ata al socket ANTES de arrancar al
    // invitado. Al reves, las primeras tramas se perderian contra un canal que
    // aun no existe, y esas son justo las que dicen que el agente se preparo.
    let socket_hilo = socket.clone();
    let receptor = std::thread::spawn(move || {
        receptor::escuchar_unix(&socket_hilo, topes, plazo + Duration::from_secs(2))
    });
    esperar_socket(&socket, Duration::from_secs(5));

    let argumentos = argumentos_del_agente(peticion, &socket);
    let arranque = Instant::now();

    // A partir de aqui la jaula existe, y su Drop la destruye pase lo que pase:
    // un `?` que salga por el camino de error, un panico, lo que sea.
    let mut jaula = Jaula::lanzar(
        &peticion.agente_invitado,
        &argumentos,
        peticion.frontera.salida,
    )?;
    let codigo = jaula.esperar(plazo);
    let destruccion = jaula.destruir();

    let recepcion = receptor
        .join()
        .map_err(|_| ErrorDetonacion::Anfitrion("el receptor se cayo".into()))?
        .map_err(|e| ErrorDetonacion::Anfitrion(e.to_string()))?;

    let observado = red.map(RedSimulada::parar).unwrap_or_default();

    let final_ = decidir_final(codigo, destruccion, arranque.elapsed(), plazo, &recepcion);
    Ok(Informe::montar(
        muestra,
        &peticion.frontera,
        final_,
        &recepcion,
        &observado,
        peticion.modo,
    ))
}

/// Como acabo, mirando todo lo que se sabe y no solo el codigo de salida.
///
/// El codigo de salida por si solo no distingue «la muestra termino» de «la
/// mataron», y esa diferencia decide si el informe puede concluir algo.
fn decidir_final(
    codigo: Option<i32>,
    destruccion: Destruccion,
    tardanza: Duration,
    plazo: Duration,
    recepcion: &Recepcion,
) -> Final {
    if recepcion.is_empty() && codigo.is_none() {
        return Final::NoArranco;
    }

    // Lo primero que se mira es lo que dice el AGENTE, no el codigo de salida.
    //
    // El codigo que el anfitrion ve es el del agente invitado, y el agente
    // termina limpiamente tanto si la muestra acabo como si tuvo que matarla por
    // plazo: las dos cosas llegan aqui como un cero. Deducir de ahi que la
    // muestra «termino» es exactamente el error que hace que alguien despliegue
    // una muestra creyendo que esta limpia.
    let fin_del_agente = recepcion.tramas.iter().rev().find_map(|t| match &t.evento {
        aegis_invitado::protocolo::Evento::Fin {
            codigo, completo, ..
        } => Some((*codigo, *completo)),
        _ => None,
    });

    // Un `completo: false` se cree siempre: nadie miente para que su informe
    // valga menos. Un `true` NO se cree solo, y por eso las comprobaciones del
    // anfitrion van despues y pueden contradecirlo.
    if matches!(fin_del_agente, Some((_, false))) {
        return Final::Plazo;
    }
    if destruccion == Destruccion::Matada || tardanza >= plazo {
        return Final::Plazo;
    }
    if recepcion
        .anomalias
        .iter()
        .any(|a| a.codigo() == "recortada")
    {
        return Final::Tope;
    }

    match fin_del_agente {
        // El codigo de la MUESTRA, que es el que interesa, no el del agente.
        Some((c, true)) => Final::Termino { codigo: c },
        // Sin trama final no se sabe si acabo o la mataron. El receptor ya lo
        // anota como anomalia; aqui se elige el lado que no concluye de mas.
        None => match codigo {
            Some(_) => Final::Plazo,
            None => Final::Plazo,
        },
        // Tratado arriba, pero se resuelve en vez de entrar en panico: un panico
        // en el orquestador de una detonacion es la peor clase de fallo, porque
        // ocurre con una muestra viva delante.
        Some((_, false)) => Final::Plazo,
    }
}

/// Argumentos con los que se lanza el agente invitado.
fn argumentos_del_agente(peticion: &Peticion, socket: &Path) -> Vec<String> {
    let mut v = vec![
        "--muestra".to_string(),
        peticion.muestra.display().to_string(),
        "--plazo".to_string(),
        peticion.frontera.limites.plazo.as_secs().to_string(),
    ];
    match peticion.frontera.confinamiento {
        // En la maquina virtual el canal es vsock de verdad; el socket de Unix
        // es lo que el hipervisor le presenta al anfitrion en el otro extremo.
        Confinamiento::MicroVm { .. } => {
            v.push("--canal-vsock".into());
            v.push(aegis_invitado::canal::PUERTO.to_string());
        }
        Confinamiento::Namespaces { .. } => {
            v.push("--canal-unix".into());
            v.push(socket.display().to_string());
        }
    }
    for a in &peticion.argumentos {
        v.push("--arg".into());
        v.push(a.clone());
    }
    v
}

/// Espera a que el receptor tenga el socket atado.
///
/// Sondear el sistema de ficheros es feo y es lo correcto: la alternativa es una
/// pausa fija, que o es demasiado corta en una maquina cargada —y entonces se
/// pierden las primeras tramas— o demasiado larga en todas las demas.
fn esperar_socket(ruta: &Path, plazo: Duration) {
    let fin = Instant::now() + plazo;
    while Instant::now() < fin {
        if ruta.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Detona dos veces la misma muestra y compara los informes.
///
/// Es como se **mide** el determinismo en vez de afirmarlo. Lo que diverge sale
/// con nombre, y entonces se puede decidir si es una fuente legitima —un nombre
/// generado al azar— o un fallo del sandbox.
///
/// # Errores
/// El primer [`ErrorDetonacion`] de las dos detonaciones.
pub fn detonar_dos_veces(
    peticion: &Peticion,
) -> Result<(Informe, Informe, Vec<informe::Divergencia>), ErrorDetonacion> {
    let a = detonar(peticion)?;
    // Cada detonacion parte de cero: directorio de trabajo propio, socket propio,
    // maquina nueva. Reutilizar cualquiera de las tres haria que la segunda
    // empezara con lo que dejo la primera, y entonces la comparacion no mediria
    // el determinismo de la muestra sino el del sandbox.
    let mut segunda = peticion.clone();
    segunda.trabajo = peticion.trabajo.join("segunda");
    let b = detonar(&segunda)?;
    let divergencias = informe::comparar(&a, &b);
    Ok((a, b, divergencias))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_frontera_se_verifica_antes_de_tocar_la_muestra() {
        // Comprobarla despues de arrancar seria comprobarla cuando ya no sirve de
        // nada. Aqui la muestra ni siquiera existe, y aun asi el error es el de
        // la frontera.
        let p = Peticion {
            muestra: PathBuf::from("/no/existe/muestra.bin"),
            argumentos: Vec::new(),
            frontera: Frontera::namespaces(),
            agente_invitado: PathBuf::from("/no/existe/agente"),
            trabajo: std::env::temp_dir().join("aegis-det-orden"),
            muestra_real: true, // con aislamiento debil, esto tiene que cortar
            modo: Modo::Fantasma,
        };
        assert!(matches!(
            detonar(&p),
            Err(ErrorDetonacion::Frontera(
                frontera::ErrorFrontera::AislamientoInsuficiente
            ))
        ));
    }

    #[test]
    fn una_muestra_que_no_esta_se_dice_con_su_ruta() {
        let p = Peticion {
            muestra: PathBuf::from("/no/existe/muestra.bin"),
            argumentos: Vec::new(),
            frontera: Frontera::namespaces(),
            agente_invitado: PathBuf::from("/no/existe/agente"),
            trabajo: std::env::temp_dir().join("aegis-det-sinmuestra"),
            muestra_real: false,
            modo: Modo::Fantasma,
        };
        match detonar(&p) {
            Err(ErrorDetonacion::SinMuestra(r)) => assert!(r.contains("muestra.bin")),
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn el_agente_recibe_el_canal_que_le_toca_a_su_confinamiento() {
        // En la jaula, un socket de Unix. En la maquina virtual, vsock de verdad:
        // pasarle el socket del anfitrion seria darle una ruta que dentro de la
        // maquina no existe.
        let base = Peticion {
            muestra: PathBuf::from("/tmp/m"),
            argumentos: vec!["-x".into()],
            frontera: Frontera::namespaces(),
            agente_invitado: PathBuf::from("/tmp/a"),
            trabajo: PathBuf::from("/tmp/t"),
            muestra_real: false,
            modo: Modo::Fantasma,
        };
        let args = argumentos_del_agente(&base, Path::new("/tmp/t/canal.sock"));
        assert!(args.contains(&"--canal-unix".to_string()));
        assert!(args.contains(&"/tmp/t/canal.sock".to_string()));
        assert!(args.contains(&"-x".to_string()), "{args:?}");

        let mut vm = base.clone();
        vm.frontera = Frontera::microvm(
            PathBuf::from("/x"),
            PathBuf::from("/y"),
            PathBuf::from("/z"),
        );
        let args = argumentos_del_agente(&vm, Path::new("/tmp/t/canal.sock"));
        assert!(args.contains(&"--canal-vsock".to_string()));
        assert!(!args.contains(&"--canal-unix".to_string()));
    }

    #[test]
    fn el_codigo_de_salida_por_si_solo_no_decide_como_acabo() {
        // No distingue «la muestra termino» de «la mataron», y esa diferencia
        // decide si el informe puede concluir algo.
        let vacia = Recepcion::default();
        assert_eq!(
            decidir_final(
                None,
                Destruccion::NoHabiaNada,
                Duration::ZERO,
                Duration::from_secs(10),
                &vacia
            ),
            Final::NoArranco
        );
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::Matada,
                Duration::from_secs(1),
                Duration::from_secs(10),
                &vacia
            ),
            Final::Plazo,
            "si hubo que matarla, termino NO es la palabra"
        );
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_secs(1),
                Duration::from_secs(10),
                &vacia
            ),
            Final::Plazo,
            "sin trama final no se sabe si acabo: no se concluye de mas"
        );
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_secs(20),
                Duration::from_secs(10),
                &vacia
            ),
            Final::Plazo,
            "pasarse del plazo es un corte aunque salga con codigo cero"
        );
    }

    fn fin(codigo: i32, completo: bool) -> Recepcion {
        let mut r = Recepcion::default();
        r.tramas.push(aegis_invitado::protocolo::Trama {
            secuencia: 0,
            evento: aegis_invitado::protocolo::Evento::Fin {
                codigo,
                emitidos: 1,
                completo,
            },
        });
        r
    }

    #[test]
    fn el_anfitrion_le_hace_caso_al_agente_sobre_si_la_muestra_acabo() {
        // EL BUG QUE ESTA PRUEBA CIERRA. El agente invitado sale con cero tanto
        // si la muestra acabo como si tuvo que matarla por plazo. Deduciendo del
        // codigo de salida, una muestra cortada salia como «termino», y con ella
        // un veredicto que decia que no hizo nada.
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_millis(100),
                Duration::from_secs(60),
                &fin(-1, false)
            ),
            Final::Plazo,
            "el agente dijo que se corto y el anfitrion tiene que creerselo"
        );
    }

    #[test]
    fn el_codigo_del_informe_es_el_de_la_muestra_y_no_el_del_agente() {
        // El agente sale con cero; la muestra salio con 42. El informe tiene que
        // llevar el de la muestra, que es por lo que se pregunta.
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_millis(100),
                Duration::from_secs(60),
                &fin(42, true)
            ),
            Final::Termino { codigo: 42 }
        );
    }

    #[test]
    fn que_el_agente_diga_completo_no_basta_si_el_anfitrion_vio_otra_cosa() {
        // Un `completo: false` se cree siempre —nadie miente para que su informe
        // valga menos— pero un `true` si seria util falsificarlo, asi que se
        // cruza con lo que el anfitrion sabe por su cuenta.
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::Matada,
                Duration::from_millis(100),
                Duration::from_secs(60),
                &fin(0, true)
            ),
            Final::Plazo,
            "hubo que matar la maquina: da igual lo que diga el invitado"
        );
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_secs(99),
                Duration::from_secs(10),
                &fin(0, true)
            ),
            Final::Plazo,
            "se paso del plazo del anfitrion: da igual lo que diga el invitado"
        );
    }

    #[test]
    fn un_recorte_en_el_canal_sale_como_tope_y_no_como_terminada() {
        let mut r = fin(0, true);
        r.anomalias.push(Anomalia::Recortada {
            motivo: "eventos guardados".into(),
        });
        assert_eq!(
            decidir_final(
                Some(0),
                Destruccion::TerminoSola,
                Duration::from_secs(1),
                Duration::from_secs(10),
                &r
            ),
            Final::Tope
        );
    }
}
