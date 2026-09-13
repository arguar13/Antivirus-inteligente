//! INVARIANTE 7 (FASE 80): con el plano de control caido, el producto **completo**
//! sigue protegiendo.
//!
//! # Por que esto no es un caso raro
//!
//! Cortar la salida a Internet es lo **primero** que hace un atacante que sabe lo
//! que tiene delante. El estado «sin plano de control» no es un fallo del que
//! recuperarse: es el estado en el que hay que detectar, y el unico en el que el
//! producto se juega de verdad su utilidad.
//!
//! La FASE 68 ya prueba que el enjambre habla durante el corte. Lo que **ninguna
//! fase prueba** es lo que esta comprobando aqui: que el resto del producto
//! —corpus local, arbitro, enriquecimiento, linaje y decision de contencion— sigue
//! dando veredicto sin pedirle permiso a nadie.
//!
//! # Y autonomia NO es permisividad
//!
//! La prueba que mas dice de este fichero es la ultima:
//! [`autonomia_no_significa_bajar_el_liston`]. Un agente aislado que aceptara
//! ordenes sin firma seria peor que uno que no detecta nada, porque el atacante
//! **crea** el aislamiento y luego manda. El corte no afloja ni una comprobacion.

use std::collections::BTreeSet;

use aegis_entidad::arbitro::{arbitrar, Juicio, Resultado, Senal};
use aegis_entidad::entidad::{self, Eid};
use aegis_entidad::escala::{Confianza, Motor, Plano, Severidad};

use aegis_share::marcado::Tlp;
use aegis_swarm::enjambre::{
    ConfigEnjambre, Enjambre, EstadoEnlace, MotivoDescarte, Salida as SalidaEnjambre,
};
use aegis_swarm::mensaje::{Sobre, TipoMensaje};
use aegis_swarm::observacion::Observacion;
use aegis_swarm::orden::{Accion, Orden};
use aegis_sync::ioc::{Ioc, IocKind};
use aegis_tejido::circuito::{enriquecer_sin_salida, T0};
use aegis_tejido::traduccion;
use aegis_update::signature::{ClaveActualizacion, UpdateKey};

/// El resumen de la muestra que el agente aislado tiene delante.
const SHA: &str = "9f2b1c7e3a4d5068b19c2e4f7a8d0b3c6e15f92a4d7b0c38e6a1f45d29b7c803";

/// La clave del plano de control que el agente lleva grabada.
///
/// El agente aislado **tiene** la clave publica: lo que no tiene es forma de
/// hablar con quien guarda la privada. Esa asimetria es justo lo que permite que
/// una orden firmada de antes siga valiendo y una fabricada durante el corte no.
///
/// Aqui es una clave que **no verifica nada**, y es lo correcto para lo que estas
/// pruebas ejercen: ninguna firma va a validar contra ella, asi que cualquier
/// orden que llegue durante el corte tiene que caer. Los caminos que dependen de
/// criptografia de verdad se ejercen en `aegis-swarm`, con claves reales.
fn clave_del_plano() -> ClaveActualizacion {
    ClaveActualizacion::Clasica(
        UpdateKey::from_bytes(&[0u8; 32])
            .expect("una clave de ceros es un punto valido para este uso"),
    )
}

/// Un agente con el enlace **cortado**.
fn agente_aislado() -> Enjambre {
    let mut e = Enjambre::nuevo(ConfigEnjambre {
        clave_plano_control: clave_del_plano(),
        saltos: 3,
        tasa: 100,
        umbral_corroboro: 3,
        ventana_corroboro_seg: 3600,
    });
    e.declarar_enlace(EstadoEnlace::Aislado);
    e
}

/// EL ARBITRO NO PREGUNTA A NADIE. Es una funcion pura: mismos hechos, mismo
/// veredicto, sin red, sin reloj y sin estado.
///
/// Suena obvio y es la mitad de la autonomia: un arbitro que consultara al plano
/// de control convertiria cada corte en una parada de la deteccion.
#[test]
fn el_arbitro_decide_sin_plano_de_control() {
    let e = entidad::contenido(SHA);
    let senales = vec![
        traduccion::de_corpus(
            aegis_ruleforge::indice::Clase::HashFichero,
            "Win.Trojan.Descarga-9931",
            &e,
            T0,
        ),
        traduccion::de_modelo(910, &e, T0),
        Senal::nueva(
            Motor::Conductual,
            e.clone(),
            Juicio::Malicioso,
            Severidad::Alta,
            Confianza::ALTA,
            "escribio en el arranque y borro el registro de autenticacion",
            T0,
        ),
    ];

    let v = arbitrar(&e, &senales, T0);
    assert_eq!(v.resultado, Resultado::Malicioso, "{}", v.resumen());
    assert!(
        v.corroboracion() >= 2,
        "un solo plano decidio: {:?}",
        v.planos
    );
    assert!(!v.porque.is_empty());

    // Y el corpus local aporta desde el plano estatico: el agente no necesita
    // preguntar por el resumen, lo reconoce con lo que ya tiene en disco.
    let planos: BTreeSet<Plano> = v.senales.iter().map(Senal::plano).collect();
    assert!(planos.contains(&Plano::Estatico));
    assert!(planos.contains(&Plano::Conductual));
}

/// EL ENRIQUECIMIENTO SIGUE DANDO RESULTADO, DEGRADADO Y DICIENDOLO.
///
/// Sin salida, las fuentes externas no responden — y eso tiene que producir «no
/// se», nunca «esta limpio». Los analizadores locales siguen corriendo: sin salida
/// es **degradado**, no apagado.
#[test]
fn el_enriquecimiento_degrada_sin_mentir() {
    let informe = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(enriquecer_sin_salida(SHA, T0));

    assert!(
        informe.exposicion.vacia(),
        "salio algo con el plano de control caido: {}",
        informe.exposicion.resumen()
    );
    assert_ne!(
        informe.fusion.veredicto,
        aegis_enrich::fusion::Veredicto::Limpio,
        "«no se pudo preguntar» se convirtio en «esta limpio»"
    );
    assert!(
        !informe.por_analizador.is_empty(),
        "no corrio ningun analizador local: sin salida seria APAGADO, no degradado"
    );

    // Y lo que llega al arbitro es no-concluyente, que no vota: el veredicto lo
    // sostienen los motores que SI vieron algo.
    let s = traduccion::de_enriquecimiento(&informe.fusion, &entidad::contenido(SHA), T0);
    assert_eq!(s.juicio, Juicio::NoConcluyente);
    assert!(!s.aporta());
}

/// LA FLOTA SE CORROBORA ENTRE SI CUANDO NADIE ARBITRA.
///
/// Tres pares distintos ven el mismo indicador y el agente aislado lo corrobora.
/// No es una orden: es evidencia que la politica local usa con el mismo criterio
/// con el que usa una deteccion propia.
#[test]
fn la_flota_se_corrobora_sin_consola() {
    let mut agente = agente_aislado();
    let mut corroboros = 0;

    for (i, par) in ["agente-11", "agente-24", "agente-37"].iter().enumerate() {
        let o = Observacion {
            origen: (*par).to_string(),
            indicador: Ioc {
                kind: IocKind::FileSha256,
                value: SHA.to_string(),
            },
            tecnica: "T1204.002".into(),
            confianza: 80,
            vista_en: 1_741_078_900 + u64::try_from(i).unwrap_or(0),
        };
        let sobre = Sobre {
            tipo: TipoMensaje::Observacion,
            saltos: 3,
            cuerpo: o.a_bytes(),
            firma: Vec::new(),
        };
        for s in agente.recibir(par, &sobre.a_bytes(), 1_741_078_901) {
            if let SalidaEnjambre::Corroborado {
                observacion,
                testigos,
            } = s
            {
                assert_eq!(observacion.indicador.value, SHA);
                assert!(testigos.len() >= 3, "{testigos:?}");
                corroboros += 1;
            }
        }
    }

    assert_eq!(
        corroboros, 1,
        "el corroboro se emite UNA vez por indicador y ventana: la politica no \
         puede recibir el mismo hallazgo cien veces porque lleguen cien mensajes"
    );
    assert_eq!(agente.enlace(), EstadoEnlace::Aislado);
}

/// EL MISMO CORROBORO, VISTO POR EL ARBITRO, NO DECIDE SOLO.
///
/// Es la union de las dos invariantes: el enjambre entrega evidencia durante el
/// corte, y el arbitro la trata como lo que es —un plano externo que repite— asi
/// que no basta por si sola. Si bastara, quien comprometiera K agentes tendria un
/// boton para incriminar cualquier fichero de la organizacion, y el corte se lo
/// habria fabricado el mismo.
#[test]
fn lo_que_llega_por_el_enjambre_no_condena_por_si_solo() {
    let e = entidad::contenido(SHA);
    let o = Observacion {
        origen: "agente-11".into(),
        indicador: Ioc {
            kind: IocKind::FileSha256,
            value: SHA.to_string(),
        },
        tecnica: "T1204.002".into(),
        confianza: 100,
        vista_en: 1,
    };

    let solo_enjambre = vec![traduccion::de_enjambre(&o, 3, &e, T0)];
    let v = arbitrar(&e, &solo_enjambre, T0);
    assert_ne!(
        v.resultado,
        Resultado::Malicioso,
        "lo externo condeno sin que nadie de casa hubiera visto nada: {}",
        v.resumen()
    );

    // Con una sola señal propia que lo acompañe, ya si: lo externo CORROBORA, no
    // decide.
    let mut con_casa = solo_enjambre;
    con_casa.push(Senal::nueva(
        Motor::Conductual,
        e.clone(),
        Juicio::Malicioso,
        Severidad::Alta,
        Confianza::ALTA,
        "el proceso escribio en el arranque",
        T0,
    ));
    let v = arbitrar(&e, &con_casa, T0);
    assert_eq!(v.resultado, Resultado::Malicioso, "{}", v.resumen());
}

/// AUTONOMIA NO ES BAJAR EL LISTON.
///
/// La prueba que mas dice del fichero. Durante el corte, el agente **no puede**
/// consultar al plano de control — y precisamente por eso no puede relajar la
/// comprobacion de firma. El atacante que corta el enlace es el mismo que despues
/// manda; si el aislamiento aflojara la validacion, cortar la red seria el primer
/// paso de la escalada en vez del ultimo recurso del defensor.
///
/// Se ejercen los tres casos que importan:
///
/// 1. Una orden **sin firma valida** se descarta, aunque venga de un par conocido.
/// 2. Una orden de las que **no viajan nunca** —levantar un aislamiento, desactivar
///    una regla, degradar la proteccion— se descarta *por su clase*, antes incluso
///    de mirar la firma: reproducidas durante el corte apagan la defensa con una
///    firma autentica.
/// 3. Un mensaje deforme no provoca panico ni deja el nodo en un estado raro.
#[test]
fn autonomia_no_significa_bajar_el_liston() {
    let mut agente = agente_aislado();

    // 1. Firma inventada sobre una orden por lo demas perfecta.
    let orden = Orden {
        accion: Accion::AislarRed,
        sujeto: "wks-4417.corp.ejemplo".into(),
        incidente: "inc-0001".into(),
        epoca: 9,
        emitida_en: 1_741_078_800,
        caduca_en: 1_741_082_400,
    };
    let sobre = Sobre {
        tipo: TipoMensaje::Orden,
        saltos: 3,
        cuerpo: orden.a_bytes(),
        firma: vec![0xAB; 64],
    };
    let salidas = agente.recibir("agente-11", &sobre.a_bytes(), 1_741_078_900);
    assert!(
        salidas
            .iter()
            .any(|s| matches!(s, SalidaEnjambre::Descartado(MotivoDescarte::FirmaInvalida))),
        "una orden con firma inventada paso durante el corte: {salidas:?}"
    );
    assert!(
        !salidas
            .iter()
            .any(|s| matches!(s, SalidaEnjambre::AplicarOrden(_))),
        "se aplico una orden sin firma del plano de control"
    );

    // 2. Las que no viajan NUNCA, ni con la firma perfecta.
    for accion in [
        Accion::LevantarAislamiento,
        Accion::DesactivarRegla,
        Accion::DegradarProteccion,
    ] {
        let o = Orden {
            accion,
            sujeto: "wks-4417.corp.ejemplo".into(),
            incidente: "inc-0002".into(),
            epoca: 10,
            emitida_en: 1_741_078_800,
            caduca_en: 1_741_082_400,
        };
        let s = Sobre {
            tipo: TipoMensaje::Orden,
            saltos: 3,
            cuerpo: o.a_bytes(),
            firma: vec![0u8; 64],
        };
        let salidas = agente.recibir("agente-24", &s.a_bytes(), 1_741_078_901);
        assert!(
            salidas.iter().any(|x| matches!(
                x,
                SalidaEnjambre::Descartado(
                    MotivoDescarte::ClaseProhibida | MotivoDescarte::FirmaInvalida
                )
            )),
            "«{accion:?}» cruzo la malla: {salidas:?}"
        );
        assert!(
            !salidas
                .iter()
                .any(|x| matches!(x, SalidaEnjambre::AplicarOrden(_))),
            "se aplico «{accion:?}», que apaga la defensa"
        );
    }

    // 3. Basura: ni panico ni estado raro.
    for basura in [
        vec![],
        vec![0u8; 1],
        vec![0xFFu8; 4096],
        b"esto no es el protocolo".to_vec(),
    ] {
        let _ = agente.recibir("agente-37", &basura, 1_741_078_902);
    }
    assert_eq!(agente.enlace(), EstadoEnlace::Aislado);
    assert!(agente.contadores().descartados() > 0);
}

/// LO QUE SE COMPARTE DURANTE EL CORTE NO PUEDE SALIR MAS DE LO DEBIDO.
///
/// El enjambre llega a maquinas que el atacante puede haber comprometido —ese es
/// el supuesto de la FASE 68, no una hipotesis—, asi que lo que cruza lleva dos
/// topes que **no se pueden subir**. Aqui se comprueba el que decide: el tope de
/// difusion sale del VEREDICTO, y un veredicto que no es malicioso confirmado se
/// marca `TLP:RED`, que no distribuye ningun canal.
#[test]
fn el_corte_no_afloja_lo_que_se_comparte() {
    assert_eq!(
        traduccion::tope_de_difusion(Resultado::Malicioso),
        Tlp::Amber
    );
    for r in [
        Resultado::Sospechoso,
        Resultado::EnDisputa,
        Resultado::SinDatos,
        Resultado::Limpio,
    ] {
        assert_eq!(
            traduccion::tope_de_difusion(r),
            Tlp::Red,
            "«{}» se volvio distribuible durante el corte",
            r.nombre()
        );
    }
}

/// El identificador que el agente aislado deriva es el mismo que derivaria el
/// plano de control con los mismos hechos.
///
/// Es lo que hace que, al volver el enlace, lo observado durante el corte encaje
/// con lo que hay al otro lado en vez de duplicarlo.
#[test]
fn el_identificador_derivado_en_el_corte_encaja_al_volver() {
    let en_el_agente: Eid = entidad::contenido(SHA);
    let en_el_servidor: Eid = entidad::contenido(SHA);
    assert_eq!(en_el_agente, en_el_servidor);
    assert_eq!(en_el_agente.texto(), en_el_servidor.texto());

    // Y no depende de nada local: ni de la maquina, ni del momento, ni del orden.
    let otra_vez = entidad::contenido(SHA);
    assert_eq!(otra_vez, en_el_agente);
}
