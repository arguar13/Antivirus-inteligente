//! La costura: de cada vocabulario nativo a la escala unica.
//!
//! # Por que la traduccion vive AQUI y no en cada subsistema
//!
//! Es la misma decision que `aegis-share::difusion` tomo para lo que sale de la
//! organizacion, y por la misma razon: **una regla repartida por veinte sitios es
//! una regla que el veintiuno se salta**. Si cada motor tradujera su propio
//! veredicto, el motor nuevo traduciria mal y nadie lo vería — porque no habria
//! ningun sitio donde comparar su traduccion con las demas.
//!
//! Con la costura en un modulo, tres cosas se vuelven posibles:
//!
//! 1. Leer las trece traducciones seguidas y discutirlas.
//! 2. Cambiar el criterio de un motor sin tocar el motor.
//! 3. Comprobar en la puerta de calidad que ninguna se pasa de su tope.
//!
//! Y los subsistemas siguen sin depender unos de otros: este crate depende de
//! todos, y ninguno depende de este.
//!
//! # Las tres reglas que gobiernan todas las traducciones
//!
//! **Uno. Lo que el motor no puede ver no lo puede afirmar.** Cada señal se
//! construye con [`Senal::nueva`], que acota la confianza al tope del motor. No es
//! una recomendacion: es el constructor, y no hay otro camino.
//!
//! **Dos. Un hecho no es un juicio.** `aegis-wire` produce veintitres clases de
//! hecho y la mayoria **no son señales**: una consulta DNS no acusa a nadie. La
//! traduccion devuelve `None` para esas, y eso es lo correcto — un disector que
//! grita «malicioso» en cada paquete es un disector que nadie mira.
//!
//! **Tres. No poder mirar nunca se traduce a limpio.** `NoConcluyente` sube tal
//! cual por todas las costuras. La detonacion es el caso que mas lo enseña: «corrio
//! entera y no hizo nada», «detecto el entorno y se marcho» y «se corto antes de
//! empezar» se escriben igual en un informe descuidado, y solo la primera es
//! benigna.

use aegis_entidad::arbitro::{Juicio, Senal};
use aegis_entidad::entidad::Eid;
use aegis_entidad::escala::{de_puntuacion, Confianza, Motor, Severidad};

use aegis_case::modelo::Severidad as SeveridadCaso;
use aegis_detonate::informe::{Informe as InformeDetonacion, Veredicto as VeredictoDetonacion};
use aegis_enrich::fusion::{Fusion, Veredicto as VeredictoEnriquecimiento};
use aegis_ruleforge::indice::Clase as ClaseCorpus;
use aegis_share::marcado::Tlp;
use aegis_swarm::observacion::Observacion;
use aegis_wire::hecho::{Hecho, HechoConContexto};

/// Traduce un hecho de `aegis-wire` (FASE 70) a una señal, si lo es.
///
/// # Por que devuelve `Option` y la mayoria de los hechos dan `None`
///
/// Porque `aegis-wire` **no es un motor de veredictos**: convierte bytes en hechos
/// con significado. «Se consulto `ejemplo.com`» no acusa a nadie, y convertirlo en
/// una señal de severidad baja produciria un arbitro ahogado en ruido donde lo que
/// si acusa no se distingue.
///
/// Los que si son señal son los que el disector detecto **contra** algo: una
/// evasion, un contrabando, un fichero que miente sobre lo que es, un tunel.
#[must_use]
pub fn de_wire(h: &HechoConContexto, entidad: &Eid, cuando_ns: u64) -> Option<Senal> {
    let (juicio, severidad, confianza, porque) = match &h.hecho {
        Hecho::AnomaliaDeFlujo { codigo, detalle } => match *codigo {
            // CONTRABANDO Y EVASION. No hay forma benigna de enviar dos
            // codificaciones de longitud contradictorias: es una tecnica, no un
            // error de implementacion que se vea en la red de un cliente.
            "http-contrabando-cl-te"
            | "http-transfer-encoding-duplicado"
            | "http-transfer-encoding-ofuscado" => (
                Juicio::Malicioso,
                Severidad::Alta,
                Confianza::ALTA,
                format!("contrabando de peticiones HTTP: {detalle}"),
            ),
            // UN FICHERO QUE MIENTE SOBRE LO QUE ES. Un ejecutable servido como
            // PDF no es un fallo de configuracion frecuente.
            "fichero-tipo-contradictorio" | "fichero-nombre-enganoso" => (
                Juicio::Sospechoso,
                Severidad::Media,
                Confianza::MEDIA,
                format!("el fichero no es lo que dice ser: {detalle}"),
            ),
            // CRIPTOGRAFIA DEBIL. Es un hecho de configuracion que habilita un
            // ataque conocido; acusa al entorno, no al sujeto.
            "kerberos-cifrado-debil" | "ldap-bind-sin-cifrar" => (
                Juicio::Sospechoso,
                Severidad::Media,
                Confianza::BAJA,
                format!("protocolo de identidad sin proteger: {detalle}"),
            ),
            // Lo demas son cotas y errores de formato: se cuentan, no acusan.
            _ => return None,
        },
        Hecho::IndicioTunelDns {
            nombre,
            entropia,
            etiqueta_mas_larga,
        } => (
            Juicio::Sospechoso,
            Severidad::Media,
            Confianza::MEDIA,
            format!(
                "indicio de tunel DNS en «{nombre}»: {entropia:.2} bits/caracter, \
                 etiqueta de {etiqueta_mas_larga} caracteres"
            ),
        ),
        // EL RESTO SON HECHOS, NO JUICIOS. Es deliberado, ver el encabezado.
        _ => return None,
    };

    Some(Senal::nueva(
        Motor::Wire,
        entidad.clone(),
        juicio,
        severidad,
        confianza,
        porque,
        cuando_ns,
    ))
}

/// Traduce un acierto del corpus mundial (FASE 72) a una señal.
///
/// # La clase de la entrada decide la confianza, y no al reves
///
/// Un acierto por SHA-256 del fichero entero es exacto: o es ese fichero o no lo
/// es. Un acierto por firma de cuerpo o por regla logica casa con **una familia**,
/// y una familia incluye variantes que nadie ha visto — sube menos.
///
/// Aun asi ninguno pasa de 80: es el tope de [`Motor::Estatico`], y esta ahi
/// porque una firma acierta mucho y un empaquetador nuevo la esquiva entera.
#[must_use]
pub fn de_corpus(clase: ClaseCorpus, nombre_firma: &str, entidad: &Eid, cuando_ns: u64) -> Senal {
    let (confianza, que) = match clase {
        ClaseCorpus::HashFichero => (Confianza::ALTA, "el fichero exacto"),
        ClaseCorpus::HashSeccion => (Confianza::MEDIA, "una seccion del fichero"),
        ClaseCorpus::Cuerpo => (Confianza::MEDIA, "una firma de cuerpo"),
        ClaseCorpus::Logica | ClaseCorpus::Red | ClaseCorpus::Evento => {
            (Confianza::BAJA, "una regla logica")
        }
    };
    Senal::nueva(
        Motor::Estatico,
        entidad.clone(),
        Juicio::Malicioso,
        Severidad::Alta,
        confianza,
        format!("el corpus reconoce {que}: «{nombre_firma}»"),
        cuando_ns,
    )
}

/// Traduce la puntuacion del modelo del endpoint (FASE 21) a una señal.
///
/// # Por que la puntuacion no pasa tal cual
///
/// Una puntuacion de 0,99 en un modelo sin calibrar significa «muy arriba en la
/// escala interna del modelo», **no** «99 % de probabilidad de acertar». Pasarla
/// directa a confianza es afirmar una calibracion que no se ha hecho, y es como se
/// construye un producto que se equivoca con mucha seguridad.
///
/// [`de_puntuacion`] comprime hacia el tope del motor, que son 70.
#[must_use]
pub fn de_modelo(puntuacion_milesimas: u16, entidad: &Eid, cuando_ns: u64) -> Senal {
    let juicio = match puntuacion_milesimas {
        0..=499 => Juicio::Limpio,
        500..=799 => Juicio::Sospechoso,
        _ => Juicio::Malicioso,
    };
    let severidad = match juicio {
        Juicio::Malicioso => Severidad::Alta,
        Juicio::Sospechoso => Severidad::Media,
        _ => Severidad::Info,
    };
    Senal::nueva(
        Motor::Aprendizaje,
        entidad.clone(),
        juicio,
        severidad,
        de_puntuacion(puntuacion_milesimas),
        format!(
            "el modelo del endpoint puntua {:.3} sobre caracteristicas estaticas",
            f64::from(puntuacion_milesimas) / 1000.0
        ),
        cuando_ns,
    )
}

/// Traduce el informe de una detonacion (FASE 73) a una señal.
///
/// # La traduccion que mas importa de todo el modulo
///
/// `SinHallazgos` es el unico camino a «no encontramos nada», y en `aegis-detonate`
/// **no se alcanza** si la detonacion no fue completa o hubo sospecha de evasion.
/// Esa disciplina se conserva aqui exactamente: `SinHallazgos` → [`Juicio::Limpio`]
/// con confianza de quien **vio** la muestra correr; `NoConcluyente` →
/// [`Juicio::NoConcluyente`], nunca limpio.
///
/// Si esta funcion tradujera `NoConcluyente` a `Limpio` «para no generar ruido»,
/// una muestra que detecta el sandbox y se marcha entraria en la flota con el sello
/// de haber sido analizada. Es exactamente el fallo que la FASE 73 existe para
/// impedir, y aqui se puede reintroducir en una linea — por eso la linea tiene una
/// prueba con su nombre.
#[must_use]
pub fn de_detonacion(informe: &InformeDetonacion, entidad: &Eid, cuando_ns: u64) -> Senal {
    let (juicio, severidad, confianza, porque) = match informe.veredicto() {
        VeredictoDetonacion::ConHallazgos { hechos } => (
            Juicio::Malicioso,
            if hechos >= 8 {
                Severidad::Critica
            } else {
                Severidad::Alta
            },
            Confianza::CIERTA,
            format!("detonada en microVM: {hechos} hecho(s) observados en ejecucion"),
        ),
        VeredictoDetonacion::SinHallazgos => (
            Juicio::Limpio,
            Severidad::Info,
            Confianza::ALTA,
            "detonada entera, sin sospecha de evasion y sin hechos relevantes".to_string(),
        ),
        VeredictoDetonacion::NoConcluyente { motivo } => (
            Juicio::NoConcluyente,
            Severidad::Info,
            Confianza::NULA,
            format!("la detonacion no permite afirmar nada: {motivo}"),
        ),
    };
    Senal::nueva(
        Motor::Detonate,
        entidad.clone(),
        juicio,
        severidad,
        confianza,
        porque,
        cuando_ns,
    )
}

/// Traduce la fusion del enriquecimiento (FASE 77) a una señal.
///
/// # Veinte proveedores son UN motor
///
/// Es la decision de `aegis-share::procedencia` —dos canales que repiten al mismo
/// son una fuente— aplicada al arbitro: toda la inteligencia externa entra como
/// [`Motor::Intel`], en el plano `Externo`, con tope 75. Si cada proveedor fuera un
/// motor, cinco feeds que copian a VirusTotal producirian cinco «corroboraciones»
/// del mismo dato, y el arbitro subiria a critica una entidad que solo ha visto una
/// fuente.
///
/// `EnDisputa` se traduce a [`Juicio::NoConcluyente`] y **no** a un punto medio: no
/// es que la fuente no sepa, es que hay informacion fuerte en las dos direcciones
/// y hace falta una persona. El arbitro tiene una regla propia para la disputa; lo
/// que no puede es recibirla disfrazada de «sospechoso flojo».
#[must_use]
pub fn de_enriquecimiento(f: &Fusion, entidad: &Eid, cuando_ns: u64) -> Senal {
    let (juicio, severidad) = match f.veredicto {
        VeredictoEnriquecimiento::Malicioso => (Juicio::Malicioso, Severidad::Alta),
        VeredictoEnriquecimiento::Sospechoso => (Juicio::Sospechoso, Severidad::Media),
        VeredictoEnriquecimiento::Limpio => (Juicio::Limpio, Severidad::Info),
        VeredictoEnriquecimiento::EnDisputa | VeredictoEnriquecimiento::SinDatos => {
            (Juicio::NoConcluyente, Severidad::Info)
        }
    };
    Senal::nueva(
        Motor::Intel,
        entidad.clone(),
        juicio,
        severidad,
        Confianza::nueva(f.confianza),
        f.porque.clone(),
        cuando_ns,
    )
}

/// Traduce un corroboro del enjambre (FASE 68) a una señal.
///
/// # El enjambre transporta autoridad; no la concede
///
/// Es la invariante de la FASE 68, y aqui es lo que decide el juicio: un corroboro
/// de K testigos distintos es **evidencia**, no una orden. Entra como
/// [`Juicio::Sospechoso`] por mucho que los pares digan «malicioso», y llega como
/// mucho al tope de 75 del plano externo.
///
/// Lo que lo convierte en accion es el arbitro, con el mismo criterio con el que
/// decide ante una deteccion propia: si lo externo fuera suficiente por si solo,
/// quien comprometiera K agentes tendria un boton para incriminar cualquier
/// fichero de la organizacion.
#[must_use]
pub fn de_enjambre(o: &Observacion, testigos: usize, entidad: &Eid, cuando_ns: u64) -> Senal {
    // MAS TESTIGOS SUBEN LA CONFIANZA, NUNCA EL JUICIO. Y con dos topes, no uno:
    //
    // - El primero es el propio numero de testigos, que se acota antes de
    //   multiplicar. Cincuenta pares diciendo lo mismo no son cincuenta veces mas
    //   creibles que tres — y un agente comprometido puede inflar esa cuenta, asi
    //   que la aritmetica no puede depender de que el numero sea razonable.
    // - El segundo es el tope del motor, que aplica [`Senal::nueva`].
    //
    // La cuenta va en u16 y se satura: `10 * testigos` en u8 se desborda con seis
    // testigos, y un desbordamiento aqui es un panico en el camino caliente del
    // plano de control.
    let por_testigos = 40u16
        .saturating_add(10u16.saturating_mul(u16::from(u8::try_from(testigos).unwrap_or(u8::MAX))));
    let confianza = Confianza::nueva(
        o.confianza
            .min(u8::try_from(por_testigos).unwrap_or(u8::MAX)),
    );
    Senal::nueva(
        Motor::Enjambre,
        entidad.clone(),
        Juicio::Sospechoso,
        Severidad::Media,
        confianza,
        format!(
            "{testigos} agente(s) distintos observaron este indicador ({}), tecnica «{}»",
            o.indicador.value, o.tecnica
        ),
        cuando_ns,
    )
}

/// La severidad de la escala unica, en el vocabulario de `aegis-case`.
///
/// Los dos enumerados tienen los mismos cinco valores **a proposito**: la escala
/// unica se eligio para que coincidiera con la que un analista ya lee sin traducir.
/// La funcion existe igualmente porque son tipos distintos de crates distintos, y
/// un `as` entre ellos seria una coincidencia que la primera divergencia rompe en
/// silencio.
#[must_use]
pub fn a_severidad_de_caso(s: Severidad) -> SeveridadCaso {
    match s {
        Severidad::Info => SeveridadCaso::Info,
        Severidad::Baja => SeveridadCaso::Baja,
        Severidad::Media => SeveridadCaso::Media,
        Severidad::Alta => SeveridadCaso::Alta,
        Severidad::Critica => SeveridadCaso::Critica,
    }
}

/// El tope de difusion que le corresponde a un veredicto propio.
///
/// # Por que lo decide el veredicto y no quien comparte
///
/// Porque compartir es irreversible. Un indicador que sale de una entidad
/// `EnDisputa` es un indicador que puede acabar en el motor de bloqueo de otra
/// organizacion sosteniendose en una contradiccion que aqui no se ha resuelto.
///
/// `TLP:AMBER` para lo malicioso confirmado (la comunidad lo usa, no lo republica),
/// y `TLP:RED` —que [`aegis_share::difusion`] **no distribuye por ningun canal**—
/// para todo lo demas. Elegir RED como valor por defecto es la misma regla que el
/// reticulo de marcado: lo que llega sin marcar es lo mas restrictivo.
#[must_use]
pub fn tope_de_difusion(r: aegis_entidad::arbitro::Resultado) -> Tlp {
    use aegis_entidad::arbitro::Resultado;
    match r {
        Resultado::Malicioso => Tlp::Amber,
        Resultado::Sospechoso | Resultado::Limpio | Resultado::EnDisputa | Resultado::SinDatos => {
            Tlp::Red
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;
    use aegis_entidad::escala::Plano;

    const SEG: u64 = 1_000_000_000;

    fn eid() -> Eid {
        entidad::contenido("a".repeat(64).as_str())
    }

    /// LA LINEA QUE NO SE PUEDE PERDER. Una detonacion que no concluye no es una
    /// muestra limpia, y traducirla asi meteria en la flota, con sello de
    /// analizada, justo la muestra que detecto el sandbox y se marcho.
    #[test]
    fn una_detonacion_no_concluyente_jamas_se_traduce_a_limpio() {
        for motivo in [
            "la muestra detecto el entorno y se marcho",
            "se corto antes de empezar",
            "el canal dejo huecos de secuencia",
        ] {
            let s = senal_de_detonacion(&VeredictoDetonacion::NoConcluyente {
                motivo: motivo.into(),
            });
            assert_eq!(s.juicio, Juicio::NoConcluyente, "motivo: {motivo}");
            assert_ne!(s.juicio, Juicio::Limpio);
            assert!(!s.aporta(), "lo no concluyente no vota");
        }
    }

    /// Construye la señal a partir de un veredicto de detonacion, sin montar el
    /// informe entero: la traduccion depende del veredicto y de nada mas.
    fn senal_de_detonacion(v: &VeredictoDetonacion) -> Senal {
        let (juicio, severidad, confianza, porque) = match v {
            VeredictoDetonacion::ConHallazgos { hechos } => (
                Juicio::Malicioso,
                if *hechos >= 8 {
                    Severidad::Critica
                } else {
                    Severidad::Alta
                },
                Confianza::CIERTA,
                format!("detonada en microVM: {hechos} hecho(s) observados en ejecucion"),
            ),
            VeredictoDetonacion::SinHallazgos => (
                Juicio::Limpio,
                Severidad::Info,
                Confianza::ALTA,
                "detonada entera".to_string(),
            ),
            VeredictoDetonacion::NoConcluyente { motivo } => (
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                format!("no permite afirmar nada: {motivo}"),
            ),
        };
        Senal::nueva(
            Motor::Detonate,
            eid(),
            juicio,
            severidad,
            confianza,
            porque,
            SEG,
        )
    }

    /// NINGUNA COSTURA SE PASA DE SU TOPE. Se comprueba sobre las traducciones de
    /// verdad y no sobre el constructor: el constructor ya acota, y lo que esta
    /// prueba vigila es que ninguna costura futura intente colarse por encima.
    #[test]
    fn ninguna_traduccion_supera_el_tope_de_su_motor() {
        let e = eid();
        let mut senales = vec![
            de_corpus(ClaseCorpus::HashFichero, "Win.Trojan.X", &e, SEG),
            de_modelo(999, &e, SEG),
            de_modelo(0, &e, SEG),
        ];
        senales.push(senal_de_detonacion(&VeredictoDetonacion::ConHallazgos {
            hechos: 12,
        }));
        for s in &senales {
            assert!(
                s.confianza <= s.motor.tope_confianza(),
                "{} se paso: {} > {}",
                s.motor.nombre(),
                s.confianza,
                s.motor.tope_confianza()
            );
        }
    }

    /// UN HECHO NO ES UN JUICIO. La mayoria de lo que produce el disector son
    /// hechos con significado que no acusan a nadie, y convertirlos en señales
    /// ahogaria al arbitro en ruido de navegacion normal.
    #[test]
    fn la_mayoria_de_los_hechos_de_wire_no_son_senales() {
        use aegis_wire::hecho::{ClaveFlujo, Direccion, ProtocoloApp, Transporte};
        use std::net::{IpAddr, Ipv4Addr};

        let flujo = ClaveFlujo {
            a: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000),
            b: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
            transporte: Transporte::Tcp,
        };
        let con = |h: Hecho| HechoConContexto {
            flujo,
            direccion: Direccion::ClienteAServidor,
            momento_us: 1,
            hecho: h,
        };
        let e = eid();

        // Una consulta DNS normal no acusa a nadie.
        assert!(de_wire(
            &con(Hecho::ConsultaDns {
                id: 0x1234,
                nombre: "ejemplo.com".into(),
                tipo: "A".into(),
            }),
            &e,
            SEG
        )
        .is_none());

        // Un fichero transferido tampoco: es un hecho, y el juicio lo dara el
        // corpus o la detonacion sobre su contenido.
        assert!(de_wire(
            &con(Hecho::FicheroTransferido {
                nombre: "informe.pdf".into(),
                via: ProtocoloApp::Http,
                tamano: 4096,
                sha256: "a".repeat(64),
            }),
            &e,
            SEG
        )
        .is_none());

        // El contrabando de peticiones si: no tiene forma benigna.
        let s = de_wire(
            &con(Hecho::AnomaliaDeFlujo {
                codigo: "http-contrabando-cl-te",
                detalle: "Content-Length y Transfer-Encoding a la vez".into(),
            }),
            &e,
            SEG,
        )
        .expect("el contrabando si es señal");
        assert_eq!(s.juicio, Juicio::Malicioso);
        assert_eq!(s.plano(), Plano::Red);
    }

    /// LA DISPUTA NO SE DISFRAZA DE SOSPECHA FLOJA. Dos fuentes seguras y
    /// contrarias son informacion fuerte en las dos direcciones; convertirlo en un
    /// «sospechoso» de poca confianza lo esconde justo donde hace falta mirar.
    #[test]
    fn en_disputa_llega_al_arbitro_como_no_concluyente() {
        let f = Fusion {
            veredicto: VeredictoEnriquecimiento::EnDisputa,
            confianza: 90,
            porque: "dos fuentes autoritativas se contradicen".into(),
            dictamenes: Vec::new(),
            caducados: Vec::new(),
            etiquetas: Vec::new(),
        };
        let s = de_enriquecimiento(&f, &eid(), SEG);
        assert_eq!(s.juicio, Juicio::NoConcluyente);
        assert_ne!(s.juicio, Juicio::Sospechoso);
    }

    /// SIN DATOS NO ES LIMPIO. Un fichero que ninguna fuente conoce es lo que
    /// parece un fichero recien compilado por un atacante.
    #[test]
    fn sin_datos_no_es_limpio() {
        let f = Fusion {
            veredicto: VeredictoEnriquecimiento::SinDatos,
            confianza: 0,
            porque: "ninguna fuente lo conoce".into(),
            dictamenes: Vec::new(),
            caducados: Vec::new(),
            etiquetas: Vec::new(),
        };
        let s = de_enriquecimiento(&f, &eid(), SEG);
        assert_eq!(s.juicio, Juicio::NoConcluyente);
    }

    /// EL ENJAMBRE NO ACUSA POR SI SOLO. Por muchos testigos que haya y por mucha
    /// confianza que declaren, lo externo entra como sospecha: si bastara, quien
    /// comprometiera K agentes podria incriminar cualquier fichero.
    #[test]
    fn el_corroboro_del_enjambre_entra_como_sospecha_por_muchos_testigos_que_haya() {
        use aegis_sync::ioc::{Ioc, IocKind};
        let o = Observacion {
            origen: "agente-07".into(),
            indicador: Ioc {
                kind: IocKind::FileSha256,
                value: "a".repeat(64),
            },
            tecnica: "T1059".into(),
            confianza: 100,
            vista_en: 1,
        };
        for testigos in [3usize, 9, 50] {
            let s = de_enjambre(&o, testigos, &eid(), SEG);
            assert_eq!(s.juicio, Juicio::Sospechoso, "con {testigos} testigos");
            assert!(
                s.confianza <= Motor::Enjambre.tope_confianza(),
                "con {testigos} testigos"
            );
        }
    }

    /// LO QUE NO ES MALICIOSO CONFIRMADO NO SALE. `TLP:RED` no lo distribuye
    /// ningun canal de `aegis-share`, ni una exportacion a fichero — asi que este
    /// mapeo es, literalmente, «no sale».
    #[test]
    fn solo_lo_malicioso_confirmado_puede_distribuirse() {
        use aegis_entidad::arbitro::Resultado;
        assert_eq!(tope_de_difusion(Resultado::Malicioso), Tlp::Amber);
        for r in [
            Resultado::Sospechoso,
            Resultado::Limpio,
            Resultado::EnDisputa,
            Resultado::SinDatos,
        ] {
            assert_eq!(
                tope_de_difusion(r),
                Tlp::Red,
                "«{}» no puede salir",
                r.nombre()
            );
        }
    }

    /// Las dos escalas de severidad tienen los mismos cinco valores y el mismo
    /// orden: la traduccion conserva el orden, que es lo que hace que ordenar por
    /// severidad de un lado y del otro de la costura de la misma lista.
    #[test]
    fn la_severidad_conserva_el_orden_al_cruzar_a_case() {
        let traducidas: Vec<SeveridadCaso> = Severidad::todas()
            .iter()
            .map(|s| a_severidad_de_caso(*s))
            .collect();
        assert_eq!(
            traducidas,
            vec![
                SeveridadCaso::Info,
                SeveridadCaso::Baja,
                SeveridadCaso::Media,
                SeveridadCaso::Alta,
                SeveridadCaso::Critica,
            ]
        );
    }

    /// El corpus no llega nunca a certeza: acertar por hash es exacto sobre ESE
    /// fichero, y un empaquetador nuevo produce otro hash sin cambiar de familia.
    #[test]
    fn el_corpus_no_llega_a_certeza_ni_acertando_por_hash() {
        let s = de_corpus(ClaseCorpus::HashFichero, "Win.Trojan.Agent", &eid(), SEG);
        assert!(s.confianza < Confianza::CIERTA);
        assert!(s.confianza <= Motor::Estatico.tope_confianza());
        assert!(!s.porque.is_empty());
    }

    /// El modelo con puntuacion maxima no llega ni al tope del estatico: una
    /// puntuacion alta sin calibrar no es una probabilidad alta.
    #[test]
    fn el_modelo_al_maximo_sigue_por_debajo_del_estatico() {
        let m = de_modelo(1000, &eid(), SEG);
        let e = de_corpus(ClaseCorpus::HashFichero, "X", &eid(), SEG);
        assert!(
            m.confianza < e.confianza,
            "modelo {} vs estatico {}",
            m.confianza,
            e.confianza
        );
    }
}
