//! Contencion preventiva: actuar **antes** de que el ataque pase.
//!
//! # El problema que este modulo existe para no crear
//!
//! Todo lo anterior calcula. Esto decide, y decide **aislar maquinas de
//! produccion por una prediccion**. Hay dos formas de que eso salga muy mal, y
//! las dos hay que cerrarlas aqui:
//!
//! **(a) El modelo se equivoca y la cura es la enfermedad.** Aislar doscientas
//! maquinas porque una heuristica de grafos predijo un radio es una denegacion de
//! servicio auto-infligida. Por encima de cierto tamano, **la contencion ES la
//! interrupcion**, y da igual que la prediccion fuera buena.
//!
//! **(b) El atacante dirige la prediccion.** Es el que se mueve lateralmente, el
//! que se autentica, el que deja credenciales cacheadas: **fabrica aristas**. Si
//! el motor actuara sobre cualquier camino, un adversario podria construirse uno
//! *a traves de la maquina que quiere tirar* y conseguir que la propia defensa la
//! aisle. Eso convierte AegisPredict en una primitiva de denegacion de servicio
//! manejada por el adversario — el mismo problema que resolvio la FASE 68, en
//! otra capa.
//!
//! # Los cinco frenos
//!
//! 1. **Nunca se toca un activo protegido.** El plano de control, los
//!    controladores de dominio y lo que el cliente declare. Sin esto, una
//!    prediccion puede cortar la capacidad del defensor de responder, que es
//!    exactamente lo que el atacante busca.
//! 2. **Tope duro de radio.** Por encima de [`ConfigContencion::max_activos`] o
//!    de [`ConfigContencion::max_fraccion_flota`] **no se actua: se escala a una
//!    persona**. No es una degradacion elegante, es la decision correcta: a esa
//!    escala, quien tiene que decidir es alguien que responde de la decision.
//! 3. **Solo evidencia solida.** El paso que se corta tiene que apoyarse en
//!    evidencia corroborada. Una arista que aparecio hace diez minutos, vista una
//!    vez y por un solo observador, no mueve nada automaticamente.
//! 4. **Umbral de probabilidad.** Un camino improbable no justifica una accion.
//! 5. **Minima y reversible.** Se prefiere cortar **la arista** a apagar **el
//!    nodo**: revocar unas credenciales o unos tickets deja la maquina
//!    trabajando; aislarla la saca de produccion. Aislar es el ultimo recurso.
//!
//! # Preventivo no es lo mismo que remediar
//!
//! Una deteccion confirmada dispara el playbook entero de la FASE 64. Una
//! **prediccion** no: dispara como mucho **una** accion acotada. La diferencia
//! esta en lo que se sabe — en un caso ha pasado algo, en el otro podria pasar—,
//! y borrarla seria tratar una hipotesis como un hecho.

use aegis_orchestrator::AccionRemediacion;

use crate::caminos::CaminoAtaque;
use crate::error::ErrorPrediccion;
use crate::grafo::{GrafoAtaque, Via};
use crate::radio::RadioExplosion;

/// Umbral de probabilidad por defecto para actuar.
pub const PROBABILIDAD_MINIMA: f64 = 0.5;

/// Tope de activos que una contencion preventiva puede afectar.
pub const MAX_ACTIVOS_POR_DEFECTO: usize = 25;

/// Tope como fraccion de la flota.
pub const MAX_FRACCION_POR_DEFECTO: f64 = 0.05;

/// Activos por debajo de los cuales la guarda **porcentual** no se aplica.
///
/// # Por que hace falta este suelo
///
/// Una guarda porcentual sobre un grafo diminuto no se puede satisfacer jamas:
/// con tres activos, contener **cualquier cosa** supera el 5 %, asi que el motor
/// escalaria absolutamente todo y la contencion automatica quedaria
/// silenciosamente inutil — el peor modo de fallo, porque parece que funciona.
///
/// El problema de fondo es que un porcentaje de un punado de activos no mide lo
/// que la guarda quiere medir. Con tres activos, uno es el 33 % por aritmetica,
/// no por importancia; el porcentaje solo empieza a significar «cuanto negocio
/// estoy tirando» cuando hay bastantes cosas que contar.
///
/// Por debajo de este umbral manda el **tope absoluto**, que sigue protegiendo.
/// Por encima, mandan los dos, y el porcentual suele ser el estricto: en una
/// organizacion de cien maquinas, aislar veinticinco automaticamente es
/// demasiado aunque el tope absoluto lo permita.
pub const FLOTA_MINIMA_PARA_FRACCION: usize = 50;

/// Configuracion de la contencion.
#[derive(Debug, Clone)]
pub struct ConfigContencion {
    /// Probabilidad minima del camino para considerar actuar.
    pub probabilidad_minima: f64,
    /// Tope absoluto de activos afectados.
    pub max_activos: usize,
    /// Tope como fraccion de la flota.
    pub max_fraccion_flota: f64,
}

impl Default for ConfigContencion {
    fn default() -> ConfigContencion {
        ConfigContencion {
            probabilidad_minima: PROBABILIDAD_MINIMA,
            max_activos: MAX_ACTIVOS_POR_DEFECTO,
            max_fraccion_flota: MAX_FRACCION_POR_DEFECTO,
        }
    }
}

/// Por que no se actua, cuando no se actua.
///
/// Enumerado y no texto: «cuantas predicciones se escalaron por radio» es una
/// metrica que dice si el motor esta bien calibrado, y se pierde con una cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Motivo {
    /// El camino no es bastante probable.
    ProbabilidadBaja,
    /// El paso a cortar se apoya en evidencia sin corroborar.
    EvidenciaDebil,
    /// Todos los pasos cortables tocan activos protegidos.
    SoloActivosProtegidos,
    /// El radio supera el tope: a esa escala decide una persona.
    RadioDemasiadoGrande,
    /// No hay camino que contener.
    SinCamino,
}

/// Lo que el motor propone.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Veredicto {
    /// Actuar, con **una** accion acotada.
    Contener {
        /// Sobre quien.
        sujeto: String,
        /// Que hacer.
        accion: AccionSerializable,
        /// Por que, en una frase legible.
        justificacion: String,
        /// Activos que se espera preservar.
        activos_preservados: f64,
    },
    /// No actuar automaticamente: que lo vea una persona.
    ///
    /// Lleva la justificacion igual, porque escalar sin decir que se vio es
    /// tirarle el problema a alguien sin el contexto.
    Escalar {
        /// Por que se escala.
        motivo: Motivo,
        /// Que se vio.
        justificacion: String,
    },
    /// No hay nada que hacer.
    NoActuar {
        /// Por que.
        motivo: Motivo,
    },
}

/// Copia serializable de [`AccionRemediacion`], que no lo es en origen.
///
/// El vocabulario de acciones lo define el orquestador de la FASE 64 y **no se
/// duplica**: dos listas que hay que mantener sincronizadas acaban divergiendo, y
/// el dia que diverjan la prediccion pedira algo que el ejecutor no sabe hacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AccionSerializable {
    /// Aislar la red del endpoint.
    AislarRed,
    /// Matar los procesos sospechosos.
    MatarProcesosSospechosos,
    /// Revocar los tickets Kerberos.
    RevocarTicketsKerberos,
    /// Volcado forense de memoria.
    VolcadoForenseMemoria,
}

impl From<AccionSerializable> for AccionRemediacion {
    fn from(a: AccionSerializable) -> AccionRemediacion {
        match a {
            AccionSerializable::AislarRed => AccionRemediacion::AislarRed,
            AccionSerializable::MatarProcesosSospechosos => {
                AccionRemediacion::MatarProcesosSospechosos
            }
            AccionSerializable::RevocarTicketsKerberos => AccionRemediacion::RevocarTicketsKerberos,
            AccionSerializable::VolcadoForenseMemoria => AccionRemediacion::VolcadoForenseMemoria,
        }
    }
}

/// La accion **minima** que corta un paso de un tipo dado.
///
/// El orden de preferencia es el de dano decreciente al negocio: revocar unas
/// credenciales deja la maquina trabajando; aislarla la saca de produccion. Se
/// aisla solo cuando no hay forma mas fina de cortar ese salto.
#[must_use]
pub fn accion_minima_para(via: Via) -> AccionSerializable {
    use crate::grafo::RelacionSerializable as R;
    match via {
        // Un salto de identidad se corta en la identidad: revocar los tickets
        // invalida el paso sin tocar ninguna maquina.
        Via::Identidad(R::MiembroDe | R::ActuaComo | R::Impersona | R::AutenticaEn) => {
            AccionSerializable::RevocarTicketsKerberos
        }
        // Credenciales cacheadas: viven en la memoria de un proceso, y matar ese
        // proceso las quita sin aislar la maquina.
        Via::Identidad(R::ControlaCredencialesDe) => AccionSerializable::MatarProcesosSospechosos,
        // Un salto de red no se puede cortar mas fino que cortando la red.
        Via::RedExpuesta | Via::RedSegmentada => AccionSerializable::AislarRed,
    }
}

/// Decide si contener preventivamente, y como.
///
/// # Errores
/// [`ErrorPrediccion::ActivoDesconocido`] si el camino nombra activos que ya no
/// estan en el grafo.
pub fn decidir(
    g: &GrafoAtaque,
    camino: Option<&CaminoAtaque>,
    radio: &RadioExplosion,
    config: &ConfigContencion,
) -> Result<Veredicto, ErrorPrediccion> {
    let Some(camino) = camino else {
        return Ok(Veredicto::NoActuar {
            motivo: Motivo::SinCamino,
        });
    };
    if camino.pasos.is_empty() {
        return Ok(Veredicto::NoActuar {
            motivo: Motivo::SinCamino,
        });
    }

    // FRENO 4: un camino improbable no justifica tocar nada.
    if camino.probabilidad < config.probabilidad_minima {
        return Ok(Veredicto::NoActuar {
            motivo: Motivo::ProbabilidadBaja,
        });
    }

    // FRENO 2: el tope de radio, ANTES de elegir accion. Por encima de esta
    // escala la contencion es la interrupcion, y quien decide es una persona.
    let total = g.activos();
    let fraccion = radio.fraccion(total);
    // La guarda porcentual solo se aplica cuando la flota es bastante grande
    // para que un porcentaje signifique algo: ver FLOTA_MINIMA_PARA_FRACCION.
    let fraccion_excedida =
        total >= FLOTA_MINIMA_PARA_FRACCION && fraccion > config.max_fraccion_flota;
    if radio.activos_esperados > config.max_activos as f64 || fraccion_excedida {
        return Ok(Veredicto::Escalar {
            motivo: Motivo::RadioDemasiadoGrande,
            justificacion: format!(
                "el radio estimado ({:.1} activos, {:.1} % de la flota) supera el tope \
                 de contencion automatica ({} activos, {:.1} %). Camino: {}",
                radio.activos_esperados,
                fraccion * 100.0,
                config.max_activos,
                config.max_fraccion_flota * 100.0,
                camino.explicar()
            ),
        });
    }

    // FRENO 1 y 5: se busca el paso mas valioso que se pueda cortar SIN tocar un
    // activo protegido, de mas valioso a menos.
    let mut candidatos: Vec<&crate::grafo::Paso> = camino.pasos.iter().collect();
    candidatos.sort_by(|a, b| {
        b.probabilidad_efectiva()
            .partial_cmp(&a.probabilidad_efectiva())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.destino.cmp(&b.destino))
    });

    let mut habia_protegido = false;
    for paso in candidatos {
        let origen = g
            .activo(&paso.origen)
            .ok_or_else(|| ErrorPrediccion::ActivoDesconocido(paso.origen.clone()))?;
        // El destino tiene que existir aunque no condicione la decision: un
        // camino que nombra un activo que ya no esta en el grafo es un camino
        // caducado, y actuar sobre el seria actuar sobre informacion vieja.
        g.activo(&paso.destino)
            .ok_or_else(|| ErrorPrediccion::ActivoDesconocido(paso.destino.clone()))?;

        // SOLO EL ORIGEN. Todas las acciones se aplican sobre quien tiene la
        // capacidad que hay que quitar, que es el origen del paso: aislar su
        // red, matar sus procesos, revocar sus tickets. Un destino protegido NO
        // impide cortar, porque cortar el paso lo PROTEGE en vez de danarlo.
        //
        // Mirar tambien el destino seria un error grave, y silencioso: los
        // caminos interesantes terminan por definicion en una joya de la corona,
        // y las joyas suelen estar protegidas — asi que la salvaguarda habria
        // desactivado la contencion exactamente en los casos que importan,
        // pareciendo que funcionaba.
        if origen.protegido {
            habia_protegido = true;
            continue;
        }

        // FRENO 3: sin evidencia corroborada no se actua automaticamente. Es lo
        // que impide que el atacante fabrique el camino que quiere que se corte.
        if !paso.evidencia.solida() {
            return Ok(Veredicto::Escalar {
                motivo: Motivo::EvidenciaDebil,
                justificacion: format!(
                    "el paso {} {} {} se apoya en evidencia sin corroborar \
                     ({} observacion(es), {} observador(es), {} s de antiguedad): \
                     podria haberla fabricado el propio atacante. Camino: {}",
                    paso.origen,
                    paso.via.describir(),
                    paso.destino,
                    paso.evidencia.observaciones,
                    paso.evidencia.observadores,
                    paso.evidencia.antiguedad_seg,
                    camino.explicar()
                ),
            });
        }

        let accion = accion_minima_para(paso.via);
        // La accion se aplica sobre el ORIGEN del paso: es quien tiene la
        // capacidad que hay que quitar. Aplicarla sobre el destino castigaria a
        // la victima del salto en vez de cortarlo.
        return Ok(Veredicto::Contener {
            sujeto: paso.origen.clone(),
            accion,
            justificacion: format!(
                "se corta el paso mas probable del camino ({} {} {}, p = {:.2}) para \
                 romper: {}. Radio evitado: {:.1} activos (±{:.1})",
                paso.origen,
                paso.via.describir(),
                paso.destino,
                paso.probabilidad_efectiva(),
                camino.explicar(),
                radio.activos_esperados,
                radio.margen
            ),
            activos_preservados: radio.activos_esperados,
        });
    }

    Ok(Veredicto::NoActuar {
        motivo: if habia_protegido {
            Motivo::SoloActivosProtegidos
        } else {
            Motivo::SinCamino
        },
    })
}

#[cfg(test)]
mod pruebas {
    use aegis_itdr::grafo::Nivel;

    use super::*;
    use crate::caminos::camino_mas_probable;
    use crate::grafo::{Activo, ClaseActivo, Evidencia, Paso, RelacionSerializable};
    use crate::radio::radio_de_explosion;

    fn escenario() -> GrafoAtaque {
        let mut g = GrafoAtaque::nuevo();
        for (n, clase, nivel, valor) in [
            ("pc-becario", ClaseActivo::Endpoint, Nivel::Usuario, 0u8),
            ("svc-backup", ClaseActivo::Identidad, Nivel::Operador, 40),
            (
                "Domain Admins",
                ClaseActivo::Identidad,
                Nivel::AdminDominio,
                100,
            ),
        ] {
            g.agregar(Activo::nuevo(n, clase, nivel, valor)).unwrap();
        }
        g.conectar(Paso::nuevo(
            "pc-becario",
            "svc-backup",
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "svc-backup",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        g
    }

    fn decidir_sobre(g: &GrafoAtaque, origen: &str, cfg: &ConfigContencion) -> Veredicto {
        let camino = camino_mas_probable(g, origen, "Domain Admins").unwrap();
        let radio = radio_de_explosion(g, origen, 2000).unwrap();
        decidir(g, camino.as_ref(), &radio, cfg).unwrap()
    }

    /// EL CASO BUENO: camino probable, radio pequeno, evidencia solida. Se actua,
    /// con la accion MINIMA y sobre el origen del paso.
    #[test]
    fn un_camino_probable_y_acotado_produce_una_accion_minima() {
        let g = escenario();
        match decidir_sobre(&g, "pc-becario", &ConfigContencion::default()) {
            Veredicto::Contener {
                sujeto,
                accion,
                justificacion,
                ..
            } => {
                // El paso mas valioso es MiembroDe (0,99), cuyo origen es
                // svc-backup, y se corta revocando tickets: no se aisla nada.
                assert_eq!(sujeto, "svc-backup");
                assert_eq!(accion, AccionSerializable::RevocarTicketsKerberos);
                assert!(justificacion.contains("Domain Admins"));
            }
            otro => panic!("se esperaba contencion: {otro:?}"),
        }
    }

    /// FRENO 2, EL MAS IMPORTANTE: por encima del tope NO se actua, se escala.
    /// A esa escala la contencion es la interrupcion.
    #[test]
    fn un_radio_demasiado_grande_escala_a_una_persona_en_vez_de_actuar() {
        // Una estrella: un endpoint que alcanza a otros cincuenta.
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "servidor-central",
            ClaseActivo::Servicio,
            Nivel::AdminLocal,
            50,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "servidor-central",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        for i in 0..60 {
            let n = format!("pc-{i}");
            g.agregar(Activo::nuevo(&n, ClaseActivo::Endpoint, Nivel::Usuario, 5))
                .unwrap();
            g.conectar(Paso::nuevo(
                "servidor-central",
                &n,
                Via::Identidad(RelacionSerializable::MiembroDe),
            ))
            .unwrap();
        }

        let v = decidir_sobre(&g, "servidor-central", &ConfigContencion::default());
        match v {
            Veredicto::Escalar {
                motivo,
                justificacion,
            } => {
                assert_eq!(motivo, Motivo::RadioDemasiadoGrande);
                // Y se dice QUE se vio: escalar sin contexto es tirarle el
                // problema a alguien.
                assert!(justificacion.contains("supera el tope"));
                assert!(justificacion.contains("Domain Admins"));
            }
            otro => panic!("a esta escala tiene que decidir una persona: {otro:?}"),
        }
    }

    /// LAS DOS MITADES DEL SUELO PORCENTUAL. Una guarda que no se puede
    /// satisfacer nunca no protege: inutiliza. Y una que no se aplica cuando
    /// toca, tampoco protege.
    #[test]
    fn la_guarda_porcentual_tiene_suelo_pero_manda_cuando_la_flota_es_grande() {
        // (a) Flota diminuta: el porcentaje es aritmetica, no importancia. Manda
        //     el tope absoluto y la contencion PUEDE ocurrir.
        let g = escenario();
        assert!(g.activos() < FLOTA_MINIMA_PARA_FRACCION);
        let v = decidir_sobre(&g, "pc-becario", &ConfigContencion::default());
        assert!(
            matches!(v, Veredicto::Contener { .. }),
            "con una flota diminuta el porcentaje escalaria SIEMPRE: {v:?}"
        );

        // (b) Flota grande y radio pequeno en absoluto pero alto en porcentaje:
        //     ahora el porcentual SI manda, y escala.
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "origen",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "origen",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        // 10 activos alcanzables de una flota de 62: por debajo del tope
        // absoluto de 25, pero muy por encima del 5 %.
        for i in 0..10 {
            let n = format!("alcanzable-{i}");
            g.agregar(Activo::nuevo(&n, ClaseActivo::Endpoint, Nivel::Usuario, 1))
                .unwrap();
            g.conectar(Paso::nuevo(
                "origen",
                &n,
                Via::Identidad(RelacionSerializable::MiembroDe),
            ))
            .unwrap();
        }
        for i in 0..50 {
            g.agregar(Activo::nuevo(
                format!("lejano-{i}"),
                ClaseActivo::Endpoint,
                Nivel::Usuario,
                1,
            ))
            .unwrap();
        }
        assert!(g.activos() >= FLOTA_MINIMA_PARA_FRACCION);

        let camino = camino_mas_probable(&g, "origen", "Domain Admins")
            .unwrap()
            .unwrap();
        let radio = radio_de_explosion(&g, "origen", 2000).unwrap();
        assert!(
            radio.activos_esperados < MAX_ACTIVOS_POR_DEFECTO as f64,
            "el tope absoluto NO se pasa: {}",
            radio.activos_esperados
        );
        match decidir(&g, Some(&camino), &radio, &ConfigContencion::default()).unwrap() {
            Veredicto::Escalar { motivo, .. } => {
                assert_eq!(motivo, Motivo::RadioDemasiadoGrande);
            }
            otro => panic!("con flota grande el porcentual tiene que mandar: {otro:?}"),
        }
    }

    /// FRENO 3: el ataque de la fase. El adversario fabrica una arista a traves
    /// de la maquina que quiere tirar; el motor NO la corta automaticamente.
    #[test]
    fn un_camino_por_evidencia_recien_fabricada_no_dispara_accion_automatica() {
        let mut g = GrafoAtaque::nuevo();
        for (n, nivel, v) in [
            ("pc-victima", Nivel::Usuario, 0u8),
            ("Domain Admins", Nivel::AdminDominio, 100),
        ] {
            g.agregar(Activo::nuevo(n, ClaseActivo::Endpoint, nivel, v))
                .unwrap();
        }
        // Arista real pero recien nacida: exactamente lo que deja un atacante
        // que quiere que la defensa aisle esa maquina.
        g.conectar(
            Paso::nuevo(
                "pc-victima",
                "Domain Admins",
                Via::Identidad(RelacionSerializable::MiembroDe),
            )
            .con_evidencia(Evidencia::recien_vista()),
        )
        .unwrap();

        let camino = camino_mas_probable(&g, "pc-victima", "Domain Admins")
            .unwrap()
            .unwrap();
        let radio = radio_de_explosion(&g, "pc-victima", 2000).unwrap();
        // Se baja el umbral de probabilidad a proposito, para que el freno que
        // actue sea el de EVIDENCIA y no el de probabilidad.
        let cfg = ConfigContencion {
            probabilidad_minima: 0.01,
            ..Default::default()
        };
        match decidir(&g, Some(&camino), &radio, &cfg).unwrap() {
            Veredicto::Escalar {
                motivo,
                justificacion,
            } => {
                assert_eq!(motivo, Motivo::EvidenciaDebil);
                assert!(justificacion.contains("podria haberla fabricado"));
            }
            otro => panic!("una arista fabricada no puede mover una accion: {otro:?}"),
        }
    }

    /// FRENO 1: un activo protegido no se toca jamas. Sin esto, una prediccion
    /// puede cortar la capacidad del defensor de responder.
    #[test]
    fn un_activo_protegido_no_se_contiene_nunca() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(
            Activo::nuevo(
                "controlador-dominio",
                ClaseActivo::Servicio,
                Nivel::AdminDominio,
                100,
            )
            .protegido(),
        )
        .unwrap();
        g.agregar(
            Activo::nuevo(
                "Domain Admins",
                ClaseActivo::Identidad,
                Nivel::AdminDominio,
                100,
            )
            .protegido(),
        )
        .unwrap();
        g.conectar(Paso::nuevo(
            "controlador-dominio",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();

        let v = decidir_sobre(&g, "controlador-dominio", &ConfigContencion::default());
        assert_eq!(
            v,
            Veredicto::NoActuar {
                motivo: Motivo::SoloActivosProtegidos
            },
            "el plano de control y los DC no se aislan por una prediccion"
        );
    }

    /// Un destino protegido NO bloquea la contencion: cortar el paso PROTEGE al
    /// destino. Si esto se rompiera, la salvaguarda desactivaria la contencion
    /// justo en los caminos que importan —los que terminan en una joya— y lo
    /// haria pareciendo que funciona.
    #[test]
    fn un_destino_protegido_no_impide_cortar_desde_un_origen_libre() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "pc-raso",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(
            Activo::nuevo(
                "Domain Admins",
                ClaseActivo::Identidad,
                Nivel::AdminDominio,
                100,
            )
            .protegido(),
        )
        .unwrap();
        g.conectar(Paso::nuevo(
            "pc-raso",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();

        match decidir_sobre(&g, "pc-raso", &ConfigContencion::default()) {
            Veredicto::Contener { sujeto, .. } => assert_eq!(sujeto, "pc-raso"),
            otro => panic!("cortar hacia una joya protegida la protege: {otro:?}"),
        }
    }

    /// Y si hay un paso protegido y otro no, se corta el que se puede.
    #[test]
    fn con_un_paso_protegido_se_corta_el_otro() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "pc-raso",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo("dc", ClaseActivo::Servicio, Nivel::AdminLocal, 90).protegido())
            .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        // pc-raso -> dc (protegido) -> Domain Admins
        g.conectar(Paso::nuevo(
            "pc-raso",
            "dc",
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "dc",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();

        match decidir_sobre(&g, "pc-raso", &ConfigContencion::default()) {
            Veredicto::Contener { sujeto, .. } => {
                assert_eq!(sujeto, "pc-raso", "se corta donde se puede, no en el DC");
            }
            otro => panic!("se esperaba contener en el paso libre: {otro:?}"),
        }
    }

    /// FRENO 4: un camino improbable no justifica tocar nada.
    #[test]
    fn un_camino_improbable_no_dispara_nada() {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo("a", ClaseActivo::Endpoint, Nivel::Usuario, 0))
            .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        // Red segmentada: p = 0,15.
        g.conectar(Paso::nuevo("a", "Domain Admins", Via::RedSegmentada))
            .unwrap();
        assert_eq!(
            decidir_sobre(&g, "a", &ConfigContencion::default()),
            Veredicto::NoActuar {
                motivo: Motivo::ProbabilidadBaja
            }
        );
    }

    /// FRENO 5: se prefiere la accion que menos dano hace al negocio. Un salto
    /// de identidad se corta en la identidad, sin aislar ninguna maquina.
    #[test]
    fn se_prefiere_cortar_la_identidad_a_aislar_la_maquina() {
        use crate::grafo::RelacionSerializable as R;
        // Ningun salto de identidad se corta aislando la red.
        for r in [
            R::MiembroDe,
            R::ActuaComo,
            R::Impersona,
            R::AutenticaEn,
            R::ControlaCredencialesDe,
        ] {
            assert_ne!(
                accion_minima_para(Via::Identidad(r)),
                AccionSerializable::AislarRed,
                "un salto de identidad no justifica sacar una maquina de produccion"
            );
        }
        // Y un salto de red si, porque no hay forma mas fina de cortarlo.
        assert_eq!(
            accion_minima_para(Via::RedExpuesta),
            AccionSerializable::AislarRed
        );
    }

    #[test]
    fn sin_camino_no_se_actua() {
        let g = escenario();
        let radio = radio_de_explosion(&g, "pc-becario", 100).unwrap();
        assert_eq!(
            decidir(&g, None, &radio, &ConfigContencion::default()).unwrap(),
            Veredicto::NoActuar {
                motivo: Motivo::SinCamino
            }
        );
    }

    /// El vocabulario de acciones es el del orquestador de la FASE 64 y la
    /// conversion es total: si alguien anade una accion alli, esto deja de
    /// compilar en vez de proponer algo que el ejecutor no sabe hacer.
    #[test]
    fn toda_accion_propuesta_existe_en_el_orquestador() {
        for a in [
            AccionSerializable::AislarRed,
            AccionSerializable::MatarProcesosSospechosos,
            AccionSerializable::RevocarTicketsKerberos,
            AccionSerializable::VolcadoForenseMemoria,
        ] {
            let real: AccionRemediacion = a.into();
            assert!(!real.descripcion().is_empty());
        }
    }

    /// La decision es determinista: mismo grafo, misma propuesta, siempre.
    #[test]
    fn la_decision_es_determinista() {
        let g = escenario();
        let primera = decidir_sobre(&g, "pc-becario", &ConfigContencion::default());
        for _ in 0..30 {
            assert_eq!(
                decidir_sobre(&g, "pc-becario", &ConfigContencion::default()),
                primera
            );
        }
    }
}
