//! La FUENTE DE VERDAD de los motores registrables del agente, generada por el
//! propio codigo (Hallazgo 0 de la FASE 4 del MP-16).
//!
//! # El problema que cierra
//!
//! La cobertura del rango salia de una lista `cableados` escrita a mano en
//! `server/crates/aegis-rango/tests/cobertura.rs`, que nadie contrastaba con el
//! agente: daba por cableados motores que el arbitro no registra (Detonate, Wire,
//! Ips, ...) y por hueco el conductual, que si lo esta desde la FASE 1. Una cifra
//! de cobertura sacada de una tabla falsa es una mentira, no una medida.
//!
//! # La solucion, de raiz
//!
//! Los motores se construyen UNA sola vez, aqui ([`construir`]), y de esa misma
//! lista sale (a) lo que `main` registra en el arbitro y (b) lo que
//! `aegis-agent --motores` imprime. La ficha de cada motor —nombre, firma, camino
//! y requisitos— se saca del propio motor, no de una tabla paralela. El fichero
//! `docs/generado/motores.txt` se regenera de esta salida y una prueba falla si el
//! fichero y el codigo no coinciden ([`pruebas::el_fichero_generado_esta_al_dia`]).
//! El rango lee ese fichero, no una lista propia.
//!
//! # Una sola lista con TODOS los motores
//!
//! [`construir`] es la UNICA lista, en el orden en que `main` los registra: el
//! triaje, el conductual, el secuestro, el estatico, el modelo, Sigma, la
//! integridad, la memoria, el nucleo, la baliza, la postura y el rol. Los que solo
//! existen con la caracteristica `bpf` (el nucleo y Sigma) llevan su `#[cfg]`, el
//! mismo que en los modulos de donde salen. Añadir un motor es añadir una linea
//! aqui: aparece a la vez en el arbitro, en `--motores` y en el fichero generado,
//! y no hay forma de que diverjan.
//!
//! # Inerte a proposito
//!
//! Construir los motores para listarlos NO arranca el trabajador confinado ni
//! engancha ninguna sonda: [`fichas`] crea el estatico con [`MotorEstatico::inerte`],
//! el rol sin persistencia en disco, y el resto con una identidad fija. La ficha es
//! la misma que tendrian en marcha, que es lo unico que se lista.

use std::sync::{Arc, Mutex};

use aegis_motor::{Ficha, Motor};

use crate::motores::baliza::MotorBaliza;
use crate::motores::conducta::MotorConducta;
use crate::motores::estatico::{MotorEstatico, MotorModelo};
use crate::motores::integridad::MotorIntegridad;
use crate::motores::memoria::MotorMemoria;
#[cfg(feature = "bpf")]
use crate::motores::nucleo::MotorNucleo;
use crate::motores::postura::MotorPostura;
use crate::motores::rol::{ConfigRol, MotorRol};
use crate::motores::secuestro::MotorSecuestro;
#[cfg(feature = "bpf")]
use crate::motores::sigma::MotorSigma;
use crate::motores::triaje::MotorTriaje;
use crate::motores::{EventoAgente, Identidad};
use crate::{GraphConfig, Pipeline, TriageConfig};

/// Construye los motores que el agente registra, en el orden en que los registra.
///
/// Es la UNICA lista. `main` la llama con el estatico REAL (con su trabajador), la
/// integridad y el rol ya construidos —de los que ya ha informado al arrancar— y el
/// pipeline y los informes compartidos; [`fichas`] la llama con un estatico inerte,
/// una integridad y un rol inertes y un pipeline propio, solo para leer las fichas.
/// Un motor nuevo se añade aqui y aparece en los dos sitios a la vez.
///
/// `estatico`, `integridad` y `rol` llegan ya construidos porque `main` informa de
/// su estado al arrancar (`rol.resumen()`, `integridad.vigilados()`) y el estatico
/// trae su trabajador confinado; el resto se construye aqui, sin estado que `main`
/// necesite ver.
#[must_use]
pub fn construir(
    identidad: &Identidad,
    pipeline: Arc<Pipeline>,
    estatico: MotorEstatico,
    integridad: MotorIntegridad,
    rol: MotorRol,
    informe_postura: Arc<Mutex<Vec<String>>>,
) -> Vec<Box<dyn Motor<EventoAgente>>> {
    // Los que existen siempre van en `vec![]`; los que solo existen con `bpf`
    // (nucleo y Sigma) se intercalan con `push` en su sitio exacto del orden,
    // porque el macro `vec!` no admite `#[cfg]` en sus elementos (su fragmento
    // `:expr` no acepta atributos).
    let mut motores: Vec<Box<dyn Motor<EventoAgente>>> = vec![
        Box::new(MotorTriaje::nuevo(
            pipeline,
            GraphConfig::default().max_nodes,
        )),
        Box::new(MotorConducta::nuevo(identidad.clone())),
        Box::new(MotorSecuestro::nuevo(identidad.clone())),
        Box::new(estatico),
        Box::new(MotorModelo),
    ];
    #[cfg(feature = "bpf")]
    motores.push(Box::new(MotorSigma::incluidas()));
    motores.push(Box::new(integridad));
    motores.push(Box::new(MotorMemoria::nuevo()));
    #[cfg(feature = "bpf")]
    motores.push(Box::new(MotorNucleo::nuevo(identidad)));
    motores.push(Box::new(MotorBaliza::nuevo()));
    motores.push(Box::new(MotorPostura::nuevo(
        identidad.clone(),
        informe_postura,
    )));
    motores.push(Box::new(rol));
    motores
}

/// Las fichas de los motores registrables, construyendolos INERTES.
///
/// No arranca el trabajador ni engancha sondas, ni toca disco para el rol: solo lee
/// la presentacion de cada motor. El orden es el de registro; las fichas se ordenan
/// por nombre en el texto generado para que el fichero sea estable.
#[must_use]
pub fn fichas() -> Vec<Ficha> {
    let identidad = Identidad::fija("motores");
    let pipeline = Arc::new(Pipeline::new(
        GraphConfig::default(),
        TriageConfig::default(),
    ));
    let integridad = MotorIntegridad::nuevo(identidad.clone());
    // El rol sin persistencia: listar las fichas no puede leer ni escribir la linea
    // base del host.
    let config_rol = ConfigRol {
        persistencia: None,
        ..ConfigRol::del_host()
    };
    let rol = MotorRol::nuevo(config_rol, Arc::new(Mutex::new(Vec::new())));
    construir(
        &identidad,
        pipeline,
        MotorEstatico::inerte(),
        integridad,
        rol,
        Arc::new(Mutex::new(Vec::new())),
    )
    .iter()
    .map(|m| m.ficha())
    .collect()
}

/// Una linea por motor: `nombre<TAB>firma<TAB>camino<TAB>req1,req2`.
///
/// La `firma` es lo que el rango necesita: es en nombre de que motor de
/// `aegis_entidad::Motor` llegan las señales al arbitro, y por tanto que tecnicas
/// PODRIA cubrir el conjunto de motores registrados.
fn linea(f: &Ficha) -> String {
    let requisitos = f
        .requisitos
        .iter()
        .map(|r| r.nombre())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}\t{}\t{}\t{}",
        f.nombre,
        f.firma.nombre(),
        f.camino.nombre(),
        requisitos
    )
}

/// El texto exacto de `docs/generado/motores.txt`: cabecera, una linea por motor
/// ordenada por nombre, y salto final. Es lo que imprime `--motores` y con lo que
/// la prueba contrasta el fichero.
#[must_use]
pub fn texto_generado() -> String {
    let mut lineas: Vec<String> = fichas().iter().map(linea).collect();
    lineas.sort();
    let mut s = String::new();
    s.push_str("# Motores registrables del agente. GENERADO por el codigo:\n");
    s.push_str("#   aegis-agent --motores > docs/generado/motores.txt\n");
    s.push_str("# No editar a mano: la prueba `el_fichero_generado_esta_al_dia`\n");
    s.push_str("# (crates/aegis-agent/src/motores/registro.rs) falla si difiere.\n");
    s.push_str("# columnas: nombre <TAB> firma <TAB> camino <TAB> requisitos\n");
    for l in lineas {
        s.push_str(&l);
        s.push('\n');
    }
    s
}

/// Ruta del fichero generado, relativa al manifiesto del agente.
const FICHERO_GENERADO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/generado/motores.txt"
);

/// Escribe el fichero generado (para `--motores --escribir`, uso de desarrollo).
///
/// # Errores
/// Si no se puede escribir el fichero.
pub fn escribir_fichero() -> std::io::Result<()> {
    std::fs::write(FICHERO_GENERADO, texto_generado())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_fichero_generado_esta_al_dia() {
        // LA PUERTA. Si alguien añade, quita o cambia un motor y no regenera
        // docs/generado/motores.txt, esto falla en make ci: el rango medira
        // contra el fichero, y un fichero desviado del codigo es justo la mentira
        // que el Hallazgo 0 vino a cerrar. Si el fichero NO EXISTE todavia, falla
        // igual, con la orden exacta para generarlo: una medida sin fuente de
        // verdad no es honesta.
        let esperado = texto_generado();
        let en_disco = std::fs::read_to_string(FICHERO_GENERADO).unwrap_or_else(|e| {
            panic!(
                "no se pudo leer la fuente de verdad {FICHERO_GENERADO}: {e}. \
                 Generala: cargo run -p aegis-agent --features bpf -- --motores \
                 > docs/generado/motores.txt"
            )
        });
        assert_eq!(
            en_disco.replace("\r\n", "\n"),
            esperado,
            "docs/generado/motores.txt no coincide con los motores del codigo. \
             Regeneralo: cargo run -p aegis-agent --features bpf -- --motores \
             > docs/generado/motores.txt"
        );
    }

    #[test]
    fn el_conductual_es_registrable_y_no_los_de_red() {
        // Contra el error concreto del Hallazgo 0: el conductual SI entrega señal,
        // y Wire/Ips/Detonate NO estan registrados en el agente.
        let firmas: std::collections::BTreeSet<&str> =
            fichas().iter().map(|f| f.firma.nombre()).collect();
        assert!(
            firmas.contains("conductual"),
            "el conductual tiene que ser registrable"
        );
        assert!(firmas.contains("estatico"));
        assert!(
            !firmas.contains("wire"),
            "wire no esta registrado en el agente"
        );
        assert!(!firmas.contains("ips"));
        assert!(!firmas.contains("detonate"));
    }
}
