//! La puerta del modelo estatico: cuando deja de ser una referencia
//! (FASE 4.4 del MP-16).
//!
//! # La regla, en una frase
//!
//! **El modelo empotrado solo opina si su tarjeta lo respalda.** La tarjeta
//! (`models/aegis-static-v1.tarjeta`) la GENERA `tools/ml/entrenar.py`, nunca
//! se escribe a mano, y el agente la acepta solo si:
//!
//! 1. declara `clase = "entrenado"`;
//! 2. su `sha256_modelo` es el del ONNX empotrado en ESTE binario;
//! 3. su `huella_extractor` es la de ESTE extractor ([`crate::vector`]): el
//!    modelo se midio sobre los mismos vectores que va a ver;
//! 4. se evaluo sobre al menos `min_benignos_evaluacion` benignos POSTERIORES a
//!    la fecha de corte, y la cota superior al 95 % de su tasa de falsos
//!    positivos en el umbral de bloqueo no supera `fpr_objetivo`
//!    (`tools/config/modelo.toml`, el unico sitio donde se declara);
//! 5. sus umbrales son coherentes.
//!
//! Si falla cualquiera, el modelo sigue siendo de REFERENCIA: su puntuacion se
//! publica como `NoConcluyente` con el motivo. Se usa la COTA y no la tasa
//! observada a proposito: cero falsos positivos sobre mil benignos no demuestra
//! un FPR de 1e-4, y la cota (regla del tres) lo dice.
//!
//! La configuracion y la tarjeta van incrustadas: un agente instalado no lee
//! `tools/`, y un fichero suelto junto al binario lo podria cambiar un
//! atacante con escritura, igual que el propio modelo.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::features::FEATURE_DIM;
use crate::model::Thresholds;

/// La tarjeta del modelo empotrado, tal cual la genero el entrenamiento.
pub const TARJETA: &str = include_str!("../models/aegis-static-v1.tarjeta");

/// El objetivo declarado (`tools/config/modelo.toml`).
pub const CONFIG: &str = include_str!("../../../tools/config/modelo.toml");

/// Lo que la puerta concluye sobre el modelo empotrado.
#[derive(Debug, Clone)]
pub enum EstadoModelo {
    /// La puntuacion se ve pero no es evidencia.
    Referencia {
        /// Por que no pasa la puerta, para la consola y el `porque`.
        motivo: String,
    },
    /// Respaldado por su tarjeta: opina con los umbrales de la tarjeta.
    Entrenado {
        /// Version del modelo segun su tarjeta.
        version: u32,
        /// Umbrales elegidos por el entrenamiento para el FPR objetivo.
        umbrales: Thresholds,
        /// Cota superior al 95 % del FPR en el umbral de bloqueo.
        fpr_cota: f64,
    },
}

/// `clave = valor` por linea; ignora comentarios, vacias y `[secciones]`.
///
/// Es el subconjunto de TOML que escribe el generador. Se analiza a mano para
/// no meter un analizador de TOML en el arbol del agente por dos ficheros planos.
fn claves(texto: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for linea in texto.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let v = v.trim();
            let v = v.split_once(" #").map_or(v, |(a, _)| a).trim();
            let v = v.trim_matches('"');
            m.insert(k.trim().to_string(), v.to_string());
        }
    }
    m
}

/// Evalua la puerta. Funcion pura: la prueban los casos de abajo.
#[must_use]
pub fn evaluar(tarjeta: &str, config: &str, sha256_modelo: &str, huella: &str) -> EstadoModelo {
    let t = claves(tarjeta);
    let c = claves(config);
    let referencia = |m: String| EstadoModelo::Referencia { motivo: m };
    let num = |m: &BTreeMap<String, String>, k: &str| {
        m.get(k)
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|x| x.is_finite())
    };

    let Some(objetivo) = num(&c, "fpr_objetivo").filter(|x| *x > 0.0 && *x < 1.0) else {
        return referencia("tools/config/modelo.toml no declara un fpr_objetivo valido".into());
    };
    let Some(min_benignos) = num(&c, "min_benignos_evaluacion") else {
        return referencia("tools/config/modelo.toml no declara min_benignos_evaluacion".into());
    };
    if t.get("clase").map(String::as_str) != Some("entrenado") {
        return referencia("la tarjeta declara un modelo de referencia, sin entrenar".into());
    }
    if t.get("sha256_modelo").map(String::as_str) != Some(sha256_modelo) {
        return referencia("la tarjeta no corresponde al modelo empotrado (hash distinto)".into());
    }
    if t.get("huella_extractor").map(String::as_str) != Some(huella) {
        return referencia(
            "el extractor de caracteristicas cambio desde el entrenamiento (huella distinta)"
                .into(),
        );
    }
    if t.get("dim").and_then(|v| v.parse::<usize>().ok()) != Some(FEATURE_DIM) {
        return referencia(format!("la tarjeta no declara dim = {FEATURE_DIM}"));
    }
    let (Some(cota), Some(n_ben), Some(vigilar), Some(bloquear), Some(contener)) = (
        num(&t, "fpr_cota95_bloqueo"),
        num(&t, "n_eval_benignos"),
        num(&t, "umbral_vigilar"),
        num(&t, "umbral_bloquear"),
        num(&t, "umbral_contener"),
    ) else {
        return referencia("la tarjeta esta incompleta".into());
    };
    if n_ben < min_benignos {
        return referencia(format!(
            "evaluado con {n_ben} benignos posteriores al corte; el minimo declarado es {min_benignos}"
        ));
    }
    if cota > objetivo {
        return referencia(format!(
            "la cota al 95 % del FPR en bloqueo ({cota:.2e}) supera el objetivo ({objetivo:.2e})"
        ));
    }
    let coherentes =
        0.0 < vigilar && vigilar <= bloquear && bloquear <= contener && contener <= 1.0;
    if !coherentes {
        return referencia("los umbrales de la tarjeta son incoherentes".into());
    }
    let version = t
        .get("version_modelo")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let defecto = Thresholds::default();
    EstadoModelo::Entrenado {
        version,
        umbrales: Thresholds {
            record: defecto.record.min(vigilar as f32),
            watch: vigilar as f32,
            block: bloquear as f32,
            contain: contener as f32,
        },
        fpr_cota: cota,
    }
}

/// El estado del modelo empotrado en este binario (se calcula una vez).
pub fn estado() -> &'static EstadoModelo {
    static ESTADO: OnceLock<EstadoModelo> = OnceLock::new();
    ESTADO.get_or_init(|| {
        evaluar(
            TARJETA,
            CONFIG,
            &crate::vector::sha256_hex(crate::EMBEDDED_MODEL),
            &crate::vector::huella_extractor(),
        )
    })
}

/// Si el modelo empotrado es de referencia (su puntuacion no es evidencia).
#[must_use]
pub fn modelo_es_referencia() -> bool {
    matches!(estado(), EstadoModelo::Referencia { .. })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const CONF: &str = "fpr_objetivo = 1.0e-4\nmin_benignos_evaluacion = 30000\n";
    const HASH: &str = "ab";
    const HUELLA: &str = "cd";

    fn tarjeta(cambios: &[(&str, &str)]) -> String {
        let mut base: BTreeMap<&str, &str> = [
            ("clase", "\"entrenado\""),
            ("version_modelo", "2"),
            ("sha256_modelo", "\"ab\""),
            ("huella_extractor", "\"cd\""),
            ("dim", "256"),
            ("fpr_cota95_bloqueo", "9.9e-5"),
            ("n_eval_benignos", "30260"),
            ("umbral_vigilar", "0.7"),
            ("umbral_bloquear", "0.95"),
            ("umbral_contener", "0.99"),
        ]
        .into_iter()
        .collect();
        for &(k, v) in cambios {
            base.insert(k, v);
        }
        base.iter()
            .map(|(k, v)| format!("{k} = {v}\n"))
            .collect::<Vec<_>>()
            .concat()
    }

    fn motivo(e: &EstadoModelo) -> String {
        match e {
            EstadoModelo::Referencia { motivo } => motivo.clone(),
            EstadoModelo::Entrenado { .. } => String::new(),
        }
    }

    #[test]
    fn una_tarjeta_que_cumple_abre_la_puerta_con_sus_umbrales() {
        match evaluar(&tarjeta(&[]), CONF, HASH, HUELLA) {
            EstadoModelo::Entrenado {
                version, umbrales, ..
            } => {
                assert_eq!(version, 2);
                assert!((umbrales.block - 0.95).abs() < 1e-6);
                assert!((umbrales.watch - 0.7).abs() < 1e-6);
            }
            otro => panic!("deberia pasar: {otro:?}"),
        }
    }

    #[test]
    fn cada_condicion_cierra_la_puerta_con_su_motivo() {
        let casos: [(&[(&str, &str)], &str); 6] = [
            (&[("clase", "\"referencia\"")], "referencia"),
            (&[("sha256_modelo", "\"00\"")], "hash distinto"),
            (&[("huella_extractor", "\"00\"")], "huella distinta"),
            (&[("fpr_cota95_bloqueo", "2e-4")], "supera el objetivo"),
            (&[("n_eval_benignos", "1000")], "minimo declarado"),
            (&[("umbral_bloquear", "0.5")], "incoherentes"),
        ];
        for (cambio, esperado) in casos {
            let m = motivo(&evaluar(&tarjeta(cambio), CONF, HASH, HUELLA));
            assert!(m.contains(esperado), "{cambio:?}: «{m}»");
        }
    }

    #[test]
    fn sin_objetivo_declarado_no_hay_modelo_entrenado() {
        let m = motivo(&evaluar(&tarjeta(&[]), "", HASH, HUELLA));
        assert!(m.contains("fpr_objetivo"), "{m}");
    }

    #[test]
    fn la_configuracion_real_declara_el_objetivo() {
        let c = claves(CONFIG);
        assert!(c
            .get("fpr_objetivo")
            .and_then(|v| v.parse::<f64>().ok())
            .is_some());
        assert!(c.contains_key("min_benignos_evaluacion"));
    }

    #[test]
    fn la_tarjeta_incrustada_es_la_del_modelo_incrustado() {
        // Regenerar el ONNX (build_model.py o entrenar.py) sin regenerar su
        // tarjeta dejaria una tarjeta que habla de otro modelo. La puerta ya lo
        // trataria como referencia; esto lo hace fallar en voz alta en make ci.
        let t = claves(TARJETA);
        assert_eq!(
            t.get("sha256_modelo").map(String::as_str),
            Some(crate::vector::sha256_hex(crate::EMBEDDED_MODEL).as_str()),
            "regenera la tarjeta: python3 tools/ml/entrenar.py referencia (o entrenar)"
        );
    }

    #[test]
    fn la_tarjeta_legible_habla_del_mismo_modelo() {
        // docs/generado/tarjeta-modelo-estatico.md la genera el mismo comando que
        // la tarjeta plana; si se regenera una sin la otra, la documentacion
        // describiria otro modelo. No se incrusta: solo lo comprueba esta prueba.
        let ruta = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/generado/tarjeta-modelo-estatico.md"
        );
        let md = std::fs::read_to_string(ruta).expect("falta la tarjeta legible generada");
        let hash = crate::vector::sha256_hex(crate::EMBEDDED_MODEL);
        assert!(
            md.contains(&format!("`{hash}`")),
            "regenera la tarjeta: python3 tools/ml/entrenar.py referencia (o entrenar)"
        );
    }

    #[test]
    fn el_estado_del_binario_se_calcula_y_explica_por_que() {
        // Hoy la tarjeta incrustada es la del modelo de referencia; mañana la de
        // un modelo entrenado. En los dos casos el estado se explica.
        match estado() {
            EstadoModelo::Referencia { motivo } => assert!(!motivo.is_empty()),
            EstadoModelo::Entrenado { fpr_cota, .. } => assert!(*fpr_cota >= 0.0),
        }
    }
}
