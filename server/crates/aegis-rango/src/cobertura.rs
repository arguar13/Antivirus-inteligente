//! La medida de cobertura: ejecutar, preguntar al arbitro, revertir, y contar
//! honestamente.
//!
//! # El ciclo, y por que siempre revierte
//!
//! Por cada tecnica aplicable: se ejecuta la emulacion benigna, se comprueba que
//! dejo su rastro, se pregunta al arbitro por la entidad afectada, se anota si hubo
//! veredicto acusatorio (detectada) o no (hueco), y **se revierte siempre** —haya
//! ido bien o mal la medida—, comprobando que el rango vuelve a su estado anterior.
//! Una tecnica que no aplica en esta plataforma se anota `NoAplicable` y **no se
//! ejecuta**.
//!
//! # La honestidad del recuento
//!
//! La cobertura es `detectadas / (detectadas + huecos)`: las `NoAplicable` **no
//! entran en el denominador** y **jamas** cuentan como detectadas. Inflar la cifra
//! contando lo que no aplica como detectado es la mentira que esta fase existe para
//! impedir.

use std::collections::BTreeMap;
use std::time::Instant;

use aegis_entidad::{arbitrar, Eid, Motor, Resultado, Senal};

use crate::rango::{ErrorRango, Rango};
use crate::tecnica::{Tactica, Tecnica};

/// De donde salen las señales que ve el arbitro sobre una entidad.
///
/// Es la **frontera**: en produccion, la tuberia de deteccion desplegada; en la
/// puerta de calidad, una fuente que refleja que motores entregan señal hoy. La
/// DECISION —detectada o hueco— la toma el arbitro real sobre lo que esta fuente
/// entrega; la fuente no decide, solo reproduce lo que los detectores observarian.
pub trait FuenteSenales {
    /// Las señales observadas sobre una entidad tras ejecutar una tecnica.
    fn senales(&self, entidad: &Eid, rango: &Rango) -> Vec<Senal>;
}

/// El estado de cobertura de una tecnica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// El arbitro produjo un veredicto acusatorio: la tecnica se detecta.
    Detectado {
        /// El motor de mayor confianza que la acuso.
        motor: Motor,
        /// Si es el motor que la tecnica esperaba que la detectara.
        era_el_esperado: bool,
        /// Cuanto tardo en haber veredicto, en nanosegundos.
        latencia_ns: u64,
    },
    /// El arbitro no acuso: **hueco de cobertura**. La tecnica se ejecuto y no se
    /// detecto.
    NoDetectado,
    /// La tecnica no aplica en la plataforma del rango: no se ejecuto. **Nunca**
    /// cuenta como detectada.
    NoAplicable {
        /// Por que no aplica.
        motivo: String,
    },
}

impl Estado {
    /// Si es una deteccion.
    #[must_use]
    pub fn detectado(&self) -> bool {
        matches!(self, Estado::Detectado { .. })
    }

    /// Si es un hueco de cobertura (aplicable y no detectado).
    #[must_use]
    pub fn es_hueco(&self) -> bool {
        matches!(self, Estado::NoDetectado)
    }
}

/// El resultado de medir una tecnica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoTecnica {
    /// El identificador ATT&CK de la tecnica.
    pub id: String,
    /// Nombre legible.
    pub nombre: String,
    /// La tactica.
    pub tactica: Tactica,
    /// El motor que se esperaba que la detectara.
    pub deteccion_esperada: Motor,
    /// A que estado se llego.
    pub estado: Estado,
}

/// El informe de cobertura completo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InformeCobertura {
    /// Un resultado por tecnica, en orden estable.
    pub resultados: Vec<ResultadoTecnica>,
}

impl InformeCobertura {
    /// Cuantas tecnicas se detectaron.
    #[must_use]
    pub fn detectadas(&self) -> usize {
        self.resultados
            .iter()
            .filter(|r| r.estado.detectado())
            .count()
    }

    /// Cuantas son huecos de cobertura (aplicables y no detectadas).
    #[must_use]
    pub fn huecos(&self) -> usize {
        self.resultados
            .iter()
            .filter(|r| r.estado.es_hueco())
            .count()
    }

    /// Cuantas no aplican en esta plataforma.
    #[must_use]
    pub fn no_aplicables(&self) -> usize {
        self.resultados
            .iter()
            .filter(|r| matches!(r.estado, Estado::NoAplicable { .. }))
            .count()
    }

    /// La cobertura sobre lo APLICABLE: `detectadas / (detectadas + huecos)`.
    ///
    /// Las no aplicables no entran: contar «no aplica» como cobertura es inflar la
    /// cifra. Si no hay nada aplicable, la cobertura es `None` —no cero, que se
    /// leeria como «lo mire y no detecte nada»—.
    #[must_use]
    pub fn cobertura(&self) -> Option<f64> {
        let aplicables = self.detectadas() + self.huecos();
        if aplicables == 0 {
            None
        } else {
            #[allow(clippy::cast_precision_loss)]
            Some(self.detectadas() as f64 / aplicables as f64)
        }
    }

    /// Los huecos, con su tecnica, para que el informe diga QUE no se detecta.
    #[must_use]
    pub fn nombres_de_huecos(&self) -> Vec<(String, String)> {
        self.resultados
            .iter()
            .filter(|r| r.estado.es_hueco())
            .map(|r| (r.id.clone(), r.nombre.clone()))
            .collect()
    }

    /// Recuento por tactica: (detectadas, huecos, no aplicables).
    #[must_use]
    pub fn por_tactica(&self) -> BTreeMap<&'static str, (usize, usize, usize)> {
        let mut m: BTreeMap<&'static str, (usize, usize, usize)> = BTreeMap::new();
        for r in &self.resultados {
            let e = m.entry(r.tactica.nombre()).or_insert((0, 0, 0));
            match r.estado {
                Estado::Detectado { .. } => e.0 += 1,
                Estado::NoDetectado => e.1 += 1,
                Estado::NoAplicable { .. } => e.2 += 1,
            }
        }
        m
    }
}

/// Mide la cobertura de deteccion del catalogo de tecnicas sobre un rango.
///
/// `ahora_ns` se pasa como argumento (no se lee del reloj) para que el veredicto
/// del arbitro sea reproducible entre ejecuciones.
///
/// # Errores
/// [`ErrorRango`] si una tecnica no deja rastro tras ejecutarse o deja residuo tras
/// revertir: una emulacion a medias o que no se limpia falla ruidosamente.
pub fn medir_cobertura(
    rango: &Rango,
    tecnicas: &[Box<dyn Tecnica>],
    fuente: &dyn FuenteSenales,
    ahora_ns: u64,
) -> Result<InformeCobertura, ErrorRango> {
    // Orden estable: por tactica y luego por id, para que el informe sea el mismo
    // entre ejecuciones y se pueda comparar con el de ayer.
    let mut orden: Vec<&dyn Tecnica> = tecnicas.iter().map(AsRef::as_ref).collect();
    orden.sort_by(|a, b| {
        a.tactica()
            .id()
            .cmp(b.tactica().id())
            .then_with(|| a.id().cmp(b.id()))
    });

    let prueba = rango.prueba();
    let plataforma = rango.plataforma();
    let mut informe = InformeCobertura::default();

    for tecnica in orden {
        // No aplicable: se anota y NO se ejecuta.
        if !tecnica.aplica_en(plataforma) {
            informe.resultados.push(ResultadoTecnica {
                id: tecnica.id().to_string(),
                nombre: tecnica.nombre().to_string(),
                tactica: tecnica.tactica(),
                deteccion_esperada: tecnica.deteccion_esperada(),
                estado: Estado::NoAplicable {
                    motivo: format!("la tecnica no aplica en {}", plataforma.nombre()),
                },
            });
            continue;
        }

        // Ejecuta la emulacion benigna dentro de la jaula.
        tecnica.ejecutar(&prueba, rango)?;
        if !tecnica.exito(rango) {
            // Se intenta revertir antes de fallar, para no dejar rastro.
            let _ = tecnica.revertir(&prueba, rango);
            return Err(ErrorRango::Inconsistente {
                tecnica: tecnica.id().to_string(),
                que: "dijo ejecutarse pero no dejo el rastro que la deteccion deberia ver",
            });
        }

        // Pregunta al arbitro por la entidad afectada.
        let entidad = tecnica.entidad_afectada(rango);
        let t0 = Instant::now();
        let senales = fuente.senales(&entidad, rango);
        let veredicto = arbitrar(&entidad, &senales, ahora_ns);
        let latencia_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);

        // Detectada si algun motor acuso: malicioso, sospechoso, o en disputa
        // —en los tres, al menos un detector VIO algo—.
        let estado = if matches!(
            veredicto.resultado,
            Resultado::Malicioso | Resultado::Sospechoso | Resultado::EnDisputa
        ) {
            // El motor de mayor confianza que acuso.
            let motor = veredicto
                .senales
                .iter()
                .filter(|s| s.juicio.acusa() && s.confianza.aporta())
                .max_by_key(|s| s.confianza.centesimas())
                .map(|s| s.motor)
                .unwrap_or(tecnica.deteccion_esperada());
            Estado::Detectado {
                motor,
                era_el_esperado: motor == tecnica.deteccion_esperada(),
                latencia_ns,
            }
        } else {
            Estado::NoDetectado
        };

        // SIEMPRE se revierte, y se comprueba que no queda residuo. Una prueba de
        // cobertura que deja una puerta abierta es un incidente.
        tecnica.revertir(&prueba, rango)?;
        if tecnica.exito(rango) {
            return Err(ErrorRango::Inconsistente {
                tecnica: tecnica.id().to_string(),
                que: "dejo residuo en el rango tras revertir",
            });
        }

        informe.resultados.push(ResultadoTecnica {
            id: tecnica.id().to_string(),
            nombre: tecnica.nombre().to_string(),
            tactica: tecnica.tactica(),
            deteccion_esperada: tecnica.deteccion_esperada(),
            estado,
        });
    }

    Ok(informe)
}
