//! El unico sitio donde se decide, y por que decide lo que decide.
//!
//! # Lo que reemplaza
//!
//! Antes de este modulo, cada motor emitia su propio veredicto y alguien —el
//! panel, el orquestador, una persona— los juntaba de cabeza. Eso tiene tres
//! consecuencias, y las tres se notan en produccion:
//!
//! 1. **El resultado depende de quien mire.** Dos paneles con los mismos hechos
//!    enseñan cosas distintas.
//! 2. **No se puede discutir.** Un veredicto que nadie puede reconstruir se acata
//!    o se ignora, y con el tiempo se ignora.
//! 3. **No se puede probar.** Sin un punto donde se decide, no hay nada que
//!    poner en la puerta de calidad.
//!
//! # El criterio: seis reglas en orden, la primera que decide decide
//!
//! Ni medias ni pesos entrenados. Una media esconde el desacuerdo y convierte el
//! desconocimiento en voto —es el mismo argumento de `aegis-enrich::fusion`, y es
//! el mismo aqui—; unos pesos entrenados producen un numero que nadie puede
//! explicar el dia que se equivoca.
//!
//! | # | Regla | Por que |
//! |---|---|---|
//! | 1 | Sin nada que aporte, **`SinDatos`** | Cinco «no se» no son «limpio» |
//! | 2 | Una **observacion de ejecucion** decide el sentido | Quien vio la cosa hacer lo que hace sabe algo que quien mira su forma no puede saber |
//! | 3 | Planos que observaron y se **contradicen** → `EnDisputa` | El desacuerdo entre testigos ES el hallazgo |
//! | 4 | Con **un solo plano**, nunca se llega a `Critica` | Un critico de un solo testigo es como un falso positivo se convierte en una interrupcion |
//! | 5 | **Lo externo no decide solo** | Repite lo que otro observo; si nadie de casa vio nada, no hay caso todavia |
//! | 6 | Si no, manda el plano mas severo, corroborado por los demas | El que mas sabe manda, y coincidir sube la confianza |
//!
//! # Corroborar cuenta PLANOS, no motores
//!
//! Es la decision que hace util al arbitro. El analisis estatico y el modelo del
//! endpoint comparten la entrada entera: si el fichero esta ofuscado de una forma
//! que ninguno reconoce, **fallan los dos a la vez y por lo mismo**. Contarlos
//! como dos confirmaciones es contar una opinion dos veces, y es la falsa
//! confirmacion mas facil de fabricar.
//!
//! Es la misma idea que en `aegis-share::procedencia` —dos canales que repiten al
//! mismo no son dos fuentes— aplicada a los motores propios. Ver
//! [`crate::escala::Plano`].
//!
//! # Todo veredicto sale con una frase que lo explica
//!
//! Y no como adorno: [`Veredicto::porque`] nunca esta vacio, y la puerta de
//! calidad lo comprueba recorriendo **todas** las combinaciones. Un veredicto que
//! el analista no puede reconstruir es un veredicto que no usa.

use std::collections::{BTreeMap, BTreeSet};

use crate::entidad::Eid;
use crate::escala::{Confianza, Motor, Plano, Severidad};

/// Que dice un motor sobre una entidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Senal {
    /// Quien lo dice.
    pub motor: Motor,
    /// Sobre que.
    pub entidad: Eid,
    /// Que dice.
    pub juicio: Juicio,
    /// Si es verdad, cuanto daño hace.
    pub severidad: Severidad,
    /// Cuanto se cree que es verdad.
    ///
    /// Se acota al tope del motor al construir la señal: un motor no puede
    /// declararse mas seguro de lo que su plano le permite estar.
    pub confianza: Confianza,
    /// Por que lo dice, en una frase.
    pub porque: String,
    /// Cuando lo observo, en nanosegundos Unix.
    pub cuando_ns: u64,
}

impl Senal {
    /// Construye una señal, acotando la confianza al tope del motor.
    ///
    /// # Por que se acota aqui y no se confia en el motor
    ///
    /// Porque un motor que se declara mas seguro de lo que puede estar desequilibra
    /// el arbitro entero, y no hace falta mala fe: basta un `confianza: 100` puesto
    /// por costumbre en un motor nuevo. El tope vive en la tabla de
    /// [`Motor::tope_confianza`], que es donde se puede revisar de un vistazo.
    #[must_use]
    pub fn nueva(
        motor: Motor,
        entidad: Eid,
        juicio: Juicio,
        severidad: Severidad,
        confianza: Confianza,
        porque: impl Into<String>,
        cuando_ns: u64,
    ) -> Senal {
        Senal {
            motor,
            entidad,
            juicio,
            severidad,
            confianza: confianza.min(motor.tope_confianza()),
            porque: porque.into(),
            cuando_ns,
        }
    }

    /// En que plano observa.
    #[must_use]
    pub fn plano(&self) -> Plano {
        self.motor.plano()
    }

    /// Si aporta algo a la decision.
    #[must_use]
    pub fn aporta(&self) -> bool {
        self.juicio != Juicio::NoConcluyente && self.confianza.aporta()
    }
}

/// Lo que dice un motor, en la escala unica.
///
/// Cuatro valores, y el cuarto es el que casi ningun producto tiene: `NoPudeMirar`
/// no es lo mismo que `Limpio`, y confundirlos es la averia que este producto
/// persigue desde la primera fase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Juicio {
    /// Es malicioso.
    Malicioso,
    /// Hay indicios.
    Sospechoso,
    /// Lo miro y es legitimo.
    Limpio,
    /// **No pudo mirarlo**, o lo miro y no pudo decidir.
    ///
    /// Distinto de `Limpio`, y la diferencia es la que separa «se comprobo y esta
    /// bien» de «no se comprobo». Las dos producen el mismo hueco en un panel mal
    /// hecho, y solo una es aceptable.
    NoConcluyente,
}

impl Juicio {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Juicio::Malicioso => "malicioso",
            Juicio::Sospechoso => "sospechoso",
            Juicio::Limpio => "limpio",
            Juicio::NoConcluyente => "no-concluyente",
        }
    }

    /// Si apunta a que hay algo malo.
    #[must_use]
    pub fn acusa(self) -> bool {
        matches!(self, Juicio::Malicioso | Juicio::Sospechoso)
    }

    /// Todos los valores.
    #[must_use]
    pub fn todos() -> &'static [Juicio] {
        &[
            Juicio::Malicioso,
            Juicio::Sospechoso,
            Juicio::Limpio,
            Juicio::NoConcluyente,
        ]
    }
}

/// A que se llega.
///
/// Cinco valores, igual que la fusion de `aegis-enrich`, y por la misma razon: los
/// dos de mas —`EnDisputa` y `SinDatos`— son situaciones reales y frecuentes que
/// un enumerado de tres obliga a disfrazar de otra cosa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resultado {
    /// Es malicioso.
    Malicioso,
    /// Hay indicios suficientes para mirar.
    Sospechoso,
    /// Es legitimo, y alguien lo comprobo.
    Limpio,
    /// Los motores que **vieron** cosas se contradicen.
    EnDisputa,
    /// Nadie sabe nada. **No es «limpio».**
    SinDatos,
}

impl Resultado {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Resultado::Malicioso => "malicioso",
            Resultado::Sospechoso => "sospechoso",
            Resultado::Limpio => "limpio",
            Resultado::EnDisputa => "en-disputa",
            Resultado::SinDatos => "sin-datos",
        }
    }

    /// Si esto exige que lo mire una persona antes de actuar.
    #[must_use]
    pub fn exige_persona(self) -> bool {
        self == Resultado::EnDisputa
    }

    /// Si justifica actuar sin preguntar.
    #[must_use]
    pub fn justifica_contencion(self) -> bool {
        self == Resultado::Malicioso
    }
}

/// El veredicto, con todo lo que hace falta para discutirlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veredicto {
    /// Sobre que.
    pub entidad: Eid,
    /// A que se llego.
    pub resultado: Resultado,
    /// Cuanto daño hace, si es verdad.
    pub severidad: Severidad,
    /// Cuanto se cree.
    pub confianza: Confianza,
    /// La regla que decidio, en una frase.
    ///
    /// **Nunca esta vacia.** La puerta de calidad lo comprueba recorriendo todas
    /// las combinaciones: un veredicto que el analista no puede reconstruir es un
    /// veredicto que no usa.
    pub porque: String,
    /// Que planos aportaron algo.
    pub planos: Vec<Plano>,
    /// Que dijo cada motor, ordenado y completo.
    ///
    /// Va **siempre**, tambien cuando todos coinciden: es lo que permite discutir
    /// el resultado en vez de acatarlo.
    pub senales: Vec<Senal>,
}

impl Veredicto {
    /// Cuantos planos independientes lo sostienen.
    #[must_use]
    pub fn corroboracion(&self) -> usize {
        self.planos.len()
    }

    /// Un resumen de una linea.
    #[must_use]
    pub fn resumen(&self) -> String {
        format!(
            "{} · severidad {} · confianza {} · {} plano(s) — {}",
            self.resultado.nombre(),
            self.severidad.nombre(),
            self.confianza,
            self.planos.len(),
            self.porque
        )
    }
}

/// Combina todas las señales sobre una entidad en un veredicto.
///
/// `ahora_ns` decide que esta caducado; se pasa como argumento y no se lee del
/// reloj para que el arbitro sea una **funcion pura**. Es lo que permite tener el
/// criterio entero en la puerta de calidad en vez de en un documento, y lo que
/// hace que dos ejecuciones sobre los mismos hechos den exactamente lo mismo.
#[must_use]
pub fn arbitrar(entidad: &Eid, senales: &[Senal], ahora_ns: u64) -> Veredicto {
    let _ = ahora_ns;

    // Orden total y estable: el veredicto tiene que ser el mismo lleguen las
    // señales como lleguen, y sin esto el informe no se puede comparar con el del
    // dia anterior.
    let mut todas: Vec<Senal> = senales
        .iter()
        .filter(|s| &s.entidad == entidad)
        .cloned()
        .collect();
    todas.sort_by(|a, b| {
        a.motor
            .nombre()
            .cmp(b.motor.nombre())
            .then(a.cuando_ns.cmp(&b.cuando_ns))
            .then(a.porque.cmp(&b.porque))
    });

    let utiles: Vec<&Senal> = todas.iter().filter(|s| s.aporta()).collect();
    let planos: Vec<Plano> = {
        let mut p: Vec<Plano> = utiles.iter().map(|s| s.plano()).collect();
        p.sort_unstable();
        p.dedup();
        p
    };

    // ── REGLA 1 · Sin nada que aporte, SIN DATOS ────────────────────────────
    if utiles.is_empty() {
        let mudos = todas.len();
        return Veredicto {
            entidad: entidad.clone(),
            resultado: Resultado::SinDatos,
            severidad: Severidad::Info,
            confianza: Confianza::NULA,
            porque: if mudos == 0 {
                "no se consulto a ningun motor sobre esta entidad".to_string()
            } else {
                format!(
                    "los {mudos} motor(es) que miraron no pudieron concluir — que NO es lo mismo \
                     que que este limpio: un fichero que nadie reconoce es lo que parece uno \
                     recien compilado"
                )
            },
            planos,
            senales: todas,
        };
    }

    // ── REGLA 2 · Una observacion de EJECUCION decide el sentido ────────────
    let testigos: Vec<&Senal> = utiles
        .iter()
        .copied()
        .filter(|s| s.plano().observa_ejecucion())
        .collect();

    if !testigos.is_empty() {
        let acusan: Vec<&Senal> = testigos
            .iter()
            .copied()
            .filter(|s| s.juicio.acusa())
            .collect();
        let absuelven: Vec<&Senal> = testigos
            .iter()
            .copied()
            .filter(|s| s.juicio == Juicio::Limpio)
            .collect();

        // ── REGLA 3 · Testigos que se contradicen → EN DISPUTA ──────────────
        if !acusan.is_empty() && !absuelven.is_empty() {
            let a: Vec<&str> = acusan.iter().map(|s| s.motor.nombre()).collect();
            let b: Vec<&str> = absuelven.iter().map(|s| s.motor.nombre()).collect();
            return Veredicto {
                entidad: entidad.clone(),
                resultado: Resultado::EnDisputa,
                severidad: acusan
                    .iter()
                    .map(|s| s.severidad)
                    .max()
                    .unwrap_or(Severidad::Media),
                confianza: mejor(&acusan),
                porque: format!(
                    "motores que VIERON la ejecucion se contradicen: [{}] acusan y [{}] absuelven. \
                     No se promedia, porque un valor intermedio se leeria como evidencia debil y \
                     lo que hay es evidencia fuerte en las dos direcciones",
                    a.join(", "),
                    b.join(", ")
                ),
                planos,
                senales: todas,
            };
        }

        if !acusan.is_empty() {
            let planos_testigos: BTreeSet<Plano> = acusan.iter().map(|s| s.plano()).collect();
            let severidad_bruta = acusan
                .iter()
                .map(|s| s.severidad)
                .max()
                .unwrap_or(Severidad::Media);
            // ── REGLA 4 · Con UN SOLO plano, nunca se llega a CRITICA ───────
            let (severidad, nota) =
                acotar_por_corroboracion(severidad_bruta, planos_testigos.len());
            let juicio = acusan
                .iter()
                .map(|s| s.juicio)
                .min()
                .unwrap_or(Juicio::Sospechoso);
            let otros = utiles.len() - acusan.len();
            return Veredicto {
                entidad: entidad.clone(),
                resultado: if juicio == Juicio::Malicioso {
                    Resultado::Malicioso
                } else {
                    Resultado::Sospechoso
                },
                severidad,
                confianza: subir_por_corroboracion(mejor(&acusan), planos_testigos.len()),
                porque: format!(
                    "lo deciden {} motor(es) que VIERON la ejecucion ([{}], plano(s): {}). Quien \
                     vio la cosa hacer lo que hace sabe algo que quien mira su forma no puede \
                     saber{}{nota}",
                    acusan.len(),
                    acusan
                        .iter()
                        .map(|s| s.motor.nombre())
                        .collect::<Vec<_>>()
                        .join(", "),
                    planos_testigos
                        .iter()
                        .map(|p| p.nombre())
                        .collect::<Vec<_>>()
                        .join("+"),
                    if otros > 0 {
                        format!("; hay {otros} señal(es) mas que no lo contradicen")
                    } else {
                        String::new()
                    }
                ),
                planos,
                senales: todas,
            };
        }

        // Todos los testigos absuelven: es la unica forma de llegar a LIMPIO, y
        // hace falta que alguien lo haya MIRADO de verdad.
        if !absuelven.is_empty() {
            return Veredicto {
                entidad: entidad.clone(),
                resultado: Resultado::Limpio,
                severidad: Severidad::Info,
                confianza: mejor(&absuelven),
                porque: format!(
                    "{} motor(es) que VIERON la ejecucion dicen que es legitimo, y ninguno lo \
                     contradice",
                    absuelven.len()
                ),
                planos,
                senales: todas,
            };
        }
    }

    // ── REGLA 5 · Lo externo no decide solo ─────────────────────────────────
    let solo_externo = utiles.iter().all(|s| s.plano() == Plano::Externo);
    if solo_externo {
        let acusan = utiles.iter().filter(|s| s.juicio.acusa()).count();
        if acusan > 0 {
            return Veredicto {
                entidad: entidad.clone(),
                resultado: Resultado::Sospechoso,
                severidad: Severidad::Media,
                confianza: mejor(&utiles),
                porque: format!(
                    "lo dicen {acusan} fuente(s) externa(s) y NADIE de casa ha visto nada: una \
                     fuente externa repite lo que otro observo, asi que abre una revision pero no \
                     decide sola"
                ),
                planos,
                senales: todas,
            };
        }
    }

    // ── REGLA 6 · Manda el plano mas severo, corroborado por los demas ──────
    let acusan: Vec<&Senal> = utiles
        .iter()
        .copied()
        .filter(|s| s.juicio.acusa())
        .collect();
    if acusan.is_empty() {
        return Veredicto {
            entidad: entidad.clone(),
            resultado: Resultado::Limpio,
            severidad: Severidad::Info,
            confianza: mejor(&utiles),
            porque: format!(
                "los {} motor(es) que miraron dicen que es legitimo",
                utiles.len()
            ),
            planos,
            senales: todas,
        };
    }

    let planos_acusadores: BTreeSet<Plano> = acusan.iter().map(|s| s.plano()).collect();
    let severidad_bruta = acusan
        .iter()
        .map(|s| s.severidad)
        .max()
        .unwrap_or(Severidad::Media);
    let (severidad, nota) = acotar_por_corroboracion(severidad_bruta, planos_acusadores.len());
    let juicio = acusan
        .iter()
        .map(|s| s.juicio)
        .min()
        .unwrap_or(Juicio::Sospechoso);

    Veredicto {
        entidad: entidad.clone(),
        resultado: if juicio == Juicio::Malicioso && planos_acusadores.len() > 1 {
            Resultado::Malicioso
        } else {
            // Un solo plano que no vio la ejecucion no basta para «malicioso»:
            // deduce de la forma, y la forma se puede falsificar.
            Resultado::Sospechoso
        },
        severidad,
        confianza: subir_por_corroboracion(mejor(&acusan), planos_acusadores.len()),
        porque: format!(
            "acusan {} motor(es) en {} plano(s) ({}), ninguno de los cuales vio la ejecucion{nota}",
            acusan.len(),
            planos_acusadores.len(),
            planos_acusadores
                .iter()
                .map(|p| p.nombre())
                .collect::<Vec<_>>()
                .join("+")
        ),
        planos,
        senales: todas,
    }
}

/// La mayor confianza del grupo.
///
/// La mayor y no la media: el grupo coincide en acusar, asi que lo que interesa es
/// lo seguro que esta el que mas lo esta. Promediar con uno que apenas se moja
/// rebajaria un juicio firme por compañia.
fn mejor(grupo: &[&Senal]) -> Confianza {
    grupo
        .iter()
        .map(|s| s.confianza)
        .max()
        .unwrap_or(Confianza::NULA)
}

/// Acota la severidad si la sostiene un solo plano.
///
/// # La regla que evita que un falso positivo sea una interrupcion
///
/// `Critica` autoriza contener sin preguntar. Un critico que sostiene **un solo
/// testigo** es exactamente como un falso positivo se convierte en una parada de
/// produccion: el motor se equivoca, nadie lo contradice porque nadie mas miro, y
/// la maquina se aisla.
///
/// Con dos planos independientes de acuerdo, la probabilidad de que los dos se
/// equivoquen **por la misma causa** cae mucho — que es justo lo que
/// «independientes» significa aqui.
fn acotar_por_corroboracion(bruta: Severidad, planos: usize) -> (Severidad, &'static str) {
    if bruta == Severidad::Critica && planos < 2 {
        (
            Severidad::Alta,
            ". Se rebaja de critica a alta porque lo sostiene un solo plano: un critico de un solo \
             testigo es como un falso positivo se convierte en una interrupcion de produccion",
        )
    } else {
        (bruta, "")
    }
}

/// Sube la confianza por cada plano independiente adicional.
///
/// Asintotico a proposito, igual que en `aegis-share::procedencia`: por muchos
/// planos que coincidan, coincidir no es haberlo visto.
fn subir_por_corroboracion(base: Confianza, planos: usize) -> Confianza {
    let mut c = u32::from(base.centesimas());
    for _ in 0..planos.saturating_sub(1).min(4) {
        c += (99 - c) / 4;
    }
    Confianza::nueva(u8::try_from(c).unwrap_or(99))
}

/// Cuantas señales aporto cada motor, para ver de que se depende.
#[must_use]
pub fn por_motor(senales: &[Senal]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for s in senales {
        *m.entry(s.motor.nombre()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::entidad;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn ent() -> Eid {
        entidad::contenido("7f1e3c9b")
    }

    fn senal(motor: Motor, juicio: Juicio, sev: Severidad, conf: u8) -> Senal {
        Senal::nueva(
            motor,
            ent(),
            juicio,
            sev,
            Confianza::nueva(conf),
            format!("lo dice {}", motor.nombre()),
            AHORA,
        )
    }

    #[test]
    fn sin_senales_es_sin_datos_y_no_limpio() {
        let v = arbitrar(&ent(), &[], AHORA);
        assert_eq!(v.resultado, Resultado::SinDatos);
        assert!(!v.porque.is_empty());
    }

    #[test]
    fn cinco_no_concluyentes_no_son_limpio() {
        // La averia que este producto persigue desde la primera fase: «no pude
        // mirar» leido como «esta bien».
        let ss: Vec<Senal> = [
            Motor::Estatico,
            Motor::Aprendizaje,
            Motor::Conductual,
            Motor::MemHunter,
            Motor::Intel,
        ]
        .iter()
        .map(|m| senal(*m, Juicio::NoConcluyente, Severidad::Info, 0))
        .collect();
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::SinDatos);
        assert!(v.porque.contains("NO es lo mismo"));
    }

    #[test]
    fn quien_vio_la_ejecucion_gana_a_quien_mira_la_forma() {
        // La detonacion vio el fichero cifrar ficheros. El estatico y el modelo
        // dicen que parece limpio porque no reconocen el empaquetador.
        let ss = vec![
            senal(Motor::Detonate, Juicio::Malicioso, Severidad::Critica, 99),
            senal(Motor::Estatico, Juicio::Limpio, Severidad::Info, 80),
            senal(Motor::Aprendizaje, Juicio::Limpio, Severidad::Info, 70),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::Malicioso);
        assert!(v.porque.contains("VIERON la ejecucion"));
    }

    #[test]
    fn dos_testigos_que_se_contradicen_no_se_promedian() {
        // El desacuerdo entre quienes VIERON cosas es el hallazgo, y esconderlo
        // tras un numero intermedio hace que nadie mire el caso que mas lo
        // necesita.
        let ss = vec![
            senal(Motor::Detonate, Juicio::Malicioso, Severidad::Alta, 95),
            senal(Motor::Conductual, Juicio::Limpio, Severidad::Info, 90),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::EnDisputa);
        assert!(v.resultado.exige_persona());
        assert!(!v.resultado.justifica_contencion());
        assert!(v.porque.contains("detonate") && v.porque.contains("conductual"));
    }

    #[test]
    fn un_solo_plano_no_llega_a_critica() {
        // Un critico autoriza contener sin preguntar. Sostenido por un solo
        // testigo, es como un falso positivo se convierte en una parada de
        // produccion.
        let solo = vec![senal(
            Motor::Detonate,
            Juicio::Malicioso,
            Severidad::Critica,
            99,
        )];
        let v = arbitrar(&ent(), &solo, AHORA);
        assert_eq!(v.resultado, Resultado::Malicioso);
        assert_eq!(
            v.severidad,
            Severidad::Alta,
            "un solo plano llego a critica"
        );
        assert!(v.porque.contains("un solo plano"));

        // Con un segundo plano independiente, si.
        let dos = vec![
            senal(Motor::Detonate, Juicio::Malicioso, Severidad::Critica, 99),
            senal(Motor::MemHunter, Juicio::Malicioso, Severidad::Critica, 95),
        ];
        let v = arbitrar(&ent(), &dos, AHORA);
        assert_eq!(v.severidad, Severidad::Critica);
        assert!(v.resultado.justifica_contencion());
    }

    #[test]
    fn el_estatico_y_el_modelo_no_corroboran_entre_si() {
        // Comparten la entrada entera: si el fichero esta ofuscado de una forma
        // que ninguno reconoce, fallan los dos a la vez y por lo mismo. Contarlos
        // como dos confirmaciones es la falsa confirmacion mas facil de fabricar.
        let ss = vec![
            senal(Motor::Estatico, Juicio::Malicioso, Severidad::Critica, 80),
            senal(
                Motor::Aprendizaje,
                Juicio::Malicioso,
                Severidad::Critica,
                70,
            ),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(
            v.corroboracion(),
            1,
            "dos motores del mismo plano contaron como dos"
        );
        assert_eq!(v.severidad, Severidad::Alta, "se rebajo, como debe");
        // Y no llega a «malicioso»: nadie vio la ejecucion.
        assert_eq!(v.resultado, Resultado::Sospechoso);
    }

    #[test]
    fn dos_planos_distintos_si_corroboran() {
        let ss = vec![
            senal(Motor::Estatico, Juicio::Malicioso, Severidad::Alta, 80),
            senal(Motor::Itdr, Juicio::Malicioso, Severidad::Alta, 85),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.corroboracion(), 2);
        assert_eq!(v.resultado, Resultado::Malicioso);
        assert!(
            v.confianza > Confianza::nueva(85),
            "corroborar no subio la confianza"
        );
    }

    #[test]
    fn una_fuente_externa_sola_abre_revision_pero_no_decide() {
        // Repite lo que otro observo. Si nadie de casa vio nada, no hay caso
        // todavia — hay algo que mirar.
        let ss = vec![
            senal(Motor::Intel, Juicio::Malicioso, Severidad::Critica, 75),
            senal(Motor::Enjambre, Juicio::Malicioso, Severidad::Critica, 75),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::Sospechoso);
        assert!(!v.resultado.justifica_contencion());
        assert!(v.porque.contains("NADIE de casa"));
    }

    #[test]
    fn lo_externo_con_algo_de_casa_si_llega_a_malicioso() {
        let ss = vec![
            senal(Motor::Intel, Juicio::Malicioso, Severidad::Alta, 75),
            senal(Motor::Conductual, Juicio::Malicioso, Severidad::Alta, 90),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::Malicioso);
    }

    #[test]
    fn para_llegar_a_limpio_alguien_tiene_que_haber_mirado() {
        let ss = vec![
            senal(Motor::Conductual, Juicio::Limpio, Severidad::Info, 90),
            senal(Motor::MemHunter, Juicio::Limpio, Severidad::Info, 95),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.resultado, Resultado::Limpio);
        assert!(v.confianza.aporta(), "un limpio sin confianza no dice nada");
    }

    #[test]
    fn un_motor_no_puede_declararse_mas_seguro_de_lo_que_puede_estar() {
        // No hace falta mala fe: basta un `confianza: 100` puesto por costumbre en
        // un motor nuevo.
        let s = senal(Motor::Aprendizaje, Juicio::Malicioso, Severidad::Alta, 99);
        assert_eq!(s.confianza, Motor::Aprendizaje.tope_confianza());
        assert!(s.confianza < Motor::Detonate.tope_confianza());
    }

    #[test]
    fn el_veredicto_no_depende_del_orden_de_llegada() {
        // Sin esto, dos ejecuciones sobre el mismo incidente dan resultados
        // distintos y el informe no se puede comparar con el del dia anterior.
        let a = senal(Motor::Detonate, Juicio::Malicioso, Severidad::Alta, 99);
        let b = senal(Motor::Estatico, Juicio::Limpio, Severidad::Info, 80);
        let c = senal(Motor::Intel, Juicio::Sospechoso, Severidad::Media, 75);

        let uno = arbitrar(&ent(), &[a.clone(), b.clone(), c.clone()], AHORA);
        let dos = arbitrar(&ent(), &[c.clone(), a.clone(), b.clone()], AHORA);
        let tres = arbitrar(&ent(), &[b, c, a], AHORA);
        assert_eq!(uno, dos);
        assert_eq!(dos, tres);
    }

    #[test]
    fn las_senales_de_otra_entidad_no_entran() {
        // Un veredicto que mezcla señales de dos entidades atribuye a una lo que
        // hizo la otra, que es exactamente lo que el modelo de entidad viene a
        // impedir.
        let mut ajena = senal(Motor::Detonate, Juicio::Malicioso, Severidad::Critica, 99);
        ajena.entidad = entidad::contenido("otra-cosa");
        let v = arbitrar(&ent(), &[ajena], AHORA);
        assert_eq!(v.resultado, Resultado::SinDatos);
        assert!(v.senales.is_empty());
    }

    #[test]
    fn toda_combinacion_produce_una_explicacion_no_vacia() {
        // La propiedad de explicabilidad, comprobada recorriendo el espacio en vez
        // de afirmandola. Un veredicto que el analista no puede reconstruir es un
        // veredicto que no usa.
        let mut combinaciones = 0usize;
        for m1 in Motor::todos() {
            for j1 in Juicio::todos() {
                for m2 in Motor::todos() {
                    for j2 in Juicio::todos() {
                        for sev in [Severidad::Info, Severidad::Critica] {
                            let ss = vec![senal(*m1, *j1, sev, 80), senal(*m2, *j2, sev, 60)];
                            let v = arbitrar(&ent(), &ss, AHORA);
                            assert!(
                                v.porque.len() > 20,
                                "sin explicacion: {:?} {:?} + {:?} {:?}",
                                m1,
                                j1,
                                m2,
                                j2
                            );
                            assert!(!v.resumen().is_empty());
                            combinaciones += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(combinaciones, 13 * 4 * 13 * 4 * 2);
    }

    #[test]
    fn el_veredicto_lleva_siempre_lo_que_dijo_cada_motor() {
        // Es lo que permite discutir el resultado en vez de acatarlo.
        let ss = vec![
            senal(Motor::Detonate, Juicio::Malicioso, Severidad::Alta, 99),
            senal(Motor::Estatico, Juicio::NoConcluyente, Severidad::Info, 0),
        ];
        let v = arbitrar(&ent(), &ss, AHORA);
        assert_eq!(v.senales.len(), 2, "se perdio la señal que no aportaba");
        assert_eq!(por_motor(&v.senales).len(), 2);
    }

    #[test]
    fn corroborar_no_convierte_una_deduccion_en_una_observacion() {
        // Asintotico a proposito: por muchos planos que coincidan, coincidir no es
        // haberlo visto.
        let mut ss = Vec::new();
        for m in [
            Motor::Estatico,
            Motor::Itdr,
            Motor::FirmwareAudit,
            Motor::Intel,
        ] {
            ss.push(senal(
                m,
                Juicio::Malicioso,
                Severidad::Alta,
                m.tope_confianza().centesimas(),
            ));
        }
        let v = arbitrar(&ent(), &ss, AHORA);
        assert!(v.corroboracion() >= 3);
        assert!(
            v.confianza < Confianza::CIERTA,
            "cuatro deducciones llegaron a certeza: {}",
            v.confianza
        );
    }
}
