//! La prueba de que una regla no rompe su motor.
//!
//! Una regla «rompe el motor» si:
//!
//! 1. no compila con el compilador que la va a usar;
//! 2. no dispara con sus muestras que disparan, o dispara con las que no (una
//!    regla que no hace nada, o que salta sobre lo legitimo);
//! 3. su coste determinista por byte supera el que declara, o lo declarado supera
//!    el tope del motor;
//! 4. medida de verdad sobre 64 KiB, tarda mas de lo que declara.
//!
//! Los puntos 1 a 3 los comprueban el publicador y el agente; el 4 solo el
//! publicador (medir tiempos en cada equipo al cargar no aporta y cuesta).
//!
//! # El coste determinista (YARA)
//!
//! `pasos_por_byte = 1 + 2·[hay cadenas nocase] + Σ estados²` de las cadenas con
//! comodines. El 1 es la pasada Aho-Corasick; el 2, la copia en minusculas y su
//! pasada; cada patron con comodines se prueba en cada posicion con una
//! simulacion que toca como mucho `estados` estados durante como mucho
//! `estados` bytes (los saltos estan acotados por construccion en
//! `aegis-patron`). Es una cota, no una medida: sale igual en cualquier maquina,
//! y por eso es la que decide en la puerta. La medida de tiempo es la segunda
//! red, para lo que la cota no vea.
//!
//! # Tipos sin validador
//!
//! Una entrada de un tipo para el que no hay validador registrado NO pasa: no se
//! publica lo que no se sabe probar. Hoy solo hay validador YARA; Sigma y los
//! modelos entran cuando exista su motor en el agente (FASE 4.3 y 4.4).

use std::fmt;
use std::time::Instant;

use aegis_patron::{Motor, Patron, Regla};

use crate::paquete::{Entrada, Manifiesto, Tipo};
use crate::Rotura;

/// Tope del motor para la cota declarada de una regla.
pub const TOPE_PASOS_POR_BYTE: u64 = 65_536;
/// Tope del motor para el tiempo declarado de una regla (64 KiB).
pub const TOPE_MICROS_64K: u32 = 50_000;
/// Tope de la suma de cotas de todas las reglas activas de un paquete.
pub const TOPE_PAQUETE_PASOS_POR_BYTE: u64 = 1 << 20;
/// Bytes sobre los que se mide el tiempo.
pub const BYTES_MEDIDA: usize = 64 << 10;
/// Repeticiones de la medida; se queda el minimo (el ruido solo suma).
pub const REPETICIONES: usize = 5;
/// Holgura de la medida en una compilacion sin optimizar (las pruebas de CI).
pub const FACTOR_DEPURACION: u64 = 25;

/// Por que una regla rompe su motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalloRegla {
    /// No hay validador para su tipo: no se sabe probar, no se publica.
    SinValidador(Tipo),
    /// No compila.
    NoCompila(String),
    /// La fuente no tiene exactamente una regla.
    NoEsUnaRegla {
        /// Reglas encontradas.
        encontradas: usize,
    },
    /// La regla de la fuente no se llama como la entrada.
    OtroNombre {
        /// El de la fuente.
        en_fuente: String,
    },
    /// Le faltan muestras en algun lado.
    SinMuestras,
    /// No dispara con una muestra que tendria que dispararla.
    NoDispara {
        /// Indice de la muestra.
        muestra: usize,
    },
    /// Dispara con una muestra que no tendria que dispararla.
    DisparaEnBenigno {
        /// Indice de la muestra.
        muestra: usize,
    },
    /// Su cota de coste supera la declarada.
    ExcedePasos {
        /// La calculada.
        calculados: u64,
        /// La declarada.
        declarados: u64,
    },
    /// Medida, tarda mas de lo declarado.
    ExcedeTiempo {
        /// Lo medido, en microsegundos (minimo de las repeticiones).
        medidos_us: u64,
        /// El tope aplicado, en microsegundos.
        tope_us: u64,
    },
    /// Lo declarado pasa del tope del motor.
    PresupuestoFueraDeTope {
        /// Que presupuesto.
        que: &'static str,
        /// Lo declarado.
        declarado: u64,
        /// El tope.
        tope: u64,
    },
}

impl fmt::Display for FalloRegla {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalloRegla::SinValidador(t) => write!(
                f,
                "no hay validador para el tipo «{}»: no se publica lo que no se sabe probar",
                t.nombre()
            ),
            FalloRegla::NoCompila(m) => write!(f, "no compila: {m}"),
            FalloRegla::NoEsUnaRegla { encontradas } => {
                write!(
                    f,
                    "la fuente tiene {encontradas} reglas; cada entrada lleva una"
                )
            }
            FalloRegla::OtroNombre { en_fuente } => {
                write!(f, "la regla de la fuente se llama «{en_fuente}»")
            }
            FalloRegla::SinMuestras => {
                f.write_str("le falta al menos una muestra que dispara y una que no")
            }
            FalloRegla::NoDispara { muestra } => {
                write!(f, "no dispara con su muestra que dispara n.º {muestra}")
            }
            FalloRegla::DisparaEnBenigno { muestra } => {
                write!(f, "dispara con su muestra que no dispara n.º {muestra}")
            }
            FalloRegla::ExcedePasos {
                calculados,
                declarados,
            } => write!(
                f,
                "cota de {calculados} pasos por byte, declara {declarados}"
            ),
            FalloRegla::ExcedeTiempo {
                medidos_us,
                tope_us,
            } => write!(
                f,
                "tarda {medidos_us} us en 64 KiB, su tope es {tope_us} us"
            ),
            FalloRegla::PresupuestoFueraDeTope {
                que,
                declarado,
                tope,
            } => write!(f, "declara {declarado} de {que}; el motor admite {tope}"),
        }
    }
}

/// Si se mide el tiempo o solo lo determinista.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medir {
    /// Todo, con la medida de tiempo: la puerta de publicacion.
    Tiempo,
    /// Sin medir tiempos: la carga en el agente.
    SoloDeterminista,
}

/// Lo que se supo de una regla que pasa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Informe {
    /// La regla.
    pub id: String,
    /// Su cota de pasos por byte.
    pub pasos_por_byte: u64,
    /// Lo medido en 64 KiB, si se midio.
    pub micros_por_64k: Option<u64>,
}

/// Quien sabe probar un tipo de contenido.
pub trait Validador: Send + Sync {
    /// El tipo que valida.
    fn tipo(&self) -> Tipo;
    /// Prueba una entrada.
    ///
    /// # Errores
    /// El [`FalloRegla`] que la descalifica.
    fn validar(&self, entrada: &Entrada, medir: Medir) -> Result<Informe, FalloRegla>;
}

/// Validador de reglas YARA con `aegis-patron`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidadorYara;

/// La cota determinista de pasos por byte de una regla YARA compilada.
#[must_use]
pub fn pasos_por_byte(r: &Regla) -> u64 {
    let mut nocase = false;
    let mut comodines: u64 = 0;
    for c in &r.cadenas {
        match &c.patron {
            Patron::Literal(_) => nocase |= c.nocase,
            Patron::Regex(p) => {
                let s = p.estados() as u64;
                comodines = comodines.saturating_add(s.saturating_mul(s));
            }
        }
    }
    // Saturando: una cota que desborda no puede volver a pasar por pequeña.
    comodines.saturating_add(1 + 2 * u64::from(nocase))
}

fn dispara(motor: &Motor, id: &str, muestra: &[u8]) -> bool {
    motor
        .escanear(muestra)
        .detecciones
        .iter()
        .any(|d| d.regla == id)
}

/// La muestra repetida hasta [`BYTES_MEDIDA`].
fn rellenar(muestra: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(BYTES_MEDIDA);
    if muestra.is_empty() {
        return v;
    }
    while v.len() < BYTES_MEDIDA {
        let falta = BYTES_MEDIDA - v.len();
        v.extend_from_slice(&muestra[..muestra.len().min(falta)]);
    }
    v
}

/// El peor, entre las muestras, del minimo de [`REPETICIONES`] escaneos de 64 KiB.
fn medir_micros(motor: &Motor, e: &Entrada) -> u64 {
    let mut peor = 0u64;
    for m in e.dispara.iter().chain(e.no_dispara.iter()) {
        let datos = rellenar(m);
        let mut mejor = u64::MAX;
        for _ in 0..REPETICIONES {
            let t = Instant::now();
            let r = motor.escanear(std::hint::black_box(&datos));
            let _ = std::hint::black_box(r);
            let us = u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX);
            mejor = mejor.min(us);
        }
        peor = peor.max(mejor);
    }
    peor
}

/// El tope de tiempo que se aplica, con la holgura de una compilacion sin
/// optimizar (declarada: la cota determinista es la que no tiene holgura).
#[must_use]
pub fn tope_efectivo_us(declarado: u32) -> u64 {
    if cfg!(debug_assertions) {
        u64::from(declarado) * FACTOR_DEPURACION
    } else {
        u64::from(declarado)
    }
}

fn comprobar_topes(e: &Entrada) -> Result<(), FalloRegla> {
    if e.coste.pasos_por_byte > TOPE_PASOS_POR_BYTE {
        return Err(FalloRegla::PresupuestoFueraDeTope {
            que: "pasos por byte",
            declarado: e.coste.pasos_por_byte,
            tope: TOPE_PASOS_POR_BYTE,
        });
    }
    if e.coste.micros_por_64k > TOPE_MICROS_64K {
        return Err(FalloRegla::PresupuestoFueraDeTope {
            que: "microsegundos por 64 KiB",
            declarado: u64::from(e.coste.micros_por_64k),
            tope: u64::from(TOPE_MICROS_64K),
        });
    }
    Ok(())
}

impl Validador for ValidadorYara {
    fn tipo(&self) -> Tipo {
        Tipo::Yara
    }

    fn validar(&self, e: &Entrada, medir: Medir) -> Result<Informe, FalloRegla> {
        comprobar_topes(e)?;
        let fuente = std::str::from_utf8(&e.fuente)
            .map_err(|_| FalloRegla::NoCompila("la fuente no es UTF-8".into()))?;
        let reglas = aegis_patron::compilar(fuente, "contenido")
            .map_err(|err| FalloRegla::NoCompila(err.to_string()))?;
        if reglas.len() != 1 {
            return Err(FalloRegla::NoEsUnaRegla {
                encontradas: reglas.len(),
            });
        }
        if reglas[0].nombre != e.id {
            return Err(FalloRegla::OtroNombre {
                en_fuente: reglas[0].nombre.clone(),
            });
        }
        let pasos = pasos_por_byte(&reglas[0]);
        if pasos > e.coste.pasos_por_byte {
            return Err(FalloRegla::ExcedePasos {
                calculados: pasos,
                declarados: e.coste.pasos_por_byte,
            });
        }
        if e.dispara.is_empty() || e.no_dispara.is_empty() {
            return Err(FalloRegla::SinMuestras);
        }
        let motor = Motor::desde_reglas(reglas);
        if let Some(muestra) = e.dispara.iter().position(|m| !dispara(&motor, &e.id, m)) {
            return Err(FalloRegla::NoDispara { muestra });
        }
        if let Some(muestra) = e.no_dispara.iter().position(|m| dispara(&motor, &e.id, m)) {
            return Err(FalloRegla::DisparaEnBenigno { muestra });
        }
        let micros = match medir {
            Medir::SoloDeterminista => None,
            Medir::Tiempo => {
                let medidos_us = medir_micros(&motor, e);
                let tope_us = tope_efectivo_us(e.coste.micros_por_64k);
                if medidos_us > tope_us {
                    return Err(FalloRegla::ExcedeTiempo {
                        medidos_us,
                        tope_us,
                    });
                }
                Some(medidos_us)
            }
        };
        Ok(Informe {
            id: e.id.clone(),
            pasos_por_byte: pasos,
            micros_por_64k: micros,
        })
    }
}

/// Los validadores registrados.
pub struct Validadores {
    lista: Vec<Box<dyn Validador>>,
}

impl fmt::Debug for Validadores {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tipos: Vec<&str> = self.lista.iter().map(|v| v.tipo().nombre()).collect();
        f.debug_struct("Validadores")
            .field("tipos", &tipos)
            .finish()
    }
}

impl Validadores {
    /// Ninguno: nada pasa.
    #[must_use]
    pub fn vacio() -> Validadores {
        Validadores { lista: Vec::new() }
    }

    /// Los que existen hoy: YARA.
    #[must_use]
    pub fn por_defecto() -> Validadores {
        Validadores::vacio().con(Box::new(ValidadorYara))
    }

    /// Añade uno (p. ej. el de Sigma cuando exista su motor).
    #[must_use]
    pub fn con(mut self, v: Box<dyn Validador>) -> Validadores {
        self.lista.retain(|x| x.tipo() != v.tipo());
        self.lista.push(v);
        self
    }

    /// Prueba todas las entradas, activas o no (una apagada se puede volver a
    /// encender en otra publicacion, y tiene que funcionar), y el tope conjunto.
    ///
    /// # Errores
    /// TODAS las reglas que rompen su motor, no solo la primera: quien publica
    /// necesita la lista entera para arreglarla de una vez.
    pub fn validar(&self, m: &Manifiesto, medir: Medir) -> Result<Vec<Informe>, Vec<Rotura>> {
        let mut informes = Vec::new();
        let mut roturas = Vec::new();
        for e in &m.entradas {
            let r = match self.lista.iter().find(|v| v.tipo() == e.tipo) {
                Some(v) => v.validar(e, medir),
                None => Err(FalloRegla::SinValidador(e.tipo)),
            };
            match r {
                Ok(i) => informes.push(i),
                Err(fallo) => roturas.push(Rotura {
                    id: e.id.clone(),
                    fallo,
                }),
            }
        }
        if roturas.is_empty() {
            let total = m
                .entradas
                .iter()
                .filter(|e| e.activa)
                .fold(0u64, |a, e| a.saturating_add(e.coste.pasos_por_byte));
            if total > TOPE_PAQUETE_PASOS_POR_BYTE {
                roturas.push(Rotura {
                    id: "(paquete)".into(),
                    fallo: FalloRegla::PresupuestoFueraDeTope {
                        que: "pasos por byte del paquete entero",
                        declarado: total,
                        tope: TOPE_PAQUETE_PASOS_POR_BYTE,
                    },
                });
            }
        }
        if roturas.is_empty() {
            Ok(informes)
        } else {
            Err(roturas)
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_cota_distingue_literales_nocase_y_comodines() {
        let r = aegis_patron::compilar("rule L { strings: $a = \"marcador\" condition: $a }", "p")
            .unwrap();
        assert_eq!(pasos_por_byte(&r[0]), 1);
        let r = aegis_patron::compilar(
            "rule N { strings: $a = \"marcador\" nocase condition: $a }",
            "p",
        )
        .unwrap();
        assert_eq!(pasos_por_byte(&r[0]), 3);
        let r = aegis_patron::compilar(
            "rule C { strings: $a = { 41 [0-32] 42 } condition: $a }",
            "p",
        )
        .unwrap();
        assert!(pasos_por_byte(&r[0]) > 100);
    }

    #[test]
    fn rellenar_llega_justo_a_64k() {
        assert_eq!(rellenar(b"abc").len(), BYTES_MEDIDA);
        assert!(rellenar(b"").is_empty());
    }
}
