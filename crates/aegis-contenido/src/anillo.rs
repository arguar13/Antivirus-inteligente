//! Anillos de despliegue: canario, porcentaje (5 %) y flota.
//!
//! # Lo decide el servidor, lo comprueba el agente
//!
//! El anillo va DENTRO de lo firmado. El agente no pregunta a nadie si le toca:
//! lo calcula con su identidad y con lo que el paquete dice, y si no le toca lo
//! ignora sin tocar su estado. Asi un paquete de canario que se escape del canal
//! de flota —por un error del servidor o de quien lo distribuya— no se carga en
//! toda la flota: cada equipo que no es canario lo rechaza el solo.
//!
//! - **Canario**: una lista explicita de huellas de equipo (SHA-256 con dominio
//!   de su identidad). El servidor elige los equipos; la lista no revela las
//!   identidades a quien lea el paquete.
//! - **Porcentaje**: el equipo cae en una cubeta de 0 a 9999 derivada de una sal
//!   de la publicacion y de su identidad; entra si su cubeta es menor que los
//!   puntos basicos del paquete (500 = 5 %). La misma sal da el mismo 5 %: un
//!   equipo no entra y sale de un despliegue al azar.
//! - **Flota**: todos.
//!
//! # La escalera
//!
//! Un paquete de un anillo ancho lleva los peldaños por los que paso su MISMO
//! contenido: en que epoca estuvo en el anillo estrecho, cuantos equipos lo
//! dieron por sano y cuantos fallaron. El agente comprueba que la escalera esta
//! completa, ordenada y limpia, y ademas, si el estuvo en un peldaño, que el
//! contenido de entonces es el de ahora ([`crate::almacen`]). Lo que el agente no
//! puede comprobar —que los numeros de sanos sean ciertos— es palabra del
//! servidor firmada: protege contra un plano de control que se equivoca, no
//! contra uno comprometido (eso ya seria la clave de firma).

use sha2::{Digest, Sha256};

use crate::codificacion::{ErrorFormato, Escritor, Lector};

/// Puntos basicos de la flota entera.
pub const PUNTOS_TOTALES: u16 = 10_000;
/// El 5 % del despliegue por porcentaje.
pub const CINCO_POR_CIENTO: u16 = 500;
/// Miembros como mucho en un canario.
pub const MAX_MIEMBROS_CANARIO: usize = 4096;
/// Peldaños como mucho en una escalera.
pub const MAX_PELDANOS: usize = 8;
/// Equipos sanos que un canario tiene que acreditar para promocionar.
pub const MIN_SANOS_CANARIO: u64 = 10;
/// Equipos sanos que el porcentaje tiene que acreditar para promocionar.
pub const MIN_SANOS_PORCENTAJE: u64 = 100;

const CTX_HUELLA: &[u8] = b"aegiscore/contenido/anillo/huella/v1";

/// Un anillo de despliegue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anillo {
    /// Solo los equipos cuya huella esta en la lista (ordenada, sin repetidos).
    Canario {
        /// Huellas de los equipos canario ([`Anillo::huella`]).
        miembros: Vec<[u8; 32]>,
    },
    /// Los equipos cuya cubeta cae por debajo de `puntos`.
    Porcentaje {
        /// Puntos basicos (500 = 5 %), entre 1 y 9999.
        puntos: u16,
        /// Sal de la publicacion.
        sal: [u8; 32],
    },
    /// Toda la flota.
    Flota,
}

impl Anillo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        nombre_orden(self.orden())
    }

    /// Anchura: 0 canario, 1 porcentaje, 2 flota.
    #[must_use]
    pub fn orden(&self) -> u8 {
        match self {
            Anillo::Canario { .. } => 0,
            Anillo::Porcentaje { .. } => 1,
            Anillo::Flota => 2,
        }
    }

    /// Un canario con estos equipos: calcula sus huellas, ordena y quita repetidos.
    #[must_use]
    pub fn canario(ids: &[&str]) -> Anillo {
        let mut miembros: Vec<[u8; 32]> = ids.iter().copied().map(Anillo::huella).collect();
        miembros.sort_unstable();
        miembros.dedup();
        Anillo::Canario { miembros }
    }

    /// Huella de un equipo: SHA-256 con dominio de su identidad.
    #[must_use]
    pub fn huella(id_equipo: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CTX_HUELLA);
        h.update(id_equipo.as_bytes());
        h.finalize().into()
    }

    /// Cubeta del equipo, de 0 a 9999, para una sal.
    #[must_use]
    pub fn cubeta(sal: &[u8; 32], id_equipo: &str) -> u16 {
        let mut h = Sha256::new();
        h.update(sal);
        h.update(Anillo::huella(id_equipo));
        let d: [u8; 32] = h.finalize().into();
        let mut a = [0u8; 8];
        a.copy_from_slice(&d[..8]);
        // El resto es menor que 10 000: cabe en u16.
        (u64::from_le_bytes(a) % u64::from(PUNTOS_TOTALES)) as u16
    }

    /// Si el equipo esta en este anillo.
    #[must_use]
    pub fn incluye(&self, id_equipo: &str) -> bool {
        match self {
            Anillo::Canario { miembros } => {
                miembros.binary_search(&Anillo::huella(id_equipo)).is_ok()
            }
            Anillo::Porcentaje { puntos, sal } => Anillo::cubeta(sal, id_equipo) < *puntos,
            Anillo::Flota => true,
        }
    }

    /// Reglas del propio anillo.
    ///
    /// # Errores
    /// El motivo, si el anillo no es canonico o no tiene sentido.
    pub fn comprobar(&self) -> Result<(), String> {
        match self {
            Anillo::Canario { miembros } => {
                if miembros.is_empty() {
                    return Err("canario sin miembros".into());
                }
                if miembros.len() > MAX_MIEMBROS_CANARIO {
                    return Err(format!(
                        "canario de {} miembros (maximo {MAX_MIEMBROS_CANARIO})",
                        miembros.len()
                    ));
                }
                if miembros.windows(2).any(|w| w[0] >= w[1]) {
                    return Err("miembros del canario sin ordenar o repetidos".into());
                }
                Ok(())
            }
            Anillo::Porcentaje { puntos, .. } => {
                if *puntos == 0 || *puntos >= PUNTOS_TOTALES {
                    return Err(format!(
                        "porcentaje de {puntos} puntos basicos: tiene que estar entre 1 y {}",
                        PUNTOS_TOTALES - 1
                    ));
                }
                Ok(())
            }
            Anillo::Flota => Ok(()),
        }
    }

    pub(crate) fn codificar(&self, e: &mut Escritor) {
        e.u8(self.orden());
        match self {
            Anillo::Canario { miembros } => {
                e.cuenta(miembros.len());
                for m in miembros {
                    e.fijo(m);
                }
            }
            Anillo::Porcentaje { puntos, sal } => {
                e.u16(*puntos);
                e.fijo(sal);
            }
            Anillo::Flota => {}
        }
    }

    pub(crate) fn decodificar(l: &mut Lector<'_>) -> Result<Anillo, ErrorFormato> {
        match l.u8()? {
            0 => {
                let n = l.cuenta(MAX_MIEMBROS_CANARIO, "miembros del canario")?;
                let mut miembros = Vec::with_capacity(n);
                for _ in 0..n {
                    miembros.push(l.fijo32()?);
                }
                Ok(Anillo::Canario { miembros })
            }
            1 => {
                let puntos = l.u16()?;
                let sal = l.fijo32()?;
                Ok(Anillo::Porcentaje { puntos, sal })
            }
            2 => Ok(Anillo::Flota),
            x => Err(ErrorFormato(format!("anillo desconocido: {x}"))),
        }
    }
}

/// Nombre de un anillo por su anchura.
#[must_use]
pub fn nombre_orden(orden: u8) -> &'static str {
    match orden {
        0 => "canario",
        1 => "porcentaje",
        2 => "flota",
        _ => "desconocido",
    }
}

/// Un peldaño de la escalera: el mismo contenido, antes, en un anillo mas estrecho.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peldano {
    /// Anchura del anillo de entonces ([`Anillo::orden`]).
    pub orden: u8,
    /// Epoca en la que se publico en ese anillo.
    pub epoca: u64,
    /// Equipos que lo dieron por sano.
    pub sanos: u64,
    /// Equipos que informaron de un fallo con el. Tiene que ser cero.
    pub fallos: u64,
}

impl Peldano {
    pub(crate) fn codificar(&self, e: &mut Escritor) {
        e.u8(self.orden);
        e.u64(self.epoca);
        e.u64(self.sanos);
        e.u64(self.fallos);
    }

    pub(crate) fn decodificar(l: &mut Lector<'_>) -> Result<Peldano, ErrorFormato> {
        Ok(Peldano {
            orden: l.u8()?,
            epoca: l.u64()?,
            sanos: l.u64()?,
            fallos: l.u64()?,
        })
    }
}

/// Comprueba la escalera de un paquete.
///
/// Reglas: cada peldaño es de un anillo mas estrecho que el del paquete y de una
/// epoca anterior; van en orden creciente de anchura y de epoca; ninguno tiene
/// fallos y todos acreditan los sanos minimos; y cada anillo por debajo del del
/// paquete tiene su peldaño. Una reversion (`revierte_a != 0`) vuelve a contenido
/// que ya subio la escalera en su dia, y no la repite: volver atras tiene que
/// ser rapido.
///
/// # Errores
/// El motivo, en texto.
pub fn comprobar_escalera(
    anillo: &Anillo,
    escalera: &[Peldano],
    epoca: u64,
    revierte_a: u64,
) -> Result<(), String> {
    if escalera.len() > MAX_PELDANOS {
        return Err(format!(
            "{} peldaños (maximo {MAX_PELDANOS})",
            escalera.len()
        ));
    }
    let mut previo: Option<&Peldano> = None;
    for p in escalera {
        let nombre = nombre_orden(p.orden);
        if p.orden >= anillo.orden() {
            return Err(format!(
                "peldaño «{nombre}» igual o mas ancho que el anillo del paquete («{}»)",
                anillo.nombre()
            ));
        }
        if p.epoca >= epoca {
            return Err(format!(
                "peldaño «{nombre}» de la epoca {} no anterior a la del paquete ({epoca})",
                p.epoca
            ));
        }
        if let Some(a) = previo {
            if p.orden <= a.orden || p.epoca <= a.epoca {
                return Err("peldaños sin orden creciente de anillo y de epoca".into());
            }
        }
        if p.fallos != 0 {
            return Err(format!(
                "el anillo «{nombre}» informo de {} fallo(s): ese contenido no se promociona",
                p.fallos
            ));
        }
        let minimo = if p.orden == 0 {
            MIN_SANOS_CANARIO
        } else {
            MIN_SANOS_PORCENTAJE
        };
        if p.sanos < minimo {
            return Err(format!(
                "el anillo «{nombre}» solo acredita {} equipo(s) sano(s) (hacen falta {minimo})",
                p.sanos
            ));
        }
        previo = Some(p);
    }
    if revierte_a != 0 {
        if revierte_a >= epoca {
            return Err(format!(
                "revierte a la epoca {revierte_a}, que no es anterior a la suya ({epoca})"
            ));
        }
        return Ok(());
    }
    for orden in 0..anillo.orden() {
        if !escalera.iter().any(|p| p.orden == orden) {
            return Err(format!(
                "llega al anillo «{}» sin haber pasado por «{}»",
                anillo.nombre(),
                nombre_orden(orden)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_canario_incluye_solo_a_sus_miembros() {
        let a = Anillo::canario(&["equipo-b", "equipo-a", "equipo-a"]);
        a.comprobar().unwrap();
        assert!(a.incluye("equipo-a"));
        assert!(a.incluye("equipo-b"));
        assert!(!a.incluye("equipo-c"));
    }

    #[test]
    fn el_cinco_por_ciento_es_un_cinco_por_ciento_estable() {
        let a = Anillo::Porcentaje {
            puntos: CINCO_POR_CIENTO,
            sal: [7; 32],
        };
        let dentro = (0..10_000)
            .filter(|i| a.incluye(&format!("equipo-{i}")))
            .count();
        // Binomial(10 000, 0.05): media 500, desviacion ~22. Mas de 4 sigmas.
        assert!((400..=600).contains(&dentro), "{dentro} de 10 000");
        // La misma sal, el mismo equipo: la misma decision.
        assert_eq!(a.incluye("equipo-17"), a.incluye("equipo-17"));
    }

    #[test]
    fn la_flota_sin_canario_ni_porcentaje_no_se_sostiene() {
        let e = comprobar_escalera(&Anillo::Flota, &[], 9, 0).unwrap_err();
        assert!(e.contains("canario"), "{e}");
        let solo_canario = [Peldano {
            orden: 0,
            epoca: 3,
            sanos: 50,
            fallos: 0,
        }];
        assert!(comprobar_escalera(&Anillo::Flota, &solo_canario, 9, 0).is_err());
        let completa = [
            solo_canario[0],
            Peldano {
                orden: 1,
                epoca: 5,
                sanos: 500,
                fallos: 0,
            },
        ];
        comprobar_escalera(&Anillo::Flota, &completa, 9, 0).unwrap();
    }

    #[test]
    fn un_peldano_con_fallos_no_promociona() {
        let p = [Peldano {
            orden: 0,
            epoca: 3,
            sanos: 50,
            fallos: 1,
        }];
        let a = Anillo::Porcentaje {
            puntos: CINCO_POR_CIENTO,
            sal: [1; 32],
        };
        assert!(comprobar_escalera(&a, &p, 4, 0).is_err());
    }

    #[test]
    fn una_reversion_no_repite_la_escalera_pero_mira_atras() {
        comprobar_escalera(&Anillo::Flota, &[], 9, 4).unwrap();
        assert!(comprobar_escalera(&Anillo::Flota, &[], 9, 9).is_err());
    }
}
