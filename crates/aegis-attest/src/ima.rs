//! IMA unido a la PROCEDENCIA (FASE 105).
//!
//! # Medir no es responder
//!
//! Keylime MIDE: recoge la lista de medidas de IMA y comprueba que cada hash esta
//! en una lista de permitidos. Pero una lista de hashes buenos no dice de DONDE
//! salio un fichero. Aqui cada medida se casa contra el inventario de procedencia
//! —los paquetes de la FASE 81 y la linea base de la FASE 104—: una medida cuyo
//! fichero ningun paquete ni la linea base avala es `SinProcedencia`, y eso es
//! justo lo que convierte una lista de hashes en una respuesta: «este binario se
//! ejecuto y no viene de ninguna parte que conozcamos».

use std::collections::BTreeMap;

/// Una entrada de la lista de medidas de IMA: un fichero que el kernel midio al
/// abrirlo o ejecutarlo, con el PCR en el que lo extendio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MedidaIma {
    /// El PCR donde se extendio (tipicamente el 10).
    pub pcr: u32,
    /// La huella del fichero, tal cual la publica IMA: `algoritmo:hex`.
    pub huella: String,
    /// La ruta del fichero medido.
    pub ruta: String,
}

impl MedidaIma {
    /// Parsea una linea del formato ascii de IMA, de forma robusta (sin panico).
    ///
    /// Formato: `PCR plantilla-hash nombre-plantilla algoritmo:hex ruta`. Se toma
    /// el PCR, el campo que lleva `algoritmo:hex` como huella, y el ultimo campo
    /// como ruta. Devuelve `None` si la linea no tiene la forma minima.
    #[must_use]
    pub fn parsear_linea(linea: &str) -> Option<MedidaIma> {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 3 {
            return None;
        }
        let pcr: u32 = campos[0].parse().ok()?;
        let huella = campos.iter().find(|c| c.contains(':'))?.to_string();
        let ruta = (*campos.last()?).to_string();
        Some(MedidaIma { pcr, huella, ruta })
    }
}

/// El inventario de procedencia: de donde salio cada huella conocida. Se puebla
/// con los paquetes (FASE 81) y con la linea base atestada (FASE 104).
#[derive(Debug, Clone, Default)]
pub struct InventarioProcedencia {
    por_huella: BTreeMap<String, String>,
}

impl InventarioProcedencia {
    /// Un inventario vacio.
    #[must_use]
    pub fn nuevo() -> InventarioProcedencia {
        InventarioProcedencia::default()
    }

    /// Registra que una huella viene de un origen (un paquete, o «linea-base»).
    #[must_use]
    pub fn con(mut self, huella: &str, origen: &str) -> InventarioProcedencia {
        self.por_huella
            .insert(huella.to_string(), origen.to_string());
        self
    }

    /// El origen de una huella, si lo conocemos.
    #[must_use]
    pub fn origen(&self, huella: &str) -> Option<&str> {
        self.por_huella.get(huella).map(String::as_str)
    }
}

/// La procedencia de una medida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Procedencia {
    /// La medida corresponde a un fichero de origen conocido.
    Conocida {
        /// El origen (paquete o linea base).
        origen: String,
    },
    /// La medida NO corresponde a nada del inventario: un fichero que se midio
    /// —se abrio o ejecuto— y que ningun paquete ni la linea base avala. Es lo
    /// que Keylime no dice.
    SinProcedencia,
}

/// Casa cada medida contra el inventario de procedencia.
#[must_use]
pub fn casar(medidas: &[MedidaIma], inv: &InventarioProcedencia) -> Vec<(MedidaIma, Procedencia)> {
    medidas
        .iter()
        .map(|m| {
            let p = match inv.origen(&m.huella) {
                Some(origen) => Procedencia::Conocida {
                    origen: origen.to_string(),
                },
                None => Procedencia::SinProcedencia,
            };
            (m.clone(), p)
        })
        .collect()
}

/// Atajo: solo las medidas SIN procedencia, que son las que hay que mirar.
#[must_use]
pub fn sin_procedencia(medidas: &[MedidaIma], inv: &InventarioProcedencia) -> Vec<MedidaIma> {
    medidas
        .iter()
        .filter(|m| inv.origen(&m.huella).is_none())
        .cloned()
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn parsea_una_linea_ima_ng() {
        let l = "10 a1b2c3 ima-ng sha256:deadbeef /usr/bin/sshd";
        let m = MedidaIma::parsear_linea(l).unwrap();
        assert_eq!(m.pcr, 10);
        assert_eq!(m.huella, "sha256:deadbeef");
        assert_eq!(m.ruta, "/usr/bin/sshd");
    }

    #[test]
    fn linea_basura_no_panica_y_devuelve_none() {
        assert_eq!(MedidaIma::parsear_linea(""), None);
        assert_eq!(MedidaIma::parsear_linea("solo-una-cosa"), None);
        let _ = MedidaIma::parsear_linea(&"x".repeat(10_000));
    }

    #[test]
    fn una_medida_sin_procedencia_es_la_que_importa() {
        // Dos medidas: una viene de un paquete, la otra no viene de ninguna parte.
        let inv = InventarioProcedencia::nuevo()
            .con("sha256:aaaa", "openssh-server")
            .con("sha256:bbbb", "linea-base");
        let medidas = vec![
            MedidaIma {
                pcr: 10,
                huella: "sha256:aaaa".to_string(),
                ruta: "/usr/sbin/sshd".to_string(),
            },
            MedidaIma {
                pcr: 10,
                huella: "sha256:cccc".to_string(),
                ruta: "/tmp/implante".to_string(),
            },
        ];
        let casadas = casar(&medidas, &inv);
        assert!(matches!(casadas[0].1, Procedencia::Conocida { .. }));
        assert_eq!(casadas[1].1, Procedencia::SinProcedencia);
        // El atajo: solo el implante.
        let sospechosas = sin_procedencia(&medidas, &inv);
        assert_eq!(sospechosas.len(), 1);
        assert_eq!(sospechosas[0].ruta, "/tmp/implante");
    }
}
