//! El linaje UNIFICADO que la consola ensena (FASE 110).
//!
//! Las consolas abiertas —Wazuh, TheHive, Velociraptor, Arkime— ensenan lo que su
//! producto sabe: una de red, otra de ficheros, otra de procesos. Ninguna cruza los
//! cinco planos en UNA cadena, porque ninguna tiene un modelo de entidad unico.
//! AegisCore si: aqui el linaje es un solo grafo que va de una conexion de red a un
//! proceso, a un fichero, a la identidad que lo lanzo, a la respuesta que se
//! ordeno, y se navega en las DOS direcciones. Es el modelo de la vista; poblarlo
//! desde cada subsistema es el cableado que se declara.

use std::collections::{BTreeMap, BTreeSet};

/// El plano en el que vive una entidad del linaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Plano {
    /// Red: flujos, conexiones, balizas.
    Red,
    /// Fichero: contenidos, rutas, artefactos.
    Fichero,
    /// Proceso: ejecucion, linaje de procesos.
    Proceso,
    /// Identidad: cuentas, sesiones, credenciales.
    Identidad,
    /// Respuesta: remediaciones, cuarentenas, flujos.
    Respuesta,
}

impl Plano {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Plano::Red => "red",
            Plano::Fichero => "fichero",
            Plano::Proceso => "proceso",
            Plano::Identidad => "identidad",
            Plano::Respuesta => "respuesta",
        }
    }
}

/// Un nodo del linaje: una entidad, en su plano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nodo {
    /// Identificador de la entidad (del modelo unico).
    pub id: String,
    /// En que plano esta.
    pub plano: Plano,
    /// Etiqueta legible para el panel.
    pub etiqueta: String,
}

/// Un enlace dirigido entre dos entidades, con la relacion que las une.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enlace {
    /// Origen.
    pub de: String,
    /// Destino.
    pub a: String,
    /// Que relacion (p. ej. «abrio», «ejecuto», «se conecto a», «contuvo»).
    pub relacion: String,
}

/// El grafo de linaje unificado.
#[derive(Debug, Clone, Default)]
pub struct Linaje {
    nodos: BTreeMap<String, Nodo>,
    enlaces: Vec<Enlace>,
}

impl Linaje {
    /// Un linaje vacio.
    #[must_use]
    pub fn nuevo() -> Linaje {
        Linaje::default()
    }

    /// Anade un nodo.
    #[must_use]
    pub fn con_nodo(mut self, id: &str, plano: Plano, etiqueta: &str) -> Linaje {
        self.nodos.insert(
            id.to_string(),
            Nodo {
                id: id.to_string(),
                plano,
                etiqueta: etiqueta.to_string(),
            },
        );
        self
    }

    /// Anade un enlace dirigido `de -> a` con su relacion.
    #[must_use]
    pub fn con_enlace(mut self, de: &str, a: &str, relacion: &str) -> Linaje {
        self.enlaces.push(Enlace {
            de: de.to_string(),
            a: a.to_string(),
            relacion: relacion.to_string(),
        });
        self
    }

    /// Un nodo por id.
    #[must_use]
    pub fn nodo(&self, id: &str) -> Option<&Nodo> {
        self.nodos.get(id)
    }

    /// Hacia adelante: a que entidades apunta esta (lo que hizo).
    #[must_use]
    pub fn hacia_adelante(&self, id: &str) -> Vec<&Nodo> {
        self.enlaces
            .iter()
            .filter(|e| e.de == id)
            .filter_map(|e| self.nodos.get(&e.a))
            .collect()
    }

    /// Hacia atras: que entidades apuntan a esta (de donde viene). Es lo que hace
    /// el linaje navegable en las DOS direcciones.
    #[must_use]
    pub fn hacia_atras(&self, id: &str) -> Vec<&Nodo> {
        self.enlaces
            .iter()
            .filter(|e| e.a == id)
            .filter_map(|e| self.nodos.get(&e.de))
            .collect()
    }

    /// Los planos que el linaje CRUZA: lo que ninguna consola de un solo plano
    /// puede ensenar.
    #[must_use]
    pub fn planos_cruzados(&self) -> BTreeSet<Plano> {
        self.nodos.values().map(|n| n.plano).collect()
    }

    /// Numero de nodos.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodos.len()
    }

    /// Si esta vacio.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodos.is_empty()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Una cadena real: una baliza de red -> el proceso que la emitio -> el fichero
    // que lo lanzo -> la identidad que lo ejecuto -> la cuarentena que se ordeno.
    fn linaje_cruzado() -> Linaje {
        Linaje::nuevo()
            .con_nodo("net:1.2.3.4:443", Plano::Red, "baliza C2")
            .con_nodo("proc:4211", Plano::Proceso, "powershell")
            .con_nodo("file:sha256:ab", Plano::Fichero, "carga.ps1")
            .con_nodo("id:alice", Plano::Identidad, "alice@dominio")
            .con_nodo("resp:q-99", Plano::Respuesta, "cuarentena de m-17")
            .con_enlace("proc:4211", "net:1.2.3.4:443", "se conecto a")
            .con_enlace("file:sha256:ab", "proc:4211", "ejecuto")
            .con_enlace("id:alice", "proc:4211", "lanzo")
            .con_enlace("resp:q-99", "net:1.2.3.4:443", "contuvo")
    }

    #[test]
    fn el_linaje_cruza_los_cinco_planos_en_una_cadena() {
        let l = linaje_cruzado();
        let planos = l.planos_cruzados();
        assert_eq!(
            planos.len(),
            5,
            "cruza red, fichero, proceso, identidad y respuesta"
        );
        assert!(planos.contains(&Plano::Red));
        assert!(planos.contains(&Plano::Identidad));
        assert!(planos.contains(&Plano::Respuesta));
    }

    #[test]
    fn se_navega_en_las_dos_direcciones() {
        let l = linaje_cruzado();
        // Hacia atras desde la baliza: el proceso que se conecto y la respuesta
        // que la contuvo apuntan a ella.
        let atras: Vec<&str> = l
            .hacia_atras("net:1.2.3.4:443")
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert!(atras.contains(&"proc:4211"));
        assert!(atras.contains(&"resp:q-99"));
        // Hacia adelante desde el proceso: la baliza a la que se conecto.
        let adelante: Vec<&str> = l
            .hacia_adelante("proc:4211")
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(adelante, vec!["net:1.2.3.4:443"]);
    }

    #[test]
    fn desde_la_identidad_se_llega_al_proceso() {
        let l = linaje_cruzado();
        let adelante: Vec<&str> = l
            .hacia_adelante("id:alice")
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(adelante, vec!["proc:4211"], "alice lanzo el proceso");
    }
}
