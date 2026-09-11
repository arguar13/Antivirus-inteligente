//! Grafo de identidad en memoria y deteccion de escaladas de privilegio.
//!
//! ## De que va
//!
//! El movimiento lateral es un problema de **grafos**, no de eventos sueltos.
//! Ningun evento aislado dice "esto es una escalada"; lo dice el CAMINO: un
//! proceso que corre como el usuario `alice` impersona la cuenta de servicio
//! `svc-backup`, que a su vez tiene credenciales cacheadas de un `Domain Admin`.
//! Ninguno de esos pasos es raro por si solo; juntos abren una ruta de un
//! privilegio bajo a uno maximo.
//!
//! Este modulo mapea las identidades (usuarios, servicios, maquinas, grupos —los
//! tokens de acceso de Windows o el `euid` de Linux) como **nodos** con un
//! **nivel** de privilegio, y las relaciones observadas ("actua como",
//! "impersona", "controla las credenciales de", "autentica en") como **aristas
//! dirigidas**. Sobre ese grafo:
//!
//! 1. [`GrafoIdentidad::observar_arista`] detecta una **escalada**: una arista
//!    nueva que abre, desde una identidad de nivel bajo, un camino a otra de
//!    nivel estrictamente mayor que antes no existia.
//! 2. [`GrafoIdentidad::intermediacion`] calcula la **centralidad de
//!    intermediacion** (algoritmo de Brandes): que identidades son cuellos de
//!    botella por los que pasan muchos caminos de ataque. Son las joyas de la
//!    corona y los concentradores de movimiento lateral que hay que vigilar.
//!
//! ## El caso decisivo
//!
//! Un administrador haciendo cosas de administrador **no es una escalada**. Si
//! `observar_arista` disparara cada vez que un `Domain Admin` toca algo, ahogaria
//! al analista. Una escalada es ganar acceso a un nivel **mayor** que el propio;
//! moverse lateral entre iguales, o hacia abajo, es operacion normal. Por eso la
//! comparacion es `nivel_destino > nivel_origen`, estricta.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::{ClaseAmenaza, Deteccion, ItdrError, Severidad};

/// Nivel de privilegio de una identidad. El orden de declaracion es el orden de
/// privilegio: `Usuario` es el mas bajo, `AdminDominio` el mas alto. Una escalada
/// es alcanzar un nivel estrictamente mayor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nivel {
    /// Usuario raso.
    Usuario,
    /// Operador o cuenta de servicio con algun privilegio delegado.
    Operador,
    /// Administrador de una maquina.
    AdminLocal,
    /// Administrador del dominio: control total de la infraestructura de identidad.
    AdminDominio,
}

/// Clase de una identidad, para dar contexto legible a la evidencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseIdentidad {
    /// Una persona.
    Usuario,
    /// Una cuenta de servicio.
    Servicio,
    /// Una cuenta de maquina.
    Maquina,
    /// Un grupo de seguridad.
    Grupo,
}

/// Una identidad: el nodo del grafo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identidad {
    /// Nombre unico (p. ej. `alice`, `svc-backup`, `Domain Admins`).
    pub nombre: String,
    /// Clase de la identidad.
    pub clase: ClaseIdentidad,
    /// Nivel de privilegio.
    pub nivel: Nivel,
}

impl Identidad {
    /// Construye una identidad.
    #[must_use]
    pub fn nueva(nombre: impl Into<String>, clase: ClaseIdentidad, nivel: Nivel) -> Self {
        Self {
            nombre: nombre.into(),
            clase,
            nivel,
        }
    }
}

/// Una relacion observada entre dos identidades: la arista dirigida `origen ->
/// destino` significa "controlar `origen` permite obtener/actuar como `destino`".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relacion {
    /// El proceso corre como esta identidad (token primario, `euid`).
    ActuaComo,
    /// Impersona a otra identidad (token de impersonacion en Windows).
    Impersona,
    /// Es miembro de un grupo.
    MiembroDe,
    /// Tiene credenciales de la otra identidad (cacheadas, en memoria de `lsass`).
    ControlaCredencialesDe,
    /// Se autentico en un host donde vive la otra identidad.
    AutenticaEn,
}

impl Relacion {
    /// Verbo legible para la evidencia.
    fn describir(self) -> &'static str {
        match self {
            Self::ActuaComo => "actuar como",
            Self::Impersona => "impersonar",
            Self::MiembroDe => "hacerse miembro de",
            Self::ControlaCredencialesDe => "controlar las credenciales de",
            Self::AutenticaEn => "autenticarse en",
        }
    }
}

/// El grafo de identidad del Control Plane.
#[derive(Debug, Default)]
pub struct GrafoIdentidad {
    grafo: DiGraph<Identidad, Relacion>,
    indice: HashMap<String, NodeIndex>,
}

impl GrafoIdentidad {
    /// Un grafo vacio.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Agrega una identidad y devuelve su indice. Si ya existe una con ese
    /// nombre, se conserva la existente (no se sobreescribe) y se devuelve su
    /// indice: el nombre es la clave estable.
    pub fn agregar_identidad(&mut self, id: Identidad) -> NodeIndex {
        if let Some(&idx) = self.indice.get(&id.nombre) {
            return idx;
        }
        let nombre = id.nombre.clone();
        let idx = self.grafo.add_node(id);
        self.indice.insert(nombre, idx);
        idx
    }

    /// Agrega una relacion entre dos identidades ya presentes, SIN evaluar
    /// escaladas. Sirve para cargar el estado conocido del grafo antes de empezar
    /// a observar cambios.
    ///
    /// # Errores
    /// [`ItdrError::IdentidadDesconocida`] si el origen o el destino no existen.
    pub fn agregar_arista(
        &mut self,
        origen: &str,
        destino: &str,
        relacion: Relacion,
    ) -> Result<(), ItdrError> {
        let (o, d) = self.par(origen, destino)?;
        if self.grafo.find_edge(o, d).is_none() {
            self.grafo.add_edge(o, d, relacion);
        }
        Ok(())
    }

    /// Observa una relacion nueva y decide si abre una **escalada**: un camino,
    /// desde `origen`, a una identidad de nivel estrictamente mayor que el de
    /// `origen`, que no existia antes de esta arista.
    ///
    /// La arista se incorpora al grafo (la observacion es real), asi que las
    /// siguientes observaciones ya la ven.
    ///
    /// # Errores
    /// [`ItdrError::IdentidadDesconocida`] si el origen o el destino no existen.
    pub fn observar_arista(
        &mut self,
        origen: &str,
        destino: &str,
        relacion: Relacion,
    ) -> Result<Option<Deteccion>, ItdrError> {
        let (o, d) = self.par(origen, destino)?;
        let nivel_origen = self.grafo[o].nivel;

        let antes = self.alcanzables_superiores(o, nivel_origen);
        if self.grafo.find_edge(o, d).is_none() {
            self.grafo.add_edge(o, d, relacion);
        }
        let despues = self.alcanzables_superiores(o, nivel_origen);

        // Nodos de nivel superior recien alcanzables desde el origen.
        let nuevos: Vec<NodeIndex> = despues.difference(&antes).copied().collect();
        let Some(&objetivo) = nuevos.iter().max_by(|&&a, &&b| {
            self.grafo[a]
                .nivel
                .cmp(&self.grafo[b].nivel)
                .then_with(|| self.grafo[b].nombre.cmp(&self.grafo[a].nombre))
        }) else {
            return Ok(None);
        };

        let nivel_objetivo = self.grafo[objetivo].nivel;
        let severidad = match nivel_objetivo {
            Nivel::AdminDominio => Severidad::Critica,
            Nivel::AdminLocal => Severidad::Alta,
            _ => Severidad::Media,
        };
        let evidencia = format!(
            "La identidad '{origen}' ({:?}) obtuvo, al {} '{destino}', un camino nuevo hasta \
             '{}' ({:?}): escalada de privilegios.",
            nivel_origen,
            relacion.describir(),
            self.grafo[objetivo].nombre,
            nivel_objetivo,
        );
        Ok(Some(Deteccion::nueva(
            ClaseAmenaza::EscaladaPrivilegios,
            severidad,
            origen,
            evidencia,
        )))
    }

    /// El nivel de una identidad, si existe.
    #[must_use]
    pub fn nivel_de(&self, nombre: &str) -> Option<Nivel> {
        self.indice.get(nombre).map(|&idx| self.grafo[idx].nivel)
    }

    /// Centralidad de intermediacion (algoritmo de Brandes) de cada identidad,
    /// para un grafo dirigido y sin pesos. El valor de un nodo es el numero de
    /// caminos minimos entre otros pares que pasan por el: cuanto mas alto, mas
    /// es un cuello de botella del movimiento lateral.
    #[must_use]
    pub fn intermediacion(&self) -> HashMap<String, f64> {
        let n = self.grafo.node_count();
        let mut cb = vec![0.0f64; n];

        for s in self.grafo.node_indices() {
            let mut pila: Vec<NodeIndex> = Vec::new();
            let mut pred: Vec<Vec<NodeIndex>> = vec![Vec::new(); n];
            let mut sigma = vec![0.0f64; n];
            let mut dist = vec![-1i64; n];
            sigma[s.index()] = 1.0;
            dist[s.index()] = 0;

            let mut cola = VecDeque::new();
            cola.push_back(s);
            while let Some(v) = cola.pop_front() {
                pila.push(v);
                for w in self.grafo.neighbors_directed(v, Direction::Outgoing) {
                    if dist[w.index()] < 0 {
                        dist[w.index()] = dist[v.index()] + 1;
                        cola.push_back(w);
                    }
                    if dist[w.index()] == dist[v.index()] + 1 {
                        sigma[w.index()] += sigma[v.index()];
                        pred[w.index()].push(v);
                    }
                }
            }

            let mut delta = vec![0.0f64; n];
            while let Some(w) = pila.pop() {
                let sigma_w = sigma[w.index()];
                for &v in &pred[w.index()] {
                    delta[v.index()] += (sigma[v.index()] / sigma_w) * (1.0 + delta[w.index()]);
                }
                if w != s {
                    cb[w.index()] += delta[w.index()];
                }
            }
        }

        let mut res = HashMap::with_capacity(n);
        for idx in self.grafo.node_indices() {
            res.insert(self.grafo[idx].nombre.clone(), cb[idx.index()]);
        }
        res
    }

    /// Las `top` identidades por centralidad de intermediacion, de mayor a menor
    /// (con el nombre como desempate estable). Son las que hay que vigilar y
    /// endurecer primero.
    #[must_use]
    pub fn nodos_criticos(&self, top: usize) -> Vec<(String, f64)> {
        let mut v: Vec<(String, f64)> = self.intermediacion().into_iter().collect();
        v.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        v.truncate(top);
        v
    }

    /// Resuelve el par (origen, destino) a sus indices, o falla nombrando el que
    /// no existe.
    fn par(&self, origen: &str, destino: &str) -> Result<(NodeIndex, NodeIndex), ItdrError> {
        let o = *self
            .indice
            .get(origen)
            .ok_or_else(|| ItdrError::IdentidadDesconocida(origen.to_string()))?;
        let d = *self
            .indice
            .get(destino)
            .ok_or_else(|| ItdrError::IdentidadDesconocida(destino.to_string()))?;
        Ok((o, d))
    }

    /// Conjunto de nodos alcanzables desde `origen` (siguiendo aristas dirigidas)
    /// cuyo nivel es estrictamente mayor que `umbral`.
    fn alcanzables_superiores(&self, origen: NodeIndex, umbral: Nivel) -> HashSet<NodeIndex> {
        let mut vistos = HashSet::new();
        let mut altos = HashSet::new();
        vistos.insert(origen);
        let mut cola = VecDeque::new();
        cola.push_back(origen);
        while let Some(v) = cola.pop_front() {
            for w in self.grafo.neighbors_directed(v, Direction::Outgoing) {
                if vistos.insert(w) {
                    if self.grafo[w].nivel > umbral {
                        altos.insert(w);
                    }
                    cola.push_back(w);
                }
            }
        }
        altos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(g: &mut GrafoIdentidad, nombre: &str, clase: ClaseIdentidad, nivel: Nivel) {
        g.agregar_identidad(Identidad::nueva(nombre, clase, nivel));
    }

    #[test]
    fn una_impersonacion_que_abre_camino_a_admin_de_dominio_es_escalada() {
        let mut g = GrafoIdentidad::nuevo();
        ident(&mut g, "alice", ClaseIdentidad::Usuario, Nivel::Usuario);
        ident(
            &mut g,
            "svc-backup",
            ClaseIdentidad::Servicio,
            Nivel::Operador,
        );
        ident(
            &mut g,
            "da-root",
            ClaseIdentidad::Usuario,
            Nivel::AdminDominio,
        );
        // svc-backup ya tenia un camino a un Domain Admin (credenciales cacheadas).
        g.agregar_arista("svc-backup", "da-root", Relacion::ControlaCredencialesDe)
            .expect("arista");

        // Antes de la impersonacion, alice no alcanza a nadie de nivel superior.
        // La impersonacion abre alice -> svc-backup -> da-root.
        let det = g
            .observar_arista("alice", "svc-backup", Relacion::Impersona)
            .expect("nodos existen")
            .expect("debe ser una escalada");

        assert_eq!(det.clase, ClaseAmenaza::EscaladaPrivilegios);
        assert_eq!(det.severidad, Severidad::Critica);
        assert_eq!(det.sujeto, "alice");
        assert!(det.evidencia.contains("da-root"), "{}", det.evidencia);
    }

    #[test]
    fn un_admin_actuando_como_admin_no_es_escalada() {
        // EL CASO DECISIVO. bob ya es Domain Admin: no hay nivel superior que
        // alcanzar, asi que tocar cualquier cosa NO es una escalada.
        let mut g = GrafoIdentidad::nuevo();
        ident(&mut g, "bob", ClaseIdentidad::Usuario, Nivel::AdminDominio);
        ident(&mut g, "dc01", ClaseIdentidad::Maquina, Nivel::AdminLocal);
        ident(
            &mut g,
            "otro-da",
            ClaseIdentidad::Usuario,
            Nivel::AdminDominio,
        );

        assert!(g
            .observar_arista("bob", "dc01", Relacion::AutenticaEn)
            .expect("nodos existen")
            .is_none());
        // Ni siquiera moverse lateral a otro Domain Admin (mismo nivel) es escalada.
        assert!(g
            .observar_arista("bob", "otro-da", Relacion::Impersona)
            .expect("nodos existen")
            .is_none());
    }

    #[test]
    fn un_usuario_entrando_a_su_estacion_no_es_escalada() {
        let mut g = GrafoIdentidad::nuevo();
        ident(&mut g, "alice", ClaseIdentidad::Usuario, Nivel::Usuario);
        ident(&mut g, "wks-alice", ClaseIdentidad::Maquina, Nivel::Usuario);
        assert!(g
            .observar_arista("alice", "wks-alice", Relacion::AutenticaEn)
            .expect("nodos existen")
            .is_none());
    }

    #[test]
    fn una_arista_a_identidad_desconocida_falla_ruidosamente() {
        let mut g = GrafoIdentidad::nuevo();
        ident(&mut g, "alice", ClaseIdentidad::Usuario, Nivel::Usuario);
        assert_eq!(
            g.observar_arista("alice", "fantasma", Relacion::Impersona),
            Err(ItdrError::IdentidadDesconocida("fantasma".to_string()))
        );
    }

    #[test]
    fn la_intermediacion_de_brandes_coincide_con_el_calculo_a_mano() {
        // KAT de grafos. Camino dirigido a -> b -> c -> d. A mano, la
        // intermediacion es: a=0, b=2, c=2, d=0 (por b pasan los caminos a->c y
        // a->d; por c pasan a->d y b->d).
        let mut g = GrafoIdentidad::nuevo();
        for n in ["a", "b", "c", "d"] {
            ident(&mut g, n, ClaseIdentidad::Usuario, Nivel::Usuario);
        }
        g.agregar_arista("a", "b", Relacion::AutenticaEn).unwrap();
        g.agregar_arista("b", "c", Relacion::AutenticaEn).unwrap();
        g.agregar_arista("c", "d", Relacion::AutenticaEn).unwrap();

        let cb = g.intermediacion();
        assert_eq!(cb["a"], 0.0);
        assert_eq!(cb["b"], 2.0);
        assert_eq!(cb["c"], 2.0);
        assert_eq!(cb["d"], 0.0);
    }

    #[test]
    fn los_nodos_criticos_ordenan_por_intermediacion() {
        // Estrella dirigida hacia el centro y desde el centro: h es el cuello de
        // botella por el que pasa todo el movimiento lateral.
        let mut g = GrafoIdentidad::nuevo();
        for n in ["h", "x1", "x2", "x3"] {
            ident(&mut g, n, ClaseIdentidad::Usuario, Nivel::Usuario);
        }
        // x1,x2,x3 -> h -> (x1,x2,x3): h intermedia todos los caminos xi -> xj.
        for x in ["x1", "x2", "x3"] {
            g.agregar_arista(x, "h", Relacion::AutenticaEn).unwrap();
            g.agregar_arista("h", x, Relacion::AutenticaEn).unwrap();
        }
        let top = g.nodos_criticos(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "h");
        assert!(top[0].1 > 0.0);
    }
}
