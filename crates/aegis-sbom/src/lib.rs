//! AegisPosture (FASE 94): el inventario de componentes de una maquina, sus
//! vulnerabilidades conocidas y, para cada una, si de verdad importa.
//!
//! # La pregunta
//!
//! Trivy, Grype, Syft, OpenVAS y Nuclei dicen que hay una vulnerabilidad. Lo que
//! no dicen es si importa **en esta maquina, ahora**: si el componente vulnerable
//! esta cargado en algun proceso vivo, si la funcion vulnerable es alcanzable
//! desde el programa que lo carga, y si ese programa escucha en la red. Una
//! lista de cuatro mil CVE sin priorizar es ruido; doce alcanzables es trabajo.
//! Y las tres respuestas salen de telemetria que el agente YA tiene: los mapas de
//! memoria, los sockets y el grafo de llamadas de la FASE 85.
//!
//! # Las piezas
//!
//! | Modulo | Que hace |
//! |---|---|
//! | [`sistema`] | paquetes de dpkg y apk (via `aegis-vuln`), con los ficheros que un proceso puede tener cargados |
//! | [`binario`] | metadatos de compilacion incrustados (`cargo-auditable`, Go) y firmas de bibliotecas estaticas |
//! | [`aplicacion`] | `Cargo.lock`, `package-lock.json`, `requirements.txt`, paquetes de Python instalados |
//! | [`contenedor`] | imagenes capa a capa: `docker save`, layout OCI y `overlay2` |
//! | [`osv`], [`version`], [`correlacion`] | avisos OSV, el orden de versiones de cada ecosistema y el cruce |
//! | [`telemetria`], [`ruta`], [`alcance`] | las tres preguntas: cargado, alcanzable, expuesto |
//!
//! # Lo que NO hay aqui, a proposito
//!
//! **No hay ningun serializador.** El inventario de una maquina es el mapa que
//! un atacante querria antes de elegir por donde entrar: que version de que
//! biblioteca, en que proceso, escuchando en que puerto. Si este crate supiera
//! escribir CycloneDX o SPDX, cualquier codigo del agente podria sacarlo por
//! cualquier sitio. Los formatos de salida viven en el plano de control
//! (`aegis-postura`), detras del unico estrangulamiento de difusion del producto
//! —el juez TLP/PAP de `aegis-share`—, con el inventario marcado como
//! `TLP:AMBER+STRICT`. La invariante 12 comprueba que aqui no aparezca ninguno.
//!
//! # El arbitro
//!
//! Una vulnerabilidad es una EXPOSICION, no un compromiso: dice que algo se
//! podria atacar, no que se haya atacado. Como las exposiciones de la auditoria
//! de plataforma (FASE 92), no mueve el juicio del arbitro: va al informe de
//! postura. Mezclarla con las senales de compromiso haria que una maquina sin
//! parchear pareciera una maquina comprometida.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod alcance;
pub mod aplicacion;
pub mod binario;
pub mod componente;
pub mod contenedor;
pub mod correlacion;
pub mod inventario;
pub mod osv;
pub mod purl;
pub mod ruta;
pub mod sistema;
pub mod tar;
pub mod telemetria;
pub mod version;

pub use alcance::{Alcance, Evaluador, Tri};
pub use componente::{Componente, Ecosistema, Procedencia};
pub use inventario::{recoger, Opciones, Sbom};
pub use osv::Aviso;

/// Un componente vulnerable, con sus tres respuestas.
#[derive(Debug, Clone, PartialEq)]
pub struct Hallazgo {
    /// Indice del componente en el SBOM.
    pub componente: usize,
    /// Indice del aviso.
    pub aviso: usize,
    /// El fallo (su CVE si lo tiene).
    pub fallo: String,
    /// La version que lo corrige, si la hay.
    pub arreglada_en: Option<String>,
    /// La gravedad del aviso.
    pub gravedad: osv::Gravedad,
    /// Cargado, alcanzable, expuesto.
    pub alcance: Alcance,
}

/// Los hallazgos de una maquina, ordenados por lo que importan.
#[derive(Debug, Clone, Default)]
pub struct Informe {
    /// Los hallazgos, de mas a menos prioritario.
    pub hallazgos: Vec<Hallazgo>,
    /// Avisos que casaban por nombre y no se pudieron evaluar (rangos de
    /// commits).
    pub sin_evaluar: usize,
    /// Procesos leidos y no leidos al tomar la instantanea.
    pub procesos: (usize, usize),
}

impl Informe {
    /// Cuantos hallazgos estan cargados.
    #[must_use]
    pub fn cargados(&self) -> usize {
        self.hallazgos
            .iter()
            .filter(|h| h.alcance.cargado.es_si())
            .count()
    }

    /// Cuantos se pueden DESCARTAR con evidencia: alguna de las tres respuestas
    /// es un «No» comprobado.
    #[must_use]
    pub fn descartables(&self) -> usize {
        self.hallazgos
            .iter()
            .filter(|h| !h.alcance.no_descartable())
            .count()
    }
}

/// Cruza el inventario con los avisos y responde las tres preguntas para cada
/// componente vulnerable.
///
/// El orden es el de trabajo: primero lo cargado, alcanzable y expuesto; dentro
/// de la misma prioridad, lo mas grave.
#[must_use]
pub fn evaluar(sbom: &Sbom, avisos: &[Aviso], ev: &Evaluador<'_>) -> Informe {
    let r = correlacion::correlacionar(&sbom.componentes, avisos);
    let mut hallazgos: Vec<Hallazgo> = r
        .coincidencias
        .iter()
        .map(|c| {
            let aviso = &avisos[c.aviso];
            let simbolos = &aviso.afectados[c.afectado].simbolos;
            Hallazgo {
                componente: c.componente,
                aviso: c.aviso,
                fallo: c.fallo.clone(),
                arreglada_en: c.arreglada_en.clone(),
                gravedad: aviso.gravedad,
                alcance: ev.evaluar(&sbom.componentes[c.componente], simbolos),
            }
        })
        .collect();
    hallazgos.sort_by(|a, b| {
        b.alcance
            .prioridad()
            .cmp(&a.alcance.prioridad())
            .then(b.gravedad.peso().total_cmp(&a.gravedad.peso()))
            .then(a.fallo.cmp(&b.fallo))
    });
    Informe {
        hallazgos,
        sin_evaluar: r.sin_evaluar,
        procesos: ev.cobertura(),
    }
}
