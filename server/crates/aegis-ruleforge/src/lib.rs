//! # aegis-ruleforge
//!
//! La fabrica de contenido: convierte el corpus publico de deteccion del mundo
//! —Suricata, Sigma, ClamAV, YARA— en un artefacto firmado que el agente puede
//! consumir sin cargarselo entero en memoria.
//!
//! ## Las cuatro invariantes que gobiernan todo lo de aqui
//!
//! **1. Lo que entra lo escribe alguien que no somos nosotros.** Emerging
//! Threats, el catalogo Sigma, las bases de ClamAV, colecciones de YARA de
//! terceros: contenido que no controlamos y que, si un feed se compromete, lo
//! escribe directamente el atacante. Por eso los analizadores son **propios**
//! ([`suricata`], [`sigma`], [`clamav`], [`yara_feed`], [`yaml`]) y no genericos:
//! un analizador de proposito general en ese camino es codigo no auditado
//! procesando entrada hostil con los permisos del defensor.
//!
//! **2. Lo que no se entiende se rechaza CON NOMBRE.** Ningun analizador acepta
//! de todo. Cada rechazo va al [`Informe`] con su codigo y su explicacion, y de
//! ahi sale la [`Informe::cobertura`]: cuantas reglas de cuantas se compilaron.
//! Un analizador permisivo no puede dar esa cifra, y sin esa cifra nadie sabe que
//! se esta perdiendo.
//!
//! **3. Lo que se distribuye no puede tumbar al cliente.** Dos puertas distintas:
//! [`regex_segura`] rechaza expresiones con retroceso catastrofico —que serian
//! una denegacion de servicio contra el propio producto, firmada por nosotros— y
//! [`canario`] rechaza el corpus entero si alguna firma dispara sobre software
//! legitimo.
//!
//! **4. Lo que llega al agente tiene que caber en el agente.** El [`indice`] vive
//! en disco con busqueda binaria por `seek`, y su residencia la fija el
//! presupuesto del host, no una constante.
//!
//! ## La tuberia
//!
//! ```text
//!   feeds ──▶ analizadores ──▶ informe ──▶ canario ──▶ indice ──▶ manifiesto
//!            (propios)       (cobertura)  (BLOQUEA)  (en disco)  (firmado)
//! ```
//!
//! [`Fabrica`] es esa tuberia entera. Cada etapa se puede usar suelta, pero el
//! orden no es negociable y por eso hay una fachada: saltarse el canario no es
//! una opcion de configuracion, es que [`corpus::preparar`] no construye
//! manifiesto sin su veredicto.
//!
//! ## Lo que este crate NO hace, declarado
//!
//! - **No ejecuta reglas.** Compila YARA a texto ordenado por dependencias, no a
//!   bytecode; evaluar Sigma contra eventos y YARA contra ficheros es de los
//!   motores, que viven en el agente.
//! - **No firma.** [`corpus::preparar`] deja los bytes exactos que hay que
//!   firmar; la clave privada vive en el firmador del plano de control.
//! - **No descarga.** De donde salen los ficheros del feed es del canal de
//!   actualizaciones, que ya tiene su propia autenticacion.
//!
//! ## Ejemplo
//!
//! ```
//! use aegis_ruleforge::{clamav::Formato, Fabrica, Fuente};
//!
//! let mut fabrica = Fabrica::nueva();
//! fabrica.ingerir(Fuente::ClamAv {
//!     nombre: "prueba.ndb",
//!     formato: Formato::Cuerpo,
//!     contenido: "Prueba.Demo:0:*:4d5a90000300000004000000ffff0000",
//! });
//!
//! // La cobertura es un hecho medido, no una aspiracion.
//! let (compilado, informe) = fabrica.cerrar();
//! assert_eq!(compilado.firmas.len(), 1);
//! assert_eq!(informe.compiladas, 1);
//! assert_eq!(informe.rechazadas(), 0);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod canario;
pub mod clamav;
pub mod corpus;
pub mod indice;
pub mod informe;
pub mod presupuesto;
pub mod regex_segura;
pub mod sigma;
pub mod suricata;
pub mod yaml;
pub mod yara_feed;

use aegis_sync::Ioc;

pub use canario::{Canario, Veredicto};
pub use clamav::Firma;
pub use corpus::{Corpus, Manifiesto};
pub use indice::{Clase, Entrada, Indice};
pub use informe::{Informe, Rechazo};
pub use presupuesto::Presupuesto;
pub use sigma::ReglaSigma;
pub use yara_feed::ReglaYara;

/// Un fichero de feed por compilar.
#[derive(Debug, Clone, Copy)]
pub enum Fuente<'a> {
    /// Reglas de Suricata o Snort (`.rules`).
    Suricata {
        /// Nombre del fichero, para el informe.
        nombre: &'a str,
        /// Contenido.
        contenido: &'a str,
    },
    /// Reglas Sigma (YAML). Cada documento es una regla.
    Sigma {
        /// Nombre del fichero.
        nombre: &'a str,
        /// Documentos YAML.
        documentos: &'a [&'a str],
    },
    /// Firmas de ClamAV.
    ClamAv {
        /// Nombre del fichero.
        nombre: &'a str,
        /// Formato, que decide como se leen los campos.
        formato: clamav::Formato,
        /// Contenido.
        contenido: &'a str,
    },
    /// Reglas YARA.
    Yara {
        /// Nombre del fichero.
        nombre: &'a str,
        /// Contenido.
        contenido: &'a str,
    },
}

impl Fuente<'_> {
    /// Nombre del fichero de origen.
    #[must_use]
    pub fn nombre(&self) -> &str {
        match self {
            Fuente::Suricata { nombre, .. }
            | Fuente::Sigma { nombre, .. }
            | Fuente::ClamAv { nombre, .. }
            | Fuente::Yara { nombre, .. } => nombre,
        }
    }
}

/// Lo que una compilacion produce.
#[derive(Debug, Default)]
pub struct Compilado {
    /// Reglas de red listas para el motor de prevencion.
    pub red: Vec<aegis_ips::Regla>,
    /// Reglas Sigma sobre eventos.
    pub eventos: Vec<ReglaSigma>,
    /// Firmas de ClamAV.
    pub firmas: Vec<Firma>,
    /// Reglas YARA, ordenadas por dependencias.
    pub yara: yara_feed::Coleccion,
}

impl Compilado {
    /// Cuantos artefactos hay en total.
    #[must_use]
    pub fn len(&self) -> usize {
        self.red.len() + self.eventos.len() + self.firmas.len() + self.yara.reglas.len()
    }

    /// Si no hay ninguno.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Indicadores que se pueden sincronizar por arbol de Merkle.
    ///
    /// Solo los hashes SHA-256: son los unicos que tienen identidad estable
    /// entre versiones del corpus, que es lo que la reconciliacion necesita.
    #[must_use]
    pub fn indicadores(&self) -> Vec<Ioc> {
        self.firmas.iter().filter_map(Firma::como_ioc).collect()
    }

    /// Entradas para el indice en disco.
    #[must_use]
    pub fn entradas(&self) -> Vec<Entrada> {
        let mut v = Vec::with_capacity(self.len());
        for f in &self.firmas {
            let (clase, clave) = match f {
                Firma::HashFichero { hash, .. } => (
                    Clase::HashFichero,
                    indice::clave_de_hex(hash).unwrap_or_else(|| indice::clave_de_nombre(hash)),
                ),
                Firma::HashSeccion { hash, .. } => (
                    Clase::HashSeccion,
                    indice::clave_de_hex(hash).unwrap_or_else(|| indice::clave_de_nombre(hash)),
                ),
                Firma::Cuerpo { nombre, .. } => (Clase::Cuerpo, indice::clave_de_nombre(nombre)),
                Firma::Logica { nombre, .. } => (Clase::Logica, indice::clave_de_nombre(nombre)),
            };
            v.push(Entrada {
                clave,
                clase,
                datos: f.nombre().as_bytes().to_vec(),
            });
        }
        for r in &self.red {
            v.push(Entrada {
                clave: indice::clave_de_nombre(&r.nombre),
                clase: Clase::Red,
                datos: r.nombre.as_bytes().to_vec(),
            });
        }
        for r in &self.eventos {
            v.push(Entrada {
                clave: indice::clave_de_nombre(&r.titulo),
                clase: Clase::Evento,
                datos: r.titulo.as_bytes().to_vec(),
            });
        }
        v
    }
}

/// La tuberia entera: ingesta, compilacion, informe y puerta de canario.
#[derive(Debug)]
pub struct Fabrica {
    presupuesto: Presupuesto,
    compilado: Compilado,
    informe: Informe,
    fuentes_yara: Vec<(String, String)>,
}

impl Default for Fabrica {
    fn default() -> Fabrica {
        Fabrica::nueva()
    }
}

impl Fabrica {
    /// Una fabrica con el presupuesto por omision.
    #[must_use]
    pub fn nueva() -> Fabrica {
        Fabrica::con_presupuesto(Presupuesto::default())
    }

    /// Una fabrica con un presupuesto explicito.
    #[must_use]
    pub fn con_presupuesto(presupuesto: Presupuesto) -> Fabrica {
        Fabrica {
            presupuesto,
            compilado: Compilado::default(),
            informe: Informe::default(),
            fuentes_yara: Vec::new(),
        }
    }

    /// El informe acumulado de todo lo ingerido hasta ahora.
    #[must_use]
    pub fn informe(&self) -> &Informe {
        &self.informe
    }

    /// El presupuesto con el que compila.
    #[must_use]
    pub fn presupuesto(&self) -> &Presupuesto {
        &self.presupuesto
    }

    /// Compila una fuente y la acumula.
    ///
    /// No devuelve error: un feed que no se puede compilar **no** detiene a los
    /// demas. Lo que pasa con el queda en el informe, con nombre y motivo, y esa
    /// es la diferencia entre perder un feed sabiendolo y perderlo en silencio.
    pub fn ingerir(&mut self, fuente: Fuente<'_>) {
        match fuente {
            Fuente::Suricata { contenido, .. } => {
                let (reglas, informe) = suricata::compilar(contenido, &self.presupuesto);
                self.compilado.red.extend(reglas);
                self.informe.fundir(informe);
            }
            Fuente::Sigma { documentos, .. } => {
                let (reglas, informe) = sigma::compilar(documentos, &self.presupuesto);
                self.compilado.eventos.extend(reglas);
                self.informe.fundir(informe);
            }
            Fuente::ClamAv {
                contenido, formato, ..
            } => {
                let (firmas, informe) = clamav::leer_fichero(contenido, formato, &self.presupuesto);
                self.compilado.firmas.extend(firmas);
                self.informe.fundir(informe);
            }
            Fuente::Yara { nombre, contenido } => {
                // YARA se acumula y se reune al cerrar: el orden por dependencias
                // solo se puede calcular con TODAS las fuentes delante, porque una
                // regla puede referirse a otra de un fichero que aun no ha
                // llegado.
                self.fuentes_yara
                    .push((nombre.to_string(), contenido.to_string()));
            }
        }
    }

    /// Cierra la ingesta y devuelve lo compilado.
    ///
    /// Es aqui donde se reunen las reglas YARA, porque hasta que no estan todas
    /// no se puede ordenar por dependencias.
    #[must_use]
    pub fn cerrar(mut self) -> (Compilado, Informe) {
        if !self.fuentes_yara.is_empty() {
            let prestadas: Vec<(&str, &str)> = self
                .fuentes_yara
                .iter()
                .map(|(n, c)| (n.as_str(), c.as_str()))
                .collect();
            let (coleccion, informe) = yara_feed::reunir(&prestadas, &self.presupuesto);
            self.compilado.yara = coleccion;
            self.informe.fundir(informe);
        }
        (self.compilado, self.informe)
    }
}

/// Error de la compilacion de un corpus completo.
#[derive(Debug, thiserror::Error)]
pub enum ErrorFabrica {
    /// El canario no dio el visto bueno.
    #[error("{0}")]
    Canario(#[from] corpus::ErrorCorpus),
    /// No se pudo escribir el indice.
    #[error("{0}")]
    Indice(#[from] indice::ErrorIndice),
}

/// Compila un corpus entero: deja el indice en disco y el manifiesto por firmar.
///
/// El orden es el que es a proposito: **el canario antes que el indice**. Si el
/// canario bloquea no queda un artefacto escrito esperando a que alguien se
/// acuerde de mirar el veredicto; no queda nada.
///
/// # Errores
/// [`ErrorFabrica::Canario`] si el corpus dispara sobre software legitimo;
/// [`ErrorFabrica::Indice`] si el indice no se puede escribir.
pub fn compilar_corpus(
    compilado: &Compilado,
    canario: &Canario,
    ruta_indice: &std::path::Path,
    epoca: u64,
    generado_ns: u64,
) -> Result<(Manifiesto, Veredicto), ErrorFabrica> {
    let veredicto = canario.evaluar(&compilado.firmas);
    if !veredicto.aprobado() {
        return Err(ErrorFabrica::Canario(
            corpus::ErrorCorpus::CanarioNoAprobado {
                rechazadas: veredicto.firmas_rechazadas().len() as u64,
                muestras: veredicto.muestras as u64,
            },
        ));
    }

    let escritas = indice::construir(ruta_indice, compilado.entradas())?;
    let bytes = std::fs::read(ruta_indice).map_err(|e| {
        ErrorFabrica::Indice(indice::ErrorIndice::Disco {
            ruta: ruta_indice.display().to_string(),
            detalle: e.to_string(),
        })
    })?;

    let manifiesto = corpus::preparar(
        epoca,
        generado_ns,
        &bytes,
        escritas as u64,
        &compilado.indicadores(),
        &veredicto,
    )?;
    Ok((manifiesto, veredicto))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_fabrica_acumula_el_informe_de_todas_las_fuentes() {
        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::ClamAv {
            nombre: "a.ndb",
            formato: clamav::Formato::Cuerpo,
            contenido: "Buena.Uno:0:*:4d5a90000300000004000000ffff0000\n\
                        # comentario\n\
                        linea-rota-sin-campos\n",
        });
        let (compilado, informe) = f.cerrar();
        assert_eq!(compilado.firmas.len(), 1);
        assert_eq!(informe.compiladas, 1);
        assert_eq!(informe.rechazadas(), 1);
        // La cobertura es un hecho: una de dos.
        assert!(
            (informe.cobertura() - 0.5).abs() < 1e-9,
            "{}",
            informe.resumen()
        );
    }

    #[test]
    fn un_feed_roto_no_se_lleva_por_delante_a_los_demas() {
        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::Suricata {
            nombre: "roto.rules",
            contenido: "esto no es una regla de suricata ni de lejos",
        });
        f.ingerir(Fuente::ClamAv {
            nombre: "bueno.ndb",
            formato: clamav::Formato::Cuerpo,
            contenido: "Buena.Uno:0:*:4d5a90000300000004000000ffff0000",
        });
        let (compilado, informe) = f.cerrar();
        assert_eq!(compilado.firmas.len(), 1, "el feed bueno sobrevive");
        assert!(
            informe.rechazadas() >= 1,
            "y el roto queda anotado con nombre"
        );
    }

    #[test]
    fn las_reglas_yara_se_reunen_al_cerrar_y_no_antes() {
        // El orden por dependencias solo se puede calcular con todas las fuentes
        // delante: una regla puede referirse a otra de un fichero posterior.
        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::Yara {
            nombre: "b.yar",
            contenido: "rule Segunda { condition: Primera }",
        });
        f.ingerir(Fuente::Yara {
            nombre: "a.yar",
            contenido: "rule Primera { condition: true }",
        });
        let (compilado, _) = f.cerrar();
        let nombres: Vec<&str> = compilado
            .yara
            .reglas
            .iter()
            .map(|r| r.nombre.as_str())
            .collect();
        assert_eq!(nombres, vec!["Primera", "Segunda"], "dependencia primero");
    }

    #[test]
    fn solo_los_hashes_sha256_se_promueven_a_indicador() {
        // Un MD5 no tiene identidad estable para reconciliar por Merkle, y
        // meterlo haria que dos corpus iguales parecieran distintos.
        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::ClamAv {
            nombre: "h.hsb",
            formato: clamav::Formato::HashFichero,
            contenido: &format!("{}:1024:Prueba.Sha", "ab".repeat(32)),
        });
        f.ingerir(Fuente::ClamAv {
            nombre: "m.hdb",
            formato: clamav::Formato::HashFichero,
            contenido: &format!("{}:1024:Prueba.Md5", "cd".repeat(16)),
        });
        let (compilado, informe) = f.cerrar();
        assert_eq!(
            compilado.firmas.len(),
            2,
            "las dos firmas se conservan: {}",
            informe.resumen()
        );
        assert_eq!(
            compilado.indicadores().len(),
            1,
            "solo el SHA-256 es indicador"
        );
    }

    #[test]
    fn sin_canario_limpio_no_hay_indice_ni_manifiesto() {
        // LA PUERTA. No se escribe un artefacto y se deja el veredicto al lado
        // esperando a que alguien lo mire: si el canario bloquea, no hay nada.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");

        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::ClamAv {
            nombre: "malo.ndb",
            // Cuatro bytes: dispara sobre cualquier binario grande.
            contenido: "Mala.Corta:0:*:deadbeef",
            formato: clamav::Formato::Cuerpo,
        });
        let (compilado, _) = f.cerrar();

        let mut canario = Canario::vacio();
        canario.anadir("legitimo.bin", vec![0x41; 4096]);

        let r = compilar_corpus(&compilado, &canario, &ruta, 1, 0);
        assert!(matches!(r, Err(ErrorFabrica::Canario(_))), "{r:?}");
        assert!(!ruta.exists(), "no puede quedar un indice escrito");
    }

    #[test]
    fn la_tuberia_entera_produce_un_manifiesto_consistente() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");

        let mut f = Fabrica::nueva();
        f.ingerir(Fuente::ClamAv {
            nombre: "b.ndb",
            formato: clamav::Formato::Cuerpo,
            contenido: "Buena.Uno:0:*:4d5a90000300000004000000ffff0000\n\
                        Buena.Dos:0:*:504b0304140000000800abcdef0123456789",
        });
        let (compilado, informe) = f.cerrar();
        assert_eq!(informe.rechazadas(), 0, "{}", informe.resumen());

        let mut canario = Canario::vacio();
        canario.anadir("legitimo.bin", b"nada que ver con esas firmas".to_vec());

        let (manifiesto, veredicto) =
            compilar_corpus(&compilado, &canario, &ruta, 7, 1_700_000_000_000_000_000).unwrap();

        assert!(veredicto.aprobado());
        assert_eq!(manifiesto.epoca, 7);
        assert_eq!(manifiesto.entradas, 2);
        assert!(manifiesto.canario.aprobado());

        // Y el manifiesto se compromete con el indice que de verdad esta en disco.
        let bytes = std::fs::read(&ruta).unwrap();
        assert_eq!(manifiesto.sha256_indice, corpus::sha256(&bytes));

        // Que ademas se puede abrir y consultar.
        let idx = Indice::abrir(&ruta).unwrap();
        assert_eq!(idx.len(), 2);
    }
}
