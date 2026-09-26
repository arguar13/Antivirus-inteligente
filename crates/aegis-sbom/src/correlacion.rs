//! Que componentes estan afectados por que avisos.
//!
//! # Las tres condiciones para casar
//!
//! 1. **El mismo ecosistema y, en los del sistema, la misma distribucion.** El
//!    `openssl 3.0.2-0ubuntu1.10` de Ubuntu 22.04 y el de Debian 12 son paquetes
//!    distintos con parches distintos; un aviso de uno no dice nada del otro.
//! 2. **El mismo nombre, en la forma que usa el aviso.** En Debian, Ubuntu y
//!    Alpine es el paquete FUENTE; en PyPI, el nombre normalizado.
//! 3. **La version dentro del rango**, con el comparador de su ecosistema.
//!
//! # Un fallo, una vez
//!
//! El mismo fallo llega con varios identificadores: `GHSA-...` y `PYSEC-...`
//! para el mismo `CVE-...`. Contarlo dos veces infla el informe y, peor, reparte
//! la atencion del operador entre dos filas que son una. Se agrupan por su
//! identificador CVE cuando lo hay.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::componente::{Componente, Distro, Ecosistema};
use crate::osv::{Afectado, Aviso, Evento, TipoRango};
use crate::purl::normalizar_pypi;
use crate::version::comparar;

/// Por que casa un componente con un aviso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// La version esta dentro de un rango.
    Rango,
    /// La version esta en la lista explicita de afectadas.
    Enumerada,
}

/// Un componente afectado por un aviso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coincidencia {
    /// Indice del componente.
    pub componente: usize,
    /// Indice del aviso.
    pub aviso: usize,
    /// Indice del paquete afectado dentro del aviso.
    pub afectado: usize,
    /// La primera version corregida posterior a la instalada, si la hay.
    pub arreglada_en: Option<String>,
    /// Por que casa.
    pub motivo: Motivo,
    /// La clave del fallo (su CVE si lo tiene), para no contarlo dos veces.
    pub fallo: String,
}

/// El resultado de correlacionar.
#[derive(Debug, Clone, Default)]
pub struct Correlacion {
    /// Las coincidencias.
    pub coincidencias: Vec<Coincidencia>,
    /// Avisos que casaban por nombre y solo traian rangos de commits: no se
    /// pudieron evaluar, y se cuentan.
    pub sin_evaluar: usize,
    /// Avisos retirados que se ignoraron.
    pub retirados: usize,
}

impl Correlacion {
    /// Cuantos fallos distintos hay, contando cada CVE una vez.
    #[must_use]
    pub fn fallos_distintos(&self) -> usize {
        self.coincidencias
            .iter()
            .map(|c| c.fallo.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

/// La clave de un fallo: su CVE si lo tiene (el menor, para que sea estable), si
/// no su identificador.
#[must_use]
pub fn clave_de_fallo(a: &Aviso) -> String {
    std::iter::once(&a.id)
        .chain(&a.alias)
        .filter(|x| x.starts_with("CVE-"))
        .min()
        .unwrap_or(&a.id)
        .clone()
}

/// El nombre con que un componente se busca en los avisos.
fn nombre_de_busqueda(c: &Componente) -> String {
    match c.ecosistema {
        Ecosistema::Deb | Ecosistema::Apk => c.nombre_fuente().to_string(),
        Ecosistema::PyPI => normalizar_pypi(&c.nombre),
        _ => c.nombre.clone(),
    }
}

/// La version con que un componente se compara.
fn version_de_busqueda(c: &Componente) -> &str {
    match c.ecosistema {
        Ecosistema::Deb | Ecosistema::Apk => c.version_de_fuente(),
        _ => &c.version,
    }
}

/// Si la distribucion del componente es la del aviso.
///
/// Alpine publica sus avisos por rama (`v3.19`) y la maquina dice su version
/// completa (`3.19.1`): casan por mayor y menor.
fn misma_distro(componente: Option<&Distro>, aviso: Option<&Distro>) -> bool {
    match (componente, aviso) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(a)) => {
            if c.id != a.id {
                return false;
            }
            if c.id == "alpine" {
                let rama = |v: &str| v.split('.').take(2).collect::<Vec<_>>().join(".");
                return rama(&c.version) == rama(&a.version);
            }
            c.version == a.version
        }
    }
}

/// Lo que del inventario puede casar con un aviso: para filtrar los avisos al
/// leerlos (ver [`crate::osv::aviso_filtrado`]).
///
/// Usa exactamente las reglas de [`correlacionar`] —ecosistema, distribucion y
/// nombre de busqueda—, de modo que lo que se descarta al leer es lo que nunca
/// habria casado. Una regla distinta aqui seria una vulnerabilidad perdida antes
/// de cruzar nada.
#[derive(Debug, Clone, Default)]
pub struct Interes {
    claves: BTreeMap<(Ecosistema, String), Vec<Option<Distro>>>,
}

impl Interes {
    /// El interes de un inventario.
    #[must_use]
    pub fn de(componentes: &[Componente]) -> Interes {
        let mut claves: BTreeMap<(Ecosistema, String), Vec<Option<Distro>>> = BTreeMap::new();
        for c in componentes {
            let d = claves
                .entry((c.ecosistema, nombre_de_busqueda(c)))
                .or_default();
            if !d.contains(&c.distro) {
                d.push(c.distro.clone());
            }
        }
        Interes { claves }
    }

    /// Si un paquete afectado de OSV puede casar con algo del inventario.
    #[must_use]
    pub fn quiere(&self, ecosistema_osv: &str, nombre: &str) -> bool {
        let Some((eco, distro)) = crate::osv::ecosistema_de(ecosistema_osv) else {
            return false;
        };
        let nombre = if eco == Ecosistema::PyPI {
            normalizar_pypi(nombre)
        } else {
            nombre.to_string()
        };
        self.claves
            .get(&(eco, nombre))
            .is_some_and(|ds| ds.iter().any(|d| misma_distro(d.as_ref(), distro.as_ref())))
    }
}

/// Evalua un rango de OSV sobre una version.
///
/// Es el algoritmo de la especificacion: los eventos se ordenan por version
/// (`"0"` es el minimo) y se aplican en orden los que no pasan de la version
/// instalada; el ultimo que aplica decide.
fn en_rango(eco: Ecosistema, version: &str, eventos: &[Evento]) -> bool {
    fn valor(e: &Evento) -> &str {
        match e {
            Evento::Introducida(v) | Evento::Arreglada(v) | Evento::UltimaAfectada(v) => v,
        }
    }
    let cmp = |a: &str, b: &str| -> Ordering {
        match (a == "0", b == "0") {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => comparar(eco, a, b),
        }
    };
    let mut evs: Vec<&Evento> = eventos.iter().collect();
    evs.sort_by(|a, b| cmp(valor(a), valor(b)));
    let mut afectada = false;
    for e in evs {
        match e {
            Evento::Introducida(v) => {
                if cmp(version, v) != Ordering::Less {
                    afectada = true;
                }
            }
            Evento::Arreglada(v) => {
                if cmp(version, v) != Ordering::Less {
                    afectada = false;
                }
            }
            Evento::UltimaAfectada(v) => {
                if cmp(version, v) == Ordering::Greater {
                    afectada = false;
                }
            }
        }
    }
    afectada
}

/// La primera version corregida posterior a la instalada.
fn arreglo(eco: Ecosistema, version: &str, af: &Afectado) -> Option<String> {
    af.rangos
        .iter()
        .flat_map(|r| &r.eventos)
        .filter_map(|e| match e {
            Evento::Arreglada(v) if comparar(eco, v, version) == Ordering::Greater => Some(v),
            _ => None,
        })
        .min_by(|a, b| comparar(eco, a, b))
        .cloned()
}

/// Cruza el inventario con los avisos.
#[must_use]
pub fn correlacionar(componentes: &[Componente], avisos: &[Aviso]) -> Correlacion {
    // Indice: (ecosistema, nombre) -> [(aviso, afectado, distro)].
    type Entrada = (usize, usize, Option<Distro>);
    let mut indice: BTreeMap<(Ecosistema, String), Vec<Entrada>> = BTreeMap::new();
    let mut r = Correlacion::default();
    for (i, a) in avisos.iter().enumerate() {
        if a.retirado {
            r.retirados += 1;
            continue;
        }
        for (j, af) in a.afectados.iter().enumerate() {
            let Some((eco, distro)) = crate::osv::ecosistema_de(&af.ecosistema_osv) else {
                continue;
            };
            let nombre = if eco == Ecosistema::PyPI {
                normalizar_pypi(&af.nombre)
            } else {
                af.nombre.clone()
            };
            indice
                .entry((eco, nombre))
                .or_default()
                .push((i, j, distro));
        }
    }
    let mut sin_evaluar: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (ci, c) in componentes.iter().enumerate() {
        let Some(candidatos) = indice.get(&(c.ecosistema, nombre_de_busqueda(c))) else {
            continue;
        };
        let version = version_de_busqueda(c);
        let mut vistos: BTreeSet<String> = BTreeSet::new();
        for (ai, afi, distro) in candidatos {
            if !misma_distro(c.distro.as_ref(), distro.as_ref()) {
                continue;
            }
            let aviso = &avisos[*ai];
            let af = &aviso.afectados[*afi];
            let fallo = clave_de_fallo(aviso);
            if vistos.contains(&fallo) {
                continue;
            }
            let motivo = if af.versiones.iter().any(|v| v == version) {
                Some(Motivo::Enumerada)
            } else if af
                .rangos
                .iter()
                .filter(|rg| rg.tipo != TipoRango::Git)
                .any(|rg| en_rango(c.ecosistema, version, &rg.eventos))
            {
                Some(Motivo::Rango)
            } else {
                if af.versiones.is_empty() && af.rangos.iter().all(|rg| rg.tipo == TipoRango::Git) {
                    sin_evaluar.insert((ci, *ai));
                }
                None
            };
            if let Some(motivo) = motivo {
                vistos.insert(fallo.clone());
                r.coincidencias.push(Coincidencia {
                    componente: ci,
                    aviso: *ai,
                    afectado: *afi,
                    arreglada_en: arreglo(c.ecosistema, version, af),
                    motivo,
                    fallo,
                });
            }
        }
    }
    r.sin_evaluar = sin_evaluar.len();
    r
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::componente::Procedencia;
    use crate::osv::documento;

    fn deb(nombre: &str, fuente: &str, version: &str, distro: (&str, &str)) -> Componente {
        let mut c = Componente::nuevo(
            Ecosistema::Deb,
            nombre,
            version,
            Procedencia::GestorDePaquetes {
                base: "/var/lib/dpkg/status".into(),
            },
        );
        c.fuente = Some(fuente.into());
        c.distro = Some(Distro {
            id: distro.0.into(),
            version: distro.1.into(),
        });
        c
    }

    const UBUNTU: &str = r#"[{
      "id":"UBUNTU-CVE-2024-5535","aliases":["CVE-2024-5535"],
      "affected":[
        {"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.2"}]}]},
        {"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"openssl"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.2-0ubuntu1.16"}]}]}
      ]},
      {"id":"USN-6937-1","aliases":["CVE-2024-5535"],
       "affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.2"}]}]}]}]"#;

    #[test]
    fn casa_por_fuente_y_distribucion_y_cuenta_el_fallo_una_vez() {
        let avisos = documento(UBUNTU);
        let comps = vec![
            deb(
                "libssl3t64",
                "openssl",
                "3.0.13-0ubuntu3.1",
                ("ubuntu", "24.04"),
            ),
            // Ya corregido.
            deb(
                "libssl3t64",
                "openssl",
                "3.0.13-0ubuntu3.4",
                ("ubuntu", "24.04"),
            ),
            // Otra distribucion para la que el aviso no dice esa version.
            deb("libssl3", "openssl", "3.0.13-0ubuntu3.1", ("debian", "12")),
        ];
        let r = correlacionar(&comps, &avisos);
        assert_eq!(r.coincidencias.len(), 1, "{:?}", r.coincidencias);
        let c = &r.coincidencias[0];
        assert_eq!(c.componente, 0);
        assert_eq!(c.fallo, "CVE-2024-5535");
        assert_eq!(c.arreglada_en.as_deref(), Some("3.0.13-0ubuntu3.2"));
        assert_eq!(
            r.fallos_distintos(),
            1,
            "UBUNTU-CVE y USN son el mismo fallo"
        );
    }

    #[test]
    fn last_affected_y_versiones_enumeradas() {
        let ev = [
            Evento::Introducida("1.0.0".into()),
            Evento::UltimaAfectada("1.2.0".into()),
        ];
        assert!(en_rango(Ecosistema::Cargo, "1.2.0", &ev));
        assert!(!en_rango(Ecosistema::Cargo, "1.2.1", &ev));
        assert!(!en_rango(Ecosistema::Cargo, "0.9.0", &ev));
        // Dos tramos: [1.0, 1.1) y [2.0, 2.3).
        let ev = [
            Evento::Introducida("2.0.0".into()),
            Evento::Arreglada("1.1.0".into()),
            Evento::Introducida("1.0.0".into()),
            Evento::Arreglada("2.3.0".into()),
        ];
        assert!(en_rango(Ecosistema::Npm, "1.0.5", &ev));
        assert!(!en_rango(Ecosistema::Npm, "1.5.0", &ev));
        assert!(en_rango(Ecosistema::Npm, "2.2.9", &ev));
        assert!(!en_rango(Ecosistema::Npm, "2.3.0", &ev));
    }

    #[test]
    fn pypi_casa_por_nombre_normalizado_y_alpine_por_rama() {
        let avisos = documento(
            r#"[{"id":"PYSEC-1","aliases":["CVE-1"],"affected":[{"package":{"ecosystem":"PyPI","name":"Jaraco_Functools"},"versions":["4.1.0"]}]},
                {"id":"ALPINE-1","affected":[{"package":{"ecosystem":"Alpine:v3.19","name":"openssl"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.4-r6"}]}]}]}]"#,
        );
        let py = Componente::nuevo(
            Ecosistema::PyPI,
            "jaraco.functools",
            "4.1.0",
            Procedencia::Instalado {
                fichero: "x".into(),
            },
        );
        let mut apk = Componente::nuevo(
            Ecosistema::Apk,
            "libcrypto3",
            "3.1.4-r5",
            Procedencia::GestorDePaquetes { base: "x".into() },
        );
        apk.fuente = Some("openssl".into());
        apk.distro = Some(Distro {
            id: "alpine".into(),
            version: "3.19.1".into(),
        });
        let r = correlacionar(&[py, apk], &avisos);
        assert_eq!(r.coincidencias.len(), 2);
        assert_eq!(r.coincidencias[0].motivo, Motivo::Enumerada);
    }

    #[test]
    fn solo_rangos_de_commits_se_cuenta_como_no_evaluado() {
        let avisos = documento(
            r#"{"id":"OSV-1","affected":[{"package":{"ecosystem":"crates.io","name":"foo"},
                "ranges":[{"type":"GIT","events":[{"introduced":"abc"}]}]}]}"#,
        );
        let c = Componente::nuevo(
            Ecosistema::Cargo,
            "foo",
            "1.0.0",
            Procedencia::Manifiesto {
                fichero: "x".into(),
            },
        );
        let r = correlacionar(&[c], &avisos);
        assert!(r.coincidencias.is_empty());
        assert_eq!(r.sin_evaluar, 1);
    }

    #[test]
    fn filtrar_al_leer_no_pierde_nada_de_lo_que_casaria() {
        // La misma correlacion, con los avisos filtrados al leer y sin filtrar:
        // tiene que dar exactamente las mismas coincidencias.
        let comps = vec![
            deb(
                "libssl3t64",
                "openssl",
                "3.0.13-0ubuntu3.1",
                ("ubuntu", "24.04"),
            ),
            deb("zlib1g", "zlib", "1:1.3", ("ubuntu", "24.04")),
        ];
        let interes = Interes::de(&comps);
        let v: serde_json::Value = serde_json::from_str(UBUNTU).unwrap();
        let filtrados: Vec<Aviso> = v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| crate::osv::aviso_filtrado(a, &|e, n| interes.quiere(e, n)))
            .collect();
        // El afectado de 22.04 no interesa y no se leyo.
        assert_eq!(filtrados[0].afectados.len(), 1);
        let a = correlacionar(&comps, &documento(UBUNTU));
        let b = correlacionar(&comps, &filtrados);
        assert_eq!(a.fallos_distintos(), b.fallos_distintos());
        assert_eq!(a.coincidencias.len(), b.coincidencias.len());
        assert!(!interes.quiere("Ubuntu:22.04:LTS", "openssl"));
        assert!(!interes.quiere("Ubuntu:24.04:LTS", "curl"));
        assert!(interes.quiere("Ubuntu:24.04:LTS", "zlib"));
    }

    #[test]
    fn un_aviso_retirado_no_casa() {
        let avisos = documento(
            r#"{"id":"OSV-2","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}"#,
        );
        let c = Componente::nuevo(
            Ecosistema::Npm,
            "a",
            "1.0.0",
            Procedencia::Manifiesto {
                fichero: "x".into(),
            },
        );
        let r = correlacionar(&[c], &avisos);
        assert!(r.coincidencias.is_empty());
        assert_eq!(r.retirados, 1);
    }
}
