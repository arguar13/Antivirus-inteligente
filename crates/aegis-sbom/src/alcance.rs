//! Las tres preguntas que separan una lista de CVE de una lista de trabajo.
//!
//! Para cada componente vulnerable:
//!
//! 1. **¿Esta CARGADO?** ¿Lo tiene proyectado en memoria algun proceso vivo?
//! 2. **¿Es ALCANZABLE la funcion vulnerable?** ¿Hay un camino de llamadas desde
//!    las raices del programa que lo carga hasta ella?
//! 3. **¿Esta EXPUESTO?** ¿Alguno de los procesos que lo cargan escucha en una
//!    direccion que no sea de bucle local?
//!
//! Cada respuesta es tri-estado, y la tercera opcion no es un adorno: sin datos
//! para responder se dice [`Tri::SinDatos`] con el motivo. **Nunca se asume
//! alcanzable ni inalcanzable.** Un «No» afirmado sin haberlo comprobado quita
//! del informe una vulnerabilidad real; un «Si» afirmado sin comprobarlo manda a
//! parchear con urgencia lo que puede esperar. Los dos errores cuestan, y el que
//! no se ve es el primero.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::componente::{Componente, Procedencia};
use crate::ruta::{analizar_elf, Grafo, Respuesta};
use crate::telemetria::{inodo_de, Procesos, Telemetria};

/// Una respuesta tri-estado con su porque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tri {
    /// Si, con la evidencia.
    Si(String),
    /// No, con lo que se comprobo.
    No(String),
    /// No se sabe, con el motivo.
    SinDatos(String),
}

impl Tri {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Tri::Si(_) => "si",
            Tri::No(_) => "no",
            Tri::SinDatos(_) => "sin-datos",
        }
    }

    /// El texto que la sostiene.
    #[must_use]
    pub fn porque(&self) -> &str {
        match self {
            Tri::Si(s) | Tri::No(s) | Tri::SinDatos(s) => s,
        }
    }

    /// Si es un si.
    #[must_use]
    pub fn es_si(&self) -> bool {
        matches!(self, Tri::Si(_))
    }

    /// Si es un no.
    #[must_use]
    pub fn es_no(&self) -> bool {
        matches!(self, Tri::No(_))
    }

    /// Peso para ordenar: si > sin datos > no.
    #[must_use]
    pub fn peso(&self) -> u8 {
        match self {
            Tri::Si(_) => 2,
            Tri::SinDatos(_) => 1,
            Tri::No(_) => 0,
        }
    }
}

/// Las tres respuestas de un componente vulnerable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alcance {
    /// ¿Lo carga algun proceso vivo?
    pub cargado: Tri,
    /// ¿Se llega a la funcion vulnerable?
    pub alcanzable: Tri,
    /// ¿Escucha en red algun proceso que lo carga?
    pub expuesto: Tri,
    /// Los procesos que lo cargan.
    pub procesos: Vec<u32>,
    /// Los ficheros por los que se vio cargado.
    pub ficheros: Vec<PathBuf>,
}

impl Alcance {
    /// La prioridad: la suma de los pesos de las tres respuestas. Seis es «cargado,
    /// alcanzable y expuesto»: eso va primero.
    #[must_use]
    pub fn prioridad(&self) -> u8 {
        self.cargado.peso() + self.alcanzable.peso() + self.expuesto.peso()
    }

    /// Si NINGUNA de las tres es un «No»: lo que no se puede descartar.
    #[must_use]
    pub fn no_descartable(&self) -> bool {
        !self.cargado.es_no() && !self.alcanzable.es_no() && !self.expuesto.es_no()
    }
}

/// Evalua la alcanzabilidad de componentes sobre una instantanea de la
/// telemetria.
///
/// La instantanea se toma UNA vez: evaluar cien componentes sobre cien lecturas
/// distintas de `/proc` daria respuestas de cien momentos distintos que no se
/// pueden comparar entre si.
pub struct Evaluador<'t> {
    telemetria: &'t dyn Telemetria,
    procesos: Procesos,
    grafos: RefCell<BTreeMap<PathBuf, Result<Grafo, String>>>,
    escuchas: RefCell<BTreeMap<u32, Result<Vec<crate::telemetria::Escucha>, String>>>,
}

/// Un fichero de un componente, resuelto en disco.
struct Resuelto {
    canonica: PathBuf,
    inodo: Option<u64>,
}

impl<'t> Evaluador<'t> {
    /// Toma la instantanea.
    #[must_use]
    pub fn nuevo(telemetria: &'t dyn Telemetria) -> Evaluador<'t> {
        Evaluador {
            procesos: telemetria.procesos(),
            telemetria,
            grafos: RefCell::new(BTreeMap::new()),
            escuchas: RefCell::new(BTreeMap::new()),
        }
    }

    /// Cuantos procesos se leyeron y cuantos no.
    #[must_use]
    pub fn cobertura(&self) -> (usize, usize) {
        (self.procesos.leidos.len(), self.procesos.no_leidos.len())
    }

    fn resolver(f: &Path) -> Resuelto {
        let canonica = std::fs::canonicalize(f).unwrap_or_else(|_| f.to_path_buf());
        Resuelto {
            inodo: inodo_de(&canonica),
            canonica,
        }
    }

    /// ¿Lo carga algun proceso?
    fn cargado(&self, c: &Componente) -> (Tri, Vec<u32>, Vec<PathBuf>) {
        if c.capa.is_some() {
            return (
                Tri::SinDatos(
                    "es un componente de una imagen de contenedor: se inventaria desde la imagen, \
                     y sus procesos vivos se miran por su propia raiz, no por esta"
                        .into(),
                ),
                Vec::new(),
                Vec::new(),
            );
        }
        if c.ficheros.is_empty() {
            match c.interpretado {
                // Se leyo su lista de ficheros y no hay codigo de ninguna clase:
                // datos, documentacion, configuracion. Ningun proceso puede
                // estar ejecutandolo, se hayan podido leer todos o no.
                Some(false) => {
                    return (
                        Tri::No(
                            "no contiene codigo: ni bibliotecas, ni ejecutables, ni codigo \
                             interpretado; ningun proceso lo puede estar ejecutando"
                                .into(),
                        ),
                        Vec::new(),
                        Vec::new(),
                    )
                }
                Some(true) => {
                    return (
                        Tri::SinDatos(
                            "solo trae codigo interpretado: un interprete lo lee, no lo \
                             proyecta, y eso no aparece en ningun mapa de memoria"
                                .into(),
                        ),
                        Vec::new(),
                        Vec::new(),
                    )
                }
                None => {}
            }
            let porque = match &c.procedencia {
                Procedencia::Manifiesto { .. } => {
                    "sale de un manifiesto, y un manifiesto no dice que fichero carga un proceso"
                }
                Procedencia::Instalado { .. } => {
                    "es un paquete de Python sin extensiones compiladas: el interprete lee su \
                     codigo, no lo proyecta, y eso no aparece en ningun mapa de memoria"
                }
                _ => "no se sabe que ficheros lo materializan en disco",
            };
            return (Tri::SinDatos(porque.into()), Vec::new(), Vec::new());
        }
        let resueltos: Vec<Resuelto> = c.ficheros.iter().map(|f| Self::resolver(f)).collect();
        let mut pids = Vec::new();
        let mut vistos: Vec<PathBuf> = Vec::new();
        let mut viejos: Vec<u32> = Vec::new();
        for p in &self.procesos.leidos {
            let mut lo_carga = false;
            for m in &p.mapas {
                for r in &resueltos {
                    let misma_ruta = m.ruta == r.canonica;
                    let mismo_inodo =
                        r.inodo == Some(m.inodo) && m.ruta.file_name() == r.canonica.file_name();
                    if misma_ruta && m.borrado {
                        // El proceso carga el fichero que HABIA en esa ruta, ya
                        // borrado: una version anterior a la instalada.
                        lo_carga = true;
                        viejos.push(p.pid);
                        if !vistos.contains(&m.ruta) {
                            vistos.push(m.ruta.clone());
                        }
                    } else if misma_ruta || mismo_inodo {
                        lo_carga = true;
                        if !vistos.contains(&m.ruta) {
                            vistos.push(m.ruta.clone());
                        }
                    }
                }
            }
            if lo_carga {
                pids.push(p.pid);
            }
        }
        if !pids.is_empty() {
            let muestra: Vec<String> = pids
                .iter()
                .take(5)
                .map(|pid| {
                    let exe = self
                        .procesos
                        .leidos
                        .iter()
                        .find(|p| p.pid == *pid)
                        .and_then(|p| p.exe.as_ref())
                        .map_or_else(|| "?".into(), |e| e.display().to_string());
                    format!("{pid} ({exe})")
                })
                .collect();
            let mut s = format!(
                "lo tienen proyectado {} proceso(s): {}{}",
                pids.len(),
                muestra.join(", "),
                if pids.len() > 5 { ", ..." } else { "" }
            );
            if !viejos.is_empty() {
                viejos.sort_unstable();
                viejos.dedup();
                s.push_str(&format!(
                    "; {} de ellos ejecutan el fichero ANTERIOR, ya borrado del disco: siguen \
                     con la version que habia antes de actualizar hasta que se reinicien",
                    viejos.len()
                ));
            }
            return (Tri::Si(s), pids, vistos);
        }
        if c.interpretado == Some(true) {
            return (
                Tri::SinDatos(format!(
                    "ningun proceso tiene proyectado ninguno de sus {} fichero(s) binarios, pero \
                     tambien trae codigo interpretado, que no aparece en los mapas de memoria \
                     aunque se este ejecutando",
                    c.ficheros.len()
                )),
                Vec::new(),
                Vec::new(),
            );
        }
        if !self.procesos.no_leidos.is_empty() {
            return (
                Tri::SinDatos(format!(
                    "ninguno de los {} procesos leidos lo carga, pero {} no se pudieron leer \
                     (sin privilegios): no se puede afirmar que ninguno lo cargue",
                    self.procesos.leidos.len(),
                    self.procesos.no_leidos.len()
                )),
                Vec::new(),
                Vec::new(),
            );
        }
        (
            Tri::No(format!(
                "ninguno de los {} procesos vivos tiene proyectado ninguno de sus {} fichero(s)",
                self.procesos.leidos.len(),
                c.ficheros.len()
            )),
            Vec::new(),
            Vec::new(),
        )
    }

    fn escuchas(&self, pid: u32) -> Result<Vec<crate::telemetria::Escucha>, String> {
        self.escuchas
            .borrow_mut()
            .entry(pid)
            .or_insert_with(|| self.telemetria.escuchas_de(pid))
            .clone()
    }

    /// ¿Escucha en red alguno de los procesos que lo cargan?
    fn expuesto(&self, cargado: &Tri, pids: &[u32]) -> Tri {
        match cargado {
            Tri::No(_) => {
                return Tri::No("no lo carga ningun proceso vivo: ningun servicio lo expone".into())
            }
            Tri::SinDatos(m) => return Tri::SinDatos(format!("no se sabe si esta cargado: {m}")),
            Tri::Si(_) => {}
        }
        let mut ilegibles = 0usize;
        let mut locales = Vec::new();
        for pid in pids {
            match self.escuchas(*pid) {
                Ok(v) => {
                    if let Some(e) = v.iter().find(|e| e.es_externa()) {
                        return Tri::Si(format!(
                            "el proceso {pid} escucha en {}:{}/{}",
                            e.ip, e.puerto, e.protocolo
                        ));
                    }
                    locales.extend(v.into_iter().map(|e| format!("{}:{}", e.ip, e.puerto)));
                }
                Err(_) => ilegibles += 1,
            }
        }
        if ilegibles > 0 {
            return Tri::SinDatos(format!(
                "no se pudieron leer los descriptores de {ilegibles} de los {} procesos que lo \
                 cargan",
                pids.len()
            ));
        }
        if locales.is_empty() {
            Tri::No(format!(
                "ninguno de los {} procesos que lo cargan escucha en red",
                pids.len()
            ))
        } else {
            locales.sort();
            locales.dedup();
            Tri::No(format!(
                "los procesos que lo cargan solo escuchan en bucle local ({})",
                locales.join(", ")
            ))
        }
    }

    fn grafo(&self, exe: &Path) -> Result<Grafo, String> {
        self.grafos
            .borrow_mut()
            .entry(exe.to_path_buf())
            .or_insert_with(|| analizar_elf(exe))
            .clone()
    }

    /// ¿Se llega a alguna de las funciones vulnerables?
    fn alcanzable(&self, c: &Componente, cargado: &Tri, pids: &[u32], simbolos: &[String]) -> Tri {
        // Lo primero, lo que no depende del aviso: si ningun proceso lo carga,
        // ninguna ejecucion llega a ninguna de sus funciones, diga el aviso cual
        // es o no.
        match cargado {
            Tri::No(_) => {
                return Tri::No(
                    "no lo carga ningun proceso vivo: ninguna ejecucion llega a su codigo".into(),
                )
            }
            Tri::SinDatos(m) => return Tri::SinDatos(format!("no se sabe si esta cargado: {m}")),
            Tri::Si(_) => {}
        }
        if simbolos.is_empty() {
            return Tri::SinDatos(
                "el aviso no dice que funcion es la vulnerable: sin eso, no hay ruta que buscar"
                    .into(),
            );
        }
        let propios: Vec<PathBuf> = c
            .ficheros
            .iter()
            .map(|f| std::fs::canonicalize(f).unwrap_or_else(|_| f.clone()))
            .collect();
        let mut noes: Vec<String> = Vec::new();
        let mut dudas: Vec<String> = Vec::new();
        for pid in pids {
            let Some(exe) = self
                .procesos
                .leidos
                .iter()
                .find(|p| p.pid == *pid)
                .and_then(|p| p.exe.clone())
            else {
                dudas.push(format!("no se pudo leer el ejecutable del proceso {pid}"));
                continue;
            };
            let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
            let grafo = match self.grafo(&exe) {
                Ok(g) => g,
                Err(e) => {
                    dudas.push(format!("{}: {e}", exe.display()));
                    continue;
                }
            };
            // Si el componente ES el ejecutable (una dependencia enlazada dentro),
            // la funcion es interna; si no, se importa de una biblioteca.
            let interno = propios.contains(&exe);
            // Funciones vulnerables que este ejecutable no importa: por cada una
            // puede haber un camino a traves de otra biblioteca cargada, y
            // mientras exista una, un «No» de las demas no basta.
            let mut sin_importar = 0usize;
            for s in simbolos {
                let r = if interno {
                    grafo.alcanza_interna(s)
                } else {
                    let corto = s.rsplit(['.', ':']).next().unwrap_or(s);
                    grafo.alcanza_importada(corto)
                };
                match r {
                    Respuesta::Si(ev) => {
                        return Tri::Si(format!("proceso {pid}, {}: {ev}", exe.display()))
                    }
                    Respuesta::No(ev) => noes.push(format!("proceso {pid}: {ev}")),
                    Respuesta::NoSe(m) => dudas.push(format!("proceso {pid}: {m}")),
                    Respuesta::NoEsDeEsteBinario => sin_importar += 1,
                }
            }
            if sin_importar > 0 {
                dudas.push(format!(
                    "{} no importa {sin_importar} de las {} funciones vulnerables: la llamada \
                     pasaria por otra biblioteca cargada, y el grafo entre modulos no se construye",
                    exe.display(),
                    simbolos.len()
                ));
            }
        }
        if dudas.is_empty() && !noes.is_empty() {
            Tri::No(noes.join("; "))
        } else {
            Tri::SinDatos(dudas.into_iter().take(3).collect::<Vec<_>>().join("; "))
        }
    }

    /// Las tres respuestas para un componente y las funciones vulnerables de su
    /// aviso.
    #[must_use]
    pub fn evaluar(&self, c: &Componente, simbolos: &[String]) -> Alcance {
        let (cargado, procesos, ficheros) = self.cargado(c);
        let expuesto = self.expuesto(&cargado, &procesos);
        let alcanzable = self.alcanzable(c, &cargado, &procesos, simbolos);
        Alcance {
            cargado,
            alcanzable,
            expuesto,
            procesos,
            ficheros,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::componente::Ecosistema;
    use crate::telemetria::{Escucha, Mapeado, ProcesoVivo, Simulada};

    fn comp(ficheros: &[&str]) -> Componente {
        let mut c = Componente::nuevo(
            Ecosistema::Deb,
            "libfalsa1",
            "1.0-1",
            Procedencia::GestorDePaquetes {
                base: "/var/lib/dpkg/status".into(),
            },
        );
        c.ficheros = ficheros.iter().map(PathBuf::from).collect();
        c
    }

    fn proceso(pid: u32, ruta: &str, borrado: bool) -> ProcesoVivo {
        ProcesoVivo {
            pid,
            exe: Some(PathBuf::from("/usr/sbin/servicio-que-no-existe")),
            mapas: vec![Mapeado {
                ruta: PathBuf::from(ruta),
                inodo: 424_242,
                borrado,
            }],
        }
    }

    const LIB: &str = "/opt/aegis-prueba-inexistente/libfalsa.so.1";

    #[test]
    fn cargado_y_expuesto_con_sus_evidencias() {
        let mut t = Simulada::default();
        t.procesos.leidos.push(proceso(10, LIB, false));
        t.escuchas.insert(
            10,
            vec![Escucha {
                protocolo: "tcp",
                ip: "0.0.0.0".parse().unwrap(),
                puerto: 8443,
            }],
        );
        let ev = Evaluador::nuevo(&t);
        let a = ev.evaluar(&comp(&[LIB]), &[]);
        assert!(a.cargado.es_si(), "{a:?}");
        assert_eq!(a.procesos, [10]);
        assert!(a.expuesto.porque().contains("0.0.0.0:8443/tcp"), "{a:?}");
        assert_eq!(
            a.alcanzable.nombre(),
            "sin-datos",
            "el aviso no dice la funcion"
        );
    }

    #[test]
    fn solo_en_bucle_local_no_esta_expuesto() {
        let mut t = Simulada::default();
        t.procesos.leidos.push(proceso(10, LIB, false));
        t.escuchas.insert(
            10,
            vec![Escucha {
                protocolo: "tcp",
                ip: "127.0.0.1".parse().unwrap(),
                puerto: 5432,
            }],
        );
        let a = Evaluador::nuevo(&t).evaluar(&comp(&[LIB]), &[]);
        assert!(a.expuesto.es_no());
        assert!(a.expuesto.porque().contains("127.0.0.1:5432"));
    }

    #[test]
    fn sin_poder_leer_los_descriptores_no_se_afirma_nada() {
        let mut t = Simulada::default();
        t.procesos.leidos.push(proceso(10, LIB, false));
        let a = Evaluador::nuevo(&t).evaluar(&comp(&[LIB]), &[]);
        assert_eq!(a.expuesto.nombre(), "sin-datos");
    }

    #[test]
    fn no_cargado_solo_si_se_pudieron_leer_todos_los_procesos() {
        let mut t = Simulada::default();
        t.procesos
            .leidos
            .push(proceso(10, "/usr/lib/otra.so", false));
        let a = Evaluador::nuevo(&t).evaluar(&comp(&[LIB]), &["f".into()]);
        assert!(a.cargado.es_no(), "{a:?}");
        assert!(a.expuesto.es_no());
        assert!(a.alcanzable.es_no(), "sin cargar, ninguna ejecucion llega");

        t.procesos.no_leidos.push((11, "permiso denegado".into()));
        let a = Evaluador::nuevo(&t).evaluar(&comp(&[LIB]), &["f".into()]);
        assert_eq!(a.cargado.nombre(), "sin-datos", "{a:?}");
        assert_eq!(a.alcanzable.nombre(), "sin-datos");
    }

    #[test]
    fn una_version_borrada_todavia_en_memoria_se_senala() {
        let mut t = Simulada::default();
        t.procesos.leidos.push(proceso(10, LIB, true));
        let a = Evaluador::nuevo(&t).evaluar(&comp(&[LIB]), &[]);
        assert!(a.cargado.es_si());
        assert!(a.cargado.porque().contains("ANTERIOR"), "{a:?}");
    }

    #[test]
    fn un_manifiesto_no_dice_que_esta_cargado() {
        let t = Simulada::default();
        let c = Componente::nuevo(
            Ecosistema::Npm,
            "lodash",
            "4.17.20",
            Procedencia::Manifiesto {
                fichero: "/app/package-lock.json".into(),
            },
        );
        let a = Evaluador::nuevo(&t).evaluar(&c, &[]);
        assert_eq!(a.cargado.nombre(), "sin-datos");
        assert!(a.no_descartable());
    }
}
