//! La lista de procesos por tres caminos, y lo que su desacuerdo demuestra.
//!
//! # Por que tres caminos y no uno bueno
//!
//! Un rootkit que oculta un proceso no borra el proceso: lo **desengancha de la
//! lista** que las herramientas recorren. En Linux, quitar un `task_struct` de
//! `init_task.tasks` lo hace invisible para `ps`, para `/proc` y para cualquier
//! cosa que recorra esa lista — y el proceso sigue ejecutandose, porque el
//! planificador no usa esa lista para planificar.
//!
//! Esa es la clave, y es la razon de que esto funcione: **el nucleo mantiene la
//! misma informacion en varias estructuras que sirven para cosas distintas**, y
//! un rootkit que quiera ser invisible tiene que desengancharla de todas. Cada
//! una que olvide es una via por la que aparece.
//!
//! Los tres caminos:
//!
//! 1. **La lista enlazada de tareas.** Es lo que recorre `ps`, y por eso es lo
//!    primero que un rootkit desengancha.
//! 2. **El arbol de identificadores de proceso.** El nucleo lo necesita para
//!    resolver un PID a su tarea —`kill(pid)` pasa por ahi—, asi que un proceso
//!    desenganchado de aqui deja de poder recibir senales.
//! 3. **El barrido de memoria.** Buscar en el volcado las estructuras por su
//!    forma, sin seguir ningun enlace. Es el mas lento y el mas caro en falsos
//!    positivos, y es el unico que un rootkit **no puede** evitar sin destruir la
//!    estructura que necesita para seguir corriendo.
//!
//! # La vista cruzada, que es el producto de este modulo
//!
//! Ninguna de las tres listas es «la buena». Lo que dice algo es **el
//! desacuerdo**: un proceso que sale por el barrido y no por la lista enlazada es
//! un proceso oculto, y no hay otra explicacion benigna que no sea una carrera
//! —que se distingue porque una carrera aparece y desaparece, y una ocultacion
//! se repite.
//!
//! # Lo que este modulo NO hace
//!
//! No reconstruye las estructuras del nucleo a partir de sus desplazamientos
//! reales. Eso depende de la version exacta del nucleo y de como se compilo, y
//! hacerlo a medias produce listas de procesos **inventadas**, que es peor que no
//! tener ninguna. Aqui se define el modelo y la vista cruzada, y el perfilado que
//! rellena los desplazamientos se declara como lo que es: ver
//! [`Perfil`].

use std::collections::{BTreeMap, BTreeSet};

/// Por que camino se encontro un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Camino {
    /// Recorriendo la lista enlazada de tareas.
    ///
    /// Es lo que hace `ps`, y por eso es lo primero que un rootkit desengancha.
    ListaEnlazada,
    /// Recorriendo el arbol de identificadores de proceso.
    ///
    /// El nucleo lo necesita para resolver un PID a su tarea, asi que un proceso
    /// que se desenganche de aqui deja de poder recibir senales.
    ArbolDePid,
    /// Barriendo la memoria en busca de estructuras por su forma.
    ///
    /// El unico que un rootkit no puede evitar sin destruir la estructura que
    /// necesita para seguir corriendo.
    BarridoDeMemoria,
}

impl Camino {
    /// Los tres, para recorrerlos.
    pub fn todos() -> [Camino; 3] {
        [
            Camino::ListaEnlazada,
            Camino::ArbolDePid,
            Camino::BarridoDeMemoria,
        ]
    }

    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Camino::ListaEnlazada => "la lista enlazada de tareas",
            Camino::ArbolDePid => "el arbol de identificadores de proceso",
            Camino::BarridoDeMemoria => "el barrido de memoria",
        }
    }

    /// Por que un proceso que falta en este camino significa algo.
    pub fn porque_importa_su_ausencia(&self) -> &'static str {
        match self {
            Camino::ListaEnlazada => {
                "es la lista que recorre `ps`, y desengancharse de ella es exactamente \
                 como se oculta un proceso: el planificador no la usa para planificar, \
                 asi que el proceso sigue corriendo mientras desaparece de las \
                 herramientas"
            }
            Camino::ArbolDePid => {
                "el nucleo resuelve un PID a su tarea por este arbol, asi que un \
                 proceso que falte aqui no puede recibir senales — y un rootkit que lo \
                 desenganche rompe su propio proceso, que es por lo que casi ninguno lo \
                 hace"
            }
            Camino::BarridoDeMemoria => {
                "la estructura esta en memoria porque el proceso la necesita para \
                 correr: faltar en el barrido significa que el proceso no existe, o \
                 que el barrido no la reconocio"
            }
        }
    }
}

/// Un proceso, en lo que la vista cruzada necesita de el.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proceso {
    /// Su identificador.
    pub pid: u32,
    /// El de su padre.
    pub padre: u32,
    /// Su nombre corto, tal y como lo guarda el nucleo.
    pub nombre: String,
    /// Donde estaba su estructura en el volcado.
    ///
    /// Es la evidencia: permite volver a mirarla, y permite distinguir dos
    /// procesos con el mismo PID —que los hay, entre espacios de nombres.
    pub direccion: u64,
}

/// Lo que dice cada camino, por separado.
#[derive(Debug, Clone, Default)]
pub struct Vistas {
    por_camino: BTreeMap<Camino, Vec<Proceso>>,
}

impl Vistas {
    /// Empieza sin ninguna vista.
    pub fn nuevas() -> Vistas {
        Vistas::default()
    }

    /// Anota lo que vio un camino.
    ///
    /// Un camino que no se pudo recorrer **no se anota**, y eso es distinto de
    /// anotarlo vacio: ver [`Vistas::caminos_recorridos`].
    pub fn anotar(&mut self, camino: Camino, procesos: Vec<Proceso>) {
        let mut v = procesos;
        v.sort_by_key(|p| (p.pid, p.direccion));
        v.dedup();
        self.por_camino.insert(camino, v);
    }

    /// Los caminos que se llegaron a recorrer.
    pub fn caminos_recorridos(&self) -> Vec<Camino> {
        self.por_camino.keys().copied().collect()
    }

    /// Lo que vio un camino, si se recorrio.
    pub fn de(&self, camino: Camino) -> Option<&[Proceso]> {
        self.por_camino.get(&camino).map(|v| v.as_slice())
    }

    /// Cruza las tres vistas.
    pub fn cruzar(&self) -> Cruce {
        let mut todos: BTreeMap<(u32, u64), Proceso> = BTreeMap::new();
        let mut donde: BTreeMap<(u32, u64), BTreeSet<Camino>> = BTreeMap::new();
        for (c, v) in &self.por_camino {
            for p in v {
                let clave = (p.pid, p.direccion);
                todos.entry(clave).or_insert_with(|| p.clone());
                donde.entry(clave).or_default().insert(*c);
            }
        }
        let recorridos: BTreeSet<Camino> = self.por_camino.keys().copied().collect();
        let mut coinciden = Vec::new();
        let mut discrepan = Vec::new();
        for (clave, p) in todos {
            let vistos = donde.remove(&clave).unwrap_or_default();
            if vistos == recorridos {
                coinciden.push(p);
            } else {
                let faltan: Vec<Camino> = recorridos.difference(&vistos).copied().collect();
                discrepan.push(Discrepancia {
                    proceso: p,
                    visto_en: vistos.into_iter().collect(),
                    falta_en: faltan,
                });
            }
        }
        Cruce {
            coinciden,
            discrepan,
            recorridos: recorridos.into_iter().collect(),
        }
    }
}

/// Un proceso en el que los caminos no se ponen de acuerdo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discrepancia {
    /// De que proceso se trata.
    pub proceso: Proceso,
    /// Por que caminos aparecio.
    pub visto_en: Vec<Camino>,
    /// Por cuales no.
    pub falta_en: Vec<Camino>,
}

impl Discrepancia {
    /// Si esta discrepancia es la firma de un proceso oculto.
    ///
    /// # La condicion, y por que es esa
    ///
    /// Aparecer en el barrido de memoria **y faltar en la lista enlazada** es
    /// exactamente lo que hace un rootkit: la estructura sigue ahi porque el
    /// proceso la necesita para correr, y el enlace no esta porque alguien lo
    /// quito.
    ///
    /// Al reves —aparecer en la lista y no en el barrido— no significa lo mismo:
    /// significa que el barrido no reconocio la estructura, que es un limite del
    /// barrido y no un hecho sobre el proceso. Confundir las dos direcciones
    /// convertiria cada fallo del barrido en una acusacion de rootkit.
    pub fn parece_oculto(&self) -> bool {
        self.visto_en.contains(&Camino::BarridoDeMemoria)
            && self.falta_en.contains(&Camino::ListaEnlazada)
    }

    /// La frase con la que esta discrepancia aparece en un informe.
    pub fn frase(&self) -> String {
        let vistos: Vec<&str> = self.visto_en.iter().map(|c| c.nombre()).collect();
        let faltan: Vec<&str> = self.falta_en.iter().map(|c| c.nombre()).collect();
        let mut s = format!(
            "el proceso {} ({}, estructura en {:#x}) aparece por {} y NO por {}",
            self.proceso.pid,
            self.proceso.nombre,
            self.proceso.direccion,
            vistos.join(" y "),
            faltan.join(" ni ")
        );
        if self.parece_oculto() {
            s.push_str(
                ". Esa combinacion concreta es la firma de un proceso oculto: su \
                 estructura sigue en memoria porque la necesita para correr, y el \
                 enlace de la lista que recorre `ps` no esta porque alguien lo quito",
            );
        } else {
            s.push_str(
                ". Esa combinacion NO es la firma de una ocultacion: puede ser un \
                 limite del barrido o un proceso que nacio o murio mientras se tomaba \
                 el volcado",
            );
        }
        s
    }
}

/// El resultado de cruzar las tres vistas.
#[derive(Debug, Clone, Default)]
pub struct Cruce {
    /// Los procesos en los que todos los caminos coinciden.
    pub coinciden: Vec<Proceso>,
    /// Aquellos en los que no.
    pub discrepan: Vec<Discrepancia>,
    /// Que caminos se llegaron a recorrer.
    pub recorridos: Vec<Camino>,
}

impl Cruce {
    /// Los procesos que parecen ocultos.
    pub fn ocultos(&self) -> Vec<&Discrepancia> {
        self.discrepan
            .iter()
            .filter(|d| d.parece_oculto())
            .collect()
    }

    /// Si el cruce puede demostrar algo.
    ///
    /// **Con menos de dos caminos no hay cruce**, hay una lista. Y una lista de
    /// procesos no demuestra que no falte ninguno: eso es justo lo que un rootkit
    /// explota. Decirlo es la diferencia entre una herramienta que sirve para
    /// esto y una que solo lo parece.
    pub fn es_un_cruce(&self) -> bool {
        self.recorridos.len() >= 2
    }

    /// Si el cruce cubre el camino que un rootkit no puede evitar.
    ///
    /// Sin el barrido de memoria, las otras dos vias las puede desenganchar el
    /// mismo rootkit, y su acuerdo no demuestra nada.
    pub fn cubre_el_camino_irrenunciable(&self) -> bool {
        self.recorridos.contains(&Camino::BarridoDeMemoria)
    }

    /// La frase con la que este cruce aparece en un informe.
    pub fn frase(&self) -> String {
        if !self.es_un_cruce() {
            return format!(
                "SOLO SE RECORRIO {} CAMINO: eso no es una vista cruzada, es una lista, \
                 y una lista de procesos no puede demostrar que no falte ninguno — que \
                 es exactamente lo que un rootkit explota",
                self.recorridos.len()
            );
        }
        let mut s = format!(
            "{} caminos recorridos, {} procesos en los que coinciden, {} discrepancias",
            self.recorridos.len(),
            self.coinciden.len(),
            self.discrepan.len()
        );
        let ocultos = self.ocultos();
        if !ocultos.is_empty() {
            s.push_str(&format!(
                "; {} de ellas con la firma de un proceso oculto: ",
                ocultos.len()
            ));
            s.push_str(
                &ocultos
                    .iter()
                    .map(|d| d.frase())
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
        }
        if !self.cubre_el_camino_irrenunciable() {
            s.push_str(
                ". NO SE PUDO BARRER LA MEMORIA: los otros dos caminos los puede \
                 desenganchar el mismo rootkit, asi que su acuerdo no demuestra que no \
                 haya nada oculto",
            );
        }
        s
    }
}

/// Lo que hace falta saber del nucleo para leer sus estructuras.
///
/// # Por que esto es un tipo y no una tabla de constantes
///
/// Porque los desplazamientos de `task_struct` **cambian entre versiones del
/// nucleo y entre configuraciones de compilacion del mismo nucleo**. Una tabla
/// fija funciona en la maquina donde se escribio y produce listas de procesos
/// inventadas en cualquier otra — y una lista de procesos inventada es peor que
/// no tener ninguna, porque nadie la va a poner en duda.
///
/// De ahi que el perfil sea explicito y que [`Perfil::completo`] exista: sin
/// perfil, los caminos que siguen enlaces **no se recorren**, y el cruce lo dice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Perfil {
    /// La version del nucleo, tal y como el volcado la declara.
    pub version: String,
    /// De donde salieron los desplazamientos.
    pub origen: OrigenDelPerfil,
    /// Desplazamiento del campo de identificador dentro de la tarea.
    pub pid: Option<u32>,
    /// Desplazamiento del nombre corto.
    pub nombre: Option<u32>,
    /// Desplazamiento del enlace de la lista de tareas.
    pub lista_de_tareas: Option<u32>,
    /// Desplazamiento del enlace al padre.
    pub padre: Option<u32>,
}

/// De donde salieron los desplazamientos de un perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrigenDelPerfil {
    /// No se pudo determinar.
    #[default]
    Ninguno,
    /// De la informacion de tipos que el propio nucleo publica (BTF).
    ///
    /// Es la fuente buena: la escribe el compilador del nucleo que se esta
    /// analizando, asi que no puede estar desfasada respecto a el.
    Btf,
    /// De reconocer las estructuras por su forma en la memoria.
    ///
    /// Es lo que queda cuando no hay BTF. Funciona y es aproximado, y por eso se
    /// declara: un perfil por firma que acierte el 95 % de los desplazamientos
    /// produce una lista de procesos con un 5 % de campos equivocados, y nadie
    /// sabe cuales.
    PorFirma,
}

impl OrigenDelPerfil {
    /// Como se lee en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            OrigenDelPerfil::Ninguno => {
                "no se pudo perfilar el nucleo del volcado, asi que las estructuras no \
                 se pueden leer y los caminos que siguen enlaces no se recorren"
            }
            OrigenDelPerfil::Btf => {
                "del BTF que el propio nucleo publica, que lo escribe su compilador y \
                 por tanto no puede estar desfasado respecto a el"
            }
            OrigenDelPerfil::PorFirma => {
                "de reconocer las estructuras por su forma, porque el volcado no traia \
                 BTF: es aproximado y se dice"
            }
        }
    }
}

impl Perfil {
    /// Si el perfil tiene lo minimo para recorrer la lista enlazada.
    ///
    /// Sin estos cuatro desplazamientos, seguir la lista produce direcciones
    /// arbitrarias y de ahi salen procesos inventados.
    pub fn completo(&self) -> bool {
        self.pid.is_some()
            && self.nombre.is_some()
            && self.lista_de_tareas.is_some()
            && self.padre.is_some()
    }

    /// La frase con la que este perfil aparece en un informe.
    pub fn frase(&self) -> String {
        let v = if self.version.is_empty() {
            "de version desconocida"
        } else {
            &self.version
        };
        format!(
            "nucleo {v}, perfilado {}{}",
            self.origen.frase(),
            if self.completo() {
                ""
            } else {
                " — INCOMPLETO: faltan desplazamientos, asi que los caminos que siguen \
                 enlaces no se pueden recorrer"
            }
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn proceso(pid: u32, nombre: &str, direccion: u64) -> Proceso {
        Proceso {
            pid,
            padre: 1,
            nombre: nombre.to_owned(),
            direccion,
        }
    }

    /// Tres vistas que coinciden en todo.
    fn vistas_coherentes() -> Vistas {
        let lista = vec![
            proceso(1, "init", 0x1000),
            proceso(42, "bash", 0x2000),
            proceso(99, "sshd", 0x3000),
        ];
        let mut v = Vistas::nuevas();
        for c in Camino::todos() {
            v.anotar(c, lista.clone());
        }
        v
    }

    #[test]
    fn cuando_los_tres_caminos_coinciden_no_hay_nada_que_decir() {
        // El caso negativo que hace que lo demas signifique algo: en una maquina
        // normal las tres vistas dicen lo mismo, y un sistema que encontrara
        // discrepancias aqui las encontraria en todas partes.
        let c = vistas_coherentes().cruzar();
        assert_eq!(c.coinciden.len(), 3);
        assert!(c.discrepan.is_empty(), "{}", c.frase());
        assert!(c.ocultos().is_empty());
        assert!(c.es_un_cruce());
        assert!(c.cubre_el_camino_irrenunciable());
    }

    #[test]
    fn un_proceso_desenganchado_de_la_lista_aparece_por_el_barrido() {
        // La firma exacta de un rootkit: quita el enlace de la lista que recorre
        // `ps` y el proceso sigue corriendo, porque el planificador no usa esa
        // lista para planificar. La estructura sigue en memoria porque la
        // necesita, y el barrido la encuentra.
        let visibles = vec![proceso(1, "init", 0x1000), proceso(42, "bash", 0x2000)];
        let mut todos = visibles.clone();
        todos.push(proceso(1337, "implante", 0x9000));

        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, visibles.clone());
        v.anotar(Camino::ArbolDePid, visibles);
        v.anotar(Camino::BarridoDeMemoria, todos);

        let c = v.cruzar();
        let ocultos = c.ocultos();
        assert_eq!(ocultos.len(), 1, "{}", c.frase());
        assert_eq!(ocultos[0].proceso.pid, 1337);
        assert!(
            ocultos[0].frase().contains("sigue en memoria"),
            "la explicacion tiene que decir POR QUE eso es una ocultacion: {}",
            ocultos[0].frase()
        );
    }

    #[test]
    fn un_proceso_que_el_barrido_no_reconoce_no_se_acusa_de_estar_oculto() {
        // La direccion contraria NO significa lo mismo. Faltar en el barrido es
        // un limite del barrido, no un hecho sobre el proceso, y confundirlas
        // convertiria cada fallo del barrido en una acusacion de rootkit.
        let completos = vec![proceso(1, "init", 0x1000), proceso(42, "bash", 0x2000)];
        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, completos.clone());
        v.anotar(Camino::ArbolDePid, completos);
        v.anotar(Camino::BarridoDeMemoria, vec![proceso(1, "init", 0x1000)]);

        let c = v.cruzar();
        assert_eq!(c.discrepan.len(), 1, "{}", c.frase());
        assert!(
            c.ocultos().is_empty(),
            "faltar en el barrido no es ocultarse: {}",
            c.frase()
        );
        assert!(
            c.discrepan[0].frase().contains("NO es la firma"),
            "{}",
            c.discrepan[0].frase()
        );
    }

    #[test]
    fn con_un_solo_camino_no_hay_cruce_y_se_dice() {
        // Una lista de procesos no demuestra que no falte ninguno, y eso es
        // justo lo que un rootkit explota. Un sistema que presentara una sola
        // lista como si fuera una comprobacion estaria dando por buena la
        // palabra del nucleo comprometido.
        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, vec![proceso(1, "init", 0x1000)]);
        let c = v.cruzar();
        assert!(!c.es_un_cruce());
        assert!(
            c.frase().contains("no es una vista cruzada"),
            "{}",
            c.frase()
        );
    }

    #[test]
    fn sin_el_barrido_de_memoria_el_acuerdo_de_los_otros_dos_no_demuestra_nada() {
        // Los dos caminos que siguen enlaces los puede desenganchar el mismo
        // rootkit. Que coincidan no dice que no haya nada oculto: dice que quien
        // lo oculto hizo bien su trabajo.
        let visibles = vec![proceso(1, "init", 0x1000)];
        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, visibles.clone());
        v.anotar(Camino::ArbolDePid, visibles);
        let c = v.cruzar();
        assert!(c.es_un_cruce());
        assert!(!c.cubre_el_camino_irrenunciable());
        assert!(c.frase().contains("NO SE PUDO BARRER"), "{}", c.frase());
    }

    #[test]
    fn dos_procesos_con_el_mismo_pid_no_se_confunden() {
        // Los hay, entre espacios de nombres. Si el cruce los tratara como uno,
        // uno de los dos pareceria estar en tres sitios y el otro en ninguno.
        let mut v = Vistas::nuevas();
        let a = proceso(42, "uno", 0x2000);
        let b = proceso(42, "otro", 0x8000);
        for c in Camino::todos() {
            v.anotar(c, vec![a.clone(), b.clone()]);
        }
        let c = v.cruzar();
        assert_eq!(c.coinciden.len(), 2);
        assert!(c.discrepan.is_empty(), "{}", c.frase());
    }

    #[test]
    fn un_perfil_incompleto_lo_declara_en_vez_de_producir_procesos_inventados() {
        // Los desplazamientos de task_struct cambian entre versiones del nucleo
        // y entre configuraciones del mismo nucleo. Una tabla fija produce listas
        // de procesos inventadas en cualquier maquina que no sea la del autor, y
        // nadie las pone en duda.
        let p = Perfil {
            version: "6.1.0".to_owned(),
            origen: OrigenDelPerfil::PorFirma,
            pid: Some(0x4E8),
            ..Default::default()
        };
        assert!(!p.completo());
        assert!(p.frase().contains("INCOMPLETO"), "{}", p.frase());
        assert!(p.frase().contains("por su forma"), "{}", p.frase());
    }

    #[test]
    fn un_perfil_de_btf_se_distingue_de_uno_por_firma() {
        // El BTF lo escribe el compilador del nucleo que se esta analizando, asi
        // que no puede estar desfasado respecto a el. Un perfil por firma que
        // acierte el 95 % de los desplazamientos produce un 5 % de campos
        // equivocados y nadie sabe cuales.
        let btf = Perfil {
            version: "6.1.0".to_owned(),
            origen: OrigenDelPerfil::Btf,
            pid: Some(1),
            nombre: Some(2),
            lista_de_tareas: Some(3),
            padre: Some(4),
        };
        assert!(btf.completo());
        assert!(btf.frase().contains("BTF"), "{}", btf.frase());
        assert!(!btf.frase().contains("INCOMPLETO"));
    }

    #[test]
    fn un_camino_que_no_se_recorrio_no_es_lo_mismo_que_uno_vacio() {
        // Si no se distinguieran, un camino que fallo haria que TODOS los
        // procesos parecieran ocultos por no aparecer en el.
        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, vec![proceso(1, "init", 0x1000)]);
        v.anotar(Camino::BarridoDeMemoria, vec![proceso(1, "init", 0x1000)]);
        assert_eq!(v.caminos_recorridos().len(), 2);
        assert!(v.de(Camino::ArbolDePid).is_none());
        let c = v.cruzar();
        assert!(c.discrepan.is_empty(), "{}", c.frase());
    }

    #[test]
    fn un_camino_recorrido_y_vacio_si_cuenta() {
        // Recorrer el arbol de PID y no encontrar nada es un hecho, y distinto de
        // no haberlo recorrido.
        let mut v = Vistas::nuevas();
        v.anotar(Camino::ListaEnlazada, vec![proceso(1, "init", 0x1000)]);
        v.anotar(Camino::ArbolDePid, Vec::new());
        v.anotar(Camino::BarridoDeMemoria, vec![proceso(1, "init", 0x1000)]);
        assert_eq!(v.caminos_recorridos().len(), 3);
        let c = v.cruzar();
        assert_eq!(c.discrepan.len(), 1);
        assert!(c.discrepan[0].falta_en.contains(&Camino::ArbolDePid));
    }
}
