//! El informe de comportamiento, y las dos cosas que no puede hacer.
//!
//! # No puede decir «benigna» cuando no lo sabe
//!
//! Hay tres situaciones que se escriben igual en un sandbox descuidado y
//! significan cosas radicalmente distintas:
//!
//! 1. La muestra corrio entera y no hizo nada malo.
//! 2. La muestra **detecto el entorno** y se marcho.
//! 3. La detonacion **se corto** antes de que la muestra empezara.
//!
//! Solo la primera es «benigna». Las otras dos son «no se sabe», y confundirlas
//! es la forma mas cara de equivocarse: alguien despliega la muestra creyendo que
//! esta limpia. Por eso [`Informe::veredicto`] **no puede** devolver
//! [`Veredicto::SinHallazgos`] si el informe esta incompleto o si hay sospecha de
//! evasion, y no es una convencion: es la estructura del `match`.
//!
//! # No puede fingir determinismo
//!
//! La misma muestra tiene que dar el mismo informe. Pero el malware usa la hora,
//! numeros al azar y el PID que le toque, asi que hay partes del informe que
//! **no pueden** ser iguales entre dos detonaciones.
//!
//! La salida no es normalizarlo todo hasta que parezca determinista —eso esconde
//! justo el comportamiento que interesa, como un nombre de fichero generado al
//! azar— sino distinguir las dos cosas:
//!
//! - La **huella** se calcula sobre la forma canonica, que renumera los PID por
//!   orden de aparicion y ordena las colecciones. Dos detonaciones iguales dan la
//!   misma huella.
//! - Lo que **no** encaja en esa forma se declara en [`Informe::indeterminismo`],
//!   con su motivo. Un informe que no trae ninguna fuente de indeterminismo esta
//!   afirmando algo fuerte, y tiene que poder sostenerlo.

use std::collections::{BTreeMap, BTreeSet};

use aegis_invitado::protocolo::{AccionFichero, AccionProceso, AccionRed, Evento};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aegis_vmi::modo::{Delator, Modo, Observacion};

use crate::antivm::{self, Cobertura, Sospecha, Tecnica};
use crate::receptor::{Anomalia, Recepcion};
use crate::red_simulada::Observado;

/// Que se detono.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Muestra {
    /// SHA-256 del fichero.
    pub sha256: String,
    /// Tamano en bytes.
    pub bytes: u64,
    /// Nombre con el que llego, solo informativo.
    pub nombre: String,
}

impl Muestra {
    /// Calcula la huella de unos bytes.
    #[must_use]
    pub fn de_bytes(nombre: &str, datos: &[u8]) -> Muestra {
        let mut h = Sha256::new();
        h.update(datos);
        Muestra {
            sha256: h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
            bytes: datos.len() as u64,
            nombre: nombre.to_string(),
        }
    }
}

/// Como acabo la detonacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Final {
    /// La muestra termino por si sola.
    Termino {
        /// Codigo de salida.
        codigo: i32,
    },
    /// Se agoto el plazo y se corto.
    Plazo,
    /// Se alcanzo un tope y se dejo de observar.
    Tope,
    /// La detonacion no llego a arrancar.
    NoArranco,
}

impl Final {
    /// Si la muestra tuvo ocasion de hacer lo que fuera a hacer.
    #[must_use]
    pub fn tuvo_ocasion(self) -> bool {
        matches!(self, Final::Termino { .. })
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Final::Termino { .. } => "termino",
            Final::Plazo => "plazo",
            Final::Tope => "tope",
            Final::NoArranco => "no-arranco",
        }
    }
}

/// Lo que la muestra hizo, agregado.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comportamiento {
    /// Imagenes que se ejecutaron.
    pub ejecutados: BTreeSet<String>,
    /// Ficheros escritos o creados.
    pub escritos: BTreeSet<String>,
    /// Ficheros borrados.
    pub borrados: BTreeSet<String>,
    /// Ficheros renombrados.
    pub renombrados: BTreeSet<String>,
    /// Destinos de red a los que intento conectar.
    pub destinos: BTreeSet<String>,
    /// Dominios que consulto por DNS.
    pub dominios: BTreeSet<String>,
    /// Peticiones HTTP, como `METODO host ruta`.
    pub peticiones: BTreeSet<String>,
    /// Tecnicas de evasion u ocultacion vistas en las llamadas.
    pub evasiones: BTreeMap<String, u64>,
    /// Procesos distintos observados.
    pub procesos: u64,
}

impl Comportamiento {
    /// Si no se observo absolutamente nada.
    #[must_use]
    pub fn vacio(&self) -> bool {
        self.ejecutados.is_empty()
            && self.escritos.is_empty()
            && self.borrados.is_empty()
            && self.renombrados.is_empty()
            && self.destinos.is_empty()
            && self.dominios.is_empty()
            && self.peticiones.is_empty()
            && self.evasiones.is_empty()
    }

    /// Cuantos hechos distintos hay.
    #[must_use]
    pub fn hechos(&self) -> usize {
        self.ejecutados.len()
            + self.escritos.len()
            + self.borrados.len()
            + self.renombrados.len()
            + self.destinos.len()
            + self.dominios.len()
            + self.peticiones.len()
            + self.evasiones.len()
    }
}

/// Algo que no puede ser igual entre dos detonaciones, y por que.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indeterminismo {
    /// Que campo o hecho.
    pub que: String,
    /// Por que no se puede fijar.
    pub por_que: String,
}

/// Que se puede afirmar de la muestra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Veredicto {
    /// Corrio entera y no se observo nada relevante.
    ///
    /// **Es la unica forma de decir «no encontramos nada», y solo se alcanza si
    /// la detonacion fue completa y no hubo sospecha de evasion.**
    SinHallazgos,
    /// Se observo comportamiento que hay que mirar.
    ConHallazgos {
        /// Cuantos hechos distintos.
        hechos: usize,
    },
    /// No se puede afirmar nada, y se dice por que.
    NoConcluyente {
        /// El motivo.
        motivo: String,
    },
}

impl Veredicto {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Veredicto::SinHallazgos => "sin-hallazgos",
            Veredicto::ConHallazgos { .. } => "con-hallazgos",
            Veredicto::NoConcluyente { .. } => "no-concluyente",
        }
    }

    /// Si el veredicto sirve para decidir si la muestra es segura.
    #[must_use]
    pub fn decide(&self) -> bool {
        !matches!(self, Veredicto::NoConcluyente { .. })
    }
}

/// El informe completo de una detonacion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Informe {
    /// Que se detono.
    pub muestra: Muestra,
    /// Con que fuerza estaba encerrada, en texto.
    ///
    /// Va dentro del informe y no en un registro aparte: quien lo lee tiene que
    /// saber cuanto puede creerselo.
    pub frontera: String,
    /// Como acabo.
    pub final_: Final,
    /// Lo que hizo.
    pub comportamiento: Comportamiento,
    /// Lo que no cuadro en el canal.
    pub anomalias: Vec<Anomalia>,
    /// Si la muestra parece haber reconocido el entorno.
    pub sospecha: Sospecha,
    /// Que tecnicas de reconocimiento se le vieron.
    pub tecnicas_vistas: BTreeSet<Tecnica>,
    /// Que se contrarresta y que no, tal cual.
    pub cobertura_antivm: Vec<Cobertura>,
    /// Como se observo a la muestra: con agente dentro, o desde el hipervisor.
    ///
    /// # Por que esto va DENTRO del informe
    ///
    /// Porque «sin hallazgos» significa cosas distintas segun el modo, y separar
    /// las dos cosas en dos valores permite que una viaje sin la otra. Cuando eso
    /// pasa —y pasa, en cuanto alguien serializa solo el veredicto— el informe
    /// queda diciendo algo cierto y enganoso.
    ///
    /// Con agente dentro, cero sucesos es indistinguible de «la muestra encontro
    /// el agente y se marcho». Sin nada dentro, cero sucesos es cero sucesos.
    #[serde(with = "modo_como_texto")]
    pub modo: Modo,
    /// Lo que no puede repetirse entre detonaciones.
    pub indeterminismo: Vec<Indeterminismo>,
    /// Eventos recibidos.
    pub eventos: u64,
}

/// El modo, en el informe, va como su nombre y no como un numero de variante.
///
/// Un informe archivado se lee meses despues, con otra version del binario. El
/// nombre de un modo no cambia; el orden de las variantes de un enum si puede, y
/// entonces un informe viejo diria que se detono de la otra forma — que es
/// exactamente la confusion que declarar el modo existe para evitar.
mod modo_como_texto {
    use super::Modo;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Escribe el nombre.
    pub fn serialize<S: Serializer>(m: &Modo, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(m.nombre())
    }

    /// Lee el nombre. Un nombre desconocido es un ERROR y no un modo por
    /// defecto: dar por bueno el modo equivocado es peor que no poder leer el
    /// informe, porque nadie lo notaria.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Modo, D::Error> {
        let s = String::deserialize(d)?;
        Modo::de_nombre(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "modo de detonacion desconocido: {s:?}. No se elige uno por defecto \
                 porque dar por bueno el modo equivocado hace que el informe mienta \
                 sobre lo que se pudo ver"
            ))
        })
    }
}

impl Informe {
    /// Monta el informe a partir de todo lo recogido.
    #[must_use]
    pub fn montar(
        muestra: Muestra,
        frontera: &crate::frontera::Frontera,
        final_: Final,
        recepcion: &Recepcion,
        red: &Observado,
        modo: Modo,
    ) -> Informe {
        let eventos = recepcion.eventos();
        let (sospecha, tecnicas_vistas) = antivm::analizar(&eventos);
        let comportamiento = resumir(&eventos, red);
        let indeterminismo = detectar_indeterminismo(&eventos, &comportamiento);

        Informe {
            muestra,
            frontera: frontera.resumen(),
            final_,
            comportamiento,
            anomalias: recepcion.anomalias.clone(),
            sospecha,
            tecnicas_vistas,
            cobertura_antivm: antivm::catalogo(),
            modo,
            indeterminismo,
            eventos: recepcion.len() as u64,
        }
    }

    /// Si el informe cubre la detonacion entera sin agujeros.
    ///
    /// # La condicion que anadio el modo fantasma
    ///
    /// Una detonacion CON AGENTE que no produjo ni un evento no esta completa,
    /// aunque la muestra arrancara y terminara limpiamente. El agente es un
    /// proceso del invitado: tiene nombre, fichero, canal con el anfitrion y sus
    /// propias llamadas al sistema, y una muestra que lo busque lo encuentra.
    /// Cero eventos con el dentro es indistinguible de «lo encontro y se
    /// marcho», y las dos lecturas llevan a decisiones opuestas.
    ///
    /// En modo fantasma no hay nada dentro que encontrar, asi que cero sucesos
    /// es cero sucesos y la detonacion si esta completa.
    #[must_use]
    pub fn completo(&self) -> bool {
        if !self.final_.tuvo_ocasion() || self.anomalias.iter().any(Anomalia::deja_hueco) {
            return false;
        }
        self.observacion().la_ausencia_significa_algo()
    }

    /// Lo observado, con su modo, para poder preguntarle que significa su
    /// silencio.
    #[must_use]
    pub fn observacion(&self) -> Observacion {
        Observacion {
            modo: self.modo,
            sucesos: self.eventos as usize,
            arranco: self.final_.tuvo_ocasion(),
        }
    }

    /// Que formas de detectar el analisis NO contrarresta el modo que se uso.
    ///
    /// El catalogo anti-VM general dice que se contrarresta del entorno; esto
    /// dice que se contrarresta de la OBSERVACION, y cambia con el modo. Sin las
    /// dos mitades, un informe puede presumir de cubrir doce tecnicas mientras
    /// el agente que lo produjo era visible desde dentro.
    #[must_use]
    pub fn delatores_del_modo(&self) -> &'static [Delator] {
        self.modo.tecnicas_que_no_contrarresta()
    }

    /// Que se puede afirmar.
    ///
    /// # La estructura del `match` es la garantia
    ///
    /// No hay ningun camino que llegue a [`Veredicto::SinHallazgos`] sin haber
    /// pasado antes por las dos comprobaciones. No es una convencion que alguien
    /// pueda saltarse por descuido en una version futura: para romperlo habria
    /// que reordenar el `match` a proposito, y eso se ve en una revision.
    #[must_use]
    pub fn veredicto(&self) -> Veredicto {
        // El caso que anadio el modo fantasma, y va PRIMERO porque es el mas
        // enganoso: la detonacion salio bien, la muestra arranco y termino, y no
        // se vio absolutamente nada. Con un agente dentro eso no significa que la
        // muestra sea inofensiva: significa que no hizo nada mientras ese agente
        // estaba ahi, y el agente se puede encontrar.
        if self.modo.deja_rastro_dentro() && self.eventos == 0 && self.final_.tuvo_ocasion() {
            return Veredicto::NoConcluyente {
                motivo: format!(
                    "la muestra arranco y no produjo ni un evento, y se detono {}. Eso es \
                     indistinguible de que encontrara el agente y se marchara. Lo que este \
                     modo NO contrarresta: {}",
                    self.modo.frase(),
                    self.delatores_del_modo()
                        .iter()
                        .map(|d| d.frase())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            };
        }
        if !self.completo() {
            return Veredicto::NoConcluyente {
                motivo: format!(
                    "la detonacion no fue completa ({}): lo observado vale, pero la ausencia de \
                     hallazgos NO significa que la muestra sea inofensiva",
                    self.final_.nombre()
                ),
            };
        }
        if self.sospecha == Sospecha::ProbableEvasion {
            return Veredicto::NoConcluyente {
                motivo: format!(
                    "la muestra reconocio el entorno y se marcho ({}): esto es una deteccion de \
                     sandbox, no un veredicto de inocuidad",
                    self.sospecha.detalle()
                ),
            };
        }
        if self.comportamiento.vacio() {
            return Veredicto::SinHallazgos;
        }
        Veredicto::ConHallazgos {
            hechos: self.comportamiento.hechos(),
        }
    }

    /// Huella canonica del comportamiento.
    ///
    /// Dos detonaciones de la misma muestra que hagan lo mismo dan la misma
    /// huella. Se calcula **solo** sobre el comportamiento agregado y ordenado:
    /// no entran ni los PID, ni los tamanos, ni el orden de llegada, porque nada
    /// de eso se repite y meterlo haria que la huella no coincidiera nunca, que
    /// es lo mismo que no tenerla.
    #[must_use]
    pub fn huella(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"aegis-detonate/informe/v1\n");
        h.update(self.muestra.sha256.as_bytes());
        h.update(b"\n");
        let c = &self.comportamiento;
        for (etiqueta, conjunto) in [
            ("ejecutados", &c.ejecutados),
            ("escritos", &c.escritos),
            ("borrados", &c.borrados),
            ("renombrados", &c.renombrados),
            ("destinos", &c.destinos),
            ("dominios", &c.dominios),
            ("peticiones", &c.peticiones),
        ] {
            h.update(etiqueta.as_bytes());
            h.update(b":");
            for v in conjunto.iter() {
                h.update(v.as_bytes());
                h.update(b"\x1f");
            }
            h.update(b"\n");
        }
        h.update(b"evasiones:");
        for k in c.evasiones.keys() {
            h.update(k.as_bytes());
            h.update(b"\x1f");
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Resumen de una linea para la consola.
    #[must_use]
    pub fn resumen(&self) -> String {
        format!(
            "{} · {} · {} hechos · {} eventos · {} · huella {}",
            &self.muestra.sha256[..16.min(self.muestra.sha256.len())],
            self.veredicto().nombre(),
            self.comportamiento.hechos(),
            self.eventos,
            self.final_.nombre(),
            &self.huella()[..16]
        )
    }
}

/// Agrega los eventos y lo visto en la red falsa.
fn resumir(eventos: &[&Evento], red: &Observado) -> Comportamiento {
    let mut c = Comportamiento::default();
    let mut pids: BTreeSet<i32> = BTreeSet::new();

    for e in eventos {
        if let Some(p) = e.pid() {
            pids.insert(p);
        }
        match e {
            Evento::Proceso { accion, imagen, .. } => {
                if matches!(accion, AccionProceso::Ejecuta) && !imagen.is_empty() {
                    c.ejecutados.insert(imagen.clone());
                }
            }
            Evento::Fichero { accion, ruta, .. } => {
                if ruta.is_empty() {
                    continue;
                }
                match accion {
                    AccionFichero::Escribe => {
                        c.escritos.insert(ruta.clone());
                    }
                    AccionFichero::Borra => {
                        c.borrados.insert(ruta.clone());
                    }
                    AccionFichero::Renombra => {
                        c.renombrados.insert(ruta.clone());
                    }
                    AccionFichero::Lee | AccionFichero::Permisos => {}
                }
            }
            Evento::Red {
                accion,
                destino,
                puerto,
                ..
            } => {
                if matches!(accion, AccionRed::Conecta | AccionRed::Envia) && !destino.is_empty() {
                    c.destinos.insert(format!("{destino}:{puerto}"));
                }
            }
            Evento::Llamada { nombre, .. } => {
                // Solo las que la tabla marca como evasion llegan aqui con un
                // nombre reconocible; el resto son ruido de fondo.
                if es_evasion(nombre) {
                    *c.evasiones.entry(nombre.clone()).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }

    // Lo que vio la red falsa. El dominio consultado es el indicador mas valioso
    // del informe, y solo existe porque hay un DNS que contesta.
    for nombre in red.nombres.keys() {
        c.dominios.insert(nombre.clone());
    }
    for p in &red.peticiones {
        c.peticiones
            .insert(format!("{} {} {}", p.metodo, p.host, p.ruta));
    }

    c.procesos = pids.len() as u64;
    c
}

/// Nombres de llamada que el trazador marca como tecnica de ocultacion.
fn es_evasion(nombre: &str) -> bool {
    const EVASIONES: &[&str] = &[
        "ptrace",
        "memfd_create",
        "mprotect+WX",
        "init_module",
        "finit_module",
        "delete_module",
        "unshare",
        "chroot",
        "pivot_root",
        "mount",
        "umount2",
        "setuid",
        "setgid",
        "open_by_handle_at",
        "reboot",
    ];
    EVASIONES.contains(&nombre)
}

/// Busca lo que no puede repetirse entre dos detonaciones.
///
/// Un informe sin ninguna fuente de indeterminismo esta afirmando algo fuerte —
/// que la muestra es completamente reproducible— y tiene que poder sostenerlo.
fn detectar_indeterminismo(eventos: &[&Evento], c: &Comportamiento) -> Vec<Indeterminismo> {
    let mut v = Vec::new();

    if eventos.iter().any(|e| e.pid().is_some()) {
        v.push(Indeterminismo {
            que: "identificadores de proceso".into(),
            por_que: "los asigna el kernel del invitado y cambian en cada arranque; no entran en \
                      la huella"
                .into(),
        });
    }

    // Rutas que parecen generadas: mucho digito o hexadecimal seguido en el
    // ultimo componente. Es lo que hace un ransomware al nombrar su nota o un
    // cargador al escribir su carga en /tmp.
    let generadas: Vec<&String> = c
        .escritos
        .iter()
        .chain(c.renombrados.iter())
        .filter(|r| parece_generada(r))
        .collect();
    if !generadas.is_empty() {
        v.push(Indeterminismo {
            que: format!("{} rutas con aspecto generado", generadas.len()),
            por_que: format!(
                "el nombre parece elegido al azar o a partir de la hora (por ejemplo «{}»); dos \
                 detonaciones no daran el mismo",
                generadas[0]
            ),
        });
    }

    // Un dominio distinto en cada ejecucion es la firma de un algoritmo de
    // generacion de dominios, y es un hallazgo, no un defecto del sandbox.
    if c.dominios.len() > 8 {
        v.push(Indeterminismo {
            que: format!("{} dominios consultados", c.dominios.len()),
            por_que: "tantos dominios distintos apuntan a un algoritmo de generacion, que suele \
                      depender de la fecha: manana no saldran los mismos"
                .into(),
        });
    }

    v
}

/// Si una ruta tiene pinta de haberse generado al azar o con la hora.
fn parece_generada(ruta: &str) -> bool {
    let Some(ultimo) = ruta.rsplit('/').next() else {
        return false;
    };
    let base = ultimo.split('.').next().unwrap_or(ultimo);
    if base.len() < 8 {
        return false;
    }
    let digitos = base.chars().filter(char::is_ascii_digit).count();
    let hexa = base.chars().filter(|c| c.is_ascii_hexdigit()).count();
    // Todo hexadecimal y largo, o mas de la mitad digitos: las dos formas en que
    // se ven los nombres que alguien no escribio a mano.
    (hexa == base.len() && base.len() >= 12) || digitos * 2 > base.len()
}

/// En que se diferencian dos informes de la misma muestra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergencia {
    /// Que campo difiere.
    pub campo: &'static str,
    /// Lo que hay en el primero y no en el segundo.
    pub solo_en_a: Vec<String>,
    /// Lo que hay en el segundo y no en el primero.
    pub solo_en_b: Vec<String>,
}

/// Compara dos detonaciones de la misma muestra.
///
/// Es como se **mide** el determinismo en vez de afirmarlo: se detona dos veces y
/// se comparan los informes. Lo que diverge sale con nombre, y entonces se puede
/// decidir si es una fuente de indeterminismo legitima —un nombre al azar— o un
/// fallo del sandbox.
#[must_use]
pub fn comparar(a: &Informe, b: &Informe) -> Vec<Divergencia> {
    let mut v = Vec::new();
    let campos: [(&'static str, &BTreeSet<String>, &BTreeSet<String>); 7] = [
        (
            "ejecutados",
            &a.comportamiento.ejecutados,
            &b.comportamiento.ejecutados,
        ),
        (
            "escritos",
            &a.comportamiento.escritos,
            &b.comportamiento.escritos,
        ),
        (
            "borrados",
            &a.comportamiento.borrados,
            &b.comportamiento.borrados,
        ),
        (
            "renombrados",
            &a.comportamiento.renombrados,
            &b.comportamiento.renombrados,
        ),
        (
            "destinos",
            &a.comportamiento.destinos,
            &b.comportamiento.destinos,
        ),
        (
            "dominios",
            &a.comportamiento.dominios,
            &b.comportamiento.dominios,
        ),
        (
            "peticiones",
            &a.comportamiento.peticiones,
            &b.comportamiento.peticiones,
        ),
    ];
    for (campo, ca, cb) in campos {
        let solo_a: Vec<String> = ca.difference(cb).cloned().collect();
        let solo_b: Vec<String> = cb.difference(ca).cloned().collect();
        if !solo_a.is_empty() || !solo_b.is_empty() {
            v.push(Divergencia {
                campo,
                solo_en_a: solo_a,
                solo_en_b: solo_b,
            });
        }
    }
    v
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::frontera::Frontera;
    use crate::receptor::Recepcion;
    use aegis_invitado::protocolo::Trama;

    fn recepcion(eventos: Vec<Evento>) -> Recepcion {
        Recepcion {
            tramas: eventos
                .into_iter()
                .enumerate()
                .map(|(i, e)| Trama {
                    secuencia: i as u64,
                    evento: e,
                })
                .collect(),
            anomalias: Vec::new(),
            bytes: 0,
        }
    }

    fn escribe(ruta: &str) -> Evento {
        Evento::Fichero {
            pid: 100,
            accion: AccionFichero::Escribe,
            ruta: ruta.into(),
            bytes: 4096,
        }
    }

    fn lee(ruta: &str) -> Evento {
        Evento::Fichero {
            pid: 100,
            accion: AccionFichero::Lee,
            ruta: ruta.into(),
            bytes: 0,
        }
    }

    /// Un informe de detonacion en modo fantasma.
    ///
    /// Es el que usan las pruebas que NO estan comprobando el efecto del modo:
    /// sin nada dentro del invitado, cero eventos significa cero eventos, asi
    /// que el resto de las propiedades se pueden comprobar sin que el modo se
    /// meta por medio.
    fn informe_de(eventos: Vec<Evento>, final_: Final) -> Informe {
        informe_en(eventos, final_, Modo::Fantasma)
    }

    fn informe_en(eventos: Vec<Evento>, final_: Final, modo: Modo) -> Informe {
        Informe::montar(
            Muestra::de_bytes("muestra.bin", b"unos bytes cualesquiera"),
            &Frontera::namespaces(),
            final_,
            &recepcion(eventos),
            &Observado::default(),
            modo,
        )
    }

    // --- El veredicto no puede mentir --------------------------------------

    #[test]
    fn una_muestra_que_detecto_el_sandbox_no_sale_como_benigna() {
        // EL CASO QUE JUSTIFICA EL MODULO. Un sandbox descuidado escribe esto
        // igual que «corrio entera y no hizo nada», y alguien despliega la
        // muestra creyendo que esta limpia.
        let i = informe_de(
            vec![
                lee("/sys/class/dmi/id/product_name"),
                lee("/proc/cpuinfo"),
                lee("/proc/uptime"),
            ],
            Final::Termino { codigo: 0 },
        );
        assert_eq!(i.sospecha, Sospecha::ProbableEvasion);
        match i.veredicto() {
            Veredicto::NoConcluyente { motivo } => {
                assert!(motivo.contains("sandbox"), "{motivo}");
            }
            otro => panic!("no puede salir {otro:?}"),
        }
        assert!(!i.veredicto().decide());
    }

    #[test]
    fn una_detonacion_cortada_no_sale_como_benigna() {
        // «No hizo nada» y «no le dio tiempo» no se pueden escribir igual.
        for final_ in [Final::Plazo, Final::Tope, Final::NoArranco] {
            let i = informe_de(Vec::new(), final_);
            assert!(
                matches!(i.veredicto(), Veredicto::NoConcluyente { .. }),
                "{final_:?} no puede dar un veredicto"
            );
        }
    }

    #[test]
    fn una_muestra_que_corrio_entera_y_no_hizo_nada_si_sale_limpia() {
        // La contraparte: si no hubiera ningun camino a SinHallazgos, el informe
        // seria inutil por el otro lado.
        let i = informe_de(Vec::new(), Final::Termino { codigo: 0 });
        assert_eq!(i.veredicto(), Veredicto::SinHallazgos);
        assert!(i.veredicto().decide());
        assert!(i.completo());
    }

    #[test]
    fn lo_que_hizo_sale_contado() {
        let i = informe_de(
            vec![
                escribe("/home/victima/nomina.xlsx.cifrado"),
                escribe("/home/victima/RESCATE.txt"),
                Evento::Red {
                    pid: 100,
                    accion: AccionRed::Conecta,
                    destino: "203.0.113.13".into(),
                    puerto: 443,
                    bytes: 0,
                },
                Evento::Llamada {
                    pid: 100,
                    numero: 319,
                    nombre: "memfd_create".into(),
                },
            ],
            Final::Termino { codigo: 0 },
        );
        match i.veredicto() {
            Veredicto::ConHallazgos { hechos } => assert!(hechos >= 4, "{hechos}"),
            otro => panic!("{otro:?}"),
        }
        assert!(i
            .comportamiento
            .escritos
            .contains("/home/victima/RESCATE.txt"));
        assert!(i.comportamiento.destinos.contains("203.0.113.13:443"));
        assert!(i.comportamiento.evasiones.contains_key("memfd_create"));
    }

    #[test]
    fn un_hueco_en_el_canal_deja_el_informe_no_concluyente() {
        let mut r = recepcion(vec![escribe("/tmp/x")]);
        r.anomalias.push(Anomalia::Hueco { desde: 1, hasta: 9 });
        let i = Informe::montar(
            Muestra::de_bytes("m", b"x"),
            &Frontera::namespaces(),
            Final::Termino { codigo: 0 },
            &r,
            &Observado::default(),
            Modo::Fantasma,
        );
        assert!(!i.completo());
        assert!(matches!(i.veredicto(), Veredicto::NoConcluyente { .. }));
    }

    // --- La huella ----------------------------------------------------------

    #[test]
    fn dos_detonaciones_con_el_mismo_comportamiento_dan_la_misma_huella() {
        let a = informe_de(
            vec![
                escribe("/tmp/carga.bin"),
                escribe("/etc/cron.d/persistencia"),
            ],
            Final::Termino { codigo: 0 },
        );
        // Los mismos hechos en otro orden y con otros PID.
        let b = Informe::montar(
            Muestra::de_bytes("muestra.bin", b"unos bytes cualesquiera"),
            &Frontera::namespaces(),
            Final::Termino { codigo: 0 },
            &recepcion(vec![
                Evento::Fichero {
                    pid: 7777,
                    accion: AccionFichero::Escribe,
                    ruta: "/etc/cron.d/persistencia".into(),
                    bytes: 1,
                },
                Evento::Fichero {
                    pid: 9999,
                    accion: AccionFichero::Escribe,
                    ruta: "/tmp/carga.bin".into(),
                    bytes: 999_999,
                },
            ]),
            &Observado::default(),
            Modo::Fantasma,
        );
        assert_eq!(
            a.huella(),
            b.huella(),
            "ni el orden ni los PID ni los tamanos pueden cambiar la huella"
        );
    }

    #[test]
    fn un_comportamiento_distinto_da_una_huella_distinta() {
        let a = informe_de(vec![escribe("/tmp/a")], Final::Termino { codigo: 0 });
        let b = informe_de(vec![escribe("/tmp/b")], Final::Termino { codigo: 0 });
        assert_ne!(a.huella(), b.huella());
    }

    #[test]
    fn la_huella_distingue_muestras_aunque_hagan_lo_mismo() {
        // Dos muestras distintas con el mismo comportamiento no son la misma
        // cosa, y la huella tiene que poder separarlas.
        let a = Informe::montar(
            Muestra::de_bytes("a", b"aaa"),
            &Frontera::namespaces(),
            Final::Termino { codigo: 0 },
            &recepcion(vec![escribe("/tmp/x")]),
            &Observado::default(),
            Modo::Fantasma,
        );
        let b = Informe::montar(
            Muestra::de_bytes("b", b"bbb"),
            &Frontera::namespaces(),
            Final::Termino { codigo: 0 },
            &recepcion(vec![escribe("/tmp/x")]),
            &Observado::default(),
            Modo::Fantasma,
        );
        assert_ne!(a.huella(), b.huella());
    }

    // --- El indeterminismo se declara, no se disimula ------------------------

    #[test]
    fn una_ruta_generada_al_azar_se_declara_en_vez_de_normalizarse() {
        // Normalizarla hasta que parezca determinista esconderia justo el
        // comportamiento que interesa.
        let i = informe_de(
            vec![escribe("/tmp/a3f9c27e41b8d05e.bin")],
            Final::Termino { codigo: 0 },
        );
        assert!(
            i.indeterminismo.iter().any(|x| x.que.contains("generado")),
            "{:?}",
            i.indeterminismo
        );
    }

    #[test]
    fn un_nombre_normal_no_se_confunde_con_uno_generado() {
        assert!(!parece_generada("/home/victima/informe-anual.docx"));
        assert!(!parece_generada("/usr/bin/curl"));
        assert!(!parece_generada("/etc/passwd"));
        assert!(parece_generada("/tmp/a3f9c27e41b8d05e.bin"));
        assert!(parece_generada("/tmp/20240117093312.tmp"));
    }

    #[test]
    fn los_pid_siempre_se_declaran_como_indeterministas() {
        let i = informe_de(vec![escribe("/tmp/x")], Final::Termino { codigo: 0 });
        assert!(i
            .indeterminismo
            .iter()
            .any(|x| x.que.contains("identificadores de proceso")));
    }

    #[test]
    fn muchos_dominios_se_leen_como_algoritmo_de_generacion() {
        let mut red = Observado::default();
        for i in 0..20 {
            red.nombres.insert(format!("x{i}kjhsdf.example"), 1);
        }
        let i = Informe::montar(
            Muestra::de_bytes("m", b"x"),
            &Frontera::namespaces(),
            Final::Termino { codigo: 0 },
            &recepcion(Vec::new()),
            &red,
            Modo::Fantasma,
        );
        assert!(i
            .indeterminismo
            .iter()
            .any(|x| x.por_que.contains("algoritmo de generacion")));
        assert_eq!(i.comportamiento.dominios.len(), 20);
    }

    // --- Comparar dos detonaciones ------------------------------------------

    #[test]
    fn comparar_dice_exactamente_en_que_divergen() {
        // Asi se MIDE el determinismo en vez de afirmarlo.
        let a = informe_de(
            vec![escribe("/tmp/comun"), escribe("/tmp/solo-a")],
            Final::Termino { codigo: 0 },
        );
        let b = informe_de(
            vec![escribe("/tmp/comun"), escribe("/tmp/solo-b")],
            Final::Termino { codigo: 0 },
        );
        let d = comparar(&a, &b);
        let escritos = d.iter().find(|x| x.campo == "escritos").unwrap();
        assert_eq!(escritos.solo_en_a, vec!["/tmp/solo-a".to_string()]);
        assert_eq!(escritos.solo_en_b, vec!["/tmp/solo-b".to_string()]);
    }

    #[test]
    fn dos_detonaciones_identicas_no_divergen_en_nada() {
        let a = informe_de(vec![escribe("/tmp/x")], Final::Termino { codigo: 0 });
        let b = informe_de(vec![escribe("/tmp/x")], Final::Termino { codigo: 0 });
        assert!(comparar(&a, &b).is_empty());
    }

    // --- El informe lleva con que fuerza estaba encerrada --------------------

    #[test]
    fn el_informe_lleva_dentro_la_frontera_y_el_catalogo_antivm() {
        // Si estuvieran en un documento aparte, nadie los leeria en el momento
        // en el que importa.
        let i = informe_de(Vec::new(), Final::Termino { codigo: 0 });
        assert!(i.frontera.contains("confinamiento"), "{}", i.frontera);
        assert!(!i.cobertura_antivm.is_empty());
        assert!(
            i.cobertura_antivm
                .iter()
                .any(|c| matches!(c.contramedida, crate::antivm::Contramedida::Ninguna { .. })),
            "el informe tiene que llevar lo que NO se contrarresta"
        );
    }

    #[test]
    fn el_informe_va_y_vuelve_por_json() {
        let i = informe_de(vec![escribe("/tmp/x")], Final::Termino { codigo: 0 });
        let texto = serde_json::to_string(&i).unwrap();
        let vuelta: Informe = serde_json::from_str(&texto).unwrap();
        assert_eq!(vuelta, i);
        assert_eq!(vuelta.huella(), i.huella());
    }

    #[test]
    fn con_agente_dentro_y_cero_eventos_no_hay_camino_a_sin_hallazgos() {
        // El caso que esta fase existe para cerrar, y el mas enganoso de todos:
        // la detonacion salio bien, la muestra arranco y termino limpiamente, y
        // no se vio absolutamente nada. Con un agente dentro eso es
        // indistinguible de que la muestra lo encontrara y se marchara.
        let i = informe_en(Vec::new(), Final::Termino { codigo: 0 }, Modo::ConAgente);
        assert!(!i.completo());
        let v = i.veredicto();
        assert!(matches!(v, Veredicto::NoConcluyente { .. }), "{v:?}");
        if let Veredicto::NoConcluyente { motivo } = v {
            assert!(motivo.contains("encontrara el agente"), "{motivo}");
            assert!(
                motivo.contains("lista de procesos"),
                "el motivo tiene que decir QUE pudo mirar la muestra: {motivo}"
            );
        }
    }

    #[test]
    fn en_modo_fantasma_cero_eventos_si_deja_concluir() {
        // Sin nada dentro que encontrar, no haber hecho nada es no haber hecho
        // nada. Es exactamente lo que el modo fantasma compra, y si no lo
        // comprara no habria razon para tenerlo.
        let i = informe_en(Vec::new(), Final::Termino { codigo: 0 }, Modo::Fantasma);
        assert!(i.completo());
        assert!(
            matches!(i.veredicto(), Veredicto::SinHallazgos),
            "{:?}",
            i.veredicto()
        );
    }

    #[test]
    fn el_catalogo_de_delatores_cambia_con_el_modo() {
        // Sin esto, declarar el modo no diria nada. El catalogo anti-VM general
        // dice que se contrarresta del ENTORNO; este dice que se contrarresta de
        // la OBSERVACION, y son dos mitades distintas.
        let con = informe_en(
            vec![escribe("/tmp/x")],
            Final::Termino { codigo: 0 },
            Modo::ConAgente,
        );
        let sin = informe_en(
            vec![escribe("/tmp/x")],
            Final::Termino { codigo: 0 },
            Modo::Fantasma,
        );
        assert_eq!(con.delatores_del_modo().len(), 4);
        assert_eq!(sin.delatores_del_modo().len(), 1);
        for d in con.delatores_del_modo() {
            assert!(
                !sin.delatores_del_modo().contains(d),
                "{d:?} tendria que desaparecer sin agente dentro"
            );
        }
    }

    #[test]
    fn el_modo_sobrevive_a_guardar_y_recuperar_el_informe() {
        // Un informe archivado se lee meses despues. Si el modo se perdiera por
        // el camino, el informe quedaria diciendo algo cierto y enganoso.
        let i = informe_en(
            vec![escribe("/tmp/x")],
            Final::Termino { codigo: 0 },
            Modo::ConAgente,
        );
        let texto = serde_json::to_string(&i).unwrap();
        assert!(texto.contains("con-agente"), "va por su nombre: {texto}");
        let vuelta: Informe = serde_json::from_str(&texto).unwrap();
        assert_eq!(vuelta.modo, Modo::ConAgente);
    }

    #[test]
    fn un_modo_desconocido_en_un_informe_guardado_es_un_error_y_no_un_valor_por_defecto() {
        // Dar por bueno el modo equivocado es peor que no poder leer el informe,
        // porque nadie lo notaria: el informe seguiria pareciendo valido y
        // diria otra cosa de lo que se pudo ver.
        let i = informe_en(
            vec![escribe("/tmp/x")],
            Final::Termino { codigo: 0 },
            Modo::ConAgente,
        );
        let texto = serde_json::to_string(&i)
            .unwrap()
            .replace("con-agente", "lo-que-sea");
        let r: Result<Informe, _> = serde_json::from_str(&texto);
        assert!(r.is_err(), "un modo desconocido tiene que ser un error");
    }
}
