//! El `AegisQLRunner`: evalua un plan contra el estado REAL del endpoint.
//!
//! No hay capa de abstraccion entre esto y el sistema, y es deliberado. Un
//! ejecutor que habla con una interfaz «fuente de datos» se prueba contra una
//! implementacion de mentira, y lo que se demuestra entonces es que el evaluador
//! funciona contra esa mentira. Aqui se lee /proc, la tabla de sockets y el
//! grafo de comportamiento de verdad, y las pruebas se ejecutan contra la
//! maquina que las corre: si `SELECT pid FROM processes WHERE pid = <el mio>`
//! no encuentra el proceso de prueba, es que algo esta roto de verdad.
//!
//! # Presupuesto
//!
//! Toda ejecucion tiene un tope de tiempo. Un endpoint es la maquina de trabajo
//! de alguien, o un servidor de produccion; una caceria mal escrita no puede
//! quedarse minutos hurgando en /proc. Al agotarse el presupuesto se devuelve
//! lo encontrado hasta ese momento, marcado como incompleto — nunca un error
//! vacio, porque los resultados parciales de una caceria siguen siendo utiles.
//!
//! # Honestidad sobre lo que no se pudo ver
//!
//! El resultado lleva la cuenta de valores que no se pudieron obtener. Un
//! analista tiene que poder distinguir «no hay nada» de «no pude mirar»: si un
//! agente corre sin privilegios y no puede leer la memoria de otros usuarios,
//! una caceria de inyeccion que devuelve cero filas no significa que la maquina
//! este limpia.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use aegis_behavior::dag::{BehaviorGraph, EdgeKind};
use aegis_parser::ast::{Expr, Proyeccion};
use aegis_parser::plan::{columnas_de_asterisco, Plan};
use aegis_scal::linux::net::{self, Socket};
use aegis_scal::memory::{MemoryRegion, Perms};
use aegis_scal::process::ProcessInfo;

use crate::entropia;
use crate::valor::Valor;

/// Presupuesto de tiempo por defecto para una consulta.
///
/// Cinco segundos es lo que tarda una caceria cara (hashes, entropia) sobre un
/// sistema con unos miles de procesos, y sigue siendo imperceptible para quien
/// esta usando la maquina.
pub const PRESUPUESTO_POR_DEFECTO: Duration = Duration::from_secs(5);

/// Bytes maximos que se muestrean de una region de memoria para la entropia.
///
/// La entropia converge muy rapido: con 64 KiB el valor ya es estable. Leer
/// regiones enteras de cientos de megabytes multiplicaria el coste sin cambiar
/// la respuesta, y ademas mantendria mapeada memoria ajena mas tiempo del
/// necesario.
pub const MUESTRA_MEMORIA: usize = 64 * 1024;

/// Tamano maximo de ejecutable que se hashea.
///
/// Por encima de esto el valor queda ausente y se cuenta como inaccesible. Un
/// hash parcial NO es una alternativa: seria un valor que parece un hash, no
/// coincide con el de nadie, y haria creer que el fichero es desconocido.
pub const HASH_MAXIMO: u64 = 512 * 1024 * 1024;

/// Resultado de ejecutar una consulta en un endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resultado {
    /// Nombres de las columnas devueltas, en orden.
    pub columnas: Vec<String>,
    /// Filas, ya convertidas a texto para el transporte.
    pub filas: Vec<Vec<String>>,
    /// Filas que pasaron el filtro, aunque no se devolvieran todas por el
    /// `LIMIT`. Es lo que responde `COUNT(*)`.
    pub coincidencias: u64,
    /// Filas examinadas.
    pub examinadas: u64,
    /// Valores que no se pudieron obtener. Ver la nota de cabecera.
    pub inaccesibles: u64,
    /// Cierto si se corto por `LIMIT` o por presupuesto.
    pub incompleto: bool,
    /// Cierto si se corto por PRESUPUESTO, que es un aviso distinto: significa
    /// que la consulta es demasiado cara para este endpoint.
    pub agotado: bool,
    /// Milisegundos empleados.
    pub duracion_ms: u64,
}

/// Ejecuta consultas contra este endpoint.
pub struct Ejecutor<'a> {
    grafo: Option<&'a BehaviorGraph>,
    yara: Option<&'a aegis_scan::YaraEngine>,
    presupuesto: Duration,
}

impl<'a> Ejecutor<'a> {
    /// Ejecutor sin acceso al grafo de comportamiento.
    ///
    /// Las columnas `graph.*` quedaran ausentes, y contadas como inaccesibles:
    /// el analista vera que esa parte de su caceria no se pudo responder.
    pub fn nuevo() -> Ejecutor<'a> {
        Ejecutor {
            grafo: None,
            yara: None,
            presupuesto: PRESUPUESTO_POR_DEFECTO,
        }
    }

    /// Ejecutor con acceso al grafo de comportamiento del agente.
    pub fn con_grafo(grafo: &'a BehaviorGraph) -> Ejecutor<'a> {
        Ejecutor {
            grafo: Some(grafo),
            yara: None,
            presupuesto: PRESUPUESTO_POR_DEFECTO,
        }
    }

    /// Da al ejecutor el motor YARA que la tabla `memory` necesita para escanear
    /// la memoria de los procesos (FASE 57). Sin el, una consulta a `memory`
    /// responde que no se pudo (inaccesible), nunca finge que no habia nada.
    #[must_use]
    pub fn con_yara(mut self, motor: &'a aegis_scan::YaraEngine) -> Ejecutor<'a> {
        self.yara = Some(motor);
        self
    }

    /// Cambia el presupuesto de tiempo.
    pub fn con_presupuesto(mut self, d: Duration) -> Ejecutor<'a> {
        self.presupuesto = d;
        self
    }

    /// Ejecuta un plan.
    pub fn ejecutar(&self, plan: &Plan) -> Resultado {
        let reloj = Instant::now();
        let mut r = match plan.consulta.tabla {
            "processes" => self.tabla_procesos(plan, reloj),
            "connections" => self.tabla_conexiones(plan, reloj),
            "memory_regions" => self.tabla_memoria(plan, reloj),
            "memory" => self.tabla_yara(plan, reloj),
            "graph_edges" => self.tabla_aristas(plan, reloj),
            // El analizador no deja pasar otra tabla. Si llegara, devolver
            // vacio es preferible a entrar en panico dentro del agente.
            _ => Resultado::default(),
        };
        r.duracion_ms = reloj.elapsed().as_millis() as u64;
        r
    }

    /// Columnas que hay que devolver segun la proyeccion.
    fn columnas_de_salida(&self, plan: &Plan) -> Vec<String> {
        match &plan.consulta.proyeccion {
            Proyeccion::Columnas(cols) => cols.iter().map(|c| c.nombre.to_string()).collect(),
            Proyeccion::Todo => columnas_de_asterisco(plan.consulta.tabla)
                .into_iter()
                .map(str::to_string)
                .collect(),
            Proyeccion::Cuenta => vec!["count".to_string()],
        }
    }

    // -----------------------------------------------------------------------
    // processes
    // -----------------------------------------------------------------------

    fn tabla_procesos(&self, plan: &Plan, reloj: Instant) -> Resultado {
        let mut r = Resultado {
            columnas: self.columnas_de_salida(plan),
            ..Default::default()
        };

        let procesos = match listar_procesos() {
            Some(p) => p,
            None => return r,
        };

        // El plan dice que columnas hacen falta, asi que los datos caros y
        // COMPARTIDOS entre filas se preparan una sola vez. Enumerar la tabla
        // de sockets por proceso convertiria una consulta en O(n^2).
        let necesita_red = plan
            .columnas_necesarias
            .iter()
            .any(|c| c.starts_with("network."));
        let sockets_por_pid = if necesita_red {
            indexar_sockets_por_pid()
        } else {
            HashMap::new()
        };

        let salida = self.columnas_de_salida(plan);
        for p in procesos {
            if reloj.elapsed() > self.presupuesto {
                r.agotado = true;
                r.incompleto = true;
                break;
            }
            r.examinadas += 1;

            let mut fila = FilaProceso {
                info: &p,
                sockets: sockets_por_pid.get(&p.key.pid).map(Vec::as_slice),
                grafo: self.grafo,
                regiones: None,
                inaccesibles: 0,
            };

            if let Some(f) = &plan.consulta.filtro {
                if !evaluar(f, &mut fila) {
                    r.inaccesibles += fila.inaccesibles;
                    continue;
                }
            }
            r.coincidencias += 1;

            if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta)
                && r.filas.len() < plan.consulta.limite as usize
            {
                r.filas
                    .push(salida.iter().map(|c| fila.valor(c).a_texto()).collect());
            } else if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
                r.incompleto = true;
            }
            r.inaccesibles += fila.inaccesibles;
        }

        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            r.filas = vec![vec![r.coincidencias.to_string()]];
        }
        r
    }

    // -----------------------------------------------------------------------
    // connections
    // -----------------------------------------------------------------------

    fn tabla_conexiones(&self, plan: &Plan, reloj: Instant) -> Resultado {
        let mut r = Resultado {
            columnas: self.columnas_de_salida(plan),
            ..Default::default()
        };
        let salida = self.columnas_de_salida(plan);

        for s in net::sockets() {
            if reloj.elapsed() > self.presupuesto {
                r.agotado = true;
                r.incompleto = true;
                break;
            }
            r.examinadas += 1;
            let mut fila = FilaSocket { socket: &s };
            if let Some(f) = &plan.consulta.filtro {
                if !evaluar(f, &mut fila) {
                    continue;
                }
            }
            r.coincidencias += 1;
            if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
                if r.filas.len() < plan.consulta.limite as usize {
                    r.filas
                        .push(salida.iter().map(|c| fila.valor(c).a_texto()).collect());
                } else {
                    r.incompleto = true;
                }
            }
        }
        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            r.filas = vec![vec![r.coincidencias.to_string()]];
        }
        r
    }

    // -----------------------------------------------------------------------
    // memory_regions
    // -----------------------------------------------------------------------

    fn tabla_memoria(&self, plan: &Plan, reloj: Instant) -> Resultado {
        let mut r = Resultado {
            columnas: self.columnas_de_salida(plan),
            ..Default::default()
        };
        let salida = self.columnas_de_salida(plan);
        let necesita_entropia = plan.columnas_necesarias.contains(&"entropy");

        let procesos = match listar_procesos() {
            Some(p) => p,
            None => return r,
        };

        for p in procesos {
            if reloj.elapsed() > self.presupuesto {
                r.agotado = true;
                r.incompleto = true;
                break;
            }
            let pid = p.key.pid;
            let Ok(regiones) = aegis_scal::linux::memory::regions_of(pid as i32) else {
                // Proceso de otro usuario o ya muerto: no se puede mirar, y se
                // dice en la cuenta en vez de fingir que no habia nada.
                r.inaccesibles += 1;
                continue;
            };
            for region in regiones {
                if reloj.elapsed() > self.presupuesto {
                    r.agotado = true;
                    r.incompleto = true;
                    break;
                }
                r.examinadas += 1;
                let mut fila = FilaRegion {
                    pid,
                    region: &region,
                    entropia: None,
                    calculada: !necesita_entropia,
                    inaccesibles: 0,
                };
                if let Some(f) = &plan.consulta.filtro {
                    if !evaluar(f, &mut fila) {
                        r.inaccesibles += fila.inaccesibles;
                        continue;
                    }
                }
                r.coincidencias += 1;
                if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
                    if r.filas.len() < plan.consulta.limite as usize {
                        r.filas
                            .push(salida.iter().map(|c| fila.valor(c).a_texto()).collect());
                    } else {
                        r.incompleto = true;
                    }
                }
                r.inaccesibles += fila.inaccesibles;
            }
        }
        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            r.filas = vec![vec![r.coincidencias.to_string()]];
        }
        r
    }

    // -----------------------------------------------------------------------
    // memory (RAM hunting con YARA, FASE 57)
    // -----------------------------------------------------------------------

    /// `SELECT pid FROM memory WHERE yara_match = 'RULE'`: por cada proceso,
    /// escanea su memoria con `AegisMemScanner` y expone el conjunto de reglas
    /// que coincidieron. El estrangulado real de E/S/CPU lo pone el SO por fuera
    /// (cgroups/Job Objects, gated); aqui el limite es el presupuesto de tiempo.
    fn tabla_yara(&self, plan: &Plan, reloj: Instant) -> Resultado {
        let mut r = Resultado {
            columnas: self.columnas_de_salida(plan),
            ..Default::default()
        };
        let salida = self.columnas_de_salida(plan);

        // Sin motor YARA cargado no se puede escanear: se dice, no se finge.
        let Some(motor) = self.yara else {
            r.inaccesibles += 1;
            return r;
        };
        let procesos = match listar_procesos() {
            Some(p) => p,
            None => return r,
        };
        let escaner =
            aegis_scan::AegisMemScanner::nuevo(motor, aegis_scan::ConfigEscaner::default());

        for p in procesos {
            if reloj.elapsed() > self.presupuesto {
                r.agotado = true;
                r.incompleto = true;
                break;
            }
            r.examinadas += 1;
            let pid = p.key.pid;
            let fuente = FuenteProceso { pid };
            let mut reglas = match escaner.escanear(&fuente, &mut aegis_scan::SinEstrangular) {
                Ok(cs) => cs.into_iter().map(|c| c.regla).collect::<Vec<_>>(),
                Err(_) => {
                    // Memoria de otro usuario o proceso muerto: no se pudo mirar.
                    r.inaccesibles += 1;
                    continue;
                }
            };
            reglas.sort();
            reglas.dedup();

            let mut fila = FilaMemoriaYara { pid, reglas };
            if let Some(f) = &plan.consulta.filtro {
                if !evaluar(f, &mut fila) {
                    continue;
                }
            }
            r.coincidencias += 1;
            if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
                if r.filas.len() < plan.consulta.limite as usize {
                    r.filas
                        .push(salida.iter().map(|c| fila.valor(c).a_texto()).collect());
                } else {
                    r.incompleto = true;
                }
            }
        }
        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            r.filas = vec![vec![r.coincidencias.to_string()]];
        }
        r
    }

    // -----------------------------------------------------------------------
    // graph_edges
    // -----------------------------------------------------------------------

    fn tabla_aristas(&self, plan: &Plan, _reloj: Instant) -> Resultado {
        let mut r = Resultado {
            columnas: self.columnas_de_salida(plan),
            ..Default::default()
        };
        let salida = self.columnas_de_salida(plan);

        let Some(grafo) = self.grafo else {
            // Sin grafo no hay aristas que ofrecer. Se marca como inaccesible
            // para que el analista sepa que la pregunta no se pudo responder.
            r.inaccesibles = 1;
            return r;
        };

        for (origen, arista) in aristas_de(grafo) {
            r.examinadas += 1;
            let mut fila = FilaArista {
                src_pid: origen,
                dst_pid: arista.peer.pid,
                kind: nombre_arista(arista.kind),
                ts_ns: arista.ts_ns,
            };
            if let Some(f) = &plan.consulta.filtro {
                if !evaluar(f, &mut fila) {
                    continue;
                }
            }
            r.coincidencias += 1;
            if !matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
                if r.filas.len() < plan.consulta.limite as usize {
                    r.filas
                        .push(salida.iter().map(|c| fila.valor(c).a_texto()).collect());
                } else {
                    r.incompleto = true;
                }
            }
        }
        if matches!(plan.consulta.proyeccion, Proyeccion::Cuenta) {
            r.filas = vec![vec![r.coincidencias.to_string()]];
        }
        r
    }
}

impl Default for Ejecutor<'_> {
    fn default() -> Self {
        Ejecutor::nuevo()
    }
}

// ---------------------------------------------------------------------------
// Evaluacion del filtro
// ---------------------------------------------------------------------------

/// Una fila capaz de dar el valor de una columna.
///
/// Es `&mut self` porque las columnas caras se calculan la primera vez que se
/// piden y se recuerdan: dentro de una misma fila, `memory.entropy > 7 OR
/// memory.entropy < 1` no puede leer la memoria dos veces.
trait Fila {
    /// Valor para la PROYECCION: uno solo, porque una celda es una celda.
    fn valor(&mut self, columna: &str) -> Valor;

    /// Comprueba un predicado para el FILTRO.
    ///
    /// Existe aparte de `valor` porque algunas columnas son multivaluadas. Un
    /// proceso tiene N conexiones, y `network.port = 4444` significa «ALGUNA de
    /// sus conexiones usa el puerto 4444»: preguntarselo solo a la primera
    /// daria una respuesta falsa en cuanto el proceso tenga mas de un socket
    /// —que es el caso de cualquier servidor—, y la caceria no encontraria la
    /// baliza que esta buscando.
    ///
    /// El cuantificador envuelve al predicado ENTERO, incluido su operador. De
    /// ahi se sigue una simetria util:
    ///
    /// ```text
    ///     network.port != 4444    hay ALGUNA conexion a un puerto distinto
    /// NOT network.port  = 4444    NO hay NINGUNA conexion al 4444
    /// ```
    ///
    /// Las dos formas hacen falta y significan cosas distintas.
    fn alguno(&mut self, columna: &str, pred: &mut dyn FnMut(&Valor) -> bool) -> bool {
        let v = self.valor(columna);
        pred(&v)
    }
}

/// Evalua un filtro sobre una fila.
///
/// Los operadores cortocircuitan: en un AND, el primer falso descarta la fila
/// sin evaluar el resto. Eso es lo que hace util el orden que dejo el
/// planificador; sin cortocircuito, reordenar no ahorraria nada.
fn evaluar(e: &Expr, fila: &mut impl Fila) -> bool {
    match e {
        Expr::Comparacion { columna, op, valor } => {
            fila.alguno(columna, &mut |v| v.compara(*op, valor))
        }
        Expr::Like {
            columna,
            patron,
            negado,
        } => {
            // El cuantificador envuelve el LIKE; la negacion envuelve el
            // cuantificador. `NOT LIKE` significa «ninguno casa», no «alguno no
            // casa»: si no, cualquier proceso con dos rutas distintas cumpliria
            // las dos condiciones a la vez.
            //
            // Un valor ausente no casa nunca, y por tanto tampoco satisface un
            // `NOT LIKE` por si solo: devolver cierto para algo que no se pudo
            // leer llenaria el resultado de filas sobre las que no se sabe nada.
            let alguno = fila.alguno(columna, &mut |v| !v.es_ausente() && v.casa_patron(patron));
            alguno != *negado
        }
        Expr::En {
            columna,
            valores,
            negado,
        } => {
            let alguno = fila.alguno(columna, &mut |v| {
                !v.es_ausente()
                    && valores
                        .iter()
                        .any(|l| v.compara(aegis_parser::ast::Comparador::Igual, l))
            });
            alguno != *negado
        }
        Expr::Bandera { columna } => {
            fila.alguno(columna, &mut |v| matches!(v, Valor::Booleano(true)))
        }
        // Los operadores cortocircuitan: en un AND, el primer falso descarta la
        // fila sin evaluar el resto. Eso es lo que hace util el orden que dejo
        // el planificador; sin cortocircuito, reordenar no ahorraria nada.
        Expr::Y(a, b) => evaluar(a, fila) && evaluar(b, fila),
        Expr::O(a, b) => evaluar(a, fila) || evaluar(b, fila),
        Expr::No(a) => !evaluar(a, fila),
    }
}

// ---------------------------------------------------------------------------
// Filas concretas
// ---------------------------------------------------------------------------

struct FilaProceso<'a> {
    info: &'a ProcessInfo,
    sockets: Option<&'a [Socket]>,
    grafo: Option<&'a BehaviorGraph>,
    regiones: Option<Vec<MemoryRegion>>,
    inaccesibles: u64,
}

impl FilaProceso<'_> {
    /// Regiones de memoria del proceso, leidas como mucho una vez.
    fn regiones(&mut self) -> &[MemoryRegion] {
        if self.regiones.is_none() {
            self.regiones = Some(
                aegis_scal::linux::memory::regions_of(self.info.key.pid as i32).unwrap_or_default(),
            );
        }
        self.regiones.as_deref().unwrap_or(&[])
    }

    /// Regiones privadas y ejecutables: el indicio clasico de codigo inyectado.
    fn privadas_ejecutables(&mut self) -> Vec<MemoryRegion> {
        self.regiones()
            .iter()
            .filter(|r| es_privada_ejecutable(r))
            .cloned()
            .collect()
    }
}

/// Una region privada y ejecutable no respaldada por fichero.
///
/// El codigo legitimo se ejecuta desde una region respaldada por el binario o
/// una biblioteca. Una region ANONIMA con permiso de ejecucion es memoria que
/// alguien escribio y despues marco ejecutable, que es la firma de cualquier
/// cargador reflectante.
fn es_privada_ejecutable(r: &MemoryRegion) -> bool {
    let p: Perms = r.perms;
    p.exec && p.private && r.path.is_none()
}

impl Fila for FilaProceso<'_> {
    /// Las columnas de red son multivaluadas: un proceso tiene N conexiones.
    /// El resto delega en la implementacion por defecto.
    fn alguno(&mut self, columna: &str, pred: &mut dyn FnMut(&Valor) -> bool) -> bool {
        if !columna.starts_with("network.") {
            let v = self.valor(columna);
            return pred(&v);
        }
        let Some(sockets) = self.sockets else {
            // El proceso no tiene ningun socket, o no se pudo atribuir ninguno.
            // Un conjunto vacio no satisface un cuantificador existencial.
            return pred(&Valor::Ausente);
        };
        sockets
            .iter()
            .any(|s| pred(&FilaProceso::valor_de_socket(columna, s)))
    }

    fn valor(&mut self, columna: &str) -> Valor {
        match columna {
            "pid" => Valor::Entero(i64::from(self.info.key.pid)),
            "ppid" => Valor::Entero(i64::from(self.info.parent_pid)),
            "start_ns" => Valor::Entero(self.info.key.start_stamp as i64),
            "uid" => Valor::Entero(i64::from(self.info.uid)),
            "gid" => Valor::Entero(i64::from(self.info.gid)),
            "threads" => Valor::Entero(i64::from(self.info.threads)),
            "state" => Valor::Texto(format!("{:?}", self.info.state).to_lowercase()),
            "name" => match self.info.image_name() {
                Some(n) => Valor::Texto(n.to_string()),
                None => {
                    self.inaccesibles += 1;
                    Valor::Ausente
                }
            },
            "path" => match &self.info.image {
                Some(p) => Valor::Texto(p.to_string_lossy().into_owned()),
                None => {
                    self.inaccesibles += 1;
                    Valor::Ausente
                }
            },
            "cmdline" => Valor::Texto(self.info.cmdline.join(" ")),
            "sha256" => match &self.info.image {
                Some(p) => match hash_de_fichero(p) {
                    Some(h) => Valor::Texto(h),
                    None => {
                        self.inaccesibles += 1;
                        Valor::Ausente
                    }
                },
                None => {
                    self.inaccesibles += 1;
                    Valor::Ausente
                }
            },

            "network.port" | "network.local_port" | "network.remote_ip" | "network.state" => {
                self.valor_de_red(columna)
            }

            "memory.rwx" => {
                let hay = self.regiones().iter().any(|r| r.perms.is_rwx());
                Valor::Booleano(hay)
            }
            "memory.private_exec" => {
                let n = self.privadas_ejecutables().len();
                Valor::Entero(n as i64)
            }
            "memory.entropy" => self.entropia_maxima(),

            "graph.techniques" | "graph.depth" | "graph.injected_by" => {
                self.valor_de_grafo(columna)
            }

            // El analizador impide llegar aqui con otra columna.
            _ => Valor::Ausente,
        }
    }
}

impl FilaProceso<'_> {
    /// Valor de una columna de red para UN socket concreto.
    fn valor_de_socket(columna: &str, s: &Socket) -> Valor {
        match columna {
            "network.port" => Valor::Entero(i64::from(s.puerto_remoto)),
            "network.local_port" => Valor::Entero(i64::from(s.puerto_local)),
            "network.remote_ip" => Valor::Texto(s.ip_remota.to_string()),
            "network.state" => Valor::Texto(s.estado.as_str().to_string()),
            _ => Valor::Ausente,
        }
    }

    /// Valor de red para la PROYECCION: el del primer socket.
    ///
    /// Una celda no puede contener N valores. Para el FILTRO no se usa esto
    /// sino `alguno`, que recorre todos los sockets del proceso.
    fn valor_de_red(&mut self, columna: &str) -> Valor {
        match self.sockets.and_then(<[Socket]>::first) {
            Some(s) => FilaProceso::valor_de_socket(columna, s),
            None => Valor::Ausente,
        }
    }

    /// Entropia maxima entre las regiones privadas y ejecutables.
    fn entropia_maxima(&mut self) -> Valor {
        let pid = self.info.key.pid as i32;
        let regiones = self.privadas_ejecutables();
        if regiones.is_empty() {
            // No es un fallo: la inmensa mayoria de procesos no tiene ninguna.
            // Cero es la respuesta correcta, no un valor ausente.
            return Valor::Real(0.0);
        }
        let mut peor = 0.0f64;
        let mut alguna = false;
        for r in regiones {
            let largo = (r.len() as usize).min(MUESTRA_MEMORIA);
            let Ok(datos) = aegis_scal::linux::memory::read_memory(pid, r.start, largo) else {
                continue;
            };
            if let Some(h) = entropia::shannon(&datos) {
                alguna = true;
                if h > peor {
                    peor = h;
                }
            }
        }
        if alguna {
            Valor::Real(peor)
        } else {
            self.inaccesibles += 1;
            Valor::Ausente
        }
    }

    fn valor_de_grafo(&mut self, columna: &str) -> Valor {
        let Some(g) = self.grafo else {
            self.inaccesibles += 1;
            return Valor::Ausente;
        };
        let Some(key) = g.key_of_pid(self.info.key.pid) else {
            // El grafo aun no conoce este proceso: es normal justo despues de
            // arrancar el agente.
            return Valor::Ausente;
        };
        match columna {
            "graph.techniques" => match g.node(key) {
                Some(n) => Valor::Entero(n.techniques.len() as i64),
                None => Valor::Ausente,
            },
            // `causal_path` incluye al propio nodo, asi que la profundidad es
            // el camino menos uno: la raiz esta a profundidad 0.
            "graph.depth" => Valor::Entero(g.causal_path(key).len().saturating_sub(1) as i64),
            "graph.injected_by" => {
                let quien = g.node(key).and_then(|n| {
                    n.incoming
                        .iter()
                        .find(|e| e.kind == EdgeKind::Injected)
                        .map(|e| e.peer.pid)
                });
                Valor::Entero(i64::from(quien.unwrap_or(0)))
            }
            _ => Valor::Ausente,
        }
    }
}

struct FilaSocket<'a> {
    socket: &'a Socket,
}

impl Fila for FilaSocket<'_> {
    fn valor(&mut self, columna: &str) -> Valor {
        match columna {
            "pid" => Valor::Entero(i64::from(self.socket.pid)),
            "protocol" => Valor::Texto(self.socket.protocolo.to_string()),
            "local_port" => Valor::Entero(i64::from(self.socket.puerto_local)),
            "remote_ip" => Valor::Texto(self.socket.ip_remota.to_string()),
            "remote_port" => Valor::Entero(i64::from(self.socket.puerto_remoto)),
            "state" => Valor::Texto(self.socket.estado.as_str().to_string()),
            _ => Valor::Ausente,
        }
    }
}

/// Fuente de memoria de un proceso vivo para `AegisMemScanner`: lee sus regiones
/// privadas legibles (donde vive el codigo inyectado o desempaquetado) a traves
/// de la capa de acceso a memoria del agente.
///
/// Leer la memoria de OTRO proceso necesita privilegios (o el driver de las
/// FASES de kernel); donde no se pueda, `leer` falla y la caza lo cuenta como
/// inaccesible en vez de fingir que no habia nada. Esa es la parte gated.
struct FuenteProceso {
    pid: u32,
}

impl aegis_scan::FuenteMemoria for FuenteProceso {
    fn regiones(&self) -> Vec<aegis_scan::RegionMem> {
        let Ok(regiones) = aegis_scal::linux::memory::regions_of(self.pid as i32) else {
            return Vec::new();
        };
        regiones
            .into_iter()
            // Regiones privadas y legibles: el codigo inyectado/desempaquetado
            // vive ahi. Saltarse las respaldadas por fichero acota el coste y el
            // ruido (una libc no es un hallazgo).
            .filter(|r| r.perms.read && r.perms.private)
            .map(|r| aegis_scan::RegionMem {
                base: r.start,
                len: r.len(),
                etiqueta: format!("pid {} {:#x}", self.pid, r.start),
            })
            .collect()
    }

    fn leer(&self, base: u64, len: usize) -> Result<Vec<u8>, aegis_scan::MemScanError> {
        aegis_scal::linux::memory::read_memory(self.pid as i32, base, len)
            .map_err(|e| aegis_scan::MemScanError::Lectura(base, e.to_string()))
    }
}

/// Fila de la tabla `memory`: un proceso y el conjunto de reglas YARA que
/// coincidieron en su memoria. `yara_match` es multi-valor, asi que el filtro lo
/// trata como cuantificador existencial (igual que `network.port`).
struct FilaMemoriaYara {
    pid: u32,
    reglas: Vec<String>,
}

impl Fila for FilaMemoriaYara {
    fn valor(&mut self, columna: &str) -> Valor {
        match columna {
            "pid" => Valor::Entero(i64::from(self.pid)),
            // Para la PROYECCION, una celda no puede tener N valores: se da la
            // primera regla que coincidio (o ausente). El FILTRO usa `alguno`.
            "yara_match" => match self.reglas.first() {
                Some(regla) => Valor::Texto(regla.clone()),
                None => Valor::Ausente,
            },
            _ => Valor::Ausente,
        }
    }

    fn alguno(&mut self, columna: &str, pred: &mut dyn FnMut(&Valor) -> bool) -> bool {
        if columna == "yara_match" {
            // Cuantificador existencial sobre las reglas que coincidieron.
            return self
                .reglas
                .iter()
                .any(|regla| pred(&Valor::Texto(regla.clone())));
        }
        pred(&self.valor(columna))
    }
}

struct FilaRegion<'a> {
    pid: u32,
    region: &'a MemoryRegion,
    entropia: Option<f64>,
    calculada: bool,
    inaccesibles: u64,
}

impl Fila for FilaRegion<'_> {
    fn valor(&mut self, columna: &str) -> Valor {
        match columna {
            "pid" => Valor::Entero(i64::from(self.pid)),
            "start" => Valor::Entero(self.region.start as i64),
            "size" => Valor::Entero(self.region.len() as i64),
            "perms" => Valor::Texto(formato_permisos(self.region.perms)),
            "private" => Valor::Booleano(self.region.perms.private),
            "path" => Valor::Texto(self.region.path.clone().unwrap_or_default()),
            "entropy" => {
                if !self.calculada {
                    let largo = (self.region.len() as usize).min(MUESTRA_MEMORIA);
                    self.entropia = aegis_scal::linux::memory::read_memory(
                        self.pid as i32,
                        self.region.start,
                        largo,
                    )
                    .ok()
                    .and_then(|d| entropia::shannon(&d));
                    self.calculada = true;
                }
                match self.entropia {
                    Some(h) => Valor::Real(h),
                    None => {
                        self.inaccesibles += 1;
                        Valor::Ausente
                    }
                }
            }
            _ => Valor::Ausente,
        }
    }
}

struct FilaArista {
    src_pid: u32,
    dst_pid: u32,
    kind: &'static str,
    ts_ns: u64,
}

impl Fila for FilaArista {
    fn valor(&mut self, columna: &str) -> Valor {
        match columna {
            "src_pid" => Valor::Entero(i64::from(self.src_pid)),
            "dst_pid" => Valor::Entero(i64::from(self.dst_pid)),
            "kind" => Valor::Texto(self.kind.to_string()),
            "ts_ns" => Valor::Entero(self.ts_ns as i64),
            _ => Valor::Ausente,
        }
    }
}

// ---------------------------------------------------------------------------
// Acceso al sistema
// ---------------------------------------------------------------------------

/// Enumera los procesos del sistema.
fn listar_procesos() -> Option<Vec<ProcessInfo>> {
    use aegis_scal::process::ProcessLifecycleProvider;
    let p = aegis_scal::linux::process::ProcFsProcesses::new();
    p.list().ok()
}

/// Indice pid -> sockets, construido una sola vez por consulta.
fn indexar_sockets_por_pid() -> HashMap<u32, Vec<Socket>> {
    let mut mapa: HashMap<u32, Vec<Socket>> = HashMap::new();
    for s in net::sockets() {
        mapa.entry(s.pid).or_default().push(s);
    }
    mapa
}

/// Permisos en el formato `rwxp` que usa /proc.
fn formato_permisos(p: Perms) -> String {
    format!(
        "{}{}{}{}",
        if p.read { 'r' } else { '-' },
        if p.write { 'w' } else { '-' },
        if p.exec { 'x' } else { '-' },
        if p.private { 'p' } else { 's' }
    )
}

/// Nombre de un tipo de arista tal y como se escribe en una consulta.
fn nombre_arista(k: EdgeKind) -> &'static str {
    match k {
        EdgeKind::Spawned => "spawned",
        EdgeKind::Injected => "injected",
        EdgeKind::Traced => "traced",
        EdgeKind::Wrote => "wrote",
    }
}

/// Aristas salientes del grafo, con el pid de su origen.
fn aristas_de(g: &BehaviorGraph) -> Vec<(u32, aegis_behavior::dag::Edge)> {
    let mut salida = Vec::new();
    for (key, nodo) in g.nodos() {
        for e in &nodo.out {
            salida.push((key.pid, *e));
        }
    }
    salida
}

/// SHA-256 de un fichero.
fn hash_de_fichero(ruta: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::metadata(ruta).ok()?;
    if meta.len() > HASH_MAXIMO {
        // Un hash parcial seria peor que ninguno: parece un hash, no coincide
        // con el de nadie, y haria creer que el fichero es desconocido.
        return None;
    }
    let datos = std::fs::read(ruta).ok()?;
    let mut h = Sha256::new();
    h.update(&datos);
    Some(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod pruebas_yara {
    use super::{Fila, FilaMemoriaYara};
    use crate::valor::Valor;

    #[test]
    fn yara_match_es_existencial_sobre_las_reglas_que_coincidieron() {
        // Un proceso con dos coincidencias: APT29_Core y Cobalt.
        let mut fila = FilaMemoriaYara {
            pid: 42,
            reglas: vec!["APT29_Core".to_string(), "Cobalt".to_string()],
        };
        // `yara_match = 'APT29_Core'`: alguna regla coincide -> cierto.
        assert!(fila.alguno("yara_match", &mut |v| *v
            == Valor::Texto("APT29_Core".into())));
        // `yara_match = 'Mimikatz'`: ninguna -> falso.
        assert!(!fila.alguno("yara_match", &mut |v| *v == Valor::Texto("Mimikatz".into())));
        // La proyeccion de pid es directa.
        assert_eq!(fila.valor("pid"), Valor::Entero(42));
    }

    #[test]
    fn sin_coincidencias_el_conjunto_vacio_no_satisface_el_filtro() {
        let mut fila = FilaMemoriaYara {
            pid: 7,
            reglas: Vec::new(),
        };
        assert_eq!(fila.valor("yara_match"), Valor::Ausente);
        // Un cuantificador existencial sobre un conjunto vacio es falso: un
        // proceso sin coincidencias no aparece en `WHERE yara_match = 'X'`.
        assert!(!fila.alguno("yara_match", &mut |_| true));
    }
}
