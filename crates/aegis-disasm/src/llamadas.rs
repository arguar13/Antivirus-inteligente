//! El grafo de llamadas, con las llamadas indirectas que se pueden resolver.
//!
//! # Por que el grafo de flujo no basta
//!
//! [`crate::cfg`] dice como se mueve el control **dentro** de una funcion. Las
//! reglas de capacidades preguntan otra cosa: que llama a que. «Reserva memoria
//! ejecutable y despues escribe en ella y despues salta» es una frase sobre
//! llamadas, no sobre bloques.
//!
//! # El problema: casi ninguna llamada interesante es directa
//!
//! El codigo que se analiza aqui no llama por nombre. Resuelve la direccion en
//! ejecucion —de la tabla de importaciones, de un recorrido del PEB, de una
//! constante que se desofusca— la deja en un registro y salta a el. Un grafo de
//! llamadas que solo siga las llamadas directas ve un binario que no llama a
//! nadie, y de un binario que no llama a nadie no se puede decir nada.
//!
//! # La solucion, y su limite
//!
//! Se propaga el valor conocido de cada registro a lo largo del grafo de flujo,
//! y cuando la transferencia indirecta sale de un registro cuyo valor se conoce,
//! se resuelve. El modelo que lo hace posible esta en
//! [`crate::instruccion::Registros`], y las distinciones que lleva —escrito
//! frente a definido, leido frente a no leido— estan ahi precisamente para que
//! esto no invente destinos.
//!
//! El limite es duro y se declara: **un destino que viene de memoria no se
//! resuelve aqui**. `call [rip+0x2f10]` lee un puntero que el analisis estatico
//! no conoce; eso lo resuelve la tabla de importaciones del contenedor, que es
//! otra pieza. Cada una de esas sale contada en [`GrafoDeLlamadas::sin_resolver`]
//! con su motivo, y no se disimula: un grafo que callara lo que no alcanza
//! pareceria exhaustivo.
//!
//! # Cuanto resuelve esto de verdad, medido
//!
//! Sobre la libc de una maquina de x86-64, este analisis resuelve **casi
//! ninguna** transferencia indirecta, y conviene decir por que antes de que
//! alguien lo lea como un fallo. De las 690 que quedan sin resolver ahi:
//!
//! - 343 tienen el destino **en memoria** (`call [rip+...]`): son la tabla de
//!   importaciones, y no se resuelven desensamblando por definicion.
//! - 111 salen de una suma de **dos registros** (`add rax, rdx` con `rdx` = base
//!   de una tabla y `rax` = un desplazamiento leido de ella): son tablas de
//!   saltos, y de esas se ocupa [`crate::cfg`] con la cota, no este modulo.
//! - 46 salen de un valor **devuelto por una funcion** que el analisis no ha
//!   mirado.
//! - el resto viene de cargas de memoria o llega por varios caminos con valores
//!   distintos.
//!
//! O sea: en un binario benigno compilado de la forma normal, el patron que este
//! modulo resuelve **casi no aparece**, porque el compilador que conoce la
//! direccion de una funcion emite una llamada directa y no se molesta en
//! materializarla en un registro.
//!
//! Donde si aparece es en lo que hay que analizar: codigo empaquetado que
//! reconstruye direcciones en ejecucion, shellcode, trampolines, y A64 —donde
//! `adrp`+`add`+`blr` es el idioma normal de la arquitectura—. Por eso el modulo
//! existe, y por eso su valor no se mide contando resoluciones sobre `/bin/ls`.
//!
//! # Por que el analisis es «de encuentro» y no de union
//!
//! Cuando dos caminos llegan al mismo bloque con valores distintos en un
//! registro, el resultado es **desconocido**, no uno de los dos. Quedarse con
//! uno daria un destino que solo es cierto por un camino, y una arista cierta a
//! medias en un grafo de llamadas es indistinguible de una falsa para quien la
//! lea despues.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::cfg::Cfg;
use crate::instruccion::{Flujo, Instruccion, MAX_REGISTROS};
use crate::plazo::Plazo;

/// Lo que se sabe del contenido de un registro en un punto del programa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Valor {
    /// No se sabe cuanto vale.
    Desconocido,
    /// Vale exactamente esto, y se establecio en esa direccion.
    ///
    /// La direccion es la evidencia: sin ella, una llamada resuelta es una
    /// afirmacion sin respaldo, y quien lea el informe no tiene como
    /// comprobarla.
    Constante {
        /// El valor.
        valor: u64,
        /// Donde se establecio.
        desde: u64,
    },
}

impl Valor {
    /// El encuentro de dos valores que llegan por caminos distintos.
    ///
    /// Solo sobrevive lo que es cierto por los dos caminos. Si discrepan, el
    /// resultado es desconocido: quedarse con uno daria una arista cierta a
    /// medias, que para quien la lea es indistinguible de una falsa.
    fn encuentro(a: Valor, b: Valor) -> Valor {
        match (a, b) {
            (
                Valor::Constante {
                    valor: va,
                    desde: da,
                },
                Valor::Constante {
                    valor: vb,
                    desde: db,
                },
            ) if va == vb => Valor::Constante {
                valor: va,
                // La menor de las dos, para que el resultado no dependa del
                // orden en que se recorrieron los predecesores. Un analisis que
                // diera evidencias distintas segun el orden del recorrido seria
                // imposible de comparar consigo mismo entre dos ejecuciones.
                desde: da.min(db),
            },
            _ => Valor::Desconocido,
        }
    }
}

/// El estado de los registros seguidos en un punto del programa.
type Estado = [Valor; MAX_REGISTROS as usize];

/// Un estado en el que no se sabe nada.
fn estado_vacio() -> Estado {
    [Valor::Desconocido; MAX_REGISTROS as usize]
}

/// Como se supo el destino de una llamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolucion {
    /// La instruccion lleva el destino escrito.
    Directa,
    /// El destino estaba en un registro cuyo valor se pudo seguir.
    PorConstante {
        /// Que registro lo llevaba.
        registro: u8,
        /// Donde se establecio ese valor. Es la evidencia de la resolucion.
        definido_en: u64,
    },
}

impl Resolucion {
    /// La frase con la que esta resolucion aparece en un informe.
    pub fn frase(&self) -> String {
        match self {
            Resolucion::Directa => "el destino esta escrito en la instruccion".to_owned(),
            Resolucion::PorConstante {
                registro,
                definido_en,
            } => format!(
                "el destino salio del registro {registro}, cuyo valor se fijo en {definido_en:#x}"
            ),
        }
    }
}

/// Por que una transferencia indirecta no se pudo resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// El destino esta en memoria, no en un registro.
    ///
    /// No es un fallo de este analisis: es que el dato no esta en el codigo.
    /// Quien lo resuelve es la tabla de importaciones del contenedor.
    EnMemoria,
    /// El destino esta en un registro cuyo valor no se pudo seguir.
    RegistroDesconocido {
        /// Que registro era.
        registro: u8,
    },
}

impl Motivo {
    /// La frase con la que este motivo aparece en un informe.
    pub fn frase(&self) -> String {
        match self {
            Motivo::EnMemoria => {
                "el destino se lee de memoria, y su contenido no esta en el codigo".to_owned()
            }
            Motivo::RegistroDesconocido { registro } => format!(
                "el destino sale del registro {registro}, cuyo valor llega por mas de un camino \
                 o se calcula con datos que no estan en el codigo"
            ),
        }
    }
}

/// Una arista del grafo de llamadas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Llamada {
    /// Desde donde se llama.
    pub desde: u64,
    /// A donde.
    pub a: u64,
    /// Como se supo.
    pub resolucion: Resolucion,
    /// Si la transferencia era un salto y no una llamada.
    ///
    /// Un salto a la entrada de otra funcion es una llamada de cola: el control
    /// no vuelve aqui, pero la arista del grafo de llamadas es la misma. Se
    /// marca en vez de esconderse porque cambia lo que significa el retorno.
    pub de_cola: bool,
}

/// Una transferencia indirecta que no se pudo resolver.
///
/// Existe como tipo propio, y no como un contador, porque cada una es una rama
/// del programa que el analisis no siguio: al lado de una lista de capacidades,
/// son lo que separa «no hay» de «no se vio».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinResolver {
    /// Donde estaba la transferencia.
    pub desde: u64,
    /// Por que no se resolvio.
    pub motivo: Motivo,
    /// Si era un salto y no una llamada.
    pub de_cola: bool,
}

/// Una funcion descubierta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Funcion {
    /// Su direccion de entrada.
    pub entrada: u64,
    /// Los bloques que le pertenecen.
    pub bloques: Vec<u64>,
    /// Lo que llama, en orden de direccion.
    pub llama_a: Vec<u64>,
}

/// El grafo de llamadas de una region de codigo.
#[derive(Debug, Clone, Default)]
pub struct GrafoDeLlamadas {
    funciones: BTreeMap<u64, Funcion>,
    /// Todas las aristas, en orden de direccion de origen.
    pub llamadas: Vec<Llamada>,
    /// Las transferencias indirectas que quedaron sin resolver.
    pub sin_resolver: Vec<SinResolver>,
    /// Destinos que este analisis descubrio y el grafo de flujo no tenia.
    ///
    /// Un salto indirecto resuelto alcanza codigo que el descenso recursivo no
    /// habia visto. Se exponen para que quien quiera pueda reconstruir el grafo
    /// de flujo con estas entradas anadidas y descubrir mas. **No se hace aqui**:
    /// seria una recursion entre dos analisis cuyo punto fijo no esta acotado, y
    /// esto corre dentro del presupuesto del agente.
    pub descubiertos: Vec<u64>,
    /// Si el analisis se corto por llegar a alguno de sus topes.
    pub cortado: bool,
}

/// Tope de funciones que se descubren.
///
/// Un binario construido para eso puede declarar cien mil puntos de entrada de
/// dos instrucciones. Llegar aqui se declara en [`GrafoDeLlamadas::cortado`].
pub const MAX_FUNCIONES: usize = 100_000;

/// Tope de aristas del grafo.
pub const MAX_LLAMADAS: usize = 1_000_000;

/// Cuantas veces se puede reanalizar un bloque antes de rendirse.
///
/// El analisis converge solo: el valor de un registro solo puede pasar de
/// desconocido a constante y de constante a desconocido, nunca al reves, asi que
/// el numero de cambios por bloque esta acotado por el numero de registros. El
/// tope esta igualmente porque un fallo en esa monotonia seria un bucle infinito
/// dentro del agente, y una cota cuesta una comparacion.
const MAX_VISITAS_POR_BLOQUE: u32 = 4 * MAX_REGISTROS as u32;

impl GrafoDeLlamadas {
    /// Construye el grafo de llamadas sin cota de trabajo.
    ///
    /// Solo para ficheros de confianza (herramientas, pruebas). El analisis de
    /// produccion usa [`GrafoDeLlamadas::construir_con_plazo`].
    pub fn construir(cfg: &Cfg) -> GrafoDeLlamadas {
        GrafoDeLlamadas::construir_con_plazo(cfg, &mut Plazo::sin_cota())
    }

    /// Construye el grafo de llamadas cobrando su trabajo al `plazo` del
    /// analisis. Si se agota, para y lo declara en [`GrafoDeLlamadas::cortado`].
    pub fn construir_con_plazo(cfg: &Cfg, plazo: &mut Plazo) -> GrafoDeLlamadas {
        let mut g = GrafoDeLlamadas::default();

        // Las entradas de funcion son las del grafo de flujo mas los destinos de
        // toda llamada directa. Es lo que se puede afirmar sin suponer nada: una
        // direccion a la que alguien llama es la entrada de una funcion.
        let mut entradas: BTreeSet<u64> = cfg.entradas.iter().copied().collect();
        for i in cfg.instrucciones() {
            if let Flujo::Llamada { destino: Some(d) } = i.flujo {
                if cfg.bloque(d).is_some() {
                    entradas.insert(d);
                }
            }
        }
        if entradas.len() > MAX_FUNCIONES {
            g.cortado = true;
        }

        // El analisis de constantes recorre el grafo de flujo entero una vez,
        // no una vez por funcion: los bloques se comparten y repetirlo seria
        // pagar el mismo trabajo tantas veces como funciones lo alcancen.
        let (salidas, propagacion_cortada) = propaga(cfg, plazo);
        g.cortado |= propagacion_cortada;

        'funciones: for entrada in entradas.iter().take(MAX_FUNCIONES).copied() {
            let bloques = cuerpo(cfg, entrada, &entradas);
            let mut llama_a = BTreeSet::new();
            for b in &bloques {
                let Some(bloque) = cfg.bloque(*b) else {
                    continue;
                };
                if !plazo.cobrar(bloque.instrucciones.len() as u64 + 1) {
                    g.cortado = true;
                    break 'funciones;
                }
                let mut estado = salidas.get(b).copied().unwrap_or_else(estado_vacio);
                for i in &bloque.instrucciones {
                    if let Some(a) = arista(i, &estado) {
                        if g.llamadas.len() >= MAX_LLAMADAS {
                            g.cortado = true;
                            break;
                        }
                        match a {
                            Ok(l) => {
                                llama_a.insert(l.a);
                                if cfg.bloque(l.a).is_none() {
                                    g.descubiertos.push(l.a);
                                }
                                g.llamadas.push(l);
                            }
                            Err(s) => g.sin_resolver.push(s),
                        }
                    }
                    aplica(i, &mut estado);
                }
            }
            g.funciones.insert(
                entrada,
                Funcion {
                    entrada,
                    bloques,
                    llama_a: llama_a.into_iter().collect(),
                },
            );
        }

        // Un mismo bloque puede pertenecer a varias funciones —el codigo
        // compartido existe—, asi que la misma arista puede haberse anotado mas
        // de una vez. Se ordenan y se deduplican para que el grafo diga cuantas
        // llamadas hay y no cuantas veces se miraron.
        g.llamadas.sort_by_key(|l| (l.desde, l.a));
        g.llamadas.dedup();
        g.sin_resolver.sort_by_key(|s| s.desde);
        g.sin_resolver.dedup();
        g.descubiertos.sort_unstable();
        g.descubiertos.dedup();
        g
    }

    /// Las funciones descubiertas, por direccion de entrada.
    pub fn funciones(&self) -> impl Iterator<Item = &Funcion> {
        self.funciones.values()
    }

    /// Cuantas funciones se descubrieron.
    pub fn cuantas_funciones(&self) -> usize {
        self.funciones.len()
    }

    /// Una funcion por su entrada.
    pub fn funcion(&self, entrada: u64) -> Option<&Funcion> {
        self.funciones.get(&entrada)
    }

    /// Cuantas transferencias indirectas se resolvieron.
    pub fn resueltas(&self) -> usize {
        self.llamadas
            .iter()
            .filter(|l| !matches!(l.resolucion, Resolucion::Directa))
            .count()
    }

    /// La frase con la que este grafo aparece en un informe.
    ///
    /// Dice lo que alcanzo **y lo que no**: sin la segunda mitad, una lista de
    /// llamadas corta se lee como «este binario llama a poco», cuando lo que
    /// significa es «no se pudo ver a que llama».
    pub fn frase(&self) -> String {
        let mut s = format!(
            "{} funciones y {} llamadas, de las cuales {} se resolvieron siguiendo \
             el valor de un registro",
            self.funciones.len(),
            self.llamadas.len(),
            self.resueltas()
        );
        if !self.sin_resolver.is_empty() {
            let en_memoria = self
                .sin_resolver
                .iter()
                .filter(|x| x.motivo == Motivo::EnMemoria)
                .count();
            s.push_str(&format!(
                "; {} transferencias indirectas quedaron sin resolver ({en_memoria} de ellas \
                 porque su destino se lee de memoria), y a donde van no se sabe",
                self.sin_resolver.len()
            ));
        }
        if self.cortado {
            s.push_str(". EL GRAFO SE CORTO AL LLEGAR A SU TOPE: hay llamadas que no aparecen");
        }
        s
    }
}

/// La arista que produce una instruccion, si produce alguna.
///
/// Devuelve `Ok` con la arista resuelta, `Err` con la transferencia que no se
/// pudo resolver, y `None` cuando la instruccion no transfiere el control a otra
/// funcion. Las tres son respuestas distintas y se distinguen: confundir la
/// segunda con la tercera es lo que hace que un grafo parezca exhaustivo.
fn arista(i: &Instruccion, estado: &Estado) -> Option<Result<Llamada, SinResolver>> {
    let (indirecta, de_cola) = match i.flujo {
        Flujo::Llamada { destino: Some(a) } => {
            return Some(Ok(Llamada {
                desde: i.direccion,
                a,
                resolucion: Resolucion::Directa,
                de_cola: false,
            }))
        }
        Flujo::Llamada { destino: None } => (true, false),
        // Un salto indirecto puede ser una llamada de cola o un `switch`. Aqui
        // se mira solo el indirecto: los directos ya los siguio el grafo de
        // flujo, y anadirlos aqui duplicaria cada arista interna de cada
        // funcion como si fuera una llamada.
        Flujo::SaltoIncondicional { destino: None } => (true, true),
        _ => return None,
    };
    debug_assert!(indirecta);

    let Some(r) = i.destino_reg else {
        return Some(Err(SinResolver {
            desde: i.direccion,
            motivo: Motivo::EnMemoria,
            de_cola,
        }));
    };
    match estado.get(r as usize) {
        Some(Valor::Constante { valor, desde }) => Some(Ok(Llamada {
            desde: i.direccion,
            a: *valor,
            resolucion: Resolucion::PorConstante {
                registro: r,
                definido_en: *desde,
            },
            de_cola,
        })),
        _ => Some(Err(SinResolver {
            desde: i.direccion,
            motivo: Motivo::RegistroDesconocido { registro: r },
            de_cola,
        })),
    }
}

/// Aplica el efecto de una instruccion al estado de los registros.
///
/// Son tres reglas, y el orden importa: primero lo que define un valor nuevo,
/// despues lo que desplaza uno conocido, y en cualquier otro caso se borra todo
/// lo que la instruccion escriba. **Esa ultima es la que sostiene el resto**: si
/// una instruccion escribe un registro y aqui no se borrara su valor, el
/// analisis seguiria dando por bueno un valor que el programa ya piso.
fn aplica(i: &Instruccion, estado: &mut Estado) {
    // Definicion: el registro pasa a valer exactamente esto, sin depender de
    // nada anterior. Se exige que la instruccion escriba UN registro y que lo
    // deje completamente definido; las dos condiciones las comprueba el modelo,
    // no se suponen aqui.
    if let (Some(v), Some(r)) = (i.valor_definido, i.regs.unico_escrito()) {
        if i.regs.define(r) {
            estado[r as usize] = Valor::Constante {
                valor: v,
                desde: i.direccion,
            };
            return;
        }
    }
    // Copia: el registro hereda el valor de otro. Se lee el estado del origen
    // ANTES de escribir el destino, que con `mov rax, rax` da lo mismo y con
    // cualquier otro par es lo unico correcto.
    if let (Some(origen), Some(r)) = (i.copia_de, i.regs.unico_escrito()) {
        if i.regs.define(r) {
            estado[r as usize] = estado[origen as usize];
            return;
        }
    }
    // Desplazamiento: el registro vale lo que valia mas una constante. Solo si
    // el registro que se escribe es el mismo que se lee; si no, el resultado no
    // tiene nada que ver con el valor anterior.
    if let (Some(d), Some(r)) = (i.delta, i.regs.unico_escrito()) {
        if i.regs.lee(r) {
            estado[r as usize] = match estado[r as usize] {
                Valor::Constante { valor, desde } => Valor::Constante {
                    valor: valor.wrapping_add(d as u64),
                    // La evidencia sigue siendo donde empezo la cadena: es la
                    // instruccion que hay que mirar para comprobar el destino.
                    desde,
                },
                Valor::Desconocido => Valor::Desconocido,
            };
            return;
        }
    }
    // Todo lo demas: lo que la instruccion escriba deja de saberse.
    if i.regs.escritos == 0 {
        return;
    }
    for r in 0..MAX_REGISTROS {
        if i.regs.escribe(r) {
            estado[r as usize] = Valor::Desconocido;
        }
    }
}

/// Propaga el estado de los registros por el grafo de flujo.
///
/// Devuelve, por bloque, el estado a la ENTRADA y a la salida. El de entrada es
/// lo que necesita quien recorra el bloque instruccion a instruccion.
///
/// Termina siempre: el valor de un registro solo puede ir de desconocido a
/// constante —la primera vez que llega— y de constante a desconocido —cuando dos
/// caminos discrepan—, nunca al reves. Como los dos cambios son por registro y
/// por bloque, el numero total de reencolados esta acotado. El tope de visitas
/// esta igualmente, porque un fallo en esa monotonia seria un bucle infinito
/// dentro del agente.
fn propaga(cfg: &Cfg, plazo: &mut Plazo) -> (BTreeMap<u64, Estado>, bool) {
    // SOLO los estados de entrada, y solo los que dicen algo.
    //
    // Antes se guardaban la entrada y la salida de cada bloque, y una copia de
    // las dos en el resultado: tres copias de 32 registros de 24 bytes por
    // bloque, unos 3 KiB. Con los 150.000 bloques de `python3` eran 470 MiB
    // (FASE 1 del MP-16). El grafo de llamadas solo usa la entrada, y la
    // salida se recalcula al propagar; y un estado en el que no se sabe nada es
    // el valor por defecto, asi que no se guarda.
    let mut entrada: BTreeMap<u64, Estado> = BTreeMap::new();
    let vacio = estado_vacio();
    let mut visitas: BTreeMap<u64, u32> = BTreeMap::new();
    let mut cola: VecDeque<u64> = VecDeque::new();
    let mut encolado: BTreeSet<u64> = BTreeSet::new();

    // Se siembra con el estado vacio todo bloque al que el recorrido no vaya a
    // llegar por si solo: los que no tienen predecesor —las entradas, y lo que
    // solo se alcanza por un destino calculado— y los que forman un ciclo al
    // que no se entra desde ninguno de esos. Un bloque al que solo se llega
    // desde fuera del grafo no puede dar por sabido nada de sus registros.
    //
    // La siembra se calcula **una vez**, con una travesia de alcanzabilidad.
    // Comprobarlo dentro del bucle principal —mirar en cada vuelta que bloques
    // siguen sin estado— costaria un recorrido de todos los bloques por
    // iteracion: con el tope de doscientos mil bloques de [`crate::cfg`], eso
    // son cuatro billones de comprobaciones, o sea un cuelgue dentro del
    // agente. El coste aqui es lineal en bloques y aristas.
    // A que bloques ya llego algun estado. Separado de `entrada` porque ahi
    // no estar significa «no se sabe nada», que no es lo mismo que «aun no se
    // llego»: el primer estado que llega se toma tal cual, los siguientes se
    // intersecan con el.
    let mut llegados: BTreeSet<u64> = BTreeSet::new();
    let mut alcanzables: BTreeSet<u64> = BTreeSet::new();
    let mut frente: VecDeque<u64> = cfg
        .bloques()
        .filter(|b| b.predecesores.is_empty())
        .map(|b| b.inicio)
        .collect();
    for d in &frente {
        alcanzables.insert(*d);
    }
    while let Some(d) = frente.pop_front() {
        let Some(b) = cfg.bloque(d) else { continue };
        for s in &b.sucesores {
            if alcanzables.insert(*s) {
                frente.push_back(*s);
            }
        }
    }
    for b in cfg.bloques() {
        if b.predecesores.is_empty() || !alcanzables.contains(&b.inicio) {
            llegados.insert(b.inicio);
            if encolado.insert(b.inicio) {
                cola.push_back(b.inicio);
            }
        }
    }

    while let Some(dir) = cola.pop_front() {
        encolado.remove(&dir);
        let v = visitas.entry(dir).or_insert(0);
        *v += 1;
        if *v > MAX_VISITAS_POR_BLOQUE {
            continue;
        }
        let Some(bloque) = cfg.bloque(dir) else {
            continue;
        };
        if !plazo.cobrar(bloque.instrucciones.len() as u64 + 1) {
            return (entrada, true);
        }
        let mut e = *entrada.get(&dir).unwrap_or(&vacio);
        for i in &bloque.instrucciones {
            aplica(i, &mut e);
        }

        for s in &bloque.sucesores {
            let ya = llegados.contains(s);
            let previo = *entrada.get(s).unwrap_or(&vacio);
            let nuevo = if ya {
                // El sucesor ya tenia un estado de entrada: se encuentra con
                // este. Solo sobrevive lo que es cierto por los dos caminos.
                let mut m = estado_vacio();
                for k in 0..MAX_REGISTROS as usize {
                    m[k] = Valor::encuentro(previo[k], e[k]);
                }
                m
            } else {
                // Primera vez que se llega: se toma tal cual.
                e
            };
            let cambia = !ya || previo != nuevo;
            llegados.insert(*s);
            if nuevo == vacio {
                entrada.remove(s);
            } else {
                entrada.insert(*s, nuevo);
            }
            if cambia && encolado.insert(*s) {
                cola.push_back(*s);
            }
        }
    }
    (entrada, false)
}

/// Los bloques que pertenecen a la funcion que empieza en `entrada`.
///
/// Se sigue el flujo **sin cruzar aristas de llamada** —una llamada va a otra
/// funcion y su cuerpo no es parte de esta— y **sin entrar en otra funcion por
/// un salto**, que es la llamada de cola: un `jmp` a la entrada de otra funcion
/// transfiere el control y no vuelve, asi que lo que hay al otro lado tampoco es
/// parte de esta.
///
/// # Lo que costaba no parar ahi
///
/// Estaba escrito en el comentario y no en el codigo, y la diferencia se midio:
/// sin parar en las entradas ajenas, una funcion de `/bin/bash` acababa
/// conteniendo bloques a medio megabyte de distancia, porque cada salto de cola
/// encadenaba con la funcion siguiente y esa con la otra. Con «funciones» asi,
/// el ambito de [`crate::capacidad::Ambito::MismaFuncion`] no acota nada y las
/// reglas vuelven a juntar hechos que no tienen relacion.
///
/// Un bloque si puede pertenecer a mas de una funcion —el codigo compartido
/// existe, y los compiladores lo generan—, y eso no es un error que haya que
/// resolver eligiendo una.
fn cuerpo(cfg: &Cfg, entrada: u64, entradas: &BTreeSet<u64>) -> Vec<u64> {
    let mut vistos = BTreeSet::new();
    let mut cola = VecDeque::new();
    if cfg.bloque(entrada).is_some() {
        cola.push_back(entrada);
        vistos.insert(entrada);
    }
    while let Some(d) = cola.pop_front() {
        let Some(b) = cfg.bloque(d) else { continue };
        for s in &b.sucesores {
            // La entrada de otra funcion no se cruza. La propia si —una funcion
            // recursiva o con un bucle que vuelve al principio es normal.
            if *s != entrada && entradas.contains(s) {
                continue;
            }
            if vistos.insert(*s) {
                cola.push_back(*s);
            }
        }
    }
    vistos.into_iter().collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::arm64;
    use crate::cfg::SinDatos;
    use crate::instruccion::Arquitectura;
    use crate::plazo::Plazo;
    use crate::x86;

    /// Construye el grafo de llamadas de un tramo de x86-64.
    fn grafo_x86(bytes: &[u8], base: u64) -> GrafoDeLlamadas {
        let t = x86::Tramo::nuevo(bytes, base, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::default();
        let cfg = Cfg::construir(&t, &SinDatos, &[base], &mut p);
        GrafoDeLlamadas::construir(&cfg)
    }

    /// Construye el grafo de llamadas de un tramo de A64.
    fn grafo_a64(palabras: &[u32], base: u64) -> GrafoDeLlamadas {
        let mut bytes = Vec::new();
        for w in palabras {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let t = arm64::Tramo::nuevo(&bytes, base, Arquitectura::Arm64).unwrap();
        let mut p = Plazo::default();
        let cfg = Cfg::construir(&t, &SinDatos, &[base], &mut p);
        GrafoDeLlamadas::construir(&cfg)
    }

    #[test]
    fn una_llamada_indirecta_por_registro_se_resuelve_y_dice_de_donde_lo_supo() {
        // mov rax, 0x1100 ; call rax ; ret
        // Es el patron minimo de todo lo que hace este modulo, y la evidencia
        // —la direccion donde se fijo el valor— es lo que separa una resolucion
        // de una afirmacion sin respaldo.
        let bytes = &[
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // mov rax, 0x1100
            0xFF, 0xD0, // call rax
            0xC3, // ret
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.llamadas.len(), 1, "{:?}", g.llamadas);
        let l = g.llamadas[0];
        assert_eq!(l.a, 0x1100);
        assert_eq!(
            l.resolucion,
            Resolucion::PorConstante {
                registro: 0,
                definido_en: 0x1000
            }
        );
        assert!(g.sin_resolver.is_empty());
    }

    #[test]
    fn una_llamada_por_memoria_se_declara_sin_resolver_y_no_se_inventa() {
        // call [rip+0x2f10] ; ret. El destino no esta en el codigo: esta en una
        // posicion de memoria cuyo contenido el analisis estatico no conoce. La
        // respuesta correcta es decirlo.
        let bytes = &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0xC3];
        let g = grafo_x86(bytes, 0x1000);
        assert!(g.llamadas.is_empty(), "no se inventa ningun destino");
        assert_eq!(g.sin_resolver.len(), 1);
        assert_eq!(g.sin_resolver[0].motivo, Motivo::EnMemoria);
        assert!(g.frase().contains("sin resolver"), "{}", g.frase());
    }

    #[test]
    fn un_valor_pisado_por_una_llamada_intermedia_no_sobrevive() {
        // mov rax, 0x1100 ; call 0x1020 ; call rax ; ret
        //
        // La funcion llamada en medio puede usar RAX —la convencion de llamada
        // se lo permite—, asi que en el segundo `call rax` el analisis ya NO
        // sabe cuanto vale. Si lo diera por bueno, estaria afirmando una arista
        // hacia 0x1100 que el programa quiza no recorre nunca.
        let bytes = &[
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // 0x1000 mov rax, 0x1100
            0xE8, 0x14, 0x00, 0x00, 0x00, // 0x1007 call 0x1020
            0xFF, 0xD0, // 0x100C call rax
            0xC3, // 0x100E ret
        ];
        let g = grafo_x86(bytes, 0x1000);
        let resueltas: Vec<_> = g.llamadas.iter().filter(|l| l.desde == 0x100C).collect();
        assert!(
            resueltas.is_empty(),
            "la llamada intermedia tuvo que borrar RAX: {resueltas:?}"
        );
        assert!(g
            .sin_resolver
            .iter()
            .any(|s| s.desde == 0x100C && s.motivo == Motivo::RegistroDesconocido { registro: 0 }));
    }

    #[test]
    fn un_valor_pisado_por_un_subregistro_no_sobrevive() {
        // mov rax, 0x1100 ; mov al, 0 ; call rax ; ret
        //
        // `mov al, 0` deja RAX valiendo 0x1100 con el byte bajo a cero, o sea
        // 0x1100 —aqui daria la casualidad de que coincide—, pero el analisis no
        // puede saberlo sin modelar escrituras parciales. Lo correcto es
        // olvidar el valor, no arrastrarlo: en cuanto el byte bajo no fuera cero
        // la arista seria falsa.
        let bytes = &[
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // mov rax, 0x1100
            0xB0, 0x00, // mov al, 0
            0xFF, 0xD0, // call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert!(g.llamadas.is_empty(), "{:?}", g.llamadas);
        assert_eq!(g.sin_resolver.len(), 1);
    }

    #[test]
    fn dos_caminos_con_valores_distintos_no_resuelven_nada() {
        // El caso que obliga a que el analisis sea de encuentro y no de union.
        //
        //   0x1000  cmp edi, 0
        //   0x1003  je  0x100E
        //   0x1005  mov rax, 0x1100
        //   0x100C  jmp 0x1015
        //   0x100E  mov rax, 0x1200
        //   0x1015  call rax
        //   0x1017  ret
        //
        // Quedarse con uno de los dos daria una arista cierta por un camino, que
        // para quien lea el grafo es indistinguible de una falsa.
        let bytes = &[
            0x83, 0xFF, 0x00, // 0x1000 cmp edi, 0
            0x74, 0x09, // 0x1003 je 0x100E
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // 0x1005 mov rax, 0x1100
            0xEB, 0x07, // 0x100C jmp 0x1015
            0x48, 0xC7, 0xC0, 0x00, 0x12, 0x00, 0x00, // 0x100E mov rax, 0x1200
            0xFF, 0xD0, // 0x1015 call rax
            0xC3, // 0x1017 ret
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert!(
            g.llamadas.iter().all(|l| l.desde != 0x1015),
            "no puede resolverse: {:?}",
            g.llamadas
        );
        assert!(g.sin_resolver.iter().any(|s| s.desde == 0x1015));
    }

    #[test]
    fn dos_caminos_que_coinciden_si_resuelven() {
        // El mismo grafo con el mismo valor por los dos lados. Aqui la
        // resolucion SI es cierta pase lo que pase, y negarla seria perder una
        // arista real por exceso de prudencia.
        let bytes = &[
            0x83, 0xFF, 0x00, // 0x1000 cmp edi, 0
            0x74, 0x09, // 0x1003 je 0x100E
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // 0x1005 mov rax, 0x1100
            0xEB, 0x07, // 0x100C jmp 0x1015
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // 0x100E mov rax, 0x1100
            0xFF, 0xD0, // 0x1015 call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        let l = g.llamadas.iter().find(|l| l.desde == 0x1015);
        assert!(l.is_some(), "{:?} / {:?}", g.llamadas, g.sin_resolver);
        assert_eq!(l.unwrap().a, 0x1100);
    }

    #[test]
    fn una_direccion_formada_con_lea_relativo_al_pc_se_sigue() {
        // lea rax, [rip+0x10] ; call rax ; ret
        // Es como llama el codigo independiente de posicion, que es todo el
        // codigo moderno.
        let bytes = &[
            0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, // lea rax,[rip+0x10]
            0xFF, 0xD0, // call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.llamadas.len(), 1);
        assert_eq!(g.llamadas[0].a, 0x1017);
    }

    #[test]
    fn una_direccion_formada_en_dos_pasos_se_sigue() {
        // lea rax, [rip+0x10] ; add rax, 8 ; call rax ; ret
        // La suma desplaza el valor conocido, y la evidencia sigue apuntando a
        // donde empezo la cadena: es la instruccion que hay que mirar para
        // comprobar el destino.
        let bytes = &[
            0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, // 0x1000 lea rax,[rip+0x10] -> 0x1017
            0x48, 0x83, 0xC0, 0x08, // 0x1007 add rax, 8
            0xFF, 0xD0, // 0x100B call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.llamadas.len(), 1, "{:?}", g.sin_resolver);
        assert_eq!(g.llamadas[0].a, 0x1017 + 8);
        assert_eq!(
            g.llamadas[0].resolucion,
            Resolucion::PorConstante {
                registro: 0,
                definido_en: 0x1000
            },
            "la evidencia apunta al lea, que es donde empieza la cadena"
        );
    }

    #[test]
    fn en_a64_una_direccion_de_adrp_mas_add_se_sigue() {
        // El equivalente de A64, que es el patron dominante de la arquitectura:
        //   0x1000 adrp x16, pagina de 0x1000  -> 0x1000
        //   0x1004 add  x16, x16, #0x40
        //   0x1008 blr  x16
        //   0x100C ret
        let g = grafo_a64(
            &[0x9000_0010, 0x9101_0210, 0xd63f_0200, 0xd65f_03c0],
            0x1000,
        );
        assert_eq!(g.llamadas.len(), 1, "{:?}", g.sin_resolver);
        assert_eq!(g.llamadas[0].a, 0x1040);
        assert_eq!(
            g.llamadas[0].resolucion,
            Resolucion::PorConstante {
                registro: 16,
                definido_en: 0x1000
            }
        );
    }

    #[test]
    fn en_a64_un_movk_intermedio_impide_resolver() {
        // adrp x16, . ; movk x16, #0x5678 ; blr x16 ; ret
        // `movk` conserva parte del valor anterior, asi que el resultado depende
        // de algo que esta instruccion no lleva. Declararlo desconocido es lo
        // correcto; arrastrar el valor del `adrp` daria una direccion falsa.
        let g = grafo_a64(
            &[0x9000_0010, 0xf28a_cf10, 0xd63f_0200, 0xd65f_03c0],
            0x1000,
        );
        assert!(g.llamadas.is_empty(), "{:?}", g.llamadas);
        assert_eq!(g.sin_resolver.len(), 1);
    }

    #[test]
    fn un_salto_indirecto_resuelto_se_marca_como_llamada_de_cola() {
        // mov rax, 0x1100 ; jmp rax
        // El control se va y no vuelve: la arista del grafo de llamadas es la
        // misma, pero lo que significa el retorno cambia, y por eso se marca.
        let bytes = &[
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // mov rax, 0x1100
            0xFF, 0xE0, // jmp rax
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.llamadas.len(), 1);
        assert!(g.llamadas[0].de_cola);
        assert_eq!(g.llamadas[0].a, 0x1100);
        assert_eq!(
            g.descubiertos,
            vec![0x1100],
            "alcanza codigo que el grafo de flujo no tenia"
        );
    }

    #[test]
    fn una_llamada_directa_abre_una_funcion() {
        // call 0x1008 ; ret ; <0x1008> ret
        // Una direccion a la que alguien llama es la entrada de una funcion: es
        // lo que se puede afirmar sin suponer nada.
        let bytes = &[
            0xE8, 0x03, 0x00, 0x00, 0x00, // 0x1000 call 0x1008
            0xC3, // 0x1005 ret
            0x90, 0x90, // relleno
            0xC3, // 0x1008 ret
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.cuantas_funciones(), 2, "{:?}", g.llamadas);
        assert!(g.funcion(0x1008).is_some());
        assert_eq!(g.llamadas[0].resolucion, Resolucion::Directa);
    }

    #[test]
    fn un_bucle_no_cuelga_el_analisis() {
        // La propiedad que hace utilizable esto dentro del agente. Un grafo con
        // ciclos hace que el estado de un bloque se recalcule; sin la monotonia
        // del encuentro, eso seria un bucle infinito.
        //
        //   0x1000 mov rax, 0x1100
        //   0x1007 dec rax
        //   0x100A jne 0x1007
        //   0x100C call rax
        //   0x100E ret
        let bytes = &[
            0x48, 0xC7, 0xC0, 0x00, 0x11, 0x00, 0x00, // mov rax, 0x1100
            0x48, 0xFF, 0xC8, // dec rax
            0x75, 0xFB, // jne 0x1007
            0xFF, 0xD0, // call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        // Lo que importa no es el resultado sino que termine y que no invente:
        // el valor de RAX en el bucle no se conoce.
        assert!(
            g.llamadas.iter().all(|l| l.desde != 0x100C),
            "{:?}",
            g.llamadas
        );
    }

    #[test]
    fn un_tramo_sin_transferencias_indirectas_no_declara_nada_sin_resolver() {
        // El caso negativo: si `sin_resolver` se llenara siempre, dejaria de
        // significar algo.
        let g = grafo_x86(&[0x31, 0xC0, 0xC3], 0x1000);
        assert!(g.sin_resolver.is_empty());
        assert!(g.llamadas.is_empty());
        assert!(!g.frase().contains("sin resolver"), "{}", g.frase());
    }

    #[test]
    fn el_encuentro_de_dos_constantes_iguales_toma_la_evidencia_menor() {
        // Para que el resultado no dependa del orden en que se recorrieron los
        // predecesores: un analisis que diera evidencias distintas segun el
        // recorrido seria imposible de comparar consigo mismo.
        let a = Valor::Constante {
            valor: 7,
            desde: 0x20,
        };
        let b = Valor::Constante {
            valor: 7,
            desde: 0x10,
        };
        assert_eq!(Valor::encuentro(a, b), Valor::encuentro(b, a));
        assert_eq!(
            Valor::encuentro(a, b),
            Valor::Constante {
                valor: 7,
                desde: 0x10
            }
        );
    }

    #[test]
    fn el_encuentro_con_lo_desconocido_es_desconocido() {
        let a = Valor::Constante {
            valor: 7,
            desde: 0x20,
        };
        assert_eq!(Valor::encuentro(a, Valor::Desconocido), Valor::Desconocido);
        assert_eq!(Valor::encuentro(Valor::Desconocido, a), Valor::Desconocido);
    }

    #[test]
    fn un_valor_que_cambia_de_registro_se_sigue() {
        // mov rbx, 0x1100 ; mov rax, rbx ; call rax ; ret
        //
        // Mover el valor de registro es de las ofuscaciones mas baratas que
        // existen, y ademas el compilador lo hace por su cuenta. Sin seguir la
        // copia, el analisis pierde el rastro justo ahi.
        let bytes = &[
            0x48, 0xC7, 0xC3, 0x00, 0x11, 0x00, 0x00, // 0x1000 mov rbx, 0x1100
            0x48, 0x89, 0xD8, // 0x1007 mov rax, rbx
            0xFF, 0xD0, // 0x100A call rax
            0xC3,
        ];
        let g = grafo_x86(bytes, 0x1000);
        assert_eq!(g.llamadas.len(), 1, "{:?}", g.sin_resolver);
        assert_eq!(g.llamadas[0].a, 0x1100);
        assert_eq!(
            g.llamadas[0].resolucion,
            Resolucion::PorConstante {
                registro: 0,
                definido_en: 0x1000
            },
            "la evidencia apunta a donde se fijo el valor, no a la copia"
        );
    }

    #[test]
    fn copiar_desde_un_registro_desconocido_no_inventa_nada() {
        // mov rax, rbx ; call rax. Nadie ha fijado rbx: heredar «lo que sea» no
        // da un valor, da otro «lo que sea».
        let bytes = &[0x48, 0x89, 0xD8, 0xFF, 0xD0, 0xC3];
        let g = grafo_x86(bytes, 0x1000);
        assert!(g.llamadas.is_empty(), "{:?}", g.llamadas);
        assert_eq!(g.sin_resolver.len(), 1);
    }

    #[test]
    fn en_a64_una_copia_entre_registros_tambien_se_sigue() {
        // adrp x16, . ; mov x17, x16 ; blr x17 ; ret
        // En A64 `mov` entre registros no existe: es `orr xd, xzr, xm`.
        let g = grafo_a64(
            &[0x9000_0010, 0xaa10_03f1, 0xd63f_0220, 0xd65f_03c0],
            0x1000,
        );
        assert_eq!(g.llamadas.len(), 1, "{:?}", g.sin_resolver);
        assert_eq!(g.llamadas[0].a, 0x1000);
        assert_eq!(
            g.llamadas[0].resolucion,
            Resolucion::PorConstante {
                registro: 17,
                definido_en: 0x1000
            }
        );
    }
}
