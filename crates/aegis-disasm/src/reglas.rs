//! El catalogo de reglas, y el motor que las evalua.
//!
//! # Las reglas son datos
//!
//! Una regla aqui es una estructura: un nombre, una familia, una tecnica de
//! ATT&CK, una lista de senales y como se combinan. El motor de [`evaluar`] no
//! sabe lo que significa ninguna: recoge senales del binario y comprueba
//! exigencias.
//!
//! Eso importa por una razon practica. Una regla escrita en Rust hay que
//! compilarla, y eso pone al mantenedor del desensamblador entre quien ve una
//! tecnica nueva y el dia en que se reconoce. Con las reglas como datos, anadir
//! una es anadir una entrada a una tabla.
//!
//! # Por que cada regla exige varias senales
//!
//! Porque casi ninguna senal suelta significa nada. `VirtualAlloc` lo llama
//! medio Windows. `WriteProcessMemory` lo llama un depurador. `CreateRemoteThread`
//! lo llama un instalador. Las tres juntas, en el mismo binario, son una
//! inyeccion de codigo y no son ninguna otra cosa.
//!
//! Una regla que dispare con una de esas tres genera tanto ruido que quien la
//! reciba aprende a ignorarla, y una regla ignorada es peor que ninguna: ocupa
//! el sitio de la que si habria servido.
//!
//! La excepcion son las senales que no tienen lectura alternativa —una
//! instruccion `aesenc` es cifrado AES y no es otra cosa—, y esas llevan
//! [`Exigencia::Alguna`] con esa razon escrita al lado.
//!
//! # Lo que estas reglas no pueden ver
//!
//! Se evaluan sobre codigo desensamblado. Un binario empaquetado no ensena su
//! codigo hasta que se ejecuta, asi que sobre el estas reglas veran el
//! desempaquetador y no la carga. Eso **no se disimula**: sale en la cobertura,
//! y es el trabajo de `aegis-unpacker` y de la detonacion, no de este modulo.

use std::collections::BTreeMap;

use crate::capacidad::{Ambito, Capacidad, Evidencia, Exigencia, Familia, VENTANA_DE_ALGORITMO};
use crate::cfg::Cfg;
use crate::importaciones::{Forma, Importaciones};
use crate::instruccion::{Arquitectura, Clase, Flujo, Instruccion, Segmento};
use crate::llamadas::GrafoDeLlamadas;

/// Lo que una regla busca en el binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Senal {
    /// Una funcion importada cuyo nombre contiene esto, sin distinguir
    /// mayusculas.
    ///
    /// Se compara por trozo y no por igualdad porque en Windows la misma funcion
    /// existe en cuatro variantes —`CreateProcessA`, `CreateProcessW`,
    /// `CreateProcessAsUserA`...— y una regla por igualdad reconoceria una de
    /// las cuatro. La comparacion sin mayusculas es porque las tablas de
    /// importacion no son consistentes ni consigo mismas.
    Importa(&'static str),
    /// Una instruccion de esta clase.
    Clase(Clase),
    /// Una constante exacta en algun operando.
    Constante(u64),
    /// Un acceso por este segmento a este desplazamiento.
    Segmento(Segmento, u64),
    /// El binario resuelve funciones de esta forma.
    Resuelve(Forma),
    /// Hay una transferencia de control cuyo destino no esta en el codigo.
    ///
    /// Es la senal de que el control se va a memoria que el binario se ha
    /// preparado —lo que hace un desempaquetador al terminar— y no a otra parte
    /// del propio binario.
    SaltaFueraDelCodigo,
    /// Hay una llamada indirecta a traves de un registro.
    LlamadaPorRegistro,
    /// Hay un BUCLE acotado por esta constante que escribe en memoria.
    ///
    /// # Por que hace falta una senal asi
    ///
    /// Porque «aparece la constante 256» no distingue nada. Medido sobre
    /// `/bin/ls`, `/bin/bash` y la libc de esta maquina: las tres tienen
    /// funciones con un `cmp` contra 256, una instruccion de cadena y un `xor`,
    /// que es cualquier funcion que copie un buffer. Una regla construida con
    /// esas tres piezas dispara en los tres binarios.
    ///
    /// Lo que si distingue es la FORMA: un bucle que da exactamente tantas
    /// vueltas como dice la constante y escribe en memoria en cada una. Eso es
    /// una tabla rellenandose, y una tabla de 256 entradas que despues se
    /// permuta es la caja de sustitucion de RC4.
    ///
    /// Sigue sin ser una prueba —hay tablas de 256 entradas legitimas— y por eso
    /// las reglas que la usan piden algo mas junto a ella.
    BucleAcotadoA(u64),
}

impl Senal {
    /// El texto con el que esta senal aparece en la evidencia.
    fn como_se_ve(&self) -> String {
        match self {
            Senal::Importa(n) => format!("se importa {n}"),
            Senal::Clase(c) => format!("hay una instruccion de clase {c:?}"),
            Senal::Constante(v) => format!("aparece la constante {v:#x}"),
            Senal::Segmento(s, d) => {
                let n = match s {
                    Segmento::Fs => "fs",
                    Segmento::Gs => "gs",
                };
                format!("se lee {n}:[{d:#x}]")
            }
            Senal::Resuelve(f) => format!("se resuelven funciones {}", f.frase()),
            Senal::SaltaFueraDelCodigo => {
                "el control salta a una direccion que no esta en el codigo del fichero".to_owned()
            }
            Senal::LlamadaPorRegistro => "se llama a traves de un registro".to_owned(),
            Senal::BucleAcotadoA(n) => {
                format!("hay un bucle acotado a {n} vueltas que escribe en memoria")
            }
        }
    }
}

/// Una regla del catalogo.
#[derive(Debug, Clone)]
pub struct Regla {
    /// Como se llama la capacidad que reconoce.
    pub nombre: &'static str,
    /// De que familia.
    pub familia: Familia,
    /// La tecnica de ATT&CK, si la tiene.
    pub attack: Option<&'static str>,
    /// Que hay que ver.
    pub senales: &'static [Senal],
    /// Cuantas de esas hay que ver.
    pub exigencia: Exigencia,
    /// Donde tienen que verse para que cuenten juntas. Ver [`Ambito`].
    pub ambito: Ambito,
    /// Por que lo que se ve significa lo que dice la regla.
    ///
    /// Va escrito aqui, a mano, y acaba en la evidencia. Una explicacion
    /// generada a partir del nombre de la regla no explicaria nada: lo
    /// repetiria.
    pub porque: &'static str,
}

/// Todo lo que se sabe del binario, para evaluar las reglas sobre ello.
///
/// Se pasa entero y no por trozos porque una regla puede necesitar cualquier
/// combinacion, y trocearlo obligaria a cambiar la firma del motor cada vez que
/// una regla nueva mire algo distinto.
pub struct Contexto<'a> {
    /// El grafo de flujo.
    pub cfg: &'a Cfg,
    /// El grafo de llamadas.
    pub llamadas: &'a GrafoDeLlamadas,
    /// Como resuelve el binario las funciones del sistema.
    pub importaciones: &'a Importaciones,
    /// Los bytes del codigo y donde se cargan, para el texto de la evidencia.
    pub codigo: &'a [u8],
    /// Donde empieza el codigo.
    pub base: u64,
    /// De que arquitectura es.
    pub arquitectura: Arquitectura,
    /// Que funciones contienen cada bloque.
    ///
    /// Se construye una vez con [`Contexto::nuevo`] y no en cada consulta: sin
    /// el, comprobar el ambito de una regla recorreria todas las funciones por
    /// cada aparicion de cada senal, que con las casi tres mil funciones de una
    /// libc y las treinta reglas del catalogo es un coste cuadratico —o sea, un
    /// atasco dentro del presupuesto del agente.
    indice_de_bloques: BTreeMap<u64, Vec<u64>>,
}

impl<'a> Contexto<'a> {
    /// Prepara el contexto, construyendo el indice de bloques.
    pub fn nuevo(
        cfg: &'a Cfg,
        llamadas: &'a GrafoDeLlamadas,
        importaciones: &'a Importaciones,
        codigo: &'a [u8],
        base: u64,
        arquitectura: Arquitectura,
    ) -> Contexto<'a> {
        let mut indice_de_bloques: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for f in llamadas.funciones() {
            for b in &f.bloques {
                indice_de_bloques.entry(*b).or_default().push(f.entrada);
            }
        }
        Contexto {
            cfg,
            llamadas,
            importaciones,
            codigo,
            base,
            arquitectura,
            indice_de_bloques,
        }
    }

    /// Las funciones que contienen `direccion`.
    ///
    /// Son varias y no una porque el codigo compartido existe: un compilador
    /// genera bloques a los que llegan dos funciones distintas, y elegir una de
    /// las dos por criterio propio haria que una regla saltara o no segun un
    /// detalle que no tiene nada que ver con lo que mira.
    ///
    /// El recorrido es sobre el grafo de llamadas ya construido y no vuelve a
    /// recorrer el codigo: lo unico que cuesta es mirar en un indice.
    fn funciones_que_contienen(&self, direccion: u64) -> Vec<u64> {
        let Some(b) = self.cfg.bloque_que_contiene(direccion) else {
            return Vec::new();
        };
        self.indice_de_bloques
            .get(&b.inicio)
            .cloned()
            .unwrap_or_default()
    }

    /// El texto de la instruccion que hay en `direccion`.
    ///
    /// Se formatea a la carta, solo para las instrucciones que acaban siendo
    /// evidencia —unas decenas—, que es la razon de que el modelo no guarde el
    /// texto de todas. Ver [`crate::instruccion`].
    fn texto(&self, direccion: u64) -> String {
        let t = match self.arquitectura {
            Arquitectura::Arm64 => crate::arm64::texto_en(self.codigo, self.base, direccion),
            a => crate::x86::texto_en(self.codigo, self.base, direccion, a),
        };
        t.unwrap_or_else(|| format!("<no se pudo formatear la instruccion de {direccion:#x}>"))
    }
}

/// Todos los sitios donde se ve una senal.
///
/// Devuelve todas las apariciones y no solo la primera porque el ambito de
/// funcion las necesita: una senal que aparece cuatro veces puede estar en la
/// funcion buena solo la cuarta, y quedarse con la primera perderia la regla.
///
/// Se acota, porque `Clase::Mov` aparece cien mil veces en un binario mediano y
/// guardarlas todas seria reservar memoria proporcional al fichero para una
/// evidencia de la que se van a usar unas pocas.
fn buscar_todas(s: &Senal, ctx: &Contexto) -> Vec<u64> {
    let mut v: Vec<u64> = match s {
        Senal::Importa(nombre) => {
            let aguja = nombre.to_ascii_lowercase();
            ctx.importaciones
                .resoluciones
                .iter()
                .filter(|r| {
                    r.nombre
                        .as_deref()
                        .is_some_and(|n| n.to_ascii_lowercase().contains(&aguja))
                })
                .map(|r| r.donde)
                .collect()
        }
        Senal::Clase(c) => ctx
            .cfg
            .instrucciones()
            .filter(|i| i.clase == *c)
            .map(|i| i.direccion)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::Constante(v) => ctx
            .cfg
            .instrucciones()
            .filter(|i| i.inmediatos.contains(v))
            .map(|i| i.direccion)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::Segmento(seg, desp) => ctx
            .cfg
            .instrucciones()
            .filter(|i| i.segmento == Some(*seg) && i.inmediatos.contains(desp))
            .map(|i| i.direccion)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::Resuelve(f) => ctx
            .importaciones
            .resoluciones
            .iter()
            .filter(|r| r.forma == *f)
            .map(|r| r.donde)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::SaltaFueraDelCodigo => ctx
            .llamadas
            .llamadas
            .iter()
            .filter(|l| !ctx.cfg.bloques().any(|b| l.a >= b.inicio && l.a < b.fin))
            .map(|l| l.desde)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::LlamadaPorRegistro => ctx
            .cfg
            .instrucciones()
            .filter(|i: &&Instruccion| {
                matches!(i.flujo, Flujo::Llamada { destino: None }) && i.destino_reg.is_some()
            })
            .map(|i| i.direccion)
            .take(MAX_APARICIONES)
            .collect(),
        Senal::BucleAcotadoA(n) => bucles_acotados(ctx, *n),
    };
    v.sort_unstable();
    v.dedup();
    v
}

/// Los bucles acotados por `cota` que escriben en memoria.
///
/// # Que cuenta como bucle
///
/// Un bloque que puede volver a si mismo: o es su propio sucesor, o uno de sus
/// sucesores acaba volviendo a el. Se busca solo hacia atras en el orden de
/// direcciones —un salto a una direccion menor o igual que la del propio
/// bloque—, que es la forma que tiene el noventa y nueve por ciento de los
/// bucles que genera un compilador y no exige recorrer el grafo entero por cada
/// bloque.
///
/// Se exige ademas que el bloque compare contra la cota y escriba en memoria.
/// Las tres condiciones juntas son «una tabla rellenandose»; cualquiera de ellas
/// sola es cualquier cosa.
fn bucles_acotados(ctx: &Contexto, cota: u64) -> Vec<u64> {
    let mut v = Vec::new();
    for b in ctx.cfg.bloques() {
        // Un salto hacia atras: el bloque puede repetirse.
        let vuelve = b.sucesores.iter().any(|s| *s <= b.inicio);
        if !vuelve {
            continue;
        }
        let compara = b
            .instrucciones
            .iter()
            .any(|i| i.clase == Clase::Comparacion && i.inmediatos.contains(&cota));
        if !compara {
            continue;
        }
        if let Some(i) = b.instrucciones.iter().find(|i| i.escribe_memoria) {
            v.push(i.direccion);
            if v.len() >= MAX_APARICIONES {
                break;
            }
        }
    }
    v
}

/// Cuantas apariciones de una senal se guardan.
///
/// Una senal que aparece mas de mil veces en un binario no se vuelve mas cierta
/// con la aparicion mil una, y guardarlas todas seria reservar memoria en
/// proporcion al fichero analizado: una via de agotamiento por un fichero
/// construido para eso.
const MAX_APARICIONES: usize = 1024;

/// Evalua una regla sobre el binario.
pub fn evaluar_una(r: &Regla, ctx: &Contexto) -> Option<Capacidad> {
    let apariciones: Vec<(&Senal, Vec<u64>)> = r
        .senales
        .iter()
        .map(|s| (s, buscar_todas(s, ctx)))
        .collect();
    let vistas = match r.ambito {
        Ambito::Global => apariciones
            .iter()
            .filter_map(|(s, v)| v.first().map(|d| (*s, *d)))
            .collect(),
        Ambito::MismaFuncion => en_una_misma_funcion(&apariciones, r, ctx)?,
    };
    if !cumple(r, &vistas) {
        return None;
    }
    Capacidad::nueva(
        r.nombre,
        r.familia,
        r.attack,
        evidencias_de(r, &vistas, ctx),
    )
}

/// Si lo visto basta para la exigencia de la regla.
fn cumple(r: &Regla, vistas: &[(&Senal, u64)]) -> bool {
    match r.exigencia {
        Exigencia::Todas => vistas.len() == r.senales.len(),
        Exigencia::Alguna => !vistas.is_empty(),
        Exigencia::AlMenos(n) => vistas.len() >= n,
    }
}

/// Busca una funcion que contenga suficientes senales de la regla.
///
/// Devuelve las senales vistas **en esa funcion**, o `None` si no hay ninguna
/// que reuna las que la regla pide. La funcion elegida es la primera por
/// direccion entre las que cumplen, para que el resultado no dependa del orden
/// de recorrido de ninguna estructura.
fn en_una_misma_funcion<'a>(
    apariciones: &[(&'a Senal, Vec<u64>)],
    r: &Regla,
    ctx: &Contexto,
) -> Option<Vec<(&'a Senal, u64)>> {
    let minimo = match r.exigencia {
        Exigencia::Todas => r.senales.len(),
        Exigencia::Alguna => 1,
        Exigencia::AlMenos(n) => n,
    };
    // Por cada funcion, la primera aparicion de cada senal dentro de ella.
    let mut por_funcion: BTreeMap<u64, Vec<(&Senal, u64)>> = BTreeMap::new();
    for (s, donde) in apariciones {
        for d in donde {
            for f in ctx.funciones_que_contienen(*d) {
                let e = por_funcion.entry(f).or_default();
                if !e.iter().any(|(otra, _)| std::ptr::eq(*otra, *s)) {
                    e.push((s, *d));
                }
            }
        }
    }
    // De cada funcion, el subconjunto mas apretado que cumple: se ordenan las
    // apariciones por direccion y se busca una ventana que contenga suficientes
    // senales DISTINTAS. Sin esto, dos piezas en la misma funcion pero a setenta
    // kilobytes una de otra contarian como el mismo algoritmo.
    for (_, mut v) in por_funcion {
        v.sort_by_key(|(_, d)| *d);
        if let Some(apretado) = ventana_suficiente(&v, minimo) {
            return Some(apretado);
        }
    }
    None
}

/// El subconjunto de apariciones que cabe en una ventana y basta para la regla.
///
/// Recorre las apariciones ordenadas con dos indices y devuelve el primer tramo
/// de como mucho [`VENTANA_DE_ALGORITMO`] bytes que contenga `minimo` senales
/// distintas. Es lineal en el numero de apariciones.
fn ventana_suficiente<'a>(
    ordenadas: &[(&'a Senal, u64)],
    minimo: usize,
) -> Option<Vec<(&'a Senal, u64)>> {
    let mut i = 0usize;
    for j in 0..ordenadas.len() {
        while ordenadas[j].1.saturating_sub(ordenadas[i].1) > VENTANA_DE_ALGORITMO {
            i += 1;
        }
        let tramo = &ordenadas[i..=j];
        let mut distintas: Vec<(&Senal, u64)> = Vec::new();
        for (s, d) in tramo {
            if !distintas.iter().any(|(otra, _)| std::ptr::eq(*otra, *s)) {
                distintas.push((*s, *d));
            }
        }
        if distintas.len() >= minimo {
            return Some(distintas);
        }
    }
    None
}

/// Construye la evidencia de una capacidad.
fn evidencias_de(r: &Regla, vistas: &[(&Senal, u64)], ctx: &Contexto) -> Vec<Evidencia> {
    vistas
        .iter()
        .map(|(s, d)| Evidencia {
            donde: *d,
            que: match s {
                // Para lo que es una instruccion, la evidencia es la instruccion
                // escrita. Para lo que es un hecho del contenedor, es el hecho.
                Senal::Clase(_)
                | Senal::Constante(_)
                | Senal::Segmento(..)
                | Senal::SaltaFueraDelCodigo
                | Senal::LlamadaPorRegistro => {
                    format!("{} ({})", ctx.texto(*d), s.como_se_ve())
                }
                _ => s.como_se_ve(),
            },
            porque: r.porque.to_owned(),
        })
        .collect()
}

/// Evalua todo el catalogo.
pub fn evaluar(ctx: &Contexto) -> Vec<Capacidad> {
    CATALOGO
        .iter()
        .filter_map(|r| evaluar_una(r, ctx))
        .collect()
}

/// El catalogo.
///
/// Cada entrada lleva escrito **por que** lo que mira significa lo que dice, y
/// esa frase acaba en el informe. Una regla cuyo «porque» no se pueda escribir
/// sin repetir su nombre es una regla que no se ha pensado.
pub static CATALOGO: &[Regla] = &[
    // ---------------------------------------------------------------- INYECCION
    Regla {
        nombre: "inyeccion de codigo en otro proceso",
        familia: Familia::Inyeccion,
        attack: Some("T1055.002"),
        senales: &[
            Senal::Importa("VirtualAllocEx"),
            Senal::Importa("WriteProcessMemory"),
            Senal::Importa("CreateRemoteThread"),
        ],
        exigencia: Exigencia::Todas,
        ambito: Ambito::Global,
        porque: "reservar memoria EN OTRO PROCESO, escribir en ella y arrancar un hilo \
                 que empieza ahi son los tres pasos de meter codigo propio en un proceso \
                 ajeno; por separado cada una tiene usos normales, y las tres juntas no \
                 tienen ninguno",
    },
    Regla {
        nombre: "inyeccion por vaciado de proceso",
        familia: Familia::Inyeccion,
        attack: Some("T1055.012"),
        senales: &[
            Senal::Importa("CreateProcess"),
            Senal::Importa("NtUnmapViewOfSection"),
            Senal::Importa("SetThreadContext"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "arrancar un proceso suspendido, quitarle de la memoria su propia imagen \
                 y cambiarle el punto de entrada es sustituir un programa legitimo por \
                 otro conservando su identidad ante el sistema",
    },
    Regla {
        nombre: "inyeccion por biblioteca cargada a distancia",
        familia: Familia::Inyeccion,
        attack: Some("T1055.001"),
        senales: &[
            Senal::Importa("VirtualAllocEx"),
            Senal::Importa("WriteProcessMemory"),
            Senal::Importa("LoadLibrary"),
            Senal::Importa("CreateRemoteThread"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "escribir la ruta de una biblioteca en otro proceso y arrancar alli un \
                 hilo que empieza en el cargador de bibliotecas hace que ese proceso \
                 cargue codigo elegido por otro",
    },
    Regla {
        nombre: "inyeccion por cola de trabajo asincrona",
        familia: Familia::Inyeccion,
        attack: Some("T1055.004"),
        senales: &[
            Senal::Importa("QueueUserAPC"),
            Senal::Importa("VirtualAllocEx"),
            Senal::Importa("OpenThread"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "encolar una llamada asincrona en un hilo ajeno hace que ese hilo ejecute \
                 codigo elegido por otro la proxima vez que entre en espera alertable, sin \
                 crear ningun hilo nuevo que delate la inyeccion",
    },
    Regla {
        nombre: "inyeccion por seccion de memoria compartida",
        familia: Familia::Inyeccion,
        attack: Some("T1055"),
        senales: &[
            Senal::Importa("NtCreateSection"),
            Senal::Importa("NtMapViewOfSection"),
        ],
        exigencia: Exigencia::Todas,
        ambito: Ambito::Global,
        porque: "crear una seccion y proyectarla en dos procesos deja escribir en la \
                 memoria de otro proceso sin llamar a ninguna funcion que lleve la \
                 palabra «write», que es justo lo que se vigila",
    },
    Regla {
        nombre: "inyeccion por cambio del procedimiento de ventana",
        familia: Familia::Inyeccion,
        attack: Some("T1055.011"),
        senales: &[
            Senal::Importa("SetWindowsHookEx"),
            Senal::Importa("SetWindowLong"),
            Senal::Importa("SendMessage"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "colgar un gancho de ventana o cambiar el procedimiento de una ventana \
                 ajena hace que el codigo propio se ejecute dentro del proceso que posee \
                 esa ventana",
    },
    Regla {
        nombre: "inyeccion por secuestro de hilo",
        familia: Familia::Inyeccion,
        attack: Some("T1055.003"),
        senales: &[
            Senal::Importa("SuspendThread"),
            Senal::Importa("GetThreadContext"),
            Senal::Importa("SetThreadContext"),
            Senal::Importa("ResumeThread"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "parar un hilo ajeno, cambiarle el contador de programa y reanudarlo hace \
                 que ese hilo siga ejecutando en otro sitio, sin crear ningun hilo nuevo",
    },
    Regla {
        nombre: "salto a memoria preparada por el propio binario",
        familia: Familia::Inyeccion,
        attack: Some("T1055"),
        senales: &[
            Senal::SaltaFueraDelCodigo,
            Senal::Importa("VirtualProtect"),
            Senal::Importa("VirtualAlloc"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::MismaFuncion,
        porque: "hacer ejecutable una region de memoria y despues transferirle el control \
                 es lo que hace un programa que ejecuta codigo que no estaba en su fichero",
    },
    // ------------------------------------------------------------- PERSISTENCIA
    Regla {
        nombre: "persistencia por clave de arranque del registro",
        familia: Familia::Persistencia,
        attack: Some("T1547.001"),
        senales: &[
            Senal::Importa("RegSetValue"),
            Senal::Importa("RegCreateKey"),
            Senal::Importa("RegOpenKey"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "escribir en el registro es normal; escribir en el registro combinado con \
                 el resto de lo que hace este binario es como se consigue volver a \
                 ejecutarse tras el reinicio",
    },
    Regla {
        nombre: "persistencia por servicio del sistema",
        familia: Familia::Persistencia,
        attack: Some("T1543.003"),
        senales: &[
            Senal::Importa("CreateService"),
            Senal::Importa("OpenSCManager"),
            Senal::Importa("StartService"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "un servicio arranca con el sistema y con los privilegios del sistema: es \
                 persistencia y elevacion en el mismo paso",
    },
    Regla {
        nombre: "persistencia por tarea programada",
        familia: Familia::Persistencia,
        attack: Some("T1053.005"),
        senales: &[
            Senal::Importa("ITaskService"),
            Senal::Importa("NetScheduleJob"),
            Senal::Importa("schtasks"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "el programador de tareas ejecuta lo que se le diga cuando se le diga, y \
                 es de los pocos sitios donde un programa puede dejar dicho que se le \
                 vuelva a ejecutar sin tocar el registro ni instalar un servicio",
    },
    Regla {
        nombre: "persistencia por carpeta de inicio",
        familia: Familia::Persistencia,
        attack: Some("T1547.001"),
        senales: &[
            Senal::Importa("SHGetFolderPath"),
            Senal::Importa("SHGetSpecialFolderPath"),
            Senal::Importa("CopyFile"),
            Senal::Importa("CreateFile"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "averiguar la ruta de la carpeta de inicio y escribir un fichero en ella \
                 es la forma mas antigua y mas simple de volver a ejecutarse en cada \
                 sesion",
    },
    Regla {
        nombre: "persistencia por suscripcion a eventos del sistema",
        familia: Familia::Persistencia,
        attack: Some("T1546.003"),
        senales: &[
            Senal::Importa("IWbemServices"),
            Senal::Importa("CoCreateInstance"),
            Senal::Importa("__EventFilter"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "una suscripcion permanente a eventos del sistema ejecuta lo que se le \
                 diga cuando pase lo que se le diga, vive fuera del sistema de ficheros y \
                 sobrevive a la limpieza de casi cualquier herramienta",
    },
    // ------------------------------------------------------------------ EVASION
    Regla {
        nombre: "deteccion de depurador",
        familia: Familia::Evasion,
        attack: Some("T1622"),
        senales: &[
            Senal::Importa("IsDebuggerPresent"),
            Senal::Importa("CheckRemoteDebuggerPresent"),
            Senal::Importa("NtQueryInformationProcess"),
            Senal::Segmento(Segmento::Gs, 0x60),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::MismaFuncion,
        porque: "preguntar si hay un depurador —por funcion o leyendo la marca del bloque \
                 de entorno del proceso— solo sirve para comportarse distinto cuando lo \
                 hay, y un programa que se comporta distinto cuando lo miran es un \
                 programa que no quiere que lo miren",
    },
    Regla {
        nombre: "resolucion de funciones sin tabla de importaciones",
        familia: Familia::Evasion,
        attack: Some("T1027"),
        senales: &[
            Senal::Resuelve(Forma::PorEstructurasDelCargador),
            Senal::Resuelve(Forma::PorHashDelNombre),
        ],
        // Las DOS, y no una. Un hash suelto es un hash: la libc de esta maquina
        // tiene catorce rotaciones de trece bits en funciones de dispersion
        // perfectamente legitimas, y `/bin/bash` cuatro. Lo que no tiene ninguna
        // lectura benigna es hashear nombres SACADOS de la lista de modulos del
        // cargador, que es lo que hace un cargador reflexivo y necesita las dos
        // piezas.
        exigencia: Exigencia::Todas,
        ambito: Ambito::Global,
        porque: "buscarse las funciones recorriendo las estructuras del cargador o por el \
                 hash de su nombre solo sirve para que la tabla de importaciones no diga \
                 lo que el programa hace; un programa que no tiene nada que esconder deja \
                 que el cargador rellene su tabla",
    },
    Regla {
        nombre: "deteccion de maquina virtual o entorno de analisis",
        familia: Familia::Evasion,
        attack: Some("T1497.001"),
        senales: &[
            Senal::Constante(0x5658_5653),
            Senal::Constante(0x564D_5868),
            Senal::Importa("GetSystemFirmwareTable"),
            Senal::Importa("SetupDiGetDeviceRegistryProperty"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::MismaFuncion,
        porque: "las dos constantes son el puerto y la firma del canal de comunicacion con \
                 el anfitrion de VMware, y las dos funciones sirven para leer el nombre del \
                 fabricante del equipo: las cuatro se usan para lo mismo, comprobar si se \
                 esta dentro de una maquina virtual y no hacer nada si lo esta",
    },
    Regla {
        nombre: "manipulacion del registro de eventos",
        familia: Familia::Evasion,
        attack: Some("T1562.002"),
        senales: &[
            Senal::Importa("EvtClearLog"),
            Senal::Importa("ClearEventLog"),
            Senal::Importa("OpenEventLog"),
            Senal::Importa("EventWrite"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "borrar o silenciar el registro de eventos del sistema no tiene ninguna \
                 lectura util para un programa que no sea una herramienta de \
                 administracion, y sirve para que no quede constancia de lo demas",
    },
    // ------------------------------------------------------------------ CIFRADO
    Regla {
        nombre: "cifrado AES con las instrucciones del procesador",
        familia: Familia::Cifrado,
        attack: Some("T1027"),
        senales: &[Senal::Clase(Clase::Cripto)],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::MismaFuncion,
        porque: "las instrucciones AES del procesador no tienen ninguna otra lectura: un \
                 binario que las usa esta cifrando o descifrando con AES, y eso es un \
                 hecho, no un indicio",
    },
    Regla {
        nombre: "cifrado AES por tabla",
        familia: Familia::Cifrado,
        attack: Some("T1027"),
        senales: &[
            Senal::Constante(0x6363_6363),
            Senal::Constante(0x0100_0000),
            Senal::Constante(0x1B00_0000),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::MismaFuncion,
        porque: "son las constantes de la expansion de clave de AES: el valor con el que \
                 se rellena la caja de sustitucion y los dos primeros de la ronda. Una \
                 implementacion de AES en software las lleva todas",
    },
    Regla {
        nombre: "cifrado RC4",
        familia: Familia::Cifrado,
        attack: Some("T1027"),
        senales: &[Senal::BucleAcotadoA(256), Senal::Clase(Clase::Logica)],
        exigencia: Exigencia::Todas,
        ambito: Ambito::MismaFuncion,
        porque: "RC4 no tiene constantes propias, asi que su unico rastro es la forma: un \
                 bucle que rellena una tabla de exactamente 256 entradas y despues la \
                 combina con la entrada mediante una operacion logica. Es la regla mas \
                 debil del catalogo —hay tablas de 256 entradas legitimas— y esta escrita \
                 asi porque la version que solo miraba la constante 256 disparaba en \
                 /bin/ls, en /bin/bash y en la libc",
    },
    Regla {
        nombre: "cifrado ChaCha20 o Salsa20",
        familia: Familia::Cifrado,
        attack: Some("T1027"),
        senales: &[
            Senal::Constante(0x6170_7865),
            Senal::Constante(0x3320_646E),
            Senal::Constante(0x7962_2D32),
            Senal::Constante(0x6B20_6574),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::MismaFuncion,
        porque: "las cuatro constantes son las palabras «expand 32-byte k» leidas como \
                 numeros, y son el estado inicial de ChaCha20 y Salsa20. No aparecen en \
                 ningun otro sitio por casualidad",
    },
    // ----------------------------------------------------------- COMUNICACIONES
    Regla {
        nombre: "comunicacion por HTTP",
        familia: Familia::Comunicaciones,
        attack: Some("T1071.001"),
        senales: &[
            Senal::Importa("InternetOpen"),
            Senal::Importa("HttpSendRequest"),
            Senal::Importa("WinHttpOpen"),
            Senal::Importa("URLDownloadToFile"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "hablar HTTP no es malo por si mismo; lo que lo convierte en un hecho \
                 relevante es que el canal de mando de casi todo lo que hay usa HTTP \
                 precisamente porque se confunde con el trafico normal",
    },
    Regla {
        nombre: "comunicacion por sockets en crudo",
        familia: Familia::Comunicaciones,
        attack: Some("T1095"),
        senales: &[
            Senal::Importa("WSASocket"),
            Senal::Importa("connect"),
            Senal::Importa("send"),
            Senal::Importa("recv"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "un canal en crudo evita las bibliotecas de red del sistema, que son \
                 justo donde estan los ganchos de las herramientas de vigilancia",
    },
    Regla {
        nombre: "resolucion de nombres para dar con su servidor",
        familia: Familia::Comunicaciones,
        attack: Some("T1071.004"),
        senales: &[
            Senal::Importa("DnsQuery"),
            Senal::Importa("getaddrinfo"),
            Senal::Importa("gethostbyname"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "resolver un nombre es lo primero que hace cualquier cosa que quiera \
                 hablar con un servidor, y cuando el nombre se genera en ejecucion es la \
                 unica pista que queda de con quien habla",
    },
    Regla {
        nombre: "descarga y ejecucion de una segunda etapa",
        familia: Familia::Comunicaciones,
        attack: Some("T1105"),
        senales: &[
            Senal::Importa("URLDownloadToFile"),
            Senal::Importa("WinExec"),
            Senal::Importa("ShellExecute"),
            Senal::Importa("CreateProcess"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "traerse un fichero de la red y ejecutarlo es como un programa pequeno se \
                 convierte en cualquier otra cosa, y es la razon de que analizar solo el \
                 primer fichero no diga lo que va a pasar",
    },
    Regla {
        nombre: "canal de mando por el propio protocolo del sistema",
        familia: Familia::Comunicaciones,
        attack: Some("T1071"),
        senales: &[
            Senal::Importa("WinHttpSetOption"),
            Senal::Importa("InternetSetOption"),
            Senal::Importa("HttpAddRequestHeaders"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "cambiar las opciones y las cabeceras de la peticion sirve para que el \
                 trafico propio se parezca al de un navegador, que es lo que se hace \
                 cuando se quiere que no destaque",
    },
    // ------------------------------------------------------------- CREDENCIALES
    Regla {
        nombre: "volcado de la memoria del proceso de autenticacion",
        familia: Familia::Credenciales,
        attack: Some("T1003.001"),
        senales: &[
            Senal::Importa("MiniDumpWriteDump"),
            Senal::Importa("OpenProcess"),
            Senal::Importa("ReadProcessMemory"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "volcar la memoria de otro proceso saca de ella lo que ese proceso tenga \
                 en claro, y el proceso de autenticacion de Windows tiene en claro las \
                 credenciales de todo el que haya iniciado sesion",
    },
    Regla {
        nombre: "lectura de las credenciales guardadas del sistema",
        familia: Familia::Credenciales,
        attack: Some("T1555.004"),
        senales: &[
            Senal::Importa("CredEnumerate"),
            Senal::Importa("CredRead"),
            Senal::Importa("CryptUnprotectData"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "el almacen de credenciales del sistema y la funcion que descifra lo que \
                 el usuario guardo ahi existen para que un programa lea las contrasenas de \
                 ese usuario; leerlas todas es lo que hace un ladron de credenciales",
    },
    Regla {
        nombre: "captura de lo que se teclea",
        familia: Familia::Credenciales,
        attack: Some("T1056.001"),
        senales: &[
            Senal::Importa("SetWindowsHookEx"),
            Senal::Importa("GetAsyncKeyState"),
            Senal::Importa("GetKeyboardState"),
            Senal::Importa("RegisterRawInputDevices"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "leer el teclado desde fuera de la ventana que tiene el foco sirve para \
                 recoger lo que el usuario escribe en cualquier otro programa, incluidas \
                 sus contrasenas",
    },
    // -------------------------------------------------------------- DESTRUCCION
    Regla {
        nombre: "borrado de las copias de seguridad del sistema",
        familia: Familia::Destruccion,
        attack: Some("T1490"),
        senales: &[
            Senal::Importa("vssadmin"),
            Senal::Importa("IVssBackupComponents"),
            Senal::Importa("DeleteFile"),
            Senal::Importa("wbadmin"),
        ],
        exigencia: Exigencia::Alguna,
        ambito: Ambito::Global,
        porque: "borrar las instantaneas de volumen no tiene ninguna lectura util salvo \
                 impedir que se recupere lo que se va a destruir a continuacion; es el \
                 paso que separa un cifrado reversible de uno que no lo es",
    },
    Regla {
        nombre: "sobrescritura destructiva de ficheros",
        familia: Familia::Destruccion,
        attack: Some("T1485"),
        senales: &[
            Senal::Importa("SetFilePointer"),
            Senal::Importa("WriteFile"),
            Senal::Importa("FindFirstFile"),
            Senal::Importa("FindNextFile"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "recorrer el sistema de ficheros y escribir encima de lo que se encuentra \
                 es lo que hace un borrador; la diferencia con un programa que guarda \
                 datos es que este no crea ficheros nuevos, escribe sobre los que ya \
                 estaban",
    },
    Regla {
        nombre: "escritura directa en el disco por debajo del sistema de ficheros",
        familia: Familia::Destruccion,
        attack: Some("T1561.002"),
        senales: &[
            Senal::Importa("PhysicalDrive"),
            Senal::Importa("DeviceIoControl"),
            Senal::Importa("CreateFile"),
        ],
        exigencia: Exigencia::AlMenos(2),
        ambito: Ambito::Global,
        porque: "abrir el disco como dispositivo y escribir en el se salta el sistema de \
                 ficheros entero: es como se destruye el sector de arranque, y ningun \
                 programa normal necesita hacerlo",
    },
    // ---------------------------------------------------------- RECONOCIMIENTO
    Regla {
        nombre: "reconocimiento del equipo y de su dominio",
        familia: Familia::Reconocimiento,
        attack: Some("T1082"),
        senales: &[
            Senal::Importa("GetComputerName"),
            Senal::Importa("GetUserName"),
            Senal::Importa("NetWkstaGetInfo"),
            Senal::Importa("GetSystemInfo"),
        ],
        exigencia: Exigencia::AlMenos(3),
        ambito: Ambito::Global,
        porque: "preguntar a la vez por el nombre del equipo, el del usuario y el dominio \
                 es lo que hace algo que acaba de llegar y quiere saber donde ha caido \
                 antes de decidir que hacer",
    },
];

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn toda_regla_tiene_senales_y_una_exigencia_coherente() {
        // Una regla sin senales dispararia con `Exigencia::Todas` sobre
        // cualquier binario —cero de cero senales es «todas»—, y produciria una
        // capacidad sin evidencia en todos los ficheros del mundo.
        for r in CATALOGO {
            assert!(!r.senales.is_empty(), "{} no mira nada", r.nombre);
            if let Exigencia::AlMenos(n) = r.exigencia {
                assert!(n > 0, "{}: al menos cero es «siempre»", r.nombre);
                assert!(
                    n <= r.senales.len(),
                    "{}: pide {n} senales y solo tiene {}",
                    r.nombre,
                    r.senales.len()
                );
            }
        }
    }

    #[test]
    fn el_porque_de_cada_regla_explica_algo_y_no_repite_su_nombre() {
        // Un «porque» que repite el nombre de la regla no explica nada, y acaba
        // en el informe haciendo creer a quien lo lea que hay una razon escrita.
        for r in CATALOGO {
            assert!(
                r.porque.len() > 60,
                "{}: el porque es demasiado corto para explicar nada",
                r.nombre
            );
            assert_ne!(r.porque, r.nombre, "{}", r.nombre);
        }
    }

    #[test]
    fn no_hay_dos_reglas_con_el_mismo_nombre() {
        // Dos reglas con el mismo nombre se deduplican en el informe y una de
        // las dos desaparece sin que nadie se entere.
        let mut v: Vec<&str> = CATALOGO.iter().map(|r| r.nombre).collect();
        v.sort_unstable();
        let antes = v.len();
        v.dedup();
        assert_eq!(antes, v.len(), "hay nombres repetidos en el catalogo");
    }

    #[test]
    fn el_catalogo_cubre_las_familias_que_el_encargo_pedia() {
        // El recuento que se prometio: inyeccion x8, persistencia x5, evasion
        // x4, cifrado x4, comunicaciones x5, credenciales x3, destruccion x3.
        // Si alguna baja de ahi, es que se quito una regla sin decirlo.
        let cuenta = |f: Familia| CATALOGO.iter().filter(|r| r.familia == f).count();
        assert!(
            cuenta(Familia::Inyeccion) >= 8,
            "{}",
            cuenta(Familia::Inyeccion)
        );
        assert!(cuenta(Familia::Persistencia) >= 5);
        assert!(cuenta(Familia::Evasion) >= 4);
        assert!(cuenta(Familia::Cifrado) >= 4);
        assert!(cuenta(Familia::Comunicaciones) >= 5);
        assert!(cuenta(Familia::Credenciales) >= 3);
        assert!(cuenta(Familia::Destruccion) >= 3);
    }

    #[test]
    fn las_tecnicas_de_attack_tienen_forma_de_tecnica_de_attack() {
        // Un identificador mal escrito no falla en ninguna parte: simplemente no
        // cruza con nada cuando alguien agrega por tecnica, y el informe parece
        // completo.
        for r in CATALOGO {
            let Some(t) = r.attack else { continue };
            assert!(t.starts_with('T'), "{}: {t}", r.nombre);
            let cuerpo = &t[1..];
            assert!(
                cuerpo.chars().all(|c| c.is_ascii_digit() || c == '.'),
                "{}: {t}",
                r.nombre
            );
            assert!(cuerpo.len() >= 4, "{}: {t}", r.nombre);
        }
    }

    #[test]
    fn la_regla_de_rc4_es_la_mas_exigente_porque_es_la_mas_debil() {
        // RC4 no tiene constantes propias. Si esa regla exigiera una sola senal,
        // dispararia con cualquier binario que use el numero 256 —o sea, con
        // todos—. Que exija las tres es la decision que la hace utilizable.
        let r = CATALOGO
            .iter()
            .find(|r| r.nombre.contains("RC4"))
            .expect("la regla de RC4 tiene que estar");
        assert_eq!(r.exigencia, Exigencia::Todas);
    }

    #[test]
    fn solo_llevan_exigencia_de_una_sola_senal_las_que_no_tienen_lectura_alternativa() {
        // `Alguna` es la exigencia que mas ruido puede generar. Se permite solo
        // donde la senal no admite otra lectura, y esta prueba fija esa lista:
        // anadir una nueva obliga a pasar por aqui y a justificarla.
        let con_alguna: Vec<&str> = CATALOGO
            .iter()
            .filter(|r| r.exigencia == Exigencia::Alguna)
            .map(|r| r.nombre)
            .collect();
        let esperadas = [
            "persistencia por tarea programada",
            "deteccion de depurador",
            "deteccion de maquina virtual o entorno de analisis",
            "cifrado AES con las instrucciones del procesador",
            "comunicacion por HTTP",
            "resolucion de nombres para dar con su servidor",
            "lectura de las credenciales guardadas del sistema",
            "captura de lo que se teclea",
            "borrado de las copias de seguridad del sistema",
        ];
        for n in &con_alguna {
            assert!(
                esperadas.contains(n),
                "{n} exige una sola senal y no esta en la lista revisada: o se \
                 justifica aqui o se le sube la exigencia"
            );
        }
    }
}
