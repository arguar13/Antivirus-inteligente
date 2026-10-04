//! El grafo de flujo de control: bloques basicos, aristas y lo que no se alcanza.
//!
//! # Esto es una salida, no un detalle interno
//!
//! La FASE 100 construye el decompilador a pseudo-C **sobre este grafo**. Por eso
//! [`Cfg`] es publico y consultable —bloques, sucesores y predecesores— y no un
//! estado privado del motor de capacidades. Un grafo que solo sirviera para las
//! reglas de hoy habria que reconstruirlo entero manana, y reconstruirlo
//! significaria volver a equivocarse en los mismos sitios.
//!
//! Por la misma razon el grafo guarda **las instrucciones de cada bloque** y no
//! solo sus limites: un decompilador necesita las instrucciones, y volver a
//! decodificarlas mas tarde sobre bytes que quiza ya no esten es como se
//! introducen las discrepancias entre dos analisis del mismo binario.
//!
//! # Descenso recursivo, no barrido lineal
//!
//! El barrido lineal —decodificar desde el principio hasta el final— produce
//! instrucciones a partir de los datos que hay entre funciones, y en un binario
//! con relleno o con tablas incrustadas produce muchas. El descenso recursivo
//! sigue el flujo desde los puntos de entrada conocidos, asi que solo decodifica
//! lo que de verdad se ejecuta.
//!
//! El precio es que **no alcanza lo que solo se alcanza por un destino
//! calculado**. Eso no se disimula: cada transferencia indirecta se cuenta en
//! [`Cfg::indirectos`] y sale en la cobertura. Un grafo que callara eso pareceria
//! exhaustivo, y las funciones que faltan son justo las que un empaquetador
//! alcanza por registro.
//!
//! # Las tablas de saltos
//!
//! Un `switch` de C compila a un salto indirecto a traves de una tabla. Sin
//! resolverla, todo el cuerpo del `switch` queda fuera del grafo. Aqui se
//! resuelve con una condicion que se puede defender: se exige la **cota** —un
//! `cmp reg, N` cerca del salto— antes de leer nada, y se leen como mucho `N+1`
//! entradas, y solo se aceptan las que caen en codigo. Ver [`Cfg::construir`].
//!
//! Sin esa cota, un salto indirecto con un desplazamiento cualquiera haria leer
//! una tabla de tamano arbitrario elegido por el fichero. Es decir: seria una
//! via de agotamiento.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::DisasmError;
use crate::instruccion::{Clase, Flujo, Instruccion};
use crate::plazo::{Cobertura, Plazo};

/// Lo que el constructor del grafo necesita de un decodificador.
///
/// Es un rasgo para que x86 y ARM64 alimenten el mismo constructor sin que el
/// constructor sepa cual es cual.
pub trait Decodifica {
    /// Decodifica en una direccion.
    fn en(&self, direccion: u64) -> Result<Instruccion, DisasmError>;
    /// Si la direccion cae en el tramo de codigo.
    fn contiene(&self, direccion: u64) -> bool;
}

impl Decodifica for crate::x86::Tramo<'_> {
    fn en(&self, direccion: u64) -> Result<Instruccion, DisasmError> {
        crate::x86::Tramo::en(self, direccion)
    }
    fn contiene(&self, direccion: u64) -> bool {
        crate::x86::Tramo::contiene(self, direccion)
    }
}

impl Decodifica for crate::arm64::Tramo<'_> {
    fn en(&self, direccion: u64) -> Result<Instruccion, DisasmError> {
        crate::arm64::Tramo::en(self, direccion)
    }
    fn contiene(&self, direccion: u64) -> bool {
        crate::arm64::Tramo::contiene(self, direccion)
    }
}

/// Lectura de datos de la imagen, para resolver tablas de saltos.
///
/// Va aparte del decodificador porque una tabla de saltos no esta en la seccion
/// de codigo: esta en datos de solo lectura, y quien construye el grafo tiene
/// que poder leerla sin que eso signifique que puede decodificarla.
pub trait LeeDatos {
    /// Lee un puntero de 64 bits.
    fn u64_en(&self, direccion: u64) -> Option<u64>;
    /// Lee un entero de 32 bits.
    fn u32_en(&self, direccion: u64) -> Option<u32>;
}

/// Un lector que no tiene datos.
///
/// Con el, las tablas de saltos no se resuelven y se cuentan como indirectas.
/// Existe para que construir un grafo sin imagen completa sea posible y para que
/// la diferencia entre «no habia tabla» y «no se pudo leer» quede en el codigo.
#[derive(Debug, Clone, Copy, Default)]
pub struct SinDatos;

impl LeeDatos for SinDatos {
    fn u64_en(&self, _: u64) -> Option<u64> {
        None
    }
    fn u32_en(&self, _: u64) -> Option<u32> {
        None
    }
}

/// Un bloque basico: instrucciones que se ejecutan siempre juntas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bloque {
    /// Primera direccion.
    pub inicio: u64,
    /// Primera direccion que ya NO pertenece al bloque.
    pub fin: u64,
    /// Sus instrucciones, en orden.
    pub instrucciones: Vec<Instruccion>,
    /// A donde puede ir el control despues.
    pub sucesores: Vec<u64>,
    /// De donde puede venir.
    pub predecesores: Vec<u64>,
}

impl Bloque {
    /// Como termina el bloque.
    pub fn termina_en(&self) -> Option<Flujo> {
        self.instrucciones.last().map(|i| i.flujo)
    }

    /// Cuantas instrucciones tiene.
    pub fn longitud(&self) -> usize {
        self.instrucciones.len()
    }
}

/// Una tabla de saltos resuelta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablaDeSaltos {
    /// Donde estaba el salto indirecto.
    pub salto: u64,
    /// Donde empieza la tabla.
    pub base: u64,
    /// Cuantas entradas se aceptaron.
    pub entradas: usize,
    /// La cota que la hizo resoluble.
    pub cota: u64,
}

/// El grafo de flujo de control de una region de codigo.
#[derive(Debug, Clone, Default)]
pub struct Cfg {
    /// Por donde se empezo.
    pub entradas: Vec<u64>,
    /// Entradas de funcion descubiertas: los destinos de las llamadas directas.
    ///
    /// Van aparte de [`Cfg::entradas`] —que son las que pidio quien llamo— y
    /// **no** son sucesores de nadie: el control no pasa del que llama al
    /// llamado dentro de una misma funcion. Estan aqui porque son codigo y hay
    /// que desensamblarlo, y porque [`crate::llamadas`] necesita saber donde
    /// empieza cada funcion.
    pub raices: Vec<u64>,
    bloques: BTreeMap<u64, Bloque>,
    /// Direcciones de transferencias de control cuyo destino no se conoce.
    ///
    /// Es la medida honesta de lo que este grafo NO alcanza.
    pub indirectos: Vec<u64>,
    /// Las tablas de saltos que se pudieron resolver.
    pub tablas: Vec<TablaDeSaltos>,
    /// Que se llego a mirar.
    pub cobertura: Cobertura,
}

/// Tope de bloques de un grafo.
///
/// Un binario construido para eso puede declarar un millon de funciones de dos
/// instrucciones. El tope es la defensa de memoria, y llegar a el se cuenta como
/// corte en la cobertura.
pub const MAX_BLOQUES: usize = 200_000;

/// Tope de instrucciones dentro de un bloque.
///
/// Ningun bloque basico real es tan largo; uno que lo sea es codigo generado
/// para agotar al analizador.
pub const MAX_INSTRUCCIONES_POR_BLOQUE: usize = 100_000;

/// Por donde sigue el descenso despues de construir un bloque.
///
/// Los sucesores y las raices son cosas distintas y por eso viajan separados:
/// un sucesor es a donde va el control dentro de esta funcion, y una raiz es
/// otra funcion que hay que desensamblar. Devolverlos en una sola lista haria
/// que el cuerpo de cada funcion incluyera el de todas las que llama.
#[derive(Debug, Clone, Default)]
struct Continuacion {
    sucesores: Vec<u64>,
    raices: Vec<u64>,
}

/// Cuantas instrucciones hacia atras se busca la cota de una tabla de saltos.
const VENTANA_DE_COTA: usize = 8;

/// Tope de entradas que se leen de una tabla de saltos.
///
/// Aunque la cota diga mas. Un `cmp reg, 0xFFFFFFFF` es legal y pediria leer
/// cuatro mil millones de punteros.
const MAX_ENTRADAS_DE_TABLA: u64 = 4096;

impl Cfg {
    /// Construye el grafo por descenso recursivo desde unas entradas.
    pub fn construir(
        d: &dyn Decodifica,
        datos: &dyn LeeDatos,
        entradas: &[u64],
        plazo: &mut Plazo,
    ) -> Cfg {
        let mut cfg = Cfg {
            entradas: entradas.to_vec(),
            ..Default::default()
        };
        let mut pendientes: VecDeque<u64> = entradas.iter().copied().collect();
        let mut vistos: BTreeSet<u64> = BTreeSet::new();
        let mut cortado = false;

        while let Some(inicio) = pendientes.pop_front() {
            if !d.contiene(inicio) || !vistos.insert(inicio) {
                continue;
            }
            if cfg.bloques.len() >= MAX_BLOQUES {
                cortado = true;
                break;
            }
            match cfg.construir_bloque(d, datos, inicio, plazo) {
                Some(c) => {
                    for s in c.sucesores.iter().chain(c.raices.iter()) {
                        if !vistos.contains(s) {
                            pendientes.push_back(*s);
                        }
                    }
                    for r in c.raices {
                        cfg.raices.push(r);
                    }
                }
                None => {
                    cortado = true;
                    break;
                }
            }
        }

        // El orden importa: partir antes de enlazar, o los predecesores serian
        // los de un grafo que ya no existe.
        cfg.partir_solapados();
        cfg.enlazar_predecesores();
        cfg.raices.sort_unstable();
        cfg.raices.dedup();
        cfg.raices.retain(|r| cfg.bloques.contains_key(r));
        // Las funciones que se han llegado a desensamblar son las entradas mas
        // los destinos de llamada directa, no solo las entradas que pidio quien
        // llamo: contar solo esas ultimas diria «una funcion» de un binario del
        // que se han desensamblado cuarenta.
        let mut funciones: BTreeSet<u64> = cfg.raices.iter().copied().collect();
        funciones.extend(cfg.entradas.iter().filter(|e| cfg.bloques.contains_key(e)));
        cfg.cobertura.funciones = funciones.len();
        cfg.cobertura.instrucciones = plazo.gastadas();
        cfg.cobertura.transferencias_indirectas = cfg.indirectos.len();
        cfg.cobertura.bytes_cubiertos = cfg
            .bloques
            .values()
            .map(|b| b.fin.saturating_sub(b.inicio))
            .sum();
        cfg.cobertura.cortado_por_plazo = plazo.agotado_por_tiempo() || cortado;
        cfg.cobertura.cortado_por_tope = plazo.agotado_por_tope();
        cfg
    }

    /// Construye un bloque desde `inicio`. Devuelve por donde seguir, o `None`
    /// si se agoto el plazo a mitad.
    fn construir_bloque(
        &mut self,
        d: &dyn Decodifica,
        datos: &dyn LeeDatos,
        inicio: u64,
        plazo: &mut Plazo,
    ) -> Option<Continuacion> {
        let mut instrucciones: Vec<Instruccion> = Vec::new();
        let mut pc = inicio;
        let mut sucesores = Vec::new();
        let mut raices = Vec::new();

        loop {
            if !plazo.sigue() {
                // El bloque a medias se guarda igual: lo que se analizo es
                // informacion valida, y tirarlo solo perderia trabajo ya hecho.
                // Lo que NO se hace es dar el grafo por completo.
                break;
            }
            if instrucciones.len() >= MAX_INSTRUCCIONES_POR_BLOQUE {
                break;
            }
            let Ok(i) = d.en(pc) else { break };
            if !i.valida() {
                break;
            }
            let flujo = i.flujo;
            let siguiente = i.siguiente();
            // La instruccion se guarda ANTES de mirar su flujo, porque la que
            // termina el bloque forma parte de el.
            instrucciones.push(i);

            match flujo {
                Flujo::Secuencial | Flujo::Frontera | Flujo::Llamada { .. } => {
                    // Una llamada no termina el bloque —vuelve— y su destino
                    // **no** es sucesor de este bloque: el control no pasa de
                    // aqui a alli dentro de esta funcion, se va y vuelve.
                    //
                    // Pero si es codigo, y hay que desensamblarlo: es la entrada
                    // de otra funcion. Sale como RAIZ, no como sucesor. Meterlo
                    // de sucesor uniria el cuerpo del callee al del caller y
                    // haria que el grafo de flujo de una funcion contuviera
                    // todas las que llama; separarlos es lo que permite que el
                    // grafo de llamadas signifique algo.
                    match flujo {
                        Flujo::Llamada { destino: Some(dd) } => raices.push(dd),
                        Flujo::Llamada { destino: None } => self.indirectos.push(pc),
                        _ => {}
                    }
                    pc = siguiente;
                }
                Flujo::SaltoCondicional { destino } => {
                    sucesores.push(destino);
                    sucesores.push(siguiente);
                    break;
                }
                Flujo::SaltoIncondicional { destino: Some(dd) } => {
                    sucesores.push(dd);
                    break;
                }
                Flujo::SaltoIncondicional { destino: None } => {
                    self.indirectos.push(pc);
                    // Aqui, y solo aqui, se intenta la tabla de saltos.
                    if let Some(t) = self.resolver_tabla(datos, d, &instrucciones, pc) {
                        for s in &t.0 {
                            sucesores.push(*s);
                        }
                        self.tablas.push(t.1);
                    }
                    break;
                }
                Flujo::Retorno | Flujo::Parada => break,
            }
        }

        if instrucciones.is_empty() {
            self.cobertura.no_decodificables += 1;
            return Some(Continuacion::default());
        }
        let fin = instrucciones
            .last()
            .map(|i| i.siguiente())
            .unwrap_or(inicio);
        self.bloques.insert(
            inicio,
            Bloque {
                inicio,
                fin,
                instrucciones,
                sucesores: sucesores.clone(),
                predecesores: Vec::new(),
            },
        );
        Some(Continuacion { sucesores, raices })
    }

    /// Parte los bloques que contienen dentro el principio de otro.
    ///
    /// # El problema que resuelve
    ///
    /// El descenso recursivo construye cada bloque de corrido hasta su
    /// terminador, sin mirar si por el camino ha pasado por encima del principio
    /// de otro bloque. Con un `switch`, un `if` o cualquier salto hacia adelante
    /// pasa constantemente: el bloque que cae por debajo del destino del salto
    /// llega hasta el final, y ademas se crea un bloque en el destino. Las
    /// mismas instrucciones quedan en dos bloques a la vez.
    ///
    /// # Por que no es cosmetico
    ///
    /// Un grafo con bloques solapados no sirve para ningun analisis de flujo de
    /// datos. La misma instruccion se analiza dos veces con dos estados
    /// distintos, y de las dos respuestas ninguna es la buena: en
    /// [`crate::llamadas`] eso salia como un `call rax` resuelto **a dos
    /// direcciones a la vez**, cada una cierta por un camino. Y la FASE 100
    /// construye el decompilador sobre este grafo, donde instrucciones
    /// duplicadas serian sentencias duplicadas.
    ///
    /// # Como se parte
    ///
    /// El bloque se trunca en el principio del otro y se le pone como unico
    /// sucesor. No hace falta mover instrucciones: el bloque que ya existe en
    /// esa direccion se decodifico desde ahi, sobre los mismos bytes, asi que
    /// contiene exactamente la cola que se quita —y sus mismos sucesores.
    ///
    /// Solo se parte en una direccion que sea **frontera de instruccion** del
    /// bloque largo. En x86 dos flujos de instrucciones pueden solaparse de
    /// verdad —es una tecnica de ofuscacion conocida—, y ahi las dos lecturas
    /// son legitimas y distintas: partir seria inventarse que son la misma.
    fn partir_solapados(&mut self) {
        let inicios: BTreeSet<u64> = self.bloques.keys().copied().collect();
        let mut cambios: Vec<(u64, u64)> = Vec::new();
        for b in self.bloques.values() {
            // El primer principio ajeno que cae dentro y es frontera de
            // instruccion. Al truncar ahi, ningun otro puede quedar dentro.
            let corte = b
                .instrucciones
                .iter()
                .map(|i| i.direccion)
                .find(|dir| *dir != b.inicio && inicios.contains(dir));
            if let Some(c) = corte {
                cambios.push((b.inicio, c));
            }
        }
        for (inicio, corte) in cambios {
            let Some(b) = self.bloques.get_mut(&inicio) else {
                continue;
            };
            b.instrucciones.retain(|i| i.direccion < corte);
            b.fin = corte;
            b.sucesores = vec![corte];
        }
    }

    /// Intenta resolver una tabla de saltos detras de un salto indirecto.
    ///
    /// # La condicion que se exige, y por que
    ///
    /// Se exige encontrar **la cota** —un `cmp reg, N` en las ocho instrucciones
    /// anteriores— antes de leer un solo byte de la tabla. Es lo que un
    /// compilador emite siempre antes de un `switch`: sin comprobar el rango, un
    /// indice fuera de la tabla saltaria a cualquier sitio.
    ///
    /// Sin esa condicion habria que leer una tabla de tamano desconocido a
    /// partir de un desplazamiento que elige el fichero, es decir, una via de
    /// agotamiento con forma de analisis. Con ella, lo peor que puede pedir un
    /// fichero es [`MAX_ENTRADAS_DE_TABLA`] punteros.
    ///
    /// Solo se aceptan los destinos que caen en codigo: una tabla legitima
    /// apunta a codigo, y una construida a mano apuntaria a donde le conviniera.
    fn resolver_tabla(
        &self,
        datos: &dyn LeeDatos,
        d: &dyn Decodifica,
        instrucciones: &[Instruccion],
        salto: u64,
    ) -> Option<(Vec<u64>, TablaDeSaltos)> {
        // 1. La cota.
        let cota = instrucciones
            .iter()
            .rev()
            .take(VENTANA_DE_COTA)
            .find(|i| i.clase == Clase::Comparacion)
            .and_then(|i| i.inmediatos.first().copied())?;
        if cota == 0 || cota > MAX_ENTRADAS_DE_TABLA {
            return None;
        }

        // 2. La base de la tabla: el desplazamiento del propio salto indirecto,
        //    o el de la instruccion que cargo la direccion justo antes.
        let base = instrucciones
            .iter()
            .rev()
            .take(VENTANA_DE_COTA)
            .filter(|i| i.lee_memoria || i.clase == Clase::Direccion)
            .find_map(|i| i.inmediatos.first().copied())?;
        if base == 0 {
            return None;
        }

        // 3. Las entradas, acotadas por la cota y por el tope.
        let cuantas = (cota + 1).min(MAX_ENTRADAS_DE_TABLA);
        let mut destinos = Vec::new();
        for n in 0..cuantas {
            let Some(p) = datos.u64_en(base.wrapping_add(n.wrapping_mul(8))) else {
                break;
            };
            // Solo lo que cae en codigo. Una tabla legitima apunta a codigo.
            if d.contiene(p) {
                destinos.push(p);
            }
        }
        if destinos.is_empty() {
            return None;
        }
        let entradas = destinos.len();
        Some((
            destinos,
            TablaDeSaltos {
                salto,
                base,
                entradas,
                cota,
            },
        ))
    }

    /// Rellena los predecesores a partir de los sucesores.
    fn enlazar_predecesores(&mut self) {
        let aristas: Vec<(u64, u64)> = self
            .bloques
            .values()
            .flat_map(|b| b.sucesores.iter().map(move |s| (b.inicio, *s)))
            .collect();
        for (desde, hasta) in aristas {
            if let Some(b) = self.bloques.get_mut(&hasta) {
                if !b.predecesores.contains(&desde) {
                    b.predecesores.push(desde);
                }
            }
        }
    }

    /// Los bloques, ordenados por direccion.
    pub fn bloques(&self) -> impl Iterator<Item = &Bloque> {
        self.bloques.values()
    }

    /// Cuantos bloques hay.
    pub fn cuantos_bloques(&self) -> usize {
        self.bloques.len()
    }

    /// El bloque que empieza exactamente en `direccion`.
    pub fn bloque(&self, direccion: u64) -> Option<&Bloque> {
        self.bloques.get(&direccion)
    }

    /// El bloque que contiene `direccion`, empiece donde empiece.
    pub fn bloque_que_contiene(&self, direccion: u64) -> Option<&Bloque> {
        self.bloques
            .range(..=direccion)
            .next_back()
            .map(|(_, b)| b)
            .filter(|b| direccion < b.fin)
    }

    /// Todas las instrucciones del grafo, en orden de direccion.
    pub fn instrucciones(&self) -> impl Iterator<Item = &Instruccion> {
        self.bloques.values().flat_map(|b| b.instrucciones.iter())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::instruccion::Arquitectura;
    use crate::x86::Tramo;

    /// Un lector de datos sobre un mapa, para las tablas de saltos.
    struct Mapa(BTreeMap<u64, u64>);
    impl LeeDatos for Mapa {
        fn u64_en(&self, d: u64) -> Option<u64> {
            self.0.get(&d).copied()
        }
        fn u32_en(&self, d: u64) -> Option<u32> {
            self.0.get(&d).map(|v| *v as u32)
        }
    }

    #[test]
    fn un_bloque_recto_termina_en_el_retorno() {
        // xor eax,eax ; ret
        let t = Tramo::nuevo(&[0x31, 0xC0, 0xC3], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert_eq!(g.cuantos_bloques(), 1);
        let b = g.bloque(0x1000).unwrap();
        assert_eq!(b.longitud(), 2);
        assert_eq!(b.termina_en(), Some(Flujo::Retorno));
        assert!(b.sucesores.is_empty());
    }

    #[test]
    fn un_salto_condicional_produce_dos_sucesores_y_sus_predecesores() {
        // 0x1000: jne +2   (a 0x1004)
        // 0x1002: nop
        // 0x1003: ret
        // 0x1004: ret
        let bytes = [0x75, 0x02, 0x90, 0xC3, 0xC3];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);

        let b = g.bloque(0x1000).unwrap();
        assert_eq!(b.sucesores.len(), 2, "el que salta y el que sigue");
        assert!(b.sucesores.contains(&0x1004));
        assert!(b.sucesores.contains(&0x1002));

        // Y los predecesores se enlazan al reves: es lo que necesita el
        // decompilador de la FASE 100 para reconstruir un `if`.
        assert_eq!(g.bloque(0x1004).unwrap().predecesores, vec![0x1000]);
        assert_eq!(g.bloque(0x1002).unwrap().predecesores, vec![0x1000]);
    }

    #[test]
    fn una_llamada_no_parte_el_bloque_de_quien_llama() {
        // Una llamada vuelve. Partir el bloque en cada llamada convertiria
        // cualquier funcion normal en una cadena de bloques de una instruccion,
        // y la forma del grafo —que es lo que miran las reglas— dejaria de decir
        // nada.
        //
        //   0x1000 call 0x1010   (5 bytes)
        //   0x1005 nop
        //   0x1006 ret
        //   0x1010 ret           <- el llamado
        let mut bytes = vec![0x90u8; 0x11];
        bytes[0..5].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00]);
        bytes[6] = 0xC3;
        bytes[0x10] = 0xC3;
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        let b = g.bloque(0x1000).unwrap();
        assert_eq!(b.longitud(), 3, "call, nop y ret en un solo bloque");
        assert!(
            b.sucesores.is_empty(),
            "el llamado NO es sucesor: el control va y vuelve"
        );
    }

    #[test]
    fn el_destino_de_una_llamada_directa_si_se_desensambla() {
        // Es codigo, y hay que mirarlo: sin esto, un binario cuyo `main` solo
        // llama a otras funciones saldria como una funcion de tres
        // instrucciones. Va como RAIZ, no como sucesor.
        let mut bytes = vec![0x90u8; 0x11];
        bytes[0..5].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00]);
        bytes[6] = 0xC3;
        bytes[0x10] = 0xC3;
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert!(g.bloque(0x1010).is_some(), "el llamado se desensamblo");
        assert_eq!(g.raices, vec![0x1010]);
        assert_eq!(g.cobertura.funciones, 2, "la entrada y el llamado");
    }

    #[test]
    fn un_bloque_que_pasa_por_encima_de_otro_se_parte() {
        // El defecto que hacia inservible el grafo para cualquier analisis de
        // flujo de datos: con un salto hacia adelante, el bloque que cae por
        // debajo del destino llegaba hasta el final Y ademas se creaba un bloque
        // en el destino, con las mismas instrucciones en los dos.
        //
        //   0x1000 cmp edi, 0
        //   0x1003 je  0x1008
        //   0x1005 nop ; nop ; nop   <- cae por debajo de 0x1008
        //   0x1008 ret
        let bytes = [
            0x83, 0xFF, 0x00, // cmp edi, 0
            0x74, 0x03, // je 0x1008
            0x90, 0x90, 0x90, // nop nop nop
            0xC3, // 0x1008 ret
        ];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        let caido = g.bloque(0x1005).unwrap();
        assert_eq!(caido.fin, 0x1008, "se trunca donde empieza el otro");
        assert_eq!(caido.longitud(), 3, "los tres nop, y el ret no");
        assert_eq!(caido.sucesores, vec![0x1008]);
        // La propiedad general: ninguna instruccion esta en dos bloques.
        let mut vistas = BTreeSet::new();
        for b in g.bloques() {
            for i in &b.instrucciones {
                assert!(
                    vistas.insert(i.direccion),
                    "{:#x} aparece en dos bloques",
                    i.direccion
                );
            }
        }
    }

    #[test]
    fn un_salto_indirecto_se_cuenta_y_no_se_adivina() {
        // `jmp rax`: el destino se calcula en ejecucion. El grafo lo declara en
        // vez de inventarse una arista.
        let t = Tramo::nuevo(&[0xFF, 0xE0], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert_eq!(g.indirectos, vec![0x1000]);
        assert!(g.bloque(0x1000).unwrap().sucesores.is_empty());
        assert_eq!(g.cobertura.transferencias_indirectas, 1);
    }

    #[test]
    fn un_bucle_no_cuelga_el_constructor() {
        // `jmp .-2`: un bucle infinito. El grafo tiene que cerrarse sobre si
        // mismo, no recorrerlo para siempre.
        let t = Tramo::nuevo(&[0xEB, 0xFE], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert_eq!(g.cuantos_bloques(), 1);
        assert_eq!(g.bloque(0x1000).unwrap().sucesores, vec![0x1000]);
        assert!(g.cobertura.completa(), "no hizo falta cortar por plazo");
    }

    #[test]
    fn una_tabla_de_saltos_con_su_cota_se_resuelve() {
        // El patron de un `switch`: comparar con la cota y saltar por la tabla.
        // 0x1000: cmp eax, 2          (83 F8 02)
        // 0x1003: jmp [0x2000]        (FF 24 25 00 20 00 00)
        // y detras, los tres destinos, que son codigo.
        let mut bytes = vec![0x83, 0xF8, 0x02, 0xFF, 0x24, 0x25, 0x00, 0x20, 0x00, 0x00];
        bytes.resize(0x100, 0xC3); // relleno de `ret`, que es codigo valido
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let tabla = Mapa([(0x2000u64, 0x1020u64), (0x2008, 0x1030), (0x2010, 0x1040)].into());
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &tabla, &[0x1000], &mut p);

        assert_eq!(g.tablas.len(), 1, "la tabla se resolvio: {:?}", g.tablas);
        assert_eq!(g.tablas[0].cota, 2);
        assert_eq!(g.tablas[0].entradas, 3);
        // Y sus destinos son bloques del grafo, que es el punto: sin resolver la
        // tabla, el cuerpo entero del `switch` habria quedado fuera.
        assert!(g.bloque(0x1020).is_some());
        assert!(g.bloque(0x1040).is_some());
    }

    #[test]
    fn un_salto_indirecto_sin_cota_no_hace_leer_una_tabla() {
        // La defensa: sin la cota, la base y el tamano de la tabla los elegiria
        // el fichero. Aqui el salto indirecto no lleva `cmp` delante, asi que no
        // se lee nada aunque el lector de datos tenga punteros preparados.
        let t = Tramo::nuevo(&[0xFF, 0xE0], 0x1000, Arquitectura::X86_64).unwrap();
        let tabla = Mapa([(0x2000u64, 0x1000u64)].into());
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &tabla, &[0x1000], &mut p);
        assert!(g.tablas.is_empty());
        assert_eq!(g.indirectos.len(), 1);
    }

    #[test]
    fn una_cota_absurda_no_hace_leer_una_tabla_absurda() {
        // `cmp eax, 0x7FFFFFFF` es legal y pediria leer dos mil millones de
        // punteros. El tope corta eso antes de reservar nada.
        let bytes = vec![
            0x3D, 0xFF, 0xFF, 0xFF, 0x7F, // cmp eax, 0x7FFFFFFF
            0xFF, 0x24, 0x25, 0x00, 0x20, 0x00, 0x00, // jmp [0x2000]
        ];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let tabla = Mapa([(0x2000u64, 0x1000u64)].into());
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &tabla, &[0x1000], &mut p);
        assert!(
            g.tablas.is_empty(),
            "una cota mayor que el tope no resuelve tabla"
        );
    }

    #[test]
    fn el_grafo_expone_sus_instrucciones_para_la_fase_100() {
        // El decompilador necesita las instrucciones, no solo los limites de los
        // bloques. Volver a decodificarlas mas tarde sobre bytes que quiza ya no
        // esten es como se introducen discrepancias entre dos analisis del mismo
        // binario.
        let t = Tramo::nuevo(&[0x31, 0xC0, 0xC3], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        let v: Vec<_> = g.instrucciones().collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].clase, Clase::Logica);
    }

    #[test]
    fn se_encuentra_el_bloque_que_contiene_una_direccion_del_medio() {
        let t = Tramo::nuevo(&[0x31, 0xC0, 0xC3], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert_eq!(g.bloque_que_contiene(0x1001).unwrap().inicio, 0x1000);
        assert_eq!(g.bloque_que_contiene(0x1002).unwrap().inicio, 0x1000);
        assert!(g.bloque_que_contiene(0x1003).is_none(), "ya es el fin");
        assert!(g.bloque_que_contiene(0x0999).is_none());
    }

    #[test]
    fn un_plazo_agotado_deja_la_cobertura_incompleta() {
        // Lo que separa «no hay nada» de «no dio tiempo».
        let bytes = vec![0x90; 4096];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::nuevo(std::time::Duration::from_secs(3600), 10);
        let g = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        assert!(!g.cobertura.completa());
        assert!(g.cobertura.cortado_por_tope);
        assert!(
            g.cobertura.frase().contains("SE CORTO"),
            "{}",
            g.cobertura.frase()
        );
    }

    #[test]
    fn dos_entradas_producen_dos_arboles_en_el_mismo_grafo() {
        // 0x1000: ret ; 0x1001: ret — dos funciones de una instruccion.
        let t = Tramo::nuevo(&[0xC3, 0xC3], 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let g = Cfg::construir(&t, &SinDatos, &[0x1000, 0x1001], &mut p);
        assert_eq!(g.cuantos_bloques(), 2);
        assert_eq!(g.cobertura.funciones, 2);
    }
}
