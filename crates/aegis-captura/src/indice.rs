//! El indice por `(entidad, tiempo)`, recorrido con **cursor** y no con
//! desplazamiento.
//!
//! # Lo que este indice hace y el del sensor de referencia no
//!
//! Arkime indexa metadatos en un motor de busqueda de texto y guarda el PCAP al
//! lado. Buscar «todo el trafico de esta maquina» se convierte en una consulta
//! de texto sobre campos que alguien normalizo, y el resultado es tan bueno como
//! esa normalizacion.
//!
//! Aqui la clave es el [`Eid`], que se **deriva** de los hechos y es el mismo que
//! usan el motor de deteccion, el linaje y el caso. Buscar el trafico de una
//! entidad no es correlacionar: es mirar en su sitio.
//!
//! # Por que cursor y no desplazamiento
//!
//! Porque el almacen purga mientras se pagina. Con un desplazamiento —«dame los
//! cien siguientes a partir del mil»— una purga entre dos paginas desplaza todo
//! lo que hay detras y el analista se salta filas **sin enterarse**. Es el fallo
//! silencioso clasico de la paginacion por desplazamiento, y en un informe de
//! incidente significa que falta trafico y nadie lo sabe.
//!
//! Un cursor nombra **la ultima fila entregada**, no una posicion. Si esa fila se
//! purgo, se continua por la siguiente que exista, y el hecho de que se purgo se
//! puede decir. Nada se salta en silencio.

use std::collections::{BTreeMap, BTreeSet};

use aegis_entidad::entidad::Eid;

use crate::retencion::{Caducidad, Politica};

/// Lo que ocupa una entrada del indice, **medido y no estimado**.
///
/// Sale de `las_entradas_del_indice_ocupan_lo_que_dice_la_constante`, que
/// construye un indice lleno y mide los bytes vivos con un asignador que cuenta
/// por hilo: **156 bytes por entrada** con veinte mil entradas de doscientas
/// entidades, y el mismo numero exacto en ejecuciones repetidas. Son mas que los
/// ~90 que suman los campos, y la diferencia son los nodos del arbol, la clave
/// del cursor y el arbol de carga que hace barato el desalojo — es decir, el
/// coste de verdad y no el de contar los campos a mano.
///
/// Aqui se declaran **256**, que no es el redondeo de 156 por gusto: los nodos de
/// un `BTreeMap` guardan entre seis y once parejas, asi que un arbol que se llena
/// en mal orden ocupa casi el doble que uno que se llena en orden. La medida se
/// toma en el caso bueno, y el margen cubre el malo. Un techo derivado de la
/// medida optimista seria un techo que se pasa cuando el trafico no colabora.
///
/// Si una entrada engorda —un campo nuevo, un `String` donde habia un `Eid`—, la
/// prueba falla y esta constante hay que volver a MEDIRLA, que es el unico
/// momento en el que se puede cambiar. Subirla para que la prueba pase es como
/// subirle el limite a la alarma para que deje de sonar.
pub const COSTE_POR_ENTRADA: usize = 256;

/// La memoria que el indice **del agente** puede ocupar, en toda la maquina.
///
/// # De donde sale este numero
///
/// Del reparto de `aegis-presupuesto`, no de la intuicion. En el host mas pequeno
/// que se soporta, el agente entero tiene `SUELO_REPOSO` (48 MiB) en reposo; de
/// ahi salen primero los costes fijos (`FIJO_TOTAL`, 30 MiB), y lo elastico que
/// queda —18 MiB— se reparte por partes, de las que la red se lleva 22 de 100:
/// unos 4 MiB. Esos 4 MiB ya se los tiene pedidos el estado de los disectores
/// (`aegis_wire::MAX_MEMORIA_APP`), asi que **el indice no tiene sitio que no le
/// quite a otro**, y pedir un cuarto de esa parte es lo que se puede defender.
///
/// Un megabyte son 4096 entradas, que a los veintitres mil paquetes por segundo
/// medidos en esta fase son **menos de dos decimas de segundo de trafico a tope**.
/// Eso no es un descuido y no se disimula subiendo el numero: el indice del
/// agente es un sitio de paso hasta que se drena al almacen, y decirlo pequeno
/// obliga a que el drenaje exista de verdad en vez de suponerlo. El almacen del
/// servidor construye el suyo con [`Indice::con_tope`].
pub const MAX_MEMORIA_INDICE: usize = 1024 * 1024;

/// Cuantas entradas caben en el indice del agente.
pub const MAX_ENTRADAS: usize = MAX_MEMORIA_INDICE / COSTE_POR_ENTRADA;

// El techo del indice no puede comerse el de los disectores: los dos salen de la
// misma parte del presupuesto, y una cota que solo se cumple por separado no es
// una cota. Es la misma comprobacion que `aegis-disectores` hace con la suya, y
// esta escrita en el compilador porque una revision se olvida.
const _: () = assert!(MAX_MEMORIA_INDICE <= aegis_wire::MAX_MEMORIA_APP / 4);
const _: () = assert!(MAX_ENTRADAS > 0);

/// Un cursor: la ultima fila entregada.
///
/// Es opaco a proposito. Si fuera un numero, alguien lo sumaria — y sumarle uno a
/// un cursor es exactamente el error que el cursor existe para impedir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    cuando_ns: u64,
    secuencia: u64,
}

impl Cursor {
    /// El cursor del principio de los tiempos.
    #[must_use]
    pub fn principio() -> Cursor {
        Cursor {
            cuando_ns: 0,
            secuencia: 0,
        }
    }

    /// Como se escribe para mandarlo al cliente y que vuelva.
    #[must_use]
    pub fn texto(&self) -> String {
        format!("{:016x}-{:016x}", self.cuando_ns, self.secuencia)
    }

    /// Como se lee de vuelta.
    #[must_use]
    pub fn de_texto(s: &str) -> Option<Cursor> {
        let (a, b) = s.split_once('-')?;
        Some(Cursor {
            cuando_ns: u64::from_str_radix(a, 16).ok()?,
            secuencia: u64::from_str_radix(b, 16).ok()?,
        })
    }
}

/// Una entrada del indice: donde esta un trozo de trafico y de que es.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// De que entidad es. Es la clave, no un campo de texto.
    pub entidad: Eid,
    /// Cuando empieza, en nanosegundos desde la epoca.
    pub cuando_ns: u64,
    /// En que particion vive. La purga es por particion, no por fila.
    pub particion: Particion,
    /// Desplazamiento dentro de la particion.
    pub desde: u64,
    /// Cuantos bytes ocupa.
    pub bytes: u64,
    /// Cuantos paquetes son.
    pub paquetes: u32,
    /// Con que politica se guardo.
    pub politica: Politica,
    /// Cuando caduca.
    pub caducidad: Caducidad,
    /// Cuantos bytes se taparon al guardarlo.
    ///
    /// Va en el indice y no solo en el contenido porque decide si una
    /// reproduccion de este trozo puede dar el mismo veredicto. Ver
    /// [`crate::reproduccion::Fidelidad`].
    pub bytes_tapados: u64,
}

/// Una particion del almacen: un dia de un tipo de retencion.
///
/// # Por que el dia y no la hora ni el mes
///
/// Porque la purga es un `DROP` de particion, y el tamano de la particion decide
/// dos cosas que tiran en sentidos contrarios: cuanto se borra de golpe —y por
/// tanto cuanto se conserva de mas antes de poder borrar— y cuantas particiones
/// hay que recorrer en una busqueda. El dia es el punto en el que las dos cosas
/// son razonables con retenciones de semanas a meses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Particion {
    /// Dias desde la epoca.
    pub dia: u32,
    /// Con que politica se escribio.
    pub politica: Politica,
}

impl Particion {
    /// La particion que corresponde a un instante y una politica.
    #[must_use]
    pub fn de(cuando_ns: u64, politica: Politica) -> Particion {
        Particion {
            dia: (cuando_ns / 86_400_000_000_000) as u32,
            politica,
        }
    }

    /// Si esta particion ha caducado a fecha de `hoy_dia`.
    ///
    /// La caducidad la trae **cada entrada**, puesta cuando se escribio: una
    /// politica que se pueda cambiar despues borraria retroactivamente pruebas
    /// de un incidente abierto. Ver [`crate::retencion::Caducidad`].
    #[must_use]
    pub fn caducada(&self, hoy_dia: u32, caducidad: Caducidad) -> bool {
        hoy_dia.saturating_sub(self.dia) >= u32::from(caducidad.dias())
    }

    /// Como se nombra en el sistema de ficheros.
    #[must_use]
    pub fn nombre(&self) -> String {
        format!("{}-{:06}", self.politica.nombre(), self.dia)
    }
}

/// Lo que devuelve una busqueda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pagina {
    /// Las entradas de esta pagina, en orden de tiempo.
    pub entradas: Vec<Entrada>,
    /// Por donde seguir, si hay mas.
    pub siguiente: Option<Cursor>,
    /// Cuantas entradas se saltaron porque su particion ya se purgo.
    ///
    /// **No es cero por casualidad y no se calla.** Es la diferencia entre «no
    /// hubo mas trafico» y «lo hubo y ya no esta», que es la misma distincion que
    /// la cifra de cobertura de los disectores hace con los mensajes.
    pub purgadas: u64,
    /// Cuantas entradas se cayeron porque el indice estaba lleno.
    ///
    /// **Va aparte de `purgadas` porque se arregla de otra forma.** Una entrada
    /// purgada se fue porque se cumplio su retencion: es lo correcto, y no hay
    /// nada que arreglar. Una entrada desbordada se fue porque el agente no tenia
    /// sitio: se arregla drenando mas a menudo o subiendo el techo, y mientras no
    /// se arregle **falta trafico en el informe**. Juntarlas en un solo numero es
    /// el mismo error que dar una sola cifra de «paquetes perdidos» en el anillo.
    pub desbordadas: u64,
}

/// El indice.
///
/// # El techo, y por que lo tiene
///
/// El anillo acota el **contenido**, pero el sobre se anota de todo el trafico,
/// tambien del que no se guarda — que es el noventa y nueve por ciento—. Un
/// indice sin techo convierte «no guardamos casi nada» en una memoria que crece
/// con el trafico, y quien genera el trafico es el atacante. Una cota sobre lo
/// que ocupa cada flujo no es una cota: un millon de flujos de un kilobyte son un
/// gigabyte.
///
/// Por eso el indice tiene un techo de entradas, fijado al construirlo, y lo que
/// no cabe **se cuenta**.
#[derive(Debug)]
pub struct Indice {
    /// Por entidad y por cursor: es el orden en el que se pagina.
    por_entidad: BTreeMap<Eid, BTreeMap<Cursor, Entrada>>,
    /// Que particiones existen todavia.
    particiones: BTreeMap<Particion, u64>,
    /// La siguiente secuencia, que desempata dos entradas del mismo instante.
    secuencia: u64,
    /// Cuantas entradas se han perdido al purgar, por entidad.
    purgadas: BTreeMap<Eid, u64>,
    /// Cuantas se han perdido por desbordamiento, por entidad.
    desbordadas: BTreeMap<Eid, u64>,
    /// Cuantas entradas caben en total.
    tope: usize,
    /// Cuantas hay ahora. Se lleva al dia para no recorrer el arbol al comprobar
    /// el techo en cada paquete: un techo que cuesta O(entidades) comprobarlo se
    /// convierte el mismo en el amplificador que viene a impedir.
    total: usize,
    /// `(cuantas, entidad)`, para encontrar a la mas cargada en O(log n).
    carga: BTreeSet<(usize, Eid)>,
}

impl Default for Indice {
    fn default() -> Indice {
        Indice::con_tope(MAX_ENTRADAS)
    }
}

impl Indice {
    /// Un indice vacio con el techo del agente ([`MAX_ENTRADAS`]).
    #[must_use]
    pub fn nuevo() -> Indice {
        Indice::default()
    }

    /// Un indice vacio con un techo dicho a mano.
    ///
    /// Lo usa el almacen del servidor, que no vive en el presupuesto del agente y
    /// cuyo techo es el del disco. **No hay `sin_tope`**: el que llame tiene que
    /// escribir un numero, y un numero escrito se puede discutir en una revision.
    /// Un indice sin techo no.
    #[must_use]
    pub fn con_tope(tope: usize) -> Indice {
        Indice {
            por_entidad: BTreeMap::new(),
            particiones: BTreeMap::new(),
            secuencia: 0,
            purgadas: BTreeMap::new(),
            desbordadas: BTreeMap::new(),
            tope: tope.max(1),
            total: 0,
            carga: BTreeSet::new(),
        }
    }

    /// Cuantas entradas caben.
    #[must_use]
    pub fn tope(&self) -> usize {
        self.tope
    }

    /// Cuantas entradas se han caido por desbordamiento, en total.
    #[must_use]
    pub fn desbordadas(&self) -> u64 {
        self.desbordadas.values().sum()
    }

    /// Anade una entrada y devuelve su cursor.
    ///
    /// Si el indice esta lleno, **hace sitio desalojando a la entidad mas
    /// cargada**, no a la mas antigua del conjunto. Ver [`Indice::desalojar`].
    pub fn anadir(&mut self, e: Entrada) -> Cursor {
        // La secuencia desempata: dos paquetes del mismo nanosegundo son
        // frecuentes en una captura, y sin desempate uno taparia al otro.
        let c = Cursor {
            cuando_ns: e.cuando_ns,
            secuencia: self.secuencia,
        };
        self.secuencia += 1;

        if self.total >= self.tope {
            self.desalojar();
        }

        *self.particiones.entry(e.particion).or_insert(0) += 1;
        let eid = e.entidad.clone();
        let filas = self.por_entidad.entry(eid.clone()).or_default();
        let antes = filas.len();
        if filas.insert(c, e).is_none() {
            self.total += 1;
            self.carga.remove(&(antes, eid.clone()));
            self.carga.insert((antes + 1, eid));
        }
        c
    }

    /// Hace sitio para una entrada.
    ///
    /// # Por que se desaloja a la entidad mas cargada y no a la entrada mas antigua
    ///
    /// Porque la mas antigua del conjunto es de **otro**. Un atacante que genere
    /// trafico llenaria el indice y, entrada a entrada, borraria el sobre de todas
    /// las demas maquinas — incluida la que esta atacando—. Tendria, gratis, un
    /// borrador de pruebas: el sensor haria el trabajo de tapar el rastro.
    ///
    /// Desalojando a la entidad con mas entradas, el que inunda **se desaloja a si
    /// mismo**: sus entradas son las que sobran, y la maquina callada conserva las
    /// suyas. Dentro de la entidad si se va la mas antigua, que es la que menos
    /// dice de lo que esta pasando ahora.
    fn desalojar(&mut self) {
        let Some((cuantas, eid)) = self.carga.iter().next_back().cloned() else {
            return;
        };
        let Some(filas) = self.por_entidad.get_mut(&eid) else {
            // No puede pasar: `carga` y `por_entidad` se mueven juntos. Si
            // pasara, se deja de contar de mas en vez de entrar en bucle.
            self.carga.remove(&(cuantas, eid));
            return;
        };
        let Some(primero) = filas.keys().next().copied() else {
            self.carga.remove(&(cuantas, eid.clone()));
            self.por_entidad.remove(&eid);
            return;
        };
        if let Some(vieja) = filas.remove(&primero) {
            self.total -= 1;
            *self.desbordadas.entry(eid.clone()).or_insert(0) += 1;
            // La particion se va cuando se queda sin entradas: `particiones()`
            // dice cuales existen, y una con cero entradas no existe.
            if let Some(n) = self.particiones.get_mut(&vieja.particion) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.particiones.remove(&vieja.particion);
                }
            }
        }
        let ahora = filas.len();
        self.carga.remove(&(cuantas, eid.clone()));
        if ahora == 0 {
            self.por_entidad.remove(&eid);
        } else {
            self.carga.insert((ahora, eid));
        }
    }

    /// Cuantas entradas hay.
    #[must_use]
    pub fn cuantas(&self) -> usize {
        self.total
    }

    /// Si la contabilidad interna cuadra.
    ///
    /// `total` y `carga` se llevan al dia para que comprobar el techo cueste lo
    /// mismo con una entidad que con cien mil. Un contador que se lleva aparte del
    /// dato es un contador que se puede desincronizar, y un techo comprobado
    /// contra un numero equivocado no es un techo — asi que se comprueba, igual
    /// que las dos invariantes del anillo.
    #[must_use]
    pub fn cuadra(&self) -> bool {
        let contadas: usize = self.por_entidad.values().map(BTreeMap::len).sum();
        let carga_real: BTreeSet<(usize, Eid)> = self
            .por_entidad
            .iter()
            .map(|(eid, filas)| (filas.len(), eid.clone()))
            .collect();
        contadas == self.total
            && carga_real == self.carga
            && self.total <= self.tope
            && self.por_entidad.values().all(|f| !f.is_empty())
    }

    /// Cuantas entidades tienen trafico.
    #[must_use]
    pub fn entidades(&self) -> usize {
        self.por_entidad.len()
    }

    /// Las particiones que existen, de mas antigua a mas reciente.
    #[must_use]
    pub fn particiones(&self) -> Vec<(Particion, u64)> {
        self.particiones.iter().map(|(p, n)| (*p, *n)).collect()
    }

    /// Busca el trafico de una entidad a partir de un cursor.
    ///
    /// `desde` es **exclusivo**: se continua por lo siguiente a la ultima fila
    /// entregada. Devolver otra vez la ultima haria que el analista viera
    /// duplicados y dudara de la captura entera.
    #[must_use]
    pub fn buscar(&self, entidad: &Eid, desde: Option<Cursor>, tope: usize) -> Pagina {
        let perdidas = |m: &BTreeMap<Eid, u64>| m.get(entidad).copied().unwrap_or(0);
        let Some(filas) = self.por_entidad.get(entidad) else {
            return Pagina {
                entradas: Vec::new(),
                siguiente: None,
                purgadas: perdidas(&self.purgadas),
                desbordadas: perdidas(&self.desbordadas),
            };
        };
        let inicio = desde.unwrap_or(Cursor::principio());
        let mut entradas = Vec::new();
        let mut ultimo = None;
        for (c, e) in filas.range((
            if desde.is_some() {
                std::ops::Bound::Excluded(inicio)
            } else {
                std::ops::Bound::Unbounded
            },
            std::ops::Bound::Unbounded,
        )) {
            if entradas.len() >= tope {
                break;
            }
            entradas.push(e.clone());
            ultimo = Some(*c);
        }
        let hay_mas = ultimo.is_some_and(|u| {
            filas
                .range((std::ops::Bound::Excluded(u), std::ops::Bound::Unbounded))
                .next()
                .is_some()
        });
        Pagina {
            entradas,
            siguiente: if hay_mas { ultimo } else { None },
            purgadas: perdidas(&self.purgadas),
            desbordadas: perdidas(&self.desbordadas),
        }
    }

    /// Purga una particion entera.
    ///
    /// # Por que de golpe y no fila a fila
    ///
    /// Porque borrar fila a fila en un almacen de terabytes no acaba nunca, y
    /// mientras lo intenta el disco sigue lleno. Un `DROP` de particion es una
    /// operacion de metadatos: el espacio vuelve entero y de una vez.
    ///
    /// Devuelve cuantas entradas desaparecieron. Ese numero **se conserva por
    /// entidad** para que una busqueda pueda decir que lo hubo y ya no esta.
    pub fn purgar(&mut self, p: Particion) -> u64 {
        let mut fuera = 0u64;
        for (eid, filas) in &mut self.por_entidad {
            let cursores: Vec<Cursor> = filas
                .iter()
                .filter(|(_, e)| e.particion == p)
                .map(|(c, _)| *c)
                .collect();
            if cursores.is_empty() {
                continue;
            }
            *self.purgadas.entry(eid.clone()).or_insert(0) += cursores.len() as u64;
            let antes = filas.len();
            for c in cursores {
                filas.remove(&c);
                fuera += 1;
            }
            // La carga de esta entidad cambio, y con ella quien es la mas cargada.
            self.carga.remove(&(antes, eid.clone()));
            if !filas.is_empty() {
                self.carga.insert((filas.len(), eid.clone()));
            }
        }
        self.por_entidad.retain(|_, filas| !filas.is_empty());
        self.particiones.remove(&p);
        self.total -= fuera as usize;
        fuera
    }

    /// Purga todo lo caducado a fecha de `hoy_dia` y devuelve cuantas entradas.
    ///
    /// La caducidad se lee de cada entrada, no de una configuracion: lo que se
    /// escribio con ciento ochenta dias caduca a los ciento ochenta, cambie luego
    /// la politica lo que cambie.
    pub fn purgar_caducadas(&mut self, hoy_dia: u32) -> u64 {
        let caducadas: Vec<Particion> = self
            .particiones
            .keys()
            .copied()
            .filter(|p| {
                let c = Caducidad::de_politica(p.politica);
                p.caducada(hoy_dia, c)
            })
            .collect();
        caducadas.into_iter().map(|p| self.purgar(p)).sum()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    fn entrada(eid: &Eid, cuando_ns: u64, politica: Politica) -> Entrada {
        Entrada {
            entidad: eid.clone(),
            cuando_ns,
            particion: Particion::de(cuando_ns, politica),
            desde: 0,
            bytes: 1500,
            paquetes: 1,
            politica,
            caducidad: Caducidad::de_politica(politica),
            bytes_tapados: 0,
        }
    }

    fn dia(n: u64) -> u64 {
        n * 86_400_000_000_000
    }

    /// LA propiedad del indice: buscar el trafico de una entidad no es
    /// correlacionar por texto, es mirar en su sitio.
    #[test]
    fn el_trafico_de_una_entidad_esta_en_su_sitio() {
        let mut i = Indice::nuevo();
        let a = entidad::maquina("portatil-1");
        let b = entidad::maquina("servidor-2");
        for n in 0..50u64 {
            i.anadir(entrada(&a, n * 1000, Politica::SoloMetadatos));
            i.anadir(entrada(&b, n * 1000, Politica::SoloMetadatos));
        }
        let p = i.buscar(&a, None, 1000);
        assert_eq!(p.entradas.len(), 50);
        assert!(p.entradas.iter().all(|e| e.entidad == a));
        assert_eq!(i.entidades(), 2);
    }

    /// Un cursor nombra la ultima fila entregada, no una posicion. Es lo que
    /// impide que una purga entre dos paginas haga que el analista se salte filas
    /// sin enterarse.
    #[test]
    fn la_paginacion_por_cursor_no_se_salta_ni_repite_ninguna() {
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        for n in 0..250u64 {
            i.anadir(entrada(&a, n * 1000, Politica::SoloMetadatos));
        }
        let mut vistas = Vec::new();
        let mut cursor = None;
        loop {
            let p = i.buscar(&a, cursor, 40);
            vistas.extend(p.entradas.iter().map(|e| e.cuando_ns));
            match p.siguiente {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(vistas.len(), 250, "se saltaron o se repitieron filas");
        let mut ordenadas = vistas.clone();
        ordenadas.sort_unstable();
        ordenadas.dedup();
        assert_eq!(ordenadas.len(), 250);
        assert_eq!(vistas, ordenadas, "salieron desordenadas");
    }

    #[test]
    fn dos_entradas_del_mismo_instante_no_se_tapan() {
        // Dos paquetes del mismo nanosegundo son frecuentes en una captura, y
        // sin desempate uno taparia al otro en silencio.
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        for _ in 0..10 {
            i.anadir(entrada(&a, 42, Politica::SoloMetadatos));
        }
        assert_eq!(i.buscar(&a, None, 100).entradas.len(), 10);
    }

    /// La diferencia entre «no hubo mas trafico» y «lo hubo y ya no esta». Es la
    /// misma distincion que la cifra de cobertura de los disectores hace con los
    /// mensajes, y por la misma razon.
    #[test]
    fn una_busqueda_dice_cuanto_se_purgo_en_vez_de_callarlo() {
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        for n in 0..10u64 {
            i.anadir(entrada(&a, dia(n), Politica::SoloMetadatos));
        }
        let p0 = Particion::de(dia(0), Politica::SoloMetadatos);
        let p1 = Particion::de(dia(1), Politica::SoloMetadatos);
        assert_eq!(i.purgar(p0), 1);
        assert_eq!(i.purgar(p1), 1);

        let p = i.buscar(&a, None, 100);
        assert_eq!(p.entradas.len(), 8);
        assert_eq!(
            p.purgadas, 2,
            "la busqueda tiene que decir lo que ya no esta"
        );
    }

    #[test]
    fn la_purga_es_por_particion_y_se_lleva_la_particion_entera() {
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        let b = entidad::maquina("n");
        for k in 0..20u64 {
            i.anadir(entrada(&a, dia(3) + k, Politica::Completo));
            i.anadir(entrada(&b, dia(3) + k, Politica::Completo));
            i.anadir(entrada(&a, dia(4) + k, Politica::Completo));
        }
        let p3 = Particion::de(dia(3), Politica::Completo);
        assert_eq!(i.purgar(p3), 40, "se lleva las de las DOS entidades");
        assert_eq!(i.cuantas(), 20);
        assert!(!i.particiones().iter().any(|(p, _)| *p == p3));
    }

    #[test]
    fn cada_politica_vive_en_su_propia_particion() {
        // Purgar lo que solo era metadatos no puede llevarse por delante el
        // contenido que un veredicto autorizo guardar.
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        i.anadir(entrada(&a, dia(1), Politica::SoloMetadatos));
        i.anadir(entrada(&a, dia(1), Politica::Completo));
        assert_eq!(i.particiones().len(), 2);
        i.purgar(Particion::de(dia(1), Politica::SoloMetadatos));
        assert_eq!(i.cuantas(), 1);
        assert_eq!(
            i.buscar(&a, None, 10).entradas[0].politica,
            Politica::Completo
        );
    }

    #[test]
    fn lo_caducado_se_va_solo_y_lo_demas_se_queda() {
        let mut i = Indice::nuevo();
        let a = entidad::maquina("m");
        // Las cabeceras caducan a los treinta dias; lo completo a los ciento
        // ochenta. En el dia cien, lo primero se va y lo segundo no.
        i.anadir(entrada(&a, dia(0), Politica::Cabeceras));
        i.anadir(entrada(&a, dia(0), Politica::Completo));
        i.anadir(entrada(&a, dia(99), Politica::Cabeceras));
        // En el dia cien caduca UNA sola: la del dia cero con politica de
        // cabeceras. La del dia cero guardada entera dura ciento ochenta dias, y
        // la del dia noventa y nueve aun no llega a treinta.
        assert_eq!(i.purgar_caducadas(100), 1);
        let quedan = i.buscar(&a, None, 10).entradas;
        assert_eq!(quedan.len(), 2);
        assert!(quedan.iter().any(|e| e.politica == Politica::Completo));
        assert!(quedan.iter().any(|e| e.cuando_ns == dia(99)));

        // Y en el dia doscientos se va tambien lo completo del dia cero.
        assert_eq!(i.purgar_caducadas(200), 2);
        assert_eq!(i.cuantas(), 0);
    }

    #[test]
    fn el_cursor_viaja_al_cliente_y_vuelve_igual() {
        let c = Cursor {
            cuando_ns: 0x1234_5678_9abc_def0,
            secuencia: 42,
        };
        assert_eq!(Cursor::de_texto(&c.texto()), Some(c));
        assert_eq!(Cursor::de_texto("no es un cursor"), None);
        assert_eq!(Cursor::de_texto("zz-zz"), None);
    }

    #[test]
    fn una_entidad_sin_trafico_devuelve_vacio_y_no_se_inventa_nada() {
        let i = Indice::nuevo();
        let p = i.buscar(&entidad::maquina("no-existe"), None, 10);
        assert!(p.entradas.is_empty());
        assert!(p.siguiente.is_none());
        assert_eq!(p.purgadas, 0);
    }

    #[test]
    fn la_particion_se_nombra_por_su_politica_y_su_dia() {
        let p = Particion::de(dia(7) + 500, Politica::Completo);
        assert_eq!(p.dia, 7);
        assert_eq!(p.nombre(), "completo-000007");
        assert!(p.caducada(300, Caducidad::de_dias(180)));
        assert!(!p.caducada(100, Caducidad::de_dias(180)));
    }
}
