//! Indice en disco: un millon de firmas sin un millon de firmas en memoria.
//!
//! # La aritmetica que obliga a esto
//!
//! Un corpus de ClamAV son dos millones de firmas. Aunque cada una ocupara solo
//! 48 bytes —hash de 32, tipo, longitud— eso son **96 MB solo en las claves**,
//! sin contar el mapa que las indexa ni los nombres.
//!
//! La cuota que el agente le da al corpus residente sale de `aegis-presupuesto`
//! y depende del host: **5 MiB en una pasarela de 1 GiB, 15 MiB en una estacion
//! de 16 GiB, 106 MiB en un host de base de datos**. Ni en el mejor de los casos
//! cabe el corpus entero, y en el peor no cabe ni el 5 %.
//!
//! No cabe, por tanto, en ninguna clase de host. Y no es «no cabe comodo»: no
//! cabe de ninguna manera, ni recortando ni comprimiendo. Cargar el corpus en
//! memoria es una decision que mata el presupuesto del agente el dia que el
//! corpus crece, que es siempre.
//!
//! # La estructura, y por que esta
//!
//! ```text
//!   [cabecera 32 B] [tabla de entradas, ORDENADA] [datos de longitud variable]
//! ```
//!
//! Las entradas son de **tamano fijo** y estan **ordenadas por clave**. Las dos
//! cosas juntas permiten una busqueda binaria haciendo `seek` sobre el fichero:
//! ~21 lecturas de 48 bytes para dos millones de entradas, sin cargar nada mas.
//!
//! Una estructura de tamano variable obligaria a recorrer desde el principio, y
//! una sin ordenar a cargarla entera para poder buscar. Las dos alternativas
//! acaban en lo mismo: el corpus en RAM.
//!
//! # Por que no hay mapeo de memoria
//!
//! `mmap` seria lo natural y exige `unsafe`: el fichero lo puede truncar otro
//! proceso mientras esta mapeado, y entonces leerlo es un fallo de segmento, no
//! un error. En un crate que procesa contenido de feeds externos eso no compensa
//! — y `seek` + `read` da lo mismo con un coste que ni se mide al lado de la
//! propia lectura de disco.
//!
//! # La residencia se MIDE, no se promete
//!
//! [`Indice::residencia_bytes`] dice cuanta memoria tiene el indice ocupada
//! ahora mismo. Hay una prueba que construye un corpus grande y comprueba la
//! cifra: una cota que nadie mide es una cota que nadie sabe si se cumple.
//!
//! Y la cota no se inventa aqui: [`Indice::abrir_para`] la pide al presupuesto
//! del host ([`aegis_presupuesto::Componente::Corpus`]) en vez de llevar una
//! constante propia. Una constante en cada consumidor es como un presupuesto
//! repartido deja de estar repartido: cada uno cree que su numero es pequeno y
//! la suma se pasa.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Marca de fichero, para no leer como indice algo que no lo es.
pub const MAGIA: &[u8; 8] = b"AEGISIDX";

/// Version del formato.
///
/// Un indice de una version que no se conoce NO se lee: leerlo interpretando
/// mal los campos daria firmas silenciosamente equivocadas, que es peor que no
/// tener indice.
pub const VERSION: u32 = 1;

/// Bytes de la cabecera.
const CABECERA: u64 = 32;

/// Bytes de cada entrada de la tabla.
///
/// Clave (32) + tipo (1) + relleno (3) + desplazamiento (8) + largo (4).
const ENTRADA: u64 = 48;

/// Coste en memoria de tener una entrada residente, en bytes.
///
/// No es `size_of::<Entrada>()`. Una entrada en la cache paga, ademas de la
/// estructura: la clave repetida como indice del mapa (32 B), la clave repetida
/// otra vez en el vector de orden (32 B) y sus datos de longitud variable. La
/// cifra es conservadora a proposito —contar de menos aqui seria prometer una
/// cota que el asignador no cumple— y [`Indice::residencia_bytes`] mide lo que
/// de verdad ocupa para que la promesa se pueda contrastar.
pub const COSTE_RESIDENTE: usize = 256;

/// Entradas que se conservan en memoria cuando nadie dice otra cosa.
///
/// El indice es en disco, pero un corpus que se consulta en rafaga —analizar un
/// directorio entero— repite claves. Una cache pequena evita volver al disco sin
/// convertir esto en «el corpus en RAM con pasos extra».
///
/// En el agente **no se usa este numero**: se usa [`Indice::abrir_para`], que
/// pide la cuota al presupuesto del host. Esta constante es el valor razonable
/// para las herramientas del plano de control, que no viven con esa cota.
pub const MAX_RESIDENTES: usize = 4096;

/// Que clase de cosa indexa una entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clase {
    /// Hash SHA-256 de un fichero.
    HashFichero,
    /// Hash de una seccion PE.
    HashSeccion,
    /// Firma de cuerpo.
    Cuerpo,
    /// Regla logica.
    Logica,
    /// Regla de red.
    Red,
    /// Regla sobre eventos.
    Evento,
}

impl Clase {
    /// Byte discriminante. Es parte del formato en disco: cambiarlo obliga a
    /// subir [`VERSION`].
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Clase::HashFichero => 1,
            Clase::HashSeccion => 2,
            Clase::Cuerpo => 3,
            Clase::Logica => 4,
            Clase::Red => 5,
            Clase::Evento => 6,
        }
    }

    /// Recupera la clase de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<Clase> {
        match t {
            1 => Some(Clase::HashFichero),
            2 => Some(Clase::HashSeccion),
            3 => Some(Clase::Cuerpo),
            4 => Some(Clase::Logica),
            5 => Some(Clase::Red),
            6 => Some(Clase::Evento),
            _ => None,
        }
    }
}

/// Lo que se guarda bajo una clave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Clave de 32 bytes. Para los hashes es el hash; para las reglas, el
    /// SHA-256 de su nombre, para que todo se pueda ordenar igual.
    pub clave: [u8; 32],
    /// Que clase de cosa es.
    pub clase: Clase,
    /// Carga util: el nombre de la firma, la regla serializada, lo que toque.
    pub datos: Vec<u8>,
}

/// Errores del indice.
#[derive(Debug, thiserror::Error)]
pub enum ErrorIndice {
    /// Fallo de entrada/salida.
    #[error("fallo de disco sobre «{ruta}»: {detalle}")]
    Disco {
        /// Que fichero.
        ruta: String,
        /// Que dijo el sistema.
        detalle: String,
    },
    /// El fichero no es un indice.
    #[error("«{0}» no es un indice de AegisCore (falta la marca)")]
    NoEsIndice(String),
    /// La version no se conoce.
    #[error(
        "el indice «{ruta}» es de la version {encontrada} y esta compilacion entiende la \
         {esperada}; leerlo interpretaria mal los campos y daria firmas equivocadas en silencio"
    )]
    VersionDesconocida {
        /// Fichero.
        ruta: String,
        /// Version que trae.
        encontrada: u32,
        /// Version que se entiende.
        esperada: u32,
    },
    /// El fichero esta truncado o incoherente.
    #[error("el indice «{ruta}» esta corrupto: {detalle}")]
    Corrupto {
        /// Fichero.
        ruta: String,
        /// Que no cuadra.
        detalle: String,
    },
}

fn disco(ruta: &Path, e: &std::io::Error) -> ErrorIndice {
    ErrorIndice::Disco {
        ruta: ruta.display().to_string(),
        detalle: e.to_string(),
    }
}

/// Construye un indice en disco a partir de entradas.
///
/// Las entradas se ordenan por clave antes de escribirse: es lo que hace posible
/// la busqueda binaria despues. Las claves repetidas se funden conservando la
/// primera, para que el fichero no tenga dos verdades sobre la misma clave.
///
/// # Errores
/// [`ErrorIndice::Disco`] si no se puede escribir.
pub fn construir(ruta: &Path, entradas: Vec<Entrada>) -> Result<usize, ErrorIndice> {
    let mut ordenadas: BTreeMap<[u8; 32], Entrada> = BTreeMap::new();
    for e in entradas {
        ordenadas.entry(e.clave).or_insert(e);
    }
    let n = ordenadas.len();

    let mut f = File::create(ruta).map_err(|e| disco(ruta, &e))?;

    // Cabecera.
    let mut cab = Vec::with_capacity(CABECERA as usize);
    cab.extend_from_slice(MAGIA);
    cab.extend_from_slice(&VERSION.to_le_bytes());
    cab.extend_from_slice(&(n as u64).to_le_bytes());
    cab.resize(CABECERA as usize, 0);
    f.write_all(&cab).map_err(|e| disco(ruta, &e))?;

    // Los datos van despues de la tabla, asi que primero hay que saber donde
    // empieza cada uno.
    let inicio_datos = CABECERA + (n as u64) * ENTRADA;
    let mut desplazamiento = inicio_datos;
    let mut tabla = Vec::with_capacity(n * ENTRADA as usize);
    let mut datos = Vec::new();

    for e in ordenadas.values() {
        tabla.extend_from_slice(&e.clave);
        tabla.push(e.clase.tag());
        tabla.extend_from_slice(&[0u8; 3]);
        tabla.extend_from_slice(&desplazamiento.to_le_bytes());
        tabla.extend_from_slice(&(e.datos.len() as u32).to_le_bytes());
        datos.extend_from_slice(&e.datos);
        desplazamiento += e.datos.len() as u64;
    }

    f.write_all(&tabla).map_err(|e| disco(ruta, &e))?;
    f.write_all(&datos).map_err(|e| disco(ruta, &e))?;
    f.flush().map_err(|e| disco(ruta, &e))?;
    Ok(n)
}

/// Un indice abierto, que consulta el disco en vez de cargarse en memoria.
#[derive(Debug)]
pub struct Indice {
    fichero: File,
    ruta: PathBuf,
    entradas: u64,
    /// Cache acotada de lo ya consultado.
    cache: BTreeMap<[u8; 32], Entrada>,
    /// Orden de llegada a la cache, para poder expulsar la mas antigua.
    orden_cache: Vec<[u8; 32]>,
    max_residentes: usize,
    /// Cuantas consultas se resolvieron sin tocar el disco.
    aciertos: u64,
    /// Cuantas tuvieron que ir al disco.
    fallos: u64,
}

impl Indice {
    /// Abre un indice ya construido, con el tope de residencia por omision.
    ///
    /// # Errores
    /// [`ErrorIndice`] si no existe, no es un indice, o su version no se conoce.
    pub fn abrir(ruta: &Path) -> Result<Indice, ErrorIndice> {
        Indice::abrir_con_tope(ruta, MAX_RESIDENTES)
    }

    /// Abre un indice con el tope que le corresponde a un presupuesto concreto.
    ///
    /// Es la forma que hay que usar en el agente: la cuota del corpus sale del
    /// host (5 MiB en una pasarela, 106 MiB en un servidor grande) en vez de ser
    /// la misma constante en todas partes. Un servidor con RAM de sobra que va al
    /// disco en cada consulta no esta siendo prudente: le esta robando E/S a la
    /// carga que de verdad justifica la maquina.
    ///
    /// # Errores
    /// Igual que [`Indice::abrir`].
    pub fn abrir_para(
        ruta: &Path,
        presupuesto: &aegis_presupuesto::Presupuesto,
    ) -> Result<Indice, ErrorIndice> {
        Indice::abrir_con_tope(ruta, Indice::residentes_para(presupuesto))
    }

    /// Entradas que caben en la cuota de corpus de un presupuesto.
    ///
    /// Se cuenta con el coste **real** de una entrada residente —la clave, los
    /// datos y lo que el mapa y el vector de orden anaden por elemento— y no solo
    /// con el tamano en disco: contar de menos aqui seria prometer una cota que
    /// el asignador no cumple.
    #[must_use]
    pub fn residentes_para(presupuesto: &aegis_presupuesto::Presupuesto) -> usize {
        let cuota = presupuesto.cuota(aegis_presupuesto::Componente::Corpus);
        let por_entrada = COSTE_RESIDENTE as u64;
        // Al menos una: un indice que no puede retener nada sigue funcionando
        // contra disco, pero un tope de cero convertiria la cache en codigo
        // muerto que se recorre sin servir para nada.
        usize::try_from(cuota / por_entrada)
            .unwrap_or(usize::MAX)
            .max(1)
    }

    /// Abre un indice con un tope de residencia explicito.
    ///
    /// # Errores
    /// Igual que [`Indice::abrir`].
    pub fn abrir_con_tope(ruta: &Path, max_residentes: usize) -> Result<Indice, ErrorIndice> {
        let mut f = File::open(ruta).map_err(|e| disco(ruta, &e))?;
        let mut cab = [0u8; CABECERA as usize];
        f.read_exact(&mut cab).map_err(|e| disco(ruta, &e))?;

        if &cab[..8] != MAGIA {
            return Err(ErrorIndice::NoEsIndice(ruta.display().to_string()));
        }
        let version = u32::from_le_bytes([cab[8], cab[9], cab[10], cab[11]]);
        if version != VERSION {
            return Err(ErrorIndice::VersionDesconocida {
                ruta: ruta.display().to_string(),
                encontrada: version,
                esperada: VERSION,
            });
        }
        let entradas = u64::from_le_bytes([
            cab[12], cab[13], cab[14], cab[15], cab[16], cab[17], cab[18], cab[19],
        ]);

        // La cuenta declarada tiene que caber en el fichero. Un indice truncado
        // se parece muchisimo a uno completo, y la unica forma de notarlo es
        // comprobar el tamano ANTES de hacer seeks que se saldrian del fichero.
        let tamano = f.metadata().map_err(|e| disco(ruta, &e))?.len();
        let minimo = CABECERA + entradas * ENTRADA;
        if tamano < minimo {
            return Err(ErrorIndice::Corrupto {
                ruta: ruta.display().to_string(),
                detalle: format!(
                    "declara {entradas} entradas, que necesitan {minimo} bytes, y el fichero \
                     tiene {tamano}"
                ),
            });
        }

        Ok(Indice {
            fichero: f,
            ruta: ruta.to_path_buf(),
            entradas,
            cache: BTreeMap::new(),
            orden_cache: Vec::new(),
            max_residentes: max_residentes.max(1),
            aciertos: 0,
            fallos: 0,
        })
    }

    /// Cuantas entradas tiene.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entradas
    }

    /// Si esta vacio.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entradas == 0
    }

    /// Bytes que el indice tiene ocupados en memoria ahora mismo.
    ///
    /// Es la cifra que se compara con el presupuesto del agente. Se expone
    /// porque una cota que nadie puede medir desde fuera no se puede verificar.
    #[must_use]
    pub fn residencia_bytes(&self) -> usize {
        let por_entrada = std::mem::size_of::<Entrada>();
        let datos: usize = self.cache.values().map(|e| e.datos.len()).sum();
        self.cache.len() * (por_entrada + std::mem::size_of::<[u8; 32]>())
            + datos
            + self.orden_cache.len() * std::mem::size_of::<[u8; 32]>()
    }

    /// Aciertos y fallos de la cache.
    #[must_use]
    pub fn estadisticas(&self) -> (u64, u64) {
        (self.aciertos, self.fallos)
    }

    /// Busca una clave.
    ///
    /// Busqueda binaria con `seek`: unas veintiuna lecturas de 48 bytes para dos
    /// millones de entradas, sin cargar el resto.
    ///
    /// # Errores
    /// [`ErrorIndice::Disco`] si falla la lectura.
    pub fn buscar(&mut self, clave: &[u8; 32]) -> Result<Option<Entrada>, ErrorIndice> {
        if let Some(e) = self.cache.get(clave) {
            self.aciertos += 1;
            return Ok(Some(e.clone()));
        }
        self.fallos += 1;

        let mut lo = 0u64;
        let mut hi = self.entradas;
        while lo < hi {
            let medio = lo + (hi - lo) / 2;
            let (clave_medio, clase, desplazamiento, largo) = self.leer_entrada(medio)?;
            match clave_medio.cmp(clave) {
                std::cmp::Ordering::Less => lo = medio + 1,
                std::cmp::Ordering::Greater => hi = medio,
                std::cmp::Ordering::Equal => {
                    let datos = self.leer_datos(desplazamiento, largo)?;
                    let e = Entrada {
                        clave: clave_medio,
                        clase,
                        datos,
                    };
                    self.recordar(e.clone());
                    return Ok(Some(e));
                }
            }
        }
        Ok(None)
    }

    /// Lee la entrada `n` de la tabla.
    fn leer_entrada(&mut self, n: u64) -> Result<([u8; 32], Clase, u64, u32), ErrorIndice> {
        let pos = CABECERA + n * ENTRADA;
        self.fichero
            .seek(SeekFrom::Start(pos))
            .map_err(|e| disco(&self.ruta, &e))?;
        let mut buf = [0u8; ENTRADA as usize];
        self.fichero
            .read_exact(&mut buf)
            .map_err(|e| disco(&self.ruta, &e))?;

        let mut clave = [0u8; 32];
        clave.copy_from_slice(&buf[..32]);
        let clase = Clase::desde_tag(buf[32]).ok_or_else(|| ErrorIndice::Corrupto {
            ruta: self.ruta.display().to_string(),
            detalle: format!("la entrada {n} declara la clase {}, que no existe", buf[32]),
        })?;
        let desplazamiento = u64::from_le_bytes([
            buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
        ]);
        let largo = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        Ok((clave, clase, desplazamiento, largo))
    }

    /// Lee la carga util de una entrada.
    fn leer_datos(&mut self, desplazamiento: u64, largo: u32) -> Result<Vec<u8>, ErrorIndice> {
        // El largo viene del fichero, que puede estar corrupto o manipulado. Sin
        // este tope, un largo inventado hace reservar lo que diga el fichero.
        const MAX_DATOS: u32 = 16 * 1024 * 1024;
        if largo > MAX_DATOS {
            return Err(ErrorIndice::Corrupto {
                ruta: self.ruta.display().to_string(),
                detalle: format!("una entrada declara {largo} bytes de datos, por encima del tope"),
            });
        }
        self.fichero
            .seek(SeekFrom::Start(desplazamiento))
            .map_err(|e| disco(&self.ruta, &e))?;
        let mut datos = vec![0u8; largo as usize];
        self.fichero
            .read_exact(&mut datos)
            .map_err(|e| disco(&self.ruta, &e))?;
        Ok(datos)
    }

    /// Mete una entrada en la cache, expulsando la mas antigua si hace falta.
    fn recordar(&mut self, e: Entrada) {
        if self.cache.len() >= self.max_residentes {
            if let Some(vieja) = self.orden_cache.first().copied() {
                self.cache.remove(&vieja);
                self.orden_cache.remove(0);
            }
        }
        self.orden_cache.push(e.clave);
        self.cache.insert(e.clave, e);
    }
}

/// Deriva la clave de 32 bytes de un nombre.
///
/// Se usa el SHA-256 del nombre para que las reglas se ordenen y se busquen con
/// el mismo mecanismo que los hashes, sin dos caminos de codigo que mantener.
#[must_use]
pub fn clave_de_nombre(nombre: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(nombre.as_bytes());
    let mut salida = [0u8; 32];
    salida.copy_from_slice(&d);
    salida
}

/// Convierte un hash hexadecimal de 64 caracteres en una clave.
#[must_use]
pub fn clave_de_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut salida = [0u8; 32];
    for (i, par) in hex.as_bytes().chunks(2).enumerate() {
        let texto = std::str::from_utf8(par).ok()?;
        salida[i] = u8::from_str_radix(texto, 16).ok()?;
    }
    Some(salida)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn entrada(n: u32, clase: Clase) -> Entrada {
        let mut clave = [0u8; 32];
        clave[..4].copy_from_slice(&n.to_be_bytes());
        Entrada {
            clave,
            clase,
            datos: format!("firma-numero-{n}").into_bytes(),
        }
    }

    #[test]
    fn lo_que_se_escribe_se_encuentra() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");

        let entradas: Vec<Entrada> = (0..1000).map(|n| entrada(n, Clase::HashFichero)).collect();
        let n = construir(&ruta, entradas.clone()).unwrap();
        assert_eq!(n, 1000);

        let mut idx = Indice::abrir(&ruta).unwrap();
        assert_eq!(idx.len(), 1000);

        for e in &entradas {
            let encontrada = idx.buscar(&e.clave).unwrap().expect("tiene que estar");
            assert_eq!(encontrada.datos, e.datos);
            assert_eq!(encontrada.clase, e.clase);
        }
    }

    /// Lo que NO esta, no esta: un indice que devuelve algo para cualquier clave
    /// haria que todo pareciera malicioso.
    #[test]
    fn lo_que_no_esta_no_se_encuentra() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");
        construir(&ruta, (0..100).map(|n| entrada(n, Clase::Cuerpo)).collect()).unwrap();

        let mut idx = Indice::abrir(&ruta).unwrap();
        let mut ausente = [0xFFu8; 32];
        ausente[0] = 0xEE;
        assert!(idx.buscar(&ausente).unwrap().is_none());
    }

    /// LA CIFRA QUE JUSTIFICA EL MODULO: un corpus grande consultado entero deja
    /// una residencia acotada, no proporcional al corpus.
    #[test]
    fn la_residencia_esta_acotada_aunque_el_corpus_sea_grande() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("grande.bin");

        const CUANTAS: u32 = 50_000;
        let entradas: Vec<Entrada> = (0..CUANTAS)
            .map(|n| entrada(n, Clase::HashFichero))
            .collect();
        construir(&ruta, entradas).unwrap();

        let mut idx = Indice::abrir_con_tope(&ruta, 512).unwrap();
        // Se consultan TODAS: el caso peor para la residencia.
        for n in 0..CUANTAS {
            let mut clave = [0u8; 32];
            clave[..4].copy_from_slice(&n.to_be_bytes());
            assert!(idx.buscar(&clave).unwrap().is_some(), "falta la {n}");
        }

        let residencia = idx.residencia_bytes();
        assert!(
            residencia < 256 * 1024,
            "tras consultar {CUANTAS} entradas la residencia es de {residencia} bytes"
        );
        // Y el fichero en disco es mucho mayor que lo que se tiene en memoria:
        // esa es exactamente la propiedad que se buscaba.
        let en_disco = std::fs::metadata(&ruta).unwrap().len();
        assert!(
            en_disco > residencia as u64 * 4,
            "en disco {en_disco}, en memoria {residencia}"
        );
    }

    /// LA COTA SE MIDE CONTRA LA CUOTA DEL HOST, no contra una constante local.
    ///
    /// Es la prueba que cierra el circulo del presupuesto: el indice pide su
    /// tope a `aegis-presupuesto`, se consulta un corpus entero para llegar al
    /// caso peor, y la residencia MEDIDA se compara con la cuota que el host le
    /// concedio. Sin esto, «cabe en la cuota» seria una frase.
    #[test]
    fn la_residencia_cabe_en_la_cuota_de_corpus_de_cada_clase_de_host() {
        use aegis_presupuesto::{Componente, Presupuesto};

        const GIB: u64 = 1024 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("cuota.bin");

        const CUANTAS: u32 = 20_000;
        let entradas: Vec<Entrada> = (0..CUANTAS)
            .map(|n| entrada(n, Clase::HashFichero))
            .collect();
        construir(&ruta, entradas).unwrap();

        for memoria in [GIB, 8 * GIB, 16 * GIB, 64 * GIB, 768 * GIB] {
            let presupuesto = Presupuesto::para(memoria);
            let cuota = presupuesto.cuota(Componente::Corpus);
            let mut idx = Indice::abrir_para(&ruta, &presupuesto).unwrap();

            // Se consultan TODAS: el caso peor para la residencia.
            for n in 0..CUANTAS {
                let mut clave = [0u8; 32];
                clave[..4].copy_from_slice(&n.to_be_bytes());
                assert!(idx.buscar(&clave).unwrap().is_some(), "falta la {n}");
            }

            let residencia = idx.residencia_bytes() as u64;
            assert!(
                residencia <= cuota,
                "host de {memoria} B: residencia medida {residencia} pasa de la cuota {cuota}"
            );
        }
    }

    /// Y el reparto se nota: un servidor retiene mucho mas que una pasarela.
    ///
    /// Si el tope saliera igual en las dos, la cuota por host seria decorativa.
    #[test]
    fn un_servidor_retiene_mucho_mas_corpus_que_una_pasarela() {
        use aegis_presupuesto::Presupuesto;

        const GIB: u64 = 1024 * 1024 * 1024;
        let pasarela = Indice::residentes_para(&Presupuesto::para(GIB));
        let servidor = Indice::residentes_para(&Presupuesto::para(768 * GIB));
        assert!(pasarela >= 1, "ni la pasarela puede quedarse en cero");
        assert!(
            servidor > pasarela * 10,
            "servidor {servidor} contra pasarela {pasarela}"
        );
    }

    /// La cache sirve de algo: repetir una consulta no vuelve al disco.
    #[test]
    fn repetir_una_consulta_no_vuelve_al_disco() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");
        construir(&ruta, (0..100).map(|n| entrada(n, Clase::Red)).collect()).unwrap();

        let mut idx = Indice::abrir(&ruta).unwrap();
        let clave = entrada(7, Clase::Red).clave;

        idx.buscar(&clave).unwrap();
        let (aciertos_antes, fallos_antes) = idx.estadisticas();
        assert_eq!(aciertos_antes, 0);
        assert_eq!(fallos_antes, 1);

        for _ in 0..10 {
            idx.buscar(&clave).unwrap();
        }
        let (aciertos, fallos) = idx.estadisticas();
        assert_eq!(aciertos, 10);
        assert_eq!(fallos, 1, "solo la primera fue al disco");
    }

    /// UN INDICE DE OTRA VERSION NO SE LEE. Leerlo interpretando mal los campos
    /// daria firmas silenciosamente equivocadas, que es peor que no tener
    /// indice: un fallo que no se ve.
    #[test]
    fn un_indice_de_otra_version_no_se_lee() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("futuro.bin");
        construir(&ruta, vec![entrada(1, Clase::Cuerpo)]).unwrap();

        // Se altera la version a mano.
        let mut datos = std::fs::read(&ruta).unwrap();
        datos[8..12].copy_from_slice(&999u32.to_le_bytes());
        std::fs::write(&ruta, &datos).unwrap();

        let e = Indice::abrir(&ruta).unwrap_err();
        assert!(matches!(e, ErrorIndice::VersionDesconocida { .. }), "{e:?}");
        assert!(e.to_string().contains("999"), "{e}");
    }

    /// Un fichero que no es un indice se dice, no se interpreta.
    #[test]
    fn un_fichero_cualquiera_no_se_toma_por_un_indice() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("otro.bin");
        std::fs::write(&ruta, b"esto no es un indice, son 32 bytes de texto...").unwrap();
        assert!(matches!(
            Indice::abrir(&ruta).unwrap_err(),
            ErrorIndice::NoEsIndice(_)
        ));
    }

    /// UN INDICE TRUNCADO SE PARECE MUCHISIMO A UNO COMPLETO. La unica forma de
    /// notarlo es comprobar que la cuenta declarada cabe en el fichero, ANTES de
    /// hacer seeks que se saldrian.
    #[test]
    fn un_indice_truncado_se_detecta_al_abrirlo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("truncado.bin");
        construir(&ruta, (0..100).map(|n| entrada(n, Clase::Logica)).collect()).unwrap();

        let datos = std::fs::read(&ruta).unwrap();
        std::fs::write(&ruta, &datos[..datos.len() / 2]).unwrap();

        let e = Indice::abrir(&ruta).unwrap_err();
        assert!(matches!(e, ErrorIndice::Corrupto { .. }), "{e:?}");
    }

    /// Las claves repetidas se funden: el fichero no puede tener dos verdades
    /// sobre la misma clave.
    #[test]
    fn las_claves_repetidas_se_funden() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("idx.bin");
        let mut a = entrada(1, Clase::HashFichero);
        a.datos = b"primera".to_vec();
        let mut b = entrada(1, Clase::HashFichero);
        b.datos = b"segunda".to_vec();

        let n = construir(&ruta, vec![a.clone(), b]).unwrap();
        assert_eq!(n, 1);

        let mut idx = Indice::abrir(&ruta).unwrap();
        assert_eq!(idx.buscar(&a.clave).unwrap().unwrap().datos, b"primera");
    }

    /// Un indice vacio es valido y no se encuentra nada en el.
    #[test]
    fn un_indice_vacio_es_valido() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("vacio.bin");
        assert_eq!(construir(&ruta, vec![]).unwrap(), 0);

        let mut idx = Indice::abrir(&ruta).unwrap();
        assert!(idx.is_empty());
        assert!(idx.buscar(&[0u8; 32]).unwrap().is_none());
    }

    /// Las claves se derivan de forma estable y sin colisiones tontas.
    #[test]
    fn las_claves_derivadas_son_estables_y_distintas() {
        assert_eq!(clave_de_nombre("Regla.A"), clave_de_nombre("Regla.A"));
        assert_ne!(clave_de_nombre("Regla.A"), clave_de_nombre("Regla.B"));

        let hex = "ab".repeat(32);
        let k = clave_de_hex(&hex).expect("64 caracteres hexadecimales");
        assert_eq!(k[0], 0xAB);
        assert!(clave_de_hex("corto").is_none());
        assert!(clave_de_hex(&"zz".repeat(32)).is_none());
    }
}
