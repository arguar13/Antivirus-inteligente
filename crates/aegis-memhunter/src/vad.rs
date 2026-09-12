//! El modelo de una region del espacio de direcciones, y como se obtiene en cada
//! sistema.
//!
//! # Por que un modelo propio y no el de `aegis-scal`
//!
//! `aegis_scal::memory::MemoryRegion` describe lo que hace falta para **leer**
//! memoria: rango, permisos y fichero detras. Este modulo necesita otra cosa: las
//! **metricas de respaldo** de cada region —cuanta de su memoria ha dejado de
//! pertenecer al fichero— y, en Windows, la proteccion **inicial**. Sin esos dos
//! campos no hay deteccion de *module stomping* ni de cargador reflexivo, y
//! meterlos en el modelo de lectura habria obligado a todo el producto a pagar un
//! parseo de `smaps` (que es diez veces mas caro que el de `maps`) para escanear
//! un buffer.
//!
//! # Los dos niveles de evidencia, y por que se usan los dos
//!
//! | Fuente | Granularidad | Coste | Que aporta |
//! |---|---|---|---|
//! | `smaps` | por region | un parseo de texto | `Anonymous:` > 0 en una region de codigo = hubo copia privada |
//! | `pagemap` | por pagina | 8 bytes por pagina | **cuales** paginas y cuantas |
//!
//! El cazador usa `smaps` para **triar** —descarta en microsegundos el 99 % del
//! espacio de direcciones— y baja a `pagemap` solo sobre las regiones que ya son
//! candidatas. Es lo que mantiene el analisis de un proceso real en latencias de
//! un digito en milisegundos: leer `pagemap` de todo el espacio de un navegador
//! serian decenas de megabytes de entradas para confirmar lo que la triacion ya
//! habia descartado.

use std::fmt;

use crate::MemHunterError;

/// Tamano de pagina que asume el analisis.
///
/// 4 KiB es el tamano de pagina base en x86-64 y en ARM64 con el kernel que
/// despliega cualquier distribucion de servidor. Las paginas enormes
/// (`KernelPageSize` de 2 MiB) existen, y `pagemap` sigue indexandose por
/// paginas de 4 KiB aunque el mapeo sea enorme: la indexacion NO cambia, que es
/// lo unico de lo que depende este modulo.
pub const PAGINA: u64 = 4096;

/// Proteccion efectiva de una region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Proteccion {
    /// Lectura.
    pub lectura: bool,
    /// Escritura.
    pub escritura: bool,
    /// Ejecucion.
    pub ejecucion: bool,
}

impl Proteccion {
    /// Lectura, escritura y ejecucion a la vez.
    ///
    /// Casi ningun compilador produce esto. Lo producen los empaquetadores, los
    /// JIT y el shellcode que se descomprime a si mismo.
    #[must_use]
    pub const fn es_rwx(self) -> bool {
        self.lectura && self.escritura && self.ejecucion
    }

    /// Analiza el campo `rwxp` de una linea de `/proc/<pid>/maps`.
    #[must_use]
    pub fn desde_maps(s: &str) -> Proteccion {
        let b = s.as_bytes();
        Proteccion {
            lectura: b.first() == Some(&b'r'),
            escritura: b.get(1) == Some(&b'w'),
            ejecucion: b.get(2) == Some(&b'x'),
        }
    }
}

impl fmt::Display for Proteccion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.lectura { 'r' } else { '-' },
            if self.escritura { 'w' } else { '-' },
            if self.ejecucion { 'x' } else { '-' }
        )
    }
}

/// Que hay detras de una region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Respaldo {
    /// Una imagen ejecutable mapeada por el cargador del sistema (un `.so`, un
    /// `.exe`, una DLL). Es el unico respaldo desde el que el codigo legitimo se
    /// ejecuta.
    Imagen {
        /// Ruta del fichero.
        ruta: String,
        /// Inodo, que es lo que ata la region al fichero aunque lo renombren.
        inodo: u64,
        /// Desplazamiento dentro del fichero.
        desplazamiento: u64,
    },
    /// Un fichero mapeado que no es codigo (datos, un mapeo de memoria
    /// compartida con respaldo).
    Mapeado {
        /// Ruta del fichero.
        ruta: String,
        /// Inodo.
        inodo: u64,
        /// Desplazamiento.
        desplazamiento: u64,
    },
    /// Memoria sin fichero detras.
    Anonima,
    /// Region especial del kernel o del proceso: `[heap]`, `[stack]`, `[vdso]`,
    /// `[vvar]`, `[vsyscall]`.
    Especial(String),
}

impl Respaldo {
    /// La ruta del fichero, si hay fichero.
    #[must_use]
    pub fn ruta(&self) -> Option<&str> {
        match self {
            Respaldo::Imagen { ruta, .. } | Respaldo::Mapeado { ruta, .. } => Some(ruta),
            _ => None,
        }
    }

    /// `true` si hay un fichero detras de la region.
    #[must_use]
    pub const fn es_de_fichero(&self) -> bool {
        matches!(self, Respaldo::Imagen { .. } | Respaldo::Mapeado { .. })
    }
}

/// Una region del espacio de direcciones con todo lo que hace falta para
/// decidir si es anomala.
///
/// El nombre viene del **VAD** de Windows (*Virtual Address Descriptor*), que es
/// la estructura con la que el kernel describe cada reserva. En Linux el
/// equivalente es la `vm_area_struct` (una linea de `maps`); el modelo es el
/// mismo salvo por un campo que solo Windows conserva: [`Self::proteccion_inicial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionVad {
    /// Direccion inicial.
    pub inicio: u64,
    /// Direccion final, exclusiva.
    pub fin: u64,
    /// Proteccion actual.
    pub proteccion: Proteccion,
    /// Proteccion con la que se RESERVO la region.
    ///
    /// `None` en Linux: el kernel no la conserva, `mprotect` la sobrescribe sin
    /// dejar rastro en `maps`. Windows SI la conserva en el VAD, y la devuelve en
    /// `AllocationProtect`. Es un dato de mucho valor: el cargador reflexivo
    /// reserva `RW`, escribe la carga util y la deja en `RX`, asi que cuando el
    /// escaner mira no hay ni una pagina `RWX`... pero el VAD sigue diciendo que
    /// aquello nacio escribible.
    pub proteccion_inicial: Option<Proteccion>,
    /// Si el mapeo es compartido (`s`) en vez de privado (`p`).
    pub compartida: bool,
    /// Que hay detras.
    pub respaldo: Respaldo,
    /// Memoria residente de la region, en KiB (`Rss` de `smaps`).
    pub residente_kb: u64,
    /// Memoria de la region que **ya no pertenece a ningun fichero**, en KiB
    /// (`Anonymous` de `smaps`).
    ///
    /// En una region anonima es, por definicion, toda la residente. En una region
    /// respaldada por fichero deberia ser CERO, y cuando no lo es significa que
    /// hubo copia privada (copy-on-write) sobre paginas del fichero. Sobre una
    /// region de CODIGO, eso es la firma del *module stomping*.
    pub anonima_kb: u64,
    /// Paginas privadas modificadas, en KiB (`Private_Dirty` de `smaps`).
    ///
    /// Corrobora a `anonima_kb` desde otro contador del kernel. Se conservan los
    /// dos porque proceden de caminos distintos dentro del kernel y un valor sin
    /// el otro es una senal mas debil.
    pub privada_sucia_kb: u64,
}

impl RegionVad {
    /// Tamano en bytes.
    #[must_use]
    pub const fn tamano(&self) -> u64 {
        self.fin.saturating_sub(self.inicio)
    }

    /// Numero de paginas de 4 KiB que cubre.
    #[must_use]
    pub const fn paginas(&self) -> u64 {
        self.tamano().div_ceil(PAGINA)
    }

    /// `true` si la region es ejecutable.
    #[must_use]
    pub const fn es_ejecutable(&self) -> bool {
        self.proteccion.ejecucion
    }

    /// `true` si la region la mapeo EL KERNEL, no el cargador ni el proceso.
    ///
    /// `[vdso]`, `[vvar]`, `[vsyscall]` y companía. El kernel las crea en cada
    /// proceso y las etiqueta el mismo: la etiqueta sale de `vm_ops->name` del
    /// propio kernel, y un atacante NO puede hacer que su mapeo se imprima asi en
    /// `maps`. Por eso excluirlas es seguro y no abre un hueco.
    ///
    /// Distinguirlas importa mucho: el **vDSO es una imagen ELF de verdad mapeada
    /// en memoria sin fichero detras**, asi que sin esta comprobacion aparece como
    /// carga reflexiva EN TODO PROCESO DE LINUX. Un detector que emite una alerta
    /// critica por proceso en toda la flota no es un detector, es ruido; y el ruido
    /// es como se consigue que nadie mire las alertas de verdad. Lo encontro la
    /// prueba que caza un proceso real: con datos sinteticos no habria salido.
    ///
    /// `[heap]` y `[stack]` NO entran aqui a proposito: pese a llevar etiqueta, son
    /// memoria del proceso y una pila ejecutable es una de las anomalias mas graves
    /// que hay. El analizador de `smaps` ya las clasifica como anonimas.
    #[must_use]
    pub fn es_mapeo_del_kernel(&self) -> bool {
        matches!(self.respaldo, Respaldo::Especial(_))
    }

    /// `true` si la region es ejecutable y NO tiene fichero detras.
    ///
    /// Es la consulta de mas valor del modulo: el codigo legitimo se ejecuta
    /// desde imagenes mapeadas. Lo que aparece aqui son los JIT y el codigo
    /// cargado reflexivamente.
    ///
    /// Los mapeos del kernel ([`Self::es_mapeo_del_kernel`]) quedan fuera: son
    /// ejecutables y no tienen fichero, pero no los puso nadie de espacio de
    /// usuario.
    #[must_use]
    pub fn es_ejecutable_sin_fichero(&self) -> bool {
        self.es_ejecutable() && !self.respaldo.es_de_fichero() && !self.es_mapeo_del_kernel()
    }

    /// `true` si es la seccion de codigo de un modulo mapeado.
    #[must_use]
    pub fn es_codigo_de_modulo(&self) -> bool {
        self.es_ejecutable() && matches!(self.respaldo, Respaldo::Imagen { .. })
    }

    /// Fraccion de la region que ha dejado de pertenecer al fichero, en `0.0..=1.0`.
    ///
    /// Se mide sobre el TAMANO de la region y no sobre lo residente, y eso es
    /// deliberado: con lo residente como denominador, una region de la que solo
    /// hay una pagina dentro —y esa pagina copiada— daria 1,0 y se reportaria
    /// como un modulo sobrescrito entero. Con el tamano, la fraccion dice lo que
    /// el analista necesita: **cuanto** del modulo dejo de ser el modulo.
    #[must_use]
    pub fn fraccion_desligada(&self) -> f64 {
        let total_kb = self.tamano() / 1024;
        if total_kb == 0 {
            return 0.0;
        }
        (self.anonima_kb as f64 / total_kb as f64).clamp(0.0, 1.0)
    }
}

/// Analiza `/proc/<pid>/smaps` completo.
///
/// Acepta tambien la salida de `maps` (sin las metricas): las regiones salen con
/// los contadores a cero y el cazador lo tiene en cuenta —sin `Anonymous` no
/// puede afirmar que hubo copia privada, y no la afirma—.
///
/// # Errores
/// [`MemHunterError::Formato`] si una cabecera de region no tiene el formato
/// esperado. Un `/proc` que cambie de formato tiene que ROMPER, no devolver cero
/// anomalias: cero anomalias se lee como "esta maquina esta limpia".
pub fn analizar_smaps(texto: &str) -> Result<Vec<RegionVad>, MemHunterError> {
    let mut regiones: Vec<RegionVad> = Vec::new();
    for (i, linea) in texto.lines().enumerate() {
        if let Some((clave, valor)) = metrica(linea) {
            // Una metrica antes de cualquier cabecera es un fichero corrupto, no
            // un caso a ignorar en silencio.
            let Some(actual) = regiones.last_mut() else {
                return Err(MemHunterError::Formato {
                    fichero: "smaps",
                    linea: i + 1,
                    detalle: format!("metrica '{clave}' sin region a la que pertenecer"),
                });
            };
            match clave {
                "Rss" => actual.residente_kb = valor,
                "Anonymous" => actual.anonima_kb = valor,
                "Private_Dirty" => actual.privada_sucia_kb = valor,
                _ => {}
            }
            continue;
        }
        // Las lineas no-metrica que no son cabecera (p. ej. `VmFlags:` o
        // `THPeligible:`) se ignoran; una cabecera mal formada, no.
        if es_cabecera(linea) {
            regiones.push(analizar_cabecera(linea, i + 1)?);
        }
    }
    Ok(regiones)
}

/// `true` si la linea parece una cabecera de region (`inicio-fin perms ...`).
fn es_cabecera(linea: &str) -> bool {
    let Some(primero) = linea.split_whitespace().next() else {
        return false;
    };
    match primero.split_once('-') {
        Some((a, b)) => {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_hexdigit())
                && b.bytes().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Extrae `("Rss", 140)` de una linea `Rss:    140 kB`.
fn metrica(linea: &str) -> Option<(&str, u64)> {
    let (clave, resto) = linea.split_once(':')?;
    if clave.is_empty() || clave.contains(char::is_whitespace) {
        return None;
    }
    let valor = resto.split_whitespace().next()?;
    valor.parse::<u64>().ok().map(|v| (clave, v))
}

/// Analiza una cabecera de region de `maps`/`smaps`.
///
/// Formato: `inicio-fin perms desplazamiento dispositivo inodo [ruta]`.
fn analizar_cabecera(linea: &str, numero: usize) -> Result<RegionVad, MemHunterError> {
    let err = |detalle: String| MemHunterError::Formato {
        fichero: "smaps",
        linea: numero,
        detalle,
    };
    let mut campos = linea.split_whitespace();
    let rango = campos
        .next()
        .ok_or_else(|| err("linea vacia".to_string()))?;
    let (a, b) = rango
        .split_once('-')
        .ok_or_else(|| err(format!("rango sin guion: '{rango}'")))?;
    let inicio =
        u64::from_str_radix(a, 16).map_err(|e| err(format!("direccion inicial '{a}': {e}")))?;
    let fin = u64::from_str_radix(b, 16).map_err(|e| err(format!("direccion final '{b}': {e}")))?;
    if fin < inicio {
        return Err(err(format!("region invertida: {a}-{b}")));
    }

    let perms = campos
        .next()
        .ok_or_else(|| err("faltan los permisos".to_string()))?;
    let proteccion = Proteccion::desde_maps(perms);
    let compartida = perms.as_bytes().get(3) == Some(&b's');

    let desplazamiento = campos
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| err("desplazamiento ilegible".to_string()))?;
    // El dispositivo se descarta: el inodo ya ata la region al fichero, y
    // guardar el par mayor:menor no aporta nada a ninguna decision de aqui.
    let _dispositivo = campos
        .next()
        .ok_or_else(|| err("falta el dispositivo".to_string()))?;
    let inodo = campos
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| err("inodo ilegible".to_string()))?;
    // La ruta puede llevar espacios; se toma el resto de la linea.
    let ruta = campos.collect::<Vec<_>>().join(" ");

    let respaldo = if ruta.is_empty() {
        Respaldo::Anonima
    } else if ruta.starts_with('[') {
        // `[heap]` y `[stack]` son ANONIMAS pese a llevar etiqueta: no hay
        // fichero detras, solo un nombre que pone el kernel. Tratarlas como
        // especiales dejaria sin detectar una pila ejecutable, que es una de las
        // anomalias mas graves que hay.
        match ruta.as_str() {
            "[heap]" | "[stack]" => Respaldo::Anonima,
            _ => Respaldo::Especial(ruta),
        }
    } else if proteccion.ejecucion {
        Respaldo::Imagen {
            ruta,
            inodo,
            desplazamiento,
        }
    } else {
        Respaldo::Mapeado {
            ruta,
            inodo,
            desplazamiento,
        }
    };

    Ok(RegionVad {
        inicio,
        fin,
        proteccion,
        // Linux no conserva la proteccion inicial. Decirlo con `None` en vez de
        // copiar la actual es importante: con una copia, el detector de
        // "reservada RW, ahora RX" dispararia siempre a cero, y pareceria que se
        // esta comprobando algo que no se comprueba.
        proteccion_inicial: None,
        compartida,
        respaldo,
        residente_kb: 0,
        anonima_kb: 0,
        privada_sucia_kb: 0,
    })
}

/// Lee y analiza el espacio de direcciones de un proceso vivo.
///
/// Prefiere `smaps` —que trae las metricas de respaldo, sin las cuales no hay
/// deteccion de *stomping*— y cae a `maps` si no existe (algunos kernels
/// endurecidos y algunos contenedores no exponen `smaps`). La diferencia NO se
/// oculta: sin `smaps`, las regiones llegan con los contadores a cero y el
/// cazador no afirma lo que no puede saber.
///
/// # Errores
/// [`MemHunterError::ProcesoMuerto`] si el proceso desaparecio (que es normal:
/// se analiza un sistema vivo), o [`MemHunterError::Lectura`]/[`MemHunterError::Formato`].
#[cfg(target_os = "linux")]
pub fn regiones_de(pid: i32) -> Result<Vec<RegionVad>, MemHunterError> {
    let smaps = format!("/proc/{pid}/smaps");
    let maps = format!("/proc/{pid}/maps");
    let texto = match std::fs::read_to_string(&smaps) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::read_to_string(&maps) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(MemHunterError::ProcesoMuerto { pid })
                }
                Err(causa) => return Err(MemHunterError::Lectura { ruta: maps, causa }),
            }
        }
        Err(causa) => return Err(MemHunterError::Lectura { ruta: smaps, causa }),
    };
    analizar_smaps(&texto)
}

/// El VAD de Windows: contrato de ABI con `VirtualQueryEx`.
///
/// # Por que esto vive aqui y se verifica en compilacion
///
/// El clasificador de Windows lee `AllocationProtect` (la proteccion **inicial**,
/// que es el dato que delata al cargador reflexivo) y `Type` (si la region esta
/// respaldada por una imagen o es memoria privada). Los dos son campos de una
/// estructura del SDK cuyo layout fija el compilador de Microsoft.
///
/// Un campo desplazado no rompe la compilacion: hace que el clasificador lea una
/// proteccion donde hay un tamano. El sintoma en produccion no seria un fallo,
/// seria un EDR que **no ve nada**, que es infinitamente peor. Por eso el tamano
/// y el desplazamiento de cada campo se afirman con `const`, igual que el resto
/// de contratos de ABI del producto (ver `crates/aegis-ipc/src/abi.rs`).
pub mod windows {
    use super::{Proteccion, RegionVad, Respaldo};

    /// `MEMORY_BASIC_INFORMATION` de la API de Windows, x86-64.
    ///
    /// El layout se corresponde con el del SDK: los `PVOID`/`SIZE_T` son de 8
    /// bytes y los `DWORD` de 4. `PartitionId` (Windows 10 2004 en adelante)
    /// ocupa el hueco de relleno que antes quedaba tras `AllocationProtect`, asi
    /// que el tamano total —48 bytes— no cambio entre versiones.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct MemoryBasicInformation {
        /// Base de la pagina desde la que se consulto.
        pub base_address: u64,
        /// Base de la reserva original (`VirtualAlloc`) que contiene esta region.
        pub allocation_base: u64,
        /// Proteccion con la que se RESERVO. El dato que Linux no conserva.
        pub allocation_protect: u32,
        /// Identificador de particion de memoria (Win10 2004+); sin uso aqui.
        pub partition_id: u16,
        /// Relleno explicito: en el SDK es el hueco de alineacion de `RegionSize`.
        pub _reservado: u16,
        /// Tamano de la region con el mismo estado y proteccion.
        pub region_size: u64,
        /// `MEM_COMMIT` / `MEM_RESERVE` / `MEM_FREE`.
        pub state: u32,
        /// Proteccion ACTUAL.
        pub protect: u32,
        /// `MEM_IMAGE` / `MEM_MAPPED` / `MEM_PRIVATE`.
        pub type_: u32,
    }

    // --- Contrato de ABI verificado en COMPILACION ---------------------------
    const _: () = {
        assert!(std::mem::size_of::<MemoryBasicInformation>() == 48);
        assert!(std::mem::align_of::<MemoryBasicInformation>() == 8);
        assert!(std::mem::offset_of!(MemoryBasicInformation, base_address) == 0);
        assert!(std::mem::offset_of!(MemoryBasicInformation, allocation_base) == 8);
        assert!(std::mem::offset_of!(MemoryBasicInformation, allocation_protect) == 16);
        assert!(std::mem::offset_of!(MemoryBasicInformation, partition_id) == 20);
        assert!(std::mem::offset_of!(MemoryBasicInformation, region_size) == 24);
        assert!(std::mem::offset_of!(MemoryBasicInformation, state) == 32);
        assert!(std::mem::offset_of!(MemoryBasicInformation, protect) == 36);
        assert!(std::mem::offset_of!(MemoryBasicInformation, type_) == 40);
    };

    /// La region esta reservada y respaldada por memoria fisica.
    pub const MEM_COMMIT: u32 = 0x0000_1000;
    /// Reservada pero sin respaldo.
    pub const MEM_RESERVE: u32 = 0x0000_2000;
    /// Libre.
    pub const MEM_FREE: u32 = 0x0001_0000;
    /// Memoria privada del proceso: sin fichero ni imagen detras.
    pub const MEM_PRIVATE: u32 = 0x0002_0000;
    /// Vista de un fichero mapeado.
    pub const MEM_MAPPED: u32 = 0x0004_0000;
    /// Vista de una imagen ejecutable mapeada por el cargador.
    pub const MEM_IMAGE: u32 = 0x0100_0000;

    /// Sin acceso.
    pub const PAGE_NOACCESS: u32 = 0x01;
    /// Solo lectura.
    pub const PAGE_READONLY: u32 = 0x02;
    /// Lectura y escritura.
    pub const PAGE_READWRITE: u32 = 0x04;
    /// Lectura y escritura con copia al escribir.
    pub const PAGE_WRITECOPY: u32 = 0x08;
    /// Solo ejecucion.
    pub const PAGE_EXECUTE: u32 = 0x10;
    /// Ejecucion y lectura.
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    /// Ejecucion, lectura y escritura.
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    /// Ejecucion, lectura y escritura con copia al escribir.
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    /// Pagina guardiana: el primer acceso lanza una excepcion.
    pub const PAGE_GUARD: u32 = 0x100;

    /// Traduce una constante `PAGE_*` a la proteccion del modelo.
    ///
    /// Los modificadores (`PAGE_GUARD`, `PAGE_NOCACHE`, `PAGE_WRITECOMBINE`) se
    /// enmascaran: se combinan con OR sobre la proteccion base y compararlos sin
    /// quitarlos haria que una pagina guardiana no se reconociera.
    #[must_use]
    pub const fn proteccion_de(protect: u32) -> Proteccion {
        let base = protect & 0xFF;
        let ejecucion = matches!(
            base,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );
        let escritura = matches!(
            base,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );
        let lectura = matches!(
            base,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        );
        Proteccion {
            lectura,
            escritura,
            ejecucion,
        }
    }

    /// Convierte un `MEMORY_BASIC_INFORMATION` en una region del modelo.
    ///
    /// `ruta_imagen` es lo que devuelve `GetMappedFileNameW` para la region; se
    /// pasa aparte porque el `MBI` no la trae, y su ausencia sobre una region
    /// `MEM_IMAGE` es en si misma sospechosa (una imagen mapeada por el cargador
    /// SIEMPRE tiene fichero; una "imagen" sin el es un mapeo fabricado a mano).
    #[must_use]
    pub fn a_region(mbi: &MemoryBasicInformation, ruta_imagen: Option<&str>) -> RegionVad {
        let proteccion = proteccion_de(mbi.protect);
        let respaldo = match (mbi.type_, ruta_imagen) {
            (MEM_IMAGE, Some(r)) => Respaldo::Imagen {
                ruta: r.to_string(),
                // Windows no expone inodo; el par (ruta, desplazamiento) es lo
                // que identifica la vista, y se deja el inodo a cero en vez de
                // inventar un identificador que no significa nada.
                inodo: 0,
                desplazamiento: mbi.base_address.saturating_sub(mbi.allocation_base),
            },
            (MEM_MAPPED, Some(r)) => Respaldo::Mapeado {
                ruta: r.to_string(),
                inodo: 0,
                desplazamiento: mbi.base_address.saturating_sub(mbi.allocation_base),
            },
            // MEM_PRIVATE, o una "imagen" sin fichero detras: anonima.
            _ => Respaldo::Anonima,
        };
        RegionVad {
            inicio: mbi.base_address,
            fin: mbi.base_address.saturating_add(mbi.region_size),
            proteccion,
            // EL dato de Windows: la proteccion con la que nacio la reserva.
            proteccion_inicial: Some(proteccion_de(mbi.allocation_protect)),
            compartida: mbi.type_ == MEM_MAPPED,
            respaldo,
            // Windows no da estas metricas por `VirtualQuery`; salen de
            // `QueryWorkingSetEx`, que es otra llamada y otro coste. Se dejan a
            // cero, y el cazador no afirma nada que dependa de ellas: en Windows
            // el *stomping* se delata por la proteccion inicial y por el tipo,
            // no por el contador de paginas copiadas.
            residente_kb: 0,
            anonima_kb: 0,
            privada_sucia_kb: 0,
        }
    }

    #[cfg(test)]
    mod pruebas {
        use super::*;

        #[test]
        fn las_constantes_de_proteccion_se_traducen_como_el_sdk() {
            assert_eq!(
                proteccion_de(PAGE_EXECUTE_READ),
                Proteccion {
                    lectura: true,
                    escritura: false,
                    ejecucion: true
                }
            );
            assert!(proteccion_de(PAGE_EXECUTE_READWRITE).es_rwx());
            assert_eq!(proteccion_de(PAGE_NOACCESS), Proteccion::default());
            // PAGE_WRITECOPY es escribible: escribir en ella provoca la copia
            // privada. Tratarla como solo-lectura dejaria pasar la escritura
            // sobre una vista de imagen, que es justo el stomping en Windows.
            assert!(proteccion_de(PAGE_WRITECOPY).escritura);
            // Un modificador no puede romper el reconocimiento de la base.
            assert!(proteccion_de(PAGE_EXECUTE_READ | PAGE_GUARD).ejecucion);
        }

        #[test]
        fn una_imagen_sin_fichero_detras_se_trata_como_anonima() {
            // Un mapeo que DICE ser imagen pero no tiene fichero es un mapeo
            // fabricado a mano: no puede clasificarse como modulo legitimo.
            let mbi = MemoryBasicInformation {
                base_address: 0x7ff0_0000_0000,
                allocation_base: 0x7ff0_0000_0000,
                allocation_protect: PAGE_READWRITE,
                region_size: 0x10000,
                state: MEM_COMMIT,
                protect: PAGE_EXECUTE_READ,
                type_: MEM_IMAGE,
                ..Default::default()
            };
            let r = a_region(&mbi, None);
            assert_eq!(r.respaldo, Respaldo::Anonima);
            assert!(r.es_ejecutable_sin_fichero());
            // Y la proteccion inicial se conserva: nacio RW, ahora es RX.
            let inicial = r.proteccion_inicial.expect("Windows si la conserva");
            assert!(inicial.escritura && !inicial.ejecucion);
            assert!(r.proteccion.ejecucion && !r.proteccion.escritura);
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un `smaps` REAL recortado: las tres primeras regiones de un proceso de
    /// verdad, con sus metricas tal cual las escribe el kernel.
    const SMAPS: &str = "\
55b8c0a00000-55b8c0a23000 r-xp 00004000 fe:00 151521                      /usr/bin/grep
Size:                140 kB
KernelPageSize:        4 kB
Rss:                 140 kB
Pss:                 140 kB
Shared_Clean:          0 kB
Private_Clean:       140 kB
Private_Dirty:         0 kB
Anonymous:             0 kB
VmFlags: rd ex mr mw me dw sd
7f0000000000-7f0000004000 rwxp 00000000 00:00 0
Size:                 16 kB
Rss:                  16 kB
Private_Dirty:        16 kB
Anonymous:            16 kB
VmFlags: rd wr ex mr mw me ac sd
7f1111100000-7f1111180000 r-xp 00000000 fe:00 152035                      /usr/lib/libvictima.so
Size:                512 kB
Rss:                 512 kB
Private_Dirty:       128 kB
Anonymous:           128 kB
VmFlags: rd ex mr mw me dw sd
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                           [stack]
Size:                132 kB
Rss:                  12 kB
Anonymous:            12 kB
";

    #[test]
    fn el_parseo_de_smaps_recupera_regiones_y_metricas() {
        let r = analizar_smaps(SMAPS).expect("smaps valido");
        assert_eq!(r.len(), 4);

        // 1. Codigo de un binario, intacto.
        assert_eq!(r[0].inicio, 0x55b8_c0a0_0000);
        assert_eq!(r[0].proteccion.to_string(), "r-x");
        assert!(r[0].es_codigo_de_modulo());
        assert_eq!(r[0].anonima_kb, 0);
        assert_eq!(r[0].respaldo.ruta(), Some("/usr/bin/grep"));

        // 2. Anonima RWX.
        assert!(r[1].proteccion.es_rwx());
        assert!(r[1].es_ejecutable_sin_fichero());
        assert_eq!(r[1].respaldo, Respaldo::Anonima);

        // 3. Codigo de un modulo con 128 KiB que YA NO son del fichero.
        assert!(r[2].es_codigo_de_modulo());
        assert_eq!(r[2].anonima_kb, 128);
        assert!((r[2].fraccion_desligada() - 0.25).abs() < 1e-9);

        // 4. `[stack]` es ANONIMA, no una region especial: si se clasificara
        //    como especial, una pila ejecutable no se detectaria jamas.
        assert_eq!(r[3].respaldo, Respaldo::Anonima);
    }

    #[test]
    fn la_fraccion_desligada_se_mide_sobre_el_tamano_no_sobre_lo_residente() {
        // Una region de 512 KiB con UNA sola pagina dentro, y copiada. Con lo
        // residente como denominador esto daria 1,0 —"el modulo entero fue
        // sobrescrito"— cuando en realidad se toco el 0,8 %.
        let r = analizar_smaps(
            "7f00000000-7f00080000 r-xp 00000000 fe:00 1                      /usr/lib/x.so\n\
             Rss:                   4 kB\n\
             Anonymous:             4 kB\n",
        )
        .expect("smaps valido");
        assert_eq!(r[0].tamano(), 512 * 1024);
        assert!(
            r[0].fraccion_desligada() < 0.01,
            "{}",
            r[0].fraccion_desligada()
        );
    }

    #[test]
    fn un_maps_sin_metricas_se_acepta_con_los_contadores_a_cero() {
        // No todos los kernels exponen `smaps`. El parseo tiene que funcionar
        // igual, y los contadores quedan a cero: el cazador no puede afirmar
        // que hubo copia privada si nadie se lo dijo, y no lo afirma.
        let r = analizar_smaps(
            "7f1111100000-7f1111180000 r-xp 00000000 fe:00 152035    /usr/lib/libv.so\n",
        )
        .expect("maps valido");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].anonima_kb, 0);
        assert_eq!(r[0].fraccion_desligada(), 0.0);
    }

    #[test]
    fn una_cabecera_corrupta_rompe_en_vez_de_devolver_cero_anomalias() {
        // Si `/proc` cambiara de formato en un kernel futuro, un parseo
        // permisivo devolveria una lista vacia, y una lista vacia se lee como
        // "esta maquina esta limpia". Tiene que romper.
        let e = analizar_smaps("zzzz-yyyy r-xp 0 00:00 0\nRss: 1 kB\n").unwrap_err();
        // La linea `zzzz-yyyy` no es hexadecimal, asi que no se toma por
        // cabecera; la metrica que la sigue se queda huerfana y ESO es lo que
        // rompe. En ambos caminos el resultado es el correcto: error, no vacio.
        assert!(matches!(e, MemHunterError::Formato { .. }), "{e:?}");
    }

    #[test]
    fn una_ruta_con_espacios_no_parte_la_region() {
        let r = analizar_smaps(
            "7f00-7f01 r-xp 00000000 fe:00 1   /opt/mi programa/lib con espacios.so\n",
        )
        .expect("smaps valido");
        assert_eq!(
            r[0].respaldo.ruta(),
            Some("/opt/mi programa/lib con espacios.so")
        );
    }

    /// EL FALSO POSITIVO QUE CASI SE ESCAPA. El vDSO es una imagen ELF autentica
    /// que el kernel mapea en TODO proceso de Linux, sin fichero detras. Sin la
    /// exclusion de los mapeos del kernel, el cazador lo reporta como carga
    /// reflexiva critica una vez por proceso, en toda la flota.
    #[test]
    fn el_vdso_no_cuenta_como_ejecutable_sin_fichero() {
        let r = analizar_smaps(
            "7ffd1b5f6000-7ffd1b5f8000 r-xp 00000000 00:00 0                          [vdso]\n\
             7ffd1b5f2000-7ffd1b5f6000 r--p 00000000 00:00 0                          [vvar]\n\
             7ffd1b400000-7ffd1b421000 rwxp 00000000 00:00 0                          [stack]\n",
        )
        .expect("smaps valido");

        assert!(r[0].es_mapeo_del_kernel(), "[vdso] lo mapea el kernel");
        assert!(
            !r[0].es_ejecutable_sin_fichero(),
            "el vDSO es ejecutable y sin fichero, pero lo pone el kernel: reportarlo \
             seria una alerta critica por proceso en toda la flota"
        );
        assert!(r[1].es_mapeo_del_kernel());

        // Y la otra cara: una pila EJECUTABLE si tiene que salir. Si la exclusion
        // se hubiera hecho por "lleva corchetes" en vez de por "la mapea el
        // kernel", esto se habria perdido, que es un agujero de verdad.
        assert!(
            !r[2].es_mapeo_del_kernel(),
            "[stack] es memoria del proceso"
        );
        assert!(
            r[2].es_ejecutable_sin_fichero(),
            "una pila ejecutable es grave"
        );
    }

    /// Sobre el `/proc/self/maps` REAL: esta maquina tiene vDSO, y el cazador no
    /// puede confundirlo con una carga reflexiva.
    #[cfg(target_os = "linux")]
    #[test]
    fn el_vdso_real_de_esta_maquina_no_se_confunde_con_codigo_inyectado() {
        let regiones = regiones_de(std::process::id() as i32).expect("smaps propio");
        let vdso = regiones
            .iter()
            .find(|r| matches!(&r.respaldo, Respaldo::Especial(n) if n == "[vdso]"))
            .expect("todo proceso de Linux tiene vDSO");
        assert!(vdso.es_ejecutable(), "el vDSO es codigo");
        assert!(!vdso.respaldo.es_de_fichero(), "y no tiene fichero detras");
        assert!(
            !vdso.es_ejecutable_sin_fichero(),
            "aun asi no puede contar como codigo sin fichero: lo mapea el kernel"
        );
    }

    /// El parseo se hace sobre el `/proc/self/smaps` de VERDAD de este proceso.
    /// No hay forma de fingir esto: si el formato real no encajara con el
    /// analizador, la prueba fallaria aqui y no en produccion.
    #[cfg(target_os = "linux")]
    #[test]
    fn el_smaps_real_de_este_proceso_se_analiza_entero() {
        let regiones = regiones_de(std::process::id() as i32).expect("smaps propio");
        assert!(
            regiones.len() > 5,
            "un proceso real tiene mas de cinco regiones, no {}",
            regiones.len()
        );
        // El binario de la propia prueba esta mapeado como imagen ejecutable.
        assert!(
            regiones.iter().any(|r| r.es_codigo_de_modulo()),
            "tiene que haber al menos una region de codigo de modulo"
        );
        // Y toda region con fichero tiene ruta; toda anonima, ninguna.
        for r in &regiones {
            assert_eq!(r.respaldo.es_de_fichero(), r.respaldo.ruta().is_some());
            assert!(r.fin >= r.inicio);
        }
    }
}
