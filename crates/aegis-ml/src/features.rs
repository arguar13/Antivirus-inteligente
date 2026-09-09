//! Extraccion de atributos estaticos de binarios PE y ELF.
//!
//! Analiza el binario **sin ejecutarlo**: se leen cabeceras, tablas de simbolos
//! y secciones con `goblin`, y se calcula entropia real sobre el contenido. El
//! resultado es un vector de 256 dimensiones que alimenta el modelo local.
//!
//! # Por que caracteristicas estructurales y no bytes crudos
//!
//! Un modelo que consume los bytes del fichero se evade **anadiendo bytes al
//! final**: sin tocar una sola instruccion, la clasificacion cambia. Un modelo
//! cuyas entradas son la estructura del binario (cuantas secciones, con que
//! entropia, que importa, si hay un segmento escribible y ejecutable) obliga al
//! atacante a modificar el binario de verdad, y eso si tiene coste.
//!
//! Ademas es explicable: cuando el motor bloquea el instalador interno de una
//! empresa, hace falta poder decir por que en segundos, y "la seccion .text
//! tiene entropia 7,98 y hay un segmento RWX" es una respuesta; "el vector cayo
//! del lado malo del hiperplano" no lo es.
//!
//! # Disposicion del vector
//!
//! ```text
//! [  0..16 )  Generales: tamano, entropia, ratios, formato
//! [ 16..32 )  Histograma de bytes en 16 cubos
//! [ 32..64 )  Histograma de entropia por bloques en 32 cubos
//! [ 64..96 )  Cabecera del formato: tipo, arquitectura, mitigaciones
//! [ 96..144)  Secciones: entropias, tamanos virtual frente a real
//! [144..208)  Importaciones por hashing en 64 cubos
//! [208..240)  Cadenas: recuentos por categoria
//! [240..256)  Firma y reservado
//! ```
//!
//! El **hashing de importaciones** evita un vocabulario fijo: una API nueva cae
//! en su cubo sin reentrenar el esquema. Un vocabulario explicito quedaria
//! obsoleto con cada version del sistema operativo.

use crate::entropy;

/// Dimension del vector de caracteristicas.
pub const FEATURE_DIM: usize = 256;

/// Inicio del bloque de histograma de bytes.
pub const OFF_BYTE_HIST: usize = 16;
/// Inicio del bloque de histograma de entropia.
pub const OFF_ENTROPY_HIST: usize = 32;
/// Inicio del bloque de cabecera.
pub const OFF_HEADER: usize = 64;
/// Inicio del bloque de secciones.
pub const OFF_SECTIONS: usize = 96;
/// Inicio del bloque de importaciones.
pub const OFF_IMPORTS: usize = 144;
/// Numero de cubos de hashing de importaciones.
pub const IMPORT_BUCKETS: usize = 64;
/// Inicio del bloque de cadenas.
pub const OFF_STRINGS: usize = 208;
/// Inicio del bloque de firma.
pub const OFF_SIGNATURE: usize = 240;

/// Formato reconocido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// Ejecutable ELF.
    Elf,
    /// Ejecutable PE.
    Pe,
    /// Ni PE ni ELF, o cabecera ilegible.
    Unknown,
}

/// Datos de una seccion, normalizados entre formatos.
#[derive(Debug, Clone, PartialEq)]
pub struct SectionInfo {
    /// Nombre.
    pub name: String,
    /// Tamano en el fichero.
    pub raw_size: u64,
    /// Tamano en memoria.
    pub virtual_size: u64,
    /// Desplazamiento en el fichero.
    pub offset: u64,
    /// Direccion virtual.
    pub address: u64,
    /// Escribible.
    pub writable: bool,
    /// Ejecutable.
    pub executable: bool,
    /// Entropia de su contenido.
    pub entropy: f64,
    /// La seccion declara mas bytes de los que hay en el fichero.
    ///
    /// Es una anomalia real: un binario truncado o con la tabla de secciones
    /// manipulada para que un analizador lea fuera de rango o se rinda.
    pub truncated: bool,
}

impl SectionInfo {
    /// Razon entre tamano en memoria y tamano en fichero.
    ///
    /// Es el indicador clasico de empaquetado: un packer declara una seccion
    /// pequena en disco que se expande en memoria al descomprimirse.
    ///
    /// La distincion entre ambos tamanos es explicita en PE (`VirtualSize`
    /// frente a `SizeOfRawData`). En ELF **no existe como tal**: `sh_size` es
    /// el tamano en el fichero, y solo hay diferencia en dos casos, ambos
    /// significativos: `SHT_NOBITS` (`.bss`, que no ocupa nada en disco por
    /// definicion) y una seccion cuyo `sh_size` excede el fichero, que es una
    /// anomalia. Tratar ELF como si tuviera la dualidad de PE produciria una
    /// caracteristica que no significa nada.
    pub fn virtual_to_raw(&self) -> f64 {
        if self.raw_size == 0 {
            // Sin contenido en fichero pero con tamano en memoria: es `.bss` o
            // una seccion que el cargador rellenara. Se acota para que no
            // domine la caracteristica.
            return if self.virtual_size > 0 { 10.0 } else { 1.0 };
        }
        (self.virtual_size as f64 / self.raw_size as f64).min(50.0)
    }

    /// Escribible y ejecutable a la vez.
    pub fn is_wx(&self) -> bool {
        self.writable && self.executable
    }
}

/// Nombres de seccion habituales en binarios producidos por un compilador.
const SECCIONES_ESTANDAR: &[&str] = &[
    ".text",
    ".data",
    ".rodata",
    ".bss",
    ".init",
    ".fini",
    ".plt",
    ".got",
    ".got.plt",
    ".dynamic",
    ".dynsym",
    ".dynstr",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".rela.dyn",
    ".rela.plt",
    ".rel.dyn",
    ".rel.plt",
    ".comment",
    ".note",
    ".eh_frame",
    ".eh_frame_hdr",
    ".gcc_except_table",
    ".tbss",
    ".tdata",
    ".init_array",
    ".fini_array",
    ".preinit_array",
    ".interp",
    ".gnu.hash",
    ".gnu.version",
    ".gnu.version_r",
    ".note.ABI-tag",
    ".note.gnu.build-id",
    ".note.gnu.property",
    ".data.rel.ro",
    ".plt.got",
    ".plt.sec",
    ".rdata",
    ".idata",
    ".edata",
    ".pdata",
    ".reloc",
    ".rsrc",
    ".tls",
    ".debug",
    ".CRT",
    ".didat",
    ".sdata",
    ".xdata",
];

fn es_seccion_estandar(nombre: &str) -> bool {
    let base = nombre.trim_end_matches(char::is_numeric);
    SECCIONES_ESTANDAR
        .iter()
        .any(|s| nombre == *s || base == *s || nombre.starts_with(&format!("{s}.")))
}

/// Atributos extraidos de un binario, antes de vectorizar.
///
/// Se conservan en forma legible ademas del vector, porque son lo que se
/// muestra al operador cuando el modelo bloquea algo: una puntuacion sin
/// atributos no se puede discutir.
#[derive(Debug, Clone, Default)]
pub struct BinaryFeatures {
    /// Formato detectado.
    pub format: Option<BinaryFormatInfo>,
    /// Tamano del fichero.
    pub size: u64,
    /// Entropia global.
    pub entropy: f64,
    /// Estadisticas de entropia por bloques.
    pub block_entropy: entropy::BlockEntropy,
    /// Fraccion de bytes imprimibles.
    pub printable_ratio: f64,
    /// Fraccion de bytes nulos.
    pub null_ratio: f64,
    /// Secciones.
    pub sections: Vec<SectionInfo>,
    /// Simbolos importados, en la forma `biblioteca!simbolo` cuando se conoce
    /// la biblioteca.
    pub imports: Vec<String>,
    /// Simbolos exportados.
    pub exports: Vec<String>,
    /// Bibliotecas de las que depende.
    pub libraries: Vec<String>,
    /// Cadenas imprimibles extraidas.
    pub strings: Vec<String>,
    /// El analisis estructural fallo.
    ///
    /// **Es una caracteristica, no un error.** Un PE o ELF malformado que aun
    /// asi carga es una tecnica de evasion deliberada contra analizadores que
    /// se rinden ante lo que no entienden.
    pub parse_failed: bool,
}

/// Datos de cabecera normalizados entre formatos.
#[derive(Debug, Clone, Default)]
pub struct BinaryFormatInfo {
    /// Formato.
    pub kind: Option<BinaryFormat>,
    /// 64 bits.
    pub is_64: bool,
    /// Little-endian.
    pub little_endian: bool,
    /// Ejecutable principal.
    pub is_exec: bool,
    /// Biblioteca compartida o DLL.
    pub is_dylib: bool,
    /// Fichero objeto reubicable.
    pub is_relocatable: bool,
    /// Arquitectura.
    pub machine: u16,
    /// Enlazado dinamicamente.
    pub dynamic: bool,
    /// Pila no ejecutable.
    pub nx: bool,
    /// Codigo independiente de posicion.
    pub pie: bool,
    /// Reubicaciones de solo lectura.
    pub relro: bool,
    /// Enlace inmediato.
    pub bind_now: bool,
    /// Sin tabla de simbolos.
    pub stripped: bool,
    /// Hay un segmento escribible y ejecutable a la vez.
    ///
    /// Casi ningun compilador lo produce. Lo producen los packers y el codigo
    /// que se modifica a si mismo.
    pub rwx_segment: bool,
    /// Punto de entrada.
    pub entry: u64,
    /// El punto de entrada cae en la ultima seccion.
    pub entry_in_last_section: bool,
    /// El punto de entrada no cae en ninguna seccion.
    pub entry_outside_sections: bool,
    /// Numero de cabeceras de programa o directorios de datos.
    pub program_headers: usize,
    /// Marca temporal declarada.
    pub timestamp: u64,
    /// Bytes despues de la ultima seccion.
    ///
    /// Un apendice grande es donde un dropper esconde su carga util.
    pub overlay_bytes: u64,
    /// Tiene almacenamiento local de hilo con retrollamadas.
    pub has_tls: bool,
    /// Declara constructores que corren antes de `main`.
    pub has_init_array: bool,
    /// Lleva firma digital incrustada.
    pub has_signature: bool,
}

/// Extractor de atributos.
#[derive(Debug, Clone, Copy)]
pub struct FeatureExtractor {
    /// Tamano de bloque para la entropia por bloques.
    pub block_size: usize,
    /// Longitud minima de una cadena para extraerla.
    pub min_string_len: usize,
    /// Numero maximo de cadenas que se extraen.
    ///
    /// Acotado: un binario de 500 MB con datos incrustados puede contener
    /// millones de cadenas, y extraerlas todas convierte el analisis estatico
    /// en un problema de memoria.
    pub max_strings: usize,
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self {
            block_size: 4096,
            min_string_len: 5,
            max_strings: 20_000,
        }
    }
}

impl FeatureExtractor {
    /// Extrae los atributos de un buffer.
    pub fn extract(&self, datos: &[u8]) -> BinaryFeatures {
        let mut f = BinaryFeatures {
            size: datos.len() as u64,
            entropy: entropy::shannon(datos),
            block_entropy: entropy::block_entropy(datos, self.block_size),
            printable_ratio: entropy::printable_ratio(datos),
            null_ratio: entropy::null_ratio(datos),
            strings: extract_strings(datos, self.min_string_len, self.max_strings),
            ..Default::default()
        };

        match goblin::Object::parse(datos) {
            Ok(goblin::Object::Elf(elf)) => extract_elf(&elf, datos, &mut f),
            Ok(goblin::Object::PE(pe)) => extract_pe(&pe, datos, &mut f),
            Ok(_) => {
                f.format = Some(BinaryFormatInfo {
                    kind: Some(BinaryFormat::Unknown),
                    ..Default::default()
                });
            }
            Err(_) => {
                // Un binario que no analiza puede seguir siendo ejecutable: es
                // una tecnica contra analizadores que se rinden. Se marca y se
                // sigue con las caracteristicas que no dependen del formato.
                f.parse_failed = true;
                f.format = Some(BinaryFormatInfo {
                    kind: Some(BinaryFormat::Unknown),
                    ..Default::default()
                });
            }
        }

        f
    }

    /// Extrae los atributos de un fichero del disco.
    pub fn extract_file(&self, ruta: &std::path::Path) -> std::io::Result<BinaryFeatures> {
        let datos = std::fs::read(ruta)?;
        Ok(self.extract(&datos))
    }
}

fn seccion_datos(datos: &[u8], offset: u64, size: u64) -> &[u8] {
    let ini = offset as usize;
    let fin = ini.saturating_add(size as usize);
    if ini >= datos.len() {
        return &[];
    }
    &datos[ini..fin.min(datos.len())]
}

fn extract_elf(elf: &goblin::elf::Elf<'_>, datos: &[u8], f: &mut BinaryFeatures) {
    use goblin::elf::program_header::{
        PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_TLS,
    };

    let mut info = BinaryFormatInfo {
        kind: Some(BinaryFormat::Elf),
        is_64: elf.is_64,
        little_endian: elf.little_endian,
        machine: elf.header.e_machine,
        entry: elf.header.e_entry,
        program_headers: elf.program_headers.len(),
        // Por defecto la pila es ejecutable; solo un PT_GNU_STACK sin PF_X la
        // marca como no ejecutable.
        nx: false,
        ..Default::default()
    };

    match elf.header.e_type {
        goblin::elf::header::ET_EXEC => info.is_exec = true,
        goblin::elf::header::ET_DYN => {
            // ET_DYN es a la vez "biblioteca compartida" y "ejecutable PIE". Se
            // distinguen por la presencia de interprete.
            info.is_dylib = true;
            info.pie = true;
        }
        goblin::elf::header::ET_REL => info.is_relocatable = true,
        _ => {}
    }

    for ph in elf.program_headers.iter() {
        match ph.p_type {
            PT_INTERP => {
                info.dynamic = true;
                info.is_exec = true;
                info.is_dylib = false;
            }
            PT_GNU_STACK => info.nx = ph.p_flags & PF_X == 0,
            PT_GNU_RELRO => info.relro = true,
            PT_TLS => info.has_tls = true,
            PT_LOAD => {
                if ph.p_flags & PF_W != 0 && ph.p_flags & PF_X != 0 {
                    info.rwx_segment = true;
                }
            }
            _ => {}
        }
    }

    info.bind_now = elf.dynamic.as_ref().is_some_and(|d| {
        d.dyns.iter().any(|e| {
            e.d_tag == goblin::elf::dynamic::DT_BIND_NOW
                || (e.d_tag == goblin::elf::dynamic::DT_FLAGS
                    && e.d_val & goblin::elf::dynamic::DF_BIND_NOW != 0)
        })
    });

    // --- Secciones ---
    let mut fin_ultima = 0u64;
    for sh in elf.section_headers.iter() {
        let nombre = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        // SHT_NOBITS (.bss) no ocupa espacio en el fichero.
        let declarado = if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            0
        } else {
            sh.sh_size
        };
        // El tamano se acota a lo que realmente hay en el fichero. Una seccion
        // que declara mas bytes de los que existen no es un caso raro: es como
        // se consigue que un analizador lea fuera de rango o se rinda.
        let disponible = (datos.len() as u64).saturating_sub(sh.sh_offset.min(datos.len() as u64));
        let raw = declarado.min(disponible);
        let truncada = declarado > disponible;
        let contenido = seccion_datos(datos, sh.sh_offset, raw);
        if raw > 0 {
            fin_ultima = fin_ultima.max(sh.sh_offset + raw);
        }
        f.sections.push(SectionInfo {
            name: nombre,
            raw_size: raw,
            virtual_size: sh.sh_size,
            offset: sh.sh_offset,
            address: sh.sh_addr,
            writable: sh.sh_flags & u64::from(goblin::elf::section_header::SHF_WRITE) != 0,
            executable: sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0,
            entropy: entropy::shannon(contenido),
            truncated: truncada,
        });
    }

    // El apendice es lo que hay DESPUES de toda la estructura del fichero, no
    // solo despues de los datos de seccion: en ELF la tabla de cabeceras de
    // seccion suele ir al final, y medir desde los datos contaria esa tabla
    // como carga util oculta.
    let fin_estructura = fin_ultima
        .max(elf.header.e_shoff + u64::from(elf.header.e_shnum) * u64::from(elf.header.e_shentsize))
        .max(
            elf.header.e_phoff + u64::from(elf.header.e_phnum) * u64::from(elf.header.e_phentsize),
        );
    info.overlay_bytes = (datos.len() as u64).saturating_sub(fin_estructura);

    info.has_init_array = f.sections.iter().any(|s| s.name == ".init_array");
    info.stripped = !f.sections.iter().any(|s| s.name == ".symtab");

    // --- Punto de entrada ---
    localizar_entrada(&mut info, &f.sections, elf.header.e_entry);

    // --- Simbolos ---
    for lib in elf.libraries.iter() {
        f.libraries.push((*lib).to_string());
    }
    for sym in elf.dynsyms.iter() {
        let Some(nombre) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if nombre.is_empty() {
            continue;
        }
        // Un simbolo indefinido es una importacion; uno definido y global, una
        // exportacion.
        if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
            f.imports.push(nombre.to_string());
        } else if sym.is_function() || sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
            f.exports.push(nombre.to_string());
        }
    }

    f.format = Some(info);
}

fn extract_pe(pe: &goblin::pe::PE<'_>, datos: &[u8], f: &mut BinaryFeatures) {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

    let opt = pe.header.optional_header;
    let dll_chars = opt
        .map(|o| o.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let mut info = BinaryFormatInfo {
        kind: Some(BinaryFormat::Pe),
        is_64: pe.is_64,
        little_endian: true,
        is_exec: !pe.is_lib,
        is_dylib: pe.is_lib,
        machine: pe.header.coff_header.machine,
        dynamic: true,
        // DYNAMIC_BASE = ASLR, NX_COMPAT = DEP.
        pie: dll_chars & 0x0040 != 0,
        nx: dll_chars & 0x0100 != 0,
        // GUARD_CF: proteccion de flujo de control.
        relro: dll_chars & 0x4000 != 0,
        entry: pe.entry as u64,
        program_headers: opt
            .map(|o| o.data_directories.data_directories.len())
            .unwrap_or(0),
        timestamp: u64::from(pe.header.coff_header.time_date_stamp),
        has_tls: opt.is_some_and(|o| {
            o.data_directories
                .get_tls_table()
                .is_some_and(|d| d.size > 0)
        }),
        has_signature: opt.is_some_and(|o| {
            o.data_directories
                .get_certificate_table()
                .is_some_and(|d| d.size > 0)
        }),
        ..Default::default()
    };

    let mut fin_ultima = 0u64;
    for s in pe.sections.iter() {
        let nombre = s.name().unwrap_or("<invalido>").to_string();
        let declarado = u64::from(s.size_of_raw_data);
        let inicio = u64::from(s.pointer_to_raw_data);
        let disponible = (datos.len() as u64).saturating_sub(inicio.min(datos.len() as u64));
        let raw = declarado.min(disponible);
        let truncada = declarado > disponible;
        let contenido = seccion_datos(datos, inicio, raw);
        if raw > 0 {
            fin_ultima = fin_ultima.max(inicio + raw);
        }
        f.sections.push(SectionInfo {
            name: nombre,
            raw_size: raw,
            virtual_size: u64::from(s.virtual_size),
            offset: u64::from(s.pointer_to_raw_data),
            address: u64::from(s.virtual_address),
            writable: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
            executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            entropy: entropy::shannon(contenido),
            truncated: truncada,
        });
    }
    info.overlay_bytes = (datos.len() as u64).saturating_sub(fin_ultima);
    info.rwx_segment = f.sections.iter().any(|s| s.is_wx());

    localizar_entrada(&mut info, &f.sections, pe.entry as u64);

    for imp in pe.imports.iter() {
        // `biblioteca!funcion` conserva de donde viene el simbolo: la misma
        // funcion importada de una DLL distinta es una senal distinta.
        f.imports.push(format!("{}!{}", imp.dll, imp.name));
        let dll = imp.dll.to_string();
        if !f.libraries.contains(&dll) {
            f.libraries.push(dll);
        }
    }
    for exp in pe.exports.iter() {
        if let Some(n) = exp.name {
            f.exports.push(n.to_string());
        }
    }

    // "Sin simbolos" se calcula AQUI, no antes: depende de las exportaciones,
    // que se acaban de poblar. Calcularlo arriba daria siempre cierto porque la
    // lista todavia estaria vacia, y la caracteristica seria una constante
    // disfrazada de senal.
    //
    // En PE la tabla de simbolos COFF es opcional y practicamente nadie la
    // emite, asi que mirarla no distingue nada. Lo que si distingue es la
    // ausencia SIMULTANEA de exportaciones y de directorio de depuracion.
    info.stripped = f.exports.is_empty()
        && opt.is_some_and(|o| {
            o.data_directories
                .get_debug_table()
                .is_none_or(|d| d.size == 0)
        });

    f.format = Some(info);
}

/// Determina donde cae el punto de entrada respecto a las secciones.
///
/// Ambos casos son senales reales: los packers suelen poner el punto de entrada
/// en la ultima seccion, la que anaden con el descompresor, y un punto de
/// entrada fuera de toda seccion indica una cabecera manipulada.
fn localizar_entrada(info: &mut BinaryFormatInfo, secciones: &[SectionInfo], entry: u64) {
    if secciones.is_empty() || entry == 0 {
        return;
    }
    let contiene = |s: &SectionInfo, dir: u64| {
        s.address != 0 && dir >= s.address && dir < s.address + s.virtual_size.max(s.raw_size)
    };
    // En PE el punto de entrada es relativo a la base; en ELF es absoluto. Se
    // prueban ambas interpretaciones para no depender del formato aqui.
    let base = secciones
        .iter()
        .map(|s| s.address)
        .filter(|a| *a != 0)
        .min()
        .unwrap_or(0);
    let candidatos = [entry, entry.wrapping_add(base)];

    let mut dentro = None;
    for (i, s) in secciones.iter().enumerate() {
        if candidatos.iter().any(|d| contiene(s, *d)) {
            dentro = Some(i);
            break;
        }
    }
    match dentro {
        Some(i) => {
            let ultima_con_codigo = secciones
                .iter()
                .rposition(|s| s.raw_size > 0)
                .unwrap_or(secciones.len() - 1);
            info.entry_in_last_section = i == ultima_con_codigo && secciones.len() > 1;
        }
        None => info.entry_outside_sections = true,
    }
}

/// Extrae cadenas ASCII imprimibles de longitud minima.
pub fn extract_strings(datos: &[u8], min_len: usize, max: usize) -> Vec<String> {
    let mut salida = Vec::new();
    let mut actual = Vec::new();
    for &b in datos {
        if (0x20..0x7f).contains(&b) {
            actual.push(b);
        } else {
            if actual.len() >= min_len {
                salida.push(String::from_utf8_lossy(&actual).into_owned());
                if salida.len() >= max {
                    return salida;
                }
            }
            actual.clear();
        }
    }
    if actual.len() >= min_len && salida.len() < max {
        salida.push(String::from_utf8_lossy(&actual).into_owned());
    }
    salida
}

/// Categorias de cadena con valor para la deteccion.
pub const CATEGORIAS: [(&str, &[&str]); 8] = [
    (
        "red",
        &[
            "http://",
            "https://",
            "socket",
            "connect",
            "bind",
            "listen",
            "curl",
            "wget",
            "ftp://",
            "User-Agent",
        ],
    ),
    (
        "cripto",
        &[
            "AES",
            "RSA",
            "encrypt",
            "decrypt",
            "CryptEncrypt",
            "EVP_",
            "chacha",
            "blowfish",
        ],
    ),
    (
        "persistencia",
        &[
            "crontab",
            "systemd",
            "rc.local",
            "CurrentVersion\\Run",
            "LaunchDaemons",
            "ld.so.preload",
            "authorized_keys",
        ],
    ),
    (
        "inyeccion",
        &[
            "ptrace",
            "process_vm_writev",
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "mprotect",
            "memfd_create",
            "LD_PRELOAD",
        ],
    ),
    (
        "antianalisis",
        &[
            "TracerPid",
            "IsDebuggerPresent",
            "VMware",
            "VirtualBox",
            "QEMU",
            "sandbox",
            "/proc/self/status",
        ],
    ),
    (
        "interprete",
        &[
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
            "python",
            "WScript.Shell",
            "base64",
        ],
    ),
    (
        "rescate",
        &[
            "ransom",
            "decrypt your files",
            "bitcoin",
            ".onion",
            "tor browser",
            "your files have been",
        ],
    ),
    (
        "reconocimiento",
        &[
            "/etc/passwd",
            "/etc/shadow",
            "whoami",
            "uname -a",
            "ifconfig",
            "netstat",
            "id_rsa",
        ],
    ),
];

/// Hash FNV-1a de 64 bits, para el hashing de importaciones.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

/// Convierte los atributos en el vector de entrada del modelo.
///
/// Todas las componentes quedan en `[0, 1]` aproximadamente. La normalizacion
/// no es cosmetica: un modelo lineal sobre caracteristicas de escalas dispares
/// queda dominado por la de mayor magnitud, y el tamano en bytes aplastaria a
/// todo lo demas.
pub fn to_vector(f: &BinaryFeatures) -> Vec<f32> {
    let mut v = vec![0f32; FEATURE_DIM];

    // --- [0..16) Generales ---
    // log10 del tamano dividido por 9: cubre de 1 byte a 1 GB en [0, 1].
    v[0] = ((f.size as f64 + 1.0).log10() / 9.0).min(1.0) as f32;
    v[1] = (f.entropy / 8.0) as f32;
    v[2] = (f.block_entropy.mean / 8.0) as f32;
    v[3] = (f.block_entropy.max / 8.0) as f32;
    v[4] = (f.block_entropy.min / 8.0) as f32;
    v[5] = (f.block_entropy.stddev / 4.0).min(1.0) as f32;
    v[6] = f.block_entropy.high_ratio as f32;
    v[7] = f.printable_ratio as f32;
    v[8] = f.null_ratio as f32;

    let info = f.format.clone().unwrap_or_default();
    v[9] = matches!(info.kind, Some(BinaryFormat::Elf)) as u8 as f32;
    v[10] = matches!(info.kind, Some(BinaryFormat::Pe)) as u8 as f32;
    v[11] = matches!(info.kind, Some(BinaryFormat::Unknown) | None) as u8 as f32;
    v[12] = info.is_64 as u8 as f32;
    v[13] = info.little_endian as u8 as f32;
    // Que el analisis falle es una CARACTERISTICA: un binario malformado que
    // aun asi ejecuta es evasion deliberada.
    v[14] = f.parse_failed as u8 as f32;
    v[15] = ((f.block_entropy.blocks as f64).log10() / 5.0).min(1.0) as f32;

    // --- [16..32) Histograma de bytes ---
    // El histograma se recalcula sobre las cadenas y no sobre el fichero para
    // no tener que retener el buffer; se rellena en `to_vector_with_data`.

    // --- [64..96) Cabecera ---
    let h = OFF_HEADER;
    v[h] = info.is_exec as u8 as f32;
    v[h + 1] = info.is_dylib as u8 as f32;
    v[h + 2] = info.is_relocatable as u8 as f32;
    v[h + 3] = (info.machine == 0x3e || info.machine == 0x8664) as u8 as f32; // x86-64
    v[h + 4] = (info.machine == 0x03 || info.machine == 0x14c) as u8 as f32; // i386
    v[h + 5] = (info.machine == 0xb7 || info.machine == 0xaa64) as u8 as f32; // aarch64
    v[h + 6] = info.dynamic as u8 as f32;
    v[h + 7] = (!info.dynamic) as u8 as f32;
    v[h + 8] = info.nx as u8 as f32;
    v[h + 9] = info.pie as u8 as f32;
    v[h + 10] = info.relro as u8 as f32;
    v[h + 11] = info.bind_now as u8 as f32;
    v[h + 12] = info.stripped as u8 as f32;
    // Segmento escribible y ejecutable: casi ningun compilador lo produce.
    v[h + 13] = info.rwx_segment as u8 as f32;
    v[h + 14] = info.entry_in_last_section as u8 as f32;
    v[h + 15] = info.entry_outside_sections as u8 as f32;
    v[h + 16] = (info.program_headers as f32 / 32.0).min(1.0);
    v[h + 17] = (f.sections.len() as f32 / 32.0).min(1.0);
    v[h + 18] = (f.libraries.len() as f32 / 32.0).min(1.0);
    v[h + 19] = (f.imports.len() as f32 / 512.0).min(1.0);
    v[h + 20] = (f.exports.len() as f32 / 512.0).min(1.0);
    v[h + 21] = info.has_tls as u8 as f32;
    v[h + 22] = info.has_init_array as u8 as f32;
    v[h + 23] = info.has_signature as u8 as f32;
    // Tabla de importaciones vacia en un ejecutable dinamico: carga por
    // resolucion manual, que es lo que hace el codigo empaquetado.
    v[h + 24] = (info.dynamic && f.imports.is_empty()) as u8 as f32;
    v[h + 25] = if f.size > 0 {
        (info.overlay_bytes as f32 / f.size as f32).min(1.0)
    } else {
        0.0
    };
    v[h + 26] = (info.overlay_bytes > 1024) as u8 as f32;

    // --- [96..144) Secciones ---
    let s = OFF_SECTIONS;
    if !f.sections.is_empty() {
        let n = f.sections.len() as f64;
        let ents: Vec<f64> = f.sections.iter().map(|x| x.entropy).collect();
        let media = ents.iter().sum::<f64>() / n;
        let maximo = ents.iter().cloned().fold(f64::MIN, f64::max);
        let minimo = ents.iter().cloned().fold(f64::MAX, f64::min);
        let var = ents.iter().map(|e| (e - media).powi(2)).sum::<f64>() / n;

        v[s] = (n as f32 / 32.0).min(1.0);
        v[s + 1] = (media / 8.0) as f32;
        v[s + 2] = (maximo / 8.0) as f32;
        v[s + 3] = (minimo / 8.0) as f32;
        v[s + 4] = (var.sqrt() / 4.0).min(1.0) as f32;
        v[s + 5] = (f
            .sections
            .iter()
            .filter(|x| x.entropy > entropy::HIGH_ENTROPY)
            .count() as f64
            / n) as f32;
        v[s + 6] = (f.sections.iter().filter(|x| x.is_wx()).count() as f64 / n) as f32;
        v[s + 7] = (f
            .sections
            .iter()
            .filter(|x| !es_seccion_estandar(&x.name))
            .count() as f64
            / n) as f32;
        v[s + 8] = (f
            .sections
            .iter()
            .filter(|x| x.raw_size == 0 && x.virtual_size > 0)
            .count() as f64
            / n) as f32;

        // Razon entre tamano en memoria y en fichero: el indicador clasico de
        // empaquetado.
        let razones: Vec<f64> = f.sections.iter().map(|x| x.virtual_to_raw()).collect();
        v[s + 9] = (razones.iter().cloned().fold(f64::MIN, f64::max) / 50.0).min(1.0) as f32;
        v[s + 10] = ((razones.iter().sum::<f64>() / n) / 50.0).min(1.0) as f32;
        v[s + 11] = (razones.iter().filter(|r| **r > 2.0).count() as f64 / n) as f32;
        // Secciones que declaran mas bytes de los que hay: manipulacion de la
        // tabla de secciones.
        v[s + 12] = (f.sections.iter().filter(|x| x.truncated).count() as f64 / n) as f32;
        v[s + 13] = if f.size > 0 {
            (f.sections.iter().map(|x| x.raw_size).max().unwrap_or(0) as f32 / f.size as f32)
                .min(1.0)
        } else {
            0.0
        };

        let buscar = |nombre: &str| f.sections.iter().find(|x| x.name == nombre);
        v[s + 14] = buscar(".text")
            .map(|x| (x.entropy / 8.0) as f32)
            .unwrap_or(0.0);
        v[s + 15] = buscar(".data")
            .map(|x| (x.entropy / 8.0) as f32)
            .unwrap_or(0.0);
        v[s + 16] = buscar(".rodata")
            .map(|x| (x.entropy / 8.0) as f32)
            .unwrap_or(0.0);
        v[s + 17] = buscar(".text").is_some() as u8 as f32;
        v[s + 18] = buscar(".data").is_some() as u8 as f32;
        v[s + 19] = buscar(".rodata").is_some() as u8 as f32;

        // Entropia de las primeras 28 secciones, en orden: da la FORMA del
        // binario, no solo un resumen. Un ejecutable normal alterna zonas de
        // entropia distinta; uno empaquetado es plano y alto.
        for (i, sec) in f.sections.iter().take(28).enumerate() {
            v[s + 20 + i] = (sec.entropy / 8.0) as f32;
        }
    }

    // --- [144..208) Importaciones por hashing ---
    let base_imp = OFF_IMPORTS;
    let total_imp = f.imports.len().max(1) as f32;
    for imp in &f.imports {
        let cubo = (fnv1a(&imp.to_ascii_lowercase()) as usize) % IMPORT_BUCKETS;
        v[base_imp + cubo] += 1.0 / total_imp;
    }

    // --- [208..240) Cadenas ---
    let st = OFF_STRINGS;
    let n_str = f.strings.len();
    v[st] = ((n_str as f64 + 1.0).log10() / 6.0).min(1.0) as f32;
    if n_str > 0 {
        let longitudes: Vec<usize> = f.strings.iter().map(|x| x.len()).collect();
        v[st + 1] =
            ((longitudes.iter().sum::<usize>() as f64 / n_str as f64) / 64.0).min(1.0) as f32;
        v[st + 2] = ((*longitudes.iter().max().unwrap() as f64) / 1024.0).min(1.0) as f32;
    }

    let contar = |pred: &dyn Fn(&str) -> bool| -> f32 {
        let c = f.strings.iter().filter(|x| pred(x)).count();
        ((c as f64 + 1.0).log10() / 4.0).min(1.0) as f32
    };
    v[st + 3] = contar(&|x| x.contains("http://") || x.contains("https://"));
    v[st + 4] = contar(&|x| parece_ip(x));
    v[st + 5] = contar(&|x| x.starts_with('/') && x.len() > 6);
    v[st + 6] = contar(&|x| x.contains(":\\") || x.contains("\\\\"));
    v[st + 7] = contar(&|x| x.contains("HKEY_") || x.contains("SOFTWARE\\"));
    v[st + 8] = contar(&|x| parece_base64(x));

    for (i, (_, palabras)) in CATEGORIAS.iter().enumerate() {
        let c = f
            .strings
            .iter()
            .filter(|s| palabras.iter().any(|p| s.contains(p)))
            .count();
        v[st + 9 + i * 2] = ((c as f64 + 1.0).log10() / 3.0).min(1.0) as f32;
        v[st + 10 + i * 2] = (c > 0) as u8 as f32;
    }

    // --- [240..256) Firma ---
    v[OFF_SIGNATURE] = info.has_signature as u8 as f32;
    v[OFF_SIGNATURE + 1] = (info.timestamp > 0) as u8 as f32;
    // Marca temporal en el futuro o anterior a 1995: cabecera manipulada.
    v[OFF_SIGNATURE + 2] = (info.timestamp > 2_000_000_000
        || (info.timestamp > 0 && info.timestamp < 788_918_400)) as u8
        as f32;

    v
}

/// Vectoriza incluyendo los histogramas, que necesitan el buffer original.
pub fn to_vector_with_data(f: &BinaryFeatures, datos: &[u8], block_size: usize) -> Vec<f32> {
    let mut v = to_vector(f);
    let bh = entropy::byte_histogram(datos, 16);
    v[OFF_BYTE_HIST..OFF_BYTE_HIST + 16].copy_from_slice(&bh);
    let eh = entropy::entropy_histogram(datos, block_size, 32);
    v[OFF_ENTROPY_HIST..OFF_ENTROPY_HIST + 32].copy_from_slice(&eh);
    v
}

fn parece_ip(s: &str) -> bool {
    let partes: Vec<&str> = s.split('.').collect();
    partes.len() == 4
        && partes
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn parece_base64(s: &str) -> bool {
    s.len() >= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}
