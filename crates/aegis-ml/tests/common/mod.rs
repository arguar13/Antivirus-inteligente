//! Constructores de binarios ELF y PE reales, byte a byte.
//!
//! No hay ficheros de muestra versionados: cada prueba fabrica su binario en
//! tiempo de ejecucion escribiendo las cabeceras a mano. Eso permite construir
//! exactamente la anomalia que se quiere probar (un segmento RWX, una seccion
//! cuyo tamano en memoria multiplica por veinte el de disco, un punto de
//! entrada fuera de toda seccion) en lugar de esperar a que aparezca en una
//! muestra recogida.

#![allow(dead_code)]

// --- ELF -------------------------------------------------------------------

/// Tipo de objeto ELF.
pub const ET_EXEC: u16 = 2;
/// Objeto compartido o ejecutable independiente de posicion.
pub const ET_DYN: u16 = 3;

/// Segmento cargable.
pub const PT_LOAD: u32 = 1;
/// Ruta del interprete dinamico.
pub const PT_INTERP: u32 = 3;
/// Permisos de la pila.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// Reubicaciones de solo lectura.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Ejecutable.
pub const PF_X: u32 = 1;
/// Escribible.
pub const PF_W: u32 = 2;
/// Legible.
pub const PF_R: u32 = 4;

/// Seccion con datos en el fichero.
pub const SHT_PROGBITS: u32 = 1;
/// Tabla de simbolos.
pub const SHT_SYMTAB: u32 = 2;
/// Seccion sin contenido en el fichero.
pub const SHT_NOBITS: u32 = 8;

/// La seccion ocupa memoria en ejecucion.
pub const SHF_ALLOC: u64 = 0x2;
/// La seccion es ejecutable.
pub const SHF_EXECINSTR: u64 = 0x4;
/// La seccion es escribible.
pub const SHF_WRITE: u64 = 0x1;

/// Descripcion de una seccion a construir.
pub struct SectionSpec {
    /// Nombre.
    pub name: &'static str,
    /// Tipo.
    pub sh_type: u32,
    /// Banderas.
    pub flags: u64,
    /// Contenido. Vacio para `SHT_NOBITS`.
    pub data: Vec<u8>,
    /// Tamano declarado en `sh_size`.
    ///
    /// En ELF `sh_size` ES el tamano en el fichero: no existe la dualidad de
    /// PE entre `VirtualSize` y `SizeOfRawData`. Solo hay dos formas legitimas
    /// de que difieran del contenido, y ambas son significativas:
    /// `SHT_NOBITS`, que no ocupa nada en disco, y una seccion truncada, que
    /// es una anomalia. Poner aqui un valor mayor que `data.len()` para una
    /// seccion `SHT_PROGBITS` construye deliberadamente el segundo caso.
    pub virtual_size: u64,
}

impl SectionSpec {
    /// Seccion con contenido.
    pub fn progbits(name: &'static str, flags: u64, data: Vec<u8>) -> SectionSpec {
        SectionSpec {
            name,
            sh_type: SHT_PROGBITS,
            flags,
            data,
            virtual_size: 0,
        }
    }
}

/// Descripcion de un segmento a construir.
pub struct SegmentSpec {
    /// Tipo.
    pub p_type: u32,
    /// Permisos.
    pub flags: u32,
}

/// Constructor de un ELF de 64 bits little-endian.
pub struct ElfBuilder {
    /// Tipo de objeto.
    pub e_type: u16,
    /// Arquitectura.
    pub machine: u16,
    /// Punto de entrada.
    pub entry: u64,
    /// Secciones.
    pub sections: Vec<SectionSpec>,
    /// Segmentos.
    pub segments: Vec<SegmentSpec>,
    /// Datos adicionales despues de la ultima seccion.
    pub overlay: Vec<u8>,
}

impl Default for ElfBuilder {
    fn default() -> Self {
        ElfBuilder {
            e_type: ET_DYN,
            machine: 0x3e, // x86-64
            entry: 0x1000,
            sections: Vec::new(),
            segments: Vec::new(),
            overlay: Vec::new(),
        }
    }
}

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;

impl ElfBuilder {
    /// Serializa el ELF completo.
    pub fn build(&self) -> Vec<u8> {
        // Disposicion: cabecera, cabeceras de programa, datos de seccion,
        // shstrtab, cabeceras de seccion, apendice.
        let mut shstrtab = vec![0u8]; // el indice 0 es siempre la cadena vacia
        let mut nombres = Vec::new();
        for s in &self.sections {
            nombres.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(s.name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let phoff = EHDR_SIZE;
        let ph_bytes = self.segments.len() * PHDR_SIZE;
        let mut cursor = phoff + ph_bytes;

        // Colocar el contenido de cada seccion.
        let mut offsets = Vec::new();
        for s in &self.sections {
            if s.sh_type == SHT_NOBITS {
                offsets.push(cursor as u64);
            } else {
                offsets.push(cursor as u64);
                cursor += s.data.len();
            }
        }
        let shstrtab_off = cursor;
        cursor += shstrtab.len();

        // Las cabeceras de seccion van alineadas a 8.
        let shoff = cursor.div_ceil(8) * 8;

        // La tabla lleva una entrada nula inicial, obligatoria en ELF.
        let shnum = self.sections.len() + 2;
        let mut out = vec![0u8; shoff + shnum * SHDR_SIZE];

        // --- Cabecera ELF ---
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&self.e_type.to_le_bytes());
        out[18..20].copy_from_slice(&self.machine.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..32].copy_from_slice(&self.entry.to_le_bytes());
        out[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&(self.segments.len() as u16).to_le_bytes());
        out[58..60].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        out[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        out[62..64].copy_from_slice(&((shnum - 1) as u16).to_le_bytes());

        // --- Cabeceras de programa ---
        for (i, seg) in self.segments.iter().enumerate() {
            let o = phoff + i * PHDR_SIZE;
            out[o..o + 4].copy_from_slice(&seg.p_type.to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&seg.flags.to_le_bytes());
            out[o + 8..o + 16].copy_from_slice(&0u64.to_le_bytes());
            out[o + 16..o + 24].copy_from_slice(&0x1000u64.to_le_bytes());
            out[o + 24..o + 32].copy_from_slice(&0x1000u64.to_le_bytes());
            out[o + 32..o + 40].copy_from_slice(&0x1000u64.to_le_bytes());
            out[o + 40..o + 48].copy_from_slice(&0x1000u64.to_le_bytes());
            out[o + 48..o + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }

        // --- Contenido de las secciones ---
        for (i, s) in self.sections.iter().enumerate() {
            if s.sh_type == SHT_NOBITS {
                continue;
            }
            let o = offsets[i] as usize;
            out[o..o + s.data.len()].copy_from_slice(&s.data);
        }
        out[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);

        // --- Cabeceras de seccion ---
        // La entrada 0 es SHT_NULL y queda a cero.
        for (i, s) in self.sections.iter().enumerate() {
            let o = shoff + (i + 1) * SHDR_SIZE;
            let vsize = if s.virtual_size > 0 {
                s.virtual_size
            } else {
                s.data.len() as u64
            };
            out[o..o + 4].copy_from_slice(&nombres[i].to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&s.sh_type.to_le_bytes());
            out[o + 8..o + 16].copy_from_slice(&s.flags.to_le_bytes());
            out[o + 16..o + 24].copy_from_slice(&(0x1000u64 + i as u64 * 0x1000).to_le_bytes());
            out[o + 24..o + 32].copy_from_slice(&offsets[i].to_le_bytes());
            out[o + 32..o + 40].copy_from_slice(&vsize.to_le_bytes());
            out[o + 48..o + 56].copy_from_slice(&1u64.to_le_bytes());
        }
        // Entrada de .shstrtab.
        let o = shoff + (shnum - 1) * SHDR_SIZE;
        out[o..o + 4].copy_from_slice(&shstrtab_name_off.to_le_bytes());
        out[o + 4..o + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        out[o + 24..o + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
        out[o + 32..o + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
        out[o + 48..o + 56].copy_from_slice(&1u64.to_le_bytes());

        out.extend_from_slice(&self.overlay);
        out
    }
}

// --- PE --------------------------------------------------------------------

/// Descripcion de una seccion PE.
pub struct PeSection {
    /// Nombre, hasta 8 bytes.
    pub name: &'static str,
    /// Contenido.
    pub data: Vec<u8>,
    /// Tamano declarado en memoria. 0 usa el del contenido.
    pub virtual_size: u32,
    /// Caracteristicas (`IMAGE_SCN_*`).
    pub characteristics: u32,
}

/// Seccion con codigo ejecutable y legible.
pub const SCN_CODE_R_X: u32 = 0x2000_0020 | 0x4000_0000;
/// Seccion de datos legible y escribible.
pub const SCN_DATA_RW: u32 = 0x4000_0040 | 0x8000_0000;
/// Seccion escribible Y ejecutable: casi ningun compilador la produce.
pub const SCN_RWX: u32 = 0x2000_0020 | 0x4000_0000 | 0x8000_0000;

/// Constructor de un PE32+ minimo pero valido.
pub struct PeBuilder {
    /// Arquitectura.
    pub machine: u16,
    /// Caracteristicas del fichero.
    pub characteristics: u16,
    /// Banderas de mitigacion (`IMAGE_DLLCHARACTERISTICS_*`).
    pub dll_characteristics: u16,
    /// Direccion virtual relativa del punto de entrada.
    pub entry_rva: u32,
    /// Marca temporal.
    pub timestamp: u32,
    /// Secciones.
    pub sections: Vec<PeSection>,
    /// Datos despues de la ultima seccion.
    pub overlay: Vec<u8>,
}

impl Default for PeBuilder {
    fn default() -> Self {
        PeBuilder {
            machine: 0x8664,
            characteristics: 0x0022, // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            dll_characteristics: 0x0140, // DYNAMIC_BASE | NX_COMPAT
            entry_rva: 0x1000,
            timestamp: 1_700_000_000,
            sections: Vec::new(),
            overlay: Vec::new(),
        }
    }
}

const PE_HDR_OFF: usize = 0x80;
const OPT_HDR_SIZE: usize = 240; // PE32+ con 16 directorios de datos
const SECT_ENTRY: usize = 40;
const FILE_ALIGN: usize = 512;

impl PeBuilder {
    /// Serializa el PE completo.
    pub fn build(&self) -> Vec<u8> {
        let n = self.sections.len();
        let tabla_off = PE_HDR_OFF + 4 + 20 + OPT_HDR_SIZE;
        let cabeceras = (tabla_off + n * SECT_ENTRY).div_ceil(FILE_ALIGN) * FILE_ALIGN;

        let mut datos_off = Vec::new();
        let mut cursor = cabeceras;
        for s in &self.sections {
            datos_off.push(cursor);
            cursor += s.data.len().div_ceil(FILE_ALIGN) * FILE_ALIGN;
        }

        let mut out = vec![0u8; cursor.max(cabeceras)];

        // --- Cabecera DOS ---
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&(PE_HDR_OFF as u32).to_le_bytes());

        // --- Firma PE + cabecera COFF ---
        out[PE_HDR_OFF..PE_HDR_OFF + 4].copy_from_slice(b"PE\0\0");
        let c = PE_HDR_OFF + 4;
        out[c..c + 2].copy_from_slice(&self.machine.to_le_bytes());
        out[c + 2..c + 4].copy_from_slice(&(n as u16).to_le_bytes());
        out[c + 4..c + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        out[c + 16..c + 18].copy_from_slice(&(OPT_HDR_SIZE as u16).to_le_bytes());
        out[c + 18..c + 20].copy_from_slice(&self.characteristics.to_le_bytes());

        // --- Cabecera opcional PE32+ ---
        let o = c + 20;
        out[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        out[o + 2] = 14; // version del enlazador
        out[o + 16..o + 20].copy_from_slice(&self.entry_rva.to_le_bytes());
        out[o + 24..o + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
        out[o + 32..o + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        out[o + 36..o + 40].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
        out[o + 40..o + 42].copy_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
        out[o + 48..o + 50].copy_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
        let size_of_image = (0x1000 + n.max(1) * 0x1000) as u32;
        out[o + 56..o + 60].copy_from_slice(&size_of_image.to_le_bytes());
        out[o + 60..o + 64].copy_from_slice(&(cabeceras as u32).to_le_bytes());
        out[o + 68..o + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem CUI
        out[o + 70..o + 72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        out[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // --- Tabla de secciones ---
        for (i, s) in self.sections.iter().enumerate() {
            let e = tabla_off + i * SECT_ENTRY;
            let bytes = s.name.as_bytes();
            let l = bytes.len().min(8);
            out[e..e + l].copy_from_slice(&bytes[..l]);
            let vsize = if s.virtual_size > 0 {
                s.virtual_size
            } else {
                s.data.len() as u32
            };
            let rva = 0x1000u32 + i as u32 * 0x1000;
            out[e + 8..e + 12].copy_from_slice(&vsize.to_le_bytes());
            out[e + 12..e + 16].copy_from_slice(&rva.to_le_bytes());
            let raw = (s.data.len().div_ceil(FILE_ALIGN) * FILE_ALIGN) as u32;
            out[e + 16..e + 20].copy_from_slice(&raw.to_le_bytes());
            out[e + 20..e + 24].copy_from_slice(&(datos_off[i] as u32).to_le_bytes());
            out[e + 36..e + 40].copy_from_slice(&s.characteristics.to_le_bytes());
        }

        // --- Contenido ---
        for (i, s) in self.sections.iter().enumerate() {
            let d = datos_off[i];
            out[d..d + s.data.len()].copy_from_slice(&s.data);
        }

        out.extend_from_slice(&self.overlay);
        out
    }
}

// --- Generadores de contenido ---------------------------------------------

/// Bytes de alta entropia, indistinguibles de datos cifrados.
///
/// Se usa un generador congruencial lineal con semilla fija: el contenido es
/// deterministico, asi que una prueba que falle vuelve a fallar igual, pero su
/// distribucion es lo bastante uniforme para dar entropia por encima de 7,9.
pub fn high_entropy(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) as u8
        })
        .collect()
}

/// Bytes con la distribucion de codigo maquina compilado.
///
/// Entropia intermedia (5,5-6,5), como la de una seccion `.text` normal.
pub fn code_like(n: usize) -> Vec<u8> {
    // Opcodes x86-64 frecuentes, repetidos con variacion: da la distribucion
    // sesgada tipica del codigo real, no la uniforme de los datos cifrados.
    const OPS: &[u8] = &[
        0x48, 0x89, 0xe5, 0x55, 0x41, 0x57, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xe8, 0xc3, 0x31, 0xc0,
        0x8b, 0x45, 0xfc, 0x83, 0xec, 0x20, 0x5d, 0x90, 0x66,
    ];
    (0..n).map(|i| OPS[(i * 7 + i / 13) % OPS.len()]).collect()
}

/// Texto plano, entropia baja.
pub fn text_like(n: usize) -> Vec<u8> {
    const T: &[u8] = b"the quick brown fox jumps over the lazy dog and then returns home again ";
    (0..n).map(|i| T[i % T.len()]).collect()
}
