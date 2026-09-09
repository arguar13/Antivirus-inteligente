//! Integridad de los stubs de syscall de las bibliotecas del sistema.
//!
//! # Que se comprueba y por que
//!
//! Un enganche ("hook") en userland sustituye los primeros bytes de una funcion
//! por un salto al codigo del atacante. Se usa en las dos direcciones:
//!
//! - **Ofensiva.** Un troyano bancario engancha `send`/`recv` para leer el
//!   trafico antes de que se cifre, o `open` para ocultar sus ficheros.
//! - **Defensiva, y por eso el desenganche.** Muchos EDR enganchan las mismas
//!   funciones para vigilarlas. El malware moderno lo sabe: **relee la
//!   biblioteca del disco y restaura los bytes originales** antes de operar.
//!   Esa restauracion es indistinguible de lo normal si solo miras la memoria.
//!
//! Este modulo compara los primeros bytes de cada simbolo exportado contra los
//! bytes que el fichero tiene en ese mismo desplazamiento. Detecta las dos
//! cosas: los bytes que ya no son los del fichero (enganchado) y, en un
//! producto que enganche, los que han vuelto a serlo (desenganchado).
//!
//! # Por que se buscan patrones y no solo diferencias
//!
//! Una diferencia puede ser una reubicacion. Un salto no. Los cuatro patrones
//! que se reconocen son las cuatro formas de escribir "salta a esta direccion"
//! en x86-64, y ninguna aparece por accidente al principio de una funcion:
//!
//! ```text
//! E9 xx xx xx xx           jmp rel32
//! FF 25 xx xx xx xx        jmp [rip+disp32]
//! 68 xx xx xx xx C3        push imm32; ret
//! 48 B8 <8 bytes> FF E0    mov rax, imm64; jmp rax
//! ```

use crate::EvasionError;

/// Bytes del prologo que se comparan por simbolo.
///
/// Los cuatro patrones de salto caben en 14; se leen 16 para poder
/// reconocerlos completos con margen.
pub const PROLOGO: usize = 16;

/// Forma del parche encontrado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    /// `E9 rel32`: salto relativo directo.
    JmpRel32,
    /// `FF 25 disp32`: salto indirecto a traves de memoria.
    JmpIndirect,
    /// `68 imm32 C3`: apila la direccion y retorna a ella.
    PushRet,
    /// `48 B8 imm64 ... FF E0`: carga absoluta y salta.
    MovRaxJmp,
    /// Los bytes difieren del fichero pero no forman ningun salto reconocible.
    ///
    /// Es lo que produce una reubicacion legitima, y tambien un parche de
    /// datos. Se reporta con peso bajo.
    Unknown,
}

impl PatchKind {
    /// Peso en la puntuacion.
    pub fn weight(self) -> u32 {
        match self {
            PatchKind::JmpRel32
            | PatchKind::JmpIndirect
            | PatchKind::PushRet
            | PatchKind::MovRaxJmp => 40,
            PatchKind::Unknown => 5,
        }
    }

    /// Indica si el patron es un salto inequivoco.
    pub fn is_jump(self) -> bool {
        !matches!(self, PatchKind::Unknown)
    }
}

/// Reconoce un patron de salto al principio de un prologo.
///
/// Funcion pura y sin estado: es lo unico de este modulo que depende del juego
/// de instrucciones, y aislarla permite probarla con bytes escritos a mano.
pub fn reconocer_salto(bytes: &[u8]) -> Option<PatchKind> {
    if bytes.len() >= 5 && bytes[0] == 0xE9 {
        return Some(PatchKind::JmpRel32);
    }
    if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
        return Some(PatchKind::JmpIndirect);
    }
    if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
        return Some(PatchKind::PushRet);
    }
    if bytes.len() >= 12
        && bytes[0] == 0x48
        && bytes[1] == 0xB8
        && bytes[10] == 0xFF
        && bytes[11] == 0xE0
    {
        return Some(PatchKind::MovRaxJmp);
    }
    None
}

/// Un simbolo cuyo prologo no coincide con el del fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookFinding {
    /// Nombre del simbolo.
    pub symbol: String,
    /// Biblioteca que lo exporta.
    pub library: String,
    /// Direccion del simbolo en el proceso.
    pub address: u64,
    /// Forma del parche.
    pub kind: PatchKind,
    /// Bytes leidos de memoria.
    pub in_memory: Vec<u8>,
    /// Bytes que el fichero tiene en ese desplazamiento.
    pub on_disk: Vec<u8>,
}

/// Resultado del analisis de enganches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookReport {
    /// Simbolos con el prologo alterado.
    pub findings: Vec<HookFinding>,
    /// Simbolos comprobados.
    pub checked: usize,
    /// Simbolos que no se pudieron comprobar.
    pub skipped: usize,
}

impl HookReport {
    /// Puntuacion acumulada, con los saltos pesando y las diferencias sin
    /// forma de salto apenas.
    pub fn score(&self) -> u32 {
        self.findings.iter().map(|f| f.kind.weight()).sum()
    }

    /// Simbolos enganchados con un salto inequivoco.
    pub fn hooked(&self) -> usize {
        self.findings.iter().filter(|f| f.kind.is_jump()).count()
    }
}

/// Funciones que un atacante engancha, y que por tanto merecen comprobarse.
///
/// La lista es la interseccion de lo que usan los troyanos bancarios, los
/// rootkits de userland y los ladrones de credenciales: entrada/salida de
/// ficheros, red, procesos y aleatoriedad.
pub const SIMBOLOS_VIGILADOS: &[&str] = &[
    // Ficheros y directorios: ocultacion.
    "open",
    "open64",
    "openat",
    "openat64",
    "read",
    "write",
    "unlink",
    "unlinkat",
    "rename",
    "readdir",
    "readdir64",
    "stat",
    "lstat",
    "fstat",
    "access",
    // Procesos y ejecucion.
    "execve",
    "execv",
    "execvp",
    "fork",
    "vfork",
    "clone",
    "ptrace",
    "kill",
    // Red: interceptacion antes del cifrado.
    "connect",
    "accept",
    "send",
    "sendto",
    "recv",
    "recvfrom",
    "socket",
    "bind",
    "getaddrinfo",
    "gethostbyname",
    // Carga dinamica: como se trae el codigo.
    "dlopen",
    "dlsym",
    "mmap",
    "mprotect",
    // Credenciales y aleatoriedad.
    "getpwnam",
    "crypt",
    "getrandom",
    "RAND_bytes",
    // TLS: lectura del texto plano.
    "SSL_read",
    "SSL_write",
];

/// Un simbolo exportado, ya resuelto a direccion de proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSymbol {
    /// Nombre.
    pub name: String,
    /// Biblioteca que lo exporta.
    pub library: String,
    /// Direccion en el espacio del proceso.
    pub address: u64,
    /// Desplazamiento del simbolo dentro del fichero.
    pub file_offset: u64,
}

/// Compara los prologos de una lista de simbolos ya resueltos.
///
/// `leer` obtiene bytes del proceso y `fichero` obtiene el contenido de una
/// biblioteca. Se inyectan para que la logica se pruebe entera sin proceso ni
/// disco: es la unica forma de cubrir los casos de parcheo, que en una maquina
/// sana no ocurren nunca.
pub fn scan_hooks<L, F>(simbolos: &[ResolvedSymbol], mut leer: L, mut fichero: F) -> HookReport
where
    L: FnMut(u64, usize) -> Option<Vec<u8>>,
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut informe = HookReport::default();

    for s in simbolos {
        let Some(datos) = fichero(&s.library) else {
            informe.skipped += 1;
            continue;
        };
        let off = s.file_offset as usize;
        if off >= datos.len() || datos.len() - off < PROLOGO {
            informe.skipped += 1;
            continue;
        }
        let Some(memoria) = leer(s.address, PROLOGO) else {
            informe.skipped += 1;
            continue;
        };
        if memoria.len() < PROLOGO {
            informe.skipped += 1;
            continue;
        }
        informe.checked += 1;

        let disco = &datos[off..off + PROLOGO];
        if memoria == disco {
            continue;
        }
        // El patron se busca en la memoria, no en la diferencia: un salto
        // instalado es un salto aunque el fichero tuviese algo parecido.
        let kind = reconocer_salto(&memoria).unwrap_or(PatchKind::Unknown);
        informe.findings.push(HookFinding {
            symbol: s.name.clone(),
            library: s.library.clone(),
            address: s.address,
            kind,
            in_memory: memoria,
            on_disk: disco.to_vec(),
        });
    }

    informe.findings.sort_by(|a, b| {
        b.kind
            .weight()
            .cmp(&a.kind.weight())
            .then(a.symbol.cmp(&b.symbol))
    });
    informe
}

/// Resuelve los simbolos vigilados de una biblioteca ELF ya mapeada.
///
/// `base` es la direccion donde el enlazador cargo el objeto. Para una
/// biblioteca compartida los simbolos son relativos a esa base; para un
/// ejecutable no-PIE, `st_value` ya es la direccion final y `base` es cero.
pub fn resolver_simbolos(
    ruta: &str,
    datos: &[u8],
    base: u64,
    vigilados: &[&str],
) -> Result<Vec<ResolvedSymbol>, EvasionError> {
    let elf = goblin::elf::Elf::parse(datos).map_err(|e| EvasionError::Elf {
        path: ruta.to_string(),
        detail: e.to_string(),
    })?;

    let mut salida = Vec::new();
    for sym in elf.dynsyms.iter() {
        if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        let Some(nombre) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        // Los simbolos versionados llegan como `open@@GLIBC_2.2.5` en algunas
        // tablas; se compara la parte anterior a la arroba.
        let base_nombre = nombre.split('@').next().unwrap_or(nombre);
        if !vigilados.contains(&base_nombre) {
            continue;
        }
        // De direccion virtual a desplazamiento de fichero: la unica traduccion
        // valida es a traves del segmento que la contiene, porque un ELF no
        // garantiza que coincidan.
        let Some(off) = virtual_a_fichero(&elf, sym.st_value) else {
            continue;
        };
        salida.push(ResolvedSymbol {
            name: base_nombre.to_string(),
            library: ruta.to_string(),
            address: base.wrapping_add(sym.st_value),
            file_offset: off,
        });
    }
    salida.sort_by(|a, b| a.name.cmp(&b.name));
    salida.dedup_by(|a, b| a.name == b.name && a.address == b.address);
    Ok(salida)
}

/// Traduce una direccion virtual a desplazamiento de fichero usando los
/// segmentos cargables.
pub fn virtual_a_fichero(elf: &goblin::elf::Elf<'_>, vaddr: u64) -> Option<u64> {
    for ph in elf.program_headers.iter() {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        // Se usa `p_filesz` y no `p_memsz`: la parte de un segmento que excede
        // el tamano en fichero es `.bss`, que no existe en el disco.
        if vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr.saturating_add(ph.p_filesz) {
            return Some(ph.p_offset + (vaddr - ph.p_vaddr));
        }
    }
    None
}
