//! ¿Llega la ejecucion a la funcion vulnerable? El grafo de llamadas de la
//! FASE 85 sobre un ELF real.
//!
//! # Lo dificil no es el grafo, son las raices
//!
//! Un recorrido desde el punto de entrada no llega a `main`: `_start` no llama a
//! `main`, le pasa su DIRECCION a `__libc_start_main`. Y lo mismo pasa con cada
//! puntero a funcion —una tabla de manejadores, una retrollamada, un constructor
//! de `.init_array`—. Un recorrido que solo sigue llamadas directas desde la
//! entrada concluye «inalcanzable» sobre medio programa, y ese «No» es falso.
//!
//! Por eso las raices son **toda funcion cuya direccion se toma** en algun sitio:
//!
//! - en el codigo: un `lea`/`mov` que carga una direccion del segmento
//!   ejecutable ([`aegis_disasm::instruccion::Instruccion::valor_definido`] y los
//!   inmediatos);
//! - en los datos: cada palabra de 8 bytes de las secciones de datos que apunta
//!   al segmento ejecutable;
//! - en las reubicaciones: los `R_X86_64_RELATIVE` de un ejecutable PIE, que es
//!   donde estan de verdad los punteros a funcion de sus tablas;
//! - en una biblioteca, ademas, todo lo que exporta.
//!
//! Con esas raices, una llamada indirecta que el analisis no resolvio solo puede
//! ir a una funcion cuya direccion se tomo —que ya es raiz—, y el «No» es sano.
//! Lo que queda fuera se declara: direcciones calculadas con aritmetica y codigo
//! generado en ejecucion.
//!
//! # Lo que responde
//!
//! Para una funcion IMPORTADA (una biblioteca dinamica vulnerable): si hay algun
//! sitio desde el que se la llama que este en una funcion alcanzable. Para una
//! funcion INTERNA con simbolo (una dependencia enlazada estaticamente): si esa
//! funcion es alcanzable. Si el analisis se corto por sus topes, un «No» se
//! convierte en `SinDatos`: no haber llegado no es haber comprobado que no se
//! llega.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::time::Duration;

use aegis_disasm::analisis::{analizar, Entrada};
use aegis_disasm::cfg::LeeDatos;
use aegis_disasm::importaciones::{Forma, Importadas};
use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::plazo::Plazo;
use goblin::elf::Elf;

/// Tope de bytes de un ELF que se analiza.
pub const MAX_ELF: u64 = 256 * 1024 * 1024;

/// Tope de raices.
pub const MAX_RAICES: usize = 200_000;

/// Plazo del analisis de un binario.
pub const PLAZO: Duration = Duration::from_secs(20);

/// Tope de instrucciones del analisis de un binario.
pub const TOPE_INSTRUCCIONES: u64 = 30_000_000;

/// La tabla de importaciones de un ELF: entrada del GOT -> nombre.
struct Got(BTreeMap<u64, String>);

impl Importadas for Got {
    fn nombre_en(&self, direccion: u64) -> Option<&str> {
        self.0.get(&direccion).map(String::as_str)
    }
}

/// La imagen de un ELF por direcciones virtuales, para leer tablas de saltos.
struct Imagen<'a> {
    bytes: &'a [u8],
    tramos: Vec<(u64, u64, usize)>, // (vaddr, filesz, offset)
}

impl Imagen<'_> {
    fn en(&self, dir: u64, n: usize) -> Option<&[u8]> {
        // Las direcciones salen del binario analizado: con sumas comprobadas, una
        // direccion cerca de u64::MAX no desborda.
        let fin = dir.checked_add(n as u64)?;
        for (va, tam, off) in &self.tramos {
            if dir >= *va && va.checked_add(*tam).is_some_and(|t| fin <= t) {
                let ini = off + usize::try_from(dir - va).ok()?;
                return self.bytes.get(ini..ini + n);
            }
        }
        None
    }
}

impl LeeDatos for Imagen<'_> {
    fn u64_en(&self, d: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.en(d, 8)?.try_into().ok()?))
    }
    fn u32_en(&self, d: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.en(d, 4)?.try_into().ok()?))
    }
}

/// El grafo de un binario, listo para preguntarle.
#[derive(Debug, Clone, Default)]
pub struct Grafo {
    /// Funciones alcanzables desde alguna raiz.
    pub alcanzables: BTreeSet<u64>,
    /// Cuantas raices se usaron.
    pub raices: usize,
    /// Nombre importado -> funciones desde las que se le llama.
    pub llamadas_a_importadas: BTreeMap<String, BTreeSet<u64>>,
    /// Los nombres que el binario importa (simbolos dinamicos sin definir).
    pub importadas: BTreeSet<String>,
    /// Funciones internas con simbolo: ruta desenredada -> direccion.
    pub simbolos: BTreeMap<String, u64>,
    /// Si el binario trae tabla de simbolos.
    pub con_simbolos: bool,
    /// Si el analisis se corto por sus topes: un «No» no vale.
    pub incompleto: bool,
    /// Funciones y llamadas del grafo, para la evidencia.
    pub frase: String,
}

/// Desenreda un simbolo de Rust con el esquema antiguo (`_ZN...E`), quitando el
/// resumen final y los parametros de tipo: `_ZN8smallvec17SmallVec$LT$A$GT$11
/// insert_many17h0123456789abcdefE` -> `smallvec::SmallVec::insert_many`.
///
/// El esquema v0 (`_R...`) no se desenreda aqui, y esos simbolos simplemente no
/// entran en la tabla.
#[must_use]
pub fn desenredar_rust(s: &str) -> Option<String> {
    let mut r = s.strip_prefix("_ZN")?.strip_suffix('E')?;
    let mut tramos = Vec::new();
    while !r.is_empty() {
        let fin = r.find(|c: char| !c.is_ascii_digit())?;
        let n: usize = r[..fin].parse().ok()?;
        let t = r.get(fin..fin + n)?;
        tramos.push(t);
        r = &r[fin + n..];
    }
    if let Some(ultimo) = tramos.last() {
        if ultimo.len() == 17
            && ultimo.starts_with('h')
            && ultimo[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            tramos.pop();
        }
    }
    let limpio: Vec<String> = tramos
        .iter()
        .map(|t| {
            let t = t
                .replace("$LT$", "<")
                .replace("$GT$", ">")
                .replace("$u20$", " ")
                .replace("$C$", ",")
                .replace("..", "::");
            // Fuera los parametros de tipo: `SmallVec<A>` -> `SmallVec`.
            let mut o = String::new();
            let mut prof = 0i32;
            for c in t.chars() {
                match c {
                    '<' => prof += 1,
                    '>' => prof -= 1,
                    _ if prof == 0 => o.push(c),
                    _ => {}
                }
            }
            o.trim_start_matches('_').to_string()
        })
        .filter(|t| !t.is_empty())
        .collect();
    (!limpio.is_empty()).then(|| limpio.join("::"))
}

/// Construye el grafo de un ELF de x86-64.
///
/// # Errors
///
/// Si no se puede leer, no es un ELF de x86-64 o no tiene segmento ejecutable.
pub fn analizar_elf(ruta: &Path) -> Result<Grafo, String> {
    let md = std::fs::metadata(ruta).map_err(|e| e.to_string())?;
    if md.len() > MAX_ELF {
        return Err(format!("{} bytes, por encima del tope", md.len()));
    }
    let bytes = std::fs::read(ruta).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("no es un ELF valido: {e}"))?;
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Err("solo se analiza x86-64".into());
    }
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    let cargables: Vec<_> = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .collect();
    let exe = cargables
        .iter()
        .filter(|p| p.p_flags & PF_X != 0)
        .max_by_key(|p| p.p_filesz)
        .ok_or("sin segmento ejecutable")?;
    let (base, off, tam) = (exe.p_vaddr, exe.p_offset as usize, exe.p_filesz as usize);
    let codigo = off
        .checked_add(tam)
        .and_then(|fin| bytes.get(off..fin))
        .ok_or("segmento fuera del fichero")?;
    let en_codigo = |d: u64| d >= base && d < base + tam as u64;
    let imagen = Imagen {
        bytes: &bytes,
        tramos: cargables
            .iter()
            .map(|p| (p.p_vaddr, p.p_filesz, p.p_offset as usize))
            .collect(),
    };

    // La tabla de importaciones: JUMP_SLOT (PLT) y GLOB_DAT (-fno-plt, .plt.got).
    let mut got = BTreeMap::new();
    let nombre_dyn = |i: usize| -> Option<String> {
        let s = elf.dynsyms.get(i)?;
        elf.dynstrtab.get_at(s.st_name).map(str::to_string)
    };
    use goblin::elf::reloc::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE};
    let mut relativas: Vec<u64> = Vec::new();
    for r in elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter())
    {
        match r.r_type {
            R_X86_64_JUMP_SLOT | R_X86_64_GLOB_DAT => {
                if let Some(n) = nombre_dyn(r.r_sym).filter(|n| !n.is_empty()) {
                    got.insert(r.r_offset, n);
                }
                // Si el simbolo esta DEFINIDO en este binario, su direccion se
                // guarda en el GOT: es una direccion tomada. Es como `_start` de
                // un PIE puede cargar la de `main`, y sin esto `main` no seria
                // raiz y el programa entero saldria «inalcanzable».
                if let Some(s) = elf.dynsyms.get(r.r_sym) {
                    if !s.is_import() && en_codigo(s.st_value) {
                        relativas.push(s.st_value);
                    }
                }
            }
            R_X86_64_RELATIVE => {
                if let Some(a) = r.r_addend {
                    if a >= 0 && en_codigo(a as u64) {
                        relativas.push(a as u64);
                    }
                }
            }
            _ => {}
        }
    }
    let importadas: BTreeSet<String> = elf
        .dynsyms
        .iter()
        .filter(|s| s.is_import())
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string))
        .filter(|n| !n.is_empty())
        .collect();

    // Entradas del primer pase: entrada, simbolos de funcion y los stubs del PLT.
    let mut entradas: BTreeSet<u64> = BTreeSet::new();
    entradas.insert(elf.header.e_entry);
    let mut simbolos = BTreeMap::new();
    let con_simbolos = elf.syms.iter().any(|s| s.is_function() && s.st_value != 0);
    for s in elf.syms.iter() {
        if s.is_function() && en_codigo(s.st_value) {
            entradas.insert(s.st_value);
            if let Some(n) = elf.strtab.get_at(s.st_name).and_then(desenredar_rust) {
                simbolos.insert(n, s.st_value);
            }
        }
    }
    let es_biblioteca =
        elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none();
    let mut exportadas = Vec::new();
    for s in elf.dynsyms.iter() {
        if s.is_function() && !s.is_import() && en_codigo(s.st_value) {
            entradas.insert(s.st_value);
            exportadas.push(s.st_value);
        }
    }
    for sh in &elf.section_headers {
        let n = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if matches!(n, ".plt" | ".plt.sec" | ".plt.got") {
            let mut d = sh.sh_addr;
            while d < sh.sh_addr + sh.sh_size {
                if en_codigo(d) {
                    entradas.insert(d);
                }
                d += if n == ".plt.got" { 8 } else { 16 };
            }
        }
    }

    // Direcciones tomadas en los datos: palabras de 8 bytes de las secciones de
    // datos que apuntan al codigo.
    let mut tomadas: BTreeSet<u64> = relativas.into_iter().collect();
    for sh in &elf.section_headers {
        let n = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        let es_datos = n.starts_with(".data")
            || n.starts_with(".init_array")
            || n.starts_with(".fini_array")
            || n == ".got";
        if !es_datos || sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            continue;
        }
        let ini = sh.sh_offset as usize;
        let Some(datos) = ini
            .checked_add(sh.sh_size as usize)
            .and_then(|fin| bytes.get(ini..fin))
        else {
            continue;
        };
        for w in datos.chunks_exact(8) {
            let v = u64::from_le_bytes(w.try_into().unwrap_or([0; 8]));
            if en_codigo(v) {
                tomadas.insert(v);
            }
        }
    }

    let mut plazo = Plazo::nuevo(PLAZO, TOPE_INSTRUCCIONES);
    let analizar_con = |ent: &BTreeSet<u64>, plazo: &mut Plazo| {
        let v: Vec<u64> = ent.iter().copied().take(MAX_RAICES).collect();
        let e = Entrada {
            codigo,
            base,
            arquitectura: Arquitectura::X86_64,
            entradas: &v,
            importadas: &Got(got.clone()),
            datos: &imagen,
        };
        analizar(&e, plazo)
    };
    let primero = analizar_con(&entradas, &mut plazo);
    // Direcciones tomadas en el codigo, que solo se ven tras desensamblar.
    for i in primero.cfg.instrucciones() {
        for v in i.valor_definido.iter().chain(i.inmediatos.iter()) {
            if en_codigo(*v) {
                tomadas.insert(*v);
            }
        }
    }
    let nuevas: BTreeSet<u64> = tomadas.difference(&entradas).copied().collect();
    let a = if nuevas.is_empty() {
        primero
    } else {
        let mut todas = entradas.clone();
        todas.extend(nuevas);
        analizar_con(&todas, &mut plazo)
    };

    // Las raices: la entrada, lo tomado y, en una biblioteca, lo exportado.
    let mut raices: BTreeSet<u64> = tomadas;
    raices.insert(elf.header.e_entry);
    if es_biblioteca {
        raices.extend(exportadas);
    }
    let mut incompleto =
        a.llamadas.cortado || plazo.agotado_por_tiempo() || plazo.agotado_por_tope();
    if raices.len() > MAX_RAICES {
        incompleto = true;
    }

    // Recorrido del grafo de llamadas.
    let mut alcanzables: BTreeSet<u64> = BTreeSet::new();
    let mut cola: VecDeque<u64> = raices
        .iter()
        .copied()
        .filter(|r| a.llamadas.funcion(*r).is_some())
        .collect();
    while let Some(f) = cola.pop_front() {
        if !alcanzables.insert(f) {
            continue;
        }
        if let Some(func) = a.llamadas.funcion(f) {
            for d in &func.llama_a {
                if !alcanzables.contains(d) {
                    cola.push_back(*d);
                }
            }
        }
    }

    // Que funcion contiene cada llamada a una importada.
    let mut bloque_a_funciones: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for f in a.llamadas.funciones() {
        for b in &f.bloques {
            bloque_a_funciones.entry(*b).or_default().push(f.entrada);
        }
    }
    let mut llamadas_a_importadas: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for r in &a.importaciones.resoluciones {
        let (Forma::PorTabla, Some(n)) = (r.forma, r.nombre.as_ref()) else {
            continue;
        };
        let Some(b) = a.cfg.bloque_que_contiene(r.donde) else {
            continue;
        };
        for f in bloque_a_funciones.get(&b.inicio).into_iter().flatten() {
            llamadas_a_importadas
                .entry(n.clone())
                .or_default()
                .insert(*f);
        }
    }

    Ok(Grafo {
        raices: raices.len(),
        frase: a.llamadas.frase(),
        alcanzables,
        llamadas_a_importadas,
        importadas,
        simbolos,
        con_simbolos,
        incompleto,
    })
}

/// Respuesta de una consulta sobre el grafo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Respuesta {
    /// Hay camino. Lleva la evidencia.
    Si(String),
    /// No hay camino, y el analisis estaba completo. Lleva el porque.
    No(String),
    /// No se puede afirmar ninguna de las dos cosas. Lleva el motivo.
    NoSe(String),
    /// El binario no importa esa funcion ni la contiene con nombre: la
    /// pregunta es de otro modulo.
    NoEsDeEsteBinario,
}

impl Grafo {
    /// ¿Se llama a la funcion importada `nombre` desde codigo alcanzable?
    ///
    /// Los simbolos versionados (`inflate@ZLIB_1.2.0`) se comparan sin version.
    #[must_use]
    pub fn alcanza_importada(&self, nombre: &str) -> Respuesta {
        let base = |n: &str| n.split('@').next().unwrap_or(n).to_string();
        let nombre = base(nombre);
        if !self.importadas.iter().any(|i| base(i) == nombre) {
            return Respuesta::NoEsDeEsteBinario;
        }
        let sitios: BTreeSet<u64> = self
            .llamadas_a_importadas
            .iter()
            .filter(|(n, _)| base(n) == nombre)
            .flat_map(|(_, f)| f.iter().copied())
            .collect();
        if sitios.is_empty() {
            return Respuesta::NoSe(format!(
                "{nombre} se importa pero no se vio ninguna llamada a traves de su entrada de la \
                 tabla: se puede estar usando por puntero"
            ));
        }
        if let Some(f) = sitios.iter().find(|f| self.alcanzables.contains(f)) {
            return Respuesta::Si(format!(
                "se llama a {nombre} desde la funcion {f:#x}, a la que se llega desde una raiz \
                 del programa ({})",
                self.frase
            ));
        }
        if self.incompleto {
            return Respuesta::NoSe(
                "el analisis se corto por sus topes: no haber llegado no es comprobar que no se \
                 llega"
                    .into(),
            );
        }
        Respuesta::No(format!(
            "{nombre} se llama desde {} funcion(es) y ninguna es alcanzable desde la entrada ni \
             desde las {} direcciones de funcion que el programa toma",
            sitios.len(),
            self.raices
        ))
    }

    /// ¿Es alcanzable la funcion interna `ruta` (`crate::modulo::funcion`)?
    #[must_use]
    pub fn alcanza_interna(&self, ruta: &str) -> Respuesta {
        if !self.con_simbolos {
            return Respuesta::NoSe(
                "el binario no trae tabla de simbolos: no se sabe donde esta la funcion".into(),
            );
        }
        let Some(dir) = self.simbolos.get(ruta) else {
            // Con simbolos y sin esta funcion puede ser que no se enlazo... o que
            // el compilador la inlinizo dentro de quien la llama. No se distingue.
            return Respuesta::NoSe(format!(
                "{ruta} no esta en la tabla de simbolos: pudo no enlazarse o quedar inlinizada, \
                 y eso no se distingue"
            ));
        };
        if self.alcanzables.contains(dir) {
            return Respuesta::Si(format!("{ruta} ({dir:#x}) se alcanza desde una raiz"));
        }
        if self.incompleto {
            return Respuesta::NoSe("el analisis se corto por sus topes".into());
        }
        Respuesta::No(format!(
            "{ruta} ({dir:#x}) esta en el binario y no se llega a ella desde ninguna de sus {} \
             raices",
            self.raices
        ))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn desenredado_de_rust_antiguo() {
        assert_eq!(
            desenredar_rust("_ZN8smallvec17SmallVec$LT$A$GT$11insert_many17h0123456789abcdefE")
                .as_deref(),
            Some("smallvec::SmallVec::insert_many")
        );
        assert_eq!(
            desenredar_rust("_ZN4core3fmt5write17h1111111111111111E").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(desenredar_rust("inflate"), None);
        assert_eq!(
            desenredar_rust("_ZN99E"),
            None,
            "longitud mayor que el resto"
        );
    }
}
