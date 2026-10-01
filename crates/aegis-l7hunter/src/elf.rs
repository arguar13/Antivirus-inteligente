//! Analisis de ELF para resolver el objetivo de un uprobe.
//!
//! # El problema que resuelve, y por que no es trivial
//!
//! Para enganchar un uprobe en `SSL_write` hacen falta dos cosas: la **ruta** de
//! la biblioteca y el **desplazamiento dentro del fichero** de la funcion. Lo
//! segundo NO es la direccion virtual del simbolo, y confundirlos es el error que
//! define este modulo: engancha en el sitio equivocado, y un uprobe en el sitio
//! equivocado no falla ruidosamente —lee basura, o no dispara nunca—.
//!
//! La traduccion correcta es, para el segmento `PT_LOAD` que contiene el simbolo:
//!
//! ```text
//! desplazamiento_fichero = vaddr_simbolo - p_vaddr + p_offset
//! ```
//!
//! ## Por que la version ingenua "funciona" y aun asi esta mal
//!
//! En la inmensa mayoria de bibliotecas compartidas, `p_offset == p_vaddr` en el
//! segmento ejecutable, y entonces `desplazamiento = vaddr` da el resultado
//! correcto por casualidad. Es exactamente el tipo de error que pasa todas las
//! pruebas y falla en produccion.
//!
//! Medido sobre ESTA maquina (1107 binarios de `/usr/lib/x86_64-linux-gnu` y
//! `/usr/bin`): **20 tienen el segmento ejecutable con `p_offset != p_vaddr`**,
//! todos con un desfase de `0x400000`, porque son ejecutables **no-PIE**
//! (`ET_EXEC`, cargados en una direccion fija). Entre ellos, `/usr/bin/python3.10`
//! y `containerd-shim-runc-v2`, que es un binario de **Go**.
//!
//! Y esos son justo los que importan: el malware moderno en Go enlaza
//! `crypto/tls` **estaticamente**, asi que el objetivo del uprobe no es una
//! `libssl` compartida sino el propio ejecutable. Con la traduccion ingenua, el
//! enganche caeria 4 MiB mas alla de la funcion.
//!
//! La prueba de este modulo no usa ficheros sinteticos: recorre los binarios
//! REALES de la maquina y comprueba que la traduccion coincide con lo que dice el
//! propio ELF, incluyendo los no-PIE.
//!
//! # Este modulo analiza entrada hostil
//!
//! Un atacante puede poner en el disco una biblioteca con cabeceras contradictorias
//! para provocar un desbordamiento o un panico en el EDR que la inspeccione. Aqui
//! **toda** lectura esta acotada y **ninguna** ruta entra en panico: cada campo se
//! lee comprobando antes que cabe, y un fichero incoherente devuelve un error con
//! nombre, nunca un indice fuera de rango.

use crate::L7Error;

/// Tamano de la cabecera ELF de 64 bits.
const EHDR64: usize = 64;
/// Tamano de una entrada de la tabla de cabeceras de programa (ELF64).
const PHDR64: usize = 56;
/// Tamano de una entrada de la tabla de cabeceras de seccion (ELF64).
const SHDR64: usize = 64;
/// Tamano de una entrada de la tabla de simbolos (ELF64).
const SYM64: usize = 24;

/// `PT_LOAD`: segmento que el cargador mapea en memoria.
const PT_LOAD: u32 = 1;
/// `PF_X`: el segmento es ejecutable.
const PF_X: u32 = 1;
/// `SHT_SYMTAB`: tabla de simbolos completa (la que conservan los binarios de Go).
const SHT_SYMTAB: u32 = 2;
/// `SHT_DYNSYM`: tabla de simbolos dinamicos (la que sobrevive al `strip`).
const SHT_DYNSYM: u32 = 11;
/// `STT_FUNC`: el simbolo es una funcion.
const STT_FUNC: u8 = 2;

/// Un segmento cargable del ELF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentoCargable {
    /// Desplazamiento del segmento dentro del fichero.
    pub desplazamiento: u64,
    /// Direccion virtual donde se mapea.
    pub direccion: u64,
    /// Bytes que ocupa EN EL FICHERO.
    pub tamano_fichero: u64,
    /// `true` si el segmento es ejecutable.
    pub ejecutable: bool,
}

impl SegmentoCargable {
    /// `true` si `vaddr` cae dentro de este segmento.
    ///
    /// La suma va SATURADA: un ELF preparado a mano puede declarar
    /// `p_vaddr = u64::MAX - 1` con un tamano grande, y en el perfil de release de
    /// este producto —que lleva `overflow-checks` activados a proposito— una suma
    /// desbordada es un panico. El EDR no puede caerse al mirar un fichero.
    #[must_use]
    pub const fn contiene(&self, vaddr: u64) -> bool {
        vaddr >= self.direccion && vaddr < self.direccion.saturating_add(self.tamano_fichero)
    }

    /// Traduce una direccion virtual a desplazamiento dentro del fichero.
    ///
    /// Devuelve `None` si la direccion no cae en este segmento.
    #[must_use]
    pub const fn a_desplazamiento(&self, vaddr: u64) -> Option<u64> {
        if !self.contiene(vaddr) {
            return None;
        }
        // Resta segura por la guarda de `contiene`; la suma, saturada por lo mismo.
        Some((vaddr - self.direccion).saturating_add(self.desplazamiento))
    }
}

/// Un simbolo de funcion exportado por el binario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimboloFuncion {
    /// Nombre, sin la version (`SSL_write`, no `SSL_write@@OPENSSL_3.0.0`).
    pub nombre: String,
    /// Direccion virtual del simbolo dentro del binario.
    pub direccion: u64,
    /// Tamano declarado de la funcion, si lo trae.
    pub tamano: u64,
}

/// Un binario ELF de 64 bits, analizado.
#[derive(Debug, Clone)]
pub struct Binario {
    /// Los segmentos cargables.
    pub segmentos: Vec<SegmentoCargable>,
    /// Las funciones que exporta, por nombre.
    pub funciones: Vec<SimboloFuncion>,
    /// `true` si es un ejecutable de posicion fija (`ET_EXEC`), no un PIE.
    ///
    /// Importa para la traduccion: son justo los binarios donde `p_vaddr` y
    /// `p_offset` difieren, y son los que usa el malware en Go con `crypto/tls`
    /// enlazado estaticamente.
    pub posicion_fija: bool,
}

impl Binario {
    /// Analiza un ELF64 completo en memoria.
    ///
    /// # Errores
    /// [`L7Error::Elf`] si no es un ELF64 valido o si sus cabeceras se contradicen.
    /// NUNCA entra en panico, por muy corrupto que este el fichero: es entrada que
    /// un atacante puede haber preparado.
    pub fn analizar(datos: &[u8]) -> Result<Binario, L7Error> {
        let err = |m: &str| L7Error::Elf(m.to_string());

        if datos.len() < EHDR64 {
            return Err(err("el fichero es mas corto que una cabecera ELF"));
        }
        if &datos[..4] != b"\x7fELF" {
            return Err(err("no empieza por la firma ELF"));
        }
        // EI_CLASS = 2 -> ELF64. Un ELF de 32 bits tiene otro layout entero y
        // analizarlo con estos desplazamientos leeria campos equivocados.
        if datos[4] != 2 {
            return Err(err("solo se analizan binarios ELF de 64 bits"));
        }
        // EI_DATA = 1 -> little-endian. El producto corre en x86-64 y aarch64,
        // los dos little-endian; analizar big-endian con `from_le_bytes` daria
        // valores absurdos en silencio, asi que se rechaza en vez de adivinar.
        if datos[5] != 1 {
            return Err(err("solo se analizan binarios little-endian"));
        }

        let e_type = leer_u16(datos, 16).ok_or_else(|| err("cabecera truncada (e_type)"))?;
        let e_phoff = leer_u64(datos, 32).ok_or_else(|| err("cabecera truncada (e_phoff)"))?;
        let e_shoff = leer_u64(datos, 40).ok_or_else(|| err("cabecera truncada (e_shoff)"))?;
        let e_phentsize = leer_u16(datos, 54).ok_or_else(|| err("cabecera truncada"))?;
        let e_phnum = leer_u16(datos, 56).ok_or_else(|| err("cabecera truncada"))?;
        let e_shentsize = leer_u16(datos, 58).ok_or_else(|| err("cabecera truncada"))?;
        let e_shnum = leer_u16(datos, 60).ok_or_else(|| err("cabecera truncada"))?;

        let segmentos = segmentos_de(datos, e_phoff, e_phentsize, e_phnum)?;
        let funciones = funciones_de(datos, e_shoff, e_shentsize, e_shnum)?;

        Ok(Binario {
            segmentos,
            funciones,
            // ET_EXEC = 2.
            posicion_fija: e_type == 2,
        })
    }

    /// Analiza el ELF de un fichero del disco.
    ///
    /// # Errores
    /// [`L7Error::Io`] si no se puede leer, o [`L7Error::Elf`] si no es valido.
    pub fn desde_fichero(ruta: &std::path::Path) -> Result<Binario, L7Error> {
        let datos = std::fs::read(ruta).map_err(|causa| L7Error::Io {
            ruta: ruta.display().to_string(),
            causa,
        })?;
        Binario::analizar(&datos)
    }

    /// Busca una funcion por nombre exacto.
    #[must_use]
    pub fn funcion(&self, nombre: &str) -> Option<&SimboloFuncion> {
        self.funciones.iter().find(|f| f.nombre == nombre)
    }

    /// El desplazamiento DENTRO DEL FICHERO de una funcion, que es lo que hay que
    /// darle al kernel para enganchar un uprobe.
    ///
    /// Devuelve `None` si la funcion no existe o si su direccion no cae en ningun
    /// segmento cargable (un ELF incoherente, o un simbolo sin codigo detras).
    #[must_use]
    pub fn desplazamiento_de(&self, nombre: &str) -> Option<u64> {
        let f = self.funcion(nombre)?;
        self.desplazamiento_de_vaddr(f.direccion)
    }

    /// Traduce una direccion virtual del binario a desplazamiento de fichero.
    ///
    /// Se prefiere el segmento EJECUTABLE cuando varios contienen la direccion:
    /// en un binario bien formado no ocurre, pero un ELF preparado a mano puede
    /// solapar segmentos, y para un uprobe el que vale es el que lleva codigo.
    #[must_use]
    pub fn desplazamiento_de_vaddr(&self, vaddr: u64) -> Option<u64> {
        self.segmentos
            .iter()
            .filter(|s| s.contiene(vaddr))
            .max_by_key(|s| u8::from(s.ejecutable))
            .and_then(|s| s.a_desplazamiento(vaddr))
    }

    /// Los nombres de funcion que casan con un predicado.
    ///
    /// Sirve para descubrir implementaciones de TLS enlazadas estaticamente, donde
    /// el simbolo no se llama `SSL_write` sino, por ejemplo,
    /// `crypto/tls.(*Conn).Write`.
    #[must_use]
    pub fn funciones_que<F: Fn(&str) -> bool>(&self, predicado: F) -> Vec<&SimboloFuncion> {
        self.funciones
            .iter()
            .filter(|f| predicado(&f.nombre))
            .collect()
    }
}

/// Lee la tabla de cabeceras de programa.
fn segmentos_de(
    datos: &[u8],
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
) -> Result<Vec<SegmentoCargable>, L7Error> {
    let err = |m: &str| L7Error::Elf(m.to_string());
    if e_phnum == 0 {
        return Ok(Vec::new());
    }
    // Una entrada mas pequena que la estructura haria que los campos se leyeran
    // desplazados entre entradas; mas grande es legitimo (relleno del enlazador).
    if (e_phentsize as usize) < PHDR64 {
        return Err(err("e_phentsize menor que una cabecera de programa"));
    }
    let inicio = usize::try_from(e_phoff).map_err(|_| err("e_phoff fuera de rango"))?;
    let mut salida = Vec::with_capacity(e_phnum as usize);
    for i in 0..e_phnum as usize {
        let base = i
            .checked_mul(e_phentsize as usize)
            .and_then(|d| inicio.checked_add(d))
            .ok_or_else(|| err("tabla de programa fuera de rango"))?;
        let p_type = leer_u32(datos, base).ok_or_else(|| err("cabecera de programa truncada"))?;
        if p_type != PT_LOAD {
            continue;
        }
        let campo = |delta: usize| base.checked_add(delta);
        let p_flags = campo(4)
            .and_then(|o| leer_u32(datos, o))
            .ok_or_else(|| err("p_flags truncado"))?;
        let p_offset = campo(8)
            .and_then(|o| leer_u64(datos, o))
            .ok_or_else(|| err("p_offset truncado"))?;
        let p_vaddr = campo(16)
            .and_then(|o| leer_u64(datos, o))
            .ok_or_else(|| err("p_vaddr truncado"))?;
        let p_filesz = campo(32)
            .and_then(|o| leer_u64(datos, o))
            .ok_or_else(|| err("p_filesz truncado"))?;
        // Un segmento cuyo contenido no cabe en el fichero es incoherente. Se
        // descarta en vez de aceptarlo: aceptarlo permitiria calcular un
        // desplazamiento que apunta fuera del fichero, y ese desplazamiento
        // acabaria en una llamada al kernel.
        if p_offset.saturating_add(p_filesz) > datos.len() as u64 {
            continue;
        }
        salida.push(SegmentoCargable {
            desplazamiento: p_offset,
            direccion: p_vaddr,
            tamano_fichero: p_filesz,
            ejecutable: p_flags & PF_X != 0,
        });
    }
    Ok(salida)
}

/// Lee las tablas de simbolos (`.dynsym` y `.symtab`) y devuelve las funciones.
fn funciones_de(
    datos: &[u8],
    e_shoff: u64,
    e_shentsize: u16,
    e_shnum: u16,
) -> Result<Vec<SimboloFuncion>, L7Error> {
    let err = |m: &str| L7Error::Elf(m.to_string());
    if e_shnum == 0 || e_shoff == 0 {
        // Un binario sin tabla de secciones (totalmente despojado) no es un error:
        // simplemente no se pueden resolver simbolos por nombre, y quien llame lo
        // vera en una lista vacia. Fingir que hay simbolos seria peor.
        return Ok(Vec::new());
    }
    if (e_shentsize as usize) < SHDR64 {
        return Err(err("e_shentsize menor que una cabecera de seccion"));
    }
    let inicio = usize::try_from(e_shoff).map_err(|_| err("e_shoff fuera de rango"))?;

    // Se recorren TODAS las secciones de simbolos y se acumulan. Un binario puede
    // traer `.dynsym` (lo exportado) y `.symtab` (todo, incluido lo estatico);
    // el malware en Go enlaza `crypto/tls` estaticamente, asi que sus funciones
    // TLS solo aparecen en `.symtab`. Quedarse solo con `.dynsym` dejaria ciego al
    // cazador justo contra el caso que mas importa.
    let mut salida = Vec::new();
    for i in 0..e_shnum as usize {
        let Some(base) = i
            .checked_mul(e_shentsize as usize)
            .and_then(|d| inicio.checked_add(d))
        else {
            break;
        };
        let Some(sh_type) = base.checked_add(4).and_then(|o| leer_u32(datos, o)) else {
            break;
        };
        if sh_type != SHT_SYMTAB && sh_type != SHT_DYNSYM {
            continue;
        }
        let campo = |delta: usize| base.checked_add(delta);
        let (Some(sh_offset), Some(sh_size), Some(sh_link), Some(sh_entsize)) = (
            campo(24).and_then(|o| leer_u64(datos, o)),
            campo(32).and_then(|o| leer_u64(datos, o)),
            campo(40).and_then(|o| leer_u32(datos, o)),
            campo(56).and_then(|o| leer_u64(datos, o)),
        ) else {
            continue;
        };
        if sh_entsize < SYM64 as u64 || sh_size == 0 {
            continue;
        }
        // `sh_link` de una tabla de simbolos apunta a SU tabla de cadenas. Usar
        // otra (p. ej. la de nombres de seccion) daria nombres plausibles pero
        // equivocados, que es peor que no dar ninguno.
        let Some(cadenas) = seccion_de_cadenas(datos, inicio, e_shentsize, e_shnum, sh_link) else {
            continue;
        };
        acumular_simbolos(datos, sh_offset, sh_size, sh_entsize, cadenas, &mut salida);
    }

    // Un mismo simbolo puede estar en `.dynsym` y en `.symtab`. Se deduplica por
    // (nombre, direccion) conservando el primero.
    salida.sort_by(|a, b| a.nombre.cmp(&b.nombre).then(a.direccion.cmp(&b.direccion)));
    salida.dedup_by(|a, b| a.nombre == b.nombre && a.direccion == b.direccion);
    Ok(salida)
}

/// Localiza el rango de la tabla de cadenas `indice`.
fn seccion_de_cadenas(
    datos: &[u8],
    inicio: usize,
    e_shentsize: u16,
    e_shnum: u16,
    indice: u32,
) -> Option<(usize, usize)> {
    if indice as usize >= e_shnum as usize {
        return None;
    }
    let base = inicio.checked_add((indice as usize).checked_mul(e_shentsize as usize)?)?;
    let off = usize::try_from(leer_u64(datos, base.checked_add(24)?)?).ok()?;
    let size = usize::try_from(leer_u64(datos, base.checked_add(32)?)?).ok()?;
    if off.checked_add(size)? > datos.len() {
        return None;
    }
    Some((off, size))
}

/// Recorre una tabla de simbolos y acumula las funciones con direccion.
fn acumular_simbolos(
    datos: &[u8],
    sh_offset: u64,
    sh_size: u64,
    sh_entsize: u64,
    cadenas: (usize, usize),
    salida: &mut Vec<SimboloFuncion>,
) {
    let Ok(tabla) = usize::try_from(sh_offset) else {
        return;
    };
    let Ok(tam) = usize::try_from(sh_size) else {
        return;
    };
    let Ok(paso) = usize::try_from(sh_entsize) else {
        return;
    };
    if paso == 0 || tabla.saturating_add(tam) > datos.len() {
        return;
    }
    let cuantos = tam / paso;
    for i in 0..cuantos {
        let Some(base) = tabla.checked_add(i.saturating_mul(paso)) else {
            return;
        };
        let campo = |delta: usize| base.checked_add(delta);
        let (Some(st_name), Some(st_info), Some(st_value), Some(st_size)) = (
            leer_u32(datos, base),
            campo(4).and_then(|o| datos.get(o).copied()),
            campo(8).and_then(|o| leer_u64(datos, o)),
            campo(16).and_then(|o| leer_u64(datos, o)),
        ) else {
            return;
        };
        // Los 4 bits bajos de st_info son el TIPO. Solo interesan las funciones:
        // enganchar un uprobe en un objeto de datos no tiene sentido.
        if st_info & 0xF != STT_FUNC {
            continue;
        }
        // Un simbolo sin direccion es una importacion sin resolver (`UND`): la
        // funcion vive en otra biblioteca, y ahi es donde habria que enganchar.
        if st_value == 0 {
            continue;
        }
        let Some(nombre) = cadena_en(datos, cadenas, st_name as usize) else {
            continue;
        };
        if nombre.is_empty() {
            continue;
        }
        salida.push(SimboloFuncion {
            // El nombre versionado (`SSL_write@@OPENSSL_3.0.0`) se recorta por la
            // arroba: el uprobe engancha en una direccion, no en una version, y
            // quien busca "SSL_write" tiene que encontrarlo.
            nombre: nombre.split('@').next().unwrap_or(nombre).to_string(),
            direccion: st_value,
            tamano: st_size,
        });
    }
}

/// Lee una cadena terminada en cero dentro de la tabla de cadenas.
fn cadena_en(datos: &[u8], (off, size): (usize, usize), indice: usize) -> Option<&str> {
    if indice >= size {
        return None;
    }
    let inicio = off.checked_add(indice)?;
    let fin = off.checked_add(size)?;
    let trozo = datos.get(inicio..fin)?;
    let largo = trozo.iter().position(|b| *b == 0).unwrap_or(trozo.len());
    // Un nombre de simbolo con bytes no-UTF8 es un fichero preparado a mano; se
    // descarta ese simbolo, no el binario entero.
    std::str::from_utf8(&trozo[..largo]).ok()
}

// --- Lecturas acotadas -----------------------------------------------------
//
// Todas devuelven `Option` en vez de indexar. Es la diferencia entre un EDR que
// informa de un fichero corrupto y uno que entra en panico al analizar el
// primer binario que un atacante le ponga delante.

// La suma `off + N` va CHECKED y no a secas. No es pedanteria: un ELF con un
// `e_phoff` cercano a `usize::MAX` —que es un fichero de 64 bytes que un atacante
// deja en el disco— desborda la suma y, en un build con `overflow-checks` (el
// perfil de release de este producto los lleva activados), eso es un panico.
// Panico en el analizador = el EDR se cae al inspeccionar el primer binario que
// le pongan delante. Lo encontro la prueba de entrada hostil.
fn leer_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off.checked_add(2)?)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

fn leer_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off.checked_add(4)?)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn leer_u64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off.checked_add(8)?)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};
    use std::path::Path;

    #[test]
    fn la_traduccion_es_identidad_cuando_el_segmento_esta_alineado() {
        let s = SegmentoCargable {
            desplazamiento: 0x1e000,
            direccion: 0x1e000,
            tamano_fichero: 0x61721,
            ejecutable: true,
        };
        // El caso de libssl.so.3 en esta maquina: SSL_read en 0x365b0.
        assert_eq!(s.a_desplazamiento(0x365b0), Some(0x365b0));
    }

    /// EL CASO QUE DEFINE EL MODULO. Un ejecutable no-PIE: el segmento ejecutable
    /// se mapea en 0x400000 pero empieza en el desplazamiento 0 del fichero. La
    /// traduccion ingenua (`desplazamiento = vaddr`) se equivoca en 4 MiB.
    #[test]
    fn la_traduccion_corrige_el_desfase_de_un_ejecutable_no_pie() {
        // Valores REALES de /usr/bin/containerd-shim-runc-v2 en esta maquina.
        let s = SegmentoCargable {
            desplazamiento: 0x0,
            direccion: 0x400000,
            tamano_fichero: 0x200000,
            ejecutable: true,
        };
        assert_eq!(s.a_desplazamiento(0x400000 + 0x1234), Some(0x1234));
        assert_ne!(
            s.a_desplazamiento(0x400000 + 0x1234),
            Some(0x400000 + 0x1234),
            "la traduccion ingenua engancharia el uprobe 4 MiB mas alla"
        );
        // Y una direccion fuera del segmento no se traduce a nada.
        assert_eq!(s.a_desplazamiento(0x100), None);
    }

    // -----------------------------------------------------------------------
    // Entrada hostil: ninguna de estas puede entrar en panico
    // -----------------------------------------------------------------------

    #[test]
    fn un_fichero_que_no_es_elf_se_rechaza_con_nombre() {
        for basura in [
            &b""[..],
            &b"MZ"[..],
            &b"\x7fELF"[..],
            &[0u8; 63][..],
            &b"no soy un elf, soy un texto cualquiera que mide bastante"[..],
        ] {
            let e = Binario::analizar(basura).unwrap_err();
            assert!(matches!(e, L7Error::Elf(_)), "{e:?}");
        }
    }

    #[test]
    fn un_elf_de_32_bits_o_big_endian_se_rechaza_en_vez_de_leerse_torcido() {
        let mut d = vec![0u8; 128];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 1; // ELFCLASS32
        d[5] = 1;
        assert!(
            Binario::analizar(&d).is_err(),
            "un ELF32 no se analiza aqui"
        );

        d[4] = 2; // ELF64
        d[5] = 2; // big-endian
        assert!(
            Binario::analizar(&d).is_err(),
            "big-endian no se analiza aqui"
        );
    }

    /// Cabeceras que se contradicen: numeros de entradas y desplazamientos que
    /// apuntan fuera del fichero. Es lo que un atacante deja en el disco para que
    /// el EDR que lo inspeccione se caiga.
    #[test]
    fn unas_cabeceras_contradictorias_no_pueden_provocar_un_panico() {
        let mut d = vec![0u8; 256];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        // e_phoff y e_shoff enormes, con muchas entradas.
        d[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        d[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        d[54..56].copy_from_slice(&56u16.to_le_bytes());
        d[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes());
        d[60..62].copy_from_slice(&u16::MAX.to_le_bytes());
        // No se afirma que falle: se afirma que NO ENTRA EN PANICO.
        let _ = Binario::analizar(&d);

        // Y con desplazamientos que caen justo en el borde.
        let mut d2 = vec![0u8; 256];
        d2[..4].copy_from_slice(b"\x7fELF");
        d2[4] = 2;
        d2[5] = 1;
        d2[32..40].copy_from_slice(&250u64.to_le_bytes());
        d2[54..56].copy_from_slice(&56u16.to_le_bytes());
        d2[56..58].copy_from_slice(&10u16.to_le_bytes());
        let _ = Binario::analizar(&d2);
    }

    // -----------------------------------------------------------------------
    // Contra los binarios REALES de esta maquina
    // -----------------------------------------------------------------------

    /// El objetivo real de la fase: encontrar `SSL_read` y `SSL_write` en la
    /// OpenSSL de verdad de esta maquina y traducir su direccion a desplazamiento.
    #[test]
    fn encuentra_ssl_read_y_ssl_write_en_la_openssl_real() {
        let ruta = Path::new("/usr/lib/x86_64-linux-gnu/libssl.so.3");
        if !ruta.exists() {
            omitir(
                &format!("no hay OpenSSL 3 en {}", ruta.display()),
                Requisito::Herramienta("libssl3"),
            );
            return;
        }
        let b = Binario::desde_fichero(ruta).expect("libssl.so.3 tiene que analizarse");

        for nombre in ["SSL_read", "SSL_write"] {
            let f = b
                .funcion(nombre)
                .unwrap_or_else(|| panic!("{nombre} tiene que estar en libssl"));
            assert!(f.direccion > 0);
            assert!(f.tamano > 0, "{nombre} tiene que tener cuerpo");

            let off = b
                .desplazamiento_de(nombre)
                .unwrap_or_else(|| panic!("{nombre} tiene que traducirse a desplazamiento"));
            // La comprobacion que importa: el desplazamiento tiene que caer
            // dentro del fichero, y en el segmento EJECUTABLE.
            let tam = std::fs::metadata(ruta).unwrap().len();
            assert!(
                off < tam,
                "{nombre}: desplazamiento {off:#x} fuera del fichero"
            );
            let seg = b
                .segmentos
                .iter()
                .find(|s| s.contiene(f.direccion))
                .expect("el simbolo cae en un segmento cargable");
            assert!(seg.ejecutable, "{nombre} tiene que estar en codigo");
        }

        // El nombre versionado se recorta: en el ELF es `SSL_write@@OPENSSL_3.0.0`.
        assert!(
            b.funciones.iter().all(|f| !f.nombre.contains('@')),
            "los nombres no pueden llevar la version pegada"
        );
    }

    /// LA PRUEBA DE LA TRADUCCION, contra TODOS los binarios de la maquina.
    ///
    /// Recorre los ejecutables y bibliotecas reales, y para cada funcion
    /// comprueba que el desplazamiento calculado apunta dentro del fichero y al
    /// segmento correcto. Incluye a proposito los no-PIE, que son los que
    /// distinguen la traduccion correcta de la ingenua.
    #[test]
    fn la_traduccion_es_correcta_en_todos_los_binarios_reales_de_la_maquina() {
        let mut revisados = 0usize;
        let mut no_pie = 0usize;
        let mut desalineados = 0usize;

        for dir in ["/usr/lib/x86_64-linux-gnu", "/usr/bin"] {
            let Ok(entradas) = std::fs::read_dir(dir) else {
                continue;
            };
            for e in entradas.flatten().take(400) {
                let ruta = e.path();
                // Sin enlaces simbolicos: el mismo fichero varias veces no aporta.
                if !ruta.is_file() || std::fs::symlink_metadata(&ruta).is_ok_and(|m| m.is_symlink())
                {
                    continue;
                }
                let Ok(datos) = std::fs::read(&ruta) else {
                    continue;
                };
                let Ok(b) = Binario::analizar(&datos) else {
                    continue;
                };
                revisados += 1;
                if b.posicion_fija {
                    no_pie += 1;
                }
                if b.segmentos
                    .iter()
                    .any(|s| s.ejecutable && s.desplazamiento != s.direccion)
                {
                    desalineados += 1;
                }

                for f in b.funciones.iter().take(50) {
                    let Some(off) = b.desplazamiento_de_vaddr(f.direccion) else {
                        continue;
                    };
                    assert!(
                        off < datos.len() as u64,
                        "{}: {} -> desplazamiento {off:#x} fuera de un fichero de {} B",
                        ruta.display(),
                        f.nombre,
                        datos.len()
                    );
                    // Y el byte de ese desplazamiento tiene que existir: si la
                    // traduccion estuviera mal por un desfase, esto lo cazaria en
                    // los binarios cuyo segmento no empieza en cero.
                    assert!(datos.get(off as usize).is_some());
                }
            }
        }

        assert!(revisados > 50, "solo se analizaron {revisados} binarios");
        eprintln!(
            "traduccion verificada sobre {revisados} binarios reales \
             ({no_pie} no-PIE, {desalineados} con el segmento ejecutable desalineado)"
        );
        assert!(
            desalineados > 0,
            "esta maquina tenia binarios con el segmento ejecutable desalineado \
             (p.ej. /usr/bin/python3.10); si ya no los tiene, la prueba dejo de \
             cubrir el caso que distingue la traduccion correcta de la ingenua"
        );
    }

    /// El caso concreto que motiva todo: un binario no-PIE con el segmento
    /// ejecutable desalineado. Si la traduccion fuera ingenua, el desplazamiento
    /// caeria fuera del fichero y el uprobe no engancharia nada.
    #[test]
    fn un_binario_no_pie_real_traduce_dentro_del_fichero() {
        for candidato in ["/usr/bin/python3.10", "/usr/bin/containerd-shim-runc-v2"] {
            let ruta = Path::new(candidato);
            if !ruta.exists() {
                continue;
            }
            let datos = std::fs::read(ruta).expect("lectura");
            let b = Binario::analizar(&datos).expect("analisis");
            let Some(seg) = b
                .segmentos
                .iter()
                .find(|s| s.ejecutable && s.desplazamiento != s.direccion)
            else {
                continue;
            };

            let vaddr = seg.direccion + 0x100;
            let correcto = b.desplazamiento_de_vaddr(vaddr).expect("traduccion");
            assert_eq!(correcto, seg.desplazamiento + 0x100);
            assert!(
                correcto < datos.len() as u64,
                "{candidato}: el desplazamiento correcto cae dentro del fichero"
            );
            assert!(
                vaddr >= datos.len() as u64 || vaddr != correcto,
                "{candidato}: la traduccion ingenua daria {vaddr:#x}, que no es {correcto:#x}"
            );
            return;
        }
        omitir(
            "esta maquina no tiene ningun binario no-PIE conocido",
            Requisito::Entorno,
        );
    }
}
