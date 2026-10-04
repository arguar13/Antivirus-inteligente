//! A que funciones del sistema llama un binario, y **como** lo averigua el.
//!
//! # Las dos preguntas, y por que la segunda importa mas
//!
//! La primera es «a que APIs llama». Se responde con la tabla de importaciones
//! del contenedor —quien la lee es `aegis-pe`, `aegis-macho` o el lector de ELF,
//! no este crate— y aqui solo se cruza con las direcciones que aparecen en el
//! codigo.
//!
//! La segunda es «**como** consigue esas direcciones», y es la que separa un
//! programa de un implante. Un programa normal deja que el cargador rellene su
//! tabla de importaciones. Quien no quiere que su tabla diga lo que hace tiene
//! que buscarse las direcciones en ejecucion, y solo hay dos formas de hacerlo:
//!
//! 1. **Recorrer las estructuras del cargador.** En Windows, `gs:[0x60]` en 64
//!    bits o `fs:[0x30]` en 32 llevan al bloque de entorno del proceso, de ahi a
//!    la lista de modulos cargados y de ahi a las tablas de exportacion.
//! 2. **Buscar por hash del nombre** en vez de por el nombre, para que la cadena
//!    `VirtualAlloc` no aparezca en el fichero.
//!
//! Las dos dejan rastro en el codigo, y ese rastro es lo que este modulo
//! reconoce. Un binario con una tabla de importaciones de tres entradas y un
//! recorrido del bloque de entorno **no** es un binario que importe tres cosas.
//!
//! # Lo que este modulo NO hace
//!
//! No dice a que API concreta se resuelve un hash. Para eso haria falta el
//! diccionario de nombres exportados de las bibliotecas de la maquina objetivo,
//! que no es algo que el desensamblador tenga, y adivinarlo produciria nombres
//! inventados con aspecto de hechos. Lo que se declara es lo que se ve: que hay
//! una resolucion por hash, con que algoritmo y desde donde.

use std::collections::BTreeMap;

use crate::cfg::Cfg;
use crate::instruccion::{Arquitectura, Clase, Instruccion, Segmento};

/// Lo que el contenedor sabe de las direcciones importadas.
///
/// Es un rasgo para que el desensamblador no tenga que saber si el binario es
/// PE, ELF o Mach-O: los tres tienen tabla de importaciones y los tres la
/// escriben distinta.
pub trait Importadas {
    /// El nombre de la funcion importada cuya entrada esta en `direccion`, si
    /// esa direccion es una entrada de la tabla.
    fn nombre_en(&self, direccion: u64) -> Option<&str>;
}

/// Una tabla vacia, para analizar codigo suelto sin contenedor.
///
/// Con ella no se resuelve ningun nombre, y las llamadas por memoria salen como
/// lo que son: sin nombre. Existe para que la diferencia entre «no habia tabla»
/// y «la tabla no tenia esa direccion» este en el codigo y no en un `Option`
/// que alguien interprete a su manera.
#[derive(Debug, Clone, Copy, Default)]
pub struct SinTabla;

impl Importadas for SinTabla {
    fn nombre_en(&self, _: u64) -> Option<&str> {
        None
    }
}

/// Como consigue el binario la direccion de una funcion del sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Forma {
    /// Por la tabla de importaciones, que es lo normal.
    PorTabla,
    /// Recorriendo las estructuras del cargador.
    PorEstructurasDelCargador,
    /// Buscando por hash del nombre.
    PorHashDelNombre,
}

impl Forma {
    /// La frase con la que esta forma aparece en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            Forma::PorTabla => {
                "por la tabla de importaciones, que es como lo hace un programa normal"
            }
            Forma::PorEstructurasDelCargador => {
                "recorriendo a mano las estructuras del cargador, que es como se llama a \
                 una funcion sin que aparezca en la tabla de importaciones"
            }
            Forma::PorHashDelNombre => {
                "buscando las funciones por un hash de su nombre, que es como se llama a \
                 una funcion sin que su nombre aparezca en el fichero"
            }
        }
    }
}

/// Una llamada al sistema resuelta, o el rastro de como se resuelve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolucion {
    /// Donde esta la instruccion que lo hace.
    pub donde: u64,
    /// Como.
    pub forma: Forma,
    /// El nombre, cuando se sabe.
    pub nombre: Option<String>,
    /// Lo que se vio exactamente, para que quien lea el informe lo pueda
    /// comprobar sin fiarse.
    pub porque: String,
}

/// Desplazamiento del bloque de entorno del proceso dentro del de hilo, en
/// Windows de 64 bits.
const PEB_EN_64: u64 = 0x60;

/// Lo mismo en 32 bits.
const PEB_EN_32: u64 = 0x30;

/// Las constantes que delatan un algoritmo de hash de nombres de API.
///
/// # Por que estas y no un detector generico de bucles
///
/// Un detector de «bucle que rota y suma» dispara con cualquier funcion de hash
/// —y las hay a montones, legitimas, en cualquier programa que use una tabla de
/// dispersion—. Estas constantes son las de los algoritmos que se usan **para
/// esto concretamente**, y las tres primeras son de dominio publico desde hace
/// veinte anos en el codigo que resuelve APIs sin tabla.
///
/// Cada una viene con el nombre del algoritmo para que la evidencia diga algo, y
/// no «se vio una constante rara».
const CONSTANTES_DE_HASH: &[(u64, &str)] = &[
    // El multiplicador de djb2, el hash mas usado en cargadores reflexivos.
    (33, "djb2"),
    (5381, "djb2 (valor inicial)"),
    // sdbm.
    (65599, "sdbm"),
    // El primo de FNV-1 de 32 bits y su desplazamiento inicial.
    (16_777_619, "FNV-1 de 32 bits"),
    (2_166_136_261, "FNV-1 de 32 bits (valor inicial)"),
    // El primo de FNV-1 de 64 bits.
    (1_099_511_628_211, "FNV-1 de 64 bits"),
    (
        14_695_981_039_346_656_037,
        "FNV-1 de 64 bits (valor inicial)",
    ),
    // El polinomio de CRC32, en su forma invertida, que es la que aparece en el
    // codigo.
    (0xEDB8_8320, "CRC32"),
    (0x04C1_1DB7, "CRC32 (forma directa)"),
];

/// La rotacion de 13 bits: el hash de nombres de API mas conocido que existe.
///
/// Va aparte de las constantes porque no se reconoce por una constante sino por
/// una instruccion concreta —una rotacion de exactamente 13— dentro de un bucle
/// que suma. Trece no es un desplazamiento que nadie elija por casualidad.
const ROTACION_DE_TRECE: u64 = 13;

/// Lo que se averiguo de como este binario llama al sistema.
#[derive(Debug, Clone, Default)]
pub struct Importaciones {
    /// Todo lo que se vio, en orden de direccion.
    pub resoluciones: Vec<Resolucion>,
}

impl Importaciones {
    /// Busca en el grafo las tres formas de resolver una llamada al sistema.
    pub fn buscar(cfg: &Cfg, tabla: &dyn Importadas, arq: Arquitectura) -> Importaciones {
        let mut v: Vec<Resolucion> = Vec::new();
        for b in cfg.bloques() {
            for (n, i) in b.instrucciones.iter().enumerate() {
                if let Some(r) = por_cargador(i, arq) {
                    v.push(r);
                }
                if let Some(r) = por_hash(i, &b.instrucciones[..n]) {
                    v.push(r);
                }
                if let Some(r) = por_tabla(i, tabla) {
                    v.push(r);
                }
            }
        }
        v.sort_by(|a, b| (a.donde, a.forma).cmp(&(b.donde, b.forma)));
        v.dedup();
        Importaciones { resoluciones: v }
    }

    /// Las formas distintas que se vieron, con cuantas veces cada una.
    pub fn formas(&self) -> BTreeMap<Forma, usize> {
        let mut m = BTreeMap::new();
        for r in &self.resoluciones {
            *m.entry(r.forma).or_insert(0) += 1;
        }
        m
    }

    /// Si el binario resuelve alguna llamada sin pasar por su tabla.
    ///
    /// Es la pregunta que de verdad importa: un binario que solo usa su tabla
    /// hace lo que su tabla dice, y uno que no, no.
    pub fn resuelve_a_escondidas(&self) -> bool {
        self.resoluciones.iter().any(|r| r.forma != Forma::PorTabla)
    }

    /// Los nombres de funcion que se pudieron poner a una llamada.
    pub fn nombres(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .resoluciones
            .iter()
            .filter_map(|r| r.nombre.as_deref())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Reconoce el recorrido de las estructuras del cargador.
///
/// El rastro es un acceso a memoria por `FS` o `GS` con el desplazamiento del
/// bloque de entorno. Se exige **el segmento y el desplazamiento**, no uno solo
/// de los dos: en Linux de 64 bits `gs` se usa para los datos locales del hilo y
/// lo toca cualquier programa, asi que el segmento por si solo no dice nada.
fn por_cargador(i: &Instruccion, arq: Arquitectura) -> Option<Resolucion> {
    let seg = i.segmento?;
    // El par segmento-desplazamiento depende de la anchura, y confundirlos tiene
    // consecuencias medidas: `fs:[0x30]` es el bloque de entorno en Windows de
    // 32 bits, pero en Linux de 64 `fs` es el area de datos locales del hilo y
    // ese desplazamiento es un campo cualquiera. La libc de esta maquina lo lee
    // 79 veces, y con la comprobacion sin anchura este modulo declaraba 79 veces
    // que la libc resuelve funciones a escondidas.
    let esperado = match (seg, arq) {
        (Segmento::Gs, Arquitectura::X86_64) => PEB_EN_64,
        (Segmento::Fs, Arquitectura::X86) => PEB_EN_32,
        _ => return None,
    };
    if !i.inmediatos.contains(&esperado) {
        return None;
    }
    let nombre_seg = match seg {
        Segmento::Gs => "gs",
        Segmento::Fs => "fs",
    };
    Some(Resolucion {
        donde: i.direccion,
        forma: Forma::PorEstructurasDelCargador,
        nombre: None,
        porque: format!(
            "en {:#x} se lee {nombre_seg}:[{esperado:#x}], que es el bloque de entorno del \
             proceso: desde ahi se llega a la lista de modulos cargados y a sus tablas de \
             exportacion sin tocar la tabla de importaciones",
            i.direccion
        ),
    })
}

/// Cuantas instrucciones hacia atras se mira para confirmar un hash.
///
/// Un algoritmo de hash de nombres cabe de sobra en esta ventana. Mas alla, la
/// constante y el bucle que se encuentran ya no tienen por que ser lo mismo, y
/// juntarlos seria construir una evidencia que no esta.
const VENTANA_DE_HASH: usize = 24;

/// Reconoce una busqueda por hash del nombre.
///
/// # Las dos condiciones, y por que hacen falta las dos
///
/// Una constante de hash suelta no prueba nada: `33` y `5381` aparecen en
/// cualquier parte de cualquier programa. Un bucle con desplazamientos tampoco.
/// Lo que si es una evidencia es **la constante del algoritmo dentro de un
/// tramo que ademas desplaza o rota**, porque eso ya no es una constante que
/// pasaba por ahi, es la constante usandose para lo que sirve.
///
/// Sigue sin ser prueba de nada malo —un programa puede tener un `djb2`
/// legitimo—, y por eso lo que sale de aqui es un hecho con su evidencia y no un
/// veredicto. Quien decide es el arbitro, con esto y con el resto.
fn por_hash(i: &Instruccion, anteriores: &[Instruccion]) -> Option<Resolucion> {
    let ventana = &anteriores[anteriores.len().saturating_sub(VENTANA_DE_HASH)..];
    let hay_desplazamiento = i.clase == Clase::Desplazamiento
        || ventana.iter().any(|p| p.clase == Clase::Desplazamiento);
    if !hay_desplazamiento {
        return None;
    }
    // La rotacion de trece, que es el caso mas conocido y no lleva constante de
    // algoritmo: la constante ES el trece.
    if i.clase == Clase::Desplazamiento && i.inmediatos.contains(&ROTACION_DE_TRECE) {
        return Some(Resolucion {
            donde: i.direccion,
            forma: Forma::PorHashDelNombre,
            nombre: None,
            porque: format!(
                "en {:#x} hay una rotacion de exactamente 13 bits, que es el hash de \
                 nombres de API mas extendido que existe y no un desplazamiento que se \
                 elija por casualidad",
                i.direccion
            ),
        });
    }
    let (_, algoritmo) = CONSTANTES_DE_HASH
        .iter()
        .find(|(c, _)| i.inmediatos.contains(c))?;
    Some(Resolucion {
        donde: i.direccion,
        forma: Forma::PorHashDelNombre,
        nombre: None,
        porque: format!(
            "en {:#x} aparece la constante de {algoritmo} dentro de un tramo que ademas \
             desplaza o rota: es la constante usandose para calcular un hash, no una \
             constante que pasaba por ahi",
            i.direccion
        ),
    })
}

/// Cruza una llamada por memoria con la tabla de importaciones.
fn por_tabla(i: &Instruccion, tabla: &dyn Importadas) -> Option<Resolucion> {
    if !i.flujo.indirecta() || i.destino_reg.is_some() {
        return None;
    }
    // El destino esta en memoria; el desplazamiento de esa memoria es lo que hay
    // que buscar en la tabla. Es el ultimo inmediato porque es el que anade
    // `inmediatos_de` cuando la instruccion toca memoria.
    let direccion = *i.inmediatos.last()?;
    let nombre = tabla.nombre_en(direccion)?;
    Some(Resolucion {
        donde: i.direccion,
        forma: Forma::PorTabla,
        nombre: Some(nombre.to_owned()),
        porque: format!(
            "en {:#x} se llama a traves de {direccion:#x}, que es la entrada de \
             {nombre} en la tabla de importaciones",
            i.direccion
        ),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cfg::SinDatos;
    use crate::plazo::Plazo;
    use crate::x86;

    /// Analiza un tramo de x86-64 y busca resoluciones.
    fn buscar(bytes: &[u8], tabla: &dyn Importadas) -> Importaciones {
        let t = x86::Tramo::nuevo(bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let cfg = Cfg::construir(&t, &SinDatos, &[0x1000], &mut p);
        Importaciones::buscar(&cfg, tabla, Arquitectura::X86_64)
    }

    /// Una tabla de importaciones de mentira, con una sola entrada.
    struct UnaEntrada(u64, &'static str);

    impl Importadas for UnaEntrada {
        fn nombre_en(&self, direccion: u64) -> Option<&str> {
            (direccion == self.0).then_some(self.1)
        }
    }

    #[test]
    fn leer_el_bloque_de_entorno_del_proceso_se_reconoce() {
        // `mov rax, gs:[0x60]` = 65 48 8B 04 25 60 00 00 00. Es el primer paso
        // de todo cargador reflexivo de Windows de 64 bits.
        let bytes = &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert_eq!(r.resoluciones.len(), 1, "{:?}", r.resoluciones);
        assert_eq!(r.resoluciones[0].forma, Forma::PorEstructurasDelCargador);
        assert!(r.resuelve_a_escondidas());
        assert!(
            r.resoluciones[0].porque.contains("gs:[0x60]"),
            "{}",
            r.resoluciones[0].porque
        );
    }

    #[test]
    fn leer_gs_con_otro_desplazamiento_no_se_reconoce() {
        // `mov rax, gs:[0x28]` es la cookie de pila de cualquier programa de
        // Linux, y lo hace absolutamente todo el mundo. Exigir solo el segmento
        // convertiria esta regla en ruido puro.
        let bytes = &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert!(r.resoluciones.is_empty(), "{:?}", r.resoluciones);
        assert!(!r.resuelve_a_escondidas());
    }

    #[test]
    fn una_rotacion_de_trece_se_reconoce_como_hash_de_nombres() {
        // `ror edx, 13` = C1 CA 0D. Trece no es un desplazamiento que nadie elija
        // por casualidad.
        let bytes = &[0xC1, 0xCA, 0x0D, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert_eq!(r.resoluciones.len(), 1, "{:?}", r.resoluciones);
        assert_eq!(r.resoluciones[0].forma, Forma::PorHashDelNombre);
        assert!(r.resoluciones[0].porque.contains("13"));
    }

    #[test]
    fn una_rotacion_de_otro_tamano_no_se_reconoce() {
        // `ror edx, 8` = C1 CA 08. Rotar ocho bits es intercambiar bytes, y lo
        // hace cualquier cosa que lea un formato de red.
        let bytes = &[0xC1, 0xCA, 0x08, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert!(r.resoluciones.is_empty(), "{:?}", r.resoluciones);
    }

    #[test]
    fn una_constante_de_hash_sin_desplazamiento_no_basta() {
        // `mov eax, 5381` = B8 05 15 00 00. La constante de djb2, sola, es un
        // numero. Sin un desplazamiento cerca no hay un hash calculandose, y
        // dispararse aqui llenaria de ruido cualquier informe.
        let bytes = &[0xB8, 0x05, 0x15, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert!(r.resoluciones.is_empty(), "{:?}", r.resoluciones);
    }

    #[test]
    fn una_constante_de_hash_con_desplazamiento_si_se_reconoce() {
        // `shl eax, 5` ; `mov eax, 5381` — la constante de djb2 dentro de un
        // tramo que desplaza. Ahi ya no es una constante que pasaba por ahi.
        let bytes = &[0xC1, 0xE0, 0x05, 0xB8, 0x05, 0x15, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert_eq!(r.resoluciones.len(), 1, "{:?}", r.resoluciones);
        assert_eq!(r.resoluciones[0].forma, Forma::PorHashDelNombre);
        assert!(r.resoluciones[0].porque.contains("djb2"));
    }

    #[test]
    fn una_llamada_por_la_tabla_se_cruza_con_el_nombre() {
        // `call [rip+0x2f10]` desde 0x1000: la entrada esta en 0x3f16.
        let bytes = &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &UnaEntrada(0x3f16, "VirtualAlloc"));
        assert_eq!(r.resoluciones.len(), 1, "{:?}", r.resoluciones);
        assert_eq!(r.resoluciones[0].forma, Forma::PorTabla);
        assert_eq!(r.resoluciones[0].nombre.as_deref(), Some("VirtualAlloc"));
        assert_eq!(r.nombres(), vec!["VirtualAlloc"]);
        assert!(
            !r.resuelve_a_escondidas(),
            "usar la tabla es lo normal y no es un hecho en contra de nadie"
        );
    }

    #[test]
    fn una_llamada_por_una_direccion_que_no_esta_en_la_tabla_no_inventa_nombre() {
        let bytes = &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &UnaEntrada(0xDEAD, "OtraCosa"));
        assert!(r.resoluciones.is_empty(), "{:?}", r.resoluciones);
    }

    #[test]
    fn sin_tabla_no_se_resuelve_ningun_nombre_y_se_nota() {
        let bytes = &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0xC3];
        let r = buscar(bytes, &SinTabla);
        assert!(r.nombres().is_empty());
    }

    #[test]
    fn un_binario_normal_no_dispara_nada() {
        // El caso negativo que hace que lo demas signifique algo: `xor eax,eax`
        // y `ret` no resuelven nada a escondidas.
        let r = buscar(&[0x31, 0xC0, 0xC3], &SinTabla);
        assert!(r.resoluciones.is_empty());
        assert!(!r.resuelve_a_escondidas());
        assert!(r.formas().is_empty());
    }
}
