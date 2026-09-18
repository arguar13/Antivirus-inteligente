//! Las regiones de memoria, y lo que sus permisos dicen.
//!
//! # Por que el respaldo importa tanto como los permisos
//!
//! Una region ejecutable no dice nada por si sola: todo el codigo del sistema
//! esta en regiones ejecutables. Lo que dice algo es una region ejecutable **que
//! no viene de ningun fichero**, porque el codigo legitimo llega al espacio de
//! direcciones de una sola forma: lo mapea el cargador desde un fichero que esta
//! en disco y que se puede volver a leer, comparar y comprobar.
//!
//! Codigo ejecutable en memoria anonima significa que alguien lo escribio ahi en
//! ejecucion. Eso lo hace un compilador al vuelo —una maquina virtual de Java, un
//! motor de JavaScript— y lo hace un cargador reflexivo. Los dos son el mismo
//! hecho, y por eso lo que sale de aqui es un hecho con su evidencia y no un
//! veredicto.

/// Que se puede hacer con una region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permisos {
    /// Se puede leer.
    pub lectura: bool,
    /// Se puede escribir.
    pub escritura: bool,
    /// Se puede ejecutar.
    pub ejecucion: bool,
}

impl Permisos {
    /// Escribible y ejecutable a la vez.
    ///
    /// Es la combinacion que ningun sistema operativo moderno concede por
    /// defecto y que ningun compilador emite: hay que pedirla explicitamente. Un
    /// programa que la tiene o la pidio, o la consiguio, y las dos cosas son
    /// informacion.
    pub fn escribible_y_ejecutable(&self) -> bool {
        self.escritura && self.ejecucion
    }

    /// Lee unos permisos escritos como los escribe Linux: `rwxp`.
    ///
    /// Se acepta cualquier longitud y se miran las tres primeras posiciones: el
    /// cuarto caracter es el modo de comparticion, que no es un permiso. Un
    /// caracter que no sea el esperado cuenta como ausencia, que es lo seguro:
    /// leer una region como menos permisiva de lo que es solo pierde un
    /// hallazgo, y leerla como mas permisiva lo inventa.
    pub fn de_texto(s: &str) -> Permisos {
        let b = s.as_bytes();
        Permisos {
            lectura: b.first() == Some(&b'r'),
            escritura: b.get(1) == Some(&b'w'),
            ejecucion: b.get(2) == Some(&b'x'),
        }
    }

    /// Como se escriben.
    pub fn texto(&self) -> String {
        format!(
            "{}{}{}",
            if self.lectura { 'r' } else { '-' },
            if self.escritura { 'w' } else { '-' },
            if self.ejecucion { 'x' } else { '-' }
        )
    }
}

/// De donde viene el contenido de una region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Respaldo {
    /// De un fichero que esta en disco.
    ///
    /// Es como llega al espacio de direcciones todo el codigo legitimo, y lo que
    /// permite comprobarlo: el fichero se puede volver a leer y comparar.
    Fichero {
        /// La ruta, tal y como la da el sistema.
        ruta: String,
    },
    /// De ninguna parte: memoria reservada en ejecucion.
    Anonima,
    /// Una region con nombre que no es un fichero: pila, monton, o lo que el
    /// sistema etiquete.
    Nombrada {
        /// La etiqueta.
        que: String,
    },
}

/// Las regiones que el nucleo mapea en TODOS los procesos.
///
/// # Por que hay que conocerlas por nombre
///
/// Son ejecutables y no vienen de ningun fichero, asi que encajan exactamente en
/// la definicion de «codigo que alguien escribio ahi en ejecucion». Y no lo son:
/// las pone el nucleo en cada proceso que arranca, por diseno, desde hace veinte
/// anos.
///
/// Medido en este mismo proceso de pruebas: de sus seis regiones ejecutables,
/// dos son `[vdso]` y `[vsyscall]`. Sin esta lista, el analisis senala dos
/// hallazgos en **todos los procesos de todas las maquinas Linux**, que es la
/// definicion de ruido.
///
/// La lista es corta y cerrada a proposito. `[stack]` y `[heap]` **no estan**:
/// una pila o un monton ejecutables no los pone el nucleo por diseno, los
/// consigue alguien, y son de los hallazgos mas claros que existen.
const MAPEADAS_POR_EL_NUCLEO: &[&str] = &["[vdso]", "[vsyscall]", "[vvar]", "[vectors]"];

impl Respaldo {
    /// Si esta region la mapea el nucleo en todos los procesos.
    ///
    /// Ver [`MAPEADAS_POR_EL_NUCLEO`].
    pub fn la_mapea_el_nucleo(&self) -> bool {
        match self {
            Respaldo::Nombrada { que } => MAPEADAS_POR_EL_NUCLEO.contains(&que.as_str()),
            _ => false,
        }
    }

    /// Si el contenido se puede comprobar contra algo.
    ///
    /// Es la pregunta que separa «esto es codigo del sistema» de «esto lo
    /// escribio alguien aqui»: sin fichero detras no hay nada contra lo que
    /// comparar, y el analisis de memoria es lo unico que queda.
    pub fn se_puede_comprobar(&self) -> bool {
        matches!(self, Respaldo::Fichero { .. })
    }

    /// Como se lee en un informe.
    pub fn frase(&self) -> String {
        match self {
            Respaldo::Fichero { ruta } => format!("respaldada por {ruta}"),
            Respaldo::Anonima => "sin respaldo de ningun fichero".to_owned(),
            Respaldo::Nombrada { que } => format!("region del sistema: {que}"),
        }
    }
}

/// Una region de memoria de un espacio de direcciones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Primera direccion.
    pub inicio: u64,
    /// Primera direccion que ya no pertenece a la region.
    pub fin: u64,
    /// Que se puede hacer con ella.
    pub permisos: Permisos,
    /// De donde viene su contenido.
    pub respaldo: Respaldo,
    /// Donde estan sus bytes dentro del volcado.
    pub desplazamiento_en_volcado: u64,
}

impl Region {
    /// Cuanto ocupa.
    pub fn tamano(&self) -> u64 {
        self.fin.saturating_sub(self.inicio)
    }

    /// Si contiene una direccion.
    pub fn contiene(&self, direccion: u64) -> bool {
        direccion >= self.inicio && direccion < self.fin
    }

    /// Si es codigo que no viene de ningun fichero **ni lo pone el nucleo**.
    ///
    /// La combinacion que de verdad dice algo. Las regiones que el nucleo mapea
    /// en todos los procesos quedan fuera, y sin esa exclusion este metodo es
    /// cierto dos veces en cada proceso de cada maquina Linux: ver
    /// [`MAPEADAS_POR_EL_NUCLEO`].
    pub fn codigo_sin_respaldo(&self) -> bool {
        self.permisos.ejecucion
            && !self.respaldo.se_puede_comprobar()
            && !self.respaldo.la_mapea_el_nucleo()
    }

    /// Si la region es coherente consigo misma.
    ///
    /// Una region con el final antes del principio no es una region: es un mapa
    /// mal escrito, y todo lo que se calcule con ella sale mal. Un volcado lo
    /// escribe una herramienta que puede estar rota o mentir.
    pub fn valida(&self) -> bool {
        self.fin > self.inicio
    }

    /// Como se lee en un informe.
    pub fn frase(&self) -> String {
        format!(
            "{:#x}-{:#x} ({} bytes, {}, {})",
            self.inicio,
            self.fin,
            self.tamano(),
            self.permisos.texto(),
            self.respaldo.frase()
        )
    }
}

/// Lee el mapa de regiones tal y como lo escribe Linux en `/proc/<pid>/maps`.
///
/// # Por que se lee esto y no una estructura del nucleo
///
/// Porque este crate analiza memoria **inerte**: lo que llega es un volcado y su
/// mapa, y el mapa es texto. Leer estructuras del nucleo es otra cosa y la hace
/// `aegis-memhunter`, en vivo y con otras garantias.
///
/// Las lineas que no se entienden **se saltan y se cuentan**. Un mapa con una
/// linea rara no invalida las otras mil, y pararse en la primera perderia todo
/// lo demas; pero tampoco se puede callar, porque una herramienta que produzca
/// mapas ilegibles tiene que notarse.
pub fn leer_mapa(texto: &str) -> (Vec<Region>, usize) {
    let mut v = Vec::new();
    let mut ilegibles = 0usize;
    let mut desplazamiento = 0u64;
    for linea in texto.lines() {
        match linea_de_mapa(linea, desplazamiento) {
            Some(r) => {
                desplazamiento = desplazamiento.saturating_add(r.tamano());
                v.push(r);
            }
            None => {
                if !linea.trim().is_empty() {
                    ilegibles += 1;
                }
            }
        }
    }
    v.sort_by_key(|r| r.inicio);
    (v, ilegibles)
}

/// Una linea de `/proc/<pid>/maps`.
///
/// Formato: `7f0e4c000000-7f0e4c021000 rw-p 00000000 00:00 0    [heap]`
fn linea_de_mapa(linea: &str, desplazamiento: u64) -> Option<Region> {
    let mut campos = linea.split_whitespace();
    let rango = campos.next()?;
    let permisos = Permisos::de_texto(campos.next()?);
    let (a, b) = rango.split_once('-')?;
    let inicio = u64::from_str_radix(a, 16).ok()?;
    let fin = u64::from_str_radix(b, 16).ok()?;
    if fin <= inicio {
        return None;
    }
    // Se saltan el desplazamiento en el fichero, el dispositivo y el inodo: lo
    // que hace falta es el ultimo campo, que es el nombre.
    let _ = campos.next()?;
    let _ = campos.next()?;
    let inodo = campos.next()?;
    let nombre = campos.next().unwrap_or("");
    let respaldo = if nombre.starts_with('/') && inodo != "0" {
        Respaldo::Fichero {
            ruta: nombre.to_owned(),
        }
    } else if nombre.is_empty() {
        Respaldo::Anonima
    } else {
        Respaldo::Nombrada {
            que: nombre.to_owned(),
        }
    };
    Some(Region {
        inicio,
        fin,
        permisos,
        respaldo,
        desplazamiento_en_volcado: desplazamiento,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un mapa de verdad, copiado de la forma que tiene en Linux.
    const MAPA: &str = "\
55a4c0000000-55a4c0021000 r-xp 00000000 08:01 1234    /usr/bin/ejemplo
55a4c0021000-55a4c0022000 rw-p 00021000 08:01 1234    /usr/bin/ejemplo
7f0e4c000000-7f0e4c021000 rwxp 00000000 00:00 0
7f0e4d000000-7f0e4d021000 rw-p 00000000 00:00 0       [heap]
7ffd0a000000-7ffd0a021000 rw-p 00000000 00:00 0       [stack]
";

    #[test]
    fn se_lee_un_mapa_con_la_forma_que_tiene_en_linux() {
        let (v, ilegibles) = leer_mapa(MAPA);
        assert_eq!(v.len(), 5);
        assert_eq!(ilegibles, 0);
        assert_eq!(v[0].inicio, 0x55a4_c000_0000);
        assert!(v[0].permisos.ejecucion);
        assert!(!v[0].permisos.escritura);
        assert_eq!(
            v[0].respaldo,
            Respaldo::Fichero {
                ruta: "/usr/bin/ejemplo".to_owned()
            }
        );
    }

    #[test]
    fn una_region_anonima_y_ejecutable_se_distingue_de_una_de_fichero() {
        // La distincion central del modulo: el codigo legitimo llega al espacio
        // de direcciones mapeado desde un fichero que se puede volver a leer.
        let (v, _) = leer_mapa(MAPA);
        let anonima = v.iter().find(|r| r.inicio == 0x7f0e_4c00_0000).unwrap();
        assert_eq!(anonima.respaldo, Respaldo::Anonima);
        assert!(anonima.codigo_sin_respaldo());
        assert!(anonima.permisos.escribible_y_ejecutable());

        let de_fichero = &v[0];
        assert!(de_fichero.permisos.ejecucion);
        assert!(
            !de_fichero.codigo_sin_respaldo(),
            "viene de un fichero: se puede comprobar"
        );
    }

    #[test]
    fn la_pila_y_el_monton_no_cuentan_como_anonimas_sin_mas() {
        // Tienen nombre, y ese nombre es informacion: una pila ejecutable no es
        // lo mismo que una region anonima ejecutable, aunque las dos sean codigo
        // sin respaldo.
        let (v, _) = leer_mapa(MAPA);
        let pila = v.iter().find(|r| r.inicio == 0x7ffd_0a00_0000).unwrap();
        assert_eq!(
            pila.respaldo,
            Respaldo::Nombrada {
                que: "[stack]".to_owned()
            }
        );
        assert!(pila.frase().contains("[stack]"), "{}", pila.frase());
    }

    #[test]
    fn una_linea_rota_se_cuenta_y_no_tumba_el_resto() {
        // Un mapa con una linea rara no invalida las otras mil, y pararse en la
        // primera perderia todo lo demas. Pero callarlo escondería que la
        // herramienta que lo produjo esta rota.
        let (v, ilegibles) = leer_mapa("esto no es una linea de mapa\n7f00-7f10 r--p 0 0:0 0\n");
        assert_eq!(ilegibles, 1);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn una_region_con_el_final_antes_del_principio_se_rechaza() {
        // Un mapa lo escribe una herramienta que puede estar rota o mentir, y
        // con una region asi todo lo que se calcule sale mal.
        let (v, ilegibles) = leer_mapa("7f10-7f00 rwxp 0 0:0 0\n");
        assert!(v.is_empty());
        assert_eq!(ilegibles, 1);
    }

    #[test]
    fn unos_permisos_raros_se_leen_como_ausencia_y_no_como_presencia() {
        // Leer una region como menos permisiva de lo que es pierde un hallazgo;
        // leerla como mas permisiva lo inventa. Se elige perder.
        let p = Permisos::de_texto("???p");
        assert!(!p.lectura && !p.escritura && !p.ejecucion);
        assert_eq!(Permisos::de_texto("").texto(), "---");
        assert_eq!(Permisos::de_texto("rwx").texto(), "rwx");
    }

    #[test]
    fn las_regiones_que_pone_el_nucleo_no_cuentan_como_codigo_sin_respaldo() {
        // Son ejecutables y no vienen de ningun fichero, y aun asi no las puso
        // nadie ahi: las pone el nucleo en cada proceso que arranca. Sin esta
        // exclusion, el analisis senala dos hallazgos en todos los procesos de
        // todas las maquinas Linux.
        let (v, _) = leer_mapa(
            "7f00-7f10 r-xp 0 00:00 0    [vdso]\n             ffffffffff600000-ffffffffff601000 --xp 0 00:00 0    [vsyscall]\n",
        );
        assert_eq!(v.len(), 2);
        for r in &v {
            assert!(r.respaldo.la_mapea_el_nucleo(), "{}", r.frase());
            assert!(!r.codigo_sin_respaldo(), "{}", r.frase());
        }
    }

    #[test]
    fn una_pila_ejecutable_si_cuenta_aunque_tenga_nombre_del_sistema() {
        // `[stack]` y `[heap]` NO estan en la lista, y es deliberado: una pila
        // ejecutable no la pone el nucleo por diseno, la consigue alguien.
        let (v, _) = leer_mapa("7f00-7f10 rwxp 0 00:00 0    [stack]\n");
        assert!(!v[0].respaldo.la_mapea_el_nucleo());
        assert!(v[0].codigo_sin_respaldo());
    }

    #[test]
    fn un_fichero_sin_inodo_no_cuenta_como_respaldado() {
        // Una region con nombre de fichero e inodo cero es un mapeo especial del
        // nucleo, no un fichero que se pueda volver a leer. Tratarlo como
        // comprobable haria que el analisis diera por bueno algo que no puede
        // comparar con nada.
        let (v, _) = leer_mapa("7f00-7f10 r-xp 0 00:00 0    /memfd:algo (deleted)\n");
        assert_eq!(v.len(), 1);
        assert!(!v[0].respaldo.se_puede_comprobar());
        assert!(v[0].codigo_sin_respaldo());
    }
}
