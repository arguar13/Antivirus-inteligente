//! Lo que se encuentra en una memoria, con la prueba de que esta ahi.
//!
//! # La misma disciplina que en el desensamblador
//!
//! Un hallazgo sin evidencia es una afirmacion que quien la lea tiene que
//! creerse. Aqui, igual que en `aegis-disasm`, la evidencia va **dentro del
//! tipo**: [`Hallazgo`] guarda la direccion, que se vio y por que cuenta, y no
//! hay forma de construir uno sin eso.
//!
//! # Por que el analisis de codigo se delega
//!
//! Una region ejecutable sin respaldo de fichero es un hecho interesante, y lo
//! siguiente que hay que preguntar es **que hace ese codigo**. Eso ya sabe
//! hacerlo `aegis-disasm`: desensambla, construye los grafos y evalua el
//! catalogo de capacidades. Reescribir aqui una version peor de eso produciria
//! dos analisis del mismo codigo que dirian cosas distintas, y el dia que
//! difieran nadie sabria cual creer.
//!
//! Asi que este modulo encuentra **donde** hay codigo que no deberia estar, y se
//! lo pasa al desensamblador para saber **que** hace.

use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::plazo::{Cobertura, Plazo};
use aegis_disasm::{analizar, Capacidad, Entrada};

use crate::adquirir::Lectura;
use crate::regiones::Region;

/// De que clase es un hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Clase {
    /// Codigo ejecutable que no viene de ningun fichero.
    CodigoSinRespaldo,
    /// Una region escribible y ejecutable a la vez.
    EscribibleYEjecutable,
    /// El codigo de una region tiene capacidades reconocidas.
    CapacidadEnMemoria,
    /// Una region con un encabezado de ejecutable dentro.
    ///
    /// Un PE o un ELF en memoria anonima es un modulo que alguien mapeo a mano,
    /// saltandose el cargador del sistema.
    EjecutableSinCargar,
}

impl Clase {
    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Clase::CodigoSinRespaldo => "codigo ejecutable sin respaldo de fichero",
            Clase::EscribibleYEjecutable => "region escribible y ejecutable a la vez",
            Clase::CapacidadEnMemoria => "capacidad reconocida en codigo de memoria",
            Clase::EjecutableSinCargar => "ejecutable mapeado sin pasar por el cargador",
        }
    }
}

/// Algo que se encontro, con la prueba de que esta ahi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hallazgo {
    /// De que clase.
    pub clase: Clase,
    /// En que direccion.
    pub donde: u64,
    /// Que se vio exactamente.
    pub que: String,
    /// Por que eso cuenta.
    pub porque: String,
}

impl Hallazgo {
    /// La frase con la que este hallazgo aparece en un informe.
    pub fn frase(&self) -> String {
        format!(
            "{} en {:#x}: {} — {}",
            self.clase.nombre(),
            self.donde,
            self.que,
            self.porque
        )
    }
}

/// Lo que se encontro en una memoria, y hasta donde se miro.
///
/// Las dos cosas van **en el mismo tipo**, por la misma razon que en
/// `aegis_disasm::Informe`: una lista de hallazgos sin su cobertura es una
/// afirmacion sobre la memoria entera que solo es cierta si el analisis termino.
#[derive(Debug, Clone, Default)]
pub struct Informe {
    hallazgos: Vec<Hallazgo>,
    /// Las capacidades que el desensamblador encontro en el codigo de memoria.
    pub capacidades: Vec<Capacidad>,
    /// Hasta donde se llego.
    pub cobertura: Cobertura,
    /// Cuantas regiones tenian codigo que desensamblar.
    ///
    /// No son todas: el mapa de **todas** se mira siempre, porque leerlo no
    /// cuesta nada y es lo que mas dice por byte leido. Lo que puede quedarse
    /// corto es el desensamblado, y por eso lo que se compara con
    /// [`Informe::regiones_miradas`] es esto y no el total.
    pub regiones_candidatas: usize,
    /// De esas, cuantas se llegaron a desensamblar.
    pub regiones_miradas: usize,
    /// Cuantas regiones habia en el mapa.
    pub regiones_totales: usize,
}

impl Informe {
    /// Lo que se encontro.
    pub fn hallazgos(&self) -> &[Hallazgo] {
        &self.hallazgos
    }

    /// Si de este informe se puede concluir que la memoria **no** tiene algo.
    ///
    /// Hacen falta las dos cosas: que ninguna region con codigo se quedara sin
    /// desensamblar por el tope, y que el desensamblado de las que si no se
    /// cortara por el plazo. Con cualquiera de las dos a medias, una lista vacia
    /// significa «no dio tiempo a mirar», que es otra frase.
    ///
    /// Una region de datos respaldada por un fichero no entra en la cuenta y no
    /// deberia: su mapa SI se miro, y no habia nada que desensamblar dentro.
    /// Exigir que se hubiera desensamblado haria que ningun informe de una
    /// memoria real pudiera concluir nada.
    pub fn la_ausencia_significa_algo(&self) -> bool {
        self.regiones_miradas == self.regiones_candidatas && self.cobertura.completa()
    }

    /// La frase con la que este informe aparece en un registro.
    pub fn frase(&self) -> String {
        let mut s = if self.hallazgos.is_empty() {
            if self.la_ausencia_significa_algo() {
                format!(
                    "se miro el mapa de las {} regiones de la memoria y el codigo de las \
                     {} que lo tenian, y no se encontro nada",
                    self.regiones_totales, self.regiones_candidatas
                )
            } else {
                format!(
                    "no se encontro nada, PERO DE LAS {} regiones con codigo SOLO SE \
                     MIRARON {}: eso no significa que no haya",
                    self.regiones_candidatas, self.regiones_miradas
                )
            }
        } else {
            format!(
                "{} hallazgos, con {} de {} regiones con codigo desensambladas: {}",
                self.hallazgos.len(),
                self.regiones_miradas,
                self.regiones_candidatas,
                self.hallazgos
                    .iter()
                    .map(|h| h.clase.nombre())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        if !self.capacidades.is_empty() {
            s.push_str(&format!(
                ". El codigo de esas regiones tiene {} capacidades: {}",
                self.capacidades.len(),
                self.capacidades
                    .iter()
                    .map(|c| c.nombre)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        s
    }
}

/// Tope de regiones que se analizan en profundidad.
///
/// Un volcado de una maquina grande tiene decenas de miles de regiones, y
/// desensamblar todas es un trabajo que no cabe en el presupuesto del agente. Se
/// miran las que tienen algo que mirar —las ejecutables sin respaldo— y se cuenta
/// cuantas quedaron fuera.
pub const MAX_REGIONES_DESENSAMBLADAS: usize = 64;

/// Cuantos bytes de una region se desensamblan.
///
/// Un modulo cargado reflexivamente cabe de sobra en un megabyte, y sin tope una
/// region declarada enorme haria reservar por su tamano declarado.
pub const MAX_BYTES_POR_REGION: usize = 1024 * 1024;

/// Analiza una memoria y devuelve lo que se encontro.
///
/// El plazo lo pone quien llama, por la misma razon que en `aegis-disasm`: el
/// presupuesto no es el mismo revisando un endpoint en marcha que analizando un
/// volcado en el servidor.
pub fn analizar_memoria(m: &dyn Lectura, arq: Arquitectura, plazo: &mut Plazo) -> Informe {
    let regiones = m.regiones();
    let mut informe = Informe {
        regiones_totales: regiones.len(),
        ..Default::default()
    };

    // Primero lo que se sabe del MAPA, que no cuesta leer nada. Un volcado
    // gigantesco cuyo desensamblado no quepa en el plazo produce igualmente esta
    // parte, que es la que mas dice por byte leido.
    for r in regiones {
        if !r.valida() {
            continue;
        }
        if r.permisos.escribible_y_ejecutable() {
            informe.hallazgos.push(Hallazgo {
                clase: Clase::EscribibleYEjecutable,
                donde: r.inicio,
                que: r.frase(),
                porque: "ningun sistema operativo moderno concede escritura y ejecucion a la \
                         vez por defecto, y ningun compilador la pide: hay que pedirla \
                         explicitamente, y quien la tiene o la pidio o la consiguio"
                    .to_owned(),
            });
        }
        if r.codigo_sin_respaldo() {
            informe.hallazgos.push(Hallazgo {
                clase: Clase::CodigoSinRespaldo,
                donde: r.inicio,
                que: r.frase(),
                porque: "el codigo legitimo llega al espacio de direcciones de una sola \
                         forma: lo mapea el cargador desde un fichero que sigue en disco y \
                         que se puede volver a leer y comparar. Codigo sin ese fichero \
                         detras lo escribio alguien ahi en ejecucion"
                    .to_owned(),
            });
        }
    }

    // Despues, el contenido de las que tienen algo que mirar.
    let todas_las_candidatas: Vec<&Region> = regiones
        .iter()
        .filter(|r| r.valida() && r.codigo_sin_respaldo())
        .collect();
    informe.regiones_candidatas = todas_las_candidatas.len();
    let candidatas =
        &todas_las_candidatas[..todas_las_candidatas.len().min(MAX_REGIONES_DESENSAMBLADAS)];

    for r in candidatas {
        let cuantos = (r.tamano() as usize).min(MAX_BYTES_POR_REGION);
        let Ok(bytes) = m.leer(r.inicio, cuantos) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        informe.regiones_miradas += 1;

        if let Some(que) = encabezado_de_ejecutable(&bytes) {
            informe.hallazgos.push(Hallazgo {
                clase: Clase::EjecutableSinCargar,
                donde: r.inicio,
                que: que.to_owned(),
                porque: "un ejecutable entero en memoria que el cargador del sistema no \
                         mapeo desde un fichero es un modulo puesto ahi a mano, que es como \
                         se carga un implante sin dejar rastro en la lista de modulos"
                    .to_owned(),
            });
        }

        // Aqui se delega. Ver la cabecera del modulo: reescribir una version
        // peor del analisis de codigo produciria dos analisis que dicen cosas
        // distintas del mismo codigo.
        let entradas = [r.inicio];
        let entrada = Entrada::minima(&bytes, r.inicio, arq, &entradas);
        let a = analizar(&entrada, plazo);
        for c in a.informe.capacidades() {
            informe.hallazgos.push(Hallazgo {
                clase: Clase::CapacidadEnMemoria,
                donde: c.evidencias().first().map(|e| e.donde).unwrap_or(r.inicio),
                que: c.nombre.to_owned(),
                porque: c
                    .evidencias()
                    .first()
                    .map(|e| e.porque.clone())
                    .unwrap_or_default(),
            });
            informe.capacidades.push(c.clone());
        }
        // La cobertura se queda con la PEOR de las regiones: si el analisis se
        // corto en una, el informe entero esta incompleto. Quedarse con la
        // ultima diria que esta completo porque la ultima region era pequena.
        if !a.informe.cobertura.completa() {
            informe.cobertura.cortado_por_plazo |= a.informe.cobertura.cortado_por_plazo;
            informe.cobertura.cortado_por_tope |= a.informe.cobertura.cortado_por_tope;
        }
        informe.cobertura.instrucciones += a.informe.cobertura.instrucciones;
        informe.cobertura.bytes_totales += bytes.len() as u64;
        informe.cobertura.bytes_cubiertos += a.informe.cobertura.bytes_cubiertos;
        informe.cobertura.funciones += a.informe.cobertura.funciones;
    }

    // Las que no se miraron por el tope tambien cuentan, y por eso el total no
    // es el numero de candidatas sino el de regiones del mapa: quien lea el
    // informe tiene que poder ver que quedaron regiones sin mirar.
    informe.hallazgos.sort_by_key(|h| (h.donde, h.clase));
    informe.hallazgos.dedup();
    informe
}

/// Si estos bytes empiezan por el encabezado de un ejecutable.
///
/// Se miran los cuatro formatos que importan. El de PE se reconoce por `MZ`
/// **y** por la firma que hay donde dice su propio encabezado, porque `MZ` a
/// secas son dos bytes que salen por casualidad cada 65.536: sin la segunda
/// comprobacion, este hallazgo apareceria en cualquier region de datos lo
/// bastante grande.
fn encabezado_de_ejecutable(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return Some("un ELF completo (7f 45 4c 46)");
    }
    if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
    {
        return Some("un Mach-O completo");
    }
    if bytes.starts_with(b"MZ") {
        // El encabezado DOS dice en el desplazamiento 0x3C donde esta el de PE.
        let off = u32::from_le_bytes([
            *bytes.get(0x3C)?,
            *bytes.get(0x3D)?,
            *bytes.get(0x3E)?,
            *bytes.get(0x3F)?,
        ]) as usize;
        if bytes.get(off..off + 4) == Some(b"PE\0\0") {
            return Some("un PE completo (MZ con su firma PE)");
        }
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::adquirir::EnMemoria;
    use crate::regiones::{Permisos, Respaldo};

    fn region(inicio: u64, fin: u64, p: &str, respaldo: Respaldo, off: u64) -> Region {
        Region {
            inicio,
            fin,
            permisos: Permisos::de_texto(p),
            respaldo,
            desplazamiento_en_volcado: off,
        }
    }

    #[test]
    fn una_region_ejecutable_de_fichero_no_es_un_hallazgo() {
        // El caso negativo que hace que lo demas signifique algo: todo el codigo
        // del sistema esta en regiones ejecutables, y un analisis que las
        // senalara senalaria todos los procesos de todas las maquinas.
        let m = EnMemoria::nueva(
            vec![0x90; 64],
            vec![region(
                0x1000,
                0x1040,
                "r-xp",
                Respaldo::Fichero {
                    ruta: "/usr/lib/libc.so.6".to_owned(),
                },
                0,
            )],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(i.hallazgos().is_empty(), "{}", i.frase());
    }

    #[test]
    fn una_region_ejecutable_anonima_si_lo_es_y_dice_por_que() {
        let m = EnMemoria::nueva(
            vec![0x90; 64],
            vec![region(0x1000, 0x1040, "r-xp", Respaldo::Anonima, 0)],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        let h = i
            .hallazgos()
            .iter()
            .find(|h| h.clase == Clase::CodigoSinRespaldo)
            .unwrap_or_else(|| panic!("{}", i.frase()));
        assert!(
            h.porque.contains("lo mapea el cargador"),
            "la evidencia tiene que explicar por que eso cuenta: {}",
            h.porque
        );
    }

    #[test]
    fn una_region_escribible_y_ejecutable_se_senala_aunque_venga_de_un_fichero() {
        // Que venga de un fichero no quita que alguien pidio los dos permisos a
        // la vez, y eso hay que pedirlo explicitamente.
        let m = EnMemoria::nueva(
            vec![0x90; 64],
            vec![region(
                0x1000,
                0x1040,
                "rwxp",
                Respaldo::Fichero {
                    ruta: "/tmp/algo".to_owned(),
                },
                0,
            )],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(i
            .hallazgos()
            .iter()
            .any(|h| h.clase == Clase::EscribibleYEjecutable));
    }

    #[test]
    fn un_elf_en_memoria_anonima_se_reconoce() {
        // Un ejecutable entero que el cargador no mapeo desde un fichero es un
        // modulo puesto ahi a mano.
        let mut bytes = vec![0x7F, b'E', b'L', b'F'];
        bytes.extend_from_slice(&[0x90; 60]);
        let m = EnMemoria::nueva(
            bytes,
            vec![region(0x1000, 0x1040, "r-xp", Respaldo::Anonima, 0)],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(i
            .hallazgos()
            .iter()
            .any(|h| h.clase == Clase::EjecutableSinCargar));
    }

    #[test]
    fn dos_bytes_mz_sueltos_no_son_un_pe() {
        // `MZ` son dos bytes que salen por casualidad cada 65.536. Sin exigir la
        // firma de PE donde el propio encabezado dice que esta, este hallazgo
        // apareceria en cualquier region de datos lo bastante grande.
        let mut bytes = vec![b'M', b'Z'];
        bytes.extend_from_slice(&[0x41; 200]);
        assert_eq!(encabezado_de_ejecutable(&bytes), None);

        // Y con la firma de verdad, si.
        let mut bueno = vec![0u8; 0x100];
        bueno[0] = b'M';
        bueno[1] = b'Z';
        bueno[0x3C] = 0x80;
        bueno[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(encabezado_de_ejecutable(&bueno).is_some());
    }

    #[test]
    fn el_codigo_de_una_region_anonima_se_desensambla_y_sus_capacidades_salen() {
        // La conexion con `aegis-disasm`, que es lo que hace util a este crate:
        // saber que hay codigo donde no deberia es la mitad; la otra mitad es
        // saber que hace. `aesenc xmm0, xmm1` = 66 0F 38 DC C1.
        let mut bytes = vec![0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        bytes.resize(64, 0x90);
        let m = EnMemoria::nueva(
            bytes,
            vec![region(0x1000, 0x1040, "rwxp", Respaldo::Anonima, 0)],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(
            !i.capacidades.is_empty(),
            "el codigo de la region tiene una capacidad: {}",
            i.frase()
        );
        assert!(i
            .hallazgos()
            .iter()
            .any(|h| h.clase == Clase::CapacidadEnMemoria));
        assert!(i.frase().contains("capacidades"), "{}", i.frase());
    }

    #[test]
    fn una_memoria_sin_nada_raro_lo_dice_y_su_ausencia_significa_algo() {
        let m = EnMemoria::nueva(
            vec![0x90; 64],
            vec![region(
                0x1000,
                0x1040,
                "r--p",
                Respaldo::Fichero {
                    ruta: "/usr/lib/datos".to_owned(),
                },
                0,
            )],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(i.hallazgos().is_empty());
        assert!(i.la_ausencia_significa_algo());
        assert!(i.frase().contains("no se encontro nada"), "{}", i.frase());
    }

    #[test]
    fn si_se_corto_el_analisis_la_ausencia_no_significa_nada() {
        // La invariante que impide que un informe forense diga «no habia nada»
        // de una memoria que no se llego a mirar entera.
        let mut bytes = vec![0x90u8; 200_000];
        bytes[0] = 0x90;
        let m = EnMemoria::nueva(
            bytes,
            vec![region(
                0x1000,
                0x1000 + 200_000,
                "r-xp",
                Respaldo::Anonima,
                0,
            )],
        );
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(3600), 50);
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut plazo);
        assert!(!i.la_ausencia_significa_algo());
    }

    #[test]
    fn un_mapa_con_mas_regiones_que_las_que_se_miran_lo_declara() {
        // Un volcado de una maquina grande tiene decenas de miles de regiones.
        // Lo que no puede pasar es que el informe parezca exhaustivo.
        let mut regiones = Vec::new();
        for n in 0..(MAX_REGIONES_DESENSAMBLADAS as u64 + 10) {
            regiones.push(region(
                0x1000 + n * 0x100,
                0x1000 + n * 0x100 + 0x40,
                "r-xp",
                Respaldo::Anonima,
                n * 0x40,
            ));
        }
        let total = regiones.len();
        let m = EnMemoria::nueva(vec![0x90; total * 0x40], regiones);
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert_eq!(i.regiones_totales, total);
        assert!(i.regiones_miradas < total, "no se miraron todas");
        assert!(!i.la_ausencia_significa_algo());
    }

    #[test]
    fn una_region_con_el_final_antes_del_principio_no_produce_hallazgos() {
        // Un mapa lo escribe una herramienta que puede estar rota o mentir.
        let m = EnMemoria::nueva(
            vec![0x90; 64],
            vec![Region {
                inicio: 0x2000,
                fin: 0x1000,
                permisos: Permisos::de_texto("rwxp"),
                respaldo: Respaldo::Anonima,
                desplazamiento_en_volcado: 0,
            }],
        );
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::default());
        assert!(i.hallazgos().is_empty());
    }
}
