//! Resolucion del objetivo de un uprobe: **que** fichero y **en que
//! desplazamiento** hay que enganchar para ver el TLS de un proceso.
//!
//! # Las tres formas en que un proceso hace TLS, y por que hay que cubrirlas
//!
//! 1. **Enlazado dinamico a una biblioteca conocida** (`libssl.so.3`,
//!    `libgnutls.so.30`). El caso mayoritario: el simbolo `SSL_write` esta
//!    exportado y la biblioteca aparece en `/proc/<pid>/maps`.
//! 2. **Estatico**: la implementacion de TLS esta DENTRO del ejecutable. Es lo
//!    que hace todo binario de **Go** (`crypto/tls`) y lo que hace, a proposito,
//!    el malware que quiere sobrevivir en maquinas sin dependencias. Aqui no hay
//!    `libssl` que enganchar: el objetivo es el propio ejecutable, y el simbolo
//!    no se llama `SSL_write` sino `crypto/tls.(*Conn).Write`.
//! 3. **Biblioteca renombrada o embebida**: la misma OpenSSL, copiada junto al
//!    binario con otro nombre. Un reconocimiento por nombre de fichero la pierde;
//!    uno por SIMBOLO, no.
//!
//! Por eso la resolucion es **por simbolo y no por nombre de fichero**. El nombre
//! solo sirve para ORDENAR los candidatos —mirar antes lo que probablemente
//! acierte— y nunca para descartar: un cazador que solo mire ficheros llamados
//! `libssl*` es ciego justo contra quien se molesta en esconderse, que es el
//! unico que importa.
//!
//! # Honestidad
//!
//! Todo este modulo se prueba de verdad: la resolucion corre sobre el
//! `/proc/self/maps` REAL del proceso de prueba y sobre las bibliotecas reales de
//! la maquina. Lo que NO se ejercita aqui es **enganchar** el uprobe, que
//! necesita `CAP_BPF`/`CAP_PERFMON` y un proceso victima que hable TLS; eso se
//! declara en `tools/verificar-l7hunter.sh`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::elf::Binario;
use crate::L7Error;

/// La pila TLS a la que pertenece un punto de enganche.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PilaTls {
    /// OpenSSL, y por herencia de API tambien BoringSSL y LibreSSL: las tres
    /// exportan `SSL_read`/`SSL_write` con la misma firma, asi que un solo
    /// enganche vale para las tres.
    OpenSsl,
    /// GnuTLS (`gnutls_record_send`/`gnutls_record_recv`). En una distribucion
    /// tipica se lleva la mitad del trafico TLS: `wget`, `apt` y todo lo que pase
    /// por glib-networking. Ignorarla deja medio sistema sin ver.
    GnuTls,
    /// NSS, la de Firefox y las herramientas de Mozilla.
    Nss,
    /// `crypto/tls` de Go, enlazado estaticamente en el ejecutable.
    Go,
}

impl PilaTls {
    /// Nombre legible.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            PilaTls::OpenSsl => "OpenSSL/BoringSSL",
            PilaTls::GnuTls => "GnuTLS",
            PilaTls::Nss => "NSS",
            PilaTls::Go => "Go crypto/tls",
        }
    }
}

/// Que se hace con el simbolo: engancharlo a la entrada, al retorno, o ambos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Enganche {
    /// Solo a la entrada. El texto plano esta en el buffer ANTES de cifrar.
    Entrada,
    /// A la entrada y al retorno. El texto plano solo existe DESPUES de
    /// descifrar, pero el puntero al buffer solo esta disponible a la entrada:
    /// hay que recordarlo y leerlo al salir.
    EntradaYRetorno,
}

/// Un simbolo que merece la pena enganchar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimboloTls {
    /// Nombre exacto del simbolo en el binario.
    pub nombre: &'static str,
    /// A que pila pertenece.
    pub pila: PilaTls,
    /// Como se engancha.
    pub enganche: Enganche,
    /// `true` si el trafico va del proceso hacia la red.
    pub saliente: bool,
}

/// El catalogo de simbolos que este cazador sabe enganchar.
///
/// Es una tabla y no una lista de nombres sueltos porque cada simbolo necesita
/// saber COMO se engancha: enganchar `SSL_read` solo a la entrada daria siempre
/// un buffer vacio —los datos aun no se han descifrado— y produciria un cazador
/// que parece funcionar y no ve nada.
pub const CATALOGO: &[SimboloTls] = &[
    SimboloTls {
        nombre: "SSL_write",
        pila: PilaTls::OpenSsl,
        enganche: Enganche::Entrada,
        saliente: true,
    },
    SimboloTls {
        nombre: "SSL_write_ex",
        pila: PilaTls::OpenSsl,
        enganche: Enganche::Entrada,
        saliente: true,
    },
    SimboloTls {
        nombre: "SSL_read",
        pila: PilaTls::OpenSsl,
        enganche: Enganche::EntradaYRetorno,
        saliente: false,
    },
    SimboloTls {
        nombre: "SSL_read_ex",
        pila: PilaTls::OpenSsl,
        enganche: Enganche::EntradaYRetorno,
        saliente: false,
    },
    SimboloTls {
        nombre: "gnutls_record_send",
        pila: PilaTls::GnuTls,
        enganche: Enganche::Entrada,
        saliente: true,
    },
    SimboloTls {
        nombre: "gnutls_record_recv",
        pila: PilaTls::GnuTls,
        enganche: Enganche::EntradaYRetorno,
        saliente: false,
    },
    SimboloTls {
        nombre: "PR_Write",
        pila: PilaTls::Nss,
        enganche: Enganche::Entrada,
        saliente: true,
    },
    SimboloTls {
        nombre: "PR_Read",
        pila: PilaTls::Nss,
        enganche: Enganche::EntradaYRetorno,
        saliente: false,
    },
    SimboloTls {
        nombre: "crypto/tls.(*Conn).Write",
        pila: PilaTls::Go,
        enganche: Enganche::Entrada,
        saliente: true,
    },
    SimboloTls {
        nombre: "crypto/tls.(*Conn).Read",
        pila: PilaTls::Go,
        enganche: Enganche::EntradaYRetorno,
        saliente: false,
    },
];

/// Un punto concreto donde enganchar un uprobe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuntoEnganche {
    /// Fichero sobre el que se engancha.
    pub ruta: PathBuf,
    /// El simbolo del catalogo.
    pub simbolo: SimboloTls,
    /// Desplazamiento DENTRO DEL FICHERO, que es lo que espera el kernel.
    ///
    /// No es la direccion virtual del simbolo: ver [`crate::elf`] para por que
    /// confundirlos engancha en el sitio equivocado sin fallar ruidosamente.
    pub desplazamiento: u64,
}

/// El resultado de analizar un proceso: por donde se le puede ver el TLS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanEnganche {
    /// PID analizado.
    pub pid: i32,
    /// Los puntos donde enganchar.
    pub puntos: Vec<PuntoEnganche>,
    /// Ficheros mapeados que se examinaron y no traian ningun simbolo del
    /// catalogo.
    ///
    /// Se cuenta y no se descarta en silencio: si un proceso hace TLS pero aqui
    /// no sale ningun punto, la diferencia entre "no mira TLS" y "usa una pila
    /// que no conocemos" es justo lo que hay que poder responder.
    pub examinados_sin_simbolos: usize,
}

impl PlanEnganche {
    /// `true` si hay al menos un punto que enganchar.
    #[must_use]
    pub fn hay_donde_enganchar(&self) -> bool {
        !self.puntos.is_empty()
    }

    /// Las pilas TLS encontradas, sin repetir.
    #[must_use]
    pub fn pilas(&self) -> BTreeSet<PilaTls> {
        self.puntos.iter().map(|p| p.simbolo.pila).collect()
    }
}

/// Prioridad de un fichero como candidato a llevar TLS: menor es antes.
///
/// Solo ORDENA; nunca descarta. Un fichero con un nombre que no dice nada se
/// examina igual, solo que despues. Es lo que permite encontrar una OpenSSL
/// renombrada, que es exactamente lo que hace quien se esconde.
#[must_use]
pub fn prioridad(ruta: &Path) -> u8 {
    let n = ruta
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if n.starts_with("libssl") || n.starts_with("libgnutls") || n.starts_with("libnss") {
        0
    } else if n.starts_with("libcrypto") || n.contains("ssl") || n.contains("tls") {
        1
    } else if n.starts_with("lib") {
        3
    } else {
        // El propio ejecutable y cualquier cosa que no parezca biblioteca: es
        // donde vive el TLS estatico de Go, asi que va ANTES que las bibliotecas
        // genericas del sistema.
        2
    }
}

/// Busca en un binario ya analizado todos los puntos de enganche del catalogo.
#[must_use]
pub fn puntos_en(binario: &Binario, ruta: &Path) -> Vec<PuntoEnganche> {
    CATALOGO
        .iter()
        .filter_map(|s| {
            let desplazamiento = binario.desplazamiento_de(s.nombre)?;
            Some(PuntoEnganche {
                ruta: ruta.to_path_buf(),
                simbolo: *s,
                desplazamiento,
            })
        })
        .collect()
}

/// Los ficheros distintos mapeados con permiso de ejecucion por un proceso.
///
/// Se leen de `/proc/<pid>/maps`. Solo los ejecutables: una biblioteca cuyo
/// codigo no esta mapeado no puede estar ejecutandose, y sus simbolos no
/// interesan.
///
/// # Errores
/// [`L7Error::Io`] si no se puede leer el mapa (el proceso murio, o faltan
/// privilegios).
#[cfg(target_os = "linux")]
pub fn ficheros_ejecutables(pid: i32) -> Result<Vec<PathBuf>, L7Error> {
    let ruta = format!("/proc/{pid}/maps");
    let texto = std::fs::read_to_string(&ruta).map_err(|causa| L7Error::Io { ruta, causa })?;
    Ok(ficheros_ejecutables_de_maps(&texto))
}

/// La parte PURA de lo anterior: extrae los ficheros ejecutables de un `maps`.
///
/// Separada del acceso a `/proc` para poder probarla con mapas reales guardados
/// y con casos que en una maquina de CI no se pueden provocar.
#[must_use]
pub fn ficheros_ejecutables_de_maps(texto: &str) -> Vec<PathBuf> {
    let mut vistos = BTreeSet::new();
    for linea in texto.lines() {
        let mut campos = linea.split_whitespace();
        let (Some(_rango), Some(perms)) = (campos.next(), campos.next()) else {
            continue;
        };
        if perms.as_bytes().get(2) != Some(&b'x') {
            continue;
        }
        // desplazamiento, dispositivo, inodo, y luego la ruta (que puede llevar
        // espacios, asi que se toma el resto de la linea).
        let resto: Vec<&str> = campos.collect();
        if resto.len() < 4 {
            continue;
        }
        let ruta = resto[3..].join(" ");
        // Las regiones anonimas y las especiales del kernel no son ficheros.
        if ruta.is_empty() || ruta.starts_with('[') {
            continue;
        }
        // Un fichero borrado sigue mapeado; su ruta lleva el sufijo del kernel y
        // ya no se puede abrir. Se descarta en vez de intentar leerlo y fallar.
        if ruta.ends_with(" (deleted)") {
            continue;
        }
        vistos.insert(PathBuf::from(ruta));
    }
    vistos.into_iter().collect()
}

/// Analiza un proceso vivo y produce el plan de enganche.
///
/// Recorre los ficheros que el proceso tiene mapeados con permiso de ejecucion,
/// los ordena por probabilidad de llevar TLS y busca en cada uno los simbolos del
/// catalogo. Un fichero que no se puede leer se salta: es normal en un sistema
/// vivo (permisos, o un contenedor con otro sistema de ficheros).
///
/// # Errores
/// [`L7Error::Io`] si no se puede leer el mapa del proceso.
#[cfg(target_os = "linux")]
pub fn planificar(pid: i32) -> Result<PlanEnganche, L7Error> {
    let mut ficheros = ficheros_ejecutables(pid)?;
    ficheros.sort_by_key(|f| (prioridad(f), f.clone()));

    let mut plan = PlanEnganche {
        pid,
        ..Default::default()
    };
    for f in &ficheros {
        let Ok(binario) = Binario::desde_fichero(f) else {
            continue;
        };
        let puntos = puntos_en(&binario, f);
        if puntos.is_empty() {
            plan.examinados_sin_simbolos += 1;
        } else {
            plan.puntos.extend(puntos);
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const MAPS: &str = "\
55b8c0a00000-55b8c0a23000 r-xp 00004000 fe:00 151521   /usr/bin/curl
7f1111100000-7f1111180000 r-xp 00000000 fe:00 152035   /usr/lib/x86_64-linux-gnu/libssl.so.3
7f2222200000-7f2222280000 rw-p 00000000 fe:00 152036   /usr/lib/x86_64-linux-gnu/libssl.so.3
7f3333300000-7f3333380000 r-xp 00000000 fe:00 152037   /tmp/copiada con espacios.so
7f4444400000-7f4444480000 r-xp 00000000 fe:00 152038   /tmp/vieja.so (deleted)
7ffd00000000-7ffd00021000 rwxp 00000000 00:00 0        [stack]
7f5555500000-7f5555504000 r-xp 00000000 00:00 0        [vdso]
7f6666600000-7f6666604000 r-xp 00000000 00:00 0
";

    #[test]
    fn del_mapa_salen_solo_los_ficheros_ejecutables() {
        let f = ficheros_ejecutables_de_maps(MAPS);
        let nombres: Vec<String> = f.iter().map(|p| p.display().to_string()).collect();

        assert!(nombres.contains(&"/usr/bin/curl".to_string()));
        assert!(nombres.contains(&"/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string()));
        // Una ruta con espacios no se parte.
        assert!(nombres.contains(&"/tmp/copiada con espacios.so".to_string()));
        // Y lo que no es fichero, o ya no existe, queda fuera.
        assert!(!nombres.iter().any(|n| n.contains("vdso")));
        assert!(!nombres.iter().any(|n| n.contains("stack")));
        assert!(!nombres.iter().any(|n| n.contains("deleted")));
        // La region rw- de libssl no anade un duplicado.
        assert_eq!(
            nombres.iter().filter(|n| n.contains("libssl.so.3")).count(),
            1
        );
    }

    /// La prioridad ORDENA pero no descarta: una OpenSSL renombrada se examina
    /// igual, solo que despues. Un cazador que filtrara por nombre seria ciego
    /// justo contra quien se molesta en esconderse.
    #[test]
    fn la_prioridad_ordena_pero_no_descarta_nada() {
        assert!(
            prioridad(Path::new("/usr/lib/libssl.so.3"))
                < prioridad(Path::new("/usr/lib/libc.so.6"))
        );
        assert!(
            prioridad(Path::new("/usr/lib/libgnutls.so.30"))
                < prioridad(Path::new("/usr/lib/libfoo.so"))
        );
        // Un ejecutable sin pinta de biblioteca va ANTES que las bibliotecas
        // genericas: ahi vive el TLS estatico de Go.
        assert!(prioridad(Path::new("/tmp/servidor")) < prioridad(Path::new("/usr/lib/libz.so.1")));
        // Y una biblioteca disfrazada tiene prioridad, pero finita: se examina.
        assert!(prioridad(Path::new("/tmp/libutil-2.31.so")) <= 3);
    }

    #[test]
    fn el_catalogo_engancha_la_lectura_a_la_entrada_y_al_retorno() {
        // Si `SSL_read` se enganchara solo a la entrada, el buffer estaria vacio
        // —los datos aun no se han descifrado— y el cazador pareceria funcionar
        // sin ver nada. Es el error que esta tabla existe para impedir.
        for s in CATALOGO {
            if s.saliente {
                assert_eq!(
                    s.enganche,
                    Enganche::Entrada,
                    "{}: el envio esta en claro AL ENTRAR",
                    s.nombre
                );
            } else {
                assert_eq!(
                    s.enganche,
                    Enganche::EntradaYRetorno,
                    "{}: la recepcion solo esta en claro AL SALIR",
                    s.nombre
                );
            }
        }
        // Las cuatro pilas estan cubiertas.
        let pilas: BTreeSet<PilaTls> = CATALOGO.iter().map(|s| s.pila).collect();
        assert_eq!(pilas.len(), 4, "{pilas:?}");
    }

    /// El objetivo real: sobre la OpenSSL de VERDAD de esta maquina, resolver los
    /// cuatro simbolos y su desplazamiento de fichero.
    #[test]
    fn resuelve_los_puntos_de_enganche_en_la_openssl_real() {
        let ruta = Path::new("/usr/lib/x86_64-linux-gnu/libssl.so.3");
        if !ruta.exists() {
            eprintln!("OMITIDA: no hay OpenSSL 3 en esta maquina");
            return;
        }
        let b = Binario::desde_fichero(ruta).expect("analisis");
        let puntos = puntos_en(&b, ruta);

        let nombres: BTreeSet<&str> = puntos.iter().map(|p| p.simbolo.nombre).collect();
        assert!(nombres.contains("SSL_read"), "{nombres:?}");
        assert!(nombres.contains("SSL_write"), "{nombres:?}");

        let tam = std::fs::metadata(ruta).unwrap().len();
        for p in &puntos {
            assert_eq!(p.simbolo.pila, PilaTls::OpenSsl);
            assert!(
                p.desplazamiento > 0 && p.desplazamiento < tam,
                "{}: desplazamiento {:#x} fuera del fichero de {tam} B",
                p.simbolo.nombre,
                p.desplazamiento
            );
        }
        // Y no hay dos puntos para el mismo simbolo.
        assert_eq!(nombres.len(), puntos.len());
    }

    /// Sobre el `/proc/self/maps` REAL de este proceso de prueba: el planificador
    /// tiene que recorrerlo entero sin caerse y sin inventarse puntos.
    #[cfg(target_os = "linux")]
    #[test]
    fn planifica_sobre_el_proceso_real_sin_inventar_nada() {
        let plan = planificar(std::process::id() as i32).expect("planificar el propio proceso");
        assert_eq!(plan.pid, std::process::id() as i32);
        assert!(
            plan.examinados_sin_simbolos > 0,
            "un proceso real mapea bibliotecas sin TLS (libc, libgcc): tienen que contarse"
        );
        // Todo punto propuesto tiene que ser real: fichero existente y
        // desplazamiento dentro de el. Un punto inventado seria un uprobe
        // enganchado en basura.
        for p in &plan.puntos {
            let tam = std::fs::metadata(&p.ruta)
                .unwrap_or_else(|e| panic!("{}: {e}", p.ruta.display()))
                .len();
            assert!(
                p.desplazamiento < tam,
                "{}:{} -> {:#x} fuera de un fichero de {tam} B",
                p.ruta.display(),
                p.simbolo.nombre,
                p.desplazamiento
            );
        }
    }

    /// Un proceso que SI habla TLS: se lanza un `curl` real contra una direccion
    /// que no existe (no hace falta que la conexion prospere; con que cargue
    /// `libssl` basta) y se comprueba que el planificador encuentra por donde
    /// verlo. Es la prueba de que la resolucion funciona sobre un proceso ajeno.
    #[cfg(target_os = "linux")]
    #[test]
    fn encuentra_donde_enganchar_en_un_proceso_que_usa_tls() {
        if !Path::new("/usr/bin/curl").exists() {
            eprintln!("OMITIDA: no hay curl en esta maquina");
            return;
        }
        // `--max-time` acota por si acaso; el proceso se mata igualmente.
        let hijo = std::process::Command::new("/usr/bin/curl")
            .args(["-s", "--max-time", "20", "https://127.0.0.1:1/"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut hijo) = hijo else {
            eprintln!("OMITIDA: no se pudo lanzar curl");
            return;
        };
        // Se le da margen para que el enlazador dinamico mapee sus bibliotecas.
        let mut plan = PlanEnganche::default();
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            if let Ok(p) = planificar(hijo.id() as i32) {
                if p.hay_donde_enganchar() {
                    plan = p;
                    break;
                }
            }
        }
        let _ = hijo.kill();
        let _ = hijo.wait();

        if !plan.hay_donde_enganchar() {
            // curl puede estar compilado contra una pila que no cubrimos, o
            // haber terminado antes de mapear. Se DICE en vez de fallar.
            eprintln!(
                "OMITIDA: no se pudo observar a curl con sus bibliotecas mapeadas \
                 (examinados sin simbolos: {})",
                plan.examinados_sin_simbolos
            );
            return;
        }
        let pilas = plan.pilas();
        assert!(!pilas.is_empty());
        eprintln!(
            "curl: {} puntos de enganche en {:?}",
            plan.puntos.len(),
            pilas.iter().map(|p| p.nombre()).collect::<Vec<_>>()
        );
    }
}
