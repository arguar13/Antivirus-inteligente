//! Lo que el malware mira para saber si esta en un sandbox, y que se hace.
//!
//! # Por que esto es codigo y no un parrafo en un documento
//!
//! Un sandbox que informa «sin comportamiento malicioso» cuando lo que paso fue
//! que la muestra **lo detecto y se marcho** no esta equivocado: esta mintiendo
//! por omision. Y el que lee el informe no tiene forma de saberlo, porque los dos
//! casos se escriben igual.
//!
//! La unica salida honesta es que cada informe lleve dentro **que evasiones se
//! contrarrestan y cuales no**. Si es un parrafo en un documento, nadie lo lee en
//! el momento en el que importa. Si es un campo del informe, se lee siempre.
//!
//! # Y la otra mitad: detectar que la muestra miro
//!
//! Contrarrestar tiene limite. Lo que no lo tiene es **darse cuenta de que la
//! muestra estuvo mirando**: si la traza ensena consultas a `/sys/class/dmi`, a
//! `/proc/cpuinfo` y a la lista de procesos, y justo despues la muestra sale sin
//! hacer nada, eso no es «benigna». Es [`Sospecha::ProbableEvasion`], y es un
//! hallazgo, no la ausencia de uno.

use std::collections::BTreeSet;

use aegis_invitado::protocolo::Evento;
use serde::{Deserialize, Serialize};

/// Que mira el malware para reconocer un entorno de analisis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tecnica {
    /// `CPUID`: el bit de hipervisor y la hoja del fabricante.
    CpuidHipervisor,
    /// Cadenas de DMI/SMBIOS: fabricante, modelo, numero de serie.
    IdentificadoresDeHardware,
    /// El prefijo del fabricante en la direccion MAC.
    PrefijoMac,
    /// Modelo y numero de serie de los discos.
    DiscoVirtual,
    /// Cuanto lleva encendida la maquina.
    TiempoEncendida,
    /// Herramientas de analisis instaladas.
    HerramientasDeAnalisis,
    /// Rastro de que alguien use la maquina: documentos, historial, ficheros recientes.
    ActividadDeUsuario,
    /// Nucleos, memoria y disco: un sandbox suele ser pequeno.
    RecursosEscasos,
    /// Medir el tiempo: `RDTSC`, relojes, si las esperas se aceleran.
    MedicionDeTiempos,
    /// Comprobar que la red es de verdad: TLS que valide, latencias creibles.
    RedCreible,
    /// Esperar mucho antes de actuar, a ver si el analisis se cansa.
    EsperaProlongada,
}

impl Tecnica {
    /// Nombre estable para el informe.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Tecnica::CpuidHipervisor => "cpuid-hipervisor",
            Tecnica::IdentificadoresDeHardware => "identificadores-de-hardware",
            Tecnica::PrefijoMac => "prefijo-mac",
            Tecnica::DiscoVirtual => "disco-virtual",
            Tecnica::TiempoEncendida => "tiempo-encendida",
            Tecnica::HerramientasDeAnalisis => "herramientas-de-analisis",
            Tecnica::ActividadDeUsuario => "actividad-de-usuario",
            Tecnica::RecursosEscasos => "recursos-escasos",
            Tecnica::MedicionDeTiempos => "medicion-de-tiempos",
            Tecnica::RedCreible => "red-creible",
            Tecnica::EsperaProlongada => "espera-prolongada",
        }
    }

    /// Rutas del invitado cuya lectura delata que se esta usando esta tecnica.
    ///
    /// No es exhaustivo ni puede serlo, pero cubre lo que mira el noventa por
    /// ciento del malware de Linux que se molesta en mirar algo.
    #[must_use]
    pub fn rastros(self) -> &'static [&'static str] {
        match self {
            Tecnica::CpuidHipervisor => &["/proc/cpuinfo"],
            Tecnica::IdentificadoresDeHardware => &[
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor",
                "/sys/devices/virtual/dmi",
            ],
            Tecnica::PrefijoMac => &["/sys/class/net"],
            Tecnica::DiscoVirtual => &["/sys/block", "/proc/scsi/scsi", "/dev/disk/by-id"],
            Tecnica::TiempoEncendida => &["/proc/uptime"],
            Tecnica::HerramientasDeAnalisis => &[
                "/usr/bin/strace",
                "/usr/bin/gdb",
                "/usr/sbin/tcpdump",
                "/proc/self/status",
            ],
            // NO va `/home` aqui, y la ausencia es deliberada. Un ransomware
            // que cifra `/home/victima/*` no esta comprobando si alguien usa la
            // maquina: la esta atacando. Marcarlo como «miro el entorno» seria
            // confundir el ataque con la inspeccion previa, y exactamente al
            // reves. Los rastros son artefactos de COMPROBACION, no directorios.
            Tecnica::ActividadDeUsuario => &[
                "/root/.bash_history",
                "/var/log/wtmp",
                "/var/log/lastlog",
                "/var/log/utmp",
                "/root/.local/share/recently-used.xbel",
            ],
            Tecnica::RecursosEscasos => &["/proc/meminfo", "/sys/devices/system/cpu"],
            Tecnica::MedicionDeTiempos => &["/proc/timer_list"],
            Tecnica::RedCreible => &["/etc/resolv.conf"],
            Tecnica::EsperaProlongada => &[],
        }
    }
}

/// Que se hace contra una tecnica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Contramedida {
    /// Se contrarresta, y como.
    Aplicada {
        /// Que se hace exactamente.
        como: String,
    },
    /// Se contrarresta a medias, y se dice por donde se escapa.
    Parcial {
        /// Lo que si se hace.
        como: String,
        /// Lo que aun asi se ve.
        hueco: String,
    },
    /// No se contrarresta, y se dice por que.
    ///
    /// Esta variante es la razon de ser del modulo. Un catalogo en el que todo
    /// saliera «aplicada» seria un catalogo inutil, porque la pregunta que el
    /// analista tiene es justo cual falta.
    Ninguna {
        /// Por que no.
        por_que: String,
    },
}

impl Contramedida {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Contramedida::Aplicada { .. } => "aplicada",
            Contramedida::Parcial { .. } => "parcial",
            Contramedida::Ninguna { .. } => "ninguna",
        }
    }

    /// Si deja al descubierto algo que la muestra puede ver.
    #[must_use]
    pub fn deja_ver(&self) -> bool {
        !matches!(self, Contramedida::Aplicada { .. })
    }
}

/// Una tecnica y lo que se hace contra ella.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cobertura {
    /// La tecnica.
    pub tecnica: Tecnica,
    /// Lo que se hace.
    pub contramedida: Contramedida,
}

/// El catalogo completo, tal y como va dentro de cada informe.
///
/// Se actualiza cuando cambia la imagen del invitado o la configuracion del
/// hipervisor, y **no antes**: una entrada que dice «aplicada» sin que lo este es
/// peor que decir que no se cubre.
#[must_use]
pub fn catalogo() -> Vec<Cobertura> {
    use Contramedida::{Aplicada, Ninguna, Parcial};
    use Tecnica as T;
    vec![
        Cobertura {
            tecnica: T::CpuidHipervisor,
            contramedida: Parcial {
                como: "el hipervisor no expone la hoja de fabricante 0x40000000".to_string(),
                hueco: "el bit 31 de ECX en la hoja 1 lo pone el hardware de virtualizacion y no \
                        se puede quitar sin interceptar CPUID, que cuesta un orden de magnitud en \
                        rendimiento"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::IdentificadoresDeHardware,
            contramedida: Aplicada {
                como: "las cadenas de DMI de la imagen se fijan a las de un fabricante corriente, \
                       con numero de serie distinto en cada detonacion"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::PrefijoMac,
            contramedida: Aplicada {
                como: "la MAC se genera con un prefijo de fabricante de tarjetas de red real, no \
                       con el del hipervisor"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::DiscoVirtual,
            contramedida: Parcial {
                como: "el modelo y el numero de serie del disco se fijan a los de un disco comun"
                    .to_string(),
                hueco: "el controlador sigue siendo virtio, y eso se ve en /sys/block".to_string(),
            },
        },
        Cobertura {
            tecnica: T::TiempoEncendida,
            contramedida: Parcial {
                como: "la imagen arranca con un tiempo de encendido simulado de varias horas"
                    .to_string(),
                hueco: "los tiempos de los procesos del sistema no cuadran con ese tiempo si se \
                        miran en detalle"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::HerramientasDeAnalisis,
            contramedida: Aplicada {
                como: "la imagen del invitado no trae depuradores, capturadores ni herramientas \
                       de analisis; el agente invitado es un binario sin nombre delator"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::ActividadDeUsuario,
            contramedida: Parcial {
                como: "la imagen trae documentos, historial de consola y ficheros recientes \
                       generados de forma reproducible"
                    .to_string(),
                hueco: "no hay raton ni teclado moviendose durante la detonacion: una muestra que \
                        espere a que alguien use la maquina no vera a nadie"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::RecursosEscasos,
            contramedida: Parcial {
                como: "por omision dos nucleos, 1 GiB de RAM y 2 GiB de disco, que es mas de lo \
                       que suele dar un sandbox"
                    .to_string(),
                hueco: "sigue siendo menos que un escritorio de verdad, y subirlo cuesta puestos \
                        de detonacion"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::MedicionDeTiempos,
            contramedida: Ninguna {
                por_que: "no se acelera el reloj ni se falsean las esperas. Acelerarlas haria que \
                          una muestra que mide RDTSC contra el reloj de pared viera la \
                          incoherencia, que es MAS detectable que la espera honesta. El coste es \
                          que una muestra que espera media hora agota el plazo"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::RedCreible,
            contramedida: Ninguna {
                por_que: "la red es falsa y se nota: todos los nombres resuelven, no hay latencia \
                          creible, y un TLS contra el servicio simulado no valida contra ninguna \
                          autoridad. Enganar esto exigiria una autoridad propia en el almacen del \
                          invitado, que es a su vez un artefacto delator"
                    .to_string(),
            },
        },
        Cobertura {
            tecnica: T::EsperaProlongada,
            contramedida: Ninguna {
                por_que: "una muestra que espera mas que el plazo agota el plazo, y el informe \
                          dice que se corto. No se disimula: un informe que presentara eso como \
                          «no hizo nada» seria exactamente la mentira que este modulo evita"
                    .to_string(),
            },
        },
    ]
}

/// Que se puede decir de la fiabilidad de un veredicto «no hizo nada».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sospecha {
    /// No hay senales de que la muestra estuviera mirando.
    Ninguna,
    /// La muestra miro el entorno, pero siguio adelante.
    ///
    /// Mirar no es evadir: mucho software legitimo consulta `/proc/cpuinfo`.
    MiroYSiguio,
    /// La muestra miro el entorno y se marcho sin hacer nada.
    ///
    /// Es el caso que un sandbox deshonesto informa como «benigna».
    ProbableEvasion,
}

impl Sospecha {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Sospecha::Ninguna => "ninguna",
            Sospecha::MiroYSiguio => "miro-y-siguio",
            Sospecha::ProbableEvasion => "probable-evasion",
        }
    }

    /// Explicacion para el informe.
    #[must_use]
    pub fn detalle(self) -> &'static str {
        match self {
            Sospecha::Ninguna => "no se vieron consultas al entorno de ejecucion",
            Sospecha::MiroYSiguio => {
                "la muestra consulto el entorno y siguio ejecutando: mirar no es evadir, y mucho \
                 software legitimo lo hace"
            }
            Sospecha::ProbableEvasion => {
                "la muestra consulto el entorno y salio enseguida sin hacer nada mas: esto NO es \
                 «sin comportamiento malicioso», es una deteccion de sandbox probable, y el \
                 informe no vale como veredicto de inocuidad"
            }
        }
    }
}

/// Eventos de comportamiento por debajo de los cuales «no hizo nada» es literal.
///
/// El numero no es magico: son los accesos que hace cualquier proceso al arrancar
/// —cargar el enlazador, leer la configuracion regional, abrir la biblioteca de C—
/// antes de hacer nada suyo. Por debajo de eso, la muestra arranco y salio.
pub const MINIMO_ACTIVIDAD: usize = 12;

/// Mira una traza y dice si la muestra parece haber reconocido el entorno.
///
/// # Como se decide
///
/// Se busca la coincidencia de dos cosas: que la muestra **consultara** rastros
/// del entorno, y que **no hiciera nada** despues. Cualquiera de las dos por
/// separado no significa nada: un instalador legitimo lee `/proc/cpuinfo`, y un
/// programa que hace poco puede simplemente hacer poco. Juntas, si.
#[must_use]
pub fn analizar(eventos: &[&Evento]) -> (Sospecha, BTreeSet<Tecnica>) {
    let mut vistas: BTreeSet<Tecnica> = BTreeSet::new();
    let mut actividad = 0usize;

    let catalogo_rastros: Vec<(Tecnica, &'static [&'static str])> = [
        Tecnica::CpuidHipervisor,
        Tecnica::IdentificadoresDeHardware,
        Tecnica::PrefijoMac,
        Tecnica::DiscoVirtual,
        Tecnica::TiempoEncendida,
        Tecnica::HerramientasDeAnalisis,
        Tecnica::ActividadDeUsuario,
        Tecnica::RecursosEscasos,
        Tecnica::MedicionDeTiempos,
        Tecnica::RedCreible,
    ]
    .into_iter()
    .map(|t| (t, t.rastros()))
    .collect();

    for e in eventos {
        match e {
            Evento::Fichero { ruta, accion, .. } => {
                let mut era_rastro = false;
                for (tecnica, rastros) in &catalogo_rastros {
                    if rastros.iter().any(|r| ruta.starts_with(r)) {
                        vistas.insert(*tecnica);
                        era_rastro = true;
                    }
                }
                // Leer un rastro del entorno NO cuenta como actividad: es
                // justamente lo que hace la muestra que esta decidiendo si
                // quedarse. Escribir si cuenta, mire lo que mire.
                if !era_rastro
                    || matches!(
                        accion,
                        aegis_invitado::protocolo::AccionFichero::Escribe
                            | aegis_invitado::protocolo::AccionFichero::Borra
                            | aegis_invitado::protocolo::AccionFichero::Renombra
                    )
                {
                    actividad += 1;
                }
            }
            Evento::Red { .. } => actividad += 1,
            Evento::Proceso { accion, .. } => {
                if matches!(accion, aegis_invitado::protocolo::AccionProceso::Ejecuta) {
                    actividad += 1;
                }
            }
            Evento::Llamada { .. } => actividad += 1,
            _ => {}
        }
    }

    let sospecha = if vistas.is_empty() {
        Sospecha::Ninguna
    } else if actividad < MINIMO_ACTIVIDAD {
        Sospecha::ProbableEvasion
    } else {
        Sospecha::MiroYSiguio
    };
    (sospecha, vistas)
}

/// Resumen del catalogo para el informe, en texto.
#[must_use]
pub fn resumen() -> String {
    let c = catalogo();
    let aplicadas = c
        .iter()
        .filter(|x| matches!(x.contramedida, Contramedida::Aplicada { .. }))
        .count();
    let parciales = c
        .iter()
        .filter(|x| matches!(x.contramedida, Contramedida::Parcial { .. }))
        .count();
    let ninguna: Vec<&str> = c
        .iter()
        .filter(|x| matches!(x.contramedida, Contramedida::Ninguna { .. }))
        .map(|x| x.tecnica.nombre())
        .collect();

    format!(
        "{} tecnicas catalogadas: {aplicadas} contrarrestadas, {parciales} a medias, \
         {} sin contrarrestar ({})",
        c.len(),
        ninguna.len(),
        ninguna.join(", ")
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_invitado::protocolo::{AccionFichero, AccionProceso};

    fn lee(ruta: &str) -> Evento {
        Evento::Fichero {
            pid: 7,
            accion: AccionFichero::Lee,
            ruta: ruta.into(),
            bytes: 0,
        }
    }

    fn escribe(ruta: &str) -> Evento {
        Evento::Fichero {
            pid: 7,
            accion: AccionFichero::Escribe,
            ruta: ruta.into(),
            bytes: 4096,
        }
    }

    // --- El catalogo -------------------------------------------------------

    #[test]
    fn el_catalogo_declara_lo_que_no_se_contrarresta() {
        // Un catalogo en el que todo saliera «aplicada» seria inutil, porque la
        // pregunta que el analista tiene es justo cual falta.
        let c = catalogo();
        let sin_cubrir: Vec<&Cobertura> = c
            .iter()
            .filter(|x| matches!(x.contramedida, Contramedida::Ninguna { .. }))
            .collect();
        assert!(
            !sin_cubrir.is_empty(),
            "si no falta ninguna, el catalogo esta mintiendo"
        );
        for x in sin_cubrir {
            match &x.contramedida {
                Contramedida::Ninguna { por_que } => assert!(
                    por_que.len() > 40,
                    "«{}» no se cubre y no dice por que en condiciones",
                    x.tecnica.nombre()
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn las_parciales_dicen_por_donde_se_escapan() {
        for x in catalogo() {
            if let Contramedida::Parcial { hueco, .. } = &x.contramedida {
                assert!(
                    hueco.len() > 30,
                    "«{}» es parcial sin decir por donde se ve",
                    x.tecnica.nombre()
                );
            }
        }
    }

    #[test]
    fn no_hay_tecnicas_repetidas_en_el_catalogo() {
        let c = catalogo();
        let unicas: BTreeSet<Tecnica> = c.iter().map(|x| x.tecnica).collect();
        assert_eq!(unicas.len(), c.len(), "hay tecnicas duplicadas");
    }

    #[test]
    fn el_resumen_nombra_lo_que_queda_al_descubierto() {
        let r = resumen();
        assert!(r.contains("sin contrarrestar"), "{r}");
        assert!(
            r.contains("medicion-de-tiempos") || r.contains("red-creible"),
            "{r}"
        );
    }

    #[test]
    fn no_se_acelera_el_reloj_y_se_explica_por_que() {
        // Acelerar las esperas hace que una muestra que mide RDTSC contra el
        // reloj de pared vea la incoherencia: es MAS detectable que la espera
        // honesta.
        let x = catalogo()
            .into_iter()
            .find(|x| x.tecnica == Tecnica::MedicionDeTiempos)
            .unwrap();
        match x.contramedida {
            Contramedida::Ninguna { por_que } => {
                assert!(por_que.contains("acelera"), "{por_que}");
            }
            otro => panic!("no se puede decir que se contrarresta: {otro:?}"),
        }
    }

    // --- La deteccion de que la muestra miro -------------------------------

    #[test]
    fn una_muestra_que_mira_y_se_marcha_no_es_benigna() {
        // EL CASO QUE JUSTIFICA EL MODULO. Un sandbox deshonesto informa esto
        // como «sin comportamiento malicioso».
        let eventos = [
            lee("/sys/class/dmi/id/product_name"),
            lee("/proc/cpuinfo"),
            lee("/proc/uptime"),
        ];
        let refs: Vec<&Evento> = eventos.iter().collect();
        let (s, vistas) = analizar(&refs);

        assert_eq!(s, Sospecha::ProbableEvasion);
        assert!(vistas.contains(&Tecnica::IdentificadoresDeHardware));
        assert!(vistas.contains(&Tecnica::CpuidHipervisor));
        assert!(s.detalle().contains("NO es"), "{}", s.detalle());
    }

    #[test]
    fn mirar_el_entorno_y_seguir_trabajando_no_es_evadir() {
        // Mucho software legitimo consulta /proc/cpuinfo. La senal es la
        // coincidencia de mirar Y no hacer nada, no cualquiera de las dos.
        let mut eventos = vec![lee("/proc/cpuinfo")];
        for i in 0..30 {
            eventos.push(escribe(&format!("/tmp/trabajo{i}.dat")));
        }
        let refs: Vec<&Evento> = eventos.iter().collect();
        let (s, vistas) = analizar(&refs);

        assert_eq!(s, Sospecha::MiroYSiguio);
        assert!(vistas.contains(&Tecnica::CpuidHipervisor));
    }

    #[test]
    fn una_muestra_que_ni_mira_no_levanta_sospecha() {
        let eventos: Vec<Evento> = (0..30)
            .map(|i| escribe(&format!("/home/victima/doc{i}.txt.cifrado")))
            .collect();
        let refs: Vec<&Evento> = eventos.iter().collect();
        let (s, vistas) = analizar(&refs);
        assert_eq!(s, Sospecha::Ninguna);
        assert!(vistas.is_empty());
    }

    #[test]
    fn cifrar_el_directorio_del_usuario_no_es_mirar_el_entorno() {
        // EL FALLO QUE ESTA PRUEBA CIERRA: con `/home` en los rastros, un
        // ransomware que cifra `/home/victima/*` salia marcado como que habia
        // estado comprobando si alguien usa la maquina. Es exactamente al reves:
        // no la esta comprobando, la esta atacando. Los rastros tienen que ser
        // artefactos de COMPROBACION, no directorios enteros.
        let eventos: Vec<Evento> = (0..50)
            .map(|i| escribe(&format!("/home/victima/documentos/informe{i}.docx.cifrado")))
            .collect();
        let refs: Vec<&Evento> = eventos.iter().collect();
        let (s, vistas) = analizar(&refs);
        assert_eq!(s, Sospecha::Ninguna, "vistas: {vistas:?}");
        assert!(
            !vistas.contains(&Tecnica::ActividadDeUsuario),
            "cifrar no es comprobar"
        );
    }

    #[test]
    fn comprobar_si_alguien_usa_la_maquina_si_se_detecta() {
        // La contraparte: lo que SI es comprobacion.
        let eventos = [
            lee("/root/.bash_history"),
            lee("/var/log/wtmp"),
            lee("/var/log/lastlog"),
        ];
        let refs: Vec<&Evento> = eventos.iter().collect();
        let (s, vistas) = analizar(&refs);
        assert!(vistas.contains(&Tecnica::ActividadDeUsuario));
        assert_eq!(s, Sospecha::ProbableEvasion);
    }

    #[test]
    fn leer_un_rastro_no_cuenta_como_actividad_pero_escribirlo_si() {
        // Leer /proc/cpuinfo es justo lo que hace la muestra que esta decidiendo
        // si quedarse. Escribir cuenta, mire lo que mire.
        let solo_lee: Vec<Evento> = (0..40).map(|_| lee("/proc/cpuinfo")).collect();
        let refs: Vec<&Evento> = solo_lee.iter().collect();
        assert_eq!(
            analizar(&refs).0,
            Sospecha::ProbableEvasion,
            "leer cuarenta veces el mismo rastro no es trabajar"
        );

        let mut mezcla = vec![lee("/proc/cpuinfo")];
        for i in 0..20 {
            mezcla.push(escribe(&format!("/proc/cpuinfo{i}")));
        }
        let refs: Vec<&Evento> = mezcla.iter().collect();
        assert_eq!(analizar(&refs).0, Sospecha::MiroYSiguio);
    }

    #[test]
    fn ejecutar_otros_procesos_cuenta_como_actividad() {
        let mut eventos = vec![lee("/sys/class/dmi/id/sys_vendor")];
        for i in 0..20 {
            eventos.push(Evento::Proceso {
                pid: 100 + i,
                padre: 7,
                accion: AccionProceso::Ejecuta,
                imagen: "/bin/sh".into(),
                argumentos: Vec::new(),
            });
        }
        let refs: Vec<&Evento> = eventos.iter().collect();
        assert_eq!(analizar(&refs).0, Sospecha::MiroYSiguio);
    }

    #[test]
    fn cada_tecnica_con_rastros_tiene_rutas_absolutas() {
        for t in [
            Tecnica::CpuidHipervisor,
            Tecnica::IdentificadoresDeHardware,
            Tecnica::TiempoEncendida,
            Tecnica::RecursosEscasos,
        ] {
            let r = t.rastros();
            assert!(!r.is_empty(), "{} sin rastros", t.nombre());
            for ruta in r {
                assert!(ruta.starts_with('/'), "{ruta} no es absoluta");
            }
        }
    }
}
