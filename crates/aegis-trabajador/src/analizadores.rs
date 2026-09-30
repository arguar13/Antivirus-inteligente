//! Los analizadores de bytes no confiables que corren DENTRO del trabajador.
//!
//! Cada uno envuelve un parser del producto y traduce lo que encuentra a
//! hallazgos del plano estatico. La funcion [`Analizadores::analizar`] es la que
//! ejecuta el trabajador y la que ejercen los objetivos de fuzzing: la invariante
//! «ningun parser entra en el trabajador sin objetivo de fuzzing» se comprueba
//! contra [`Analizador::todos`].
//!
//! # Por que la traduccion es conservadora
//!
//! Un indicio de forma (una seccion escribible y ejecutable, un segmento raro)
//! lo tienen tambien empaquetadores comerciales y compiladores viejos. Se
//! traduce a `Sospechoso` con confianza BAJA y nunca a `Malicioso`: el plano
//! estatico no decide solo, y que un indicio de forma llene la consola de
//! sospechosos enseñaria a ignorarla. Medir cuantos falsos positivos da cada
//! analizador es la FASE 4; hasta entonces todo esto corre en solo-auditoria.

use aegis_entidad::{Confianza, Juicio, Motor, Severidad};

use crate::protocolo::{Hallazgo, Informe};

/// Un analizador que el trabajador sabe ejecutar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Analizador {
    /// Modelo estatico de clasificacion sobre ELF y PE (aegis-ml).
    Modelo,
    /// Estructura de ejecutables de Windows (aegis-pe).
    Pe,
    /// Estructura de binarios de macOS (aegis-macho).
    Macho,
    /// Capacidades por desensamblado del codigo de un ELF (aegis-disasm).
    Desensamblado,
    /// Emulacion de codigo suelto (aegis-emu), para lo que se ejecuta sin
    /// fichero: la region escrita y ejecutada, un `memfd`.
    Emulacion,
    /// PRUEBA: entra en panico si los datos empiezan por `PANICO`.
    #[cfg(feature = "prueba-fallos")]
    PruebaPanico,
    /// PRUEBA: reserva y toca memoria hasta que el cgroup lo mate.
    #[cfg(feature = "prueba-fallos")]
    PruebaMemoria,
    /// PRUEBA: no termina nunca; lo corta el plazo del cliente.
    #[cfg(feature = "prueba-fallos")]
    PruebaBucle,
    /// PRUEBA: intenta abrir un fichero y un socket desde dentro, e informa.
    #[cfg(feature = "prueba-fallos")]
    PruebaSonda,
}

impl Analizador {
    /// Los analizadores de produccion. Cada uno tiene su objetivo de fuzzing.
    #[must_use]
    pub fn todos() -> &'static [Analizador] {
        &[
            Analizador::Modelo,
            Analizador::Pe,
            Analizador::Macho,
            Analizador::Desensamblado,
            Analizador::Emulacion,
        ]
    }

    /// Nombre estable: el del objetivo de fuzzing es `trabajador_<nombre>`.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Analizador::Modelo => "modelo",
            Analizador::Pe => "pe",
            Analizador::Macho => "macho",
            Analizador::Desensamblado => "desensamblado",
            Analizador::Emulacion => "emulacion",
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaPanico => "prueba-panico",
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaMemoria => "prueba-memoria",
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaBucle => "prueba-bucle",
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaSonda => "prueba-sonda",
        }
    }

    /// Discriminante en el cable. Cambiarlo obliga a subir la version.
    #[must_use]
    pub fn tag(self) -> u16 {
        match self {
            Analizador::Modelo => 1,
            Analizador::Pe => 2,
            Analizador::Macho => 3,
            Analizador::Desensamblado => 4,
            Analizador::Emulacion => 5,
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaPanico => 900,
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaMemoria => 901,
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaBucle => 902,
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaSonda => 903,
        }
    }

    /// Recupera un analizador de su discriminante.
    #[must_use]
    pub fn desde_tag(t: u16) -> Option<Analizador> {
        match t {
            1 => Some(Analizador::Modelo),
            2 => Some(Analizador::Pe),
            3 => Some(Analizador::Macho),
            4 => Some(Analizador::Desensamblado),
            5 => Some(Analizador::Emulacion),
            #[cfg(feature = "prueba-fallos")]
            900 => Some(Analizador::PruebaPanico),
            #[cfg(feature = "prueba-fallos")]
            901 => Some(Analizador::PruebaMemoria),
            #[cfg(feature = "prueba-fallos")]
            902 => Some(Analizador::PruebaBucle),
            #[cfg(feature = "prueba-fallos")]
            903 => Some(Analizador::PruebaSonda),
            _ => None,
        }
    }

    /// Los que el trabajador anuncia en su saludo.
    #[must_use]
    pub fn disponibles() -> Vec<Analizador> {
        #[cfg(not(feature = "prueba-fallos"))]
        let v = Analizador::todos().to_vec();
        #[cfg(feature = "prueba-fallos")]
        let v = {
            let mut v = Analizador::todos().to_vec();
            v.extend([
                Analizador::PruebaPanico,
                Analizador::PruebaMemoria,
                Analizador::PruebaBucle,
                Analizador::PruebaSonda,
            ]);
            v
        };
        v
    }
}

/// Que analizadores tocan a un fichero ejecutable, segun su numero magico.
#[must_use]
pub fn para_ejecutable(cabeza: &[u8]) -> Vec<Analizador> {
    if cabeza.starts_with(b"\x7fELF") {
        vec![Analizador::Modelo, Analizador::Desensamblado]
    } else if cabeza.starts_with(b"MZ") {
        vec![Analizador::Modelo, Analizador::Pe]
    } else if matches!(
        cabeza.get(..4),
        Some([0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe])
    ) {
        vec![Analizador::Macho]
    } else {
        Vec::new()
    }
}

fn hallazgo(
    firma: Motor,
    juicio: Juicio,
    severidad: Severidad,
    confianza: Confianza,
    porque: String,
) -> Hallazgo {
    Hallazgo {
        firma,
        juicio,
        severidad,
        confianza,
        porque,
    }
}

/// Los analizadores, con el estado que conviene cargar una sola vez.
#[derive(Default)]
pub struct Analizadores {
    modelo: Option<Result<aegis_ml::MalwareModel, String>>,
}

impl Analizadores {
    /// Carga lo que es de confianza y cuesta cargar (el modelo empotrado).
    ///
    /// El trabajador lo llama ANTES de confinarse: el modelo viene dentro del
    /// propio binario, y cargarlo despues exigiria permitir en seccomp llamadas
    /// que el analisis de un fichero hostil no necesita.
    pub fn precargar(&mut self) {
        self.modelo
            .get_or_insert_with(|| aegis_ml::MalwareModel::embedded().map_err(|e| e.to_string()));
    }

    /// Analiza unos bytes.
    ///
    /// # Errores
    ///
    /// El motivo por el que el analizador no pudo mirar (datos ilegibles para
    /// su formato, modelo que no carga). Se publica como `SinDatos` con esa
    /// causa, nunca como limpio.
    pub fn analizar(&mut self, a: Analizador, datos: &[u8]) -> Result<Informe, String> {
        match a {
            Analizador::Modelo => self.modelo(datos),
            Analizador::Pe => Ok(pe(datos)),
            Analizador::Macho => Ok(macho(datos)),
            Analizador::Desensamblado => desensamblado(datos),
            Analizador::Emulacion => Ok(emulacion(datos)),
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaPanico => {
                assert!(
                    !datos.starts_with(b"PANICO"),
                    "panico provocado por la prueba de confinamiento"
                );
                Ok(Informe {
                    hallazgos: Vec::new(),
                    completo: true,
                })
            }
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaMemoria => {
                // Reserva y TOCA memoria sin fin: el techo del cgroup lo mata.
                let mut retenido: Vec<Vec<u8>> = Vec::new();
                loop {
                    retenido.push(vec![0xA5u8; 8 * 1024 * 1024]);
                    std::hint::black_box(&retenido);
                }
            }
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaBucle => loop {
                std::hint::spin_loop();
            },
            #[cfg(feature = "prueba-fallos")]
            Analizador::PruebaSonda => {
                // Lo que un parser comprometido intentaria primero: leer un
                // fichero del sistema y abrir un socket. Se informa del error
                // tal cual; la prueba exige que los dos fallen.
                let fichero = match std::fs::read("/etc/hostname") {
                    Ok(_) => "abrio".to_string(),
                    Err(e) => format!("{:?}", e.kind()),
                };
                let red = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(_) => "abrio".to_string(),
                    Err(e) => format!("{:?}", e.kind()),
                };
                Ok(Informe {
                    hallazgos: vec![hallazgo(
                        Motor::Estatico,
                        Juicio::NoConcluyente,
                        Severidad::Info,
                        Confianza::NULA,
                        format!("fichero={fichero} red={red}"),
                    )],
                    completo: true,
                })
            }
        }
    }

    fn modelo(&mut self, datos: &[u8]) -> Result<Informe, String> {
        let modelo = self
            .modelo
            .get_or_insert_with(|| aegis_ml::MalwareModel::embedded().map_err(|e| e.to_string()));
        let modelo = modelo
            .as_ref()
            .map_err(|e| format!("el modelo no carga: {e}"))?;
        let rasgos = aegis_ml::FeatureExtractor::default().extract(datos);
        let vector = aegis_ml::features::to_vector(&rasgos);
        let p = modelo.predict(&vector).map_err(|e| e.to_string())?;
        let milesimas = (p.score.clamp(0.0, 1.0) * 1000.0) as u16;
        let confianza = aegis_entidad::escala::de_puntuacion(milesimas);
        if aegis_ml::EMBEDDED_MODEL_ES_REFERENCIA {
            // El modelo de referencia no esta entrenado: su puntuacion se ve,
            // pero no acusa ni absuelve (ver aegis_ml::EMBEDDED_MODEL_ES_REFERENCIA).
            return Ok(Informe {
                hallazgos: vec![hallazgo(
                    Motor::Aprendizaje,
                    Juicio::NoConcluyente,
                    Severidad::Info,
                    Confianza::NULA,
                    format!(
                        "modelo de referencia sin entrenar: puntuacion {:.3} ({:?}); no es evidencia",
                        p.score, p.verdict
                    ),
                )],
                completo: true,
            });
        }
        let (juicio, severidad) = match p.verdict {
            aegis_ml::Verdict::Record => (Juicio::Limpio, Severidad::Info),
            aegis_ml::Verdict::Watch => (Juicio::Sospechoso, Severidad::Media),
            aegis_ml::Verdict::Block | aegis_ml::Verdict::Contain => {
                (Juicio::Sospechoso, Severidad::Alta)
            }
        };
        // El limpio de un modelo solo vale lo que su calibracion, que para el
        // modelo de referencia no existe: se publica con la confianza que da
        // su puntuacion invertida, acotada por el tope del motor.
        let confianza = if juicio == Juicio::Limpio {
            aegis_entidad::escala::de_puntuacion(1000 - milesimas)
        } else {
            confianza
        };
        Ok(Informe {
            hallazgos: vec![hallazgo(
                Motor::Aprendizaje,
                juicio,
                severidad,
                confianza,
                format!(
                    "modelo estatico: puntuacion {:.3} ({:?})",
                    p.score, p.verdict
                ),
            )],
            completo: true,
        })
    }
}

fn pe(datos: &[u8]) -> Informe {
    let Ok(informe) = aegis_pe::Informe::de(datos) else {
        return Informe {
            hallazgos: vec![hallazgo(
                Motor::Estatico,
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                "PE ilegible: la cabecera no se deja leer".into(),
            )],
            completo: false,
        };
    };
    let hallazgos = informe
        .indicios
        .iter()
        .filter(|i| {
            matches!(
                i,
                aegis_pe::Indicio::SeccionEscribibleYEjecutable { .. }
                    | aegis_pe::Indicio::PuntoDeEntradaFueraDeTodaSeccion { .. }
                    | aegis_pe::Indicio::PuntoDeEntradaEnSeccionEscribible { .. }
            )
        })
        .map(|i| {
            hallazgo(
                Motor::Estatico,
                Juicio::Sospechoso,
                Severidad::Media,
                Confianza::BAJA,
                format!("PE: {}", i.frase()),
            )
        })
        .collect();
    Informe {
        hallazgos,
        completo: true,
    }
}

fn macho(datos: &[u8]) -> Informe {
    let Ok(binario) = aegis_macho::universal::Binario::leer(datos) else {
        return Informe {
            hallazgos: vec![hallazgo(
                Motor::Estatico,
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                "Mach-O ilegible".into(),
            )],
            completo: false,
        };
    };
    let mut completo = true;
    let mut hallazgos = Vec::new();
    for i in aegis_macho::indicios::de(&binario) {
        use aegis_macho::IndicioMac as I;
        match &i {
            I::SegmentoEscribibleYEjecutable { .. } | I::DylibSecuestrable { .. } => {
                hallazgos.push(hallazgo(
                    Motor::Estatico,
                    Juicio::Sospechoso,
                    Severidad::Media,
                    Confianza::BAJA,
                    format!("Mach-O: {}", i.frase()),
                ));
            }
            I::Cifrado | I::RodajaIlegible { .. } => {
                completo = false;
                hallazgos.push(hallazgo(
                    Motor::Estatico,
                    Juicio::NoConcluyente,
                    Severidad::Info,
                    Confianza::NULA,
                    format!("Mach-O: {}", i.frase()),
                ));
            }
            _ => {}
        }
    }
    Informe {
        hallazgos,
        completo,
    }
}

/// Unidades de trabajo del desensamblado dentro del trabajador.
pub const TOPE_DESENSAMBLADO: u64 = 400_000;

/// Funciones de simbolo que se toman como entradas del desensamblado, como mucho.
const MAX_ENTRADAS: usize = 4096;

fn desensamblado(datos: &[u8]) -> Result<Informe, String> {
    use goblin::elf::{header, program_header, sym, Elf};
    let elf = Elf::parse(datos).map_err(|e| format!("ELF ilegible: {e}"))?;
    let arquitectura = match elf.header.e_machine {
        header::EM_X86_64 => aegis_disasm::Arquitectura::X86_64,
        header::EM_386 => aegis_disasm::Arquitectura::X86,
        header::EM_AARCH64 => aegis_disasm::Arquitectura::Arm64,
        otra => return Err(format!("arquitectura ELF {otra} sin desensamblador")),
    };
    // El segmento ejecutable que contiene el punto de entrada.
    let entrada = elf.entry;
    let seg = elf
        .program_headers
        .iter()
        .find(|p| {
            p.p_type == program_header::PT_LOAD
                && p.is_executable()
                && entrada >= p.p_vaddr
                && entrada < p.p_vaddr.saturating_add(p.p_filesz)
        })
        .ok_or("el punto de entrada no cae en ningun segmento ejecutable")?;
    let desde = usize::try_from(seg.p_offset).map_err(|_| "desplazamiento enorme")?;
    let hasta = desde
        .checked_add(usize::try_from(seg.p_filesz).map_err(|_| "tamaño enorme")?)
        .ok_or("segmento fuera del fichero")?;
    let codigo = datos
        .get(desde..hasta)
        .ok_or("segmento fuera del fichero")?;
    let base = seg.p_vaddr;
    let mut entradas = vec![entrada];
    for s in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if entradas.len() >= MAX_ENTRADAS {
            break;
        }
        if s.st_type() == sym::STT_FUNC && s.st_value >= base && s.st_value < base + seg.p_filesz {
            entradas.push(s.st_value);
        }
    }
    entradas.sort_unstable();
    entradas.dedup();
    // El tope de trabajo sale del techo de memoria del trabajador, no del
    // defecto del crate: el grafo de flujo cuesta unos 256 bytes por
    // instruccion (medido sobre `python3`: 113 MiB para 443.000), y el
    // trabajador tiene 256 MiB para todo. Con 400.000 unidades el analisis
    // entero cabe con margen; un ejecutable mayor se analiza en parte y la
    // cobertura lo dice.
    let mut plazo =
        aegis_disasm::Plazo::nuevo(aegis_disasm::plazo::PLAZO_POR_DEFECTO, TOPE_DESENSAMBLADO);
    let analisis = aegis_disasm::analizar(
        &aegis_disasm::Entrada::minima(codigo, base, arquitectura, &entradas),
        &mut plazo,
    );
    let informe = &analisis.informe;
    let completo = informe.cobertura.completa();
    if informe.capacidades().is_empty() {
        return Ok(Informe {
            hallazgos: Vec::new(),
            completo,
        });
    }
    // La traduccion a juicio la hace el propio crate (`senal_de`), que es quien
    // conoce su calibracion; aqui solo se copia. La entidad es un marcador: el
    // trabajador no sabe de quien es el fichero, y no le hace falta.
    let s =
        aegis_disasm::senal::senal_de(informe, aegis_entidad::entidad::maquina("trabajador"), 0);
    Ok(Informe {
        hallazgos: vec![hallazgo(
            Motor::Estatico,
            s.juicio,
            s.severidad,
            s.confianza,
            s.porque,
        )],
        completo,
    })
}

fn emulacion(datos: &[u8]) -> Informe {
    let informe = aegis_emu::AegisSandbox::nuevo().analizar(datos);
    let v = &informe.veredicto;
    let hallazgos = if v.malicioso {
        // Emular no es ver ejecutarse en el sistema de verdad: el plano sigue
        // siendo el estatico, y el juicio, sospechoso.
        vec![hallazgo(
            Motor::Estatico,
            Juicio::Sospechoso,
            Severidad::Alta,
            Confianza::MEDIA,
            format!("emulacion: {:?}: {}", v.clase, v.evidencia),
        )]
    } else {
        Vec::new()
    };
    Informe {
        hallazgos,
        completo: true,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_tags_son_unicos_y_van_y_vuelven() {
        let todos = Analizador::disponibles();
        for a in &todos {
            assert_eq!(Analizador::desde_tag(a.tag()), Some(*a));
        }
        let mut tags: Vec<u16> = todos.iter().map(|a| a.tag()).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), todos.len());
    }

    #[test]
    fn el_numero_magico_elige_los_analizadores() {
        assert_eq!(
            para_ejecutable(b"\x7fELF\x02\x01"),
            vec![Analizador::Modelo, Analizador::Desensamblado]
        );
        assert_eq!(
            para_ejecutable(b"MZ\x90\x00"),
            vec![Analizador::Modelo, Analizador::Pe]
        );
        assert!(para_ejecutable(b"#!/bin/sh").is_empty());
    }

    #[test]
    fn basura_no_hace_caer_a_ninguno_y_nunca_sale_limpia() {
        let mut a = Analizadores::default();
        for basura in [
            &b""[..],
            b"\x7fELF",
            b"MZ",
            &[0xcf, 0xfa, 0xed, 0xfe, 0, 0],
            &[0u8; 64],
        ] {
            for &an in &[
                Analizador::Pe,
                Analizador::Macho,
                Analizador::Desensamblado,
                Analizador::Emulacion,
            ] {
                if let Ok(i) = a.analizar(an, basura) {
                    assert!(
                        i.hallazgos.iter().all(|h| h.juicio != Juicio::Limpio),
                        "{an:?} dio limpio sobre basura"
                    );
                }
            }
        }
    }

    /// Las dos pruebas del emulador que vivian en el agente (`microsandbox`),
    /// ahora sobre el analizador que lo ejecuta confinado.
    #[test]
    fn el_emulador_ve_la_autoinyeccion_y_no_acusa_lo_benigno() {
        // mmap(RWX) + escribir un HLT en la region + saltar a ella.
        let inyecta = [
            0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
            0x31, 0xFF, // xor edi, edi
            0xBE, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
            0xBA, 0x07, 0x00, 0x00, 0x00, // mov edx, 7 (RWX)
            0x0F, 0x05, // syscall
            0xC6, 0x00, 0xF4, // mov byte [rax], 0xF4
            0xFF, 0xE0, // jmp rax
        ];
        let mut a = Analizadores::default();
        let i = a.analizar(Analizador::Emulacion, &inyecta).unwrap();
        assert!(
            i.hallazgos
                .iter()
                .any(|h| h.juicio == Juicio::Sospechoso && h.porque.contains("AutoInyeccion")),
            "{:?}",
            i.hallazgos
        );
        // read + exit: nada que decir.
        let benigno = [
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0 (read)
            0x0F, 0x05, // syscall
            0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
            0x31, 0xFF, // xor edi, edi
            0x0F, 0x05, // syscall
        ];
        let i = a.analizar(Analizador::Emulacion, &benigno).unwrap();
        assert!(i.hallazgos.is_empty(), "{:?}", i.hallazgos);
    }

    #[test]
    fn el_modelo_de_referencia_no_acusa_ni_absuelve() {
        // Sobre binarios corrientes el modelo de referencia daba «sospechoso»:
        // mientras no haya modelo entrenado, su puntuacion no es evidencia.
        if !aegis_ml::EMBEDDED_MODEL_ES_REFERENCIA {
            return; // con un modelo entrenado, acusar es su trabajo
        }
        let mut a = Analizadores::default();
        for ruta in ["/bin/ls", "/bin/sh"] {
            let Ok(bytes) = std::fs::read(ruta) else {
                continue;
            };
            let i = a
                .analizar(Analizador::Modelo, &bytes)
                .expect("el modelo analiza");
            assert!(
                i.hallazgos
                    .iter()
                    .all(|h| h.juicio == Juicio::NoConcluyente),
                "{ruta}: {:?}",
                i.hallazgos
            );
        }
    }

    #[test]
    fn el_propio_binario_de_prueba_se_desensambla() {
        let yo = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let i = Analizadores::default()
            .analizar(Analizador::Desensamblado, &yo)
            .expect("un ELF valido se desensambla");
        assert!(i.hallazgos.iter().all(|h| h.firma == Motor::Estatico));
    }
}
