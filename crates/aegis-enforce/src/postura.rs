//! La postura de aplicacion de esta maquina, medida contra el sistema real.

use std::collections::BTreeMap;

use aegis_scal::platform::Platform;

/// Un mecanismo por el que el producto puede imponer algo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capacidad {
    /// Filtros de llamadas al sistema (Linux).
    Seccomp,
    /// Restriccion de acceso a ficheros por ruta (Linux).
    Landlock,
    /// Ganchos LSM programables, que pueden **negar** una operacion (Linux).
    BpfLsm,
    /// Filtrado de paquetes en el camino de recepcion (Linux).
    Xdp,
    /// Minifiltro del sistema de ficheros (Windows).
    Minifiltro,
    /// Callbacks de objeto para la auto-defensa (Windows).
    ObCallbacks,
    /// Endpoint Security (macOS).
    EndpointSecurity,
}

impl Capacidad {
    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Capacidad::Seccomp => "seccomp",
            Capacidad::Landlock => "Landlock",
            Capacidad::BpfLsm => "BPF LSM",
            Capacidad::Xdp => "XDP",
            Capacidad::Minifiltro => "minifiltro",
            Capacidad::ObCallbacks => "ObCallbacks",
            Capacidad::EndpointSecurity => "Endpoint Security",
        }
    }

    /// En que plataforma tiene sentido.
    pub fn plataforma(&self) -> Platform {
        match self {
            Capacidad::Seccomp | Capacidad::Landlock | Capacidad::BpfLsm | Capacidad::Xdp => {
                Platform::Linux
            }
            Capacidad::Minifiltro | Capacidad::ObCallbacks => Platform::Windows,
            Capacidad::EndpointSecurity => Platform::MacOs,
        }
    }
}

/// En que situacion esta una capacidad en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// Puede **negar** una operacion.
    Aplica,
    /// Ve la operacion y **no** puede negarla.
    ///
    /// Es telemetria. Existe como estado propio porque contarla como aplicacion
    /// es lo que produce el informe tranquilizador de una maquina desprotegida.
    SoloObserva {
        /// Por que no puede negar.
        motivo: String,
    },
    /// No esta disponible aqui.
    Ausente {
        /// Por que.
        motivo: String,
    },
    /// No aplica en esta plataforma.
    ///
    /// Distinto de ausente: que en Linux no haya minifiltro no es una carencia
    /// de la maquina, y mezclarlos llenaria de falsas alarmas el informe de cada
    /// endpoint de la flota.
    OtraPlataforma,
}

impl Estado {
    /// Si de verdad puede negar una operacion.
    pub fn aplica(&self) -> bool {
        matches!(self, Estado::Aplica)
    }
}

/// Lo que una politica exige del endpoint donde se despliega.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exigencia {
    /// Basta con ver y alertar.
    Observar,
    /// Hace falta poder impedirlo.
    Aplicar,
}

/// Lo que esta maquina puede imponer, medido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postura {
    /// Plataforma sobre la que se midio.
    pub plataforma: Platform,
    /// El estado de cada capacidad.
    pub capacidades: BTreeMap<Capacidad, Estado>,
}

impl Postura {
    /// Sondea esta maquina.
    ///
    /// No lee configuracion: pregunta al sistema. Lo que diga un fichero sobre
    /// lo que el producto «tiene activado» no dice nada de lo que este kernel
    /// acepta, y la diferencia entre las dos cosas es justo lo que se descubre
    /// tarde.
    pub fn medida() -> Postura {
        let mut capacidades = BTreeMap::new();
        let plataforma = plataforma_actual();

        for c in [
            Capacidad::Seccomp,
            Capacidad::Landlock,
            Capacidad::BpfLsm,
            Capacidad::Xdp,
            Capacidad::Minifiltro,
            Capacidad::ObCallbacks,
            Capacidad::EndpointSecurity,
        ] {
            let estado = if c.plataforma() != plataforma {
                Estado::OtraPlataforma
            } else {
                sondear(c)
            };
            capacidades.insert(c, estado);
        }

        Postura {
            plataforma,
            capacidades,
        }
    }

    /// Si esta maquina puede impedir algo, por algun camino.
    pub fn puede_aplicar_algo(&self) -> bool {
        self.capacidades.values().any(|e| e.aplica())
    }

    /// Si una politica con esta exigencia se puede cumplir aqui.
    ///
    /// Con [`Exigencia::Aplicar`] hace falta al menos un mecanismo que niegue de
    /// verdad. **Falla cerrado**: una politica que dice «esto no se ejecuta» y
    /// se despliega sobre una maquina que no puede impedirlo tiene que
    /// rechazarse en el despliegue, no descubrirse en el incidente.
    pub fn puede_cumplir(&self, exigencia: Exigencia) -> bool {
        match exigencia {
            Exigencia::Observar => true,
            Exigencia::Aplicar => self.puede_aplicar_algo(),
        }
    }

    /// Las capacidades que aplican de verdad.
    pub fn aplicando(&self) -> Vec<Capacidad> {
        self.capacidades
            .iter()
            .filter(|(_, e)| e.aplica())
            .map(|(c, _)| *c)
            .collect()
    }

    /// Lo que falta, con su motivo, para el informe.
    ///
    /// No lista lo de otras plataformas: que en Linux no haya minifiltro no es
    /// una carencia, y meterlo aqui llenaria de ruido el informe de cada
    /// endpoint hasta que nadie lo leyera.
    pub fn lo_que_no_se_puede_imponer(&self) -> Vec<String> {
        self.capacidades
            .iter()
            .filter_map(|(c, e)| match e {
                Estado::Aplica | Estado::OtraPlataforma => None,
                Estado::SoloObserva { motivo } => Some(format!(
                    "{}: ve la operacion pero no puede negarla ({motivo})",
                    c.nombre()
                )),
                Estado::Ausente { motivo } => {
                    Some(format!("{}: no esta disponible ({motivo})", c.nombre()))
                }
            })
            .collect()
    }

    /// La frase con la que el agente debe describirse.
    ///
    /// Es la unica salida que se permite al panel, y por eso esta aqui y no en
    /// la interfaz: «protegido» es una palabra que hay que ganarse, y quien la
    /// escribe no puede ser quien la muestra.
    pub fn como_describirse(&self) -> &'static str {
        if self.puede_aplicar_algo() {
            "aplicando: este agente puede impedir operaciones en esta maquina"
        } else {
            "SOLO OBSERVANDO: este agente ve y alerta, y no puede impedir nada en \
             esta maquina"
        }
    }
}

/// La plataforma sobre la que corre esto.
fn plataforma_actual() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

/// Sondea una capacidad contra el sistema de verdad.
fn sondear(c: Capacidad) -> Estado {
    match c {
        Capacidad::Seccomp | Capacidad::Landlock => sondear_aislamiento(c),
        Capacidad::BpfLsm => sondear_bpf_lsm(),
        Capacidad::Xdp => Estado::Ausente {
            motivo: "el enganche XDP se mide por interfaz al programarlo, no aqui".into(),
        },
        // En Linux nunca se llega: `Postura::medida` ya devolvio OtraPlataforma.
        Capacidad::Minifiltro | Capacidad::ObCallbacks => Estado::Ausente {
            motivo: "hace falta el driver cargado y firmado".into(),
        },
        Capacidad::EndpointSecurity => Estado::Ausente {
            motivo: "hace falta el permiso concedido por el usuario y el entitlement de Apple"
                .into(),
        },
    }
}

/// seccomp y Landlock, por la deteccion que ya hace `aegis-sandbox`.
fn sondear_aislamiento(c: Capacidad) -> Estado {
    let s = aegis_sandbox::Support::detect();
    match c {
        Capacidad::Seccomp if s.seccomp => Estado::Aplica,
        Capacidad::Seccomp => Estado::Ausente {
            motivo: "el kernel no admite filtros de seccomp".into(),
        },
        Capacidad::Landlock => match s.landlock_abi {
            Some(abi) if abi >= 1 => Estado::Aplica,
            _ => Estado::Ausente {
                motivo: "el kernel no trae Landlock o no esta habilitado".into(),
            },
        },
        _ => unreachable!("solo se llama con seccomp o Landlock"),
    }
}

/// BPF LSM: el unico que puede NEGAR desde un programa eBPF.
///
/// Los ganchos de traza —kprobes, tracepoints— ven pasar la operacion y no
/// pueden pararla. Confundirlos es exactamente el error que este crate existe
/// para impedir: un producto que dice bloquear con kprobes esta alertando.
fn sondear_bpf_lsm() -> Estado {
    // El kernel publica la lista de LSM activos en securityfs. La LECTURA vive
    // aqui; la DECISION vive en `clasificar_lsm`, que es pura y comprobable sin
    // depender de que securityfs este montado en el entorno de la prueba.
    clasificar_lsm(
        std::fs::read_to_string("/sys/kernel/security/lsm")
            .ok()
            .as_deref(),
    )
}

/// Clasifica BPF LSM a partir de la lista de LSM activos del kernel.
///
/// Puro, sin E/S: por eso se puede probar de forma determinista con la entrada
/// inyectada, sin que el resultado dependa de que securityfs este montado —que es
/// una condicion del entorno, no una propiedad del producto, y lo que hace flaky a
/// un test que lee el fichero real—. `None` es «no se pudo leer»: securityfs sin
/// montar, o el kernel sin el framework LSM.
fn clasificar_lsm(lista: Option<&str>) -> Estado {
    let Some(lista) = lista else {
        return Estado::Ausente {
            motivo: "no se puede leer /sys/kernel/security/lsm (securityfs sin montar o el \
                     kernel sin el framework LSM): no se puede afirmar que niegue"
                .into(),
        };
    };
    if lista.split(',').any(|l| l.trim() == "bpf") {
        Estado::Aplica
    } else {
        Estado::SoloObserva {
            motivo: format!(
                "el kernel trae LSM ({}) pero «bpf» no esta en la lista: se puede \
                 observar con kprobes y no se puede negar",
                lista.trim()
            ),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_postura_de_esta_maquina_se_mide_de_verdad() {
        let p = Postura::medida();
        assert_eq!(p.plataforma, Platform::Linux, "el CI es Linux");
        assert_eq!(p.capacidades.len(), 7, "las siete capacidades, contadas");
        // Las de otras plataformas se marcan como tales y no como carencias.
        assert_eq!(
            p.capacidades[&Capacidad::Minifiltro],
            Estado::OtraPlataforma
        );
        assert_eq!(
            p.capacidades[&Capacidad::EndpointSecurity],
            Estado::OtraPlataforma
        );
    }

    #[test]
    fn seccomp_y_landlock_estan_aplicando_en_esta_maquina() {
        // Se sabe que los dos existen aqui: la FASE 26 los ejercita y la puerta
        // del sandbox los mide en cada `make ci`. Si esta prueba falla, o el
        // kernel cambio o la sonda dejo de funcionar, y las dos cosas hay que
        // mirarlas.
        let p = Postura::medida();
        assert!(
            p.capacidades[&Capacidad::Seccomp].aplica(),
            "seccomp: {:?}",
            p.capacidades[&Capacidad::Seccomp]
        );
        assert!(
            p.capacidades[&Capacidad::Landlock].aplica(),
            "Landlock: {:?}",
            p.capacidades[&Capacidad::Landlock]
        );
    }

    #[test]
    fn la_clasificacion_de_bpf_lsm_es_determinista_y_no_depende_del_entorno() {
        // La distincion que este crate existe para hacer —NEGAR con BPF LSM vs.
        // solo VER con kprobes— se prueba con la entrada inyectada, sin leer el
        // sistema. Asi es determinista y no depende de que securityfs este
        // montado (que es lo que hacia flaky a un test que leia el fichero real).
        //
        // «bpf» en la lista => puede NEGAR: aplica.
        assert_eq!(
            clasificar_lsm(Some("capability,landlock,yama,safesetid,selinux,bpf")),
            Estado::Aplica
        );
        // Lista SIN «bpf» => ve con kprobes y no niega: SoloObserva, y NO aplica.
        // Es el estado que impide el informe tranquilizador de una maquina que en
        // realidad solo observa.
        let solo = clasificar_lsm(Some("capability,landlock,yama"));
        assert!(matches!(solo, Estado::SoloObserva { .. }), "{solo:?}");
        assert!(!solo.aplica(), "observar no es negar");
        // Sin fichero (securityfs sin montar, o kernel sin el framework) =>
        // Ausente, y se DICE con su motivo, en vez de afirmar que niega.
        let aus = clasificar_lsm(None);
        assert!(matches!(aus, Estado::Ausente { .. }), "{aus:?}");
        assert!(!aus.aplica());
    }

    #[test]
    fn observar_no_cuenta_como_aplicar() {
        let e = Estado::SoloObserva {
            motivo: "kprobes ven la operacion y no la paran".into(),
        };
        assert!(!e.aplica(), "ver pasar algo no es poder pararlo");
    }

    #[test]
    fn una_politica_que_exige_aplicar_se_rechaza_donde_no_se_puede_aplicar() {
        // La regla de fallar cerrado. Una maquina sin ningun mecanismo de
        // aplicacion no puede recibir una politica de bloqueo, y eso se decide
        // en el despliegue y no en el incidente.
        let vacia = Postura {
            plataforma: Platform::Linux,
            capacidades: [(
                Capacidad::Seccomp,
                Estado::Ausente {
                    motivo: "kernel sin seccomp".into(),
                },
            )]
            .into(),
        };
        assert!(!vacia.puede_aplicar_algo());
        assert!(
            !vacia.puede_cumplir(Exigencia::Aplicar),
            "una politica de bloqueo no se puede cumplir aqui"
        );
        assert!(
            vacia.puede_cumplir(Exigencia::Observar),
            "y una de observacion si"
        );
    }

    #[test]
    fn un_agente_que_no_puede_bloquear_no_se_describe_como_protegiendo() {
        let vacia = Postura {
            plataforma: Platform::Linux,
            capacidades: BTreeMap::new(),
        };
        let frase = vacia.como_describirse();
        assert!(
            frase.contains("SOLO OBSERVANDO"),
            "no puede llamarse protegido: {frase}"
        );
        assert!(!frase.contains("aplicando"), "{frase}");
    }

    #[test]
    fn esta_maquina_si_puede_describirse_como_aplicando() {
        let p = Postura::medida();
        assert!(p.puede_aplicar_algo());
        assert!(p.como_describirse().starts_with("aplicando"));
        assert!(!p.aplicando().is_empty());
    }

    #[test]
    fn lo_de_otras_plataformas_no_sale_como_carencia() {
        // Si saliera, cada endpoint de Linux reportaria tres carencias por no
        // ser Windows ni un Mac, y el informe dejaria de leerse.
        let p = Postura::medida();
        let falta = p.lo_que_no_se_puede_imponer();
        assert!(
            !falta.iter().any(|f| f.contains("minifiltro")),
            "no es una carencia de una maquina Linux: {falta:?}"
        );
        assert!(!falta.iter().any(|f| f.contains("Endpoint Security")));
    }

    #[test]
    fn cada_capacidad_declara_su_plataforma() {
        assert_eq!(Capacidad::Seccomp.plataforma(), Platform::Linux);
        assert_eq!(Capacidad::Minifiltro.plataforma(), Platform::Windows);
        assert_eq!(Capacidad::EndpointSecurity.plataforma(), Platform::MacOs);
    }
}
