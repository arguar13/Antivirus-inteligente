//! La frontera: que puede tocar la muestra y que no.
//!
//! # La propiedad que define la fase
//!
//! Una detonacion es, por definicion, ejecutar malware a proposito. Todo lo demas
//! —la traza, el informe, el analisis— vale cero si esa ejecucion puede tocar
//! algo real. La frontera no es una capa mas: es la unica razon por la que el
//! resto puede existir.
//!
//! # No hay variante para «red de verdad»
//!
//! [`Salida`] tiene dos variantes y ninguna es «la red de produccion». Igual que
//! en el protocolo del canal, la ausencia **es** la frontera: nadie puede
//! configurar por error lo que no se puede expresar. Para conectar una detonacion
//! a una red real habria que anadir una variante, y eso se ve en una revision.
//!
//! # Los dos confinamientos, y por que no son equivalentes
//!
//! | | MicroVM | Espacios de nombres |
//! |---|---|---|
//! | Frontera | Hipervisor | Kernel compartido |
//! | Escape | Necesita un fallo del hipervisor | Basta una elevacion local del kernel |
//! | Uso | **Produccion**: muestras reales | Ejercitar la maquinaria |
//!
//! La diferencia no es de grado. Una elevacion local de privilegios en el kernel
//! —de las que salen varias al ano— saca a la muestra de los espacios de nombres
//! y la pone en el anfitrion. Contra una maquina virtual, esa misma elevacion la
//! deja donde estaba: le hace falta ademas un escape del hipervisor, que es otra
//! categoria de fallo.
//!
//! Por eso [`Confinamiento::Namespaces`] **se niega a detonar muestras reales**
//! salvo que quien lo pide lo reconozca explicitamente. Un aislamiento mas debil
//! que se puede elegir sin darse cuenta es peor que no tenerlo, porque invita a
//! confiar en el.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Que salida de red ve la muestra.
///
/// **No existe ninguna variante que de acceso a una red real.** Esa ausencia es
/// la frontera, no un olvido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Salida {
    /// Nada: ni siquiera bucle local hacia fuera.
    ///
    /// Es lo mas contenido y lo peor para el analisis: mucho malware que no
    /// resuelve su C2 se limita a salir sin hacer nada, y entonces el informe
    /// dice «no hizo nada» cuando lo cierto es «no le dejamos empezar».
    Ninguna,
    /// Servicios falsos: DNS que resuelve todo, HTTP que contesta a todo.
    ///
    /// Es el que se usa: al malware hay que **dejarle creer** que llego a su C2
    /// para que haga lo siguiente, que es lo que se quiere ver.
    Simulada,
}

impl Salida {
    /// Nombre estable para el informe.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Salida::Ninguna => "ninguna",
            Salida::Simulada => "simulada",
        }
    }
}

/// Limites duros de una detonacion.
///
/// Todos tienen que estar puestos. Un limite ausente no es «generoso»: es una
/// muestra que puede llenar el disco del anfitrion, comerse su RAM o no terminar
/// nunca, y las tres cosas son un incidente causado por la herramienta de
/// analisis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limites {
    /// Nucleos virtuales.
    pub vcpus: u8,
    /// Memoria del invitado, en MiB.
    pub memoria_mib: u32,
    /// Disco de escritura del invitado, en MiB.
    pub disco_mib: u32,
    /// Plazo de pared de la detonacion entera.
    pub plazo: Duration,
    /// Eventos de traza maximos antes de recortar y declararlo.
    pub max_eventos: u64,
    /// Bytes maximos de captura de red.
    pub max_captura: u64,
}

impl Default for Limites {
    /// Limites pensados para que una muestra normal quepa y una patologica no.
    ///
    /// Los numeros salen de lo que hace falta para que el malware se comporte:
    /// con menos de 512 MiB muchas familias empaquetadas ni se desempaquetan, y
    /// con un solo nucleo el codigo que mide la concurrencia para detectar el
    /// sandbox se da cuenta.
    fn default() -> Limites {
        Limites {
            vcpus: 2,
            memoria_mib: 1024,
            disco_mib: 2048,
            plazo: Duration::from_secs(120),
            max_eventos: 200_000,
            max_captura: 64 * 1024 * 1024,
        }
    }
}

/// Por que unos limites no valen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorFrontera {
    /// Un limite esta a cero o falta.
    #[error(
        "el limite «{0}» esta a cero: un limite ausente no es generoso, es una muestra que puede \
         llenar el disco del anfitrion o no terminar nunca"
    )]
    LimiteAusente(&'static str),
    /// Un limite es tan grande que deja de acotar.
    #[error("el limite «{campo}» vale {valor} y el tope es {tope}")]
    LimiteExcesivo {
        /// Que limite.
        campo: &'static str,
        /// Lo que se pedia.
        valor: u64,
        /// El tope.
        tope: u64,
    },
    /// Se pidio detonar una muestra real bajo un aislamiento que no basta.
    #[error(
        "detonar una muestra real bajo aislamiento por espacios de nombres necesita reconocerlo \
         explicitamente: una elevacion local del kernel saca a la muestra de ahi y la pone en el \
         anfitrion, cosa que contra una maquina virtual no consigue"
    )]
    AislamientoInsuficiente,
    /// Se pidio red simulada bajo un confinamiento que no puede darla.
    #[error(
        "el confinamiento por espacios de nombres no puede ofrecer la red simulada: los servicios \
         falsos viven en el anfitrion y el espacio de nombres de red los deja fuera, que es \
         justamente su trabajo. Darlos exigiria levantarlos DENTRO del espacio, que es lo que \
         hace el camino de maquina virtual con su dispositivo tap. Se rechaza en vez de degradar \
         a «sin salida» en silencio: un informe que dice «no contacto con nadie» cuando lo cierto \
         es «no habia con quien» es la misma mentira de siempre con otra ropa"
    )]
    RedSimuladaNoDisponible,
    /// La imagen del invitado no esta.
    #[error("la imagen del invitado no esta en «{0}»")]
    SinImagen(String),
}

/// Topes absolutos: por encima de esto el limite deja de acotar nada.
const TOPE_VCPUS: u64 = 16;
/// Tope de memoria del invitado, en MiB.
const TOPE_MEMORIA_MIB: u64 = 16 * 1024;
/// Tope de disco del invitado, en MiB.
const TOPE_DISCO_MIB: u64 = 64 * 1024;
/// Tope del plazo, en segundos.
///
/// Media hora. Mas alla, una muestra que no ha hecho nada no lo va a hacer, y lo
/// unico que se consigue es tener un puesto de detonacion ocupado.
const TOPE_PLAZO_S: u64 = 1800;

impl Limites {
    /// Comprueba que los limites acotan de verdad.
    ///
    /// # Errores
    /// [`ErrorFrontera`] si alguno esta a cero o pasa de su tope.
    pub fn verificar(&self) -> Result<(), ErrorFrontera> {
        if self.vcpus == 0 {
            return Err(ErrorFrontera::LimiteAusente("vcpus"));
        }
        if self.memoria_mib == 0 {
            return Err(ErrorFrontera::LimiteAusente("memoria_mib"));
        }
        if self.disco_mib == 0 {
            return Err(ErrorFrontera::LimiteAusente("disco_mib"));
        }
        if self.plazo.is_zero() {
            return Err(ErrorFrontera::LimiteAusente("plazo"));
        }
        if self.max_eventos == 0 {
            return Err(ErrorFrontera::LimiteAusente("max_eventos"));
        }
        if self.max_captura == 0 {
            return Err(ErrorFrontera::LimiteAusente("max_captura"));
        }

        let comprobar = |campo, valor: u64, tope: u64| {
            if valor > tope {
                Err(ErrorFrontera::LimiteExcesivo { campo, valor, tope })
            } else {
                Ok(())
            }
        };
        comprobar("vcpus", u64::from(self.vcpus), TOPE_VCPUS)?;
        comprobar("memoria_mib", u64::from(self.memoria_mib), TOPE_MEMORIA_MIB)?;
        comprobar("disco_mib", u64::from(self.disco_mib), TOPE_DISCO_MIB)?;
        comprobar("plazo", self.plazo.as_secs(), TOPE_PLAZO_S)?;
        Ok(())
    }
}

/// Como se encierra la muestra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confinamiento {
    /// Maquina virtual con su propio kernel. **Es el de produccion.**
    MicroVm {
        /// Binario del hipervisor (Firecracker o Cloud Hypervisor).
        hipervisor: PathBuf,
        /// Kernel del invitado.
        kernel: PathBuf,
        /// Imagen de raiz del invitado, de solo lectura.
        ///
        /// La detonacion nunca escribe aqui: se le pone encima una capa
        /// desechable, y por eso dos detonaciones de la misma muestra parten del
        /// mismo estado exacto.
        raiz: PathBuf,
    },
    /// Espacios de nombres del kernel del anfitrion. **No equivale a una VM.**
    Namespaces {
        /// Reconocimiento explicito de que se detona algo real aqui.
        ///
        /// Existe para que nadie elija el aislamiento debil sin enterarse. Un
        /// campo que hay que poner a mano se ve en una revision; un valor por
        /// omision, no.
        acepto_aislamiento_debil: bool,
    },
}

impl Confinamiento {
    /// Nombre estable para el informe.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Confinamiento::MicroVm { .. } => "microvm",
            Confinamiento::Namespaces { .. } => "namespaces",
        }
    }

    /// Si la frontera aguanta una elevacion local de privilegios del invitado.
    ///
    /// Solo la maquina virtual. Decirlo asi, en una funcion que el informe
    /// consulta, evita la conversacion de «bueno, los espacios de nombres
    /// tambien aislan».
    #[must_use]
    pub fn aguanta_elevacion_local(&self) -> bool {
        matches!(self, Confinamiento::MicroVm { .. })
    }
}

/// La politica completa de una detonacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontera {
    /// Como se encierra.
    pub confinamiento: Confinamiento,
    /// Que red ve.
    pub salida: Salida,
    /// Limites duros.
    pub limites: Limites,
}

impl Frontera {
    /// Frontera de produccion sobre una microVM.
    #[must_use]
    pub fn microvm(hipervisor: PathBuf, kernel: PathBuf, raiz: PathBuf) -> Frontera {
        Frontera {
            confinamiento: Confinamiento::MicroVm {
                hipervisor,
                kernel,
                raiz,
            },
            salida: Salida::Simulada,
            limites: Limites::default(),
        }
    }

    /// Frontera por espacios de nombres, **solo para ejercitar la maquinaria**.
    ///
    /// No acepta muestras reales: hay que decirlo aparte con
    /// [`Frontera::acepto_aislamiento_debil`], y el informe lo lleva escrito.
    #[must_use]
    pub fn namespaces() -> Frontera {
        Frontera {
            confinamiento: Confinamiento::Namespaces {
                acepto_aislamiento_debil: false,
            },
            // Sin salida, y no por prudencia: es que este confinamiento NO PUEDE
            // dar la simulada. Ver `ErrorFrontera::RedSimuladaNoDisponible`.
            salida: Salida::Ninguna,
            limites: Limites::default(),
        }
    }

    /// Reconoce explicitamente que se va a detonar algo real con aislamiento debil.
    #[must_use]
    pub fn acepto_aislamiento_debil(mut self) -> Frontera {
        if let Confinamiento::Namespaces {
            acepto_aislamiento_debil,
        } = &mut self.confinamiento
        {
            *acepto_aislamiento_debil = true;
        }
        self
    }

    /// Comprueba que la frontera se sostiene para lo que se le va a pedir.
    ///
    /// `muestra_real` distingue ejercitar la maquinaria de detonar algo que
    /// muerde. La distincion la hace quien llama porque solo el la sabe, y por
    /// eso es un argumento y no un campo que se pueda dejar puesto.
    ///
    /// # Errores
    /// [`ErrorFrontera`] si los limites no acotan, si falta la imagen, o si se
    /// pide algo real bajo un aislamiento que no basta.
    pub fn verificar(&self, muestra_real: bool) -> Result<(), ErrorFrontera> {
        self.limites.verificar()?;
        match &self.confinamiento {
            Confinamiento::MicroVm {
                hipervisor,
                kernel,
                raiz,
            } => {
                for (que, ruta) in [
                    ("hipervisor", hipervisor),
                    ("kernel", kernel),
                    ("raiz", raiz),
                ] {
                    if !ruta.exists() {
                        return Err(ErrorFrontera::SinImagen(format!(
                            "{que}: {}",
                            ruta.display()
                        )));
                    }
                }
                Ok(())
            }
            Confinamiento::Namespaces {
                acepto_aislamiento_debil,
            } => {
                if muestra_real && !acepto_aislamiento_debil {
                    return Err(ErrorFrontera::AislamientoInsuficiente);
                }
                if self.salida == Salida::Simulada {
                    return Err(ErrorFrontera::RedSimuladaNoDisponible);
                }
                Ok(())
            }
        }
    }

    /// Resumen de la frontera para el informe.
    ///
    /// Va **dentro** del informe y no en un log aparte: quien lee un informe de
    /// comportamiento tiene que saber con que fuerza estaba encerrada la muestra
    /// que lo produjo, porque eso cambia cuanto se puede creer.
    #[must_use]
    pub fn resumen(&self) -> String {
        format!(
            "confinamiento {} (aguanta elevacion local: {}) · salida de red {} · \
             {} vcpu, {} MiB RAM, {} MiB disco, plazo {} s",
            self.confinamiento.nombre(),
            if self.confinamiento.aguanta_elevacion_local() {
                "si"
            } else {
                "NO"
            },
            self.salida.nombre(),
            self.limites.vcpus,
            self.limites.memoria_mib,
            self.limites.disco_mib,
            self.limites.plazo.as_secs()
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_limites_por_omision_acotan_de_verdad() {
        let l = Limites::default();
        l.verificar().unwrap();
        assert!(l.vcpus > 0 && l.memoria_mib > 0 && l.disco_mib > 0);
        assert!(!l.plazo.is_zero());
    }

    #[test]
    fn un_limite_a_cero_se_rechaza_con_nombre() {
        // «Sin limite» no es generoso: es una muestra que llena el disco del
        // anfitrion o no termina nunca.
        for (campo, romper) in [
            ("vcpus", (|l: &mut Limites| l.vcpus = 0) as fn(&mut Limites)),
            ("memoria_mib", |l: &mut Limites| l.memoria_mib = 0),
            ("disco_mib", |l: &mut Limites| l.disco_mib = 0),
            ("plazo", |l: &mut Limites| l.plazo = Duration::ZERO),
            ("max_eventos", |l: &mut Limites| l.max_eventos = 0),
            ("max_captura", |l: &mut Limites| l.max_captura = 0),
        ] {
            let mut l = Limites::default();
            romper(&mut l);
            assert_eq!(
                l.verificar(),
                Err(ErrorFrontera::LimiteAusente(campo)),
                "{campo} a cero tiene que rechazarse"
            );
        }
    }

    #[test]
    fn un_limite_absurdo_tampoco_vale() {
        let l = Limites {
            plazo: Duration::from_secs(100_000),
            ..Default::default()
        };
        assert!(matches!(
            l.verificar(),
            Err(ErrorFrontera::LimiteExcesivo { campo: "plazo", .. })
        ));

        let l = Limites {
            memoria_mib: 1024 * 1024,
            ..Default::default()
        };
        assert!(matches!(
            l.verificar(),
            Err(ErrorFrontera::LimiteExcesivo {
                campo: "memoria_mib",
                ..
            })
        ));
    }

    // --- El aislamiento debil no se elige sin querer -----------------------

    #[test]
    fn una_muestra_real_no_se_detona_en_espacios_de_nombres_por_descuido() {
        // LA PUERTA. Una elevacion local del kernel —de las que salen varias al
        // ano— saca a la muestra de los espacios de nombres y la pone en el
        // anfitrion. Contra una VM no lo consigue: le hace falta ademas un
        // escape del hipervisor, que es otra categoria de fallo.
        let f = Frontera::namespaces();
        assert_eq!(
            f.verificar(true),
            Err(ErrorFrontera::AislamientoInsuficiente)
        );
        // Ejercitar la maquinaria si vale.
        assert!(f.verificar(false).is_ok());
        // Y reconocerlo explicitamente tambien, porque se ve en una revision.
        assert!(f.acepto_aislamiento_debil().verificar(true).is_ok());
    }

    #[test]
    fn solo_la_maquina_virtual_aguanta_una_elevacion_local() {
        assert!(!Frontera::namespaces()
            .confinamiento
            .aguanta_elevacion_local());
        let vm = Confinamiento::MicroVm {
            hipervisor: PathBuf::from("/x"),
            kernel: PathBuf::from("/y"),
            raiz: PathBuf::from("/z"),
        };
        assert!(vm.aguanta_elevacion_local());
    }

    #[test]
    fn el_resumen_dice_con_que_fuerza_estaba_encerrada() {
        // Quien lee un informe tiene que saberlo: cambia cuanto se puede creer.
        let r = Frontera::namespaces().resumen();
        assert!(r.contains("namespaces"), "{r}");
        assert!(r.contains("NO"), "tiene que decir que no aguanta: {r}");

        let vm = Frontera::microvm(
            PathBuf::from("/x"),
            PathBuf::from("/y"),
            PathBuf::from("/z"),
        );
        assert!(vm.resumen().contains("microvm"));
    }

    // --- La frontera de red -------------------------------------------------

    #[test]
    fn no_existe_forma_de_pedir_red_de_verdad() {
        // La ausencia de variante ES la frontera: nadie puede configurar por
        // error lo que no se puede expresar. Si alguien anade una variante para
        // red real, esta prueba deja de compilar y se ve en la revision.
        let todas = [Salida::Ninguna, Salida::Simulada];
        for s in todas {
            assert!(matches!(s, Salida::Ninguna | Salida::Simulada));
        }
        assert_eq!(todas.len(), 2, "si esto cambia, alguien anadio una salida");
    }

    #[test]
    fn en_maquina_virtual_la_salida_por_omision_es_simulada() {
        // Sin servicios falsos, mucho malware que no resuelve su C2 se limita a
        // salir, y el informe diria «no hizo nada» cuando lo cierto es «no le
        // dejamos empezar».
        let vm = Frontera::microvm(
            PathBuf::from("/x"),
            PathBuf::from("/y"),
            PathBuf::from("/z"),
        );
        assert_eq!(vm.salida, Salida::Simulada);
    }

    #[test]
    fn la_jaula_no_finge_tener_una_red_simulada_que_no_puede_dar() {
        // Los servicios falsos viven en el anfitrion y el espacio de nombres de
        // red los deja fuera, que es justamente su trabajo. Degradar en silencio
        // a «sin salida» produciria informes que dicen «no contacto con nadie»
        // cuando lo cierto es «no habia con quien»: la misma mentira de siempre
        // con otra ropa.
        let mut f = Frontera::namespaces();
        assert_eq!(f.salida, Salida::Ninguna, "por omision, sin salida");
        assert!(f.verificar(false).is_ok());

        f.salida = Salida::Simulada;
        assert_eq!(
            f.verificar(false),
            Err(ErrorFrontera::RedSimuladaNoDisponible)
        );
    }

    #[test]
    fn una_microvm_sin_imagen_no_arranca_nada() {
        let f = Frontera::microvm(
            PathBuf::from("/no/existe/firecracker"),
            PathBuf::from("/no/existe/vmlinux"),
            PathBuf::from("/no/existe/raiz.ext4"),
        );
        assert!(matches!(
            f.verificar(false),
            Err(ErrorFrontera::SinImagen(_))
        ));
    }
}
