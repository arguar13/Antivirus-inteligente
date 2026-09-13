//! El contrato de un analizador, y el registro que lo valida al entrar.
//!
//! # Las cuatro cosas que un analizador NO puede elegir
//!
//! Un analizador traduce lo que contesta un tercero. Eso lo convierte, desde el
//! punto de vista del plano de control, en codigo que trata entrada hostil. De
//! modo que hay cuatro cosas que **no decide el analizador**, y cada una cierra
//! una escalada concreta:
//!
//! | No decide | Si pudiera |
//! |---|---|
//! | Su **clase** ([`Ficha::clase`]) | Un canal comunitario se declararia autoritativo y se saltaria la jerarquia entera de la fusion |
//! | Su **exposicion** en tiempo de ejecucion | Declararia «local» y consultaria fuera; la declaracion no valdria nada |
//! | Si **hay red** | Es [`crate::salida`] quien se la entrega o no. Una bandera se olvida; una capacidad que no existe no se puede usar |
//! | Su **cuota** | Una fuente que se autoasigna la cuota puede agotar el contrato |
//!
//! Las cuatro viven en la [`Ficha`], que se da **al registrar** y no se puede
//! cambiar despues.
//!
//! # Por que el analizador no recibe el observable entero sin filtrar
//!
//! Recibe un [`Encargo`], y el orquestador ya comprobo
//! [`crate::observable::Observable::puede_salir`] antes de construirlo. Un
//! analizador externo **nunca llega a ver** una ruta de fichero o una cuenta de
//! usuario: no es que no deba mandarlas, es que no las tiene.

use std::time::Duration;

use crate::dictamen::{Clase, Dictamen};
use crate::exposicion::Exposicion;
use crate::observable::Tipo;
use crate::salida::Salida;
use crate::tasa::Cuota;

/// Lo que el analizador declara al registrarse, y que no puede cambiar despues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ficha {
    /// Nombre estable. Es la clave de la cache y de la cuota.
    pub nombre: String,
    /// De que clase es esta fuente. **No la elige la respuesta.**
    pub clase: Clase,
    /// Que tipos de observable sabe mirar.
    ///
    /// Vacio no tiene sentido y el registro lo rechaza: un analizador que no
    /// acepta nada es codigo muerto que alguien creera que funciona.
    pub acepta: Vec<Tipo>,
    /// Que sale de la organizacion al ejecutarlo.
    pub exposicion: Exposicion,
    /// Cuota del proveedor. `None` solo para analizadores locales.
    pub cuota: Option<Cuota>,
    /// Cuanto puede tardar como maximo.
    pub plazo: Duration,
}

impl Ficha {
    /// Comprueba que la ficha es coherente.
    ///
    /// Se llama **al registrar**. Un analizador mal declarado tiene que romper el
    /// arranque, no la primera consulta de un incidente.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo de la incoherencia.
    pub fn coherente(&self) -> Result<(), String> {
        if self.nombre.trim().is_empty() {
            return Err(
                "un analizador sin nombre no se puede citar en el informe, y un veredicto \
                        sin fuente citable no se puede discutir"
                    .into(),
            );
        }
        if self.acepta.is_empty() {
            return Err(format!(
                "«{}» no acepta ningun tipo de observable: es codigo muerto que alguien creera que \
                 funciona",
                self.nombre
            ));
        }
        self.exposicion
            .coherente()
            .map_err(|e| format!("«{}»: {e}", self.nombre))?;

        // Un analizador que sale a la red sin cuota declarada puede agotar el
        // contrato del cliente sin que nadie lo vea hasta que el proveedor corta.
        if self.exposicion.destino.necesita_red() && self.cuota.is_none() {
            return Err(format!(
                "«{}» sale a la red y no declara cuota: puede agotar el contrato sin que nadie lo \
                 vea, y el proveedor corta justo durante un incidente",
                self.nombre
            ));
        }
        // Y al reves: una cuota en un analizador local es una declaracion que no
        // significa nada, y las declaraciones que no significan nada acaban
        // copiandose a sitios donde si significan algo.
        if !self.exposicion.destino.necesita_red() && self.cuota.is_some() {
            return Err(format!(
                "«{}» es local y declara cuota: no hay proveedor al que respetarle nada",
                self.nombre
            ));
        }
        if self.plazo.is_zero() {
            return Err(format!("«{}» declara plazo cero", self.nombre));
        }
        Ok(())
    }

    /// Si necesita que se le entregue la salida de red.
    #[must_use]
    pub fn necesita_salida(&self) -> bool {
        self.exposicion.destino.necesita_red()
    }
}

/// Lo que se le entrega a un analizador para que trabaje.
///
/// El observable ya paso la comprobacion de privacidad: un analizador externo
/// nunca llega a ver una ruta o una cuenta.
#[derive(Debug, Clone)]
pub struct Encargo {
    /// Sobre que se pregunta.
    pub observable: crate::observable::Observable,
    /// El instante de referencia, en nanosegundos Unix.
    ///
    /// Se pasa y no se lee del reloj para que un analizador sea una funcion del
    /// encargo: dos ejecuciones con el mismo encargo dan el mismo dictamen, que es
    /// lo que permite probarlos.
    pub ahora_ns: u64,
}

/// Lo que sabe hacer un analizador.
///
/// Es `Send + Sync` porque el orquestador los ejecuta a la vez.
pub trait Analizador: Send + Sync {
    /// Su ficha. Constante durante toda la vida del analizador.
    fn ficha(&self) -> &Ficha;

    /// Mira el observable y produce un dictamen.
    ///
    /// `salida` es `None` cuando no hay red —modo sin salida, o analizador
    /// local—. **No es un error que haya que comprobar: es que no hay a quien
    /// preguntar.** Un analizador que necesita red y recibe `None` no llega ni a
    /// ejecutarse; el orquestador lo resuelve antes.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo por el que no pudo producir un dictamen. Un fallo **no
    /// es un dictamen de «limpio»**: el orquestador lo registra como `NoAplicable`
    /// con su motivo, y eso es lo que ve el analista.
    fn mirar(&self, encargo: &Encargo, salida: Option<&dyn Salida>) -> Result<Dictamen, String>;
}

/// Por que un analizador no produjo dictamen.
///
/// **Todas las variantes llevan motivo.** Es la propiedad central del modulo: un
/// analizador que no se ejecuto nunca puede producir el mismo hueco visual que uno
/// que se ejecuto y no encontro nada. Si lo hiciera, el analista leeria «sin
/// resultados» y entenderia «limpio», que es la confusion que este crate existe
/// para impedir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoAplicable {
    /// No sabe mirar ese tipo de observable.
    TipoNoSoportado {
        /// Cual se le pidio.
        tipo: Tipo,
    },
    /// El observable no puede salir de la organizacion.
    ObservableRetenido {
        /// Por que.
        motivo: crate::observable::MotivoRetencion,
    },
    /// El sistema esta en modo sin salida.
    SinSalida {
        /// A donde habria ido.
        destino: String,
    },
    /// La consulta necesitaba autorizacion y no la tenia.
    FaltaAutorizacion {
        /// Las lineas del aviso que el analista tenia que aprobar.
        aviso: Vec<String>,
    },
    /// No habia cuota.
    SinCuota {
        /// Por que.
        motivo: crate::tasa::SinCuota,
    },
    /// Se agoto el plazo **mientras el analizador trabajaba**.
    PlazoAgotado {
        /// Cuanto se le dio.
        plazo: Duration,
    },
    /// Se agoto el plazo **antes de que el analizador llegara a arrancar**.
    ///
    /// # Por que no es lo mismo que [`NoAplicable::PlazoAgotado`]
    ///
    /// Son dos hechos distintos y el informe no los puede juntar:
    ///
    /// - «no contesto en 200 ms» dice algo del **analizador**, y la accion es
    ///   revisarlo o darle mas plazo.
    /// - «no llego a ejecutarse» dice algo del **sistema**: esta saturado, y
    ///   darle mas plazo a un analizador que ni siquiera arranco no arregla nada.
    ///
    /// Confundirlos manda al analista a mirar el sitio equivocado, que es la
    /// misma averia que este crate existe para impedir en el otro sentido —«no se
    /// consulto» leido como «no habia nada»—.
    NoEjecutado {
        /// Cuanto se le dio.
        plazo: Duration,
    },
    /// El analizador fallo.
    Fallo {
        /// Que dijo.
        motivo: String,
    },
    /// El analizador entro en panico.
    ///
    /// Se recoge y se registra en vez de tumbar el orquestador: un analizador es
    /// codigo que trata entrada hostil, y el plano de control no puede caerse
    /// porque un proveedor devolviera algo raro.
    Panico,
}

impl NoAplicable {
    /// Nombre estable, para agrupar en el panel.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            NoAplicable::TipoNoSoportado { .. } => "tipo-no-soportado",
            NoAplicable::ObservableRetenido { .. } => "observable-retenido",
            NoAplicable::SinSalida { .. } => "sin-salida",
            NoAplicable::FaltaAutorizacion { .. } => "falta-autorizacion",
            NoAplicable::SinCuota { .. } => "sin-cuota",
            NoAplicable::PlazoAgotado { .. } => "plazo-agotado",
            NoAplicable::NoEjecutado { .. } => "no-ejecutado",
            NoAplicable::Fallo { .. } => "fallo",
            NoAplicable::Panico => "panico",
        }
    }

    /// El motivo completo, en una frase que va al informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            NoAplicable::TipoNoSoportado { tipo } => {
                format!("no sabe mirar observables de tipo «{}»", tipo.nombre())
            }
            NoAplicable::ObservableRetenido { motivo } => {
                format!(
                    "el observable no sale de la organizacion: {}",
                    motivo.texto()
                )
            }
            NoAplicable::SinSalida { destino } => format!(
                "el sistema esta en modo sin salida, asi que no se consulto a {destino}. NO se \
                 consulto: eso no quiere decir que no haya nada"
            ),
            NoAplicable::FaltaAutorizacion { aviso } => format!(
                "esta consulta exige autorizacion explicita y no la tiene. {}",
                aviso.join(" ")
            ),
            NoAplicable::SinCuota { motivo } => motivo.texto(),
            NoAplicable::PlazoAgotado { plazo } => format!(
                "no contesto en {} ms y se corto para no bloquear a los demas",
                plazo.as_millis()
            ),
            NoAplicable::NoEjecutado { plazo } => format!(
                "no llego a arrancar en {} ms: el sistema esta saturado, y darle mas plazo a un \
                 analizador que ni siquiera empezo no arregla nada",
                plazo.as_millis()
            ),
            // El motivo lo escribe el analizador y puede ser una linea suelta
            // («json roto»). Lo que NO puede faltar es lo que significa: un
            // analizador que fallo no dijo que estuviera limpio, y sin esa frase
            // el informe enseña un motivo cripico que se lee como «nada que ver».
            NoAplicable::Fallo { motivo } => format!(
                "el analizador fallo ({motivo}); no dijo que estuviera limpio, dijo que no pudo \
                 mirarlo"
            ),
            NoAplicable::Panico => {
                "el analizador entro en panico; se recogio para que no tumbara el plano de control"
                    .to_string()
            }
        }
    }

    /// Si esto se puede arreglar volviendo a intentarlo mas tarde.
    ///
    /// Importa para el panel: un «vuelve en 30 s» y un «esto nunca va a funcionar
    /// para este observable» exigen cosas distintas del analista.
    #[must_use]
    pub fn es_transitorio(&self) -> bool {
        matches!(
            self,
            NoAplicable::SinCuota { .. }
                | NoAplicable::PlazoAgotado { .. }
                | NoAplicable::NoEjecutado { .. }
        )
    }
}

/// El registro de analizadores.
///
/// Valida al registrar, no al ejecutar.
#[derive(Default)]
pub struct Registro {
    analizadores: Vec<std::sync::Arc<dyn Analizador>>,
}

impl std::fmt::Debug for Registro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registro")
            .field(
                "analizadores",
                &self
                    .analizadores
                    .iter()
                    .map(|a| a.ficha().nombre.clone())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Registro {
    /// Un registro vacio.
    #[must_use]
    pub fn nuevo() -> Registro {
        Registro::default()
    }

    /// Añade un analizador, validando su ficha.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo si la ficha es incoherente o el nombre ya existe.
    pub fn registrar(&mut self, analizador: std::sync::Arc<dyn Analizador>) -> Result<(), String> {
        let ficha = analizador.ficha().clone();
        ficha.coherente()?;
        // Dos analizadores con el mismo nombre comparten cache y cuota, y en el
        // informe se leen como una sola fuente: dos opiniones se convertirian en
        // una y la fusion contaria mal.
        if self
            .analizadores
            .iter()
            .any(|a| a.ficha().nombre == ficha.nombre)
        {
            return Err(format!(
                "ya hay un analizador llamado «{}»: compartirian cache y cuota, y en el informe se \
                 leerian como una sola fuente",
                ficha.nombre
            ));
        }
        self.analizadores.push(analizador);
        Ok(())
    }

    /// Los analizadores registrados.
    #[must_use]
    pub fn todos(&self) -> &[std::sync::Arc<dyn Analizador>] {
        &self.analizadores
    }

    /// Los que saben mirar ese tipo.
    #[must_use]
    pub fn para(&self, tipo: Tipo) -> Vec<std::sync::Arc<dyn Analizador>> {
        self.analizadores
            .iter()
            .filter(|a| a.ficha().acepta.contains(&tipo))
            .cloned()
            .collect()
    }

    /// Cuantos hay.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.analizadores.len()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::exposicion::{Campo, Destino, Jurisdiccion, Retencion};
    use std::sync::Arc;

    struct Falso(Ficha);

    impl Analizador for Falso {
        fn ficha(&self) -> &Ficha {
            &self.0
        }
        fn mirar(&self, _e: &Encargo, _s: Option<&dyn Salida>) -> Result<Dictamen, String> {
            Err("no implementado".into())
        }
    }

    fn ficha_externa(nombre: &str) -> Ficha {
        Ficha {
            nombre: nombre.into(),
            clase: Clase::Reputacion,
            acepta: vec![Tipo::Hash],
            exposicion: Exposicion {
                destino: Destino::Externo {
                    proveedor: "rep.example".into(),
                    jurisdiccion: Jurisdiccion::Eee,
                    retencion: Retencion::Indefinida,
                },
                campos: vec![Campo::ResumenDeFichero],
            },
            cuota: Some(Cuota::por_minuto(60)),
            plazo: Duration::from_secs(5),
        }
    }

    fn ficha_local(nombre: &str) -> Ficha {
        Ficha {
            nombre: nombre.into(),
            clase: Clase::Propia,
            acepta: vec![Tipo::Hash],
            exposicion: Exposicion::ninguna(),
            cuota: None,
            plazo: Duration::from_secs(1),
        }
    }

    #[test]
    fn una_ficha_bien_declarada_pasa() {
        assert!(ficha_externa("rep").coherente().is_ok());
        assert!(ficha_local("yara").coherente().is_ok());
    }

    #[test]
    fn un_analizador_que_no_acepta_nada_se_rechaza() {
        // Codigo muerto que alguien creera que funciona.
        let mut f = ficha_externa("rep");
        f.acepta.clear();
        assert!(f.coherente().unwrap_err().contains("codigo muerto"));
    }

    #[test]
    fn salir_a_la_red_sin_cuota_declarada_se_rechaza() {
        // Puede agotar el contrato del cliente sin que nadie lo vea, y el proveedor
        // corta justo durante un incidente.
        let mut f = ficha_externa("rep");
        f.cuota = None;
        assert!(f.coherente().unwrap_err().contains("no declara cuota"));
    }

    #[test]
    fn un_local_con_cuota_tambien_se_rechaza() {
        // Una declaracion que no significa nada acaba copiandose a un sitio donde
        // si significa algo.
        let mut f = ficha_local("yara");
        f.cuota = Some(Cuota::por_minuto(60));
        assert!(f
            .coherente()
            .unwrap_err()
            .contains("es local y declara cuota"));
    }

    #[test]
    fn un_analizador_sin_nombre_se_rechaza() {
        let mut f = ficha_externa("  ");
        f.nombre = "  ".into();
        assert!(f.coherente().unwrap_err().contains("sin nombre"));
    }

    #[test]
    fn un_plazo_cero_se_rechaza() {
        let mut f = ficha_externa("rep");
        f.plazo = Duration::ZERO;
        assert!(f.coherente().unwrap_err().contains("plazo cero"));
    }

    #[test]
    fn dos_analizadores_con_el_mismo_nombre_se_rechazan() {
        // Compartirian cache y cuota, y en el informe se leerian como una sola
        // fuente: dos opiniones se convertirian en una y la fusion contaria mal.
        let mut r = Registro::nuevo();
        r.registrar(Arc::new(Falso(ficha_externa("rep"))))
            .expect("primera");
        let e = r
            .registrar(Arc::new(Falso(ficha_externa("rep"))))
            .expect_err("segunda");
        assert!(e.contains("ya hay un analizador"));
        assert_eq!(r.cuantos(), 1);
    }

    #[test]
    fn el_registro_filtra_por_tipo() {
        let mut r = Registro::nuevo();
        r.registrar(Arc::new(Falso(ficha_externa("hash-rep"))))
            .expect("ok");
        let mut f = ficha_externa("dom-rep");
        f.acepta = vec![Tipo::Dominio];
        r.registrar(Arc::new(Falso(f))).expect("ok");

        assert_eq!(r.para(Tipo::Hash).len(), 1);
        assert_eq!(r.para(Tipo::Dominio).len(), 1);
        assert_eq!(r.para(Tipo::Ip).len(), 0);
    }

    #[test]
    fn una_exposicion_incoherente_rompe_el_registro_y_no_la_ejecucion() {
        // Un analizador mal declarado tiene que romper el arranque, no la primera
        // consulta de un incidente a las tres de la mañana.
        let mut f = ficha_externa("rep");
        f.exposicion.campos.clear();
        let mut r = Registro::nuevo();
        assert!(r.registrar(Arc::new(Falso(f))).is_err());
        assert_eq!(r.cuantos(), 0);
    }

    #[test]
    fn todo_motivo_de_no_aplicable_lleva_explicacion() {
        // La propiedad central: un analizador que no se ejecuto nunca puede
        // producir el mismo hueco visual que uno que se ejecuto y no encontro nada.
        let casos = [
            NoAplicable::TipoNoSoportado { tipo: Tipo::Hash },
            NoAplicable::ObservableRetenido {
                motivo: crate::observable::MotivoRetencion::DatoPersonal,
            },
            NoAplicable::SinSalida {
                destino: "externo:rep".into(),
            },
            NoAplicable::FaltaAutorizacion {
                aviso: vec!["sale el fichero entero".into()],
            },
            NoAplicable::SinCuota {
                motivo: crate::tasa::SinCuota::FuenteDesconocida,
            },
            NoAplicable::PlazoAgotado {
                plazo: Duration::from_secs(5),
            },
            NoAplicable::NoEjecutado {
                plazo: Duration::from_secs(5),
            },
            NoAplicable::Fallo {
                motivo: "json roto".into(),
            },
            NoAplicable::Panico,
        ];
        for c in &casos {
            assert!(c.texto().len() > 20, "{c:?} no explica nada");
            assert!(!c.nombre().is_empty());
        }
    }

    #[test]
    fn solo_la_cuota_y_el_plazo_son_transitorios() {
        // Un «vuelve en 30 s» y un «esto nunca va a funcionar para este observable»
        // exigen cosas distintas del analista.
        assert!(NoAplicable::SinCuota {
            motivo: crate::tasa::SinCuota::Espera { falta_ns: 1 }
        }
        .es_transitorio());
        assert!(NoAplicable::PlazoAgotado {
            plazo: Duration::from_secs(1)
        }
        .es_transitorio());
        assert!(NoAplicable::NoEjecutado {
            plazo: Duration::from_secs(1)
        }
        .es_transitorio());
        assert!(!NoAplicable::ObservableRetenido {
            motivo: crate::observable::MotivoRetencion::DatoPersonal
        }
        .es_transitorio());
        assert!(!NoAplicable::SinSalida {
            destino: "x".into()
        }
        .es_transitorio());
    }
}
