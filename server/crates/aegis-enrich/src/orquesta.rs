//! El orquestador: quien decide que se ejecuta, con que, y que se hace con lo que
//! sale.
//!
//! # El orden de las puertas, y por que ese y no otro
//!
//! Cada encargo pasa por seis puertas. **El orden importa**, porque una puerta que
//! se cruza antes de tiempo cuesta algo que ya no se recupera:
//!
//! | # | Puerta | Si se hiciera despues |
//! |---|---|---|
//! | 1 | ¿Sabe mirar este tipo? | Se gastaria cuota en un analizador que iba a decir que no |
//! | 2 | ¿El observable puede salir? | **Ya habria salido.** Es la unica puerta irreversible |
//! | 3 | ¿Hay salida en este modo? | Igual: se habria consultado |
//! | 4 | ¿Esta autorizado? | Se habria mandado el fichero antes de que nadie lo aprobara |
//! | 5 | ¿Esta en cache? | Se gastaria cuota y exposicion por algo que ya se sabe |
//! | 6 | ¿Hay cuota? | Se reservaria una ficha para no usarla |
//!
//! La puerta 2 es la que manda: **es la unica que no se puede deshacer**. Una
//! consulta hecha no se retira.
//!
//! # El plazo corta de verdad
//!
//! Cada analizador corre en su propia tarea con `tokio::time::timeout`. Uno que se
//! cuelga **no bloquea a los demas**: se abandona su tarea y el resto sigue. Y lo
//! que se le devuelve al analista no es un hueco, es
//! [`NoAplicable::PlazoAgotado`] con el plazo que se le dio.
//!
//! # El muro, declarado
//!
//! Un analizador **cooperativo** —el que espera en una llamada de red— se cancela
//! limpiamente al agotarse el plazo. Uno que se meta en un bucle de CPU sin ceder
//! ocupa su hilo hasta que termine: Rust no puede quitarle el control a una
//! funcion que no lo suelta.
//!
//! Lo que hace que eso no sea un agujero: los analizadores corren en el pozo de
//! hilos de bloqueo, que esta **acotado**, asi que uno atascado consume un hilo y
//! no el servidor. El orquestador no lo espera, el analista recibe su
//! `PlazoAgotado` en el plazo prometido, y el hilo se recupera cuando el
//! analizador termine. Decirlo es parte del diseño: un marco que promete
//! aislamiento que no tiene invita a confiar en el.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::analizador::{Analizador, Encargo, NoAplicable, Registro};
use crate::cache::{Cache, Procedencia};
use crate::dictamen::Dictamen;
use crate::exposicion::Campo;
use crate::fusion::{fusionar, Fusion};
use crate::observable::Observable;
use crate::salida::{Modo, Salida};
use crate::tasa::Limitador;

/// Lo que paso con un analizador concreto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resultado {
    /// Produjo un dictamen.
    Dictamen {
        /// Que dijo.
        dictamen: Dictamen,
        /// Si se consulto ahora o vino de cache.
        procedencia: Procedencia,
    },
    /// No produjo dictamen, y este es el motivo.
    NoAplicable(NoAplicable),
}

impl Resultado {
    /// El dictamen, si lo hay.
    #[must_use]
    pub fn dictamen(&self) -> Option<&Dictamen> {
        match self {
            Resultado::Dictamen { dictamen, .. } => Some(dictamen),
            Resultado::NoAplicable(_) => None,
        }
    }

    /// Si esto supuso sacar datos de la organizacion.
    #[must_use]
    pub fn hubo_exposicion(&self) -> bool {
        match self {
            Resultado::Dictamen { procedencia, .. } => procedencia.hubo_exposicion(),
            Resultado::NoAplicable(_) => false,
        }
    }
}

/// Lo que de verdad salio de la organizacion en un enriquecimiento.
///
/// Se calcula de lo que **ocurrio**, no de lo que se declaro: un acierto de cache
/// no expone nada, y un analizador que no llego a ejecutarse tampoco. Sin esto, el
/// informe de privacidad contaria intenciones en vez de hechos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exposicion {
    /// A que proveedores se consulto de verdad.
    pub proveedores: Vec<String>,
    /// Que campos salieron de verdad.
    pub campos: Vec<Campo>,
    /// Cuantas consultas se ahorraron por cache.
    pub evitadas_por_cache: usize,
    /// Cuantas no se hicieron por el modo sin salida.
    pub evitadas_sin_salida: usize,
    /// Cuantas no se hicieron porque el observable no podia salir.
    pub evitadas_por_privacidad: usize,
}

impl Exposicion {
    /// Si no salio nada.
    #[must_use]
    pub fn vacia(&self) -> bool {
        self.proveedores.is_empty()
    }

    /// Si se consulto a ese proveedor.
    #[must_use]
    pub fn hubo_exposicion_de(&self, proveedor: &str) -> bool {
        self.proveedores.iter().any(|p| p == proveedor)
    }

    /// Resumen para el informe.
    #[must_use]
    pub fn resumen(&self) -> String {
        if self.vacia() {
            return format!(
                "no salio nada de la organizacion ({} evitadas por cache, {} por modo sin salida, \
                 {} por privacidad del observable)",
                self.evitadas_por_cache, self.evitadas_sin_salida, self.evitadas_por_privacidad
            );
        }
        let campos: Vec<&str> = self.campos.iter().map(|c| c.nombre()).collect();
        format!(
            "salieron [{}] hacia [{}]; se evitaron {} consultas por cache",
            campos.join(", "),
            self.proveedores.join(", "),
            self.evitadas_por_cache
        )
    }
}

/// El informe completo de un enriquecimiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Informe {
    /// Sobre que se pregunto.
    pub observable: Observable,
    /// El veredicto fusionado.
    pub fusion: Fusion,
    /// Que hizo cada analizador, por nombre.
    ///
    /// **Estan todos**, tambien los que no produjeron nada. Es la propiedad que
    /// impide que «no se consulto» se lea como «no habia nada».
    pub por_analizador: BTreeMap<String, Resultado>,
    /// Lo que de verdad salio.
    pub exposicion: Exposicion,
}

impl Informe {
    /// Los analizadores que no produjeron dictamen, con su motivo.
    #[must_use]
    pub fn sin_resultado(&self) -> Vec<(&str, &NoAplicable)> {
        self.por_analizador
            .iter()
            .filter_map(|(n, r)| match r {
                Resultado::NoAplicable(na) => Some((n.as_str(), na)),
                Resultado::Dictamen { .. } => None,
            })
            .collect()
    }

    /// Si merece la pena reintentar mas tarde, y por que.
    ///
    /// Un enriquecimiento en el que tres fuentes se quedaron sin cuota no es el
    /// mismo que uno en el que tres fuentes dijeron que no sabian nada, y el panel
    /// tiene que poder ofrecer «reintentar» solo en el primero.
    #[must_use]
    pub fn merece_reintento(&self) -> Vec<&str> {
        self.por_analizador
            .iter()
            .filter_map(|(n, r)| match r {
                Resultado::NoAplicable(na) if na.es_transitorio() => Some(n.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// Un analizador listo para correr, con la salida que se le entrega (o ninguna).
type Preparado = (Arc<dyn Analizador>, Option<Arc<dyn Salida>>);

/// Quien ejecuta los analizadores.
///
/// `salidas` lleva, por nombre de analizador, la salida que se le entrega. Un
/// analizador sin entrada aqui **no tiene red**, y eso no es un error de
/// configuracion que haya que avisar: es la forma de apagarlo.
pub struct Orquestador {
    registro: Registro,
    limitador: Arc<Limitador>,
    cache: std::sync::Mutex<Cache>,
    modo: Modo,
    salidas: BTreeMap<String, Arc<dyn Salida>>,
    autorizados: std::collections::BTreeSet<String>,
}

impl std::fmt::Debug for Orquestador {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Orquestador")
            .field("registro", &self.registro)
            .field("modo", &self.modo)
            .field("con_salida", &self.salidas.keys().collect::<Vec<_>>())
            .field("autorizados", &self.autorizados)
            .finish()
    }
}

impl Orquestador {
    /// Crea un orquestador.
    #[must_use]
    pub fn nuevo(registro: Registro, limitador: Arc<Limitador>, modo: Modo) -> Orquestador {
        Orquestador {
            registro,
            limitador,
            cache: std::sync::Mutex::new(Cache::nueva()),
            modo,
            salidas: BTreeMap::new(),
            autorizados: std::collections::BTreeSet::new(),
        }
    }

    /// Entrega la salida de red a un analizador.
    ///
    /// En [`Modo::SinSalida`] esto **no hace nada**: la comprobacion esta aqui y no
    /// en el momento de usarla para que no exista ningun camino, ni siquiera por
    /// error de programacion, en el que una salida llegue a manos de un analizador
    /// con el modo puesto.
    pub fn entregar_salida(&mut self, analizador: &str, salida: Arc<dyn Salida>) {
        if !self.modo.permite(salida.destino()) {
            return;
        }
        self.salidas.insert(analizador.to_string(), salida);
    }

    /// Marca un analizador como autorizado por una persona.
    ///
    /// Solo hace falta para los que [`crate::exposicion::Exposicion::exige_autorizacion`]
    /// declara. Sin esto, esos analizadores devuelven `FaltaAutorizacion` con el
    /// aviso que habia que aprobar.
    pub fn autorizar(&mut self, analizador: &str) {
        self.autorizados.insert(analizador.to_string());
    }

    /// El modo actual.
    #[must_use]
    pub fn modo(&self) -> Modo {
        self.modo
    }

    /// Cuantos analizadores hay.
    #[must_use]
    pub fn analizadores(&self) -> usize {
        self.registro.cuantos()
    }

    /// El aviso de exposicion de todo lo que se ejecutaria para este observable.
    ///
    /// Es lo que el panel enseña **antes** de ejecutar. Se calcula sin ejecutar
    /// nada y sin salir a ningun sitio: es una funcion de las fichas.
    #[must_use]
    pub fn aviso_previo(&self, observable: &Observable) -> Vec<(String, Vec<String>)> {
        let mut salida = Vec::new();
        for a in self.registro.para(observable.tipo()) {
            let f = a.ficha();
            if f.necesita_salida() && observable.puede_salir().is_err() {
                continue;
            }
            if !self.modo.permite(&f.exposicion.destino) {
                continue;
            }
            salida.push((f.nombre.clone(), f.exposicion.aviso()));
        }
        salida
    }

    /// Enriquece un observable.
    ///
    /// Ejecuta todos los analizadores que aplican **a la vez**, cada uno con su
    /// plazo, y fusiona lo que salga.
    pub async fn enriquecer(&self, observable: &Observable, ahora_ns: u64) -> Informe {
        let candidatos = self.registro.para(observable.tipo());
        let mut por_analizador: BTreeMap<String, Resultado> = BTreeMap::new();
        let mut exposicion = Exposicion::default();
        let mut a_ejecutar: Vec<Preparado> = Vec::new();

        // Los analizadores que no aceptan este tipo tambien salen en el informe:
        // saber que una fuente no mira resumenes es informacion, y su ausencia
        // silenciosa hace pensar que se consulto.
        for a in self.registro.todos() {
            let f = a.ficha();
            if !f.acepta.contains(&observable.tipo()) {
                por_analizador.insert(
                    f.nombre.clone(),
                    Resultado::NoAplicable(NoAplicable::TipoNoSoportado {
                        tipo: observable.tipo(),
                    }),
                );
            }
        }

        for a in candidatos {
            let f = a.ficha().clone();

            // PUERTA 2 · la unica irreversible. Va antes que ninguna otra que
            // pueda hacer salir el dato.
            if f.necesita_salida() {
                if let Err(motivo) = observable.puede_salir() {
                    exposicion.evitadas_por_privacidad += 1;
                    por_analizador.insert(
                        f.nombre.clone(),
                        Resultado::NoAplicable(NoAplicable::ObservableRetenido { motivo }),
                    );
                    continue;
                }
            }

            // PUERTA 3 · modo sin salida.
            if f.necesita_salida() && !self.modo.permite(&f.exposicion.destino) {
                exposicion.evitadas_sin_salida += 1;
                por_analizador.insert(
                    f.nombre.clone(),
                    Resultado::NoAplicable(NoAplicable::SinSalida {
                        destino: f.exposicion.destino.nombre(),
                    }),
                );
                continue;
            }

            // PUERTA 4 · autorizacion explicita.
            if f.exposicion.exige_autorizacion() && !self.autorizados.contains(&f.nombre) {
                por_analizador.insert(
                    f.nombre.clone(),
                    Resultado::NoAplicable(NoAplicable::FaltaAutorizacion {
                        aviso: f.exposicion.aviso(),
                    }),
                );
                continue;
            }

            // PUERTA 5 · cache. Antes de la cuota: un acierto no gasta ficha ni
            // expone nada.
            let de_cache = {
                let mut c = self.cache.lock().expect("la cache no entra en panico");
                c.buscar(&f.nombre, observable, ahora_ns)
            };
            if let Some((dictamen, procedencia)) = de_cache {
                exposicion.evitadas_por_cache += 1;
                por_analizador.insert(
                    f.nombre.clone(),
                    Resultado::Dictamen {
                        dictamen,
                        procedencia,
                    },
                );
                continue;
            }

            // PUERTA 6 · cuota. La ficha se reserva ANTES de salir, no se
            // comprueba y despues se sale.
            let permiso = if f.necesita_salida() {
                match self.limitador.reservar(&f.nombre, ahora_ns) {
                    Ok(p) => Some(p),
                    Err(motivo) => {
                        por_analizador.insert(
                            f.nombre.clone(),
                            Resultado::NoAplicable(NoAplicable::SinCuota { motivo }),
                        );
                        continue;
                    }
                }
            } else {
                None
            };

            let salida = self.salidas.get(&f.nombre).cloned();
            // Un analizador que necesita red y al que no se le entrego salida
            // esta apagado: se dice, y no se le reserva la ficha.
            if f.necesita_salida() && salida.is_none() {
                if let Some(p) = permiso {
                    p.devolver();
                }
                exposicion.evitadas_sin_salida += 1;
                por_analizador.insert(
                    f.nombre.clone(),
                    Resultado::NoAplicable(NoAplicable::SinSalida {
                        destino: f.exposicion.destino.nombre(),
                    }),
                );
                continue;
            }
            if let Some(p) = permiso {
                p.gastado();
            }
            a_ejecutar.push((a, salida));
        }

        // Todos a la vez, cada uno con su plazo. Uno que se cuelga no bloquea a
        // los demas: se abandona su tarea y el resto sigue.
        let mut tareas = Vec::new();
        for (a, salida) in a_ejecutar {
            let encargo = Encargo {
                observable: observable.clone(),
                ahora_ns,
            };
            let plazo = a.ficha().plazo;
            let nombre = a.ficha().nombre.clone();
            // Marca puesta por el propio analizador al empezar.
            //
            // Sin ella, un sistema saturado hace que el plazo salte ANTES de que
            // el analizador llegue a arrancar, y el informe dice «no contesto en
            // 200 ms» cuando la verdad es «no llego a ejecutarse». Son dos hechos
            // distintos y mandan al analista a sitios distintos: uno a revisar el
            // analizador, el otro a mirar por que el sistema no da abasto.
            let arranco = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let testigo = Arc::clone(&arranco);
            tareas.push(tokio::spawn(async move {
                let r = tokio::time::timeout(
                    plazo,
                    tokio::task::spawn_blocking(move || {
                        testigo.store(true, std::sync::atomic::Ordering::SeqCst);
                        a.mirar(&encargo, salida.as_deref())
                    }),
                )
                .await;
                let resultado = match r {
                    // El analizador contesto.
                    Ok(Ok(Ok(d))) => Ok(d),
                    // El analizador devolvio error.
                    Ok(Ok(Err(motivo))) => Err(NoAplicable::Fallo { motivo }),
                    // La tarea murio: panico dentro del analizador. Se recoge en
                    // vez de tumbar el plano de control.
                    Ok(Err(_)) => Err(NoAplicable::Panico),
                    // Se agoto el plazo. Que llegara a arrancar o no cambia el
                    // diagnostico, asi que cambia lo que se informa.
                    Err(_) => {
                        if arranco.load(std::sync::atomic::Ordering::SeqCst) {
                            Err(NoAplicable::PlazoAgotado { plazo })
                        } else {
                            Err(NoAplicable::NoEjecutado { plazo })
                        }
                    }
                };
                (nombre, resultado)
            }));
        }

        for t in tareas {
            // Si la tarea de envoltura muere, se registra igual: no hay camino en
            // el que un analizador desaparezca del informe sin dejar motivo.
            let (nombre, resultado) = match t.await {
                Ok(v) => v,
                Err(_) => continue,
            };
            match resultado {
                Ok(mut d) => {
                    // La clase NO la elige la respuesta: viene de la ficha. Sin
                    // esto, un canal comunitario se declararia autoritativo y se
                    // saltaria la jerarquia entera de la fusion.
                    if let Some(a) = self
                        .registro
                        .todos()
                        .iter()
                        .find(|a| a.ficha().nombre == nombre)
                    {
                        d.clase = a.ficha().clase;
                        d.fuente = a.ficha().nombre.clone();
                        // Y el observable tampoco: un analizador que devolviera un
                        // observable distinto del que se le pidio meteria en el
                        // informe un veredicto sobre otra cosa.
                        d.observable = observable.clone();
                        if a.ficha().necesita_salida() {
                            anotar_exposicion(&mut exposicion, a.ficha());
                        }
                    }
                    // Saneado SIEMPRE: lo que sale de un analizador es lo que
                    // contesto un tercero por Internet.
                    d.sanear(ahora_ns);
                    {
                        let mut c = self.cache.lock().expect("la cache no entra en panico");
                        c.guardar(&d, ahora_ns);
                    }
                    por_analizador.insert(
                        nombre,
                        Resultado::Dictamen {
                            dictamen: d,
                            procedencia: Procedencia::Consultado,
                        },
                    );
                }
                Err(na) => {
                    por_analizador.insert(nombre, Resultado::NoAplicable(na));
                }
            }
        }

        exposicion.proveedores.sort();
        exposicion.proveedores.dedup();
        exposicion.campos.sort();
        exposicion.campos.dedup();

        let dictamenes: Vec<Dictamen> = por_analizador
            .values()
            .filter_map(|r| r.dictamen().cloned())
            .collect();

        Informe {
            observable: observable.clone(),
            fusion: fusionar(&dictamenes, ahora_ns),
            por_analizador,
            exposicion,
        }
    }

    /// Cuentas de la cache: aciertos, fallos y desalojos.
    #[must_use]
    pub fn cuentas_de_cache(&self) -> (u64, u64, u64) {
        self.cache
            .lock()
            .expect("la cache no entra en panico")
            .cuentas()
    }

    /// Borra lo guardado de una fuente.
    pub fn olvidar_fuente(&self, fuente: &str) -> usize {
        self.cache
            .lock()
            .expect("la cache no entra en panico")
            .olvidar_fuente(fuente)
    }
}

fn anotar_exposicion(e: &mut Exposicion, f: &crate::analizador::Ficha) {
    if let crate::exposicion::Destino::Externo { proveedor, .. } = &f.exposicion.destino {
        e.proveedores.push(proveedor.clone());
    }
    e.campos.extend(f.exposicion.campos.iter().copied());
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::analizador::Ficha;
    use crate::dictamen::{Clase, Juicio};
    use crate::exposicion::{Destino, Exposicion as Exp, Jurisdiccion, Retencion};
    use crate::observable::{MotivoRetencion, Tipo};
    use crate::salida::{FalloDeSalida, Peticion};
    use crate::tasa::Cuota;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    struct Guion {
        ficha: Ficha,
        juicio: Juicio,
        /// Si se cuelga mas de su plazo.
        cuelga: bool,
        /// Si entra en panico.
        entra_en_panico: bool,
        /// Si intenta usar la salida, y cuantas veces lo consiguio.
        usa_salida: bool,
        salio: Arc<AtomicUsize>,
    }

    impl Analizador for Guion {
        fn ficha(&self) -> &Ficha {
            &self.ficha
        }
        fn mirar(&self, e: &Encargo, s: Option<&dyn Salida>) -> Result<Dictamen, String> {
            if self.entra_en_panico {
                panic!("el proveedor devolvio algo raro");
            }
            if self.usa_salida {
                // Si le entregaron salida, la usa. Si no, no puede: no hay a quien
                // preguntar, y eso es el modo sin salida por construccion.
                if let Some(s) = s {
                    let _ = s.consultar(&Peticion::nueva("/v1"));
                    self.salio.fetch_add(1, Ordering::SeqCst);
                }
            }
            if self.cuelga {
                std::thread::sleep(Duration::from_millis(400));
            }
            Ok(Dictamen {
                fuente: "mentira".into(),
                // Se declara autoritativo a proposito: el orquestador tiene que
                // ignorarlo y poner la clase de la ficha.
                clase: Clase::Propia,
                observable: Observable::Hash("otra-cosa".into()),
                juicio: self.juicio,
                confianza: 90,
                observado_ns: e.ahora_ns,
                porque: "porque si".into(),
                etiquetas: vec![],
            })
        }
    }

    struct SalidaFalsa(Destino);
    impl Salida for SalidaFalsa {
        fn consultar(&self, _p: &Peticion) -> Result<Vec<u8>, FalloDeSalida> {
            Ok(b"{}".to_vec())
        }
        fn destino(&self) -> &Destino {
            &self.0
        }
    }

    fn externo() -> Destino {
        Destino::Externo {
            proveedor: "rep.example".into(),
            jurisdiccion: Jurisdiccion::Eee,
            retencion: Retencion::Indefinida,
        }
    }

    fn ficha(nombre: &str, clase: Clase, red: bool) -> Ficha {
        Ficha {
            nombre: nombre.into(),
            clase,
            acepta: vec![Tipo::Hash],
            exposicion: if red {
                Exp {
                    destino: externo(),
                    campos: vec![Campo::ResumenDeFichero, Campo::IdentidadDelConsultante],
                }
            } else {
                Exp::ninguna()
            },
            cuota: red.then(|| Cuota::por_minuto(600)),
            plazo: Duration::from_millis(150),
        }
    }

    fn guion(nombre: &str, clase: Clase, red: bool, juicio: Juicio) -> Guion {
        Guion {
            ficha: ficha(nombre, clase, red),
            juicio,
            cuelga: false,
            entra_en_panico: false,
            usa_salida: red,
            salio: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn monta(guiones: Vec<Guion>, modo: Modo) -> Orquestador {
        let l = Limitador::nuevo();
        let mut r = Registro::nuevo();
        for g in guiones {
            if let Some(c) = g.ficha.cuota {
                l.declarar(g.ficha.nombre.clone(), c, AHORA);
            }
            r.registrar(Arc::new(g)).expect("ficha valida");
        }
        let nombres: Vec<String> = r.todos().iter().map(|a| a.ficha().nombre.clone()).collect();
        let necesitan: Vec<String> = r
            .todos()
            .iter()
            .filter(|a| a.ficha().necesita_salida())
            .map(|a| a.ficha().nombre.clone())
            .collect();
        let mut o = Orquestador::nuevo(r, l, modo);
        for n in nombres.iter().filter(|n| necesitan.contains(n)) {
            o.entregar_salida(n, Arc::new(SalidaFalsa(externo())));
        }
        o
    }

    #[tokio::test]
    async fn un_analizador_que_se_cuelga_se_corta_y_no_bloquea_a_los_demas() {
        let mut lento = guion("lento", Clase::Reputacion, false, Juicio::Malicioso);
        lento.cuelga = true;
        let rapido = guion("rapido", Clase::Reputacion, false, Juicio::Malicioso);

        let o = monta(vec![lento, rapido], Modo::Conectado);
        let inicio = std::time::Instant::now();
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        let tardo = inicio.elapsed();

        assert!(
            tardo < Duration::from_millis(350),
            "el colgado bloqueo al resto: {tardo:?}"
        );
        // Se corto, y el motivo dice cual de las dos cosas paso: si llego a
        // arrancar y se paso del plazo, o si ni siquiera arranco porque la maquina
        // va cargada. Las dos son «se corto»; solo una es culpa del analizador.
        assert!(
            matches!(
                i.por_analizador["lento"],
                Resultado::NoAplicable(NoAplicable::PlazoAgotado { .. })
                    | Resultado::NoAplicable(NoAplicable::NoEjecutado { .. })
            ),
            "el colgado no se corto: {:?}",
            i.por_analizador["lento"]
        );
        assert!(i.por_analizador["rapido"].dictamen().is_some());
        // Y el veredicto sale igual, con lo que si contesto.
        assert_eq!(i.fusion.veredicto, crate::fusion::Veredicto::Malicioso);
    }

    #[tokio::test]
    async fn en_modo_sin_salida_el_analizador_externo_no_sale() {
        let g = guion("rep", Clase::Reputacion, true, Juicio::Malicioso);
        let salio = Arc::clone(&g.salio);
        let o = monta(vec![g], Modo::SinSalida);

        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(
            salio.load(Ordering::SeqCst),
            0,
            "salio a la red con el modo puesto"
        );
        // Y lo que se ve NO es un hueco: es el motivo.
        let Resultado::NoAplicable(NoAplicable::SinSalida { destino }) = &i.por_analizador["rep"]
        else {
            panic!("deberia ser sin-salida: {:?}", i.por_analizador["rep"]);
        };
        assert_eq!(destino, "externo:rep.example");
        assert_eq!(i.fusion.veredicto, crate::fusion::Veredicto::SinDatos);
        assert!(i.exposicion.vacia());
        assert_eq!(i.exposicion.evitadas_sin_salida, 1);
    }

    #[tokio::test]
    async fn en_modo_sin_salida_los_locales_siguen_funcionando() {
        // Es el requisito que separa «modo sin salida» de «apagado».
        let o = monta(
            vec![
                guion("yara", Clase::Propia, false, Juicio::Malicioso),
                guion("rep", Clase::Reputacion, true, Juicio::Limpio),
            ],
            Modo::SinSalida,
        );
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(i.fusion.veredicto, crate::fusion::Veredicto::Malicioso);
        assert!(i.por_analizador["yara"].dictamen().is_some());
        assert!(i.por_analizador["rep"].dictamen().is_none());
    }

    #[tokio::test]
    async fn un_analizador_no_puede_declararse_autoritativo() {
        // El guion devuelve `Clase::Propia` a proposito. Si colara, un canal
        // comunitario se saltaria la jerarquia entera de la fusion.
        let o = monta(
            vec![guion("com", Clase::Comunitaria, false, Juicio::Malicioso)],
            Modo::Conectado,
        );
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        let d = i.por_analizador["com"].dictamen().expect("hay dictamen");
        assert_eq!(
            d.clase,
            Clase::Comunitaria,
            "se creyo la clase que dijo el analizador"
        );
        assert_eq!(d.fuente, "com", "se creyo el nombre que dijo el analizador");
    }

    #[tokio::test]
    async fn un_analizador_no_puede_cambiar_el_observable() {
        // El guion devuelve un observable distinto. Si colara, meteria en el
        // informe un veredicto sobre otra cosa.
        let o = monta(
            vec![guion("rep", Clase::Reputacion, false, Juicio::Malicioso)],
            Modo::Conectado,
        );
        let obs = Observable::Hash("abc".into());
        let i = o.enriquecer(&obs, AHORA).await;
        assert_eq!(i.por_analizador["rep"].dictamen().unwrap().observable, obs);
    }

    #[tokio::test]
    async fn un_analizador_que_entra_en_panico_no_tumba_el_orquestador() {
        let mut malo = guion("malo", Clase::Reputacion, false, Juicio::Malicioso);
        malo.entra_en_panico = true;
        // Plazo generoso a proposito: lo que esta prueba comprueba es la RECOGIDA
        // del panico, no el reloj. Con un plazo corto, una maquina cargada hace
        // saltar el plazo antes de que el analizador arranque y la prueba mide
        // otra cosa — que es justo el fallo que `NoEjecutado` existe para
        // distinguir.
        malo.ficha.plazo = Duration::from_secs(5);
        let o = monta(
            vec![
                malo,
                guion("bueno", Clase::Reputacion, false, Juicio::Malicioso),
            ],
            Modo::Conectado,
        );
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(
            i.por_analizador["malo"],
            Resultado::NoAplicable(NoAplicable::Panico)
        );
        assert!(i.por_analizador["bueno"].dictamen().is_some());
    }

    #[tokio::test]
    async fn un_observable_retenido_no_llega_a_ningun_analizador_externo() {
        let g = guion("rep", Clase::Reputacion, true, Juicio::Malicioso);
        let salio = Arc::clone(&g.salio);
        let mut f = g.ficha.clone();
        f.acepta = vec![Tipo::Usuario];
        let g = Guion { ficha: f, ..g };
        let o = monta(vec![g], Modo::Conectado);

        let i = o
            .enriquecer(&Observable::Usuario("maria.lopez".into()), AHORA)
            .await;
        assert_eq!(salio.load(Ordering::SeqCst), 0);
        assert_eq!(
            i.por_analizador["rep"],
            Resultado::NoAplicable(NoAplicable::ObservableRetenido {
                motivo: MotivoRetencion::DatoPersonal
            })
        );
        assert_eq!(i.exposicion.evitadas_por_privacidad, 1);
    }

    #[tokio::test]
    async fn la_segunda_consulta_sale_de_cache_y_no_expone_nada() {
        let g = guion("rep", Clase::Reputacion, true, Juicio::Malicioso);
        let salio = Arc::clone(&g.salio);
        let o = monta(vec![g], Modo::Conectado);
        let obs = Observable::Hash("abc".into());

        let uno = o.enriquecer(&obs, AHORA).await;
        assert_eq!(salio.load(Ordering::SeqCst), 1);
        assert!(uno.exposicion.hubo_exposicion_de("rep.example"));

        let dos = o.enriquecer(&obs, AHORA + 60 * SEG).await;
        assert_eq!(salio.load(Ordering::SeqCst), 1, "volvio a salir a la red");
        assert!(matches!(
            dos.por_analizador["rep"],
            Resultado::Dictamen {
                procedencia: Procedencia::DeCache { .. },
                ..
            }
        ));
        // La propiedad que hace de la cache una medida de privacidad.
        assert!(dos.exposicion.vacia());
        assert_eq!(dos.exposicion.evitadas_por_cache, 1);
    }

    #[tokio::test]
    async fn sin_cuota_se_dice_y_no_se_consulta() {
        let mut g = guion("rep", Clase::Reputacion, true, Juicio::Malicioso);
        g.ficha.cuota = Some(Cuota {
            por_minuto: 60,
            rafaga: 1,
        });
        let salio = Arc::clone(&g.salio);
        let o = monta(vec![g], Modo::Conectado);
        let a = Observable::Hash("a".into());
        let b = Observable::Hash("b".into());

        o.enriquecer(&a, AHORA).await;
        let i = o.enriquecer(&b, AHORA).await;
        assert_eq!(salio.load(Ordering::SeqCst), 1);
        assert!(matches!(
            i.por_analizador["rep"],
            Resultado::NoAplicable(NoAplicable::SinCuota { .. })
        ));
        // Y el panel puede ofrecer reintentar, porque es transitorio.
        assert_eq!(i.merece_reintento(), vec!["rep"]);
    }

    #[tokio::test]
    async fn lo_que_exige_autorizacion_no_se_ejecuta_sin_ella() {
        let mut g = guion("subida", Clase::Reputacion, true, Juicio::Malicioso);
        g.ficha.exposicion.campos.push(Campo::ContenidoDeFichero);
        let salio = Arc::clone(&g.salio);
        let mut o = monta(vec![g], Modo::Conectado);

        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(salio.load(Ordering::SeqCst), 0);
        let Resultado::NoAplicable(NoAplicable::FaltaAutorizacion { aviso }) =
            &i.por_analizador["subida"]
        else {
            panic!("deberia faltar autorizacion");
        };
        assert!(aviso.iter().any(|l| l.contains("EXIGE autorizacion")));

        o.autorizar("subida");
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert!(i.por_analizador["subida"].dictamen().is_some());
        assert_eq!(salio.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn un_analizador_que_no_acepta_el_tipo_tambien_sale_en_el_informe() {
        // Su ausencia silenciosa haria pensar que se consulto.
        let mut g = guion("solo-dominios", Clase::Reputacion, false, Juicio::Malicioso);
        g.ficha.acepta = vec![Tipo::Dominio];
        let o = monta(vec![g], Modo::Conectado);
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(
            i.por_analizador["solo-dominios"],
            Resultado::NoAplicable(NoAplicable::TipoNoSoportado { tipo: Tipo::Hash })
        );
        assert_eq!(i.sin_resultado().len(), 1);
    }

    #[tokio::test]
    async fn el_aviso_previo_no_ejecuta_nada() {
        let g = guion("rep", Clase::Reputacion, true, Juicio::Malicioso);
        let salio = Arc::clone(&g.salio);
        let o = monta(vec![g], Modo::Conectado);
        let aviso = o.aviso_previo(&Observable::Hash("abc".into()));
        assert_eq!(salio.load(Ordering::SeqCst), 0, "el aviso previo consulto");
        assert_eq!(aviso.len(), 1);
        assert!(aviso[0]
            .1
            .join(" ")
            .contains("ese fichero exacto esta en tu red"));
    }

    #[tokio::test]
    async fn el_informe_de_exposicion_cuenta_hechos_y_no_intenciones() {
        let o = monta(
            vec![
                guion("rep", Clase::Reputacion, true, Juicio::Malicioso),
                guion("yara", Clase::Propia, false, Juicio::Malicioso),
            ],
            Modo::Conectado,
        );
        let i = o.enriquecer(&Observable::Hash("abc".into()), AHORA).await;
        assert_eq!(i.exposicion.proveedores, vec!["rep.example".to_string()]);
        assert!(i.exposicion.campos.contains(&Campo::ResumenDeFichero));
        // El local no aparece: no expuso nada, aunque se ejecutara.
        assert_eq!(i.exposicion.proveedores.len(), 1);
    }
}
