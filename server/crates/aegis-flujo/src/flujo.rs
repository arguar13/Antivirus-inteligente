//! El flujo como grafo aciclico tipado, y el motor que lo ejecuta como una
//! transaccion.
//!
//! # El grafo se construye con tipos
//!
//! [`Flujo::nuevo`] da el nodo de entrada, con su tipo. Cada [`Flujo::paso`]
//! recibe el [`Nodo`] cuya salida consume, y el compilador exige que su tipo
//! sea el que el paso declara como entrada. Un paso que consume un proceso no
//! puede recibir un fichero:
//!
//! ```compile_fail,E0308
//! use aegis_entidad::Eid;
//! use aegis_flujo::flujo::Flujo;
//! use aegis_flujo::paso::{ErrorPaso, Fut, Paso, Reversibilidad, SinFirma};
//! use aegis_flujo::tipos::{Fichero, Proceso, Ref};
//!
//! struct SoloProcesos;
//! impl Paso<()> for SoloProcesos {
//!     type Entrada = Ref<Proceso>;
//!     type Salida = ();
//!     type Deshacer = ();
//!     type Permiso = SinFirma;
//!     const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
//!     const TOCA_FLOTA: bool = false;
//!     fn nombre(&self) -> &'static str { "solo procesos" }
//!     fn objetivos<'a>(&'a self, p: &'a Ref<Proceso>, _: &'a ()) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
//!         Box::pin(async move { Ok(vec![p.eid().clone()]) })
//!     }
//!     fn clave(&self, p: &Ref<Proceso>) -> String { p.eid().texto() }
//!     fn ejecutar<'a>(&'a self, _: &'a Ref<Proceso>, _: &'a ()) -> Fut<'a, Result<((), ()), ErrorPaso>> {
//!         Box::pin(async { Ok(((), ())) })
//!     }
//!     fn revertir<'a>(&'a self, _: (), _: &'a ()) -> Fut<'a, Result<(), ErrorPaso>> {
//!         Box::pin(async { Ok(()) })
//!     }
//! }
//!
//! let (mut f, fichero) = Flujo::<(), Ref<Fichero>>::nuevo("mal tipado");
//! f.paso(SoloProcesos, fichero, SinFirma); // un fichero no es un proceso
//! ```
//!
//! Y el grafo es aciclico POR CONSTRUCCION: un paso solo se puede enganchar a
//! un nodo que ya existe, porque [`Nodo`] no tiene constructor publico y solo lo
//! devuelven [`Flujo::nuevo`] y [`Flujo::paso`]. El orden en que se anaden los
//! pasos es, por eso mismo, un orden topologico.
//!
//! # Un paso irreversible sin firma no compila
//!
//! La comprobacion es una constante evaluada al instanciar [`Flujo::paso`] para
//! ese paso:
//!
//! ```compile_fail,E0080
//! use aegis_entidad::Eid;
//! use aegis_flujo::flujo::Flujo;
//! use aegis_flujo::paso::{ErrorPaso, Fut, Paso, Reversibilidad, SinFirma};
//! use aegis_flujo::tipos::{Proceso, Ref};
//!
//! struct IrreversibleSinFirma;
//! impl Paso<()> for IrreversibleSinFirma {
//!     type Entrada = Ref<Proceso>;
//!     type Salida = ();
//!     type Deshacer = ();
//!     type Permiso = SinFirma;
//!     const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Irreversible;
//!     const TOCA_FLOTA: bool = true;
//!     fn nombre(&self) -> &'static str { "irreversible sin firma" }
//!     fn objetivos<'a>(&'a self, p: &'a Ref<Proceso>, _: &'a ()) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
//!         Box::pin(async move { Ok(vec![p.eid().clone()]) })
//!     }
//!     fn clave(&self, p: &Ref<Proceso>) -> String { p.eid().texto() }
//!     fn ejecutar<'a>(&'a self, _: &'a Ref<Proceso>, _: &'a ()) -> Fut<'a, Result<((), ()), ErrorPaso>> {
//!         Box::pin(async { Ok(((), ())) })
//!     }
//!     fn revertir<'a>(&'a self, _: (), _: &'a ()) -> Fut<'a, Result<(), ErrorPaso>> {
//!         Box::pin(async { Ok(()) })
//!     }
//! }
//!
//! let (mut f, p) = Flujo::<(), Ref<Proceso>>::nuevo("sin firma");
//! f.paso(IrreversibleSinFirma, p, SinFirma);
//! ```
//!
//! # El motor: o todo o nada
//!
//! Los pasos se ejecutan en el orden en que se anadieron. Antes de cada paso
//! que toca la flota, los cinco frenos con SUS objetivos; antes de cada paso,
//! que su permiso cubra la ejecucion concreta. Si un paso falla —o lo detiene un
//! freno, o su firma no cubre sus objetivos—, los pasos ya hechos se REVIERTEN
//! en orden inverso, con lo que cada uno guardo del estado de antes. Lo
//! irreversible ya hecho no se finge deshacer: se cuenta y se escala.
//!
//! # Idempotencia
//!
//! Dos nodos del mismo flujo con el mismo paso y la misma clave son el mismo
//! efecto: el segundo toma la salida del primero y no lo repite. Y cada efecto
//! del catalogo es idempotente contra su estado —bloquear lo que ya esta
//! bloqueado no crea un segundo bloqueo—, asi que reintentar un flujo entero
//! tampoco duplica nada.

use std::any::Any;
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;

use aegis_entidad::Eid;

use crate::firma::huella;
use crate::frenos::{Decision, Frenos, Motivo, Solicitud};
use crate::paso::{ErrorPaso, Fut, Paso, Permiso, Reversibilidad};

type Caja = Box<dyn Any + Send + Sync>;

/// La salida de un nodo, con su tipo.
///
/// Solo la devuelven [`Flujo::nuevo`] y [`Flujo::paso`]: el grafo no puede
/// tener ciclos.
#[derive(Debug)]
pub struct Nodo<T> {
    indice: usize,
    _tipo: PhantomData<fn() -> T>,
}

impl<T> Clone for Nodo<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Nodo<T> {}

/// Un paso ya metido en el grafo, sin su tipo.
trait NodoDyn<C>: Send + Sync {
    fn nombre(&self) -> &'static str;
    fn desde(&self) -> usize;
    fn toca_flota(&self) -> bool;
    fn reversibilidad(&self) -> Reversibilidad;
    fn firmado(&self) -> bool;
    fn quien(&self) -> Option<String>;
    fn cubre(&self, h: &[u8; 32]) -> bool;
    fn objetivos<'a>(
        &'a self,
        entrada: &'a Caja,
        ctx: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>>;
    fn clave(&self, entrada: &Caja) -> Result<String, ErrorPaso>;
    fn ejecutar<'a>(
        &'a self,
        entrada: &'a Caja,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Caja, Caja), ErrorPaso>>;
    fn revertir<'a>(&'a self, deshacer: Caja, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>>;
}

struct Adaptador<P, C>
where
    P: Paso<C>,
{
    paso: P,
    desde: usize,
    permiso: P::Permiso,
    _c: PhantomData<fn(&C)>,
}

/// Recupera la entrada con su tipo. Con el grafo construido por tipos no puede
/// fallar; si fallara, seria un error del motor y se trata como un fallo del
/// paso —que revierte lo hecho—, nunca como un panico a mitad de una respuesta.
fn de<T: 'static>(c: &Caja) -> Result<&T, ErrorPaso> {
    c.downcast_ref::<T>().ok_or_else(|| {
        ErrorPaso::Entrada("el tipo de la entrada no es el que el paso declara".into())
    })
}

impl<P, C> NodoDyn<C> for Adaptador<P, C>
where
    P: Paso<C>,
    C: Send + Sync + 'static,
{
    fn nombre(&self) -> &'static str {
        self.paso.nombre()
    }
    fn desde(&self) -> usize {
        self.desde
    }
    fn toca_flota(&self) -> bool {
        P::TOCA_FLOTA
    }
    fn reversibilidad(&self) -> Reversibilidad {
        P::REVERSIBILIDAD
    }
    fn firmado(&self) -> bool {
        <P::Permiso as Permiso>::FIRMADO
    }
    fn quien(&self) -> Option<String> {
        self.permiso.quien().map(str::to_string)
    }
    fn cubre(&self, h: &[u8; 32]) -> bool {
        self.permiso.cubre(h)
    }
    fn objetivos<'a>(
        &'a self,
        entrada: &'a Caja,
        ctx: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async move { self.paso.objetivos(de::<P::Entrada>(entrada)?, ctx).await })
    }
    fn clave(&self, entrada: &Caja) -> Result<String, ErrorPaso> {
        Ok(self.paso.clave(de::<P::Entrada>(entrada)?))
    }
    fn ejecutar<'a>(
        &'a self,
        entrada: &'a Caja,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Caja, Caja), ErrorPaso>> {
        Box::pin(async move {
            let (salida, deshacer) = self.paso.ejecutar(de::<P::Entrada>(entrada)?, ctx).await?;
            Ok((Box::new(salida) as Caja, Box::new(deshacer) as Caja))
        })
    }
    fn revertir<'a>(&'a self, deshacer: Caja, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let d = deshacer.downcast::<P::Deshacer>().map_err(|_| {
                ErrorPaso::Entrada("lo guardado para deshacer no es de este paso".into())
            })?;
            self.paso.revertir(*d, ctx).await
        })
    }
}

/// Un flujo: un grafo aciclico de pasos tipados sobre un contexto `C`, cuya
/// entrada es de tipo `E`.
pub struct Flujo<C, E> {
    nombre: String,
    nodos: Vec<Box<dyn NodoDyn<C>>>,
    _e: PhantomData<fn(E)>,
}

impl<C, E> std::fmt::Debug for Flujo<C, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flujo")
            .field("nombre", &self.nombre)
            .field(
                "pasos",
                &self.nodos.iter().map(|n| n.nombre()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl<C, E> Flujo<C, E>
where
    C: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    /// Un flujo nuevo, y el nodo de su entrada.
    #[must_use]
    pub fn nuevo(nombre: &str) -> (Flujo<C, E>, Nodo<E>) {
        (
            Flujo {
                nombre: nombre.to_string(),
                nodos: Vec::new(),
                _e: PhantomData,
            },
            Nodo {
                indice: 0,
                _tipo: PhantomData,
            },
        )
    }

    /// Anade un paso que consume la salida de `desde`.
    ///
    /// El tipo de `desde` tiene que ser el de la entrada del paso, y `permiso`
    /// el que el paso exige: los dos los comprueba el compilador. Un paso
    /// irreversible cuyo permiso no es una firma humana no compila.
    pub fn paso<P: Paso<C>>(
        &mut self,
        paso: P,
        desde: Nodo<P::Entrada>,
        permiso: P::Permiso,
    ) -> Nodo<P::Salida> {
        const {
            assert!(
                !matches!(P::REVERSIBILIDAD, Reversibilidad::Irreversible)
                    || <P::Permiso as Permiso>::FIRMADO,
                "un paso irreversible exige una Firma humana como permiso"
            );
        }
        self.nodos.push(Box::new(Adaptador {
            paso,
            desde: desde.indice,
            permiso,
            _c: PhantomData,
        }));
        Nodo {
            indice: self.nodos.len(),
            _tipo: PhantomData,
        }
    }

    /// Nombre del flujo: entra en la huella que firma una persona.
    #[must_use]
    pub fn nombre(&self) -> &str {
        &self.nombre
    }

    /// Los pasos, en orden.
    #[must_use]
    pub fn pasos(&self) -> Vec<&'static str> {
        self.nodos.iter().map(|n| n.nombre()).collect()
    }
}

/// Lo que paso con un paso.
#[derive(Debug, Clone, PartialEq)]
pub enum ResultadoPaso {
    /// Se aplico y sigue aplicado.
    Hecho,
    /// Ya estaba hecho en este flujo (mismo paso, misma clave): no se repitio.
    Repetido,
    /// Fallo; con esto empezo la reversion.
    Fallido(String),
    /// Lo detuvo un freno.
    Frenado(Decision),
    /// Su permiso no cubre la ejecucion concreta: una firma para otros
    /// objetivos, u otro paso.
    SinPermiso,
    /// Se aplico y luego se revirtio.
    Revertido,
    /// Se aplico, se intento revertir y no se pudo.
    ReversionFallida(String),
    /// Se aplico y es irreversible: no se deshace, se escala.
    IrreversibleHecho,
}

/// Una fila del registro de una ejecucion.
#[derive(Debug, Clone, PartialEq)]
pub struct Registro {
    /// El paso.
    pub paso: &'static str,
    /// Sus objetivos.
    pub objetivos: Vec<Eid>,
    /// Los activos protegidos que habria tocado.
    pub preservados: Vec<Eid>,
    /// Quien lo aprobo, si hizo falta.
    pub aprobado_por: Option<String>,
    /// Que paso.
    pub resultado: ResultadoPaso,
}

/// Como termino un flujo.
#[derive(Debug, Clone, PartialEq)]
pub enum Estado {
    /// Todos los pasos se aplicaron.
    Completado,
    /// Un paso fallo y todo lo hecho se revirtio.
    Revertido {
        /// El paso que fallo.
        paso: &'static str,
        /// Por que.
        motivo: String,
    },
    /// Un freno detuvo un paso: se escala a una persona, y lo hecho se revirtio.
    Escalado {
        /// El paso detenido.
        paso: &'static str,
        /// El motivo.
        motivo: Motivo,
    },
    /// Hubo que revertir y algo no se pudo deshacer: a una persona.
    RevertidoConFallos {
        /// El paso que detuvo el flujo.
        paso: &'static str,
        /// Por que se detuvo.
        motivo: String,
        /// Los pasos que no se pudieron revertir o eran irreversibles.
        pendientes: Vec<&'static str>,
    },
}

/// El resultado de ejecutar un flujo.
#[derive(Debug, Clone, PartialEq)]
pub struct Informe {
    /// Como termino.
    pub estado: Estado,
    /// Paso a paso, en el orden del flujo.
    pub registro: Vec<Registro>,
}

/// Por que se detuvo un flujo.
enum Parada {
    Fallo(&'static str, String),
    Freno(&'static str, Motivo),
}

/// Ejecuta flujos sobre un contexto, con unos frenos.
pub struct Motor<'a, C> {
    ctx: &'a C,
    frenos: &'a dyn Frenos,
}

impl<C> std::fmt::Debug for Motor<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Motor").finish_non_exhaustive()
    }
}

impl<'a, C: Send + Sync + 'static> Motor<'a, C> {
    /// Un motor.
    #[must_use]
    pub fn nuevo(ctx: &'a C, frenos: &'a dyn Frenos) -> Motor<'a, C> {
        Motor { ctx, frenos }
    }

    /// Ejecuta un flujo con una entrada: o se aplica entero, o lo aplicado se
    /// revierte y el informe dice por que y que no se pudo deshacer.
    pub async fn ejecutar<E: Send + Sync + 'static>(
        &self,
        flujo: &Flujo<C, E>,
        entrada: E,
    ) -> Informe {
        // Los valores producidos, y en que ranura esta la salida de cada nodo
        // (el 0 es la entrada). Un paso repetido apunta a la ranura del primero.
        let mut valores: Vec<Caja> = vec![Box::new(entrada)];
        let mut ranura: Vec<usize> = vec![0];
        let mut registro: Vec<Registro> = Vec::with_capacity(flujo.nodos.len());
        // Lo hecho, para revertir: (fila del registro, nodo, deshacer).
        let mut hecho: Vec<(usize, usize, Caja)> = Vec::new();
        // Diario de idempotencia: (paso, clave) -> ranura de su salida.
        let mut diario: HashMap<(&'static str, String), usize> = HashMap::new();
        // Las entidades que ya han tocado los pasos de flota de esta ejecucion:
        // el radio que miran los frenos es el acumulado.
        let mut tocados: BTreeSet<Eid> = BTreeSet::new();
        let mut parada: Option<Parada> = None;

        for (i, n) in flujo.nodos.iter().enumerate() {
            let entrada = &valores[ranura[n.desde()]];
            let mut fila = Registro {
                paso: n.nombre(),
                objetivos: Vec::new(),
                preservados: Vec::new(),
                aprobado_por: n.quien(),
                resultado: ResultadoPaso::SinPermiso,
            };
            let clave = match n.clave(entrada) {
                Ok(k) => (n.nombre(), k),
                Err(e) => {
                    fila.resultado = ResultadoPaso::Fallido(e.to_string());
                    registro.push(fila);
                    parada = Some(Parada::Fallo(n.nombre(), e.to_string()));
                    break;
                }
            };
            if let Some(&r) = diario.get(&clave) {
                fila.resultado = ResultadoPaso::Repetido;
                registro.push(fila);
                ranura.push(r);
                continue;
            }
            let objetivos = match n.objetivos(entrada, self.ctx).await {
                Ok(o) => o,
                Err(e) => {
                    fila.resultado = ResultadoPaso::Fallido(e.to_string());
                    registro.push(fila);
                    parada = Some(Parada::Fallo(n.nombre(), e.to_string()));
                    break;
                }
            };
            // Los frenos, con los objetivos reales de ESTE paso.
            if n.toca_flota() {
                match self.frenos.evaluar(&Solicitud {
                    paso: n.nombre(),
                    objetivos: &objetivos,
                    radio: tocados.len()
                        + objetivos
                            .iter()
                            .filter(|e| !tocados.contains(*e))
                            .collect::<BTreeSet<_>>()
                            .len(),
                    reversibilidad: n.reversibilidad(),
                    firmado: n.firmado(),
                }) {
                    Decision::Actuar { preservados, .. } if !preservados.is_empty() => {
                        // Los frenos preservan los protegidos, pero el efecto de
                        // un paso es indivisible sobre su entrada: bloquear una
                        // red que contiene el controlador de dominio lo corta a
                        // el tambien. No hay forma de ejecutar el paso «sin los
                        // protegidos», asi que se detiene y lo decide una
                        // persona, con los preservados en el registro.
                        let motivo = Motivo::ProtegidosEnElRadio {
                            preservados: preservados.len(),
                        };
                        fila.objetivos = objetivos;
                        fila.preservados = preservados;
                        fila.resultado = ResultadoPaso::Frenado(Decision::Escalar(motivo.clone()));
                        registro.push(fila);
                        parada = Some(Parada::Freno(n.nombre(), motivo));
                        break;
                    }
                    Decision::Actuar { .. } => fila.objetivos = objetivos,
                    d @ (Decision::Escalar(_) | Decision::NoActuar(_)) => {
                        let (Decision::Escalar(m) | Decision::NoActuar(m)) = &d else {
                            unreachable!("el patron de arriba solo deja pasar estas dos")
                        };
                        let motivo = m.clone();
                        fila.objetivos = objetivos;
                        fila.resultado = ResultadoPaso::Frenado(d);
                        registro.push(fila);
                        parada = Some(Parada::Freno(n.nombre(), motivo));
                        break;
                    }
                }
            } else {
                fila.objetivos = objetivos;
            }
            // El permiso tiene que cubrir ESTA ejecucion: este flujo, este paso
            // y estos objetivos.
            if !n.cubre(&huella(flujo.nombre(), n.nombre(), &fila.objetivos)) {
                registro.push(fila);
                parada = Some(Parada::Fallo(
                    n.nombre(),
                    "el permiso no cubre esta ejecucion".into(),
                ));
                break;
            }
            match n.ejecutar(entrada, self.ctx).await {
                Ok((salida, deshacer)) => {
                    if n.toca_flota() {
                        tocados.extend(fila.objetivos.iter().cloned());
                    }
                    fila.resultado = ResultadoPaso::Hecho;
                    registro.push(fila);
                    hecho.push((registro.len() - 1, i, deshacer));
                    valores.push(salida);
                    ranura.push(valores.len() - 1);
                    diario.insert(clave, valores.len() - 1);
                }
                Err(e) => {
                    fila.resultado = ResultadoPaso::Fallido(e.to_string());
                    registro.push(fila);
                    parada = Some(Parada::Fallo(n.nombre(), e.to_string()));
                    break;
                }
            }
        }

        let Some(parada) = parada else {
            return Informe {
                estado: Estado::Completado,
                registro,
            };
        };
        // Reversion, en orden inverso.
        let mut pendientes: Vec<&'static str> = Vec::new();
        while let Some((r, i, deshacer)) = hecho.pop() {
            let n = &flujo.nodos[i];
            if n.reversibilidad() == Reversibilidad::Irreversible {
                registro[r].resultado = ResultadoPaso::IrreversibleHecho;
                pendientes.push(n.nombre());
                continue;
            }
            registro[r].resultado = match n.revertir(deshacer, self.ctx).await {
                Ok(()) => ResultadoPaso::Revertido,
                Err(e) => {
                    pendientes.push(n.nombre());
                    ResultadoPaso::ReversionFallida(e.to_string())
                }
            };
        }
        pendientes.reverse();
        let estado = match (parada, pendientes.is_empty()) {
            (Parada::Fallo(paso, motivo), true) => Estado::Revertido { paso, motivo },
            (Parada::Freno(paso, motivo), true) => Estado::Escalado { paso, motivo },
            (Parada::Fallo(paso, motivo), false) => Estado::RevertidoConFallos {
                paso,
                motivo,
                pendientes,
            },
            (Parada::Freno(paso, motivo), false) => Estado::RevertidoConFallos {
                paso,
                motivo: motivo.frase(),
                pendientes,
            },
        };
        Informe { estado, registro }
    }
}
