//! El rasgo [`Tabla`], sus filas, y el motivo por el que a veces no hay ninguna.
//!
//! # La idea que sostiene el modulo entero
//!
//! Hay tres respuestas posibles a «dame los procesos de esta maquina», y un
//! producto serio tiene que poder distinguirlas:
//!
//!   1. Aqui estan, y son estos.
//!   2. No hay ninguno. (Raro en procesos; normal en `suid_binaries`.)
//!   3. No he podido mirar.
//!
//! osquery colapsa la segunda y la tercera en una lista vacia. Eso no es un
//! descuido de su implementacion: es lo que ocurre cuando el tipo de retorno es
//! `Vec<Fila>` y no hay sitio donde poner el motivo. La firma de [`Tabla::leer`]
//! —`Result<Filas, MotivoNoLeible>`— existe para que la tercera respuesta tenga
//! donde vivir, y para que sea IMPOSIBLE devolverla como si fuera la segunda.
//!
//! Hay ademas una cuarta respuesta, mas sutil, que tambien necesita sitio: «he
//! mirado, aqui esta lo que vi, y estas otras cosas no las pude ver». Una tabla
//! de ficheros que enumera diez mil y no puede abrir tres no ha fallado, pero
//! tampoco ha visto la maquina entera. Para eso estan los [`Aviso`]s dentro de
//! [`Filas`]: la lectura tuvo exito Y declara sus huecos.

use std::fmt;

use aegis_entidad::{Clase, Eid};
use aegis_parser::ast::Literal;
use aegis_parser::esquema::{Coste, Tabla as Esquema};
use aegis_parser::valor::Valor;

use crate::contexto::Contexto;

// ---------------------------------------------------------------------------
// Por que no se pudo leer
// ---------------------------------------------------------------------------

/// Por que una tabla no se pudo leer.
///
/// LA AUSENCIA ES LA FRONTERA: no hay variante `Otro(String)` ni
/// `Desconocido`. Cada motivo que este enumerado puede expresar es un motivo
/// que alguien penso, escribio y puede explicar a un analista. El dia que haga
/// falta uno nuevo, se anade con su frase; lo que no se puede es esconder un
/// fallo sin diagnosticar detras de una variante comodin, porque esa variante
/// se convierte en el vertedero donde acaban todos los fallos que nadie miro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MotivoNoLeible {
    /// El agente no tiene permiso, y se dice CUAL hace falta.
    SinPrivilegios {
        /// Que se intentaba hacer.
        operacion: &'static str,
        /// Que privilegio concreto lo permitiria.
        necesita: &'static str,
    },
    /// La interfaz del nucleo no existe en esta version o no esta compilada.
    NoExisteEnEsteNucleo {
        /// Interfaz que falta, por su nombre real.
        interfaz: &'static str,
    },
    /// La tabla no tiene sentido en esta plataforma.
    ///
    /// Distinta de la anterior a proposito: «este nucleo no trae cgroup v2» y
    /// «esto es Windows» llevan al analista a sitios distintos.
    NoAplicaEnEstaPlataforma {
        /// Interfaz nativa que haria falta.
        interfaz: &'static str,
    },
    /// La fuente no esta en el sistema de ficheros.
    FuenteAusente {
        /// Ruta que se esperaba encontrar.
        ruta: String,
    },
    /// Lo que se estaba leyendo cambio mientras se leia.
    ///
    /// No es un error del agente: un proceso que muere a mitad de la
    /// enumeracion es el funcionamiento normal de una maquina viva. Se declara
    /// porque una lectura no atomica no puede presentarse como una foto.
    CambioDuranteLaLectura {
        /// Que cambio.
        ruta: String,
    },
    /// El sistema devolvio un error que no encaja en los anteriores.
    ErrorDelSistema {
        /// Operacion que fallo.
        operacion: &'static str,
        /// Lo que dijo el sistema, tal cual.
        detalle: String,
    },
    /// La tabla es de coste [`Coste::Peligroso`] y la consulta no la filtro.
    ///
    /// No es un fallo de lectura: es una NEGATIVA, y es la unica variante que
    /// el proveedor devuelve sin haber tocado el sistema. Ver [`crate::coste`].
    RequiereFiltro {
        /// Columnas por las que se puede acotar para que la consulta se admita.
        columnas: &'static [&'static str],
    },
    /// Se agoto el presupuesto de tiempo antes de poder empezar.
    PresupuestoAgotado,
}

impl MotivoNoLeible {
    /// La frase que ve el analista.
    ///
    /// Se escribe aqui y no en la consola porque el motivo viaja: de la tabla
    /// al ejecutor, del ejecutor al informe, del informe al plano de control y
    /// de ahi al panel. Si cada capa lo redactara a su manera, el analista
    /// leeria una cosa distinta segun donde mirase.
    pub fn frase(&self) -> String {
        match self {
            MotivoNoLeible::SinPrivilegios {
                operacion,
                necesita,
            } => {
                format!("sin privilegios para {operacion}: hace falta {necesita}")
            }
            MotivoNoLeible::NoExisteEnEsteNucleo { interfaz } => {
                format!("este nucleo no expone {interfaz}")
            }
            MotivoNoLeible::NoAplicaEnEstaPlataforma { interfaz } => {
                format!("no aplica en esta plataforma: {interfaz} es de otra")
            }
            MotivoNoLeible::FuenteAusente { ruta } => {
                format!("la fuente no existe en esta maquina: {ruta}")
            }
            MotivoNoLeible::CambioDuranteLaLectura { ruta } => {
                format!("cambio mientras se leia: {ruta}")
            }
            MotivoNoLeible::ErrorDelSistema { operacion, detalle } => {
                format!("el sistema fallo al {operacion}: {detalle}")
            }
            MotivoNoLeible::RequiereFiltro { columnas } => {
                format!(
                    "tabla de coste peligroso: hay que acotar la consulta por {}",
                    columnas.join(" o ")
                )
            }
            MotivoNoLeible::PresupuestoAgotado => {
                "se agoto el presupuesto de la consulta antes de leer esta tabla".to_string()
            }
        }
    }

    /// Indica si el motivo depende de la maquina y no de la consulta.
    ///
    /// Lo usa el plano de control para NO contar como fallo de la caceria que
    /// una tabla de TPM no exista en una maquina sin TPM. Una flota
    /// heterogenea produce estos motivos por diseño, no por avería.
    pub fn es_de_la_maquina(&self) -> bool {
        matches!(
            self,
            MotivoNoLeible::NoExisteEnEsteNucleo { .. }
                | MotivoNoLeible::NoAplicaEnEstaPlataforma { .. }
                | MotivoNoLeible::FuenteAusente { .. }
        )
    }

    /// Indica si volver a intentarlo podria dar otro resultado.
    pub fn es_transitorio(&self) -> bool {
        matches!(
            self,
            MotivoNoLeible::CambioDuranteLaLectura { .. } | MotivoNoLeible::PresupuestoAgotado
        )
    }
}

impl fmt::Display for MotivoNoLeible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.frase())
    }
}

// ---------------------------------------------------------------------------
// Lo que si se pudo leer
// ---------------------------------------------------------------------------

/// Un hueco dentro de una lectura que, por lo demas, tuvo exito.
///
/// La diferencia con [`MotivoNoLeible`] es de alcance, no de gravedad: aquel
/// dice «no hay tabla», este dice «hay tabla, y le faltan estas filas».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aviso {
    /// Que no se pudo ver.
    pub sujeto: String,
    /// Por que.
    pub motivo: MotivoNoLeible,
}

/// Una fila, con sus valores en el orden del esquema.
#[derive(Debug, Clone, PartialEq)]
pub struct Fila {
    valores: Vec<Valor>,
    entidad: Option<Eid>,
}

impl Fila {
    /// Valor de la columna en la posicion `indice` del esquema.
    ///
    /// Fuera de rango devuelve [`Valor::Ausente`] en vez de entrar en panico:
    /// este codigo corre en el endpoint de un cliente, y un desajuste entre
    /// esquema y proveedor tiene que degradar la respuesta, no tumbar el
    /// agente. Que el desajuste no llegue a produccion lo garantiza la prueba
    /// de cobertura del catalogo, que es donde ese error se tiene que ver.
    pub fn valor(&self, indice: usize) -> &Valor {
        self.valores.get(indice).unwrap_or(&Valor::Ausente)
    }

    /// Todos los valores, en el orden del esquema.
    pub fn valores(&self) -> &[Valor] {
        &self.valores
    }

    /// La entidad que esta fila nombra, si nombra alguna.
    pub fn entidad(&self) -> Option<&Eid> {
        self.entidad.as_ref()
    }

    /// Cuantos valores no se pudieron obtener.
    pub fn ausentes(&self) -> usize {
        self.valores.iter().filter(|v| v.es_ausente()).count()
    }
}

/// El resultado de leer una tabla.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Filas {
    /// Las filas.
    pub filas: Vec<Fila>,
    /// Cuantas unidades se examinaron para producirlas.
    ///
    /// No coincide con `filas.len()` cuando hubo empuje de predicados: ahi esta
    /// justamente la ganancia, y medirla es como se demuestra que el empuje
    /// funciona.
    pub examinadas: u64,
    /// Huecos declarados dentro de una lectura que tuvo exito.
    pub avisos: Vec<Aviso>,
    /// Cierto si la lectura se corto por la cota de la tabla o por presupuesto.
    ///
    /// Una lista truncada que no lo dice es una mentira por omision: el
    /// analista cuenta las filas y cree que ese es el numero.
    pub truncada: bool,
}

impl Filas {
    /// Construye un resultado a partir de las filas, sin avisos ni truncamiento.
    pub fn de(filas: Vec<Fila>) -> Filas {
        let examinadas = filas.len() as u64;
        Filas {
            filas,
            examinadas,
            avisos: Vec::new(),
            truncada: false,
        }
    }

    /// Anade un hueco declarado.
    pub fn avisar(&mut self, sujeto: impl Into<String>, motivo: MotivoNoLeible) {
        self.avisos.push(Aviso {
            sujeto: sujeto.into(),
            motivo,
        });
    }
}

// ---------------------------------------------------------------------------
// Construir una fila sin desalinearla
// ---------------------------------------------------------------------------

/// Construye una fila poniendo los valores POR NOMBRE de columna.
///
/// POR QUE NO SE CONSTRUYE CON UN `Vec` Y YA
/// -----------------------------------------
/// Porque un `vec![Valor::Entero(pid), Valor::Texto(nombre), ...]` de veinte
/// posiciones se desalinea el dia que alguien inserta una columna en medio del
/// esquema, y el sintoma no es un error de compilacion: es que la columna
/// `uid` empieza a devolver el numero de hilos. Un fallo silencioso que
/// convierte cada respuesta del producto en algo peor que no responder.
///
/// Con el constructor, insertar una columna en el esquema no puede desalinear
/// nada, porque la posicion se resuelve por nombre en el momento de escribir.
#[derive(Debug)]
pub struct Constructor {
    esquema: &'static Esquema,
    valores: Vec<Valor>,
    entidad: Option<Eid>,
    desconocidas: u32,
}

impl Constructor {
    /// Fila nueva, con todas las columnas del esquema ausentes.
    pub fn nuevo(esquema: &'static Esquema) -> Constructor {
        Constructor {
            esquema,
            valores: vec![Valor::Ausente; esquema.columnas.len()],
            entidad: None,
            desconocidas: 0,
        }
    }

    /// Pone el valor de una columna.
    ///
    /// Una columna que no esta en el esquema se CUENTA y se descarta, en vez de
    /// entrar en panico. El recuento lo comprueba la prueba de cobertura del
    /// catalogo, que es donde ese error se tiene que ver: en CI, no en el
    /// endpoint de un cliente.
    pub fn pon(&mut self, columna: &str, valor: Valor) -> &mut Constructor {
        match self
            .esquema
            .columnas
            .iter()
            .position(|c| c.nombre == columna)
        {
            Some(i) => self.valores[i] = valor,
            None => self.desconocidas += 1,
        }
        self
    }

    /// Pone un entero, convirtiendo desde cualquier tipo que quepa.
    pub fn entero(&mut self, columna: &str, v: impl Into<i64>) -> &mut Constructor {
        self.pon(columna, Valor::Entero(v.into()))
    }

    /// Pone un texto.
    pub fn texto(&mut self, columna: &str, v: impl Into<String>) -> &mut Constructor {
        self.pon(columna, Valor::Texto(v.into()))
    }

    /// Pone un booleano.
    pub fn booleano(&mut self, columna: &str, v: bool) -> &mut Constructor {
        self.pon(columna, Valor::Booleano(v))
    }

    /// Pone un real.
    pub fn real(&mut self, columna: &str, v: f64) -> &mut Constructor {
        self.pon(columna, Valor::Real(v))
    }

    /// Pone un texto que puede no estar, sin inventar una cadena vacia.
    ///
    /// La diferencia importa: `path = ''` y «no pude leer la ruta» son cosas
    /// distintas, y una cadena vacia casa con `path = ''` en un filtro.
    pub fn texto_opcional(
        &mut self,
        columna: &str,
        v: Option<impl Into<String>>,
    ) -> &mut Constructor {
        match v {
            Some(t) => self.texto(columna, t),
            None => self.pon(columna, Valor::Ausente),
        }
    }

    /// Asocia la entidad que esta fila nombra.
    pub fn entidad(&mut self, eid: Eid) -> &mut Constructor {
        self.entidad = Some(eid);
        self
    }

    /// Indica si esta fila ya lleva entidad.
    ///
    /// Lo usan los proveedores que derivan la entidad por dos caminos —la
    /// ubicacion siempre, el contenido solo si se pudo hashear— para no
    /// sobreescribir la que ya pusieron.
    pub fn entidad_puesta(&self) -> bool {
        self.entidad.is_some()
    }

    /// Cierra la fila.
    pub fn fin(&mut self) -> Fila {
        Fila {
            valores: std::mem::replace(
                &mut self.valores,
                vec![Valor::Ausente; self.esquema.columnas.len()],
            ),
            entidad: self.entidad.take(),
        }
    }

    /// Cuantas columnas desconocidas se intentaron escribir.
    pub fn desconocidas(&self) -> u32 {
        self.desconocidas
    }
}

// ---------------------------------------------------------------------------
// Empuje de predicados
// ---------------------------------------------------------------------------

/// Lo que la consulta ya sabe, para que la tabla no enumere de mas.
///
/// # La propiedad que hace que esto sea seguro
///
/// El filtro empujado es una AYUDA, no una obligacion. Una tabla puede
/// ignorarlo entero y seguir siendo correcta; lo que NO puede es devolver menos
/// filas de las que cumplen el filtro. Formalmente:
///
/// > lo que devuelve `leer(ctx, filtro)` ⊇ lo que cumple `filtro` dentro de
/// > `leer(ctx, Filtro::ninguno())`
///
/// El ejecutor vuelve a evaluar el filtro completo sobre lo que reciba, asi que
/// devolver de mas cuesta tiempo pero no cambia el resultado; devolver de menos
/// PIERDE DETECCION en silencio, que es la unica manera de que este mecanismo
/// haga daño. De ahi que solo se empujen predicados en conjuncion pura: bajo un
/// `OR` o un `NOT`, «pid = 42» no autoriza a mirar solo el 42.
///
/// La prueba `el_empuje_no_cambia_el_conjunto_de_filas` fija la propiedad
/// comparando, tabla por tabla, la lectura con filtro contra la lectura sin el.
#[derive(Debug, Clone, Default)]
pub struct Filtro {
    igualdades: Vec<(&'static str, Literal)>,
    conjuntos: Vec<(&'static str, Vec<Literal>)>,
    prefijos: Vec<(&'static str, String)>,
    necesarias: Option<Vec<&'static str>>,
}

impl Filtro {
    /// Un filtro que no dice nada: la tabla enumera lo que sea que enumere.
    pub fn ninguno() -> Filtro {
        Filtro::default()
    }

    /// Declara que columnas necesita de verdad la consulta.
    ///
    /// Sale de `Plan::columnas_necesarias`, que el planificador ya calcula. Sin
    /// esto, un proveedor no tiene forma de saber que `sha256` no se ha pedido,
    /// y hashear cada fichero del recorrido «por si acaso» convierte una
    /// consulta de metadatos en horas de E/S.
    ///
    /// El valor por defecto —no declarar nada— significa TODAS, que es el fallo
    /// seguro: se trabaja de mas, nunca se devuelve de menos.
    pub fn con_columnas(mut self, columnas: Vec<&'static str>) -> Filtro {
        self.necesarias = Some(columnas);
        self
    }

    /// Indica si la consulta necesita esta columna.
    pub fn necesita(&self, columna: &str) -> bool {
        match &self.necesarias {
            Some(v) => v.contains(&columna),
            None => true,
        }
    }

    /// Anade `columna = literal`.
    pub fn con_igualdad(mut self, columna: &'static str, valor: Literal) -> Filtro {
        self.igualdades.push((columna, valor));
        self
    }

    /// Anade `columna IN (...)`.
    pub fn con_conjunto(mut self, columna: &'static str, valores: Vec<Literal>) -> Filtro {
        self.conjuntos.push((columna, valores));
        self
    }

    /// Anade el prefijo constante de un `columna LIKE 'pre%'`.
    pub fn con_prefijo(mut self, columna: &'static str, prefijo: impl Into<String>) -> Filtro {
        self.prefijos.push((columna, prefijo.into()));
        self
    }

    /// Indica si el filtro no aporta nada.
    pub fn vacio(&self) -> bool {
        self.igualdades.is_empty() && self.conjuntos.is_empty() && self.prefijos.is_empty()
    }

    /// Indica si la consulta acota por alguna de estas columnas.
    ///
    /// Es lo que mira una tabla peligrosa para decidir si se deja leer.
    pub fn acota_por(&self, columnas: &[&str]) -> bool {
        columnas.iter().any(|c| {
            self.igualdades.iter().any(|(n, _)| n == c)
                || self.conjuntos.iter().any(|(n, _)| n == c)
                || self.prefijos.iter().any(|(n, _)| n == c)
        })
    }

    /// El entero exacto por el que se filtra esta columna, si lo hay.
    pub fn entero(&self, columna: &str) -> Option<i64> {
        self.igualdades.iter().find_map(|(n, l)| match l {
            Literal::Entero(v) if *n == columna => Some(*v),
            _ => None,
        })
    }

    /// El texto exacto por el que se filtra esta columna, si lo hay.
    pub fn texto(&self, columna: &str) -> Option<&str> {
        self.igualdades.iter().find_map(|(n, l)| match l {
            Literal::Texto(v) if *n == columna => Some(v.as_str()),
            _ => None,
        })
    }

    /// El conjunto de enteros de un `IN`, si lo hay.
    pub fn enteros(&self, columna: &str) -> Option<Vec<i64>> {
        self.conjuntos.iter().find_map(|(n, vs)| {
            if *n != columna {
                return None;
            }
            let mut salida = Vec::with_capacity(vs.len());
            for v in vs {
                match v {
                    Literal::Entero(x) => salida.push(*x),
                    // Un `IN` mezclado no se empuja: el analizador ya garantiza
                    // que los tipos casan, asi que esto solo puede pasar si
                    // alguien construye el filtro a mano. Renunciar al empuje
                    // es la salida segura; filtrar por la mitad de la lista no.
                    _ => return None,
                }
            }
            Some(salida)
        })
    }

    /// El prefijo constante de un `LIKE`, si lo hay.
    pub fn prefijo(&self, columna: &str) -> Option<&str> {
        self.prefijos
            .iter()
            .find(|(n, _)| *n == columna)
            .map(|(_, p)| p.as_str())
    }
}

// ---------------------------------------------------------------------------
// El rasgo
// ---------------------------------------------------------------------------

/// Un proveedor de estado del endpoint.
///
/// Ver la cabecera de [`crate`] sobre por que este rasgo existe para organizar
/// cincuenta y un proveedores y NO para poder sustituirlos por dobles.
pub trait Tabla: Send + Sync {
    /// El esquema, que vive en el lenguaje y aqui solo se apunta.
    fn esquema(&self) -> &'static Esquema;

    /// Lo que cuesta leer esta tabla entera.
    ///
    /// El coste del ESQUEMA es por columna —lo usa el planificador para ordenar
    /// predicados—; este es por TABLA, y es el que decide si una consulta se
    /// puede difundir a cien mil endpoints. Son dos preguntas distintas: «que
    /// predicado evaluo primero» y «puedo permitirme esta tabla».
    fn coste(&self) -> Coste;

    /// La clase de entidad que nombran sus filas, si nombran alguna.
    ///
    /// `None` para tablas que describen el sistema y no una cosa con identidad
    /// propia —`cpu_info` no es una entidad, es una propiedad de la maquina—.
    fn clase(&self) -> Option<Clase> {
        None
    }

    /// Columnas por las que una tabla peligrosa admite ser acotada.
    ///
    /// Vacio en las tablas que no son peligrosas. Se declara aparte del coste
    /// porque el analista necesita saber NO SOLO que la consulta se rechaza,
    /// sino como escribirla para que no lo sea.
    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &[]
    }

    /// Lee la tabla.
    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible>;

    /// El nombre, que sale del esquema y no se repite aqui.
    fn nombre(&self) -> &'static str {
        self.esquema().nombre
    }

    /// Comprueba la cota de coste antes de tocar el sistema.
    ///
    /// Lo llama cada proveedor peligroso como primera linea de `leer`. Podria
    /// hacerlo el catalogo por el, y se ha decidido que no: un proveedor que
    /// declara `Coste::Peligroso` y se olvida de llamar a esto tiene un fallo
    /// que la prueba `toda_tabla_peligrosa_exige_filtro` detecta, y ese fallo es
    /// visible. Si lo impusiera el catalogo, el proveedor podria saltarselo el
    /// dia que alguien lo llame por su tipo concreto.
    fn exige_cota(&self, filtro: &Filtro) -> Result<(), MotivoNoLeible> {
        if self.coste() == Coste::Peligroso && !filtro.acota_por(self.columnas_que_acotan()) {
            return Err(MotivoNoLeible::RequiereFiltro {
                columnas: self.columnas_que_acotan(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_parser::esquema;

    fn esquema_procesos() -> &'static Esquema {
        esquema::tabla("processes").expect("la tabla processes existe desde la FASE 34")
    }

    #[test]
    fn el_constructor_coloca_por_nombre_y_no_por_orden() {
        let e = esquema_procesos();
        let mut c = Constructor::nuevo(e);
        // A proposito en orden distinto al del esquema: es justo lo que el
        // constructor tiene que hacer irrelevante.
        c.entero("uid", 1000i64);
        c.entero("pid", 42i64);
        let fila = c.fin();

        let i_pid = e.columnas.iter().position(|c| c.nombre == "pid").unwrap();
        let i_uid = e.columnas.iter().position(|c| c.nombre == "uid").unwrap();
        assert_eq!(fila.valor(i_pid), &Valor::Entero(42));
        assert_eq!(fila.valor(i_uid), &Valor::Entero(1000));
    }

    #[test]
    fn lo_que_no_se_escribe_queda_ausente_y_no_a_cero() {
        // Un cero inventado es un dato falso: `threads = 0` es imposible y
        // aun asi casaria con `threads < 2`.
        let e = esquema_procesos();
        let mut c = Constructor::nuevo(e);
        c.entero("pid", 1i64);
        let fila = c.fin();
        let i = e
            .columnas
            .iter()
            .position(|c| c.nombre == "threads")
            .unwrap();
        assert_eq!(fila.valor(i), &Valor::Ausente);
        assert!(fila.ausentes() >= 1);
    }

    #[test]
    fn una_columna_que_no_existe_se_cuenta_y_no_entra_en_panico() {
        let mut c = Constructor::nuevo(esquema_procesos());
        c.entero("columna_que_no_existe", 1i64);
        assert_eq!(c.desconocidas(), 1);
        // Y la fila sigue siendo utilizable: el agente no se cae por esto.
        let _ = c.fin();
    }

    #[test]
    fn el_constructor_se_puede_reutilizar_para_varias_filas() {
        // Lo hacen todos los proveedores: una tabla con dos mil procesos no
        // construye dos mil constructores.
        let e = esquema_procesos();
        let mut c = Constructor::nuevo(e);
        let i = e.columnas.iter().position(|c| c.nombre == "pid").unwrap();

        c.entero("pid", 1i64);
        let a = c.fin();
        c.entero("pid", 2i64);
        let b = c.fin();

        assert_eq!(a.valor(i), &Valor::Entero(1));
        assert_eq!(b.valor(i), &Valor::Entero(2));
        // Y la segunda fila NO arrastra los valores de la primera.
        let j = e.columnas.iter().position(|c| c.nombre == "uid").unwrap();
        assert_eq!(b.valor(j), &Valor::Ausente);
    }

    #[test]
    fn el_valor_fuera_de_rango_es_ausente_y_no_panico() {
        let fila = Constructor::nuevo(esquema_procesos()).fin();
        assert_eq!(fila.valor(9_999), &Valor::Ausente);
    }

    #[test]
    fn el_filtro_devuelve_lo_que_se_le_puso() {
        let f = Filtro::ninguno()
            .con_igualdad("pid", Literal::Entero(42))
            .con_igualdad("name", Literal::Texto("curl".into()))
            .con_conjunto("uid", vec![Literal::Entero(0), Literal::Entero(1000)])
            .con_prefijo("path", "/tmp/");

        assert_eq!(f.entero("pid"), Some(42));
        assert_eq!(f.texto("name"), Some("curl"));
        assert_eq!(f.enteros("uid"), Some(vec![0, 1000]));
        assert_eq!(f.prefijo("path"), Some("/tmp/"));
        assert!(!f.vacio());
    }

    #[test]
    fn el_filtro_no_confunde_columnas_ni_tipos() {
        let f = Filtro::ninguno().con_igualdad("pid", Literal::Entero(42));
        // Otra columna: nada.
        assert_eq!(f.entero("ppid"), None);
        // La columna correcta con el tipo que no es: nada, jamas una conversion
        // silenciosa que haria que `name = '42'` filtrara por pid.
        assert_eq!(f.texto("pid"), None);
    }

    #[test]
    fn un_conjunto_mezclado_no_se_empuja() {
        // Renunciar al empuje es correcto; empujar la mitad de la lista seria
        // perder filas, que es la unica forma de que esto haga daño.
        let f = Filtro::ninguno().con_conjunto(
            "uid",
            vec![Literal::Entero(0), Literal::Texto("root".into())],
        );
        assert_eq!(f.enteros("uid"), None);
    }

    #[test]
    fn acota_por_reconoce_las_tres_formas_de_acotar() {
        assert!(Filtro::ninguno()
            .con_igualdad("pid", Literal::Entero(1))
            .acota_por(&["pid"]));
        assert!(Filtro::ninguno()
            .con_conjunto("pid", vec![Literal::Entero(1)])
            .acota_por(&["pid"]));
        assert!(Filtro::ninguno()
            .con_prefijo("path", "/etc/")
            .acota_por(&["path"]));
        assert!(!Filtro::ninguno().acota_por(&["pid"]));
        // Y no se deja acotar por una columna que no es la suya.
        assert!(!Filtro::ninguno()
            .con_igualdad("uid", Literal::Entero(0))
            .acota_por(&["pid"]));
    }

    #[test]
    fn cada_motivo_tiene_una_frase_que_dice_algo() {
        let motivos = [
            MotivoNoLeible::SinPrivilegios {
                operacion: "leer /proc/1/environ",
                necesita: "CAP_SYS_PTRACE o ser el dueno del proceso",
            },
            MotivoNoLeible::NoExisteEnEsteNucleo {
                interfaz: "/sys/fs/cgroup/cgroup.controllers",
            },
            MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "EndpointSecurity",
            },
            MotivoNoLeible::FuenteAusente {
                ruta: "/etc/sudoers".into(),
            },
            MotivoNoLeible::CambioDuranteLaLectura {
                ruta: "/proc/42".into(),
            },
            MotivoNoLeible::ErrorDelSistema {
                operacion: "abrir /proc/net/route",
                detalle: "EACCES".into(),
            },
            MotivoNoLeible::RequiereFiltro {
                columnas: &["path", "mount"],
            },
            MotivoNoLeible::PresupuestoAgotado,
        ];
        for m in &motivos {
            let f = m.frase();
            assert!(f.len() > 12, "frase demasiado corta para {m:?}: {f}");
            assert!(!f.contains("None"), "frase con hueco sin rellenar: {f}");
        }
    }

    #[test]
    fn la_frase_de_requiere_filtro_dice_como_arreglarlo() {
        // Un rechazo que no dice como escribir la consulta bien es un muro.
        let m = MotivoNoLeible::RequiereFiltro {
            columnas: &["path", "mount"],
        };
        let f = m.frase();
        assert!(f.contains("path"), "{f}");
        assert!(f.contains("mount"), "{f}");
    }

    #[test]
    fn se_distingue_lo_que_es_de_la_maquina_de_lo_que_es_del_agente() {
        // Que una maquina sin TPM no tenga PCRs no es un fallo de la caceria, y
        // el plano de control necesita poder no contarlo como tal.
        assert!(MotivoNoLeible::NoExisteEnEsteNucleo { interfaz: "x" }.es_de_la_maquina());
        assert!(MotivoNoLeible::FuenteAusente { ruta: "x".into() }.es_de_la_maquina());
        assert!(!MotivoNoLeible::SinPrivilegios {
            operacion: "x",
            necesita: "y"
        }
        .es_de_la_maquina());
    }

    #[test]
    fn lo_transitorio_se_distingue_de_lo_permanente() {
        assert!(MotivoNoLeible::CambioDuranteLaLectura { ruta: "x".into() }.es_transitorio());
        assert!(MotivoNoLeible::PresupuestoAgotado.es_transitorio());
        assert!(!MotivoNoLeible::NoExisteEnEsteNucleo { interfaz: "x" }.es_transitorio());
    }

    #[test]
    fn filas_de_cuenta_las_examinadas() {
        let e = esquema_procesos();
        let mut c = Constructor::nuevo(e);
        c.entero("pid", 1i64);
        let f = Filas::de(vec![c.fin()]);
        assert_eq!(f.examinadas, 1);
        assert!(!f.truncada);
        assert!(f.avisos.is_empty());
    }

    #[test]
    fn un_aviso_conserva_sujeto_y_motivo() {
        let mut f = Filas::default();
        f.avisar(
            "/proc/1/environ",
            MotivoNoLeible::SinPrivilegios {
                operacion: "leer el entorno",
                necesita: "ser el dueno del proceso",
            },
        );
        assert_eq!(f.avisos.len(), 1);
        assert_eq!(f.avisos[0].sujeto, "/proc/1/environ");
        assert!(f.avisos[0].motivo.frase().contains("dueno"));
    }
}
