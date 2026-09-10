//! Arbol sintactico de AegisQL.
//!
//! Es deliberadamente pequeno. Cada nodo que se anade a un lenguaje que se
//! ejecuta en el endpoint de un cliente es codigo nuevo corriendo con
//! privilegios en decenas de miles de maquinas, asi que la pregunta no es «que
//! mas podria expresar» sino «que necesita de verdad un analista para cazar».
//!
//! Lo que NO existe, y no por falta de tiempo:
//!   - `JOIN`: coste cuadratico pagado por el endpoint. Ver `esquema`.
//!   - Subconsultas: mismo problema, y ademas hacen indecidible el coste.
//!   - Funciones definidas por el usuario o llamadas al sistema: seria dar
//!     ejecucion de codigo remota a quien controle la consola.
//!   - Cualquier verbo de escritura. La gramatica no puede expresar una
//!     modificacion, asi que no hay nada que filtrar ni nada que se escape.

use crate::esquema::Tipo;

/// Una consulta completa, ya validada contra el esquema.
#[derive(Debug, Clone, PartialEq)]
pub struct Consulta {
    /// Que se devuelve.
    pub proyeccion: Proyeccion,
    /// Tabla sobre la que se consulta.
    pub tabla: &'static str,
    /// Filtro, si lo hay.
    pub filtro: Option<Expr>,
    /// Ordenacion, si la hay.
    pub orden: Option<Orden>,
    /// Numero maximo de filas.
    ///
    /// Nunca es `None` despues del analisis: si el operador no escribe `LIMIT`,
    /// se aplica el limite por defecto. Una consulta sin techo devolviendo
    /// procesos de diez mil maquinas es una denegacion de servicio contra el
    /// propio plano de control.
    pub limite: u32,
}

/// Que devuelve la consulta.
#[derive(Debug, Clone, PartialEq)]
pub enum Proyeccion {
    /// Columnas concretas, en el orden en que se escribieron.
    Columnas(Vec<Columna>),
    /// Todas las columnas de coste trivial o barato.
    ///
    /// `SELECT *` NO incluye las columnas caras: en una flota grande, un
    /// asterisco que hashee cada ejecutable y calcule la entropia de cada
    /// region de memoria de cada proceso es un incidente de disponibilidad
    /// provocado por el propio EDR. Quien quiera esas columnas las nombra.
    Todo,
    /// `COUNT(*)`: solo el numero de filas que pasan el filtro.
    ///
    /// Es la proyeccion mas util a escala de flota, porque la respuesta de cada
    /// endpoint es un numero y agregarla es sumar.
    Cuenta,
}

/// Una columna proyectada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Columna {
    /// Nombre tal y como aparece en el esquema.
    pub nombre: &'static str,
    /// Tipo del valor.
    pub tipo: Tipo,
}

/// Clausula de ordenacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orden {
    /// Columna por la que se ordena.
    pub columna: &'static str,
    /// Si es descendente.
    pub descendente: bool,
}

/// Un valor literal.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    /// Entero con signo.
    Entero(i64),
    /// Real de doble precision.
    Real(f64),
    /// Texto.
    Texto(String),
    /// Booleano.
    Booleano(bool),
}

impl Literal {
    /// Tipo del literal.
    pub fn tipo(&self) -> Tipo {
        match self {
            Literal::Entero(_) => Tipo::Entero,
            Literal::Real(_) => Tipo::Real,
            Literal::Texto(_) => Tipo::Texto,
            Literal::Booleano(_) => Tipo::Booleano,
        }
    }
}

/// Operador de comparacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparador {
    /// Igualdad.
    Igual,
    /// Desigualdad.
    Distinto,
    /// Menor estricto.
    Menor,
    /// Menor o igual.
    MenorIgual,
    /// Mayor estricto.
    Mayor,
    /// Mayor o igual.
    MayorIgual,
}

/// Una expresion booleana del filtro.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Comparacion entre una columna y un literal.
    ///
    /// El literal va SIEMPRE a la derecha, aunque el operador lo escriba al
    /// reves: el parser normaliza `4444 = network.port` a la forma canonica.
    /// Asi el ejecutor tiene un solo caso que tratar en vez de cuatro.
    Comparacion {
        /// Columna comparada.
        columna: &'static str,
        /// Comparador.
        op: Comparador,
        /// Valor contra el que se compara.
        valor: Literal,
    },
    /// Comparacion de texto con comodines `%` (varios) y `_` (uno).
    Like {
        /// Columna de texto.
        columna: &'static str,
        /// Patron.
        patron: String,
        /// Si va negada (`NOT LIKE`).
        negado: bool,
    },
    /// Pertenencia a una lista de literales del mismo tipo.
    En {
        /// Columna comparada.
        columna: &'static str,
        /// Valores admitidos.
        valores: Vec<Literal>,
        /// Si va negada (`NOT IN`).
        negado: bool,
    },
    /// Columna booleana usada como predicado.
    Bandera {
        /// Columna de tipo booleano.
        columna: &'static str,
    },
    /// Conjuncion.
    Y(Box<Expr>, Box<Expr>),
    /// Disyuncion.
    O(Box<Expr>, Box<Expr>),
    /// Negacion.
    No(Box<Expr>),
}

impl Expr {
    /// Recorre el arbol aplicando una funcion a cada nodo hoja.
    ///
    /// Lo usa el planificador para saber que columnas toca la consulta sin
    /// duplicar el recorrido en cada sitio que lo necesite.
    pub fn para_cada_columna(&self, f: &mut impl FnMut(&'static str)) {
        match self {
            Expr::Comparacion { columna, .. }
            | Expr::Like { columna, .. }
            | Expr::En { columna, .. }
            | Expr::Bandera { columna } => f(columna),
            Expr::Y(a, b) | Expr::O(a, b) => {
                a.para_cada_columna(f);
                b.para_cada_columna(f);
            }
            Expr::No(a) => a.para_cada_columna(f),
        }
    }
}
