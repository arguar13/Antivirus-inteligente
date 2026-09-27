//! La representacion intermedia: tres direcciones, forma SSA, memoria explicita.
//!
//! # Por que una IR propia y tipada, y no texto
//!
//! Es la decision con mas consecuencias del crate. Casi todos los decompiladores
//! del mundo pasan por una IR que serializan a texto y vuelven a parsear entre
//! fases; ese viaje es donde se pierde la trazabilidad —que instruccion origino
//! que— y donde entra el indeterminismo. Aqui la IR es un TIPO: nadie la
//! serializa para volver a leerla, cada valor sabe de que instrucciones sale, y
//! el orden es el del recorrido por direccion, no el del analisis.
//!
//! Y es UNA sola IR en el producto: la misma que la FASE 102 usa para la ejecucion
//! simbolica. Dos IR seria la averia que la invariante 10 del MEGAPROMPT 7 existe
//! para impedir.
//!
//! # Forma SSA
//!
//! Cada valor se define exactamente una vez ([`ValId`]), asi que preguntar «de
//! donde sale este valor» tiene una sola respuesta. Donde el flujo une dos
//! definiciones —el final de un `if`, la cabeza de un bucle— hay un [`Fi`] (phi),
//! que dice «el valor es este si venimos de aqui, y aquel si venimos de alla». Es
//! lo que permite la propagacion de constantes y la reconstruccion de expresiones
//! sin perder de vista los caminos.
//!
//! # La memoria es explicita
//!
//! Una carga es un valor ([`Operacion::Cargar`]); un almacenamiento es una
//! sentencia con efecto ([`Sentencia::Almacenar`]), no un valor. Separarlos es lo
//! que permite razonar sobre el flujo de datos por registros sin confundirlo con
//! el de memoria, y lo que hace que un `mov [rbp-8], eax` no pretenda «definir» un
//! valor SSA que luego nadie usa.

use std::collections::BTreeMap;

use crate::tipos::Tipo;

/// El identificador de un valor SSA. Se asignan en un recorrido por direccion,
/// asi que dos ejecuciones sobre el mismo binario dan los mismos identificadores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValId(pub u32);

/// El identificador de un bloque de la IR. Es la direccion de inicio del bloque
/// basico del CFG, para que el linaje con el desensamblado sea directo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BloqueId(pub u64);

/// El ancho de un valor, en bits. Es parte del tipo mas basico que hay: sin el, no
/// se puede saber si un `mov eax, ...` define 32 bits (con extension por ceros) o
/// 64, y esa diferencia cambia el comportamiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ancho {
    /// 8 bits.
    B8,
    /// 16 bits.
    B16,
    /// 32 bits.
    B32,
    /// 64 bits.
    B64,
    /// 128 bits (registros vectoriales que participan en cifrado).
    B128,
}

impl Ancho {
    /// El ancho en bits.
    #[must_use]
    pub fn bits(self) -> u32 {
        match self {
            Ancho::B8 => 8,
            Ancho::B16 => 16,
            Ancho::B32 => 32,
            Ancho::B64 => 64,
            Ancho::B128 => 128,
        }
    }

    /// El ancho a partir de un numero de bytes, si es uno de los representables.
    #[must_use]
    pub fn de_bytes(bytes: u32) -> Option<Ancho> {
        match bytes {
            1 => Some(Ancho::B8),
            2 => Some(Ancho::B16),
            4 => Some(Ancho::B32),
            8 => Some(Ancho::B64),
            16 => Some(Ancho::B128),
            _ => None,
        }
    }
}

/// Un operando: o un valor SSA ya definido, o una constante. Nunca un registro
/// crudo —los registros son un detalle de la maquina, y en SSA ya se han
/// resuelto a valores—.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operando {
    /// Un valor SSA definido antes.
    Val(ValId),
    /// Una constante literal de un ancho dado.
    Const(u64, Ancho),
    /// Un valor que el analisis no pudo determinar. **No es cero**: es «no se»,
    /// y quien lo consuma tiene que tratarlo como tal, no como un valor mas.
    Indefinido,
}

/// La operacion binaria de una [`Operacion::Bin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpBin {
    /// Suma.
    Sumar,
    /// Resta.
    Restar,
    /// Multiplicacion.
    Multiplicar,
    /// Division sin signo.
    DividirU,
    /// Division con signo.
    DividirS,
    /// Resto sin signo.
    RestoU,
    /// Resto con signo.
    RestoS,
    /// AND de bits.
    Y,
    /// OR de bits.
    O,
    /// XOR de bits.
    Xor,
    /// Desplazamiento a la izquierda.
    DesplazarIzq,
    /// Desplazamiento logico a la derecha (rellena con ceros).
    DesplazarDerL,
    /// Desplazamiento aritmetico a la derecha (conserva el signo).
    DesplazarDerA,
    /// Rotacion a la izquierda.
    RotarIzq,
    /// Rotacion a la derecha.
    RotarDer,
}

/// La operacion unaria de una [`Operacion::Un`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpUn {
    /// Negacion aritmetica (complemento a dos).
    Negar,
    /// Complemento de bits.
    No,
    /// Extension con signo a un ancho mayor.
    ExtenderS(Ancho),
    /// Extension con ceros a un ancho mayor.
    ExtenderU(Ancho),
    /// Truncamiento a un ancho menor.
    Truncar(Ancho),
}

/// El operador de una comparacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCmp {
    /// Igual.
    Igual,
    /// Distinto.
    Distinto,
    /// Menor sin signo.
    MenorU,
    /// Menor o igual sin signo.
    MenorIgualU,
    /// Menor con signo.
    MenorS,
    /// Menor o igual con signo.
    MenorIgualS,
}

/// La parte derecha de una definicion: como se calcula un valor SSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operacion {
    /// Una constante o una copia de otro operando.
    Copiar(Operando),
    /// Operacion binaria.
    Bin {
        /// Que operacion.
        op: OpBin,
        /// Operando izquierdo.
        a: Operando,
        /// Operando derecho.
        b: Operando,
    },
    /// Operacion unaria.
    Un {
        /// Que operacion.
        op: OpUn,
        /// El operando.
        a: Operando,
    },
    /// Comparacion: define un valor de un bit (verdadero/falso).
    Comparar {
        /// Que comparacion.
        op: OpCmp,
        /// Operando izquierdo.
        a: Operando,
        /// Operando derecho.
        b: Operando,
    },
    /// Carga de memoria: lee `ancho` bits de la direccion `dir`.
    Cargar {
        /// La direccion, como operando (registro base + desplazamiento ya
        /// combinados en un valor SSA, o una constante).
        dir: Operando,
        /// Cuanto se lee.
        ancho: Ancho,
    },
    /// Un fi (phi) de SSA: el valor depende del bloque del que se venga.
    Fi(Fi),
    /// El resultado de una llamada (el valor de retorno). La llamada en si, con
    /// sus efectos, es una [`Sentencia::Llamada`]; esto es solo su resultado.
    ResultadoLlamada,
    /// Un argumento de la funcion, por posicion en la convencion de llamada.
    Argumento(u32),
    /// Un valor que el analisis no pudo reconstruir. Se emite como `desconocido`,
    /// nunca se inventa.
    Indefinido,
}

/// Un fi (phi) de SSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fi {
    /// De cada bloque predecesor, que operando aporta. Ordenado por bloque para
    /// que sea determinista.
    pub fuentes: BTreeMap<BloqueId, Operando>,
}

/// Una sentencia de un bloque de la IR: define un valor o produce un efecto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sentencia {
    /// Define un valor SSA.
    Definir {
        /// El valor que se define.
        destino: ValId,
        /// Su ancho.
        ancho: Ancho,
        /// Su tipo reconstruido, o [`Tipo::Desconocido`].
        tipo: Tipo,
        /// Como se calcula.
        op: Operacion,
        /// Las direcciones de las instrucciones que originan esta sentencia. Es
        /// la EVIDENCIA: el pseudo-C que salga de aqui cita estas direcciones.
        origen: Vec<u64>,
    },
    /// Escribe en memoria. Es un efecto, no un valor.
    Almacenar {
        /// La direccion destino.
        dir: Operando,
        /// El valor a escribir.
        valor: Operando,
        /// Cuanto se escribe.
        ancho: Ancho,
        /// Las instrucciones que la originan.
        origen: Vec<u64>,
    },
    /// Una llamada, con sus efectos. Su valor de retorno, si se usa, se define
    /// aparte con [`Operacion::ResultadoLlamada`].
    Llamada {
        /// A donde llama, si se sabe (una constante para llamadas directas, un
        /// valor para las indirectas resueltas, o [`Operando::Indefinido`]).
        destino: Operando,
        /// El nombre de la API, si la importacion lo resolvio.
        nombre: Option<String>,
        /// Los argumentos, segun la convencion de llamada detectada.
        argumentos: Vec<Operando>,
        /// El valor donde queda el retorno, si se usa despues.
        retorno: Option<ValId>,
        /// Las instrucciones que la originan.
        origen: Vec<u64>,
    },
}

impl Sentencia {
    /// Las direcciones de origen de la sentencia, para la evidencia.
    #[must_use]
    pub fn origen(&self) -> &[u64] {
        match self {
            Sentencia::Definir { origen, .. }
            | Sentencia::Almacenar { origen, .. }
            | Sentencia::Llamada { origen, .. } => origen,
        }
    }
}

/// Como termina un bloque de la IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminador {
    /// Salta incondicionalmente a otro bloque.
    Ir(BloqueId),
    /// Salta a `si` si la condicion es verdadera, a `no` si no.
    Rama {
        /// La condicion (un valor de un bit).
        cond: Operando,
        /// A donde si es verdadera.
        si: BloqueId,
        /// A donde si es falsa.
        no: BloqueId,
    },
    /// Un `switch` sobre una tabla resuelta.
    Conmutar {
        /// El valor sobre el que se conmuta.
        valor: Operando,
        /// (caso, bloque destino), ordenado por caso.
        casos: Vec<(u64, BloqueId)>,
        /// El bloque por defecto.
        defecto: BloqueId,
    },
    /// Retorna de la funcion.
    Retornar(Option<Operando>),
    /// Una transferencia indirecta cuyo destino el analisis no resolvio. Es la
    /// medida honesta de lo que no se alcanza; se cuenta en la calidad.
    Indirecto,
    /// Un punto que el flujo no puede alcanzar (tras una parada, o tras una
    /// llamada que no retorna).
    Inalcanzable,
}

/// Un bloque de la IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloqueIr {
    /// Su identificador (la direccion de inicio del bloque basico del CFG).
    pub id: BloqueId,
    /// Sus sentencias, en orden.
    pub sentencias: Vec<Sentencia>,
    /// Como termina.
    pub terminador: Terminador,
}

/// Una funcion elevada a la IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncionIr {
    /// La direccion de entrada de la funcion.
    pub entrada: u64,
    /// Sus bloques, ordenados por identificador (direccion) para determinismo.
    pub bloques: BTreeMap<BloqueId, BloqueIr>,
    /// Cuantos valores SSA se definieron, para dimensionar tablas.
    pub valores: u32,
}

impl FuncionIr {
    /// Una funcion vacia con su entrada.
    #[must_use]
    pub fn nueva(entrada: u64) -> FuncionIr {
        FuncionIr {
            entrada,
            bloques: BTreeMap::new(),
            valores: 0,
        }
    }

    /// El bloque de entrada, si esta.
    #[must_use]
    pub fn bloque_entrada(&self) -> Option<&BloqueIr> {
        self.bloques.get(&BloqueId(self.entrada))
    }

    /// Recorre los bloques en orden estable (por direccion).
    pub fn bloques_ordenados(&self) -> impl Iterator<Item = &BloqueIr> {
        self.bloques.values()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_ancho_ida_y_vuelta_por_bytes() {
        for (b, a) in [
            (1, Ancho::B8),
            (2, Ancho::B16),
            (4, Ancho::B32),
            (8, Ancho::B64),
            (16, Ancho::B128),
        ] {
            assert_eq!(Ancho::de_bytes(b), Some(a));
            assert_eq!(a.bits(), b * 8);
        }
        assert_eq!(Ancho::de_bytes(3), None, "un ancho raro no se inventa");
    }

    #[test]
    fn un_indefinido_no_es_una_constante_cero() {
        // La distincion que impide leer «no se» como «vale 0».
        assert_ne!(Operando::Indefinido, Operando::Const(0, Ancho::B64));
    }

    #[test]
    fn el_origen_de_toda_sentencia_es_accesible_para_la_evidencia() {
        let s = Sentencia::Definir {
            destino: ValId(0),
            ancho: Ancho::B32,
            tipo: Tipo::Desconocido,
            op: Operacion::Copiar(Operando::Const(1, Ancho::B32)),
            origen: vec![0x1000, 0x1003],
        };
        assert_eq!(s.origen(), &[0x1000, 0x1003]);
    }

    #[test]
    fn los_bloques_se_recorren_en_orden_de_direccion() {
        // El determinismo empieza aqui: el recorrido es por direccion, no por el
        // orden en que se elevaron los bloques.
        let mut f = FuncionIr::nueva(0x1000);
        for dir in [0x1020u64, 0x1000, 0x1010] {
            f.bloques.insert(
                BloqueId(dir),
                BloqueIr {
                    id: BloqueId(dir),
                    sentencias: vec![],
                    terminador: Terminador::Inalcanzable,
                },
            );
        }
        let orden: Vec<u64> = f.bloques_ordenados().map(|b| b.id.0).collect();
        assert_eq!(orden, vec![0x1000, 0x1010, 0x1020]);
    }
}
