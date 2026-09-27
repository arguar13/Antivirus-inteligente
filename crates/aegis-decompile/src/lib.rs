//! # aegis-decompile — de bytes a pseudo-C, y determinista (FASE 100)
//!
//! ## Inventario obligatorio: que expone hoy el grafo, y que necesita el decompilador
//!
//! El disparador de la fase manda escribir esto ANTES de una linea de codigo, y
//! por una razon concreta: el riesgo de esta fase es rodear el grafo de la FASE 85
//! en vez de abrirlo, y acabar con dos analisis del mismo binario que se
//! contradicen. Este es el mapa, leido de `aegis-disasm` entero.
//!
//! ### Lo que el grafo YA expone, y es consultable (no hay que rodearlo)
//!
//! | Pieza | Tipo | Lo que da al decompilador |
//! |---|---|---|
//! | Punto de entrada | [`aegis_disasm::analizar`] -> [`aegis_disasm::Analisis`] | encadena todo: CFG, llamadas, importaciones |
//! | Grafo de flujo | [`aegis_disasm::Cfg`] | `bloques()`, `bloque(dir)`, `bloque_que_contiene(dir)`, `entradas`, `raices`, `indirectos`, `tablas`, `cobertura` |
//! | Bloque basico | [`aegis_disasm::Bloque`] | `inicio`, `fin`, `instrucciones`, **`sucesores`** y **`predecesores`** —lo que hace falta para dominancia y para colocar los fi de SSA— |
//! | Grafo de llamadas | `aegis_disasm::llamadas::GrafoDeLlamadas` | `funciones()`, `funcion(entrada)`: los limites de cada funcion |
//! | Importaciones | `aegis_disasm::importaciones::Importaciones` | prototipos y nombres de las APIs, para tipar argumentos |
//! | Cobertura y plazo | [`aegis_disasm::Cobertura`], [`aegis_disasm::Plazo`] | que se corto y con que cobertura, que este crate hereda |
//!
//! El grafo esta bien: lleva las instrucciones DENTRO de cada bloque (no solo sus
//! limites), asi que no hay que volver a decodificar sobre bytes que quiza ya no
//! esten. Los predecesores estan, que es justo lo que la construccion de SSA
//! necesita y lo que un CFG mal hecho no da.
//!
//! ### Lo que el grafo NO da, y el decompilador necesita —aqui se ABRE, no se rodea
//!
//! [`aegis_disasm::Instruccion`] guarda lo que el motor de CAPACIDADES necesita:
//! la **clase** de la instruccion ([`aegis_disasm::instruccion::Clase`], gruesa:
//! `Aritmetica`, `Logica`, `Mov`...), mascaras de registros leidos/escritos/
//! definidos, unos inmediatos acotados, y unas pocas relaciones de analisis de
//! constantes (`copia_de`, `delta`, `destino_reg`). Es deliberadamente **sin
//! texto y sin operandos**: por diseno no guarda el mnemonico ni la forma exacta
//! del operando, porque el motor de capacidades no los mira y guardarlos costaria
//! dos asignaciones por instruccion.
//!
//! Un decompilador FIEL necesita justo eso que falta: para elevar `add eax,
//! [rbp-8]` a una IR que se pueda **recompilar y comportar igual**, hay que saber
//! que se suma un registro de 32 bits y una carga de 32 bits desde `rbp-8`, que el
//! resultado va a `eax` con extension por ceros de la parte alta, y como quedan
//! las banderas. La clase `Aritmetica` + una mascara de registros no basta.
//!
//! **La decision, y por que esta es abrir y no rodear:** este crate anade una capa
//! de ELEVACION SEMANTICA ([`elevar`]) que produce, por instruccion, sus
//! micro-operaciones sobre la IR. Consume las direcciones y los limites de bloque
//! del CFG —la salida que la FASE 85 abrio a proposito— y re-decodifica cada
//! instruccion a su semantica completa con el mismo `iced-x86` que ya usa el
//! desensamblador (para x86) y con el decodificador A64 propio. No se duplica el
//! GRAFO —ese se consume tal cual—; se anade la unica pieza que faltaba, la
//! semantica de operandos, en el sitio donde tiene que vivir. Reconstruir el CFG
//! aqui habria sido rodearlo; re-leer la semantica de cada instruccion que el CFG
//! ya localizo es abrir lo que el modelo de capacidades no necesitaba exponer.
//!
//! ## Las cuatro cosas en las que este decompilador gana a Ghidra
//!
//! 1. **Determinismo.** La salida de Ghidra cambia entre versiones y entre
//!    analisis. Aqui la misma entrada da byte a byte la misma salida, fijado por
//!    prueba y comprobado entre dos maquinas. La causa del indeterminismo en casi
//!    todos los decompiladores es nombrar las variables por el ORDEN de analisis;
//!    aqui los nombres se derivan del CONTENIDO (hash del subgrafo que define la
//!    variable), no del orden. Ver [`nombres`].
//! 2. **La decompilacion es evidencia.** Cada sentencia de pseudo-C lleva las
//!    direcciones de las instrucciones que la sostienen, asi que una capacidad
//!    detectada CITA el codigo. Ver [`ir::Sentencia::origen`].
//! 3. **Cota dura y calidad declarada.** Se corta al plazo y DICE con que
//!    cobertura, y la [`calidad::Calidad`] —porcentaje elevado, gotos emitidos,
//!    variables sin tipo, funciones abandonadas— es parte de la salida, no un
//!    informe aparte. El decompilador DICE lo bueno que fue el resultado.
//! 4. **No ejecuta nada.** Invariante 10 del megaprompt (heredada de la FASE 85):
//!    los tipos de este crate no tienen variante de salida al sistema real, y el
//!    crate declara `#![forbid(unsafe_code)]`, que cierra la via del puntero a
//!    funcion. Se verifica por lo que FALTA.
//!
//! ## La metrica de calidad es la cifra de la fase
//!
//! La prueba honesta de un decompilador es el **redondeo semantico**: se compila
//! un corpus de funciones desde C conocido, se decompila, se **recompila** el
//! pseudo-C y se comprueba equivalencia de comportamiento sobre entradas
//! generadas. La **tasa de equivalencia** es la cifra de la fase, y se publica tal
//! cual sale —no se infla—. Un decompilador que dijera «100 %» sobre codigo
//! optimizado estaria mintiendo; este dice el numero real, y la cota de lo que no
//! alcanza sale en la calidad.
//!
//! ## El muro declarado
//!
//! No se persigue la ergonomia interactiva de Ghidra —renombrado colaborativo,
//! scripting de usuario, navegacion—. Ghidra es un IDE de ingenieria inversa;
//! AegisCore es un EDR. Se dice, y se dice por que.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod calidad;
pub mod decompilar;
pub mod elevar;
pub mod emitir;
pub mod estructura;
pub mod ir;
pub mod nombres;
pub mod tipos;

pub use calidad::Calidad;
pub use decompilar::{decompilar, Decompilacion};
pub use emitir::PseudoC;
pub use ir::{FuncionIr, Operacion, Operando, Sentencia, Terminador, ValId};
pub use tipos::Tipo;
