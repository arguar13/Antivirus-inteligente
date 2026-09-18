//! # aegis-disasm
//!
//! Desensamblado multiarquitectura, reconstruccion del flujo de control y
//! deduccion de **capacidades con evidencia**.
//!
//! # Inventario: que analisis estatico existe HOY, antes de esta fase
//!
//! Este inventario no es cortesia. El riesgo concreto de una fase como esta es
//! reconstruir en grande algo que ya existe en pequeno, y acabar con dos
//! implementaciones del mismo analisis que se contradicen en el caso raro. Se
//! escribe aqui, y no en un comentario de confirmacion, porque quien lea este
//! crate dentro de dos anos necesita saber **por que hay un decodificador mas**.
//!
//! | Crate | Que hace | Que produce | Identificador de entidad |
//! |---|---|---|---|
//! | `aegis-ml` | Extrae 256 atributos **estructurales** de un PE o ELF sin ejecutarlo, e infiere con un modelo ONNX empotrado | `BinaryFeatures` (formato, entropia global y por bloques, secciones, importaciones como `biblioteca!simbolo`, exportaciones, cadenas, y `parse_failed` como atributo y no como error) y `Prediction`/`Verdict` | **ninguno** |
//! | `aegis-emu` | Emula un **subconjunto** de x86-64 en una CPU virtual, para desplegar empaquetadores sin tocar el procesador real | `EventoComportamiento`, `Veredicto`, la carga desempaquetada y `DeteccionDop` | **ninguno** |
//! | `aegis-unpacker` | **Ejecuta** el binario bajo `ptrace`, confinado, hasta el punto de entrada original, y vuelca la region | Los bytes desempaquetados, que van al motor YARA | **ninguno** |
//!
//! Y en el plano de control, `aegis-tejido::traduccion::de_corpus` convierte un
//! acierto del corpus en una `Senal` de [`Motor::Estatico`], acotada al tope 80
//! de ese motor.
//!
//! ## Que se deduce de ese inventario, y por que este crate no lo duplica
//!
//! **`aegis-ml` lee importaciones, pero como texto y solo por la tabla.** Le
//! sirven de atributo para un modelo: no hay instrucciones, ni bloques, ni grafo,
//! ni resolucion de las importaciones que el binario resuelve **en ejecucion**,
//! que es justo lo que usa el shellcode. Su lectura y la de aqui no compiten:
//! una alimenta un vector de caracteristicas y la otra un grafo consultable.
//!
//! **`aegis-emu` tiene un decodificador x86-64 y NO es este.** El suyo cubre el
//! subconjunto que ejecutan los descompresores y rechaza ruidosamente lo demas,
//! porque su trabajo es **ejecutar** fielmente o pararse. El de aqui tiene que
//! cubrir el conjunto completo y **no ejecuta nada** —lo prohibe la invariante 8—.
//! Son dos problemas distintos con la misma palabra: uno no puede fingir que
//! entiende un opcode, y el otro no puede negarse a leerlo. Reutilizar el del
//! emulador habria significado que el analisis estatico heredara los limites de
//! la emulacion, que es exactamente al reves de lo que hace falta.
//!
//! **`aegis-unpacker` ejecuta.** Este crate trabaja sobre bytes inertes. Lo que
//! el desempaquetador produce —la region volcada— es una **entrada** valida para
//! este crate, y ahi esta la relacion correcta entre los dos.
//!
//! **Ninguno de los tres lleva `Eid`.** El plano estatico existe en el modelo de
//! entidad y lo alimenta el corpus; lo que no existe es un motor estatico que
//! produzca **capacidades a nivel de instruccion** con su evidencia. Ese es el
//! hueco, y es el que cierra [`senal`].
//!
//! # Lo que hay aqui
//!
//! | Pieza | Que resuelve | Modulo |
//! |---|---|---|
//! | Modelo comun de instruccion | que x86 y ARM64 alimenten el mismo grafo | [`instruccion`] |
//! | x86 y x86-64 | decodificacion completa sobre `iced-x86` | [`x86`] |
//! | ARM64 | decodificador propio de A64 | [`arm64`] |
//! | Grafo de flujo de control | bloques basicos, saltos indirectos y tablas de saltos | [`cfg`] |
//! | Grafo de llamadas | quien llama a quien, incluidas las indirectas resueltas | [`llamadas`] |
//! | Importaciones | por tabla, por **hash de nombre** y por recorrido de la PEB | [`importaciones`] |
//! | Capacidades | reglas declarativas con su tecnica ATT&CK y su evidencia | [`capacidad`], [`reglas`] |
//! | Cota de tiempo | el analisis se corta y **dice** con que cobertura | [`plazo`] |
//! | Puente al arbitro | la capacidad como `Senal` del motor estatico | [`senal`] |
//!
//! # Las cuatro decisiones
//!
//! **Nada se ejecuta.** La invariante 8 del megaprompt no admite matices: un
//! desensamblador que ejecuta lo que desensambla es un ejecutor de malware con
//! otro nombre. Aqui no hay ni una llamada que transfiera control a los bytes
//! analizados, y el crate declara `#![forbid(unsafe_code)]`, que es lo que
//! impide que aparezca por la via de un puntero a funcion.
//!
//! **ARM64 se decodifica en casa, y es una decision medida.** `iced-x86` entra
//! con **cero** dependencias transitivas y ya estaba en la linea base del agente.
//! El candidato para ARM64, `yaxpeax-arm`, arrastra ocho crates —`bitvec`,
//! `funty`, `radium`, `tap`, `wyz`, `num-traits`...— para decodificar una
//! codificacion de **ancho fijo de 32 bits**. Este proyecto rechazo libp2p por su
//! arbol; aceptar ocho crates por A64 seria incoherente. Ver [`arm64`].
//!
//! **El grafo es la salida, no un detalle interno.** La FASE 100 construye el
//! decompilador a pseudo-C **sobre este grafo**. Por eso [`cfg::Cfg`] y
//! [`llamadas::GrafoDeLlamadas`] son estructuras publicas y consultables, con sus
//! bloques, sus aristas y sus predecesores, y no un estado privado del motor de
//! capacidades. Un grafo que solo sirva para las reglas de hoy habria que
//! reconstruirlo entero manana.
//!
//! **Un analisis truncado lo dice.** [`plazo::Cobertura`] acompana a todo
//! resultado. Un analisis que se corta en silencio se lee, en un informe, como
//! «no encontramos nada» — y son dos frases muy distintas.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate lee bytes que elige el atacante y los recorre siguiendo
// desplazamientos que tambien elige el atacante. Es el sitio donde el producto
// no admite `unsafe` bajo ningun argumento de rendimiento.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod arm64;
pub mod cfg;
pub mod error;
pub mod instruccion;
pub mod llamadas;
pub mod plazo;
pub mod x86;

pub use cfg::{Bloque, Cfg};
pub use error::DisasmError;
pub use instruccion::{Arquitectura, Flujo, Instruccion};
pub use plazo::{Cobertura, Plazo};

/// Tope de confianza del motor que produce este analisis.
///
/// Se reexporta para que quien lea las capacidades vea, sin salir de aqui, que
/// **ninguna pasa de 80**. Una firma estatica acierta mucho y un empaquetador
/// nuevo la esquiva entera, y el tope esta puesto por eso.
pub const TOPE_DE_CONFIANZA: u8 = 80;

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::escala::Motor;

    #[test]
    fn el_tope_declarado_aqui_es_el_que_aplica_el_arbitro() {
        // No se puede comprobar en tiempo de compilacion —`tope_confianza` no es
        // `const fn`— asi que se comprueba aqui. El riesgo que cubre es real:
        // que alguien mueva la tabla de topes y este crate siga documentando 80
        // mientras el arbitro aplica otro numero. La documentacion mentiria, y
        // nadie lo veria hasta auditar un veredicto.
        assert_eq!(
            TOPE_DE_CONFIANZA,
            Motor::Estatico.tope_confianza().centesimas(),
            "el tope de este crate y el del motor tienen que ser el mismo numero"
        );
    }
}
