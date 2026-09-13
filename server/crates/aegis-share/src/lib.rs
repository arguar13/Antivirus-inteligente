//! AegisShare: producir, consumir y compartir inteligencia sin filtrar nada.
//!
//! # La asimetria que lo decide todo
//!
//! Compartir es **irreversible**, y los errores se propagan. De ahi salen los dos
//! fallos que este crate existe para impedir, y ninguno de los dos es de formato:
//!
//! 1. **Sale algo que no debia.** Un `TLP:RED` en un canal publico no se puede
//!    retirar. Y no hace falta un ataque: basta un filtro que se quedo atras
//!    cuando se añadio un camino nuevo.
//! 2. **Entra algo envenenado y no se puede deshacer.** Un canal mete tres
//!    semanas de indicadores fabricados; se descubre; y sin procedencia no se
//!    sabe cuales eran suyos.
//!
//! El formato —STIX, TAXII— es la parte facil. Lo dificil es que **no haya
//! ningun camino** por el que algo salga sin pasar por la politica, y que
//! **siempre** se pueda deshacer lo que entro.
//!
//! # Los modulos, y el problema de cada uno
//!
//! | Modulo | El problema |
//! |---|---|
//! | [`marcado`] | Casi todo el mundo implementa TLP y se olvida de PAP: `TLP:GREEN`+`PAP:RED` significa «compartelo con todos y NO lo bloquees», y quien solo mira TLP lo bloquea y quema la operacion ajena |
//! | [`stix`] | Un paquete STIX es JSON de un desconocido que procesa el plano de control, y la extensibilidad del formato **es** la superficie de ataque |
//! | [`difusion`] | Si cada camino de salida tuviera su filtro, uno se quedaria atras — y el que se queda atras comparte de mas |
//! | [`taxii`] | La paginacion por desplazamiento **pierde objetos en silencio** cuando alguien escribe entre dos peticiones |
//! | [`federacion`] | «Ya he visto ese identificador» corta el bucle y tambien las correcciones |
//! | [`procedencia`] | Dos canales que repiten al mismo no son dos fuentes, y quien envenena el de arriba cobra en los dos |
//! | [`taxonomia`] | Una etiqueta de texto libre no es una etiqueta, es una nota: en seis meses la misma cosa esta escrita de cuatro formas |
//! | [`puente`] | El enjambre llega a maquinas que el atacante puede haber comprometido |
//!
//! # Las cinco propiedades que hay que poder afirmar
//!
//! 1. **Ida y vuelta STIX sin perder nada**, incluido lo que este nodo no
//!    entiende — si no, este nodo es un agujero en la federacion.
//! 2. **Un indicador no compartible no sale por ningun camino**: TAXII,
//!    federacion, enjambre y exportacion, y la puerta de calidad recorre el
//!    enumerado entero para que un camino nuevo no se quede sin cubrir.
//! 3. **Un ciclo de federacion no produce un bucle**, y una **actualizacion si
//!    circula**: las dos mitades, porque la defensa evidente rompe la segunda.
//! 4. **Un canal envenenado se revierte por procedencia**, dejando en pie lo que
//!    sostenian los demas.
//! 5. **Entrada hostil**: ningun paquete preparado provoca panico ni consumo sin
//!    acotar.
//!
//! # La doctrina del enjambre se conserva intacta
//!
//! > **El enjambre transporta autoridad; no la concede.**
//!
//! Un indicador que llega por federacion **no se convierte en una orden** por muy
//! fiable que sea su fuente. [`puente::Carga`] tiene dos variantes y ninguna manda
//! nada: evidencia, que necesita corroboro de K pares, y artefacto, que necesita
//! la firma del plano de control. **No hay una tercera**, y esa ausencia es la
//! misma tecnica que en `aegis-detonate` y en `orden::Accion::gossipable`: lo que
//! no se puede expresar no se puede configurar por error.
//!
//! # Sobre el reloj
//!
//! Todo recibe `ahora_ns` como argumento, igual que en `aegis-case`,
//! `aegis-scale` y `aegis-enrich`. Es lo que permite probar una federacion de
//! cinco instancias y noventa dias de caducidad en microsegundos, y tener estas
//! propiedades en la puerta de calidad en vez de en un documento.

#![forbid(unsafe_code)]

pub mod difusion;
pub mod federacion;
pub mod marcado;
pub mod procedencia;
pub mod puente;
pub mod stix;
pub mod taxii;
pub mod taxonomia;

pub use difusion::{Canal, Destino, Difusor, Reparto, Retenido};
pub use federacion::{Absorcion, Descarte, EnTransito, Instancia, Par};
pub use marcado::{Marcado, Pap, Tlp};
pub use procedencia::{Aporte, Fiabilidad, Registro, Revocacion};
pub use puente::{Carga, Indicador, Puente};
pub use stix::{Objeto, Paquete, Rechazo, Tipo};
pub use taxii::{Cliente, Coleccion, Cursor, Peticion, Servidor};
pub use taxonomia::{Etiqueta, Galaxia, Grupo, Taxonomia, Vocabulario};
