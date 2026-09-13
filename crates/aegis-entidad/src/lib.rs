//! AegisFabric: un solo modelo de entidad, un solo veredicto.
//!
//! # La ventaja estructural, dicha sin adornos
//!
//! Nueve subsistemas de deteccion, cada uno con su propia idea de «que es una
//! cosa» y su propio enumerado de veredicto, producen **nueve sucesos sin
//! relacion** ante un mismo ataque. Antes de esta fase este arbol tenia **doce
//! enumerados de veredicto y nueve de severidad** distintos —veintiuno en total,
//! sin contar los que hablan de otras cosas, como el regimen de memoria o la
//! compatibilidad de protocolo—, y ninguno estaba mal por separado.
//!
//! Lo que esta fase construye no es una capa mas: es el tejido que hace que la
//! misma cosa se llame igual en los nueve, y que lo que digan se combine en un
//! sitio con un criterio que se puede leer.
//!
//! Eso no se consigue integrando productos de fabricantes distintos. Es la unica
//! ventaja de este diseño que **no se puede copiar comprando**.
//!
//! # Los cuatro modulos
//!
//! | Modulo | Que resuelve |
//! |---|---|
//! | [`entidad`] | Cuando dos observaciones son la misma cosa — y sobre todo, cuando NO |
//! | [`escala`] | Severidad y confianza son ejes distintos, y la traduccion de cada motor esta escrita Y se comprueba |
//! | [`arbitro`] | Un solo sitio donde se decide, con seis reglas en orden y sin medias magicas |
//! | [`linaje`] | El camino del ataque atraviesa red, fichero, proceso, identidad y respuesta como UNA cadena |
//!
//! # El inventario: de donde sale este vocabulario
//!
//! No se invento: se **conto**. Estos son los trece motores que producen veredictos
//! hoy, con que hablaban antes de esta fase y sobre que clase de entidad. El censo
//! completo —con el crate, la fase y la derivacion de cada identificador— vive en
//! `aegis_tejido::inventario`, en el plano de control, porque es alli donde estan
//! todos los subsistemas a la vez; y la puerta de calidad recorre [`escala::Motor`]
//! exigiendo que ninguno se quede sin fila.
//!
//! | Plano | Motores | Vocabulario nativo del que se viene |
//! |---|---|---|
//! | Estatico | `estatico`, `aprendizaje` | coincidencia de firma; `Veredicto{Benigno,Sospechoso,Malicioso}` + puntuacion `f32` |
//! | Conductual | `conductual`, `syscallguard`, `detonate` | puntuacion acumulada; `Severidad` de cinco; `Veredicto{SinHallazgos,ConHallazgos,NoConcluyente}` |
//! | Red | `wire`, `ips`, `l7hunter` | `Hecho` de 23 variantes; `Confianza{Baja,Media,Alta}`; `Veredicto{SinMuestra,Irregular,Baliza…}` |
//! | Memoria | `memhunter` | `Severidad` de cinco sobre la region |
//! | Identidad | `itdr` | `Severidad` de cinco + `Nivel` del grafo de identidad |
//! | Plataforma | `fwaudit` | `Veredicto` de linea base + `Severidad` de anomalia ACPI |
//! | Externo | `intel`, `enjambre` | `Veredicto` de cinco de la fusion; `Veredicto{Insuficiente,Corroborado,…}` |
//!
//! Eran **doce enumerados de veredicto y nueve de severidad**, y ninguno estaba
//! mal por separado. Lo que no habia era una sola tabla que dijera cual se traduce
//! a cual — y sin ella, nueve subsistemas ante un mismo ataque producen nueve
//! sucesos sin relacion.
//!
//! Tres productores **no** entran en la tabla, a proposito: el veredicto de cierre
//! de `aegis-case` (lo escribe una persona, y llega despues: darle voto seria
//! realimentar la deteccion con su propio resultado), la decision de contencion de
//! `aegis-predict` (consume veredictos, no los produce) y los motivos de retencion
//! de `aegis-share` (gobiernan la difusion, no dicen si algo es malicioso).
//!
//! # Las decisiones que se repiten, y de donde vienen
//!
//! No son nuevas: son las mismas que el producto ya tomo en otras fases, aplicadas
//! aqui. Que se repitan es la señal de que son el criterio de la casa y no una
//! ocurrencia:
//!
//! - **Corroborar cuenta planos, no motores.** Es «dos canales que repiten al
//!   mismo no son dos fuentes» de `aegis-share::procedencia`, aplicado a los
//!   motores propios: el estatico y el modelo del endpoint comparten la entrada
//!   entera.
//! - **No se promedia.** Es el argumento de `aegis-enrich::fusion`: una media
//!   esconde el desacuerdo y convierte el desconocimiento en voto.
//! - **`NoConcluyente` no es `Limpio`.** Es la disciplina de tri-estado desde la
//!   primera fase.
//! - **El identificador se deriva, no se coordina.** Es el reparto por sorteo de
//!   `aegis-scale`: dos observadores con los mismos hechos llegan al mismo nombre
//!   sin hablar entre ellos.
//! - **Todo veredicto sale con una frase.** Y la puerta de calidad la comprueba
//!   recorriendo **todas** las combinaciones, no afirmandolo.
//!
//! # Coste en el endpoint
//!
//! Una dependencia, `sha2`, que el agente **ya tenia**. El arbol de dependencias
//! del endpoint no crece ni un crate — que en un producto que corre con
//! privilegios en cada maquina es la mitad del diseño.

#![forbid(unsafe_code)]

pub mod arbitro;
pub mod entidad;
pub mod escala;
pub mod linaje;

pub use arbitro::{arbitrar, Juicio, Resultado, Senal, Veredicto};
pub use entidad::{Clase, Eid};
pub use escala::{Confianza, Motor, Plano, Severidad};
pub use linaje::{Arista, Linaje, Relacion};
