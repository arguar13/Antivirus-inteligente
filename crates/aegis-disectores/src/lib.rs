//! # `aegis-disectores` — AegisDissect (FASE 89)
//!
//! Los disectores de protocolo del sensor de red, en un crate **aparte** del
//! motor.
//!
//! ## Por que aparte
//!
//! Porque el arbol del motor no puede crecer con cada protocolo nuevo. El motor
//! ([`aegis_wire`]) es la parte que corre en la ruta caliente de cada paquete de
//! cada endpoint: su codigo se audita entero y su memoria esta presupuestada.
//! Los disectores son cuarenta y pico piezas independientes que se anaden, se
//! quitan y se compilan por perfil —una pasarela industrial no necesita el
//! disector de Kafka, y un servidor de aplicaciones no necesita el de Modbus—.
//! Mezclarlos habria hecho imposible las dos cosas.
//!
//! ## Las tres invariantes de esta fase
//!
//! 1. **Sans-IO.** Ningun disector abre un socket, lee un fichero ni mira el
//!    reloj: recibe `&[u8]` y devuelve hechos. Eso es lo que permite construir
//!    cada ataque entero en una prueba, sin montar un servidor y sin carreras.
//!    Ver [`disector`].
//! 2. **Una cota por flujo no es una cota.** El atacante elige tambien el numero
//!    de flujos. De ahi los dos techos de [`disector::Registro`]: el de un flujo
//!    y el de todos juntos, con recuento de lo que se suelta al llegar al
//!    segundo.
//! 3. **El sensor no puede ser un amplificador.** El rasgo [`disector::Disector`]
//!    no tiene forma de emitir bytes. No responde, no sondea y no pregunta al
//!    dispositivo — que en una red industrial no es una preferencia de estilo:
//!    un PLC de hace veinte anos se cae con un escaneo, y el sensor que
//!    «enriquece» preguntandole provoca la parada de planta que venia a evitar.
//!
//! ## La cifra de cobertura
//!
//! Lo que distingue a este crate de Wireshark y de Zeek no es cuantos protocolos
//! diseca, sino que **declara lo que no entiende**. Cada disector publica los
//! mensajes que entiende y los que reconoce y no analiza, y cada diseccion suma
//! a una [`cobertura::Cobertura`] que dice si de ese flujo se puede concluir
//! algo. Sin ella, una lista de hechos vacia es una afirmacion sobre el flujo
//! entero que solo es cierta si se entendio entero.
//!
//! ## Que habia antes
//!
//! [`inventario::LINEA_BASE`]: los doce protocolos que `aegis-wire` ya disecaba,
//! con lo que saca de cada uno. Esta en el codigo y no en un documento porque
//! una medida escrita aparte se queda desfasada el primer dia.

// Un disector es un parseador de entrada hostil. Aqui no hay ni un `unsafe`, y
// que el compilador lo impida es parte del diseno: el modo de fallo de este
// crate tiene que ser un error con nombre, nunca una lectura fuera de rango.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bases;
pub mod catalogo;
pub mod cobertura;
pub mod correo;
pub mod disector;
pub mod identidad;
pub mod industrial;
pub mod inventario;
pub mod mensajeria;
pub mod nube;
pub mod remoto;
pub mod texto;
pub mod tuneles;
pub mod web;

pub use catalogo::{registro_completo, Comparacion, Familia, Perfil};
pub use cobertura::{Cobertura, Motivo};
pub use disector::{Contexto, Disector, Registro, Salida, MAX_ESTADO_GLOBAL, MAX_ESTADO_POR_FLUJO};
