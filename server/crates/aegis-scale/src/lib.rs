//! AegisScale: el plano de control para cien mil agentes.
//!
//! # La diferencia entre diez agentes y cien mil no es un factor de escala
//!
//! Es un diseno distinto. Los sistemas que no se disenaron para ello **no se
//! arreglan anadiendo maquinas**, porque lo que falla no es la capacidad de una
//! maquina: es que la funcion que reparte la flota rebaraja el ochenta por ciento
//! al anadir un nodo, que la purga de la base de datos tarda cada dia un poco mas
//! hasta el dia en que no acaba, y que veinte mil agentes reconectando a la vez
//! tiran al nodo que acaba de levantarse.
//!
//! Los cuatro modulos de aqui son esas cuatro cosas:
//!
//! | Modulo | El fallo que evita |
//! |---|---|
//! | [`fragmento`] | Anadir un servidor rebaraja la flota entera |
//! | [`sesion`] | Cien mil conexiones vivas no caben, y la manada tira al nodo que vuelve |
//! | [`particion`] | Una tabla de alertas sin particionar muere al año, y muere por la purga |
//! | [`version`] | Una actualizacion progresiva rompe en silencio por un campo que un nodo viejo ignora |
//!
//! # Lo que NO esta aqui, y donde esta
//!
//! * **Las cuotas por inquilino** y la **senal de contrapresion** hacia los
//!   agentes ya se construyeron en `aegis-pipeline` (FASE 74). Reimplementarlas
//!   aqui seria tener dos politicas de admision, y el dia que difirieran un
//!   cliente veria una y otro la otra.
//! * **La entrega durable y el reenvio** viven en `aegis-ingest` y en
//!   `aegis-firehose`.
//!
//! # Por que ninguno de estos modulos hace entrada/salida
//!
//! Todos son funciones puras sobre estado explicito: el reparto es una funcion de
//! (agente, nodos), el plan de particiones es una funcion de (ahora, existentes),
//! la compatibilidad es una funcion de (version, version). Eso permite **probar
//! cien mil agentes y trece meses de particiones en milisegundos**, que es la
//! unica forma de tener estas propiedades en una puerta de calidad en vez de en
//! un documento.
//!
//! Quien hace la entrada/salida es `aegis-server`, que usa esto.

#![forbid(unsafe_code)]

pub mod fragmento;
pub mod particion;
pub mod sesion;
pub mod version;

pub use fragmento::{Mapa, Membresia, Nodo, Reparto};
pub use particion::{planificar, Mes, Plan};
pub use sesion::{Capacidad, Repartidor, Resultado};
pub use version::{compatibilidad, Compatibilidad, Progresiva, Version};
