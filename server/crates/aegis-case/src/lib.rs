//! AegisCase: de alerta a caso cerrado.
//!
//! # El hueco que cierra
//!
//! Un producto que detecta pero no da un flujo de trabajo al analista genera
//! alertas que nadie mira. Y no por dejadez: un analista que recibe cincuenta
//! alertas al dia de las que cuarenta y ocho son ruido **deja de mirarlas**,
//! porque es la respuesta racional a una senal con esa relacion. El dia que llega
//! la que importa, va al mismo sitio que las demas.
//!
//! Asi que esto no es una capa de gestion encima del producto: es lo que impide
//! que la deteccion se pierda por el camino.
//!
//! # Los cuatro modulos, y el problema concreto de cada uno
//!
//! | Modulo | El problema |
//! |---|---|
//! | [`modelo`] | Un caso cerrado sin veredicto, o con tareas abiertas y sin justificar, cuenta igual en la metrica que uno resuelto |
//! | [`fusion`] | Mil alertas de una campana esconden el caso distinto que llego en medio — y fusionar de mas pierde un incidente sin dejar hueco |
//! | [`cronologia`] | Quien escribe la cronologia a mano copia los hechos que confirman su hipotesis |
//! | [`auditoria`] | Un registro que se puede editar despues no vale como evidencia, y no hace falta un atacante para romperlo |
//! | [`metricas`] | Sin ruido por regla no se pueden apagar las reglas que solo hacen ruido, que es lo unico que de verdad cambia un SOC |
//! | [`plantillas`] | «Contener primero» es correcto para un ransomware y catastrofico para una cuenta comprometida |
//!
//! # Lo que este crate NO hace
//!
//! No toca la base de datos y no habla por la red. Todo son funciones puras sobre
//! estado explicito, igual que `aegis-scale`: es lo que permite probar mil
//! alertas de una campana y un rastro manipulado en milisegundos, y tener esas
//! propiedades en la puerta de calidad en vez de en un documento.
//!
//! La persistencia y la API viven en `aegis-server`, que usa esto.

#![forbid(unsafe_code)]

pub mod auditoria;
pub mod cronologia;
pub mod fusion;
pub mod metricas;
pub mod modelo;
pub mod plantillas;

pub use auditoria::{Accion, Rastro, Rotura};
pub use cronologia::Cronologia;
pub use fusion::{Fusionador, Motivo};
pub use metricas::{calcular, Resumen};
pub use modelo::{Alerta, Caso, Estado, Observable, Severidad, Veredicto};
pub use plantillas::{proponer, Clase, Plantilla};
