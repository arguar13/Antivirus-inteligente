//! AegisKnowledge: el modelo de conocimiento de amenazas (FASE 98).
//!
//! OpenCTI modela el conocimiento y lo relaciona. Aqui se hace lo mismo Y se une
//! con lo OBSERVADO: un actor no es una ficha, es un conjunto de entidades que
//! este despliegue ha visto de verdad. «Que se de este actor» y «que he visto yo
//! de este actor» tienen la MISMA respuesta, porque es el mismo grafo.

pub mod catalogo;
pub mod grafo;
pub mod inferencia;
pub mod intercambio;
pub mod observado;
