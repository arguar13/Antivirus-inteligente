//! Las reglas que viajan dentro del binario del agente.
//!
//! FICHERO GENERADO por `tools/sigma/importar.sh` (ejemplo `importar` de este
//! crate) desde el commit fijado en `tools/sigma/COMMIT`: no se edita a mano.
//! La prueba `reglas_incluidas` falla si `reglas/linux/` y esta lista no
//! coinciden.
//!
//! Hoy no se ha importado nada: la lista esta vacia, el motor del agente lo dice
//! al arrancar («0 reglas, sin contenido») y `tools/verificar-sigma.sh` lo
//! declara en cada make ci. Vacio no es «limpio»: es «sin contenido».

/// `(fichero, fuente)` de cada regla incluida.
pub const LINUX: &[(&str, &str)] = &[];

/// El fichero de presupuestos de falsos positivos de las reglas incluidas.
pub const PRESUPUESTOS: &str = "";
