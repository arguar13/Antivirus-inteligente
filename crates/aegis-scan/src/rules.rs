//! Conjunto de reglas base, empotrado en el binario.

/// Reglas base compiladas al arrancar.
///
/// Van empotradas y no en un fichero suelto por la misma razon que el objeto
/// eBPF: un `.yar` junto al binario es algo que un atacante con permisos de
/// escritura puede vaciar, y el agente arrancaria sin detectar nada y sin
/// quejarse.
pub const BASE_RULES: &str = include_str!("../rules/base.yar");

/// Numero de reglas que se espera compilar del conjunto base.
///
/// Se comprueba al arrancar: si el conjunto se corrompe o se recorta, el motor
/// arranca con menos reglas de las que cree tener y el operador nunca se
/// entera. Cambiar el conjunto obliga a actualizar esta constante, que es
/// exactamente la friccion que se busca.
pub const BASE_RULE_COUNT: usize = 14;
