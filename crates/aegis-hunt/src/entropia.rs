//! Entropia de Shannon sobre una muestra de bytes.
//!
//! Es el indicio que separa un binario normal de uno empaquetado o cifrado: el
//! codigo maquina y el texto tienen mucha estructura y se quedan por debajo de
//! 7 bits/byte; un blob cifrado o comprimido se acerca a 8.
//!
//! La formula es H = -sum(p_i * log2(p_i)) sobre la frecuencia de cada valor de
//! byte. La cota superior con n simbolos distintos es log2(n), y eso tiene una
//! consecuencia PRACTICA que hay que respetar al muestrear: con menos de 256
//! bytes de muestra el maximo alcanzable ya es menor que 8, asi que un umbral
//! de 7,9 nunca se cruzaria por falta de muestra, no por falta de cifrado.

/// Bytes minimos para que la medida signifique algo.
///
/// Con menos de 256 valores posibles vistos, la cota log2(n) deja el resultado
/// artificialmente bajo. Por debajo de este tamano se prefiere no dar un numero
/// a dar uno enganoso.
pub const MUESTRA_MINIMA: usize = 256;

/// Entropia de Shannon en bits por byte, o `None` si la muestra es demasiado
/// pequena para que el numero signifique algo.
pub fn shannon(datos: &[u8]) -> Option<f64> {
    if datos.len() < MUESTRA_MINIMA {
        return None;
    }
    let mut cuentas = [0u32; 256];
    for b in datos {
        cuentas[*b as usize] += 1;
    }
    let total = datos.len() as f64;
    let mut h = 0.0;
    for c in cuentas.iter().filter(|c| **c > 0) {
        let p = f64::from(*c) / total;
        h -= p * p.log2();
    }
    Some(h)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_muestra_uniforme_da_ocho_bits() {
        // Cada valor de byte exactamente cuatro veces: el maximo teorico.
        let datos: Vec<u8> = (0..=255u8).flat_map(|b| [b; 4]).collect();
        let h = shannon(&datos).unwrap();
        assert!((h - 8.0).abs() < 1e-9, "h = {h}");
    }

    #[test]
    fn un_solo_valor_da_cero() {
        let datos = vec![0x41u8; 1024];
        assert_eq!(shannon(&datos), Some(0.0));
    }

    #[test]
    fn el_texto_normal_se_queda_muy_por_debajo_del_umbral() {
        let texto = "El rapido zorro marron salta sobre el perro perezoso. "
            .repeat(40)
            .into_bytes();
        let h = shannon(&texto).unwrap();
        assert!(h < 5.0, "el texto no deberia parecer cifrado: h = {h}");
    }

    #[test]
    fn una_muestra_corta_no_devuelve_un_numero_enganoso() {
        // Con 100 bytes el maximo alcanzable es log2(100) = 6,64: un umbral de
        // 7,9 no se cruzaria nunca, y el analista creeria que no hay nada.
        assert_eq!(shannon(&[0u8; 100]), None);
        assert!(shannon(&[0u8; MUESTRA_MINIMA]).is_some());
    }

    #[test]
    fn la_entropia_nunca_pasa_de_ocho() {
        // Invariante matematica: con 256 simbolos, H <= log2(256) = 8.
        for semilla in 0..16u32 {
            let datos: Vec<u8> = (0..4096u32)
                .map(|i| (i.wrapping_mul(2654435761).wrapping_add(semilla) >> 16) as u8)
                .collect();
            let h = shannon(&datos).unwrap();
            assert!((0.0..=8.0).contains(&h), "h fuera de rango: {h}");
        }
    }
}
