//! Nombres estables derivados del CONTENIDO, no del orden de analisis.
//!
//! # La causa del indeterminismo de casi todos los decompiladores
//!
//! Ghidra —y casi todos— nombra las variables `local_10`, `uVar3`, `iVar4`... por
//! el ORDEN en que las descubre. Cambia una version del analizador, o el orden en
//! que recorre los bloques, y los nombres bailan: dos decompilaciones del mismo
//! binario dan textos distintos que no se pueden comparar. El informe que
//! justifica una deteccion el lunes no cuadra con el del martes, y nadie sabe si
//! cambio el binario o solo el numerado.
//!
//! Aqui el nombre de un valor se deriva de UNA huella de su definicion —que
//! operacion es, sobre que operandos, en que ancho— con FNV-1a. Dos valores que se
//! calculan igual reciben el mismo nombre en cualquier maquina y en cualquier
//! version, y dos que se calculan distinto reciben nombres distintos. El nombre
//! deja de depender del orden.
//!
//! # Por que FNV-1a y no `DefaultHasher`
//!
//! Por lo mismo que en `aegis-predict`: la salida de `DefaultHasher` puede cambiar
//! entre versiones de Rust, asi que un nombre derivado de el cambiaria al
//! recompilar el propio AegisCore. FNV-1a esta fijado por especificacion y se
//! implementa aqui, en unas lineas, sin dependencia.

/// El desplazamiento inicial de FNV-1a de 64 bits.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// El primo de FNV-1a de 64 bits.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// La huella FNV-1a de 64 bits de unos bytes. Determinista y fijada por
/// especificacion, no por la version del compilador.
#[must_use]
pub fn huella(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Un nombre de variable estable a partir de una huella y una letra de familia.
///
/// La letra da una pista de la clase del valor sin depender del orden: `v` para un
/// valor de calculo, `a` para un argumento, `p` para un puntero, `s` para un valor
/// de pila. Los cuatro primeros bytes hex de la huella lo hacen unico y estable.
#[must_use]
pub fn nombre(familia: char, huella: u64) -> String {
    format!("{familia}_{:08x}", huella & 0xffff_ffff)
}

/// Un nombre de variable derivado de una descripcion canonica de su definicion.
///
/// El llamante arma `descripcion` de forma determinista —la operacion, los
/// operandos, el ancho— y este nombre no dependera del orden en que se descubrio.
#[must_use]
pub fn nombre_de(familia: char, descripcion: &[u8]) -> String {
    nombre(familia, huella(descripcion))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn fnv_1a_da_el_valor_de_la_especificacion() {
        // Vector conocido: FNV-1a de la cadena vacia es el offset basis.
        assert_eq!(huella(b""), FNV_OFFSET);
        // Y de "a": offset xor 'a', por el primo.
        let esperado = (FNV_OFFSET ^ 0x61).wrapping_mul(FNV_PRIME);
        assert_eq!(huella(b"a"), esperado);
    }

    #[test]
    fn dos_definiciones_iguales_reciben_el_mismo_nombre() {
        // Es la propiedad que hace la salida comparable entre ejecuciones: el
        // nombre no depende del orden, solo del contenido.
        let d = b"bin:sumar(arg0,const:4);b32";
        assert_eq!(nombre_de('v', d), nombre_de('v', d));
    }

    #[test]
    fn dos_definiciones_distintas_reciben_nombres_distintos() {
        assert_ne!(
            nombre_de('v', b"bin:sumar(arg0,const:4);b32"),
            nombre_de('v', b"bin:sumar(arg0,const:8);b32")
        );
    }

    #[test]
    fn el_nombre_tiene_forma_estable() {
        let n = nombre('p', 0xdead_beef_1234_5678);
        assert_eq!(n, "p_12345678");
    }
}
