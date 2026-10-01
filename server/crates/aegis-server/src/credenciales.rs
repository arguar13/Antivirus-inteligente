//! Credenciales de los operadores de la consola (H-02).
//!
//! # El problema que cierra
//!
//! `POST /api/sesion` emitia una sesion a CUALQUIER nombre de usuario no vacio:
//! la «autenticacion» de la API autenticaba que alguien habia escrito un nombre.
//! Ahora la sesion solo se emite contra una clave VERIFICADA frente a un
//! derivado guardado en PostgreSQL (`operadores`, migracion 0010).
//!
//! # Por que PBKDF2-HMAC-SHA256 con `ring` y no Argon2
//!
//! Argon2id es mejor contra hardware dedicado (es costoso en memoria). Pero
//! traerlo es una dependencia nueva en el plano de control, con su auditoria. En
//! cambio, `ring` ya esta en el arbol (rustls y tonic con `ring`) y trae
//! PBKDF2 con comparacion en tiempo constante. Con 600.000 iteraciones
//! (recomendacion de OWASP para PBKDF2-HMAC-SHA256) es una eleccion aceptada.
//! Cambiar a Argon2id es un cambio de este modulo solo, porque el formato
//! guardado lleva su algoritmo y sus parametros.
//!
//! # Formato guardado
//!
//! `pbkdf2-sha256$<iteraciones>$<sal en hex>$<derivado en hex>`. Las
//! iteraciones viajan con el derivado: subirlas manana no invalida las claves
//! ya dadas de alta, y las pruebas pueden usar pocas sin tocar produccion.
//!
//! # Lo que NO revela
//!
//! Un usuario inexistente cuesta lo mismo que uno existente con clave erronea
//! (se deriva igual, contra una sal fija), asi que el tiempo de respuesta no
//! dice que nombres existen.

use std::num::NonZeroU32;

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::PgPool;

use crate::error::{ErrorServidor, Resultado};

/// Iteraciones de PBKDF2 para las claves nuevas.
pub const ITERACIONES: u32 = 600_000;

/// `ITERACIONES` como `NonZeroU32`, comprobado al compilar.
const ITERACIONES_NZ: NonZeroU32 = match NonZeroU32::new(ITERACIONES) {
    Some(n) => n,
    None => panic!("ITERACIONES no puede ser cero"),
};

/// Algoritmo de derivacion.
const ALGORITMO: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

/// Prefijo del formato guardado.
const PREFIJO: &str = "pbkdf2-sha256";

/// Bytes de sal.
const LONGITUD_SAL: usize = 16;

/// Bytes del derivado (la salida de SHA-256).
const LONGITUD_DERIVADA: usize = 32;

/// Longitud minima de una clave nueva, en caracteres.
pub const LONGITUD_MINIMA_CLAVE: usize = 12;

/// Longitud maxima de una clave, en bytes. Acota el trabajo por peticion.
pub const LONGITUD_MAXIMA_CLAVE: usize = 1024;

/// Longitud maxima de un nombre de operador, en bytes.
pub const LONGITUD_MAXIMA_USUARIO: usize = 128;

/// Comprueba que un alta es aceptable antes de derivar nada.
///
/// # Errores
/// [`ErrorServidor::Config`] con el motivo.
pub fn validar_alta(usuario: &str, clave: &str) -> Resultado<()> {
    if usuario.is_empty()
        || usuario.len() > LONGITUD_MAXIMA_USUARIO
        || usuario.chars().any(char::is_control)
    {
        return Err(ErrorServidor::Config(format!(
            "usuario vacio, de mas de {LONGITUD_MAXIMA_USUARIO} bytes o con caracteres de control"
        )));
    }
    if clave.chars().count() < LONGITUD_MINIMA_CLAVE {
        return Err(ErrorServidor::Config(format!(
            "la clave necesita al menos {LONGITUD_MINIMA_CLAVE} caracteres"
        )));
    }
    if clave.len() > LONGITUD_MAXIMA_CLAVE {
        return Err(ErrorServidor::Config(format!(
            "la clave no puede pasar de {LONGITUD_MAXIMA_CLAVE} bytes"
        )));
    }
    Ok(())
}

/// Deriva una clave con las iteraciones de produccion.
///
/// # Errores
/// Si el sistema no da aleatoriedad para la sal.
pub fn derivar(clave: &str) -> Resultado<String> {
    derivar_con(clave, ITERACIONES)
}

/// Deriva una clave con un numero de iteraciones explicito.
///
/// Existe para las pruebas (600.000 iteraciones sin optimizar tardan
/// segundos). El alta de produccion usa [`derivar`].
///
/// # Errores
/// Iteraciones cero, o el sistema sin aleatoriedad.
pub fn derivar_con(clave: &str, iteraciones: u32) -> Resultado<String> {
    let n = NonZeroU32::new(iteraciones)
        .ok_or_else(|| ErrorServidor::Config("iteraciones de PBKDF2 = 0".into()))?;
    let mut sal = [0u8; LONGITUD_SAL];
    SystemRandom::new()
        .fill(&mut sal)
        .map_err(|_| ErrorServidor::Config("el sistema no da aleatoriedad para la sal".into()))?;
    let mut derivada = [0u8; LONGITUD_DERIVADA];
    pbkdf2::derive(ALGORITMO, n, &sal, clave.as_bytes(), &mut derivada);
    Ok(format!(
        "{PREFIJO}${iteraciones}${}${}",
        a_hex(&sal),
        a_hex(&derivada)
    ))
}

/// Comprueba una clave contra lo guardado. `None` = el usuario no existe.
///
/// La comparacion es la de `ring` (tiempo constante). Un usuario inexistente o
/// un derivado ilegible devuelven `false` DESPUES de hacer el mismo trabajo que
/// una comprobacion real.
pub fn comprobar(clave: &str, guardado: Option<&str>) -> bool {
    if let Some(f) = guardado.and_then(Guardado::leer) {
        return pbkdf2::verify(
            ALGORITMO,
            f.iteraciones,
            &f.sal,
            clave.as_bytes(),
            &f.derivada,
        )
        .is_ok();
    }
    let mut descartada = [0u8; LONGITUD_DERIVADA];
    pbkdf2::derive(
        ALGORITMO,
        ITERACIONES_NZ,
        &[0u8; LONGITUD_SAL],
        clave.as_bytes(),
        &mut descartada,
    );
    false
}

/// Derivado guardado, ya leido.
struct Guardado {
    iteraciones: NonZeroU32,
    sal: Vec<u8>,
    derivada: Vec<u8>,
}

impl Guardado {
    fn leer(texto: &str) -> Option<Guardado> {
        let mut partes = texto.split('$');
        if partes.next()? != PREFIJO {
            return None;
        }
        let iteraciones = NonZeroU32::new(partes.next()?.parse().ok()?)?;
        let sal = de_hex(partes.next()?)?;
        let derivada = de_hex(partes.next()?)?;
        if partes.next().is_some()
            || sal.len() < LONGITUD_SAL
            || derivada.len() != LONGITUD_DERIVADA
        {
            return None;
        }
        Some(Guardado {
            iteraciones,
            sal,
            derivada,
        })
    }
}

/// Derivado guardado de un operador ACTIVO, si existe.
///
/// # Errores
/// Fallo de la base de datos.
pub async fn hash_de_operador(pool: &PgPool, usuario: &str) -> Resultado<Option<String>> {
    let fila: Option<(String,)> =
        sqlx::query_as("SELECT hash_clave FROM operadores WHERE usuario = $1 AND activo")
            .bind(usuario)
            .fetch_optional(pool)
            .await?;
    Ok(fila.map(|(h,)| h))
}

/// Da de alta un operador, o le cambia la clave y lo reactiva.
///
/// # Errores
/// Fallo de la base de datos.
pub async fn alta_operador(pool: &PgPool, usuario: &str, hash: &str) -> Resultado<()> {
    sqlx::query(
        "INSERT INTO operadores (usuario, hash_clave) VALUES ($1, $2) \
         ON CONFLICT (usuario) DO UPDATE SET hash_clave = EXCLUDED.hash_clave, activo = TRUE",
    )
    .bind(usuario)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Anota el ultimo acceso correcto de un operador.
///
/// # Errores
/// Fallo de la base de datos.
pub async fn registrar_acceso(pool: &PgPool, usuario: &str) -> Resultado<()> {
    sqlx::query("UPDATE operadores SET ultimo_acceso = now() WHERE usuario = $1")
        .bind(usuario)
        .execute(pool)
        .await?;
    Ok(())
}

fn a_hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITOS[usize::from(b >> 4)]));
        s.push(char::from(DIGITOS[usize::from(b & 0x0f)]));
    }
    s
}

fn de_hex(texto: &str) -> Option<Vec<u8>> {
    if (texto.len() & 1) != 0 || !texto.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(texto.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_clave_correcta_pasa_y_la_erronea_no() {
        let h = derivar_con("una clave larga de prueba", 1_000).unwrap();
        assert!(comprobar("una clave larga de prueba", Some(&h)));
        assert!(!comprobar("una clave larga de prueba.", Some(&h)));
        assert!(!comprobar("", Some(&h)));
    }

    #[test]
    fn la_misma_clave_da_derivados_distintos_por_la_sal() {
        let a = derivar_con("una clave larga de prueba", 1_000).unwrap();
        let b = derivar_con("una clave larga de prueba", 1_000).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn sin_usuario_o_con_guardado_ilegible_no_pasa_nada() {
        assert!(!comprobar("cualquiera", None));
        assert!(!comprobar(
            "cualquiera",
            Some("texto-que-no-es-un-derivado")
        ));
        assert!(!comprobar("cualquiera", Some("pbkdf2-sha256$0$00$00")));
        assert!(!comprobar("cualquiera", Some("pbkdf2-sha256$1000$zz$zz")));
    }

    #[test]
    fn el_alta_exige_una_clave_razonable() {
        assert!(validar_alta("admin", "corta").is_err());
        assert!(validar_alta("", "una clave larga de prueba").is_err());
        assert!(validar_alta("ad\nmin", "una clave larga de prueba").is_err());
        assert!(validar_alta("admin", "una clave larga de prueba").is_ok());
    }

    #[test]
    fn el_formato_se_lee_de_vuelta() {
        let h = derivar_con("x", 7).unwrap();
        let g = Guardado::leer(&h).expect("el formato propio se lee");
        assert_eq!(g.iteraciones.get(), 7);
        assert_eq!(g.sal.len(), LONGITUD_SAL);
        assert_eq!(g.derivada.len(), LONGITUD_DERIVADA);
    }
}
