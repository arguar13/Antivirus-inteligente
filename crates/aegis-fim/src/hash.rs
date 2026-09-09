//! Hashing BLAKE3 de ficheros, concurrente.
//!
//! # Por que BLAKE3 y no SHA-256
//!
//! El FIM vuelve a calcular el hash de un fichero cada vez que cambia, y en el
//! arranque calcula el de todos los ficheros vigilados. BLAKE3 es varias veces
//! mas rapido que SHA-256 y ademas paraleliza internamente sobre un mismo
//! fichero grande, asi que el coste de recalcular es una fraccion. Para integridad
//! —detectar que un fichero cambio— no se necesita nada de SHA-2; lo que importa
//! es que sea resistente a colisiones y rapido, y BLAKE3 es ambas cosas.
//!
//! # Concurrencia
//!
//! Los ficheros se hashean en paralelo repartidos entre hilos. En el arranque
//! hay cientos de ficheros de sistema que hashear, y hacerlo en serie retrasaria
//! la proteccion; en paralelo se aprovecha el disco y los nucleos.

use std::path::{Path, PathBuf};

/// Hash BLAKE3 de 32 bytes.
pub type Blake3 = [u8; 32];

/// Calcula el BLAKE3 de un fichero por streaming, sin cargarlo entero en
/// memoria: un binario de sistema puede ocupar decenas de MB y el presupuesto
/// del agente no da para tenerlo entero en RAM.
pub fn hash_file(ruta: &Path) -> std::io::Result<Blake3> {
    use std::io::Read;
    let mut f = std::fs::File::open(ruta)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Calcula el BLAKE3 de un buffer en memoria.
pub fn hash_bytes(datos: &[u8]) -> Blake3 {
    *blake3::hash(datos).as_bytes()
}

/// Representa un hash en hexadecimal.
pub fn to_hex(h: &Blake3) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hashea un conjunto de ficheros en paralelo.
///
/// Devuelve, por cada ruta, su hash o el error de E/S. Reparte las rutas entre
/// `hilos` trabajadores; con `hilos = 0` se usa el numero de nucleos disponibles
/// acotado, que es lo razonable para no saturar el disco.
pub fn hash_files_concurrent(
    rutas: &[PathBuf],
    hilos: usize,
) -> Vec<(PathBuf, std::io::Result<Blake3>)> {
    if rutas.is_empty() {
        return Vec::new();
    }
    let hilos = if hilos == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 8)
    } else {
        hilos
    };

    // Reparto estatico por indice: simple, sin contencion de una cola, y con
    // cientos de ficheros de tamano parecido el desequilibrio es despreciable.
    // io::Error no es Clone, asi que no se puede usar vec![None; n]; se
    // inicializa con None repetido de forma explicita.
    let resultado = std::sync::Mutex::new((0..rutas.len()).map(|_| None).collect::<Vec<_>>());
    std::thread::scope(|s| {
        for t in 0..hilos {
            let resultado = &resultado;
            let rutas = &rutas;
            s.spawn(move || {
                let mut i = t;
                while i < rutas.len() {
                    let h = hash_file(&rutas[i]);
                    resultado.lock().unwrap()[i] = Some((rutas[i].clone(), h));
                    i += hilos;
                }
            });
        }
    });

    resultado
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|o| o.expect("todos los indices se rellenan"))
        .collect()
}
