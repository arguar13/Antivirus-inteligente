//! El lado del trabajador: confinarse, saludar y servir peticiones hasta que el
//! agente cierre el canal.

use std::io::{self, BufReader, BufWriter};

use crate::analizadores::{Analizador, Analizadores};
use crate::confinamiento::{confinar, UID_POR_DEFECTO};
use crate::protocolo::{
    codificar_fallo, escribir, leer, ErrorProtocolo, Hola, Peticion, Tipo, Trama,
};

/// Variable de entorno con el uid propio del trabajador.
pub const VAR_UID: &str = "AEGIS_TRABAJADOR_UID";

/// Cierra todo descriptor heredado por encima de los tres estandar.
///
/// El agente tiene abiertos descriptores que en manos de un parser comprometido
/// serian una puerta: el ring buffer de las sondas, por ejemplo, se puede mapear
/// con `mmap`, que la lista blanca de seccomp permite. La biblioteca estandar
/// abre los suyos con `O_CLOEXEC`, pero no todo lo que el agente enlaza lo hace.
fn cerrar_heredados() {
    let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
        return;
    };
    let fds: Vec<i32> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&fd| fd > 2)
        .collect();
    for fd in fds {
        // SAFETY: cerrar un descriptor que no es de ningun objeto Rust vivo. El
        // que usaba `read_dir` ya se cerro al soltar el iterador.
        unsafe {
            libc::close(fd);
        }
    }
}

/// El trabajador entero. No vuelve: sale con 0 cuando el agente cierra el
/// canal, con 3 si no pudo confinarse lo bastante y con 4 ante una trama
/// invalida (el agente lo relanza).
pub fn servir() -> ! {
    cerrar_heredados();

    // Lo que es de confianza se carga ANTES de confinarse: el modelo empotrado
    // viene en el propio binario, no del atacante.
    let mut analizadores = Analizadores::default();
    analizadores.precargar();

    let uid = std::env::var(VAR_UID)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(UID_POR_DEFECTO);
    let aplicado = confinar(uid);
    let suficiente = aplicado.suficiente();

    let mut salida = BufWriter::new(io::stdout().lock());
    let hola = Hola {
        analizadores: if suficiente {
            Analizador::disponibles()
        } else {
            Vec::new()
        },
        confinamiento: aplicado.to_string(),
    };
    let saludo = Trama {
        tipo: Tipo::Hola,
        id: 0,
        carga: hola.codificar(),
    };
    if escribir(&mut salida, &saludo).is_err() || !suficiente {
        std::process::exit(3);
    }

    let mut entrada = BufReader::new(io::stdin().lock());
    loop {
        let trama = match leer(&mut entrada) {
            Ok(t) => t,
            Err(ErrorProtocolo::Cerrado) => std::process::exit(0),
            Err(_) => std::process::exit(4),
        };
        if trama.tipo != Tipo::Peticion {
            std::process::exit(4);
        }
        let respuesta = match Peticion::decodificar(&trama.carga) {
            Ok(p) => match analizadores.analizar(p.analizador, &p.datos) {
                Ok(informe) => Trama {
                    tipo: Tipo::Informe,
                    id: trama.id,
                    carga: informe.codificar(),
                },
                Err(motivo) => Trama {
                    tipo: Tipo::Fallo,
                    id: trama.id,
                    carga: codificar_fallo(&motivo),
                },
            },
            Err(e) => Trama {
                tipo: Tipo::Fallo,
                id: trama.id,
                carga: codificar_fallo(&e.to_string()),
            },
        };
        if escribir(&mut salida, &respuesta).is_err() {
            std::process::exit(0);
        }
    }
}
