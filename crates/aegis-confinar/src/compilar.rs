//! Del perfil y el modo a lo que el kernel impone.
//!
//! # La traduccion, escrita
//!
//! | Del perfil | A | Modo aprendiendo | Modo permisivo | Modo obligatorio |
//! |---|---|---|---|---|
//! | llamadas | seccomp | todo se notifica | lo aprendido pasa; lo demas se notifica y se anota | lo aprendido pasa; lo demas, `EPERM` |
//! | familias de socket | argumento 0 de `socket` en seccomp | se notifica | se notifica y se compara | solo las aprendidas |
//! | rutas generalizadas | Landlock | — | se comprueban en el supervisor | reglas de Landlock |
//! | capacidades | conjunto limite | — | — | se quitan las no retenidas |
//!
//! Y dos excepciones que no son un detalle:
//!
//! - En los modos supervisados, `execve` y `execveat` se notifican SIEMPRE,
//!   esten o no en el perfil: el primer `execve` es lo que deja al hijo
//!   esperando mientras el padre recoge la escucha (ver
//!   `aegis_sandbox::supervisor`). Si pasara sin notificarse, el hijo cerraria la
//!   escucha antes de que el padre la tuviera.
//! - En permisivo, las llamadas que llevan rutas o direcciones se notifican
//!   aunque esten en el perfil: el numero de llamada no basta para saber si el
//!   perfil las permitiria, hay que mirar el argumento.
//!
//! La traduccion se COMPRUEBA con el interprete de BPF de `aegis-sandbox`: cada
//! llamada aprendida tiene que pasar, cada una no aprendida tiene que dar
//! `EPERM`. Sin esa prueba, «el perfil se compila a seccomp» es una intencion.

use aegis_sandbox::error::SandboxError;
use aegis_sandbox::seccomp::{compile_lista_blanca, ListaBlanca, Resto, SockFilter};
use aegis_sandbox::syscalls;
use aegis_sandbox::CompiledSandbox;

use crate::modo::Confirmacion;
use crate::observacion::mira_argumentos;
use crate::perfil::Perfil;

/// El errno de una llamada que el perfil no contiene, en modo obligatorio.
pub const ERRNO_DENEGADA: i32 = libc::EPERM;

fn nr(nombre: &str) -> Option<u32> {
    syscalls::numero(nombre)
}

/// El filtro del modo aprendiendo: todo se notifica.
#[must_use]
pub fn filtro_aprendizaje() -> Vec<SockFilter> {
    compile_lista_blanca(&ListaBlanca {
        permitidas: &[],
        dominios_socket: None,
        resto: Resto::Notificar,
        pasaje_de_escucha: true,
    })
}

/// Las llamadas que el filtro permisivo deja pasar sin preguntar.
#[must_use]
pub fn permitidas_en_permisivo(p: &Perfil) -> Vec<u32> {
    let exec = [nr("execve"), nr("execveat")];
    p.llamadas
        .iter()
        .copied()
        .filter(|n| !exec.contains(&Some(*n)))
        .filter(|n| !mira_argumentos(*n))
        .collect()
}

/// El filtro del modo permisivo.
#[must_use]
pub fn filtro_permisivo(p: &Perfil) -> Vec<SockFilter> {
    let permitidas = permitidas_en_permisivo(p);
    compile_lista_blanca(&ListaBlanca {
        permitidas: &permitidas,
        dominios_socket: None,
        resto: Resto::Notificar,
        pasaje_de_escucha: true,
    })
}

/// El programa de seccomp del modo obligatorio.
#[must_use]
pub fn programa_obligatorio(p: &Perfil) -> Vec<SockFilter> {
    let permitidas: Vec<u32> = p.llamadas.iter().copied().collect();
    let dominios: Vec<u32> = p.dominios.iter().copied().collect();
    compile_lista_blanca(&ListaBlanca {
        permitidas: &permitidas,
        // `socket` solo con las familias aprendidas. Si no se aprendio ninguna,
        // `socket` tampoco esta en las llamadas y no hay nada que filtrar.
        dominios_socket: Some(&dominios),
        resto: Resto::Errno(ERRNO_DENEGADA),
        pasaje_de_escucha: false,
    })
}

/// Compila el perfil para imponerlo. Exige la confirmacion: sin ella no hay
/// forma de obtener el sandbox obligatorio.
///
/// # Errores
/// Si el kernel no admite seccomp o una regla de Landlock falla.
pub fn obligatorio(
    p: &Perfil,
    _confirmacion: &Confirmacion,
) -> Result<CompiledSandbox, SandboxError> {
    CompiledSandbox::desde_perfil(
        programa_obligatorio(p),
        &reglas_aplicables(p),
        Some(p.capacidades_retenidas()),
    )
}

/// Las reglas de Landlock que se pueden aplicar EN ESTA MAQUINA.
///
/// El aprendizaje anota tambien lo que el programa intento abrir y no existia:
/// el cargador dinamico prueba cada directorio de `LD_LIBRARY_PATH` antes de
/// encontrar la biblioteca, y el supervisor ve la llamada, no su resultado.
/// Sobre un fichero que no existe no se puede poner una regla de Landlock (hay
/// que abrirlo), y tampoco hace falta: abrir algo que no existe falla con
/// `ENOENT` antes de que Landlock llegue a mirar. Se omiten aqui, al compilar, y
/// no en el perfil: el modo permisivo sigue comprobando contra todas.
#[must_use]
pub fn reglas_aplicables(p: &Perfil) -> aegis_sandbox::policy::FsPolicy {
    let (mut fs, _) = p.reglas();
    fs.read_only.retain(|r| r.exists());
    fs.read_write.retain(|r| r.exists());
    fs
}

/// Resumen de la traduccion, para el informe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traduccion {
    /// Llamadas que el perfil permite.
    pub llamadas_permitidas: usize,
    /// Llamadas de la tabla de esta arquitectura que el perfil deniega.
    pub llamadas_denegadas: usize,
    /// Reglas de Landlock en lectura.
    pub reglas_lectura: usize,
    /// Reglas en escritura.
    pub reglas_escritura: usize,
    /// Capacidades que se conservan.
    pub capacidades_retenidas: u64,
}

/// La traduccion de un perfil.
#[must_use]
pub fn traduccion(p: &Perfil) -> Traduccion {
    let (fs, _) = p.reglas();
    let total = syscalls::todas().len();
    Traduccion {
        llamadas_permitidas: p.llamadas.len(),
        llamadas_denegadas: total.saturating_sub(p.llamadas.len()),
        reglas_lectura: fs.read_only.len(),
        reglas_escritura: fs.read_write.len(),
        capacidades_retenidas: p.capacidades_retenidas(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::observacion::Observacion;
    use aegis_sandbox::seccomp::{evaluar, AUDIT_ARCH, RET_ALLOW, RET_ERRNO, RET_USER_NOTIF};
    use std::path::Path;

    fn perfil() -> Perfil {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        for n in [
            "read",
            "write",
            "openat",
            "close",
            "execve",
            "exit_group",
            "socket",
            "mmap",
        ] {
            p.anotar(&Observacion::Llamada(nr(n).expect(n)));
        }
        p.anotar(&Observacion::Socket {
            dominio: libc::AF_UNIX as u32,
            tipo: 1,
        });
        p
    }

    fn ev(prog: &[SockFilter], n: u32, a0: u64) -> u32 {
        evaluar(prog, n, AUDIT_ARCH, [a0, 0, 0, 0, 0, 0]).expect("interpretable")
    }

    /// LA TRADUCCION, COMPROBADA llamada a llamada sobre la tabla entera.
    #[test]
    fn en_obligatorio_pasa_exactamente_lo_aprendido_y_nada_mas() {
        let p = perfil();
        let prog = programa_obligatorio(&p);
        let denegada = RET_ERRNO | ERRNO_DENEGADA as u32;
        let sock = nr("socket").expect("socket");
        for (n, nombre) in syscalls::todas() {
            let esperado = if p.llamadas.contains(n) {
                RET_ALLOW
            } else {
                denegada
            };
            let a0 = if *n == sock { libc::AF_UNIX as u64 } else { 0 };
            assert_eq!(ev(&prog, *n, a0), esperado, "{nombre}");
        }
        // socket con una familia no aprendida: denegado aunque socket este.
        assert_eq!(ev(&prog, sock, libc::AF_INET as u64), denegada);
        let t = traduccion(&p);
        assert_eq!(t.llamadas_permitidas, 8);
        assert_eq!(
            t.llamadas_permitidas + t.llamadas_denegadas,
            syscalls::todas().len()
        );
    }

    #[test]
    fn en_permisivo_execve_y_las_llamadas_con_rutas_siempre_se_notifican() {
        let p = perfil();
        let prog = filtro_permisivo(&p);
        assert_eq!(ev(&prog, nr("read").expect("x"), 0), RET_ALLOW);
        assert_eq!(ev(&prog, nr("execve").expect("x"), 0), RET_USER_NOTIF);
        assert_eq!(ev(&prog, nr("openat").expect("x"), 0), RET_USER_NOTIF);
        assert_eq!(ev(&prog, nr("socket").expect("x"), 1), RET_USER_NOTIF);
        assert_eq!(ev(&prog, nr("ptrace").expect("x"), 0), RET_USER_NOTIF);
    }

    #[test]
    fn en_aprendizaje_todo_se_notifica() {
        let prog = filtro_aprendizaje();
        for (n, nombre) in syscalls::todas() {
            assert_eq!(ev(&prog, *n, 0), RET_USER_NOTIF, "{nombre}");
        }
    }
}
