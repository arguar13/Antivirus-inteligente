//! # aegis-integridad — integridad sin carrera y por significado (FASE 104)
//!
//! Sustituye a `aegis-fim` (inotify + BLAKE3), que era EXACTAMENTE lo que hace
//! Wazuh FIM. Frente a Wazuh, AIDE y Tripwire, gana en cuatro cosas —y aqui esta
//! el lado que DECIDE, probado como logica pura sin kernel ni TPM—:
//!
//! 1. **Sin carrera, y con AUTOR.** inotify dice «este fichero cambio». Aqui el
//!    cambio nace del gancho LSM de la FASE 103 y lleva QUIEN lo hizo —proceso,
//!    credenciales y linaje— capturado EN EL KERNEL en el instante del cambio,
//!    sin releer `/proc` (invariante 9). Ver [`autoria`].
//! 2. **Por significado, no por hash.** Los ficheros de configuracion se parsean y
//!    el cambio se expresa en su semantica: «se abrio root por SSH», «se concedio
//!    NOPASSWD», «se anadio una clave autorizada». Un comentario nuevo no es una
//!    alerta; una puerta trasera si. Ver [`semantica`].
//! 3. **Linea base firmada y sellada contra el TPM.** Root puede reescribir la
//!    linea base, pero no puede volver a firmarla sin la clave del plano de
//!    control ni reproducir un sello de un arranque que no ocurrio. Es el fallo
//!    clasico de AIDE y Tripwire, cerrado. Ver [`baseline`].
//! 4. **Cobertura de lo que no es un fichero:** unidades de systemd, `cron`,
//!    modulos, `initramfs`, arranque, ACL, xattr, capacidades de fichero y el
//!    propio arbol del agente. Ver [`objetos`].
//!
//! La recuperacion ([`recuperacion`]) restaura desde la linea base atestada, pero
//! NUNCA en automatico: es una accion con las salvaguardas de la FASE 71. Y todo
//! cambio se traduce a una [`aegis_entidad::Senal`] del modelo unico ([`senal`]).
//!
//! # La frontera, dicha en voz alta
//!
//! La CAPTURA en vivo —el programa LSM-BPF que se engancha en `security_file_open`,
//! `path_rename`, `inode_unlink`... y lee `task->cred` para el autor— es trabajo
//! nuevo en `drivers/linux/aegis-bpf`: hoy ese arbol solo tiene tracepoints de
//! `sys_enter_*`, que solo VEN y tienen carrera. Sobre este entorno BPF LSM esta
//! activo (FASE 103), asi que ese gancho SE PUEDE enganchar; construirlo es el
//! incremento siguiente. Aqui esta el lado que decide, que es race-free POR
//! CONSTRUCCION: solo actua sobre lo que el evento capturo, y jamas relee el
//! sistema.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod autoria;
pub mod baseline;
pub mod objetos;
pub mod recuperacion;
pub mod semantica;
pub mod senal;

pub use autoria::{Autor, CambioConAutor, Credenciales};
pub use baseline::{EntradaBase, ErrorLineaBase, LineaBase, LineaBaseSellada, Pcr};
pub use objetos::Objeto;
pub use recuperacion::{proponer_restauracion, PropuestaRestauracion};
pub use semantica::{analizar_cambio, CambioSemantico, Formato};
pub use senal::senal_de_cambio;
