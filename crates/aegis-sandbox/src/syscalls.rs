//! Numeros de llamada al sistema, por arquitectura.
//!
//! # Por que una tabla propia y no una caja
//!
//! Un filtro de seccomp trabaja con NUMEROS, y los numeros dependen de la
//! arquitectura: `ptrace` es 101 en x86-64 y 117 en aarch64. Equivocarse no
//! produce un error de compilacion ni un fallo visible: produce un sandbox que
//! bloquea una llamada distinta de la que se pretendia y deja pasar la que
//! importaba. Por eso la tabla esta aqui, explicita, con una constante por
//! nombre y separada por arquitectura, en vez de escondida tras una dependencia.
//!
//! Las arquitecturas que no estan son un error de compilacion, no un filtro
//! vacio: un sandbox que no bloquea nada es peor que no tener sandbox, porque
//! quien lo despliega cree estar protegido.

/// Una llamada al sistema que el sandbox sabe nombrar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Syscall {
    /// `ptrace`: control total sobre otro proceso.
    Ptrace,
    /// `process_vm_readv`: lectura de memoria ajena.
    ProcessVmReadv,
    /// `process_vm_writev`: escritura de memoria ajena, la inyeccion sin ptrace.
    ProcessVmWritev,
    /// `kexec_load`: sustitucion del kernel en marcha.
    KexecLoad,
    /// `kexec_file_load`: idem, desde un descriptor.
    KexecFileLoad,
    /// `init_module`: carga de un modulo de kernel.
    InitModule,
    /// `finit_module`: idem, desde un descriptor.
    FinitModule,
    /// `delete_module`: descarga de un modulo, incluido el del propio EDR.
    DeleteModule,
    /// `bpf`: carga de programas eBPF, incluidos los que sustituirian a los del
    /// agente.
    Bpf,
    /// `perf_event_open`: acceso a contadores y trazas del kernel.
    PerfEventOpen,
    /// `socket`.
    Socket,
    /// `connect`.
    Connect,
    /// `bind`.
    Bind,
    /// `listen`.
    Listen,
    /// `accept`.
    Accept,
    /// `accept4`.
    Accept4,
    /// `sendto`.
    Sendto,
    /// `sendmsg`.
    Sendmsg,
    /// `recvfrom`.
    Recvfrom,
    /// `recvmsg`.
    Recvmsg,
    /// `mount`.
    Mount,
    /// `umount2`.
    Umount2,
    /// `pivot_root`.
    PivotRoot,
    /// `chroot`.
    Chroot,
    /// `setuid`.
    Setuid,
    /// `setgid`.
    Setgid,
    /// `setreuid`.
    Setreuid,
    /// `setregid`.
    Setregid,
    /// `setresuid`.
    Setresuid,
    /// `setresgid`.
    Setresgid,
    /// `capset`: alteracion de las capacidades del proceso.
    Capset,
    /// `unshare`: creacion de espacios de nombres.
    Unshare,
    /// `setns`: entrada en el espacio de nombres de otro proceso.
    Setns,
    /// `personality`: cambio de ABI, usado para desactivar ASLR.
    Personality,
    /// `userfaultfd`: manejo de fallos de pagina en espacio de usuario, usado
    /// para ganar carreras de tiempo de comprobacion contra tiempo de uso.
    Userfaultfd,
    /// `keyctl`.
    Keyctl,
    /// `add_key`.
    AddKey,
    /// `request_key`.
    RequestKey,
}

#[cfg(target_arch = "x86_64")]
impl Syscall {
    /// Numero de la llamada en esta arquitectura.
    pub fn number(self) -> u32 {
        match self {
            Syscall::Socket => 41,
            Syscall::Connect => 42,
            Syscall::Accept => 43,
            Syscall::Sendto => 44,
            Syscall::Recvfrom => 45,
            Syscall::Sendmsg => 46,
            Syscall::Recvmsg => 47,
            Syscall::Bind => 49,
            Syscall::Listen => 50,
            Syscall::Setuid => 105,
            Syscall::Setgid => 106,
            Syscall::Ptrace => 101,
            Syscall::Setreuid => 113,
            Syscall::Setregid => 114,
            Syscall::Setresuid => 117,
            Syscall::Setresgid => 119,
            Syscall::Capset => 126,
            Syscall::Personality => 135,
            Syscall::PivotRoot => 155,
            Syscall::Chroot => 161,
            Syscall::Mount => 165,
            Syscall::Umount2 => 166,
            Syscall::InitModule => 175,
            Syscall::DeleteModule => 176,
            Syscall::KexecLoad => 246,
            Syscall::AddKey => 248,
            Syscall::RequestKey => 249,
            Syscall::Keyctl => 250,
            Syscall::Unshare => 272,
            Syscall::Accept4 => 288,
            Syscall::PerfEventOpen => 298,
            Syscall::Setns => 308,
            Syscall::ProcessVmReadv => 310,
            Syscall::ProcessVmWritev => 311,
            Syscall::FinitModule => 313,
            Syscall::KexecFileLoad => 320,
            Syscall::Bpf => 321,
            Syscall::Userfaultfd => 323,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Syscall {
    /// Numero de la llamada en esta arquitectura.
    pub fn number(self) -> u32 {
        match self {
            Syscall::Umount2 => 39,
            Syscall::Mount => 40,
            Syscall::PivotRoot => 41,
            Syscall::Chroot => 51,
            Syscall::Capset => 91,
            Syscall::Personality => 92,
            Syscall::Unshare => 97,
            Syscall::KexecLoad => 104,
            Syscall::InitModule => 105,
            Syscall::DeleteModule => 106,
            Syscall::Ptrace => 117,
            Syscall::Setregid => 143,
            Syscall::Setgid => 144,
            Syscall::Setreuid => 145,
            Syscall::Setuid => 146,
            Syscall::Setresuid => 147,
            Syscall::Setresgid => 149,
            Syscall::Socket => 198,
            Syscall::Bind => 200,
            Syscall::Listen => 201,
            Syscall::Accept => 202,
            Syscall::Connect => 203,
            Syscall::Sendto => 206,
            Syscall::Recvfrom => 207,
            Syscall::Sendmsg => 211,
            Syscall::Recvmsg => 212,
            Syscall::AddKey => 217,
            Syscall::RequestKey => 218,
            Syscall::Keyctl => 219,
            Syscall::PerfEventOpen => 241,
            Syscall::Accept4 => 242,
            Syscall::Setns => 268,
            Syscall::ProcessVmReadv => 270,
            Syscall::ProcessVmWritev => 271,
            Syscall::FinitModule => 273,
            Syscall::Bpf => 280,
            Syscall::Userfaultfd => 282,
            Syscall::KexecFileLoad => 294,
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "aegis-sandbox no tiene tabla de llamadas para esta arquitectura. \
     Un filtro de seccomp con numeros equivocados no protege: bloquea una \
     llamada distinta de la que se pretendia y deja pasar la que importaba."
);

/// Llamadas que dan control sobre otro proceso.
pub const CONTROL_DE_PROCESOS: &[Syscall] = &[
    Syscall::Ptrace,
    Syscall::ProcessVmReadv,
    Syscall::ProcessVmWritev,
];

/// Llamadas que tocan el kernel: modulos, kexec, eBPF y trazado.
pub const SUPERFICIE_DE_KERNEL: &[Syscall] = &[
    Syscall::KexecLoad,
    Syscall::KexecFileLoad,
    Syscall::InitModule,
    Syscall::FinitModule,
    Syscall::DeleteModule,
    Syscall::Bpf,
    Syscall::PerfEventOpen,
];

/// Llamadas de red.
pub const RED: &[Syscall] = &[
    Syscall::Socket,
    Syscall::Connect,
    Syscall::Bind,
    Syscall::Listen,
    Syscall::Accept,
    Syscall::Accept4,
    Syscall::Sendto,
    Syscall::Sendmsg,
    Syscall::Recvfrom,
    Syscall::Recvmsg,
];

/// Llamadas que cambian privilegios o el espacio de nombres.
pub const CAMBIO_DE_PRIVILEGIOS: &[Syscall] = &[
    Syscall::Setuid,
    Syscall::Setgid,
    Syscall::Setreuid,
    Syscall::Setregid,
    Syscall::Setresuid,
    Syscall::Setresgid,
    Syscall::Capset,
    Syscall::Unshare,
    Syscall::Setns,
    Syscall::Mount,
    Syscall::Umount2,
    Syscall::PivotRoot,
    Syscall::Chroot,
];

// ─── Todas las llamadas, por nombre (FASE 93) ─────────────────────────────────
//
// El enumerado de arriba nombra las llamadas que una POLITICA escrita a mano
// prohibe. Un perfil APRENDIDO, en cambio, habla de cualquiera de las
// cuatrocientas que un proceso puede usar, y el analista tiene que poder leerlo:
// «este servicio usa `openat`, `read`, `epoll_wait`…», no «usa 257, 0, 232».
// La tabla sale de la cabecera del kernel (ver `tabla_x86_64.rs`).

#[cfg(target_arch = "x86_64")]
use crate::tabla_x86_64::LLAMADAS;
#[cfg(not(target_arch = "x86_64"))]
const LLAMADAS: &[(u32, &str)] = &[];

/// El nombre de una llamada por su numero, si esta arquitectura tiene tabla.
#[must_use]
pub fn nombre(nr: u32) -> Option<&'static str> {
    LLAMADAS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| LLAMADAS[i].1)
}

/// El numero de una llamada por su nombre.
#[must_use]
pub fn numero(nombre: &str) -> Option<u32> {
    LLAMADAS
        .iter()
        .find(|(_, n)| *n == nombre)
        .map(|(nr, _)| *nr)
}

/// Todas las llamadas que conoce la tabla de esta arquitectura.
#[must_use]
pub fn todas() -> &'static [(u32, &'static str)] {
    LLAMADAS
}

#[cfg(all(test, target_arch = "x86_64"))]
mod pruebas_tabla {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    #[test]
    fn la_tabla_esta_ordenada_y_sin_repetidos() {
        for w in LLAMADAS.windows(2) {
            assert!(w[0].0 < w[1].0, "{:?} {:?}", w[0], w[1]);
        }
        assert!(LLAMADAS.len() > 300);
    }

    /// La tabla y el enumerado escrito a mano tienen que decir lo mismo: si no,
    /// uno de los dos esta mal, y el que este mal confina la llamada que no es.
    #[test]
    fn el_enumerado_y_la_tabla_generada_coinciden() {
        use Syscall::*;
        for (s, n) in [
            (Ptrace, "ptrace"),
            (ProcessVmReadv, "process_vm_readv"),
            (ProcessVmWritev, "process_vm_writev"),
            (KexecLoad, "kexec_load"),
            (KexecFileLoad, "kexec_file_load"),
            (InitModule, "init_module"),
            (FinitModule, "finit_module"),
            (DeleteModule, "delete_module"),
            (Bpf, "bpf"),
            (PerfEventOpen, "perf_event_open"),
            (Socket, "socket"),
            (Connect, "connect"),
            (Bind, "bind"),
            (Listen, "listen"),
            (Accept, "accept"),
            (Accept4, "accept4"),
            (Sendto, "sendto"),
            (Sendmsg, "sendmsg"),
            (Recvfrom, "recvfrom"),
            (Recvmsg, "recvmsg"),
            (Mount, "mount"),
            (Umount2, "umount2"),
            (PivotRoot, "pivot_root"),
            (Chroot, "chroot"),
            (Setuid, "setuid"),
            (Setgid, "setgid"),
            (Setreuid, "setreuid"),
            (Setregid, "setregid"),
            (Setresuid, "setresuid"),
            (Setresgid, "setresgid"),
            (Capset, "capset"),
            (Unshare, "unshare"),
            (Setns, "setns"),
            (Personality, "personality"),
            (Userfaultfd, "userfaultfd"),
            (Keyctl, "keyctl"),
            (AddKey, "add_key"),
            (RequestKey, "request_key"),
        ] {
            assert_eq!(numero(n), Some(s.number()), "{n}");
            assert_eq!(nombre(s.number()), Some(n));
        }
    }

    /// Y contra la cabecera del kernel de ESTA maquina, cuando la hay.
    #[test]
    fn la_tabla_casa_con_la_cabecera_del_kernel() {
        let ruta = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";
        let Ok(texto) = std::fs::read_to_string(ruta) else {
            omitir(
                &format!("{ruta} no existe en esta maquina"),
                Requisito::Herramienta("linux-libc-dev"),
            );
            return;
        };
        let mut vistas = 0;
        for l in texto.lines() {
            let mut p = l.split_whitespace();
            if p.next() != Some("#define") {
                continue;
            }
            let (Some(n), Some(v)) = (p.next(), p.next()) else {
                continue;
            };
            let (Some(n), Ok(v)) = (n.strip_prefix("__NR_"), v.parse::<u32>()) else {
                continue;
            };
            assert_eq!(numero(n), Some(v), "{n} = {v} en la cabecera");
            vistas += 1;
        }
        assert_eq!(
            vistas,
            LLAMADAS.len(),
            "la tabla y la cabecera no tienen las mismas llamadas"
        );
    }
}
