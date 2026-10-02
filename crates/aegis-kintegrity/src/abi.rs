//! Espejo en Rust del contrato de `aegis_kintegrity.h`.
//!
//! La disposicion en memoria es parte del contrato: el programa eBPF lee la
//! peticion de un mapa y devuelve la respuesta con estas mismas estructuras. Un
//! campo desplazado no da un error de compilacion, da veredictos de rootkit
//! sobre procesos inocentes, asi que los tamanos y desplazamientos se
//! comprueban en tiempo de COMPILACION aqui y se cotejan contra el compilador
//! de C en `tools/abi-check.sh`.
//!
//! La conversion a bytes y desde bytes se hace campo a campo, sin `unsafe`: la
//! respuesta del iterador llega como bytes de un `read()`, y decodificarla con
//! desplazamientos explicitos es lo que permite probarla sin kernel.

use crate::error::KiError;

/// Longitud de `comm` en el kernel, incluido el terminador.
pub const COMM_LEN: usize = 16;

/// Capacidad de los mapas de vista: tareas vivas, no numeros de PID.
pub const MAX_TAREAS: u32 = 65_536;

/// PID que abarca, como mucho, una invocacion del barrido: un tramo.
///
/// El espacio entero (`pid_max`, hasta 4194304) se cubre en varias lecturas
/// del iterador; ver [`crate::tramos`]. Una peticion mayor vuelve con
/// [`ERR_ARGS`], nunca recortada.
pub const MAX_BARRIDO: u32 = 65_536;

/// `bpf_iter_task_new`: solo lideres de grupo de hilos.
pub const ITER_SOLO_PROCESOS: u32 = 0;
/// `bpf_iter_task_new`: todas las tareas, hilos incluidos.
pub const ITER_TODOS_LOS_HILOS: u32 = 1;

/// Peticion invalida: tramo vacio, con negativos o de mas de [`MAX_BARRIDO`]
/// PID.
pub const ERR_ARGS: i32 = -1;
/// El iterador de tareas no se pudo crear.
pub const ERR_ITERADOR: i32 = -2;

/// Retrato de una tarea vista por el kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KiTask {
    /// Nanosegundos monotonos desde el arranque del sistema.
    pub start_boottime: u64,
    /// Grupo de hilos: el PID en terminologia de espacio de usuario.
    pub tgid: u32,
    /// Generacion del barrido que escribio la entrada.
    pub gen: u32,
    /// Reservado.
    pub flags: u32,
    /// Nombre corto de la tarea, terminado en NUL.
    pub comm: [u8; COMM_LEN],
    /// Relleno explicito.
    pub _pad: u32,
}

impl KiTask {
    /// Nombre corto como texto, sin el terminador.
    ///
    /// El kernel garantiza que `comm` es imprimible, pero no que sea UTF-8
    /// valido en todos los casos; se sustituye lo invalido en vez de fallar,
    /// porque el nombre es contexto para el analista, no una clave.
    pub fn comm_str(&self) -> String {
        let fin = self.comm.iter().position(|b| *b == 0).unwrap_or(COMM_LEN);
        String::from_utf8_lossy(&self.comm[..fin]).into_owned()
    }
}

/// Argumentos y resultados del barrido de UN tramo.
///
/// `[primero, ultimo]` delimita las dos vistas: C sondea esos PID y B guarda
/// solo las tareas cuyo PID cae ahi.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KiArgs {
    /// Primer PID del tramo.
    pub primero: i32,
    /// Ultimo PID del tramo, inclusive.
    pub ultimo: i32,
    /// Generacion; descarta entradas de barridos anteriores.
    pub gen: u32,
    /// Tareas vistas en la lista de tareas.
    pub en_lista: u32,
    /// Tareas halladas en el espacio de PID.
    pub en_pidmap: u32,
    /// Entradas que no cupieron en los mapas.
    pub desbordes: u32,
    /// 0, o uno de los `ERR_*`.
    pub error: i32,
    /// Relleno explicito.
    pub _pad: u32,
}

/// Confirmacion de un solo TID por los dos caminos.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KiConfirm {
    /// TID a confirmar. En la respuesta, negativo es uno de los `ERR_*`.
    pub tid: i32,
    /// 1 si aparece en la lista de tareas.
    pub en_lista: u32,
    /// 1 si aparece en el espacio de PID.
    pub en_pidmap: u32,
    /// Grupo de hilos, si se pudo leer.
    pub tgid: u32,
    /// Instante de arranque, si se pudo leer.
    pub start_boottime: u64,
}

// Comprobaciones de disposicion. Si alguna falla, el programa eBPF y este
// espejo han divergido y la deteccion estaria leyendo campos equivocados.
const _: () = {
    use std::mem::{align_of, size_of};

    assert!(size_of::<KiTask>() == 40);
    assert!(align_of::<KiTask>() == 8);
    assert!(size_of::<KiArgs>() == 32);
    assert!(align_of::<KiArgs>() == 4);
    assert!(size_of::<KiConfirm>() == 24);
    assert!(align_of::<KiConfirm>() == 8);
};

/// Desplazamientos declarados, para que `tools/abi-check.sh` los coteje contra
/// los que calcula el compilador de C sobre la misma cabecera.
pub const OFFSETS: [(&str, &str, usize); 12] = [
    ("aegis_ki_task", "start_boottime", 0),
    ("aegis_ki_task", "tgid", 8),
    ("aegis_ki_task", "gen", 12),
    ("aegis_ki_task", "flags", 16),
    ("aegis_ki_task", "comm", 20),
    ("aegis_ki_args", "primero", 0),
    ("aegis_ki_args", "ultimo", 4),
    ("aegis_ki_args", "gen", 8),
    ("aegis_ki_args", "en_lista", 12),
    ("aegis_ki_confirm", "tid", 0),
    ("aegis_ki_confirm", "tgid", 12),
    ("aegis_ki_confirm", "start_boottime", 16),
];

fn u32_en(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn i32_en(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_en(b: &[u8], o: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[o..o + 8]);
    u64::from_ne_bytes(x)
}

/// Lo que llego del iterador no es una respuesta utilizable.
fn respuesta_rota(op: &'static str, detalle: String) -> KiError {
    KiError::Bpf {
        op,
        detail: detalle,
    }
}

impl KiArgs {
    /// Tamano en bytes, el mismo que ve el programa eBPF.
    pub const TAM: usize = 32;

    /// Los bytes tal y como los lee el programa eBPF (orden nativo).
    pub fn a_bytes(&self) -> [u8; Self::TAM] {
        let mut b = [0u8; Self::TAM];
        b[0..4].copy_from_slice(&self.primero.to_ne_bytes());
        b[4..8].copy_from_slice(&self.ultimo.to_ne_bytes());
        b[8..12].copy_from_slice(&self.gen.to_ne_bytes());
        b[12..16].copy_from_slice(&self.en_lista.to_ne_bytes());
        b[16..20].copy_from_slice(&self.en_pidmap.to_ne_bytes());
        b[20..24].copy_from_slice(&self.desbordes.to_ne_bytes());
        b[24..28].copy_from_slice(&self.error.to_ne_bytes());
        b[28..32].copy_from_slice(&self._pad.to_ne_bytes());
        b
    }

    /// La estructura desde sus bytes, o `None` si no miden lo que deben.
    pub fn desde_bytes(b: &[u8]) -> Option<KiArgs> {
        if b.len() != Self::TAM {
            return None;
        }
        Some(KiArgs {
            primero: i32_en(b, 0),
            ultimo: i32_en(b, 4),
            gen: u32_en(b, 8),
            en_lista: u32_en(b, 12),
            en_pidmap: u32_en(b, 16),
            desbordes: u32_en(b, 20),
            error: i32_en(b, 24),
            _pad: u32_en(b, 28),
        })
    }

    /// Interpreta lo leido del iterador del barrido.
    ///
    /// Exige una respuesta completa, sin error y de la generacion pedida: una
    /// respuesta de otra generacion diria que los mapas se leen contra un
    /// barrido que no es el que se acaba de hacer.
    pub fn respuesta(b: &[u8], gen: u32) -> Result<KiArgs, KiError> {
        if b.is_empty() {
            return Err(respuesta_rota(
                "respuesta del barrido",
                "el programa no respondio: el iterador no visito la tarea ancla".into(),
            ));
        }
        let r = KiArgs::desde_bytes(b).ok_or_else(|| {
            respuesta_rota(
                "respuesta del barrido",
                format!("{} bytes y se esperaban {}", b.len(), Self::TAM),
            )
        })?;
        if r.error != 0 {
            return Err(KiError::Programa(r.error));
        }
        if r.gen != gen {
            return Err(respuesta_rota(
                "respuesta del barrido",
                format!("generacion {} y se pidio la {gen}", r.gen),
            ));
        }
        Ok(r)
    }
}

impl KiConfirm {
    /// Tamano en bytes, el mismo que ve el programa eBPF.
    pub const TAM: usize = 24;

    /// Los bytes tal y como los lee el programa eBPF (orden nativo).
    pub fn a_bytes(&self) -> [u8; Self::TAM] {
        let mut b = [0u8; Self::TAM];
        b[0..4].copy_from_slice(&self.tid.to_ne_bytes());
        b[4..8].copy_from_slice(&self.en_lista.to_ne_bytes());
        b[8..12].copy_from_slice(&self.en_pidmap.to_ne_bytes());
        b[12..16].copy_from_slice(&self.tgid.to_ne_bytes());
        b[16..24].copy_from_slice(&self.start_boottime.to_ne_bytes());
        b
    }

    /// La estructura desde sus bytes, o `None` si no miden lo que deben.
    pub fn desde_bytes(b: &[u8]) -> Option<KiConfirm> {
        if b.len() != Self::TAM {
            return None;
        }
        Some(KiConfirm {
            tid: i32_en(b, 0),
            en_lista: u32_en(b, 4),
            en_pidmap: u32_en(b, 8),
            tgid: u32_en(b, 12),
            start_boottime: u64_en(b, 16),
        })
    }

    /// Interpreta lo leido del iterador de la confirmacion.
    ///
    /// El `tid` vuelve tal cual; negativo es un `ERR_*`, y otro distinto del
    /// pedido es una respuesta que no corresponde a esta pregunta.
    pub fn respuesta(b: &[u8], tid: i32) -> Result<KiConfirm, KiError> {
        if b.is_empty() {
            return Err(respuesta_rota(
                "respuesta de la confirmacion",
                "el programa no respondio: el iterador no visito la tarea ancla".into(),
            ));
        }
        let r = KiConfirm::desde_bytes(b).ok_or_else(|| {
            respuesta_rota(
                "respuesta de la confirmacion",
                format!("{} bytes y se esperaban {}", b.len(), Self::TAM),
            )
        })?;
        if r.tid < 0 {
            return Err(KiError::Programa(r.tid));
        }
        if r.tid != tid {
            return Err(respuesta_rota(
                "respuesta de la confirmacion",
                format!("responde por el tid {} y se pregunto por el {tid}", r.tid),
            ));
        }
        Ok(r)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn desplazamiento(estructura: &str, campo: &str) -> usize {
        OFFSETS
            .iter()
            .find(|(s, c, _)| *s == estructura && *c == campo)
            .map(|(_, _, o)| *o)
            .expect("campo declarado en OFFSETS")
    }

    #[test]
    fn los_bytes_del_barrido_van_y_vuelven() {
        let a = KiArgs {
            primero: 1,
            ultimo: 4_194_304,
            gen: 0xA1B2_C3D4,
            en_lista: 7,
            en_pidmap: 8,
            desbordes: 9,
            error: ERR_ITERADOR,
            _pad: 0,
        };
        assert_eq!(KiArgs::desde_bytes(&a.a_bytes()), Some(a));
        assert_eq!(KiArgs::TAM, std::mem::size_of::<KiArgs>());
    }

    #[test]
    fn los_bytes_de_la_confirmacion_van_y_vuelven() {
        let c = KiConfirm {
            tid: 4321,
            en_lista: 1,
            en_pidmap: 0,
            tgid: 4320,
            start_boottime: 0x0102_0304_0506_0708,
        };
        assert_eq!(KiConfirm::desde_bytes(&c.a_bytes()), Some(c));
        assert_eq!(KiConfirm::TAM, std::mem::size_of::<KiConfirm>());
    }

    #[test]
    fn la_codificacion_respeta_los_desplazamientos_declarados() {
        // Si `a_bytes` escribiera un campo en otro sitio, el programa eBPF lo
        // leeria de donde dice la cabecera de C y no de donde se escribio.
        let a = KiArgs {
            gen: 0xDEAD_BEEF,
            en_lista: 0x0BAD_F00D,
            ultimo: 0x1234_5678,
            ..Default::default()
        };
        let b = a.a_bytes();
        let o = desplazamiento("aegis_ki_args", "gen");
        assert_eq!(&b[o..o + 4], &0xDEAD_BEEFu32.to_ne_bytes());
        let o = desplazamiento("aegis_ki_args", "en_lista");
        assert_eq!(&b[o..o + 4], &0x0BAD_F00Du32.to_ne_bytes());
        let o = desplazamiento("aegis_ki_args", "ultimo");
        assert_eq!(&b[o..o + 4], &0x1234_5678i32.to_ne_bytes());

        let c = KiConfirm {
            tgid: 0x0A0B_0C0D,
            start_boottime: u64::MAX - 1,
            ..Default::default()
        };
        let b = c.a_bytes();
        let o = desplazamiento("aegis_ki_confirm", "tgid");
        assert_eq!(&b[o..o + 4], &0x0A0B_0C0Du32.to_ne_bytes());
        let o = desplazamiento("aegis_ki_confirm", "start_boottime");
        assert_eq!(&b[o..o + 8], &(u64::MAX - 1).to_ne_bytes());
    }

    #[test]
    fn una_respuesta_de_barrido_solo_vale_completa_sin_error_y_de_su_generacion() {
        let buena = KiArgs {
            gen: 5,
            en_lista: 100,
            en_pidmap: 100,
            ..Default::default()
        };
        assert_eq!(KiArgs::respuesta(&buena.a_bytes(), 5).unwrap(), buena);

        // Vacia: el programa no llego a trabajar. Nunca es «cero tareas».
        let e = KiArgs::respuesta(&[], 5).unwrap_err();
        assert!(e.to_string().contains("no respondio"), "{e}");

        // Truncada o con cola: el transporte se rompio.
        assert!(KiArgs::respuesta(&buena.a_bytes()[..31], 5).is_err());
        let mut larga = buena.a_bytes().to_vec();
        larga.extend_from_slice(&[0; 4]);
        assert!(KiArgs::respuesta(&larga, 5).is_err());

        // De otra generacion.
        let e = KiArgs::respuesta(&buena.a_bytes(), 6).unwrap_err();
        assert!(e.to_string().contains("generacion"), "{e}");

        // Con error del programa.
        let mala = KiArgs {
            error: ERR_ITERADOR,
            ..buena
        };
        assert!(matches!(
            KiArgs::respuesta(&mala.a_bytes(), 5),
            Err(KiError::Programa(ERR_ITERADOR))
        ));
    }

    #[test]
    fn una_respuesta_de_confirmacion_responde_por_el_tid_pedido() {
        let buena = KiConfirm {
            tid: 77,
            en_lista: 1,
            en_pidmap: 1,
            tgid: 70,
            start_boottime: 123,
        };
        assert_eq!(KiConfirm::respuesta(&buena.a_bytes(), 77).unwrap(), buena);
        assert!(KiConfirm::respuesta(&[], 77).is_err());
        assert!(KiConfirm::respuesta(&buena.a_bytes()[..16], 77).is_err());
        let e = KiConfirm::respuesta(&buena.a_bytes(), 78).unwrap_err();
        assert!(e.to_string().contains("78"), "{e}");
        let error = KiConfirm {
            tid: ERR_ITERADOR,
            ..Default::default()
        };
        assert!(matches!(
            KiConfirm::respuesta(&error.a_bytes(), 77),
            Err(KiError::Programa(ERR_ITERADOR))
        ));
    }
}
