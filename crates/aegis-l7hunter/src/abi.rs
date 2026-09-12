//! El contrato de cable con el programa eBPF.
//!
//! El ring buffer del kernel entrega bytes crudos. Este modulo reproduce en
//! Rust, campo a campo, la `struct aegis_l7_evento` que define
//! `drivers/linux/aegis-bpf/include/aegis_sslsniff.h`, y **fija su layout con
//! aserciones de compilacion**.
//!
//! # Por que no basta con "escribirlo igual"
//!
//! Si el struct de C y el de Rust divergieran en un solo byte de relleno, el
//! analizador leeria el `pid` donde hay una longitud y la carga util donde hay
//! una marca de tiempo. Eso **no rompe la compilacion ni la carga del programa**:
//! produce un EDR que ve basura y por tanto no detecta nada, que es el peor fallo
//! posible porque parece que funciona.
//!
//! Las aserciones `const` de aqui fijan lo que Rust calcula, y las de la cabecera
//! fijan lo que calcula C. Lo que ninguna de las dos puede ver es a la otra: eso
//! lo cierra `tools/abi-check-l7.sh`, que compila una sonda en C y otra en Rust y
//! compara sus salidas con un `diff`. Es el mismo criterio que el ABI principal
//! del producto (`tools/abi-check.sh`), y por el mismo motivo.

/// Bytes de carga util que viajan por evento. Espejo de `AEGIS_L7_CARGA_MAX`.
pub const CARGA_MAX: usize = 1024;

/// Longitud del nombre de proceso. Espejo de `AEGIS_L7_COMM_MAX`.
pub const COMM_MAX: usize = 16;

/// Direccion del trafico respecto al proceso observado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direccion {
    /// El proceso ENVIA: capturado en la entrada de `SSL_write`, en claro.
    Saliente,
    /// El proceso RECIBE: capturado en el retorno de `SSL_read`, ya descifrado.
    Entrante,
}

impl Direccion {
    /// Traduce el valor de cable.
    ///
    /// Un valor desconocido se trata como saliente y se DECLARA en el nombre de
    /// la funcion: es preferible clasificar de mas —el analisis lo descartara si
    /// no encaja— que perder un mensaje porque el programa eBPF de un despliegue
    /// mas nuevo use un valor que esta version no conoce.
    #[must_use]
    pub const fn desde_cable_o_saliente(v: u32) -> Direccion {
        match v {
            1 => Direccion::Entrante,
            _ => Direccion::Saliente,
        }
    }

    /// El valor de cable.
    #[must_use]
    pub const fn a_cable(self) -> u32 {
        match self {
            Direccion::Saliente => 0,
            Direccion::Entrante => 1,
        }
    }
}

/// Un evento L7 en claro, tal y como lo escribe el programa eBPF.
///
/// `repr(C)` y el orden de campos son parte del contrato, no una preferencia de
/// estilo: cambiar cualquiera de los dos rompe la lectura del ring.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventoL7Crudo {
    /// Marca monotona del kernel.
    pub tiempo_ns: u64,
    /// Instante de arranque de la tarea (la otra mitad de la identidad estable).
    pub inicio_tarea_ns: u64,
    /// Bytes REALES de la operacion, aunque la carga venga recortada.
    pub longitud_total: u64,
    /// PID.
    pub pid: u32,
    /// TID.
    pub tid: u32,
    /// Direccion, en su valor de cable.
    pub direccion: u32,
    /// Bytes utiles en `carga`.
    pub carga_len: u32,
    /// Nombre del proceso.
    pub comm: [u8; COMM_MAX],
    /// El texto en claro.
    pub carga: [u8; CARGA_MAX],
}

// --- Contrato de ABI, fijado en COMPILACION --------------------------------
const _: () = {
    assert!(std::mem::size_of::<EventoL7Crudo>() == 1080);
    assert!(std::mem::align_of::<EventoL7Crudo>() == 8);
    assert!(std::mem::offset_of!(EventoL7Crudo, tiempo_ns) == 0);
    assert!(std::mem::offset_of!(EventoL7Crudo, inicio_tarea_ns) == 8);
    assert!(std::mem::offset_of!(EventoL7Crudo, longitud_total) == 16);
    assert!(std::mem::offset_of!(EventoL7Crudo, pid) == 24);
    assert!(std::mem::offset_of!(EventoL7Crudo, tid) == 28);
    assert!(std::mem::offset_of!(EventoL7Crudo, direccion) == 32);
    assert!(std::mem::offset_of!(EventoL7Crudo, carga_len) == 36);
    assert!(std::mem::offset_of!(EventoL7Crudo, comm) == 40);
    assert!(std::mem::offset_of!(EventoL7Crudo, carga) == 56);
};

/// Un evento ya validado y listo para analizar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventoL7 {
    /// Marca monotona del kernel, en nanosegundos.
    pub tiempo_ns: u64,
    /// Identidad estable del proceso: `(pid, instante de arranque)`.
    pub inicio_tarea_ns: u64,
    /// Bytes reales de la operacion.
    pub longitud_total: u64,
    /// PID.
    pub pid: u32,
    /// TID.
    pub tid: u32,
    /// Direccion.
    pub direccion: Direccion,
    /// Nombre del proceso.
    pub comm: String,
    /// El texto en claro, ya recortado a los bytes utiles.
    pub carga: Vec<u8>,
}

/// Motivo por el que un registro del ring se descarta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CrudoInvalido {
    /// El registro no llega al tamano del evento.
    #[error("el registro mide {0} B; el evento son 1080 B")]
    Corto(usize),
    /// `carga_len` declara mas bytes de los que caben.
    #[error("carga_len = {0} excede el maximo de {CARGA_MAX}")]
    CargaDesmesurada(u32),
}

impl EventoL7 {
    /// Valida y decodifica un registro crudo del ring buffer.
    ///
    /// # Por que se valida `carga_len` si lo escribe nuestro propio programa
    ///
    /// Porque el ring es memoria compartida con el kernel y este codigo es el
    /// borde de confianza del espacio de usuario. Confiar en una longitud que
    /// viene de fuera y usarla para cortar un `slice` es, literalmente, la forma
    /// canonica de leer fuera de rango. Que hoy el escritor sea codigo propio no
    /// es una garantia estructural: manana el programa eBPF lo carga otro
    /// componente, o alguien cambia la constante en un solo lado.
    ///
    /// # Errores
    /// [`CrudoInvalido`] si el registro es corto o su `carga_len` es imposible.
    pub fn desde_crudo(bytes: &[u8]) -> Result<EventoL7, CrudoInvalido> {
        let tam = std::mem::size_of::<EventoL7Crudo>();
        if bytes.len() < tam {
            return Err(CrudoInvalido::Corto(bytes.len()));
        }
        let leer_u64 = |o: usize| u64::from_ne_bytes(bytes[o..o + 8].try_into().expect("acotado"));
        let leer_u32 = |o: usize| u32::from_ne_bytes(bytes[o..o + 4].try_into().expect("acotado"));

        let carga_len = leer_u32(36);
        if carga_len as usize > CARGA_MAX {
            return Err(CrudoInvalido::CargaDesmesurada(carga_len));
        }
        let inicio_carga = 56;
        let carga = bytes[inicio_carga..inicio_carga + carga_len as usize].to_vec();

        // `comm` del kernel es un array de 16 bytes terminado en cero si sobra
        // sitio; si el nombre ocupa los 16, NO lleva terminador.
        let comm_bytes = &bytes[40..40 + COMM_MAX];
        let fin = comm_bytes.iter().position(|b| *b == 0).unwrap_or(COMM_MAX);
        let comm = String::from_utf8_lossy(&comm_bytes[..fin]).into_owned();

        Ok(EventoL7 {
            tiempo_ns: leer_u64(0),
            inicio_tarea_ns: leer_u64(8),
            longitud_total: leer_u64(16),
            pid: leer_u32(24),
            tid: leer_u32(28),
            direccion: Direccion::desde_cable_o_saliente(leer_u32(32)),
            carga,
            comm,
        })
    }

    /// `true` si la carga venia recortada respecto a la operacion real.
    #[must_use]
    pub fn recortado(&self) -> bool {
        (self.carga.len() as u64) < self.longitud_total
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un registro crudo como lo escribiria el kernel.
    fn crudo(carga: &[u8], comm: &str, total: u64) -> Vec<u8> {
        let mut b = vec![0u8; std::mem::size_of::<EventoL7Crudo>()];
        b[0..8].copy_from_slice(&1_234_567_890u64.to_ne_bytes());
        b[8..16].copy_from_slice(&42u64.to_ne_bytes());
        b[16..24].copy_from_slice(&total.to_ne_bytes());
        b[24..28].copy_from_slice(&999u32.to_ne_bytes());
        b[28..32].copy_from_slice(&1000u32.to_ne_bytes());
        b[32..36].copy_from_slice(&1u32.to_ne_bytes());
        b[36..40].copy_from_slice(&(carga.len() as u32).to_ne_bytes());
        let n = comm.len().min(COMM_MAX);
        b[40..40 + n].copy_from_slice(&comm.as_bytes()[..n]);
        b[56..56 + carga.len()].copy_from_slice(carga);
        b
    }

    #[test]
    fn un_registro_del_ring_se_decodifica_entero() {
        let ev = EventoL7::desde_crudo(&crudo(b"GET / HTTP/1.1\r\n", "curl", 16)).expect("valido");
        assert_eq!(ev.tiempo_ns, 1_234_567_890);
        assert_eq!(ev.inicio_tarea_ns, 42);
        assert_eq!(ev.pid, 999);
        assert_eq!(ev.tid, 1000);
        assert_eq!(ev.direccion, Direccion::Entrante);
        assert_eq!(ev.comm, "curl");
        assert_eq!(ev.carga, b"GET / HTTP/1.1\r\n");
        assert!(!ev.recortado());
    }

    #[test]
    fn un_registro_corto_se_rechaza_en_vez_de_leer_fuera_de_rango() {
        for n in [0usize, 1, 55, 1079] {
            assert_eq!(
                EventoL7::desde_crudo(&vec![0u8; n]),
                Err(CrudoInvalido::Corto(n))
            );
        }
    }

    /// EL CASO QUE JUSTIFICA LA VALIDACION. Una longitud imposible en el registro
    /// no puede convertirse en una lectura fuera de rango: este codigo es el
    /// borde de confianza entre el kernel y el espacio de usuario.
    #[test]
    fn una_longitud_imposible_no_puede_provocar_una_lectura_fuera_de_rango() {
        let mut b = crudo(b"hola", "x", 4);
        b[36..40].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(
            EventoL7::desde_crudo(&b),
            Err(CrudoInvalido::CargaDesmesurada(u32::MAX))
        );
        // Y justo una por encima del maximo, que es donde fallan estas cosas.
        b[36..40].copy_from_slice(&((CARGA_MAX + 1) as u32).to_ne_bytes());
        assert!(EventoL7::desde_crudo(&b).is_err());
        // El maximo exacto SI es valido.
        b[36..40].copy_from_slice(&(CARGA_MAX as u32).to_ne_bytes());
        assert!(EventoL7::desde_crudo(&b).is_ok());
    }

    #[test]
    fn un_comm_que_ocupa_los_dieciseis_bytes_no_pierde_el_ultimo() {
        // El kernel NO pone terminador cuando el nombre llena el array.
        let mut b = crudo(b"x", "0123456789abcdef", 1);
        b[40..56].copy_from_slice(b"0123456789abcdef");
        let ev = EventoL7::desde_crudo(&b).expect("valido");
        assert_eq!(ev.comm, "0123456789abcdef");
    }

    #[test]
    fn un_recorte_se_declara_en_vez_de_mentir_sobre_el_volumen() {
        // 1 KiB de carga pero 1 MiB de operacion real: la matematica de volumen
        // tiene que usar el total, no lo que cupo en el evento.
        let ev =
            EventoL7::desde_crudo(&crudo(&[b'A'; CARGA_MAX], "curl", 1_048_576)).expect("valido");
        assert!(ev.recortado());
        assert_eq!(ev.longitud_total, 1_048_576);
        assert_eq!(ev.carga.len(), CARGA_MAX);
    }

    #[test]
    fn la_direccion_desconocida_no_pierde_el_mensaje() {
        assert_eq!(Direccion::desde_cable_o_saliente(0), Direccion::Saliente);
        assert_eq!(Direccion::desde_cable_o_saliente(1), Direccion::Entrante);
        // Un valor de una version mas nueva del programa eBPF: se clasifica de
        // mas, no se descarta.
        assert_eq!(Direccion::desde_cable_o_saliente(7), Direccion::Saliente);
        assert_eq!(Direccion::Entrante.a_cable(), 1);
    }
}
