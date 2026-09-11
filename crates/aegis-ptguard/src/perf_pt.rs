//! ABI de `perf_event_attr` para Intel PT (espejo `repr(C)` del kernel).
//!
//! `libc` no expone `perf_event_attr` —es una estructura grande con uniones y un
//! campo de bits— asi que se declara aqui como espejo exacto del `struct` del
//! kernel (`include/uapi/linux/perf_event.h`). Es codigo portable: la estructura
//! se compila y su tamano se comprueba en cada `make ci`, aunque ABRIR el evento
//! (la fontaneria de [`crate::captura`]) sea imposible sin Intel PT.
//!
//! Un layout mal copiado es un fallo silencioso peligroso: `perf_event_open`
//! valida `size` contra su propia idea del `struct`, y un campo desalineado hace
//! que el kernel lea basura donde espera los flags. Por eso el tamano se asevera.

/// Espejo de `struct perf_event_attr`. Solo se rellenan los campos que Intel PT
/// necesita; el resto va a cero, que es su valor por defecto valido.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfEventAttr {
    /// `PERF_TYPE_*`; para Intel PT es un valor dinamico leido de sysfs.
    pub type_: u32,
    /// `sizeof(perf_event_attr)`: el kernel lo usa para versionar la ABI.
    pub size: u32,
    /// Configuracion del evento (bits de Intel PT: ToPA, branch, etc.).
    pub config: u64,
    /// Union sample_period / sample_freq.
    pub sample_period_o_freq: u64,
    /// `PERF_SAMPLE_*`.
    pub sample_type: u64,
    /// `PERF_FORMAT_*`.
    pub read_format: u64,
    /// Campo de bits: disabled, inherit, exclude_kernel, exclude_hv, etc.
    pub flags: u64,
    /// Union wakeup_events / wakeup_watermark.
    pub wakeup: u32,
    /// Tipo de breakpoint (no usado por PT).
    pub bp_type: u32,
    /// Union bp_addr / config1.
    pub config1: u64,
    /// Union bp_len / config2.
    pub config2: u64,
    /// `PERF_SAMPLE_BRANCH_*`.
    pub branch_sample_type: u64,
    /// Registros de usuario a muestrear.
    pub sample_regs_user: u64,
    /// Tamano de pila de usuario a muestrear.
    pub sample_stack_user: u32,
    /// Reloj.
    pub clockid: i32,
    /// Registros a muestrear en la interrupcion.
    pub sample_regs_intr: u64,
    /// Marca de agua del area AUX: cuando despertar al consumidor.
    pub aux_watermark: u32,
    /// Profundidad maxima de pila muestreada.
    pub sample_max_stack: u16,
    /// Reservado.
    pub reservado_2: u16,
    /// Tamano de muestra del area AUX.
    pub aux_sample_size: u32,
    /// Reservado.
    pub reservado_3: u32,
    /// `sig_data`: dato que acompana a las senales de eventos (anadido en
    /// `PERF_ATTR_SIZE_VER7`). Sin este campo el espejo se quedaba en 120 bytes
    /// —una version de ABI anterior— y el kernel leeria basura donde espera el
    /// final del `struct`.
    pub sig_data: u64,
}

/// `disabled`: el evento arranca parado; se habilita con un ioctl.
pub const ATTR_DISABLED: u64 = 1 << 0;
/// `exclude_kernel`: no trazar codigo de kernel (ni hace falta, ni se quiere el
/// privilegio que exigiria).
pub const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
/// `exclude_hv`: no trazar el hipervisor.
pub const ATTR_EXCLUDE_HV: u64 = 1 << 6;

impl PerfEventAttr {
    /// Una `attr` de Intel PT lista para `perf_event_open`: parada, sin kernel ni
    /// hipervisor, con `size` fijado.
    pub fn intel_pt(tipo: u32) -> PerfEventAttr {
        PerfEventAttr {
            type_: tipo,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_tamano_coincide_con_la_abi_del_kernel() {
        // El kernel define perf_event_attr en 128 bytes desde 4.x. Un cambio de
        // tamano aqui significa que el layout se desalineo.
        assert_eq!(core::mem::size_of::<PerfEventAttr>(), 128);
    }

    #[test]
    fn intel_pt_fija_los_flags_correctos() {
        let a = PerfEventAttr::intel_pt(8);
        assert_eq!(a.type_, 8);
        assert_eq!(a.size, 128);
        assert!(a.flags & ATTR_DISABLED != 0);
        assert!(a.flags & ATTR_EXCLUDE_KERNEL != 0);
    }
}
