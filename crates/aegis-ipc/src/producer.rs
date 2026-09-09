//! Lado productor del ring buffer SPSC.
//!
//! # Que es esto y que no es
//!
//! En produccion, quien escribe el ring es el driver en Ring 0. Este productor
//! es el mismo protocolo escrito para espacio de usuario: lo usan el modelo del
//! driver, los bancos de pruebas de carga y cualquier fuente de telemetria que
//! no viva en el kernel (por ejemplo un colector que reinyecta eventos).
//!
//! Reproduce las tres reglas que hacen correcto el protocolo, y de las que
//! depende que el consumidor nunca lea basura:
//!
//! 1. **Nunca se pisan datos sin leer.** Antes de escribir se compara contra el
//!    cursor del consumidor; si no hay hueco, se incrementa `dropped_events` y
//!    el evento se pierde. Perder un evento es un punto ciego; sobrescribir uno
//!    sin leer es corromper el flujo, que es mucho peor.
//! 2. **Los registros no cruzan el final del buffer.** Si el registro no cabe
//!    en el tramo contiguo hasta el final, se rellena ese tramo con un registro
//!    de relleno y se envuelve. El consumidor salta el relleno sin entregarlo.
//! 3. **El registro se publica DESPUES de escribirse entero,** con un
//!    release-store del cursor de escritura que ordena la publicacion despues
//!    de todas las escrituras del registro.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{
    AegisEvtHdr, AegisRingCtrl, AEGIS_ABI_VERSION, AEGIS_EVT_MAGIC, AEGIS_RING_MAGIC,
};
use crate::ring::{
    offset_consumer_tail, offset_dropped_bytes, offset_dropped_events, offset_producer_head,
    RingError, RECORD_ALIGN,
};

/// Tipo de registro de relleno hasta el final del buffer.
const EVT_PADDING: u16 = 0xFFFF;

/// Resultado de intentar publicar un evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// El evento se escribio y publico.
    Pushed {
        /// Bytes que ocupo el registro, incluyendo relleno de alineacion.
        record_len: u32,
    },
    /// No habia hueco: el consumidor no drena lo bastante rapido. Se conto en
    /// `dropped_events` y el evento se perdio.
    Dropped,
    /// El evento no cabe en el ring ni con el vacio: es un error de
    /// programacion, no una condicion de carga.
    TooLarge {
        /// Bytes que habria necesitado.
        needed: u32,
        /// Capacidad del ring.
        capacity: u64,
    },
}

impl PushOutcome {
    /// Indica si el evento llego al ring.
    pub fn is_pushed(self) -> bool {
        matches!(self, PushOutcome::Pushed { .. })
    }
}

/// Escritor del ring. Solo puede haber uno por ring (SPSC).
pub struct RingProducer {
    base: *mut u8,
    data: *mut u8,
    capacity: u64,
    mask: u64,
    /// Copia local del cursor de escritura, para no releer memoria compartida.
    head: u64,
    /// Contadores locales, espejo de los del bloque de control.
    dropped_events: u64,
    dropped_bytes: u64,
}

// SAFETY: posee el lado productor y todos sus accesos compartidos son atomicos;
// puede moverse entre hilos mientras solo uno lo use a la vez (lo impone
// `&mut self`).
unsafe impl Send for RingProducer {}

impl RingProducer {
    /// Se adjunta como productor al ring mapeado en `[base, base + len)`.
    ///
    /// # Safety
    ///
    /// - `base` debe apuntar a un mapeo valido y escribible de al menos `len`
    ///   bytes, alineado a 64, vivo mientras exista el productor.
    /// - Nadie mas en el sistema puede actuar como productor del mismo ring.
    pub unsafe fn attach(base: *mut u8, len: usize) -> Result<RingProducer, RingError> {
        if len < core::mem::size_of::<AegisRingCtrl>() {
            return Err(RingError::MappingTooSmall);
        }
        // SAFETY: el llamante garantiza un mapeo valido y alineado; cabe el
        // bloque de control por la comprobacion de arriba.
        let ctrl = unsafe { &*(base as *const AegisRingCtrl) };
        if ctrl.magic != AEGIS_RING_MAGIC {
            return Err(RingError::BadMagic);
        }
        if ctrl.abi_version != u32::from(AEGIS_ABI_VERSION) {
            return Err(RingError::AbiMismatch {
                found: ctrl.abi_version,
            });
        }
        let capacity = ctrl.capacity;
        if capacity == 0 || !capacity.is_power_of_two() || capacity < u64::from(RECORD_ALIGN) {
            return Err(RingError::BadCapacity);
        }
        let data_offset = ctrl.data_offset;
        let end = data_offset
            .checked_add(capacity)
            .ok_or(RingError::DataOutOfBounds)?;
        if data_offset < core::mem::size_of::<AegisRingCtrl>() as u64
            || data_offset % u64::from(RECORD_ALIGN) != 0
            || end > len as u64
        {
            return Err(RingError::DataOutOfBounds);
        }

        // SAFETY: `data_offset + capacity <= len`.
        let data = unsafe { base.add(data_offset as usize) };
        let head = atomic(base, offset_producer_head()).load(Ordering::Relaxed);

        Ok(RingProducer {
            base,
            data,
            capacity,
            mask: capacity - 1,
            head,
            dropped_events: 0,
            dropped_bytes: 0,
        })
    }

    /// Inicializa un bloque de control en un mapeo recien creado.
    ///
    /// Sirve para bancos de pruebas y para el colector de reinyeccion. El driver
    /// del kernel escribe su propio bloque; aqui se ofrece la version de espacio
    /// de usuario, con los mismos invariantes.
    ///
    /// # Safety
    ///
    /// `base` debe apuntar a un mapeo escribible y a cero de al menos
    /// `data_offset + capacity` bytes, alineado a 64. `capacity` debe ser
    /// potencia de dos.
    pub unsafe fn format(
        base: *mut u8,
        len: usize,
        capacity: u64,
        data_offset: u64,
    ) -> Result<(), RingError> {
        if !capacity.is_power_of_two() || capacity < u64::from(RECORD_ALIGN) {
            return Err(RingError::BadCapacity);
        }
        if data_offset < core::mem::size_of::<AegisRingCtrl>() as u64
            || data_offset % u64::from(RECORD_ALIGN) != 0
            || data_offset
                .checked_add(capacity)
                .is_none_or(|e| e > len as u64)
        {
            return Err(RingError::DataOutOfBounds);
        }
        // SAFETY: el llamante garantiza tamano y alineacion.
        let ctrl = unsafe { &mut *(base as *mut AegisRingCtrl) };
        ctrl.magic = AEGIS_RING_MAGIC;
        ctrl.abi_version = u32::from(AEGIS_ABI_VERSION);
        ctrl.capacity = capacity;
        ctrl.data_offset = data_offset;
        Ok(())
    }

    /// Eventos perdidos por ring lleno.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Bytes perdidos por ring lleno.
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    /// Bytes pendientes de que el consumidor drene.
    pub fn backlog_bytes(&self) -> u64 {
        let tail = atomic(self.base, offset_consumer_tail()).load(Ordering::Acquire);
        self.head.saturating_sub(tail)
    }

    /// Publica un evento con su cabecera y cuerpo.
    ///
    /// `body` es todo lo que va tras los 64 bytes de cabecera: la carga fija y
    /// las cadenas. El productor calcula la longitud total alineada a 64.
    pub fn push(&mut self, ty: u16, actor_key: u64, ts_ns: u64, body: &[u8]) -> PushOutcome {
        let content = core::mem::size_of::<AegisEvtHdr>() + body.len();
        let total_len = match align_up(content) {
            Some(v) if u64::from(v) <= self.capacity => v,
            _ => {
                return PushOutcome::TooLarge {
                    needed: content as u32,
                    capacity: self.capacity,
                }
            }
        };

        // Puede hacer falta una vuelta extra: rellenar hasta el final y volver a
        // intentar en el inicio. Como cada relleno avanza `head` hasta un
        // multiplo de la capacidad, el bucle da como mucho dos vueltas.
        for _ in 0..2 {
            let tail = atomic(self.base, offset_consumer_tail()).load(Ordering::Acquire);
            let offset = (self.head & self.mask) as usize;
            let contiguo = self.capacity as usize - offset;

            if contiguo < total_len as usize {
                // Hace falta relleno de `contiguo` bytes y luego el registro.
                let necesario = contiguo as u64 + u64::from(total_len);
                if self.head + necesario - tail > self.capacity {
                    return self.soltar(total_len);
                }
                self.escribir_relleno(offset, contiguo as u32);
                self.head += contiguo as u64;
                self.publicar();
                continue;
            }

            if self.head + u64::from(total_len) - tail > self.capacity {
                return self.soltar(total_len);
            }

            self.escribir(offset, ty, actor_key, ts_ns, total_len, body);
            self.head += u64::from(total_len);
            self.publicar();
            return PushOutcome::Pushed {
                record_len: total_len,
            };
        }

        // Dos vueltas sin escribir solo puede pasar si el registro no cabe, y
        // eso ya se descarto arriba; por seguridad, se cuenta como soltado.
        self.soltar(total_len)
    }

    fn escribir(
        &mut self,
        offset: usize,
        ty: u16,
        actor_key: u64,
        ts_ns: u64,
        total_len: u32,
        body: &[u8],
    ) {
        let hdr = AegisEvtHdr {
            magic: AEGIS_EVT_MAGIC,
            abi_version: AEGIS_ABI_VERSION,
            ty,
            total_len,
            flags: 0,
            seq: self.head,
            ts_ns,
            actor_key,
            target_key: 0,
            cpu: 0,
            verdict_id: 0,
            reserved: 0,
        };
        // SAFETY: el llamante comprobo `offset + total_len <= capacity`, asi que
        // todo el registro cae dentro de la zona de datos. Se pone a cero el
        // relleno de alineacion para no filtrar memoria previa.
        unsafe {
            let dst = self.data.add(offset);
            core::ptr::write_bytes(dst, 0, total_len as usize);
            core::ptr::write(dst as *mut AegisEvtHdr, hdr);
            core::ptr::copy_nonoverlapping(
                body.as_ptr(),
                dst.add(core::mem::size_of::<AegisEvtHdr>()),
                body.len(),
            );
        }
    }

    fn escribir_relleno(&mut self, offset: usize, len: u32) {
        let hdr = AegisEvtHdr {
            magic: AEGIS_EVT_MAGIC,
            abi_version: AEGIS_ABI_VERSION,
            ty: EVT_PADDING,
            total_len: len,
            flags: 0,
            seq: self.head,
            ts_ns: 0,
            actor_key: 0,
            target_key: 0,
            cpu: 0,
            verdict_id: 0,
            reserved: 0,
        };
        // SAFETY: el relleno ocupa exactamente el tramo contiguo restante, que
        // acaba en el final de la zona de datos.
        unsafe {
            let dst = self.data.add(offset);
            core::ptr::write_bytes(dst, 0, len as usize);
            core::ptr::write(dst as *mut AegisEvtHdr, hdr);
        }
    }

    fn publicar(&self) {
        atomic(self.base, offset_producer_head()).store(self.head, Ordering::Release);
    }

    fn soltar(&mut self, total_len: u32) -> PushOutcome {
        self.dropped_events += 1;
        self.dropped_bytes += u64::from(total_len);
        atomic(self.base, offset_dropped_events()).store(self.dropped_events, Ordering::Relaxed);
        atomic(self.base, offset_dropped_bytes()).store(self.dropped_bytes, Ordering::Relaxed);
        PushOutcome::Dropped
    }
}

#[inline]
fn atomic(base: *mut u8, byte_offset: usize) -> &'static AtomicU64 {
    // SAFETY: los offsets provienen de `offset_of!` sobre `AegisRingCtrl`, que
    // esta dentro del mapeo verificado en `attach`/`format`, y el bloque esta
    // alineado a 64 B, asi que cada u64 lo esta a 8.
    unsafe { &*(base.add(byte_offset) as *const AtomicU64) }
}

#[inline]
fn align_up(n: usize) -> Option<u32> {
    let a = RECORD_ALIGN as usize;
    let v = n.checked_add(a - 1)? & !(a - 1);
    u32::try_from(v).ok()
}
