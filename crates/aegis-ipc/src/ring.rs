//! Consumidor SPSC del ring buffer compartido entre el driver y el agente.
//!
//! Modelo: **un productor** (Ring 0, en el contexto de un callback de kernel) y
//! **un consumidor** (el hilo colector del agente). Ninguno de los dos bloquea
//! al otro. Esto importa mas de lo que parece: el productor corre dentro de
//! callbacks del sistema operativo donde adquirir un lock que posea un proceso
//! de usuario seria una via directa al deadlock del sistema entero. Por eso el
//! protocolo es puramente de cursores atomicos y el productor, si el ring esta
//! lleno, **descarta y cuenta** en lugar de esperar.
//!
//! ## Protocolo
//!
//! `producer_head` y `consumer_tail` son contadores monotonos de 64 bits que
//! nunca se envuelven en la practica (a 10 M eventos/s de 256 B tardarian ~2.3
//! millones de anios en desbordar). El offset real dentro del buffer es
//! `cursor & (capacity - 1)`, con `capacity` potencia de dos.
//!
//! Un registro nunca se parte por el final del buffer: si el que toca escribir
//! no cabe en el tramo contiguo restante, el productor inserta un registro
//! [`evt::PADDING`] que consume ese tramo y escribe el real desde el principio.
//! El consumidor lo salta sin entregarlo. Esto le ahorra a la ruta caliente la
//! gestion de lecturas y escrituras partidas en dos.
//!
//! ## Ordenacion de memoria
//!
//! El productor escribe el registro completo y **despues** publica con un
//! release-store sobre `producer_head`; el consumidor lee `producer_head` con
//! acquire-load antes de tocar los datos. Ese par release/acquire es lo que
//! garantiza que el contenido del registro es visible antes que el cursor que
//! lo anuncia. Sin el, el consumidor podria leer un registro a medio escribir.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{
    evt, AegisEvtHdr, AegisRingCtrl, AegisStr, AEGIS_ABI_VERSION, AEGIS_EVT_MAGIC, AEGIS_RING_MAGIC,
};

/// Alineacion y paso minimo de todo registro del ring.
pub const RECORD_ALIGN: u32 = 64;

/// Errores al adjuntarse o leer del ring compartido.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// El mapeo es mas pequeno que el bloque de control.
    MappingTooSmall,
    /// El magic del bloque de control no coincide.
    BadMagic,
    /// La version del ABI del driver no es la que entiende este agente.
    AbiMismatch {
        /// Version encontrada en el mapeo.
        found: u32,
    },
    /// `capacity` no es potencia de dos o es cero.
    BadCapacity,
    /// La zona de datos declarada no cabe en el mapeo.
    DataOutOfBounds,
    /// Los datos del ring no son coherentes: cursores imposibles o registro
    /// invalido. El agente debe desconectarse y renegociar el canal.
    Corrupt,
}

/// Vista de solo lectura sobre un registro del ring, sin copia.
#[derive(Debug)]
pub struct EventView<'a> {
    hdr: AegisEvtHdr,
    bytes: &'a [u8],
}

impl<'a> EventView<'a> {
    /// Interpreta un registro suelto que ya no viene del ring SPSC propio.
    ///
    /// En Linux el transporte es `BPF_MAP_TYPE_RINGBUF`, que entrega cada
    /// registro por separado a un callback en vez de exponer un buffer
    /// circular con cursores. El CONTENIDO del registro es el mismo ABI, asi
    /// que el correlador no cambia; solo cambia como llega.
    ///
    /// Valida igual que [`RingConsumer::drain`]: magic, version del ABI y
    /// coherencia de `total_len`. El productor es codigo de kernel y por tanto
    /// confiable, pero un bug suyo no debe convertirse en una lectura fuera de
    /// rango dentro del agente.
    pub fn parse(bytes: &'a [u8]) -> Result<EventView<'a>, RingError> {
        if bytes.len() < core::mem::size_of::<AegisEvtHdr>() {
            return Err(RingError::Corrupt);
        }
        // SAFETY: se acaba de comprobar que hay al menos una cabecera completa.
        // La lectura es unaligned porque el ring buffer de BPF no garantiza
        // alineacion de 64 bytes para el inicio de cada registro.
        let hdr = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const AegisEvtHdr) };

        if hdr.magic != AEGIS_EVT_MAGIC || hdr.abi_version != AEGIS_ABI_VERSION {
            return Err(RingError::Corrupt);
        }
        let total_len = hdr.total_len as usize;
        if total_len < core::mem::size_of::<AegisEvtHdr>()
            || total_len % RECORD_ALIGN as usize != 0
            || total_len > bytes.len()
        {
            return Err(RingError::Corrupt);
        }
        Ok(EventView {
            hdr,
            bytes: &bytes[..total_len],
        })
    }

    /// Cabecera del evento.
    #[inline]
    pub fn header(&self) -> &AegisEvtHdr {
        &self.hdr
    }

    /// Tipo de evento, una de las constantes de [`evt`].
    #[inline]
    pub fn event_type(&self) -> u16 {
        self.hdr.ty
    }

    /// Bytes del payload de tamano fijo, entre la cabecera y las cadenas.
    #[inline]
    pub fn payload_bytes(&self) -> &'a [u8] {
        &self.bytes[core::mem::size_of::<AegisEvtHdr>()..]
    }

    /// Decodifica el payload como `T` si el tipo de evento encaja y el registro
    /// es lo bastante grande.
    ///
    /// Devuelve una copia por valor: el registro solo garantiza alineacion de
    /// 64 bytes para la cabecera, no la alineacion natural de cada payload.
    pub fn payload<T: Payload>(&self) -> Option<T> {
        if !T::EVENT_TYPES.contains(&self.hdr.ty) {
            return None;
        }
        let start = core::mem::size_of::<AegisEvtHdr>();
        let end = start.checked_add(core::mem::size_of::<T>())?;
        if end > self.bytes.len() {
            return None;
        }
        // SAFETY: el rango esta comprobado contra la longitud del registro y
        // `T: Payload` garantiza que es un POD `#[repr(C)]` sin invariantes de
        // validez (todo patron de bits es un valor legitimo). La lectura es
        // unaligned porque el payload solo hereda la alineacion del registro.
        Some(unsafe { core::ptr::read_unaligned(self.bytes.as_ptr().add(start) as *const T) })
    }

    /// Resuelve una referencia a cadena contra los limites reales del registro.
    ///
    /// Devuelve `None` si `(off, len)` se sale del registro. El driver es
    /// codigo confiable, pero un bug suyo no debe convertirse en una lectura
    /// fuera de rango dentro del agente.
    pub fn resolve(&self, s: AegisStr) -> Option<&'a [u8]> {
        if s.len == 0 {
            return None;
        }
        let start = s.off as usize;
        let end = start.checked_add(s.len as usize)?;
        if start < core::mem::size_of::<AegisEvtHdr>() || end > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[start..end])
    }

    /// Igual que [`EventView::resolve`], pero valida que el contenido sea UTF-8.
    pub fn resolve_str(&self, s: AegisStr) -> Option<&'a str> {
        core::str::from_utf8(self.resolve(s)?).ok()
    }
}

/// Marca los payloads `#[repr(C)]` que se pueden decodificar desde el ring.
///
/// # Safety
///
/// El tipo tiene que ser `#[repr(C)]`, POD (sin punteros, sin `bool`, sin
/// `enum` de Rust, sin padding con significado) y todo patron de bits de su
/// tamano debe ser un valor valido: los bytes vienen de otro dominio de
/// privilegio y no se puede asumir nada sobre ellos.
pub unsafe trait Payload: Copy {
    /// Tipos de evento cuyo payload es este tipo.
    const EVENT_TYPES: &'static [u16];
}

// SAFETY: las tres son `#[repr(C)]` compuestas solo de enteros sin signo.
unsafe impl Payload for crate::abi::AegisProcCreate {
    const EVENT_TYPES: &'static [u16] = &[evt::PROCESS_CREATE];
}
unsafe impl Payload for crate::abi::AegisImageLoad {
    const EVENT_TYPES: &'static [u16] = &[evt::IMAGE_LOAD];
}
unsafe impl Payload for crate::abi::AegisFileOp {
    const EVENT_TYPES: &'static [u16] = &[
        evt::FILE_PRE_CREATE,
        evt::FILE_WRITE,
        evt::FILE_RENAME,
        evt::FILE_DELETE,
    ];
}
unsafe impl Payload for crate::abi::AegisRemoteMem {
    // HANDLE_REQUEST comparte payload: en Linux lo produce ptrace(), que es el
    // equivalente exacto de abrir un handle a otro proceso con permiso de
    // lectura o escritura de memoria. Los campos se reutilizan sin forzarlos:
    // target_pid es el proceso objetivo, alloc_type la peticion de ptrace y
    // address el argumento addr.
    const EVENT_TYPES: &'static [u16] = &[
        evt::REMOTE_ALLOC,
        evt::REMOTE_WRITE,
        evt::REMOTE_PROTECT,
        evt::REMOTE_THREAD,
        evt::HANDLE_REQUEST,
    ];
}
unsafe impl Payload for crate::abi::AegisSyscallAnomaly {
    const EVENT_TYPES: &'static [u16] = &[evt::SYSCALL_ANOMALY];
}

// SAFETY: `#[repr(C)]` compuesta de enteros; todo patron de bits es valido.
unsafe impl Payload for crate::abi::AegisFileWrite {
    const EVENT_TYPES: &'static [u16] = &[evt::FILE_WRITE];
}

// SAFETY: `#[repr(C)]` compuesta de enteros; todo patron de bits es valido.
unsafe impl Payload for crate::abi::AegisFdBind {
    const EVENT_TYPES: &'static [u16] = &[evt::FILE_FD_BIND];
}

// SAFETY: `#[repr(C)]` compuesta de enteros sin signo y arrays de u8.
unsafe impl Payload for crate::abi::AegisNetConn {
    const EVENT_TYPES: &'static [u16] = &[evt::NET_CONNECT, evt::NET_SCAN, evt::NET_BLOCKED];
}

/// Consumidor del ring. Se adjunta a una seccion ya mapeada por el llamante.
#[derive(Debug)]
pub struct RingConsumer {
    base: *const u8,
    data: *const u8,
    capacity: u64,
    mask: u64,
    /// Copia local del cursor de lectura: evita releer memoria compartida en
    /// cada iteracion del bucle de drenado.
    tail: u64,
}

// SAFETY: `RingConsumer` posee el lado consumidor del protocolo y todos sus
// accesos a memoria compartida son atomicos. Puede moverse entre hilos siempre
// que solo un hilo lo use a la vez, que es lo que impone `&mut self` en drain.
unsafe impl Send for RingConsumer {}

impl RingConsumer {
    /// Se adjunta al ring mapeado en `[base, base + len)`.
    ///
    /// # Safety
    ///
    /// - `base` debe apuntar a un mapeo valido y legible de al menos `len`
    ///   bytes, alineado a 64 bytes, y seguir vivo mientras exista el
    ///   `RingConsumer`.
    /// - Nadie mas en este proceso puede actuar como consumidor del mismo ring.
    pub unsafe fn attach(base: *const u8, len: usize) -> Result<Self, RingError> {
        if len < core::mem::size_of::<AegisRingCtrl>() {
            return Err(RingError::MappingTooSmall);
        }
        // SAFETY: el llamante garantiza un mapeo valido y alineado de `len`
        // bytes, y acabamos de comprobar que cabe el bloque de control.
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

        // SAFETY: `data_offset + capacity <= len`, comprobado justo arriba.
        let data = unsafe { base.add(data_offset as usize) };
        let tail = Self::atomic_u64(base, offset_consumer_tail()).load(Ordering::Relaxed);

        Ok(Self {
            base,
            data,
            capacity,
            mask: capacity - 1,
            tail,
        })
    }

    #[inline]
    fn atomic_u64(base: *const u8, byte_offset: usize) -> &'static AtomicU64 {
        // SAFETY: los offsets provienen de `offset_of!` sobre `AegisRingCtrl`,
        // que esta enteramente dentro del mapeo verificado en `attach`. El
        // bloque de control esta alineado a 64 B, asi que cada u64 lo esta a 8.
        unsafe { &*(base.add(byte_offset) as *const AtomicU64) }
    }

    #[inline]
    fn atomic_u32(base: *const u8, byte_offset: usize) -> &'static AtomicU32 {
        // SAFETY: igual que en `atomic_u64`.
        unsafe { &*(base.add(byte_offset) as *const AtomicU32) }
    }

    /// Eventos que el driver tuvo que descartar por ring lleno.
    ///
    /// Es la metrica de salud del canal: si crece, el agente no drena lo bastante
    /// rapido y hay puntos ciegos de deteccion.
    pub fn dropped_events(&self) -> u64 {
        Self::atomic_u64(self.base, offset_dropped_events()).load(Ordering::Relaxed)
    }

    /// Bytes descartados por ring lleno.
    pub fn dropped_bytes(&self) -> u64 {
        Self::atomic_u64(self.base, offset_dropped_bytes()).load(Ordering::Relaxed)
    }

    /// Eventos pendientes de drenar, en bytes.
    pub fn backlog_bytes(&self) -> u64 {
        let head = Self::atomic_u64(self.base, offset_producer_head()).load(Ordering::Acquire);
        head.saturating_sub(self.tail)
    }

    /// Publica el latido del consumidor. Si el driver deja de verlo avanzar,
    /// degrada a modo minimo en vez de seguir llenando un ring que nadie lee.
    pub fn heartbeat(&self, tick: u32) {
        Self::atomic_u32(self.base, offset_consumer_alive()).store(tick, Ordering::Release);
    }

    /// Drena hasta `budget` eventos, invocando `f` con cada uno.
    ///
    /// El presupuesto acota el tiempo que el hilo colector pasa en el ring y le
    /// permite atender otras cosas (rotacion de reglas, apagado) sin que una
    /// rafaga de telemetria lo secuestre.
    ///
    /// Devuelve cuantos eventos se entregaron, o [`RingError::Corrupt`] si el
    /// flujo deja de ser interpretable; en ese caso el cursor no avanza y el
    /// agente debe renegociar el canal.
    pub fn drain<F>(&mut self, budget: usize, mut f: F) -> Result<usize, RingError>
    where
        F: FnMut(EventView<'_>),
    {
        let head = Self::atomic_u64(self.base, offset_producer_head()).load(Ordering::Acquire);
        if head < self.tail || head - self.tail > self.capacity {
            return Err(RingError::Corrupt);
        }

        let mut delivered = 0usize;
        while delivered < budget && self.tail < head {
            let offset = (self.tail & self.mask) as usize;

            // SAFETY: `offset < capacity` por el enmascarado, y la zona de datos
            // tiene `capacity` bytes validos verificados en `attach`. El
            // acquire-load de `head` ordena esta lectura despues de la escritura
            // completa del registro por parte del productor.
            let hdr = unsafe { core::ptr::read(self.data.add(offset) as *const AegisEvtHdr) };

            if hdr.magic != AEGIS_EVT_MAGIC || hdr.abi_version != AEGIS_ABI_VERSION {
                return Err(RingError::Corrupt);
            }
            let total_len = hdr.total_len;
            if total_len < core::mem::size_of::<AegisEvtHdr>() as u32
                || total_len % RECORD_ALIGN != 0
                || u64::from(total_len) > self.capacity
                || u64::from(total_len) > head - self.tail
                || offset as u64 + u64::from(total_len) > self.capacity
            {
                return Err(RingError::Corrupt);
            }

            if hdr.ty != evt::PADDING {
                // SAFETY: `offset + total_len <= capacity`, comprobado arriba,
                // asi que el registro completo esta dentro de la zona de datos.
                let bytes = unsafe {
                    core::slice::from_raw_parts(self.data.add(offset), total_len as usize)
                };
                f(EventView { hdr, bytes });
                delivered += 1;
            }

            self.tail += u64::from(total_len);
        }

        Self::atomic_u64(self.base, offset_consumer_tail()).store(self.tail, Ordering::Release);
        Ok(delivered)
    }
}

// Offsets del bloque de control, derivados del propio tipo para que no puedan
// desincronizarse de la definicion.
const fn offset_producer_head() -> usize {
    core::mem::offset_of!(AegisRingCtrl, producer_head)
}
const fn offset_dropped_events() -> usize {
    core::mem::offset_of!(AegisRingCtrl, dropped_events)
}
const fn offset_dropped_bytes() -> usize {
    core::mem::offset_of!(AegisRingCtrl, dropped_bytes)
}
const fn offset_consumer_tail() -> usize {
    core::mem::offset_of!(AegisRingCtrl, consumer_tail)
}
const fn offset_consumer_alive() -> usize {
    core::mem::offset_of!(AegisRingCtrl, consumer_alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{flags, AegisProcCreate};
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    /// Ring de pruebas: reproduce en el host exactamente lo que hace el driver,
    /// para poder ejercitar el protocolo (envolvimiento, relleno, corrupcion)
    /// sin cargar codigo en el kernel.
    struct TestRing {
        base: *mut u8,
        layout: Layout,
        capacity: u64,
        data_offset: u64,
        head: u64,
    }

    const DATA_OFFSET: u64 = 256;

    impl TestRing {
        fn new(capacity: u64) -> Self {
            assert!(capacity.is_power_of_two());
            let total = (DATA_OFFSET + capacity) as usize;
            let layout = Layout::from_size_align(total, 64).unwrap();
            // SAFETY: layout de tamano no nulo y alineacion valida.
            let base = unsafe { alloc_zeroed(layout) };
            assert!(!base.is_null());

            // SAFETY: `base` apunta a `total` bytes recien reservados y a cero.
            let ctrl = unsafe { &mut *(base as *mut AegisRingCtrl) };
            ctrl.magic = AEGIS_RING_MAGIC;
            ctrl.abi_version = u32::from(AEGIS_ABI_VERSION);
            ctrl.capacity = capacity;
            ctrl.data_offset = DATA_OFFSET;

            Self {
                base,
                layout,
                capacity,
                data_offset: DATA_OFFSET,
                head: 0,
            }
        }

        fn consumer(&self) -> RingConsumer {
            // SAFETY: mapeo vivo, alineado a 64 y del tamano declarado.
            unsafe { RingConsumer::attach(self.base, self.layout.size()) }.unwrap()
        }

        fn data(&self) -> *mut u8 {
            // SAFETY: `data_offset` esta dentro de la reserva.
            unsafe { self.base.add(self.data_offset as usize) }
        }

        /// Escribe un registro y lo publica con release-store, igual que el driver.
        fn push(&mut self, ty: u16, payload: &[u8], tail_bytes: &[u8]) -> u32 {
            let content = 64 + payload.len() + tail_bytes.len();
            let total_len = content.next_multiple_of(RECORD_ALIGN as usize) as u32;
            assert!(u64::from(total_len) <= self.capacity);

            let offset = (self.head & (self.capacity - 1)) as usize;
            let contiguous = self.capacity as usize - offset;
            if contiguous < total_len as usize {
                self.push_padding(contiguous as u32);
                return self.push(ty, payload, tail_bytes);
            }

            // El driver real nunca pisa datos que el agente aun no ha leido:
            // si no hay hueco, incrementa dropped_events y sigue. Modelarlo
            // aqui impide que una prueba construya un ring imposible y luego
            // culpe al consumidor de rechazarlo.
            let tail =
                RingConsumer::atomic_u64(self.base, offset_consumer_tail()).load(Ordering::Acquire);
            assert!(
                self.head + u64::from(total_len) - tail <= self.capacity,
                "el ring de prueba se desbordaria: hay que drenar antes de seguir escribiendo"
            );

            let mut hdr = AegisEvtHdr {
                magic: AEGIS_EVT_MAGIC,
                abi_version: AEGIS_ABI_VERSION,
                ty,
                total_len,
                flags: 0,
                seq: self.head,
                ts_ns: 1_000 + self.head,
                actor_key: 0xAAAA_0000 | (self.head & 0xFFFF),
                target_key: 0,
                cpu: 0,
                verdict_id: 0,
                reserved: 0,
            };
            if ty == evt::FILE_PRE_CREATE {
                hdr.flags |= flags::NEEDS_VERDICT;
                hdr.verdict_id = 7;
            }

            // SAFETY: se acaba de comprobar que el registro entero cabe en el
            // tramo contiguo que empieza en `offset`.
            unsafe {
                let dst = self.data().add(offset);
                std::ptr::write_bytes(dst, 0, total_len as usize);
                std::ptr::write(dst as *mut AegisEvtHdr, hdr);
                std::ptr::copy_nonoverlapping(payload.as_ptr(), dst.add(64), payload.len());
                std::ptr::copy_nonoverlapping(
                    tail_bytes.as_ptr(),
                    dst.add(64 + payload.len()),
                    tail_bytes.len(),
                );
            }

            self.head += u64::from(total_len);
            self.publish();
            total_len
        }

        fn push_padding(&mut self, len: u32) {
            let offset = (self.head & (self.capacity - 1)) as usize;
            let hdr = AegisEvtHdr {
                magic: AEGIS_EVT_MAGIC,
                abi_version: AEGIS_ABI_VERSION,
                ty: evt::PADDING,
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
            // SAFETY: el relleno ocupa justo el tramo contiguo restante.
            unsafe {
                let dst = self.data().add(offset);
                std::ptr::write_bytes(dst, 0, len as usize);
                std::ptr::write(dst as *mut AegisEvtHdr, hdr);
            }
            self.head += u64::from(len);
            self.publish();
        }

        fn publish(&self) {
            RingConsumer::atomic_u64(self.base, offset_producer_head())
                .store(self.head, Ordering::Release);
        }

        fn set_dropped(&self, events: u64, bytes: u64) {
            RingConsumer::atomic_u64(self.base, offset_dropped_events())
                .store(events, Ordering::Relaxed);
            RingConsumer::atomic_u64(self.base, offset_dropped_bytes())
                .store(bytes, Ordering::Relaxed);
        }

        /// Corrompe el `total_len` del registro que hay en `cursor`.
        fn corrupt_len_at(&self, cursor: u64, value: u32) {
            let offset = (cursor & (self.capacity - 1)) as usize;
            // SAFETY: offset dentro de la zona de datos.
            unsafe {
                let hdr = self.data().add(offset) as *mut AegisEvtHdr;
                (*hdr).total_len = value;
            }
        }
    }

    impl Drop for TestRing {
        fn drop(&mut self) {
            // SAFETY: mismo puntero y layout con los que se reservo.
            unsafe { dealloc(self.base, self.layout) };
        }
    }

    /// Construye el payload y las cadenas de un PROCESS_CREATE.
    fn proc_create(image: &str, cmdline: &str) -> (Vec<u8>, Vec<u8>) {
        let img_off = 64 + core::mem::size_of::<AegisProcCreate>();
        let cmd_off = img_off + image.len();
        let p = AegisProcCreate {
            parent_key: 0x1111,
            creator_key: 0x2222,
            image_id: 0xFEED,
            create_time: 0xC0FFEE,
            pid: 4242,
            parent_pid: 1,
            session_id: 1,
            token_flags: 0,
            integrity_level: crate::abi::integrity::MEDIUM,
            signature_level: 0,
            image_path: AegisStr {
                off: img_off as u16,
                len: image.len() as u16,
            },
            cmdline: AegisStr {
                off: cmd_off as u16,
                len: cmdline.len() as u16,
            },
            user_sid: AegisStr::default(),
        };
        // SAFETY: `AegisProcCreate` es POD `#[repr(C)]`; se serializa tal cual.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &p as *const _ as *const u8,
                core::mem::size_of::<AegisProcCreate>(),
            )
        }
        .to_vec();
        let mut strings = image.as_bytes().to_vec();
        strings.extend_from_slice(cmdline.as_bytes());
        (bytes, strings)
    }

    #[test]
    fn attach_valida_el_bloque_de_control() {
        let ring = TestRing::new(4096);

        // SAFETY: mapeo valido, pero deliberadamente demasiado corto.
        let err = unsafe { RingConsumer::attach(ring.base, 8) }.unwrap_err();
        assert_eq!(err, RingError::MappingTooSmall);

        // SAFETY: `base` apunta al bloque de control vivo.
        unsafe { (*(ring.base as *mut AegisRingCtrl)).magic = 0xDEAD_BEEF };
        // SAFETY: mapeo valido; se espera fallo por magic.
        let err = unsafe { RingConsumer::attach(ring.base, ring.layout.size()) }.unwrap_err();
        assert_eq!(err, RingError::BadMagic);

        // SAFETY: se restaura el magic y se rompe la capacidad.
        unsafe {
            let c = ring.base as *mut AegisRingCtrl;
            (*c).magic = AEGIS_RING_MAGIC;
            (*c).capacity = 3000; // no es potencia de dos
        }
        // SAFETY: mapeo valido; se espera fallo por capacidad.
        let err = unsafe { RingConsumer::attach(ring.base, ring.layout.size()) }.unwrap_err();
        assert_eq!(err, RingError::BadCapacity);
    }

    #[test]
    fn attach_rechaza_abi_distinta() {
        let ring = TestRing::new(4096);
        // SAFETY: bloque de control vivo.
        unsafe { (*(ring.base as *mut AegisRingCtrl)).abi_version = 99 };
        // SAFETY: mapeo valido; se espera fallo por version.
        let err = unsafe { RingConsumer::attach(ring.base, ring.layout.size()) }.unwrap_err();
        assert_eq!(err, RingError::AbiMismatch { found: 99 });
    }

    #[test]
    fn round_trip_de_evento_con_cadenas() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);

        let mut consumer = ring.consumer();
        let mut vistos = 0;
        let n = consumer
            .drain(16, |ev| {
                vistos += 1;
                assert_eq!(ev.event_type(), evt::PROCESS_CREATE);
                let p: AegisProcCreate = ev.payload().expect("payload decodificable");
                assert_eq!(p.pid, 4242);
                assert_eq!(p.creator_key, 0x2222);
                assert_eq!(
                    ev.resolve_str(p.image_path).unwrap(),
                    "C:\\Windows\\System32\\cmd.exe"
                );
                assert_eq!(ev.resolve_str(p.cmdline).unwrap(), "cmd.exe /c whoami");
                assert!(ev.resolve(p.user_sid).is_none(), "cadena ausente => None");
            })
            .unwrap();

        assert_eq!(n, 1);
        assert_eq!(vistos, 1);
        assert_eq!(consumer.drain(16, |_| panic!("ring vacio")).unwrap(), 0);
    }

    #[test]
    fn payload_rechaza_tipo_que_no_corresponde() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/usr/bin/bash", "-c id");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);

        let mut consumer = ring.consumer();
        consumer
            .drain(1, |ev| {
                assert!(
                    ev.payload::<crate::abi::AegisFileOp>().is_none(),
                    "un PROCESS_CREATE no se puede leer como operacion de fichero"
                );
            })
            .unwrap();
    }

    #[test]
    fn cadena_fuera_de_rango_no_se_resuelve() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/bin/ls", "ls");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);

        let mut consumer = ring.consumer();
        consumer
            .drain(1, |ev| {
                // Un driver con un bug podria emitir un offset disparatado.
                let mala = AegisStr {
                    off: 60_000,
                    len: 128,
                };
                assert!(ev.resolve(mala).is_none());
                let solapa_cabecera = AegisStr { off: 8, len: 4 };
                assert!(ev.resolve(solapa_cabecera).is_none());
            })
            .unwrap();
    }

    #[test]
    fn el_relleno_de_fin_de_buffer_se_salta() {
        // Capacidad justa para que el tercer registro no quepa al final.
        let mut ring = TestRing::new(512);
        let (payload, strings) = proc_create("/bin/a", "a");

        // Dos registros de 192 B dejan 128 B libres al final del buffer.
        let l1 = ring.push(evt::PROCESS_CREATE, &payload, &strings);
        let l2 = ring.push(evt::PROCESS_CREATE, &payload, &strings);
        assert_eq!(l1 + l2, 384);

        let mut consumer = ring.consumer();
        assert_eq!(consumer.drain(16, |_| {}).unwrap(), 2);

        // El tercero no cabe en los 128 B contiguos que quedan: el productor
        // inserta relleno hasta el final y escribe el registro real en el
        // origen del buffer.
        ring.push(evt::PROCESS_CREATE, &payload, &strings);

        let mut vistos = 0;
        let n = consumer
            .drain(16, |ev| {
                vistos += 1;
                assert_eq!(ev.event_type(), evt::PROCESS_CREATE);
                let p: AegisProcCreate = ev.payload().unwrap();
                // Tras el envolvimiento las cadenas se siguen resolviendo:
                // los offsets son relativos al registro, no al buffer.
                assert_eq!(ev.resolve_str(p.image_path).unwrap(), "/bin/a");
            })
            .unwrap();
        assert_eq!(n, 1, "solo el evento real se entrega; el relleno se salta");
        assert_eq!(vistos, 1);
    }

    #[test]
    fn el_presupuesto_acota_el_drenado() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/bin/a", "a");
        for _ in 0..8 {
            ring.push(evt::PROCESS_CREATE, &payload, &strings);
        }

        let mut consumer = ring.consumer();
        assert_eq!(consumer.drain(3, |_| {}).unwrap(), 3);
        assert_eq!(consumer.drain(3, |_| {}).unwrap(), 3);
        assert_eq!(consumer.drain(9, |_| {}).unwrap(), 2);
        assert_eq!(consumer.drain(9, |_| {}).unwrap(), 0);
    }

    #[test]
    fn un_registro_corrupto_no_avanza_el_cursor() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/bin/a", "a");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);
        // total_len no multiplo de 64: imposible en un productor correcto.
        ring.corrupt_len_at(0, 100);

        let mut consumer = ring.consumer();
        assert_eq!(consumer.drain(16, |_| {}), Err(RingError::Corrupt));
        // El cursor sigue a cero: el agente renegocia el canal en vez de
        // interpretar basura como telemetria.
        assert_eq!(
            RingConsumer::atomic_u64(ring.base, offset_consumer_tail()).load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn total_len_que_desborda_el_buffer_es_corrupcion() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/bin/a", "a");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);
        ring.corrupt_len_at(0, 8192); // mayor que la capacidad

        let mut consumer = ring.consumer();
        assert_eq!(consumer.drain(16, |_| {}), Err(RingError::Corrupt));
    }

    #[test]
    fn el_backlog_y_las_perdidas_son_observables() {
        let mut ring = TestRing::new(4096);
        let (payload, strings) = proc_create("/bin/a", "a");
        ring.push(evt::PROCESS_CREATE, &payload, &strings);
        ring.set_dropped(12, 3072);

        let mut consumer = ring.consumer();
        assert_eq!(consumer.backlog_bytes(), 192);
        assert_eq!(consumer.dropped_events(), 12);
        assert_eq!(consumer.dropped_bytes(), 3072);

        consumer.drain(16, |_| {}).unwrap();
        assert_eq!(consumer.backlog_bytes(), 0);

        consumer.heartbeat(99);
        assert_eq!(
            RingConsumer::atomic_u32(ring.base, offset_consumer_alive()).load(Ordering::Acquire),
            99
        );
    }

    #[test]
    fn parse_valida_registros_sueltos() {
        // Registro bien formado, como el que entrega el ring buffer de BPF.
        let (payload, strings) = proc_create("/usr/bin/id", "id -u");
        let mut rec = vec![0u8; 512];
        let hdr = AegisEvtHdr {
            magic: AEGIS_EVT_MAGIC,
            abi_version: AEGIS_ABI_VERSION,
            ty: evt::PROCESS_CREATE,
            total_len: 512,
            flags: 0,
            seq: 1,
            ts_ns: 5,
            actor_key: 0xABCD,
            target_key: 0,
            cpu: 0,
            verdict_id: 0,
            reserved: 0,
        };
        // SAFETY: `rec` tiene 512 bytes y la cabecera ocupa 64.
        unsafe { std::ptr::write_unaligned(rec.as_mut_ptr() as *mut AegisEvtHdr, hdr) };
        rec[64..64 + payload.len()].copy_from_slice(&payload);
        let soff = 64 + payload.len();
        rec[soff..soff + strings.len()].copy_from_slice(&strings);

        let ev = EventView::parse(&rec).expect("registro valido");
        assert_eq!(ev.event_type(), evt::PROCESS_CREATE);
        let p: AegisProcCreate = ev.payload().unwrap();
        assert_eq!(ev.resolve_str(p.image_path).unwrap(), "/usr/bin/id");

        // Demasiado corto para contener una cabecera.
        assert_eq!(
            EventView::parse(&rec[..32]).unwrap_err(),
            RingError::Corrupt
        );
        // total_len declara mas bytes de los que se entregan.
        let mut corto = rec.clone();
        corto.truncate(256);
        assert_eq!(EventView::parse(&corto).unwrap_err(), RingError::Corrupt);
        // Magic incorrecto.
        let mut malo = rec.clone();
        malo[0] = 0;
        assert_eq!(EventView::parse(&malo).unwrap_err(), RingError::Corrupt);
        // total_len que no es multiplo de la alineacion de registro.
        let mut desalineado = rec.clone();
        desalineado[8..12].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(
            EventView::parse(&desalineado).unwrap_err(),
            RingError::Corrupt
        );
    }

    #[test]
    fn el_evento_que_exige_veredicto_se_marca() {
        let mut ring = TestRing::new(4096);
        ring.push(evt::FILE_PRE_CREATE, &[0u8; 64], &[]);

        let mut consumer = ring.consumer();
        consumer
            .drain(1, |ev| {
                assert_ne!(ev.header().flags & flags::NEEDS_VERDICT, 0);
                assert_eq!(ev.header().verdict_id, 7);
            })
            .unwrap();
    }
}
