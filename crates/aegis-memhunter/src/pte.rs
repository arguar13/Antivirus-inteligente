//! La tabla de paginas: `/proc/<pid>/pagemap`, una entrada de 64 bits por pagina.
//!
//! # Que dice cada bit, y cual importa
//!
//! | Bit | Significado |
//! |---|---|
//! | 63 | la pagina esta PRESENTE en memoria fisica |
//! | 62 | la pagina esta en el area de intercambio |
//! | 61 | la pagina esta **respaldada por un fichero** (o es anonima compartida) |
//! | 56 | la pagina esta mapeada en exclusiva por este proceso |
//! | 55 | *soft-dirty*: se escribio desde la ultima puesta a cero |
//! | 0-54 | numero de marco de pagina fisica (cero sin `CAP_SYS_ADMIN`) |
//!
//! El bit 61 es el que sostiene esta fase. La deduccion, paso a paso:
//!
//! 1. Una region privada respaldada por fichero (`r-xp /usr/lib/libfoo.so`, la
//!    seccion de codigo de un modulo) empieza con todas sus paginas apuntando a
//!    la cache de paginas del fichero: bit 61 a **1**.
//! 2. Escribir en una de esas paginas obliga al kernel a hacer **copy-on-write**:
//!    asigna una pagina nueva, copia el contenido y la sustituye. La pagina nueva
//!    ya no pertenece al fichero: bit 61 a **0**.
//! 3. Una pagina de CODIGO no se escribe nunca en operacion normal.
//!
//! Luego una pagina presente, con el bit 61 a 0, dentro de una region de codigo
//! respaldada por fichero, significa que **lo que se ejecuta ahi ya no es lo que
//! hay en el fichero**. Es *module stomping*, delatado sin leer un byte de la
//! memoria del proceso y sin abrir el fichero de disco para comparar.
//!
//! Los tres estados no se deducen de la documentacion: se **verifican contra el
//! kernel de la maquina** en [`pruebas_vivas`], construyendo cada caso de verdad.
//!
//! # El descuento legitimo que hay que hacer
//!
//! Hay dos motivos honrados por los que una pagina de codigo sufre copy-on-write
//! en el arranque de casi cualquier proceso de glibc:
//!
//! - **Resolucion de IFUNC**: `memcpy`, `strlen` y companía se resuelven en carga
//!   a la variante que soporta la CPU, lo que reescribe entradas de la PLT.
//! - **Reubicaciones en texto** (`DT_TEXTREL`): un objeto sin `-fPIC` hace que el
//!   enlazador parchee instrucciones directamente.
//!
//! Los dos tocan unas pocas paginas al principio de la region. Sobrescribir el
//! codigo de un modulo toca la region entera. Por eso este modulo no responde
//! "hubo copia privada": responde **cuantas paginas y cuales**, y la decision de
//! si eso es un parcheo legitimo o una sustitucion la toma [`crate::hunter`] con
//! un umbral explicito.

use crate::{vad::PAGINA, MemHunterError};

/// Una entrada de la tabla de paginas tal y como la expone `pagemap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntradaPagina(pub u64);

impl EntradaPagina {
    /// Bit 63: la pagina esta presente en memoria fisica.
    #[must_use]
    pub const fn presente(self) -> bool {
        self.0 >> 63 & 1 == 1
    }

    /// Bit 62: la pagina esta en el area de intercambio.
    #[must_use]
    pub const fn intercambiada(self) -> bool {
        self.0 >> 62 & 1 == 1
    }

    /// Bit 61: la pagina esta respaldada por un fichero (o es anonima compartida).
    #[must_use]
    pub const fn respaldada_por_fichero(self) -> bool {
        self.0 >> 61 & 1 == 1
    }

    /// Bit 56: la pagina esta mapeada en exclusiva por este proceso.
    #[must_use]
    pub const fn exclusiva(self) -> bool {
        self.0 >> 56 & 1 == 1
    }

    /// Bit 55: se escribio desde la ultima puesta a cero de `soft-dirty`.
    ///
    /// Solo es util si alguien puso los contadores a cero antes
    /// (`/proc/<pid>/clear_refs`), cosa que este modulo NO hace: escribir ahi
    /// altera el estado de un proceso que puede ser la victima de un incidente
    /// en curso, y un EDR que modifica la escena no es un EDR.
    #[must_use]
    pub const fn sucia_blanda(self) -> bool {
        self.0 >> 55 & 1 == 1
    }

    /// Numero de marco de pagina fisica.
    ///
    /// El kernel lo devuelve a CERO sin `CAP_SYS_ADMIN` (desde Linux 4.2, para
    /// cerrar la via de Rowhammer que abria conocer la disposicion fisica). Este
    /// modulo no lo necesita para nada: todas sus decisiones salen de los bits de
    /// estado, que si estan disponibles sin privilegios. Se expone porque el
    /// escaner de memoria fisica de la FASE 57 si lo usa.
    #[must_use]
    pub const fn marco_fisico(self) -> u64 {
        self.0 & ((1 << 55) - 1)
    }

    /// `true` si la pagina esta presente y su contenido **ya no procede del
    /// fichero** que respalda su region.
    ///
    /// Es el predicado central de la fase. Solo tiene sentido preguntarlo sobre
    /// una region respaldada por fichero: en una region anonima toda pagina lo
    /// cumple por definicion y la respuesta no significa nada.
    #[must_use]
    pub const fn desligada_del_fichero(self) -> bool {
        self.presente() && !self.respaldada_por_fichero()
    }
}

/// Las entradas de la tabla de paginas de un rango de direcciones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapaPaginas {
    /// Direccion de la primera pagina cubierta.
    pub base: u64,
    /// Una entrada por pagina, en orden.
    pub entradas: Vec<EntradaPagina>,
    /// `true` si el rango se recorto por exceder el presupuesto de lectura.
    ///
    /// Se expone en vez de silenciarse: un veredicto calculado sobre una muestra
    /// y uno calculado sobre la region entera no son la misma afirmacion, y
    /// quien lea el informe tiene que poder distinguirlos.
    pub truncado: bool,
}

impl MapaPaginas {
    /// Cuantas paginas presentes han dejado de pertenecer al fichero.
    #[must_use]
    pub fn paginas_desligadas(&self) -> usize {
        self.entradas
            .iter()
            .filter(|e| e.desligada_del_fichero())
            .count()
    }

    /// Cuantas paginas estan presentes en memoria fisica.
    #[must_use]
    pub fn paginas_presentes(&self) -> usize {
        self.entradas.iter().filter(|e| e.presente()).count()
    }

    /// Los rangos CONTIGUOS de paginas desligadas, como `(direccion, longitud)`.
    ///
    /// Importa la forma y no solo el recuento: una resolucion de IFUNC deja
    /// paginas sueltas y dispersas al principio de la region; una sobrescritura
    /// de codigo deja **un bloque contiguo**. Dar los rangos permite al analista
    /// ir directo a la direccion, y al cazador distinguir las dos formas.
    #[must_use]
    pub fn rangos_desligados(&self) -> Vec<(u64, u64)> {
        let mut rangos = Vec::new();
        let mut inicio: Option<u64> = None;
        for (i, e) in self.entradas.iter().enumerate() {
            let dir = self.base + i as u64 * PAGINA;
            match (e.desligada_del_fichero(), inicio) {
                (true, None) => inicio = Some(dir),
                (false, Some(ini)) => {
                    rangos.push((ini, dir - ini));
                    inicio = None;
                }
                _ => {}
            }
        }
        if let Some(ini) = inicio {
            let fin = self.base + self.entradas.len() as u64 * PAGINA;
            rangos.push((ini, fin - ini));
        }
        rangos
    }

    /// El bloque contiguo de paginas desligadas mas largo, en bytes.
    #[must_use]
    pub fn mayor_bloque_desligado(&self) -> u64 {
        self.rangos_desligados()
            .into_iter()
            .map(|(_, largo)| largo)
            .max()
            .unwrap_or(0)
    }
}

/// Maximo de entradas que se leen de una sola region.
///
/// 262 144 entradas son 2 MiB de lectura y cubren 1 GiB de espacio de
/// direcciones. Mas alla de eso, el coste deja de compensar: una region de 40
/// GiB de un proceso de base de datos serian 80 MiB de entradas para confirmar
/// lo que la triacion por `smaps` ya habia decidido. Cuando se recorta, se DICE
/// ([`MapaPaginas::truncado`]).
pub const MAX_ENTRADAS_POR_REGION: usize = 256 * 1024;

/// Lee las entradas de la tabla de paginas del rango `[inicio, fin)` de `pid`.
///
/// # Por que `pread` y no `seek` + `read`
///
/// Porque el desplazamiento es funcion de la direccion virtual y una lectura
/// posicional no tiene estado compartido: dos hilos del agente pueden analizar
/// dos procesos a la vez con el MISMO descriptor sin pisarse el cursor. Con
/// `seek` + `read` habria que serializar o abrir un descriptor por region, y el
/// analisis de una flota es justo lo que no puede serializarse.
///
/// # Errores
/// [`MemHunterError::ProcesoMuerto`] si el proceso desaparecio entre enumerar
/// sus regiones y leer sus paginas (que es normal en un sistema vivo, no un
/// fallo), o [`MemHunterError::Lectura`] si `pagemap` no se puede leer.
#[cfg(target_os = "linux")]
pub fn leer_pagemap(pid: i32, inicio: u64, fin: u64) -> Result<MapaPaginas, MemHunterError> {
    use std::os::fd::AsRawFd;

    let ruta = format!("/proc/{pid}/pagemap");
    let fichero = match std::fs::File::open(&ruta) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(MemHunterError::ProcesoMuerto { pid })
        }
        Err(causa) => return Err(MemHunterError::Lectura { ruta, causa }),
    };

    let base = inicio & !(PAGINA - 1);
    let total = (fin.saturating_sub(base)).div_ceil(PAGINA) as usize;
    let cuantas = total.min(MAX_ENTRADAS_POR_REGION);
    if cuantas == 0 {
        return Ok(MapaPaginas {
            base,
            entradas: Vec::new(),
            truncado: false,
        });
    }

    let mut crudo = vec![0u8; cuantas * 8];
    let desplazamiento = (base / PAGINA) * 8;
    let mut leidos = 0usize;
    while leidos < crudo.len() {
        // SEGURIDAD: `crudo` es un buffer propio y vivo; el puntero y la
        // longitud se derivan de el, asi que la escritura del kernel cae
        // siempre dentro. `pread` no toca el cursor del descriptor.
        let n = unsafe {
            libc::pread(
                fichero.as_raw_fd(),
                crudo[leidos..].as_mut_ptr().cast::<libc::c_void>(),
                crudo.len() - leidos,
                (desplazamiento + leidos as u64) as libc::off_t,
            )
        };
        match n {
            // Fin de fichero antes de lo previsto: el espacio de direcciones se
            // encogio mientras se leia (el proceso hizo `munmap`). Es normal en
            // un sistema vivo; se devuelve lo leido y se marca truncado.
            0 => {
                crudo.truncate(leidos);
                break;
            }
            n if n > 0 => leidos += n as usize,
            _ => {
                let causa = std::io::Error::last_os_error();
                // ESRCH/EPERM/EIO: el proceso murio o no se puede leer. Se
                // distingue "murio" del resto porque no es un fallo del producto.
                if causa.raw_os_error() == Some(libc::ESRCH) {
                    return Err(MemHunterError::ProcesoMuerto { pid });
                }
                if causa.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(MemHunterError::Lectura { ruta, causa });
            }
        }
    }

    let entradas = crudo
        .chunks_exact(8)
        .map(|c| EntradaPagina(u64::from_ne_bytes(c.try_into().expect("chunks_exact(8)"))))
        .collect::<Vec<_>>();
    let truncado = total > cuantas || entradas.len() < cuantas;
    Ok(MapaPaginas {
        base,
        entradas,
        truncado,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Entradas construidas con los valores EXACTOS que devuelve el kernel,
    /// tomados de una ejecucion real (ver `pruebas_vivas`).
    const ANONIMA_PRESENTE: u64 = 0x8100_0000_0033_c8fa; // presente, bit61=0, excl
    const FICHERO_PRESENTE: u64 = 0xa000_0000_002d_3898; // presente, bit61=1
    const AUSENTE: u64 = 0x0000_0000_0000_0000;

    #[test]
    fn los_bits_se_interpretan_como_los_define_el_kernel() {
        let anon = EntradaPagina(ANONIMA_PRESENTE);
        assert!(anon.presente());
        assert!(!anon.intercambiada());
        assert!(!anon.respaldada_por_fichero());
        assert!(anon.exclusiva());
        assert!(anon.desligada_del_fichero());

        let fich = EntradaPagina(FICHERO_PRESENTE);
        assert!(fich.presente());
        assert!(fich.respaldada_por_fichero());
        assert!(
            !fich.desligada_del_fichero(),
            "una pagina de fichero intacta no puede contar como sobrescrita"
        );

        // Una pagina AUSENTE no dice nada: no esta en memoria, asi que no puede
        // haber sido sobrescrita. Contarla como desligada convertiria cada
        // region no residente en una deteccion, que es como se construye un
        // detector que nadie mira.
        let fuera = EntradaPagina(AUSENTE);
        assert!(!fuera.presente());
        assert!(!fuera.desligada_del_fichero());
    }

    fn mapa(base: u64, valores: &[u64]) -> MapaPaginas {
        MapaPaginas {
            base,
            entradas: valores.iter().copied().map(EntradaPagina).collect(),
            truncado: false,
        }
    }

    #[test]
    fn los_rangos_contiguos_distinguen_un_parcheo_de_una_sobrescritura() {
        // Resolucion de IFUNC: paginas sueltas y dispersas.
        let parcheo = mapa(
            0x1000_0000,
            &[
                ANONIMA_PRESENTE,
                FICHERO_PRESENTE,
                FICHERO_PRESENTE,
                ANONIMA_PRESENTE,
                FICHERO_PRESENTE,
            ],
        );
        assert_eq!(parcheo.paginas_desligadas(), 2);
        assert_eq!(parcheo.rangos_desligados().len(), 2);
        assert_eq!(parcheo.mayor_bloque_desligado(), PAGINA);

        // Sobrescritura: un bloque contiguo.
        let stomping = mapa(
            0x1000_0000,
            &[
                FICHERO_PRESENTE,
                ANONIMA_PRESENTE,
                ANONIMA_PRESENTE,
                ANONIMA_PRESENTE,
                FICHERO_PRESENTE,
            ],
        );
        assert_eq!(stomping.paginas_desligadas(), 3);
        assert_eq!(stomping.rangos_desligados().len(), 1);
        assert_eq!(stomping.mayor_bloque_desligado(), 3 * PAGINA);
        assert_eq!(stomping.rangos_desligados()[0].0, 0x1000_0000 + PAGINA);
    }

    #[test]
    fn un_bloque_que_llega_al_final_se_cierra_bien() {
        // El fallo clasico de este tipo de bucle: el ultimo rango se pierde
        // porque no hay un elemento "falso" detras que lo cierre.
        let m = mapa(
            0x2000,
            &[FICHERO_PRESENTE, ANONIMA_PRESENTE, ANONIMA_PRESENTE],
        );
        assert_eq!(m.rangos_desligados(), vec![(0x2000 + PAGINA, 2 * PAGINA)]);
    }

    #[test]
    fn un_mapa_vacio_no_afirma_nada() {
        let m = mapa(0, &[]);
        assert_eq!(m.paginas_desligadas(), 0);
        assert!(m.rangos_desligados().is_empty());
        assert_eq!(m.mayor_bloque_desligado(), 0);
    }
}

/// Pruebas contra el KERNEL de esta maquina: construyen cada estado de pagina de
/// verdad y comprueban que `pagemap` dice lo que esta fase afirma que dice.
///
/// Esto no es un extra: TODA la deteccion de *module stomping* se apoya en la
/// semantica del bit 61, y esa semantica es un contrato con el kernel, no un
/// detalle de implementacion de este crate. Si un kernel futuro lo cambiara, la
/// deteccion se volveria silenciosamente inutil —dejaria de encontrar nada, que
/// es el peor fallo posible en un EDR— y nadie se enteraria. Aqui se entera el CI.
#[cfg(all(test, target_os = "linux"))]
mod pruebas_vivas {
    use super::*;

    /// Reserva `paginas` paginas con `mmap` y devuelve la direccion base.
    ///
    /// # Panicos
    /// Si `mmap` falla, que en una maquina de CI con memoria libre no ocurre y,
    /// si ocurriera, invalidaria la prueba entera.
    fn mapear(paginas: usize, prot: libc::c_int, flags: libc::c_int) -> *mut libc::c_void {
        // SEGURIDAD: reserva anonima nueva; no se toca memoria ajena.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                paginas * PAGINA as usize,
                prot,
                flags,
                -1,
                0,
            )
        };
        assert_ne!(
            p,
            libc::MAP_FAILED,
            "mmap fallo: {}",
            std::io::Error::last_os_error()
        );
        p
    }

    fn entrada_de(dir: u64) -> EntradaPagina {
        let m = leer_pagemap(std::process::id() as i32, dir, dir + PAGINA)
            .expect("pagemap del propio proceso");
        assert_eq!(m.entradas.len(), 1);
        m.entradas[0]
    }

    /// EL CONTRATO CON EL KERNEL. Los tres estados, construidos de verdad.
    #[test]
    fn el_bit_61_distingue_pagina_de_fichero_de_pagina_copiada() {
        // --- 1. Anonima privada, escrita: NO es de fichero -------------------
        let anon = mapear(
            1,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        );
        // SEGURIDAD: se escribe dentro de la reserva recien hecha.
        unsafe { std::ptr::write_bytes(anon.cast::<u8>(), 0x41, PAGINA as usize) };
        let e = entrada_de(anon as u64);
        assert!(
            e.presente(),
            "la pagina recien escrita tiene que estar residente"
        );
        assert!(
            !e.respaldada_por_fichero(),
            "una pagina anonima privada NO puede decir que la respalda un fichero"
        );

        // --- 2. Fichero mapeado privado, solo leido: SI es de fichero --------
        let dir = std::env::temp_dir().join(format!("aegis-memhunter-{}", std::process::id()));
        std::fs::write(&dir, vec![0xCCu8; PAGINA as usize * 4]).expect("fichero de respaldo");
        let f = std::fs::File::open(&dir).expect("abrir el respaldo");
        use std::os::fd::AsRawFd;
        // SEGURIDAD: mapeo privado de un fichero propio recien creado.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGINA as usize * 4,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            )
        };
        assert_ne!(m, libc::MAP_FAILED, "{}", std::io::Error::last_os_error());
        // Tocar la pagina 0 para que sea residente, sin escribirla.
        // SEGURIDAD: lectura de un byte dentro del propio mapeo.
        let leido = unsafe { std::ptr::read_volatile(m.cast::<u8>()) };
        assert_eq!(leido, 0xCC);
        let e0 = entrada_de(m as u64);
        assert!(e0.presente());
        assert!(
            e0.respaldada_por_fichero(),
            "una pagina de codigo intacta TIENE que decir que la respalda el fichero"
        );

        // --- 3. La misma region, otra pagina, TRAS copy-on-write ------------
        //
        // Esto es exactamente lo que hace el module stomping: dejar escribible
        // una pagina de codigo de un modulo mapeado y sobrescribirla.
        let pagina1 = (m as usize + PAGINA as usize) as *mut libc::c_void;
        // SEGURIDAD: cambia la proteccion de una pagina del propio mapeo.
        let rc = unsafe {
            libc::mprotect(
                pagina1,
                PAGINA as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )
        };
        assert_eq!(rc, 0, "mprotect: {}", std::io::Error::last_os_error());
        // SEGURIDAD: escritura dentro de la pagina recien hecha escribible.
        unsafe { std::ptr::write_bytes(pagina1.cast::<u8>(), 0x90, 16) };

        let e1 = entrada_de(pagina1 as u64);
        assert!(e1.presente());
        assert!(
            !e1.respaldada_por_fichero(),
            "TRAS copy-on-write, la pagina ya no pertenece al fichero: es en esta \
             igualdad donde se apoya toda la deteccion de module stomping"
        );
        assert!(e1.desligada_del_fichero());

        // Y la pagina 0, que no se toco, sigue siendo del fichero: la deteccion
        // localiza la pagina exacta, no marca la region entera.
        assert!(entrada_de(m as u64).respaldada_por_fichero());

        // SEGURIDAD: se liberan las reservas propias.
        unsafe {
            libc::munmap(m, PAGINA as usize * 4);
            libc::munmap(anon, PAGINA as usize);
        }
        let _ = std::fs::remove_file(&dir);
    }

    /// Leer `pagemap` de un rango fuera del espacio de direcciones no puede
    /// entrar en panico ni inventar entradas.
    #[test]
    fn un_rango_no_mapeado_devuelve_entradas_vacias_no_un_panico() {
        // Una direccion del espacio de usuario alta pero sin mapear.
        let m = leer_pagemap(
            std::process::id() as i32,
            0x7000_0000_0000,
            0x7000_0000_4000,
        )
        .expect("leer un rango no mapeado es legitimo");
        assert!(
            m.entradas.iter().all(|e| !e.presente()),
            "un rango sin mapear no puede tener paginas presentes"
        );
        assert!(
            m.paginas_desligadas() == 0,
            "sin paginas presentes no puede haber paginas desligadas"
        );
    }

    /// Un proceso que ya no existe se reporta como tal y no como un fallo del
    /// producto: analizar un sistema vivo significa que los procesos mueren
    /// mientras se los mira.
    #[test]
    fn un_proceso_muerto_se_distingue_de_un_fallo() {
        // PID imposible: el maximo de /proc/sys/kernel/pid_max mas uno.
        let e = leer_pagemap(i32::MAX, 0x1000, 0x2000).unwrap_err();
        assert!(matches!(e, MemHunterError::ProcesoMuerto { .. }), "{e:?}");
    }
}
