//! Lectura de las estructuras internas del kernel desde la memoria fisica cruda,
//! SIN pasar por las APIs del sistema operativo.
//!
//! # Por que sin las APIs del SO
//!
//! Un rootkit de Ring 0 hookea las APIs del kernel: cuando una herramienta
//! pregunta "que procesos hay", el rootkit borra el suyo de la respuesta. Por eso
//! la introspeccion desde el hipervisor NO pregunta: lee la memoria fisica y
//! reconstruye las estructuras (`task_struct` en Linux, `EPROCESS` en Windows)
//! ella misma, siguiendo los punteros a mano. Es lo que hace Volatility sobre un
//! volcado, pero en vivo y por debajo del SO.
//!
//! # La deteccion por vista cruzada
//!
//! La tecnica que delata a un rootkit DKOM (Direct Kernel Object Manipulation):
//! el rootkit DESENLAZA su `task_struct` de la lista de procesos para que el SO
//! no lo vea, pero la estructura SIGUE en memoria (el planificador aun la
//! necesita). Se comparan dos vistas:
//!
//! - **Por lista**: se recorre la lista enlazada de procesos, como haria el SO.
//! - **Por barrido**: se barre la memoria fisica buscando la firma de un
//!   `task_struct`, encontrando TODOS, enlazados o no.
//!
//! Un proceso que aparece en el barrido pero NO en la lista esta oculto: es la
//! prueba del rootkit. Todo esto es DEFENSIVO: se observa para delatar, no se
//! oculta ni se persiste nada.
//!
//! # Honestidad
//!
//! El parser y la deteccion por vista cruzada son Rust puro y se prueban aqui con
//! memoria fisica sintetica que contiene estructuras reales. Obtener los OFFSETS
//! correctos de un kernel en vivo (de sus simbolos / BTF) y leer su memoria
//! fisica de verdad es el muro, gated tras `kvm`.

/// Acceso a la memoria fisica del anfitrion. La implementacion de produccion lee
/// la RAM fisica a traves del hipervisor; la de prueba, de un buffer.
pub trait MemoriaFisica {
    /// Lee `len` bytes desde la direccion fisica `addr`, o `None` si no se puede.
    fn leer(&self, addr: u64, len: usize) -> Option<Vec<u8>>;
}

/// Los offsets de los campos que interesan dentro de la estructura de proceso del
/// kernel. Cambian por version de kernel y arquitectura; en produccion salen de
/// los simbolos/BTF del kernel (parte gated). Aqui se parametriza para que el
/// parser sea el mismo en Linux (`task_struct`) y en Windows (`EPROCESS`).
#[derive(Debug, Clone)]
pub struct PerfilKernel {
    /// Firma que marca el comienzo de una estructura de proceso, para el barrido.
    /// En Windows es el pool tag `Proc`; en Linux se usa una heuristica
    /// estructural. Aqui se pasa explicita.
    pub firma: Vec<u8>,
    /// Offset del PID (entero de 32 bits).
    pub off_pid: usize,
    /// Offset del nombre del proceso.
    pub off_nombre: usize,
    /// Longitud del campo de nombre (16 para `comm` de Linux, 15 para Windows).
    pub long_nombre: usize,
    /// Offset del puntero `next` del enlace de la lista de procesos (el
    /// `list_head` de `tasks` en Linux, `ActiveProcessLinks` en Windows).
    pub off_enlace: usize,
    /// Tamano de la estructura, usado como paso del barrido.
    pub tam_struct: usize,
}

/// Un proceso reconstruido de la memoria del kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proceso {
    /// PID.
    pub pid: u32,
    /// Nombre (recortado en el primer nul).
    pub nombre: String,
    /// Direccion fisica de la estructura.
    pub direccion: u64,
}

/// Lee un `u32` little-endian de la memoria.
fn leer_u32(mem: &impl MemoriaFisica, addr: u64) -> Option<u32> {
    let b = mem.leer(addr, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Lee un `u64` little-endian de la memoria.
fn leer_u64(mem: &impl MemoriaFisica, addr: u64) -> Option<u64> {
    let b = mem.leer(addr, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    Some(u64::from_le_bytes(a))
}

/// Reconstruye un [`Proceso`] leyendo sus campos en la direccion base `base`.
fn leer_proceso(mem: &impl MemoriaFisica, base: u64, perfil: &PerfilKernel) -> Option<Proceso> {
    let pid = leer_u32(mem, base + perfil.off_pid as u64)?;
    let bruto = mem.leer(base + perfil.off_nombre as u64, perfil.long_nombre)?;
    let fin = bruto.iter().position(|&b| b == 0).unwrap_or(bruto.len());
    let nombre = String::from_utf8_lossy(&bruto[..fin]).into_owned();
    Some(Proceso {
        pid,
        nombre,
        direccion: base,
    })
}

/// Recorre la lista enlazada de procesos empezando por el enlace en
/// `addr_lista` (el `list_head` de la cabecera, p. ej. el de `init_task`), como
/// haria el SO. Devuelve los procesos que la lista muestra.
///
/// Sigue los punteros `next`; la base de cada estructura es `enlace - off_enlace`
/// (el enlace esta embebido dentro de la estructura). Se protege contra ciclos y
/// listas corruptas con un limite y un registro de visitados: un rootkit puede
/// haber dejado la lista en cualquier estado.
#[must_use]
pub fn procesos_por_lista(
    mem: &impl MemoriaFisica,
    addr_lista: u64,
    perfil: &PerfilKernel,
) -> Vec<Proceso> {
    const LIMITE: usize = 100_000; // cota dura contra una lista maliciosamente infinita
    let mut salida = Vec::new();
    let mut vistos = std::collections::BTreeSet::new();

    // La cabecera es tambien un proceso (p. ej. init_task).
    if let Some(p) = leer_proceso(mem, addr_lista - perfil.off_enlace as u64, perfil) {
        salida.push(p);
    }
    vistos.insert(addr_lista);

    let Some(mut cur) = leer_u64(mem, addr_lista) else {
        return salida;
    };
    while cur != addr_lista && vistos.len() < LIMITE {
        if !vistos.insert(cur) {
            break; // ciclo que no vuelve a la cabecera: lista corrupta.
        }
        let base = cur.wrapping_sub(perfil.off_enlace as u64);
        if let Some(p) = leer_proceso(mem, base, perfil) {
            salida.push(p);
        }
        let Some(siguiente) = leer_u64(mem, cur) else {
            break;
        };
        cur = siguiente;
    }
    salida
}

/// Barre la memoria fisica `[base, base+largo)` buscando la firma de una
/// estructura de proceso y reconstruye todas las que encuentra: enlazadas o NO.
/// Es la vista que un rootkit DKOM no puede falsear escondiendose de la lista.
#[must_use]
pub fn procesos_por_barrido(
    mem: &impl MemoriaFisica,
    base: u64,
    largo: u64,
    perfil: &PerfilKernel,
) -> Vec<Proceso> {
    let mut salida = Vec::new();
    if perfil.firma.is_empty() {
        return salida;
    }
    let n = perfil.firma.len();
    let mut addr = base;
    let fin = base + largo;
    // Se barre con alineacion de 8 bytes: las estructuras del kernel salen de
    // asignadores alineados.
    while addr + n as u64 <= fin {
        if mem.leer(addr, n).as_deref() == Some(perfil.firma.as_slice()) {
            if let Some(p) = leer_proceso(mem, addr, perfil) {
                salida.push(p);
            }
        }
        addr += 8;
    }
    salida
}

/// Procesos que el barrido encuentra pero la lista no muestra: los OCULTOS. Es la
/// prueba de un rootkit DKOM.
#[must_use]
pub fn ocultos(por_barrido: &[Proceso], por_lista: &[Proceso]) -> Vec<Proceso> {
    let visibles: std::collections::BTreeSet<u64> = por_lista.iter().map(|p| p.direccion).collect();
    por_barrido
        .iter()
        .filter(|p| !visibles.contains(&p.direccion))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memoria fisica plana con base 0.
    struct MemoriaPlana {
        datos: Vec<u8>,
    }
    impl MemoriaFisica for MemoriaPlana {
        fn leer(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            let a = usize::try_from(addr).ok()?;
            let fin = a.checked_add(len)?;
            self.datos.get(a..fin).map(<[u8]>::to_vec)
        }
    }

    /// Perfil de prueba: estructuras de 64 bytes con firma "TASK".
    fn perfil() -> PerfilKernel {
        PerfilKernel {
            firma: b"TASK".to_vec(),
            off_pid: 8,
            off_nombre: 16,
            long_nombre: 16,
            off_enlace: 40,
            tam_struct: 64,
        }
    }

    /// Escribe una estructura de proceso en `datos` en la posicion `base`.
    fn escribir_proceso(datos: &mut [u8], base: usize, pid: u32, nombre: &str, next: u64) {
        let p = &perfil();
        datos[base..base + 4].copy_from_slice(&p.firma);
        datos[base + p.off_pid..base + p.off_pid + 4].copy_from_slice(&pid.to_le_bytes());
        let nb = nombre.as_bytes();
        let n = nb.len().min(p.long_nombre);
        datos[base + p.off_nombre..base + p.off_nombre + n].copy_from_slice(&nb[..n]);
        datos[base + p.off_enlace..base + p.off_enlace + 8].copy_from_slice(&next.to_le_bytes());
    }

    #[test]
    fn detecta_un_proceso_oculto_por_dkom() {
        // EL CASO DECISIVO. Tres task_structs en memoria fisica: init (0x100),
        // bash (0x200) y EVIL (0x300). init y bash estan enlazados en la lista
        // circular; EVIL esta DESENLAZADO (un rootkit lo escondio del SO).
        let p = perfil();
        let mut datos = vec![0u8; 0x1000];
        let enlace = |base: u64| base + p.off_enlace as u64;

        // Lista circular init <-> bash: init.next = bash.enlace; bash.next = init.enlace.
        escribir_proceso(&mut datos, 0x100, 1, "init", enlace(0x200));
        escribir_proceso(&mut datos, 0x200, 1420, "bash", enlace(0x100));
        // EVIL: su next apunta a si mismo (aislado); nadie lo enlaza.
        escribir_proceso(&mut datos, 0x300, 6666, "rootkit", enlace(0x300));

        let mem = MemoriaPlana { datos };

        // Vista del SO (por lista, empezando en el enlace de init).
        let lista = procesos_por_lista(&mem, enlace(0x100), &p);
        let nombres_lista: Vec<&str> = lista.iter().map(|x| x.nombre.as_str()).collect();
        assert_eq!(
            nombres_lista,
            vec!["init", "bash"],
            "la lista NO ve al oculto"
        );

        // Vista real (por barrido de la memoria fisica).
        let barrido = procesos_por_barrido(&mem, 0, 0x1000, &p);
        assert_eq!(barrido.len(), 3, "el barrido encuentra los tres");

        // Vista cruzada: EVIL esta en el barrido pero no en la lista.
        let ocultos = ocultos(&barrido, &lista);
        assert_eq!(ocultos.len(), 1);
        assert_eq!(ocultos[0].nombre, "rootkit");
        assert_eq!(ocultos[0].pid, 6666);
        assert_eq!(ocultos[0].direccion, 0x300);
    }

    #[test]
    fn sin_ocultos_cuando_todo_esta_enlazado() {
        let p = perfil();
        let mut datos = vec![0u8; 0x1000];
        let enlace = |base: u64| base + p.off_enlace as u64;
        escribir_proceso(&mut datos, 0x100, 1, "init", enlace(0x200));
        escribir_proceso(&mut datos, 0x200, 42, "sshd", enlace(0x100));
        let mem = MemoriaPlana { datos };

        let lista = procesos_por_lista(&mem, enlace(0x100), &p);
        let barrido = procesos_por_barrido(&mem, 0, 0x1000, &p);
        assert_eq!(lista.len(), 2);
        assert_eq!(barrido.len(), 2);
        assert!(ocultos(&barrido, &lista).is_empty());
    }

    #[test]
    fn una_lista_ciclica_corrupta_no_cuelga() {
        // Un rootkit deja la lista apuntandose en un ciclo que NO vuelve a la
        // cabecera: el recorrido tiene que terminar igual, no colgarse.
        let p = perfil();
        let mut datos = vec![0u8; 0x1000];
        let enlace = |base: u64| base + p.off_enlace as u64;
        // init.next = A; A.next = B; B.next = A  (ciclo A<->B, nunca vuelve a init).
        escribir_proceso(&mut datos, 0x100, 1, "init", enlace(0x200));
        escribir_proceso(&mut datos, 0x200, 2, "a", enlace(0x300));
        escribir_proceso(&mut datos, 0x300, 3, "b", enlace(0x200));
        let mem = MemoriaPlana { datos };
        // No debe colgarse ni entrar en panico.
        let lista = procesos_por_lista(&mem, enlace(0x100), &p);
        assert!(lista.len() >= 2);
    }
}
