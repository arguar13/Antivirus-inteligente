//! # `aegis-vmi` — Introspeccion de maquina virtual DEFENSIVA (FASE 54)
//!
//! ## Bajar al Ring -1, para DEFENDER
//!
//! Un rootkit de Ring 0 subvierte el kernel: controla las tablas de paginas y
//! hookea las APIs, asi que cualquier defensa que corra DENTRO del SO puede ser
//! cegada. AegisCore baja por debajo del SO, al Ring -1 (el hipervisor), desde
//! donde el rootkit no puede mentirle. Dos capacidades:
//!
//! 1. **Introspeccion de memoria por EPT** ([`ept`]): con las Extended Page
//!    Tables —que controla el hipervisor, no el SO— se marcan las paginas de
//!    codigo del kernel de modo que ejecutar codigo oculto o parchear el kernel
//!    disparen una violacion que el hipervisor atrapa.
//! 2. **Lectura directa de las estructuras del kernel** ([`introspeccion`]): se
//!    reconstruyen `task_struct`/`EPROCESS` leyendo la memoria fisica a mano, sin
//!    preguntarle al SO, y se compara la lista de procesos que el SO muestra con
//!    la que hay de verdad en memoria. Un proceso que el SO esconde pero sigue en
//!    memoria (un rootkit DKOM) queda al descubierto.
//!
//! ## La linea etica (esto NO es un rootkit)
//!
//! El hipervisor de AegisCore es 100% DEFENSIVO. Se usa para **observar y
//! delatar** la manipulacion del kernel desde debajo, nunca para lo contrario.
//! Prohibido y ausente: persistencia en firmware o UEFI contra el dueno, ocultar
//! el agente, evadir su eliminacion. La antigua idea de un "bootkit UEFI" se
//! rechazo por ser malware; esto es su opuesto legitimo: un guardian que mira el
//! SO desde fuera para detectar a quien lo ataca, y que el dueno de la flota
//! controla y puede quitar cuando quiera.
//!
//! ## Honestidad de validacion
//!
//! El diseno de las **estructuras** (EPT y las del kernel: tamano y disposicion
//! de bits verificados en compilacion) y toda la **logica** —recorrer las EPT,
//! clasificar una violacion, parsear el kernel, detectar lo oculto por vista
//! cruzada— es Rust puro y se prueba aqui con datos reales, cero mocks.
//!
//! El **muro** es la ejecucion en vivo: programar las EPT en un procesador real,
//! atrapar sus violaciones y leer la memoria fisica del anfitrion necesita
//! **VT-x/AMD-V** y privilegios, que el runner del CI no tiene. Esa ruta se aisla
//! tras la caracteristica `kvm` ([`kvm_vivo`]): el CI comprueba que COMPILA y
//! declara que no se pudo ejercer aqui —nunca se finge—.

// El nucleo es Rust seguro; solo la ruta en vivo sobre KVM (gated) usa `unsafe`
// para los ioctl, con permiso explicito en su modulo.
#![deny(unsafe_code)]

pub mod ept;
pub mod introspeccion;
pub mod modo;

#[cfg(feature = "kvm")]
#[allow(unsafe_code)]
pub mod kvm_vivo;

// Las trampas de la tabla de paginas extendida se MODELAN sin necesitar el
// hipervisor: programarlas si lo necesita, y comprobar que no cambian la memoria
// del invitado no. Dejarlas detras de la caracteristica kvm haria que la
// invariante central de la FASE 88 no se comprobara en ninguna compilacion de CI.
pub mod trampa;

use introspeccion::{MemoriaFisica, PerfilKernel, Proceso};

/// La base del hipervisor de introspeccion de AegisCore. Compone la deteccion por
/// EPT y la lectura directa del kernel bajo un mismo objeto, parametrizado por el
/// perfil del kernel que se protege.
///
/// El objeto en si es la parte de DISENO y DECISION (probada). Arrancar la VM y
/// programar el hardware es la ruta en vivo, gated tras `kvm`.
#[derive(Debug, Clone)]
pub struct AegisHypervisor {
    perfil: PerfilKernel,
}

impl AegisHypervisor {
    /// Crea el hipervisor para un kernel descrito por `perfil` (los offsets de
    /// sus estructuras, que en produccion salen de los simbolos/BTF del kernel).
    #[must_use]
    pub fn nuevo(perfil: PerfilKernel) -> Self {
        Self { perfil }
    }

    /// Los permisos EPT que se programarian para una pagina de codigo del kernel:
    /// lectura y ejecucion, pero NO escritura. Asi, un intento de parchear el
    /// codigo (un hook en linea) dispara una violacion de escritura.
    #[must_use]
    pub fn permisos_codigo_kernel() -> (bool, bool, bool) {
        (true, false, true)
    }

    /// Clasifica una EPT violation: la decision defensiva que distingue el codigo
    /// oculto y el parcheo del kernel del ruido. Ver [`ept::clasificar`].
    #[must_use]
    pub fn clasificar_violacion(
        &self,
        violacion: ept::ViolacionEpt,
        traduccion: &Result<ept::Traduccion, ept::EptFallo>,
    ) -> ept::VeredictoEpt {
        ept::clasificar(violacion, traduccion)
    }

    /// La capacidad estrella: detecta los procesos que el SO oculta pero siguen en
    /// memoria (rootkit DKOM), comparando la vista por lista con la vista por
    /// barrido de la memoria fisica.
    ///
    /// `addr_lista` es la direccion del `list_head` de la cabecera de procesos
    /// (p. ej. el `tasks` de `init_task`); `[base_barrido, base_barrido+largo)` es
    /// el rango de memoria fisica a barrer.
    #[must_use]
    pub fn procesos_ocultos(
        &self,
        mem: &impl MemoriaFisica,
        addr_lista: u64,
        base_barrido: u64,
        largo: u64,
    ) -> Vec<Proceso> {
        let por_lista = introspeccion::procesos_por_lista(mem, addr_lista, &self.perfil);
        let por_barrido =
            introspeccion::procesos_por_barrido(mem, base_barrido, largo, &self.perfil);
        introspeccion::ocultos(&por_barrido, &por_lista)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn los_permisos_de_codigo_del_kernel_no_permiten_escritura() {
        let (r, w, x) = AegisHypervisor::permisos_codigo_kernel();
        assert!(
            r && x && !w,
            "el codigo del kernel es R+X, nunca escribible"
        );
    }

    #[test]
    fn el_hipervisor_compone_la_deteccion_de_ocultos() {
        // Reusa el perfil de prueba de introspeccion via un buffer minimo.
        let perfil = PerfilKernel {
            firma: b"TASK".to_vec(),
            off_pid: 8,
            off_nombre: 16,
            long_nombre: 16,
            off_enlace: 40,
            tam_struct: 64,
        };
        // Dos estructuras: una enlazada (init) y una oculta (evil).
        struct Mem {
            datos: Vec<u8>,
        }
        impl MemoriaFisica for Mem {
            fn leer(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
                let a = usize::try_from(addr).ok()?;
                self.datos.get(a..a + len).map(<[u8]>::to_vec)
            }
        }
        let mut datos = vec![0u8; 0x800];
        let poner = |datos: &mut [u8], base: usize, pid: u32, nombre: &str, next: u64| {
            datos[base..base + 4].copy_from_slice(b"TASK");
            datos[base + 8..base + 12].copy_from_slice(&pid.to_le_bytes());
            let nb = nombre.as_bytes();
            datos[base + 16..base + 16 + nb.len()].copy_from_slice(nb);
            datos[base + 40..base + 48].copy_from_slice(&next.to_le_bytes());
        };
        // init se enlaza consigo mismo (lista de un elemento); evil queda fuera.
        poner(&mut datos, 0x100, 1, "init", 0x100 + 40);
        poner(&mut datos, 0x300, 99, "evil", 0x300 + 40);
        let mem = Mem { datos };

        let hv = AegisHypervisor::nuevo(perfil);
        let ocultos = hv.procesos_ocultos(&mem, 0x100 + 40, 0, 0x800);
        assert_eq!(ocultos.len(), 1);
        assert_eq!(ocultos[0].nombre, "evil");
    }
}
